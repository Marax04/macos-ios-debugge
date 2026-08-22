//! `dwarf_provider.rs` — DWARF debug-info symbol provider stub.
//!
//! Parses DWARF version 2–5 debug information from the sections:
//! - `.debug_info`   — Compilation unit headers and DIE trees
//! - `.debug_abbrev` — Abbreviation tables referenced by `.debug_info`
//! - `.debug_str`    — String pool (`DW_FORM_strp` offsets)
//! - `.debug_line`   — Line number program (for source location lookup)
//!
//! Key DWARF tags extracted:
//! - `DW_TAG_subprogram`  → functions
//! - `DW_TAG_variable`    → global variables (when at non-stack address)
//! - `DW_TAG_compile_unit`→ compilation unit metadata
//!
//! Split DWARF (`.dwo` files, `DW_AT_GNU_dwo_name`) is detected and flagged
//! but not loaded automatically.
//!
//! This is a **parsing stub**: it implements the full API surface with correct
//! data types.  Replace the `parse_*` functions with real DWARF parsing
//! (e.g. using the `gimli` crate) when integrating.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding, SymbolProvider,
    SymbolSource, SymbolVisibility, UnifiedSymbol,
};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors raised while parsing DWARF debug sections.
#[derive(Debug, Error)]
pub enum DwarfError {
    /// A required `.debug_*` section was absent from the object.
    #[error("section not found: {0}")]
    SectionNotFound(String),
    /// A compilation unit declared a DWARF version this reader does not support.
    #[error("invalid DWARF version: {0}")]
    InvalidVersion(u16),
    /// The byte stream was malformed at the given section offset.
    #[error("parse error at offset {offset}: {msg}")]
    ParseError {
        /// Byte offset within the section where parsing failed.
        offset: usize,
        /// Human-readable description of the failure.
        msg: String,
    },
    /// An attribute used a `DW_FORM_*` this reader does not decode.
    #[error("unsupported DWARF form: {0:#x}")]
    UnsupportedForm(u64),
    /// An I/O error occurred while reading the object.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A CU referenced a split-DWARF `.dwo` file that has not been loaded.
    #[error("split DWARF (.dwo) not loaded for: {0}")]
    SplitDwarfNotLoaded(String),
    /// Any other error, carrying a message.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias for DWARF operations.
pub type Result<T> = std::result::Result<T, DwarfError>;

// ── DWARF constants ───────────────────────────────────────────────────────────

/// `DW_TAG_compile_unit` — a compilation unit (translation unit).
pub const DW_TAG_COMPILE_UNIT: u16 = 0x11;
/// `DW_TAG_subprogram` — a function or subroutine.
pub const DW_TAG_SUBPROGRAM: u16 = 0x2e;
/// `DW_TAG_variable` — a variable / data object.
pub const DW_TAG_VARIABLE: u16 = 0x34;
/// `DW_TAG_formal_parameter` — a function parameter.
pub const DW_TAG_FORMAL_PARAM: u16 = 0x05;
/// `DW_TAG_base_type` — a primitive scalar type.
pub const DW_TAG_BASE_TYPE: u16 = 0x24;
/// `DW_TAG_structure_type` — a struct type.
pub const DW_TAG_STRUCT_TYPE: u16 = 0x13;
/// `DW_TAG_pointer_type` — a pointer type.
pub const DW_TAG_POINTER_TYPE: u16 = 0x0f;
/// `DW_TAG_typedef` — a type alias.
pub const DW_TAG_TYPEDEF: u16 = 0x16;
/// `DW_TAG_namespace` — a C++ namespace.
pub const DW_TAG_NAMESPACE: u16 = 0x39;
/// `DW_TAG_class_type` — a C++ class type.
pub const DW_TAG_CLASS_TYPE: u16 = 0x02;
/// `DW_TAG_inlined_subroutine` — an inlined instance of a function.
pub const DW_TAG_INLINED_SUB: u16 = 0x1d;

/// `DW_AT_name` — the entity's name.
pub const DW_AT_NAME: u64 = 0x03;
/// `DW_AT_comp_dir` — the compilation directory.
pub const DW_AT_COMP_DIR: u64 = 0x1b;
/// `DW_AT_low_pc` — the entity's starting address.
pub const DW_AT_LOW_PC: u64 = 0x11;
/// `DW_AT_high_pc` — end address, or (DWARF 4+) size relative to `low_pc`.
pub const DW_AT_HIGH_PC: u64 = 0x12;
/// `DW_AT_byte_size` — size of a type/object in bytes.
pub const DW_AT_BYTE_SIZE: u64 = 0x0b;
/// `DW_AT_type` — reference to the entity's type DIE.
pub const DW_AT_TYPE: u64 = 0x49;
/// `DW_AT_declaration` — flag: this DIE is only a declaration.
pub const DW_AT_DECLARATION: u64 = 0x3c;
/// `DW_AT_external` — flag: the entity has external linkage.
pub const DW_AT_EXTERNAL: u64 = 0x3f;
/// `DW_AT_location` — a location expression / list.
pub const DW_AT_LOCATION: u64 = 0x02;
/// `DW_AT_decl_file` — file-table index of the declaration site.
pub const DW_AT_DECL_FILE: u64 = 0x3a;
/// `DW_AT_decl_line` — source line of the declaration.
pub const DW_AT_DECL_LINE: u64 = 0x3b;
/// `DW_AT_decl_column` — source column of the declaration.
pub const DW_AT_DECL_COLUMN: u64 = 0x39;
/// `DW_AT_producer` — the compiler that produced the CU.
pub const DW_AT_PRODUCER: u64 = 0x25;
/// `DW_AT_GNU_dwo_name` — GNU split-DWARF: name of the `.dwo` file.
pub const DW_AT_GNU_DWO_NAME: u64 = 0x2130;
/// `DW_AT_GNU_dwo_id` — GNU split-DWARF: id matching a `.dwo` unit.
pub const DW_AT_GNU_DWO_ID: u64 = 0x2131;
/// `DW_AT_dwo_name` — DWARF 5 split-DWARF: name of the `.dwo` file.
pub const DW_AT_DWO_NAME: u64 = 0x76; // DWARF 5
/// `DW_AT_str_offsets_base` — DWARF 5: base into `.debug_str_offsets`.
pub const DW_AT_STR_OFFSETS_BASE: u64 = 0x72; // DWARF 5
/// `DW_AT_addr_base` — DWARF 5: base into `.debug_addr`.
pub const DW_AT_ADDR_BASE: u64 = 0x73; // DWARF 5

// DW_FORM constants (DWARF 2–5)
/// `DW_FORM_addr` — a target-address-sized machine address.
pub const DW_FORM_ADDR: u64 = 0x01;
/// `DW_FORM_block2` — a block whose length is a 2-byte prefix.
pub const DW_FORM_BLOCK2: u64 = 0x03;
/// `DW_FORM_block4` — a block whose length is a 4-byte prefix.
pub const DW_FORM_BLOCK4: u64 = 0x04;
/// `DW_FORM_data2` — a 2-byte constant.
pub const DW_FORM_DATA2: u64 = 0x05;
/// `DW_FORM_data4` — a 4-byte constant.
pub const DW_FORM_DATA4: u64 = 0x06;
/// `DW_FORM_data8` — an 8-byte constant.
pub const DW_FORM_DATA8: u64 = 0x07;
/// `DW_FORM_string` — an inline NUL-terminated string.
pub const DW_FORM_STRING: u64 = 0x08;
/// `DW_FORM_block` — a block with a ULEB128 length prefix.
pub const DW_FORM_BLOCK: u64 = 0x09;
/// `DW_FORM_block1` — a block whose length is a 1-byte prefix.
pub const DW_FORM_BLOCK1: u64 = 0x0a;
/// `DW_FORM_data1` — a 1-byte constant.
pub const DW_FORM_DATA1: u64 = 0x0b;
/// `DW_FORM_flag` — a 1-byte boolean flag.
pub const DW_FORM_FLAG: u64 = 0x0c;
/// `DW_FORM_sdata` — a signed LEB128 constant.
pub const DW_FORM_SDATA: u64 = 0x0d;
/// `DW_FORM_strp` — a 4/8-byte offset into `.debug_str`.
pub const DW_FORM_STRP: u64 = 0x0e;
/// `DW_FORM_udata` — an unsigned LEB128 constant.
pub const DW_FORM_UDATA: u64 = 0x0f;
/// `DW_FORM_ref_addr` — a section-relative reference to another DIE.
pub const DW_FORM_REF_ADDR: u64 = 0x10;
/// `DW_FORM_ref1` — a 1-byte CU-relative DIE reference.
pub const DW_FORM_REF1: u64 = 0x11;
/// `DW_FORM_ref2` — a 2-byte CU-relative DIE reference.
pub const DW_FORM_REF2: u64 = 0x12;
/// `DW_FORM_ref4` — a 4-byte CU-relative DIE reference.
pub const DW_FORM_REF4: u64 = 0x13;
/// `DW_FORM_ref8` — an 8-byte CU-relative DIE reference.
pub const DW_FORM_REF8: u64 = 0x14;
/// `DW_FORM_ref_udata` — a ULEB128 CU-relative DIE reference.
pub const DW_FORM_REF_UDATA: u64 = 0x15;
/// `DW_FORM_indirect` — the real form is a ULEB128 read from the data stream.
pub const DW_FORM_INDIRECT: u64 = 0x16;
/// `DW_FORM_sec_offset` — a 4/8-byte offset into another `.debug_*` section.
pub const DW_FORM_SEC_OFFSET: u64 = 0x17;
/// `DW_FORM_exprloc` — a location expression with a ULEB128 length prefix.
pub const DW_FORM_EXPRLOC: u64 = 0x18;
/// `DW_FORM_flag_present` — an implicit `true` flag occupying no data bytes.
pub const DW_FORM_FLAG_PRESENT: u64 = 0x19;
/// `DW_FORM_strx` — a ULEB128 index into `.debug_str_offsets`.
pub const DW_FORM_STRX: u64 = 0x1a;
/// `DW_FORM_addrx` — a ULEB128 index into `.debug_addr`.
pub const DW_FORM_ADDRX: u64 = 0x1b;
/// `DW_FORM_ref_sup4` — a 4-byte reference into a supplementary object file.
pub const DW_FORM_REF_SUP4: u64 = 0x1c;
/// `DW_FORM_strp_sup` — a string offset into a supplementary object file.
pub const DW_FORM_STRP_SUP: u64 = 0x1d;
/// `DW_FORM_data16` — a 16-byte constant (e.g. a `DW_AT_GNU_dwo_id`/MD5).
pub const DW_FORM_DATA16: u64 = 0x1e;
/// `DW_FORM_line_strp` — a 4/8-byte offset into `.debug_line_str`.
pub const DW_FORM_LINE_STRP: u64 = 0x1f;
/// `DW_FORM_ref_sig8` — an 8-byte type-unit signature.
pub const DW_FORM_REF_SIG8: u64 = 0x20;
/// `DW_FORM_implicit_const` — a constant stored in the abbreviation, not the data.
pub const DW_FORM_IMPLICIT_CONST: u64 = 0x21;
/// `DW_FORM_loclistx` — a ULEB128 index into `.debug_loclists`.
pub const DW_FORM_LOCLISTX: u64 = 0x22;
/// `DW_FORM_rnglistx` — a ULEB128 index into `.debug_rnglists`.
pub const DW_FORM_RNGLISTX: u64 = 0x23;
/// `DW_FORM_ref_sup8` — an 8-byte reference into a supplementary object file.
pub const DW_FORM_REF_SUP8: u64 = 0x24;
/// `DW_FORM_strx1` — a 1-byte index into `.debug_str_offsets`.
pub const DW_FORM_STRX1: u64 = 0x25;
/// `DW_FORM_strx2` — a 2-byte index into `.debug_str_offsets`.
pub const DW_FORM_STRX2: u64 = 0x26;
/// `DW_FORM_strx3` — a 3-byte index into `.debug_str_offsets`.
pub const DW_FORM_STRX3: u64 = 0x27;
/// `DW_FORM_strx4` — a 4-byte index into `.debug_str_offsets`.
pub const DW_FORM_STRX4: u64 = 0x28;
/// `DW_FORM_addrx1` — a 1-byte index into `.debug_addr`.
pub const DW_FORM_ADDRX1: u64 = 0x29;
/// `DW_FORM_addrx2` — a 2-byte index into `.debug_addr`.
pub const DW_FORM_ADDRX2: u64 = 0x2a;
/// `DW_FORM_addrx3` — a 3-byte index into `.debug_addr`.
pub const DW_FORM_ADDRX3: u64 = 0x2b;
/// `DW_FORM_addrx4` — a 4-byte index into `.debug_addr`.
pub const DW_FORM_ADDRX4: u64 = 0x2c;

// ── LEB128 ────────────────────────────────────────────────────────────────────

/// Read an unsigned LEB128 value from `data` at `pos`, advancing `pos`.
pub(crate) fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7f) << shift;
        }
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 63 + 7 {
            return None; // overlong
        }
    }
}

/// Read a signed LEB128 value from `data` at `pos`, advancing `pos`.
pub(crate) fn read_sleb128(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift; // sign-extend
            }
            return Some(result);
        }
        if shift > 63 + 7 {
            return None;
        }
    }
}

// ── Abbreviation tables ───────────────────────────────────────────────────────

/// One attribute spec inside an abbreviation declaration.
#[derive(Debug, Clone)]
pub struct DwarfAbbrevAttr {
    /// The attribute code (`DW_AT_*`).
    pub at: u64,
    /// The attribute's encoding form (`DW_FORM_*`).
    pub form: u64,
    /// Only set for `DW_FORM_implicit_const`.
    pub implicit_const: i64,
}

/// One abbreviation declaration (`code -> tag + attribute list`).
#[derive(Debug, Clone)]
pub struct DwarfAbbrevDecl {
    /// Abbreviation code that DIEs reference to select this declaration.
    pub code: u64,
    /// The `DW_TAG_*` this abbreviation describes.
    pub tag: u16,
    /// Whether DIEs using this abbreviation have child DIEs.
    pub has_children: bool,
    /// The ordered `(attribute, form)` specs for DIEs of this abbreviation.
    pub attrs: Vec<DwarfAbbrevAttr>,
}

/// Parse the abbreviation table starting at `offset` in `.debug_abbrev`.
///
/// # Errors
///
/// Returns `DwarfError::ParseError` on a truncated table.
pub fn parse_abbrev_table(
    data: &[u8],
    offset: usize,
) -> Result<HashMap<u64, DwarfAbbrevDecl>> {
    let mut table = HashMap::new();
    if offset >= data.len() {
        return Ok(table); // empty/absent table: tolerated (null-DIE-only CUs)
    }
    let mut pos = offset;
    loop {
        let code = read_uleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
            offset: pos,
            msg: "truncated abbrev code".into(),
        })?;
        if code == 0 {
            break; // end of table
        }
        let tag = read_uleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
            offset: pos,
            msg: "truncated abbrev tag".into(),
        })?;
        let has_children = *data.get(pos).ok_or_else(|| DwarfError::ParseError {
            offset: pos,
            msg: "truncated has_children".into(),
        })? != 0;
        pos += 1;
        let mut attrs = Vec::new();
        loop {
            let at = read_uleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
                offset: pos,
                msg: "truncated attr name".into(),
            })?;
            let form = read_uleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
                offset: pos,
                msg: "truncated attr form".into(),
            })?;
            if at == 0 && form == 0 {
                break;
            }
            let implicit_const = if form == DW_FORM_IMPLICIT_CONST {
                read_sleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
                    offset: pos,
                    msg: "truncated implicit_const".into(),
                })?
            } else {
                0
            };
            attrs.push(DwarfAbbrevAttr {
                at,
                form,
                implicit_const,
            });
        }
        table.insert(
            code,
            DwarfAbbrevDecl {
                code,
                tag: u16::try_from(tag).unwrap_or(u16::MAX),
                has_children,
                attrs,
            },
        );
    }
    Ok(table)
}

// ── DwarfTag ──────────────────────────────────────────────────────────────────

/// A recognised DWARF DIE tag; `Unknown` preserves the raw `DW_TAG_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DwarfTag {
    /// `DW_TAG_compile_unit`.
    CompileUnit,
    /// `DW_TAG_subprogram` (function).
    Subprogram,
    /// `DW_TAG_variable`.
    Variable,
    /// `DW_TAG_formal_parameter`.
    FormalParameter,
    /// `DW_TAG_base_type`.
    BaseType,
    /// `DW_TAG_structure_type`.
    StructType,
    /// `DW_TAG_pointer_type`.
    PointerType,
    /// `DW_TAG_typedef`.
    Typedef,
    /// `DW_TAG_namespace`.
    Namespace,
    /// `DW_TAG_class_type`.
    ClassType,
    /// `DW_TAG_inlined_subroutine`.
    InlinedSubroutine,
    /// Any other tag, preserving its raw numeric value.
    Unknown(u16),
}

impl DwarfTag {
    /// Map a raw `DW_TAG_*` number to a [`DwarfTag`].
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            DW_TAG_COMPILE_UNIT => Self::CompileUnit,
            DW_TAG_SUBPROGRAM => Self::Subprogram,
            DW_TAG_VARIABLE => Self::Variable,
            DW_TAG_FORMAL_PARAM => Self::FormalParameter,
            DW_TAG_BASE_TYPE => Self::BaseType,
            DW_TAG_STRUCT_TYPE => Self::StructType,
            DW_TAG_POINTER_TYPE => Self::PointerType,
            DW_TAG_TYPEDEF => Self::Typedef,
            DW_TAG_NAMESPACE => Self::Namespace,
            DW_TAG_CLASS_TYPE => Self::ClassType,
            DW_TAG_INLINED_SUB => Self::InlinedSubroutine,
            other => Self::Unknown(other),
        }
    }

    /// Map back to the raw `DW_TAG_*` number.
    #[must_use]
    pub const fn tag_number(self) -> u16 {
        match self {
            Self::CompileUnit => DW_TAG_COMPILE_UNIT,
            Self::Subprogram => DW_TAG_SUBPROGRAM,
            Self::Variable => DW_TAG_VARIABLE,
            Self::FormalParameter => DW_TAG_FORMAL_PARAM,
            Self::BaseType => DW_TAG_BASE_TYPE,
            Self::StructType => DW_TAG_STRUCT_TYPE,
            Self::PointerType => DW_TAG_POINTER_TYPE,
            Self::Typedef => DW_TAG_TYPEDEF,
            Self::Namespace => DW_TAG_NAMESPACE,
            Self::ClassType => DW_TAG_CLASS_TYPE,
            Self::InlinedSubroutine => DW_TAG_INLINED_SUB,
            Self::Unknown(n) => n,
        }
    }
}

impl std::fmt::Display for DwarfTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── DwarfAttribute ────────────────────────────────────────────────────────────

/// A parsed DWARF attribute value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DwarfAttrValue {
    /// A machine address (`DW_FORM_addr`).
    Address(u64),
    /// An unsigned constant.
    Udata(u64),
    /// A signed constant.
    Sdata(i64),
    /// An unresolved offset into `.debug_str` (`DW_FORM_strp`).
    Strp(u32), // offset into .debug_str
    /// A resolved string value (`DW_FORM_string` or a resolved `strp`/`strx`).
    String(String), // inline string (DW_FORM_string)
    /// A boolean flag.
    Flag(bool),
    /// A reference to another DIE, as an offset into `.debug_info`.
    Ref(u64), // reference to another DIE (offset in .debug_info)
    /// A raw block of bytes (e.g. a location expression).
    Block(Vec<u8>), // raw block (location expressions etc.)
    /// DWARF 5 indexed string (`DW_FORM_strx*`): an index into the CU's slice
    /// of `.debug_str_offsets`. Present only when the section was not supplied
    /// (or the index is out of range); otherwise the parser rewrites it to
    /// [`DwarfAttrValue::String`].
    Strx(u64),
    /// DWARF 5 indexed address (`DW_FORM_addrx*`): an index into the CU's slice
    /// of `.debug_addr`. Rewritten to [`DwarfAttrValue::Address`] when the
    /// section is available.
    Addrx(u64),
    /// A value whose form this reader does not decode.
    Unknown,
}

impl DwarfAttrValue {
    /// The address if this is an [`Address`](Self::Address), else `None`.
    #[must_use]
    pub const fn as_address(&self) -> Option<u64> {
        if let Self::Address(a) = self {
            Some(*a)
        } else {
            None
        }
    }
    /// The value as a `u64` if it is an unsigned constant or an address.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Udata(v) | Self::Address(v) => Some(*v),
            _ => None,
        }
    }
    /// The string if this is a resolved [`String`](Self::String), else `None`.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    /// The flag value if this is a [`Flag`](Self::Flag), else `None`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Flag(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

// ── DwarfDie ──────────────────────────────────────────────────────────────────

/// A single Debugging Information Entry (DIE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfDie {
    /// Offset of this DIE within `.debug_info`.
    pub offset: u64,
    /// Tag (what kind of entity this DIE represents).
    pub tag: DwarfTag,
    /// Parsed attributes.
    pub attributes: HashMap<u64, DwarfAttrValue>,
    /// Child DIE offsets (populated when `has_children` is true).
    pub children: Vec<u64>,
}

impl DwarfDie {
    /// Create an attribute-less DIE at `offset` with the given `tag`.
    #[must_use]
    pub fn new(offset: u64, tag: DwarfTag) -> Self {
        Self {
            offset,
            tag,
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    /// Set (or overwrite) attribute `at` to `value`.
    pub fn set_attr(&mut self, at: u64, value: DwarfAttrValue) {
        self.attributes.insert(at, value);
    }
    /// Borrow attribute `at` (a `DW_AT_*` code), if present.
    #[must_use]
    pub fn get_attr(&self, at: u64) -> Option<&DwarfAttrValue> {
        self.attributes.get(&at)
    }

    /// The DIE's `DW_AT_name`, if any.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.attributes.get(&DW_AT_NAME).and_then(|v| v.as_str())
    }

    /// The DIE's `DW_AT_low_pc` (start address), if any.
    #[must_use]
    pub fn low_pc(&self) -> Option<u64> {
        self.attributes
            .get(&DW_AT_LOW_PC)
            .and_then(DwarfAttrValue::as_u64)
    }

    /// Static (link-time) address of a `DW_TAG_variable`.
    ///
    /// A global variable's address lives in `DW_AT_location` as an exprloc
    /// holding a single `DW_OP_addr <addr>` — `DW_AT_low_pc` is a
    /// subprogram/lexical-block attribute that variables do not carry, so
    /// looking there finds nothing for real `.debug_info`.
    ///
    /// Returns `None` for anything that is not a single-operation constant
    /// address: `DW_OP_fbreg` (a stack local), register locations, and
    /// multi-piece expressions all describe non-static storage.
    /// `DW_OP_addrx` / `DW_OP_GNU_addr_index` yield an index into
    /// `.debug_addr`, which this method cannot resolve because it has no
    /// access to the owning CU's `DW_AT_addr_base`, so those return `None`.
    /// (Attribute-level `DW_FORM_addrx*` is resolved separately, by
    /// [`DwarfParser::resolve_indexed_forms`].)
    ///
    /// `address_size` is the CU's address size in bytes.
    #[must_use]
    pub fn static_address(&self, address_size: u8) -> Option<u64> {
        const DW_OP_ADDR: u8 = 0x03;

        if let Some(DwarfAttrValue::Block(expr)) = self.attributes.get(&DW_AT_LOCATION) {
            let n = address_size as usize;
            // Exactly one DW_OP_addr and nothing else; a longer expression
            // means the address is only one piece of a composite location.
            if expr.first() == Some(&DW_OP_ADDR)
                && expr.len() == 1 + n
                && (n == 4 || n == 8)
            {
                let bytes = expr.get(1..1 + n)?;
                let mut v = 0u64;
                for (i, b) in bytes.iter().enumerate() {
                    v |= u64::from(*b) << (8 * i);
                }
                return Some(v);
            }
            return None;
        }

        // Fall back to DW_AT_low_pc: real variables do not carry it, but
        // synthetic DIEs built by callers and tests may.
        self.low_pc()
    }

    /// The DIE's raw `DW_AT_high_pc` value (may be an end address or a length).
    #[must_use]
    pub fn high_pc(&self) -> Option<u64> {
        self.attributes
            .get(&DW_AT_HIGH_PC)
            .and_then(DwarfAttrValue::as_u64)
    }

    /// The DIE's `DW_AT_byte_size` (size of a type/object in bytes), if any.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.attributes
            .get(&DW_AT_BYTE_SIZE)
            .and_then(DwarfAttrValue::as_u64)
    }

    /// Whether the DIE has `DW_AT_external` set (external linkage).
    #[must_use]
    pub fn is_external(&self) -> bool {
        self.attributes
            .get(&DW_AT_EXTERNAL)
            .and_then(DwarfAttrValue::as_bool)
            .unwrap_or(false)
    }

    /// Whether the DIE has `DW_AT_declaration` set (declaration only, no definition).
    #[must_use]
    pub fn is_declaration(&self) -> bool {
        self.attributes
            .get(&DW_AT_DECLARATION)
            .and_then(DwarfAttrValue::as_bool)
            .unwrap_or(false)
    }

    /// The DIE's `DW_AT_decl_file` (file-table index of its declaration), if any.
    #[must_use]
    pub fn decl_file(&self) -> Option<u64> {
        self.attributes
            .get(&DW_AT_DECL_FILE)
            .and_then(DwarfAttrValue::as_u64)
    }

    /// The DIE's `DW_AT_decl_line` (declaration source line), if any.
    #[must_use]
    pub fn decl_line(&self) -> Option<u64> {
        self.attributes
            .get(&DW_AT_DECL_LINE)
            .and_then(DwarfAttrValue::as_u64)
    }

    /// Compute the function size from `low_pc` / `high_pc`.
    /// In DWARF 4+, `high_pc` may be a constant offset (length) rather than an
    /// absolute address.  We return the size if the relationship can be
    /// determined.
    #[must_use]
    pub fn function_size(&self, low: u64) -> Option<u64> {
        // DWARF defines the semantics by form class: an address form is an
        // absolute end address, a constant form is a length. The heuristic
        // "high >= low means absolute" mis-sizes any function whose length
        // exceeds its low_pc (PIE binaries, .o files with low_pc = 0).
        match self.attributes.get(&DW_AT_HIGH_PC)? {
            DwarfAttrValue::Address(high) => high.checked_sub(low),
            DwarfAttrValue::Udata(len) => Some(*len),
            DwarfAttrValue::Sdata(len) => u64::try_from(*len).ok(),
            _ => None,
        }
    }
}

// ── DwarfCompileUnit ──────────────────────────────────────────────────────────

/// A `.debug_info` compilation unit header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfCompileUnit {
    /// Byte offset of this CU within `.debug_info`.
    pub offset: u64,
    /// DWARF version (2–5).
    pub version: u16,
    /// Offset into `.debug_abbrev` for this CU's abbreviation table.
    pub abbrev_offset: u64,
    /// Address size in bytes (4 or 8).
    pub address_size: u8,
    /// CU-level attributes (from the `DW_TAG_compile_unit` DIE).
    pub name: Option<String>,
    /// `DW_AT_comp_dir` — the directory the CU was compiled in.
    pub comp_dir: Option<String>,
    /// `DW_AT_producer` — the compiler identification string.
    pub producer: Option<String>,
    /// If true, this CU references a split DWARF `.dwo` file.
    pub has_split_dwarf: bool,
    /// Path to the split `.dwo` file, if `has_split_dwarf`.
    pub dwo_name: Option<String>,
    /// DWARF 5 `DW_AT_str_offsets_base` (offset of this CU's entry array in
    /// `.debug_str_offsets`). Defaults to 8, past a 32-bit-format header.
    pub str_offsets_base: u64,
    /// DWARF 5 `DW_AT_addr_base` (offset of this CU's entry array in
    /// `.debug_addr`). Defaults to 8, past a 32-bit-format header.
    pub addr_base: u64,
    /// DIEs owned by this CU (keyed by DIE offset).
    pub dies: HashMap<u64, DwarfDie>,
}

impl DwarfCompileUnit {
    /// Create a CU header with the given fields and empty attribute/DIE state;
    /// the DWARF 5 `str_offsets_base`/`addr_base` default to 8 (past a 32-bit header).
    #[must_use]
    pub fn new(offset: u64, version: u16, abbrev_offset: u64, address_size: u8) -> Self {
        Self {
            offset,
            version,
            abbrev_offset,
            address_size,
            name: None,
            comp_dir: None,
            producer: None,
            has_split_dwarf: false,
            dwo_name: None,
            str_offsets_base: 8,
            addr_base: 8,
            dies: HashMap::new(),
        }
    }

    /// Add a DIE, keyed by its `.debug_info` offset.
    pub fn add_die(&mut self, die: DwarfDie) {
        self.dies.insert(die.offset, die);
    }

    /// All `DW_TAG_subprogram` (function) DIEs in this CU.
    #[must_use]
    pub fn subprograms(&self) -> Vec<&DwarfDie> {
        self.dies
            .values()
            .filter(|d| d.tag == DwarfTag::Subprogram)
            .collect()
    }

    /// All `DW_TAG_variable` DIEs in this CU.
    #[must_use]
    pub fn variables(&self) -> Vec<&DwarfDie> {
        self.dies
            .values()
            .filter(|d| d.tag == DwarfTag::Variable)
            .collect()
    }
}

// ── DwarfLineEntry ────────────────────────────────────────────────────────────

/// A row from the `.debug_line` line number matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfLineEntry {
    /// Machine address this row maps.
    pub address: u64,
    /// Index into the line program's file-name table.
    pub file_index: u32,
    /// Source line number (0 = no line associated).
    pub line: u32,
    /// Source column number (0 = no column).
    pub column: u32,
    /// Whether this address is a recommended breakpoint location (`is_stmt`).
    pub is_stmt: bool,
    /// Whether this row marks the end of a contiguous address sequence.
    pub end_sequence: bool,
}

// ── DwarfLineTable ────────────────────────────────────────────────────────────

/// Full line-number program result for a single CU.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DwarfLineTable {
    /// File-name table indexed by [`DwarfLineEntry::file_index`].
    pub file_names: Vec<String>,
    /// Line-matrix rows, kept sorted by address by [`Self::add_entry`].
    pub entries: Vec<DwarfLineEntry>,
}

impl DwarfLineTable {
    /// Create an empty line table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a file name to the file-name table.
    pub fn add_file(&mut self, name: impl Into<String>) {
        self.file_names.push(name.into());
    }
    /// Add an entry, keeping `entries` sorted by address so [`Self::source_at`]
    /// can binary-search. Appending in ascending order (the common case for a
    /// line program) is O(1).
    pub fn add_entry(&mut self, entry: DwarfLineEntry) {
        let pos = self.entries.partition_point(|e| e.address <= entry.address);
        if pos == self.entries.len() {
            self.entries.push(entry);
        } else {
            self.entries.insert(pos, entry);
        }
    }

    /// Resolve a `DW_AT_decl_file` index against this table's `file_names`.
    ///
    /// In DWARF 2-4 the file index is 1-based (0 means "no file"); in DWARF 5
    /// it is 0-based.
    #[must_use]
    pub fn file_name_for_index(&self, dwarf_version: u16, idx: u64) -> Option<String> {
        let i = if dwarf_version >= 5 {
            idx
        } else {
            idx.checked_sub(1)?
        };
        self.file_names.get(usize::try_from(i).ok()?).cloned()
    }

    /// Look up the source location for a given address (nearest-below).
    ///
    /// Binary-searches `entries`, which [`Self::add_entry`] keeps sorted.
    #[must_use]
    pub fn source_at(&self, addr: u64) -> Option<SourceLocation> {
        let upper = self.entries.partition_point(|e| e.address <= addr);
        let entry = self.entries[..upper].iter().rev().find(|e| !e.end_sequence)?;
        let file = self
            .file_names
            .get(entry.file_index as usize)
            .cloned()
            .unwrap_or_else(|| format!("<file{}>", entry.file_index));
        Some(SourceLocation {
            file,
            line: entry.line,
            column: entry.column,
        })
    }
}

// ── DwarfSections ─────────────────────────────────────────────────────────────

/// Raw section data passed to the DWARF parser.
#[derive(Debug, Default, Clone)]
pub struct DwarfSections {
    /// `.debug_info` — the DIE tree.
    pub debug_info: Vec<u8>,
    /// `.debug_abbrev` — abbreviation tables referenced by CUs.
    pub debug_abbrev: Vec<u8>,
    /// `.debug_str` — the string pool `DW_FORM_strp` points into.
    pub debug_str: Vec<u8>,
    /// `.debug_line` — the line-number programs.
    pub debug_line: Vec<u8>,
    /// DWARF 5 `.debug_str_offsets` — the table `DW_FORM_strx*` indexes into.
    pub debug_str_offsets: Vec<u8>,
    /// DWARF 5 `.debug_addr` — the table `DW_FORM_addrx*` indexes into.
    pub debug_addr: Vec<u8>,
    /// Optional: pre-loaded `.dwo` sections for split DWARF.
    pub split_debug_info: Option<Vec<u8>>,
}

impl DwarfSections {
    /// Create an all-empty section set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `.debug_info` is present (non-empty).
    #[must_use]
    pub const fn has_debug_info(&self) -> bool {
        !self.debug_info.is_empty()
    }
    /// Whether `.debug_str` is present (non-empty).
    #[must_use]
    pub const fn has_debug_str(&self) -> bool {
        !self.debug_str.is_empty()
    }
    /// Whether `.debug_line` is present (non-empty).
    #[must_use]
    pub const fn has_debug_line(&self) -> bool {
        !self.debug_line.is_empty()
    }

    /// Resolve a `DW_FORM_strp` offset to a string from `.debug_str`.
    #[must_use]
    pub fn resolve_strp(&self, offset: u32) -> Option<String> {
        let data = &self.debug_str;
        if offset as usize >= data.len() {
            return None;
        }
        let end = data[offset as usize..].iter().position(|&b| b == 0)?;
        std::str::from_utf8(&data[offset as usize..offset as usize + end])
            .ok()
            .map(std::string::ToString::to_string)
    }

    /// Offset of the first entry of a section whose unit header this owns —
    /// 8 bytes for the 32-bit DWARF format, 16 for the 64-bit one (which is
    /// introduced by an initial-length escape of `0xffff_ffff`).
    ///
    /// Used as the fallback when a CU carries no `DW_AT_str_offsets_base` /
    /// `DW_AT_addr_base`; assuming 8 against a 64-bit-format table read the
    /// entries 8 bytes early.
    #[must_use]
    fn default_base(section: &[u8]) -> u64 {
        if section.get(..4) == Some(&[0xff, 0xff, 0xff, 0xff][..]) {
            16
        } else {
            8
        }
    }

    /// Fallback `DW_AT_str_offsets_base` for a CU that does not declare one.
    #[must_use]
    pub fn default_str_offsets_base(&self) -> u64 {
        Self::default_base(&self.debug_str_offsets)
    }

    /// Fallback `DW_AT_addr_base` for a CU that does not declare one.
    #[must_use]
    pub fn default_addr_base(&self) -> u64 {
        Self::default_base(&self.debug_addr)
    }

    /// Resolve a `DW_FORM_strx*` index against `.debug_str_offsets`.
    ///
    /// `base` is the CU's `DW_AT_str_offsets_base` — the offset of the CU's
    /// entry array, i.e. just past the unit header (8 bytes for the 32-bit
    /// DWARF format, 16 for the 64-bit one). The entry width is derived from
    /// the header's initial length field so both formats work.
    #[must_use]
    pub fn resolve_strx(&self, base: u64, index: u64) -> Option<String> {
        let table = &self.debug_str_offsets;
        let base = usize::try_from(base).ok()?;
        // A 64-bit-format unit starts with 0xffffffff; its entries are 8 bytes.
        let is_64 = base >= 16
            && table
                .get(base - 16..base - 12)
                .is_some_and(|b| b == [0xff, 0xff, 0xff, 0xff]);
        let entry_size = if is_64 { 8usize } else { 4 };
        let idx = usize::try_from(index).ok()?;
        let start = base.checked_add(idx.checked_mul(entry_size)?)?;
        let bytes = table.get(start..start.checked_add(entry_size)?)?;
        let mut buf = [0u8; 8];
        buf[..entry_size].copy_from_slice(bytes);
        let str_off = u64::from_le_bytes(buf);
        self.resolve_strp(u32::try_from(str_off).ok()?)
    }

    /// Resolve a `DW_FORM_addrx*` index against `.debug_addr`.
    ///
    /// `base` is the CU's `DW_AT_addr_base` (past the 8-byte 32-bit-format
    /// header, or the 16-byte 64-bit one); `address_size` is the CU's address
    /// size in bytes.
    #[must_use]
    pub fn resolve_addrx(&self, base: u64, index: u64, address_size: u8) -> Option<u64> {
        let n = usize::from(address_size);
        if n == 0 || n > 8 {
            return None;
        }
        let base = usize::try_from(base).ok()?;
        let idx = usize::try_from(index).ok()?;
        let start = base.checked_add(idx.checked_mul(n)?)?;
        let bytes = self.debug_addr.get(start..start.checked_add(n)?)?;
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(bytes);
        Some(u64::from_le_bytes(buf))
    }
}

// ── DwarfParser ───────────────────────────────────────────────────────────────

/// Parses DWARF sections into a list of [`DwarfCompileUnit`]s.
///
/// This stub implements the `parse_*` entry points; real parsing logic should
/// be substituted with `gimli` calls.
pub struct DwarfParser<'a> {
    sections: &'a DwarfSections,
    is_64bit: bool,
}

impl<'a> DwarfParser<'a> {
    /// Create a parser over `sections`; `is_64bit` selects the 64-bit DWARF
    /// format (vs the default 32-bit format).
    #[must_use]
    pub const fn new(sections: &'a DwarfSections, is_64bit: bool) -> Self {
        Self { sections, is_64bit }
    }

    /// Returns `true` if this parser is configured for the 64-bit DWARF format
    /// (12-byte CU intro with `0xffffffff` length marker) rather than 32-bit
    /// (4-byte length).
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Parse all compilation units from `.debug_info`.
    ///
    /// # Errors
    ///
    /// Returns `DwarfError::ParseError` if the section is too short, or `DwarfError::InvalidVersion`
    /// if a CU header has an unsupported DWARF version.
    ///
    /// # Panics
    ///
    /// Panics only if internal slice-to-array conversions fail, which is impossible by construction.
    pub fn parse_compile_units(&self) -> Result<Vec<DwarfCompileUnit>> {
        let data = &self.sections.debug_info;
        if data.is_empty() {
            return Ok(vec![]);
        }
        if data.len() < 11 {
            return Err(DwarfError::ParseError {
                offset: 0,
                msg: "debug_info too short for CU header".into(),
            });
        }

        let mut units = Vec::new();
        let mut cursor = 0;

        while cursor + 11 <= data.len() {
            // CU header: u32 unit_length, u16 version, then (v2–4) u32
            // abbrev_offset + u8 addr_size, or (v5) u8 unit_type + u8
            // addr_size + u32 abbrev_offset. 64-bit DWARF (0xffffffff
            // marker) is detected and rejected as unsupported for now.
            let unit_length =
                u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            if unit_length == 0 {
                break;
            }
            if unit_length == 0xffff_ffff {
                return Err(DwarfError::ParseError {
                    offset: cursor,
                    msg: "64-bit DWARF format not supported".into(),
                });
            }

            let version = u16::from_le_bytes(data[cursor + 4..cursor + 6].try_into().unwrap());
            if !(2..=5).contains(&version) {
                return Err(DwarfError::InvalidVersion(version));
            }

            let cu_end = (cursor + 4 + unit_length).min(data.len());
            let (abbrev_offset, addr_size, die_start) = if version >= 5 {
                if cursor + 12 > data.len() {
                    return Err(DwarfError::ParseError {
                        offset: cursor,
                        msg: "truncated DWARF 5 CU header".into(),
                    });
                }
                // unit_type at +6, addr_size at +7, abbrev_offset at +8..12
                let addr_size = data[cursor + 7];
                let abbrev_offset = u64::from(u32::from_le_bytes(
                    data[cursor + 8..cursor + 12].try_into().unwrap(),
                ));
                (abbrev_offset, addr_size, cursor + 12)
            } else {
                let abbrev_offset = u64::from(u32::from_le_bytes(
                    data[cursor + 6..cursor + 10].try_into().unwrap(),
                ));
                (abbrev_offset, data[cursor + 10], cursor + 11)
            };

            let mut cu = DwarfCompileUnit::new(cursor as u64, version, abbrev_offset, addr_size);

            let abbrevs = parse_abbrev_table(
                &self.sections.debug_abbrev,
                usize::try_from(abbrev_offset).unwrap_or(usize::MAX),
            )?;
            self.parse_die_tree(data, die_start, cu_end, &abbrevs, &mut cu)?;
            self.resolve_indexed_forms(&mut cu, die_start as u64);

            // Hoist interesting root-DIE attributes onto the CU.
            if let Some(root) = cu.dies.get(&(die_start as u64)).cloned()
                && root.tag == DwarfTag::CompileUnit
            {
                cu.name = root.name().map(std::string::ToString::to_string);
                cu.comp_dir = root
                    .get_attr(DW_AT_COMP_DIR)
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string);
                cu.producer = root
                    .get_attr(DW_AT_PRODUCER)
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string);
                let dwo = root
                    .get_attr(DW_AT_GNU_DWO_NAME)
                    .or_else(|| root.get_attr(DW_AT_DWO_NAME));
                if let Some(v) = dwo {
                    cu.has_split_dwarf = true;
                    cu.dwo_name = v.as_str().map(std::string::ToString::to_string);
                } else if root.get_attr(DW_AT_GNU_DWO_ID).is_some() {
                    // A GCC skeleton CU carries `DW_AT_GNU_dwo_id` as well as
                    // the name, and the name can be absent or in a form this
                    // reader does not resolve (a `.dwo_name` strx into a
                    // `.debug_str_offsets` table that was not shipped). Keying
                    // the flag on the name alone made such a CU look like an
                    // ordinary, merely empty unit: the caller got zero symbols
                    // and no `SplitDwarfNotLoaded` signal telling it why.
                    // `DW_AT_GNU_DWO_ID` was declared for exactly this and was
                    // referenced nowhere.
                    cu.has_split_dwarf = true;
                }
            }

            units.push(cu);
            cursor += 4 + unit_length;
        }

        Ok(units)
    }

    /// Parse the DIE tree of one CU (from `start` to `end` in `.debug_info`)
    /// using its abbreviation table, adding all DIEs to `cu`.
    fn parse_die_tree(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        abbrevs: &HashMap<u64, DwarfAbbrevDecl>,
        cu: &mut DwarfCompileUnit,
    ) -> Result<()> {
        let mut pos = start;
        // Stack of parent DIE offsets for children bookkeeping.
        let mut parents: Vec<u64> = Vec::new();
        while pos < end {
            let die_offset = pos as u64;
            let code = read_uleb128(data, &mut pos).ok_or_else(|| DwarfError::ParseError {
                offset: pos,
                msg: "truncated abbrev code in DIE".into(),
            })?;
            if code == 0 {
                // Null DIE: end of current siblings list.
                if parents.pop().is_none() {
                    break; // end of the whole tree
                }
                continue;
            }
            let Some(decl) = abbrevs.get(&code) else {
                return Err(DwarfError::ParseError {
                    offset: pos,
                    msg: format!("unknown abbrev code {code}"),
                });
            };
            let mut die = DwarfDie::new(die_offset, DwarfTag::from_u16(decl.tag));
            for attr in &decl.attrs {
                let value = self.read_form_value(data, &mut pos, attr, cu.address_size)?;
                die.set_attr(attr.at, value);
            }
            if let Some(&parent) = parents.last()
                && let Some(p) = cu.dies.get_mut(&parent)
            {
                p.children.push(die_offset);
            }
            let has_children = decl.has_children;
            cu.add_die(die);
            if has_children {
                parents.push(die_offset);
            }
        }
        Ok(())
    }

    /// Rewrite every [`DwarfAttrValue::Strx`] / [`DwarfAttrValue::Addrx`] in a
    /// freshly parsed CU into a `String` / `Address`, using the CU root DIE's
    /// `DW_AT_str_offsets_base` / `DW_AT_addr_base`.
    ///
    /// Each base defaults to the offset just past its section's unit header —
    /// 8 bytes in the 32-bit DWARF format, 16 in the 64-bit one — which is
    /// where the first entry of a single-CU table lives. Indices that fall
    /// outside the section are left as `Strx`/`Addrx` so callers can tell
    /// "unresolved" from a real value.
    pub fn resolve_indexed_forms(&self, cu: &mut DwarfCompileUnit, root_offset: u64) {
        let base_of = |at: u64, default_base: u64| -> u64 {
            cu.dies
                .get(&root_offset)
                .and_then(|d| d.get_attr(at))
                .and_then(|v| match v {
                    DwarfAttrValue::Ref(n)
                    | DwarfAttrValue::Udata(n)
                    | DwarfAttrValue::Address(n) => Some(*n),
                    _ => None,
                })
                .unwrap_or(default_base)
        };
        let str_base = base_of(
            DW_AT_STR_OFFSETS_BASE,
            self.sections.default_str_offsets_base(),
        );
        let addr_base = base_of(DW_AT_ADDR_BASE, self.sections.default_addr_base());
        cu.str_offsets_base = str_base;
        cu.addr_base = addr_base;

        let addr_size = cu.address_size;
        for die in cu.dies.values_mut() {
            for value in die.attributes.values_mut() {
                match value {
                    DwarfAttrValue::Strx(i) => {
                        if let Some(s) = self.sections.resolve_strx(str_base, *i) {
                            *value = DwarfAttrValue::String(s);
                        }
                    }
                    DwarfAttrValue::Addrx(i) => {
                        if let Some(a) = self.sections.resolve_addrx(addr_base, *i, addr_size) {
                            *value = DwarfAttrValue::Address(a);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Decode one attribute value according to its DWARF form.
    ///
    /// The form families that need no access to `self` are delegated to
    /// [`read_constant_form`], [`read_reference_form`], [`read_block_form`] and
    /// [`read_indexed_form`]; only the address, string and flag forms — the ones
    /// that resolve against `self.sections` or carry the abbreviation's
    /// `implicit_const` — are decoded here.
    fn read_form_value(
        &self,
        data: &[u8],
        pos: &mut usize,
        attr: &DwarfAbbrevAttr,
        addr_size: u8,
    ) -> Result<DwarfAttrValue> {
        let mut form = attr.form;
        if form == DW_FORM_INDIRECT {
            form = read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?;
        }
        Ok(match form {
            DW_FORM_ADDR => {
                let n = usize::from(addr_size.clamp(1, 8));
                let bytes = take_bytes(data, pos, n)?;
                let mut buf = [0u8; 8];
                buf[..n].copy_from_slice(bytes);
                DwarfAttrValue::Address(u64::from_le_bytes(buf))
            }
            DW_FORM_DATA1 | DW_FORM_DATA2 | DW_FORM_DATA4 | DW_FORM_DATA8 | DW_FORM_UDATA
            | DW_FORM_SDATA => read_constant_form(data, pos, form)?,
            DW_FORM_STRING => {
                let start = *pos;
                let nul = data
                    .get(start..)
                    .and_then(|rest| rest.iter().position(|&b| b == 0))
                    .ok_or_else(|| truncated_at(start))?;
                *pos = start + nul + 1;
                DwarfAttrValue::String(
                    String::from_utf8_lossy(&data[start..start + nul]).into_owned(),
                )
            }
            DW_FORM_STRP | DW_FORM_LINE_STRP | DW_FORM_STRP_SUP => {
                let off = u32::try_from(read_le_uint(data, pos, 4)?).unwrap_or(u32::MAX);
                // Resolve eagerly against .debug_str where possible.
                self.sections
                    .resolve_strp(off)
                    .map_or(DwarfAttrValue::Strp(off), DwarfAttrValue::String)
            }
            DW_FORM_FLAG => DwarfAttrValue::Flag(take_bytes(data, pos, 1)?[0] != 0),
            DW_FORM_FLAG_PRESENT => DwarfAttrValue::Flag(true),
            DW_FORM_REF1 | DW_FORM_REF2 | DW_FORM_REF4 | DW_FORM_REF_ADDR | DW_FORM_REF_SUP4
            | DW_FORM_SEC_OFFSET | DW_FORM_REF8 | DW_FORM_REF_SIG8 | DW_FORM_REF_SUP8
            | DW_FORM_REF_UDATA => read_reference_form(data, pos, form)?,
            DW_FORM_BLOCK1 | DW_FORM_BLOCK2 | DW_FORM_BLOCK4 | DW_FORM_BLOCK | DW_FORM_EXPRLOC
            | DW_FORM_DATA16 => read_block_form(data, pos, form)?,
            DW_FORM_IMPLICIT_CONST => DwarfAttrValue::Sdata(attr.implicit_const),
            DW_FORM_STRX | DW_FORM_ADDRX | DW_FORM_LOCLISTX | DW_FORM_RNGLISTX | DW_FORM_STRX1
            | DW_FORM_ADDRX1 | DW_FORM_STRX2 | DW_FORM_ADDRX2 | DW_FORM_STRX3
            | DW_FORM_ADDRX3 | DW_FORM_STRX4 | DW_FORM_ADDRX4 => {
                read_indexed_form(data, pos, form)?
            }
            other => return Err(DwarfError::UnsupportedForm(other)),
        })
    }

    /// Extract all subprogram DIEs from a slice of CUs.
    #[must_use]
    pub fn extract_subprograms(cus: &[DwarfCompileUnit]) -> Vec<&DwarfDie> {
        cus.iter().flat_map(|cu| cu.subprograms()).collect()
    }

    /// Extract all global variable DIEs.
    #[must_use]
    pub fn extract_variables(cus: &[DwarfCompileUnit]) -> Vec<&DwarfDie> {
        cus.iter().flat_map(|cu| cu.variables()).collect()
    }

    /// Parse the line number table from `.debug_line`.
    ///
    /// Fully decodes the DWARF 2–4 line-number program (header, standard,
    /// extended and special opcodes). For DWARF 5 headers (or malformed
    /// programs) it falls back to a heuristic file-name scan so callers still
    /// get file names.
    ///
    /// # Errors
    ///
    /// Currently infallible (fallback path absorbs malformed input); the
    /// `Result` is kept for API stability.
    pub fn parse_line_table(&self) -> Result<DwarfLineTable> {
        let data = &self.sections.debug_line;
        if data.is_empty() {
            return Ok(DwarfLineTable::new());
        }
        // `.debug_line` holds one line-number program per compilation unit,
        // laid end to end. Parsing only the first left every other CU's
        // addresses unresolvable.
        let mut merged = DwarfLineTable::new();
        let mut cursor = 0usize;
        let mut any = false;
        while cursor + 4 <= data.len() {
            let Ok(len_bytes) = data[cursor..cursor + 4].try_into() else {
                break;
            };
            let unit_length = u32::from_le_bytes(len_bytes) as usize;
            // 0xffff_ffff introduces a 64-bit-format unit, which
            // `parse_line_program` does not decode; stop rather than
            // misinterpret the rest of the section.
            if unit_length == 0 || unit_length == 0xffff_ffff {
                break;
            }
            let Some(end) = cursor.checked_add(4 + unit_length) else {
                break;
            };
            if end > data.len() {
                break;
            }
            if let Some(table) = Self::parse_line_program(&data[cursor..end]) {
                // File indices are per-program, so rebase this program's
                // entries onto the shared, concatenated file_names list.
                let base = u32::try_from(merged.file_names.len()).unwrap_or(u32::MAX);
                merged.file_names.extend(table.file_names);
                merged.entries.extend(table.entries.into_iter().map(|mut e| {
                    e.file_index = e.file_index.saturating_add(base);
                    e
                }));
                any = true;
            }
            // Guard against a non-advancing cursor.
            if end <= cursor {
                break;
            }
            cursor = end;
        }
        if any {
            return Ok(merged);
        }
        Ok(Self::scan_line_strings(data))
    }

    /// Decode a DWARF 2–4 line-number program. Returns `None` on any
    /// structural problem (caller falls back to the heuristic scan).
    ///
    /// Split in two: [`Self::parse_line_program_header`] decodes the fixed
    /// header plus the file-name table, and [`Self::run_line_program`] executes
    /// the opcode stream against the state machine those values configure.
    fn parse_line_program(data: &[u8]) -> Option<DwarfLineTable> {
        let (header, mut table, pos) = Self::parse_line_program_header(data)?;
        // The program proper starts after the header; a header_length that
        // disagrees with what was consumed is tolerated as long as it stays
        // inside the unit.
        let program_start = 10 + header.header_length;
        if program_start > header.end {
            return None;
        }
        let pc = program_start.max(pos);
        Self::run_line_program(data, &header, &mut table, pc);
        Some(table)
    }

    /// Decode the DWARF 2–4 line-program header and its file-name table.
    ///
    /// Returns the decoded header, a table pre-populated with the file names,
    /// and the offset just past the last header byte consumed.
    fn parse_line_program_header(
        data: &[u8],
    ) -> Option<(LineProgramHeader, DwarfLineTable, usize)> {
        if data.len() < 15 {
            return None;
        }
        let unit_length = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if unit_length == 0xffff_ffff {
            return None; // 64-bit DWARF unsupported
        }
        let end = (4 + unit_length).min(data.len());
        let version = u16::from_le_bytes(data[4..6].try_into().ok()?);
        if !(2..=4).contains(&version) {
            return None; // v5 header layout differs — fallback
        }
        let header_length = u32::from_le_bytes(data[6..10].try_into().ok()?) as usize;
        let mut pos = 10;
        let min_inst_length = *data.get(pos)?;
        pos += 1;
        if version >= 4 {
            pos += 1; // maximum_operations_per_instruction
        }
        let default_is_stmt = *data.get(pos)? != 0;
        pos += 1;
        // `line_base` is a *signed* byte: reinterpreting the byte's bit pattern
        // is the specified decoding, so it is spelled as a byte-level decode
        // rather than a wrapping `as i8` cast.
        let line_base = i8::from_le_bytes([*data.get(pos)?]);
        pos += 1;
        let line_range = *data.get(pos)?;
        pos += 1;
        let opcode_base = *data.get(pos)?;
        pos += 1;
        if line_range == 0 || opcode_base == 0 {
            return None;
        }
        // standard_opcode_lengths
        let std_lengths: Vec<u8> = data.get(pos..pos + usize::from(opcode_base) - 1)?.to_vec();
        pos += usize::from(opcode_base) - 1;

        let mut table = DwarfLineTable::new();
        // include_directories: sequence of nul-terminated strings, empty ends.
        loop {
            let nul = data.get(pos..)?.iter().position(|&b| b == 0)?;
            if nul == 0 {
                pos += 1;
                break;
            }
            pos += nul + 1; // directories recorded implicitly via file entries
        }
        // file_names: name, dir(uleb), mtime(uleb), size(uleb); empty name ends.
        loop {
            let rest = data.get(pos..)?;
            let nul = rest.iter().position(|&b| b == 0)?;
            if nul == 0 {
                pos += 1;
                break;
            }
            let name = String::from_utf8_lossy(&rest[..nul]).into_owned();
            pos += nul + 1;
            let _dir = read_uleb128(data, &mut pos)?;
            let _mtime = read_uleb128(data, &mut pos)?;
            let _size = read_uleb128(data, &mut pos)?;
            table.add_file(name);
        }

        Some((
            LineProgramHeader {
                end,
                header_length,
                min_inst_length,
                default_is_stmt,
                line_base,
                line_range,
                opcode_base,
                std_lengths,
            },
            table,
            pos,
        ))
    }

    /// Execute the line-number opcode stream from `pc` to the end of the unit,
    /// appending every emitted row to `table`.
    ///
    /// Runs to the end of the program on well-formed input and stops early —
    /// leaving the rows decoded so far in place — on a malformed operand, which
    /// is the same tolerance the surrounding parser applies elsewhere.
    fn run_line_program(
        data: &[u8],
        header: &LineProgramHeader,
        table: &mut DwarfLineTable,
        mut pc: usize,
    ) {
        let mut state = LineMachine::new(header.default_is_stmt);
        while pc < header.end {
            let Some(&opcode) = data.get(pc) else { return };
            pc += 1;
            if opcode >= header.opcode_base {
                state.apply_special(header, opcode - header.opcode_base);
                state.emit(table, false);
            } else if opcode == 0 {
                let Some(next) = Self::run_extended_opcode(data, header, table, &mut state, pc)
                else {
                    return;
                };
                pc = next;
            } else {
                let Some(next) = Self::run_standard_opcode(data, header, table, &mut state, opcode, pc)
                else {
                    return;
                };
                pc = next;
            }
        }
    }

    /// Execute one extended (`opcode 0`) instruction, returning the offset of
    /// the next instruction, or `None` if the operand is malformed.
    fn run_extended_opcode(
        data: &[u8],
        header: &LineProgramHeader,
        table: &mut DwarfLineTable,
        state: &mut LineMachine,
        mut pc: usize,
    ) -> Option<usize> {
        let len = usize::try_from(read_uleb128(data, &mut pc)?).ok()?;
        if len == 0 || pc + len > data.len() {
            return None;
        }
        match *data.get(pc)? {
            1 => {
                // DW_LNE_end_sequence
                state.emit(table, true);
                state.reset(header.default_is_stmt);
            }
            2 => {
                // DW_LNE_set_address: address size = len - 1
                let n = (len - 1).min(8);
                let mut buf = [0u8; 8];
                buf[..n].copy_from_slice(data.get(pc + 1..pc + 1 + n)?);
                state.address = u64::from_le_bytes(buf);
            }
            _ => {} // DW_LNE_define_file and vendor opcodes: skip
        }
        Some(pc + len)
    }

    /// Execute one standard opcode, returning the offset of the next
    /// instruction, or `None` if an operand is malformed.
    fn run_standard_opcode(
        data: &[u8],
        header: &LineProgramHeader,
        table: &mut DwarfLineTable,
        state: &mut LineMachine,
        opcode: u8,
        mut pc: usize,
    ) -> Option<usize> {
        match opcode {
            1 => state.emit(table, false), // DW_LNS_copy
            2 => {
                let adv = read_uleb128(data, &mut pc)?;
                state.advance_address(adv, header.min_inst_length);
            }
            3 => state.line += read_sleb128(data, &mut pc)?,
            4 => state.file = read_uleb128(data, &mut pc)?,
            5 => state.column = read_uleb128(data, &mut pc)?,
            6 => state.is_stmt = !state.is_stmt,
            8 => {
                // const_add_pc: like special opcode 255 address advance
                let adj = u64::from(255 - header.opcode_base);
                state.advance_address(adj / u64::from(header.line_range), header.min_inst_length);
            }
            9 => {
                let adv = u16::from_le_bytes(data.get(pc..pc + 2)?.try_into().ok()?);
                pc += 2;
                state.address = state.address.wrapping_add(u64::from(adv));
            }
            // `DW_LNS_set_basic_block` (7), `DW_LNS_set_prologue_end` (10) and
            // `DW_LNS_set_epilogue_begin` (11) all set flags this table does not
            // carry, so each is a no-op with no operands to skip.
            7 | 10 | 11 => {}
            12 => {
                let _isa = read_uleb128(data, &mut pc)?;
            }
            other => {
                // Unknown standard opcode: skip its uleb operands.
                let n_args = header
                    .std_lengths
                    .get(usize::from(other) - 1)
                    .copied()
                    .unwrap_or(0);
                for _ in 0..n_args {
                    let _ = read_uleb128(data, &mut pc)?;
                }
            }
        }
        Some(pc)
    }

    /// Heuristic fallback: scan `.debug_line` for file-name-looking strings.
    fn scan_line_strings(data: &[u8]) -> DwarfLineTable {
        let mut table = DwarfLineTable::new();
        let mut i = 0;
        while i < data.len() {
            if data[i].is_ascii_graphic() {
                let start = i;
                while i < data.len() && data[i] != 0 {
                    i += 1;
                }
                if i - start > 1
                    && i - start < 256
                    && let Ok(s) = std::str::from_utf8(&data[start..i])
                    && (s.contains('.') || s.contains('/'))
                {
                    table.add_file(s.to_string());
                }
            }
            i += 1;
        }
        table
    }
}

// ── DwarfSymbolProvider ───────────────────────────────────────────────────────

/// Implements [`SymbolProvider`] for DWARF debug information.
#[derive(Debug)]
pub struct DwarfSymbolProvider {
    name: String,
    symbols: Vec<Symbol>,
    line_table: DwarfLineTable,
    compile_units: Vec<DwarfCompileUnit>,
    split_dwo_paths: Vec<PathBuf>,
    /// `name → index into symbols` (first occurrence wins).
    by_name: HashMap<String, usize>,
    /// `(address, index into symbols)` sorted ascending, for O(log n) lookups.
    addr_sorted: Vec<(u64, usize)>,
}

impl DwarfSymbolProvider {
    /// Create an empty provider identified by `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            symbols: Vec::new(),
            line_table: DwarfLineTable::new(),
            compile_units: Vec::new(),
            split_dwo_paths: Vec::new(),
            by_name: HashMap::new(),
            addr_sorted: Vec::new(),
        }
    }

    /// Rebuild the name / address lookup indexes from `symbols`.
    fn rebuild_index(&mut self) {
        self.by_name.clear();
        self.addr_sorted.clear();
        self.addr_sorted.reserve(self.symbols.len());
        for (i, s) in self.symbols.iter().enumerate() {
            self.by_name.entry(s.name.clone()).or_insert(i);
            self.addr_sorted.push((s.address, i));
        }
        self.addr_sorted.sort_unstable();
    }

    /// Construct from pre-parsed compile units.
    ///
    /// # Errors
    ///
    /// Currently infallible; the `Result` is reserved for future error returns when DWARF
    /// validation is added.
    pub fn from_compile_units(
        name: impl Into<String>,
        cus: Vec<DwarfCompileUnit>,
        _sections: &DwarfSections,
    ) -> Self {
        let mut p = Self::new(name);
        // Convert subprograms → Symbol
        for cu in &cus {
            for die in cu.subprograms() {
                if die.is_declaration() {
                    continue;
                }
                // A DIE whose DW_AT_name is an unresolved DWARF 5 indexed
                // string yields None here; emitting it as "?" produced a table
                // of identically-named symbols, so skip it instead.
                if let (Some(low), Some(name)) = (die.low_pc(), die.name()) {
                    let sym_name = name.to_string();
                    let size = die.function_size(low);
                    let mut sym = Symbol::new(sym_name, low, SymKind::Function);
                    sym.size = size;
                    sym.source = LegacySymbolSource::Debug;
                    sym.binding = if die.is_external() {
                        SymbolBinding::Global
                    } else {
                        SymbolBinding::Local
                    };
                    // Source location. `DW_AT_decl_file` is an index into the
                    // CU line-program file_names table, NOT a .debug_str
                    // offset, so it cannot be resolved here (the line table is
                    // not parsed yet). `resolve_source_files` fills it in once
                    // the line table is available; until then it stays None.
                    if let Some(line) = die.decl_line() {
                        sym.source_line = Some(u32::try_from(line).unwrap_or(u32::MAX));
                    }
                    p.symbols.push(sym);
                }
            }
            // Globals: address comes from DW_AT_location (DW_OP_addr), not
            // from DW_AT_low_pc, which DW_TAG_variable never carries. Stack
            // locals (DW_OP_fbreg) and register locations yield None and are
            // skipped.
            for die in cu.variables() {
                if die.is_declaration() {
                    continue;
                }
                if let (Some(addr), Some(name)) = (die.static_address(cu.address_size), die.name())
                {
                    let mut sym = Symbol::new(name.to_string(), addr, SymKind::Data);
                    sym.size = die.byte_size();
                    sym.source = LegacySymbolSource::Debug;
                    p.symbols.push(sym);
                }
            }
        }
        p.compile_units = cus;
        p.rebuild_index();
        p
    }

    /// Load DWARF sections from a pre-split binary blob (e.g. .`debug_info` extracted).
    ///
    /// # Errors
    ///
    /// Propagates errors from CU parsing or line-table decoding.
    pub fn from_sections(name: impl Into<String>, sections: &DwarfSections) -> Result<Self> {
        let parser = DwarfParser::new(sections, false);
        let cus = parser.parse_compile_units()?;
        let mut p = Self::from_compile_units(name, cus, sections);
        p.line_table = parser.parse_line_table()?;
        p.resolve_source_files();
        Ok(p)
    }

    /// Resolve `DW_AT_decl_file` indices for function symbols against the
    /// line-table `file_names` (1-based for DWARF 2-4, 0-based for DWARF 5).
    fn resolve_source_files(&mut self) {
        let mut decl_files: HashMap<u64, (u16, u64)> = HashMap::new();
        for cu in &self.compile_units {
            for die in cu.subprograms() {
                if let (Some(low), Some(idx)) = (die.low_pc(), die.decl_file()) {
                    decl_files.insert(low, (cu.version, idx));
                }
            }
        }
        let line_table = &self.line_table;
        for sym in &mut self.symbols {
            if sym.kind == SymKind::Function
                && sym.source_file.is_none()
                && let Some(&(version, idx)) = decl_files.get(&sym.address)
            {
                sym.source_file = line_table.file_name_for_index(version, idx);
            }
        }
    }

    /// Load DWARF debug info from an on-disk container (object file path).
    ///
    /// Stub: registers `path` as the provider name and returns an empty provider.
    /// Real implementations should slice the container into [`DwarfSections`]
    /// and feed [`Self::from_sections`].
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future error returns when on-disk loading is implemented.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Ok(Self::new(path.to_string_lossy()))
    }

    /// Project the provider's [`Symbol`] list into the spec §7 [`UnifiedSymbol`]
    /// taxonomy.  Function/data binding becomes [`SymbolKind`], the source is
    /// stamped as [`SymbolSource::Dwarf`], and external linkage maps to
    /// [`SymbolVisibility::Default`] vs. [`SymbolVisibility::Hidden`].
    #[must_use]
    pub fn to_unified_symbols(&self) -> Vec<UnifiedSymbol> {
        self.symbols
            .iter()
            .map(|s| {
                // Shared with STABS and the merger: one exhaustive table instead
                // of three copies whose catch-alls disagreed.
                let kind = crate::symbol_merger::legacy_to_unified_kind(s.kind);
                let mut u =
                    UnifiedSymbol::new(s.name.clone(), s.address, kind, SymbolSource::Dwarf);
                u.size = s.size;
                // Visibility hint flows into the module tag so downstream consumers
                // can recover the binding/visibility relationship.
                let vis = match s.binding {
                    SymbolBinding::Local => SymbolVisibility::Hidden,
                    _ => SymbolVisibility::Default,
                };
                u.module = Some(format!("dwarf:{vis}"));
                u.is_external = matches!(s.binding, SymbolBinding::Global | SymbolBinding::Weak);
                u
            })
            .collect()
    }

    // ── Mutation helpers ─────────────────────────────────────────────────────

    /// Append a symbol and incrementally update the name/address indexes.
    pub fn add_symbol(&mut self, sym: Symbol) {
        self.symbols.push(sym);
        let idx = self.symbols.len() - 1;
        let s = &self.symbols[idx];
        self.by_name.entry(s.name.clone()).or_insert(idx);
        let key = (s.address, idx);
        let pos = self.addr_sorted.partition_point(|&e| e <= key);
        self.addr_sorted.insert(pos, key);
    }
    /// Register the path of a split-DWARF `.dwo` file this provider depends on.
    pub fn add_split_dwo(&mut self, path: impl Into<PathBuf>) {
        self.split_dwo_paths.push(path.into());
    }
    /// Replace the line table and re-resolve function source files against it.
    pub fn set_line_table(&mut self, table: DwarfLineTable) {
        self.line_table = table;
        self.resolve_source_files();
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The parsed compile units.
    #[must_use]
    pub fn compile_units(&self) -> &[DwarfCompileUnit] {
        &self.compile_units
    }
    /// Paths of the split-DWARF `.dwo` files this provider references.
    #[must_use]
    pub fn split_dwo_paths(&self) -> &[PathBuf] {
        &self.split_dwo_paths
    }
    /// The provider's line-number table.
    #[must_use]
    pub const fn line_table(&self) -> &DwarfLineTable {
        &self.line_table
    }
    /// Number of symbols held.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
    /// Number of compile units held.
    #[must_use]
    pub const fn cu_count(&self) -> usize {
        self.compile_units.len()
    }
}

impl SymbolProvider for DwarfSymbolProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.by_name.get(name).map(|&i| self.symbols[i].clone())
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        let start = self.addr_sorted.partition_point(|&(a, _)| a < addr);
        let &(a, i) = self.addr_sorted.get(start)?;
        (a == addr).then(|| self.symbols[i].clone())
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        let ub = self.addr_sorted.partition_point(|&(a, _)| a <= addr);
        let &(best, _) = self.addr_sorted[..ub].last()?;
        let start = self.addr_sorted[..ub].partition_point(|&(a, _)| a < best);
        Some(self.symbols[self.addr_sorted[start].1].clone())
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
        self.line_table.source_at(addr)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sym(name: &str, addr: u64) -> Symbol {
        Symbol::new(name.to_string(), addr, SymKind::Function)
    }

    fn make_die(
        tag: DwarfTag,
        name: Option<&str>,
        low: Option<u64>,
        size: Option<u64>,
    ) -> DwarfDie {
        let mut d = DwarfDie::new(0, tag);
        if let Some(n) = name {
            d.set_attr(DW_AT_NAME, DwarfAttrValue::String(n.to_string()));
        }
        if let Some(lo) = low {
            d.set_attr(DW_AT_LOW_PC, DwarfAttrValue::Address(lo));
        }
        if let Some(hi) = size {
            d.set_attr(DW_AT_HIGH_PC, DwarfAttrValue::Udata(hi));
        }
        d
    }

    // ── DwarfTag ──────────────────────────────────────────────────────────────

    #[test]
    fn tag_subprogram() {
        assert_eq!(DwarfTag::from_u16(DW_TAG_SUBPROGRAM), DwarfTag::Subprogram);
    }
    #[test]
    fn tag_compile_unit() {
        assert_eq!(
            DwarfTag::from_u16(DW_TAG_COMPILE_UNIT),
            DwarfTag::CompileUnit
        );
    }
    #[test]
    fn tag_variable() {
        assert_eq!(DwarfTag::from_u16(DW_TAG_VARIABLE), DwarfTag::Variable);
    }
    #[test]
    fn tag_unknown() {
        assert!(matches!(
            DwarfTag::from_u16(0xffff),
            DwarfTag::Unknown(0xffff)
        ));
    }
    #[test]
    fn tag_roundtrip() {
        let tags = [
            DwarfTag::Subprogram,
            DwarfTag::Variable,
            DwarfTag::CompileUnit,
        ];
        for t in tags {
            assert_eq!(DwarfTag::from_u16(t.tag_number()), t);
        }
    }
    #[test]
    fn tag_display() {
        assert!(DwarfTag::Subprogram.to_string().contains("Subprogram"));
    }

    // ── DwarfAttrValue ────────────────────────────────────────────────────────

    #[test]
    fn attr_address() {
        let v = DwarfAttrValue::Address(0x1000);
        assert_eq!(v.as_address(), Some(0x1000));
    }
    #[test]
    fn attr_string() {
        let v = DwarfAttrValue::String("foo".into());
        assert_eq!(v.as_str(), Some("foo"));
    }
    #[test]
    fn attr_flag() {
        let v = DwarfAttrValue::Flag(true);
        assert_eq!(v.as_bool(), Some(true));
    }
    #[test]
    fn attr_udata_as_u64() {
        let v = DwarfAttrValue::Udata(42);
        assert_eq!(v.as_u64(), Some(42));
    }
    #[test]
    fn attr_unknown_as_address() {
        assert_eq!(DwarfAttrValue::Unknown.as_address(), None);
    }

    // ── DwarfDie ──────────────────────────────────────────────────────────────

    #[test]
    fn die_new() {
        let d = DwarfDie::new(0, DwarfTag::Subprogram);
        assert_eq!(d.tag, DwarfTag::Subprogram);
    }
    #[test]
    fn die_name() {
        let d = make_die(DwarfTag::Subprogram, Some("main"), None, None);
        assert_eq!(d.name(), Some("main"));
    }
    #[test]
    fn die_low_pc() {
        let d = make_die(DwarfTag::Subprogram, None, Some(0x1000), None);
        assert_eq!(d.low_pc(), Some(0x1000));
    }
    #[test]
    fn die_function_size_from_high_pc_absolute() {
        let mut d = make_die(DwarfTag::Subprogram, None, Some(0x1000), None);
        d.set_attr(DW_AT_HIGH_PC, DwarfAttrValue::Address(0x1100));
        assert_eq!(d.function_size(0x1000), Some(0x100));
    }
    #[test]
    fn die_function_size_from_high_pc_offset() {
        let d = make_die(DwarfTag::Subprogram, None, Some(0x1000), Some(0x80));
        assert_eq!(d.function_size(0x1000), Some(0x80));
    }
    #[test]
    fn die_function_size_length_exceeding_low_pc() {
        // Udata (constant form) is always a length, even when >= low_pc.
        // The old heuristic returned len - low here (0x100 instead of 0x500).
        let d = make_die(DwarfTag::Subprogram, None, Some(0x400), Some(0x500));
        assert_eq!(d.function_size(0x400), Some(0x500));
    }
    #[test]
    fn die_function_size_address_below_low_is_none() {
        let mut d = make_die(DwarfTag::Subprogram, None, Some(0x2000), None);
        d.set_attr(DW_AT_HIGH_PC, DwarfAttrValue::Address(0x1000));
        assert_eq!(d.function_size(0x2000), None);
    }
    #[test]
    fn line_table_file_name_for_index_versions() {
        let mut t = DwarfLineTable::new();
        t.add_file("a.c");
        t.add_file("b.c");
        // DWARF 2-4: 1-based, 0 means "no file".
        assert_eq!(t.file_name_for_index(4, 1), Some("a.c".into()));
        assert_eq!(t.file_name_for_index(4, 2), Some("b.c".into()));
        assert_eq!(t.file_name_for_index(4, 0), None);
        // DWARF 5: 0-based.
        assert_eq!(t.file_name_for_index(5, 0), Some("a.c".into()));
        assert_eq!(t.file_name_for_index(5, 3), None);
    }
    #[test]
    fn line_table_source_at_out_of_order_insertion() {
        let mut t = DwarfLineTable::new();
        t.add_file("a.c");
        for addr in [0x3000u64, 0x1000, 0x2000] {
            t.add_entry(DwarfLineEntry {
                address: addr,
                file_index: 0,
                line: u32::try_from(addr).unwrap(),
                column: 0,
                is_stmt: true,
                end_sequence: false,
            });
        }
        assert_eq!(t.source_at(0x2500).unwrap().line, 0x2000);
        assert!(t.source_at(0x0fff).is_none());
    }
    #[test]
    fn provider_resolves_decl_file_from_line_table() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        let mut d = make_die(DwarfTag::Subprogram, Some("main"), Some(0x1000), Some(0x80));
        d.set_attr(DW_AT_DECL_FILE, DwarfAttrValue::Udata(1));
        cu.dies.insert(0, d);
        let sections = DwarfSections::new();
        let mut p = DwarfSymbolProvider::from_compile_units("t", vec![cu], &sections);
        // Line table not yet available: source_file must stay None (never a
        // bogus .debug_str tail).
        assert!(p.lookup_name("main").unwrap().source_file.is_none());
        let mut lt = DwarfLineTable::new();
        lt.add_file("main.c");
        p.set_line_table(lt);
        assert_eq!(
            p.lookup_name("main").unwrap().source_file.as_deref(),
            Some("main.c")
        );
    }
    #[test]
    fn provider_indexed_lookups() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_symbol(make_sym("f1", 0x1000));
        p.add_symbol(make_sym("f2", 0x2000));
        p.add_symbol(make_sym("f0", 0x500));
        assert_eq!(p.lookup_name("f2").unwrap().address, 0x2000);
        assert_eq!(p.lookup_address(0x1000).unwrap().name, "f1");
        assert!(p.lookup_address(0x1001).is_none());
        assert_eq!(p.lookup_nearest(0x1fff).unwrap().name, "f1");
        assert_eq!(p.lookup_nearest(0x2000).unwrap().name, "f2");
        assert!(p.lookup_nearest(0x4ff).is_none());
    }
    #[test]
    fn die_is_external_true() {
        let mut d = DwarfDie::new(0, DwarfTag::Subprogram);
        d.set_attr(DW_AT_EXTERNAL, DwarfAttrValue::Flag(true));
        assert!(d.is_external());
    }
    #[test]
    fn die_is_declaration_false() {
        let d = DwarfDie::new(0, DwarfTag::Subprogram);
        assert!(!d.is_declaration());
    }
    #[test]
    fn die_get_attr() {
        let d = make_die(DwarfTag::Variable, Some("g_count"), Some(0x5000), None);
        assert!(d.get_attr(DW_AT_NAME).is_some());
        assert!(d.get_attr(0xdead).is_none());
    }

    // ── DwarfCompileUnit ──────────────────────────────────────────────────────

    #[test]
    fn cu_new() {
        let cu = DwarfCompileUnit::new(0, 4, 0, 8);
        assert_eq!(cu.version, 4);
        assert_eq!(cu.address_size, 8);
    }
    #[test]
    fn cu_add_get_die() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        cu.add_die(make_die(
            DwarfTag::Subprogram,
            Some("main"),
            Some(0x1000),
            Some(0x100),
        ));
        assert_eq!(cu.subprograms().len(), 1);
    }
    #[test]
    fn cu_variables() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        cu.add_die(make_die(
            DwarfTag::Variable,
            Some("g_x"),
            Some(0x4000),
            None,
        ));
        assert_eq!(cu.variables().len(), 1);
    }
    #[test]
    fn cu_split_dwarf_flag() {
        let cu = DwarfCompileUnit::new(0, 5, 0, 8);
        assert!(!cu.has_split_dwarf);
    }

    // ── DwarfLineTable ────────────────────────────────────────────────────────

    #[test]
    fn line_table_empty() {
        let t = DwarfLineTable::new();
        assert!(t.source_at(0x1000).is_none());
    }
    #[test]
    fn line_table_source_at() {
        let mut t = DwarfLineTable::new();
        t.add_file("main.c");
        t.add_entry(DwarfLineEntry {
            address: 0x1000,
            file_index: 0,
            line: 10,
            column: 1,
            is_stmt: true,
            end_sequence: false,
        });
        t.add_entry(DwarfLineEntry {
            address: 0x1010,
            file_index: 0,
            line: 11,
            column: 1,
            is_stmt: true,
            end_sequence: false,
        });
        let loc = t.source_at(0x1008).unwrap();
        assert_eq!(loc.file, "main.c");
        assert_eq!(loc.line, 10);
    }
    #[test]
    fn line_table_end_sequence_skipped() {
        let mut t = DwarfLineTable::new();
        t.add_file("f.c");
        t.add_entry(DwarfLineEntry {
            address: 0x100,
            file_index: 0,
            line: 1,
            column: 0,
            is_stmt: true,
            end_sequence: true,
        });
        assert!(t.source_at(0x100).is_none());
    }

    // ── DwarfSections ─────────────────────────────────────────────────────────

    #[test]
    fn sections_has_debug_info() {
        let mut s = DwarfSections::new();
        assert!(!s.has_debug_info());
        s.debug_info.push(1);
        assert!(s.has_debug_info());
    }
    #[test]
    fn sections_resolve_strp() {
        let mut s = DwarfSections::new();
        s.debug_str = b"hello\0world\0".to_vec();
        assert_eq!(s.resolve_strp(0), Some("hello".into()));
        assert_eq!(s.resolve_strp(6), Some("world".into()));
    }
    #[test]
    fn sections_resolve_strp_oob() {
        let s = DwarfSections::new();
        assert!(s.resolve_strp(99).is_none());
    }

    // ── DwarfParser ───────────────────────────────────────────────────────────

    #[test]
    fn parser_empty_sections() {
        let s = DwarfSections::new();
        let p = DwarfParser::new(&s, false);
        assert_eq!(p.parse_compile_units().unwrap().len(), 0);
    }
    #[test]
    fn parser_too_short_err() {
        let mut s = DwarfSections::new();
        s.debug_info = vec![0; 5];
        let p = DwarfParser::new(&s, false);
        assert!(p.parse_compile_units().is_err());
    }
    #[test]
    fn parser_valid_stub_cu() {
        let mut s = DwarfSections::new();
        // Minimal CU header: unit_length=20(u32), version=4(u16), abbrev_offset=0(u32), addr_size=8(u8)
        let mut data = vec![20u8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8];
        // Pad to unit_length+4 = 24
        data.extend(vec![0u8; 13]);
        s.debug_info = data;
        let p = DwarfParser::new(&s, false);
        let cus = p.parse_compile_units().unwrap();
        assert_eq!(cus.len(), 1);
        assert_eq!(cus[0].version, 4);
    }
    #[test]
    fn parser_invalid_version() {
        let mut s = DwarfSections::new();
        let mut data = vec![20u8, 0, 0, 0];
        data.extend_from_slice(&[9u8, 0]); // version 9
        data.extend(vec![0u8; 18]);
        s.debug_info = data;
        let p = DwarfParser::new(&s, false);
        assert!(matches!(
            p.parse_compile_units(),
            Err(DwarfError::InvalidVersion(9))
        ));
    }
    #[test]
    fn parser_line_table_empty() {
        let s = DwarfSections::new();
        let p = DwarfParser::new(&s, false);
        assert!(p.parse_line_table().unwrap().entries.is_empty());
    }

    // ── DwarfSymbolProvider ───────────────────────────────────────────────────

    #[test]
    fn provider_new_empty() {
        let p = DwarfSymbolProvider::new("libc.so");
        assert_eq!(p.symbol_count(), 0);
    }
    #[test]
    fn provider_add_symbol() {
        let mut p = DwarfSymbolProvider::new("libc.so");
        p.add_symbol(make_sym("main", 0x1000));
        assert_eq!(p.symbol_count(), 1);
    }
    #[test]
    fn provider_lookup_name() {
        let mut p = DwarfSymbolProvider::new("test");
        p.add_symbol(make_sym("foo", 0x100));
        p.add_symbol(make_sym("bar", 0x200));
        assert!(p.lookup_name("foo").is_some());
        assert!(p.lookup_name("baz").is_none());
    }
    #[test]
    fn provider_lookup_address() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_symbol(make_sym("f", 0x400));
        assert!(p.lookup_address(0x400).is_some());
        assert!(p.lookup_address(0x401).is_none());
    }
    #[test]
    fn provider_lookup_nearest() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_symbol(make_sym("a", 0x1000));
        p.add_symbol(make_sym("b", 0x3000));
        assert_eq!(p.lookup_nearest(0x2000).unwrap().name, "a");
    }
    #[test]
    fn provider_all_symbols() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_symbol(make_sym("x", 0x100));
        p.add_symbol(make_sym("y", 0x200));
        assert_eq!(p.all_symbols().len(), 2);
    }
    #[test]
    fn provider_all_functions() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_symbol(make_sym("f", 0x100));
        let mut d = make_sym("g_var", 0x200);
        d.kind = SymKind::Data;
        p.add_symbol(d);
        assert_eq!(p.all_functions().len(), 1);
    }
    #[test]
    fn provider_source_line_none() {
        let p = DwarfSymbolProvider::new("t");
        assert!(p.source_line_for_address(0x1000).is_none());
    }
    #[test]
    fn provider_source_line_from_table() {
        let mut p = DwarfSymbolProvider::new("t");
        let mut lt = DwarfLineTable::new();
        lt.add_file("main.c");
        lt.add_entry(DwarfLineEntry {
            address: 0x1000,
            file_index: 0,
            line: 42,
            column: 0,
            is_stmt: true,
            end_sequence: false,
        });
        p.set_line_table(lt);
        let loc = p.source_line_for_address(0x1000).unwrap();
        assert_eq!(loc.line, 42);
        assert_eq!(loc.file, "main.c");
    }
    #[test]
    fn provider_add_split_dwo() {
        let mut p = DwarfSymbolProvider::new("t");
        p.add_split_dwo("/path/to/module.dwo");
        assert_eq!(p.split_dwo_paths().len(), 1);
    }
    #[test]
    fn provider_name() {
        let p = DwarfSymbolProvider::new("libc.so.6");
        assert_eq!(p.name(), "libc.so.6");
    }

    // ── From compile units ─────────────────────────────────────────────────────

    #[test]
    fn provider_from_compile_units() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        let mut die = make_die(
            DwarfTag::Subprogram,
            Some("main"),
            Some(0x1000),
            Some(0x100),
        );
        die.set_attr(DW_AT_EXTERNAL, DwarfAttrValue::Flag(true));
        cu.add_die(die);
        let secs = DwarfSections::new();
        let p = DwarfSymbolProvider::from_compile_units("binary", vec![cu], &secs);
        assert!(p.lookup_name("main").is_some());
        let sym = p.lookup_name("main").unwrap();
        assert_eq!(sym.binding, SymbolBinding::Global);
    }
    #[test]
    fn provider_from_compile_units_skips_declarations() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        let mut die = make_die(
            DwarfTag::Subprogram,
            Some("decl_only"),
            Some(0x2000),
            Some(0x10),
        );
        die.set_attr(DW_AT_DECLARATION, DwarfAttrValue::Flag(true));
        cu.add_die(die);
        let p = DwarfSymbolProvider::from_compile_units("b", vec![cu], &DwarfSections::new());
        assert!(p.lookup_name("decl_only").is_none());
    }
    #[test]
    fn provider_from_sections_empty() {
        let p = DwarfSymbolProvider::from_sections("t", &DwarfSections::new()).unwrap();
        assert_eq!(p.symbol_count(), 0);
    }

    // ── LEB128 ────────────────────────────────────────────────────────────────

    #[test]
    fn uleb128_single_and_multi_byte() {
        let mut pos = 0;
        assert_eq!(read_uleb128(&[0x7f], &mut pos), Some(127));
        pos = 0;
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26], &mut pos), Some(624_485));
        assert_eq!(pos, 3);
    }

    #[test]
    fn uleb128_truncated() {
        let mut pos = 0;
        assert_eq!(read_uleb128(&[0x80], &mut pos), None);
    }

    #[test]
    fn sleb128_negative() {
        let mut pos = 0;
        assert_eq!(read_sleb128(&[0x7f], &mut pos), Some(-1));
        pos = 0;
        assert_eq!(read_sleb128(&[0x9b, 0xf1, 0x59], &mut pos), Some(-624_485));
    }

    // ── Abbrev tables ─────────────────────────────────────────────────────────

    fn uleb(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = v;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }

    /// Build a small abbrev table:
    ///   code 1: `compile_unit`, `has_children`, [name:string, `comp_dir:string`]
    ///   code 2: subprogram, no children,
    ///           [name:string, `low_pc:addr`, `high_pc:data8`, external:flag]
    fn test_abbrev_table() -> Vec<u8> {
        let mut a = Vec::new();
        // decl 1
        a.extend(uleb(1));
        a.extend(uleb(u64::from(DW_TAG_COMPILE_UNIT)));
        a.push(1); // has children
        for (at, form) in [(DW_AT_NAME, DW_FORM_STRING), (DW_AT_COMP_DIR, DW_FORM_STRING)] {
            a.extend(uleb(at));
            a.extend(uleb(form));
        }
        a.extend([0, 0]);
        // decl 2
        a.extend(uleb(2));
        a.extend(uleb(u64::from(DW_TAG_SUBPROGRAM)));
        a.push(0); // no children
        for (at, form) in [
            (DW_AT_NAME, DW_FORM_STRING),
            (DW_AT_LOW_PC, DW_FORM_ADDR),
            (DW_AT_HIGH_PC, DW_FORM_DATA8),
            (DW_AT_EXTERNAL, DW_FORM_FLAG),
        ] {
            a.extend(uleb(at));
            a.extend(uleb(form));
        }
        a.extend([0, 0]);
        a.push(0); // end of table
        a
    }

    #[test]
    fn abbrev_table_parses() {
        let data = test_abbrev_table();
        let table = parse_abbrev_table(&data, 0).unwrap();
        assert_eq!(table.len(), 2);
        let cu = &table[&1];
        assert_eq!(cu.tag, DW_TAG_COMPILE_UNIT);
        assert!(cu.has_children);
        assert_eq!(cu.attrs.len(), 2);
        let sp = &table[&2];
        assert_eq!(sp.tag, DW_TAG_SUBPROGRAM);
        assert!(!sp.has_children);
        assert_eq!(sp.attrs.len(), 4);
    }

    /// Build a full synthetic DWARF v4 .`debug_info` with the test abbrev table:
    /// a compile unit "main.c" containing subprogram "main" @0x1000 size 0x40.
    fn synthetic_dwarf_v4() -> DwarfSections {
        let mut body = Vec::new();
        // Root DIE: abbrev code 1
        body.extend(uleb(1));
        body.extend(b"main.c\0");
        body.extend(b"/src\0");
        // Child DIE: abbrev code 2
        body.extend(uleb(2));
        body.extend(b"main\0");
        body.extend(0x1000u64.to_le_bytes()); // low_pc (addr, 8 bytes)
        body.extend(0x40u64.to_le_bytes()); // high_pc as length
        body.push(1); // external = true
        body.push(0); // null DIE: end of root's children

        let mut info = Vec::new();
        let unit_length = 7 + body.len(); // version(2)+abbrev_off(4)+addr_size(1)+body
        info.extend((u32::try_from(unit_length).unwrap()).to_le_bytes());
        info.extend(4u16.to_le_bytes()); // version 4
        info.extend(0u32.to_le_bytes()); // abbrev offset
        info.push(8); // address size
        info.extend(body);

        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = test_abbrev_table();
        s
    }

    /// A GCC skeleton CU whose root carries only `DW_AT_GNU_dwo_id` — no
    /// `DW_AT_GNU_dwo_name`. Before `DW_AT_GNU_DWO_ID` was wired into the
    /// detection it was a declared-but-unreferenced constant, and such a CU came
    /// back with `has_split_dwarf == false`: indistinguishable from an ordinary
    /// empty unit, so the caller never learned the debug info lives in a `.dwo`
    /// it did not load. Dropping the new `else if` makes this assertion fail.
    #[test]
    fn skeleton_cu_with_only_dwo_id_is_flagged_as_split_dwarf() {
        // abbrev: code 1 = DW_TAG_compile_unit, no children, DW_AT_GNU_dwo_id
        // as DW_FORM_data8.
        let mut abbrev = Vec::new();
        abbrev.extend(uleb(1));
        abbrev.extend(uleb(u64::from(DW_TAG_COMPILE_UNIT)));
        abbrev.push(0); // no children
        abbrev.extend(uleb(DW_AT_GNU_DWO_ID));
        abbrev.extend(uleb(DW_FORM_DATA8));
        abbrev.extend([0, 0]);
        abbrev.push(0);

        let mut body = Vec::new();
        body.extend(uleb(1));
        body.extend(0x0123_4567_89AB_CDEFu64.to_le_bytes());

        let mut info = Vec::new();
        let unit_length = 7 + body.len();
        info.extend(u32::try_from(unit_length).unwrap().to_le_bytes());
        info.extend(4u16.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.push(8);
        info.extend(body);

        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = abbrev;
        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        assert_eq!(cus.len(), 1);
        assert!(cus[0].has_split_dwarf, "dwo_id-only skeleton not flagged");
        // No name was present, so none must be invented.
        assert!(cus[0].dwo_name.is_none());
    }

    #[test]
    fn real_parse_v4_cu_and_subprogram() {
        let s = synthetic_dwarf_v4();
        let parser = DwarfParser::new(&s, false);
        let cus = parser.parse_compile_units().unwrap();
        assert_eq!(cus.len(), 1);
        let cu = &cus[0];
        assert_eq!(cu.version, 4);
        assert_eq!(cu.name.as_deref(), Some("main.c"));
        assert_eq!(cu.comp_dir.as_deref(), Some("/src"));
        let subs = cu.subprograms();
        assert_eq!(subs.len(), 1);
        let main = subs[0];
        assert_eq!(main.name(), Some("main"));
        assert_eq!(main.low_pc(), Some(0x1000));
        assert!(main.is_external());
        assert_eq!(main.function_size(0x1000), Some(0x40));
    }

    #[test]
    fn real_parse_root_records_children() {
        let s = synthetic_dwarf_v4();
        let parser = DwarfParser::new(&s, false);
        let cus = parser.parse_compile_units().unwrap();
        let root = cus[0]
            .dies
            .values()
            .find(|d| d.tag == DwarfTag::CompileUnit)
            .unwrap();
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn real_parse_end_to_end_provider() {
        let s = synthetic_dwarf_v4();
        let p = DwarfSymbolProvider::from_sections("bin", &s).unwrap();
        let main = p.lookup_name("main").unwrap();
        assert_eq!(main.address, 0x1000);
        assert_eq!(main.size, Some(0x40));
        assert_eq!(main.binding, SymbolBinding::Global);
        assert_eq!(main.kind, SymKind::Function);
    }

    // ── DWARF 5 indexed forms (strx / addrx) ─────────────────────────────────

    /// Abbrev table using DWARF 5 indexed forms:
    ///   code 1: `compile_unit`, `has_children`,
    ///           [name:strx1, `str_offsets_base:sec_offset`, `addr_base:sec_offset`]
    ///   code 2: subprogram, no children,
    ///           [name:strx1, `low_pc:addrx1`, `high_pc:data8`]
    fn dwarf5_indexed_abbrev() -> Vec<u8> {
        let mut a = Vec::new();
        a.extend(uleb(1));
        a.extend(uleb(u64::from(DW_TAG_COMPILE_UNIT)));
        a.push(1);
        for (at, form) in [
            (DW_AT_NAME, DW_FORM_STRX1),
            (DW_AT_STR_OFFSETS_BASE, DW_FORM_SEC_OFFSET),
            (DW_AT_ADDR_BASE, DW_FORM_SEC_OFFSET),
        ] {
            a.extend(uleb(at));
            a.extend(uleb(form));
        }
        a.extend([0, 0]);
        a.extend(uleb(2));
        a.extend(uleb(u64::from(DW_TAG_SUBPROGRAM)));
        a.push(0);
        for (at, form) in [
            (DW_AT_NAME, DW_FORM_STRX1),
            (DW_AT_LOW_PC, DW_FORM_ADDRX1),
            (DW_AT_HIGH_PC, DW_FORM_DATA8),
        ] {
            a.extend(uleb(at));
            a.extend(uleb(form));
        }
        a.extend([0, 0]);
        a.push(0);
        a
    }

    /// A DWARF 5 CU whose names/addresses use `DW_FORM_strx1`/`DW_FORM_addrx1`,
    /// as clang 16+ and gcc 11+ emit with `-gdwarf-5`.
    fn synthetic_dwarf_v5_indexed(with_index_sections: bool) -> DwarfSections {
        let mut body = Vec::new();
        body.extend(uleb(1));
        body.push(0); // name -> str index 0 ("five.c")
        body.extend(8u32.to_le_bytes()); // DW_AT_str_offsets_base
        body.extend(8u32.to_le_bytes()); // DW_AT_addr_base
        body.extend(uleb(2));
        body.push(1); // name -> str index 1 ("compute")
        body.push(0); // low_pc -> addr index 0
        body.extend(0x40u64.to_le_bytes()); // high_pc as length
        body.push(0); // end of root's children

        let mut info = Vec::new();
        let unit_length = 8 + body.len();
        info.extend(u32::try_from(unit_length).unwrap().to_le_bytes());
        info.extend(5u16.to_le_bytes());
        info.push(1); // DW_UT_compile
        info.push(8); // address size
        info.extend(0u32.to_le_bytes()); // abbrev offset
        info.extend(body);

        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = dwarf5_indexed_abbrev();
        if with_index_sections {
            s.debug_str = b"five.c\0compute\0".to_vec();
            // .debug_str_offsets: 8-byte 32-bit-format header, then u32 entries.
            let mut so = Vec::new();
            so.extend(12u32.to_le_bytes()); // unit_length
            so.extend(5u16.to_le_bytes()); // version
            so.extend(0u16.to_le_bytes()); // padding
            so.extend(0u32.to_le_bytes()); // index 0 -> "five.c"
            so.extend(7u32.to_le_bytes()); // index 1 -> "compute"
            s.debug_str_offsets = so;
            // .debug_addr: 8-byte header, then address_size entries.
            let mut ad = Vec::new();
            ad.extend(12u32.to_le_bytes());
            ad.extend(5u16.to_le_bytes());
            ad.push(8); // address_size
            ad.push(0); // segment_selector_size
            ad.extend(0x40_1000u64.to_le_bytes()); // index 0
            s.debug_addr = ad;
        }
        s
    }

    #[test]
    fn dwarf5_strx_and_addrx_are_resolved() {
        let s = synthetic_dwarf_v5_indexed(true);
        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        assert_eq!(cus.len(), 1);
        let cu = &cus[0];
        assert_eq!(cu.name.as_deref(), Some("five.c"));
        assert_eq!(cu.str_offsets_base, 8);
        assert_eq!(cu.addr_base, 8);
        let subs = cu.subprograms();
        assert_eq!(subs.len(), 1);
        // Before the fix these were None / Some(0) (the raw .debug_addr index).
        assert_eq!(subs[0].name(), Some("compute"));
        assert_eq!(subs[0].low_pc(), Some(0x40_1000));
    }

    #[test]
    fn dwarf5_indexed_provider_emits_named_symbol() {
        let s = synthetic_dwarf_v5_indexed(true);
        let p = DwarfSymbolProvider::from_sections("bin", &s).unwrap();
        let sym = p.lookup_name("compute").unwrap();
        assert_eq!(sym.address, 0x40_1000);
        assert_eq!(sym.size, Some(0x40));
        assert!(p.lookup_name("?").is_none());
    }

    #[test]
    fn dwarf5_unresolvable_index_is_not_emitted_as_question_mark() {
        // No .debug_str_offsets / .debug_addr: the indexes stay unresolved, so
        // the symbol must be skipped rather than emitted as "?" at address 0.
        let s = synthetic_dwarf_v5_indexed(false);
        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        let sub = cus[0].subprograms()[0];
        assert!(matches!(
            sub.get_attr(DW_AT_NAME),
            Some(DwarfAttrValue::Strx(1))
        ));
        // An unresolved addrx must never be mistaken for an address.
        assert_eq!(sub.low_pc(), None);
        let p = DwarfSymbolProvider::from_sections("bin", &s).unwrap();
        assert!(p.lookup_name("?").is_none());
    }

    /// Abbrev table with the same indexed forms but NO `DW_AT_str_offsets_base`
    /// / `DW_AT_addr_base` on the root, so both bases must be defaulted.
    fn dwarf5_indexed_abbrev_no_bases() -> Vec<u8> {
        let mut a = Vec::new();
        a.extend(uleb(1));
        a.extend(uleb(u64::from(DW_TAG_COMPILE_UNIT)));
        a.push(1);
        a.extend(uleb(DW_AT_NAME));
        a.extend(uleb(DW_FORM_STRX1));
        a.extend([0, 0]);
        a.extend(uleb(2));
        a.extend(uleb(u64::from(DW_TAG_SUBPROGRAM)));
        a.push(0);
        for (at, form) in [
            (DW_AT_NAME, DW_FORM_STRX1),
            (DW_AT_LOW_PC, DW_FORM_ADDRX1),
            (DW_AT_HIGH_PC, DW_FORM_DATA8),
        ] {
            a.extend(uleb(at));
            a.extend(uleb(form));
        }
        a.extend([0, 0]);
        a.push(0);
        a
    }

    /// A DWARF 5 CU with no base attributes whose index sections use the
    /// 64-bit DWARF format: a `0xffff_ffff` escape, a 16-byte header and
    /// 8-byte `.debug_str_offsets` entries.
    fn synthetic_dwarf_v5_indexed_64bit_tables() -> DwarfSections {
        let mut body = Vec::new();
        body.extend(uleb(1));
        body.push(0); // CU name -> str index 0
        body.extend(uleb(2));
        body.push(1); // subprogram name -> str index 1
        body.push(0); // low_pc -> addr index 0
        body.extend(0x40u64.to_le_bytes());
        body.push(0); // end of root's children

        let mut info = Vec::new();
        let unit_length = 8 + body.len();
        info.extend(u32::try_from(unit_length).unwrap().to_le_bytes());
        info.extend(5u16.to_le_bytes());
        info.push(1); // DW_UT_compile
        info.push(8); // address size
        info.extend(0u32.to_le_bytes()); // abbrev offset
        info.extend(body);

        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = dwarf5_indexed_abbrev_no_bases();
        s.debug_str = b"five.c\0compute\0".to_vec();

        // .debug_str_offsets, 64-bit format: escape + u64 length + version +
        // padding = a 16-byte header, then 8-byte entries.
        let mut so = Vec::new();
        so.extend(0xffff_ffffu32.to_le_bytes());
        so.extend(20u64.to_le_bytes()); // unit_length
        so.extend(5u16.to_le_bytes()); // version
        so.extend(0u16.to_le_bytes()); // padding
        so.extend(0u64.to_le_bytes()); // index 0 -> "five.c"
        so.extend(7u64.to_le_bytes()); // index 1 -> "compute"
        s.debug_str_offsets = so;

        // .debug_addr, 64-bit format: same 16-byte header shape. Entries are
        // address_size wide in both formats.
        let mut ad = Vec::new();
        ad.extend(0xffff_ffffu32.to_le_bytes());
        ad.extend(12u64.to_le_bytes());
        ad.extend(5u16.to_le_bytes());
        ad.push(8); // address_size
        ad.push(0); // segment_selector_size
        ad.extend(0x40_1000u64.to_le_bytes()); // index 0
        s.debug_addr = ad;
        s
    }

    #[test]
    fn absent_bases_default_past_a_64bit_format_header() {
        let s = synthetic_dwarf_v5_indexed_64bit_tables();
        assert_eq!(s.default_str_offsets_base(), 16);
        assert_eq!(s.default_addr_base(), 16);

        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        let cu = &cus[0];
        assert_eq!(cu.str_offsets_base, 16);
        assert_eq!(cu.addr_base, 16);
        let sub = cu.subprograms()[0];
        // With the old unconditional default of 8 the resolver read 8 bytes
        // early: the name came back as "c" (offset 5 of .debug_str, from the
        // version+padding words read as an entry) and low_pc as garbage.
        assert_eq!(sub.name(), Some("compute"));
        assert_eq!(sub.low_pc(), Some(0x40_1000));
    }

    #[test]
    fn default_base_is_8_for_the_32bit_format() {
        let s = synthetic_dwarf_v5_indexed(true);
        assert_eq!(s.default_str_offsets_base(), 8);
        assert_eq!(s.default_addr_base(), 8);
    }

    #[test]
    fn resolve_strx_handles_out_of_range_index() {
        let s = synthetic_dwarf_v5_indexed(true);
        assert_eq!(s.resolve_strx(8, 0).as_deref(), Some("five.c"));
        assert_eq!(s.resolve_strx(8, 99), None);
        assert_eq!(s.resolve_addrx(8, 0, 8), Some(0x40_1000));
        assert_eq!(s.resolve_addrx(8, 99, 8), None);
        assert_eq!(s.resolve_addrx(8, 0, 0), None);
    }

    #[test]
    fn real_parse_v5_header() {
        // DWARF 5 header: length, version=5, unit_type=1 (compile), addr_size, abbrev_off
        let mut body = Vec::new();
        body.extend(uleb(1));
        body.extend(b"five.c\0");
        body.extend(b"/src5\0");
        body.push(0); // end children
        let mut info = Vec::new();
        let unit_length = 8 + body.len(); // version(2)+unit_type(1)+addr(1)+abbrev(4)
        info.extend((u32::try_from(unit_length).unwrap()).to_le_bytes());
        info.extend(5u16.to_le_bytes());
        info.push(1); // unit_type = DW_UT_compile
        info.push(8); // address size
        info.extend(0u32.to_le_bytes()); // abbrev offset
        info.extend(body);
        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = test_abbrev_table();
        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        assert_eq!(cus.len(), 1);
        assert_eq!(cus[0].version, 5);
        assert_eq!(cus[0].name.as_deref(), Some("five.c"));
    }

    #[test]
    fn real_parse_strp_resolves_from_debug_str() {
        // Abbrev: code 1, compile_unit, no children, [name:strp]
        let mut abbrev = Vec::new();
        abbrev.extend(uleb(1));
        abbrev.extend(uleb(u64::from(DW_TAG_COMPILE_UNIT)));
        abbrev.push(0);
        abbrev.extend(uleb(DW_AT_NAME));
        abbrev.extend(uleb(DW_FORM_STRP));
        abbrev.extend([0, 0, 0]);
        let mut body = Vec::new();
        body.extend(uleb(1));
        body.extend(4u32.to_le_bytes()); // strp offset 4 -> "pool.c"
        let mut info = Vec::new();
        info.extend((u32::try_from(7 + body.len()).unwrap()).to_le_bytes());
        info.extend(4u16.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.push(8);
        info.extend(body);
        let mut s = DwarfSections::new();
        s.debug_info = info;
        s.debug_abbrev = abbrev;
        s.debug_str = b"xxx\0pool.c\0".to_vec();
        let cus = DwarfParser::new(&s, false).parse_compile_units().unwrap();
        assert_eq!(cus[0].name.as_deref(), Some("pool.c"));
    }

    #[test]
    fn real_parse_unknown_abbrev_code_errors() {
        let mut s = synthetic_dwarf_v4();
        s.debug_abbrev = vec![0]; // empty table -> code 1 unknown
        let r = DwarfParser::new(&s, false).parse_compile_units();
        assert!(r.is_err());
    }

    // ── Real line-number program ─────────────────────────────────────────────

    /// Handcraft a tiny DWARF v3 line program:
    /// files: `["a.c"]`, `set_address` 0x1000, copy (line 1), `advance_line` +4,
    /// `advance_pc` 0x10, copy (line 5), `end_sequence`.
    fn synthetic_line_program() -> Vec<u8> {
        let mut hdr_tail = vec![
            1,       // min_inst_length
            1,       // default_is_stmt
            0xfb_u8, // line_base = -5
            14,      // line_range
            13,      // opcode_base
        ];
        hdr_tail.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]); // std opcode lengths
        hdr_tail.push(0); // include_directories terminator
        hdr_tail.extend(b"a.c\0"); // file 1
        hdr_tail.extend([0, 0, 0]); // dir, mtime, size ulebs
        hdr_tail.push(0); // file table terminator

        let mut program = Vec::new();
        // DW_LNE_set_address 0x1000
        program.push(0);
        program.extend(uleb(9)); // length: opcode + 8-byte address
        program.push(2);
        program.extend(0x1000u64.to_le_bytes());
        program.push(1); // DW_LNS_copy → row (0x1000, line 1)
        program.push(3); // DW_LNS_advance_line
        program.push(4); // +4 (sleb)
        program.push(2); // DW_LNS_advance_pc
        program.extend(uleb(0x10));
        program.push(1); // copy → row (0x1010, line 5)
        // DW_LNE_end_sequence
        program.push(0);
        program.extend(uleb(1));
        program.push(1);

        let header_length = hdr_tail.len();
        let mut out = Vec::new();
        let unit_length = 2 + 4 + header_length + program.len();
        out.extend((u32::try_from(unit_length).unwrap()).to_le_bytes());
        out.extend(3u16.to_le_bytes()); // version 3
        out.extend((u32::try_from(header_length).unwrap()).to_le_bytes());
        out.extend(hdr_tail);
        out.extend(program);
        out
    }

    #[test]
    fn line_program_decodes_rows() {
        let mut s = DwarfSections::new();
        s.debug_line = synthetic_line_program();
        let t = DwarfParser::new(&s, false).parse_line_table().unwrap();
        assert_eq!(t.file_names, vec!["a.c".to_string()]);
        // 2 copies + 1 end_sequence
        assert_eq!(t.entries.len(), 3);
        assert_eq!(t.entries[0].address, 0x1000);
        assert_eq!(t.entries[0].line, 1);
        assert_eq!(t.entries[1].address, 0x1010);
        assert_eq!(t.entries[1].line, 5);
        assert!(t.entries[2].end_sequence);
        // source_at resolves through the provider path
        let loc = t.source_at(0x1008).unwrap();
        assert_eq!(loc.file, "a.c");
        assert_eq!(loc.line, 1);
    }

    #[test]
    fn line_program_special_opcode() {
        // Same header; program: set_address 0x2000 then one special opcode.
        let mut data = synthetic_line_program();
        // Rebuild with only a special opcode: opcode_base=13, line_base=-5, line_range=14.
        // special = 13 + (0 * 14) + (line_adv - line_base) where line_adv=+2 → adj=7 → op=20
        let mut hdr = data[..data.len()].to_vec();
        hdr.truncate(0);
        let _ = hdr;
        // Simpler: append a second CU is overkill; instead just verify the
        // existing program parses when a special opcode is appended before
        // end_sequence is not trivial — craft minimal one instead.
        let mut tail = vec![1, 1, 0xfb_u8, 14, 13];
        tail.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        tail.push(0);
        tail.extend(b"s.c\0");
        tail.extend([0, 0, 0]);
        tail.push(0);
        let mut prog = Vec::new();
        prog.push(0);
        prog.extend(uleb(9));
        prog.push(2);
        prog.extend(0x2000u64.to_le_bytes());
        // special opcode: adj = op - 13; addr += adj/14; line += -5 + adj%14
        // op = 13 + 1*14 + (3+5) = 35 → addr += 1, line += 3
        prog.push(35);
        prog.push(0);
        prog.extend(uleb(1));
        prog.push(1);
        data.clear();
        let unit_length = 2 + 4 + tail.len() + prog.len();
        data.extend((u32::try_from(unit_length).unwrap()).to_le_bytes());
        data.extend(3u16.to_le_bytes());
        data.extend((u32::try_from(tail.len()).unwrap()).to_le_bytes());
        data.extend(tail);
        data.extend(prog);

        let mut s = DwarfSections::new();
        s.debug_line = data;
        let t = DwarfParser::new(&s, false).parse_line_table().unwrap();
        assert_eq!(t.entries[0].address, 0x2001);
        assert_eq!(t.entries[0].line, 4); // 1 + 3
    }

    // -- Regression: globals located via DW_AT_location, not DW_AT_low_pc ----

    fn var_die(offset: u64, name: &str, loc: Vec<u8>) -> DwarfDie {
        let mut d = DwarfDie::new(offset, DwarfTag::Variable);
        d.set_attr(DW_AT_NAME, DwarfAttrValue::String(name.to_string()));
        d.set_attr(DW_AT_LOCATION, DwarfAttrValue::Block(loc));
        d
    }

    /// `DW_OP_addr` (0x03) followed by an 8-byte little-endian address.
    fn op_addr64(addr: u64) -> Vec<u8> {
        let mut v = vec![0x03u8];
        v.extend_from_slice(&addr.to_le_bytes());
        v
    }

    #[test]
    fn static_address_decodes_dw_op_addr() {
        let d = var_die(1, "g_counter", op_addr64(0x0040_2000));
        assert_eq!(d.static_address(8), Some(0x0040_2000));
        // DW_AT_low_pc is absent, which is exactly why the old code found
        // nothing for real variables.
        assert_eq!(d.low_pc(), None);
    }

    #[test]
    fn static_address_decodes_32bit_dw_op_addr() {
        let mut v = vec![0x03u8];
        v.extend_from_slice(&0x0804_8000u32.to_le_bytes());
        assert_eq!(var_die(1, "g", v).static_address(4), Some(0x0804_8000));
    }

    #[test]
    fn static_address_rejects_frame_relative_locals() {
        // DW_OP_fbreg (0x91) + SLEB offset: a stack local, not a global.
        let d = var_die(1, "local", vec![0x91, 0x78]);
        assert_eq!(d.static_address(8), None, "fbreg is not a static address");
    }

    #[test]
    fn static_address_rejects_addrx_and_composites() {
        // DW_OP_addrx (0xa1): an index into .debug_addr, which is not loaded.
        assert_eq!(var_die(1, "a", vec![0xa1, 0x02]).static_address(8), None);
        // DW_OP_addr followed by more operations (a composite location).
        let mut composite = op_addr64(0x1000);
        composite.push(0x9f); // DW_OP_stack_value
        assert_eq!(var_die(2, "c", composite).static_address(8), None);
    }

    #[test]
    fn static_address_falls_back_to_low_pc_when_no_location() {
        // Synthetic DIEs built by callers/tests may set low_pc directly.
        let mut d = DwarfDie::new(1, DwarfTag::Variable);
        d.set_attr(DW_AT_LOW_PC, DwarfAttrValue::Address(0x3000));
        assert_eq!(d.static_address(8), Some(0x3000));
    }

    #[test]
    fn from_compile_units_recovers_globals_from_location() {
        let mut cu = DwarfCompileUnit::new(0, 4, 0, 8);
        cu.add_die(var_die(1, "g_counter", op_addr64(0x0040_2000)));
        cu.add_die(var_die(2, "stack_local", vec![0x91, 0x78]));

        let p = DwarfSymbolProvider::from_compile_units(
            "t",
            vec![cu],
            &DwarfSections::default(),
        );

        let g = p.lookup_name("g_counter").expect("global must be recovered");
        assert_eq!(g.address, 0x0040_2000);
        assert_eq!(g.kind, SymKind::Data);
        assert!(
            p.lookup_name("stack_local").is_none(),
            "stack locals must not become global data symbols"
        );
    }

}

// ── Form decoding helpers ─────────────────────────────────────────────────────

/// The error reported when an attribute value runs past the end of the section.
fn truncated_at(offset: usize) -> DwarfError {
    DwarfError::ParseError {
        offset,
        msg: "truncated attribute value".into(),
    }
}

/// Consume `n` bytes at `*pos`, advancing the cursor, or report truncation.
fn take_bytes<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(n).ok_or_else(|| truncated_at(*pos))?;
    let slice = data.get(*pos..end).ok_or_else(|| truncated_at(*pos))?;
    *pos = end;
    Ok(slice)
}

/// Read a little-endian fixed-width unsigned integer of `n` bytes (`n <= 8`)
/// and widen it to `u64` without loss.
fn read_le_uint(data: &[u8], pos: &mut usize, n: usize) -> Result<u64> {
    let bytes = take_bytes(data, pos, n.min(8))?;
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

/// Decode the constant forms: `DW_FORM_DATA1/2/4/8`, `DW_FORM_UDATA` and
/// `DW_FORM_SDATA`.
fn read_constant_form(data: &[u8], pos: &mut usize, form: u64) -> Result<DwarfAttrValue> {
    Ok(match form {
        DW_FORM_DATA1 => DwarfAttrValue::Udata(read_le_uint(data, pos, 1)?),
        DW_FORM_DATA2 => DwarfAttrValue::Udata(read_le_uint(data, pos, 2)?),
        DW_FORM_DATA4 => DwarfAttrValue::Udata(read_le_uint(data, pos, 4)?),
        DW_FORM_DATA8 => DwarfAttrValue::Udata(read_le_uint(data, pos, 8)?),
        DW_FORM_UDATA => {
            DwarfAttrValue::Udata(read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        DW_FORM_SDATA => {
            DwarfAttrValue::Sdata(read_sleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        other => return Err(DwarfError::UnsupportedForm(other)),
    })
}

/// Decode the reference forms: `DW_FORM_REF1/2/4/8`, `DW_FORM_REF_ADDR`,
/// `DW_FORM_REF_SUP4/8`, `DW_FORM_REF_SIG8`, `DW_FORM_SEC_OFFSET` and
/// `DW_FORM_REF_UDATA`.
fn read_reference_form(data: &[u8], pos: &mut usize, form: u64) -> Result<DwarfAttrValue> {
    Ok(match form {
        DW_FORM_REF1 => DwarfAttrValue::Ref(read_le_uint(data, pos, 1)?),
        DW_FORM_REF2 => DwarfAttrValue::Ref(read_le_uint(data, pos, 2)?),
        DW_FORM_REF4 | DW_FORM_REF_ADDR | DW_FORM_REF_SUP4 | DW_FORM_SEC_OFFSET => {
            DwarfAttrValue::Ref(read_le_uint(data, pos, 4)?)
        }
        DW_FORM_REF8 | DW_FORM_REF_SIG8 | DW_FORM_REF_SUP8 => {
            DwarfAttrValue::Ref(read_le_uint(data, pos, 8)?)
        }
        DW_FORM_REF_UDATA => {
            DwarfAttrValue::Ref(read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        other => return Err(DwarfError::UnsupportedForm(other)),
    })
}

/// Decode the block forms: `DW_FORM_BLOCK1/2/4`, `DW_FORM_BLOCK`,
/// `DW_FORM_EXPRLOC` and the fixed 16-byte `DW_FORM_DATA16`.
///
/// Each length prefix is widened to `u64` and then converted to `usize` with a
/// checked conversion, so a hostile 4-byte or LEB128 length can only produce a
/// truncation error, never a wrapped-around slice bound.
fn read_block_form(data: &[u8], pos: &mut usize, form: u64) -> Result<DwarfAttrValue> {
    let len = match form {
        DW_FORM_BLOCK1 => read_le_uint(data, pos, 1)?,
        DW_FORM_BLOCK2 => read_le_uint(data, pos, 2)?,
        DW_FORM_BLOCK4 => read_le_uint(data, pos, 4)?,
        DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
            read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?
        }
        DW_FORM_DATA16 => 16,
        other => return Err(DwarfError::UnsupportedForm(other)),
    };
    let n = usize::try_from(len).map_err(|_| truncated_at(*pos))?;
    Ok(DwarfAttrValue::Block(take_bytes(data, pos, n)?.to_vec()))
}

/// Decode the DWARF 5 indexed forms: `DW_FORM_STRX*`, `DW_FORM_ADDRX*`,
/// `DW_FORM_LOCLISTX` and `DW_FORM_RNGLISTX`.
///
/// `Strx`/`Addrx` keep their own value variants so an index is never mistaken
/// for a constant or an address before the CU's `str_offsets`/`addr` bases are
/// known.
fn read_indexed_form(data: &[u8], pos: &mut usize, form: u64) -> Result<DwarfAttrValue> {
    Ok(match form {
        DW_FORM_STRX => {
            DwarfAttrValue::Strx(read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        DW_FORM_ADDRX => {
            DwarfAttrValue::Addrx(read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        DW_FORM_LOCLISTX | DW_FORM_RNGLISTX => {
            DwarfAttrValue::Udata(read_uleb128(data, pos).ok_or_else(|| truncated_at(*pos))?)
        }
        DW_FORM_STRX1 => DwarfAttrValue::Strx(read_le_uint(data, pos, 1)?),
        DW_FORM_ADDRX1 => DwarfAttrValue::Addrx(read_le_uint(data, pos, 1)?),
        DW_FORM_STRX2 => DwarfAttrValue::Strx(read_le_uint(data, pos, 2)?),
        DW_FORM_ADDRX2 => DwarfAttrValue::Addrx(read_le_uint(data, pos, 2)?),
        DW_FORM_STRX3 => DwarfAttrValue::Strx(read_le_uint(data, pos, 3)?),
        DW_FORM_ADDRX3 => DwarfAttrValue::Addrx(read_le_uint(data, pos, 3)?),
        DW_FORM_STRX4 => DwarfAttrValue::Strx(read_le_uint(data, pos, 4)?),
        DW_FORM_ADDRX4 => DwarfAttrValue::Addrx(read_le_uint(data, pos, 4)?),
        other => return Err(DwarfError::UnsupportedForm(other)),
    })
}

// ── Line-number program state ─────────────────────────────────────────────────

/// The decoded fixed header of a DWARF 2–4 line-number program.
///
/// Bundling these eight values keeps every opcode helper to a small parameter
/// list and gives the header a single name to pass around.
#[derive(Debug, Clone)]
struct LineProgramHeader {
    /// Offset one byte past the end of this unit.
    end: usize,
    /// `header_length` field, i.e. bytes from after that field to the program.
    header_length: usize,
    /// `minimum_instruction_length`, the address advance quantum.
    min_inst_length: u8,
    /// Initial value of the `is_stmt` register.
    default_is_stmt: bool,
    /// `line_base`, the signed line advance of the smallest special opcode.
    line_base: i8,
    /// `line_range`, the number of line values a special opcode spans.
    line_range: u8,
    /// First opcode value treated as a special opcode.
    opcode_base: u8,
    /// Operand counts of the standard opcodes, used to skip unknown ones.
    std_lengths: Vec<u8>,
}

/// The DWARF line-number state machine registers this decoder tracks.
#[derive(Debug, Clone, Copy)]
struct LineMachine {
    /// Current program-counter value of the row being built.
    address: u64,
    /// Current file number (1-based, as DWARF 2–4 defines it).
    file: u64,
    /// Current source line; signed because `DW_LNS_advance_line` may go back.
    line: i64,
    /// Current source column.
    column: u64,
    /// Whether the row is a recommended breakpoint location.
    is_stmt: bool,
}

impl LineMachine {
    /// The register values a sequence starts (and restarts) from.
    const fn new(default_is_stmt: bool) -> Self {
        Self {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            is_stmt: default_is_stmt,
        }
    }

    /// Reset to the initial register values after `DW_LNE_end_sequence`.
    const fn reset(&mut self, default_is_stmt: bool) {
        *self = Self::new(default_is_stmt);
    }

    /// Advance the address register by `operation_advance` quanta.
    fn advance_address(&mut self, operation_advance: u64, min_inst_length: u8) {
        self.address = self
            .address
            .wrapping_add(operation_advance.wrapping_mul(u64::from(min_inst_length)));
    }

    /// Apply a special opcode's combined address and line advance.
    fn apply_special(&mut self, header: &LineProgramHeader, adjusted: u8) {
        let adj = u64::from(adjusted);
        self.advance_address(adj / u64::from(header.line_range), header.min_inst_length);
        let line_advance = i64::try_from(adj % u64::from(header.line_range)).unwrap_or(0);
        self.line += i64::from(header.line_base) + line_advance;
    }

    /// Append the current registers to `table` as one row.
    fn emit(&self, table: &mut DwarfLineTable, end_sequence: bool) {
        table.add_entry(DwarfLineEntry {
            address: self.address,
            // DWARF file numbering is 1-based in v2–4; our table is 0-based.
            file_index: u32::try_from(self.file.saturating_sub(1)).unwrap_or(u32::MAX),
            line: u32::try_from(self.line.max(0)).unwrap_or(u32::MAX),
            column: u32::try_from(self.column).unwrap_or(u32::MAX),
            is_stmt: self.is_stmt,
            end_sequence,
        });
    }
}
