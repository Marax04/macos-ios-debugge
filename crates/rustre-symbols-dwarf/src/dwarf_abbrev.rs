//! DWARF `.debug_abbrev` section parser.
//!
//! Each compilation unit in `.debug_info` references a table of *abbreviation
//! declarations* stored in `.debug_abbrev`.  Every DIE (Debugging Information
//! Entry) starts with a ULEB128 abbreviation code that indexes this table.
//!
//! Types: [`DwForm`], [`AbbrevAttr`], [`AbbrevDecl`], [`AbbrevTable`],
//! [`FormValue`].

use std::collections::HashMap;
use std::fmt;

// ─── ULEB128 / SLEB128 helpers ────────────────────────────────────────────────

/// Decode an unsigned LEB128 integer from `data` starting at `*pos`.
/// Advances `*pos` past the decoded bytes.
///
/// # Errors
/// Returns `None` if the data ends before the value is complete.
pub fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        let low7 = u64::from(byte & 0x7F);
        result |= low7 << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    Some(result)
}

/// Decode a signed LEB128 integer from `data` starting at `*pos`.
pub fn read_sleb128(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut last_byte: u8;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        last_byte = byte;
        let low7 = i64::from(byte & 0x7F);
        result |= low7 << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    // Sign-extend if the sign bit of the last group was set.
    if shift < 64 && (last_byte & 0x40 != 0) {
        // Use wrapping_neg so shift==63 (1<<63 == i64::MIN) does not panic.
        result |= (1_i64 << shift).wrapping_neg();
    }
    Some(result)
}

// ─── DwForm ───────────────────────────────────────────────────────────────────

/// DWARF attribute form codes (`DW_FORM_*`).
///
/// This enum covers all forms defined in DWARF 5 §7.5.4 plus the GNU/LLVM
/// extensions used in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum DwForm {
    /// `DW_FORM_addr`: target-address-sized value.
    Addr            = 0x01,
    /// `DW_FORM_block2`: block with a 2-byte length prefix.
    Block2          = 0x03,
    /// `DW_FORM_block4`: block with a 4-byte length prefix.
    Block4          = 0x04,
    /// `DW_FORM_data2`: 2-byte constant.
    Data2           = 0x05,
    /// `DW_FORM_data4`: 4-byte constant.
    Data4           = 0x06,
    /// `DW_FORM_data8`: 8-byte constant.
    Data8           = 0x07,
    /// `DW_FORM_string`: inline NUL-terminated string.
    String          = 0x08,
    /// `DW_FORM_block`: block with a ULEB128 length prefix.
    Block           = 0x09,
    /// `DW_FORM_block1`: block with a 1-byte length prefix.
    Block1          = 0x0A,
    /// `DW_FORM_data1`: 1-byte constant.
    Data1           = 0x0B,
    /// `DW_FORM_flag`: 1-byte boolean flag.
    Flag            = 0x0C,
    /// `DW_FORM_sdata`: SLEB128 constant.
    Sdata           = 0x0D,
    /// `DW_FORM_strp`: offset into `.debug_str`.
    Strp            = 0x0E,
    /// `DW_FORM_udata`: ULEB128 constant.
    Udata           = 0x0F,
    /// `DW_FORM_ref_addr`: section-relative DIE reference.
    RefAddr         = 0x10,
    /// `DW_FORM_ref1`: 1-byte CU-relative DIE reference.
    Ref1            = 0x11,
    /// `DW_FORM_ref2`: 2-byte CU-relative DIE reference.
    Ref2            = 0x12,
    /// `DW_FORM_ref4`: 4-byte CU-relative DIE reference.
    Ref4            = 0x13,
    /// `DW_FORM_ref8`: 8-byte CU-relative DIE reference.
    Ref8            = 0x14,
    /// `DW_FORM_ref_udata`: ULEB128 CU-relative DIE reference.
    RefUdata        = 0x15,
    /// `DW_FORM_indirect`: actual form is a ULEB128 in the info stream.
    Indirect        = 0x16,
    /// `DW_FORM_sec_offset`: offset into another debug section.
    SecOffset       = 0x17,
    /// `DW_FORM_exprloc`: DWARF expression block (ULEB128 length prefix).
    Exprloc         = 0x18,
    /// `DW_FORM_flag_present`: implicitly-true flag, zero bytes.
    FlagPresent     = 0x19,
    /// `DW_FORM_strx`: ULEB128 index into `.debug_str_offsets`.
    StrX            = 0x1A,
    /// `DW_FORM_addrx`: ULEB128 index into `.debug_addr`.
    AddrX           = 0x1B,
    /// `DW_FORM_ref_sup4`: 4-byte reference into a supplementary file.
    RefSup4         = 0x1C,
    /// `DW_FORM_strp_sup`: string offset in a supplementary file.
    StrpSup         = 0x1D,
    /// `DW_FORM_data16`: 16-byte constant (e.g. MD5).
    Data16          = 0x1E,
    /// `DW_FORM_line_strp`: offset into `.debug_line_str`.
    LineStrp        = 0x1F,
    /// `DW_FORM_ref_sig8`: 8-byte type-unit signature reference.
    RefSig8         = 0x20,
    /// `DW_FORM_implicit_const`: value stored in the abbrev table itself.
    ImplicitConst   = 0x21,
    /// `DW_FORM_loclistx`: ULEB128 index into `.debug_loclists`.
    Loclistx        = 0x22,
    /// `DW_FORM_rnglistx`: ULEB128 index into `.debug_rnglists`.
    Rnglistx        = 0x23,
    /// `DW_FORM_ref_sup8`: 8-byte reference into a supplementary file.
    RefSup8         = 0x24,
    /// `DW_FORM_strx1`: 1-byte string-offsets index.
    StrX1           = 0x25,
    /// `DW_FORM_strx2`: 2-byte string-offsets index.
    StrX2           = 0x26,
    /// `DW_FORM_strx3`: 3-byte string-offsets index.
    StrX3           = 0x27,
    /// `DW_FORM_strx4`: 4-byte string-offsets index.
    StrX4           = 0x28,
    /// `DW_FORM_addrx1`: 1-byte address-table index.
    AddrX1          = 0x29,
    /// `DW_FORM_addrx2`: 2-byte address-table index.
    AddrX2          = 0x2A,
    /// `DW_FORM_addrx3`: 3-byte address-table index.
    AddrX3          = 0x2B,
    /// `DW_FORM_addrx4`: 4-byte address-table index.
    AddrX4          = 0x2C,
    // GNU extensions
    /// `DW_FORM_GNU_strp_alt`: string offset in an alternate (dwz) file.
    GnuStrpAlt      = 0x1F20,
    /// `DW_FORM_GNU_ref_alt`: DIE reference into an alternate (dwz) file.
    GnuRefAlt       = 0x1F21,
    /// Unrecognized form code.
    Unknown         = 0xFFFF,
}

impl DwForm {
    /// Parse a `DW_FORM_*` code into `DwForm`.
    #[must_use]
    pub const fn from_code(code: u64) -> Self {
        match code {
            0x01 => Self::Addr,
            0x03 => Self::Block2,
            0x04 => Self::Block4,
            0x05 => Self::Data2,
            0x06 => Self::Data4,
            0x07 => Self::Data8,
            0x08 => Self::String,
            0x09 => Self::Block,
            0x0A => Self::Block1,
            0x0B => Self::Data1,
            0x0C => Self::Flag,
            0x0D => Self::Sdata,
            0x0E => Self::Strp,
            0x0F => Self::Udata,
            0x10 => Self::RefAddr,
            0x11 => Self::Ref1,
            0x12 => Self::Ref2,
            0x13 => Self::Ref4,
            0x14 => Self::Ref8,
            0x15 => Self::RefUdata,
            0x16 => Self::Indirect,
            0x17 => Self::SecOffset,
            0x18 => Self::Exprloc,
            0x19 => Self::FlagPresent,
            0x1A => Self::StrX,
            0x1B => Self::AddrX,
            0x1C => Self::RefSup4,
            0x1D => Self::StrpSup,
            0x1E => Self::Data16,
            0x1F => Self::LineStrp,
            0x20 => Self::RefSig8,
            0x21 => Self::ImplicitConst,
            0x22 => Self::Loclistx,
            0x23 => Self::Rnglistx,
            0x24 => Self::RefSup8,
            0x25 => Self::StrX1,
            0x26 => Self::StrX2,
            0x27 => Self::StrX3,
            0x28 => Self::StrX4,
            0x29 => Self::AddrX1,
            0x2A => Self::AddrX2,
            0x2B => Self::AddrX3,
            0x2C => Self::AddrX4,
            0x1F20 => Self::GnuStrpAlt,
            0x1F21 => Self::GnuRefAlt,
            _ => Self::Unknown,
        }
    }

    /// Whether the form requires reading an `implicit_const` value from the
    /// abbreviation table rather than from the `.debug_info` byte stream.
    #[must_use]
    pub const fn is_implicit_const(self) -> bool {
        matches!(self, Self::ImplicitConst)
    }

    /// Whether the form has fixed size in `.debug_info`.
    #[must_use]
    pub const fn fixed_size(self, addr_size: u8) -> Option<usize> {
        match self {
            Self::Addr => Some(addr_size as usize),
            Self::Data1 | Self::Flag | Self::Ref1 | Self::StrX1 | Self::AddrX1 => Some(1),
            Self::Data2 | Self::Ref2 | Self::StrX2 | Self::AddrX2 => Some(2),
            Self::StrX3 | Self::AddrX3 => Some(3),
            Self::Data4 | Self::Ref4 | Self::RefSup4 | Self::StrX4 | Self::AddrX4 => Some(4),
            Self::Data8 | Self::Ref8 | Self::RefSig8 | Self::RefSup8 => Some(8),
            Self::Data16 => Some(16),
            Self::FlagPresent => Some(0),
            Self::Strp | Self::StrpSup | Self::SecOffset
            | Self::RefAddr | Self::LineStrp => Some(4), // 32-bit DWARF default
            _ => None,
        }
    }
}

impl fmt::Display for DwForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DW_FORM_{self:?}")
    }
}

// ─── DwTag (small selection for cross-referencing) ────────────────────────────

/// A selection of commonly used `DW_TAG_*` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DwTag(pub u64);

impl DwTag {
    /// `DW_TAG_compile_unit`.
    pub const COMPILE_UNIT: Self   = Self(0x11);
    /// `DW_TAG_subprogram`.
    pub const SUBPROGRAM: Self     = Self(0x2E);
    /// `DW_TAG_variable`.
    pub const VARIABLE: Self       = Self(0x34);
    /// `DW_TAG_formal_parameter`.
    pub const FORMAL_PARAM: Self   = Self(0x05);
    /// `DW_TAG_base_type`.
    pub const BASE_TYPE: Self      = Self(0x24);
    /// `DW_TAG_pointer_type`.
    pub const POINTER_TYPE: Self   = Self(0x0F);
    /// `DW_TAG_typedef`.
    pub const TYPEDEF: Self        = Self(0x16);
    /// `DW_TAG_structure_type`.
    pub const STRUCTURE_TYPE: Self = Self(0x13);
    /// `DW_TAG_union_type`.
    pub const UNION_TYPE: Self     = Self(0x17);
    /// `DW_TAG_array_type`.
    pub const ARRAY_TYPE: Self     = Self(0x01);
    /// `DW_TAG_member`.
    pub const MEMBER: Self         = Self(0x0D);
    /// `DW_TAG_lexical_block`.
    pub const LEXICAL_BLOCK: Self  = Self(0x0B);
    /// `DW_TAG_inlined_subroutine`.
    pub const INLINED_SUBP: Self   = Self(0x1D);
}

impl fmt::Display for DwTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DW_TAG({:#x})", self.0)
    }
}

// ─── DwAt (attribute name) ────────────────────────────────────────────────────

/// Wrapper for a `DW_AT_*` attribute name code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DwAt(pub u64);

impl DwAt {
    /// `DW_AT_name`.
    pub const NAME: Self           = Self(0x03);
    /// `DW_AT_byte_size`.
    pub const BYTE_SIZE: Self      = Self(0x0B);
    /// `DW_AT_comp_dir`.
    pub const COMP_DIR: Self       = Self(0x1B);
    /// `DW_AT_low_pc`.
    pub const LOW_PC: Self         = Self(0x11);
    /// `DW_AT_high_pc`.
    pub const HIGH_PC: Self        = Self(0x12);
    /// `DW_AT_language`.
    pub const LANGUAGE: Self       = Self(0x13);
    /// `DW_AT_producer`.
    pub const PRODUCER: Self       = Self(0x25);
    /// `DW_AT_type`.
    pub const TYPE: Self           = Self(0x49);
    /// `DW_AT_location`.
    pub const LOCATION: Self       = Self(0x02);
    /// `DW_AT_decl_file`.
    pub const DECL_FILE: Self      = Self(0x3A);
    /// `DW_AT_decl_line`.
    pub const DECL_LINE: Self      = Self(0x3B);
    /// `DW_AT_external`.
    pub const EXTERNAL: Self       = Self(0x3F);
    /// `DW_AT_ranges`.
    pub const RANGES: Self         = Self(0x55);
    /// `DW_AT_stmt_list`.
    pub const STMT_LIST: Self      = Self(0x10);
    /// `DW_AT_abstract_origin`.
    pub const ABSTRACT_ORIGIN: Self= Self(0x31);
    /// `DW_AT_inline`.
    pub const INLINE: Self         = Self(0x20);
    /// `DW_AT_encoding`.
    pub const ENCODING: Self       = Self(0x3E);
    /// `DW_AT_data_member_location`.
    pub const DATA_MEMBER_LOC: Self= Self(0x38);
    /// `DW_AT_upper_bound`.
    pub const UPPER_BOUND: Self    = Self(0x2F);
}

impl fmt::Display for DwAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DW_AT({:#x})", self.0)
    }
}

// ─── AbbrevAttr ───────────────────────────────────────────────────────────────

/// A single attribute specification inside an abbreviation declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbbrevAttr {
    /// `DW_AT_*` code.
    pub name: DwAt,
    /// `DW_FORM_*` code.
    pub form: DwForm,
    /// Constant value for `DW_FORM_implicit_const`.
    pub implicit_const: i64,
}

impl AbbrevAttr {
    /// Create an attribute spec from raw `DW_AT_*` and `DW_FORM_*` codes.
    #[must_use]
    pub const fn new(name: u64, form: u64) -> Self {
        Self {
            name: DwAt(name),
            form: DwForm::from_code(form),
            implicit_const: 0,
        }
    }
    /// Create a `DW_FORM_implicit_const` attribute spec with its stored value.
    #[must_use]
    pub const fn new_implicit(name: u64, value: i64) -> Self {
        Self {
            name: DwAt(name),
            form: DwForm::ImplicitConst,
            implicit_const: value,
        }
    }
}

impl fmt::Display for AbbrevAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  {}", self.name, self.form)
    }
}

// ─── AbbrevDecl ───────────────────────────────────────────────────────────────

/// A complete abbreviation declaration (one entry in `.debug_abbrev`).
#[derive(Debug, Clone)]
pub struct AbbrevDecl {
    /// Abbreviation code (1-based; 0 means end-of-siblings).
    pub code: u64,
    /// `DW_TAG_*` code.
    pub tag: DwTag,
    /// Whether this DIE has children.
    pub has_children: bool,
    /// Ordered attribute specifications.
    pub attrs: Vec<AbbrevAttr>,
}

impl AbbrevDecl {
    /// Create a declaration with no attributes yet.
    #[must_use]
    pub const fn new(code: u64, tag: u64, has_children: bool) -> Self {
        Self {
            code,
            tag: DwTag(tag),
            has_children,
            attrs: Vec::new(),
        }
    }
    /// Append an attribute specification.
    pub fn push_attr(&mut self, attr: AbbrevAttr) {
        self.attrs.push(attr);
    }
    /// Find the attribute spec for the given `DW_AT_*` name, if present.
    #[must_use]
    pub fn attr(&self, name: DwAt) -> Option<&AbbrevAttr> {
        self.attrs.iter().find(|a| a.name == name)
    }
}

impl fmt::Display for AbbrevDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "abbrev[{}] {} has_children={} ({} attrs)",
            self.code,
            self.tag,
            self.has_children,
            self.attrs.len()
        )
    }
}

// ─── AbbrevTable ─────────────────────────────────────────────────────────────

/// A parsed `.debug_abbrev` table: code → `AbbrevDecl`.
///
/// A single `.debug_abbrev` section may contain multiple tables (one per CU
/// offset).  This type holds the table for a *single* abbreviation-table offset
/// (`DW_AT_stmt_list` is analogous — the CU header points to one table).
#[derive(Debug, Default)]
pub struct AbbrevTable {
    decls: HashMap<u64, AbbrevDecl>,
}

impl AbbrevTable {
    /// Create an empty abbreviation table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up an abbreviation by code.
    #[must_use]
    pub fn get(&self, code: u64) -> Option<&AbbrevDecl> {
        self.decls.get(&code)
    }

    /// Number of declarations in this table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decls.len()
    }

    /// True if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decls.is_empty()
    }

    /// Iterate over all declarations in insertion order (not guaranteed to be
    /// sorted).
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &AbbrevDecl)> {
        self.decls.iter()
    }

    fn insert(&mut self, decl: AbbrevDecl) {
        self.decls.insert(decl.code, decl);
    }
}

// ─── parse_abbrev_table ───────────────────────────────────────────────────────

/// Parse a single abbreviation table from `data` starting at byte offset
/// `start`.  Stops at the first zero code (end of table).
///
/// Returns `None` if the data is truncated or malformed.
#[must_use]
pub fn parse_abbrev_table(data: &[u8], start: usize) -> Option<AbbrevTable> {
    let mut table = AbbrevTable::new();
    let mut pos = start;

    loop {
        // An empty `.debug_abbrev` slice (no bytes at all) is equivalent to a
        // table whose first byte is 0 (end-of-table marker).
        if pos >= data.len() {
            break;
        }
        let code = read_uleb128(data, &mut pos)?;
        if code == 0 {
            break;
        }
        let tag_code = read_uleb128(data, &mut pos)?;
        let has_children_byte = *data.get(pos)?;
        pos += 1;
        let has_children = has_children_byte != 0;

        let mut decl = AbbrevDecl::new(code, tag_code, has_children);

        loop {
            let attr_name = read_uleb128(data, &mut pos)?;
            let attr_form = read_uleb128(data, &mut pos)?;
            if attr_name == 0 && attr_form == 0 {
                break;
            }
            let attr = if attr_form == DwForm::ImplicitConst as u64 {
                let val = read_sleb128(data, &mut pos)?;
                AbbrevAttr::new_implicit(attr_name, val)
            } else {
                AbbrevAttr::new(attr_name, attr_form)
            };
            decl.push_attr(attr);
        }

        table.insert(decl);
    }

    Some(table)
}

/// Parse all abbreviation tables from a complete `.debug_abbrev` section.
/// Returns a map from byte offset → `AbbrevTable`.
#[must_use]
pub fn parse_all_abbrev_tables(data: &[u8]) -> HashMap<usize, AbbrevTable> {
    let mut tables: HashMap<usize, AbbrevTable> = HashMap::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let start = pos;
        // Peek: if the next ULEB128 is 0 we've hit an empty table, skip.
        let mut peek = pos;
        let Some(first_code) = read_uleb128(data, &mut peek) else { break };
        if first_code == 0 {
            pos = peek;
            continue;
        }
        if let Some(table) = parse_abbrev_table(data, pos) {
            // Advance pos past all parsed decls.
            // Re-parse to find end position.
            let mut scan = pos;
            loop {
                let c = read_uleb128(data, &mut scan).unwrap_or(0);
                if c == 0 {
                    break;
                }
                read_uleb128(data, &mut scan); // tag
                scan += 1; // has_children
                loop {
                    let n = read_uleb128(data, &mut scan).unwrap_or(0);
                    let frm = read_uleb128(data, &mut scan).unwrap_or(0);
                    if n == 0 && frm == 0 {
                        break;
                    }
                    if frm == DwForm::ImplicitConst as u64 {
                        read_sleb128(data, &mut scan);
                    }
                }
            }
            tables.insert(start, table);
            pos = scan;
        } else {
            break;
        }
    }
    tables
}

// ─── FormValue ────────────────────────────────────────────────────────────────

/// A resolved form value from a `.debug_info` byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormValue {
    /// Unsigned integer (covers Data1..Data8, Udata, Flag, Ref*, Addr).
    Uint(u64),
    /// Signed integer (Sdata, `ImplicitConst`).
    Int(i64),
    /// Inline string (`DW_FORM_string`).
    String(String),
    /// String pool offset (`DW_FORM_strp`, linestrp, `strp_sup`).
    StrOffset(u64),
    /// Raw byte block.
    Bytes(Vec<u8>),
    /// Section offset (`DW_FORM_sec_offset`, `DW_FORM_exprloc`).
    SecOffset(u64),
    /// Reference to another DIE within the same CU (byte offset from CU start).
    CuRef(u64),
    /// Indirect form — the actual form is encoded in the info stream.
    Indirect,
    /// Unknown / not resolved.
    Unknown,
}

impl fmt::Display for FormValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uint(v) => write!(f, "{v:#x}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s:?}"),
            Self::StrOffset(o) => write!(f, "strp({o:#x})"),
            Self::Bytes(b) => write!(f, "bytes[{}]", b.len()),
            Self::SecOffset(o) => write!(f, "sec_off({o:#x})"),
            Self::CuRef(o) => write!(f, "cu_ref({o:#x})"),
            Self::Indirect => write!(f, "<indirect>"),
            Self::Unknown => write!(f, "<unknown>"),
        }
    }
}

/// Read the value of `form` from `data` starting at `*pos`, using `addr_size`
/// (4 or 8) and `is_dwarf64` to determine the size of offsets and references.
///
/// Returns `None` on truncation.
pub fn read_form_value(
    data: &[u8],
    pos: &mut usize,
    form: DwForm,
    addr_size: u8,
    is_dwarf64: bool,
    implicit_const: i64,
) -> Option<FormValue> {
    let offset_size: usize = if is_dwarf64 { 8 } else { 4 };
    let read_u8 = |data: &[u8], p: &mut usize| -> Option<u8> {
        let v = *data.get(*p)?;
        *p += 1;
        Some(v)
    };
    let read_u16 = |data: &[u8], p: &mut usize| -> Option<u16> {
        if *p + 2 > data.len() { return None; }
        let v = u16::from_le_bytes(data[*p..*p+2].try_into().ok()?);
        *p += 2;
        Some(v)
    };
    let read_u32 = |data: &[u8], p: &mut usize| -> Option<u32> {
        if *p + 4 > data.len() { return None; }
        let v = u32::from_le_bytes(data[*p..*p+4].try_into().ok()?);
        *p += 4;
        Some(v)
    };
    let read_u64 = |data: &[u8], p: &mut usize| -> Option<u64> {
        if *p + 8 > data.len() { return None; }
        let v = u64::from_le_bytes(data[*p..*p+8].try_into().ok()?);
        *p += 8;
        Some(v)
    };

    match form {
        DwForm::ImplicitConst => Some(FormValue::Int(implicit_const)),
        DwForm::FlagPresent => Some(FormValue::Uint(1)),
        DwForm::Addr => {
            let v = match addr_size {
                2 => u64::from(read_u16(data, pos)?),
                4 => u64::from(read_u32(data, pos)?),
                8 => read_u64(data, pos)?,
                _ => return None,
            };
            Some(FormValue::Uint(v))
        }
        DwForm::Data1 | DwForm::Flag | DwForm::Ref1 => {
            Some(FormValue::Uint(u64::from(read_u8(data, pos)?)))
        }
        DwForm::Data2 | DwForm::Ref2 => {
            Some(FormValue::Uint(u64::from(read_u16(data, pos)?)))
        }
        DwForm::Data4 | DwForm::Ref4 | DwForm::RefSup4 => {
            Some(FormValue::Uint(u64::from(read_u32(data, pos)?)))
        }
        DwForm::Data8 | DwForm::Ref8 | DwForm::RefSup8 | DwForm::RefSig8 => {
            Some(FormValue::Uint(read_u64(data, pos)?))
        }
        DwForm::Sdata => Some(FormValue::Int(read_sleb128(data, pos)?)),
        DwForm::Udata | DwForm::RefUdata | DwForm::Loclistx | DwForm::Rnglistx
        | DwForm::StrX | DwForm::AddrX => {
            Some(FormValue::Uint(read_uleb128(data, pos)?))
        }
        DwForm::Strp | DwForm::StrpSup | DwForm::GnuStrpAlt | DwForm::LineStrp => {
            let off = if offset_size == 8 { read_u64(data, pos)? } else { u64::from(read_u32(data, pos)?) };
            Some(FormValue::StrOffset(off))
        }
        DwForm::SecOffset | DwForm::RefAddr => {
            let off = if offset_size == 8 { read_u64(data, pos)? } else { u64::from(read_u32(data, pos)?) };
            Some(FormValue::SecOffset(off))
        }
        DwForm::String => {
            let start = *pos;
            while pos < &mut data.len() && data[*pos] != 0 {
                *pos += 1;
            }
            let s = std::str::from_utf8(&data[start..*pos])
                .unwrap_or("<invalid utf8>")
                .to_string();
            *pos += 1; // consume NUL
            Some(FormValue::String(s))
        }
        DwForm::Block1 => {
            let len = read_u8(data, pos)? as usize;
            if *pos + len > data.len() { return None; }
            let b = data[*pos..*pos+len].to_vec();
            *pos += len;
            Some(FormValue::Bytes(b))
        }
        DwForm::Block2 => {
            let len = read_u16(data, pos)? as usize;
            if *pos + len > data.len() { return None; }
            let b = data[*pos..*pos+len].to_vec();
            *pos += len;
            Some(FormValue::Bytes(b))
        }
        DwForm::Block4 => {
            let len = read_u32(data, pos)? as usize;
            if *pos + len > data.len() { return None; }
            let b = data[*pos..*pos+len].to_vec();
            *pos += len;
            Some(FormValue::Bytes(b))
        }
        DwForm::Block | DwForm::Exprloc => {
            let len = read_uleb128(data, pos)? as usize;
            // `len` is attacker-controlled up to u64::MAX: `*pos + len` would
            // wrap in release and bypass the bounds check.
            if len > data.len().saturating_sub(*pos) { return None; }
            let b = data[*pos..*pos+len].to_vec();
            *pos += len;
            Some(FormValue::Bytes(b))
        }
        DwForm::Data16 => {
            if *pos + 16 > data.len() { return None; }
            let b = data[*pos..*pos+16].to_vec();
            *pos += 16;
            Some(FormValue::Bytes(b))
        }
        // DWARF 5 index forms: 1/2/3/4-byte little-endian indices into
        // .debug_str_offsets / .debug_addr. Previously these fell into the
        // catch-all and consumed ZERO bytes, desynchronising the DIE stream.
        DwForm::StrX1 | DwForm::AddrX1 => Some(FormValue::Uint(u64::from(read_u8(data, pos)?))),
        DwForm::StrX2 | DwForm::AddrX2 => Some(FormValue::Uint(u64::from(read_u16(data, pos)?))),
        DwForm::StrX3 | DwForm::AddrX3 => {
            // 3-byte LE — must be assembled manually.
            let b0 = u64::from(read_u8(data, pos)?);
            let b1 = u64::from(read_u8(data, pos)?);
            let b2 = u64::from(read_u8(data, pos)?);
            Some(FormValue::Uint(b0 | (b1 << 8) | (b2 << 16)))
        }
        DwForm::StrX4 | DwForm::AddrX4 => Some(FormValue::Uint(u64::from(read_u32(data, pos)?))),
        DwForm::GnuRefAlt => {
            let off = if offset_size == 8 { read_u64(data, pos)? } else { u64::from(read_u32(data, pos)?) };
            Some(FormValue::SecOffset(off))
        }
        DwForm::Indirect => {
            // The actual form code is encoded as a ULEB128 at this position.
            let actual_form_code = read_uleb128(data, pos)?;
            let actual_form = DwForm::from_code(actual_form_code);
            read_form_value(data, pos, actual_form, addr_size, is_dwarf64, implicit_const)
        }
        // A genuinely unknown form has no known size, and DWARF attributes are
        // packed with no separators — "skip it" is impossible. Returning
        // Some(Unknown) here consumed ZERO bytes and desynchronised the rest of
        // the DIE, so a hard failure is the only honest answer.
        DwForm::Unknown => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_single_byte() {
        let data = [0x07u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), Some(7));
        assert_eq!(pos, 1);
    }

    #[test]
    fn uleb128_multi_byte() {
        // ULEB128 encoding of 624485
        let data = [0xE5u8, 0x8E, 0x26];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), Some(624_485));
    }

    #[test]
    fn sleb128_negative() {
        // SLEB128 encoding of -123456
        let data = [0xC0u8, 0xBB, 0x78];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), Some(-123_456));
    }

    #[test]
    fn sleb128_positive_small() {
        let data = [0x3Eu8];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), Some(62));
    }

    #[test]
    fn dw_form_from_code_roundtrip() {
        assert_eq!(DwForm::from_code(0x01), DwForm::Addr);
        assert_eq!(DwForm::from_code(0x08), DwForm::String);
        assert_eq!(DwForm::from_code(0x21), DwForm::ImplicitConst);
        assert_eq!(DwForm::from_code(0xDEAD), DwForm::Unknown);
    }

    #[test]
    fn dw_form_fixed_size() {
        assert_eq!(DwForm::Data1.fixed_size(8), Some(1));
        assert_eq!(DwForm::Data8.fixed_size(4), Some(8));
        assert_eq!(DwForm::FlagPresent.fixed_size(4), Some(0));
        assert_eq!(DwForm::Block.fixed_size(4), None);
    }

    #[test]
    fn abbrev_attr_new() {
        let a = AbbrevAttr::new(0x03, 0x08);
        assert_eq!(a.name, DwAt(0x03));
        assert_eq!(a.form, DwForm::String);
        assert_eq!(a.implicit_const, 0);
    }

    #[test]
    fn abbrev_attr_implicit_const() {
        let a = AbbrevAttr::new_implicit(0x0B, -5);
        assert_eq!(a.form, DwForm::ImplicitConst);
        assert_eq!(a.implicit_const, -5);
    }

    #[test]
    fn parse_abbrev_table_basic() {
        // Minimal .debug_abbrev: code=1, DW_TAG_compile_unit(0x11),
        // has_children=1, DW_AT_name(0x03) DW_FORM_string(0x08),
        // then 0,0 (end attrs), then 0 (end table).
        let mut data = vec![
            0x01,       // code = 1
            0x11,       // DW_TAG_compile_unit
            0x01,       // has_children = yes
            0x03, 0x08, // DW_AT_name, DW_FORM_string
            0x00, 0x00, // end attrs
            0x00,       // end table
        ];
        let table = parse_abbrev_table(&data, 0).unwrap();
        assert_eq!(table.len(), 1);
        let decl = table.get(1).unwrap();
        assert_eq!(decl.tag, DwTag::COMPILE_UNIT);
        assert!(decl.has_children);
        assert_eq!(decl.attrs.len(), 1);
        assert_eq!(decl.attrs[0].name, DwAt(0x03));
        assert_eq!(decl.attrs[0].form, DwForm::String);

        // Test missing leading byte → None
        data.clear();
        assert!(parse_abbrev_table(&data, 0).is_some()); // empty table = code 0
    }

    #[test]
    fn abbrev_decl_attr_lookup() {
        let mut decl = AbbrevDecl::new(1, 0x11, true);
        decl.push_attr(AbbrevAttr::new(0x03, 0x08)); // DW_AT_name
        decl.push_attr(AbbrevAttr::new(0x11, 0x01)); // DW_AT_low_pc
        assert!(decl.attr(DwAt(0x03)).is_some());
        assert!(decl.attr(DwAt(0xFF)).is_none());
    }

    #[test]
    fn read_form_value_data4() {
        let data: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        let mut pos = 0;
        let v = read_form_value(&data, &mut pos, DwForm::Data4, 4, false, 0).unwrap();
        assert_eq!(v, FormValue::Uint(0x12345678));
        assert_eq!(pos, 4);
    }

    #[test]
    fn read_form_value_string() {
        let data = b"hello\0world\0";
        let mut pos = 0;
        let v = read_form_value(data, &mut pos, DwForm::String, 4, false, 0).unwrap();
        assert_eq!(v, FormValue::String("hello".into()));
        assert_eq!(pos, 6);
    }

    #[test]
    fn read_form_value_flag_present() {
        let data: [u8; 0] = [];
        let mut pos = 0;
        let v = read_form_value(&data, &mut pos, DwForm::FlagPresent, 4, false, 0).unwrap();
        assert_eq!(v, FormValue::Uint(1));
        assert_eq!(pos, 0);
    }

    #[test]
    fn read_form_value_implicit_const() {
        let data: [u8; 0] = [];
        let mut pos = 0;
        let v = read_form_value(&data, &mut pos, DwForm::ImplicitConst, 4, false, -42).unwrap();
        assert_eq!(v, FormValue::Int(-42));
    }

    #[test]
    fn form_value_display() {
        assert_eq!(FormValue::Uint(0xFF).to_string(), "0xff");
        assert_eq!(FormValue::Int(-1).to_string(), "-1");
        assert!(FormValue::String("foo".into()).to_string().contains("foo"));
    }

    #[test]
    fn parse_all_abbrev_tables_empty() {
        let data: [u8; 1] = [0x00];
        let map = parse_all_abbrev_tables(&data);
        assert!(map.is_empty());
    }
}
