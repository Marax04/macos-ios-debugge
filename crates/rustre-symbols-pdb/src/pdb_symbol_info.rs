//! `pdb_symbol_info` — full PDB DBI stream and symbol record parser.
//!
//! Parses:
//! * DBI stream: module info, section contributions, source files
//! * Symbol records: `S_GPROC32`/`S_LPROC32`, `S_GDATA32`/`S_LDATA32`, `S_PUB32`,
//!   `S_CONSTANT`, `S_UDT`, `S_LOCAL`, `S_DEFRANGE_REGISTER`,
//!   `S_DEFRANGE_FRAMEPOINTER_REL`, `S_DEFRANGE_REGISTER_REL`,
//!   `S_INLINESITE`, `S_THUNK32`, `S_BLOCK32`, `S_LABEL32`

use std::collections::HashMap;

// ── Symbol record type codes ──────────────────────────────────────────────────

// Single source of truth: `crate::sym_kinds` (cvinfo.h SYM_ENUM_e).
pub use crate::sym_kinds::{
    S_BLOCK32, S_CONSTANT, S_GDATA32, S_GPROC32, S_LABEL32, S_LDATA32, S_LPROC32, S_PUB32,
    S_THUNK32, S_UDT,
};
/// Alias of [`S_CONSTANT`] kept for backwards compatibility.
pub const S_CONSTANT32: u16 = S_CONSTANT;
/// Alias of [`S_UDT`] kept for backwards compatibility.
pub const S_UDT32: u16 = S_UDT;
/// `S_LOCAL` — local variable symbol record type code.
pub const S_LOCAL: u16 = 0x113E;
/// `S_DEFRANGE_REGISTER` — live range of a local held in a register.
pub const S_DEFRANGE_REGISTER: u16 = 0x1141;
/// `S_DEFRANGE_FRAMEPOINTER_REL` — live range of a local at a frame-pointer-relative offset.
pub const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
/// `S_DEFRANGE_REGISTER_REL` — live range of a local at a register-relative offset.
pub const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
/// `S_INLINESITE` — inline call site symbol record type code.
pub const S_INLINESITE: u16 = 0x114D;
/// `S_INLINESITE_END` — end marker for an `S_INLINESITE` scope.
pub const S_INLINESITE_END: u16 = 0x114E;
/// `S_PROC_ID_END` — end marker for an id-variant procedure scope.
pub const S_PROC_ID_END: u16 = 0x114F;
/// `S_GPROC32_ID` — global procedure record referencing the IPI stream.
pub const S_GPROC32_ID: u16 = 0x1147;
/// `S_LPROC32_ID` — local procedure record referencing the IPI stream.
pub const S_LPROC32_ID: u16 = 0x1146;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced while parsing DBI or symbol record streams.
#[derive(Debug, thiserror::Error)]
pub enum SymInfoError {
    /// The stream ended before the offset the parser needed to read.
    #[error("stream too short at offset {0}")]
    TooShort(usize),
    /// A symbol record at the given offset is structurally invalid.
    #[error("corrupt symbol record at offset {0}")]
    Corrupt(usize),
}

/// Result alias for symbol-info parsing.
pub type Result<T> = std::result::Result<T, SymInfoError>;

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], off: usize) -> Result<u8> {
    data.get(off).copied().ok_or(SymInfoError::TooShort(off))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SymInfoError::TooShort(off))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SymInfoError::TooShort(off))
}

fn read_i32(data: &[u8], off: usize) -> Result<i32> {
    read_u32(data, off).map(u32::cast_signed)
}

fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    let start = off;
    let mut pos = off;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..pos]).into_owned();
    (s, if pos < data.len() { pos + 1 } else { pos })
}

// ── Module info ───────────────────────────────────────────────────────────────

/// A module (object file or lib entry) in the DBI module info sub-stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleInfo {
    /// Module name (typically the .obj path).
    pub name: String,
    /// Object file / archive path.
    pub object_file: String,
    /// Index into the PDB stream directory for this module's symbol sub-stream.
    pub stream_index: u16,
    /// Number of bytes of symbols in the module's symbol sub-stream.
    pub sym_byte_size: u32,
    /// Number of C13 line-info bytes.
    pub c13_byte_size: u32,
    /// Number of `GlobalRefs` bytes.
    pub global_refs_size: u32,
}

/// Parse the module-info sub-stream of the DBI stream.
/// `data` is the raw DBI stream; `module_info_size` comes from the DBI header at offset 24.
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_module_info(data: &[u8], module_info_size: u32) -> Result<Vec<ModuleInfo>> {
    let start = 64usize;
    let end = start + module_info_size as usize;
    if end > data.len() {
        return Err(SymInfoError::TooShort(end));
    }
    let mod_data = &data[start..end];

    let mut modules = Vec::new();
    let mut off = 0usize;

    while off + 64 <= mod_data.len() {
        // Fixed 64-byte header per ModInfo record (simplified layout):
        // [0..4]   opened (unused)
        // [4..8]   section (SectionContrib, 28 bytes total) – skip
        // [32..34] flags
        // [34..36] stream_index
        // [36..40] sym_byte_size
        // [40..44] c11_byte_size (old)
        // [44..48] c13_byte_size
        // [48..50] source_file_count
        // [50..52] pad
        // [52..56] unused
        // [56..60] global_refs_size
        // [60..64] ec_info_size
        let stream_index = read_u16(mod_data, off + 34)?;
        let sym_byte_size = read_u32(mod_data, off + 36)?;
        let c13_byte_size = read_u32(mod_data, off + 44)?;
        let global_refs_size = read_u32(mod_data, off + 56)?;

        let (name, after_name) = read_cstring(mod_data, off + 64);
        let (object_file, after_obj) = read_cstring(mod_data, after_name);

        modules.push(ModuleInfo {
            name,
            object_file,
            stream_index,
            sym_byte_size,
            c13_byte_size,
            global_refs_size,
        });

        // Records are 4-byte aligned.
        let record_size = after_obj - off;
        off += (record_size + 3) & !3;
    }

    Ok(modules)
}

// ── Section contributions ─────────────────────────────────────────────────────

/// A section contribution record from the DBI `SectionContrib` sub-stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SectionContrib {
    /// 1-based section index the contribution belongs to.
    pub section: u16,
    /// Byte offset of the contribution within the section.
    pub offset: u32,
    /// Size of the contribution in bytes.
    pub size: u32,
    /// COFF section characteristics flags.
    pub characteristics: u32,
    /// Index of the contributing module in the module-info sub-stream.
    pub module_index: u16,
}

/// Parse the `SectionContrib` sub-stream (follows the module-info sub-stream).
/// `offset_in_dbi` = 64 + `module_info_size` + `section_contrib_offset` (DBI header[28..32]).
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_section_contribs(data: &[u8], start: usize, size: u32) -> Result<Vec<SectionContrib>> {
    let end = start + size as usize;
    if end > data.len() {
        return Err(SymInfoError::TooShort(end));
    }
    let sc_data = &data[start..end];
    let mut contribs = Vec::new();
    let mut off = 0usize;

    // Version word (4 bytes) at start.
    if sc_data.len() < 4 {
        return Ok(contribs);
    }
    let version = read_u32(sc_data, 0)?;
    let entry_size = if version == 0xeffe_0000 + 19_970_605 { 28 } else { 60 };
    off += 4;

    while off + entry_size <= sc_data.len() {
        let section = read_u16(sc_data, off)?;
        // pad2 at off+2
        let sc_offset = read_u32(sc_data, off + 4)?;
        let sc_size = read_u32(sc_data, off + 8)?;
        let characteristics = read_u32(sc_data, off + 12)?;
        let module_index = read_u16(sc_data, off + 16)?;
        contribs.push(SectionContrib {
            section,
            offset: sc_offset,
            size: sc_size,
            characteristics,
            module_index,
        });
        off += entry_size;
    }

    Ok(contribs)
}

// ── Symbol record data types ──────────────────────────────────────────────────

/// A function symbol (`S_GPROC32` / `S_LPROC32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcSymbol {
    /// Function name.
    pub name: String,
    /// Offset of the function within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// Length of the function body in bytes.
    pub length: u32,
    /// Offset of the end of the prologue relative to the function start.
    pub debug_start: u32,
    /// Offset of the start of the epilogue relative to the function start.
    pub debug_end: u32,
    /// TPI type index of the function's type.
    pub type_index: u32,
    /// `CV_PROCFLAGS` bit flags.
    pub flags: u8,
    /// True for `S_GPROC32`, false for `S_LPROC32`.
    pub is_global: bool,
}

/// A data symbol (`S_GDATA32` / `S_LDATA32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataSymbol {
    /// Variable name.
    pub name: String,
    /// Offset of the data within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// TPI type index of the variable's type.
    pub type_index: u32,
    /// True for `S_GDATA32`, false for `S_LDATA32`.
    pub is_global: bool,
}

/// A public symbol (`S_PUB32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicSymbol {
    /// Mangled public symbol name.
    pub name: String,
    /// Offset of the symbol within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// `CV_PUBSYMFLAGS` bit flags (code/function/managed/MSIL).
    pub flags: u32,
}

/// A named constant (`S_CONSTANT`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstantSymbol {
    /// Constant name.
    pub name: String,
    /// TPI type index of the constant's type.
    pub type_index: u32,
    /// Constant value decoded from the numeric leaf.
    pub value: u64,
}

/// A UDT (user-defined type) alias symbol (`S_UDT`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdtSymbol {
    /// Type alias name.
    pub name: String,
    /// TPI type index the alias refers to.
    pub type_index: u32,
}

/// A local variable symbol (`S_LOCAL`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalSymbol {
    /// Local variable name.
    pub name: String,
    /// TPI type index of the local's type.
    pub type_index: u32,
    /// `CV_LVARFLAGS` bit flags (parameter, enregistered, ...).
    pub flags: u16,
}

/// A defrange record for a local in a register (`S_DEFRANGE_REGISTER`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefrangeRegister {
    /// `CodeView` register number holding the variable.
    pub register: u16,
    /// Attribute flags (`CV_RANGEATTR`).
    pub may_have_no_name: u16,
    /// Start offset of the live range within its section.
    pub range_offset: u32,
    /// Section index of the live range.
    pub range_section: u16,
    /// Length of the live range in bytes.
    pub range_length: u16,
}

/// A defrange record relative to the frame pointer (`S_DEFRANGE_FRAMEPOINTER_REL`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefrangeFramePointerRel {
    /// Signed offset of the variable from the frame pointer.
    pub offset_from_fp: i32,
    /// Start offset of the live range within its section.
    pub range_offset: u32,
    /// Section index of the live range.
    pub range_section: u16,
    /// Length of the live range in bytes.
    pub range_length: u16,
}

/// A defrange for a register-relative location (`S_DEFRANGE_REGISTER_REL`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefrangeRegisterRel {
    /// `CodeView` register number used as the base.
    pub base_register: u16,
    /// Spilled-UDT-member flags and parent offset.
    pub flags: u16,
    /// Signed offset from the base register.
    pub base_pointer_offset: i32,
    /// Start offset of the live range within its section.
    pub range_offset: u32,
    /// Section index of the live range.
    pub range_section: u16,
    /// Length of the live range in bytes.
    pub range_length: u16,
}

/// Metadata for an inline callsite (`S_INLINESITE`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineSite {
    /// Offset of the parent scope record in the symbol stream.
    pub parent: u32,
    /// Offset of the matching end record in the symbol stream.
    pub end: u32,
    /// IPI item id of the inlined function.
    pub inlinee: u32,
    /// Raw binary annotation stream (compressed line/offset deltas).
    pub annotations: Vec<u8>,
}

/// A block symbol (`S_BLOCK32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockSymbol {
    /// Optional block name.
    pub name: String,
    /// Offset of the parent scope record in the symbol stream.
    pub parent: u32,
    /// Offset of the matching end record in the symbol stream.
    pub end: u32,
    /// Offset of the block's code within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// Length of the block's code in bytes.
    pub length: u32,
}

/// A label symbol (`S_LABEL32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LabelSymbol {
    /// Label name.
    pub name: String,
    /// Offset of the label within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// `CV_PROCFLAGS` bit flags.
    pub flags: u8,
}

/// A thunk symbol (`S_THUNK32`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThunkSymbol {
    /// Thunk name.
    pub name: String,
    /// Offset of the thunk within its segment.
    pub offset: u32,
    /// Segment (section) index.
    pub segment: u16,
    /// Length of the thunk in bytes.
    pub length: u16,
    /// `THUNK_ORDINAL` kind (no-type, adjustor, vcall, pcode, ...).
    pub thunk_kind: u8,
}

/// Parsed symbol from a module or global symbol stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SymbolRecord {
    /// Function symbol (`S_GPROC32`/`S_LPROC32`).
    Proc(ProcSymbol),
    /// Data symbol (`S_GDATA32`/`S_LDATA32`).
    Data(DataSymbol),
    /// Public symbol (`S_PUB32`).
    Public(PublicSymbol),
    /// Named constant (`S_CONSTANT`).
    Constant(ConstantSymbol),
    /// UDT alias (`S_UDT`).
    Udt(UdtSymbol),
    /// Local variable (`S_LOCAL`).
    Local(LocalSymbol),
    /// Register live range (`S_DEFRANGE_REGISTER`).
    DefrangeRegister(DefrangeRegister),
    /// Frame-pointer-relative live range (`S_DEFRANGE_FRAMEPOINTER_REL`).
    DefrangeFramePointerRel(DefrangeFramePointerRel),
    /// Register-relative live range (`S_DEFRANGE_REGISTER_REL`).
    DefrangeRegisterRel(DefrangeRegisterRel),
    /// Inline call site (`S_INLINESITE`).
    InlineSite(InlineSite),
    /// Lexical block (`S_BLOCK32`).
    Block(BlockSymbol),
    /// Code label (`S_LABEL32`).
    Label(LabelSymbol),
    /// Thunk (`S_THUNK32`).
    Thunk(ThunkSymbol),
    /// Procedure/scope end marker (`S_END`).
    ProcEnd,
    /// Inline site or id-procedure end marker (`S_INLINESITE_END`/`S_PROC_ID_END`).
    InlineSiteEnd,
    /// Any record type not decoded by this parser.
    Unknown {
        /// Raw `CodeView` record type code.
        rec_type: u16,
        /// Total record size in bytes (including the 4-byte header).
        size: usize,
    },
}

// ── Numeric value decoder (for S_CONSTANT) ────────────────────────────────────

/// Decode a `CodeView` numeric leaf starting at `off`.
/// Returns `(value_as_u64, bytes_consumed)`.
fn decode_numeric_leaf(payload: &[u8], off: usize) -> (u64, usize) {
    if off + 2 > payload.len() {
        return (0, 0);
    }
    let leaf = u16::from_le_bytes([payload[off], payload[off + 1]]);
    if leaf < 0x8000 {
        // inline small integer
        return (u64::from(leaf), 2);
    }
    match leaf {
        0x8000 => {
            // LF_CHAR — 1 byte signed
            let v = i64::from(payload.get(off + 2).copied().unwrap_or(0).cast_signed()).cast_unsigned();
            (v, 3)
        }
        0x8001 => {
            // LF_SHORT
            if off + 4 <= payload.len() {
                let v = i64::from(i16::from_le_bytes([payload[off + 2], payload[off + 3]])).cast_unsigned();
                (v, 4)
            } else {
                (0, 2)
            }
        }
        0x8002 => {
            // LF_USHORT
            if off + 4 <= payload.len() {
                let v = u16::from_le_bytes([payload[off + 2], payload[off + 3]]);
                (u64::from(v), 4)
            } else {
                (0, 2)
            }
        }
        0x8003 => {
            // LF_LONG
            if off + 6 <= payload.len() {
                let v = i64::from(i32::from_le_bytes(payload[off + 2..off + 6].try_into().unwrap())).cast_unsigned();
                (v, 6)
            } else {
                (0, 2)
            }
        }
        0x8004 => {
            // LF_ULONG
            if off + 6 <= payload.len() {
                let v = u32::from_le_bytes(payload[off + 2..off + 6].try_into().unwrap());
                (u64::from(v), 6)
            } else {
                (0, 2)
            }
        }
        0x8009
            // LF_QUADWORD
            if off + 10 <= payload.len() => {
                let v = u64::from_le_bytes(payload[off + 2..off + 10].try_into().unwrap());
                (v, 10)
            }
        _ => (0, 2),
    }
}

// ── Symbol record parser ──────────────────────────────────────────────────────

/// Parse all symbol records from a raw symbol stream (global or module).
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_symbol_records(data: &[u8]) -> Result<Vec<SymbolRecord>> {
    let mut records = Vec::new();
    let mut off = 0usize;

    while off + 4 <= data.len() {
        let length = read_u16(data, off)? as usize;
        if length < 2 {
            break;
        }
        let rec_type = read_u16(data, off + 2)?;
        let payload_end = off + 2 + length;
        let payload = data.get(off + 4..payload_end).unwrap_or(&[]);

        let record = parse_one_symbol(rec_type, payload, off)?;
        records.push(record);

        off = (payload_end + 3) & !3;
    }

    Ok(records)
}

fn parse_defrange_register(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 12 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let register = read_u16(payload, 0)?;
    let may_have_no_name = read_u16(payload, 2)?;
    let range_offset = read_u32(payload, 4)?;
    let range_section = read_u16(payload, 8)?;
    let range_length = read_u16(payload, 10)?;
    Ok(SymbolRecord::DefrangeRegister(DefrangeRegister {
        register, may_have_no_name, range_offset, range_section, range_length,
    }))
}

fn parse_defrange_fp_rel(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 12 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let offset_from_fp = read_i32(payload, 0)?;
    let range_offset = read_u32(payload, 4)?;
    let range_section = read_u16(payload, 8)?;
    let range_length = read_u16(payload, 10)?;
    Ok(SymbolRecord::DefrangeFramePointerRel(DefrangeFramePointerRel {
        offset_from_fp, range_offset, range_section, range_length,
    }))
}

fn parse_defrange_register_rel(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 16 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let base_register = read_u16(payload, 0)?;
    let flags = read_u16(payload, 2)?;
    let base_pointer_offset = read_i32(payload, 4)?;
    let range_offset = read_u32(payload, 8)?;
    let range_section = read_u16(payload, 12)?;
    let range_length = read_u16(payload, 14)?;
    Ok(SymbolRecord::DefrangeRegisterRel(DefrangeRegisterRel {
        base_register, flags, base_pointer_offset,
        range_offset, range_section, range_length,
    }))
}

fn parse_inlinesite(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 12 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let parent = read_u32(payload, 0)?;
    let end = read_u32(payload, 4)?;
    let inlinee = read_u32(payload, 8)?;
    let annotations = payload.get(12..).unwrap_or(&[]).to_vec();
    Ok(SymbolRecord::InlineSite(InlineSite { parent, end, inlinee, annotations }))
}

fn parse_proc(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    // parent(4)+end(4)+next(4)+len(4)+dbg_start(4)+dbg_end(4)+typind(4)+offset(4)+seg(2)+flags(1)+name
    if payload.len() < 36 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let length = read_u32(payload, 12)?;
    let debug_start = read_u32(payload, 16)?;
    let debug_end = read_u32(payload, 20)?;
    let type_index = read_u32(payload, 24)?;
    let offset = read_u32(payload, 28)?;
    let segment = read_u16(payload, 32)?;
    let flags = read_u8(payload, 34)?;
    let (name, _) = read_cstring(payload, 35);
    Ok(SymbolRecord::Proc(ProcSymbol {
        name, offset, segment, length, debug_start, debug_end, type_index, flags,
        is_global: rec_type == S_GPROC32 || rec_type == S_GPROC32_ID,
    }))
}

fn parse_data_sym(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 10 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let type_index = read_u32(payload, 0)?;
    let offset = read_u32(payload, 4)?;
    let segment = read_u16(payload, 8)?;
    let (name, _) = read_cstring(payload, 10);
    Ok(SymbolRecord::Data(DataSymbol {
        name, offset, segment, type_index, is_global: rec_type == S_GDATA32,
    }))
}

fn parse_pub32(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 10 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let flags = read_u32(payload, 0)?;
    let offset = read_u32(payload, 4)?;
    let segment = read_u16(payload, 8)?;
    let (name, _) = read_cstring(payload, 10);
    Ok(SymbolRecord::Public(PublicSymbol { name, offset, segment, flags }))
}

fn parse_constant(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 6 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let type_index = read_u32(payload, 0)?;
    let (value, consumed) = decode_numeric_leaf(payload, 4);
    let (name, _) = read_cstring(payload, 4 + consumed);
    Ok(SymbolRecord::Constant(ConstantSymbol { name, type_index, value }))
}

fn parse_udt(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 4 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let type_index = read_u32(payload, 0)?;
    let (name, _) = read_cstring(payload, 4);
    Ok(SymbolRecord::Udt(UdtSymbol { name, type_index }))
}

fn parse_local(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 6 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let type_index = read_u32(payload, 0)?;
    let flags = read_u16(payload, 4)?;
    let (name, _) = read_cstring(payload, 6);
    Ok(SymbolRecord::Local(LocalSymbol { name, type_index, flags }))
}

fn parse_block32(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 18 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let parent = read_u32(payload, 0)?;
    let end = read_u32(payload, 4)?;
    let length = read_u32(payload, 8)?;
    let offset = read_u32(payload, 12)?;
    let segment = read_u16(payload, 16)?;
    let (name, _) = read_cstring(payload, 18);
    Ok(SymbolRecord::Block(BlockSymbol { name, parent, end, offset, segment, length }))
}

fn parse_label32(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 7 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let offset = read_u32(payload, 0)?;
    let segment = read_u16(payload, 4)?;
    let flags = read_u8(payload, 6)?;
    let (name, _) = read_cstring(payload, 7);
    Ok(SymbolRecord::Label(LabelSymbol { name, offset, segment, flags }))
}

fn parse_thunk32(rec_type: u16, payload: &[u8]) -> Result<SymbolRecord> {
    if payload.len() < 19 {
        return Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 });
    }
    let offset = read_u32(payload, 12)?;
    let segment = read_u16(payload, 16)?;
    let length = read_u16(payload, 18)?;
    let thunk_kind = payload.get(20).copied().unwrap_or(0);
    let (name, _) = read_cstring(payload, 21.min(payload.len()));
    Ok(SymbolRecord::Thunk(ThunkSymbol { name, offset, segment, length, thunk_kind }))
}

fn parse_one_symbol(rec_type: u16, payload: &[u8], _base_off: usize) -> Result<SymbolRecord> {
    match rec_type {
        S_GPROC32 | S_LPROC32 | S_GPROC32_ID | S_LPROC32_ID => parse_proc(rec_type, payload),
        S_GDATA32 | S_LDATA32 => parse_data_sym(rec_type, payload),
        S_PUB32 => parse_pub32(rec_type, payload),
        S_CONSTANT32 => parse_constant(rec_type, payload),
        S_UDT32 => parse_udt(rec_type, payload),
        S_LOCAL => parse_local(rec_type, payload),
        S_DEFRANGE_REGISTER => parse_defrange_register(rec_type, payload),
        S_DEFRANGE_FRAMEPOINTER_REL => parse_defrange_fp_rel(rec_type, payload),
        S_DEFRANGE_REGISTER_REL => parse_defrange_register_rel(rec_type, payload),
        S_INLINESITE => parse_inlinesite(rec_type, payload),
        S_INLINESITE_END | S_PROC_ID_END => Ok(SymbolRecord::InlineSiteEnd),
        0x0006 => Ok(SymbolRecord::ProcEnd), // S_END
        S_BLOCK32 => parse_block32(rec_type, payload),
        S_LABEL32 => parse_label32(rec_type, payload),
        S_THUNK32 => parse_thunk32(rec_type, payload),
        _ => Ok(SymbolRecord::Unknown { rec_type, size: payload.len() + 4 }),
    }
}

// ── SymbolIndex — address-indexed lookup ──────────────────────────────────────

/// An index mapping RVA (section-relative offset) to symbol records.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    /// RVA -> list of (record index, `kind_tag`)
    pub by_offset: HashMap<u32, Vec<usize>>,
    /// All parsed symbol records in stream order.
    pub records: Vec<SymbolRecord>,
}

impl SymbolIndex {
    /// Build from parsed symbol records.
    #[must_use]
    pub fn build(records: Vec<SymbolRecord>) -> Self {
        let mut by_offset: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, rec) in records.iter().enumerate() {
            let offset = match rec {
                SymbolRecord::Proc(p) => Some(p.offset),
                SymbolRecord::Data(d) => Some(d.offset),
                SymbolRecord::Public(p) => Some(p.offset),
                SymbolRecord::Label(l) => Some(l.offset),
                SymbolRecord::Thunk(t) => Some(t.offset),
                SymbolRecord::Block(b) => Some(b.offset),
                _ => None,
            };
            if let Some(off) = offset {
                by_offset.entry(off).or_default().push(i);
            }
        }
        Self { by_offset, records }
    }

    /// Look up all symbols at the given offset.
    #[must_use]
    pub fn at_offset(&self, offset: u32) -> Vec<&SymbolRecord> {
        self.by_offset
            .get(&offset)
            .map(|idxs| idxs.iter().map(|&i| &self.records[i]).collect())
            .unwrap_or_default()
    }

    /// Filter function symbols.
    #[must_use]
    pub fn functions(&self) -> Vec<&ProcSymbol> {
        self.records
            .iter()
            .filter_map(|r| if let SymbolRecord::Proc(p) = r { Some(p) } else { None })
            .collect()
    }

    /// Filter data symbols.
    #[must_use]
    pub fn data_symbols(&self) -> Vec<&DataSymbol> {
        self.records
            .iter()
            .filter_map(|r| if let SymbolRecord::Data(d) = r { Some(d) } else { None })
            .collect()
    }
}

// ── Source file table ─────────────────────────────────────────────────────────

/// Parsed source file entry from the DBI file-info sub-stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceFile {
    /// Source file path.
    pub name: String,
    /// Index of the module that references this file.
    pub module_index: u16,
}

/// Parse the file-info sub-stream of DBI.
/// `start` = byte offset inside `data` where the sub-stream begins.
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_file_info(data: &[u8], start: usize, size: u32) -> Result<Vec<SourceFile>> {
    let end = start + size as usize;
    if end > data.len() {
        return Err(SymInfoError::TooShort(end));
    }
    let fi = &data[start..end];
    if fi.len() < 4 {
        return Ok(vec![]);
    }
    let num_modules = read_u16(fi, 0)? as usize;
    let num_files = read_u16(fi, 2)? as usize;
    if fi.len() < 4 + num_modules * 2 + num_modules * 2 + num_files * 4 {
        return Ok(vec![]);
    }
    // Layout after the 4-byte header:
    //   u16 mod_indices[num_modules]      (truncated prefix sums — ignored)
    //   u16 mod_file_counts[num_modules]
    //   u32 file_name_offsets[num_files]
    //   NUL-separated string buffer
    let counts_start = 4 + num_modules * 2;
    let file_name_offsets_start = 4 + num_modules * 4;
    // string buffer follows
    let str_buf_start = file_name_offsets_start + num_files * 4;
    let str_buf = fi.get(str_buf_start..).unwrap_or(&[]);

    let mut files = Vec::with_capacity(num_files);
    // Running prefix sum of file counts; `mod_indices` in the file is a u16
    // that saturates on large PDBs, so we recompute it in usize.
    let mut file_start_idx = 0usize;
    for module_i in 0..num_modules {
        let file_count = read_u16(fi, counts_start + module_i * 2).unwrap_or(0) as usize;
        for f in 0..file_count {
            let name_off_idx = file_name_offsets_start + (file_start_idx + f) * 4;
            if name_off_idx + 4 > fi.len() {
                break;
            }
            let name_off = read_u32(fi, name_off_idx)? as usize;
            if name_off >= str_buf.len() {
                continue;
            }
            let end_pos = str_buf[name_off..]
                .iter()
                .position(|&b| b == 0)
                .map_or(str_buf.len(), |p| name_off + p);
            let name = String::from_utf8_lossy(&str_buf[name_off..end_pos]).into_owned();
            files.push(SourceFile {
                name,
                module_index: u16::try_from(module_i).unwrap_or(u16::MAX),
            });
        }
        file_start_idx += file_count;
    }
    Ok(files)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pub32_payload(name: &str, offset: u32, flags: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&flags.to_le_bytes());
        p.extend_from_slice(&offset.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes()); // segment
        p.extend_from_slice(name.as_bytes());
        p.push(0);
        p
    }

    fn frame_record(rec_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&rec_type.to_le_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn test_parse_pub32() {
        let stream = frame_record(S_PUB32, &make_pub32_payload("my_func", 0x1000, 0x2));
        let records = parse_symbol_records(&stream).unwrap();
        assert_eq!(records.len(), 1);
        if let SymbolRecord::Public(p) = &records[0] {
            assert_eq!(p.name, "my_func");
            assert_eq!(p.offset, 0x1000);
        } else {
            panic!("expected PublicSymbol");
        }
    }

    #[test]
    fn test_parse_gdata32() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u32.to_le_bytes()); // type_index
        payload.extend_from_slice(&0x2000u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // segment
        payload.extend_from_slice(b"global_var\x00");
        let stream = frame_record(S_GDATA32, &payload);
        let records = parse_symbol_records(&stream).unwrap();
        assert_eq!(records.len(), 1);
        if let SymbolRecord::Data(d) = &records[0] {
            assert_eq!(d.name, "global_var");
            assert!(d.is_global);
        } else {
            panic!("expected DataSymbol");
        }
    }

    #[test]
    fn test_parse_local_symbol() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x74u32.to_le_bytes()); // type_index
        payload.extend_from_slice(&0x0000u16.to_le_bytes()); // flags
        payload.extend_from_slice(b"my_local\x00");
        let stream = frame_record(S_LOCAL, &payload);
        let records = parse_symbol_records(&stream).unwrap();
        assert_eq!(records.len(), 1);
        if let SymbolRecord::Local(l) = &records[0] {
            assert_eq!(l.name, "my_local");
            assert_eq!(l.type_index, 0x74);
        } else {
            panic!("expected LocalSymbol");
        }
    }

    #[test]
    fn test_parse_defrange_framepointer_rel() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(-8i32).to_le_bytes()); // offset_from_fp
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // range_offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // range_section
        payload.extend_from_slice(&0x20u16.to_le_bytes()); // range_length
        let stream = frame_record(S_DEFRANGE_FRAMEPOINTER_REL, &payload);
        let records = parse_symbol_records(&stream).unwrap();
        assert_eq!(records.len(), 1);
        if let SymbolRecord::DefrangeFramePointerRel(d) = &records[0] {
            assert_eq!(d.offset_from_fp, -8);
            assert_eq!(d.range_length, 0x20);
        } else {
            panic!("expected DefrangeFramePointerRel");
        }
    }

    #[test]
    fn test_parse_label32() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x3000u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0u8); // flags
        payload.extend_from_slice(b"loop_start\x00");
        let stream = frame_record(S_LABEL32, &payload);
        let records = parse_symbol_records(&stream).unwrap();
        if let SymbolRecord::Label(l) = &records[0] {
            assert_eq!(l.name, "loop_start");
        } else {
            panic!("expected LabelSymbol");
        }
    }

    #[test]
    fn test_symbol_index_lookup() {
        let records = vec![
            SymbolRecord::Public(PublicSymbol {
                name: "foo".into(),
                offset: 0x1000,
                segment: 1,
                flags: 0,
            }),
            SymbolRecord::Label(LabelSymbol {
                name: "bar".into(),
                offset: 0x2000,
                segment: 1,
                flags: 0,
            }),
        ];
        let idx = SymbolIndex::build(records);
        assert_eq!(idx.at_offset(0x1000).len(), 1);
        assert_eq!(idx.at_offset(0x9999).len(), 0);
    }

    #[test]
    fn test_symbol_index_functions() {
        let records = vec![
            SymbolRecord::Proc(ProcSymbol {
                name: "main".into(),
                offset: 0x1000,
                segment: 1,
                length: 0x100,
                debug_start: 0,
                debug_end: 0,
                type_index: 0,
                flags: 0,
                is_global: true,
            }),
            SymbolRecord::Public(PublicSymbol {
                name: "data".into(),
                offset: 0x2000,
                segment: 2,
                flags: 0,
            }),
        ];
        let idx = SymbolIndex::build(records);
        assert_eq!(idx.functions().len(), 1);
        assert_eq!(idx.data_symbols().len(), 0);
    }

    #[test]
    fn test_empty_stream() {
        let records = parse_symbol_records(&[]).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_decode_numeric_leaf_inline() {
        let data = [0x2Au8, 0x00]; // 42 inline
        let (v, n) = decode_numeric_leaf(&data, 0);
        assert_eq!(v, 42);
        assert_eq!(n, 2);
    }

    #[test]
    fn test_decode_numeric_leaf_long() {
        let mut data = vec![0x03u8, 0x80]; // LF_LONG
        data.extend_from_slice(&(-1i32).to_le_bytes());
        let (v, n) = decode_numeric_leaf(&data, 0);
        assert_eq!(n, 6);
        assert_eq!(v.cast_signed(), -1);
    }
}
