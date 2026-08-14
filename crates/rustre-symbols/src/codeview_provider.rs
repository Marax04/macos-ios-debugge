//! `CodeView` symbol provider —  parses `CodeView` 4.0 / NB10 / NB11 debug data.
//!
//! Supports:
//! * `CV_SymRecord` types: `S_PUB32`, `S_GPROC32`, `S_LPROC32`, `S_GDATA32`, `S_LDATA32`, `S_LABEL32`
//! * `CV_TypeRecord` types: `LF_STRUCTURE`, `LF_ARRAY`, `LF_POINTER`, `LF_PROCEDURE`
//! * `.pdb 2.0` `CodeView` stream (signature "NB10" / "NB11" / "RSDS")
//! * Implements [`SymbolProvider`] for drop-in use in a [`crate::SymbolTable`].

use crate::{
    LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding, SymbolProvider,
    SymbolVisibility, TypeInfo,
};
use std::collections::HashMap;
use std::fmt;

// â"€â"€ CodeView signature constants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// `NB10` `CodeView` signature (PDB 2.0 external debug info).
pub const CV_SIGNATURE_NB10: u32 = 0x3031_424e; // "NB10"
/// `NB11` `CodeView` signature.
pub const CV_SIGNATURE_NB11: u32 = 0x3131_424e; // "NB11"
/// `RSDS` `CodeView` signature (PDB 7.0 external debug info; carries a GUID+age).
pub const CV_SIGNATURE_RSDS: u32 = 0x5344_5352; // "RSDS"

// â"€â"€ Symbol-record type codes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A recognised `CodeView` symbol-record kind (`S_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CvSymKind {
    /// `S_PUB32` — public symbol.
    SPub32 = 0x0203,
    /// `S_GPROC32` — global procedure.
    SGproc32 = 0x1110,
    /// `S_LPROC32` — local (static) procedure.
    SLproc32 = 0x110f,
    /// `S_GDATA32` — global data.
    SGdata32 = 0x110d,
    /// `S_LDATA32` — local (static) data.
    SLdata32 = 0x110c,
    /// `S_LABEL32` — a code label.
    SLabel32 = 0x1105,
    /// Any unrecognised record kind.
    SUnknown = 0xffff,
}

impl CvSymKind {
    /// Map a raw `S_*` record type to a [`CvSymKind`] (`SUnknown` if unknown).
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0203 => Self::SPub32,
            0x1110 => Self::SGproc32,
            0x110f => Self::SLproc32,
            0x110d => Self::SGdata32,
            0x110c => Self::SLdata32,
            0x1105 => Self::SLabel32,
            _ => Self::SUnknown,
        }
    }
    /// Map to the crate's [`SymKind`] (public symbols are treated as functions).
    #[must_use]
    pub const fn to_sym_kind(self) -> SymKind {
        // SPub32 is usually a function export, so grouped with Gproc32/Lproc32.
        match self {
            Self::SGproc32 | Self::SLproc32 | Self::SPub32 => SymKind::Function,
            Self::SLabel32 => SymKind::Label,
            Self::SGdata32 | Self::SLdata32 | Self::SUnknown => SymKind::Data,
        }
    }
}

// â"€â"€ Type-record leaf codes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A recognised `CodeView` type-record leaf kind (`LF_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CvLeafKind {
    /// `LF_STRUCTURE` — a struct type.
    LfStructure = 0x1505,
    /// `LF_ARRAY` — an array type.
    LfArray = 0x1503,
    /// `LF_POINTER` — a pointer type.
    LfPointer = 0x1002,
    /// `LF_PROCEDURE` — a procedure/function type.
    LfProcedure = 0x1008,
    /// Any unrecognised leaf.
    LfUnknown = 0xffff,
}

impl CvLeafKind {
    /// Map a raw `LF_*` leaf to a [`CvLeafKind`] (`LfUnknown` if unknown).
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x1505 => Self::LfStructure,
            0x1503 => Self::LfArray,
            0x1002 => Self::LfPointer,
            0x1008 => Self::LfProcedure,
            _ => Self::LfUnknown,
        }
    }
}

impl fmt::Display for CvSymKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for CvLeafKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// â"€â"€ CV_SymRecord â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A decoded `CodeView` symbol record.
#[derive(Debug, Clone)]
pub struct CvSymRecord {
    /// Record size in bytes (including the `kind` field).
    pub record_size: u16,
    /// The record's `CodeView` kind.
    pub kind: CvSymKind,
    /// The symbol name (still mangled).
    pub name: String,
    /// Offset into the section (for GPROC/LPROC/DATA/LABEL).
    pub offset: u32,
    /// Section index.
    pub segment: u16,
    /// Size of the procedure in bytes (proc records only).
    pub proc_size: u32,
    /// Type index.
    pub type_index: u32,
    /// Procedure flags (`CV_PROCFLAGS`); 0 for non-procedure records.
    pub flags: u8,
}

impl CvSymRecord {
    /// Convert to a [`Symbol`], applying a section-offset â†' VA map.
    #[must_use]
    pub fn to_symbol(&self, section_bases: &[u64], base_addr: u64) -> Symbol {
        let va = if self.segment == 0 || self.segment as usize > section_bases.len() {
            base_addr.wrapping_add(u64::from(self.offset))
        } else {
            section_bases[self.segment as usize - 1].wrapping_add(u64::from(self.offset))
        };
        let binding = if matches!(self.kind, CvSymKind::SLproc32 | CvSymKind::SLdata32) {
            SymbolBinding::Local
        } else {
            SymbolBinding::Global
        };
        let mut sym = Symbol {
            id: va,
            name: self.name.clone(),
            demangled_name: None,
            address: va,
            size: if self.proc_size > 0 {
                Some(u64::from(self.proc_size))
            } else {
                None
            },
            kind: self.kind.to_sym_kind(),
            binding,
            visibility: SymbolVisibility::Default,
            section_index: if self.segment > 0 {
                Some(self.segment)
            } else {
                None
            },
            file_offset: None,
            source: LegacySymbolSource::Debug,
            source_file: None,
            source_line: None,
            ordinal: None,
            tags: vec!["codeview".into()],
        };
        sym.type_index_tag(&self.type_index.to_string());
        sym
    }
}

trait SymbolTagHelper {
    fn type_index_tag(&mut self, index: &str);
}
impl SymbolTagHelper for Symbol {
    fn type_index_tag(&mut self, index: &str) {
        self.tags.push(format!("cv_type:{index}"));
    }
}

// â"€â"€ CV_TypeRecord â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A decoded `CodeView` type record.
#[derive(Debug, Clone)]
pub struct CvTypeRecord {
    /// The record's type index (TI).
    pub type_index: u32,
    /// The record's leaf kind.
    pub leaf: CvLeafKind,
    /// The type's name, if the leaf carries one.
    pub name: Option<String>,
    /// The recovered type description.
    pub type_info: TypeInfo,
}

// â"€â"€ CodeView stream â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The parsed content of a `CodeView` debug stream.
#[derive(Debug, Default, Clone)]
pub struct CodeViewStream {
    /// The `CodeView` signature (`NB10`/`NB11`/`RSDS`).
    pub signature: u32,
    /// PDB age (incremented on each edit), matched against the external PDB.
    pub age: u32,
    /// The 16-byte PDB GUID (RSDS) or signature bytes.
    pub guid: [u8; 16],
    /// Path of the external PDB file, if the stream names one.
    pub pdb_file_name: Option<String>,
    /// Decoded symbol records.
    pub sym_records: Vec<CvSymRecord>,
    /// Decoded type records.
    pub type_records: Vec<CvTypeRecord>,
    /// section bases (index 0 = section 1) for VA resolution.
    pub section_bases: Vec<u64>,
    /// Image base address added to section-relative offsets.
    pub base_addr: u64,
}

// â"€â"€ Parsing utilities â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn read_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}
fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_cstr(data: &[u8], off: usize) -> Option<(String, usize)> {
    // `off` may exceed `data.len()` on truncated inputs; never index directly.
    let slice = data.get(off..)?;
    let end = slice.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&slice[..end]).ok()?.to_string();
    Some((s, off + end + 1))
}
// Length-prefixed Pascal string (1 byte length + chars, no NUL).
fn read_pstring(data: &[u8], off: usize) -> Option<(String, usize)> {
    let len = *data.get(off)? as usize;
    let s = std::str::from_utf8(data.get(off + 1..off + 1 + len)?)
        .ok()?
        .to_string();
    Some((s, off + 1 + len))
}

/// How symbol names are encoded in a `CodeView` symbol stream.
///
/// Whether a name is a length-prefixed Pascal string (CV4 / 16-bit era) or
/// NUL-terminated (CV8 / C13, i.e. everything modern) is a property of the
/// stream signature, not something that can be guessed per record: a Pascal
/// decode of a NUL-terminated name succeeds spuriously whenever the first
/// character's byte value happens to be a valid in-bounds length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvNameEncoding {
    /// NUL-terminated (NB10 / NB11 / RSDS / C13).
    CStr,
    /// Length-prefixed Pascal string (CV4 / NB09-era).
    Pascal,
    /// Signature not recognised — try `CStr` first, then Pascal.
    Unknown,
}

impl CvNameEncoding {
    /// Pick the encoding implied by a `CodeView` stream signature.
    #[must_use]
    pub const fn from_signature(sig: u32) -> Self {
        match sig {
            CV_SIGNATURE_NB10 | CV_SIGNATURE_NB11 | CV_SIGNATURE_RSDS => Self::CStr,
            _ => Self::Unknown,
        }
    }
}

/// Decode a name at `off` using `enc`. `data` must already be clamped to the
/// end of the containing record so no decoder can read into the next one.
fn read_name(data: &[u8], off: usize, enc: CvNameEncoding) -> Option<(String, usize)> {
    match enc {
        CvNameEncoding::CStr => read_cstr(data, off),
        CvNameEncoding::Pascal => read_pstring(data, off),
        CvNameEncoding::Unknown => read_cstr(data, off).or_else(|| read_pstring(data, off)),
    }
}

// â"€â"€ Parse symbol records from a raw sym bytes slice â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse `CodeView` symbol records from a raw symbol-substream slice,
/// auto-detecting the name encoding.
#[must_use]
pub fn parse_sym_records(data: &[u8]) -> Vec<CvSymRecord> {
    parse_sym_records_with_encoding(data, CvNameEncoding::Unknown)
}

/// Parse symbol records, decoding names with the encoding implied by the
/// stream signature (see [`CvNameEncoding::from_signature`]).
#[must_use]
pub fn parse_sym_records_with_encoding(data: &[u8], enc: CvNameEncoding) -> Vec<CvSymRecord> {
    let mut records = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let Some(rec_size) = read_u16_le(data, off) else {
            break;
        };
        if rec_size < 2 {
            break;
        }
        let rec_end = off + 2 + rec_size as usize;
        if rec_end > data.len() {
            break;
        }
        let Some(kind_raw) = read_u16_le(data, off + 2) else {
            break;
        };
        let kind = CvSymKind::from_u16(kind_raw);
        // Clamp every decode to this record: a name decoder must never be able
        // to run past `rec_end` into an adjacent record's bytes.
        let rec_data = &data[..rec_end];
        let rec = match kind {
            CvSymKind::SPub32 => parse_pub32(rec_data, off + 4, rec_size, kind, enc),
            CvSymKind::SGproc32 | CvSymKind::SLproc32 => {
                parse_proc32(rec_data, off + 4, rec_size, kind, enc)
            }
            CvSymKind::SGdata32 | CvSymKind::SLdata32 => {
                parse_data32(rec_data, off + 4, rec_size, kind, enc)
            }
            CvSymKind::SLabel32 => parse_label32(rec_data, off + 4, rec_size, kind, enc),
            CvSymKind::SUnknown => None,
        };
        if let Some(r) = rec {
            records.push(r);
        }
        off = rec_end;
    }
    records
}

fn parse_pub32(
    data: &[u8],
    base: usize,
    rec_size: u16,
    kind: CvSymKind,
    enc: CvNameEncoding,
) -> Option<CvSymRecord> {
    // flags(4) offset(4) seg(2) name(pascal)
    let flags = read_u8(data, base)?;
    let offset = read_u32_le(data, base + 4)?;
    let segment = read_u16_le(data, base + 8)?;
    let (name, _) = read_name(data, base + 10, enc)?;
    Some(CvSymRecord {
        record_size: rec_size,
        kind,
        name,
        offset,
        segment,
        proc_size: 0,
        type_index: 0,
        flags,
    })
}

fn parse_proc32(
    data: &[u8],
    base: usize,
    rec_size: u16,
    kind: CvSymKind,
    enc: CvNameEncoding,
) -> Option<CvSymRecord> {
    // parent(4) end(4) next(4) len(4) dbg_start(4) dbg_end(4) type(4) offset(4) seg(2) flags(1) name(pascal)
    let proc_size = read_u32_le(data, base + 12)?;
    let type_index = read_u32_le(data, base + 24)?;
    let offset = read_u32_le(data, base + 28)?;
    let segment = read_u16_le(data, base + 32)?;
    let flags = read_u8(data, base + 34)?;
    let (name, _) = read_name(data, base + 35, enc)?;
    Some(CvSymRecord {
        record_size: rec_size,
        kind,
        name,
        offset,
        segment,
        proc_size,
        type_index,
        flags,
    })
}

fn parse_data32(
    data: &[u8],
    base: usize,
    rec_size: u16,
    kind: CvSymKind,
    enc: CvNameEncoding,
) -> Option<CvSymRecord> {
    // type(4) offset(4) seg(2) name(pascal)
    let type_index = read_u32_le(data, base)?;
    let offset = read_u32_le(data, base + 4)?;
    let segment = read_u16_le(data, base + 8)?;
    let (name, _) = read_name(data, base + 10, enc)?;
    Some(CvSymRecord {
        record_size: rec_size,
        kind,
        name,
        offset,
        segment,
        proc_size: 0,
        type_index,
        flags: 0,
    })
}

fn parse_label32(
    data: &[u8],
    base: usize,
    rec_size: u16,
    kind: CvSymKind,
    enc: CvNameEncoding,
) -> Option<CvSymRecord> {
    // offset(4) seg(2) flags(1) name(pascal)
    let offset = read_u32_le(data, base)?;
    let segment = read_u16_le(data, base + 4)?;
    let flags = read_u8(data, base + 6)?;
    let (name, _) = read_name(data, base + 7, enc)?;
    Some(CvSymRecord {
        record_size: rec_size,
        kind,
        name,
        offset,
        segment,
        proc_size: 0,
        type_index: 0,
        flags,
    })
}

// â"€â"€ Parse type records â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse `CodeView` type records from a raw type-substream slice, assigning
/// type indices starting at the conventional `0x1000`.
#[must_use]
pub fn parse_type_records(data: &[u8]) -> Vec<CvTypeRecord> {
    let mut records = Vec::new();
    let mut type_index = 0x1000u32;
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let Some(rec_size) = read_u16_le(data, off) else {
            break;
        };
        if rec_size < 2 {
            break;
        }
        let rec_end = off + 2 + rec_size as usize;
        if rec_end > data.len() {
            break;
        }
        let Some(leaf_raw) = read_u16_le(data, off + 2) else {
            break;
        };
        let leaf = CvLeafKind::from_u16(leaf_raw);
        let body = &data[off + 4..rec_end];
        let type_info = match leaf {
            CvLeafKind::LfStructure => parse_lf_structure(body),
            CvLeafKind::LfArray => parse_lf_array(body),
            CvLeafKind::LfPointer => parse_lf_pointer(body),
            CvLeafKind::LfProcedure => parse_lf_procedure(body),
            CvLeafKind::LfUnknown => TypeInfo::Unknown,
        };
        let name = extract_type_name(&type_info);
        records.push(CvTypeRecord {
            type_index,
            leaf,
            name,
            type_info,
        });
        type_index += 1;
        off = rec_end;
    }
    records
}

fn extract_type_name(ti: &TypeInfo) -> Option<String> {
    match ti {
        TypeInfo::Struct { name, .. } => Some(name.clone()),
        TypeInfo::Named(n) => Some(n.clone()),
        _ => None,
    }
}

/// Byte length of the numeric leaf at `off`, including its 2-byte leaf code
/// when it has one. Values below `LF_NUMERIC` (0x8000) are stored inline in
/// the u16 itself and occupy 2 bytes total.
fn numeric_leaf_len(body: &[u8], off: usize) -> Option<usize> {
    let v = read_u16_le(body, off)?;
    if v < 0x8000 {
        return Some(2);
    }
    let payload = match v {
        0x8000 => 1,               // LF_CHAR
        0x8001 | 0x8002 => 2,      // LF_SHORT / LF_USHORT
        0x8003 | 0x8004 => 4,      // LF_LONG / LF_ULONG
        0x8009 | 0x800a => 8,      // LF_QUADWORD / LF_UQUADWORD
        _ => return None,
    };
    Some(2 + payload)
}

fn parse_lf_structure(body: &[u8]) -> TypeInfo {
    // count(2) property(2) field(4) derived(4) vshape(4) size(num) name(pascal)
    // The fixed prefix is 2+2+4+4+4 = 16 bytes, then a variable-length numeric
    // leaf for `size`, and only then the name.
    if body.len() < 16 {
        return TypeInfo::Unknown;
    }
    let Some(num_len) = numeric_leaf_len(body, 16) else {
        return TypeInfo::Unknown;
    };
    let name_off = 16 + num_len;
    if let Some((name, _)) = read_pstring(body, name_off).or_else(|| read_cstr(body, name_off)) {
        TypeInfo::Struct {
            name,
            fields: vec![],
        }
    } else {
        TypeInfo::Unknown
    }
}

fn parse_lf_array(body: &[u8]) -> TypeInfo {
    // element_type(4) index_type(4) size(num) name(pascal)
    if body.len() < 8 {
        return TypeInfo::Unknown;
    }
    let _elem_type = read_u32_le(body, 0).unwrap_or(0);
    TypeInfo::Array {
        element: Box::new(TypeInfo::Unknown),
        count: 0,
    }
}

fn parse_lf_pointer(body: &[u8]) -> TypeInfo {
    if body.len() < 8 {
        return TypeInfo::Unknown;
    }
    let attr = read_u32_le(body, 4).unwrap_or(0);
    // CodeView LF_POINTER attribute layout: ptrtype[0:4], ptrmode[5:7],
    // isflat32[8], isvolatile[9], isconst[10], isunaligned[11],
    // isrestrict[12], size[13:18]. CV_PTR_NEAR32 (0x0a) and CV_PTR_64 (0x0c)
    // are ptrtype values and live in the low 5 bits.
    let ptr_type = (attr & 0x1f) as u8;
    let size = match ptr_type {
        0x0a | 0x0c => 8u8, // 64-bit
        _ => 4u8,           // 32-bit
    };
    TypeInfo::Pointer {
        target: Box::new(TypeInfo::Unknown),
        size,
    }
}

fn parse_lf_procedure(body: &[u8]) -> TypeInfo {
    if body.len() < 12 {
        return TypeInfo::Unknown;
    }
    TypeInfo::Function {
        return_type: Box::new(TypeInfo::Unknown),
        params: vec![],
    }
}

// â"€â"€ Parse a full CodeView / PDB 2.0 header block â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse a `CodeView` debug directory header block.
///
/// Decodes the `NB10`/`NB11` (`CV_INFO_PDB20`) or `RSDS` (`CV_INFO_PDB70`)
/// layout into a [`CodeViewStream`]. Returns `None` if the signature is
/// unrecognised or the block is too short.
#[must_use]
pub fn parse_codeview_header(data: &[u8]) -> Option<CodeViewStream> {
    if data.len() < 8 {
        return None;
    }
    let sig = read_u32_le(data, 0)?;
    let mut stream = CodeViewStream {
        signature: sig,
        ..Default::default()
    };

    match sig {
        CV_SIGNATURE_NB10 | CV_SIGNATURE_NB11 => {
            // CV_INFO_PDB20 layout: sig(4) offset(4) timestamp(4) age(4)
            // filename(NUL-term). Age is at +12, name at +16.
            stream.age = read_u32_le(data, 12).unwrap_or(0);
            if let Some((name, _)) = read_cstr(data, 16) {
                stream.pdb_file_name = Some(name);
            }
        }
        CV_SIGNATURE_RSDS => {
            // RSDS: GUID(16) age(4) filename(NUL-term)
            if data.len() >= 24 {
                stream.guid.copy_from_slice(&data[4..20]);
                stream.age = read_u32_le(data, 20).unwrap_or(0);
                if let Some((name, _)) = read_cstr(data, 24) {
                    stream.pdb_file_name = Some(name);
                }
            }
        }
        _ => return None,
    }
    Some(stream)
}

// â"€â"€ CodeViewProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// [`SymbolProvider`] backed by parsed `CodeView` debug data.
#[derive(Debug)]
pub struct CodeViewProvider {
    name: String,
    /// The parsed `CodeView` stream this provider serves symbols from.
    pub stream: CodeViewStream,
    by_addr: HashMap<u64, usize>, // va â†' index into `symbols`
    by_name: HashMap<String, usize>,
    symbols: Vec<Symbol>,
    type_map: HashMap<u32, CvTypeRecord>,
}

impl CodeViewProvider {
    /// Build from a pre-parsed [`CodeViewStream`].
    #[must_use]
    pub fn new(name: impl Into<String>, stream: CodeViewStream) -> Self {
        // Materialise symbols
        let mut symbols: Vec<Symbol> = stream
            .sym_records
            .iter()
            .map(|r| r.to_symbol(&stream.section_bases, stream.base_addr))
            .collect();
        // Sort by address for nearest lookup
        symbols.sort_by_key(|s| s.address);

        let by_addr: HashMap<u64, usize> = symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (s.address, i))
            .collect();
        let by_name: HashMap<String, usize> = symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name.clone(), i))
            .collect();
        let type_map: HashMap<u32, CvTypeRecord> = stream
            .type_records
            .iter()
            .map(|r| (r.type_index, r.clone()))
            .collect();

        Self {
            name: name.into(),
            stream,
            by_addr,
            by_name,
            symbols,
            type_map,
        }
    }

    /// Parse raw `CodeView` bytes + optional section table.
    pub fn from_raw(
        name: impl Into<String>,
        cv_data: &[u8],
        sym_data: &[u8],
        type_data: &[u8],
        section_bases: Vec<u64>,
        base_addr: u64,
    ) -> Option<Self> {
        let mut stream = parse_codeview_header(cv_data)?;
        let enc = CvNameEncoding::from_signature(stream.signature);
        stream.sym_records = parse_sym_records_with_encoding(sym_data, enc);
        stream.type_records = parse_type_records(type_data);
        stream.section_bases = section_bases;
        stream.base_addr = base_addr;
        Some(Self::new(name, stream))
    }

    /// Look up a type record by CV type index.
    #[must_use]
    pub fn type_record(&self, index: u32) -> Option<&CvTypeRecord> {
        self.type_map.get(&index)
    }

    /// Total number of loaded symbols.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Total number of loaded type records.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.type_map.len()
    }

    /// PDB file name extracted from the header (if any).
    #[must_use]
    pub fn pdb_file_name(&self) -> Option<&str> {
        self.stream.pdb_file_name.as_deref()
    }

    /// CV stream age.
    #[must_use]
    pub const fn age(&self) -> u32 {
        self.stream.age
    }

    /// CV GUID (for RSDS streams).
    #[must_use]
    pub const fn guid(&self) -> &[u8; 16] {
        &self.stream.guid
    }
}

impl SymbolProvider for CodeViewProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.by_name.get(name).map(|&i| self.symbols[i].clone())
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.by_addr.get(&addr).map(|&i| self.symbols[i].clone())
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        let idx = match self.symbols.binary_search_by_key(&addr, |s| s.address) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        Some(self.symbols[idx].clone())
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

    fn source_line_for_address(&self, _addr: u64) -> Option<SourceLocation> {
        None
    }
}

// â"€â"€ CodeViewIndex â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Multi-module index over several [`CodeViewProvider`]s.
#[derive(Debug, Default)]
pub struct CodeViewIndex {
    providers: Vec<CodeViewProvider>,
}

impl CodeViewIndex {
    /// Create an empty index over no providers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider (one `CodeView` module) to the index.
    pub fn add(&mut self, p: CodeViewProvider) {
        self.providers.push(p);
    }

    /// Look up a symbol by name across all modules (first match wins).
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.providers.iter().find_map(|p| p.lookup_name(name))
    }

    /// Look up a symbol by exact address across all modules (first match wins).
    #[must_use]
    pub fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.providers.iter().find_map(|p| p.lookup_address(addr))
    }

    /// Collect every symbol from every module.
    #[must_use]
    pub fn all_symbols(&self) -> Vec<Symbol> {
        self.providers
            .iter()
            .flat_map(super::SymbolProvider::all_symbols)
            .collect()
    }

    /// Number of modules (providers) in the index.
    #[must_use]
    pub const fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Total symbol count summed across all modules.
    #[must_use]
    pub fn total_symbols(&self) -> usize {
        self.providers
            .iter()
            .map(CodeViewProvider::symbol_count)
            .sum()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stream_with_syms(records: Vec<CvSymRecord>) -> CodeViewStream {
        CodeViewStream {
            signature: CV_SIGNATURE_NB10,
            age: 1,
            sym_records: records,
            section_bases: vec![0x1000, 0x2000], // sections 1 & 2
            base_addr: 0x0040_0000,
            ..Default::default()
        }
    }

    fn make_pub32(name: &str, offset: u32, seg: u16) -> CvSymRecord {
        CvSymRecord {
            record_size: 30,
            kind: CvSymKind::SPub32,
            name: name.into(),
            offset,
            segment: seg,
            proc_size: 0,
            type_index: 0,
            flags: 0,
        }
    }
    fn make_gproc32(name: &str, offset: u32, seg: u16, size: u32) -> CvSymRecord {
        CvSymRecord {
            record_size: 60,
            kind: CvSymKind::SGproc32,
            name: name.into(),
            offset,
            segment: seg,
            proc_size: size,
            type_index: 0x1001,
            flags: 0,
        }
    }
    fn make_ldata32(name: &str, offset: u32, seg: u16) -> CvSymRecord {
        CvSymRecord {
            record_size: 20,
            kind: CvSymKind::SLdata32,
            name: name.into(),
            offset,
            segment: seg,
            proc_size: 0,
            type_index: 0x1002,
            flags: 0,
        }
    }
    fn _make_label32(name: &str, offset: u32, seg: u16) -> CvSymRecord {
        CvSymRecord {
            record_size: 16,
            kind: CvSymKind::SLabel32,
            name: name.into(),
            offset,
            segment: seg,
            proc_size: 0,
            type_index: 0,
            flags: 0,
        }
    }

    // â"€â"€ CvSymKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cv_sym_kind_round_trip() {
        assert_eq!(CvSymKind::from_u16(0x1110), CvSymKind::SGproc32);
        assert_eq!(CvSymKind::from_u16(0x110c), CvSymKind::SLdata32);
        assert_eq!(CvSymKind::from_u16(0x9999), CvSymKind::SUnknown);
    }

    #[test]
    fn cv_sym_kind_to_sym_kind_function() {
        assert_eq!(CvSymKind::SGproc32.to_sym_kind(), SymKind::Function);
        assert_eq!(CvSymKind::SLproc32.to_sym_kind(), SymKind::Function);
        assert_eq!(CvSymKind::SPub32.to_sym_kind(), SymKind::Function);
    }

    #[test]
    fn cv_sym_kind_to_sym_kind_label() {
        assert_eq!(CvSymKind::SLabel32.to_sym_kind(), SymKind::Label);
    }

    #[test]
    fn cv_sym_kind_to_sym_kind_data() {
        assert_eq!(CvSymKind::SGdata32.to_sym_kind(), SymKind::Data);
        assert_eq!(CvSymKind::SLdata32.to_sym_kind(), SymKind::Data);
    }

    // â"€â"€ CvLeafKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cv_leaf_kind_round_trip() {
        assert_eq!(CvLeafKind::from_u16(0x1505), CvLeafKind::LfStructure);
        assert_eq!(CvLeafKind::from_u16(0x1503), CvLeafKind::LfArray);
        assert_eq!(CvLeafKind::from_u16(0x1002), CvLeafKind::LfPointer);
        assert_eq!(CvLeafKind::from_u16(0x1008), CvLeafKind::LfProcedure);
        assert_eq!(CvLeafKind::from_u16(0x0000), CvLeafKind::LfUnknown);
    }

    // â"€â"€ CvSymRecord::to_symbol â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn sym_record_va_from_section() {
        let r = make_pub32("foo", 0x100, 1);
        let sym = r.to_symbol(&[0x1000, 0x2000], 0x0);
        assert_eq!(sym.address, 0x1100);
        assert_eq!(sym.name, "foo");
    }

    #[test]
    fn sym_record_va_zero_seg_uses_base() {
        let r = make_pub32("fallback", 0x500, 0);
        let sym = r.to_symbol(&[0x1000], 0x0040_0000);
        assert_eq!(sym.address, 0x0040_0500);
    }

    #[test]
    fn sym_record_proc_size() {
        let r = make_gproc32("main", 0x0, 1, 0x80);
        let sym = r.to_symbol(&[0x1000], 0x0);
        assert_eq!(sym.size, Some(0x80));
    }

    #[test]
    fn sym_record_ldata_binding() {
        let r = make_ldata32("local_var", 0x0, 2);
        let sym = r.to_symbol(&[0x1000, 0x2000], 0x0);
        assert_eq!(sym.binding, SymbolBinding::Local);
    }

    #[test]
    fn sym_record_tagged_codeview() {
        let r = make_pub32("exported_fn", 0x0, 1);
        let sym = r.to_symbol(&[0x1000], 0x0);
        assert!(sym.tags.contains(&"codeview".to_string()));
    }

    // â"€â"€ CodeViewProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn provider_empty() {
        let p = CodeViewProvider::new("test", make_stream_with_syms(vec![]));
        assert_eq!(p.symbol_count(), 0);
        assert!(p.all_symbols().is_empty());
    }

    #[test]
    fn provider_lookup_name() {
        let stream = make_stream_with_syms(vec![make_pub32("alpha", 0x100, 1)]);
        let p = CodeViewProvider::new("t", stream);
        assert!(p.lookup_name("alpha").is_some());
        assert!(p.lookup_name("beta").is_none());
    }

    #[test]
    fn provider_lookup_address() {
        let stream = make_stream_with_syms(vec![make_pub32("fn1", 0x200, 1)]);
        let p = CodeViewProvider::new("t", stream);
        // section 1 base = 0x1000, so VA = 0x1200
        assert!(p.lookup_address(0x1200).is_some());
        assert!(p.lookup_address(0x9999).is_none());
    }

    #[test]
    fn provider_lookup_nearest() {
        let stream = make_stream_with_syms(vec![
            make_gproc32("f1", 0x0, 1, 0x100),
            make_gproc32("f2", 0x200, 1, 0x100),
        ]);
        let p = CodeViewProvider::new("t", stream);
        let s = p.lookup_nearest(0x1050).unwrap();
        assert_eq!(s.name, "f1");
    }

    #[test]
    fn provider_all_functions() {
        let stream = make_stream_with_syms(vec![
            make_gproc32("fn", 0x0, 1, 0x40),
            make_ldata32("data", 0x0, 2),
        ]);
        let p = CodeViewProvider::new("t", stream);
        assert_eq!(p.all_functions().len(), 1);
    }

    #[test]
    fn provider_name() {
        let p = CodeViewProvider::new("my_cv", make_stream_with_syms(vec![]));
        assert_eq!(p.name(), "my_cv");
    }

    // â"€â"€ parse_codeview_header â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn parse_nb10_header() {
        // CV_INFO_PDB20: sig(4) offset(4) timestamp(4) age(4) name(cstr)
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&CV_SIGNATURE_NB10.to_le_bytes());
        data[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // timestamp
        data[12..16].copy_from_slice(&5u32.to_le_bytes()); // age
        data[16..24].copy_from_slice(b"foo.pdb\0");
        let s = parse_codeview_header(&data).unwrap();
        assert_eq!(s.signature, CV_SIGNATURE_NB10);
        assert_eq!(s.age, 5);
        assert_eq!(s.pdb_file_name.as_deref(), Some("foo.pdb"));
    }

    #[test]
    fn parse_nb11_header_same_layout_as_nb10() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&CV_SIGNATURE_NB11.to_le_bytes());
        data[12..16].copy_from_slice(&7u32.to_le_bytes()); // age
        data[16..24].copy_from_slice(b"baz.pdb\0");
        let s = parse_codeview_header(&data).unwrap();
        assert_eq!(s.age, 7);
        assert_eq!(s.pdb_file_name.as_deref(), Some("baz.pdb"));
    }

    #[test]
    fn parse_truncated_nb10_no_panic() {
        // 8-15 byte NB10 blobs used to panic in read_cstr (off > len).
        for len in 8..16 {
            let mut data = vec![0u8; len];
            data[0..4].copy_from_slice(&CV_SIGNATURE_NB10.to_le_bytes());
            let s = parse_codeview_header(&data).unwrap();
            assert!(s.pdb_file_name.is_none());
        }
    }

    #[test]
    fn read_cstr_out_of_range_offset_is_none() {
        assert!(read_cstr(b"abc\0", 10).is_none());
    }

    #[test]
    fn parse_rsds_header() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&CV_SIGNATURE_RSDS.to_le_bytes());
        data[20..24].copy_from_slice(&3u32.to_le_bytes()); // age
        data[24..32].copy_from_slice(b"bar.pdb\0");
        let s = parse_codeview_header(&data).unwrap();
        assert_eq!(s.age, 3);
    }

    #[test]
    fn parse_invalid_sig_returns_none() {
        let data = [0xFFu8; 8];
        assert!(parse_codeview_header(&data).is_none());
    }

    // â"€â"€ pdb_file_name / age â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn provider_pdb_file_name_none_when_missing() {
        let p = CodeViewProvider::new("t", CodeViewStream::default());
        assert!(p.pdb_file_name().is_none());
    }

    #[test]
    fn provider_age() {
        let s = CodeViewStream {
            age: 7,
            ..CodeViewStream::default()
        };
        let p = CodeViewProvider::new("t", s);
        assert_eq!(p.age(), 7);
    }

    // â"€â"€ CodeViewIndex â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn index_empty() {
        let idx = CodeViewIndex::new();
        assert_eq!(idx.provider_count(), 0);
        assert_eq!(idx.total_symbols(), 0);
    }

    #[test]
    fn index_add_provider() {
        let mut idx = CodeViewIndex::new();
        let s = make_stream_with_syms(vec![make_pub32("x", 0, 1)]);
        idx.add(CodeViewProvider::new("t", s));
        assert_eq!(idx.provider_count(), 1);
        assert_eq!(idx.total_symbols(), 1);
    }

    #[test]
    fn index_lookup_name_across_providers() {
        let mut idx = CodeViewIndex::new();
        let s1 = make_stream_with_syms(vec![make_pub32("alpha", 0, 1)]);
        let s2 = make_stream_with_syms(vec![make_pub32("beta", 0x100, 1)]);
        idx.add(CodeViewProvider::new("m1", s1));
        idx.add(CodeViewProvider::new("m2", s2));
        assert!(idx.lookup_name("alpha").is_some());
        assert!(idx.lookup_name("beta").is_some());
        assert!(idx.lookup_name("gamma").is_none());
    }

    #[test]
    fn index_all_symbols_combined() {
        let mut idx = CodeViewIndex::new();
        let s1 = make_stream_with_syms(vec![make_pub32("a", 0, 1), make_pub32("b", 0x10, 1)]);
        let s2 = make_stream_with_syms(vec![make_pub32("c", 0x200, 2)]);
        idx.add(CodeViewProvider::new("m1", s1));
        idx.add(CodeViewProvider::new("m2", s2));
        assert_eq!(idx.all_symbols().len(), 3);
    }

    // â"€â"€ parse_sym_records â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn parse_sym_empty() {
        assert!(parse_sym_records(&[]).is_empty());
    }

    #[test]
    fn parse_sym_truncated_graceful() {
        let data = [0x04u8, 0x00, 0x03, 0x02]; // size=4, kind=S_PUB32 but body too short
        // Should not panic
        let _ = parse_sym_records(&data);
    }

    // â"€â"€ type records â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn parse_type_empty() {
        assert!(parse_type_records(&[]).is_empty());
    }

    #[test]
    fn type_record_lf_pointer() {
        let mut body = vec![0u8; 12];
        // ptrtype = CV_PTR_64 (0x0c) in bits 0-4, per the real attribute layout.
        body[4..8].copy_from_slice(&0x0000_000c_u32.to_le_bytes());
        let ti = parse_lf_pointer(&body);
        if let TypeInfo::Pointer { size, .. } = ti {
            assert_eq!(size, 8);
        } else {
            panic!("expected Pointer");
        }
    }

    #[test]
    fn lf_pointer_near32_is_four_bytes() {
        let mut body = vec![0u8; 12];
        // ptrtype = CV_PTR_NEAR32 (0x0a) with unrelated high bits set: the old
        // `attr >> 16` extraction read those high bits and got this wrong.
        body[4..8].copy_from_slice(&0x00ff_000a_u32.to_le_bytes());
        assert!(matches!(
            parse_lf_pointer(&body),
            TypeInfo::Pointer { size: 8, .. }
        ));
    }

    #[test]
    fn lf_pointer_plain_32bit_is_four_bytes() {
        let mut body = vec![0u8; 12];
        // ptrtype = CV_PTR_NEAR (0x00) => 32-bit.
        body[4..8].copy_from_slice(&0x000c_0000_u32.to_le_bytes());
        assert!(matches!(
            parse_lf_pointer(&body),
            TypeInfo::Pointer { size: 4, .. }
        ));
    }

    #[test]
    fn lf_structure_name_after_numeric_leaf() {
        // count(2) property(2) field(4) derived(4) vshape(4) = 16 bytes,
        // then an inline numeric leaf (size < 0x8000), then the name.
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&0x0010_u16.to_le_bytes()); // size = 16, inline
        body.push(3); // pascal length
        body.extend_from_slice(b"Foo");
        match parse_lf_structure(&body) {
            TypeInfo::Struct { name, .. } => assert_eq!(name, "Foo"),
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn lf_structure_name_after_wide_numeric_leaf() {
        // LF_ULONG (0x8004) size leaf occupies 2 + 4 = 6 bytes.
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&0x8004_u16.to_le_bytes());
        body.extend_from_slice(&0x0001_0000_u32.to_le_bytes());
        body.push(3);
        body.extend_from_slice(b"Big");
        match parse_lf_structure(&body) {
            TypeInfo::Struct { name, .. } => assert_eq!(name, "Big"),
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn type_record_lf_procedure_returns_function() {
        let body = vec![0u8; 16];
        let ti = parse_lf_procedure(&body);
        assert!(matches!(ti, TypeInfo::Function { .. }));
    }
}
