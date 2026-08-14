//! `codeview_parser` — Low-level `CodeView` stream parser.
//!
//! Handles NB09, NB10, NB11, and RSDS signatures; parses module info,
//! contributions, global and public symbol tables, and type info streams.
//! This module is byte-level and does not interpret record semantics.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CodeViewError;

// ---------------------------------------------------------------------------
// CodeView signature constants
// ---------------------------------------------------------------------------

/// NB09 — `CodeView` 4.10 (old PDB format)
pub const NB09_SIG: u32 = 0x3930_424e;
/// NB10 — `CodeView` 5.0 (old PDB format, includes PDB path at tail)
pub const NB10_SIG: u32 = 0x3031_424e;
/// NB11 — `CodeView` 7.0 (pre-RSDS)
pub const NB11_SIG: u32 = 0x3131_424e;
/// RSDS — PDB 7.0 (modern, most common)
pub const RSDS_SIG: u32 = 0x5344_5352;
/// MTOC — Apple Mach-O `CodeView` extension
pub const MTOC_SIG: u32 = 0x434f_544d;

// ---------------------------------------------------------------------------
// Debug directory / CV record header
// ---------------------------------------------------------------------------

/// The kind of `CodeView` record found in a PE debug directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvRecordKind {
    Nb09,
    Nb10,
    Nb11,
    Rsds,
    Mtoc,
    Unknown(u32),
}

impl CvRecordKind {
    #[must_use] 
    pub const fn from_sig(sig: u32) -> Self {
        match sig {
            NB09_SIG => Self::Nb09,
            NB10_SIG => Self::Nb10,
            NB11_SIG => Self::Nb11,
            RSDS_SIG => Self::Rsds,
            MTOC_SIG => Self::Mtoc,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn is_pdb_ref(&self) -> bool {
        matches!(self, Self::Nb10 | Self::Rsds)
    }
}

impl fmt::Display for CvRecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nb09 => write!(f, "NB09"),
            Self::Nb10 => write!(f, "NB10"),
            Self::Nb11 => write!(f, "NB11"),
            Self::Rsds => write!(f, "RSDS"),
            Self::Mtoc => write!(f, "MTOC"),
            Self::Unknown(v) => write!(f, "Unknown(0x{v:08X})"),
        }
    }
}

/// Parsed RSDS (PDB 7.0) `CodeView` header found in PE debug directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsdsHeader {
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
}

impl RsdsHeader {
    /// GUID formatted as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    #[must_use] 
    pub fn guid_str(&self) -> String {
        let g = &self.guid;
        format!(
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            g[3], g[2], g[1], g[0],
            g[5], g[4],
            g[7], g[6],
            g[8], g[9],
            g[10], g[11], g[12], g[13], g[14], g[15]
        )
    }
}

/// Parsed NB10 `CodeView` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nb10Header {
    pub offset: u32,
    pub timestamp: u32,
    pub age: u32,
    pub pdb_path: String,
}

/// Combined result of parsing a `CodeView` record from a PE debug directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvDebugRecord {
    Rsds(RsdsHeader),
    Nb10(Nb10Header),
    Nb09 { offset: u32 },
    Nb11 { offset: u32 },
    Unknown { sig: u32, raw: Vec<u8> },
}

impl CvDebugRecord {
    #[must_use] 
    pub const fn kind(&self) -> CvRecordKind {
        match self {
            Self::Rsds(_) => CvRecordKind::Rsds,
            Self::Nb10(_) => CvRecordKind::Nb10,
            Self::Nb09 { .. } => CvRecordKind::Nb09,
            Self::Nb11 { .. } => CvRecordKind::Nb11,
            Self::Unknown { sig, .. } => CvRecordKind::Unknown(*sig),
        }
    }

    #[must_use] 
    pub fn pdb_path(&self) -> Option<&str> {
        match self {
            Self::Rsds(r) => Some(&r.pdb_path),
            Self::Nb10(n) => Some(&n.pdb_path),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn age(&self) -> Option<u32> {
        match self {
            Self::Rsds(r) => Some(r.age),
            Self::Nb10(n) => Some(n.age),
            _ => None,
        }
    }

    #[must_use] 
    pub fn guid_str(&self) -> Option<String> {
        match self {
            Self::Rsds(r) => Some(r.guid_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_nul_str(data: &[u8], off: usize) -> String {
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off + end]).into_owned()
}

/// Parse a `CodeView` debug record from raw bytes (the data portion of a PE
/// `IMAGE_DEBUG_DIRECTORY` entry with `Type == IMAGE_DEBUG_TYPE_CODEVIEW`).
///
/// # Errors
/// Returns [`CodeViewError::InvalidSignature`] when `data` is shorter than 4 bytes,
/// or [`CodeViewError::TruncatedStream`] when the body is too short for the
/// detected record kind.
///
/// # Panics
/// Does not panic in practice — the internal `unwrap()` calls on
/// `read_u32_le` are guarded by explicit length checks above each call.
pub fn parse_cv_debug_record(data: &[u8]) -> Result<CvDebugRecord, CodeViewError> {
    if data.len() < 4 {
        return Err(CodeViewError::InvalidSignature(0));
    }
    let sig = read_u32_le(data, 0).unwrap();
    match CvRecordKind::from_sig(sig) {
        CvRecordKind::Rsds => {
            if data.len() < 24 {
                return Err(CodeViewError::TruncatedStream);
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&data[4..20]);
            let age = read_u32_le(data, 20).unwrap();
            let pdb_path = read_nul_str(data, 24);
            Ok(CvDebugRecord::Rsds(RsdsHeader { guid, age, pdb_path }))
        }
        CvRecordKind::Nb10 => {
            if data.len() < 16 {
                return Err(CodeViewError::TruncatedStream);
            }
            let offset = read_u32_le(data, 4).unwrap();
            let timestamp = read_u32_le(data, 8).unwrap();
            let age = read_u32_le(data, 12).unwrap();
            let pdb_path = if data.len() > 16 { read_nul_str(data, 16) } else { String::new() };
            Ok(CvDebugRecord::Nb10(Nb10Header { offset, timestamp, age, pdb_path }))
        }
        CvRecordKind::Nb09 => {
            let offset = if data.len() >= 8 { read_u32_le(data, 4).unwrap_or(0) } else { 0 };
            Ok(CvDebugRecord::Nb09 { offset })
        }
        CvRecordKind::Nb11 => {
            let offset = if data.len() >= 8 { read_u32_le(data, 4).unwrap_or(0) } else { 0 };
            Ok(CvDebugRecord::Nb11 { offset })
        }
        CvRecordKind::Unknown(s) => Ok(CvDebugRecord::Unknown { sig: s, raw: data.to_vec() }),
        CvRecordKind::Mtoc => Ok(CvDebugRecord::Unknown { sig, raw: data.to_vec() }),
    }
}

// ---------------------------------------------------------------------------
// CV8 subsection types (used in .debug$S sections in COFF/object files)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cv8SubsectionType {
    Symbols = 0xF1,
    Lines = 0xF2,
    StringTable = 0xF3,
    FileChecksums = 0xF4,
    FrameData = 0xF5,
    InlineeLines = 0xF6,
    CrossScopeImports = 0xF7,
    CrossScopeExports = 0xF8,
    IlLines = 0xF9,
    FuncMdTokenMap = 0xFA,
    TypeMdTokenMap = 0xFB,
    MergedAssemblyInput = 0xFC,
    CoffSymRva = 0xFD,
    Unknown(u32),
}

impl Cv8SubsectionType {
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
            0xF9 => Self::IlLines,
            0xFA => Self::FuncMdTokenMap,
            0xFB => Self::TypeMdTokenMap,
            0xFC => Self::MergedAssemblyInput,
            0xFD => Self::CoffSymRva,
            other => Self::Unknown(other),
        }
    }
}

/// A single CV8 subsection extracted from a `.debug$S` COFF section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cv8Subsection {
    pub kind: Cv8SubsectionType,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Parse all CV8 subsections from a `.debug$S` section payload.
/// The first 4 bytes must be 0x00000004 (CV8 signature).
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] if `data` is shorter than the
/// 4-byte CV8 magic or any sub-section length runs past the buffer, and
/// [`CodeViewError::InvalidSignature`] when the leading magic differs from 4.
///
/// # Panics
/// Does not panic — `read_u32_le` unwraps are guarded by preceding length
/// checks.
pub fn parse_cv8_subsections(data: &[u8]) -> Result<Vec<Cv8Subsection>, CodeViewError> {
    if data.len() < 4 {
        return Err(CodeViewError::TruncatedStream);
    }
    let magic = read_u32_le(data, 0).unwrap();
    if magic != 4 {
        return Err(CodeViewError::InvalidSignature(magic));
    }
    let mut pos = 4usize;
    let mut out = Vec::new();
    while pos + 8 <= data.len() {
        let kind_val = read_u32_le(data, pos).unwrap();
        let len_u32 = read_u32_le(data, pos + 4).unwrap();
        let len = len_u32 as usize;
        // Guard against malformed length that exceeds remaining buffer.
        if len > data.len() - pos - 8 {
            return Err(CodeViewError::TruncatedStream);
        }
        pos += 8;
        if pos + len > data.len() {
            return Err(CodeViewError::TruncatedStream);
        }
        let section_data = data[pos..pos + len].to_vec();
        out.push(Cv8Subsection {
            kind: Cv8SubsectionType::from_u32(kind_val),
            offset: pos,
            data: section_data,
        });
        // Align to 4 bytes
        pos += len;
        let rem = pos % 4;
        if rem != 0 {
            pos = pos.saturating_add(4 - rem);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// String table parser (CV8 subsection 0xF3)
// ---------------------------------------------------------------------------

/// A flat string table extracted from a CV8 `StringTable` subsection.
/// Strings are NUL-terminated; indices are byte offsets into the table.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CvStringTable {
    raw: Vec<u8>,
}

impl CvStringTable {
    #[must_use] 
    pub const fn new(data: Vec<u8>) -> Self { Self { raw: data } }

    #[must_use] 
    pub fn get(&self, offset: usize) -> Option<&str> {
        if offset >= self.raw.len() { return None; }
        let end = self.raw[offset..].iter().position(|&b| b == 0).unwrap_or(self.raw.len() - offset);
        std::str::from_utf8(&self.raw[offset..offset + end]).ok()
    }

    #[must_use] 
    pub const fn iter(&self) -> CvStringTableIter<'_> {
        CvStringTableIter { table: self, pos: 0 }
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.raw.is_empty() }
    #[must_use] 
    pub const fn raw_len(&self) -> usize { self.raw.len() }
}

pub struct CvStringTableIter<'a> {
    table: &'a CvStringTable,
    pos: usize,
}

impl<'a> IntoIterator for &'a CvStringTable {
    type Item = (usize, &'a str);
    type IntoIter = CvStringTableIter<'a>;
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}

impl<'a> Iterator for CvStringTableIter<'a> {
    type Item = (usize, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.table.raw.len() { return None; }
        let start = self.pos;
        let s = self.table.get(start)?;
        self.pos += s.len() + 1;
        Some((start, s))
    }
}

// ---------------------------------------------------------------------------
// File checksum record (CV8 subsection 0xF4)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvChecksumKind {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
    Unknown(u8),
}

impl CvChecksumKind {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v { 0 => Self::None, 1 => Self::Md5, 2 => Self::Sha1, 3 => Self::Sha256, o => Self::Unknown(o) }
    }
    #[must_use] 
    pub const fn byte_len(&self) -> usize {
        match self { Self::Md5 => 16, Self::Sha1 => 20, Self::Sha256 => 32, Self::None | Self::Unknown(_) => 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvFileChecksum {
    /// Offset into string table giving the file path.
    pub name_offset: u32,
    pub kind: CvChecksumKind,
    pub checksum: Vec<u8>,
}

/// Parse a CV8 file-checksum subsection (`0xF4`).
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] if a record's declared checksum
/// length runs past the end of `data`.
///
/// # Panics
/// Does not panic — `read_u32_le` unwraps are guarded by the loop's
/// `pos + 6 <= data.len()` check.
pub fn parse_file_checksums(data: &[u8]) -> Result<Vec<CvFileChecksum>, CodeViewError> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos + 6 <= data.len() {
        let name_offset = read_u32_le(data, pos).unwrap();
        let len = data[pos + 4] as usize;
        let kind = CvChecksumKind::from_u8(data[pos + 5]);
        pos += 6;
        if pos + len > data.len() {
            return Err(CodeViewError::TruncatedStream);
        }
        let checksum = data[pos..pos + len].to_vec();
        out.push(CvFileChecksum { name_offset, kind, checksum });
        pos += len;
        let rem = pos % 4;
        if rem != 0 {
            pos = pos.saturating_add(4 - rem);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Line number record parser (CV8 subsection 0xF2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvLineBlock {
    pub func_offset: u32,
    pub segment: u16,
    pub file_checksum_offset: u32,
    pub lines: Vec<CvLineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvLineEntry {
    pub offset: u32,
    pub line_start: u32,
    pub line_end: u32,
    pub col_start: u16,
    pub col_end: u16,
    pub is_statement: bool,
}

/// Parse a CV8 line-number subsection (`0xF2`).
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when the header or any line
/// block runs past the buffer.
///
/// # Panics
/// Does not panic — all `unwrap()` calls follow explicit length checks.
pub fn parse_line_subsection(data: &[u8]) -> Result<Vec<CvLineBlock>, CodeViewError> {
    if data.len() < 12 {
        return Err(CodeViewError::TruncatedStream);
    }
    let func_offset = read_u32_le(data, 0).unwrap();
    let segment = read_u16_le(data, 4).unwrap();
    let flags = read_u16_le(data, 6).unwrap();
    let _code_size = read_u32_le(data, 8).unwrap();
    let has_columns = (flags & 1) != 0;
    let mut pos = 12usize;
    let mut blocks = Vec::new();
    while pos + 12 <= data.len() {
        let file_checksum_offset = read_u32_le(data, pos).unwrap();
        let num_lines = read_u32_le(data, pos + 4).unwrap() as usize;
        let _block_size = read_u32_le(data, pos + 8).unwrap();
        pos += 12;
        // Anti-DoS: never pre-allocate from an attacker-controlled u32.
        // Each line entry is at least 8 bytes, so cap capacity by what the
        // remaining buffer could actually hold.
        let max_entries = (data.len().saturating_sub(pos)) / 8;
        let mut lines = Vec::with_capacity(num_lines.min(max_entries));
        for _ in 0..num_lines {
            if pos + 8 > data.len() { return Err(CodeViewError::TruncatedStream); }
            let offset = read_u32_le(data, pos).unwrap();
            let line_flags = read_u32_le(data, pos + 4).unwrap();
            let line_start = line_flags & 0x00FF_FFFF;
            let delta_end = (line_flags >> 24) & 0x7F;
            let is_statement = (line_flags >> 31) != 0;
            pos += 8;
            let (col_start, col_end) = if has_columns && pos + 4 <= data.len() {
                let cs = read_u16_le(data, pos).unwrap();
                let ce = read_u16_le(data, pos + 2).unwrap();
                pos += 4;
                (cs, ce)
            } else { (0, 0) };
            lines.push(CvLineEntry {
                offset,
                line_start,
                line_end: line_start + delta_end,
                col_start,
                col_end,
                is_statement,
            });
        }
        blocks.push(CvLineBlock { func_offset, segment, file_checksum_offset, lines });
    }
    Ok(blocks)
}

// ---------------------------------------------------------------------------
// Raw symbol record iterator
// ---------------------------------------------------------------------------

/// A raw `CodeView` symbol record (not yet decoded).
#[derive(Debug, Clone)]
pub struct RawSymRecord<'a> {
    pub kind: u16,
    pub data: &'a [u8],
    pub offset: usize,
}

/// Iterate over raw symbol records in a symbol stream.
pub struct RawSymIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RawSymIter<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
}

impl<'a> Iterator for RawSymIter<'a> {
    type Item = Result<RawSymRecord<'a>, CodeViewError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.data.len() { return None; }
        let len = read_u16_le(self.data, self.pos)? as usize;
        if len < 2 {
            self.pos = self.data.len();
            return Some(Err(CodeViewError::InvalidRecord));
        }
        let kind = read_u16_le(self.data, self.pos + 2)?;
        let rec_end = self.pos + 2 + len;
        if rec_end > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(CodeViewError::TruncatedStream));
        }
        let data = &self.data[self.pos + 4..rec_end];
        let offset = self.pos;
        self.pos = rec_end;
        Some(Ok(RawSymRecord { kind, data, offset }))
    }
}

// ---------------------------------------------------------------------------
// Raw type record iterator
// ---------------------------------------------------------------------------

/// A raw `CodeView` type record.
#[derive(Debug, Clone)]
pub struct RawTypeRecord<'a> {
    pub type_index: u32,
    pub leaf_kind: u16,
    pub data: &'a [u8],
}

/// Iterate over records in a TPI (Type Info) stream.
pub struct RawTypeIter<'a> {
    data: &'a [u8],
    pos: usize,
    next_index: u32,
}

impl<'a> RawTypeIter<'a> {
    /// `start_index` is usually 0x1000 for the TPI stream.
    #[must_use] 
    pub const fn new(data: &'a [u8], start_index: u32) -> Self {
        Self { data, pos: 0, next_index: start_index }
    }
}

impl<'a> Iterator for RawTypeIter<'a> {
    type Item = Result<RawTypeRecord<'a>, CodeViewError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.data.len() { return None; }
        let len = read_u16_le(self.data, self.pos)? as usize;
        if len < 2 {
            self.pos = self.data.len();
            return Some(Err(CodeViewError::InvalidRecord));
        }
        let leaf_kind = read_u16_le(self.data, self.pos + 2)?;
        let rec_end = self.pos + 2 + len;
        if rec_end > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(CodeViewError::TruncatedStream));
        }
        let data = &self.data[self.pos + 4..rec_end];
        let type_index = self.next_index;
        self.pos = rec_end;
        self.next_index += 1;
        Some(Ok(RawTypeRecord { type_index, leaf_kind, data }))
    }
}

// ---------------------------------------------------------------------------
// Module contribution record (used in DBI stream)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvModuleContrib {
    pub section: u16,
    pub offset: u32,
    pub size: u32,
    pub characteristics: u32,
    pub module_index: u16,
}

/// Group parsed module contributions by `(section, module_index)`, sorted by RVA.
///
/// Returns a `BTreeMap` so callers iterate contributions deterministically per
/// section. Useful when building per-module RVA ranges or merging line info.
#[must_use] 
pub fn group_module_contribs_by_section(
    contribs: &[CvModuleContrib],
) -> BTreeMap<u16, Vec<CvModuleContrib>> {
    let mut out: BTreeMap<u16, Vec<CvModuleContrib>> = BTreeMap::new();
    for c in contribs {
        out.entry(c.section).or_default().push(c.clone());
    }
    for v in out.values_mut() {
        v.sort_by_key(|c| c.offset);
    }
    out
}

/// Parse module contributions from DBI stream section contributions substream.
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when `data` is shorter than the
/// 4-byte version header.
///
/// # Panics
/// Does not panic — `read_*` unwraps are guarded by the loop's `pos + rec_size <= data.len()` check.
pub fn parse_module_contribs(data: &[u8]) -> Result<Vec<CvModuleContrib>, CodeViewError> {
    if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
    let version = read_u32_le(data, 0).unwrap();
    let rec_size: usize = match version {
        v if v == 0xeffe_0000 + 19_970_605 => 28,
        v if v == 0xeffe_0000 + 20_140_516 => 28,
        _ => 28,
    };
    let mut pos = 4usize;
    let mut out = Vec::new();
    while pos + rec_size <= data.len() {
        let section = read_u16_le(data, pos).unwrap();
        let offset = read_u32_le(data, pos + 4).unwrap();
        let size = read_u32_le(data, pos + 8).unwrap();
        let characteristics = read_u32_le(data, pos + 12).unwrap();
        let module_index = read_u16_le(data, pos + 16).unwrap();
        out.push(CvModuleContrib { section, offset, size, characteristics, module_index });
        pos += rec_size;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CodeView stream index for full CV4 / NB11 images
// ---------------------------------------------------------------------------

/// Lightweight index over a `CodeView` NB11 image.
#[derive(Debug, Default)]
pub struct CvStreamIndex {
    pub modules: Vec<CvModuleInfo>,
    pub global_sym_offset: u32,
    pub global_sym_size: u32,
    pub pub_sym_offset: u32,
    pub pub_sym_size: u32,
    pub type_info_offset: u32,
    pub type_info_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvModuleInfo {
    pub name: String,
    pub sym_offset: u32,
    pub sym_size: u32,
    pub src_module_offset: u32,
    pub src_module_size: u32,
}

/// Parse a minimal NB11 stream index (subsection directory).
/// Parse the NB11 stream directory layout from a raw `CodeView` image.
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when the directory header runs
/// past the buffer, and [`CodeViewError::InvalidRecord`] when the entry size
/// is below the 12-byte minimum.
///
/// # Panics
/// Does not panic — `read_*` unwraps are guarded by explicit length checks.
pub fn parse_nb11_directory(data: &[u8]) -> Result<CvStreamIndex, CodeViewError> {
    if data.len() < 8 { return Err(CodeViewError::TruncatedStream); }
    let sig = read_u32_le(data, 0).unwrap();
    if sig != NB11_SIG { return Err(CodeViewError::InvalidSignature(sig)); }
    let dir_offset_raw = read_u32_le(data, 4).unwrap();
    let dir_offset = dir_offset_raw as usize;
    // Guard against truncated or crafted offset that would overflow.
    if dir_offset_raw as usize != dir_offset || dir_offset.saturating_add(8) > data.len() {
        return Err(CodeViewError::TruncatedStream);
    }
    let _dir_size = read_u16_le(data, dir_offset).unwrap();
    let entry_size = read_u16_le(data, dir_offset + 2).unwrap() as usize;
    let num_entries = read_u32_le(data, dir_offset + 4).unwrap() as usize;
    if entry_size < 12 { return Err(CodeViewError::InvalidRecord); }
    let mut idx = CvStreamIndex::default();
    let mut pos = dir_offset + 8;
    for _ in 0..num_entries {
        if pos + entry_size > data.len() { break; }
        let subsection_type = read_u16_le(data, pos).unwrap();
        let module = read_u16_le(data, pos + 2).unwrap();
        let offset = read_u32_le(data, pos + 4).unwrap();
        let size = read_u32_le(data, pos + 8).unwrap();
        match subsection_type {
            0x120 => { // sstGlobalSym
                idx.global_sym_offset = offset;
                idx.global_sym_size = size;
            }
            0x121 => { // sstGlobalTypes
                idx.type_info_offset = offset;
                idx.type_info_size = size;
            }
            0x125 => { // sstPublicSym
                idx.pub_sym_offset = offset;
                idx.pub_sym_size = size;
            }
            0x127 => { // sstModule
                let name_off = offset as usize + 64;
                let name = if name_off < data.len() { read_nul_str(data, name_off) } else { String::new() };
                idx.modules.push(CvModuleInfo {
                    name,
                    sym_offset: offset,
                    sym_size: size,
                    src_module_offset: 0,
                    src_module_size: 0,
                });
                let _ = module;
            }
            _ => {}
        }
        pos += entry_size;
    }
    Ok(idx)
}

// ---------------------------------------------------------------------------
// Frame data record (CV8 0xF5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvFrameData {
    pub rva_start: u32,
    pub block_size: u32,
    pub locals_size: u32,
    pub params_size: u32,
    pub max_stack_size: u32,
    pub frame_func_offset: u32,
    pub prolog_size: u16,
    pub saved_regs_size: u16,
    pub flags: u32,
}

/// Parse the CV8 frame-data subsection (`0xF5`).
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when the leading RVA-base header
/// is missing.
///
/// # Panics
/// Does not panic — `read_*` unwraps are guarded by the `pos + 32 <= data.len()` check.
pub fn parse_frame_data(data: &[u8]) -> Result<Vec<CvFrameData>, CodeViewError> {
    if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
    // first u32 is a "RVA base" for relative frame data entries
    let mut pos = 4usize;
    let mut out = Vec::new();
    while pos + 32 <= data.len() {
        let rva_start = read_u32_le(data, pos).unwrap();
        let block_size = read_u32_le(data, pos + 4).unwrap();
        let locals_size = read_u32_le(data, pos + 8).unwrap();
        let params_size = read_u32_le(data, pos + 12).unwrap();
        let max_stack_size = read_u32_le(data, pos + 16).unwrap();
        let frame_func_offset = read_u32_le(data, pos + 20).unwrap();
        let prolog_size = read_u16_le(data, pos + 24).unwrap();
        let saved_regs_size = read_u16_le(data, pos + 26).unwrap();
        let flags = read_u32_le(data, pos + 28).unwrap();
        out.push(CvFrameData { rva_start, block_size, locals_size, params_size, max_stack_size, frame_func_offset, prolog_size, saved_regs_size, flags });
        pos += 32;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Address map (PDB public symbol hash table lookup helper)
// ---------------------------------------------------------------------------

/// A sorted map from (segment, offset) → symbol name, built from public symbols.
#[derive(Debug, Default, Clone)]
pub struct CvAddressMap {
    entries: Vec<(u16, u32, String)>,
    sorted: bool,
}

impl CvAddressMap {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, seg: u16, off: u32, name: String) {
        self.entries.push((seg, off, name));
        self.sorted = false;
    }

    pub fn sort(&mut self) {
        self.entries.sort_by_key(|&(s, o, _)| (s, o));
        self.sorted = true;
    }

    #[must_use] 
    pub fn find_nearest(&self, seg: u16, off: u32) -> Option<(&str, u32)> {
        if !self.sorted { return None; }
        let idx = self.entries.partition_point(|&(s, o, _)| (s, o) <= (seg, off));
        if idx == 0 { return None; }
        let (s, o, ref name) = self.entries[idx - 1];
        if s != seg { return None; }
        let displacement = off.saturating_sub(o);
        Some((name.as_str(), displacement))
    }

    #[must_use] 
    pub const fn len(&self) -> usize { self.entries.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ---------------------------------------------------------------------------
// Utility: locate debug directory in a PE image
// ---------------------------------------------------------------------------

/// Find the raw offset and size of the Debug data directory contents
/// within a raw PE image byte slice.
#[must_use] 
pub fn find_debug_directory(pe: &[u8]) -> Option<(usize, usize)> {
    if pe.len() < 64 { return None; }
    let e_lfanew = u32::from_le_bytes(pe[60..64].try_into().ok()?) as usize;
    let sig_off = e_lfanew;
    if pe.get(sig_off..sig_off + 4)? != b"PE\0\0" { return None; }
    // PE32 vs PE32+ is decided by the Optional Header magic, NOT by the machine
    // type: ARM64/IA64 images are PE32+ but have machine != 0x8664.
    let magic = u16::from_le_bytes(pe.get(sig_off + 24..sig_off + 26)?.try_into().ok()?);
    let dd_off = if magic == 0x20B {
        sig_off + 24 + 112
    } else {
        sig_off + 24 + 96
    };
    // Directory entry 6 = debug
    let debug_entry_off = dd_off + 6 * 8;
    if debug_entry_off + 8 > pe.len() { return None; }
    let rva = u32::from_le_bytes(pe.get(debug_entry_off..debug_entry_off + 4)?.try_into().ok()?) as usize;
    let size = u32::from_le_bytes(pe.get(debug_entry_off + 4..debug_entry_off + 8)?.try_into().ok()?) as usize;
    if rva == 0 || size == 0 { return None; }
    // Convert RVA → file offset (simple: find the section that contains it)
    let num_sections = u16::from_le_bytes(pe.get(sig_off + 6..sig_off + 8)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(pe.get(sig_off + 20..sig_off + 22)?.try_into().ok()?) as usize;
    let sect_start = sig_off + 24 + opt_size;
    for i in 0..num_sections {
        let sect_off = sect_start + i * 40;
        if sect_off + 40 > pe.len() { break; }
        let vaddr = u32::from_le_bytes(pe.get(sect_off + 12..sect_off + 16)?.try_into().ok()?) as usize;
        // IMAGE_SECTION_HEADER: VirtualSize @8, VirtualAddress @12,
        // SizeOfRawData @16, PointerToRawData @20.  Reading only one of the two
        // sizes loses a case each way: VirtualSize is 0 in object files, and
        // SizeOfRawData is 0 for an uninitialised section.  Take the larger,
        // which is what the mapped section actually spans.
        let vsz = {
            let virt = u32::from_le_bytes(pe.get(sect_off + 8..sect_off + 12)?.try_into().ok()?) as usize;
            let raw_sz = u32::from_le_bytes(pe.get(sect_off + 16..sect_off + 20)?.try_into().ok()?) as usize;
            virt.max(raw_sz)
        };
        let raw = u32::from_le_bytes(pe.get(sect_off + 20..sect_off + 24)?.try_into().ok()?) as usize;
        if rva >= vaddr && rva < vaddr.saturating_add(vsz) {
            let foff = raw.saturating_add(rva - vaddr);
            if foff.checked_add(size).is_some_and(|end| end <= pe.len()) {
                return Some((foff, size));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_subsection_huge_num_lines_no_alloc_dos() {
        // A malformed block claiming u32::MAX lines must not pre-allocate
        // gigabytes; it must fail with TruncatedStream instead.
        let mut data = vec![0u8; 12]; // header
        data.extend_from_slice(&0u32.to_le_bytes()); // file_checksum_offset
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // num_lines
        data.extend_from_slice(&0u32.to_le_bytes()); // block_size
        let r = parse_line_subsection(&data);
        assert!(matches!(r, Err(CodeViewError::TruncatedStream)));
    }

    #[test]
    fn test_rsds_parse() {
        let mut data = vec![0u8; 30];
        data[0..4].copy_from_slice(&RSDS_SIG.to_le_bytes());
        data[4..20].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD, 0xEF, 0x01,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        ]);
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24] = b'a'; data[25] = b'.'; data[26] = b'p'; data[27] = b'd'; data[28] = b'b'; data[29] = 0;
        let rec = parse_cv_debug_record(&data).unwrap();
        if let CvDebugRecord::Rsds(r) = rec {
            assert_eq!(r.age, 1);
            assert_eq!(r.pdb_path, "a.pdb");
            assert!(r.guid_str().starts_with('{'));
        } else { panic!("expected RSDS"); }
    }

    #[test]
    fn test_cv8_subsections() {
        let mut data = vec![0u8; 4 + 8 + 4];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..8].copy_from_slice(&(0xF3u32).to_le_bytes());
        data[8..12].copy_from_slice(&4u32.to_le_bytes()); // len=4
        data[12..16].copy_from_slice(b"foo\0");
        let subs = parse_cv8_subsections(&data).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].kind, Cv8SubsectionType::StringTable);
    }

    #[test]
    fn test_string_table() {
        let raw = b"hello\0world\0".to_vec();
        let st = CvStringTable::new(raw);
        assert_eq!(st.get(0), Some("hello"));
        assert_eq!(st.get(6), Some("world"));
        assert_eq!(st.get(99), None);
    }

    #[test]
    fn test_address_map() {
        let mut m = CvAddressMap::new();
        m.insert(1, 0x1000, "func_a".into());
        m.insert(1, 0x2000, "func_b".into());
        m.insert(1, 0x1500, "func_c".into());
        m.sort();
        let (name, disp) = m.find_nearest(1, 0x1800).unwrap();
        assert_eq!(name, "func_c");
        assert_eq!(disp, 0x300);
    }

    #[test]
    fn test_raw_sym_iter() {
        // Build two minimal symbol records: len=6 (4 bytes data), kind=0x110E (S_PUB32)
        let mut data = Vec::new();
        let kind: u16 = 0x110E;
        let len: u16 = 6; // includes kind (2) + 4 bytes data
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let recs: Vec<_> = RawSymIter::new(&data).collect();
        assert_eq!(recs.len(), 1);
        let r = recs[0].as_ref().unwrap();
        assert_eq!(r.kind, 0x110E);
        assert_eq!(r.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_nb10_parse() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&NB10_SIG.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        data[12..16].copy_from_slice(&3u32.to_le_bytes());
        data[16] = b'x'; data[17] = b'.'; data[18] = b'p'; data[19] = 0;
        let rec = parse_cv_debug_record(&data).unwrap();
        if let CvDebugRecord::Nb10(n) = rec {
            assert_eq!(n.age, 3);
            assert_eq!(n.pdb_path, "x.p");
        } else { panic!("expected NB10"); }
    }

    #[test]
    fn test_checksum_kind_byte_len() {
        assert_eq!(CvChecksumKind::Md5.byte_len(), 16);
        assert_eq!(CvChecksumKind::Sha256.byte_len(), 32);
        assert_eq!(CvChecksumKind::None.byte_len(), 0);
    }
}
