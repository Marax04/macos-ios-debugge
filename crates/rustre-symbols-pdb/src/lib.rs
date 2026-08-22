//! `rustre-symbols-pdb`
//!
//! Microsoft `PDB` (Program Database) symbol reader implemented as a pure-Rust
//! parser for the `MSF` (Multi-Stream File) container and the `DBI`/Symbol streams
//! it carries.  No external `pdb` crate is required.
//!
//! # Supported structures
//! * `MSF` superblock detection (v7 magic)
//! * Stream directory traversal
//! * `DBI` stream: module list extraction
//! * Symbol records: `S_PUB32`, `S_GPROC32`, `S_LPROC32`, `S_GDATA32`,
//!   `S_LDATA32`, `S_LABEL32`, `S_THUNK32`
//! * `TPI` stream: simple type records (`LF_STRUCTURE`, `LF_UNION`, `LF_ENUM`,
//!   `LF_POINTER`, `LF_ARRAY`, `LF_PROCEDURE`, primitives)
//! * `GUID` / Age fields from the `PDB` Info stream (stream 1)
//!
//! # Known limitations
//! The `TPI` decoder reachable through [`PdbReader::types`] does **not** follow
//! `LF_FIELDLIST`: struct/union/enum members come back as `field_0`, `field_1`,
//! … placeholders with the right *count* but no names or types. Use
//! [`pdb_type_info`] for real field-list decoding.
//!
//! # Modules
//! Beyond the top-level reader this crate exposes: [`build_info`],
//! [`global_symbols`], [`gsi_stream`], [`line_info`], [`module_symbols`],
//! [`pdb_dbi_reader`], [`pdb_dbi_stream`], [`pdb_gsi`], [`pdb_line_info`],
//! [`pdb_omap`], [`pdb_publics_reader`], [`pdb_source_lines`],
//! [`pdb_stream_parser`], [`pdb_symbol_info`], [`pdb_type_info`],
//! [`section_contributions`], [`stream_reader`], [`sym_kinds`], [`tpi_types`]
//! and [`type_info`].

#![warn(missing_docs)]

pub mod build_info;
pub mod global_symbols;
pub mod gsi_stream;
pub mod line_info;
/// MSF container parsing: superblock, stream directory and named-stream map.
pub mod pdb_stream_parser;
/// DBI (debug information) stream: module list, section contributions, file info.
pub mod pdb_dbi_stream;
/// GSI (global symbol index) stream: hash records and address map.
pub mod pdb_gsi;
pub mod module_symbols;
pub mod pdb_type_info;
pub mod section_contributions;
pub mod stream_reader;
pub mod tpi_types;
pub mod type_info;
pub mod pdb_dbi_reader;
pub mod pdb_publics_reader;
pub mod pdb_source_lines;
pub mod pdb_line_info;
pub mod pdb_omap;
pub mod pdb_symbol_info;
pub mod sym_kinds;

use std::{collections::HashMap, fs, io, path::Path};

use thiserror::Error;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors returned by the `PDB` reader.
#[derive(Debug, Error)]
pub enum PdbError {
    /// Underlying I/O failure while reading the file.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// The file does not start with the MSF 7.00 magic.
    #[error("Not a valid PDB file (bad MSF magic)")]
    BadMagic,
    /// The MSF container version is not supported.
    #[error("Unsupported MSF version")]
    UnsupportedVersion,
    /// A stream index exceeded the number of streams in the directory.
    #[error("Stream {0} is out of range")]
    StreamOutOfRange(u32),
    /// Stream contents failed structural validation.
    #[error("Corrupt stream data")]
    CorruptData,
    /// A stream ended before an expected field could be read.
    #[error("Stream too short")]
    StreamTooShort,
}

/// Convenience alias for results with [`PdbError`].
pub type Result<T> = std::result::Result<T, PdbError>;

// ── MSF magic ────────────────────────────────────────────────────────────────

const MSF_MAGIC_V7: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

// ── Public API types ──────────────────────────────────────────────────────────

/// Kind of a `PDB` symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SymbolKind {
    /// Procedure / function symbol.
    Function,
    /// Global or static data symbol.
    Data,
    /// Code label.
    Label,
    /// Thunk (e.g. incremental-link jump stub).
    Thunk,
}

/// A symbol exported from a `PDB` file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbSymbol {
    /// Symbol name (possibly mangled).
    pub name: String,
    /// Resolved virtual address.
    pub address: u64,
    /// Size in bytes, 0 when unknown.
    pub size: u32,
    /// What kind of symbol this is.
    pub kind: SymbolKind,
}

/// Kind of a `PDB` type record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TypeKind {
    /// Structure with named fields.
    Struct {
        /// Field names in declaration order.
        fields: Vec<String>,
    },
    /// Union with named members.
    Union {
        /// Member names in declaration order.
        fields: Vec<String>,
    },
    /// Enumeration.
    Enum {
        /// Variant names in declaration order.
        variants: Vec<String>,
    },
    /// Built-in primitive type.
    Primitive,
    /// Pointer type.
    Pointer,
    /// Array type.
    Array,
    /// Function / procedure type.
    Function,
}

/// A type record from the `TPI` stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbType {
    /// Type name as recorded in the TPI stream.
    pub name: String,
    /// Category and shape of the type.
    pub kind: TypeKind,
    /// Size in bytes, 0 when unknown.
    pub size: u32,
}

/// A module (object file / lib) listed in the `DBI` stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbModule {
    /// Module name (usually the source object path).
    pub name: String,
    /// Object file / archive member the module came from.
    pub object_file: String,
    /// MSF stream index of the module's symbol stream (`0xFFFF` if none).
    pub stream_index: u16,
}

/// A procedure symbol harvested from a per-module `DBI` symbol stream.
///
/// `S_GPROC32` / `S_LPROC32` records carry a
/// `(segment, code_offset, code_size, name)` tuple. The caller is expected to
/// translate `segment` (1-based PE section index) into an image RVA / VA using
/// the binary's own section table.
///
/// Note that the `S_PROCREF` / `S_LPROCREF` / `S_DATAREF` reference records
/// found in the *global* symbol stream do **not** carry this tuple: their
/// layout is `u32 sumName, u32 ibSym, u16 imod, name`, i.e. a 1-based module
/// index plus a byte offset into that module's symbol stream. Resolving one
/// means following `imod`/`ibSym` into the module stream, not reading
/// `imod` as a segment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbModuleProc {
    /// Procedure name as stored in the PDB (may be MSVC-mangled).
    pub name: String,
    /// 1-based PE section index this procedure lives in.
    pub segment: u16,
    /// Byte offset of the procedure start within its section.
    pub code_offset: u32,
    /// Procedure size in bytes (from the `S_GPROC32` length field).
    pub code_size: u32,
}

/// 128-bit `GUID` from the `PDB` Info stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbGuid {
    /// Raw GUID bytes in on-disk order.
    pub data: [u8; 16],
}

impl PdbGuid {
    /// Format as the standard `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` string.
    #[must_use]
    pub fn to_string_fmt(&self) -> String {
        let d = &self.data;
        format!(
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            d[3],
            d[2],
            d[1],
            d[0],
            d[5],
            d[4],
            d[7],
            d[6],
            d[8],
            d[9],
            d[10],
            d[11],
            d[12],
            d[13],
            d[14],
            d[15],
        )
    }
}

/// Age counter from the `PDB` Info stream (used for symbol-server matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbAge(pub u32);

// ── Low-level byte helpers ────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PdbError::StreamTooShort)
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(PdbError::StreamTooShort)
}

/// Read a null-terminated UTF-8 (best-effort) string starting at `off`.
fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    let start = off;
    let mut pos = off;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..pos]).into_owned();
    let next = if pos < data.len() { pos + 1 } else { pos }; // skip the null byte if present
    (s, next)
}

// ── MSF superblock ────────────────────────────────────────────────────────────

struct MsfSuperblock {
    block_size: u32,
    /// Serialised stream directory pages.
    directory_pages: Vec<u32>,
}

fn parse_superblock(raw: &[u8]) -> Result<MsfSuperblock> {
    if raw.len() < 56 {
        return Err(PdbError::BadMagic);
    }
    // Same as `MsfSuperblock::parse`: name the PDB 2.00 container instead of
    // calling it garbage. See `pdb_stream_parser::MSF_MAGIC_V2`.
    if raw.len() >= crate::pdb_stream_parser::MSF_MAGIC_V2.len()
        && &raw[0..crate::pdb_stream_parser::MSF_MAGIC_V2.len()]
            == crate::pdb_stream_parser::MSF_MAGIC_V2
    {
        return Err(PdbError::UnsupportedVersion);
    }
    if &raw[0..32] != MSF_MAGIC_V7 {
        return Err(PdbError::BadMagic);
    }
    let block_size = read_u32_le(raw, 32)?;
    // Everything downstream multiplies and divides by `block_size`. A
    // non-power-of-two value (3, 0x4000_0000, …) reassembles streams from
    // fragments at the wrong stride and produces coherent-looking garbage.
    if !block_size.is_power_of_two() || !(512..=8192).contains(&block_size) {
        return Err(PdbError::CorruptData);
    }
    // The Free Page Map lives at block 1 or 2 in every writer we know of.
    let free_block_map_block = read_u32_le(raw, 36)?;
    if free_block_map_block != 1 && free_block_map_block != 2 {
        return Err(PdbError::CorruptData);
    }
    // num_blocks at 40 – unused
    let num_dir_bytes = read_u32_le(raw, 44)?;
    // reserved u32 at 48
    let block_map_addr = read_u32_le(raw, 52)?;

    // Number of pages required to store the directory.
    let blocks_per_dir = num_dir_bytes.div_ceil(block_size);

    // The block-map itself is stored at block_map_addr.  Each u32 there is a
    // page number that holds part of the directory.
    let bm_offset = (block_map_addr as usize)
        .checked_mul(block_size as usize)
        .ok_or(PdbError::CorruptData)?;
    // Cap the pre-allocation by what the file could actually hold: the block
    // map cannot list more pages than fit in the file after `bm_offset`.
    let max_pages = raw.len().saturating_sub(bm_offset) / 4;
    let mut directory_pages = Vec::with_capacity((blocks_per_dir as usize).min(max_pages));
    for i in 0..blocks_per_dir as usize {
        let page = read_u32_le(raw, bm_offset + i * 4)?;
        directory_pages.push(page);
    }

    Ok(MsfSuperblock {
        block_size,
        directory_pages,
    })
}

/// Build the full stream-directory and return a map of `stream_index -> bytes`.
fn build_stream_map(raw: &[u8], sb: &MsfSuperblock) -> Result<HashMap<u32, Vec<u8>>> {
    if sb.block_size == 0 {
        return Err(PdbError::CorruptData);
    }
    let block_size = sb.block_size as usize;

    // Reassemble directory bytes.
    let mut dir_data: Vec<u8> = Vec::new();
    for &page in &sb.directory_pages {
        let start = (page as usize) * block_size;
        let end = (start + block_size).min(raw.len());
        if start >= raw.len() {
            break;
        }
        dir_data.extend_from_slice(&raw[start..end]);
    }

    let num_streams = read_u32_le(&dir_data, 0)? as usize;
    let mut off = 4;

    // Read stream sizes.
    // `num_streams` is attacker-controlled; cap the pre-allocation by the
    // number of u32 entries the directory could actually contain.
    let mut stream_sizes = Vec::with_capacity(num_streams.min(dir_data.len() / 4));
    for _ in 0..num_streams {
        let sz = read_u32_le(&dir_data, off)?;
        stream_sizes.push(sz);
        off += 4;
    }

    // Read block lists for each stream and reconstruct content.
    let mut map = HashMap::new();
    for (idx, &sz) in stream_sizes.iter().enumerate() {
        let idx_u32 = u32::try_from(idx).map_err(|_| PdbError::CorruptData)?;
        if sz == 0xFFFF_FFFF {
            // Nil stream.
            map.insert(idx_u32, Vec::new());
            continue;
        }
        let num_blocks = (sz as usize).div_ceil(block_size);
        let capacity = usize::try_from(sz).map_err(|_| PdbError::CorruptData)?.min(raw.len());
        let mut content = Vec::with_capacity(capacity);
        for _ in 0..num_blocks {
            let page = read_u32_le(&dir_data, off)?;
            off += 4;
            let start = (page as usize).saturating_mul(block_size);
            // Skipping an out-of-range page silently *shifts* the stream: the
            // missing block's bytes are simply absent and everything after
            // slides left. Reject instead.
            if start >= raw.len() {
                return Err(PdbError::CorruptData);
            }
            let end = (start + block_size).min(raw.len());
            content.extend_from_slice(&raw[start..end]);
        }
        content.truncate(sz as usize);
        map.insert(idx_u32, content);
    }

    Ok(map)
}

// ── PDB Info stream (stream 1) ────────────────────────────────────────────────

fn parse_info_stream(data: &[u8]) -> Result<(PdbGuid, PdbAge)> {
    if data.len() < 28 {
        return Err(PdbError::StreamTooShort);
    }
    // version u32 at 0, signature u32 at 4
    let age = read_u32_le(data, 8)?;
    let mut guid_bytes = [0u8; 16];
    guid_bytes.copy_from_slice(&data[12..28]);
    Ok((PdbGuid { data: guid_bytes }, PdbAge(age)))
}

// ── DBI stream (stream 3) ─────────────────────────────────────────────────────

/// Minimal `DBI` header – only the fields we need.
struct DbiHeader {
    symbol_stream: u16,
    module_info_size: u32,
}

fn parse_dbi_header(data: &[u8]) -> Result<DbiHeader> {
    if data.len() < 64 {
        return Err(PdbError::StreamTooShort);
    }
    // signature i32 at 0 (must be -1)
    // version u32 at 4
    // age u32 at 8
    // global_symbol_stream u16 at 12
    // build_number u16 at 14
    // public_symbol_stream u16 at 16
    // pdb_dll_version u16 at 18
    let symbol_stream = read_u16_le(data, 20)?;
    // pdb_dll_rbld u16 at 22
    let module_info_size = read_u32_le(data, 24)?;

    Ok(DbiHeader {
        symbol_stream,
        module_info_size,
    })
}

/// Parse the module info sub-stream of `DBI` (starts at byte 64 in the `DBI` stream).
fn parse_dbi_modules(data: &[u8], module_info_size: u32) -> Result<Vec<PdbModule>> {
    Ok(parse_dbi_modules_ext(data, module_info_size)?
        .into_iter()
        .map(|(m, _)| m)
        .collect())
}

/// Extended variant of [`parse_dbi_modules`] that additionally returns the
/// `sym_byte_size` (length in bytes of the `CodeView` symbol sub-stream embedded
/// in this module's stream). The symbol sub-stream sits at offset 4 of each
/// module's stream, prefixed by a 4-byte signature.
fn parse_dbi_modules_ext(
    data: &[u8],
    module_info_size: u32,
) -> Result<Vec<(PdbModule, u32)>> {
    let start = 64usize;
    let end = start.saturating_add(module_info_size as usize);
    let mod_data = data.get(start..end).ok_or(PdbError::StreamTooShort)?;

    let mut modules = Vec::new();
    let mut off = 0usize;

    while off + 64 <= mod_data.len() {
        // Each module info record has a 64-byte fixed header followed by two
        // null-terminated strings: module name and object file name.
        let stream_index = read_u16_le(mod_data, off + 34)?;
        // sym_byte_size lives just past module_sym_stream in the fixed header.
        let sym_byte_size = read_u32_le(mod_data, off + 36)?;

        let (mod_name, after_name) = read_cstring(mod_data, off + 64);
        let (obj_name, after_obj) = read_cstring(mod_data, after_name);

        modules.push((
            PdbModule {
                name: mod_name,
                object_file: obj_name,
                stream_index,
            },
            sym_byte_size,
        ));

        // Records are 4-byte aligned.
        let record_size = after_obj - off;
        let aligned = (record_size + 3) & !3;
        off += aligned;
    }

    Ok(modules)
}

// ── Symbol records ────────────────────────────────────────────────────────────

// Record type codes used in the global symbol stream.
// Single source of truth: `crate::sym_kinds` (cvinfo.h SYM_ENUM_e).
use crate::sym_kinds::{
    S_GDATA32, S_GPROC32, S_GPROC32_ID, S_LABEL32, S_LDATA32, S_LPROC32, S_LPROC32_ID, S_PUB32,
    S_THUNK32,
};

/// Post-parse sanity filter for PDB symbol records.
///
/// Malformed/partial streams produce records with absurd sizes and junk
/// names. Reject anything that obviously cannot be a real symbol.
pub(crate) fn pdb_symbol_is_sane(name: &str, size: u32) -> bool {
    // No real function/data symbol exceeds 64 MiB.
    if size > 0x0400_0000 {
        return false;
    }
    if name.is_empty() {
        return false;
    }
    if name.contains('\0') {
        return false;
    }
    let bytes = name.as_bytes();
    if bytes[0] == 0 {
        return false;
    }
    if name.len() == 1 {
        let c = bytes[0] as char;
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    true
}

fn parse_symbols_with_segment_from_stream(
    data: &[u8],
) -> Result<Vec<(u16, u32, String, SymbolKind)>> {
    let mut out: Vec<(u16, u32, String, SymbolKind)> = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let length = read_u16_le(data, off)? as usize;
        if length < 2 {
            break;
        }
        let rec_type = read_u16_le(data, off + 2)?;
        let payload = data
            .get(off + 4..off + 2 + length)
            .ok_or(PdbError::CorruptData)?;
        match rec_type {
            S_PUB32 => {
                // flags(4) + offset(4) + segment(2) + name(nul)
                if payload.len() >= 10 {
                    let flags = read_u32_le(payload, 0)?;
                    let offset = read_u32_le(payload, 4)?;
                    let segment = read_u16_le(payload, 8)?;
                    let (name, _) = read_cstring(payload, 10);
                    let kind = if flags & 0x2 != 0 {
                        SymbolKind::Function
                    } else {
                        SymbolKind::Data
                    };
                    if segment != 0 && pdb_symbol_is_sane(&name, 0) {
                        out.push((segment, offset, name, kind));
                    }
                }
            }
            S_GPROC32 | S_LPROC32 => {
                if payload.len() >= 36 {
                    let size = read_u32_le(payload, 12)?;
                    let offset = read_u32_le(payload, 28)?;
                    let segment = read_u16_le(payload, 32)?;
                    let (name, _) = read_cstring(payload, 35);
                    if segment != 0 && pdb_symbol_is_sane(&name, size) {
                        out.push((segment, offset, name, SymbolKind::Function));
                    }
                }
            }
            S_GDATA32 | S_LDATA32 => {
                if payload.len() >= 10 {
                    let offset = read_u32_le(payload, 4)?;
                    let segment = read_u16_le(payload, 8)?;
                    let (name, _) = read_cstring(payload, 10);
                    if segment != 0 && pdb_symbol_is_sane(&name, 0) {
                        out.push((segment, offset, name, SymbolKind::Data));
                    }
                }
            }
            S_LABEL32 => {
                if payload.len() >= 7 {
                    let offset = read_u32_le(payload, 0)?;
                    let segment = read_u16_le(payload, 4)?;
                    let (name, _) = read_cstring(payload, 7);
                    if segment != 0 && pdb_symbol_is_sane(&name, 0) {
                        out.push((segment, offset, name, SymbolKind::Label));
                    }
                }
            }
            S_THUNK32
                if payload.len() >= 21 => {
                    let offset = read_u32_le(payload, 12)?;
                    let segment = read_u16_le(payload, 16)?;
                    let (name, _) = read_cstring(payload, 21);
                    if segment != 0 && pdb_symbol_is_sane(&name, 0) {
                        out.push((segment, offset, name, SymbolKind::Thunk));
                    }
                }
            _ => {}
        }
        off += 2 + length;
        off = (off + 3) & !3;
    }
    Ok(out)
}

fn parse_symbols_from_stream(data: &[u8]) -> Result<Vec<PdbSymbol>> {
    let mut symbols = Vec::new();
    let mut off = 0usize;

    while off + 4 <= data.len() {
        let length = read_u16_le(data, off)? as usize;
        if length < 2 {
            break;
        }
        let rec_type = read_u16_le(data, off + 2)?;
        let payload = data
            .get(off + 4..off + 2 + length)
            .ok_or(PdbError::CorruptData)?;

        match rec_type {
            S_PUB32 => {
                // flags(4) + offset(4) + segment(2) + name(nul)
                if payload.len() >= 10 {
                    let offset = u64::from(read_u32_le(payload, 4)?);
                    let (name, _) = read_cstring(payload, 10);
                    let flags = read_u32_le(payload, 0)?;
                    let kind = if flags & 0x2 != 0 {
                        SymbolKind::Function
                    } else {
                        SymbolKind::Data
                    };
                    if pdb_symbol_is_sane(&name, 0) {
                        symbols.push(PdbSymbol {
                            name,
                            address: offset,
                            size: 0,
                            kind,
                        });
                    }
                }
            }
            S_GPROC32 | S_LPROC32 => {
                // parent(4)+end(4)+next(4)+len(4)+dbg_start(4)+dbg_end(4)+typind(4)+offset(4)+seg(2)+flags(1)+name(nul)
                if payload.len() >= 36 {
                    let size = read_u32_le(payload, 12)?;
                    let offset = u64::from(read_u32_le(payload, 28)?);
                    let (name, _) = read_cstring(payload, 35);
                    if pdb_symbol_is_sane(&name, size) {
                        symbols.push(PdbSymbol {
                            name,
                            address: offset,
                            size,
                            kind: SymbolKind::Function,
                        });
                    }
                }
            }
            S_GDATA32 | S_LDATA32 => {
                // typind(4) + offset(4) + segment(2) + name(nul)
                if payload.len() >= 10 {
                    let offset = u64::from(read_u32_le(payload, 4)?);
                    let (name, _) = read_cstring(payload, 10);
                    if pdb_symbol_is_sane(&name, 0) {
                        symbols.push(PdbSymbol {
                            name,
                            address: offset,
                            size: 0,
                            kind: SymbolKind::Data,
                        });
                    }
                }
            }
            S_LABEL32 => {
                // offset(4) + segment(2) + flags(1) + name(nul)
                if payload.len() >= 7 {
                    let offset = u64::from(read_u32_le(payload, 0)?);
                    let (name, _) = read_cstring(payload, 7);
                    if pdb_symbol_is_sane(&name, 0) {
                        symbols.push(PdbSymbol {
                            name,
                            address: offset,
                            size: 0,
                            kind: SymbolKind::Label,
                        });
                    }
                }
            }
            S_THUNK32
                // parent(4)+end(4)+next(4)+offset(4)+segment(2)+len(2)+ord(1)+name(nul)+variant
                if payload.len() >= 21 => {
                    let offset = u64::from(read_u32_le(payload, 12)?);
                    let size = u32::from(read_u16_le(payload, 18)?);
                    let (name, _) = read_cstring(payload, 21);
                    if pdb_symbol_is_sane(&name, size) {
                        symbols.push(PdbSymbol {
                            name,
                            address: offset,
                            size,
                            kind: SymbolKind::Thunk,
                        });
                    }
                }
            _ => {}
        }

        off += 2 + length;
        // Records are 4-byte aligned.
        off = (off + 3) & !3;
    }

    Ok(symbols)
}

// ── TPI stream (stream 2) – type records ─────────────────────────────────────

// Leaf type codes (subset).
const LF_POINTER: u16 = 0x1002;
const LF_ARRAY: u16 = 0x1503;
const LF_CLASS: u16 = 0x1504;
const LF_STRUCTURE: u16 = 0x1505;
const LF_UNION: u16 = 0x1506;
const LF_ENUM: u16 = 0x1507;
const LF_PROCEDURE: u16 = 0x1008;

/// Decode the simple type records this crate's top-level reader understands
/// from a raw `TPI` stream.
///
/// This is the parser behind [`PdbReader::types`]. Note the limitation
/// documented at the crate root: `LF_FIELDLIST` is not followed, so struct /
/// union / enum members come back as `field_N` / `variant_N` placeholders.
///
/// # Errors
/// Returns a [`PdbError`] if the stream is truncated or a record is malformed.
pub fn parse_tpi_stream(data: &[u8]) -> Result<Vec<PdbType>> {
    if data.len() < 56 {
        return Err(PdbError::StreamTooShort);
    }
    let mut types = Vec::new();
    let mut off = 56usize;
    while off + 4 <= data.len() {
        let length = read_u16_le(data, off)? as usize;
        if length < 2 {
            break;
        }
        let leaf_type = read_u16_le(data, off + 2)?;
        let payload = data
            .get(off + 4..off + 2 + length)
            .ok_or(PdbError::CorruptData)?;
        if let Some(t) = parse_tpi_record(leaf_type, payload)? {
            types.push(t);
        }
        off += 2 + length;
    }
    Ok(types)
}

fn parse_tpi_record(leaf_type: u16, payload: &[u8]) -> Result<Option<PdbType>> {
    let t = match leaf_type {
        LF_STRUCTURE | LF_CLASS => parse_tpi_struct(payload)?,
        LF_UNION => parse_tpi_union(payload)?,
        LF_ENUM => parse_tpi_enum(payload)?,
        LF_POINTER => Some(PdbType {
            name: "pointer".into(),
            kind: TypeKind::Pointer,
            size: 8,
        }),
        LF_ARRAY => Some(PdbType {
            name: "array".into(),
            kind: TypeKind::Array,
            size: 0,
        }),
        LF_PROCEDURE => Some(PdbType {
            name: "function_type".into(),
            kind: TypeKind::Function,
            size: 0,
        }),
        0x0001..=0x00FF => Some(PdbType {
            name: primitive_type_name(leaf_type),
            kind: TypeKind::Primitive,
            size: primitive_type_size(leaf_type),
        }),
        _ => None,
    };
    Ok(t)
}

/// Decode a `CodeView` numeric leaf at `payload[pos..]`.
///
/// A value below 0x8000 *is* the value and occupies the 2 tag bytes. Otherwise
/// the tag names a wider signed/unsigned field that follows it. Returns
/// `(value, bytes_consumed)`.
fn read_numeric_leaf_at(payload: &[u8], pos: usize) -> Option<(u64, usize)> {
    let tag = read_u16_le(payload, pos).ok()?;
    if tag < 0x8000 {
        return Some((u64::from(tag), 2));
    }
    let rd = |n: usize| -> Option<u64> {
        let b = payload.get(pos + 2..pos + 2 + n)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(b);
        Some(u64::from_le_bytes(v))
    };
    match tag {
        0x8000 => Some((rd(1)?, 3)),                     // LF_CHAR   (i8)
        0x8001 | 0x8002 => Some((rd(2)?, 4)),            // LF_SHORT / LF_USHORT
        0x8003 | 0x8004 => Some((rd(4)?, 6)),            // LF_LONG / LF_ULONG
        0x8009 | 0x800a => Some((rd(8)?, 10)),           // LF_QUADWORD / LF_UQUADWORD
        _ => None,
    }
}

fn parse_tpi_struct(payload: &[u8]) -> Result<Option<PdbType>> {
    if payload.len() < 18 {
        return Ok(None);
    }
    let count = read_u16_le(payload, 0)? as usize;
    let fields: Vec<String> = (0..count).map(|i| format!("field_{i}")).collect();
    // LF_STRUCTURE: u16 count, u16 property, u32 field, u32 derived,
    // u32 vshape, <numeric leaf size>, name. The size is a *numeric leaf*:
    // anything >= 0x8000 is a tag plus 1/2/4/8 more bytes, so the name does
    // not always start at 18.
    let Some((size64, consumed)) = read_numeric_leaf_at(payload, 16) else {
        return Ok(None);
    };
    let size = u32::try_from(size64).unwrap_or(u32::MAX);
    let (name, _) = read_cstring(payload, 16 + consumed);
    Ok(Some(PdbType {
        name: if name.is_empty() {
            "<unnamed_struct>".into()
        } else {
            name
        },
        kind: TypeKind::Struct { fields },
        size,
    }))
}

fn parse_tpi_union(payload: &[u8]) -> Result<Option<PdbType>> {
    if payload.len() < 10 {
        return Ok(None);
    }
    let count = read_u16_le(payload, 0)? as usize;
    let fields: Vec<String> = (0..count).map(|i| format!("variant_{i}")).collect();
    // LF_UNION: u16 count, u16 property, u32 field, <numeric leaf size>, name.
    let Some((size64, consumed)) = read_numeric_leaf_at(payload, 8) else {
        return Ok(None);
    };
    let size = u32::try_from(size64).unwrap_or(u32::MAX);
    let (name, _) = read_cstring(payload, 8 + consumed);
    Ok(Some(PdbType {
        name: if name.is_empty() {
            "<unnamed_union>".into()
        } else {
            name
        },
        kind: TypeKind::Union { fields },
        size,
    }))
}

fn parse_tpi_enum(payload: &[u8]) -> Result<Option<PdbType>> {
    // LF_ENUM: u16 count, u16 property, u32 underlying_ti, u32 field_list_ti,
    // name — the name begins at offset **12**, not 10. Reading at 10 splices
    // the two low bytes of field_list_ti onto the front of the name.
    if payload.len() < 12 {
        return Ok(None);
    }
    let count = read_u16_le(payload, 0)? as usize;
    let variants: Vec<String> = (0..count).map(|i| format!("variant_{i}")).collect();
    let (name, _) = read_cstring(payload, 12);
    Ok(Some(PdbType {
        name: if name.is_empty() {
            "<unnamed_enum>".into()
        } else {
            name
        },
        kind: TypeKind::Enum { variants },
        size: 4,
    }))
}

fn primitive_type_name(code: u16) -> String {
    match code {
        0x01 => "void",
        0x03 => "bool",
        0x10 => "i8",
        0x11 => "i16",
        0x12 => "i32",
        0x13 => "i64",
        0x20 => "u8",
        0x21 => "u16",
        0x22 => "u32",
        0x23 => "u64",
        0x40 => "f32",
        0x41 => "f64",
        _ => "primitive",
    }
    .into()
}

const fn primitive_type_size(code: u16) -> u32 {
    match code {
        0x03 | 0x10 | 0x20 => 1,
        0x11 | 0x21 => 2,
        0x12 | 0x22 | 0x40 => 4,
        0x13 | 0x23 | 0x41 => 8,
        _ => 0,
    }
}

// ── PdbReader ─────────────────────────────────────────────────────────────────

/// Main entry point for reading a `PDB` file.
pub struct PdbReader {
    streams: HashMap<u32, Vec<u8>>,
    guid: PdbGuid,
    age: PdbAge,
}

impl PdbReader {
    /// Open and parse a `PDB` file from disk.
    ///
    /// # Errors
    /// Returns an error if parsing/reading fails.
    pub fn open(path: &Path) -> Result<Self> {
        let raw = fs::read(path)?;
        Self::from_bytes(&raw)
    }

    /// Parse `PDB` from an in-memory byte slice (useful for testing).
    ///
    /// # Errors
    /// Returns an error if parsing/reading fails.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let sb = parse_superblock(raw)?;
        let streams = build_stream_map(raw, &sb)?;

        let info = streams.get(&1).ok_or(PdbError::StreamOutOfRange(1))?;
        let (guid, age) = parse_info_stream(info)?;

        Ok(Self { streams, guid, age })
    }

    /// Return the `PDB` `GUID`.
    #[must_use]
    pub const fn guid(&self) -> PdbGuid {
        self.guid
    }

    /// Return the `PDB` Age counter.
    #[must_use]
    pub const fn age(&self) -> PdbAge {
        self.age
    }

    /// Return every code-bearing symbol from the global symbol stream,
    /// carrying the original `(segment, offset)` pair so callers can lift
    /// them to a VA via the binary's section table.
    ///
    /// Unlike [`Self::symbols`], this skips records that have no segment
    /// (which would otherwise collide on bogus `address == raw_offset`
    /// values and pollute name-by-VA lookup tables).
    #[must_use]
    pub fn symbols_with_segment(&self) -> Vec<(u16, u32, String, SymbolKind)> {
        self.try_symbols_with_segment().unwrap_or_default()
    }

    /// Fallible counterpart of [`Self::symbols_with_segment`].
    ///
    /// # Errors
    /// Returns [`PdbError::StreamOutOfRange`] when the `DBI` stream or the
    /// symbol stream it points at is missing, or a parse error when a record
    /// is malformed — cases the infallible variant flattens into an empty
    /// `Vec`, making a truncated `PDB` indistinguishable from a symbol-less one.
    pub fn try_symbols_with_segment(&self) -> Result<Vec<(u16, u32, String, SymbolKind)>> {
        let sym_stream = self.symbol_record_stream()?;
        parse_symbols_with_segment_from_stream(sym_stream)
    }

    /// Return all symbols found in the global symbol stream.
    #[must_use]
    pub fn symbols(&self) -> Vec<PdbSymbol> {
        self.try_symbols().unwrap_or_default()
    }

    /// Fallible counterpart of [`Self::symbols`].
    ///
    /// # Errors
    /// See [`Self::try_symbols_with_segment`].
    pub fn try_symbols(&self) -> Result<Vec<PdbSymbol>> {
        let sym_stream = self.symbol_record_stream()?;
        parse_symbols_from_stream(sym_stream)
    }

    /// Resolve the symbol record stream via the `DBI` header.
    fn symbol_record_stream(&self) -> Result<&Vec<u8>> {
        let dbi = self.streams.get(&3).ok_or(PdbError::StreamOutOfRange(3))?;
        let header = parse_dbi_header(dbi)?;
        let sym_stream_idx = u32::from(header.symbol_stream);
        self.streams
            .get(&sym_stream_idx)
            .ok_or(PdbError::StreamOutOfRange(sym_stream_idx))
    }

    /// Return all type records from the `TPI` stream.
    #[must_use]
    pub fn types(&self) -> Vec<PdbType> {
        self.try_types().unwrap_or_default()
    }

    /// Fallible counterpart of [`Self::types`].
    ///
    /// # Errors
    /// Returns [`PdbError::StreamOutOfRange`] when the `TPI` stream is absent,
    /// or a parse error when it is truncated or malformed.
    pub fn try_types(&self) -> Result<Vec<PdbType>> {
        let tpi = self.streams.get(&2).ok_or(PdbError::StreamOutOfRange(2))?;
        parse_tpi_stream(tpi)
    }

    /// Return all modules listed in the `DBI` stream.
    #[must_use]
    pub fn modules(&self) -> Vec<PdbModule> {
        self.try_modules().unwrap_or_default()
    }

    /// Fallible counterpart of [`Self::modules`].
    ///
    /// # Errors
    /// Returns [`PdbError::StreamOutOfRange`] when the `DBI` stream is absent,
    /// or a parse error when its header / module-info substream is malformed.
    pub fn try_modules(&self) -> Result<Vec<PdbModule>> {
        let dbi = self.streams.get(&3).ok_or(PdbError::StreamOutOfRange(3))?;
        let header = parse_dbi_header(dbi)?;
        parse_dbi_modules(dbi, header.module_info_size)
    }

    /// Walk every per-module symbol stream listed in the `DBI` stream and
    /// extract `S_GPROC32` / `S_LPROC32` procedure records.
    ///
    /// Microsoft toolchains (and `rustc` when targeting the MSVC ABI) frequently
    /// emit release PDBs whose **public** symbol stream is empty — every
    /// non-exported procedure lives only in its compiland's per-module stream.
    /// [`Self::symbols`] only returns the public stream, so this method is the
    /// fallback path that yields the actual function table for a stripped Rust
    /// release build.
    ///
    /// Each returned [`PdbModuleProc`] carries the 1-based PE section index
    /// (`segment`) and a section-relative `code_offset`; the caller is
    /// responsible for converting those into a final VA via the binary's
    /// section table.
    #[must_use]
    pub fn module_proc_symbols(&self) -> Vec<PdbModuleProc> {
        self.try_module_proc_symbols().unwrap_or_default()
    }

    /// Fallible counterpart of [`Self::module_proc_symbols`].
    ///
    /// # Errors
    /// Returns [`PdbError::StreamOutOfRange`] when the `DBI` stream is absent,
    /// or a parse error when its header / module-info substream is malformed.
    /// Individual module streams that are missing or truncated are still
    /// skipped rather than failing the whole walk.
    pub fn try_module_proc_symbols(&self) -> Result<Vec<PdbModuleProc>> {
        let dbi = self.streams.get(&3).ok_or(PdbError::StreamOutOfRange(3))?;
        let header = parse_dbi_header(dbi)?;
        let modules = parse_dbi_modules_ext(dbi, header.module_info_size)?;
        let mut out: Vec<PdbModuleProc> = Vec::new();
        for (m, sym_byte_size) in modules {
            if m.stream_index == 0xFFFF || sym_byte_size < 4 {
                continue;
            }
            let Some(stream) = self.streams.get(&u32::from(m.stream_index)) else {
                continue;
            };
            // The module stream starts with a 4-byte signature (usually
            // `CV_SIGNATURE_C13` = 4). The symbol sub-stream then runs for
            // `sym_byte_size - 4` bytes.
            let sym_start = 4usize;
            let sym_len = (sym_byte_size as usize).saturating_sub(4);
            let sym_end = sym_start.saturating_add(sym_len).min(stream.len());
            if sym_end <= sym_start {
                continue;
            }
            let sub = &stream[sym_start..sym_end];
            extract_procs_from_module_stream(sub, &mut out);
        }
        Ok(out)
    }
}

/// Walk one module's `CodeView` symbol sub-stream and push every `S_GPROC32` /
/// `S_LPROC32` procedure into `out`. Skips other records but tracks `S_END`
/// scope nesting implicitly by only emitting on the leading proc record.
fn extract_procs_from_module_stream(data: &[u8], out: &mut Vec<PdbModuleProc>) {
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let Ok(length) = read_u16_le(data, off) else { break };
        let length = length as usize;
        if length < 2 {
            break;
        }
        let Ok(rec_type) = read_u16_le(data, off + 2) else { break };
        let rec_end = off + 2 + length;
        if rec_end > data.len() {
            break;
        }
        if rec_type == S_GPROC32
            || rec_type == S_LPROC32
            || rec_type == S_GPROC32_ID
            || rec_type == S_LPROC32_ID
        {
            // S_GPROC32 payload layout:
            //   parent(4) end(4) next(4) len(4) dbg_start(4) dbg_end(4)
            //   typind(4) offset(4) segment(2) flags(1) name(nul)
            // S_*PROC32_ID has identical layout — the only difference is that
            // `typind` references an ID stream entry instead of a TPI entry.
            // Rust ships these by default; ignoring them was leaving ~30
            // module-local helpers unnamed on cargo-zyphora.exe.
            let payload = &data[off + 4..rec_end];
            if payload.len() >= 36
                && let (Ok(code_size), Ok(code_offset), Ok(segment)) = (
                    read_u32_le(payload, 12),
                    read_u32_le(payload, 28),
                    read_u16_le(payload, 32),
                ) {
                    let (name, _) = read_cstring(payload, 35);
                    if !name.is_empty() && segment != 0 {
                        out.push(PdbModuleProc {
                            name,
                            segment,
                            code_offset,
                            code_size,
                        });
                    }
                }
        } else if rec_type == S_THUNK32 {
            // S_THUNK32 payload:
            //   parent(4) end(4) next(4) offset(4) segment(2) len(2)
            //   ord(1) name(nul) variant
            // Rust's MSVC backend emits per-trampoline thunks for tail-call
            // helpers and import call-stubs; they show up as their own
            // boundaries in the detector, but the name only lives in this
            // record. Treat them as a 0-sized proc — the wire layer matches
            // on the start VA, not the size.
            let payload = &data[off + 4..rec_end];
            if payload.len() >= 21
                && let (Ok(code_offset), Ok(segment), Ok(thunk_len)) = (
                    read_u32_le(payload, 12),
                    read_u16_le(payload, 16),
                    read_u16_le(payload, 18),
                ) {
                    let (name, _) = read_cstring(payload, 21);
                    if !name.is_empty() && segment != 0 {
                        out.push(PdbModuleProc {
                            name,
                            segment,
                            code_offset,
                            code_size: u32::from(thunk_len),
                        });
                    }
                }
        }
        off = rec_end;
        // Records are 4-byte aligned in module streams as well.
        off = (off + 3) & !3;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers to build minimal in-memory PDB data ──────────────────────────

    fn make_info_stream() -> Vec<u8> {
        let mut v = vec![0u8; 56];
        // version = 20_000_404
        v[0..4].copy_from_slice(&20_000_404u32.to_le_bytes());
        // signature
        v[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // age = 1
        v[8..12].copy_from_slice(&1u32.to_le_bytes());
        // GUID bytes
        for (i, b) in v[12..28].iter_mut().enumerate() {
            *b = u8::try_from(i + 1).unwrap();
        }
        v
    }

    fn make_symbol_record_pub32(name: &str, offset: u32, is_fn: bool) -> Vec<u8> {
        let flags: u32 = if is_fn { 0x2 } else { 0x0 };
        let mut r = Vec::new();
        r.extend_from_slice(&flags.to_le_bytes()); // flags
        r.extend_from_slice(&offset.to_le_bytes()); // offset
        r.extend_from_slice(&1u16.to_le_bytes()); // segment
        r.extend_from_slice(name.as_bytes());
        r.push(0); // null terminator
        r
    }

    fn frame_record(rec_type: u16, payload: &[u8]) -> Vec<u8> {
        // length = type(2) + payload
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&rec_type.to_le_bytes());
        v.extend_from_slice(payload);
        // pad to 4-byte boundary
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn make_symbol_stream() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(frame_record(
            S_PUB32,
            &make_symbol_record_pub32("MyFunction", 0x1000, true),
        ));
        v.extend(frame_record(
            S_PUB32,
            &make_symbol_record_pub32("MyData", 0x2000, false),
        ));
        v
    }

    fn make_dbi_stream(sym_stream_idx: u16) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        // signature = -1
        v[0..4].copy_from_slice(&(-1i32).to_le_bytes());
        // version
        v[4..8].copy_from_slice(&19_990_903u32.to_le_bytes());
        // symbol_stream at offset 20
        v[20..22].copy_from_slice(&sym_stream_idx.to_le_bytes());
        // module_info_size = 0
        v[24..28].copy_from_slice(&0u32.to_le_bytes());
        v
    }

    fn make_tpi_stream_with_struct(type_name: &str) -> Vec<u8> {
        let mut v = vec![0u8; 56]; // header
        // LF_STRUCTURE record
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // count
        payload.extend_from_slice(&0u16.to_le_bytes()); // property
        payload.extend_from_slice(&0u32.to_le_bytes()); // field
        payload.extend_from_slice(&0u32.to_le_bytes()); // derived
        payload.extend_from_slice(&0u32.to_le_bytes()); // vshape
        payload.extend_from_slice(&16u16.to_le_bytes()); // size leaf (simple u16)
        payload.extend_from_slice(type_name.as_bytes());
        payload.push(0);
        v.extend(frame_record(LF_STRUCTURE, &payload));
        v
    }

    fn make_tpi_stream_with_enum(type_name: &str) -> Vec<u8> {
        let mut v = vec![0u8; 56];
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u16.to_le_bytes()); // count        (0..2)
        payload.extend_from_slice(&0u16.to_le_bytes()); // property      (2..4)
        payload.extend_from_slice(&0x0074u32.to_le_bytes()); // underlying_ti (4..8)
        // The real LF_ENUM layout: field_list_ti is a full u32 at 8..12, so the
        // name begins at offset 12. The old fixture emitted a 2-byte field and
        // put the name at 10, which happened to agree with a buggy parser.
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // field_list_ti (8..12)
        payload.extend_from_slice(type_name.as_bytes());
        payload.push(0);
        v.extend(frame_record(LF_ENUM, &payload));
        v
    }

    // ── PdbGuid tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_guid_format() {
        let guid = PdbGuid {
            data: [
                0x78, 0x56, 0x34, 0x12, 0xCD, 0xAB, 0x01, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                0x70, 0x80,
            ],
        };
        let s = guid.to_string_fmt();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert_eq!(s.len(), 38);
    }

    #[test]
    fn test_guid_all_zeros() {
        let guid = PdbGuid { data: [0u8; 16] };
        let s = guid.to_string_fmt();
        assert_eq!(s, "{00000000-0000-0000-0000-000000000000}");
    }

    // ── PdbAge tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_age_value() {
        let age = PdbAge(42);
        assert_eq!(age.0, 42);
    }

    // ── SymbolKind tests ──────────────────────────────────────────────────────

    #[test]
    fn test_symbol_kind_variants() {
        assert_ne!(SymbolKind::Function, SymbolKind::Data);
        assert_ne!(SymbolKind::Label, SymbolKind::Thunk);
    }

    // ── Low-level read helpers ────────────────────────────────────────────────

    #[test]
    fn test_read_u16_le() {
        let data = [0x34u8, 0x12];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_u32_le_too_short() {
        let data = [0x01u8, 0x02];
        assert!(read_u32_le(&data, 0).is_err());
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\x00world\x00";
        let (s, next) = read_cstring(data, 0);
        assert_eq!(s, "hello");
        assert_eq!(next, 6);
    }

    #[test]
    fn test_read_cstring_empty() {
        let data = b"\x00rest";
        let (s, next) = read_cstring(data, 0);
        assert_eq!(s, "");
        assert_eq!(next, 1);
    }

    // ── Info stream parsing ───────────────────────────────────────────────────

    #[test]
    fn test_parse_info_stream() {
        let data = make_info_stream();
        let (guid, age) = parse_info_stream(&data).unwrap();
        assert_eq!(age.0, 1);
        assert_eq!(guid.data[0], 1);
        assert_eq!(guid.data[15], 16);
    }

    #[test]
    fn test_parse_info_stream_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_info_stream(&data).is_err());
    }

    // ── Symbol parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_symbol_pub32_function() {
        let payload = make_symbol_record_pub32("TestFunc", 0xDEAD, true);
        let stream = frame_record(S_PUB32, &payload);
        let syms = parse_symbols_from_stream(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "TestFunc");
        assert_eq!(syms[0].address, 0xDEAD);
        assert_eq!(syms[0].kind, SymbolKind::Function);
    }

    #[test]
    fn test_parse_symbol_pub32_data() {
        let payload = make_symbol_record_pub32("GlobalVar", 0x4000, false);
        let stream = frame_record(S_PUB32, &payload);
        let syms = parse_symbols_from_stream(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, SymbolKind::Data);
    }

    #[test]
    fn test_parse_multiple_symbols() {
        let stream = make_symbol_stream();
        let syms = parse_symbols_from_stream(&stream).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "MyFunction");
        assert_eq!(syms[0].kind, SymbolKind::Function);
        assert_eq!(syms[1].name, "MyData");
        assert_eq!(syms[1].kind, SymbolKind::Data);
    }

    #[test]
    fn test_parse_symbol_label() {
        // offset(4) + segment(2) + flags(1) + name
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x3000u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0); // flags
        payload.extend_from_slice(b"jump_target\x00");
        let stream = frame_record(S_LABEL32, &payload);
        let syms = parse_symbols_from_stream(&stream).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, SymbolKind::Label);
        assert_eq!(syms[0].name, "jump_target");
    }

    #[test]
    fn test_parse_empty_stream() {
        let syms = parse_symbols_from_stream(&[]).unwrap();
        assert!(syms.is_empty());
    }

    // ── TPI type parsing ──────────────────────────────────────────────────────

    #[test]
    fn test_tpi_struct() {
        let tpi = make_tpi_stream_with_struct("MyStruct");
        let types = parse_tpi_stream(&tpi).unwrap();
        assert!(!types.is_empty());
        let t = types.iter().find(|t| t.name == "MyStruct");
        assert!(t.is_some());
        assert!(matches!(t.unwrap().kind, TypeKind::Struct { .. }));
    }

    #[test]
    fn test_tpi_enum() {
        let tpi = make_tpi_stream_with_enum("Color");
        let types = parse_tpi_stream(&tpi).unwrap();
        let t = types.iter().find(|t| t.name == "Color");
        assert!(t.is_some());
        if let TypeKind::Enum { variants } = &t.unwrap().kind {
            assert_eq!(variants.len(), 3);
        } else {
            panic!("Expected enum kind");
        }
    }

    #[test]
    fn test_tpi_pointer() {
        let mut tpi = vec![0u8; 56];
        // minimal LF_POINTER record: payload can be just type_index(4) + attr(4)
        let payload = vec![0u8; 8];
        tpi.extend(frame_record(LF_POINTER, &payload));
        let types = parse_tpi_stream(&tpi).unwrap();
        assert!(types.iter().any(|t| matches!(t.kind, TypeKind::Pointer)));
    }

    #[test]
    fn test_tpi_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_tpi_stream(&data).is_err());
    }

    // ── DBI module parsing ────────────────────────────────────────────────────

    #[test]
    fn test_dbi_header_sym_stream() {
        let dbi = make_dbi_stream(5);
        let hdr = parse_dbi_header(&dbi).unwrap();
        assert_eq!(hdr.symbol_stream, 5);
    }

    #[test]
    fn test_dbi_header_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_dbi_header(&data).is_err());
    }

    // ── PdbSymbol struct ──────────────────────────────────────────────────────

    #[test]
    fn test_pdb_symbol_clone() {
        let s = PdbSymbol {
            name: "foo".into(),
            address: 0x1000,
            size: 64,
            kind: SymbolKind::Function,
        };
        let c = s.clone();
        assert_eq!(s, c);
    }

    #[test]
    fn test_pdb_type_clone() {
        let t = PdbType {
            name: "Bar".into(),
            kind: TypeKind::Struct {
                fields: vec!["x".into()],
            },
            size: 8,
        };
        let c = t.clone();
        assert_eq!(t, c);
    }

    #[test]
    fn test_bad_magic() {
        let data = vec![0u8; 512];
        assert!(matches!(
            PdbReader::from_bytes(&data),
            Err(PdbError::BadMagic)
        ));
    }

    // ── S_PUB32 synthetic stream tests ────────────────────────────────────────

    /// Build a raw `S_PUB32` stream for "?Foo@@YAXXZ" at offset 0x1000, segment 1,
    /// flags=2 (function), then assert `parse_symbols_from_stream` returns exactly
    /// one symbol with the correct name and address.
    #[test]
    fn test_parse_pub32_msvc_mangled_name() {
        let name = "?Foo@@YAXXZ";
        // S_PUB32 payload: flags(4) + offset(4) + segment(2) + name(nul)
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes()); // flags: function
        payload.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // segment
        payload.extend_from_slice(name.as_bytes());
        payload.push(0); // null terminator

        let stream = frame_record(S_PUB32, &payload);
        let syms = parse_symbols_from_stream(&stream).unwrap();
        assert_eq!(syms.len(), 1, "expected 1 symbol, got {}", syms.len());
        assert_eq!(syms[0].name, name);
        assert_eq!(syms[0].address, 0x1000);
        assert_eq!(syms[0].size, 0); // S_PUB32 always has size 0
        assert_eq!(syms[0].kind, SymbolKind::Function);
    }

    /// Assert that `pdb_symbol_is_sane` accepts typical MSVC public symbol names
    /// that appear in real PDB files, including mangled, import-stub, and
    /// compiler-generated prefixes.
    #[test]
    fn test_sane_filter_accepts_msvc_public_names() {
        let accepted = [
            "?Foo@@YAXXZ",
            "_main",
            "??_C@_0BA@PBPGMDHD@Hello?5world?$AA@",
            "__imp_VirtualAlloc",
            "__security_cookie",
            "?__imp_X@@3PEAXEA",
        ];
        for name in &accepted {
            assert!(
                pdb_symbol_is_sane(name, 0),
                "pdb_symbol_is_sane rejected legitimate name: {name:?}"
            );
        }
    }

    #[test]
    fn test_filter_accepts_typical_public_names() {
        let names = ["?Foo@@YAXXZ", "_main", "__imp_GetProcAddress", "main", "A", "_"];
        for n in &names {
            assert!(
                pdb_symbol_is_sane(n, 0),
                "filter rejected {n:?} at size 0"
            );
            assert!(
                pdb_symbol_is_sane(n, 0x100),
                "filter rejected {n:?} at size 0x100"
            );
        }
    }

    #[test]
    fn test_filter_rejects_garbage() {
        assert!(!pdb_symbol_is_sane("", 0));
        assert!(!pdb_symbol_is_sane("\0", 0));
        assert!(!pdb_symbol_is_sane("?", 0));
        assert!(!pdb_symbol_is_sane("@", 0));
        assert!(!pdb_symbol_is_sane("main", 1_000_000_000));
    }

    #[test]
    fn test_primitive_type_name() {
        assert_eq!(primitive_type_name(0x01), "void");
        assert_eq!(primitive_type_name(0x12), "i32");
        assert_eq!(primitive_type_name(0x41), "f64");
    }

    #[test]
    fn test_primitive_type_size() {
        assert_eq!(primitive_type_size(0x12), 4);
        assert_eq!(primitive_type_size(0x41), 8);
        assert_eq!(primitive_type_size(0x01), 0);
    }
}

// ── PdbStreamReader ───────────────────────────────────────────────────────────

/// Well-known fixed `PDB` stream indices.
pub mod stream_indices {
    /// Previous MSF stream directory (unused by readers).
    pub const OLD_DIRECTORY: u32 = 0;
    /// PDB Info stream: version, signature, age, GUID, named streams.
    pub const PDB_INFO: u32 = 1;
    /// TPI stream: type records.
    pub const TPI: u32 = 2;
    /// DBI stream: modules, section contributions, file info.
    pub const DBI: u32 = 3;
    /// IPI stream: id records.
    pub const IPI: u32 = 4;
}

/// Metadata stored in the `PDB` Info stream (stream 1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbStreamInfo {
    /// `PDB` format version (e.g. `20_000_404`).
    pub version: u32,
    /// Signature timestamp written at link time.
    pub signature: u32,
    /// Age counter used for symbol-server matching.
    pub age: u32,
    /// 128-bit `GUID`.
    pub guid: [u8; 16],
}

/// Reads named-stream and info metadata directly from raw `PDB` bytes without
/// constructing a full [`PdbReader`].
pub struct PdbStreamReader;

impl PdbStreamReader {
    /// Parse the `PDB` Info stream (stream 1) and return [`PdbStreamInfo`].
    ///
    /// Returns `None` if the file is not a valid `PDB` or the stream is too short.
    #[must_use]
    pub fn parse_pdb_info(pdb_bytes: &[u8]) -> Option<PdbStreamInfo> {
        let sb = parse_superblock(pdb_bytes).ok()?;
        let streams = build_stream_map(pdb_bytes, &sb).ok()?;
        let info = streams.get(&stream_indices::PDB_INFO)?;
        if info.len() < 28 {
            return None;
        }
        let version = read_u32_le(info, 0).ok()?;
        let signature = read_u32_le(info, 4).ok()?;
        let age = read_u32_le(info, 8).ok()?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&info[12..28]);
        Some(PdbStreamInfo {
            version,
            signature,
            age,
            guid,
        })
    }

    /// Parse the named-stream directory embedded in the `PDB` Info stream and
    /// return a map of stream name → stream index.
    ///
    /// The named-stream hash-map is stored after the fixed 56-byte header in
    /// stream 1.  Layout (all little-endian):
    ///   - u32  `string_buffer_size`
    ///   - [u8; `string_buffer_size`]  (NUL-separated strings)
    ///   - u32  capacity
    ///   - u32  `present_word_count`  (number of u32 words in "present" bitset)
    ///   - [u32; `present_word_count`]
    ///   - u32  `deleted_word_count`
    ///   - [u32; `deleted_word_count`]
    ///   - [u32 key, u32 value; `num_present_bits`] pairs
    ///
    /// Returns an empty map on any parse failure so callers never crash.
    #[must_use]
    pub fn parse_stream_names(pdb_bytes: &[u8]) -> HashMap<String, u32> {
        let mut out = HashMap::new();
        let Ok(sb) = parse_superblock(pdb_bytes) else { return out };
        let Ok(streams) = build_stream_map(pdb_bytes, &sb) else { return out };
        let Some(info) = streams.get(&stream_indices::PDB_INFO) else {
            return out;
        };

        // Fixed header is 56 bytes: version(4)+signature(4)+age(4)+guid(16)+
        // and then the named-stream map starts at offset 28 (after guid).
        // Some PDB writers start the named-stream block at offset 28.
        let mut off = 28usize;
        if off + 4 > info.len() {
            return out;
        }
        let strbuf_size = match read_u32_le(info, off) {
            Ok(v) => v as usize,
            Err(_) => return out,
        };
        off += 4;
        if off + strbuf_size > info.len() {
            return out;
        }
        let strbuf = &info[off..off + strbuf_size];
        off += strbuf_size;

        // capacity (ignored), present bits, deleted bits, then key/value pairs.
        if off + 4 > info.len() {
            return out;
        }
        off += 4; // capacity
        if off + 4 > info.len() {
            return out;
        }
        let present_words = match read_u32_le(info, off) {
            Ok(v) => v as usize,
            Err(_) => return out,
        };
        off += 4;
        // Count set bits in the present bit-set; that is the number of
        // key/value pairs that follow. No need to materialise the bitset.
        let mut num_entries = 0usize;
        for _ in 0..present_words {
            if off + 4 > info.len() {
                return out;
            }
            let Ok(word) = read_u32_le(info, off) else { return out };
            off += 4;
            num_entries += word.count_ones() as usize;
        }
        if off + 4 > info.len() {
            return out;
        }
        let deleted_words = match read_u32_le(info, off) {
            Ok(v) => v as usize,
            Err(_) => return out,
        };
        off += 4;
        off = off.saturating_add(deleted_words.saturating_mul(4)); // skip deleted bitset

        for _ in 0..num_entries {
            if off + 8 > info.len() {
                break;
            }
            let key_off = match read_u32_le(info, off) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            let Ok(stream_idx) = read_u32_le(info, off + 4) else { break };
            off += 8;
            // Read the NUL-terminated name from strbuf.
            if key_off < strbuf.len() {
                let end = strbuf[key_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(strbuf.len(), |p| key_off + p);
                let name = String::from_utf8_lossy(&strbuf[key_off..end]).into_owned();
                if !name.is_empty() {
                    out.insert(name, stream_idx);
                }
            }
        }
        out
    }
}

// ── PdbPublicSymbolScanner ────────────────────────────────────────────────────

/// A public symbol record extracted from the publics stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdbPublicSymbol {
    /// Demangled (or raw) symbol name.
    pub name: String,
    /// Section-relative offset.
    pub offset: u32,
    /// Section index (1-based).
    pub section: u16,
}

/// Scans the public-symbols stream of a `PDB` file.
///
/// The public-symbols stream is referenced via the `DBI` stream header at offset
/// 16 (the `public_symbol_stream` field).  Each record in the stream is a
/// `S_PUB32` symbol record.
pub struct PdbPublicSymbolScanner;

impl PdbPublicSymbolScanner {
    /// Extract all public symbols from `pdb_bytes`.
    ///
    /// Returns an empty `Vec` if the file is not a valid `PDB`.
    ///
    /// The publics stream itself contains a [`PublicsHeader`] (28 bytes), then
    /// a GSI hash table — **not** raw symbol records. The actual `S_PUB32`
    /// records live in the **symbol-records stream** referenced by the DBI
    /// header at offset 20 (`sym_record_stream`). This function reads from
    /// that stream and additionally filters for `S_PUB32` records.
    #[must_use]
    pub fn scan_public_symbols(pdb_bytes: &[u8]) -> Vec<PdbPublicSymbol> {
        let Ok(sb) = parse_superblock(pdb_bytes) else { return Vec::new() };
        let Ok(streams) = build_stream_map(pdb_bytes, &sb) else { return Vec::new() };

        // DBI stream is at index 3.
        let Some(dbi) = streams.get(&stream_indices::DBI) else {
            return Vec::new();
        };
        if dbi.len() < 24 {
            return Vec::new();
        }
        // The publics stream (DBI offset 16) carries a GSI hash table and is
        // *not* a flat list of symbol records. Records live in the
        // sym_record_stream at DBI offset 20.
        let sym_record_stream_idx = match read_u16_le(dbi, 20) {
            Ok(v) => u32::from(v),
            Err(_) => return Vec::new(),
        };

        let mut syms: Vec<PdbPublicSymbol> =
            streams.get(&sym_record_stream_idx).map_or_else(Vec::new, |rec_stream| {
                Self::parse_pub_stream_at(rec_stream, 0)
            });

        // Some toolchains place S_PUB32 records directly in the publics stream
        // after a 28-byte header. As a fallback when the records stream yields
        // nothing, try the publics stream both at offset 0 and offset 28.
        if syms.is_empty() {
            let pub_stream_idx = match read_u16_le(dbi, 16) {
                Ok(v) => u32::from(v),
                Err(_) => return syms,
            };
            if let Some(pub_stream) = streams.get(&pub_stream_idx) {
                syms = Self::parse_pub_stream_at(pub_stream, 0);
                if syms.is_empty() && pub_stream.len() > 28 {
                    syms = Self::parse_pub_stream_at(pub_stream, 28);
                }
            }
        }
        syms
    }

    fn parse_pub_stream_at(data: &[u8], start: usize) -> Vec<PdbPublicSymbol> {
        let mut syms = Vec::new();
        let mut off = start;

        while off + 4 <= data.len() {
            let length = match read_u16_le(data, off) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            if length < 2 {
                break;
            }
            let Ok(rec_type) = read_u16_le(data, off + 2) else { break };
            let payload_end = off + 2 + length;
            let Some(payload) = data.get(off + 4..payload_end) else {
                break;
            };

            if rec_type == S_PUB32 && payload.len() >= 10 {
                // flags(4) + offset(4) + segment(2) + name(nul)
                let Ok(offset) = read_u32_le(payload, 4) else {
                    off = (payload_end + 3) & !3;
                    continue;
                };
                let Ok(section) = read_u16_le(payload, 8) else {
                    off = (payload_end + 3) & !3;
                    continue;
                };
                let (name, _) = read_cstring(payload, 10);
                if !name.is_empty() {
                    syms.push(PdbPublicSymbol {
                        name,
                        offset,
                        section,
                    });
                }
            }

            off = (payload_end + 3) & !3;
        }
        syms
    }
}

// ── resolve_name_for_address ──────────────────────────────────────────────────

/// Result of a symbolic-name lookup by virtual address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSymbol {
    /// The queried virtual address.
    pub address: u64,
    /// Raw (possibly mangled) symbol name.
    pub name: String,
    /// Demangled name, or a copy of `name` if demangling failed.
    pub demangled: String,
    /// `"import"`, `"export"`, or `"pdb"`.
    pub source: String,
    /// DLL name for imports; `None` otherwise.
    pub dll: Option<String>,
}

/// Look up the best symbolic name for `address` inside `pe_data`.
///
/// Search order:
/// 1. PE import address table (IAT) — `image_base + iat_rva == address`
/// 2. PE export table              — `image_base + rva == address`
/// 3. PDB public symbols           — `sym.address == Some(address)`
///
/// Returns `None` if no source matches.
#[must_use]
pub fn resolve_name_for_address(
    pe_data: &[u8],
    address: u64,
    pdb_data: Option<&[u8]>,
) -> Option<ResolvedSymbol> {
    let demangle = |s: &str| rustre_demangle::demangler_dispatcher::auto_demangle(s);

    if let Ok(mut pe) = rustre_pe_tools::PeFile::parse(pe_data) {
        let _ = pe.parse_imports(pe_data);
        for imp in &pe.imports {
            let va = pe.image_base + u64::from(imp.iat_rva);
            if va == address {
                let raw = imp.name.as_deref().unwrap_or("").to_owned();
                let name = if raw.is_empty() {
                    format!("ord_{}", imp.ordinal.unwrap_or(0))
                } else {
                    raw
                };
                return Some(ResolvedSymbol {
                    address,
                    demangled: demangle(&name),
                    source: "import".to_owned(),
                    dll: Some(imp.dll.clone()),
                    name,
                });
            }
        }
        let _ = pe.parse_exports(pe_data);
        for exp in &pe.exports {
            let va = pe.image_base + u64::from(exp.rva);
            if va == address {
                let name =
                    exp.name.clone().unwrap_or_else(|| format!("ord_{}", exp.ordinal));
                return Some(ResolvedSymbol {
                    address,
                    demangled: demangle(&name),
                    source: "export".to_owned(),
                    dll: None,
                    name,
                });
            }
        }
    }

    if let Some(pdb_bytes) = pdb_data
        && let Ok(syms) = global_symbols::parse_global_symbols(pdb_bytes) {
            for sym in &syms {
                if sym.address == Some(address) {
                    let demangled = sym
                        .demangled
                        .clone()
                        .unwrap_or_else(|| demangle(&sym.name));
                    return Some(ResolvedSymbol {
                        address,
                        name: sym.name.clone(),
                        demangled,
                        source: "pdb".to_owned(),
                        dll: None,
                    });
                }
            }
        }

    None
}

// ── Tests for new PDB types ───────────────────────────────────────────────────

#[cfg(test)]
mod pdb_stream_tests {
    use super::*;

    #[test]
    fn test_pdb_stream_info_parse_none_on_garbage() {
        let result = PdbStreamReader::parse_pdb_info(&[0u8; 64]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_stream_names_empty_on_garbage() {
        let names = PdbStreamReader::parse_stream_names(&[0u8; 64]);
        assert!(names.is_empty());
    }

    #[test]
    fn test_pdb_stream_info_fields() {
        let info = PdbStreamInfo {
            version: 20_000_404,
            signature: 0xDEAD_BEEF,
            age: 3,
            guid: [1u8; 16],
        };
        assert_eq!(info.version, 20_000_404);
        assert_eq!(info.signature, 0xDEAD_BEEF);
        assert_eq!(info.age, 3);
        assert_eq!(info.guid[0], 1);
    }

    #[test]
    fn test_public_symbol_fields() {
        let sym = PdbPublicSymbol {
            name: "TestSym".to_owned(),
            offset: 0x1000,
            section: 1,
        };
        assert_eq!(sym.name, "TestSym");
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.section, 1);
    }

    #[test]
    fn test_scan_public_symbols_bad_data() {
        let syms = PdbPublicSymbolScanner::scan_public_symbols(&[0u8; 128]);
        assert!(syms.is_empty());
    }

    #[test]
    fn test_stream_indices_constants() {
        assert_eq!(stream_indices::PDB_INFO, 1);
        assert_eq!(stream_indices::TPI, 2);
        assert_eq!(stream_indices::DBI, 3);
        assert_eq!(stream_indices::IPI, 4);
    }

    /// Smoke test: a sym-record stream with two `S_PUB32` records must yield
    /// exactly two parsed publics, with correct names/offsets/sections.
    #[test]
    fn test_pub32_smoke_two_records() {
        let name1 = b"_func_a\x00";
        let mut p1: Vec<u8> = Vec::new();
        p1.extend_from_slice(&0x2u32.to_le_bytes());
        p1.extend_from_slice(&0x1000u32.to_le_bytes());
        p1.extend_from_slice(&1u16.to_le_bytes());
        p1.extend_from_slice(name1);
        let len1 = u16::try_from(2 + p1.len()).unwrap();
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&len1.to_le_bytes());
        stream.extend_from_slice(&S_PUB32.to_le_bytes());
        stream.extend_from_slice(&p1);
        while !stream.len().is_multiple_of(4) { stream.push(0); }

        let name2 = b"_data_b\x00";
        let mut p2: Vec<u8> = Vec::new();
        p2.extend_from_slice(&0u32.to_le_bytes());
        p2.extend_from_slice(&0x2000u32.to_le_bytes());
        p2.extend_from_slice(&2u16.to_le_bytes());
        p2.extend_from_slice(name2);
        let len2 = u16::try_from(2 + p2.len()).unwrap();
        stream.extend_from_slice(&len2.to_le_bytes());
        stream.extend_from_slice(&S_PUB32.to_le_bytes());
        stream.extend_from_slice(&p2);
        while !stream.len().is_multiple_of(4) { stream.push(0); }

        let syms = PdbPublicSymbolScanner::parse_pub_stream_at(&stream, 0);
        assert_eq!(syms.len(), 2, "expected exactly 2 S_PUB32 symbols");
        assert_eq!(syms[0].name, "_func_a");
        assert_eq!(syms[0].offset, 0x1000);
        assert_eq!(syms[0].section, 1);
        assert_eq!(syms[1].name, "_data_b");
        assert_eq!(syms[1].offset, 0x2000);
        assert_eq!(syms[1].section, 2);
    }

    #[test]
    fn test_public_symbol_scanner_parses_pub32_record() {
        // Build a minimal S_PUB32 record stream (no real PDB container — just
        // verify the inner parser works when called directly).
        let name = b"my_export\x00";
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&0x2u32.to_le_bytes()); // flags (function bit)
        payload.extend_from_slice(&0x4000u32.to_le_bytes()); // offset
        payload.extend_from_slice(&2u16.to_le_bytes()); // section
        payload.extend_from_slice(name);

        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&length.to_le_bytes());
        stream.extend_from_slice(&S_PUB32.to_le_bytes());
        stream.extend_from_slice(&payload);
        while !stream.len().is_multiple_of(4) {
            stream.push(0);
        }

        let syms = PdbPublicSymbolScanner::parse_pub_stream_at(&stream, 0);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "my_export");
        assert_eq!(syms[0].offset, 0x4000);
        assert_eq!(syms[0].section, 2);
    }
}
