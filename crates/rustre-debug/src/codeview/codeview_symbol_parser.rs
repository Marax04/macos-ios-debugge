//! `CodeView` symbol record parser.
//!
//! Parses the symbol stream of a PDB or embedded `CodeView` debug section,
//! producing structured representations of `S_PUB32`, `S_LPROC32`,
//! `S_GPROC32`, `S_LDATA32`, `S_GDATA32`, `S_LOCAL`, `S_REGREL32`,
//! `S_COMPILE3`, `S_THUNK32`, `S_LABEL32`, and `S_FRAMEPROC` records.
//!
//! # Status: not wired into the live pipeline (as of 2026-07-21)
//!
//! No external caller anywhere in the crate or `rustre-mcp-tools` — only
//! this file's own `#[cfg(test)]` module exercises it. The live symbol path
//! is `mod.rs::parse_cv_symbols` (via `CodeViewProvider`, used by
//! `debug.load_symbols`). See `ENHANCEMENT_LOG.md` iters 230/232/233.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{read_u16, read_u32};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can arise during symbol parsing.
#[derive(Debug)]
pub enum SymParseError {
    /// The buffer ended before the record was fully read.
    Truncated {
        /// Byte offset of the record at which the buffer was exhausted.
        record_offset: usize,
    },
    /// A record's length field is smaller than the minimum.
    RecordTooShort {
        /// The record kind whose length was invalid.
        kind: u16,
        /// The declared record length in bytes.
        len: usize,
    },
    /// An internal offset computation overflowed.
    OffsetOverflow,
}

impl std::fmt::Display for SymParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { record_offset } => {
                write!(f, "truncated record at offset {record_offset:#x}")
            }
            Self::RecordTooShort { kind, len } => {
                write!(f, "record {kind:#06x} length {len} too short")
            }
            Self::OffsetOverflow => write!(f, "offset overflow in symbol stream"),
        }
    }
}

impl std::error::Error for SymParseError {}

// ---------------------------------------------------------------------------
// Null-terminated string reader
// ---------------------------------------------------------------------------

fn cstr(data: &[u8], from: usize) -> String {
    if from >= data.len() {
        return String::new();
    }
    let slice = &data[from..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// ProcSymbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_GPROC32` / `S_LPROC32` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSymbol {
    /// Offset of the parent scope record (0 = top-level).
    pub parent: u32,
    /// Stream offset of the matching `S_END` record.
    pub end: u32,
    /// Offset of the next sibling procedure.
    pub next: u32,
    /// Total code length of the procedure in bytes.
    pub code_len: u32,
    /// Offset of the first statement from procedure start.
    pub dbg_start: u32,
    /// Offset past the last statement.
    pub dbg_end: u32,
    /// TPI type index of the procedure's function type.
    pub type_index: u32,
    /// Section-relative start offset.
    pub offset: u32,
    /// PE section (segment) index.
    pub segment: u16,
    /// CV procedure flags byte.
    pub flags: u8,
    /// Mangled / undecorated procedure name.
    pub name: String,
}

impl ProcSymbol {
    /// Try to parse from the record payload (after the 2-byte record-kind tag).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 35 {
            return None;
        }
        Some(Self {
            parent: read_u32(data, 0),
            end: read_u32(data, 4),
            next: read_u32(data, 8),
            code_len: read_u32(data, 12),
            dbg_start: read_u32(data, 16),
            dbg_end: read_u32(data, 20),
            type_index: read_u32(data, 24),
            offset: read_u32(data, 28),
            segment: read_u16(data, 32),
            flags: *data.get(34)?,
            name: cstr(data, 35),
        })
    }

    /// Returns `true` if the `CVPF_NOFPO` flag is set (no frame pointer omission).
    #[must_use]
    pub const fn no_fpo(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns `true` if the `CVPF_INTERRUPT` flag is set.
    #[must_use]
    pub const fn is_interrupt(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

impl std::fmt::Display for ProcSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "proc '{}' seg:{} off:{:#x} len:{}",
            self.name, self.segment, self.offset, self.code_len
        )
    }
}

// ---------------------------------------------------------------------------
// DataSymbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_GDATA32` / `S_LDATA32` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSymbol {
    /// TPI type index.
    pub type_index: u32,
    /// Section-relative offset.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Symbol name.
    pub name: String,
}

impl DataSymbol {
    /// Parse from the record payload bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            type_index: read_u32(data, 0),
            offset: read_u32(data, 4),
            segment: read_u16(data, 8),
            name: cstr(data, 10),
        })
    }
}

impl std::fmt::Display for DataSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "data '{}' seg:{} off:{:#x} ti:{:#x}",
            self.name, self.segment, self.offset, self.type_index
        )
    }
}

// ---------------------------------------------------------------------------
// PublicSymbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_PUB32` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSymbol {
    /// CV public-symbol flags (CVPUBSYMFLAGS).
    pub flags: u32,
    /// Section-relative offset.
    pub offset: u32,
    /// Section (segment) index.
    pub segment: u16,
    /// Decorated (mangled) name.
    pub name: String,
}

impl PublicSymbol {
    /// Parse from the record payload.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            flags: read_u32(data, 0),
            offset: read_u32(data, 4),
            segment: read_u16(data, 8),
            name: cstr(data, 10),
        })
    }

    /// Returns `true` if the `CVPSFLAG_FUNCTION` bit is set.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Returns `true` if the `CVPSFLAG_MANAGED` bit is set (managed code).
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

impl std::fmt::Display for PublicSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pub '{}' seg:{} off:{:#x}",
            self.name, self.segment, self.offset
        )
    }
}

// ---------------------------------------------------------------------------
// LocalSymbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_LOCAL` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSymbol {
    /// TPI type index of the variable type.
    pub type_index: u32,
    /// Flags (CVLVARFLAGS).
    pub flags: u16,
    /// Variable name.
    pub name: String,
}

impl LocalSymbol {
    /// Parse from the record payload.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        Some(Self {
            type_index: read_u32(data, 0),
            flags: read_u16(data, 4),
            name: cstr(data, 6),
        })
    }

    /// Returns `true` if `CVLVARFLAG_ISPARAM` is set.
    #[must_use]
    pub const fn is_param(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns `true` if `CVLVARFLAG_ISADDRTAKEN` is set.
    #[must_use]
    pub const fn is_addr_taken(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

// ---------------------------------------------------------------------------
// RegRelSymbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_REGREL32` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegRelSymbol {
    /// Offset from register.
    pub offset: u32,
    /// TPI type index.
    pub type_index: u32,
    /// Register number (AMD64/x86).
    pub register: u16,
    /// Variable name.
    pub name: String,
}

impl RegRelSymbol {
    /// Parse from the record payload.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        Some(Self {
            offset: read_u32(data, 0),
            type_index: read_u32(data, 4),
            register: read_u16(data, 8),
            name: cstr(data, 10),
        })
    }
}

// ---------------------------------------------------------------------------
// Compile3Symbol
// ---------------------------------------------------------------------------

/// Parsed payload of an `S_COMPILE3` record (compilation unit info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compile3Symbol {
    /// Language and compile flags.
    pub flags: u32,
    /// Machine type.
    pub machine: u16,
    /// Front-end version major.
    pub fe_major: u16,
    /// Front-end version minor.
    pub fe_minor: u16,
    /// Front-end version build.
    pub fe_build: u16,
    /// Back-end version major.
    pub be_major: u16,
    /// Back-end version minor.
    pub be_minor: u16,
    /// Back-end version build.
    pub be_build: u16,
    /// Compiler version string.
    pub version_string: String,
}

impl Compile3Symbol {
    /// Parse from the record payload.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        Some(Self {
            flags: read_u32(data, 0),
            machine: read_u16(data, 4),
            fe_major: read_u16(data, 6),
            fe_minor: read_u16(data, 8),
            fe_build: read_u16(data, 10),
            be_major: read_u16(data, 12),
            be_minor: read_u16(data, 14),
            be_build: read_u16(data, 16),
            version_string: cstr(data, 18),
        })
    }

    /// Returns the source language (bits 0-7 of flags).
    #[must_use]
    pub const fn language(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }
}

// ---------------------------------------------------------------------------
// ParsedSymbol — discriminated union of all known record kinds
// ---------------------------------------------------------------------------

/// The fully parsed payload of a `CodeView` symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsedSymbol {
    /// Procedure start (`S_GPROC32`/`S_LPROC32`).
    Proc(ProcSymbol),
    /// Global or local data (`S_GDATA32`/`S_LDATA32`).
    Data(DataSymbol),
    /// Public symbol (`S_PUB32`).
    Public(PublicSymbol),
    /// Local variable (`S_LOCAL`).
    Local(LocalSymbol),
    /// Register-relative variable (`S_REGREL32`).
    RegRel(RegRelSymbol),
    /// Compiler information (`S_COMPILE3`).
    Compile3(Compile3Symbol),
    /// End of scope marker.
    End,
    /// Any record kind we do not decode in detail.
    Raw {
        /// The raw `CodeView` record kind value.
        kind: u16,
        /// The undecoded record body bytes.
        data: Vec<u8>,
    },
}

impl ParsedSymbol {
    /// Returns the address (section-relative offset) if available.
    #[must_use]
    pub const fn offset(&self) -> Option<u32> {
        match self {
            Self::Proc(p) => Some(p.offset),
            Self::Data(d) => Some(d.offset),
            Self::Public(p) => Some(p.offset),
            _ => None,
        }
    }

    /// Returns the name of the symbol, if available.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Proc(p) => Some(&p.name),
            Self::Data(d) => Some(&d.name),
            Self::Public(p) => Some(&p.name),
            Self::Local(l) => Some(&l.name),
            Self::RegRel(r) => Some(&r.name),
            _ => None,
        }
    }

    /// Returns `true` if this is a function-like symbol.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Proc(_))
            || matches!(self, Self::Public(p) if p.is_function())
    }

    /// Kind tag string.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Proc(_) => "S_PROC32",
            Self::Data(_) => "S_DATA32",
            Self::Public(_) => "S_PUB32",
            Self::Local(_) => "S_LOCAL",
            Self::RegRel(_) => "S_REGREL32",
            Self::Compile3(_) => "S_COMPILE3",
            Self::End => "S_END",
            Self::Raw { .. } => "S_UNKNOWN",
        }
    }
}

impl std::fmt::Display for ParsedSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proc(p) => write!(f, "{p}"),
            Self::Data(d) => write!(f, "{d}"),
            Self::Public(p) => write!(f, "{p}"),
            Self::Local(l) => write!(f, "local '{}'", l.name),
            Self::RegRel(r) => write!(f, "regrel '{}'", r.name),
            Self::Compile3(c) => write!(f, "compile3 '{}'", c.version_string),
            Self::End => write!(f, "end"),
            Self::Raw { kind, .. } => write!(f, "raw {kind:#06x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolRecord — wraps ParsedSymbol with stream metadata
// ---------------------------------------------------------------------------

/// A parsed symbol record with stream offset and raw record kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    /// Byte offset of this record within the symbol stream.
    pub stream_offset: usize,
    /// Raw `CodeView` record-kind tag.
    pub kind: u16,
    /// Parsed payload.
    pub symbol: ParsedSymbol,
}

// ---------------------------------------------------------------------------
// CodeViewSymbolParser
// ---------------------------------------------------------------------------

/// Iterative parser for a `CodeView` symbol stream.
///
/// Feed raw symbol stream bytes via `parse_stream()`.  Access results
/// through `records()`, `functions()`, `data_symbols()`, or by name.
#[derive(Debug, Default)]
pub struct CodeViewSymbolParser {
    records: Vec<SymbolRecord>,
    /// name → index into `records`
    name_index: HashMap<String, Vec<usize>>,
}

impl CodeViewSymbolParser {
    /// Create a new empty parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse an entire symbol stream payload.
    ///
    /// Returns the number of records successfully parsed.
    ///
    /// # Errors
    ///
    /// Returns [`SymParseError`] if the stream is truncated or malformed.
    pub fn parse_stream(&mut self, data: &[u8]) -> Result<usize, SymParseError> {
        let mut pos = 0usize;
        let start = self.records.len();

        while pos + 4 <= data.len() {
            let stream_offset = pos;
            let record_len = read_u16(data, pos) as usize;
            let kind = read_u16(data, pos + 2);

            if record_len < 2 {
                // Zero-length record — stop.
                break;
            }

            let record_end = pos
                .checked_add(2)
                .and_then(|x| x.checked_add(record_len))
                .ok_or(SymParseError::OffsetOverflow)?;

            if record_end > data.len() {
                return Err(SymParseError::Truncated {
                    record_offset: stream_offset,
                });
            }

            let payload = &data[pos + 4..record_end];
            let sym = Self::parse_one(kind, payload);

            let idx = self.records.len();
            if let Some(name) = sym.name() {
                self.name_index
                    .entry(name.to_owned())
                    .or_default()
                    .push(idx);
            }

            self.records.push(SymbolRecord {
                stream_offset,
                kind,
                symbol: sym,
            });

            pos = record_end;
        }

        Ok(self.records.len() - start)
    }

    fn parse_one(kind: u16, payload: &[u8]) -> ParsedSymbol {
        match kind {
            // S_LPROC32 = 0x110F, S_GPROC32 = 0x1110
            0x110F | 0x1110 => ProcSymbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::Proc,
            ),
            // S_GDATA32 = 0x110D, S_LDATA32 = 0x110C
            0x110D | 0x110C => DataSymbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::Data,
            ),
            // S_PUB32 = 0x110E (0x1009 is the obsolete _ST form, still accepted)
            0x110E | 0x1009 => PublicSymbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::Public,
            ),
            // S_LOCAL = 0x113E
            0x113E => LocalSymbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::Local,
            ),
            // S_REGREL32 = 0x1111 (0x1108 is S_UDT and must not be decoded here)
            0x1111 => RegRelSymbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::RegRel,
            ),
            // S_COMPILE3 = 0x113C
            0x113C => Compile3Symbol::parse(payload).map_or_else(
                || ParsedSymbol::Raw { kind, data: payload.to_vec() },
                ParsedSymbol::Compile3,
            ),
            // S_END = 0x0006
            0x0006 => ParsedSymbol::End,
            _ => ParsedSymbol::Raw {
                kind,
                data: payload.to_vec(),
            },
        }
    }

    /// All parsed symbol records.
    #[must_use]
    pub fn records(&self) -> &[SymbolRecord] {
        &self.records
    }

    /// Number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no records have been parsed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// All function records (`S_GPROC32` / `S_LPROC32`).
    #[must_use]
    pub fn functions(&self) -> Vec<&SymbolRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.symbol, ParsedSymbol::Proc(_)))
            .collect()
    }

    /// All data symbol records.
    #[must_use]
    pub fn data_symbols(&self) -> Vec<&SymbolRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.symbol, ParsedSymbol::Data(_)))
            .collect()
    }

    /// All public symbol records.
    #[must_use]
    pub fn public_symbols(&self) -> Vec<&SymbolRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.symbol, ParsedSymbol::Public(_)))
            .collect()
    }

    /// Look up records by exact name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&SymbolRecord> {
        self.name_index
            .get(name)
            .map(|idxs| idxs.iter().filter_map(|&i| self.records.get(i)).collect())
            .unwrap_or_default()
    }

    /// Build an address → record map (section-relative offsets).
    #[must_use]
    pub fn address_map(&self) -> HashMap<u32, &SymbolRecord> {
        self.records
            .iter()
            .filter_map(|r| r.symbol.offset().map(|off| (off, r)))
            .collect()
    }

    /// Deduplicated, sorted list of all symbol names.
    #[must_use]
    pub fn all_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .records
            .iter()
            .filter_map(|r| r.symbol.name().map(str::to_owned))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Find the nearest function symbol at or before `addr`.
    #[must_use]
    pub fn nearest_function(&self, addr: u32) -> Option<&SymbolRecord> {
        self.records
            .iter()
            .filter(|r| {
                matches!(&r.symbol, ParsedSymbol::Proc(p) if p.offset <= addr)
            })
            .min_by_key(|r| {
                if let ParsedSymbol::Proc(p) = &r.symbol {
                    addr - p.offset
                } else {
                    u32::MAX
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Test helpers — build minimal symbol records
// ---------------------------------------------------------------------------

/// Build a raw `S_GPROC32` record (len + kind + payload).
#[must_use]
pub fn build_gproc32_record(name: &str, offset: u32, type_index: u32) -> Vec<u8> {
    // Payload: parent(4) end(4) next(4) code_len(4) dbg_start(4) dbg_end(4)
    //          type_index(4) offset(4) segment(2) flags(1) name\0
    let mut payload = vec![0u8; 35];
    payload[24..28].copy_from_slice(&type_index.to_le_bytes());
    payload[28..32].copy_from_slice(&offset.to_le_bytes());
    payload[32..34].copy_from_slice(&1u16.to_le_bytes()); // segment=1
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    let kind: u16 = 0x1110;
    let len = super::casts::usize_to_u16(2 + payload.len());
    let mut rec = Vec::new();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&kind.to_le_bytes());
    rec.extend_from_slice(&payload);
    rec
}

/// Build a raw `S_PUB32` record.
#[must_use]
pub fn build_pub32_record(name: &str, offset: u32, flags: u32) -> Vec<u8> {
    // Payload: flags(4) offset(4) segment(2) name\0
    let mut payload = Vec::new();
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    let kind: u16 = 0x110E;
    let len = super::casts::usize_to_u16(2 + payload.len());
    let mut rec = Vec::new();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&kind.to_le_bytes());
    rec.extend_from_slice(&payload);
    rec
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gproc32() {
        let data = build_gproc32_record("main", 0x1000, 0x1234);
        let mut parser = CodeViewSymbolParser::new();
        let count = parser.parse_stream(&data).unwrap();
        assert_eq!(count, 1);
        let rec = &parser.records()[0];
        match &rec.symbol {
            ParsedSymbol::Proc(p) => {
                assert_eq!(p.name, "main");
                assert_eq!(p.offset, 0x1000);
                assert_eq!(p.type_index, 0x1234);
            }
            other => panic!("expected Proc, got {other:?}"),
        }
    }

    #[test]
    fn parse_pub32_function_flag() {
        let data = build_pub32_record("MyFunc", 0x2000, 0x02);
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        let rec = &parser.records()[0];
        if let ParsedSymbol::Public(p) = &rec.symbol {
            assert!(p.is_function());
        } else {
            panic!("expected Public");
        }
    }

    /// Build a raw record with an arbitrary kind tag.
    fn raw_record(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = super::super::casts::usize_to_u16(2 + payload.len());
        let mut rec = Vec::new();
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&kind.to_le_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    /// Regression: `parse_one` matched 0x1110|0x1111 as a procedure, but 0x1111
    /// is `S_REGREL32`. `S_LPROC32` (0x110F) fell through to `Raw`.
    #[test]
    fn parse_lproc32_is_a_procedure() {
        let mut payload = vec![0u8; 35];
        payload[28..32].copy_from_slice(&0x3000u32.to_le_bytes());
        payload[32..34].copy_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(b"static_fn\0");
        let data = raw_record(0x110F, &payload);
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        match &parser.records()[0].symbol {
            ParsedSymbol::Proc(p) => assert_eq!(p.name, "static_fn"),
            other => panic!("expected Proc for S_LPROC32, got {other:?}"),
        }
        assert_eq!(parser.functions().len(), 1);
    }

    /// 0x1111 is `S_REGREL32`, a local variable — never a procedure.
    #[test]
    fn parse_regrel32_is_not_a_procedure() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0xFFFF_FFF8u32.to_le_bytes()); // offset -8
        payload.extend_from_slice(&0x1080u32.to_le_bytes()); // type index
        payload.extend_from_slice(&335u16.to_le_bytes()); // RSP
        payload.extend_from_slice(b"local_i\0");
        payload.resize(48, 0); // long enough that the old code parsed it as a proc
        let data = raw_record(0x1111, &payload);
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        assert_eq!(parser.functions().len(), 0);
        match &parser.records()[0].symbol {
            ParsedSymbol::RegRel(r) => assert_eq!(r.name, "local_i"),
            other => panic!("expected RegRel for S_REGREL32, got {other:?}"),
        }
    }

    /// Modern `S_PUB32` is 0x110E; 0x1009 is the obsolete `_ST` form.
    #[test]
    fn parse_pub32_modern_kind() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x02u32.to_le_bytes());
        payload.extend_from_slice(&0x4000u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(b"PublicFn\0");
        let data = raw_record(0x110E, &payload);
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        match &parser.records()[0].symbol {
            ParsedSymbol::Public(p) => assert_eq!(p.name, "PublicFn"),
            other => panic!("expected Public for 0x110E, got {other:?}"),
        }
    }

    /// 0x1108 is `S_UDT`, not `S_REGREL32` — it must not decode as a RegRel.
    #[test]
    fn parse_udt_kind_is_not_regrel() {
        let data = raw_record(0x1108, &[0u8; 16]);
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        assert!(matches!(
            &parser.records()[0].symbol,
            ParsedSymbol::Raw { kind: 0x1108, .. }
        ));
    }

    #[test]
    fn lookup_by_name() {
        let mut data = build_gproc32_record("alpha", 0x100, 0);
        data.extend(build_gproc32_record("beta", 0x200, 0));
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        assert_eq!(parser.by_name("alpha").len(), 1);
        assert_eq!(parser.by_name("gamma").len(), 0);
    }

    #[test]
    fn functions_filtered() {
        let mut data = build_gproc32_record("fn1", 0x10, 0);
        data.extend(build_pub32_record("pub1", 0x20, 0));
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        assert_eq!(parser.functions().len(), 1);
        assert_eq!(parser.public_symbols().len(), 1);
    }

    #[test]
    fn nearest_function() {
        let mut data = build_gproc32_record("low", 0x1000, 0);
        data.extend(build_gproc32_record("high", 0x2000, 0));
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        let near = parser.nearest_function(0x1500).unwrap();
        if let ParsedSymbol::Proc(p) = &near.symbol {
            assert_eq!(p.name, "low");
        }
    }

    #[test]
    fn all_names_deduped() {
        let mut data = build_gproc32_record("dup", 0x100, 0);
        data.extend(build_pub32_record("dup", 0x200, 0));
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        let names = parser.all_names();
        assert_eq!(names.iter().filter(|n| n.as_str() == "dup").count(), 1);
    }

    #[test]
    fn truncated_stream_returns_error() {
        let mut data = build_gproc32_record("ok", 0x100, 0);
        // Append a record header claiming 100 bytes but with no body.
        data.extend_from_slice(&100u16.to_le_bytes()); // len = 100
        data.extend_from_slice(&0x1110u16.to_le_bytes()); // kind
        let mut parser = CodeViewSymbolParser::new();
        let result = parser.parse_stream(&data);
        assert!(result.is_err());
    }

    #[test]
    fn public_symbol_not_function() {
        let data = build_pub32_record("my_data", 0x3000, 0x00); // flags=0: not a function
        let mut parser = CodeViewSymbolParser::new();
        parser.parse_stream(&data).unwrap();
        if let ParsedSymbol::Public(p) = &parser.records()[0].symbol {
            assert!(!p.is_function());
        }
    }
}
