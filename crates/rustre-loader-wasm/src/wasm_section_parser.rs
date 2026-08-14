//! WebAssembly section parser.
//!
//! Provides a section-level reader that iterates over the raw sections of a
//! WebAssembly binary without performing deep per-section decoding.  Each
//! section is represented as a [`WasmSection`] that carries its [`SectionKind`]
//! and the raw payload bytes, which can be handed to specialised decoders.
//!
//! This module is complementary to the full `WasmParser` in `lib.rs`; it is
//! useful when you need streaming access to sections or want to inspect only
//! a subset of them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Leb128Decoder, WasmError, WASM_MAGIC, WASM_VERSION, MAX_SECTION_SIZE};

// ---------------------------------------------------------------------------
// SectionKind
// ---------------------------------------------------------------------------

/// The kind of a WebAssembly section, as specified by its section ID byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SectionKind {
    /// Custom section (id = 0). Name is stored separately in `WasmSection`.
    Custom,
    /// Type section (id = 1): function type signatures.
    Type,
    /// Import section (id = 2): external imports.
    Import,
    /// Function section (id = 3): type-index list for defined functions.
    Function,
    /// Table section (id = 4): table declarations.
    Table,
    /// Memory section (id = 5): linear memory declarations.
    Memory,
    /// Global section (id = 6): global variable declarations.
    Global,
    /// Export section (id = 7): exported entities.
    Export,
    /// Start section (id = 8): optional entry-point function index.
    Start,
    /// Element section (id = 9): table element segments.
    Element,
    /// Code section (id = 10): function bodies.
    Code,
    /// Data section (id = 11): linear memory initialisation.
    Data,
    /// `DataCount` section (id = 12): bulk-memory proposal.
    DataCount,
    /// Unknown section ID — forward-compatibility placeholder.
    Unknown(u8),
}

impl SectionKind {
    /// Parse from a raw section ID byte.
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            0 => Self::Custom,
            1 => Self::Type,
            2 => Self::Import,
            3 => Self::Function,
            4 => Self::Table,
            5 => Self::Memory,
            6 => Self::Global,
            7 => Self::Export,
            8 => Self::Start,
            9 => Self::Element,
            10 => Self::Code,
            11 => Self::Data,
            12 => Self::DataCount,
            other => Self::Unknown(other),
        }
    }

    /// Return the numeric section ID.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Custom => 0,
            Self::Type => 1,
            Self::Import => 2,
            Self::Function => 3,
            Self::Table => 4,
            Self::Memory => 5,
            Self::Global => 6,
            Self::Export => 7,
            Self::Start => 8,
            Self::Element => 9,
            Self::Code => 10,
            Self::Data => 11,
            Self::DataCount => 12,
            Self::Unknown(id) => id,
        }
    }

    /// Human-readable name of the section.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Custom => "custom",
            Self::Type => "type",
            Self::Import => "import",
            Self::Function => "function",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Export => "export",
            Self::Start => "start",
            Self::Element => "element",
            Self::Code => "code",
            Self::Data => "data",
            Self::DataCount => "datacount",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether this section kind is known (i.e. not [`SectionKind::Unknown`]).
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for SectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "unknown({id})"),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmSection
// ---------------------------------------------------------------------------

/// A single parsed section from a WebAssembly binary.
#[derive(Debug, Clone)]
pub struct WasmSection {
    /// The kind of this section.
    pub kind: SectionKind,
    /// For custom sections (id = 0), the UTF-8 name from the payload header.
    pub custom_name: Option<String>,
    /// The raw section payload bytes (after the section header and, for custom
    /// sections, after the name).
    pub payload: Vec<u8>,
    /// Byte offset of this section's payload in the original binary.
    pub payload_offset: usize,
    /// Full byte offset of the section ID byte in the original binary.
    pub section_offset: usize,
    /// Total byte size of the section (id byte + length LEB128 + payload).
    pub total_size: usize,
}

impl WasmSection {
    /// Return `true` if this is a custom section named `name`.
    #[must_use]
    pub fn is_custom_named(&self, name: &str) -> bool {
        self.kind == SectionKind::Custom
            && self.custom_name.as_deref() == Some(name)
    }

    /// Return `true` if this is a DWARF debug section (custom, name starts with `.debug_`).
    #[must_use]
    pub fn is_dwarf(&self) -> bool {
        self.kind == SectionKind::Custom
            && self
                .custom_name
                .as_deref()
                .is_some_and(|n| n.starts_with(".debug_"))
    }

    /// Return the payload as a `Leb128Decoder`.
    #[must_use]
    pub fn decoder(&self) -> Leb128Decoder<'_> {
        Leb128Decoder::new(&self.payload)
    }

    /// Return `true` if the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Return the payload length in bytes.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

impl fmt::Display for WasmSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.custom_name {
            write!(
                f,
                "{}(\"{}\") @0x{:x} payload={}B",
                self.kind, name, self.payload_offset, self.payload.len()
            )
        } else {
            write!(
                f,
                "{} @0x{:x} payload={}B",
                self.kind, self.payload_offset, self.payload.len()
            )
        }
    }
}

// ---------------------------------------------------------------------------
// WasmSectionParser
// ---------------------------------------------------------------------------

/// A streaming section-level parser for WebAssembly binaries.
///
/// Unlike `WasmParser` (which deep-decodes every section), `WasmSectionParser`
/// only splits the binary into its top-level sections and returns each one with
/// its raw payload.  This is useful for:
/// - Inspecting a single section without paying the cost of full decoding.
/// - Writing custom section processors.
/// - Forward-compatible handling of future / proposal section IDs.
pub struct WasmSectionParser;

impl WasmSectionParser {
    /// Parse all sections from a WebAssembly binary.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if the binary is malformed.
    pub fn parse_all(bytes: &[u8]) -> Result<Vec<WasmSection>, WasmError> {
        let mut out = Vec::new();
        let mut iter = Self::iter(bytes)?;
        while let Some(sec) = iter.next_section()? {
            out.push(sec);
        }
        Ok(out)
    }

    /// Create an iterator-style parser over the sections of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] if the magic or version header is invalid.
    pub fn iter(bytes: &[u8]) -> Result<SectionIterator<'_>, WasmError> {
        if bytes.len() < 8 {
            return Err(WasmError::InvalidMagic);
        }
        if bytes[0..4] != WASM_MAGIC {
            return Err(WasmError::InvalidMagic);
        }
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != WASM_VERSION {
            return Err(WasmError::UnsupportedVersion(version));
        }
        Ok(SectionIterator {
            bytes,
            cursor: 8,
        })
    }

    /// Return the count of sections in `bytes` by kind.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed binary.
    pub fn section_counts(bytes: &[u8]) -> Result<std::collections::HashMap<SectionKind, usize>, WasmError> {
        let mut counts = std::collections::HashMap::new();
        for sec in Self::parse_all(bytes)? {
            *counts.entry(sec.kind).or_insert(0) += 1;
        }
        Ok(counts)
    }

    /// Return the first section of the given `kind`, if present.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed binary.
    pub fn find_section(bytes: &[u8], kind: SectionKind) -> Result<Option<WasmSection>, WasmError> {
        for sec in Self::parse_all(bytes)? {
            if sec.kind == kind {
                return Ok(Some(sec));
            }
        }
        Ok(None)
    }

    /// Return all custom sections with the given name.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed binary.
    pub fn find_custom(bytes: &[u8], name: &str) -> Result<Vec<WasmSection>, WasmError> {
        Ok(Self::parse_all(bytes)?
            .into_iter()
            .filter(|s| s.is_custom_named(name))
            .collect())
    }

    /// Validate that there are no duplicate standard sections (section ids 1–11
    /// must appear at most once each).
    ///
    /// Returns a list of duplicate section kinds found.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed binary.
    pub fn check_duplicates(bytes: &[u8]) -> Result<Vec<SectionKind>, WasmError> {
        let counts = Self::section_counts(bytes)?;
        let mut dupes = Vec::new();
        for kind in [
            SectionKind::Type,
            SectionKind::Import,
            SectionKind::Function,
            SectionKind::Table,
            SectionKind::Memory,
            SectionKind::Global,
            SectionKind::Export,
            SectionKind::Start,
            SectionKind::Element,
            SectionKind::Code,
            SectionKind::Data,
        ] {
            if counts.get(&kind).copied().unwrap_or(0) > 1 {
                dupes.push(kind);
            }
        }
        Ok(dupes)
    }

    /// Return a summary of the sections present in a binary.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed binary.
    pub fn summary(bytes: &[u8]) -> Result<SectionSummary, WasmError> {
        let sections = Self::parse_all(bytes)?;
        Ok(SectionSummary::from_sections(&sections))
    }
}

// ---------------------------------------------------------------------------
// SectionIterator
// ---------------------------------------------------------------------------

/// A streaming iterator over sections of a WebAssembly binary.
pub struct SectionIterator<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl SectionIterator<'_> {
    /// Read the next section, or `Ok(None)` if all bytes have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn next_section(&mut self) -> Result<Option<WasmSection>, WasmError> {
        if self.cursor >= self.bytes.len() {
            return Ok(None);
        }

        let section_offset = self.cursor;
        let id_byte = self.bytes[self.cursor];
        self.cursor += 1;

        // LEB128 section length.
        let (payload_size, consumed) = decode_u32_at(self.bytes, self.cursor)?;
        self.cursor += consumed;

        if payload_size > MAX_SECTION_SIZE {
            return Err(WasmError::SectionTooLarge(payload_size));
        }
        let payload_end = self.cursor
            .checked_add(payload_size as usize)
            .ok_or(WasmError::UnexpectedEof(self.cursor))?;
        if payload_end > self.bytes.len() {
            return Err(WasmError::UnexpectedEof(self.cursor));
        }

        let kind = SectionKind::from_id(id_byte);
        let payload_start = self.cursor;

        // For custom sections, strip the name prefix.
        let (custom_name, real_payload_start) = if kind == SectionKind::Custom {
            let mut dec = Leb128Decoder::new(&self.bytes[payload_start..payload_end]);
            let name = dec.read_name()?;
            (Some(name), payload_start + dec.offset())
        } else {
            (None, payload_start)
        };

        let payload = self.bytes[real_payload_start..payload_end].to_vec();
        let total_size = payload_end - section_offset;
        self.cursor = payload_end;

        Ok(Some(WasmSection {
            kind,
            custom_name,
            payload,
            payload_offset: real_payload_start,
            section_offset,
            total_size,
        }))
    }

    /// Return the current byte cursor position within the binary.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Return `true` if all sections have been consumed.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.cursor >= self.bytes.len()
    }
}

// ---------------------------------------------------------------------------
// SectionSummary
// ---------------------------------------------------------------------------

/// A human-readable summary of the sections found in a binary.
#[derive(Debug, Clone, Default)]
pub struct SectionSummary {
    pub section_count: usize,
    pub type_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub function_count: usize,
    pub code_count: usize,
    pub data_count: usize,
    pub custom_names: Vec<String>,
    pub total_payload_bytes: usize,
}

impl SectionSummary {
    /// Compute from a slice of parsed sections.
    #[must_use]
    pub fn from_sections(sections: &[WasmSection]) -> Self {
        let mut s = Self::default();
        for sec in sections {
            s.section_count += 1;
            s.total_payload_bytes += sec.payload.len();
            match sec.kind {
                SectionKind::Type => s.type_count += 1,
                SectionKind::Import => s.import_count += 1,
                SectionKind::Export => s.export_count += 1,
                SectionKind::Function => s.function_count += 1,
                SectionKind::Code => s.code_count += 1,
                SectionKind::Data => s.data_count += 1,
                SectionKind::Custom => {
                    if let Some(ref n) = sec.custom_name {
                        s.custom_names.push(n.clone());
                    }
                }
                _ => {}
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode a u32 LEB128 at `offset` in `data`.
fn decode_u32_at(data: &[u8], offset: usize) -> Result<(u32, usize), WasmError> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = offset;
    loop {
        if i >= data.len() {
            return Err(WasmError::UnexpectedEof(i));
        }
        let byte = data[i];
        i += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return Err(WasmError::Leb128Error(i));
        }
    }
    Ok((result, i - offset))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid WASM binary: magic + version + type section with 0 entries.
    fn minimal_wasm() -> Vec<u8> {
        let mut v = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // Type section (id=1), length=1, 0 entries.
        v.push(0x01); // section id
        v.push(0x01); // section length (LEB128)
        v.push(0x00); // count = 0
        v
    }

    fn wasm_with_custom(name: &str, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // Custom section.
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() as u8;
        let payload_len = 1 + name_len as usize + data.len();
        v.push(0x00);
        v.push(payload_len as u8);
        v.push(name_len);
        v.extend_from_slice(name_bytes);
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn test_parse_minimal() {
        let sections = WasmSectionParser::parse_all(&minimal_wasm()).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, SectionKind::Type);
    }

    #[test]
    fn test_invalid_magic() {
        let bad = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = WasmSectionParser::parse_all(&bad).unwrap_err();
        assert!(matches!(err, WasmError::InvalidMagic));
    }

    #[test]
    fn test_unsupported_version() {
        let mut bad = vec![0x00, 0x61, 0x73, 0x6D];
        bad.extend_from_slice(&2u32.to_le_bytes());
        let err = WasmSectionParser::parse_all(&bad).unwrap_err();
        assert!(matches!(err, WasmError::UnsupportedVersion(2)));
    }

    #[test]
    fn test_custom_section_name() {
        let sections = WasmSectionParser::parse_all(&wasm_with_custom("name", &[0x00])).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, SectionKind::Custom);
        assert_eq!(sections[0].custom_name.as_deref(), Some("name"));
        assert!(sections[0].is_custom_named("name"));
    }

    #[test]
    fn test_find_section() {
        let sec = WasmSectionParser::find_section(&minimal_wasm(), SectionKind::Type)
            .unwrap()
            .unwrap();
        assert_eq!(sec.kind, SectionKind::Type);
    }

    #[test]
    fn test_find_section_missing() {
        let sec = WasmSectionParser::find_section(&minimal_wasm(), SectionKind::Code).unwrap();
        assert!(sec.is_none());
    }

    #[test]
    fn test_find_custom() {
        let bin = wasm_with_custom("name", &[]);
        let sections = WasmSectionParser::find_custom(&bin, "name").unwrap();
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn test_section_kind_roundtrip() {
        for id in 0u8..=12 {
            let kind = SectionKind::from_id(id);
            assert_eq!(kind.id(), id);
        }
    }

    #[test]
    fn test_section_kind_unknown() {
        let kind = SectionKind::from_id(99);
        assert!(matches!(kind, SectionKind::Unknown(99)));
        assert!(!kind.is_known());
    }

    #[test]
    fn test_section_kind_display() {
        assert_eq!(SectionKind::Type.to_string(), "type");
        assert_eq!(SectionKind::Custom.to_string(), "custom");
        assert_eq!(SectionKind::Unknown(42).to_string(), "unknown(42)");
    }

    #[test]
    fn test_is_dwarf() {
        let bin = wasm_with_custom(".debug_info", &[0xDE, 0xAD]);
        let sections = WasmSectionParser::parse_all(&bin).unwrap();
        assert!(sections[0].is_dwarf());
    }

    #[test]
    fn test_is_not_dwarf() {
        let bin = wasm_with_custom("producers", &[]);
        let sections = WasmSectionParser::parse_all(&bin).unwrap();
        assert!(!sections[0].is_dwarf());
    }

    #[test]
    fn test_summary() {
        let s = WasmSectionParser::summary(&minimal_wasm()).unwrap();
        assert_eq!(s.type_count, 1);
        assert_eq!(s.section_count, 1);
    }

    #[test]
    fn test_check_duplicates_none() {
        let dupes = WasmSectionParser::check_duplicates(&minimal_wasm()).unwrap();
        assert!(dupes.is_empty());
    }

    #[test]
    fn test_iterator() {
        let bytes = minimal_wasm();
        let mut iter = WasmSectionParser::iter(&bytes).unwrap();
        let sec = iter.next_section().unwrap().unwrap();
        assert_eq!(sec.kind, SectionKind::Type);
        assert!(iter.next_section().unwrap().is_none());
        assert!(iter.is_done());
    }
}
