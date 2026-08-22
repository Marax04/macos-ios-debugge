//! STABS in XCOFF (AIX) format.
//!
//! On AIX, STABS debug information is embedded inside the XCOFF (Extended COFF)
//! object format.  Unlike ELF, XCOFF stores debug strings in the symbol-table
//! `C_FILE` / `C_BINCL` / `C_EINCL` etc. entries rather than a separate `.stabstr`
//! section.  The `.debug` section contains the numeric stab records.
//!
//! This module provides:
//! * [`XcoffHeader`] — minimal XCOFF file header parser.
//! * [`XcoffSectionHeader`] — section header record.
//! * [`XcoffSymbolEntry`] — symbol table entry (18 bytes each).
//! * [`XcoffStabsExtractor`] — extracts `(stab_records, string_table)` from an XCOFF blob.
//! * AIX-specific type extensions (long double, complex, vectors).

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from XCOFF parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XcoffError {
    /// The file does not start with an XCOFF magic number.
    BadMagic,
    /// The file is shorter than a required structure.
    Truncated,
    /// A section header is malformed.
    InvalidSection(String),
    /// No `.debug` / `.stab` section is present.
    NoDebugSection,
    /// Generic parse failure.
    ParseError(String),
}

impl std::fmt::Display for XcoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not an XCOFF file (bad magic)"),
            Self::Truncated => write!(f, "XCOFF file truncated"),
            Self::InvalidSection(s) => write!(f, "invalid section: {s}"),
            Self::NoDebugSection => write!(f, "no .debug section found"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for XcoffError {}

// ─────────────────────────────────────────────────────────────────────────────
// XCOFF magic numbers
// ─────────────────────────────────────────────────────────────────────────────

/// XCOFF32 big-endian magic.
pub const XCOFF32_MAGIC: u16 = 0x01DF;
/// XCOFF64 big-endian magic (AIX 5.1+).
pub const XCOFF64_MAGIC: u16 = 0x01F7;

// ─────────────────────────────────────────────────────────────────────────────
// XcoffBitness
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the XCOFF file is 32-bit or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XcoffBitness {
    /// 32-bit XCOFF.
    Xcoff32,
    /// 64-bit XCOFF (AIX 5.1+).
    Xcoff64,
}

// ─────────────────────────────────────────────────────────────────────────────
// XcoffHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal XCOFF file header.  Fields are big-endian in the file.
#[derive(Debug, Clone)]
pub struct XcoffHeader {
    /// 32- or 64-bit variant.
    pub bitness: XcoffBitness,
    /// Magic number as read from the file.
    pub magic: u16,
    /// Number of section headers.
    pub n_sections: u16,
    /// Time/date stamp.
    pub timestamp: u32,
    /// File offset to the symbol table.
    pub sym_offset: u64,
    /// Number of symbol table entries.
    pub n_syms: u32,
    /// Size of the optional header.
    pub opt_header_size: u16,
    /// Flags.
    pub flags: u16,
}

impl XcoffHeader {
    /// Try to parse from the start of a byte slice.
    ///
    /// # Errors
    /// Returns [`XcoffError`] if the data is too short or the magic bytes are unrecognized.
    ///
    /// # Panics
    /// Panics if the slice indexing is inconsistent (should not happen given length checks above).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), XcoffError> {
        if data.len() < 4 {
            return Err(XcoffError::Truncated);
        }
        let magic = u16::from_be_bytes([data[0], data[1]]);
        let bitness = match magic {
            XCOFF32_MAGIC => XcoffBitness::Xcoff32,
            XCOFF64_MAGIC => XcoffBitness::Xcoff64,
            _ => return Err(XcoffError::BadMagic),
        };

        match bitness {
            XcoffBitness::Xcoff32 => {
                if data.len() < 20 {
                    return Err(XcoffError::Truncated);
                }
                // 32-bit layout (20 bytes):
                // [2] magic, [2] n_sections, [4] timestamp, [4] sym_offset,
                // [4] n_syms, [2] opt_header_size, [2] flags
                let n_sections = u16::from_be_bytes([data[2], data[3]]);
                let timestamp = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let sym_offset = u64::from(u32::from_be_bytes(data[8..12].try_into().unwrap()));
                let n_syms = u32::from_be_bytes(data[12..16].try_into().unwrap());
                let opt_header_size = u16::from_be_bytes([data[16], data[17]]);
                let flags = u16::from_be_bytes([data[18], data[19]]);
                let header = Self { bitness, magic, n_sections, timestamp, sym_offset, n_syms, opt_header_size, flags };
                let cursor = 20usize.saturating_add(usize::from(opt_header_size));
                if cursor > data.len() {
                    return Err(XcoffError::Truncated);
                }
                Ok((header, cursor))
            }
            XcoffBitness::Xcoff64 => {
                if data.len() < 24 {
                    return Err(XcoffError::Truncated);
                }
                // 64-bit layout (24 bytes):
                // [2] magic, [2] n_sections, [4] timestamp, [8] sym_offset,
                // [4] n_syms, [2] opt_header_size, [2] flags
                let n_sections = u16::from_be_bytes([data[2], data[3]]);
                let timestamp = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let sym_offset = u64::from_be_bytes(data[8..16].try_into().unwrap());
                let n_syms = u32::from_be_bytes(data[16..20].try_into().unwrap());
                let opt_header_size = u16::from_be_bytes([data[20], data[21]]);
                let flags = u16::from_be_bytes([data[22], data[23]]);
                let header = Self { bitness, magic, n_sections, timestamp, sym_offset, n_syms, opt_header_size, flags };
                let cursor = 24usize.saturating_add(usize::from(opt_header_size));
                if cursor > data.len() {
                    return Err(XcoffError::Truncated);
                }
                Ok((header, cursor))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XcoffSectionHeader
// ─────────────────────────────────────────────────────────────────────────────

/// XCOFF section header (40 bytes for XCOFF32, 72 bytes for XCOFF64).
#[derive(Debug, Clone)]
pub struct XcoffSectionHeader {
    /// Section name (8 bytes, NUL-padded).
    pub name: String,
    /// Physical (load) address.
    pub paddr: u64,
    /// Virtual address.
    pub vaddr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset to section data.
    pub scn_ptr: u64,
    /// File offset to relocation entries.
    pub rel_ptr: u64,
    /// File offset to line-number entries.
    pub lnno_ptr: u64,
    /// Number of relocation entries.
    pub n_reloc: u32,
    /// Number of line-number entries.
    pub n_lnno: u32,
    /// Section flags.
    pub flags: u32,
}

impl XcoffSectionHeader {
    const SIZE32: usize = 40;
    const SIZE64: usize = 72;

    /// Parse a section header from `data[offset..]`.
    ///
    /// # Errors
    /// Returns [`XcoffError`] if data is too short.
    ///
    /// # Panics
    /// Panics if the slice indexing is inconsistent (should not happen given length checks above).
    pub fn parse(data: &[u8], offset: usize, bitness: XcoffBitness) -> Result<Self, XcoffError> {
        let sz = match bitness { XcoffBitness::Xcoff32 => Self::SIZE32, XcoffBitness::Xcoff64 => Self::SIZE64 };
        // Checked: `offset` is caller-supplied on this public API, so
        // `offset + sz` can WRAP (release builds have overflow-checks off),
        // slip past the bound test and panic on the slice below.
        if offset.checked_add(sz).is_none_or(|e| e > data.len()) {
            return Err(XcoffError::Truncated);
        }
        let d = &data[offset..offset+sz];
        let name_end = d[0..8].iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&d[0..name_end]).into_owned();

        let (paddr, vaddr, size, scn_ptr, rel_ptr, lnno_ptr, n_reloc, n_lnno, flags) = match bitness {
            XcoffBitness::Xcoff32 => {
                let paddr    = u64::from(u32::from_be_bytes(d[8..12].try_into().unwrap()));
                let vaddr    = u64::from(u32::from_be_bytes(d[12..16].try_into().unwrap()));
                let size     = u64::from(u32::from_be_bytes(d[16..20].try_into().unwrap()));
                let scn_ptr  = u64::from(u32::from_be_bytes(d[20..24].try_into().unwrap()));
                let rel_ptr  = u64::from(u32::from_be_bytes(d[24..28].try_into().unwrap()));
                let lnno_ptr = u64::from(u32::from_be_bytes(d[28..32].try_into().unwrap()));
                let n_reloc  = u32::from(u16::from_be_bytes([d[32], d[33]]));
                let n_lnno   = u32::from(u16::from_be_bytes([d[34], d[35]]));
                let flags    = u32::from_be_bytes(d[36..40].try_into().unwrap());
                (paddr, vaddr, size, scn_ptr, rel_ptr, lnno_ptr, n_reloc, n_lnno, flags)
            }
            XcoffBitness::Xcoff64 => {
                let paddr    = u64::from_be_bytes(d[8..16].try_into().unwrap());
                let vaddr    = u64::from_be_bytes(d[16..24].try_into().unwrap());
                let size     = u64::from_be_bytes(d[24..32].try_into().unwrap());
                let scn_ptr  = u64::from_be_bytes(d[32..40].try_into().unwrap());
                let rel_ptr  = u64::from_be_bytes(d[40..48].try_into().unwrap());
                let lnno_ptr = u64::from_be_bytes(d[48..56].try_into().unwrap());
                let n_reloc  = u32::from_be_bytes(d[56..60].try_into().unwrap());
                let n_lnno   = u32::from_be_bytes(d[60..64].try_into().unwrap());
                let flags    = u32::from_be_bytes(d[64..68].try_into().unwrap());
                (paddr, vaddr, size, scn_ptr, rel_ptr, lnno_ptr, n_reloc, n_lnno, flags)
            }
        };

        Ok(Self { name, paddr, vaddr, size, scn_ptr, rel_ptr, lnno_ptr, n_reloc, n_lnno, flags })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XCOFF symbol storage class codes relevant to STABS
// ─────────────────────────────────────────────────────────────────────────────

/// `C_BINCL` storage class: Begin include file.
pub const C_BINCL: u8 = 108; // Begin include file
/// `C_EINCL` storage class: End include file.
pub const C_EINCL: u8 = 109; // End include file
/// `C_GSYM` storage class: Global symbol (STABS).
pub const C_GSYM:  u8 = 20;  // Global symbol (STABS)
/// `C_LSYM` storage class: Local symbol (STABS).
pub const C_LSYM:  u8 = 21;  // Local sym (STABS)
/// `C_PSYM` storage class: Function parameter (STABS).
pub const C_PSYM:  u8 = 27;  // Function parameter (STABS)
/// `C_RSYM` storage class: Register variable (STABS).
pub const C_RSYM:  u8 = 22;  // Register var (STABS)
/// `C_RPSYM` storage class: Register parameter (STABS).
pub const C_RPSYM: u8 = 23;  // Register param (STABS)
/// `C_STSYM` storage class: Static (data) symbol (STABS).
pub const C_STSYM: u8 = 24;  // Static (data) symbol (STABS)
/// `C_TCSYM` storage class: TOC symbol.
pub const C_TCSYM: u8 = 25;  // TOC symbol
/// `C_BCOMM` storage class: Begin common block.
pub const C_BCOMM: u8 = 110; // Begin common block
/// `C_ECOML` storage class: End common block (local name).
pub const C_ECOML: u8 = 111; // End common (local)
/// `C_ECOMM` storage class: End common block.
pub const C_ECOMM: u8 = 112; // End common block
/// `C_DECL` storage class: Declaration of an object.
pub const C_DECL:  u8 = 33;  // Declaration of object
/// `C_FUN` storage class: Function (STABS).
pub const C_FUN:   u8 = 142; // Function (STABS)
/// `C_FCN` storage class: Function begin/end.
pub const C_FCN:   u8 = 101; // Function begin/end

// ─────────────────────────────────────────────────────────────────────────────
// XcoffSymbolEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An XCOFF symbol table entry (18 bytes).
#[derive(Debug, Clone)]
pub struct XcoffSymbolEntry {
    /// Symbol name (inline 8 bytes, or long name via string table).
    pub name: String,
    /// Symbol value (address or storage-class-specific meaning).
    pub value: u32,
    /// Section number (1-based; special negative values for absolute/debug).
    pub section_num: i16,
    /// Basic + derived type field.
    pub sym_type: u16,
    /// Storage class (one of the `C_*` constants).
    pub storage_class: u8,
    /// Number of auxiliary entries following this one.
    pub n_aux_entries: u8,
}

/// Bucket a slice of XCOFF symbol entries by storage class
/// (`C_FILE`, `C_EXT`, `C_FUN`, ...). Returns a histogram suitable for
/// quick triage of a binary's symbol-table layout.
#[must_use]
pub fn xcoff_storage_class_histogram(syms: &[XcoffSymbolEntry]) -> HashMap<u8, usize> {
    let mut out: HashMap<u8, usize> = HashMap::new();
    for s in syms {
        *out.entry(s.storage_class).or_insert(0) += 1;
    }
    out
}

impl XcoffSymbolEntry {
    const SIZE: usize = 18;

    /// Parse from `data[offset..]`.  `strtab` is the XCOFF string table.
    ///
    /// # Errors
    /// Returns [`XcoffError`] if data is too short.
    ///
    /// # Panics
    /// Panics if the slice indexing is inconsistent (should not happen given length checks above).
    pub fn parse(data: &[u8], offset: usize, strtab: &[u8]) -> Result<Self, XcoffError> {
        // Checked for the same wrapping reason as `XcoffSectionHeader::parse`.
        if offset.checked_add(Self::SIZE).is_none_or(|e| e > data.len()) {
            return Err(XcoffError::Truncated);
        }
        let d = &data[offset..offset+Self::SIZE];

        // If first 4 bytes are zero, next 4 bytes are string table offset.
        let name = if d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0 {
            let str_off = usize::try_from(u32::from_be_bytes(d[4..8].try_into().unwrap())).unwrap_or(usize::MAX);
            if str_off < strtab.len() {
                let end = strtab[str_off..].iter().position(|&b| b == 0)
                    .map_or(strtab.len(), |n| str_off + n);
                String::from_utf8_lossy(&strtab[str_off..end]).into_owned()
            } else {
                String::new()
            }
        } else {
            let name_end = d[0..8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&d[0..name_end]).into_owned()
        };

        let value = u32::from_be_bytes(d[8..12].try_into().unwrap());
        let section_num = i16::from_be_bytes([d[12], d[13]]);
        let sym_type = u16::from_be_bytes([d[14], d[15]]);
        let storage_class = d[16];
        let n_aux_entries = d[17];

        Ok(Self { name, value, section_num, sym_type, storage_class, n_aux_entries })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AixTypeExtension
// ─────────────────────────────────────────────────────────────────────────────

/// AIX-specific STABS type extensions beyond the GNU/ELF baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AixTypeExtension {
    /// `__longdouble128` — 128-bit long double.
    LongDouble128,
    /// `_Complex float` — complex 32-bit float.
    ComplexFloat,
    /// `_Complex double` — complex 64-bit double.
    ComplexDouble,
    /// `_Complex long double` — complex 128-bit long double.
    ComplexLongDouble,
    /// `__int128` — 128-bit integer.
    Int128 {
        /// Whether the integer is signed.
        signed: bool,
    },
    /// Decimal floating point (C99 `_Decimal32`, `_Decimal64`, `_Decimal128`).
    DecimalFloat {
        /// Width in bits (32, 64, or 128).
        bits: u8,
    },
    /// AIX vector type (`__vector`).
    Vector {
        /// Element width in bits.
        elem_bits: u8,
        /// Number of elements.
        count: u8,
    },
}

impl AixTypeExtension {
    /// Try to identify an AIX type extension from a type name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "__longdouble128" | "long double" => Some(Self::LongDouble128),
            "_Complex float" => Some(Self::ComplexFloat),
            "_Complex double" => Some(Self::ComplexDouble),
            "_Complex long double" => Some(Self::ComplexLongDouble),
            "__int128" => Some(Self::Int128 { signed: true }),
            "__uint128" | "unsigned __int128" => Some(Self::Int128 { signed: false }),
            "_Decimal32" => Some(Self::DecimalFloat { bits: 32 }),
            "_Decimal64" => Some(Self::DecimalFloat { bits: 64 }),
            "_Decimal128" => Some(Self::DecimalFloat { bits: 128 }),
            _ => None,
        }
    }

    /// C-string representation.
    #[must_use]
    pub const fn c_name(&self) -> &'static str {
        match self {
            Self::LongDouble128 => "__longdouble128",
            Self::ComplexFloat => "_Complex float",
            Self::ComplexDouble => "_Complex double",
            Self::ComplexLongDouble => "_Complex long double",
            Self::Int128 { signed: true } => "__int128",
            Self::Int128 { signed: false } => "unsigned __int128",
            Self::DecimalFloat { bits: 32 } => "_Decimal32",
            Self::DecimalFloat { bits: 64 } => "_Decimal64",
            Self::DecimalFloat { .. } => "_Decimal128",
            Self::Vector { .. } => "__vector",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XcoffStabsExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts STABS records and their string table from an XCOFF binary blob.
pub struct XcoffStabsExtractor;

impl XcoffStabsExtractor {
    /// Parse an XCOFF binary and return `(stab_bytes, stabstr_bytes)` or an error.
    ///
    /// On AIX, STABS are in the `.debug` section; the string data comes partly
    /// from the symbol table (`C_BINCL` entries) and partly from `.debug` itself.
    ///
    /// # Errors
    /// Returns [`XcoffError`] if the header is invalid or the `.debug` section is missing.
    pub fn extract(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), XcoffError> {
        let (header, hdr_cursor) = XcoffHeader::parse(data)?;

        // Parse section headers.
        let mut cursor = hdr_cursor;
        let mut sections = Vec::new();
        let sec_size = match header.bitness {
            XcoffBitness::Xcoff32 => XcoffSectionHeader::SIZE32,
            XcoffBitness::Xcoff64 => XcoffSectionHeader::SIZE64,
        };
        for _ in 0..header.n_sections {
            let sec = XcoffSectionHeader::parse(data, cursor, header.bitness)?;
            sections.push(sec);
            cursor += sec_size;
        }

        // Find .debug and .stabstr sections.
        let debug_sec = sections.iter().find(|s| s.name == ".debug" || s.name == ".stab");
        let str_sec = sections.iter().find(|s| s.name == ".stabstr");

        let stab_bytes = if let Some(sec) = debug_sec {
            // `scn_ptr` / `size` are attacker-controlled big-endian words:
            // `off + sz` must be checked or it panics (debug) / wraps past the
            // bounds test (release).
            let off = usize::try_from(sec.scn_ptr).unwrap_or(usize::MAX);
            let sz = usize::try_from(sec.size).unwrap_or(usize::MAX);
            let end = off.checked_add(sz).ok_or(XcoffError::Truncated)?;
            data.get(off..end).ok_or(XcoffError::Truncated)?.to_vec()
        } else {
            return Err(XcoffError::NoDebugSection);
        };

        let stabstr_bytes = str_sec.map_or_else(
            || Self::extract_strings_from_symtab(data, &header),
            |sec| {
                let off = usize::try_from(sec.scn_ptr).unwrap_or(usize::MAX);
                let sz = usize::try_from(sec.size).unwrap_or(usize::MAX);
                off.checked_add(sz)
                    .and_then(|end| data.get(off..end))
                    .map_or_else(Vec::new, <[u8]>::to_vec)
            },
        );

        Ok((stab_bytes, stabstr_bytes))
    }

    /// Build a string table by scanning the XCOFF symbol table for STABS-related
    /// entries (`C_BINCL`, `C_FUN`, `C_GSYM`, `C_LSYM`, `C_PSYM`, `C_RSYM`).
    fn extract_strings_from_symtab(data: &[u8], header: &XcoffHeader) -> Vec<u8> {
        let sym_off = usize::try_from(header.sym_offset).unwrap_or(usize::MAX);
        if sym_off == 0 || sym_off >= data.len() {
            return Vec::new();
        }

        // XCOFF symbol table string table is at sym_off + n_syms * 18.
        let strtab_off = sym_off.saturating_add(
            usize::try_from(header.n_syms).unwrap_or(usize::MAX).saturating_mul(XcoffSymbolEntry::SIZE),
        );
        // `strtab_off` is already a saturating_add/mul result and can be
        // usize::MAX, so the `+ 4` needs to be checked too.
        let strtab_hdr = strtab_off
            .checked_add(4)
            .and_then(|e| data.get(strtab_off..e));
        let strtab = if let Some(hdr) = strtab_hdr {
            // First 4 bytes of XCOFF strtab is the total strtab size.
            let strtab_size = usize::try_from(u32::from_be_bytes(
                hdr.try_into().unwrap_or([0u8; 4])
            )).unwrap_or(usize::MAX);
            let end = strtab_off.saturating_add(strtab_size).min(data.len());
            data.get(strtab_off..end).unwrap_or(&data[0..0])
        } else {
            &data[0..0]
        };

        let mut out = Vec::new();
        let mut i = 0usize;
        loop {
            // Checked arithmetic: `i` is bumped by an attacker-controlled
            // `n_aux_entries`, so the offset computation can overflow.
            let Some(ent_off) = i
                .checked_mul(XcoffSymbolEntry::SIZE)
                .and_then(|o| o.checked_add(sym_off))
            else {
                break;
            };
            if ent_off.checked_add(XcoffSymbolEntry::SIZE).is_none_or(|e| e > data.len())
                || u32::try_from(i).unwrap_or(u32::MAX) >= header.n_syms
            {
                break;
            }
            let sym_result = XcoffSymbolEntry::parse(data, ent_off, strtab);
            if let Ok(sym) = sym_result {
                if matches!(sym.storage_class,
                    C_BINCL | C_EINCL | C_GSYM | C_LSYM | C_PSYM | C_RSYM | C_STSYM | C_FUN) {
                    out.extend_from_slice(sym.name.as_bytes());
                    out.push(0);
                }
                i += sym.n_aux_entries as usize + 1;
            } else {
                i += 1;
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XcoffStabsInfo — summary after extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Summary information after extracting STABS from XCOFF.
#[derive(Debug, Clone)]
pub struct XcoffStabsInfo {
    /// Bitness of the binary.
    pub bitness: XcoffBitness,
    /// Number of raw STABS records extracted.
    pub n_stab_records: usize,
    /// Size of the extracted string table.
    pub stabstr_size: usize,
    /// Whether a `.debug` section was found.
    pub has_debug_section: bool,
    /// Section names in the binary.
    pub section_names: Vec<String>,
}

impl XcoffStabsInfo {
    /// Gather info by parsing the XCOFF header and sections (no full extraction).
    ///
    /// # Errors
    /// Returns [`XcoffError`] if the XCOFF header is invalid.
    pub fn probe(data: &[u8]) -> Result<Self, XcoffError> {
        let (header, hdr_cursor) = XcoffHeader::parse(data)?;
        let sec_size = match header.bitness {
            XcoffBitness::Xcoff32 => XcoffSectionHeader::SIZE32,
            XcoffBitness::Xcoff64 => XcoffSectionHeader::SIZE64,
        };
        let mut cursor = hdr_cursor;
        let mut section_names = Vec::new();
        let mut has_debug = false;
        for _ in 0..header.n_sections {
            if let Ok(sec) = XcoffSectionHeader::parse(data, cursor, header.bitness) {
                if sec.name == ".debug" || sec.name == ".stab" {
                    has_debug = true;
                }
                section_names.push(sec.name);
            }
            cursor += sec_size;
        }
        Ok(Self {
            bitness: header.bitness,
            n_stab_records: 0, // filled in after full extraction
            stabstr_size: 0,
            has_debug_section: has_debug,
            section_names,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal XCOFF32 header.
    fn make_xcoff32_header() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&XCOFF32_MAGIC.to_be_bytes()); // magic
        data.extend_from_slice(&0u16.to_be_bytes()); // n_sections
        data.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        data.extend_from_slice(&0u32.to_be_bytes()); // sym_offset
        data.extend_from_slice(&0u32.to_be_bytes()); // n_syms
        data.extend_from_slice(&0u16.to_be_bytes()); // opt_header_size
        data.extend_from_slice(&0u16.to_be_bytes()); // flags
        data
    }

    #[test]
    fn test_xcoff32_header_parse() {
        let data = make_xcoff32_header();
        let (hdr, cursor) = XcoffHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic, XCOFF32_MAGIC);
        assert_eq!(hdr.bitness, XcoffBitness::Xcoff32);
        assert_eq!(cursor, 20);
    }

    #[test]
    fn test_xcoff_bad_magic() {
        let data = [0xAA, 0xBB, 0x00, 0x00];
        assert_eq!(XcoffHeader::parse(&data).unwrap_err(), XcoffError::BadMagic);
    }

    #[test]
    fn test_xcoff_truncated() {
        let data = [0x01, 0xDF]; // too short
        assert_eq!(XcoffHeader::parse(&data).unwrap_err(), XcoffError::Truncated);
    }

    #[test]
    fn test_aix_type_extension_from_name() {
        assert_eq!(AixTypeExtension::from_name("__longdouble128"), Some(AixTypeExtension::LongDouble128));
        assert_eq!(AixTypeExtension::from_name("_Complex float"), Some(AixTypeExtension::ComplexFloat));
        assert_eq!(AixTypeExtension::from_name("__int128"), Some(AixTypeExtension::Int128 { signed: true }));
        assert_eq!(AixTypeExtension::from_name("unknown_type"), None);
    }

    #[test]
    fn test_xcoff_section_header_parse32() {
        let mut data = vec![0u8; XcoffSectionHeader::SIZE32];
        // name: ".debug"
        data[0..6].copy_from_slice(b".debug");
        // size = 100
        data[16..20].copy_from_slice(&100u32.to_be_bytes());
        // scn_ptr = 512
        data[20..24].copy_from_slice(&512u32.to_be_bytes());
        let sec = XcoffSectionHeader::parse(&data, 0, XcoffBitness::Xcoff32).unwrap();
        assert_eq!(sec.name, ".debug");
        assert_eq!(sec.size, 100);
        assert_eq!(sec.scn_ptr, 512);
    }

    #[test]
    fn test_symbol_entry_short_name() {
        let mut data = vec![0u8; XcoffSymbolEntry::SIZE];
        data[0..5].copy_from_slice(b"hello");
        data[16] = C_LSYM;
        data[17] = 0;
        let sym = XcoffSymbolEntry::parse(&data, 0, &[]).unwrap();
        assert_eq!(sym.name, "hello");
        assert_eq!(sym.storage_class, C_LSYM);
    }

    #[test]
    fn test_extract_no_debug_returns_error() {
        let data = make_xcoff32_header();
        let result = XcoffStabsExtractor::extract(&data);
        assert_eq!(result.unwrap_err(), XcoffError::NoDebugSection);
    }

    #[test]
    fn test_probe_no_sections() {
        let data = make_xcoff32_header();
        let info = XcoffStabsInfo::probe(&data).unwrap();
        assert_eq!(info.bitness, XcoffBitness::Xcoff32);
        assert!(!info.has_debug_section);
        assert!(info.section_names.is_empty());
    }
}

#[cfg(test)]
mod wrap_hardening_tests {
    use super::*;

    /// `parse` is public and takes a caller-supplied `offset`. With
    /// `offset + sz > data.len()` the addition WRAPS in release (overflow-checks
    /// are off), the guard passes, and the slice index panics. Both parsers must
    /// use a checked add instead.
    #[test]
    fn section_header_parse_rejects_wrapping_offset() {
        let data = [0u8; 64];
        let r = XcoffSectionHeader::parse(&data, usize::MAX - 4, XcoffBitness::Xcoff32);
        assert!(matches!(r, Err(XcoffError::Truncated)));
    }

    #[test]
    fn symbol_entry_parse_rejects_wrapping_offset() {
        let data = [0u8; 64];
        let r = XcoffSymbolEntry::parse(&data, usize::MAX - 4, &[]);
        assert!(matches!(r, Err(XcoffError::Truncated)));
    }
}
