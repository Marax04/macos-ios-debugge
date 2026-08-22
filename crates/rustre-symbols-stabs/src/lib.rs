//! `rustre-symbols-stabs` — STABS debug format parser.
//!
//! Handles the old Unix/GCC debug format stored in ELF `.stab` / `.stabstr` sections.
//! Full support for `N_FUN`, `N_GSYM`, `N_STSYM`, `N_SO`, `N_SOL`, `N_SLINE`, `N_LSYM`, `N_RSYM`,
//! `N_PSYM` type descriptor parsing, struct/union/enum reconstruction, and line-number tables.
//!
//! # Canonical API
//!
//! The **canonical** entry points are the items defined in this file:
//! [`StabRecord`] / [`StabRecord::parse_all`] for record-level parsing,
//! [`StabsProvider`] for the `SymbolProvider` implementation, and
//! [`LineNumberTable`] for line lookups. The submodules below contain
//! alternative/legacy parsers kept for API compatibility
//! (`stabs_complete`, `stabs_full_parser`, `stabs_line_info` vs
//! `stabs_lineinfo`, ...); prefer the top-level items for new code.
//! N_-code byte values follow binutils/gdb `stab.def` and are cross-checked
//! between `StabType` (here) and `stabs_complete::StabType` by tests.

#![warn(missing_docs)]

pub mod cu_strings;
pub mod stabs_cfparser;
pub mod stabs_complete;
pub mod stabs_full_parser;
pub mod stabs_line_info;
pub mod stabs_lineinfo;
pub mod stabs_reconstruct;
pub mod stabs_type_reconstructor;
pub mod stabs_types;
pub mod xcoff_stabs;
/// Alternative record-level STABS parser (legacy API).
pub mod stabs_parser;
pub mod stabs_type_decoder;
/// STABS to DWARF conversion (record-level).
pub mod stabs_to_dwarf;
pub mod stabs_type_parser;
pub mod stabs_scope_tracker;
pub mod stabs_source_mapper;
/// STABS type-reference resolution.
pub mod stabs_type_resolver;
/// STABS to DWARF conversion (structured converter).
pub mod stabs_to_dwarf_converter;

/// Split a STABS symbol string into `(name, descriptor)`.
///
/// The separator is the first colon that is **not** part of a C++ `::`
/// qualifier. A naive `split(':').next()` truncates every C++ symbol at its
/// class name — `Foo::bar:F(0,1)` yields the name `"Foo"` and the unparseable
/// descriptor `":bar:F(0,1)"`, collapsing every method of a class onto one
/// name. GDB performs the same `::`-skipping scan.
///
/// If there is no such colon the whole string is the name and the descriptor
/// is empty.
#[must_use]
pub fn split_stab_name(s: &str) -> (&str, &str) {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b':' {
            if b.get(i + 1) == Some(&b':') {
                // Part of a `::` qualifier — skip both bytes and keep scanning.
                i += 2;
                continue;
            }
            return (&s[..i], &s[i + 1..]);
        }
        i += 1;
    }
    (s, "")
}

/// Name half of [`split_stab_name`].
#[must_use]
pub fn stab_name_of(s: &str) -> &str {
    split_stab_name(s).0
}

use rustre_symbols::{SourceLocation, StructField, SymKind, Symbol, SymbolProvider, TypeInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Errors produced by the STABS parser.
#[derive(Debug, Error)]
pub enum StabsError {
    /// A stab record at the given index could not be decoded.
    #[error("invalid stab record at index {0}")]
    InvalidRecord(usize),
    /// The string table could not be accessed.
    #[error("string table error: {0}")]
    StringTable(String),
    /// A generic parse error.
    #[error("parse: {0}")]
    Parse(String),
    /// A type descriptor could not be parsed.
    #[error("type parse: {0}")]
    TypeParse(String),
}

// ---------------------------------------------------------------------------
// StabType
// ---------------------------------------------------------------------------

/// STAB record type codes (the `n_type` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum StabType {
    /// `N_UNDF` — Undefined; start-of-CU header carrying string-table sizes.
    NUndf = 0x00,
    /// `N_GSYM` — Global symbol.
    NGsym = 0x20,
    /// `N_FNAME` — Function name (Pascal/Fortran).
    NFname = 0x22,
    /// `N_FUN` — Function or text-segment variable.
    NFun = 0x24,
    /// `N_STSYM` — Static symbol in the data segment.
    NStsym = 0x26,
    /// `N_LCSYM` — Static symbol in the BSS segment.
    NLcsym = 0x28,
    /// `N_MAIN` — Name of the main routine.
    NMain = 0x2A,
    /// `N_ROSYM` — Read-only data symbol.
    NRosym = 0x2C,
    /// `N_PC` — Global symbol (Pascal).
    NPc = 0x30,
    /// `N_NSYMS` — Number of symbols (Ultrix).
    NNsyms = 0x32,
    /// `N_NOMAP` — No DST map.
    NNomap = 0x34,
    /// `N_OBJ` — Object file (Solaris).
    NObj = 0x38,
    /// `N_OPT` — Debugger options (Solaris).
    NOpt = 0x3C,
    /// `N_RSYM` — Register variable.
    NRsym = 0x40,
    /// `N_M2C` — Modula-2 compilation unit.
    NM2c = 0x42,
    /// `N_SLINE` — Source line in the text segment.
    NSline = 0x44,
    /// `N_DSLINE` — Source line in the data segment.
    NDsline = 0x46,
    /// `N_BSLINE` — Source line in the BSS segment.
    NBsline = 0x48,
    /// `N_DEFD` — GNU Modula-2 definition module dependency.
    NDefd = 0x4A,
    /// `N_FLINE` — Function start/body/end line (Sun).
    NFline = 0x4C,
    /// `N_EHDECL` — GNU C++ exception variable.
    NEhdecl = 0x50,
    /// `N_CATCH` — GNU C++ catch clause.
    NCatch = 0x54,
    /// `N_SSYM` — Structure/union element.
    NSsym = 0x60,
    /// `N_ENDM` — Last stab for module (Solaris).
    NEndm = 0x62,
    /// `N_SO` — Main source file (compilation unit).
    NSo = 0x64,
    /// `N_LSYM` — Local symbol (stack variable or type definition).
    NLsym = 0x80,
    /// `N_BINCL` — Begin include file.
    NBincl = 0x82,
    /// `N_SOL` — Included source file.
    NSol = 0x84,
    /// `N_PSYM` — Function parameter.
    NPsym = 0xA0,
    /// `N_EINCL` — End include file.
    NEincl = 0xA2,
    /// `N_ENTRY` — Alternate function entry point.
    NEntry = 0xA4,
    /// `N_LBRAC` — Begin lexical block.
    NLbrac = 0xC0,
    /// `N_EXCL` — Excluded include file (deduplicated).
    NExcl = 0xC2,
    /// `N_SCOPE` — Modula-2 scope information (Sun).
    NScope = 0xC4,
    /// `N_RBRAC` — End lexical block.
    NRbrac = 0xE0,
    /// `N_BCOMM` — Begin common block.
    NBcomm = 0xE2,
    /// `N_ECOMM` — End common block.
    NEcomm = 0xE4,
    /// `N_ECOML` — End common block (local name).
    NEcoml = 0xE8,
    /// `N_WITH` — Pascal `with` statement.
    NWith = 0xEA,
    /// `N_NBTEXT` — Gould non-base register text symbol.
    NNbtext = 0xF0,
    /// `N_NBDATA` — Gould non-base register data symbol.
    NNbdata = 0xF2,
    /// `N_NBBSS` — Gould non-base register BSS symbol.
    NNbbss = 0xF4,
    /// `N_NBSTS` — Gould non-base register STS symbol.
    NNbsts = 0xF6,
    /// `N_NBLCS` — Gould non-base register LCS symbol.
    NNblcs = 0xF8,
    /// Unrecognised type code.
    Unknown = 0xFF,
}

impl StabType {
    /// Convert a raw byte to a `StabType`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::NUndf,
            0x20 => Self::NGsym,
            0x22 => Self::NFname,
            0x24 => Self::NFun,
            0x26 => Self::NStsym,
            0x28 => Self::NLcsym,
            0x2A => Self::NMain,
            0x2C => Self::NRosym,
            0x30 => Self::NPc,
            0x32 => Self::NNsyms,
            0x34 => Self::NNomap,
            0x38 => Self::NObj,
            0x3C => Self::NOpt,
            0x40 => Self::NRsym,
            0x42 => Self::NM2c,
            0x44 => Self::NSline,
            0x46 => Self::NDsline,
            0x48 => Self::NBsline,
            0x4A => Self::NDefd,
            0x4C => Self::NFline,
            0x50 => Self::NEhdecl,
            0x54 => Self::NCatch,
            0x60 => Self::NSsym,
            0x62 => Self::NEndm,
            0x64 => Self::NSo,
            0x80 => Self::NLsym,
            0x82 => Self::NBincl,
            0x84 => Self::NSol,
            0xA0 => Self::NPsym,
            0xA2 => Self::NEincl,
            0xA4 => Self::NEntry,
            0xC0 => Self::NLbrac,
            0xC2 => Self::NExcl,
            0xC4 => Self::NScope,
            0xE0 => Self::NRbrac,
            0xE2 => Self::NBcomm,
            0xE4 => Self::NEcomm,
            0xE8 => Self::NEcoml,
            0xEA => Self::NWith,
            0xF0 => Self::NNbtext,
            0xF2 => Self::NNbdata,
            0xF4 => Self::NNbbss,
            0xF6 => Self::NNbsts,
            0xF8 => Self::NNblcs,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this type typically introduces a named symbol.
    #[must_use]
    pub const fn is_symbol(&self) -> bool {
        matches!(
            self,
            Self::NFun | Self::NGsym | Self::NStsym | Self::NRsym | Self::NPsym
        )
    }

    /// Returns `true` if this type carries source file information.
    #[must_use]
    pub const fn is_source_file(&self) -> bool {
        matches!(self, Self::NSo | Self::NSol | Self::NBincl | Self::NEincl)
    }

    /// Returns `true` if this type carries line number information.
    #[must_use]
    pub const fn is_line_number(&self) -> bool {
        matches!(
            self,
            Self::NSline | Self::NDsline | Self::NBsline | Self::NFline
        )
    }

    /// Returns `true` if this is a scope bracket.
    #[must_use]
    pub const fn is_scope_bracket(&self) -> bool {
        matches!(self, Self::NLbrac | Self::NRbrac)
    }

    /// Human-readable category string.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        if self.is_symbol() {
            "symbol"
        } else if self.is_source_file() {
            "file"
        } else if self.is_line_number() {
            "line"
        } else if self.is_scope_bracket() {
            "scope"
        } else {
            "other"
        }
    }
}

impl StabType {
    /// Canonical N_-prefixed STABS name for this type code.
    ///
    /// This matches the historical `nlist.h` constant names (e.g. `"N_FUN"`)
    /// even though the Rust variant identifiers use CamelCase. Useful when
    /// emitting dumps that should look identical to GDB/binutils output.
    #[must_use]
    pub const fn name_for(b: u8) -> Option<&'static str> {
        Some(match b {
            0x00 => "N_UNDF",
            0x20 => "N_GSYM",
            0x22 => "N_FNAME",
            0x24 => "N_FUN",
            0x26 => "N_STSYM",
            0x28 => "N_LCSYM",
            0x2A => "N_MAIN",
            0x2C => "N_ROSYM",
            0x30 => "N_PC",
            0x32 => "N_NSYMS",
            0x34 => "N_NOMAP",
            0x38 => "N_OBJ",
            0x3C => "N_OPT",
            0x40 => "N_RSYM",
            0x42 => "N_M2C",
            0x44 => "N_SLINE",
            0x46 => "N_DSLINE",
            0x48 => "N_BSLINE",
            0x4A => "N_DEFD",
            0x4C => "N_FLINE",
            0x50 => "N_EHDECL",
            0x54 => "N_CATCH",
            0x60 => "N_SSYM",
            0x62 => "N_ENDM",
            0x64 => "N_SO",
            0x80 => "N_LSYM",
            0x82 => "N_BINCL",
            0x84 => "N_SOL",
            0xA0 => "N_PSYM",
            0xA2 => "N_EINCL",
            0xA4 => "N_ENTRY",
            0xC0 => "N_LBRAC",
            0xC2 => "N_EXCL",
            0xC4 => "N_SCOPE",
            0xE0 => "N_RBRAC",
            0xE2 => "N_BCOMM",
            0xE4 => "N_ECOMM",
            0xE8 => "N_ECOML",
            0xEA => "N_WITH",
            0xF0 => "N_NBTEXT",
            0xF2 => "N_NBDATA",
            0xF4 => "N_NBBSS",
            0xF6 => "N_NBSTS",
            0xF8 => "N_NBLCS",
            _ => return None,
        })
    }

    /// Canonical N_-prefixed name for this variant, or `"Unknown"`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        Self::name_for(*self as u8).unwrap_or("Unknown")
    }
}

impl fmt::Display for StabType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// StabRecord
// ---------------------------------------------------------------------------

/// A single decoded STAB record (12 bytes on-disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabRecord {
    /// Index into the string table (`n_strx`).
    pub strx: u32,
    /// Record type (`n_type`).
    pub stab_type: StabType,
    /// Misc byte (`n_other`).
    pub other: u8,
    /// Line / desc field (`n_desc`).
    pub desc: u16,
    /// Value field — typically an address (`n_value`).
    pub value: u32,
    /// Name string resolved from the string table.
    pub string: String,
}

impl StabRecord {
    /// Parse all records from a raw `.stab` section, resolving names from `.stabstr`.
    ///
    /// `N_UNDF` compilation-unit headers are honoured, so `n_strx` is resolved
    /// relative to the running per-CU string-table base (see
    /// [`crate::cu_strings`]). A `.stab` without headers resolves identically
    /// to a plain absolute lookup.
    #[must_use]
    pub fn parse_all(stab_data: &[u8], stabstr: &[u8]) -> Vec<Self> {
        Self::parse_all_endian(stab_data, stabstr, false)
    }

    /// Parse all records from a big-endian `.stab` section.
    #[must_use]
    pub fn parse_all_be(stab_data: &[u8], stabstr: &[u8]) -> Vec<Self> {
        Self::parse_all_endian(stab_data, stabstr, true)
    }

    /// Shared record loop for both byte orders.
    ///
    /// Both public entry points delegate here so the CU-relative string base
    /// cannot be threaded through one endianness and not the other.
    fn parse_all_endian(stab_data: &[u8], stabstr: &[u8], big_endian: bool) -> Vec<Self> {
        let mut base = cu_strings::CuStringBase::new();
        stab_data
            .chunks_exact(12)
            .map(|chunk| {
                let b4 = |r: [u8; 4]| {
                    if big_endian {
                        u32::from_be_bytes(r)
                    } else {
                        u32::from_le_bytes(r)
                    }
                };
                let strx = b4(chunk[0..4].try_into().unwrap_or([0; 4]));
                let n_type = chunk[4];
                let stab_type = StabType::from_u8(n_type);
                let other = chunk[5];
                let desc = if big_endian {
                    u16::from_be_bytes([chunk[6], chunk[7]])
                } else {
                    u16::from_le_bytes([chunk[6], chunk[7]])
                };
                let value = b4(chunk[8..12].try_into().unwrap_or([0; 4]));
                let string =
                    String::from_utf8_lossy(base.resolve_bytes(stabstr, n_type, strx, value))
                        .into_owned();
                Self {
                    strx,
                    stab_type,
                    other,
                    desc,
                    value,
                    string,
                }
            })
            .collect()
    }

    /// Extract the symbol name from a STABS type descriptor string.
    /// The name is everything before the first `:`.
    #[must_use]
    pub fn symbol_name(&self) -> &str {
        split_stab_name(&self.string).0
    }

    /// Extract the type descriptor part (after the name/descriptor separator).
    #[must_use]
    pub fn type_descriptor(&self) -> &str {
        split_stab_name(&self.string).1
    }

    /// Returns `true` if this record has a non-empty string.
    #[must_use]
    pub const fn has_string(&self) -> bool {
        !self.string.is_empty()
    }
}

impl fmt::Display for StabRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} val={:#x} '{}'",
            self.stab_type, self.value, self.string
        )
    }
}

// ---------------------------------------------------------------------------
// StabTypeDescriptor
// ---------------------------------------------------------------------------

/// Parsed STABS type descriptor code (the character after `:` in `name:TYPE_CODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabTypeCode {
    /// `f` — file-scope function.
    Function,
    /// `F` — globally visible function.
    GlobalFunction,
    /// `g` — global variable.
    GlobalVar,
    /// `s` — static variable.
    StaticVar,
    /// `r` — register variable.
    RegisterVar,
    /// `p` — function parameter.
    Parameter,
    /// `t` — typedef.
    Typedef,
    /// `T` — structure/union/enum tag.
    Tag,
    /// `v` — variable-length array.
    VarArray,
    /// Other / unrecognised.
    Other(char),
}

impl StabTypeCode {
    /// Parse from the first character of the type descriptor.
    #[must_use]
    pub const fn from_char(c: char) -> Self {
        match c {
            'f' => Self::Function,
            'F' => Self::GlobalFunction,
            'g' => Self::GlobalVar,
            's' => Self::StaticVar,
            'r' => Self::RegisterVar,
            'p' => Self::Parameter,
            't' => Self::Typedef,
            'T' => Self::Tag,
            'v' => Self::VarArray,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for StabTypeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(c) => write!(f, "Other({c})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// StabsTypeParser
// ---------------------------------------------------------------------------

/// Minimal STABS type descriptor parser.
///
/// Parses the canonical STABS type format (as emitted by GCC) into [`TypeInfo`].
pub struct StabsTypeParser {
    /// Map from type number string (e.g. `"0,1"`) to resolved [`TypeInfo`].
    type_map: HashMap<String, TypeInfo>,
}

impl StabsTypeParser {
    /// Create a new parser with built-in primitive type mappings.
    #[must_use]
    pub fn new() -> Self {
        let mut m = HashMap::new();
        // Primitive type indices as commonly used by GCC
        m.insert(
            "(0,1)".to_string(),
            TypeInfo::Int {
                width: 32,
                signed: true,
            },
        );
        m.insert(
            "(0,2)".to_string(),
            TypeInfo::Int {
                width: 8,
                signed: true,
            },
        );
        m.insert(
            "(0,3)".to_string(),
            TypeInfo::Int {
                width: 16,
                signed: true,
            },
        );
        m.insert(
            "(0,4)".to_string(),
            TypeInfo::Int {
                width: 64,
                signed: true,
            },
        );
        m.insert(
            "(0,5)".to_string(),
            TypeInfo::Int {
                width: 8,
                signed: false,
            },
        );
        m.insert(
            "(0,6)".to_string(),
            TypeInfo::Int {
                width: 16,
                signed: false,
            },
        );
        m.insert(
            "(0,7)".to_string(),
            TypeInfo::Int {
                width: 32,
                signed: false,
            },
        );
        m.insert(
            "(0,8)".to_string(),
            TypeInfo::Int {
                width: 64,
                signed: false,
            },
        );
        m.insert("(0,9)".to_string(), TypeInfo::Float { width: 32 });
        m.insert("(0,10)".to_string(), TypeInfo::Float { width: 64 });
        m.insert("(0,11)".to_string(), TypeInfo::Float { width: 80 });
        m.insert(
            "(0,12)".to_string(),
            TypeInfo::Int {
                width: 8,
                signed: false,
            },
        ); // char
        m.insert("(0,14)".to_string(), TypeInfo::Void);
        Self { type_map: m }
    }

    /// Register a type number → [`TypeInfo`] mapping.
    pub fn register(&mut self, type_num: String, info: TypeInfo) {
        self.type_map.insert(type_num, info);
    }

    /// Look up a type by its number string.
    #[must_use]
    pub fn lookup(&self, type_num: &str) -> Option<&TypeInfo> {
        self.type_map.get(type_num)
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.type_map.len()
    }

    /// Returns `true` if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.type_map.is_empty()
    }

    /// Parse a type descriptor string (the portion after `:`) and return a [`TypeInfo`].
    ///
    /// Handles the most common cases:
    /// - Type number reference: `(n,m)` → look up in the type map.
    /// - Pointer: `*(n,m)` → `TypeInfo::Pointer`.
    /// - Array: `ar(n,m);lo;hi;(n2,m2)` → `TypeInfo::Array`.
    /// - Named struct/enum: `s...` or `e...` → `TypeInfo::Struct`/`TypeInfo::Enum`.
    ///
    /// # Errors
    ///
    /// Returns [`StabsError::TypeParse`] if the descriptor is completely unrecognisable.
    pub fn parse_descriptor(&self, desc: &str) -> Result<TypeInfo, StabsError> {
        let desc = desc.trim();
        if desc.is_empty() {
            return Ok(TypeInfo::Unknown);
        }

        // Skip type-code char (f, F, g, r, p, t, T, v…) if present.
        // Note: 's' (struct) and 'e' (enum) are NOT stripped here — they
        // are handled below as struct/enum prefix markers.
        let desc = if desc
            .starts_with(['f', 'F', 'g', 'r', 'p', 't', 'T', 'v'])
        {
            &desc[1..]
        } else {
            desc
        };

        // Pointer type: `*TYPE`
        if let Some(inner) = desc.strip_prefix('*') {
            let inner_type = self.parse_descriptor(inner).unwrap_or(TypeInfo::Unknown);
            return Ok(TypeInfo::Pointer {
                target: Box::new(inner_type),
                size: 8,
            });
        }

        // Array type: `ar...`
        if desc.starts_with("ar") {
            return Ok(self.parse_array_descriptor(desc));
        }

        // Struct type: `sN...`
        if desc.starts_with('s') || desc.starts_with("Su") {
            return Ok(self.parse_struct_descriptor(desc));
        }

        // Enum type: `e...`
        if desc.starts_with('e') {
            return Ok(Self::parse_enum_descriptor(desc));
        }

        // Type number reference: `(n,m)`
        if desc.starts_with('(')
            && let Some(end) = desc.find(')') {
                let key = &desc[..=end];
                if let Some(ti) = self.type_map.get(key) {
                    return Ok(ti.clone());
                }
                return Ok(TypeInfo::Named(key.to_string()));
            }

        // Simple integer index
        if desc.chars().all(|c| c.is_ascii_digit()) {
            return Ok(TypeInfo::Named(desc.to_string()));
        }

        Ok(TypeInfo::Unknown)
    }

    fn parse_array_descriptor(&self, desc: &str) -> TypeInfo {
        // ar(index_type);lo;hi;(element_type)
        // We do a best-effort parse.
        let parts: Vec<&str> = desc.splitn(4, ';').collect();
        let count = if parts.len() >= 3 {
            let lo: i64 = parts[1].parse().unwrap_or(0);
            let hi: i64 = parts[2].parse().unwrap_or(-1);
            u64::try_from((hi - lo + 1).max(0)).unwrap_or(0)
        } else {
            0u64
        };
        let elem = if parts.len() >= 4 {
            self.parse_descriptor(parts[3]).unwrap_or(TypeInfo::Unknown)
        } else {
            TypeInfo::Unknown
        };
        TypeInfo::Array {
            element: Box::new(elem),
            count,
        }
    }

    fn parse_struct_descriptor(&self, desc: &str) -> TypeInfo {
        // sNFIELD_NAME:TYPE,OFFSET,SIZE;...;
        // N is struct size in bytes.
        // We extract field list.
        let body = desc.strip_prefix('s').unwrap_or(desc);
        // Find struct byte size at start
        let (_, rest) = body.split_at(
            body.find(|c: char| !c.is_ascii_digit())
                .unwrap_or(body.len()),
        );
        let mut fields = Vec::new();
        // Simple field parser: split on ';', each item is "NAME:TYPE,OFFSET,SIZE"
        for entry in rest.split(';') {
            if entry.is_empty() || entry == "," {
                continue;
            }
            if let Some(colon_pos) = entry.find(':') {
                let field_name = &entry[..colon_pos];
                let rest2 = &entry[colon_pos + 1..];
                // TYPE,OFFSET,SIZE
                // Find first comma outside balanced parentheses, since TYPE
                // may itself be a `(file,index)` reference containing commas.
                let comma1 = {
                    let bytes = rest2.as_bytes();
                    let mut depth: i32 = 0;
                    let mut found = rest2.len();
                    for (i, &b) in bytes.iter().enumerate() {
                        match b {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            b',' if depth == 0 => {
                                found = i;
                                break;
                            }
                            _ => {}
                        }
                    }
                    found
                };
                let type_desc = &rest2[..comma1];
                let after_comma1 = &rest2[comma1..];
                let offset_str = after_comma1.trim_start_matches(',');
                let comma2 = offset_str.find(',').unwrap_or(offset_str.len());
                let offset_bits: u32 = offset_str[..comma2].parse().unwrap_or(0);
                let field_type = self
                    .parse_descriptor(type_desc)
                    .unwrap_or(TypeInfo::Unknown);
                if !field_name.is_empty() {
                    fields.push(StructField {
                        name: field_name.to_string(),
                        offset: offset_bits / 8,
                        type_info: field_type,
                    });
                }
            }
        }
        TypeInfo::Struct {
            name: String::new(),
            fields,
        }
    }

    fn parse_enum_descriptor(desc: &str) -> TypeInfo {
        // eNAME:VALUE,NAME2:VALUE2,...;
        let body = desc.strip_prefix('e').unwrap_or(desc);
        let mut variants = Vec::new();
        for entry in body.split(',') {
            if let Some(colon_pos) = entry.rfind(':') {
                let var_name = &entry[..colon_pos];
                let var_val: i64 = entry[colon_pos + 1..]
                    .trim_end_matches(';')
                    .parse()
                    .unwrap_or(0);
                if !var_name.is_empty() {
                    variants.push((var_name.to_string(), var_val));
                }
            }
        }
        TypeInfo::Enum {
            name: String::new(),
            variants,
            base_type: Box::new(TypeInfo::Int {
                width: 32,
                signed: false,
            }),
        }
    }
}

impl Default for StabsTypeParser {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LineNumberTable
// ---------------------------------------------------------------------------

/// A line-number table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineEntry {
    /// Absolute address.
    pub address: u64,
    /// Source line number.
    pub line: u32,
    /// Source file.
    pub file: String,
}

impl fmt::Display for LineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} @ {:#x}", self.file, self.line, self.address)
    }
}

/// A sorted line-number table derived from STABS records.
#[derive(Debug, Default)]
pub struct LineNumberTable {
    entries: Vec<LineEntry>,
}

impl LineNumberTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a line entry.
    pub fn add(&mut self, entry: LineEntry) {
        self.entries.push(entry);
    }

    /// Sort entries by address for efficient lookup.
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.address);
    }

    /// Look up the line entry at or before `addr`.
    #[must_use]
    pub fn lookup(&self, addr: u64) -> Option<&LineEntry> {
        // Binary search for the last entry with address ≤ addr.
        let pos = self.entries.partition_point(|e| e.address <= addr);
        if pos == 0 {
            None
        } else {
            self.entries.get(pos - 1)
        }
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries.
    #[must_use]
    pub fn entries(&self) -> &[LineEntry] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// FunctionInfo
// ---------------------------------------------------------------------------

/// Information about a single function extracted from STABS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Start address (`image_base` + value).
    pub address: u64,
    /// Source file at the time this function was defined.
    pub source_file: String,
    /// List of local variables (`N_LSYM` inside the function scope).
    pub locals: Vec<LocalVarInfo>,
    /// List of parameters (`N_PSYM` inside the function scope).
    pub parameters: Vec<ParameterInfo>,
    /// Line number where this function starts.
    pub start_line: u32,
}

impl fmt::Display for FunctionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fn {} @ {:#x} ({})",
            self.name, self.address, self.source_file
        )
    }
}

/// A local variable inside a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVarInfo {
    /// Variable name.
    pub name: String,
    /// Frame pointer offset (`N_LSYM` value).
    pub fp_offset: i32,
    /// Type descriptor string.
    pub type_desc: String,
}

/// A function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name.
    pub name: String,
    /// Stack offset from frame pointer.
    pub offset: i32,
    /// Type descriptor string.
    pub type_desc: String,
}

// ---------------------------------------------------------------------------
// StabsParser (higher-level)
// ---------------------------------------------------------------------------

/// Full STABS parser that builds symbol tables, type maps, and line tables.
pub struct StabsParser {
    type_parser: StabsTypeParser,
    functions: Vec<FunctionInfo>,
    globals: Vec<Symbol>,
    line_table: LineNumberTable,
}

impl StabsParser {
    /// Create a new parser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_parser: StabsTypeParser::new(),
            functions: Vec::new(),
            globals: Vec::new(),
            line_table: LineNumberTable::new(),
        }
    }

    /// Process all STABS records, populating internal tables.
    ///
    /// # Errors
    ///
    /// Returns [`StabsError`] on structural parse failures.
    pub fn process(&mut self, records: &[StabRecord], image_base: u64) -> Result<(), StabsError> {
        let mut current_file = String::new();
        let mut current_fn: Option<FunctionInfo> = None;

        for rec in records {
            match rec.stab_type {
                StabType::NSo => {
                    // Finish any in-progress function.
                    if let Some(f) = current_fn.take() {
                        self.functions.push(f);
                    }
                    if !rec.string.is_empty() {
                        current_file.clone_from(&rec.string);
                    }
                }
                StabType::NSol => {
                    // Sub-file change.
                    if !rec.string.is_empty() {
                        current_file.clone_from(&rec.string);
                    }
                }
                StabType::NFun => {
                    // Finish previous function.
                    if let Some(f) = current_fn.take() {
                        self.functions.push(f);
                    }
                    if !rec.string.is_empty() && rec.string.contains(':') {
                        let name = rec.symbol_name().to_string();
                        if !name.is_empty() {
                            current_fn = Some(FunctionInfo {
                                name,
                                address: image_base.saturating_add(u64::from(rec.value)),
                                source_file: current_file.clone(),
                                locals: Vec::new(),
                                parameters: Vec::new(),
                                start_line: u32::from(rec.desc),
                            });
                        }
                    }
                }
                StabType::NGsym => {
                    let name = rec.symbol_name().to_string();
                    if !name.is_empty() {
                        self.globals
                            .push(Symbol::new(name, u64::from(rec.value), SymKind::Data));
                    }
                }
                StabType::NStsym => {
                    let name = rec.symbol_name().to_string();
                    if !name.is_empty() {
                        let mut sym =
                            Symbol::new(name, image_base.saturating_add(u64::from(rec.value)), SymKind::Data);
                        if !current_file.is_empty() {
                            sym.source_file = Some(current_file.clone());
                        }
                        self.globals.push(sym);
                    }
                }
                StabType::NLsym => {
                    if let Some(ref mut f) = current_fn {
                        let name = rec.symbol_name().to_string();
                        let td = rec.type_descriptor().to_string();
                        if !name.is_empty() {
                            f.locals.push(LocalVarInfo {
                                name,
                                fp_offset: rec.value.cast_signed(),
                                type_desc: td,
                            });
                        }
                    }
                }
                StabType::NPsym => {
                    if let Some(ref mut f) = current_fn {
                        let name = rec.symbol_name().to_string();
                        let td = rec.type_descriptor().to_string();
                        if !name.is_empty() {
                            f.parameters.push(ParameterInfo {
                                name,
                                offset: rec.value.cast_signed(),
                                type_desc: td,
                            });
                        }
                    }
                }
                StabType::NSline => {
                    if !current_file.is_empty() {
                        let addr = sline_address(
                            current_fn.as_ref().map(|f| f.address),
                            image_base,
                            u64::from(rec.value),
                        );
                        self.line_table.add(LineEntry {
                            address: addr,
                            line: u32::from(rec.desc),
                            file: current_file.clone(),
                        });
                    }
                }
                _ => {}
            }
        }

        // Don't lose a trailing function.
        if let Some(f) = current_fn {
            self.functions.push(f);
        }

        self.line_table.sort();
        Ok(())
    }

    /// All parsed functions.
    #[must_use]
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    /// All parsed global symbols.
    #[must_use]
    pub fn globals(&self) -> &[Symbol] {
        &self.globals
    }

    /// The line-number table.
    #[must_use]
    pub const fn line_table(&self) -> &LineNumberTable {
        &self.line_table
    }

    /// Collect all symbols (functions + globals) as a flat `Vec<Symbol>`.
    #[must_use]
    pub fn all_symbols(&self) -> Vec<Symbol> {
        let mut out: Vec<Symbol> = self
            .functions
            .iter()
            .map(|f| {
                let mut s = Symbol::new(f.name.clone(), f.address, SymKind::Function);
                if !f.source_file.is_empty() {
                    s.source_file = Some(f.source_file.clone());
                }
                s
            })
            .collect();
        out.extend_from_slice(&self.globals);
        out
    }

    /// The type parser reference.
    #[must_use]
    pub const fn type_parser(&self) -> &StabsTypeParser {
        &self.type_parser
    }

    /// Mutable reference to the type parser.
    pub const fn type_parser_mut(&mut self) -> &mut StabsTypeParser {
        &mut self.type_parser
    }
}

impl Default for StabsParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared `N_SLINE` address semantics used by every parsing path in this
/// crate: `n_value` is **function-relative** when inside an `N_FUN` scope
/// (whose address already includes `image_base`), and **absolute**
/// (`image_base + value`) otherwise. All additions saturate so a hostile
/// 32-bit value combined with a large caller-supplied base cannot panic in
/// debug builds.
#[must_use]
pub fn sline_address(fn_addr: Option<u64>, image_base: u64, value: u64) -> u64 {
    fn_addr.unwrap_or(image_base).saturating_add(value)
}

// ---------------------------------------------------------------------------
// StabsProvider (SymbolProvider impl)
// ---------------------------------------------------------------------------

/// A [`SymbolProvider`] that reads STABS debug information.
#[derive(Debug)]
pub struct StabsProvider {
    /// Symbols sorted by address (enables binary-search lookups).
    symbols: Vec<Symbol>,
    /// Source-line map sorted by address.
    source_map: Vec<(u64, SourceLocation)>,
    /// Name → index into `symbols` (first occurrence wins).
    name_index: HashMap<String, usize>,
}

impl StabsProvider {
    /// Build a provider from pre-parsed STAB records.
    ///
    /// `image_base` is added to every `N_FUN` address to produce virtual addresses.
    #[must_use]
    pub fn from_records(records: &[StabRecord], image_base: u64) -> Self {
        let mut symbols = vec![];
        let mut source_map = vec![];
        let mut current_file = String::new();
        let mut current_fn_addr: Option<u64> = None;

        for rec in records {
            match rec.stab_type {
                StabType::NSo | StabType::NSol => {
                    if rec.stab_type == StabType::NSo {
                        // A new (or ending) compilation unit closes any open
                        // function scope.
                        current_fn_addr = None;
                    }
                    if !rec.string.is_empty() {
                        current_file.clone_from(&rec.string);
                    }
                }
                StabType::NFun => {
                    if !rec.string.is_empty() && rec.string.contains(':') {
                        let name = rec
                            .string
                            .split(':')
                            .next()
                            .unwrap_or(&rec.string)
                            .to_string();
                        let addr = image_base.saturating_add(u64::from(rec.value));
                        current_fn_addr = Some(addr);
                        let mut sym = Symbol::new(name, addr, SymKind::Function);
                        if !current_file.is_empty() {
                            sym.source_file = Some(current_file.clone());
                        }
                        symbols.push(sym);
                    }
                }
                StabType::NGsym => {
                    let name = rec
                        .string
                        .split(':')
                        .next()
                        .unwrap_or(&rec.string)
                        .to_string();
                    if !name.is_empty() {
                        symbols.push(Symbol::new(name, u64::from(rec.value), SymKind::Data));
                    }
                }
                StabType::NStsym => {
                    let name = split_stab_name(&rec.string).0.to_string();
                    if !name.is_empty() {
                        let mut sym =
                            Symbol::new(name, image_base.saturating_add(u64::from(rec.value)), SymKind::Data);
                        if !current_file.is_empty() {
                            sym.source_file = Some(current_file.clone());
                        }
                        symbols.push(sym);
                    }
                }
                StabType::NSline => {
                    if !current_file.is_empty() {
                        source_map.push((
                            sline_address(current_fn_addr, image_base, u64::from(rec.value)),
                            SourceLocation {
                                file: current_file.clone(),
                                line: u32::from(rec.desc),
                                column: 0,
                            },
                        ));
                    }
                }
                _ => {}
            }
        }

        // Sort once so every lookup is O(log n) instead of a linear scan.
        symbols.sort_by_key(|s| s.address);
        source_map.sort_by_key(|a| a.0);
        let mut name_index = HashMap::with_capacity(symbols.len());
        for (i, s) in symbols.iter().enumerate() {
            name_index.entry(s.name.clone()).or_insert(i);
        }
        Self {
            symbols,
            source_map,
            name_index,
        }
    }

    /// Build from raw stab and stabstr bytes.
    #[must_use]
    pub fn from_bytes(stab_data: &[u8], stabstr: &[u8], image_base: u64) -> Self {
        let records = StabRecord::parse_all(stab_data, stabstr);
        Self::from_records(&records, image_base)
    }

    /// Number of symbols extracted.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Number of source-line mappings extracted.
    #[must_use]
    pub const fn source_map_len(&self) -> usize {
        self.source_map.len()
    }

    /// All symbols sorted by address (already sorted at construction).
    #[must_use]
    pub fn symbols_sorted(&self) -> Vec<Symbol> {
        self.symbols.clone()
    }

    /// Filter symbols by kind.
    #[must_use]
    pub fn symbols_of_kind(&self, kind: SymKind) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == kind)
            .cloned()
            .collect()
    }

    /// Find symbol by name prefix.
    #[must_use]
    pub fn symbols_with_prefix(&self, prefix: &str) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.name.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl SymbolProvider for StabsProvider {
    fn name(&self) -> &'static str {
        "stabs"
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.name_index
            .get(name)
            .and_then(|&i| self.symbols.get(i))
            .cloned()
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        let i = self.symbols.partition_point(|s| s.address < addr);
        self.symbols
            .get(i)
            .filter(|s| s.address == addr)
            .cloned()
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        // Last symbol with address <= addr (symbols are sorted by address).
        let i = self.symbols.partition_point(|s| s.address <= addr);
        i.checked_sub(1).and_then(|i| self.symbols.get(i)).cloned()
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
        // Nearest mapping at or before `addr` via binary search (map sorted).
        let i = self.source_map.partition_point(|(a, _)| *a <= addr);
        i.checked_sub(1)
            .and_then(|i| self.source_map.get(i))
            .map(|(_, loc)| loc.clone())
    }
}

// ---------------------------------------------------------------------------
// StabsStringTable
// ---------------------------------------------------------------------------

/// Helper for building and querying STABS string tables.
pub struct StabsStringTable {
    data: Vec<u8>,
    index: HashMap<String, u32>,
}

impl StabsStringTable {
    /// Create an empty string table.
    #[must_use]
    pub fn new() -> Self {
        // Start with a null byte.
        Self {
            data: vec![0],
            index: HashMap::new(),
        }
    }

    /// Intern a string and return its offset.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.index.get(s) {
            return off;
        }
        let off = u32::try_from(self.data.len()).unwrap_or(u32::MAX);
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0);
        self.index.insert(s.to_string(), off);
        off
    }

    /// Look up a string at the given offset.
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

    /// Raw bytes of the string table.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Total size in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if empty (only the initial null byte).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.len() <= 1
    }
}

impl Default for StabsStringTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StabsType enum  (N_-prefix names, task §7.4)
// ---------------------------------------------------------------------------

/// STABS N_-type codes as a standalone enum.
///
/// This mirrors [`StabType`] but uses the exact names requested by the spec
/// (GSYM, FNAME, FUN, …) without the `N_` prefix so that callers can import
/// `StabsType::*` ergonomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum StabsType {
    /// `N_GSYM` — Global symbol.
    GSYM = 0x20,
    /// `N_FNAME` — Function name (Pascal/Fortran).
    FNAME = 0x22,
    /// `N_FUN` — Function or text-segment variable.
    FUN = 0x24,
    /// `N_STSYM` — Static symbol in the data segment.
    STSYM = 0x26,
    /// `N_LCSYM` — Static symbol in the BSS segment.
    LCSYM = 0x28,
    /// `N_MAIN` — Name of the main routine.
    MAIN = 0x2a,
    /// `N_ROSYM` — Read-only data symbol.
    ROSYM = 0x2c,
    /// `N_PC` — Global symbol (Pascal).
    PC = 0x30,
    /// `N_NSYMS` — Number of symbols (Ultrix).
    NSYMS = 0x32,
    /// `N_NOMAP` — No DST map.
    NOMAP = 0x34,
    /// `N_OBJ` — Object file (Solaris).
    OBJ = 0x38,
    /// `N_OPT` — Debugger options (Solaris).
    OPT = 0x3c,
    /// `N_RSYM` — Register variable.
    RSYM = 0x40,
    /// `N_SLINE` — Source line in the text segment.
    SLINE = 0x44,
    /// `N_DSLINE` — Source line in the data segment.
    DSLINE = 0x46,
    /// `N_BSLINE` — Source line in the BSS segment.
    BSLINE = 0x48,
    /// `N_SSYM` — Structure/union element.
    SSYM = 0x60,
    /// `N_ENDM` — Last stab for module (Solaris).
    ENDM = 0x62,
    /// `N_SO` — Main source file (compilation unit).
    SO = 0x64,
    /// `N_LSYM` — Local symbol (stack variable or type definition).
    LSYM = 0x80,
    /// `N_BINCL` — Begin include file.
    BINCL = 0x82,
    /// `N_SOL` — Included source file.
    SOL = 0x84,
    /// `N_PSYM` — Function parameter.
    PSYM = 0xa0,
    /// `N_EINCL` — End include file.
    EINCL = 0xa2,
    /// `N_ENTRY` — Alternate function entry point.
    ENTRY = 0xa4,
    /// `N_LBRAC` — Begin lexical block.
    LBRAC = 0xc0,
    /// `N_EXCL` — Excluded include file (deduplicated).
    EXCL = 0xc2,
    /// `N_SCOPE` — Modula-2 scope information (Sun).
    SCOPE = 0xc4,
    /// `N_RBRAC` — End lexical block.
    RBRAC = 0xe0,
    /// `N_BCOMM` — Begin common block.
    BCOMM = 0xe2,
    /// `N_ECOMM` — End common block.
    ECOMM = 0xe4,
    /// `N_ECOML` — End common block (local name).
    ECOML = 0xe8,
    /// `N_LENG` — Length of the preceding entry.
    LENG = 0xfe,
    /// Unrecognised code.
    Unknown = 0x00,
}

impl StabsType {
    /// Convert a raw byte to a [`StabsType`].
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x20 => Self::GSYM,
            0x22 => Self::FNAME,
            0x24 => Self::FUN,
            0x26 => Self::STSYM,
            0x28 => Self::LCSYM,
            0x2a => Self::MAIN,
            0x2c => Self::ROSYM,
            0x30 => Self::PC,
            0x32 => Self::NSYMS,
            0x34 => Self::NOMAP,
            0x38 => Self::OBJ,
            0x3c => Self::OPT,
            0x40 => Self::RSYM,
            0x44 => Self::SLINE,
            0x46 => Self::DSLINE,
            0x48 => Self::BSLINE,
            0x60 => Self::SSYM,
            0x62 => Self::ENDM,
            0x64 => Self::SO,
            0x80 => Self::LSYM,
            0x82 => Self::BINCL,
            0x84 => Self::SOL,
            0xa0 => Self::PSYM,
            0xa2 => Self::EINCL,
            0xa4 => Self::ENTRY,
            0xc0 => Self::LBRAC,
            0xc2 => Self::EXCL,
            0xc4 => Self::SCOPE,
            0xe0 => Self::RBRAC,
            0xe2 => Self::BCOMM,
            0xe4 => Self::ECOMM,
            0xe8 => Self::ECOML,
            0xfe => Self::LENG,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for StabsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// StabsEntry struct
// ---------------------------------------------------------------------------

/// A single raw STABS entry with resolved string.
///
/// Corresponds exactly to the 12-byte on-disk layout:
/// `n_strx` (4) | `n_type` (1) | `n_other` (1) | `n_desc` (2) | `n_value` (4)
/// plus the string resolved from the `.stabstr` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsEntry {
    /// Index into the string table (`n_strx`).
    pub n_strx: u32,
    /// Raw type byte (`n_type`).
    pub n_type: u8,
    /// Misc byte (`n_other`).
    pub n_other: u8,
    /// Descriptor / line number (`n_desc`).
    pub n_desc: i16,
    /// Value field — typically an address (`n_value`).
    pub n_value: u32,
    /// Name string resolved from the string table.
    pub string_value: String,
}

impl StabsEntry {
    /// Decoded type code as a [`StabsType`].
    #[must_use]
    pub const fn stabs_type(&self) -> StabsType {
        StabsType::from_u8(self.n_type)
    }

    /// Symbol name: everything before the first `:` in `string_value`.
    #[must_use]
    pub fn symbol_name(&self) -> &str {
        crate::split_stab_name(&self.string_value).0
    }

    /// Type descriptor: everything after the first `:` in `string_value`.
    #[must_use]
    pub fn type_descriptor(&self) -> &str {
        self.string_value.find(':').map_or("", |pos| &self.string_value[pos + 1..])
    }
}

impl fmt::Display for StabsEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} n_other={} n_desc={} n_value={:#x} '{}'",
            self.stabs_type(),
            self.n_other,
            self.n_desc,
            self.n_value,
            self.string_value
        )
    }
}

// ---------------------------------------------------------------------------
// StabsParser (low-level, byte-slice based)
// ---------------------------------------------------------------------------

/// Low-level STABS binary parser.
///
/// Reads raw `.stab` / `.stabstr` bytes and produces [`StabsEntry`] vectors.
/// For ELF files, use [`StabsParser::parse_from_elf`] which locates sections
/// automatically via goblin.
pub struct StabsLowParser;

impl StabsLowParser {
    /// Parse all 12-byte records from `stab_data`, resolving strings from
    /// `stabstr_data`.
    ///
    /// # Errors
    ///
    /// Returns [`anyhow::Error`] if the stab section length is not a multiple
    /// of 12 (strict mode: use the plain version for lenient parsing).
    pub fn parse(stab_data: &[u8], stabstr_data: &[u8]) -> anyhow::Result<Vec<StabsEntry>> {
        Self::parse_with_endian(stab_data, stabstr_data, false)
    }

    /// Like [`Self::parse`] but explicit about byte order.
    ///
    /// STABS byte order follows the containing object file. `.stab` in a
    /// big-endian ELF (SPARC, m68k, PowerPC, MIPS-BE — precisely the platforms
    /// where STABS is still encountered) was previously decoded byte-swapped,
    /// yielding garbage addresses and out-of-range string indices with no error.
    ///
    /// # Errors
    ///
    /// Returns [`anyhow::Error`] on malformed input.
    pub fn parse_with_endian(
        stab_data: &[u8],
        stabstr_data: &[u8],
        big_endian: bool,
    ) -> anyhow::Result<Vec<StabsEntry>> {
        let mut entries = Vec::with_capacity(stab_data.len() / 12);
        let mut base = cu_strings::CuStringBase::new();
        for chunk in stab_data.chunks_exact(12) {
            let b4 = |r: [u8; 4]| if big_endian { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) };
            let n_strx = b4(chunk[0..4].try_into().unwrap_or([0; 4]));
            let n_type = chunk[4];
            let n_other = chunk[5];
            let n_desc = if big_endian {
                i16::from_be_bytes([chunk[6], chunk[7]])
            } else {
                i16::from_le_bytes([chunk[6], chunk[7]])
            };
            let n_value = b4(chunk[8..12].try_into().unwrap_or([0; 4]));

            // CU-relative: resolve at the running base, then let an N_UNDF
            // header advance it past this CU's `.stabstr` slice.
            let string_value =
                String::from_utf8_lossy(base.resolve_bytes(stabstr_data, n_type, n_strx, n_value))
                    .into_owned();

            entries.push(StabsEntry {
                n_strx,
                n_type,
                n_other,
                n_desc,
                n_value,
                string_value,
            });
        }
        Ok(entries)
    }

    /// Parse entries from an ELF binary.  Uses goblin to locate `.stab` and
    /// `.stabstr` sections; returns an empty `Vec` when neither section exists.
    ///
    /// # Errors
    ///
    /// Returns [`anyhow::Error`] if goblin fails to parse the ELF header or if
    /// section data cannot be read.
    pub fn parse_from_elf(elf_data: &[u8]) -> anyhow::Result<Vec<StabsEntry>> {
        use goblin::Object;

        match Object::parse(elf_data)? {
            Object::Elf(elf) => {
                // Locate .stab and .stabstr sections
                let mut stab_bytes: &[u8] = &[];
                let mut stabstr_bytes: &[u8] = &[];

                for shdr in &elf.section_headers {
                    let name = elf.shdr_strtab.get_at(shdr.sh_name).unwrap_or("");
                    let start = usize::try_from(shdr.sh_offset).unwrap_or(usize::MAX);
                    let size = usize::try_from(shdr.sh_size).unwrap_or(0);
                    let end = start.saturating_add(size);
                    if end > elf_data.len() {
                        continue;
                    }
                    match name {
                        ".stab" => stab_bytes = &elf_data[start..end],
                        ".stabstr" => stabstr_bytes = &elf_data[start..end],
                        _ => {}
                    }
                }

                if stab_bytes.is_empty() {
                    return Ok(Vec::new());
                }
                // Honour EI_DATA rather than assuming little-endian.
                Self::parse_with_endian(stab_bytes, stabstr_bytes, !elf.little_endian)
            }
            _ => Ok(Vec::new()),
        }
    }

    // ------------------------------------------------------------------
    // internal helpers
    // ------------------------------------------------------------------

    // String resolution now lives in `cu_strings`: the record loop above
    // threads a `CuStringBase` so CU-relative `n_strx` values resolve against
    // the running per-CU `.stabstr` slice. The old absolute-offset
    // `resolve_string` helper was removed rather than left as a second,
    // divergent resolver.
}

// ---------------------------------------------------------------------------
// StabsFunction / StabsLine  (higher-level extraction results)
// ---------------------------------------------------------------------------

/// A function extracted from STABS `N_FUN` entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsFunction {
    /// Demangled/raw function name.
    pub name: String,
    /// Address from `n_value`.
    pub addr: u32,
    /// Source file active at the time of the `N_FUN` record.
    pub source_file: Option<String>,
}

impl fmt::Display for StabsFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fn {} @ {:#x}", self.name, self.addr)?;
        if let Some(ref file) = self.source_file {
            write!(f, " ({file})")?;
        }
        Ok(())
    }
}

/// A source-line mapping extracted from STABS `N_SLINE` entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsLine {
    /// PC offset (relative to enclosing `N_FUN`, or absolute if no function context).
    pub addr: u32,
    /// Source line number (`n_desc`).
    pub line_no: u16,
    /// Name of the enclosing function, if known.
    pub function: Option<String>,
}

impl fmt::Display for StabsLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {} @ {:#x}", self.line_no, self.addr)?;
        if let Some(ref fn_name) = self.function {
            write!(f, " in {fn_name}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StabsSymbolExtractor
// ---------------------------------------------------------------------------

/// High-level extractor that turns a slice of [`StabsEntry`] into typed
/// collections: functions, source files, and line-number mappings.
pub struct StabsSymbolExtractor;

impl StabsSymbolExtractor {
    /// Extract all [`StabsFunction`] items from `N_FUN` (0x24) entries.
    ///
    /// The current source file is tracked via preceding `N_SO/N_SOL` entries.
    #[must_use]
    pub fn extract_functions(entries: &[StabsEntry]) -> Vec<StabsFunction> {
        let mut fns = Vec::new();
        let mut current_file: Option<String> = None;

        for entry in entries {
            match entry.stabs_type() {
                StabsType::SO | StabsType::SOL => {
                    if !entry.string_value.is_empty() {
                        current_file = Some(entry.string_value.clone());
                    }
                }
                StabsType::FUN => {
                    let raw_name = entry.symbol_name();
                    // Empty-name N_FUN marks end-of-function in GCC output
                    if raw_name.is_empty() {
                        continue;
                    }
                    fns.push(StabsFunction {
                        name: raw_name.to_string(),
                        addr: entry.n_value,
                        source_file: current_file.clone(),
                    });
                }
                _ => {}
            }
        }
        fns
    }

    /// Extract all source file paths from `N_SO` (0x64) entries.
    ///
    /// GCC emits `N_SO` twice: once for the directory and once for the filename.
    /// Both non-empty strings are included; the caller may concatenate them.
    #[must_use]
    pub fn extract_source_files(entries: &[StabsEntry]) -> Vec<String> {
        entries
            .iter()
            .filter(|e| e.stabs_type() == StabsType::SO && !e.string_value.is_empty())
            .map(|e| e.string_value.clone())
            .collect()
    }

    /// Extract all [`StabsLine`] items from `N_SLINE` (0x44) entries.
    ///
    /// The enclosing function name is tracked via preceding `N_FUN` entries.
    #[must_use]
    pub fn extract_line_info(entries: &[StabsEntry]) -> Vec<StabsLine> {
        let mut lines = Vec::new();
        let mut current_fn: Option<String> = None;

        for entry in entries {
            match entry.stabs_type() {
                StabsType::FUN => {
                    let name = entry.symbol_name();
                    current_fn = if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    };
                }
                StabsType::SLINE => {
                    lines.push(StabsLine {
                        addr: entry.n_value,
                        line_no: entry.n_desc.cast_unsigned(),
                        function: current_fn.clone(),
                    });
                }
                _ => {}
            }
        }
        lines
    }
}

// ---------------------------------------------------------------------------
// StabsTypeParser (high-level)
// ---------------------------------------------------------------------------

/// Information decoded from a raw STABS type descriptor string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsTypeInfo {
    /// Broad kind label: `"int"`, `"float"`, `"pointer"`, `"array"`, `"struct"`,
    /// `"enum"`, `"void"`, `"subrange"`, `"ref"`, `"unknown"`, etc.
    pub kind: String,
    /// Size in bytes, if determinable.
    pub size: Option<u32>,
    /// Human-readable type name or descriptor fragment.
    pub name: Option<String>,
}

impl StabsTypeInfo {
    fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            size: None,
            name: None,
        }
    }

    const fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl fmt::Display for StabsTypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ref n) = self.name {
            write!(f, "<{n}>")?;
        }
        if let Some(sz) = self.size {
            write!(f, "[{sz}]")?;
        }
        Ok(())
    }
}

/// Standalone STABS type-descriptor parser (separate from the existing
/// [`StabsTypeParser`] which resolves into [`TypeInfo`]).
///
/// Handles the compact descriptor strings used in `name:TYPE_DESCRIPTOR`
/// pairs, e.g. `"i"` → int, `"r1;0;127;"` → subrange, `"*(0,1)"` → pointer.
pub struct StabsTypeDescParser;

impl StabsTypeDescParser {
    /// Parse a raw type descriptor string (the portion after `:` in a STABS
    /// string).  Returns [`StabsTypeInfo`] — never fails; falls back to
    /// `kind = "unknown"` for unrecognised forms.
    #[must_use]
    pub fn parse_type_desc(desc: &str) -> StabsTypeInfo {
        // Strip the leading symbol-type code, if any. STABS has exactly ONE
        // leading code character, so at most one is removed
        // (`trim_start_matches` would eat several, corrupting e.g. "ft(0,1)").
        // A bare one-character descriptor ("f" = float, "d" = double, ...) is
        // a built-in type code, not a symbol code, and must NOT be stripped.
        let desc = if desc.len() > 1 {
            desc.strip_prefix(['f', 'F', 'g', 'p', 't', 'T', 'v'])
                .unwrap_or(desc)
        } else {
            desc
        };

        // Pointer
        if let Some(__stripped) = desc.strip_prefix('*') {
            return StabsTypeInfo::new("pointer").with_name(__stripped);
        }

        // Reference (C++)
        if let Some(__stripped) = desc.strip_prefix('&') {
            return StabsTypeInfo::new("ref").with_name(__stripped);
        }

        // Array
        if desc.starts_with("ar") {
            return Self::parse_array(desc);
        }

        // Struct
        if desc.starts_with('s') || desc.starts_with("Su") {
            return Self::parse_struct(desc);
        }

        // Union
        if desc.starts_with('u') {
            return Self::parse_union(desc);
        }

        // Enum
        if desc.starts_with('e') {
            return StabsTypeInfo::new("enum");
        }

        // Subrange:  r TYPE_NUM ; LOW ; HIGH ;
        if desc.starts_with('r') {
            return Self::parse_subrange(desc);
        }

        // Named type reference: (file,num) or plain integer
        if desc.starts_with('(') {
            return StabsTypeInfo::new("ref").with_name(desc);
        }
        if desc.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return StabsTypeInfo::new("ref").with_name(desc);
        }

        // GCC built-in character codes
        match desc.chars().next() {
            Some('i') => StabsTypeInfo::new("int").with_size(4),
            Some('c') => StabsTypeInfo::new("char").with_size(1),
            Some('b' | 'B') => StabsTypeInfo::new("bool").with_size(1),
            Some('f') => StabsTypeInfo::new("float").with_size(4),
            Some('d') => StabsTypeInfo::new("double").with_size(8),
            Some('l') => StabsTypeInfo::new("long").with_size(8),
            Some('w') => StabsTypeInfo::new("void"),
            Some('x') => StabsTypeInfo::new("cross-ref").with_name(desc),
            _ => StabsTypeInfo::new("unknown").with_name(desc),
        }
    }

    // ---- private helpers ----

    fn parse_array(desc: &str) -> StabsTypeInfo {
        // ar INDEX_TYPE ; LO ; HI ; ELEM_TYPE
        let parts: Vec<&str> = desc.splitn(4, ';').collect();
        let elem_count = if parts.len() >= 3 {
            let lo: i64 = parts[1].parse().unwrap_or(0);
            let hi: i64 = parts[2].parse().unwrap_or(-1);
            (hi - lo + 1).max(0).cast_unsigned()
        } else {
            0
        };
        let elem_desc = parts.get(3).copied().unwrap_or("");
        StabsTypeInfo::new("array")
            .with_size(u32::try_from(elem_count.min(u64::from(u32::MAX))).unwrap_or(u32::MAX))
            .with_name(format!("[{elem_count}]{elem_desc}"))
    }

    fn parse_struct(desc: &str) -> StabsTypeInfo {
        // sNNfields...
        let body = desc.strip_prefix('s').unwrap_or(desc);
        let size_end = body
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(body.len());
        let size: u32 = body[..size_end].parse().unwrap_or(0);
        StabsTypeInfo::new("struct").with_size(size)
    }

    fn parse_union(desc: &str) -> StabsTypeInfo {
        let body = desc.strip_prefix('u').unwrap_or(desc);
        let size_end = body
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(body.len());
        let size: u32 = body[..size_end].parse().unwrap_or(0);
        StabsTypeInfo::new("union").with_size(size)
    }

    fn parse_subrange(desc: &str) -> StabsTypeInfo {
        // r BASE_TYPE ; LO ; HI ;
        let body = desc.strip_prefix('r').unwrap_or(desc);
        let parts: Vec<&str> = body.splitn(4, ';').collect();
        if parts.len() >= 3 {
            let lo: i64 = parts[1].parse().unwrap_or(0);
            let hi: i64 = parts[2].parse().unwrap_or(0);
            let bits: u32 = match hi - lo + 1 {
                0..=256 => 8,
                257..=65536 => 16,
                _ => 32,
            };
            StabsTypeInfo::new("subrange")
                .with_size(bits / 8)
                .with_name(format!("{lo}..{hi}"))
        } else {
            StabsTypeInfo::new("subrange")
        }
    }
}

// ---------------------------------------------------------------------------
// UnifiedSymbol / SymbolKind / SymbolSource
// ---------------------------------------------------------------------------

/// Broad symbol kind for the unified representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    /// Executable code.
    Function,
    /// Data / variable.
    Variable,
    /// Assembly label or misc named location.
    Label,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Origin of a [`UnifiedSymbol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolSource {
    /// Came from STABS debug information.
    Stabs,
}

/// A symbol in the unified representation produced by [`convert_to_symbol_table`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedSymbol {
    /// Symbol name (raw; not demangled).
    pub name: String,
    /// Virtual address.
    pub addr: u64,
    /// Broad category.
    pub kind: SymbolKind,
    /// Debug-info origin.
    pub source: SymbolSource,
}

impl fmt::Display for UnifiedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}:{}] {} @ {:#x}",
            self.source, self.kind, self.name, self.addr
        )
    }
}

// ---------------------------------------------------------------------------
// convert_to_symbol_table
// ---------------------------------------------------------------------------

/// Convert a slice of [`StabsEntry`] into a flat [`Vec<UnifiedSymbol>`].
///
/// Mapping rules:
/// - `N_FUN`   → [`SymbolKind::Function`]
/// - `N_GSYM`, `N_STSYM`, `N_LCSYM`, `N_ROSYM`, `N_LSYM`, `N_RSYM`, `N_PSYM`
///   → [`SymbolKind::Variable`]
/// - `N_ENTRY`, `N_MAIN`, `N_FNAME`
///   → [`SymbolKind::Label`]
///
/// Entries with empty names (after stripping the type descriptor) are skipped.
#[must_use]
pub fn convert_to_symbol_table(stabs: &[StabsEntry]) -> Vec<UnifiedSymbol> {
    let mut symbols = Vec::new();

    for entry in stabs {
        let kind = match entry.stabs_type() {
            StabsType::FUN => SymbolKind::Function,
            StabsType::GSYM
            | StabsType::STSYM
            | StabsType::LCSYM
            | StabsType::ROSYM
            | StabsType::LSYM
            | StabsType::RSYM
            | StabsType::PSYM
            | StabsType::SSYM => SymbolKind::Variable,
            StabsType::ENTRY | StabsType::MAIN | StabsType::FNAME => SymbolKind::Label,
            _ => continue,
        };

        let name = entry.symbol_name();
        if name.is_empty() {
            continue;
        }

        symbols.push(UnifiedSymbol {
            name: name.to_string(),
            addr: u64::from(entry.n_value),
            kind,
            source: SymbolSource::Stabs,
        });
    }

    symbols
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers ----

    /// Build a 12-byte STAB record.
    fn stab_record(strx: u32, stab_type: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&strx.to_le_bytes());
        b[4] = stab_type;
        b[5] = other;
        b[6..8].copy_from_slice(&desc.to_le_bytes());
        b[8..12].copy_from_slice(&value.to_le_bytes());
        b
    }

    /// Build a stabstr buffer from a list of strings (null-separated).
    fn build_stabstr(strings: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    // ---- StabType::from_u8 ----
    #[test]
    fn test_stab_type_known_values() {
        assert_eq!(StabType::from_u8(0x20), StabType::NGsym);
        assert_eq!(StabType::from_u8(0x24), StabType::NFun);
        assert_eq!(StabType::from_u8(0x44), StabType::NSline);
        assert_eq!(StabType::from_u8(0x64), StabType::NSo);
        assert_eq!(StabType::from_u8(0x00), StabType::NUndf);
    }

    #[test]
    fn test_stab_type_unknown() {
        assert_eq!(StabType::from_u8(0xFF), StabType::Unknown);
        assert_eq!(StabType::from_u8(0x01), StabType::Unknown);
    }

    #[test]
    fn test_stab_type_is_symbol_true() {
        assert!(StabType::NFun.is_symbol());
        assert!(StabType::NGsym.is_symbol());
        assert!(StabType::NStsym.is_symbol());
        assert!(StabType::NRsym.is_symbol());
        assert!(StabType::NPsym.is_symbol());
    }

    #[test]
    fn test_stab_type_is_symbol_false() {
        assert!(!StabType::NSo.is_symbol());
        assert!(!StabType::NSline.is_symbol());
        assert!(!StabType::Unknown.is_symbol());
    }

    #[test]
    fn test_stab_type_is_source_file() {
        assert!(StabType::NSo.is_source_file());
        assert!(StabType::NSol.is_source_file());
        assert!(StabType::NBincl.is_source_file());
        assert!(!StabType::NFun.is_source_file());
    }

    #[test]
    fn test_stab_type_is_line_number() {
        assert!(StabType::NSline.is_line_number());
        assert!(StabType::NDsline.is_line_number());
        assert!(!StabType::NFun.is_line_number());
    }

    #[test]
    fn test_stab_type_is_scope_bracket() {
        assert!(StabType::NLbrac.is_scope_bracket());
        assert!(StabType::NRbrac.is_scope_bracket());
        assert!(!StabType::NFun.is_scope_bracket());
    }

    #[test]
    fn test_stab_type_category() {
        assert_eq!(StabType::NFun.category(), "symbol");
        assert_eq!(StabType::NSo.category(), "file");
        assert_eq!(StabType::NSline.category(), "line");
        assert_eq!(StabType::NLbrac.category(), "scope");
        assert_eq!(StabType::NUndf.category(), "other");
    }

    #[test]
    fn test_stab_type_display() {
        assert_eq!(StabType::NFun.to_string(), "N_FUN");
        assert_eq!(StabType::NSo.to_string(), "N_SO");
    }

    // ---- StabRecord::parse_all ----
    #[test]
    fn test_parse_all_empty() {
        let records = StabRecord::parse_all(&[], &[]);
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_all_single_n_so() {
        let stabstr = build_stabstr(&["main.c"]);
        let raw = stab_record(0, 0x64 /* N_SO */, 0, 0, 0x1000);
        let records = StabRecord::parse_all(&raw, &stabstr);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stab_type, StabType::NSo);
        assert_eq!(records[0].string, "main.c");
        assert_eq!(records[0].value, 0x1000);
    }

    #[test]
    fn test_parse_all_multiple_records() {
        let stabstr = build_stabstr(&["src.c", "main:F(0,1)"]);
        let r1 = stab_record(0, 0x64, 0, 0, 0);
        let r2 = stab_record(6, 0x24, 0, 0, 0x1000);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].stab_type, StabType::NFun);
        assert_eq!(records[1].string, "main:F(0,1)");
    }

    #[test]
    fn test_parse_all_strx_out_of_bounds() {
        let stabstr = b"hello\0";
        let raw = stab_record(9999, 0x20, 0, 0, 0);
        let records = StabRecord::parse_all(&raw, stabstr);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].string, "");
    }

    #[test]
    fn test_parse_all_ignores_incomplete_chunk() {
        let raw = vec![0u8; 11];
        let records = StabRecord::parse_all(&raw, &[]);
        assert!(records.is_empty());
    }

    // ---- StabRecord display ----
    #[test]
    fn test_stab_record_display() {
        let r = StabRecord {
            strx: 0,
            stab_type: StabType::NFun,
            other: 0,
            desc: 0,
            value: 0x1000,
            string: "main:F".to_string(),
        };
        let s = r.to_string();
        assert!(s.contains("N_FUN"));
        assert!(s.contains("0x1000"));
        assert!(s.contains("main:F"));
    }

    #[test]
    fn test_stab_record_symbol_name() {
        let r = StabRecord {
            strx: 0,
            stab_type: StabType::NFun,
            other: 0,
            desc: 0,
            value: 0,
            string: "myfn:F(0,1)".to_string(),
        };
        assert_eq!(r.symbol_name(), "myfn");
        assert_eq!(r.type_descriptor(), "F(0,1)");
        assert!(r.has_string());
    }

    // ---- StabsProvider ----
    #[test]
    fn test_provider_empty_records() {
        let p = StabsProvider::from_records(&[], 0);
        assert_eq!(p.symbol_count(), 0);
        assert_eq!(p.source_map_len(), 0);
        assert_eq!(p.name(), "stabs");
    }

    #[test]
    fn test_provider_n_fun() {
        let stabstr = build_stabstr(&["", "foo:F(0,1)"]);
        let r1 = stab_record(0, 0x64, 0, 0, 0);
        let r2 = stab_record(1, 0x24, 0, 0, 0x2000);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0x400000);
        assert_eq!(p.symbol_count(), 1);
        let sym = p.all_symbols()[0].clone();
        assert_eq!(sym.name, "foo");
        assert_eq!(sym.address, 0x400000 + 0x2000);
        assert_eq!(sym.kind, SymKind::Function);
    }

    #[test]
    fn test_provider_n_gsym() {
        let stabstr = build_stabstr(&["g_var:G(0,1)"]);
        let raw = stab_record(0, 0x20 /* N_GSYM */, 0, 0, 0);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert_eq!(p.symbol_count(), 1);
        assert_eq!(p.all_symbols()[0].name, "g_var");
        assert_eq!(p.all_symbols()[0].kind, SymKind::Data);
    }

    #[test]
    fn test_provider_n_sline() {
        let stabstr = build_stabstr(&["main.c", "main:F"]);
        let r_so = stab_record(0, 0x64, 0, 0, 0);
        let r_fun = stab_record(7, 0x24, 0, 0, 0x1000);
        // N_SLINE value is function-relative (see `sline_address`): 0x1000 + 8.
        let r_sline = stab_record(0, 0x44, 0, 42, 0x8);
        let mut raw = r_so.to_vec();
        raw.extend_from_slice(&r_fun);
        raw.extend_from_slice(&r_sline);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert_eq!(p.source_map_len(), 1);
        let loc = p.source_line_for_address(0x1008).unwrap();
        assert_eq!(loc.line, 42);
        assert_eq!(loc.file, "main.c");
    }

    #[test]
    fn test_provider_lookup_name() {
        let stabstr = build_stabstr(&["bar:F(0,1)"]);
        let raw = stab_record(0, 0x24, 0, 0, 0x300);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert!(p.lookup_name("bar").is_some());
        assert!(p.lookup_name("baz").is_none());
    }

    #[test]
    fn test_provider_lookup_address() {
        let stabstr = build_stabstr(&["fn1:F"]);
        let raw = stab_record(0, 0x24, 0, 0, 0x5000);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0x100000);
        assert!(p.lookup_address(0x100000 + 0x5000).is_some());
        assert!(p.lookup_address(0).is_none());
    }

    #[test]
    fn test_provider_lookup_nearest() {
        let stabstr = build_stabstr(&["a:F", "b:F"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x1000);
        let r2 = stab_record(4, 0x24, 0, 0, 0x3000);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        let nearest = p.lookup_nearest(0x2000).unwrap();
        assert_eq!(nearest.name, "a");
    }

    #[test]
    fn test_provider_all_functions() {
        let stabstr = build_stabstr(&["fn:F", "global:G"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x100);
        let r2 = stab_record(5, 0x20, 0, 0, 0);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        let fns = p.all_functions();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].kind, SymKind::Function);
    }

    #[test]
    fn test_provider_source_line_none_when_no_map() {
        let p = StabsProvider::from_records(&[], 0);
        assert!(p.source_line_for_address(0x1000).is_none());
    }

    #[test]
    fn test_stabs_error_display() {
        assert!(StabsError::InvalidRecord(3).to_string().contains('3'));
        assert!(
            StabsError::StringTable("oob".to_string())
                .to_string()
                .contains("oob")
        );
        assert!(
            StabsError::Parse("bad".to_string())
                .to_string()
                .contains("bad")
        );
        assert!(
            StabsError::TypeParse("bad".to_string())
                .to_string()
                .contains("type")
        );
    }

    #[test]
    fn test_stab_source_file_attached_to_function() {
        let stabstr = build_stabstr(&["hello.c", "myfn:F"]);
        let r_so = stab_record(0, 0x64, 0, 0, 0);
        let r_fun = stab_record(8, 0x24, 0, 0, 0x100);
        let mut raw = r_so.to_vec();
        raw.extend_from_slice(&r_fun);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        let sym = p.lookup_name("myfn").unwrap();
        assert_eq!(sym.source_file.as_deref(), Some("hello.c"));
    }

    #[test]
    fn test_provider_name_is_stabs() {
        let p = StabsProvider::from_records(&[], 0);
        assert_eq!(p.name(), "stabs");
    }

    #[test]
    fn test_stab_type_full_coverage_n_undf() {
        assert_eq!(StabType::from_u8(0x00), StabType::NUndf);
    }

    #[test]
    fn test_stab_type_all_32_variants_known() {
        let known: &[u8] = &[
            0x00, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x30, 0x32, 0x34, 0x38, 0x3C, 0x40,
            0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x50, 0x54, 0x60, 0x62, 0x64, 0x80, 0x82, 0x84,
            0xA0, 0xA2, 0xA4, 0xC0, 0xC2, 0xC4, 0xE0, 0xE2, 0xE4, 0xE8, 0xEA, 0xF0, 0xF2, 0xF4,
            0xF6, 0xF8,
        ];
        for &v in known {
            assert_ne!(
                StabType::from_u8(v),
                StabType::Unknown,
                "code {v:#x} should be known"
            );
        }
    }

    #[test]
    fn test_parse_all_preserves_other_and_desc() {
        let raw = stab_record(0, 0x64, 7, 99, 0x1000);
        let records = StabRecord::parse_all(&raw, b"\0");
        assert_eq!(records[0].other, 7);
        assert_eq!(records[0].desc, 99);
    }

    #[test]
    fn test_provider_all_symbols_returns_all_kinds() {
        let stabstr = build_stabstr(&["fn:F", "gv:G"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x100);
        let r2 = stab_record(5, 0x20, 0, 0, 0x200);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert_eq!(p.all_symbols().len(), 2);
    }

    #[test]
    fn test_n_fun_without_colon_ignored() {
        let stabstr = build_stabstr(&["nocolon"]);
        let raw = stab_record(0, 0x24, 0, 0, 0x400);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert_eq!(p.symbol_count(), 0);
    }

    // ---- StabsTypeParser ----

    #[test]
    fn test_type_parser_primitives() {
        let p = StabsTypeParser::new();
        assert!(matches!(
            p.lookup("(0,1)"),
            Some(TypeInfo::Int {
                width: 32,
                signed: true
            })
        ));
        assert!(matches!(p.lookup("(0,14)"), Some(TypeInfo::Void)));
        assert!(matches!(
            p.lookup("(0,9)"),
            Some(TypeInfo::Float { width: 32 })
        ));
    }

    #[test]
    fn test_type_parser_register_custom() {
        let mut p = StabsTypeParser::new();
        p.register("(5,1)".to_string(), TypeInfo::Bool);
        assert!(matches!(p.lookup("(5,1)"), Some(TypeInfo::Bool)));
    }

    #[test]
    fn test_type_parser_len() {
        let p = StabsTypeParser::new();
        assert!(!p.is_empty());
        assert!(!p.is_empty());
    }

    #[test]
    fn test_type_parser_pointer() {
        let p = StabsTypeParser::new();
        let t = p.parse_descriptor("*(0,1)").unwrap();
        assert!(matches!(t, TypeInfo::Pointer { .. }));
    }

    #[test]
    fn test_type_parser_array() {
        let p = StabsTypeParser::new();
        // ar(index);0;9;(0,1)
        let t = p.parse_descriptor("ar(0,1);0;9;(0,1)").unwrap();
        assert!(matches!(t, TypeInfo::Array { count: 10, .. }));
    }

    #[test]
    fn test_type_parser_struct() {
        let p = StabsTypeParser::new();
        let t = p
            .parse_descriptor("s12x:(0,1),0,32;y:(0,1),32,32;")
            .unwrap();
        if let TypeInfo::Struct { fields, .. } = t {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].name, "x");
            assert_eq!(fields[1].name, "y");
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_type_parser_enum() {
        let p = StabsTypeParser::new();
        let t = p.parse_descriptor("eRed:0,Green:1,Blue:2;").unwrap();
        if let TypeInfo::Enum { variants, .. } = t {
            assert_eq!(variants.len(), 3);
            assert_eq!(variants[0].0, "Red");
            assert_eq!(variants[1].1, 1);
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn test_type_parser_empty_descriptor() {
        let p = StabsTypeParser::new();
        let t = p.parse_descriptor("").unwrap();
        assert!(matches!(t, TypeInfo::Unknown));
    }

    // ---- LineNumberTable ----

    #[test]
    fn test_line_table_empty() {
        let t = LineNumberTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.lookup(0x1000).is_none());
    }

    #[test]
    fn test_line_table_lookup() {
        let mut t = LineNumberTable::new();
        t.add(LineEntry {
            address: 0x1000,
            line: 10,
            file: "a.c".to_string(),
        });
        t.add(LineEntry {
            address: 0x1010,
            line: 15,
            file: "a.c".to_string(),
        });
        t.sort();
        let e = t.lookup(0x1008).unwrap();
        assert_eq!(e.line, 10);
    }

    #[test]
    fn test_line_table_before_first() {
        let mut t = LineNumberTable::new();
        t.add(LineEntry {
            address: 0x1000,
            line: 1,
            file: "f.c".to_string(),
        });
        t.sort();
        assert!(t.lookup(0x100).is_none());
    }

    #[test]
    fn test_line_entry_display() {
        let e = LineEntry {
            address: 0x1234,
            line: 42,
            file: "foo.c".to_string(),
        };
        assert!(e.to_string().contains("42"));
        assert!(e.to_string().contains("foo.c"));
    }

    // ---- StabsParser ----

    #[test]
    fn test_stabs_parser_n_fun() {
        let stabstr = build_stabstr(&["main.c", "main:F(0,1)"]);
        let r_so = stab_record(0, 0x64, 0, 0, 0);
        let r_fun = stab_record(7, 0x24, 0, 5, 0x1000);
        let mut raw = r_so.to_vec();
        raw.extend_from_slice(&r_fun);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let mut parser = StabsParser::new();
        parser.process(&records, 0x400000).unwrap();
        assert_eq!(parser.functions().len(), 1);
        assert_eq!(parser.functions()[0].name, "main");
        assert_eq!(parser.functions()[0].start_line, 5);
    }

    #[test]
    fn test_stabs_parser_globals() {
        let stabstr = build_stabstr(&["gvar:G(0,1)"]);
        let raw = stab_record(0, 0x20, 0, 0, 0x2000);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let mut parser = StabsParser::new();
        parser.process(&records, 0).unwrap();
        assert_eq!(parser.globals().len(), 1);
        assert_eq!(parser.globals()[0].name, "gvar");
    }

    #[test]
    fn test_stabs_parser_all_symbols() {
        let stabstr = build_stabstr(&["fn:F", "gv:G"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x100);
        let r2 = stab_record(5, 0x20, 0, 0, 0x200);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let mut parser = StabsParser::new();
        parser.process(&records, 0).unwrap();
        assert_eq!(parser.all_symbols().len(), 2);
    }

    // ---- StabsStringTable ----

    #[test]
    fn test_string_table_intern_and_get() {
        let mut t = StabsStringTable::new();
        let off = t.intern("hello");
        assert_eq!(t.get(off), "hello");
    }

    #[test]
    fn test_string_table_dedup() {
        let mut t = StabsStringTable::new();
        let o1 = t.intern("world");
        let o2 = t.intern("world");
        assert_eq!(o1, o2);
    }

    #[test]
    fn test_string_table_len() {
        let mut t = StabsStringTable::new();
        assert!(t.is_empty());
        t.intern("x");
        assert!(!t.is_empty());
        assert!(t.len() > 1);
    }

    #[test]
    fn test_string_table_oob() {
        let t = StabsStringTable::new();
        assert_eq!(t.get(9999), "");
    }

    // ---- StabTypeCode ----

    #[test]
    fn test_stab_type_code_from_char() {
        assert!(matches!(
            StabTypeCode::from_char('f'),
            StabTypeCode::Function
        ));
        assert!(matches!(
            StabTypeCode::from_char('F'),
            StabTypeCode::GlobalFunction
        ));
        assert!(matches!(
            StabTypeCode::from_char('g'),
            StabTypeCode::GlobalVar
        ));
        assert!(matches!(
            StabTypeCode::from_char('t'),
            StabTypeCode::Typedef
        ));
        assert!(matches!(StabTypeCode::from_char('T'), StabTypeCode::Tag));
        assert!(matches!(
            StabTypeCode::from_char('X'),
            StabTypeCode::Other('X')
        ));
    }

    #[test]
    fn test_stab_type_code_display() {
        assert_eq!(StabTypeCode::Function.to_string(), "Function");
        assert_eq!(StabTypeCode::Other('Z').to_string(), "Other(Z)");
    }

    // ---- StabsProvider symbols_sorted / symbols_of_kind / symbols_with_prefix ----

    #[test]
    fn test_provider_symbols_sorted() {
        let stabstr = build_stabstr(&["z_fn:F", "a_fn:F"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x3000);
        let r2 = stab_record(7, 0x24, 0, 0, 0x1000);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        let sorted = p.symbols_sorted();
        assert!(sorted[0].address <= sorted[1].address);
    }

    #[test]
    fn test_provider_symbols_of_kind() {
        let stabstr = build_stabstr(&["fn:F", "gv:G"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x100);
        let r2 = stab_record(5, 0x20, 0, 0, 0x200);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        assert_eq!(p.symbols_of_kind(SymKind::Function).len(), 1);
        assert_eq!(p.symbols_of_kind(SymKind::Data).len(), 1);
    }

    #[test]
    fn test_provider_symbols_with_prefix() {
        let stabstr = build_stabstr(&["my_func:F", "my_data:G", "other:F"]);
        let r1 = stab_record(0, 0x24, 0, 0, 0x100);
        let r2 = stab_record(10, 0x20, 0, 0, 0x200);
        let r3 = stab_record(20, 0x24, 0, 0, 0x300);
        let mut raw = r1.to_vec();
        raw.extend_from_slice(&r2);
        raw.extend_from_slice(&r3);
        let records = StabRecord::parse_all(&raw, &stabstr);
        let p = StabsProvider::from_records(&records, 0);
        let prefixed = p.symbols_with_prefix("my_");
        assert_eq!(prefixed.len(), 2);
    }

    // ---- from_bytes constructor ----
    #[test]
    fn test_provider_from_bytes() {
        let stabstr = build_stabstr(&["main.c", "fn:F"]);
        let r_so = stab_record(0, 0x64, 0, 0, 0);
        let r_fun = stab_record(7, 0x24, 0, 0, 0x100);
        let mut raw = r_so.to_vec();
        raw.extend_from_slice(&r_fun);
        let p = StabsProvider::from_bytes(&raw, &stabstr, 0x400000);
        assert_eq!(p.symbol_count(), 1);
    }
}

// ---------------------------------------------------------------------------
// StabsKind
// ---------------------------------------------------------------------------

/// High-level kind of a STABS symbol produced by [`StabsSymbolParser`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabsKind {
    /// `N_FUN` — function definition.
    Function,
    /// `N_GSYM` / `N_STSYM` — global or static symbol.
    Global,
    /// `N_LSYM` — local (stack) variable.
    Local,
    /// `N_SO` / `N_SOL` — source file marker.
    SourceFile,
    /// `N_SLINE` — source line number.
    SourceLine,
    /// Any other stab type.
    Other,
}

// ---------------------------------------------------------------------------
// StabsSymbol
// ---------------------------------------------------------------------------

/// A decoded symbol produced by [`StabsSymbolParser`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsSymbol {
    /// Semantic kind of this stab entry.
    pub kind: StabsKind,
    /// Symbol name (may be empty for non-named entries).
    pub name: String,
    /// Value field (address or frame offset depending on kind).
    pub value: u64,
    /// Source file at the point of this entry, if available.
    pub source_file: Option<String>,
    /// Source line number for `N_SLINE` entries (or function start line).
    pub line: Option<u32>,
}

// ---------------------------------------------------------------------------
// StabsSymbolParser
// ---------------------------------------------------------------------------

/// Parses STABS debug-format entries into [`StabsSymbol`] records.
///
/// The input is a slice of 5-tuples mirroring the raw STABS on-disk layout:
/// `(strx, n_type, desc, reserved, value)`.  Strings are passed as `&str`
/// slices already resolved from the `.stabstr` section.
///
/// # Example
/// ```ignore
/// let entries: Vec<(u32, u8, u16, u32, &str)> = vec![
///     (0, 0x64, 0, 0, "main.c"),   // N_SO
///     (0, 0x24, 1, 0, "foo:F"),    // N_FUN  (line 1)
///     (0, 0x44, 5, 0, ""),         // N_SLINE (offset 0, line 5)
/// ];
/// let syms = StabsSymbolParser::parse(&entries);
/// ```
pub struct StabsSymbolParser;

impl StabsSymbolParser {
    /// Parse a slice of raw STAB entries into `Vec<StabsSymbol>`.
    ///
    /// Each tuple is `(strx, n_type, desc, value_u32, name_str)` where the
    /// `name_str` is already resolved from the string table.
    #[must_use]
    pub fn parse(stab_entries: &[(u32, u8, u16, u32, &str)]) -> Vec<StabsSymbol> {
        let mut out = Vec::with_capacity(stab_entries.len());
        let mut current_file: Option<String> = None;
        let mut current_fn_addr: u64 = 0;

        for &(_, n_type, desc, value, name_str) in stab_entries {
            let stab_type = StabType::from_u8(n_type);
            let value64 = u64::from(value);
            Self::process_entry(stab_type, desc, value64, name_str, &mut out, &mut current_file, &mut current_fn_addr);
        }
        out
    }

    fn process_entry(
        stab_type: StabType,
        desc: u16,
        value64: u64,
        name_str: &str,
        out: &mut Vec<StabsSymbol>,
        current_file: &mut Option<String>,
        current_fn_addr: &mut u64,
    ) {
        match stab_type {
            StabType::NSo => {
                let file_name = name_str.to_owned();
                if !file_name.is_empty() {
                    *current_file = Some(file_name.clone());
                }
                out.push(StabsSymbol {
                    kind: StabsKind::SourceFile,
                    name: file_name,
                    value: value64,
                    source_file: None,
                    line: None,
                });
            }
            StabType::NSol => {
                if !name_str.is_empty() {
                    *current_file = Some(name_str.to_owned());
                }
                out.push(StabsSymbol {
                    kind: StabsKind::SourceFile,
                    name: name_str.to_owned(),
                    value: value64,
                    source_file: current_file.clone(),
                    line: None,
                });
            }
            StabType::NFun => {
                let sym_name = crate::split_stab_name(name_str).0.to_owned();
                *current_fn_addr = value64;
                if !sym_name.is_empty() {
                    out.push(StabsSymbol {
                        kind: StabsKind::Function,
                        name: sym_name,
                        value: value64,
                        source_file: current_file.clone(),
                        line: if desc != 0 { Some(u32::from(desc)) } else { None },
                    });
                }
            }
            StabType::NGsym | StabType::NStsym => {
                let sym_name = crate::split_stab_name(name_str).0.to_owned();
                if !sym_name.is_empty() {
                    out.push(StabsSymbol {
                        kind: StabsKind::Global,
                        name: sym_name,
                        value: value64,
                        source_file: current_file.clone(),
                        line: None,
                    });
                }
            }
            StabType::NLsym => {
                let sym_name = crate::split_stab_name(name_str).0.to_owned();
                if !sym_name.is_empty() {
                    out.push(StabsSymbol {
                        kind: StabsKind::Local,
                        name: sym_name,
                        value: value64,
                        source_file: current_file.clone(),
                        line: None,
                    });
                }
            }
            StabType::NSline => {
                let addr = current_fn_addr.saturating_add(value64);
                out.push(StabsSymbol {
                    kind: StabsKind::SourceLine,
                    name: String::new(),
                    value: addr,
                    source_file: current_file.clone(),
                    line: Some(u32::from(desc)),
                });
            }
            _ => {
                if !name_str.is_empty() {
                    out.push(StabsSymbol {
                        kind: StabsKind::Other,
                        name: name_str.to_owned(),
                        value: value64,
                        source_file: current_file.clone(),
                        line: if desc != 0 { Some(u32::from(desc)) } else { None },
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StabsToSourceMap
// ---------------------------------------------------------------------------

/// Converts STABS `N_SLINE` entries into an address → (file, line) map.
///
/// The map is sorted by address so that range queries with
/// [`StabsToSourceMap::lookup`] are O(log n).
#[derive(Debug, Default)]
pub struct StabsToSourceMap {
    /// Sorted (address, file, line) triples.
    entries: Vec<(u64, String, u32)>,
}

impl StabsToSourceMap {
    /// Build a source map from a previously parsed list of [`StabsSymbol`].
    #[must_use]
    pub fn from_symbols(symbols: &[StabsSymbol]) -> Self {
        let mut entries: Vec<(u64, String, u32)> = symbols
            .iter()
            .filter(|s| s.kind == StabsKind::SourceLine)
            .filter_map(|s| {
                let file = s.source_file.clone()?;
                let line = s.line?;
                Some((s.value, file, line))
            })
            .collect();
        entries.sort_by_key(|(addr, _, _)| *addr);
        Self { entries }
    }

    /// Build directly from raw STAB entry tuples (same format as
    /// [`StabsSymbolParser::parse`]).
    #[must_use]
    pub fn from_stab_entries(stab_entries: &[(u32, u8, u16, u32, &str)]) -> Self {
        let syms = StabsSymbolParser::parse(stab_entries);
        Self::from_symbols(&syms)
    }

    /// Look up the (file, line) pair for `addr`.
    ///
    /// Returns the entry with the largest address that is ≤ `addr`, mirroring
    /// the standard DWARF line-table semantics.
    #[must_use]
    pub fn lookup(&self, addr: u64) -> Option<(&str, u32)> {
        let pos = self.entries.partition_point(|(a, _, _)| *a <= addr);
        if pos == 0 {
            return None;
        }
        let (_, file, line) = &self.entries[pos - 1];
        Some((file.as_str(), *line))
    }

    /// Number of entries in the map.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All raw entries as `(address, file, line)` slices.
    #[must_use]
    pub fn entries(&self) -> &[(u64, String, u32)] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Tests for StabsSymbolParser and StabsToSourceMap
// ---------------------------------------------------------------------------

#[cfg(test)]
mod stabs_symbol_parser_tests {
    use super::*;

    fn make_entries<'a>(
        tuples: &[(&'a str, u8, u16, u32, &'a str)],
    ) -> Vec<(u32, u8, u16, u32, &'a str)> {
        tuples
            .iter()
            .map(|&(_, t, d, v, s)| (0u32, t, d, v, s))
            .collect()
    }

    #[test]
    fn test_parse_n_so() {
        let entries = make_entries(&[("", 0x64, 0, 0, "foo.c")]);
        let syms = StabsSymbolParser::parse(&entries);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].kind, StabsKind::SourceFile);
        assert_eq!(syms[0].name, "foo.c");
    }

    #[test]
    fn test_parse_n_fun() {
        let entries = make_entries(&[
            ("", 0x64, 0, 0, "main.c"),
            ("", 0x24, 10, 0x1000, "my_func:F"),
        ]);
        let syms = StabsSymbolParser::parse(&entries);
        let fn_sym = syms.iter().find(|s| s.kind == StabsKind::Function).unwrap();
        assert_eq!(fn_sym.name, "my_func");
        assert_eq!(fn_sym.value, 0x1000);
        assert_eq!(fn_sym.line, Some(10));
        assert_eq!(fn_sym.source_file.as_deref(), Some("main.c"));
    }

    #[test]
    fn test_parse_n_gsym() {
        let entries = make_entries(&[("", 0x20, 0, 0x2000, "g_var:G")]);
        let syms = StabsSymbolParser::parse(&entries);
        assert_eq!(syms[0].kind, StabsKind::Global);
        assert_eq!(syms[0].name, "g_var");
    }

    #[test]
    fn test_parse_n_lsym() {
        let entries = make_entries(&[
            ("", 0x64, 0, 0, "src.c"),
            ("", 0x24, 0, 0x100, "fn:F"),
            ("", 0x80, 0, 0xFFFFFFE0, "local_x:(0,1)"),
        ]);
        let syms = StabsSymbolParser::parse(&entries);
        let local = syms.iter().find(|s| s.kind == StabsKind::Local).unwrap();
        assert_eq!(local.name, "local_x");
    }

    #[test]
    fn test_parse_n_sline_addr_calculation() {
        // N_FUN sets fn base; N_SLINE value is offset from that base.
        let entries = make_entries(&[
            ("", 0x64, 0, 0, "x.c"),
            ("", 0x24, 1, 0x4000, "xfn:F"),
            ("", 0x44, 5, 0x10, ""),
        ]);
        let syms = StabsSymbolParser::parse(&entries);
        let sline = syms
            .iter()
            .find(|s| s.kind == StabsKind::SourceLine)
            .unwrap();
        assert_eq!(sline.value, 0x4010);
        assert_eq!(sline.line, Some(5));
    }

    #[test]
    fn test_parse_empty() {
        let syms = StabsSymbolParser::parse(&[]);
        assert!(syms.is_empty());
    }

    #[test]
    fn test_source_map_lookup_basic() {
        let entries = make_entries(&[
            ("", 0x64, 0, 0, "a.c"),
            ("", 0x24, 0, 0x1000, "f:F"),
            ("", 0x44, 10, 0, ""),
            ("", 0x44, 20, 0x20, ""),
            ("", 0x44, 30, 0x40, ""),
        ]);
        let map = StabsToSourceMap::from_stab_entries(&entries);
        assert_eq!(map.len(), 3);
        let (file, line) = map.lookup(0x1028).unwrap();
        assert_eq!(file, "a.c");
        assert_eq!(line, 20);
    }

    #[test]
    fn test_source_map_lookup_exact() {
        let entries = make_entries(&[
            ("", 0x64, 0, 0, "b.c"),
            ("", 0x24, 0, 0x2000, "g:F"),
            ("", 0x44, 7, 0, ""),
        ]);
        let map = StabsToSourceMap::from_stab_entries(&entries);
        let (file, line) = map.lookup(0x2000).unwrap();
        assert_eq!(file, "b.c");
        assert_eq!(line, 7);
    }

    #[test]
    fn test_source_map_lookup_miss() {
        let map = StabsToSourceMap::default();
        assert!(map.lookup(0xDEAD).is_none());
    }

    #[test]
    fn test_stabs_kind_variants() {
        assert_ne!(StabsKind::Function, StabsKind::Global);
        assert_ne!(StabsKind::Local, StabsKind::SourceLine);
    }

    #[test]
    fn test_source_map_from_symbols() {
        let syms = vec![StabsSymbol {
            kind: StabsKind::SourceLine,
            name: String::new(),
            value: 0x100,
            source_file: Some("c.c".to_owned()),
            line: Some(42),
        }];
        let map = StabsToSourceMap::from_symbols(&syms);
        assert_eq!(map.len(), 1);
        let (f, l) = map.lookup(0x100).unwrap();
        assert_eq!(f, "c.c");
        assert_eq!(l, 42);
    }
}
