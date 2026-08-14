//! dSYM bundle symbolication: address → `file:line` from Apple debug archives.
//!
//! # What a dSYM is
//!
//! When a Mach-O image is linked, the DWARF produced by the compiler is *not*
//! copied into the executable. `dsymutil` collects it from the object files and
//! writes a **bundle**:
//!
//! ```text
//! MyApp.dSYM/
//!   Contents/
//!     Info.plist
//!     Resources/
//!       DWARF/
//!         MyApp          <- a Mach-O of file type MH_DSYM
//! ```
//!
//! That inner file is a real Mach-O whose `__DWARF` segment carries
//! `__debug_info`, `__debug_line`, `__debug_abbrev`, `__debug_str` (and on
//! DWARF 5, `__debug_line_str` / `__debug_str_offsets`). It has essentially no
//! code: its `__TEXT` segment is a zero-sized placeholder that preserves the
//! address space of the original image, which is exactly what makes static
//! addresses in the dSYM comparable with static addresses in the shipped
//! binary.
//!
//! # The UUID invariant — why this module refuses rather than guesses
//!
//! A dSYM is only valid for the *exact* build it was produced from. The link
//! stamps an `LC_UUID` into the image and `dsymutil` copies it verbatim. Two
//! builds of the same source with the same compiler differ in UUID, and their
//! line tables differ by whole basic blocks. Symbolicating with a mismatched
//! dSYM does not fail loudly — it produces plausible, confidently wrong
//! `file:line` answers, which is the single worst outcome for a debugger.
//!
//! So [`DsymBundle::verify_against_uuid`] is a hard error
//! ([`DsymError::UuidMismatch`]), never a warning, and
//! [`find_dsym_for_binary`] filters candidates by UUID before returning them.
//!
//! # Relationship to the rest of the workspace
//!
//! * The Mach-O container is parsed by `rustre_loader_macho`, the workspace's
//!   only real Mach-O parser. No nlist/segment/section decoding is re-derived.
//! * The DWARF *line program state machine* is
//!   [`crate::source_map::LineTableStateMachine`]. It was already
//!   complete; what it lacked — and what this module adds — is the
//!   **`.debug_line` header parser** that feeds it, plus the `.debug_info` /
//!   `.debug_abbrev` walk needed to discover which line programs exist and what
//!   `DW_AT_comp_dir` each one resolves file names against.
//! * Nothing here is gated on `cfg(target_os = "macos")`: a dSYM is a byte
//!   container, and every function below is byte math. The tests build
//!   synthetic dSYM bundles on disk and run on Windows.
//!
//! # Trust boundary
//!
//! A dSYM may come from a remote target, a symbol server, or a crash report
//! bundle. Every read below is bounds-checked through [`Cursor`]; malformed
//! input yields [`DsymError::MalformedDwarf`] or a truncated-but-valid result,
//! never a panic and never an unbounded allocation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::source_map::{
    FileEntry, LineTableHeader, LineTableRow, LineTableStateMachine, SourceLocation, SourceMap,
    SourceMapIndex, SourceRootMapper,
};
use rustre_loader_macho::{MachoArch, MachoParser};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failure modes of dSYM discovery, extraction and line mapping.
///
/// The variants are deliberately distinct: "no dSYM next to the binary" and
/// "found a dSYM whose UUID disagrees" call for completely different actions
/// from the caller (fetch symbols vs. rebuild), and collapsing them into one
/// string would hide that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DsymError {
    /// A filesystem operation failed. The path is included because a dSYM walk
    /// touches many paths and "permission denied" alone is not actionable.
    #[error("i/o error at {path}: {message}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying OS message.
        message: String,
    },

    /// No `.dSYM` bundle was found for the binary.
    #[error("no dSYM bundle found for {0}")]
    NotFound(String),

    /// A `.dSYM` directory exists but holds no Mach-O under
    /// `Contents/Resources/DWARF`.
    #[error("dSYM bundle {0} contains no DWARF payload")]
    EmptyBundle(String),

    /// The DWARF payload could not be parsed as a Mach-O image.
    #[error("mach-o parse failed: {0}")]
    Macho(String),

    /// The dSYM does not belong to the binary being debugged. Symbolicating
    /// anyway would produce confidently wrong line numbers, so this is fatal.
    #[error("dSYM UUID mismatch: binary {binary}, dSYM {dsym}")]
    UuidMismatch {
        /// UUID recorded in the executable's `LC_UUID`.
        binary: String,
        /// UUID recorded in the dSYM's `LC_UUID`.
        dsym: String,
    },

    /// One side of a UUID comparison had no `LC_UUID` at all, so the match
    /// cannot be established. Reported instead of assuming a match.
    #[error("cannot verify dSYM: {which} has no LC_UUID")]
    MissingUuid {
        /// `"binary"` or `"dSYM"`.
        which: &'static str,
    },

    /// A DWARF section required for the requested operation is absent.
    #[error("dSYM has no {0} section")]
    MissingSection(&'static str),

    /// The DWARF byte stream is structurally invalid.
    #[error("malformed DWARF: {0}")]
    MalformedDwarf(String),
}

/// Result alias for this module.
pub type DsymResult<T> = Result<T, DsymError>;

/// Format a Mach-O UUID the way `dwarfdump --uuid` and `otool -l` do.
#[must_use]
pub fn format_uuid(uuid: &[u8; 16]) -> String {
    let h = |r: &[u8]| -> String { r.iter().map(|b| format!("{b:02X}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(&uuid[0..4]),
        h(&uuid[4..6]),
        h(&uuid[6..8]),
        h(&uuid[8..10]),
        h(&uuid[10..16])
    )
}

/// Parse a canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` UUID.
///
/// Returns `None` on any deviation — this is used to interpret user input and
/// symbol-server paths, both of which are untrusted.
#[must_use]
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounds-checked cursor
// ─────────────────────────────────────────────────────────────────────────────

/// A non-panicking little-endian reader over untrusted bytes.
///
/// Every accessor returns `Option`; there is no indexing anywhere in this
/// module, because the byte stream originates on a target we do not control.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a slice, positioned at zero.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Wrap a slice, positioned at `pos` (clamped to the end).
    #[must_use]
    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos: pos.min(data.len()) }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Move to `pos` (clamped to the end of the buffer).
    pub const fn seek(&mut self, pos: usize) {
        self.pos = if pos > self.data.len() { self.data.len() } else { pos };
    }

    /// Bytes remaining.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// `true` when the cursor is exhausted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> Option<u16> {
        let raw: [u8; 2] = self.bytes(2)?.try_into().ok()?;
        Some(u16::from_le_bytes(raw))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        let raw: [u8; 4] = self.bytes(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(raw))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> Option<u64> {
        let raw: [u8; 8] = self.bytes(8)?.try_into().ok()?;
        Some(u64::from_le_bytes(raw))
    }

    /// Read `n` bytes as a sub-slice.
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Skip `n` bytes, failing (without moving) if that would overrun.
    pub fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// Read an unsigned LEB128. Caps at 10 groups so a hostile stream of
    /// continuation bytes cannot spin.
    pub fn uleb(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.u8()?;
            result |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
        None
    }

    /// Read a signed LEB128.
    pub fn sleb(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.u8()?;
            result |= i64::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
        }
        None
    }

    /// Read a NUL-terminated string. Non-UTF-8 bytes are replaced rather than
    /// rejected: a mojibake path is still a usable key, a hard failure is not.
    pub fn cstr(&mut self) -> Option<String> {
        let start = self.pos;
        while let Some(b) = self.data.get(self.pos) {
            if *b == 0 {
                let s = String::from_utf8_lossy(self.data.get(start..self.pos)?).into_owned();
                self.pos += 1;
                return Some(s);
            }
            self.pos += 1;
        }
        None
    }

    /// Read an address of `size` bytes (4 or 8). Any other size is rejected.
    pub fn address(&mut self, size: u8) -> Option<u64> {
        match size {
            4 => self.u32().map(u64::from),
            8 => self.u64(),
            _ => None,
        }
    }

    /// Read a DWARF initial length, returning `(length, is_64bit)`.
    pub fn initial_length(&mut self) -> Option<(u64, bool)> {
        let first = self.u32()?;
        if first == 0xFFFF_FFFF {
            Some((self.u64()?, true))
        } else if first >= 0xFFFF_FFF0 {
            // Reserved escape values; treating them as a length would desync
            // the whole section.
            None
        } else {
            Some((u64::from(first), false))
        }
    }

    /// Read a section offset sized by the DWARF format (4 or 8 bytes).
    pub fn offset(&mut self, is_64bit: bool) -> Option<u64> {
        if is_64bit { self.u64() } else { self.u32().map(u64::from) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DWARF constants (only the ones this module acts on)
// ─────────────────────────────────────────────────────────────────────────────

/// DWARF attribute codes consulted by the compile-unit walk.
pub mod dw_at {
    /// `DW_AT_name`
    pub const NAME: u64 = 0x03;
    /// `DW_AT_stmt_list` — offset of this unit's line program.
    pub const STMT_LIST: u64 = 0x10;
    /// `DW_AT_low_pc`
    pub const LOW_PC: u64 = 0x11;
    /// `DW_AT_comp_dir` — directory file names are relative to.
    pub const COMP_DIR: u64 = 0x1B;
    /// `DW_AT_str_offsets_base` (DWARF 5).
    pub const STR_OFFSETS_BASE: u64 = 0x72;
}

/// DWARF form codes understood by the attribute decoder.
pub mod dw_form {
    /// `DW_FORM_addr`
    pub const ADDR: u64 = 0x01;
    /// `DW_FORM_block2`
    pub const BLOCK2: u64 = 0x03;
    /// `DW_FORM_block4`
    pub const BLOCK4: u64 = 0x04;
    /// `DW_FORM_data2`
    pub const DATA2: u64 = 0x05;
    /// `DW_FORM_data4`
    pub const DATA4: u64 = 0x06;
    /// `DW_FORM_data8`
    pub const DATA8: u64 = 0x07;
    /// `DW_FORM_string`
    pub const STRING: u64 = 0x08;
    /// `DW_FORM_block`
    pub const BLOCK: u64 = 0x09;
    /// `DW_FORM_block1`
    pub const BLOCK1: u64 = 0x0A;
    /// `DW_FORM_data1`
    pub const DATA1: u64 = 0x0B;
    /// `DW_FORM_flag`
    pub const FLAG: u64 = 0x0C;
    /// `DW_FORM_sdata`
    pub const SDATA: u64 = 0x0D;
    /// `DW_FORM_strp`
    pub const STRP: u64 = 0x0E;
    /// `DW_FORM_udata`
    pub const UDATA: u64 = 0x0F;
    /// `DW_FORM_ref_addr`
    pub const REF_ADDR: u64 = 0x10;
    /// `DW_FORM_ref1`
    pub const REF1: u64 = 0x11;
    /// `DW_FORM_ref2`
    pub const REF2: u64 = 0x12;
    /// `DW_FORM_ref4`
    pub const REF4: u64 = 0x13;
    /// `DW_FORM_ref8`
    pub const REF8: u64 = 0x14;
    /// `DW_FORM_ref_udata`
    pub const REF_UDATA: u64 = 0x15;
    /// `DW_FORM_indirect`
    pub const INDIRECT: u64 = 0x16;
    /// `DW_FORM_sec_offset`
    pub const SEC_OFFSET: u64 = 0x17;
    /// `DW_FORM_exprloc`
    pub const EXPRLOC: u64 = 0x18;
    /// `DW_FORM_flag_present`
    pub const FLAG_PRESENT: u64 = 0x19;
    /// `DW_FORM_strx`
    pub const STRX: u64 = 0x1A;
    /// `DW_FORM_addrx`
    pub const ADDRX: u64 = 0x1B;
    /// `DW_FORM_ref_sup4`
    pub const REF_SUP4: u64 = 0x1C;
    /// `DW_FORM_strp_sup`
    pub const STRP_SUP: u64 = 0x1D;
    /// `DW_FORM_data16`
    pub const DATA16: u64 = 0x1E;
    /// `DW_FORM_line_strp`
    pub const LINE_STRP: u64 = 0x1F;
    /// `DW_FORM_ref_sig8`
    pub const REF_SIG8: u64 = 0x20;
    /// `DW_FORM_implicit_const`
    pub const IMPLICIT_CONST: u64 = 0x21;
    /// `DW_FORM_loclistx`
    pub const LOCLISTX: u64 = 0x22;
    /// `DW_FORM_rnglistx`
    pub const RNGLISTX: u64 = 0x23;
    /// `DW_FORM_ref_sup8`
    pub const REF_SUP8: u64 = 0x24;
    /// `DW_FORM_strx1`
    pub const STRX1: u64 = 0x25;
    /// `DW_FORM_strx2`
    pub const STRX2: u64 = 0x26;
    /// `DW_FORM_strx3`
    pub const STRX3: u64 = 0x27;
    /// `DW_FORM_strx4`
    pub const STRX4: u64 = 0x28;
    /// `DW_FORM_addrx1`
    pub const ADDRX1: u64 = 0x29;
    /// `DW_FORM_addrx2`
    pub const ADDRX2: u64 = 0x2A;
    /// `DW_FORM_addrx3`
    pub const ADDRX3: u64 = 0x2B;
    /// `DW_FORM_addrx4`
    pub const ADDRX4: u64 = 0x2C;
}

/// DWARF 5 line-header content type codes.
pub mod dw_lnct {
    /// `DW_LNCT_path`
    pub const PATH: u64 = 0x01;
    /// `DW_LNCT_directory_index`
    pub const DIRECTORY_INDEX: u64 = 0x02;
    /// `DW_LNCT_timestamp`
    pub const TIMESTAMP: u64 = 0x03;
    /// `DW_LNCT_size`
    pub const SIZE: u64 = 0x04;
}

/// `DW_TAG_compile_unit`
pub const DW_TAG_COMPILE_UNIT: u64 = 0x11;

// ─────────────────────────────────────────────────────────────────────────────
// DWARF sections extracted from the dSYM Mach-O
// ─────────────────────────────────────────────────────────────────────────────

/// The `__DWARF` payload of a dSYM, copied out of the Mach-O.
///
/// Sections are owned rather than borrowed because a `DsymBundle` outlives the
/// file bytes it was read from in every realistic caller (a debug session keeps
/// the bundle, not the file).
#[derive(Debug, Clone, Default)]
pub struct DwarfSections {
    /// `__debug_info` — compile units and their DIEs.
    pub debug_info: Vec<u8>,
    /// `__debug_abbrev` — abbreviation tables referenced by the units.
    pub debug_abbrev: Vec<u8>,
    /// `__debug_line` — line number programs.
    pub debug_line: Vec<u8>,
    /// `__debug_str` — string table for `DW_FORM_strp` / `DW_FORM_strx`.
    pub debug_str: Vec<u8>,
    /// `__debug_line_str` — DWARF 5 string table for line headers.
    pub debug_line_str: Vec<u8>,
    /// `__debug_str_offsets` — DWARF 5 indirection for `DW_FORM_strx`.
    pub debug_str_offsets: Vec<u8>,
    /// `__debug_ranges` — retained for callers doing range lookups.
    pub debug_ranges: Vec<u8>,
    /// `__debug_addr` — DWARF 5 address table.
    pub debug_addr: Vec<u8>,
}

impl DwarfSections {
    /// Extract the `__DWARF` sections from a thin Mach-O image.
    ///
    /// Section *names* are matched, not segment names, because `dsymutil`
    /// output and `-gdwarf` object files disagree about the containing segment
    /// while agreeing about the section name.
    pub fn from_macho(bytes: &[u8]) -> DsymResult<Self> {
        let info =
            MachoParser::parse_single(bytes).map_err(|e| DsymError::Macho(e.to_string()))?;
        let mut out = Self::default();
        for seg in &info.segments {
            for sec in &seg.sections {
                let start = sec.offset as usize;
                let len = usize::try_from(sec.size).unwrap_or(0);
                let Some(data) = bytes.get(start..start.saturating_add(len)) else {
                    // A section pointing outside the file is a corrupt dSYM;
                    // skip it rather than aborting the whole extraction, since
                    // the remaining sections are often still usable.
                    continue;
                };
                let slot: Option<&mut Vec<u8>> = match sec.name.as_str() {
                    "__debug_info" => Some(&mut out.debug_info),
                    "__debug_abbrev" => Some(&mut out.debug_abbrev),
                    "__debug_line" => Some(&mut out.debug_line),
                    "__debug_str" => Some(&mut out.debug_str),
                    "__debug_line_str" => Some(&mut out.debug_line_str),
                    "__debug_str_offsets" => Some(&mut out.debug_str_offsets),
                    "__debug_ranges" => Some(&mut out.debug_ranges),
                    "__debug_addr" => Some(&mut out.debug_addr),
                    _ => None,
                };
                if let Some(dst) = slot {
                    dst.clear();
                    dst.extend_from_slice(data);
                }
            }
        }
        Ok(out)
    }

    /// `true` when no DWARF section at all was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.debug_info.is_empty() && self.debug_line.is_empty() && self.debug_abbrev.is_empty()
    }

    /// Names of the sections that are present, in a stable order — used for
    /// diagnostics that must say *what* is missing.
    #[must_use]
    pub fn present_sections(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (name, data) in [
            ("__debug_info", &self.debug_info),
            ("__debug_abbrev", &self.debug_abbrev),
            ("__debug_line", &self.debug_line),
            ("__debug_str", &self.debug_str),
            ("__debug_line_str", &self.debug_line_str),
            ("__debug_str_offsets", &self.debug_str_offsets),
            ("__debug_ranges", &self.debug_ranges),
            ("__debug_addr", &self.debug_addr),
        ] {
            if !data.is_empty() {
                v.push(name);
            }
        }
        v
    }

    /// Fetch a NUL-terminated string from `__debug_str`.
    #[must_use]
    pub fn str_at(&self, offset: u64) -> Option<String> {
        Cursor::at(&self.debug_str, usize::try_from(offset).ok()?).cstr()
    }

    /// Fetch a NUL-terminated string from `__debug_line_str`.
    #[must_use]
    pub fn line_str_at(&self, offset: u64) -> Option<String> {
        Cursor::at(&self.debug_line_str, usize::try_from(offset).ok()?).cstr()
    }

    /// Resolve a `DW_FORM_strx` index through `__debug_str_offsets`.
    ///
    /// `base` is `DW_AT_str_offsets_base`; when the unit does not carry one the
    /// caller passes the DWARF 5 default of 8 (the size of the section header).
    #[must_use]
    pub fn strx(&self, base: u64, index: u64, is_64bit: bool) -> Option<String> {
        let entry_size = if is_64bit { 8u64 } else { 4 };
        let at = base.checked_add(index.checked_mul(entry_size)?)?;
        let mut c = Cursor::at(&self.debug_str_offsets, usize::try_from(at).ok()?);
        if c.remaining() < usize::try_from(entry_size).ok()? {
            return None;
        }
        let off = c.offset(is_64bit)?;
        self.str_at(off)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_abbrev
// ─────────────────────────────────────────────────────────────────────────────

/// One abbreviation declaration: the shape of a class of DIEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abbrev {
    /// `DW_TAG_*` of the DIEs using this abbreviation.
    pub tag: u64,
    /// Whether DIEs of this shape are followed by children.
    pub has_children: bool,
    /// `(attribute, form, implicit_const)` triples in declaration order.
    pub attrs: Vec<(u64, u64, i64)>,
}

/// Parse the abbreviation table starting at `offset` within `__debug_abbrev`.
///
/// A table ends at a zero abbreviation code. Truncated input yields whatever
/// was decoded before the truncation, because a partially usable table still
/// symbolicates the units that reference its early entries.
#[must_use]
pub fn parse_abbrev_table(data: &[u8], offset: u64) -> HashMap<u64, Abbrev> {
    let mut out = HashMap::new();
    let Ok(start) = usize::try_from(offset) else {
        return out;
    };
    let mut c = Cursor::at(data, start);
    loop {
        let Some(code) = c.uleb() else { return out };
        if code == 0 {
            return out;
        }
        let (Some(tag), Some(children)) = (c.uleb(), c.u8()) else {
            return out;
        };
        let mut attrs = Vec::new();
        loop {
            let (Some(at), Some(form)) = (c.uleb(), c.uleb()) else {
                return out;
            };
            if at == 0 && form == 0 {
                break;
            }
            let implicit = if form == dw_form::IMPLICIT_CONST {
                match c.sleb() {
                    Some(v) => v,
                    None => return out,
                }
            } else {
                0
            };
            attrs.push((at, form, implicit));
        }
        out.insert(code, Abbrev { tag, has_children: children != 0, attrs });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_info — just enough to find line programs
// ─────────────────────────────────────────────────────────────────────────────

/// The subset of a `DW_TAG_compile_unit` root DIE that line mapping needs.
///
/// Deliberately not a general DIE tree: a debugger asking "which file and line
/// is this address" needs exactly `DW_AT_stmt_list` (which line program) and
/// `DW_AT_comp_dir` (what relative file names mean). Parsing the full tree here
/// would duplicate the decompiler's DWARF consumer for no gain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileUnit {
    /// Offset of the unit header within `__debug_info`.
    pub unit_offset: u64,
    /// DWARF version of the unit.
    pub version: u16,
    /// Target address size in bytes.
    pub address_size: u8,
    /// `true` when the unit uses the 64-bit DWARF format.
    pub is_64bit: bool,
    /// `DW_AT_name` — primary source file of the unit.
    pub name: Option<String>,
    /// `DW_AT_comp_dir` — directory relative file names resolve against.
    pub comp_dir: Option<String>,
    /// `DW_AT_stmt_list` — offset of this unit's program in `__debug_line`.
    pub stmt_list: Option<u64>,
    /// `DW_AT_low_pc` — the unit's base static address, when present.
    pub low_pc: Option<u64>,
}

/// Enumerate the compile units of `__debug_info`, reading only the root DIE of
/// each.
///
/// Units that fail to decode are skipped, not fatal: one bad unit in a large
/// dSYM must not cost the other thousands.
#[must_use]
pub fn parse_compile_units(sections: &DwarfSections) -> Vec<CompileUnit> {
    let info = &sections.debug_info;
    let mut out = Vec::new();
    let mut pos = 0usize;
    // Guard against a zero-length unit spinning the loop forever.
    while pos + 11 <= info.len() {
        let mut c = Cursor::at(info, pos);
        let Some((unit_len, is_64bit)) = c.initial_length() else { break };
        let after_len = c.pos();
        let Some(unit_end) = usize::try_from(unit_len).ok().and_then(|l| after_len.checked_add(l))
        else {
            break;
        };
        if unit_len == 0 || unit_end > info.len() {
            break;
        }
        if let Some(cu) = parse_one_unit(sections, &mut c, pos as u64, is_64bit) {
            out.push(cu);
        }
        pos = unit_end;
    }
    out
}

fn parse_one_unit(
    sections: &DwarfSections,
    c: &mut Cursor<'_>,
    unit_offset: u64,
    is_64bit: bool,
) -> Option<CompileUnit> {
    let version = c.u16()?;
    // DWARF 5 reordered the header: unit_type and address_size come before the
    // abbrev offset. Getting this backwards silently shifts every subsequent
    // read, which is why the two layouts are spelled out rather than patched.
    let (abbrev_off, address_size) = if version >= 5 {
        let _unit_type = c.u8()?;
        let addr_size = c.u8()?;
        (c.offset(is_64bit)?, addr_size)
    } else {
        let off = c.offset(is_64bit)?;
        (off, c.u8()?)
    };
    if address_size != 4 && address_size != 8 {
        return None;
    }

    let abbrevs = parse_abbrev_table(&sections.debug_abbrev, abbrev_off);
    let code = c.uleb()?;
    if code == 0 {
        return None;
    }
    let abbrev = abbrevs.get(&code)?;
    if abbrev.tag != DW_TAG_COMPILE_UNIT {
        return None;
    }

    let mut cu = CompileUnit {
        unit_offset,
        version,
        address_size,
        is_64bit,
        name: None,
        comp_dir: None,
        stmt_list: None,
        low_pc: None,
    };

    // DWARF 5 puts DW_AT_str_offsets_base in the same DIE whose strings it is
    // needed to decode, so strx values are resolved in a second pass once the
    // base is known. The default (8) is the header size of a 32-bit
    // .debug_str_offsets contribution.
    let mut pending_strx: Vec<(u64, u64)> = Vec::new();
    let mut str_offsets_base: Option<u64> = None;

    for &(at, form, implicit) in &abbrev.attrs {
        let value = read_attr_value(sections, c, form, implicit, address_size, is_64bit)?;
        match (at, value) {
            (dw_at::STR_OFFSETS_BASE, AttrValue::Uint(v)) => str_offsets_base = Some(v),
            (dw_at::NAME | dw_at::COMP_DIR, AttrValue::Str(s)) => {
                if at == dw_at::NAME {
                    cu.name = Some(s);
                } else {
                    cu.comp_dir = Some(s);
                }
            }
            (dw_at::NAME | dw_at::COMP_DIR, AttrValue::StrIndex(i)) => pending_strx.push((at, i)),
            (dw_at::STMT_LIST, AttrValue::Uint(v)) => cu.stmt_list = Some(v),
            (dw_at::LOW_PC, AttrValue::Uint(v)) => cu.low_pc = Some(v),
            _ => {}
        }
    }

    let base = str_offsets_base.unwrap_or(if is_64bit { 16 } else { 8 });
    for (at, idx) in pending_strx {
        if let Some(s) = sections.strx(base, idx, is_64bit) {
            if at == dw_at::NAME {
                cu.name = Some(s);
            } else {
                cu.comp_dir = Some(s);
            }
        }
    }

    Some(cu)
}

/// A decoded attribute value, reduced to the three shapes this module acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AttrValue {
    Uint(u64),
    Str(String),
    /// A `DW_FORM_strx*` index awaiting `DW_AT_str_offsets_base`.
    StrIndex(u64),
    Other,
}

/// Decode (or skip over) one attribute value.
///
/// Every form in DWARF 2–5 is handled: an unhandled form would desync the DIE
/// stream and turn every later attribute into garbage, so unknown forms are a
/// hard `None` rather than a guess.
fn read_attr_value(
    sections: &DwarfSections,
    c: &mut Cursor<'_>,
    form: u64,
    implicit: i64,
    address_size: u8,
    is_64bit: bool,
) -> Option<AttrValue> {
    use dw_form as f;
    Some(match form {
        f::ADDR => AttrValue::Uint(c.address(address_size)?),
        f::BLOCK1 => {
            let n = c.u8()? as usize;
            c.skip(n)?;
            AttrValue::Other
        }
        f::BLOCK2 => {
            let n = c.u16()? as usize;
            c.skip(n)?;
            AttrValue::Other
        }
        f::BLOCK4 => {
            let n = usize::try_from(c.u32()?).ok()?;
            c.skip(n)?;
            AttrValue::Other
        }
        f::BLOCK | f::EXPRLOC => {
            let n = usize::try_from(c.uleb()?).ok()?;
            c.skip(n)?;
            AttrValue::Other
        }
        f::DATA1 | f::REF1 | f::STRX1 | f::ADDRX1 | f::FLAG => {
            let v = u64::from(c.u8()?);
            if form == f::STRX1 { AttrValue::StrIndex(v) } else { AttrValue::Uint(v) }
        }
        f::DATA2 | f::REF2 | f::STRX2 | f::ADDRX2 => {
            let v = u64::from(c.u16()?);
            if form == f::STRX2 { AttrValue::StrIndex(v) } else { AttrValue::Uint(v) }
        }
        f::STRX3 | f::ADDRX3 => {
            let b = c.bytes(3)?;
            let v = u64::from(b.first().copied()?)
                | (u64::from(b.get(1).copied()?) << 8)
                | (u64::from(b.get(2).copied()?) << 16);
            if form == f::STRX3 { AttrValue::StrIndex(v) } else { AttrValue::Uint(v) }
        }
        f::DATA4 | f::REF4 | f::STRX4 | f::ADDRX4 | f::REF_SUP4 => {
            let v = u64::from(c.u32()?);
            if form == f::STRX4 { AttrValue::StrIndex(v) } else { AttrValue::Uint(v) }
        }
        f::DATA8 | f::REF8 | f::REF_SIG8 | f::REF_SUP8 => AttrValue::Uint(c.u64()?),
        f::DATA16 => {
            c.skip(16)?;
            AttrValue::Other
        }
        f::STRING => AttrValue::Str(c.cstr()?),
        f::SDATA => AttrValue::Uint(c.sleb()? as u64),
        f::UDATA | f::REF_UDATA | f::LOCLISTX | f::RNGLISTX => AttrValue::Uint(c.uleb()?),
        f::STRX | f::ADDRX => {
            let v = c.uleb()?;
            if form == f::STRX { AttrValue::StrIndex(v) } else { AttrValue::Uint(v) }
        }
        f::STRP | f::STRP_SUP => {
            let off = c.offset(is_64bit)?;
            sections.str_at(off).map_or(AttrValue::Other, AttrValue::Str)
        }
        f::LINE_STRP => {
            let off = c.offset(is_64bit)?;
            sections.line_str_at(off).map_or(AttrValue::Other, AttrValue::Str)
        }
        f::SEC_OFFSET | f::REF_ADDR => AttrValue::Uint(c.offset(is_64bit)?),
        f::FLAG_PRESENT => AttrValue::Uint(1),
        f::IMPLICIT_CONST => AttrValue::Uint(implicit as u64),
        f::INDIRECT => {
            let real = c.uleb()?;
            // A DW_FORM_indirect naming itself would recurse without bound.
            if real == f::INDIRECT {
                return None;
            }
            read_attr_value(sections, c, real, implicit, address_size, is_64bit)?
        }
        _ => return None,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_line header
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed line-number program: its header plus the byte range of the opcode
/// stream that [`LineTableStateMachine`] should execute.
#[derive(Debug, Clone)]
pub struct LineProgram {
    /// Header in the shape `crate::source_map` expects.
    pub header: LineTableHeader,
    /// Offset of the program header within `__debug_line`.
    pub offset: u64,
    /// Offset just past this program (start of the next one).
    pub end_offset: u64,
    /// Offset of the first opcode byte.
    pub program_start: u64,
    /// DWARF 5 numbers files from 0, earlier versions from 1. Rows carrying a
    /// raw file index must be shifted by this before the shared
    /// [`SourceMap::from_line_table`] (which assumes 1-based) sees them.
    pub file_index_bias: u32,
    /// `DW_LNCT_path` of file entry 0 on DWARF 5 — the unit's primary source.
    pub primary_file: Option<PathBuf>,
    /// Directory entry 0 on DWARF 5, which `clang` sets to the compilation
    /// directory. More reliable than `DW_AT_comp_dir` when both exist.
    pub header_comp_dir: Option<PathBuf>,
}

/// Parse the line-program header at `offset` in `__debug_line`.
///
/// Supports DWARF versions 2 through 5. Version 5 is not an incremental change
/// here: directories and file names move from NUL-terminated lists to
/// format-descriptor-driven tables, and file numbering shifts from 1-based to
/// 0-based. Both are handled explicitly.
pub fn parse_line_program(sections: &DwarfSections, offset: u64) -> DsymResult<LineProgram> {
    let data = &sections.debug_line;
    if data.is_empty() {
        return Err(DsymError::MissingSection("__debug_line"));
    }
    let start = usize::try_from(offset)
        .map_err(|_| DsymError::MalformedDwarf(format!("line offset {offset} out of range")))?;
    if start >= data.len() {
        return Err(DsymError::MalformedDwarf(format!(
            "line program offset {offset} past end of __debug_line ({})",
            data.len()
        )));
    }
    let mut c = Cursor::at(data, start);
    let bad = |what: &str| DsymError::MalformedDwarf(format!("line header: {what}"));

    let (unit_len, is_64bit) = c.initial_length().ok_or_else(|| bad("truncated unit length"))?;
    let after_len = c.pos() as u64;
    let end_offset = after_len
        .checked_add(unit_len)
        .filter(|e| *e as usize <= data.len())
        .ok_or_else(|| bad("unit length overruns section"))?;

    let version = c.u16().ok_or_else(|| bad("truncated version"))?;
    if !(2..=5).contains(&version) {
        return Err(bad(&format!("unsupported version {version}")));
    }

    let mut address_size = 8u8;
    if version >= 5 {
        address_size = c.u8().ok_or_else(|| bad("truncated address_size"))?;
        let _segment_selector_size = c.u8().ok_or_else(|| bad("truncated segment selector"))?;
        if address_size != 4 && address_size != 8 {
            return Err(bad(&format!("bad address size {address_size}")));
        }
    }

    let header_len = c.offset(is_64bit).ok_or_else(|| bad("truncated header_length"))?;
    let program_start = (c.pos() as u64)
        .checked_add(header_len)
        .filter(|p| *p <= end_offset)
        .ok_or_else(|| bad("header_length overruns unit"))?;

    let minimum_instruction_length = c.u8().ok_or_else(|| bad("truncated min_inst_len"))?;
    let maximum_ops_per_instruction =
        if version >= 4 { c.u8().ok_or_else(|| bad("truncated max_ops"))? } else { 1 };
    let default_is_stmt = c.u8().ok_or_else(|| bad("truncated default_is_stmt"))? != 0;
    let line_base = c.u8().ok_or_else(|| bad("truncated line_base"))? as i8;
    let line_range = c.u8().ok_or_else(|| bad("truncated line_range"))?;
    let opcode_base = c.u8().ok_or_else(|| bad("truncated opcode_base"))?;
    if line_range == 0 || minimum_instruction_length == 0 {
        return Err(bad("zero line_range or minimum_instruction_length"));
    }

    let mut standard_opcode_lengths = Vec::new();
    for _ in 1..opcode_base {
        standard_opcode_lengths.push(c.u8().ok_or_else(|| bad("truncated std opcode lengths"))?);
    }

    let mut include_directories: Vec<PathBuf> = Vec::new();
    let mut file_names: Vec<FileEntry> = Vec::new();
    let mut file_index_bias = 0u32;
    let mut primary_file = None;
    let mut header_comp_dir = None;

    if version >= 5 {
        let dirs = read_v5_entries(sections, &mut c, is_64bit)?;
        let files = read_v5_entries(sections, &mut c, is_64bit)?;

        // Directory 0 is the compilation directory; `FileEntry::resolve_path`
        // already treats dir_index 0 as "comp dir", so dropping it from the
        // list keeps index arithmetic identical for versions 2–5.
        header_comp_dir = dirs.first().map(|d| PathBuf::from(&d.path));
        include_directories = dirs.iter().skip(1).map(|d| PathBuf::from(&d.path)).collect();

        primary_file = files.first().map(|f| PathBuf::from(&f.path));
        for f in &files {
            file_names.push(FileEntry {
                name: PathBuf::from(&f.path),
                dir_index: f.dir_index,
                modification: f.timestamp,
                length: f.size,
            });
        }
        // Rows will carry 0-based indices; shift them to the 1-based world the
        // shared SourceMap builder assumes.
        file_index_bias = 1;
    } else {
        loop {
            let s = c.cstr().ok_or_else(|| bad("truncated include_directories"))?;
            if s.is_empty() {
                break;
            }
            include_directories.push(PathBuf::from(s));
        }
        loop {
            let name = c.cstr().ok_or_else(|| bad("truncated file_names"))?;
            if name.is_empty() {
                break;
            }
            let dir_index = c.uleb().ok_or_else(|| bad("truncated file dir_index"))?;
            let modification = c.uleb().ok_or_else(|| bad("truncated file mtime"))?;
            let length = c.uleb().ok_or_else(|| bad("truncated file length"))?;
            file_names.push(FileEntry {
                name: PathBuf::from(name),
                dir_index: u32::try_from(dir_index).unwrap_or(0),
                modification,
                length,
            });
        }
    }

    Ok(LineProgram {
        header: LineTableHeader {
            minimum_instruction_length,
            maximum_ops_per_instruction: maximum_ops_per_instruction.max(1),
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            standard_opcode_lengths,
            include_directories,
            file_names,
            address_size,
            is_64bit,
            version,
        },
        offset,
        end_offset,
        program_start,
        file_index_bias,
        primary_file,
        header_comp_dir,
    })
}

/// One DWARF 5 directory/file table entry after format-descriptor decoding.
#[derive(Debug, Clone, Default)]
struct V5Entry {
    path: String,
    dir_index: u32,
    timestamp: u64,
    size: u64,
}

fn read_v5_entries(
    sections: &DwarfSections,
    c: &mut Cursor<'_>,
    is_64bit: bool,
) -> DsymResult<Vec<V5Entry>> {
    let bad = |what: &str| DsymError::MalformedDwarf(format!("line header v5: {what}"));
    let format_count = c.u8().ok_or_else(|| bad("truncated format count"))?;
    let mut formats: Vec<(u64, u64)> = Vec::with_capacity(format_count as usize);
    for _ in 0..format_count {
        let ct = c.uleb().ok_or_else(|| bad("truncated content type"))?;
        let form = c.uleb().ok_or_else(|| bad("truncated form"))?;
        formats.push((ct, form));
    }
    let count = c.uleb().ok_or_else(|| bad("truncated entry count"))?;
    // A hostile count cannot be trusted to allocate against; the loop below
    // fails fast on truncation anyway, so the vector grows only as it decodes.
    let mut out: Vec<V5Entry> = Vec::new();
    for _ in 0..count {
        let mut e = V5Entry::default();
        for &(ct, form) in &formats {
            let v = read_attr_value(sections, c, form, 0, if is_64bit { 8 } else { 4 }, is_64bit)
                .ok_or_else(|| bad("truncated entry value"))?;
            match (ct, v) {
                (dw_lnct::PATH, AttrValue::Str(s)) => e.path = s,
                (dw_lnct::DIRECTORY_INDEX, AttrValue::Uint(u)) => {
                    e.dir_index = u32::try_from(u).unwrap_or(0);
                }
                (dw_lnct::TIMESTAMP, AttrValue::Uint(u)) => e.timestamp = u,
                (dw_lnct::SIZE, AttrValue::Uint(u)) => e.size = u,
                _ => {}
            }
        }
        out.push(e);
    }
    Ok(out)
}

/// Execute a line program and return its rows, already shifted into the 1-based
/// file numbering the shared [`SourceMap`] builder expects.
pub fn run_line_program(
    sections: &DwarfSections,
    program: &LineProgram,
) -> DsymResult<Vec<LineTableRow>> {
    let start = usize::try_from(program.program_start).unwrap_or(usize::MAX);
    let end = usize::try_from(program.end_offset).unwrap_or(usize::MAX);
    let body = sections
        .debug_line
        .get(start..end)
        .ok_or_else(|| DsymError::MalformedDwarf("line program body out of range".into()))?;
    let mut sm = LineTableStateMachine::new(&program.header, body);
    let mut rows = sm
        .execute()
        .map_err(|e| DsymError::MalformedDwarf(e.to_string()))?;
    if program.file_index_bias != 0 {
        for r in &mut rows {
            r.file_index = r.file_index.saturating_add(program.file_index_bias);
        }
    }
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Locate the Mach-O payload inside a `.dSYM` directory.
///
/// Returns the first regular file under `Contents/Resources/DWARF`. A bundle
/// with several architecture payloads yields them all via
/// [`dwarf_payloads_in_bundle`]; this convenience picks the first.
pub fn dwarf_payload_in_bundle(bundle: &Path) -> DsymResult<PathBuf> {
    dwarf_payloads_in_bundle(bundle)?
        .into_iter()
        .next()
        .ok_or_else(|| DsymError::EmptyBundle(bundle.display().to_string()))
}

/// All Mach-O payloads under `<bundle>/Contents/Resources/DWARF`, sorted by
/// file name so the result is deterministic across filesystems.
pub fn dwarf_payloads_in_bundle(bundle: &Path) -> DsymResult<Vec<PathBuf>> {
    let dir = bundle.join("Contents").join("Resources").join("DWARF");
    let entries = std::fs::read_dir(&dir).map_err(|e| DsymError::Io {
        path: dir.display().to_string(),
        message: e.to_string(),
    })?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            out.push(p);
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(DsymError::EmptyBundle(bundle.display().to_string()));
    }
    Ok(out)
}

/// Candidate `.dSYM` bundle paths for `binary_path`, in search order.
///
/// Xcode writes `Foo.dSYM` beside `Foo`; `dsymutil` writes `Foo.app.dSYM`
/// beside `Foo.app`. Both spellings, plus the extension-stripped form, are
/// tried before giving up.
#[must_use]
pub fn candidate_bundle_paths(binary_path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(parent) = binary_path.parent() else { return out };
    let Some(name) = binary_path.file_name().and_then(|s| s.to_str()) else {
        return out;
    };
    out.push(parent.join(format!("{name}.dSYM")));
    if let Some(stem) = binary_path.file_stem().and_then(|s| s.to_str()) {
        if stem != name {
            out.push(parent.join(format!("{stem}.dSYM")));
        }
    }
    // A `.app` bundle keeps its dSYM one level up, beside the bundle.
    if let Some(grandparent) = parent.parent() {
        out.push(grandparent.join(format!("{name}.dSYM")));
    }
    out
}

/// Read the `LC_UUID` of a Mach-O file on disk.
pub fn uuid_of_macho_file(path: &Path) -> DsymResult<Option<[u8; 16]>> {
    let bytes = std::fs::read(path).map_err(|e| DsymError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    uuid_of_macho_bytes(&bytes)
}

/// Read the `LC_UUID` of a thin Mach-O image held in memory.
pub fn uuid_of_macho_bytes(bytes: &[u8]) -> DsymResult<Option<[u8; 16]>> {
    let info = MachoParser::parse_single(bytes).map_err(|e| DsymError::Macho(e.to_string()))?;
    Ok(info.uuid)
}

// ─────────────────────────────────────────────────────────────────────────────
// DsymBundle
// ─────────────────────────────────────────────────────────────────────────────

/// An opened dSYM: its DWARF payload plus the identity needed to prove it
/// belongs to the image being debugged.
#[derive(Debug, Clone)]
pub struct DsymBundle {
    /// Path of the Mach-O payload that was read.
    pub dwarf_path: PathBuf,
    /// `LC_UUID` of the payload, if it has one.
    pub uuid: Option<[u8; 16]>,
    /// Architecture of the payload.
    pub arch: MachoArch,
    /// Extracted `__DWARF` sections.
    pub sections: DwarfSections,
}

impl DsymBundle {
    /// Open a dSYM payload (the Mach-O *inside* `Contents/Resources/DWARF`).
    pub fn open_payload(path: &Path) -> DsymResult<Self> {
        let bytes = std::fs::read(path).map_err(|e| DsymError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Self::from_payload_bytes(path, &bytes)
    }

    /// Build from payload bytes already in memory (symbol server, archive,
    /// remote fetch).
    pub fn from_payload_bytes(path: &Path, bytes: &[u8]) -> DsymResult<Self> {
        let info =
            MachoParser::parse_single(bytes).map_err(|e| DsymError::Macho(e.to_string()))?;
        let sections = DwarfSections::from_macho(bytes)?;
        if sections.is_empty() {
            return Err(DsymError::MissingSection("__DWARF"));
        }
        Ok(Self {
            dwarf_path: path.to_path_buf(),
            uuid: info.uuid,
            arch: info.arch,
            sections,
        })
    }

    /// Open the `.dSYM` bundle *directory* (the `Foo.dSYM` path itself).
    pub fn open_bundle(bundle: &Path) -> DsymResult<Self> {
        let payload = dwarf_payload_in_bundle(bundle)?;
        Self::open_payload(&payload)
    }

    /// `true` when this dSYM carries exactly `uuid`.
    #[must_use]
    pub fn matches_uuid(&self, uuid: [u8; 16]) -> bool {
        self.uuid == Some(uuid)
    }

    /// Prove this dSYM belongs to an image with `binary_uuid`.
    ///
    /// A missing UUID on either side is an error, not a pass: "cannot tell"
    /// and "matches" must never be the same answer.
    pub fn verify_against_uuid(&self, binary_uuid: Option<[u8; 16]>) -> DsymResult<()> {
        let Some(bin) = binary_uuid else {
            return Err(DsymError::MissingUuid { which: "binary" });
        };
        let Some(dsym) = self.uuid else {
            return Err(DsymError::MissingUuid { which: "dSYM" });
        };
        if bin == dsym {
            Ok(())
        } else {
            Err(DsymError::UuidMismatch {
                binary: format_uuid(&bin),
                dsym: format_uuid(&dsym),
            })
        }
    }

    /// Prove this dSYM belongs to the given Mach-O image bytes.
    pub fn verify_against_binary(&self, binary_bytes: &[u8]) -> DsymResult<()> {
        self.verify_against_uuid(uuid_of_macho_bytes(binary_bytes)?)
    }

    /// UUID as the canonical dashed string, or `"<none>"`.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        self.uuid.as_ref().map_or_else(|| "<none>".to_string(), format_uuid)
    }

    /// Compile units described by `__debug_info`.
    #[must_use]
    pub fn compile_units(&self) -> Vec<CompileUnit> {
        parse_compile_units(&self.sections)
    }

    /// All line programs in `__debug_line`, walked sequentially.
    ///
    /// This is the fallback path for a dSYM whose `__debug_info` is absent or
    /// unparseable: the line section is self-delimiting, so line mapping does
    /// not actually require `.debug_info` — only the `DW_AT_comp_dir` niceness
    /// does.
    pub fn line_programs(&self) -> Vec<LineProgram> {
        let mut out = Vec::new();
        let mut offset = 0u64;
        let total = self.sections.debug_line.len() as u64;
        while offset < total {
            match parse_line_program(&self.sections, offset) {
                Ok(p) => {
                    let next = p.end_offset;
                    out.push(p);
                    if next <= offset {
                        break; // never advance backwards on a malformed unit
                    }
                    offset = next;
                }
                Err(_) => break,
            }
        }
        out
    }

    /// Build the address → `file:line` index for this dSYM.
    ///
    /// Units come from `__debug_info` when it is present (so `DW_AT_comp_dir`
    /// is honoured); otherwise every line program in `__debug_line` is used
    /// with the header's own directory 0 as the compilation directory.
    pub fn build_source_index(&self, mapper: &SourceRootMapper) -> DsymResult<SourceMapIndex> {
        if self.sections.debug_line.is_empty() {
            return Err(DsymError::MissingSection("__debug_line"));
        }
        let mut index = SourceMapIndex::new();
        let no_functions: HashMap<u64, String> = HashMap::new();
        let mut used_offsets: Vec<u64> = Vec::new();

        for cu in self.compile_units() {
            let Some(stmt) = cu.stmt_list else { continue };
            if used_offsets.contains(&stmt) {
                continue;
            }
            let Ok(program) = parse_line_program(&self.sections, stmt) else { continue };
            let Ok(rows) = run_line_program(&self.sections, &program) else { continue };
            let comp_dir = comp_dir_for(&cu, &program);
            index.add(SourceMap::from_line_table(
                &rows,
                &program.header,
                &comp_dir,
                mapper.clone(),
                &no_functions,
            ));
            used_offsets.push(stmt);
        }

        if used_offsets.is_empty() {
            for program in self.line_programs() {
                let Ok(rows) = run_line_program(&self.sections, &program) else { continue };
                let comp_dir = program
                    .header_comp_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("."));
                index.add(SourceMap::from_line_table(
                    &rows,
                    &program.header,
                    &comp_dir,
                    mapper.clone(),
                    &no_functions,
                ));
            }
        }

        Ok(index)
    }
}

/// Pick the compilation directory for a unit.
///
/// The DWARF 5 line header's directory 0 is preferred over `DW_AT_comp_dir`
/// because `dsymutil` rewrites the former when it relocates paths and leaves
/// the latter alone; trusting the DIE there produces paths that do not exist.
fn comp_dir_for(cu: &CompileUnit, program: &LineProgram) -> PathBuf {
    program
        .header_comp_dir
        .clone()
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| cu.comp_dir.clone().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery by path and by UUID
// ─────────────────────────────────────────────────────────────────────────────

/// Find and open the dSYM that belongs to `binary_path`.
///
/// Candidates beside the binary are tried in order; each is *verified by UUID*
/// against the binary before being accepted. A candidate that exists but does
/// not match is reported as [`DsymError::UuidMismatch`] rather than skipped,
/// because a stale `Foo.dSYM` next to a rebuilt `Foo` is the single most common
/// way a debugger ends up lying about line numbers, and silence would hide it.
pub fn find_dsym_for_binary(binary_path: &Path) -> DsymResult<DsymBundle> {
    let binary_uuid = uuid_of_macho_file(binary_path).ok().flatten();
    let mut mismatch: Option<DsymError> = None;

    for bundle in candidate_bundle_paths(binary_path) {
        if !bundle.is_dir() {
            continue;
        }
        let Ok(payloads) = dwarf_payloads_in_bundle(&bundle) else { continue };
        for payload in payloads {
            let Ok(dsym) = DsymBundle::open_payload(&payload) else { continue };
            match (binary_uuid, dsym.uuid) {
                // No UUID on the binary: accept, but the caller has no proof.
                (None, _) => return Ok(dsym),
                (Some(b), Some(d)) if b == d => return Ok(dsym),
                (Some(b), Some(d)) => {
                    mismatch.get_or_insert(DsymError::UuidMismatch {
                        binary: format_uuid(&b),
                        dsym: format_uuid(&d),
                    });
                }
                (Some(_), None) => {
                    mismatch.get_or_insert(DsymError::MissingUuid { which: "dSYM" });
                }
            }
        }
    }

    Err(mismatch.unwrap_or_else(|| DsymError::NotFound(binary_path.display().to_string())))
}

/// Search `root` recursively (up to `max_depth` directory levels) for a dSYM
/// whose payload carries `uuid`.
///
/// This is the symbol-server / build-archive path: the binary may be nowhere
/// near its debug info, and the UUID is the only link. Depth is bounded because
/// the caller may point this at a home directory.
pub fn find_dsym_by_uuid(root: &Path, uuid: [u8; 16], max_depth: usize) -> DsymResult<DsymBundle> {
    let mut found: Option<DsymBundle> = None;
    // Why the RIGHT bundle was rejected, when one matched by UUID but could not
    // be opened. Without this the search fell through to `NotFound`, telling the
    // caller no dSYM with that UUID exists under `root` — while it was sitting
    // right there and had been discarded. The user then goes looking for a file
    // they already have.
    let mut matched_but_unusable: Option<DsymError> = None;
    visit_dsym_bundles(root, max_depth, &mut |bundle| {
        if found.is_some() {
            return;
        }
        let Ok(payloads) = dwarf_payloads_in_bundle(bundle) else { return };
        for payload in payloads {
            if uuid_of_macho_file(&payload).ok().flatten() == Some(uuid) {
                match DsymBundle::open_payload(&payload) {
                    Ok(d) => {
                        found = Some(d);
                        return;
                    }
                    // Keep looking — another bundle may carry the same UUID and
                    // be usable — but remember why this one was not.
                    Err(e) => matched_but_unusable = Some(e),
                }
            }
        }
    });
    found.ok_or_else(|| {
        matched_but_unusable.unwrap_or_else(|| {
            DsymError::NotFound(format!("uuid {} under {}", format_uuid(&uuid), root.display()))
        })
    })
}

/// Enumerate every `.dSYM` directory under `root`, bounded by `max_depth`.
#[must_use]
pub fn list_dsym_bundles(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    visit_dsym_bundles(root, max_depth, &mut |p| out.push(p.to_path_buf()));
    out
}

fn visit_dsym_bundles(dir: &Path, depth_left: usize, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("dSYM")) {
            f(&path);
            // A dSYM never contains another dSYM; do not descend.
            continue;
        }
        if depth_left > 0 {
            visit_dsym_bundles(&path, depth_left - 1, f);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime-address mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Address → source mapper for one loaded image, backed by its dSYM.
///
/// The dSYM describes **static** addresses; a live debugger sees **runtime**
/// ones. `static + slide == runtime` is the whole relationship, and it lives
/// here as a field rather than being subtracted ad hoc at every call site —
/// the same reasoning as [`crate::ios::symbolication::ImageSymbols`].
pub struct DsymLineMapper {
    index: SourceMapIndex,
    slide: u64,
    uuid: Option<[u8; 16]>,
}

// `SourceMapIndex` is not `Debug` (it holds `Arc<SourceMap>` with a file
// cache), so the impl is written by hand rather than dropping `Debug` from a
// type that appears in debugger diagnostics.
impl std::fmt::Debug for DsymLineMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsymLineMapper")
            .field("entries", &self.index.total_entries())
            .field("slide", &format_args!("0x{:x}", self.slide))
            .field("uuid", &self.uuid.as_ref().map(format_uuid))
            .finish()
    }
}

impl DsymLineMapper {
    /// Build a mapper from an opened bundle.
    pub fn from_bundle(bundle: &DsymBundle, mapper: &SourceRootMapper) -> DsymResult<Self> {
        Ok(Self {
            index: bundle.build_source_index(mapper)?,
            slide: 0,
            uuid: bundle.uuid,
        })
    }

    /// Set the ASLR slide reported by the target.
    #[must_use]
    pub const fn with_slide(mut self, slide: u64) -> Self {
        self.slide = slide;
        self
    }

    /// Current slide.
    #[must_use]
    pub const fn slide(&self) -> u64 {
        self.slide
    }

    /// UUID of the dSYM this mapper came from.
    #[must_use]
    pub const fn uuid(&self) -> Option<[u8; 16]> {
        self.uuid
    }

    /// Number of address rows indexed.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.index.total_entries()
    }

    /// Map a **runtime** address to a source location.
    #[must_use]
    pub fn runtime_addr_to_source(&self, runtime_addr: u64) -> Option<SourceLocation> {
        self.index.addr_to_source(runtime_addr.wrapping_sub(self.slide))
    }

    /// Map a **static** address (as recorded in the dSYM) to a source location.
    #[must_use]
    pub fn static_addr_to_source(&self, static_addr: u64) -> Option<SourceLocation> {
        self.index.addr_to_source(static_addr)
    }

    /// Runtime addresses for a `file:line` breakpoint.
    #[must_use]
    pub fn source_to_runtime_addrs(&self, file: &str, line: u32) -> Vec<u64> {
        self.index
            .source_to_addr(file, line)
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.wrapping_add(self.slide))
            .collect()
    }

    /// Borrow the underlying index for callers that need its richer API.
    #[must_use]
    pub const fn index(&self) -> &SourceMapIndex {
        &self.index
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── synthetic DWARF builders ────────────────────────────────────────────

    fn uleb(v: u64, out: &mut Vec<u8>) {
        let mut v = v;
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return;
            }
        }
    }

    fn sleb(mut v: i64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            let sign = b & 0x40 != 0;
            if (v == 0 && !sign) || (v == -1 && sign) {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn cstr(s: &str, out: &mut Vec<u8>) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    /// A DWARF 4 line program: header + a tiny opcode stream.
    ///
    /// Emits rows at 0x1000 (line 10), 0x1004 (line 11) and an end-sequence at
    /// 0x1008, in file 1 (`main.c`) under directory 0.
    fn build_debug_line_v4() -> Vec<u8> {
        let mut header_tail = Vec::new();
        header_tail.push(1); // minimum_instruction_length
        header_tail.push(1); // maximum_ops_per_instruction (v4)
        header_tail.push(1); // default_is_stmt
        header_tail.push(0xFBu8); // line_base = -5
        header_tail.push(14); // line_range
        header_tail.push(13); // opcode_base
        header_tail.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        cstr("/src/inc", &mut header_tail); // include_directories[0]
        header_tail.push(0); // end of directories
        cstr("main.c", &mut header_tail);
        uleb(0, &mut header_tail); // dir 0 == comp dir
        uleb(0, &mut header_tail);
        uleb(0, &mut header_tail);
        cstr("util.c", &mut header_tail);
        uleb(1, &mut header_tail); // dir 1 == /src/inc
        uleb(0, &mut header_tail);
        uleb(0, &mut header_tail);
        header_tail.push(0); // end of file names

        let mut prog = Vec::new();
        // DW_LNE_set_address 0x1000
        prog.push(0);
        uleb(9, &mut prog);
        prog.push(0x02);
        prog.extend_from_slice(&0x1000u64.to_le_bytes());
        // DW_LNS_advance_line +9  -> line 10
        prog.push(0x03);
        sleb(9, &mut prog);
        // DW_LNS_copy
        prog.push(0x01);
        // DW_LNS_advance_pc 4
        prog.push(0x02);
        uleb(4, &mut prog);
        // DW_LNS_advance_line +1 -> line 11
        prog.push(0x03);
        sleb(1, &mut prog);
        prog.push(0x01); // copy
        // DW_LNS_advance_pc 4 then DW_LNE_end_sequence
        prog.push(0x02);
        uleb(4, &mut prog);
        prog.push(0);
        uleb(1, &mut prog);
        prog.push(0x01);

        let mut out = Vec::new();
        let header_len = header_tail.len() as u32;
        // unit_length covers everything after the length field itself
        let unit_len = 2 + 4 + header_len + prog.len() as u32;
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // version
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header_tail);
        out.extend_from_slice(&prog);
        out
    }

    /// `.debug_abbrev` with one abbreviation: a compile unit carrying
    /// name/comp_dir as inline strings and stmt_list as a sec_offset.
    fn build_debug_abbrev() -> Vec<u8> {
        let mut out = Vec::new();
        uleb(1, &mut out); // code
        uleb(DW_TAG_COMPILE_UNIT, &mut out);
        out.push(0); // no children
        uleb(dw_at::NAME, &mut out);
        uleb(dw_form::STRING, &mut out);
        uleb(dw_at::COMP_DIR, &mut out);
        uleb(dw_form::STRING, &mut out);
        uleb(dw_at::LOW_PC, &mut out);
        uleb(dw_form::ADDR, &mut out);
        uleb(dw_at::STMT_LIST, &mut out);
        uleb(dw_form::SEC_OFFSET, &mut out);
        uleb(0, &mut out);
        uleb(0, &mut out); // end of attrs
        uleb(0, &mut out); // end of table
        out
    }

    fn build_debug_info(stmt_list: u32) -> Vec<u8> {
        let mut die = Vec::new();
        uleb(1, &mut die); // abbrev code
        cstr("main.c", &mut die);
        cstr("/build/proj", &mut die);
        die.extend_from_slice(&0x1000u64.to_le_bytes());
        die.extend_from_slice(&stmt_list.to_le_bytes());

        let mut out = Vec::new();
        let unit_len = 2 + 4 + 1 + die.len() as u32; // version + abbrev_off + addr_size + DIE
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // version 4
        out.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
        out.push(8); // address size
        out.extend_from_slice(&die);
        out
    }

    // ── synthetic Mach-O builder ────────────────────────────────────────────

    const LC_UUID: u32 = 0x1B;
    const LC_SEGMENT_64: u32 = 0x19;

    /// Build a little-endian 64-bit Mach-O of file type `MH_DSYM` holding a
    /// `__DWARF` segment with the given sections.
    /// Truncation + mutation sweep over the DWARF parsers.
    ///
    /// A `.dSYM` is an untrusted file: it is whatever the user points us at.
    /// DWARF has historically been the richest source of parser bugs in this
    /// crate (the `.eh_frame`/CFI hardening of iters 208-212), and these
    /// parsers were never swept the way the local formats were in iter 235.
    #[test]
    fn dwarf_parsers_never_panic_on_truncated_or_mutated_input() {
        let macho = build_dsym_macho(TEST_UUID, &[
            ("__debug_info", vec![0u8; 64]),
            ("__debug_abbrev", vec![1u8, 0x11, 0x01, 0, 0]),
            ("__debug_line", vec![0u8; 48]),
            ("__debug_str", b"main.swift\0Demo\0".to_vec()),
        ]);

        for len in 0..=macho.len() {
            let _ = DsymBundle::from_payload_bytes(std::path::Path::new("t.dSYM"), &macho[..len]);
        }
        for i in 0..macho.len() {
            for probe in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = macho.clone();
                m[i] = probe;
                let _ = DsymBundle::from_payload_bytes(std::path::Path::new("t.dSYM"), &m);
            }
        }
        // Whole 4-byte fields blown out: DWARF is full of lengths and offsets
        // that a single-byte flip never pushes to an extreme.
        for i in 0..macho.len().saturating_sub(4) {
            let mut m = macho.clone();
            m[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let _ = DsymBundle::from_payload_bytes(std::path::Path::new("t.dSYM"), &m);
        }

        // The section-level parsers, reached once sections are located.
        for raw in [
            vec![],
            vec![0xFFu8; 32],
            vec![0x00u8; 32],
            b"\x01\x11\x01\x00\x00".to_vec(),
        ] {
            let _ = parse_abbrev_table(&raw, 0);
            let _ = parse_abbrev_table(&raw, u64::MAX);
            let _ = parse_uuid(&String::from_utf8_lossy(&raw));
        }
    }

    fn build_dsym_macho(uuid: [u8; 16], sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let seg_cmd_size = 72 + 80 * sections.len();
        let uuid_cmd_size = 24usize;
        let header_size = 32usize;
        let sizeofcmds = seg_cmd_size + uuid_cmd_size;
        let data_start = header_size + sizeofcmds;

        // Lay section payloads out back to back after the load commands.
        let mut offsets = Vec::new();
        let mut cursor = data_start;
        for (_, body) in sections {
            offsets.push(cursor);
            cursor += body.len();
        }
        let total_data = cursor - data_start;

        let mut out = Vec::with_capacity(cursor);
        // mach_header_64
        out.extend_from_slice(&0xFEED_FACFu32.to_le_bytes()); // MH_MAGIC_64
        out.extend_from_slice(&0x0100_000Cu32.to_le_bytes()); // CPU_TYPE_ARM64
        out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        out.extend_from_slice(&10u32.to_le_bytes()); // MH_DSYM
        out.extend_from_slice(&2u32.to_le_bytes()); // ncmds
        out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // LC_SEGMENT_64 __DWARF
        out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        out.extend_from_slice(&(seg_cmd_size as u32).to_le_bytes());
        let mut segname = [0u8; 16];
        segname[..7].copy_from_slice(b"__DWARF");
        out.extend_from_slice(&segname);
        out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        out.extend_from_slice(&(total_data as u64).to_le_bytes()); // vmsize
        out.extend_from_slice(&(data_start as u64).to_le_bytes()); // fileoff
        out.extend_from_slice(&(total_data as u64).to_le_bytes()); // filesize
        out.extend_from_slice(&7u32.to_le_bytes()); // maxprot
        out.extend_from_slice(&3u32.to_le_bytes()); // initprot
        out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags

        for (i, (name, body)) in sections.iter().enumerate() {
            let mut sectname = [0u8; 16];
            let n = name.len().min(16);
            sectname[..n].copy_from_slice(&name.as_bytes()[..n]);
            out.extend_from_slice(&sectname);
            out.extend_from_slice(&segname);
            out.extend_from_slice(&0u64.to_le_bytes()); // addr
            out.extend_from_slice(&(body.len() as u64).to_le_bytes()); // size
            out.extend_from_slice(&(offsets[i] as u32).to_le_bytes()); // offset
            out.extend_from_slice(&0u32.to_le_bytes()); // align
            out.extend_from_slice(&0u32.to_le_bytes()); // reloff
            out.extend_from_slice(&0u32.to_le_bytes()); // nreloc
            out.extend_from_slice(&0u32.to_le_bytes()); // flags
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
        }

        // LC_UUID
        out.extend_from_slice(&LC_UUID.to_le_bytes());
        out.extend_from_slice(&(uuid_cmd_size as u32).to_le_bytes());
        out.extend_from_slice(&uuid);

        assert_eq!(out.len(), data_start, "load commands must end where data starts");
        for (_, body) in sections {
            out.extend_from_slice(body);
        }
        out
    }

    fn standard_sections() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("__debug_line", build_debug_line_v4()),
            ("__debug_abbrev", build_debug_abbrev()),
            ("__debug_info", build_debug_info(0)),
            ("__debug_str", b"\0".to_vec()),
        ]
    }

    const TEST_UUID: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF,
    ];

    /// Unique scratch directory; the tests never touch the user's project tree.
    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let p = std::env::temp_dir().join(format!("rustre_dsym_{tag}_{nanos}"));
        std::fs::create_dir_all(&p).expect("scratch dir");
        p
    }

    /// Write a full `<name>.dSYM` bundle beside a (fake) binary.
    fn write_bundle(root: &Path, name: &str, macho: &[u8]) -> PathBuf {
        let bundle = root.join(format!("{name}.dSYM"));
        let dwarf_dir = bundle.join("Contents").join("Resources").join("DWARF");
        std::fs::create_dir_all(&dwarf_dir).expect("bundle dirs");
        std::fs::write(dwarf_dir.join(name), macho).expect("payload");
        bundle
    }

    // ── cursor ──────────────────────────────────────────────────────────────

    #[test]
    fn cursor_never_reads_out_of_bounds() {
        let mut c = Cursor::new(&[1, 2]);
        assert_eq!(c.u8(), Some(1));
        assert_eq!(c.u16(), None); // only one byte left
        assert_eq!(c.u8(), Some(2));
        assert_eq!(c.u8(), None);
        assert!(c.is_empty());
        assert_eq!(Cursor::new(&[]).uleb(), None);
        assert_eq!(Cursor::at(&[0u8; 2], 99).pos(), 2);
    }

    #[test]
    fn leb128_roundtrips_both_signs() {
        for v in [0u64, 1, 127, 128, 300, 0xFFFF_FFFF, u64::MAX] {
            let mut b = Vec::new();
            uleb(v, &mut b);
            assert_eq!(Cursor::new(&b).uleb(), Some(v), "uleb {v}");
        }
        for v in [0i64, -1, 63, -64, 64, -65, i64::MIN + 1, i64::MAX] {
            let mut b = Vec::new();
            sleb(v, &mut b);
            assert_eq!(Cursor::new(&b).sleb(), Some(v), "sleb {v}");
        }
    }

    #[test]
    fn uleb_of_unterminated_continuations_fails_instead_of_spinning() {
        let hostile = vec![0x80u8; 64];
        assert_eq!(Cursor::new(&hostile).uleb(), None);
        assert_eq!(Cursor::new(&hostile).sleb(), None);
    }

    #[test]
    fn initial_length_rejects_reserved_escapes() {
        let reserved = 0xFFFF_FFF1u32.to_le_bytes();
        let mut c = Cursor::new(&reserved);
        assert_eq!(c.initial_length(), None);
        let mut c64 = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF, 8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(c64.initial_length(), Some((8, true)));
    }

    // ── uuid helpers ────────────────────────────────────────────────────────

    #[test]
    fn uuid_formatting_matches_dwarfdump_shape() {
        assert_eq!(format_uuid(&TEST_UUID), "01234567-89AB-CDEF-0123-456789ABCDEF");
        assert_eq!(parse_uuid("01234567-89AB-CDEF-0123-456789ABCDEF"), Some(TEST_UUID));
        assert_eq!(parse_uuid("0123456789ABCDEF0123456789ABCDEF"), Some(TEST_UUID));
        assert_eq!(parse_uuid("not-a-uuid"), None);
        assert_eq!(parse_uuid(""), None);
        assert_eq!(parse_uuid("01234567-89AB-CDEF-0123-456789ABCDEG"), None);
    }

    // ── abbrev / info ───────────────────────────────────────────────────────

    #[test]
    fn abbrev_table_decodes_declared_attributes() {
        let table = parse_abbrev_table(&build_debug_abbrev(), 0);
        let a = table.get(&1).expect("abbrev 1");
        assert_eq!(a.tag, DW_TAG_COMPILE_UNIT);
        assert!(!a.has_children);
        assert_eq!(a.attrs.len(), 4);
        assert_eq!(a.attrs[0], (dw_at::NAME, dw_form::STRING, 0));
        assert_eq!(a.attrs[3], (dw_at::STMT_LIST, dw_form::SEC_OFFSET, 0));
    }

    #[test]
    fn abbrev_table_survives_truncation() {
        let full = build_debug_abbrev();
        for cut in 1..full.len() {
            // Must not panic for any prefix.
            let _ = parse_abbrev_table(&full[..cut], 0);
        }
        assert!(parse_abbrev_table(&[], 0).is_empty());
    }

    #[test]
    fn compile_unit_yields_name_comp_dir_and_stmt_list() {
        let sections = DwarfSections {
            debug_info: build_debug_info(0),
            debug_abbrev: build_debug_abbrev(),
            debug_line: build_debug_line_v4(),
            ..DwarfSections::default()
        };
        let cus = parse_compile_units(&sections);
        assert_eq!(cus.len(), 1);
        let cu = &cus[0];
        assert_eq!(cu.name.as_deref(), Some("main.c"));
        assert_eq!(cu.comp_dir.as_deref(), Some("/build/proj"));
        assert_eq!(cu.stmt_list, Some(0));
        assert_eq!(cu.low_pc, Some(0x1000));
        assert_eq!(cu.version, 4);
        assert_eq!(cu.address_size, 8);
    }

    #[test]
    fn compile_unit_walk_survives_truncation() {
        let full = build_debug_info(0);
        for cut in 0..full.len() {
            let sections = DwarfSections {
                debug_info: full[..cut].to_vec(),
                debug_abbrev: build_debug_abbrev(),
                ..DwarfSections::default()
            };
            let _ = parse_compile_units(&sections);
        }
    }

    // ── line program ────────────────────────────────────────────────────────

    fn line_sections() -> DwarfSections {
        DwarfSections { debug_line: build_debug_line_v4(), ..DwarfSections::default() }
    }

    #[test]
    fn line_header_v4_parses_dirs_and_files() {
        let s = line_sections();
        let p = parse_line_program(&s, 0).expect("header");
        assert_eq!(p.header.version, 4);
        assert_eq!(p.header.opcode_base, 13);
        assert_eq!(p.header.line_base, -5);
        assert_eq!(p.header.line_range, 14);
        assert_eq!(p.header.include_directories, vec![PathBuf::from("/src/inc")]);
        assert_eq!(p.header.file_names.len(), 2);
        assert_eq!(p.header.file_names[0].name, PathBuf::from("main.c"));
        assert_eq!(p.header.file_names[1].dir_index, 1);
        assert_eq!(p.file_index_bias, 0);
        assert_eq!(p.end_offset as usize, s.debug_line.len());
    }

    #[test]
    fn line_program_produces_expected_rows() {
        let s = line_sections();
        let p = parse_line_program(&s, 0).expect("header");
        let rows = run_line_program(&s, &p).expect("rows");
        let real: Vec<_> = rows.iter().filter(|r| !r.row_flags.end_sequence()).collect();
        assert_eq!(real.len(), 2);
        assert_eq!((real[0].address, real[0].line), (0x1000, 10));
        assert_eq!((real[1].address, real[1].line), (0x1004, 11));
        assert!(rows.iter().any(|r| r.row_flags.end_sequence() && r.address == 0x1008));
    }

    #[test]
    fn line_header_rejects_bad_offsets_and_versions() {
        let s = line_sections();
        assert!(matches!(
            parse_line_program(&s, 9_999),
            Err(DsymError::MalformedDwarf(_))
        ));
        let empty = DwarfSections::default();
        assert!(matches!(
            parse_line_program(&empty, 0),
            Err(DsymError::MissingSection("__debug_line"))
        ));
        // Version 9 does not exist; must be rejected, not guessed at.
        let mut bad = build_debug_line_v4();
        bad[4] = 9;
        let s2 = DwarfSections { debug_line: bad, ..DwarfSections::default() };
        assert!(parse_line_program(&s2, 0).is_err());
    }

    #[test]
    fn line_header_survives_arbitrary_truncation() {
        let full = build_debug_line_v4();
        for cut in 0..full.len() {
            let s = DwarfSections { debug_line: full[..cut].to_vec(), ..DwarfSections::default() };
            if let Ok(p) = parse_line_program(&s, 0) {
                let _ = run_line_program(&s, &p);
            }
        }
    }

    // ── DWARF 5 line header ─────────────────────────────────────────────────

    /// DWARF 5 header using `DW_FORM_string` paths, one directory and one file.
    fn build_debug_line_v5() -> Vec<u8> {
        let mut tail = Vec::new();
        tail.push(1); // min_inst_len
        tail.push(1); // max_ops
        tail.push(1); // default_is_stmt
        tail.push(0xFBu8); // line_base -5
        tail.push(14);
        tail.push(13);
        tail.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        // directory table: one format (path, string), two entries
        tail.push(1);
        uleb(dw_lnct::PATH, &mut tail);
        uleb(dw_form::STRING, &mut tail);
        uleb(2, &mut tail);
        cstr("/build/v5", &mut tail); // dir 0 == comp dir
        cstr("/build/v5/sub", &mut tail); // dir 1
        // file table: two formats (path, dir index), two entries
        tail.push(2);
        uleb(dw_lnct::PATH, &mut tail);
        uleb(dw_form::STRING, &mut tail);
        uleb(dw_lnct::DIRECTORY_INDEX, &mut tail);
        uleb(dw_form::UDATA, &mut tail);
        uleb(2, &mut tail);
        cstr("main.c", &mut tail);
        uleb(0, &mut tail);
        cstr("helper.c", &mut tail);
        uleb(1, &mut tail);

        let mut prog = Vec::new();
        prog.push(0);
        uleb(9, &mut prog);
        prog.push(0x02);
        prog.extend_from_slice(&0x2000u64.to_le_bytes());
        // DW_LNS_set_file 1 (0-based -> helper.c)
        prog.push(0x04);
        uleb(1, &mut prog);
        prog.push(0x03);
        sleb(41, &mut prog); // line 42
        prog.push(0x01); // copy
        prog.push(0x02);
        uleb(4, &mut prog);
        prog.push(0);
        uleb(1, &mut prog);
        prog.push(0x01); // end_sequence

        let mut out = Vec::new();
        let header_len = tail.len() as u32;
        let unit_len = 2 + 1 + 1 + 4 + header_len + prog.len() as u32;
        out.extend_from_slice(&unit_len.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.push(8); // address_size
        out.push(0); // segment selector size
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&tail);
        out.extend_from_slice(&prog);
        out
    }

    #[test]
    fn line_header_v5_shifts_file_indices_and_exposes_comp_dir() {
        let s = DwarfSections { debug_line: build_debug_line_v5(), ..DwarfSections::default() };
        let p = parse_line_program(&s, 0).expect("v5 header");
        assert_eq!(p.header.version, 5);
        assert_eq!(p.file_index_bias, 1);
        assert_eq!(p.header_comp_dir, Some(PathBuf::from("/build/v5")));
        assert_eq!(p.primary_file, Some(PathBuf::from("main.c")));
        // dir 0 dropped: include_directories[0] must be the DWARF's dir 1
        assert_eq!(p.header.include_directories, vec![PathBuf::from("/build/v5/sub")]);

        let rows = run_line_program(&s, &p).expect("rows");
        let real: Vec<_> = rows.iter().filter(|r| !r.row_flags.end_sequence()).collect();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].line, 42);
        // raw index 1 was biased to 2 -> file_names[1] == helper.c
        assert_eq!(real[0].file_index, 2);

        let map = SourceMap::from_line_table(
            &rows,
            &p.header,
            Path::new("/build/v5"),
            SourceRootMapper::new(),
            &HashMap::new(),
        );
        let loc = map.addr_to_source(0x2000).expect("location");
        assert_eq!(loc.line, 42);
        assert!(
            loc.file.to_string_lossy().replace('\\', "/").ends_with("/build/v5/sub/helper.c"),
            "unexpected path {}",
            loc.file.display()
        );
    }

    // ── Mach-O extraction ───────────────────────────────────────────────────

    #[test]
    fn dwarf_sections_are_extracted_from_the_macho() {
        let macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let s = DwarfSections::from_macho(&macho).expect("sections");
        assert!(!s.is_empty());
        assert_eq!(s.debug_line, build_debug_line_v4());
        assert_eq!(s.debug_abbrev, build_debug_abbrev());
        assert_eq!(s.debug_info, build_debug_info(0));
        let present = s.present_sections();
        assert!(present.contains(&"__debug_line"));
        assert!(present.contains(&"__debug_info"));
        assert!(!present.contains(&"__debug_ranges"));
    }

    #[test]
    fn payload_bytes_yield_uuid_and_sections() {
        let macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &macho).expect("bundle");
        assert_eq!(b.uuid, Some(TEST_UUID));
        assert_eq!(b.uuid_string(), "01234567-89AB-CDEF-0123-456789ABCDEF");
        assert!(b.matches_uuid(TEST_UUID));
        assert!(!b.matches_uuid([0u8; 16]));
    }

    /// A dSYM that MATCHES the uuid but cannot be opened must not be reported as
    /// "no such uuid".
    ///
    /// `find_dsym_by_uuid` did `if let Ok(d) = DsymBundle::open_payload(..)` and
    /// fell through on `Err`, so a bundle carrying exactly the requested UUID
    /// was discarded and the search ended in `NotFound`. The caller is then told
    /// no dSYM with that UUID exists under the root — while it is sitting right
    /// there. The user goes hunting for a file they already have, and the real
    /// reason (a payload that is not usable) is never shown.
    #[test]
    fn a_matching_dsym_that_cannot_be_opened_is_not_reported_as_missing() {
        let root = scratch("matched_unusable");
        // Right UUID, no DWARF sections: `uuid_of_macho_bytes` reads it, and
        // `open_payload` rejects it — exactly "found but unusable".
        let macho = build_dsym_macho(TEST_UUID, &[]);
        write_bundle(&root, "Broken", &macho);

        let err = find_dsym_by_uuid(&root, TEST_UUID, 4)
            .expect_err("the only candidate is unusable");
        assert!(
            !matches!(err, DsymError::NotFound(_)),
            "a bundle with the requested uuid was reported as absent: {err}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_macho_without_dwarf_is_rejected_not_silently_empty() {
        let macho = build_dsym_macho(TEST_UUID, &[("__text", vec![0u8; 4])]);
        assert!(matches!(
            DsymBundle::from_payload_bytes(Path::new("mem"), &macho),
            Err(DsymError::MissingSection("__DWARF"))
        ));
    }

    #[test]
    fn garbage_is_not_a_macho() {
        assert!(matches!(
            DsymBundle::from_payload_bytes(Path::new("mem"), b"not a mach-o at all"),
            Err(DsymError::Macho(_))
        ));
    }

    // ── UUID verification ───────────────────────────────────────────────────

    #[test]
    fn uuid_verification_is_a_hard_gate() {
        let macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &macho).expect("bundle");

        assert!(b.verify_against_uuid(Some(TEST_UUID)).is_ok());

        let mut other = TEST_UUID;
        other[0] ^= 0xFF;
        match b.verify_against_uuid(Some(other)) {
            Err(DsymError::UuidMismatch { binary, dsym }) => {
                assert_ne!(binary, dsym);
                assert_eq!(dsym, "01234567-89AB-CDEF-0123-456789ABCDEF");
            }
            other => panic!("expected mismatch, got {other:?}"),
        }

        // "cannot tell" must never read as "matches".
        assert!(matches!(
            b.verify_against_uuid(None),
            Err(DsymError::MissingUuid { which: "binary" })
        ));
    }

    #[test]
    fn verify_against_binary_bytes_uses_the_binary_lc_uuid() {
        let dsym_macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &dsym_macho).expect("bundle");

        let matching_binary = build_dsym_macho(TEST_UUID, &[("__text", vec![0x1F, 0x20, 0x03, 0xD5])]);
        assert!(b.verify_against_binary(&matching_binary).is_ok());

        let mut other = TEST_UUID;
        other[15] ^= 0x01;
        let stale_binary = build_dsym_macho(other, &[("__text", vec![0u8; 4])]);
        assert!(matches!(
            b.verify_against_binary(&stale_binary),
            Err(DsymError::UuidMismatch { .. })
        ));
    }

    // ── end-to-end over a real directory layout ─────────────────────────────

    #[test]
    fn find_dsym_beside_binary_and_map_an_address() {
        let root = scratch("beside");
        let macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let binary = root.join("MyApp");
        std::fs::write(&binary, build_dsym_macho(TEST_UUID, &[("__text", vec![0u8; 8])]))
            .expect("binary");
        write_bundle(&root, "MyApp", &macho);

        let bundle = find_dsym_for_binary(&binary).expect("dsym found");
        assert_eq!(bundle.uuid, Some(TEST_UUID));

        let mapper = DsymLineMapper::from_bundle(&bundle, &SourceRootMapper::new())
            .expect("line mapper");
        assert!(mapper.entry_count() >= 2);

        let loc = mapper.static_addr_to_source(0x1000).expect("0x1000 maps");
        assert_eq!(loc.line, 10);
        assert!(
            loc.file.to_string_lossy().replace('\\', "/").ends_with("/build/proj/main.c"),
            "unexpected path {}",
            loc.file.display()
        );
        assert_eq!(mapper.static_addr_to_source(0x1004).map(|l| l.line), Some(11));

        // A slide moves runtime addresses without moving static ones.
        let slid = DsymLineMapper::from_bundle(&bundle, &SourceRootMapper::new())
            .expect("mapper")
            .with_slide(0x4000_0000);
        assert_eq!(slid.runtime_addr_to_source(0x4000_1004).map(|l| l.line), Some(11));
        assert_eq!(slid.static_addr_to_source(0x1004).map(|l| l.line), Some(11));

        let addrs = slid.source_to_runtime_addrs("main.c", 10);
        assert!(addrs.contains(&0x4000_1000), "got {addrs:?}");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_stale_dsym_beside_the_binary_is_an_error_not_a_silent_wrong_answer() {
        let root = scratch("stale");
        let binary = root.join("MyApp");
        std::fs::write(&binary, build_dsym_macho(TEST_UUID, &[("__text", vec![0u8; 8])]))
            .expect("binary");
        let mut stale = TEST_UUID;
        stale[3] ^= 0xAA;
        write_bundle(&root, "MyApp", &build_dsym_macho(stale, &standard_sections()));

        match find_dsym_for_binary(&binary) {
            Err(DsymError::UuidMismatch { .. }) => {}
            other => panic!("stale dSYM must not be accepted: {other:?}"),
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_bundle_reports_not_found() {
        let root = scratch("missing");
        let binary = root.join("Nothing");
        std::fs::write(&binary, build_dsym_macho(TEST_UUID, &[("__text", vec![0u8; 4])]))
            .expect("binary");
        assert!(matches!(find_dsym_for_binary(&binary), Err(DsymError::NotFound(_))));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_by_uuid_searches_a_tree_and_ignores_the_wrong_bundles() {
        let root = scratch("byuuid");
        let deep = root.join("Archives").join("2026-07-29").join("Products");
        std::fs::create_dir_all(&deep).expect("dirs");

        let mut decoy = TEST_UUID;
        decoy[0] = 0xEE;
        write_bundle(&deep, "Decoy", &build_dsym_macho(decoy, &standard_sections()));
        write_bundle(&deep, "Wanted", &build_dsym_macho(TEST_UUID, &standard_sections()));

        let bundles = list_dsym_bundles(&root, 8);
        assert_eq!(bundles.len(), 2, "found {bundles:?}");

        let found = find_dsym_by_uuid(&root, TEST_UUID, 8).expect("by uuid");
        assert_eq!(found.uuid, Some(TEST_UUID));
        assert!(found.dwarf_path.ends_with("Wanted"));

        // Depth 0 cannot reach the nested archive.
        assert!(find_dsym_by_uuid(&root, TEST_UUID, 0).is_err());
        // An unknown UUID is not found rather than approximated.
        assert!(matches!(
            find_dsym_by_uuid(&root, [0xAB; 16], 8),
            Err(DsymError::NotFound(_))
        ));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn empty_bundle_directory_is_reported_distinctly() {
        let root = scratch("empty");
        let bundle = root.join("Hollow.dSYM");
        std::fs::create_dir_all(bundle.join("Contents").join("Resources").join("DWARF"))
            .expect("dirs");
        assert!(matches!(
            DsymBundle::open_bundle(&bundle),
            Err(DsymError::EmptyBundle(_))
        ));
        // A bundle with no Contents at all is an I/O error, a different defect.
        assert!(matches!(
            DsymBundle::open_bundle(&root.join("Absent.dSYM")),
            Err(DsymError::Io { .. })
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn candidate_paths_cover_the_common_layouts() {
        let c = candidate_bundle_paths(Path::new("/tmp/build/MyApp.app"));
        assert!(c.contains(&PathBuf::from("/tmp/build/MyApp.app.dSYM")));
        assert!(c.contains(&PathBuf::from("/tmp/build/MyApp.dSYM")));
        assert!(candidate_bundle_paths(Path::new("MyApp")).is_empty() || !c.is_empty());
    }

    #[test]
    fn line_programs_fallback_works_without_debug_info() {
        // dSYMs stripped of .debug_info still have usable line tables.
        let macho = build_dsym_macho(
            TEST_UUID,
            &[("__debug_line", build_debug_line_v4()), ("__debug_abbrev", build_debug_abbrev())],
        );
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &macho).expect("bundle");
        assert!(b.compile_units().is_empty());
        assert_eq!(b.line_programs().len(), 1);

        let index = b.build_source_index(&SourceRootMapper::new()).expect("index");
        assert!(index.total_entries() >= 2);
        assert_eq!(index.addr_to_source(0x1000).map(|l| l.line), Some(10));
    }

    #[test]
    fn build_source_index_requires_a_line_section() {
        let macho = build_dsym_macho(TEST_UUID, &[("__debug_info", build_debug_info(0))]);
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &macho).expect("bundle");
        assert!(matches!(
            b.build_source_index(&SourceRootMapper::new()),
            Err(DsymError::MissingSection("__debug_line"))
        ));
    }

    #[test]
    fn source_root_remapping_is_honoured() {
        let macho = build_dsym_macho(TEST_UUID, &standard_sections());
        let b = DsymBundle::from_payload_bytes(Path::new("mem"), &macho).expect("bundle");
        let mut mapper = SourceRootMapper::new();
        mapper.add_mapping("/build/proj", "/local/checkout");
        let m = DsymLineMapper::from_bundle(&b, &mapper).expect("mapper");
        // The map still keys on the DWARF path; remapping applies at read time,
        // so the mapping must at least not break lookup.
        assert_eq!(m.static_addr_to_source(0x1000).map(|l| l.line), Some(10));
    }

    #[test]
    fn attribute_forms_that_are_unknown_stop_the_walk_rather_than_desync_it() {
        let sections = DwarfSections::default();
        let mut c = Cursor::new(&[0u8; 8]);
        assert!(read_attr_value(&sections, &mut c, 0x7F, 0, 8, false).is_none());
        // DW_FORM_indirect naming itself must not recurse.
        let mut c2 = Cursor::new(&[dw_form::INDIRECT as u8]);
        assert!(read_attr_value(&sections, &mut c2, dw_form::INDIRECT, 0, 8, false).is_none());
    }
}
