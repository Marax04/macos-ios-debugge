//! Parse and apply dyld chained fixup pointers (`LC_DYLD_CHAINED_FIXUPS`).
//!
//! Starting with iOS 13.4 / macOS 10.16, dyld replaced the traditional rebase
//! and bind opcodes with a compact "chained fixups" format stored in the
//! `__TEXT,__chain_starts` or `__LINKEDIT` segment.  This module provides:
//!
//! * [`DyldFixupChains`] — top-level parser that locates chain starts
//! * [`FixupChain`] — one contiguous chain of fixup pointers
//! * [`ChainedFixup`] — a single fixup pointer (rebase or bind)
//! * [`FixupKind`] — the fixup type (rebase, bind, …)
//! * [`apply_fixups`] — apply all fixups to a loaded image buffer
//!
//! # Relationship to `dyld_fixups`
//!
//! **`dyld_fixup_chains`** (this module) is the high-level, self-contained consumer of the
//! modern chained-fixup format.  It carries a rich typed API with its own [`FixupError`],
//! PAC diversity / key fields on each [`ChainedFixup`], a `ptr_format` constants sub-module,
//! and an `apply_fixups` function that patches an in-memory image buffer in place.
//!
//! **`dyld_fixups`** is the low-level unified pipeline that handles *all* Mach-O fixup
//! stream types (classic rebase opcodes, bind opcodes, lazy-bind, weak-bind) in addition
//! to chained fixups.  It uses `anyhow` for errors and requires an explicit [`SegmentInfo`]
//! table from the caller.  Prefer it when processing pre-iOS 14 binaries or when you need
//! to process all fixup types together via a single [`FixupContext::parse_all`] call.

use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by fixup chain parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupError {
    /// The buffer is too short for the required structure.
    Truncated { offset: usize, needed: usize },
    /// An unsupported pointer format was encountered.
    UnsupportedFormat(u16),
    /// A chain stride value is zero or invalid.
    InvalidStride(usize),
    /// A computed offset points outside the buffer.
    OutOfBounds { offset: usize, available: usize },
    /// Generic structural issue.
    Structural(String),
}

impl fmt::Display for FixupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {offset:#x}: need {needed} bytes")
            }
            Self::UnsupportedFormat(fmt) => write!(f, "unsupported pointer format {fmt:#x}"),
            Self::InvalidStride(s) => write!(f, "invalid stride {s}"),
            Self::OutOfBounds { offset, available } => {
                write!(f, "offset {offset:#x} out of bounds (available {available:#x})")
            }
            Self::Structural(s) => write!(f, "structural error: {s}"),
        }
    }
}

impl std::error::Error for FixupError {}

// ── FixupKind ─────────────────────────────────────────────────────────────────

/// The kind of a single chained fixup pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupKind {
    /// The pointer must be rebased by adding the ASLR slide.
    Rebase,
    /// The pointer must be resolved to the address of an imported symbol.
    Bind,
    /// A "rebase + bind" fixup (combined pointer format).
    RebaseBind,
    /// Auth rebase (arm64e PAC signed pointer).
    AuthRebase,
    /// Auth bind (arm64e PAC signed import).
    AuthBind,
    /// Unknown or unsupported kind.
    Unknown(u8),
}

impl fmt::Display for FixupKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rebase => write!(f, "rebase"),
            Self::Bind => write!(f, "bind"),
            Self::RebaseBind => write!(f, "rebase+bind"),
            Self::AuthRebase => write!(f, "auth_rebase"),
            Self::AuthBind => write!(f, "auth_bind"),
            Self::Unknown(k) => write!(f, "unknown({k:#x})"),
        }
    }
}

// ── ChainedFixup ──────────────────────────────────────────────────────────────

/// A single fixup pointer extracted from a fixup chain.
#[derive(Debug, Clone)]
pub struct ChainedFixup {
    /// Offset within the image where this pointer resides.
    pub image_offset: u32,
    /// The kind of fixup required.
    pub kind: FixupKind,
    /// For `Rebase`: the target virtual address (before sliding).
    pub target: u64,
    /// For `Bind`: the import ordinal.
    pub bind_ordinal: u32,
    /// For `Bind`: optional addend to the bound address.
    pub addend: i64,
    /// For auth pointers: the PAC diversity value.
    pub diversity: u16,
    /// For auth pointers: whether address diversity is enabled.
    pub addr_div: bool,
    /// For auth pointers: the key index (0=IA, 1=IB, 2=DA, 3=DB).
    pub key: u8,
    /// The raw 8-byte word at `image_offset`.
    pub raw_value: u64,
}

impl ChainedFixup {
    /// Return `true` if this is a bind fixup.
    #[must_use] 
    pub const fn is_bind(&self) -> bool {
        matches!(self.kind, FixupKind::Bind | FixupKind::AuthBind)
    }

    /// Return `true` if this is a rebase fixup.
    #[must_use] 
    pub const fn is_rebase(&self) -> bool {
        matches!(self.kind, FixupKind::Rebase | FixupKind::AuthRebase)
    }

    /// Return `true` if this is an authenticated (PAC) pointer.
    #[must_use] 
    pub const fn is_auth(&self) -> bool {
        matches!(self.kind, FixupKind::AuthRebase | FixupKind::AuthBind)
    }

    /// Compute the rebased target address given the ASLR `slide`.
    #[must_use] 
    pub const fn rebased_target(&self, slide: u64) -> u64 {
        self.target.wrapping_add(slide)
    }
}

impl fmt::Display for ChainedFixup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainedFixup {{ off={:#x}, kind={}, target={:#x} }}",
            self.image_offset, self.kind, self.target
        )
    }
}

// ── Pointer formats ───────────────────────────────────────────────────────────

/// Known chained pointer format identifiers (`DYLD_CHAINED_PTR`_*).
pub mod ptr_format {
    pub const ARM64E: u16 = 1;
    pub const ARM64E_KERNEL: u16 = 7;
    pub const ARM64E_USERLAND: u16 = 12;
    pub const ARM64E_FIRMWARE: u16 = 13;
    pub const ARM64E_USERLAND24: u16 = 14;
    pub const PTR_64: u16 = 2;
    pub const PTR_64_OFFSET: u16 = 6;
    pub const PTR_32: u16 = 3;
    pub const PTR_32_CACHE: u16 = 4;
    pub const PTR_32_FIRMWARE: u16 = 5;
    pub const X86_64_KERNEL_CACHE: u16 = 8;
}

// ── FixupChain ────────────────────────────────────────────────────────────────

/// A contiguous sequence of chained fixup pointers in one page.
#[derive(Debug, Clone)]
pub struct FixupChain {
    /// Pointer format for all entries in this chain.
    pub pointer_format: u16,
    /// Starting offset (within the image) of the first entry.
    pub start_offset: u32,
    /// Page index this chain covers.
    pub page_index: u32,
    /// All fixup entries in this chain.
    pub fixups: Vec<ChainedFixup>,
}

impl FixupChain {
    /// Number of fixups in this chain.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.fixups.len()
    }

    /// Return `true` if the chain has no fixups.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.fixups.is_empty()
    }

    /// Return all bind fixups in this chain.
    #[must_use] 
    pub fn binds(&self) -> Vec<&ChainedFixup> {
        self.fixups.iter().filter(|f| f.is_bind()).collect()
    }

    /// Return all rebase fixups in this chain.
    #[must_use] 
    pub fn rebases(&self) -> Vec<&ChainedFixup> {
        self.fixups.iter().filter(|f| f.is_rebase()).collect()
    }
}

// ── DyldFixupChains ───────────────────────────────────────────────────────────

/// Top-level parser for the dyld chained fixups structure.
///
/// Accepts either the raw `LC_DYLD_CHAINED_FIXUPS` data blob (from the load
/// command's linked-it data) or a slice of the image that contains the
/// `dyld_chained_fixups_header`.
#[derive(Debug, Clone)]
pub struct DyldFixupChains {
    /// Parsed chains (one per segment/page-starts entry).
    pub chains: Vec<FixupChain>,
    /// All imports referenced by bind fixups.
    pub imports: Vec<ChainImport>,
    /// Pointer format detected from the header.
    pub pointer_format: u16,
    /// Total number of fixup entries parsed.
    pub total_fixup_count: usize,
}

/// A symbol import referenced by a bind fixup.
#[derive(Debug, Clone)]
pub struct ChainImport {
    pub ordinal: u32,
    pub name: String,
    pub addend: i64,
    pub weak: bool,
}

impl DyldFixupChains {
    /// Parse a `dyld_chained_fixups_header` blob.
    ///
    /// The format is:
    /// ```text
    /// struct dyld_chained_fixups_header {
    ///     uint32_t fixups_version;   // 0
    ///     uint32_t starts_offset;    // 4
    ///     uint32_t imports_offset;   // 8
    ///     uint32_t symbols_offset;   // 12
    ///     uint32_t imports_count;    // 16
    ///     uint32_t imports_format;   // 20
    ///     uint32_t symbols_format;   // 24
    /// };
    /// ```
    ///
    /// # Errors
    /// Returns [`FixupError`] if the blob is malformed.
    pub fn parse(blob: &[u8]) -> Result<Self, FixupError> {
        if blob.len() < 28 {
            return Err(FixupError::Truncated { offset: 0, needed: 28 });
        }

        let fixups_version = read_u32_le(blob, 0)?;
        let _ = fixups_version; // tolerate any version
        let starts_offset = read_u32_le(blob, 4)? as usize;
        let imports_offset = read_u32_le(blob, 8)? as usize;
        let symbols_offset = read_u32_le(blob, 12)? as usize;
        let imports_count = read_u32_le(blob, 16)? as usize;
        let imports_format = read_u32_le(blob, 20)?;
        let _symbols_format = read_u32_le(blob, 24)?;

        // Parse imports
        let imports = Self::parse_imports(blob, imports_offset, symbols_offset, imports_count, imports_format)?;

        // Parse starts (dyld_chained_starts_in_image)
        let (chains, pointer_format) = Self::parse_starts(blob, starts_offset)?;

        let total_fixup_count = chains.iter().map(|c| c.fixups.len()).sum();

        Ok(Self { chains, imports, pointer_format, total_fixup_count })
    }

    fn parse_imports(
        blob: &[u8],
        imports_offset: usize,
        symbols_offset: usize,
        count: usize,
        format: u32,
    ) -> Result<Vec<ChainImport>, FixupError> {
        let mut imports = Vec::with_capacity(count);
        // format 1 = DYLD_CHAINED_IMPORT (4 bytes each)
        // format 2 = DYLD_CHAINED_IMPORT_ADDEND (8 bytes each)
        let entry_size: usize = match format {
            2 | 3 => 8,
            // DYLD_CHAINED_IMPORT_ADDEND64
            _ => 4, // default
        };

        for i in 0..count {
            let off = imports_offset + i * entry_size;
            if off + entry_size > blob.len() {
                break;
            }
            let raw = read_u32_le(blob, off)?;
            let lib_ordinal = raw & 0xFF;
            let weak = (raw >> 8) & 1 != 0;
            let name_off = (raw >> 9) as usize;
            let sym_off = symbols_offset + name_off;
            let name = if sym_off < blob.len() {
                read_cstring(blob, sym_off)
            } else {
                format!("sym_{name_off:#x}")
            };
            let addend: i64 = if entry_size == 8 {
                read_u32_le(blob, off + 4).map_or(0, i64::from)
            } else {
                0
            };
            imports.push(ChainImport { ordinal: lib_ordinal, name, addend, weak });
        }
        Ok(imports)
    }

    fn parse_starts(blob: &[u8], starts_offset: usize) -> Result<(Vec<FixupChain>, u16), FixupError> {
        if starts_offset + 4 > blob.len() {
            // No chains — return empty
            return Ok((Vec::new(), ptr_format::PTR_64));
        }

        // dyld_chained_starts_in_image:
        //   uint32_t seg_count;
        //   uint32_t seg_info_offset[seg_count];
        let seg_count = read_u32_le(blob, starts_offset)? as usize;
        let mut all_chains = Vec::new();
        let mut pointer_format = ptr_format::PTR_64;

        for s in 0..seg_count {
            let seg_off_ptr = starts_offset + 4 + s * 4;
            if seg_off_ptr + 4 > blob.len() {
                break;
            }
            let seg_off = read_u32_le(blob, seg_off_ptr)? as usize;
            if seg_off == 0 {
                continue;
            }
            let abs_off = starts_offset + seg_off;
            if abs_off + 22 > blob.len() {
                continue;
            }
            // dyld_chained_starts_in_segment:
            //   uint32_t size;            +0
            //   uint16_t page_size;       +4
            //   uint16_t pointer_format;  +6
            //   uint64_t segment_offset;  +8
            //   uint32_t max_valid_pointer; +16
            //   uint16_t page_count;      +20
            //   uint16_t page_start[page_count]; +22
            let seg_size = read_u32_le(blob, abs_off)? as usize;
            let _ = seg_size;
            let page_size = read_u16_le(blob, abs_off + 4)? as usize;
            let pf = read_u16_le(blob, abs_off + 6)?;
            let segment_offset = read_u64_le(blob, abs_off + 8)?;
            let page_count = read_u16_le(blob, abs_off + 20)? as usize;
            pointer_format = pf;

            let page_starts_off = abs_off + 22;
            for p in 0..page_count {
                let ps_off = page_starts_off + p * 2;
                if ps_off + 2 > blob.len() {
                    break;
                }
                let page_start = read_u16_le(blob, ps_off)?;
                // 0xFFFF means no chain on this page
                if page_start == 0xFFFF {
                    continue;
                }
                let chain_start_offset = segment_offset + p as u64 * page_size as u64 + u64::from(page_start);
                let fixups = Self::walk_chain(blob, chain_start_offset as usize, pf);
                all_chains.push(FixupChain {
                    pointer_format: pf,
                    start_offset: chain_start_offset as u32,
                    page_index: p as u32,
                    fixups,
                });
            }
        }

        Ok((all_chains, pointer_format))
    }

    fn walk_chain(data: &[u8], start: usize, format: u16) -> Vec<ChainedFixup> {
        let mut fixups = Vec::new();
        let mut off = start;

        loop {
            if off + 8 > data.len() {
                break;
            }
            let raw = u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]));

            let (kind, target, bind_ordinal, addend, next_off, diversity, addr_div, key) =
                Self::decode_ptr(raw, format);

            fixups.push(ChainedFixup {
                image_offset: off as u32,
                kind,
                target,
                bind_ordinal,
                addend,
                diversity,
                addr_div,
                key,
                raw_value: raw,
            });

            if next_off == 0 {
                break;
            }
            off = match off.checked_add(next_off) {
                Some(v) => v,
                None => break,
            };
        }
        fixups
    }

    /// Decode one pointer word according to `format`.
    /// Returns `(kind, target, bind_ordinal, addend, next_off_bytes, diversity, addr_div, key)`.
    const fn decode_ptr(raw: u64, format: u16) -> (FixupKind, u64, u32, i64, usize, u16, bool, u8) {
        match format {
            ptr_format::ARM64E | ptr_format::ARM64E_USERLAND | ptr_format::ARM64E_USERLAND24 => {
                // Bit 63: auth bit, Bit 62: bind bit
                let is_auth = (raw >> 63) & 1 != 0;
                let is_bind = (raw >> 62) & 1 != 0;
                if is_auth {
                    let diversity = ((raw >> 32) & 0xFFFF) as u16;
                    let addr_div = (raw >> 48) & 1 != 0;
                    let key = ((raw >> 49) & 3) as u8;
                    let next_off = ((raw >> 51) & 0x7FF) as usize * 8;
                    if is_bind {
                        let bind_ordinal = (raw & 0xFFFF) as u32;
                        (FixupKind::AuthBind, 0, bind_ordinal, 0, next_off, diversity, addr_div, key)
                    } else {
                        let target = raw & 0x3FFF_FFFF;
                        (FixupKind::AuthRebase, target, 0, 0, next_off, diversity, addr_div, key)
                    }
                } else if is_bind {
                    let bind_ordinal = ((raw >> 32) & 0xFFFF) as u32;
                    let addend = ((raw >> 24) & 0xFF) as i8 as i64;
                    let next_off = ((raw >> 51) & 0x7FF) as usize * 8;
                    (FixupKind::Bind, 0, bind_ordinal, addend, next_off, 0, false, 0)
                } else {
                    let target = raw & 0x0FFF_FFFF_FFFF;
                    let next_off = ((raw >> 51) & 0x7FF) as usize * 8;
                    (FixupKind::Rebase, target, 0, 0, next_off, 0, false, 0)
                }
            }
            ptr_format::PTR_64 | ptr_format::PTR_64_OFFSET => {
                // Bit 63: bind, bits [0..35] = target/ordinal
                let is_bind = (raw >> 63) & 1 != 0;
                let next_off = ((raw >> 51) & 0xFFF) as usize * 4;
                if is_bind {
                    let bind_ordinal = (raw & 0xFFFF) as u32;
                    let addend = ((raw >> 32) & 0x00FF_FFFF) as i64;
                    (FixupKind::Bind, 0, bind_ordinal, addend, next_off, 0, false, 0)
                } else {
                    let target = raw & 0x000F_FFFF_FFFF;
                    (FixupKind::Rebase, target, 0, 0, next_off, 0, false, 0)
                }
            }
            _ => {
                // Generic: treat as rebase, no chain continuation
                (FixupKind::Unknown((raw >> 62) as u8), raw & 0x0FFF_FFFF_FFFF, 0, 0, 0, 0, false, 0)
            }
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// All rebase fixups across all chains.
    #[must_use] 
    pub fn all_rebases(&self) -> Vec<&ChainedFixup> {
        self.chains.iter().flat_map(|c| c.rebases()).collect()
    }

    /// All bind fixups across all chains.
    #[must_use] 
    pub fn all_binds(&self) -> Vec<&ChainedFixup> {
        self.chains.iter().flat_map(|c| c.binds()).collect()
    }

    /// Lookup the import for a bind ordinal.
    #[must_use] 
    pub fn import_for_ordinal(&self, ordinal: u32) -> Option<&ChainImport> {
        self.imports.iter().find(|i| i.ordinal == ordinal)
    }

    /// Number of chains.
    #[must_use] 
    pub const fn chain_count(&self) -> usize {
        self.chains.len()
    }
}

/// Apply all chained fixups in `chains` to `image_bytes`.
///
/// For rebase fixups: the target address at `fixup.image_offset` is updated
/// to `fixup.target + slide`.
/// For bind fixups: the target address is set to the value supplied in
/// `bind_resolver(ordinal)` if the resolver is `Some`, otherwise the slot is
/// zeroed.
///
/// Returns the number of fixups applied.
///
/// # Errors
/// Returns [`FixupError`] if a fixup offset lies outside `image_bytes`.
pub fn apply_fixups(
    chains: &DyldFixupChains,
    image_bytes: &mut [u8],
    slide: u64,
    image_base: u64,
    bind_resolver: Option<&dyn Fn(u32) -> Option<u64>>,
) -> Result<usize, FixupError> {
    let mut applied = 0usize;

    for chain in &chains.chains {
        for fixup in &chain.fixups {
            let off = fixup.image_offset as usize;
            if off + 8 > image_bytes.len() {
                return Err(FixupError::OutOfBounds { offset: off, available: image_bytes.len() });
            }

            let patched: u64 = match fixup.kind {
                FixupKind::Rebase | FixupKind::AuthRebase => {
                    let base = if fixup.target >= image_base {
                        fixup.target
                    } else {
                        image_base + fixup.target
                    };
                    base.wrapping_add(slide)
                }
                FixupKind::Bind | FixupKind::AuthBind => {
                    if let Some(resolver) = bind_resolver {
                        resolver(fixup.bind_ordinal)
                            .map_or(0, |addr| addr.wrapping_add(fixup.addend.cast_unsigned()))
                    } else {
                        0
                    }
                }
                FixupKind::RebaseBind => {
                    image_base.wrapping_add(fixup.target).wrapping_add(slide)
                }
                FixupKind::Unknown(_) => continue,
            };

            image_bytes[off..off + 8].copy_from_slice(&patched.to_le_bytes());
            applied += 1;
        }
    }
    Ok(applied)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], off: usize) -> Result<u16, FixupError> {
    data.get(off..off + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FixupError::Truncated { offset: off, needed: 2 })
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32, FixupError> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FixupError::Truncated { offset: off, needed: 4 })
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64, FixupError> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FixupError::Truncated { offset: off, needed: 8 })
}

fn read_cstring(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fixup_header_blob() -> Vec<u8> {
        // Minimal valid dyld_chained_fixups_header with zero imports and zero chains.
        let mut blob = vec![0u8; 64];
        // fixups_version = 0
        blob[0..4].copy_from_slice(&0u32.to_le_bytes());
        // starts_offset = 28 (right after header)
        blob[4..8].copy_from_slice(&28u32.to_le_bytes());
        // imports_offset = 32
        blob[8..12].copy_from_slice(&32u32.to_le_bytes());
        // symbols_offset = 36
        blob[12..16].copy_from_slice(&36u32.to_le_bytes());
        // imports_count = 0
        blob[16..20].copy_from_slice(&0u32.to_le_bytes());
        // imports_format = 1
        blob[20..24].copy_from_slice(&1u32.to_le_bytes());
        // symbols_format = 0
        blob[24..28].copy_from_slice(&0u32.to_le_bytes());
        // seg_count = 0 at starts_offset(28)
        blob[28..32].copy_from_slice(&0u32.to_le_bytes());
        blob
    }

    #[test]
    fn test_parse_empty_chains() {
        let blob = make_fixup_header_blob();
        let chains = DyldFixupChains::parse(&blob).unwrap();
        assert_eq!(chains.chain_count(), 0);
        assert_eq!(chains.total_fixup_count, 0);
        assert!(chains.imports.is_empty());
    }

    #[test]
    fn test_parse_too_short() {
        let err = DyldFixupChains::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, FixupError::Truncated { .. }));
    }

    #[test]
    fn test_all_rebases_empty() {
        let blob = make_fixup_header_blob();
        let chains = DyldFixupChains::parse(&blob).unwrap();
        assert!(chains.all_rebases().is_empty());
    }

    #[test]
    fn test_all_binds_empty() {
        let blob = make_fixup_header_blob();
        let chains = DyldFixupChains::parse(&blob).unwrap();
        assert!(chains.all_binds().is_empty());
    }

    #[test]
    fn test_fixup_kind_display() {
        assert_eq!(FixupKind::Rebase.to_string(), "rebase");
        assert_eq!(FixupKind::Bind.to_string(), "bind");
        assert_eq!(FixupKind::AuthRebase.to_string(), "auth_rebase");
        assert_eq!(FixupKind::AuthBind.to_string(), "auth_bind");
    }

    #[test]
    fn test_chained_fixup_is_bind() {
        let f = ChainedFixup {
            image_offset: 0,
            kind: FixupKind::Bind,
            target: 0,
            bind_ordinal: 5,
            addend: 0,
            diversity: 0,
            addr_div: false,
            key: 0,
            raw_value: 0,
        };
        assert!(f.is_bind());
        assert!(!f.is_rebase());
    }

    #[test]
    fn test_chained_fixup_is_rebase() {
        let f = ChainedFixup {
            image_offset: 0,
            kind: FixupKind::Rebase,
            target: 0x1000,
            bind_ordinal: 0,
            addend: 0,
            diversity: 0,
            addr_div: false,
            key: 0,
            raw_value: 0,
        };
        assert!(f.is_rebase());
        assert!(!f.is_bind());
    }

    #[test]
    fn test_chained_fixup_rebased_target() {
        let f = ChainedFixup {
            image_offset: 0,
            kind: FixupKind::Rebase,
            target: 0x1_8000_0000,
            bind_ordinal: 0,
            addend: 0,
            diversity: 0,
            addr_div: false,
            key: 0,
            raw_value: 0,
        };
        assert_eq!(f.rebased_target(0x1000), 0x1_8000_1000);
    }

    #[test]
    fn test_apply_fixups_rebase() {
        // Build a fake DyldFixupChains with one rebase
        let chain = FixupChain {
            pointer_format: ptr_format::PTR_64,
            start_offset: 0,
            page_index: 0,
            fixups: vec![ChainedFixup {
                image_offset: 0,
                kind: FixupKind::Rebase,
                target: 0x1000,
                bind_ordinal: 0,
                addend: 0,
                diversity: 0,
                addr_div: false,
                key: 0,
                raw_value: 0,
            }],
        };
        let dfc = DyldFixupChains {
            chains: vec![chain],
            imports: Vec::new(),
            pointer_format: ptr_format::PTR_64,
            total_fixup_count: 1,
        };
        let mut image = vec![0u8; 16];
        let applied = apply_fixups(&dfc, &mut image, 0x1000, 0, None).unwrap();
        assert_eq!(applied, 1);
        let written = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(written, 0x2000); // 0x1000 (target, < image_base 0) + slide 0x1000
    }

    #[test]
    fn test_apply_fixups_bind_with_resolver() {
        let chain = FixupChain {
            pointer_format: ptr_format::PTR_64,
            start_offset: 0,
            page_index: 0,
            fixups: vec![ChainedFixup {
                image_offset: 0,
                kind: FixupKind::Bind,
                target: 0,
                bind_ordinal: 3,
                addend: 0x10,
                diversity: 0,
                addr_div: false,
                key: 0,
                raw_value: 0,
            }],
        };
        let dfc = DyldFixupChains {
            chains: vec![chain],
            imports: Vec::new(),
            pointer_format: ptr_format::PTR_64,
            total_fixup_count: 1,
        };
        let mut image = vec![0u8; 16];
        let resolver = |ord: u32| if ord == 3 { Some(0xDEAD_0000u64) } else { None };
        apply_fixups(&dfc, &mut image, 0, 0, Some(&resolver)).unwrap();
        let written = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(written, 0xDEAD_0010);
    }

    #[test]
    fn test_apply_fixups_out_of_bounds() {
        let chain = FixupChain {
            pointer_format: ptr_format::PTR_64,
            start_offset: 0,
            page_index: 0,
            fixups: vec![ChainedFixup {
                image_offset: 0xFFFF_FFFF,
                kind: FixupKind::Rebase,
                target: 0,
                bind_ordinal: 0,
                addend: 0,
                diversity: 0,
                addr_div: false,
                key: 0,
                raw_value: 0,
            }],
        };
        let dfc = DyldFixupChains {
            chains: vec![chain],
            imports: Vec::new(),
            pointer_format: ptr_format::PTR_64,
            total_fixup_count: 1,
        };
        let mut image = vec![0u8; 16];
        let err = apply_fixups(&dfc, &mut image, 0, 0, None).unwrap_err();
        assert!(matches!(err, FixupError::OutOfBounds { .. }));
    }

    #[test]
    fn test_fixup_error_display() {
        let e = FixupError::Truncated { offset: 0x10, needed: 8 };
        assert!(e.to_string().contains("truncated"));
        let e2 = FixupError::UnsupportedFormat(0xABCD);
        assert!(e2.to_string().contains("unsupported"));
    }

    #[test]
    fn test_decode_ptr_64_rebase() {
        // PTR_64: bit 63=0 → rebase
        let raw: u64 = 0x1000;
        let (kind, target, _, _, _, _, _, _) = DyldFixupChains::decode_ptr(raw, ptr_format::PTR_64);
        assert_eq!(kind, FixupKind::Rebase);
        assert_eq!(target, 0x1000);
    }

    #[test]
    fn test_decode_ptr_64_bind() {
        // PTR_64: bit 63=1 → bind
        let raw: u64 = 1u64 << 63 | 5;
        let (kind, _, bind_ord, _, _, _, _, _) = DyldFixupChains::decode_ptr(raw, ptr_format::PTR_64);
        assert_eq!(kind, FixupKind::Bind);
        assert_eq!(bind_ord, 5);
    }
}
