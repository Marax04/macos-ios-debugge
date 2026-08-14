//! `relocation_engine` — Relocation processing for the multi-format loader.
//!
//! This module provides types and functions for representing and applying
//! binary relocations.  Relocations modify the loaded image in-place so that
//! absolute references point to their final resolved addresses.
//!
//! # Supported relocation kinds
//!
//! * **x86-64** (ELF `SysV` AMD64 ABI): `R_X86_64_64`, `R_X86_64_PC32`,
//!   `R_X86_64_GOT32`, `R_X86_64_PLT32`, `R_X86_64_32`, `R_X86_64_32S`.
//! * **`AArch64` / ARM64** (ELF): `R_AARCH64_ABS64`, `R_AARCH64_ABS32`,
//!   `R_AARCH64_CALL26`, `R_AARCH64_ADR_PREL_PG_HI21`.
//! * **MIPS32**: `R_MIPS_32`, `R_MIPS_HI16`, `R_MIPS_LO16`,
//!   `R_MIPS_PC16`, `R_MIPS_26`.
//! * **Generic**: `Absolute32`, `Absolute64`, `Relative32`, `Relative64`.
//!
//! # Applying relocations
//!
//! Pass a mutable byte slice (the loaded image), a slice of [`RelocationEntry`]s,
//! and a symbol-resolver closure to [`apply_relocations`].  For batch use,
//! [`fix_up_binary`] bundles loading, relocation application, and optional
//! validation into one call.

use std::collections::HashMap;

// ─── RelocationKind ───────────────────────────────────────────────────────────

/// Relocation type, categorised by target architecture and ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationKind {
    // ── x86-64 (ELF SysV AMD64) ──────────────────────────────────────────────
    /// Absolute 64-bit reference (S + A).
    X86_64Abs64,
    /// PC-relative 32-bit reference (S + A - P).
    X86_64Pc32,
    /// 32-bit GOT offset (G + A).
    X86_64Got32,
    /// 32-bit PLT-relative offset (L + A - P).
    X86_64Plt32,
    /// Absolute 32-bit (zero-extended) reference (S + A).
    X86_64Abs32,
    /// Absolute 32-bit (sign-extended) reference (S + A).
    X86_64Abs32S,

    // ── AArch64 / ARM64 (ELF) ────────────────────────────────────────────────
    /// Absolute 64-bit reference (S + A).
    AArch64Abs64,
    /// Absolute 32-bit reference (S + A).
    AArch64Abs32,
    /// Call/branch offset (26-bit PC-relative, scaled by 4).
    AArch64Call26,
    /// ADR / ADRP page-relative 21-bit offset.
    AArch64AdrPrelPgHi21,

    // ── MIPS32 ───────────────────────────────────────────────────────────────
    /// Absolute 32-bit reference.
    Mips32,
    /// High 16 bits of a 32-bit reference.
    MipsHi16,
    /// Low 16 bits of a 32-bit reference.
    MipsLo16,
    /// PC-relative 16-bit branch offset.
    MipsPc16,
    /// 26-bit direct jump target.
    Mips26,

    // ── Generic / portable ───────────────────────────────────────────────────
    /// Generic absolute 32-bit patch.
    Absolute32,
    /// Generic absolute 64-bit patch.
    Absolute64,
    /// Generic 32-bit PC-relative patch.
    Relative32,
    /// Generic 64-bit PC-relative patch.
    Relative64,
}

impl RelocationKind {
    /// Return the size in bytes of the field modified by this relocation.
    #[must_use]
    pub const fn field_size(self) -> usize {
        match self {
            Self::X86_64Abs32
            | Self::X86_64Abs32S
            | Self::X86_64Pc32
            | Self::X86_64Got32
            | Self::X86_64Plt32
            | Self::AArch64Abs32
            | Self::AArch64Call26
            | Self::AArch64AdrPrelPgHi21
            | Self::Mips32
            | Self::MipsHi16
            | Self::MipsLo16
            | Self::MipsPc16
            | Self::Mips26
            | Self::Absolute32
            | Self::Relative32 => 4,
            Self::X86_64Abs64 | Self::AArch64Abs64 | Self::Absolute64 | Self::Relative64 => 8,
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86_64Abs64 => "R_X86_64_64",
            Self::X86_64Pc32 => "R_X86_64_PC32",
            Self::X86_64Got32 => "R_X86_64_GOT32",
            Self::X86_64Plt32 => "R_X86_64_PLT32",
            Self::X86_64Abs32 => "R_X86_64_32",
            Self::X86_64Abs32S => "R_X86_64_32S",
            Self::AArch64Abs64 => "R_AARCH64_ABS64",
            Self::AArch64Abs32 => "R_AARCH64_ABS32",
            Self::AArch64Call26 => "R_AARCH64_CALL26",
            Self::AArch64AdrPrelPgHi21 => "R_AARCH64_ADR_PREL_PG_HI21",
            Self::Mips32 => "R_MIPS_32",
            Self::MipsHi16 => "R_MIPS_HI16",
            Self::MipsLo16 => "R_MIPS_LO16",
            Self::MipsPc16 => "R_MIPS_PC16",
            Self::Mips26 => "R_MIPS_26",
            Self::Absolute32 => "ABS32",
            Self::Absolute64 => "ABS64",
            Self::Relative32 => "REL32",
            Self::Relative64 => "REL64",
        }
    }
}

impl std::fmt::Display for RelocationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── RelocationEntry ──────────────────────────────────────────────────────────

/// A single relocation record.
///
/// A relocation instructs the loader to patch `field_size()` bytes at
/// `offset_in_image` according to `kind`, using `symbol_name` and `addend`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Byte offset in the image where the field to be patched lives.
    pub offset_in_image: u64,
    /// Relocation kind (determines computation and field size).
    pub kind: RelocationKind,
    /// Name of the symbol this relocation references (may be empty for
    /// base-relative relocations).
    pub symbol_name: String,
    /// Addend value (A in ELF notation).
    pub addend: i64,
    /// Section index this relocation belongs to (informational).
    pub section_index: Option<u32>,
}

impl RelocationEntry {
    /// Construct a new `RelocationEntry`.
    #[must_use]
    pub fn new(
        offset_in_image: u64,
        kind: RelocationKind,
        symbol_name: impl Into<String>,
        addend: i64,
    ) -> Self {
        Self {
            offset_in_image,
            kind,
            symbol_name: symbol_name.into(),
            addend,
            section_index: None,
        }
    }

    /// Attach a section index.
    #[must_use]
    pub const fn with_section(mut self, section_index: u32) -> Self {
        self.section_index = Some(section_index);
        self
    }
}

// ─── RelocationError ──────────────────────────────────────────────────────────

/// Errors produced by [`apply_relocations`] and [`fix_up_binary`].
#[derive(Debug, thiserror::Error)]
pub enum RelocationError {
    /// The relocation offset is outside the image bounds.
    #[error("relocation at offset 0x{offset:x}: out of bounds (image size {size})")]
    OutOfBounds { offset: u64, size: usize },

    /// A required symbol was not found in the resolver.
    #[error("relocation at offset 0x{offset:x}: symbol '{name}' not found")]
    SymbolNotFound { offset: u64, name: String },

    /// An arithmetic overflow occurred during value computation.
    #[error("relocation at offset 0x{offset:x}: arithmetic overflow")]
    Overflow { offset: u64 },

    /// The relocation kind produced a value that does not fit in the field.
    #[error("relocation at offset 0x{offset:x}: value 0x{value:x} truncated by {kind}")]
    Truncation {
        offset: u64,
        value: u64,
        kind: String,
    },
}

// ─── apply_relocations ────────────────────────────────────────────────────────

/// Apply `relocations` to `image`, using `resolver` to look up symbol values.
///
/// `resolver` is called with the symbol name and should return the resolved
/// virtual address, or `None` if the symbol is undefined (which produces
/// [`RelocationError::SymbolNotFound`]).
///
/// `image_load_address` is the virtual address at which `image[0]` is mapped.
/// It is used to compute PC-relative values.
///
/// # Errors
///
/// Returns the first [`RelocationError`] encountered.  Callers that need
/// best-effort application should use [`apply_relocations_lossy`] instead.
pub fn apply_relocations<F>(
    image: &mut [u8],
    relocations: &[RelocationEntry],
    image_load_address: u64,
    resolver: F,
) -> Result<usize, RelocationError>
where
    F: Fn(&str) -> Option<u64>,
{
    let mut count = 0usize;
    for reloc in relocations {
        apply_one(image, reloc, image_load_address, &resolver)?;
        count += 1;
    }
    Ok(count)
}

/// Apply relocations in a best-effort manner, collecting all errors.
///
/// Returns `(applied_count, errors)`.
pub fn apply_relocations_lossy<F>(
    image: &mut [u8],
    relocations: &[RelocationEntry],
    image_load_address: u64,
    resolver: F,
) -> (usize, Vec<RelocationError>)
where
    F: Fn(&str) -> Option<u64>,
{
    let mut applied = 0;
    let mut errors = Vec::new();
    for reloc in relocations {
        match apply_one(image, reloc, image_load_address, &resolver) {
            Ok(()) => applied += 1,
            Err(e) => errors.push(e),
        }
    }
    (applied, errors)
}

/// Reinterpret the low 32 bits of a u64 as u32 (intentional truncation).
fn u64_low32(v: u64) -> u32 {
    u32::from_le_bytes(v.to_le_bytes()[..4].try_into().unwrap())
}

/// Reinterpret the low 16 bits of a u64 as u16 (intentional truncation).
fn u64_low16(v: u64) -> u16 {
    u16::from_le_bytes(v.to_le_bytes()[..2].try_into().unwrap())
}

/// Bitwise reinterpret u64 as i64 (intentional wrapping).
const fn u64_as_i64(v: u64) -> i64 {
    i64::from_ne_bytes(v.to_ne_bytes())
}

/// Bitwise reinterpret i64 as u64 (intentional sign-drop).
const fn i64_as_u64(v: i64) -> u64 {
    u64::from_ne_bytes(v.to_ne_bytes())
}

/// Bitwise reinterpret i32 as u32 (intentional sign-drop).
const fn i32_as_u32(v: i32) -> u32 {
    u32::from_ne_bytes(v.to_ne_bytes())
}

fn apply_x86_64_reloc(
    image: &mut [u8],
    reloc: &RelocationEntry,
    offset: usize,
    sym_value: u64,
    p: u64,
) -> Result<(), RelocationError> {
    match reloc.kind {
        RelocationKind::X86_64Abs64 | RelocationKind::AArch64Abs64 | RelocationKind::Absolute64 => {
            let val = sym_value.wrapping_add_signed(reloc.addend);
            image[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
        RelocationKind::X86_64Abs32 => {
            let val = sym_value.wrapping_add_signed(reloc.addend);
            if val > u64::from(u32::MAX) {
                return Err(RelocationError::Truncation { offset: reloc.offset_in_image, value: val, kind: reloc.kind.to_string() });
            }
            image[offset..offset + 4].copy_from_slice(&u64_low32(val).to_le_bytes());
        }
        RelocationKind::X86_64Abs32S => {
            let val = u64_as_i64(sym_value.wrapping_add_signed(reloc.addend));
            if val < i64::from(i32::MIN) || val > i64::from(i32::MAX) {
                return Err(RelocationError::Truncation { offset: reloc.offset_in_image, value: i64_as_u64(val), kind: reloc.kind.to_string() });
            }
            let v32 = i32::try_from(val).expect("bounds checked");
            image[offset..offset + 4].copy_from_slice(&v32.to_le_bytes());
        }
        RelocationKind::X86_64Pc32 | RelocationKind::X86_64Got32 | RelocationKind::X86_64Plt32 => {
            let val = u64_as_i64(sym_value.wrapping_add_signed(reloc.addend).wrapping_sub(p));
            if val < i64::from(i32::MIN) || val > i64::from(i32::MAX) {
                return Err(RelocationError::Truncation { offset: reloc.offset_in_image, value: i64_as_u64(val), kind: reloc.kind.to_string() });
            }
            let v32 = i32::try_from(val).expect("bounds checked");
            image[offset..offset + 4].copy_from_slice(&v32.to_le_bytes());
        }
        RelocationKind::Absolute32 => {
            let val = u64_low32(sym_value.wrapping_add_signed(reloc.addend));
            image[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }
        RelocationKind::Relative32 => {
            let raw = sym_value.wrapping_add_signed(reloc.addend).wrapping_sub(p);
            image[offset..offset + 4].copy_from_slice(&u64_low32(raw).to_le_bytes());
        }
        RelocationKind::Relative64 => {
            let val = u64_as_i64(sym_value.wrapping_add_signed(reloc.addend).wrapping_sub(p));
            image[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
        _ => {}
    }
    Ok(())
}

fn apply_aarch64_mips_reloc(
    image: &mut [u8],
    reloc: &RelocationEntry,
    offset: usize,
    sym_value: u64,
    p: u64,
) -> Result<(), RelocationError> {
    match reloc.kind {
        RelocationKind::AArch64Abs32 => {
            let val = u64_low32(sym_value.wrapping_add_signed(reloc.addend));
            image[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }
        RelocationKind::AArch64Call26 => {
            let delta = u64_as_i64(sym_value.wrapping_add_signed(reloc.addend).wrapping_sub(p));
            if delta % 4 != 0 {
                return Err(RelocationError::Truncation { offset: reloc.offset_in_image, value: i64_as_u64(delta), kind: "AArch64Call26 (target not 4-byte aligned)".to_string() });
            }
            let imm26 = i32::try_from(delta / 4).unwrap_or(i32::MAX);
            let instr = u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & !0x03FF_FFFF) | (i32_as_u32(imm26) & 0x03FF_FFFF);
            image[offset..offset + 4].copy_from_slice(&patched.to_le_bytes());
        }
        RelocationKind::AArch64AdrPrelPgHi21 => {
            let page_s = sym_value.wrapping_add_signed(reloc.addend) >> 12;
            let page_p = p >> 12;
            let delta = u64_low32(page_s.wrapping_sub(page_p));
            let instr = u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & !0x60FF_FFE0) | ((delta & 0x3) << 29) | (((delta >> 2) & 0x7FFFF) << 5);
            image[offset..offset + 4].copy_from_slice(&patched.to_le_bytes());
        }
        RelocationKind::Mips32 => {
            let val = u64_low32(sym_value.wrapping_add_signed(reloc.addend));
            image[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
        }
        RelocationKind::MipsHi16 => {
            let full = sym_value.wrapping_add_signed(reloc.addend);
            let hi = u64_low16((full.wrapping_add(0x8000)) >> 16);
            let instr = u32::from_be_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & 0xFFFF_0000) | u32::from(hi);
            image[offset..offset + 4].copy_from_slice(&patched.to_be_bytes());
        }
        RelocationKind::MipsLo16 => {
            let lo = u64_low16(sym_value.wrapping_add_signed(reloc.addend));
            let instr = u32::from_be_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & 0xFFFF_0000) | u32::from(lo);
            image[offset..offset + 4].copy_from_slice(&patched.to_be_bytes());
        }
        RelocationKind::MipsPc16 => {
            let delta_i64 = u64_as_i64(sym_value.wrapping_add_signed(reloc.addend).wrapping_sub(p));
            if delta_i64 < i64::from(i32::MIN) || delta_i64 > i64::from(i32::MAX) {
                return Err(RelocationError::Truncation { offset: reloc.offset_in_image, value: i64_as_u64(delta_i64), kind: "MipsPc16 (PC-relative delta out of i32 range)".to_string() });
            }
            let delta = i32::try_from(delta_i64).expect("bounds checked") / 4;
            let instr = u32::from_be_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & 0xFFFF_0000) | (i32_as_u32(delta) & 0xFFFF);
            image[offset..offset + 4].copy_from_slice(&patched.to_be_bytes());
        }
        RelocationKind::Mips26 => {
            let tgt = u64_low32(sym_value.wrapping_add_signed(reloc.addend) >> 2);
            let instr = u32::from_be_bytes(image[offset..offset + 4].try_into().unwrap());
            let patched = (instr & 0xFC00_0000) | (tgt & 0x03FF_FFFF);
            image[offset..offset + 4].copy_from_slice(&patched.to_be_bytes());
        }
        _ => {}
    }
    Ok(())
}

fn apply_one<F>(
    image: &mut [u8],
    reloc: &RelocationEntry,
    base: u64,
    resolver: &F,
) -> Result<(), RelocationError>
where
    F: Fn(&str) -> Option<u64>,
{
    let offset = usize::try_from(reloc.offset_in_image).unwrap_or(usize::MAX);
    let field_size = reloc.kind.field_size();

    if offset.checked_add(field_size).is_none_or(|end| end > image.len()) {
        return Err(RelocationError::OutOfBounds { offset: reloc.offset_in_image, size: image.len() });
    }

    let sym_value: u64 = if reloc.symbol_name.is_empty() {
        0
    } else {
        resolver(&reloc.symbol_name).ok_or_else(|| RelocationError::SymbolNotFound {
            offset: reloc.offset_in_image,
            name: reloc.symbol_name.clone(),
        })?
    };

    let p = base.checked_add(reloc.offset_in_image).ok_or(RelocationError::OutOfBounds {
        offset: reloc.offset_in_image,
        size: image.len(),
    })?;

    apply_x86_64_reloc(image, reloc, offset, sym_value, p)?;
    apply_aarch64_mips_reloc(image, reloc, offset, sym_value, p)?;
    Ok(())
}

// ─── fix_up_binary ────────────────────────────────────────────────────────────

/// High-level: apply all relocations in `relocations` to `image`, using
/// `symbols` as the resolver map.
///
/// Returns the number of successfully applied relocations.
///
/// # Errors
///
/// Returns the first [`RelocationError`] on failure.
pub fn fix_up_binary<S: ::std::hash::BuildHasher>(
    image: &mut Vec<u8>,
    relocations: &[RelocationEntry],
    image_load_address: u64,
    symbols: &HashMap<String, u64, S>,
) -> Result<usize, RelocationError> {
    apply_relocations(
        image.as_mut_slice(),
        relocations,
        image_load_address,
        |name| symbols.get(name).copied(),
    )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sym_map(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // ── RelocationKind ──────────────────────────────────────────────────────

    #[test]
    fn test_kind_field_size_32() {
        assert_eq!(RelocationKind::X86_64Abs32.field_size(), 4);
        assert_eq!(RelocationKind::Mips32.field_size(), 4);
        assert_eq!(RelocationKind::Absolute32.field_size(), 4);
    }

    #[test]
    fn test_kind_field_size_64() {
        assert_eq!(RelocationKind::X86_64Abs64.field_size(), 8);
        assert_eq!(RelocationKind::AArch64Abs64.field_size(), 8);
        assert_eq!(RelocationKind::Absolute64.field_size(), 8);
    }

    #[test]
    fn test_kind_names() {
        assert_eq!(RelocationKind::X86_64Abs64.name(), "R_X86_64_64");
        assert_eq!(RelocationKind::AArch64Call26.name(), "R_AARCH64_CALL26");
        assert_eq!(RelocationKind::Mips32.name(), "R_MIPS_32");
    }

    #[test]
    fn test_kind_display() {
        let s = RelocationKind::X86_64Pc32.to_string();
        assert_eq!(s, "R_X86_64_PC32");
    }

    // ── RelocationEntry ─────────────────────────────────────────────────────

    #[test]
    fn test_entry_new() {
        let r = RelocationEntry::new(0x100, RelocationKind::X86_64Abs64, "foo", 0);
        assert_eq!(r.offset_in_image, 0x100);
        assert_eq!(r.symbol_name, "foo");
        assert!(r.section_index.is_none());
    }

    #[test]
    fn test_entry_with_section() {
        let r = RelocationEntry::new(0, RelocationKind::Absolute32, "x", 0).with_section(2);
        assert_eq!(r.section_index, Some(2));
    }

    // ── apply_relocations — X86_64 ──────────────────────────────────────────

    #[test]
    fn test_x86_64_abs64() {
        let mut image = vec![0u8; 16];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::X86_64Abs64,
            "fn",
            0,
        )];
        let syms = sym_map(&[("fn", 0xDEAD_BEEF_1234_5678)]);
        let count = apply_relocations(&mut image, &relocs, 0x0, |n| syms.get(n).copied()).unwrap();
        assert_eq!(count, 1);
        let val = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(val, 0xDEAD_BEEF_1234_5678);
    }

    #[test]
    fn test_x86_64_abs32() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::X86_64Abs32,
            "sym",
            4,
        )];
        let syms = sym_map(&[("sym", 0x1000)]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u32::from_le_bytes(image[0..4].try_into().unwrap());
        assert_eq!(val, 0x1004);
    }

    #[test]
    fn test_x86_64_pc32() {
        // sym at 0x5000, patch at offset 0x10 in image loaded at 0x4000.
        // P = 0x4010, delta = sym + addend - P = 0x5000 + 0 - 0x4010 = 0xFF0
        let mut image = vec![0u8; 0x20];
        let relocs = vec![RelocationEntry::new(
            0x10,
            RelocationKind::X86_64Pc32,
            "target",
            0,
        )];
        let syms = sym_map(&[("target", 0x5000)]);
        apply_relocations(&mut image, &relocs, 0x4000, |n| syms.get(n).copied()).unwrap();
        let val = i32::from_le_bytes(image[0x10..0x14].try_into().unwrap());
        assert_eq!(val, 0xFF0);
    }

    #[test]
    fn test_x86_64_abs32_truncation_error() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::X86_64Abs32,
            "big",
            0,
        )];
        let syms = sym_map(&[("big", 0x1_0000_0000)]);
        let result = apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied());
        assert!(matches!(result, Err(RelocationError::Truncation { .. })));
    }

    // ── Generic relocations ─────────────────────────────────────────────────

    #[test]
    fn test_absolute32_generic() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(4, RelocationKind::Absolute32, "s", 8)];
        let syms = sym_map(&[("s", 0x100)]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u32::from_le_bytes(image[4..8].try_into().unwrap());
        assert_eq!(val, 0x108);
    }

    #[test]
    fn test_absolute64_generic() {
        let mut image = vec![0u8; 16];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::Absolute64,
            "",
            0x42,
        )];
        let syms = sym_map(&[]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(val, 0x42);
    }

    #[test]
    fn test_relative32_generic() {
        // sym=0x5000, base=0x4000, patch offset=0x10 -> P=0x4010, delta=0xFF0
        let mut image = vec![0u8; 0x20];
        let relocs = vec![RelocationEntry::new(
            0x10,
            RelocationKind::Relative32,
            "t",
            0,
        )];
        let syms = sym_map(&[("t", 0x5000)]);
        apply_relocations(&mut image, &relocs, 0x4000, |n| syms.get(n).copied()).unwrap();
        let val = i32::from_le_bytes(image[0x10..0x14].try_into().unwrap());
        assert_eq!(val, 0xFF0);
    }

    // ── MIPS ────────────────────────────────────────────────────────────────

    #[test]
    fn test_mips32() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(0, RelocationKind::Mips32, "fn", 0)];
        let syms = sym_map(&[("fn", 0x1234_5678)]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u32::from_be_bytes(image[0..4].try_into().unwrap());
        assert_eq!(val, 0x1234_5678);
    }

    // ── Error paths ─────────────────────────────────────────────────────────

    #[test]
    fn test_out_of_bounds() {
        let mut image = vec![0u8; 4];
        let relocs = vec![RelocationEntry::new(3, RelocationKind::X86_64Abs64, "x", 0)];
        let syms = sym_map(&[("x", 0x1000)]);
        let result = apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied());
        assert!(matches!(result, Err(RelocationError::OutOfBounds { .. })));
    }

    #[test]
    fn test_symbol_not_found() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::Absolute32,
            "missing",
            0,
        )];
        let syms: HashMap<String, u64> = HashMap::new();
        let result = apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied());
        assert!(matches!(
            result,
            Err(RelocationError::SymbolNotFound { .. })
        ));
    }

    #[test]
    fn test_lossy_collects_errors() {
        let mut image = vec![0u8; 8];
        let relocs = vec![
            RelocationEntry::new(0, RelocationKind::Absolute32, "good", 0),
            RelocationEntry::new(0, RelocationKind::Absolute32, "missing", 0),
        ];
        let syms = sym_map(&[("good", 0xAA)]);
        let (applied, errors) =
            apply_relocations_lossy(&mut image, &relocs, 0, |n| syms.get(n).copied());
        assert_eq!(applied, 1);
        assert_eq!(errors.len(), 1);
    }

    // ── fix_up_binary ───────────────────────────────────────────────────────

    #[test]
    fn test_fix_up_binary() {
        let mut image = vec![0u8; 16];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::Absolute64,
            "start",
            0,
        )];
        let syms = sym_map(&[("start", 0xCAFE_BABE_0000_0001)]);
        let count = fix_up_binary(&mut image, &relocs, 0, &syms).unwrap();
        assert_eq!(count, 1);
        let val = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(val, 0xCAFE_BABE_0000_0001);
    }

    // ── AArch64 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_aarch64_abs64() {
        let mut image = vec![0u8; 16];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::AArch64Abs64,
            "sym",
            0,
        )];
        let syms = sym_map(&[("sym", 0x0001_0000_0000_0000)]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(val, 0x0001_0000_0000_0000);
    }

    #[test]
    fn test_aarch64_abs32() {
        let mut image = vec![0u8; 8];
        let relocs = vec![RelocationEntry::new(
            0,
            RelocationKind::AArch64Abs32,
            "sym",
            0,
        )];
        let syms = sym_map(&[("sym", 0xABCD_EF00)]);
        apply_relocations(&mut image, &relocs, 0, |n| syms.get(n).copied()).unwrap();
        let val = u32::from_le_bytes(image[0..4].try_into().unwrap());
        assert_eq!(val, 0xABCD_EF00);
    }

    #[test]
    fn test_mips_hi16_lo16() {
        // sym = 0x1234_5678
        // hi = (0x1234_5678 + 0x8000) >> 16 = 0x1235
        // lo = 0x5678
        let sym = 0x1234_5678u64;
        let mut image_hi = [0u8; 4];
        let mut image_lo = [0u8; 4];
        // Encode as big-endian MIPS instruction (just use 0 as base instr)
        let reloc_hi = RelocationEntry::new(0, RelocationKind::MipsHi16, "s", 0);
        let reloc_lo = RelocationEntry::new(0, RelocationKind::MipsLo16, "s", 0);
        let syms = sym_map(&[("s", sym)]);
        apply_relocations(&mut image_hi, &[reloc_hi], 0, |n| syms.get(n).copied()).unwrap();
        apply_relocations(&mut image_lo, &[reloc_lo], 0, |n| syms.get(n).copied()).unwrap();
        let hi = u32::from_be_bytes(image_hi) & 0xFFFF;
        let lo = u32::from_be_bytes(image_lo) & 0xFFFF;
        // Reconstruct: hi << 16 + sign_extend(lo)
        let lo_i = i32::from(lo as i16);
        let reconstructed = ((hi as i32) << 16) + lo_i;
        assert_eq!(reconstructed as u64, sym);
    }
}
