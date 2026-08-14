//! `pe_header_editor` — Low-level PE header field editor.
//!
//! Provides [`PeHeaderEditor`] for reading and rewriting individual fields of
//! the DOS header, COFF file header, and optional header without requiring the
//! entire [`crate::PeEditor`] machinery.  Useful when you only need to tweak a
//! timestamp, flip a characteristic bit, or update version metadata without
//! touching section data.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Error produced by [`PeHeaderEditor`] operations.
#[derive(Debug, Error, Clone)]
pub enum HeaderEditError {
    /// The provided buffer is too short to contain a valid PE image.
    #[error("buffer too short: need {needed} bytes, have {got}")]
    TooShort { needed: usize, got: usize },
    /// The MZ signature at offset 0 is wrong.
    #[error("invalid MZ magic: {0:#06x}")]
    InvalidMzMagic(u16),
    /// The PE signature at `e_lfanew` is wrong.
    #[error("invalid PE signature at offset {0:#x}")]
    InvalidPeSignature(usize),
    /// A computed offset falls outside the buffer.
    #[error("field offset {offset:#x} (size {size}) is out of bounds (buf={buf_len})")]
    OffsetOutOfBounds {
        offset: usize,
        size: usize,
        buf_len: usize,
    },
    /// The optional header magic indicates an unsupported format.
    #[error("unsupported optional header magic: {0:#06x}")]
    UnsupportedMagic(u16),
}

// ─────────────────────────────────────────────────────────────────────────────
// DosHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Full `IMAGE_DOS_HEADER` (64 bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Parse from the first 64 bytes of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError::TooShort`] if `data.len() < 64` or
    /// [`HeaderEditError::InvalidMzMagic`] if the signature is wrong.
    pub fn parse(data: &[u8]) -> Result<Self, HeaderEditError> {
        if data.len() < 64 {
            return Err(HeaderEditError::TooShort {
                needed: 64,
                got: data.len(),
            });
        }
        let magic = r16(data, 0);
        if magic != 0x5A4D {
            return Err(HeaderEditError::InvalidMzMagic(magic));
        }
        let mut e_res = [0u16; 4];
        for (i, v) in e_res.iter_mut().enumerate() {
            *v = r16(data, 28 + i * 2);
        }
        let mut e_res2 = [0u16; 10];
        for (i, v) in e_res2.iter_mut().enumerate() {
            *v = r16(data, 36 + i * 2);
        }
        Ok(Self {
            e_magic: magic,
            e_cblp: r16(data, 2),
            e_cp: r16(data, 4),
            e_crlc: r16(data, 6),
            e_cparhdr: r16(data, 8),
            e_minalloc: r16(data, 10),
            e_maxalloc: r16(data, 12),
            e_ss: r16(data, 14),
            e_sp: r16(data, 16),
            e_csum: r16(data, 18),
            e_ip: r16(data, 20),
            e_cs: r16(data, 22),
            e_lfarlc: r16(data, 24),
            e_ovno: r16(data, 26),
            e_res,
            e_oemid: r16(data, 36),
            e_oeminfo: r16(data, 38),
            e_res2,
            e_lfanew: r32(data, 60),
        })
    }

    /// Serialize back into the first 64 bytes of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError::TooShort`] if `data.len() < 64`.
    pub fn write_to(&self, data: &mut [u8]) -> Result<(), HeaderEditError> {
        if data.len() < 64 {
            return Err(HeaderEditError::TooShort {
                needed: 64,
                got: data.len(),
            });
        }
        w16(data, 0, self.e_magic);
        w16(data, 2, self.e_cblp);
        w16(data, 4, self.e_cp);
        w16(data, 6, self.e_crlc);
        w16(data, 8, self.e_cparhdr);
        w16(data, 10, self.e_minalloc);
        w16(data, 12, self.e_maxalloc);
        w16(data, 14, self.e_ss);
        w16(data, 16, self.e_sp);
        w16(data, 18, self.e_csum);
        w16(data, 20, self.e_ip);
        w16(data, 22, self.e_cs);
        w16(data, 24, self.e_lfarlc);
        w16(data, 26, self.e_ovno);
        for (i, &v) in self.e_res.iter().enumerate() {
            w16(data, 28 + i * 2, v);
        }
        w16(data, 36, self.e_oemid);
        w16(data, 38, self.e_oeminfo);
        for (i, &v) in self.e_res2.iter().enumerate() {
            w16(data, 40 + i * 2, v);
        }
        w32(data, 60, self.e_lfanew);
        Ok(())
    }

    /// Returns `true` if the DOS signature matches.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.e_magic == 0x5A4D
    }
}

impl fmt::Display for DosHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DOS e_magic={:#06x} e_lfanew={:#x}",
            self.e_magic, self.e_lfanew
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeHeader (COFF file header)
// ─────────────────────────────────────────────────────────────────────────────

/// `IMAGE_FILE_HEADER` — the COFF file header that follows the "PE\0\0" signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeHeader {
    /// Target machine type (e.g. `0x8664` for AMD64).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Unix timestamp of when the binary was linked.
    pub time_date_stamp: u32,
    /// File offset of COFF symbol table (deprecated, normally 0).
    pub pointer_to_symbol_table: u32,
    /// Number of symbols (deprecated, normally 0).
    pub number_of_symbols: u32,
    /// Size in bytes of the optional header.
    pub size_of_optional_header: u16,
    /// Characteristics flags.
    pub characteristics: u16,
}

impl PeHeader {
    /// Parse from `data` at `offset` (where `data[offset..]` begins with
    /// the "PE\0\0" signature, followed by the 20-byte COFF header).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] on invalid signature or short buffer.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, HeaderEditError> {
        let needed = offset + 4 + 20;
        if data.len() < needed {
            return Err(HeaderEditError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let sig = r32(data, offset);
        if sig != 0x0000_4550 {
            return Err(HeaderEditError::InvalidPeSignature(offset));
        }
        let base = offset + 4;
        Ok(Self {
            machine: r16(data, base),
            number_of_sections: r16(data, base + 2),
            time_date_stamp: r32(data, base + 4),
            pointer_to_symbol_table: r32(data, base + 8),
            number_of_symbols: r32(data, base + 12),
            size_of_optional_header: r16(data, base + 16),
            characteristics: r16(data, base + 18),
        })
    }

    /// Serialize the COFF file header back into `data` at `pe_offset + 4`
    /// (after the "PE\0\0" signature which is not modified by this call).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the write would exceed the buffer.
    pub fn write_to(&self, data: &mut [u8], pe_offset: usize) -> Result<(), HeaderEditError> {
        let base = pe_offset + 4;
        let needed = base + 20;
        if data.len() < needed {
            return Err(HeaderEditError::TooShort {
                needed,
                got: data.len(),
            });
        }
        w16(data, base, self.machine);
        w16(data, base + 2, self.number_of_sections);
        w32(data, base + 4, self.time_date_stamp);
        w32(data, base + 8, self.pointer_to_symbol_table);
        w32(data, base + 12, self.number_of_symbols);
        w16(data, base + 16, self.size_of_optional_header);
        w16(data, base + 18, self.characteristics);
        Ok(())
    }

    /// Returns the machine name string for common architectures.
    #[must_use]
    pub const fn machine_name(&self) -> &'static str {
        match self.machine {
            0x0000 => "Unknown",
            0x014C => "i386",
            0x0200 => "IA64",
            0x8664 => "AMD64",
            0xAA64 => "ARM64",
            0x01C4 => "ARMv7",
            0x01C0 => "ARM",
            0x0EBC => "EFI-BC",
            _ => "Other",
        }
    }

    /// Returns `true` if `IMAGE_FILE_DLL` characteristic is set.
    #[must_use]
    pub const fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }

    /// Returns `true` if `IMAGE_FILE_EXECUTABLE_IMAGE` is set.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x0002 != 0
    }

    /// Returns `true` if stripped of relocation information.
    #[must_use]
    pub const fn is_relocs_stripped(&self) -> bool {
        self.characteristics & 0x0001 != 0
    }
}

impl fmt::Display for PeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "COFF machine={} sections={} timestamp={:#010x} chars={:#06x}",
            self.machine_name(),
            self.number_of_sections,
            self.time_date_stamp,
            self.characteristics,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptionalHeaderKind
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminator for 32-bit vs 64-bit optional headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptionalHeaderKind {
    /// `IMAGE_OPTIONAL_HEADER32` (magic 0x010B).
    Pe32,
    /// `IMAGE_OPTIONAL_HEADER64` (magic 0x020B).
    Pe32Plus,
}

impl OptionalHeaderKind {
    /// Try to construct from the magic value.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError::UnsupportedMagic`] if the magic is not
    /// `0x010B` or `0x020B`.
    pub const fn from_magic(magic: u16) -> Result<Self, HeaderEditError> {
        match magic {
            0x010B => Ok(Self::Pe32),
            0x020B => Ok(Self::Pe32Plus),
            other => Err(HeaderEditError::UnsupportedMagic(other)),
        }
    }

    /// Returns the magic value.
    #[must_use]
    pub const fn magic(self) -> u16 {
        match self {
            Self::Pe32 => 0x010B,
            Self::Pe32Plus => 0x020B,
        }
    }

    /// Byte offset of `ImageBase` within the optional header body.
    #[must_use]
    pub const fn image_base_offset(self) -> usize {
        match self {
            Self::Pe32 => 28,
            Self::Pe32Plus => 24,
        }
    }

    /// Byte size of `ImageBase` field.
    #[must_use]
    pub const fn image_base_size(self) -> usize {
        match self {
            Self::Pe32 => 4,
            Self::Pe32Plus => 8,
        }
    }
}

impl fmt::Display for OptionalHeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pe32 => write!(f, "PE32"),
            Self::Pe32Plus => write!(f, "PE32+"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeHeaderEditor
// ─────────────────────────────────────────────────────────────────────────────

/// High-level editor for PE header fields.
///
/// Wraps a mutable byte buffer and provides named methods for reading and
/// writing individual fields.  The buffer is not validated against a full PE
/// spec on construction — only the DOS magic and PE signature are checked.
pub struct PeHeaderEditor {
    data: Vec<u8>,
    pe_offset: usize,
    opt_offset: usize,
    opt_kind: OptionalHeaderKind,
}

impl PeHeaderEditor {
    /// Create an editor from a raw PE byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the DOS header or PE signature is invalid.
    pub fn new(data: Vec<u8>) -> Result<Self, HeaderEditError> {
        if data.len() < 64 {
            return Err(HeaderEditError::TooShort {
                needed: 64,
                got: data.len(),
            });
        }
        let magic = r16(&data, 0);
        if magic != 0x5A4D {
            return Err(HeaderEditError::InvalidMzMagic(magic));
        }
        let pe_offset = r32(&data, 60) as usize;
        if pe_offset + 24 + 2 > data.len() {
            return Err(HeaderEditError::TooShort {
                needed: pe_offset + 26,
                got: data.len(),
            });
        }
        let sig = r32(&data, pe_offset);
        if sig != 0x0000_4550 {
            return Err(HeaderEditError::InvalidPeSignature(pe_offset));
        }
        let opt_offset = pe_offset + 24;
        let magic2 = r16(&data, opt_offset);
        let opt_kind = OptionalHeaderKind::from_magic(magic2)?;
        Ok(Self {
            data,
            pe_offset,
            opt_offset,
            opt_kind,
        })
    }

    /// Return the PE signature offset.
    #[must_use]
    pub const fn pe_offset(&self) -> usize {
        self.pe_offset
    }

    /// Return the optional header offset.
    #[must_use]
    pub const fn opt_offset(&self) -> usize {
        self.opt_offset
    }

    /// Return the optional header kind (32-bit or 64-bit).
    #[must_use]
    pub const fn opt_kind(&self) -> OptionalHeaderKind {
        self.opt_kind
    }

    // ── DOS header ────────────────────────────────────────────────────────────

    /// Read the full DOS header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if parsing fails.
    pub fn read_dos_header(&self) -> Result<DosHeader, HeaderEditError> {
        DosHeader::parse(&self.data)
    }

    /// Write the full DOS header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the buffer is too short.
    pub fn write_dos_header(&mut self, dos: &DosHeader) -> Result<(), HeaderEditError> {
        dos.write_to(&mut self.data)
    }

    // ── COFF file header ──────────────────────────────────────────────────────

    /// Read the COFF file header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] on parse failure.
    pub fn read_pe_header(&self) -> Result<PeHeader, HeaderEditError> {
        PeHeader::parse(&self.data, self.pe_offset)
    }

    /// Write the COFF file header (preserves the PE signature).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the write would overflow the buffer.
    pub fn write_pe_header(&mut self, hdr: &PeHeader) -> Result<(), HeaderEditError> {
        hdr.write_to(&mut self.data, self.pe_offset)
    }

    // ── timestamp ─────────────────────────────────────────────────────────────

    /// Read the `TimeDateStamp` from the COFF file header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the field is out of bounds.
    pub fn read_timestamp(&self) -> Result<u32, HeaderEditError> {
        let off = self.pe_offset + 4 + 4;
        self.check_bounds(off, 4)?;
        Ok(r32(&self.data, off))
    }

    /// Write a new `TimeDateStamp` into the COFF file header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if the field is out of bounds.
    pub fn edit_timestamp(&mut self, ts: u32) -> Result<(), HeaderEditError> {
        let off = self.pe_offset + 4 + 4;
        self.check_bounds(off, 4)?;
        w32(&mut self.data, off, ts);
        Ok(())
    }

    /// Zero the timestamp (common anti-forensics step).
    ///
    /// # Errors
    ///
    /// Propagates from [`Self::edit_timestamp`].
    pub fn zero_timestamp(&mut self) -> Result<(), HeaderEditError> {
        self.edit_timestamp(0)
    }

    // ── characteristics ───────────────────────────────────────────────────────

    /// Read the COFF `Characteristics` field.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_characteristics(&self) -> Result<u16, HeaderEditError> {
        let off = self.pe_offset + 4 + 18;
        self.check_bounds(off, 2)?;
        Ok(r16(&self.data, off))
    }

    /// Write the COFF `Characteristics` field.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_characteristics(&mut self, chars: u16) -> Result<(), HeaderEditError> {
        let off = self.pe_offset + 4 + 18;
        self.check_bounds(off, 2)?;
        w16(&mut self.data, off, chars);
        Ok(())
    }

    /// Set or clear a single bit in the COFF `Characteristics` field.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn set_characteristic_bit(&mut self, bit: u16, set: bool) -> Result<(), HeaderEditError> {
        let mut chars = self.read_characteristics()?;
        if set {
            chars |= bit;
        } else {
            chars &= !bit;
        }
        self.write_characteristics(chars)
    }

    // ── optional header: image base ───────────────────────────────────────────

    /// Read `ImageBase` from the optional header.
    ///
    /// Returns `u64` regardless of Pe32 vs `Pe32Plus`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_image_base(&self) -> Result<u64, HeaderEditError> {
        let off = self.opt_offset + self.opt_kind.image_base_offset();
        match self.opt_kind {
            OptionalHeaderKind::Pe32 => {
                self.check_bounds(off, 4)?;
                Ok(u64::from(r32(&self.data, off)))
            }
            OptionalHeaderKind::Pe32Plus => {
                self.check_bounds(off, 8)?;
                Ok(r64(&self.data, off))
            }
        }
    }

    /// Write `ImageBase` into the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds or value truncated for PE32.
    ///
    /// # Panics
    /// Panics if `base` exceeds `u32::MAX` for a PE32 image (use [`HeaderEditError`] path instead).
    pub fn write_image_base(&mut self, base: u64) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + self.opt_kind.image_base_offset();
        match self.opt_kind {
            OptionalHeaderKind::Pe32 => {
                self.check_bounds(off, 4)?;
                w32(&mut self.data, off, u32::try_from(base).expect("image base fits in u32 for PE32"));
            }
            OptionalHeaderKind::Pe32Plus => {
                self.check_bounds(off, 8)?;
                w64(&mut self.data, off, base);
            }
        }
        Ok(())
    }

    // ── optional header: entry point ─────────────────────────────────────────

    /// Read `AddressOfEntryPoint` from the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_entry_point(&self) -> Result<u32, HeaderEditError> {
        let off = self.opt_offset + 16;
        self.check_bounds(off, 4)?;
        Ok(r32(&self.data, off))
    }

    /// Write `AddressOfEntryPoint`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_entry_point(&mut self, ep: u32) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + 16;
        self.check_bounds(off, 4)?;
        w32(&mut self.data, off, ep);
        Ok(())
    }

    // ── optional header: checksum ─────────────────────────────────────────────

    /// Read the `CheckSum` field from the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_checksum(&self) -> Result<u32, HeaderEditError> {
        let off = self.opt_offset + 64;
        self.check_bounds(off, 4)?;
        Ok(r32(&self.data, off))
    }

    /// Write a new `CheckSum` into the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_checksum(&mut self, csum: u32) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + 64;
        self.check_bounds(off, 4)?;
        w32(&mut self.data, off, csum);
        Ok(())
    }

    /// Zero the checksum field.
    ///
    /// # Errors
    ///
    /// Propagates from [`Self::write_checksum`].
    pub fn zero_checksum(&mut self) -> Result<(), HeaderEditError> {
        self.write_checksum(0)
    }

    // ── optional header: DllCharacteristics ──────────────────────────────────

    /// Read `DllCharacteristics` from the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_dll_characteristics(&self) -> Result<u16, HeaderEditError> {
        let off = self.opt_offset + 70;
        self.check_bounds(off, 2)?;
        Ok(r16(&self.data, off))
    }

    /// Write `DllCharacteristics`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_dll_characteristics(&mut self, dc: u16) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + 70;
        self.check_bounds(off, 2)?;
        w16(&mut self.data, off, dc);
        Ok(())
    }

    /// Set or clear a single `DllCharacteristics` bit.
    ///
    /// # Errors
    ///
    /// Propagates from read/write operations.
    pub fn set_dll_characteristic(&mut self, bit: u16, set: bool) -> Result<(), HeaderEditError> {
        let mut dc = self.read_dll_characteristics()?;
        if set {
            dc |= bit;
        } else {
            dc &= !bit;
        }
        self.write_dll_characteristics(dc)
    }

    // ── optional header: subsystem ────────────────────────────────────────────

    /// Read the `Subsystem` field.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_subsystem(&self) -> Result<u16, HeaderEditError> {
        let off = self.opt_offset + 68;
        self.check_bounds(off, 2)?;
        Ok(r16(&self.data, off))
    }

    /// Write the `Subsystem` field.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_subsystem(&mut self, sub: u16) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + 68;
        self.check_bounds(off, 2)?;
        w16(&mut self.data, off, sub);
        Ok(())
    }

    // ── optional header: version fields ──────────────────────────────────────

    /// Read a u16 field from the optional header body at `field_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_opt_u16(&self, field_offset: usize) -> Result<u16, HeaderEditError> {
        let off = self.opt_offset + field_offset;
        self.check_bounds(off, 2)?;
        Ok(r16(&self.data, off))
    }

    /// Write a u16 field into the optional header body at `field_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_opt_u16(&mut self, field_offset: usize, val: u16) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + field_offset;
        self.check_bounds(off, 2)?;
        w16(&mut self.data, off, val);
        Ok(())
    }

    /// Read a u32 field from the optional header body at `field_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn read_opt_u32(&self, field_offset: usize) -> Result<u32, HeaderEditError> {
        let off = self.opt_offset + field_offset;
        self.check_bounds(off, 4)?;
        Ok(r32(&self.data, off))
    }

    /// Write a u32 field into the optional header body at `field_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if out of bounds.
    pub fn write_opt_u32(&mut self, field_offset: usize, val: u32) -> Result<(), HeaderEditError> {
        let off = self.opt_offset + field_offset;
        self.check_bounds(off, 4)?;
        w32(&mut self.data, off, val);
        Ok(())
    }

    // ── data directory ────────────────────────────────────────────────────────

    /// Read a data directory entry (RVA, Size) at index `index` (0-based).
    ///
    /// The data directory table starts at a fixed offset within the optional
    /// header (after version/stack/heap/loader fields).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if `index >= 16` or out of bounds.
    pub fn read_data_directory(&self, index: usize) -> Result<(u32, u32), HeaderEditError> {
        let dd_base = self.data_directory_base();
        let off = dd_base + index * 8;
        self.check_bounds(off, 8)?;
        Ok((r32(&self.data, off), r32(&self.data, off + 4)))
    }

    /// Write a data directory entry at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError`] if `index >= 16` or out of bounds.
    pub fn write_data_directory(
        &mut self,
        index: usize,
        rva: u32,
        size: u32,
    ) -> Result<(), HeaderEditError> {
        let dd_base = self.data_directory_base();
        let off = dd_base + index * 8;
        self.check_bounds(off, 8)?;
        w32(&mut self.data, off, rva);
        w32(&mut self.data, off + 4, size);
        Ok(())
    }

    /// Zero a specific data directory entry (removes the reference).
    ///
    /// # Errors
    ///
    /// Propagates from [`Self::write_data_directory`].
    pub fn clear_data_directory(&mut self, index: usize) -> Result<(), HeaderEditError> {
        self.write_data_directory(index, 0, 0)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Consume the editor and return the modified bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the bytes without consuming.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    const fn check_bounds(&self, offset: usize, size: usize) -> Result<(), HeaderEditError> {
        if offset + size > self.data.len() {
            Err(HeaderEditError::OffsetOutOfBounds {
                offset,
                size,
                buf_len: self.data.len(),
            })
        } else {
            Ok(())
        }
    }

    const fn data_directory_base(&self) -> usize {
        match self.opt_kind {
            OptionalHeaderKind::Pe32 => self.opt_offset + 96,
            OptionalHeaderKind::Pe32Plus => self.opt_offset + 112,
        }
    }
}

impl fmt::Debug for PeHeaderEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeHeaderEditor {{ buf={} pe_off={:#x} kind={} }}",
            self.data.len(),
            self.pe_offset,
            self.opt_kind
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section header helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed section header entry with named fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionHeaderEntry {
    /// Section name (up to 8 bytes, NUL-padded).
    pub name: [u8; 8],
    /// Virtual size.
    pub virtual_size: u32,
    /// Relative virtual address.
    pub virtual_address: u32,
    /// Size of raw data on disk.
    pub size_of_raw_data: u32,
    /// File offset of raw data.
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations.
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers.
    pub pointer_to_line_numbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_line_numbers: u16,
    /// Section characteristics.
    pub characteristics: u32,
}

impl SectionHeaderEntry {
    /// Returns the section name as a UTF-8 string, trimming NUL bytes.
    #[must_use]
    pub fn name_str(&self) -> String {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..len]).into_owned()
    }

    /// Parse from `data` at `offset` (expects 40 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError::TooShort`] if the buffer is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, HeaderEditError> {
        let needed = offset + 40;
        if data.len() < needed {
            return Err(HeaderEditError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[offset..offset + 8]);
        Ok(Self {
            name,
            virtual_size: r32(data, offset + 8),
            virtual_address: r32(data, offset + 12),
            size_of_raw_data: r32(data, offset + 16),
            pointer_to_raw_data: r32(data, offset + 20),
            pointer_to_relocations: r32(data, offset + 24),
            pointer_to_line_numbers: r32(data, offset + 28),
            number_of_relocations: r16(data, offset + 32),
            number_of_line_numbers: r16(data, offset + 34),
            characteristics: r32(data, offset + 36),
        })
    }

    /// Serialize into `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderEditError::TooShort`] if the buffer is too short.
    pub fn write_to(&self, data: &mut [u8], offset: usize) -> Result<(), HeaderEditError> {
        let needed = offset + 40;
        if data.len() < needed {
            return Err(HeaderEditError::TooShort {
                needed,
                got: data.len(),
            });
        }
        data[offset..offset + 8].copy_from_slice(&self.name);
        w32(data, offset + 8, self.virtual_size);
        w32(data, offset + 12, self.virtual_address);
        w32(data, offset + 16, self.size_of_raw_data);
        w32(data, offset + 20, self.pointer_to_raw_data);
        w32(data, offset + 24, self.pointer_to_relocations);
        w32(data, offset + 28, self.pointer_to_line_numbers);
        w16(data, offset + 32, self.number_of_relocations);
        w16(data, offset + 34, self.number_of_line_numbers);
        w32(data, offset + 36, self.characteristics);
        Ok(())
    }

    /// Returns `true` if the characteristics include the executable flag.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Returns `true` if the characteristics include the writable flag.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Returns `true` if the characteristics include the readable flag.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
}

impl fmt::Display for SectionHeaderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Section '{}' va={:#010x} vsz={} raw_off={:#x} raw_sz={} chars={:#010x}",
            self.name_str(),
            self.virtual_address,
            self.virtual_size,
            self.pointer_to_raw_data,
            self.size_of_raw_data,
            self.characteristics,
        )
    }
}

/// Enumerate all section header entries from a PE buffer.
///
/// # Errors
///
/// Returns [`HeaderEditError`] if the PE structure is invalid or truncated.
pub fn enumerate_sections(
    data: &[u8],
) -> Result<Vec<SectionHeaderEntry>, HeaderEditError> {
    if data.len() < 64 {
        return Err(HeaderEditError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    if pe_off + 24 + 2 > data.len() {
        return Err(HeaderEditError::TooShort {
            needed: pe_off + 26,
            got: data.len(),
        });
    }
    let n_sects = r16(data, pe_off + 6) as usize;
    let opt_size = r16(data, pe_off + 20) as usize;
    let sect_base = pe_off + 24 + opt_size;
    let mut result = Vec::with_capacity(n_sects);
    for i in 0..n_sects {
        let off = sect_base + i * 40;
        result.push(SectionHeaderEntry::parse(data, off)?);
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Primitive read/write helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn r16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn r32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn r64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

#[inline]
fn w16(data: &mut [u8], off: usize, val: u16) {
    data[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn w32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn w64(data: &mut [u8], off: usize, val: u64) {
    data[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        // 512-byte buffer with valid MZ + PE + minimal optional header
        let mut buf = vec![0u8; 512];
        // DOS magic
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew = 0x80
        buf[60] = 0x80;
        // PE signature at 0x80
        buf[0x80] = 0x50;
        buf[0x81] = 0x45;
        buf[0x82] = 0x00;
        buf[0x83] = 0x00;
        // Machine = AMD64
        buf[0x84] = 0x64;
        buf[0x85] = 0x86;
        // NumberOfSections = 1
        buf[0x86] = 0x01;
        // TimeDateStamp
        buf[0x88] = 0xDE;
        buf[0x89] = 0xAD;
        buf[0x8A] = 0xBE;
        buf[0x8B] = 0xEF;
        // SizeOfOptionalHeader = 240
        buf[0x94] = 0xF0;
        // Characteristics
        buf[0x96] = 0x02; // IMAGE_FILE_EXECUTABLE_IMAGE
        // Optional header magic = PE32+
        buf[0x98] = 0x0B;
        buf[0x99] = 0x02;
        buf
    }

    #[test]
    fn test_parse_dos_header() {
        let buf = minimal_pe();
        let dos = DosHeader::parse(&buf).unwrap();
        assert_eq!(dos.e_magic, 0x5A4D);
        assert_eq!(dos.e_lfanew, 0x80);
        assert!(dos.is_valid());
    }

    #[test]
    fn test_parse_pe_header() {
        let buf = minimal_pe();
        let pe = PeHeader::parse(&buf, 0x80).unwrap();
        assert_eq!(pe.machine, 0x8664);
        assert_eq!(pe.time_date_stamp, 0xEFBE_ADDE);
        assert!(pe.is_executable());
        assert_eq!(pe.machine_name(), "AMD64");
    }

    #[test]
    fn test_edit_timestamp() {
        let buf = minimal_pe();
        let mut editor = PeHeaderEditor::new(buf).unwrap();
        editor.edit_timestamp(0x1234_5678).unwrap();
        assert_eq!(editor.read_timestamp().unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_zero_timestamp() {
        let buf = minimal_pe();
        let mut editor = PeHeaderEditor::new(buf).unwrap();
        editor.zero_timestamp().unwrap();
        assert_eq!(editor.read_timestamp().unwrap(), 0);
    }

    #[test]
    fn test_read_write_characteristics() {
        let buf = minimal_pe();
        let mut editor = PeHeaderEditor::new(buf).unwrap();
        let orig = editor.read_characteristics().unwrap();
        editor.write_characteristics(orig | 0x2000).unwrap();
        assert_eq!(editor.read_characteristics().unwrap() & 0x2000, 0x2000);
    }

    #[test]
    fn test_opt_kind_pe32plus() {
        let buf = minimal_pe();
        let editor = PeHeaderEditor::new(buf).unwrap();
        assert_eq!(editor.opt_kind(), OptionalHeaderKind::Pe32Plus);
    }

    #[test]
    fn test_invalid_mz_magic() {
        let mut buf = minimal_pe();
        buf[0] = 0;
        assert!(matches!(
            PeHeaderEditor::new(buf),
            Err(HeaderEditError::InvalidMzMagic(_))
        ));
    }

    #[test]
    fn test_dos_header_roundtrip() {
        let buf = minimal_pe();
        let dos = DosHeader::parse(&buf).unwrap();
        let mut buf2 = buf.clone();
        dos.write_to(&mut buf2).unwrap();
        let dos2 = DosHeader::parse(&buf2).unwrap();
        assert_eq!(dos, dos2);
    }

    #[test]
    fn test_pe_header_roundtrip() {
        let buf = minimal_pe();
        let pe = PeHeader::parse(&buf, 0x80).unwrap();
        let mut buf2 = buf.clone();
        pe.write_to(&mut buf2, 0x80).unwrap();
        let pe2 = PeHeader::parse(&buf2, 0x80).unwrap();
        assert_eq!(pe, pe2);
    }
}
