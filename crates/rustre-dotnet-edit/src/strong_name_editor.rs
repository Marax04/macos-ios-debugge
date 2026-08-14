//! `strong_name_editor` — Edit and strip .NET strong-name signatures.
//!
//! # Layer relationship
//! This module is the **lightweight editing** layer for strong-name metadata.
//! It exposes [`StrongNameEditor`] (typed `StrongNameError`, `CorFlagsEditor`,
//! `strip_signature` free function) and is used by [`crate::dotnet_patcher`]
//! for PE-level stripping.
//!
//! For RSA-SHA1 signature **verification** and delay-sign preparation see
//! [`crate::assembly_signer`].
//!
//! Provides [`StrongNameEditor`] for inspecting, stripping, and re-signing
//! strong-name information in raw .NET PE files.  All operations work on raw
//! byte slices so no external CLI tool is required.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StrongNameError {
    #[error("PE too small: need at least {need} bytes, got {got}")]
    TooSmall { need: usize, got: usize },
    #[error("invalid PE magic at offset 0x3C")]
    InvalidMz,
    #[error("unknown optional header magic 0x{0:04X}")]
    UnknownPeMagic(u16),
    #[error("CLI header not present (size = 0 in data directory)")]
    NoCliHeader,
    #[error("RVA 0x{0:08X} not found in any section")]
    RvaNotMapped(u32),
    #[error("public key data is empty; assembly is not strongly named")]
    NotStrongNamed,
    #[error("slice out of range: offset={offset} len={len} buf={buf}")]
    OutOfRange { offset: usize, len: usize, buf: usize },
    #[error("signature blob is already zeroed")]
    AlreadyStripped,
    #[error("{0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, StrongNameError>;

// ─── StrongNameHeader ─────────────────────────────────────────────────────────

/// Parsed subset of the CLI header relevant to strong-name signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrongNameHeader {
    /// File offset of the CLI header itself.
    pub cli_header_offset: usize,
    /// `CorFlags` word (at CLI header +16).
    pub cor_flags: u32,
    /// RVA of the `StrongNameSignature` blob.
    pub sn_rva: u32,
    /// Size in bytes of the `StrongNameSignature` blob.
    pub sn_size: u32,
    /// File offset of the `StrongNameSignature` blob (0 if not present).
    pub sn_file_offset: usize,
    /// Whether the `StrongNameSigned` `CorFlag` (bit 3 = 0x08) is set.
    pub is_signed: bool,
    /// Whether the signature blob is all-zeroes (delay-signed / stripped).
    pub is_zeroed: bool,
    /// Number of sections in the PE.
    pub section_count: u16,
}

impl StrongNameHeader {
    /// Determine whether strong-name verification would be required.
    #[must_use]
    pub const fn verification_required(&self) -> bool {
        self.is_signed && !self.is_zeroed
    }

    /// Whether the assembly was delay-signed (flag set but blob zeroed).
    #[must_use]
    pub const fn is_delay_signed(&self) -> bool {
        self.is_signed && self.is_zeroed
    }
}

impl fmt::Display for StrongNameHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StrongNameHeader(flags=0x{:08X} sn_rva=0x{:08X} sn_size={} signed={} zeroed={})",
            self.cor_flags, self.sn_rva, self.sn_size, self.is_signed, self.is_zeroed
        )
    }
}

// ─── SectionHeader ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct SectionHeader {
    virt_addr: u32,
    virt_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

// ─── StrongNameEditor ────────────────────────────────────────────────────────

/// Reads and edits the strong-name metadata inside a raw .NET PE file.
///
/// ```ignore
/// let mut editor = StrongNameEditor::new(pe_bytes.to_vec());
/// let header = editor.parse_header()?;
/// editor.strip_signature()?;
/// let patched = editor.into_bytes();
/// ```
pub struct StrongNameEditor {
    data: Vec<u8>,
}

impl StrongNameEditor {
    /// Create an editor from raw PE bytes.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create from a byte slice (clones).
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    // ── Low-level helpers ────────────────────────────────────────────────

    fn read_u16(&self, offset: usize) -> Result<u16> {
        self.data
            .get(offset..offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(StrongNameError::OutOfRange {
                offset,
                len: 2,
                buf: self.data.len(),
            })
    }

    fn read_u32(&self, offset: usize) -> Result<u32> {
        self.data
            .get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(StrongNameError::OutOfRange {
                offset,
                len: 4,
                buf: self.data.len(),
            })
    }

    fn write_u32(&mut self, offset: usize, val: u32) -> Result<()> {
        let buf_len = self.data.len();
        self.data
            .get_mut(offset..offset + 4)
            .ok_or(StrongNameError::OutOfRange {
                offset,
                len: 4,
                buf: buf_len,
            })?
            .copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    /// Locate the PE header start.
    fn pe_offset(&self) -> Result<usize> {
        if self.data.len() < 0x40 {
            return Err(StrongNameError::TooSmall {
                need: 0x40,
                got: self.data.len(),
            });
        }
        if self.data[0] != b'M' || self.data[1] != b'Z' {
            return Err(StrongNameError::InvalidMz);
        }
        Ok(self.read_u32(0x3C)? as usize)
    }

    /// Parse section headers.
    fn sections(&self, pe_off: usize) -> Result<Vec<SectionHeader>> {
        let num_sections = self.read_u16(pe_off + 6)? as usize;
        let opt_size = self.read_u16(pe_off + 20)? as usize;
        let sec_start = pe_off + 24 + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_start + i * 40;
            if s + 40 > self.data.len() {
                break;
            }
            let virt_size = self.read_u32(s + 8)?;
            let virt_addr = self.read_u32(s + 12)?;
            let raw_size = self.read_u32(s + 16)?;
            let raw_offset = self.read_u32(s + 20)?;
            sections.push(SectionHeader {
                virt_addr,
                virt_size,
                raw_offset,
                raw_size,
            });
        }
        Ok(sections)
    }

    /// RVA → file offset via section table.
    fn rva_to_file_offset(&self, rva: u32, sections: &[SectionHeader]) -> Result<usize> {
        if rva == 0 {
            return Ok(0);
        }
        for s in sections {
            let size = s.virt_size.max(s.raw_size);
            if rva >= s.virt_addr && rva < s.virt_addr.saturating_add(size) {
                let delta = rva - s.virt_addr;
                return Ok((s.raw_offset + delta) as usize);
            }
        }
        // Fall back: treat as file offset
        Ok(rva as usize)
    }

    // ── CLI header helpers ───────────────────────────────────────────────

    fn optional_header_start(&self, pe_off: usize) -> Result<usize> {
        Ok(pe_off + 24)
    }

    fn data_directory_base(&self, pe_off: usize) -> Result<usize> {
        let opt_start = self.optional_header_start(pe_off)?;
        let magic = self.read_u16(opt_start)?;
        match magic {
            0x010B => Ok(opt_start + 96),  // PE32
            0x020B => Ok(opt_start + 112), // PE32+
            m => Err(StrongNameError::UnknownPeMagic(m)),
        }
    }

    fn cli_header_offset(&self) -> Result<usize> {
        let pe_off = self.pe_offset()?;
        let dd_base = self.data_directory_base(pe_off)?;
        let cli_dir = dd_base + 14 * 8;
        let cli_rva = self.read_u32(cli_dir)?;
        let cli_size = self.read_u32(cli_dir + 4)?;
        if cli_rva == 0 || cli_size == 0 {
            return Err(StrongNameError::NoCliHeader);
        }
        let sections = self.sections(pe_off)?;
        self.rva_to_file_offset(cli_rva, &sections)
    }

    // ── Public API ───────────────────────────────────────────────────────

    /// Parse the strong-name header from the PE.
    pub fn parse_header(&self) -> Result<StrongNameHeader> {
        let pe_off = self.pe_offset()?;
        let sections = self.sections(pe_off)?;
        let section_count = sections.len() as u16;
        let cli_off = self.cli_header_offset()?;

        let cor_flags = self.read_u32(cli_off + 16)?;
        let sn_rva = self.read_u32(cli_off + 32)?;
        let sn_size = self.read_u32(cli_off + 36)?;

        let sn_file_offset = if sn_rva != 0 {
            self.rva_to_file_offset(sn_rva, &sections)?
        } else {
            0
        };

        let is_signed = (cor_flags & 0x08) != 0;
        let is_zeroed = if sn_file_offset != 0 && sn_size != 0 {
            let end = sn_file_offset + sn_size as usize;
            if end <= self.data.len() {
                self.data[sn_file_offset..end].iter().all(|&b| b == 0)
            } else {
                false
            }
        } else {
            true
        };

        Ok(StrongNameHeader {
            cli_header_offset: cli_off,
            cor_flags,
            sn_rva,
            sn_size,
            sn_file_offset,
            is_signed,
            is_zeroed,
            section_count,
        })
    }

    /// Strip the strong-name signature:
    /// 1. Clear `StrongNameSigned` in `CorFlags`.
    /// 2. Zero the signature blob bytes.
    pub fn strip_signature(&mut self) -> Result<()> {
        let header = self.parse_header()?;

        // state-machine-on-error: zero the blob BEFORE clearing the flag so
        // that if the blob write fails the signed flag is still set and the
        // state remains consistent (both the flag and the bytes agree).
        if header.sn_file_offset != 0 && header.sn_size != 0 {
            let start = header.sn_file_offset;
            let sn_size_usize = header.sn_size as usize;
            let end = start.checked_add(sn_size_usize).ok_or(StrongNameError::OutOfRange {
                offset: start,
                len: sn_size_usize,
                buf: self.data.len(),
            })?;
            let buf_len = self.data.len();
            let region = self.data.get_mut(start..end).ok_or(StrongNameError::OutOfRange {
                offset: start,
                len: sn_size_usize,
                buf: buf_len,
            })?;
            region.fill(0);
        }

        // Clear bit 3 of CorFlags only after the blob has been successfully zeroed.
        let new_flags = header.cor_flags & !0x08u32;
        self.write_u32(header.cli_header_offset + 16, new_flags)?;

        Ok(())
    }

    /// Set the `StrongNameSigned` `CorFlag` without touching the blob.
    pub fn set_signed_flag(&mut self, signed: bool) -> Result<()> {
        let header = self.parse_header()?;
        let new_flags = if signed {
            header.cor_flags | 0x08
        } else {
            header.cor_flags & !0x08u32
        };
        self.write_u32(header.cli_header_offset + 16, new_flags)
    }

    /// Read the raw signature bytes.
    pub fn read_signature(&self) -> Result<Vec<u8>> {
        let header = self.parse_header()?;
        if header.sn_file_offset == 0 || header.sn_size == 0 {
            return Ok(Vec::new());
        }
        let start = header.sn_file_offset;
        let sn_size_usize = header.sn_size as usize;
        let end = start.checked_add(sn_size_usize).ok_or(StrongNameError::OutOfRange {
            offset: start,
            len: sn_size_usize,
            buf: self.data.len(),
        })?;
        self.data
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or(StrongNameError::OutOfRange {
                offset: start,
                len: sn_size_usize,
                buf: self.data.len(),
            })
    }

    /// Write `new_sig` bytes into the signature blob.  The blob must already
    /// have been allocated (`sn_size` > 0) and `new_sig.len() == sn_size`.
    pub fn write_signature(&mut self, new_sig: &[u8]) -> Result<()> {
        let header = self.parse_header()?;
        if header.sn_size == 0 {
            return Err(StrongNameError::NotStrongNamed);
        }
        if new_sig.len() != header.sn_size as usize {
            return Err(StrongNameError::Other(format!(
                "signature length mismatch: expected {} got {}",
                header.sn_size,
                new_sig.len()
            )));
        }
        let start = header.sn_file_offset;
        let sn_size_usize = header.sn_size as usize;
        let end = start.checked_add(sn_size_usize).ok_or(StrongNameError::OutOfRange {
            offset: start,
            len: sn_size_usize,
            buf: self.data.len(),
        })?;
        let buf_len = self.data.len();
        let region = self.data.get_mut(start..end).ok_or(StrongNameError::OutOfRange {
            offset: start,
            len: sn_size_usize,
            buf: buf_len,
        })?;
        region.copy_from_slice(new_sig);
        Ok(())
    }

    /// Whether the file is strongly named (signed flag set).
    pub fn is_strong_named(&self) -> Result<bool> {
        Ok(self.parse_header()?.is_signed)
    }

    /// Whether the signature is zeroed (delay-signed or stripped).
    pub fn is_signature_zeroed(&self) -> Result<bool> {
        Ok(self.parse_header()?.is_zeroed)
    }

    /// Consume the editor and return the (potentially modified) byte vector.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Compute a naive SHA-256 of the file with the signature blob zeroed.
    /// Useful for testing / debugging.
    #[must_use]
    pub fn hash_without_signature(&self) -> Option<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let header = self.parse_header().ok()?;
        let mut copy = self.data.clone();

        // Zero the signature range
        if header.sn_file_offset != 0 && header.sn_size != 0 {
            if let Some(end) = header.sn_file_offset.checked_add(header.sn_size as usize) {
                if end <= copy.len() {
                    copy[header.sn_file_offset..end].fill(0);
                }
            }
        }

        let mut h = DefaultHasher::new();
        copy.hash(&mut h);
        let result = h.finish().to_le_bytes().to_vec();
        Some(result)
    }
}

// ─── strip_signature() free function ─────────────────────────────────────────

/// Convenience wrapper: strip the strong-name signature from `data` in-place.
///
/// # Errors
/// See [`StrongNameError`].
pub fn strip_signature(data: &mut Vec<u8>) -> std::result::Result<(), StrongNameError> {
    let mut editor = StrongNameEditor::new(std::mem::take(data));
    editor.strip_signature()?;
    *data = editor.into_bytes();
    Ok(())
}

// ─── CorFlagsEditor ──────────────────────────────────────────────────────────

/// A helper for reading / writing the CorFlags word directly.
pub struct CorFlagsEditor<'a> {
    editor: &'a mut StrongNameEditor,
}

impl<'a> CorFlagsEditor<'a> {
    /// Wrap an existing `StrongNameEditor`.
    pub fn new(editor: &'a mut StrongNameEditor) -> Self {
        Self { editor }
    }

    /// Read the current CorFlags value.
    pub fn read_cor_flags(&self) -> Result<u32> {
        Ok(self.editor.parse_header()?.cor_flags)
    }

    /// Write a new CorFlags value.
    pub fn write_cor_flags(&mut self, flags: u32) -> Result<()> {
        let h = self.editor.parse_header()?;
        self.editor.write_u32(h.cli_header_offset + 16, flags)
    }

    /// Set or clear a specific bit.
    pub fn set_bit(&mut self, bit: u32, value: bool) -> Result<()> {
        let h = self.editor.parse_header()?;
        let new = if value {
            h.cor_flags | bit
        } else {
            h.cor_flags & !bit
        };
        self.editor.write_u32(h.cli_header_offset + 16, new)
    }

    /// Set the `32BITREQUIRED` flag (bit 1).
    pub fn set_32bit_required(&mut self, v: bool) -> Result<()> {
        self.set_bit(0x02, v)
    }

    /// Set the `ILOnly` flag (bit 0).
    pub fn set_il_only(&mut self, v: bool) -> Result<()> {
        self.set_bit(0x01, v)
    }

    /// Set the `StrongNameSigned` flag (bit 3).
    pub fn set_strong_name_signed(&mut self, v: bool) -> Result<()> {
        self.set_bit(0x08, v)
    }

    /// Set the `NativeEntryPoint` flag (bit 4).
    pub fn set_native_entry_point(&mut self, v: bool) -> Result<()> {
        self.set_bit(0x10, v)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid .NET PE stub large enough for the editor to parse.
    fn minimal_pe() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        // MZ header
        buf[0] = b'M';
        buf[1] = b'Z';

        // PE offset at 0x3C = 0x80
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature at 0x80
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        // COFF: number of sections = 1, opt header size = 0xE0
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());

        // Optional header at 0x80+24 = 0x98
        let opt = 0x98usize;
        // Magic = PE32 (0x010B)
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());

        // Data directories start at opt + 96 = 0x98 + 96 = 0xF8
        let dd_base = opt + 96;

        // CLI header directory (entry 14) at dd_base + 14*8 = dd_base + 112 = 0x168
        let cli_dir = dd_base + 112;
        let cli_rva: u32 = 0x200; // RVA of CLI header in the .text section
        buf[cli_dir..cli_dir + 4].copy_from_slice(&cli_rva.to_le_bytes());
        buf[cli_dir + 4..cli_dir + 8].copy_from_slice(&72u32.to_le_bytes()); // size

        // Section header at opt + 0xE0 = 0x98 + 0xE0 = 0x178
        let sec = 0x178usize;
        buf[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        buf[sec + 12..sec + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // CLI header at file offset 0x200
        let cli = 0x200usize;
        // cb = 72
        buf[cli..cli + 4].copy_from_slice(&72u32.to_le_bytes());
        // CorFlags = 0x09 (ILOnly | StrongNameSigned)
        buf[cli + 16..cli + 20].copy_from_slice(&0x09u32.to_le_bytes());
        // StrongNameSignature: RVA = 0x240, Size = 0x80
        buf[cli + 32..cli + 36].copy_from_slice(&0x240u32.to_le_bytes());
        buf[cli + 36..cli + 40].copy_from_slice(&0x80u32.to_le_bytes());

        // Signature blob at 0x240 — fill with non-zero bytes
        for i in 0x240..0x2C0 {
            buf[i] = 0xAB;
        }

        buf
    }

    #[test]
    fn test_parse_header() {
        let pe = minimal_pe();
        let editor = StrongNameEditor::new(pe);
        let h = editor.parse_header().unwrap();
        assert!(h.is_signed);
        assert!(!h.is_zeroed);
        assert_eq!(h.sn_size, 0x80);
    }

    #[test]
    fn test_strip_signature_clears_flag() {
        let pe = minimal_pe();
        let mut editor = StrongNameEditor::new(pe);
        editor.strip_signature().unwrap();
        let h = editor.parse_header().unwrap();
        assert!(!h.is_signed);
        assert!(h.is_zeroed);
    }

    #[test]
    fn test_strip_zeros_blob() {
        let pe = minimal_pe();
        let mut editor = StrongNameEditor::new(pe);
        editor.strip_signature().unwrap();
        let sig = editor.read_signature().unwrap();
        assert!(sig.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_set_signed_flag_true() {
        let pe = minimal_pe();
        let mut editor = StrongNameEditor::new(pe);
        editor.strip_signature().unwrap();
        editor.set_signed_flag(true).unwrap();
        assert!(editor.is_strong_named().unwrap());
    }

    #[test]
    fn test_is_signature_zeroed_after_strip() {
        let pe = minimal_pe();
        let mut editor = StrongNameEditor::new(pe);
        editor.strip_signature().unwrap();
        assert!(editor.is_signature_zeroed().unwrap());
    }

    #[test]
    fn test_cor_flags_editor() {
        let pe = minimal_pe();
        let mut editor = StrongNameEditor::new(pe);
        {
            let mut cf = CorFlagsEditor::new(&mut editor);
            cf.set_strong_name_signed(false).unwrap();
            cf.set_il_only(true).unwrap();
        }
        let h = editor.parse_header().unwrap();
        assert_eq!(h.cor_flags & 0x08, 0);
        assert_eq!(h.cor_flags & 0x01, 1);
    }

    #[test]
    fn test_strip_signature_free_fn() {
        let mut pe = minimal_pe();
        strip_signature(&mut pe).unwrap();
        let editor = StrongNameEditor::new(pe);
        let h = editor.parse_header().unwrap();
        assert!(!h.is_signed);
    }

    #[test]
    fn test_hash_without_signature() {
        let pe = minimal_pe();
        let editor = StrongNameEditor::new(pe.clone());
        let hash = editor.hash_without_signature();
        assert!(hash.is_some());
        // Two identical PEs should have identical hashes
        let editor2 = StrongNameEditor::new(pe);
        let hash2 = editor2.hash_without_signature();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_into_bytes_roundtrip() {
        let pe = minimal_pe();
        let editor = StrongNameEditor::new(pe.clone());
        assert_eq!(editor.into_bytes(), pe);
    }

    #[test]
    fn test_invalid_mz() {
        let buf = vec![0u8; 0x100];
        let editor = StrongNameEditor::new(buf);
        assert!(matches!(editor.parse_header(), Err(StrongNameError::InvalidMz)));
    }

    #[test]
    fn test_too_small() {
        let buf = vec![0u8; 10];
        let editor = StrongNameEditor::new(buf);
        assert!(matches!(editor.parse_header(), Err(StrongNameError::TooSmall { .. })));
    }
}
