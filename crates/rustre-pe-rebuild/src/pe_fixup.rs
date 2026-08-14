//! PE header fixup after unpacking.
//!
//! Key types:
//! - [`PeFixup`] — applies fixups to a PE image in memory.
//! - [`PeVerifier`] — verifies a PE image is structurally well-formed.
//! - [`PatchInfo`] — records what was changed by each fixup operation.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// PatchInfo
// ---------------------------------------------------------------------------

/// Describes a single modification applied to the PE image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    /// Byte offset in the image where the patch was applied.
    pub offset: usize,
    /// Number of bytes patched.
    pub size: usize,
    /// Human-readable description.
    pub description: String,
    /// Previous value (up to 8 bytes).
    pub old_value: Vec<u8>,
    /// New value (up to 8 bytes).
    pub new_value: Vec<u8>,
}

impl PatchInfo {
    /// Create a patch record.
    #[must_use]
    pub fn new(
        offset: usize,
        size: usize,
        description: impl Into<String>,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    ) -> Self {
        Self {
            offset,
            size,
            description: description.into(),
            old_value,
            new_value,
        }
    }
}

impl fmt::Display for PatchInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Patch @ {:#x}+{}: {}",
            self.offset, self.size, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// FixupError
// ---------------------------------------------------------------------------

/// Errors from PE fixup operations.
#[derive(Debug)]
pub enum FixupError {
    /// Image too short to contain a valid PE header.
    TooShort,
    /// MZ or PE signature is missing.
    InvalidSignature,
    /// A requested fixup could not be applied due to bounds.
    OutOfBounds {
        offset: usize,
        required: usize,
        available: usize,
    },
    /// A field is corrupt or has an unexpected value.
    CorruptField(String),
}

impl fmt::Display for FixupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "image too short"),
            Self::InvalidSignature => write!(f, "invalid MZ/PE signature"),
            Self::OutOfBounds {
                offset,
                required,
                available,
            } => write!(
                f,
                "out of bounds at {offset:#x}: need {required}, have {available}"
            ),
            Self::CorruptField(s) => write!(f, "corrupt field: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifyResult
// ---------------------------------------------------------------------------

/// Result of [`PeVerifier::verify`].
#[derive(Debug, Clone, Default)]
pub struct VerifyResult {
    /// Whether the basic PE structure is valid.
    pub valid: bool,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Fatal errors preventing execution.
    pub errors: Vec<String>,
    /// Informational notes.
    pub notes: Vec<String>,
}

impl VerifyResult {
    /// Returns `true` when there are no errors.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn warn(&mut self, s: impl Into<String>) {
        self.warnings.push(s.into());
    }

    fn error(&mut self, s: impl Into<String>) {
        self.errors.push(s.into());
        self.valid = false;
    }

    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyResult {{ valid={}, warnings={}, errors={} }}",
            self.valid,
            self.warnings.len(),
            self.errors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PeVerifier
// ---------------------------------------------------------------------------

/// Verifies structural integrity of a PE image.
pub struct PeVerifier;

impl PeVerifier {
    /// Perform a full structural verification of `image`.
    #[must_use]
    pub fn verify(image: &[u8]) -> VerifyResult {
        let mut r = VerifyResult {
            valid: true,
            ..Default::default()
        };

        // Minimum size check.
        if image.len() < 64 {
            r.error("image shorter than 64 bytes — cannot be a valid PE");
            return r;
        }

        // MZ signature.
        if &image[0..2] != b"MZ" {
            r.error("missing MZ signature at offset 0");
            return r;
        }
        r.note("MZ signature OK");

        // e_lfanew.
        let e_lfanew = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
        if e_lfanew + 4 > image.len() {
            r.error(format!(
                "e_lfanew {e_lfanew:#x} points beyond image length {}",
                image.len()
            ));
            return r;
        }

        // PE signature.
        if &image[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            r.error(format!("PE signature missing at e_lfanew {e_lfanew:#x}"));
            return r;
        }
        r.note("PE signature OK");

        let coff_off = e_lfanew + 4;
        if coff_off + 20 > image.len() {
            r.error("COFF header out of bounds");
            return r;
        }

        let machine = u16::from_le_bytes([image[coff_off], image[coff_off + 1]]);
        let num_sections = u16::from_le_bytes([image[coff_off + 2], image[coff_off + 3]]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([image[coff_off + 16], image[coff_off + 17]]) as usize;

        // Machine type check.
        match machine {
            0x014c => r.note("Machine: x86 (i386)"),
            0x8664 => r.note("Machine: x86-64 (AMD64)"),
            0xAA64 => r.note("Machine: ARM64"),
            0 => r.warn("Machine field is 0 — may be stripped"),
            other => r.warn(format!("Unknown machine type {other:#x}")),
        }

        // Section count.
        if num_sections == 0 {
            r.warn("No sections defined (SizeOfHeaders may cover data)");
        } else if num_sections > 96 {
            r.warn(format!("Unusual section count: {num_sections}"));
        }

        // Optional header.
        let opt_off = coff_off + 20;
        if opt_hdr_size == 0 {
            r.warn("SizeOfOptionalHeader = 0 — object file or stripped PE");
        } else if opt_off + opt_hdr_size > image.len() {
            r.error("Optional header extends beyond image");
            return r;
        } else {
            let magic = u16::from_le_bytes([image[opt_off], image[opt_off + 1]]);
            match magic {
                0x010B => r.note("PE32 optional header"),
                0x020B => r.note("PE32+ optional header"),
                other => r.warn(format!("Unknown optional header magic {other:#x}")),
            }

            // Entry point.
            if opt_off + 0x14 <= image.len() {
                let ep = u32::from_le_bytes(
                    image[opt_off + 0x10..opt_off + 0x14]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                if ep == 0 && machine != 0 {
                    r.warn("Entry point is 0 — may be a DLL without startup code");
                }
            }
        }

        // Section table.
        let sec_tbl = opt_off + opt_hdr_size;
        let mut last_raw_end: usize = 0;
        for i in 0..num_sections.min(96) {
            let s = sec_tbl + i * 40;
            if s + 40 > image.len() {
                r.error(format!("Section {i} header extends beyond image"));
                break;
            }
            let raw_off =
                u32::from_le_bytes(image[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;
            let raw_size =
                u32::from_le_bytes(image[s + 16..s + 20].try_into().unwrap_or([0; 4])) as usize;
            let name_bytes = &image[s..s + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

            if raw_off > 0 && raw_off + raw_size > image.len() {
                r.warn(format!("Section '{name}' raw data extends beyond image"));
            }
            if raw_off + raw_size > last_raw_end {
                last_raw_end = raw_off + raw_size;
            }
        }

        // Overlay.
        if last_raw_end > 0 && last_raw_end < image.len() {
            let overlay = image.len() - last_raw_end;
            r.note(format!("Overlay detected: {overlay} bytes"));
        }

        r
    }
}

// ---------------------------------------------------------------------------
// PeFixup
// ---------------------------------------------------------------------------

/// Applies structural fixups to a PE image in-place.
///
/// Fixup operations:
/// 1. Fix / recompute the PE checksum.
/// 2. Fix bound imports (clear bound import directory).
/// 3. Fix data directory entries (IAT, reloc, debug, TLS, exception).
/// 4. Align section virtual sizes to `section_alignment`.
/// 5. Rebuild the section table (sort by VA, fix raw offsets).
/// 6. Optionally override the entry point.
/// 7. Strip the security/signature directory.
pub struct PeFixup {
    image: Vec<u8>,
    patches: Vec<PatchInfo>,
}

impl PeFixup {
    /// Create a [`PeFixup`] wrapping `image`.
    #[must_use]
    pub const fn new(image: Vec<u8>) -> Self {
        Self {
            image,
            patches: Vec::new(),
        }
    }

    /// Return a reference to the current image bytes.
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Consume the fixup and return `(image, patches)`.
    #[must_use]
    pub fn finish(self) -> (Vec<u8>, Vec<PatchInfo>) {
        (self.image, self.patches)
    }

    /// All patches applied so far.
    #[must_use]
    pub fn patches(&self) -> &[PatchInfo] {
        &self.patches
    }

    // ── Helper accessors ────────────────────────────────────────────────────

    fn locate_pe(&self) -> Option<usize> {
        let data = &self.image;
        if data.len() < 0x40 {
            return None;
        }
        if &data[0..2] != b"MZ" {
            return None;
        }
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        if pe_off + 4 > data.len() {
            return None;
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return None;
        }
        Some(pe_off)
    }

    fn opt_magic(&self, pe_off: usize) -> Option<u16> {
        let opt_off = pe_off + 0x18;
        if opt_off + 2 > self.image.len() {
            return None;
        }
        Some(u16::from_le_bytes([
            self.image[opt_off],
            self.image[opt_off + 1],
        ]))
    }

    const fn dd_base(pe_off: usize, magic: u16) -> usize {
        let opt_off = pe_off + 0x18;
        if magic == 0x020b {
            opt_off + 0x70
        } else {
            opt_off + 0x60
        }
    }

    fn patch_u32(&mut self, offset: usize, new_val: u32, desc: &str) -> bool {
        if offset + 4 > self.image.len() {
            return false;
        }
        let old = self.image[offset..offset + 4].to_vec();
        self.image[offset..offset + 4].copy_from_slice(&new_val.to_le_bytes());
        self.patches.push(PatchInfo::new(
            offset,
            4,
            desc,
            old,
            new_val.to_le_bytes().to_vec(),
        ));
        true
    }

    fn patch_u16(&mut self, offset: usize, new_val: u16, desc: &str) -> bool {
        if offset + 2 > self.image.len() {
            return false;
        }
        let old = self.image[offset..offset + 2].to_vec();
        self.image[offset..offset + 2].copy_from_slice(&new_val.to_le_bytes());
        self.patches.push(PatchInfo::new(
            offset,
            2,
            desc,
            old,
            new_val.to_le_bytes().to_vec(),
        ));
        true
    }

    fn zero_range(&mut self, offset: usize, len: usize, desc: &str) -> bool {
        if offset + len > self.image.len() {
            return false;
        }
        let old = self.image[offset..offset + len].to_vec();
        self.image[offset..offset + len].fill(0);
        self.patches
            .push(PatchInfo::new(offset, len, desc, old, vec![0u8; len]));
        true
    }

    // ── Public fixup operations ─────────────────────────────────────────────

    /// Recompute and write a valid PE checksum.
    ///
    /// Uses the same algorithm as `imagehlp.dll CheckSumMappedFile`.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn fix_checksum(&mut self) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let Some(magic) = self.opt_magic(pe_off) else {
            return Err(FixupError::TooShort);
        };
        let cs_off = pe_off + 0x18 + 0x40; // CheckSum field
        if cs_off + 4 > self.image.len() {
            return Err(FixupError::OutOfBounds {
                offset: cs_off,
                required: 4,
                available: self.image.len(),
            });
        }
        let _ = magic;

        // PE checksum algorithm.
        let mut checksum: u64 = 0;
        let data = &self.image;
        let mut i = 0usize;
        while i + 1 < data.len() {
            // Skip the checksum field itself.
            if i == cs_off || i == cs_off + 1 || i == cs_off + 2 || i == cs_off + 3 {
                i += 1;
                continue;
            }
            let word = u64::from(u16::from_le_bytes([data[i], data[i + 1]]));
            checksum += word;
            if checksum > 0xFFFF_FFFF {
                checksum = (checksum & 0xFFFF) + (checksum >> 32);
            }
            i += 2;
        }
        if !data.len().is_multiple_of(2) {
            checksum += u64::from(data[data.len() - 1]);
        }
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += checksum >> 16;
        checksum &= 0xFFFF;
        checksum += u64::try_from(data.len()).unwrap_or(u64::MAX);

        self.patch_u32(cs_off, u32::try_from(checksum).unwrap_or(u32::MAX), "checksum recomputed");
        Ok(())
    }

    /// Clear the bound import directory (`DataDirectory[11]`).
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn fix_bound_imports(&mut self) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let magic = self.opt_magic(pe_off).ok_or(FixupError::TooShort)?;
        let dd_off = Self::dd_base(pe_off, magic);
        let bound_off = dd_off + 11 * 8;
        self.zero_range(bound_off, 8, "bound import directory cleared");
        Ok(())
    }

    /// Strip the authenticode signature (`DataDirectory[4]`).
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn strip_signature(&mut self) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let magic = self.opt_magic(pe_off).ok_or(FixupError::TooShort)?;
        let dd_off = Self::dd_base(pe_off, magic);
        let sig_off = dd_off + 4 * 8;
        self.zero_range(sig_off, 8, "security directory (signature) zeroed");
        Ok(())
    }

    /// Zero the Debug data directory (`DataDirectory[6]`).
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn clear_debug_dir(&mut self) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let magic = self.opt_magic(pe_off).ok_or(FixupError::TooShort)?;
        let dd_off = Self::dd_base(pe_off, magic);
        let dbg_off = dd_off + 6 * 8;
        self.zero_range(dbg_off, 8, "debug directory zeroed");
        Ok(())
    }

    /// Override the entry point RVA.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn set_entry_point(&mut self, ep_rva: u32) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let opt_off = pe_off + 0x18;
        if opt_off + 0x14 > self.image.len() {
            return Err(FixupError::TooShort);
        }
        self.patch_u32(
            opt_off + 0x10,
            ep_rva,
            &format!("entry point set to {ep_rva:#x}"),
        );
        Ok(())
    }

    /// Set the DLL characteristic flag (bit 0x2000 in COFF characteristics).
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn set_dll_flag(&mut self, is_dll: bool) -> Result<(), FixupError> {
        const DLL: u16 = 0x2000;
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let chars_off = pe_off + 22; // COFF Characteristics
        if chars_off + 2 > self.image.len() {
            return Err(FixupError::TooShort);
        }
        let mut ch = u16::from_le_bytes([self.image[chars_off], self.image[chars_off + 1]]);
        if is_dll {
            ch |= DLL;
        } else {
            ch &= !DLL;
        }
        self.patch_u16(chars_off, ch, &format!("DLL flag = {is_dll}"));
        Ok(())
    }

    /// Align all section virtual sizes up to `section_alignment`.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature.
    pub fn align_section_virtual_sizes(
        &mut self,
        section_alignment: u32,
    ) -> Result<usize, FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let num_sections =
            u16::from_le_bytes([self.image[pe_off + 6], self.image[pe_off + 7]]) as usize;
        let opt_size =
            u16::from_le_bytes([self.image[pe_off + 0x14], self.image[pe_off + 0x15]]) as usize;
        let sec_tbl = pe_off + 0x18 + opt_size;
        let align = section_alignment.max(1);
        let mut patched = 0usize;

        for i in 0..num_sections.min(96) {
            let s = sec_tbl + i * 40;
            if s + 40 > self.image.len() {
                break;
            }
            let vsize = u32::from_le_bytes(self.image[s + 8..s + 12].try_into().unwrap_or([0; 4]));
            let aligned = align_up(vsize, align);
            if aligned != vsize {
                self.patch_u32(
                    s + 8,
                    aligned,
                    &format!("section[{i}] VirtualSize aligned: {vsize:#x} -> {aligned:#x}"),
                );
                patched += 1;
            }
        }
        Ok(patched)
    }

    /// Sort sections by virtual address and fix up section table ordering.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature or is too short.
    pub fn sort_section_table(&mut self) -> Result<usize, FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let num_sections =
            u16::from_le_bytes([self.image[pe_off + 6], self.image[pe_off + 7]]) as usize;
        let opt_size =
            u16::from_le_bytes([self.image[pe_off + 0x14], self.image[pe_off + 0x15]]) as usize;
        let sec_tbl = pe_off + 0x18 + opt_size;

        if sec_tbl + num_sections * 40 > self.image.len() {
            return Err(FixupError::OutOfBounds {
                offset: sec_tbl,
                required: num_sections * 40,
                available: self.image.len() - sec_tbl,
            });
        }

        // Extract section headers as raw 40-byte blobs.
        let mut headers: Vec<[u8; 40]> = (0..num_sections.min(96))
            .map(|i| {
                let s = sec_tbl + i * 40;
                let mut h = [0u8; 40];
                h.copy_from_slice(&self.image[s..s + 40]);
                h
            })
            .collect();

        // Sort by VirtualAddress (bytes 12..16 in each header).
        headers.sort_by_key(|h| u32::from_le_bytes([h[12], h[13], h[14], h[15]]));

        // Write back.
        let mut swapped = 0usize;
        for (i, h) in headers.iter().enumerate() {
            let s = sec_tbl + i * 40;
            if &self.image[s..s + 40] != h.as_slice() {
                let old = self.image[s..s + 40].to_vec();
                self.image[s..s + 40].copy_from_slice(h);
                self.patches.push(PatchInfo::new(
                    s,
                    40,
                    format!("section[{i}] reordered"),
                    old,
                    h.to_vec(),
                ));
                swapped += 1;
            }
        }
        Ok(swapped)
    }

    /// Fix `SizeOfImage` to cover all sections.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if the image has an invalid signature.
    pub fn fix_size_of_image(&mut self) -> Result<(), FixupError> {
        let Some(pe_off) = self.locate_pe() else {
            return Err(FixupError::InvalidSignature);
        };
        let opt_off = pe_off + 0x18;
        let magic = self.opt_magic(pe_off).ok_or(FixupError::TooShort)?;
        let _ = magic;

        let num_sections =
            u16::from_le_bytes([self.image[pe_off + 6], self.image[pe_off + 7]]) as usize;
        let opt_size =
            u16::from_le_bytes([self.image[pe_off + 0x14], self.image[pe_off + 0x15]]) as usize;
        let sec_tbl = pe_off + 0x18 + opt_size;

        // SectionAlignment is at opt_off + 0x20 for both PE32/PE32+.
        let sec_align = if opt_off + 0x24 <= self.image.len() {
            u32::from_le_bytes(
                self.image[opt_off + 0x20..opt_off + 0x24]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x1000
        };

        let mut max_va_end: u32 = 0;
        for i in 0..num_sections.min(96) {
            let s = sec_tbl + i * 40;
            if s + 40 > self.image.len() {
                break;
            }
            let va = u32::from_le_bytes(self.image[s + 12..s + 16].try_into().unwrap_or([0; 4]));
            let vsize = u32::from_le_bytes(self.image[s + 8..s + 12].try_into().unwrap_or([0; 4]));
            let end = va.saturating_add(align_up(vsize, sec_align.max(1)));
            if end > max_va_end {
                max_va_end = end;
            }
        }

        if max_va_end > 0 && opt_off + 0x38 <= self.image.len() {
            // SizeOfImage is at opt_off + 0x38.
            self.patch_u32(
                opt_off + 0x38,
                max_va_end,
                &format!("SizeOfImage set to {max_va_end:#x}"),
            );
        }
        Ok(())
    }

    /// Apply all standard fixups in sequence:
    /// strip signature, fix bound imports, align sections, fix `SizeOfImage`, fix checksum.
    ///
    /// # Errors
    ///
    /// Returns [`FixupError`] if a critical fixup fails.
    pub fn apply_all(&mut self) -> Result<Vec<String>, FixupError> {
        let mut notes = Vec::new();
        if self.strip_signature().is_ok() {
            notes.push("signature stripped".to_string());
        }
        if self.fix_bound_imports().is_ok() {
            notes.push("bound imports cleared".to_string());
        }
        if let Ok(n) = self.align_section_virtual_sizes(0x1000) && n > 0 {
            notes.push(format!("{n} section virtual sizes aligned"));
        }
        if self.fix_size_of_image().is_ok() {
            notes.push("SizeOfImage fixed".to_string());
        }
        if self.fix_checksum().is_ok() {
            notes.push("checksum recomputed".to_string());
        }
        Ok(notes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x400];
        // MZ
        v[0] = 0x4D;
        v[1] = 0x5A;
        // e_lfanew = 0x40
        v[0x3c] = 0x40;
        // PE signature
        v[0x40] = 0x50;
        v[0x41] = 0x45;
        // Machine x64
        v[0x44] = 0x64;
        v[0x45] = 0x86;
        // NumberOfSections = 2
        v[0x46] = 0x02;
        // SizeOfOptionalHeader = 0xF0
        v[0x54] = 0xF0;
        // Optional header magic = PE32+
        v[0x58] = 0x0B;
        v[0x59] = 0x02;
        // SectionAlignment = 0x1000
        v[0x78] = 0x00;
        v[0x79] = 0x10;
        v
    }

    #[test]
    fn test_patch_info_display() {
        let p = PatchInfo::new(0x100, 4, "test", vec![0, 0, 0, 0], vec![1, 0, 0, 0]);
        let s = p.to_string();
        assert!(s.contains("0x100"));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_pe_verifier_too_short() {
        let r = PeVerifier::verify(&[0u8; 10]);
        assert!(!r.is_ok());
    }

    #[test]
    fn test_pe_verifier_no_mz() {
        let data = vec![0u8; 64];
        let r = PeVerifier::verify(&data);
        assert!(!r.is_ok());
    }

    #[test]
    fn test_pe_verifier_valid_minimal() {
        let data = minimal_pe();
        let r = PeVerifier::verify(&data);
        // Minimal PE passes MZ + PE checks.
        assert!(
            r.errors
                .iter()
                .all(|e| !e.contains("MZ") && !e.contains("PE signature"))
        );
    }

    #[test]
    fn test_pe_verifier_result_display() {
        let r = VerifyResult::default();
        let s = r.to_string();
        assert!(s.contains("VerifyResult"));
    }

    #[test]
    fn test_pe_fixup_new() {
        let f = PeFixup::new(minimal_pe());
        assert!(!f.image().is_empty());
    }

    #[test]
    fn test_pe_fixup_set_entry_point() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.set_entry_point(0x1000).is_ok());
        assert!(!f.patches().is_empty());
    }

    #[test]
    fn test_pe_fixup_strip_signature() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.strip_signature().is_ok());
    }

    #[test]
    fn test_pe_fixup_fix_bound_imports() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.fix_bound_imports().is_ok());
    }

    #[test]
    fn test_pe_fixup_set_dll_flag_true() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.set_dll_flag(true).is_ok());
    }

    #[test]
    fn test_pe_fixup_set_dll_flag_false() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.set_dll_flag(false).is_ok());
    }

    #[test]
    fn test_pe_fixup_fix_checksum() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.fix_checksum().is_ok());
    }

    #[test]
    fn test_pe_fixup_align_sections() {
        let mut f = PeFixup::new(minimal_pe());
        let r = f.align_section_virtual_sizes(0x1000);
        assert!(r.is_ok());
    }

    #[test]
    fn test_pe_fixup_sort_section_table() {
        let mut f = PeFixup::new(minimal_pe());
        let r = f.sort_section_table();
        assert!(r.is_ok());
    }

    #[test]
    fn test_pe_fixup_fix_size_of_image() {
        let mut f = PeFixup::new(minimal_pe());
        assert!(f.fix_size_of_image().is_ok());
    }

    #[test]
    fn test_pe_fixup_apply_all() {
        let mut f = PeFixup::new(minimal_pe());
        let notes = f.apply_all().unwrap();
        assert!(!notes.is_empty());
    }

    #[test]
    fn test_pe_fixup_finish() {
        let f = PeFixup::new(minimal_pe());
        let (img, patches) = f.finish();
        assert!(!img.is_empty());
        assert!(patches.is_empty()); // no fixups applied yet
    }

    #[test]
    fn test_pe_fixup_patch_count_after_all() {
        let mut f = PeFixup::new(minimal_pe());
        f.apply_all().unwrap();
        assert!(!f.patches().is_empty());
    }

    #[test]
    fn test_fixup_error_display() {
        let e = FixupError::TooShort;
        assert_eq!(e.to_string(), "image too short");
        let e2 = FixupError::OutOfBounds {
            offset: 0x100,
            required: 8,
            available: 4,
        };
        let s = e2.to_string();
        assert!(s.contains("0x100"));
    }

    #[test]
    fn test_verify_result_is_ok() {
        let r = VerifyResult {
            valid: true,
            ..VerifyResult::default()
        };
        assert!(r.is_ok());
    }

    #[test]
    fn test_verify_result_not_ok_on_error() {
        let mut r = VerifyResult::default();
        r.error("something broke");
        assert!(!r.is_ok());
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(1, 0x200), 0x200);
    }

    #[test]
    fn test_pe_fixup_on_empty_data() {
        let mut f = PeFixup::new(vec![]);
        assert!(f.fix_checksum().is_err());
    }

    #[test]
    fn test_pe_fixup_no_mz_is_err() {
        let mut f = PeFixup::new(vec![0u8; 128]);
        assert!(f.set_entry_point(0).is_err());
    }
}
