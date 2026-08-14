//! `overlay_editor` — Manipulate PE overlay data.
//!
//! The PE overlay is any data that follows the last section's raw data in the
//! file.  It is often used by self-extracting archives, installers, and some
//! packers to append additional payloads.
//!
//! This module provides:
//!
//! * [`Overlay`] — represents an overlay (byte offset + content).
//! * [`detect_overlay`] — determine whether a PE file has an overlay and where
//!   it starts.
//! * [`OverlayEditor`] — append, strip, and inspect PE overlay data.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Overlay
// ---------------------------------------------------------------------------

/// An overlay: data appended after the last PE section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlay {
    /// File offset at which the overlay begins.
    pub offset: usize,
    /// The overlay data bytes.
    pub data: Vec<u8>,
}

impl Overlay {
    /// Create a new overlay at `offset` with the given `data`.
    #[must_use]
    pub const fn new(offset: usize, data: Vec<u8>) -> Self {
        Self { offset, data }
    }

    /// Length of the overlay in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the overlay contains no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the first `n` bytes of the overlay as a slice (or fewer if shorter).
    #[must_use]
    pub fn head(&self, n: usize) -> &[u8] {
        let end = n.min(self.data.len());
        &self.data[..end]
    }

    /// Compute a simple FNV-1a 64-bit hash of the overlay data.
    #[must_use]
    pub fn fnv1a_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Overlay[offset={:#x}, size={}]",
            self.offset,
            self.data.len()
        )
    }
}

// ---------------------------------------------------------------------------
// detect_overlay — determine the overlay offset for a PE file
// ---------------------------------------------------------------------------

/// Determine the byte offset at which the overlay begins in `pe_data`.
///
/// The overlay starts immediately after the last section's raw data ends.
/// Returns `None` if `pe_data` is too short, malformed, or has no sections.
#[must_use]
pub fn detect_overlay(pe_data: &[u8]) -> Option<usize> {
    if pe_data.len() < 64 {
        return None;
    }

    // Read e_lfanew at offset 60 (DOS header).
    let pe_offset =
        u32::from_le_bytes([pe_data[60], pe_data[61], pe_data[62], pe_data[63]]) as usize;
    if pe_offset + 24 > pe_data.len() {
        return None;
    }

    // Verify PE signature.
    if &pe_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    // Number of sections at PE + 6.
    let n_sections = u16::from_le_bytes([pe_data[pe_offset + 6], pe_data[pe_offset + 7]]) as usize;
    if n_sections == 0 {
        return None;
    }

    // Size of optional header at PE + 20.
    let opt_hdr_size =
        u16::from_le_bytes([pe_data[pe_offset + 20], pe_data[pe_offset + 21]]) as usize;

    // Section table starts at PE + 24 + opt_hdr_size.
    let sect_table = pe_offset + 24 + opt_hdr_size;
    if sect_table + n_sections * 40 > pe_data.len() {
        return None;
    }

    // Walk section table to find the maximum (PointerToRawData + SizeOfRawData).
    let mut end_of_sections: usize = 0;
    for i in 0..n_sections {
        let base = sect_table + i * 40;
        let raw_size = u32::from_le_bytes(pe_data[base + 16..base + 20].try_into().ok()?) as usize;
        let raw_offset =
            u32::from_le_bytes(pe_data[base + 20..base + 24].try_into().ok()?) as usize;
        if raw_offset > 0 {
            let end = raw_offset + raw_size;
            if end > end_of_sections {
                end_of_sections = end;
            }
        }
    }

    if end_of_sections == 0 || end_of_sections >= pe_data.len() {
        // No overlay.
        return None;
    }

    Some(end_of_sections)
}

// ---------------------------------------------------------------------------
// OverlayEditor
// ---------------------------------------------------------------------------

/// Reads, appends, and strips overlay data in a PE image buffer.
pub struct OverlayEditor {
    data: Vec<u8>,
}

impl OverlayEditor {
    /// Create an overlay editor from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if `data` does not contain a valid MZ header.
    pub fn new(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < 2 || data[0] != b'M' || data[1] != b'Z' {
            return Err("not a valid PE file (missing MZ magic)".to_string());
        }
        Ok(Self { data })
    }

    /// Create an editor from raw bytes without validation.
    #[must_use]
    pub const fn from_bytes_unchecked(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Detect the overlay in the current buffer.
    ///
    /// Returns `Some(Overlay)` if an overlay is present, `None` otherwise.
    #[must_use]
    pub fn detect(&self) -> Option<Overlay> {
        let offset = detect_overlay(&self.data)?;
        if offset >= self.data.len() {
            return None;
        }
        let overlay_data = self.data[offset..].to_vec();
        Some(Overlay::new(offset, overlay_data))
    }

    /// Return `true` if the current PE has an overlay.
    #[must_use]
    pub fn has_overlay(&self) -> bool {
        self.detect().is_some()
    }

    /// Return the size of the overlay in bytes (0 if none).
    #[must_use]
    pub fn overlay_size(&self) -> usize {
        self.detect().map_or(0, |o| o.data.len())
    }

    /// Append `data` to the end of the PE file as overlay bytes.
    ///
    /// If an overlay already exists, the new data is appended after it.
    pub fn append_overlay(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Strip the overlay from the PE image.
    ///
    /// Returns the stripped overlay bytes, or an empty [`Vec`] if there was
    /// no overlay.
    pub fn strip_overlay(&mut self) -> Vec<u8> {
        if let Some(overlay) = self.detect() {
            let stripped = self.data[overlay.offset..].to_vec();
            self.data.truncate(overlay.offset);
            stripped
        } else {
            vec![]
        }
    }

    /// Replace the existing overlay (or add one if none) with `new_data`.
    pub fn replace_overlay(&mut self, new_data: &[u8]) {
        self.strip_overlay();
        self.data.extend_from_slice(new_data);
    }

    /// Read the current overlay without modifying the buffer.
    #[must_use]
    pub fn read_overlay(&self) -> Option<Overlay> {
        self.detect()
    }

    /// Consume the editor and return the (possibly modified) bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Total size of the file in bytes, including any overlay.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Debug for OverlayEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OverlayEditor {{ size: {} }}", self.data.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid PE with `n_sections` stub sections.
    ///
    /// The PE is just large enough to have a DOS header, PE signature, COFF
    /// header, a trivial optional header (PE32), and `n_sections` section
    /// headers, each with a 16-byte raw data block.
    fn make_minimal_pe(n_sections: usize, overlay: Option<&[u8]>) -> Vec<u8> {
        let opt_hdr_size: usize = 96; // minimal PE32 optional header
        let section_raw_size: usize = 16;
        let pe_offset: usize = 0x40;
        let coff_size: usize = 20;
        let sect_table_offset = pe_offset + 4 + coff_size + opt_hdr_size;
        let raw_data_start = sect_table_offset + n_sections * 40;
        // Align raw_data_start to 0x200
        let raw_data_start = (raw_data_start + 0x1FF) & !0x1FF;
        let file_size = raw_data_start + n_sections * section_raw_size;

        let mut pe = vec![0u8; file_size];

        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew = pe_offset
        let pe_off_bytes = (pe_offset as u32).to_le_bytes();
        pe[60..64].copy_from_slice(&pe_off_bytes);

        // PE signature
        pe[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        let coff = pe_offset + 4;
        pe[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // Machine: x86
        pe[coff + 2..coff + 4].copy_from_slice(&(n_sections as u16).to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&(opt_hdr_size as u16).to_le_bytes());

        // Optional header (magic PE32 = 0x10B)
        let opt = coff + coff_size;
        pe[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());

        // Section headers
        for i in 0..n_sections {
            let base = sect_table_offset + i * 40;
            let raw_off = (raw_data_start + i * section_raw_size) as u32;
            let raw_sz = section_raw_size as u32;
            pe[base + 16..base + 20].copy_from_slice(&raw_sz.to_le_bytes());
            pe[base + 20..base + 24].copy_from_slice(&raw_off.to_le_bytes());
            // Virtual address
            let va = ((i + 1) as u32) * 0x1000;
            pe[base + 12..base + 16].copy_from_slice(&va.to_le_bytes());
            pe[base + 8..base + 12].copy_from_slice(&raw_sz.to_le_bytes());
        }

        // Append overlay if provided
        if let Some(ov) = overlay {
            pe.extend_from_slice(ov);
        }

        pe
    }

    // ── detect_overlay ────────────────────────────────────────────────────────

    #[test]
    fn test_detect_no_overlay() {
        let pe = make_minimal_pe(1, None);
        let result = detect_overlay(&pe);
        assert!(
            result.is_none(),
            "expected no overlay, got offset {result:?}"
        );
    }

    #[test]
    fn test_detect_with_overlay() {
        let overlay_data = b"OVERLAY_PAYLOAD_123";
        let pe = make_minimal_pe(1, Some(overlay_data));
        let offset = detect_overlay(&pe);
        assert!(offset.is_some(), "expected overlay to be detected");
        let off = offset.unwrap();
        assert_eq!(&pe[off..], overlay_data, "overlay content mismatch");
    }

    #[test]
    fn test_detect_too_short_returns_none() {
        let short = vec![0u8; 8];
        assert!(detect_overlay(&short).is_none());
    }

    #[test]
    fn test_detect_invalid_pe_sig_returns_none() {
        let mut pe = make_minimal_pe(1, None);
        // Corrupt PE signature.
        pe[0x40] = b'X';
        assert!(detect_overlay(&pe).is_none());
    }

    // ── OverlayEditor ─────────────────────────────────────────────────────────

    #[test]
    fn test_overlay_editor_new_invalid_magic() {
        let bad = vec![0u8; 64];
        assert!(OverlayEditor::new(bad).is_err());
    }

    #[test]
    fn test_has_overlay_false_for_clean_pe() {
        let pe = make_minimal_pe(2, None);
        let editor = OverlayEditor::new(pe).unwrap();
        assert!(!editor.has_overlay());
    }

    #[test]
    fn test_append_and_detect_overlay() {
        let pe = make_minimal_pe(1, None);
        let mut editor = OverlayEditor::new(pe).unwrap();
        editor.append_overlay(b"HELLO_OVERLAY");
        assert!(editor.has_overlay());
        let ov = editor.read_overlay().unwrap();
        assert_eq!(ov.data, b"HELLO_OVERLAY");
    }

    #[test]
    fn test_strip_overlay() {
        let pe = make_minimal_pe(1, Some(b"STRIP_ME"));
        let mut editor = OverlayEditor::new(pe).unwrap();
        assert!(editor.has_overlay());
        let stripped = editor.strip_overlay();
        assert_eq!(stripped, b"STRIP_ME");
        assert!(!editor.has_overlay());
    }

    #[test]
    fn test_strip_no_overlay_returns_empty() {
        let pe = make_minimal_pe(1, None);
        let mut editor = OverlayEditor::new(pe).unwrap();
        let stripped = editor.strip_overlay();
        assert!(stripped.is_empty());
    }

    #[test]
    fn test_replace_overlay() {
        let pe = make_minimal_pe(1, Some(b"OLD"));
        let mut editor = OverlayEditor::new(pe).unwrap();
        editor.replace_overlay(b"NEW_OVERLAY");
        let ov = editor.read_overlay().unwrap();
        assert_eq!(ov.data, b"NEW_OVERLAY");
    }

    // ── Overlay helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_overlay_head() {
        let ov = Overlay::new(0, b"ABCDEF".to_vec());
        assert_eq!(ov.head(3), b"ABC");
        assert_eq!(ov.head(100), b"ABCDEF");
    }

    #[test]
    fn test_overlay_fnv1a_hash_deterministic() {
        let ov = Overlay::new(0, b"test".to_vec());
        assert_eq!(ov.fnv1a_hash(), ov.fnv1a_hash());
    }

    #[test]
    fn test_overlay_display() {
        let ov = Overlay::new(0x400, vec![0u8; 16]);
        let s = ov.to_string();
        assert!(s.contains("0x400"), "unexpected: {s}");
        assert!(s.contains("16"), "unexpected: {s}");
    }
}
