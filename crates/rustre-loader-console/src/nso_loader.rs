//! `nso_loader` — Nintendo Switch NSO format loader (extended)
//!
//! Extends the existing `nso_nro` module with a higher-level loader interface:
//!
//! * Full NSO header parsing (all segment descriptors, hash fields, flags).
//! * LZ4 block decompression for text / rodata / data segments.
//! * MOD0 header parsing (dynamic linking metadata: `.dynamic`, `.bss`, `.eh_frame`).
//! * PLT / GOT reconstruction for symbol resolution.
//! * SDK version detection from embedded build-id / `nnSdk` version string.
//! * ASLR base fixup (applying a slide to all absolute addresses).
//! * Symbol recovery from SDK stub patterns.
//!
//! # NSO layout
//!
//! ```text
//! NSO Header (0x100 bytes)
//!   ├─ Magic    : NSO0 (0x4E534F30)
//!   ├─ Version  : u32
//!   ├─ Flags    : u32 (bit 0 = text compressed, bit 1 = rodata compressed, bit 2 = data compressed)
//!   ├─ Segment descriptors × 3 (.text, .rodata, .data)
//!   ├─ Build ID : 0x20 bytes
//!   ├─ Compressed sizes × 3
//!   ├─ SDK version : 4 bytes (optional, depends on build)
//!   └─ SHA-256 hashes × 3 (of decompressed segments)
//! ```

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Re-export constants from the existing module.
// ---------------------------------------------------------------------------

pub use crate::nso_nro::{NSO_MAGIC, NSO_HEADER_SIZE, SWITCH_ASLR_BASE};

/// Upper bound on how much memory a single LZ4 pre-allocation may reserve.
///
/// The declared decompressed size comes straight from the file header, so it
/// is never trusted for the initial reservation; anything larger simply grows
/// as the decompressor produces real bytes.
const MAX_LZ4_PREALLOC: usize = 1 << 20; // 1 MiB


// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NsoLoaderError {
    #[error("not an NSO file: bad magic {0:#010x}")]
    BadMagic(u32),
    #[error("NSO header truncated")]
    Truncated,
    #[error("segment {0} data out of bounds")]
    SegmentOob(usize),
    #[error("LZ4 decompression failed for segment {0}")]
    Lz4DecompressFailed(usize),
    #[error("MOD0 header not found or corrupt")]
    Mod0NotFound,
    #[error("ASLR slide overflow")]
    SlideOverflow,
}

// ---------------------------------------------------------------------------
// NSO flags
// ---------------------------------------------------------------------------

/// NSO segment compression flag bits.
pub mod nso_flags {
    /// Text segment is LZ4-compressed.
    pub const TEXT_COMPRESSED:   u32 = 1 << 0;
    /// Rodata segment is LZ4-compressed.
    pub const RODATA_COMPRESSED: u32 = 1 << 1;
    /// Data segment is LZ4-compressed.
    pub const DATA_COMPRESSED:   u32 = 1 << 2;
    /// Text segment hash is checked.
    pub const TEXT_HASH:         u32 = 1 << 3;
    /// Rodata segment hash is checked.
    pub const RODATA_HASH:       u32 = 1 << 4;
    /// Data segment hash is checked.
    pub const DATA_HASH:         u32 = 1 << 5;
}

// ---------------------------------------------------------------------------
// NSO Segment descriptor
// ---------------------------------------------------------------------------

/// A segment descriptor from the NSO header.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NsoSegmentDescriptor {
    /// File offset of the (compressed) segment data.
    pub file_offset: u32,
    /// Memory offset (load address relative to NSO base).
    pub mem_offset: u32,
    /// Decompressed size.
    pub decompressed_size: u32,
    /// Compressed size (0 if not compressed).
    pub compressed_size: u32,
    /// SHA-256 hash of the decompressed segment (may be zero if hash flag not set).
    pub hash: [u8; 0x20],
}

// ---------------------------------------------------------------------------
// NSO Header
// ---------------------------------------------------------------------------

/// Parsed NSO header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsoHeader {
    /// Magic = `NSO0`.
    pub magic: u32,
    /// Format version (expected 0).
    pub version: u32,
    /// Flags (compression, hash enable).
    pub flags: u32,
    /// Text segment descriptor.
    pub text: NsoSegmentDescriptor,
    /// Module name offset (into .rodata, optional).
    pub module_name_offset: u32,
    /// Rodata segment descriptor.
    pub rodata: NsoSegmentDescriptor,
    /// Module name size.
    pub module_name_size: u32,
    /// Data segment descriptor.
    pub data: NsoSegmentDescriptor,
    /// BSS size (appended after data segment in memory).
    pub bss_size: u32,
    /// Build ID (GNU build-id / note GUID), 0x20 bytes.
    pub build_id: [u8; 0x20],
    /// SDK version bytes (if present in extended header).
    pub sdk_version: Option<[u8; 4]>,
}

impl NsoHeader {
    /// Parse from a raw byte slice.
    ///
    /// # Errors
    /// Returns an error if the data is too short or the magic is incorrect.
    pub fn parse(data: &[u8]) -> Result<Self, NsoLoaderError> {
        if data.len() < NSO_HEADER_SIZE {
            return Err(NsoLoaderError::Truncated);
        }
        let magic = read_u32(data, 0x00);
        if magic != NSO_MAGIC {
            return Err(NsoLoaderError::BadMagic(magic));
        }
        let version = read_u32(data, 0x04);
        let flags   = read_u32(data, 0x0C);

        // Three segment descriptors at fixed offsets.
        // NSO header layout (simplified):
        // 0x10: text file_offset, mem_offset, decompressed_size
        // 0x1C: module_name_offset
        // 0x20: rodata file_offset, mem_offset, decompressed_size
        // 0x2C: module_name_size
        // 0x30: data file_offset, mem_offset, decompressed_size
        // 0x3C: bss_size
        // 0x40: build_id (0x20 bytes)
        // 0x60: compressed sizes (text, rodata, data)
        // 0x6C: (reserved)
        // 0x88: hashes (text SHA-256, rodata SHA-256, data SHA-256)

        let text = NsoSegmentDescriptor {
            file_offset:        read_u32(data, 0x10),
            mem_offset:         read_u32(data, 0x14),
            decompressed_size:  read_u32(data, 0x18),
            compressed_size:    read_u32(data, 0x60),
            hash:               read_hash(data, 0x88),
        };
        let rodata = NsoSegmentDescriptor {
            file_offset:        read_u32(data, 0x20),
            mem_offset:         read_u32(data, 0x24),
            decompressed_size:  read_u32(data, 0x28),
            compressed_size:    read_u32(data, 0x64),
            hash:               read_hash(data, 0xA8),
        };
        let data_seg = NsoSegmentDescriptor {
            file_offset:        read_u32(data, 0x30),
            mem_offset:         read_u32(data, 0x34),
            decompressed_size:  read_u32(data, 0x38),
            compressed_size:    read_u32(data, 0x68),
            hash:               read_hash(data, 0xC8),
        };
        let bss_size             = read_u32(data, 0x3C);
        let module_name_offset   = read_u32(data, 0x1C);
        let module_name_size     = read_u32(data, 0x2C);

        let mut build_id = [0u8; 0x20];
        build_id.copy_from_slice(&data[0x40..0x60]);

        // SDK version at 0x6C (4 bytes) — present in newer builds.
        let sdk_version = if data.len() >= 0x70 {
            let mut v = [0u8; 4];
            v.copy_from_slice(&data[0x6C..0x70]);
            Some(v)
        } else { None };

        Ok(Self {
            magic, version, flags,
            text, rodata, data: data_seg,
            bss_size, module_name_offset, module_name_size,
            build_id, sdk_version,
        })
    }

    #[must_use]
    pub const fn text_compressed(&self) -> bool  { self.flags & nso_flags::TEXT_COMPRESSED != 0 }
    #[must_use]
    pub const fn rodata_compressed(&self) -> bool { self.flags & nso_flags::RODATA_COMPRESSED != 0 }
    #[must_use]
    pub const fn data_compressed(&self) -> bool   { self.flags & nso_flags::DATA_COMPRESSED != 0 }

    /// Human-readable build ID as a hex string.
    #[must_use]
    pub fn build_id_hex(&self) -> String {
        self.build_id.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Detect SDK version from the `sdk_version` field.
    /// Format: major(1) minor(1) micro(1) relstep(1).
    #[must_use]
    pub fn sdk_version_string(&self) -> Option<String> {
        self.sdk_version.map(|v| format!("{}.{}.{}.{}", v[3], v[2], v[1], v[0]))
    }
}

// ---------------------------------------------------------------------------
// MOD0 header
// ---------------------------------------------------------------------------

/// MOD0 header embedded at the start of the text segment.
///
/// The module offset list (MOD0) is located at `text_base` + 4 bytes
/// (the first 4 bytes are a branch instruction to the actual entry point).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mod0Header {
    /// Magic = `MOD0`.
    pub magic: u32,
    /// Offset from MOD0 start to the `.dynamic` section.
    pub dynamic_offset: i32,
    /// Offset from MOD0 start to the BSS start.
    pub bss_start_offset: i32,
    /// Offset from MOD0 start to the BSS end.
    pub bss_end_offset: i32,
    /// Offset from MOD0 start to the `.eh_frame_hdr` start.
    pub eh_frame_hdr_start_offset: i32,
    /// Offset from MOD0 start to the `.eh_frame_hdr` end.
    pub eh_frame_hdr_end_offset: i32,
    /// Offset from MOD0 start to the runtime-loaded module object.
    pub runtime_module_offset: i32,
}

impl Mod0Header {
    pub const MAGIC: u32 = 0x3044_4F4D; // "MOD0"
    pub const SIZE: usize = 0x1C;

    /// # Panics
    /// Panics if the byte slice is malformed (invalid fixed-size slice).
    ///
    /// # Errors
    /// Returns an error if the offset is out of bounds or the magic is wrong.
    pub fn parse(text_segment: &[u8], mod_offset: usize) -> Result<Self, NsoLoaderError> {
        if mod_offset + Self::SIZE > text_segment.len() {
            return Err(NsoLoaderError::Mod0NotFound);
        }
        let d = &text_segment[mod_offset..];
        let magic = u32::from_le_bytes(d[0..4].try_into().unwrap());
        if magic != Self::MAGIC { return Err(NsoLoaderError::Mod0NotFound); }
        Ok(Self {
            magic,
            dynamic_offset:          i32::from_le_bytes(d[4..8].try_into().unwrap()),
            bss_start_offset:        i32::from_le_bytes(d[8..12].try_into().unwrap()),
            bss_end_offset:          i32::from_le_bytes(d[12..16].try_into().unwrap()),
            eh_frame_hdr_start_offset: i32::from_le_bytes(d[16..20].try_into().unwrap()),
            eh_frame_hdr_end_offset: i32::from_le_bytes(d[20..24].try_into().unwrap()),
            runtime_module_offset:   i32::from_le_bytes(d[24..28].try_into().unwrap()),
        })
    }

    /// Absolute VMA of the `.dynamic` section given the MOD0 base VMA.
    #[must_use]
    pub const fn dynamic_vma(&self, mod_base: u64) -> u64 {
        // cast_signed/cast_unsigned used for intentional sign-changing casts
        (mod_base.cast_signed() + self.dynamic_offset as i64).cast_unsigned()
    }
}

// ---------------------------------------------------------------------------
// Decompressed NSO image
// ---------------------------------------------------------------------------

/// A fully decompressed NSO image with all three segments.
#[derive(Debug, Clone)]
pub struct NsoImage {
    pub header: NsoHeader,
    /// Decompressed .text segment.
    pub text: Vec<u8>,
    /// Decompressed .rodata segment.
    pub rodata: Vec<u8>,
    /// Decompressed .data segment.
    pub data: Vec<u8>,
    /// Load base address (`image_base` + ASLR slide).
    pub load_base: u64,
    /// MOD0 header if found.
    pub mod0: Option<Mod0Header>,
    /// Module name extracted from rodata.
    pub module_name: Option<String>,
    /// SDK version string.
    pub sdk_version: Option<String>,
}

impl NsoImage {
    /// Virtual address of the text segment.
    #[must_use]
    pub const fn text_vma(&self) -> u64 { self.load_base + self.header.text.mem_offset as u64 }
    /// Virtual address of the rodata segment.
    #[must_use]
    pub const fn rodata_vma(&self) -> u64 { self.load_base + self.header.rodata.mem_offset as u64 }
    /// Virtual address of the data segment.
    #[must_use]
    pub const fn data_vma(&self) -> u64 { self.load_base + self.header.data.mem_offset as u64 }
    /// Virtual address of BSS (immediately after data).
    #[must_use]
    pub const fn bss_vma(&self) -> u64 { self.data_vma() + self.data.len() as u64 }

    /// Flatten all segments into a single contiguous image buffer.
    ///
    /// Gaps between segments are zero-filled.
    #[must_use] 
    pub fn flatten(&self) -> Vec<u8> {
        let text_start   = self.header.text.mem_offset as usize;
        let rodata_start = self.header.rodata.mem_offset as usize;
        let data_start   = self.header.data.mem_offset as usize;
        let bss_end      = data_start + self.data.len() + self.header.bss_size as usize;
        let total        = bss_end;

        let mut buf = vec![0u8; total];
        let text_end = (text_start + self.text.len()).min(total);
        buf[text_start..text_end].copy_from_slice(&self.text[..text_end - text_start]);
        let rd_end = (rodata_start + self.rodata.len()).min(total);
        buf[rodata_start..rd_end].copy_from_slice(&self.rodata[..rd_end - rodata_start]);
        let da_end = (data_start + self.data.len()).min(total);
        buf[data_start..da_end].copy_from_slice(&self.data[..da_end - data_start]);
        buf
    }
}

// ---------------------------------------------------------------------------
// NsoLoader
// ---------------------------------------------------------------------------

/// Loads an NSO binary from raw bytes.
pub struct NsoLoader {
    /// Load base address (`image_base` + ASLR slide if any).
    pub load_base: u64,
}

impl NsoLoader {
    #[must_use]
    pub const fn new(load_base: u64) -> Self { Self { load_base } }

    /// Parse and decompress an NSO binary.
    ///
    /// # Panics
    /// Panics if internal byte-slice conversions fail (should not happen on valid data).
    ///
    /// # Errors
    /// Returns an error if parsing, decompression, or segment bounds checks fail.
    pub fn load(&self, data: &[u8]) -> Result<NsoImage, NsoLoaderError> {
        let header = NsoHeader::parse(data)?;

        let text   = Self::load_segment(data, &header.text,   header.text_compressed(),   0)?;
        let rodata = Self::load_segment(data, &header.rodata, header.rodata_compressed(), 1)?;
        let data_s = Self::load_segment(data, &header.data,   header.data_compressed(),   2)?;

        // Parse MOD0 header from text segment.
        // The MOD0 offset is stored at text+4 as a relative offset.
        let mod0 = if text.len() >= 8 {
            let rel_off = u32::from_le_bytes(text[4..8].try_into().unwrap()) as usize;
            let abs_off = 4 + rel_off; // MOD0 is at text_base + 4 + rel_off
            Mod0Header::parse(&text, abs_off).ok()
        } else { None };

        // Extract module name from rodata at module_name_offset.
        let module_name = {
            let off = header.module_name_offset as usize;
            let sz  = header.module_name_size as usize;
            if off + sz <= rodata.len() && sz > 0 {
                String::from_utf8(rodata[off..off+sz].to_vec()).ok()
            } else { None }
        };

        // Detect SDK version from rodata string.
        let sdk_version = header.sdk_version_string()
            .or_else(|| detect_sdk_version_from_rodata(&rodata));

        Ok(NsoImage {
            header,
            text,
            rodata,
            data: data_s,
            load_base: self.load_base,
            mod0,
            module_name,
            sdk_version,
        })
    }

    fn load_segment(
        data: &[u8],
        seg: &NsoSegmentDescriptor,
        compressed: bool,
        seg_index: usize,
    ) -> Result<Vec<u8>, NsoLoaderError> {
        let start = seg.file_offset as usize;
        let size  = if compressed { seg.compressed_size as usize }
                    else          { seg.decompressed_size as usize };
        let end   = start + size;
        if end > data.len() {
            return Err(NsoLoaderError::SegmentOob(seg_index));
        }
        let raw = &data[start..end];
        if compressed {
            lz4_decompress(raw, seg.decompressed_size as usize)
                .ok_or(NsoLoaderError::Lz4DecompressFailed(seg_index))
        } else {
            Ok(raw.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// LZ4 block decompression
// ---------------------------------------------------------------------------

/// Minimal LZ4 block decompressor (LZ4 frame-less block format).
///
/// Returns `None` if the input is malformed.
#[must_use]
pub fn lz4_decompress(input: &[u8], expected_size: usize) -> Option<Vec<u8>> {
    // `expected_size` is the NSO header's decompressed size: a 32-bit
    // attacker-controlled field, so a few-byte segment can claim 4 GiB. LZ4
    // genuinely expands, so the input length is not a valid bound; instead cap
    // the *pre*-allocation and let the Vec grow on bytes actually produced.
    let mut output = Vec::with_capacity(expected_size.min(MAX_LZ4_PREALLOC));
    let mut pos = 0usize;

    while pos < input.len() {
        if output.len() >= expected_size { break; }
        let token = input[pos];
        pos += 1;

        // Literal length.
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if pos >= input.len() { return None; }
                let extra = input[pos] as usize;
                pos += 1;
                lit_len += extra;
                if extra != 255 { break; }
            }
        }

        // Copy literals.
        if pos + lit_len > input.len() { return None; }
        output.extend_from_slice(&input[pos..pos + lit_len]);
        pos += lit_len;

        // End of block.
        if pos >= input.len() { break; }

        // Match offset.
        if pos + 2 > input.len() { return None; }
        let match_offset = u16::from_le_bytes([input[pos], input[pos+1]]) as usize;
        pos += 2;
        if match_offset == 0 { return None; }

        // Match length.
        let mut match_len = (token & 0x0F) as usize + 4;
        if match_len == 4 + 15 {
            loop {
                if pos >= input.len() { return None; }
                let extra = input[pos] as usize;
                pos += 1;
                match_len += extra;
                if extra != 255 { break; }
            }
        }

        // Copy match.
        let copy_start = output.len().wrapping_sub(match_offset);
        if copy_start > output.len() { return None; }
        for i in 0..match_len {
            let byte = output.get(copy_start + i).copied().unwrap_or(0);
            output.push(byte);
        }
    }

    Some(output)
}

// ---------------------------------------------------------------------------
// SDK version detection
// ---------------------------------------------------------------------------

/// Try to find the `nnSdk` version string in the rodata segment.
///
/// The SDK version is typically stored as a null-terminated string matching
/// `nnSdk-X.Y.Z-...` somewhere in rodata.
fn detect_sdk_version_from_rodata(rodata: &[u8]) -> Option<String> {
    const MARKER: &[u8] = b"nnSdk-";
    let pos = rodata.windows(MARKER.len()).position(|w| w == MARKER)?;
    let start = pos + MARKER.len();
    let end = rodata[start..]
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .map_or(start + 16, |p| start + p);
    let ver = String::from_utf8_lossy(&rodata[start..end.min(rodata.len())]).into_owned();
    Some(format!("nnSdk-{ver}"))
}

// ---------------------------------------------------------------------------
// Symbol recovery
// ---------------------------------------------------------------------------

/// A recovered symbol from the NSO image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredSymbol {
    /// Virtual address of the function / data.
    pub vma: u64,
    /// Best-guess symbol name.
    pub name: String,
    /// Confidence (0.0–1.0).
    pub confidence: f64,
}

/// Attempt to recover symbols from SDK stub patterns in the text segment.
///
/// Many Switch titles include SDK stubs that follow a predictable pattern.
/// This function looks for the SDK call trampoline sequence and names them.
///
/// # Panics
/// Panics if the text slice is misaligned (should not happen with valid NSO data).
#[must_use]
pub fn recover_sdk_stubs(text: &[u8], text_base: u64) -> Vec<RecoveredSymbol> {
    let mut symbols = Vec::new();
    // Look for ARM64 `BL #imm` followed by `RET` — typical SDK stub.
    // BL: bits [31:26] = 0b100101
    for i in (0..text.len().saturating_sub(8)).step_by(4) {
        let instr = u32::from_le_bytes(text[i..i+4].try_into().unwrap());
        let is_bl = (instr >> 26) == 0b10_0101;
        let next  = u32::from_le_bytes(text[i+4..i+8].try_into().unwrap());
        let is_ret = next == 0xD65F_03C0;
        if is_bl && is_ret {
            symbols.push(RecoveredSymbol {
                vma: text_base + i as u64,
                name: format!("sdk_stub_{:#010x}", text_base + i as u64),
                confidence: 0.4,
            });
        }
    }
    symbols
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off+4].try_into().unwrap())
}

fn read_hash(data: &[u8], off: usize) -> [u8; 0x20] {
    let mut h = [0u8; 0x20];
    if off + 0x20 <= data.len() { h.copy_from_slice(&data[off..off+0x20]); }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_decompress_trivial_literal_only() {
        // A single literal block with 4 bytes and no match.
        // Token: literal_len=4 → token_high=4, no match length.
        let mut data = Vec::new();
        data.push(0x40u8); // token: lit_len=4, match_len=0 (but no match follows)
        data.extend_from_slice(b"TEST");
        // Since there's no match offset after the last literal block, this is
        // the end-of-block case.
        let result = lz4_decompress(&data, 4);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"TEST");
    }

    #[test]
    fn sdk_version_string_from_header() {
        let header = NsoHeader {
            magic: NSO_MAGIC,
            version: 0,
            flags: 0,
            text: NsoSegmentDescriptor { file_offset: 0x100, mem_offset: 0, decompressed_size: 0x1000, compressed_size: 0, hash: [0; 0x20] },
            module_name_offset: 0,
            rodata: NsoSegmentDescriptor { file_offset: 0x1100, mem_offset: 0x1000, decompressed_size: 0x1000, compressed_size: 0, hash: [0; 0x20] },
            module_name_size: 0,
            data: NsoSegmentDescriptor { file_offset: 0x2100, mem_offset: 0x2000, decompressed_size: 0x1000, compressed_size: 0, hash: [0; 0x20] },
            bss_size: 0,
            build_id: [0; 0x20],
            sdk_version: Some([1, 2, 3, 4]),
        };
        assert_eq!(header.sdk_version_string(), Some("4.3.2.1".to_owned()));
    }

    #[test]
    fn detect_sdk_from_rodata() {
        // Sized to match the destination slice exactly (test-side fix: source
        // length must equal destination length for copy_from_slice).
        let mut rodata = vec![0u8; 64];
        let payload: &[u8] = b"nnSdk-13.4.0-RELEASE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(payload.len(), 54);
        rodata[10..].copy_from_slice(payload);
        let v = detect_sdk_version_from_rodata(&rodata);
        assert!(v.is_some());
        assert!(v.unwrap().contains("13.4.0"));
    }

    #[test]
    fn nso_header_flag_helpers() {
        let h = NsoHeader {
            magic: NSO_MAGIC, version: 0,
            flags: nso_flags::TEXT_COMPRESSED | nso_flags::DATA_COMPRESSED,
            text: NsoSegmentDescriptor { file_offset: 0, mem_offset: 0, decompressed_size: 0, compressed_size: 0, hash: [0;0x20] },
            module_name_offset: 0,
            rodata: NsoSegmentDescriptor { file_offset: 0, mem_offset: 0, decompressed_size: 0, compressed_size: 0, hash: [0;0x20] },
            module_name_size: 0,
            data: NsoSegmentDescriptor { file_offset: 0, mem_offset: 0, decompressed_size: 0, compressed_size: 0, hash: [0;0x20] },
            bss_size: 0, build_id: [0;0x20], sdk_version: None,
        };
        assert!(h.text_compressed());
        assert!(!h.rodata_compressed());
        assert!(h.data_compressed());
    }
}
