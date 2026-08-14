//! Nintendo Switch NSO / NRO loader.
//!
//! Implements header parsing and segment decompression stubs for:
//! * **NSO** (Nintendo Switch Object) — used by main executables (magic `NSO0` / `0x4E534F30`).
//! * **NRO** (Nintendo Relocatable Object) — homebrews built with devkitPro (magic `NRO0` / `0x304F524E`).
//! * **NRR** (Nintendo Relocatable Record) — RO module record tables.
//!
//! Segment compression uses LZ4; decompressed segments are laid out in a flat virtual
//! address space starting at 0x7100000000 (the Switch ASLR base used by most loaders).

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Upper bound on how much memory a single LZ4 pre-allocation may reserve.
///
/// The declared decompressed size comes straight from the file header, so it
/// is never trusted for the initial reservation; anything larger simply grows
/// as the decompressor produces real bytes.
const MAX_LZ4_PREALLOC: usize = 1 << 20; // 1 MiB


// ─── constants ────────────────────────────────────────────────────────────────

/// NSO0 magic (`NSO0` in ASCII little-endian).
pub const NSO_MAGIC: u32 = 0x4E53_4F30;
/// NRO0 magic (`NRO0` in ASCII little-endian).
pub const NRO_MAGIC: u32 = 0x304F_524E;
/// NRR0 magic (`NRR0` in ASCII little-endian).
pub const NRR_MAGIC: u32 = 0x3052_524E;

/// Default virtual base for the Switch user-land address space.
pub const SWITCH_ASLR_BASE: u64 = 0x7100_0000_0000;

/// NSO header size in bytes.
pub const NSO_HEADER_SIZE: usize = 0x100;
/// NRO header size in bytes (first 0x70 bytes are fixed, remainder is optional).
pub const NRO_HEADER_SIZE: usize = 0x70;

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors produced by the NSO/NRO loader.
#[derive(Debug, Error)]
pub enum NsoNroError {
    /// Bad or missing magic value in the file header.
    #[error("invalid magic: expected {expected:#010x}, got {got:#010x}")]
    BadMagic { expected: u32, got: u32 },
    /// The file is shorter than the minimum required header size.
    #[error("file too short: need {need} bytes, have {have}")]
    FileTooShort { need: usize, have: usize },
    /// A compressed segment exceeds the bounds of the file.
    #[error("segment {idx} out of bounds (offset {offset:#x}, size {size:#x}, file {file_len:#x})")]
    SegmentOob {
        idx: usize,
        offset: usize,
        size: usize,
        file_len: usize,
    },
    /// LZ4 decompression produced fewer bytes than declared.
    #[error("LZ4 decompression underflow: expected {expected} bytes, got {got}")]
    Lz4Underflow { expected: usize, got: usize },
    /// NRR signature verification failed.
    #[error("NRR signature verification failed")]
    NrrSigFailure,
    /// Generic parse error.
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── NsoFlags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags field in the NSO0 header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct NsoFlags: u32 {
        /// .text segment is LZ4-compressed.
        const TEXT_COMPRESSED  = 0b0000_0001;
        /// .rodata segment is LZ4-compressed.
        const RODATA_COMPRESSED = 0b0000_0010;
        /// .data segment is LZ4-compressed.
        const DATA_COMPRESSED  = 0b0000_0100;
        /// SHA-256 hash of .text present.
        const TEXT_HASH        = 0b0000_1000;
        /// SHA-256 hash of .rodata present.
        const RODATA_HASH      = 0b0001_0000;
        /// SHA-256 hash of .data present.
        const DATA_HASH        = 0b0010_0000;
    }
}

impl Default for NsoFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ─── NsoSegmentHeader ─────────────────────────────────────────────────────────

/// One of the three segment descriptors embedded in the NSO0 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsoSegmentHeader {
    /// File offset to the (possibly compressed) segment data.
    pub file_offset: u32,
    /// Virtual memory offset of the segment inside the process image.
    pub mem_offset: u32,
    /// Decompressed size of the segment.
    pub mem_size: u32,
    /// For .text and .rodata: 0.  For .data: size of the BSS region appended.
    pub align_or_total_size: u32,
}

impl NsoSegmentHeader {
    /// Parse from a 16-byte slice.
    ///
    /// # Errors
    /// Returns an error if the slice is shorter than 16 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, NsoNroError> {
        if data.len() < 16 {
            return Err(NsoNroError::FileTooShort {
                need: 16,
                have: data.len(),
            });
        }
        Ok(Self {
            file_offset: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            mem_offset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            mem_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            align_or_total_size: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

impl fmt::Display for NsoSegmentHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NsoSeg file={:#010x} mem={:#010x} size={:#010x}",
            self.file_offset, self.mem_offset, self.mem_size
        )
    }
}

// ─── NsoHeader ────────────────────────────────────────────────────────────────

/// Parsed NSO0 header (256 bytes total).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsoHeader {
    /// Magic (must equal [`NSO_MAGIC`]).
    pub magic: u32,
    /// Version (always 0 for retail).
    pub version: u32,
    /// Reserved field.
    pub reserved0: u32,
    /// Segment flags.
    pub flags: NsoFlags,
    /// .text segment descriptor.
    pub text_segment: NsoSegmentHeader,
    /// Module name offset (relative to .text mem base).
    pub module_name_offset: u32,
    /// .rodata segment descriptor.
    pub rodata_segment: NsoSegmentHeader,
    /// Module name size.
    pub module_name_size: u32,
    /// .data segment descriptor.
    pub data_segment: NsoSegmentHeader,
    /// BSS size (appended after .data).
    pub bss_size: u32,
    /// Build ID (20 bytes, rest padded).
    pub build_id: [u8; 32],
    /// Compressed sizes for text / rodata / data.
    pub compressed_sizes: [u32; 3],
    /// SHA-256 hashes for text / rodata / data (32 bytes each = 96 bytes).
    pub hashes: [[u8; 32]; 3],
}

impl NsoHeader {
    /// Parse a 256-byte NSO0 header from `data`.
    ///
    /// # Errors
    /// Returns [`NsoNroError::FileTooShort`] or [`NsoNroError::BadMagic`].
    pub fn parse(data: &[u8]) -> Result<Self, NsoNroError> {
        if data.len() < NSO_HEADER_SIZE {
            return Err(NsoNroError::FileTooShort {
                need: NSO_HEADER_SIZE,
                have: data.len(),
            });
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != NSO_MAGIC {
            return Err(NsoNroError::BadMagic {
                expected: NSO_MAGIC,
                got: magic,
            });
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let reserved = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let raw_flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let flags = NsoFlags::from_bits_truncate(raw_flags);

        let text_segment = NsoSegmentHeader::parse(&data[0x10..0x20])?;
        let module_name_off = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);
        let rodata_segment = NsoSegmentHeader::parse(&data[0x24..0x34])?;
        let module_name_sz = u32::from_le_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]);
        let data_segment = NsoSegmentHeader::parse(&data[0x38..0x48])?;
        let bss_size = u32::from_le_bytes([data[0x48], data[0x49], data[0x4A], data[0x4B]]);

        let mut build_id = [0u8; 32];
        build_id.copy_from_slice(&data[0x4C..0x6C]);

        let compressed_sizes = [
            u32::from_le_bytes([data[0x60], data[0x61], data[0x62], data[0x63]]),
            u32::from_le_bytes([data[0x64], data[0x65], data[0x66], data[0x67]]),
            u32::from_le_bytes([data[0x68], data[0x69], data[0x6A], data[0x6B]]),
        ];

        let mut hashes = [[0u8; 32]; 3];
        hashes[0].copy_from_slice(&data[0x80..0xA0]);
        hashes[1].copy_from_slice(&data[0xA0..0xC0]);
        hashes[2].copy_from_slice(&data[0xC0..0xE0]);

        Ok(Self {
            magic,
            version,
            reserved0: reserved,
            flags,
            text_segment,
            module_name_offset: module_name_off,
            rodata_segment,
            module_name_size: module_name_sz,
            data_segment,
            bss_size,
            build_id,
            compressed_sizes,
            hashes,
        })
    }

    /// Returns `true` if the .text segment is LZ4-compressed.
    #[must_use]
    pub const fn text_compressed(&self) -> bool {
        self.flags.contains(NsoFlags::TEXT_COMPRESSED)
    }
    /// Returns `true` if the .rodata segment is LZ4-compressed.
    #[must_use]
    pub const fn rodata_compressed(&self) -> bool {
        self.flags.contains(NsoFlags::RODATA_COMPRESSED)
    }
    /// Returns `true` if the .data segment is LZ4-compressed.
    #[must_use]
    pub const fn data_compressed(&self) -> bool {
        self.flags.contains(NsoFlags::DATA_COMPRESSED)
    }

    /// Compressed file size of .text (equals `mem_size` when not compressed).
    #[must_use]
    pub const fn text_file_size(&self) -> u32 {
        if self.text_compressed() {
            self.compressed_sizes[0]
        } else {
            self.text_segment.mem_size
        }
    }
    /// Compressed file size of .rodata.
    #[must_use]
    pub const fn rodata_file_size(&self) -> u32 {
        if self.rodata_compressed() {
            self.compressed_sizes[1]
        } else {
            self.rodata_segment.mem_size
        }
    }
    /// Compressed file size of .data.
    #[must_use]
    pub const fn data_file_size(&self) -> u32 {
        if self.data_compressed() {
            self.compressed_sizes[2]
        } else {
            self.data_segment.mem_size
        }
    }

    /// Build ID as a lowercase hex string (first 20 bytes, as in `build.id`).
    #[must_use]
    pub fn build_id_hex(&self) -> String {
        self.build_id[..20].iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

impl fmt::Display for NsoHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSO0 build_id={} flags={:?} text={} rodata={} data={} bss={}",
            self.build_id_hex(),
            self.flags,
            self.text_segment.mem_size,
            self.rodata_segment.mem_size,
            self.data_segment.mem_size,
            self.bss_size,
        )
    }
}

// ─── lz4_decompress ──────────────────────────────────────────────────────────

/// LZ4 block decompressor, implemented here rather than pulled from
/// `lz4_flex`.
///
/// The doc comment used to call this a "stub"; it is not one — the body below
/// decodes real LZ4 tokens, literals and back-references. The label is removed
/// because a working decoder described as a stub invites callers to distrust
/// correct output, exactly as a stub described as working invites the opposite.
///
/// The NSO format uses LZ4 *block* format (no frame headers).
///
/// # Errors
/// Returns [`NsoNroError::Lz4Underflow`] if the output is smaller than `expected`.
pub fn lz4_decompress(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, NsoNroError> {
    // See `nso_loader::lz4_decompress`: bound the pre-allocation, not the
    // output, since LZ4 legitimately expands beyond the input length.
    let mut output = Vec::with_capacity(expected_size.min(MAX_LZ4_PREALLOC));
    let mut pos = 0;

    while pos < compressed.len() {
        let token = compressed[pos];
        pos += 1;

        // Literal length
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if pos >= compressed.len() {
                    break;
                }
                let extra = compressed[pos] as usize;
                pos += 1;
                lit_len = lit_len.saturating_add(extra);
                // Guard: lit_len can never exceed the remaining output budget.
                if lit_len > expected_size {
                    lit_len = expected_size;
                    break;
                }
                if extra != 255 {
                    break;
                }
            }
        }

        // Copy literals
        if pos + lit_len > compressed.len() {
            break;
        }
        output.extend_from_slice(&compressed[pos..pos + lit_len]);
        pos += lit_len;

        if pos >= compressed.len() {
            break;
        } // last sequence has no match

        // Match offset (little-endian u16)
        if pos + 2 > compressed.len() {
            break;
        }
        let offset = u16::from_le_bytes([compressed[pos], compressed[pos + 1]]) as usize;
        pos += 2;

        // Match length
        let mut match_len = (token & 0x0F) as usize + 4;
        if match_len - 4 == 15 {
            loop {
                if pos >= compressed.len() {
                    break;
                }
                let extra = compressed[pos] as usize;
                pos += 1;
                match_len = match_len.saturating_add(extra);
                // Guard: match_len can never exceed the remaining output budget.
                if match_len > expected_size {
                    match_len = expected_size;
                    break;
                }
                if extra != 255 {
                    break;
                }
            }
        }

        if offset == 0 || output.len() < offset {
            break;
        }
        let match_start = output.len() - offset;
        for i in 0..match_len {
            let byte = output[match_start + (i % offset)];
            output.push(byte);
        }
    }

    if output.len() < expected_size {
        return Err(NsoNroError::Lz4Underflow {
            expected: expected_size,
            got: output.len(),
        });
    }
    output.truncate(expected_size);
    Ok(output)
}

// ─── NsoLoader ────────────────────────────────────────────────────────────────

/// High-level NSO loader: parses the header, decompresses segments, and
/// returns a flat image laid out at the Switch ASLR base.
#[derive(Debug, Default)]
pub struct NsoLoader;

/// Result of loading an NSO file.
#[derive(Debug, Clone)]
pub struct NsoLoadResult {
    /// Parsed header.
    pub header: NsoHeader,
    /// Decompressed .text bytes.
    pub text: Vec<u8>,
    /// Decompressed .rodata bytes.
    pub rodata: Vec<u8>,
    /// Decompressed .data bytes (not including BSS).
    pub data: Vec<u8>,
    /// Virtual address of .text.
    pub text_va: u64,
    /// Virtual address of .rodata.
    pub rodata_va: u64,
    /// Virtual address of .data.
    pub data_va: u64,
    /// Entry point virtual address (always == `text_va` for NSO).
    pub entry_point: u64,
}

impl NsoLoader {
    /// Load an NSO file from `raw_data`.
    ///
    /// # Errors
    /// Forwards [`NsoNroError`] variants on parse or decompression failure.
    pub fn load(raw_data: &[u8]) -> Result<NsoLoadResult, NsoNroError> {
        let header = NsoHeader::parse(raw_data)?;
        let base = SWITCH_ASLR_BASE;

        let text = Self::extract_segment(
            raw_data,
            &header.text_segment,
            header.text_file_size() as usize,
            header.text_compressed(),
            0,
        )?;
        let rodata = Self::extract_segment(
            raw_data,
            &header.rodata_segment,
            header.rodata_file_size() as usize,
            header.rodata_compressed(),
            1,
        )?;
        let data = Self::extract_segment(
            raw_data,
            &header.data_segment,
            header.data_file_size() as usize,
            header.data_compressed(),
            2,
        )?;

        let text_va = base + u64::from(header.text_segment.mem_offset);
        let rodata_va = base + u64::from(header.rodata_segment.mem_offset);
        let data_va = base + u64::from(header.data_segment.mem_offset);

        Ok(NsoLoadResult {
            header,
            text,
            rodata,
            data,
            text_va,
            rodata_va,
            data_va,
            entry_point: text_va,
        })
    }

    fn extract_segment(
        data: &[u8],
        seg: &NsoSegmentHeader,
        file_size: usize,
        compressed: bool,
        idx: usize,
    ) -> Result<Vec<u8>, NsoNroError> {
        let off = seg.file_offset as usize;
        let end = off.saturating_add(file_size);
        if end > data.len() {
            return Err(NsoNroError::SegmentOob {
                idx,
                offset: off,
                size: file_size,
                file_len: data.len(),
            });
        }
        let raw = &data[off..end];
        if compressed {
            lz4_decompress(raw, seg.mem_size as usize)
        } else {
            Ok(raw.to_vec())
        }
    }
}

// ─── NroHeader ────────────────────────────────────────────────────────────────

/// Parsed NRO0 header (0x70 bytes of fixed fields).
///
/// The NRO format is used by homebrew applications and libraries built with
/// devkitPro.  Segments are always uncompressed and flat in the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NroHeader {
    /// Jump instruction at offset 0 (ARM64 `B` to module start).
    pub start_code: u32,
    /// Module offset (relative to file start).
    pub mod_offset: u32,
    /// Magic (must equal [`NRO_MAGIC`]).
    pub magic: u32,
    /// Version (0).
    pub version: u32,
    /// Total size of the NRO file.
    pub total_size: u32,
    /// Flags (currently unused).
    pub flags: u32,
    /// .text virtual offset and size.
    pub text_va: u32,
    pub text_size: u32,
    /// .rodata virtual offset and size.
    pub rodata_va: u32,
    pub rodata_size: u32,
    /// .data virtual offset and size (BSS follows immediately).
    pub data_va: u32,
    pub data_size: u32,
    /// BSS size.
    pub bss_size: u32,
    /// Build ID (32 bytes).
    pub build_id: [u8; 32],
}

impl NroHeader {
    /// Parse from the first 0x70 bytes of `data`.
    ///
    /// # Errors
    /// Returns [`NsoNroError`] if `data` is too short or the magic is invalid.
    pub fn parse(data: &[u8]) -> Result<Self, NsoNroError> {
        if data.len() < NRO_HEADER_SIZE {
            return Err(NsoNroError::FileTooShort {
                need: NRO_HEADER_SIZE,
                have: data.len(),
            });
        }
        let magic = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
        if magic != NRO_MAGIC {
            return Err(NsoNroError::BadMagic {
                expected: NRO_MAGIC,
                got: magic,
            });
        }

        let mut build_id = [0u8; 32];
        build_id.copy_from_slice(&data[0x40..0x60]);

        Ok(Self {
            start_code: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            mod_offset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            magic,
            version: u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]),
            total_size: u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]),
            flags: u32::from_le_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]),
            text_va: u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]),
            text_size: u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]),
            rodata_va: u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]),
            rodata_size: u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]),
            data_va: u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]),
            data_size: u32::from_le_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]),
            bss_size: u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]),
            build_id,
        })
    }

    /// Build ID as a lowercase hex string (first 20 bytes).
    #[must_use]
    pub fn build_id_hex(&self) -> String {
        self.build_id[..20].iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// Total image size including BSS.
    #[must_use]
    pub const fn image_size(&self) -> u32 {
        self.data_va + self.data_size + self.bss_size
    }
}

impl fmt::Display for NroHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NRO0 build_id={} total={:#x} text={:#x}+{:#x} rodata={:#x}+{:#x} data={:#x}+{:#x} bss={:#x}",
            self.build_id_hex(),
            self.total_size,
            self.text_va,
            self.text_size,
            self.rodata_va,
            self.rodata_size,
            self.data_va,
            self.data_size,
            self.bss_size,
        )
    }
}

// ─── HomeBrewLoader ABI (NRO + NRR) ──────────────────────────────────────────

/// Parsed NRR0 header used by homebrew's RO service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrrHeader {
    /// Magic (must equal [`NRR_MAGIC`]).
    pub magic: u32,
    /// Certificate size.
    pub cert_size: u32,
    /// NRR header signature (RSA-2048 PSS, 256 bytes).
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 256],
    /// Hash of the binary (SHA-256).
    pub hash: [u8; 32],
}

impl NrrHeader {
    /// Minimum NRR header size.
    pub const MIN_SIZE: usize = 0x108;

    /// Parse from `data`.
    ///
    /// # Errors
    /// Returns [`NsoNroError`] on truncation or bad magic.
    pub fn parse(data: &[u8]) -> Result<Self, NsoNroError> {
        if data.len() < Self::MIN_SIZE {
            return Err(NsoNroError::FileTooShort {
                need: Self::MIN_SIZE,
                have: data.len(),
            });
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != NRR_MAGIC {
            return Err(NsoNroError::BadMagic {
                expected: NRR_MAGIC,
                got: magic,
            });
        }
        let cert_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let mut signature = [0u8; 256];
        let sig_end = 8 + 256.min(data.len() - 8);
        signature[..sig_end - 8].copy_from_slice(&data[8..sig_end]);

        let mut hash = [0u8; 32];
        let hash_off = 0x108;
        if data.len() >= hash_off + 32 {
            hash.copy_from_slice(&data[hash_off..hash_off + 32]);
        }

        Ok(Self {
            magic,
            cert_size,
            signature,
            hash,
        })
    }

    /// Verify the NRO's RSA-2048 PSS signature.
    ///
    /// Returns `None`: this build carries no RSA-PSS implementation and no
    /// trusted key material, so the signature can be neither confirmed nor
    /// refuted. It previously returned `true` unconditionally, which reads as
    /// "signature valid" — the one answer a verifier must never give without
    /// checking. `None` forces the caller to handle "unknown" explicitly.
    ///
    /// To make this return `Some(bool)`, verify `Self::hash` against the
    /// signature block with RSA-2048 PSS and a caller-supplied public key.
    #[must_use]
    pub const fn verify_signature(&self) -> Option<bool> {
        None
    }
}

// ─── NroLoader ────────────────────────────────────────────────────────────────

/// High-level NRO loader.
#[derive(Debug, Default)]
pub struct NroLoader;

/// Result of loading an NRO file.
#[derive(Debug, Clone)]
pub struct NroLoadResult {
    /// Parsed NRO header.
    pub header: NroHeader,
    /// .text bytes (direct copy from file at `text_va` offset).
    pub text: Vec<u8>,
    /// .rodata bytes.
    pub rodata: Vec<u8>,
    /// .data bytes.
    pub data: Vec<u8>,
    /// Virtual base address where the NRO will be loaded.
    pub load_base: u64,
}

impl NroLoader {
    /// Load an NRO from `raw_data`, placing it at `load_base`.
    ///
    /// # Errors
    /// Forwards [`NsoNroError`] on parse failure.
    pub fn load(raw_data: &[u8], load_base: u64) -> Result<NroLoadResult, NsoNroError> {
        let header = NroHeader::parse(raw_data)?;

        let text = extract_slice(
            raw_data,
            header.text_va as usize,
            header.text_size as usize,
            0,
        )?;
        let rodata = extract_slice(
            raw_data,
            header.rodata_va as usize,
            header.rodata_size as usize,
            1,
        )?;
        let data = extract_slice(
            raw_data,
            header.data_va as usize,
            header.data_size as usize,
            2,
        )?;

        Ok(NroLoadResult {
            header,
            text,
            rodata,
            data,
            load_base,
        })
    }
}

fn extract_slice(
    data: &[u8],
    offset: usize,
    size: usize,
    idx: usize,
) -> Result<Vec<u8>, NsoNroError> {
    let end = offset.saturating_add(size);
    if end > data.len() {
        return Err(NsoNroError::SegmentOob {
            idx,
            offset,
            size,
            file_len: data.len(),
        });
    }
    Ok(data[offset..end].to_vec())
}

// ─── is_nso / is_nro helpers ─────────────────────────────────────────────────

/// Returns `true` if `data` starts with the NSO0 magic.
#[must_use]
pub fn is_nso(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == NSO_MAGIC
}

/// Returns `true` if `data` starts with the NRO0 magic (at offset 0x10).
#[must_use]
pub fn is_nro(data: &[u8]) -> bool {
    data.len() >= 0x14
        && u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]) == NRO_MAGIC
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_signature_reports_unknown_not_valid() {
        // A verifier with no key material and no RSA-PSS implementation must
        // not answer "valid". `None` is the only honest result, and the type
        // makes it impossible for a caller to read it as success.
        // A non-zero signature block makes the point sharper: even with
        // something that looks like a signature present, the answer is still
        // "unknown", because nothing here can check it.
        let hdr = NrrHeader {
            magic: u32::from_le_bytes(*b"NRR0"),
            cert_size: 0,
            signature: [0xAB; 256],
            hash: [0u8; 32],
        };
        assert_eq!(hdr.verify_signature(), None);
    }

    fn minimal_nso_header() -> Vec<u8> {
        let mut h = vec![0u8; NSO_HEADER_SIZE];
        // magic
        h[0..4].copy_from_slice(&NSO_MAGIC.to_le_bytes());
        // text segment at file offset 0x100, mem offset 0, size 0x10
        h[0x10..0x14].copy_from_slice(&0x0100_u32.to_le_bytes()); // file offset
        h[0x14..0x18].copy_from_slice(&0x0000_u32.to_le_bytes()); // mem offset
        h[0x18..0x1C].copy_from_slice(&0x0010_u32.to_le_bytes()); // mem size
        // rodata segment at file offset 0x110
        h[0x24..0x28].copy_from_slice(&0x0110_u32.to_le_bytes());
        h[0x28..0x2C].copy_from_slice(&0x1000_u32.to_le_bytes());
        h[0x2C..0x30].copy_from_slice(&0x0010_u32.to_le_bytes());
        // data segment at file offset 0x120
        h[0x38..0x3C].copy_from_slice(&0x0120_u32.to_le_bytes());
        h[0x3C..0x40].copy_from_slice(&0x2000_u32.to_le_bytes());
        h[0x40..0x44].copy_from_slice(&0x0010_u32.to_le_bytes());
        h
    }

    #[test]
    fn test_nso_magic_detection() {
        let h = minimal_nso_header();
        assert!(is_nso(&h));
    }

    #[test]
    fn test_nso_header_parse_magic_check() {
        let mut h = minimal_nso_header();
        h[0] = 0xFF;
        let err = NsoHeader::parse(&h).unwrap_err();
        assert!(matches!(err, NsoNroError::BadMagic { .. }));
    }

    #[test]
    fn test_nso_header_parse_too_short() {
        let h = vec![0u8; 10];
        let err = NsoHeader::parse(&h).unwrap_err();
        assert!(matches!(err, NsoNroError::FileTooShort { .. }));
    }

    #[test]
    fn test_nso_header_build_id_hex_length() {
        let h = minimal_nso_header();
        let hdr = NsoHeader::parse(&h).unwrap();
        assert_eq!(hdr.build_id_hex().len(), 40); // 20 bytes * 2 hex chars
    }

    #[test]
    fn test_nso_flags_default_empty() {
        let h = minimal_nso_header();
        let hdr = NsoHeader::parse(&h).unwrap();
        assert!(!hdr.text_compressed());
        assert!(!hdr.rodata_compressed());
        assert!(!hdr.data_compressed());
    }

    #[test]
    fn test_nso_segment_header_parse() {
        let data = [
            0x00, 0x01, 0x00, 0x00, // file_offset = 0x100
            0x00, 0x00, 0x00, 0x00, // mem_offset = 0
            0x10, 0x00, 0x00, 0x00, // mem_size = 0x10
            0x00, 0x00, 0x00, 0x00,
        ]; // align = 0
        let seg = NsoSegmentHeader::parse(&data).unwrap();
        assert_eq!(seg.file_offset, 0x100);
        assert_eq!(seg.mem_size, 0x10);
    }

    #[test]
    fn test_nso_display() {
        let h = minimal_nso_header();
        let hdr = NsoHeader::parse(&h).unwrap();
        let s = format!("{hdr}");
        assert!(s.contains("NSO0"));
    }

    fn minimal_nro_header() -> Vec<u8> {
        let mut h = vec![0u8; NRO_HEADER_SIZE + 0x100];
        // jump instruction at offset 0 (ARM64 B forward to 0x10)
        h[0..4].copy_from_slice(&0x1400_0004_u32.to_le_bytes());
        // mod offset = 8
        h[4..8].copy_from_slice(&8_u32.to_le_bytes());
        // magic at 0x10
        h[0x10..0x14].copy_from_slice(&NRO_MAGIC.to_le_bytes());
        // version = 0
        // total size
        h[0x18..0x1C].copy_from_slice(&(u32::try_from(NRO_HEADER_SIZE).unwrap_or(u32::MAX) + 0x60).to_le_bytes());
        // text at offset 0x70, size 0x10
        h[0x20..0x24].copy_from_slice(&0x0070_u32.to_le_bytes());
        h[0x24..0x28].copy_from_slice(&0x0010_u32.to_le_bytes());
        // rodata at 0x80, size 0x10
        h[0x28..0x2C].copy_from_slice(&0x0080_u32.to_le_bytes());
        h[0x2C..0x30].copy_from_slice(&0x0010_u32.to_le_bytes());
        // data at 0x90, size 0x10
        h[0x30..0x34].copy_from_slice(&0x0090_u32.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&0x0010_u32.to_le_bytes());
        // bss size = 0x100
        h[0x38..0x3C].copy_from_slice(&0x0100_u32.to_le_bytes());
        h
    }

    #[test]
    fn test_nro_detection() {
        let h = minimal_nro_header();
        assert!(is_nro(&h));
    }

    #[test]
    fn test_nro_header_parse_ok() {
        let h = minimal_nro_header();
        let hdr = NroHeader::parse(&h).unwrap();
        assert_eq!(hdr.magic, NRO_MAGIC);
        assert_eq!(hdr.text_va, 0x70);
        assert_eq!(hdr.bss_size, 0x100);
    }

    #[test]
    fn test_nro_build_id_hex_length() {
        let h = minimal_nro_header();
        let hdr = NroHeader::parse(&h).unwrap();
        assert_eq!(hdr.build_id_hex().len(), 40);
    }

    #[test]
    fn test_nro_loader_load_ok() {
        let h = minimal_nro_header();
        let result = NroLoader::load(&h, SWITCH_ASLR_BASE).unwrap();
        assert_eq!(result.load_base, SWITCH_ASLR_BASE);
        assert_eq!(result.text.len(), 0x10);
        assert_eq!(result.rodata.len(), 0x10);
        assert_eq!(result.data.len(), 0x10);
    }

    #[test]
    fn test_nro_display() {
        let h = minimal_nro_header();
        let hdr = NroHeader::parse(&h).unwrap();
        let s = format!("{hdr}");
        assert!(s.contains("NRO0"));
    }

    #[test]
    fn test_nso_flags_bitflags() {
        let f = NsoFlags::TEXT_COMPRESSED | NsoFlags::RODATA_COMPRESSED;
        assert!(f.contains(NsoFlags::TEXT_COMPRESSED));
        assert!(!f.contains(NsoFlags::DATA_COMPRESSED));
    }

    #[test]
    fn test_lz4_decompress_empty_input() {
        let out = lz4_decompress(&[], 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_lz4_decompress_underflow_error() {
        let err = lz4_decompress(&[], 10).unwrap_err();
        assert!(matches!(err, NsoNroError::Lz4Underflow { .. }));
    }

    #[test]
    fn test_nrr_header_parse_bad_magic() {
        let data = vec![0xFF_u8; NrrHeader::MIN_SIZE];
        let err = NrrHeader::parse(&data).unwrap_err();
        assert!(matches!(err, NsoNroError::BadMagic { .. }));
    }

    #[test]
    fn test_nso_segment_oob_error() {
        // Build a minimal NSO header that points to a segment beyond the file
        let mut data = minimal_nso_header();
        // text at file offset 0x100, size 0x10 — append those bytes
        data.extend(vec![0xAAu8; 0x10]); // text at 0x100
        data.extend(vec![0xBBu8; 0x10]); // rodata at 0x110
        // but do NOT include data segment bytes
        let result = NsoLoader::load(&data);
        // data segment oob
        assert!(result.is_err());
    }
}
