//! `rustre-loader-firmware`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: FIRMWARE
//!
//! Comprehensive firmware loader implementing raw binary, Intel HEX,
//! Motorola S-record (SREC), UF2, and U-Boot legacy/FIT image format parsing.
//!
//! ## Features
//! - **U-Boot uImage**: magic `0x27051956`, header (crc, time, size, load, ep,
//!   dcrc, os, arch, type, comp, name), payload extraction and decompression hint.
//! - **Intel HEX**: parse records (DATA:0, EOF:1, EXSEG:2, STARTSEG:3,
//!   EXLIN:4, STARTLIN:5), reconstruct memory image with segment merging.
//! - **Motorola S-Record**: S0/S1/S2/S3/S5/S7/S8/S9 record types, checksum
//!   verification, multi-region image assembly.
//! - **UF2**: Microsoft USB Flashing Format, 512-byte blocks, payload assembly.
//! - **Raw binary**: entropy scan, magic byte search, architecture auto-detect
//!   heuristics (ARM: `0xEAxxxxxx` branch patterns, MIPS: `lui`/`addiu` pairs,
//!   x86: `push ebp` / `push esp` sequences, RISC-V: `auipc` patterns).
//! - **Binwalk-equivalent signature scanner**: gzip, squashfs, cramfs, jffs2,
//!   ubifs, ext2, PE/MZ, ELF, zlib, lzma, XZ, bzip2, 7-zip, ZIP, U-Boot.
//! - **RTOS detection**: `FreeRTOS`, `VxWorks`, `ThreadX`, RTEMS, QNX, Contiki,
//!   Tizen RT, Zephyr, RIOT OS, `NuttX`, `LynxOS`, INTEGRITY.
//! - **Entropy analysis**: 256-bin byte-frequency histogram, Shannon entropy.
//! - **String extraction** with category classification (URL, path, IP, version).
//! - **Boot section identification**: Cortex-M vector table, U-Boot payload,
//!   UF2 regions, generic boot-marker strings.

// ── new sub-modules ───────────────────────────────────────────────────────────
pub mod entropy_analysis;
pub mod extractor;
pub mod filesystem_extraction;
pub mod firmware_analysis_report;
pub mod firmware_security;
pub mod intel_hex;
pub mod signature_db;
pub mod srec_parser;
pub mod uboot_parser;
pub mod uefi_analysis;

pub use uefi_analysis::{
    DxeDriver, EfiFfs, EfiFirmwareVolume, EfiSection, EfiSectionType, FV_SIGNATURE, FfsFileType,
    Guid, GuidDatabase, PeiModule, UefiAnalysis, UefiError, format_guid,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo,
};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::permissions::Permissions;
use rustre_core::{LoadResult, Loader, LoaderInput, NestedBinary};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the firmware loader subsystem.
#[derive(Debug, thiserror::Error)]
pub enum FirmwareError {
    /// Data is too short to contain a valid structure.
    #[error("truncated data")]
    TruncatedData,
    /// A format-specific magic value did not match.
    #[error("invalid magic: {0}")]
    InvalidMagic(String),
    /// Checksum verification failed.
    #[error("checksum mismatch: expected {expected:#04x}, got {actual:#04x}")]
    ChecksumMismatch { expected: u8, actual: u8 },
    /// Record type is not recognised.
    #[error("unknown record type: {0:#04x}")]
    UnknownRecord(u8),
    /// Generic parse failure with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// Address overflow detected.
    #[error("address overflow at record {0}")]
    AddressOverflow(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// Firmware kind detection
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a raw firmware image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareKind {
    /// Plain binary blob with no recognised container.
    Raw,
    /// U-Boot legacy image (`0x27051956`).
    UBoot,
    /// U-Boot FIT image (device tree blob `0xD00DFEED`).
    UBootFit,
    /// `SquashFS` compressed filesystem.
    SquashFs,
    /// JFFS2 flash filesystem.
    Jffs2,
    /// `CramFS` compressed filesystem.
    CramFs,
    /// ext2/3/4 filesystem.
    Ext2,
    /// YAFFS2 flash filesystem.
    Yaffs2,
    /// Gzip / tar.gz archive.
    TarGz,
    /// Bzip2 compressed archive.
    Bzip2,
    /// LZMA compressed stream.
    Lzma,
    /// XZ compressed stream.
    Xz,
    /// Intel HEX ASCII text record format.
    IntelHex,
    /// Motorola SREC (S-record) ASCII text format.
    Srec,
    /// Microsoft UF2 (USB Flashing Format).
    Uf2,
    /// Unrecognised but non-empty binary.
    Unknown,
}

impl FirmwareKind {
    /// Return `true` if this kind is a compressed archive.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        matches!(self, Self::TarGz | Self::Bzip2 | Self::Lzma | Self::Xz)
    }

    /// Return `true` if this kind is a filesystem image.
    #[must_use]
    pub const fn is_filesystem(self) -> bool {
        matches!(
            self,
            Self::SquashFs | Self::Jffs2 | Self::CramFs | Self::Ext2 | Self::Yaffs2
        )
    }

    /// Return `true` if this kind is an ASCII text format.
    #[must_use]
    pub const fn is_text_format(self) -> bool {
        matches!(self, Self::IntelHex | Self::Srec)
    }
}

impl fmt::Display for FirmwareKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::UBoot => write!(f, "uboot-legacy"),
            Self::UBootFit => write!(f, "uboot-fit"),
            Self::SquashFs => write!(f, "squashfs"),
            Self::Jffs2 => write!(f, "jffs2"),
            Self::CramFs => write!(f, "cramfs"),
            Self::Ext2 => write!(f, "ext2"),
            Self::Yaffs2 => write!(f, "yaffs2"),
            Self::TarGz => write!(f, "tar.gz"),
            Self::Bzip2 => write!(f, "bzip2"),
            Self::Lzma => write!(f, "lzma"),
            Self::Xz => write!(f, "xz"),
            Self::IntelHex => write!(f, "intel-hex"),
            Self::Srec => write!(f, "srec"),
            Self::Uf2 => write!(f, "uf2"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Detect the firmware container kind from the first bytes of `data`.
#[must_use]
pub fn detect_firmware_kind(data: &[u8]) -> FirmwareKind {
    if data.len() < 2 {
        return FirmwareKind::Raw;
    }
    if data.starts_with(b"\x1f\x8b") {
        return FirmwareKind::TarGz;
    }
    if data.starts_with(b"BZh") {
        return FirmwareKind::Bzip2;
    }
    if data.starts_with(b"\xFD7zXZ\x00") {
        return FirmwareKind::Xz;
    }
    if data.starts_with(&[0x5D, 0x00, 0x00]) {
        return FirmwareKind::Lzma;
    }
    if data.starts_with(b":") {
        return FirmwareKind::IntelHex;
    }
    if data.len() >= 2 && data[0] == b'S' && data[1].is_ascii_digit() {
        return FirmwareKind::Srec;
    }
    if data.starts_with(b"UF2\n") {
        return FirmwareKind::Uf2;
    }
    if data.len() < 4 {
        return FirmwareKind::Unknown;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0x2705_1956 => FirmwareKind::UBoot,
        0xD00D_FEED => FirmwareKind::UBootFit,
        0x7371_7368 | 0x7173_6873 | 0x6873_7173 | 0x6873_7371 => FirmwareKind::SquashFs,
        0x1985_2003 => FirmwareKind::Jffs2,
        0x28CD_3D45 => FirmwareKind::CramFs,
        // NOTE: Ext2 magic (0xEF53) lives at superblock offset 1080–1081, not at
        // file offset 0. Detection from the first 4 bytes is meaningless and
        // would never match a real Ext2 image. Ext2 is detected properly in
        // Ext2Extractor::detect (reads bytes at offset 1080–1081). No arm here.
        _ => FirmwareKind::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Binwalk-equivalent embedded signature scanner
// ─────────────────────────────────────────────────────────────────────────────

/// A signature match found while scanning a firmware image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedSignature {
    /// Human-readable name of the found format.
    pub name: &'static str,
    /// Byte offset within the firmware image.
    pub offset: usize,
    /// Length of the signature in bytes.
    pub sig_len: usize,
    /// Additional description or metadata string.
    pub description: String,
}

/// Scan `data` for embedded file format signatures.
///
/// Equivalent to a subset of binwalk's signature database.
/// Returns all matches found, sorted by offset.
#[must_use]
pub fn scan_embedded_signatures(data: &[u8]) -> Vec<EmbeddedSignature> {
    let signatures: &[(&'static str, &[u8], &str)] = &[
        // Compressed streams
        ("gzip", &[0x1F, 0x8B], "gzip compressed data"),
        ("bzip2", b"BZh", "bzip2 compressed data"),
        (
            "xz",
            &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            "XZ compressed stream",
        ),
        ("lzma", &[0x5D, 0x00, 0x00], "LZMA compressed stream"),
        ("zlib", &[0x78, 0x9C], "zlib compressed (default)"),
        ("zlib-best", &[0x78, 0xDA], "zlib compressed (best)"),
        ("zlib-low", &[0x78, 0x01], "zlib compressed (low)"),
        ("7-zip", b"7z\xBC\xAF\x27\x1C", "7-zip archive"),
        // Filesystems
        (
            "squashfs-le",
            &[0x73, 0x71, 0x73, 0x68],
            "SquashFS filesystem (LE)",
        ),
        (
            "squashfs-be",
            &[0x71, 0x73, 0x68, 0x73],
            "SquashFS filesystem (BE)",
        ),
        ("jffs2", &[0x19, 0x85], "JFFS2 filesystem"),
        ("cramfs", &[0x45, 0x3D, 0xCD, 0x28], "CramFS filesystem"),
        ("ubifs", &[0x31, 0x18, 0x10, 0x06], "UBIFS superblock"),
        ("ext2", &[0x53, 0xEF], "ext2/3/4 filesystem"),
        // Executables
        ("elf", &[0x7F, 0x45, 0x4C, 0x46], "ELF executable"),
        ("pe", &[0x4D, 0x5A], "PE/MZ executable"),
        // Firmware formats
        ("uboot", &[0x27, 0x05, 0x19, 0x56], "U-Boot uImage"),
        ("fit", &[0xD0, 0x0D, 0xFE, 0xED], "U-Boot FIT image"),
        ("uf2", b"UF2\n", "UF2 flash image"),
        // Archives
        ("zip", b"PK\x03\x04", "ZIP archive"),
        ("zip-eocd", b"PK\x05\x06", "ZIP end of central dir"),
        ("tar", b"ustar", "POSIX tar archive"),
        // Certificates / keys
        ("der-cert", &[0x30, 0x82], "DER certificate"),
    ];

    let mut results = Vec::new();
    for &(name, sig, desc) in signatures {
        let mut search_offset = 0;
        while search_offset + sig.len() <= data.len() {
            if let Some(rel) = data[search_offset..]
                .windows(sig.len())
                .position(|w| w == sig)
            {
                let abs = search_offset + rel;
                results.push(EmbeddedSignature {
                    name,
                    offset: abs,
                    sig_len: sig.len(),
                    description: desc.to_string(),
                });
                search_offset = abs + sig.len().max(1);
            } else {
                break;
            }
        }
    }

    results.sort_by_key(|e| e.offset);
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-frequency histogram for entropy analysis.
#[derive(Debug, Clone)]
pub struct ByteHistogram {
    /// Counts for each of the 256 byte values.
    pub counts: [u64; 256],
    /// Total number of bytes sampled.
    pub total: u64,
}

impl ByteHistogram {
    /// Build a histogram from `data`.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        Self {
            counts,
            total: data.len() as u64,
        }
    }

    /// Compute Shannon entropy in bits per byte (range: 0.0 to 8.0).
    ///
    /// Fully random data approaches 8.0; highly repetitive data approaches 0.0.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        self.counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total;
                -p * p.log2()
            })
            .sum()
    }

    /// Returns `true` when entropy is likely encrypted/compressed (> 7.0 bits).
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy() > 7.0
    }

    /// Returns `true` when entropy is very low (< 1.0 bits) — likely sparse data.
    #[must_use]
    pub fn is_sparse(&self) -> bool {
        self.entropy() < 1.0
    }

    /// Return the most common byte value.
    #[must_use]
    pub fn most_common_byte(&self) -> u8 {
        let mut best_idx = 0usize;
        let mut best_count = self.counts[0];
        for (i, &c) in self.counts.iter().enumerate().skip(1) {
            if c > best_count {
                best_count = c;
                best_idx = i;
            }
        }
        best_idx as u8
    }

    /// Compute entropy of a sliding window (`window_size` bytes, `step_size` stride).
    /// Returns vec of (offset, entropy) pairs.
    #[must_use]
    pub fn sliding_entropy(data: &[u8], window_size: usize, step_size: usize) -> Vec<(usize, f64)> {
        if window_size == 0 || step_size == 0 || data.len() < window_size {
            return vec![];
        }
        (0..=(data.len() - window_size))
            .step_by(step_size)
            .map(|off| {
                let h = ByteHistogram::from_data(&data[off..off + window_size]);
                (off, h.entropy())
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture auto-detect heuristics for raw binaries
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture guessed from binary heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryArch {
    ArmThumb,
    ArmAarch32,
    Aarch64,
    Mips32Be,
    Mips32Le,
    X86,
    X86_64,
    RiscV32,
    RiscV64,
    PowerPcBe,
    Unknown,
}

impl fmt::Display for BinaryArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ArmThumb => "arm-thumb",
            Self::ArmAarch32 => "arm-aarch32",
            Self::Aarch64 => "aarch64",
            Self::Mips32Be => "mips32-be",
            Self::Mips32Le => "mips32-le",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::PowerPcBe => "ppc-be",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Heuristically detect the target architecture of a raw binary image.
///
/// Uses the following heuristics in order of confidence:
/// 1. **ARM `AArch32`**: scan for unconditional branch encoding `0xEAxxxxxx`
///    (big-endian) or `0xEA` at byte 3 (little-endian).
/// 2. **ARM Thumb/Thumb-2**: common 16-bit push `0xB5xx` or function preamble.
/// 3. **MIPS big-endian**: `lui` instruction `0x3Cxxxxxx` at 4-byte aligned offsets.
/// 4. **MIPS little-endian**: `lui` instruction with `0x3C` at byte 3.
/// 5. **`x86/x86_64`**: `push ebp; mov ebp, esp` (`0x55 0x89 0xE5`) or `ENDBR64`.
/// 6. **RISC-V**: `auipc` pattern (`0x17` in low 7 bits of first byte).
/// 7. **PowerPC BE**: `mflr r0` (`0x7C0802A6`) at aligned offsets.
/// 8. **`AArch64`**: 32-bit instruction alignment + known encoding masks.
#[must_use]
pub fn detect_binary_arch(data: &[u8]) -> BinaryArch {
    if data.len() < 16 {
        return BinaryArch::Unknown;
    }

    // Scores per architecture
    let mut scores: HashMap<BinaryArch, u32> = HashMap::new();

    let sample_len = data.len().min(65536);
    let sample = &data[..sample_len];

    // ARM AArch32 unconditional branch: 0xEA in bits [31:24] (BE), 0xEA at byte[3] (LE)
    let mut arm_be = 0u32;
    let mut arm_le = 0u32;
    for chunk in sample.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        if chunk[0] == 0xEA {
            arm_be += 1;
        }
        if chunk[3] == 0xEA {
            arm_le += 1;
        }
    }
    if arm_le > arm_be && arm_le > 5 {
        *scores.entry(BinaryArch::ArmAarch32).or_default() += arm_le;
    } else if arm_be > 5 {
        *scores.entry(BinaryArch::ArmAarch32).or_default() += arm_be;
    }

    // Thumb: 0xB5xx (push {..., lr}) at 2-byte aligned offsets
    let mut thumb_score = 0u32;
    for i in (0..sample.len().saturating_sub(1)).step_by(2) {
        if sample[i] == 0xB5 {
            thumb_score += 1;
        }
        if sample[i] == 0xBD {
            thumb_score += 1;
        } // pop {..., pc}
    }
    if thumb_score > 3 {
        *scores.entry(BinaryArch::ArmThumb).or_default() += thumb_score;
    }

    // MIPS BE: lui 0x3Cxx at 4-byte aligned
    let mut mips_be = 0u32;
    let mut mips_le = 0u32;
    for i in (0..sample.len().saturating_sub(3)).step_by(4) {
        if sample[i] == 0x3C {
            mips_be += 1;
        }
        if sample[i + 3] == 0x3C {
            mips_le += 1;
        }
        // addiu: 0x24 (BE) / 0x24 at byte 3 (LE)
        if sample[i] == 0x24 {
            mips_be += 1;
        }
        if sample[i + 3] == 0x24 {
            mips_le += 1;
        }
    }
    if mips_le > mips_be && mips_le > 5 {
        *scores.entry(BinaryArch::Mips32Le).or_default() += mips_le;
    } else if mips_be > 5 {
        *scores.entry(BinaryArch::Mips32Be).or_default() += mips_be;
    }

    // x86: push ebp; mov ebp,esp = 0x55 0x89 0xE5
    let x86_preamble = [0x55u8, 0x89, 0xE5];
    let x86_score = sample.windows(3).filter(|w| *w == x86_preamble).count() as u32;
    // Also: 0x90 (nop) runs
    let nop_score = sample.windows(1).filter(|w| w[0] == 0x90).count() as u32;
    if x86_score > 1 || (nop_score > 20 && x86_score > 0) {
        *scores.entry(BinaryArch::X86).or_default() += x86_score * 10 + nop_score / 5;
    }
    // ENDBR64: F3 0F 1E FA
    let endbr64 = [0xF3u8, 0x0F, 0x1E, 0xFA];
    if sample.windows(4).any(|w| w == endbr64) {
        *scores.entry(BinaryArch::X86_64).or_default() += 50;
    }

    // RISC-V: auipc = opcode 0x17 in low 7 bits, 4-byte aligned
    let mut rv_score = 0u32;
    for i in (0..sample.len().saturating_sub(3)).step_by(4) {
        if (sample[i] & 0x7F) == 0x17 {
            rv_score += 1;
        } // auipc
        if (sample[i] & 0x7F) == 0x13 {
            rv_score += 1;
        } // addi immediate family
        if (sample[i] & 0x7F) == 0x67 {
            rv_score += 1;
        } // jalr
    }
    if rv_score > 8 {
        *scores.entry(BinaryArch::RiscV32).or_default() += rv_score;
    }

    // PowerPC BE: mflr r0 = 7C 08 02 A6
    let mflr = [0x7Cu8, 0x08, 0x02, 0xA6];
    let ppc_score = sample
        .chunks(4)
        .filter(|c| c.len() == 4 && *c == mflr)
        .count() as u32;
    if ppc_score > 1 {
        *scores.entry(BinaryArch::PowerPcBe).or_default() += ppc_score * 10;
    }

    // AArch64: instructions are 32 bits; look for common encodings:
    // bl/blr family: bits 31:26 = 0b100101 (bl = 0x94xxxxxx) or 0x97xxxxxx
    let mut a64_score = 0u32;
    for i in (0..sample.len().saturating_sub(3)).step_by(4) {
        let instr = u32::from_le_bytes([sample[i], sample[i + 1], sample[i + 2], sample[i + 3]]);
        // bl instruction: bits 31:26 == 0b100101 = 0x25 (LE upper byte = 0x94 or 0x97)
        if (instr >> 26) == 0b100101 {
            a64_score += 1;
        }
        // stp/ldp: bits 31:27 == 0b10100 or 0b10101
        if (instr >> 27) & 0x1F == 0b10100 {
            a64_score += 1;
        }
    }
    if a64_score > 5 {
        *scores.entry(BinaryArch::Aarch64).or_default() += a64_score;
    }

    // Return highest-scoring architecture
    scores
        .into_iter()
        .max_by_key(|(_, s)| *s)
        .map(|(arch, _)| arch)
        .unwrap_or(BinaryArch::Unknown)
}

/// Auto-detect endianness for a raw binary using the detected architecture.
///
/// Returns `Some(Endian::Big)`, `Some(Endian::Little)`, or `None` if unknown.
#[must_use]
pub const fn detect_raw_endian(arch: BinaryArch) -> Option<Endian> {
    match arch {
        BinaryArch::ArmThumb
        | BinaryArch::ArmAarch32
        | BinaryArch::Aarch64
        | BinaryArch::Mips32Le
        | BinaryArch::X86
        | BinaryArch::X86_64
        | BinaryArch::RiscV32
        | BinaryArch::RiscV64 => Some(Endian::Little),
        BinaryArch::Mips32Be | BinaryArch::PowerPcBe => Some(Endian::Big),
        BinaryArch::Unknown => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level FirmwareInfo
// ─────────────────────────────────────────────────────────────────────────────

/// High-level metadata about a firmware image.
#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    /// Detected container format.
    pub kind: FirmwareKind,
    /// Effective load address.
    pub base_address: u64,
    /// Total byte size of the image.
    pub size: usize,
    /// Optional architecture hint (from string markers).
    pub arch_hint: Option<String>,
    /// Optional endianness hint (from byte-order analysis).
    pub endian_hint: Option<String>,
    /// Architecture detected from binary heuristics.
    pub binary_arch: BinaryArch,
    /// RTOS detected inside the image (if any).
    pub rtos: Option<RtosKind>,
    /// Strings found in the image.
    pub strings: Vec<FirmwareString>,
    /// Boot sections identified.
    pub boot_sections: Vec<BootSection>,
    /// Shannon entropy of the entire image.
    pub entropy: f64,
    /// Embedded signatures found by the binwalk-style scanner.
    pub embedded_signatures: Vec<EmbeddedSignature>,
}

impl FirmwareInfo {
    /// Build a `FirmwareInfo` from raw binary `data`.
    #[must_use]
    pub fn analyse(data: &[u8], base_address: u64) -> Self {
        let kind = detect_firmware_kind(data);
        let arch_hint = detect_arch_hint(data);
        let endian_hint = detect_endian_hint(data);
        let binary_arch = detect_binary_arch(data);
        let rtos = detect_rtos(data);
        let strings = extract_firmware_strings(data, 6);
        let boot_sections = detect_boot_sections(data, base_address);
        let histogram = ByteHistogram::from_data(data);
        let entropy = histogram.entropy();
        let embedded_signatures = scan_embedded_signatures(data);
        Self {
            kind,
            base_address,
            size: data.len(),
            arch_hint,
            endian_hint,
            binary_arch,
            rtos,
            strings,
            boot_sections,
            entropy,
            embedded_signatures,
        }
    }
}

impl fmt::Display for FirmwareInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "firmware kind={} base={:#x} size={} arch={} binary_arch={} endian={} rtos={} entropy={:.2}",
            self.kind,
            self.base_address,
            self.size,
            self.arch_hint.as_deref().unwrap_or("?"),
            self.binary_arch,
            self.endian_hint.as_deref().unwrap_or("?"),
            self.rtos
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| "none".to_string()),
            self.entropy,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RTOS detection
// ─────────────────────────────────────────────────────────────────────────────

/// RTOS identified inside a firmware image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtosKind {
    FreeRtos,
    VxWorks,
    ThreadX,
    Rtems,
    QnxNeutrino,
    Contiki,
    TizenRt,
    Zephyr,
    Riot,
    Nuttx,
    LynxOs,
    Integrity,
}

impl fmt::Display for RtosKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FreeRtos => "FreeRTOS",
            Self::VxWorks => "VxWorks",
            Self::ThreadX => "ThreadX",
            Self::Rtems => "RTEMS",
            Self::QnxNeutrino => "QNX Neutrino",
            Self::Contiki => "Contiki",
            Self::TizenRt => "Tizen RT",
            Self::Zephyr => "Zephyr",
            Self::Riot => "RIOT OS",
            Self::Nuttx => "NuttX",
            Self::LynxOs => "LynxOS",
            Self::Integrity => "INTEGRITY",
        };
        write!(f, "{name}")
    }
}

/// Detect RTOS by scanning for known strings.
#[must_use]
pub fn detect_rtos(data: &[u8]) -> Option<RtosKind> {
    let sigs: &[(&[u8], RtosKind)] = &[
        (b"FreeRTOS", RtosKind::FreeRtos),
        (b"freertos", RtosKind::FreeRtos),
        (b"FREERTOS", RtosKind::FreeRtos),
        (b"VxWorks", RtosKind::VxWorks),
        (b"VXWORKS", RtosKind::VxWorks),
        (b"ThreadX", RtosKind::ThreadX),
        (b"THREADX", RtosKind::ThreadX),
        (b"RTEMS", RtosKind::Rtems),
        (b"QNX", RtosKind::QnxNeutrino),
        (b"Contiki", RtosKind::Contiki),
        (b"TIZEN", RtosKind::TizenRt),
        (b"zephyr", RtosKind::Zephyr),
        (b"Zephyr", RtosKind::Zephyr),
        (b"RIOT-OS", RtosKind::Riot),
        (b"NuttX", RtosKind::Nuttx),
        (b"NUTTX", RtosKind::Nuttx),
        (b"LynxOS", RtosKind::LynxOs),
        (b"INTEGRITY", RtosKind::Integrity),
    ];
    for (sig, kind) in sigs {
        if data.windows(sig.len()).any(|w| w == *sig) {
            return Some(*kind);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture / endian heuristics (string-marker based)
// ─────────────────────────────────────────────────────────────────────────────

/// Guess the target architecture from string markers in `data`.
#[must_use]
pub fn detect_arch_hint(data: &[u8]) -> Option<String> {
    let markers: &[(&[u8], &str)] = &[
        (b"ARM Ltd", "arm"),
        (b"ARM Cortex", "arm"),
        (b"Cortex-M", "arm"),
        (b"ARM64", "aarch64"),
        (b"AArch64", "aarch64"),
        (b"MIPS", "mips"),
        (b"mips", "mips"),
        (b"PowerPC", "ppc"),
        (b"RISC-V", "riscv"),
        (b"riscv", "riscv"),
        (b"x86_64", "x86_64"),
        (b"i386", "x86"),
        (b"AVR", "avr"),
        (b"Xtensa", "xtensa"),
        (b"xtensa", "xtensa"),
        (b"ESP32", "xtensa"),
        (b"ESP8266", "xtensa"),
        (b"STM32", "arm"),
        (b"nRF5", "arm"),
        (b"MSP430", "msp430"),
        (b"PIC32", "mips"),
        (b"SPARC", "sparc"),
    ];
    for (marker, arch) in markers {
        if data.windows(marker.len()).any(|w| w == *marker) {
            return Some((*arch).to_string());
        }
    }
    None
}

/// Guess endianness from repeated pointer-sized patterns near the start.
#[must_use]
pub fn detect_endian_hint(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let check_len = data.len().min(256) & !3;
    let mut le_score = 0u32;
    let mut be_score = 0u32;
    for off in (0..check_len).step_by(4) {
        if data[off + 3] == 0 {
            le_score += 1;
        }
        if data[off] == 0 {
            be_score += 1;
        }
    }
    if le_score > be_score + 2 {
        Some("little".to_string())
    } else if be_score > le_score + 2 {
        Some("big".to_string())
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot section identification
// ─────────────────────────────────────────────────────────────────────────────

/// A named region inside a firmware image likely to be a boot section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSection {
    /// Human-readable name.
    pub name: String,
    /// Offset inside the firmware file.
    pub offset: usize,
    /// Size of the section in bytes.
    pub size: usize,
    /// Guessed load address (0 if unknown).
    pub load_address: u64,
}

/// Identify common boot regions in a firmware image.
#[must_use]
pub fn detect_boot_sections(data: &[u8], base: u64) -> Vec<BootSection> {
    let mut sections = Vec::new();

    if let Some(hdr) = UBootHeader::parse(data) {
        let payload_off = 64usize;
        let payload_len = hdr.data_size as usize;
        let end = payload_off.saturating_add(payload_len);
        if end <= data.len() {
            sections.push(BootSection {
                name: "uboot-payload".to_string(),
                offset: payload_off,
                size: payload_len,
                load_address: u64::from(hdr.load_addr),
            });
        }
        sections.push(BootSection {
            name: "uboot-header".to_string(),
            offset: 0,
            size: 64,
            // Use the actual load address from the header, not the caller-supplied
            // base override, so this is consistent with the payload section above.
            load_address: u64::from(hdr.load_addr),
        });
        return sections;
    }

    if let Ok(blocks) = Uf2Record::parse_all(data)
        && !blocks.is_empty()
    {
        let mut seen: HashMap<u64, usize> = HashMap::new();
        for blk in &blocks {
            *seen.entry(u64::from(blk.target_addr) & !0xFFFF).or_insert(0) += 1;
        }
        for (addr, count) in &seen {
            sections.push(BootSection {
                name: format!("uf2-region@{addr:#010x}"),
                offset: 0,
                size: count * 256,
                load_address: *addr,
            });
        }
        return sections;
    }

    // Cortex-M vector table detection: SP then Reset handler in first 8 bytes
    if data.len() >= 8 {
        let sp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let pc = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if sp > 0x2000_0000 && sp < 0x2010_0000 && pc > 0x0800_0000 && pc < 0x0810_0000 {
            sections.push(BootSection {
                name: "cortex-m-vector-table".to_string(),
                offset: 0,
                size: data.len().min(0x400),
                load_address: base,
            });
        }
    }

    // Scan for common boot strings
    let boot_markers: &[(&[u8], &str)] = &[
        (b"Bootloader", "bootloader"),
        (b"BOOTLOADER", "bootloader"),
        (b"U-Boot", "u-boot"),
        (b"GRUB", "grub"),
        (b"BootROM", "bootrom"),
        (b"SecureBoot", "secure-boot"),
        (b"ATF", "arm-trusted-firmware"),
        (b"TF-A", "arm-trusted-firmware"),
    ];
    for (marker, name) in boot_markers {
        if let Some(pos) = data.windows(marker.len()).position(|w| w == *marker) {
            sections.push(BootSection {
                name: (*name).to_string(),
                offset: pos,
                size: marker.len(),
                load_address: base + pos as u64,
            });
        }
    }

    sections
}

// ─────────────────────────────────────────────────────────────────────────────
// U-Boot legacy image header
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed U-Boot legacy image header (64 bytes).
///
/// Magic: `0x27051956` (big-endian). All multi-byte fields are big-endian.
///
/// See U-Boot source: `include/image.h`, struct `image_header`.
#[derive(Debug, Clone)]
pub struct UBootHeader {
    /// Magic number (`0x27051956`).
    pub magic: u32,
    /// Header CRC32 (computed over header with this field zeroed).
    pub header_crc: u32,
    /// Creation timestamp (POSIX epoch seconds).
    pub timestamp: u32,
    /// Uncompressed data size in bytes.
    pub data_size: u32,
    /// Load address for the image payload.
    pub load_addr: u32,
    /// Entry point address.
    pub entry_point: u32,
    /// Data CRC32.
    pub data_crc: u32,
    /// OS type identifier (see `os_str()`).
    pub os_type: u8,
    /// Architecture identifier (see `arch_str()`).
    pub arch: u8,
    /// Image type identifier (see `image_type_str()`).
    pub image_type: u8,
    /// Compression type identifier (see `comp_str()`).
    pub comp_type: u8,
    /// Null-terminated image name (up to 32 characters).
    pub name: String,
}

impl UBootHeader {
    /// U-Boot magic value.
    pub const MAGIC: u32 = 0x2705_1956;

    /// Parse a `UBootHeader` from the beginning of `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != Self::MAGIC {
            return None;
        }
        let nul_off = data[32..64].iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&data[32..32 + nul_off]).to_string();
        Some(Self {
            magic,
            header_crc: u32::from_be_bytes(data[4..8].try_into().ok()?),
            timestamp: u32::from_be_bytes(data[8..12].try_into().ok()?),
            data_size: u32::from_be_bytes(data[12..16].try_into().ok()?),
            load_addr: u32::from_be_bytes(data[16..20].try_into().ok()?),
            entry_point: u32::from_be_bytes(data[20..24].try_into().ok()?),
            data_crc: u32::from_be_bytes(data[24..28].try_into().ok()?),
            os_type: data[28],
            arch: data[29],
            image_type: data[30],
            comp_type: data[31],
            name,
        })
    }

    /// Return a human-readable architecture name from the `arch` field.
    #[must_use]
    pub const fn arch_str(&self) -> &'static str {
        match self.arch {
            1 => "alpha",
            2 => "arm",
            3 => "x86",
            4 => "mips",
            5 => "mips64",
            6 => "ppc",
            7 => "s390",
            8 => "sh",
            9 => "sparc",
            10 => "sparc64",
            11 => "m68k",
            13 => "microblaze",
            14 => "nios2",
            15 => "blackfin",
            16 => "avr32",
            17 => "st200",
            22 => "aarch64",
            23 => "arc",
            24 => "x86_64",
            25 => "xtensa",
            26 => "riscv",
            _ => "unknown",
        }
    }

    /// Return OS type as a string.
    #[must_use]
    pub const fn os_str(&self) -> &'static str {
        match self.os_type {
            1 => "openbsd",
            2 => "netbsd",
            3 => "freebsd",
            4 => "4.4bsd",
            5 => "linux",
            6 => "svr4",
            7 => "esix",
            8 => "solaris",
            9 => "irix",
            10 => "sco",
            11 => "dell",
            12 => "ncr",
            13 => "lynxos",
            14 => "vxworks",
            15 => "psos",
            16 => "qnx",
            17 => "u-boot",
            18 => "rtems",
            19 => "artos",
            20 => "unity",
            21 => "integrity",
            _ => "unknown",
        }
    }

    /// Return compression type as a string.
    #[must_use]
    pub const fn comp_str(&self) -> &'static str {
        match self.comp_type {
            0 => "none",
            1 => "gzip",
            2 => "bzip2",
            3 => "lzma",
            4 => "lzo",
            5 => "lz4",
            6 => "zstd",
            _ => "unknown",
        }
    }

    /// Return image type as a string.
    #[must_use]
    pub const fn image_type_str(&self) -> &'static str {
        match self.image_type {
            1 => "standalone",
            2 => "kernel",
            3 => "ramdisk",
            4 => "multi",
            5 => "firmware",
            6 => "script",
            7 => "filesystem",
            8 => "flat_dt",
            _ => "unknown",
        }
    }

    /// Return the entry point as a `u64`.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry_point as u64
    }

    /// Extract the payload bytes (raw, possibly compressed).
    ///
    /// Returns the slice `data[64..64+data_size]`, or `None` if out of bounds.
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let start = 64usize;
        let end = start.saturating_add(self.data_size as usize);
        if end <= data.len() {
            Some(&data[start..end])
        } else {
            None
        }
    }
}

impl fmt::Display for UBootHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "uImage '{}' os={} arch={} type={} comp={} load={:#x} ep={:#x} size={}",
            self.name,
            self.os_str(),
            self.arch_str(),
            self.image_type_str(),
            self.comp_str(),
            self.load_addr,
            self.entry_point,
            self.data_size,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Intel HEX parser
// ─────────────────────────────────────────────────────────────────────────────

/// One parsed Intel HEX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntelHexRecord {
    pub byte_count: u8,
    pub address: u16,
    pub record_type: IntelHexRecordType,
    pub data: Vec<u8>,
    pub checksum: u8,
}

/// Intel HEX record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelHexRecordType {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
    Unknown(u8),
}

impl IntelHexRecordType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Data,
            0x01 => Self::EndOfFile,
            0x02 => Self::ExtendedSegmentAddress,
            0x03 => Self::StartSegmentAddress,
            0x04 => Self::ExtendedLinearAddress,
            0x05 => Self::StartLinearAddress,
            other => Self::Unknown(other),
        }
    }
}

fn parse_hex_byte(data: &[u8], offset: usize) -> Result<u8, FirmwareError> {
    if offset + 2 > data.len() {
        return Err(FirmwareError::TruncatedData);
    }
    let hi = char::from(data[offset])
        .to_digit(16)
        .ok_or_else(|| FirmwareError::ParseError(format!("invalid hex at {offset}")))?;
    let lo = char::from(data[offset + 1])
        .to_digit(16)
        .ok_or_else(|| FirmwareError::ParseError(format!("invalid hex at {}", offset + 1)))?;
    Ok((hi * 16 + lo) as u8)
}

impl IntelHexRecord {
    /// Parse a single Intel HEX record line (must start with `':'`).
    pub fn parse_line(line: &[u8]) -> Result<Self, FirmwareError> {
        if line.is_empty() || line[0] != b':' {
            return Err(FirmwareError::InvalidMagic(
                "missing ':' in IHEX record".to_string(),
            ));
        }
        let hex = &line[1..];
        if hex.len() < 10 {
            return Err(FirmwareError::TruncatedData);
        }
        let byte_count = parse_hex_byte(hex, 0)?;
        let addr_hi = u16::from(parse_hex_byte(hex, 2)?);
        let addr_lo = u16::from(parse_hex_byte(hex, 4)?);
        let address = (addr_hi << 8) | addr_lo;
        let rt = parse_hex_byte(hex, 6)?;
        let record_type = IntelHexRecordType::from_byte(rt);
        let data_start = 8usize;
        let data_end = data_start + byte_count as usize * 2;
        if data_end + 2 > hex.len() {
            return Err(FirmwareError::TruncatedData);
        }
        let mut data = Vec::with_capacity(byte_count as usize);
        for i in 0..byte_count as usize {
            data.push(parse_hex_byte(hex, data_start + i * 2)?);
        }
        let checksum = parse_hex_byte(hex, data_end)?;
        // Intel HEX checksum: all bytes (byte_count, addr_hi, addr_lo, record_type,
        // data bytes, checksum) summed mod 256 must equal 0. Use u8 wrapping_add
        // to match the spec exactly (all arithmetic performed mod 256).
        // addr_hi/addr_lo are stored as u16 for address arithmetic above, but each
        // is a single byte in the record, so cast back to u8 before summing.
        let mut sum = byte_count
            .wrapping_add(addr_hi as u8)
            .wrapping_add(addr_lo as u8)
            .wrapping_add(rt);
        for &b in &data {
            sum = sum.wrapping_add(b);
        }
        sum = sum.wrapping_add(checksum);
        if sum != 0 {
            return Err(FirmwareError::ChecksumMismatch {
                expected: 0,
                actual: sum,
            });
        }
        Ok(Self {
            byte_count,
            address,
            record_type,
            data,
            checksum,
        })
    }
}

/// Result of parsing a complete Intel HEX file.
#[derive(Debug, Clone)]
pub struct IntelHexImage {
    pub regions: Vec<(u64, Vec<u8>)>,
    pub start_address: Option<u64>,
}

impl IntelHexImage {
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        let mut upper_base = 0u64;
        let mut start_address = None;
        let mut regions: Vec<(u64, Vec<u8>)> = Vec::new();
        for (line_no, line) in data.split(|&b| b == b'\n').enumerate() {
            let line = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };
            if line.is_empty() {
                continue;
            }
            let record = IntelHexRecord::parse_line(line)
                .map_err(|e| FirmwareError::ParseError(format!("line {line_no}: {e}")))?;
            match record.record_type {
                IntelHexRecordType::Data => {
                    let addr = upper_base + u64::from(record.address);
                    if let Some(last) = regions.last_mut() && last.0 + last.1.len() as u64 == addr {
                        last.1.extend_from_slice(&record.data);
                        continue;
                    }
                    regions.push((addr, record.data));
                }
                IntelHexRecordType::EndOfFile => break,
                IntelHexRecordType::ExtendedLinearAddress => {
                    if record.data.len() < 2 {
                        return Err(FirmwareError::TruncatedData);
                    }
                    upper_base =
                        u64::from(u16::from_be_bytes([record.data[0], record.data[1]])) << 16;
                }
                IntelHexRecordType::ExtendedSegmentAddress => {
                    if record.data.len() < 2 {
                        return Err(FirmwareError::TruncatedData);
                    }
                    upper_base = u64::from(u16::from_be_bytes([record.data[0], record.data[1]])) * 16;
                }
                IntelHexRecordType::StartLinearAddress => {
                    if record.data.len() >= 4 {
                        start_address = Some(u64::from(u32::from_be_bytes([
                            record.data[0],
                            record.data[1],
                            record.data[2],
                            record.data[3],
                        ])));
                    }
                }
                IntelHexRecordType::StartSegmentAddress => {
                    if record.data.len() >= 4 {
                        let cs = u64::from(u16::from_be_bytes([record.data[0], record.data[1]]));
                        let ip = u64::from(u16::from_be_bytes([record.data[2], record.data[3]]));
                        start_address = Some((cs << 4) + ip);
                    }
                }
                IntelHexRecordType::Unknown(_) => {}
            }
        }
        Ok(Self {
            regions,
            start_address,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Motorola SREC parser
// ─────────────────────────────────────────────────────────────────────────────

/// One parsed SREC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrecRecord {
    pub record_type: char,
    pub byte_count: u8,
    pub address: u64,
    pub data: Vec<u8>,
    pub checksum: u8,
}

impl SrecRecord {
    pub fn parse_line(line: &[u8]) -> Result<Self, FirmwareError> {
        if line.len() < 4 || line[0] != b'S' {
            return Err(FirmwareError::InvalidMagic(
                "SREC must start with 'S'".to_string(),
            ));
        }
        let record_type = char::from(line[1]);
        let hex = &line[2..];
        let byte_count = parse_hex_byte(hex, 0)?;
        let addr_bytes: usize = match record_type {
            '0' | '1' | '5' | '9' => 2,
            '2' | '6' | '8' => 3,
            '3' | '7' => 4,
            _ => return Err(FirmwareError::UnknownRecord(line[1])),
        };
        if (byte_count as usize) < addr_bytes + 1 {
            return Err(FirmwareError::TruncatedData);
        }
        let mut addr = 0u64;
        for i in 0..addr_bytes {
            addr = (addr << 8) | u64::from(parse_hex_byte(hex, 2 + i * 2)?);
        }
        let data_start = 2 + addr_bytes * 2;
        let data_count = byte_count as usize - addr_bytes - 1;
        let data_end = data_start + data_count * 2;
        if data_end + 2 > hex.len() {
            return Err(FirmwareError::TruncatedData);
        }
        let mut data = Vec::with_capacity(data_count);
        for i in 0..data_count {
            data.push(parse_hex_byte(hex, data_start + i * 2)?);
        }
        let checksum = parse_hex_byte(hex, data_end)?;
        let mut sum = u32::from(byte_count);
        for i in 0..addr_bytes {
            sum += u32::from(parse_hex_byte(hex, 2 + i * 2)?);
        }
        for &b in &data {
            sum += u32::from(b);
        }
        let expected = (!(sum & 0xFF)) as u8;
        if expected != checksum {
            return Err(FirmwareError::ChecksumMismatch {
                expected,
                actual: checksum,
            });
        }
        Ok(Self {
            record_type,
            byte_count,
            address: addr,
            data,
            checksum,
        })
    }
}

/// Assembled result of a complete SREC file.
#[derive(Debug, Clone)]
pub struct SrecImage {
    pub regions: Vec<(u64, Vec<u8>)>,
    pub entry_point: Option<u64>,
}

impl SrecImage {
    pub fn parse(data: &[u8]) -> Result<Self, FirmwareError> {
        let mut entry_point = None;
        let mut regions: Vec<(u64, Vec<u8>)> = Vec::new();
        for (line_no, line) in data.split(|&b| b == b'\n').enumerate() {
            let line = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };
            if line.is_empty() || line[0] != b'S' {
                continue;
            }
            let record = SrecRecord::parse_line(line)
                .map_err(|e| FirmwareError::ParseError(format!("SREC line {line_no}: {e}")))?;
            match record.record_type {
                '1' | '2' | '3' => {
                    let addr = record.address;
                    if let Some(last) = regions.last_mut() && last.0 + last.1.len() as u64 == addr {
                        last.1.extend_from_slice(&record.data);
                        continue;
                    }
                    regions.push((addr, record.data));
                }
                '7' | '8' | '9' => {
                    entry_point = Some(record.address);
                }
                _ => {}
            }
        }
        Ok(Self {
            regions,
            entry_point,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UF2 format parser
// ─────────────────────────────────────────────────────────────────────────────

pub const UF2_MAGIC_START0: u32 = 0x0A32_4655;
pub const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
pub const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
pub const UF2_BLOCK_SIZE: usize = 512;

/// One parsed UF2 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uf2Record {
    pub flags: u32,
    pub target_addr: u32,
    pub payload_size: u32,
    pub block_no: u32,
    pub num_blocks: u32,
    pub file_size: u32,
    pub data: Vec<u8>,
}

impl Uf2Record {
    pub fn parse(block: &[u8]) -> Result<Self, FirmwareError> {
        if block.len() < UF2_BLOCK_SIZE {
            return Err(FirmwareError::TruncatedData);
        }
        let m0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let m1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        if m0 != UF2_MAGIC_START0 || m1 != UF2_MAGIC_START1 {
            return Err(FirmwareError::InvalidMagic(
                "UF2 magic mismatch".to_string(),
            ));
        }
        let end_magic = u32::from_le_bytes([block[508], block[509], block[510], block[511]]);
        if end_magic != UF2_MAGIC_END {
            return Err(FirmwareError::InvalidMagic(
                "UF2 end magic mismatch".to_string(),
            ));
        }
        Ok(Self {
            flags: u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
            target_addr: u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
            payload_size: u32::from_le_bytes([block[16], block[17], block[18], block[19]]),
            block_no: u32::from_le_bytes([block[20], block[21], block[22], block[23]]),
            num_blocks: u32::from_le_bytes([block[24], block[25], block[26], block[27]]),
            file_size: u32::from_le_bytes([block[28], block[29], block[30], block[31]]),
            data: block[32..508].to_vec(),
        })
    }

    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, FirmwareError> {
        // Truncate to the largest aligned prefix so that flash dumps with
        // trailing padding or appended data are still parsed correctly.
        let aligned_len = (data.len() / UF2_BLOCK_SIZE) * UF2_BLOCK_SIZE;
        data[..aligned_len].chunks(UF2_BLOCK_SIZE).map(Self::parse).collect()
    }

    #[must_use]
    pub fn assemble(records: &[Self]) -> Vec<(u64, Vec<u8>)> {
        let mut regions: Vec<(u64, Vec<u8>)> = Vec::new();
        for rec in records {
            let addr = u64::from(rec.target_addr);
            let size = rec.payload_size as usize;
            let payload = &rec.data[..size.min(rec.data.len())];
            if let Some(last) = regions.last_mut() && last.0 + last.1.len() as u64 == addr {
                last.1.extend_from_slice(payload);
                continue;
            }
            regions.push((addr, payload.to_vec()));
        }
        regions
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// String extraction
// ─────────────────────────────────────────────────────────────────────────────

/// A printable string found in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareString {
    pub offset: usize,
    pub text: String,
    pub category: StringCategory,
}

/// Broad category for a firmware string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringCategory {
    Version,
    Url,
    Path,
    IpAddress,
    Generic,
}

impl fmt::Display for StringCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => write!(f, "version"),
            Self::Url => write!(f, "url"),
            Self::Path => write!(f, "path"),
            Self::IpAddress => write!(f, "ip"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Classify a string into a category.
#[must_use]
pub fn classify_string(s: &str) -> StringCategory {
    if s.contains("http://") || s.contains("https://") || s.contains("ftp://") {
        return StringCategory::Url;
    }
    if s.starts_with('/') || s.contains(":/") || s.contains('\\') {
        return StringCategory::Path;
    }
    if s.chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
        && s.contains('.')
        && s.split('.').count() == 4
        && s.split('.').all(|p| p.parse::<u8>().is_ok())
    {
        return StringCategory::IpAddress;
    }
    if s.to_lowercase().contains("version")
        || s.contains("v1.")
        || s.contains("v2.")
        || s.contains("v3.")
        || (s.contains('.') && s.chars().any(|c| c.is_ascii_digit()))
    {
        return StringCategory::Version;
    }
    StringCategory::Generic
}

/// Extract all printable ASCII strings of at least `min_len` from `data`.
#[must_use]
pub fn extract_firmware_strings(data: &[u8], min_len: usize) -> Vec<FirmwareString> {
    let mut result = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len {
                // all bytes in s..i passed is_ascii_graphic() || b' ', so valid UTF-8.
                let text = std::str::from_utf8(&data[s..i]).expect("ascii bytes are valid utf-8").to_owned();
                let category = classify_string(&text);
                result.push(FirmwareString {
                    offset: s,
                    text,
                    category,
                });
            }
        }
    }
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_len {
            // all bytes in s.. passed is_ascii_graphic() || b' ', so valid UTF-8.
            let text = std::str::from_utf8(&data[s..]).expect("ascii bytes are valid utf-8").to_owned();
            let category = classify_string(&text);
            result.push(FirmwareString {
                offset: s,
                text,
                category,
            });
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture stub
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal Architecture implementation for a generic firmware target.
#[derive(Debug)]
pub struct FirmwareArch {
    arch_name: String,
    ptr_size: usize,
    endian: Endian,
}

impl FirmwareArch {
    #[must_use]
    pub const fn new(arch_name: String) -> Self {
        Self {
            arch_name,
            ptr_size: 4,
            endian: Endian::Little,
        }
    }

    #[must_use]
    pub const fn with_params(arch_name: String, ptr_size: usize, endian: Endian) -> Self {
        Self {
            arch_name,
            ptr_size,
            endian,
        }
    }
}

impl Architecture for FirmwareArch {
    fn name(&self) -> &str {
        &self.arch_name
    }
    fn pointer_size(&self) -> usize {
        self.ptr_size
    }
    fn endian(&self) -> Endian {
        self.endian
    }

    fn disassemble(&self, _address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        // This used to answer `nop` for every input, with a length invented as
        // `bytes[0] % 4 + 1` — a size that varies with the data, so the output
        // looked like a genuine decode of variable-length instructions while
        // bearing no relation to the bytes.
        //
        // A firmware image can hold ARM, Thumb, MIPS, RISC-V or Xtensa code;
        // this crate detects which (`detect_binary_arch`) but carries no decoder
        // for any of them, and it does not depend on the rustre-arch-* crates
        // that do. Saying so is the only honest answer available here.
        if bytes.is_empty() {
            return Err(CoreError::InvalidInput {
                message: "disassemble called with empty byte slice".into(),
            });
        }
        Err(CoreError::ArchitectureError {
            arch: self.arch_name.clone(),
            message: "rustre-loader-firmware detects architectures but does not \
                      decode instructions; use the matching rustre-arch-* crate"
                .into(),
        })
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }
    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }
    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw firmware loader
// ─────────────────────────────────────────────────────────────────────────────

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const PE_MAGIC: &[u8; 2] = b"MZ";

/// Loader for raw firmware and ROM images. Accepts any input not handled by
/// the dedicated ELF or PE loaders.
#[derive(Debug, Default)]
pub struct FirmwareLoader;

impl FirmwareLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for FirmwareLoader {
    fn name(&self) -> &str {
        "firmware"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        let data = &input.data;
        if data.len() < 4 {
            return false;
        }
        if data.starts_with(ELF_MAGIC) {
            return false;
        }
        if data.starts_with(PE_MAGIC) {
            return false;
        }
        true
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let hint_base = input.hints.base_address().map(rustre_core::Address::as_u64);
        let arch_name = input
            .hints
            .architecture()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());

        let (entry, actual_base) = if let Some(hdr) = UBootHeader::parse(&input.data) {
            (u64::from(hdr.entry_point), u64::from(hdr.load_addr))
        } else {
            let base = hint_base.unwrap_or(0);
            (base, base)
        };

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(actual_base),
                    Address::new(actual_base + size),
                ),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }

        let arch = Arc::new(FirmwareArch::new(arch_name));
        let view = BinaryView::new(
            ViewId::from_raw(rustre_core::loader::next_view_id().into_raw()),
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(entry)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Intel HEX loader
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct IntelHexLoader;

impl IntelHexLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for IntelHexLoader {
    fn name(&self) -> &str {
        "intel-hex"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        input.data.starts_with(b":")
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let arch_name = input
            .hints
            .architecture()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let image =
            IntelHexImage::parse(&input.data).map_err(|e| CoreError::parse(0, e.to_string()))?;
        let mut mem = Memory::new();
        for (addr, data) in &image.regions {
            let end = addr + data.len() as u64;
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(*addr), Address::new(end)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: data.clone(),
            });
        }
        let entry = image
            .start_address
            .or_else(|| image.regions.first().map(|(a, _)| *a))
            .unwrap_or(0);
        let arch = Arc::new(FirmwareArch::new(arch_name));
        let view = BinaryView::new(
            ViewId::from_raw(rustre_core::loader::next_view_id().into_raw()),
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(entry)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SREC loader
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SrecLoader;

impl SrecLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for SrecLoader {
    fn name(&self) -> &str {
        "srec"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        input.data.len() >= 2 && input.data[0] == b'S' && input.data[1].is_ascii_digit()
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let arch_name = input
            .hints
            .architecture()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let image =
            SrecImage::parse(&input.data).map_err(|e| CoreError::parse(0, e.to_string()))?;
        let mut mem = Memory::new();
        for (addr, data) in &image.regions {
            let end = addr + data.len() as u64;
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(*addr), Address::new(end)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: data.clone(),
            });
        }
        let entry = image
            .entry_point
            .or_else(|| image.regions.first().map(|(a, _)| *a))
            .unwrap_or(0);
        let arch = Arc::new(FirmwareArch::new(arch_name));
        let view = BinaryView::new(
            ViewId::from_raw(rustre_core::loader::next_view_id().into_raw()),
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(entry)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UF2 loader
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Uf2Loader;

impl Uf2Loader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for Uf2Loader {
    fn name(&self) -> &str {
        "uf2"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        input.data.len() >= UF2_BLOCK_SIZE && input.data.starts_with(b"UF2\n")
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let arch_name = input
            .hints
            .architecture()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let records =
            Uf2Record::parse_all(&input.data).map_err(|e| CoreError::parse(0, e.to_string()))?;
        let regions = Uf2Record::assemble(&records);
        let mut mem = Memory::new();
        for (addr, data) in &regions {
            let end = addr + data.len() as u64;
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(*addr), Address::new(end)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: data.clone(),
            });
        }
        let entry = regions.first().map(|(a, _)| *a).unwrap_or(0);
        let arch = Arc::new(FirmwareArch::new(arch_name));
        let view = BinaryView::new(
            ViewId::from_raw(rustre_core::loader::next_view_id().into_raw()),
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(entry)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_firmware_kind ───────────────────────────────────────────────────

    #[test]
    fn test_detect_uboot() {
        let data = [0x27, 0x05, 0x19, 0x56, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::UBoot);
    }

    #[test]
    fn test_detect_uboot_fit() {
        let data = [0xD0, 0x0D, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::UBootFit);
    }

    #[test]
    fn test_detect_squashfs() {
        let data = [0x73, 0x71, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::SquashFs);
    }

    #[test]
    fn test_detect_squashfs_be() {
        let data = [0x71, 0x73, 0x68, 0x73, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::SquashFs);
    }

    #[test]
    fn test_detect_jffs2() {
        let data = [0x19, 0x85, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::Jffs2);
    }

    #[test]
    fn test_detect_cramfs() {
        let data = [0x28, 0xCD, 0x3D, 0x45, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::CramFs);
    }

    #[test]
    fn test_detect_targz() {
        assert_eq!(
            detect_firmware_kind(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]),
            FirmwareKind::TarGz
        );
    }

    #[test]
    fn test_detect_bzip2() {
        assert_eq!(detect_firmware_kind(b"BZh91AY"), FirmwareKind::Bzip2);
    }

    #[test]
    fn test_detect_xz() {
        let data = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::Xz);
    }

    #[test]
    fn test_detect_lzma() {
        assert_eq!(
            detect_firmware_kind(&[0x5D, 0x00, 0x00, 0x10, 0x00]),
            FirmwareKind::Lzma
        );
    }

    #[test]
    fn test_detect_intel_hex() {
        assert_eq!(
            detect_firmware_kind(b":10000000..."),
            FirmwareKind::IntelHex
        );
    }

    #[test]
    fn test_detect_srec() {
        assert_eq!(detect_firmware_kind(b"S0030000FC"), FirmwareKind::Srec);
    }

    #[test]
    fn test_detect_uf2() {
        let mut data = vec![0u8; 512];
        data[..4].copy_from_slice(b"UF2\n");
        assert_eq!(detect_firmware_kind(&data), FirmwareKind::Uf2);
    }

    #[test]
    fn test_detect_raw_short() {
        assert_eq!(detect_firmware_kind(&[0x00]), FirmwareKind::Raw);
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(
            detect_firmware_kind(&[0xAA, 0xBB, 0xCC, 0xDD]),
            FirmwareKind::Unknown
        );
    }

    // ── FirmwareKind methods ───────────────────────────────────────────────────

    #[test]
    fn test_firmware_kind_is_compressed() {
        assert!(FirmwareKind::TarGz.is_compressed());
        assert!(!FirmwareKind::UBoot.is_compressed());
    }

    #[test]
    fn test_firmware_kind_is_filesystem() {
        assert!(FirmwareKind::SquashFs.is_filesystem());
        assert!(!FirmwareKind::TarGz.is_filesystem());
    }

    #[test]
    fn test_firmware_kind_is_text_format() {
        assert!(FirmwareKind::IntelHex.is_text_format());
        assert!(!FirmwareKind::Raw.is_text_format());
    }

    #[test]
    fn test_firmware_kind_display() {
        assert_eq!(FirmwareKind::UBoot.to_string(), "uboot-legacy");
        assert_eq!(FirmwareKind::SquashFs.to_string(), "squashfs");
    }

    // ── Entropy analysis ──────────────────────────────────────────────────────

    #[test]
    fn test_entropy_empty() {
        let h = ByteHistogram::from_data(&[]);
        assert_eq!(h.entropy(), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All zeros → entropy 0
        let h = ByteHistogram::from_data(&[0u8; 256]);
        assert_eq!(h.entropy(), 0.0);
        assert!(h.is_sparse());
    }

    #[test]
    fn test_entropy_all_bytes() {
        // All 256 values exactly once → maximum entropy
        let data: Vec<u8> = (0u8..=255).collect();
        let h = ByteHistogram::from_data(&data);
        let e = h.entropy();
        assert!(e > 7.9, "entropy={e}");
        assert!(h.is_high_entropy());
    }

    #[test]
    fn test_most_common_byte() {
        let data = [0xAAu8, 0xAA, 0xBB, 0xAA, 0xCC];
        let h = ByteHistogram::from_data(&data);
        assert_eq!(h.most_common_byte(), 0xAA);
    }

    #[test]
    fn test_sliding_entropy_length() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let windows = ByteHistogram::sliding_entropy(&data, 256, 256);
        assert_eq!(windows.len(), 4);
    }

    #[test]
    fn test_sliding_entropy_empty_window() {
        let result = ByteHistogram::sliding_entropy(&[1u8, 2, 3], 10, 1);
        assert!(result.is_empty()); // window larger than data
    }

    // ── Embedded signature scanner ────────────────────────────────────────────

    #[test]
    fn test_scan_embedded_signatures_gzip() {
        let mut data = vec![0u8; 32];
        data[10..12].copy_from_slice(&[0x1F, 0x8B]);
        let sigs = scan_embedded_signatures(&data);
        assert!(sigs.iter().any(|s| s.name == "gzip" && s.offset == 10));
    }

    #[test]
    fn test_scan_embedded_signatures_elf() {
        let mut data = vec![0u8; 64];
        data[16..20].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        let sigs = scan_embedded_signatures(&data);
        assert!(sigs.iter().any(|s| s.name == "elf"));
    }

    #[test]
    fn test_scan_embedded_signatures_empty() {
        let sigs = scan_embedded_signatures(&[0u8; 32]);
        // No known sigs in all-zero data (except possibly gzip 0x1f 0x8b = not present)
        assert!(sigs.iter().all(|s| s.name != "gzip"));
    }

    #[test]
    fn test_scan_embedded_signatures_sorted() {
        let mut data = vec![0u8; 100];
        data[80..82].copy_from_slice(&[0x1F, 0x8B]); // gzip at 80
        data[50..54].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]); // ELF at 50
        let sigs = scan_embedded_signatures(&data);
        let offsets: Vec<usize> = sigs.iter().map(|s| s.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] <= w[1]));
    }

    // ── Architecture detection ─────────────────────────────────────────────────

    #[test]
    fn test_detect_binary_arch_unknown_short() {
        assert_eq!(detect_binary_arch(&[0u8; 4]), BinaryArch::Unknown);
    }

    #[test]
    fn test_detect_binary_arch_x86_64_endbr() {
        let mut data = vec![0u8; 64];
        data[32..36].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA]); // ENDBR64
        let arch = detect_binary_arch(&data);
        assert_eq!(arch, BinaryArch::X86_64);
    }

    #[test]
    fn test_detect_binary_arch_x86_preamble() {
        let mut data = vec![0u8; 64];
        // Multiple function preambles → x86
        for i in (0..48).step_by(8) {
            data[i..i + 3].copy_from_slice(&[0x55, 0x89, 0xE5]);
        }
        let arch = detect_binary_arch(&data);
        assert_eq!(arch, BinaryArch::X86);
    }

    #[test]
    fn test_detect_raw_endian_arm() {
        assert_eq!(
            detect_raw_endian(BinaryArch::ArmAarch32),
            Some(Endian::Little)
        );
    }

    #[test]
    fn test_detect_raw_endian_mips_be() {
        assert_eq!(detect_raw_endian(BinaryArch::Mips32Be), Some(Endian::Big));
    }

    #[test]
    fn test_detect_raw_endian_unknown() {
        assert_eq!(detect_raw_endian(BinaryArch::Unknown), None);
    }

    #[test]
    fn test_binary_arch_display() {
        assert_eq!(BinaryArch::Aarch64.to_string(), "aarch64");
        assert_eq!(BinaryArch::X86_64.to_string(), "x86_64");
    }

    // ── UBootHeader ────────────────────────────────────────────────────────────

    fn make_uboot_header(load: u32, entry: u32, arch_byte: u8, name: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x2705_1956_u32.to_be_bytes());
        data[12..16].copy_from_slice(&1024_u32.to_be_bytes());
        data[16..20].copy_from_slice(&load.to_be_bytes());
        data[20..24].copy_from_slice(&entry.to_be_bytes());
        data[29] = arch_byte;
        let name_len = name.len().min(31);
        data[32..32 + name_len].copy_from_slice(&name[..name_len]);
        data
    }

    #[test]
    fn test_uboot_parse() {
        let data = make_uboot_header(0x8020_0000, 0x8020_0100, 2, b"router-fw");
        let hdr = UBootHeader::parse(&data).unwrap();
        assert_eq!(hdr.load_addr, 0x8020_0000);
        assert_eq!(hdr.entry_point, 0x8020_0100);
        assert_eq!(hdr.arch_str(), "arm");
        assert_eq!(hdr.name, "router-fw");
    }

    #[test]
    fn test_uboot_arch_codes() {
        let cases = [
            (2, "arm"),
            (3, "x86"),
            (4, "mips"),
            (22, "aarch64"),
            (26, "riscv"),
            (99, "unknown"),
        ];
        for (byte, expected) in cases {
            let data = make_uboot_header(0, 0, byte, b"");
            let hdr = UBootHeader::parse(&data).unwrap();
            assert_eq!(hdr.arch_str(), expected);
        }
    }

    #[test]
    fn test_uboot_too_short() {
        assert!(UBootHeader::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_uboot_wrong_magic() {
        assert!(UBootHeader::parse(&[0u8; 64]).is_none());
    }

    #[test]
    fn test_uboot_comp_str() {
        let data = make_uboot_header(0, 0, 2, b"");
        let mut hdr = UBootHeader::parse(&data).unwrap();
        hdr.comp_type = 1;
        assert_eq!(hdr.comp_str(), "gzip");
        hdr.comp_type = 2;
        assert_eq!(hdr.comp_str(), "bzip2");
        hdr.comp_type = 6;
        assert_eq!(hdr.comp_str(), "zstd");
    }

    #[test]
    fn test_uboot_image_type_str() {
        let data = make_uboot_header(0, 0, 2, b"");
        let mut hdr = UBootHeader::parse(&data).unwrap();
        hdr.image_type = 2;
        assert_eq!(hdr.image_type_str(), "kernel");
        hdr.image_type = 3;
        assert_eq!(hdr.image_type_str(), "ramdisk");
    }

    #[test]
    fn test_uboot_payload() {
        let mut data = make_uboot_header(0, 0, 2, b"");
        data[12..16].copy_from_slice(&8_u32.to_be_bytes()); // data_size = 8
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        let hdr = UBootHeader::parse(&data).unwrap();
        let payload = hdr.payload(&data).unwrap();
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_uboot_display() {
        let data = make_uboot_header(0x8000_0000, 0x8000_0000, 2, b"my-image");
        let hdr = UBootHeader::parse(&data).unwrap();
        assert!(hdr.to_string().contains("my-image"));
    }

    // ── Intel HEX ─────────────────────────────────────────────────────────────

    fn ihex_checksum(body: &[u8]) -> u8 {
        let sum: u32 = body.iter().map(|&b| b as u32).sum();
        ((0x100u32 - (sum & 0xFF)) & 0xFF) as u8
    }

    fn make_ihex_line(addr: u16, record_type: u8, data: &[u8]) -> Vec<u8> {
        let mut body = vec![
            data.len() as u8,
            (addr >> 8) as u8,
            (addr & 0xFF) as u8,
            record_type,
        ];
        body.extend_from_slice(data);
        let cs = ihex_checksum(&body);
        body.push(cs);
        let mut line = b":".to_vec();
        for b in &body {
            line.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        line
    }

    #[test]
    fn test_intel_hex_parse_data_record() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let line = make_ihex_line(0x0000, 0x00, &data);
        let record = IntelHexRecord::parse_line(&line).unwrap();
        assert_eq!(record.byte_count, 4);
        assert!(matches!(record.record_type, IntelHexRecordType::Data));
        assert_eq!(&record.data, &data);
    }

    #[test]
    fn test_intel_hex_eof_record() {
        let line = make_ihex_line(0x0000, 0x01, &[]);
        let record = IntelHexRecord::parse_line(&line).unwrap();
        assert!(matches!(record.record_type, IntelHexRecordType::EndOfFile));
    }

    #[test]
    fn test_intel_hex_extended_linear_address() {
        let line = make_ihex_line(0x0000, 0x04, &[0x08, 0x00]);
        let record = IntelHexRecord::parse_line(&line).unwrap();
        assert!(matches!(
            record.record_type,
            IntelHexRecordType::ExtendedLinearAddress
        ));
    }

    #[test]
    fn test_intel_hex_bad_checksum() {
        let mut line = make_ihex_line(0x0000, 0x00, &[0xDE, 0xAD]);
        let len = line.len();
        line[len - 2] = b'F';
        line[len - 1] = b'F';
        assert!(IntelHexRecord::parse_line(&line).is_err());
    }

    #[test]
    fn test_intel_hex_full_parse() {
        let mut hex = make_ihex_line(0x0000, 0x04, &[0x08, 0x00]);
        hex.extend_from_slice(b"\r\n");
        hex.extend_from_slice(&make_ihex_line(0x0000, 0x00, &[0x11, 0x22, 0x33, 0x44]));
        hex.extend_from_slice(b"\r\n");
        hex.extend_from_slice(&make_ihex_line(0x0000, 0x01, &[]));
        hex.extend_from_slice(b"\r\n");
        let image = IntelHexImage::parse(&hex).unwrap();
        assert!(!image.regions.is_empty());
        assert_eq!(image.regions[0].0, 0x0800_0000);
    }

    // ── SREC ──────────────────────────────────────────────────────────────────

    fn srec_checksum(body: &[u8]) -> u8 {
        let sum: u32 = body.iter().map(|&b| b as u32).sum();
        (!(sum & 0xFF)) as u8
    }

    fn make_srec_s1(addr: u16, data: &[u8]) -> Vec<u8> {
        let byte_count = 2 + data.len() + 1;
        let mut body = Vec::new();
        body.push(byte_count as u8);
        body.push((addr >> 8) as u8);
        body.push(addr as u8);
        body.extend_from_slice(data);
        let cs = srec_checksum(&body);
        body.push(cs);
        let mut line = b"S1".to_vec();
        for b in &body {
            line.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        line
    }

    fn make_srec_s9(addr: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(3u8);
        body.push((addr >> 8) as u8);
        body.push(addr as u8);
        let cs = srec_checksum(&body);
        body.push(cs);
        let mut line = b"S9".to_vec();
        for b in &body {
            line.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        line
    }

    #[test]
    fn test_srec_parse_s1_data() {
        let line = make_srec_s1(0x0000, &[0xAA, 0xBB, 0xCC]);
        let record = SrecRecord::parse_line(&line).unwrap();
        assert_eq!(record.record_type, '1');
        assert_eq!(&record.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_srec_image_parse() {
        let mut srec = make_srec_s1(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        srec.extend_from_slice(b"\r\n");
        srec.extend_from_slice(&make_srec_s9(0x1000));
        srec.extend_from_slice(b"\r\n");
        let image = SrecImage::parse(&srec).unwrap();
        assert!(!image.regions.is_empty());
        assert_eq!(image.entry_point, Some(0x1000));
    }

    // ── UF2 ───────────────────────────────────────────────────────────────────

    fn make_uf2_block(target_addr: u32, payload: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
        block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
        block[12..16].copy_from_slice(&target_addr.to_le_bytes());
        let size = payload.len().min(476) as u32;
        block[16..20].copy_from_slice(&size.to_le_bytes());
        block[24..28].copy_from_slice(&1u32.to_le_bytes());
        let plen = payload.len().min(476);
        block[32..32 + plen].copy_from_slice(&payload[..plen]);
        block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
        block
    }

    #[test]
    fn test_uf2_parse_single_block() {
        let block = make_uf2_block(0x0800_0000, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let record = Uf2Record::parse(&block).unwrap();
        assert_eq!(record.target_addr, 0x0800_0000);
        assert_eq!(record.payload_size, 4);
    }

    #[test]
    fn test_uf2_bad_magic() {
        assert!(Uf2Record::parse(&vec![0u8; 512]).is_err());
    }

    #[test]
    fn test_uf2_assemble() {
        let block = make_uf2_block(0x0800_0000, &[0x11, 0x22]);
        let records = Uf2Record::parse_all(&block).unwrap();
        let regions = Uf2Record::assemble(&records);
        assert_eq!(regions[0].0, 0x0800_0000);
    }

    // ── RTOS detection ────────────────────────────────────────────────────────

    #[test]
    fn test_detect_rtos_freertos() {
        assert_eq!(detect_rtos(b"Hello FreeRTOS"), Some(RtosKind::FreeRtos));
    }

    #[test]
    fn test_detect_rtos_vxworks() {
        assert_eq!(detect_rtos(b"VxWorks powered"), Some(RtosKind::VxWorks));
    }

    #[test]
    fn test_detect_rtos_none() {
        assert_eq!(detect_rtos(b"plain firmware"), None);
    }

    #[test]
    fn test_detect_rtos_zephyr() {
        assert_eq!(detect_rtos(b"Zephyr Project"), Some(RtosKind::Zephyr));
    }

    #[test]
    fn test_detect_rtos_nuttx() {
        assert_eq!(detect_rtos(b"NuttX embedded"), Some(RtosKind::Nuttx));
    }

    #[test]
    fn test_rtos_display() {
        assert_eq!(RtosKind::FreeRtos.to_string(), "FreeRTOS");
        assert_eq!(RtosKind::Zephyr.to_string(), "Zephyr");
    }

    // ── Architecture detection ─────────────────────────────────────────────────

    #[test]
    fn test_detect_arch_arm() {
        assert_eq!(detect_arch_hint(b"ARM Cortex-M4"), Some("arm".to_string()));
    }

    #[test]
    fn test_detect_arch_none() {
        assert_eq!(detect_arch_hint(b"no hints here"), None);
    }

    #[test]
    fn test_detect_arch_mips() {
        assert_eq!(
            detect_arch_hint(b"MIPS processor"),
            Some("mips".to_string())
        );
    }

    #[test]
    fn test_detect_arch_xtensa() {
        assert_eq!(
            detect_arch_hint(b"ESP32 module"),
            Some("xtensa".to_string())
        );
    }

    // ── String extraction ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_strings_basic() {
        let data = b"\x00\x00Hello World\x00\x00short\x00test_long_string\x00";
        let strings = extract_firmware_strings(data, 6);
        assert!(strings.iter().any(|s| s.text.contains("Hello World")));
    }

    #[test]
    fn test_extract_strings_min_len_filter() {
        let data = b"ab\x00abcdefgh\x00";
        let strings = extract_firmware_strings(data, 5);
        assert!(strings.iter().all(|s| s.text.len() >= 5));
    }

    #[test]
    fn test_string_category_url() {
        assert_eq!(
            classify_string("https://example.com/path"),
            StringCategory::Url
        );
    }

    #[test]
    fn test_string_category_path() {
        assert_eq!(
            classify_string("/etc/firmware/config"),
            StringCategory::Path
        );
    }

    #[test]
    fn test_string_category_ip() {
        assert_eq!(classify_string("192.168.1.1"), StringCategory::IpAddress);
    }

    #[test]
    fn test_string_category_version() {
        assert_eq!(classify_string("firmware version"), StringCategory::Version);
    }

    #[test]
    fn test_string_category_generic() {
        assert_eq!(classify_string("helloworld"), StringCategory::Generic);
    }

    #[test]
    fn test_string_category_display() {
        assert_eq!(StringCategory::Url.to_string(), "url");
        assert_eq!(StringCategory::Path.to_string(), "path");
    }

    // ── FirmwareInfo ──────────────────────────────────────────────────────────

    #[test]
    fn test_firmware_info_display() {
        let info = FirmwareInfo {
            kind: FirmwareKind::UBoot,
            base_address: 0x8020_0000,
            size: 2 * 1024 * 1024,
            arch_hint: Some("arm".to_string()),
            endian_hint: Some("little".to_string()),
            binary_arch: BinaryArch::ArmAarch32,
            rtos: Some(RtosKind::FreeRtos),
            strings: vec![],
            boot_sections: vec![],
            entropy: 5.5,
            embedded_signatures: vec![],
        };
        let s = info.to_string();
        assert!(s.contains("uboot-legacy"));
        assert!(s.contains("FreeRTOS"));
        assert!(s.contains("5.5") || s.contains("entropy"));
    }

    #[test]
    fn test_firmware_info_analyse_uboot() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x2705_1956_u32.to_be_bytes());
        data[29] = 2;
        let info = FirmwareInfo::analyse(&data, 0x8000_0000);
        assert_eq!(info.kind, FirmwareKind::UBoot);
    }

    // ── FirmwareLoader ────────────────────────────────────────────────────────

    #[test]
    fn test_firmware_loader_name() {
        assert_eq!(FirmwareLoader::new().name(), "firmware");
    }

    #[test]
    fn test_firmware_loader_can_load() {
        assert!(FirmwareLoader::new().can_load(&LoaderInput::new("fw.bin", vec![0xAA; 1024])));
    }

    #[test]
    fn test_firmware_loader_cannot_load_elf() {
        let data = b"\x7fELF\x00\x00\x00\x00".to_vec();
        assert!(!FirmwareLoader::new().can_load(&LoaderInput::new("fw.elf", data)));
    }

    #[test]
    fn test_firmware_loader_cannot_load_pe() {
        let data = b"MZ\x00\x00".to_vec();
        assert!(!FirmwareLoader::new().can_load(&LoaderInput::new("fw.exe", data)));
    }

    #[tokio::test]
    async fn test_firmware_loader_load() {
        let result = FirmwareLoader::new()
            .load(LoaderInput::new("fw.bin", vec![0xAA; 256]))
            .await
            .unwrap();
        assert_eq!(result.view.uri, "fw.bin");
    }

    #[tokio::test]
    async fn test_firmware_loader_uboot() {
        let mut data = make_uboot_header(0x8020_0000, 0x8020_0100, 2, b"test");
        data.extend_from_slice(&[0u8; 1024]);
        let result = FirmwareLoader::new()
            .load(LoaderInput::new("uimage.bin", data))
            .await
            .unwrap();
        assert_eq!(result.view.entry_points[0].as_u64(), 0x8020_0100);
    }

    // ── IntelHexLoader ────────────────────────────────────────────────────────

    #[test]
    fn test_ihex_loader_name() {
        assert_eq!(IntelHexLoader::new().name(), "intel-hex");
    }

    #[test]
    fn test_ihex_loader_can_load() {
        assert!(
            IntelHexLoader::new()
                .can_load(&LoaderInput::new("fw.hex", b":00000001FF\r\n".to_vec()))
        );
    }

    #[test]
    fn test_ihex_loader_cannot_load_binary() {
        assert!(!IntelHexLoader::new().can_load(&LoaderInput::new("fw.bin", vec![0xDE, 0xAD])));
    }

    // ── SrecLoader ────────────────────────────────────────────────────────────

    #[test]
    fn test_srec_loader_name() {
        assert_eq!(SrecLoader::new().name(), "srec");
    }

    #[test]
    fn test_srec_loader_can_load() {
        assert!(
            SrecLoader::new().can_load(&LoaderInput::new("fw.srec", b"S0030000FC\r\n".to_vec()))
        );
    }

    // ── Uf2Loader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_uf2_loader_name() {
        assert_eq!(Uf2Loader::new().name(), "uf2");
    }

    #[test]
    fn test_uf2_loader_can_load() {
        let block = make_uf2_block(0x0800_0000, &[0x11; 256]);
        assert!(Uf2Loader::new().can_load(&LoaderInput::new("fw.uf2", block)));
    }

    #[tokio::test]
    async fn test_uf2_loader_load() {
        let block = make_uf2_block(0x0800_0000, &[0x11; 256]);
        let result = Uf2Loader::new()
            .load(LoaderInput::new("fw.uf2", block))
            .await
            .unwrap();
        assert_eq!(result.view.entry_points[0].as_u64(), 0x0800_0000);
    }

    // ── FirmwareArch ──────────────────────────────────────────────────────────

    #[test]
    fn test_firmware_arch_name() {
        assert_eq!(FirmwareArch::new("arm".to_string()).name(), "arm");
    }

    #[test]
    fn firmware_arch_disassemble_admits_it_cannot_decode() {
        // The old body returned `nop` with length `bytes[0] % 4 + 1`: a size
        // that changes with the input, so successive calls produced a plausible
        // stream of variable-length instructions that meant nothing. An error
        // naming the architecture is the only answer this crate can support.
        let arch = FirmwareArch::new("thumb".to_string());
        let err = arch
            .disassemble(Address::new(0), &[0x12, 0x34, 0x56, 0x78])
            .expect_err("must not claim to have decoded anything");
        let text = err.to_string();
        assert!(
            text.contains("thumb"),
            "the error should name the architecture, got: {text}"
        );

        // A different first byte used to yield a different length; now both are
        // refused, so no caller can mistake one for a real decode.
        assert!(arch.disassemble(Address::new(0), &[0x03]).is_err());
        assert!(arch.disassemble(Address::new(0), &[]).is_err());
    }

    #[test]
    fn test_firmware_arch_ptr_size() {
        assert_eq!(
            FirmwareArch::with_params("arm".to_string(), 4, Endian::Little).pointer_size(),
            4
        );
    }

    #[test]
    fn test_firmware_arch_endian() {
        assert_eq!(
            FirmwareArch::with_params("mips".to_string(), 4, Endian::Big).endian(),
            Endian::Big
        );
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_truncated() {
        assert!(
            FirmwareError::TruncatedData
                .to_string()
                .contains("truncated")
        );
    }

    #[test]
    fn test_error_invalid_magic() {
        assert!(
            FirmwareError::InvalidMagic("test".into())
                .to_string()
                .contains("test")
        );
    }

    #[test]
    fn test_error_checksum() {
        let e = FirmwareError::ChecksumMismatch {
            expected: 0xAA,
            actual: 0xBB,
        };
        assert!(e.to_string().contains("mismatch"));
    }

    #[test]
    fn test_error_unknown_record() {
        assert!(
            FirmwareError::UnknownRecord(0xFF)
                .to_string()
                .contains("record")
        );
    }

    #[test]
    fn test_error_address_overflow() {
        assert!(
            FirmwareError::AddressOverflow(42)
                .to_string()
                .contains("overflow")
        );
    }
}
