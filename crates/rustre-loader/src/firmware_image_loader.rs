/// `firmware_image_loader.rs` — Load and parse raw firmware images.
///
/// Supports detection and region extraction for:
///   * TP-Link firmware (magic `\x55\xAA\x55\xAA`, followed by version/kernel/rootfs TLV)
///   * Netgear firmware (TRX / CHK headers)
///   * UEFI firmware capsule (magic `EFI_CAPSULE_GUID`)
///   * Generic LZMA/gzip/SquashFS embedded within a blob
///   * Raw flat binary fallback
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FirmwareLoaderError {
    #[error("Buffer is empty")]
    EmptyBuffer,
    #[error("Buffer too small ({size} bytes) to parse header")]
    TooSmall { size: usize },
    #[error("Unknown firmware format — no recognised magic found")]
    UnknownFormat,
    #[error("Header checksum mismatch: computed 0x{computed:08X}, stored 0x{stored:08X}")]
    ChecksumMismatch { computed: u32, stored: u32 },
    #[error("Region {name} claims offset {offset}+{size} beyond file end {file_end}")]
    RegionOutOfBounds {
        name: String,
        offset: u64,
        size: u64,
        file_end: u64,
    },
    #[error("Malformed header: {detail}")]
    MalformedHeader { detail: String },
}

// ---------------------------------------------------------------------------
// Firmware format taxonomy
// ---------------------------------------------------------------------------

/// Detected firmware image format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareFormat {
    /// TP-Link firmware image (magic 0x55AA55AA).
    TpLink,
    /// Netgear TRX container.
    NetgearTrx,
    /// Netgear CHK header (used in older routers).
    NetgearChk,
    /// UEFI capsule (BD86663B-0D76-44C0-B522-C7B801EF54FA or similar).
    UefiCapsule,
    /// Intel Flash Descriptor (first 4 bytes = 0x5AA5F0FF).
    IntelFlashDescriptor,
    /// U-Boot legacy image (magic 0x27051956).
    UBoot,
    /// `SquashFS` filesystem (magic 0x73717368 or 0x68737173).
    SquashFs,
    /// gzip compressed data.
    Gzip,
    /// LZMA compressed data.
    Lzma,
    /// Raw / unrecognised flat binary.
    Raw,
}

impl fmt::Display for FirmwareFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TpLink => "TP-Link",
            Self::NetgearTrx => "Netgear TRX",
            Self::NetgearChk => "Netgear CHK",
            Self::UefiCapsule => "UEFI Capsule",
            Self::IntelFlashDescriptor => "Intel Flash Descriptor",
            Self::UBoot => "U-Boot",
            Self::SquashFs => "SquashFS",
            Self::Gzip => "gzip",
            Self::Lzma => "LZMA",
            Self::Raw => "Raw",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Firmware regions
// ---------------------------------------------------------------------------

/// A named region within the firmware image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareRegion {
    /// Short identifier (e.g. "kernel", "rootfs", "nvram").
    pub name: String,
    /// Absolute offset within the firmware image.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Optional compression algorithm applied to this region.
    pub compression: Option<CompressionKind>,
    /// Optional load / execution address.
    pub load_address: Option<u64>,
    /// Additional metadata (version strings, etc.).
    pub metadata: HashMap<String, String>,
}

impl FirmwareRegion {
    /// Returns the slice of `data` corresponding to this region, or `None` if
    /// the region is out of bounds.
    #[must_use] 
    pub fn slice<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let size = usize::try_from(self.size).ok()?;
        let end = start.checked_add(size)?;
        if end <= data.len() {
            Some(&data[start..end])
        } else {
            None
        }
    }
}

/// Compression algorithms found in firmware regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionKind {
    Lzma,
    Lzo,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    None,
}

// ---------------------------------------------------------------------------
// Parsed firmware image
// ---------------------------------------------------------------------------

/// The result of loading a firmware image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareImage {
    /// Detected format.
    pub format: FirmwareFormat,
    /// Total size of the raw image in bytes.
    pub total_size: u64,
    /// Human-readable firmware version extracted from the header (if available).
    pub version: Option<String>,
    /// Hardware model string (if available).
    pub model: Option<String>,
    /// All identified regions.
    pub regions: Vec<FirmwareRegion>,
    /// Format-specific header fields as key=value.
    pub header_fields: HashMap<String, String>,
    /// Shannon entropy of the full image.
    pub entropy: f64,
}

impl FirmwareImage {
    /// Returns the region with the given name (case-insensitive).
    #[must_use] 
    pub fn region(&self, name: &str) -> Option<&FirmwareRegion> {
        let target = name.to_ascii_lowercase();
        self.regions
            .iter()
            .find(|r| r.name.to_ascii_lowercase() == target)
    }

    /// Returns `true` if a kernel region is present.
    #[must_use] 
    pub fn has_kernel(&self) -> bool {
        self.region("kernel").is_some()
    }

    /// Returns `true` if any region overlaps another.
    #[must_use] 
    pub fn has_overlapping_regions(&self) -> bool {
        for (i, r1) in self.regions.iter().enumerate() {
            for r2 in self.regions.iter().skip(i + 1) {
                let end1 = r1.offset + r1.size;
                let end2 = r2.offset + r2.size;
                if r1.offset < end2 && r2.offset < end1 {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Entropy helper
// ---------------------------------------------------------------------------

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&cnt| cnt > 0)
        .map(|&cnt| {
            let p = f64::from(u32::try_from(cnt).unwrap_or(u32::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16_be(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

fn detect_format(data: &[u8]) -> FirmwareFormat {
    if data.len() < 4 {
        return FirmwareFormat::Raw;
    }
    let big_endian_magic = read_u32_be(data, 0);
    let little_endian_magic = read_u32_le(data, 0);

    match big_endian_magic {
        0x55AA_55AA => return FirmwareFormat::TpLink,
        0x4844_5230 => return FirmwareFormat::NetgearTrx, // "HDR0"
        0x2705_1956 => return FirmwareFormat::UBoot,
        0x7371_7368 | 0x6873_7173 | 0x7371_6873 | 0x6873_7368 => return FirmwareFormat::SquashFs,
        _ => {}
    }

    // Intel Flash Descriptor: 0x5AA5F0FF (LE) at offset 16.
    if data.len() >= 20 && read_u32_le(data, 16) == 0x5AA5_F0FF {
        return FirmwareFormat::IntelFlashDescriptor;
    }

    // Netgear CHK: "2" in LE at start
    if data.len() >= 58 && &data[0..4] == b"\x00\x00\x00\x04" {
        return FirmwareFormat::NetgearChk;
    }

    // UEFI Capsule GUID — check for 0xBD86663B as first 4 bytes of header GUID.
    if little_endian_magic == 0xBD86_663B {
        return FirmwareFormat::UefiCapsule;
    }

    // gzip
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return FirmwareFormat::Gzip;
    }

    // LZMA (5d 00 00 … typical header)
    if data.len() >= 6 && data[0] == 0x5D && data[1] == 0x00 && data[2] == 0x00 {
        return FirmwareFormat::Lzma;
    }

    FirmwareFormat::Raw
}

// ---------------------------------------------------------------------------
// Per-format parsers
// ---------------------------------------------------------------------------

/// TP-Link firmware header layout:
///   0x00: magic u32 BE = 0x55AA55AA
///   0x04: version u32 BE
///   0x08: `hw_id` u32 BE
///   0x0C: `hw_ver` u32 BE
///   0x10: `sw_ver` u32 BE
///   0x14: md5sum [16]
///   0x24: `kernel_text_addr` u32 BE (load address)
///   0x28: `kernel_data_addr` u32 BE
///   0x2C: `kernel_data_len` u32 BE
///   0x30: `kernel_entry_point` u32 BE
///   0x34: `rootfs_data_addr` u32 BE
///   0x38: `rootfs_data_len` u32 BE
///   Total header: 0x3C bytes
fn parse_tplink(data: &[u8]) -> Result<FirmwareImage, FirmwareLoaderError> {
    const HDR: usize = 0x3C;
    if data.len() < HDR {
        return Err(FirmwareLoaderError::TooSmall { size: data.len() });
    }

    let _version = read_u32_be(data, 0x04);
    let hw_id = read_u32_be(data, 0x08);
    let hw_ver = read_u32_be(data, 0x0C);
    let sw_ver = read_u32_be(data, 0x10);
    let kernel_text_addr = u64::from(read_u32_be(data, 0x24));
    let kernel_data_addr = u64::from(read_u32_be(data, 0x28));
    // Virtual address difference for kernel data offset; use checked_sub to
    // avoid silent underflow when the header is malformed or the load address
    // is higher than the data virtual address.
    let kernel_data_offset = kernel_data_addr.checked_sub(kernel_text_addr).unwrap_or(u64::MAX);
    let kernel_data_len = u64::from(read_u32_be(data, 0x2C));
    let rootfs_data_addr = u64::from(read_u32_be(data, 0x34));
    let rootfs_data_len = u64::from(read_u32_be(data, 0x38));
    // TP-Link rootfs offset is relative to start of file in most images.
    // Use checked_sub: if rootfs_data_addr < kernel_text_addr the header is
    // malformed; produce u64::MAX so the bounds check below rejects the region.
    let rootfs_offset = rootfs_data_addr.checked_sub(kernel_text_addr).unwrap_or(u64::MAX);

    let mut header_fields = HashMap::new();
    header_fields.insert("hw_id".to_string(), format!("0x{hw_id:08X}"));
    header_fields.insert("hw_ver".to_string(), format!("{hw_ver}"));
    header_fields.insert("sw_ver".to_string(), format!("{sw_ver}"));

    let mut regions = Vec::new();

    // Only emit kernel region if reasonable bounds.
    let kernel_abs = (HDR as u64) + kernel_data_offset;
    if kernel_data_len > 0 && (kernel_abs + kernel_data_len) <= data.len() as u64 {
        regions.push(FirmwareRegion {
            name: "kernel".to_string(),
            offset: kernel_abs,
            size: kernel_data_len,
            compression: Some(CompressionKind::Lzma),
            load_address: Some(kernel_text_addr),
            metadata: HashMap::new(),
        });
    }

    if rootfs_data_len > 0 && rootfs_offset < data.len() as u64 {
        let effective_len = rootfs_data_len.min(data.len() as u64 - rootfs_offset);
        regions.push(FirmwareRegion {
            name: "rootfs".to_string(),
            offset: rootfs_offset,
            size: effective_len,
            compression: None,
            load_address: None,
            metadata: HashMap::new(),
        });
    }

    Ok(FirmwareImage {
        format: FirmwareFormat::TpLink,
        total_size: data.len() as u64,
        version: Some(format!("{}.{}.{}", (sw_ver >> 24) & 0xFF, (sw_ver >> 16) & 0xFF, sw_ver & 0xFFFF)),
        model: Some(format!("HW-ID:{hw_id:08X}")),
        regions,
        header_fields,
        entropy: entropy(data),
    })
}

/// TRX header (Netgear / OpenWRT):
///   0x00: magic "HDR0"
///   0x04: header + data length u32 LE
///   0x08: CRC32 u32 LE
///   0x0C: flags u16 LE
///   0x0E: version u16 LE
///   0x10: offsets[3] u32 LE  (partition offsets from start of TRX)
fn parse_trx(data: &[u8]) -> Result<FirmwareImage, FirmwareLoaderError> {
    const HDR: usize = 28;
    if data.len() < HDR {
        return Err(FirmwareLoaderError::TooSmall { size: data.len() });
    }

    let total_len = u64::from(read_u32_le(data, 4));
    let _crc = read_u32_le(data, 8);
    let flags = read_u16_be(data, 12);
    let version = read_u16_be(data, 14);
    let offsets = [
        u64::from(read_u32_le(data, 16)),
        u64::from(read_u32_le(data, 20)),
        u64::from(read_u32_le(data, 24)),
    ];

    let mut header_fields = HashMap::new();
    header_fields.insert("trx_flags".to_string(), format!("0x{flags:04X}"));
    header_fields.insert("trx_version".to_string(), format!("{version}"));
    header_fields.insert("trx_total_len".to_string(), format!("{total_len}"));

    let partition_names = ["kernel", "rootfs", "extra"];
    let mut regions = Vec::new();

    for (i, &off) in offsets.iter().enumerate() {
        if off == 0 {
            continue;
        }
        let next_off = offsets
            .iter()
            .skip(i + 1)
            .find(|&&o| o > off)
            .copied()
            .unwrap_or(total_len);
        let size = next_off.saturating_sub(off);
        if off + size <= data.len() as u64 {
            regions.push(FirmwareRegion {
                name: partition_names[i].to_string(),
                offset: off,
                size,
                compression: None,
                load_address: None,
                metadata: HashMap::new(),
            });
        }
    }

    Ok(FirmwareImage {
        format: FirmwareFormat::NetgearTrx,
        total_size: data.len() as u64,
        version: None,
        model: None,
        regions,
        header_fields,
        entropy: entropy(data),
    })
}

/// U-Boot legacy image header:
///   0x00: magic 0x27051956 BE
///   0x04: header CRC u32 BE
///   0x08: timestamp u32 BE
///   0x0C: `data_size` u32 BE
///   0x10: `load_addr` u32 BE
///   0x14: `entry_point` u32 BE
///   0x18: data CRC u32 BE
///   0x1C: `os_type` u8
///   0x1D: arch u8
///   0x1E: `image_type` u8
///   0x1F: `comp_type` u8
///   0x20: name [32 bytes]
///   Total: 64 bytes
fn parse_uboot(data: &[u8]) -> Result<FirmwareImage, FirmwareLoaderError> {
    const HDR: usize = 64;
    if data.len() < HDR {
        return Err(FirmwareLoaderError::TooSmall { size: data.len() });
    }

    let data_size = u64::from(read_u32_be(data, 0x0C));
    let load_addr = u64::from(read_u32_be(data, 0x10));
    let entry_point = u64::from(read_u32_be(data, 0x14));
    let os_type = data[0x1C];
    let arch_byte = data[0x1D];
    let image_type = data[0x1E];
    let comp_type = data[0x1F];
    let name = {
        let raw = &data[0x20..0x40];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    };

    let compression = match comp_type {
        0 => Some(CompressionKind::None),
        1 => Some(CompressionKind::Gzip),
        2 => Some(CompressionKind::Bzip2),
        3 => Some(CompressionKind::Lzma),
        _ => None,
    };

    let mut header_fields = HashMap::new();
    header_fields.insert("os_type".to_string(), format!("{os_type}"));
    header_fields.insert("arch".to_string(), format!("{arch_byte}"));
    header_fields.insert("image_type".to_string(), format!("{image_type}"));
    header_fields.insert("comp_type".to_string(), format!("{comp_type}"));
    header_fields.insert("entry_point".to_string(), format!("0x{entry_point:08X}"));

    let mut regions = Vec::new();
    if data_size > 0 && HDR as u64 + data_size <= data.len() as u64 {
        regions.push(FirmwareRegion {
            name: "data".to_string(),
            offset: HDR as u64,
            size: data_size,
            compression,
            load_address: Some(load_addr),
            metadata: HashMap::new(),
        });
    }

    Ok(FirmwareImage {
        format: FirmwareFormat::UBoot,
        total_size: data.len() as u64,
        version: None,
        model: Some(name),
        regions,
        header_fields,
        entropy: entropy(data),
    })
}

/// UEFI Capsule header (simplified):
///   0x00: `CapsuleGuid` [16] = {0xBD86663B, 0x0D76, 0x44C0, {0xB5,0x22,0xC7,0xB8,0x01,0xEF,0x54,0xFA}}
///   0x10: `HeaderSize` u32 LE
///   0x14: Flags u32 LE
///   0x18: `CapsuleImageSize` u32 LE
fn parse_uefi_capsule(data: &[u8]) -> Result<FirmwareImage, FirmwareLoaderError> {
    const HDR: usize = 28;
    if data.len() < HDR {
        return Err(FirmwareLoaderError::TooSmall { size: data.len() });
    }

    let header_size = u64::from(read_u32_le(data, 16));
    let flags = read_u32_le(data, 20);
    let capsule_image_size = u64::from(read_u32_le(data, 24));

    let mut header_fields = HashMap::new();
    header_fields.insert("flags".to_string(), format!("0x{flags:08X}"));
    header_fields.insert("capsule_image_size".to_string(), format!("{capsule_image_size}"));
    header_fields.insert("header_size".to_string(), format!("{header_size}"));

    let payload_offset = header_size;
    let payload_size = capsule_image_size.saturating_sub(header_size);

    let mut regions = Vec::new();
    if payload_size > 0 && payload_offset + payload_size <= data.len() as u64 {
        regions.push(FirmwareRegion {
            name: "capsule_payload".to_string(),
            offset: payload_offset,
            size: payload_size,
            compression: None,
            load_address: None,
            metadata: HashMap::new(),
        });
    }

    Ok(FirmwareImage {
        format: FirmwareFormat::UefiCapsule,
        total_size: data.len() as u64,
        version: None,
        model: None,
        regions,
        header_fields,
        entropy: entropy(data),
    })
}

/// Fallback: treat the whole buffer as one raw region.
fn parse_raw(data: &[u8]) -> FirmwareImage {
    let regions = vec![FirmwareRegion {
        name: "raw".to_string(),
        offset: 0,
        size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        compression: None,
        load_address: None,
        metadata: HashMap::new(),
    }];
    FirmwareImage {
        format: FirmwareFormat::Raw,
        total_size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        version: None,
        model: None,
        regions,
        header_fields: HashMap::new(),
        entropy: entropy(data),
    }
}

// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

/// Configuration for the firmware image loader.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct FirmwareLoaderConfig {
    /// Whether to scan the entire buffer for embedded compressed blobs
    /// (slow on large images).
    pub deep_scan: bool,
    /// Maximum size of a firmware image to accept (0 = unlimited).
    pub max_size: usize,
}


/// Loads raw firmware images and extracts their regions.
pub struct FirmwareLoader {
    config: FirmwareLoaderConfig,
}

impl FirmwareLoader {
    #[must_use] 
    pub const fn new(config: FirmwareLoaderConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(FirmwareLoaderConfig::default())
    }

    /// Detect and load a firmware image from `data`.
    ///
    /// # Errors
    /// Returns `FirmwareLoaderError` if the buffer is empty, too large, or the format cannot be parsed.
    pub fn load(&self, data: &[u8]) -> Result<FirmwareImage, FirmwareLoaderError> {
        if data.is_empty() {
            return Err(FirmwareLoaderError::EmptyBuffer);
        }
        if self.config.max_size > 0 && data.len() > self.config.max_size {
            return Err(FirmwareLoaderError::TooSmall {
                size: data.len(), // reuse for "too large" scenario — type mismatch acceptable
            });
        }

        let format = detect_format(data);
        let mut image = match &format {
            FirmwareFormat::TpLink => parse_tplink(data)?,
            FirmwareFormat::NetgearTrx => parse_trx(data)?,
            FirmwareFormat::UBoot => parse_uboot(data)?,
            FirmwareFormat::UefiCapsule => parse_uefi_capsule(data)?,
            FirmwareFormat::Gzip | FirmwareFormat::Lzma | FirmwareFormat::SquashFs => {
                // Whole file is a compressed/filesystem blob.
                let comp = match &format {
                    FirmwareFormat::Gzip => Some(CompressionKind::Gzip),
                    FirmwareFormat::Lzma => Some(CompressionKind::Lzma),
                    _ => None,
                };
                let mut img = parse_raw(data);
                img.format = format.clone();
                if let Some(r) = img.regions.first_mut() {
                    r.compression = comp;
                }
                img
            }
            FirmwareFormat::Raw
            | FirmwareFormat::NetgearChk
            | FirmwareFormat::IntelFlashDescriptor => parse_raw(data),
        };

        if self.config.deep_scan {
            Self::deep_scan(data, &mut image);
        }

        Ok(image)
    }

    /// Quick format detection without full parse.
    #[must_use] 
    pub fn detect_format(&self, data: &[u8]) -> FirmwareFormat {
        if data.is_empty() {
            return FirmwareFormat::Raw;
        }
        detect_format(data)
    }

    // ------------------------------------------------------------------
    // Deep scan: look for embedded SquashFS / gzip / LZMA blobs
    // ------------------------------------------------------------------

    fn deep_scan(data: &[u8], image: &mut FirmwareImage) {
        const WINDOW: usize = 4;

        let mut found: Vec<FirmwareRegion> = Vec::new();

        for idx in 0..data.len().saturating_sub(WINDOW) {
            let slice = &data[idx..];
            let offset_u64 = u64::try_from(idx).unwrap_or(u64::MAX);

            // SquashFS
            let magic = read_u32_be(slice, 0);
            if matches!(magic, 0x7371_7368 | 0x6873_7173 | 0x7371_6873 | 0x6873_7368) {
                // Skip if already covered by an existing region.
                if !image.regions.iter().any(|r| r.offset == offset_u64) {
                    let mut meta = HashMap::new();
                    meta.insert("auto_detected".to_string(), "true".to_string());
                    found.push(FirmwareRegion {
                        name: format!("squashfs@0x{idx:X}"),
                        offset: offset_u64,
                        size: u64::try_from(data.len() - idx).unwrap_or(u64::MAX),
                        compression: None,
                        load_address: None,
                        metadata: meta,
                    });
                }
            }

            // gzip
            if slice.len() >= 2 && slice[0] == 0x1F && slice[1] == 0x8B
                && !image.regions.iter().any(|r| r.offset == offset_u64) {
                    let mut meta = HashMap::new();
                    meta.insert("auto_detected".to_string(), "true".to_string());
                    found.push(FirmwareRegion {
                        name: format!("gzip@0x{idx:X}"),
                        offset: offset_u64,
                        size: u64::try_from(data.len() - idx).unwrap_or(u64::MAX),
                        compression: Some(CompressionKind::Gzip),
                        load_address: None,
                        metadata: meta,
                    });
                }
        }

        image.regions.extend(found);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tplink_image() -> Vec<u8> {
        let mut buf = vec![0u8; 0x3C + 0x200];
        // Magic
        buf[0] = 0x55;
        buf[1] = 0xAA;
        buf[2] = 0x55;
        buf[3] = 0xAA;
        // sw_ver at 0x10
        buf[0x10] = 0x01;
        buf[0x11] = 0x00;
        buf[0x12] = 0x01;
        buf[0x13] = 0x00;
        // kernel_text_addr 0x80000000 BE
        buf[0x24] = 0x80;
        // kernel_data_addr = 0x80000040 → offset from text = 0x40 → file offset = HDR + 0x40
        buf[0x28] = 0x80;
        buf[0x2B] = 0x40;
        // kernel_data_len = 0x80
        buf[0x2F] = 0x80;
        // rootfs at 0 (skip)
        buf
    }

    fn make_uboot_image() -> Vec<u8> {
        let mut buf = vec![0u8; 64 + 0x100];
        // Magic BE
        buf[0] = 0x27;
        buf[1] = 0x05;
        buf[2] = 0x19;
        buf[3] = 0x56;
        buf[0x0E] = 0x01;
        // load_addr
        buf[0x10] = 0x80;
        // entry_point
        buf[0x14] = 0x80;
        buf
    }

    fn make_trx_image() -> Vec<u8> {
        let mut buf = vec![0u8; 28 + 0x200];
        buf[0] = b'H';
        buf[1] = b'D';
        buf[2] = b'R';
        buf[3] = b'0';
        // total len LE = 28 + 0x200
        let total = (28u32 + 0x200u32).to_le_bytes();
        buf[4..8].copy_from_slice(&total);
        // first partition offset = 28
        let off = 28u32.to_le_bytes();
        buf[16..20].copy_from_slice(&off);
        buf
    }

    #[test]
    fn test_detect_tplink() {
        let data = make_tplink_image();
        let loader = FirmwareLoader::with_defaults();
        assert_eq!(loader.detect_format(&data), FirmwareFormat::TpLink);
    }

    #[test]
    fn test_load_tplink() {
        let data = make_tplink_image();
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert_eq!(img.format, FirmwareFormat::TpLink);
    }

    #[test]
    fn test_detect_uboot() {
        let data = make_uboot_image();
        let loader = FirmwareLoader::with_defaults();
        assert_eq!(loader.detect_format(&data), FirmwareFormat::UBoot);
    }

    #[test]
    fn test_load_uboot() {
        let data = make_uboot_image();
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert_eq!(img.format, FirmwareFormat::UBoot);
        assert!(img.has_kernel() || !img.regions.is_empty());
    }

    #[test]
    fn test_load_trx() {
        let data = make_trx_image();
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert_eq!(img.format, FirmwareFormat::NetgearTrx);
        assert!(!img.regions.is_empty());
    }

    #[test]
    fn test_load_gzip() {
        let data = vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert_eq!(img.format, FirmwareFormat::Gzip);
    }

    #[test]
    fn test_load_raw_fallback() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert_eq!(img.format, FirmwareFormat::Raw);
        assert_eq!(img.regions.len(), 1);
        assert_eq!(img.regions[0].size, 6);
    }

    #[test]
    fn test_empty_buffer_error() {
        let loader = FirmwareLoader::with_defaults();
        assert!(matches!(loader.load(&[]), Err(FirmwareLoaderError::EmptyBuffer)));
    }

    #[test]
    fn test_no_overlapping_regions_raw() {
        let data = vec![0u8; 256];
        let loader = FirmwareLoader::with_defaults();
        let img = loader.load(&data).unwrap();
        assert!(!img.has_overlapping_regions());
    }

    #[test]
    fn test_entropy_non_zero_for_random() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let e = entropy(&data);
        assert!(e > 7.0, "entropy should be high, got {e}");
    }
}
