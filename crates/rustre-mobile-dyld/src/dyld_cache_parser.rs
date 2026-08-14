//! dyld shared cache parser: cache header, mapping info, images list,
//! accelerate info; extract individual Mach-O images.
//!
//! The `dyld_shared_cache` format combines all system dylibs into a single
//! memory-mapped file so they share TEXT pages across processes.  This module
//! handles the full on-disk format from iOS 6 / macOS 10.9 through
//! iOS 16 / macOS 13, including split sub-cache files.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ── Magic / constants ─────────────────────────────────────────────────────────

/// All known `dyld_shared_cache` magic strings.
pub const DYLD_CACHE_MAGIC_STRINGS: &[&str] = &[
    "dyld_v1    i386",
    "dyld_v1  x86_64",
    "dyld_v1 x86_64h",
    "dyld_v1   armv6",
    "dyld_v1   armv7",
    "dyld_v1  armv7f",
    "dyld_v1  armv7s",
    "dyld_v1  armv7k",
    "dyld_v1   arm64",
    "dyld_v1  arm64e",
    "dyld_v1arm64_32",
];

/// Minimum number of bytes required to read the legacy header.
pub const DYLD_CACHE_HEADER_MIN_SIZE: usize = 0x100;

// ── Architecture ──────────────────────────────────────────────────────────────

/// Instruction set detected from the magic string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CacheArch {
    I386,
    X86_64,
    X86_64h,
    ArmV6,
    ArmV7,
    ArmV7f,
    ArmV7s,
    ArmV7k,
    Arm64,
    Arm64e,
    Arm64_32,
    Unknown,
}

impl CacheArch {
    /// Detect from the magic string.
    #[must_use]
    pub fn from_magic(magic: &str) -> Self {
        if magic.contains("x86_64h") {
            return Self::X86_64h;
        }
        if magic.contains("x86_64") {
            return Self::X86_64;
        }
        if magic.contains("i386") {
            return Self::I386;
        }
        if magic.contains("arm64e") {
            return Self::Arm64e;
        }
        if magic.contains("arm64_32") {
            return Self::Arm64_32;
        }
        if magic.contains("arm64") {
            return Self::Arm64;
        }
        if magic.contains("armv7k") {
            return Self::ArmV7k;
        }
        if magic.contains("armv7s") {
            return Self::ArmV7s;
        }
        if magic.contains("armv7f") {
            return Self::ArmV7f;
        }
        if magic.contains("armv7") {
            return Self::ArmV7;
        }
        if magic.contains("armv6") {
            return Self::ArmV6;
        }
        Self::Unknown
    }

    /// Returns `true` for 64-bit architectures.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::X86_64 | Self::X86_64h | Self::Arm64 | Self::Arm64e)
    }

    /// Pointer size in bytes.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        if self.is_64bit() { 8 } else { 4 }
    }
}

impl fmt::Display for CacheArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::I386 => "i386",
            Self::X86_64 => "x86_64",
            Self::X86_64h => "x86_64h",
            Self::ArmV6 => "armv6",
            Self::ArmV7 => "armv7",
            Self::ArmV7f => "armv7f",
            Self::ArmV7s => "armv7s",
            Self::ArmV7k => "armv7k",
            Self::Arm64 => "arm64",
            Self::Arm64e => "arm64e",
            Self::Arm64_32 => "arm64_32",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ── CacheMappingInfo ──────────────────────────────────────────────────────────

/// One `dyld_cache_mapping_info` entry (32 bytes on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMappingInfo {
    /// Preferred VM start address.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// File offset of the data.
    pub file_offset: u64,
    /// Maximum VM protection.
    pub max_prot: u32,
    /// Initial VM protection.
    pub init_prot: u32,
}

impl CacheMappingInfo {
    /// On-disk entry size in bytes.
    pub const ENTRY_SIZE: usize = 32;

    /// Parse from 32 bytes.
    ///
    /// # Errors
    /// Returns an error if the slice is too short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::ENTRY_SIZE {
            bail!("CacheMappingInfo: slice too short ({} < {})", data.len(), Self::ENTRY_SIZE);
        }
        Ok(Self {
            address:     u64::from_le_bytes(data[0..8].try_into()?),
            size:        u64::from_le_bytes(data[8..16].try_into()?),
            file_offset: u64::from_le_bytes(data[16..24].try_into()?),
            max_prot:    u32::from_le_bytes(data[24..28].try_into()?),
            init_prot:   u32::from_le_bytes(data[28..32].try_into()?),
        })
    }

    /// Returns `true` if `va` falls within this mapping.
    #[must_use]
    pub const fn contains(&self, va: u64) -> bool {
        va >= self.address && va < self.address.saturating_add(self.size)
    }

    /// Translate `va` to a file offset, or `None` if not covered.
    #[must_use]
    pub const fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if !self.contains(va) {
            return None;
        }
        Some(self.file_offset + (va - self.address))
    }

    /// Human-readable protection string (`"r-x"`, `"rw-"`, …).
    #[must_use]
    pub fn prot_string(&self) -> String {
        let r = if self.init_prot & 1 != 0 { 'r' } else { '-' };
        let w = if self.init_prot & 2 != 0 { 'w' } else { '-' };
        let x = if self.init_prot & 4 != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }

    /// Returns `true` if the mapping is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.init_prot & 4 != 0
    }
}

impl fmt::Display for CacheMappingInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mapping va={:#018x} size={:#018x} file={:#018x} {}",
            self.address, self.size, self.file_offset, self.prot_string()
        )
    }
}

// ── CacheImageInfo ────────────────────────────────────────────────────────────

/// One `dyld_cache_image_info` entry (32 bytes on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheImageInfo {
    /// Load address of the Mach-O header.
    pub address: u64,
    /// Modification time from the host build machine.
    pub mod_time: u64,
    /// Inode from the host build machine.
    pub inode: u64,
    /// File offset of the NUL-terminated path string.
    pub path_file_offset: u32,
    /// Reserved / padding.
    pub pad: u32,
    /// Decoded path (e.g. `/usr/lib/libSystem.B.dylib`).
    pub path: String,
}

impl CacheImageInfo {
    /// On-disk entry size in bytes.
    pub const ENTRY_SIZE: usize = 32;

    /// Parse from 32 bytes + full cache buffer for path decoding.
    ///
    /// # Errors
    /// Returns an error if the slice is too short.
    pub fn parse(entry: &[u8], all_data: &[u8]) -> Result<Self> {
        if entry.len() < Self::ENTRY_SIZE {
            bail!("CacheImageInfo: entry too short");
        }
        let address    = u64::from_le_bytes(entry[0..8].try_into()?);
        let mod_time   = u64::from_le_bytes(entry[8..16].try_into()?);
        let inode      = u64::from_le_bytes(entry[16..24].try_into()?);
        let path_file_offset = u32::from_le_bytes(entry[24..28].try_into()?);
        let pad        = u32::from_le_bytes(entry[28..32].try_into()?);

        let path = read_cstring(all_data, path_file_offset as usize);

        Ok(Self { address, mod_time, inode, path_file_offset, pad, path })
    }

    /// Returns the filename component of the path.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Returns `true` if this is a system framework or dylib.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.path.starts_with("/usr/lib/")
            || self.path.starts_with("/System/Library/")
            || self.path.starts_with("/System/PrivateFrameworks/")
    }

    /// Returns the framework name if this is a `.framework` dylib.
    #[must_use]
    pub fn framework_name(&self) -> Option<&str> {
        let idx = self.path.find(".framework/")?;
        let start = self.path[..idx].rfind('/')? + 1;
        Some(&self.path[start..idx])
    }
}

// ── AccelerateInfo ────────────────────────────────────────────────────────────

/// Accelerate info tables for fast symbol lookup (pre-computed by dyld).
///
/// These tables exist at `dyld_cache_accelerator_info` within the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccelerateInfo {
    /// VA of the accelerate info structure.
    pub va: u64,
    /// Number of image extras.
    pub image_extras_count: u32,
    /// Number of bottom-up ordered images.
    pub bottom_up_count: u32,
    /// Number of ranges in the range table.
    pub range_table_count: u32,
    /// Total export trie size across all images.
    pub exports_trie_addr: u64,
    /// Size of the exports trie region.
    pub exports_trie_size: u32,
    /// List of fast-linked symbol names from the accelerator.
    pub symbol_names: Vec<String>,
}

impl AccelerateInfo {
    /// Parse an accelerate info block from `data` at the file offset corresponding to `va`.
    ///
    /// `mappings` are used to translate VA → file offset.
    pub fn parse(data: &[u8], va: u64, mappings: &[CacheMappingInfo]) -> Result<Self> {
        let file_off = usize::try_from(mappings
            .iter()
            .find_map(|m| m.va_to_file_offset(va))
            .context("AccelerateInfo VA not found in any mapping")?)?;

        if file_off + 0x80 > data.len() {
            bail!("AccelerateInfo block truncated at {file_off:#x}");
        }

        let buf = &data[file_off..];
        let rd_u32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap_or([0; 4]));
        let rd_u64 = |o: usize| -> u64 {
            buf.get(o..o + 8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, |b: [u8; 8]| u64::from_le_bytes(b))
        };

        let image_extras_count = rd_u32(0x00);
        let bottom_up_count    = rd_u32(0x04);
        let range_table_count  = rd_u32(0x08);
        let exports_trie_addr  = rd_u64(0x10);
        let exports_trie_size  = rd_u32(0x18);

        Ok(Self {
            va,
            image_extras_count,
            bottom_up_count,
            range_table_count,
            exports_trie_addr,
            exports_trie_size,
            symbol_names: Vec::new(),
        })
    }
}

// ── SubCache descriptor ───────────────────────────────────────────────────────

/// A sub-cache entry (iOS 16+ / macOS 13+ split caches).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubCacheEntry {
    /// UUID of the sub-cache file.
    pub uuid: [u8; 16],
    /// Cache VM offset: this sub-cache's content starts at `base + cache_vm_offset`.
    pub cache_vm_offset: u64,
    /// File suffix string (e.g. `".1"`, `".2"`, `".symbols"`).
    pub suffix: String,
}

impl SubCacheEntry {
    /// On-disk entry size (UUID + `cache_vm_offset` + 32-char suffix).
    pub const ENTRY_SIZE: usize = 56;

    /// Parse from `ENTRY_SIZE` bytes.
    ///
    /// # Errors
    /// Returns an error if truncated.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::ENTRY_SIZE {
            bail!("SubCacheEntry: too short");
        }
        let uuid: [u8; 16] = data[0..16].try_into()?;
        let cache_vm_offset = u64::from_le_bytes(data[16..24].try_into()?);
        // 32-byte NUL-padded suffix string.
        let suffix_raw = &data[24..56];
        let nul = suffix_raw.iter().position(|&b| b == 0).unwrap_or(32);
        let suffix = String::from_utf8_lossy(&suffix_raw[..nul]).into_owned();
        Ok(Self { uuid, cache_vm_offset, suffix })
    }

    /// Format UUID as lowercase hyphenated string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15],
        )
    }
}

// ── DyldCacheHeader (full on-disk representation) ─────────────────────────────

/// Complete parsed dyld shared cache header.
///
/// This struct covers the legacy header (present in all versions) plus
/// extended fields introduced in newer iOS/macOS releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldCacheFullHeader {
    /// Magic string (e.g. `"dyld_v1  arm64e"`).
    pub magic: String,
    /// Detected architecture.
    pub arch: CacheArch,
    /// File offset of first `CacheMappingInfo`.
    pub mapping_offset: u32,
    /// Number of `CacheMappingInfo` entries.
    pub mapping_count: u32,
    /// File offset of first `CacheImageInfo`.
    pub images_offset: u32,
    /// Number of `CacheImageInfo` entries.
    pub images_count: u32,
    /// Preferred VM base address.
    pub dyld_base_address: u64,
    /// Code signature blob offset.
    pub code_sig_offset: u64,
    /// Code signature blob size.
    pub code_sig_size: u64,
    /// Legacy slide info offset (deprecated in later versions).
    pub slide_info_offset: u64,
    /// Legacy slide info size.
    pub slide_info_size: u64,
    /// Local symbols blob offset.
    pub local_symbols_offset: u64,
    /// Local symbols blob size.
    pub local_symbols_size: u64,
    /// Cache UUID.
    pub uuid: [u8; 16],
    /// Cache type (0 = production, 1 = development).
    pub cache_type: u64,
    /// Branch-pool array offset (`AArch64` stubs).
    pub branch_pools_offset: u32,
    /// Number of branch-pool entries.
    pub branch_pools_count: u32,
    /// Sub-cache array offset (iOS 16+ split caches).
    pub sub_cache_array_offset: u32,
    /// Number of sub-cache entries.
    pub sub_cache_array_count: u32,
    /// UUID of the `.symbols` sub-cache (if present).
    pub symbol_file_uuid: [u8; 16],
    /// Read-only Rosetta translation buffer VA.
    pub rosetta_read_only_addr: u64,
    /// Read-write Rosetta translation buffer VA.
    pub rosetta_read_write_addr: u64,
    /// Images-text array offset (dyld 940+).
    pub images_text_offset: u64,
    /// Number of images-text entries.
    pub images_text_count: u64,
    /// Accelerate info VA.
    pub accelerate_info_addr: u64,
    /// Accelerate info size.
    pub accelerate_info_size: u64,
    /// Platform (1=iOS, 2=macOS, …).
    pub platform: u32,
    /// Format version.
    pub format_version: u32,
}

impl DyldCacheFullHeader {
    /// Minimum bytes required to parse the base header.
    pub const BASE_SIZE: usize = 0x100;

    /// Parse the header from the beginning of `data`.
    ///
    /// # Errors
    /// Returns an error if the data is too short or the magic doesn't start with `dyld_v1`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BASE_SIZE {
            bail!("dyld cache header: data too short ({} < {})", data.len(), Self::BASE_SIZE);
        }

        let magic_raw = &data[..16];
        let magic = String::from_utf8_lossy(magic_raw)
            .trim_end_matches('\0')
            .to_string();

        if !magic.starts_with("dyld_v1") {
            bail!("dyld cache: invalid magic '{magic}'");
        }

        let arch = CacheArch::from_magic(&magic);

        let rd_u32 = |off: usize| -> u32 {
            data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };
        let rd_u64 = |off: usize| -> u64 {
            data.get(off..off + 8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, |b: [u8; 8]| u64::from_le_bytes(b))
        };

        let mapping_offset = rd_u32(0x10);
        let mapping_count  = rd_u32(0x14);
        let images_offset  = rd_u32(0x18);
        let images_count   = rd_u32(0x1C);
        let dyld_base_address = rd_u64(0x20);
        let code_sig_offset   = rd_u64(0x28);
        let code_sig_size     = rd_u64(0x30);
        let slide_info_offset = rd_u64(0x38);
        let slide_info_size   = rd_u64(0x40);
        let local_symbols_offset = rd_u64(0x48);
        let local_symbols_size   = rd_u64(0x50);

        let uuid: [u8; 16] = data.get(0x58..0x68)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 16]);

        let cache_type            = rd_u64(0x68);
        let branch_pools_offset   = rd_u32(0x70);
        let branch_pools_count    = rd_u32(0x74);
        let accelerate_info_addr  = rd_u64(0x78);
        let accelerate_info_size  = rd_u64(0x80);
        let images_text_offset    = rd_u64(0x88);
        let images_text_count     = rd_u64(0x90);
        let sub_cache_array_offset = rd_u32(0x98);
        let sub_cache_array_count  = rd_u32(0x9C);

        let symbol_file_uuid: [u8; 16] = data.get(0xA0..0xB0)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 16]);

        let rosetta_read_only_addr  = rd_u64(0xB0);
        let rosetta_read_write_addr = rd_u64(0xB8);
        let platform                = rd_u32(0xC0);
        let format_version          = rd_u32(0xC4);

        Ok(Self {
            magic,
            arch,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_sig_offset,
            code_sig_size,
            slide_info_offset,
            slide_info_size,
            local_symbols_offset,
            local_symbols_size,
            uuid,
            cache_type,
            branch_pools_offset,
            branch_pools_count,
            sub_cache_array_offset,
            sub_cache_array_count,
            symbol_file_uuid,
            rosetta_read_only_addr,
            rosetta_read_write_addr,
            images_text_offset,
            images_text_count,
            accelerate_info_addr,
            accelerate_info_size,
            platform,
            format_version,
        })
    }

    /// Format the UUID as a lowercase hyphenated hex string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],
            u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15],
        )
    }

    /// Platform name string.
    #[must_use]
    pub const fn platform_name(&self) -> &'static str {
        match self.platform {
            1 => "iOS",
            2 => "macOS",
            3 => "tvOS",
            4 => "watchOS",
            5 => "bridgeOS",
            6 => "macCatalyst",
            7 => "iOSSimulator",
            8 => "tvOSSimulator",
            9 => "watchOSSimulator",
            _ => "unknown",
        }
    }

    /// Returns `true` if this cache uses sub-cache files (iOS 16+).
    #[must_use]
    pub const fn has_sub_caches(&self) -> bool {
        self.sub_cache_array_count > 0
    }

    /// Returns `true` if the cache has the accelerate info tables.
    #[must_use]
    pub const fn has_accelerate_info(&self) -> bool {
        self.accelerate_info_addr != 0
    }
}

impl fmt::Display for DyldCacheFullHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DyldCache {} arch={} platform={} mappings={} images={} uuid={}",
            self.magic.trim(),
            self.arch,
            self.platform_name(),
            self.mapping_count,
            self.images_count,
            self.uuid_string(),
        )
    }
}

// ── DyldCacheParser ───────────────────────────────────────────────────────────

/// Fully-parsed dyld shared cache.
#[derive(Debug, Serialize, Deserialize)]
pub struct DyldCacheParser {
    /// Parsed header.
    pub header: DyldCacheFullHeader,
    /// Memory mappings.
    pub mappings: Vec<CacheMappingInfo>,
    /// Image descriptors.
    pub images: Vec<CacheImageInfo>,
    /// Sub-cache descriptors (for split caches).
    pub sub_caches: Vec<SubCacheEntry>,
    /// Accelerate info, if parsed.
    pub accelerate_info: Option<AccelerateInfo>,
    /// Any warnings accumulated during parsing.
    pub warnings: Vec<String>,
}

impl DyldCacheParser {
    /// Parse a dyld shared cache from `data`.
    ///
    /// # Errors
    /// Returns an error if the magic is wrong or data is too short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = DyldCacheFullHeader::parse(data)?;
        let mut warnings = Vec::new();

        // Parse mappings.
        let mut mappings = Vec::with_capacity(header.mapping_count as usize);
        for i in 0..header.mapping_count as usize {
            let off = header.mapping_offset as usize + i * CacheMappingInfo::ENTRY_SIZE;
            if off + CacheMappingInfo::ENTRY_SIZE > data.len() {
                warnings.push(format!("mapping {i} truncated"));
                break;
            }
            match CacheMappingInfo::parse(&data[off..]) {
                Ok(m) => mappings.push(m),
                Err(e) => {
                    warnings.push(format!("mapping {i}: {e}"));
                    break;
                }
            }
        }

        // Parse images.
        let mut images = Vec::with_capacity(header.images_count as usize);
        for i in 0..header.images_count as usize {
            let off = header.images_offset as usize + i * CacheImageInfo::ENTRY_SIZE;
            if off + CacheImageInfo::ENTRY_SIZE > data.len() {
                warnings.push(format!("image {i} truncated"));
                break;
            }
            match CacheImageInfo::parse(&data[off..off + CacheImageInfo::ENTRY_SIZE], data) {
                Ok(img) => images.push(img),
                Err(e) => {
                    warnings.push(format!("image {i}: {e}"));
                    break;
                }
            }
        }

        // Parse sub-cache descriptors.
        let mut sub_caches = Vec::with_capacity(header.sub_cache_array_count as usize);
        if header.sub_cache_array_offset > 0 {
            for i in 0..header.sub_cache_array_count as usize {
                let off = header.sub_cache_array_offset as usize + i * SubCacheEntry::ENTRY_SIZE;
                if off + SubCacheEntry::ENTRY_SIZE > data.len() {
                    warnings.push(format!("sub-cache {i} truncated"));
                    break;
                }
                match SubCacheEntry::parse(&data[off..]) {
                    Ok(sc) => sub_caches.push(sc),
                    Err(e) => {
                        warnings.push(format!("sub-cache {i}: {e}"));
                        break;
                    }
                }
            }
        }

        // Optionally parse accelerate info.
        let accelerate_info = if header.has_accelerate_info() {
            match AccelerateInfo::parse(data, header.accelerate_info_addr, &mappings) {
                Ok(ai) => Some(ai),
                Err(e) => {
                    warnings.push(format!("accelerate info: {e}"));
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            header,
            mappings,
            images,
            sub_caches,
            accelerate_info,
            warnings,
        })
    }

    /// Translate a virtual address to a file offset using the mapping table.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.mappings.iter().find_map(|m| m.va_to_file_offset(va))
    }

    /// Find an image by exact path.
    #[must_use]
    pub fn find_image(&self, path: &str) -> Option<&CacheImageInfo> {
        self.images.iter().find(|img| img.path == path)
    }

    /// Find all images whose path contains `fragment`.
    #[must_use]
    pub fn find_images_containing(&self, fragment: &str) -> Vec<&CacheImageInfo> {
        self.images.iter().filter(|img| img.path.contains(fragment)).collect()
    }

    /// Extract the raw Mach-O bytes for an image at `address`.
    ///
    /// Copies up to `max_size` bytes from the cache starting at the file offset
    /// that corresponds to the image's load address.
    ///
    /// # Errors
    /// Returns an error if no mapping covers the address.
    pub fn extract_image_bytes(
        &self,
        data: &[u8],
        address: u64,
        max_size: usize,
    ) -> Result<Vec<u8>> {
        let file_off = usize::try_from(self
            .va_to_file_offset(address)
            .context(format!("VA {address:#018x} not found in any mapping"))?)?;

        let end = (file_off + max_size).min(data.len());
        Ok(data[file_off..end].to_vec())
    }

    /// Build an index: path → image index.
    #[must_use]
    pub fn path_index(&self) -> HashMap<String, usize> {
        self.images
            .iter()
            .enumerate()
            .map(|(i, img)| (img.path.clone(), i))
            .collect()
    }

    /// Resolve an image path as a [`PathBuf`] (useful for OS path manipulation).
    #[must_use]
    pub fn image_path_buf(&self, idx: usize) -> Option<PathBuf> {
        self.images.get(idx).map(|img| PathBuf::from(&img.path))
    }

    /// Find the first image whose cache path matches `path` (compared as a [`Path`]).
    #[must_use]
    pub fn find_image_by_path(&self, path: &Path) -> Option<&CacheImageInfo> {
        let target = path.to_string_lossy();
        self.images.iter().find(|img| Path::new(&img.path) == Path::new(target.as_ref()))
    }

    /// Summary statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let text_size: u64 = self.mappings.iter()
            .filter(|m| m.is_executable())
            .map(|m| m.size)
            .sum();
        CacheStats {
            mapping_count: self.mappings.len(),
            image_count: self.images.len(),
            sub_cache_count: self.sub_caches.len(),
            text_size,
            arch: self.header.arch,
            platform: self.header.platform_name().to_string(),
        }
    }
}

/// High-level statistics about a parsed cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub mapping_count: usize,
    pub image_count: usize,
    pub sub_cache_count: usize,
    pub text_size: u64,
    pub arch: CacheArch,
    pub platform: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_arch_from_magic() {
        assert_eq!(CacheArch::from_magic("dyld_v1  arm64e"), CacheArch::Arm64e);
        assert_eq!(CacheArch::from_magic("dyld_v1  x86_64"), CacheArch::X86_64);
        assert!(CacheArch::Arm64e.is_64bit());
        assert!(!CacheArch::ArmV7.is_64bit());
    }

    #[test]
    fn mapping_prot_string() {
        let m = CacheMappingInfo {
            address: 0x1000, size: 0x1000, file_offset: 0, max_prot: 5, init_prot: 5,
        };
        assert_eq!(m.prot_string(), "r-x");
        assert!(m.is_executable());
    }

    #[test]
    fn mapping_va_to_file_offset() {
        let m = CacheMappingInfo {
            address: 0x1_8000_0000, size: 0x10_0000, file_offset: 0, max_prot: 5, init_prot: 5,
        };
        assert_eq!(m.va_to_file_offset(0x1_8000_1000), Some(0x1000));
        assert!(m.va_to_file_offset(0x2_0000_0000).is_none());
    }

    #[test]
    fn sub_cache_entry_parse() {
        let mut data = vec![0u8; SubCacheEntry::ENTRY_SIZE];
        data[..16].fill(0xAB); // UUID
        data[16..24].copy_from_slice(&0x1234u64.to_le_bytes()); // vm_offset
        data[24..26].copy_from_slice(b".1");
        let sc = SubCacheEntry::parse(&data).unwrap();
        assert_eq!(sc.cache_vm_offset, 0x1234);
        assert_eq!(sc.suffix, ".1");
    }

    #[test]
    fn header_bad_magic() {
        let data = vec![0u8; 512];
        let err = DyldCacheFullHeader::parse(&data).unwrap_err();
        assert!(err.to_string().contains("invalid magic"));
    }

    #[test]
    fn header_too_short() {
        let data = vec![0u8; 20];
        let err = DyldCacheFullHeader::parse(&data).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn header_minimal_valid() {
        let mut data = vec![0u8; 512];
        let magic = b"dyld_v1   arm64e";
        data[..16].copy_from_slice(magic);
        let hdr = DyldCacheFullHeader::parse(&data).unwrap();
        assert_eq!(hdr.arch, CacheArch::Arm64e);
        assert!(!hdr.has_sub_caches());
    }

    #[test]
    fn parser_minimal() {
        let mut data = vec![0u8; 512];
        data[..16].copy_from_slice(b"dyld_v1   arm64\0");
        let parser = DyldCacheParser::parse(&data).unwrap();
        assert_eq!(parser.images.len(), 0);
        assert_eq!(parser.mappings.len(), 0);
    }
}
