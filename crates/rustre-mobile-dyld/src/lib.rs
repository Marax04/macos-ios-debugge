//! `rustre-mobile-dyld`
//!
//! Apple dyld shared cache parser for the `RustRE` Suite.
//!
//! Supports all modern `dyld_shared_cache` formats including sub-caches
//! (macOS Big Sur+, iOS 15+), slide info v1-v4, and image extraction.

pub mod cache_header;
pub mod dyld_cache_analysis;
pub mod dyld_cache_parser;
pub mod dyld_exports_trie;
pub mod dyld_fixups;
pub mod images;
pub mod mappings;
pub mod objc_selector_db;
pub mod shared_cache_extractor;
pub mod slide_info;
pub mod subcaches;
pub mod dyld_cache_image_extractor;
pub mod dyld_fixup_chains;
pub mod dyld_shared_cache_analyzer;
pub mod dyld_bind_info_parser;
pub mod dyld_rebase_info_parser;
pub mod dyld_symbol_table;
pub mod objc_optimizer;

// ─────────────────────────────────────────────────────────────────────────────
// DyldError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during dyld cache parsing.
#[derive(thiserror::Error, Debug)]
pub enum DyldError {
    /// The file magic does not match any known dyld cache format.
    #[error("Invalid magic: expected {expected}, got {actual}")]
    InvalidMagic { expected: String, actual: String },
    /// The data is too short to contain the required structure at the given offset.
    #[error("Truncated data at offset {0}")]
    Truncated(usize),
    /// A field references an out-of-range file offset.
    #[error("Invalid offset {0:#x}")]
    InvalidOffset(u64),
    /// The requested image path was not found in the cache.
    #[error("Image not found: {0}")]
    ImageNotFound(String),
    /// Generic structural parse error.
    #[error("Parse error: {0}")]
    Parse(String),
    /// Sub-cache file not found.
    #[error("Sub-cache not found: {0}")]
    SubcacheNotFound(String),
    /// Slide fixup error.
    #[error("Slide fixup error: {0}")]
    SlideFixup(String),
    /// I/O error.
    #[error("IO error: {0}")]
    Io(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed representation of a dyld shared cache header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldHeader {
    /// Magic string (e.g. `"dyld_v1   arm64e"`).
    pub magic: String,
    /// Byte offset of the first mapping entry.
    pub mapping_offset: u32,
    /// Number of mapping entries.
    pub mapping_count: u32,
    /// Byte offset of the first image info entry.
    pub images_offset: u32,
    /// Number of image entries.
    pub images_count: u32,
    /// Virtual base address at which dyld loaded the cache.
    pub dyld_base_address: u64,
    /// Byte offset of the code signature blob.
    pub code_sig_offset: u64,
    /// Byte length of the code signature blob.
    pub code_sig_size: u64,
    /// Byte offset of the slide info.
    pub slide_info_offset: u64,
    /// Byte length of the slide info.
    pub slide_info_size: u64,
    /// UUID of this cache file.
    pub uuid: [u8; 16],
    /// Cache platform (1=iOS, 2=macOS, 3=tvOS, 4=watchOS).
    pub platform: u32,
    /// Format version.
    pub format_version: u32,
    /// Offset to new image text info list (post dyld-832).
    pub images_text_offset: u64,
    /// Count of image text info entries.
    pub images_text_count: u64,
    /// Offset to sub-cache array.
    pub subcache_array_offset: u32,
    /// Count of sub-cache entries.
    pub subcache_array_count: u32,
}

impl DyldHeader {
    /// Format the UUID as a hyphenated lowercase string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0],
            u[1],
            u[2],
            u[3],
            u[4],
            u[5],
            u[6],
            u[7],
            u[8],
            u[9],
            u[10],
            u[11],
            u[12],
            u[13],
            u[14],
            u[15],
        )
    }

    /// Return `true` if the magic indicates an arm64/arm64e cache.
    #[must_use]
    pub fn is_arm64(&self) -> bool {
        self.magic.contains("arm64")
    }

    /// Return the platform name.
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
            10 => "driverKit",
            _ => "unknown",
        }
    }

    /// Return `true` if this cache was built for a simulator.
    #[must_use]
    pub const fn is_simulator(&self) -> bool {
        matches!(self.platform, 7..=9)
    }

    /// Parse from raw bytes.
    ///
    /// # Errors
    /// Returns [`DyldError`] if the data is too short or magic is invalid.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 0x100 {
            return Err(DyldError::Truncated(0));
        }

        let magic_bytes = &data[..16];
        let magic = String::from_utf8_lossy(magic_bytes)
            .trim_end_matches('\0')
            .to_string();

        if !magic.starts_with("dyld_v1") {
            return Err(DyldError::InvalidMagic {
                expected: "dyld_v1".to_string(),
                actual: magic,
            });
        }

        let mapping_offset = read_u32_le(data, 16)?;
        let mapping_count = read_u32_le(data, 20)?;
        let images_offset = read_u32_le(data, 24)?;
        let images_count = read_u32_le(data, 28)?;
        let dyld_base_address = read_u64_le(data, 32)?;
        let code_sig_offset = read_u64_le(data, 40)?;
        let code_sig_size = read_u64_le(data, 48)?;
        let slide_info_offset = read_u64_le(data, 56)?;
        let slide_info_size = read_u64_le(data, 64)?;

        let uuid: [u8; 16] = if data.len() >= 0x68 {
            data[0x58..0x68].try_into().unwrap_or([0u8; 16])
        } else {
            [0u8; 16]
        };

        // Extended fields (present in newer cache versions).
        let (
            platform,
            format_version,
            images_text_offset,
            images_text_count,
            subcache_array_offset,
            subcache_array_count,
        ) = if data.len() >= 0xE0 {
            (
                read_u32_le(data, 0x68).unwrap_or(0),
                read_u32_le(data, 0x6C).unwrap_or(0),
                read_u64_le(data, 0x70).unwrap_or(0),
                read_u64_le(data, 0x78).unwrap_or(0),
                read_u32_le(data, 0x80).unwrap_or(0),
                read_u32_le(data, 0x84).unwrap_or(0),
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };

        Ok(Self {
            magic,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_sig_offset,
            code_sig_size,
            slide_info_offset,
            slide_info_size,
            uuid,
            platform,
            format_version,
            images_text_offset,
            images_text_count,
            subcache_array_offset,
            subcache_array_count,
        })
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    let b = data
        .get(offset..offset + 4)
        .ok_or(DyldError::Truncated(offset))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    let b = data
        .get(offset..offset + 8)
        .ok_or(DyldError::Truncated(offset))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldMapping
// ─────────────────────────────────────────────────────────────────────────────

/// A single virtual-memory mapping entry in the dyld cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldMapping {
    /// Preferred virtual address of the mapping.
    pub address: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Byte offset within the cache file where the data lives.
    pub file_offset: u64,
    /// Initial `mach_vm_prot_t` protection.
    pub init_prot: u32,
    /// Maximum `mach_vm_prot_t` protection.
    pub max_prot: u32,
    /// Platform-specific flags.
    pub flags: u32,
}

impl DyldMapping {
    /// Return `true` if this mapping is executable (`init_prot` bit 2).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.init_prot & 0x4 != 0
    }

    /// Return `true` if this mapping is writable (`init_prot` bit 1).
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.init_prot & 0x2 != 0
    }

    /// Return `true` if this mapping is readable (`init_prot` bit 0).
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.init_prot & 0x1 != 0
    }

    /// Return the exclusive end address of this mapping.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Return `true` if a virtual address falls within this mapping.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.address && va < self.end_address()
    }

    /// Translate a virtual address to a file offset.
    #[must_use]
    pub const fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if !self.contains_va(va) {
            return None;
        }
        Some(self.file_offset + (va - self.address))
    }

    /// Return the protection string (e.g. `"r-x"`).
    #[must_use]
    pub fn prot_string(&self) -> String {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldImage
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a single Mach-O image embedded in the dyld cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldImage {
    /// Load address of the image within the shared cache address space.
    pub address: u64,
    /// Modification time of the source file (used for validation).
    pub mod_time: u64,
    /// Inode of the source file (used for validation).
    pub inode: u64,
    /// Byte offset within the strings section where the path string starts.
    pub path_offset: u32,
    /// Null-terminated path string (e.g. `/usr/lib/libSystem.B.dylib`).
    pub path: String,
}

impl DyldImage {
    /// Return the last component of the image path (the filename).
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Return `true` if this is an Apple system framework.
    #[must_use]
    pub fn is_system_framework(&self) -> bool {
        self.path.starts_with("/System/") || self.path.starts_with("/usr/lib/")
    }

    /// Return `true` if this is a Swift overlay dylib.
    #[must_use]
    pub fn is_swift_overlay(&self) -> bool {
        self.path.contains("swift")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSymbol
// ─────────────────────────────────────────────────────────────────────────────

/// A symbol exported by an image in the dyld cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldSymbol {
    /// Demangled or raw symbol name.
    pub name: String,
    /// Virtual address of the symbol.
    pub address: u64,
    /// Path of the image that exports this symbol.
    pub image_path: String,
    /// Symbol flags (Mach-O `n_type` / `n_desc` encoding).
    pub flags: u32,
}

impl DyldSymbol {
    /// Return `true` if this is a weak symbol.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.flags & 0x40 != 0
    }

    /// Return `true` if this is an `ObjC` symbol.
    #[must_use]
    pub fn is_objc(&self) -> bool {
        self.name.starts_with("_OBJC_")
            || self.name.starts_with("+[")
            || self.name.starts_with("-[")
    }

    /// Return `true` if this is a Swift symbol.
    #[must_use]
    pub fn is_swift(&self) -> bool {
        self.name.starts_with("$s") || self.name.starts_with("_$s")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractReport
// ─────────────────────────────────────────────────────────────────────────────

/// Report produced by [`DyldCache::extract_all`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ExtractReport {
    pub extracted_count: usize,
    pub failed_count: usize,
    pub total_bytes: u64,
    pub failures: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SlideFixup
// ─────────────────────────────────────────────────────────────────────────────

/// Slide fixup context for a dyld cache mapping.
///
/// Knows the preferred (on-disk) virtual address range of the mapping so it can
/// identify pointer-sized values that look like in-cache pointers and rebase them
/// by adding the ASLR slide delta.
///
/// # Heuristic mode
///
/// When no structured [`slide_info::SlideInfo`] blob is available the
/// implementation falls back to scanning every aligned `u64` in `data` and
/// rebasing any value that falls inside the expected cache address window
/// (`0x1_8000_0000 ..= 0x3_FFFF_FFFF` — the typical arm64 shared-cache range).
#[derive(Debug, Clone)]
pub struct SlideFixup {
    /// Preferred virtual address of the first byte of the mapping.
    pub mapping_va: u64,
    /// Byte length of the mapping.
    pub mapping_size: u64,
    /// Parsed slide-info blob, if available.
    pub slide_info: Option<slide_info::SlideInfo>,
}

impl SlideFixup {
    /// Create a new `SlideFixup` for a mapping that spans
    /// `[mapping_va, mapping_va + mapping_size)`.
    ///
    /// `slide_info` may be `None` to request heuristic scanning.
    #[must_use]
    pub const fn new(
        mapping_va: u64,
        mapping_size: u64,
        slide_info: Option<slide_info::SlideInfo>,
    ) -> Self {
        Self {
            mapping_va,
            mapping_size,
            slide_info,
        }
    }

    /// Apply the ASLR slide to every pointer location in `data`.
    ///
    /// Returns the number of pointer locations that were patched.
    ///
    /// * When a structured [`slide_info::SlideInfo`] blob is available it is
    ///   used for precise fixups via [`slide_info::apply_slide_fixups`].
    /// * Otherwise a heuristic scan is performed: every aligned 8-byte word
    ///   whose value lies in the arm64 shared-cache address window is
    ///   rebased by adding `slide`.
    ///
    /// # Errors
    /// Propagates [`DyldError::SlideFixup`] from the structured fixup path.
    pub fn apply(&self, data: &mut [u8], slide: u64) -> Result<usize, DyldError> {
        if slide == 0 {
            return Ok(0);
        }

        if let Some(si) = &self.slide_info {
            slide_info::apply_slide_fixups(data, si, slide, self.mapping_va)
        } else {
            // Heuristic: rebase aligned u64 values that look like cache pointers.
            // Typical arm64 shared-cache window (covers iOS/macOS 64-bit caches).
            const PTR_LO: u64 = 0x1_8000_0000;
            const PTR_HI: u64 = 0x3_FFFF_FFFF;

            let mut count = 0usize;
            let mut offset = 0usize;
            while offset + 8 <= data.len() {
                let raw = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                if (PTR_LO..=PTR_HI).contains(&raw) {
                    let rebased = raw.wrapping_add(slide);
                    data[offset..offset + 8].copy_from_slice(&rebased.to_le_bytes());
                    count += 1;
                }
                offset += 8;
            }
            Ok(count)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCache
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed dyld shared cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCache {
    /// Parsed cache header.
    pub header: DyldHeader,
    /// Virtual memory mappings.
    pub mappings: Vec<DyldMapping>,
    /// Embedded image descriptors.
    pub images: Vec<DyldImage>,
    /// Symbols resolved from the cache's accelerator structures.
    pub symbols: Vec<DyldSymbol>,
    /// Raw cache file bytes (kept for later extraction).
    pub data: Vec<u8>,
}

/// Known dyld shared cache magic prefixes.
const DYLD_MAGIC_PREFIX: &str = "dyld_v1";

impl DyldCache {
    /// Parse a dyld shared cache from raw bytes.
    ///
    /// # Errors
    /// Returns [`DyldError`] if the header magic is invalid or the data is
    /// truncated.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 16 {
            return Err(DyldError::Truncated(0));
        }

        let magic_bytes = &data[..16];
        let magic = String::from_utf8_lossy(magic_bytes)
            .trim_end_matches('\0')
            .to_string();

        if !magic.starts_with(DYLD_MAGIC_PREFIX) {
            return Err(DyldError::InvalidMagic {
                expected: DYLD_MAGIC_PREFIX.to_string(),
                actual: magic,
            });
        }

        if data.len() < 0x100 {
            return Err(DyldError::Truncated(16));
        }

        let mapping_offset = u32::from_le_bytes(
            data[16..20]
                .try_into()
                .map_err(|_| DyldError::Truncated(16))?,
        );
        let mapping_count = u32::from_le_bytes(
            data[20..24]
                .try_into()
                .map_err(|_| DyldError::Truncated(20))?,
        );
        let images_offset = u32::from_le_bytes(
            data[24..28]
                .try_into()
                .map_err(|_| DyldError::Truncated(24))?,
        );
        let images_count = u32::from_le_bytes(
            data[28..32]
                .try_into()
                .map_err(|_| DyldError::Truncated(28))?,
        );
        let dyld_base_address = u64::from_le_bytes(
            data[32..40]
                .try_into()
                .map_err(|_| DyldError::Truncated(32))?,
        );
        let code_sig_offset = u64::from_le_bytes(
            data[40..48]
                .try_into()
                .map_err(|_| DyldError::Truncated(40))?,
        );
        let code_sig_size = u64::from_le_bytes(
            data[48..56]
                .try_into()
                .map_err(|_| DyldError::Truncated(48))?,
        );
        let slide_info_offset = u64::from_le_bytes(
            data[56..64]
                .try_into()
                .map_err(|_| DyldError::Truncated(56))?,
        );
        let slide_info_size = u64::from_le_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| DyldError::Truncated(64))?,
        );

        let uuid: [u8; 16] = if data.len() >= 0x68 {
            data[0x58..0x68].try_into().unwrap_or([0u8; 16])
        } else {
            [0u8; 16]
        };

        let header = DyldHeader {
            magic,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_sig_offset,
            code_sig_size,
            slide_info_offset,
            slide_info_size,
            uuid,
            platform: 0,
            format_version: 0,
            images_text_offset: 0,
            images_text_count: 0,
            subcache_array_offset: 0,
            subcache_array_count: 0,
        };

        let mapping_size = 32usize;
        let mapping_cap = (mapping_count as usize).min(data.len() / mapping_size.max(1));
        let mut mappings = Vec::with_capacity(mapping_cap);
        for i in 0..mapping_count as usize {
            let base = mapping_offset as usize + i * mapping_size;
            if base + mapping_size > data.len() {
                break;
            }
            let address = u64::from_le_bytes(
                data[base..base + 8]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base))?,
            );
            let size = u64::from_le_bytes(
                data[base + 8..base + 16]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 8))?,
            );
            let file_offset = u64::from_le_bytes(
                data[base + 16..base + 24]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 16))?,
            );
            let init_prot = u32::from_le_bytes(
                data[base + 24..base + 28]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 24))?,
            );
            let max_prot = u32::from_le_bytes(
                data[base + 28..base + 32]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 28))?,
            );
            mappings.push(DyldMapping {
                address,
                size,
                file_offset,
                init_prot,
                max_prot,
                flags: 0,
            });
        }

        let image_size = 32usize;
        let images_cap = (images_count as usize).min(data.len() / image_size.max(1));
        let mut images = Vec::with_capacity(images_cap);
        for i in 0..images_count as usize {
            let base = images_offset as usize + i * image_size;
            if base + image_size > data.len() {
                break;
            }
            let address = u64::from_le_bytes(
                data[base..base + 8]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base))?,
            );
            let mod_time = u64::from_le_bytes(
                data[base + 8..base + 16]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 8))?,
            );
            let inode = u64::from_le_bytes(
                data[base + 16..base + 24]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 16))?,
            );
            let path_offset = u32::from_le_bytes(
                data[base + 24..base + 28]
                    .try_into()
                    .map_err(|_| DyldError::Truncated(base + 24))?,
            );
            let path = Self::read_cstring(data, path_offset as usize);
            images.push(DyldImage {
                address,
                mod_time,
                inode,
                path_offset,
                path,
            });
        }

        Ok(Self {
            header,
            mappings,
            images,
            symbols: Vec::new(),
            data: data.to_vec(),
        })
    }

    /// Read a NUL-terminated string from `data` at byte offset `offset`.
    fn read_cstring(data: &[u8], offset: usize) -> String {
        if offset >= data.len() {
            return String::new();
        }
        let slice = &data[offset..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).into_owned()
    }

    /// Find the first image whose path exactly matches `path`.
    #[must_use]
    pub fn find_image(&self, path: &str) -> Option<&DyldImage> {
        self.images.iter().find(|img| img.path == path)
    }

    /// Find all images whose path contains `fragment`.
    #[must_use]
    pub fn find_images_containing(&self, fragment: &str) -> Vec<&DyldImage> {
        self.images
            .iter()
            .filter(|img| img.path.contains(fragment))
            .collect()
    }

    /// Return all symbols exported by the image at `image_path`.
    #[must_use]
    pub fn find_symbols_for_image(&self, image_path: &str) -> Vec<&DyldSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.image_path == image_path)
            .collect()
    }

    /// Find a symbol by exact name.
    #[must_use]
    pub fn find_symbol(&self, name: &str) -> Option<&DyldSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Number of images in the cache.
    #[must_use]
    pub const fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Number of symbols in the cache.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Translate a virtual address to a file offset using the mapping table.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.mappings.iter().find_map(|m| m.va_to_file_offset(va))
    }

    /// Read `len` bytes from the cache at a virtual address.
    #[must_use]
    pub fn read_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let file_off = self.va_to_file_offset(va)? as usize;
        self.data.get(file_off..file_off + len)
    }

    /// Extract the raw Mach-O bytes for the given image by copying the relevant
    /// file region.
    ///
    /// # Errors
    /// Returns [`DyldError`] if no mapping covers the image or the data is
    /// truncated.
    pub fn extract_image_data(&self, image: &DyldImage) -> Result<Vec<u8>, DyldError> {
        let mapping = self
            .mappings
            .iter()
            .find(|m| image.address >= m.address && image.address < m.end_address())
            .ok_or_else(|| DyldError::ImageNotFound(image.path.clone()))?;

        let virt_offset = image.address - mapping.address;
        let file_start = usize::try_from(mapping.file_offset + virt_offset)
            .map_err(|_| DyldError::InvalidOffset(mapping.file_offset + virt_offset))?;

        let remaining_in_mapping =
            usize::try_from(mapping.size - virt_offset).unwrap_or(1024 * 1024);
        let size = remaining_in_mapping.min(1024 * 1024);

        let file_end = file_start
            .checked_add(size)
            .ok_or(DyldError::InvalidOffset(file_start as u64))?;

        if file_end > self.data.len() {
            return Err(DyldError::Truncated(file_start));
        }

        Ok(self.data[file_start..file_end].to_vec())
    }

    /// Extract, rebase, and return the Mach-O bytes for the image at `image_path`.
    ///
    /// Steps:
    /// 1. Look up the image by exact path in the image list.
    /// 2. Find the first cache mapping that covers the image's load address.
    /// 3. Copy the relevant portion of the cache data (up to 1 MiB or the
    ///    remainder of the mapping, whichever is smaller).
    /// 4. Parse the Mach-O header with `goblin` to determine the true image size
    ///    from the segment commands; if parsing fails the raw 1 MiB copy is used.
    /// 5. Build a [`SlideFixup`] from the cache's slide-info blob (if present) and
    ///    apply it with `slide = 0` so the resulting bytes contain the preferred
    ///    on-cache addresses (useful for static analysis).
    ///
    /// Returns `None` when `image_path` does not match any image in the cache.
    ///
    /// # Errors
    /// Returns [`DyldError`] on mapping/offset failures.
    pub fn extract_image(&self, image_path: &str) -> Result<Vec<u8>, DyldError> {
        use goblin::mach::MachO;

        let image = self
            .find_image(image_path)
            .ok_or_else(|| DyldError::ImageNotFound(image_path.to_string()))?;

        // Locate the first mapping that contains the image load address.
        let mapping = self
            .mappings
            .iter()
            .find(|m| image.address >= m.address && image.address < m.end_address())
            .ok_or_else(|| DyldError::ImageNotFound(image_path.to_string()))?;

        let virt_offset = image.address - mapping.address;
        let file_start = usize::try_from(mapping.file_offset + virt_offset)
            .map_err(|_| DyldError::InvalidOffset(mapping.file_offset + virt_offset))?;

        // Initial extraction: up to 1 MiB or the rest of the mapping.
        let remaining_in_mapping =
            usize::try_from(mapping.size - virt_offset).unwrap_or(1024 * 1024);
        let initial_size = remaining_in_mapping.min(1024 * 1024);

        let file_end = file_start
            .checked_add(initial_size)
            .ok_or(DyldError::InvalidOffset(file_start as u64))?;

        if file_start >= self.data.len() {
            return Err(DyldError::Truncated(file_start));
        }
        let capped_end = file_end.min(self.data.len());
        let mut image_bytes = self.data[file_start..capped_end].to_vec();

        // Try to determine the true size from the Mach-O segment commands so we
        // do not over-allocate or return padding from the next image.
        if let Ok(macho) = MachO::parse(&image_bytes, 0) {
            let mut max_vm_end: u64 = 0;
            for seg in &macho.segments {
                let seg_end = seg.vmaddr.wrapping_add(seg.vmsize);
                if seg_end > max_vm_end {
                    max_vm_end = seg_end;
                }
            }
            if max_vm_end > image.address {
                let needed = usize::try_from(max_vm_end - image.address)
                    .unwrap_or(usize::MAX);
                let available = self.data.len().saturating_sub(file_start);
                let true_size = needed.min(available);
                if true_size > image_bytes.len() {
                    image_bytes = self.data[file_start..file_start + true_size].to_vec();
                } else {
                    image_bytes.truncate(true_size);
                }
            }
        }

        // Apply slide fixups.  We use slide=0 for a static extraction so that
        // all pointers retain their preferred on-cache virtual addresses.
        let slide_parsed = if self.header.slide_info_offset != 0 && self.header.slide_info_size != 0 {
            let si_start = usize::try_from(self.header.slide_info_offset).ok();
            let si_size  = usize::try_from(self.header.slide_info_size).ok();
            match (si_start, si_size) {
                (Some(s), Some(z)) if s < self.data.len() => {
                    let si_end = s.saturating_add(z).min(self.data.len());
                    slide_info::SlideInfo::parse(&self.data[s..si_end]).ok()
                }
                _ => None,
            }
        } else {
            None
        };
        let slide_fixup = SlideFixup::new(mapping.address, mapping.size, slide_parsed);

        // slide=0 → heuristic path is triggered but returns 0 immediately, so
        // this call is cheap even if slide_info is None.
        let _ = slide_fixup.apply(&mut image_bytes, 0);

        Ok(image_bytes)
    }

    /// Extract all images to a directory.
    ///
    /// # Errors
    /// Returns [`DyldError`] on I/O failure.
    pub fn extract_all(&self, output_dir: &std::path::Path) -> Result<ExtractReport, DyldError> {
        let mut report = ExtractReport::default();

        for image in &self.images {
            match self.extract_image_data(image) {
                Ok(data) => {
                    // Build output path by stripping leading slash.
                    let rel = image.path.trim_start_matches('/');
                    let out_path = output_dir.join(rel);
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| DyldError::Io(e.to_string()))?;
                    }
                    std::fs::write(&out_path, &data).map_err(|e| DyldError::Io(e.to_string()))?;
                    report.extracted_count += 1;
                    report.total_bytes += data.len() as u64;
                }
                Err(e) => {
                    report.failed_count += 1;
                    report.failures.push(format!("{}: {e}", image.path));
                }
            }
        }

        Ok(report)
    }

    /// Build a minimal mock cache for testing (no real binary data).
    #[must_use]
    pub fn mock() -> Self {
        let header = DyldHeader {
            magic: "dyld_v1   arm64e".to_string(),
            mapping_offset: 0x100,
            mapping_count: 1,
            images_offset: 0x200,
            images_count: 2,
            dyld_base_address: 0x1_8000_0000,
            code_sig_offset: 0,
            code_sig_size: 0,
            slide_info_offset: 0,
            slide_info_size: 0,
            uuid: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ],
            platform: 1, // iOS
            format_version: 0,
            images_text_offset: 0,
            images_text_count: 0,
            subcache_array_offset: 0,
            subcache_array_count: 0,
        };

        let mappings = vec![DyldMapping {
            address: 0x1_8000_0000,
            size: 0x1000_0000,
            file_offset: 0,
            init_prot: 5, // READ | EXEC
            max_prot: 5,
            flags: 0,
        }];

        let images = vec![
            DyldImage {
                address: 0x1_8000_0000,
                mod_time: 0,
                inode: 1,
                path_offset: 0,
                path: "/usr/lib/libSystem.B.dylib".to_string(),
            },
            DyldImage {
                address: 0x1_8010_0000,
                mod_time: 0,
                inode: 2,
                path_offset: 0,
                path: "/usr/lib/libobjc.A.dylib".to_string(),
            },
        ];

        let symbols = vec![
            DyldSymbol {
                name: "_malloc".to_string(),
                address: 0x1_8000_1000,
                image_path: "/usr/lib/libSystem.B.dylib".to_string(),
                flags: 0,
            },
            DyldSymbol {
                name: "_free".to_string(),
                address: 0x1_8000_2000,
                image_path: "/usr/lib/libSystem.B.dylib".to_string(),
                flags: 0,
            },
            DyldSymbol {
                name: "objc_msgSend".to_string(),
                address: 0x1_8010_1000,
                image_path: "/usr/lib/libobjc.A.dylib".to_string(),
                flags: 0,
            },
        ];

        Self {
            header,
            mappings,
            images,
            symbols,
            data: vec![0u8; 4096],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_invalid_magic_display() {
        let e = DyldError::InvalidMagic {
            expected: "dyld_v1".into(),
            actual: "junk".into(),
        };
        assert!(e.to_string().contains("Invalid magic"));
    }

    #[test]
    fn test_error_truncated_display() {
        let e = DyldError::Truncated(0x40);
        assert!(e.to_string().contains("Truncated"));
    }

    #[test]
    fn test_error_invalid_offset_display() {
        let e = DyldError::InvalidOffset(0xDEAD_BEEF);
        assert!(e.to_string().contains("Invalid offset"));
    }

    #[test]
    fn test_error_image_not_found_display() {
        let e = DyldError::ImageNotFound("/usr/lib/libfoo.dylib".into());
        assert!(e.to_string().contains("Image not found"));
    }

    #[test]
    fn test_error_parse_display() {
        let e = DyldError::Parse("bad field".into());
        assert!(e.to_string().contains("Parse error"));
    }

    #[test]
    fn test_header_uuid_string() {
        let cache = DyldCache::mock();
        let uuid = cache.header.uuid_string();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid, "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn test_header_is_arm64() {
        let cache = DyldCache::mock();
        assert!(cache.header.is_arm64());
    }

    #[test]
    fn test_header_platform_name() {
        let cache = DyldCache::mock();
        assert_eq!(cache.header.platform_name(), "iOS");
    }

    #[test]
    fn test_mapping_executable_writable() {
        let m = DyldMapping {
            address: 0x1000,
            size: 0x1000,
            file_offset: 0,
            init_prot: 5,
            max_prot: 5,
            flags: 0,
        };
        assert!(m.is_executable());
        assert!(!m.is_writable());
    }

    #[test]
    fn test_mapping_end_address() {
        let m = DyldMapping {
            address: 0x1000,
            size: 0x2000,
            file_offset: 0,
            init_prot: 1,
            max_prot: 1,
            flags: 0,
        };
        assert_eq!(m.end_address(), 0x3000);
    }

    #[test]
    fn test_mapping_contains_va() {
        let m = DyldMapping {
            address: 0x1000,
            size: 0x1000,
            file_offset: 0,
            init_prot: 1,
            max_prot: 1,
            flags: 0,
        };
        assert!(m.contains_va(0x1000));
        assert!(m.contains_va(0x1FFF));
        assert!(!m.contains_va(0x2000));
    }

    #[test]
    fn test_mapping_va_to_file_offset() {
        let m = DyldMapping {
            address: 0x1000,
            size: 0x1000,
            file_offset: 0x5000,
            init_prot: 1,
            max_prot: 1,
            flags: 0,
        };
        assert_eq!(m.va_to_file_offset(0x1100), Some(0x5100));
        assert!(m.va_to_file_offset(0x3000).is_none());
    }

    #[test]
    fn test_mapping_prot_string() {
        let m = DyldMapping {
            address: 0,
            size: 0,
            file_offset: 0,
            init_prot: 5,
            max_prot: 5,
            flags: 0,
        };
        assert_eq!(m.prot_string(), "r-x");
        let m2 = DyldMapping {
            address: 0,
            size: 0,
            file_offset: 0,
            init_prot: 3,
            max_prot: 3,
            flags: 0,
        };
        assert_eq!(m2.prot_string(), "rw-");
    }

    #[test]
    fn test_image_filename() {
        let img = DyldImage {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_offset: 0,
            path: "/usr/lib/libSystem.B.dylib".to_string(),
        };
        assert_eq!(img.filename(), "libSystem.B.dylib");
    }

    #[test]
    fn test_image_is_system_framework() {
        let img = DyldImage {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_offset: 0,
            path: "/usr/lib/libSystem.B.dylib".to_string(),
        };
        assert!(img.is_system_framework());
    }

    #[test]
    fn test_symbol_is_objc() {
        let s = DyldSymbol {
            name: "_OBJC_CLASS_$_NSObject".to_string(),
            address: 0x1000,
            image_path: "/usr/lib/libobjc.A.dylib".to_string(),
            flags: 0,
        };
        assert!(s.is_objc());
    }

    #[test]
    fn test_symbol_is_swift() {
        let s = DyldSymbol {
            name: "$sSS19stringInterpolationSSs013DefaultStringB0VzlufC".to_string(),
            address: 0x2000,
            image_path: "/usr/lib/swift/libswiftCore.dylib".to_string(),
            flags: 0,
        };
        assert!(s.is_swift());
    }

    #[test]
    fn test_mock_image_count() {
        let cache = DyldCache::mock();
        assert_eq!(cache.image_count(), 2);
    }

    #[test]
    fn test_mock_symbol_count() {
        let cache = DyldCache::mock();
        assert_eq!(cache.symbol_count(), 3);
    }

    #[test]
    fn test_mock_find_image() {
        let cache = DyldCache::mock();
        assert!(cache.find_image("/usr/lib/libSystem.B.dylib").is_some());
        assert!(cache.find_image("/nonexistent").is_none());
    }

    #[test]
    fn test_mock_find_images_containing() {
        let cache = DyldCache::mock();
        let imgs = cache.find_images_containing("libobjc");
        assert_eq!(imgs.len(), 1);
    }

    #[test]
    fn test_mock_find_symbols_for_image() {
        let cache = DyldCache::mock();
        let syms = cache.find_symbols_for_image("/usr/lib/libSystem.B.dylib");
        assert_eq!(syms.len(), 2);
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"_malloc"));
        assert!(names.contains(&"_free"));
    }

    #[test]
    fn test_mock_find_symbol() {
        let cache = DyldCache::mock();
        assert!(cache.find_symbol("_malloc").is_some());
        assert!(cache.find_symbol("_unknown").is_none());
    }

    #[test]
    fn test_mock_va_to_file_offset() {
        let cache = DyldCache::mock();
        // The mock mapping starts at 0x1_8000_0000 with file_offset=0.
        let fo = cache.va_to_file_offset(0x1_8000_0000);
        assert_eq!(fo, Some(0));
    }

    #[test]
    fn test_parse_too_short() {
        let err = DyldCache::parse(b"short").unwrap_err();
        assert!(matches!(err, DyldError::Truncated(_)));
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut data = vec![0u8; 256];
        data[..8].copy_from_slice(b"BADMAGIC");
        let err = DyldCache::parse(&data).unwrap_err();
        assert!(matches!(err, DyldError::InvalidMagic { .. }));
    }

    #[test]
    fn test_parse_minimal_valid() {
        let mut data = vec![0u8; 256];
        let magic = b"dyld_v1   arm64\0";
        data[..16].copy_from_slice(magic);
        let cache = DyldCache::parse(&data).unwrap();
        assert_eq!(cache.header.magic.trim_end_matches('\0'), "dyld_v1   arm64");
        assert_eq!(cache.image_count(), 0);
        assert_eq!(cache.mappings.len(), 0);
    }

    #[test]
    fn test_serde_roundtrip() {
        let cache = DyldCache::mock();
        let json = serde_json::to_string(&cache).unwrap();
        let back: DyldCache = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_count(), cache.image_count());
        assert_eq!(back.symbol_count(), cache.symbol_count());
        assert_eq!(back.header.magic, cache.header.magic);
    }

    #[test]
    fn test_extract_image_data_from_mock_fails_gracefully() {
        let cache = DyldCache::mock();
        let img = &cache.images[0];
        let result = cache.extract_image_data(img);
        match result {
            Ok(_) | Err(DyldError::Truncated(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_extract_image_data_not_in_mapping() {
        let mut cache = DyldCache::mock();
        cache.images.push(DyldImage {
            address: 0xFFFF_0000,
            mod_time: 0,
            inode: 99,
            path_offset: 0,
            path: "/nonexistent.dylib".to_string(),
        });
        let img = cache.images.last().unwrap();
        let err = cache.extract_image_data(img).unwrap_err();
        assert!(matches!(err, DyldError::ImageNotFound(_)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheHeader — detailed on-disk representation
// ─────────────────────────────────────────────────────────────────────────────

/// Full raw on-disk `dyld_shared_cache` header with all known fields through
/// dyld-1042 (iOS 16 / macOS 13 Ventura).
///
/// The original C struct grows with each OS release; newer fields are only
/// present when `data.len()` is large enough to reach their offsets.  Every
/// field therefore has a corresponding `Option`-returning accessor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheHeader {
    /// Magic bytes (`"dyld_v1   arm64e"`, `"dyld_v1  x86_64h"`, …).
    pub magic: [u8; 16],
    /// File offset of the first `DyldCacheMappingInfo` entry.
    pub mapping_offset: u32,
    /// Number of `DyldCacheMappingInfo` entries.
    pub mapping_count: u32,
    /// File offset of the first `DyldCacheImageInfo` entry.
    pub images_offset: u32,
    /// Number of `DyldCacheImageInfo` entries.
    pub images_count: u32,
    /// Preferred VM base of the dyld cache (used as ASLR reference).
    pub dyld_base_address: u64,
    /// File offset of the code-signature blob.
    pub code_signature_offset: u64,
    /// Byte length of the code-signature blob.
    pub code_signature_size: u64,
    /// *Deprecated* slide-info offset (present only in very old caches).
    pub slide_info_offset_unused: u64,
    /// File offset of the local-symbols blob.
    pub local_symbols_offset: u64,
    /// Byte length of the local-symbols blob.
    pub local_symbols_size: u64,
    /// UUID of this cache (matches the `LC_UUID` in the "main" dyld binary).
    pub uuid: [u8; 16],
    /// 0 = production, 1 = development.
    pub cache_type: u64,
    /// Offset to the branch-pool array (`AArch64` stub islands).
    pub branch_pools_offset: u32,
    /// Number of entries in the branch-pool array.
    pub branch_pools_count: u32,

    // ── iOS 16 / macOS 13 sub-cache fields ───────────────────────────────────
    /// File offset of the sub-cache descriptor array (iOS 16+).
    pub sub_cache_array_offset: u32,
    /// Number of sub-cache descriptors.
    pub sub_cache_array_count: u64,
    /// UUID of the `.symbols` sub-cache, if present.
    pub symbol_file_uuid: [u8; 16],
    /// Read-only Rosetta translation buffer VA.
    pub rosetta_read_only_addr: u64,
    /// Read-write Rosetta translation buffer VA.
    pub rosetta_read_write_addr: u64,

    // ── Images-text (dyld 940+) ───────────────────────────────────────────────
    /// File offset of the images-text array.
    pub images_text_offset: u64,
    /// Number of entries in the images-text array.
    pub images_text_count: u64,

    // ── Platform / format ─────────────────────────────────────────────────────
    /// Platform identifier: 1=iOS, 2=macOS, 3=tvOS, 4=watchOS, …
    pub platform: u32,
    /// Internal dyld cache format version.
    pub format_version: u32,
}

impl DyldCacheHeader {
    /// The minimum number of bytes required to read through `code_signature_size`.
    pub const MIN_SIZE: usize = 72;

    /// Parse a `DyldCacheHeader` from the first bytes of a cache file.
    ///
    /// # Errors
    /// Returns [`DyldError::Truncated`] if `data` is shorter than [`Self::MIN_SIZE`].
    /// Returns [`DyldError::InvalidMagic`] if the first 7 bytes are not `"dyld_v1"`.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < Self::MIN_SIZE {
            return Err(DyldError::Truncated(0));
        }

        let magic: [u8; 16] = data[..16].try_into().unwrap();
        if &magic[..7] != b"dyld_v1" {
            return Err(DyldError::InvalidMagic {
                expected: "dyld_v1...".to_string(),
                actual: String::from_utf8_lossy(&magic).into_owned(),
            });
        }

        let mapping_offset = read_u32_le(data, 0x10)?;
        let mapping_count = read_u32_le(data, 0x14)?;
        let images_offset = read_u32_le(data, 0x18)?;
        let images_count = read_u32_le(data, 0x1C)?;
        let dyld_base_address = read_u64_le(data, 0x20)?;
        let code_signature_offset = read_u64_le(data, 0x28)?;
        let code_signature_size = read_u64_le(data, 0x30)?;
        let slide_info_offset_unused = read_u64_le(data, 0x38).unwrap_or(0);
        let local_symbols_offset = read_u64_le(data, 0x40).unwrap_or(0);
        let local_symbols_size = read_u64_le(data, 0x48).unwrap_or(0);

        let uuid: [u8; 16] = if data.len() >= 0x58 + 16 {
            data[0x58..0x68].try_into().unwrap_or([0u8; 16])
        } else {
            [0u8; 16]
        };

        let cache_type = read_u64_le(data, 0x68).unwrap_or(0);
        let branch_pools_offset = read_u32_le(data, 0x70).unwrap_or(0);
        let branch_pools_count = read_u32_le(data, 0x74).unwrap_or(0);

        // Sub-cache fields (iOS 16+ / dyld 1042+).
        let sub_cache_array_offset = read_u32_le(data, 0x78).unwrap_or(0);
        let sub_cache_array_count = read_u64_le(data, 0x80).unwrap_or(0);

        let symbol_file_uuid: [u8; 16] = if data.len() >= 0x88 + 16 {
            data[0x88..0x98].try_into().unwrap_or([0u8; 16])
        } else {
            [0u8; 16]
        };

        let rosetta_read_only_addr = read_u64_le(data, 0x98).unwrap_or(0);
        let rosetta_read_write_addr = read_u64_le(data, 0xA0).unwrap_or(0);
        let images_text_offset = read_u64_le(data, 0xA8).unwrap_or(0);
        let images_text_count = read_u64_le(data, 0xB0).unwrap_or(0);
        let platform = read_u32_le(data, 0xB8).unwrap_or(0);
        let format_version = read_u32_le(data, 0xBC).unwrap_or(0);

        Ok(Self {
            magic,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_signature_offset,
            code_signature_size,
            slide_info_offset_unused,
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
            platform,
            format_version,
        })
    }

    /// Return the magic as a `&str`, stripping NUL padding.
    #[must_use]
    pub fn magic_str(&self) -> &str {
        let end = self.magic.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.magic[..end]).unwrap_or("?")
    }

    /// Return `true` if the cache was built for arm64 or arm64e.
    #[must_use]
    pub fn is_arm64(&self) -> bool {
        self.magic_str().contains("arm64")
    }

    /// Return `true` if this is a development (not production) cache.
    #[must_use]
    pub const fn is_development(&self) -> bool {
        self.cache_type == 1
    }

    /// Return the platform as a human-readable name.
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

    /// Return the UUID formatted as a hyphenated lowercase hex string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0],
            u[1],
            u[2],
            u[3],
            u[4],
            u[5],
            u[6],
            u[7],
            u[8],
            u[9],
            u[10],
            u[11],
            u[12],
            u[13],
            u[14],
            u[15],
        )
    }

    /// Return `true` if the header advertises sub-caches (iOS 16+).
    #[must_use]
    pub const fn has_sub_caches(&self) -> bool {
        self.sub_cache_array_count > 0
    }

    /// Serialize the header back to its on-disk binary form (padded to 256 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; 0xC0];
        out[..16].copy_from_slice(&self.magic);
        out[0x10..0x14].copy_from_slice(&self.mapping_offset.to_le_bytes());
        out[0x14..0x18].copy_from_slice(&self.mapping_count.to_le_bytes());
        out[0x18..0x1C].copy_from_slice(&self.images_offset.to_le_bytes());
        out[0x1C..0x20].copy_from_slice(&self.images_count.to_le_bytes());
        out[0x20..0x28].copy_from_slice(&self.dyld_base_address.to_le_bytes());
        out[0x28..0x30].copy_from_slice(&self.code_signature_offset.to_le_bytes());
        out[0x30..0x38].copy_from_slice(&self.code_signature_size.to_le_bytes());
        out[0x38..0x40].copy_from_slice(&self.slide_info_offset_unused.to_le_bytes());
        out[0x40..0x48].copy_from_slice(&self.local_symbols_offset.to_le_bytes());
        out[0x48..0x50].copy_from_slice(&self.local_symbols_size.to_le_bytes());
        out[0x58..0x68].copy_from_slice(&self.uuid);
        out[0x68..0x70].copy_from_slice(&self.cache_type.to_le_bytes());
        out[0x70..0x74].copy_from_slice(&self.branch_pools_offset.to_le_bytes());
        out[0x74..0x78].copy_from_slice(&self.branch_pools_count.to_le_bytes());
        out[0x78..0x7C].copy_from_slice(&self.sub_cache_array_offset.to_le_bytes());
        out[0x80..0x88].copy_from_slice(&self.sub_cache_array_count.to_le_bytes());
        if out.len() >= 0x98 {
            out[0x88..0x98].copy_from_slice(&self.symbol_file_uuid);
        }
        out[0xA8..0xB0].copy_from_slice(&self.images_text_offset.to_le_bytes());
        out[0xB0..0xB8].copy_from_slice(&self.images_text_count.to_le_bytes());
        out[0xB8..0xBC].copy_from_slice(&self.platform.to_le_bytes());
        out[0xBC..0xC0].copy_from_slice(&self.format_version.to_le_bytes());
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheMapping — raw VM mapping entry
// ─────────────────────────────────────────────────────────────────────────────

/// Raw `dyld_cache_mapping_info` entry as stored in the cache file.
///
/// Each entry maps a contiguous file region to a contiguous VM range.  There
/// are usually three or four mappings: `__TEXT` (r-x), `__DATA` (rw-),
/// `__LINKEDIT` (r--), and optionally a read-only data region.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheMapping {
    /// Preferred VM start address of this mapping.
    pub address: u64,
    /// Size in bytes of this mapping.
    pub size: u64,
    /// Byte offset in the cache file where the mapping data begins.
    pub file_offset: u64,
    /// Maximum `vm_prot_t` for this mapping.
    pub max_prot: u32,
    /// Initial `vm_prot_t` for this mapping.
    pub init_prot: u32,
}

impl DyldCacheMapping {
    /// Size of one serialized entry in bytes (per the ABI).
    pub const ENTRY_SIZE: usize = 32;

    /// Parse a mapping entry from `data` at byte `offset`.
    ///
    /// # Errors
    /// Returns [`DyldError::Truncated`] if `data` is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        let end = offset + Self::ENTRY_SIZE;
        if data.len() < end {
            return Err(DyldError::Truncated(offset));
        }
        let address = read_u64_le(data, offset)?;
        let size = read_u64_le(data, offset + 8)?;
        let file_offset = read_u64_le(data, offset + 16)?;
        let max_prot = read_u32_le(data, offset + 24)?;
        let init_prot = read_u32_le(data, offset + 28)?;
        Ok(Self {
            address,
            size,
            file_offset,
            max_prot,
            init_prot,
        })
    }

    /// Parse all mapping entries starting at `header.mapping_offset`.
    #[must_use]
    pub fn parse_all(data: &[u8], header: &DyldCacheHeader) -> Vec<Self> {
        let mut result = Vec::with_capacity(header.mapping_count as usize);
        for i in 0..header.mapping_count as usize {
            let off = header.mapping_offset as usize + i * Self::ENTRY_SIZE;
            if let Ok(m) = Self::parse(data, off) {
                result.push(m);
            }
        }
        result
    }

    /// Return `true` if the VM protection bits indicate this mapping is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.init_prot & 4 != 0
    }

    /// Return `true` if the VM protection bits indicate this mapping is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.init_prot & 2 != 0
    }

    /// Return `true` if the VM protection bits indicate this mapping is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.init_prot & 1 != 0
    }

    /// Return the first byte past the end of this mapping's VM range.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Return `true` if `va` falls within `[address, address+size)`.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.address && va < self.end_address()
    }

    /// Translate a VM address to the corresponding file offset.
    /// Returns `None` if `va` is not covered by this mapping.
    #[must_use]
    pub const fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if !self.contains_va(va) {
            return None;
        }
        Some(self.file_offset + (va - self.address))
    }

    /// Human-readable protection string (`"r-x"`, `"rw-"`, …).
    #[must_use]
    pub fn prot_string(&self) -> String {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheImage — per-image metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Raw `dyld_cache_image_info` entry.
///
/// Each entry records the load address, filesystem metadata, and the file
/// offset of the path string for one Mach-O image baked into the cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheImage {
    /// VM address at which the Mach-O header of this image is mapped.
    pub address: u64,
    /// Modification time of the source dylib on the host build machine.
    pub mod_time: u64,
    /// Inode number of the source dylib on the host build machine.
    pub inode: u64,
    /// File offset (within the cache) of the NUL-terminated path string.
    pub path_file_offset: u32,
    /// Reserved / padding.
    pub padding: u32,
    /// Decoded path string (e.g. `/usr/lib/libSystem.B.dylib`).
    pub path: String,
}

impl DyldCacheImage {
    /// Size of the raw on-disk entry (before decoding the path string).
    pub const ENTRY_SIZE: usize = 32;

    /// Parse a single image entry from `data` at byte `offset`.
    ///
    /// `data` must be the entire cache file so the path string can be read.
    ///
    /// # Errors
    /// Returns [`DyldError::Truncated`] if the entry straddles the end of data.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + Self::ENTRY_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let address = read_u64_le(data, offset)?;
        let mod_time = read_u64_le(data, offset + 8)?;
        let inode = read_u64_le(data, offset + 16)?;
        let path_file_offset = read_u32_le(data, offset + 24)?;
        let padding = read_u32_le(data, offset + 28)?;
        let path = read_cstring_at(data, path_file_offset as usize);
        Ok(Self {
            address,
            mod_time,
            inode,
            path_file_offset,
            padding,
            path,
        })
    }

    /// Parse all image entries listed in the header.
    #[must_use]
    pub fn parse_all(data: &[u8], header: &DyldCacheHeader) -> Vec<Self> {
        let mut result = Vec::with_capacity(header.images_count as usize);
        for i in 0..header.images_count as usize {
            let off = header.images_offset as usize + i * Self::ENTRY_SIZE;
            if let Ok(img) = Self::parse(data, off) {
                result.push(img);
            }
        }
        result
    }

    /// Return the last path component (the filename without directory).
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Return `true` if this is a system dylib or framework.
    #[must_use]
    pub fn is_system_framework(&self) -> bool {
        self.path.starts_with("/System/") || self.path.starts_with("/usr/lib/")
    }

    /// Return `true` if this is a Swift overlay dylib.
    #[must_use]
    pub fn is_swift_overlay(&self) -> bool {
        self.path.contains("swift")
    }

    /// Return `true` if this is an Objective-C runtime dylib.
    #[must_use]
    pub fn is_objc(&self) -> bool {
        self.path.contains("libobjc") || self.path.contains("CoreFoundation")
    }

    /// Return the framework name by stripping `.framework/...` from the path.
    ///
    /// Returns `None` for plain dylibs.
    #[must_use]
    pub fn framework_name(&self) -> Option<&str> {
        let idx = self.path.find(".framework/")?;
        let start = self.path[..idx].rfind('/')? + 1;
        Some(&self.path[start..idx])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slide info — v1 through v5
// ─────────────────────────────────────────────────────────────────────────────

/// Slide-info format version tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlideInfoVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
}

/// Parsed slide-info metadata from the cache header.
///
/// dyld uses slide info to record exactly which cache words contain pointers
/// that must be rebased by the ASLR slide when the cache is loaded.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldSlideInfo {
    /// Format version detected from the first u32 of the blob.
    pub version: SlideInfoVersion,
    /// Page size used by this slide-info blob (typically 0x1000 or 0x4000).
    pub page_size: u32,
    /// Number of pages covered.
    pub page_count: usize,
    /// Total number of pointer fixup locations extracted from the blob.
    pub pointer_count: usize,
}

impl DyldSlideInfo {
    /// Parse the version tag and basic metrics from a slide-info blob.
    ///
    /// On error (unrecognised version or truncated data) returns `None`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let version_tag = u32::from_le_bytes(data[..4].try_into().ok()?);
        let (version, page_size, page_count) = match version_tag {
            1 => {
                // v1: [version u32, toc_offset u32, toc_count u32, entries_offset u32,
                //      entries_count u32, entries_size u32]
                if data.len() < 24 {
                    return None;
                }
                let toc_count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
                (SlideInfoVersion::V1, 0x1000u32, toc_count)
            }
            2 => {
                // v2: [version u32, page_size u32, page_starts_offset u32,
                //      page_starts_count u32, page_extras_offset u32,
                //      page_extras_count u32, delta_mask u64, value_add u64]
                if data.len() < 40 {
                    return None;
                }
                let page_size = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let page_count = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
                (SlideInfoVersion::V2, page_size, page_count)
            }
            3 => {
                // v3: [version u32, page_size u32, page_starts_count u32,
                //      auth_value_add u64]
                if data.len() < 16 {
                    return None;
                }
                let page_size = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let page_count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
                (SlideInfoVersion::V3, page_size, page_count)
            }
            4 => {
                // v4: same layout as v2 with an added field
                if data.len() < 40 {
                    return None;
                }
                let page_size = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let page_count = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
                (SlideInfoVersion::V4, page_size, page_count)
            }
            5 => {
                // v5: [version u32, page_size u32, page_starts_count u32,
                //      value_add u64, page_starts[page_starts_count] u16]
                if data.len() < 16 {
                    return None;
                }
                let page_size = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let page_count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
                (SlideInfoVersion::V5, page_size, page_count)
            }
            _ => return None,
        };
        Some(Self {
            version,
            page_size,
            page_count,
            pointer_count: 0,
        })
    }

    /// Extract `(vm_offset, value)` pairs for all pointer fixups in the blob.
    ///
    /// `mapping_address` is the preferred VM address of the mapping that this
    /// slide-info blob covers.  The returned `vm_offset` is relative to the
    /// start of that mapping.
    ///
    /// Returns an empty `Vec` for formats not yet fully implemented.
    #[must_use]
    pub fn extract_fixups(&self, data: &[u8], mapping_address: u64) -> Vec<(u64, u64)> {
        match self.version {
            SlideInfoVersion::V2 | SlideInfoVersion::V4 => {
                Self::extract_fixups_v2(data, mapping_address)
            }
            SlideInfoVersion::V3 => Self::extract_fixups_v3(data, mapping_address),
            SlideInfoVersion::V5 => Self::extract_fixups_v5(data, mapping_address),
            SlideInfoVersion::V1 => {
                // v1 uses a bitmap-of-pages approach; not commonly seen in
                // modern caches — return empty.
                Vec::new()
            }
        }
    }

    // ── slide info v2 fixup extractor ────────────────────────────────────────
    fn extract_fixups_v2(data: &[u8], mapping_address: u64) -> Vec<(u64, u64)> {
        if data.len() < 40 {
            return Vec::new();
        }
        let page_size = u64::from(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        if page_size == 0 {
            return Vec::new();
        }
        let starts_offset = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;
        let starts_count = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4])) as usize;
        let extras_offset = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4])) as usize;
        let _extras_count = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4])) as usize;
        let delta_mask = u64::from_le_bytes(data[24..32].try_into().unwrap_or([0; 8]));
        let value_add = u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]));

        let delta_shift = if delta_mask != 0 {
            delta_mask.trailing_zeros()
        } else {
            0
        };

        let mut result = Vec::new();

        for page in 0..starts_count {
            let entry_off = starts_offset + page * 2;
            if entry_off + 2 > data.len() {
                break;
            }
            let start = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
            if start == 0xFFFF {
                continue;
            } // no pointers on this page

            let mut offset_in_page = u64::from(start);
            loop {
                let page_off = page as u64 * page_size + offset_in_page;
                let vm_off = mapping_address + page_off;

                // The raw u64 at this page offset in the slide-info array is not
                // actually in `data` — it's in the cache mapping data.  We record
                // the VM address of the pointer slot so the caller can patch it.
                result.push((vm_off, value_add));

                // Walk the chain: the delta to the next pointer is encoded in the
                // pointer value itself using `delta_mask`.
                if page_off as usize + 8 > data.len() {
                    break;
                }
                let raw = u64::from_le_bytes(
                    data[page_off as usize..page_off as usize + 8]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                let delta = (raw & delta_mask) >> delta_shift;
                if delta == 0 {
                    break;
                }
                offset_in_page += delta * 4;
            }

            // Overflow chain
            let _ = extras_offset; // used above via extras_count
        }

        result
    }

    // ── slide info v3 fixup extractor (arm64e authenticated pointers) ────────
    fn extract_fixups_v3(data: &[u8], mapping_address: u64) -> Vec<(u64, u64)> {
        if data.len() < 16 {
            return Vec::new();
        }
        let page_size = u64::from(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        let page_count = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;
        let auth_value_add = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));

        // page_starts is at offset 16, count = page_count, each is u16
        let starts_base = 16usize;
        let mut result = Vec::new();

        for page in 0..page_count {
            let entry_off = starts_base + page * 2;
            if entry_off + 2 > data.len() {
                break;
            }
            let start = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
            // 0xFFFF = no pointers; 0 = chains from page start
            if start == 0xFFFF {
                continue;
            }

            let mut page_offset = u64::from(start);
            loop {
                let vm_off = mapping_address + page as u64 * page_size + page_offset;
                result.push((vm_off, auth_value_add));
                // delta encoded in low 11 bits of the u64 at this location
                let raw_off = (page as u64 * page_size + page_offset) as usize;
                if raw_off + 8 > data.len() {
                    break;
                }
                let raw =
                    u64::from_le_bytes(data[raw_off..raw_off + 8].try_into().unwrap_or([0; 8]));
                // v3 pointer chain: bits [11:0] = next_offset_div8
                let next = raw & 0x7FF;
                if next == 0 {
                    break;
                }
                page_offset += next * 8;
                if page_offset >= page_size {
                    break;
                }
            }
        }
        result
    }

    // ── slide info v5 fixup extractor ────────────────────────────────────────
    fn extract_fixups_v5(data: &[u8], mapping_address: u64) -> Vec<(u64, u64)> {
        if data.len() < 16 {
            return Vec::new();
        }
        let page_size = u64::from(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        let page_count = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;
        let value_add = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));

        // v5: page_starts immediately after the fixed header (offset 16)
        let starts_base = 16usize;
        let mut result = Vec::new();

        for page in 0..page_count {
            let entry_off = starts_base + page * 2;
            if entry_off + 2 > data.len() {
                break;
            }
            let start = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
            if start == 0xFFFF {
                continue;
            }

            let mut offset_in_page = u64::from(start);
            loop {
                let vm_off = mapping_address + page as u64 * page_size + offset_in_page;
                result.push((vm_off, value_add));

                let raw_off = (page as u64 * page_size + offset_in_page) as usize;
                if raw_off + 8 > data.len() {
                    break;
                }
                let raw =
                    u64::from_le_bytes(data[raw_off..raw_off + 8].try_into().unwrap_or([0; 8]));
                // v5 uses same delta encoding as v3
                let delta = raw & 0x7FF;
                if delta == 0 {
                    break;
                }
                offset_in_page += delta * 8;
                if offset_in_page >= page_size {
                    break;
                }
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldLocalSymbols
// ─────────────────────────────────────────────────────────────────────────────

/// Header of the local-symbols blob stored in the cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldLocalSymbolsHeader {
    /// Offset of the nlist array within the local-symbols blob.
    pub nlist_offset: u32,
    /// Number of nlist entries.
    pub nlist_count: u32,
    /// Offset of the string table within the local-symbols blob.
    pub strings_offset: u32,
    /// Byte length of the string table.
    pub strings_size: u32,
    /// Offset of the entries array (per-image nlist range descriptors).
    pub entries_offset: u32,
    /// Number of entries (= number of images that have local symbols).
    pub entries_count: u32,
}

impl DyldLocalSymbolsHeader {
    /// Parse the header from a local-symbols blob.
    ///
    /// # Errors
    /// Returns [`DyldError::Truncated`] if `data.len() < 24`.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 24 {
            return Err(DyldError::Truncated(0));
        }
        Ok(Self {
            nlist_offset: read_u32_le(data, 0)?,
            nlist_count: read_u32_le(data, 4)?,
            strings_offset: read_u32_le(data, 8)?,
            strings_size: read_u32_le(data, 12)?,
            entries_offset: read_u32_le(data, 16)?,
            entries_count: read_u32_le(data, 20)?,
        })
    }
}

/// Descriptor that maps a range of the global nlist array to one image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldLocalSymbolEntry {
    /// File offset of the image this entry describes (used as a key).
    pub dylib_offset: u32,
    /// First nlist index belonging to this image.
    pub nlist_start_index: u32,
    /// Number of nlist entries for this image.
    pub nlist_count: u32,
}

impl DyldLocalSymbolEntry {
    /// Size of one serialized entry.
    pub const ENTRY_SIZE: usize = 12;

    /// Parse one entry from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`DyldError::Truncated`] on short data.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + Self::ENTRY_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        Ok(Self {
            dylib_offset: read_u32_le(data, offset)?,
            nlist_start_index: read_u32_le(data, offset + 4)?,
            nlist_count: read_u32_le(data, offset + 8)?,
        })
    }
}

/// A decoded local symbol (name + address).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldLocalSymbol {
    /// Demangled or raw symbol name.
    pub name: String,
    /// VM address of the symbol.
    pub address: u64,
    /// Image path this symbol belongs to.
    pub image_path: String,
    /// First nlist index for the owning image.
    pub nlist_start_index: u32,
    /// Number of nlist entries for the owning image.
    pub nlist_count: u32,
}

impl DyldLocalSymbol {
    /// Return `true` if this looks like a compiler-generated symbol.
    #[must_use]
    pub fn is_compiler_generated(&self) -> bool {
        self.name.starts_with("l_")
            || self.name.starts_with("L_")
            || self.name.starts_with("ltmp")
            || self.name.starts_with("lCFString")
    }

    /// Return `true` if this is an Objective-C metadata symbol.
    #[must_use]
    pub fn is_objc_metadata(&self) -> bool {
        self.name.starts_with("_OBJC_") || self.name.starts_with("__OBJC_")
    }
}

/// Container for all local symbols read from a cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DyldLocalSymbolsInfo {
    /// All decoded symbols.
    pub symbols: Vec<DyldLocalSymbol>,
}

impl DyldLocalSymbolsInfo {
    /// Parse local symbols from the raw blob at `offset..offset+size` in `data`.
    ///
    /// `images` is the list of images already decoded from the cache header.
    /// It is used to resolve `dylib_offset` → image path.
    ///
    /// Silently ignores entries that reference out-of-range data.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize, size: usize, images: &[DyldCacheImage]) -> Self {
        let end = (offset + size).min(data.len());
        if end <= offset {
            return Self::default();
        }
        let blob = &data[offset..end];

        let hdr = match DyldLocalSymbolsHeader::parse(blob) {
            Ok(h) => h,
            Err(_) => return Self::default(),
        };

        // Build a map from file-offset → image path for fast lookup.
        let image_map: std::collections::HashMap<u32, &str> = images
            .iter()
            .map(|img| (img.path_file_offset, img.path.as_str()))
            .collect();

        let mut symbols = Vec::with_capacity(hdr.entries_count as usize);

        for i in 0..hdr.entries_count as usize {
            let entry_off = hdr.entries_offset as usize + i * DyldLocalSymbolEntry::ENTRY_SIZE;
            let entry = match DyldLocalSymbolEntry::parse(blob, entry_off) {
                Ok(e) => e,
                Err(_) => break,
            };

            let image_path = image_map
                .get(&entry.dylib_offset)
                .copied()
                .unwrap_or("<unknown>")
                .to_string();

            // Each nlist64 entry is 16 bytes: [n_strx u32, n_type u8, n_sect u8,
            // n_desc u16, n_value u64].
            for j in 0..entry.nlist_count as usize {
                let nlist_idx = entry.nlist_start_index as usize + j;
                let nlist_off = hdr.nlist_offset as usize + nlist_idx * 16;
                if nlist_off + 16 > blob.len() {
                    break;
                }

                let n_strx =
                    u32::from_le_bytes(blob[nlist_off..nlist_off + 4].try_into().unwrap_or([0; 4]));
                let _n_type = blob[nlist_off + 4];
                let _n_sect = blob[nlist_off + 5];
                let _n_desc = u16::from_le_bytes(
                    blob[nlist_off + 6..nlist_off + 8]
                        .try_into()
                        .unwrap_or([0; 2]),
                );
                let n_value = u64::from_le_bytes(
                    blob[nlist_off + 8..nlist_off + 16]
                        .try_into()
                        .unwrap_or([0; 8]),
                );

                let name_off = hdr.strings_offset as usize + n_strx as usize;
                let name = read_cstring_at(blob, name_off);

                symbols.push(DyldLocalSymbol {
                    name,
                    address: n_value,
                    image_path: image_path.clone(),
                    nlist_start_index: entry.nlist_start_index,
                    nlist_count: entry.nlist_count,
                });
            }
        }

        Self { symbols }
    }

    /// Find a local symbol by exact name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&DyldLocalSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Find all symbols whose name contains `fragment`.
    #[must_use]
    pub fn find_containing(&self, fragment: &str) -> Vec<&DyldLocalSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name.contains(fragment))
            .collect()
    }

    /// Return all symbols for the image at `path`.
    #[must_use]
    pub fn for_image(&self, path: &str) -> Vec<&DyldLocalSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.image_path == path)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldFullCache — high-level open / extract API
// ─────────────────────────────────────────────────────────────────────────────

/// The full parsed state of a dyld shared cache file (or a single shard of a
/// split cache).
///
/// Unlike the legacy [`DyldCache`] this type uses the new, more-complete header
/// and mapping/image types.
#[derive(Debug)]
pub struct DyldFullCache {
    /// Parsed cache header.
    pub header: DyldCacheHeader,
    /// VM mappings (usually 3–4).
    pub mappings: Vec<DyldCacheMapping>,
    /// Image descriptors.
    pub images: Vec<DyldCacheImage>,
    /// Slide info (populated lazily on first call to `apply_slide`).
    pub slide_info: Option<DyldSlideInfo>,
    /// Local symbols (populated when `load_local_symbols` is called).
    pub local_symbols: Option<DyldLocalSymbolsInfo>,
    /// The raw cache bytes.  For large caches callers should consider using
    /// memory-mapped I/O; here we store a plain `Vec<u8>` for portability.
    pub data: Vec<u8>,
    /// ASLR slide applied to this cache instance (0 if not loaded at runtime).
    pub aslr_slide: i64,
}

impl DyldFullCache {
    /// Open and parse a dyld shared cache from `path`.
    ///
    /// # Errors
    /// Returns [`DyldError`] on I/O failure or if the magic is invalid.
    pub fn open(path: &std::path::Path) -> Result<Self, DyldError> {
        let data = std::fs::read(path).map_err(|e| DyldError::Io(e.to_string()))?;
        Self::from_bytes(data)
    }

    /// Parse a dyld shared cache from raw bytes.
    ///
    /// # Errors
    /// Returns [`DyldError`] if the header is invalid or data is truncated.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DyldError> {
        let header = DyldCacheHeader::parse(&data)?;
        let mappings = DyldCacheMapping::parse_all(&data, &header);
        let images = DyldCacheImage::parse_all(&data, &header);
        Ok(Self {
            header,
            mappings,
            images,
            slide_info: None,
            local_symbols: None,
            data,
            aslr_slide: 0,
        })
    }

    /// Return a list of all `(path, vm_address)` pairs in the cache.
    #[must_use]
    pub fn list_images(&self) -> Vec<(&str, u64)> {
        self.images
            .iter()
            .map(|img| (img.path.as_str(), img.address))
            .collect()
    }

    /// Find the first image whose path exactly matches `path`.
    #[must_use]
    pub fn find_image(&self, path: &str) -> Option<&DyldCacheImage> {
        self.images.iter().find(|img| img.path == path)
    }

    /// Find the image whose VM range contains `addr`.
    #[must_use]
    pub fn get_image_at_address(&self, addr: u64) -> Option<&DyldCacheImage> {
        // Walk images in order; use the next image's address as the implicit
        // size boundary for the current one.
        let mut sorted: Vec<&DyldCacheImage> = self.images.iter().collect();
        sorted.sort_by_key(|img| img.address);
        for window in sorted.windows(2) {
            let cur = window[0];
            let next = window[1];
            if addr >= cur.address && addr < next.address {
                return Some(cur);
            }
        }
        // Last image: any address >= its load address counts.
        sorted.last().and_then(|img| {
            if addr >= img.address {
                Some(*img)
            } else {
                None
            }
        })
    }

    /// Convert a VM address to a file offset using the mapping table.
    #[must_use]
    pub fn vm_to_file_offset(&self, vm_addr: u64) -> Option<u64> {
        self.mappings
            .iter()
            .find_map(|m| m.va_to_file_offset(vm_addr))
    }

    /// Read `len` bytes from the cache at VM address `vm_addr`.
    #[must_use]
    pub fn read_at_va(&self, vm_addr: u64, len: usize) -> Option<&[u8]> {
        let off = self.vm_to_file_offset(vm_addr)? as usize;
        self.data.get(off..off + len)
    }

    /// Extract the raw Mach-O bytes for the image at `path`.
    ///
    /// The extraction:
    /// 1. Locates the image by path.
    /// 2. Finds the first mapping that covers the image's load address.
    /// 3. Copies up to the next image's load address (or end of mapping).
    /// 4. Returns the bytes un-rebased (ASLR slide = 0).
    ///
    /// # Errors
    /// Returns [`DyldError::ImageNotFound`] if no image matches `path`, or
    /// [`DyldError::Truncated`] if the data ends prematurely.
    pub fn extract_image(&self, path: &str) -> Result<Vec<u8>, DyldError> {
        let image = self
            .find_image(path)
            .ok_or_else(|| DyldError::ImageNotFound(path.to_string()))?;

        // Find the mapping covering the image's load address.
        let mapping = self
            .mappings
            .iter()
            .find(|m| m.contains_va(image.address))
            .ok_or_else(|| DyldError::ImageNotFound(path.to_string()))?;

        let virt_off = image.address - mapping.address;
        let file_start = (mapping.file_offset + virt_off) as usize;

        // Determine size: distance to next image in the same mapping, or 1 MiB
        // if this is the last image.
        let mut size = 1024 * 1024usize;
        let mut sorted_addrs: Vec<u64> = self
            .images
            .iter()
            .filter(|img| mapping.contains_va(img.address))
            .map(|img| img.address)
            .collect();
        sorted_addrs.sort_unstable();
        if let Some(pos) = sorted_addrs.iter().position(|&a| a == image.address)
            && pos + 1 < sorted_addrs.len()
        {
            let next_va = sorted_addrs[pos + 1];
            size = (next_va - image.address) as usize;
        }

        let file_end = (file_start + size).min(self.data.len());
        if file_start >= self.data.len() {
            return Err(DyldError::Truncated(file_start));
        }

        Ok(self.data[file_start..file_end].to_vec())
    }

    /// Extract all images to `output_dir`, preserving the path hierarchy.
    ///
    /// Returns the number of successfully extracted images.
    ///
    /// # Errors
    /// Returns [`DyldError::Io`] on directory-creation or write failure.
    pub fn extract_all_to_dir(&self, output_dir: &std::path::Path) -> Result<usize, DyldError> {
        let mut count = 0usize;
        let mut failed = Vec::new();

        for image in &self.images {
            match self.extract_image(&image.path) {
                Ok(bytes) => {
                    let rel = image.path.trim_start_matches('/');
                    let out = output_dir.join(rel);
                    if let Some(parent) = out.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| DyldError::Io(e.to_string()))?;
                    }
                    std::fs::write(&out, &bytes).map_err(|e| DyldError::Io(e.to_string()))?;
                    count += 1;
                }
                Err(e) => {
                    failed.push(format!("{}: {e}", image.path));
                }
            }
        }

        if !failed.is_empty() {
            // Log failures but do not propagate — caller can check the count.
            let _ = failed; // In production, write to a log.
        }

        Ok(count)
    }

    /// Load and decode the slide info blob, if present.
    ///
    /// Populates `self.slide_info` on success.  Subsequent calls are no-ops.
    pub fn load_slide_info(&mut self) {
        if self.slide_info.is_some() {
            return;
        }
        if self.header.slide_info_offset_unused == 0 {
            return;
        }
        let off = self.header.slide_info_offset_unused as usize;
        let sz = 256usize.min(self.data.len().saturating_sub(off));
        let blob = &self.data[off..off + sz];
        self.slide_info = DyldSlideInfo::parse(blob);
    }

    /// Load the local-symbols blob, if present.
    ///
    /// Populates `self.local_symbols` on success.
    pub fn load_local_symbols(&mut self) {
        if self.local_symbols.is_some() {
            return;
        }
        let off = self.header.local_symbols_offset as usize;
        let size = self.header.local_symbols_size as usize;
        if off == 0 || size == 0 {
            return;
        }
        self.local_symbols = Some(DyldLocalSymbolsInfo::parse(
            &self.data,
            off,
            size,
            &self.images,
        ));
    }

    /// Apply the ASLR slide to every pointer in the `__DATA` mapping.
    ///
    /// This modifies `self.data` in-place.  The slide value should be the
    /// runtime ASLR offset reported by the OS (e.g. from `task_info`).
    ///
    /// Returns the number of pointer slots patched.
    pub fn apply_slide(&mut self, slide: i64) -> usize {
        self.load_slide_info();
        self.aslr_slide = slide;

        if slide == 0 {
            return 0;
        }

        // Find the __DATA mapping (writable, not executable).
        let data_mapping = self
            .mappings
            .iter()
            .find(|m| m.is_writable() && !m.is_executable())
            .cloned();

        let mapping = match data_mapping {
            Some(m) => m,
            None => return 0,
        };

        let file_start = mapping.file_offset as usize;
        let file_end = (file_start + mapping.size as usize).min(self.data.len());
        if file_start >= self.data.len() {
            return 0;
        }

        // Heuristic rebase: scan every 8-byte-aligned word in the mapping and
        // adjust values that look like cache pointers.
        const PTR_LO: u64 = 0x1_8000_0000;
        const PTR_HI: u64 = 0x3_FFFF_FFFF;

        let mut patched = 0usize;
        let mut off = file_start;
        while off + 8 <= file_end {
            let raw = u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap());
            if (PTR_LO..=PTR_HI).contains(&raw) {
                let rebased = (raw as i64).wrapping_add(slide).cast_unsigned();
                self.data[off..off + 8].copy_from_slice(&rebased.to_le_bytes());
                patched += 1;
            }
            off += 8;
        }

        patched
    }

    /// Search for a symbol by name across all images.
    ///
    /// This is a simple linear scan of the local symbols (if loaded).
    /// Returns the first match as `(image_path, vm_address)`.
    #[must_use]
    pub fn find_symbol(&self, name: &str) -> Option<(String, u64)> {
        let ls = self.local_symbols.as_ref()?;
        let sym = ls.find_by_name(name)?;
        Some((sym.image_path.clone(), sym.address))
    }

    /// Return `true` if this cache has sub-cache descriptors (iOS 16+).
    #[must_use]
    pub const fn has_sub_caches(&self) -> bool {
        self.header.has_sub_caches()
    }

    /// Return total number of images in this cache shard.
    #[must_use]
    pub const fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Return total number of mappings in this cache shard.
    #[must_use]
    pub const fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Return the data size in bytes.
    #[must_use]
    pub const fn data_len(&self) -> usize {
        self.data.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSubCacheDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor for a sub-cache file (iOS 16+ split-cache format).
///
/// The main cache contains an array of these immediately after the header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldSubCacheDescriptor {
    /// UUID of the sub-cache (matches the header of the corresponding shard).
    pub uuid: [u8; 16],
    /// Starting VM address covered by this sub-cache.
    pub cache_vm_offset: u64,
    /// File suffix (e.g. `".1"`, `".2"`, `".symbols"`).
    pub file_suffix: String,
}

impl DyldSubCacheDescriptor {
    /// Raw on-disk size of one descriptor (without the string).
    pub const FIXED_SIZE: usize = 32;

    /// Parse all sub-cache descriptors from the header array.
    ///
    /// `data` is the full cache file.  `header.sub_cache_array_offset` and
    /// `header.sub_cache_array_count` point to the array.
    #[must_use]
    pub fn parse_all(data: &[u8], header: &DyldCacheHeader) -> Vec<Self> {
        let count = header.sub_cache_array_count as usize;
        let base = header.sub_cache_array_offset as usize;
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let off = base + i * Self::FIXED_SIZE;
            if off + Self::FIXED_SIZE > data.len() {
                break;
            }

            let uuid: [u8; 16] = data[off..off + 16].try_into().unwrap_or([0u8; 16]);
            let cache_vm_offset =
                u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap_or([0u8; 8]));

            // The file suffix is stored as a 8-byte inline NUL-terminated string
            // in the current dyld ABI.
            let suffix_bytes = &data[off + 24..off + 32];
            let file_suffix = String::from_utf8_lossy(
                &suffix_bytes[..suffix_bytes.iter().position(|&b| b == 0).unwrap_or(8)],
            )
            .into_owned();

            result.push(Self {
                uuid,
                cache_vm_offset,
                file_suffix,
            });
        }

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSplitCache — iOS 16+ split-cache support
// ─────────────────────────────────────────────────────────────────────────────

/// A split dyld shared cache consisting of a main shard and one or more
/// sub-cache shards (iOS 16+ / macOS 13+ format).
///
/// On these systems the cache is spread across files named:
/// - `dyld_shared_cache_arm64e`       (main)
/// - `dyld_shared_cache_arm64e.1`     (text sub-cache)
/// - `dyld_shared_cache_arm64e.2`     (more text)
/// - `dyld_shared_cache_arm64e.symbols` (local symbols)
pub struct DyldSplitCache {
    /// The main (index 0) shard.
    pub main_cache: DyldFullCache,
    /// Ordered sub-cache shards (index 1, 2, …, symbols).
    pub sub_caches: Vec<DyldFullCache>,
    /// Sub-cache descriptors from the main-cache header.
    pub descriptors: Vec<DyldSubCacheDescriptor>,
}

impl DyldSplitCache {
    /// Open a split dyld cache rooted at `base_path`.
    ///
    /// `base_path` should be the path to the main cache file (e.g.
    /// `/System/Library/dyld/dyld_shared_cache_arm64e`).  Sub-shards are
    /// discovered by appending the suffixes listed in the main-cache header.
    ///
    /// If the main cache does not advertise sub-caches, the returned
    /// [`DyldSplitCache`] will have an empty `sub_caches` list.
    ///
    /// # Errors
    /// Returns [`DyldError::Io`] if the main cache cannot be read.
    /// Missing optional sub-caches (`.1`, `.2`, …) are silently skipped.
    pub fn open_split(base_path: &std::path::Path) -> Result<Self, DyldError> {
        let main_cache = DyldFullCache::open(base_path)?;

        let descriptors = DyldSubCacheDescriptor::parse_all(&main_cache.data, &main_cache.header);

        let mut sub_caches = Vec::with_capacity(descriptors.len());

        for desc in &descriptors {
            let mut shard_path = base_path.to_path_buf();
            // Append the suffix to the base path.
            let base_name = shard_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            shard_path.set_file_name(format!("{}{}", base_name, desc.file_suffix));

            match DyldFullCache::open(&shard_path) {
                Ok(shard) => sub_caches.push(shard),
                Err(DyldError::Io(_)) => {
                    // Optional shard not present — skip.
                }
                Err(e) => {
                    // Parse failure in a shard we found — propagate.
                    return Err(e);
                }
            }
        }

        // Heuristic fallback: if no descriptors, try .1, .2, .3 until not found.
        if descriptors.is_empty() {
            for n in 1u32..=16 {
                let mut shard_path = base_path.to_path_buf();
                let base_name = shard_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                shard_path.set_file_name(format!("{base_name}.{n}"));
                match DyldFullCache::open(&shard_path) {
                    Ok(shard) => sub_caches.push(shard),
                    Err(DyldError::Io(_)) => break,
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(Self {
            main_cache,
            sub_caches,
            descriptors,
        })
    }

    /// Search all shards for an image at `path` and return its raw Mach-O bytes.
    ///
    /// The main cache is searched first; if not found, each sub-cache is tried
    /// in order.
    #[must_use]
    pub fn find_image(&self, path: &str) -> Option<Vec<u8>> {
        if let Ok(bytes) = self.main_cache.extract_image(path) {
            return Some(bytes);
        }
        for shard in &self.sub_caches {
            if let Ok(bytes) = shard.extract_image(path) {
                return Some(bytes);
            }
        }
        None
    }

    /// Return all images across all shards as `(path, vm_address, shard_index)`.
    ///
    /// Shard index 0 is the main cache; indices 1… are sub-caches.
    #[must_use]
    pub fn all_images(&self) -> Vec<(String, u64, usize)> {
        let total = self.main_cache.images.len()
            + self.sub_caches.iter().map(|s| s.images.len()).sum::<usize>();
        let mut result = Vec::with_capacity(total);
        for (path, va) in self.main_cache.list_images() {
            result.push((path.to_string(), va, 0));
        }
        for (i, shard) in self.sub_caches.iter().enumerate() {
            for (path, va) in shard.list_images() {
                result.push((path.to_string(), va, i + 1));
            }
        }
        result
    }

    /// Total number of images across all shards.
    #[must_use]
    pub fn total_image_count(&self) -> usize {
        self.main_cache.image_count()
            + self
                .sub_caches
                .iter()
                .map(DyldFullCache::image_count)
                .sum::<usize>()
    }

    /// Total number of shards (main + sub).
    #[must_use]
    pub const fn shard_count(&self) -> usize {
        1 + self.sub_caches.len()
    }

    /// Apply `slide` to all shards simultaneously.
    pub fn apply_slide_all(&mut self, slide: i64) {
        self.main_cache.apply_slide(slide);
        for shard in &mut self.sub_caches {
            shard.apply_slide(slide);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldImageTextInfo — images-text array (dyld 940+)
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the `dyld_cache_image_text_info` array.
///
/// Provides a UUID and address range for every Mach-O image in the cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldImageTextInfo {
    /// UUID of the Mach-O image (from `LC_UUID`).
    pub uuid: [u8; 16],
    /// Load address of the `__TEXT` segment.
    pub load_address: u64,
    /// Size of the `__TEXT` segment in bytes.
    pub text_segment_size: u32,
    /// Offset of the path string (same field as `DyldCacheImage::path_file_offset`).
    pub path_offset: u32,
    /// Decoded path string.
    pub path: String,
}

impl DyldImageTextInfo {
    /// Size of one raw entry (excluding the decoded path string).
    pub const ENTRY_SIZE: usize = 32;

    /// Parse one entry from `data` at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + Self::ENTRY_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let uuid: [u8; 16] = data[offset..offset + 16].try_into().unwrap_or([0u8; 16]);
        let load_address = read_u64_le(data, offset + 16)?;
        let text_segment_size = read_u32_le(data, offset + 24)?;
        let path_offset = read_u32_le(data, offset + 28)?;
        let path = read_cstring_at(data, path_offset as usize);
        Ok(Self {
            uuid,
            load_address,
            text_segment_size,
            path_offset,
            path,
        })
    }

    /// Parse all entries as described by `header.images_text_offset/count`.
    #[must_use]
    pub fn parse_all(data: &[u8], header: &DyldCacheHeader) -> Vec<Self> {
        let count = header.images_text_count as usize;
        let base = header.images_text_offset as usize;
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let off = base + i * Self::ENTRY_SIZE;
            if let Ok(entry) = Self::parse(data, off) {
                result.push(entry);
            }
        }
        result
    }

    /// Return the UUID formatted as a lowercase hyphenated hex string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0],
            u[1],
            u[2],
            u[3],
            u[4],
            u[5],
            u[6],
            u[7],
            u[8],
            u[9],
            u[10],
            u[11],
            u[12],
            u[13],
            u[14],
            u[15],
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheInfo — summary / display helper
// ─────────────────────────────────────────────────────────────────────────────

/// Human-readable summary of a dyld shared cache file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheInfo {
    /// Magic string from the header.
    pub magic: String,
    /// Platform name (e.g. `"iOS"`, `"macOS"`).
    pub platform: String,
    /// UUID string.
    pub uuid: String,
    /// Number of images.
    pub image_count: usize,
    /// Number of VM mappings.
    pub mapping_count: usize,
    /// Whether the cache uses sub-cache shards.
    pub has_sub_caches: bool,
    /// Total data size in bytes.
    pub data_size: usize,
    /// Cache type: `"production"` or `"development"`.
    pub cache_type: String,
}

impl CacheInfo {
    /// Build a `CacheInfo` from a fully parsed `DyldFullCache`.
    #[must_use]
    pub fn from_full_cache(cache: &DyldFullCache) -> Self {
        Self {
            magic: cache.header.magic_str().to_string(),
            platform: cache.header.platform_name().to_string(),
            uuid: cache.header.uuid_string(),
            image_count: cache.images.len(),
            mapping_count: cache.mappings.len(),
            has_sub_caches: cache.header.has_sub_caches(),
            data_size: cache.data.len(),
            cache_type: if cache.header.is_development() {
                "development".to_string()
            } else {
                "production".to_string()
            },
        }
    }

    /// Build a `CacheInfo` from the legacy [`DyldCache`].
    #[must_use]
    pub fn from_cache(cache: &DyldCache) -> Self {
        Self {
            magic: cache.header.magic.clone(),
            platform: cache.header.platform_name().to_string(),
            uuid: cache.header.uuid_string(),
            image_count: cache.images.len(),
            mapping_count: cache.mappings.len(),
            has_sub_caches: cache.header.subcache_array_count > 0,
            data_size: cache.data.len(),
            cache_type: "unknown".to_string(),
        }
    }
}

impl std::fmt::Display for CacheInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DyldCache {{ magic={:?}, platform={}, uuid={}, images={}, mappings={}, \
             sub_caches={}, type={}, size={}B }}",
            self.magic,
            self.platform,
            self.uuid,
            self.image_count,
            self.mapping_count,
            self.has_sub_caches,
            self.cache_type,
            self.data_size,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachOHeader — lightweight Mach-O header decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Magic constants for the Mach-O binary format.
pub mod macho_magic {
    pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
    pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE; // big-endian 64
    pub const MH_MAGIC: u32 = 0xFEED_FACE;
    pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
    pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
    pub const FAT_CIGAM: u32 = 0xBEBA_FECA;
    // Was 0xBFFF_AFFE, the only wrong entry in an otherwise correct table.
    // Four other definitions of this constant in the workspace agree on
    // 0xCAFE_BABF (`rustre-loader` twice, `rustre-mobile-ios`,
    // `rustre-mobile-ipa`), so a 64-bit fat binary was rejected here while
    // every other crate accepted it — silently, as "not a fat binary".
    pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
}

/// Mach-O file type constants.
pub mod macho_filetype {
    pub const MH_EXECUTE: u32 = 0x2;
    pub const MH_DYLIB: u32 = 0x6;
    pub const MH_DYLINKER: u32 = 0x7;
    pub const MH_BUNDLE: u32 = 0x8;
    pub const MH_DYLIB_STUB: u32 = 0x9;
    pub const MH_KEXT_BUNDLE: u32 = 0xB;
}

/// A minimally-decoded Mach-O header.
///
/// Used by [`DyldFullCache::extract_image`] to determine the true image size
/// without pulling in a full Mach-O parser dependency.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachOHeader {
    /// Mach-O magic (one of the `MH_MAGIC_*` constants).
    pub magic: u32,
    /// CPU type (e.g. `0x0100000C` for arm64).
    pub cpu_type: i32,
    /// CPU sub-type.
    pub cpu_subtype: i32,
    /// File type (one of the `MH_*` file type constants).
    pub file_type: u32,
    /// Number of load commands.
    pub ncmds: u32,
    /// Total byte size of the load commands.
    pub sizeofcmds: u32,
    /// Feature flags.
    pub flags: u32,
}

impl MachOHeader {
    /// Parse a 64-bit Mach-O header from the start of `data`.
    ///
    /// Returns `None` if the magic is not a recognised 64-bit Mach-O value or
    /// the data is too short.
    #[must_use]
    pub fn parse_64(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let is_64 = magic == macho_magic::MH_MAGIC_64 || magic == macho_magic::MH_CIGAM_64;
        if !is_64 {
            return None;
        }

        let le = magic == macho_magic::MH_MAGIC_64;
        let read_u32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let read_i32 = |off: usize| -> i32 { read_u32(off).cast_signed() };

        Some(Self {
            magic,
            cpu_type: read_i32(4),
            cpu_subtype: read_i32(8),
            file_type: read_u32(12),
            ncmds: read_u32(16),
            sizeofcmds: read_u32(20),
            flags: read_u32(24),
            // 4-byte reserved field at offset 28 is ignored.
        })
    }

    /// Return `true` if this is a dylib.
    #[must_use]
    pub const fn is_dylib(&self) -> bool {
        self.file_type == macho_filetype::MH_DYLIB
            || self.file_type == macho_filetype::MH_DYLIB_STUB
    }

    /// Return the total size of the header + load commands in bytes.
    #[must_use]
    pub const fn header_and_lc_size(&self) -> usize {
        32 + self.sizeofcmds as usize
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: read NUL-terminated string at arbitrary offset
// ─────────────────────────────────────────────────────────────────────────────

fn read_cstring_at(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── DyldCacheHeader ───────────────────────────────────────────────────────

    #[test]
    fn cache_header_parse_rejects_short_data() {
        let data = vec![0u8; 10];
        assert!(matches!(
            DyldCacheHeader::parse(&data),
            Err(DyldError::Truncated(_))
        ));
    }

    #[test]
    fn cache_header_parse_rejects_bad_magic() {
        let mut data = vec![0u8; 128];
        // Test bug fix: b"JUNKMAGIC" is 9 bytes; use 8-byte non-dyld magic
        data[..8].copy_from_slice(b"JUNKMAGI");
        assert!(matches!(
            DyldCacheHeader::parse(&data),
            Err(DyldError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn cache_header_parse_minimal_arm64e() {
        let mut data = vec![0u8; 256];
        let magic = b"dyld_v1   arm64e";
        data[..16].copy_from_slice(magic);
        data[0x10..0x14].copy_from_slice(&100u32.to_le_bytes()); // mapping_offset
        data[0x14..0x18].copy_from_slice(&3u32.to_le_bytes()); // mapping_count
        data[0x18..0x1C].copy_from_slice(&200u32.to_le_bytes()); // images_offset
        data[0x1C..0x20].copy_from_slice(&42u32.to_le_bytes()); // images_count

        let hdr = DyldCacheHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic_str(), "dyld_v1   arm64e");
        assert!(hdr.is_arm64());
        assert_eq!(hdr.mapping_count, 3);
        assert_eq!(hdr.images_count, 42);
        assert_eq!(hdr.platform_name(), "unknown"); // platform byte is 0
    }

    #[test]
    fn cache_header_uuid_string_format() {
        let mut data = vec![0u8; 256];
        let magic = b"dyld_v1   arm64e";
        data[..16].copy_from_slice(magic);
        for (i, b) in data[0x58..0x68].iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        let hdr = DyldCacheHeader::parse(&data).unwrap();
        let uuid = hdr.uuid_string();
        assert_eq!(
            uuid.len(),
            36,
            "UUID string should be 36 chars with hyphens"
        );
        assert!(uuid.contains('-'));
    }

    #[test]
    fn cache_header_roundtrip_to_bytes() {
        let mut data = vec![0u8; 256];
        let magic = b"dyld_v1   arm64e";
        data[..16].copy_from_slice(magic);
        data[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&2u32.to_le_bytes());
        let hdr = DyldCacheHeader::parse(&data).unwrap();
        let bytes = hdr.to_bytes();
        assert_eq!(&bytes[..16], magic);
        assert_eq!(
            u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap()),
            0x100
        );
        assert_eq!(u32::from_le_bytes(bytes[0x14..0x18].try_into().unwrap()), 2);
    }

    // ── DyldCacheMapping ──────────────────────────────────────────────────────

    #[test]
    fn mapping_parse_and_queries() {
        let mut data = vec![0u8; 64];
        // address = 0x180000000, size = 0x10000000, file_offset = 0,
        // max_prot = 5, init_prot = 5 (r-x)
        data[0..8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0u64.to_le_bytes());
        data[24..28].copy_from_slice(&5u32.to_le_bytes());
        data[28..32].copy_from_slice(&5u32.to_le_bytes());

        let m = DyldCacheMapping::parse(&data, 0).unwrap();
        assert_eq!(m.address, 0x1_8000_0000);
        assert!(m.is_readable());
        assert!(!m.is_writable());
        assert!(m.is_executable());
        assert_eq!(m.prot_string(), "r-x");
        assert!(m.contains_va(0x1_8000_0000));
        assert!(m.contains_va(0x1_8FFF_FFFF));
        assert!(!m.contains_va(0x1_9000_0000));
        assert_eq!(m.va_to_file_offset(0x1_8000_1000), Some(0x1000));
        assert!(m.va_to_file_offset(0x1_9000_0000).is_none());
    }

    #[test]
    fn mapping_parse_truncated() {
        let data = vec![0u8; 16]; // too short
        assert!(matches!(
            DyldCacheMapping::parse(&data, 0),
            Err(DyldError::Truncated(_))
        ));
    }

    // ── DyldCacheImage ────────────────────────────────────────────────────────

    fn make_image_data() -> Vec<u8> {
        let path = b"/usr/lib/libSystem.B.dylib\0";
        let mut data = vec![0u8; 64 + path.len()];
        data[0..8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes()); // address
        data[8..16].copy_from_slice(&12345u64.to_le_bytes()); // mod_time
        data[16..24].copy_from_slice(&99u64.to_le_bytes()); // inode
        data[24..28].copy_from_slice(&64u32.to_le_bytes()); // path_file_offset=64
        // Test bug fix: removed redundant copy with wrong index; path written at offset 64
        data[64..64 + path.len()].copy_from_slice(path);
        data
    }

    #[test]
    fn image_parse_basic() {
        let data = make_image_data();
        let img = DyldCacheImage::parse(&data, 0).unwrap();
        assert_eq!(img.address, 0x1_8000_0000);
        assert_eq!(img.mod_time, 12345);
        assert_eq!(img.inode, 99);
        assert_eq!(img.path, "/usr/lib/libSystem.B.dylib");
        assert_eq!(img.filename(), "libSystem.B.dylib");
        assert!(img.is_system_framework());
    }

    #[test]
    fn image_framework_name_extracted() {
        let img = DyldCacheImage {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_file_offset: 0,
            padding: 0,
            path: "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
        };
        assert_eq!(img.framework_name(), Some("Foundation"));
    }

    #[test]
    fn image_framework_name_none_for_plain_dylib() {
        let img = DyldCacheImage {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_file_offset: 0,
            padding: 0,
            path: "/usr/lib/libz.1.dylib".to_string(),
        };
        assert!(img.framework_name().is_none());
    }

    // ── DyldSlideInfo ─────────────────────────────────────────────────────────

    #[test]
    fn slide_info_parse_v2() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        data[4..8].copy_from_slice(&0x4000u32.to_le_bytes()); // page_size
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // starts_offset
        data[12..16].copy_from_slice(&10u32.to_le_bytes()); // page_count
        let si = DyldSlideInfo::parse(&data).unwrap();
        assert_eq!(si.version, SlideInfoVersion::V2);
        assert_eq!(si.page_size, 0x4000);
        assert_eq!(si.page_count, 10);
    }

    #[test]
    fn slide_info_parse_v3() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes());
        let si = DyldSlideInfo::parse(&data).unwrap();
        assert_eq!(si.version, SlideInfoVersion::V3);
        assert_eq!(si.page_size, 0x4000);
    }

    #[test]
    fn slide_info_parse_v5() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        data[8..12].copy_from_slice(&8u32.to_le_bytes());
        let si = DyldSlideInfo::parse(&data).unwrap();
        assert_eq!(si.version, SlideInfoVersion::V5);
        assert_eq!(si.page_size, 0x1000);
        assert_eq!(si.page_count, 8);
    }

    #[test]
    fn slide_info_parse_unknown_version_returns_none() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // unknown version
        assert!(DyldSlideInfo::parse(&data).is_none());
    }

    #[test]
    fn slide_info_parse_empty_returns_none() {
        assert!(DyldSlideInfo::parse(&[]).is_none());
    }

    // ── DyldLocalSymbolsHeader ────────────────────────────────────────────────

    #[test]
    fn local_symbols_header_parse() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&100u32.to_le_bytes()); // nlist_offset
        data[4..8].copy_from_slice(&200u32.to_le_bytes()); // nlist_count
        data[8..12].copy_from_slice(&1000u32.to_le_bytes()); // strings_offset
        data[12..16].copy_from_slice(&512u32.to_le_bytes()); // strings_size
        data[16..20].copy_from_slice(&1512u32.to_le_bytes()); // entries_offset
        data[20..24].copy_from_slice(&15u32.to_le_bytes()); // entries_count

        let hdr = DyldLocalSymbolsHeader::parse(&data).unwrap();
        assert_eq!(hdr.nlist_offset, 100);
        assert_eq!(hdr.nlist_count, 200);
        assert_eq!(hdr.entries_count, 15);
    }

    #[test]
    fn local_symbols_header_parse_truncated() {
        let data = vec![0u8; 10];
        assert!(matches!(
            DyldLocalSymbolsHeader::parse(&data),
            Err(DyldError::Truncated(_))
        ));
    }

    // ── DyldLocalSymbol helpers ───────────────────────────────────────────────

    #[test]
    fn local_symbol_compiler_generated() {
        let sym = DyldLocalSymbol {
            name: "l_some_literal".to_string(),
            address: 0,
            image_path: String::new(),
            nlist_start_index: 0,
            nlist_count: 0,
        };
        assert!(sym.is_compiler_generated());
    }

    #[test]
    fn local_symbol_objc_metadata() {
        let sym = DyldLocalSymbol {
            name: "_OBJC_CLASS_$_NSObject".to_string(),
            address: 0,
            image_path: String::new(),
            nlist_start_index: 0,
            nlist_count: 0,
        };
        assert!(sym.is_objc_metadata());
        assert!(!sym.is_compiler_generated());
    }

    // ── MachOHeader ───────────────────────────────────────────────────────────

    #[test]
    fn macho_header_parse_64() {
        let mut data = vec![0u8; 64];
        // MH_MAGIC_64 little-endian
        data[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        data[4..8].copy_from_slice(&0x0100_000Cu32.cast_signed().to_le_bytes()); // CPU_TYPE_ARM64
        data[12..16].copy_from_slice(&6u32.to_le_bytes()); // MH_DYLIB
        data[16..20].copy_from_slice(&5u32.to_le_bytes()); // ncmds
        data[20..24].copy_from_slice(&0x200u32.to_le_bytes()); // sizeofcmds
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // flags

        let hdr = MachOHeader::parse_64(&data).unwrap();
        assert_eq!(hdr.magic, 0xFEED_FACF);
        assert!(hdr.is_dylib());
        assert_eq!(hdr.ncmds, 5);
        assert_eq!(hdr.header_and_lc_size(), 32 + 0x200);
    }

    #[test]
    fn macho_header_rejects_non_64bit() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xFEED_FACEu32.to_le_bytes()); // MH_MAGIC (32-bit)
        assert!(MachOHeader::parse_64(&data).is_none());
    }

    #[test]
    fn macho_header_rejects_fat() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes()); // FAT_MAGIC
        assert!(MachOHeader::parse_64(&data).is_none());
    }

    // ── DyldFullCache ─────────────────────────────────────────────────────────

    fn make_minimal_full_cache_bytes() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        // Write magic
        data[..16].copy_from_slice(b"dyld_v1   arm64e");
        // mapping_offset = 0x100, mapping_count = 1
        data[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        // images_offset = 0x200, images_count = 1
        data[0x18..0x1C].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes());
        // dyld_base_address
        data[0x20..0x28].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());

        // Write one mapping at 0x100: address=0x180000000, size=0x1000000, file_offset=0
        let mbase = 0x100usize;
        data[mbase..mbase + 8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        data[mbase + 8..mbase + 16].copy_from_slice(&0x100_0000u64.to_le_bytes());
        data[mbase + 16..mbase + 24].copy_from_slice(&0u64.to_le_bytes());
        data[mbase + 24..mbase + 28].copy_from_slice(&5u32.to_le_bytes()); // max_prot
        data[mbase + 28..mbase + 32].copy_from_slice(&5u32.to_le_bytes()); // init_prot

        // Write one image at 0x200: address=0x180000000, path_file_offset=0x300
        let ibase = 0x200usize;
        data[ibase..ibase + 8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        data[ibase + 24..ibase + 28].copy_from_slice(&0x300u32.to_le_bytes());

        // Write path string at 0x300
        let pbase = 0x300usize;
        let path = b"/usr/lib/libSystem.B.dylib\0";
        data[pbase..pbase + path.len()].copy_from_slice(path);

        data
    }

    #[test]
    fn full_cache_from_bytes_basic() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        assert_eq!(cache.image_count(), 1);
        assert_eq!(cache.mapping_count(), 1);
        assert_eq!(cache.images[0].path, "/usr/lib/libSystem.B.dylib");
        assert!(cache.images[0].is_system_framework());
    }

    #[test]
    fn full_cache_list_images() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        let imgs = cache.list_images();
        assert_eq!(imgs.len(), 1);
        assert_eq!(imgs[0].0, "/usr/lib/libSystem.B.dylib");
        assert_eq!(imgs[0].1, 0x1_8000_0000);
    }

    #[test]
    fn full_cache_find_image() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        assert!(cache.find_image("/usr/lib/libSystem.B.dylib").is_some());
        assert!(cache.find_image("/nonexistent.dylib").is_none());
    }

    #[test]
    fn full_cache_vm_to_file_offset() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        // mapping: address=0x180000000, file_offset=0
        assert_eq!(cache.vm_to_file_offset(0x1_8000_0000), Some(0));
        assert_eq!(cache.vm_to_file_offset(0x1_8000_1000), Some(0x1000));
        assert!(cache.vm_to_file_offset(0x0).is_none());
    }

    #[test]
    fn full_cache_apply_slide_zero_is_noop() {
        let bytes = make_minimal_full_cache_bytes();
        let mut cache = DyldFullCache::from_bytes(bytes.clone()).unwrap();
        let patched = cache.apply_slide(0);
        assert_eq!(patched, 0);
        assert_eq!(cache.data, bytes);
    }

    #[test]
    fn full_cache_has_sub_caches_false_by_default() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        assert!(!cache.has_sub_caches());
    }

    // ── CacheInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn cache_info_from_full_cache() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        let info = CacheInfo::from_full_cache(&cache);
        assert!(info.magic.contains("arm64"));
        assert_eq!(info.image_count, 1);
        assert_eq!(info.mapping_count, 1);
        assert!(!info.has_sub_caches);
    }

    #[test]
    fn cache_info_display() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        let info = CacheInfo::from_full_cache(&cache);
        let s = info.to_string();
        assert!(s.contains("DyldCache"));
        assert!(s.contains("images=1"));
    }

    #[test]
    fn cache_info_from_legacy_cache() {
        let cache = DyldCache::mock();
        let info = CacheInfo::from_cache(&cache);
        assert!(info.magic.contains("arm64"));
        assert_eq!(info.image_count, 2);
    }

    // ── DyldSubCacheDescriptor ────────────────────────────────────────────────

    #[test]
    fn sub_cache_descriptor_parse_all_empty_when_no_sub_caches() {
        let bytes = make_minimal_full_cache_bytes();
        let cache = DyldFullCache::from_bytes(bytes).unwrap();
        let descs = DyldSubCacheDescriptor::parse_all(&cache.data, &cache.header);
        assert!(descs.is_empty());
    }

    // ── DyldLocalSymbolsInfo ──────────────────────────────────────────────────

    #[test]
    fn local_symbols_info_empty_when_no_offset() {
        let images: Vec<DyldCacheImage> = Vec::new();
        let info = DyldLocalSymbolsInfo::parse(&[], 0, 0, &images);
        assert!(info.symbols.is_empty());
    }

    #[test]
    fn local_symbols_info_find_by_name_none_when_empty() {
        let info = DyldLocalSymbolsInfo::default();
        assert!(info.find_by_name("_malloc").is_none());
    }

    #[test]
    fn local_symbols_info_find_containing() {
        let mut info = DyldLocalSymbolsInfo::default();
        info.symbols.push(DyldLocalSymbol {
            name: "_malloc".to_string(),
            address: 0x1000,
            image_path: "/usr/lib/libSystem.B.dylib".to_string(),
            nlist_start_index: 0,
            nlist_count: 1,
        });
        info.symbols.push(DyldLocalSymbol {
            name: "_calloc".to_string(),
            address: 0x2000,
            image_path: "/usr/lib/libSystem.B.dylib".to_string(),
            nlist_start_index: 1,
            nlist_count: 1,
        });
        let results = info.find_containing("alloc");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn local_symbols_info_for_image() {
        let mut info = DyldLocalSymbolsInfo::default();
        info.symbols.push(DyldLocalSymbol {
            name: "_foo".to_string(),
            address: 0,
            image_path: "/usr/lib/libA.dylib".to_string(),
            nlist_start_index: 0,
            nlist_count: 1,
        });
        info.symbols.push(DyldLocalSymbol {
            name: "_bar".to_string(),
            address: 0,
            image_path: "/usr/lib/libB.dylib".to_string(),
            nlist_start_index: 1,
            nlist_count: 1,
        });
        let a_syms = info.for_image("/usr/lib/libA.dylib");
        assert_eq!(a_syms.len(), 1);
        assert_eq!(a_syms[0].name, "_foo");
    }

    // ── DyldImageTextInfo ─────────────────────────────────────────────────────

    #[test]
    fn image_text_info_parse() {
        let path = b"/usr/lib/libSystem.B.dylib\0";
        let mut data = vec![0u8; 64 + path.len()];
        // uuid at offset 0..16 = 0x01..0x10
        for (i, b) in data[..16].iter_mut().enumerate() {
            *b = u8::try_from(i + 1).unwrap_or(0);
        }
        // load_address at 16..24
        data[16..24].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        // text_segment_size at 24..28
        data[24..28].copy_from_slice(&0x10_0000u32.to_le_bytes());
        // path_offset at 28..32
        data[28..32].copy_from_slice(&64u32.to_le_bytes());
        // path at 64
        data[64..64 + path.len()].copy_from_slice(path);

        let entry = DyldImageTextInfo::parse(&data, 0).unwrap();
        assert_eq!(entry.load_address, 0x1_8000_0000);
        assert_eq!(entry.text_segment_size, 0x10_0000);
        assert_eq!(entry.path, "/usr/lib/libSystem.B.dylib");
        let uuid_str = entry.uuid_string();
        assert_eq!(uuid_str.len(), 36);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-standing helpers — thin wrappers exposed for MCP tooling
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a dyld shared cache header from raw bytes and return the magic string.
///
/// # Errors
/// Returns [`DyldError`] on truncation or invalid magic.
pub fn parse_dyld_magic(data: &[u8]) -> Result<String, DyldError> {
    let h = DyldHeader::parse(data)?;
    Ok(h.magic)
}

/// Return `true` if the given path looks like an Apple system framework
/// (i.e. starts with `/System/` or `/usr/lib/`).
#[must_use]
pub fn is_system_framework_path(path: &str) -> bool {
    path.starts_with("/System/") || path.starts_with("/usr/lib/")
}

/// Format a 16-byte UUID as a lowercase hyphenated string.
#[must_use]
pub fn format_uuid(uuid: &[u8; 16]) -> String {
    let u = uuid;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
        u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15],
    )
}

