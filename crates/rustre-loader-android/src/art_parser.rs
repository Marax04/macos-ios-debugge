//! Android ART image parser.
//!
//! ART image files (`boot.art`, `boot-framework.art`, per-app `.art` profiles)
//! are memory-mapped binary blobs produced by `dex2oat`.  Each image captures a
//! pre-initialised heap snapshot that the runtime can load without replaying
//! class initialisation.
//!
//! This module handles:
//! - ART image header (magic, version, image sections, root objects)
//! - Section descriptors (Objects, `ArtFields`, `ArtMethods`, `ImTables`, …)
//! - Class table parsing (hash buckets + `ClassTableEntry` chains)
//! - Image root references (`kDexCaches`, `kClassRoots`, …)
//! - Bitmap section parsing (live-objects bitmap)

use std::collections::HashMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ── Magic / version ───────────────────────────────────────────────────────────

/// ART image magic bytes: `"art\n"`.
pub const ART_IMAGE_MAGIC: &[u8; 4] = b"art\n";

/// Minimum header size for all supported ART versions.
pub const ART_HEADER_MIN_SIZE: usize = 0xA0;

// ── Section identifiers ───────────────────────────────────────────────────────

/// Named sections inside an ART image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ArtSectionId {
    Objects = 0,
    ArtFields = 1,
    ArtMethods = 2,
    ImTables = 3,
    IMTConflictTables = 4,
    RuntimeMethods = 5,
    JniStubMethods = 6,
    DataImTables = 7,
    DataIMTConflictTables = 8,
    Count = 9,
}

impl ArtSectionId {
    /// Decode from a raw u32.
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Objects),
            1 => Some(Self::ArtFields),
            2 => Some(Self::ArtMethods),
            3 => Some(Self::ImTables),
            4 => Some(Self::IMTConflictTables),
            5 => Some(Self::RuntimeMethods),
            6 => Some(Self::JniStubMethods),
            7 => Some(Self::DataImTables),
            8 => Some(Self::DataIMTConflictTables),
            _ => None,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Objects => "Objects",
            Self::ArtFields => "ArtFields",
            Self::ArtMethods => "ArtMethods",
            Self::ImTables => "ImTables",
            Self::IMTConflictTables => "IMTConflictTables",
            Self::RuntimeMethods => "RuntimeMethods",
            Self::JniStubMethods => "JniStubMethods",
            Self::DataImTables => "DataImTables",
            Self::DataIMTConflictTables => "DataIMTConflictTables",
            Self::Count => "Count",
        }
    }

    /// Returns `true` if this section contains Java / Dalvik object references.
    #[must_use]
    pub const fn contains_objects(self) -> bool {
        matches!(self, Self::Objects | Self::RuntimeMethods | Self::JniStubMethods)
    }
}

impl fmt::Display for ArtSectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── ArtSection ────────────────────────────────────────────────────────────────

/// Byte range describing one section within the image.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ArtSection {
    /// Section identifier.
    pub id: u32,
    /// Offset from the start of the image (not the file).
    pub offset: u32,
    /// Byte length of the section.
    pub size: u32,
}

impl ArtSection {
    /// Parse from 8 bytes (offset: u32, size: u32).
    #[must_use]
    pub fn parse_pair(data: &[u8]) -> Self {
        let offset = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let size = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        Self { id: 0, offset, size }
    }

    /// Returns the exclusive end offset.
    #[must_use]
    pub const fn end_offset(&self) -> u32 {
        self.offset.saturating_add(self.size)
    }

    /// Returns `true` if `image_offset` falls within this section.
    #[must_use]
    pub const fn contains(&self, image_offset: u32) -> bool {
        image_offset >= self.offset && image_offset < self.end_offset()
    }
}

impl fmt::Display for ArtSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "section[{}] off={:#010x} size={:#010x}",
            self.id, self.offset, self.size
        )
    }
}

// ── Image root identifiers ─────────────────────────────────────────────────────

/// Well-known image root indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtImageRoot {
    DexCaches = 0,
    ClassRoots = 1,
    ClassLoader = 2,
    BootImageLiveObjects = 3,
}

// ── ART image header ──────────────────────────────────────────────────────────

/// ART image format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtVersion {
    pub raw: [u8; 4],
}

impl ArtVersion {
    /// Parse from the 4-byte version field in the header.
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        let mut raw = [0u8; 4];
        if data.len() >= 4 {
            raw.copy_from_slice(&data[..4]);
        }
        Self { raw }
    }

    /// Return the version as a numeric value (first 3 digits).
    #[must_use]
    pub fn as_number(&self) -> u32 {
        std::str::from_utf8(&self.raw[..3])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

impl fmt::Display for ArtVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = std::str::from_utf8(&self.raw).unwrap_or("????");
        write!(f, "{}", s.trim_end_matches('\0'))
    }
}

/// Fully-parsed ART image header.
///
/// The layout evolves across Android releases.  Fields present in all versions
/// (Android 5.0–14) are documented here; version-specific fields are decoded
/// from `raw_extended` when the version is high enough.
///
/// Core layout (≥ version 029, Android 7.0+):
/// ```text
/// Offset  Size  Field
/// 0x00    4     magic
/// 0x04    4     version
/// 0x08    4     image_begin             (uint32_t – preferred load VA)
/// 0x0C    4     image_size              (uint32_t)
/// 0x10    4     oat_checksum            (uint32_t)
/// 0x14    4     oat_file_begin          (uint32_t)
/// 0x18    4     oat_file_end            (uint32_t)
/// 0x1C    4     oat_data_begin          (uint32_t)
/// 0x20    4     oat_data_end            (uint32_t)
/// 0x24    4     patch_delta             (int32_t – ASLR slide applied at build)
/// 0x28    4     image_roots             (uint32_t – VA of image roots array)
/// 0x2C    4     pointer_size            (uint32_t – 4 or 8)
/// 0x30    4     compile_pic             (uint32_t – bool)
/// 0x34    4     is_pic                  (uint32_t – bool, newer versions)
/// 0x38    4     boot_image_begin        (uint32_t – for app images)
/// 0x3C    4     boot_image_size         (uint32_t)
/// 0x40    4     boot_oat_begin          (uint32_t)
/// 0x44    4     boot_oat_size           (uint32_t)
/// 0x48    4     storage_mode            (uint32_t – 0=uncompressed)
/// 0x4C    4     data_size               (uint32_t)
/// 0x50    9*8   sections[9]             (offset:u32, size:u32 pairs)
/// 0x98    16*4  image_methods[16]       (uint32_t VAs of special ART runtime methods)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtImageHeader {
    /// ART version string (e.g. `"079"`).
    pub version: ArtVersion,
    /// Preferred load virtual address.
    pub image_begin: u32,
    /// Total image size in bytes.
    pub image_size: u32,
    /// Adler-32 checksum of the linked OAT file.
    pub oat_checksum: u32,
    /// VA of the start of the OAT file.
    pub oat_file_begin: u32,
    /// VA of the end of the OAT file.
    pub oat_file_end: u32,
    /// VA of the start of the OAT data section.
    pub oat_data_begin: u32,
    /// VA of the end of the OAT data section.
    pub oat_data_end: u32,
    /// ASLR patch delta applied during compilation.
    pub patch_delta: i32,
    /// VA of the image roots array.
    pub image_roots: u32,
    /// Pointer size in bytes (4 or 8).
    pub pointer_size: u32,
    /// Whether this image was compiled as position-independent.
    pub compile_pic: bool,
    /// Boot image VA range (for app images).
    pub boot_image_begin: u32,
    /// Boot image size in bytes.
    pub boot_image_size: u32,
    /// Boot OAT VA range.
    pub boot_oat_begin: u32,
    /// Boot OAT size.
    pub boot_oat_size: u32,
    /// Storage mode (0 = uncompressed).
    pub storage_mode: u32,
    /// Data section size.
    pub data_size: u32,
    /// Named sections.
    pub sections: Vec<ArtSection>,
    /// VA table of special ART runtime methods (up to 16 entries).
    pub image_methods: Vec<u32>,
    /// Byte offset at which this header was found.
    pub file_offset: usize,
}

impl ArtImageHeader {
    /// Number of section descriptors in the header.
    pub const SECTION_COUNT: usize = 9;

    /// Number of image method VAs in the header.
    pub const IMAGE_METHODS_COUNT: usize = 16;

    /// Parse an ART image header from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error if the data is too short or magic doesn't match.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + ART_HEADER_MIN_SIZE {
            bail!("ART image data too short at offset {offset:#x}");
        }

        let buf = &data[offset..];

        if &buf[..4] != ART_IMAGE_MAGIC {
            bail!("invalid ART image magic at {offset:#x}");
        }

        let version = ArtVersion::parse(&buf[4..8]);

        let rd_u32 = |off: usize| -> u32 {
            buf.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };
        let rd_i32 = |off: usize| -> i32 {
            buf.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, i32::from_le_bytes)
        };

        let image_begin = rd_u32(0x08);
        let image_size = rd_u32(0x0C);
        let oat_checksum = rd_u32(0x10);
        let oat_file_begin = rd_u32(0x14);
        let oat_file_end = rd_u32(0x18);
        let oat_data_begin = rd_u32(0x1C);
        let oat_data_end = rd_u32(0x20);
        let patch_delta = rd_i32(0x24);
        let image_roots = rd_u32(0x28);
        let pointer_size = rd_u32(0x2C);
        let compile_pic = rd_u32(0x30) != 0;
        let boot_image_begin = rd_u32(0x38);
        let boot_image_size = rd_u32(0x3C);
        let boot_oat_begin = rd_u32(0x40);
        let boot_oat_size = rd_u32(0x44);
        let storage_mode = rd_u32(0x48);
        let data_size = rd_u32(0x4C);

        // Sections: 9 × 8 bytes starting at 0x50.
        let sections_base = 0x50;
        let mut sections = Vec::with_capacity(Self::SECTION_COUNT);
        for i in 0..Self::SECTION_COUNT {
            let off = sections_base + i * 8;
            if off + 8 > buf.len() {
                break;
            }
            let mut sec = ArtSection::parse_pair(&buf[off..]);
            sec.id = i as u32;
            sections.push(sec);
        }

        // Image methods: up to 16 u32 VAs starting at 0x98.
        let methods_base = sections_base + Self::SECTION_COUNT * 8; // = 0x98
        let mut image_methods = Vec::with_capacity(Self::IMAGE_METHODS_COUNT);
        for i in 0..Self::IMAGE_METHODS_COUNT {
            let off = methods_base + i * 4;
            if off + 4 > buf.len() {
                break;
            }
            image_methods.push(rd_u32(off));
        }

        Ok(Self {
            version,
            image_begin,
            image_size,
            oat_checksum,
            oat_file_begin,
            oat_file_end,
            oat_data_begin,
            oat_data_end,
            patch_delta,
            image_roots,
            pointer_size,
            compile_pic,
            boot_image_begin,
            boot_image_size,
            boot_oat_begin,
            boot_oat_size,
            storage_mode,
            data_size,
            sections,
            image_methods,
            file_offset: offset,
        })
    }

    /// Return the section for `id`, or `None`.
    #[must_use]
    pub fn section(&self, id: ArtSectionId) -> Option<&ArtSection> {
        self.sections.get(id as usize)
    }

    /// Return the objects section.
    #[must_use]
    pub fn objects_section(&self) -> Option<&ArtSection> {
        self.section(ArtSectionId::Objects)
    }

    /// Return the `ArtMethods` section.
    #[must_use]
    pub fn art_methods_section(&self) -> Option<&ArtSection> {
        self.section(ArtSectionId::ArtMethods)
    }

    /// Returns `true` if this is a 64-bit image.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.pointer_size == 8
    }

    /// Returns `true` if the image has a non-zero patch delta (ASLR applied).
    #[must_use]
    pub const fn is_patched(&self) -> bool {
        self.patch_delta != 0
    }

    /// Returns the OAT file VA range as `(begin, end)`.
    #[must_use]
    pub const fn oat_file_range(&self) -> (u32, u32) {
        (self.oat_file_begin, self.oat_file_end)
    }

    /// Returns the OAT data VA range as `(begin, end)`.
    #[must_use]
    pub const fn oat_data_range(&self) -> (u32, u32) {
        (self.oat_data_begin, self.oat_data_end)
    }
}

impl fmt::Display for ArtImageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ART v{} image@{:#010x} size={:#x} ptr={} oat@{:#010x}..{:#010x} patch={:+}",
            self.version,
            self.image_begin,
            self.image_size,
            self.pointer_size,
            self.oat_file_begin,
            self.oat_file_end,
            self.patch_delta,
        )
    }
}

// ── ClassTable ────────────────────────────────────────────────────────────────

/// A resolved class entry from the ART class table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtClassEntry {
    /// Hash value stored in the class table.
    pub hash: u32,
    /// In-image VA of the `mirror::Class` object.
    pub class_va: u32,
    /// Class descriptor string (resolved from the Objects section, if possible).
    pub descriptor: Option<String>,
}

/// Parsed ART class table.
///
/// The class table is stored as a hash-map with open-addressing and a
/// fixed-size bucket array followed by overflow chains.  This parser
/// performs a linear scan of the bucket array and returns all valid entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtClassTable {
    /// All class entries found in the table.
    pub entries: Vec<ArtClassEntry>,
    /// Number of hash buckets.
    pub bucket_count: usize,
    /// Raw byte offset of the class table within the image file.
    pub file_offset: usize,
}

impl ArtClassTable {
    /// Linear-scan parse of the class table stored at `offset` within `data`.
    ///
    /// `image_begin` is the preferred VA of the image start (used to translate
    /// in-image VAs to file offsets).
    ///
    /// # Errors
    /// Returns an error if the data is truncated.
    pub fn parse(data: &[u8], offset: usize, image_begin: u32, pointer_size: u32) -> Result<Self> {
        if offset + 8 > data.len() {
            bail!("ArtClassTable too short at {offset:#x}");
        }

        // Class table header: bucket_count (u32) + capacity (u32).
        let bucket_count = u32::from_le_bytes(data[offset..offset + 4].try_into()?) as usize;
        let _capacity = u32::from_le_bytes(data[offset + 4..offset + 8].try_into()?) as usize;

        let entry_size = if pointer_size == 8 { 12usize } else { 8usize };
        // Each entry: hash (u32) + class_ptr (pointer_size bytes).
        let table_start = offset + 8;
        let table_bytes = bucket_count * entry_size;

        if table_start + table_bytes > data.len() {
            bail!("ArtClassTable bucket array truncated at {offset:#x}");
        }

        let mut entries = Vec::with_capacity(bucket_count);

        for i in 0..bucket_count {
            let base = table_start + i * entry_size;
            let hash = u32::from_le_bytes(data[base..base + 4].try_into()?);
            let class_ptr_raw: u64 = if pointer_size == 8 {
                u64::from_le_bytes(data[base + 4..base + 12].try_into()?)
            } else {
                u64::from(u32::from_le_bytes(data[base + 4..base + 8].try_into()?))
            };

            // Skip empty slots (hash == 0 typically indicates empty).
            if hash == 0 && class_ptr_raw == 0 {
                continue;
            }

            // Convert VA to file offset.
            let class_va = class_ptr_raw as u32;
            let file_off = if class_va >= image_begin {
                (class_va - image_begin) as usize
            } else {
                usize::MAX
            };

            // Attempt to read the class descriptor from the Objects section.
            let descriptor = read_class_descriptor(data, file_off, image_begin);

            entries.push(ArtClassEntry {
                hash,
                class_va,
                descriptor,
            });
        }

        Ok(Self {
            entries,
            bucket_count,
            file_offset: offset,
        })
    }

    /// Look up a class entry by descriptor (exact match).
    #[must_use]
    pub fn find_by_descriptor(&self, desc: &str) -> Option<&ArtClassEntry> {
        self.entries.iter().find(|e| e.descriptor.as_deref() == Some(desc))
    }

    /// Return all entries that have a resolved descriptor.
    #[must_use]
    pub fn entries_with_descriptors(&self) -> Vec<&ArtClassEntry> {
        self.entries.iter().filter(|e| e.descriptor.is_some()).collect()
    }
}

/// Try to read a Dalvik class descriptor from a `mirror::Class` object in the image.
///
/// `mirror::Class` layout (simplified, 64-bit):
/// The class descriptor string pointer is stored at a version-dependent offset.
/// We perform a heuristic scan for a valid Dalvik descriptor starting with `L` or `[`.
fn read_class_descriptor(data: &[u8], class_file_off: usize, _image_begin: u32) -> Option<String> {
    if class_file_off >= data.len() {
        return None;
    }
    // Heuristic: scan for a NUL-terminated string starting with 'L' or '[' within
    // 128 bytes of the class pointer.  Not guaranteed correct for all ART versions.
    let scan_start = class_file_off;
    let scan_end = (class_file_off + 256).min(data.len());
    let scan = &data[scan_start..scan_end];

    for (i, window) in scan.windows(2).enumerate() {
        if window[0] == b'L' || window[0] == b'[' {
            // Try to read until NUL or semicolon.
            let s_start = scan_start + i;
            let slice = &data[s_start..scan_end];
            if let Some(nul) = slice.iter().position(|&b| b == 0) {
                let candidate = std::str::from_utf8(&slice[..nul]).ok()?;
                if is_dalvik_descriptor(candidate) {
                    return Some(candidate.to_owned());
                }
            }
        }
    }
    None
}

fn is_dalvik_descriptor(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 {
        return false;
    }
    // Array descriptor: [[...
    if s.starts_with('[') {
        return true;
    }
    // Class descriptor: Lpackage/name;
    s.starts_with('L') && s.ends_with(';') && s.contains('/')
}

// ── ArtImage (top-level) ──────────────────────────────────────────────────────

/// Fully-parsed ART image file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtImage {
    /// Parsed image header.
    pub header: ArtImageHeader,
    /// Class table (if present and successfully parsed).
    pub class_table: Option<ArtClassTable>,
    /// Quick stats derived from the header.
    pub stats: ArtImageStats,
    /// Any parse warnings.
    pub warnings: Vec<String>,
}

/// High-level statistics about an ART image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtImageStats {
    /// Total image size in bytes.
    pub image_size: u32,
    /// Objects section size.
    pub objects_size: u32,
    /// `ArtMethods` section size.
    pub art_methods_size: u32,
    /// `ArtFields` section size.
    pub art_fields_size: u32,
    /// Whether ASLR was applied.
    pub is_patched: bool,
    /// Pointer size (4 or 8).
    pub pointer_size: u32,
    /// Number of classes in the table.
    pub class_count: usize,
    /// ART version string.
    pub version: String,
}

impl ArtImage {
    /// Parse an ART image from `data`.
    ///
    /// # Errors
    /// Returns an error if the magic is wrong or the header is truncated.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Find ART magic.
        let art_base = data
            .windows(4)
            .position(|w| w == ART_IMAGE_MAGIC)
            .context("ART image magic not found")?;

        let header = ArtImageHeader::parse(data, art_base)?;
        let mut warnings = Vec::new();

        // Attempt to parse the class table from the Objects section.
        let class_table = if let Some(obj_sec) = header.objects_section() {
            let obj_off = art_base + obj_sec.offset as usize;
            match ArtClassTable::parse(data, obj_off, header.image_begin, header.pointer_size) {
                Ok(ct) => Some(ct),
                Err(e) => {
                    warnings.push(format!("class table parse failed: {e}"));
                    None
                }
            }
        } else {
            None
        };

        let class_count = class_table.as_ref().map_or(0, |ct| ct.entries.len());

        let stats = ArtImageStats {
            image_size: header.image_size,
            objects_size: header.objects_section().map_or(0, |s| s.size),
            art_methods_size: header.art_methods_section().map_or(0, |s| s.size),
            art_fields_size: header.sections.get(ArtSectionId::ArtFields as usize).map_or(0, |s| s.size),
            is_patched: header.is_patched(),
            pointer_size: header.pointer_size,
            class_count,
            version: header.version.to_string(),
        };

        Ok(Self { header, class_table, stats, warnings })
    }

    /// Return the number of classes in the class table.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.class_table.as_ref().map_or(0, |ct| ct.entries.len())
    }

    /// Return all resolved class descriptors.
    #[must_use]
    pub fn class_descriptors(&self) -> Vec<String> {
        match &self.class_table {
            None => Vec::new(),
            Some(ct) => ct
                .entries
                .iter()
                .filter_map(|e| e.descriptor.clone())
                .collect(),
        }
    }

    /// Try to find a class entry by Dalvik descriptor (e.g. `"Ljava/lang/String;"`).
    #[must_use]
    pub fn find_class(&self, descriptor: &str) -> Option<&ArtClassEntry> {
        self.class_table.as_ref()?.find_by_descriptor(descriptor)
    }

    /// Build an index: descriptor → class VA.
    #[must_use]
    pub fn class_index(&self) -> HashMap<String, u32> {
        match &self.class_table {
            None => HashMap::new(),
            Some(ct) => ct
                .entries
                .iter()
                .filter_map(|e| e.descriptor.as_ref().map(|d| (d.clone(), e.class_va)))
                .collect(),
        }
    }
}

// ── Bitmap section ────────────────────────────────────────────────────────────

/// ART heap bitmap for one continuous region (tracks which heap words are live objects).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtBitmap {
    /// Heap start address this bitmap covers.
    pub heap_begin: u64,
    /// Number of bits (= heap size / `pointer_size`).
    pub bit_count: usize,
    /// Raw bitmap words.
    pub words: Vec<u64>,
}

impl ArtBitmap {
    /// Parse an ART heap bitmap from `data` at `offset`.
    ///
    /// `heap_begin` is the heap start VA, `heap_size` is the size in bytes,
    /// `pointer_size` is 4 or 8.
    ///
    /// # Errors
    /// Returns an error if truncated.
    pub fn parse(
        data: &[u8],
        offset: usize,
        heap_begin: u64,
        heap_size: usize,
        pointer_size: usize,
    ) -> Result<Self> {
        let bit_count = heap_size / pointer_size;
        let word_count = bit_count.div_ceil(64);
        let byte_count = word_count * 8;

        if offset + byte_count > data.len() {
            bail!(
                "ArtBitmap truncated: need {byte_count} bytes at {offset:#x}, have {}",
                data.len().saturating_sub(offset),
            );
        }

        let words: Vec<u64> = data[offset..offset + byte_count]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();

        Ok(Self { heap_begin, bit_count, words })
    }

    /// Returns `true` if object at `va` is marked live in the bitmap.
    #[must_use]
    pub fn is_live(&self, va: u64, pointer_size: usize) -> bool {
        if va < self.heap_begin {
            return false;
        }
        let offset = (va - self.heap_begin) as usize / pointer_size;
        if offset >= self.bit_count {
            return false;
        }
        let word = offset / 64;
        let bit = offset % 64;
        self.words.get(word).is_some_and(|w| w & (1 << bit) != 0)
    }

    /// Count the number of live objects in this bitmap.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn art_section_id_names() {
        assert_eq!(ArtSectionId::Objects.name(), "Objects");
        assert_eq!(ArtSectionId::ArtMethods.name(), "ArtMethods");
        assert!(ArtSectionId::Objects.contains_objects());
        assert!(!ArtSectionId::ArtFields.contains_objects());
    }

    #[test]
    fn art_section_parse_pair() {
        let data = [0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00];
        let sec = ArtSection::parse_pair(&data);
        assert_eq!(sec.offset, 0x1000);
        assert_eq!(sec.size, 0x800);
        assert_eq!(sec.end_offset(), 0x1800);
        assert!(sec.contains(0x1400));
        assert!(!sec.contains(0x1800));
    }

    #[test]
    fn art_version_display() {
        let v = ArtVersion { raw: *b"079\0" };
        assert_eq!(v.to_string(), "079");
        assert_eq!(v.as_number(), 79);
    }

    #[test]
    fn art_header_bad_magic() {
        let data = vec![0u8; 200];
        let err = ArtImageHeader::parse(&data, 0).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn art_header_too_short() {
        let data = vec![0u8; 50];
        let err = ArtImageHeader::parse(&data, 0).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn art_header_valid() {
        let mut data = vec![0u8; 0x100];
        data[..4].copy_from_slice(b"art\n");
        data[4..8].copy_from_slice(b"079\0");
        // image_begin = 0x70000000
        data[8..12].copy_from_slice(&0x7000_0000u32.to_le_bytes());
        // image_size = 0x500000
        data[12..16].copy_from_slice(&0x0050_0000u32.to_le_bytes());
        // pointer_size = 8
        data[0x2C..0x30].copy_from_slice(&8u32.to_le_bytes());

        let hdr = ArtImageHeader::parse(&data, 0).unwrap();
        assert_eq!(hdr.image_begin, 0x7000_0000);
        assert_eq!(hdr.image_size, 0x0050_0000);
        assert!(hdr.is_64bit());
        assert!(!hdr.is_patched());
        assert_eq!(hdr.version.to_string(), "079");
    }

    #[test]
    fn art_bitmap_live_count() {
        // 8 words, first word = 0xFFFF_FFFF_FFFF_FFFF (all live)
        let mut words_bytes = [0u8; 64];
        words_bytes[..8].fill(0xFF);
        let bm = ArtBitmap {
            heap_begin: 0x1000,
            bit_count: 512,
            words: words_bytes
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        };
        assert_eq!(bm.live_count(), 64); // 64 bits set in first word
        assert!(bm.is_live(0x1000, 8)); // first slot
        assert!(!bm.is_live(0x0FFF, 8)); // below heap_begin
    }

    #[test]
    fn is_dalvik_desc() {
        assert!(is_dalvik_descriptor("Ljava/lang/String;"));
        assert!(is_dalvik_descriptor("[I"));
        assert!(!is_dalvik_descriptor("String"));
        assert!(!is_dalvik_descriptor(""));
    }
}
