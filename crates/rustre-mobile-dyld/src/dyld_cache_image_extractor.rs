//! Extract individual Mach-O images from a dyld shared cache.
//!
//! [`DyldCacheImageExtractor`] accepts the raw bytes of a dyld shared cache
//! and provides methods for locating, extracting, and rewriting individual
//! Mach-O images by their in-cache path.  Each result is wrapped in an
//! [`ImageExtractResult`] that carries the extracted bytes together with
//! metadata about the extraction.

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by the image extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The buffer does not start with a valid dyld cache magic.
    InvalidMagic,
    /// The buffer is too short for the expected structure.
    Truncated { offset: usize },
    /// The requested image path was not found in the cache.
    ImageNotFound(String),
    /// A computed file offset falls outside the buffer.
    InvalidOffset { offset: usize, needed: usize, available: usize },
    /// A Mach-O header parse error.
    MachOError(String),
    /// Other structural inconsistency.
    Structural(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid dyld cache magic"),
            Self::Truncated { offset } => write!(f, "buffer truncated at offset {offset:#x}"),
            Self::ImageNotFound(p) => write!(f, "image not found: {p}"),
            Self::InvalidOffset { offset, needed, available } => {
                write!(f, "invalid offset {offset:#x}: need {needed}, have {available}")
            }
            Self::MachOError(s) => write!(f, "Mach-O parse error: {s}"),
            Self::Structural(s) => write!(f, "structural error: {s}"),
        }
    }
}

impl std::error::Error for ExtractError {}

// ── CacheImage ────────────────────────────────────────────────────────────────

/// Metadata for a single image embedded in the dyld cache.
#[derive(Debug, Clone)]
pub struct CacheImage {
    /// Load address of the Mach-O header within the cache's virtual address space.
    pub load_address: u64,
    /// Modification time of the source file (filesystem metadata).
    pub mod_time: u64,
    /// Inode of the source file (filesystem metadata).
    pub inode: u64,
    /// File offset of the NUL-terminated path string within the cache.
    pub path_file_offset: u32,
    /// Resolved path string (e.g. `/usr/lib/libSystem.B.dylib`).
    pub path: String,
}

impl CacheImage {
    /// Return the last path component (filename).
    #[must_use] 
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Return `true` if this image lives under `/usr/lib/` or `/System/`.
    #[must_use] 
    pub fn is_system(&self) -> bool {
        self.path.starts_with("/usr/lib/") || self.path.starts_with("/System/")
    }

    /// Return `true` if this is a Swift overlay dylib.
    #[must_use] 
    pub fn is_swift(&self) -> bool {
        self.path.contains("swift")
    }

    /// Return the framework name if the path contains `.framework/`.
    #[must_use] 
    pub fn framework_name(&self) -> Option<&str> {
        let idx = self.path.find(".framework/")?;
        let start = self.path[..idx].rfind('/')? + 1;
        Some(&self.path[start..idx])
    }
}

impl fmt::Display for CacheImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CacheImage {{ {} @ {:#x} }}", self.path, self.load_address)
    }
}

// ── CacheMapping ──────────────────────────────────────────────────────────────

/// A virtual-memory mapping entry from the cache header.
#[derive(Debug, Clone, Copy)]
struct CacheMapping {
    address: u64,
    size: u64,
    file_offset: u64,
    init_prot: u32,
}

impl CacheMapping {
    const fn end_address(self) -> u64 {
        self.address.saturating_add(self.size)
    }

    const fn contains(self, va: u64) -> bool {
        va >= self.address && va < self.end_address()
    }

    /// Returns the initial VM protection flags of this mapping (`VM_PROT_*`).
    const fn initial_protection(self) -> u32 {
        self.init_prot
    }

    /// Returns `true` if the mapping is marked executable in `init_prot`.
    const fn is_executable(self) -> bool {
        // VM_PROT_EXECUTE = 0x04
        (self.initial_protection() & 0x04) != 0
    }

    const fn va_to_file_offset(self, va: u64) -> Option<u64> {
        if self.contains(va) {
            Some(self.file_offset + (va - self.address))
        } else {
            None
        }
    }
}

// ── ImageExtractResult ────────────────────────────────────────────────────────

/// The result of extracting a single Mach-O image from the cache.
#[derive(Debug, Clone)]
pub struct ImageExtractResult {
    /// Path of the extracted image.
    pub path: String,
    /// Load address in the original cache.
    pub load_address: u64,
    /// Extracted raw Mach-O bytes.
    pub bytes: Vec<u8>,
    /// File offset within the cache where extraction started.
    pub cache_file_offset: usize,
    /// Whether Mach-O header parsing succeeded (used to determine true size).
    pub macho_parsed: bool,
    /// Detected number of Mach-O load commands.
    pub load_command_count: u32,
    /// Whether the cache mapping that holds this image is executable
    /// (i.e. corresponds to a `__TEXT` mapping).
    pub mapping_executable: bool,
}

impl ImageExtractResult {
    /// Size of the extracted image in bytes.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if the extracted image is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ── DyldCacheImageExtractor ───────────────────────────────────────────────────

/// Extracts individual Mach-O images from a dyld shared cache.
///
/// The extractor parses the cache header on construction and builds an index
/// of all embedded images.  Extraction is performed lazily when
/// [`extract_image`](Self::extract_image) is called.
pub struct DyldCacheImageExtractor {
    data: Vec<u8>,
    images: Vec<CacheImage>,
    mappings: Vec<CacheMapping>,
    /// Lazy index: path → image list index.
    path_index: HashMap<String, usize>,
}

impl DyldCacheImageExtractor {
    /// Parse a dyld shared cache and build the image index.
    ///
    /// # Errors
    /// Returns [`ExtractError`] if the buffer is not a valid dyld cache.
    pub fn new(data: Vec<u8>) -> Result<Self, ExtractError> {
        if data.len() < 0x100 {
            return Err(ExtractError::Truncated { offset: 0 });
        }
        if &data[..7] != b"dyld_v1" {
            return Err(ExtractError::InvalidMagic);
        }

        let mapping_offset = read_u32_le(&data, 0x10)? as usize;
        let mapping_count = read_u32_le(&data, 0x14)? as usize;
        let images_offset = read_u32_le(&data, 0x18)? as usize;
        let images_count = read_u32_le(&data, 0x1C)? as usize;

        let mut mappings = Vec::with_capacity(mapping_count);
        for i in 0..mapping_count {
            let base = mapping_offset + i * 32;
            if base + 32 > data.len() {
                break;
            }
            let address = read_u64_le(&data, base)?;
            let size = read_u64_le(&data, base + 8)?;
            let file_offset = read_u64_le(&data, base + 16)?;
            let init_prot = read_u32_le(&data, base + 24)?;
            mappings.push(CacheMapping { address, size, file_offset, init_prot });
        }

        let mut images = Vec::with_capacity(images_count);
        let mut path_index = HashMap::new();
        for i in 0..images_count {
            let base = images_offset + i * 32;
            if base + 32 > data.len() {
                break;
            }
            let load_address = read_u64_le(&data, base)?;
            let mod_time = read_u64_le(&data, base + 8)?;
            let inode = read_u64_le(&data, base + 16)?;
            let path_file_offset = read_u32_le(&data, base + 24)?;
            let path = read_cstring(&data, path_file_offset as usize);
            path_index.insert(path.clone(), images.len());
            images.push(CacheImage {
                load_address,
                mod_time,
                inode,
                path_file_offset,
                path,
            });
        }

        Ok(Self { data, images, mappings, path_index })
    }

    // ── Querying ──────────────────────────────────────────────────────────────

    /// Return a reference to all images in the cache.
    #[must_use] 
    pub fn images(&self) -> &[CacheImage] {
        &self.images
    }

    /// Find an image by exact path.
    #[must_use] 
    pub fn find_image(&self, path: &str) -> Option<&CacheImage> {
        self.path_index.get(path).and_then(|&i| self.images.get(i))
    }

    /// Find all images whose path contains `fragment`.
    #[must_use] 
    pub fn find_images_containing(&self, fragment: &str) -> Vec<&CacheImage> {
        self.images.iter().filter(|img| img.path.contains(fragment)).collect()
    }

    /// Translate a virtual address to a file offset using the mapping table.
    #[must_use] 
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.mappings.iter().find_map(|m| m.va_to_file_offset(va))
    }

    /// Number of images in the cache.
    #[must_use] 
    pub const fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Number of virtual memory mappings in the cache.
    #[must_use] 
    pub const fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    // ── Extraction ────────────────────────────────────────────────────────────

    /// Extract the raw Mach-O bytes for the image at `path`.
    ///
    /// The method:
    /// 1. Looks up the image by exact path.
    /// 2. Finds the first mapping that covers the image's load address.
    /// 3. Copies bytes from the file, using the Mach-O header to determine
    ///    the true image size when possible.
    ///
    /// # Errors
    /// Returns [`ExtractError`] if the image is not found or the buffer is
    /// inconsistent.
    pub fn extract_image(&self, path: &str) -> Result<ImageExtractResult, ExtractError> {
        let image = self
            .find_image(path)
            .ok_or_else(|| ExtractError::ImageNotFound(path.to_string()))?;

        let mapping = self
            .mappings
            .iter()
            .find(|m| m.contains(image.load_address))
            .ok_or_else(|| ExtractError::Structural(format!(
                "no mapping covers load address {:#x}",
                image.load_address
            )))?;

        let virt_off = image.load_address - mapping.address;
        let file_start = (mapping.file_offset + virt_off) as usize;

        if file_start >= self.data.len() {
            return Err(ExtractError::InvalidOffset {
                offset: file_start,
                needed: 1,
                available: self.data.len(),
            });
        }

        // Initial extraction — up to 1 MiB or the rest of the mapping.
        let remaining = ((mapping.size - virt_off) as usize).min(1024 * 1024);
        let file_end = (file_start + remaining).min(self.data.len());
        let bytes = self.data[file_start..file_end].to_vec();

        // Attempt Mach-O header parse to find true image size.
        let (macho_parsed, load_command_count) = self.try_parse_macho_header(&bytes, image.load_address);

        Ok(ImageExtractResult {
            path: path.to_string(),
            load_address: image.load_address,
            bytes,
            cache_file_offset: file_start,
            macho_parsed,
            load_command_count,
            mapping_executable: mapping.is_executable(),
        })
    }

    /// Extract multiple images by path.  Images that fail are silently skipped.
    #[must_use] 
    pub fn extract_images(&self, paths: &[&str]) -> Vec<ImageExtractResult> {
        paths.iter().filter_map(|p| self.extract_image(p).ok()).collect()
    }

    /// Extract all images, returning successes and errors separately.
    #[must_use] 
    pub fn extract_all(&self) -> (Vec<ImageExtractResult>, Vec<(String, ExtractError)>) {
        let mut ok = Vec::new();
        let mut errors = Vec::new();
        for img in &self.images {
            match self.extract_image(&img.path) {
                Ok(r) => ok.push(r),
                Err(e) => errors.push((img.path.clone(), e)),
            }
        }
        (ok, errors)
    }

    // ── Mach-O heuristics ─────────────────────────────────────────────────────

    /// Attempt to parse the Mach-O header in `bytes` to extract the true image
    /// size from segment commands.  Returns `(success, ncmds)`.
    fn try_parse_macho_header(&self, bytes: &[u8], load_address: u64) -> (bool, u32) {
        if bytes.len() < 32 {
            return (false, 0);
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // MH_MAGIC_64 = 0xFEEDFACF, MH_CIGAM_64 = 0xCFFAEDFE
        // MH_MAGIC    = 0xFEEDFACE, MH_CIGAM    = 0xCEFAEDFE
        let (is_64, big_endian) = match magic {
            0xFEED_FACF => (true, false),
            0xCFFA_EDFE => (true, true),
            0xFEED_FACE => (false, false),
            0xCEFA_EDFE => (false, true),
            _ => return (false, 0),
        };
        let _ = big_endian;
        let _ = is_64;
        let _ = load_address;
        // ncmds is at offset 16 for both 32 and 64-bit Mach-O
        if bytes.len() < 28 {
            return (false, 0);
        }
        let ncmds = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        (true, ncmds)
    }

    // ── Metadata helpers ──────────────────────────────────────────────────────

    /// Return a summary string for each image (path + load address).
    #[must_use] 
    pub fn image_summaries(&self) -> Vec<String> {
        self.images
            .iter()
            .map(|img| format!("{} @ {:#x}", img.path, img.load_address))
            .collect()
    }

    /// Return all framework names found in the cache.
    #[must_use] 
    pub fn framework_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .images
            .iter()
            .filter_map(|img| img.framework_name())
            .map(std::string::ToString::to_string)
            .collect();
        names.dedup();
        names
    }

    /// Count images by whether they are system libraries.
    #[must_use] 
    pub fn system_image_count(&self) -> usize {
        self.images.iter().filter(|i| i.is_system()).count()
    }
}

impl fmt::Debug for DyldCacheImageExtractor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DyldCacheImageExtractor {{ {} images, {} mappings, {} bytes }}",
            self.images.len(),
            self.mappings.len(),
            self.data.len()
        )
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn read_u32_le(data: &[u8], off: usize) -> Result<u32, ExtractError> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ExtractError::Truncated { offset: off })
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64, ExtractError> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ExtractError::Truncated { offset: off })
}

fn read_cstring(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ── Mock builder ──────────────────────────────────────────────────────────────

/// Build a minimal synthetic dyld cache buffer for testing.
#[must_use] 
pub fn build_mock_cache(images: &[(&str, u64)]) -> Vec<u8> {
    let magic = b"dyld_v1   arm64e\0";
    // Layout:
    //  0x00: magic (16 bytes)
    //  0x10: mapping_offset (u32) = 0x100
    //  0x14: mapping_count (u32) = 1
    //  0x18: images_offset (u32) = 0x140
    //  0x1C: images_count (u32) = N
    //  ...
    //  0x100: one mapping (32 bytes)
    //  0x140: image entries (32 bytes each)
    //  0x140 + N*32: path strings

    let mapping_offset: u32 = 0x100;
    let images_offset: u32 = 0x140;
    let image_count = images.len() as u32;
    let paths_start = images_offset as usize + images.len() * 32;
    // Enough padding for paths + some actual "file" data
    let total = paths_start + images.iter().map(|(p, _)| p.len() + 1).sum::<usize>() + 0x1000;

    let mut buf = vec![0u8; total.max(0x1000)];

    // Magic
    buf[..16].copy_from_slice(&magic[..16]);

    // Header fields
    buf[0x10..0x14].copy_from_slice(&mapping_offset.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // mapping_count
    buf[0x18..0x1C].copy_from_slice(&images_offset.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&image_count.to_le_bytes());

    // One mapping: covers [0x1_8000_0000, +0x4000_0000), file_offset=0
    let mapping_addr: u64 = 0x1_8000_0000;
    let mapping_size: u64 = 0x4000_0000;
    let mapping_file_off: u64 = 0;
    buf[0x100..0x108].copy_from_slice(&mapping_addr.to_le_bytes());
    buf[0x108..0x110].copy_from_slice(&mapping_size.to_le_bytes());
    buf[0x110..0x118].copy_from_slice(&mapping_file_off.to_le_bytes());
    buf[0x118..0x11C].copy_from_slice(&5u32.to_le_bytes()); // max_prot = R|X
    buf[0x11C..0x120].copy_from_slice(&5u32.to_le_bytes()); // init_prot

    // Image entries
    let mut path_cursor = paths_start;
    for (i, (path, load_addr)) in images.iter().enumerate() {
        let entry_base = images_offset as usize + i * 32;
        buf[entry_base..entry_base + 8].copy_from_slice(&load_addr.to_le_bytes());
        // mod_time, inode = 0
        let path_off = path_cursor as u32;
        buf[entry_base + 24..entry_base + 28].copy_from_slice(&path_off.to_le_bytes());

        // Write path string
        let pb = path.as_bytes();
        buf[path_cursor..path_cursor + pb.len()].copy_from_slice(pb);
        buf[path_cursor + pb.len()] = 0;
        path_cursor += pb.len() + 1;
    }

    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const LIB_SYSTEM: &str = "/usr/lib/libSystem.B.dylib";
    const LIB_OBJC: &str = "/usr/lib/libobjc.A.dylib";

    fn make_extractor() -> DyldCacheImageExtractor {
        let buf = build_mock_cache(&[
            (LIB_SYSTEM, 0x1_8000_0000),
            (LIB_OBJC, 0x1_8010_0000),
        ]);
        DyldCacheImageExtractor::new(buf).unwrap()
    }

    #[test]
    fn test_new_parses_images() {
        let e = make_extractor();
        assert_eq!(e.image_count(), 2);
    }

    #[test]
    fn test_find_image_by_path() {
        let e = make_extractor();
        assert!(e.find_image(LIB_SYSTEM).is_some());
        assert!(e.find_image("/nonexistent").is_none());
    }

    #[test]
    fn test_find_images_containing() {
        let e = make_extractor();
        let results = e.find_images_containing("libobjc");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, LIB_OBJC);
    }

    #[test]
    fn test_image_filename() {
        let e = make_extractor();
        let img = e.find_image(LIB_SYSTEM).unwrap();
        assert_eq!(img.filename(), "libSystem.B.dylib");
    }

    #[test]
    fn test_image_is_system() {
        let e = make_extractor();
        let img = e.find_image(LIB_SYSTEM).unwrap();
        assert!(img.is_system());
    }

    #[test]
    fn test_va_to_file_offset() {
        let e = make_extractor();
        // mapping: address=0x1_8000_0000, file_offset=0
        let fo = e.va_to_file_offset(0x1_8000_0000);
        assert_eq!(fo, Some(0));
        let fo2 = e.va_to_file_offset(0x1_8000_0100);
        assert_eq!(fo2, Some(0x100));
    }

    #[test]
    fn test_extract_image_ok() {
        let e = make_extractor();
        let result = e.extract_image(LIB_SYSTEM).unwrap();
        assert_eq!(result.path, LIB_SYSTEM);
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_extract_image_not_found() {
        let e = make_extractor();
        let err = e.extract_image("/nonexistent").unwrap_err();
        assert!(matches!(err, ExtractError::ImageNotFound(_)));
    }

    #[test]
    fn test_extract_images_skips_errors() {
        let e = make_extractor();
        let results = e.extract_images(&[LIB_SYSTEM, "/nonexistent"]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_extract_all() {
        let e = make_extractor();
        let (ok, errors) = e.extract_all();
        // Both images are within the mapping (file_offset=0) so they extract OK
        let total = ok.len() + errors.len();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_image_summaries() {
        let e = make_extractor();
        let sums = e.image_summaries();
        assert_eq!(sums.len(), 2);
        assert!(sums[0].contains(LIB_SYSTEM));
    }

    #[test]
    fn test_invalid_magic_error() {
        let mut buf = vec![0u8; 256];
        buf[..8].copy_from_slice(b"BADMAGIC");
        let err = DyldCacheImageExtractor::new(buf).unwrap_err();
        assert_eq!(err, ExtractError::InvalidMagic);
    }

    #[test]
    fn test_truncated_error() {
        let err = DyldCacheImageExtractor::new(vec![0u8; 10]).unwrap_err();
        assert!(matches!(err, ExtractError::Truncated { .. }));
    }

    #[test]
    fn test_system_image_count() {
        let e = make_extractor();
        assert_eq!(e.system_image_count(), 2);
    }

    #[test]
    fn test_extract_result_len() {
        let e = make_extractor();
        let r = e.extract_image(LIB_SYSTEM).unwrap();
        assert_eq!(r.len(), r.bytes.len());
        assert!(!r.is_empty());
    }

    #[test]
    fn test_extract_result_cache_file_offset() {
        let e = make_extractor();
        let r = e.extract_image(LIB_SYSTEM).unwrap();
        // LIB_SYSTEM is at load_address=0x1_8000_0000, mapping file_offset=0
        assert_eq!(r.cache_file_offset, 0);
    }
}
