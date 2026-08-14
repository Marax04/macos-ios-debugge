//! `images` — dyld shared cache image list and extraction.
//!
//! Covers both the legacy `dyld_cache_image_info` (path + mtime + inode)
//! and the newer `dyld_cache_image_text_info` (UUID + load-address + path).

use super::DyldError;
use super::mappings::MappingSet;

// ─────────────────────────────────────────────────────────────────────────────
// Struct sizes
// ─────────────────────────────────────────────────────────────────────────────

/// Byte size of `dyld_cache_image_info`.
pub const IMAGE_INFO_SIZE: usize = 32;
/// Byte size of `dyld_cache_image_text_info`.
pub const IMAGE_TEXT_INFO_SIZE: usize = 40;

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheImageInfo (legacy)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_image_info` — the original image list entry format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheImageInfo {
    /// Virtual address of the Mach-O header for this image.
    pub address: u64,
    /// `mtime` of the source dylib at cache-build time.
    pub mod_time: u64,
    /// Inode number of the source dylib at cache-build time.
    pub inode: u64,
    /// File offset of the NUL-terminated path string.
    pub path_file_offset: u32,
    /// Padding (reserved).
    pub pad: u32,
    /// Resolved install-name path (populated after parsing the string table).
    pub path: String,
}

impl DyldCacheImageInfo {
    /// Parse one `dyld_cache_image_info` at `offset` from raw cache bytes.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + IMAGE_INFO_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let d = &data[offset..];
        let address = read_u64(d, 0)?;
        let mod_time = read_u64(d, 8)?;
        let inode = read_u64(d, 16)?;
        let path_file_offset = read_u32(d, 24)?;
        let pad = read_u32(d, 28)?;

        // Read NUL-terminated path string.
        let path = read_cstr(data, path_file_offset as usize)?;

        Ok(Self {
            address,
            mod_time,
            inode,
            path_file_offset,
            pad,
            path,
        })
    }

    /// Parse all legacy image info entries.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, DyldError> {
        let max_possible = data.len() / IMAGE_INFO_SIZE;
        let count_capped = (count as usize).min(max_possible);
        let mut images = Vec::with_capacity(count_capped);
        for i in 0..count as usize {
            let entry_offset = (offset as usize)
                .checked_add(i.checked_mul(IMAGE_INFO_SIZE).ok_or(DyldError::InvalidOffset(i as u64))?)
                .ok_or(DyldError::InvalidOffset(i as u64))?;
            images.push(Self::parse(data, entry_offset)?);
        }
        Ok(images)
    }

    /// Returns `true` if the path is a system framework.
    #[must_use]
    pub fn is_system_framework(&self) -> bool {
        self.path.starts_with("/System/")
            || self.path.starts_with("/usr/lib/")
            || self.path.starts_with("/Library/Apple/")
    }

    /// Returns `true` if this is a Swift overlay dylib.
    #[must_use]
    pub fn is_swift_overlay(&self) -> bool {
        self.path.contains("swiftFoundation")
            || self.path.contains("libswift")
            || self.path.contains("Swift_")
            || self.path.ends_with(".swiftmodule")
    }

    /// Returns the install-name of the dylib (last path component without
    /// directory, same as the framework directory name).
    #[must_use]
    pub fn dylib_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(self.path.as_str())
    }

    /// Returns the framework name if the path follows the standard
    /// `.framework/` bundle layout, otherwise `None`.
    #[must_use]
    pub fn framework_name(&self) -> Option<&str> {
        // Match: /Foo.framework/Foo  →  "Foo"
        // Use find(".framework/") to avoid collecting path components into a Vec.
        let idx = self.path.find(".framework/")?;
        let start = self.path[..idx].rfind('/')? + 1;
        Some(&self.path[start..idx])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheImageTextInfo (dyld-832+)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_image_text_info` — the newer image entry that adds a UUID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DyldCacheImageTextInfo {
    /// UUID of this Mach-O image.
    pub uuid: [u8; 16],
    /// Virtual address of the Mach-O header.
    pub load_address: u64,
    /// Size of the TEXT segment (for extraction).
    pub text_segment_size: u32,
    /// File offset of the NUL-terminated path string.
    pub path_offset: u32,
    /// Resolved install-name path.
    pub path: String,
}

impl DyldCacheImageTextInfo {
    /// Parse one entry at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DyldError> {
        if data.len() < offset + IMAGE_TEXT_INFO_SIZE {
            return Err(DyldError::Truncated(offset));
        }
        let d = &data[offset..];
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&d[0..16]);
        let load_address = read_u64(d, 16)?;
        let text_segment_size = read_u32(d, 24)?;
        let path_offset = read_u32(d, 28)?;
        // Note: bytes 32..40 are a 64-bit pad / reserved field.
        let path = read_cstr(data, path_offset as usize)?;

        Ok(Self {
            uuid,
            load_address,
            text_segment_size,
            path_offset,
            path,
        })
    }

    /// Parse all new-format image text entries.
    pub fn parse_all(data: &[u8], offset: u64, count: u64) -> Result<Vec<Self>, DyldError> {
        let base_offset = usize::try_from(offset)
            .map_err(|_| DyldError::InvalidOffset(offset))?;
        let max_possible = data.len() / IMAGE_TEXT_INFO_SIZE;
        let count_capped = usize::try_from(count).unwrap_or(max_possible).min(max_possible);
        let mut images = Vec::with_capacity(count_capped);
        for i in 0..usize::try_from(count).unwrap_or(max_possible) {
            let entry_offset = base_offset
                .checked_add(i.checked_mul(IMAGE_TEXT_INFO_SIZE).ok_or(DyldError::InvalidOffset(i as u64))?)
                .ok_or(DyldError::InvalidOffset(i as u64))?;
            images.push(Self::parse(data, entry_offset)?);
        }
        Ok(images)
    }

    /// Returns the UUID as a formatted string.
    #[must_use]
    pub fn uuid_string(&self) -> String {
        let u = &self.uuid;
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
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
// ImageIndex — unified index over both list formats
// ─────────────────────────────────────────────────────────────────────────────

/// A unified, searchable index of all images in a dyld shared cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageIndex {
    /// Legacy image list (may be empty if the cache uses only the new list).
    pub legacy: Vec<DyldCacheImageInfo>,
    /// New image-text list (may be empty for older caches).
    pub text: Vec<DyldCacheImageTextInfo>,
}

impl ImageIndex {
    /// Build an `ImageIndex` from already-parsed image lists.
    #[must_use]
    pub const fn new(legacy: Vec<DyldCacheImageInfo>, text: Vec<DyldCacheImageTextInfo>) -> Self {
        Self { legacy, text }
    }

    /// Total number of unique images (prefer `text` list if available).
    #[must_use]
    pub const fn count(&self) -> usize {
        if self.text.is_empty() {
            self.legacy.len()
        } else {
            self.text.len()
        }
    }

    /// Find a legacy image by exact install-name path.
    #[must_use]
    pub fn find_by_path(&self, path: &str) -> Option<&DyldCacheImageInfo> {
        self.legacy.iter().find(|i| i.path == path)
    }

    /// Find a legacy image whose path contains `substr`.
    #[must_use]
    pub fn find_containing(&self, substr: &str) -> Vec<&DyldCacheImageInfo> {
        self.legacy
            .iter()
            .filter(|i| i.path.contains(substr))
            .collect()
    }

    /// Find a new-format image by exact path.
    #[must_use]
    pub fn find_text_by_path(&self, path: &str) -> Option<&DyldCacheImageTextInfo> {
        self.text.iter().find(|i| i.path == path)
    }

    /// Find a new-format image by UUID string (case-insensitive).
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &str) -> Option<&DyldCacheImageTextInfo> {
        let upper = uuid.to_uppercase().replace('-', "");
        self.text
            .iter()
            .find(|i| i.uuid_string().replace('-', "") == upper)
    }

    /// Collect all framework names present in the cache.
    #[must_use]
    pub fn framework_names(&self) -> Vec<&str> {
        self.legacy
            .iter()
            .filter_map(|i| i.framework_name())
            .collect()
    }

    /// Collect the paths of all Swift overlay dylibs.
    #[must_use]
    pub fn swift_overlays(&self) -> Vec<&str> {
        self.legacy
            .iter()
            .filter(|i| i.is_swift_overlay())
            .map(|i| i.path.as_str())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Image extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Result of extracting a single Mach-O image from the shared cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractedImage {
    /// Install-name path.
    pub path: String,
    /// The raw Mach-O bytes of the extracted image.
    pub data: Vec<u8>,
    /// Virtual load address of the image header.
    pub load_address: u64,
    /// Whether the on-disk image was rebased (slide fixups NOT applied —
    /// the bytes are in their on-cache packed form).
    pub slide_fixups_pending: bool,
}

impl ExtractedImage {
    /// Returns `true` if the extracted bytes start with a known Mach-O magic.
    #[must_use]
    pub fn is_valid_macho(&self) -> bool {
        if self.data.len() < 4 {
            return false;
        }
        let magic = u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
        matches!(magic, 0xFEED_FACE | 0xFEED_FACF | 0xCAFE_BABE | 0xBEBA_FECA)
    }
}

/// Extract one Mach-O image from the shared cache by its virtual load address.
///
/// The extraction copies the TEXT segment bytes (as reported by the image-text
/// info list).  Slide fixups are NOT applied — the caller must use
/// `slide_info::apply_slide_fixups()` if a fully relocated image is required.
pub fn extract_image(
    cache_data: &[u8],
    mappings: &MappingSet,
    load_address: u64,
    text_segment_size: u32,
    path: String,
) -> Result<ExtractedImage, DyldError> {
    let file_off = mappings
        .va_to_file_offset(load_address)
        .ok_or(DyldError::InvalidOffset(load_address))? as usize;

    let size = text_segment_size as usize;
    if file_off + size > cache_data.len() {
        return Err(DyldError::Truncated(file_off));
    }
    let data = cache_data[file_off..file_off + size].to_vec();

    Ok(ExtractedImage {
        path,
        data,
        load_address,
        slide_fixups_pending: true,
    })
}

/// Extract all images from a cache using the new-format image-text list.
///
/// Images whose TEXT segment extends beyond the cache data are skipped (not
/// an error — this can happen with split caches).
#[must_use]
pub fn extract_all_images(
    cache_data: &[u8],
    mappings: &MappingSet,
    text_images: &[DyldCacheImageTextInfo],
) -> Vec<ExtractedImage> {
    let mut results = Vec::with_capacity(text_images.len());
    for img in text_images {
        if let Ok(e) = extract_image(
            cache_data,
            mappings,
            img.load_address,
            img.text_segment_size,
            img.path.clone(),
        ) {
            results.push(e);
        } else {
            // Skip images that can't be extracted (split cache, etc.).
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    data.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(DyldError::Truncated(offset))
}

/// Read a NUL-terminated C string from `data` starting at `offset`.
fn read_cstr(data: &[u8], offset: usize) -> Result<String, DyldError> {
    if offset >= data.len() {
        return Err(DyldError::InvalidOffset(offset as u64));
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|_| DyldError::Parse(format!("invalid UTF-8 path at offset {offset:#x}")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::mappings::DyldCacheMappingInfo;
    use super::*;

    fn make_legacy_image(addr: u64, path_offset: u32) -> [u8; IMAGE_INFO_SIZE] {
        let mut b = [0u8; IMAGE_INFO_SIZE];
        b[0..8].copy_from_slice(&addr.to_le_bytes());
        // mod_time = 0, inode = 0
        b[24..28].copy_from_slice(&path_offset.to_le_bytes());
        b
    }

    fn build_cache_with_image(path: &str) -> Vec<u8> {
        // Minimal cache blob: mapping area + path string
        let path_offset: u32 = u32::try_from(IMAGE_INFO_SIZE).unwrap_or(0);
        let mut data = Vec::new();
        data.extend_from_slice(&make_legacy_image(0x0001_8000_0000, path_offset));
        data.extend_from_slice(path.as_bytes());
        data.push(0); // NUL terminator
        data
    }

    #[test]
    fn test_parse_legacy_image() {
        let data = build_cache_with_image("/usr/lib/libSystem.B.dylib");
        let img = DyldCacheImageInfo::parse(&data, 0).expect("parse");
        assert_eq!(img.address, 0x0001_8000_0000);
        assert_eq!(img.path, "/usr/lib/libSystem.B.dylib");
        assert!(img.is_system_framework());
    }

    #[test]
    fn test_dylib_name() {
        let data =
            build_cache_with_image("/System/Library/Frameworks/Foundation.framework/Foundation");
        let img = DyldCacheImageInfo::parse(&data, 0).expect("parse");
        assert_eq!(img.dylib_name(), "Foundation");
        assert_eq!(img.framework_name(), Some("Foundation"));
    }

    #[test]
    fn test_swift_overlay_detection() {
        let data = build_cache_with_image("/usr/lib/swift/libswiftCore.dylib");
        let img = DyldCacheImageInfo::parse(&data, 0).expect("parse");
        assert!(img.is_swift_overlay());
    }

    #[test]
    fn test_parse_text_info() {
        let mut raw = [0u8; IMAGE_TEXT_INFO_SIZE];
        // UUID: 1..16
        for i in 0..16usize {
            raw[i] = u8::try_from(i + 1).unwrap_or(0);
        }
        // load_address = 0x180000000
        raw[16..24].copy_from_slice(&0x0001_8000_0000_u64.to_le_bytes());
        // text_segment_size = 0x1000
        raw[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
        // path_offset = 40 (right after this struct)
        raw[28..32].copy_from_slice(&40u32.to_le_bytes());

        let mut data = raw.to_vec();
        data.extend_from_slice(b"/usr/lib/libz.1.dylib\0");

        let img = DyldCacheImageTextInfo::parse(&data, 0).expect("parse");
        assert_eq!(img.load_address, 0x0001_8000_0000);
        assert_eq!(img.text_segment_size, 0x1000);
        assert_eq!(img.path, "/usr/lib/libz.1.dylib");
        assert!(img.uuid_string().contains('-'));
    }

    #[test]
    fn test_image_index_find() {
        let data1 = build_cache_with_image("/usr/lib/libSystem.B.dylib");
        let data2 = build_cache_with_image("/usr/lib/libz.1.dylib");
        let img1 = DyldCacheImageInfo::parse(&data1, 0).unwrap();
        let img2 = DyldCacheImageInfo::parse(&data2, 0).unwrap();
        let idx = ImageIndex::new(vec![img1, img2], vec![]);
        assert!(idx.find_by_path("/usr/lib/libSystem.B.dylib").is_some());
        assert_eq!(idx.find_containing("libz").len(), 1);
        assert_eq!(idx.count(), 2);
    }

    #[test]
    fn test_extract_image() {
        // Create a fake cache with a 0x10-byte Mach-O at file offset 0.
        let mut cache = Vec::new();
        // Fake Mach-O magic (MH_MAGIC_64)
        cache.extend_from_slice(&0xFEED_FACF_u32.to_le_bytes());
        cache.resize(0x1000, 0xCC);

        // Single mapping: VA 0x100000000 → file offset 0, size 0x1000
        let mapping = DyldCacheMappingInfo {
            address: 0x0001_0000_0000,
            size: 0x1000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        let mappings = MappingSet::new(vec![mapping]);

        let extracted = extract_image(
            &cache,
            &mappings,
            0x0001_0000_0000,
            0x1000,
            "/test/lib".to_owned(),
        )
        .expect("extract");
        assert!(extracted.is_valid_macho());
        assert_eq!(extracted.data.len(), 0x1000);
    }
}
