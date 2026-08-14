//! `dyld_shared_cache_analyzer` — High-level analysis of dyld shared caches.
//!
//! Provides [`DyldSharedCacheAnalyzer`] which wraps a parsed cache and exposes
//! diagnostic queries: image enumeration, dependency scanning, symbol statistics,
//! duplicate-symbol detection, and a human-readable summary report.

use std::collections::{HashMap, HashSet};

use crate::{DyldError, DyldHeader, DyldImage, DyldMapping, DyldSymbol};

// ─────────────────────────────────────────────────────────────────────────────
// CacheHeader
// ─────────────────────────────────────────────────────────────────────────────

/// Distilled header information for analysis purposes.
///
/// Derived from a raw [`DyldHeader`]; adds computed fields that are expensive
/// to recompute on every query.
#[derive(Debug, Clone)]
pub struct CacheHeader {
    /// Raw magic string (e.g. `"dyld_v1   arm64e"`).
    pub magic: String,
    /// Platform identifier (1 = iOS, 2 = macOS, …).
    pub platform: u32,
    /// Human-readable platform name.
    pub platform_name: &'static str,
    /// Format version advertised by the cache.
    pub format_version: u32,
    /// UUID formatted as a lowercase hyphenated string.
    pub uuid_string: String,
    /// Preferred dyld base address.
    pub dyld_base_address: u64,
    /// Total byte size of all code-signature blobs.
    pub code_sig_size: u64,
    /// Whether the cache advertises sub-caches (iOS 16+ / macOS 13+).
    pub has_sub_caches: bool,
    /// Whether the magic indicates an `arm64`/`arm64e` cache.
    pub is_arm64: bool,
}

impl CacheHeader {
    /// Build a `CacheHeader` from a raw [`DyldHeader`].
    #[must_use]
    pub fn from_dyld_header(h: &DyldHeader) -> Self {
        Self {
            magic: h.magic.clone(),
            platform: h.platform,
            platform_name: h.platform_name(),
            format_version: h.format_version,
            uuid_string: h.uuid_string(),
            dyld_base_address: h.dyld_base_address,
            code_sig_size: h.code_sig_size,
            has_sub_caches: h.subcache_array_count > 0,
            is_arm64: h.is_arm64(),
        }
    }
}

impl std::fmt::Display for CacheHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CacheHeader {{ magic: {:?}, platform: {}, uuid: {}, arm64: {} }}",
            self.magic, self.platform_name, self.uuid_string, self.is_arm64
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheImage
// ─────────────────────────────────────────────────────────────────────────────

/// Analysis-layer view of a single Mach-O image inside the shared cache.
#[derive(Debug, Clone)]
pub struct CacheImage {
    /// Virtual address at which the Mach-O header of this image is mapped.
    pub load_address: u64,
    /// Full path (e.g. `/usr/lib/libSystem.B.dylib`).
    pub path: String,
    /// Filename component of the path.
    pub filename: String,
    /// Whether this is an Apple system framework/dylib.
    pub is_system: bool,
    /// Whether this is a Swift overlay dylib.
    pub is_swift: bool,
    /// Whether this is an Objective-C runtime dylib.
    pub is_objc: bool,
    /// Framework name, if the path contains `.framework/`.
    pub framework_name: Option<String>,
    /// Modification time from the image info table.
    pub mod_time: u64,
    /// Inode number from the image info table.
    pub inode: u64,
    /// Index in the original images array.
    pub index: usize,
}

impl CacheImage {
    /// Construct from a raw [`DyldImage`] at position `index` in the image list.
    #[must_use]
    pub fn from_dyld_image(img: &DyldImage, index: usize) -> Self {
        let filename = img.filename().to_string();
        let is_system = img.is_system_framework();
        let is_swift = img.is_swift_overlay();
        let is_objc = img.path.contains("libobjc") || img.path.contains("CoreFoundation");
        let framework_name = extract_framework_name(&img.path);

        Self {
            load_address: img.address,
            path: img.path.clone(),
            filename,
            is_system,
            is_swift,
            is_objc,
            framework_name,
            mod_time: img.mod_time,
            inode: img.inode,
            index,
        }
    }
}

impl std::fmt::Display for CacheImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:4}] {:#018x}  {}",
            self.index, self.load_address, self.path
        )
    }
}

fn extract_framework_name(path: &str) -> Option<String> {
    let idx = path.find(".framework/")?;
    let start = path[..idx].rfind('/')? + 1;
    Some(path[start..idx].to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced by [`DyldSharedCacheAnalyzer::generate_report`].
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    /// Distilled cache header.
    pub header: CacheHeader,
    /// Total number of images.
    pub image_count: usize,
    /// Total number of mappings.
    pub mapping_count: usize,
    /// Total number of symbols in the cache.
    pub symbol_count: usize,
    /// Breakdown of image count by framework vs. plain dylib.
    pub framework_count: usize,
    /// Number of Swift overlay images.
    pub swift_image_count: usize,
    /// Number of `ObjC` runtime images.
    pub objc_image_count: usize,
    /// Combined size of all executable mappings in bytes.
    pub executable_mapping_bytes: u64,
    /// Combined size of all writable mappings in bytes.
    pub writable_mapping_bytes: u64,
    /// Names of duplicate symbols (same name found in multiple images).
    pub duplicate_symbols: Vec<String>,
    /// Top-10 images by exported symbol count.
    pub top_images_by_symbol_count: Vec<(String, usize)>,
}

impl std::fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== dyld Shared Cache Analysis Report ===")?;
        writeln!(f, "{}", self.header)?;
        writeln!(f, "Images:      {}", self.image_count)?;
        writeln!(f, "  Frameworks: {}", self.framework_count)?;
        writeln!(f, "  Swift:      {}", self.swift_image_count)?;
        writeln!(f, "  ObjC:       {}", self.objc_image_count)?;
        writeln!(f, "Mappings:    {}", self.mapping_count)?;
        writeln!(
            f,
            "  Exec bytes: {:#x}",
            self.executable_mapping_bytes
        )?;
        writeln!(
            f,
            "  Write bytes: {:#x}",
            self.writable_mapping_bytes
        )?;
        writeln!(f, "Symbols:     {}", self.symbol_count)?;
        writeln!(f, "Duplicates:  {}", self.duplicate_symbols.len())?;
        writeln!(f, "Top images by symbol count:")?;
        for (path, count) in &self.top_images_by_symbol_count {
            writeln!(f, "  {count:6}  {path}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSharedCacheAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// High-level analyzer for a parsed dyld shared cache.
///
/// The analyzer owns the raw header / mappings / images / symbols data and
/// provides a collection of query methods for reverse-engineering workflows:
///
/// * `list_images()` — enumerate all embedded Mach-O images.
/// * `find_image_by_path()` — look up a specific library.
/// * `images_in_framework()` — list all images from a named framework.
/// * `find_symbol()` / `symbols_for_image()` — symbol lookup.
/// * `mappings_covering()` — find mappings that contain a VA.
/// * `generate_report()` — produce a comprehensive text report.
pub struct DyldSharedCacheAnalyzer {
    /// Analyzed header.
    pub header: CacheHeader,
    /// Analyzed image list.
    images: Vec<CacheImage>,
    /// Raw mappings.
    mappings: Vec<DyldMapping>,
    /// Raw symbols.
    symbols: Vec<DyldSymbol>,
    /// Value → image index lookup built at construction.
    path_index: HashMap<String, usize>,
    /// Symbol name → indices into `symbols` built at construction.
    symbol_index: HashMap<String, Vec<usize>>,
}

impl DyldSharedCacheAnalyzer {
    /// Construct an analyzer from the constituent parts of a parsed cache.
    ///
    /// Builds internal indexes in O(n) time.
    #[must_use]
    pub fn new(
        raw_header: &DyldHeader,
        raw_images: &[DyldImage],
        mappings: Vec<DyldMapping>,
        symbols: Vec<DyldSymbol>,
    ) -> Self {
        let header = CacheHeader::from_dyld_header(raw_header);

        let mut images = Vec::with_capacity(raw_images.len());
        let mut path_index = HashMap::with_capacity(raw_images.len());
        for (i, img) in raw_images.iter().enumerate() {
            path_index.insert(img.path.clone(), i);
            images.push(CacheImage::from_dyld_image(img, i));
        }

        let mut symbol_index: HashMap<String, Vec<usize>> =
            HashMap::with_capacity(symbols.len());
        for (i, sym) in symbols.iter().enumerate() {
            symbol_index.entry(sym.name.clone()).or_default().push(i);
        }

        Self {
            header,
            images,
            mappings,
            symbols,
            path_index,
            symbol_index,
        }
    }

    // ── Image queries ────────────────────────────────────────────────────────

    /// Return all images in the cache, ordered by load address.
    #[must_use]
    pub fn list_images(&self) -> Vec<&CacheImage> {
        let mut imgs: Vec<&CacheImage> = self.images.iter().collect();
        imgs.sort_by_key(|i| i.load_address);
        imgs
    }

    /// Find an image by its exact filesystem path.
    #[must_use]
    pub fn find_image_by_path(&self, path: &str) -> Option<&CacheImage> {
        let idx = *self.path_index.get(path)?;
        self.images.get(idx)
    }

    /// Find images whose path contains `fragment` (case-sensitive).
    #[must_use]
    pub fn find_images_containing(&self, fragment: &str) -> Vec<&CacheImage> {
        self.images
            .iter()
            .filter(|img| img.path.contains(fragment))
            .collect()
    }

    /// List all images that belong to the named framework.
    ///
    /// Matches when the path contains `<name>.framework/`.
    #[must_use]
    pub fn images_in_framework(&self, framework_name: &str) -> Vec<&CacheImage> {
        let needle = format!("{framework_name}.framework/");
        self.images
            .iter()
            .filter(|img| img.path.contains(&needle))
            .collect()
    }

    /// Return all Swift overlay images.
    #[must_use]
    pub fn swift_images(&self) -> Vec<&CacheImage> {
        self.images.iter().filter(|img| img.is_swift).collect()
    }

    /// Return all `ObjC` runtime images.
    #[must_use]
    pub fn objc_images(&self) -> Vec<&CacheImage> {
        self.images.iter().filter(|img| img.is_objc).collect()
    }

    /// Total number of images.
    #[must_use]
    pub const fn image_count(&self) -> usize {
        self.images.len()
    }

    // ── Symbol queries ───────────────────────────────────────────────────────

    /// Find a symbol by exact name. Returns the first match.
    #[must_use]
    pub fn find_symbol(&self, name: &str) -> Option<&DyldSymbol> {
        let idx = self.symbol_index.get(name)?.first().copied()?;
        self.symbols.get(idx)
    }

    /// Find all symbols with names containing `fragment`.
    #[must_use]
    pub fn find_symbols_containing(&self, fragment: &str) -> Vec<&DyldSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name.contains(fragment))
            .collect()
    }

    /// Return all symbols exported by the image at `image_path`.
    #[must_use]
    pub fn symbols_for_image(&self, image_path: &str) -> Vec<&DyldSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.image_path == image_path)
            .collect()
    }

    /// Detect duplicate symbol names (same name in two or more images).
    #[must_use]
    pub fn duplicate_symbols(&self) -> Vec<String> {
        let mut name_to_images: HashMap<&str, HashSet<&str>> = HashMap::new();
        for sym in &self.symbols {
            name_to_images
                .entry(&sym.name)
                .or_default()
                .insert(&sym.image_path);
        }
        let mut dups: Vec<String> = name_to_images
            .into_iter()
            .filter(|(_, imgs)| imgs.len() > 1)
            .map(|(name, _)| name.to_string())
            .collect();
        dups.sort();
        dups
    }

    // ── Mapping queries ──────────────────────────────────────────────────────

    /// Find the mapping that contains a given virtual address.
    #[must_use]
    pub fn mapping_for_va(&self, va: u64) -> Option<&DyldMapping> {
        self.mappings.iter().find(|m| {
            va >= m.address && va < m.address.saturating_add(m.size)
        })
    }

    /// Return all mappings that overlap the range `[start, end)`.
    #[must_use]
    pub fn mappings_covering(&self, start: u64, end: u64) -> Vec<&DyldMapping> {
        self.mappings
            .iter()
            .filter(|m| {
                let m_end = m.address.saturating_add(m.size);
                m.address < end && m_end > start
            })
            .collect()
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return a map from image path to its exported symbol count, sorted descending.
    #[must_use]
    pub fn symbol_count_per_image(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for sym in &self.symbols {
            *counts.entry(&sym.image_path).or_insert(0) += 1;
        }
        let mut v: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    // ── Report ────────────────────────────────────────────────────────────────

    /// Generate a comprehensive [`AnalysisReport`] of the cache.
    #[must_use]
    pub fn generate_report(&self) -> AnalysisReport {
        let framework_count = self
            .images
            .iter()
            .filter(|img| img.framework_name.is_some())
            .count();
        let swift_image_count = self.images.iter().filter(|img| img.is_swift).count();
        let objc_image_count = self.images.iter().filter(|img| img.is_objc).count();

        let executable_mapping_bytes: u64 = self
            .mappings
            .iter()
            .filter(|m| m.init_prot & 0x4 != 0)
            .map(|m| m.size)
            .sum();
        let writable_mapping_bytes: u64 = self
            .mappings
            .iter()
            .filter(|m| m.init_prot & 0x2 != 0)
            .map(|m| m.size)
            .sum();

        let duplicate_symbols = self.duplicate_symbols();
        let per_image = self.symbol_count_per_image();
        let top_images_by_symbol_count = per_image.into_iter().take(10).collect();

        AnalysisReport {
            header: self.header.clone(),
            image_count: self.images.len(),
            mapping_count: self.mappings.len(),
            symbol_count: self.symbols.len(),
            framework_count,
            swift_image_count,
            objc_image_count,
            executable_mapping_bytes,
            writable_mapping_bytes,
            duplicate_symbols,
            top_images_by_symbol_count,
        }
    }
}

impl std::fmt::Debug for DyldSharedCacheAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DyldSharedCacheAnalyzer")
            .field("images", &self.images.len())
            .field("mappings", &self.mappings.len())
            .field("symbols", &self.symbols.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an [`DyldSharedCacheAnalyzer`] from raw cache bytes.
///
/// Convenience wrapper that calls [`crate::DyldCache::parse`] internally.
///
/// # Errors
/// Returns [`DyldError`] if the header magic is invalid or the data is too short.
pub fn analyzer_from_bytes(data: &[u8]) -> Result<DyldSharedCacheAnalyzer, DyldError> {
    let cache = crate::DyldCache::parse(data)?;
    Ok(DyldSharedCacheAnalyzer::new(
        &cache.header,
        &cache.images,
        cache.mappings.clone(),
        cache.symbols.clone(),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DyldCache;

    fn make_analyzer() -> DyldSharedCacheAnalyzer {
        let cache = DyldCache::mock();
        DyldSharedCacheAnalyzer::new(
            &cache.header,
            &cache.images,
            cache.mappings.clone(),
            cache.symbols.clone(),
        )
    }

    #[test]
    fn test_list_images_count() {
        let a = make_analyzer();
        assert_eq!(a.list_images().len(), 2);
    }

    #[test]
    fn test_list_images_sorted_by_load_addr() {
        let a = make_analyzer();
        let imgs = a.list_images();
        for w in imgs.windows(2) {
            assert!(w[0].load_address <= w[1].load_address);
        }
    }

    #[test]
    fn test_find_image_by_path() {
        let a = make_analyzer();
        assert!(a.find_image_by_path("/usr/lib/libSystem.B.dylib").is_some());
        assert!(a.find_image_by_path("/nonexistent").is_none());
    }

    #[test]
    fn test_find_images_containing() {
        let a = make_analyzer();
        let found = a.find_images_containing("libobjc");
        assert_eq!(found.len(), 1);
        assert!(found[0].path.contains("libobjc"));
    }

    #[test]
    fn test_symbols_for_image() {
        let a = make_analyzer();
        let syms = a.symbols_for_image("/usr/lib/libSystem.B.dylib");
        assert_eq!(syms.len(), 2);
    }

    #[test]
    fn test_find_symbol() {
        let a = make_analyzer();
        assert!(a.find_symbol("_malloc").is_some());
        assert!(a.find_symbol("_nothere").is_none());
    }

    #[test]
    fn test_find_symbols_containing() {
        let a = make_analyzer();
        let syms = a.find_symbols_containing("_m");
        assert!(!syms.is_empty());
    }

    #[test]
    fn test_image_count() {
        let a = make_analyzer();
        assert_eq!(a.image_count(), 2);
    }

    #[test]
    fn test_mapping_for_va() {
        let a = make_analyzer();
        let m = a.mapping_for_va(0x1_8000_0000);
        assert!(m.is_some());
    }

    #[test]
    fn test_mapping_for_va_miss() {
        let a = make_analyzer();
        assert!(a.mapping_for_va(0x0).is_none());
    }

    #[test]
    fn test_mappings_covering() {
        let a = make_analyzer();
        let ms = a.mappings_covering(0x1_8000_0000, 0x1_8001_0000);
        assert!(!ms.is_empty());
    }

    #[test]
    fn test_symbol_count_per_image_sorted() {
        let a = make_analyzer();
        let counts = a.symbol_count_per_image();
        for w in counts.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn test_generate_report() {
        let a = make_analyzer();
        let r = a.generate_report();
        assert_eq!(r.image_count, 2);
        assert_eq!(r.symbol_count, 3);
        assert_eq!(r.mapping_count, 1);
        let text = r.to_string();
        assert!(text.contains("Analysis Report"));
    }

    #[test]
    fn test_duplicate_symbols_empty_when_unique() {
        let a = make_analyzer();
        let dups = a.duplicate_symbols();
        // Mock cache has no duplicate symbol names across images
        assert!(dups.is_empty());
    }

    #[test]
    fn test_cache_header_display() {
        let a = make_analyzer();
        let s = a.header.to_string();
        assert!(s.contains("CacheHeader"));
    }

    #[test]
    fn test_cache_image_display() {
        let a = make_analyzer();
        let img = &a.list_images()[0];
        let s = img.to_string();
        assert!(s.contains("0x"));
    }

    #[test]
    fn test_cache_header_is_arm64() {
        let a = make_analyzer();
        assert!(a.header.is_arm64);
    }

    #[test]
    fn test_images_in_framework_empty() {
        let a = make_analyzer();
        // Mock images are plain dylibs, not frameworks
        let frames = a.images_in_framework("UIKit");
        assert!(frames.is_empty());
    }

    #[test]
    fn test_swift_images() {
        let a = make_analyzer();
        // Mock images don't contain "swift" in their paths
        let _ = a.swift_images();
    }

    #[test]
    fn test_objc_images() {
        let a = make_analyzer();
        let objc = a.objc_images();
        // libobjc.A.dylib contains "libobjc"
        assert!(!objc.is_empty());
    }

    #[test]
    fn test_analyzer_from_bad_bytes_errors() {
        let err = analyzer_from_bytes(b"bad").unwrap_err();
        assert!(matches!(err, DyldError::Truncated(_)));
    }

    #[test]
    fn test_analyzer_debug() {
        let a = make_analyzer();
        let s = format!("{a:?}");
        assert!(s.contains("DyldSharedCacheAnalyzer"));
    }

    #[test]
    fn test_extract_framework_name_present() {
        let name = extract_framework_name(
            "/System/Library/Frameworks/Foundation.framework/Foundation",
        );
        assert_eq!(name.as_deref(), Some("Foundation"));
    }

    #[test]
    fn test_extract_framework_name_absent() {
        assert!(extract_framework_name("/usr/lib/libSystem.B.dylib").is_none());
    }
}
