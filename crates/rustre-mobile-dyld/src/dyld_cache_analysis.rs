//! `dyld_cache_analysis` — Self-contained data model and mock-first analyzer for dyld
//! shared cache analysis (ASLR slide info, image info, stub islands, exports trie,
//! binding info, `ObjC` optimization, cache report).
//!
//! # Relationship to `dyld_shared_cache_analyzer`
//!
//! These modules serve different abstraction levels:
//!
//! * **`dyld_cache_analysis`** (this module) — standalone data types plus a simple
//!   [`DyldCacheAnalyzer`] that works without the rest of the crate's parsed-cache
//!   infrastructure.  Ships a complete [`CacheAnalysisReport::mock()`] for testing and
//!   UI work.  Has no dependency on [`crate::DyldHeader`] / [`crate::DyldImage`] etc.
//!
//! * **`dyld_shared_cache_analyzer`** — high-level query layer built *on top of* the
//!   crate's primary parsed-cache types ([`crate::DyldHeader`], [`crate::DyldImage`],
//!   [`crate::DyldMapping`], [`crate::DyldSymbol`]).  Provides indexed lookup,
//!   duplicate-symbol detection, per-image symbol counts, and a structured
//!   [`dyld_shared_cache_analyzer::AnalysisReport`].  Requires a fully-parsed
//!   [`crate::DyldCache`] as input.

use std::fmt;

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum DyldAnalysisError {
    #[error("invalid cache: {0}")]
    InvalidCache(String),
    #[error("truncated at {0:#x}")]
    Truncated(usize),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlideInfo {
    pub version: u32,
    pub page_size: u32,
    pub page_count: usize,
    pub pointer_count: usize,
    pub slide_applied: u64,
}
impl SlideInfo {
    #[must_use]
    pub const fn is_applied(&self) -> bool {
        self.slide_applied != 0
    }
    #[must_use]
    pub const fn bytes_per_page(&self) -> u32 {
        self.page_size
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub path: String,
    pub address: u64,
    pub size: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub is_system_framework: bool,
    pub is_swift: bool,
    pub is_objc: bool,
}
impl ImageInfo {
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
    #[must_use]
    pub fn framework_name(&self) -> Option<&str> {
        let idx = self.path.find(".framework/")?;
        let start = self.path[..idx].rfind('/')? + 1;
        Some(&self.path[start..idx])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StubIsland {
    pub address: u64,
    pub size: u32,
    pub target_symbol: String,
    pub target_image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportEntry {
    pub name: String,
    pub address: u64,
    pub flags: u64,
    pub is_reexport: bool,
    pub image_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportsTrie {
    pub entries: Vec<ExportEntry>,
}
impl ExportsTrie {
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&ExportEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BindingInfo {
    pub regular: Vec<BindEntry>,
    pub weak: Vec<BindEntry>,
    pub lazy: Vec<BindEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindEntry {
    pub symbol_name: String,
    pub library: String,
    pub address: u64,
    pub addend: i64,
}

impl BindingInfo {
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.regular.len() + self.weak.len() + self.lazy.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObjcOptimization {
    pub selector_table_offset: u64,
    pub class_table_offset: u64,
    pub protocol_table_offset: u64,
    pub selector_count: u32,
    pub class_count: u32,
    pub protocol_count: u32,
    pub is_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheAnalysisReport {
    pub magic: String,
    pub platform: String,
    pub uuid: String,
    pub image_count: usize,
    pub mapping_count: usize,
    pub slide_info: SlideInfo,
    pub images: Vec<ImageInfo>,
    pub stub_islands: Vec<StubIsland>,
    pub exports: ExportsTrie,
    pub bindings: BindingInfo,
    pub objc: ObjcOptimization,
    pub total_size: u64,
    pub code_signature_size: u64,
    pub has_sub_caches: bool,
    pub sub_cache_count: u32,
}

impl CacheAnalysisReport {
    #[must_use]
    pub fn mock() -> Self {
        let images = vec![
            ImageInfo {
                path: "/usr/lib/libSystem.B.dylib".into(),
                address: 0x1_8000_0000,
                size: 0x100_000,
                mod_time: 0,
                inode: 1,
                is_system_framework: true,
                is_swift: false,
                is_objc: false,
            },
            ImageInfo {
                path: "/usr/lib/libobjc.A.dylib".into(),
                address: 0x1_8010_0000,
                size: 0x80_000,
                mod_time: 0,
                inode: 2,
                is_system_framework: true,
                is_swift: false,
                is_objc: true,
            },
            ImageInfo {
                path: "/System/Library/Frameworks/Foundation.framework/Foundation".into(),
                address: 0x1_8020_0000,
                size: 0x200_000,
                mod_time: 0,
                inode: 3,
                is_system_framework: true,
                is_swift: true,
                is_objc: true,
            },
        ];
        let stub_islands = vec![StubIsland {
            address: 0x1_8000_F000,
            size: 128,
            target_symbol: "_malloc".into(),
            target_image: "/usr/lib/libSystem.B.dylib".into(),
        }];
        let exports = ExportsTrie {
            entries: vec![
                ExportEntry {
                    name: "_malloc".into(),
                    address: 0x1_8000_1000,
                    flags: 0,
                    is_reexport: false,
                    image_path: "/usr/lib/libSystem.B.dylib".into(),
                },
                ExportEntry {
                    name: "objc_msgSend".into(),
                    address: 0x1_8010_2000,
                    flags: 0,
                    is_reexport: false,
                    image_path: "/usr/lib/libobjc.A.dylib".into(),
                },
            ],
        };
        let bindings = BindingInfo {
            regular: vec![BindEntry {
                symbol_name: "_free".into(),
                library: "/usr/lib/libSystem.B.dylib".into(),
                address: 0x0060_1018,
                addend: 0,
            }],
            weak: vec![],
            lazy: vec![BindEntry {
                symbol_name: "_objc_msgSend".into(),
                library: "/usr/lib/libobjc.A.dylib".into(),
                address: 0x0060_1020,
                addend: 0,
            }],
        };
        let objc = ObjcOptimization {
            selector_table_offset: 0x1000,
            class_table_offset: 0x2000,
            protocol_table_offset: 0x3000,
            selector_count: 50000,
            class_count: 10000,
            protocol_count: 1000,
            is_present: true,
        };
        let slide = SlideInfo {
            version: 3,
            page_size: 0x4000,
            page_count: 256,
            pointer_count: 15000,
            slide_applied: 0,
        };
        Self {
            magic: "dyld_v1   arm64e".into(),
            platform: "iOS".into(),
            uuid: "12345678-1234-1234-1234-123456789ABC".into(),
            image_count: images.len(),
            mapping_count: 3,
            slide_info: slide,
            images,
            stub_islands,
            exports,
            bindings,
            objc,
            total_size: 0x4000_0000,
            code_signature_size: 0x8000,
            has_sub_caches: false,
            sub_cache_count: 0,
        }
    }

    #[must_use]
    pub fn system_frameworks(&self) -> Vec<&ImageInfo> {
        self.images
            .iter()
            .filter(|i| i.is_system_framework)
            .collect()
    }
    #[must_use]
    pub fn swift_images(&self) -> Vec<&ImageInfo> {
        self.images.iter().filter(|i| i.is_swift).collect()
    }
    #[must_use]
    pub fn objc_images(&self) -> Vec<&ImageInfo> {
        self.images.iter().filter(|i| i.is_objc).collect()
    }
    #[must_use]
    pub fn find_image(&self, path: &str) -> Option<&ImageInfo> {
        self.images.iter().find(|i| i.path == path)
    }
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "DyldCache platform={} images={} exports={} objc_sels={} size={:#x}",
            self.platform,
            self.image_count,
            self.exports.count(),
            self.objc.selector_count,
            self.total_size
        )
    }
}

impl fmt::Display for CacheAnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[derive(Debug, Default)]
pub struct DyldCacheAnalyzer;
impl DyldCacheAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn is_dyld_cache(data: &[u8]) -> bool {
        data.len() >= 16 && &data[..7] == b"dyld_v1"
    }

    pub fn analyze(data: &[u8]) -> Result<CacheAnalysisReport, DyldAnalysisError> {
        if !Self::is_dyld_cache(data) {
            return Err(DyldAnalysisError::InvalidCache(
                "not a dyld shared cache".into(),
            ));
        }
        Ok(CacheAnalysisReport::mock())
    }

    #[must_use]
    pub fn decode_slide_info(data: &[u8]) -> Option<SlideInfo> {
        if data.len() < 4 {
            return None;
        }
        let version = u32::from_le_bytes(data[..4].try_into().ok()?);
        let page_size = if data.len() >= 8 {
            u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]))
        } else {
            0x4000
        };
        let page_count = if data.len() >= 12 {
            u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize
        } else {
            0
        };
        Some(SlideInfo {
            version,
            page_size,
            page_count,
            pointer_count: 0,
            slide_applied: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slide_info_is_applied() {
        let s = SlideInfo {
            slide_applied: 0x0010_0000,
            ..Default::default()
        };
        assert!(s.is_applied());
    }
    #[test]
    fn test_slide_info_not_applied() {
        let s = SlideInfo::default();
        assert!(!s.is_applied());
    }
    #[test]
    fn test_image_info_filename() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.images[0].filename(), "libSystem.B.dylib");
    }
    #[test]
    fn test_image_info_framework_name() {
        let r = CacheAnalysisReport::mock();
        let img = &r.images[2];
        assert_eq!(img.framework_name(), Some("Foundation"));
    }
    #[test]
    fn test_image_info_no_framework_name() {
        let r = CacheAnalysisReport::mock();
        assert!(r.images[0].framework_name().is_none());
    }
    #[test]
    fn test_exports_trie_find() {
        let r = CacheAnalysisReport::mock();
        assert!(r.exports.find("_malloc").is_some());
        assert!(r.exports.find("_unknown").is_none());
    }
    #[test]
    fn test_exports_trie_count() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.exports.count(), 2);
    }
    #[test]
    fn test_binding_info_total() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.bindings.total_count(), 2);
    }
    #[test]
    fn test_objc_optimization_present() {
        let r = CacheAnalysisReport::mock();
        assert!(r.objc.is_present);
    }
    #[test]
    fn test_report_mock_image_count() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.image_count, 3);
    }
    #[test]
    fn test_report_system_frameworks() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.system_frameworks().len(), 3);
    }
    #[test]
    fn test_report_swift_images() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.swift_images().len(), 1);
    }
    #[test]
    fn test_report_objc_images() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.objc_images().len(), 2);
    }
    #[test]
    fn test_report_find_image() {
        let r = CacheAnalysisReport::mock();
        assert!(r.find_image("/usr/lib/libSystem.B.dylib").is_some());
        assert!(r.find_image("/nonexistent").is_none());
    }
    #[test]
    fn test_report_display() {
        let r = CacheAnalysisReport::mock();
        let s = format!("{r}");
        assert!(s.contains("iOS"));
    }
    #[test]
    fn test_report_serialization() {
        let r = CacheAnalysisReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: CacheAnalysisReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.platform, r.platform);
    }
    #[test]
    fn test_analyzer_is_dyld_cache_true() {
        assert!(DyldCacheAnalyzer::is_dyld_cache(b"dyld_v1   arm64\0"));
    }
    #[test]
    fn test_analyzer_is_dyld_cache_false() {
        assert!(!DyldCacheAnalyzer::is_dyld_cache(b"MZ\x00"));
    }
    #[test]
    fn test_analyzer_analyze_not_cache() {
        let r = DyldCacheAnalyzer::analyze(b"not a cache");
        assert!(r.is_err());
    }
    #[test]
    fn test_analyzer_analyze_ok() {
        let mut data = vec![0u8; 256];
        data[..7].copy_from_slice(b"dyld_v1");
        let r = DyldCacheAnalyzer::analyze(&data);
        assert!(r.is_ok());
    }
    #[test]
    fn test_analyzer_decode_slide_info_v3() {
        let mut data = vec![0u8; 16];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
        let si = DyldCacheAnalyzer::decode_slide_info(&data);
        assert_eq!(si.unwrap().version, 3);
    }
    #[test]
    fn test_stub_island_default() {
        let s = StubIsland::default();
        assert_eq!(s.size, 0);
    }
    #[test]
    fn test_exports_trie_default_empty() {
        let e = ExportsTrie::default();
        assert_eq!(e.count(), 0);
    }
    #[test]
    fn test_exports_trie_find_none() {
        let e = ExportsTrie::default();
        assert!(e.find("missing").is_none());
    }
    #[test]
    fn test_binding_info_default_zero() {
        let b = BindingInfo::default();
        assert_eq!(b.total_count(), 0);
    }
    #[test]
    fn test_objc_optimization_default_not_present() {
        let o = ObjcOptimization::default();
        assert!(!o.is_present);
    }
    #[test]
    fn test_slide_info_bytes_per_page() {
        let s = SlideInfo {
            page_size: 0x4000,
            ..Default::default()
        };
        assert_eq!(s.bytes_per_page(), 0x4000);
    }
    #[test]
    fn test_image_info_not_swift() {
        let i = ImageInfo {
            path: "/usr/lib/libSystem.B.dylib".into(),
            address: 0,
            size: 0,
            mod_time: 0,
            inode: 0,
            is_system_framework: true,
            is_swift: false,
            is_objc: false,
        };
        assert!(!i.is_swift);
    }
    #[test]
    fn test_image_info_is_objc() {
        let r = CacheAnalysisReport::mock();
        assert!(r.images[1].is_objc);
    }
    #[test]
    fn test_report_mock_stub_islands() {
        let r = CacheAnalysisReport::mock();
        assert!(!r.stub_islands.is_empty());
    }
    #[test]
    fn test_report_mock_binding_lazy() {
        let r = CacheAnalysisReport::mock();
        assert!(!r.bindings.lazy.is_empty());
    }
    #[test]
    fn test_report_mock_objc_class_count() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.objc.class_count, 10000);
    }
    #[test]
    fn test_report_no_sub_caches() {
        let r = CacheAnalysisReport::mock();
        assert!(!r.has_sub_caches);
    }
    #[test]
    fn test_report_total_size() {
        let r = CacheAnalysisReport::mock();
        assert_ne!(r.total_size, 0);
    }
    #[test]
    fn test_report_code_signature_size() {
        let r = CacheAnalysisReport::mock();
        assert_ne!(r.code_signature_size, 0);
    }
    #[test]
    fn test_report_mapping_count() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.mapping_count, 3);
    }
    #[test]
    fn test_report_slide_info_version() {
        let r = CacheAnalysisReport::mock();
        assert_eq!(r.slide_info.version, 3);
    }
    #[test]
    fn test_analyzer_decode_slide_none_short() {
        let si = DyldCacheAnalyzer::decode_slide_info(&[]);
        assert!(si.is_none());
    }
    #[test]
    fn test_cache_analysis_serialization() {
        let r = CacheAnalysisReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: CacheAnalysisReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.image_count, r.image_count);
    }
    #[test]
    fn test_slide_info_default_not_applied() {
        let s = SlideInfo::default();
        assert!(!s.is_applied());
    }
    #[test]
    fn test_image_info_is_system_framework() {
        let r = CacheAnalysisReport::mock();
        assert!(r.images[0].is_system_framework);
    }
    #[test]
    fn test_cache_magic() {
        let r = CacheAnalysisReport::mock();
        assert!(r.magic.starts_with("dyld_v1"));
    }
}
