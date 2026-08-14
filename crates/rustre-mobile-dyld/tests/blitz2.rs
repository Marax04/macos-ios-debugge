//! Deep adversarial coverage for rustre-mobile-dyld public API.
//!
//! All fuzz inputs are derived from a deterministic seeded LCG to keep the
//! suite reproducible. No `std::time` or external rng.

use rustre_mobile_dyld::{
    CacheInfo, DyldCache, DyldCacheHeader, DyldCacheImage, DyldCacheMapping, DyldError,
    DyldFullCache, DyldHeader, DyldImage, DyldImageTextInfo, DyldLocalSymbol, DyldLocalSymbolEntry,
    DyldLocalSymbolsHeader, DyldLocalSymbolsInfo, DyldMapping, DyldSlideInfo,
    DyldSubCacheDescriptor, DyldSymbol, ExtractReport, SlideFixup, SlideInfoVersion,
};

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(((self.next() >> 32) & 0xFF) as u8);
        }
        v
    }
}

// ─── Mock-based DyldCache (legacy) ───────────────────────────────────────────

#[test]
fn mock_cache_basic_shape() {
    let c = DyldCache::mock();
    assert_eq!(c.image_count(), 2);
    assert_eq!(c.symbol_count(), 3);
    assert!(c.header.is_arm64());
    assert_eq!(c.header.platform_name(), "iOS");
    assert!(!c.header.is_simulator());
}

#[test]
fn mock_cache_uuid_format() {
    let c = DyldCache::mock();
    let s = c.header.uuid_string();
    assert_eq!(s.len(), 36);
    assert_eq!(s.matches('-').count(), 4);
    assert!(s.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit()));
}

#[test]
fn mock_cache_serde_roundtrip_50() {
    let c = DyldCache::mock();
    for _ in 0..50 {
        let json = serde_json::to_string(&c).unwrap();
        let back: DyldCache = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_count(), c.image_count());
        assert_eq!(back.symbol_count(), c.symbol_count());
        assert_eq!(back.header.magic, c.header.magic);
    }
}

#[test]
fn mock_cache_find_image_paths() {
    let c = DyldCache::mock();
    assert!(c.find_image("/usr/lib/libSystem.B.dylib").is_some());
    assert!(c.find_image("/usr/lib/libobjc.A.dylib").is_some());
    assert!(c.find_image("/missing").is_none());
    assert_eq!(c.find_images_containing("lib").len(), 2);
    assert_eq!(c.find_images_containing("xxx").len(), 0);
}

#[test]
fn mock_cache_find_symbols() {
    let c = DyldCache::mock();
    assert!(c.find_symbol("_malloc").is_some());
    assert!(c.find_symbol("__nope__").is_none());
    let syms = c.find_symbols_for_image("/usr/lib/libSystem.B.dylib");
    assert_eq!(syms.len(), 2);
    let syms = c.find_symbols_for_image("/missing");
    assert_eq!(syms.len(), 0);
}

#[test]
fn mock_cache_va_translation() {
    let c = DyldCache::mock();
    assert_eq!(c.va_to_file_offset(0x1_8000_0000), Some(0));
    assert_eq!(c.va_to_file_offset(0x1_8000_0FFF), Some(0xFFF));
    assert_eq!(c.va_to_file_offset(0xFFFF_FFFF_FFFF_FFFF), None);
    assert!(c.read_at_va(0x1_8000_0000, 16).is_some());
    assert!(c.read_at_va(0xFFFF_FFFF, 16).is_none());
}

#[test]
fn mock_extract_image_data_oob() {
    let mut c = DyldCache::mock();
    c.images.push(DyldImage {
        address: 0xFFFF_0000,
        mod_time: 0,
        inode: 9,
        path_offset: 0,
        path: "/x".into(),
    });
    let last = c.images.last().unwrap();
    let e = c.extract_image_data(last).unwrap_err();
    assert!(matches!(e, DyldError::ImageNotFound(_)));
}

// ─── DyldMapping prot bits ───────────────────────────────────────────────────

#[test]
fn mapping_prot_string_all_combos() {
    for bits in 0u32..=7 {
        let m = DyldMapping {
            address: 0,
            size: 0x1000,
            file_offset: 0,
            init_prot: bits,
            max_prot: bits,
            flags: 0,
        };
        let s = m.prot_string();
        assert_eq!(s.len(), 3);
        assert_eq!(s.as_bytes()[0] == b'r', bits & 1 != 0);
        assert_eq!(s.as_bytes()[1] == b'w', bits & 2 != 0);
        assert_eq!(s.as_bytes()[2] == b'x', bits & 4 != 0);
    }
}

#[test]
fn mapping_contains_va_boundaries() {
    let m = DyldMapping {
        address: 0x1000,
        size: 0x1000,
        file_offset: 0,
        init_prot: 1,
        max_prot: 1,
        flags: 0,
    };
    assert!(!m.contains_va(0x0FFF));
    assert!(m.contains_va(0x1000));
    assert!(m.contains_va(0x1FFF));
    assert!(!m.contains_va(0x2000));
}

#[test]
fn mapping_end_address_saturating() {
    let m = DyldMapping {
        address: u64::MAX,
        size: 1,
        file_offset: 0,
        init_prot: 0,
        max_prot: 0,
        flags: 0,
    };
    assert_eq!(m.end_address(), u64::MAX);
}

#[test]
fn mapping_va_to_file_offset_50_inputs() {
    let m = DyldMapping {
        address: 0x1000,
        size: 0x1000,
        file_offset: 0x5000,
        init_prot: 1,
        max_prot: 1,
        flags: 0,
    };
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let v = g.next();
        let result = m.va_to_file_offset(v);
        if (0x1000..0x2000).contains(&v) {
            assert_eq!(result, Some(0x5000 + (v - 0x1000)));
        } else {
            assert_eq!(result, None);
        }
    }
}

// ─── DyldImage helpers ───────────────────────────────────────────────────────

#[test]
fn image_filename_no_slash() {
    let img = DyldImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_offset: 0,
        path: "bare.dylib".into(),
    };
    assert_eq!(img.filename(), "bare.dylib");
}

#[test]
fn image_classifications() {
    let sys = DyldImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_offset: 0,
        path: "/usr/lib/x.dylib".into(),
    };
    assert!(sys.is_system_framework());
    let sw = DyldImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_offset: 0,
        path: "/usr/lib/swift/libswiftCore.dylib".into(),
    };
    assert!(sw.is_swift_overlay());
    let app = DyldImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_offset: 0,
        path: "/Applications/App.app/X".into(),
    };
    assert!(!app.is_system_framework());
    assert!(!app.is_swift_overlay());
}

// ─── DyldSymbol classification ───────────────────────────────────────────────

#[test]
fn symbol_classification_matrix() {
    let cases = [
        ("_OBJC_CLASS_$_NSObject", true, false),
        ("+[NSObject alloc]", true, false),
        ("-[NSObject init]", true, false),
        ("$sSiN", false, true),
        ("_$sSi", false, true),
        ("_malloc", false, false),
    ];
    for (name, objc, swift) in cases {
        let s = DyldSymbol {
            name: name.to_string(),
            address: 0,
            image_path: "x".into(),
            flags: 0,
        };
        assert_eq!(s.is_objc(), objc, "objc {name}");
        assert_eq!(s.is_swift(), swift, "swift {name}");
    }
}

#[test]
fn symbol_weak_flag() {
    let s = DyldSymbol {
        name: "w".into(),
        address: 0,
        image_path: "x".into(),
        flags: 0x40,
    };
    assert!(s.is_weak());
    let s2 = DyldSymbol {
        name: "w".into(),
        address: 0,
        image_path: "x".into(),
        flags: 0,
    };
    assert!(!s2.is_weak());
}

// ─── DyldCache::parse fuzz ───────────────────────────────────────────────────

#[test]
fn parse_truncated_under_16() {
    for n in 0..16 {
        let err = DyldCache::parse(&vec![0u8; n]).unwrap_err();
        assert!(matches!(err, DyldError::Truncated(_)));
    }
}

#[test]
fn parse_truncated_between_16_and_100() {
    let mut data = vec![0u8; 60];
    data[..16].copy_from_slice(b"dyld_v1  arm64\0\0");
    let err = DyldCache::parse(&data).unwrap_err();
    assert!(matches!(err, DyldError::Truncated(_)));
}

#[test]
fn parse_bad_magic_fuzz_50() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let mut data = vec![0u8; 256];
        for byte in data.iter_mut().take(16) {
            *byte = ((g.next() >> 32) & 0xFF) as u8;
        }
        // Ensure not "dyld_v1"
        data[..7].copy_from_slice(b"XXXXXXX");
        let err = DyldCache::parse(&data).unwrap_err();
        assert!(matches!(err, DyldError::InvalidMagic { .. }));
    }
}

#[test]
fn parse_valid_min_header_fuzz_50() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let mut data = vec![0u8; 256];
        for byte in data.iter_mut().take(256).skip(16) {
            *byte = ((g.next() >> 32) & 0xFF) as u8;
        }
        data[..16].copy_from_slice(b"dyld_v1   arm64\0");
        // Zero out mapping/image counts so we don't trip oob reads
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        let result = DyldCache::parse(&data);
        assert!(result.is_ok());
    }
}

#[test]
fn parse_never_panics_random_256() {
    let mut g = Lcg::new(lcg_seed() ^ 0xAA);
    for _ in 0..200 {
        let data = g.bytes(256);
        let _ = DyldCache::parse(&data);
    }
}

// ─── DyldCacheHeader ─────────────────────────────────────────────────────────

#[test]
fn cache_header_min_size_constant() {
    assert_eq!(DyldCacheHeader::MIN_SIZE, 72);
}

#[test]
fn cache_header_parse_too_short() {
    for n in 0..DyldCacheHeader::MIN_SIZE {
        assert!(DyldCacheHeader::parse(&vec![0u8; n]).is_err());
    }
}

#[test]
fn cache_header_parse_invalid_magic_fuzz() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let mut data = g.bytes(256);
        data[..7].copy_from_slice(b"BADMAGI");
        let err = DyldCacheHeader::parse(&data).unwrap_err();
        assert!(matches!(err, DyldError::InvalidMagic { .. }));
    }
}

#[test]
fn cache_header_to_bytes_roundtrip_50() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        // Construct a header by writing valid magic then random bytes.
        let mut raw = vec![0u8; 0xC0];
        raw[..16].copy_from_slice(b"dyld_v1   arm64\0");
        for b in raw.iter_mut().skip(16) {
            *b = ((g.next() >> 32) & 0xFF) as u8;
        }
        // Ensure sub_cache_array_count high bits don't go absurd (still u64).
        let h = DyldCacheHeader::parse(&raw).unwrap();
        let bytes = h.to_bytes();
        let h2 = DyldCacheHeader::parse(&bytes).unwrap();
        assert_eq!(h.mapping_offset, h2.mapping_offset);
        assert_eq!(h.mapping_count, h2.mapping_count);
        assert_eq!(h.images_offset, h2.images_offset);
        assert_eq!(h.uuid, h2.uuid);
        assert_eq!(h.cache_type, h2.cache_type);
        assert_eq!(h.sub_cache_array_count, h2.sub_cache_array_count);
        assert_eq!(h.platform, h2.platform);
        assert_eq!(h.format_version, h2.format_version);
    }
}

#[test]
fn cache_header_platform_name_all_values() {
    let names: [(u32, &str); 10] = [
        (1, "iOS"),
        (2, "macOS"),
        (3, "tvOS"),
        (4, "watchOS"),
        (5, "bridgeOS"),
        (6, "macCatalyst"),
        (7, "iOSSimulator"),
        (8, "tvOSSimulator"),
        (9, "watchOSSimulator"),
        (999, "unknown"),
    ];
    for (p, expected) in names {
        let mut raw = vec![0u8; 0xC0];
        raw[..16].copy_from_slice(b"dyld_v1   arm64\0");
        raw[0xB8..0xBC].copy_from_slice(&p.to_le_bytes());
        let h = DyldCacheHeader::parse(&raw).unwrap();
        assert_eq!(h.platform_name(), expected);
    }
}

#[test]
fn cache_header_uuid_string() {
    let mut raw = vec![0u8; 0xC0];
    raw[..16].copy_from_slice(b"dyld_v1   arm64\0");
    for i in 0..16 {
        raw[0x58 + i] = i as u8; // loop bound is 16, cannot truncate
    }
    let h = DyldCacheHeader::parse(&raw).unwrap();
    let s = h.uuid_string();
    assert_eq!(s.len(), 36);
    assert!(s.starts_with("00010203"));
}

#[test]
fn cache_header_is_arm64_and_has_sub_caches() {
    let mut raw = vec![0u8; 0xC0];
    raw[..16].copy_from_slice(b"dyld_v1   arm64\0");
    raw[0x80..0x88].copy_from_slice(&2u64.to_le_bytes());
    let h = DyldCacheHeader::parse(&raw).unwrap();
    assert!(h.is_arm64());
    assert!(h.has_sub_caches());
}

#[test]
fn cache_header_is_development() {
    let mut raw = vec![0u8; 0xC0];
    raw[..16].copy_from_slice(b"dyld_v1   arm64\0");
    raw[0x68..0x70].copy_from_slice(&1u64.to_le_bytes());
    let h = DyldCacheHeader::parse(&raw).unwrap();
    assert!(h.is_development());
}

#[test]
fn cache_header_magic_str_truncates_at_nul() {
    let mut raw = vec![0u8; 0xC0];
    raw[..16].copy_from_slice(b"dyld_v1\0\0\0\0\0\0\0\0\0");
    let h = DyldCacheHeader::parse(&raw).unwrap();
    assert_eq!(h.magic_str(), "dyld_v1");
}

// ─── DyldCacheMapping ────────────────────────────────────────────────────────

#[test]
fn cache_mapping_entry_size_const() {
    assert_eq!(DyldCacheMapping::ENTRY_SIZE, 32);
}

#[test]
fn cache_mapping_parse_truncated_fuzz() {
    for n in 0..32 {
        let data = vec![0u8; n];
        assert!(matches!(
            DyldCacheMapping::parse(&data, 0),
            Err(DyldError::Truncated(_))
        ));
    }
}

#[test]
fn cache_mapping_parse_50_random() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let data = g.bytes(64);
        let m = DyldCacheMapping::parse(&data, 0).unwrap();
        assert!(m.prot_string().len() == 3);
        // No panic on saturating_add
        let _ = m.end_address();
    }
}

#[test]
fn cache_mapping_prot_checks() {
    let m = DyldCacheMapping {
        address: 0,
        size: 0,
        file_offset: 0,
        init_prot: 7,
        max_prot: 7,
    };
    assert!(m.is_readable());
    assert!(m.is_writable());
    assert!(m.is_executable());
    assert_eq!(m.prot_string(), "rwx");
}

// ─── DyldCacheImage ──────────────────────────────────────────────────────────

#[test]
fn cache_image_entry_size_const() {
    assert_eq!(DyldCacheImage::ENTRY_SIZE, 32);
}

#[test]
fn cache_image_parse_truncated() {
    for n in 0..32 {
        assert!(matches!(
            DyldCacheImage::parse(&vec![0u8; n], 0),
            Err(DyldError::Truncated(_))
        ));
    }
}

#[test]
fn cache_image_framework_name() {
    let img = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/System/Library/Frameworks/Foo.framework/Foo".into(),
    };
    assert_eq!(img.framework_name(), Some("Foo"));
    let dylib = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/usr/lib/libSystem.dylib".into(),
    };
    assert_eq!(dylib.framework_name(), None);
}

#[test]
fn cache_image_is_objc() {
    let img = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/usr/lib/libobjc.A.dylib".into(),
    };
    assert!(img.is_objc());
    let img2 = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".into(),
    };
    assert!(img2.is_objc());
}

// ─── DyldSlideInfo ───────────────────────────────────────────────────────────

#[test]
fn slide_info_unknown_version_returns_none() {
    let data = [0u8; 64];
    assert!(DyldSlideInfo::parse(&data).is_none());
}

#[test]
fn slide_info_v2_v3_v5_versions() {
    let mut v2 = vec![0u8; 64];
    v2[..4].copy_from_slice(&2u32.to_le_bytes());
    v2[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&v2).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V2);
    assert_eq!(si.page_size, 0x4000);

    let mut v3 = vec![0u8; 64];
    v3[..4].copy_from_slice(&3u32.to_le_bytes());
    v3[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&v3).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V3);

    let mut v5 = vec![0u8; 64];
    v5[..4].copy_from_slice(&5u32.to_le_bytes());
    v5[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&v5).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V5);
}

#[test]
fn slide_info_too_short_returns_none() {
    assert!(DyldSlideInfo::parse(&[]).is_none());
    assert!(DyldSlideInfo::parse(&[1, 0, 0]).is_none());
    // version=1 but short
    let mut v1 = vec![0u8; 10];
    v1[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(DyldSlideInfo::parse(&v1).is_none());
}

#[test]
fn slide_info_fuzz_never_panics() {
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..100 {
        let data = g.bytes(128);
        if let Some(si) = DyldSlideInfo::parse(&data) {
            // extract_fixups must not panic
            let _ = si.extract_fixups(&data, 0x1_8000_0000);
        }
    }
}

#[test]
fn slide_info_v1_extract_empty() {
    let mut v1 = vec![0u8; 64];
    v1[..4].copy_from_slice(&1u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&v1).unwrap();
    assert!(si.extract_fixups(&v1, 0).is_empty());
}

// ─── DyldLocalSymbolsHeader + Entry ──────────────────────────────────────────

#[test]
fn local_symbols_header_parse_truncated() {
    for n in 0..24 {
        assert!(matches!(
            DyldLocalSymbolsHeader::parse(&vec![0u8; n]),
            Err(DyldError::Truncated(_))
        ));
    }
}

#[test]
fn local_symbols_header_parse_roundtrip() {
    let mut data = vec![0u8; 24];
    data[0..4].copy_from_slice(&100u32.to_le_bytes());
    data[4..8].copy_from_slice(&200u32.to_le_bytes());
    data[8..12].copy_from_slice(&300u32.to_le_bytes());
    data[12..16].copy_from_slice(&400u32.to_le_bytes());
    data[16..20].copy_from_slice(&500u32.to_le_bytes());
    data[20..24].copy_from_slice(&600u32.to_le_bytes());
    let h = DyldLocalSymbolsHeader::parse(&data).unwrap();
    assert_eq!(h.nlist_offset, 100);
    assert_eq!(h.nlist_count, 200);
    assert_eq!(h.strings_offset, 300);
    assert_eq!(h.strings_size, 400);
    assert_eq!(h.entries_offset, 500);
    assert_eq!(h.entries_count, 600);
}

#[test]
fn local_symbol_entry_size() {
    assert_eq!(DyldLocalSymbolEntry::ENTRY_SIZE, 12);
}

#[test]
fn local_symbol_entry_truncated() {
    for n in 0..12 {
        assert!(matches!(
            DyldLocalSymbolEntry::parse(&vec![0u8; n], 0),
            Err(DyldError::Truncated(_))
        ));
    }
}

#[test]
fn local_symbol_classification() {
    let cases = [
        ("l_foo", true, false),
        ("L_bar", true, false),
        ("ltmpX", true, false),
        ("lCFString12", true, false),
        ("_OBJC_CLASS_$_NSObject", false, true),
        ("__OBJC_THING", false, true),
        ("_normal", false, false),
    ];
    for (n, cg, om) in cases {
        let s = DyldLocalSymbol {
            name: n.into(),
            address: 0,
            image_path: "x".into(),
            nlist_start_index: 0,
            nlist_count: 0,
        };
        assert_eq!(s.is_compiler_generated(), cg, "cg {n}");
        assert_eq!(s.is_objc_metadata(), om, "om {n}");
    }
}

#[test]
fn local_symbols_info_default_and_lookups() {
    let info = DyldLocalSymbolsInfo::default();
    assert!(info.find_by_name("anything").is_none());
    assert!(info.find_containing("x").is_empty());
    assert!(info.for_image("p").is_empty());
}

#[test]
fn local_symbols_info_parse_garbage_returns_empty() {
    // Bad blob → default
    let info = DyldLocalSymbolsInfo::parse(&[0u8; 4], 0, 4, &[]);
    assert!(info.symbols.is_empty());

    // size==0 → default
    let info2 = DyldLocalSymbolsInfo::parse(&[0u8; 100], 0, 0, &[]);
    assert!(info2.symbols.is_empty());
}

// ─── DyldFullCache ───────────────────────────────────────────────────────────

fn build_min_full_cache_bytes() -> Vec<u8> {
    let mut data = vec![0u8; 0x200];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    // mapping_offset=0x100, mapping_count=0, images_count=0
    data[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
    data
}

#[test]
fn full_cache_from_bytes_minimal() {
    let data = build_min_full_cache_bytes();
    let c = DyldFullCache::from_bytes(data).unwrap();
    assert_eq!(c.image_count(), 0);
    assert_eq!(c.mapping_count(), 0);
    assert!(c.data_len() >= 0x200);
    assert_eq!(c.aslr_slide, 0);
    assert!(!c.has_sub_caches());
}

#[test]
fn full_cache_from_bytes_invalid_magic() {
    let mut data = vec![0u8; 0x200];
    data[..16].copy_from_slice(b"NOTACACHE\0\0\0\0\0\0\0");
    let e = DyldFullCache::from_bytes(data).unwrap_err();
    assert!(matches!(e, DyldError::InvalidMagic { .. }));
}

#[test]
fn full_cache_apply_slide_zero_returns_zero() {
    let data = build_min_full_cache_bytes();
    let mut c = DyldFullCache::from_bytes(data).unwrap();
    assert_eq!(c.apply_slide(0), 0);
}

#[test]
fn full_cache_lookup_apis_empty() {
    let data = build_min_full_cache_bytes();
    let c = DyldFullCache::from_bytes(data).unwrap();
    assert!(c.find_image("/missing").is_none());
    assert!(c.get_image_at_address(0).is_none());
    assert!(c.vm_to_file_offset(0xABCD).is_none());
    assert!(c.read_at_va(0xABCD, 8).is_none());
    assert!(c.list_images().is_empty());
    assert!(c.find_symbol("x").is_none());
}

#[test]
fn full_cache_extract_missing_image_errs() {
    let data = build_min_full_cache_bytes();
    let c = DyldFullCache::from_bytes(data).unwrap();
    let e = c.extract_image("/missing").unwrap_err();
    assert!(matches!(e, DyldError::ImageNotFound(_)));
}

#[test]
fn full_cache_load_slide_info_no_blob() {
    let data = build_min_full_cache_bytes();
    let mut c = DyldFullCache::from_bytes(data).unwrap();
    c.load_slide_info();
    assert!(c.slide_info.is_none());
    // idempotent
    c.load_slide_info();
    assert!(c.slide_info.is_none());
}

#[test]
fn full_cache_load_local_symbols_no_blob() {
    let data = build_min_full_cache_bytes();
    let mut c = DyldFullCache::from_bytes(data).unwrap();
    c.load_local_symbols();
    assert!(c.local_symbols.is_none());
}

// ─── DyldSubCacheDescriptor ──────────────────────────────────────────────────

#[test]
fn subcache_descriptor_parse_zero_count() {
    let data = build_min_full_cache_bytes();
    let header = DyldCacheHeader::parse(&data).unwrap();
    let descs = DyldSubCacheDescriptor::parse_all(&data, &header);
    assert!(descs.is_empty());
}

#[test]
fn subcache_descriptor_fixed_size() {
    assert_eq!(DyldSubCacheDescriptor::FIXED_SIZE, 32);
}

// ─── DyldImageTextInfo ───────────────────────────────────────────────────────

#[test]
fn image_text_info_truncated() {
    for n in 0..32 {
        assert!(matches!(
            DyldImageTextInfo::parse(&vec![0u8; n], 0),
            Err(DyldError::Truncated(_))
        ));
    }
}

#[test]
fn image_text_info_uuid_string_length() {
    let mut data = vec![0u8; 64];
    for i in 0..16 {
        data[i] = i as u8; // loop bound is 16, cannot truncate
    }
    let e = DyldImageTextInfo::parse(&data, 0).unwrap();
    let s = e.uuid_string();
    assert_eq!(s.len(), 36);
}

// ─── SlideFixup ──────────────────────────────────────────────────────────────

#[test]
fn slide_fixup_zero_slide_noop() {
    let f = SlideFixup::new(0x1_8000_0000, 0x1000, None);
    let mut data = vec![0xAAu8; 64];
    let n = f.apply(&mut data, 0).unwrap();
    assert_eq!(n, 0);
    assert!(data.iter().all(|&b| b == 0xAA));
}

#[test]
fn slide_fixup_heuristic_rebases_in_range() {
    let f = SlideFixup::new(0x1_8000_0000, 0x1000, None);
    let mut data = vec![0u8; 16];
    let ptr: u64 = 0x1_8001_0000;
    data[0..8].copy_from_slice(&ptr.to_le_bytes());
    // Out-of-window value untouched
    let other: u64 = 0x42;
    data[8..16].copy_from_slice(&other.to_le_bytes());
    let n = f.apply(&mut data, 0x1000).unwrap();
    assert_eq!(n, 1);
    let v0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(v0, ptr + 0x1000);
    let v1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
    assert_eq!(v1, other);
}

#[test]
fn slide_fixup_fuzz_never_panics() {
    let f = SlideFixup::new(0x1_8000_0000, 0x1000, None);
    let mut g = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let mut data = g.bytes(64);
        let slide = g.next();
        let _ = f.apply(&mut data, slide);
    }
}

// ─── DyldError variants ──────────────────────────────────────────────────────

#[test]
fn dyld_error_display_all_variants() {
    let cases: Vec<DyldError> = vec![
        DyldError::InvalidMagic {
            expected: "a".into(),
            actual: "b".into(),
        },
        DyldError::Truncated(0),
        DyldError::InvalidOffset(0xFF),
        DyldError::ImageNotFound("x".into()),
        DyldError::Parse("p".into()),
        DyldError::SubcacheNotFound("s".into()),
        DyldError::SlideFixup("sf".into()),
        DyldError::Io("io".into()),
    ];
    for e in cases {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// ─── CacheInfo ───────────────────────────────────────────────────────────────

#[test]
fn cache_info_from_full() {
    let data = build_min_full_cache_bytes();
    let c = DyldFullCache::from_bytes(data).unwrap();
    let info = CacheInfo::from_full_cache(&c);
    assert_eq!(info.platform, "unknown");
    assert_eq!(info.cache_type, "production");
    assert!(info.magic.contains("dyld_v1"));
}

#[test]
fn cache_info_from_legacy_mock() {
    let c = DyldCache::mock();
    let info = CacheInfo::from_cache(&c);
    assert_eq!(info.platform, "iOS");
    assert_eq!(info.image_count, 2);
}

// ─── ExtractReport ──────────────────────────────────────────────────────────

#[test]
fn extract_report_default_and_serde() {
    let r = ExtractReport::default();
    assert_eq!(r.extracted_count, 0);
    assert_eq!(r.failed_count, 0);
    let json = serde_json::to_string(&r).unwrap();
    let back: ExtractReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_bytes, 0);
}

// ─── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn dyld_cache_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let c = Arc::new(DyldCache::mock());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&c);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for _ in 0..100 {
                acc += c.image_count();
                acc += c.symbol_count();
                let _ = c.find_image("/usr/lib/libSystem.B.dylib");
                let _ = c.find_symbol("_malloc");
                let _ = c.va_to_file_offset(0x1_8000_0000);
            }
            acc
        }));
    }
    let mut total = 0usize;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 4 * 100 * (2 + 3));
}

#[test]
fn dyld_full_cache_send_threaded() {
    use std::sync::Arc;
    use std::thread;
    let data = build_min_full_cache_bytes();
    let c = Arc::new(DyldFullCache::from_bytes(data).unwrap());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&c);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = c.image_count();
                let _ = c.mapping_count();
                let _ = c.data_len();
                let _ = c.list_images();
                let _ = c.find_image("/x");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── DyldHeader basic ────────────────────────────────────────────────────────

#[test]
fn dyld_header_simulator_classification() {
    let mut h = DyldCache::mock().header;
    h.platform = 7;
    assert!(h.is_simulator());
    h.platform = 8;
    assert!(h.is_simulator());
    h.platform = 9;
    assert!(h.is_simulator());
    h.platform = 1;
    assert!(!h.is_simulator());
}

#[test]
fn dyld_header_parse_truncated_lib() {
    for n in 0..0x100 {
        let result = DyldHeader::parse(&vec![0u8; n]);
        assert!(result.is_err());
    }
}

#[test]
fn dyld_header_parse_minimal() {
    let mut d = vec![0u8; 0x100];
    d[..16].copy_from_slice(b"dyld_v1   arm64\0");
    let h = DyldHeader::parse(&d).unwrap();
    assert!(h.is_arm64());
}
