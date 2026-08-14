//! Blitz suite for `rustre-mobile-dyld` — focuses on public API surfaces in
//! `lib.rs` (header parsing, mappings, images, symbols, slide fixups).

use rustre_mobile_dyld::{
    DyldCache, DyldCacheHeader, DyldCacheImage, DyldCacheMapping, DyldError, DyldHeader, DyldImage,
    DyldMapping, DyldSlideInfo, DyldSymbol, ExtractReport, SlideFixup, SlideInfoVersion,
};

// ─────────────────────────────────────────────────────────────────────────────
// DyldError
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn err_invalid_magic_contains_fields() {
    let e = DyldError::InvalidMagic {
        expected: "dyld_v1".into(),
        actual: "xx".into(),
    };
    let s = e.to_string();
    assert!(s.contains("dyld_v1"));
    assert!(s.contains("xx"));
}

#[test]
fn err_subcache_not_found_display() {
    let e = DyldError::SubcacheNotFound("x.1".into());
    assert!(e.to_string().contains("Sub-cache not found"));
}

#[test]
fn err_slide_fixup_display() {
    let e = DyldError::SlideFixup("bad chain".into());
    assert!(e.to_string().contains("Slide fixup error"));
}

#[test]
fn err_io_display() {
    let e = DyldError::Io("disk full".into());
    assert!(e.to_string().contains("IO error"));
    assert!(e.to_string().contains("disk full"));
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldHeader
// ─────────────────────────────────────────────────────────────────────────────

fn make_min_header_bytes() -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    data
}

#[test]
fn header_parse_too_short_errors() {
    let data = vec![0u8; 0x40];
    let err = DyldHeader::parse(&data).unwrap_err();
    assert!(matches!(err, DyldError::Truncated(_)));
}

#[test]
fn header_parse_bad_magic_errors() {
    let mut data = vec![0u8; 0x100];
    data[..8].copy_from_slice(b"NOTDYLD!");
    let err = DyldHeader::parse(&data).unwrap_err();
    match err {
        DyldError::InvalidMagic { expected, .. } => assert_eq!(expected, "dyld_v1"),
        _ => panic!(),
    }
}

#[test]
fn header_parse_minimal_ok() {
    let data = make_min_header_bytes();
    let h = DyldHeader::parse(&data).unwrap();
    assert!(h.magic.starts_with("dyld_v1"));
}

#[test]
fn header_uuid_string_zeroed() {
    let data = make_min_header_bytes();
    let h = DyldHeader::parse(&data).unwrap();
    assert_eq!(h.uuid_string(), "00000000-0000-0000-0000-000000000000");
}

#[test]
fn header_is_arm64_true() {
    let data = make_min_header_bytes();
    let h = DyldHeader::parse(&data).unwrap();
    assert!(h.is_arm64());
}

#[test]
fn header_is_arm64_false_for_x86() {
    let mut data = vec![0u8; 0x100];
    data[..16].copy_from_slice(b"dyld_v1  x86_64\0");
    let h = DyldHeader::parse(&data).unwrap();
    assert!(!h.is_arm64());
}

#[test]
fn header_platform_name_all_variants() {
    let mut h = DyldCache::mock().header;
    for (p, name) in &[
        (1u32, "iOS"),
        (2, "macOS"),
        (3, "tvOS"),
        (4, "watchOS"),
        (5, "bridgeOS"),
        (6, "macCatalyst"),
        (7, "iOSSimulator"),
        (8, "tvOSSimulator"),
        (9, "watchOSSimulator"),
        (10, "driverKit"),
        (999, "unknown"),
    ] {
        h.platform = *p;
        assert_eq!(h.platform_name(), *name, "platform {p}");
    }
}

#[test]
fn header_is_simulator() {
    let mut h = DyldCache::mock().header;
    h.platform = 7;
    assert!(h.is_simulator());
    h.platform = 9;
    assert!(h.is_simulator());
    h.platform = 1;
    assert!(!h.is_simulator());
    h.platform = 10;
    assert!(!h.is_simulator());
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldMapping
// ─────────────────────────────────────────────────────────────────────────────

const fn mk_mapping(addr: u64, size: u64, file_offset: u64, prot: u32) -> DyldMapping {
    DyldMapping {
        address: addr,
        size,
        file_offset,
        init_prot: prot,
        max_prot: prot,
        flags: 0,
    }
}

#[test]
fn mapping_prot_bits_independent() {
    let r = mk_mapping(0, 1, 0, 1);
    assert!(r.is_readable() && !r.is_writable() && !r.is_executable());
    let w = mk_mapping(0, 1, 0, 2);
    assert!(!w.is_readable() && w.is_writable() && !w.is_executable());
    let x = mk_mapping(0, 1, 0, 4);
    assert!(!x.is_readable() && !x.is_writable() && x.is_executable());
    let rwx = mk_mapping(0, 1, 0, 7);
    assert_eq!(rwx.prot_string(), "rwx");
}

#[test]
fn mapping_prot_string_combinations() {
    assert_eq!(mk_mapping(0, 0, 0, 0).prot_string(), "---");
    assert_eq!(mk_mapping(0, 0, 0, 1).prot_string(), "r--");
    assert_eq!(mk_mapping(0, 0, 0, 3).prot_string(), "rw-");
    assert_eq!(mk_mapping(0, 0, 0, 5).prot_string(), "r-x");
    assert_eq!(mk_mapping(0, 0, 0, 6).prot_string(), "-wx");
}

#[test]
fn mapping_end_address_saturates_on_overflow() {
    let m = mk_mapping(u64::MAX - 1, 100, 0, 1);
    assert_eq!(m.end_address(), u64::MAX);
}

#[test]
fn mapping_contains_va_boundaries() {
    let m = mk_mapping(0x1000, 0x1000, 0, 1);
    assert!(!m.contains_va(0x0FFF));
    assert!(m.contains_va(0x1000));
    assert!(m.contains_va(0x1FFF));
    assert!(!m.contains_va(0x2000));
}

#[test]
fn mapping_va_to_file_offset_translation() {
    let m = mk_mapping(0x1_8000_0000, 0x1000, 0xA000, 1);
    assert_eq!(m.va_to_file_offset(0x1_8000_0000), Some(0xA000));
    assert_eq!(m.va_to_file_offset(0x1_8000_0FFF), Some(0xA000 + 0xFFF));
    assert!(m.va_to_file_offset(0x1_8000_1000).is_none());
    assert!(m.va_to_file_offset(0).is_none());
}

#[test]
fn mapping_empty_contains_nothing() {
    let m = mk_mapping(0x1000, 0, 0, 7);
    assert!(!m.contains_va(0x1000));
    assert!(m.va_to_file_offset(0x1000).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldImage
// ─────────────────────────────────────────────────────────────────────────────

fn mk_image(path: &str) -> DyldImage {
    DyldImage {
        address: 0x1_8000_0000,
        mod_time: 0,
        inode: 0,
        path_offset: 0,
        path: path.to_string(),
    }
}

#[test]
fn image_filename_root_only() {
    let img = mk_image("libfoo.dylib");
    assert_eq!(img.filename(), "libfoo.dylib");
}

#[test]
fn image_filename_nested() {
    let img = mk_image("/a/b/c/foo.dylib");
    assert_eq!(img.filename(), "foo.dylib");
}

#[test]
fn image_filename_trailing_slash() {
    // edge: last segment is empty after final '/'
    let img = mk_image("/a/b/");
    assert_eq!(img.filename(), "");
}

#[test]
fn image_is_system_framework() {
    assert!(mk_image("/System/Library/x.dylib").is_system_framework());
    assert!(mk_image("/usr/lib/libc.dylib").is_system_framework());
    assert!(!mk_image("/Applications/Foo.app/Foo").is_system_framework());
}

#[test]
fn image_is_swift_overlay() {
    assert!(mk_image("/usr/lib/swift/libswiftCore.dylib").is_swift_overlay());
    assert!(!mk_image("/usr/lib/libc.dylib").is_swift_overlay());
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSymbol
// ─────────────────────────────────────────────────────────────────────────────

fn mk_sym(name: &str, flags: u32) -> DyldSymbol {
    DyldSymbol {
        name: name.to_string(),
        address: 0x1000,
        image_path: "/usr/lib/x.dylib".to_string(),
        flags,
    }
}

#[test]
fn symbol_is_weak() {
    assert!(mk_sym("_x", 0x40).is_weak());
    assert!(!mk_sym("_x", 0).is_weak());
    assert!(mk_sym("_x", 0xFF).is_weak());
}

#[test]
fn symbol_is_objc_variants() {
    assert!(mk_sym("_OBJC_CLASS_$_NSObject", 0).is_objc());
    assert!(mk_sym("+[NSObject alloc]", 0).is_objc());
    assert!(mk_sym("-[NSObject init]", 0).is_objc());
    assert!(!mk_sym("_malloc", 0).is_objc());
}

#[test]
fn symbol_is_swift_variants() {
    assert!(mk_sym("$sSiN", 0).is_swift());
    assert!(mk_sym("_$sSiN", 0).is_swift());
    assert!(!mk_sym("_malloc", 0).is_swift());
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCache::parse — adversarial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cache_parse_empty() {
    assert!(matches!(
        DyldCache::parse(&[]).unwrap_err(),
        DyldError::Truncated(_)
    ));
}

#[test]
fn cache_parse_just_magic_no_body() {
    let data = b"dyld_v1   arm64\0".to_vec();
    assert!(matches!(
        DyldCache::parse(&data).unwrap_err(),
        DyldError::Truncated(_)
    ));
}

#[test]
fn cache_parse_bad_magic() {
    let mut data = vec![0u8; 0x100];
    data[..8].copy_from_slice(b"OOPSMAGI");
    let e = DyldCache::parse(&data).unwrap_err();
    assert!(matches!(e, DyldError::InvalidMagic { .. }));
}

#[test]
fn cache_parse_modest_oversized_counts_break_safely() {
    // mapping_count and images_count larger than data can hold, but small
    // enough that an unchecked Vec::with_capacity won't OOM the harness.
    // (The u32::MAX form aborts the process — see BUG report.)
    let mut data = vec![0u8; 0x100];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    data[16..20].copy_from_slice(&0x80u32.to_le_bytes());
    data[20..24].copy_from_slice(&1000u32.to_le_bytes());
    data[24..28].copy_from_slice(&0x80u32.to_le_bytes());
    data[28..32].copy_from_slice(&1000u32.to_le_bytes());
    let c = DyldCache::parse(&data).expect("must not panic");
    assert!(c.mappings.len() < 100);
    assert!(c.images.len() < 100);
}

#[test]
fn cache_parse_roundtrip_serde() {
    let cache = DyldCache::mock();
    let json = serde_json::to_string(&cache).unwrap();
    let back: DyldCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back.image_count(), cache.image_count());
}

#[test]
fn cache_va_to_file_offset_via_mappings() {
    let cache = DyldCache::mock();
    assert_eq!(cache.va_to_file_offset(0x1_8000_0000), Some(0));
    assert!(cache.va_to_file_offset(0xDEAD_BEEF).is_none());
}

#[test]
fn cache_read_at_va_in_mock() {
    let cache = DyldCache::mock();
    // mock data is 4096 zeros at file offset 0; mapping starts at va 0x1_8000_0000.
    let slice = cache.read_at_va(0x1_8000_0000, 16).unwrap();
    assert_eq!(slice, [0u8; 16]);
}

#[test]
fn cache_read_at_va_out_of_bounds_returns_none() {
    let cache = DyldCache::mock();
    // Past the 4096-byte mock data buffer.
    assert!(cache.read_at_va(0x1_8000_0000 + 8192, 16).is_none());
}

#[test]
fn cache_find_images_containing_no_match() {
    let cache = DyldCache::mock();
    assert!(cache.find_images_containing("zzzz").is_empty());
}

#[test]
fn cache_find_symbols_for_image_no_match() {
    let cache = DyldCache::mock();
    assert!(cache.find_symbols_for_image("/no/such").is_empty());
}

#[test]
fn cache_extract_image_missing_path_errors() {
    let cache = DyldCache::mock();
    let err = cache.extract_image("/not/here").unwrap_err();
    assert!(matches!(err, DyldError::ImageNotFound(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// SlideFixup
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn slide_fixup_zero_slide_no_changes() {
    let f = SlideFixup::new(0x1_8000_0000, 0x1000, None);
    let mut data = vec![0u8; 64];
    // place a "pointer" value
    data[0..8].copy_from_slice(&0x1_8000_1000u64.to_le_bytes());
    let n = f.apply(&mut data, 0).unwrap();
    assert_eq!(n, 0);
    let v = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(v, 0x1_8000_1000);
}

#[test]
fn slide_fixup_heuristic_patches_in_range_pointers() {
    let f = SlideFixup::new(0x1_8000_0000, 0x1000, None);
    let mut data = vec![0u8; 32];
    data[0..8].copy_from_slice(&0x1_8000_1000u64.to_le_bytes()); // in window
    data[8..16].copy_from_slice(&0u64.to_le_bytes()); // out
    data[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes()); // in window
    data[24..32].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes()); // out
    let n = f.apply(&mut data, 0x1000).unwrap();
    assert_eq!(n, 2);
    assert_eq!(
        u64::from_le_bytes(data[0..8].try_into().unwrap()),
        0x1_8000_1000 + 0x1000
    );
    assert_eq!(
        u64::from_le_bytes(data[16..24].try_into().unwrap()),
        0x2_0000_0000 + 0x1000
    );
}

#[test]
fn slide_fixup_handles_data_smaller_than_8() {
    let f = SlideFixup::new(0, 0, None);
    let mut data = vec![0u8; 4];
    let n = f.apply(&mut data, 0x100).unwrap();
    assert_eq!(n, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheHeader (raw on-disk struct)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn raw_header_min_size_too_short() {
    let data = vec![0u8; DyldCacheHeader::MIN_SIZE - 1];
    assert!(matches!(
        DyldCacheHeader::parse(&data).unwrap_err(),
        DyldError::Truncated(_)
    ));
}

#[test]
fn raw_header_bad_magic() {
    let mut data = vec![0u8; 0x100];
    data[..7].copy_from_slice(b"XXX_v1!");
    assert!(matches!(
        DyldCacheHeader::parse(&data).unwrap_err(),
        DyldError::InvalidMagic { .. }
    ));
}

#[test]
fn raw_header_parse_min_ok_and_accessors() {
    let mut data = vec![0u8; DyldCacheHeader::MIN_SIZE];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    let h = DyldCacheHeader::parse(&data).unwrap();
    assert!(h.is_arm64());
    assert_eq!(h.magic_str(), "dyld_v1   arm64");
    assert!(!h.is_development());
    assert!(!h.has_sub_caches());
    assert_eq!(h.platform_name(), "unknown");
    assert_eq!(h.uuid_string(), "00000000-0000-0000-0000-000000000000");
}

#[test]
fn raw_header_roundtrip_to_bytes_then_parse() {
    let mut data = vec![0u8; 0xC0];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    // platform = 2 (macOS) at 0xB8
    data[0xB8..0xBC].copy_from_slice(&2u32.to_le_bytes());
    // sub_cache_array_count = 3 at 0x80
    data[0x80..0x88].copy_from_slice(&3u64.to_le_bytes());
    // cache_type = 1 (development) at 0x68
    data[0x68..0x70].copy_from_slice(&1u64.to_le_bytes());
    let h = DyldCacheHeader::parse(&data).unwrap();
    assert_eq!(h.platform_name(), "macOS");
    assert!(h.has_sub_caches());
    assert!(h.is_development());
    let out = h.to_bytes();
    let h2 = DyldCacheHeader::parse(&out).unwrap();
    assert_eq!(h2.platform, 2);
    assert_eq!(h2.sub_cache_array_count, 3);
    assert_eq!(h2.cache_type, 1);
    assert_eq!(h2.magic_str(), "dyld_v1   arm64");
}

#[test]
fn raw_header_platform_names() {
    let mut data = vec![0u8; 0xC0];
    data[..16].copy_from_slice(b"dyld_v1   arm64\0");
    for (p, name) in [
        (1u32, "iOS"),
        (2, "macOS"),
        (3, "tvOS"),
        (4, "watchOS"),
        (5, "bridgeOS"),
        (6, "macCatalyst"),
        (7, "iOSSimulator"),
        (8, "tvOSSimulator"),
        (9, "watchOSSimulator"),
        (42, "unknown"),
    ] {
        data[0xB8..0xBC].copy_from_slice(&p.to_le_bytes());
        let h = DyldCacheHeader::parse(&data).unwrap();
        assert_eq!(h.platform_name(), name, "platform {p}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheMapping (raw)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn raw_mapping_parse_short_errs() {
    let data = vec![0u8; 16];
    assert!(matches!(
        DyldCacheMapping::parse(&data, 0).unwrap_err(),
        DyldError::Truncated(_)
    ));
}

#[test]
fn raw_mapping_parse_ok_and_helpers() {
    let mut data = vec![0u8; 32];
    data[0..8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    data[8..16].copy_from_slice(&0x10_0000u64.to_le_bytes());
    data[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
    data[24..28].copy_from_slice(&5u32.to_le_bytes()); // max_prot
    data[28..32].copy_from_slice(&5u32.to_le_bytes()); // init_prot
    let m = DyldCacheMapping::parse(&data, 0).unwrap();
    assert_eq!(m.end_address(), 0x1_8010_0000);
    assert!(m.contains_va(0x1_8000_0000));
    assert!(!m.contains_va(0x1_8010_0000));
    assert_eq!(m.va_to_file_offset(0x1_8000_0010), Some(0x4010));
    assert_eq!(m.prot_string(), "r-x");
    assert!(m.is_readable());
    assert!(!m.is_writable());
    assert!(m.is_executable());
}

#[test]
fn raw_mapping_parse_all_with_zero_count() {
    let data = vec![0u8; 0x100];
    let h = DyldCacheHeader {
        magic: *b"dyld_v1   arm64\0",
        mapping_offset: 0,
        mapping_count: 0,
        images_offset: 0,
        images_count: 0,
        dyld_base_address: 0,
        code_signature_offset: 0,
        code_signature_size: 0,
        slide_info_offset_unused: 0,
        local_symbols_offset: 0,
        local_symbols_size: 0,
        uuid: [0; 16],
        cache_type: 0,
        branch_pools_offset: 0,
        branch_pools_count: 0,
        sub_cache_array_offset: 0,
        sub_cache_array_count: 0,
        symbol_file_uuid: [0; 16],
        rosetta_read_only_addr: 0,
        rosetta_read_write_addr: 0,
        images_text_offset: 0,
        images_text_count: 0,
        platform: 0,
        format_version: 0,
    };
    let v = DyldCacheMapping::parse_all(&data, &h);
    assert!(v.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldCacheImage (raw)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn raw_image_parse_short_errs() {
    let data = vec![0u8; 16];
    assert!(matches!(
        DyldCacheImage::parse(&data, 0).unwrap_err(),
        DyldError::Truncated(_)
    ));
}

#[test]
fn raw_image_parse_reads_path_cstring() {
    // Layout: 32-byte entry at offset 0; path string starts at file offset 32.
    let mut data = vec![0u8; 96];
    data[0..8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    data[8..16].copy_from_slice(&0u64.to_le_bytes());
    data[16..24].copy_from_slice(&0u64.to_le_bytes());
    data[24..28].copy_from_slice(&32u32.to_le_bytes()); // path_file_offset
    let path = b"/usr/lib/libSystem.B.dylib\0";
    data[32..32 + path.len()].copy_from_slice(path);
    let img = DyldCacheImage::parse(&data, 0).unwrap();
    assert_eq!(img.path, "/usr/lib/libSystem.B.dylib");
    assert_eq!(img.filename(), "libSystem.B.dylib");
    assert!(img.is_system_framework());
    assert!(!img.is_swift_overlay());
    assert!(!img.is_objc());
}

#[test]
fn raw_image_helpers_classification() {
    let mut img = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/usr/lib/libobjc.A.dylib".into(),
    };
    assert!(img.is_objc());
    img.path = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".into();
    assert!(img.is_objc());
    assert_eq!(img.framework_name(), Some("CoreFoundation"));
    img.path = "/usr/lib/libc.dylib".into();
    assert_eq!(img.framework_name(), None);
}

#[test]
fn raw_image_framework_name_nested() {
    let img = DyldCacheImage {
        address: 0,
        mod_time: 0,
        inode: 0,
        path_file_offset: 0,
        padding: 0,
        path: "/System/Library/Frameworks/UIKit.framework/UIKit".into(),
    };
    assert_eq!(img.framework_name(), Some("UIKit"));
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldSlideInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn slide_info_parse_too_short() {
    assert!(DyldSlideInfo::parse(&[]).is_none());
    assert!(DyldSlideInfo::parse(&[1, 0, 0]).is_none());
}

#[test]
fn slide_info_parse_unknown_version() {
    let data = 99u32.to_le_bytes().to_vec();
    let mut d = data;
    d.extend(std::iter::repeat_n(0u8, 64));
    assert!(DyldSlideInfo::parse(&d).is_none());
}

#[test]
fn slide_info_parse_v1() {
    let mut d = vec![0u8; 24];
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    // toc_count = 7 at offset 8
    d[8..12].copy_from_slice(&7u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V1);
    assert_eq!(si.page_size, 0x1000);
    assert_eq!(si.page_count, 7);
}

#[test]
fn slide_info_parse_v2() {
    let mut d = vec![0u8; 40];
    d[..4].copy_from_slice(&2u32.to_le_bytes());
    d[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
    d[12..16].copy_from_slice(&5u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V2);
    assert_eq!(si.page_size, 0x4000);
    assert_eq!(si.page_count, 5);
}

#[test]
fn slide_info_parse_v3() {
    let mut d = vec![0u8; 16];
    d[..4].copy_from_slice(&3u32.to_le_bytes());
    d[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
    d[8..12].copy_from_slice(&3u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V3);
    assert_eq!(si.page_count, 3);
}

#[test]
fn slide_info_parse_v5() {
    let mut d = vec![0u8; 16];
    d[..4].copy_from_slice(&5u32.to_le_bytes());
    d[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
    d[8..12].copy_from_slice(&2u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    assert_eq!(si.version, SlideInfoVersion::V5);
    assert_eq!(si.page_size, 0x4000);
}

#[test]
fn slide_info_extract_fixups_v1_returns_empty() {
    let mut d = vec![0u8; 24];
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    assert!(si.extract_fixups(&d, 0).is_empty());
}

#[test]
fn slide_info_extract_fixups_empty_when_pages_marked_ffff() {
    // v2 with one page entry of 0xFFFF (no pointers).
    let mut d = vec![0u8; 64];
    d[..4].copy_from_slice(&2u32.to_le_bytes());
    d[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // page_size
    d[8..12].copy_from_slice(&48u32.to_le_bytes()); // starts_offset
    d[12..16].copy_from_slice(&1u32.to_le_bytes()); // starts_count
    d[48..50].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let si = DyldSlideInfo::parse(&d).unwrap();
    let v = si.extract_fixups(&d, 0x1_8000_0000);
    assert!(v.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractReport
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn extract_report_default_is_zeroed() {
    let r = ExtractReport::default();
    assert_eq!(r.extracted_count, 0);
    assert_eq!(r.failed_count, 0);
    assert_eq!(r.total_bytes, 0);
    assert!(r.failures.is_empty());
}

#[test]
fn extract_report_serde_roundtrip() {
    let r = ExtractReport {
        extracted_count: 3,
        failed_count: 1,
        total_bytes: 12345,
        failures: vec!["x".into()],
    };
    let s = serde_json::to_string(&r).unwrap();
    let back: ExtractReport = serde_json::from_str(&s).unwrap();
    assert_eq!(back.extracted_count, 3);
    assert_eq!(back.failures, vec!["x".to_string()]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Send/Sync
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DyldCache>();
    assert_send_sync::<DyldHeader>();
    assert_send_sync::<DyldError>();
    assert_send_sync::<DyldMapping>();
    assert_send_sync::<DyldImage>();
    assert_send_sync::<DyldSymbol>();
    assert_send_sync::<SlideFixup>();
}
