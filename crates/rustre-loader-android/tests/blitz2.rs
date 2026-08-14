//! Deep adversarial coverage for rustre-loader-android public API.

use rustre_loader_android::*;

// ── seeded LCG ─────────────────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut g = lcg();
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.extend_from_slice(&g().to_le_bytes());
    }
    v.truncate(n);
    v
}

// ── magic detection ───────────────────────────────────────────────────────
#[test]
fn is_dex_recognises_valid_magic() {
    let mut data = b"dex\n035\0".to_vec();
    data.extend_from_slice(&[0u8; 200]);
    assert!(is_dex(&data));
}

#[test]
fn is_dex_rejects_short() {
    assert!(!is_dex(b""));
    assert!(!is_dex(b"dex"));
    assert!(!is_dex(b"dex\n"));
    assert!(!is_dex(b"dex\n035"));
}

#[test]
fn is_dex_rejects_non_digit_version() {
    let data = b"dex\nABCD";
    assert!(!is_dex(data));
}

#[test]
fn is_apk_requires_pk_header() {
    assert!(!is_apk(b""));
    assert!(!is_apk(b"PK\x03\x04"));
    let mut v = b"PK\x03\x04".to_vec();
    v.extend_from_slice(b"classes.dex");
    assert!(is_apk(&v));
}

#[test]
fn is_apk_rejects_wrong_signature() {
    let mut v = b"XX\x03\x04".to_vec();
    v.extend_from_slice(b"classes.dex");
    assert!(!is_apk(&v));
}

#[test]
fn is_vdex_recognises_magic() {
    let mut data = b"vdex019\0".to_vec();
    data.extend_from_slice(&[0u8; 40]);
    assert!(is_vdex(&data));
}

#[test]
fn is_vdex_rejects_short_and_nondigit() {
    assert!(!is_vdex(b""));
    assert!(!is_vdex(b"vdex"));
    assert!(!is_vdex(b"vdexabcd"));
}

// ── adler32 ────────────────────────────────────────────────────────────────
#[test]
fn adler32_empty_is_one() {
    assert_eq!(adler32(b""), 1);
}

#[test]
fn adler32_known_vectors() {
    // Known: adler32("Wikipedia") = 0x11E60398
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    assert_eq!(adler32(b"a"), 0x0062_0062);
}

#[test]
fn adler32_deterministic_over_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 1024) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        assert_eq!(adler32(&data), adler32(&data));
    }
}

#[test]
fn verify_dex_checksum_truncated() {
    assert!(matches!(
        verify_dex_checksum(&[0; 4]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn verify_dex_checksum_mismatch() {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(b"dex\n");
    data[8..12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let r = verify_dex_checksum(&data);
    assert!(matches!(r, Err(AndroidLoaderError::ChecksumMismatch { .. })));
}

#[test]
fn verify_dex_checksum_match_roundtrip() {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(b"dex\n");
    let cs = adler32(&data[12..]);
    data[8..12].copy_from_slice(&cs.to_le_bytes());
    assert!(verify_dex_checksum(&data).is_ok());
}

// ── DexHeader ──────────────────────────────────────────────────────────────
fn build_dex_blob() -> Vec<u8> {
    let mut data = vec![0u8; 256];
    data[0..8].copy_from_slice(b"dex\n035\0");
    data[32..36].copy_from_slice(&256u32.to_le_bytes()); // file_size
    data[36..40].copy_from_slice(&112u32.to_le_bytes()); // header_size
    data[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian
    let cs = adler32(&data[12..]);
    data[8..12].copy_from_slice(&cs.to_le_bytes());
    data
}

#[test]
fn dex_header_parses_minimum() {
    let data = build_dex_blob();
    let h = DexHeader::parse(&data).expect("parse");
    assert!(h.is_valid());
    assert_eq!(h.version_str(), "035");
    assert_eq!(h.version_int(), 35);
    assert_eq!(h.file_size, 256);
    assert_eq!(h.header_size, 112);
    assert!(h.is_little_endian());
}

#[test]
fn dex_header_truncated() {
    assert!(matches!(
        DexHeader::parse(&[0; 111]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn dex_header_invalid_magic() {
    let mut d = vec![0u8; 256];
    d[0..4].copy_from_slice(b"XXX\n");
    assert!(matches!(
        DexHeader::parse(&d),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn dex_header_off_by_one_boundary() {
    let mut d = vec![0u8; 112];
    d[0..4].copy_from_slice(b"dex\n");
    assert!(DexHeader::parse(&d).is_ok());
}

#[test]
fn dex_header_version_str_non_ascii_safe() {
    let mut d = vec![0u8; 256];
    d[0..4].copy_from_slice(b"dex\n");
    d[4..8].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0x00]);
    let h = DexHeader::parse(&d).expect("parse");
    // Should not panic; version_str returns either real or "???".
    let _ = h.version_str();
    assert_eq!(h.version_int(), 0);
}

#[test]
fn dex_header_display_does_not_panic() {
    let data = build_dex_blob();
    let h = DexHeader::parse(&data).unwrap();
    let s = format!("{h}");
    assert!(s.contains("DEX"));
}

#[test]
fn dex_header_endian_other_value() {
    let mut data = build_dex_blob();
    data[40..44].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
    let h = DexHeader::parse(&data).unwrap();
    assert!(!h.is_little_endian());
}

// ── DexFile parse on synthetic blobs ────────────────────────────────────────
#[test]
fn dex_file_parse_empty_tables() {
    let data = build_dex_blob();
    let df = DexFile::parse(&data).unwrap();
    assert!(df.strings.is_empty());
    assert!(df.type_ids.is_empty());
    assert!(df.method_ids.is_empty());
    let _ = format!("{df}");
}

#[test]
fn dex_file_all_class_names_empty() {
    let data = build_dex_blob();
    let df = DexFile::parse(&data).unwrap();
    assert!(df.all_class_names().is_empty());
    assert!(df.all_method_names().is_empty());
}

// ── read_dex_string boundaries ─────────────────────────────────────────────
#[test]
fn read_dex_string_out_of_bounds() {
    assert_eq!(read_dex_string(&[], 0), "");
    assert_eq!(read_dex_string(&[1, 2, 3], 100), "");
}

#[test]
fn read_dex_string_uleb_truncated() {
    let data = [0x80, 0x80, 0x80, 0x80, 0x80];
    let s = read_dex_string(&data, 0);
    // Should not panic.
    let _ = s.len();
}

#[test]
fn read_dex_string_basic() {
    // ULEB128 = 5, then "hello\0"
    let data = [5u8, b'h', b'e', b'l', b'l', b'o', 0];
    let s = read_dex_string(&data, 0);
    assert_eq!(s, "hello");
}

// ── ULEB128 ────────────────────────────────────────────────────────────────
#[test]
fn read_uleb128_zero() {
    let data = [0u8];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 0);
    assert_eq!(p, 1);
}

#[test]
fn read_uleb128_multibyte() {
    // 0xE5 0x8E 0x26 = 624485
    let data = [0xE5, 0x8E, 0x26];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 624485);
    assert_eq!(p, 3);
}

#[test]
fn read_uleb128_overflow_guard() {
    let data = [0xFF; 10];
    let mut p = 0;
    let _ = read_uleb128(&data, &mut p);
    // Should not loop forever (shift cap).
    assert!(p <= 10);
}

#[test]
fn read_uleb128_at_eob() {
    let data = [];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 0);
}

// ── CodeItem ───────────────────────────────────────────────────────────────
#[test]
fn code_item_truncated() {
    assert!(CodeItem::parse(&[0; 15], 0).is_none());
}

#[test]
fn code_item_empty_insns() {
    let mut d = vec![0u8; 16];
    // insns_size = 0
    let ci = CodeItem::parse(&d, 0).unwrap();
    assert_eq!(ci.insns_size, 0);
    assert!(ci.insns.is_empty());
    assert!(ci.bytecode_bytes().is_empty());
    d[0] = 1; // mutation just to silence
}

#[test]
fn code_item_roundtrip_bytecode() {
    let mut d = vec![0u8; 16];
    d[12..16].copy_from_slice(&3u32.to_le_bytes()); // insns_size = 3 units
    d.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let ci = CodeItem::parse(&d, 0).unwrap();
    assert_eq!(ci.insns.len(), 3);
    let bytes = ci.bytecode_bytes();
    assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

#[test]
fn code_item_oversize_returns_none() {
    let mut d = vec![0u8; 16];
    d[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CodeItem::parse(&d, 0).is_none());
}

// ── ClassDefItem ───────────────────────────────────────────────────────────
#[test]
fn class_def_visibility_decoding() {
    let mk = |flags: u32| ClassDefItem {
        class_idx: 0,
        access_flags: flags,
        superclass_idx: 0,
        interfaces_off: 0,
        source_file_idx: 0,
        annotations_off: 0,
        class_data_off: 0,
        static_values_off: 0,
    };
    assert_eq!(mk(0x1).visibility(), DexVisibility::Public);
    assert_eq!(mk(0x2).visibility(), DexVisibility::Private);
    assert_eq!(mk(0x4).visibility(), DexVisibility::Protected);
    assert_eq!(mk(0).visibility(), DexVisibility::PackagePrivate);
    assert!(mk(0x0200).is_interface());
    assert!(mk(0x0400).is_abstract());
    assert!(mk(0x4000).is_enum());
    assert!(mk(0x2000).is_annotation());
}

#[test]
fn class_def_parse_truncated() {
    assert!(ClassDefItem::parse(&[0; 31], 0).is_none());
}

#[test]
fn dex_visibility_display() {
    assert_eq!(DexVisibility::Public.to_string(), "public");
    assert_eq!(DexVisibility::Private.to_string(), "private");
    assert_eq!(DexVisibility::Protected.to_string(), "protected");
    assert_eq!(DexVisibility::PackagePrivate.to_string(), "");
}

// ── ApkEntry helpers ──────────────────────────────────────────────────────
fn entry(name: &str) -> ApkEntry {
    ApkEntry {
        name: name.to_string(),
        compression: 0,
        compressed_size: 0,
        uncompressed_size: 0,
        local_header_offset: 0,
    }
}

#[test]
fn apk_entry_classification() {
    assert!(entry("classes.dex").is_dex());
    assert!(entry("classes2.DEX").is_dex());
    assert!(!entry("classes.dex.bak").is_dex());
    assert!(entry("AndroidManifest.xml").is_manifest());
    assert!(!entry("manifest.xml").is_manifest());
    assert!(entry("resources.arsc").is_resources());
    assert!(entry("lib/arm64-v8a/libfoo.so").is_native_lib());
    assert!(!entry("libfoo.so").is_native_lib());
}

#[test]
fn apk_entry_native_abi() {
    assert_eq!(
        entry("lib/arm64-v8a/libfoo.so").native_abi(),
        Some("arm64-v8a")
    );
    assert_eq!(entry("classes.dex").native_abi(), None);
}

// ── AndroidAbi ─────────────────────────────────────────────────────────────
#[test]
fn android_abi_roundtrip_via_display() {
    let abis = [
        AndroidAbi::Armeabi,
        AndroidAbi::ArmeabiV7a,
        AndroidAbi::Arm64V8a,
        AndroidAbi::X86,
        AndroidAbi::X86_64,
        AndroidAbi::Mips,
        AndroidAbi::Mips64,
    ];
    for a in abis {
        let s = a.to_string();
        let parsed = AndroidAbi::from_str(&s);
        assert_eq!(parsed, a, "abi {s} did not round-trip");
    }
    assert_eq!(AndroidAbi::from_str("nope"), AndroidAbi::Unknown);
    assert_eq!(AndroidAbi::Unknown.to_string(), "unknown");
}

#[test]
fn android_abi_pointer_bits() {
    assert_eq!(AndroidAbi::Arm64V8a.pointer_bits(), 64);
    assert_eq!(AndroidAbi::X86_64.pointer_bits(), 64);
    assert_eq!(AndroidAbi::Mips64.pointer_bits(), 64);
    assert_eq!(AndroidAbi::ArmeabiV7a.pointer_bits(), 32);
    assert_eq!(AndroidAbi::X86.pointer_bits(), 32);
    assert_eq!(AndroidAbi::Unknown.pointer_bits(), 32);
}

// ── parse_apk_entries / fuzz ──────────────────────────────────────────────
#[test]
fn parse_apk_entries_no_eocd() {
    assert!(matches!(
        parse_apk_entries(&[]),
        Err(AndroidLoaderError::InvalidZip)
    ));
    assert!(matches!(
        parse_apk_entries(&random_bytes(64)),
        Err(AndroidLoaderError::InvalidZip)
    ));
}

#[test]
fn parse_apk_entries_minimal_empty_eocd() {
    // 22-byte EOCD with zero entries.
    let mut data = vec![0u8; 22];
    data[0..4].copy_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    let r = parse_apk_entries(&data).unwrap();
    assert!(r.is_empty());
}

#[test]
fn parse_apk_entries_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 256) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = parse_apk_entries(&data);
    }
}

// ── detect_signing_schemes ────────────────────────────────────────────────
#[test]
fn detect_signing_schemes_empty() {
    assert!(detect_signing_schemes(&[]).is_empty());
    assert!(detect_signing_schemes(b"hello").is_empty());
}

#[test]
fn detect_signing_schemes_v1() {
    let mut data = b"some bytes META-INF blah .SF more".to_vec();
    data.extend(vec![0u8; 100]);
    let s = detect_signing_schemes(&data);
    assert!(s.contains(&ApkSigningScheme::V1Jar));
}

#[test]
fn detect_signing_schemes_v2() {
    let mut data = vec![0u8; 64];
    data.extend_from_slice(b"APK Sig Block 42");
    data.extend(vec![0u8; 64]);
    let s = detect_signing_schemes(&data);
    assert!(s.contains(&ApkSigningScheme::V2));
}

#[test]
fn detect_signing_schemes_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 512) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = detect_signing_schemes(&data);
    }
}

#[test]
fn apk_signing_scheme_display_distinct() {
    let schemes = [
        ApkSigningScheme::V1Jar,
        ApkSigningScheme::V2,
        ApkSigningScheme::V3,
        ApkSigningScheme::V4,
    ];
    let mut seen = std::collections::HashSet::new();
    for s in schemes {
        assert!(seen.insert(s.to_string()));
    }
}

// ── VdexHeader ─────────────────────────────────────────────────────────────
#[test]
fn vdex_header_truncated() {
    assert!(matches!(
        VdexHeader::parse(&[0; 27]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn vdex_header_invalid_magic() {
    assert!(matches!(
        VdexHeader::parse(&[0; 64]),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn vdex_header_valid() {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"vdex");
    d[4..8].copy_from_slice(b"019\0");
    d[8..12].copy_from_slice(&2u32.to_le_bytes());
    let h = VdexHeader::parse(&d).unwrap();
    assert_eq!(h.number_of_dex_files, 2);
    assert_eq!(h.version_str(), "019");
    assert_eq!(h.dex_start_offset(), 28 + 8);
    let _ = format!("{h}");
}

#[test]
fn vdex_header_extreme_number_of_dex_parses_or_errors() {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"vdex");
    d[4..8].copy_from_slice(b"019\0");
    d[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    // Either succeeds (parser stores number_of_dex_files as-is) or returns an
    // error; what matters is that it must not panic.
    let _ = VdexHeader::parse(&d);
}

#[test]
fn extract_vdex_dex_files_empty() {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"vdex");
    d[4..8].copy_from_slice(b"019\0");
    let files = extract_vdex_dex_files(&d).unwrap();
    assert!(files.is_empty());
}

#[test]
fn extract_vdex_dex_files_fuzz() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = 28 + (g() % 256) as usize;
        let mut d: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        d[0..4].copy_from_slice(b"vdex");
        d[4..8].copy_from_slice(b"019\0");
        // Set number_of_dex_files to a small value to satisfy the guard.
        d[8..12].copy_from_slice(&1u32.to_le_bytes());
        let _ = extract_vdex_dex_files(&d);
    }
}

// ── AndroidManifest ───────────────────────────────────────────────────────
#[test]
fn manifest_attack_surface_collects_all() {
    let mut m = AndroidManifest::default();
    m.exported_activities.push("A".to_string());
    m.exported_services.push("S".to_string());
    m.exported_receivers.push("R".to_string());
    m.exported_providers.push("P".to_string());
    let s = m.attack_surface();
    assert!(s.contains(&"activity:A".to_string()));
    assert!(s.contains(&"service:S".to_string()));
    assert!(s.contains(&"receiver:R".to_string()));
    assert!(s.contains(&"provider:P".to_string()));
    assert!(m.has_unprotected_exports());
}

#[test]
fn manifest_default_has_no_exports() {
    let m = AndroidManifest::default();
    assert!(!m.has_unprotected_exports());
    assert!(m.attack_surface().is_empty());
}

#[test]
fn parse_manifest_truncated() {
    assert!(matches!(
        parse_manifest(&[0; 7]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn parse_manifest_bad_magic() {
    assert!(matches!(
        parse_manifest(&[0xFF; 16]),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn parse_manifest_minimal_valid() {
    // file_type=0x0003, hdr_size=0x0008, total_size=8
    let data = [0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00];
    let m = parse_manifest(&data).unwrap();
    assert_eq!(m.package_name, "");
}

#[test]
fn parse_manifest_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 512) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = parse_manifest(&data);
    }
}

// ── ApkInfo ────────────────────────────────────────────────────────────────
#[test]
fn apk_info_mock_consistent() {
    let m = ApkInfo::mock();
    assert_eq!(m.package_name, "com.example.app");
    assert_eq!(
        m.entry_class.as_deref(),
        Some("com.example.app.MainActivity")
    );
}

#[test]
fn apk_info_from_data_detects_native_libs_and_dex() {
    let mut d = b"junk".to_vec();
    d.extend_from_slice(b"libfoo.so name classes.dex bytes");
    let i = ApkInfo::from_data(&d);
    assert!(i.has_native_libs);
    // Was `assert_eq!(i.package_name, "com.unknown.app")` before 2026-07-29,
    // which pinned an invented value. A byte scan sees `classes.dex` and can
    // conclude the input looks like an APK — it cannot read the manifest, so
    // the package name stays unknown.
    assert_eq!(
        i.package_name, "",
        "detecting classes.dex must not manufacture a package name"
    );
    let _ = format!("{i}");
}

#[test]
fn apk_info_from_data_empty() {
    let i = ApkInfo::from_data(&[]);
    assert!(!i.has_native_libs);
    assert_eq!(i.package_name, "");
}

#[test]
fn apk_info_parse_garbage_returns_err() {
    assert!(ApkInfo::parse(&[]).is_err());
}

// ── Hash/Eq consistency ────────────────────────────────────────────────────
#[test]
fn android_abi_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut g = lcg();
    let pool = [
        AndroidAbi::Armeabi,
        AndroidAbi::ArmeabiV7a,
        AndroidAbi::Arm64V8a,
        AndroidAbi::X86,
        AndroidAbi::X86_64,
        AndroidAbi::Mips,
        AndroidAbi::Mips64,
        AndroidAbi::Unknown,
    ];
    for _ in 0..40 {
        let a = pool[(g() as usize) % pool.len()];
        let b = pool[(g() as usize) % pool.len()];
        let mut s = HashSet::new();
        s.insert(a);
        if a == b {
            assert!(s.contains(&b));
        }
    }
}

#[test]
fn signing_scheme_eq() {
    assert_eq!(ApkSigningScheme::V2, ApkSigningScheme::V2);
    assert_ne!(ApkSigningScheme::V2, ApkSigningScheme::V3);
}

#[test]
fn dex_visibility_eq_pairs() {
    let pool = [
        DexVisibility::Public,
        DexVisibility::Private,
        DexVisibility::Protected,
        DexVisibility::PackagePrivate,
    ];
    for &a in &pool {
        for &b in &pool {
            assert_eq!(a == b, format!("{a:?}") == format!("{b:?}"));
        }
    }
}

// ── error display ─────────────────────────────────────────────────────────
#[test]
fn error_display_strings() {
    let e = AndroidLoaderError::InvalidMagic;
    assert!(format!("{e}").contains("invalid magic"));
    let e = AndroidLoaderError::TruncatedHeader;
    assert!(format!("{e}").contains("truncated"));
    let e = AndroidLoaderError::ChecksumMismatch {
        expected: 1,
        computed: 2,
    };
    assert!(format!("{e}").contains("checksum"));
    let e = AndroidLoaderError::IndexOutOfBounds {
        table: "t",
        index: 1,
        len: 0,
    };
    assert!(format!("{e}").contains("index out of bounds"));
    let e = AndroidLoaderError::MalformedAxmlChunk(0x100);
    assert!(format!("{e}").contains("AXML"));
    let e = AndroidLoaderError::ParseError("x".into());
    assert!(format!("{e}").contains("parse"));
    let e = AndroidLoaderError::InvalidZip;
    assert!(format!("{e}").contains("ZIP"));
}

// ── threaded Send/Sync stress ─────────────────────────────────────────────
#[test]
fn threaded_dex_header_parse_send_sync() {
    use std::sync::Arc;
    use std::thread;
    let data = Arc::new(build_dex_blob());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                for _ in 0..100 {
                    let _ = DexHeader::parse(&d).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_adler32_stable() {
    use std::sync::Arc;
    use std::thread;
    let data = Arc::new(vec![0xABu8; 4096]);
    let baseline = adler32(&data);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(adler32(&d), baseline);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ── Read table parsers gracefully handle bad offsets ──────────────────────
#[test]
fn read_string_table_bad_offset() {
    let data = build_dex_blob();
    let mut h = DexHeader::parse(&data).unwrap();
    h.string_ids_size = 5;
    h.string_ids_off = data.len() as u32 + 100;
    let v = read_string_table(&data, &h);
    // All should be empty strings since offsets are OOB.
    assert_eq!(v.len(), 5);
    for s in v {
        assert!(s.is_empty());
    }
}

#[test]
fn read_type_ids_oob_returns_empty_or_partial() {
    let data = build_dex_blob();
    let mut h = DexHeader::parse(&data).unwrap();
    h.type_ids_size = 10;
    h.type_ids_off = (data.len() - 3) as u32;
    let v = read_type_ids(&data, &h);
    assert!(v.len() <= 10);
}

#[test]
fn parse_encoded_methods_zero_off() {
    assert!(parse_encoded_methods(b"junk", 0).is_empty());
}

#[test]
fn parse_encoded_methods_oob() {
    assert!(parse_encoded_methods(b"x", 100).is_empty());
}

#[test]
fn parse_encoded_methods_minimal() {
    // off=0 is a sentinel meaning "no class data"; place real class_data_item at off=1.
    // sizes: 0 static, 0 inst, 1 direct, 0 virtual; then one method (diff=0, access=0, code_off=0)
    let data = [0xFFu8, 0, 0, 1, 0, 0, 0, 0];
    let methods = parse_encoded_methods(&data, 1);
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].method_idx, 0);
}
