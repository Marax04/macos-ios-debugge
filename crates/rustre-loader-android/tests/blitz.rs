//! Exhaustive integration tests for the public API of `rustre-loader-android`.
//!
//! Focuses on parsers and detectors in `lib.rs`: magic detection, Adler-32,
//! DEX header/tables, APK ZIP central directory, AXML manifest, VDEX header,
//! APK signing scheme detection, ABI decode, ULEB128.

use rustre_loader_android::*;
use std::collections::HashSet;

// ── Magic detection ────────────────────────────────────────────────────────

#[test]
fn is_apk_rejects_empty() {
    assert!(!is_apk(&[]));
}

#[test]
fn is_apk_rejects_pk_without_classes_dex() {
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(&[0u8; 64]);
    assert!(!is_apk(&data));
}

#[test]
fn is_apk_accepts_pk_with_classes_dex() {
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(b"classes.dex");
    data.extend_from_slice(&[0u8; 32]);
    assert!(is_apk(&data));
}

#[test]
fn is_apk_rejects_non_pk_prefix() {
    let mut data = b"AB\x03\x04".to_vec();
    data.extend_from_slice(b"classes.dex");
    assert!(!is_apk(&data));
}

#[test]
fn is_dex_rejects_short() {
    assert!(!is_dex(&[]));
    assert!(!is_dex(b"dex\n035"));
}

#[test]
fn is_dex_accepts_dex_035() {
    assert!(is_dex(b"dex\n035\0"));
}

#[test]
fn is_dex_rejects_bad_magic() {
    assert!(!is_dex(b"dxx\n035\0"));
}

#[test]
fn is_dex_requires_ascii_digit_at_4() {
    assert!(!is_dex(b"dex\nX35\0"));
}

#[test]
fn is_vdex_rejects_short() {
    assert!(!is_vdex(&[]));
    assert!(!is_vdex(b"vdex"));
}

#[test]
fn is_vdex_accepts_versioned() {
    assert!(is_vdex(b"vdex019\0"));
}

#[test]
fn is_vdex_rejects_wrong_magic() {
    assert!(!is_vdex(b"vdxx019\0"));
}

// ── Adler-32 ──────────────────────────────────────────────────────────────

#[test]
fn adler32_empty_is_one() {
    assert_eq!(adler32(&[]), 1);
}

#[test]
fn adler32_known_vector_wikipedia() {
    // Adler32("Wikipedia") = 0x11E60398
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
}

#[test]
fn adler32_single_byte() {
    // a=1+1=2, b=0+2=2, result = (2<<16)|2
    assert_eq!(adler32(&[1u8]), (2u32 << 16) | 2);
}

#[test]
fn verify_dex_checksum_truncated() {
    let err = verify_dex_checksum(&[0u8; 11]).unwrap_err();
    assert!(matches!(err, AndroidLoaderError::TruncatedHeader));
}

#[test]
fn verify_dex_checksum_roundtrip() {
    // Build minimal 16-byte buffer: 8 magic + 4 checksum + 4 payload
    let mut data = vec![0u8; 16];
    data[..8].copy_from_slice(b"dex\n035\0");
    data[12..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let expected = adler32(&data[12..]);
    data[8..12].copy_from_slice(&expected.to_le_bytes());
    verify_dex_checksum(&data).expect("checksum must verify");
}

#[test]
fn verify_dex_checksum_mismatch_reports_values() {
    let mut data = vec![0u8; 16];
    data[..8].copy_from_slice(b"dex\n035\0");
    data[8..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    data[12..16].copy_from_slice(&[1, 2, 3, 4]);
    let err = verify_dex_checksum(&data).unwrap_err();
    match err {
        AndroidLoaderError::ChecksumMismatch { expected, computed } => {
            assert_eq!(expected, 0xEFBE_ADDE);
            assert_eq!(computed, adler32(&data[12..]));
        }
        _ => panic!("expected ChecksumMismatch"),
    }
}

// ── DEX header ────────────────────────────────────────────────────────────

fn make_dex_header(version: &[u8; 3]) -> Vec<u8> {
    let mut data = vec![0u8; 112];
    data[..4].copy_from_slice(b"dex\n");
    data[4..7].copy_from_slice(version);
    data[7] = 0;
    // endian tag at offset 40
    data[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    // header_size at offset 36
    data[36..40].copy_from_slice(&112u32.to_le_bytes());
    // file_size at offset 32
    data[32..36].copy_from_slice(&112u32.to_le_bytes());
    data
}

#[test]
fn dex_header_truncated() {
    assert!(matches!(
        DexHeader::parse(&[0u8; 50]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn dex_header_bad_magic() {
    let mut data = vec![0u8; 112];
    data[..4].copy_from_slice(b"junk");
    assert!(matches!(
        DexHeader::parse(&data),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn dex_header_parses_version() {
    let data = make_dex_header(b"035");
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(hdr.is_valid());
    assert_eq!(hdr.version_str(), "035");
    assert_eq!(hdr.version_int(), 35);
    assert!(hdr.is_little_endian());
    assert_eq!(hdr.header_size, 112);
}

#[test]
fn dex_header_non_le_endian_tag() {
    let mut data = make_dex_header(b"035");
    data[40..44].copy_from_slice(&0x7856_3412u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(!hdr.is_little_endian());
}

#[test]
fn dex_header_display_contains_version() {
    let data = make_dex_header(b"039");
    let hdr = DexHeader::parse(&data).unwrap();
    let s = format!("{hdr}");
    assert!(s.contains("v039"));
    assert!(s.contains("file_size="));
}

#[test]
fn dex_header_version_int_invalid_string_yields_zero() {
    let mut data = make_dex_header(b"035");
    data[4..7].copy_from_slice(b"ABC");
    // Magic check still passes because only first 4 bytes "dex\n" matter.
    let hdr = DexHeader::parse(&data).unwrap();
    assert_eq!(hdr.version_int(), 0);
}

// ── DEX string / type / proto / field / method / class tables ─────────────

#[test]
fn read_string_table_empty() {
    let data = make_dex_header(b"035");
    let hdr = DexHeader::parse(&data).unwrap();
    let strings = read_string_table(&data, &hdr);
    assert!(strings.is_empty());
}

#[test]
fn read_string_table_handles_oob_offset() {
    // string_ids_size=1, string_ids_off pointing past end → should not panic
    let mut data = make_dex_header(b"035");
    data[56..60].copy_from_slice(&1u32.to_le_bytes());
    data[60..64].copy_from_slice(&9999u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    let strings = read_string_table(&data, &hdr);
    // Either pushes empty string or returns single empty; both safe.
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], "");
}

#[test]
fn read_dex_string_oob_returns_empty() {
    let data = [0u8; 4];
    assert_eq!(read_dex_string(&data, 999), "");
}

#[test]
fn read_dex_string_basic() {
    // ULEB128 length 5, then "hello\0"
    let mut data = vec![0u8; 16];
    data[0] = 5; // len
    data[1..6].copy_from_slice(b"hello");
    data[6] = 0;
    assert_eq!(read_dex_string(&data, 0), "hello");
}

#[test]
fn read_dex_string_multi_byte_uleb() {
    // length 200 → ULEB128: 0xC8 0x01 (200 = 0b11001000)
    let mut data = vec![0u8; 256];
    data[0] = 0xC8;
    data[1] = 0x01;
    for i in 0..5 {
        data[2 + i] = b'A' + i as u8;
    }
    data[7] = 0; // NUL terminator stops the string
    let s = read_dex_string(&data, 0);
    assert_eq!(s, "ABCDE");
}

#[test]
fn read_type_ids_oob_safe() {
    let mut data = make_dex_header(b"035");
    data[64..68].copy_from_slice(&5u32.to_le_bytes()); // type_ids_size
    data[68..72].copy_from_slice(&9999u32.to_le_bytes()); // off OOB
    let hdr = DexHeader::parse(&data).unwrap();
    let v = read_type_ids(&data, &hdr);
    assert_eq!(v.len(), 0);
}

#[test]
fn read_proto_ids_oob_safe() {
    let mut data = make_dex_header(b"035");
    data[72..76].copy_from_slice(&3u32.to_le_bytes());
    data[76..80].copy_from_slice(&9999u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(read_proto_ids(&data, &hdr).is_empty());
}

#[test]
fn read_field_ids_oob_safe() {
    let mut data = make_dex_header(b"035");
    data[80..84].copy_from_slice(&3u32.to_le_bytes());
    data[84..88].copy_from_slice(&9999u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(read_field_ids(&data, &hdr).is_empty());
}

#[test]
fn read_method_ids_oob_safe() {
    let mut data = make_dex_header(b"035");
    data[88..92].copy_from_slice(&3u32.to_le_bytes());
    data[92..96].copy_from_slice(&9999u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(read_method_ids(&data, &hdr).is_empty());
}

#[test]
fn read_class_defs_oob_safe() {
    let mut data = make_dex_header(b"035");
    data[96..100].copy_from_slice(&3u32.to_le_bytes());
    data[100..104].copy_from_slice(&9999u32.to_le_bytes());
    let hdr = DexHeader::parse(&data).unwrap();
    assert!(read_class_defs(&data, &hdr).is_empty());
}

#[test]
fn class_def_parse_truncated() {
    assert!(ClassDefItem::parse(&[0u8; 10], 0).is_none());
}

#[test]
fn class_def_access_flags() {
    let mut data = vec![0u8; 64];
    // access_flags at offset 4: ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT
    let flags: u32 = 0x1 | 0x0200 | 0x0400;
    data[4..8].copy_from_slice(&flags.to_le_bytes());
    let def = ClassDefItem::parse(&data, 0).unwrap();
    assert_eq!(def.visibility(), DexVisibility::Public);
    assert!(def.is_interface());
    assert!(def.is_abstract());
    assert!(!def.is_enum());
    assert!(!def.is_annotation());
}

#[test]
fn class_def_visibility_variants() {
    let mut data = vec![0u8; 32];
    for (flag, expect) in [
        (0x1u32, DexVisibility::Public),
        (0x2, DexVisibility::Private),
        (0x4, DexVisibility::Protected),
        (0x0, DexVisibility::PackagePrivate),
    ] {
        data[4..8].copy_from_slice(&flag.to_le_bytes());
        let def = ClassDefItem::parse(&data, 0).unwrap();
        assert_eq!(def.visibility(), expect);
    }
}

#[test]
fn class_def_no_index_constant() {
    assert_eq!(ClassDefItem::NO_INDEX, 0xFFFF_FFFF);
}

#[test]
fn dex_visibility_display() {
    assert_eq!(format!("{}", DexVisibility::Public), "public");
    assert_eq!(format!("{}", DexVisibility::Private), "private");
    assert_eq!(format!("{}", DexVisibility::Protected), "protected");
    assert_eq!(format!("{}", DexVisibility::PackagePrivate), "");
}

// ── ULEB128 ───────────────────────────────────────────────────────────────

#[test]
fn uleb128_single_byte() {
    let data = [0x05u8];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 5);
    assert_eq!(p, 1);
}

#[test]
fn uleb128_multi_byte() {
    // 0xE5 0x8E 0x26 = 624485
    let data = [0xE5, 0x8E, 0x26];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 624_485);
    assert_eq!(p, 3);
}

#[test]
fn uleb128_oob_breaks() {
    let data: [u8; 0] = [];
    let mut p = 0;
    assert_eq!(read_uleb128(&data, &mut p), 0);
}

// ── CodeItem ──────────────────────────────────────────────────────────────

#[test]
fn code_item_parse_truncated() {
    assert!(CodeItem::parse(&[0u8; 10], 0).is_none());
}

#[test]
fn code_item_roundtrip_bytecode() {
    let mut data = vec![0u8; 24];
    data[0..2].copy_from_slice(&3u16.to_le_bytes()); // registers
    data[2..4].copy_from_slice(&1u16.to_le_bytes()); // ins
    data[4..6].copy_from_slice(&2u16.to_le_bytes()); // outs
    data[6..8].copy_from_slice(&0u16.to_le_bytes()); // tries
    data[8..12].copy_from_slice(&0u32.to_le_bytes()); // debug_info
    data[12..16].copy_from_slice(&4u32.to_le_bytes()); // insns_size = 4 units = 8 bytes
    data[16..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x00]);
    let code = CodeItem::parse(&data, 0).unwrap();
    assert_eq!(code.registers_size, 3);
    assert_eq!(code.insns.len(), 4);
    assert_eq!(code.insns[0], 0x3412);
    let raw = code.bytecode_bytes();
    assert_eq!(raw, &[0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x00]);
}

#[test]
fn code_item_insns_overflow_returns_none() {
    let mut data = vec![0u8; 18];
    data[12..16].copy_from_slice(&100u32.to_le_bytes());
    assert!(CodeItem::parse(&data, 0).is_none());
}

#[test]
fn parse_encoded_methods_zero_offset_returns_empty() {
    let data = vec![0u8; 16];
    assert!(parse_encoded_methods(&data, 0).is_empty());
}

#[test]
fn parse_encoded_methods_oob_returns_empty() {
    let data = vec![0u8; 4];
    assert!(parse_encoded_methods(&data, 99).is_empty());
}

#[test]
fn parse_encoded_methods_two_direct() {
    // class_data_item must live at a non-zero offset (offset 0 is treated as "none").
    let mut data: Vec<u8> = vec![0xFFu8; 4]; // padding so class_data_off != 0
    data.extend_from_slice(&[
        0, 0, 2, 0, // sizes: 0 static, 0 instance, 2 direct, 0 virtual
        5, 1, 0, // m1: diff=5, access=1, code=0
        3, 2, 0, // m2: diff=3, access=2, code=0
    ]);
    let methods = parse_encoded_methods(&data, 4);
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0].method_idx, 5);
    assert_eq!(methods[1].method_idx, 8);
    assert_eq!(methods[1].access_flags, 2);
}

// ── ApkEntry classifiers ──────────────────────────────────────────────────

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
fn apk_entry_is_dex_case_insensitive() {
    assert!(entry("classes.dex").is_dex());
    assert!(entry("classes2.DEX").is_dex());
    assert!(!entry("classes.dey").is_dex());
}

#[test]
fn apk_entry_is_manifest() {
    assert!(entry("AndroidManifest.xml").is_manifest());
    assert!(!entry("androidmanifest.xml").is_manifest());
}

#[test]
fn apk_entry_is_resources() {
    assert!(entry("resources.arsc").is_resources());
    assert!(!entry("Resources.arsc").is_resources());
}

#[test]
fn apk_entry_native_lib_and_abi() {
    let e = entry("lib/arm64-v8a/libfoo.so");
    assert!(e.is_native_lib());
    assert_eq!(e.native_abi(), Some("arm64-v8a"));
    let e2 = entry("classes.dex");
    assert!(!e2.is_native_lib());
    assert_eq!(e2.native_abi(), None);
}

#[test]
fn apk_entry_native_lib_uppercase_so() {
    assert!(entry("lib/x86/foo.SO").is_native_lib());
}

// ── ZIP / APK parsing ─────────────────────────────────────────────────────

#[test]
fn parse_apk_entries_no_eocd() {
    let err = parse_apk_entries(&[0u8; 100]).unwrap_err();
    assert!(matches!(err, AndroidLoaderError::InvalidZip));
}

#[test]
fn parse_apk_entries_minimal_empty_zip() {
    // EOCD only, zero entries
    let mut data = Vec::new();
    data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    data.extend_from_slice(&[0u8; 18]); // disk fields zero
    let entries = parse_apk_entries(&data).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn parse_apk_entries_one_entry() {
    // Build minimal ZIP: local header + central dir + EOCD
    let name = b"hello.txt";
    let mut data = Vec::new();
    let lh_off = data.len() as u32;
    // local file header
    data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    data.extend_from_slice(&[0u8; 22]); // through compressed/uncompressed sizes
    data.extend_from_slice(&(name.len() as u16).to_le_bytes()); // fname_len
    data.extend_from_slice(&0u16.to_le_bytes()); // extra_len
    data.extend_from_slice(name);
    // (no file body)

    let cd_off = data.len() as u32;
    // central directory header
    data.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
    data.extend_from_slice(&[0u8; 6]); // version made by, version needed, flags
    data.extend_from_slice(&0u16.to_le_bytes()); // compression
    data.extend_from_slice(&[0u8; 8]); // time/date/crc
    data.extend_from_slice(&0u32.to_le_bytes()); // compressed_size
    data.extend_from_slice(&0u32.to_le_bytes()); // uncompressed_size
    data.extend_from_slice(&(name.len() as u16).to_le_bytes()); // fname
    data.extend_from_slice(&0u16.to_le_bytes()); // extra
    data.extend_from_slice(&0u16.to_le_bytes()); // comment
    data.extend_from_slice(&[0u8; 8]); // disk/internal/external attrs
    data.extend_from_slice(&lh_off.to_le_bytes());
    data.extend_from_slice(name);

    // EOCD
    data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    data.extend_from_slice(&[0u8; 4]); // disk
    data.extend_from_slice(&1u16.to_le_bytes()); // cd total this disk
    data.extend_from_slice(&1u16.to_le_bytes()); // cd total
    data.extend_from_slice(&0u32.to_le_bytes()); // cd size
    data.extend_from_slice(&cd_off.to_le_bytes()); // cd offset
    data.extend_from_slice(&0u16.to_le_bytes()); // comment length

    let entries = parse_apk_entries(&data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].local_header_offset, lh_off);

    // extract_entry_data should yield the (empty) payload slice
    let payload = extract_entry_data(&data, &entries[0]).unwrap();
    assert_eq!(payload.len(), 0);
}

#[test]
fn extract_entry_data_corrupt_local_header() {
    let bogus = vec![0u8; 64];
    let e = ApkEntry {
        name: "x".into(),
        compression: 0,
        compressed_size: 0,
        uncompressed_size: 0,
        local_header_offset: 0,
    };
    assert!(matches!(
        extract_entry_data(&bogus, &e),
        Err(AndroidLoaderError::InvalidZip)
    ));
}

#[test]
fn extract_entry_data_oob_offset() {
    let data = vec![0u8; 8];
    let e = ApkEntry {
        name: "x".into(),
        compression: 0,
        compressed_size: 0,
        uncompressed_size: 0,
        local_header_offset: 100,
    };
    assert!(matches!(
        extract_entry_data(&data, &e),
        Err(AndroidLoaderError::InvalidZip)
    ));
}

// ── ABI ───────────────────────────────────────────────────────────────────

#[test]
fn android_abi_from_str_all_known() {
    assert_eq!(AndroidAbi::from_str("armeabi"), AndroidAbi::Armeabi);
    assert_eq!(AndroidAbi::from_str("armeabi-v7a"), AndroidAbi::ArmeabiV7a);
    assert_eq!(AndroidAbi::from_str("arm64-v8a"), AndroidAbi::Arm64V8a);
    assert_eq!(AndroidAbi::from_str("x86"), AndroidAbi::X86);
    assert_eq!(AndroidAbi::from_str("x86_64"), AndroidAbi::X86_64);
    assert_eq!(AndroidAbi::from_str("mips"), AndroidAbi::Mips);
    assert_eq!(AndroidAbi::from_str("mips64"), AndroidAbi::Mips64);
    assert_eq!(AndroidAbi::from_str("weird"), AndroidAbi::Unknown);
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

#[test]
fn android_abi_display_roundtrip() {
    for s in ["armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64", "mips", "mips64"] {
        let abi = AndroidAbi::from_str(s);
        assert_eq!(format!("{abi}"), s);
    }
    assert_eq!(format!("{}", AndroidAbi::Unknown), "unknown");
}

#[test]
fn android_abi_hash_eq() {
    let mut set = HashSet::new();
    set.insert(AndroidAbi::Arm64V8a);
    set.insert(AndroidAbi::Arm64V8a);
    assert_eq!(set.len(), 1);
}

// ── APK signing scheme detection ──────────────────────────────────────────

#[test]
fn detect_signing_schemes_none() {
    let data = vec![0u8; 64];
    assert!(detect_signing_schemes(&data).is_empty());
}

#[test]
fn detect_signing_schemes_v1_jar() {
    let mut data = Vec::new();
    data.extend_from_slice(b"...META-INF/CERT.SF...");
    let s = detect_signing_schemes(&data);
    assert!(s.contains(&ApkSigningScheme::V1Jar));
}

#[test]
fn detect_signing_schemes_v2_magic() {
    // need 8 bytes (block size) BEFORE the magic
    let mut data = vec![0u8; 16];
    data.extend_from_slice(b"APK Sig Block 42");
    let s = detect_signing_schemes(&data);
    assert!(s.contains(&ApkSigningScheme::V2));
}

#[test]
fn signing_scheme_display() {
    assert_eq!(format!("{}", ApkSigningScheme::V1Jar), "v1-jar");
    assert_eq!(format!("{}", ApkSigningScheme::V2), "v2");
    assert_eq!(format!("{}", ApkSigningScheme::V3), "v3");
    assert_eq!(format!("{}", ApkSigningScheme::V4), "v4");
}

// ── VDEX ──────────────────────────────────────────────────────────────────

#[test]
fn vdex_header_truncated() {
    assert!(matches!(
        VdexHeader::parse(&[0u8; 20]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn vdex_header_bad_magic() {
    let data = vec![0u8; 64];
    assert!(matches!(
        VdexHeader::parse(&data),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn vdex_header_basic() {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"vdex");
    data[4..8].copy_from_slice(b"019\0");
    data[8..12].copy_from_slice(&2u32.to_le_bytes()); // number_of_dex_files
    data[12..16].copy_from_slice(&100u32.to_le_bytes()); // dex_section_size
    let hdr = VdexHeader::parse(&data).unwrap();
    assert_eq!(hdr.number_of_dex_files, 2);
    assert_eq!(hdr.dex_section_size, 100);
    assert_eq!(hdr.version_str(), "019");
    assert_eq!(hdr.dex_start_offset(), 28 + 2 * 4);
    let disp = format!("{hdr}");
    assert!(disp.contains("VDEX"));
}

#[test]
fn vdex_header_rejects_oversized_dex_count() {
    // Craft number_of_dex_files so big it doesn't fit
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"vdex");
    data[4..8].copy_from_slice(b"019\0");
    data[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let err = VdexHeader::parse(&data).unwrap_err();
    assert!(matches!(err, AndroidLoaderError::TruncatedHeader));
}

#[test]
fn extract_vdex_dex_files_returns_empty_when_no_embedded() {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"vdex");
    data[4..8].copy_from_slice(b"019\0");
    data[8..12].copy_from_slice(&0u32.to_le_bytes());
    let v = extract_vdex_dex_files(&data).unwrap();
    assert!(v.is_empty());
}

// ── AndroidManifest helpers ───────────────────────────────────────────────

#[test]
fn manifest_attack_surface_collects_all() {
    let m = AndroidManifest {
        exported_activities: vec!["A".into()],
        exported_services: vec!["S".into()],
        exported_receivers: vec!["R".into()],
        exported_providers: vec!["P".into()],
        ..AndroidManifest::default()
    };
    let s = m.attack_surface();
    assert!(s.contains(&"activity:A".to_string()));
    assert!(s.contains(&"service:S".to_string()));
    assert!(s.contains(&"receiver:R".to_string()));
    assert!(s.contains(&"provider:P".to_string()));
    assert_eq!(s.len(), 4);
}

#[test]
fn manifest_has_unprotected_exports() {
    let mut m = AndroidManifest::default();
    assert!(!m.has_unprotected_exports());
    m.exported_activities.push("X".into());
    assert!(m.has_unprotected_exports());
}

#[test]
fn parse_manifest_truncated() {
    assert!(matches!(
        parse_manifest(&[0u8; 4]),
        Err(AndroidLoaderError::TruncatedHeader)
    ));
}

#[test]
fn parse_manifest_bad_magic() {
    let data = vec![0u8; 32];
    assert!(matches!(
        parse_manifest(&data),
        Err(AndroidLoaderError::InvalidMagic)
    ));
}

#[test]
fn parse_manifest_minimal_valid_header() {
    // file_type = 0x0003, hdr_size = 0x0008, total_size = 8
    let mut data = vec![0u8; 8];
    data[0..2].copy_from_slice(&0x0003u16.to_le_bytes());
    data[2..4].copy_from_slice(&0x0008u16.to_le_bytes());
    data[4..8].copy_from_slice(&8u32.to_le_bytes());
    let m = parse_manifest(&data).unwrap();
    assert_eq!(m.package_name, "");
    assert!(m.permissions.is_empty());
}

// ── ApkInfo ───────────────────────────────────────────────────────────────

#[test]
fn apk_info_mock_is_consistent() {
    let info = ApkInfo::mock();
    assert_eq!(info.package_name, "com.example.app");
    assert!(!info.has_native_libs);
    assert!(info.entry_class.is_some());
}

#[test]
fn apk_info_from_data_detects_native_libs() {
    let data = b"random.so bytes here".to_vec();
    let info = ApkInfo::from_data(&data);
    assert!(info.has_native_libs);
    assert_eq!(info.package_name, "");
}

/// Seeing `classes.dex` in the raw bytes must NOT produce a package name.
///
/// Until 2026-07-29 this asserted `package_name == "com.unknown.app"` — it was
/// pinning a fabrication in place, so making the loader honest would have read
/// as a regression. `from_data` is a byte scan that never opens the manifest,
/// so the only truthful answer is the empty string, which is what the sibling
/// test `apk_info_from_data_detects_native_libs` already expected. The two
/// tests contradicted each other, exactly as the two code branches did.
#[test]
fn apk_info_from_data_does_not_invent_a_package_name() {
    let data = b"......classes.dex......".to_vec();
    let info = ApkInfo::from_data(&data);
    assert_eq!(
        info.package_name, "",
        "a byte scan cannot know the package name and must not invent one"
    );
}

#[test]
fn apk_info_display() {
    let info = ApkInfo::mock();
    let s = format!("{info}");
    assert!(s.contains("com.example.app"));
    assert!(s.contains("dex_count=0"));
}

// ── Error type ────────────────────────────────────────────────────────────

#[test]
fn error_display_strings() {
    let e = AndroidLoaderError::InvalidMagic;
    assert_eq!(format!("{e}"), "invalid magic");
    let e = AndroidLoaderError::ChecksumMismatch { expected: 1, computed: 2 };
    let s = format!("{e}");
    assert!(s.contains("checksum mismatch"));
    let e = AndroidLoaderError::IndexOutOfBounds { table: "t", index: 9, len: 1 };
    let s = format!("{e}");
    assert!(s.contains("table=t"));
}

// ── DexFile end-to-end on a hand-rolled DEX ───────────────────────────────

#[test]
fn dex_file_parse_minimal_empty_tables() {
    let data = make_dex_header(b"035");
    let dex = DexFile::parse(&data).unwrap();
    assert!(dex.strings.is_empty());
    assert!(dex.class_defs.is_empty());
    assert!(dex.all_class_names().is_empty());
    assert!(dex.all_method_names().is_empty());
    assert_eq!(dex.type_descriptor(0), None);
    let s = format!("{dex}");
    assert!(s.contains("DexFile"));
}

#[test]
fn dex_file_class_name_descriptor_conversion() {
    // Build header with 1 string ("Lcom/example/Foo;"), 1 type, 1 class_def.
    // Layout (offsets within file):
    //   0..112    : header
    //   112..116  : string_id (off pointing to 116)
    //   116..     : ULEB128 length + bytes + NUL
    // ...we'll lay it out and patch header offsets.
    let mut data = vec![0u8; 256];
    data[..4].copy_from_slice(b"dex\n");
    data[4..7].copy_from_slice(b"035");
    data[36..40].copy_from_slice(&112u32.to_le_bytes());
    data[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());

    // string_ids: size=1, off=112
    data[56..60].copy_from_slice(&1u32.to_le_bytes());
    data[60..64].copy_from_slice(&112u32.to_le_bytes());
    // string_id_item at 112 → points to string_data at 120
    data[112..116].copy_from_slice(&120u32.to_le_bytes());
    // string_data at 120: ULEB128 len=17, then "Lcom/example/Foo;\0"
    let s = b"Lcom/example/Foo;";
    data[120] = s.len() as u8;
    data[121..121 + s.len()].copy_from_slice(s);
    data[121 + s.len()] = 0;

    // type_ids: size=1, off=160
    data[64..68].copy_from_slice(&1u32.to_le_bytes());
    data[68..72].copy_from_slice(&160u32.to_le_bytes());
    data[160..164].copy_from_slice(&0u32.to_le_bytes()); // points to string idx 0

    // class_defs: size=1, off=170
    data[96..100].copy_from_slice(&1u32.to_le_bytes());
    data[100..104].copy_from_slice(&170u32.to_le_bytes());
    // class_def_item at 170: class_idx=0, all else zero (32 bytes)
    data[170..174].copy_from_slice(&0u32.to_le_bytes());

    let dex = DexFile::parse(&data).unwrap();
    assert_eq!(dex.strings.len(), 1);
    assert_eq!(dex.strings[0], "Lcom/example/Foo;");
    assert_eq!(dex.type_descriptor(0), Some("Lcom/example/Foo;"));
    let names = dex.all_class_names();
    assert_eq!(names, vec!["com.example.Foo".to_string()]);
}
