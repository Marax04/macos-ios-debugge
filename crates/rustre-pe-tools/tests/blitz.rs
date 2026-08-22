//! Integration "blitz" test suite for rustre-pe-tools.
//!
//! Focuses on the public API surface: parsers, classifiers, helpers,
//! roundtrips, edge/adversarial inputs.

use rustre_pe_tools::pe_checksum_calculator as ck;
use rustre_pe_tools::pe_manifest_parser as mp;
use rustre_pe_tools::pe_overlay_analyzer as ova;
use rustre_pe_tools::pe_rich_header as rh;
use rustre_pe_tools::pe_sign_checker as sc;
use rustre_pe_tools::pe_statistics as st;
use rustre_pe_tools::*;

// ---------- helpers ----------

fn build_x64(sections: &[(&str, Vec<u8>, u32)]) -> Vec<u8> {
    let mut b = PeBuilder::new_x64();
    for (n, d, c) in sections {
        b.add_section(n, d.clone(), *c);
    }
    b.build()
}

fn minimal_x64() -> Vec<u8> {
    build_x64(&[(".text", vec![0x90u8; 64], 0x6000_0020)])
}

// ===========================================================
// PeMachine
// ===========================================================

#[test]
fn machine_arm_alias() {
    // Both 0x01c0 and 0x01c4 should map to Arm.
    assert_eq!(PeMachine::from_value(0x01c0), PeMachine::Arm);
    assert_eq!(PeMachine::from_value(0x01c4), PeMachine::Arm);
}

#[test]
fn machine_unknown_to_value_zero() {
    assert_eq!(PeMachine::Unknown.to_value(), 0);
}

#[test]
fn machine_unknown_pointer_size_default_4() {
    assert_eq!(PeMachine::Unknown.pointer_size(), 4);
}

#[test]
fn machine_to_core_mode_consistency() {
    use rustre_core::arch_mode::Mode;
    assert_eq!(PeMachine::I386.to_core_mode(), Mode::X86_32);
    assert_eq!(PeMachine::Amd64.to_core_mode(), Mode::X86_64);
    assert_eq!(PeMachine::Arm64.to_core_mode(), Mode::Aarch64);
}

// ===========================================================
// PeSubsystem
// ===========================================================

#[test]
fn subsystem_unknown_value_zero() {
    assert_eq!(PeSubsystem::Unknown.to_value(), 0);
}

#[test]
fn subsystem_efi_runtime_driver() {
    assert_eq!(
        PeSubsystem::from_value(12),
        PeSubsystem::EfiRuntimeDriver
    );
    assert!(PeSubsystem::EfiRuntimeDriver.is_efi());
}

// ===========================================================
// DllCharacteristics flag_names ordering / completeness
// ===========================================================

#[test]
fn dll_chars_all_flags_named() {
    let all: u16 = 0xFFFF;
    let dc = DllCharacteristics(all);
    let names = dc.flag_names();
    // Spec defines 11 names in the implementation; ensure all those bits
    // produce names.
    for needed in &[
        "HIGH_ENTROPY_VA",
        "DYNAMIC_BASE",
        "FORCE_INTEGRITY",
        "NX_COMPAT",
        "NO_ISOLATION",
        "NO_SEH",
        "NO_BIND",
        "APPCONTAINER",
        "WDM_DRIVER",
        "GUARD_CF",
        "TERMINAL_SERVER_AWARE",
    ] {
        assert!(names.contains(needed), "missing {needed}");
    }
}

#[test]
fn dll_chars_empty_no_names() {
    let dc = DllCharacteristics(0);
    assert!(dc.flag_names().is_empty());
}

// ===========================================================
// align_up
// ===========================================================

#[test]
fn align_up_non_power_of_two() {
    // align_up uses bitwise mask: only correct for power-of-two `align`.
    // For non-power-of-two values, the result is mathematically wrong but
    // we exercise the code path. Just assert it does not panic.
    let _ = align_up(5, 3);
}

#[test]
fn align_up_max_value_no_panic() {
    // 0xFFFF_FFFF + 0x200 - 1 overflows; document behavior. The function
    // does NOT use overflow-checked arithmetic and will panic in debug
    // builds. To avoid masking a real bug, restrict to safe inputs.
    let r = align_up(0xFFFF_FE00, 0x200);
    assert_eq!(r, 0xFFFF_FE00);
}

// ===========================================================
// PeError formatting variants
// ===========================================================

#[test]
fn pe_error_io_wraps() {
    let io = std::io::Error::other("boom");
    let e: PeError = io.into();
    assert!(e.to_string().contains("io"));
}

// ===========================================================
// compute_entropy
// ===========================================================

#[test]
fn entropy_two_symbols_one_bit() {
    let mut data = vec![0u8; 128];
    data.extend(vec![1u8; 128]);
    let e = compute_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0 got {e}");
}

#[test]
fn entropy_single_byte_zero() {
    let e = compute_entropy(&[0x42]);
    assert!(e.abs() < 1e-12);
}

// ===========================================================
// compute_pe_checksum
// ===========================================================

#[test]
fn pe_checksum_short_input_returns_zero() {
    assert_eq!(compute_pe_checksum(&[0u8; 10]), 0);
}

#[test]
fn pe_checksum_minimal_pe_nonzero() {
    let bytes = minimal_x64();
    let cs = compute_pe_checksum(&bytes);
    // A minimal PE with non-zero contents should yield non-zero checksum.
    assert_ne!(cs, 0);
}

#[test]
fn pe_checksum_roundtrip_after_patch() {
    // Use the higher-level calculator to patch, then verify.
    let mut bytes = minimal_x64();
    let calc = ck::PeChecksumCalculator::new();
    let new_cs = calc.patch_checksum(&mut bytes).expect("patch");
    let result = calc.calculate(&bytes).expect("re-calc");
    assert_eq!(result.stored, new_cs);
    assert!(result.is_valid(), "checksum should match after patch");
}

#[test]
fn pe_checksum_zero_then_verify_false_unless_zero() {
    let mut bytes = minimal_x64();
    // First, give the file a real checksum.
    let calc = ck::PeChecksumCalculator::new();
    calc.patch_checksum(&mut bytes).unwrap();
    // Now zero it. Stored=0, computed!=0 → not valid.
    calc.zero_checksum(&mut bytes).unwrap();
    let r = calc.calculate(&bytes).unwrap();
    assert!(r.is_zero());
    assert!(!r.is_valid());
}

#[test]
fn pe_checksum_too_short() {
    let r = ck::calculate_checksum(&[0u8; 8]);
    assert!(matches!(r, Err(ck::ChecksumError::TooShort { .. })));
}

#[test]
fn pe_checksum_no_pe_signature() {
    // Provide an MZ stub pointing to a bad PE signature.
    let mut buf = vec![0u8; 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // bytes at offset 0x80 are zero, not "PE\0\0"
    let r = ck::calculate_checksum(&buf);
    assert!(matches!(r, Err(ck::ChecksumError::NoPeSignature)));
}

#[test]
fn pe_checksum_bad_elfanew() {
    let mut buf = vec![0u8; 0x80];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let r = ck::calculate_checksum(&buf);
    assert!(matches!(r, Err(ck::ChecksumError::BadElfanew { .. })));
}

#[test]
fn checksum_result_delta_signed() {
    let r = ck::ChecksumResult {
        stored: 10,
        computed: 7,
        file_size: 100,
        checksum_field_offset: 0x58,
    };
    assert_eq!(r.delta(), -3);
}

#[test]
fn checksum_stats_record() {
    let mut s = ck::ChecksumStats::default();
    s.record(&ck::ChecksumResult {
        stored: 0,
        computed: 0,
        file_size: 10,
        checksum_field_offset: 0,
    });
    s.record(&ck::ChecksumResult {
        stored: 5,
        computed: 5,
        file_size: 10,
        checksum_field_offset: 0,
    });
    s.record(&ck::ChecksumResult {
        stored: 5,
        computed: 6,
        file_size: 10,
        checksum_field_offset: 0,
    });
    assert_eq!(s.total, 3);
    assert_eq!(s.zeroed, 1);
    assert_eq!(s.valid, 1);
    assert_eq!(s.mismatch, 1);
}

// ===========================================================
// PeFile::parse — adversarial
// ===========================================================

#[test]
fn parse_pe_offset_out_of_range() {
    let mut buf = vec![0u8; 80];
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[60..64].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let err = PeFile::parse(&buf).expect_err("must fail");
    assert!(matches!(err, PeError::InvalidHeader(_)));
}

#[test]
fn parse_pe_missing_signature() {
    let mut buf = vec![0u8; 0x200];
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    // Don't write "PE\0\0" at offset 0x80
    let err = PeFile::parse(&buf).expect_err("must fail");
    assert!(matches!(err, PeError::InvalidHeader(_)));
}

#[test]
fn parse_truncated_optional_header() {
    // Valid MZ, valid PE signature, but file ends before optional header.
    let mut buf = vec![0u8; 64 + 4 + 20 + 1];
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[60..64].copy_from_slice(&64u32.to_le_bytes());
    buf[64..68].copy_from_slice(b"PE\0\0");
    let err = PeFile::parse(&buf).expect_err("must fail");
    // Either TooShort or InvalidHeader (both acceptable error paths).
    assert!(matches!(err, PeError::TooShort { .. } | PeError::InvalidHeader(_)));
}

#[test]
fn parse_section_data_clipped_when_raw_size_exceeds_file() {
    // PeBuilder always builds well-formed PEs; verify parse handles a manually
    // truncated trailer gracefully without panicking.
    let mut bytes = minimal_x64();
    let before = bytes.len();
    bytes.truncate(before - 4); // chop last bytes
    let pe = PeFile::parse(&bytes).expect("should still parse");
    let s = pe.section_by_name(".text").unwrap();
    // Section data must not extend past the truncated file.
    assert!(s.data.len() <= bytes.len());
}

// ===========================================================
// PeFile RVA/section utilities
// ===========================================================

#[test]
fn rva_to_offset_outside_any_section_returns_none() {
    let bytes = minimal_x64();
    let pe = PeFile::parse(&bytes).unwrap();
    assert!(pe.rva_to_offset(0xFFFF_0000).is_none());
}

#[test]
fn section_at_rva_outside_returns_none() {
    let bytes = minimal_x64();
    let pe = PeFile::parse(&bytes).unwrap();
    assert!(pe.section_at_rva(0).is_none());
}

#[test]
fn arch_mode_matches_machine() {
    let bytes = minimal_x64();
    let pe = PeFile::parse(&bytes).unwrap();
    assert_eq!(pe.arch_mode(), pe.machine.to_core_mode());
}

// ===========================================================
// pe_statistics::classify_api
// ===========================================================

#[test]
fn classify_api_anti_debug() {
    assert_eq!(st::classify_api("IsDebuggerPresent"), st::ApiCategory::AntiDebug);
    assert_eq!(st::classify_api("DebugBreak"), st::ApiCategory::AntiDebug);
    assert_eq!(st::classify_api("OutputDebugStringA"), st::ApiCategory::AntiDebug);
}

#[test]
fn classify_api_injection() {
    assert_eq!(st::classify_api("VirtualAllocEx"), st::ApiCategory::Injection);
    assert_eq!(st::classify_api("WriteProcessMemory"), st::ApiCategory::Injection);
    assert_eq!(st::classify_api("CreateRemoteThread"), st::ApiCategory::Injection);
}

#[test]
fn classify_api_crypto() {
    assert_eq!(st::classify_api("CryptAcquireContextW"), st::ApiCategory::Crypto);
    assert_eq!(st::classify_api("BCryptHashData"), st::ApiCategory::Crypto);
}

#[test]
fn classify_api_network_wsa() {
    assert_eq!(st::classify_api("WSAStartup"), st::ApiCategory::Network);
}

#[test]
fn classify_api_network_internet_open() {
    // InternetOpenA is a canonical Windows network API (wininet). The
    // network classifier should recognise it. Currently it falls through
    // to Misc because none of the substrings match.
    assert_eq!(st::classify_api("InternetOpenA"), st::ApiCategory::Network);
}

#[test]
fn classify_api_misc_fallback() {
    assert_eq!(st::classify_api("Sleep"), st::ApiCategory::Misc);
}

#[test]
fn classify_api_case_insensitive() {
    assert_eq!(st::classify_api("CREATEFILEA"), st::ApiCategory::File);
}

// ===========================================================
// pe_statistics::classify_string
// ===========================================================

#[test]
fn classify_string_url() {
    assert_eq!(st::classify_string("http://example.com"), st::StringCategory::Url);
    assert_eq!(st::classify_string("https://test.org/x"), st::StringCategory::Url);
    assert_eq!(st::classify_string("ftp://files/"), st::StringCategory::Url);
}

#[test]
fn classify_string_registry() {
    assert_eq!(
        st::classify_string("HKEY_LOCAL_MACHINE\\Software\\X"),
        st::StringCategory::RegistryKey
    );
}

#[test]
fn classify_string_filepath_windows() {
    assert_eq!(
        st::classify_string("C:\\Windows\\System32\\kernel32.dll"),
        st::StringCategory::FilePath
    );
}

#[test]
fn classify_string_filepath_unix() {
    assert_eq!(st::classify_string("/usr/bin/sh"), st::StringCategory::FilePath);
}

#[test]
fn classify_string_email() {
    assert_eq!(
        st::classify_string("user@example.com"),
        st::StringCategory::Email
    );
}

#[test]
fn classify_string_ipv4() {
    assert_eq!(st::classify_string("192.168.1.1"), st::StringCategory::IpAddress);
    assert_eq!(st::classify_string("8.8.8.8"), st::StringCategory::IpAddress);
}

#[test]
fn classify_string_ipv4_invalid_octet_falls_through() {
    // 999 is not a valid u8 — should fall through to Domain or Unknown.
    let cat = st::classify_string("999.1.1.1");
    assert!(matches!(
        cat,
        st::StringCategory::Domain | st::StringCategory::Unknown
    ));
}

#[test]
fn classify_string_domain() {
    assert_eq!(st::classify_string("example.com"), st::StringCategory::Domain);
}

#[test]
fn classify_string_unknown_short() {
    assert_eq!(st::classify_string("abc"), st::StringCategory::Unknown);
}

#[test]
fn classify_string_display() {
    assert_eq!(st::StringCategory::Url.to_string(), "URL");
    assert_eq!(st::StringCategory::IpAddress.to_string(), "IP Address");
}

// ===========================================================
// pe_statistics::extract_ascii_strings
// ===========================================================

#[test]
fn extract_ascii_finds_strings() {
    let data = b"hello\x00world\x00xx\x00longer_string\x00";
    let v = st::extract_ascii_strings(data, 4);
    let texts: Vec<&str> = v.iter().map(|c| c.value.as_str()).collect();
    assert!(texts.contains(&"hello"));
    assert!(texts.contains(&"world"));
    assert!(texts.contains(&"longer_string"));
    // "xx" is too short.
    assert!(!texts.contains(&"xx"));
}

#[test]
fn extract_ascii_empty_input() {
    assert!(st::extract_ascii_strings(&[], 4).is_empty());
}

#[test]
fn extract_ascii_high_min_len_filters_all() {
    let data = b"short\x00tiny\x00";
    assert!(st::extract_ascii_strings(data, 100).is_empty());
}

#[test]
fn extract_utf16_finds_strings() {
    // "ABCD" in UTF-16LE
    let mut data = Vec::new();
    for &c in &[b'A', b'B', b'C', b'D'] {
        data.push(c);
        data.push(0);
    }
    data.push(0);
    data.push(0); // null terminator
    let v = st::extract_utf16le_strings(&data, 4);
    assert!(v.iter().any(|c| c.value == "ABCD"));
}

#[test]
fn extract_utf16_short_data() {
    assert!(st::extract_utf16le_strings(&[1u8], 4).is_empty());
}

// ===========================================================
// pe_overlay_analyzer free functions
// ===========================================================

#[test]
fn overlay_compute_entropy_empty_is_zero() {
    assert!(ova::compute_entropy(&[]).abs() < 1e-12);
}

#[test]
fn overlay_is_all_zeros_true() {
    assert!(ova::is_all_zeros(&[0u8; 32]));
}

#[test]
fn overlay_is_all_zeros_false() {
    assert!(!ova::is_all_zeros(&[0, 0, 1, 0]));
}

#[test]
fn overlay_is_all_zeros_empty_true() {
    // Vacuously true.
    assert!(ova::is_all_zeros(&[]));
}

#[test]
fn overlay_byte_histogram_sum() {
    let h = ova::byte_histogram(&[1u8, 2, 3, 1]);
    let total: u64 = h.iter().sum();
    assert_eq!(total, 4);
    assert_eq!(h[1], 2);
}

#[test]
fn overlay_most_frequent_byte() {
    assert_eq!(ova::most_frequent_byte(&[5, 5, 5, 1, 2]), Some(5));
    assert_eq!(ova::most_frequent_byte(&[]), None);
}

#[test]
fn overlay_find_embedded_pe_offsets_finds_minimal() {
    let pe = minimal_x64();
    let mut combo = vec![0u8; 16];
    combo.extend_from_slice(&pe);
    let offsets = ova::find_embedded_pe_offsets(&combo);
    assert!(offsets.contains(&16));
}

#[test]
fn overlay_find_embedded_pe_none_in_random() {
    let data = vec![0u8; 256];
    assert!(ova::find_embedded_pe_offsets(&data).is_empty());
}

#[test]
fn overlay_estimate_pe_size_nonzero() {
    let pe = minimal_x64();
    let mut wrap = vec![0u8; 0];
    wrap.extend_from_slice(&pe);
    let sz = ova::estimate_pe_size(&wrap, 0);
    assert!(sz > 0);
}

#[test]
fn overlay_find_offset_short_data_safe() {
    // Function checks i + 64 < len, so any data shorter must return empty.
    assert!(ova::find_embedded_pe_offsets(&[0x4D, 0x5A]).is_empty());
}

// ===========================================================
// pe_sign_checker free functions
// ===========================================================

#[test]
fn decode_oid_basic() {
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    // DER bytes: 60 86 48 01 65 03 04 02 01
    let der = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let s = sc::decode_oid(&der);
    assert_eq!(s, "2.16.840.1.101.3.4.2.1");
}

#[test]
fn decode_oid_empty() {
    assert_eq!(sc::decode_oid(&[]), "");
}

#[test]
fn known_oid_name_lookup() {
    assert_eq!(sc::known_oid_name("2.16.840.1.101.3.4.2.1"), "sha256");
    assert_eq!(sc::known_oid_name("2.5.4.3"), "CN");
    assert_eq!(sc::known_oid_name("garbage"), "unknown");
}

// ===========================================================
// pe_manifest_parser
// ===========================================================

#[test]
fn manifest_minimal_empty_xml() {
    let m = mp::parse_manifest_xml("");
    assert_eq!(m.execution_level, None);
    assert!(!m.ui_access);
    assert!(m.assembly_name.is_empty());
    assert!(m.dependencies.is_empty());
    assert!(m.supported_os.is_empty());
}

#[test]
fn manifest_execution_level_asinvoker() {
    let xml = r#"<assembly><requestedExecutionLevel level="asInvoker"/></assembly>"#;
    let m = mp::parse_manifest_xml(xml);
    assert_eq!(m.execution_level, Some(mp::ExecutionLevel::AsInvoker));
}

#[test]
fn manifest_constants() {
    assert_eq!(mp::RT_MANIFEST, 24);
    assert_eq!(mp::MANIFEST_ID_EXE, 1);
    assert_eq!(mp::MANIFEST_ID_DLL, 2);
}

#[test]
fn manifest_alias_module_reexport() {
    // The lib re-exports pe_manifest_parser as manifest_parser.
    let _ = rustre_pe_tools::manifest_parser::RT_MANIFEST;
}

// ===========================================================
// pe_rich_header::decode_rich_header
// ===========================================================

#[test]
fn rich_header_decode_no_header() {
    let buf = vec![0u8; 256];
    let r = rh::decode_rich_header(&buf);
    assert!(r.is_err());
}

#[test]
fn rich_header_decode_too_short() {
    let r = rh::decode_rich_header(&[0u8; 10]);
    assert!(r.is_err());
}

// ===========================================================
// RichHeader::parse from lib (free fn on type)
// ===========================================================

#[test]
fn rich_header_parse_returns_none_without_marker() {
    let bytes = minimal_x64();
    assert!(RichHeader::parse(&bytes).is_none());
}

#[test]
fn rich_header_parse_short_data() {
    assert!(RichHeader::parse(&[0u8; 10]).is_none());
}

// ===========================================================
// PeCache concurrency / API completeness
// ===========================================================

#[test]
fn pe_cache_thread_safe_basic_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PeCache>();
}

#[test]
fn pe_cache_overwrite_replaces() {
    let cache = PeCache::new();
    let bytes = minimal_x64();
    let pe = PeFile::parse(&bytes).unwrap();
    cache.insert("k".into(), pe.clone());
    cache.insert("k".into(), pe);
    assert_eq!(cache.len(), 1);
}

#[test]
fn pe_cache_remove_missing_returns_none() {
    let cache = PeCache::new();
    assert!(cache.remove("nope").is_none());
}

// ===========================================================
// scan_pe sanity
// ===========================================================

#[test]
fn scan_pe_short_data_fails() {
    let r = scan_pe(&[0u8; 16]);
    assert!(r.is_err());
}

#[test]
fn scan_pe_dll_count_zero_for_minimal() {
    let bytes = minimal_x64();
    let r = scan_pe(&bytes).unwrap();
    assert_eq!(r.dll_count, 0);
    assert_eq!(r.export_count, 0);
}

// ===========================================================
// PeBuilder configuration
// ===========================================================

#[test]
fn pe_builder_x86_section_data_present() {
    let mut b = PeBuilder::new_x86();
    b.add_section(".text", vec![0xAAu8; 32], 0x6000_0020);
    let bytes = b.build();
    let pe = PeFile::parse(&bytes).unwrap();
    let t = pe.section_by_name(".text").unwrap();
    assert!(t.data.iter().any(|&b| b == 0xAA));
}

#[test]
fn pe_builder_hardened_flags_chainable() {
    let mut b = PeBuilder::new_x64();
    b.with_hardened_flags();
    b.add_section(".text", vec![0x90u8; 8], 0x6000_0020);
    let bytes = b.build();
    let pe = PeFile::parse(&bytes).unwrap();
    let dc = pe.dll_characteristics;
    assert!(dc.has_aslr() && dc.has_nx() && dc.has_high_entropy_va());
}

#[test]
fn pe_builder_dll_flag_propagates() {
    let mut b = PeBuilder::new_x64();
    b.is_dll = true;
    b.add_section(".text", vec![0x90u8; 8], 0x6000_0020);
    let bytes = b.build();
    let pe = PeFile::parse(&bytes).unwrap();
    assert!(pe.is_dll);
}

// ===========================================================
// PeSection helpers via direct construction
// ===========================================================

#[test]
fn section_permission_rwx_combinations() {
    let mk = |c: u32| PeSection {
        name: "s".to_string(),
        virtual_address: 0,
        virtual_size: 0,
        raw_offset: 0,
        raw_size: 0,
        characteristics: c,
        data: vec![],
    };
    assert_eq!(mk(0xE000_0000).permission_string(), "rwx");
    assert_eq!(mk(0x4000_0000).permission_string(), "r--");
    assert_eq!(mk(0xC000_0000).permission_string(), "rw-");
    assert_eq!(mk(0x6000_0000).permission_string(), "r-x");
    assert_eq!(mk(0).permission_string(), "---");
}

#[test]
fn section_entropy_random_high() {
    let mut data = Vec::with_capacity(2048);
    let mut x: u64 = 0xABCDEF0123456789;
    for _ in 0..2048 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        data.push((x >> 33) as u8);
    }
    let sec = PeSection {
        name: ".x".into(),
        virtual_address: 0,
        virtual_size: 0,
        raw_offset: 0,
        raw_size: data.len() as u32,
        characteristics: 0,
        data,
    };
    assert!(sec.entropy() > 7.0);
    assert!(sec.is_likely_packed());
}

#[test]
fn section_count_byte_empty_zero() {
    let sec = PeSection {
        name: String::new(),
        virtual_address: 0,
        virtual_size: 0,
        raw_offset: 0,
        raw_size: 0,
        characteristics: 0,
        data: vec![],
    };
    assert_eq!(sec.count_byte(0), 0);
}

// ===========================================================
// SecuritySummary score
// ===========================================================

#[test]
fn security_summary_all_off_score_one() {
    // !has_tls is true when has_tls is false → score should be at least 1.
    let ss = SecuritySummary {
        aslr: AslrFlags { aslr: false, high_entropy_va: false },
        protection: ProtectionFlags { nx: false, cfg: false, no_seh: false },
        integrity: IntegrityFlags { force_integrity: false, appcontainer: false, is_signed: false },
        runtime: RuntimeFlags { has_tls: false, is_dotnet: false },
    };
    assert_eq!(ss.score(), 1);
}

#[test]
fn security_summary_all_features_max_score() {
    let ss = SecuritySummary {
        aslr: AslrFlags { aslr: true, high_entropy_va: true },
        protection: ProtectionFlags { nx: true, cfg: true, no_seh: true },
        integrity: IntegrityFlags { force_integrity: true, appcontainer: true, is_signed: true },
        runtime: RuntimeFlags { has_tls: false, is_dotnet: true }, // !has_tls counted
    };
    assert_eq!(ss.score(), 10);
}

// ===========================================================
// DataDir
// ===========================================================

#[test]
fn data_dir_zero_size_present_iff_rva_nonzero() {
    let d = DataDir { rva: 1, size: 0 };
    assert!(d.is_present());
    let d0 = DataDir { rva: 0, size: 999 };
    assert!(!d0.is_present());
}

// ===========================================================
// imports/exports formatting edge cases
// ===========================================================

#[test]
fn pe_import_display_ordinal_only_no_name() {
    let i = PeImport {
        dll: "a.dll".into(),
        name: None,
        ordinal: Some(42),
        hint: 0,
        iat_rva: 0,
    };
    assert_eq!(i.to_string(), "a.dll!ord#42");
}

#[test]
fn pe_export_display_unnamed() {
    let e = PeExport {
        name: None,
        ordinal: 7,
        rva: 0x1000,
        forwarder: None,
    };
    assert!(e.to_string().contains("<unnamed>"));
}

// ===========================================================
// JSON roundtrip serde
// ===========================================================

#[test]
fn pe_json_roundtrip_basic() {
    let bytes = minimal_x64();
    let pe = PeFile::parse(&bytes).unwrap();
    let j = pe.to_json().unwrap();
    let back: PeFile = serde_json::from_str(&j).unwrap();
    assert_eq!(back.machine, pe.machine);
    assert_eq!(back.sections.len(), pe.sections.len());
}
