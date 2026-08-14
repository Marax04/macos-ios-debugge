//! Blitz test suite for rustre-loader-pe.
//!
//! Focus: pure parser helpers, public surface invariants, malformed input
//! handling, and `PeInfo::parse` on adversarial inputs.

use rustre_loader_pe::*;

// ---------------------------------------------------------------------------
// PeInfo::parse on adversarial / non-PE input
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_input_errors() {
    assert!(PeInfo::parse(&[]).is_err());
}

#[test]
fn parse_too_short_input_errors() {
    assert!(PeInfo::parse(&[0u8; 4]).is_err());
}

#[test]
fn parse_random_garbage_errors() {
    let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    assert!(PeInfo::parse(&data).is_err());
}

#[test]
fn parse_dos_header_without_pe_errors() {
    let mut data = vec![0u8; 0x100];
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew = 0x80 → points to zeros (no PE\0\0 signature)
    data[0x3C] = 0x80;
    assert!(PeInfo::parse(&data).is_err());
}

#[test]
fn parse_dos_header_bad_e_lfanew_errors() {
    let mut data = vec![0u8; 0x100];
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew well past EOF
    data[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(PeInfo::parse(&data).is_err());
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn entropy_constant_is_zero() {
    assert!(shannon_entropy(&vec![0x77u8; 1024]) < 1e-9);
}

#[test]
fn entropy_uniform_is_eight() {
    let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    assert!(shannon_entropy(&data) > 7.99);
}

#[test]
fn entropy_two_symbols_is_one_bit() {
    let mut data = vec![0u8; 512];
    data.extend(std::iter::repeat_n(1u8, 512));
    let e = shannon_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0 got {e}");
}

#[test]
fn byte_histogram_sums_to_len() {
    let data: Vec<u8> = (0..200u8).collect();
    let h = byte_histogram(&data);
    let sum: u64 = h.iter().map(|&c| u64::from(c)).sum();
    assert_eq!(sum, data.len() as u64);
}

#[test]
fn most_common_byte_empty() {
    assert_eq!(most_common_byte(&[]), (0, 0));
}

#[test]
fn most_common_byte_finds_max() {
    let mut d = vec![5u8; 100];
    d.extend(std::iter::repeat_n(9u8, 50));
    assert_eq!(most_common_byte(&d), (5, 100));
}

#[test]
fn looks_packed_short_buffer_false() {
    let data: Vec<u8> = (0..=255u8).cycle().take(100).collect();
    assert!(!looks_packed(&data));
}

#[test]
fn looks_packed_uniform_true() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    assert!(looks_packed(&data));
}

#[test]
fn looks_packed_zeros_false() {
    assert!(!looks_packed(&vec![0u8; 4096]));
}

#[test]
fn entropy_summary_no_sections_not_packed() {
    let summary = EntropySummary::analyze(&[0u8; 100], &[]);
    assert_eq!(summary.packed_section_count, 0);
    assert!(!summary.verdict_packed);
    assert_eq!(summary.avg_section_entropy, 0.0);
}

#[test]
fn entropy_summary_high_entropy_filter_sorted_desc() {
    let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    let secs = vec![
        SectionWithName {
            section: RvaSection {
                virtual_address: 0,
                virtual_size: 4096,
                raw_size: 4096,
                raw_offset: 0,
            },
            name: ".a".into(),
        },
        SectionWithName {
            section: RvaSection {
                virtual_address: 0x2000,
                virtual_size: 4096,
                raw_size: 4096,
                raw_offset: 4096,
            },
            name: ".b".into(),
        },
    ];
    let s = EntropySummary::analyze(&data, &secs);
    let high = s.high_entropy_sections(0.0);
    assert_eq!(high.len(), 2);
    assert!(high[0].entropy >= high[1].entropy);
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

#[test]
fn scan_ascii_finds_basic() {
    let data = b"\x00\x00hello world\x00";
    let s = scan_ascii(data, 4);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].value, "hello world");
    assert_eq!(s[0].offset, 2);
}

#[test]
fn scan_ascii_below_min_len_ignored() {
    let s = scan_ascii(b"abc\x00xy\x00", 4);
    assert!(s.is_empty());
}

#[test]
fn scan_ascii_empty() {
    assert!(scan_ascii(&[], 4).is_empty());
}

#[test]
fn scan_ascii_string_at_eof() {
    let s = scan_ascii(b"abcdefgh", 4);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].value, "abcdefgh");
}

#[test]
fn scan_utf16_basic() {
    let data: Vec<u8> = "WIDE".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let s = scan_utf16le(&data, 4);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].value, "WIDE");
}

#[test]
fn scan_utf16_too_short_input() {
    assert!(scan_utf16le(&[0u8], 4).is_empty());
    assert!(scan_utf16le(&[], 4).is_empty());
}

#[test]
fn scan_strings_dedup_works() {
    let opts = ScanOptions {
        deduplicate: true,
        scan_utf16le: false,
        ..Default::default()
    };
    let r = scan_strings(b"abcd\x00abcd\x00abcd\x00", &opts);
    assert_eq!(r.iter().filter(|s| s.value == "abcd").count(), 1);
}

#[test]
fn scan_section_out_of_range_returns_empty() {
    let opts = ScanOptions::default();
    let r = scan_section(b"hello", 999, 10, ".x", &opts);
    assert!(r.is_empty());
}

#[test]
fn is_printable_ascii_boundaries() {
    assert!(is_printable_ascii(0x20));
    assert!(is_printable_ascii(0x7E));
    assert!(!is_printable_ascii(0x1F));
    assert!(!is_printable_ascii(0x7F));
    assert!(!is_printable_ascii(0));
}

#[test]
fn is_printable_utf16_boundaries() {
    assert!(is_printable_utf16(0x0020));
    assert!(is_printable_utf16(0x007E));
    assert!(!is_printable_utf16(0xD800)); // surrogate
    assert!(!is_printable_utf16(0xD7FF + 1)); // == 0xD800
    assert!(is_printable_utf16(0xD7FF));
    assert!(!is_printable_utf16(0));
}

#[test]
fn extracted_string_byte_size_utf16_is_double() {
    let s = ExtractedString {
        value: "abc".into(),
        offset: 0,
        encoding: StringEncoding::Utf16Le,
        section: None,
    };
    assert_eq!(s.byte_size(), 6);
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
}

#[test]
fn classify_url_wins_over_path() {
    let s = ExtractedString {
        value: "https://example.com/x".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), Some(InterestingCategory::Url));
}

#[test]
fn classify_registry_key() {
    let s = ExtractedString {
        value: "HKLM\\Software\\Foo".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), Some(InterestingCategory::RegistryKey));
}

#[test]
fn classify_file_path_windows() {
    let s = ExtractedString {
        value: "C:\\Windows\\System32".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), Some(InterestingCategory::FilePath));
}

#[test]
fn classify_base64_before_api() {
    let s = ExtractedString {
        value: "QUJDREVGR0hJSktMTU5PUFFSU1RVVlc=".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), Some(InterestingCategory::Base64));
}

#[test]
fn classify_api_name() {
    let s = ExtractedString {
        value: "CreateFileW".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), Some(InterestingCategory::ApiName));
}

#[test]
fn classify_short_non_matching_returns_none() {
    let s = ExtractedString {
        value: "abc".into(),
        offset: 0,
        encoding: StringEncoding::Ascii,
        section: None,
    };
    assert_eq!(classify_string(&s), None);
}

// ---------------------------------------------------------------------------
// RvaSection / rva_to_file_offset
// ---------------------------------------------------------------------------

const fn sec(va: u32, vs: u32, ro: u32, rs: u32) -> RvaSection {
    RvaSection {
        virtual_address: va,
        virtual_size: vs,
        raw_size: rs,
        raw_offset: ro,
    }
}

#[test]
fn rva_to_offset_inside_section() {
    let s = sec(0x1000, 0x100, 0x400, 0x100);
    assert_eq!(s.rva_to_offset(0x1000), Some(0x400));
    assert_eq!(s.rva_to_offset(0x1050), Some(0x450));
}

#[test]
fn rva_to_offset_outside_section_none() {
    let s = sec(0x1000, 0x100, 0x400, 0x100);
    assert_eq!(s.rva_to_offset(0x0FFF), None);
    assert_eq!(s.rva_to_offset(0x1100), None);
}

#[test]
fn rva_to_offset_boundary_end_exclusive() {
    let s = sec(0x1000, 0x100, 0x400, 0x100);
    // end is exclusive: 0x1000 + 0x100 = 0x1100, so 0x10FF in, 0x1100 out
    assert!(s.rva_to_offset(0x10FF).is_some());
    assert!(s.rva_to_offset(0x1100).is_none());
}

#[test]
fn rva_to_file_offset_multi_section() {
    let secs = vec![sec(0x1000, 0x100, 0x400, 0x100), sec(0x2000, 0x100, 0x600, 0x100)];
    assert_eq!(rva_to_file_offset(0x2010, &secs), Some(0x610));
    assert_eq!(rva_to_file_offset(0x3000, &secs), None);
}

#[test]
fn rva_to_file_offset_empty_sections() {
    assert_eq!(rva_to_file_offset(0x1000, &[]), None);
}

// ---------------------------------------------------------------------------
// ImportDescriptor / DelayImportDescriptor
// ---------------------------------------------------------------------------

#[test]
fn import_descriptor_truncated_errors() {
    let data = vec![0u8; 10];
    assert!(ImportDescriptor::parse(&data, 0).is_err());
}

#[test]
fn import_descriptor_null_entry() {
    let data = vec![0u8; 20];
    let d = ImportDescriptor::parse(&data, 0).unwrap();
    assert!(d.is_null());
    assert!(!d.is_bound());
}

#[test]
fn import_descriptor_bound_flag() {
    let mut data = vec![0u8; 20];
    data[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let d = ImportDescriptor::parse(&data, 0).unwrap();
    assert!(d.is_bound());
    assert!(!d.is_null());
}

#[test]
fn delay_import_descriptor_truncated_errors() {
    let data = vec![0u8; 10];
    assert!(DelayImportDescriptor::parse(&data, 0).is_err());
}

#[test]
fn delay_import_descriptor_uses_rvas_bit() {
    let mut data = vec![0u8; 32];
    data[0] = 0x01;
    let d = DelayImportDescriptor::parse(&data, 0).unwrap();
    assert!(d.uses_rvas());
    data[0] = 0x00;
    let d = DelayImportDescriptor::parse(&data, 0).unwrap();
    assert!(!d.uses_rvas());
}

// ---------------------------------------------------------------------------
// Debug directory helpers
// ---------------------------------------------------------------------------

#[test]
fn debug_type_name_known() {
    assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_CODEVIEW), "CODEVIEW");
    assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_REPRO), "REPRO");
}

#[test]
fn debug_type_name_unknown() {
    assert_eq!(debug_type_name(9999), "UNKNOWN_TYPE");
}

#[test]
fn debug_directory_entry_truncated() {
    let data = vec![0u8; 10];
    assert!(DebugDirectoryEntry::parse(&data, 0).is_err());
}

#[test]
fn debug_directory_entry_codeview_flag() {
    let mut data = vec![0u8; 28];
    data[12..16].copy_from_slice(&IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes());
    let e = DebugDirectoryEntry::parse(&data, 0).unwrap();
    assert!(e.is_codeview());
    assert_eq!(e.type_name(), "CODEVIEW");
}

#[test]
fn detect_dotnet_nonzero_rva() {
    assert!(detect_dotnet(0x2000));
    assert!(!detect_dotnet(0));
}

// ---------------------------------------------------------------------------
// Overlay / SfxKind / WinCertificate
// ---------------------------------------------------------------------------

#[test]
fn cert_type_name_known() {
    assert_eq!(cert_type_name(WIN_CERT_TYPE_X509), "X.509");
    assert!(cert_type_name(WIN_CERT_TYPE_PKCS_SIGNED_DATA).contains("Authenticode"));
}

#[test]
fn cert_type_name_unknown() {
    assert_eq!(cert_type_name(0xBEEF), "Unknown");
}

#[test]
fn detect_sfx_kind_rar() {
    assert_eq!(detect_sfx_kind(b"Rar!\x1A\x07\x00"), SfxKind::WinRar);
    assert_eq!(detect_sfx_kind(b"Rar!\x1A\x07\x01\x00"), SfxKind::WinRar);
}

#[test]
fn detect_sfx_kind_7z() {
    assert_eq!(detect_sfx_kind(b"7z\xBC\xAF\x27\x1C"), SfxKind::SevenZip);
}

#[test]
fn detect_sfx_kind_zip() {
    assert_eq!(detect_sfx_kind(b"PK\x03\x04"), SfxKind::Zip);
}

#[test]
fn detect_sfx_kind_cabinet() {
    assert_eq!(detect_sfx_kind(b"MSCF"), SfxKind::Cabinet);
}

#[test]
fn detect_sfx_kind_autoit() {
    assert_eq!(detect_sfx_kind(b"AU3!EA06abcd"), SfxKind::AutoIt);
}

#[test]
fn detect_sfx_kind_unknown_short() {
    assert_eq!(detect_sfx_kind(b""), SfxKind::Unknown);
    assert_eq!(detect_sfx_kind(b"AB"), SfxKind::Unknown);
}

#[test]
fn sfx_kind_label_non_empty() {
    for k in [
        SfxKind::Nsis,
        SfxKind::WinRar,
        SfxKind::SevenZip,
        SfxKind::Zip,
        SfxKind::InnoSetup,
        SfxKind::InstallShield,
        SfxKind::Cabinet,
        SfxKind::AutoIt,
        SfxKind::Unknown,
    ] {
        assert!(!k.label().is_empty());
    }
}

#[test]
fn win_certificate_too_short_errors() {
    assert!(WinCertificate::parse(&[0u8; 4], 0).is_err());
}

#[test]
fn win_certificate_length_below_header_errors() {
    let mut data = vec![0u8; 16];
    // length=4 (< 8) → must error
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    assert!(WinCertificate::parse(&data, 0).is_err());
}

#[test]
fn win_certificate_truncated_data_errors() {
    let mut data = vec![0u8; 10];
    // length = 100 but buffer only 10 bytes
    data[0..4].copy_from_slice(&100u32.to_le_bytes());
    data[4..6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    data[6..8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    assert!(WinCertificate::parse(&data, 0).is_err());
}

#[test]
fn win_certificate_round_trip_minimal() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&12u32.to_le_bytes()); // length: 8 hdr + 4 body
    data[4..6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    data[6..8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    data[8..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let c = WinCertificate::parse(&data, 0).unwrap();
    assert_eq!(c.length, 12);
    assert_eq!(c.revision, WIN_CERT_REVISION_2_0);
    assert!(c.is_authenticode());
    assert_eq!(c.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    // padded length: 12 → next multiple of 8 = 16
    assert_eq!(c.padded_length(), 16);
    assert_eq!(c.type_name(), cert_type_name(WIN_CERT_TYPE_PKCS_SIGNED_DATA));
}

#[test]
fn win_certificate_padded_length_already_aligned() {
    let c = WinCertificate {
        length: 16,
        revision: WIN_CERT_REVISION_1_0,
        certificate_type: WIN_CERT_TYPE_X509,
        data: vec![0u8; 8],
    };
    assert_eq!(c.padded_length(), 16);
    assert!(!c.is_authenticode());
}

#[test]
fn find_overlay_offset_no_overlay() {
    let data = vec![0u8; 100];
    let secs = vec![sec(0x1000, 0x100, 0, 100)];
    assert_eq!(find_overlay_offset(&data, &secs, 0, 0), None);
}

#[test]
fn find_overlay_offset_has_overlay() {
    let data = vec![0u8; 200];
    let secs = vec![sec(0x1000, 0x100, 0, 100)];
    assert_eq!(find_overlay_offset(&data, &secs, 0, 0), Some(100));
}

#[test]
fn find_overlay_offset_uses_cert_dir_max() {
    let data = vec![0u8; 400];
    let secs = vec![sec(0x1000, 0x100, 0, 100)];
    // cert dir extends to 300 → overlay starts at 300
    assert_eq!(find_overlay_offset(&data, &secs, 200, 100), Some(300));
}

#[test]
fn find_overlay_offset_empty_sections_no_cert() {
    let data = vec![0u8; 100];
    assert_eq!(find_overlay_offset(&data, &[], 0, 0), None);
}

#[test]
fn parse_security_directory_empty_returns_empty() {
    let data = vec![0u8; 100];
    assert!(parse_security_directory(&data, 0, 0).is_empty());
}

#[test]
fn parse_security_directory_out_of_range_returns_empty() {
    let data = vec![0u8; 100];
    assert!(parse_security_directory(&data, 200, 50).is_empty());
}

// ---------------------------------------------------------------------------
// SectionInfo helpers
// ---------------------------------------------------------------------------

use rustre_core::permissions::Permissions;

fn mk_section(chars: u32) -> SectionInfo {
    SectionInfo {
        name: ".x".into(),
        virtual_address: 0x1000,
        virtual_size: 0x200,
        raw_offset: 0x400,
        raw_size: 0x100,
        characteristics: chars,
        permissions: Permissions::READ,
    }
}

#[test]
fn section_info_is_code_writable_readable() {
    let exec = mk_section(0x2000_0000);
    assert!(exec.is_code());
    assert!(!exec.is_writable());
    assert!(!exec.is_readable());

    let rw = mk_section(0xC000_0000);
    assert!(rw.is_readable());
    assert!(rw.is_writable());
    assert!(!rw.is_code());
}

#[test]
fn section_info_va_range_and_mapped_size() {
    let s = mk_section(0x4000_0000);
    assert_eq!(s.va_range(), (0x1000, 0x1200));
    assert_eq!(s.mapped_size(), 0x200);
}

// ---------------------------------------------------------------------------
// Machine / Subsystem enum derives
// ---------------------------------------------------------------------------

#[test]
fn machine_eq_and_clone() {
    let m = Machine::X64;
    let n = m.clone();
    assert_eq!(m, n);
    assert_ne!(Machine::X64, Machine::X86);
    assert_eq!(Machine::Unknown(0x1234), Machine::Unknown(0x1234));
}

#[test]
fn subsystem_eq_and_debug() {
    assert_eq!(Subsystem::Console, Subsystem::Console);
    assert!(format!("{:?}", Subsystem::EfiRom).contains("EfiRom"));
}

// ---------------------------------------------------------------------------
// ExportEntry / ImportEntry trivial value semantics
// ---------------------------------------------------------------------------

#[test]
fn export_entry_eq() {
    let a = ExportEntry {
        name: Some("foo".into()),
        ordinal: 1,
        address: 0x1000,
        forwarder: None,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn import_entry_eq() {
    let a = ImportEntry {
        dll: "user32.dll".into(),
        name: Some("MessageBoxW".into()),
        ordinal: None,
        address: 0x2000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Relocation constants sanity
// ---------------------------------------------------------------------------

#[test]
fn relocation_constants_have_expected_values() {
    assert_eq!(IMAGE_REL_BASED_ABSOLUTE, 0);
    assert_eq!(IMAGE_REL_BASED_HIGHLOW, 3);
    assert_eq!(IMAGE_REL_BASED_DIR64, 10);
}

#[test]
fn parse_relocation_directory_empty_returns_empty() {
    let data = vec![0u8; 100];
    let secs: Vec<RvaSection> = vec![];
    let blocks = parse_relocation_directory(&data, &secs, 0x1000, 0);
    assert!(blocks.is_empty());
}

// ---------------------------------------------------------------------------
// PE thresholds
// ---------------------------------------------------------------------------

#[test]
fn entropy_thresholds_ordered() {
    assert!(LOW_ENTROPY_THRESHOLD < PACKED_ENTROPY_THRESHOLD);
    assert!(PACKED_ENTROPY_THRESHOLD < HIGH_ENTROPY_THRESHOLD);
    assert!(HIGH_ENTROPY_THRESHOLD <= 8.0);
}

#[test]
fn min_string_constants_reasonable() {
    assert!(MIN_ASCII_LEN >= 1);
    assert!(MIN_UTF16_LEN >= 1);
}

// ---------------------------------------------------------------------------
// Ordinal flag constants
// ---------------------------------------------------------------------------

#[test]
fn ordinal_flag_constants() {
    assert_eq!(IMAGE_ORDINAL_FLAG32, 0x8000_0000);
    assert_eq!(IMAGE_ORDINAL_FLAG64, 0x8000_0000_0000_0000);
}
