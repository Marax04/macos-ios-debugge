//! Blitz test suite — adversarial / boundary tests for `rustre-mobile-ipa`.
//!
//! These tests exercise the public surface with malformed, oversized, empty
//! and edge-case inputs to surface real bugs.  Tests live outside the crate
//! so they can only touch the public API.

use rustre_mobile_ipa::*;
use rustre_mobile_ipa::decrypt::{
    CryptSummary, DecryptError, EncryptionInfo, FairPlayInfo, FairPlaySlice, apply_dump,
    decryption_workflow, detect_fairplay,
};
use rustre_mobile_ipa::swift_demangler::{
    DemangleStats, demangle, demangle_batch, demangle_with_stats, extract_type_names,
    group_by_module, is_swift_symbol,
};

// ──────────────────────────────────────────────────────────────────────────
// IpaEntry boundary tests
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn entry_empty_path_filename_is_empty() {
    let e = IpaEntry { path: String::new(), size: 0, is_dir: false };
    assert_eq!(e.filename(), "");
}

#[test]
fn entry_trailing_slash_filename_empty() {
    let e = IpaEntry { path: "Payload/App.app/".into(), size: 0, is_dir: true };
    assert_eq!(e.filename(), "");
}

#[test]
fn entry_extension_hidden_dotfile() {
    // ".env" → rsplit finds "env"; behavior is documented behavior of rfind('.')
    let e = IpaEntry { path: ".env".into(), size: 1, is_dir: false };
    // rfind('.') at position 0, slice [1..] => "env"
    assert_eq!(e.extension(), Some("env"));
}

#[test]
fn entry_extension_multi_dot() {
    let e = IpaEntry { path: "Foo.tar.gz".into(), size: 1, is_dir: false };
    assert_eq!(e.extension(), Some("gz"));
}

#[test]
fn entry_is_swift_module_case_insensitive() {
    let e = IpaEntry { path: "Foo.SwiftModule".into(), size: 1, is_dir: false };
    assert!(e.is_swift_module());
}

#[test]
fn entry_is_likely_binary_size_boundary_1024_excluded() {
    // size > 1024 required.
    let e = IpaEntry { path: "Payload/App.app/App".into(), size: 1024, is_dir: false };
    assert!(!e.is_likely_binary(), "size == 1024 should not be 'likely binary'");
}

#[test]
fn entry_is_likely_binary_size_boundary_1025_included() {
    let e = IpaEntry { path: "Payload/App.app/App".into(), size: 1025, is_dir: false };
    assert!(e.is_likely_binary());
}

#[test]
fn entry_is_likely_binary_dir_excluded() {
    let e = IpaEntry { path: "Payload/App.app/App".into(), size: 1_000_000, is_dir: true };
    assert!(!e.is_likely_binary());
}

#[test]
fn entry_directory_just_slash() {
    let e = IpaEntry { path: "/".into(), size: 0, is_dir: false };
    assert_eq!(e.directory(), "");
}

// ──────────────────────────────────────────────────────────────────────────
// InfoPlist parsed_min_os edge cases
// ──────────────────────────────────────────────────────────────────────────

fn empty_info_plist(min_os: &str) -> InfoPlist {
    InfoPlist {
        bundle_id: String::new(),
        bundle_name: String::new(),
        bundle_version: String::new(),
        min_os_version: min_os.into(),
        executable: String::new(),
        supported_platforms: vec![],
        entitlements: Default::default(),
        permissions: vec![],
    }
}

#[test]
fn parsed_min_os_empty_returns_none() {
    let p = empty_info_plist("");
    assert_eq!(p.parsed_min_os(), None);
}

#[test]
fn parsed_min_os_major_only() {
    let p = empty_info_plist("17");
    assert_eq!(p.parsed_min_os(), Some((17, 0)));
}

#[test]
fn parsed_min_os_with_patch_version() {
    let p = empty_info_plist("16.4.1");
    assert_eq!(p.parsed_min_os(), Some((16, 4)));
}

#[test]
fn parsed_min_os_garbage_returns_none() {
    let p = empty_info_plist("abc");
    assert_eq!(p.parsed_min_os(), None);
}

#[test]
fn parsed_min_os_only_dot() {
    let p = empty_info_plist(".");
    // major is "" → parse fails → None
    assert_eq!(p.parsed_min_os(), None);
}

#[test]
fn targets_iphone_case_variants() {
    let p = InfoPlist {
        bundle_id: String::new(),
        bundle_name: String::new(),
        bundle_version: String::new(),
        min_os_version: String::new(),
        executable: String::new(),
        supported_platforms: vec!["IPHONEOS".into()],
        entitlements: Default::default(),
        permissions: vec![],
    };
    assert!(p.targets_iphone());
}

#[test]
fn targets_iphone_negative() {
    let p = InfoPlist {
        bundle_id: String::new(),
        bundle_name: String::new(),
        bundle_version: String::new(),
        min_os_version: String::new(),
        executable: String::new(),
        supported_platforms: vec!["MacOSX".into()],
        entitlements: Default::default(),
        permissions: vec![],
    };
    assert!(!p.targets_iphone());
}

// ──────────────────────────────────────────────────────────────────────────
// CodeSignature / CertInfo
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn codesig_adhoc_when_empty_chain() {
    // An empty certificate chain no longer means "ad-hoc": it means no
    // certificates were recovered. `CS_ADHOC` in the CodeDirectory flags is
    // what actually says a signature is ad-hoc.
    let cs = CodeSignature {
        team_id: String::new(),
        signing_id: String::new(),
        flags: 0,
        cert_chain: vec![],
        entitlements_xml: String::new(),
    };
    assert!(!cs.is_adhoc());

    let adhoc = CodeSignature {
        flags: rustre_mobile_ipa::CS_ADHOC,
        ..cs.clone()
    };
    assert!(adhoc.is_adhoc());
    assert!(cs.leaf_cert().is_none());
    assert!(cs.root_cert().is_none());
}

#[test]
fn codesig_leaf_vs_root_differ() {
    let cs = CodeSignature {
        team_id: String::new(),
        signing_id: String::new(),
        flags: 0,
        cert_chain: vec![
            CertInfo { subject: "Leaf".into(), issuer: String::new(), serial: String::new(),
                not_before: String::new(), not_after: String::new() },
            CertInfo { subject: "Intermediate".into(), issuer: String::new(), serial: String::new(),
                not_before: String::new(), not_after: String::new() },
            CertInfo { subject: "Root".into(), issuer: String::new(), serial: String::new(),
                not_before: String::new(), not_after: String::new() },
        ],
        entitlements_xml: String::new(),
    };
    assert_eq!(cs.leaf_cert().unwrap().subject, "Leaf");
    assert_eq!(cs.root_cert().unwrap().subject, "Root");
}

#[test]
fn certinfo_apple_issued_substring_match() {
    let ci = CertInfo {
        subject: String::new(),
        issuer: "Apple Worldwide Developer Relations".into(),
        serial: String::new(),
        not_before: String::new(),
        not_after: String::new(),
    };
    assert!(ci.is_apple_issued());
}

#[test]
fn certinfo_not_apple_issued() {
    let ci = CertInfo {
        subject: String::new(),
        issuer: "Self-Signed".into(),
        serial: String::new(),
        not_before: String::new(),
        not_after: String::new(),
    };
    assert!(!ci.is_apple_issued());
}

// ──────────────────────────────────────────────────────────────────────────
// IpaPackage::parse — adversarial inputs
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn parse_too_small_for_eocd() {
    // 21 bytes is below the 22-byte EOCD minimum.
    let err = IpaPackage::parse(&[0u8; 21]).unwrap_err();
    assert!(matches!(err, IpaError::InvalidIpa(_)));
}

#[test]
fn parse_garbage_fails_with_invalid_ipa() {
    let err = IpaPackage::parse(&vec![0xFFu8; 100]).unwrap_err();
    assert!(matches!(err, IpaError::InvalidIpa(_)));
}

// ──────────────────────────────────────────────────────────────────────────
// SimplePlistReader edge cases
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn simple_plist_find_key_value_empty_key() {
    // Per implementation: empty key on binary path returns None.
    let mut data = b"bplist00".to_vec();
    data.resize(100, 0);
    assert!(SimplePlistReader::find_key_value(&data, "").is_none());
}

#[test]
fn simple_plist_find_key_value_xml_false() {
    let xml = b"<plist><key>Flag</key><false/></plist>";
    assert_eq!(SimplePlistReader::find_key_value(xml, "Flag").as_deref(), Some("false"));
}

#[test]
fn simple_plist_all_strings_empty_binary() {
    // Bare magic with no payload after — should not panic.
    let data = b"bplist00";
    let _ = SimplePlistReader::all_strings(data);
}

#[test]
fn simple_plist_all_strings_invalid_utf8_returns_empty() {
    // Non-XML, non-bplist invalid UTF-8 → returns empty vec.
    let data = &[0xFFu8, 0xFE, 0xFD][..];
    let strings = SimplePlistReader::all_strings(data);
    assert!(strings.is_empty());
}

#[test]
fn simple_plist_read_string_ascii_max_length_inline() {
    // tag 0x5E = ASCII string of length 14 (0x0E)
    let mut data = vec![0x5Eu8];
    data.extend_from_slice(b"hello world!!!");
    assert_eq!(SimplePlistReader::read_string(&data, 0).as_deref(), Some("hello world!!!"));
}

#[test]
fn simple_plist_read_string_truncated_returns_none() {
    // tag 0x55 says 5 bytes, but only 2 follow.
    let data = &[0x55u8, b'a', b'b'][..];
    assert!(SimplePlistReader::read_string(data, 0).is_none());
}

#[test]
fn simple_plist_read_string_utf16_basic() {
    // tag 0x62 = UTF-16BE string, 2 code units → "ok"
    let data = &[0x62u8, 0x00, b'o', 0x00, b'k'][..];
    assert_eq!(SimplePlistReader::read_string(data, 0).as_deref(), Some("ok"));
}

#[test]
fn simple_plist_read_string_offset_out_of_bounds() {
    let data = &[0x53u8, b'a', b'b', b'c'][..];
    assert!(SimplePlistReader::read_string(data, 999).is_none());
}

// ──────────────────────────────────────────────────────────────────────────
// InfoPlistFull
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn info_plist_full_from_data_invalid_utf8_xml() {
    // Not bplist magic, not valid UTF-8 → error.
    let data = &[0xFFu8, 0xFE, 0xFD, 0xFC][..];
    assert!(InfoPlistFull::from_data(data).is_err());
}

#[test]
fn info_plist_full_from_xml_missing_keys_default_empty() {
    let p = InfoPlistFull::from_xml("<plist><dict></dict></plist>").unwrap();
    assert_eq!(p.bundle_id, "");
    assert_eq!(p.bundle_name, "");
    assert!(p.url_schemes.is_empty());
}

#[test]
fn info_plist_full_falls_back_to_bundle_version() {
    let xml = r"<plist><dict>
        <key>CFBundleVersion</key><string>9.9</string>
    </dict></plist>";
    let p = InfoPlistFull::from_xml(xml).unwrap();
    assert_eq!(p.bundle_version, "9.9");
}

// ──────────────────────────────────────────────────────────────────────────
// Entitlements adversarial
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn entitlements_invalid_utf8_xml_errors() {
    let data = &[0xFFu8, 0xFE][..];
    assert!(Entitlements::from_plist(data).is_err());
}

#[test]
fn entitlements_default_is_clean() {
    let e = Entitlements::default();
    assert!(e.application_identifier.is_none());
    assert!(!e.get_task_allow);
    assert!(e.keychain_access_groups.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────
// ProvisioningProfile
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn provisioning_profile_empty_errors() {
    let r = ProvisioningProfile::parse_cms(&[]);
    assert!(r.is_err());
}

#[test]
fn provisioning_profile_binary_plist_embedded() {
    // Profile data containing bplist00 magic — should succeed (returns profile,
    // most fields empty since we don't fully parse bplist values via find_key_value
    // for these unusual structures, but should not error out).
    let mut data = b"\x30\x82\x01\x00".to_vec(); // fake CMS prefix
    data.extend_from_slice(b"bplist00");
    data.resize(200, 0);
    // bplist payload of NUL bytes happens to be valid UTF-8, so parse succeeds
    // with empty fields — assert it does not panic and yields default-ish data.
    let r = ProvisioningProfile::parse_cms(&data);
    let profile = r.expect("zero-padded bplist payload is valid UTF-8");
    assert!(profile.uuid.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────
// BplistParser adversarial
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn bplist_parse_empty_errors() {
    assert!(BplistParser::parse(&[]).is_err());
}

#[test]
fn bplist_parse_any_invalid_utf8_xml_errors() {
    // Not bplist magic, not valid UTF-8.
    let data = &[0xFFu8, 0xFE][..];
    assert!(BplistParser::parse_any(data).is_err());
}

#[test]
fn bplist_parse_zero_trailer_errors() {
    // 32 bytes of zeros — trailer has offset_size=0 → invalid.
    let mut data = b"bplist00".to_vec();
    data.resize(40, 0); // 8 header + 32 trailer = 40
    assert!(BplistParser::parse(&data).is_err());
}

#[test]
fn bplist_value_get_chain_on_array() {
    let v = BplistValue::Array(vec![BplistValue::Int(1)]);
    assert!(v.get("any").is_none());
}

#[test]
fn bplist_value_int_negative_serde() {
    let v = BplistValue::Int(-42);
    let json = serde_json::to_string(&v).unwrap();
    let back: BplistValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back.as_int(), Some(-42));
}

#[test]
fn bplist_xml_with_no_top_level_dict_returns_null() {
    let v = BplistParser::parse_xml(b"<plist></plist>").unwrap();
    assert!(matches!(v, BplistValue::Null));
}

// ──────────────────────────────────────────────────────────────────────────
// FairPlay detection — boundary
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn fairplay_default_is_unencrypted() {
    let info = FairPlayInfo::default();
    assert!(!info.is_encrypted);
    assert!(info.slices.is_empty());
}

#[test]
fn fairplay_detect_truncated_macho_no_crash() {
    // MH_MAGIC_64 but truncated → should not panic.
    let data = &[0xCFu8, 0xFA, 0xED, 0xFE, 0, 0, 0, 0][..];
    let info = detect_fairplay(data);
    assert!(!info.is_encrypted);
}

#[test]
fn fairplay_detect_fat_with_zero_archs() {
    // FAT_MAGIC then nfat_arch=0
    let data = &[0xCAu8, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0][..];
    let info = detect_fairplay(data);
    assert!(!info.is_encrypted);
    assert!(info.slices.is_empty());
}

#[test]
fn fairplay_detect_fat_oversized_arch_count_capped() {
    // nfat_arch claims a huge number; implementation caps at 16.
    let mut data = vec![0xCAu8, 0xFE, 0xBA, 0xBE];
    data.extend_from_slice(&u32::to_be_bytes(99999));
    // Not enough bytes for any arch slice → loop breaks safely.
    let info = detect_fairplay(&data);
    assert!(!info.is_encrypted);
}

#[test]
fn encryption_info_scheme_unknown() {
    let ei = EncryptionInfo { cmd: 0x21, crypt_offset: 0, crypt_size: 0, crypt_id: 99 };
    assert_eq!(ei.scheme_name(), "Unknown");
    assert!(ei.is_encrypted());
}

#[test]
fn fairplay_slice_no_info_not_encrypted() {
    let s = FairPlaySlice { arch: "arm64".into(), file_offset: 0, encryption_info: None };
    assert!(!s.is_encrypted());
}

#[test]
fn crypt_summary_empty() {
    let s = CryptSummary::from_fairplay_info(&FairPlayInfo::default());
    assert_eq!(s.total_slices, 0);
    assert_eq!(s.encrypted_slices, 0);
    assert!(!s.has_fairplay);
    assert!(s.arch_list.is_empty());
}

#[test]
fn apply_dump_garbage_magic_errors() {
    let r = apply_dump(&[0, 1, 2, 3], "App", std::path::Path::new("."));
    assert!(matches!(r, Err(DecryptError::InvalidMachO(_))));
}

#[test]
fn decryption_workflow_mentions_frida() {
    let s = decryption_workflow();
    assert!(s.contains("frida") || s.contains("bagbak"));
}

#[test]
fn decrypt_error_display_variants() {
    assert!(DecryptError::Io("e".into()).to_string().contains("io"));
    assert!(DecryptError::PatchFailed("p".into()).to_string().contains("patch"));
}

// ──────────────────────────────────────────────────────────────────────────
// Swift demangler shim
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn swift_demangle_not_swift_input() {
    assert!(demangle("malloc").is_none());
    assert!(demangle("_objc_msgSend").is_none());
    assert!(demangle("").is_none());
}

#[test]
fn swift_is_swift_symbol_negatives() {
    assert!(!is_swift_symbol(""));
    assert!(!is_swift_symbol("plain_c"));
}

#[test]
fn swift_demangle_batch_empty_input() {
    let r = demangle_batch(&[]);
    assert!(r.is_empty());
}

#[test]
fn swift_stats_zero_total_success_rate_is_zero() {
    let s = DemangleStats::default();
    assert_eq!(s.success_rate(), 0.0);
}

#[test]
fn swift_demangle_with_stats_all_failed() {
    let syms = vec!["malloc".into(), "free".into()];
    let (_, stats) = demangle_with_stats(&syms);
    assert_eq!(stats.total, 2);
    assert_eq!(stats.failed, 2);
    assert_eq!(stats.demangled, 0);
    assert_eq!(stats.success_rate(), 0.0);
}

#[test]
fn swift_group_by_module_empty_input() {
    let g = group_by_module(&[]);
    assert!(g.is_empty());
}

#[test]
fn swift_extract_type_names_empty() {
    let v = extract_type_names(&[]);
    assert!(v.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────
// Serde roundtrips
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn serde_fairplay_info_roundtrip() {
    let info = FairPlayInfo {
        is_encrypted: true,
        slices: vec![FairPlaySlice {
            arch: "arm64".into(),
            file_offset: 0x1000,
            encryption_info: Some(EncryptionInfo {
                cmd: 0x2C, crypt_offset: 0x4000, crypt_size: 0x4000, crypt_id: 1,
            }),
        }],
    };
    let json = serde_json::to_string(&info).unwrap();
    let back: FairPlayInfo = serde_json::from_str(&json).unwrap();
    assert!(back.is_encrypted);
    assert_eq!(back.slices.len(), 1);
    assert_eq!(back.slices[0].arch, "arm64");
}

#[test]
fn serde_entitlements_full_roundtrip() {
    let e = Entitlements {
        application_identifier: Some("T.x".into()),
        keychain_access_groups: vec!["a".into(), "b".into()],
        team_identifier: Some("T".into()),
        get_task_allow: true,
        aps_environment: Some("development".into()),
        associated_domains: vec!["applinks:e.com".into()],
    };
    let s = serde_json::to_string(&e).unwrap();
    let back: Entitlements = serde_json::from_str(&s).unwrap();
    assert_eq!(back.keychain_access_groups.len(), 2);
    assert!(back.get_task_allow);
}

#[test]
fn serde_bplist_dict_roundtrip() {
    let v = BplistValue::Dict(vec![
        ("a".into(), BplistValue::Int(1)),
        ("b".into(), BplistValue::Bool(true)),
        ("c".into(), BplistValue::Real(2.5)),
    ]);
    let s = serde_json::to_string(&v).unwrap();
    let back: BplistValue = serde_json::from_str(&s).unwrap();
    assert_eq!(back.get("a").and_then(BplistValue::as_int), Some(1));
    assert_eq!(back.get("b").and_then(BplistValue::as_bool), Some(true));
}
