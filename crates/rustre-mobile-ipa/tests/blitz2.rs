//! blitz2 adversarial test suite for rustre-mobile-ipa public API.

use rustre_mobile_ipa::{
    BplistParser, BplistValue, CertInfo, CodeSignature, Entitlements, InfoPlist, InfoPlistFull,
    IpaEntry, IpaError, IpaPackage, ProvisioningProfile, SimplePlistReader,
};
use std::collections::HashMap;

// Seeded LCG fuzz generator.
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(n: usize, rng: &mut impl FnMut() -> u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let r = rng();
        v.extend_from_slice(&r.to_le_bytes());
    }
    v.truncate(n);
    v
}

// ---------------------------------------------------------------------------
// IpaError display + Debug
// ---------------------------------------------------------------------------

#[test]
fn t01_error_displays_all_variants() {
    let variants = vec![
        IpaError::InvalidIpa("x".into()),
        IpaError::MissingFile("x".into()),
        IpaError::PlistParse("x".into()),
        IpaError::Io("x".into()),
        IpaError::FairPlay("x".into()),
        IpaError::Resource("x".into()),
    ];
    for e in variants {
        let s = e.to_string();
        assert!(!s.is_empty());
        let d = format!("{e:?}");
        assert!(!d.is_empty());
    }
}

// ---------------------------------------------------------------------------
// IpaEntry helpers — boundaries and edge cases
// ---------------------------------------------------------------------------

#[test]
fn t02_entry_filename_directory_root_path() {
    let e = IpaEntry {
        path: String::new(),
        size: 0,
        is_dir: false,
    };
    assert_eq!(e.filename(), "");
    assert_eq!(e.directory(), "");
}

#[test]
fn t03_entry_extension_dotfile() {
    let e = IpaEntry {
        path: ".hidden".into(),
        size: 0,
        is_dir: false,
    };
    // .hidden → rfind('.') at 0, extension = "hidden"
    assert_eq!(e.extension(), Some("hidden"));
}

#[test]
fn t04_entry_extension_multiple_dots() {
    let e = IpaEntry {
        path: "lib.so.1.2.3".into(),
        size: 0,
        is_dir: false,
    };
    assert_eq!(e.extension(), Some("3"));
}

#[test]
fn t05_entry_is_swift_module_case_insensitive() {
    let e = IpaEntry {
        path: "Mod.SwiftModule".into(),
        size: 100,
        is_dir: false,
    };
    assert!(e.is_swift_module());
}

#[test]
fn t06_entry_is_likely_binary_boundaries() {
    // size = 1024 → not greater than 1024
    let e1 = IpaEntry {
        path: "App".into(),
        size: 1024,
        is_dir: false,
    };
    assert!(!e1.is_likely_binary());
    let e2 = IpaEntry {
        path: "App".into(),
        size: 1025,
        is_dir: false,
    };
    assert!(e2.is_likely_binary());
    // dirs are not binary
    let e3 = IpaEntry {
        path: "Dir".into(),
        size: 99999,
        is_dir: true,
    };
    assert!(!e3.is_likely_binary());
    // having extension disqualifies
    let e4 = IpaEntry {
        path: "App.png".into(),
        size: 99999,
        is_dir: false,
    };
    assert!(!e4.is_likely_binary());
}

#[test]
fn t07_entry_serde_roundtrip_50_inputs() {
    let mut g = lcg();
    for i in 0..50 {
        let e = IpaEntry {
            path: format!("Payload/A{i}.app/file_{}", g() % 1000),
            size: g(),
            is_dir: i % 3 == 0,
        };
        let j = serde_json::to_string(&e).unwrap();
        let back: IpaEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back.path, e.path);
        assert_eq!(back.size, e.size);
        assert_eq!(back.is_dir, e.is_dir);
    }
}

// ---------------------------------------------------------------------------
// InfoPlist helpers
// ---------------------------------------------------------------------------

#[test]
fn t08_info_plist_parsed_min_os_variations() {
    let mk = |v: &str| InfoPlist {
        bundle_id: "x".into(),
        bundle_name: "x".into(),
        bundle_version: "x".into(),
        min_os_version: v.into(),
        executable: "x".into(),
        supported_platforms: vec![],
        entitlements: HashMap::new(),
        permissions: vec![],
    };
    assert_eq!(mk("15.0").parsed_min_os(), Some((15, 0)));
    assert_eq!(mk("16").parsed_min_os(), Some((16, 0)));
    assert_eq!(mk("16.4.2").parsed_min_os(), Some((16, 4)));
    assert_eq!(mk("").parsed_min_os(), None);
    assert_eq!(mk("notanumber").parsed_min_os(), None);
}

#[test]
fn t09_info_plist_targets_iphone_case_insensitive() {
    let p = InfoPlist {
        bundle_id: String::new(),
        bundle_name: String::new(),
        bundle_version: String::new(),
        min_os_version: String::new(),
        executable: String::new(),
        supported_platforms: vec!["IPHONEOS".into()],
        entitlements: HashMap::new(),
        permissions: vec![],
    };
    assert!(p.targets_iphone());
}

#[test]
fn t10_info_plist_has_permission_negative() {
    let p = InfoPlist {
        bundle_id: String::new(),
        bundle_name: String::new(),
        bundle_version: String::new(),
        min_os_version: String::new(),
        executable: String::new(),
        supported_platforms: vec![],
        entitlements: HashMap::new(),
        permissions: vec!["NSCameraUsageDescription".into()],
    };
    assert!(p.has_permission("NSCameraUsageDescription"));
    assert!(!p.has_permission("NSMicrophoneUsageDescription"));
    assert!(!p.has_permission(""));
}

// ---------------------------------------------------------------------------
// CodeSignature / CertInfo
// ---------------------------------------------------------------------------

#[test]
fn t11_code_signature_adhoc_empty_chain() {
    let cs = CodeSignature {
        team_id: String::new(),
        signing_id: String::new(),
        flags: 0,
        cert_chain: vec![],
        entitlements_xml: String::new(),
    };
    // Empty chain now means "no certificates recovered", not "ad-hoc";
    // CS_ADHOC in the CodeDirectory flags is the real signal.
    assert!(!cs.is_adhoc());
    assert!(!cs.is_developer_signed());
    assert!(!cs.is_enterprise());
    assert!(cs.leaf_cert().is_none());
    assert!(cs.root_cert().is_none());
}

#[test]
fn t12_code_signature_enterprise_detect() {
    let cs = CodeSignature {
        team_id: "T".into(),
        signing_id: "S".into(),
        // 7 sets CS_ADHOC (0x2), so this signature really does declare itself
        // ad-hoc; only the certificate-derived questions differ.
        flags: 7,
        cert_chain: vec![CertInfo {
            subject: "iPhone Distribution: Acme".into(),
            issuer: "Apple WWDR".into(),
            serial: "1".into(),
            not_before: "n".into(),
            not_after: "n".into(),
        }],
        entitlements_xml: String::new(),
    };
    assert!(cs.is_enterprise());
    assert!(!cs.is_developer_signed());
    assert!(cs.is_adhoc());
}

#[test]
fn t13_cert_info_apple_issued_negative() {
    let c = CertInfo {
        subject: "CN=evil".into(),
        issuer: "Acme Root".into(),
        serial: "x".into(),
        not_before: "x".into(),
        not_after: "x".into(),
    };
    assert!(!c.is_apple_issued());
}

#[test]
fn t14_cert_info_serde_roundtrip_30_pairs() {
    let mut g = lcg();
    for _ in 0..30 {
        let c = CertInfo {
            subject: format!("CN=test{}", g() % 100),
            issuer: "Apple".into(),
            serial: format!("{:x}", g()),
            not_before: "a".into(),
            not_after: "b".into(),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: CertInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back.subject, c.subject);
        assert_eq!(back.serial, c.serial);
    }
}

// ---------------------------------------------------------------------------
// IpaPackage::parse — adversarial inputs
// ---------------------------------------------------------------------------

#[test]
fn t15_parse_empty_is_err() {
    assert!(matches!(IpaPackage::parse(&[]), Err(IpaError::InvalidIpa(_))));
}

#[test]
fn t16_parse_one_byte_is_err() {
    for b in 0u8..=255 {
        let r = IpaPackage::parse(&[b]);
        assert!(r.is_err());
    }
}

#[test]
fn t17_parse_22_zero_bytes_is_err() {
    // Just enough length to start EOCD search but no valid EOCD signature.
    let data = vec![0u8; 22];
    assert!(IpaPackage::parse(&data).is_err());
}

#[test]
fn t18_parse_fuzz_never_panics() {
    let mut g = lcg();
    for sz in [0, 1, 21, 22, 23, 64, 256, 1024, 4096] {
        for _ in 0..20 {
            let bytes = rand_bytes(sz, &mut g);
            let _ = IpaPackage::parse(&bytes); // must not panic
        }
    }
}

#[test]
fn t19_parse_fuzz_with_eocd_magic_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let mut bytes = rand_bytes(200, &mut g);
        // Inject EOCD magic at the end
        let n = bytes.len();
        bytes[n - 22..n - 18].copy_from_slice(&0x0605_4B50u32.to_le_bytes());
        let _ = IpaPackage::parse(&bytes);
    }
}

// ---------------------------------------------------------------------------
// IpaPackage::mock + helpers
// ---------------------------------------------------------------------------

#[test]
fn t20_mock_invariants() {
    let pkg = IpaPackage::mock();
    assert_eq!(pkg.entry_count(), pkg.entries.len());
    assert_eq!(pkg.framework_count(), pkg.frameworks.len());
    assert!(!pkg.is_encrypted());
    assert!(pkg.has_entitlement("com.apple.developer.team-identifier"));
}

#[test]
fn t21_mock_serde_roundtrip() {
    let pkg = IpaPackage::mock();
    let j = serde_json::to_string(&pkg).unwrap();
    let back: IpaPackage = serde_json::from_str(&j).unwrap();
    assert_eq!(back.executable_path, pkg.executable_path);
    assert_eq!(back.entries.len(), pkg.entries.len());
    assert_eq!(back.frameworks.len(), pkg.frameworks.len());
}

#[test]
fn t22_mock_binary_entries_filter() {
    let pkg = IpaPackage::mock();
    let bins = pkg.binary_entries();
    // Only the TestApp executable (512KB, no extension) qualifies.
    assert_eq!(bins.len(), 1);
    assert_eq!(bins[0].path, "Payload/TestApp.app/TestApp");
}

#[test]
fn t23_mock_asset_catalog_entries_empty() {
    let pkg = IpaPackage::mock();
    assert!(pkg.asset_catalog_entries().is_empty());
    assert!(pkg.strings_entries().is_empty());
}

// ---------------------------------------------------------------------------
// SimplePlistReader
// ---------------------------------------------------------------------------

#[test]
fn t24_simple_plist_is_binary_short_data() {
    for n in 0..8 {
        let d = vec![b'b'; n];
        assert!(!SimplePlistReader::is_binary_plist(&d));
    }
}

#[test]
fn t25_simple_plist_find_key_value_false_true_xml() {
    let xml = b"<dict><key>K1</key><false/><key>K2</key><true/></dict>";
    assert_eq!(SimplePlistReader::find_key_value(xml, "K1").as_deref(), Some("false"));
    assert_eq!(SimplePlistReader::find_key_value(xml, "K2").as_deref(), Some("true"));
}

#[test]
fn t26_simple_plist_read_string_truncated() {
    // tag 0x55 says length 5 but only 2 bytes follow
    let data = &[0x55u8, b'a', b'b'];
    assert!(SimplePlistReader::read_string(data, 0).is_none());
}

#[test]
fn t27_simple_plist_read_string_oob_offset() {
    let data = &[0x53u8];
    assert!(SimplePlistReader::read_string(data, 5).is_none());
}

#[test]
fn t28_simple_plist_read_string_utf16() {
    // 0x61 = UTF-16 tag, length 1 code unit. Then 'A' as UTF-16BE = 0x00, 0x41.
    let data = &[0x61u8, 0x00, 0x41];
    assert_eq!(SimplePlistReader::read_string(data, 0).as_deref(), Some("A"));
}

#[test]
fn t29_simple_plist_fuzz_read_string_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() as usize) % 128 + 1;
        let data = rand_bytes(n, &mut g);
        for off in 0..data.len() {
            let _ = SimplePlistReader::read_string(&data, off);
        }
    }
}

#[test]
fn t30_simple_plist_all_strings_xml() {
    let xml = b"<plist><string>a</string><string>b</string><string>c</string></plist>";
    let s = SimplePlistReader::all_strings(xml);
    assert_eq!(s, vec!["a", "b", "c"]);
}

#[test]
fn t31_simple_plist_fuzz_find_key_value() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 256 + 8;
        let data = rand_bytes(n, &mut g);
        // Must not panic
        let _ = SimplePlistReader::find_key_value(&data, "K");
        let _ = SimplePlistReader::find_key_value(&data, "CFBundleIdentifier");
    }
}

#[test]
fn t32_simple_plist_find_key_empty_key() {
    // Empty key should return None for binary plist path; for XML it's odd but should not panic.
    let bplist = b"bplist00xxxxxxxxxxxxxxxx";
    assert!(SimplePlistReader::find_key_value(bplist, "").is_none());
}

// ---------------------------------------------------------------------------
// InfoPlistFull
// ---------------------------------------------------------------------------

#[test]
fn t33_info_plist_full_empty_xml() {
    let p = InfoPlistFull::from_xml("<plist><dict></dict></plist>").unwrap();
    assert!(p.bundle_id.is_empty());
    assert!(p.url_schemes.is_empty());
    assert!(p.background_modes.is_empty());
}

#[test]
fn t34_info_plist_full_fallback_bundle_version() {
    let xml = r"<plist><dict>
        <key>CFBundleIdentifier</key><string>x</string>
        <key>CFBundleVersion</key><string>9.9</string>
    </dict></plist>";
    let p = InfoPlistFull::from_xml(xml).unwrap();
    assert_eq!(p.bundle_version, "9.9");
}

#[test]
fn t35_info_plist_full_fuzz_xml_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 512;
        let bytes = rand_bytes(n, &mut g);
        // Coerce to valid UTF-8 to call from_xml — Use from_data so it handles both
        let _ = InfoPlistFull::from_data(&bytes);
    }
}

#[test]
fn t36_info_plist_full_serde_50_inputs() {
    for i in 0..50 {
        let xml = format!(
            r#"<plist><dict><key>CFBundleIdentifier</key><string>com.t.{i}</string></dict></plist>"#
        );
        let p = InfoPlistFull::from_xml(&xml).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: InfoPlistFull = serde_json::from_str(&j).unwrap();
        assert_eq!(back.bundle_id, format!("com.t.{i}"));
    }
}

#[test]
fn t37_info_plist_full_from_data_invalid_utf8_no_bplist_magic() {
    let bad: &[u8] = &[0xFF, 0xFE, 0xFD, 0xFC];
    assert!(InfoPlistFull::from_data(bad).is_err());
}

// ---------------------------------------------------------------------------
// Entitlements
// ---------------------------------------------------------------------------

#[test]
fn t38_entitlements_default_is_clean() {
    let e = Entitlements::default();
    assert!(e.application_identifier.is_none());
    assert!(!e.get_task_allow);
    assert!(e.keychain_access_groups.is_empty());
    assert!(e.associated_domains.is_empty());
}

#[test]
fn t39_entitlements_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 512;
        let bytes = rand_bytes(n, &mut g);
        let _ = Entitlements::from_plist(&bytes); // may Err but never panics
    }
}

#[test]
fn t40_entitlements_serde_roundtrip_30() {
    let mut g = lcg();
    for _ in 0..30 {
        let e = Entitlements {
            application_identifier: Some(format!("T.app.{}", g() % 1000)),
            keychain_access_groups: vec![format!("kg{}", g() % 100)],
            team_identifier: Some(format!("TM{}", g() % 100)),
            get_task_allow: g() & 1 == 1,
            aps_environment: Some("development".into()),
            associated_domains: vec!["applinks:x".into()],
        };
        let j = serde_json::to_string(&e).unwrap();
        let back: Entitlements = serde_json::from_str(&j).unwrap();
        assert_eq!(back.application_identifier, e.application_identifier);
        assert_eq!(back.get_task_allow, e.get_task_allow);
    }
}

// ---------------------------------------------------------------------------
// ProvisioningProfile
// ---------------------------------------------------------------------------

#[test]
fn t41_provisioning_profile_no_magic_errs() {
    assert!(ProvisioningProfile::parse_cms(b"no magic").is_err());
    assert!(ProvisioningProfile::parse_cms(&[]).is_err());
}

#[test]
fn t42_provisioning_profile_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 1024;
        let bytes = rand_bytes(n, &mut g);
        let _ = ProvisioningProfile::parse_cms(&bytes);
    }
}

#[test]
fn t43_provisioning_profile_serde_default() {
    let p = ProvisioningProfile::default();
    let j = serde_json::to_string(&p).unwrap();
    let back: ProvisioningProfile = serde_json::from_str(&j).unwrap();
    assert_eq!(back.uuid, "");
    assert!(!back.is_enterprise);
}

// ---------------------------------------------------------------------------
// BplistParser / BplistValue
// ---------------------------------------------------------------------------

#[test]
fn t44_bplist_too_short_errs() {
    for n in 0..32 {
        let d = vec![0u8; n];
        assert!(BplistParser::parse(&d).is_err());
    }
}

#[test]
fn t45_bplist_xml_unknown_value_is_handled() {
    let xml = "<plist><dict><key>X</key><weird>thing</weird></dict></plist>";
    let _ = BplistParser::parse_xml(xml.as_bytes()).unwrap();
}

#[test]
fn t46_bplist_value_eq_consistency() {
    let pairs = vec![
        (BplistValue::Null, BplistValue::Null),
        (BplistValue::Bool(true), BplistValue::Bool(true)),
        (BplistValue::Int(42), BplistValue::Int(42)),
        (BplistValue::String("a".into()), BplistValue::String("a".into())),
        (BplistValue::Uid(7), BplistValue::Uid(7)),
        (BplistValue::Data(vec![1, 2, 3]), BplistValue::Data(vec![1, 2, 3])),
        (BplistValue::Array(vec![BplistValue::Int(1)]), BplistValue::Array(vec![BplistValue::Int(1)])),
    ];
    for (a, b) in &pairs {
        assert_eq!(a, b);
    }
    assert_ne!(BplistValue::Int(1), BplistValue::Int(2));
    assert_ne!(BplistValue::Bool(true), BplistValue::Bool(false));
}

#[test]
fn t47_bplist_serde_roundtrip_array() {
    let v = BplistValue::Array(vec![
        BplistValue::Int(1),
        BplistValue::String("x".into()),
        BplistValue::Bool(false),
    ]);
    let j = serde_json::to_string(&v).unwrap();
    let back: BplistValue = serde_json::from_str(&j).unwrap();
    assert_eq!(back, v);
}

#[test]
fn t48_bplist_parse_any_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 256;
        let bytes = rand_bytes(n, &mut g);
        let _ = BplistParser::parse_any(&bytes);
    }
}

#[test]
fn t49_bplist_parse_binary_invalid_trailer_fuzz() {
    let mut g = lcg();
    for _ in 0..30 {
        let mut bytes = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"bplist00");
        // Random trailer
        let n = bytes.len();
        for i in (n - 32)..n {
            bytes[i] = (g() & 0xFF) as u8;
        }
        let _ = BplistParser::parse(&bytes);
    }
}

#[test]
fn t50_bplist_value_accessors_negative() {
    let n = BplistValue::Null;
    assert!(n.as_bool().is_none());
    assert!(n.as_int().is_none());
    assert!(n.as_real().is_none());
    assert!(n.as_str().is_none());
    assert!(n.get("x").is_none());
}

// ---------------------------------------------------------------------------
// Threaded Send+Sync check on Entitlements & InfoPlistFull
// ---------------------------------------------------------------------------

#[test]
fn t51_send_sync_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let pkg = Arc::new(IpaPackage::mock());
    let mut handles = vec![];
    for _ in 0..4 {
        let p = Arc::clone(&pkg);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for _ in 0..100 {
                acc += p.entry_count();
                acc += p.framework_count();
                let _ = p.has_entitlement("com.apple.developer.team-identifier");
                let _ = p.binary_entries().len();
            }
            acc
        }));
    }
    let mut total = 0usize;
    for h in handles {
        total += h.join().unwrap();
    }
    assert!(total > 0);
}

// ---------------------------------------------------------------------------
// Hash/Eq consistency — InfoPlistFull pair check via Debug strings
// (struct doesn't impl Hash; check field equality)
// ---------------------------------------------------------------------------

#[test]
fn t52_info_plist_full_field_equality_30() {
    for i in 0..30 {
        let xml = format!(
            "<plist><dict><key>CFBundleIdentifier</key><string>id{i}</string></dict></plist>"
        );
        let a = InfoPlistFull::from_xml(&xml).unwrap();
        let b = InfoPlistFull::from_xml(&xml).unwrap();
        assert_eq!(a.bundle_id, b.bundle_id);
        assert_eq!(a.platform, b.platform);
    }
}
