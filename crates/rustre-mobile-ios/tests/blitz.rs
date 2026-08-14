//! Integration tests for the public API of `rustre-mobile-ios`.

use rustre_mobile_ios::{
    BundleInfo, CodeSignature, DebugSymbolStatus, Entitlement, EntitlementValue, IosAppInfo,
    IosAppInfoExtractor, IosClassDumper, IosError, IosFramework, IosPlatform, IosSecurityChecker,
    IpaBundle, IpaInfo, ObjcClass, ObjcIvar, ObjcMethod, ObjcProperty, SwiftDemangler,
    decode_type_encoding, scan_objc_classes, scan_objc_selectors,
};

// ─── IosPlatform Display ──────────────────────────────────────────────────────

#[test]
fn ios_platform_display_all_variants() {
    assert_eq!(IosPlatform::IphoneOs.to_string(), "iphoneos");
    assert_eq!(IosPlatform::MacOs.to_string(), "macos");
    assert_eq!(IosPlatform::TvOs.to_string(), "tvos");
    assert_eq!(IosPlatform::WatchOs.to_string(), "watchos");
    assert_eq!(IosPlatform::VisionOs.to_string(), "visionos");
}

#[test]
fn ios_platform_equality_and_clone() {
    let a = IosPlatform::IphoneOs;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(IosPlatform::IphoneOs, IosPlatform::MacOs);
}

#[test]
fn ios_platform_serde_roundtrip() {
    let p = IosPlatform::VisionOs;
    let j = serde_json::to_string(&p).unwrap();
    let back: IosPlatform = serde_json::from_str(&j).unwrap();
    assert_eq!(p, back);
}

// ─── EntitlementValue Display ─────────────────────────────────────────────────

#[test]
fn entitlement_value_display_bool() {
    assert_eq!(EntitlementValue::Bool(true).to_string(), "true");
    assert_eq!(EntitlementValue::Bool(false).to_string(), "false");
}

#[test]
fn entitlement_value_display_str() {
    assert_eq!(EntitlementValue::Str("abc".into()).to_string(), "abc");
}

#[test]
fn entitlement_value_display_array_empty() {
    assert_eq!(EntitlementValue::Array(vec![]).to_string(), "[]");
}

#[test]
fn entitlement_value_display_array_multi() {
    let v = EntitlementValue::Array(vec!["x".into(), "y".into(), "z".into()]);
    assert_eq!(v.to_string(), "[x, y, z]");
}

#[test]
fn entitlement_value_equality() {
    assert_eq!(EntitlementValue::Bool(true), EntitlementValue::Bool(true));
    assert_ne!(EntitlementValue::Bool(true), EntitlementValue::Bool(false));
}

// ─── CodeSignature ────────────────────────────────────────────────────────────

fn make_sig() -> CodeSignature {
    CodeSignature {
        team_id: "TEAM".into(),
        signing_id: "id".into(),
        entitlements: vec![
            Entitlement {
                key: "k1".into(),
                value: EntitlementValue::Bool(true),
            },
            Entitlement {
                key: "k2".into(),
                value: EntitlementValue::Str("v2".into()),
            },
        ],
    }
}

#[test]
fn code_signature_has_present() {
    assert!(make_sig().has("k1"));
    assert!(make_sig().has("k2"));
}

#[test]
fn code_signature_has_absent() {
    assert!(!make_sig().has("missing"));
}

#[test]
fn code_signature_get_value() {
    let sig = make_sig();
    assert_eq!(sig.get("k1"), Some(&EntitlementValue::Bool(true)));
    assert_eq!(sig.get("k2"), Some(&EntitlementValue::Str("v2".into())));
    assert_eq!(sig.get("none"), None);
}

#[test]
fn code_signature_empty() {
    let sig = CodeSignature {
        team_id: "T".into(),
        signing_id: "i".into(),
        entitlements: vec![],
    };
    assert!(!sig.has("anything"));
    assert!(sig.get("anything").is_none());
}

// ─── IpaBundle ────────────────────────────────────────────────────────────────

#[test]
fn ipa_bundle_mock_fields() {
    let b = IpaBundle::mock();
    assert_eq!(b.info.bundle_id, "com.example.App");
    assert_eq!(b.info.name, "ExampleApp");
    assert_eq!(b.info.version, "1.0.0");
    assert_eq!(b.info.platform, IosPlatform::IphoneOs);
    assert_eq!(b.executable, "ExampleApp");
}

#[test]
fn ipa_bundle_framework_count_mock() {
    assert_eq!(IpaBundle::mock().framework_count(), 3);
}

#[test]
fn ipa_bundle_framework_count_after_clear() {
    let mut b = IpaBundle::mock();
    b.frameworks.clear();
    assert_eq!(b.framework_count(), 0);
}

#[test]
fn ipa_bundle_is_debuggable_default_false() {
    assert!(!IpaBundle::mock().is_debuggable());
}

#[test]
fn ipa_bundle_is_debuggable_when_true() {
    let mut b = IpaBundle::mock();
    if let Some(sig) = &mut b.signature {
        for e in &mut sig.entitlements {
            if e.key == "get-task-allow" {
                e.value = EntitlementValue::Bool(true);
            }
        }
    }
    assert!(b.is_debuggable());
}

#[test]
fn ipa_bundle_is_debuggable_no_signature() {
    let mut b = IpaBundle::mock();
    b.signature = None;
    assert!(!b.is_debuggable());
}

#[test]
fn ipa_bundle_system_frameworks_filters() {
    let b = IpaBundle::mock();
    let sys = b.system_frameworks();
    assert_eq!(sys.len(), 2);
    assert!(sys.iter().all(|f| f.is_system));
}

#[test]
fn ipa_bundle_serde_roundtrip() {
    let b = IpaBundle::mock();
    let j = serde_json::to_string(&b).unwrap();
    let back: IpaBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(back.info.bundle_id, b.info.bundle_id);
    assert_eq!(back.frameworks.len(), b.frameworks.len());
}

// ─── IosError Display ─────────────────────────────────────────────────────────

#[test]
fn ios_error_display_variants() {
    assert!(IosError::ParseError("p".into()).to_string().contains('p'));
    assert!(IosError::MissingInfo("m".into()).to_string().contains('m'));
    assert!(IosError::InvalidBundle("i".into()).to_string().contains('i'));
    assert!(IosError::Io("io".into()).to_string().contains("io"));
    assert!(IosError::CodeSign("c".into()).to_string().contains('c'));
    assert!(IosError::Plist("pl".into()).to_string().contains("pl"));
}

// ─── ObjcClass ────────────────────────────────────────────────────────────────

fn sample_objc_class() -> ObjcClass {
    ObjcClass {
        name: "Foo".into(),
        superclass: Some("NSObject".into()),
        protocols: vec!["NSCopying".into()],
        instance_methods: vec![ObjcMethod {
            name: "doIt".into(),
            type_encoding: "v@:".into(),
            imp_addr: 0x1000,
        }],
        class_methods: vec![ObjcMethod {
            name: "alloc".into(),
            type_encoding: "@@:".into(),
            imp_addr: 0x2000,
        }],
        ivars: vec![ObjcIvar {
            name: "_x".into(),
            type_encoding: "i".into(),
            offset: 8,
            size: 4,
        }],
        properties: vec![ObjcProperty {
            name: "x".into(),
            attributes: "Ti,N".into(),
        }],
    }
}

#[test]
fn objc_class_method_counts() {
    let c = sample_objc_class();
    assert_eq!(c.total_method_count(), 2);
}

#[test]
fn objc_class_method_count_empty() {
    let mut c = sample_objc_class();
    c.instance_methods.clear();
    c.class_methods.clear();
    assert_eq!(c.total_method_count(), 0);
}

#[test]
fn objc_class_adopts_protocol() {
    let c = sample_objc_class();
    assert!(c.adopts_protocol("NSCopying"));
    assert!(!c.adopts_protocol("NSCoding"));
}

#[test]
fn objc_class_find_methods() {
    let c = sample_objc_class();
    assert_eq!(c.find_instance_method("doIt").unwrap().imp_addr, 0x1000);
    assert!(c.find_instance_method("missing").is_none());
    assert_eq!(c.find_class_method("alloc").unwrap().imp_addr, 0x2000);
    assert!(c.find_class_method("missing").is_none());
}

#[test]
fn objc_method_ivar_property_equality() {
    let m1 = ObjcMethod {
        name: "a".into(),
        type_encoding: "v".into(),
        imp_addr: 1,
    };
    let m2 = m1.clone();
    assert_eq!(m1, m2);

    let i1 = ObjcIvar {
        name: "x".into(),
        type_encoding: "i".into(),
        offset: 0,
        size: 4,
    };
    assert_eq!(i1, i1.clone());

    let p1 = ObjcProperty {
        name: "p".into(),
        attributes: "T".into(),
    };
    assert_eq!(p1, p1.clone());
}

// ─── decode_type_encoding ─────────────────────────────────────────────────────

#[test]
fn decode_basic_triplet() {
    assert_eq!(decode_type_encoding("@:I"), ["id", "SEL", "unsigned int"]);
}

#[test]
fn decode_primitives() {
    assert_eq!(
        decode_type_encoding("vcisql"),
        ["void", "char", "int", "short", "long long", "long"]
    );
}

#[test]
fn decode_unsigned_and_float() {
    assert_eq!(
        decode_type_encoding("CISLQfdB"),
        [
            "unsigned char",
            "unsigned int",
            "unsigned short",
            "unsigned long",
            "unsigned long long",
            "float",
            "double",
            "bool"
        ]
    );
}

#[test]
fn decode_class_and_cstring() {
    assert_eq!(decode_type_encoding("#"), ["Class"]);
    assert_eq!(decode_type_encoding("*"), ["char*"]);
}

#[test]
fn decode_pointer_recurses() {
    assert_eq!(decode_type_encoding("^^i"), ["**int"]);
}

#[test]
fn decode_array() {
    let r = decode_type_encoding("[10i]");
    assert_eq!(r[0], "int[10]");
}

#[test]
fn decode_struct_named() {
    let r = decode_type_encoding("{CGRect=dddd}");
    assert_eq!(r[0], "struct CGRect");
}

#[test]
fn decode_union_named() {
    let r = decode_type_encoding("(u=i)");
    assert_eq!(r[0], "union u");
}

#[test]
fn decode_object_with_classname() {
    let r = decode_type_encoding("@\"NSString\"");
    assert_eq!(r[0], "id<NSString>");
}

#[test]
fn decode_qualifiers_consumed() {
    // 'r' qualifier then 'i' int
    let r = decode_type_encoding("ri");
    assert_eq!(r, ["int"]);
}

#[test]
fn decode_func_ptr() {
    let r = decode_type_encoding("?");
    assert_eq!(r, ["func_ptr"]);
}

#[test]
fn decode_empty_input() {
    let r = decode_type_encoding("");
    assert!(r.is_empty());
}

// ─── SwiftDemangler ───────────────────────────────────────────────────────────

#[test]
fn swift_is_mangled_recognises_prefixes() {
    assert!(SwiftDemangler::is_swift_mangled("_$sSS"));
    assert!(SwiftDemangler::is_swift_mangled("_$SAnything"));
    assert!(!SwiftDemangler::is_swift_mangled("_OBJC_CLASS_$_NSObject"));
    assert!(!SwiftDemangler::is_swift_mangled(""));
}

#[test]
fn swift_demangle_returns_none_for_non_swift() {
    assert!(SwiftDemangler::demangle("plain_c_symbol").is_none());
}

#[test]
fn swift_demangle_stdlib_types() {
    assert_eq!(
        SwiftDemangler::demangle("_$sSS").as_deref(),
        Some("Swift.String")
    );
    assert_eq!(
        SwiftDemangler::demangle("_$sSi").as_deref(),
        Some("Swift.Int")
    );
    assert_eq!(
        SwiftDemangler::demangle("_$sSb").as_deref(),
        Some("Swift.Bool")
    );
    assert_eq!(
        SwiftDemangler::demangle("_$sSf").as_deref(),
        Some("Swift.Float")
    );
    assert_eq!(
        SwiftDemangler::demangle("_$sSd").as_deref(),
        Some("Swift.Double")
    );
    assert_eq!(
        SwiftDemangler::demangle("_$sSu").as_deref(),
        Some("Swift.UInt")
    );
}

#[test]
fn swift_demangle_function_suffix() {
    assert_eq!(
        SwiftDemangler::demangle("_$s3FooyyF").as_deref(),
        Some("() -> ()")
    );
}

#[test]
fn swift_demangle_length_prefixed() {
    // _$s3Foo3Bar should decode via length-prefix or class-suffix logic
    let r = SwiftDemangler::demangle("_$s3Foo3Bar");
    assert!(r.is_some());
}

// ─── DebugSymbolStatus ────────────────────────────────────────────────────────

#[test]
fn debug_symbol_status_from_bool() {
    assert_eq!(DebugSymbolStatus::from_bool(true), DebugSymbolStatus::Present);
    assert_eq!(DebugSymbolStatus::from_bool(false), DebugSymbolStatus::Absent);
}

#[test]
fn debug_symbol_status_is_present() {
    assert!(DebugSymbolStatus::Present.is_present());
    assert!(!DebugSymbolStatus::Absent.is_present());
}

#[test]
fn debug_symbol_status_display() {
    assert_eq!(DebugSymbolStatus::Present.to_string(), "true");
    assert_eq!(DebugSymbolStatus::Absent.to_string(), "false");
}

#[test]
fn debug_symbol_status_equality_and_copy() {
    let a = DebugSymbolStatus::Present;
    let b = a; // Copy
    assert_eq!(a, b);
}

// ─── Mach-O scanners on invalid input ─────────────────────────────────────────

#[test]
fn scan_objc_selectors_on_garbage_returns_empty() {
    assert!(scan_objc_selectors(&[0u8; 16]).is_empty());
    assert!(scan_objc_selectors(b"not a macho").is_empty());
}

#[test]
fn scan_objc_classes_on_garbage_returns_empty() {
    assert!(scan_objc_classes(&[0u8; 16]).is_empty());
    assert!(scan_objc_classes(b"not a macho").is_empty());
}

#[test]
fn class_dumper_on_garbage_returns_empty() {
    assert!(IosClassDumper::extract_objc_classes(&[0u8; 32]).is_empty());
    assert!(IosClassDumper::extract_swift_types(&[0u8; 32]).is_empty());
}

#[test]
fn security_checker_on_garbage() {
    let bytes = [0u8; 32];
    assert!(!IosSecurityChecker::check_arc_usage(&bytes));
    assert!(!IosSecurityChecker::check_pie_enabled(&bytes));
    assert!(!IosSecurityChecker::check_stack_canary(&bytes));
    assert!(!IosSecurityChecker::check_debug_symbols(&bytes));
    let r = IosSecurityChecker::report(&bytes);
    assert!(!r.arc);
    assert!(!r.pie);
    assert!(!r.stack_canary);
    assert_eq!(r.has_debug_symbols, DebugSymbolStatus::Absent);
    let r2 = IosSecurityChecker::full_report(&bytes);
    assert_eq!(r2.arc, r.arc);
}

#[test]
fn ipa_info_from_garbage_macho() {
    let info = IpaInfo::from_macho(&[0u8; 64]);
    assert_eq!(info.bundle_id, "unknown");
    assert_eq!(info.version, "unknown");
    assert_eq!(info.min_os, "unknown");
    assert_eq!(info.class_count, 0);
    assert_eq!(info.method_count, 0);
    assert_eq!(info.swift_class_count, 0);
    assert!(info.entitlements.is_empty());
    assert!(!info.has_bitcode);
    assert!(info.architectures.is_empty());
}

// ─── IosAppInfoExtractor ──────────────────────────────────────────────────────

#[test]
fn extract_app_info_on_garbage_zip_returns_none() {
    assert!(IosAppInfoExtractor::extract_app_info(&[0u8; 32]).is_none());
}

#[test]
fn parse_xml_plist_extracts_fields() {
    let xml = r#"<?xml version="1.0"?>
<plist><dict>
<key>CFBundleIdentifier</key><string>com.test.app</string>
<key>CFBundleShortVersionString</key><string>2.3.4</string>
<key>MinimumOSVersion</key><string>15.0</string>
<key>NSCameraUsageDescription</key><string>need camera</string>
</dict></plist>"#;
    let info = IosAppInfoExtractor::parse_plist(xml.as_bytes()).unwrap();
    assert_eq!(info.bundle_id, "com.test.app");
    assert_eq!(info.version, "2.3.4");
    assert_eq!(info.min_ios, "15.0");
    assert!(info.permissions.iter().any(|p| p == "NSCameraUsageDescription"));
}

#[test]
fn parse_plist_falls_back_to_bundle_version() {
    let xml = r#"<?xml version="1.0"?>
<plist><dict>
<key>CFBundleIdentifier</key><string>com.x</string>
<key>CFBundleVersion</key><string>9</string>
</dict></plist>"#;
    let info = IosAppInfoExtractor::parse_plist(xml.as_bytes()).unwrap();
    assert_eq!(info.version, "9");
    assert_eq!(info.min_ios, "unknown");
}

#[test]
fn parse_plist_unknown_when_missing() {
    let info = IosAppInfoExtractor::parse_plist(b"<plist></plist>").unwrap();
    assert_eq!(info.bundle_id, "unknown");
    assert_eq!(info.version, "unknown");
    assert_eq!(info.min_ios, "unknown");
    assert!(info.permissions.is_empty());
}

#[test]
fn parse_plist_invalid_utf8_returns_none() {
    let bad = [0xFFu8, 0xFE, 0xFD, 0xFC];
    assert!(IosAppInfoExtractor::parse_plist(&bad).is_none());
}

#[test]
fn parse_binary_plist_prefix() {
    let mut data: Vec<u8> = b"bplist00".to_vec();
    data.extend_from_slice(b"CFBundleIdentifier\x00com.bin.app\x00");
    let info = IosAppInfoExtractor::parse_plist(&data).unwrap();
    // Heuristic scanner — may or may not parse but should not panic.
    let _ = info;
}

// ─── Send + Sync bounds ───────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<IpaBundle>();
    assert_send_sync::<BundleInfo>();
    assert_send_sync::<CodeSignature>();
    assert_send_sync::<Entitlement>();
    assert_send_sync::<EntitlementValue>();
    assert_send_sync::<IosFramework>();
    assert_send_sync::<IosPlatform>();
    assert_send_sync::<IosError>();
    assert_send_sync::<ObjcClass>();
    assert_send_sync::<IpaInfo>();
    assert_send_sync::<IosAppInfo>();
    assert_send_sync::<DebugSymbolStatus>();
}
