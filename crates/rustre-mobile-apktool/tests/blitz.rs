//! Exhaustive bug-hunting test suite for rustre-mobile-apktool.

use rustre_mobile_apktool::*;
use rustre_mobile_apktool::arsc_value_decoder::*;
use rustre_mobile_apktool::dex_parser::*;
use rustre_mobile_apktool::manifest::*;

// ───── lib.rs: ApktoolConfig / Runner ─────────────────────────────────────────

#[test]
fn config_defaults_off() {
    let c = ApktoolConfig::new("a", "b");
    assert!(!c.no_src && !c.no_res && !c.force);
}

#[test]
fn config_builder_all() {
    let c = ApktoolConfig::new("a", "b").with_no_src().with_no_res().with_force();
    assert!(c.no_src && c.no_res && c.force);
}

#[test]
fn config_roundtrip_json() {
    let c = ApktoolConfig::new("ap", "out").with_no_res();
    let s = serde_json::to_string(&c).unwrap();
    let d: ApktoolConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(d.output_dir, "out");
    assert!(d.no_res);
}

#[test]
fn mock_runner_failure_decode_variant() {
    let r = MockApktoolRunner::failure();
    let cfg = ApktoolConfig::new("a", "b");
    match r.decode("x.apk", &cfg).unwrap_err() {
        ApktoolError::Decode(_) => {}
        e => panic!("expected Decode, got {e:?}"),
    }
}

#[test]
fn runner_impl_decode_apk_case_insensitive() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    // Uppercase .APK should also work per docstring
    assert!(r.decode("APP.APK").is_ok());
}

#[test]
fn runner_impl_decode_rejects_jar() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("app.jar"), Err(ApktoolError::Decode(_))));
}

#[test]
fn runner_impl_install_framework_apk_ok() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(r.install_framework("x.apk").is_ok());
    assert!(r.install_framework("X.APK").is_ok());
}

#[test]
fn runner_impl_install_framework_bad_ext_err() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.install_framework("x.zip"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn decode_result_smali_count_zero() {
    let r = DecodeResult {
        output_dir: String::new(), smali_dirs: vec![], res_dir: None,
        success: false, log: String::new(),
    };
    assert_eq!(r.smali_count(), 0);
}

#[test]
fn apk_decode_result_clean_after_no_warnings() {
    let r = ApkDecodeResult {
        output_dir: "/out".into(), smali_dirs: vec![],
        res_dir: None, manifest_path: None, warnings: vec![],
    };
    assert!(r.is_clean());
}

#[test]
fn error_display_variants() {
    assert!(ApktoolError::NotFound("z".into()).to_string().contains("not found"));
    assert!(ApktoolError::Io("z".into()).to_string().contains("io"));
}

// ───── arsc_value_decoder ─────────────────────────────────────────────────────

fn dec() -> ArscValueDecoder {
    ArscValueDecoder::new(vec!["zero".into(), "one".into()])
}

#[test]
fn datatype_roundtrip_all_known() {
    for (b, expected_name) in [
        (0x00u8, "null"), (0x01, "reference"), (0x02, "attribute"),
        (0x03, "string"), (0x04, "float"), (0x05, "dimension"),
        (0x06, "fraction"), (0x07, "dynamic_reference"),
        (0x10, "int_dec"), (0x11, "int_hex"), (0x12, "boolean"),
        (0x1C, "color_argb8"), (0x1D, "color_rgb8"),
        (0x1E, "color_argb4"), (0x1F, "color_rgb4"),
    ] {
        let dt = DataType::from_u8(b);
        assert_eq!(dt.name(), expected_name, "byte {b:#x}");
        assert_eq!(format!("{dt}"), expected_name);
    }
}

#[test]
fn datatype_is_integer_set() {
    assert!(DataType::IntDec.is_integer());
    assert!(DataType::IntBoolean.is_integer());
    assert!(DataType::IntColorRgb4.is_integer());
    assert!(!DataType::Float.is_integer());
    assert!(!DataType::Null.is_integer());
}

#[test]
fn decode_attribute_format() {
    let v = dec().decode(DataType::Attribute as u8, 0xABCD);
    assert!(v.display.starts_with('?'));
}

#[test]
fn decode_dynamic_ref_format() {
    let v = dec().decode(DataType::DynamicReference as u8, 0x01);
    assert!(v.display.starts_with("@dyn:"));
}

#[test]
fn decode_float_value() {
    let raw = 1.5f32.to_bits();
    let v = dec().decode(DataType::Float as u8, raw);
    assert!(v.display.contains("1.5"));
}

#[test]
fn decode_dimension_dp() {
    // mantissa nonzero, radix 0, unit = DIP (1)
    let raw: u32 = (16u32 << 8) | 1; // 16 * 1 = 16 (radix 0 -> *1)
    let v = dec().decode(DataType::Dimension as u8, raw);
    assert!(v.display.ends_with("dp"), "got {}", v.display);
}

#[test]
fn decode_fraction_percent() {
    let raw: u32 = 1u32 << 8; // not is_parent
    let v = dec().decode(DataType::Fraction as u8, raw);
    assert!(v.display.ends_with('%'));
}

#[test]
fn decode_fraction_parent_percent() {
    let raw: u32 = (1u32 << 8) | 0x01;
    let v = dec().decode(DataType::Fraction as u8, raw);
    assert!(v.display.ends_with("%p"));
}

#[test]
fn decode_int_dec_negative() {
    let v = dec().decode(DataType::IntDec as u8, u32::MAX);
    assert_eq!(v.display, "-1");
    assert_eq!(v.as_int(), Some(-1));
}

#[test]
fn decode_color_rgb8_masks_alpha() {
    let v = dec().decode(DataType::IntColorRgb8 as u8, 0xFFAA_BBCC);
    assert_eq!(v.display, "#AABBCC");
}

#[test]
fn decode_color_argb4_format() {
    let v = dec().decode(DataType::IntColorArgb4 as u8, 0x1234);
    assert_eq!(v.display, "#1234");
}

#[test]
fn decode_color_rgb4_format() {
    let v = dec().decode(DataType::IntColorRgb4 as u8, 0x0123);
    assert_eq!(v.display, "#123");
}

#[test]
fn decode_unknown_byte_value() {
    let v = dec().decode(0xAB, 7);
    assert!(v.display.starts_with("0x"));
    assert_eq!(v.data_type, DataType::Unknown);
}

#[test]
fn as_bool_only_for_boolean() {
    assert!(dec().decode(DataType::IntBoolean as u8, 1).as_bool() == Some(true));
    assert!(dec().decode(DataType::IntDec as u8, 1).as_bool().is_none());
}

#[test]
fn as_string_index_only_for_string() {
    assert_eq!(dec().decode(DataType::String as u8, 5).as_string_index(), Some(5));
    assert!(dec().decode(DataType::IntDec as u8, 5).as_string_index().is_none());
}

#[test]
fn as_int_only_for_int_types() {
    assert!(dec().decode(DataType::Float as u8, 0).as_int().is_none());
    assert_eq!(dec().decode(DataType::IntHex as u8, 7).as_int(), Some(7));
}

#[test]
fn decode_bytes_too_short() {
    let d = dec();
    assert!(d.decode_bytes(&[0u8; 7], 0).is_none());
}

#[test]
fn decode_bytes_at_offset() {
    let d = dec();
    let mut buf = vec![0u8; 16];
    // res_value at offset 4: dataType byte at off+3 = idx 7, data 4 bytes from 8..12
    buf[7] = DataType::IntDec as u8;
    buf[8..12].copy_from_slice(&42u32.to_le_bytes());
    let v = d.decode_bytes(&buf, 4).unwrap();
    assert_eq!(v.display, "42");
}

#[test]
fn resource_id_decompose_roundtrip() {
    let id = ArscValueDecoder::decode_resource_id(0x7F0A_0001);
    assert_eq!(id.package, 0x7F);
    assert_eq!(id.type_id, 0x0A);
    assert_eq!(id.entry, 0x0001);
    assert_eq!(id.raw, 0x7F0A_0001);
}

#[test]
fn resource_id_display() {
    let id = ArscValueDecoder::decode_resource_id(0x7F0A_0001);
    assert_eq!(format!("{id}"), "@7F0A0001");
}

#[test]
fn decode_attr_value_min_size() {
    // 20 bytes minimum. dataType byte is at offset+15, data at offset+16..20.
    let mut buf = vec![0u8; 20];
    buf[15] = DataType::IntDec as u8;
    buf[16..20].copy_from_slice(&7u32.to_le_bytes());
    let v = decode_attr_value(&buf, 0, &[]).unwrap();
    assert_eq!(v.display, "7");
}

#[test]
fn decode_attr_list_multi() {
    let mut buf = vec![0u8; 40];
    buf[15] = DataType::IntDec as u8;
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    buf[35] = DataType::IntBoolean as u8;
    buf[36..40].copy_from_slice(&1u32.to_le_bytes());
    let list = decode_attr_list(&buf, &[]);
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].display, "1");
    assert_eq!(list[1].display, "true");
}

#[test]
fn color_components_extract() {
    let c = ColorComponents::from_argb8(0x12_34_56_78);
    assert_eq!(c.alpha, 0x12);
    assert_eq!(c.red, 0x34);
    assert_eq!(c.green, 0x56);
    assert_eq!(c.blue, 0x78);
    assert!(!c.is_opaque());
}

#[test]
fn color_components_css_rgba_format() {
    let c = ColorComponents { alpha: 0xFF, red: 0x10, green: 0x20, blue: 0x30 };
    let s = c.to_css_rgba();
    assert!(s.starts_with("rgba("));
    assert!(s.contains("16,32,48"));
}

#[test]
fn decoder_default_empty_pool() {
    let d = ArscValueDecoder::default();
    let v = d.decode(DataType::String as u8, 0);
    assert!(v.display.starts_with("@string/"));
}

// ───── dex_parser ─────────────────────────────────────────────────────────────

#[test]
fn dex_check_magic_classic() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"dex\n");
    assert!(DexParser::new(data).check_magic());
}

#[test]
fn dex_check_magic_cdex() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(b"cdex");
    assert!(DexParser::new(data).check_magic());
}

#[test]
fn dex_check_magic_bad() {
    let data = vec![0u8; 16];
    assert!(!DexParser::new(data).check_magic());
}

#[test]
fn parse_dex_rejects_nonmagic() {
    let data = vec![0u8; 200];
    assert!(parse_dex(data).is_err());
}

#[test]
fn dex_class_entry_flags() {
    let e = DexClassEntry {
        name: String::new(), superclass: String::new(),
        access_flags: 0x0001 | 0x0200,
        source_file: None, methods: vec![], fields: vec![],
    };
    assert!(e.is_public());
    assert!(e.is_interface());
    assert!(!e.is_abstract());
}

#[test]
fn disassemble_dalvik_empty() {
    let out = disassemble_dalvik(&[]);
    assert!(out.is_empty());
}

#[test]
fn disassemble_dalvik_nop() {
    let out = disassemble_dalvik(&[0x0000]); // opcode 0x00 = nop
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "nop");
    assert_eq!(out[0].length, 1);
}

#[test]
fn disassemble_dalvik_return_void() {
    let out = disassemble_dalvik(&[0x000E]);
    assert_eq!(out[0].mnemonic, "return-void");
}

#[test]
fn disassemble_dalvik_unknown_op_still_makes_progress() {
    // 0xFF is not in the table — opcode -> hex string, length 1
    let out = disassemble_dalvik(&[0x00FF, 0x00FF, 0x00FF]);
    assert_eq!(out.len(), 3);
}

#[test]
fn disassemble_dalvik_multi_word_const() {
    // const opcode 0x14 → length 3. Provide 3 words.
    let out = disassemble_dalvik(&[0x0014, 0xCAFE, 0xBABE]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].mnemonic, "const");
    assert_eq!(out[0].length, 3);
}

#[test]
fn disassemble_dalvik_offsets_track() {
    let out = disassemble_dalvik(&[0x0000, 0x0000, 0x0000]);
    assert_eq!(out[0].offset, 0);
    assert_eq!(out[1].offset, 2);
    assert_eq!(out[2].offset, 4);
}

#[test]
fn disassemble_dalvik_handles_truncated_multi_word() {
    // op 0x14 wants 3 words but only 1 provided — must not panic.
    let out = disassemble_dalvik(&[0x0014]);
    assert!(!out.is_empty());
}

// ───── manifest module ────────────────────────────────────────────────────────

#[test]
fn intent_filter_is_launcher() {
    let f = IntentFilter {
        actions: vec!["android.intent.action.MAIN".into()],
        categories: vec!["android.intent.category.LAUNCHER".into()],
        ..Default::default()
    };
    assert!(f.is_launcher());
}

#[test]
fn intent_filter_not_launcher_missing_category() {
    let f = IntentFilter {
        actions: vec!["android.intent.action.MAIN".into()],
        ..Default::default()
    };
    assert!(!f.is_launcher());
}

#[test]
fn component_effective_export_explicit_true() {
    let mut c = ComponentInfo::new("c");
    c.exported = Some(true);
    assert!(c.is_effectively_exported());
}

#[test]
fn component_effective_export_explicit_false_with_filter() {
    let mut c = ComponentInfo::new("c");
    c.exported = Some(false);
    c.intent_filters.push(IntentFilter::default());
    assert!(!c.is_effectively_exported(), "explicit false must win over filter");
}

#[test]
fn component_effective_export_none_no_filter() {
    let c = ComponentInfo::new("c");
    assert!(!c.is_effectively_exported());
}

#[test]
fn component_effective_export_none_with_filter() {
    let mut c = ComponentInfo::new("c");
    c.intent_filters.push(IntentFilter::default());
    assert!(c.is_effectively_exported());
}

#[test]
fn manifest_default_sane() {
    let m = AndroidManifest::default();
    assert!(m.allow_backup);
    assert!(!m.debuggable);
    assert_eq!(m.min_sdk, 1);
    assert_eq!(m.component_count(), 0);
}

#[test]
fn manifest_dangerous_permissions_picks_known() {
    let mut m = AndroidManifest::default();
    m.permissions.push(UsesPermission {
        name: "android.permission.CAMERA".into(), max_sdk: None,
    });
    m.permissions.push(UsesPermission {
        name: "android.permission.INTERNET".into(), max_sdk: None,
    });
    let d = m.dangerous_permissions();
    assert_eq!(d, vec!["android.permission.CAMERA"]);
}

#[test]
fn manifest_exported_activities_filter() {
    let mut m = AndroidManifest::default();
    let mut a1 = ActivityInfo::new("A1");
    a1.base.exported = Some(true);
    let a2 = ActivityInfo::new("A2"); // default not exported
    m.activities.push(a1);
    m.activities.push(a2);
    assert_eq!(m.exported_activities().len(), 1);
}

#[test]
fn manifest_component_count_sums() {
    let mut m = AndroidManifest::default();
    m.activities.push(ActivityInfo::new("a"));
    m.services.push(ServiceInfo::new("s"));
    m.receivers.push(ReceiverInfo::new("r"));
    m.providers.push(ProviderInfo::new("p", "auth"));
    assert_eq!(m.component_count(), 4);
}

#[test]
fn provider_info_defaults() {
    let p = ProviderInfo::new("p", "com.example.auth");
    assert_eq!(p.authorities, "com.example.auth");
    assert!(!p.grant_uri_permissions);
    assert!(p.read_permission.is_none());
}

#[test]
fn activity_info_default_launch_mode() {
    let a = ActivityInfo::new("X");
    assert_eq!(a.launch_mode, "standard");
}

#[test]
fn axml_value_as_str_string_only() {
    assert_eq!(AxmlValue::String("hi".into()).as_str(), Some("hi"));
    assert!(AxmlValue::Int(1).as_str().is_none());
}

#[test]
fn axml_value_as_int_includes_bool() {
    assert_eq!(AxmlValue::Bool(true).as_int(), Some(1));
    assert_eq!(AxmlValue::Bool(false).as_int(), Some(0));
    assert_eq!(AxmlValue::Int(42).as_int(), Some(42));
    assert!(AxmlValue::Null.as_int().is_none());
}

#[test]
fn axml_value_as_bool_int_nonzero() {
    assert_eq!(AxmlValue::Int(0).as_bool(), Some(false));
    assert_eq!(AxmlValue::Int(5).as_bool(), Some(true));
    assert_eq!(AxmlValue::Bool(true).as_bool(), Some(true));
    assert!(AxmlValue::Null.as_bool().is_none());
}

#[test]
fn axml_parser_too_short() {
    let r = AxmlParser::new(vec![0u8; 4]);
    assert!(matches!(r, Err(ManifestError::Truncated)));
}

#[test]
fn axml_parser_no_string_pool_ok_empty() {
    // 8 bytes header with non-string-pool chunk type → parser succeeds with empty pool.
    let mut data = vec![0u8; 8];
    data[0..2].copy_from_slice(&0x0003u16.to_le_bytes()); // XML chunk header
    data[4..8].copy_from_slice(&8u32.to_le_bytes());
    let p = AxmlParser::new(data).unwrap();
    assert_eq!(p.get_string(0), "");
    assert_eq!(p.get_string(999), "");
}

#[test]
fn manifest_error_display() {
    assert!(ManifestError::InvalidMagic.to_string().contains("magic"));
    assert!(ManifestError::Truncated.to_string().contains("truncated"));
    assert!(ManifestError::Utf8Error.to_string().contains("UTF"));
    assert!(ManifestError::ParseError("x".into()).to_string().contains('x'));
}

#[test]
fn manifest_error_eq() {
    assert_eq!(ManifestError::InvalidMagic, ManifestError::InvalidMagic);
    assert_ne!(ManifestError::InvalidMagic, ManifestError::Truncated);
}

// ───── Aggressive edge cases / bug hunting ────────────────────────────────────

/// `runner_impl.decode` strips trailing ".apk" via `trim_end_matches` which
/// strips *any combination* of the chars, not the literal suffix. Probing.
#[test]
fn runner_impl_decode_basename_no_double_strip() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    let res = r.decode("/path/myapp.apk").unwrap();
    // expected: /out/myapp
    assert!(res.output_dir.ends_with("/myapp"), "got {}", res.output_dir);
}

/// `trim_end_matches` takes a *set of chars* with a char slice arg, but here
/// it's a &str — it strips the literal suffix. Still, names ending in just
/// "k" or "pk" could be a trap. Validate.
#[test]
fn runner_impl_decode_name_ending_in_pk() {
    let cfg = ApktoolConfig::new("ap", "/out");
    let r = ApktoolRunnerImpl::new(cfg);
    // The path itself must end in .apk to pass the extension check; we
    // verify here that the basename trim only removes the literal .apk.
    let res = r.decode("/path/quickpick.apk").unwrap();
    assert!(res.output_dir.ends_with("/quickpick"), "got {}", res.output_dir);
}

/// Disassembler with 0-length opcode could spin — but length is forced
/// to max(1). Verify forward progress on op 0x00 with a single word.
#[test]
fn disassemble_dalvik_single_word_forward_progress() {
    let words: Vec<u16> = (0..16).collect();
    let out = disassemble_dalvik(&words);
    // each op is the index value (0..15); decoded as ops, but at minimum
    // we should not loop forever and must produce >0 results.
    assert!(!out.is_empty());
    // last decoded offset must be < 32 bytes (16 words * 2)
    assert!(out.last().unwrap().offset < 32);
}

/// `ColorComponents` { 0xFF, .. } must be opaque.
#[test]
fn color_components_opaque_true() {
    let c = ColorComponents { alpha: 0xFF, red: 0, green: 0, blue: 0 };
    assert!(c.is_opaque());
}

/// `AxmlValue::Float` should have no int conversion.
#[test]
fn axml_value_float_as_int_none() {
    assert!(AxmlValue::Float(1.5).as_int().is_none());
}

/// Resource ID round-trip across full u32 range edges.
#[test]
fn resource_id_edges() {
    let max = ArscValueDecoder::decode_resource_id(u32::MAX);
    assert_eq!(max.package, 0xFF);
    assert_eq!(max.type_id, 0xFF);
    assert_eq!(max.entry, 0xFFFF);
    let zero = ArscValueDecoder::decode_resource_id(0);
    assert_eq!(zero.raw, 0);
    assert!(!zero.is_app() && !zero.is_framework());
}

/// `DexParser::read_string` returns empty when `string_ids_off` + idx*4 is OOB.
#[test]
fn dex_read_string_oob_returns_empty() {
    let p = DexParser::new(vec![0u8; 8]);
    assert_eq!(p.read_string(0, 100), "");
}

/// `decode_attr_list` with odd-length buffer drops the tail.
#[test]
fn decode_attr_list_truncated_tail() {
    // 25 bytes — only first 20 are a complete attr.
    let mut buf = vec![0u8; 25];
    buf[15] = DataType::IntDec as u8;
    buf[16..20].copy_from_slice(&9u32.to_le_bytes());
    let list = decode_attr_list(&buf, &[]);
    assert_eq!(list.len(), 1);
}
