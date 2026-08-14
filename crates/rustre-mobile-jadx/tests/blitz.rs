//! Exhaustive integration tests for rustre-mobile-jadx public API.
//! Tests are designed to surface bugs; assertions are strict.

use rustre_mobile_jadx::*;
use std::collections::HashMap;

// ── JadxConfig (legacy) ─────────────────────────────────────────────────────

#[test]
fn cfg_new_defaults() {
    let c = JadxConfig::new("jadx", "a.apk", "/out");
    assert_eq!(c.threads, 4);
    assert!(!c.deobfuscate);
}

#[test]
fn cfg_with_threads_zero() {
    let c = JadxConfig::new("j", "a", "o").with_threads(0);
    assert_eq!(c.threads, 0);
}

#[test]
fn cfg_with_threads_max() {
    let c = JadxConfig::new("j", "a", "o").with_threads(u32::MAX);
    assert_eq!(c.threads, u32::MAX);
}

#[test]
fn cfg_with_deobf_flips() {
    let c = JadxConfig::new("j", "a", "o").with_deobfuscate();
    assert!(c.deobfuscate);
}

#[test]
fn cfg_serde_roundtrip_preserves_all_fields() {
    let c = JadxConfig::new("jadx", "input.apk", "/tmp/o")
        .with_threads(7)
        .with_deobfuscate();
    let j = serde_json::to_string(&c).unwrap();
    let d: JadxConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(d.jadx_path, "jadx");
    assert_eq!(d.input, "input.apk");
    assert_eq!(d.output_dir, "/tmp/o");
    assert_eq!(d.threads, 7);
    assert!(d.deobfuscate);
}

// ── JavaMethod / JavaClass ─────────────────────────────────────────────────

#[test]
fn jm_constructor_init() {
    let m = JavaMethod {
        name: "<init>".into(),
        signature: String::new(),
        return_type: "void".into(),
        params: vec![],
        body: String::new(),
        is_static: false,
        is_native: false,
    };
    assert!(m.is_constructor());
}

#[test]
fn jm_constructor_name_constructor() {
    let m = JavaMethod {
        name: "constructor".into(),
        signature: String::new(),
        return_type: "void".into(),
        params: vec![],
        body: String::new(),
        is_static: false,
        is_native: false,
    };
    assert!(m.is_constructor());
}

#[test]
fn jm_clinit_not_constructor() {
    let m = JavaMethod {
        name: "<clinit>".into(),
        signature: String::new(),
        return_type: "void".into(),
        params: vec![],
        body: String::new(),
        is_static: true,
        is_native: false,
    };
    // <clinit> is the static initializer, NOT a constructor per this API.
    assert!(!m.is_constructor());
}

// ── DecompiledProject ───────────────────────────────────────────────────────

#[test]
fn dp_mock_invariants() {
    let p = DecompiledProject::mock();
    assert_eq!(p.classes.len(), 9);
    assert_eq!(p.total, p.classes.len());
    assert_eq!(p.failed, 0);
}

#[test]
fn dp_find_by_simple_and_fqn() {
    let p = DecompiledProject::mock();
    assert!(p.find_class("MainActivity").is_some());
    assert!(p.find_class("com.example.app.MainActivity").is_some());
    assert!(p.find_class("nope").is_none());
    assert!(p.find_class("").is_none());
}

#[test]
fn dp_in_package_exact_match() {
    let p = DecompiledProject::mock();
    assert_eq!(p.in_package("com.example.app").len(), 3);
    assert_eq!(p.in_package("com.example").len(), 0); // prefix should not match
}

#[test]
fn dp_success_rate_empty_is_one() {
    let p = DecompiledProject {
        classes: vec![],
        total: 0,
        failed: 0,
    };
    assert!((p.success_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn dp_success_rate_all_failed_is_zero() {
    let p = DecompiledProject {
        classes: vec![],
        total: 10,
        failed: 10,
    };
    assert!(p.success_rate().abs() < f64::EPSILON);
}

#[test]
fn dp_success_rate_half() {
    let p = DecompiledProject {
        classes: vec![],
        total: 10,
        failed: 5,
    };
    assert!((p.success_rate() - 0.5).abs() < 1e-9);
}

#[test]
fn dp_success_rate_failed_gt_total_saturates() {
    // saturating_sub keeps things sane; result should not be negative.
    let p = DecompiledProject {
        classes: vec![],
        total: 5,
        failed: 100,
    };
    let r = p.success_rate();
    assert!((0.0..=1.0).contains(&r), "unexpected {r}");
}

// ── MockJadxRunner / trait ──────────────────────────────────────────────────

#[test]
fn mock_runner_returns_mock_project() {
    let r = MockJadxRunner;
    let cfg = JadxConfig::new("j", "a", "o");
    let p = r.decompile(&cfg).unwrap();
    assert_eq!(p.classes.len(), 9);
}

#[test]
fn jadx_runner_is_object_safe_send_sync() {
    // compile-time check
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn JadxRunner>();
}

// ── JadxError Display ───────────────────────────────────────────────────────

#[test]
fn jadx_error_display_variants() {
    assert!(JadxError::NotFound("x".into()).to_string().contains('x'));
    assert!(JadxError::Decompile("y".into()).to_string().contains('y'));
    assert!(JadxError::Parse("z".into()).to_string().contains('z'));
    assert!(JadxError::Io("w".into()).to_string().contains('w'));
    assert!(JadxError::NotFound("x".into()).to_string().contains("not found"));
}

// ── CliJadxConfig / CliJadxRunner ───────────────────────────────────────────

#[test]
fn cli_cfg_default_flags_off() {
    let c = CliJadxConfig::default();
    assert!(!c.deobfuscate);
    assert!(!c.show_inconsistent_code);
    assert!(!c.no_res);
    assert!(c.output_dir.is_none());
}

#[test]
fn cli_runner_construct() {
    let cfg = CliJadxConfig::default();
    let r = CliJadxRunner::new(cfg);
    let _ = format!("{r:?}");
}

#[test]
fn find_jadx_in_path_does_not_panic() {
    let _ = CliJadxRunner::find_jadx_in_path();
    let _ = find_jadx();
}

// ── NativeDexDecompiler ────────────────────────────────────────────────────

fn dm(insns: &[&str]) -> DalvikMethod {
    DalvikMethod {
        name: "m".into(),
        class_name: "C".into(),
        return_type: "void".into(),
        params: vec![],
        instructions: insns.iter().map(|s| (*s).to_string()).collect(),
    }
}

#[test]
fn ndd_return_void() {
    let s = NativeDexDecompiler::decompile_method(&dm(&["return-void"])).unwrap();
    assert!(s.contains("return;"));
}

#[test]
fn ndd_const_value_emitted() {
    let s = NativeDexDecompiler::decompile_method(&dm(&["const v0, 42"])).unwrap();
    assert!(s.contains("v0 = 42"));
}

#[test]
fn ndd_const_string_emitted() {
    let s =
        NativeDexDecompiler::decompile_method(&dm(&[r#"const-string v0, "hi""#])).unwrap();
    assert!(s.contains("hi"));
}

#[test]
fn ndd_invoke_static_marked() {
    let s = NativeDexDecompiler::decompile_method(&dm(&[
        "invoke-static {v0}, Foo->bar()V",
    ]))
    .unwrap();
    assert!(s.contains("invoke-static"));
}

#[test]
fn ndd_arithmetic_emits_operators() {
    for (op, ch) in [
        ("add-int", "+"),
        ("sub-int", "-"),
        ("mul-int", "*"),
        ("div-int", "/"),
        ("rem-int", "%"),
        ("and-int", "&"),
        ("or-int", "|"),
        ("xor-int", "^"),
    ] {
        let insn = format!("{op} v0, v1, v2");
        let s = NativeDexDecompiler::decompile_method(&dm(&[&insn])).unwrap();
        assert!(s.contains(ch), "{op} should contain {ch}; got: {s}");
    }
}

#[test]
fn ndd_unhandled_opcode_comment() {
    let s = NativeDexDecompiler::decompile_method(&dm(&["banana-split v0"])).unwrap();
    assert!(s.contains("[native decompiler]"));
}

#[test]
fn ndd_check_cast_emits_cast() {
    let s = NativeDexDecompiler::decompile_method(&dm(&[
        "check-cast v0, Ljava/lang/String;",
    ]))
    .unwrap();
    assert!(s.contains("check-cast"));
}

#[test]
fn ndd_monitor_enter_exit() {
    let s = NativeDexDecompiler::decompile_method(&dm(&[
        "monitor-enter v0",
        "monitor-exit v0",
    ]))
    .unwrap();
    assert!(s.contains("synchronized"));
    assert!(s.contains("monitor-exit"));
}

#[test]
fn ndd_throw_statement() {
    let s = NativeDexDecompiler::decompile_method(&dm(&["throw v0"])).unwrap();
    assert!(s.contains("throw v0;"));
}

#[test]
fn ndd_nop() {
    let s = NativeDexDecompiler::decompile_method(&dm(&["nop"])).unwrap();
    assert!(s.contains("nop"));
}

// ── DalvikOpcode round-trip ────────────────────────────────────────────────

#[test]
fn opcode_from_byte_mnemonic_roundtrip() {
    let pairs = [
        (0x0e, "return-void"),
        (0x0f, "return"),
        (0x12, "const/4"),
        (0x1a, "const-string"),
        (0x54, "iget"),
        (0x59, "iput"),
        (0x6e, "invoke-virtual"),
        (0x70, "invoke-direct"),
        (0x71, "invoke-static"),
        (0x0a, "move-result"),
        (0x90, "add-int"),
        (0x91, "sub-int"),
        (0x92, "mul-int"),
        (0x32, "if-eq"),
        (0x33, "if-ne"),
        (0x34, "if-lt"),
        (0x35, "if-ge"),
        (0x36, "if-gt"),
        (0x37, "if-le"),
        (0x28, "goto"),
        (0x22, "new-instance"),
    ];
    for (b, mnem) in pairs {
        let op = DalvikOpcode::from_byte(b).expect("known opcode");
        assert_eq!(op.mnemonic(), mnem, "byte 0x{b:02x}");
        assert_eq!(op as u8, b);
    }
}

#[test]
fn opcode_unknown_byte() {
    assert!(DalvikOpcode::from_byte(0xff).is_none());
    assert!(DalvikOpcode::from_byte(0x00).is_none()); // nop is not in subset
}

#[test]
fn opcode_hash_eq_consistent() {
    use std::collections::HashSet;
    let mut s: HashSet<DalvikOpcode> = HashSet::new();
    s.insert(DalvikOpcode::Goto);
    s.insert(DalvikOpcode::Goto);
    assert_eq!(s.len(), 1);
}

// ── NativeDexLifter ────────────────────────────────────────────────────────

#[test]
fn lifter_return_void_exact() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::ReturnVoid, &[], &[]);
    assert_eq!(s, "return;");
}

#[test]
fn lifter_return_uses_reg() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::Return, &[3], &[]);
    assert_eq!(s, "return v3;");
}

#[test]
fn lifter_const4_signed_immediate() {
    // Single-byte payload is cast_signed; 0xff => -1
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::Const4, &[0], &[0xff]);
    assert_eq!(s, "v0 = -1;");
}

#[test]
fn lifter_const4_zero_payload_defaults_zero() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::Const4, &[2], &[]);
    assert_eq!(s, "v2 = 0;");
}

#[test]
fn lifter_const4_two_byte_le() {
    // 0x00 0x01 = 256
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::Const4, &[1], &[0x00, 0x01]);
    assert_eq!(s, "v1 = 256;");
}

#[test]
fn lifter_const_string_wraps_quotes() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::ConstString, &[0], b"abc");
    assert!(s.contains("\"abc\""));
    assert!(s.starts_with("v0 ="));
}

#[test]
fn lifter_addint_three_regs() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::AddInt, &[0, 1, 2], &[]);
    assert_eq!(s, "v0 = v1 + v2;");
}

#[test]
fn lifter_missing_regs_use_v_question() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::AddInt, &[], &[]);
    assert!(s.contains("v?"));
}

#[test]
fn lifter_branch_signed_offset() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::IfEq, &[0, 1], &[0xfc, 0xff]);
    // -4 as i16
    assert!(s.contains("v0 == v1"));
    assert!(s.contains("label_-4"), "got: {s}");
}

#[test]
fn lifter_goto_signed_offset() {
    let s = NativeDexLifter::lift_instruction(DalvikOpcode::Goto, &[], &[0x05]);
    // +5
    assert!(s.contains("label_+5"), "got: {s}");
}

#[test]
fn lifter_new_instance_strips_l_and_semi() {
    let s = NativeDexLifter::lift_instruction(
        DalvikOpcode::NewInstance,
        &[0],
        b"Ljava/lang/String;",
    );
    assert_eq!(s, "v0 = new java.lang.String();");
}

#[test]
fn lifter_iget_field_extraction() {
    let s =
        NativeDexLifter::lift_instruction(DalvikOpcode::Iget, &[0, 1], b"LFoo;->bar:I");
    assert_eq!(s, "v0 = v1.bar;");
}

#[test]
fn lifter_iput_field_extraction() {
    let s =
        NativeDexLifter::lift_instruction(DalvikOpcode::Iput, &[0, 1], b"LFoo;->bar:I");
    assert_eq!(s, "v1.bar = v0;");
}

#[test]
fn lifter_lift_raw_unknown_byte() {
    let s = NativeDexLifter::lift_raw(0xff, &[], &[]);
    assert!(s.contains("unknown opcode 0xff"));
}

#[test]
fn lifter_lift_raw_known_byte_delegates() {
    let s = NativeDexLifter::lift_raw(0x0e, &[], &[]);
    assert_eq!(s, "return;");
}

// ── JadxDecompilerConfig ────────────────────────────────────────────────────

#[test]
fn jdc_default_then_full() {
    let d = JadxDecompilerConfig::default();
    assert!(!d.deobf_enable);
    let f = JadxDecompilerConfig::full();
    assert!(f.deobf_enable);
}

#[test]
fn jdc_json_roundtrip() {
    let cfg = JadxDecompilerConfig {
        show_comments: false,
        use_imports: false,
        deobf_enable: true,
        deobf_min_len: 9,
    };
    let j = cfg.to_json().unwrap();
    let r = JadxDecompilerConfig::from_json(&j).unwrap();
    assert_eq!(r.deobf_min_len, 9);
    assert!(r.deobf_enable);
    assert!(!r.show_comments);
    assert!(!r.use_imports);
}

#[test]
fn jdc_from_invalid_json_is_parse_err() {
    let e = JadxDecompilerConfig::from_json("{ not json").unwrap_err();
    assert!(matches!(e, JadxError::Parse(_)));
}

// ── JadxResultProcessor ─────────────────────────────────────────────────────

#[test]
fn jrp_parse_class_name_and_package() {
    let java = "package a.b;\npublic class Foo {\n}\n";
    let c = JadxResultProcessor::parse_class_output(java);
    assert_eq!(c.package, "a.b");
    assert_eq!(c.name, "Foo");
}

#[test]
fn jrp_parse_no_package_returns_unknown() {
    let c = JadxResultProcessor::parse_class_output("class Bar {}");
    assert_eq!(c.package, "unknown");
    assert_eq!(c.name, "Bar");
}

#[test]
fn jrp_parse_interface_name() {
    let c = JadxResultProcessor::parse_class_output("interface IFoo { void run(); }");
    assert_eq!(c.name, "IFoo");
}

#[test]
fn jrp_parse_enum_name() {
    let c = JadxResultProcessor::parse_class_output("enum E { A, B }");
    assert_eq!(c.name, "E");
}

#[test]
fn jrp_extract_strings_order_and_duplicates() {
    let java = r#"a="x"; b="y"; c="x";"#;
    let v = JadxResultProcessor::extract_string_constants(java);
    assert_eq!(v, vec!["x", "y", "x"]);
}

#[test]
fn jrp_extract_strings_unterminated_consumes_rest() {
    let java = r#"a = "abc"#; // no closing quote
    let v = JadxResultProcessor::extract_string_constants(java);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0], "abc");
}

#[test]
fn jrp_extract_strings_escape_backslash_quote() {
    let java = r#"x = "he\"llo";"#;
    let v = JadxResultProcessor::extract_string_constants(java);
    assert_eq!(v.len(), 1);
    assert!(v[0].contains('"'));
}

#[test]
fn jrp_methods_and_fields_extracted() {
    let java = r"
package x;
public class C {
    private int count;
    public void doIt() {}
}
";
    let c = JadxResultProcessor::parse_class_output(java);
    assert!(!c.methods.is_empty());
    assert!(!c.fields.is_empty());
}

// ── DalvikType / descriptor parsing ────────────────────────────────────────

#[test]
fn desc_primitives() {
    assert_eq!(descriptor_to_type("V"), DalvikType::Void);
    assert_eq!(descriptor_to_type("Z"), DalvikType::Boolean);
    assert_eq!(descriptor_to_type("B"), DalvikType::Byte);
    assert_eq!(descriptor_to_type("S"), DalvikType::Short);
    assert_eq!(descriptor_to_type("C"), DalvikType::Char);
    assert_eq!(descriptor_to_type("I"), DalvikType::Int);
    assert_eq!(descriptor_to_type("J"), DalvikType::Long);
    assert_eq!(descriptor_to_type("F"), DalvikType::Float);
    assert_eq!(descriptor_to_type("D"), DalvikType::Double);
}

#[test]
fn desc_object() {
    let t = descriptor_to_type("Ljava/lang/String;");
    assert_eq!(t, DalvikType::Object("java/lang/String".into()));
}

#[test]
fn desc_array_int() {
    let t = descriptor_to_type("[I");
    assert_eq!(t, DalvikType::Array(Box::new(DalvikType::Int)));
}

#[test]
fn desc_array_2d_object() {
    let t = descriptor_to_type("[[Ljava/lang/Object;");
    match t {
        DalvikType::Array(a) => match *a {
            DalvikType::Array(b) => match *b {
                DalvikType::Object(s) => assert_eq!(s, "java/lang/Object"),
                _ => panic!("inner not Object"),
            },
            _ => panic!("not Array of Array"),
        },
        _ => panic!("not Array"),
    }
}

#[test]
fn desc_empty_is_unknown() {
    assert_eq!(descriptor_to_type(""), DalvikType::Unknown);
}

#[test]
fn desc_garbage_is_unknown() {
    assert_eq!(descriptor_to_type("Q"), DalvikType::Unknown);
}

#[test]
fn dtype_to_java_object_simple_name() {
    let t = DalvikType::Object("java/lang/String".into());
    assert_eq!(t.to_java_string(), "String");
}

#[test]
fn dtype_to_java_array() {
    let t = DalvikType::Array(Box::new(DalvikType::Int));
    assert_eq!(t.to_java_string(), "int[]");
}

#[test]
fn dtype_is_wide() {
    assert!(DalvikType::Long.is_wide());
    assert!(DalvikType::Double.is_wide());
    assert!(!DalvikType::Int.is_wide());
    assert!(!DalvikType::Object("x".into()).is_wide());
}

#[test]
fn dtype_is_primitive() {
    assert!(DalvikType::Int.is_primitive());
    assert!(DalvikType::Boolean.is_primitive());
    assert!(!DalvikType::Object("x".into()).is_primitive());
    assert!(!DalvikType::Void.is_primitive());
    assert!(!DalvikType::Unknown.is_primitive());
}

#[test]
fn dtype_join_identity() {
    assert_eq!(DalvikType::Int.join(&DalvikType::Int), DalvikType::Int);
}

#[test]
fn dtype_join_unknown_absorbs() {
    assert_eq!(
        DalvikType::Int.join(&DalvikType::Unknown),
        DalvikType::Int
    );
    assert_eq!(
        DalvikType::Unknown.join(&DalvikType::Long),
        DalvikType::Long
    );
}

#[test]
fn dtype_join_int_bool_is_int() {
    assert_eq!(
        DalvikType::Int.join(&DalvikType::Boolean),
        DalvikType::Int
    );
    assert_eq!(
        DalvikType::Boolean.join(&DalvikType::Int),
        DalvikType::Int
    );
}

#[test]
fn dtype_join_disjoint_unknown() {
    assert_eq!(
        DalvikType::Int.join(&DalvikType::Float),
        DalvikType::Unknown
    );
}

// ── parse_method_proto / parse_type_list ───────────────────────────────────

#[test]
fn proto_simple_void_no_args() {
    let (params, ret) = parse_method_proto("()V");
    assert!(params.is_empty());
    assert_eq!(ret, DalvikType::Void);
}

#[test]
fn proto_with_object_and_array() {
    let (params, ret) = parse_method_proto("(ILjava/lang/String;[I)Z");
    assert_eq!(params.len(), 3);
    assert_eq!(params[0], DalvikType::Int);
    assert_eq!(params[1], DalvikType::Object("java/lang/String".into()));
    assert_eq!(params[2], DalvikType::Array(Box::new(DalvikType::Int)));
    assert_eq!(ret, DalvikType::Boolean);
}

#[test]
fn proto_missing_parens() {
    let (p, r) = parse_method_proto("garbage");
    assert!(p.is_empty());
    assert_eq!(r, DalvikType::Unknown);
}

#[test]
fn type_list_concatenated() {
    let v = parse_type_list("IJZ");
    assert_eq!(
        v,
        vec![DalvikType::Int, DalvikType::Long, DalvikType::Boolean]
    );
}

#[test]
fn type_list_empty() {
    assert!(parse_type_list("").is_empty());
}

#[test]
fn type_list_with_object_terminated() {
    let v = parse_type_list("ILjava/lang/String;Z");
    assert_eq!(v.len(), 3);
    assert_eq!(v[1], DalvikType::Object("java/lang/String".into()));
}

// ── build_shorty / MethodProto ─────────────────────────────────────────────

#[test]
fn shorty_void_no_args() {
    let s = build_shorty(&[], &DalvikType::Void);
    assert_eq!(s, "V");
}

#[test]
fn shorty_mixed() {
    let s = build_shorty(
        &[
            DalvikType::Int,
            DalvikType::Object("java/lang/String".into()),
            DalvikType::Array(Box::new(DalvikType::Int)),
        ],
        &DalvikType::Boolean,
    );
    // return first, then params
    assert_eq!(s, "ZILL");
}

#[test]
fn method_proto_parse_basic() {
    let mp = MethodProto::parse("(I)V");
    assert!(mp.is_void());
    assert!(!mp.is_no_arg());
    assert_eq!(mp.param_slots(), 1);
    assert_eq!(mp.shorty, "VI");
    assert_eq!(mp.java_sig(), "(int) -> void");
}

#[test]
fn method_proto_wide_params_consume_two_slots() {
    let mp = MethodProto::parse("(JD)V");
    assert_eq!(mp.param_slots(), 4);
}

#[test]
fn method_proto_no_arg() {
    let mp = MethodProto::parse("()I");
    assert!(mp.is_no_arg());
    assert!(!mp.is_void());
}

// ── try_decrypt_xor ────────────────────────────────────────────────────────

#[test]
fn xor_roundtrip_ascii() {
    let plain = b"hello world";
    let key: u8 = 0x5a;
    let enc: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
    let out = try_decrypt_xor(i64::from(key), &enc).unwrap();
    assert_eq!(out, "hello world");
}

#[test]
fn xor_key_takes_low_byte_only() {
    let plain = b"abc";
    let enc: Vec<u8> = plain.iter().map(|b| b ^ 0x11).collect();
    // Key 0x10000_0011 -> low byte is 0x11
    let out = try_decrypt_xor(0x1_0000_0011, &enc).unwrap();
    assert_eq!(out, "abc");
}

#[test]
fn xor_invalid_utf8_returns_none() {
    // 0xff stays 0xff with key 0; invalid UTF-8
    let out = try_decrypt_xor(0, &[0xff, 0xfe]);
    assert!(out.is_none());
}

#[test]
fn xor_empty_input_empty_output() {
    let s = try_decrypt_xor(0x42, &[]).unwrap();
    assert!(s.is_empty());
}

#[test]
fn xor_negative_key_low_byte() {
    // i64 -1 -> low byte 0xff
    let plain = b"AB";
    let enc: Vec<u8> = plain.iter().map(|b| b ^ 0xff).collect();
    let out = try_decrypt_xor(-1, &enc).unwrap();
    assert_eq!(out, "AB");
}

#[test]
fn decrypt_strings_uses_payload_fn() {
    let call = EncryptedStringCall {
        call_offset: 100,
        key: 0x42,
        dest_reg: None,
    };
    let map = decrypt_strings(&[call], |k| {
        Some(b"hi".iter().map(|b| b ^ u8::try_from(k & 0xff).unwrap_or(0)).collect())
    });
    assert_eq!(map.get(&100), Some(&"hi".to_string()));
}

#[test]
fn decrypt_strings_skips_missing_payload() {
    let call = EncryptedStringCall {
        call_offset: 7,
        key: 1,
        dest_reg: None,
    };
    let map: HashMap<u32, String> = decrypt_strings(&[call], |_| None);
    assert!(map.is_empty());
}

// ── deobf_class_name / method_name / field_name ────────────────────────────

#[test]
fn deobf_class_keeps_long_readable_name() {
    let r = deobf_class_name("Lcom/example/MyService;", Some("Service"), 7, 3);
    assert_eq!(r, "Lcom/example/MyService;");
}

#[test]
fn deobf_class_renames_short_with_activity_suffix() {
    let r = deobf_class_name("Lcom/ex/a;", Some("Activity"), 5, 3);
    assert!(r.contains("Activity5"));
    assert!(r.starts_with("Lcom/ex/"));
}

#[test]
fn deobf_class_no_package() {
    let r = deobf_class_name("La;", Some("View"), 1, 3);
    assert!(r.contains("View1"));
    assert!(!r.contains('/'));
}

#[test]
fn deobf_class_no_super_uses_class_suffix() {
    let r = deobf_class_name("La;", None, 2, 3);
    assert!(r.contains("Class2"));
}

#[test]
fn deobf_method_keeps_init_clinit() {
    assert_eq!(deobf_method_name("<init>", "()V", 0, 0, 3), "<init>");
    assert_eq!(deobf_method_name("<clinit>", "()V", 8, 0, 3), "<clinit>");
}

#[test]
fn deobf_method_keeps_long_names() {
    assert_eq!(deobf_method_name("computeValue", "()I", 0, 0, 3), "computeValue");
}

#[test]
fn deobf_method_short_void_static_init_prefix() {
    let r = deobf_method_name("a", "()V", 0x0008, 4, 3);
    assert_eq!(r, "init4");
}

#[test]
fn deobf_method_short_void_instance_do_prefix() {
    let r = deobf_method_name("a", "()V", 0, 3, 3);
    assert_eq!(r, "do3");
}

#[test]
fn deobf_method_short_boolean_is_prefix() {
    let r = deobf_method_name("b", "()Z", 0, 1, 3);
    assert_eq!(r, "is1");
}

#[test]
fn deobf_method_short_object_get_prefix() {
    let r = deobf_method_name("c", "()Ljava/lang/String;", 0, 2, 3);
    assert_eq!(r, "get2");
}

#[test]
fn deobf_field_keeps_long() {
    assert_eq!(
        deobf_field_name("counter", &DalvikType::Int, 0, 3),
        "counter"
    );
}

#[test]
fn deobf_field_short_gets_prefix_and_index() {
    let r = deobf_field_name("a", &DalvikType::Int, 7, 3);
    // var_prefix_for_type(Int) is "i", then capitalized to "I"
    assert_eq!(r, "mI7");
}

// ── DalvikInstr predicates ─────────────────────────────────────────────────

#[test]
fn dinstr_is_return_range() {
    for op in 0x0e..=0x11u8 {
        let i = DalvikInstr {
            offset: 0,
            opcode: op,
            mnemonic: "x",
            regs: vec![],
            imm: None,
            target: None,
            ref_idx: None,
            format: DalvikFmt::Fmt10x,
        };
        assert!(i.is_return(), "0x{op:02x}");
        assert!(i.is_terminator());
    }
}

#[test]
fn dinstr_is_branch_from_target() {
    let i = DalvikInstr {
        offset: 0,
        opcode: 0x32,
        mnemonic: "if-eq",
        regs: vec![],
        imm: None,
        target: Some(4),
        ref_idx: None,
        format: DalvikFmt::Fmt22t,
    };
    assert!(i.is_branch());
}

#[test]
fn dinstr_is_invoke_range() {
    for op in [0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x78, 0xfa, 0xfb, 0xfc] {
        let i = DalvikInstr {
            offset: 0,
            opcode: op,
            mnemonic: "",
            regs: vec![],
            imm: None,
            target: None,
            ref_idx: None,
            format: DalvikFmt::Fmt35c,
        };
        assert!(i.is_invoke(), "op 0x{op:02x}");
    }
    // 0x73 is the gap.
    let gap = DalvikInstr {
        offset: 0,
        opcode: 0x73,
        mnemonic: "",
        regs: vec![],
        imm: None,
        target: None,
        ref_idx: None,
        format: DalvikFmt::FmtUnknown,
    };
    assert!(!gap.is_invoke());
}

#[test]
fn dinstr_code_units_by_format() {
    let mk = |f: DalvikFmt| DalvikInstr {
        offset: 0,
        opcode: 0,
        mnemonic: "",
        regs: vec![],
        imm: None,
        target: None,
        ref_idx: None,
        format: f,
    };
    assert_eq!(mk(DalvikFmt::Fmt10x).code_units(), 1);
    assert_eq!(mk(DalvikFmt::Fmt22x).code_units(), 2);
    assert_eq!(mk(DalvikFmt::Fmt30t).code_units(), 3);
    assert_eq!(mk(DalvikFmt::Fmt51l).code_units(), 5);
}

// ── decode_dalvik ──────────────────────────────────────────────────────────

#[test]
fn decode_empty_buffer() {
    let v = decode_dalvik(&[]);
    assert!(v.is_empty());
}

#[test]
fn decode_return_void() {
    // opcode 0x0e in low byte, aa=0
    let v = decode_dalvik(&[0x000e]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, 0x0e);
    assert!(v[0].is_return());
}

#[test]
fn decode_advances_pc_by_units() {
    // return-void (1 unit) followed by another return-void
    let v = decode_dalvik(&[0x000e, 0x000e]);
    assert_eq!(v.len(), 2);
}

#[test]
fn opcode_mnemonic_known_values() {
    assert_eq!(opcode_mnemonic(0x0e), "return-void");
    assert_eq!(opcode_mnemonic(0x00), "nop");
}

#[test]
fn opcode_format_known_values() {
    assert_eq!(opcode_format(0x0e), DalvikFmt::Fmt10x);
}

// ── DexFile / DexFileContext ───────────────────────────────────────────────

#[test]
fn dexfile_empty_lookups_return_none() {
    let f = DexFile::empty();
    assert!(f.string_by_idx(0).is_none());
    assert!(f.type_desc(0).is_none());
    assert!(f.field_desc(0).is_none());
    assert!(f.method_proto(0).is_none());
}

#[test]
fn dexfile_populated_lookups() {
    let f = DexFile {
        strings: vec!["hello".into()],
        types: vec!["Ljava/lang/Object;".into()],
        fields: vec!["F".into()],
        method_protos: vec!["()V".into()],
    };
    assert_eq!(f.string_by_idx(0), Some("hello"));
    assert_eq!(f.type_desc(0), Some("Ljava/lang/Object;"));
    assert_eq!(f.field_desc(0), Some("F"));
    assert_eq!(f.method_proto(0), Some("()V"));
    assert!(f.string_by_idx(99).is_none());
}

// ── ClassSource / DecompileResult ──────────────────────────────────────────

#[test]
fn classsource_serde_roundtrip() {
    let cs = ClassSource {
        class_name: "x.Y".into(),
        source: "class Y {}".into(),
    };
    let j = serde_json::to_string(&cs).unwrap();
    let d: ClassSource = serde_json::from_str(&j).unwrap();
    assert_eq!(d.class_name, "x.Y");
}

#[test]
fn decompile_result_variants_compile() {
    let _ = DecompileResult::Native(vec![]);
    let _ = DecompileResult::Jadx(std::path::PathBuf::from("/x"));
}
