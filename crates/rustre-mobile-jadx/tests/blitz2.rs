//! blitz2: deep adversarial coverage of rustre-mobile-jadx pure-function API.

use rustre_mobile_jadx::*;
use std::collections::HashMap;

// Seeded LCG (Knuth MMIX constants)
const fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *s
}

// ─── descriptor_to_type ───────────────────────────────────────────────────────

#[test]
fn desc_primitives_all() {
    for (d, exp) in &[
        ("V", DalvikType::Void),
        ("Z", DalvikType::Boolean),
        ("B", DalvikType::Byte),
        ("S", DalvikType::Short),
        ("C", DalvikType::Char),
        ("I", DalvikType::Int),
        ("J", DalvikType::Long),
        ("F", DalvikType::Float),
        ("D", DalvikType::Double),
    ] {
        assert_eq!(&descriptor_to_type(d), exp, "for {d}");
    }
}

#[test]
fn desc_empty_is_unknown() {
    assert_eq!(descriptor_to_type(""), DalvikType::Unknown);
}

#[test]
fn desc_unknown_byte() {
    assert_eq!(descriptor_to_type("Q"), DalvikType::Unknown);
    assert_eq!(descriptor_to_type("?"), DalvikType::Unknown);
}

#[test]
fn desc_object_basic() {
    let t = descriptor_to_type("Ljava/lang/String;");
    assert_eq!(t, DalvikType::Object("java/lang/String".to_string()));
}

#[test]
fn desc_array_int() {
    let t = descriptor_to_type("[I");
    assert_eq!(t, DalvikType::Array(Box::new(DalvikType::Int)));
}

#[test]
fn desc_nested_array() {
    let t = descriptor_to_type("[[[D");
    let expected = DalvikType::Array(Box::new(DalvikType::Array(Box::new(DalvikType::Array(
        Box::new(DalvikType::Double),
    )))));
    assert_eq!(t, expected);
}

#[test]
fn desc_truncated_array_safe() {
    // "[" without inner descriptor must not panic
    let _ = descriptor_to_type("[");
}

// ─── parse_type_list / parse_method_proto round-trips ─────────────────────────

#[test]
fn proto_void_no_args() {
    let (p, r) = parse_method_proto("()V");
    assert!(p.is_empty());
    assert_eq!(r, DalvikType::Void);
}

#[test]
fn proto_complex() {
    let (p, r) = parse_method_proto("(I[Ljava/lang/String;J)Ljava/util/List;");
    assert_eq!(p.len(), 3);
    assert_eq!(p[0], DalvikType::Int);
    assert_eq!(p[2], DalvikType::Long);
    assert_eq!(r, DalvikType::Object("java/util/List".to_string()));
}

#[test]
fn proto_no_parens_unknown() {
    let (p, r) = parse_method_proto("garbage");
    assert!(p.is_empty());
    assert_eq!(r, DalvikType::Unknown);
}

#[test]
fn proto_missing_rparen() {
    let (p, r) = parse_method_proto("(I");
    assert!(p.is_empty());
    assert_eq!(r, DalvikType::Unknown);
}

#[test]
fn parse_type_list_empty() {
    assert!(parse_type_list("").is_empty());
}

#[test]
fn parse_type_list_mixed() {
    let v = parse_type_list("IJ[BLfoo/Bar;");
    assert_eq!(v.len(), 4);
    assert_eq!(v[3], DalvikType::Object("foo/Bar".to_string()));
}

#[test]
fn parse_type_list_unterminated_l() {
    // "Lfoo" without ';' — must not panic and must not infinite-loop
    let v = parse_type_list("Lfoo");
    assert!(!v.is_empty());
}

#[test]
fn fuzz_descriptor_never_panics() {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut g = || lcg(&mut s);
    let alphabet = b"VZBSCIJFD[L;abc/123";
    for _ in 0..200 {
        let len = usize::try_from(g() % 24).unwrap_or(0);
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[usize::try_from(g()).unwrap_or(0) % alphabet.len()])
            .collect();
        if let Ok(st) = std::str::from_utf8(&bytes) {
            let _ = descriptor_to_type(st);
            let _ = parse_type_list(st);
            let _ = parse_method_proto(st);
        }
    }
}

// ─── DalvikType behaviour ─────────────────────────────────────────────────────

#[test]
fn type_is_wide_only_long_double() {
    assert!(DalvikType::Long.is_wide());
    assert!(DalvikType::Double.is_wide());
    assert!(!DalvikType::Int.is_wide());
    assert!(!DalvikType::Float.is_wide());
    assert!(!DalvikType::Void.is_wide());
    assert!(!DalvikType::Object("X".to_string()).is_wide());
}

#[test]
fn type_is_primitive_set() {
    for t in [
        DalvikType::Boolean,
        DalvikType::Byte,
        DalvikType::Short,
        DalvikType::Char,
        DalvikType::Int,
        DalvikType::Long,
        DalvikType::Float,
        DalvikType::Double,
    ] {
        assert!(t.is_primitive(), "{t:?}");
    }
    assert!(!DalvikType::Void.is_primitive());
    assert!(!DalvikType::Unknown.is_primitive());
    assert!(!DalvikType::Object("x".into()).is_primitive());
    assert!(!DalvikType::Array(Box::new(DalvikType::Int)).is_primitive());
}

#[test]
fn type_join_idempotent() {
    let t = DalvikType::Int;
    assert_eq!(t.join(&t), DalvikType::Int);
}

#[test]
fn type_join_unknown_identity() {
    let t = DalvikType::Float;
    assert_eq!(t.join(&DalvikType::Unknown), DalvikType::Float);
    assert_eq!(DalvikType::Unknown.join(&t), DalvikType::Float);
}

#[test]
fn type_join_int_boolean() {
    assert_eq!(DalvikType::Int.join(&DalvikType::Boolean), DalvikType::Int);
    assert_eq!(DalvikType::Boolean.join(&DalvikType::Int), DalvikType::Int);
}

#[test]
fn type_join_unrelated_unknown() {
    assert_eq!(
        DalvikType::Float.join(&DalvikType::Long),
        DalvikType::Unknown
    );
}

#[test]
fn type_to_java_string_basic() {
    assert_eq!(DalvikType::Void.to_java_string(), "void");
    assert_eq!(DalvikType::Boolean.to_java_string(), "boolean");
    assert_eq!(DalvikType::Unknown.to_java_string(), "Object");
}

#[test]
fn type_to_java_string_object_uses_simple_name() {
    let t = DalvikType::Object("java/lang/String".to_string());
    assert_eq!(t.to_java_string(), "String");
}

#[test]
fn type_to_java_string_array_appends_brackets() {
    let t = DalvikType::Array(Box::new(DalvikType::Int));
    assert_eq!(t.to_java_string(), "int[]");
    let t2 = DalvikType::Array(Box::new(DalvikType::Array(Box::new(DalvikType::Double))));
    assert_eq!(t2.to_java_string(), "double[][]");
}

// ─── build_shorty ─────────────────────────────────────────────────────────────

#[test]
fn shorty_void_void() {
    let s = build_shorty(&[], &DalvikType::Void);
    assert_eq!(s, "V");
}

#[test]
fn shorty_full_alphabet() {
    let params = vec![
        DalvikType::Boolean,
        DalvikType::Byte,
        DalvikType::Short,
        DalvikType::Char,
        DalvikType::Int,
        DalvikType::Long,
        DalvikType::Float,
        DalvikType::Double,
        DalvikType::Object("X".into()),
        DalvikType::Array(Box::new(DalvikType::Int)),
        DalvikType::Unknown,
    ];
    let s = build_shorty(&params, &DalvikType::Int);
    assert_eq!(s, "IZBSCIJFDLLL");
}

// ─── MethodProto ──────────────────────────────────────────────────────────────

#[test]
fn methodproto_parse_void_void() {
    let m = MethodProto::parse("()V");
    assert!(m.is_no_arg());
    assert!(m.is_void());
    assert_eq!(m.shorty, "V");
    assert_eq!(m.param_slots(), 0);
}

#[test]
fn methodproto_param_slots_wide() {
    let m = MethodProto::parse("(IJF)V");
    // I=1, J=2, F=1 => 4
    assert_eq!(m.param_slots(), 4);
}

#[test]
fn methodproto_java_sig() {
    let m = MethodProto::parse("(I)Ljava/lang/String;");
    assert_eq!(m.java_sig(), "(int) -> String");
}

#[test]
fn methodproto_fuzz_protos_no_panic() {
    let mut s: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let mut g = || lcg(&mut s);
    let alphabet = b"()VZBSCIJFD[Lfoo/Bar;";
    for _ in 0..100 {
        let len = usize::try_from(g() % 32).unwrap_or(0);
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[usize::try_from(g()).unwrap_or(0) % alphabet.len()])
            .collect();
        if let Ok(st) = std::str::from_utf8(&bytes) {
            let m = MethodProto::parse(st);
            // shorty length = 1 + params
            assert_eq!(m.shorty.len(), m.params.len() + 1);
        }
    }
}

// ─── deobf_class_name / method_name / field_name ──────────────────────────────

#[test]
fn deobf_class_keeps_readable() {
    let r = deobf_class_name("Lcom/foo/MyActivity;", None, 0, 3);
    assert_eq!(r, "Lcom/foo/MyActivity;");
}

#[test]
fn deobf_class_renames_short_with_super() {
    let r = deobf_class_name("Lcom/foo/a;", Some("Landroid/app/Activity;"), 7, 3);
    assert!(r.contains("Activity7"), "got {r}");
}

#[test]
fn deobf_class_no_package() {
    let r = deobf_class_name("La;", None, 1, 3);
    assert!(r.starts_with('L') && r.ends_with(';'));
    assert!(r.contains("Class1"));
}

#[test]
fn deobf_class_fragment_super() {
    let r = deobf_class_name("Lp/a;", Some("Landroidx/fragment/app/Fragment;"), 2, 3);
    assert!(r.contains("Fragment2"));
}

#[test]
fn deobf_method_init_unchanged() {
    let r = deobf_method_name("<init>", "()V", 0, 5, 3);
    assert_eq!(r, "<init>");
    let r2 = deobf_method_name("<clinit>", "()V", 0, 5, 3);
    assert_eq!(r2, "<clinit>");
}

#[test]
fn deobf_method_boolean_returns_is() {
    let r = deobf_method_name("a", "()Z", 0, 9, 3);
    assert_eq!(r, "is9");
}

#[test]
fn deobf_method_void_static_init() {
    let r = deobf_method_name("a", "()V", 0x0008, 3, 3);
    assert_eq!(r, "init3");
}

#[test]
fn deobf_method_void_nonstatic_do() {
    let r = deobf_method_name("a", "()V", 0, 4, 3);
    assert_eq!(r, "do4");
}

#[test]
fn deobf_method_keeps_long_name() {
    let r = deobf_method_name("computeChecksum", "()I", 0, 0, 3);
    assert_eq!(r, "computeChecksum");
}

#[test]
fn deobf_field_keeps_long() {
    let r = deobf_field_name("totalCount", &DalvikType::Int, 0, 3);
    assert_eq!(r, "totalCount");
}

#[test]
fn deobf_field_renames_short() {
    let r = deobf_field_name("a", &DalvikType::Int, 5, 3);
    // Starts with m, then capital prefix, then idx
    assert!(r.starts_with('m'));
    assert!(r.ends_with('5'));
}

// ─── try_decrypt_xor ──────────────────────────────────────────────────────────

#[test]
fn xor_decrypt_zero_key_passthrough_ascii() {
    let r = try_decrypt_xor(0, b"hello");
    assert_eq!(r.as_deref(), Some("hello"));
}

#[test]
fn xor_decrypt_roundtrip_50_inputs() {
    let mut s: u64 = 0xABCD_EF01_2345_6789;
    let mut g = || lcg(&mut s);
    for _ in 0..50 {
        let key = i64::try_from(g() & 0xff).unwrap_or(0);
        let len = usize::try_from(g() % 32).unwrap_or(0) + 1;
        // Choose plaintext ASCII so utf8 holds after xor-back
        let plain: Vec<u8> = (0..len).map(|_| b'a' + u8::try_from(g() & 0x0f).unwrap_or(0)).collect();
        let k = u8::try_from(key & 0xff).unwrap_or(0);
        let enc: Vec<u8> = plain.iter().map(|b| b ^ k).collect();
        let dec = try_decrypt_xor(key, &enc).unwrap();
        assert_eq!(dec.as_bytes(), plain.as_slice());
    }
}

#[test]
fn xor_decrypt_invalid_utf8_returns_none() {
    // 0xC0 is not valid leading utf-8 byte on its own
    let r = try_decrypt_xor(0, &[0xC0, 0xC0]);
    assert!(r.is_none());
}

#[test]
fn xor_decrypt_key_only_low_byte() {
    // Keys differing only above low byte must produce the same result
    let a = try_decrypt_xor(0x12, b"abc");
    let b = try_decrypt_xor(0xFF00_0012, b"abc");
    assert_eq!(a, b);
}

// ─── format_decrypted_strings_comment ─────────────────────────────────────────

#[test]
fn format_empty_decrypted_yields_empty() {
    let m: HashMap<u32, String> = HashMap::new();
    assert!(format_decrypted_strings_comment(&m).is_empty());
}

#[test]
fn format_decrypted_sorted_by_offset() {
    let mut m: HashMap<u32, String> = HashMap::new();
    m.insert(20, "b".to_string());
    m.insert(10, "a".to_string());
    let s = format_decrypted_strings_comment(&m);
    let i_a = s.find("0x000a").unwrap();
    let i_b = s.find("0x0014").unwrap();
    assert!(i_a < i_b);
    assert!(s.starts_with("/* Decrypted strings:"));
    assert!(s.trim_end().ends_with(" */"));
}

// ─── DecompiledProject ────────────────────────────────────────────────────────

#[test]
fn project_mock_invariants() {
    let p = DecompiledProject::mock();
    assert!(p.total >= p.failed);
    assert!(p.success_rate() >= 0.0 && p.success_rate() <= 1.0);
}

#[test]
fn project_find_class_simple_and_fqn() {
    let p = DecompiledProject::mock();
    let any = p.classes.first().cloned().expect("non-empty mock");
    let by_simple = p.find_class(&any.class_name).expect("simple");
    assert_eq!(by_simple.class_name, any.class_name);
    let fqn = format!("{}.{}", any.package, any.class_name);
    let by_fqn = p.find_class(&fqn).expect("fqn");
    assert_eq!(by_fqn.class_name, any.class_name);
    assert!(p.find_class("definitely::not::a::class::name").is_none());
}

#[test]
fn project_success_rate_zero_total() {
    let p = DecompiledProject {
        classes: vec![],
        total: 0,
        failed: 0,
    };
    assert!((p.success_rate() - 1.0).abs() < 1e-9);
}

#[test]
fn project_success_rate_all_failed() {
    let p = DecompiledProject {
        classes: vec![],
        total: 10,
        failed: 10,
    };
    assert!(p.success_rate().abs() < 1e-9);
}

#[test]
fn project_success_rate_failed_exceeds_total_saturating() {
    let p = DecompiledProject {
        classes: vec![],
        total: 5,
        failed: 100,
    };
    // saturating_sub clamps; result must be 0 not negative
    assert!(p.success_rate() >= 0.0);
    assert!(p.success_rate() <= 1.0);
}

// ─── JavaMethod / JavaClass ───────────────────────────────────────────────────

#[test]
fn method_is_constructor_detection() {
    let m = JavaMethod {
        name: "<init>".into(),
        signature: "()V".into(),
        return_type: "void".into(),
        params: vec![],
        body: String::new(),
        is_static: false,
        is_native: false,
    };
    assert!(m.is_constructor());
    let m2 = JavaMethod {
        name: "constructor".into(),
        ..m.clone()
    };
    assert!(m2.is_constructor());
    let m3 = JavaMethod {
        name: "foo".into(),
        ..m
    };
    assert!(!m3.is_constructor());
}

#[test]
fn class_static_and_native_filtering() {
    let mk = |n: &str, s, na| JavaMethod {
        name: n.into(),
        signature: format!("{n}()V"),
        return_type: "void".into(),
        params: vec![],
        body: String::new(),
        is_static: s,
        is_native: na,
    };
    let c = JavaClass {
        class_name: "C".into(),
        package: "p".into(),
        source: String::new(),
        methods: vec![mk("a", true, false), mk("b", false, true), mk("c", true, true)],
        super_class: None,
    };
    assert_eq!(c.static_methods().len(), 2);
    assert_eq!(c.native_methods().len(), 2);
}

// ─── JadxConfig builder ───────────────────────────────────────────────────────

#[test]
fn jadxconfig_defaults_and_builders() {
    let c = JadxConfig::new("j", "i", "o");
    assert_eq!(c.threads, 4);
    assert!(!c.deobfuscate);
    let c2 = c.with_threads(8).with_deobfuscate();
    assert_eq!(c2.threads, 8);
    assert!(c2.deobfuscate);
}

#[test]
fn jadxconfig_serde_roundtrip() {
    let c = JadxConfig::new("j", "i", "o").with_threads(2).with_deobfuscate();
    let json = serde_json::to_string(&c).unwrap();
    let back: JadxConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.threads, 2);
    assert!(back.deobfuscate);
    assert_eq!(back.jadx_path, "j");
}

// ─── DexFile / DexFileContext ────────────────────────────────────────────────

#[test]
fn dexfile_empty_lookups_none() {
    let d = DexFile::empty();
    assert!(d.string_by_idx(0).is_none());
    assert!(d.type_desc(0).is_none());
    assert!(d.field_desc(0).is_none());
    assert!(d.method_proto(0).is_none());
}

#[test]
fn dexfile_populated_lookups() {
    let d = DexFile {
        strings: vec!["hello".into(), "world".into()],
        types: vec!["Ljava/lang/String;".into()],
        fields: vec!["F".into()],
        method_protos: vec!["()V".into()],
    };
    assert_eq!(d.string_by_idx(0), Some("hello"));
    assert_eq!(d.string_by_idx(1), Some("world"));
    assert!(d.string_by_idx(2).is_none());
    assert_eq!(d.type_desc(0), Some("Ljava/lang/String;"));
    assert_eq!(d.field_desc(0), Some("F"));
    assert_eq!(d.method_proto(0), Some("()V"));
}

#[test]
fn dexfile_lookup_uint_max_safe() {
    let d = DexFile::empty();
    assert!(d.string_by_idx(u32::MAX).is_none());
}

// ─── Hash/Eq sanity on DalvikType ─────────────────────────────────────────────

#[test]
fn dalviktype_eq_reflexive_symmetric_30_pairs() {
    // DalvikType does not impl Hash, so verify Eq reflexivity + symmetry + clone-equality.
    let samples = [
        DalvikType::Void,
        DalvikType::Boolean,
        DalvikType::Byte,
        DalvikType::Short,
        DalvikType::Char,
        DalvikType::Int,
        DalvikType::Long,
        DalvikType::Float,
        DalvikType::Double,
        DalvikType::Object("a".to_string()),
        DalvikType::Object("b".to_string()),
        DalvikType::Array(Box::new(DalvikType::Int)),
        DalvikType::Array(Box::new(DalvikType::Long)),
        DalvikType::Unknown,
    ];
    let mut checked = 0;
    for a in &samples {
        assert_eq!(a, &a.clone());
        for b in &samples {
            assert_eq!(a == b, b == a, "symmetry violated for {a:?} vs {b:?}");
            checked += 1;
            if checked >= 30 {
                return;
            }
        }
    }
}

#[test]
fn methodproto_clone_debug_smoke() {
    // Misc Hash unrelated: ensure debug+clone work on relevant API types.
    let m = MethodProto::parse("(II)V");
    let _ = format!("{m:?}");
    let _ = m;
}

// ─── Send+Sync threaded stress ────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn dalviktype_send_sync() {
    assert_send_sync::<DalvikType>();
}

#[test]
fn dexfile_send_sync() {
    assert_send_sync::<DexFile>();
}

#[test]
fn threaded_descriptor_parser_stress() {
    use std::sync::Arc;
    use std::thread;
    let inputs: Arc<Vec<String>> = Arc::new(
        vec![
            "I", "J", "V", "Ljava/lang/String;", "[I", "[[D", "(II)V", "()Z", "", "Q",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );
    let mut handles = vec![];
    for tid in 0..4 {
        let ins = Arc::clone(&inputs);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xABCD_1234_5678_9ABC ^ u64::try_from(tid).unwrap_or(0);
            for _ in 0..100 {
                let idx = usize::try_from(lcg(&mut s)).unwrap_or(0) % ins.len();
                let st = &ins[idx];
                let _ = descriptor_to_type(st);
                let _ = parse_method_proto(st);
                let _ = parse_type_list(st);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── opcode_format / decode_dalvik smoke + fuzz ───────────────────────────────

#[test]
fn opcode_format_known_values() {
    assert_eq!(opcode_format(0x00), DalvikFmt::Fmt10x);
    assert_eq!(opcode_format(0x0e), DalvikFmt::Fmt10x); // return-void
    assert_eq!(opcode_format(0x12), DalvikFmt::Fmt11n); // const/4
    assert_eq!(opcode_format(0x6e), DalvikFmt::Fmt35c); // invoke-virtual
}

#[test]
fn opcode_format_total_function_for_all_bytes() {
    // must not panic for any u8
    for op in 0u8..=255 {
        let _ = opcode_format(op);
    }
}

#[test]
fn decode_dalvik_empty() {
    assert!(decode_dalvik(&[]).is_empty());
}

#[test]
fn decode_dalvik_return_void() {
    let v = decode_dalvik(&[0x000e]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, 0x0e);
}

#[test]
fn decode_dalvik_fuzz_no_panic_seeded() {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..50 {
        let len = usize::try_from(lcg(&mut s) % 16).unwrap_or(0);
        let code: Vec<u16> = (0..len).map(|_| u16::try_from(lcg(&mut s) & 0xffff).unwrap_or(0)).collect();
        let _ = decode_dalvik(&code);
    }
}

// ─── find_encrypted_string_calls boundary ─────────────────────────────────────

#[test]
fn find_encrypted_empty_in_empty_out() {
    let v = find_encrypted_string_calls(&[], 0);
    assert!(v.is_empty());
}

#[test]
fn decrypt_strings_empty_calls_empty_map() {
    let m = decrypt_strings(&[], |_| Some(vec![]));
    assert!(m.is_empty());
}

#[test]
fn find_and_decrypt_no_instrs_noop() {
    let m = find_and_decrypt_strings(&[], 0, |_| Some(vec![]));
    assert!(m.is_empty());
}

// ─── apply_try_regions: no-op on empty ────────────────────────────────────────

#[test]
fn apply_try_regions_empty_items_returns_input() {
    let stmts = vec![JavaStmt::Label(0), JavaStmt::Label(4)];
    let out = apply_try_regions(stmts.clone(), &[]);
    assert_eq!(out.len(), stmts.len());
}

// ─── JadxError Display ───────────────────────────────────────────────────────

#[test]
fn jadx_error_display_variants() {
    let e = JadxError::NotFound("x".into());
    assert!(format!("{e}").contains("not found"));
    let e = JadxError::Decompile("y".into());
    assert!(format!("{e}").contains("decompile"));
    let e = JadxError::Parse("z".into());
    assert!(format!("{e}").contains("parse"));
    let e = JadxError::Io("w".into());
    assert!(format!("{e}").contains("io"));
}
