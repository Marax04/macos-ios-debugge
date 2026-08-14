//! Blitz test suite for rustre-script-rhai.
//! Targets pure helpers and lib.rs public API surface.

use std::str::FromStr;

use rustre_script_rhai::*;

// ─── num_cast re-exports ────────────────────────────────────────────────────

#[test]
fn lossy_u64_to_f64_zero() {
    assert_eq!(lossy_u64_to_f64(0), 0.0);
}

#[test]
fn lossy_u64_to_f64_small() {
    assert_eq!(lossy_u64_to_f64(42), 42.0);
}

#[test]
fn lossy_u64_to_f64_large() {
    assert_eq!(lossy_u64_to_f64(u64::MAX), u64::MAX as f64);
}

#[test]
fn lossy_usize_to_f64_basic() {
    assert_eq!(lossy_usize_to_f64(1000), 1000.0);
}

#[test]
fn lossy_i64_to_f64_positive() {
    assert_eq!(lossy_i64_to_f64(123), 123.0);
}

#[test]
fn lossy_i64_to_f64_negative() {
    assert_eq!(lossy_i64_to_f64(-123), -123.0);
}

#[test]
fn lossy_i64_to_f64_min() {
    let v = lossy_i64_to_f64(i64::MIN);
    assert!(v < 0.0);
    assert!((v - (i64::MIN as f64)).abs() < 1.0);
}

#[test]
fn trunc_f64_to_i64_basic() {
    assert_eq!(trunc_f64_to_i64(42.7), 42);
    assert_eq!(trunc_f64_to_i64(-42.7), -42);
}

#[test]
fn trunc_f64_to_i64_nan_returns_zero() {
    assert_eq!(trunc_f64_to_i64(f64::NAN), 0);
}

#[test]
fn trunc_f64_to_i64_positive_inf_saturates() {
    assert_eq!(trunc_f64_to_i64(f64::INFINITY), i64::MAX);
}

#[test]
fn trunc_f64_to_i64_negative_inf_saturates() {
    assert_eq!(trunc_f64_to_i64(f64::NEG_INFINITY), i64::MIN);
}

#[test]
fn trunc_f64_to_i64_zero() {
    assert_eq!(trunc_f64_to_i64(0.0), 0);
    assert_eq!(trunc_f64_to_i64(-0.0), 0);
}

#[test]
fn trunc_f64_to_i64_subnormal() {
    assert_eq!(trunc_f64_to_i64(1e-300), 0);
}

#[test]
fn sat_usize_to_i64_basic() {
    assert_eq!(sat_usize_to_i64(0), 0);
    assert_eq!(sat_usize_to_i64(42), 42);
}

#[test]
fn sat_u64_to_usize_basic() {
    assert_eq!(sat_u64_to_usize(0), 0);
    assert_eq!(sat_u64_to_usize(123), 123);
}

#[test]
fn sat_i64_to_usize_negative_is_zero() {
    assert_eq!(sat_i64_to_usize(-1), 0);
    assert_eq!(sat_i64_to_usize(i64::MIN), 0);
}

#[test]
fn sat_i64_to_usize_positive() {
    assert_eq!(sat_i64_to_usize(100), 100);
}

#[test]
fn trunc_i64_to_u8_basic() {
    assert_eq!(trunc_i64_to_u8(0), 0);
    assert_eq!(trunc_i64_to_u8(0xFF), 0xFF);
    assert_eq!(trunc_i64_to_u8(0x1FF), 0xFF);
    assert_eq!(trunc_i64_to_u8(0x100), 0);
}

#[test]
fn trunc_i64_to_u32_basic() {
    assert_eq!(trunc_i64_to_u32(0), 0);
    assert_eq!(trunc_i64_to_u32(0xFFFF_FFFF), 0xFFFF_FFFF);
    assert_eq!(trunc_i64_to_u32(0x1_0000_0000), 0);
}

#[test]
fn trunc_u128_to_u64_basic() {
    assert_eq!(trunc_u128_to_u64(0), 0);
    assert_eq!(trunc_u128_to_u64(u128::from(u64::MAX)), u64::MAX);
    assert_eq!(trunc_u128_to_u64(u128::from(u64::MAX) + 1), 0);
}

// ─── sha256_bytes_impl ──────────────────────────────────────────────────────

#[test]
fn sha256_empty() {
    assert_eq!(
        sha256_bytes_impl(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_abc() {
    assert_eq!(
        sha256_bytes_impl(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_len_is_64() {
    assert_eq!(sha256_bytes_impl(b"anything").len(), 64);
}

// ─── entropy_impl ───────────────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(entropy_impl(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    assert_eq!(entropy_impl(&[0u8; 1000]), 0.0);
}

#[test]
fn entropy_uniform_is_eight() {
    let mut data = Vec::with_capacity(256);
    for i in 0..=255u8 {
        data.push(i);
    }
    let e = entropy_impl(&data);
    assert!((e - 8.0).abs() < 1e-9, "expected ~8.0, got {e}");
}

#[test]
fn entropy_two_values_is_one() {
    let data: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
    let e = entropy_impl(&data);
    assert!((e - 1.0).abs() < 1e-9, "expected ~1.0, got {e}");
}

#[test]
fn entropy_classify_thresholds() {
    assert!(entropy_classify(0.5).starts_with("very low"));
    assert!(entropy_classify(2.0).starts_with("low"));
    assert!(entropy_classify(4.0).starts_with("medium"));
    assert!(entropy_classify(6.5).starts_with("high"));
    assert!(entropy_classify(7.8).starts_with("very high"));
}

// ─── hex encode/decode round-trip ───────────────────────────────────────────

#[test]
fn hex_encode_empty() {
    assert_eq!(hex_encode_impl(&[]), "");
}

#[test]
fn hex_encode_basic() {
    assert_eq!(hex_encode_impl(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
}

#[test]
fn hex_encode_lowercase() {
    assert_eq!(hex_encode_impl(&[0xFF, 0xAB]), "ffab");
}

#[test]
fn hex_decode_basic() {
    assert_eq!(hex_decode_impl("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hex_decode_with_spaces() {
    assert_eq!(hex_decode_impl("de ad be ef"), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hex_decode_with_0x() {
    assert_eq!(hex_decode_impl("0xdead"), vec![0xde, 0xad]);
}

#[test]
fn hex_decode_empty() {
    assert!(hex_decode_impl("").is_empty());
}

#[test]
fn hex_encode_decode_roundtrip() {
    let original: Vec<u8> = (0..=255u8).collect();
    let encoded = hex_encode_impl(&original);
    let decoded = hex_decode_impl(&encoded);
    assert_eq!(original, decoded);
}

#[test]
fn hex_decode_odd_length_drops_last() {
    // odd length: "abc" → only "ab" decoded
    assert_eq!(hex_decode_impl("abc"), vec![0xab]);
}

// ─── xor / rotate ───────────────────────────────────────────────────────────

#[test]
fn xor_bytes_zero_key_identity() {
    let data = vec![1, 2, 3, 4];
    assert_eq!(xor_bytes_impl(&data, 0), data);
}

#[test]
fn xor_bytes_involution() {
    let data = vec![0xAA, 0xBB, 0xCC];
    let once = xor_bytes_impl(&data, 0x55);
    let twice = xor_bytes_impl(&once, 0x55);
    assert_eq!(data, twice);
}

#[test]
fn rotate_bytes_zero_identity() {
    let data = vec![0b1100_0011];
    assert_eq!(rotate_bytes_impl(&data, 0, true), data);
    assert_eq!(rotate_bytes_impl(&data, 0, false), data);
}

#[test]
fn rotate_bytes_eight_identity() {
    let data = vec![0b1100_0011];
    // n % 8 == 0
    assert_eq!(rotate_bytes_impl(&data, 8, true), data);
}

#[test]
fn rotate_bytes_left_one() {
    assert_eq!(rotate_bytes_impl(&[0b1000_0001], 1, true), vec![0b0000_0011]);
}

#[test]
fn rotate_bytes_right_one() {
    assert_eq!(rotate_bytes_impl(&[0b0000_0011], 1, false), vec![0b1000_0001]);
}

#[test]
fn rotate_roundtrip() {
    let data = vec![0x12, 0x34, 0x56];
    let rotated = rotate_bytes_impl(&data, 3, true);
    let back = rotate_bytes_impl(&rotated, 3, false);
    assert_eq!(data, back);
}

// ─── find_pattern_impl ──────────────────────────────────────────────────────

#[test]
fn find_pattern_empty_pattern() {
    let r = find_pattern_impl(b"hello", "");
    assert!(r.is_empty());
}

#[test]
fn find_pattern_simple() {
    let data = b"\x90\x90\xEB\xFE";
    let r = find_pattern_impl(data, "90 90");
    assert_eq!(r.len(), 1);
}

#[test]
fn find_pattern_wildcard() {
    let data = b"\x90\xAB\xCD\x90\xEF\xCD";
    let r = find_pattern_impl(data, "90 ?? CD");
    assert_eq!(r.len(), 2);
}

#[test]
fn find_pattern_double_question() {
    let data = b"\x90\xAB\xCD";
    let r = find_pattern_impl(data, "?? ?? ??");
    assert_eq!(r.len(), 1);
}

#[test]
fn find_pattern_too_long() {
    let r = find_pattern_impl(b"\x01", "01 02 03");
    assert!(r.is_empty());
}

#[test]
fn find_pattern_no_match() {
    let r = find_pattern_impl(b"\x00\x00\x00", "FF FF");
    assert!(r.is_empty());
}

// ─── find_strings_in_blob ───────────────────────────────────────────────────

#[test]
fn find_strings_empty() {
    let r = find_strings_in_blob(b"", 4);
    assert!(r.is_empty());
}

#[test]
fn find_strings_basic() {
    let r = find_strings_in_blob(b"hello\x00world\x00", 4);
    assert_eq!(r.len(), 2);
}

#[test]
fn find_strings_min_len_filter() {
    let r = find_strings_in_blob(b"hi\x00hello\x00", 4);
    assert_eq!(r.len(), 1);
}

#[test]
fn find_strings_at_end_no_terminator() {
    let r = find_strings_in_blob(b"hello", 4);
    assert_eq!(r.len(), 1);
}

// ─── detect_format ──────────────────────────────────────────────────────────

#[test]
fn detect_format_pe() {
    assert_eq!(detect_format(b"MZ\x00\x00"), "PE");
}

#[test]
fn detect_format_elf() {
    assert_eq!(detect_format(b"\x7fELF\x00"), "ELF");
}

#[test]
fn detect_format_wasm() {
    assert_eq!(detect_format(b"\0asm\x01\x00\x00\x00"), "WASM");
}

#[test]
fn detect_format_dex() {
    assert_eq!(detect_format(b"dex\n035\x00"), "DEX");
}

#[test]
fn detect_format_macho() {
    let data = 0xfeed_facfu32.to_be_bytes();
    assert_eq!(detect_format(&data), "MachO");
}

#[test]
fn detect_format_macho_fat() {
    let data = 0xcafe_babeu32.to_be_bytes();
    assert_eq!(detect_format(&data), "MachO-fat");
}

#[test]
fn detect_format_unknown_empty() {
    assert_eq!(detect_format(b""), "unknown");
}

#[test]
fn detect_format_unknown_random() {
    assert_eq!(detect_format(b"xyz!"), "unknown");
}

// ─── detect_arch ────────────────────────────────────────────────────────────

#[test]
fn detect_arch_elf_x86_64() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"\x7fELF");
    data[18] = 0x3e;
    data[19] = 0x00;
    assert_eq!(detect_arch(&data), "x86_64");
}

#[test]
fn detect_arch_elf_aarch64() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"\x7fELF");
    data[18] = 0xb7;
    data[19] = 0x00;
    assert_eq!(detect_arch(&data), "aarch64");
}

#[test]
fn detect_arch_wasm() {
    assert_eq!(detect_arch(b"\0asm\x01\x00\x00\x00"), "wasm32");
}

#[test]
fn detect_arch_dex() {
    assert_eq!(detect_arch(b"dex\n035\x00"), "dalvik");
}

#[test]
fn detect_arch_unknown() {
    assert_eq!(detect_arch(b""), "unknown");
}

// ─── RhaiValue ──────────────────────────────────────────────────────────────

#[test]
fn rhai_value_is_unit() {
    assert!(RhaiValue::Unit.is_unit());
    assert!(!RhaiValue::Bool(true).is_unit());
}

#[test]
fn rhai_value_as_int_from_int() {
    assert_eq!(RhaiValue::Int(7).as_int(), Some(7));
}

#[test]
fn rhai_value_as_int_from_float() {
    assert_eq!(RhaiValue::Float(7.9).as_int(), Some(7));
}

#[test]
fn rhai_value_as_int_from_string_is_none() {
    assert_eq!(RhaiValue::String("x".into()).as_int(), None);
}

#[test]
fn rhai_value_as_float_from_int() {
    assert_eq!(RhaiValue::Int(3).as_float(), Some(3.0));
}

#[test]
fn rhai_value_as_str_returns_some() {
    assert_eq!(RhaiValue::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(RhaiValue::Int(1).as_str(), None);
}

#[test]
fn rhai_value_as_bool() {
    assert_eq!(RhaiValue::Bool(true).as_bool(), Some(true));
    assert_eq!(RhaiValue::Int(1).as_bool(), None);
}

#[test]
fn rhai_value_dynamic_roundtrip_int() {
    let v = RhaiValue::Int(42);
    let d = v.clone().into_dynamic();
    assert_eq!(RhaiValue::from_dynamic(d), v);
}

#[test]
fn rhai_value_dynamic_roundtrip_string() {
    let v = RhaiValue::String("hello".into());
    let d = v.clone().into_dynamic();
    assert_eq!(RhaiValue::from_dynamic(d), v);
}

#[test]
fn rhai_value_dynamic_roundtrip_array() {
    let v = RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Int(2)]);
    let d = v.clone().into_dynamic();
    assert_eq!(RhaiValue::from_dynamic(d), v);
}

#[test]
fn rhai_value_dynamic_roundtrip_bytes() {
    let v = RhaiValue::Bytes(vec![1, 2, 3]);
    let d = v.clone().into_dynamic();
    assert_eq!(RhaiValue::from_dynamic(d), v);
}

#[test]
fn rhai_value_display_unit() {
    assert_eq!(RhaiValue::Unit.to_string(), "()");
}

#[test]
fn rhai_value_display_bytes() {
    assert_eq!(RhaiValue::Bytes(vec![0; 5]).to_string(), "<blob 5 bytes>");
}

#[test]
fn rhai_value_display_array() {
    assert_eq!(
        RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Int(2)]).to_string(),
        "[1, 2]"
    );
}

// ─── EventBus ───────────────────────────────────────────────────────────────

#[test]
fn event_bus_default_empty() {
    let bus = EventBus::new();
    assert_eq!(bus.handler_count(), 0);
    assert!(bus.registered_events().is_empty());
}

#[test]
fn event_bus_register_and_dispatch() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    let ast = engine.compile("42").unwrap();
    bus.on("tick", ast);
    assert_eq!(bus.handler_count(), 1);
    let results = bus.dispatch(&engine, "tick");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap(), &RhaiValue::Int(42));
}

#[test]
fn event_bus_dispatch_no_match() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("tick", engine.compile("1").unwrap());
    assert!(bus.dispatch(&engine, "other").is_empty());
}

#[test]
fn event_bus_remove_handlers() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("a", engine.compile("1").unwrap());
    bus.on("b", engine.compile("2").unwrap());
    bus.remove_handlers("a");
    assert_eq!(bus.handler_count(), 1);
    assert_eq!(bus.registered_events(), vec!["b".to_string()]);
}

#[test]
fn event_bus_registered_events_sorted_dedup() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("z", engine.compile("1").unwrap());
    bus.on("a", engine.compile("2").unwrap());
    bus.on("a", engine.compile("3").unwrap());
    let events = bus.registered_events();
    assert_eq!(events, vec!["a".to_string(), "z".to_string()]);
}

#[test]
fn event_bus_dispatch_with_data() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("e", engine.compile("event_data + 1").unwrap());
    let results = bus.dispatch_with_data(&engine, "e", rhai::Dynamic::from(10i64));
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap(), &RhaiValue::Int(11));
}

// ─── EventHookSystem ────────────────────────────────────────────────────────

#[test]
fn event_hook_system_default_empty() {
    let s = EventHookSystem::default();
    assert_eq!(s.hook_count(), 0);
}

#[test]
fn event_hook_system_on_event() {
    let mut s = EventHookSystem::new();
    // Synthesize a FnPtr via Rhai engine
    let engine = rhai::Engine::new();
    let fp: rhai::FnPtr = engine.eval("Fn(\"my_cb\")").unwrap();
    s.on_event("custom", fp);
    assert_eq!(s.hook_count(), 1);
    let hooks = s.hooks_for("custom");
    assert_eq!(hooks, vec!["my_cb"]);
}

// ─── RhaiXrefKind ───────────────────────────────────────────────────────────

#[test]
fn rhai_xref_kind_from_str_known() {
    assert_eq!(RhaiXrefKind::from_str("call").unwrap(), RhaiXrefKind::Call);
    assert_eq!(RhaiXrefKind::from_str("jump").unwrap(), RhaiXrefKind::Jump);
    assert_eq!(RhaiXrefKind::from_str("data").unwrap(), RhaiXrefKind::Data);
}

#[test]
fn rhai_xref_kind_from_str_unknown() {
    assert_eq!(RhaiXrefKind::from_str("???").unwrap(), RhaiXrefKind::Unknown);
}

#[test]
fn rhai_xref_kind_display() {
    assert_eq!(RhaiXrefKind::Call.to_string(), "call");
    assert_eq!(RhaiXrefKind::Jump.to_string(), "jump");
    assert_eq!(RhaiXrefKind::Data.to_string(), "data");
    assert_eq!(RhaiXrefKind::Unknown.to_string(), "unknown");
}

#[test]
fn rhai_xref_kind_roundtrip() {
    for k in [
        RhaiXrefKind::Call,
        RhaiXrefKind::Jump,
        RhaiXrefKind::Data,
        RhaiXrefKind::Unknown,
    ] {
        let s = k.to_string();
        // "unknown" round-trips; others should too
        assert_eq!(RhaiXrefKind::from_str(&s).unwrap(), k);
    }
}

// ─── RhaiSegmentKind ────────────────────────────────────────────────────────

#[test]
fn rhai_segment_kind_display() {
    assert_eq!(RhaiSegmentKind::Code.to_string(), "code");
    assert_eq!(RhaiSegmentKind::Data.to_string(), "data");
    assert_eq!(RhaiSegmentKind::ReadOnly.to_string(), "rodata");
    assert_eq!(RhaiSegmentKind::Bss.to_string(), "bss");
    assert_eq!(RhaiSegmentKind::Unknown.to_string(), "unknown");
}

// ─── RhaiInstruction ────────────────────────────────────────────────────────

#[test]
fn rhai_instruction_to_string_with_operands() {
    let i = RhaiInstruction {
        address: 0x1000,
        mnemonic: "mov".into(),
        operands: "eax, ebx".into(),
        bytes: vec![0x89, 0xd8],
        size: 2,
    };
    let s = i.to_string_repr();
    assert!(s.contains("0x00001000"));
    assert!(s.contains("89d8"));
    assert!(s.contains("mov eax, ebx"));
}

#[test]
fn rhai_instruction_to_string_no_operands() {
    let i = RhaiInstruction {
        address: 0,
        mnemonic: "ret".into(),
        operands: String::new(),
        bytes: vec![0xc3],
        size: 1,
    };
    let s = i.to_string_repr();
    assert!(s.ends_with("ret"));
}

// ─── RhaiScriptEngine integration ───────────────────────────────────────────

#[test]
fn engine_eval_int() {
    let e = RhaiScriptEngine::new();
    assert_eq!(e.eval_int("1 + 2").unwrap(), 3);
}

#[test]
fn engine_eval_bool() {
    let e = RhaiScriptEngine::new();
    assert!(e.eval_bool("true && true").unwrap());
}

#[test]
fn engine_eval_string() {
    let e = RhaiScriptEngine::new();
    assert_eq!(e.eval_string(r#""hi""#).unwrap(), "hi");
}

#[test]
fn engine_eval_float() {
    let e = RhaiScriptEngine::new();
    let v = e.eval_float("3.14").unwrap();
    assert!((v - 3.14).abs() < 1e-9);
}

#[test]
fn engine_eval_int_type_error_on_string() {
    let e = RhaiScriptEngine::new();
    let r = e.eval_int(r#""x""#);
    assert!(matches!(r, Err(ScriptError::TypeError { .. })));
}

#[test]
fn engine_eval_with_var() {
    let e = RhaiScriptEngine::new();
    let r = e.eval_with_var("x * 2", "x", 21i64).unwrap();
    assert_eq!(r, RhaiValue::Int(42));
}

#[test]
fn engine_with_rustre_module_logs() {
    let e = RhaiScriptEngine::with_rustre_module();
    e.eval(r#"rustre_log("hello")"#).unwrap();
    assert_eq!(e.log_messages(), vec!["hello".to_string()]);
}

#[test]
fn engine_rustre_version() {
    let e = RhaiScriptEngine::with_rustre_module();
    let v = e.eval_string("rustre_version()").unwrap();
    assert!(v.contains("rustre-script-rhai"));
}

#[test]
fn engine_parse_error() {
    let e = RhaiScriptEngine::new();
    let r = e.compile("let x =");
    assert!(matches!(r, Err(ScriptError::Parse(_))));
}

#[test]
fn engine_re_api_hex_encode() {
    let e = RhaiScriptEngine::with_re_api();
    let r = e
        .eval_string(r#"let b = blob(); b.push(0xde); b.push(0xad); hex_encode(b)"#)
        .unwrap();
    assert_eq!(r, "dead");
}

#[test]
fn engine_re_api_dec_to_hex() {
    let e = RhaiScriptEngine::with_re_api();
    assert_eq!(e.eval_string("dec_to_hex(26)").unwrap(), "0x1a");
}

#[test]
fn engine_re_api_hex_to_dec() {
    let e = RhaiScriptEngine::with_re_api();
    assert_eq!(e.eval_int(r#"hex_to_dec("0x1a")"#).unwrap(), 26);
}

fn mkblob(script: &str) -> String {
    // helper builds a script that constructs a blob of given bytes
    script.to_string()
}

#[test]
fn engine_re_api_find_bytes_match() {
    let e = RhaiScriptEngine::with_re_api();
    let code = mkblob(
        r#"
        let h = blob(); h.push(1); h.push(2); h.push(3); h.push(4); h.push(5);
        let n = blob(); n.push(3); n.push(4);
        find_bytes(h, n)
        "#,
    );
    let r = e.eval_int(&code).unwrap();
    assert_eq!(r, 2);
}

#[test]
fn engine_re_api_find_bytes_no_match() {
    let e = RhaiScriptEngine::with_re_api();
    let code = r#"
        let h = blob(); h.push(1); h.push(2); h.push(3);
        let n = blob(); n.push(9); n.push(9);
        find_bytes(h, n)
        "#;
    let r = e.eval_int(code).unwrap();
    assert_eq!(r, -1);
}

#[test]
fn engine_re_api_find_bytes_empty_needle() {
    let e = RhaiScriptEngine::with_re_api();
    let code = r#"
        let h = blob(); h.push(1); h.push(2); h.push(3);
        let n = blob();
        find_bytes(h, n)
        "#;
    let r = e.eval_int(code).unwrap();
    assert_eq!(r, -1);
}

#[test]
fn engine_re_api_xor() {
    let e = RhaiScriptEngine::with_re_api();
    let code = r#"
        let b = blob(); b.push(0xAA); b.push(0xBB);
        xor(b, 0x55)
        "#;
    let r = e.eval(code).unwrap();
    if let RhaiValue::Bytes(b) = r {
        assert_eq!(b, vec![0xFF, 0xEE]);
    } else {
        panic!("expected bytes, got {r:?}");
    }
}

#[test]
fn load_binary_missing_file_returns_err() {
    let r = rhai_load_binary_impl("/this/path/definitely/does/not/exist__zzzz");
    assert!(r.is_err());
}

#[test]
fn get_info_unknown_id_has_error() {
    let m = rhai_get_info_impl("nonexistent-binary-id-zzz");
    assert!(m.contains_key("error"));
}

// ─── RustreState ────────────────────────────────────────────────────────────

#[test]
fn rustre_state_default_empty() {
    let s = RustreState::new();
    assert!(s.log_messages.is_empty());
    assert!(s.actions.is_empty());
    assert!(s.event_listeners.is_empty());
}

// ─── RhaiEngine wrapper ─────────────────────────────────────────────────────

#[test]
fn rhai_engine_eval_expr() {
    let e = RhaiEngine::new();
    let v = e.eval_expr("1 + 1").unwrap();
    assert_eq!(v.cast::<i64>(), 2);
}

#[test]
fn rhai_engine_call_no_args() {
    let mut e = RhaiEngine::new();
    e.register_global_fn("answer", || -> i64 { 42 });
    let r = e.call("answer", vec![]).unwrap();
    assert_eq!(r.cast::<i64>(), 42);
}

#[test]
fn rhai_engine_call_with_args() {
    let mut e = RhaiEngine::new();
    e.register_global_fn("add", |a: i64, b: i64| -> i64 { a + b });
    let r = e
        .call("add", vec![rhai::Dynamic::from(2i64), rhai::Dynamic::from(3i64)])
        .unwrap();
    assert_eq!(r.cast::<i64>(), 5);
}
