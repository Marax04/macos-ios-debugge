//! Blitz2: deep adversarial coverage for rustre-script-rhai lib.rs API.

use std::str::FromStr;

use rustre_script_rhai::*;
use std::sync::Arc;
use std::thread;

// Seeded LCG
fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ─── num_cast deep tests ────────────────────────────────────────────────────

#[test]
fn lcg_lossy_u64_to_f64_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..200 {
        let v = g();
        let f = lossy_u64_to_f64(v);
        assert!(f.is_finite());
        assert!(f >= 0.0);
    }
}

#[test]
fn lcg_trunc_f64_to_i64_fuzz_round_trip_small() {
    let mut g = make_lcg();
    for _ in 0..100 {
        let n = (g() as i64) >> 16;
        let f = lossy_i64_to_f64(n);
        assert_eq!(trunc_f64_to_i64(f), n);
    }
}

#[test]
fn trunc_f64_to_i64_nan_is_zero() {
    assert_eq!(trunc_f64_to_i64(f64::NAN), 0);
}

#[test]
fn trunc_f64_to_i64_inf_saturates() {
    assert_eq!(trunc_f64_to_i64(f64::INFINITY), i64::MAX);
    assert_eq!(trunc_f64_to_i64(f64::NEG_INFINITY), i64::MIN);
}

#[test]
fn trunc_f64_to_i64_overflow_saturates() {
    assert_eq!(trunc_f64_to_i64(1e30), i64::MAX);
    assert_eq!(trunc_f64_to_i64(-1e30), i64::MIN);
}

#[test]
fn trunc_f64_to_i64_subnormal_is_zero() {
    assert_eq!(trunc_f64_to_i64(0.5), 0);
    assert_eq!(trunc_f64_to_i64(-0.5), 0);
    assert_eq!(trunc_f64_to_i64(0.0), 0);
}

#[test]
fn sat_usize_to_i64_boundary() {
    assert_eq!(sat_usize_to_i64(0), 0);
    assert_eq!(sat_usize_to_i64(1), 1);
    assert_eq!(sat_usize_to_i64(usize::MAX), i64::MAX);
}

#[test]
fn sat_u64_to_usize_boundary() {
    assert_eq!(sat_u64_to_usize(0), 0);
    assert_eq!(sat_u64_to_usize(42), 42);
}

#[test]
fn sat_i64_to_usize_negative_is_zero() {
    assert_eq!(sat_i64_to_usize(-1), 0);
    assert_eq!(sat_i64_to_usize(i64::MIN), 0);
    assert_eq!(sat_i64_to_usize(0), 0);
    assert_eq!(sat_i64_to_usize(123), 123);
}

#[test]
fn trunc_i64_to_u8_low_bits() {
    assert_eq!(trunc_i64_to_u8(0xFF), 0xFF);
    assert_eq!(trunc_i64_to_u8(0x1FF), 0xFF);
    assert_eq!(trunc_i64_to_u8(0x100), 0);
    assert_eq!(trunc_i64_to_u8(0), 0);
}

#[test]
fn trunc_i64_to_u32_low_bits() {
    assert_eq!(trunc_i64_to_u32(0xFFFF_FFFF), 0xFFFF_FFFF);
    assert_eq!(trunc_i64_to_u32(0x1_0000_0000), 0);
}

#[test]
fn trunc_u128_to_u64_low_bits() {
    assert_eq!(trunc_u128_to_u64(u128::from(u64::MAX)), u64::MAX);
    assert_eq!(trunc_u128_to_u64(0), 0);
}

// ─── RhaiValue tests ────────────────────────────────────────────────────────

#[test]
fn rhai_value_display_variants() {
    assert_eq!(RhaiValue::Unit.to_string(), "()");
    assert_eq!(RhaiValue::Bool(true).to_string(), "true");
    assert_eq!(RhaiValue::Int(42).to_string(), "42");
    assert_eq!(RhaiValue::String("hi".into()).to_string(), "hi");
    assert_eq!(
        RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Int(2)]).to_string(),
        "[1, 2]"
    );
    assert_eq!(RhaiValue::Bytes(vec![1, 2, 3]).to_string(), "<blob 3 bytes>");
}

#[test]
fn rhai_value_is_unit() {
    assert!(RhaiValue::Unit.is_unit());
    assert!(!RhaiValue::Int(0).is_unit());
}

#[test]
fn rhai_value_as_int_paths() {
    assert_eq!(RhaiValue::Int(7).as_int(), Some(7));
    assert_eq!(RhaiValue::Float(7.9).as_int(), Some(7));
    assert_eq!(RhaiValue::Bool(true).as_int(), None);
    assert_eq!(RhaiValue::String("hi".into()).as_int(), None);
}

#[test]
fn rhai_value_as_float_paths() {
    assert_eq!(RhaiValue::Float(1.5).as_float(), Some(1.5));
    assert_eq!(RhaiValue::Int(3).as_float(), Some(3.0));
    assert_eq!(RhaiValue::Bool(false).as_float(), None);
}

#[test]
fn rhai_value_as_str_and_bool() {
    assert_eq!(RhaiValue::String("x".into()).as_str(), Some("x"));
    assert_eq!(RhaiValue::Int(0).as_str(), None);
    assert_eq!(RhaiValue::Bool(true).as_bool(), Some(true));
    assert_eq!(RhaiValue::Int(0).as_bool(), None);
}

#[test]
fn rhai_value_round_trip_via_dynamic() {
    let cases = vec![
        RhaiValue::Unit,
        RhaiValue::Bool(true),
        RhaiValue::Bool(false),
        RhaiValue::Int(0),
        RhaiValue::Int(-1),
        RhaiValue::Int(i64::MAX),
        RhaiValue::Int(i64::MIN),
        RhaiValue::Float(3.14),
        RhaiValue::String("hello".into()),
        RhaiValue::String(String::new()),
        RhaiValue::Bytes(vec![]),
        RhaiValue::Bytes(vec![0, 1, 2, 255]),
        RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Bool(true)]),
    ];
    for v in cases {
        let d = v.clone().into_dynamic();
        let back = RhaiValue::from_dynamic(d);
        assert_eq!(v, back, "round trip failed for {:?}", v);
    }
}

#[test]
fn rhai_value_eq_consistency() {
    let pairs: Vec<(RhaiValue, RhaiValue, bool)> = vec![
        (RhaiValue::Int(1), RhaiValue::Int(1), true),
        (RhaiValue::Int(1), RhaiValue::Int(2), false),
        (RhaiValue::Bool(true), RhaiValue::Bool(true), true),
        (RhaiValue::Bool(true), RhaiValue::Bool(false), false),
        (RhaiValue::Unit, RhaiValue::Unit, true),
        (RhaiValue::Unit, RhaiValue::Int(0), false),
        (
            RhaiValue::String("a".into()),
            RhaiValue::String("a".into()),
            true,
        ),
        (
            RhaiValue::String("a".into()),
            RhaiValue::String("b".into()),
            false,
        ),
        (
            RhaiValue::Bytes(vec![1, 2]),
            RhaiValue::Bytes(vec![1, 2]),
            true,
        ),
        (
            RhaiValue::Bytes(vec![1, 2]),
            RhaiValue::Bytes(vec![1, 3]),
            false,
        ),
        (RhaiValue::Float(1.5), RhaiValue::Float(1.5), true),
        (
            RhaiValue::Array(vec![RhaiValue::Int(1)]),
            RhaiValue::Array(vec![RhaiValue::Int(1)]),
            true,
        ),
        (
            RhaiValue::Array(vec![RhaiValue::Int(1)]),
            RhaiValue::Array(vec![RhaiValue::Int(2)]),
            false,
        ),
        (RhaiValue::Int(1), RhaiValue::Float(1.0), false),
        (RhaiValue::Int(0), RhaiValue::Bool(false), false),
    ];
    for (a, b, expected) in pairs {
        assert_eq!(a == b, expected, "{:?} vs {:?}", a, b);
    }
}

// ─── hex round-trip ────────────────────────────────────────────────────────

#[test]
fn hex_round_trip_deterministic() {
    for n in 0u8..=255 {
        let buf = vec![n];
        let enc = hex_encode_impl(&buf);
        let back = hex_decode_impl(&enc);
        assert_eq!(buf, back, "byte {n} failed");
    }
}

#[test]
fn hex_round_trip_fuzz() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let len = (g() % 64) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let enc = hex_encode_impl(&buf);
        let back = hex_decode_impl(&enc);
        assert_eq!(buf, back);
    }
}

#[test]
fn hex_decode_strips_spaces_and_prefix() {
    assert_eq!(hex_decode_impl("0x41 42"), vec![0x41, 0x42]);
    assert_eq!(hex_decode_impl("4142"), vec![0x41, 0x42]);
}

#[test]
fn hex_decode_empty_and_odd() {
    assert_eq!(hex_decode_impl(""), Vec::<u8>::new());
    // Odd-length tail dropped (no panic).
    let r = hex_decode_impl("4");
    assert!(r.is_empty() || r.len() == 0);
}

// ─── entropy & classify ───────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(entropy_impl(&[]), 0.0);
}

#[test]
fn entropy_uniform_byte_is_zero() {
    let buf = vec![0u8; 1000];
    assert!(entropy_impl(&buf).abs() < 1e-9);
}

#[test]
fn entropy_uniform_distribution_near_eight() {
    let buf: Vec<u8> = (0u32..2048).map(|i| (i & 0xFF) as u8).collect();
    let e = entropy_impl(&buf);
    assert!(e > 7.9 && e <= 8.0, "expected ~8.0, got {e}");
}

#[test]
fn entropy_classify_buckets() {
    assert!(entropy_classify(0.5).contains("very low"));
    assert!(entropy_classify(2.0).contains("low"));
    assert!(entropy_classify(5.0).contains("medium"));
    assert!(entropy_classify(6.5).contains("high"));
    assert!(entropy_classify(7.9).contains("very high"));
}

// ─── xor / rotate round trips ─────────────────────────────────────────────

#[test]
fn xor_self_inverse_fuzz() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let len = (g() % 100) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let key = (g() & 0xFF) as u8;
        let enc = xor_bytes_impl(&data, key);
        let dec = xor_bytes_impl(&enc, key);
        assert_eq!(data, dec);
    }
}

#[test]
fn rotate_round_trip() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let len = (g() % 50) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let n = (g() % 8) as u8;
        let l = rotate_bytes_impl(&data, n, true);
        let back = rotate_bytes_impl(&l, n, false);
        assert_eq!(data, back);
    }
}

#[test]
fn rotate_zero_is_identity() {
    let data = vec![0x12, 0x34, 0x56];
    assert_eq!(rotate_bytes_impl(&data, 0, true), data);
    assert_eq!(rotate_bytes_impl(&data, 8, true), data);
    assert_eq!(rotate_bytes_impl(&data, 16, false), data);
}

// ─── find_pattern ─────────────────────────────────────────────────────────

#[test]
fn find_pattern_exact() {
    let data = b"\x90\x90\xEB\xFE";
    let hits = find_pattern_impl(data, "90 90");
    assert_eq!(hits.len(), 1);
}

#[test]
fn find_pattern_wildcard() {
    let data = b"\x90\xAA\xEB";
    let hits = find_pattern_impl(data, "90 ?? EB");
    assert_eq!(hits.len(), 1);
    let hits2 = find_pattern_impl(data, "90 ? EB");
    assert_eq!(hits2.len(), 1);
}

#[test]
fn find_pattern_empty_and_oversized() {
    assert_eq!(find_pattern_impl(b"", "90").len(), 0);
    assert_eq!(find_pattern_impl(b"\x90", "").len(), 0);
    assert_eq!(find_pattern_impl(b"\x90", "90 90 90 90").len(), 0);
}

#[test]
fn find_pattern_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..30 {
        let len = (g() % 64) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let _ = find_pattern_impl(&data, "?? ?? ??");
        let _ = find_pattern_impl(&data, "FF");
        let _ = find_pattern_impl(&data, "");
    }
}

// ─── format / arch detection ──────────────────────────────────────────────

#[test]
fn detect_format_known() {
    assert_eq!(detect_format(b"MZdata"), "PE");
    assert_eq!(detect_format(b"\x7fELFdata"), "ELF");
    assert_eq!(detect_format(b"dex\nstuff"), "DEX");
    assert_eq!(detect_format(b"\0asm\x01\x00\x00\x00"), "WASM");
    assert_eq!(detect_format(b"\xfe\xed\xfa\xce"), "MachO");
    assert_eq!(detect_format(b"\xca\xfe\xba\xbe"), "MachO-fat");
    assert_eq!(detect_format(b""), "unknown");
    assert_eq!(detect_format(b"random"), "unknown");
}

#[test]
fn detect_arch_elf_machine() {
    // Build minimal ELF header: 18 bytes of pad, then e_machine LE.
    let mut buf = vec![0u8; 20];
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[18] = 0x3e;
    buf[19] = 0x00;
    assert_eq!(detect_arch(&buf), "x86_64");
    buf[18] = 0x03;
    buf[19] = 0x00;
    assert_eq!(detect_arch(&buf), "x86");
    buf[18] = 0xb7;
    buf[19] = 0x00;
    assert_eq!(detect_arch(&buf), "aarch64");
}

#[test]
fn detect_arch_unknown_short() {
    assert_eq!(detect_arch(b""), "unknown");
    assert_eq!(detect_arch(b"\x7fEL"), "unknown");
    assert_eq!(detect_arch(b"random"), "unknown");
}

#[test]
fn detect_arch_wasm_dex() {
    assert_eq!(detect_arch(b"\0asm\x01\x00\x00\x00"), "wasm32");
    assert_eq!(detect_arch(b"dex\n035\0"), "dalvik");
}

// ─── sha256 ────────────────────────────────────────────────────────────────

#[test]
fn sha256_empty_known() {
    assert_eq!(
        sha256_bytes_impl(&[]),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_abc_known() {
    assert_eq!(
        sha256_bytes_impl(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_length_always_64() {
    let mut g = make_lcg();
    for _ in 0..20 {
        let len = (g() % 200) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let h = sha256_bytes_impl(&buf);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ─── find_strings_in_blob ─────────────────────────────────────────────────

#[test]
fn find_strings_in_blob_basic() {
    let data = b"Hello\x00World\x00";
    let strs = find_strings_in_blob(data, 4);
    assert_eq!(strs.len(), 2);
}

#[test]
fn find_strings_min_len_filter() {
    let data = b"hi\x00thereLong\x00";
    let strs = find_strings_in_blob(data, 6);
    assert_eq!(strs.len(), 1);
}

#[test]
fn find_strings_empty() {
    assert_eq!(find_strings_in_blob(b"", 4).len(), 0);
    assert_eq!(find_strings_in_blob(b"\x00\x00\x00", 1).len(), 0);
}

// ─── RhaiXrefKind ─────────────────────────────────────────────────────────

#[test]
fn xref_kind_display_from_round_trip() {
    let kinds = [
        RhaiXrefKind::Call,
        RhaiXrefKind::Jump,
        RhaiXrefKind::Data,
        RhaiXrefKind::Unknown,
    ];
    for k in kinds {
        let s = k.to_string();
        let back = RhaiXrefKind::from_str(&s).unwrap();
        // Unknown round-trip: "unknown" is the literal; others match.
        assert_eq!(back, k);
    }
}

#[test]
fn xref_kind_from_str_unknown_default() {
    assert_eq!(RhaiXrefKind::from_str("nonsense").unwrap(), RhaiXrefKind::Unknown);
    assert_eq!(RhaiXrefKind::from_str("").unwrap(), RhaiXrefKind::Unknown);
}

// ─── RhaiSegmentKind ──────────────────────────────────────────────────────

#[test]
fn segment_kind_display() {
    assert_eq!(RhaiSegmentKind::Code.to_string(), "code");
    assert_eq!(RhaiSegmentKind::Data.to_string(), "data");
    assert_eq!(RhaiSegmentKind::ReadOnly.to_string(), "rodata");
    assert_eq!(RhaiSegmentKind::Bss.to_string(), "bss");
    assert_eq!(RhaiSegmentKind::Unknown.to_string(), "unknown");
}

// ─── RhaiInstruction ──────────────────────────────────────────────────────

#[test]
fn instruction_to_string_repr() {
    let i = RhaiInstruction {
        address: 0x1000,
        mnemonic: "nop".into(),
        operands: String::new(),
        bytes: vec![0x90],
        size: 1,
    };
    let s = i.to_string_repr();
    assert!(s.contains("0x00001000"));
    assert!(s.contains("nop"));
    assert!(s.contains("90"));
}

#[test]
fn instruction_to_string_with_operands() {
    let i = RhaiInstruction {
        address: 0x2000,
        mnemonic: "mov".into(),
        operands: "eax, ebx".into(),
        bytes: vec![0x89, 0xd8],
        size: 2,
    };
    let s = i.to_string_repr();
    assert!(s.contains("mov eax, ebx"));
}

// ─── EventBus ──────────────────────────────────────────────────────────────

#[test]
fn event_bus_register_and_count() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    assert_eq!(bus.handler_count(), 0);
    let ast = engine.compile("1 + 1").unwrap();
    bus.on("foo", ast);
    assert_eq!(bus.handler_count(), 1);
}

#[test]
fn event_bus_dispatch_returns_value() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    let ast = engine.compile("40 + 2").unwrap();
    bus.on("compute", ast);
    let results = bus.dispatch(&engine, "compute");
    assert_eq!(results.len(), 1);
    let v = results.into_iter().next().unwrap().unwrap();
    assert_eq!(v.as_int(), Some(42));
}

#[test]
fn event_bus_no_match_no_results() {
    let engine = rhai::Engine::new();
    let bus = EventBus::new();
    let results = bus.dispatch(&engine, "nope");
    assert!(results.is_empty());
}

#[test]
fn event_bus_remove_handlers() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("a", engine.compile("1").unwrap());
    bus.on("b", engine.compile("2").unwrap());
    bus.on("a", engine.compile("3").unwrap());
    assert_eq!(bus.handler_count(), 3);
    bus.remove_handlers("a");
    assert_eq!(bus.handler_count(), 1);
}

#[test]
fn event_bus_registered_events_sorted_unique() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    bus.on("z", engine.compile("1").unwrap());
    bus.on("a", engine.compile("1").unwrap());
    bus.on("a", engine.compile("1").unwrap());
    let evs = bus.registered_events();
    assert_eq!(evs, vec!["a".to_string(), "z".to_string()]);
}

#[test]
fn event_bus_dispatch_with_data() {
    let engine = rhai::Engine::new();
    let mut bus = EventBus::new();
    let ast = engine.compile("event_data + 10").unwrap();
    bus.on("e", ast);
    let results = bus.dispatch_with_data(&engine, "e", rhai::Dynamic::from(5_i64));
    assert_eq!(results.len(), 1);
    assert_eq!(results.into_iter().next().unwrap().unwrap().as_int(), Some(15));
}

// ─── EventHookSystem ──────────────────────────────────────────────────────

#[test]
fn event_hook_system_default_empty() {
    let s = EventHookSystem::default();
    assert_eq!(s.hook_count(), 0);
}

#[test]
fn event_hook_system_register_script() {
    let engine = rhai::Engine::new();
    let mut s = EventHookSystem::new();
    let ast = engine.compile("event_data * 2").unwrap();
    s.register_script("handler", ast);
    // Cannot easily construct FnPtr externally; just verify hook_count without on_event.
    assert_eq!(s.hook_count(), 0);
}

#[test]
fn event_hook_system_hooks_for_filters() {
    // Without callable FnPtr, ensure on_event API exists and hooks_for returns empty for unknown.
    let s = EventHookSystem::new();
    assert!(s.hooks_for("any").is_empty());
}

// ─── RustreState ──────────────────────────────────────────────────────────

#[test]
fn rustre_state_default_empty() {
    let s = RustreState::new();
    assert!(s.log_messages.is_empty());
    assert!(s.actions.is_empty());
    assert!(s.event_listeners.is_empty());
}

// ─── RhaiEngine ──────────────────────────────────────────────────────────

#[test]
fn rhai_engine_eval_expr_basic() {
    let e = RhaiEngine::new();
    let d = e.eval_expr("1 + 2").unwrap();
    assert_eq!(d.cast::<i64>(), 3);
}

#[test]
fn rhai_engine_eval_expr_parse_error() {
    let e = RhaiEngine::new();
    let r = e.eval_expr("let x = ;");
    assert!(r.is_err());
}

#[test]
fn rhai_engine_register_and_call() {
    let mut e = RhaiEngine::new();
    e.register_global_fn("double", |x: i64| x * 2);
    let v = e.eval_expr("double(21)").unwrap();
    assert_eq!(v.cast::<i64>(), 42);
}

// ─── RhaiScriptEngine ────────────────────────────────────────────────────

#[test]
fn script_engine_eval_int_float_string_bool() {
    let e = RhaiScriptEngine::new();
    assert_eq!(e.eval_int("5 + 5").unwrap(), 10);
    assert_eq!(e.eval_bool("true && true").unwrap(), true);
    assert_eq!(e.eval_string("\"abc\"").unwrap(), "abc");
    assert!((e.eval_float("1.5 + 2.5").unwrap() - 4.0).abs() < 1e-9);
}

#[test]
fn script_engine_eval_int_from_float() {
    let e = RhaiScriptEngine::new();
    assert_eq!(e.eval_int("3.7").unwrap(), 3);
}

#[test]
fn script_engine_eval_bool_type_error() {
    let e = RhaiScriptEngine::new();
    let r = e.eval_bool("42");
    assert!(matches!(r, Err(ScriptError::TypeError { .. })));
}

#[test]
fn script_engine_eval_with_var() {
    let e = RhaiScriptEngine::new();
    let r = e.eval_with_var("x * 2", "x", 21_i64).unwrap();
    assert_eq!(r.as_int(), Some(42));
}

#[test]
fn script_engine_eval_with_vars_multi() {
    let e = RhaiScriptEngine::new();
    let vars = vec![
        ("a", rhai::Dynamic::from(10_i64)),
        ("b", rhai::Dynamic::from(32_i64)),
    ];
    let r = e.eval_with_vars("a + b", vars).unwrap();
    assert_eq!(r.as_int(), Some(42));
}

#[test]
fn script_engine_compile_and_run_ast() {
    let e = RhaiScriptEngine::new();
    let ast = e.compile("100 - 58").unwrap();
    let r = e.run_ast(&ast).unwrap();
    assert_eq!(r.as_int(), Some(42));
}

#[test]
fn script_engine_compile_error() {
    let e = RhaiScriptEngine::new();
    let r = e.compile("let = 5");
    assert!(matches!(r, Err(ScriptError::Parse(_))));
}

#[test]
fn script_engine_with_rustre_module_log() {
    let e = RhaiScriptEngine::with_rustre_module();
    e.eval("rustre_log(\"hello\")").unwrap();
    assert_eq!(e.log_messages(), vec!["hello".to_string()]);
}

#[test]
fn script_engine_with_re_api_load_binary_error() {
    let e = RhaiScriptEngine::with_re_api();
    // Non-existent file should produce Err (error in eval).
    let r = e.eval("load_binary(\"/definitely/does/not/exist/xyz\")");
    assert!(r.is_err());
}

#[test]
fn script_engine_with_re_api_hex_helpers() {
    let e = RhaiScriptEngine::with_re_api();
    let r = e.eval("hex_to_dec(\"0x2a\")").unwrap();
    assert_eq!(r.as_int(), Some(42));
    let s = e.eval("dec_to_hex(255)").unwrap();
    assert_eq!(s.as_str(), Some("0xff"));
}

#[test]
fn script_engine_threaded_eval_send_sync() {
    let e = Arc::new(RhaiScriptEngine::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let code = format!("{} + {}", t, i);
                let r = e.eval(&code).unwrap();
                assert_eq!(r.as_int(), Some(t + i));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── ScriptError ──────────────────────────────────────────────────────────

#[test]
fn script_error_display_variants() {
    let e = ScriptError::Runtime("oops".into());
    assert!(e.to_string().contains("oops"));
    let e = ScriptError::FunctionNotFound("f".into());
    assert!(e.to_string().contains("f"));
    let e = ScriptError::TypeError {
        expected: "int".into(),
        got: "str".into(),
    };
    let s = e.to_string();
    assert!(s.contains("int") && s.contains("str"));
}

#[test]
fn script_error_io_from() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: ScriptError = io.into();
    assert!(matches!(e, ScriptError::Io(_)));
}

#[test]
fn script_error_into_eval_alt_result() {
    let e = ScriptError::Runtime("boom".into());
    let _b: Box<rhai::EvalAltResult> = e.into();
}

// ─── RustreModule build ──────────────────────────────────────────────────

#[test]
fn rustre_module_build_compiles_and_callable() {
    let mut engine = rhai::Engine::new();
    let m = RustreModule::build();
    engine.register_static_module("rustre", m.into());
    let r: i64 = engine.eval("rustre::utils::hex_decode(\"4142\").len()").unwrap();
    assert_eq!(r, 2);
}

// ─── find_bytes via engine ───────────────────────────────────────────────

#[test]
fn engine_find_bytes_index_and_not_found() {
    let e = RhaiScriptEngine::with_re_api();
    let idx = e
        .eval("find_bytes(hex_decode(\"4142434445\"), hex_decode(\"4344\"))")
        .unwrap();
    assert_eq!(idx.as_int(), Some(2));
    let idx2 = e
        .eval("find_bytes(hex_decode(\"4142\"), hex_decode(\"99\"))")
        .unwrap();
    assert_eq!(idx2.as_int(), Some(-1));
}

#[test]
fn engine_xor_round_trip_in_script() {
    let e = RhaiScriptEngine::with_re_api();
    let r = e
        .eval("hex_encode(xor(xor(hex_decode(\"deadbeef\"), 0x42), 0x42))")
        .unwrap();
    assert_eq!(r.as_str(), Some("deadbeef"));
}

// ─── Boundary: read_bytes via direct impl-equivalent through engine ──────

#[test]
fn engine_count_nonzero() {
    let e = RhaiScriptEngine::with_re_api();
    let r = e
        .eval("count_nonzero(hex_decode(\"0001000200\"))")
        .unwrap();
    assert_eq!(r.as_int(), Some(2));
}
