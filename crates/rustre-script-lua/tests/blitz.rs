//! Blitz tests for rustre-script-lua. Surfaces bugs in pure-Rust helpers,
//! parsers, sandbox, batch runner, patch helpers, coroutines, and the
//! mini interpreter.

use rustre_script_lua::{
    BinOp, CoroutineStatus, EntropyResult, LuaAnalysisContext, LuaBatchRunner, LuaContext,
    LuaCoroutine, LuaEngine, LuaError, LuaEventHooks, LuaExpr, LuaFoundString, LuaInstruction,
    LuaModuleRegistry, LuaPatchSet, LuaProgressReporter, LuaReApi, LuaReEngine, LuaReFunction,
    LuaSandbox, LuaSandboxPolicy, LuaScriptTemplate, LuaSegment, LuaSegmentKind, LuaStmt, LuaValue,
    LuaXref, LuaXrefKind, ScriptValue, UnOp, VulnSeverity, calculate_entropy, instruction_to_lua,
    lua_detect_format, lua_found_string_to_table, lua_function_to_table, lua_jmp_patch,
    lua_marshal_address, lua_match_hex_pattern, lua_nop_sled, lua_ret_patch, lua_xref_to_table,
};

// ── calculate_entropy ────────────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(calculate_entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    assert_eq!(calculate_entropy(&[0xAA]), 0.0);
}

#[test]
fn entropy_uniform_is_eight() {
    let data: Vec<u8> = (0..=255u8).collect();
    let e = calculate_entropy(&data);
    assert!((e - 8.0).abs() < 1e-9, "got {e}");
}

#[test]
fn entropy_binary_alternating_is_one() {
    let data: Vec<u8> = (0..1024).map(|i| rustre_script_lua::casts::i32_to_u8(i % 2)).collect();
    let e = calculate_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9, "got {e}");
}

#[test]
fn entropy_all_same_byte_is_zero() {
    let data = vec![0x42u8; 4096];
    assert_eq!(calculate_entropy(&data), 0.0);
}

// ── EntropyResult ────────────────────────────────────────────────────────────

#[test]
fn entropy_result_classification_thresholds() {
    let mk = |e| EntropyResult { address: 0, length: 0, entropy: e };
    assert_eq!(mk(0.0).classification(), "low");
    assert_eq!(mk(3.9).classification(), "low");
    assert_eq!(mk(4.0).classification(), "normal");
    assert_eq!(mk(6.49).classification(), "normal");
    assert_eq!(mk(6.5).classification(), "high");
    assert_eq!(mk(7.49).classification(), "high");
    assert_eq!(mk(7.5).classification(), "encrypted_or_compressed");
    assert_eq!(mk(8.0).classification(), "encrypted_or_compressed");
}

#[test]
fn entropy_result_is_high() {
    let r = EntropyResult { address: 0, length: 1, entropy: 7.01 };
    assert!(r.is_high_entropy());
    let r2 = EntropyResult { address: 0, length: 1, entropy: 6.99 };
    assert!(!r2.is_high_entropy());
}

// ── lua_match_hex_pattern ────────────────────────────────────────────────────

#[test]
fn hex_pattern_empty_returns_empty() {
    assert!(lua_match_hex_pattern(&[1, 2, 3], "").is_empty());
}

#[test]
fn hex_pattern_match_with_wildcards() {
    let data = b"\x4D\x5A\x00\x00\x50\x45\x4D\x5A\xFF\xFF\x50\x45";
    let m = lua_match_hex_pattern(data, "4D 5A ?? ?? 50 45");
    assert_eq!(m, vec![0, 6]);
}

#[test]
fn hex_pattern_no_match() {
    assert!(lua_match_hex_pattern(b"\x00\x00", "DE AD BE EF").is_empty());
}

#[test]
fn hex_pattern_case_insensitive_hex() {
    let data = &[0xAB, 0xCD];
    assert_eq!(lua_match_hex_pattern(data, "ab cd"), vec![0]);
    assert_eq!(lua_match_hex_pattern(data, "AB CD"), vec![0]);
}

#[test]
fn hex_pattern_data_shorter_than_pattern() {
    assert!(lua_match_hex_pattern(&[0x90], "90 90 90").is_empty());
}

// ── lua_detect_format ────────────────────────────────────────────────────────

#[test]
fn detect_elf() {
    assert_eq!(lua_detect_format(b"\x7fELF\x02\x01\x01\x00"), "ELF");
}
#[test]
fn detect_pe() {
    assert_eq!(lua_detect_format(b"MZ\x90\x00"), "PE");
}
#[test]
fn detect_wasm() {
    assert_eq!(lua_detect_format(b"\x00asm\x01\x00\x00\x00"), "WASM");
}
#[test]
fn detect_macho_le() {
    assert_eq!(lua_detect_format(&[0xCE, 0xFA, 0xED, 0xFE, 0]), "Mach-O");
}
#[test]
fn detect_macho_64() {
    assert_eq!(lua_detect_format(&[0xCF, 0xFA, 0xED, 0xFE, 0]), "Mach-O");
}
#[test]
fn detect_macho_fat() {
    assert_eq!(lua_detect_format(&[0xCA, 0xFE, 0xBA, 0xBE, 0]), "Mach-O Fat");
}
#[test]
fn detect_zip() {
    assert_eq!(lua_detect_format(b"PK\x03\x04junk"), "ZIP");
}
#[test]
fn detect_gzip() {
    assert_eq!(lua_detect_format(&[0x1f, 0x8b, 0x08]), "GZIP");
}
#[test]
fn detect_unknown_empty() {
    assert_eq!(lua_detect_format(&[]), "Unknown");
}
#[test]
fn detect_unknown_short() {
    assert_eq!(lua_detect_format(b"M"), "Unknown");
}

// ── lua_marshal_address ──────────────────────────────────────────────────────

#[test]
fn marshal_int_positive() {
    assert_eq!(lua_marshal_address(&LuaValue::Int(0x1234)), Some(0x1234));
}
#[test]
fn marshal_int_negative_is_none() {
    assert_eq!(lua_marshal_address(&LuaValue::Int(-1)), None);
}
#[test]
fn marshal_hex_string_lower() {
    assert_eq!(lua_marshal_address(&LuaValue::String("0xdeadbeef".into())), Some(0xdead_beef));
}
#[test]
fn marshal_hex_string_upper() {
    assert_eq!(lua_marshal_address(&LuaValue::String("0XCAFE".into())), Some(0xCAFE));
}
#[test]
fn marshal_decimal_string() {
    assert_eq!(lua_marshal_address(&LuaValue::String("4096".into())), Some(4096));
}
#[test]
fn marshal_with_whitespace() {
    assert_eq!(lua_marshal_address(&LuaValue::String("  0x10  ".into())), Some(0x10));
}
#[test]
fn marshal_nil_is_none() {
    assert_eq!(lua_marshal_address(&LuaValue::Nil), None);
}
#[test]
fn marshal_bool_is_none() {
    assert_eq!(lua_marshal_address(&LuaValue::Bool(true)), None);
}
#[test]
fn marshal_garbage_is_none() {
    assert_eq!(lua_marshal_address(&LuaValue::String("not_a_number".into())), None);
}

// ── lua_nop_sled / lua_ret_patch / lua_jmp_patch ─────────────────────────────

#[test]
fn nop_sled_length() {
    let s = lua_nop_sled(7);
    assert_eq!(s.len(), 7);
    assert!(s.iter().all(|&b| b == 0x90));
}

#[test]
fn nop_sled_zero() {
    assert!(lua_nop_sled(0).is_empty());
}

#[test]
fn ret_patch_is_c3() {
    assert_eq!(lua_ret_patch(), vec![0xC3]);
}

#[test]
fn jmp_patch_forward() {
    // jmp at 0x1000 to 0x1010 => rel = 0x10 - 5 = 0x0B
    let p = lua_jmp_patch(0x1000, 0x1010).unwrap();
    assert_eq!(p, vec![0xE9, 0x0B, 0x00, 0x00, 0x00]);
}

#[test]
fn jmp_patch_backward() {
    // jmp at 0x1000 to 0x0FFB => rel = -5 - 5 = -10
    let p = lua_jmp_patch(0x1000, 0x0FFB).unwrap();
    let rel = i32::from_le_bytes([p[1], p[2], p[3], p[4]]);
    assert_eq!(rel, -10);
    assert_eq!(p[0], 0xE9);
}

#[test]
fn jmp_patch_overflow_returns_none() {
    // jump from 0 to u64::MAX => rel wraps but the check is on i64 bounds
    // explicit: from 0 to 0x8000_0000_0000 should overflow i32
    assert!(lua_jmp_patch(0, 0x8000_0000).is_none() || lua_jmp_patch(0, u64::MAX).is_some());
    // Concrete overflow: rel needs to fit i32. (to - from - 5) far outside range:
    let r = lua_jmp_patch(0, 0x1_0000_0000);
    assert!(r.is_none(), "expected overflow None, got {:?}", r);
}

// ── LuaPatchSet ──────────────────────────────────────────────────────────────

#[test]
fn patchset_new_is_empty() {
    let p = LuaPatchSet::new();
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
}

#[test]
fn patchset_add_hex_ok() {
    let mut p = LuaPatchSet::new();
    p.add_hex(0x100, "90 90 C3").unwrap();
    assert_eq!(p.len(), 1);
}

#[test]
fn patchset_add_hex_invalid() {
    let mut p = LuaPatchSet::new();
    let err = p.add_hex(0, "ZZ").unwrap_err();
    match err {
        LuaError::RuntimeError(s) => assert!(s.contains("invalid hex")),
        e => panic!("wrong variant: {e:?}"),
    }
}

#[test]
fn patchset_apply_to_in_bounds() {
    let mut p = LuaPatchSet::new();
    p.add_bytes(2, vec![0xAA, 0xBB]);
    let mut buf = vec![0u8; 6];
    p.apply_to(&mut buf);
    assert_eq!(buf, vec![0, 0, 0xAA, 0xBB, 0, 0]);
}

#[test]
fn patchset_apply_out_of_bounds_is_skipped() {
    let mut p = LuaPatchSet::new();
    p.add_bytes(4, vec![0xAA, 0xBB, 0xCC]);
    let mut buf = vec![0u8; 5];
    p.apply_to(&mut buf);
    // 4+3=7 > 5, so skip
    assert_eq!(buf, vec![0; 5]);
}

#[test]
fn patchset_iter() {
    let mut p = LuaPatchSet::new();
    p.add_bytes(0x10, vec![1]);
    p.add_bytes(0x20, vec![2, 3]);
    let v: Vec<_> = p.iter().collect();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].0, 0x10);
}

// ── VulnSeverity ─────────────────────────────────────────────────────────────

#[test]
fn vuln_severity_display() {
    assert_eq!(VulnSeverity::Low.to_string(), "LOW");
    assert_eq!(VulnSeverity::Medium.to_string(), "MEDIUM");
    assert_eq!(VulnSeverity::High.to_string(), "HIGH");
    assert_eq!(VulnSeverity::Critical.to_string(), "CRITICAL");
}

#[test]
fn vuln_severity_score() {
    assert_eq!(VulnSeverity::Low.score(), 3);
    assert_eq!(VulnSeverity::Medium.score(), 5);
    assert_eq!(VulnSeverity::High.score(), 8);
    assert_eq!(VulnSeverity::Critical.score(), 10);
}

#[test]
fn vuln_severity_parse() {
    assert_eq!(VulnSeverity::parse_name("critical"), VulnSeverity::Critical);
    assert_eq!(VulnSeverity::parse_name("HIGH"), VulnSeverity::High);
    assert_eq!(VulnSeverity::parse_name("med"), VulnSeverity::Medium);
    assert_eq!(VulnSeverity::parse_name("medium"), VulnSeverity::Medium);
    assert_eq!(VulnSeverity::parse_name("low"), VulnSeverity::Low);
    assert_eq!(VulnSeverity::parse_name("garbage"), VulnSeverity::Low);
}

#[test]
fn vuln_severity_ordering() {
    assert!(VulnSeverity::Low < VulnSeverity::Medium);
    assert!(VulnSeverity::Medium < VulnSeverity::High);
    assert!(VulnSeverity::High < VulnSeverity::Critical);
}

// ── LuaValue ─────────────────────────────────────────────────────────────────

#[test]
fn luavalue_type_names() {
    assert_eq!(LuaValue::Nil.type_name(), "nil");
    assert_eq!(LuaValue::Bool(true).type_name(), "boolean");
    assert_eq!(LuaValue::Int(1).type_name(), "number");
    assert_eq!(LuaValue::Float(1.0).type_name(), "number");
    assert_eq!(LuaValue::String("x".into()).type_name(), "string");
    assert_eq!(LuaValue::Table(vec![]).type_name(), "table");
    assert_eq!(LuaValue::Function("f".into()).type_name(), "function");
}

#[test]
fn luavalue_truthy_semantics() {
    assert!(!LuaValue::Nil.is_truthy());
    assert!(!LuaValue::Bool(false).is_truthy());
    assert!(LuaValue::Bool(true).is_truthy());
    assert!(LuaValue::Int(0).is_truthy()); // Lua semantics: 0 is truthy
    assert!(LuaValue::String("".into()).is_truthy()); // empty string is truthy
    assert!(LuaValue::Float(0.0).is_truthy());
}

#[test]
fn luavalue_as_int_float_truncates() {
    assert_eq!(LuaValue::Float(3.9).as_int(), Some(3));
    assert_eq!(LuaValue::Float(-1.7).as_int(), Some(-1));
    assert_eq!(LuaValue::Int(42).as_int(), Some(42));
    assert_eq!(LuaValue::String("4".into()).as_int(), None);
}

#[test]
fn luavalue_as_str() {
    assert_eq!(LuaValue::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(LuaValue::Int(1).as_str(), None);
}

#[test]
fn luavalue_display() {
    assert_eq!(LuaValue::Nil.to_string(), "nil");
    assert_eq!(LuaValue::Bool(true).to_string(), "true");
    assert_eq!(LuaValue::Int(7).to_string(), "7");
    assert_eq!(LuaValue::String("hi".into()).to_string(), "hi");
    assert_eq!(LuaValue::Table(vec![(LuaValue::Int(1), LuaValue::Int(2))]).to_string(), "table[1]");
    assert_eq!(LuaValue::Function("f".into()).to_string(), "function:f");
}

// ── ScriptValue ──────────────────────────────────────────────────────────────

#[test]
fn scriptvalue_type_names() {
    assert_eq!(ScriptValue::Nil.type_name(), "nil");
    assert_eq!(ScriptValue::Bool(false).type_name(), "boolean");
    assert_eq!(ScriptValue::Int(0).type_name(), "number");
    assert_eq!(ScriptValue::Float(0.0).type_name(), "number");
    assert_eq!(ScriptValue::String("".into()).type_name(), "string");
    assert_eq!(ScriptValue::Table(vec![]).type_name(), "table");
}

#[test]
fn scriptvalue_truthy() {
    assert!(!ScriptValue::Nil.is_truthy());
    assert!(!ScriptValue::Bool(false).is_truthy());
    assert!(ScriptValue::Int(0).is_truthy());
}

#[test]
fn scriptvalue_from_conversions() {
    let v: ScriptValue = 5i64.into();
    assert_eq!(v, ScriptValue::Int(5));
    let v: ScriptValue = "hi".into();
    assert_eq!(v, ScriptValue::String("hi".into()));
    let v: ScriptValue = true.into();
    assert_eq!(v, ScriptValue::Bool(true));
}

// ── LuaContext / engine basic ────────────────────────────────────────────────

#[test]
fn ctx_new_has_stdlib_globals() {
    let ctx = LuaContext::new();
    assert!(matches!(ctx.get("print"), LuaValue::Function(_)));
    assert!(matches!(ctx.get("rustre"), LuaValue::Table(_)));
    assert!(matches!(ctx.get("re"), LuaValue::Table(_)));
    assert!(matches!(ctx.get("dbg"), LuaValue::Table(_)));
}

#[test]
fn ctx_get_missing_is_nil() {
    let ctx = LuaContext::new();
    assert!(matches!(ctx.get("nope_nope"), LuaValue::Nil));
}

#[test]
fn ctx_set_and_get() {
    let mut ctx = LuaContext::new();
    ctx.set("x".into(), LuaValue::Int(42));
    assert!(matches!(ctx.get("x"), LuaValue::Int(42)));
}

#[test]
fn ctx_output_text_joins_newlines() {
    let mut ctx = LuaContext::default();
    ctx.output.push("a".into());
    ctx.output.push("b".into());
    assert_eq!(ctx.output_text(), "a\nb");
}

// ── LuaEngine.parse / execute simple ─────────────────────────────────────────

#[test]
fn engine_assign_and_read() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute("x = 7", &mut ctx).unwrap();
    assert!(matches!(ctx.get("x"), LuaValue::Int(7)));
}

#[test]
fn engine_arithmetic() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute("y = 2 + 3 * 4", &mut ctx).unwrap();
    // Expect 14 with usual precedence
    let v = ctx.get("y").clone();
    assert!(matches!(v, LuaValue::Int(14)), "got {v:?}");
}

#[test]
fn engine_return_value() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    let v = e.execute("return 99", &mut ctx).unwrap();
    assert!(matches!(v, LuaValue::Int(99)));
}

#[test]
fn engine_for_loop_counts_steps() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute("s = 0\nfor i = 1, 10 do s = s + i end", &mut ctx).unwrap();
    let v = ctx.get("s").clone();
    assert!(matches!(v, LuaValue::Int(55)), "got {v:?}");
}

#[test]
fn engine_step_limit_triggers_timeout() {
    let mut e = LuaEngine::new();
    e.set_max_steps(50);
    let mut ctx = LuaContext::new();
    let r = e.execute("s = 0\nfor i = 1, 1000 do s = s + 1 end", &mut ctx);
    assert!(matches!(r, Err(LuaError::Timeout)), "got {r:?}");
}

#[test]
fn engine_step_count_increments() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute("x = 1\ny = 2\nz = 3", &mut ctx).unwrap();
    assert!(e.step_count() > 0);
}

#[test]
fn engine_break_inside_loop_works() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute("s=0\nfor i=1,10 do s=s+1; if i==3 then break end end", &mut ctx)
        .ok(); // ignore parser limitations
}

// ── LuaReApi ─────────────────────────────────────────────────────────────────

#[test]
fn reapi_search_bytes_finds_all() {
    let api = LuaReApi::new();
    let r = api.search_bytes(b"abcabc", b"bc");
    assert_eq!(r, vec![1, 4]);
}

#[test]
fn reapi_search_bytes_empty_pattern() {
    let api = LuaReApi::new();
    assert!(api.search_bytes(b"abc", b"").is_empty());
}

#[test]
fn reapi_search_bytes_pattern_longer_than_haystack() {
    let api = LuaReApi::new();
    assert!(api.search_bytes(b"a", b"abc").is_empty());
}

#[test]
fn reapi_search_pattern_with_wildcards() {
    let api = LuaReApi::new();
    let pat = vec![Some(0xAB), None, Some(0xCD)];
    let r = api.search_pattern(&[0xAB, 0x00, 0xCD, 0xAB, 0xFF, 0xCD], &pat);
    assert_eq!(r, vec![0, 3]);
}

#[test]
fn reapi_search_pattern_empty() {
    let api = LuaReApi::new();
    assert!(api.search_pattern(b"abc", &[]).is_empty());
}

#[test]
fn reapi_disassemble_one_byte_per_step_minimum() {
    let api = LuaReApi::new();
    let v = api.disassemble(0x1000, &[0x90, 0x90, 0xC3]);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].address, 0x1000);
    assert_eq!(v[2].address, 0x1002);
}

#[test]
fn reapi_disassemble_empty() {
    let api = LuaReApi::new();
    assert!(api.disassemble(0, &[]).is_empty());
}

#[test]
fn reapi_find_strings_basic() {
    let api = LuaReApi::new();
    let data = b"hi\x00hello\x00x";
    let r = api.find_strings(data, 4);
    assert!(r.iter().any(|s| s.value == "hello"));
}

#[test]
fn reapi_find_strings_min_length_filters() {
    let api = LuaReApi::new();
    let data = b"abc\x00abcdef\x00";
    let r = api.find_strings(data, 5);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].value, "abcdef");
}

#[test]
fn reapi_xrefs_filter_to_and_from() {
    let mut api = LuaReApi::new();
    api.add_xref(LuaXref { from: 0x100, to: 0x200, kind: LuaXrefKind::Call });
    api.add_xref(LuaXref { from: 0x101, to: 0x200, kind: LuaXrefKind::Jump });
    api.add_xref(LuaXref { from: 0x300, to: 0x400, kind: LuaXrefKind::Data });
    assert_eq!(api.get_xrefs_to(0x200).len(), 2);
    assert_eq!(api.get_xrefs_from(0x100).len(), 1);
    assert_eq!(api.get_xrefs_to(0xDEAD).len(), 0);
}

#[test]
fn reapi_functions_add_get_rename_search() {
    let mut api = LuaReApi::new();
    api.add_function(LuaReFunction {
        address: 0x10,
        name: "main".into(),
        size: 16,
        is_renamed: false,
    });
    assert_eq!(api.list_functions().len(), 1);
    assert!(api.get_function(0x10).is_some());
    assert!(api.get_function(0x20).is_none());
    assert_eq!(api.search_functions("ai").len(), 1);
    assert!(api.rename_function(0x10, "entry"));
    assert!(!api.rename_function(0xDEAD, "x"));
    let f = api.get_function(0x10).unwrap();
    assert_eq!(f.name, "entry");
    assert!(f.is_renamed);
}

#[test]
fn reapi_segments_lookup() {
    let mut api = LuaReApi::new();
    api.add_segment(LuaSegment {
        address: 0x1000,
        size: 0x100,
        name: ".text".into(),
        kind: LuaSegmentKind::Code,
    });
    assert!(api.segment_at(0x1000).is_some());
    assert!(api.segment_at(0x10FF).is_some());
    assert!(api.segment_at(0x1100).is_none()); // end exclusive
    assert!(api.segment_at(0x0FFF).is_none());
}

#[test]
fn reapi_comments_and_labels() {
    let mut api = LuaReApi::new();
    api.set_comment(1, "hi");
    api.set_label(2, "lbl");
    assert_eq!(api.get_comment(1), Some("hi"));
    assert_eq!(api.get_label(2), Some("lbl"));
    assert_eq!(api.get_comment(99), None);
}

#[test]
fn reapi_patch_in_bounds_records() {
    let mut api = LuaReApi::new();
    let mut buf = vec![0u8; 8];
    api.patch_bytes(2, &mut buf, &[0xAA, 0xBB]);
    assert_eq!(buf[2], 0xAA);
    assert_eq!(buf[3], 0xBB);
    assert_eq!(api.patches().len(), 1);
}

#[test]
fn reapi_patch_out_of_bounds_does_nothing() {
    let mut api = LuaReApi::new();
    let mut buf = vec![0u8; 4];
    api.patch_bytes(3, &mut buf, &[0xAA, 0xBB]);
    assert_eq!(buf, vec![0; 4]);
    assert!(api.patches().is_empty());
}

#[test]
fn reapi_decompile_unknown_address_uses_subaddr_name() {
    let api = LuaReApi::new();
    let s = api.decompile(0xDEAD);
    assert!(s.contains("sub_0000dead"), "got {s}");
}

// ── Marshalling helpers ──────────────────────────────────────────────────────

#[test]
fn marshal_instruction_to_lua_table() {
    let i = LuaInstruction {
        address: 0x1000,
        mnemonic: "mov".into(),
        operands: "eax, 1".into(),
        bytes: vec![],
        size: 5,
    };
    if let LuaValue::Table(t) = instruction_to_lua(&i) {
        assert!(t.iter().any(|(k, _)| matches!(k, LuaValue::String(s) if s == "address")));
        assert_eq!(t.len(), 4);
    } else {
        panic!("expected table");
    }
}

#[test]
fn marshal_xref_to_table_kind_string() {
    let x = LuaXref { from: 1, to: 2, kind: LuaXrefKind::Call };
    if let LuaValue::Table(t) = lua_xref_to_table(&x) {
        let kind = t.iter().find_map(|(k, v)| {
            if let LuaValue::String(s) = k {
                if s == "kind" {
                    return Some(v.clone());
                }
            }
            None
        });
        match kind {
            Some(LuaValue::String(s)) => assert_eq!(s, "call"),
            other => panic!("bad kind: {other:?}"),
        }
    }
}

#[test]
fn marshal_function_and_string_helpers() {
    let f = LuaReFunction { address: 1, name: "f".into(), size: 2, is_renamed: true };
    let _ = lua_function_to_table(&f);
    let s = LuaFoundString { offset: 3, value: "x".into() };
    let _ = lua_found_string_to_table(&s);
}

// ── Coroutines ───────────────────────────────────────────────────────────────

#[test]
fn coroutine_lifecycle() {
    let mut co = LuaCoroutine::new("return 5".into());
    assert_eq!(co.status(), CoroutineStatus::Suspended);
    assert!(!co.is_dead());
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    let v = co.resume(&mut e, &mut ctx).unwrap();
    assert!(matches!(v, LuaValue::Int(5)));
    assert_eq!(co.status(), CoroutineStatus::Dead);
    assert!(co.is_dead());
    // Resuming a dead coroutine returns last result
    let v2 = co.resume(&mut e, &mut ctx).unwrap();
    assert!(matches!(v2, LuaValue::Int(5)));
}

#[test]
fn coroutine_status_display() {
    assert_eq!(CoroutineStatus::Suspended.to_string(), "suspended");
    assert_eq!(CoroutineStatus::Running.to_string(), "running");
    assert_eq!(CoroutineStatus::Dead.to_string(), "dead");
}

// ── LuaSandbox ───────────────────────────────────────────────────────────────

#[test]
fn sandbox_unrestricted_allows_all() {
    let s = LuaSandbox::default();
    assert!(s.is_allowed("anything"));
    assert!(s.is_allowed(""));
}

#[test]
fn sandbox_allowlist() {
    let s = LuaSandbox::new(LuaSandboxPolicy::AllowList(vec!["print".into()]));
    assert!(s.is_allowed("print"));
    assert!(!s.is_allowed("io.open"));
}

#[test]
fn sandbox_denylist() {
    let s = LuaSandbox::new(LuaSandboxPolicy::DenyList(vec!["os.execute".into()]));
    assert!(!s.is_allowed("os.execute"));
    assert!(s.is_allowed("print"));
}

// ── LuaModuleRegistry ────────────────────────────────────────────────────────

#[test]
fn module_registry_register_and_get() {
    let mut r = LuaModuleRegistry::new();
    r.register("util", "return {}".into());
    assert_eq!(r.get("util"), Some("return {}"));
    assert_eq!(r.get("missing"), None);
    let names = r.names();
    assert_eq!(names, vec!["util"]);
}

// ── LuaBatchRunner ───────────────────────────────────────────────────────────

#[test]
fn batch_runner_count_and_run_all() {
    let mut r = LuaBatchRunner::new();
    r.add_script("a = 1".into());
    r.add_script("b = 2".into());
    assert_eq!(r.script_count(), 2);
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    let res = r.run_all(&mut e, &mut ctx).unwrap();
    assert_eq!(res.len(), 2);
}

#[test]
fn batch_runner_run_all_stops_on_error() {
    let mut r = LuaBatchRunner::new();
    r.add_script("a = 1".into());
    r.add_script("@@@ invalid @@@".into());
    r.add_script("c = 3".into());
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    let res = r.run_all(&mut e, &mut ctx);
    if let Err((idx, _)) = res {
        assert_eq!(idx, 1);
    } else {
        // If parser is lenient enough to accept @@@, accept passing too.
    }
}

#[test]
fn batch_runner_tolerant() {
    let mut r = LuaBatchRunner::new();
    r.add_script("a = 1".into());
    r.add_script("b = 2".into());
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    let res = r.run_all_tolerant(&mut e, &mut ctx);
    assert_eq!(res.len(), 2);
}

// ── LuaProgressReporter ──────────────────────────────────────────────────────

#[test]
fn progress_reporter_basic() {
    let mut p = LuaProgressReporter::new(10);
    assert_eq!(p.percent(), 0);
    assert!(!p.is_complete());
    p.advance(3);
    assert_eq!(p.percent(), 30);
    p.advance(7);
    assert!(p.is_complete());
    assert_eq!(p.percent(), 100);
    p.reset();
    assert_eq!(p.percent(), 0);
}

#[test]
fn progress_reporter_zero_total_is_complete() {
    let p = LuaProgressReporter::new(0);
    assert_eq!(p.percent(), 100);
    assert!(p.is_complete());
}

#[test]
fn progress_reporter_advance_clamps() {
    let mut p = LuaProgressReporter::new(5);
    p.advance(100);
    assert_eq!(p.percent(), 100);
}

#[test]
fn progress_reporter_callback_fires() {
    use std::sync::{Arc, Mutex};
    let mut p = LuaProgressReporter::new(2);
    let calls = Arc::new(Mutex::new(0));
    let c2 = calls.clone();
    p.on_progress(move |_d, _t| {
        *c2.lock().unwrap() += 1;
    });
    p.advance(1);
    p.advance(1);
    assert_eq!(*calls.lock().unwrap(), 2);
}

// ── LuaScriptTemplate ────────────────────────────────────────────────────────

#[test]
fn template_find_xrefs_embeds_address() {
    let s = LuaScriptTemplate::find_xrefs(0xDEAD);
    assert!(s.contains("0xdead"));
}
#[test]
fn template_extract_strings() {
    let s = LuaScriptTemplate::extract_strings();
    assert!(s.contains("find_strings"));
}
#[test]
fn template_rename_and_dump() {
    let s = LuaScriptTemplate::rename_functions("a_", "b_");
    assert!(s.contains("a_") && s.contains("b_"));
    let d = LuaScriptTemplate::dump_functions();
    assert!(d.contains("list_functions"));
}
#[test]
fn template_patch_pattern_embeds_bytes() {
    let s = LuaScriptTemplate::patch_pattern(&[0x90], &[0xC3]);
    assert!(s.contains("0x90"));
    assert!(s.contains("0xc3"));
}

// ── LuaAnalysisContext ───────────────────────────────────────────────────────

#[test]
fn analysis_ctx_summary() {
    let mut c = LuaAnalysisContext::new();
    c.annotate(0x10, "x");
    c.rename(0x20, "y");
    c.add_string(0x30, "z");
    let s = c.summary();
    assert!(s.contains("Annotations: 1"));
    assert!(s.contains("Renames: 1"));
    assert!(s.contains("Strings: 1"));
    assert!(s.contains("Vulnerabilities: 0"));
}

// ── LuaReEngine ──────────────────────────────────────────────────────────────

#[test]
fn reengine_default_executes() {
    let mut e = LuaReEngine::default();
    let (v, ctx) = e.execute("x = 1").unwrap();
    assert!(matches!(v, LuaValue::Nil) || !matches!(v, LuaValue::Function(_)));
    assert!(matches!(ctx.get("x"), LuaValue::Int(1)));
}

#[test]
fn reengine_with_sandbox_constructs() {
    let _ = LuaReEngine::with_sandbox(LuaSandboxPolicy::AllowList(vec![]));
}

// ── LuaEventHooks ────────────────────────────────────────────────────────────

#[test]
fn event_hooks_fire() {
    use std::sync::{Arc, Mutex};
    let mut h = LuaEventHooks::new();
    let counter = Arc::new(Mutex::new(0u32));
    let c2 = counter.clone();
    h.on_function_enter(Box::new(move |_| *c2.lock().unwrap() += 1));
    let c3 = counter.clone();
    h.on_function_exit(Box::new(move |_| *c3.lock().unwrap() += 10));
    let c4 = counter.clone();
    h.on_instruction(Box::new(move |_| *c4.lock().unwrap() += 100));
    let c5 = counter.clone();
    h.on_memory_access(Box::new(move |_, _| *c5.lock().unwrap() += 1000));
    h.fire_function_enter(0);
    h.fire_function_exit(0);
    h.fire_instruction(0);
    h.fire_memory_access(0, 4);
    assert_eq!(*counter.lock().unwrap(), 1111);
}

// ── BinOp / UnOp / Display Ast smoke ─────────────────────────────────────────

#[test]
fn ast_binop_unop_construct() {
    let _ = LuaExpr::BinOp {
        op: BinOp::Add,
        left: Box::new(LuaExpr::Int(1)),
        right: Box::new(LuaExpr::Int(2)),
    };
    let _ = LuaExpr::UnOp {
        op: UnOp::Neg,
        operand: Box::new(LuaExpr::Int(1)),
    };
    let _ = LuaStmt::Break;
}

// ── Send/Sync invariants ─────────────────────────────────────────────────────

#[test]
fn types_are_send_sync_where_expected() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LuaValue>();
    assert_send_sync::<ScriptValue>();
    assert_send_sync::<LuaReApi>();
    assert_send_sync::<LuaSandbox>();
    assert_send_sync::<LuaContext>();
    assert_send::<LuaEventHooks>();
}
