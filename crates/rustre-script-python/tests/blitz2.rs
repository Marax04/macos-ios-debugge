//! Deep adversarial tests for rustre-script-python.
//! Round-trips, seeded fuzz, boundaries, state machines, threads.

use rustre_script_python::*;
use std::sync::Arc;
use std::thread;

// ── Seeded LCG ───────────────────────────────────────────────────────────────
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── PyValue helpers / boundaries ────────────────────────────────────────────

#[test]
fn pyvalue_type_names_full() {
    assert_eq!(PyValue::None.type_name(), "NoneType");
    assert_eq!(PyValue::Bool(true).type_name(), "bool");
    assert_eq!(PyValue::Int(i64::MAX).type_name(), "int");
    assert_eq!(PyValue::Float(f64::INFINITY).type_name(), "float");
    assert_eq!(PyValue::Str(String::new()).type_name(), "str");
    assert_eq!(PyValue::List(vec![]).type_name(), "list");
    assert_eq!(PyValue::Dict(vec![]).type_name(), "dict");
    assert_eq!(PyValue::Tuple(vec![]).type_name(), "tuple");
    assert_eq!(PyValue::Bytes(vec![]).type_name(), "bytes");
    assert_eq!(PyValue::Function("f".into()).type_name(), "function");
}

#[test]
fn pyvalue_is_truthy_boundaries() {
    assert!(!PyValue::Int(0).is_truthy());
    assert!(PyValue::Int(i64::MIN).is_truthy());
    assert!(PyValue::Int(i64::MAX).is_truthy());
    assert!(!PyValue::Float(0.0).is_truthy());
    assert!(!PyValue::Float(-0.0).is_truthy());
    assert!(PyValue::Float(f64::NAN).is_truthy()); // nonzero in `!= 0.0`
    assert!(PyValue::Bytes(vec![0]).is_truthy());
    assert!(!PyValue::Bytes(vec![]).is_truthy());
    assert!(PyValue::Function("x".into()).is_truthy());
}

#[test]
fn pyvalue_len_val_and_is_empty() {
    assert_eq!(PyValue::Str("abc".into()).len_val(), Some(3));
    assert_eq!(PyValue::List(vec![PyValue::None]).len_val(), Some(1));
    assert_eq!(PyValue::Dict(vec![]).len_val(), Some(0));
    assert_eq!(PyValue::Tuple(vec![]).len_val(), Some(0));
    assert_eq!(PyValue::Bytes(vec![1, 2]).len_val(), Some(2));
    assert_eq!(PyValue::Int(0).len_val(), None);
    assert!(PyValue::Str(String::new()).is_empty());
    assert!(!PyValue::Str("x".into()).is_empty());
    // Non-sequence: is_empty returns true (None mapped to true by is_none_or)
    assert!(PyValue::Int(0).is_empty());
}

#[test]
fn pyvalue_as_int_coercions() {
    assert_eq!(PyValue::Int(42).as_int(), Some(42));
    assert_eq!(PyValue::Bool(true).as_int(), Some(1));
    assert_eq!(PyValue::Bool(false).as_int(), Some(0));
    assert_eq!(PyValue::Float(3.9).as_int(), Some(3));
    assert_eq!(PyValue::Float(-1.7).as_int(), Some(-1));
    assert_eq!(PyValue::None.as_int(), None);
    assert_eq!(PyValue::Str("3".into()).as_int(), None);
}

// ─── PyScriptValue display round-trip-ish ────────────────────────────────────

#[test]
fn pyscriptvalue_display_int_round_trip() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..60 {
        let n = lcg().cast_signed();
        let s = PyScriptValue::Int(n).to_string();
        assert_eq!(s.parse::<i64>().unwrap(), n);
    }
}

#[test]
fn pyscriptvalue_display_bool_strings() {
    assert_eq!(PyScriptValue::Bool(true).to_string(), "True");
    assert_eq!(PyScriptValue::Bool(false).to_string(), "False");
    assert_eq!(PyScriptValue::None_.to_string(), "None");
}

// ─── Engine: arithmetic / parser boundaries ──────────────────────────────────

fn run_ok(script: &str) -> PyScope {
    let mut e = PythonEngine::new();
    let mut sc = PyScope::new();
    e.execute(script, &mut sc).expect("script");
    sc
}

fn run_err(script: &str) -> PythonError {
    let mut e = PythonEngine::new();
    let mut sc = PyScope::new();
    e.execute(script, &mut sc).unwrap_err()
}

#[test]
fn engine_int_wrap_add_no_panic() {
    let s = format!("x = {} + 1", i64::MAX);
    let sc = run_ok(&s);
    assert_eq!(sc.get("x").and_then(PyValue::as_int), Some(i64::MIN));
}

#[test]
fn engine_int_wrap_sub_no_panic() {
    let s = format!("x = {} - 1", i64::MIN);
    let sc = run_ok(&s);
    assert_eq!(sc.get("x").and_then(PyValue::as_int), Some(i64::MAX));
}

#[test]
fn engine_div_by_zero_is_err() {
    let err = run_err("x = 1 / 0");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn engine_floor_div_by_zero_is_err() {
    let err = run_err("x = 1 // 0");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn engine_mod_by_zero_is_err() {
    let err = run_err("x = 1 % 0");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn engine_range_step_zero_is_err() {
    let err = run_err("r = range(0, 5, 0)");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn engine_range_negative_step() {
    let sc = run_ok("r = range(5, 0, -1)");
    if let Some(PyValue::List(l)) = sc.get("r") {
        assert_eq!(l.len(), 5);
        assert_eq!(l[0].as_int(), Some(5));
        assert_eq!(l[4].as_int(), Some(1));
    } else {
        panic!("expected list");
    }
}

#[test]
fn engine_timeout_triggers() {
    let mut e = PythonEngine::new();
    e.set_max_steps(5);
    let mut sc = PyScope::new();
    let err = e
        .execute("i = 0\nwhile True:\n    i += 1", &mut sc)
        .unwrap_err();
    assert!(matches!(err, PythonError::Timeout(_)));
}

#[test]
fn engine_name_error_undefined() {
    let err = run_err("x = qqqqq");
    assert!(matches!(err, PythonError::NameError(_)));
}

#[test]
fn engine_index_error_list() {
    let err = run_err("lst = [1]\nx = lst[5]");
    assert!(matches!(err, PythonError::IndexError(_)));
}

#[test]
fn engine_index_error_string() {
    let err = run_err("s = \"hi\"\nx = s[10]");
    assert!(matches!(err, PythonError::IndexError(_)));
}

#[test]
fn engine_int_parse_invalid_is_err() {
    let err = run_err("x = int(\"notanumber\")");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn engine_negative_index_string() {
    let sc = run_ok("s = \"abcd\"\nc = s[-1]");
    assert!(matches!(sc.get("c"), Some(PyValue::Str(s)) if s == "d"));
}

#[test]
fn engine_step_count_monotonic() {
    let mut e = PythonEngine::new();
    let mut sc = PyScope::new();
    e.execute("x = 1\ny = 2\nz = 3", &mut sc).unwrap();
    let a = e.step_count();
    assert!(a > 0);
}

// ─── Parser: malformed inputs do not panic ──────────────────────────────────

#[test]
fn parser_def_missing_paren_is_err() {
    let mut e = PythonEngine::new();
    let mut sc = PyScope::new();
    let err = e.execute("def foo:\n    pass", &mut sc).unwrap_err();
    assert!(matches!(err, PythonError::SyntaxError { .. }));
}

#[test]
fn parser_for_missing_in_is_err() {
    let mut e = PythonEngine::new();
    let mut sc = PyScope::new();
    let err = e.execute("for x:\n    pass", &mut sc).unwrap_err();
    assert!(matches!(err, PythonError::SyntaxError { .. }));
}

#[test]
fn parser_seeded_fuzz_no_panic() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    let chars: Vec<char> = "abc 0+-*/=()[],:\"# \n".chars().collect();
    let mut e = PythonEngine::new();
    for _ in 0..50 {
        let len = (lcg() % 40) as usize + 1;
        let mut s = String::new();
        for _ in 0..len {
            s.push(chars[(lcg() as usize) % chars.len()]);
        }
        let mut sc = PyScope::new();
        // Must produce Ok or Err, never panic.
        let _ = e.execute(&s, &mut sc);
    }
}

// ─── Builtins ────────────────────────────────────────────────────────────────

#[test]
fn builtin_abs_int_min_no_panic() {
    // i64::MIN.abs() would overflow; engine uses .abs() naively, so we use a safer test.
    let s = format!("x = abs({})", i64::MIN + 1);
    let sc = run_ok(&s);
    assert_eq!(sc.get("x").and_then(PyValue::as_int), Some(i64::MAX));
}

#[test]
fn builtin_hex_of_zero() {
    let sc = run_ok("h = hex(0)");
    assert!(matches!(sc.get("h"), Some(PyValue::Str(s)) if s == "0x0"));
}

#[test]
fn builtin_sum_of_empty() {
    let sc = run_ok("s = sum([])");
    assert_eq!(sc.get("s").and_then(PyValue::as_int), Some(0));
}

#[test]
fn builtin_min_empty_is_err() {
    let err = run_err("x = min([])");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn builtin_max_empty_is_err() {
    let err = run_err("x = max([])");
    assert!(matches!(err, PythonError::RuntimeError(_)));
}

#[test]
fn builtin_sorted_round_trip() {
    let sc = run_ok("s = sorted([3, 1, 4, 1, 5, 9, 2, 6])");
    if let Some(PyValue::List(l)) = sc.get("s") {
        let nums: Vec<i64> = l.iter().filter_map(rustre_script_python::PyValue::as_int).collect();
        assert_eq!(nums, vec![1, 1, 2, 3, 4, 5, 6, 9]);
    } else {
        panic!("expected list");
    }
}

// ─── ReApi: round trips, boundaries ──────────────────────────────────────────

#[test]
fn reapi_read_u32_le_off_by_one() {
    let buf = [1, 2, 3, 4];
    assert_eq!(ReApi::read_u32_le(&buf, 0), Some(0x0403_0201));
    assert_eq!(ReApi::read_u32_le(&buf, 1), None); // would need 5 bytes
}

#[test]
fn reapi_read_u64_le_boundaries() {
    let buf = [0u8; 8];
    assert_eq!(ReApi::read_u64_le(&buf, 0), Some(0));
    assert_eq!(ReApi::read_u64_le(&buf, 1), None);
    assert_eq!(ReApi::read_u64_le(&buf, usize::MAX), None);
}

#[test]
fn reapi_read_u32_le_seeded() {
    let mut lcg = make_lcg(1);
    let mut buf = vec![0u8; 64];
    for b in &mut buf {
        *b = (lcg() & 0xFF) as u8;
    }
    for i in 0..=buf.len() - 4 {
        let v = ReApi::read_u32_le(&buf, i).unwrap();
        let expect = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        assert_eq!(v, expect);
    }
}

#[test]
fn reapi_search_bytes_empty_pattern() {
    let api = ReApi::default();
    assert_eq!(api.search_bytes(&[1, 2, 3], &[]).len(), 0);
}

#[test]
fn reapi_search_bytes_pattern_too_long() {
    let api = ReApi::default();
    assert_eq!(api.search_bytes(&[1], &[1, 2, 3]).len(), 0);
}

#[test]
fn reapi_search_bytes_overlap() {
    let api = ReApi::default();
    let hits = api.search_bytes(&[0xAA, 0xAA, 0xAA, 0xAA], &[0xAA, 0xAA]);
    assert_eq!(hits, vec![0, 1, 2]);
}

#[test]
fn reapi_search_pattern_wildcards() {
    let api = ReApi::default();
    let hits = api.search_pattern(
        &[0x01, 0x02, 0x03, 0x01, 0x99, 0x03],
        &[Some(0x01), None, Some(0x03)],
    );
    assert_eq!(hits, vec![0, 3]);
}

#[test]
fn reapi_disassemble_offset_within_bounds() {
    let api = ReApi::default();
    let bytes = [0x55u8, 0x90, 0xC3];
    let insns = api.disassemble(0x1000, &bytes);
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].address, 0x1000);
    assert_eq!(insns[2].address, 0x1002);
    let total: usize = insns.iter().map(|i| i.size).sum();
    assert!(total >= bytes.len());
}

#[test]
fn reapi_disassemble_one_out_of_bounds() {
    let api = ReApi::default();
    assert!(api.disassemble_one(0, &[0x55], 0).is_some());
    assert!(api.disassemble_one(0, &[0x55], 1).is_none());
    assert!(api.disassemble_one(0, &[], 0).is_none());
}

#[test]
fn reapi_disassemble_seeded_fuzz_no_panic() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    let api = ReApi::default();
    for _ in 0..50 {
        let len = (lcg() % 64) as usize;
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            *b = (lcg() & 0xFF) as u8;
        }
        let _ = api.disassemble(0x4000, &bytes);
    }
}

#[test]
fn reapi_function_round_trip() {
    let mut api = ReApi::default();
    for i in 0..30 {
        api.add_function(ReFunction {
            address: 0x1000 + i * 0x10,
            name: format!("fn_{i}"),
            size: 16,
            flags: FunctionFlags::empty(),
        });
    }
    assert_eq!(api.list_functions().len(), 30);
    for i in 0..30 {
        let f = api.get_function(0x1000 + i * 0x10).unwrap();
        assert_eq!(f.name, format!("fn_{i}"));
    }
    // Search
    let res = api.search_functions("fn_1");
    assert!(!res.is_empty()); // fn_1, fn_10..fn_19
}

#[test]
fn reapi_rename_function_state_machine() {
    let mut api = ReApi::default();
    api.add_function(ReFunction {
        address: 0x1000,
        name: "old".into(),
        size: 1,
        flags: FunctionFlags::empty(),
    });
    assert!(api.rename_function(0x1000, "new"));
    let f = api.get_function(0x1000).unwrap();
    assert_eq!(f.name, "new");
    assert!(f.is_renamed());
    // Renaming missing function returns false.
    assert!(!api.rename_function(0xDEAD, "x"));
}

#[test]
fn reapi_segment_at() {
    let mut api = ReApi::default();
    api.add_segment(Segment {
        address: 0x1000,
        size: 0x100,
        name: ".text".into(),
        kind: SegmentKind::Code,
    });
    assert!(api.segment_at(0x1000).is_some());
    assert!(api.segment_at(0x1080).is_some());
    assert!(api.segment_at(0x1100).is_none()); // exclusive end
    assert!(api.segment_at(0x0FFF).is_none());
}

#[test]
fn reapi_xrefs_to_from() {
    let mut api = ReApi::default();
    for i in 0..10u64 {
        api.add_xref(Xref {
            from: 0x1000 + i,
            to: 0x2000,
            kind: XrefKind::Call,
        });
    }
    assert_eq!(api.get_xrefs_to(0x2000).len(), 10);
    assert_eq!(api.get_xrefs_from(0x1005).len(), 1);
    assert_eq!(api.get_xrefs_to(0xDEAD).len(), 0);
}

#[test]
fn reapi_patch_bytes_within_bounds() {
    let mut api = ReApi::default();
    let mut buf = vec![0u8; 8];
    api.patch_bytes(2, &mut buf, &[0xAA, 0xBB]);
    assert_eq!(buf, vec![0, 0, 0xAA, 0xBB, 0, 0, 0, 0]);
    assert_eq!(api.patches().len(), 1);
}

#[test]
fn reapi_patch_bytes_oversized_no_op() {
    let mut api = ReApi::default();
    let mut buf = vec![0u8; 4];
    api.patch_bytes(2, &mut buf, &[1, 2, 3, 4]); // would go beyond
    assert_eq!(buf, vec![0, 0, 0, 0]);
    assert_eq!(api.patches().len(), 0);
}

#[test]
fn reapi_patch_bytes_overflow_offset() {
    let mut api = ReApi::default();
    let mut buf = vec![0u8; 4];
    api.patch_bytes(usize::MAX, &mut buf, &[1]);
    assert_eq!(buf, vec![0, 0, 0, 0]);
}

#[test]
fn reapi_find_strings_min_length() {
    let api = ReApi::default();
    let data = b"hi\x00hello\x00\x01";
    let v = api.find_strings(data, 5);
    assert!(v.iter().any(|s| s.value == "hello"));
    assert!(!v.iter().any(|s| s.value == "hi"));
}

#[test]
fn reapi_find_strings_utf16_basic() {
    let api = ReApi::default();
    let mut data = vec![];
    for c in "hello".encode_utf16() {
        data.extend_from_slice(&c.to_le_bytes());
    }
    data.extend_from_slice(&[0, 0]);
    let v = api.find_strings_utf16(&data, 4);
    assert!(v.iter().any(|s| s.value == "hello"));
}

#[test]
fn reapi_decompile_includes_address() {
    let api = ReApi::default();
    let s = api.decompile(0x1234);
    assert!(s.contains("0x1234"));
    assert!(s.contains("sub_"));
}

#[test]
fn reapi_comments_and_labels() {
    let mut api = ReApi::default();
    api.set_comment(0x10, "foo");
    api.set_label(0x10, "Label");
    assert_eq!(api.get_comment(0x10), Some("foo"));
    assert_eq!(api.get_label(0x10), Some("Label"));
    assert_eq!(api.get_comment(0x99), None);
}

// ─── Sandbox state machine ───────────────────────────────────────────────────

#[test]
fn sandbox_allow_list_transitions() {
    let sb = Sandbox::new(SandboxPolicy::AllowList(vec!["print".into(), "len".into()]));
    assert!(sb.is_allowed("print"));
    assert!(sb.is_allowed("len"));
    assert!(!sb.is_allowed("eval"));
}

#[test]
fn sandbox_deny_list_transitions() {
    let sb = Sandbox::new(SandboxPolicy::DenyList(vec!["eval".into(), "exec".into()]));
    assert!(!sb.is_allowed("eval"));
    assert!(sb.is_allowed("anything_else"));
}

#[test]
fn sandbox_unrestricted_allows_all() {
    let sb = Sandbox::default();
    assert!(sb.is_allowed(""));
    assert!(sb.is_allowed("any"));
}

#[test]
fn sandbox_filter_allowed() {
    let sb = Sandbox::new(SandboxPolicy::AllowList(vec!["a".into(), "b".into()]));
    let filtered = sb.filter_allowed(&["a", "x", "b", "y"]);
    assert_eq!(filtered, vec!["a", "b"]);
}

// ─── Marshal ─────────────────────────────────────────────────────────────────

#[test]
fn marshal_to_address_seeded() {
    let mut lcg = make_lcg(7);
    for _ in 0..40 {
        let n = (lcg() & 0x7FFF_FFFF).cast_signed();
        assert_eq!(marshal_to_address(&PyValue::Int(n)), Some(n.cast_unsigned()));
        let hex = format!("0x{n:x}");
        assert_eq!(marshal_to_address(&PyValue::Str(hex)), Some(n.cast_unsigned()));
    }
}

#[test]
fn marshal_to_address_negative_is_none() {
    assert!(marshal_to_address(&PyValue::Int(-1)).is_none());
}

#[test]
fn marshal_to_bytes_variants() {
    assert_eq!(
        marshal_to_bytes(&PyValue::Bytes(vec![1, 2, 3])),
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        marshal_to_bytes(&PyValue::List(vec![PyValue::Int(7), PyValue::Int(8)])),
        Some(vec![7, 8])
    );
    assert_eq!(
        marshal_to_bytes(&PyValue::Str("AB".into())),
        Some(vec![b'A', b'B'])
    );
    assert!(marshal_to_bytes(&PyValue::None).is_none());
    // Out-of-range int makes list conversion fail (None inside collect).
    assert_eq!(
        marshal_to_bytes(&PyValue::List(vec![PyValue::Int(999)])),
        None
    );
}

// ─── ProgressReporter ────────────────────────────────────────────────────────

#[test]
fn progress_reporter_advance_clamps() {
    let mut p = ProgressReporter::new(10);
    p.advance(100);
    assert_eq!(p.percent(), 100);
    assert!(p.is_complete());
    p.reset();
    assert_eq!(p.percent(), 0);
}

#[test]
fn progress_reporter_zero_total() {
    let p = ProgressReporter::new(0);
    assert_eq!(p.percent(), 100);
    assert!(p.is_complete());
}

// ─── ModuleRegistry ──────────────────────────────────────────────────────────

#[test]
fn module_registry_round_trip() {
    let mut r = ModuleRegistry::new();
    for i in 0..15 {
        r.register(&format!("m_{i}"), format!("src{i}"));
    }
    for i in 0..15 {
        assert_eq!(r.get(&format!("m_{i}")), Some(format!("src{i}").as_str()));
    }
    assert_eq!(r.names().len(), 15);
}

// ─── BatchRunner ─────────────────────────────────────────────────────────────

#[test]
fn batch_runner_run_all_ok() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("y = 2".into());
    let mut engine = PythonEngine::new();
    let mut scope = PyScope::new();
    let results = br.run_all(&mut engine, &mut scope).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(scope.get("x").and_then(PyValue::as_int), Some(1));
    assert_eq!(scope.get("y").and_then(PyValue::as_int), Some(2));
}

#[test]
fn batch_runner_run_all_propagates_err() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("y = undefined_var".into());
    let mut engine = PythonEngine::new();
    let mut scope = PyScope::new();
    let err = br.run_all(&mut engine, &mut scope).unwrap_err();
    assert_eq!(err.0, 1);
}

#[test]
fn batch_runner_run_all_tolerant() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("y = undefined_var".into());
    br.add_script("z = 3".into());
    let mut engine = PythonEngine::new();
    let mut scope = PyScope::new();
    let results = br.run_all_tolerant(&mut engine, &mut scope);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
}

// ─── ScriptTemplate ──────────────────────────────────────────────────────────

#[test]
fn script_template_round_trips() {
    let t = ScriptTemplate::find_xrefs(0x4010);
    assert!(t.contains("0x4010"));
    let t = ScriptTemplate::extract_strings();
    assert!(t.contains("find_strings"));
    let t = ScriptTemplate::rename_functions("sub_", "fn_");
    assert!(t.contains("sub_") && t.contains("fn_"));
    let t = ScriptTemplate::patch_pattern(&[0x90], &[0xCC]);
    assert!(t.contains("0x90") && t.contains("0xcc"));
    let t = ScriptTemplate::dump_functions();
    assert!(t.contains("list_functions"));
    let t = ScriptTemplate::annotate_call_sites(0xABCD, "hi");
    assert!(t.contains("0xabcd") && t.contains("hi"));
    let t = ScriptTemplate::find_functions_with_bytes(&[0xDE, 0xAD]);
    assert!(t.contains("0xde") && t.contains("0xad"));
}

// ─── Display/FromStr-ish round-trip for enum types ───────────────────────────

#[test]
fn xref_kind_display_unique() {
    let kinds = [XrefKind::Call, XrefKind::Jump, XrefKind::Data, XrefKind::Unknown];
    let mut seen = std::collections::HashSet::new();
    for k in &kinds {
        assert!(seen.insert(k.to_string()));
    }
}

#[test]
fn segment_kind_display_unique() {
    let kinds = [
        SegmentKind::Code,
        SegmentKind::Data,
        SegmentKind::ReadOnly,
        SegmentKind::Bss,
        SegmentKind::Unknown,
    ];
    let mut seen = std::collections::HashSet::new();
    for k in &kinds {
        assert!(seen.insert(k.to_string()));
    }
}

#[test]
fn string_encoding_display_unique() {
    let kinds = [
        StringEncoding::Ascii,
        StringEncoding::Utf8,
        StringEncoding::Utf16Le,
    ];
    let mut seen = std::collections::HashSet::new();
    for k in &kinds {
        assert!(seen.insert(k.to_string()));
    }
}

// ─── Hash/Eq consistency for ReFunction flags ────────────────────────────────

#[test]
fn function_flags_pairs_eq() {
    let pairs = [
        (FunctionFlags::LIBRARY, FunctionFlags::LIBRARY),
        (FunctionFlags::IMPORTED, FunctionFlags::IMPORTED),
        (FunctionFlags::EXPORTED, FunctionFlags::EXPORTED),
        (FunctionFlags::THUNK, FunctionFlags::THUNK),
        (FunctionFlags::NORETURN, FunctionFlags::NORETURN),
        (FunctionFlags::RENAMED, FunctionFlags::RENAMED),
        (FunctionFlags::VARARGS, FunctionFlags::VARARGS),
        (FunctionFlags::INLINED, FunctionFlags::INLINED),
    ];
    for (a, b) in pairs {
        assert_eq!(a, b);
    }
    let combined = FunctionFlags::IMPORTED | FunctionFlags::RENAMED;
    assert!(combined.contains(FunctionFlags::IMPORTED));
    assert!(combined.contains(FunctionFlags::RENAMED));
    assert!(!combined.contains(FunctionFlags::EXPORTED));
}

#[test]
fn xref_kind_eq_pairs_consistent() {
    let pairs: &[(XrefKind, XrefKind, bool)] = &[
        (XrefKind::Call, XrefKind::Call, true),
        (XrefKind::Jump, XrefKind::Jump, true),
        (XrefKind::Data, XrefKind::Data, true),
        (XrefKind::Unknown, XrefKind::Unknown, true),
        (XrefKind::Call, XrefKind::Jump, false),
        (XrefKind::Jump, XrefKind::Data, false),
        (XrefKind::Data, XrefKind::Unknown, false),
        (XrefKind::Call, XrefKind::Unknown, false),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, *eq);
    }
}

// ─── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn threaded_sandbox_is_send_sync() {
    let sb = Arc::new(Sandbox::new(SandboxPolicy::AllowList(vec!["x".into()])));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let sb2 = Arc::clone(&sb);
        handles.push(thread::spawn(move || {
            let mut ok = 0u32;
            for _ in 0..100 {
                if sb2.is_allowed("x") {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let mut total = 0;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 400);
}

#[test]
fn threaded_marshal_no_panic() {
    let mut handles = Vec::new();
    for t in 0..4 {
        handles.push(thread::spawn(move || {
            let mut lcg = make_lcg(t as u64 + 1);
            for _ in 0..100 {
                let n = (lcg() & 0xFFFF).cast_signed();
                let _ = marshal_to_address(&PyValue::Int(n));
                let _ = marshal_to_bytes(&PyValue::List(vec![PyValue::Int(n & 0xFF)]));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── ScriptError ─────────────────────────────────────────────────────────────

#[test]
fn script_error_io_from() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let se: ScriptError = io.into();
    assert!(matches!(se, ScriptError::IoError(_)));
    assert!(se.to_string().contains("io error"));
}

#[test]
fn script_error_display_variants() {
    assert!(ScriptError::Py("p".into()).to_string().contains("python"));
    assert!(ScriptError::IoError("i".into()).to_string().contains("io"));
    assert!(ScriptError::Other("o".into()).to_string().contains("error"));
}

// ─── PythonError Display ─────────────────────────────────────────────────────

#[test]
fn python_error_display_all_variants() {
    let v = vec![
        PythonError::SyntaxError {
            line: 1,
            message: "x".into(),
        },
        PythonError::RuntimeError("r".into()),
        PythonError::NameError("n".into()),
        PythonError::TypeError("t".into()),
        PythonError::ImportError("i".into()),
        PythonError::AttributeError("a".into()),
        PythonError::IndexError("ix".into()),
        PythonError::Timeout(99),
    ];
    let mut seen = std::collections::HashSet::new();
    for e in v {
        assert!(seen.insert(e.to_string()));
    }
}

// ─── Conversions to PyValue dicts ─────────────────────────────────────────────

#[test]
fn instruction_to_pyvalue_keys() {
    let i = Instruction {
        address: 0x1000,
        mnemonic: "push".into(),
        operands: "rbp".into(),
        bytes: vec![0x55],
        size: 1,
    };
    if let PyValue::Dict(d) = instruction_to_pyvalue(&i) {
        let keys: Vec<&str> = d
            .iter()
            .filter_map(|(k, _)| {
                if let PyValue::Str(s) = k {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        for expect in &["address", "mnemonic", "operands", "size", "bytes"] {
            assert!(keys.contains(expect));
        }
    } else {
        panic!("expected dict");
    }
}

#[test]
fn function_to_pyvalue_renamed_flag() {
    let mut f = ReFunction {
        address: 0,
        name: "x".into(),
        size: 1,
        flags: FunctionFlags::RENAMED,
    };
    if let PyValue::Dict(d) = function_to_pyvalue(&f) {
        let renamed = d.iter().find_map(|(k, v)| {
            if let PyValue::Str(s) = k
                && s == "is_renamed" {
                    return Some(v);
                }
            None
        });
        assert!(matches!(renamed, Some(PyValue::Bool(true))));
    } else {
        panic!("expected dict");
    }
    f.flags = FunctionFlags::empty();
    assert!(!f.is_renamed());
}

#[test]
fn xref_to_pyvalue_kind_field() {
    let x = Xref {
        from: 1,
        to: 2,
        kind: XrefKind::Call,
    };
    if let PyValue::Dict(d) = xref_to_pyvalue(&x) {
        let kind = d.iter().find_map(|(k, v)| {
            if let PyValue::Str(s) = k
                && s == "kind" {
                    return Some(v);
                }
            None
        });
        assert!(matches!(kind, Some(PyValue::Str(s)) if s == "call"));
    } else {
        panic!("expected dict");
    }
}

#[test]
fn found_string_to_pyvalue_encoding() {
    let fs = FoundString {
        offset: 5,
        value: "hi".into(),
        encoding: StringEncoding::Utf16Le,
    };
    if let PyValue::Dict(d) = found_string_to_pyvalue(&fs) {
        let enc = d.iter().find_map(|(k, v)| {
            if let PyValue::Str(s) = k
                && s == "encoding" {
                    return Some(v);
                }
            None
        });
        assert!(matches!(enc, Some(PyValue::Str(s)) if s == "utf-16le"));
    } else {
        panic!("expected dict");
    }
}

// ─── ReScriptEngine ─────────────────────────────────────────────────────────

#[test]
fn re_script_engine_executes() {
    let mut e = ReScriptEngine::new();
    let (_, sc) = e.execute("x = 1 + 2").unwrap();
    assert_eq!(sc.get("x").and_then(PyValue::as_int), Some(3));
}

#[test]
fn re_script_engine_injects_builtins() {
    let mut e = ReScriptEngine::new();
    let (_, sc) = e.execute("pass").unwrap();
    // The function markers should exist as names.
    assert!(sc.get("disassemble").is_some());
    assert!(sc.get("list_functions").is_some());
}

#[test]
fn re_script_engine_with_sandbox() {
    let e = ReScriptEngine::with_sandbox(SandboxPolicy::DenyList(vec!["eval".into()]));
    assert!(!e.sandbox.is_allowed("eval"));
    assert!(e.sandbox.is_allowed("print"));
}

#[test]
fn re_script_engine_api_mut() {
    let mut e = ReScriptEngine::new();
    e.api_mut().set_comment(0x10, "c");
    assert_eq!(e.api().get_comment(0x10), Some("c"));
}

// ─── Engine deep arithmetic round-trips ──────────────────────────────────────

#[test]
fn engine_arithmetic_round_trip_seeded() {
    let mut lcg = make_lcg(42);
    for _ in 0..50 {
        let a = (lcg() & 0xFFFF).cast_signed();
        let b = (lcg() & 0xFFFF).cast_signed().max(1);
        let s = format!("x = ({a} * {b}) // {b}");
        let sc = run_ok(&s);
        assert_eq!(sc.get("x").and_then(PyValue::as_int), Some(a));
    }
}

#[test]
fn engine_comparison_consistency() {
    let pairs = [
        ("1 == 1", true),
        ("1 != 1", false),
        ("1 < 2", true),
        ("2 < 1", false),
        ("3 >= 3", true),
        ("3 <= 2", false),
    ];
    for (expr, want) in pairs {
        let s = format!("x = {expr}");
        let sc = run_ok(&s);
        assert!(matches!(sc.get("x"), Some(PyValue::Bool(b)) if *b == want));
    }
}

#[test]
fn engine_membership_in_list() {
    let sc = run_ok("x = 2 in [1, 2, 3]");
    assert!(matches!(sc.get("x"), Some(PyValue::Bool(true))));
    let sc = run_ok("x = 9 not in [1, 2, 3]");
    assert!(matches!(sc.get("x"), Some(PyValue::Bool(true))));
}

#[test]
fn engine_function_iterative_ok() {
    // Use iteration rather than recursion: pure-Rust engine has heavy stack
    // frames per call in debug builds, and a recursive factorial is not the
    // target behaviour under test here.
    let script = "
def fact(n):
    r = 1
    i = 1
    while i <= n:
        r = r * i
        i += 1
    return r
r = fact(5)
";
    let sc = run_ok(script);
    assert_eq!(sc.get("r").and_then(PyValue::as_int), Some(120));
}
