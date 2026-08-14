//! Exhaustive blitz tests for rustre-script-python.
//! Focuses on pure-Rust APIs (no Python interpreter init required) to surface bugs.

use rustre_script_python::*;

// ─── PyScriptValue ───────────────────────────────────────────────────────────
#[test]
fn pyscriptvalue_type_names() {
    assert_eq!(PyScriptValue::None_.type_name(), "NoneType");
    assert_eq!(PyScriptValue::Bool(true).type_name(), "bool");
    assert_eq!(PyScriptValue::Int(0).type_name(), "int");
    assert_eq!(PyScriptValue::Float(0.0).type_name(), "float");
    assert_eq!(PyScriptValue::Str(String::new()).type_name(), "str");
    assert_eq!(PyScriptValue::List(vec![]).type_name(), "list");
    assert_eq!(PyScriptValue::Dict(vec![]).type_name(), "dict");
}

#[test]
fn pyscriptvalue_is_none() {
    assert!(PyScriptValue::None_.is_none());
    assert!(!PyScriptValue::Bool(false).is_none());
}

#[test]
fn pyscriptvalue_as_bool() {
    assert_eq!(PyScriptValue::Bool(true).as_bool(), Some(true));
    assert_eq!(PyScriptValue::Int(0).as_bool(), None);
}

#[test]
fn pyscriptvalue_as_int_includes_bool() {
    assert_eq!(PyScriptValue::Int(42).as_int(), Some(42));
    assert_eq!(PyScriptValue::Bool(true).as_int(), Some(1));
    assert_eq!(PyScriptValue::Bool(false).as_int(), Some(0));
    assert_eq!(PyScriptValue::Float(1.5).as_int(), None);
}

#[test]
fn pyscriptvalue_as_float() {
    assert_eq!(PyScriptValue::Float(1.5).as_float(), Some(1.5));
    assert_eq!(PyScriptValue::Int(2).as_float(), Some(2.0));
    assert_eq!(PyScriptValue::Str("3".into()).as_float(), None);
}

#[test]
fn pyscriptvalue_as_str() {
    assert_eq!(PyScriptValue::Str("hi".into()).as_str(), Some("hi"));
    assert_eq!(PyScriptValue::Int(1).as_str(), None);
}

#[test]
fn pyscriptvalue_display_bool_python_style() {
    assert_eq!(format!("{}", PyScriptValue::Bool(true)), "True");
    assert_eq!(format!("{}", PyScriptValue::Bool(false)), "False");
    assert_eq!(format!("{}", PyScriptValue::None_), "None");
}

#[test]
fn pyscriptvalue_display_list() {
    let v = PyScriptValue::List(vec![PyScriptValue::Int(1), PyScriptValue::Int(2)]);
    assert_eq!(format!("{v}"), "[1, 2]");
}

#[test]
fn pyscriptvalue_eq() {
    assert_eq!(PyScriptValue::Int(1), PyScriptValue::Int(1));
    assert_ne!(PyScriptValue::Int(1), PyScriptValue::Bool(true));
}

#[test]
fn pyscriptvalue_json_roundtrip() {
    let v = PyScriptValue::List(vec![
        PyScriptValue::Int(1),
        PyScriptValue::Str("x".into()),
        PyScriptValue::None_,
    ]);
    let s = serde_json::to_string(&v).unwrap();
    let v2: PyScriptValue = serde_json::from_str(&s).unwrap();
    assert_eq!(v, v2);
}

// ─── ScriptError ─────────────────────────────────────────────────────────────
#[test]
fn script_error_display() {
    assert!(ScriptError::Py("e".into()).to_string().contains("python error"));
    assert!(ScriptError::IoError("e".into()).to_string().contains("io error"));
    assert!(ScriptError::Other("e".into()).to_string().contains("error"));
}

#[test]
fn script_error_from_io() {
    let e = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let s: ScriptError = e.into();
    assert!(matches!(s, ScriptError::IoError(_)));
}

// ─── PyValue ─────────────────────────────────────────────────────────────────
#[test]
fn pyvalue_type_names_all_variants() {
    assert_eq!(PyValue::None.type_name(), "NoneType");
    assert_eq!(PyValue::Bool(true).type_name(), "bool");
    assert_eq!(PyValue::Int(1).type_name(), "int");
    assert_eq!(PyValue::Float(1.0).type_name(), "float");
    assert_eq!(PyValue::Str("x".into()).type_name(), "str");
    assert_eq!(PyValue::List(vec![]).type_name(), "list");
    assert_eq!(PyValue::Dict(vec![]).type_name(), "dict");
    assert_eq!(PyValue::Tuple(vec![]).type_name(), "tuple");
    assert_eq!(PyValue::Bytes(vec![]).type_name(), "bytes");
    assert_eq!(PyValue::Function("f".into()).type_name(), "function");
}

#[test]
fn pyvalue_truthiness() {
    assert!(!PyValue::None.is_truthy());
    assert!(!PyValue::Bool(false).is_truthy());
    assert!(PyValue::Bool(true).is_truthy());
    assert!(!PyValue::Int(0).is_truthy());
    assert!(PyValue::Int(-1).is_truthy());
    assert!(!PyValue::Float(0.0).is_truthy());
    assert!(PyValue::Float(0.1).is_truthy());
    assert!(!PyValue::Str(String::new()).is_truthy());
    assert!(PyValue::Str("x".into()).is_truthy());
    assert!(!PyValue::List(vec![]).is_truthy());
    assert!(PyValue::List(vec![PyValue::None]).is_truthy());
    assert!(!PyValue::Dict(vec![]).is_truthy());
    assert!(!PyValue::Tuple(vec![]).is_truthy());
    assert!(!PyValue::Bytes(vec![]).is_truthy());
    assert!(PyValue::Function("f".into()).is_truthy());
}

#[test]
fn pyvalue_as_int_conversions() {
    assert_eq!(PyValue::Int(5).as_int(), Some(5));
    assert_eq!(PyValue::Bool(true).as_int(), Some(1));
    assert_eq!(PyValue::Float(3.7).as_int(), Some(3));
    assert_eq!(PyValue::Str("4".into()).as_int(), None);
}

#[test]
fn pyvalue_len_val() {
    assert_eq!(PyValue::Str("abc".into()).len_val(), Some(3));
    assert_eq!(PyValue::List(vec![PyValue::None; 4]).len_val(), Some(4));
    assert_eq!(PyValue::Bytes(vec![0; 7]).len_val(), Some(7));
    assert_eq!(PyValue::Int(0).len_val(), None);
}

#[test]
fn pyvalue_is_empty_semantics() {
    // is_empty uses is_none_or, so non-sized values like Int are "empty"
    assert!(PyValue::Str(String::new()).is_empty());
    assert!(!PyValue::Str("x".into()).is_empty());
    assert!(PyValue::List(vec![]).is_empty());
    // Int has no len; current code reports empty via is_none_or
    assert!(PyValue::Int(0).is_empty());
}

#[test]
fn pyvalue_display() {
    assert_eq!(PyValue::None.to_string(), "None");
    assert_eq!(PyValue::Bool(true).to_string(), "True");
    assert_eq!(PyValue::Int(7).to_string(), "7");
    assert_eq!(PyValue::Str("hi".into()).to_string(), "hi");
    assert_eq!(PyValue::Function("g".into()).to_string(), "<function g>");
}

// ─── PyScope ─────────────────────────────────────────────────────────────────
#[test]
fn pyscope_default_and_new() {
    let s = PyScope::new();
    // Built-ins registered
    assert!(s.get("print").is_some());
    assert!(s.get("len").is_some());
    // Constants
    assert!(matches!(s.get("True"), Some(PyValue::Bool(true))));
    assert!(matches!(s.get("False"), Some(PyValue::Bool(false))));
    assert!(matches!(s.get("None"), Some(PyValue::None)));
}

#[test]
fn pyscope_set_get() {
    let mut s = PyScope::new();
    s.set("x".into(), PyValue::Int(42));
    assert!(matches!(s.get("x"), Some(PyValue::Int(42))));
}

#[test]
fn pyscope_output_text() {
    let mut s = PyScope::new();
    s.output.push("a".into());
    s.output.push("b".into());
    assert_eq!(s.output_text(), "a\nb");
}

// ─── PythonEngine ────────────────────────────────────────────────────────────
#[test]
fn engine_new_defaults() {
    let e = PythonEngine::new();
    assert_eq!(e.step_count(), 0);
}

#[test]
fn engine_set_max_steps() {
    let mut e = PythonEngine::new();
    e.set_max_steps(5);
    let mut scope = PyScope::new();
    // infinite-like loop should hit timeout
    let r = e.execute("while True:\n    x = 1", &mut scope);
    assert!(matches!(r, Err(PythonError::Timeout(_))), "got {r:?}");
}

#[test]
fn engine_assignment() {
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    e.execute("x = 5", &mut s).unwrap();
    assert!(matches!(s.get("x"), Some(PyValue::Int(5))));
}

#[test]
fn engine_aug_assign_add() {
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    e.execute("x = 1\nx += 2", &mut s).unwrap();
    assert!(matches!(s.get("x"), Some(PyValue::Int(3))));
}

#[test]
fn engine_if_else() {
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    e.execute("x = 0\nif True:\n    x = 1\nelse:\n    x = 2", &mut s).unwrap();
    assert!(matches!(s.get("x"), Some(PyValue::Int(1))));
}

#[test]
fn engine_pass() {
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    e.execute("pass", &mut s).unwrap();
}

#[test]
fn engine_parse_error_propagates() {
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    // def without parens
    let r = e.execute("def foo:\n    pass", &mut s);
    assert!(matches!(r, Err(PythonError::SyntaxError { .. })));
}

#[test]
fn engine_parse_ok_smoke() {
    let e = PythonEngine::new();
    let stmts = e.parse("x = 1\ny = 2").unwrap();
    assert_eq!(stmts.len(), 2);
}

#[test]
fn engine_default_impl() {
    let _ = PythonEngine::default();
}

// ─── Instruction / Xref / Segment / FoundString display ──────────────────────
#[test]
fn instruction_display() {
    let i = Instruction {
        address: 0x1000,
        mnemonic: "mov".into(),
        operands: "rax, rbx".into(),
        bytes: vec![0x48, 0x89, 0xD8],
        size: 3,
    };
    let s = i.to_string();
    assert!(s.contains("0x00001000"));
    assert!(s.contains("mov"));
    assert!(s.contains("rax, rbx"));
}

#[test]
fn xref_kind_display_and_eq() {
    assert_eq!(XrefKind::Call.to_string(), "call");
    assert_eq!(XrefKind::Jump.to_string(), "jump");
    assert_eq!(XrefKind::Data.to_string(), "data");
    assert_eq!(XrefKind::Unknown.to_string(), "unknown");
    assert_eq!(XrefKind::Call, XrefKind::Call);
    assert_ne!(XrefKind::Call, XrefKind::Jump);
}

#[test]
fn segment_kind_display() {
    assert_eq!(SegmentKind::Code.to_string(), "code");
    assert_eq!(SegmentKind::Data.to_string(), "data");
    assert_eq!(SegmentKind::ReadOnly.to_string(), "rodata");
    assert_eq!(SegmentKind::Bss.to_string(), "bss");
    assert_eq!(SegmentKind::Unknown.to_string(), "unknown");
}

#[test]
fn string_encoding_display() {
    assert_eq!(StringEncoding::Ascii.to_string(), "ascii");
    assert_eq!(StringEncoding::Utf8.to_string(), "utf-8");
    assert_eq!(StringEncoding::Utf16Le.to_string(), "utf-16le");
}

// ─── ReFunction & FunctionFlags ──────────────────────────────────────────────
#[test]
fn refunction_flag_helpers() {
    let f = ReFunction {
        address: 0x400,
        name: "foo".into(),
        size: 10,
        flags: FunctionFlags::RENAMED | FunctionFlags::IMPORTED,
    };
    assert!(f.is_renamed());
    assert!(f.is_imported());
    assert!(!f.is_noreturn());
}

#[test]
fn refunction_display() {
    let f = ReFunction {
        address: 0x100,
        name: "bar".into(),
        size: 8,
        flags: FunctionFlags::empty(),
    };
    let s = f.to_string();
    assert!(s.contains("0x00000100"));
    assert!(s.contains("bar"));
    assert!(s.contains("8 bytes"));
}

// ─── ReApi: disassembly ──────────────────────────────────────────────────────
#[test]
fn reapi_disassemble_empty() {
    let api = ReApi::new();
    assert!(api.disassemble(0, &[]).is_empty());
}

#[test]
fn reapi_disassemble_known_opcodes() {
    let api = ReApi::new();
    let bytes = [0x55u8, 0x90, 0xC3]; // push rbp, nop, ret
    let v = api.disassemble(0x1000, &bytes);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].mnemonic, "push");
    assert_eq!(v[1].mnemonic, "nop");
    assert_eq!(v[2].mnemonic, "ret");
    assert_eq!(v[0].address, 0x1000);
    assert_eq!(v[1].address, 0x1001);
}

#[test]
fn reapi_disassemble_one_oob() {
    let api = ReApi::new();
    assert!(api.disassemble_one(0, &[0x90], 5).is_none());
}

#[test]
fn reapi_disassemble_one_truncates_size() {
    // 0xE8 (call) claims size 5 but buffer has only 1 byte; must clamp
    let api = ReApi::new();
    let one = api.disassemble_one(0, &[0xE8], 0).unwrap();
    assert_eq!(one.size, 1);
    assert_eq!(one.bytes.len(), 1);
}

// ─── ReApi: read_u32_le / read_u64_le ────────────────────────────────────────
#[test]
fn reapi_read_u32_basic_and_bounds() {
    assert_eq!(ReApi::read_u32_le(&[1, 0, 0, 0], 0), Some(1));
    assert_eq!(ReApi::read_u32_le(&[0, 0, 0, 0xFF], 0), Some(0xFF00_0000));
    assert_eq!(ReApi::read_u32_le(&[1, 2, 3], 0), None);
    assert_eq!(ReApi::read_u32_le(&[1, 2, 3, 4], 1), None);
}

#[test]
fn reapi_read_u32_overflow_offset() {
    let buf = [0u8; 4];
    assert_eq!(ReApi::read_u32_le(&buf, usize::MAX - 2), None);
}

#[test]
fn reapi_read_u64_basic_and_bounds() {
    let buf = [1, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(ReApi::read_u64_le(&buf, 0), Some(1));
    assert_eq!(ReApi::read_u64_le(&buf[..7], 0), None);
}

// ─── ReApi: patches ──────────────────────────────────────────────────────────
#[test]
fn reapi_patch_bytes_in_range() {
    let mut api = ReApi::new();
    let mut buf = vec![0u8; 4];
    api.patch_bytes(1, &mut buf, &[0xAA, 0xBB]);
    assert_eq!(buf, vec![0, 0xAA, 0xBB, 0]);
    assert_eq!(api.patches().len(), 1);
    assert_eq!(api.patches()[0], (1, vec![0xAA, 0xBB]));
}

#[test]
fn reapi_patch_bytes_out_of_range_no_op() {
    let mut api = ReApi::new();
    let mut buf = vec![0u8; 2];
    api.patch_bytes(1, &mut buf, &[1, 2, 3]); // would extend past end
    assert_eq!(buf, vec![0, 0]);
    assert!(api.patches().is_empty());
}

#[test]
fn reapi_patch_bytes_offset_overflow() {
    let mut api = ReApi::new();
    let mut buf = vec![0u8; 4];
    api.patch_bytes(usize::MAX, &mut buf, &[1, 2]);
    assert_eq!(buf, vec![0, 0, 0, 0]);
}

// ─── ReApi: search ───────────────────────────────────────────────────────────
#[test]
fn reapi_search_bytes_basic() {
    let api = ReApi::new();
    assert_eq!(api.search_bytes(b"abcabc", b"abc"), vec![0, 3]);
    assert!(api.search_bytes(b"abc", b"xyz").is_empty());
    assert!(api.search_bytes(b"", b"a").is_empty());
    assert!(api.search_bytes(b"abc", b"").is_empty());
}

#[test]
fn reapi_search_bytes_pattern_larger_than_haystack() {
    let api = ReApi::new();
    assert!(api.search_bytes(b"ab", b"abcd").is_empty());
}

#[test]
fn reapi_search_bytes_overlap() {
    let api = ReApi::new();
    // overlapping matches should both be found
    assert_eq!(api.search_bytes(b"aaaa", b"aa"), vec![0, 1, 2]);
}

#[test]
fn reapi_search_pattern_with_wildcards() {
    let api = ReApi::new();
    let pat = [Some(0x48), None, Some(0xC3)];
    let haystack = [0x48, 0x89, 0xC3, 0x48, 0xFF, 0xC3];
    let r = api.search_pattern(&haystack, &pat);
    assert_eq!(r, vec![0, 3]);
}

#[test]
fn reapi_search_pattern_empty() {
    let api = ReApi::new();
    assert!(api.search_pattern(b"abc", &[]).is_empty());
}

// ─── ReApi: find_strings ─────────────────────────────────────────────────────
#[test]
fn reapi_find_strings_basic() {
    let api = ReApi::new();
    let buf = b"hello\x00world\x00";
    let r = api.find_strings(buf, 4);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].value, "hello");
    assert_eq!(r[0].offset, 0);
    assert_eq!(r[1].value, "world");
}

#[test]
fn reapi_find_strings_min_length_filter() {
    let api = ReApi::new();
    let buf = b"hi\x00toolong\x00";
    let r = api.find_strings(buf, 5);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].value, "toolong");
}

#[test]
fn reapi_find_strings_trailing_no_null() {
    let api = ReApi::new();
    let r = api.find_strings(b"abcdef", 3);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].value, "abcdef");
}

#[test]
fn reapi_find_strings_empty_buffer() {
    let api = ReApi::new();
    assert!(api.find_strings(b"", 1).is_empty());
}

#[test]
fn reapi_find_strings_utf16_basic() {
    let api = ReApi::new();
    // "Hi" in UTF-16LE: 0x48 0x00 0x69 0x00 then null terminator 0x00 0x00
    let buf = b"H\x00i\x00\x00\x00";
    let r = api.find_strings_utf16(buf, 2);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].value, "Hi");
    assert_eq!(r[0].encoding, StringEncoding::Utf16Le);
}

#[test]
fn reapi_find_strings_utf16_too_short_buffer() {
    let api = ReApi::new();
    assert!(api.find_strings_utf16(&[0x41], 1).is_empty());
}

// ─── ReApi: xrefs, functions, segments, comments, labels ─────────────────────
#[test]
fn reapi_xrefs_round_trip() {
    let mut api = ReApi::new();
    api.add_xref(Xref { from: 0x1, to: 0x10, kind: XrefKind::Call });
    api.add_xref(Xref { from: 0x2, to: 0x10, kind: XrefKind::Jump });
    api.add_xref(Xref { from: 0x1, to: 0x20, kind: XrefKind::Data });
    assert_eq!(api.get_xrefs_to(0x10).len(), 2);
    assert_eq!(api.get_xrefs_from(0x1).len(), 2);
    assert!(api.get_xrefs_to(0xDEAD).is_empty());
}

#[test]
fn reapi_function_add_list_get_rename() {
    let mut api = ReApi::new();
    api.add_function(ReFunction {
        address: 0x400,
        name: "foo".into(),
        size: 32,
        flags: FunctionFlags::empty(),
    });
    assert_eq!(api.list_functions().len(), 1);
    assert!(api.get_function(0x400).is_some());
    assert!(api.get_function(0x500).is_none());
    assert!(api.rename_function(0x400, "bar"));
    let f = api.get_function(0x400).unwrap();
    assert_eq!(f.name, "bar");
    assert!(f.is_renamed());
    assert!(!api.rename_function(0xDEAD, "x"));
}

#[test]
fn reapi_search_functions_substr() {
    let mut api = ReApi::new();
    for (a, n) in [(1u64, "alpha"), (2, "beta"), (3, "alphabet")] {
        api.add_function(ReFunction {
            address: a,
            name: n.into(),
            size: 0,
            flags: FunctionFlags::empty(),
        });
    }
    assert_eq!(api.search_functions("alpha").len(), 2);
    assert_eq!(api.search_functions("zzz").len(), 0);
}

#[test]
fn reapi_segment_at() {
    let mut api = ReApi::new();
    api.add_segment(Segment {
        address: 0x1000,
        size: 0x100,
        name: ".text".into(),
        kind: SegmentKind::Code,
    });
    assert!(api.segment_at(0x1000).is_some());
    assert!(api.segment_at(0x10FF).is_some());
    assert!(api.segment_at(0x1100).is_none()); // end-exclusive
    assert!(api.segment_at(0x0FFF).is_none());
    assert_eq!(api.list_segments().len(), 1);
}

#[test]
fn reapi_comments_and_labels() {
    let mut api = ReApi::new();
    api.set_comment(0x100, "hello");
    api.set_label(0x100, "L1");
    assert_eq!(api.get_comment(0x100), Some("hello"));
    assert_eq!(api.get_label(0x100), Some("L1"));
    assert!(api.get_comment(0x200).is_none());
    // Overwrite
    api.set_comment(0x100, "world");
    assert_eq!(api.get_comment(0x100), Some("world"));
}

#[test]
fn reapi_read_bytes_zero_filled() {
    let api = ReApi::new();
    let r = api.read_bytes(0, 5);
    assert_eq!(r, vec![0u8; 5]);
}

// ─── ReApi: decompile ────────────────────────────────────────────────────────
#[test]
fn reapi_decompile_unknown_address_default_name() {
    let api = ReApi::new();
    let s = api.decompile(0xDEAD);
    assert!(s.contains("sub_0000dead"));
    assert!(s.contains("int64_t"));
    assert!(s.contains("return 0"));
}

#[test]
fn reapi_decompile_uses_function_metadata() {
    let mut api = ReApi::new();
    api.add_function(ReFunction {
        address: 0x100,
        name: "myfunc".into(),
        size: 42,
        flags: FunctionFlags::NORETURN | FunctionFlags::IMPORTED,
    });
    let s = api.decompile(0x100);
    assert!(s.contains("myfunc"));
    assert!(s.contains("noreturn"));
    assert!(s.contains("imported"));
    assert!(s.contains("size=42"));
}

// ─── ReApi: analyse ──────────────────────────────────────────────────────────
#[test]
fn reapi_analyse_basic() {
    let api = ReApi::new();
    let bytes = [0x55u8, 0x90, 0xC3]; // 3 instructions, no strings
    let r = api.analyse(0, &bytes);
    assert_eq!(r.instruction_count, 3);
    assert_eq!(r.strings.len(), r.string_count);
}

// ─── Sandbox ─────────────────────────────────────────────────────────────────
#[test]
fn sandbox_allow_list() {
    let sb = Sandbox::new(SandboxPolicy::AllowList(vec!["print".into(), "len".into()]));
    assert!(sb.is_allowed("print"));
    assert!(!sb.is_allowed("eval"));
}

#[test]
fn sandbox_deny_list() {
    let sb = Sandbox::new(SandboxPolicy::DenyList(vec!["eval".into()]));
    assert!(sb.is_allowed("print"));
    assert!(!sb.is_allowed("eval"));
}

#[test]
fn sandbox_unrestricted_default() {
    let sb = Sandbox::default();
    assert!(sb.is_allowed("anything"));
}

#[test]
fn sandbox_filter_allowed() {
    let sb = Sandbox::new(SandboxPolicy::DenyList(vec!["bad".into()]));
    let out = sb.filter_allowed(&["good", "bad", "ok"]);
    assert_eq!(out, vec!["good", "ok"]);
}

// ─── ModuleRegistry ──────────────────────────────────────────────────────────
#[test]
fn module_registry_register_get_names() {
    let mut r = ModuleRegistry::new();
    r.register("mod1", "content1".into());
    r.register("mod2", "content2".into());
    assert_eq!(r.get("mod1"), Some("content1"));
    assert!(r.get("nope").is_none());
    let mut names = r.names();
    names.sort_unstable();
    assert_eq!(names, vec!["mod1", "mod2"]);
}

// ─── BatchRunner ─────────────────────────────────────────────────────────────
#[test]
fn batch_runner_run_all_success() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("y = 2".into());
    assert_eq!(br.script_count(), 2);
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    let r = br.run_all(&mut e, &mut s).unwrap();
    assert_eq!(r.len(), 2);
}

#[test]
fn batch_runner_run_all_reports_failing_index() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("def bad:\n    pass".into()); // syntax error
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    let r = br.run_all(&mut e, &mut s);
    let (idx, _err) = r.unwrap_err();
    assert_eq!(idx, 1);
}

#[test]
fn batch_runner_tolerant() {
    let mut br = BatchRunner::new();
    br.add_script("x = 1".into());
    br.add_script("def bad:\n    pass".into());
    br.add_script("y = 2".into());
    let mut e = PythonEngine::new();
    let mut s = PyScope::new();
    let r = br.run_all_tolerant(&mut e, &mut s);
    assert_eq!(r.len(), 3);
    assert!(r[0].is_ok());
    assert!(r[1].is_err());
    assert!(r[2].is_ok());
}

// ─── ProgressReporter ────────────────────────────────────────────────────────
#[test]
fn progress_reporter_basic() {
    let mut p = ProgressReporter::new(10);
    assert_eq!(p.percent(), 0);
    assert!(!p.is_complete());
    p.advance(3);
    assert_eq!(p.percent(), 30);
    p.advance(7);
    assert!(p.is_complete());
    assert_eq!(p.percent(), 100);
    p.advance(5); // saturate at total
    assert!(p.is_complete());
    p.reset();
    assert_eq!(p.percent(), 0);
}

#[test]
fn progress_reporter_zero_total_is_100() {
    let p = ProgressReporter::new(0);
    assert_eq!(p.percent(), 100);
    assert!(p.is_complete());
}

#[test]
fn progress_reporter_callbacks_fire() {
    use std::sync::{Arc, Mutex};
    let mut p = ProgressReporter::new(4);
    let log = Arc::new(Mutex::new(Vec::<(usize, usize)>::new()));
    let log2 = Arc::clone(&log);
    p.on_progress(move |d, t| log2.lock().unwrap().push((d, t)));
    p.advance(1);
    p.advance(2);
    let l = log.lock().unwrap();
    assert_eq!(*l, vec![(1, 4), (3, 4)]);
}

// ─── ScriptTemplate ──────────────────────────────────────────────────────────
#[test]
fn script_template_find_xrefs_contains_addr() {
    let s = ScriptTemplate::find_xrefs(0x1234);
    assert!(s.contains("0x1234"));
    assert!(s.contains("get_xrefs_to"));
}

#[test]
fn script_template_extract_strings_contains_loop() {
    let s = ScriptTemplate::extract_strings();
    assert!(s.contains("find_strings"));
    assert!(s.contains("for s in"));
}

#[test]
fn script_template_rename_functions_uses_prefix_len() {
    let s = ScriptTemplate::rename_functions("old_", "new_");
    assert!(s.contains("rename_function"));
    assert!(s.contains("old_"));
    assert!(s.contains("new_"));
    assert!(s.contains("[4:]")); // prefix_len = 4
}

#[test]
fn script_template_patch_pattern() {
    let s = ScriptTemplate::patch_pattern(&[0x90], &[0xCC]);
    assert!(s.contains("0x90"));
    assert!(s.contains("0xcc"));
    assert!(s.contains("search_bytes"));
}

#[test]
fn script_template_dump_functions() {
    let s = ScriptTemplate::dump_functions();
    assert!(s.contains("list_functions"));
}

#[test]
fn script_template_annotate_call_sites() {
    let s = ScriptTemplate::annotate_call_sites(0xAA, "hi");
    assert!(s.contains("0xaa"));
    assert!(s.contains("set_comment"));
    assert!(s.contains("hi"));
}

#[test]
fn script_template_find_functions_with_bytes() {
    let s = ScriptTemplate::find_functions_with_bytes(&[0xDE, 0xAD]);
    assert!(s.contains("0xde"));
    assert!(s.contains("0xad"));
}

// ─── Marshalling helpers ─────────────────────────────────────────────────────
#[test]
fn marshal_to_address_int() {
    assert_eq!(marshal_to_address(&PyValue::Int(0x100)), Some(0x100));
    assert_eq!(marshal_to_address(&PyValue::Int(-1)), None);
}

#[test]
fn marshal_to_address_string_hex_and_decimal() {
    assert_eq!(marshal_to_address(&PyValue::Str("0x100".into())), Some(0x100));
    assert_eq!(marshal_to_address(&PyValue::Str("0X1A".into())), Some(0x1A));
    assert_eq!(marshal_to_address(&PyValue::Str("256".into())), Some(256));
    assert_eq!(marshal_to_address(&PyValue::Str("garbage".into())), None);
    assert_eq!(marshal_to_address(&PyValue::Str("  0x10  ".into())), Some(0x10));
}

#[test]
fn marshal_to_address_other_types() {
    assert_eq!(marshal_to_address(&PyValue::None), None);
    assert_eq!(marshal_to_address(&PyValue::Float(1.0)), None);
}

#[test]
fn marshal_to_bytes_variants() {
    assert_eq!(marshal_to_bytes(&PyValue::Bytes(vec![1, 2])), Some(vec![1, 2]));
    assert_eq!(
        marshal_to_bytes(&PyValue::List(vec![PyValue::Int(1), PyValue::Int(255)])),
        Some(vec![1, 255])
    );
    // Out-of-range u8 -> None for the list path
    assert_eq!(
        marshal_to_bytes(&PyValue::List(vec![PyValue::Int(300)])),
        None
    );
    assert_eq!(marshal_to_bytes(&PyValue::Str("abc".into())), Some(b"abc".to_vec()));
    assert_eq!(marshal_to_bytes(&PyValue::None), None);
}

#[test]
fn instruction_to_pyvalue_shape() {
    let i = Instruction {
        address: 0x10,
        mnemonic: "mov".into(),
        operands: "x, y".into(),
        bytes: vec![1, 2],
        size: 2,
    };
    let pv = instruction_to_pyvalue(&i);
    let PyValue::Dict(d) = pv else { panic!("expected dict") };
    assert_eq!(d.len(), 5);
}

#[test]
fn function_to_pyvalue_shape() {
    let f = ReFunction {
        address: 0x1,
        name: "n".into(),
        size: 1,
        flags: FunctionFlags::RENAMED,
    };
    let pv = function_to_pyvalue(&f);
    if let PyValue::Dict(d) = pv {
        assert_eq!(d.len(), 5);
    } else {
        panic!();
    }
}

#[test]
fn found_string_to_pyvalue_shape() {
    let fs = FoundString { offset: 0, value: "x".into(), encoding: StringEncoding::Ascii };
    if let PyValue::Dict(d) = found_string_to_pyvalue(&fs) {
        assert_eq!(d.len(), 3);
    } else {
        panic!();
    }
}

#[test]
fn xref_to_pyvalue_shape() {
    let x = Xref { from: 1, to: 2, kind: XrefKind::Call };
    if let PyValue::Dict(d) = xref_to_pyvalue(&x) {
        assert_eq!(d.len(), 3);
    } else {
        panic!();
    }
}

// ─── ReScriptEngine ──────────────────────────────────────────────────────────
#[test]
fn re_script_engine_new_default() {
    let e = ReScriptEngine::new();
    assert!(e.api().list_functions().is_empty());
    let _ = ReScriptEngine::default();
}

#[test]
fn re_script_engine_execute_injects_bindings() {
    let mut e = ReScriptEngine::new();
    let (_v, scope) = e.execute("x = 1").unwrap();
    assert!(scope.get("disassemble").is_some());
    assert!(scope.get("decompile").is_some());
    assert!(matches!(scope.get("x"), Some(PyValue::Int(1))));
}

#[test]
fn re_script_engine_with_sandbox() {
    let mut e = ReScriptEngine::with_sandbox(SandboxPolicy::DenyList(vec!["bad".into()]));
    assert!(e.sandbox.is_allowed("good"));
    assert!(!e.sandbox.is_allowed("bad"));
    e.set_max_steps(10);
    e.api_mut().add_function(ReFunction {
        address: 1,
        name: "x".into(),
        size: 0,
        flags: FunctionFlags::empty(),
    });
    assert_eq!(e.api().list_functions().len(), 1);
}

// ─── FunctionFlags bitflags sanity ───────────────────────────────────────────
#[test]
fn function_flags_bits() {
    let all = FunctionFlags::LIBRARY
        | FunctionFlags::THUNK
        | FunctionFlags::VARARGS
        | FunctionFlags::RENAMED
        | FunctionFlags::EXPORTED
        | FunctionFlags::IMPORTED
        | FunctionFlags::INLINED
        | FunctionFlags::NORETURN;
    assert!(all.contains(FunctionFlags::RENAMED));
    let empty = FunctionFlags::empty();
    assert!(!empty.contains(FunctionFlags::RENAMED));
}
