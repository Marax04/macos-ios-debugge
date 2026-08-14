//! Deep adversarial tests for `rustre-script` public API in `lib.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_script::{
    builtin_bytes_concat, builtin_bytes_fill, builtin_bytes_find, builtin_bytes_slice,
    builtin_bytes_to_hex, builtin_functions, builtin_hex_to_bytes, builtin_len, builtin_read_u16,
    builtin_read_u32, builtin_read_u32_be, builtin_read_u64, builtin_read_u8, builtin_to_string,
    builtin_typeof, builtin_write_u16, builtin_write_u32, builtin_write_u64, builtin_write_u8,
    builtin_xor_bytes, native_fn, re_module, register_builtins, CompiledScript, EventSystem,
    NativeFunction, SandboxPolicy, ScriptConfig, ScriptContext, ScriptEngineRegistry, ScriptError,
    ScriptHost, ScriptModule, ScriptPipeline, ScriptResult, ScriptValue, VariableFrame,
    PipelineStep,
};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ── ScriptValue: type_name & basics ──────────────────────────────────────────

#[test]
fn type_name_covers_all_variants() {
    assert_eq!(ScriptValue::Null.type_name(), "null");
    assert_eq!(ScriptValue::Bool(true).type_name(), "bool");
    assert_eq!(ScriptValue::Int(0).type_name(), "int");
    assert_eq!(ScriptValue::Float(0.0).type_name(), "float");
    assert_eq!(ScriptValue::String(String::new()).type_name(), "string");
    assert_eq!(ScriptValue::Bytes(vec![]).type_name(), "bytes");
    assert_eq!(ScriptValue::List(vec![]).type_name(), "list");
    assert_eq!(ScriptValue::Map(HashMap::new()).type_name(), "map");
    assert_eq!(ScriptValue::Address(0).type_name(), "address");
    assert_eq!(ScriptValue::Callable("f".into()).type_name(), "callable");
}

#[test]
fn truthiness_matrix() {
    assert!(!ScriptValue::Null.is_truthy());
    assert!(!ScriptValue::Bool(false).is_truthy());
    assert!(ScriptValue::Bool(true).is_truthy());
    assert!(!ScriptValue::Int(0).is_truthy());
    assert!(ScriptValue::Int(1).is_truthy());
    assert!(!ScriptValue::Float(0.0).is_truthy());
    assert!(ScriptValue::Float(0.5).is_truthy());
    assert!(!ScriptValue::String(String::new()).is_truthy());
    assert!(ScriptValue::String("x".into()).is_truthy());
    assert!(!ScriptValue::Bytes(vec![]).is_truthy());
    assert!(ScriptValue::Bytes(vec![0]).is_truthy());
    assert!(!ScriptValue::List(vec![]).is_truthy());
    assert!(!ScriptValue::Map(HashMap::new()).is_truthy());
    assert!(ScriptValue::Address(0).is_truthy());
    assert!(ScriptValue::Callable("f".into()).is_truthy());
}

#[test]
fn as_int_boundaries() {
    assert_eq!(ScriptValue::Int(i64::MAX).as_int().unwrap(), i64::MAX);
    assert_eq!(ScriptValue::Int(i64::MIN).as_int().unwrap(), i64::MIN);
    assert_eq!(ScriptValue::Bool(true).as_int().unwrap(), 1);
    assert_eq!(ScriptValue::Bool(false).as_int().unwrap(), 0);
    assert_eq!(ScriptValue::Float(1.9).as_int().unwrap(), 1);
    assert_eq!(ScriptValue::Float(-1.9).as_int().unwrap(), -1);
    assert!(ScriptValue::Float(f64::INFINITY).as_int().is_err());
    assert!(ScriptValue::Float(1e30).as_int().is_err());
    assert!(ScriptValue::String("1".into()).as_int().is_err());
    assert!(ScriptValue::Null.as_int().is_err());
}

#[test]
fn as_float_coercions() {
    assert_eq!(ScriptValue::Int(7).as_float().unwrap(), 7.0);
    assert_eq!(ScriptValue::Bool(true).as_float().unwrap(), 1.0);
    assert_eq!(ScriptValue::Bool(false).as_float().unwrap(), 0.0);
    assert_eq!(ScriptValue::Float(3.5).as_float().unwrap(), 3.5);
    assert!(ScriptValue::Null.as_float().is_err());
}

#[test]
fn as_str_bytes_bool_address_list_map() {
    assert_eq!(ScriptValue::String("x".into()).as_str().unwrap(), "x");
    assert!(ScriptValue::Int(0).as_str().is_err());
    assert_eq!(
        ScriptValue::Bytes(vec![1, 2]).as_bytes().unwrap(),
        &[1, 2][..]
    );
    assert!(ScriptValue::Int(0).as_bytes().is_err());
    assert!(ScriptValue::Bool(true).as_bool().unwrap());
    assert!(ScriptValue::Int(0).as_bool().is_err());
    assert_eq!(ScriptValue::Address(0xff).as_address().unwrap(), 0xff);
    assert_eq!(ScriptValue::Int(5).as_address().unwrap(), 5);
    assert!(ScriptValue::Null.as_address().is_err());
    let l = ScriptValue::List(vec![ScriptValue::Int(1)]);
    assert_eq!(l.as_list().unwrap().len(), 1);
    assert!(ScriptValue::Null.as_list().is_err());
    let mut m = HashMap::new();
    m.insert("a".into(), ScriptValue::Int(1));
    assert_eq!(ScriptValue::Map(m).as_map().unwrap().len(), 1);
    assert!(ScriptValue::Null.as_map().is_err());
}

#[test]
fn len_and_is_empty_consistent() {
    let cases: Vec<ScriptValue> = vec![
        ScriptValue::String("hello".into()),
        ScriptValue::String(String::new()),
        ScriptValue::Bytes(vec![1, 2, 3]),
        ScriptValue::Bytes(vec![]),
        ScriptValue::List(vec![ScriptValue::Null; 4]),
        ScriptValue::List(vec![]),
        ScriptValue::Map(HashMap::new()),
    ];
    for c in cases {
        let len = c.len().unwrap();
        let empty = c.is_empty().unwrap();
        assert_eq!(empty, len == 0);
    }
    assert!(ScriptValue::Null.len().is_err());
    assert!(ScriptValue::Int(0).is_empty().is_err());
}

#[test]
fn json_roundtrip_for_basic_types() {
    let values = vec![
        ScriptValue::Null,
        ScriptValue::Bool(true),
        ScriptValue::Bool(false),
        ScriptValue::Int(0),
        ScriptValue::Int(-99),
        ScriptValue::Int(i64::MAX),
        ScriptValue::String("hi".into()),
        ScriptValue::List(vec![ScriptValue::Int(1), ScriptValue::Int(2)]),
    ];
    for v in values {
        let j = v.to_json();
        let back = ScriptValue::from_json(j);
        assert_eq!(back, v, "json roundtrip failed for {v:?}");
    }
}

#[test]
fn display_matches_to_display_string() {
    let v = ScriptValue::Int(42);
    assert_eq!(format!("{v}"), v.to_display_string());
    let m = {
        let mut m = HashMap::new();
        m.insert("a".into(), ScriptValue::Int(1));
        m.insert("b".into(), ScriptValue::Int(2));
        ScriptValue::Map(m)
    };
    let s = m.to_display_string();
    // map display is sorted by key
    assert!(s.starts_with("{a: 1"), "got: {s}");
}

#[test]
fn from_conversions() {
    assert_eq!(ScriptValue::from(1i64), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1i32), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1u32), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1.5f64), ScriptValue::Float(1.5));
    assert_eq!(ScriptValue::from(1.5f32), ScriptValue::Float(1.5));
    assert_eq!(ScriptValue::from(true), ScriptValue::Bool(true));
    assert_eq!(ScriptValue::from("x"), ScriptValue::String("x".into()));
    assert_eq!(
        ScriptValue::from("y".to_string()),
        ScriptValue::String("y".into())
    );
    assert_eq!(ScriptValue::from(0xfu64), ScriptValue::Address(0xf));
    assert_eq!(ScriptValue::from(vec![1u8, 2]), ScriptValue::Bytes(vec![1, 2]));
}

#[test]
fn as_string_int_bool_opt() {
    assert_eq!(ScriptValue::String("x".into()).as_string(), Some("x"));
    assert_eq!(ScriptValue::Int(0).as_string(), None);
    assert_eq!(ScriptValue::Int(5).as_int_opt(), Some(5));
    assert_eq!(ScriptValue::Bool(true).as_int_opt(), Some(1));
    assert_eq!(ScriptValue::Float(2.7).as_int_opt(), Some(2));
    assert_eq!(ScriptValue::Float(f64::NAN).as_int_opt(), None);
    assert_eq!(ScriptValue::Float(f64::INFINITY).as_int_opt(), None);
    assert_eq!(ScriptValue::Null.as_int_opt(), None);
    assert_eq!(ScriptValue::Bool(false).as_bool_opt(), Some(false));
    assert_eq!(ScriptValue::Int(0).as_bool_opt(), None);
}

// ── Hash/Eq pairs (PartialEq) ────────────────────────────────────────────────

#[test]
fn equality_pairs_30_plus() {
    let mut g = lcg();
    for _ in 0..30 {
        let x = (g() % 100) as i64;
        let a = ScriptValue::Int(x);
        let b = ScriptValue::Int(x);
        assert_eq!(a, b);
        assert_eq!(a.clone(), a);
    }
    // Inequality across variants
    assert_ne!(ScriptValue::Int(0), ScriptValue::Float(0.0));
    assert_ne!(ScriptValue::Null, ScriptValue::Bool(false));
    assert_ne!(ScriptValue::String("".into()), ScriptValue::Bytes(vec![]));
}

// ── ScriptError ──────────────────────────────────────────────────────────────

#[test]
fn error_is_recoverable_classification() {
    assert!(ScriptError::FunctionNotFound("f".into()).is_recoverable());
    assert!(ScriptError::UndefinedVariable("v".into()).is_recoverable());
    assert!(ScriptError::TypeMismatch {
        expected: "x".into(),
        got: "y".into()
    }
    .is_recoverable());
    assert!(ScriptError::ArityMismatch {
        name: "f".into(),
        expected: 1,
        got: 0
    }
    .is_recoverable());
    assert!(!ScriptError::Timeout { ms: 1 }.is_recoverable());
    assert!(!ScriptError::StackOverflow.is_recoverable());
    assert!(!ScriptError::DivisionByZero.is_recoverable());
}

#[test]
fn error_constructors_and_display() {
    let e = ScriptError::runtime("boom");
    assert!(format!("{e}").contains("boom"));
    let e = ScriptError::parse(10, 4, "oops");
    let s = format!("{e}");
    assert!(s.contains("10") && s.contains("4") && s.contains("oops"));
}

// ── ScriptContext ────────────────────────────────────────────────────────────

#[test]
fn context_global_set_get_remove() {
    let mut ctx = ScriptContext::new();
    assert!(ctx.get_global("k").is_none());
    ctx.set_global("k", ScriptValue::Int(7));
    assert_eq!(ctx.get_global("k").cloned().unwrap(), ScriptValue::Int(7));
    let removed = ctx.remove_global("k").unwrap();
    assert_eq!(removed, ScriptValue::Int(7));
    assert!(ctx.get_global("k").is_none());
}

#[test]
fn context_with_timeout_and_globals() {
    let ctx = ScriptContext::with_timeout(500);
    assert_eq!(ctx.timeout_ms, Some(500));
    let mut m = HashMap::new();
    m.insert("a".into(), ScriptValue::Int(1));
    let ctx = ScriptContext::new().with_globals(m);
    assert!(ctx.get_global("a").is_some());
}

#[test]
fn context_native_fn_register_and_lookup() {
    let mut ctx = ScriptContext::new();
    ctx.register_fn("inc", native_fn(|args| Ok(ScriptValue::Int(args[0].as_int()? + 1))));
    let f = ctx.get_fn("inc").unwrap();
    let r = f.call(&[ScriptValue::Int(4)]).unwrap();
    assert_eq!(r, ScriptValue::Int(5));
}

#[test]
fn context_output_meta_names() {
    let mut ctx = ScriptContext::new();
    ctx.write_output("hi");
    ctx.write_error("err");
    ctx.set_meta("k", "v");
    assert_eq!(ctx.output, vec!["hi".to_string()]);
    assert_eq!(ctx.error_output, vec!["err".to_string()]);
    assert_eq!(ctx.get_meta("k").unwrap(), "v");
    ctx.set_global("g", ScriptValue::Null);
    let names = ctx.global_names();
    assert!(names.contains(&"g"));
}

// ── ScriptResult ─────────────────────────────────────────────────────────────

#[test]
fn script_result_success_and_failure() {
    let mut ctx = ScriptContext::new();
    ctx.write_output("ok");
    let r = ScriptResult::new(ScriptValue::Int(1), &ctx).with_elapsed(42);
    assert!(r.success);
    assert_eq!(r.elapsed_ms, 42);
    assert_eq!(r.stdout_joined(), "ok");
    assert!(!r.has_errors());
    let f = ScriptResult::failure("bad");
    assert!(!f.success);
    assert!(f.has_errors());
    assert_eq!(f.stderr_joined(), "bad");
}

// ── ScriptModule ─────────────────────────────────────────────────────────────

#[test]
fn module_add_and_lookup() {
    let mut m = ScriptModule::new("mod");
    m.add_fn("f", native_fn(|_| Ok(ScriptValue::Int(1))));
    m.add_const("C", ScriptValue::Int(99));
    assert_eq!(m.symbol_count(), 2);
    assert!(m.get_fn("f").is_some());
    assert!(m.get_fn("nope").is_none());
    assert_eq!(m.get_const("C").cloned().unwrap(), ScriptValue::Int(99));
}

// ── ScriptEngineRegistry ─────────────────────────────────────────────────────

#[test]
fn registry_count_and_remove_empty() {
    let r = ScriptEngineRegistry::new();
    assert_eq!(r.count(), 0);
    assert!(r.list_engines().is_empty());
    assert!(!r.remove("nothing"));
    assert!(r.find_by_name("x").is_none());
    assert!(r.find_by_extension("rh").is_none());
}

// ── ScriptPipeline ───────────────────────────────────────────────────────────

#[test]
fn pipeline_empty_and_push() {
    let mut p = ScriptPipeline::new();
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
    p.push(PipelineStep::new("lua", "x").with_label("step1"));
    assert!(!p.is_empty());
    assert_eq!(p.len(), 1);
}

// ── SandboxPolicy ────────────────────────────────────────────────────────────

#[test]
fn sandbox_policies() {
    let d = SandboxPolicy::deny_all();
    assert!(!d.allow_fs_read && !d.allow_fs_write && !d.allow_network && !d.allow_subprocess);
    let a = SandboxPolicy::allow_all();
    assert!(a.allow_fs_read && a.allow_fs_write && a.allow_network && a.allow_subprocess);
    let r = SandboxPolicy::read_only();
    assert!(r.allow_fs_read);
    assert!(!r.allow_fs_write);
    assert_eq!(r.max_time_ms, 5_000);
}

// ── builtin: hex/bytes round trip ────────────────────────────────────────────

#[test]
fn hex_roundtrip_deterministic_50() {
    let mut g = lcg();
    for n in 0..50usize {
        let len = (g() as usize % 32) + 1;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let v = ScriptValue::Bytes(bytes.clone());
        let hex = builtin_bytes_to_hex(&[v]).unwrap();
        let back = builtin_hex_to_bytes(&[hex.clone()]).unwrap();
        assert_eq!(back, ScriptValue::Bytes(bytes), "iter {n}");
        // also with 0x prefix
        let s = hex.as_str().unwrap().to_string();
        let prefixed = ScriptValue::String(format!("0x{s}"));
        let back2 = builtin_hex_to_bytes(&[prefixed]).unwrap();
        assert_eq!(back2, back);
    }
}

#[test]
fn hex_odd_length_errors() {
    let r = builtin_hex_to_bytes(&[ScriptValue::String("abc".into())]);
    assert!(matches!(r, Err(ScriptError::RuntimeError(_))));
}

#[test]
fn hex_invalid_chars_errors() {
    let r = builtin_hex_to_bytes(&[ScriptValue::String("zz".into())]);
    assert!(r.is_err());
}

#[test]
fn hex_arity_zero_errors() {
    let r = builtin_hex_to_bytes(&[]);
    assert!(matches!(r, Err(ScriptError::ArityMismatch { .. })));
    let r = builtin_bytes_to_hex(&[]);
    assert!(matches!(r, Err(ScriptError::ArityMismatch { .. })));
}

// ── builtin: read/write u8/u16/u32/u64 roundtrip ─────────────────────────────

#[test]
fn read_write_u8_roundtrip() {
    let buf = ScriptValue::Bytes(vec![0u8; 4]);
    let written = builtin_write_u8(&[buf, ScriptValue::Int(2), ScriptValue::Int(0xAB)]).unwrap();
    let read = builtin_read_u8(&[written, ScriptValue::Int(2)]).unwrap();
    assert_eq!(read, ScriptValue::Int(0xAB));
}

#[test]
fn read_write_u16_le_roundtrip() {
    let buf = ScriptValue::Bytes(vec![0u8; 8]);
    let w = builtin_write_u16(&[buf, ScriptValue::Int(1), ScriptValue::Int(0x1234)]).unwrap();
    let r = builtin_read_u16(&[w, ScriptValue::Int(1)]).unwrap();
    assert_eq!(r, ScriptValue::Int(0x1234));
}

#[test]
fn read_write_u32_le_roundtrip() {
    let buf = ScriptValue::Bytes(vec![0u8; 8]);
    let w = builtin_write_u32(&[buf, ScriptValue::Int(0), ScriptValue::Int(0xDEADBEEF)]).unwrap();
    let r = builtin_read_u32(&[w, ScriptValue::Int(0)]).unwrap();
    assert_eq!(r, ScriptValue::Int(0xDEADBEEF));
}

#[test]
fn read_u32_be_known_bytes() {
    let buf = ScriptValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let r = builtin_read_u32_be(&[buf, ScriptValue::Int(0)]).unwrap();
    assert_eq!(r, ScriptValue::Int(0xDEADBEEF));
}

#[test]
fn read_write_u64_le_roundtrip() {
    let buf = ScriptValue::Bytes(vec![0u8; 16]);
    // Use a positive value to ensure round-trip via signed int
    let val: i64 = 0x0123_4567_89AB_CDEF;
    let w = builtin_write_u64(&[buf, ScriptValue::Int(0), ScriptValue::Int(val)]).unwrap();
    let r = builtin_read_u64(&[w, ScriptValue::Int(0)]).unwrap();
    assert_eq!(r, ScriptValue::Int(val));
}

#[test]
fn read_out_of_bounds_errors() {
    let buf = ScriptValue::Bytes(vec![0u8; 2]);
    let r = builtin_read_u32(&[buf, ScriptValue::Int(0)]);
    assert!(matches!(r, Err(ScriptError::IndexOutOfBounds { .. })));
}

#[test]
fn read_negative_offset_errors() {
    let buf = ScriptValue::Bytes(vec![0u8; 4]);
    let r = builtin_read_u8(&[buf, ScriptValue::Int(-1)]);
    assert!(matches!(r, Err(ScriptError::IndexOutOfBounds { .. })));
}

#[test]
fn read_arity_errors() {
    assert!(matches!(
        builtin_read_u32(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_write_u32(&[ScriptValue::Bytes(vec![0; 4]), ScriptValue::Int(0)]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn write_at_end_errors() {
    let buf = ScriptValue::Bytes(vec![0u8; 4]);
    let r = builtin_write_u32(&[buf, ScriptValue::Int(1), ScriptValue::Int(0)]);
    assert!(matches!(r, Err(ScriptError::IndexOutOfBounds { .. })));
}

// ── builtin: xor ─────────────────────────────────────────────────────────────

#[test]
fn xor_known_value() {
    let r = builtin_xor_bytes(&[
        ScriptValue::Bytes(vec![0xff, 0x00, 0xaa]),
        ScriptValue::Bytes(vec![0x0f]),
    ])
    .unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xf0, 0x0f, 0xa5]));
}

#[test]
fn xor_self_inverse_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize % 24) + 1;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let key_len = (g() as usize % 8) + 1;
        let key: Vec<u8> = (0..key_len).map(|_| (g() & 0xff) as u8).collect();
        let xored = builtin_xor_bytes(&[
            ScriptValue::Bytes(data.clone()),
            ScriptValue::Bytes(key.clone()),
        ])
        .unwrap();
        let back =
            builtin_xor_bytes(&[xored, ScriptValue::Bytes(key)]).unwrap();
        assert_eq!(back, ScriptValue::Bytes(data));
    }
}

#[test]
fn xor_empty_key_errors() {
    let r = builtin_xor_bytes(&[ScriptValue::Bytes(vec![1, 2]), ScriptValue::Bytes(vec![])]);
    assert!(matches!(r, Err(ScriptError::RuntimeError(_))));
}

#[test]
fn xor_arity_errors() {
    let r = builtin_xor_bytes(&[ScriptValue::Bytes(vec![1])]);
    assert!(matches!(r, Err(ScriptError::ArityMismatch { .. })));
}

// ── builtin: bytes_concat / slice / fill / find ──────────────────────────────

#[test]
fn bytes_concat_basic_and_arity() {
    let r = builtin_bytes_concat(&[
        ScriptValue::Bytes(vec![1, 2]),
        ScriptValue::Bytes(vec![3, 4]),
    ])
    .unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![1, 2, 3, 4]));
    assert!(matches!(
        builtin_bytes_concat(&[ScriptValue::Bytes(vec![])]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn bytes_slice_boundaries() {
    let b = ScriptValue::Bytes(vec![1, 2, 3, 4, 5]);
    let r = builtin_bytes_slice(&[b.clone(), ScriptValue::Int(1), ScriptValue::Int(3)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![2, 3]));
    // empty slice at end
    let r0 = builtin_bytes_slice(&[b.clone(), ScriptValue::Int(5), ScriptValue::Int(5)]).unwrap();
    assert_eq!(r0, ScriptValue::Bytes(vec![]));
    // end > len errors
    assert!(matches!(
        builtin_bytes_slice(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(6)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
    // start > end errors
    assert!(matches!(
        builtin_bytes_slice(&[b.clone(), ScriptValue::Int(3), ScriptValue::Int(1)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
    // negative
    assert!(matches!(
        builtin_bytes_slice(&[b, ScriptValue::Int(-1), ScriptValue::Int(0)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
}

#[test]
fn bytes_fill_basic_and_too_big() {
    let r = builtin_bytes_fill(&[ScriptValue::Int(4), ScriptValue::Int(0xAB)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xAB; 4]));
    // zero
    let r0 = builtin_bytes_fill(&[ScriptValue::Int(0), ScriptValue::Int(0)]).unwrap();
    assert_eq!(r0, ScriptValue::Bytes(vec![]));
    // negative count
    assert!(builtin_bytes_fill(&[ScriptValue::Int(-1), ScriptValue::Int(0)]).is_err());
    // arity
    assert!(matches!(
        builtin_bytes_fill(&[ScriptValue::Int(1)]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    // too big
    let r = builtin_bytes_fill(&[
        ScriptValue::Int(300 * 1024 * 1024),
        ScriptValue::Int(0),
    ]);
    assert!(matches!(r, Err(ScriptError::RuntimeError(_))));
}

#[test]
fn bytes_find_cases() {
    let h = ScriptValue::Bytes(vec![1, 2, 3, 4, 5]);
    let n = ScriptValue::Bytes(vec![3, 4]);
    let r = builtin_bytes_find(&[h.clone(), n]).unwrap();
    assert_eq!(r, ScriptValue::Int(2));
    // empty needle returns 0
    let r0 = builtin_bytes_find(&[h.clone(), ScriptValue::Bytes(vec![])]).unwrap();
    assert_eq!(r0, ScriptValue::Int(0));
    // needle longer than haystack
    let r1 = builtin_bytes_find(&[h.clone(), ScriptValue::Bytes(vec![0; 100])]).unwrap();
    assert_eq!(r1, ScriptValue::Null);
    // not found
    let r2 = builtin_bytes_find(&[h, ScriptValue::Bytes(vec![9, 9])]).unwrap();
    assert_eq!(r2, ScriptValue::Null);
    // arity
    assert!(matches!(
        builtin_bytes_find(&[ScriptValue::Bytes(vec![])]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

// ── builtin: to_string / len / typeof ────────────────────────────────────────

#[test]
fn builtin_helpers() {
    assert_eq!(
        builtin_to_string(&[ScriptValue::Int(42)]).unwrap(),
        ScriptValue::String("42".into())
    );
    assert_eq!(
        builtin_len(&[ScriptValue::List(vec![ScriptValue::Null; 3])]).unwrap(),
        ScriptValue::Int(3)
    );
    assert_eq!(
        builtin_typeof(&[ScriptValue::Bool(true)]).unwrap(),
        ScriptValue::String("bool".into())
    );
    assert!(matches!(
        builtin_typeof(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_len(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_to_string(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

// ── builtin_functions / re_module / register_builtins ────────────────────────

#[test]
fn builtin_functions_map_complete() {
    let map = builtin_functions();
    for name in [
        "hex_to_bytes",
        "bytes_to_hex",
        "read_u8",
        "read_u16",
        "read_u32",
        "read_u32_be",
        "read_u64",
        "write_u8",
        "write_u16",
        "write_u32",
        "write_u64",
        "xor_bytes",
        "to_string",
        "len",
        "typeof",
        "bytes_concat",
        "bytes_slice",
        "bytes_fill",
        "bytes_find",
    ] {
        assert!(map.contains_key(name), "missing: {name}");
    }
}

#[test]
fn re_module_has_constants() {
    let m = re_module();
    assert_eq!(m.name, "re");
    assert_eq!(m.get_const("NULL").cloned().unwrap(), ScriptValue::Null);
    assert_eq!(m.get_const("TRUE").cloned().unwrap(), ScriptValue::Bool(true));
    assert_eq!(m.get_const("FALSE").cloned().unwrap(), ScriptValue::Bool(false));
    assert!(m.get_fn("hex_to_bytes").is_some());
}

#[test]
fn register_builtins_into_context() {
    let mut ctx = ScriptContext::new();
    register_builtins(&mut ctx);
    assert!(ctx.get_fn("hex_to_bytes").is_some());
    assert!(ctx.get_fn("bytes_to_hex").is_some());
}

// ── VariableFrame ────────────────────────────────────────────────────────────

#[test]
fn variable_frame_basic_bind_lookup() {
    let mut f = VariableFrame::root();
    f.bind("x", ScriptValue::Int(1));
    assert_eq!(f.lookup("x").cloned().unwrap(), ScriptValue::Int(1));
    assert!(f.lookup("y").is_none());
    assert_eq!(f.local_count(), 1);
}

#[test]
fn variable_frame_child_chain_and_assign() {
    let mut root = VariableFrame::root();
    root.bind("a", ScriptValue::Int(1));
    let mut child = VariableFrame::child(root);
    child.bind("b", ScriptValue::Int(2));
    assert_eq!(child.lookup("a").cloned().unwrap(), ScriptValue::Int(1));
    assert_eq!(child.lookup("b").cloned().unwrap(), ScriptValue::Int(2));
    assert!(child.assign("a", ScriptValue::Int(11)));
    assert_eq!(child.lookup("a").cloned().unwrap(), ScriptValue::Int(11));
    assert!(!child.assign("does_not_exist", ScriptValue::Null));
}

// ── ScriptHost ───────────────────────────────────────────────────────────────

struct DummyBackend {
    name: String,
    last_eval: Option<String>,
}

impl rustre_script::ScriptingBackend for DummyBackend {
    fn name(&self) -> &str {
        &self.name
    }
    fn eval(&mut self, code: &str) -> Result<ScriptValue, ScriptError> {
        self.last_eval = Some(code.to_string());
        Ok(ScriptValue::String(format!("evaled:{code}")))
    }
    fn exec(&mut self, _code: &str) -> Result<(), ScriptError> {
        Ok(())
    }
    fn call(&mut self, func: &str, _args: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::String(format!("called:{func}")))
    }
    fn load_file(&mut self, _path: &std::path::Path) -> Result<(), ScriptError> {
        Ok(())
    }
    fn register_fn(
        &mut self,
        _name: &str,
        _f: Box<dyn Fn(Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> + Send + Sync>,
    ) {
    }
}

fn dummy(name: &str) -> Box<dyn rustre_script::ScriptingBackend> {
    Box::new(DummyBackend {
        name: name.to_string(),
        last_eval: None,
    })
}

#[test]
fn host_new_is_empty() {
    let h = ScriptHost::new();
    assert!(h.backend_names().is_empty());
    assert!(h.active_name().is_none());
}

#[test]
fn host_add_first_backend_becomes_active() {
    let mut h = ScriptHost::new();
    h.add_backend(dummy("lua"));
    assert_eq!(h.active_name(), Some("lua"));
    h.add_backend(dummy("rhai"));
    // still lua
    assert_eq!(h.active_name(), Some("lua"));
}

#[test]
fn host_set_active_known_and_unknown() {
    let mut h = ScriptHost::new();
    h.add_backend(dummy("lua"));
    h.add_backend(dummy("rhai"));
    h.set_active("rhai").unwrap();
    assert_eq!(h.active_name(), Some("rhai"));
    assert!(h.set_active("nope").is_err());
}

#[test]
fn host_run_script_routes_correctly() {
    let mut h = ScriptHost::new();
    h.add_backend(dummy("lua"));
    let v = h.run_script("lua", "return 1").unwrap();
    assert_eq!(v, ScriptValue::String("evaled:return 1".into()));
    assert!(h.run_script("unknown", "x").is_err());
}

#[test]
fn host_run_file_extension_routing() {
    use std::path::PathBuf;
    let mut h = ScriptHost::new();
    h.add_backend(dummy("lua"));
    let p = PathBuf::from("nonexistent.lua");
    // backend load_file is a no-op for dummy
    h.run_file(&p).unwrap();
    // unknown extension -> err
    assert!(h.run_file(&PathBuf::from("x.unknown")).is_err());
    // missing backend for known ext
    assert!(h.run_file(&PathBuf::from("x.py")).is_err());
}

#[test]
fn host_active_backend_when_none() {
    let mut h = ScriptHost::new();
    assert!(h.active_backend().is_err());
}

#[test]
fn host_backend_mut_lookup() {
    let mut h = ScriptHost::new();
    h.add_backend(dummy("lua"));
    assert!(h.backend_mut("lua").is_some());
    assert!(h.backend_mut("none").is_none());
}

// ── EventSystem ──────────────────────────────────────────────────────────────

#[test]
fn event_system_subscribe_count_clear() {
    let mut es = EventSystem::new();
    assert_eq!(es.handler_count("e"), 0);
    es.on("e", "lua", "x=1");
    es.on("e", "lua", "x=2");
    assert_eq!(es.handler_count("e"), 2);
    let events = es.events();
    assert!(events.contains(&"e"));
    assert_eq!(es.clear_event("e"), 2);
    assert_eq!(es.handler_count("e"), 0);
    assert_eq!(es.clear_event("nope"), 0);
}

#[test]
fn event_system_emit_no_handlers_is_noop() {
    let mut es = EventSystem::new();
    let mut host = ScriptHost::new();
    es.emit("nothing", &ScriptValue::Null, &mut host);
}

// ── CompiledScript ───────────────────────────────────────────────────────────

#[test]
fn compiled_script_constructors_and_warnings() {
    let c = CompiledScript::new("rhai", "x");
    assert!(!c.is_empty());
    assert_eq!(c.engine_name, "rhai");
    let mut e = CompiledScript::empty("lua");
    assert!(e.is_empty());
    e.add_warning("w1");
    assert_eq!(e.warnings.len(), 1);
}

// ── Native fn arc/wrapper ────────────────────────────────────────────────────

#[test]
fn native_fn_construction_and_call() {
    let f: NativeFunction = native_fn(|args| Ok(ScriptValue::Int(args.len() as i64)));
    let r = f.call(&[ScriptValue::Null, ScriptValue::Null]).unwrap();
    assert_eq!(r, ScriptValue::Int(2));
    assert!(f.arity().is_none());
    assert_eq!(f.name(), "<native>");
}

// ── ScriptConfig serde sanity ────────────────────────────────────────────────

#[test]
fn script_config_serde_roundtrip() {
    // ScriptConfig fields not fully read here, but minimal: default + serialize
    let cfg = ScriptConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ScriptConfig = serde_json::from_str(&json).unwrap();
    let _ = back;
}

// ── Send/Sync threaded stress on NativeFunction ──────────────────────────────

#[test]
fn native_function_threaded_stress() {
    let f: NativeFunction = native_fn(|args| {
        let mut sum: i64 = 0;
        for a in args {
            sum = sum.wrapping_add(a.as_int().unwrap_or(0));
        }
        Ok(ScriptValue::Int(sum))
    });
    let mut handles = Vec::new();
    for t in 0..4 {
        let f = Arc::clone(&f);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let r = f.call(&[ScriptValue::Int(t), ScriptValue::Int(i)]).unwrap();
                assert_eq!(r, ScriptValue::Int(t + i));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn registry_send_sync_threaded() {
    let r = Arc::new(ScriptEngineRegistry::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = Arc::clone(&r);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r.count();
                let _ = r.list_engines();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── LCG fuzz: never panic ────────────────────────────────────────────────────

#[test]
fn fuzz_hex_to_bytes_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() as usize % 40) as usize;
        let s: String = (0..len)
            .map(|_| {
                let c = (g() & 0x7f) as u8;
                if c.is_ascii_graphic() {
                    c as char
                } else {
                    'a'
                }
            })
            .collect();
        let _ = builtin_hex_to_bytes(&[ScriptValue::String(s)]);
    }
}

#[test]
fn fuzz_read_writes_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() as usize % 20) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let off = (g() & 0xff) as i64 - 50;
        let _ = builtin_read_u8(&[ScriptValue::Bytes(buf.clone()), ScriptValue::Int(off)]);
        let _ = builtin_read_u16(&[ScriptValue::Bytes(buf.clone()), ScriptValue::Int(off)]);
        let _ = builtin_read_u32(&[ScriptValue::Bytes(buf.clone()), ScriptValue::Int(off)]);
        let _ = builtin_read_u64(&[ScriptValue::Bytes(buf.clone()), ScriptValue::Int(off)]);
        let _ = builtin_read_u32_be(&[ScriptValue::Bytes(buf), ScriptValue::Int(off)]);
    }
}

#[test]
fn fuzz_bytes_slice_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() as usize % 16) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        let s = (g() & 0x1f) as i64;
        let e = (g() & 0x1f) as i64;
        let _ = builtin_bytes_slice(&[
            ScriptValue::Bytes(buf),
            ScriptValue::Int(s),
            ScriptValue::Int(e),
        ]);
    }
}

#[test]
fn fuzz_xor_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let a_len = (g() as usize % 16) as usize;
        let b_len = ((g() as usize % 8) as usize).max(1);
        let a: Vec<u8> = (0..a_len).map(|_| (g() & 0xff) as u8).collect();
        let b: Vec<u8> = (0..b_len).map(|_| (g() & 0xff) as u8).collect();
        let _ = builtin_xor_bytes(&[ScriptValue::Bytes(a), ScriptValue::Bytes(b)]);
    }
}
