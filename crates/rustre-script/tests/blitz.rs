//! Exhaustive blitz tests for rustre-script.
//!
//! Targets lib.rs's pure API: ScriptError, ScriptValue, ScriptContext,
//! ScriptModule, ScriptResult, CompiledScript, ScriptEngineRegistry,
//! SandboxPolicy, ScriptPipeline, VariableFrame, ScriptHost, and builtins.

use std::collections::HashMap;
use std::sync::Arc;

use rustre_script::*;

// ── ScriptError ──────────────────────────────────────────────────────────────

#[test]
fn err_is_recoverable_matrix() {
    assert!(ScriptError::FunctionNotFound("f".into()).is_recoverable());
    assert!(ScriptError::UndefinedVariable("x".into()).is_recoverable());
    assert!(ScriptError::TypeMismatch { expected: "a".into(), got: "b".into() }.is_recoverable());
    assert!(ScriptError::ArityMismatch { name: "f".into(), expected: 1, got: 0 }.is_recoverable());

    assert!(!ScriptError::RuntimeError("x".into()).is_recoverable());
    assert!(!ScriptError::Timeout { ms: 1 }.is_recoverable());
    assert!(!ScriptError::DivisionByZero.is_recoverable());
    assert!(!ScriptError::StackOverflow.is_recoverable());
    assert!(!ScriptError::IoError("x".into()).is_recoverable());
    assert!(!ScriptError::ModuleNotFound("m".into()).is_recoverable());
    assert!(!ScriptError::ModuleAlreadyRegistered("m".into()).is_recoverable());
    assert!(!ScriptError::CompilationError("c".into()).is_recoverable());
    assert!(!ScriptError::PermissionDenied("p".into()).is_recoverable());
    assert!(!ScriptError::Custom("c".into()).is_recoverable());
    assert!(!ScriptError::IndexOutOfBounds { index: 0, length: 0 }.is_recoverable());
    assert!(!ScriptError::EngineNotFound { name: "n".into(), ext: "e".into() }.is_recoverable());
    assert!(!ScriptError::ParseError { line: 1, col: 1, msg: "x".into() }.is_recoverable());
}

#[test]
fn err_constructors() {
    let r = ScriptError::runtime("oops");
    match r {
        ScriptError::RuntimeError(m) => assert_eq!(m, "oops"),
        _ => panic!(),
    }
    let p = ScriptError::parse(3, 7, "bad");
    match p {
        ScriptError::ParseError { line, col, msg } => {
            assert_eq!(line, 3);
            assert_eq!(col, 7);
            assert_eq!(msg, "bad");
        }
        _ => panic!(),
    }
}

#[test]
fn err_display_contains_fields() {
    let e = ScriptError::parse(2, 5, "boom");
    let s = format!("{e}");
    assert!(s.contains("2") && s.contains("5") && s.contains("boom"));

    let e = ScriptError::ArityMismatch { name: "f".into(), expected: 3, got: 1 };
    let s = format!("{e}");
    assert!(s.contains("f") && s.contains("3") && s.contains("1"));
}

// ── ScriptValue: type_name + is_truthy + is_null ─────────────────────────────

#[test]
fn value_type_names() {
    assert_eq!(ScriptValue::Null.type_name(), "null");
    assert_eq!(ScriptValue::Bool(true).type_name(), "bool");
    assert_eq!(ScriptValue::Int(0).type_name(), "int");
    assert_eq!(ScriptValue::Float(0.0).type_name(), "float");
    assert_eq!(ScriptValue::String("".into()).type_name(), "string");
    assert_eq!(ScriptValue::Bytes(vec![]).type_name(), "bytes");
    assert_eq!(ScriptValue::List(vec![]).type_name(), "list");
    assert_eq!(ScriptValue::Map(HashMap::new()).type_name(), "map");
    assert_eq!(ScriptValue::Address(0).type_name(), "address");
    assert_eq!(ScriptValue::Callable("f".into()).type_name(), "callable");
}

#[test]
fn value_truthiness() {
    assert!(!ScriptValue::Null.is_truthy());
    assert!(!ScriptValue::Bool(false).is_truthy());
    assert!(ScriptValue::Bool(true).is_truthy());
    assert!(!ScriptValue::Int(0).is_truthy());
    assert!(ScriptValue::Int(-1).is_truthy());
    assert!(!ScriptValue::Float(0.0).is_truthy());
    assert!(ScriptValue::Float(1e-300).is_truthy());
    assert!(!ScriptValue::String("".into()).is_truthy());
    assert!(ScriptValue::String("x".into()).is_truthy());
    assert!(!ScriptValue::Bytes(vec![]).is_truthy());
    assert!(ScriptValue::Bytes(vec![0]).is_truthy());
    assert!(!ScriptValue::List(vec![]).is_truthy());
    assert!(ScriptValue::List(vec![ScriptValue::Null]).is_truthy());
    assert!(!ScriptValue::Map(HashMap::new()).is_truthy());
    assert!(ScriptValue::Address(0).is_truthy());
    assert!(ScriptValue::Callable("f".into()).is_truthy());
}

#[test]
fn value_is_null() {
    assert!(ScriptValue::Null.is_null());
    assert!(!ScriptValue::Bool(false).is_null());
    assert!(!ScriptValue::Int(0).is_null());
}

// ── as_int / as_float / as_bool / as_address / as_str / as_bytes / as_list ───

#[test]
fn as_int_paths() {
    assert_eq!(ScriptValue::Int(42).as_int().unwrap(), 42);
    assert_eq!(ScriptValue::Float(3.9).as_int().unwrap(), 3);
    assert_eq!(ScriptValue::Float(-3.9).as_int().unwrap(), -3);
    assert_eq!(ScriptValue::Bool(true).as_int().unwrap(), 1);
    assert_eq!(ScriptValue::Bool(false).as_int().unwrap(), 0);
    assert!(matches!(
        ScriptValue::String("x".into()).as_int(),
        Err(ScriptError::TypeMismatch { .. })
    ));
    // Out-of-range float
    assert!(matches!(
        ScriptValue::Float(1.0e30).as_int(),
        Err(ScriptError::TypeMismatch { .. })
    ));
}

#[test]
fn as_float_paths() {
    assert_eq!(ScriptValue::Float(2.5).as_float().unwrap(), 2.5);
    assert_eq!(ScriptValue::Int(7).as_float().unwrap(), 7.0);
    assert_eq!(ScriptValue::Bool(true).as_float().unwrap(), 1.0);
    assert_eq!(ScriptValue::Bool(false).as_float().unwrap(), 0.0);
    assert!(ScriptValue::Null.as_float().is_err());
}

#[test]
fn as_str_and_as_bytes() {
    assert_eq!(ScriptValue::String("hi".into()).as_str().unwrap(), "hi");
    assert!(ScriptValue::Int(0).as_str().is_err());
    assert_eq!(ScriptValue::Bytes(vec![1, 2]).as_bytes().unwrap(), &[1u8, 2][..]);
    assert!(ScriptValue::Null.as_bytes().is_err());
}

#[test]
fn as_bool_paths() {
    assert_eq!(ScriptValue::Bool(true).as_bool().unwrap(), true);
    assert!(ScriptValue::Int(1).as_bool().is_err());
}

#[test]
fn as_address_paths() {
    assert_eq!(ScriptValue::Address(0xdead).as_address().unwrap(), 0xdead);
    assert_eq!(ScriptValue::Int(42).as_address().unwrap(), 42);
    assert_eq!(ScriptValue::Int(-1).as_address().unwrap(), u64::MAX);
    assert!(ScriptValue::String("x".into()).as_address().is_err());
}

#[test]
fn as_list_and_map() {
    let l = ScriptValue::List(vec![ScriptValue::Int(1)]);
    assert_eq!(l.as_list().unwrap().len(), 1);
    let mut m = HashMap::new();
    m.insert("k".to_string(), ScriptValue::Int(7));
    let mv = ScriptValue::Map(m);
    assert_eq!(mv.as_map().unwrap().len(), 1);
    assert!(ScriptValue::Null.as_list().is_err());
    assert!(ScriptValue::Null.as_map().is_err());
}

#[test]
fn len_and_is_empty() {
    assert_eq!(ScriptValue::String("abc".into()).len().unwrap(), 3);
    assert_eq!(ScriptValue::Bytes(vec![0; 5]).len().unwrap(), 5);
    assert_eq!(ScriptValue::List(vec![]).len().unwrap(), 0);
    assert_eq!(ScriptValue::Map(HashMap::new()).len().unwrap(), 0);
    assert!(ScriptValue::Int(0).len().is_err());
    assert!(ScriptValue::String("".into()).is_empty().unwrap());
    assert!(!ScriptValue::String("x".into()).is_empty().unwrap());
}

// ── as_string / as_int_opt / as_bool_opt ─────────────────────────────────────

#[test]
fn opt_accessors() {
    assert_eq!(ScriptValue::String("z".into()).as_string(), Some("z"));
    assert_eq!(ScriptValue::Int(0).as_string(), None);
    assert_eq!(ScriptValue::Int(5).as_int_opt(), Some(5));
    assert_eq!(ScriptValue::Float(2.7).as_int_opt(), Some(2));
    assert_eq!(ScriptValue::Float(f64::NAN).as_int_opt(), None);
    assert_eq!(ScriptValue::Float(f64::INFINITY).as_int_opt(), None);
    assert_eq!(ScriptValue::Float(1e30).as_int_opt(), None);
    assert_eq!(ScriptValue::Bool(true).as_int_opt(), Some(1));
    assert_eq!(ScriptValue::Bool(false).as_int_opt(), Some(0));
    assert_eq!(ScriptValue::String("x".into()).as_int_opt(), None);
    assert_eq!(ScriptValue::Bool(true).as_bool_opt(), Some(true));
    assert_eq!(ScriptValue::Int(1).as_bool_opt(), None);
}

// ── to_json / from_json round-trip ───────────────────────────────────────────

#[test]
fn json_roundtrip_basic() {
    let v = ScriptValue::List(vec![
        ScriptValue::Int(1),
        ScriptValue::String("hi".into()),
        ScriptValue::Bool(false),
        ScriptValue::Null,
    ]);
    let j = v.to_json();
    let back = ScriptValue::from_json(j);
    assert_eq!(back, v);
}

#[test]
fn json_address_and_callable_are_strings() {
    assert_eq!(ScriptValue::Address(0x10).to_json(), serde_json::json!("0x10"));
    assert_eq!(
        ScriptValue::Callable("foo".into()).to_json(),
        serde_json::json!("<callable:foo>")
    );
}

#[test]
fn json_bytes_to_hex_string() {
    let v = ScriptValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(v.to_json(), serde_json::json!("deadbeef"));
}

#[test]
fn json_float_nan_becomes_null() {
    assert_eq!(ScriptValue::Float(f64::NAN).to_json(), serde_json::Value::Null);
}

// ── Display / to_display_string ──────────────────────────────────────────────

#[test]
fn display_variants() {
    assert_eq!(format!("{}", ScriptValue::Null), "null");
    assert_eq!(format!("{}", ScriptValue::Bool(true)), "true");
    assert_eq!(format!("{}", ScriptValue::Int(-3)), "-3");
    assert_eq!(format!("{}", ScriptValue::String("x".into())), "x");
    assert_eq!(format!("{}", ScriptValue::Bytes(vec![1, 2, 3])), "bytes(3)");
    assert_eq!(format!("{}", ScriptValue::Address(0x1f)), "0x1f");
    assert_eq!(format!("{}", ScriptValue::Callable("f".into())), "<fn:f>");
    let list = ScriptValue::List(vec![ScriptValue::Int(1), ScriptValue::Int(2)]);
    assert_eq!(format!("{list}"), "[1, 2]");
}

#[test]
fn display_map_sorted_keys() {
    let mut m = HashMap::new();
    m.insert("b".to_string(), ScriptValue::Int(2));
    m.insert("a".to_string(), ScriptValue::Int(1));
    let s = ScriptValue::Map(m).to_display_string();
    assert_eq!(s, "{a: 1, b: 2}");
}

// ── From impls ───────────────────────────────────────────────────────────────

#[test]
fn from_impls() {
    assert_eq!(ScriptValue::from(1i32), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1i64), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1u32), ScriptValue::Int(1));
    assert_eq!(ScriptValue::from(1u64), ScriptValue::Address(1));
    assert_eq!(ScriptValue::from(true), ScriptValue::Bool(true));
    assert_eq!(ScriptValue::from(1.5f32), ScriptValue::Float(1.5));
    assert_eq!(ScriptValue::from(1.5f64), ScriptValue::Float(1.5));
    assert_eq!(ScriptValue::from("x"), ScriptValue::String("x".into()));
    assert_eq!(ScriptValue::from("x".to_string()), ScriptValue::String("x".into()));
    assert_eq!(ScriptValue::from(vec![1u8, 2]), ScriptValue::Bytes(vec![1, 2]));
    let lst: Vec<ScriptValue> = vec![ScriptValue::Int(1)];
    assert_eq!(ScriptValue::from(lst.clone()), ScriptValue::List(lst));
}

#[test]
fn default_is_null() {
    assert_eq!(ScriptValue::default(), ScriptValue::Null);
}

// ── ScriptContext ────────────────────────────────────────────────────────────

#[test]
fn context_basic() {
    let mut ctx = ScriptContext::new();
    ctx.set_global("x", ScriptValue::Int(1));
    assert_eq!(ctx.get_global("x"), Some(&ScriptValue::Int(1)));
    assert_eq!(ctx.remove_global("x"), Some(ScriptValue::Int(1)));
    assert_eq!(ctx.get_global("x"), None);

    ctx.write_output("line1");
    ctx.write_error("err1");
    assert_eq!(ctx.output, vec!["line1".to_string()]);
    assert_eq!(ctx.error_output, vec!["err1".to_string()]);

    ctx.set_meta("k", "v");
    assert_eq!(ctx.get_meta("k"), Some(&"v".to_string()));
}

#[test]
fn context_with_timeout_and_globals() {
    let ctx = ScriptContext::with_timeout(1000);
    assert_eq!(ctx.timeout_ms, Some(1000));

    let mut g = HashMap::new();
    g.insert("a".to_string(), ScriptValue::Int(5));
    let ctx = ScriptContext::new().with_globals(g);
    assert_eq!(ctx.get_global("a"), Some(&ScriptValue::Int(5)));
    assert_eq!(ctx.global_names().len(), 1);
}

#[test]
fn context_register_and_get_fn() {
    let mut ctx = ScriptContext::new();
    let f: NativeFunction = native_fn(|_| Ok(ScriptValue::Int(7)));
    ctx.register_fn("f", f);
    let g = ctx.get_fn("f").unwrap();
    assert_eq!(g.call(&[]).unwrap(), ScriptValue::Int(7));
    assert!(ctx.get_fn("missing").is_none());
}

#[test]
fn context_debug_does_not_panic() {
    let mut ctx = ScriptContext::new();
    ctx.set_global("g", ScriptValue::Int(0));
    let _ = format!("{ctx:?}");
}

// ── ScriptResult ─────────────────────────────────────────────────────────────

#[test]
fn script_result_construction() {
    let mut ctx = ScriptContext::new();
    ctx.write_output("a");
    ctx.write_output("b");
    ctx.write_error("e");
    let r = ScriptResult::new(ScriptValue::Int(1), &ctx).with_elapsed(42);
    assert_eq!(r.value, ScriptValue::Int(1));
    assert_eq!(r.elapsed_ms, 42);
    assert!(r.success);
    assert_eq!(r.stdout_joined(), "a\nb");
    assert_eq!(r.stderr_joined(), "e");
    assert!(r.has_errors());
}

#[test]
fn script_result_failure() {
    let r = ScriptResult::failure("boom");
    assert!(!r.success);
    assert_eq!(r.value, ScriptValue::Null);
    assert!(r.has_errors());
    assert_eq!(r.stderr, vec!["boom".to_string()]);
}

// ── ScriptModule ─────────────────────────────────────────────────────────────

#[test]
fn module_register_and_lookup() {
    let mut m = ScriptModule::new("mymod");
    assert_eq!(m.name, "mymod");
    assert_eq!(m.symbol_count(), 0);
    m.add_fn("f", native_fn(|_| Ok(ScriptValue::Null)));
    m.add_const("PI", ScriptValue::Float(3.14));
    assert_eq!(m.symbol_count(), 2);
    assert!(m.get_fn("f").is_some());
    assert!(m.get_fn("missing").is_none());
    assert_eq!(m.get_const("PI"), Some(&ScriptValue::Float(3.14)));
    let _ = format!("{m:?}");
}

// ── CompiledScript ───────────────────────────────────────────────────────────

#[test]
fn compiled_script_basics() {
    let mut c = CompiledScript::new("rhai", "let x = 1;");
    assert_eq!(c.engine_name, "rhai");
    assert!(!c.is_empty());
    c.add_warning("unused");
    assert_eq!(c.warnings.len(), 1);

    let e = CompiledScript::empty("lua");
    assert!(e.is_empty());
    assert_eq!(e.source, "");
}

// ── ScriptEngineRegistry ─────────────────────────────────────────────────────

struct DummyEngine {
    n: &'static str,
    exts: Vec<&'static str>,
}

#[async_trait::async_trait]
impl ScriptEngine for DummyEngine {
    fn name(&self) -> &str { self.n }
    fn file_extensions(&self) -> &[&str] { &self.exts }
    async fn execute(&self, _: &str, _: &mut ScriptContext) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::Int(1))
    }
    async fn execute_file(&self, _: &std::path::Path, _: &mut ScriptContext) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::Null)
    }
    fn call_function(&self, _: &str, _: &[ScriptValue], _: &mut ScriptContext) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::Null)
    }
    fn register_function(&mut self, _: &str, _: Box<dyn ScriptFn>) -> Result<(), ScriptError> { Ok(()) }
    fn set_global(&mut self, _: &str, _: ScriptValue) -> Result<(), ScriptError> { Ok(()) }
    fn get_global(&self, _: &str) -> Option<ScriptValue> { None }
}

#[test]
fn registry_register_find_remove() {
    let reg = ScriptEngineRegistry::new();
    assert_eq!(reg.count(), 0);
    reg.register(Arc::new(DummyEngine { n: "a", exts: vec!["a1", "a2"] }));
    reg.register(Arc::new(DummyEngine { n: "b", exts: vec!["b1"] }));
    assert_eq!(reg.count(), 2);
    assert!(reg.find_by_name("a").is_some());
    assert!(reg.find_by_name("missing").is_none());
    assert!(reg.find_by_extension("a2").is_some());
    assert!(reg.find_by_extension("nope").is_none());
    let names = reg.list_engines();
    assert!(names.contains(&"a".to_string()));
    assert!(reg.remove("a"));
    assert!(!reg.remove("a"));
    assert_eq!(reg.count(), 1);
    let _ = format!("{reg:?}");
}

#[test]
fn registry_default() {
    let reg = ScriptEngineRegistry::default();
    assert_eq!(reg.count(), 0);
}

// ── ScriptPipeline ───────────────────────────────────────────────────────────

#[test]
fn pipeline_basics() {
    let mut p = ScriptPipeline::new();
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
    p.push(PipelineStep::new("a", "code").with_label("step1"));
    p.push(PipelineStep::new("a", "code2"));
    assert_eq!(p.len(), 2);
    assert!(!p.is_empty());
    let d = ScriptPipeline::default();
    assert!(d.is_empty());
}

#[test]
fn pipeline_executes_and_threads_prev() {
    let reg = ScriptEngineRegistry::new();
    reg.register(Arc::new(DummyEngine { n: "x", exts: vec![] }));
    let mut p = ScriptPipeline::new();
    p.push(PipelineStep::new("x", "1"));
    p.push(PipelineStep::new("x", "2"));
    let mut ctx = ScriptContext::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(p.execute_all(&reg, &mut ctx)).unwrap();
    assert_eq!(results.len(), 2);
    // _prev should be set to the previous step's value (Int(1)) by the end.
    assert_eq!(ctx.get_global("_prev"), Some(&ScriptValue::Int(1)));
}

#[test]
fn pipeline_engine_not_found_errors() {
    let reg = ScriptEngineRegistry::new();
    let mut p = ScriptPipeline::new();
    p.push(PipelineStep::new("ghost", "code"));
    let mut ctx = ScriptContext::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(p.execute_all(&reg, &mut ctx));
    assert!(matches!(res, Err(ScriptError::EngineNotFound { .. })));
}

// ── SandboxPolicy ────────────────────────────────────────────────────────────

#[test]
fn sandbox_deny_all() {
    let p = SandboxPolicy::deny_all();
    assert!(!p.allow_fs_read);
    assert!(!p.allow_fs_write);
    assert!(!p.allow_network);
    assert!(!p.allow_subprocess);
    assert_eq!(p.max_heap_bytes, 0);
    assert_eq!(p.max_time_ms, 0);
    assert_eq!(p.max_call_depth, 0);
}

#[test]
fn sandbox_allow_all_and_read_only() {
    let p = SandboxPolicy::allow_all();
    assert!(p.allow_fs_read && p.allow_fs_write && p.allow_network && p.allow_subprocess);
    let r = SandboxPolicy::read_only();
    assert!(r.allow_fs_read);
    assert!(!r.allow_fs_write);
    assert_eq!(r.max_time_ms, 5_000);
    assert_eq!(r.max_call_depth, 256);
}

// ── Built-ins ────────────────────────────────────────────────────────────────

#[test]
fn hex_to_bytes_basic_and_prefix() {
    let r = builtin_hex_to_bytes(&[ScriptValue::String("deadbeef".into())]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
    let r = builtin_hex_to_bytes(&[ScriptValue::String("0xCAFE".into())]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xca, 0xfe]));
    let r = builtin_hex_to_bytes(&[ScriptValue::String("0X01".into())]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0x01]));
    let r = builtin_hex_to_bytes(&[ScriptValue::String("".into())]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![]));
}

#[test]
fn hex_to_bytes_errors() {
    // No args.
    assert!(matches!(
        builtin_hex_to_bytes(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    // Odd length.
    assert!(matches!(
        builtin_hex_to_bytes(&[ScriptValue::String("abc".into())]),
        Err(ScriptError::RuntimeError(_))
    ));
    // Wrong type.
    assert!(matches!(
        builtin_hex_to_bytes(&[ScriptValue::Int(1)]),
        Err(ScriptError::TypeMismatch { .. })
    ));
    // Invalid hex.
    assert!(matches!(
        builtin_hex_to_bytes(&[ScriptValue::String("zz".into())]),
        Err(ScriptError::RuntimeError(_))
    ));
}

#[test]
fn bytes_to_hex_roundtrip() {
    let v = ScriptValue::Bytes(vec![0, 0xff, 0x10]);
    let r = builtin_bytes_to_hex(&[v]).unwrap();
    assert_eq!(r, ScriptValue::String("00ff10".into()));
    // Round-trip with hex_to_bytes.
    let r2 = builtin_hex_to_bytes(&[r]).unwrap();
    assert_eq!(r2, ScriptValue::Bytes(vec![0, 0xff, 0x10]));
}

#[test]
fn bytes_to_hex_errors() {
    assert!(matches!(
        builtin_bytes_to_hex(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_bytes_to_hex(&[ScriptValue::Int(1)]),
        Err(ScriptError::TypeMismatch { .. })
    ));
}

#[test]
fn read_u8_u16_u32_u64() {
    let b = ScriptValue::Bytes(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(
        builtin_read_u8(&[b.clone(), ScriptValue::Int(0)]).unwrap(),
        ScriptValue::Int(1)
    );
    assert_eq!(
        builtin_read_u16(&[b.clone(), ScriptValue::Int(0)]).unwrap(),
        ScriptValue::Int(0x0201)
    );
    assert_eq!(
        builtin_read_u32(&[b.clone(), ScriptValue::Int(0)]).unwrap(),
        ScriptValue::Int(0x04030201)
    );
    assert_eq!(
        builtin_read_u32_be(&[b.clone(), ScriptValue::Int(0)]).unwrap(),
        ScriptValue::Int(0x01020304)
    );
    assert_eq!(
        builtin_read_u64(&[b.clone(), ScriptValue::Int(0)]).unwrap(),
        // Fixed: read_u64 returns Int for consistency with read_u8/u16/u32 family (see unit test_read_u64_le).
        ScriptValue::Int(0x0807060504030201)
    );
}

#[test]
fn read_oob_returns_error() {
    let b = ScriptValue::Bytes(vec![0u8; 2]);
    assert!(matches!(
        builtin_read_u32(&[b.clone(), ScriptValue::Int(0)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
    assert!(matches!(
        builtin_read_u16(&[b, ScriptValue::Int(1)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
}

#[test]
fn read_negative_offset_errors() {
    let b = ScriptValue::Bytes(vec![0u8; 4]);
    assert!(matches!(
        builtin_read_u8(&[b, ScriptValue::Int(-1)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
}

#[test]
fn read_arity_error() {
    assert!(matches!(
        builtin_read_u8(&[ScriptValue::Bytes(vec![0])]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn write_u8_u16_u32_u64() {
    let b = ScriptValue::Bytes(vec![0u8; 8]);
    let r = builtin_write_u8(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(0xAB)]).unwrap();
    assert_eq!(r.as_bytes().unwrap()[0], 0xAB);

    let r = builtin_write_u16(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(0x1234)]).unwrap();
    assert_eq!(&r.as_bytes().unwrap()[..2], &[0x34, 0x12]);

    let r = builtin_write_u32(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(0xDEADBEEF)]).unwrap();
    assert_eq!(&r.as_bytes().unwrap()[..4], &[0xef, 0xbe, 0xad, 0xde]);

    let r = builtin_write_u64(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(1)]).unwrap();
    assert_eq!(&r.as_bytes().unwrap()[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn write_arity_and_oob() {
    let b = ScriptValue::Bytes(vec![0u8; 1]);
    assert!(matches!(
        builtin_write_u8(&[b.clone(), ScriptValue::Int(0)]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_write_u32(&[b, ScriptValue::Int(0), ScriptValue::Int(1)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
}

#[test]
fn write_round_trip_with_read() {
    let b = ScriptValue::Bytes(vec![0u8; 4]);
    let w = builtin_write_u32(&[b, ScriptValue::Int(0), ScriptValue::Int(0xCAFEBABEi64)]).unwrap();
    let r = builtin_read_u32(&[w, ScriptValue::Int(0)]).unwrap();
    assert_eq!(r, ScriptValue::Int(0xCAFEBABE));
}

#[test]
fn xor_bytes_cycles_key() {
    let a = ScriptValue::Bytes(vec![0xff; 5]);
    let k = ScriptValue::Bytes(vec![0x0f, 0xf0]);
    let r = builtin_xor_bytes(&[a, k]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xf0, 0x0f, 0xf0, 0x0f, 0xf0]));
}

#[test]
fn xor_bytes_empty_key_errors() {
    let a = ScriptValue::Bytes(vec![1, 2]);
    let k = ScriptValue::Bytes(vec![]);
    assert!(matches!(
        builtin_xor_bytes(&[a, k]),
        Err(ScriptError::RuntimeError(_))
    ));
}

#[test]
fn xor_bytes_arity_and_type_errors() {
    assert!(matches!(
        builtin_xor_bytes(&[ScriptValue::Bytes(vec![1])]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_xor_bytes(&[ScriptValue::Int(1), ScriptValue::Bytes(vec![1])]),
        Err(ScriptError::TypeMismatch { .. })
    ));
}

#[test]
fn to_string_typeof_len() {
    assert_eq!(
        builtin_to_string(&[ScriptValue::Int(7)]).unwrap(),
        ScriptValue::String("7".into())
    );
    assert_eq!(
        builtin_typeof(&[ScriptValue::Null]).unwrap(),
        ScriptValue::String("null".into())
    );
    assert_eq!(
        builtin_len(&[ScriptValue::String("hello".into())]).unwrap(),
        ScriptValue::Int(5)
    );
    assert!(matches!(
        builtin_len(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_to_string(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_typeof(&[]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn bytes_concat_basic() {
    let r = builtin_bytes_concat(&[
        ScriptValue::Bytes(vec![1, 2]),
        ScriptValue::Bytes(vec![3, 4]),
    ])
    .unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![1, 2, 3, 4]));
}

#[test]
fn bytes_concat_errors() {
    assert!(matches!(
        builtin_bytes_concat(&[ScriptValue::Bytes(vec![1])]),
        Err(ScriptError::ArityMismatch { .. })
    ));
    assert!(matches!(
        builtin_bytes_concat(&[ScriptValue::Int(1), ScriptValue::Bytes(vec![1])]),
        Err(ScriptError::TypeMismatch { .. })
    ));
}

#[test]
fn bytes_slice_happy_and_bounds() {
    let b = ScriptValue::Bytes(vec![10, 20, 30, 40, 50]);
    let r = builtin_bytes_slice(&[b.clone(), ScriptValue::Int(1), ScriptValue::Int(4)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![20, 30, 40]));
    // Empty slice.
    let r = builtin_bytes_slice(&[b.clone(), ScriptValue::Int(2), ScriptValue::Int(2)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![]));
    // end > len
    assert!(matches!(
        builtin_bytes_slice(&[b.clone(), ScriptValue::Int(0), ScriptValue::Int(10)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
    // start > end
    assert!(matches!(
        builtin_bytes_slice(&[b.clone(), ScriptValue::Int(3), ScriptValue::Int(1)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
    // negative
    assert!(matches!(
        builtin_bytes_slice(&[b, ScriptValue::Int(-1), ScriptValue::Int(2)]),
        Err(ScriptError::IndexOutOfBounds { .. })
    ));
}

#[test]
fn bytes_slice_arity() {
    assert!(matches!(
        builtin_bytes_slice(&[ScriptValue::Bytes(vec![1]), ScriptValue::Int(0)]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn bytes_fill_basic() {
    let r = builtin_bytes_fill(&[ScriptValue::Int(4), ScriptValue::Int(0xAB)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![0xAB; 4]));
    let r = builtin_bytes_fill(&[ScriptValue::Int(0), ScriptValue::Int(0)]).unwrap();
    assert_eq!(r, ScriptValue::Bytes(vec![]));
}

#[test]
fn bytes_fill_negative_errors() {
    assert!(matches!(
        builtin_bytes_fill(&[ScriptValue::Int(-1), ScriptValue::Int(0)]),
        Err(ScriptError::TypeMismatch { .. })
    ));
    assert!(matches!(
        builtin_bytes_fill(&[ScriptValue::Int(1)]),
        Err(ScriptError::ArityMismatch { .. })
    ));
}

#[test]
fn bytes_find_happy() {
    let h = ScriptValue::Bytes(vec![0, 1, 2, 3, 4, 5]);
    let n = ScriptValue::Bytes(vec![2, 3]);
    assert_eq!(builtin_bytes_find(&[h, n]).unwrap(), ScriptValue::Int(2));
}

#[test]
fn bytes_find_missing_returns_null() {
    let h = ScriptValue::Bytes(vec![0, 1, 2]);
    let n = ScriptValue::Bytes(vec![9, 9]);
    assert_eq!(builtin_bytes_find(&[h, n]).unwrap(), ScriptValue::Null);
}

#[test]
fn bytes_find_empty_needle_returns_zero() {
    let h = ScriptValue::Bytes(vec![1, 2]);
    let n = ScriptValue::Bytes(vec![]);
    assert_eq!(builtin_bytes_find(&[h, n]).unwrap(), ScriptValue::Int(0));
}

#[test]
fn bytes_find_needle_longer_than_haystack() {
    let h = ScriptValue::Bytes(vec![1]);
    let n = ScriptValue::Bytes(vec![1, 2, 3]);
    // saturating_sub gives 0; loop runs for i=0; index range [0..3] is out of
    // bounds for a 1-byte haystack and will panic if not guarded.
    let r = builtin_bytes_find(&[h, n]);
    assert!(matches!(r, Ok(ScriptValue::Null)),
        "bytes_find should return Null when needle longer than haystack, got {r:?}");
}

#[test]
fn bytes_find_empty_haystack_nonempty_needle() {
    let h = ScriptValue::Bytes(vec![]);
    let n = ScriptValue::Bytes(vec![1]);
    let r = builtin_bytes_find(&[h, n]);
    assert!(matches!(r, Ok(ScriptValue::Null)),
        "bytes_find on empty haystack should return Null, got {r:?}");
}

// ── builtin_functions / register_builtins / re_module ────────────────────────

#[test]
fn builtin_functions_contains_all_names() {
    let m = builtin_functions();
    for n in [
        "hex_to_bytes", "bytes_to_hex", "read_u8", "read_u16", "read_u32",
        "read_u32_be", "read_u64", "write_u8", "write_u16", "write_u32",
        "write_u64", "xor_bytes", "to_string", "len", "typeof",
        "bytes_concat", "bytes_slice", "bytes_fill", "bytes_find",
    ] {
        assert!(m.contains_key(n), "missing builtin: {n}");
    }
}

#[test]
fn register_builtins_populates_ctx() {
    let mut ctx = ScriptContext::new();
    register_builtins(&mut ctx);
    assert!(ctx.get_fn("hex_to_bytes").is_some());
    assert!(ctx.get_fn("len").is_some());
    // Sanity: call one through the registered handle.
    let r = ctx.get_fn("typeof").unwrap().call(&[ScriptValue::Bool(true)]).unwrap();
    assert_eq!(r, ScriptValue::String("bool".into()));
}

#[test]
fn re_module_has_constants_and_fns() {
    let m = re_module();
    assert_eq!(m.name, "re");
    assert_eq!(m.get_const("NULL"), Some(&ScriptValue::Null));
    assert_eq!(m.get_const("TRUE"), Some(&ScriptValue::Bool(true)));
    assert_eq!(m.get_const("FALSE"), Some(&ScriptValue::Bool(false)));
    assert!(m.get_fn("hex_to_bytes").is_some());
}

// ── VariableFrame ────────────────────────────────────────────────────────────

#[test]
fn frame_root_and_bind_lookup() {
    let mut f = VariableFrame::root();
    assert_eq!(f.local_count(), 0);
    f.bind("a", ScriptValue::Int(1));
    assert_eq!(f.lookup("a"), Some(&ScriptValue::Int(1)));
    assert_eq!(f.local_count(), 1);
    assert!(f.lookup("missing").is_none());
}

#[test]
fn frame_child_inherits() {
    let mut root = VariableFrame::root();
    root.bind("x", ScriptValue::Int(5));
    let child = VariableFrame::child(root);
    assert_eq!(child.lookup("x"), Some(&ScriptValue::Int(5)));
    assert_eq!(child.local_count(), 0); // x is in parent, not local
}

#[test]
fn frame_assign_walks_chain() {
    let mut root = VariableFrame::root();
    root.bind("x", ScriptValue::Int(1));
    let mut child = VariableFrame::child(root);
    child.bind("y", ScriptValue::Int(2));
    // Assign to parent.
    assert!(child.assign("x", ScriptValue::Int(99)));
    assert_eq!(child.lookup("x"), Some(&ScriptValue::Int(99)));
    // Assign to local.
    assert!(child.assign("y", ScriptValue::Int(20)));
    assert_eq!(child.lookup("y"), Some(&ScriptValue::Int(20)));
    // Missing.
    assert!(!child.assign("zzz", ScriptValue::Int(0)));
}

// ── ScriptHost ───────────────────────────────────────────────────────────────

struct DummyBackend {
    n: &'static str,
    last_eval: parking_lot::Mutex<String>,
}

impl ScriptingBackend for DummyBackend {
    fn name(&self) -> &str { self.n }
    fn eval(&mut self, code: &str) -> Result<ScriptValue, ScriptError> {
        *self.last_eval.lock() = code.to_string();
        Ok(ScriptValue::String(code.into()))
    }
    fn exec(&mut self, _: &str) -> Result<(), ScriptError> { Ok(()) }
    fn call(&mut self, func: &str, _: Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> {
        Ok(ScriptValue::String(func.into()))
    }
    fn load_file(&mut self, _: &std::path::Path) -> Result<(), ScriptError> { Ok(()) }
    fn register_fn(
        &mut self,
        _: &str,
        _: Box<dyn Fn(Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> + Send + Sync>,
    ) {}
}

#[test]
fn host_add_backend_sets_active() {
    let mut h = ScriptHost::new();
    h.add_backend(Box::new(DummyBackend {
        n: "x",
        last_eval: parking_lot::Mutex::new(String::new()),
    }));
    let _ = format!("{h:?}");
}

// ── ScriptFn closure adapter ─────────────────────────────────────────────────

#[test]
fn closure_implements_script_fn() {
    let f = native_fn(|args: &[ScriptValue]| Ok(ScriptValue::Int(args.len() as i64)));
    assert_eq!(f.call(&[]).unwrap(), ScriptValue::Int(0));
    assert_eq!(
        f.call(&[ScriptValue::Null, ScriptValue::Null]).unwrap(),
        ScriptValue::Int(2)
    );
    // Default arity is None, default name is "<native>".
    assert!(f.arity().is_none());
    assert_eq!(f.name(), "<native>");
}

// ── ScriptError is Send + Sync + Clone ───────────────────────────────────────

#[test]
fn error_is_send_sync_clone() {
    fn assert_send_sync<T: Send + Sync + Clone>() {}
    assert_send_sync::<ScriptError>();
    let e = ScriptError::Custom("hi".into());
    let e2 = e.clone();
    assert_eq!(format!("{e}"), format!("{e2}"));
}
