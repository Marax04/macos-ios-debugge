// Deep adversarial integration tests for rustre-plugin-lua.

use rustre_plugin_lua::{
    ApiFunction, ApiTable, LuaApiProvider, LuaPluginLoader, LuaState, LuaStateManager, StatePool,
};
use rustre_plugin_lua::lua_api_provider::ApiError;
use rustre_plugin_lua::lua_plugin_loader::LuaLoadError;
use rustre_plugin_lua::lua_state_manager::StateError;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// â"€â"€ LuaState â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn state_new_id_preserved() {
    for id in [0u64, 1, 42, u64::MAX, u64::MAX - 1, 1 << 32] {
        let s = LuaState::new(id);
        assert_eq!(s.id(), id);
    }
}

#[test]
fn state_eval_arithmetic() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return 2+3*4").unwrap(), "14");
    assert_eq!(s.eval_string("return -1").unwrap(), "-1");
    assert_eq!(s.eval_string("return 0").unwrap(), "0");
}

#[test]
fn state_eval_boundary_ints() {
    // Lua source literals are double-typed for very large magnitudes, so use
    // arithmetic expressions that the lexer treats as integers end-to-end.
    let s = LuaState::new(0);
    let max = i64::MAX;
    assert_eq!(s.eval_string(&format!("return {max}")).unwrap(), max.to_string());
    // i64::MIN = -i64::MAX - 1, computed inside Lua to stay in the integer domain.
    let min_expr = format!("return -{max} - 1");
    assert_eq!(s.eval_string(&min_expr).unwrap(), i64::MIN.to_string());
}

#[test]
fn state_eval_strings() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return ''").unwrap(), "");
    assert_eq!(s.eval_string("return 'a'").unwrap(), "a");
    assert_eq!(s.eval_string("return string.rep('x',100)").unwrap().len(), 100);
}

#[test]
fn state_eval_bool_nil_table() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return false").unwrap(), "false");
    assert_eq!(s.eval_string("return true").unwrap(), "true");
    assert_eq!(s.eval_string("return nil").unwrap(), "nil");
    let t = s.eval_string("return {}").unwrap();
    assert!(t.starts_with('<') && t.contains("table"));
}

#[test]
fn state_exec_side_effects() {
    let s = LuaState::new(7);
    s.exec_string("g_v = 11").unwrap();
    assert_eq!(s.eval_string("return g_v").unwrap(), "11");
}

#[test]
fn state_eval_errors_dont_panic() {
    let s = LuaState::new(0);
    assert!(s.eval_string("@@@bad@@@").is_err());
    assert!(s.eval_string("error('boom')").is_err());
    assert!(s.eval_string("return nonexistent.field").is_err());
}

#[test]
fn state_exec_errors_dont_panic() {
    let s = LuaState::new(0);
    assert!(s.exec_string("syntax !! error").is_err());
    assert!(s.exec_string("error('x')").is_err());
}

#[test]
fn state_fuzz_lcg_never_panics() {
    let s = LuaState::new(0);
    let mut g = make_lcg();
    for _ in 0..60 {
        let n = g();
        let code = format!("return {}", n.cast_signed());
        let r = s.eval_string(&code);
        assert!(r.is_ok() || r.is_err());
    }
}

#[test]
fn state_fuzz_random_garbage() {
    let s = LuaState::new(0);
    let mut g = make_lcg();
    let chars: &[u8] = b"abcdef0123 +-*/();={}[].,'\"\n\t!@#$";
    for _ in 0..50 {
        let len = usize::try_from(g() % 40).unwrap_or(usize::MAX);
        let bytes: Vec<u8> = (0..len).map(|_| chars[(g() as usize) % chars.len()]).collect();
        let s_in = String::from_utf8_lossy(&bytes).to_string();
        let _ = s.eval_string(&s_in);
        let _ = s.exec_string(&s_in);
    }
}

#[test]
fn state_raw_lua_usable() {
    let s = LuaState::new(0);
    s.raw().globals().set("rk", 99i64).unwrap();
    assert_eq!(s.eval_string("return rk").unwrap(), "99");
}

#[test]
fn state_debug_format() {
    let s = LuaState::new(123);
    let d = format!("{s:?}");
    assert!(d.contains("LuaState"));
    assert!(d.contains("123"));
}

#[test]
fn state_eval_float() {
    let s = LuaState::new(0);
    let r = s.eval_string("return 1.5").unwrap();
    assert!(r.contains("1.5") || r.contains("1,5"));
}

#[test]
fn state_truncated_inputs() {
    let s = LuaState::new(0);
    for code in ["", " ", "return", "return ", "function", "if true then"] {
        let _ = s.eval_string(code);
    }
}

// â"€â"€ StatePool / LuaStateManager â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn pool_default_value() {
    assert_eq!(StatePool::default().max_states, 8);
}

#[test]
fn pool_copy_clone() {
    let a = StatePool { max_states: 5 };
    let b = a;
    let c = a;
    assert_eq!(b.max_states, 5);
    assert_eq!(c.max_states, 5);
}

#[test]
fn manager_acquire_release_cycle() {
    let mgr = LuaStateManager::new(StatePool { max_states: 4 });
    let mut v = Vec::new();
    for _ in 0..4 {
        v.push(mgr.acquire().unwrap());
    }
    assert_eq!(mgr.issued(), 4);
    assert!(matches!(mgr.acquire(), Err(StateError::Exhausted(4))));
    while let Some(s) = v.pop() {
        mgr.release(s);
    }
    assert_eq!(mgr.issued(), 0);
    assert!(mgr.idle() <= 4);
}

#[test]
fn manager_recycles_states() {
    let mgr = LuaStateManager::new(StatePool { max_states: 2 });
    let s1 = mgr.acquire().unwrap();
    let id1 = s1.id();
    mgr.release(s1);
    assert_eq!(mgr.idle(), 1);
    let s2 = mgr.acquire().unwrap();
    // Recycled state should have the same id (it's the same VM).
    assert_eq!(s2.id(), id1);
    mgr.release(s2);
}

#[test]
fn manager_unique_ids() {
    let mgr = LuaStateManager::new(StatePool { max_states: 8 });
    let mut ids = Vec::new();
    let mut held = Vec::new();
    for _ in 0..5 {
        let s = mgr.acquire().unwrap();
        ids.push(s.id());
        held.push(s);
    }
    assert_eq!(held.len(), 5);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 5);
}

#[test]
fn manager_release_with_outstanding_ref_does_not_park() {
    let mgr = LuaStateManager::new(StatePool { max_states: 2 });
    let s = mgr.acquire().unwrap();
    let extra = s.clone();
    mgr.release(s);
    assert_eq!(mgr.issued(), 0);
    // Cannot park because extra ref is held.
    assert_eq!(mgr.idle(), 0);
    drop(extra);
}

#[test]
fn manager_release_saturating() {
    let mgr = LuaStateManager::new(StatePool { max_states: 2 });
    let s = mgr.acquire().unwrap();
    mgr.release(s.clone());
    // Issued went 1 -> 0; another release should saturate at 0 not underflow.
    mgr.release(s);
    assert_eq!(mgr.issued(), 0);
}

#[test]
fn manager_exhaustion_message() {
    let mgr = LuaStateManager::new(StatePool { max_states: 1 });
    let _a = mgr.acquire().unwrap();
    let e = mgr.acquire().unwrap_err();
    let msg = format!("{e}");
    assert!(msg.contains("exhausted"));
    assert!(msg.contains('1'));
}

#[test]
fn manager_debug_format() {
    let mgr = LuaStateManager::new(StatePool { max_states: 3 });
    let d = format!("{mgr:?}");
    assert!(d.contains("LuaStateManager"));
}

#[test]
fn manager_threaded_acquire_release() {
    let mgr = Arc::new(LuaStateManager::new(StatePool { max_states: 8 }));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let m = mgr.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(s) = m.acquire() {
                    let _ = s.eval_string("return 1");
                    m.release(s);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(mgr.issued(), 0);
}

#[test]
fn manager_zero_capacity() {
    let mgr = LuaStateManager::new(StatePool { max_states: 0 });
    assert!(matches!(mgr.acquire(), Err(StateError::Exhausted(0))));
}

#[test]
fn state_error_display_lua() {
    let s = LuaState::new(0);
    match s.eval_string("error('e')") {
        Err(StateError::Lua(_)) => {}
        other => panic!("expected Lua error, got {other:?}"),
    }
}

// â"€â"€ LuaApiProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn provider_default_empty() {
    let p = LuaApiProvider::default();
    assert_eq!(p.table_count(), 0);
    assert!(p.table_names().is_empty());
}

#[test]
fn provider_register_many() {
    let p = LuaApiProvider::new();
    for i in 0..30 {
        p.register_table(ApiTable::new(format!("t{i}"))).unwrap();
    }
    assert_eq!(p.table_count(), 30);
    let names = p.table_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn provider_duplicate_returns_err() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("z")).unwrap();
    match p.register_table(ApiTable::new("z")) {
        Err(ApiError::Duplicate(n)) => assert_eq!(n, "z"),
        other => panic!("expected duplicate err, got {other:?}"),
    }
}

#[test]
fn provider_install_invokes_callbacks() {
    let p = LuaApiProvider::new();
    let t = ApiTable::new("ns").with_function(ApiFunction::new("ident", "doc", |_, args| {
        Ok(args.into_iter().next().unwrap_or(mlua::Value::Nil))
    }));
    p.register_table(t).unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let v: i64 = lua.load("return rustre.ns.ident(7)").eval().unwrap();
    assert_eq!(v, 7);
}

#[test]
fn provider_install_multi_function_table() {
    let p = LuaApiProvider::new();
    let t = ApiTable::new("m")
        .with_function(ApiFunction::new("add1", "", |_, a| {
            let n = match a.into_iter().next() {
                Some(mlua::Value::Integer(i)) => i,
                _ => 0,
            };
            Ok(mlua::Value::Integer(n + 1))
        }))
        .with_function(ApiFunction::new("sq", "", |_, a| {
            let n = match a.into_iter().next() {
                Some(mlua::Value::Integer(i)) => i,
                _ => 0,
            };
            Ok(mlua::Value::Integer(n * n))
        }));
    p.register_table(t).unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let v: i64 = lua
        .load("return rustre.m.add1(rustre.m.sq(5))")
        .eval()
        .unwrap();
    assert_eq!(v, 26);
}

#[test]
fn provider_install_empty_ok() {
    let p = LuaApiProvider::new();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let exists: bool = lua.load("return type(rustre) == 'table'").eval().unwrap();
    assert!(exists);
}

#[test]
fn provider_callback_can_error() {
    let p = LuaApiProvider::new();
    let t = ApiTable::new("e").with_function(ApiFunction::new("boom", "", |_, _| {
        Err::<mlua::Value, _>(mlua::Error::external("bad"))
    }));
    p.register_table(t).unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let r = lua.load("return rustre.e.boom()").eval::<mlua::Value>();
    assert!(r.is_err());
}

#[test]
fn provider_debug_format() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("dbg")).unwrap();
    let d = format!("{p:?}");
    assert!(d.contains("LuaApiProvider"));
}

#[test]
fn provider_install_twice_overwrites_global() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("only")).unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    p.install(&lua).unwrap();
    let n: i64 = lua.load("local c=0 for k,_ in pairs(rustre) do c=c+1 end return c").eval().unwrap();
    assert_eq!(n, 1);
}

#[test]
fn provider_threaded_register() {
    let p = Arc::new(LuaApiProvider::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let pc = p.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let _ = pc.register_table(ApiTable::new(format!("t{t}_{i}")));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(p.table_count(), 400);
}

#[test]
fn api_function_new_preserves_fields() {
    let f = ApiFunction::new("nm", "d0c", |_, _| Ok(mlua::Value::Nil));
    assert_eq!(f.name, "nm");
    assert_eq!(f.doc, "d0c");
}

#[test]
fn api_table_with_function_chaining() {
    let t = ApiTable::new("x")
        .with_function(ApiFunction::new("a", "", |_, _| Ok(mlua::Value::Nil)))
        .with_function(ApiFunction::new("b", "", |_, _| Ok(mlua::Value::Nil)));
    assert_eq!(t.name, "x");
    assert_eq!(t.functions.len(), 2);
}

#[test]
fn api_table_clone() {
    let t = ApiTable::new("c").with_function(ApiFunction::new("f", "", |_, _| Ok(mlua::Value::Nil)));
    let t2 = t.clone();
    assert_eq!(t.name, t2.name);
    assert_eq!(t.functions.len(), t2.functions.len());
}

// â"€â"€ LuaPluginLoader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn loader_default_empty() {
    let l = LuaPluginLoader::default();
    assert_eq!(l.count(), 0);
    assert!(l.ids().is_empty());
}

#[test]
fn loader_load_basic_plugin() {
    let l = LuaPluginLoader::default();
    let src = "return { name='a', version='1', description='d' }";
    let p = l.load_source(src, &PathBuf::from("a")).unwrap();
    assert_eq!(p.entry.name, "a");
    assert_eq!(p.entry.version, "1");
    assert_eq!(p.entry.description, "d");
    assert!(!p.entry.has_on_load);
    assert!(!p.entry.has_on_unload);
    assert_eq!(p.id, "a@1");
}

#[test]
fn loader_missing_version() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return { name='x' }", &PathBuf::from("p"));
    match r {
        Err(LuaLoadError::MissingField { field, .. }) => assert_eq!(field, "version"),
        other => panic!("expected MissingField version, got {other:?}"),
    }
}

#[test]
fn loader_missing_name() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return { version='1' }", &PathBuf::from("p"));
    match r {
        Err(LuaLoadError::MissingField { field, .. }) => assert_eq!(field, "name"),
        other => panic!("expected MissingField name, got {other:?}"),
    }
}

#[test]
fn loader_wrong_type_field() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return { name=123, version='1' }", &PathBuf::from("p"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
}

#[test]
fn loader_not_a_table_variants() {
    let l = LuaPluginLoader::default();
    for src in ["return 1", "return 'x'", "return nil", "return true", "return function() end"] {
        let r = l.load_source(src, &PathBuf::from("p"));
        assert!(matches!(r, Err(LuaLoadError::NotATable { .. })), "src: {src} => {r:?}");
    }
}

#[test]
fn loader_syntax_error_returns_lua() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("@@@", &PathBuf::from("p"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
}

#[test]
fn loader_duplicate_rejected() {
    let l = LuaPluginLoader::default();
    let src = "return { name='d', version='1' }";
    l.load_source(src, &PathBuf::from("1")).unwrap();
    let r = l.load_source(src, &PathBuf::from("2"));
    assert!(matches!(r, Err(LuaLoadError::AlreadyLoaded { .. })));
}

#[test]
fn loader_on_load_called_once() {
    let l = LuaPluginLoader::default();
    let src = r"
        cnt = 0
        return { name='o', version='1', on_load=function() cnt=cnt+1 end }
    ";
    let p = l.load_source(src, &PathBuf::from("o")).unwrap();
    let c: i64 = p.lua().globals().get("cnt").unwrap();
    assert_eq!(c, 1);
    assert!(p.entry.has_on_load);
}

#[test]
fn loader_on_load_error_propagates_and_does_not_register() {
    let l = LuaPluginLoader::default();
    let src = "return { name='bad', version='1', on_load=function() error('nope') end }";
    let r = l.load_source(src, &PathBuf::from("b"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
    assert_eq!(l.count(), 0);
    // Slot freed: same id can be loaded again with a healthy script.
    let ok = "return { name='bad', version='1' }";
    l.load_source(ok, &PathBuf::from("b2")).unwrap();
    assert_eq!(l.count(), 1);
}

#[test]
fn loader_get_and_count_and_ids_sorted() {
    let l = LuaPluginLoader::default();
    l.load_source("return { name='b', version='1' }", &PathBuf::from("b")).unwrap();
    l.load_source("return { name='a', version='1' }", &PathBuf::from("a")).unwrap();
    assert_eq!(l.count(), 2);
    assert_eq!(l.ids(), vec!["a@1", "b@1"]);
    assert!(l.get("a@1").is_some());
    assert!(l.get("missing").is_none());
}

#[test]
fn loader_unload_unknown() {
    let l = LuaPluginLoader::default();
    let r = l.unload("nope@0");
    match r {
        Err(LuaLoadError::NotFound { id }) => assert_eq!(id, "nope@0"),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn loader_unload_existing() {
    let l = LuaPluginLoader::default();
    l.load_source("return { name='u', version='1' }", &PathBuf::from("u")).unwrap();
    l.unload("u@1").unwrap();
    assert_eq!(l.count(), 0);
}

#[test]
fn loader_load_file_io_error() {
    let l = LuaPluginLoader::default();
    let r = l.load_file("Z:/definitely/does/not/exist/file.lua");
    assert!(matches!(r, Err(LuaLoadError::Io { .. })));
}

#[test]
fn loader_apis_installed_into_vm() {
    let apis = Arc::new(LuaApiProvider::new());
    let t = ApiTable::new("ping").with_function(ApiFunction::new("pong", "", |_, _| {
        Ok(mlua::Value::Integer(7))
    }));
    apis.register_table(t).unwrap();
    let l = LuaPluginLoader::new(StatePool::default(), apis);
    let src = r"
        return {
            name='p', version='1',
            on_load=function() result = rustre.ping.pong() end,
        }
    ";
    let p = l.load_source(src, &PathBuf::from("p")).unwrap();
    let r: i64 = p.lua().globals().get("result").unwrap();
    assert_eq!(r, 7);
}

#[test]
fn loader_apis_accessor_returns_same() {
    let apis = Arc::new(LuaApiProvider::new());
    let l = LuaPluginLoader::new(StatePool::default(), apis.clone());
    let got = l.apis();
    assert!(Arc::ptr_eq(&got, &apis));
}

#[test]
fn loader_fuzz_random_scripts_no_panic() {
    let l = LuaPluginLoader::default();
    let mut g = make_lcg();
    let chars: &[u8] = b"abc123 ={}',()\nreturn nameversio";
    for i in 0..50 {
        let len = usize::try_from(g() % 60).unwrap_or(usize::MAX);
        let bytes: Vec<u8> = (0..len).map(|_| chars[(g() as usize) % chars.len()]).collect();
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = l.load_source(&s, &PathBuf::from(format!("f{i}")));
    }
}

#[test]
fn loader_threaded_loads() {
    let l = Arc::new(LuaPluginLoader::new(
        // Plugins retain their VM for their entire lifetime, so the pool must
        // be at least as large as the total number of concurrently-loaded plugins.
        StatePool { max_states: 128 },
        Arc::new(LuaApiProvider::new()),
    ));
    let mut handles = Vec::new();
    for t in 0..4 {
        let lc = l.clone();
        handles.push(thread::spawn(move || {
            for i in 0..20 {
                let src = format!("return {{ name='t{t}_{i}', version='1' }}");
                let _ = lc.load_source(&src, &PathBuf::from(format!("t{t}_{i}")));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // 4 * 20 = 80 unique ids expected.
    assert_eq!(l.count(), 80);
}

#[test]
fn loader_description_optional() {
    let l = LuaPluginLoader::default();
    let p = l
        .load_source("return { name='n', version='1' }", &PathBuf::from("n"))
        .unwrap();
    assert_eq!(p.entry.description, "");
}

#[test]
fn loader_has_on_unload_flag() {
    let l = LuaPluginLoader::default();
    let src = "return { name='u', version='1', on_unload=function() end }";
    let p = l.load_source(src, &PathBuf::from("u")).unwrap();
    assert!(p.entry.has_on_unload);
}

#[test]
fn loader_plugin_lua_accessor() {
    let l = LuaPluginLoader::default();
    let p = l
        .load_source("return { name='q', version='1' }", &PathBuf::from("q"))
        .unwrap();
    let _lua: &mlua::Lua = p.lua();
    let _st = p.state();
}

#[test]
fn loader_debug_format() {
    let l = LuaPluginLoader::default();
    let d = format!("{l:?}");
    assert!(d.contains("LuaPluginLoader"));
}

#[test]
fn plugin_entry_clone_eq_fields() {
    let l = LuaPluginLoader::default();
    let p = l
        .load_source("return { name='c', version='2', description='x' }", &PathBuf::from("c"))
        .unwrap();
    let e = p.entry.clone();
    assert_eq!(e.name, "c");
    assert_eq!(e.version, "2");
    assert_eq!(e.description, "x");
}

#[test]
fn loader_after_pool_exhausted_propagates() {
    // max_states = 1: first load takes the only VM; second must fail with a
    // Lua-wrapped exhaustion error because the pool can't lend another VM.
    let l = LuaPluginLoader::new(StatePool { max_states: 1 }, Arc::new(LuaApiProvider::new()));
    l.load_source("return { name='a', version='1' }", &PathBuf::from("a")).unwrap();
    let r = l.load_source("return { name='b', version='1' }", &PathBuf::from("b"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
}

#[test]
fn error_display_strings_nonempty() {
    let e = LuaLoadError::NotFound { id: "z".into() };
    assert!(!format!("{e}").is_empty());
    let e2 = LuaLoadError::AlreadyLoaded { id: "z".into() };
    assert!(format!("{e2}").contains("already"));
    let e3 = StateError::Exhausted(3);
    assert!(format!("{e3}").contains('3'));
    let e4 = ApiError::Duplicate("x".into());
    assert!(format!("{e4}").contains('x'));
}
