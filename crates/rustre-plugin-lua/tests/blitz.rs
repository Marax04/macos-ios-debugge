// Exhaustive integration tests for rustre-plugin-lua.

use rustre_plugin_lua::{
    ApiFunction, ApiTable, LuaApiProvider, LuaPluginLoader, LuaState, LuaStateManager, StatePool,
};
use rustre_plugin_lua::lua_api_provider::ApiError;
use rustre_plugin_lua::lua_plugin_loader::LuaLoadError;
use rustre_plugin_lua::lua_state_manager::StateError;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::thread;

// â"€â"€â"€ LuaState â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn state_id_round_trip() {
    let s = LuaState::new(7);
    assert_eq!(s.id(), 7);
}

#[test]
fn state_id_max() {
    let s = LuaState::new(u64::MAX);
    assert_eq!(s.id(), u64::MAX);
}

#[test]
fn state_id_zero() {
    let s = LuaState::new(0);
    assert_eq!(s.id(), 0);
}

#[test]
fn state_raw_returns_usable_lua() {
    let s = LuaState::new(0);
    let v: i64 = s.raw().load("return 5").eval().unwrap();
    assert_eq!(v, 5);
}

#[test]
fn eval_integer_value() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return 99").unwrap(), "99");
}

#[test]
fn eval_negative_integer() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return -42").unwrap(), "-42");
}

#[test]
fn eval_float_value() {
    let s = LuaState::new(0);
    let out = s.eval_string("return 1.5").unwrap();
    assert!(out.contains("1.5"), "got {out}");
}

#[test]
fn eval_false() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("return false").unwrap(), "false");
}

#[test]
fn eval_empty_returns_nil() {
    let s = LuaState::new(0);
    assert_eq!(s.eval_string("").unwrap(), "nil");
}

#[test]
fn eval_table_is_typename() {
    let s = LuaState::new(0);
    let out = s.eval_string("return {}").unwrap();
    assert!(out.starts_with('<') && out.contains("table"), "got {out}");
}

#[test]
fn eval_function_is_typename() {
    let s = LuaState::new(0);
    let out = s.eval_string("return function() end").unwrap();
    assert!(out.starts_with('<') && out.contains("function"), "got {out}");
}

#[test]
fn exec_then_eval_state_persists() {
    let s = LuaState::new(0);
    s.exec_string("g = 'persisted'").unwrap();
    assert_eq!(s.eval_string("return g").unwrap(), "persisted");
}

#[test]
fn eval_runtime_error_propagates() {
    let s = LuaState::new(0);
    let r = s.eval_string("error('boom')");
    assert!(r.is_err());
    assert!(matches!(r.unwrap_err(), StateError::Lua(_)));
}

#[test]
fn exec_runtime_error_propagates() {
    let s = LuaState::new(0);
    assert!(s.exec_string("error('boom')").is_err());
}

#[test]
fn state_debug_contains_id() {
    let s = LuaState::new(123);
    let d = format!("{s:?}");
    assert!(d.contains("123"), "debug missing id: {d}");
}

#[test]
fn state_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<LuaState>();
}

// â"€â"€â"€ StatePool â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn statepool_default_is_8() {
    assert_eq!(StatePool::default().max_states, 8);
}

#[test]
fn statepool_copy_clone() {
    let a = StatePool { max_states: 3 };
    let b = a;
    let c = a;
    assert_eq!(b.max_states, 3);
    assert_eq!(c.max_states, 3);
}

// â"€â"€â"€ LuaStateManager â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn mgr_acquire_assigns_unique_ids() {
    let mgr = LuaStateManager::new(StatePool { max_states: 4 });
    let a = mgr.acquire().unwrap();
    let b = mgr.acquire().unwrap();
    assert_ne!(a.id(), b.id());
}

#[test]
fn mgr_acquire_ids_start_at_zero() {
    let mgr = LuaStateManager::new(StatePool { max_states: 4 });
    let a = mgr.acquire().unwrap();
    assert_eq!(a.id(), 0);
}

#[test]
fn mgr_exhausts_at_max() {
    let mgr = LuaStateManager::new(StatePool { max_states: 2 });
    let _a = mgr.acquire().unwrap();
    let _b = mgr.acquire().unwrap();
    let r = mgr.acquire();
    assert!(matches!(r, Err(StateError::Exhausted(2))));
}

#[test]
fn mgr_zero_max_always_exhausts() {
    let mgr = LuaStateManager::new(StatePool { max_states: 0 });
    assert!(matches!(mgr.acquire(), Err(StateError::Exhausted(0))));
}

#[test]
fn mgr_release_then_reacquire_reuses_id() {
    let mgr = LuaStateManager::new(StatePool { max_states: 1 });
    let a = mgr.acquire().unwrap();
    let id_a = a.id();
    mgr.release(a);
    let b = mgr.acquire().unwrap();
    assert_eq!(b.id(), id_a, "recycled state should have same id");
}

#[test]
fn mgr_release_decrements_issued() {
    let mgr = LuaStateManager::new(StatePool::default());
    let a = mgr.acquire().unwrap();
    let b = mgr.acquire().unwrap();
    assert_eq!(mgr.issued(), 2);
    mgr.release(a);
    assert_eq!(mgr.issued(), 1);
    mgr.release(b);
    assert_eq!(mgr.issued(), 0);
}

#[test]
fn mgr_release_saturates_at_zero() {
    let mgr = LuaStateManager::new(StatePool::default());
    let a = mgr.acquire().unwrap();
    mgr.release(a.clone()); // strong_count > 1 here -> won't pool
    mgr.release(a); // double-release shouldn't underflow
    assert_eq!(mgr.issued(), 0);
}

#[test]
fn mgr_release_with_outstanding_refs_does_not_pool() {
    let mgr = LuaStateManager::new(StatePool::default());
    let a = mgr.acquire().unwrap();
    let _extra = a.clone();
    mgr.release(a);
    assert_eq!(mgr.idle(), 0, "should not pool while extra ref outstanding");
}

#[test]
fn mgr_recycle_increments_issued_above_max_bug() {
    // BUG candidate: acquire() pops from available without checking the issued cap.
    // After releasing 2 states, max=1, we should not be able to issue 2.
    let mgr = LuaStateManager::new(StatePool { max_states: 1 });
    let a = mgr.acquire().unwrap();
    mgr.release(a);
    let _x = mgr.acquire().unwrap();
    // pool is now empty, issued=1. next acquire should fail (cap=1).
    let r = mgr.acquire();
    assert!(matches!(r, Err(StateError::Exhausted(1))), "got {r:?}");
}

#[test]
fn mgr_idle_capped_by_max() {
    // Pool more than max_states (forces multiple release calls when max smaller).
    let mgr = LuaStateManager::new(StatePool { max_states: 2 });
    let a = mgr.acquire().unwrap();
    let b = mgr.acquire().unwrap();
    mgr.release(a);
    mgr.release(b);
    assert!(mgr.idle() <= 2);
}

#[test]
fn mgr_debug_format() {
    let mgr = LuaStateManager::new(StatePool { max_states: 5 });
    let d = format!("{mgr:?}");
    assert!(d.contains("LuaStateManager"));
    assert!(d.contains('5'));
}

#[test]
fn mgr_multithreaded_acquire() {
    let mgr = Arc::new(LuaStateManager::new(StatePool { max_states: 32 }));
    let mut handles = vec![];
    for _ in 0..8 {
        let m = mgr.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                let s = m.acquire().unwrap();
                let _: i64 = s.raw().load("return 1").eval().unwrap();
                m.release(s);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(mgr.issued(), 0);
}

// â"€â"€â"€ ApiTable / ApiFunction / LuaApiProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn apitable_new_empty() {
    let t = ApiTable::new("foo");
    assert_eq!(t.name, "foo");
    assert!(t.functions.is_empty());
}

#[test]
fn apitable_with_function_appends() {
    let t = ApiTable::new("ns")
        .with_function(ApiFunction::new("a", "", |_, _| Ok(mlua::Value::Nil)))
        .with_function(ApiFunction::new("b", "", |_, _| Ok(mlua::Value::Nil)));
    assert_eq!(t.functions.len(), 2);
    assert_eq!(t.functions[0].name, "a");
    assert_eq!(t.functions[1].name, "b");
}

#[test]
fn apifunction_debug_does_not_panic() {
    let f = ApiFunction::new("nm", "doc", |_, _| Ok(mlua::Value::Nil));
    let d = format!("{f:?}");
    assert!(d.contains("nm"));
    assert!(d.contains("doc"));
}

#[test]
fn provider_new_is_empty() {
    let p = LuaApiProvider::new();
    assert_eq!(p.table_count(), 0);
    assert!(p.table_names().is_empty());
}

#[test]
fn provider_register_increments() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("x")).unwrap();
    assert_eq!(p.table_count(), 1);
}

#[test]
fn provider_duplicate_preserves_first() {
    let p = LuaApiProvider::new();
    p.register_table(
        ApiTable::new("dup").with_function(ApiFunction::new("f1", "", |_, _| {
            Ok(mlua::Value::Integer(1))
        })),
    )
    .unwrap();
    let err = p.register_table(ApiTable::new("dup")).unwrap_err();
    assert!(matches!(err, ApiError::Duplicate(s) if s == "dup"));
    // Original table still installed: should still have f1.
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let v: i64 = lua.load("return rustre.dup.f1()").eval().unwrap();
    assert_eq!(v, 1);
}

#[test]
fn provider_install_no_tables_creates_rustre_global() {
    let p = LuaApiProvider::new();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let is_table: bool = lua.load("return type(rustre) == 'table'").eval().unwrap();
    assert!(is_table);
}

#[test]
fn provider_install_multiple_namespaces() {
    let p = LuaApiProvider::new();
    p.register_table(
        ApiTable::new("a").with_function(ApiFunction::new("v", "", |_, _| {
            Ok(mlua::Value::Integer(1))
        })),
    )
    .unwrap();
    p.register_table(
        ApiTable::new("b").with_function(ApiFunction::new("v", "", |_, _| {
            Ok(mlua::Value::Integer(2))
        })),
    )
    .unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let a: i64 = lua.load("return rustre.a.v()").eval().unwrap();
    let b: i64 = lua.load("return rustre.b.v()").eval().unwrap();
    assert_eq!(a, 1);
    assert_eq!(b, 2);
}

#[test]
fn provider_install_passes_variadic_args() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("ns").with_function(ApiFunction::new(
        "sum",
        "",
        |_, args| {
            let mut total: i64 = 0;
            for v in args {
                if let mlua::Value::Integer(i) = v {
                    total += i;
                }
            }
            Ok(mlua::Value::Integer(total))
        },
    )))
    .unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let v: i64 = lua.load("return rustre.ns.sum(1,2,3,4)").eval().unwrap();
    assert_eq!(v, 10);
}

#[test]
fn provider_callback_can_be_invoked_concurrently() {
    let counter = Arc::new(AtomicI64::new(0));
    let c = counter.clone();
    let p = Arc::new(LuaApiProvider::new());
    p.register_table(ApiTable::new("ns").with_function(ApiFunction::new(
        "inc",
        "",
        move |_, _| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(mlua::Value::Nil)
        },
    )))
    .unwrap();
    let mut handles = vec![];
    for _ in 0..4 {
        let p2 = p.clone();
        handles.push(thread::spawn(move || {
            let lua = mlua::Lua::new();
            p2.install(&lua).unwrap();
            for _ in 0..10 {
                lua.load("rustre.ns.inc()").exec().unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(counter.load(Ordering::SeqCst), 40);
}

#[test]
fn provider_table_names_sorted() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("zeta")).unwrap();
    p.register_table(ApiTable::new("alpha")).unwrap();
    p.register_table(ApiTable::new("mu")).unwrap();
    assert_eq!(p.table_names(), vec!["alpha", "mu", "zeta"]);
}

#[test]
fn provider_debug_shows_count() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("a")).unwrap();
    let d = format!("{p:?}");
    assert!(d.contains("LuaApiProvider"));
}

#[test]
fn provider_callback_error_propagates_to_lua() {
    let p = LuaApiProvider::new();
    p.register_table(ApiTable::new("ns").with_function(ApiFunction::new(
        "boom",
        "",
        |_, _| Err(mlua::Error::external("custom failure")),
    )))
    .unwrap();
    let lua = mlua::Lua::new();
    p.install(&lua).unwrap();
    let r: mlua::Result<mlua::Value> = lua.load("return rustre.ns.boom()").eval();
    assert!(r.is_err());
}

#[test]
fn provider_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<LuaApiProvider>();
}

// â"€â"€â"€ LuaPluginLoader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[test]
fn loader_default_is_empty() {
    let l = LuaPluginLoader::default();
    assert_eq!(l.count(), 0);
    assert!(l.ids().is_empty());
}

#[test]
fn loader_apis_returns_shared() {
    let apis = Arc::new(LuaApiProvider::new());
    let l = LuaPluginLoader::new(StatePool::default(), apis.clone());
    let got = l.apis();
    assert!(Arc::ptr_eq(&got, &apis));
}

#[test]
fn loader_get_returns_loaded() {
    let l = LuaPluginLoader::default();
    let src = "return { name='g', version='1' }";
    l.load_source(src, &PathBuf::from("g")).unwrap();
    let p = l.get("g@1").unwrap();
    assert_eq!(p.entry.name, "g");
}

#[test]
fn loader_get_missing_returns_none() {
    let l = LuaPluginLoader::default();
    assert!(l.get("no@such").is_none());
}

#[test]
fn loader_ids_sorted() {
    let l = LuaPluginLoader::default();
    l.load_source("return { name='b', version='1' }", &PathBuf::from("a")).unwrap();
    l.load_source("return { name='a', version='1' }", &PathBuf::from("b")).unwrap();
    l.load_source("return { name='c', version='1' }", &PathBuf::from("c")).unwrap();
    assert_eq!(l.ids(), vec!["a@1", "b@1", "c@1"]);
}

#[test]
fn loader_missing_version_field() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return { name = 'x' }", &PathBuf::from("x"));
    match r {
        Err(LuaLoadError::MissingField { field, .. }) => assert_eq!(field, "version"),
        other => panic!("expected MissingField(version), got {other:?}"),
    }
}

#[test]
fn loader_not_a_table_string() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return 'hello'", &PathBuf::from("x"));
    assert!(matches!(r, Err(LuaLoadError::NotATable { .. })));
}

#[test]
fn loader_not_a_table_no_return() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("local x = 1", &PathBuf::from("x"));
    assert!(matches!(r, Err(LuaLoadError::NotATable { .. })));
}

#[test]
fn loader_syntax_error_is_lua_err() {
    let l = LuaPluginLoader::default();
    let r = l.load_source("return {", &PathBuf::from("x"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
}

#[test]
fn loader_on_load_error_propagates() {
    let l = LuaPluginLoader::default();
    let src = r#"
        return {
            name = "bad",
            version = "1",
            on_load = function() error("nope") end,
        }
    "#;
    let r = l.load_source(src, &PathBuf::from("x"));
    assert!(matches!(r, Err(LuaLoadError::Lua { .. })));
    // Failed load must NOT be counted.
    assert_eq!(l.count(), 0);
}

#[test]
fn loader_description_optional_defaults_empty() {
    let l = LuaPluginLoader::default();
    let p = l.load_source(
        "return { name='nd', version='1' }",
        &PathBuf::from("nd"),
    )
    .unwrap();
    assert_eq!(p.entry.description, "");
}

#[test]
fn loader_has_on_unload_true() {
    let l = LuaPluginLoader::default();
    let src = r#"
        return {
            name = "u",
            version = "1",
            on_unload = function() end,
        }
    "#;
    let p = l.load_source(src, &PathBuf::from("u")).unwrap();
    assert!(p.entry.has_on_unload);
    assert!(!p.entry.has_on_load);
}

#[test]
fn loader_unload_removes_plugin() {
    let l = LuaPluginLoader::default();
    let src = "return { name='r', version='1' }";
    l.load_source(src, &PathBuf::from("r")).unwrap();
    assert_eq!(l.count(), 1);
    l.unload("r@1").unwrap();
    assert_eq!(l.count(), 0);
    assert!(l.get("r@1").is_none());
}

#[test]
fn loader_unload_then_reload_ok() {
    let l = LuaPluginLoader::default();
    let src = "return { name='rl', version='1' }";
    l.load_source(src, &PathBuf::from("rl")).unwrap();
    l.unload("rl@1").unwrap();
    l.load_source(src, &PathBuf::from("rl")).unwrap();
    assert_eq!(l.count(), 1);
}

#[test]
fn loader_load_file_missing_io_error() {
    let l = LuaPluginLoader::default();
    let r = l.load_file("Z:/this/does/not/exist.lua");
    assert!(matches!(r, Err(LuaLoadError::Io { .. })));
}

#[test]
fn loader_load_file_real_file() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rustre_plugin_lua_test_{}.lua", std::process::id()));
    std::fs::write(&path, "return { name='disk', version='9' }").unwrap();
    let l = LuaPluginLoader::default();
    let p = l.load_file(&path).unwrap();
    assert_eq!(p.entry.name, "disk");
    assert_eq!(p.id, "disk@9");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn loader_plugin_lua_works() {
    let l = LuaPluginLoader::default();
    let src = "return { name='q', version='1' }";
    let p = l.load_source(src, &PathBuf::from("q")).unwrap();
    let v: i64 = p.lua().load("return 7").eval().unwrap();
    assert_eq!(v, 7);
}

#[test]
fn loader_plugin_state_accessor() {
    let l = LuaPluginLoader::default();
    let src = "return { name='s', version='1' }";
    let p = l.load_source(src, &PathBuf::from("s")).unwrap();
    let st = p.state();
    let _ = st.id();
}

#[test]
fn loader_apis_installed_in_vm() {
    let apis = Arc::new(LuaApiProvider::new());
    apis.register_table(ApiTable::new("host").with_function(ApiFunction::new(
        "ans",
        "",
        |_, _| Ok(mlua::Value::Integer(42)),
    )))
    .unwrap();
    let l = LuaPluginLoader::new(StatePool::default(), apis);
    let src = r#"
        return {
            name = "uses",
            version = "1",
            on_load = function()
                check_value = rustre.host.ans()
            end,
        }
    "#;
    let p = l.load_source(src, &PathBuf::from("uses")).unwrap();
    let v: i64 = p.lua().globals().get("check_value").unwrap();
    assert_eq!(v, 42);
}

#[test]
fn loader_duplicate_id_after_successful_load() {
    let l = LuaPluginLoader::default();
    let src = "return { name='dd', version='1' }";
    l.load_source(src, &PathBuf::from("a")).unwrap();
    let r = l.load_source(src, &PathBuf::from("b"));
    match r {
        Err(LuaLoadError::AlreadyLoaded { id }) => assert_eq!(id, "dd@1"),
        other => panic!("expected AlreadyLoaded, got {other:?}"),
    }
    assert_eq!(l.count(), 1);
}

#[test]
fn loader_debug_format() {
    let l = LuaPluginLoader::default();
    let d = format!("{l:?}");
    assert!(d.contains("LuaPluginLoader"));
}

#[test]
fn loader_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<LuaPluginLoader>();
}

#[test]
fn loader_unload_unknown_is_notfound() {
    let l = LuaPluginLoader::default();
    match l.unload("ghost@0") {
        Err(LuaLoadError::NotFound { id }) => assert_eq!(id, "ghost@0"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// Pool-leak scenario: after AlreadyLoaded the second VM acquisition is wasted.
// Verifies issued counter behaviour vs cap.
#[test]
fn loader_duplicate_load_does_not_exhaust_pool_silently() {
    let pool = StatePool { max_states: 2 };
    let l = LuaPluginLoader::new(pool, Arc::new(LuaApiProvider::new()));
    let src = "return { name='leak', version='1' }";
    l.load_source(src, &PathBuf::from("a")).unwrap();
    // second attempt should fail with AlreadyLoaded —" but it acquires a VM first.
    let r = l.load_source(src, &PathBuf::from("b"));
    assert!(matches!(r, Err(LuaLoadError::AlreadyLoaded { .. })));
    // Third attempt with a different name: pool should still have a slot.
    let src2 = "return { name='other', version='1' }";
    let r2 = l.load_source(src2, &PathBuf::from("c"));
    assert!(r2.is_ok(), "pool prematurely exhausted: {r2:?}");
}
