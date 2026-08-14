// Deep adversarial integration tests for rustre-plugin-native.

use std::collections::HashSet;
use std::ffi::CString;
use std::sync::Arc;
use std::thread;

use rustre_plugin_native::native_abi_bridge::{
    NativeAbiBridge, PLUGIN_REGISTER_SYMBOL, PluginVTable, RUSTRE_NATIVE_ABI_MAGIC,
    RUSTRE_NATIVE_ABI_VERSION,
};
use rustre_plugin_native::{
    CallConv, ExportedSymbol, FunctionPtr, NativePluginLoader, NativeSymbolResolver, SymbolKind,
};
use rustre_plugin_native::native_plugin_loader::NativeLoadError;

// ── seeded LCG ───────────────────────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── CallConv ─────────────────────────────────────────────────────────────────

#[test]
fn callconv_as_str_all_variants() {
    assert_eq!(CallConv::C.as_str(), "C");
    assert_eq!(CallConv::System.as_str(), "system");
    assert_eq!(CallConv::Rust.as_str(), "Rust");
}

#[test]
fn callconv_copy_eq() {
    let a = CallConv::System;
    let b = a; // copy
    assert_eq!(a, b);
    assert_ne!(CallConv::C, CallConv::Rust);
}

#[test]
fn callconv_debug_nonempty() {
    for cc in [CallConv::C, CallConv::System, CallConv::Rust] {
        assert!(!format!("{cc:?}").is_empty());
    }
}

// ── FunctionPtr ──────────────────────────────────────────────────────────────

#[test]
fn function_ptr_null_unresolved() {
    let p = FunctionPtr::null();
    assert_eq!(p.addr, 0);
    assert!(!p.is_resolved());
    assert_eq!(p.conv, CallConv::C);
}

#[test]
fn function_ptr_from_raw_boundary_addrs() {
    let cases = [0usize, 1, 2, usize::MAX - 1, usize::MAX];
    for (i, &a) in cases.iter().enumerate() {
        let cc = match i % 3 {
            0 => CallConv::C,
            1 => CallConv::System,
            _ => CallConv::Rust,
        };
        let p = FunctionPtr::from_raw(a, cc);
        assert_eq!(p.addr, a);
        assert_eq!(p.conv, cc);
        assert_eq!(p.is_resolved(), a != 0);
    }
}

#[test]
fn function_ptr_fuzz_roundtrip() {
    let mut g = lcg();
    for _ in 0..200 {
        let a = usize::try_from(g()).unwrap_or(usize::MAX);
        let cc = match g() % 3 {
            0 => CallConv::C,
            1 => CallConv::System,
            _ => CallConv::Rust,
        };
        let p = FunctionPtr::from_raw(a, cc);
        assert_eq!(p.addr, a);
        assert_eq!(p.conv, cc);
        assert_eq!(p.is_resolved(), a != 0);
        let q = p; // Copy
        assert_eq!(q.addr, p.addr);
    }
}

// ── NativeAbiBridge: CString / cstr ──────────────────────────────────────────

#[test]
fn into_cstring_basic_strings() {
    for s in ["", "x", "hello", "with space", "utf8 αβγ", "long".repeat(50).as_str()] {
        let cs = NativeAbiBridge::into_cstring(s).expect("no nul");
        unsafe {
            let back = NativeAbiBridge::read_cstr(cs.as_ptr()).unwrap();
            assert_eq!(back, s);
        }
    }
}

#[test]
fn into_cstring_interior_nul_rejected() {
    for bad in ["\0", "a\0", "\0b", "mid\0dle", "a\0b\0c"] {
        assert!(NativeAbiBridge::into_cstring(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn read_cstr_null_returns_none() {
    unsafe {
        assert!(NativeAbiBridge::read_cstr(std::ptr::null()).is_none());
    }
}

#[test]
fn cstring_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..60 {
        let n = usize::try_from(g() % 32).unwrap();
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            // ASCII printable, no NUL
            let c = ((g() % 95) as u8) + 32;
            s.push(c as char);
        }
        let cs = NativeAbiBridge::into_cstring(&s).unwrap();
        unsafe {
            let back = NativeAbiBridge::read_cstr(cs.as_ptr()).unwrap();
            assert_eq!(back, s);
        }
    }
}

// ── validate_vtable ──────────────────────────────────────────────────────────

fn make_vtable(name: &CString, ver: &CString, magic: u32, abi: u32) -> PluginVTable {
    PluginVTable {
        magic,
        abi_version: abi,
        name: name.as_ptr(),
        version: ver.as_ptr(),
        free_string: None,
    }
}

#[test]
fn validate_vtable_ok() {
    let n = CString::new("plg").unwrap();
    let v = CString::new("1.0.0").unwrap();
    let vt = make_vtable(&n, &v, RUSTRE_NATIVE_ABI_MAGIC, RUSTRE_NATIVE_ABI_VERSION);
    NativeAbiBridge::validate_vtable(&vt).unwrap();
}

#[test]
fn validate_vtable_bad_magic_values() {
    let n = CString::new("plg").unwrap();
    let v = CString::new("1").unwrap();
    for m in [0u32, 1, 0xFFFF_FFFF, RUSTRE_NATIVE_ABI_MAGIC.wrapping_add(1)] {
        let vt = make_vtable(&n, &v, m, RUSTRE_NATIVE_ABI_VERSION);
        let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
        assert!(err.contains("magic"), "{err}");
    }
}

#[test]
fn validate_vtable_bad_abi_versions() {
    let n = CString::new("plg").unwrap();
    let v = CString::new("1").unwrap();
    for a in [0u32, RUSTRE_NATIVE_ABI_VERSION + 1, u32::MAX] {
        if a == RUSTRE_NATIVE_ABI_VERSION { continue; }
        let vt = make_vtable(&n, &v, RUSTRE_NATIVE_ABI_MAGIC, a);
        let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
        assert!(err.contains("ABI") || err.contains("version"), "{err}");
    }
}

#[test]
fn validate_vtable_null_name() {
    let v = CString::new("1").unwrap();
    let vt = PluginVTable {
        magic: RUSTRE_NATIVE_ABI_MAGIC,
        abi_version: RUSTRE_NATIVE_ABI_VERSION,
        name: std::ptr::null(),
        version: v.as_ptr(),
        free_string: None,
    };
    let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
    assert!(err.contains("name"));
}

#[test]
fn validate_vtable_null_version() {
    let n = CString::new("plg").unwrap();
    let vt = PluginVTable {
        magic: RUSTRE_NATIVE_ABI_MAGIC,
        abi_version: RUSTRE_NATIVE_ABI_VERSION,
        name: n.as_ptr(),
        version: std::ptr::null(),
        free_string: None,
    };
    let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
    assert!(err.contains("version"));
}

#[test]
fn validate_vtable_fuzz_only_canonical_passes() {
    let name = CString::new("plg").unwrap();
    let ver = CString::new("1").unwrap();
    let mut gen_rand = lcg();
    for _ in 0..80 {
        let magic = u32::try_from(gen_rand() & 0xFFFF_FFFF).unwrap();
        let abi = u32::try_from(gen_rand() & 0xFFFF_FFFF).unwrap();
        let vt = make_vtable(&name, &ver, magic, abi);
        let res = NativeAbiBridge::validate_vtable(&vt);
        if magic == RUSTRE_NATIVE_ABI_MAGIC && abi == RUSTRE_NATIVE_ABI_VERSION {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
        }
    }
}

#[test]
fn abi_constants() {
    assert_eq!(RUSTRE_NATIVE_ABI_MAGIC, 0x5253_5245);
    assert_eq!(RUSTRE_NATIVE_ABI_VERSION, 1);
    assert_eq!(PLUGIN_REGISTER_SYMBOL, b"rustre_plugin_register");
}

#[test]
fn plugin_vtable_send_sync_threaded() {
    // PluginVTable is Send+Sync per unsafe impl; verify Arc usage compiles+runs.
    let n = CString::new("p").unwrap();
    let v = CString::new("1").unwrap();
    let vt = Arc::new(make_vtable(&n, &v, RUSTRE_NATIVE_ABI_MAGIC, RUSTRE_NATIVE_ABI_VERSION));
    let mut hs = Vec::new();
    for _ in 0..4 {
        let vt = Arc::clone(&vt);
        hs.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(NativeAbiBridge::validate_vtable(&vt).is_ok());
            }
        }));
    }
    // Keep the CStrings alive until threads finish.
    for h in hs { h.join().unwrap(); }
    drop(n); drop(v);
}

// ── SymbolKind ───────────────────────────────────────────────────────────────

#[test]
fn symbol_kind_strings() {
    assert_eq!(SymbolKind::Function.as_str(), "function");
    assert_eq!(SymbolKind::Data.as_str(), "data");
    assert_eq!(SymbolKind::Weak.as_str(), "weak");
}

#[test]
fn symbol_kind_hash_eq_consistency() {
    let pairs = [
        (SymbolKind::Function, SymbolKind::Function, true),
        (SymbolKind::Data, SymbolKind::Data, true),
        (SymbolKind::Weak, SymbolKind::Weak, true),
        (SymbolKind::Function, SymbolKind::Data, false),
        (SymbolKind::Function, SymbolKind::Weak, false),
        (SymbolKind::Data, SymbolKind::Weak, false),
    ];
    let mut set: HashSet<SymbolKind> = HashSet::new();
    set.insert(SymbolKind::Function);
    set.insert(SymbolKind::Data);
    set.insert(SymbolKind::Weak);
    set.insert(SymbolKind::Function); // duplicate
    assert_eq!(set.len(), 3);
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq);
    }
}

// ── ExportedSymbol ───────────────────────────────────────────────────────────

#[test]
fn exported_symbol_resolved_and_unresolved() {
    let s = ExportedSymbol {
        name: "f".into(),
        kind: SymbolKind::Function,
        ptr: FunctionPtr::from_raw(1, CallConv::C),
    };
    assert!(s.is_resolved());

    let s2 = ExportedSymbol {
        name: "g".into(),
        kind: SymbolKind::Weak,
        ptr: FunctionPtr::null(),
    };
    assert!(!s2.is_resolved());
}

#[test]
fn exported_symbol_clone_preserves_fields() {
    let s = ExportedSymbol {
        name: "abc".into(),
        kind: SymbolKind::Data,
        ptr: FunctionPtr::from_raw(0xC0DE, CallConv::System),
    };
    let c = s.clone();
    assert_eq!(c.name, s.name);
    assert_eq!(c.kind, s.kind);
    assert_eq!(c.ptr.addr, s.ptr.addr);
    assert_eq!(c.ptr.conv, s.ptr.conv);
}

// ── NativeSymbolResolver ─────────────────────────────────────────────────────

#[test]
fn resolver_default_state() {
    let r = NativeSymbolResolver::new();
    assert_eq!(r.cache_len(), 0);
    assert!(r.cached("x").is_none());
    assert_eq!(r.iter().count(), 0);
}

#[test]
fn resolver_with_default_conv() {
    let r = NativeSymbolResolver::new().with_default_conv(CallConv::System);
    // Debug includes default_conv
    let dbg = format!("{r:?}");
    assert!(dbg.contains("System"));
}

#[test]
fn resolver_clear_removes_all() {
    let mut r = NativeSymbolResolver::new();
    for i in 0..10 {
        // populate via the only public mutation: ExportedSymbol cache is private,
        // so use resolve_weak against the host binary (which lacks the symbol).
        // That fills the cache with null entries.
        let lib = unsafe { libloading::Library::new(current_exe_path()).unwrap() };
        let name = format!("__rustre_missing_sym_{i}");
        let _ = r.resolve_weak(&lib, &name);
    }
    assert!(r.cache_len() >= 1);
    r.clear();
    assert_eq!(r.cache_len(), 0);
    assert_eq!(r.iter().count(), 0);
}

fn current_exe_path() -> std::path::PathBuf {
    // Use the test binary itself as a "library" — libloading can open the
    // running executable on all major platforms.
    std::env::current_exe().unwrap()
}

#[test]
fn resolver_weak_missing_symbol_is_unresolved_and_cached() {
    let lib = unsafe { libloading::Library::new(current_exe_path()).unwrap() };
    let mut r = NativeSymbolResolver::new();
    let s = r.resolve_weak(&lib, "__rustre_definitely_not_present_sym_A");
    assert!(!s.is_resolved());
    assert_eq!(s.kind, SymbolKind::Weak);
    assert_eq!(r.cache_len(), 1);

    // Second call hits cache and returns identical record.
    let s2 = r.resolve_weak(&lib, "__rustre_definitely_not_present_sym_A");
    assert_eq!(s.name, s2.name);
    assert_eq!(s.ptr.addr, s2.ptr.addr);
    assert_eq!(r.cache_len(), 1);
}

#[test]
fn resolver_function_missing_errors() {
    let lib = unsafe { libloading::Library::new(current_exe_path()).unwrap() };
    let mut r = NativeSymbolResolver::new();
    let res = r.resolve_function(&lib, "__rustre_missing_required_sym_B");
    assert!(res.is_err());
    // failed resolve_function should NOT insert into cache
    assert_eq!(r.cache_len(), 0);
}

#[test]
fn resolver_cached_lookup_consistency() {
    let lib = unsafe { libloading::Library::new(current_exe_path()).unwrap() };
    let mut r = NativeSymbolResolver::new();
    let mut g = lcg();
    let mut names = Vec::new();
    for _ in 0..40 {
        let name = format!("__missing_{:x}", g());
        names.push(name);
    }
    for n in &names {
        let _ = r.resolve_weak(&lib, n);
    }
    assert_eq!(r.cache_len(), names.len());
    for n in &names {
        let c = r.cached(n).expect("cached");
        assert_eq!(c.name, *n);
        assert_eq!(c.kind, SymbolKind::Weak);
        assert!(!c.is_resolved());
    }
    assert_eq!(r.iter().count(), names.len());
}

#[test]
fn resolver_debug_format() {
    let r = NativeSymbolResolver::new();
    let s = format!("{r:?}");
    assert!(s.contains("NativeSymbolResolver"));
    assert!(s.contains("cached"));
}

// ── NativePluginLoader ───────────────────────────────────────────────────────

#[test]
fn loader_new_empty() {
    let l = NativePluginLoader::new();
    assert_eq!(l.count(), 0);
    assert!(l.ids().is_empty());
    assert!(l.get("anything").is_none());
}

#[test]
fn loader_default_equiv_new() {
    let a = NativePluginLoader::default();
    let b = NativePluginLoader::new();
    assert_eq!(a.count(), b.count());
}

#[test]
fn loader_missing_path_errors() {
    let l = NativePluginLoader::new();
    let err = l.load("/no/such/path/xyz.dll").expect_err("missing path");
    match err {
        NativeLoadError::Open { path, .. } => {
            assert!(path.to_string_lossy().contains("xyz.dll"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn loader_load_running_exe_missing_entry() {
    // Loading the test binary itself succeeds at Library::new but the
    // `rustre_plugin_register` symbol is absent.
    let l = NativePluginLoader::new();
    let exe = current_exe_path();
    let err = l.load(&exe).expect_err("no register sym");
    match err {
        NativeLoadError::MissingEntry { symbol, path, .. } => {
            assert_eq!(symbol, "rustre_plugin_register");
            assert_eq!(path, exe);
        }
        // On some platforms loading the running exe may itself fail with Open.
        NativeLoadError::Open { .. } => {}
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(l.count(), 0);
}

#[test]
fn loader_unload_unknown_errors() {
    let l = NativePluginLoader::new();
    let e = l.unload("nope@0.0.0").unwrap_err();
    assert!(matches!(e, NativeLoadError::NotFound { .. }));
}

#[test]
fn loader_fuzz_paths_never_panic() {
    let loader = NativePluginLoader::new();
    let mut gen_rand = lcg();
    for _ in 0..30 {
        let len = usize::try_from(gen_rand() % 16).unwrap() + 1;
        let mut buf = String::new();
        for _ in 0..len {
            let ch = ((gen_rand() % 26) as u8 + b'a') as char;
            buf.push(ch);
        }
        let res = loader.load(&buf);
        assert!(res.is_err());
    }
    assert_eq!(loader.count(), 0);
}

#[test]
fn loader_debug_format() {
    let l = NativePluginLoader::new();
    let s = format!("{l:?}");
    assert!(s.contains("NativePluginLoader"));
}

#[test]
fn loader_count_and_ids_threadsafe() {
    let l = Arc::new(NativePluginLoader::new());
    let mut hs = Vec::new();
    for _ in 0..4 {
        let l = Arc::clone(&l);
        hs.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(l.count(), 0);
                assert!(l.ids().is_empty());
                assert!(l.get("x").is_none());
                let _ = l.unload("y");
            }
        }));
    }
    for h in hs { h.join().unwrap(); }
}

#[test]
fn load_error_display_nonempty() {
    let l = NativePluginLoader::new();
    let e = l.load("/no/where/zz.dll").unwrap_err();
    let s = format!("{e}");
    assert!(!s.is_empty());
    // source chain at least exists
    let _ = std::error::Error::source(&e);

    let e2 = l.unload("missing@0").unwrap_err();
    assert!(!format!("{e2}").is_empty());
}

#[test]
fn load_error_variants_format() {
    // Exercise every Display branch we can without a real dylib.
    let p: std::path::PathBuf = "/x".into();
    let v_null = NativeLoadError::NullVtable { path: p.clone() };
    let v_abi = NativeLoadError::Abi { path: p.clone(), reason: "r".into() };
    let v_inv = NativeLoadError::InvalidName { path: p };
    let v_al = NativeLoadError::AlreadyLoaded { id: "a@1".into() };
    let v_nf = NativeLoadError::NotFound { id: "a@1".into() };
    for e in [&v_null, &v_abi, &v_inv, &v_al, &v_nf] {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ── DylibHandle (indirect — we can't easily make one without a real dylib) ──

#[test]
fn dylib_handle_is_send_sync_bound() {
    // Compile-time check: DylibHandle must be Send + Sync.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<rustre_plugin_native::DylibHandle>();
    assert_send_sync::<NativePluginLoader>();
}

// ── NativePlugin.id ──────────────────────────────────────────────────────────

#[test]
fn native_plugin_id_accessor() {
    // We can't construct one without a real plugin, but we can check that
    // `id()` borrows from `id`. Compile-time type check:
    fn _check(p: &rustre_plugin_native::NativePlugin) -> &str { p.id() }
    let _ = _check;
}

// ── PluginVTable layout ──────────────────────────────────────────────────────

#[test]
fn plugin_vtable_repr_c_size_stable() {
    // Just check size > 0 and alignment is reasonable.
    let sz = std::mem::size_of::<PluginVTable>();
    assert!(sz >= 16);
    let al = std::mem::align_of::<PluginVTable>();
    assert!(al >= 4);
}
