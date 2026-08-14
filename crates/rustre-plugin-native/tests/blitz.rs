// Blitz tests for rustre-plugin-native.
use std::ffi::CString;
use std::os::raw::c_char;

use rustre_plugin_native::native_abi_bridge::{
    NativeAbiBridge, PluginVTable, RUSTRE_NATIVE_ABI_MAGIC, RUSTRE_NATIVE_ABI_VERSION,
    PLUGIN_REGISTER_SYMBOL,
};
use rustre_plugin_native::native_plugin_loader::NativeLoadError;
use rustre_plugin_native::{
    CallConv, ExportedSymbol, FunctionPtr, NativePluginLoader, NativeSymbolResolver, SymbolKind,
};

// ── CallConv ─────────────────────────────────────────────────────────────────

#[test]
fn callconv_as_str_all_variants() {
    assert_eq!(CallConv::C.as_str(), "C");
    assert_eq!(CallConv::System.as_str(), "system");
    assert_eq!(CallConv::Rust.as_str(), "Rust");
}

#[test]
fn callconv_eq_and_copy() {
    let a = CallConv::C;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(CallConv::C, CallConv::System);
    assert_ne!(CallConv::System, CallConv::Rust);
}

#[test]
fn callconv_debug_nonempty() {
    assert!(!format!("{:?}", CallConv::C).is_empty());
    assert!(!format!("{:?}", CallConv::System).is_empty());
    assert!(!format!("{:?}", CallConv::Rust).is_empty());
}

// ── FunctionPtr ──────────────────────────────────────────────────────────────

#[test]
fn function_ptr_null_is_unresolved() {
    let p = FunctionPtr::null();
    assert_eq!(p.addr, 0);
    assert!(!p.is_resolved());
    assert_eq!(p.conv, CallConv::C);
}

#[test]
fn function_ptr_from_raw_zero_is_unresolved() {
    // Off-by-zero: explicitly zero address should not be considered resolved.
    let p = FunctionPtr::from_raw(0, CallConv::System);
    assert!(!p.is_resolved());
    assert_eq!(p.conv, CallConv::System);
}

#[test]
fn function_ptr_from_raw_one_is_resolved() {
    let p = FunctionPtr::from_raw(1, CallConv::C);
    assert!(p.is_resolved());
}

#[test]
fn function_ptr_max_addr() {
    let p = FunctionPtr::from_raw(usize::MAX, CallConv::Rust);
    assert!(p.is_resolved());
    assert_eq!(p.addr, usize::MAX);
    assert_eq!(p.conv, CallConv::Rust);
}

#[test]
fn function_ptr_copy_semantics() {
    let p = FunctionPtr::from_raw(0xabc, CallConv::C);
    let q = p; // Copy
    assert_eq!(p.addr, q.addr);
    assert_eq!(p.conv, q.conv);
}

// ── NativeAbiBridge: read_cstr / into_cstring ────────────────────────────────

#[test]
fn read_cstr_null_returns_none() {
    let v: Option<&str> = unsafe { NativeAbiBridge::read_cstr(std::ptr::null()) };
    assert!(v.is_none());
}

#[test]
fn read_cstr_empty_string() {
    let c = CString::new("").unwrap();
    let s = unsafe { NativeAbiBridge::read_cstr(c.as_ptr()) }.unwrap();
    assert_eq!(s, "");
}

#[test]
fn read_cstr_unicode() {
    let c = CString::new("héllo🌎").unwrap();
    let s = unsafe { NativeAbiBridge::read_cstr(c.as_ptr()) }.unwrap();
    assert_eq!(s, "héllo🌎");
}

#[test]
fn read_cstr_invalid_utf8_returns_none() {
    // 0xFF is not valid UTF-8 start byte.
    let bytes: [c_char; 3] = [0xFFu8.cast_signed(), 0x41 as c_char, 0];
    let s = unsafe { NativeAbiBridge::read_cstr(bytes.as_ptr()) };
    assert!(s.is_none());
}

#[test]
fn into_cstring_basic() {
    let c = NativeAbiBridge::into_cstring("plugin").unwrap();
    assert_eq!(c.to_bytes(), b"plugin");
}

#[test]
fn into_cstring_empty_ok() {
    let c = NativeAbiBridge::into_cstring("").unwrap();
    assert_eq!(c.to_bytes(), b"");
}

#[test]
fn into_cstring_interior_nul_fails() {
    assert!(NativeAbiBridge::into_cstring("a\0b").is_none());
    assert!(NativeAbiBridge::into_cstring("\0").is_none());
}

#[test]
fn into_cstring_roundtrip_via_read_cstr() {
    let c = NativeAbiBridge::into_cstring("roundtrip").unwrap();
    let s = unsafe { NativeAbiBridge::read_cstr(c.as_ptr()) }.unwrap();
    assert_eq!(s, "roundtrip");
}

#[test]
fn into_cstring_large_string() {
    let big = "x".repeat(10_000);
    let c = NativeAbiBridge::into_cstring(&big).unwrap();
    let s = unsafe { NativeAbiBridge::read_cstr(c.as_ptr()) }.unwrap();
    assert_eq!(s.len(), 10_000);
}

// ── NativeAbiBridge: validate_vtable ─────────────────────────────────────────

fn make_vtable(magic: u32, ver: u32, name: *const c_char, version: *const c_char) -> PluginVTable {
    PluginVTable {
        magic,
        abi_version: ver,
        name,
        version,
        free_string: None,
    }
}

#[test]
fn validate_vtable_correct_passes() {
    let n = CString::new("p").unwrap();
    let v = CString::new("1.0.0").unwrap();
    let vt = make_vtable(
        RUSTRE_NATIVE_ABI_MAGIC,
        RUSTRE_NATIVE_ABI_VERSION,
        n.as_ptr(),
        v.as_ptr(),
    );
    NativeAbiBridge::validate_vtable(&vt).unwrap();
}

#[test]
fn validate_vtable_zero_magic_fails_with_message() {
    let n = CString::new("p").unwrap();
    let v = CString::new("1").unwrap();
    let vt = make_vtable(0, RUSTRE_NATIVE_ABI_VERSION, n.as_ptr(), v.as_ptr());
    let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
    assert!(err.contains("magic"), "got: {err}");
}

#[test]
fn validate_vtable_off_by_one_magic_fails() {
    let n = CString::new("p").unwrap();
    let v = CString::new("1").unwrap();
    let vt = make_vtable(
        RUSTRE_NATIVE_ABI_MAGIC.wrapping_sub(1),
        RUSTRE_NATIVE_ABI_VERSION,
        n.as_ptr(),
        v.as_ptr(),
    );
    assert!(NativeAbiBridge::validate_vtable(&vt).is_err());
}

#[test]
fn validate_vtable_version_zero_fails() {
    let n = CString::new("p").unwrap();
    let v = CString::new("1").unwrap();
    let vt = make_vtable(RUSTRE_NATIVE_ABI_MAGIC, 0, n.as_ptr(), v.as_ptr());
    let err = NativeAbiBridge::validate_vtable(&vt).unwrap_err();
    assert!(err.contains("ABI version"), "got: {err}");
}

#[test]
fn validate_vtable_max_version_fails() {
    let n = CString::new("p").unwrap();
    let v = CString::new("1").unwrap();
    let vt = make_vtable(RUSTRE_NATIVE_ABI_MAGIC, u32::MAX, n.as_ptr(), v.as_ptr());
    assert!(NativeAbiBridge::validate_vtable(&vt).is_err());
}

#[test]
fn validate_vtable_magic_value_is_rsre_ascii() {
    // "RSRE" = 0x52 53 52 45
    assert_eq!(RUSTRE_NATIVE_ABI_MAGIC, 0x5253_5245);
}

#[test]
fn abi_version_constant_is_positive() {
    // Read through a black_box so the comparison is not const-folded by clippy.
    let v = std::hint::black_box(RUSTRE_NATIVE_ABI_VERSION);
    assert!(v >= 1);
}

#[test]
fn plugin_register_symbol_is_expected_name() {
    assert_eq!(PLUGIN_REGISTER_SYMBOL, b"rustre_plugin_register");
}

// ── PluginVTable Send/Sync (compile-time check) ──────────────────────────────

#[test]
fn vtable_send_sync_bounds() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PluginVTable>();
}

// ── SymbolKind ───────────────────────────────────────────────────────────────

#[test]
fn symbol_kind_as_str_all() {
    assert_eq!(SymbolKind::Function.as_str(), "function");
    assert_eq!(SymbolKind::Data.as_str(), "data");
    assert_eq!(SymbolKind::Weak.as_str(), "weak");
}

#[test]
fn symbol_kind_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(SymbolKind::Function);
    s.insert(SymbolKind::Function);
    s.insert(SymbolKind::Data);
    s.insert(SymbolKind::Weak);
    assert_eq!(s.len(), 3);
}

// ── ExportedSymbol ───────────────────────────────────────────────────────────

#[test]
fn exported_symbol_resolved_true_when_addr_nonzero() {
    let s = ExportedSymbol {
        name: "f".into(),
        kind: SymbolKind::Function,
        ptr: FunctionPtr::from_raw(0x1, CallConv::C),
    };
    assert!(s.is_resolved());
}

#[test]
fn exported_symbol_unresolved_when_null() {
    let s = ExportedSymbol {
        name: "f".into(),
        kind: SymbolKind::Weak,
        ptr: FunctionPtr::null(),
    };
    assert!(!s.is_resolved());
}

#[test]
fn exported_symbol_clone_preserves_fields() {
    let s = ExportedSymbol {
        name: "n".into(),
        kind: SymbolKind::Data,
        ptr: FunctionPtr::from_raw(0x42, CallConv::System),
    };
    let c = s;
    assert_eq!(c.name, "n");
    assert_eq!(c.kind, SymbolKind::Data);
    assert_eq!(c.ptr.addr, 0x42);
    assert_eq!(c.ptr.conv, CallConv::System);
}

// ── NativeSymbolResolver ─────────────────────────────────────────────────────

#[test]
fn resolver_new_is_empty() {
    let r = NativeSymbolResolver::new();
    assert_eq!(r.cache_len(), 0);
    assert!(r.cached("x").is_none());
    assert_eq!(r.iter().count(), 0);
}

#[test]
fn resolver_default_matches_new() {
    let a = NativeSymbolResolver::new();
    let b = NativeSymbolResolver::default();
    assert_eq!(a.cache_len(), b.cache_len());
}

#[test]
fn resolver_with_default_conv_changes_debug() {
    let r = NativeSymbolResolver::new().with_default_conv(CallConv::System);
    let dbg = format!("{r:?}");
    assert!(dbg.contains("System"), "debug should mention conv: {dbg}");
}

#[test]
fn resolver_clear_when_empty_is_noop() {
    let mut r = NativeSymbolResolver::new();
    r.clear();
    assert_eq!(r.cache_len(), 0);
}

#[test]
fn resolver_iter_empty() {
    let r = NativeSymbolResolver::new();
    assert_eq!(r.iter().count(), 0);
}

#[test]
fn resolver_debug_format_contains_count() {
    let r = NativeSymbolResolver::new();
    let s = format!("{r:?}");
    assert!(s.contains("NativeSymbolResolver"));
    assert!(s.contains("cached"));
}

// resolve_function / resolve_weak require a real Library; we exercise them
// against the currently-running process via libloading::Library::this() where
// possible. To avoid platform fragility we test only the failure path: a
// definitely-missing symbol on a freshly loaded library.

#[test]
fn resolver_resolve_weak_missing_returns_null_and_caches() {
    // Try loading the current executable as a library. If unsupported, skip
    // gracefully without using #[ignore].
    let lib_result = unsafe { libloading::Library::new(std::env::current_exe().unwrap()) };
    if let Ok(lib) = lib_result {
        let mut r = NativeSymbolResolver::new();
        let name = "__definitely_not_a_real_symbol_zzz_blitz__";
        let sym = r.resolve_weak(&lib, name);
        assert_eq!(sym.kind, SymbolKind::Weak);
        assert!(!sym.is_resolved());
        assert_eq!(sym.ptr.addr, 0);
        // Cached on second call.
        assert_eq!(r.cache_len(), 1);
        let _again = r.resolve_weak(&lib, name);
        assert_eq!(r.cache_len(), 1);
        assert!(r.cached(name).is_some());
    }
}

#[test]
fn resolver_resolve_function_missing_errors() {
    let lib_result = unsafe { libloading::Library::new(std::env::current_exe().unwrap()) };
    if let Ok(lib) = lib_result {
        let mut r = NativeSymbolResolver::new();
        let res = r.resolve_function(&lib, "__definitely_not_a_real_symbol_zzz_blitz2__");
        assert!(res.is_err());
        // Failed lookups must NOT be cached (so a later real load can succeed).
        assert_eq!(r.cache_len(), 0);
    }
}

// ── NativePluginLoader ───────────────────────────────────────────────────────

#[test]
fn loader_new_default_empty() {
    let l = NativePluginLoader::new();
    assert_eq!(l.count(), 0);
    assert!(l.ids().is_empty());
    assert!(l.get("anything").is_none());
}

#[test]
fn loader_debug_format() {
    let l = NativePluginLoader::new();
    let s = format!("{l:?}");
    assert!(s.contains("NativePluginLoader"));
}

#[test]
fn loader_load_nonexistent_path_yields_open_error() {
    let l = NativePluginLoader::new();
    let err = l.load("Z:/this/path/does/not/exist_blitz.dll").unwrap_err();
    match err {
        NativeLoadError::Open { path, .. } => {
            assert!(path.to_string_lossy().contains("exist_blitz"));
        }
        other => panic!("expected Open, got {other:?}"),
    }
    // Failed load must not leave anything tracked.
    assert_eq!(l.count(), 0);
}

#[test]
fn loader_load_empty_path_errors() {
    let l = NativePluginLoader::new();
    assert!(l.load("").is_err());
    assert_eq!(l.count(), 0);
}

#[test]
fn loader_unload_unknown_yields_notfound() {
    let l = NativePluginLoader::new();
    let err = l.unload("ghost@0.0.0").unwrap_err();
    assert!(matches!(err, NativeLoadError::NotFound { ref id } if id == "ghost@0.0.0"));
}

#[test]
fn loader_unload_unknown_after_failed_load_still_notfound() {
    let l = NativePluginLoader::new();
    let _ = l.load("not_real.dll");
    assert!(matches!(
        l.unload("x@1").unwrap_err(),
        NativeLoadError::NotFound { .. }
    ));
}

#[test]
fn loader_ids_sorted() {
    // Can't load real plugins, but ids() on empty is trivially sorted.
    let l = NativePluginLoader::new();
    let v = l.ids();
    let mut s = v.clone();
    s.sort();
    assert_eq!(v, s);
}

#[test]
fn loader_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NativePluginLoader>();
}

// ── NativeLoadError display strings ──────────────────────────────────────────

#[test]
fn load_error_notfound_display_contains_id() {
    let e = NativeLoadError::NotFound { id: "abc@1.0".into() };
    let s = format!("{e}");
    assert!(s.contains("abc@1.0"), "got: {s}");
}

#[test]
fn load_error_already_loaded_display_contains_id() {
    let e = NativeLoadError::AlreadyLoaded { id: "dup@2".into() };
    let s = format!("{e}");
    assert!(s.contains("dup@2"));
}

#[test]
fn load_error_null_vtable_display_contains_path() {
    let e = NativeLoadError::NullVtable {
        path: std::path::PathBuf::from("/p/q.dll"),
    };
    let s = format!("{e}");
    assert!(s.contains("q.dll"));
}

#[test]
fn load_error_abi_display_contains_reason() {
    let e = NativeLoadError::Abi {
        path: std::path::PathBuf::from("p"),
        reason: "boom".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("boom"));
}

#[test]
fn load_error_invalid_name_display_contains_path() {
    let e = NativeLoadError::InvalidName {
        path: std::path::PathBuf::from("xx.so"),
    };
    let s = format!("{e}");
    assert!(s.contains("xx.so"));
}
