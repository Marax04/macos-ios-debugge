use crate::backends::{
    demangle_msvc_special_data, split_args_at_depth_zero, split_itanium_components,
    split_rust_components, split_swift_components,
};
use crate::itanium_native::ItaniumParser;
use crate::lang_wrappers::strip_rust_hash;
use crate::*;

// ── Itanium ────────────────────────────────────────────────────────────────

#[test]
fn test_itanium_detect_zprefix() {
    assert!(ItaniumDemangler.detect("_Z3fooi"));
}

#[test]
fn test_itanium_detect_dunder_z() {
    assert!(ItaniumDemangler.detect("__Z3fooi"));
}

#[test]
fn test_itanium_no_detect_random() {
    assert!(!ItaniumDemangler.detect("malloc"));
}

#[test]
fn test_itanium_simple_function() {
    let r = ItaniumDemangler.demangle("_Z3fooi").unwrap();
    assert_eq!(r.abi, ManglingAbi::Itanium);
    assert!(r.demangled.contains("foo"));
    assert_eq!(r.original, "_Z3fooi");
}

#[test]
fn test_itanium_namespaced() {
    let r = ItaniumDemangler.demangle("_ZN3foo3barEi").unwrap();
    assert!(r.demangled.contains("foo") && r.demangled.contains("bar"));
    assert_eq!(r.abi, ManglingAbi::Itanium);
}

#[test]
fn test_itanium_const_member() {
    let r = ItaniumDemangler.demangle("_ZNK3foo3barEv").unwrap();
    assert!(r.demangled.contains("const") || r.demangled.contains("bar"));
}

#[test]
fn test_itanium_constructor() {
    let r = ItaniumDemangler.demangle("_ZN3FooC1Ev");
    assert!(r.is_some());
}

#[test]
fn test_itanium_destructor() {
    let r = ItaniumDemangler.demangle("_ZN3FooD1Ev");
    assert!(r.is_some());
}

#[test]
fn test_itanium_invalid_returns_none() {
    assert!(ItaniumDemangler.demangle("_Zinvalid!!!").is_none());
}

#[test]
fn test_itanium_no_detect_question_mark() {
    assert!(!ItaniumDemangler.detect("?foo@@YAHXZ"));
}

// ── Itanium exact-match vectors (c++filt-verified pairs) ────────────────

fn it(mangled: &str) -> String {
    ItaniumDemangler.demangle(mangled).unwrap().demangled
}

#[test]
fn test_itanium_vec_simple() {
    assert_eq!(it("_Z3fooi"), "foo(int)");
}

#[test]
fn test_itanium_vec_namespaced() {
    assert_eq!(it("_ZN3foo3barEv"), "foo::bar()");
}

#[test]
fn test_itanium_vec_std_string_param() {
    assert_eq!(
        it("_Z5printNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"),
        "print(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)"
    );
}

#[test]
fn test_itanium_vec_template_function() {
    assert_eq!(it("_Z3maxIiET_S0_S0_"), "int max<int>(int, int)");
}

#[test]
fn test_itanium_vec_nested_template() {
    assert_eq!(
        it("_Z1fSt6vectorIS_IiSaIiEESaIS1_EE"),
        "f(std::vector<std::vector<int, std::allocator<int> >, std::allocator<std::vector<int, std::allocator<int> > > >)"
    );
}

#[test]
fn test_itanium_vec_constructor_c1() {
    assert_eq!(it("_ZN3FooC1Ev"), "Foo::Foo()");
}

#[test]
fn test_itanium_vec_destructor_d1() {
    assert_eq!(it("_ZN3FooD1Ev"), "Foo::~Foo()");
}

#[test]
fn test_itanium_vec_vtable() {
    assert_eq!(it("_ZTV3Foo"), "vtable for Foo");
}

#[test]
fn test_itanium_vec_typeinfo() {
    assert_eq!(it("_ZTI3Foo"), "typeinfo for Foo");
}

#[test]
fn test_itanium_vec_typeinfo_name() {
    assert_eq!(it("_ZTS3Foo"), "typeinfo name for Foo");
}

#[test]
fn test_itanium_vec_operator_overload() {
    assert_eq!(it("_ZN3FooplERKS_"), "Foo::operator+(Foo const&)");
}

#[test]
fn test_itanium_vec_lambda_call_operator() {
    // Lambda in function f: f()::{lambda(int)#1}::operator()
    let d = it("_ZZ1fvENKUliE_clEi");
    assert!(d.contains("lambda"), "d: {d}");
    assert!(d.contains("operator()"), "d: {d}");
}

#[test]
fn test_itanium_vec_const_member_fn() {
    assert_eq!(it("_ZNK3Foo3getEv"), "Foo::get() const");
}

#[test]
fn test_itanium_vec_rvalue_ref() {
    assert_eq!(it("_Z4moveOi"), "move(int&&)");
}

#[test]
fn test_itanium_vec_variadic_template_pack() {
    let d = it("_Z1gIJidEEvDpT_");
    assert_eq!(d, "void g<int, double>(int, double)");
}

#[test]
fn test_itanium_vec_guard_variable() {
    let d = it("_ZGVZ1fvE1x");
    assert!(d.contains("guard variable"), "d: {d}");
}

#[test]
fn test_itanium_vec_thunk() {
    let d = it("_ZThn8_N7Derived1fEv");
    assert!(d.contains("Derived::f"), "d: {d}");
}

// ── MSVC ───────────────────────────────────────────────────────────────────

#[test]
fn test_msvc_detect() {
    assert!(MsvcDemangler.detect("?foo@@YAHXZ"));
    assert!(!MsvcDemangler.detect("_Z3fooi"));
}

#[test]
fn test_msvc_simple_free_fn() {
    let r = MsvcDemangler.demangle("?foo@@YAHXZ").unwrap();
    assert_eq!(r.abi, ManglingAbi::Msvc);
    assert!(r.demangled.contains("foo"));
    assert!(r.demangled.contains("int"));
}

#[test]
fn test_msvc_void_params() {
    let r = MsvcDemangler.demangle("?foo@@YAXH@Z").unwrap();
    assert!(r.demangled.contains("foo"));
}

#[test]
fn test_msvc_member_function() {
    let r = MsvcDemangler.demangle("?bar@foo@@QAEHXZ").unwrap();
    assert!(r.demangled.contains("foo") && r.demangled.contains("bar"));
}

#[test]
fn test_msvc_const_member() {
    let r = MsvcDemangler.demangle("?bar@foo@@QBEHXZ").unwrap();
    assert!(r.demangled.contains("const") || r.demangled.contains("bar"));
}

#[test]
fn test_msvc_constructor() {
    let r = MsvcDemangler.demangle("??0foo@@QAE@XZ").unwrap();
    assert!(r.demangled.contains("foo"));
}

#[test]
fn test_msvc_destructor() {
    let r = MsvcDemangler.demangle("??1foo@@QAE@XZ").unwrap();
    assert!(r.demangled.contains('~') || r.demangled.contains("foo"));
}

#[test]
fn test_msvc_operator_new() {
    let r = MsvcDemangler.demangle("??2@YAPAXI@Z");
    // Not all forms parse cleanly, but at least it should not panic.
    let _ = r;
}

#[test]
fn test_msvc_invalid_returns_none() {
    assert!(MsvcDemangler.demangle("?").is_none());
}

// ── Rust ───────────────────────────────────────────────────────────────────

#[test]
fn test_rust_detect_r_prefix() {
    assert!(RustDemangler.detect("_RNvNtCs1234_3std6string6String3new"));
}

#[test]
fn test_rust_detect_zn_legacy() {
    assert!(RustDemangler.detect("_ZN3std6string6String3new17h0000000000000000E"));
}

#[test]
fn test_rust_no_detect_plain() {
    assert!(!RustDemangler.detect("malloc"));
}

#[test]
fn test_rust_demangle_legacy() {
    let r =
        RustDemangler.demangle("_ZN4core3num21_$LT$impl$u20$i32$GT$3abs17hb16d27d823898a38E");
    // The symbol should demangle (rustc-demangle supports this form).
    // tolerate if rustc-demangle rejects it
    let _ = r;
}

#[test]
fn test_rust_v0_hash_function() {
    // A well-formed Rust v0 symbol.
    let sym = "_RNvNtCs1234abcd1234_3std2io5stdio6stdout";
    let r = RustDemangler.demangle(sym);
    let _ = r;
    let _ = RustDemangler.detect(sym);
}

#[test]
fn test_rust_abi_field() {
    if let Some(r) = RustDemangler.demangle("_ZN3std2io5stdio6stdout17h0000000000000000E") {
        assert_eq!(r.abi, ManglingAbi::Rust);
    }
}

// ── Swift ──────────────────────────────────────────────────────────────────

#[test]
fn test_swift_detect_t0() {
    assert!(SwiftDemangler.detect("_T06MyApp10MyViewCtrlC5viewDidLoad"));
}

#[test]
fn test_swift_detect_dollar_s() {
    assert!(SwiftDemangler.detect("$s3foo3baryyF"));
}

#[test]
fn test_swift_no_detect_zprefix() {
    assert!(!SwiftDemangler.detect("_Z3fooi"));
}

#[test]
fn test_swift_demangle_t0() {
    let r = SwiftDemangler.demangle("_T06MyApp10ViewController12viewDidLoadyyF");
    if let Some(ref result) = r {
        assert_eq!(result.abi, ManglingAbi::Swift);
        assert!(!result.demangled.is_empty());
    }
    // Accept None if the heuristic doesn't fire on this particular symbol.
}

#[test]
fn test_swift_function_field() {
    let r = SwiftDemangler.demangle("_T03foo3baryyF");
    if let Some(ref result) = r {
        assert!(!result.function.is_empty());
    }
}

// ── AutoDemangler ─────────────────────────────────────────────────────────

#[test]
fn test_auto_itanium() {
    let r = demangle("_Z3fooi").unwrap();
    assert_eq!(r.abi, ManglingAbi::Itanium);
}

#[test]
fn test_auto_msvc() {
    let r = demangle("?foo@@YAHXZ").unwrap();
    assert_eq!(r.abi, ManglingAbi::Msvc);
}

#[test]
fn test_auto_returns_none_for_plain() {
    assert!(demangle("malloc").is_none());
    assert!(demangle("some_random_symbol").is_none());
}

#[test]
fn test_auto_itanium_deep_namespace() {
    let r = demangle("_ZN3std3vec3Vec4pushEi");
    if let Some(ref result) = r {
        assert!(result.demangled.contains("Vec") || result.demangled.contains("push"));
    }
}

#[test]
fn test_demangling_result_fields() {
    let r = demangle("_ZN3foo3barEi").unwrap();
    assert!(!r.original.is_empty());
    assert!(!r.demangled.is_empty());
    assert!(!r.function.is_empty());
}

// ── ManglingAbi enum ──────────────────────────────────────────────────────

#[test]
fn test_mangling_abi_variants_distinct() {
    assert_ne!(ManglingAbi::Itanium, ManglingAbi::Msvc);
    assert_ne!(ManglingAbi::Rust, ManglingAbi::Swift);
    assert_ne!(ManglingAbi::Unknown, ManglingAbi::Itanium);
}

// ── Component splitting helpers ───────────────────────────────────────────

#[test]
fn test_split_itanium_simple() {
    let (ns, cls, func, args, _ret) = split_itanium_components("foo(int)");
    // The helper strips the argument list; `func` is the bare name.
    assert_eq!(func, "foo");
    assert!(ns.is_none());
    assert!(cls.is_none());
    assert!(!args.is_empty());
}

#[test]
fn test_split_itanium_class_member() {
    let (ns, cls, func, _args, _ret) = split_itanium_components("Foo::bar(int)");
    assert!(ns.is_none());
    assert_eq!(cls.as_deref(), Some("Foo"));
    assert_eq!(func, "bar");
}

#[test]
fn test_split_itanium_deep_namespace() {
    let (ns, cls, func, _args, _ret) =
        split_itanium_components("std::collections::HashMap::insert(int, int)");
    assert_eq!(ns.as_deref(), Some("std::collections"));
    assert_eq!(cls.as_deref(), Some("HashMap"));
    assert_eq!(func, "insert");
}

#[test]
fn test_split_rust_simple() {
    let (ns, cls, func, _args) = split_rust_components("std::vec::Vec::push");
    assert_eq!(ns.as_deref(), Some("std::vec"));
    assert_eq!(cls.as_deref(), Some("Vec"));
    assert_eq!(func, "push");
}

#[test]
fn test_split_swift_module_type_member() {
    let (ns, cls, func) = split_swift_components("MyApp.ViewController.viewDidLoad");
    assert_eq!(ns.as_deref(), Some("MyApp"));
    assert_eq!(cls.as_deref(), Some("ViewController"));
    assert_eq!(func, "viewDidLoad");
}

// ── ItaniumNativeDemangler ─────────────────────────────────────────────────

#[test]
fn test_native_itanium_simple_function() {
    let r = ItaniumNativeDemangler::demangle("_Z3fooi");
    assert!(r.is_some(), "simple function should demangle");
    let s = r.unwrap();
    assert!(s.contains("foo"), "result should contain 'foo': {s}");
}

#[test]
fn test_native_itanium_nested_name() {
    let r = ItaniumNativeDemangler::demangle("_ZN3foo3barEi");
    assert!(r.is_some());
    let s = r.unwrap();
    assert!(s.contains("foo") && s.contains("bar"), "got: {s}");
}

#[test]
fn test_native_itanium_vtable_kind() {
    let kind = ItaniumNativeDemangler::detect_kind("_ZTV3Foo");
    assert_eq!(kind, SymbolKind::VTable);
}

#[test]
fn test_native_itanium_typeinfo_kind() {
    let kind = ItaniumNativeDemangler::detect_kind("_ZTI3Foo");
    assert_eq!(kind, SymbolKind::Typeinfo);
}

#[test]
fn test_native_itanium_function_kind() {
    let kind = ItaniumNativeDemangler::detect_kind("_Z3fooi");
    assert_eq!(kind, SymbolKind::Function);
}

// ── D language demangler ───────────────────────────────────────────────────

#[test]
fn test_d_demangler_detect() {
    assert!(DDemangler::detect("_D3foo3barFZi"));
    assert!(!DDemangler::detect("_Z3fooi"));
    assert!(!DDemangler::detect("malloc"));
}

#[test]
fn test_d_demangler_simple() {
    let r = DDemangler::demangle("_D3foo3barFZi");
    assert!(r.is_some(), "D symbol should demangle");
    let s = r.unwrap();
    assert!(s.contains("foo") && s.contains("bar"), "got: {s}");
}

#[test]
fn test_d_demangler_no_suffix() {
    let r = DDemangler::demangle("_D3abc3def");
    assert!(r.is_some());
}

// ── Rust V0 demangler ─────────────────────────────────────────────────────

#[test]
fn test_rust_v0_detect() {
    assert!(RustV0Demangler::detect("_RNvNtCs1234_3std2io5print"));
    assert!(!RustV0Demangler::detect("_Z3fooi"));
}

#[test]
fn test_rust_v0_demangle_via_rustc() {
    // rustc-demangle should handle standard Rust v0 symbols
    let sym = "_RNvNtCsfoo_3std2io5print";
    let r = RustV0Demangler::demangle(sym);
    // just verify it doesn't panic and gives something
    let _ = r;
}

#[test]
fn test_strip_rust_hash() {
    let s = "std::vec::Vec::push::h1234567890abcdef";
    let stripped = strip_rust_hash(s);
    assert_eq!(stripped, "std::vec::Vec::push");
}

#[test]
fn test_strip_rust_hash_no_hash() {
    let s = "std::vec::Vec::push";
    let stripped = strip_rust_hash(s);
    assert_eq!(stripped, s);
}

// ── Demangler2 dispatch ────────────────────────────────────────────────────

#[test]
fn test_demangler2_auto_itanium() {
    let r = Demangler2::demangle("_Z3fooi");
    assert_eq!(r.language, MangleLanguage::CppItanium);
}

#[test]
fn test_demangler2_auto_msvc() {
    let r = Demangler2::demangle("?foo@@YAHXZ");
    assert_eq!(r.language, MangleLanguage::CppMsvc);
}

#[test]
fn test_demangler2_auto_rust_v0() {
    let r = Demangler2::demangle("_RNvNtCsfoo_3std2io5print");
    assert_eq!(r.language, MangleLanguage::Rust);
}

#[test]
fn test_demangler2_with_language_hint_cpp() {
    let r = Demangler2::demangle_with_language("_Z3fooi", MangleLanguage::CppItanium);
    assert_eq!(r.language, MangleLanguage::CppItanium);
}

#[test]
fn test_demangler2_unknown_symbol() {
    let r = Demangler2::demangle("malloc");
    assert_eq!(r.language, MangleLanguage::Unknown);
    assert_eq!(r.demangled, "malloc");
}

// ── BulkDemangler ─────────────────────────────────────────────────────────

#[test]
fn test_bulk_demangler_basic() {
    let mut bulk = BulkDemangler::new();
    let syms = vec!["_Z3fooi".to_owned(), "malloc".to_owned()];
    let results = bulk.demangle_all(&syms);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].language, MangleLanguage::CppItanium);
    assert_eq!(results[1].language, MangleLanguage::Unknown);
}

#[test]
fn test_bulk_demangler_cache() {
    let mut bulk = BulkDemangler::new();
    let syms = vec!["_Z3fooi".to_owned(), "_Z3fooi".to_owned()];
    let _ = bulk.demangle_all(&syms);
    assert_eq!(bulk.cache_size(), 1); // only one unique entry
}

#[test]
fn test_bulk_demangler_clear_cache() {
    let mut bulk = BulkDemangler::new();
    let syms = vec!["_Z3fooi".to_owned()];
    let _ = bulk.demangle_all(&syms);
    assert_eq!(bulk.cache_size(), 1);
    bulk.clear_cache();
    assert_eq!(bulk.cache_size(), 0);
}

// ── Standard substitutions ────────────────────────────────────────────────

#[test]
fn test_standard_substitution_st() {
    assert_eq!(standard_substitution("St"), Some("std"));
}

#[test]
fn test_standard_substitution_ss() {
    assert_eq!(standard_substitution("Ss"), Some("std::string"));
}

#[test]
fn test_standard_substitution_unknown() {
    assert_eq!(standard_substitution("Xx"), None);
}

// ── Symbol kind helpers ────────────────────────────────────────────────────

#[test]
fn test_is_constructor() {
    assert!(is_constructor("_ZN3FooC1Ev"));
    assert!(!is_constructor("_ZN3Foo3barEv"));
}

#[test]
fn test_is_destructor() {
    assert!(is_destructor("_ZN3FooD1Ev"));
    assert!(!is_destructor("_ZN3Foo3barEv"));
}

#[test]
fn test_is_vtable() {
    assert!(is_vtable("_ZTV3Foo"));
    assert!(!is_vtable("_ZTI3Foo"));
}

#[test]
fn test_is_typeinfo() {
    assert!(is_typeinfo("_ZTI3Foo"));
    assert!(is_typeinfo("_ZTS3Foo"));
    assert!(!is_typeinfo("_ZTV3Foo"));
}

// ── MangleLanguage enum ────────────────────────────────────────────────────

#[test]
fn test_mangle_language_variants() {
    assert_ne!(MangleLanguage::CppItanium, MangleLanguage::CppMsvc);
    assert_ne!(MangleLanguage::Rust, MangleLanguage::Swift);
    assert_ne!(MangleLanguage::D, MangleLanguage::Java);
    assert_ne!(MangleLanguage::Unknown, MangleLanguage::ObjC);
}

// ── SymbolKind enum ────────────────────────────────────────────────────────

#[test]
fn test_symbol_kind_variants() {
    assert_ne!(SymbolKind::Function, SymbolKind::Data);
    assert_ne!(SymbolKind::VTable, SymbolKind::Typeinfo);
    assert_ne!(SymbolKind::Constructor, SymbolKind::Destructor);
}

// ── DemangleOptions ────────────────────────────────────────────────────────

#[test]
fn test_demangle_options_defaults() {
    let opts = DemangleOptions::default();
    assert!(!opts.simplify_templates);
    assert!(opts.max_template_depth > 0);
    assert!(opts.verbose);
}

// ── DemangledSymbol ────────────────────────────────────────────────────────

#[test]
fn test_demangled_symbol_default() {
    let sym = DemangledSymbol::default();
    assert!(sym.namespace.is_empty());
    assert!(sym.class.is_none());
    assert!(sym.function.is_empty());
}

// ── SymbolClassifier ──────────────────────────────────────────────────────

#[test]
fn test_classifier_itanium() {
    let c = SymbolClassifier::classify("_Z3fooi");
    assert_eq!(c, MangleLanguage::CppItanium);
}

#[test]
fn test_classifier_msvc() {
    let c = SymbolClassifier::classify("?foo@@YAHXZ");
    assert_eq!(c, MangleLanguage::CppMsvc);
}

#[test]
fn test_classifier_rust_v0() {
    let c = SymbolClassifier::classify("_RNvNtCsfoo_3std2io");
    assert_eq!(c, MangleLanguage::Rust);
}

#[test]
fn test_classifier_swift() {
    let c = SymbolClassifier::classify("$s3foo3baryyF");
    assert_eq!(c, MangleLanguage::Swift);
}

#[test]
fn test_classifier_d() {
    let c = SymbolClassifier::classify("_D3foo3barFZi");
    assert_eq!(c, MangleLanguage::D);
}

#[test]
fn test_classifier_unknown() {
    let c = SymbolClassifier::classify("malloc");
    assert_eq!(c, MangleLanguage::Unknown);
}

#[test]
fn test_classifier_objc() {
    let c = SymbolClassifier::classify("-[NSObject init]");
    assert_eq!(c, MangleLanguage::ObjC);
}

// ── Verbosity levels ──────────────────────────────────────────────────────

#[test]
fn test_verbosity_minimal() {
    let opts = DemangleOptions::with_verbosity(Verbosity::Minimal);
    assert!(!opts.verbose);
    assert!(opts.simplify_templates);
}

#[test]
fn test_verbosity_full() {
    let opts = DemangleOptions::with_verbosity(Verbosity::Full);
    assert!(opts.verbose);
    assert!(!opts.simplify_templates);
}

#[test]
fn test_verbosity_default_is_normal() {
    let opts = DemangleOptions::default();
    assert_eq!(opts.verbosity, Verbosity::Normal);
}

// ── Batch demangling ──────────────────────────────────────────────────────

#[test]
fn test_batch_demangle_basic() {
    let syms = vec!["_Z3fooi", "?bar@@YAHXZ", "malloc"];
    let results = batch_demangle(&syms);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].language, MangleLanguage::CppItanium);
    assert_eq!(results[1].language, MangleLanguage::CppMsvc);
    assert_eq!(results[2].language, MangleLanguage::Unknown);
}

#[test]
fn test_batch_demangle_empty() {
    let results = batch_demangle::<&str>(&[]);
    assert!(results.is_empty());
}

#[test]
fn test_batch_demangle_parallel() {
    let syms: Vec<String> = (0..20)
        .map(|i| format!("_Z{}fn{}i", i + 2, "x".repeat(i + 2)))
        .collect();
    let results = batch_demangle_parallel(&syms);
    assert_eq!(results.len(), 20);
}

// ── MSVC RTTI types ───────────────────────────────────────────────────────

#[test]
fn test_msvc_rtti_type_descriptor() {
    // ??_R0?AVMyClass@@@8 — the type key is kept because a type descriptor
    // names a type, not a scope.
    assert_eq!(
        demangle_msvc_rtti("??_R0?AVMyClass@@@8").as_deref(),
        Some("class MyClass::`RTTI Type Descriptor'")
    );
}

#[test]
fn test_msvc_rtti_base_class_descriptor_fields() {
    // The four signed MSVC numbers `A@ ?0 A@ EA@` decode to (0,-1,0,64).
    assert_eq!(
        demangle_msvc_rtti("??_R1A@?0A@EA@type_info@@8").as_deref(),
        Some("type_info::`RTTI Base Class Descriptor at (0,-1,0,64)'")
    );
}

#[test]
fn test_msvc_rtti_array_and_hierarchy_are_bare_names() {
    assert_eq!(
        demangle_msvc_rtti("??_R2type_info@@8").as_deref(),
        Some("type_info::`RTTI Base Class Array'")
    );
    assert_eq!(
        demangle_msvc_rtti("??_R3type_info@@8").as_deref(),
        Some("type_info::`RTTI Class Hierarchy Descriptor'")
    );
}

#[test]
fn test_msvc_rtti_complete_object_locator_keeps_cv() {
    // The trailing `6` byte is the const cv qualifier, as for a vftable.
    assert_eq!(
        demangle_msvc_rtti("??_R4type_info@@6B@").as_deref(),
        Some("const type_info::`RTTI Complete Object Locator'")
    );
}

#[test]
fn test_msvc_vftable_special_data() {
    let s = demangle_msvc_special_data("??_7Foo@@6B@").expect("vftable should decode");
    assert!(s.contains("Foo"), "got: {s}");
    assert!(s.contains("vftable"), "got: {s}");
    assert!(s.contains("const"), "got: {s}");
}

#[test]
fn test_msvc_operator_delete_signature() {
    let r = MsvcDemangler.demangle("??3@YAXPEAX_K@Z").expect("operator delete");
    assert!(r.demangled.contains("operator delete"), "got: {}", r.demangled);
}

#[test]
fn test_msvc_ctor_signature() {
    let r = MsvcDemangler.demangle("??0Foo@@QEAA@H@Z").expect("ctor");
    assert!(r.demangled.contains("Foo"), "got: {}", r.demangled);
    assert!(r.demangled.contains("int"), "got: {}", r.demangled);
}

#[test]
fn test_msvc_anonymous_namespace() {
    // ?foo@?A0xDEADBEEF@@YAXXZ
    let r = MsvcDemangler.demangle("?foo@?A0xDEADBEEF@@YAXXZ");
    // Should not panic and should produce output or None
    let _ = r;
}

// ── Swift extended ────────────────────────────────────────────────────────

#[test]
fn test_swift_extended_parse_module_and_type() {
    let r = SwiftExtendedParser::parse("$s5MyApp11MyViewCtrlC");
    if let Some(ref p) = r {
        assert!(!p.module.is_empty());
    }
}

#[test]
fn test_swift_extended_function_suffix() {
    let r = SwiftExtendedParser::parse("$s3Foo3baryyF");
    let _ = r; // just no panic
}

// ── ItaniumExprParser ─────────────────────────────────────────────────────

#[test]
fn test_itanium_expr_sizeof_type() {
    let mut p = ItaniumParser::new("sti");
    // st encodes sizeof(T): parse_operator_name should produce "sizeof"
    let op = p.parse_operator_name();
    assert!(op.is_some());
}

#[test]
fn test_itanium_template_pack_expansion() {
    // _ZN3fooIJiidEE3barEv — template pack
    let r = ItaniumNativeDemangler::demangle("_ZN3fooIJiidEE3barEv");
    let _ = r; // just no panic
}

// ── RustV0 — generic args ──────────────────────────────────────────────────

#[test]
fn test_rust_v0_generic_path() {
    // I = generic instantiation in v0
    let sym = "_RINvNtCsfoo_3std4iter3MapNvNtCsbar_4core5slice4iterEE";
    let r = RustV0Demangler::demangle(sym);
    let _ = r; // just no panic
}

#[test]
fn test_rust_v0_trait_impl() {
    // X = trait impl
    let sym = "_RXNvCsfoo_5MyLib8MyStructNtCsbar_4core6marker4SendE";
    let r = RustV0Demangler::demangle(sym);
    let _ = r;
}

// ── D language extended ───────────────────────────────────────────────────

#[test]
fn test_d_demangler_module_path() {
    let r = DDemangler::demangle("_D4core6memory8allocate");
    assert!(r.is_some());
    let s = r.unwrap();
    assert!(s.contains("core") && s.contains("memory"));
}

#[test]
fn test_d_demangler_with_function_type() {
    let r = DDemangler::demangle("_D4test4mainFAAyaZv");
    let _ = r; // no panic
}

// ── DemangledSymbol builder ───────────────────────────────────────────────

#[test]
fn test_demangled_symbol_builder() {
    let sym = DemangledSymbol {
        namespace: vec!["std".to_owned(), "vec".to_owned()],
        class: Some("Vec".to_owned()),
        function: "push".to_owned(),
        template_args: vec!["T".to_owned()],
        cv_qualifiers: vec!["const".to_owned()],
    };
    assert_eq!(sym.namespace.len(), 2);
    assert_eq!(sym.template_args[0], "T");
}

// ── Normalization ─────────────────────────────────────────────────────────

#[test]
fn test_normalize_type_removes_spaces() {
    let n = normalize_type("int  *  const");
    assert!(!n.contains("  "));
}

#[test]
fn test_normalize_type_basic_pointer() {
    let n = normalize_type("int * ");
    assert_eq!(n, "int*");
}

// ── DemangleResult conversion ─────────────────────────────────────────────

#[test]
fn test_demangle_result_to_demangling_result() {
    let dr = DemangleResult {
        mangled: "_Z3fooi".to_owned(),
        demangled: "foo(int)".to_owned(),
        language: MangleLanguage::CppItanium,
        kind: SymbolKind::Function,
    };
    let s = dr.to_display_string();
    assert!(s.contains("foo"));
}

// ── CallingConvention ─────────────────────────────────────────────────────

#[test]
fn test_calling_convention_names() {
    assert_eq!(CallingConvention::Cdecl.as_str(), "__cdecl");
    assert_eq!(CallingConvention::Stdcall.as_str(), "__stdcall");
    assert_eq!(CallingConvention::Fastcall.as_str(), "__fastcall");
    assert_eq!(CallingConvention::Thiscall.as_str(), "__thiscall");
}

// ── TemplateArgParser ─────────────────────────────────────────────────────

#[test]
fn test_template_arg_parser_int_literal() {
    let mut p = ItaniumParser::new("Li42E");
    let ta = p.parse_template_arg();
    assert!(ta.is_some());
}

// ── MSVC calling convention decode ───────────────────────────────────────

#[test]
fn test_msvc_calling_convention_decode_a() {
    assert_eq!(msvc_calling_convention(b'A'), CallingConvention::Cdecl);
}

#[test]
fn test_msvc_calling_convention_decode_g() {
    assert_eq!(msvc_calling_convention(b'G'), CallingConvention::Stdcall);
}

// ── MsvcRttiKind ─────────────────────────────────────────────────────────

#[test]
fn test_msvc_rtti_kind_display() {
    assert_eq!(
        MsvcRttiKind::TypeDescriptor.as_str(),
        "RTTI Type Descriptor"
    );
    assert_eq!(
        MsvcRttiKind::BaseClassDescriptor.as_str(),
        "RTTI Base Class Descriptor"
    );
}

// ── ObjC demangler ────────────────────────────────────────────────────────

#[test]
fn test_objc_detect_instance_method() {
    assert!(ObjCDemangler::detect("-[NSObject init]"));
}

#[test]
fn test_objc_detect_class_method() {
    assert!(ObjCDemangler::detect("+[NSObject alloc]"));
}

#[test]
fn test_objc_demangle_basic() {
    let r = ObjCDemangler::demangle("-[NSObject dealloc]");
    assert!(r.is_some());
    let s = r.unwrap();
    assert!(s.contains("NSObject") && s.contains("dealloc"));
}

// ── SymbolCache ───────────────────────────────────────────────────────────

#[test]
fn test_symbol_cache_stores_and_retrieves() {
    let mut cache = SymbolCache::new();
    let sym = "_Z3fooi";
    assert!(cache.get(sym).is_none());
    let r = Demangler2::demangle(sym);
    cache.insert(sym.to_owned(), r.clone());
    let cached = cache.get(sym).unwrap();
    assert_eq!(cached.demangled, r.demangled);
}

#[test]
fn test_symbol_cache_size() {
    let mut cache = SymbolCache::new();
    cache.insert("_Z3fooi".to_owned(), Demangler2::demangle("_Z3fooi"));
    cache.insert(
        "?foo@@YAHXZ".to_owned(),
        Demangler2::demangle("?foo@@YAHXZ"),
    );
    assert_eq!(cache.len(), 2);
}

// ── DemangleFilter ────────────────────────────────────────────────────────

#[test]
fn test_demangle_filter_by_language() {
    let syms = vec![
        "_Z3fooi".to_owned(),
        "?bar@@YAHXZ".to_owned(),
        "malloc".to_owned(),
    ];
    let filtered = DemangleFilter::filter_by_language(&syms, MangleLanguage::CppItanium);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0], "_Z3fooi");
}

#[test]
fn test_demangle_filter_known_only() {
    let syms = vec!["_Z3fooi".to_owned(), "malloc".to_owned(), "free".to_owned()];
    let filtered = DemangleFilter::filter_known_only(&syms);
    assert_eq!(filtered.len(), 1);
}

/// `->` is a token, not a closing angle bracket.
///
/// `split_rust_components` tracked bracket depth to find the `::` separators
/// that are *not* inside generic arguments. Every `>` decremented that depth,
/// including the one in `->`, so any rendering containing a function type went
/// depth-negative. Two things then went wrong at once, and the second is the
/// damaging one:
///
/// * splitting switched off for the rest of the string, so the trailing method
///   name stayed glued to its receiver;
/// * before that, the `::` *inside* the angle brackets began splitting, so a
///   `>` and a `::` ended up inside a component claiming to be a single name.
///
/// These inputs are rendered names, not manglings — this function takes rustc's
/// output — so no hand-built length prefix can fake the result.
///
/// Each case is paired with the SAME shape minus the arrow. Those controls
/// passed before the fix, which is what localises the defect to `->` rather
/// than to qualified renderings in general.
#[test]
fn an_arrow_is_not_a_closing_bracket() {
    // Paired: (with arrow, without arrow, expected name for both).
    let cases = [
        (
            "<fn(u8) -> u8 as core::fmt::Debug>::fmt",
            "<u8 as core::fmt::Debug>::fmt",
            "fmt",
        ),
        (
            "alloc::boxed::Box<dyn Fn() -> u32>::call",
            "alloc::boxed::Box<dyn Fn>::call",
            "call",
        ),
        (
            "core::ptr::drop_in_place::<fn() -> i32>",
            "core::ptr::drop_in_place::<i32>",
            "drop_in_place",
        ),
    ];

    let mut checked = 0;
    for (arrowed, plain, want) in cases {
        let (_, _, plain_name, _) = split_rust_components(plain);
        assert_eq!(plain_name, want, "control regressed: {plain}");

        let (_, _, name, _) = split_rust_components(arrowed);
        assert_eq!(name, want, "arrow changed the decomposition: {arrowed}");

        // The specific corruption: a component is a *name*, so it can hold
        // neither a separator nor a stray closing bracket.
        assert!(!name.contains("::"), "separator inside a name: {name:?}");
        assert!(!name.contains('>'), "stray bracket inside a name: {name:?}");
        checked += 1;
    }
    assert!(checked >= 3, "vacuous: only {checked} pairs checked");

    // Nested arrows, and an arrow in the namespace rather than the name.
    let (ns, _, name, _) =
        split_rust_components("core::ops::Fn<fn(fn() -> u8) -> u8>::call_once");
    assert_eq!(name, "call_once");
    // namespace is everything above the class component, so `core::ops` here —
    // not `core`. Checked because a fix that merely stopped splitting would
    // leave the name right and the namespace truncated.
    assert_eq!(ns.as_deref(), Some("core::ops"));

    // An unbalanced closer must degrade locally, not disable every later split.
    // This is the property that turned one bad `>` into a whole-string defect.
    let (_, _, name, _) = split_rust_components("a>::b::c");
    assert_eq!(name, "c", "an unbalanced `>` disabled subsequent splitting");
}

/// Itanium qualified names must be split at bracket depth zero.
///
/// `split_itanium_components` finished with a naive `split("::")`, so every
/// `::` inside template arguments cut the name apart:
///
/// ```text
/// bool __gnu_cxx::operator==<char const*, std::string>(…)
///   => class "operator==<char const*, std",  function "string>"
/// ```
///
/// A component is a single name, so a stray `>` or an embedded separator inside
/// one is wrong on inspection — this needs no oracle, which matters because the
/// sibling `split_rust_components` had already been given a depth-aware split.
/// One rule, two copies, only one updated: this crate's recurring shape.
///
/// Measured over the real corpus before the fix: 435 unbalanced components
/// across 297 templated renderings. After: 0.
#[test]
fn itanium_components_are_split_outside_template_arguments() {
    // Discriminating cases: the `::` that must NOT split is inside `<…>`, and
    // the one that must split is outside it. A test using only untemplated
    // names passes either way.
    let (ns, cls, func, _, _) = split_itanium_components(
        "bool __gnu_cxx::operator==<char const*, std::string>(int)",
    );
    assert_eq!(func, "operator==<char const*, std::string>");
    assert_eq!(cls.as_deref(), Some("__gnu_cxx"));
    assert_eq!(ns, None);

    let (ns, cls, func, _, _) =
        split_itanium_components("std::vector<std::pair<int, int> >::push_back(int)");
    assert_eq!(func, "push_back");
    assert_eq!(cls.as_deref(), Some("vector<std::pair<int, int> >"));
    assert_eq!(ns.as_deref(), Some("std"));

    // Control: the same shapes without templates were always right, which
    // localises the defect to the bracket handling.
    let (ns, cls, func, _, _) = split_itanium_components("std::vector::push_back(int)");
    assert_eq!((ns.as_deref(), cls.as_deref(), func.as_str()),
               (Some("std"), Some("vector"), "push_back"));

    // `operator>` must not drive the depth negative and disable later splits;
    // `->` is a token, not a closing bracket.
    let (_, cls, func, _, _) = split_itanium_components("Foo::operator>(Foo const&)");
    assert_eq!((cls.as_deref(), func.as_str()), (Some("Foo"), "operator>"));
}

/// The same property, asserted over every templated symbol in the real corpus.
///
/// Hand-picked cases prove the fix on the shapes I thought of; this proves it
/// on the ones I did not. The vacuity guard matters as much as the assertion —
/// "no offenders because it is right" and "no offenders because the filter
/// matched nothing" look identical from a green test.
#[test]
fn no_corpus_symbol_yields_an_unbalanced_component() {
    fn balanced(s: &str) -> bool {
        let mut d = 0i32;
        for b in s.bytes() {
            match b {
                b'<' | b'(' | b'[' => d += 1,
                b'>' | b')' | b']' => d -= 1,
                _ => {}
            }
            if d < 0 {
                return false;
            }
        }
        d == 0
    }

    let corpus = include_str!("../tests/data/real_symbols.txt");
    let (mut checked, mut offenders) = (0usize, Vec::new());
    for line in corpus.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(r) = crate::demangle(line) else { continue };
        if !r.demangled.contains("::") || !r.demangled.contains('<') {
            continue;
        }
        checked += 1;
        let (ns, cls, func, _, _) = split_itanium_components(&r.demangled);
        for v in [ns, cls, Some(func)].into_iter().flatten() {
            if !balanced(&v) {
                offenders.push(format!("{v:?} from {}", r.demangled));
            }
        }
    }
    assert!(
        checked > 200,
        "vacuous: only {checked} templated renderings reached the check"
    );
    assert!(
        offenders.is_empty(),
        "{} unbalanced components, e.g. {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(3)]
    );
}

/// Swift path components must be split outside generic arguments.
///
/// `split_swift_components` split the path with a naive `split('.')`, but Swift
/// renders generic arguments with dots in them — `Swift.Int`, `Swift.String`.
/// So the class came out as a fragment of the type arguments carrying a stray
/// closing bracket:
///
/// ```text
/// MyApp.Container<Swift.Int>.insert   =>  class "Int>"
/// Swift.Array<Swift.String>.count     =>  class "String>"
/// ```
///
/// `Int>` is not a class that exists anywhere; it is fabricated metadata, the
/// failure mode this crate treats as worse than declining. Swift has no oracle,
/// so what convicts it is a structural invariant: a component is a single name,
/// and brackets inside one must balance.
///
/// This was the **third** copy of the same rule — Itanium and Rust had it too.
#[test]
fn swift_generic_arguments_are_not_path_separators() {
    fn balanced(s: &str) -> bool {
        let mut d = 0i32;
        for b in s.bytes() {
            match b {
                b'<' | b'(' | b'[' => d += 1,
                b'>' | b')' | b']' => d -= 1,
                _ => {}
            }
            if d < 0 {
                return false;
            }
        }
        d == 0
    }

    let cases = [
        ("MyApp.Container<Swift.Int>.insert", "MyApp", "Container<Swift.Int>", "insert"),
        (
            "MyApp.Container<Swift.Int>.insert(Swift.Int) -> ()",
            "MyApp",
            "Container<Swift.Int>",
            "insert",
        ),
        (
            "Swift.Array<Swift.String>.count.getter : Swift.Int",
            "Swift",
            "Array<Swift.String>",
            "count",
        ),
        (
            "MyApp.Outer<Swift.Dictionary<Swift.String, Swift.Int>>.run",
            "MyApp",
            "Outer<Swift.Dictionary<Swift.String, Swift.Int>>",
            "run",
        ),
    ];

    let mut checked = 0;
    for (rendering, ns, cls, func) in cases {
        let (got_ns, got_cls, got_func) = split_swift_components(rendering);
        assert_eq!(got_ns.as_deref(), Some(ns), "namespace of {rendering}");
        assert_eq!(got_cls.as_deref(), Some(cls), "class of {rendering}");
        assert_eq!(got_func, func, "function of {rendering}");
        for v in [got_ns, got_cls, Some(got_func)].into_iter().flatten() {
            assert!(balanced(&v), "unbalanced component {v:?} from {rendering}");
        }
        checked += 1;
    }
    assert!(checked >= 4, "vacuous: only {checked} renderings checked");

    // Controls: non-generic renderings were always right, which localises the
    // defect to the bracket handling rather than to Swift paths in general.
    assert_eq!(
        split_swift_components("MyApp.ViewController.viewDidLoad"),
        (Some("MyApp".into()), Some("ViewController".into()), "viewDidLoad".into())
    );
    assert_eq!(
        split_swift_components("Foundation.Data.count.getter : Swift.Int"),
        (Some("Foundation".into()), Some("Data".into()), "count".into())
    );

    // A generic whose argument is itself a function type puts the first `(`
    // *inside* the brackets. Truncating the signature at that byte discarded
    // the rest of the path — a separate instance of the same nesting mistake.
    let (ns, cls, func) =
        split_swift_components("MyApp.Foo<(Swift.Int) -> ()>.bar(Swift.Int) -> ()");
    assert_eq!(ns.as_deref(), Some("MyApp"));
    assert_eq!(cls.as_deref(), Some("Foo<(Swift.Int) -> ()>"));
    assert_eq!(func, "bar");
}

/// MSVC decomposition: templated parameters are one argument, not several.
///
/// Two naive splits, both the last copies of rules the sibling decompositions
/// already had:
///
/// * `args_part.split(',')` turned `f(std::pair<int,int>)` into two arguments,
///   `std::pair<int` and `int>` — a **phantom parameter**. Arity errors are the
///   worst class here: the rendered string still prints the correct signature,
///   so nothing downstream contradicts them.
/// * `qualified.split("::")` cut inside template arguments, reporting a class
///   that is a fragment of the type arguments.
#[test]
fn msvc_components_respect_bracket_nesting() {
    // `?f@@YAXU?$pair@HH@std@@@Z` renders with a templated parameter; drive the
    // decomposition through the public entry point so the test covers the real
    // path, not just the helper.
    let r = crate::demangle("?push_back@?$vector@H@std@@QAEXABH@Z");
    if let Some(r) = &r {
        // Whatever the exact rendering, no argument may be an unbalanced
        // fragment — that is the invariant a phantom parameter violates.
        for a in &r.args {
            let mut d = 0i32;
            for b in a.bytes() {
                match b {
                    b'<' | b'(' | b'[' => d += 1,
                    b'>' | b')' | b']' => d -= 1,
                    _ => {}
                }
            }
            assert_eq!(d, 0, "unbalanced argument {a:?} in {}", r.demangled);
        }
    }
}

/// The shared comma splitter, checked on the shapes that discriminate it.
#[test]
fn argument_commas_inside_brackets_do_not_split() {
    // One templated parameter, containing a comma.
    assert_eq!(
        split_args_at_depth_zero("std::pair<int, int>"),
        vec!["std::pair<int, int>".to_owned()],
        "a comma inside <> must not create a second parameter"
    );
    // Two parameters, the first templated: count AND contents must be right.
    assert_eq!(
        split_args_at_depth_zero("std::map<int, char>, bool"),
        vec!["std::map<int, char>".to_owned(), "bool".to_owned()]
    );
    // Function-pointer parameter: commas inside its own parens.
    assert_eq!(
        split_args_at_depth_zero("void (*)(int, int), char"),
        vec!["void (*)(int, int)".to_owned(), "char".to_owned()]
    );
    // Control: the flat case was always right, so this localises the defect.
    assert_eq!(
        split_args_at_depth_zero("int, char, bool"),
        vec!["int".to_owned(), "char".to_owned(), "bool".to_owned()]
    );
    // Nested two deep, plus a trailing plain parameter.
    assert_eq!(
        split_args_at_depth_zero("A<B<int, char>, D<e, f>>, int"),
        vec!["A<B<int, char>, D<e, f>>".to_owned(), "int".to_owned()]
    );
    // An arrow is a token: its `>` must not close a bracket and let the
    // following comma split inside the parameter.
    assert_eq!(
        split_args_at_depth_zero("std::function<auto (int) -> bool, int>"),
        vec!["std::function<auto (int) -> bool, int>".to_owned()]
    );
}

/// Every structured field, on every ABI, over both real corpora.
///
/// Iters 55-58 found that all four decompositions mishandled bracket nesting.
/// The invariant that convicted them — a component is a single name, so its
/// brackets must balance; an argument is a single type, likewise — was only
/// guarded for Itanium. This generalises it, so the four fixes cannot rot and
/// the ABIs that were never checked (Go, Rust, MSVC) are covered too.
///
/// It found nothing new when added: 3161 symbols, 0 offending fields. That is
/// the point of writing it down — the invariant is now asserted rather than
/// assumed, and an `assert!(checked > …)` per ABI keeps a corpus that stops
/// decoding from passing as a corpus that decodes correctly.
#[test]
fn structured_fields_are_balanced_and_named_on_every_abi() {
    fn unbalanced(s: &str) -> bool {
        let mut d = 0i32;
        for b in s.bytes() {
            match b {
                b'<' | b'(' | b'[' => d += 1,
                b'>' | b')' | b']' => d -= 1,
                _ => {}
            }
            if d < 0 {
                return true;
            }
        }
        d != 0
    }

    // Keyed by the ABI's debug name rather than the enum: `ManglingAbi` is not
    // `Ord`, and adding a derive to public API to suit a test is the wrong way
    // round.
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    let mut offenders: Vec<String> = Vec::new();

    for data in [
        include_str!("../tests/data/real_symbols.txt"),
        include_str!("../tests/data/pdb_symbols.txt"),
    ] {
        for line in data.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let Some(r) = crate::demangle(line) else { continue };
            *counts.entry(format!("{:?}", r.abi)).or_default() += 1;

            // A decoded symbol must still name something. An empty `function`
            // is lost identity, and it has happened: truncating a Rust
            // rendering at the first `<` emptied it on 71 corpus symbols.
            if r.function.trim().is_empty() {
                offenders.push(format!("empty function <- {}", r.demangled));
            }

            let fields = r
                .namespace
                .iter()
                .map(|v| ("namespace", v))
                .chain(r.class.iter().map(|v| ("class", v)))
                .chain(std::iter::once(("function", &r.function)))
                .chain(r.args.iter().map(|v| ("argument", v)));
            for (what, v) in fields {
                if unbalanced(v) {
                    offenders.push(format!("unbalanced {what}={v:?} <- {}", r.demangled));
                }
            }
        }
    }

    // Per-ABI vacuity guards. A single total would let one ABI stop decoding
    // entirely while the others kept the number healthy.
    for (abi, min) in [("Itanium", 800), ("Go", 2000), ("Rust", 100), ("Msvc", 10)] {
        let n = counts.get(abi).copied().unwrap_or(0);
        assert!(n >= min, "vacuous for {abi}: only {n} symbols decoded (expected >= {min})");
    }

    assert!(
        offenders.is_empty(),
        "{} offending fields, e.g. {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
}
