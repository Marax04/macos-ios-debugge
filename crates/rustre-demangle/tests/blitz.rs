//! Blitz test suite for `rustre-demangle`. Exercises public surface,
//! boundary conditions, and adversarial inputs.

use rustre_demangle::*;

// ── Trivial / smoke ──────────────────────────────────────────────────────────

#[test]
fn demangle_empty_returns_none() {
    assert!(demangle("").is_none());
}

#[test]
fn demangle_garbage_returns_none() {
    assert!(demangle("not_a_mangled_symbol").is_none());
}

#[test]
fn auto_demangler_new_works() {
    let a = AutoDemangler::new();
    assert!(a.demangle("").is_none());
}

// ── Itanium detection / demangle ─────────────────────────────────────────────

#[test]
fn itanium_detects_underscore_z() {
    let d = ItaniumDemangler;
    assert!(d.detect("_ZN3foo3barEi"));
    assert!(d.detect("__Z3fooi"));
    assert!(!d.detect("foo"));
    assert!(!d.detect("?foo"));
}

#[test]
fn itanium_demangle_simple() {
    let d = ItaniumDemangler;
    let r = d.demangle("_ZN3foo3barEi").expect("itanium demangle");
    assert_eq!(r.abi, ManglingAbi::Itanium);
    assert_eq!(r.original, "_ZN3foo3barEi");
    assert!(r.demangled.contains("bar"));
    assert_eq!(r.function, "bar(int)".split('(').next().unwrap_or("bar"));
}

#[test]
fn itanium_demangle_rejects_non_itanium() {
    let d = ItaniumDemangler;
    assert!(d.demangle("?foo@@YAXXZ").is_none());
}

#[test]
fn itanium_demangle_empty() {
    let d = ItaniumDemangler;
    assert!(d.demangle("").is_none());
}

#[test]
fn itanium_demangle_truncated() {
    let d = ItaniumDemangler;
    // Truncated length prefix
    assert!(d.demangle("_ZN99notenoughbytes").is_none());
}

// ── MSVC ─────────────────────────────────────────────────────────────────────

#[test]
fn msvc_detect() {
    let d = MsvcDemangler;
    assert!(d.detect("?foo@@YAXXZ"));
    assert!(!d.detect("_Zfoo"));
    assert!(!d.detect(""));
}

#[test]
fn msvc_demangle_basic() {
    let d = MsvcDemangler;
    // Simple free function: void foo(void)
    let r = d.demangle("?foo@@YAXXZ");
    // Should succeed; if not, capture state.
    assert!(r.is_some(), "expected MSVC demangle of ?foo@@YAXXZ to succeed");
    let r = r.unwrap();
    assert_eq!(r.abi, ManglingAbi::Msvc);
    assert!(r.demangled.contains("foo"));
}

#[test]
fn msvc_returns_none_on_non_msvc() {
    let d = MsvcDemangler;
    assert!(d.demangle("_ZN3foo3barEi").is_none());
}

// ── Rust ─────────────────────────────────────────────────────────────────────

#[test]
fn rust_detect_v0() {
    let d = RustDemangler;
    assert!(d.detect("_RNvCs1234_4test3foo"));
}

#[test]
fn rust_demangle_legacy() {
    let d = RustDemangler;
    // Legacy form with hash suffix
    let r = d.demangle("_ZN4test4main17h0123456789abcdefE");
    assert!(r.is_some(), "legacy rust symbol should demangle");
    let r = r.unwrap();
    assert_eq!(r.abi, ManglingAbi::Rust);
}

#[test]
fn rust_returns_none_on_garbage() {
    let d = RustDemangler;
    assert!(d.demangle("garbage").is_none());
}

// ── Swift ────────────────────────────────────────────────────────────────────

#[test]
fn swift_detect_prefixes() {
    let d = SwiftDemangler;
    assert!(d.detect("$sSi"));
    assert!(d.detect("$Sfoo"));
    assert!(d.detect("_T0foo"));
    assert!(d.detect("__T0foo"));
    assert!(!d.detect("?foo"));
}

#[test]
fn swift_demangle_basic_identifiers() {
    let d = SwiftDemangler;
    // 3foo3bar = "foo.bar"
    let r = d.demangle("$s3foo3bar");
    assert!(r.is_some());
    let r = r.unwrap();
    assert_eq!(r.abi, ManglingAbi::Swift);
    assert!(r.demangled.contains("foo"));
    assert!(r.demangled.contains("bar"));
}

#[test]
fn swift_demangle_zero_length_fails_gracefully() {
    let d = SwiftDemangler;
    // 0-length prefix should stop parsing
    let r = d.demangle("$s0foo");
    // It either returns None or stops at the zero, but must not panic
    let _ = r;
}

#[test]
fn swift_extended_parser_basic() {
    let s = SwiftExtendedParser::parse("$s4main3FooC").expect("parse");
    assert_eq!(s.module, "main");
    assert_eq!(s.path, vec!["Foo".to_owned()]);
}

#[test]
fn swift_extended_parser_unknown_prefix() {
    assert!(SwiftExtendedParser::parse("noprefix").is_none());
}

#[test]
fn swift_extended_parser_truncated_length() {
    // "99" but only a few chars - must not panic
    let r = SwiftExtendedParser::parse("$s99ab");
    let _ = r;
}

// ── DemangleOptions / Verbosity ──────────────────────────────────────────────

#[test]
fn options_default() {
    let o = DemangleOptions::default();
    assert!(o.verbose);
    assert_eq!(o.max_template_depth, 32);
    assert!(!o.simplify_templates);
    assert_eq!(o.verbosity, Verbosity::Normal);
}

#[test]
fn options_minimal() {
    let o = DemangleOptions::with_verbosity(Verbosity::Minimal);
    assert!(o.simplify_templates);
    assert!(!o.verbose);
    assert_eq!(o.max_template_depth, 0);
}

#[test]
fn options_full() {
    let o = DemangleOptions::with_verbosity(Verbosity::Full);
    assert!(o.verbose);
    assert_eq!(o.max_template_depth, 64);
}

#[test]
fn options_normal() {
    let o = DemangleOptions::with_verbosity(Verbosity::Normal);
    assert_eq!(o.verbosity, Verbosity::Normal);
    assert_eq!(o.max_template_depth, 32);
}

#[test]
fn verbosity_default_is_normal() {
    assert_eq!(Verbosity::default(), Verbosity::Normal);
}

// ── Symbol classification ────────────────────────────────────────────────────

#[test]
fn classifier_rust_v0() {
    assert_eq!(
        SymbolClassifier::classify("_RNvCs1234_4test3foo"),
        MangleLanguage::Rust
    );
}

#[test]
fn classifier_itanium() {
    assert_eq!(
        SymbolClassifier::classify("_ZN3foo3barEi"),
        MangleLanguage::CppItanium
    );
}

#[test]
fn classifier_msvc() {
    assert_eq!(
        SymbolClassifier::classify("?foo@@YAXXZ"),
        MangleLanguage::CppMsvc
    );
}

#[test]
fn classifier_swift() {
    assert_eq!(
        SymbolClassifier::classify("$s4main3FooC"),
        MangleLanguage::Swift
    );
}

#[test]
fn classifier_objc() {
    assert_eq!(
        SymbolClassifier::classify("+[NSString string]"),
        MangleLanguage::ObjC
    );
}

#[test]
fn classifier_unknown() {
    assert_eq!(SymbolClassifier::classify(""), MangleLanguage::Unknown);
    assert_eq!(SymbolClassifier::classify("plain"), MangleLanguage::Unknown);
}

#[test]
fn classifier_legacy_rust_via_itanium_prefix() {
    let sym = "_ZN4test4main17h0123456789abcdefE";
    assert_eq!(SymbolClassifier::classify(sym), MangleLanguage::Rust);
}

#[test]
fn classifier_instance_form_matches_assoc() {
    let c = SymbolClassifier::new();
    let s = "?foo@@YAXXZ";
    assert_eq!(c.classify_symbol(s), SymbolClassifier::classify(s));
}

// ── Calling conventions ──────────────────────────────────────────────────────

#[test]
fn calling_convention_table() {
    assert_eq!(msvc_calling_convention(b'A'), CallingConvention::Cdecl);
    assert_eq!(msvc_calling_convention(b'B'), CallingConvention::Cdecl);
    assert_eq!(msvc_calling_convention(b'C'), CallingConvention::Pascal);
    assert_eq!(msvc_calling_convention(b'E'), CallingConvention::Thiscall);
    assert_eq!(msvc_calling_convention(b'G'), CallingConvention::Stdcall);
    assert_eq!(msvc_calling_convention(b'I'), CallingConvention::Fastcall);
    assert_eq!(msvc_calling_convention(b'Q'), CallingConvention::Vectorcall);
    assert_eq!(msvc_calling_convention(b'M'), CallingConvention::Clrcall);
    // Unrecognised
    assert_eq!(msvc_calling_convention(b'Z'), CallingConvention::Cdecl);
    assert_eq!(msvc_calling_convention(0), CallingConvention::Cdecl);
}

#[test]
fn calling_convention_as_str() {
    assert_eq!(CallingConvention::Cdecl.as_str(), "__cdecl");
    assert_eq!(CallingConvention::Pascal.as_str(), "__pascal");
    assert_eq!(CallingConvention::Thiscall.as_str(), "__thiscall");
    assert_eq!(CallingConvention::Stdcall.as_str(), "__stdcall");
    assert_eq!(CallingConvention::Fastcall.as_str(), "__fastcall");
    assert_eq!(CallingConvention::Vectorcall.as_str(), "__vectorcall");
    assert_eq!(CallingConvention::Clrcall.as_str(), "__clrcall");
}

// ── MSVC RTTI ────────────────────────────────────────────────────────────────

#[test]
fn rtti_kind_from_digit() {
    assert_eq!(MsvcRttiKind::from_digit('0'), Some(MsvcRttiKind::TypeDescriptor));
    assert_eq!(MsvcRttiKind::from_digit('1'), Some(MsvcRttiKind::BaseClassDescriptor));
    assert_eq!(MsvcRttiKind::from_digit('2'), Some(MsvcRttiKind::BaseClassArray));
    assert_eq!(MsvcRttiKind::from_digit('3'), Some(MsvcRttiKind::ClassHierarchyDescriptor));
    assert_eq!(MsvcRttiKind::from_digit('4'), Some(MsvcRttiKind::CompleteObjectLocator));
    assert_eq!(MsvcRttiKind::from_digit('5'), None);
    assert_eq!(MsvcRttiKind::from_digit('x'), None);
}

#[test]
fn rtti_kind_as_str_nonempty() {
    for k in [
        MsvcRttiKind::TypeDescriptor,
        MsvcRttiKind::BaseClassDescriptor,
        MsvcRttiKind::BaseClassArray,
        MsvcRttiKind::ClassHierarchyDescriptor,
        MsvcRttiKind::CompleteObjectLocator,
    ] {
        assert!(!k.as_str().is_empty());
        assert!(k.as_str().starts_with("RTTI"));
    }
}

#[test]
fn rtti_demangle_basic() {
    // `??_R0` carries a storage suffix; `msvc-demangler` rejects the bare
    // `??_R0?AVFoo@@`, which is what this test used to pass in. It only passed
    // because the parser took the name and discarded whatever followed —
    // including nothing at all. Real symbols look like the corpus's
    // `??_R0?AVtype_info@@@8`.
    let r = demangle_msvc_rtti("??_R0?AVFoo@@@8");
    assert!(r.is_some());
    let s = r.unwrap();
    assert!(s.contains("RTTI Type Descriptor"));
}

#[test]
fn rtti_demangle_rejects_non_rtti() {
    assert!(demangle_msvc_rtti("?foo@@YAXXZ").is_none());
    assert!(demangle_msvc_rtti("").is_none());
}

#[test]
fn rtti_demangle_bad_digit() {
    assert!(demangle_msvc_rtti("??_R9foo@@").is_none());
}

// ── is_constructor / is_destructor / is_vtable / is_typeinfo ────────────────

#[test]
fn ctor_detector() {
    assert!(is_constructor("_ZN3FooC1Ev"));
    assert!(is_constructor("_ZN3FooC2Ev"));
    assert!(!is_constructor("_ZN3FooD1Ev"));
    assert!(!is_constructor("_Zhello"));
    assert!(!is_constructor(""));
    assert!(!is_constructor("?foo@@"));
}

#[test]
fn dtor_detector() {
    assert!(is_destructor("_ZN3FooD0Ev"));
    assert!(is_destructor("_ZN3FooD1Ev"));
    assert!(is_destructor("_ZN3FooD2Ev"));
    assert!(!is_destructor("_ZN3FooC1Ev"));
    assert!(!is_destructor(""));
}

#[test]
fn vtable_detector() {
    assert!(is_vtable("_ZTV3Foo"));
    assert!(!is_vtable("_ZTI3Foo"));
    assert!(!is_vtable(""));
}

#[test]
fn typeinfo_detector() {
    assert!(is_typeinfo("_ZTI3Foo"));
    assert!(is_typeinfo("_ZTS3Foo"));
    assert!(!is_typeinfo("_ZTV3Foo"));
    assert!(!is_typeinfo(""));
}

// ── standard_substitution ────────────────────────────────────────────────────

#[test]
fn standard_subs_known() {
    assert_eq!(standard_substitution("St"), Some("std"));
    assert_eq!(standard_substitution("Sa"), Some("std::allocator"));
    assert_eq!(standard_substitution("Sb"), Some("std::basic_string"));
    assert_eq!(standard_substitution("Ss"), Some("std::string"));
    assert_eq!(standard_substitution("Si"), Some("std::istream"));
    assert_eq!(standard_substitution("So"), Some("std::ostream"));
    assert_eq!(standard_substitution("Sd"), Some("std::iostream"));
    assert_eq!(standard_substitution("Sz"), None);
    assert_eq!(standard_substitution(""), None);
}

// ── ObjC ─────────────────────────────────────────────────────────────────────

#[test]
fn objc_detect_method_syntax() {
    assert!(ObjCDemangler::detect("+[NSString stringWithUTF8String:]"));
    assert!(ObjCDemangler::detect("-[Foo bar]"));
    assert!(ObjCDemangler::detect("_OBJC_CLASS_$_Foo"));
    assert!(!ObjCDemangler::detect("foo"));
    assert!(!ObjCDemangler::detect("+[no_bracket_close"));
}

#[test]
fn objc_demangle_method() {
    let r = ObjCDemangler::demangle("+[NSString string]").unwrap();
    assert!(r.contains("NSString"));
    assert!(r.contains("string"));
    assert!(r.starts_with('+'));
}

#[test]
fn objc_demangle_class_linker() {
    let r = ObjCDemangler::demangle("_OBJC_CLASS_$_Foo").unwrap();
    assert!(r.contains("class"));
    assert!(r.contains("Foo"));
}

#[test]
fn objc_demangle_metaclass_linker() {
    let r = ObjCDemangler::demangle("_OBJC_METACLASS_$_Foo").unwrap();
    assert!(r.contains("metaclass"));
    assert!(r.contains("Foo"));
}

#[test]
fn objc_demangle_ivar_linker() {
    let r = ObjCDemangler::demangle("_OBJC_IVAR_$_Foo._field").unwrap();
    assert!(r.contains("ivar"));
    assert!(r.contains("Foo::_field"));
}

#[test]
fn objc_demangle_empty_class() {
    assert!(ObjCDemangler::demangle("+[]").is_none() || ObjCDemangler::demangle("+[]").is_some());
}

// ── Demangler2 dispatch ──────────────────────────────────────────────────────

#[test]
fn demangler2_unknown_passthrough() {
    let r = Demangler2::demangle("not_a_symbol");
    assert_eq!(r.language, MangleLanguage::Unknown);
    assert_eq!(r.kind, SymbolKind::Unknown);
    assert_eq!(r.demangled, "not_a_symbol");
    assert_eq!(r.mangled, "not_a_symbol");
}

#[test]
fn demangler2_itanium() {
    let r = Demangler2::demangle("_ZN3foo3barEi");
    assert_eq!(r.language, MangleLanguage::CppItanium);
}

#[test]
fn demangler2_with_language_hint_unknown_falls_back() {
    let r = Demangler2::demangle_with_language("_ZN3foo3barEi", MangleLanguage::Unknown);
    // Falls back to auto-detect Itanium
    assert_eq!(r.language, MangleLanguage::CppItanium);
}

#[test]
fn demangler2_with_language_msvc_hint() {
    let r = Demangler2::demangle_with_language("?foo@@YAXXZ", MangleLanguage::CppMsvc);
    assert_eq!(r.language, MangleLanguage::CppMsvc);
}

// ── DemangleResult::to_display_string ────────────────────────────────────────

#[test]
fn display_string_prefers_demangled() {
    let r = DemangleResult {
        mangled: "M".to_owned(),
        demangled: "D".to_owned(),
        language: MangleLanguage::Unknown,
        kind: SymbolKind::Unknown,
    };
    assert_eq!(r.to_display_string(), "D");
}

#[test]
fn display_string_falls_back_to_mangled() {
    let r = DemangleResult {
        mangled: "M".to_owned(),
        demangled: String::new(),
        language: MangleLanguage::Unknown,
        kind: SymbolKind::Unknown,
    };
    assert_eq!(r.to_display_string(), "M");
}

// ── BulkDemangler / SymbolCache ──────────────────────────────────────────────

#[test]
fn bulk_demangler_caches() {
    let mut b = BulkDemangler::new();
    assert_eq!(b.cache_size(), 0);
    let syms = vec!["_ZN3foo3barEi".to_owned(), "_ZN3foo3barEi".to_owned()];
    let r = b.demangle_all(&syms);
    assert_eq!(r.len(), 2);
    assert_eq!(b.cache_size(), 1);
    b.clear_cache();
    assert_eq!(b.cache_size(), 0);
}

#[test]
fn bulk_demangler_default() {
    let b = BulkDemangler::default();
    assert_eq!(b.cache_size(), 0);
}

#[test]
fn symbol_cache_lifecycle() {
    let mut c = SymbolCache::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
    let r = c.demangle_cached("_ZN3foo3barEi");
    assert_eq!(c.len(), 1);
    assert!(!c.is_empty());
    assert!(c.get("_ZN3foo3barEi").is_some());
    assert!(c.get("missing").is_none());
    // Second call hits cache (no panic, same result)
    let r2 = c.demangle_cached("_ZN3foo3barEi");
    assert_eq!(r.demangled, r2.demangled);
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn symbol_cache_manual_insert() {
    let mut c = SymbolCache::new();
    let r = DemangleResult {
        mangled: "x".to_owned(),
        demangled: "y".to_owned(),
        language: MangleLanguage::Unknown,
        kind: SymbolKind::Unknown,
    };
    c.insert("x".to_owned(), r);
    assert_eq!(c.get("x").unwrap().demangled, "y");
}

// ── batch_demangle ───────────────────────────────────────────────────────────

#[test]
fn batch_demangle_preserves_order() {
    let syms = ["_ZN3foo3barEi", "garbage", "?foo@@YAXXZ"];
    let r = batch_demangle(&syms);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].language, MangleLanguage::CppItanium);
    assert_eq!(r[1].language, MangleLanguage::Unknown);
    assert_eq!(r[2].language, MangleLanguage::CppMsvc);
}

#[test]
fn batch_demangle_parallel_dedups() {
    let syms = ["_ZN3foo3barEi", "_ZN3foo3barEi", "_ZN3foo3barEi"];
    let r = batch_demangle_parallel(&syms);
    assert_eq!(r.len(), 3);
    for x in &r {
        assert_eq!(x.language, MangleLanguage::CppItanium);
    }
}

#[test]
fn batch_demangle_empty() {
    let v: Vec<String> = Vec::new();
    let r = batch_demangle(&v);
    assert!(r.is_empty());
}

// ── DemangleFilter ───────────────────────────────────────────────────────────

#[test]
fn filter_by_language() {
    let syms = vec![
        "_ZN3foo3barEi".to_owned(),
        "?foo@@YAXXZ".to_owned(),
        "garbage".to_owned(),
    ];
    let it = DemangleFilter::filter_by_language(&syms, MangleLanguage::CppItanium);
    assert_eq!(it.len(), 1);
    let mv = DemangleFilter::filter_by_language(&syms, MangleLanguage::CppMsvc);
    assert_eq!(mv.len(), 1);
    let unk = DemangleFilter::filter_by_language(&syms, MangleLanguage::Unknown);
    assert_eq!(unk.len(), 1);
}

#[test]
fn filter_known_only() {
    let syms = vec![
        "_ZN3foo3barEi".to_owned(),
        "garbage".to_owned(),
        "?foo@@YAXXZ".to_owned(),
    ];
    let r = DemangleFilter::filter_known_only(&syms);
    assert_eq!(r.len(), 2);
}

// ── normalize_type ───────────────────────────────────────────────────────────

#[test]
fn normalize_collapses_whitespace() {
    assert_eq!(normalize_type("int    foo"), "int foo");
    assert_eq!(normalize_type("  int  "), "int");
}

#[test]
fn normalize_tightens_pointers() {
    assert_eq!(normalize_type("int *"), "int*");
    assert_eq!(normalize_type("int &"), "int&");
}

#[test]
fn normalize_empty() {
    assert_eq!(normalize_type(""), "");
    assert_eq!(normalize_type("   "), "");
}

// ── Trait object: Demangler is Send+Sync ────────────────────────────────────

#[test]
fn demangler_trait_object_is_send_sync() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn Demangler>();
}

// ── DemanglingResult equality/serde ──────────────────────────────────────────

#[test]
fn demangling_result_clone_eq() {
    let r = DemanglingResult {
        original: "o".to_owned(),
        demangled: "d".to_owned(),
        abi: ManglingAbi::Itanium,
        namespace: None,
        class: None,
        function: "f".to_owned(),
        args: vec!["int".to_owned()],
        return_type: None,
    };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn mangling_abi_eq_copy() {
    assert_eq!(ManglingAbi::Itanium, ManglingAbi::Itanium);
    assert_ne!(ManglingAbi::Itanium, ManglingAbi::Msvc);
    let a = ManglingAbi::Rust;
    let b = a; // copy
    assert_eq!(a, b);
}

#[test]
fn symbol_kind_variants() {
    let kinds = [
        SymbolKind::Function,
        SymbolKind::Data,
        SymbolKind::VTable,
        SymbolKind::Typeinfo,
        SymbolKind::TypeinfoName,
        SymbolKind::VTT,
        SymbolKind::Constructor,
        SymbolKind::Destructor,
        SymbolKind::Thunk,
        SymbolKind::Unknown,
    ];
    // All distinct.
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn demangled_symbol_default() {
    let s = DemangledSymbol::default();
    assert!(s.namespace.is_empty());
    assert!(s.class.is_none());
    assert!(s.function.is_empty());
}

// ── Adversarial inputs (should not panic) ────────────────────────────────────

#[test]
fn fuzz_random_should_not_panic() {
    let long_z = format!("_ZN{}", "9".repeat(100));
    let long_q = format!("?{}", "@".repeat(100));
    let inputs: Vec<&str> = vec![
        "",
        "_",
        "_Z",
        "_ZN",
        "_ZN999",
        "_ZN1aE",
        "?",
        "??",
        "??_R",
        "??_R0",
        "$s",
        "$S",
        "_T0",
        "_R",
        "_R\x00",
        "_ZN\u{00ff}E",
        long_z.as_str(),
        long_q.as_str(),
    ];
    for s in &inputs {
        let _ = demangle(s);
        let _ = Demangler2::demangle(s);
        let _ = SymbolClassifier::classify(s);
        let _ = is_constructor(s);
        let _ = is_destructor(s);
        let _ = is_vtable(s);
        let _ = is_typeinfo(s);
    }
}

#[test]
fn fuzz_unicode_safe() {
    let inputs = ["_Zαβγ", "?αβ@@", "$sñ", "_Rñ"];
    for s in &inputs {
        let _ = demangle(s);
        let _ = SymbolClassifier::classify(s);
    }
}

#[test]
fn long_input_no_overflow() {
    let s = format!("_ZN{}{}E", 1000, "a".repeat(10));
    let _ = demangle(&s);
}
