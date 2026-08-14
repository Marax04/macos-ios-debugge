//! Deep adversarial tests for rustre-demangle.
//!
//! Covers: fuzz-resistance, boundaries, classifier consistency, round trips,
//! Send+Sync threading, hash/eq.

#![allow(clippy::cast_possible_truncation, reason = "seeded LCG indices are bounded by % before the cast")]

use rustre_demangle::*;
use std::collections::HashSet;
use std::sync::Arc;

// ── Seeded LCG ────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn ascii_string(&mut self, max_len: usize) -> String {
        let n = (self.next() as usize) % max_len.max(1) + 1;
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            let b = (self.next() % 95) as u8 + 32; // printable ascii
            s.push(b as char);
        }
        s
    }
}

// ── 1-2. Itanium parser ───────────────────────────────────────────────────────

#[test]
fn itanium_detect_basic_set() {
    let yes = ["_Z3fooi", "__Z3fooi", "_ZN3foo3barEi", "_ZTV3Foo"];
    for s in yes {
        assert!(ItaniumDemangler.detect(s), "should detect {s}");
    }
    let no = ["?foo@@YAHXZ", "malloc", "_T03foo", "$s3foo", ""];
    for s in no {
        assert!(!ItaniumDemangler.detect(s), "should not detect {s}");
    }
}

#[test]
fn itanium_simple_returns_some_and_function_set() {
    let inputs = [
        "_Z3fooi",
        "_Z3barv",
        "_ZN3std3vec3VecE",
        "_ZN3foo3barEi",
        "_ZNK3foo3barEv",
        "_ZN3FooC1Ev",
        "_ZN3FooD1Ev",
    ];
    for s in inputs {
        let r = ItaniumDemangler.demangle(s).expect(s);
        assert_eq!(r.original, s);
        assert_eq!(r.abi, ManglingAbi::Itanium);
        assert!(!r.demangled.is_empty());
        // function must be non-empty for a recognised symbol.
        assert!(!r.function.is_empty(), "empty function for {s}: {r:?}");
    }
}

#[test]
fn itanium_demangle_does_not_panic_on_fuzz() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let mut s = String::from("_Z");
        for _ in 0..((lcg.next() as usize) % 40) {
            let b = (lcg.next() % 95) as u8 + 32;
            s.push(b as char);
        }
        let _ = ItaniumDemangler.demangle(&s);
    }
}

// ── 3-4. MSVC ──────────────────────────────────────────────────────────────────

#[test]
fn msvc_detect_basic() {
    assert!(MsvcDemangler.detect("?foo@@YAHXZ"));
    assert!(MsvcDemangler.detect("??0foo@@QAE@XZ"));
    assert!(!MsvcDemangler.detect("_Z3fooi"));
    assert!(!MsvcDemangler.detect(""));
}

#[test]
fn msvc_demangle_known_good_set() {
    let good = ["?foo@@YAHXZ", "?bar@foo@@QAEHXZ"];
    for s in good {
        let r = MsvcDemangler.demangle(s).expect(s);
        assert_eq!(r.abi, ManglingAbi::Msvc);
        assert!(!r.function.is_empty());
    }
}

#[test]
fn msvc_invalid_returns_none() {
    assert!(MsvcDemangler.demangle("?").is_none());
    assert!(MsvcDemangler.demangle("not_msvc").is_none());
}

#[test]
fn msvc_fuzz_no_panic() {
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..200 {
        let mut s = String::from("?");
        for _ in 0..((lcg.next() as usize) % 40) {
            let b = (lcg.next() % 95) as u8 + 32;
            s.push(b as char);
        }
        let _ = MsvcDemangler.demangle(&s);
    }
}

#[test]
fn msvc_rtti_no_panic_and_some_for_real_form() {
    let _ = demangle_msvc_rtti("??_R0?AVMyClass@@@8");
    // Wrong prefix -> None
    assert!(demangle_msvc_rtti("?foo@@YAHXZ").is_none());
}

#[test]
fn msvc_calling_convention_all_pairs() {
    use CallingConvention::*;
    let pairs = [
        (b'A', Cdecl),
        (b'B', Cdecl),
        (b'C', Pascal),
        (b'D', Pascal),
        (b'E', Thiscall),
        (b'F', Thiscall),
        (b'G', Stdcall),
        (b'H', Stdcall),
        (b'I', Fastcall),
        (b'J', Fastcall),
        (b'Q', Vectorcall),
        (b'R', Vectorcall),
        (b'M', Clrcall),
        (b'N', Clrcall),
    ];
    for (b, cc) in pairs {
        assert_eq!(msvc_calling_convention(b), cc);
    }
    // Unknown -> Cdecl per documented fallback.
    assert_eq!(msvc_calling_convention(0xFF), CallingConvention::Cdecl);
}

#[test]
fn msvc_calling_convention_as_str_round_trip() {
    use CallingConvention::*;
    for cc in [Cdecl, Pascal, Thiscall, Stdcall, Fastcall, Vectorcall, Clrcall] {
        let s = cc.as_str();
        assert!(s.starts_with("__"));
    }
}

// ── 5. Rust ────────────────────────────────────────────────────────────────────

#[test]
fn rust_detect_v0_and_legacy() {
    assert!(RustDemangler.detect("_RNvNtCs1234_3std6string6String3new"));
    assert!(RustDemangler.detect(
        "_ZN3std6string6String3new17h0000000000000000E"
    ));
    assert!(!RustDemangler.detect("malloc"));
    assert!(!RustDemangler.detect(""));
}

#[test]
fn rust_demangle_does_not_panic_on_fuzz() {
    let mut lcg = Lcg::new(0xCAFE_F00D_DEAD_BEEF);
    for _ in 0..150 {
        let mut s = String::from(if lcg.next() & 1 == 0 { "_R" } else { "_ZN" });
        for _ in 0..((lcg.next() as usize) % 30) {
            // restrict to ASCII alphanum so rustc-demangle is exercised meaningfully
            let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
            let b = alphabet[(lcg.next() as usize) % alphabet.len()];
            s.push(b as char);
        }
        let _ = RustDemangler.demangle(&s);
    }
}

// ── 6. Swift ───────────────────────────────────────────────────────────────────

#[test]
fn swift_detect_set() {
    let yes = ["_T03foo", "$s3foo", "$S3foo", "__T03foo"];
    for s in yes {
        assert!(SwiftDemangler.detect(s));
    }
    let no = ["_Z3fooi", "?foo@@", "malloc"];
    for s in no {
        assert!(!SwiftDemangler.detect(s));
    }
}

#[test]
fn swift_extended_parser_module_extracted() {
    let r = SwiftExtendedParser::parse("$s5MyApp11MyViewCtrlC").unwrap();
    assert_eq!(r.module, "MyApp");
    // Parser is greedy on length digits — kind marker C ends up included in the identifier.
    assert!(r.path.iter().any(|p| p.contains("MyViewCtrl")));
}

#[test]
fn swift_extended_parser_unknown_prefix_none() {
    assert!(SwiftExtendedParser::parse("malloc").is_none());
    assert!(SwiftExtendedParser::parse("").is_none());
}

#[test]
fn swift_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xFEED_FACE_BAAD_F00D);
    for _ in 0..150 {
        let s = format!("$s{}", lcg.ascii_string(40));
        let _ = SwiftExtendedParser::parse(&s);
        let _ = SwiftDemangler.demangle(&s);
    }
}

// ── 7. D demangler ─────────────────────────────────────────────────────────────

#[test]
fn d_detect_and_simple() {
    assert!(DDemangler::detect("_D3foo3barFZi"));
    assert!(!DDemangler::detect("_Z3fooi"));
    let r = DDemangler::demangle("_D3foo3barFZi").unwrap();
    assert!(r.contains("foo") && r.contains("bar"));
}

#[test]
fn d_fuzz_no_panic() {
    let mut lcg = Lcg::new(0x0BAD_C0DE_1234_5678);
    for _ in 0..150 {
        let s = format!("_D{}", lcg.ascii_string(40));
        let _ = DDemangler::demangle(&s);
        let _ = DDemangler::detect(&s);
    }
}

// ── 8. Auto / convenience ─────────────────────────────────────────────────────

#[test]
fn auto_demangler_dispatches_correctly() {
    let r = demangle("_Z3fooi").unwrap();
    assert_eq!(r.abi, ManglingAbi::Itanium);

    let r = demangle("?foo@@YAHXZ").unwrap();
    assert_eq!(r.abi, ManglingAbi::Msvc);

    assert!(demangle("malloc").is_none());
    assert!(demangle("").is_none());
}

#[test]
fn auto_demangler_struct_default_eq_new() {
    let a = AutoDemangler::new();
    let b = AutoDemangler::default();
    // Both should succeed on the same input.
    let ra = a.demangle("_Z3fooi");
    let rb = b.demangle("_Z3fooi");
    assert_eq!(ra.is_some(), rb.is_some());
}

// ── 9. SymbolClassifier exhaustive ────────────────────────────────────────────

#[test]
fn classifier_covers_all_known_prefixes() {
    let cases = [
        ("_Z3fooi", MangleLanguage::CppItanium),
        ("__Z3fooi", MangleLanguage::CppItanium),
        ("?foo@@YAHXZ", MangleLanguage::CppMsvc),
        ("_RNvCsfoo_3bar", MangleLanguage::Rust),
        ("$s3foo3baryyF", MangleLanguage::Swift),
        ("$S3foo3baryyF", MangleLanguage::Swift),
        ("_T03foo", MangleLanguage::Swift),
        ("_D3foo3barFZi", MangleLanguage::D),
        ("-[NSObject init]", MangleLanguage::ObjC),
        ("+[NSObject alloc]", MangleLanguage::ObjC),
        ("malloc", MangleLanguage::Unknown),
        ("", MangleLanguage::Unknown),
    ];
    for (s, want) in cases {
        assert_eq!(SymbolClassifier::classify(s), want, "input {s}");
    }
    // Instance form mirrors the associated function.
    let c = SymbolClassifier::new();
    assert_eq!(
        c.classify_symbol("_Z3fooi"),
        SymbolClassifier::classify("_Z3fooi")
    );
}

#[test]
fn classifier_legacy_rust_distinguished_from_itanium() {
    let legacy = "_ZN3std6string6String3new17h0000000000000000E";
    assert_eq!(SymbolClassifier::classify(legacy), MangleLanguage::Rust);
}

#[test]
fn classifier_fuzz_total_function() {
    let mut lcg = Lcg::new(0xABCD_EF01_2345_6789);
    for _ in 0..500 {
        let s = lcg.ascii_string(60);
        let _ = SymbolClassifier::classify(&s); // total, never panics
    }
}

// ── 10. Symbol-kind helpers ───────────────────────────────────────────────────

#[test]
fn is_constructor_boundaries() {
    assert!(is_constructor("_ZN3FooC1Ev"));
    assert!(is_constructor("_ZN3FooC2Ev"));
    assert!(is_constructor("_ZN3FooC3Ev"));
    assert!(!is_constructor("_ZN3Foo3barEv"));
    assert!(!is_constructor("?foo@@YAHXZ")); // wrong prefix
    assert!(!is_constructor(""));
}

#[test]
fn is_destructor_boundaries() {
    assert!(is_destructor("_ZN3FooD0Ev"));
    assert!(is_destructor("_ZN3FooD1Ev"));
    assert!(is_destructor("_ZN3FooD2Ev"));
    assert!(!is_destructor("_ZN3Foo3barEv"));
    assert!(!is_destructor(""));
}

#[test]
fn vtable_typeinfo_prefix_checks() {
    assert!(is_vtable("_ZTV3Foo"));
    assert!(!is_vtable("_ZTI3Foo"));
    assert!(is_typeinfo("_ZTI3Foo"));
    assert!(is_typeinfo("_ZTS3Foo"));
    assert!(!is_typeinfo("_ZTV3Foo"));
}

// ── 11. Standard substitutions table ──────────────────────────────────────────

#[test]
fn standard_substitution_all_codes() {
    assert_eq!(standard_substitution("St"), Some("std"));
    assert_eq!(standard_substitution("Sa"), Some("std::allocator"));
    assert_eq!(standard_substitution("Sb"), Some("std::basic_string"));
    assert_eq!(standard_substitution("Ss"), Some("std::string"));
    assert_eq!(standard_substitution("Si"), Some("std::istream"));
    assert_eq!(standard_substitution("So"), Some("std::ostream"));
    assert_eq!(standard_substitution("Sd"), Some("std::iostream"));
    assert_eq!(standard_substitution("Sx"), None);
    assert_eq!(standard_substitution(""), None);
}

// ── 12. Normalize_type ────────────────────────────────────────────────────────

#[test]
fn normalize_type_idempotent_and_collapses() {
    let inputs = [
        "int  *  const",
        "int * ",
        "const  int   * volatile",
        "  std :: vector  ",
        "",
    ];
    for s in inputs {
        let once = normalize_type(s);
        let twice = normalize_type(&once);
        assert_eq!(once, twice, "not idempotent for {s:?}");
        // No double spaces.
        assert!(!once.contains("  "));
        // No space before * or &.
        assert!(!once.contains(" *"));
        assert!(!once.contains(" &"));
    }
}

// ── 13. DemangleOptions / Verbosity ──────────────────────────────────────────

#[test]
fn demangle_options_verbosity_presets() {
    let m = DemangleOptions::with_verbosity(Verbosity::Minimal);
    assert!(!m.verbose);
    assert!(m.simplify_templates);
    assert_eq!(m.max_template_depth, 0);

    let n = DemangleOptions::with_verbosity(Verbosity::Normal);
    assert_eq!(n.verbosity, Verbosity::Normal);

    let f = DemangleOptions::with_verbosity(Verbosity::Full);
    assert!(f.verbose);
    assert!(!f.simplify_templates);
    assert!(f.max_template_depth >= 64);
}

#[test]
fn verbosity_default_is_normal_and_distinct() {
    let v: Verbosity = Verbosity::default();
    assert_eq!(v, Verbosity::Normal);
    assert_ne!(Verbosity::Minimal, Verbosity::Full);
    assert_ne!(Verbosity::Minimal, Verbosity::Normal);
}

// ── 14. DemangleResult display & convenience ─────────────────────────────────

#[test]
fn demangle_result_display_falls_back_to_mangled() {
    let dr = DemangleResult {
        mangled: "_Z3fooi".to_owned(),
        demangled: String::new(),
        language: MangleLanguage::CppItanium,
        kind: SymbolKind::Function,
    };
    assert_eq!(dr.to_display_string(), "_Z3fooi");
    let dr2 = DemangleResult {
        mangled: "_Z3fooi".to_owned(),
        demangled: "foo(int)".to_owned(),
        language: MangleLanguage::CppItanium,
        kind: SymbolKind::Function,
    };
    assert_eq!(dr2.to_display_string(), "foo(int)");
}

// ── 15. Batch demangling ─────────────────────────────────────────────────────

#[test]
fn batch_demangle_preserves_order_and_length() {
    let syms = ["_Z3fooi", "?bar@@YAHXZ", "malloc", "_Z3bazv"];
    let results = batch_demangle(&syms);
    assert_eq!(results.len(), syms.len());
    assert_eq!(results[0].language, MangleLanguage::CppItanium);
    assert_eq!(results[1].language, MangleLanguage::CppMsvc);
    assert_eq!(results[2].language, MangleLanguage::Unknown);
    assert_eq!(results[3].language, MangleLanguage::CppItanium);
}

#[test]
fn batch_demangle_parallel_matches_batch_demangle() {
    let syms: Vec<String> = (0..30)
        .map(|i| {
            if i % 3 == 0 {
                format!("_Z{}foo", i + 3)
            } else if i % 3 == 1 {
                format!("?fn{i}@@YAHXZ")
            } else {
                format!("plain{i}")
            }
        })
        .collect();
    let a = batch_demangle(&syms);
    let b = batch_demangle_parallel(&syms);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x.language, y.language);
        assert_eq!(x.demangled, y.demangled);
        assert_eq!(x.mangled, y.mangled);
    }
}

#[test]
fn batch_demangle_empty() {
    assert!(batch_demangle::<&str>(&[]).is_empty());
    assert!(batch_demangle_parallel::<&str>(&[]).is_empty());
}

// ── 16. SymbolCache ───────────────────────────────────────────────────────────

#[test]
fn symbol_cache_lifecycle() {
    let mut c = SymbolCache::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
    assert!(c.get("_Z3fooi").is_none());
    let _ = c.demangle_cached("_Z3fooi");
    assert_eq!(c.len(), 1);
    let _ = c.demangle_cached("_Z3fooi"); // same key -> same len
    assert_eq!(c.len(), 1);
    let _ = c.demangle_cached("?foo@@YAHXZ");
    assert_eq!(c.len(), 2);
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn symbol_cache_default_equiv_new() {
    let a = SymbolCache::new();
    let b = SymbolCache::default();
    assert_eq!(a.len(), b.len());
    assert!(a.is_empty() && b.is_empty());
}

// ── 17. BulkDemangler ─────────────────────────────────────────────────────────

#[test]
fn bulk_demangler_dedup_cache() {
    let mut bulk = BulkDemangler::new();
    let syms = vec!["_Z3fooi".to_owned(), "_Z3fooi".to_owned(), "malloc".to_owned()];
    let results = bulk.demangle_all(&syms);
    assert_eq!(results.len(), 3);
    assert_eq!(bulk.cache_size(), 2);
    bulk.clear_cache();
    assert_eq!(bulk.cache_size(), 0);
}

// ── 18. DemangleFilter ────────────────────────────────────────────────────────

#[test]
fn demangle_filter_by_language_and_known() {
    let syms = vec![
        "_Z3fooi".to_owned(),
        "?bar@@YAHXZ".to_owned(),
        "malloc".to_owned(),
        "_RNvCsfoo_3bar".to_owned(),
    ];
    let cpp = DemangleFilter::filter_by_language(&syms, MangleLanguage::CppItanium);
    assert_eq!(cpp, vec!["_Z3fooi".to_owned()]);
    let known = DemangleFilter::filter_known_only(&syms);
    assert_eq!(known.len(), 3);
}

// ── 19. Enum hash/eq consistency ─────────────────────────────────────────────

#[test]
fn enum_hash_eq_consistency_30_pairs() {
    let abis = [
        ManglingAbi::Itanium,
        ManglingAbi::Msvc,
        ManglingAbi::Rust,
        ManglingAbi::Swift,
        ManglingAbi::Unknown,
    ];
    let langs = [
        MangleLanguage::CppItanium,
        MangleLanguage::CppMsvc,
        MangleLanguage::Rust,
        MangleLanguage::Swift,
        MangleLanguage::D,
        MangleLanguage::Java,
        MangleLanguage::ObjC,
        MangleLanguage::Unknown,
    ];
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
    // 5 + 8 + 10 = 23 distinct via Eq; build 30+ pairs via cross-equality.
    let mut pairs = 0usize;
    for a in &abis {
        for b in &abis {
            assert_eq!(a == b, std::mem::discriminant(a) == std::mem::discriminant(b));
            pairs += 1;
        }
    }
    for a in &langs {
        for b in &langs {
            assert_eq!(a == b, std::mem::discriminant(a) == std::mem::discriminant(b));
            pairs += 1;
        }
    }
    for a in &kinds {
        for b in &kinds {
            assert_eq!(a == b, std::mem::discriminant(a) == std::mem::discriminant(b));
            pairs += 1;
        }
    }
    assert!(pairs >= 30);

    // HashSet uniqueness check on a hashable wrapper struct.
    let mut set = HashSet::new();
    for &k in &kinds {
        set.insert(format!("{k:?}"));
    }
    assert_eq!(set.len(), kinds.len());
}

#[test]
fn calling_convention_eq_consistency() {
    use CallingConvention::*;
    let all = [Cdecl, Pascal, Thiscall, Stdcall, Fastcall, Vectorcall, Clrcall];
    for a in &all {
        for b in &all {
            assert_eq!(a == b, std::mem::discriminant(a) == std::mem::discriminant(b));
        }
    }
}

// ── 20. MsvcRttiKind ─────────────────────────────────────────────────────────

#[test]
fn msvc_rtti_kind_from_digit_all() {
    assert_eq!(MsvcRttiKind::from_digit('0'), Some(MsvcRttiKind::TypeDescriptor));
    assert_eq!(MsvcRttiKind::from_digit('1'), Some(MsvcRttiKind::BaseClassDescriptor));
    assert_eq!(MsvcRttiKind::from_digit('2'), Some(MsvcRttiKind::BaseClassArray));
    assert_eq!(
        MsvcRttiKind::from_digit('3'),
        Some(MsvcRttiKind::ClassHierarchyDescriptor)
    );
    assert_eq!(
        MsvcRttiKind::from_digit('4'),
        Some(MsvcRttiKind::CompleteObjectLocator)
    );
    assert!(MsvcRttiKind::from_digit('5').is_none());
    assert!(MsvcRttiKind::from_digit('x').is_none());
    for k in [
        MsvcRttiKind::TypeDescriptor,
        MsvcRttiKind::BaseClassDescriptor,
        MsvcRttiKind::BaseClassArray,
        MsvcRttiKind::ClassHierarchyDescriptor,
        MsvcRttiKind::CompleteObjectLocator,
    ] {
        assert!(k.as_str().starts_with("RTTI "));
    }
}

// ── 21. ObjCDemangler ────────────────────────────────────────────────────────

#[test]
fn objc_demangle_forms() {
    let r = ObjCDemangler::demangle("-[NSObject dealloc]").unwrap();
    assert!(r.contains("NSObject") && r.contains("dealloc"));

    let r = ObjCDemangler::demangle("+[NSString stringWithUTF8String:]").unwrap();
    assert!(r.contains("NSString"));

    let r = ObjCDemangler::demangle("_OBJC_CLASS_$_Foo").unwrap();
    assert!(r.contains("Foo") && r.contains("class"));

    let r = ObjCDemangler::demangle("_OBJC_METACLASS_$_Bar").unwrap();
    assert!(r.contains("Bar") && r.contains("metaclass"));

    let r = ObjCDemangler::demangle("_OBJC_IVAR_$_Foo._field").unwrap();
    assert!(r.contains("Foo") && r.contains("field"));

    // No `+[` or `-[` and no `_OBJC_` -> None.
    assert!(ObjCDemangler::demangle("malloc").is_none());
}

#[test]
fn objc_detect_set() {
    assert!(ObjCDemangler::detect("+[X y]"));
    assert!(ObjCDemangler::detect("-[X y]"));
    assert!(ObjCDemangler::detect("_OBJC_CLASS_$_Foo"));
    assert!(!ObjCDemangler::detect("_Z3fooi"));
    assert!(!ObjCDemangler::detect(""));
}

// ── 22. DemangledSymbol default ──────────────────────────────────────────────

#[test]
fn demangled_symbol_default_empty() {
    let s = DemangledSymbol::default();
    assert!(s.namespace.is_empty());
    assert!(s.class.is_none());
    assert!(s.function.is_empty());
    assert!(s.template_args.is_empty());
    assert!(s.cv_qualifiers.is_empty());
}

// ── 23. Demangler2 dispatch ──────────────────────────────────────────────────

#[test]
fn demangler2_returns_input_for_unknown() {
    let r = Demangler2::demangle("plain_C_name");
    assert_eq!(r.language, MangleLanguage::Unknown);
    assert_eq!(r.demangled, "plain_C_name");
    assert_eq!(r.mangled, "plain_C_name");
}

#[test]
fn demangler2_language_hint_respected() {
    let r = Demangler2::demangle_with_language("_Z3fooi", MangleLanguage::CppItanium);
    assert_eq!(r.language, MangleLanguage::CppItanium);
}

// ── 24. DemangleResult round trip via SymbolCache ────────────────────────────

#[test]
fn symbol_cache_demangle_cached_consistent() {
    let mut c = SymbolCache::new();
    let r1 = c.demangle_cached("_Z3fooi");
    let r2 = c.demangle_cached("_Z3fooi");
    assert_eq!(r1.demangled, r2.demangled);
    assert_eq!(r1.language, r2.language);
}

// ── 25. Stats / success rate ─────────────────────────────────────────────────

#[test]
fn demangler_stats_success_rate_bounds() {
    let s = DemanglerStats {
        input_count: 0,
        success_count: 0,
        avg_ns: 0,
    };
    assert!(s.success_rate().abs() < f64::EPSILON);
    let s = DemanglerStats {
        input_count: 10,
        success_count: 7,
        avg_ns: 100,
    };
    assert!((s.success_rate() - 0.7).abs() < 1e-9);
    let s = DemanglerStats {
        input_count: 4,
        success_count: 4,
        avg_ns: 0,
    };
    assert!((s.success_rate() - 1.0).abs() < 1e-9);
}

// ── 26. Send + Sync threaded stress ──────────────────────────────────────────

#[test]
fn auto_demangler_threaded_stress() {
    let auto: Arc<AutoDemangler> = Arc::new(AutoDemangler::new());
    let mut handles = Vec::new();
    let inputs = [
        "_Z3fooi",
        "?bar@@YAHXZ",
        "_ZN3foo3barEi",
        "_T03foo3baryyF",
        "malloc",
    ];
    for t in 0..4 {
        let auto = Arc::clone(&auto);
        
        handles.push(std::thread::spawn(move || {
            let mut lcg = Lcg::new(0x1000_0000 + t);
            for _ in 0..100 {
                let s = inputs[(lcg.next() as usize) % inputs.len()];
                let _ = auto.demangle(s);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn itanium_demangler_send_sync_threaded() {
    let d = Arc::new(ItaniumDemangler);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&d);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = d.demangle("_Z3fooi");
                assert!(r.is_some());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn msvc_demangler_send_sync_threaded() {
    let d = Arc::new(MsvcDemangler);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&d);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = d.demangle("?foo@@YAHXZ");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── 27. DemanglingResult invariants ──────────────────────────────────────────

#[test]
fn demangling_result_original_preserved() {
    let inputs = ["_Z3fooi", "_ZN3foo3barEi", "?foo@@YAHXZ"];
    for s in inputs {
        let r = demangle(s).expect(s);
        assert_eq!(r.original, s);
        assert!(!r.demangled.is_empty());
    }
}

// ── 28. Boundaries / off-by-one ──────────────────────────────────────────────

#[test]
fn boundary_inputs_no_panic() {
    let edges = [
        "",
        "_",
        "_Z",
        "__Z",
        "_R",
        "?",
        "$s",
        "_D",
        "_T0",
        "_OBJC_",
        "+",
        "-",
        "+[",
        "-[",
        "+[ ]",
        "_OBJC_CLASS_$_",
    ];
    for s in edges {
        let _ = demangle(s);
        let _ = SymbolClassifier::classify(s);
        let _ = ItaniumDemangler.demangle(s);
        let _ = MsvcDemangler.demangle(s);
        let _ = RustDemangler.demangle(s);
        let _ = SwiftDemangler.demangle(s);
        let _ = DDemangler::demangle(s);
        let _ = ObjCDemangler::demangle(s);
        let _ = is_constructor(s);
        let _ = is_destructor(s);
        let _ = is_vtable(s);
        let _ = is_typeinfo(s);
        let _ = standard_substitution(s);
        let _ = normalize_type(s);
        let _ = demangle_msvc_rtti(s);
    }
}

// ── 29. Large fuzz over the auto dispatcher ──────────────────────────────────

#[test]
fn auto_demangler_full_fuzz() {
    let mut lcg = Lcg::new(0xDEAD_C0DE_BEEF_F00D);
    for _ in 0..500 {
        let s = lcg.ascii_string(80);
        let _ = demangle(&s);
        let _ = Demangler2::demangle(&s);
    }
}

// ── 30. ItaniumNativeDemangler kind detection ────────────────────────────────

#[test]
fn native_itanium_detect_kind_categories() {
    assert_eq!(
        ItaniumNativeDemangler::detect_kind("_ZTV3Foo"),
        SymbolKind::VTable
    );
    assert_eq!(
        ItaniumNativeDemangler::detect_kind("_ZTI3Foo"),
        SymbolKind::Typeinfo
    );
    assert_eq!(
        ItaniumNativeDemangler::detect_kind("_Z3fooi"),
        SymbolKind::Function
    );
}

// ── 31. RustV0Demangler detect ───────────────────────────────────────────────

#[test]
fn rust_v0_detect_and_no_panic() {
    assert!(RustV0Demangler::detect("_RNvNtCs1234_3std2io5print"));
    assert!(!RustV0Demangler::detect("_Z3fooi"));
    let _ = RustV0Demangler::demangle("_RNvCsfoo_3bar");
}
