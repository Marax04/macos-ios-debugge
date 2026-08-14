//! Fidelity test suite for `rustre_demangle::demangle`.
//!
//! Verifies demangled OUTPUT correctness against known-good expected strings
//! matching the documented behavior of the reference demanglers
//! (c++filt / Itanium ABI examples, rustc-demangle, llvm-undname,
//! Go tool conventions, swift-demangle, D ABI).
//!
//! Cases where the crate's current output is semantically wrong (wrong arity,
//! wrong return type, missing member, or no output at all) are NOT baked in as
//! passing assertions; they live in the ignored `fidelity_known_gaps` test,
//! each with a comment describing expected vs actual, so gaps are documented
//! while CI stays green.

/// Assert that every `(mangled, expected)` pair demangles exactly to `expected`.
fn check(cases: &[(&str, &str)]) {
    for (mangled, expected) in cases {
        let Some(result) = rustre_demangle::demangle(mangled) else {
            panic!("demangle returned None for {mangled} (expected {expected})");
        };
        assert_eq!(
            result.demangled, *expected,
            "symbol {mangled}: expected {expected}, got {}",
            result.demangled
        );
    }
}

/// Report ALL mismatching cases at once rather than aborting on the first.
///
/// Used by the gap tracker so a single run shows the full remaining backlog,
/// and so closing a gap is visible as a shrinking list instead of a new
/// first-failure.
fn report_gaps(cases: &[(&str, &str)]) {
    let mut open = Vec::new();
    let mut closed = Vec::new();
    for (mangled, expected) in cases {
        match rustre_demangle::demangle(mangled) {
            Some(result) if result.demangled == *expected => closed.push(*mangled),
            Some(result) => open.push(format!(
                "  {mangled}\n    expected: {expected}\n    actual:   {}",
                result.demangled
            )),
            None => open.push(format!(
                "  {mangled}\n    expected: {expected}\n    actual:   <None>"
            )),
        }
    }
    println!(
        "fidelity gaps: {} closed / {} tracked",
        closed.len(),
        cases.len()
    );
    for c in &closed {
        println!("  CLOSED: {c}");
    }
    assert!(
        open.is_empty(),
        "{} fidelity gaps still open:\n{}",
        open.len(),
        open.join("\n")
    );
}

#[test]
fn fidelity_itanium_simple() {
    check(&[
        (r"_Z3fooi", "foo(int)"),
        (r"_Z3foov", "foo()"),
        (r"_Z3barPKc", "bar(char const*)"),
        (r"_Z3addii", "add(int, int)"),
        (r"_Z1hic", "h(int, char)"),
        (r"_Z1fPFivE", "f(int (*)())"),
        (r"_Z1fA37_iPS_", "f(int [37], int (*) [37])"),
    ]);
}

#[test]
fn fidelity_itanium_nested_names() {
    check(&[
        (r"_ZN3foo3barEv", "foo::bar()"),
        (r"_ZN2ns5funcsEid", "ns::funcs(int, double)"),
        (r"_ZN4outr5inner4funcEi", "outr::inner::func(int)"),
        (r"_ZN5first6secondEv", "first::second()"),
        (r"_ZN9wikipedia7article6formatEv", "wikipedia::article::format()"),
        (
            r"_ZN9wikipedia7article8print_toERSo",
            "wikipedia::article::print_to(std::ostream&)",
        ),
    ]);
}

#[test]
fn fidelity_itanium_std_substitutions() {
    check(&[
        (
            r"_ZNSt6vectorIiSaIiEE9push_backERKi",
            "std::vector<int, std::allocator<int> >::push_back(int const&)",
        ),
        (
            r"_ZNSt12basic_stringIcSt11char_traitsIcESaIcEE5clearEv",
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> >::clear()",
        ),
        (r"_ZNSaIcEC1Ev", "std::allocator<char>::allocator()"),
        (r"_ZNSs4sizeEv", "std::string::size()"),
        (
            r"_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc",
            "std::basic_ostream<char, std::char_traits<char> >& std::operator<< \
             <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)",
        ),
        (
            r"_Z6promptRSt6vectorIiSaIiEE",
            "prompt(std::vector<int, std::allocator<int> >&)",
        ),
        (r"_ZSt4sqrtf", "std::sqrt(float)"),
        (
            r"_ZNSt6vectorIiSaIiEEC1Ev",
            "std::vector<int, std::allocator<int> >::vector()",
        ),
    ]);
}

#[test]
fn fidelity_itanium_operators() {
    check(&[
        (r"_ZplRK1XS1_", "operator+(X const&, X const&)"),
        (r"_ZN1XplERKS_", "X::operator+(X const&)"),
        (r"_ZdlPv", "operator delete(void*)"),
        (r"_Znwm", "operator new(unsigned long)"),
    ]);
}

#[test]
fn fidelity_itanium_ctor_dtor() {
    check(&[
        (r"_ZN3FooC1Ev", "Foo::Foo()"),
        (r"_ZN3FooC2Ei", "Foo::Foo(int)"),
        (r"_ZN3FooD1Ev", "Foo::~Foo()"),
        (r"_ZN3FooD0Ev", "Foo::~Foo()"),
    ]);
}

#[test]
fn fidelity_itanium_templates() {
    check(&[
        (r"_Z4funcIiEvT_", "void func<int>(int)"),
        (r"_Z3maxIiET_S0_S0_", "int max<int>(int, int)"),
    ]);
}

#[test]
fn fidelity_itanium_vtable_typeinfo() {
    check(&[
        (r"_ZTV3Foo", "vtable for Foo"),
        (r"_ZTI3Foo", "typeinfo for Foo"),
        (r"_ZTS3Foo", "typeinfo name for Foo"),
    ]);
}

#[test]
fn fidelity_itanium_const_member_fns() {
    check(&[
        (r"_ZNK3Foo3barEv", "Foo::bar() const"),
        (r"_ZNK3Map4sizeEv", "Map::size() const"),
    ]);
}

#[test]
fn fidelity_rust_legacy() {
    // rustc-demangle semantics, trailing 17-char hash segment stripped.
    check(&[
        (
            r"_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
            "core::fmt::Formatter::pad",
        ),
        (
            r"_ZN4core3ptr13drop_in_place17h1234567890abcdefE",
            "core::ptr::drop_in_place",
        ),
        (
            r"_ZN3std2io5stdio6_print17h1234567890abcdefE",
            "std::io::stdio::_print",
        ),
        (
            r"_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$7reserve17h1234567890abcdefE",
            "alloc::raw_vec::RawVec<T,A>::reserve",
        ),
        (r"_ZN4testE", "test"),
    ]);
}

#[test]
fn fidelity_rust_v0() {
    // rustc-demangle v0 semantics (crate-disambiguator hash omitted).
    check(&[
        (r"_RNvC6_123foo3bar", "123foo::bar"),
        (r"_RNvCs1234_7mycrate3foo", "mycrate::foo"),
        (r"_RNvNtC8my_crate6module8function", "my_crate::module::function"),
        (r"_RINvNtC3std3mem8align_ofjE", "std::mem::align_of::<usize>"),
        (r"_RNvMC0INtC8my_crate3FooiE3bar", "<my_crate::Foo<isize>>::bar"),
    ]);
}

#[test]
fn fidelity_msvc_member_functions() {
    // Member functions carry `this`-pointer modifiers (`E` = __ptr64,
    // `F` = __unaligned, `I` = __restrict) between the access byte and the
    // cv byte. Skipping them is mandatory: otherwise the return type and the
    // parameter list are decoded one byte out of alignment.
    // Type spellings follow the crate's canonical form (`const char*`),
    // which is the same convention as the free-function cases above.
    check(&[
        (r"?foo@bar@@QEAAHXZ", "public: int __cdecl bar::foo(void)"),
        (
            r"?func@MyClass@@QEAAHH@Z",
            "public: int __cdecl MyClass::func(int)",
        ),
        (r"??0Foo@@QEAA@XZ", "public: __cdecl Foo::Foo(void)"),
        (r"??1Foo@@QEAA@XZ", "public: __cdecl Foo::~Foo(void)"),
        (
            r"?name@Person@@QEBAPEBDXZ",
            "public: const char* __cdecl Person::name(void) const",
        ),
        (
            r"?bar@Foo@ns@@QEAAXXZ",
            "public: void __cdecl ns::Foo::bar(void)",
        ),
        // Global/static data symbol (storage class `3`).
        (r"?x@@3HA", "int x"),
    ]);
}

#[test]
fn fidelity_d() {
    // D ABI: `F…Z<ret>` is a function type, the return type follows `Z`.
    check(&[
        (r"_D4main3fooFZv", "void main.foo()"),
        (r"_D3app4funcFiZi", "int app.func(int)"),
        (r"_D2ns5inner6methodFZv", "void ns.inner.method()"),
        (
            r"_D4core6memory2GC6mallocFmZPv",
            "void* core.memory.GC.malloc(ulong)",
        ),
    ]);
}

#[test]
fn fidelity_go() {
    // Go names are stored undecorated in the binary; the demangler routes
    // them through the Go path and normalises generic instantiations.
    check(&[
        (r"main.main", "main.main"),
        (r"main.(*Server).Start", "main.(*Server).Start"),
        (r"runtime.morestack", "runtime.morestack"),
        (r"encoding/json.Marshal", "encoding/json.Marshal"),
        (r"github.com/user/repo/pkg.Func", "github.com/user/repo/pkg.Func"),
        // Generic instantiation: the synthetic `go.shape.` qualifier is
        // stripped and the type arguments stay attached to the receiver.
        (
            r"main.Map[go.shape.int,go.shape.string].Get",
            "main.Map[int, string].Get",
        ),
        (r"slices.Sort[go.shape.int]", "slices.Sort[int]"),
    ]);
}

#[test]
fn fidelity_rust_legacy_escapes() {
    // `$LT$`/`$GT$`/`$u20$` escapes in a leading path segment.
    // NOTE: the length prefix must match the escaped segment exactly —
    // `_$LT$Test$u20$as$u20$core..fmt..Debug$GT$` is 41 characters. A wrong
    // prefix makes the symbol malformed, and rustc-demangle rejects it too.
    check(&[(
        r"_ZN41_$LT$Test$u20$as$u20$core..fmt..Debug$GT$3fmt17h1234567890abcdefE",
        "<Test as core::fmt::Debug>::fmt",
    )]);
}

#[test]
fn fidelity_itanium_internal_linkage() {
    // `_ZL` marks internal linkage. Verified against cpp_demangle: the length
    // prefix counts the identifier only, so `9static_fn` + `v` (void params).
    check(&[
        (r"_ZL9static_fnv", "static_fn()"),
        (r"_ZL3fooi", "foo(int)"),
    ]);
}

#[test]
fn fidelity_msvc() {
    // Cases where the crate's output matches llvm-undname semantics
    // (modulo the crate's canonical type spellings, e.g.
    // "unsigned long long" for unsigned __int64 and "const char*" spacing).
    check(&[
        (r"?foo@@YAHH@Z", "int __cdecl foo(int)"),
        (r"??2@YAPEAX_K@Z", "void* __cdecl operator new(unsigned long long)"),
        (r"??3@YAXPEAX@Z", "void __cdecl operator delete(void*)"),
        (r"??_7Foo@@6B@", "const Foo::`vftable'"),
        (r"?value@@YAHXZ", "int __cdecl value(void)"),
        (r"?print@@YAXPEBD@Z", "void __cdecl print(const char*)"),
    ]);
}

#[test]
fn fidelity_swift() {
    check(&[
        // `$s` (Swift 4.2+): module `4main`, name `3foo`, `y` empty-tuple
        // params, `y` empty-tuple result, `F` function entity.
        (r"$s4main3fooyyF", "main.foo() -> ()"),
        // `_T` (Swift 3): `F` function, module `4main`, name `3foo`,
        // type `F T_ T_` = () -> ().
        (r"_TF4main3fooFT_T_", "main.foo() -> ()"),
        // Same, with a `C` (class) context: main.Foo, method `3bar`,
        // `f` uncurried method type over `T_ T_`.
        (r"_TFC4main3Foo3barfT_T_", "main.Foo.bar() -> ()"),
        // `V` struct Foundation.Data, member `5count` of type `Si`
        // (Swift.Int), `v` variable, `g` getter.
        (
            r"$s10Foundation4DataV5countSivg",
            "Foundation.Data.count.getter : Swift.Int",
        ),
    ]);
}

/// Documented fidelity gaps: cases where the crate's current output is
/// semantically wrong or missing versus the reference demangler. Each entry
/// asserts the CORRECT expected string, so this test fails until the gap is
/// fixed; it is ignored so CI stays green. Comments give expected vs actual.
#[test]
#[ignore = "documents known demangling gaps; each assertion is the correct reference output"]
fn fidelity_known_gaps() {
    // Empty: every tracked gap has been closed. New gaps found against a
    // reference demangler go here (as the CORRECT expected string, with a
    // comment giving expected vs actual) so they are documented and visible
    // via `cargo test -- --ignored --nocapture` without turning CI red.
    //
    // Before adding an entry, VALIDATE the symbol against the reference
    // implementation — see `examples/gap_probe.rs`. Several "gaps" here were
    // once malformed test symbols where the reference produced exactly our
    // output; bending the code to match them would have broken correct code.
    report_gaps(&[]);
}
