//! D decoding, on inputs that discriminate.
//!
//! D has no oracle among the crate's dependencies — unlike Itanium
//! (`cpp_demangle`), Rust (`rustc-demangle`) and MSVC (`msvc-demangler`) — but
//! it does have a documented grammar: `_D <QualifiedName> <Type>`, where a
//! function is `F <params> Z <return>`. That is enough to build cases a naive
//! implementation would get wrong, which a single `_D4main3fooFZv` cannot.
//!
//! The corpora contain no D symbols at all, so nothing here is reachable from
//! a corpus invariant.

fn demangled(s: &str) -> String {
    rustre_demangle::demangle(s)
        .unwrap_or_else(|| panic!("{s} must decode"))
        .demangled
}

/// One parameter is not enough to prove a parameter list is parsed: two are.
#[test]
fn parameter_lists_are_parsed_not_assumed() {
    assert_eq!(demangled("_D4main3fooFZv"), "void main.foo()");
    assert_eq!(
        demangled("_D3std5stdio7writelnFiZv"),
        "void std.stdio.writeln(int)"
    );
    assert_eq!(demangled("_D4main3barFiiZi"), "int main.bar(int, int)");
}

/// The return type sits after `Z`, so it must vary independently of the
/// parameters — an implementation that echoed the last type seen would pass
/// the `FZv` case and fail here.
#[test]
fn return_type_is_read_from_its_own_position() {
    assert_eq!(demangled("_D4main3bazFiZd"), "double main.baz(int)");
    assert_eq!(demangled("_D4main3fooFbZb"), "bool main.foo(bool)");
}

/// Every length-prefixed component of the qualified name must become a `.`,
/// the property that was broken in OCaml.
#[test]
fn nested_module_paths_are_fully_split() {
    assert_eq!(demangled("_D3pkg3sub2fnFZv"), "void pkg.sub.fn()");
}

/// Not every D symbol is a function; a variable has a bare type and no `F…Z`.
#[test]
fn variables_decode_without_a_signature() {
    let out = demangled("_D4main1xi");
    assert_eq!(out, "int main.x");
    assert!(!out.contains('('), "a variable must not gain a parameter list: {out}");
}

/// Compound type constructors, which the scalar cases above cannot exercise.
///
/// Each is a distinct D type prefix from the ABI spec, chosen so a wrong
/// implementation is visible: `P` (pointer) vs `A` (dynamic array) render
/// differently, nesting (`PP` -> `int**`) proves the constructor recurses
/// rather than emitting a single fixed `*`, and `x` (const) must wrap its
/// operand as `const(int)` rather than dropping the qualifier. Verified against
/// the documented grammar — D has no oracle, so these are the ground truth.
#[test]
fn compound_type_constructors_decode() {
    assert_eq!(demangled("_D4main3fooFPiZv"), "void main.foo(int*)");
    assert_eq!(demangled("_D4main3fooFAiZv"), "void main.foo(int[])");
    assert_eq!(demangled("_D4main3fooFPPiZv"), "void main.foo(int**)");
    assert_eq!(demangled("_D4main3fooFxiZv"), "void main.foo(const(int))");
}

/// A function pointer is `P` applied to a *function type*, not to a scalar, so
/// it must render `void function(int)` — one parameter — rather than a pointee
/// plus `*`.
///
/// This is the discriminating case because a `P` arm that always emits
/// `{inner}*` does not merely format it oddly: it consumes the `F` as if it
/// were a type code, emits the fabricated `?(F)*`, and then reads the function's
/// own parameters as *further parameters of the outer function*. The defect is
/// therefore visible in the parameter count, not just the spelling — which is
/// why the arity is asserted separately below.
///
/// Ground truth is the documented D ABI grammar (`P` `TypeFunction`); D has no
/// oracle. The delegate form `D`, already handled, is the same shape and is
/// asserted alongside so the two cannot drift apart.
#[test]
fn function_pointers_are_not_pointers_to_a_fabricated_type() {
    let out = demangled("_D4main3fooFPFiZvZv");
    assert_eq!(out, "void main.foo(void function(int))");
    assert!(!out.contains("?("), "no fabricated type code: {out}");
    assert_eq!(
        out.matches(',').count(),
        0,
        "the inner function's parameters must not leak into the outer list: {out}"
    );

    // Same shape, delegate rather than pointer.
    assert_eq!(
        demangled("_D4main3fooFDFiZvZv"),
        "void main.foo(void delegate(int))"
    );

    // A non-D linkage on the pointee is still a function pointer: `U` is
    // extern(C). This separates "recognises the byte F" from "recognises a
    // function type".
    assert_eq!(
        demangled("_D4main3fooFPUiZvZv"),
        "void main.foo(void function(int))"
    );
}

/// The D runtime's special symbols — `__ModuleInfo`, `__init`, `__vtbl`,
/// `__Class`, `__Interface` — end in a bare `Z`, which is the parameter-list
/// terminator and is *never* a valid type code. Reading it as a type produced a
/// fabricated `?(Z)` in front of an otherwise correctly decoded name.
///
/// This is asserted as an absence rather than a spelling on purpose. What is
/// certain from the grammar is that `Z` is not a type; what the "right" type
/// would be is not a question the grammar answers, so the honest fix removes
/// the invention rather than replacing it with a different guess. The test
/// therefore pins the decoded name and the absence of a fabricated type, not a
/// rendering nobody can source.
///
/// The variable case is the control: it proves the fix narrowed the `Z` path
/// specifically and did not simply stop typing data symbols.
#[test]
fn runtime_special_symbols_do_not_gain_a_fabricated_type() {
    for (sym, want) in [
        ("_D4main12__ModuleInfoZ", "main.__ModuleInfo"),
        ("_D4main1S6__initZ", "main.S.__init"),
        ("_D4main1C7__ClassZ", "main.C.__Class"),
        ("_D4main1C6__vtblZ", "main.C.__vtbl"),
        ("_D4main1I11__InterfaceZ", "main.I.__Interface"),
        ("_D3std5stdio12__ModuleInfoZ", "std.stdio.__ModuleInfo"),
    ] {
        let out = demangled(sym);
        assert_eq!(out, want, "{sym}");
        assert!(!out.contains("?("), "no fabricated type: {out}");
        assert!(!out.contains('Z'), "the trailing Z must be consumed: {out}");
        // Still a real demangling, not an echo of the input.
        assert_ne!(out, sym, "output must differ from input: {out}");
    }

    // Control: an ordinary data symbol still carries its type. Without this a
    // regression that dropped variable typing wholesale would pass everything
    // above.
    assert_eq!(demangled("_D4main1xi"), "int main.x");
    // Control: a function whose `Z` is a terminator mid-symbol is untouched.
    assert_eq!(demangled("_D4main3fooFiZv"), "void main.foo(int)");
}

/// `Nn` is the `noreturn` bottom type, and unlike its `N`-prefixed neighbours
/// `Ng` (inout) and `Nh` (`__vector`) it is complete on its own — it takes no
/// operand.
///
/// That is what makes the nested cases discriminating rather than the bare one.
/// `FZNn` alone would pass even for an implementation that consumed an operand,
/// because there is nothing after the return type to consume. Wrapping it in
/// `P` and `A` puts a `Z` immediately behind it: an arm that recursed into
/// `parse_type_code` would swallow the terminator and wreck the signature, so
/// the defect shows up as structural damage, not just a mis-spelled type.
///
/// Ground truth is the documented D ABI type-code table; D has no oracle.
///
/// Deliberately not asserted: `F` `Nn` … , where `N` sits in the function's
/// *attribute* position rather than the type position. The grammar resolves
/// that in favour of attributes, and the two readings are not distinguishable
/// here, so pinning a spelling for it would pin a guess.
#[test]
fn noreturn_is_a_complete_type_and_consumes_no_operand() {
    assert_eq!(demangled("_D4main3fooFZNn"), "noreturn main.foo()");

    for (sym, want) in [
        ("_D4main3fooFPNnZv", "void main.foo(noreturn*)"),
        ("_D4main3fooFANnZv", "void main.foo(noreturn[])"),
    ] {
        let out = demangled(sym);
        assert_eq!(out, want, "{sym}");
        assert!(!out.contains("?("), "no fabricated type code: {out}");
        assert!(
            out.starts_with("void "),
            "the `Z` terminator must survive, leaving the return readable: {out}"
        );
    }
}

/// `X` (typesafe variadic), `Y` (C-style variadic) and `Z` (non-variadic) are
/// all parameter-list *terminators*; the return type follows each of them.
///
/// `Y` is the discriminating one. A `Y` arm that records "variadic" but forgets
/// to stop reading parameters still produces a plausible-looking `…, ...)`, so
/// spelling alone does not separate right from wrong. What it actually does is
/// consume the *return type* as one more parameter and then find nothing left
/// to parse, fabricating a `?` return. So this asserts the return type and the
/// parameter count — the two places the defect is visible — and pins `X` beside
/// `Y` so the two terminators cannot diverge again.
///
/// Ground truth is the documented D ABI parameter-list grammar; D has no oracle.
#[test]
fn all_three_parameter_terminators_end_the_list() {
    // Z: plain, non-variadic.
    assert_eq!(demangled("_D4main3fooFiZv"), "void main.foo(int)");

    // X and Y must agree: same params, same return, both variadic.
    let x = demangled("_D4main3fooFiXv");
    let y = demangled("_D4main3fooFiYv");
    assert_eq!(x, "void main.foo(int, ...)");
    assert_eq!(y, x, "X and Y are both terminators and must not diverge");

    for out in [&x, &y] {
        assert!(
            out.starts_with("void "),
            "the return type follows the terminator and must be read: {out}"
        );
        assert!(!out.contains('?'), "no fabricated return type: {out}");
        assert!(
            !out.contains("void,"),
            "the return type must not be consumed as a parameter: {out}"
        );
    }

    // A non-void return proves the return is read from its own position rather
    // than defaulted, for the Y case specifically.
    assert_eq!(demangled("_D4main3fooFiYi"), "int main.foo(int, ...)");
}

/// `R` is excluded from the function-pointer linkage set on purpose: it is also
/// the type code for a reference, so `PRi` must stay a pointer to `ref int`
/// rather than being misread as an extern(C++) function type. Pinning this
/// keeps a later "completeness" edit from widening the set and silently
/// breaking it.
#[test]
fn pointer_to_reference_is_not_read_as_a_cpp_function_pointer() {
    let out = demangled("_D4main3fooFPRiZv");
    assert!(
        !out.contains("function"),
        "PRi is a pointer to a reference, not a function pointer: {out}"
    );
}

/// `k` is `uint`, a *basic type*, not a qualifier on the following type — so
/// `FkiZ` is two parameters, `(uint, int)`, not one qualified `int`. This is
/// the discriminating case that separates reading `k` as a type from reading
/// it as a modifier: the two produce different parameter counts.
#[test]
fn single_letter_basic_types_are_not_qualifiers() {
    assert_eq!(demangled("_D4main3fooFkiZv"), "void main.foo(uint, int)");
}

/// The complex and imaginary floating-point triples must both be complete.
///
/// D spells the imaginary types `o`/`p`/`j` (ifloat/idouble/ireal) and the
/// complex ones `q`/`r`/`c` (cfloat/cdouble/creal). The parser had all three
/// imaginary codes and only two of the three complex ones — an asymmetry
/// visible in its own table, which is what identified `c` as the gap without
/// any appeal to an oracle D has none of.
///
/// `c` previously fell through to the catch-all and rendered `?(c)`, which the
/// placeholder rule turns into a decline, so the symbol was reported as
/// `UnsupportedAbi`: honest about the missing capability, but missing it.
///
/// Asserted as a pair of complete triples rather than as a single new case,
/// because the defect was the *asymmetry*: a future edit that adds a type to
/// one row and forgets the other fails here.
#[test]
fn the_complex_and_imaginary_type_triples_are_both_complete() {
    for (code, want) in [
        // imaginary
        ("o", "ifloat"),
        ("p", "idouble"),
        ("j", "ireal"),
        // complex
        ("q", "cfloat"),
        ("r", "cdouble"),
        ("c", "creal"),
    ] {
        let sym = format!("_D4main3fooF{code}Zv");
        let got = demangled(&sym);
        assert_eq!(
            got,
            format!("void main.foo({want})"),
            "{sym} should render the parameter as {want}"
        );
        assert!(!got.contains('?'), "no placeholder for {code}: {got}");
    }

    // The plain triple, for contrast: `f`/`d`/`e` are the real ones and must be
    // unaffected by anything done to their complex counterparts.
    for (code, want) in [("f", "float"), ("d", "double"), ("e", "real")] {
        assert_eq!(
            demangled(&format!("_D4main3fooF{code}Zv")),
            format!("void main.foo({want})")
        );
    }
}

/// An `N`-prefixed **type** in parameter position must reach the type parser.
///
/// `parse_param_storage` maps `J`/`K`/`L`/`M` to out/ref/lazy/scope, each
/// advancing the cursor, and then has an `N` arm that deliberately advances
/// **nothing** — its comment reads "Could be func attrs or 'return'; consume
/// carefully". That no-op is load-bearing: `N` also begins three type codes,
/// `Ng` (inout), `Nh` (`__vector`) and `Nn` (noreturn), and consuming the `N`
/// as a storage class would corrupt every parameter that uses them.
///
/// The trap is that the arm *looks* unfinished. `DParamStorage` declares
/// `Return` and `In` variants that nothing in the crate ever constructs, and
/// the storage letters run `J K L M N` contiguously, so "wire `N` up to
/// `Return`" reads as the obvious completion — the same table-asymmetry
/// reasoning that correctly found the missing `creal`. Here it is wrong, and
/// the probe that settled it is exactly this test: with `N` consumed, all four
/// cases below break at once.
///
/// So the unused `Return`/`In` variants are dead API surface, not a missing
/// feature; D does not appear to mangle those storage classes at all.
#[test]
fn an_n_prefixed_type_in_parameter_position_is_not_eaten_as_a_storage_class() {
    for (sym, want) in [
        ("_D4main3fooFiNgiZv", "void main.foo(int, inout(int))"),
        ("_D4main3fooFiNhiZv", "void main.foo(int, __vector(int))"),
        ("_D4main3fooFiNnZv", "void main.foo(int, noreturn)"),
        // Nested one level down, so a fix that special-cased the top level only
        // would still fail here.
        ("_D4main3fooFiPNgiZv", "void main.foo(int, inout(int)*)"),
    ] {
        let got = demangled(sym);
        assert_eq!(got, want, "{sym}");
        assert!(!got.contains('?'), "no placeholder: {got}");
        // The storage-class spellings must not appear: these are types.
        for kw in ["return ", "in ", "out ", "ref ", "lazy ", "scope "] {
            assert!(
                !got.contains(kw),
                "{sym} gained a storage class it does not have: {got}"
            );
        }
    }

    // Control: the storage classes that *are* mangled still work, so this test
    // cannot pass by disabling storage-class parsing altogether.
    for (sym, want) in [
        ("_D4main3fooFJiZv", "void main.foo(out int)"),
        ("_D4main3fooFKiZv", "void main.foo(ref int)"),
        ("_D4main3fooFLiZv", "void main.foo(lazy int)"),
        ("_D4main3fooFMiZv", "void main.foo(scope int)"),
    ] {
        assert_eq!(demangled(sym), want, "{sym}");
    }
}

/// An `N`-prefixed type standing where an attribute could be must survive the
/// attribute loop intact.
///
/// `parse_func_attrs` consumes the `N`, reads the next byte, and on an
/// unrecognised letter backs up to hand the sequence back. It backed up by
/// **one** byte — undoing the letter but not the `N` — so the `N` was dropped
/// and the letter was re-read as a bare type code:
///
/// ```text
/// FNhiZv  ->  "ubyte, int"     instead of  "__vector(int)"
/// FNnZv   ->  "typeof(null)"   instead of  "noreturn"
/// ```
///
/// The first case is the worse one: it invents a *second parameter* as well as
/// mis-typing the first, so the damage shows in the arity, not just the
/// spelling.
///
/// It is decidable which reading is right, but *not* by reading the letters
/// off the parser's table — that is what this note used to do, and the table
/// was wrong. The decidable property is invariance: `Nh` and `Nn` render as
/// `__vector` and `noreturn` in every other position, so they cannot become
/// attributes merely by coming first. See `tests/d_attribute_positions.rs`,
/// which is where that argument now lives and which caught the third letter
/// this note's circular version had excused.
///
/// The controls matter in both directions: the same types already worked when
/// *not* first, which is what localises the defect to the attribute loop; and
/// the real attributes must keep parsing.
///
/// This note previously argued that `Ng` stays `@nogc` because "the D attribute
/// letters are `a b c d e f g i j k` — **measured from the parser's own
/// table**". That reasoning is circular: the table was the thing in question,
/// and it was wrong. `Ng` is `inout`, and it was the same position-dependence
/// defect this test exists for, one letter short of fixed. See
/// `tests/d_attribute_positions.rs`.
#[test]
fn an_n_prefixed_type_survives_the_attribute_loop() {
    // First parameter position — where the attribute loop runs.
    assert_eq!(
        demangled("_D4main3fooFNhiZv"),
        "void main.foo(__vector(int))"
    );
    assert_eq!(demangled("_D4main3fooFNnZv"), "void main.foo(noreturn)");

    // Same types elsewhere: unaffected before and after the fix.
    assert_eq!(
        demangled("_D4main3fooFiNhiZv"),
        "void main.foo(int, __vector(int))"
    );
    assert_eq!(demangled("_D4main3fooFiNnZv"), "void main.foo(int, noreturn)");
    assert_eq!(
        demangled("_D4main3fooFANhiZv"),
        "void main.foo(__vector(int)[])"
    );

    // Real attributes still parse, singly and stacked.
    assert_eq!(demangled("_D4main3fooFNaiZv"), "void main.foo(int) pure");
    assert_eq!(demangled("_D4main3fooFNbiZv"), "void main.foo(int) nothrow");
    assert_eq!(
        demangled("_D4main3fooFNaNbiZv"),
        "void main.foo(int) pure nothrow"
    );

    // `Ng` is a type constructor like `Nh` and `Nn`, so it belongs with them
    // above rather than with the attributes.
    assert_eq!(demangled("_D4main3fooFNgiZv"), "void main.foo(inout(int))");
}

/// A tuple's number is a COUNT OF TYPES, not the byte length of a name.
///
/// D's `TypeTuple` is `B` Number Arguments, where each argument is a type
/// parsed recursively. The implementation routed it through the qualified-name
/// parser, which reads `<len><chars>` — so the digits were taken as a byte
/// length and that many raw mangled characters were copied into the output.
///
/// Two distinct defects follow, and the second is the damaging one:
///
/// * the element types were never decoded — `Tuple!(iv)` rather than
///   `Tuple!(int, void)`, mangled letters reaching user-visible output;
/// * consuming N *characters* where N *types* were meant leaves the rest of the
///   tuple standing in parameter position, so `B2PiAk` decoded as a tuple
///   **plus a fabricated second parameter**. That is an arity error, which
///   compiles and reads as fact.
///
/// The cases below are discriminating in that they separate the two counts.
/// `B2ii` cannot: two types that are each one character make count and length
/// coincide, which is exactly the case anyone writes first.
#[test]
fn a_tuple_count_counts_types_not_characters() {
    // Multi-character element types: length and count diverge.
    assert_eq!(
        demangled("_D4main3fooFB2PiAkZv"),
        "void main.foo(Tuple!(int*, uint[]))",
        "B2 must take two TYPES (`Pi`, `Ak`), not two characters"
    );
    assert_eq!(
        demangled("_D4main3fooFB2PPiPAkZv"),
        "void main.foo(Tuple!(int**, uint[]*))"
    );

    // The element types must be decoded, not echoed.
    assert_eq!(demangled("_D4main3fooFB2ivZv"), "void main.foo(Tuple!(int, void))");
    assert_eq!(
        demangled("_D4main3fooFB3idfZv"),
        "void main.foo(Tuple!(int, double, float))"
    );

    // Arity control: what follows the declared number of types is a genuine
    // second parameter, and must stay one. This fails in BOTH directions — a
    // fix that consumed types greedily to the `Z` would also break it.
    assert_eq!(
        demangled("_D4main3fooFB2iiiZv"),
        "void main.foo(Tuple!(int, int), int)",
        "the third `i` is a second parameter, not a third tuple element"
    );
    assert_eq!(demangled("_D4main3fooFB1iiZv"), "void main.foo(Tuple!(int), int)");

    // Empty tuple: zero types consumed, so `i` remains a parameter.
    assert_eq!(demangled("_D4main3fooFB0iZv"), "void main.foo(Tuple!(), int)");

    // A declared count is attacker-controlled; an absurd one must terminate
    // rather than spin on a type code that consumes nothing.
    let _ = rustre_demangle::demangle("_D4main3fooFB999999999Zv");
}

/// A named type with no qualified name is not an empty type.
///
/// D's `C`/`S`/`E`/`T`/`I` codes introduce a length-prefixed qualified name.
/// When none followed, `parse_qualified` returned an empty vector and
/// `parts.join(".")` produced the **empty string**, which was then emitted as a
/// parameter:
///
/// ```text
/// _D4main3fooFiIZv  =>  void main.foo(int, )
/// _D4main3fooFIiZv  =>  void main.foo(, int)
/// _D4main3fooFIZv   =>  void main.foo()        (vanished entirely)
/// ```
///
/// This needs no oracle on three counts: `void main.foo(int, )` is not valid D;
/// an empty string is not the name of any type; and the second case *shifts the
/// real parameter into second place*, so the arity and the order are both
/// misreported. The third silently drops the parameter, which is the arity error
/// that no rendering shows.
///
/// The fix returns the placeholder so the existing D placeholder rule declines.
/// Declining beats inventing — the standing preference in this crate.
#[test]
fn a_named_type_without_a_name_declines_rather_than_rendering_empty() {
    // Every one of the five codes, alone and beside a real parameter, so a fix
    // applied to one arm cannot pass while the other four still fabricate.
    let mut checked = 0;
    for code in ['C', 'S', 'E', 'T', 'I'] {
        for shape in [
            format!("_D4main3fooF{code}Zv"),
            format!("_D4main3fooFi{code}Zv"),
            format!("_D4main3fooF{code}iZv"),
        ] {
            let got = rustre_demangle::demangle(&shape).map(|r| r.demangled);
            assert!(
                got.is_none(),
                "{shape}: a nameless `{code}` must decline, got {got:?}"
            );
            checked += 1;
        }
    }
    assert!(checked == 15, "expected 15 shapes, checked {checked}");

    // Controls — the same codes WITH a name must still decode, in every
    // position, or the fix has simply disabled named types.
    assert_eq!(demangled("_D4main3fooFC4main3FooZv"), "void main.foo(main.Foo)");
    assert_eq!(demangled("_D4main3fooFS4main3BarZv"), "void main.foo(main.Bar)");
    assert_eq!(demangled("_D4main3fooFE4main3ColZv"), "void main.foo(main.Col)");
    assert_eq!(
        demangled("_D4main3fooFC4main3FooC4main3BarZv"),
        "void main.foo(main.Foo, main.Bar)",
        "two named parameters: the first must not swallow the second"
    );
    assert_eq!(
        demangled("_D4main3fooFPC4main3FooZv"),
        "void main.foo(main.Foo*)"
    );
    assert_eq!(
        demangled("_D4main3fooFAS4main3BarZv"),
        "void main.foo(main.Bar[])"
    );

    // And an unrelated single-letter type in the same position is untouched:
    // `t` really is `ushort`, so the fix must not have widened into a rule
    // against single letters.
    assert_eq!(demangled("_D4main3fooFtZv"), "void main.foo(ushort)");
}

/// A required Number is required: `B` and `B0` must not mean the same thing.
///
/// D's static array is `G` Number Type and its tuple is `B` Number Arguments.
/// Both read the Number with `parse_length().unwrap_or(0)`, so a *missing*
/// number silently became zero:
///
/// ```text
/// _D4main3fooFGiZv  =>  void main.foo(int[0])     same as G0i
/// _D4main3fooFBZv   =>  void main.foo(Tuple!())   same as B0
/// ```
///
/// `int[0]` is an invented array size — the input never stated a length. Worse
/// than the wrong value is the collapse: a well-formed symbol and a malformed
/// one produced **identical output**, so the rendering could not be trusted to
/// reflect what was actually mangled.
///
/// The discriminating pair is the whole test. Checking only `G3i` proves
/// nothing, and checking only `Gi` cannot tell a correct implementation from one
/// that declines every static array.
#[test]
fn a_missing_required_number_is_not_zero() {
    // Malformed: the Number is absent.
    for shape in [
        "_D4main3fooFGiZv",
        "_D4main3fooFBZv",
        "_D4main3fooFiGiZv",
        "_D4main3fooFiBZv",
        // Nested: the missing number is inside a pointer/array.
        "_D4main3fooFPGiZv",
        "_D4main3fooFAGiZv",
    ] {
        let got = rustre_demangle::demangle(shape).map(|r| r.demangled);
        assert!(got.is_none(), "{shape} is malformed and must decline, got {got:?}");
    }

    // Well-formed with an explicit zero — this is what the buggy code was
    // pretending to see, and it must still decode.
    assert_eq!(demangled("_D4main3fooFG0iZv"), "void main.foo(int[0])");
    assert_eq!(demangled("_D4main3fooFB0Zv"), "void main.foo(Tuple!())");

    // Well-formed with a non-zero number, in several positions.
    assert_eq!(demangled("_D4main3fooFG3iZv"), "void main.foo(int[3])");
    assert_eq!(demangled("_D4main3fooFG12AyaZv"), "void main.foo(immutable(char)[][12])");
    assert_eq!(demangled("_D4main3fooFPG4iZv"), "void main.foo(int[4]*)");
    assert_eq!(demangled("_D4main3fooFB2iiZv"), "void main.foo(Tuple!(int, int))");
    assert_eq!(
        demangled("_D4main3fooFiG3iZv"),
        "void main.foo(int, int[3])",
        "a static array after another parameter"
    );
}

/// Distinct D type codes must not decode to the same thing.
///
/// Injectivity is the general form of the three defects fixed in iters 60-62: a
/// silent default made a malformed input indistinguishable from a well-formed
/// one. `Gi` and `G0i` both gave `int[0]`; `B` and `B0` both gave `Tuple!()`;
/// GHC's `Z1T` and `Z0T` both gave `()`. In every case the tell was a
/// *collision*, and in every case I spotted it by eye. This asserts it.
///
/// Two inputs sharing an output are not automatically wrong — a genuine alias
/// would collide legitimately — so a failure here is a finding to read, not a
/// verdict. But the D type grammar has no aliases at this level, so the
/// expected count is zero.
#[test]
fn distinct_type_codes_decode_distinctly() {
    use std::collections::HashMap;

    let basics: Vec<String> = (0x21u8..0x7f).map(|b| (b as char).to_string()).collect();
    // Type constructors and qualifiers, each combined with every basic byte.
    let ctors = [
        "P", "A", "R", "O", "x", "y", "N", "G", "B", "H", "D", "C", "S", "E", "T", "I", "F",
    ];
    let mut codes: Vec<String> = basics.clone();
    for c in &ctors {
        for b in &basics {
            codes.push(format!("{c}{b}"));
        }
    }

    let mut by_output: HashMap<String, Vec<String>> = HashMap::new();
    let mut decoded = 0;
    for code in &codes {
        let sym = format!("_D4main3fooF{code}Zv");
        if let Some(r) = rustre_demangle::demangle(&sym) {
            decoded += 1;
            by_output.entry(r.demangled).or_default().push(code.clone());
        }
    }

    // Vacuity: most combinations are invalid D and must decline, but a healthy
    // sweep still decodes a large minority. If this drops, the sweep has stopped
    // exercising the parser rather than the parser having become injective.
    assert!(
        decoded > 150,
        "vacuous: only {decoded} of {} codes decoded",
        codes.len()
    );

    let collisions: Vec<_> = by_output.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        collisions.is_empty(),
        "{} outputs reachable from more than one type code, e.g. {:#?}",
        collisions.len(),
        collisions.iter().take(3).collect::<Vec<_>>()
    );
}

/// The function-attribute table is complete, distinct, and closed.
///
/// `N<letter>` introduces a function attribute. Iter 52 found the recovery path
/// for a *non*-attribute letter was broken (`Nh`, `Nn` are types, not
/// attributes, and the loop rewound by one byte instead of two). This pins the
/// table itself: every documented letter renders its own attribute, the two
/// type-valued letters stay types, and every other letter declines rather than
/// being quietly absorbed.
#[test]
fn the_function_attribute_table_is_complete_and_closed() {
    let attrs = [
        ('a', "pure"),
        ('b', "nothrow"),
        ('c', "ref"),
        ('d', "@property"),
        ('e', "@trusted"),
        ('f', "@safe"),
        ('i', "@nogc"),
        ('j', "return"),
        ('k', "scope"),
        ('m', "@live"),
    ];

    let mut seen = std::collections::HashSet::new();
    for (letter, want) in attrs {
        let out = demangled(&format!("_D4main3fooFN{letter}iZv"));
        assert_eq!(
            out, format!("void main.foo(int) {want}"),
            "N{letter} must be the {want} attribute"
        );
        assert!(seen.insert(want), "two letters render the same attribute: {want}");
    }
    assert_eq!(seen.len(), 10, "expected 10 distinct attributes");

    // The three letters that are TYPES in this position, not attributes. `Nh`
    // and `Nn` were the iter-52 defect; `Ng` was the same defect left in place
    // because the table it was checked against was itself wrong. Kept here so
    // the table and the exceptions are stated together.
    assert_eq!(demangled("_D4main3fooFNgiZv"), "void main.foo(inout(int))");
    assert_eq!(demangled("_D4main3fooFNhiZv"), "void main.foo(__vector(int))");
    assert_eq!(demangled("_D4main3fooFNniZv"), "void main.foo(noreturn, int)");

    // Closed: no other letter may be absorbed silently.
    for letter in "lopqrstuvwxyz".chars() {
        let sym = format!("_D4main3fooFN{letter}iZv");
        assert!(
            rustre_demangle::demangle(&sym).is_none(),
            "N{letter} is not an attribute and must decline"
        );
    }
}

/// D back-references are unimplemented, and decline rather than fabricate.
///
/// `Q<n>` refers to a previously mangled name or type. `d_demangler` has no `Q`
/// arm at all — the construct needs a real D binary to verify an expansion
/// against, which this crate does not have, so it was deliberately left alone.
///
/// What *is* decidable without an oracle is the failure mode. An unimplemented
/// construct may decline; it may not invent. This pins that, in every position a
/// `Q` can occupy: bare, alone, before and after a real parameter, nested under a
/// pointer and an array, and in the qualified-name path.
///
/// The controls matter as much: the same shapes with a real type must still
/// decode, or a future partial `Q` implementation could satisfy the declines by
/// breaking D types generally.
///
/// This is the last unprobed construct in the D grammar. Everything else has a
/// test: type codes (injective over 1692 inputs), the attribute table (complete
/// and closed), named types, required Numbers, tuples, delegates, function
/// pointers, linkages, associative arrays, the complex triple, `noreturn`,
/// `__vector`, variadic terminators and module paths.
#[test]
fn d_back_references_decline_rather_than_fabricating() {
    for sym in [
        "_D4main3fooFQdZv",
        "_D4main3fooFQZv",
        "_D4main3fooFiQdZv",
        "_D4main3fooFQdiZv",
        "_D4main3fooFPQdZv",
        "_D4main3fooFAQdZv",
        "_D4mainQd3fooFZv",
        "_D4main3fooQdFZv",
    ] {
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert!(
            got.is_none(),
            "{sym} uses an unimplemented back-reference and must decline, got {got:?}"
        );
    }

    // Controls: the same positions with a real type still decode.
    assert_eq!(demangled("_D4main3fooFiZv"), "void main.foo(int)");
    assert_eq!(demangled("_D4main3fooFPiZv"), "void main.foo(int*)");
    assert_eq!(demangled("_D4main3fooFAiZv"), "void main.foo(int[])");
    assert_eq!(demangled("_D4main3fooFiiZv"), "void main.foo(int, int)");
}
