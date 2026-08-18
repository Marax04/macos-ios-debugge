//! Grammar-driven differential testing of the MSVC demangler against
//! `msvc-demangler`, on the model of `differential_proptest.rs` (Itanium).
//!
//! A fixed corpus only covers the symbols someone thought to write down; this
//! suite *generates* well-formed MSVC decorated names from the grammar and
//! compares each against the reference, exploring access × storage ×
//! cv-qualifier × pointer-depth combinations no hand-written list would
//! enumerate. Divergences are real by construction; symbols the reference
//! rejects are skipped, and an anti-vacuity guard asserts the generated
//! shapes are overwhelmingly accepted.

mod msvc_oracle;
use msvc_oracle::{compare, reference};
use proptest::prelude::*;

/// Convert an RNG value the caller has already reduced with `%` to `usize`.
///
/// The reduction happens in `u64`, so the value reaching this function is small
/// by construction; `try_from` states that in code rather than leaving a
/// truncating `as usize` cast to be trusted.
fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Pick an index into a `len`-element table from an RNG value, reducing in
/// `u64` so no value is ever truncated on the way to `usize`.
fn pick(v: u64, len: usize) -> usize {
    let modulus = u64::try_from(len).unwrap_or(u64::MAX).max(1);
    to_usize(v % modulus)
}


/// Builtin MSVC type codes usable as parameters and return types.
const TYPE_CODES: &[&str] =
    &["C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N", "O", "_N", "_J", "_K", "_W"];

/// An MSVC identifier fragment (no length prefix in this ABI).
fn ident() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_]{0,9}".prop_map(|s| s)
}

/// A parameter/return type: a builtin, optionally behind a pointer or
/// reference with a cv-qualified pointee (`PEA`/`PEB` = `T*`/`const T*`,
/// `AEA`/`AEB` = `T&`/`const T&`).
fn param_type() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            4 => prop::sample::select(TYPE_CODES).prop_map(str::to_owned),
            // `void` base — only valid behind a pointer, enforced below.
            1 => Just("X".to_owned()),
            // Class/struct types: `V<name>@@` / `U<name>@@`.
            1 => ("[VU]", "[A-Z][a-zA-Z0-9_]{0,7}").prop_map(|(k, n)| format!("{k}{n}@@")),
        ],
        prop::sample::select(vec!["", "PEA", "PEB", "AEA", "AEB"]),
    )
        .prop_map(|(base, wrap)| {
            if base == "X" && wrap.is_empty() {
                // Bare `void` is not a parameter type; wrap it.
                format!("PEA{base}")
            } else {
                format!("{wrap}{base}")
            }
        })
}

/// Render a parameter list: `X` for empty (MSVC's `(void)`), otherwise the
/// types followed by the `@` list terminator; `Z` closes the function.
fn param_list(params: &[String]) -> String {
    if params.is_empty() {
        "XZ".to_owned()
    } else {
        format!("{}@Z", params.concat())
    }
}

/// Anti-vacuity guard: `compare` returns `Ok` when the reference rejects a
/// symbol, so degraded generators would make every case a silent skip and the
/// suite would pass while testing nothing. Assert the generated shapes are
/// overwhelmingly accepted by the reference.
#[test]
fn generators_produce_symbols_the_reference_accepts() {
    let mut state = 0x51ab_c0de_u64;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    let mut accepted = 0usize;
    let mut total = 0usize;
    for _ in 0..300 {
        let len = to_usize(next() % 6 + 3);
        let name: String = (0..len)
            .map(|_| char::from(b'a' + u8::try_from(next() % 26).unwrap_or(0)))
            .collect();
        let ty = TYPE_CODES[pick(next(), TYPE_CODES.len())];
        for sym in [
            format!("?{name}@@YA{ty}{ty}@Z"),
            format!("?{name}@Cls@@QEAA{ty}XZ"),
            format!("?{name}@Cls@@SA{ty}{ty}@Z"),
            format!("?{name}@@3{ty}A"),
            format!("??0{name}@@QEAA@{ty}@Z"),
        ] {
            total += 1;
            if reference(&sym).is_some() {
                accepted += 1;
            }
        }
    }

    println!("msvc generator acceptance: {accepted}/{total}");
    assert!(
        accepted * 100 >= total * 95,
        "MSVC generators produce symbols the reference rejects \
         ({accepted}/{total}); the differential suite would be silently vacuous"
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1500, ..ProptestConfig::default() })]

    /// Free functions: `?<name>@@YA<ret><params>`.
    #[test]
    fn differential_generated_free_functions(
        name in ident(),
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 0..4),
    ) {
        let sym = format!("?{name}@@YA{ret}{}", param_list(&params));
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Member functions: access (private/protected/public) × constness of
    /// `this` × nested class path. The access/cv run is exactly where both
    /// historical byte-misalignment bugs lived.
    #[test]
    fn differential_generated_member_functions(
        name in ident(),
        classes in prop::collection::vec(ident(), 1..3),
        access in prop::sample::select(vec!['A', 'I', 'Q']),
        this_cv in prop::sample::select(vec!['A', 'B']),
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 0..3),
    ) {
        let path = classes.join("@");
        let sym = format!(
            "?{name}@{path}@@{access}E{this_cv}A{ret}{}",
            param_list(&params)
        );
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Static and virtual member functions: static members carry no `this`
    /// cv byte (`SA<ret>…`), virtual ones do (`UEAA<ret>…`) — the asymmetry
    /// the corpus-based suite caught as a real bug.
    #[test]
    fn differential_generated_static_and_virtual_members(
        name in ident(),
        cls in ident(),
        is_static in prop::bool::ANY,
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 0..3),
    ) {
        let sym = if is_static {
            format!("?{name}@{cls}@@SA{ret}{}", param_list(&params))
        } else {
            format!("?{name}@{cls}@@UEAA{ret}{}", param_list(&params))
        };
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Constructors and destructors: `??0`/`??1` with the class name repeated
    /// through the backref machinery in parameters when present.
    #[test]
    fn differential_generated_ctor_dtor(
        cls in ident(),
        is_ctor in prop::bool::ANY,
        params in prop::collection::vec(param_type(), 0..3),
    ) {
        let sym = if is_ctor {
            format!("??0{cls}@@QEAA@{}", param_list(&params))
        } else {
            format!("??1{cls}@@QEAA@XZ")
        };
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Operators on classes: `??<code><cls>@@QEAA<ret><params>`, covering the
    /// arithmetic/comparison/assignment operator code table.
    #[test]
    fn differential_generated_operators(
        cls in ident(),
        op in prop::sample::select(vec![
            "4", "5", "6", "7", "8", "9", "A", "D", "E", "F", "G", "H", "I",
            "K", "L", "M", "N", "O", "P", "R", "S", "T", "U", "Y", "Z",
        ]),
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 0..3),
    ) {
        let sym = format!("??{op}{cls}@@QEAA{ret}{}", param_list(&params));
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Templates: function templates (`??$name@<args>@@YA…`) and members of
    /// class templates (`?method@?$cls@<args>@ns@@…`).
    #[test]
    fn differential_generated_templates(
        name in ident(),
        cls in ident(),
        targs in prop::collection::vec(
            prop_oneof![
                prop::sample::select(TYPE_CODES).prop_map(str::to_owned),
                // Integer args: single digit `$0<d>` = d+1, hex `$0<A-P>+@`,
                // negative `$0?<…>`.
                (0u8..10).prop_map(|d| format!("$0{d}")),
                (0u8..16).prop_map(|h| format!("$0{}@", char::from(b'A' + h))),
                (0u8..10).prop_map(|d| format!("$0?{d}")),
            ],
            1..3,
        ),
        is_function_template in prop::bool::ANY,
        ret in prop::sample::select(TYPE_CODES),
        params in prop::collection::vec(param_type(), 0..3),
    ) {
        let sym = if is_function_template {
            format!("??${name}@{}@@YA{ret}{}", targs.concat(), param_list(&params))
        } else {
            format!(
                "?{name}@?${cls}@{}@ns@@QEAA{ret}{}",
                targs.concat(),
                param_list(&params)
            )
        };
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }

    /// Data symbols: globals (`3`) and static members (`0`/`1`/`2`), with
    /// plain and pointer types and the trailing cv byte.
    #[test]
    fn differential_generated_data_symbols(
        name in ident(),
        cls in ident(),
        member_access in prop::sample::select(vec!['0', '1', '2']),
        is_member in prop::bool::ANY,
        ty in param_type(),
        cv in prop::sample::select(vec!['A', 'B']),
    ) {
        let sym = if is_member {
            format!("?{name}@{cls}@@{member_access}{ty}{cv}")
        } else {
            format!("?{name}@@3{ty}{cv}")
        };
        if let Err(e) = compare(&sym) {
            prop_assert!(false, "divergence:\n{}", e);
        }
    }
}
