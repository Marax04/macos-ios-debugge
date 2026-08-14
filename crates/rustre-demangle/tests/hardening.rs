//! Regression tests for panics/DoS reachable from adversarial symbol input.
//! Each case previously crashed (slice panic, integer overflow, or stack
//! overflow) before the 2026-07-20 hardening pass.

use rustre_demangle::cpp_demangler::{demangle_itanium, ItaniumParser};
use rustre_demangle::go_demangler::decode_go_symbol;
use rustre_demangle::msvc_demangler::MsvcDemangler;

#[test]
fn go_bracket_before_open_does_not_panic() {
    // `]` before `[` used to invert the slice range in split_generic_args.
    let _ = decode_go_symbol("x.a]b[c", true);
    let _ = decode_go_symbol("x.a]b[c", false);
    let _ = decode_go_symbol("p.]x[", true);
}

#[test]
fn d_deep_pointer_chain_does_not_overflow_stack() {
    // parse_type_code recursed once per `P` with no depth guard.
    let sym = format!("_D3foo{}", "P".repeat(200_000));
    let mut d = rustre_demangle::d_demangler::DDemangler::new(&sym);
    let _ = d.demangle();
}

#[test]
fn itanium_huge_length_prefix_does_not_panic() {
    // u64::MAX length wrapped the `pos + len` bounds check into a slice panic.
    assert!(demangle_itanium("_Z18446744073709551615").is_err());
    // Overflowing digit accumulation must error, not wrap/panic.
    assert!(demangle_itanium(&format!("_Z{}", "9".repeat(40))).is_err());
}

#[test]
fn itanium_deep_pointer_chain_does_not_overflow_stack() {
    let sym = format!("_Z1f{}i", "P".repeat(500_000));
    let _ = demangle_itanium(&sym);
}

#[test]
fn itanium_deep_local_name_chain_does_not_overflow_stack() {
    let input = "Z".repeat(500_000);
    let mut parser = ItaniumParser::new(input.as_bytes());
    let _ = parser.parse_mangled();
}

#[test]
fn msvc_deep_pointer_chain_does_not_overflow_stack() {
    let encoded = format!("{}H", "PA".repeat(500_000));
    let _ = MsvcDemangler::decode_msvc_type(&encoded);
}

#[test]
fn itanium_substitutions_resolve() {
    // `S0_` back-reference to the second substitution candidate; before the
    // fix substitution tables were never populated and this fell back to the
    // literal "S0_" placeholder in the ItaniumParser path.
    let mut parser = ItaniumParser::new(b"N3foo3barES0_");
    let parsed = parser.parse_mangled().expect("parse");
    assert!(
        !parsed.to_string_repr().contains("S0_"),
        "substitution left unresolved: {}",
        parsed.to_string_repr()
    );
}

#[test]
fn dispatcher_survives_adversarial_corpus() {
    // Deterministic pseudo-random garbage through the top-level entry point.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut lcg = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    for _ in 0..500 {
        let len = (lcg() % 48) as usize + 1;
        let body: String = (0..len)
            .map(|_| char::from(u8::try_from(lcg() % 94 + 33).unwrap_or(b'!')))
            .collect();
        for prefix in ["_Z", "?", "_R", "_D", "$s", ""] {
            let _ = rustre_demangle::demangle(&format!("{prefix}{body}"));
        }
    }
}
