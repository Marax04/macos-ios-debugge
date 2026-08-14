//! MSVC pointer-to-array data (`PAY…`) decodes to a declarator `T (*name)[d]`.
//!
//! An array is `Y<ndims><dim…>`, each a standard MSVC number (`9` → 10,
//! `BE@` → 20). Behind a pointer it renders as a declarator, not a suffix, so
//! the variable name is woven into the `(*)` slot: `?arr@@3PAY09HA` →
//! `int (*arr)[10]`. The old pointer path read `Y` as a type and, finding no
//! such type, declined the whole symbol. Verified against `msvc-demangler`.

#[test]
fn pointer_to_array_of_ten_ints_decodes() {
    let r = rustre_demangle::demangle("?arr@@3PAY09HA").expect("must decode");
    assert_eq!(r.demangled, "int (*arr)[10]");
}

#[test]
fn pointer_to_array_of_twenty_ints_decodes_multibyte_dim() {
    // The dimension 20 is the multi-byte number form `BE@`, exercising the
    // non-digit branch of the number parser.
    let r = rustre_demangle::demangle("?arr@@3PAY0BE@HA").expect("must decode");
    assert_eq!(r.demangled, "int (*arr)[20]");
}
