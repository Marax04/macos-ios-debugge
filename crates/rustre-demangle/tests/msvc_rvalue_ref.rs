//! MSVC rvalue-reference parameters (`$$Q…`) decode to `&&`.
//!
//! `$$Q` is the rvalue-reference type shorthand. Like a pointer, its referent
//! carries an optional `__ptr64`/`__ptr32` marker (`E`/`F`) before the cv byte,
//! so `$$QEAH` is `E` (ptr64) + `A` (no cv) + `H` (int). The decoder consumed
//! only one byte after `$$Q`, mis-reading the marker as the cv and the cv as a
//! stray lvalue reference, which declined the whole symbol. Verified against
//! `msvc-demangler`: `void __cdecl h(int &&)`.

#[test]
fn rvalue_reference_parameter_decodes() {
    let r = rustre_demangle::demangle("?h@@YAX$$QEAH@Z").expect("must decode");
    assert!(
        r.demangled.contains("int&&") || r.demangled.contains("int &&"),
        "expected an rvalue reference, got {}",
        r.demangled
    );
}
