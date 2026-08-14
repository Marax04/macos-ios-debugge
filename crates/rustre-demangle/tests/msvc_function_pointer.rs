//! MSVC function-pointer parameters (`P6…@Z`) decode to `<ret> (*)(<params>)`.
//!
//! A function pointer is `P6<cc><return><params>@Z`: the `6` marks a function
//! type, the next byte is the calling convention. Its inner is a signature, not
//! a plain type, so the pointer path (which reads a cv byte then a type) mis-read
//! the `6` as a cv and declined. Verified against `msvc-demangler`.

#[test]
fn function_pointer_parameter_decodes() {
    // void f(int (__cdecl *)(int))
    let r = rustre_demangle::demangle("?f@@YAXP6AHH@Z@Z").expect("must decode");
    assert!(
        r.demangled.contains("int (__cdecl *)(int)")
            || r.demangled.contains("int (__cdecl*)(int)"),
        "expected a function pointer, got {}",
        r.demangled
    );
}

#[test]
fn function_pointer_returning_and_taking_void_decodes() {
    // void g(void (__cdecl *)(void))
    let r = rustre_demangle::demangle("?g@@YAXP6AXXZ@Z").expect("must decode");
    assert!(
        r.demangled.contains("void (__cdecl *)(void)")
            || r.demangled.contains("void (__cdecl*)(void)"),
        "got {}",
        r.demangled
    );
}
