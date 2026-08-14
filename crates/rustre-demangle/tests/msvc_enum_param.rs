//! MSVC enum parameters (`W4…`) decode to `enum <name>`.
//!
//! An enum type is `W<underlying-type-digit><qualified-name>`. The digit
//! (0..=7) selects the underlying integer type and is not rendered; the name is
//! prefixed with `enum`. The decoder shared the `U`/`V` (struct/class) path,
//! which does not consume the digit, so the name parser started at `4Color@1@`
//! and declined the whole symbol. Verified against `msvc-demangler`:
//! `void __cdecl ns::fn(enum ns::Color)`. The `@1@` is a name back-reference to
//! the enclosing `ns`, so this also exercises that the enum's name resolves it.

#[test]
fn enum_parameter_decodes_with_the_enum_keyword() {
    let r = rustre_demangle::demangle("?fn@ns@@YAXW4Color@1@@Z").expect("must decode");
    assert_eq!(r.demangled, "void __cdecl ns::fn(enum ns::Color)");
}
