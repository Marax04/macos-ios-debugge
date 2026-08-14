//! JNI escape sequences must be decoded, not passed through.
//!
//! A JNI native method name encodes the Java package, class and method with a
//! specific escape alphabet: `_1` for `_`, `_2` for `;`, `_3` for `[`,
//! `_0XXXX` for a UTF-16 code unit, and a doubled `__` introducing the
//! argument signature used to disambiguate overloads.
//!
//! Neither corpus contains a single `Java_` symbol (checked 2026-07-23), so no
//! corpus invariant exercises any of this. The rules are precise enough to
//! test directly, which is the right tool when the sample cannot reach the
//! behaviour.

fn demangled(s: &str) -> String {
    rustre_demangle::demangle(s)
        .unwrap_or_else(|| panic!("{s} must decode"))
        .demangled
}

/// The plain shape: package, class, method.
#[test]
fn plain_jni_name_decodes_to_a_java_path() {
    assert_eq!(demangled("Java_com_example_Foo_bar"), "com.example.Foo.bar");
}

/// `_1` is an escaped underscore, so the class here is `Foo_Bar`, not a
/// package boundary. Passing it through would split one identifier into two.
#[test]
fn escaped_underscore_does_not_split_an_identifier() {
    assert_eq!(
        demangled("Java_com_example_Foo_1Bar_baz"),
        "com.example.Foo_Bar.baz"
    );
}

/// `_0XXXX` is a UTF-16 code unit; `_00024` is `$`, which is how JNI spells a
/// nested class.
#[test]
fn utf16_escape_yields_the_nested_class_separator() {
    assert_eq!(demangled("Java_a_b_c_00024Inner_m"), "a.b.c$Inner.m");
}

/// A supplementary-plane character is spelled as a UTF-16 *surrogate pair* —
/// two `_0XXXX` escapes. Decoding each half independently fails, because a lone
/// surrogate (0xD800..=0xDFFF) is not a Unicode scalar value; the two must be
/// combined. `😀` (U+1F600) is `_0d83d_0de00`, and CJK ext-B `𤭢` (U+24B62)
/// is `_0d852_0df62`. Both used to decline entirely.
#[test]
fn supplementary_plane_surrogate_pairs_combine() {
    assert_eq!(demangled("Java_a_b_c_0d83d_0de00_m"), "a.b.c😀.m");
    assert_eq!(demangled("Java_pkg_Cls_0d852_0df62_m"), "pkg.Cls𤭢.m");
}

/// A doubled `__` introduces the argument signature, which is not part of the
/// name and must not leak into the output.
#[test]
fn overload_signature_is_not_part_of_the_name() {
    for s in [
        "Java_pkg_Cls_meth__Ljava_lang_String_2",
        "Java_pkg_Cls_meth___3I",
    ] {
        assert_eq!(demangled(s), "pkg.Cls.meth", "{s}");
    }
}

/// `Java_` alone is not a JNI name: the convention needs package/class/method
/// structure, and claiming a plain C function that merely starts with `Java_`
/// would be the same phantom-defect mistake `_R`, `_T` and `_D` made.
#[test]
fn bare_java_prefix_is_not_claimed() {
    assert!(rustre_demangle::demangle("Java_helper").is_none());
    assert!(rustre_demangle::demangle("Java_").is_none());
}

/// The escape that decodes to the separator itself.
///
/// `_0XXXX` takes exactly four hex digits, so U+005F — the underscore — is
/// spelled `_0005f`. This is the case that separates a single-pass decoder from
/// a two-pass one: decode the escapes, and the result contains a literal `_`
/// that a second splitting pass would read as a package boundary, turning one
/// identifier into two. The escapes already covered here cannot show that —
/// `_1` is handled by the splitter itself, and `_00024` (`$`), the surrogate
/// pairs and the CJK cases all produce characters that are not separators.
///
/// `_00041` ('A') is the control: same escape form, an ordinary character, so a
/// failure here means the four-hex-digit parse broke rather than the separator
/// handling.
#[test]
fn a_unicode_escape_may_decode_to_the_separator_character() {
    assert_eq!(demangled("Java_a_b_C_0005fx_m"), "a.b.C_x.m");
    assert_eq!(demangled("Java_a_b_C_00041x_m"), "a.b.CAx.m");

    // Non-ASCII escapes in the same four-digit form, BMP and beyond ASCII.
    assert_eq!(demangled("Java_a_b_C_000e9_m"), "a.b.Cé.m");
    assert_eq!(demangled("Java_a_b_C_04e2d_m"), "a.b.C中.m");
}

/// Two escaped underscores in a row must both survive. A decoder that consumed
/// the separator greedily would collapse them into one.
#[test]
fn consecutive_escaped_underscores_are_both_kept() {
    assert_eq!(demangled("Java_a_b_C_1_1x_m"), "a.b.C__x.m");
}
