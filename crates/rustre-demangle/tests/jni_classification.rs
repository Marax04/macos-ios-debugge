//! JNI symbols must classify as Java.
//!
//! `MangleLanguage::Java` existed as a variant that `SymbolClassifier::classify`
//! could never return, while the crate decoded `Java_pkg_Class_method` symbols
//! happily. The visible consequence was on public API:
//! `DemangleFilter::filter_by_language(syms, MangleLanguage::Java)` returned
//! nothing regardless of input.
//!
//! The corpora contain no `Java_` symbols, so this is probed directly.

use rustre_demangle::{DemangleFilter, MangleLanguage, SymbolClassifier};

/// A JNI native method classifies as Java and still decodes.
#[test]
fn jni_symbols_classify_as_java() {
    for s in [
        "Java_com_example_Foo_bar",
        "Java_org_gnome_Widget_show",
        "JNICALL_Java_com_example_Foo_baz",
    ] {
        assert_eq!(
            SymbolClassifier::classify(s),
            MangleLanguage::Java,
            "{s} is a JNI native method"
        );
        assert!(
            rustre_demangle::demangle(s).is_some(),
            "{s} must still decode"
        );
    }
}

/// The filter that motivated this must now work.
#[test]
fn filter_by_language_finds_java_symbols() {
    let syms = vec![
        "Java_com_example_Foo_bar".to_owned(),
        "_Z3fooi".to_owned(),
        "main".to_owned(),
    ];
    let filtered = DemangleFilter::filter_by_language(&syms, MangleLanguage::Java);
    assert_eq!(filtered, vec!["Java_com_example_Foo_bar".to_owned()]);
}

/// Restraint in the other direction: `Java_` alone is not enough. The detector
/// requires a further `_` (package/class/method structure), so a C function
/// merely starting with `Java_` stays unclassified — the `_R`/`_T`/`_D` lesson
/// applied before the fact rather than after.
#[test]
fn bare_java_prefix_is_not_classified() {
    for s in ["Java_helper", "Java_", "Javascript"] {
        assert_ne!(
            SymbolClassifier::classify(s),
            MangleLanguage::Java,
            "{s} lacks JNI structure"
        );
    }
}
