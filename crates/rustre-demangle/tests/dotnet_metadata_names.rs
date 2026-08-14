//! .NET metadata names, which are not symbols and not C identifiers.
//!
//! Motivation is real: `sample5_cs.exe` and `sample10_cs.exe` in the corpus
//! contain Roslyn compiler-generated names — `<>c`, `<Module>`,
//! `<PopCount>g__SoftwareFallback|22_0`, `<DetermineLibraryNameVariations>d__4`.
//!
//! They are **not** a corpus, deliberately. The names live in a metadata heap
//! whose entries are not NUL-separated, so `strings` merges adjacent ones and
//! yields entries with a stray leading or trailing character
//! (`<FormatInt32>g__FormatInt32Slow|21_0L` runs into the next name). Checking
//! in that extraction would be corpus-scale hand-construction error, so the
//! inputs below are derived from the documented Roslyn generated-name grammar
//! instead — the crate's own rule of starting from the grammar, not the corpus.
//! Building the real corpus needs a CLI metadata reader.
//!
//! Two defects, one root cause: the classifier's rules came from ELF/PE symbol
//! tables, and .NET names break them.

use rustre_demangle::decline::{decline_reason, is_dotnet_metadata_name, DeclineReason};

/// The Roslyn forms: enclosing member in angle brackets, then a kind character
/// (`b` lambda, `d` state machine, `g` local function, `k` backing field,
/// `c` display class).
#[test]
fn generated_names_are_classified_not_parked() {
    for s in [
        "<Module>",
        "<PrivateImplementationDetails>",
        "<>c",
        "<>c__DisplayClass0_0",
        "<Main>b__0_0",
        "<DetermineLibraryNameVariations>d__4",
        "<PopCount>g__SoftwareFallback|22_0",
        "<Prop>k__BackingField",
    ] {
        assert_eq!(decline_reason(s), DeclineReason::DotNetMetadata, "{s}");
    }
}

/// The discriminating pair, and the point of the whole change.
///
/// `.ctor` was not merely unclassified — it was reported as a *linker section*,
/// an affirmatively wrong answer. The fix must separate the two constructor
/// names from sections without weakening the leading-dot rule, so both halves
/// are asserted together: deleting or loosening that rule fails the second
/// half, and dropping the special case fails the first.
#[test]
fn constructors_are_not_sections_and_sections_still_are() {
    for s in [".ctor", ".cctor"] {
        assert_eq!(decline_reason(s), DeclineReason::DotNetMetadata, "{s} is a CLR method");
    }
    for s in [".text", ".bss", ".rdata", ".CRT$XCA", ".pdata.unlikely._ZSt9terminatev"] {
        assert_eq!(decline_reason(s), DeclineReason::LinkerSection, "{s} is a section");
    }
}

/// The bracket rule is narrow: a malformed string is not a generated name, and
/// must stay `Unknown` rather than be absorbed into a correct-decline category
/// where it would stop being visible.
#[test]
fn the_predicate_rejects_malformed_bracket_forms() {
    for s in ["<", "<>", "<abc", "<a b>c", "<>1x", "<Main]b__0", "plain", ""] {
        assert!(!is_dotnet_metadata_name(s), "{s:?} should not read as a .NET name");
        assert_ne!(decline_reason(s), DeclineReason::DotNetMetadata, "{s:?}");
    }
}

/// Ordinary CLR members carry no decoration at all, so they are plain C
/// identifiers and must stay that way — the new rule must not widen to every
/// .NET-looking name.
#[test]
fn undecorated_clr_members_stay_undecorated_c() {
    for s in ["get_Length", "set_Item", "Main", "ToString", "op_Addition"] {
        assert_eq!(decline_reason(s), DeclineReason::UndecoratedC, "{s}");
    }
}

/// A correct decline must never shadow a defect: anything carrying an ABI
/// sigil stays `UnsupportedAbi`, even when it also looks .NET-ish.
#[test]
fn a_sigil_still_wins() {
    for s in ["_ZN4test<Main>b__0E", "_RNvC<>c", "?<Module>@@YAXXZ"] {
        assert_ne!(decline_reason(s), DeclineReason::DotNetMetadata, "{s}");
    }
}

/// Neither new category may be counted as a crate defect.
#[test]
fn dotnet_metadata_is_a_correct_decline() {
    assert!(!DeclineReason::DotNetMetadata.is_defect());
    assert!(DeclineReason::UnsupportedAbi.is_defect());
}
