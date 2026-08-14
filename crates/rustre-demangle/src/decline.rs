//! Why a symbol was declined.
//!
//! [`crate::demangle`] returns `None` for reasons that are not equivalent:
//! `.bss` has no demangling because it is a section name, `main` has none
//! because C does not mangle, and a truncated `_ZNSt…` has none because the
//! crate failed at something it should handle. Only the last is a defect.
//!
//! Collapsing all three into `None` makes the corpus metric unreadable: the
//! real-symbol corpus contains ~2200 section names and ~800 undecorated C
//! identifiers, so a genuine decoding regression of a handful of symbols
//! disappears into the noise. [`decline_reason`] separates them, which lets a
//! test assert the one number that matters — that
//! [`DeclineReason::UnsupportedAbi`] stays at zero.

use crate::classify::SymbolClassifier;
use crate::core_types::MangleLanguage;

/// Why [`crate::demangle`] produced no output for a given string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclineReason {
    /// Not declined: the symbol decoded successfully.
    Decoded,
    /// A linker section name (`.text`, `.bss`, `.debug_info`, `.CRT$XCA`, and
    /// the `-ffunction-sections` per-function forms such as
    /// `.pdata.unlikely._ZSt9terminatev`).
    ///
    /// These reach a demangler only because `nm` lists section symbols
    /// alongside real ones. A section is not a symbol and has no correct
    /// demangling, even when its name embeds one.
    LinkerSection,
    /// A symbol synthesised by the toolchain rather than by a compiler
    /// front-end: `__CTOR_LIST__`, `__DELAY_IMPORT_DIRECTORY_start__`,
    /// `_head_libgcc_s_dw2_1_dll`, PE import thunks around unmangled names.
    LinkerArtifact,
    /// A plain C identifier. C does not mangle, so the name is already its own
    /// demangling and declining is the correct answer.
    UndecoratedC,
    /// The string carries a recognised mangling sigil (`_Z`, `_R`, `?`, `$s`,
    /// `_D`, …) but no backend decoded it.
    ///
    /// This is the only variant that indicates a defect in this crate — either
    /// a gap in a backend or a genuinely malformed symbol in the input.
    UnsupportedAbi,
    /// A name that has already been demangled: `alloc::raw_vec::RawVec::
    /// grow_one<u16,alloc::alloc::Global>`, `std::vector<int>::push_back`.
    ///
    /// A demangler normally never sees these, which is why the category was
    /// missing. They come from debug info rather than a symbol table: MSVC-
    /// targeting compilers write the *decoded* name into the `CodeView`
    /// `S_GPROC32` procedure records, so a PDB holds both forms — the mangled
    /// one in `S_PUB32` and this one a few bytes away.
    ///
    /// Declining is the correct answer, for the same reason as
    /// [`Self::UndecoratedC`]: the string is already its own demangling. The
    /// distinction matters because these were previously [`Self::Unknown`],
    /// which this crate holds at zero precisely so that an unrecognised shape
    /// gets understood and named rather than parked.
    ///
    /// The discriminator is `::`. No mangling scheme emits a raw scope
    /// separator — Itanium and Rust length-prefix their components, MSVC
    /// separates with `@`, Go with `.` — so its presence means the name is
    /// output, not input. Tested last regardless, so a sigil-bearing symbol
    /// still reports [`Self::UnsupportedAbi`] and stays visible as a defect.
    AlreadyDemangled,
    /// A .NET metadata name: `.ctor`, `<Module>`, `<>c__DisplayClass0_0`,
    /// `<PopCount>g__SoftwareFallback|22_0`, `<Prop>k__BackingField`.
    ///
    /// C# does not mangle — the CLR stores method and type names plainly — so
    /// declining is correct, as for [`Self::UndecoratedC`]. These are not plain
    /// C identifiers though: the Roslyn compiler-generated forms wrap the
    /// enclosing member in angle brackets and append a kind character
    /// (`b` lambda, `d` state machine, `g` local function, `k` backing field,
    /// `c` display class), which no C identifier may contain.
    ///
    /// Two defects motivated the variant, both from the same root cause — the
    /// classifier's rules were derived from ELF/PE symbol tables, and .NET
    /// metadata names are not symbols:
    ///
    /// * the angle-bracket forms landed in [`Self::Unknown`], held at zero so
    ///   an unrecognised shape gets named rather than parked;
    /// * `.ctor` and `.cctor` were reported as [`Self::LinkerSection`], which
    ///   is not merely missing but *wrong* — a constructor is not a section.
    ///   The leading-dot rule reads "every leading-dot name in the corpus is a
    ///   section", and that was true only of the corpora it was written for.
    DotNetMetadata,
    /// None of the above: no sigil, but not a plain identifier either.
    Unknown,
}

impl DeclineReason {
    /// Whether this reason represents a shortcoming of the crate.
    ///
    /// `LinkerSection`, `LinkerArtifact`, `UndecoratedC` and `AlreadyDemangled`
    /// are all *correct* declines — there is nothing to decode. Only
    /// [`Self::UnsupportedAbi`] means a mangled name went unhandled.
    #[must_use]
    pub const fn is_defect(self) -> bool {
        matches!(self, Self::UnsupportedAbi)
    }
}

/// Toolchain-generated name prefixes.
///
/// The `__`-prefixed entries come from mingw-w64 / binutils PE support. `go:`
/// and `type:` are the Go linker's own namespaces for metadata it synthesises
/// — build IDs (`go:buildid`), FIPS section bounds (`go:textfipsstart`),
/// interface tables (`go:itab.…`) and type descriptors (`type:.eq.…`). None
/// name a function or variable written in Go, so declining them is correct.
const ARTIFACT_PREFIXES: [&str; 11] = [
    "__imp_",
    "_head_",
    "__head_",
    "__RUNTIME_PSEUDO_RELOC_LIST",
    "__DELAY_IMPORT_DIRECTORY",
    "__IMPORT_DESCRIPTOR_",
    "__NULL_IMPORT_DESCRIPTOR",
    "__IAT_",
    // MSVC's XMM constant pool: `__xmm@0b288bdf897532a555fa0890b2611bb2`.
    "__xmm@",
    "go:",
    "type:",
];

/// Toolchain-generated name suffixes.
///
/// The PE import table ends each DLL's thunk list with a null entry named
/// `<dll>_NULL_THUNK_DATA`. The DLL name leads, so this cannot be a prefix
/// rule.
const ARTIFACT_SUFFIXES: [&str; 1] = ["_NULL_THUNK_DATA"];

/// Explain why `s` does or does not demangle.
///
/// Returns [`DeclineReason::Decoded`] when the symbol decodes. Classification
/// is otherwise purely lexical and never re-runs a backend beyond the single
/// decode attempt.
#[must_use]
pub fn decline_reason(s: &str) -> DeclineReason {
    if crate::demangle(s).is_some() {
        return DeclineReason::Decoded;
    }
    // Before the leading-dot rule: `.ctor`/`.cctor` are CLR constructor names,
    // and calling them sections is an affirmatively wrong answer rather than a
    // missing one. An exact two-name set, so no section can be caught by it.
    if is_dotnet_metadata_name(s) {
        return DeclineReason::DotNetMetadata;
    }
    if s.starts_with('.') {
        // Every leading-dot name in the corpus is a section: PE/COFF section
        // names begin with `.`, while Go — the one scheme whose names contain
        // dots — never starts with one (`main.main`, `runtime.gcBgMarkWorker`).
        return DeclineReason::LinkerSection;
    }
    if ARTIFACT_PREFIXES.iter().any(|p| s.starts_with(p))
        || ARTIFACT_SUFFIXES.iter().any(|p| s.ends_with(p))
        || (s.starts_with("__") && s.ends_with("__") && s.len() > 4)
        || is_constant_pool(s)
    {
        return DeclineReason::LinkerArtifact;
    }
    // A recognised sigil that still failed to decode is the defect case, and
    // must be tested before the plain-identifier rule below — `_ZNSt…` also
    // matches the identifier shape.
    if SymbolClassifier::classify(s) != MangleLanguage::Unknown {
        return DeclineReason::UnsupportedAbi;
    }
    if is_c_identifier(strip_clone_suffix(s)) {
        // Either a bare C name, or one carrying a GCC IPA clone suffix
        // (`__pformat_int.isra.0`). Both are C functions with nothing to
        // demangle; the suffix does not change that.
        return DeclineReason::UndecoratedC;
    }
    if is_gcc_local_static(s) {
        // A GCC function-local `static` promoted to a symbol: `msg.0`,
        // `table.0`, `C.9.0`. Same case as the clone suffix above — a C entity
        // with a compiler-appended numeric tag and nothing to demangle. It
        // reaches here only because `GoDemangler::detect` now refuses it; before
        // that it was echoed back as a decode under `abi: Go`.
        return DeclineReason::UndecoratedC;
    }
    if is_already_demangled(s) {
        return DeclineReason::AlreadyDemangled;
    }
    DeclineReason::Unknown
}

/// Whether `s` is a .NET metadata name.
///
/// See [`DeclineReason::DotNetMetadata`]. Two disjoint shapes:
///
/// * the CLR's two reserved method names, matched exactly. `.ctor` and
///   `.cctor` are the only leading-dot names here that are not sections, so an
///   exact set is both sufficient and incapable of swallowing `.text`;
/// * the Roslyn compiler-generated forms, which wrap the enclosing member in
///   angle brackets: `<>c`, `<Module>`, `<Main>b__0_0`, `<Foo>d__4`,
///   `<Bar>g__Local|3_1`, `<Prop>k__BackingField`.
///
/// The bracket rule requires a closing `>`, an inner part that is empty or an
/// identifier, and — unless the brackets wrap the whole name (`<Module>`) — a
/// kind character after them. That rejects `<`, `<>`, `<abc`, `<a b>c` and
/// `<>1x`, which are not generated names but malformed strings.
///
/// Cannot mask a defect: sigil-bearing symbols are tested separately, and no
/// mangling scheme opens with `<` or `.ctor`.
#[must_use]
pub fn is_dotnet_metadata_name(s: &str) -> bool {
    if s == ".ctor" || s == ".cctor" {
        return true;
    }
    let Some(rest) = s.strip_prefix('<') else {
        return false;
    };
    let Some((inner, tail)) = rest.split_once('>') else {
        return false;
    };
    if !inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    // `<Module>` and `<PrivateImplementationDetails>` wrap a whole type name;
    // every other form appends a kind character.
    tail.is_empty() && !inner.is_empty()
        || tail.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// Whether `s` is demangler *output* rather than input.
///
/// See [`DeclineReason::AlreadyDemangled`] for where such names come from. The
/// test is the scope separator `::`, which no mangling scheme emits raw, plus
/// two guards that keep the rule from being a bare `contains`:
///
/// * the name must not start or end with the separator, and no component may
///   be empty — `::foo`, `foo::` and `a::::b` are malformed, not decoded names;
/// * the first component must begin like an identifier, so the MSVC debug-info
///   fragments that also carry `::` (`1'::filt$0`) stay [`DeclineReason::
///   Unknown`] rather than being absorbed into a category that claims they are
///   understood.
///
/// Deliberately narrow. A loose rule here would be worse than the gap it
/// closes: this variant reports "correct decline", so anything it wrongly
/// swallows stops being counted as a defect.
#[must_use]
pub fn is_already_demangled(s: &str) -> bool {
    if !s.contains("::") {
        return false;
    }
    let mut parts = s.split("::");
    let Some(head) = parts.next() else {
        return false;
    };
    if !head.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return false;
    }
    parts.all(|p| !p.is_empty())
}

/// Whether `s` is a GCC function-local static promoted to a linker symbol.
///
/// GCC names such a symbol `<identifier>.<counter>`, nesting the tag when the
/// counter is itself scoped (`C.9.0`), so every dot-separated component after
/// the base is a bare integer. That is the property separating it from a Go
/// symbol, which always carries at least one named component (a function, type
/// or method) after the package — see `go_demangler::GoDemangler::detect`,
/// which calls this to refuse them.
///
/// Public and defined once so the detector, the classifier and the corpus
/// bucketing share a single rule rather than three copies that could drift —
/// the defect shape this crate has paid for repeatedly.
#[must_use]
pub fn is_gcc_local_static(s: &str) -> bool {
    let Some((base, tail)) = s.split_once('.') else {
        return false;
    };
    is_c_identifier(base)
        && !tail.is_empty()
        && tail
            .split('.')
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `s` carries a GCC clone suffix (`.cold`, `.part.0`, `.isra.0`,
/// `.constprop.0`, …): `classify.cold`, `d_encoding.part.0`.
///
/// A clone suffix is decisive evidence of a C/C++ symbol — Go never emits one
/// — so such names are correctly declined, not decoded. Public and defined
/// once so the detector, the decoder and the corpus bucketing share a single
/// rule (the marker list lives in [`crate::backends::split_clone_suffix`])
/// rather than copies that drift. Without this the corpus classifier bucketed
/// `classify.cold` as a *Go* candidate purely because it contains a dot, and
/// counted its correct decline against Go's coverage.
#[must_use]
pub fn is_gcc_clone(s: &str) -> bool {
    crate::backends::split_clone_suffix(s).is_some()
}

/// Whether `s` names a linker constant pool entry: `$f64.3ff0000000000000`.
///
/// Matched on the full `$<type>.<hex>` shape rather than the leading `$`
/// alone, because `$s`/`$S` introduce Swift mangling: a bare `$` rule would
/// file an undecodable Swift symbol as a linker artifact and hide the very
/// defect [`DeclineReason::UnsupportedAbi`] exists to surface.
fn is_constant_pool(s: &str) -> bool {
    let llvm = s
        .strip_prefix('$')
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(tag, bits)| {
            matches!(tag, "f32" | "f64" | "i32" | "i64")
                && !bits.is_empty()
                && bits.chars().all(|c| c.is_ascii_hexdigit())
        });

    // MSVC's constant pool: `__real@3ff0000000000000`,
    // `__xmm@0000...`, `__ymm@…`. The payload after `@` *is* the constant's
    // value written in hex — there is no name to recover and nothing to
    // demangle, which is exactly what `LinkerArtifact` describes.
    //
    // Without this they fell through to `Unknown`, the variant this crate keeps
    // locked at zero, and `__xmm@…` was worse still: the stdcall-decoration
    // detector claimed it (its payload is all digits) and rendered `_xmm`,
    // dropping the value.
    let msvc = ["__real@", "__xmm@", "__ymm@", "__zmm@"]
        .iter()
        .find_map(|p| s.strip_prefix(p))
        .is_some_and(|bits| !bits.is_empty() && bits.chars().all(|c| c.is_ascii_hexdigit()));

    // ARM ELF mapping symbols: `$a` (ARM code), `$t` (Thumb), `$d` (data),
    // `$x` (A64 code), each optionally followed by `.<anything>`. They mark
    // instruction-set transitions in the section, name no entity, and are
    // emitted by every ARM toolchain — so they belong here rather than in
    // `Unknown`, the variant this crate keeps locked at zero.
    let arm_mapping = s.strip_prefix('$').is_some_and(|rest| {
        let mut chars = rest.chars();
        chars.next().is_some_and(|c| matches!(c, 'a' | 't' | 'd' | 'x'))
            && chars.next().is_none_or(|c| c == '.')
    });

    llvm || msvc || arm_mapping
}

/// Strip a trailing GCC clone suffix, returning `s` unchanged if it has none.
///
/// Delegates to the same split the decoder uses, so classification cannot
/// drift from decoding: a symbol declined there for having an undecodable base
/// is classified here by exactly that base. A second copy of the marker list
/// would diverge the first time anyone added a tag to one of them.
fn strip_clone_suffix(s: &str) -> &str {
    crate::backends::split_clone_suffix(s).map_or(s, |(base, _)| base)
}

/// Whether `s` is a bare C identifier: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_c_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{DeclineReason, decline_reason};

    #[test]
    fn decoded_symbols_report_decoded() {
        assert_eq!(
            decline_reason("_ZNSt10bad_typeidD1Ev"),
            DeclineReason::Decoded
        );
    }

    #[test]
    fn section_names_are_sections() {
        for s in [
            ".bss",
            ".text",
            ".CRT$XCA",
            ".debug_aranges",
            ".pdata.unlikely._ZSt9terminatev",
        ] {
            assert_eq!(decline_reason(s), DeclineReason::LinkerSection, "{s}");
        }
    }

    #[test]
    fn toolchain_names_are_artifacts() {
        for s in [
            "__CTOR_LIST__",
            "__DELAY_IMPORT_DIRECTORY_start__",
            "_head_libgcc_s_dw2_1_dll",
            "__imp_CreateFileW",
        ] {
            assert_eq!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    /// Go linker metadata namespaces. These reach the classifier only when the
    /// permissive Go detector declines them (it claims any dotted name), so
    /// the cases asserted here are the dot-free ones.
    #[test]
    fn go_linker_metadata_is_an_artifact() {
        for s in [
            "go:buildid",
            "go:buildinfo",
            "go:fipsinfo",
            "go:textfipsstart",
            "go:noptrdatafipsend",
        ] {
            assert_eq!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    /// A real Go function must not be swept up by the `go:` rule — the prefix
    /// is `go:`, not `go`, and ordinary Go symbols decode anyway.
    #[test]
    fn real_go_symbols_are_not_artifacts() {
        for s in ["main.main", "runtime.gcBgMarkWorker", "gopher.Run"] {
            assert_ne!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    #[test]
    fn plain_c_names_are_undecorated() {
        for s in ["main", "memcpy", "_CRT_MT", "atexit"] {
            assert_eq!(decline_reason(s), DeclineReason::UndecoratedC, "{s}");
        }
    }

    /// PE import-table machinery from MSVC-linked binaries.
    #[test]
    fn pe_import_table_names_are_artifacts() {
        for s in [
            "__IMPORT_DESCRIPTOR_api-ms-win-crt-heap-l1-1-0",
            "__NULL_IMPORT_DESCRIPTOR_api-ms-win-core-synch-l1-2-0",
            "KERNEL32_NULL_THUNK_DATA",
            "api-ms-win-crt-stdio-l1-1-0_NULL_THUNK_DATA",
            "__xmm@0b288bdf897532a555fa0890b2611bb2",
        ] {
            assert_eq!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    /// `_RTC_*` is the MSVC runtime-check CRT, not Rust v0. Classifying it as
    /// Rust made it look like an unhandled Rust symbol — a phantom defect.
    #[test]
    fn msvc_runtime_check_names_are_not_rust_defects() {
        for s in ["_RTC_Initialize", "_RTC_InitBase", "_RTC_Terminate"] {
            assert_eq!(decline_reason(s), DeclineReason::UndecoratedC, "{s}");
        }
    }

    #[test]
    fn constant_pool_entries_are_artifacts() {
        for s in ["$f64.3ff0000000000000", "$f32.4048f5c3", "$i64.8000000000000000"] {
            assert_eq!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    /// A `$`-prefixed name that is not a constant pool entry must not be
    /// filed as an artifact — `$s`/`$S` is Swift, and an undecodable Swift
    /// symbol is a defect that has to stay visible.
    #[test]
    fn swift_sigil_is_not_swallowed_by_the_constant_pool_rule() {
        for s in ["$sSomeGarbageThatWillNotDecode", "$foo.bar", "$f64.notahexnumber"] {
            assert_ne!(decline_reason(s), DeclineReason::LinkerArtifact, "{s}");
        }
    }

    /// A clone suffix does not turn a C function into an unknown shape: the
    /// base is still a plain C name with nothing to demangle.
    #[test]
    fn clone_suffixed_c_names_are_undecorated() {
        for s in [
            "__pformat_int.isra.0",
            "__pthread_rwlock_timedrdlock.part.0",
            "_pthread_once_raw.constprop.0.isra.0",
            "__pthread_self_lite.part.0.cold",
        ] {
            assert_eq!(decline_reason(s), DeclineReason::UndecoratedC, "{s}");
        }
    }

    #[test]
    fn only_unsupported_abi_counts_as_a_defect() {
        assert!(DeclineReason::UnsupportedAbi.is_defect());
        for r in [
            DeclineReason::Decoded,
            DeclineReason::LinkerSection,
            DeclineReason::LinkerArtifact,
            DeclineReason::UndecoratedC,
            DeclineReason::Unknown,
        ] {
            assert!(!r.is_defect(), "{r:?} must not count as a defect");
        }
    }
}
