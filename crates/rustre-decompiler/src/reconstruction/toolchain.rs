//! What a binary is made of: source language, toolchain and runtime.
//!
//! Every rule here was derived by measuring the 12-binary corpus, not from
//! general knowledge about executable formats — several plausible-sounding
//! markers turned out to be absent (see [`Language::DotNetNativeAot`]).
//!
//! Per the module contract in [`super`], detection is **evidence-based and
//! honest**: each verdict carries the markers that produced it, and a language
//! that cannot be distinguished from another is reported as ambiguous rather
//! than guessed.

use std::collections::BTreeSet;
use std::fmt;

/// Source language / runtime family of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Language {
    Go,
    Rust,
    /// C# (and other .NET languages) compiled **ahead-of-time to native code**.
    ///
    /// Worth stating plainly, because it inverts the usual assumption: this is
    /// NOT the easy IL case. There is no CLI header, no `mscoree.dll` import
    /// and no `_CorExeMain` — those markers are ABSENT from the corpus's C#
    /// binaries, which is how this variant was discovered. ILSpy/dnSpy-style
    /// near-lossless IL decompilation does not apply; this is ordinary native
    /// machine code carrying .NET runtime metadata, i.e. the hard problem.
    DotNetNativeAot,
    /// C++ with observable C++ runtime usage (mangled names, EH personality).
    Cpp,
    /// C, or C++ that uses no C++ feature at all.
    ///
    /// **Deliberately ambiguous.** `sample2_cpp` in the corpus is genuinely
    /// C++ yet contains zero `_Z` mangling, no libstdc++ reference and no
    /// `operator new` — at the binary level it is indistinguishable from C.
    /// Reporting "C" there would be a confident lie, so the ambiguity is part
    /// of the verdict.
    COrCpp,
}

impl Language {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Rust => "rust",
            Self::DotNetNativeAot => "dotnet_nativeaot",
            Self::Cpp => "cpp",
            Self::COrCpp => "c_or_cpp",
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Compiler / runtime toolchain the binary was produced by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Toolchain {
    /// mingw-w64 (GCC targeting Windows). Statically linked CRT in this corpus.
    MingwW64,
    /// The Rust compiler. Identified by the `/rustc/<commit>` source-path
    /// prefix baked into panic locations, which survives release builds.
    Rustc,
    /// The Go toolchain, identified by the `go1.<minor>.<patch>` runtime stamp.
    Go,
    /// .NET NativeAOT's ILCompiler-produced native image.
    ///
    /// Deliberately NOT keyed on the bare string `Microsoft`: that was measured
    /// to also appear inside ordinary managed type names (e.g.
    /// `Microsoft.Extensions.DependencyInjection.*`), so it is evidence of
    /// managed metadata in general, not of the toolchain.
    DotNetNativeAot,
}

impl Toolchain {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::MingwW64 => "mingw-w64",
            Self::Rustc => "rustc",
            Self::Go => "go",
            Self::DotNetNativeAot => "dotnet-nativeaot",
        }
    }
}

/// A detection result together with the evidence that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainReport {
    /// `None` when no rule matched — never a guess, and never a default.
    pub language: Option<Language>,
    pub toolchain: Option<Toolchain>,
    /// Marker strings actually found, sorted and deduplicated.
    pub markers: BTreeSet<&'static str>,
    /// Toolchain version read verbatim out of the image (e.g. `1.25.1` for Go,
    /// the `31fca3ad` commit hash for rustc, `15.2.0` for GCC).
    ///
    /// `None` when the producing toolchain stamps no version, or when the
    /// stamp is present but unparseable — never a guess.
    pub version: Option<String>,
}

impl ToolchainReport {
    /// One-line summary, e.g. `go (markers: Go build ID, runtime.goexit)`.
    #[must_use]
    pub fn explain(&self) -> String {
        let lang = self.language.map_or("unknown", Language::id);
        let tc = self.toolchain.map(Toolchain::id).unwrap_or("-");
        let ver = self.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
        if self.markers.is_empty() {
            return format!("{lang} / {tc}{ver} (no markers found)");
        }
        let m: Vec<&str> = self.markers.iter().copied().collect();
        format!("{lang} / {tc}{ver} (markers: {})", m.join(", "))
    }
}

/// Markers for a language, in priority order. The first family with any hit
/// wins, so the more specific runtimes are listed before the generic ones.
///
/// Each entry was confirmed present in the corpus binaries of that language
/// and absent from the others.
const LANGUAGE_MARKERS: &[(Language, &[&str])] = &[
    // Go: the build-ID stamp and the scheduler symbol both survive stripping.
    (Language::Go, &["Go build ID", "runtime.goexit"]),
    // Rust: panic machinery is present even in release builds.
    (Language::Rust, &["rust_begin_unwind", "core::panicking", "RUST_BACKTRACE"]),
    // .NET NativeAOT: the runtime is linked in, so its own assembly names and
    // GC thread names appear as plain strings.
    (
        Language::DotNetNativeAot,
        &["System.Private.CoreLib", "System.Private.TypeLoader", ".NET BGC", ".NET Finalizer"],
    ),
    // C++ ONLY when the C++ runtime is actually observable. Absent these, a
    // C++ program falls through to `COrCpp` — see that variant's note.
    (Language::Cpp, &["__gxx_personality", "_ZSt", "_ZN", "libstdc++"]),
];

/// Toolchain markers, in priority order — first family with any hit wins.
///
/// Every entry below was measured across all 12 corpus binaries and confirmed
/// to hit **only** the binaries of its own toolchain (see the module tests).
/// The language-specific toolchains are listed before mingw-w64 because a Rust
/// or Go binary on Windows can still link mingw pieces; the more specific
/// producer is the honest answer.
const TOOLCHAIN_MARKERS: &[(Toolchain, &[&str])] = &[
    // `/rustc/<commit-hash>/` prefixes every std source path in panic metadata.
    (Toolchain::Rustc, &["/rustc/", "rustc"]),
    // The Go runtime stamps its own version, plus the build ID.
    (Toolchain::Go, &["go1.", "Go build"]),
    // NativeAOT links the runtime in; these are its own component names.
    (Toolchain::DotNetNativeAot, &["System.Private.CoreLib", "System.Private.TypeLoader"]),
    (Toolchain::MingwW64, &["__mingw", "mingw"]),
];

/// Toolchain version signatures: (toolchain, prefix to find, charset that ends
/// the version token). Extracted verbatim from the image so the value is
/// evidence, never an inference.
const VERSION_SIGNATURES: &[(Toolchain, &str)] = &[
    (Toolchain::Rustc, "/rustc/"),
    (Toolchain::Go, "go1."),
    (Toolchain::MingwW64, "GCC: "),
];

/// Detect language and toolchain from the raw image bytes.
///
/// Scans for ASCII markers directly in the image rather than requiring a
/// parsed symbol table, so it works on stripped binaries.
#[must_use]
pub fn detect(image: &[u8]) -> ToolchainReport {
    let mut markers = BTreeSet::new();

    let mut language = None;
    for (lang, pats) in LANGUAGE_MARKERS {
        let hits: Vec<&'static str> =
            pats.iter().copied().filter(|p| contains_ascii(image, p.as_bytes())).collect();
        if !hits.is_empty() {
            language = Some(*lang);
            markers.extend(hits);
            break;
        }
    }

    let mut toolchain = None;
    for (tc, pats) in TOOLCHAIN_MARKERS {
        let hits: Vec<&'static str> =
            pats.iter().copied().filter(|p| contains_ascii(image, p.as_bytes())).collect();
        if !hits.is_empty() {
            toolchain = Some(*tc);
            markers.extend(hits);
            break;
        }
    }

    // A mingw-w64 binary with no language-specific runtime evidence is C — or
    // C++ that never touched the C++ runtime. Say both; see `COrCpp`.
    if language.is_none() && toolchain == Some(Toolchain::MingwW64) {
        language = Some(Language::COrCpp);
    }

    let version = toolchain.and_then(|tc| extract_version(image, tc));

    ToolchainReport { language, toolchain, markers, version }
}

/// Read the toolchain's own version stamp out of the image.
///
/// Returns the token that follows the signature prefix, bounded to a short
/// window so a corrupt or padded image cannot pull in unbounded garbage.
fn extract_version(image: &[u8], tc: Toolchain) -> Option<String> {
    let prefix = VERSION_SIGNATURES.iter().find(|(t, _)| *t == tc).map(|(_, p)| *p)?;
    let at = find_ascii(image, prefix.as_bytes())?;
    let rest = &image[at + prefix.len()..];

    // GCC stamps `GCC: (Rev8, Built by MSYS2 project) 15.2.0` — the version is
    // the LAST token, after the parenthesised vendor blurb.
    if tc == Toolchain::MingwW64 {
        let line: Vec<u8> = rest.iter().copied().take(96).take_while(|b| *b != 0).collect();
        let text = String::from_utf8_lossy(&line);
        return text
            .rsplit(')')
            .next()
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
            .map(str::to_owned);
    }

    // rustc: the commit hash up to the next `/`. Go: the `1.25.1` after `go1.`,
    // which the caller's prefix already consumed down to the digits.
    let end = |b: u8| -> bool {
        match tc {
            Toolchain::Rustc => !b.is_ascii_alphanumeric(),
            _ => !(b.is_ascii_digit() || b == b'.'),
        }
    };
    let token: Vec<u8> = rest.iter().copied().take(48).take_while(|b| !end(*b)).collect();
    if token.is_empty() {
        return None;
    }
    let mut v = String::from_utf8(token).ok()?;
    if tc == Toolchain::Go {
        // The prefix ate `go1.`, so restore the major/minor the stamp implies.
        v = format!("1.{}", v.trim_start_matches('.'));
    }
    // A trailing `.` means the stamp was truncated mid-token; report nothing
    // rather than a malformed version.
    Some(v.trim_end_matches('.').to_owned()).filter(|v| !v.is_empty())
}

/// Offset of `needle` in `haystack`, if present.
fn find_ascii(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Substring search over raw bytes (the image is not valid UTF-8).
fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_go_from_build_id() {
        let r = detect(b"....Go build ID: \"abc\"....");
        assert_eq!(r.language, Some(Language::Go));
        assert!(r.markers.contains("Go build ID"));
    }

    #[test]
    fn detects_rust_from_panic_machinery() {
        assert_eq!(detect(b"..rust_begin_unwind..").language, Some(Language::Rust));
    }

    #[test]
    fn detects_dotnet_nativeaot_without_any_cli_marker() {
        // The point of this variant: no mscoree, no _CorExeMain, still .NET.
        let r = detect(b"..System.Private.CoreLib....NET BGC..");
        assert_eq!(r.language, Some(Language::DotNetNativeAot));
    }

    #[test]
    fn mingw_without_language_evidence_is_reported_ambiguous() {
        // Must NOT claim "C": a C++ program using no C++ feature looks the same.
        let r = detect(b"..__mingw_setusermatherr..");
        assert_eq!(r.language, Some(Language::COrCpp));
        assert_eq!(r.toolchain, Some(Toolchain::MingwW64));
    }

    #[test]
    fn cpp_wins_over_the_ambiguous_fallback_when_runtime_is_visible() {
        let r = detect(b"..__gxx_personality_seh0....__mingw..");
        assert_eq!(r.language, Some(Language::Cpp));
        assert_eq!(r.toolchain, Some(Toolchain::MingwW64));
    }

    #[test]
    fn rustc_toolchain_and_commit_hash() {
        let r = detect(b"..panicked at /rustc/31fca3ad/library/core/src/x.rs..");
        assert_eq!(r.toolchain, Some(Toolchain::Rustc));
        assert_eq!(r.version.as_deref(), Some("31fca3ad"));
    }

    #[test]
    fn go_toolchain_and_version() {
        let r = detect(b"..go1.25.1..runtime.goexit..");
        assert_eq!(r.language, Some(Language::Go));
        assert_eq!(r.toolchain, Some(Toolchain::Go));
        assert_eq!(r.version.as_deref(), Some("1.25.1"));
    }

    #[test]
    fn gcc_version_is_taken_after_the_vendor_blurb() {
        // The real corpus stamp — the version trails a parenthesised blurb.
        let r = detect(b"..__mingw..GCC: (Rev8, Built by MSYS2 project) 15.2.0\x00..");
        assert_eq!(r.toolchain, Some(Toolchain::MingwW64));
        assert_eq!(r.version.as_deref(), Some("15.2.0"));
    }

    #[test]
    fn bare_microsoft_is_not_toolchain_evidence() {
        // Measured: `Microsoft` also occurs inside ordinary managed type names,
        // so it must not by itself produce a NativeAOT toolchain verdict.
        let r = detect(b"..Microsoft.Extensions.DependencyInjection.Foo..");
        assert_eq!(r.toolchain, None);
    }

    #[test]
    fn nativeaot_toolchain_needs_a_runtime_component() {
        let r = detect(b"..System.Private.CoreLib....NET BGC..");
        assert_eq!(r.toolchain, Some(Toolchain::DotNetNativeAot));
        assert_eq!(r.version, None, "NativeAOT stamps no version we can trust");
    }

    #[test]
    fn a_language_specific_toolchain_outranks_mingw() {
        // A Rust binary on Windows still links mingw pieces; rustc is the
        // honest producer.
        let r = detect(b"..rust_begin_unwind../rustc/deadbeef/..__mingw..");
        assert_eq!(r.toolchain, Some(Toolchain::Rustc));
    }

    #[test]
    fn nothing_is_reported_when_nothing_matches() {
        let r = detect(b"\x00\x01\x02 no markers here");
        assert_eq!(r.language, None, "must not guess a default language");
        assert_eq!(r.toolchain, None);
        assert!(r.explain().contains("no markers"));
    }
}
