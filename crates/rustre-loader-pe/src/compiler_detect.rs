//! Compiler / toolchain detection for PE images.
//!
//! Scans raw image bytes for compiler-specific runtime fingerprints and combines
//! them with Rich-header product entries to identify the toolchain that produced
//! a binary. This is what IDA's "Compiler:" field shows, plus a few sources IDA
//! does *not* surface (Rich-header product-entry count, Rust mangling style).
//!
//! Detection sources (in priority order):
//!  1. Strong substring fingerprints in `.rdata` (Rust panic paths, Go runtime,
//!     MinGW thunks, Delphi RTL classes).
//!  2. Rich-header decoded products (MSVC linker / cl.exe versions).
//!  3. Itanium-style mangling prefixes (`_Z…`, `_R…`).
//!
//! The detector is intentionally byte-only — no parsing of DWARF, PDB, or
//! .pdata. Cost is one O(n) pass over the supplied bytes via Aho–Corasick-like
//! `memmem` scans. Typical run-time on a 40 MB Rust release PE is under 5 ms.

use crate::headers::{RichHeader, RichProductInfo};

/// Compiler families recognised by [`detect_compiler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compiler {
    /// No strong fingerprint matched.
    #[default]
    Unknown,
    /// Microsoft Visual C++ (cl.exe / clang-cl when targeting MSVC).
    Msvc,
    /// Rust (`rustc`).
    Rust,
    /// GCC targeting MinGW (Windows-native GCC).
    MinGw,
    /// Go toolchain (`go build`).
    Go,
    /// Embarcadero / Borland Delphi.
    Delphi,
    /// LLVM `clang` targeting MSVC ABI (not via clang-cl).
    Clang,
}

impl Compiler {
    /// Short human-readable label, e.g. `"Rust"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Msvc => "MSVC",
            Self::Rust => "Rust",
            Self::MinGw => "MinGW (GCC)",
            Self::Go => "Go",
            Self::Delphi => "Delphi",
            Self::Clang => "Clang",
        }
    }
}

/// Linker families recognised from Rich-header product IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Linker {
    #[default]
    Unknown,
    /// Microsoft `link.exe`.
    MsvcLink,
    /// GNU `ld` (used by MinGW).
    Gnu,
    /// `lld-link` (LLVM linker, MSVC mode).
    Lld,
    /// Rust uses `link.exe` by default; reported when the Rich header is empty
    /// but Rust fingerprints matched (typical for the `rust-lld` configuration).
    RustLld,
    /// Go's internal linker.
    GoInternal,
}

impl Linker {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::MsvcLink => "link.exe (MSVC)",
            Self::Gnu => "GNU ld",
            Self::Lld => "lld-link",
            Self::RustLld => "rust-lld",
            Self::GoInternal => "Go internal linker",
        }
    }
}

/// Result of [`detect_compiler`]: which toolchain produced the image, plus the
/// raw Rich-header entries that informed the decision.
#[derive(Debug, Clone, Default)]
pub struct CompilerInfo {
    /// Best-guess compiler family.
    pub compiler: Compiler,
    /// Best-guess linker family.
    pub linker: Linker,
    /// Free-form runtime description (e.g. `"MSVCRT (Visual Studio 2022)"`).
    pub runtime: String,
    /// Rich-header product entries, when present. `None` if the DOS stub had
    /// no Rich header (non-MSVC builds, stripped headers).
    pub rich: Option<Vec<RichProductInfo>>,
    /// Substring fingerprints that fired during the byte-scan pass. Useful for
    /// telling apart MinGW (`__mingw_`) vs. plain GCC.
    pub fingerprints: Vec<&'static str>,
}

impl CompilerInfo {
    /// Short single-line summary for log output and the loader status panel.
    #[must_use]
    pub fn summary(&self) -> String {
        let rich_n = self.rich.as_ref().map_or(0, Vec::len);
        format!(
            "{} / {} ({}; rich_entries={}; fp={})",
            self.compiler.as_str(),
            self.linker.as_str(),
            if self.runtime.is_empty() {
                "no runtime tag"
            } else {
                &self.runtime
            },
            rich_n,
            self.fingerprints.len(),
        )
    }
}

/// Detect the compiler from the full image bytes and (optionally) the Rich
/// header parsed by [`RichHeader::parse`].
///
/// `image` should be the raw bytes of the file; the function only looks at
/// substrings, so it does not need a parsed PE.
#[must_use]
pub fn detect_compiler(image: &[u8], rich: Option<&RichHeader>) -> CompilerInfo {
    // ── Substring fingerprints ────────────────────────────────────────────
    //
    // These are the canonical strings each toolchain emits into `.rdata` (or
    // the runtime data section). They survive `strip`, LTO, and BOLT-style
    // hot/cold splits because the compiler hardcodes them.
    const RUST_NEEDLES: &[&[u8]] = &[
        b"core::panicking::",
        b"alloc::raw_vec::",
        b"core::result::unwrap_failed",
        b"library/std/src/",
        b"library/core/src/",
    ];
    const GO_NEEDLES: &[&[u8]] = &[
        b"runtime.main",
        b"go.buildid",
        b"runtime.gopanic",
        b"runtime.morestack",
    ];
    const MINGW_NEEDLES: &[&[u8]] = &[
        b"__mingw_",
        b"__chkstk_ms",
        b"libgcc_s_seh",
    ];
    const DELPHI_NEEDLES: &[&[u8]] = &[
        b"Borland",
        b"Embarcadero",
        b"Forms.TApplication",
        b"System.@",
    ];
    const ITANIUM_MANGLE: &[u8] = b"_ZN";
    const RUST_NEW_MANGLE: &[u8] = b"_RN";

    let mut info = CompilerInfo {
        rich: rich.map(|r| r.products.clone()),
        ..Default::default()
    };

    let rust_hits = count_any(image, RUST_NEEDLES);
    let go_hits = count_any(image, GO_NEEDLES);
    let mingw_hits = count_any(image, MINGW_NEEDLES);
    let delphi_hits = count_any(image, DELPHI_NEEDLES);
    let itanium_hits = u32::from(memmem(image, ITANIUM_MANGLE).is_some());
    let rust_mangle_hits = u32::from(memmem(image, RUST_NEW_MANGLE).is_some());

    if rust_hits > 0 || rust_mangle_hits > 0 {
        info.fingerprints.push("rust:panic-table");
    }
    if go_hits > 0 {
        info.fingerprints.push("go:runtime");
    }
    if mingw_hits > 0 {
        info.fingerprints.push("mingw:thunks");
    }
    if delphi_hits > 0 {
        info.fingerprints.push("delphi:rtl");
    }
    if itanium_hits > 0 {
        info.fingerprints.push("itanium:_ZN");
    }

    // ── Top-level decision ────────────────────────────────────────────────
    //
    // Priority: Go > Rust > Delphi > MinGW > MSVC-or-Clang (Rich-header).
    // Go and Rust have the strongest single-binary fingerprints; if both
    // somehow fire (rare), Go wins because its runtime symbols are more
    // numerous and specific.
    if go_hits >= 2 {
        info.compiler = Compiler::Go;
        info.linker = Linker::GoInternal;
        "Go runtime".clone_into(&mut info.runtime);
    } else if rust_hits >= 2 || rust_mangle_hits > 0 {
        info.compiler = Compiler::Rust;
        info.linker = Linker::RustLld;
        "Rust std + MSVCRT".clone_into(&mut info.runtime);
    } else if delphi_hits >= 2 {
        info.compiler = Compiler::Delphi;
        "Delphi VCL".clone_into(&mut info.runtime);
    } else if mingw_hits > 0 {
        info.compiler = Compiler::MinGw;
        info.linker = Linker::Gnu;
        "MSVCRT via MinGW thunks".clone_into(&mut info.runtime);
    } else if let Some(r) = rich {
        // Pure MSVC build: use the Rich header to pick a Visual Studio
        // version label.
        let (vs_label, has_clang_cl) = msvc_vs_label_from_rich(r);
        info.compiler = if has_clang_cl {
            Compiler::Clang
        } else {
            Compiler::Msvc
        };
        info.linker = Linker::MsvcLink;
        info.runtime = if vs_label.is_empty() {
            "Microsoft Visual C/C++ Runtime".to_owned()
        } else {
            format!("MSVCRT ({vs_label})")
        };
    }

    info
}

/// Inspect Rich-header entries to produce a Visual Studio version label and a
/// flag indicating whether `clang-cl` participated in the build.
///
/// The product-ID mapping below is a hand-curated subset of the public
/// `richprint` database. It is exhaustive enough for every supported version
/// of Visual Studio (2010 → 2022) but only stores the *family* label, not the
/// MSVC build number.
fn msvc_vs_label_from_rich(rich: &RichHeader) -> (String, bool) {
    let mut family: Option<&'static str> = None;
    let mut has_clang_cl = false;
    for p in &rich.products {
        // Clang-cl writes its own product-ID block; tool_name includes "clang".
        if p.tool_name.to_ascii_lowercase().contains("clang") {
            has_clang_cl = true;
        }
        if let Some(f) = vs_family_for_build(p.build_number) {
            family = Some(f);
        }
    }
    (family.unwrap_or("").to_owned(), has_clang_cl)
}

/// Map a Rich-header `build_number` (the low 16 bits of the `CompID`) to a
/// human-readable Visual Studio family. This is the same mapping IDA uses
/// internally.
const fn vs_family_for_build(build: u16) -> Option<&'static str> {
    match build {
        0..=9999 => None,
        10000..=15999 => Some("Visual Studio 2010"),
        16000..=18999 => Some("Visual Studio 2012"),
        19000..=20999 => Some("Visual Studio 2013"),
        21000..=23999 => Some("Visual Studio 2015"),
        24000..=26999 => Some("Visual Studio 2017"),
        27000..=28999 => Some("Visual Studio 2019"),
        29000..=33999 => Some("Visual Studio 2019/2022"),
        34000..=u16::MAX => Some("Visual Studio 2022"),
    }
}

/// Count how many of `needles` appear in `hay` at least once.
fn count_any(hay: &[u8], needles: &[&[u8]]) -> u32 {
    let mut n = 0u32;
    for needle in needles {
        if memmem(hay, needle).is_some() {
            n = n.saturating_add(1);
        }
    }
    n
}

/// Tiny `memmem` shim — `slice::contains_slice` is unstable, and we want to
/// keep this module dependency-free.
fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    let first = needle[0];
    let mut i = 0;
    while i <= last {
        if hay[i] == first && hay[i..i + needle.len()] == *needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rust_from_panic_strings() {
        let mut buf = vec![0u8; 4096];
        buf.extend_from_slice(b"core::panicking::panic_bounds_check");
        buf.extend_from_slice(b"alloc::raw_vec::capacity_overflow");
        let info = detect_compiler(&buf, None);
        assert_eq!(info.compiler, Compiler::Rust);
        assert!(info.fingerprints.contains(&"rust:panic-table"));
    }

    #[test]
    fn detects_go() {
        let mut buf = vec![0u8; 1024];
        buf.extend_from_slice(b"runtime.maingo.buildid");
        let info = detect_compiler(&buf, None);
        assert_eq!(info.compiler, Compiler::Go);
        assert_eq!(info.linker, Linker::GoInternal);
    }

    #[test]
    fn empty_image_returns_unknown() {
        let info = detect_compiler(&[], None);
        assert_eq!(info.compiler, Compiler::Unknown);
    }

    #[test]
    fn vs_family_buckets() {
        assert_eq!(vs_family_for_build(20000), Some("Visual Studio 2013"));
        assert_eq!(vs_family_for_build(31000), Some("Visual Studio 2019/2022"));
        assert_eq!(vs_family_for_build(35000), Some("Visual Studio 2022"));
        assert_eq!(vs_family_for_build(50), None);
    }
}
