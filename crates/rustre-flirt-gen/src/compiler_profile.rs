//! Compiler runtime-library profiles for FLIRT signature generation.
//!
//! Each [`CompilerProfile`] describes a specific compiler / runtime combination
//! (e.g. MSVC 2022 x64 Release, GCC 12 libstdc++, Rust std 1.78) and bundles:
//!
//! * A list of library files / archive names to scan.
//! * Known function name prefixes specific to that runtime.
//! * Calling-convention metadata.
//! * Pre-built prologue byte sequences common to that compiler.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Calling convention used by functions in this profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallingConvention {
    /// `__cdecl` — caller cleans stack, args right-to-left.
    Cdecl,
    /// `__stdcall` — callee cleans, args right-to-left (`WinAPI`).
    Stdcall,
    /// `__fastcall` — first two args in ECX/EDX (MSVC 32-bit).
    Fastcall,
    /// Microsoft x64 ABI — first 4 args in RCX/RDX/R8/R9.
    MsX64,
    /// System V AMD64 ABI — first 6 args in RDI/RSI/RDX/RCX/R8/R9.
    SysVX64,
    /// ARM AAPCS32.
    AapcsArm32,
    /// ARM AAPCS64 / `AArch64`.
    AapcsAarch64,
    /// Unknown / unspecified.
    Unknown,
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::MsX64 => "ms_x64",
            Self::SysVX64 => "sysv_x64",
            Self::AapcsArm32 => "aapcs32",
            Self::AapcsAarch64 => "aapcs64",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Arch / Os
// ─────────────────────────────────────────────────────────────────────────────

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileArch {
    X86,
    X86_64,
    Arm32,
    Aarch64,
    RiscV32,
    RiscV64,
}

impl fmt::Display for ProfileArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm32 => "arm32",
            Self::Aarch64 => "aarch64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
        };
        write!(f, "{s}")
    }
}

/// Target operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileOs {
    Windows,
    Linux,
    MacOs,
    FreeBsd,
    Aix,
    Bare,
}

impl fmt::Display for ProfileOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::FreeBsd => "freebsd",
            Self::Aix => "aix",
            Self::Bare => "bare",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProloguePattern
// ─────────────────────────────────────────────────────────────────────────────

/// A known function prologue byte sequence for a compiler/arch combination.
#[derive(Debug, Clone)]
pub struct ProloguePattern {
    /// Concrete bytes; `0xFF` in the mask means wildcard.
    pub bytes: Vec<u8>,
    /// Wildcard positions (indices into `bytes`).
    pub wildcards: Vec<usize>,
    /// Human-readable label.
    pub label: &'static str,
}

impl ProloguePattern {

    fn build(bytes: &[u8], wildcards: &[usize], label: &'static str) -> Self {
        Self {
            bytes: bytes.to_vec(),
            wildcards: wildcards.to_vec(),
            label,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompilerProfile
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a compiler / runtime / platform combination.
#[derive(Debug, Clone)]
pub struct CompilerProfile {
    /// Short unique identifier (e.g. `"msvc2022_x64"`).
    pub id: &'static str,
    /// Human-readable display name.
    pub display_name: &'static str,
    /// Target architecture.
    pub arch: ProfileArch,
    /// Target operating system.
    pub os: ProfileOs,
    /// Primary calling convention.
    pub calling_convention: CallingConvention,
    /// Library files / archive names that belong to this profile.
    pub library_files: Vec<String>,
    /// Function name prefixes associated with this runtime.
    pub name_prefixes: Vec<&'static str>,
    /// Name suffixes / decorations (e.g. `"@@"` for MSVC name mangling).
    pub name_suffixes: Vec<&'static str>,
    /// Common function prologues for this compiler.
    pub prologues: Vec<ProloguePattern>,
    /// Extra metadata key/value pairs.
    pub meta: HashMap<&'static str, &'static str>,
}

impl CompilerProfile {
    /// Return `true` if the given function name looks like it belongs to this profile.
    #[must_use]
    pub fn name_matches(&self, name: &str) -> bool {
        if (self.id.starts_with("msvc") || self.id.starts_with("clang_cl"))
            && (name.starts_with("_ZN") || name.starts_with("_Z") || name.starts_with("_R"))
        {
            return false;
        }
        self.name_prefixes.iter().any(|p| name.starts_with(p))
            || self.name_suffixes.iter().any(|s| name.ends_with(s))
    }

    /// Return the first prologue that starts `data`.
    #[must_use]
    pub fn match_prologue<'a>(&'a self, data: &[u8]) -> Option<&'a ProloguePattern> {
        self.prologues.iter().find(|p| {
            if data.len() < p.bytes.len() {
                return false;
            }
            p.bytes.iter().zip(data.iter()).enumerate().all(|(i, (&pb, &db))| {
                p.wildcards.contains(&i) || pb == db
            })
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile constructors
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! profile {
    ($id:expr, $name:expr, $arch:expr, $os:expr, $cc:expr,
     libs = [$($lib:expr),*],
     prefixes = [$($pfx:expr),*],
     suffixes = [$($sfx:expr),*]) => {{
        CompilerProfile {
            id: $id,
            display_name: $name,
            arch: $arch,
            os: $os,
            calling_convention: $cc,
            library_files: vec![$($lib.to_string()),*],
            name_prefixes: vec![$($pfx),*],
            name_suffixes: vec![$($sfx),*],
            prologues: Vec::new(),
            meta: HashMap::new(),
        }
    }};
}

// ── MSVC profiles ─────────────────────────────────────────────────────────────

/// MSVC 2015 (VC14) x86 release CRT.
#[must_use]
pub fn msvc2015_x86() -> CompilerProfile {
    let mut p = profile!(
        "msvc2015_x86", "MSVC 2015 x86 CRT",
        ProfileArch::X86, ProfileOs::Windows, CallingConvention::Cdecl,
        libs = ["libcmt.lib", "msvcrt.lib", "libcpmt.lib", "msvcprt.lib",
                "libvcruntimed.lib", "vcruntime140.lib"],
        prefixes = ["_", "__", "?"],
        suffixes = ["@@"]
    );
    // push frame: PUSH EBP / MOV EBP, ESP
    p.prologues.push(ProloguePattern::build(&[0x55, 0x8B, 0xEC], &[], "push_ebp_mov_esp"));
    // sub esp variant: PUSH EBP / MOV EBP,ESP / SUB ESP,imm8
    p.prologues.push(ProloguePattern::build(&[0x55, 0x8B, 0xEC, 0x83, 0xEC], &[5], "sub_esp_imm8"));
    p.meta.insert("vc_version", "140");
    p
}

/// MSVC 2017 (VC15) x64 release CRT.
#[must_use]
pub fn msvc2017_x64() -> CompilerProfile {
    let mut p = profile!(
        "msvc2017_x64", "MSVC 2017 x64 CRT",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["libcmt.lib", "msvcrt.lib", "libcpmt.lib", "msvcprt.lib",
                "vcruntime140.lib", "vcruntime140_1.lib"],
        prefixes = ["_", "__", "?"],
        suffixes = ["@@"]
    );
    // Standard x64 prologue: MOV [RSP+8], RCX (or push variant)
    p.prologues.push(ProloguePattern::build(&[0x48, 0x89, 0x4C, 0x24, 0x08], &[], "mov_rsp8_rcx"));
    p.prologues.push(ProloguePattern::build(&[0x40, 0x53, 0x48, 0x83, 0xEC], &[5], "push_rbx_sub_rsp"));
    p.meta.insert("vc_version", "141");
    p
}

/// MSVC 2019 (VC16) x64 release CRT.
#[must_use]
pub fn msvc2019_x64() -> CompilerProfile {
    let p = msvc2017_x64();
    // override id/name but keep rest
    let mut q = profile!(
        "msvc2019_x64", "MSVC 2019 x64 CRT",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["libcmt.lib", "msvcrt.lib", "libcpmt.lib", "msvcprt.lib",
                "vcruntime140.lib", "vcruntime140_1.lib", "ucrt.lib"],
        prefixes = ["_", "__", "?"],
        suffixes = ["@@"]
    );
    q.prologues = p.prologues;
    q.meta.insert("vc_version", "142");
    q
}

/// MSVC 2022 (VC17) x64 release CRT.
#[must_use]
pub fn msvc2022_x64() -> CompilerProfile {
    let mut p = profile!(
        "msvc2022_x64", "MSVC 2022 x64 CRT",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["libcmt.lib", "msvcrt.lib", "libcpmt.lib", "msvcprt.lib",
                "vcruntime140.lib", "vcruntime140_1.lib", "ucrt.lib", "clang_rt.builtins-x86_64.lib"],
        prefixes = ["_", "__", "?", "__cdecl_"],
        suffixes = ["@@", "@Z"]
    );
    p.prologues.push(ProloguePattern::build(&[0x48, 0x89, 0x4C, 0x24, 0x08], &[], "mov_rsp8_rcx"));
    p.prologues.push(ProloguePattern::build(&[0x48, 0x83, 0xEC], &[3], "sub_rsp_imm8"));
    p.meta.insert("vc_version", "143");
    p
}

// ── GCC profiles ──────────────────────────────────────────────────────────────

/// GCC 9 `x86_64` Linux libgcc + libstdc++.
#[must_use]
pub fn gcc9_x64_linux() -> CompilerProfile {
    let mut p = profile!(
        "gcc9_x64_linux", "GCC 9 x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libgcc.a", "libgcc_s.so", "libstdc++.a", "libstdc++.so",
                "libm.a", "libc.a", "crt1.o", "crti.o", "crtn.o"],
        prefixes = ["_Z", "__", "_GCC_"],
        suffixes = []
    );
    p.prologues.push(ProloguePattern::build(&[0x55, 0x48, 0x89, 0xE5], &[], "push_rbp"));
    p.prologues.push(ProloguePattern::build(&[0x53, 0x48, 0x83, 0xEC], &[4], "push_rbx_sub_rsp"));
    p.meta.insert("gcc_version", "9");
    p
}

/// GCC 10 `x86_64` Linux.
#[must_use]
pub fn gcc10_x64_linux() -> CompilerProfile {
    let p = gcc9_x64_linux();
    let mut q = profile!(
        "gcc10_x64_linux", "GCC 10 x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libgcc.a", "libgcc_s.so", "libstdc++.a", "libstdc++.so",
                "libm.a", "libc.a"],
        prefixes = ["_Z", "__", "_GCC_"],
        suffixes = []
    );
    q.prologues = p.prologues;
    q.meta.insert("gcc_version", "10");
    q
}

/// GCC 11 `x86_64` Linux.
#[must_use]
pub fn gcc11_x64_linux() -> CompilerProfile {
    let p = gcc10_x64_linux();
    let mut q = profile!(
        "gcc11_x64_linux", "GCC 11 x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libgcc.a", "libgcc_s.so", "libstdc++.a", "libstdc++.so",
                "libm.a", "libc.a", "libatomic.a"],
        prefixes = ["_Z", "__", "_GCC_"],
        suffixes = []
    );
    q.prologues = p.prologues;
    q.meta.insert("gcc_version", "11");
    q
}

/// GCC 12 `x86_64` Linux.
#[must_use]
pub fn gcc12_x64_linux() -> CompilerProfile {
    let p = gcc11_x64_linux();
    let mut q = profile!(
        "gcc12_x64_linux", "GCC 12 x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libgcc.a", "libgcc_s.so", "libstdc++.a", "libstdc++.so",
                "libm.a", "libc.a", "libatomic.a"],
        prefixes = ["_Z", "__", "_GCC_"],
        suffixes = []
    );
    q.prologues = p.prologues;
    q.meta.insert("gcc_version", "12");
    q
}

// ── Clang/LLVM profiles ───────────────────────────────────────────────────────

/// Clang/LLVM `x86_64` Linux (uses compiler-rt builtins).
#[must_use]
pub fn clang_x64_linux() -> CompilerProfile {
    let mut p = profile!(
        "clang_x64_linux", "Clang/LLVM x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libclang_rt.builtins-x86_64.a", "libstdc++.a", "libm.a", "libc.a"],
        prefixes = ["_Z", "__", "_clang_", "__asan_", "__ubsan_", "__tsan_"],
        suffixes = []
    );
    p.prologues.push(ProloguePattern::build(&[0x55, 0x48, 0x89, 0xE5], &[], "push_rbp"));
    p.prologues.push(ProloguePattern::build(&[0x50], &[], "push_rax_frame"));
    p.meta.insert("compiler", "clang");
    p
}

/// Clang/LLVM `x86_64` Windows (clang-cl mode).
#[must_use]
pub fn clang_cl_x64_windows() -> CompilerProfile {
    let mut p = profile!(
        "clang_cl_x64_windows", "Clang-CL x64 Windows",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["clang_rt.builtins-x86_64.lib", "libcmt.lib", "vcruntime140.lib"],
        prefixes = ["_", "__", "?", "_clang_"],
        suffixes = ["@@", "@Z"]
    );
    p.prologues.push(ProloguePattern::build(&[0x48, 0x89, 0x4C, 0x24, 0x08], &[], "mov_rsp8_rcx"));
    p.meta.insert("compiler", "clang-cl");
    p
}

// ── Rust std profiles ─────────────────────────────────────────────────────────

/// Rust std library (`x86_64` Linux).
#[must_use]
pub fn rust_std_x64_linux() -> CompilerProfile {
    let mut p = profile!(
        "rust_std_x64_linux", "Rust std x86_64 Linux",
        ProfileArch::X86_64, ProfileOs::Linux, CallingConvention::SysVX64,
        libs = ["libstd.rlib", "libcore.rlib", "liballoc.rlib",
                "libcompiler_builtins.rlib", "libunwind.rlib"],
        prefixes = ["_ZN", "__rust_", "_rust_", "rust_begin_unwind",
                    "__rg_", "core::", "std::", "alloc::"],
        suffixes = ["17h", "E"]
    );
    p.prologues.push(ProloguePattern::build(&[0x55, 0x48, 0x89, 0xE5], &[], "push_rbp"));
    p.prologues.push(ProloguePattern::build(&[0x48, 0x83, 0xEC], &[3], "sub_rsp"));
    p.meta.insert("compiler", "rustc");
    p.meta.insert("abi", "rust");
    p
}

/// Rust std library (`x86_64` Windows MSVC).
#[must_use]
pub fn rust_std_x64_windows() -> CompilerProfile {
    let mut p = profile!(
        "rust_std_x64_windows", "Rust std x86_64 Windows",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["std.lib", "core.lib", "alloc.lib", "compiler_builtins.lib"],
        prefixes = ["_ZN", "__rust_", "rust_begin_unwind", "core::", "std::"],
        suffixes = ["17h", "E"]
    );
    p.prologues.push(ProloguePattern::build(&[0x48, 0x89, 0x4C, 0x24, 0x08], &[], "mov_rsp8_rcx"));
    p.meta.insert("compiler", "rustc");
    p.meta.insert("abi", "rust");
    p
}

// ── MinGW profiles ────────────────────────────────────────────────────────────

/// MinGW-w64 GCC 12 `x86_64` Windows.
#[must_use]
pub fn mingw_gcc12_x64() -> CompilerProfile {
    let mut p = profile!(
        "mingw_gcc12_x64", "MinGW-w64 GCC 12 x64",
        ProfileArch::X86_64, ProfileOs::Windows, CallingConvention::MsX64,
        libs = ["libgcc.a", "libgcc_s.a", "libstdc++.a", "libmingw32.a",
                "libmingwex.a", "libmsvcrt.a", "libucrt.a", "crt2.o"],
        prefixes = ["_Z", "__", "_", "mingw_"],
        suffixes = []
    );
    p.prologues.push(ProloguePattern::build(&[0x55, 0x48, 0x89, 0xE5], &[], "push_rbp"));
    p.meta.insert("compiler", "mingw-w64");
    p.meta.insert("gcc_version", "12");
    p
}

/// `MinGW32` GCC 9 x86 Windows (old 32-bit mingw).
#[must_use]
pub fn mingw32_gcc9_x86() -> CompilerProfile {
    let mut p = profile!(
        "mingw32_gcc9_x86", "MinGW32 GCC 9 x86",
        ProfileArch::X86, ProfileOs::Windows, CallingConvention::Cdecl,
        libs = ["libgcc.a", "libstdc++.a", "libmingw32.a", "libmingwex.a"],
        prefixes = ["_Z", "__", "_"],
        suffixes = []
    );
    p.prologues.push(ProloguePattern::build(&[0x55, 0x8B, 0xEC], &[], "push_ebp_mov_esp"));
    p.meta.insert("compiler", "mingw32");
    p.meta.insert("gcc_version", "9");
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of all known compiler profiles, keyed by profile ID.
pub struct ProfileRegistry {
    profiles: HashMap<&'static str, CompilerProfile>,
}

impl ProfileRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self { profiles: HashMap::new() }
    }

    /// Create a registry pre-loaded with all built-in profiles.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut r = Self::empty();
        r.register(msvc2015_x86());
        r.register(msvc2017_x64());
        r.register(msvc2019_x64());
        r.register(msvc2022_x64());
        r.register(gcc9_x64_linux());
        r.register(gcc10_x64_linux());
        r.register(gcc11_x64_linux());
        r.register(gcc12_x64_linux());
        r.register(clang_x64_linux());
        r.register(clang_cl_x64_windows());
        r.register(rust_std_x64_linux());
        r.register(rust_std_x64_windows());
        r.register(mingw_gcc12_x64());
        r.register(mingw32_gcc9_x86());
        r
    }

    /// Add a profile to the registry.
    pub fn register(&mut self, p: CompilerProfile) {
        self.profiles.insert(p.id, p);
    }

    /// Look up a profile by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&CompilerProfile> {
        self.profiles.get(id)
    }

    /// All profiles for a given OS.
    #[must_use]
    pub fn for_os(&self, os: ProfileOs) -> Vec<&CompilerProfile> {
        self.profiles.values().filter(|p| p.os == os).collect()
    }

    /// All profiles for a given architecture.
    #[must_use]
    pub fn for_arch(&self, arch: ProfileArch) -> Vec<&CompilerProfile> {
        self.profiles.values().filter(|p| p.arch == arch).collect()
    }

    /// Find profiles whose `library_files` list contains a given filename.
    #[must_use]
    pub fn for_library(&self, filename: &str) -> Vec<&CompilerProfile> {
        let lc = filename.to_lowercase();
        self.profiles.values()
            .filter(|p| p.library_files.iter().any(|l| l.to_lowercase() == lc))
            .collect()
    }

    /// Attempt to identify which profile a function name most likely belongs to.
    #[must_use]
    pub fn identify_function<'a>(&'a self, name: &str) -> Vec<&'a CompilerProfile> {
        self.profiles.values().filter(|p| p.name_matches(name)).collect()
    }

    /// Number of registered profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// `true` when no profiles are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Iterate over all profiles.
    pub fn iter(&self) -> impl Iterator<Item = &CompilerProfile> {
        self.profiles.values()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_builtins() {
        let reg = ProfileRegistry::with_builtins();
        assert!(reg.len() >= 12);
        assert!(reg.get("msvc2022_x64").is_some());
        assert!(reg.get("rust_std_x64_linux").is_some());
    }

    #[test]
    fn test_for_os() {
        let reg = ProfileRegistry::with_builtins();
        let win = reg.for_os(ProfileOs::Windows);
        assert!(!win.is_empty());
        assert!(win.iter().all(|p| p.os == ProfileOs::Windows));
    }

    #[test]
    fn test_for_library() {
        let reg = ProfileRegistry::with_builtins();
        let hits = reg.for_library("libcmt.lib");
        // MSVC profiles include libcmt.lib.
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_name_matches() {
        let p = msvc2022_x64();
        assert!(p.name_matches("?foo@@"));
        assert!(!p.name_matches("_ZNfoo"));
    }

    #[test]
    fn test_prologue_match() {
        let p = msvc2022_x64();
        let data = &[0x48u8, 0x89, 0x4C, 0x24, 0x08, 0x00, 0x00];
        let hit = p.match_prologue(data);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().label, "mov_rsp8_rcx");
    }

    #[test]
    fn test_rust_prefix() {
        let p = rust_std_x64_linux();
        assert!(p.name_matches("_ZN3std"));
        assert!(p.name_matches("__rust_alloc"));
    }
}
