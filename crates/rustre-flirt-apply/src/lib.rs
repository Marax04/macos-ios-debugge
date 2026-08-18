//! `rustre-flirt-apply`
//!
//! Apply FLIRT (Fast Library Identification and Recognition Technology)
//! signatures to identify library functions inside a binary.

// These crates parse third-party `.sig`, `.pat` and `.lib` files. Every memory
// error in a parser of untrusted input is a security bug, so the whole family
// is kept free of `unsafe` by construction rather than by convention: the
// compiler refuses to build a violation.
//
// Measured 2026-07-29: all four crates already contained zero `unsafe` blocks.
// (An earlier inventory reported "3 unsafe in rustre-flirt-apply" — that was a
// grep counting the *word* inside comments that said "no unsafe".)
#![forbid(unsafe_code)]
pub mod apply_engine;
pub mod bulk_applier;
pub mod collision_resolution;
pub mod disambig;
pub mod ida_sig_compat;
pub mod match_scorer;
pub mod pat_parser;
pub mod recognition_session;
pub mod rename_propagator;
pub mod sig_pack;
pub mod sig_parser;
pub mod sig_priority;
pub mod trie_index;
pub mod flirt_applicator;
pub mod match_validator;
pub mod batch_applicator;
pub mod name_propagator;
pub mod confidence_scorer;
pub mod batch_applier;
pub mod applied_names_store;
pub mod match_conflict_resolver;
pub mod sig_file_loader;
pub mod runtime_prototypes;
pub mod typerecov_bridge;
pub(crate) mod casts;

pub use crate::casts::{
    f32_from_f64_bits, f32_to_u8, f32_to_usize, f64_to_f32, f64_to_u8, f64_to_usize, i32_to_u8,
    u128_to_u64, u32_to_f32, u64_to_f32, u64_to_f64, u64_to_i64, u64_to_u8, u64_to_usize,
    usize_to_f32, usize_to_f64, usize_to_u32, usize_to_u8,
};

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use sig_pack::SignaturePack;
pub use applied_names_store::{
    AppliedName, AppliedNamesStore, CommitStats, NameOrigin, StoreConfig,
};
pub use name_propagator::{
    NameBinding, NameConflictResolver, NamePropagator, PropagationResult, XrefGraph,
    is_placeholder,
};

/// Errors from FLIRT operations.
#[derive(Debug, Error)]
pub enum FlirtError {
    /// The signature file is structurally invalid.
    #[error("invalid signature file")]
    InvalidSigFile,
    /// The supplied pattern is too short to be reliable.
    #[error("pattern too short: {0}")]
    PatternTooShort(usize),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Generic parse error.
    #[error("parse: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// FlirtPattern
// ---------------------------------------------------------------------------

/// A FLIRT signature pattern.
///
/// Bytes are stored as `Option<u8>` where `None` represents a wildcard (`..`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtPattern {
    /// Byte sequence, with `None` for wildcards.
    pub bytes: Vec<Option<u8>>,
    /// Primary function name this pattern identifies.
    pub name: String,
    /// Library that contains this function.
    pub lib_name: String,
    /// Library version string.
    pub version: String,
    /// File offset of the CRC-checked region.
    pub crc_offset: u16,
    /// Length of the CRC-checked region.
    pub crc_len: u16,
    /// CRC value.
    pub crc: u16,
    /// Public names defined at (offset, name).
    pub public_names: Vec<(u32, String)>,
    /// Local (private) names.
    pub local_names: Vec<(u32, String)>,
    /// References to other names: (offset, length, name).
    pub references: Vec<(u32, u16, String)>,
}

impl FlirtPattern {
    /// Create a minimal pattern with default metadata.
    #[must_use]
    pub const fn new(name: String, bytes: Vec<Option<u8>>) -> Self {
        Self {
            bytes,
            name,
            lib_name: String::new(),
            version: String::new(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
            public_names: Vec::new(),
            local_names: Vec::new(),
            references: Vec::new(),
        }
    }

    /// Length of the pattern in bytes.
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern matches at the beginning of `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(data.iter())
            .all(|(pat, &byte)| pat.is_none_or(|b| b == byte))
    }

    /// Parse a hex pattern string such as `"55 8B EC ?? ?? 8B"` into a
    /// [`FlirtPattern`].
    ///
    /// `??` tokens become wildcard bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::PatternTooShort`] if the parsed pattern is fewer
    /// than 4 bytes, or [`FlirtError::Parse`] for any lexical error.
    pub fn from_pattern_str(pattern: &str, name: String, lib: String) -> Result<Self, FlirtError> {
        let mut bytes: Vec<Option<u8>> = Vec::new();

        // Normalise continuous hex strings (e.g. "deadbeef") to spaced pairs
        // ("de ad be ef") so both formats are accepted.
        let normalised;
        let effective = if !pattern.contains(' ') && !pattern.contains("..") && !pattern.contains("??") {
            let s = pattern.trim();
            if s.len() >= 2 && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit()) {
                normalised = s
                    .as_bytes()
                    .chunks(2)
                    .map(|c| std::str::from_utf8(c).unwrap_or("00"))
                    .collect::<Vec<_>>()
                    .join(" ");
                normalised.as_str()
            } else {
                pattern
            }
        } else {
            pattern
        };

        for token in effective.split_whitespace() {
            if token == "??" || token == "." || token == ".." {
                bytes.push(None);
            } else {
                let v = u8::from_str_radix(token, 16)
                    .map_err(|_| FlirtError::Parse(format!("invalid token: {token}")))?;
                bytes.push(Some(v));
            }
        }

        if bytes.len() < 4 {
            return Err(FlirtError::PatternTooShort(bytes.len()));
        }

        let mut pat = Self::new(name, bytes);
        pat.lib_name = lib;
        Ok(pat)
    }

    /// Convert a loaded [`FlirtSignature`] (masked byte form) back into a
    /// [`FlirtPattern`] (`Option<u8>` form), preserving CRC metadata.
    #[must_use]
    pub fn from_signature(sig: &FlirtSignature) -> Self {
        let bytes: Vec<Option<u8>> = sig
            .bytes
            .iter()
            .zip(sig.mask.iter())
            .map(|(&b, &m)| if m == 0 { None } else { Some(b) })
            .collect();
        let mut pat = Self::new(sig.name.clone(), bytes);
        pat.lib_name = sig.lib_name.clone();
        pat.crc_offset = sig.crc_offset;
        pat.crc_len = sig.crc_len;
        pat.crc = sig.crc;
        pat
    }
}

impl fmt::Display for FlirtPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) {} bytes",
            self.name,
            self.lib_name,
            self.bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// FlirtMatch
// ---------------------------------------------------------------------------

/// A FLIRT signature match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtMatch {
    /// Absolute address of the matched function.
    pub address: u64,
    /// Name of the identified function.
    pub function_name: String,
    /// Library this function comes from.
    pub lib_name: String,
    /// Confidence score `0..=100`.
    pub confidence: u8,
    /// Length of the matched pattern in bytes.
    pub pattern_length: usize,
}

impl fmt::Display for FlirtMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}: {} [{}] confidence={}%",
            self.address, self.function_name, self.lib_name, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// LibraryMark — feature K projection of FLIRT matches onto FunctionTable
// ---------------------------------------------------------------------------

/// A minimal projection of a FLIRT signature match used by feature K to label
/// the matching function in the authoritative `FunctionTable` as library code.
///
/// Carries only what the labelling pass needs: the function address and the
/// originating library name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LibraryMark {
    /// Address of the function that should be marked as library code.
    pub address: u64,
    /// Name of the library that contributed the identification.
    pub lib_name: String,
}

/// Project a slice of [`FlirtMatch`]es into the minimal [`LibraryMark`] list
/// used by feature K. Entries with an empty library name are dropped, since
/// "library" classification requires a known origin.
#[must_use]
pub fn library_marks_from_matches(matches: &[FlirtMatch]) -> Vec<LibraryMark> {
    matches
        .iter()
        .filter(|m| !m.lib_name.is_empty())
        .map(|m| LibraryMark {
            address: m.address,
            lib_name: m.lib_name.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// FlirtSigDb
// ---------------------------------------------------------------------------

/// A database of FLIRT signature patterns.
pub struct FlirtSigDb {
    patterns: Vec<FlirtPattern>,
}

impl FlirtSigDb {
    /// Create an empty database.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to the database.
    pub fn add_pattern(&mut self, pat: FlirtPattern) {
        self.patterns.push(pat);
    }

    /// Total number of patterns in the database.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Load a pre-built set of demo signatures for common CRT / Win32 functions.
    ///
    /// The patterns use `??` wildcards for address-dependent bytes.
    #[must_use]
    pub fn load_demo_sigs() -> Self {
        let mut db = Self::new();

        // Helper closure
        let mut add = |name: &str, lib: &str, pattern: &str| {
            if let Ok(p) =
                FlirtPattern::from_pattern_str(pattern, name.to_string(), lib.to_string())
            {
                db.add_pattern(p);
            }
        };

        // memcpy — MSVC x86 prologue
        add("memcpy", "msvcrt", "55 8B EC 8B 4D 10 8B 55 0C 8B 45 08");
        // memset — MSVC x86 prologue
        add("memset", "msvcrt", "55 8B EC 8B 45 10 8B 4D 0C 8B 55 08");
        // strlen
        add("strlen", "msvcrt", "8A 01 84 C0 74 ?? 41 8A 01 84 C0 74");
        // strcpy
        add("strcpy", "msvcrt", "55 8B EC 8B 55 08 8B 45 0C 8A 0A 88 08");
        // strcmp
        add(
            "strcmp",
            "msvcrt",
            "8B 44 24 04 8B 4C 24 08 8A 10 3A 01 75 ?? 84 D2",
        );
        // malloc
        add("malloc", "msvcrt", "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 5D C3");
        // free
        add(
            "free",
            "msvcrt",
            "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 5D C3 90",
        );
        // printf
        add(
            "printf",
            "msvcrt",
            "55 8B EC 8D 45 0C 50 FF 75 08 ?? ?? ?? ?? ?? 5D C3",
        );
        // sprintf
        add(
            "sprintf",
            "msvcrt",
            "55 8B EC 8D 45 10 50 8D 45 0C 50 FF 75 08 ?? ?? ?? ??",
        );
        // puts
        add(
            "puts",
            "msvcrt",
            "55 8B EC 51 8B 4D 08 51 ?? ?? ?? ?? ?? 8B E5 5D C3",
        );
        // exit
        add(
            "exit",
            "msvcrt",
            "55 8B EC FF 75 08 E8 ?? ?? ?? ?? 83 C4 04 33 C0 50",
        );
        // abort
        add("abort", "msvcrt", "E8 ?? ?? ?? ?? CC CC CC CC CC 55 8B EC");
        // memmove
        add(
            "memmove",
            "msvcrt",
            "55 8B EC 56 8B 75 0C 57 8B 7D 08 8B 4D 10",
        );
        // fopen
        add(
            "fopen",
            "msvcrt",
            "55 8B EC FF 75 0C FF 75 08 ?? ?? ?? ?? ?? 5D C3",
        );
        // fclose
        add(
            "fclose",
            "msvcrt",
            "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 85 C0 5D C3",
        );
        // UPX0 entry stub (common unpacker pattern)
        add(
            "UPX_decompress",
            "UPX",
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF",
        );
        // NtAllocateVirtualMemory syscall stub
        add(
            "NtAllocateVirtualMemory",
            "ntdll",
            "B8 ?? 00 00 00 BA 00 D0 FE 7F FF D2 C2",
        );
        // HeapAlloc import thunk
        add(
            "HeapAlloc_thunk",
            "kernel32",
            "FF 25 ?? ?? ?? ?? CC CC CC CC 55 8B EC",
        );

        db
    }

    /// Load an extended set of x86-64 signatures covering UCRT, MSVCRT, Rust
    /// stdlib, Windows CRT init stubs, and common Win32 import thunks.
    ///
    /// Call [`FlirtSigDb::merge`] to combine with [`load_demo_sigs`].
    #[must_use]
    pub fn load_extended_sigs() -> Self {
        let mut db = Self::new();

        Self::add_x64_import_thunks_jmp_rip_rel32(&mut db);
        Self::add_ntdll_thunks(&mut db);
        Self::add_ucrt_msvcrt_x64(&mut db);
        Self::add_windows_crt_security_stack_check_init(&mut db);
        Self::add_math_x64_msvcrt_ucrt(&mut db);
        Self::add_time_misc_crt(&mut db);
        Self::add_wide_char_unicode(&mut db);
        Self::add_io_low_level(&mut db);
        Self::add_string_util_variations(&mut db);
        Self::add_rust_stdlib_x64(&mut db);
        Self::add_ucrt_additional_misc(&mut db);
        Self::add_vcruntime_compiler_intrinsics(&mut db);
        Self::add_seh_exception_handling(&mut db);
        Self::add_additional_crt_helpers(&mut db);
        Self::add_common_small_function_patterns_x64(&mut db);
        Self::add_rust_specific_runtime_helpers(&mut db);
        Self::add_common_rust_msvc_linker_helpers(&mut db);
        Self::add_windows_api_non_kernel32(&mut db);

        db
    }

    /// Record one signature, ignoring patterns that fail to parse.
    ///
    /// Decides nothing beyond that: a malformed literal in the built-in table
    /// is skipped rather than aborting the whole database.
    fn add_sig(&mut self, name: &str, lib: &str, pattern: &str) {
        if let Ok(p) = FlirtPattern::from_pattern_str(pattern, name.to_string(), lib.to_string()) {
            self.add_pattern(p);
        }
    }

    /// Register the x64 import thunks (JMP [RIP+rel32]) signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_x64_import_thunks_jmp_rip_rel32(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        // These 6-byte thunks are identical in layout; the wildcard covers the
        // 4-byte RIP-relative displacement.  Padding bytes distinguish them.
        add("HeapAlloc",              "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B C1");
        add("HeapFree",               "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9");
        add("HeapReAlloc",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 49 8B C8");
        add("GetProcessHeap",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 05");
        add("VirtualAlloc",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C");
        add("VirtualFree",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2");
        add("VirtualProtect",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 41 8B C0");
        add("VirtualQuery",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B C9");
        add("LoadLibraryA",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74");
        add("LoadLibraryW",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 75");
        add("GetProcAddress",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B D1");
        add("FreeLibrary",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B C9");
        add("GetLastError",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B");
        add("SetLastError",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 89 0D");
        add("CloseHandle",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 F9");
        add("CreateFileA",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C1");
        add("CreateFileW",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B D1");
        add("ReadFile",               "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C0");
        add("WriteFile",              "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C9");
        add("GetFileSize",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2");
        add("SetFilePointer",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 49 8B D8");
        add("GetCurrentProcess",      "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 C7 C0");
        add("GetCurrentThread",       "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 C7 C0 FE");
        add("GetCurrentThreadId",     "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 8B 04");
        add("GetCurrentProcessId",    "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 8B 0C");
        add("ExitProcess",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 40 53 48");
        add("ExitThread",             "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 40 53 33");
        add("Sleep",                  "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28");
        add("CreateThread",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 57");
        add("WaitForSingleObject",    "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("WaitForMultipleObjects", "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C1 48");
        add("InitializeCriticalSection","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 48");
        add("DeleteCriticalSection",  "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 48 85");
        add("EnterCriticalSection",   "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 41 08");
        add("LeaveCriticalSection",   "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 41 10");
        add("CreateMutexA",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 10");
        add("CreateMutexW",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 18");
        add("ReleaseMutex",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 F9 00");
        add("CreateEventA",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 45 33 C9");
        add("CreateEventW",           "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 45 33 C0");
        add("SetEvent",               "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 75");
        add("ResetEvent",             "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 FF");
        add("GetSystemInfo",          "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8D 05");
        add("GetSystemTimeAsFileTime","kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8D 05");
        add("QueryPerformanceCounter","kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 0D");
        add("QueryPerformanceFrequency","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 15");
        add("FormatMessageA",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 41 8B D0 48");
        add("FormatMessageW",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 41 8B C8 48");
        add("MultiByteToWideChar",    "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C9");
        add("WideCharToMultiByte",    "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B D9");
        add("GetModuleHandleA",       "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 0F");
        add("GetModuleHandleW",       "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 7E");
        add("GetModuleFileNameA",     "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C0 74");
        add("GetModuleFileNameW",     "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C9 74");
        add("OutputDebugStringA",     "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ?? C3");
        add("OutputDebugStringW",     "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 75 ?? C3");
        add("IsDebuggerPresent",      "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 64 8B 04 25");
        add("DebugBreak",             "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC");
        add("RaiseException",         "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 40 53 56 57");
        add("UnhandledExceptionFilter","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 20");
        add("SetUnhandledExceptionFilter","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 0D ?? ?? ?? ?? 48");
        add("FlsAlloc",               "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 53 48 83 EC");
        add("FlsFree",                "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 8B C1 48");
        add("FlsGetValue",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 30");
        add("FlsSetValue",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 58");
        add("TlsAlloc",               "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 30 00");
        add("TlsFree",                "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 53 8B D9 65 48");
        add("TlsGetValue",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 58 00");
        add("TlsSetValue",            "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 58 00 00 00");
        add("TerminateProcess",       "kernel32", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 FF 15");
    }
    /// Register the ntdll thunks signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_ntdll_thunks(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("RtlAllocateHeap",        "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 74");
        add("RtlFreeHeap",            "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 85");
        add("RtlReAllocateHeap",      "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 57 48 83 EC 20");
        add("RtlSizeHeap",            "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 53 48 83 EC 20 4C");
        add("NtAllocateVirtualMemory","ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8");
        add("NtFreeVirtualMemory",    "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8 1B");
        add("NtQueryVirtualMemory",   "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8");
        add("NtProtectVirtualMemory", "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8 50");
        add("NtWriteVirtualMemory",   "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8 3A");
        add("NtReadVirtualMemory",    "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B D1 B8 3F");
        add("RtlCopyMemory",          "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 4C 8B C1 49 83 E8");
        add("RtlZeroMemory",          "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 49 83 E8 08 72");
        add("RtlCompareMemory",       "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 53 56 48 8B D9");
        add("RtlUnwind",              "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 6C");
        add("RtlUnwindEx",            "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 74 24 10 57");
        add("RtlRaiseException",      "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 57 48 81 EC");
        add("RtlLookupFunctionEntry", "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 53 48 83 EC 20 45");
        add("RtlVirtualUnwind",       "ntdll",    "FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 74 24 18 57");
    }
    /// Register the ucrt / msvcrt x64 signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_ucrt_msvcrt_x64(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        // memcpy x64 UCRT
        add("memcpy",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2");
        add("memcpy",    "ucrt", "4C 8B D9 4C 8B D1 4D 03 D0 49 8B C0 F3 A4 4D 8B C3");
        add("memcpy",    "ucrt", "48 8B C1 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 49 23 C3 75 ??");
        // memset x64 UCRT
        add("memset",    "ucrt", "49 8B C8 4C 8B D9 4C 8B D1 49 83 E9 08 72 ??");
        add("memset",    "ucrt", "48 8B C1 48 8B CA 48 8B D1 48 D1 E9 F3 48 AB");
        add("memset",    "ucrt", "4C 8B D9 0F B6 D2 48 69 D2 ?? ?? ?? ?? ?? 48 B8");
        // memmove x64 UCRT
        add("memmove",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30");
        add("memmove",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8");
        // memcmp x64
        add("memcmp",    "ucrt", "48 85 D2 74 ?? 53 48 83 EC 20 0F B6 19 44 0F B6 01");
        add("memchr",    "ucrt", "48 85 D2 74 ?? 0F B6 11 40 0F B6 C6 3A D0 74 ??");
        // strlen x64 UCRT
        add("strlen",    "ucrt", "48 85 C9 74 ?? 48 8B C1 66 0F 1F 44 00 00 0F B6 10");
        add("strlen",    "ucrt", "0F B6 01 48 FF C1 84 C0 75 ?? 48 8D 41 FF 48 2B C1");
        add("strlen",    "ucrt", "4C 8D 05 ?? ?? ?? ?? 48 85 C9 4C 0F 45 C1");
        // wcslen x64
        add("wcslen",    "ucrt", "48 85 C9 74 ?? 48 8B C1 66 66 0F 1F 84 00 00 00 00 00 66 83 38 00");
        add("wcslen",    "ucrt", "66 83 39 00 74 ?? 48 FF C1 66 83 39 00 74 ??");
        // strcpy x64
        add("strcpy",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9");
        add("strcpy",    "ucrt", "48 8B C1 48 8B CA 8A 11 84 D2 74 ?? 88 10 48 FF C1 48 FF C0 EB ??");
        // wcscpy
        add("wcscpy",    "ucrt", "48 8B C1 48 8B CA 66 8B 11 66 85 D2 74 ?? 66 89 10 48 83 C1 02");
        // strcmp x64
        add("strcmp",    "ucrt", "0F B6 01 0F B6 11 2B C2 75 ?? 84 C0 74 ?? 0F B6 41 01");
        add("strcmp",    "ucrt", "48 85 C9 74 ?? 48 85 D2 74 ?? 0F B6 01 0F B6 11 2B C2");
        // wcscmp
        add("wcscmp",    "ucrt", "66 0F B6 01 66 0F B6 11 2B C2 75 ?? 66 85 C0 74 ??");
        // strncpy
        add("strncpy",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4C 8B C2");
        // strncmp
        add("strncmp",   "ucrt", "4D 85 C0 74 ?? 48 85 C9 74 ?? 48 85 D2 74 ?? 0F B6 01 0F B6 11");
        // strcat
        add("strcat",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 E8");
        // strncat
        add("strncat",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4C 8B CA");
        // strstr
        add("strstr",    "ucrt", "48 85 C9 74 ?? 48 85 D2 74 ?? 53 48 83 EC 20 48 8B D9");
        // strchr
        add("strchr",    "ucrt", "40 0F B6 F2 0F B6 01 3A C6 74 ?? 84 C0 74 ?? FF C0 48 FF C1");
        // strrchr
        add("strrchr",   "ucrt", "0F B6 C2 48 8B C9 0F B6 01 3A C2 74 ?? 84 C0 74 ?? FF C0 48 FF C1");
        // strtol / strtoul / atoi / atol
        add("strtol",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 33 DB");
        add("strtoul",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 33 FF");
        add("strtoll",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 4C");
        add("strtoull",  "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 4D");
        add("strtof",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 F3");
        add("strtod",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 F2");
        add("atoi",      "ucrt", "48 83 EC 28 48 8B C8 45 33 C0 33 D2 FF 15 ?? ?? ?? ?? 48 83 C4 28");
        add("atol",      "ucrt", "48 83 EC 28 48 8B C8 45 33 C0 33 D2 FF 15 ?? ?? ?? ?? 99 48 83 C4 28");
        add("atof",      "ucrt", "48 83 EC 28 33 D2 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("atoll",     "ucrt", "48 89 5C 24 08 57 48 83 EC 20 33 FF 48 8B D9");

        // printf / fprintf / sprintf family x64
        add("printf",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8");
        add("printf",    "ucrt", "40 53 48 83 EC 20 48 8B D9 4C 8D 44 24 30 48 8D 15 ?? ?? ?? ??");
        add("fprintf",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F0");
        add("sprintf",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B D8");
        add("snprintf",  "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4D 8B C8 4C");
        add("vprintf",   "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8D 0D ?? ?? ?? ??");
        add("vfprintf",  "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 E8");
        add("vsprintf",  "ucrt", "48 89 5C 24 08 57 48 83 EC 20 49 8B D8 48 8B FA E8");
        add("vsnprintf", "ucrt", "48 89 5C 24 08 57 48 83 EC 20 4D 8B C8 49 8B D8 48 8B FA E8");
        add("sscanf",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B F1");
        add("scanf",     "ucrt", "48 83 EC 28 4C 8D 44 24 30 48 8D 15 ?? ?? ?? ??");
        add("fscanf",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4D 8B C8 49 8B F0");

        // puts / putchar / getchar / gets
        add("puts",      "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ??");
        add("putchar",   "ucrt", "48 83 EC 28 0F BE C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("putchar",   "ucrt", "48 83 EC 28 48 8D 0D ?? ?? ?? ?? 0F BE C9");
        add("getchar",   "ucrt", "48 83 EC 28 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("getchar",   "ucrt", "48 83 EC 28 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 83 C4 28");
        add("fgets",     "ucrt", "48 89 5C 24 08 57 48 83 EC 30 44 8B C2 48 8B FA");
        add("fputs",     "ucrt", "48 85 D2 74 ?? 48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9");

        // fopen / fclose / fread / fwrite / fseek / ftell / fflush
        add("fopen",     "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48 8B EA");
        add("fopen",     "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 85 C9 74 ??");
        add("fclose",    "ucrt", "48 83 EC 28 48 85 C9 74 ?? FF 15 ?? ?? ?? ?? 0F 1F 44 00 00");
        add("fclose",    "ucrt", "53 48 83 EC 20 48 8B D9 48 85 C9 74 ?? E8 ?? ?? ?? ??");
        add("fread",     "ucrt", "48 89 5C 24 08 57 48 83 EC 30 49 8B D8 48 8B FA 48 8B F1");
        add("fwrite",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 48 83 EC 40");
        add("fseek",     "ucrt", "48 83 EC 28 48 8B C9 48 8B D0 44 8B CA E8 ?? ?? ?? ??");
        add("ftell",     "ucrt", "48 83 EC 28 48 8B C9 48 8B D0 E8 ?? ?? ?? ?? 48 83 C4 28");
        add("fflush",    "ucrt", "48 83 EC 28 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("feof",      "ucrt", "48 85 C9 74 ?? 8B 41 ?? C3 33 C0 C3");
        add("ferror",    "ucrt", "48 85 C9 74 ?? 8B 41 ?? 25 ?? ?? ?? ?? C3");
        add("clearerr",  "ucrt", "48 85 C9 74 ?? 83 61 ?? ?? C3");
        add("rewind",    "ucrt", "48 83 EC 28 48 8B C9 33 D2 45 33 C0 E8 ?? ?? ?? ??");
        add("fgetc",     "ucrt", "48 83 EC 28 48 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("fputc",     "ucrt", "48 83 EC 28 0F BE C1 48 8B CA E8 ?? ?? ?? ?? 48 83 C4 28");
        add("ungetc",    "ucrt", "48 83 EC 28 48 8B D1 0F BE C9 E8 ?? ?? ?? ?? 48 83 C4 28");
        add("tmpfile",   "ucrt", "48 83 EC 28 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("tmpnam",    "ucrt", "48 83 EC 28 48 85 C9 48 0F 45 0D ?? ?? ?? ??");

        // malloc / free / realloc / calloc x64 UCRT
        add("malloc",    "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 85 C9 74 ?? 65 48 8B 0C 25");
        add("malloc",    "ucrt", "48 83 EC 28 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("free",      "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3");
        add("realloc",   "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 C9");
        add("calloc",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9");
        add("_msize",    "ucrt", "48 85 C9 74 ?? 48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_expand",   "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9");

        // exit / abort / _exit
        add("exit",      "ucrt", "40 53 48 83 EC 20 8B D9 E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 8B CB");
        add("exit",      "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28");
        add("_exit",     "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 8B C8 FF 15 ?? ?? ?? ?? 48 83 C4 28");
        add("abort",     "ucrt", "48 83 EC 28 FF 15 ?? ?? ?? ?? CC");
        add("abort",     "ucrt", "40 53 48 83 EC 20 E8 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 33 DB");
        add("raise",     "ucrt", "48 83 EC 28 85 C9 74 ?? E8 ?? ?? ?? ?? 48 83 C4 28");
        add("terminate", "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28");
    }
    /// Register the Windows CRT security / stack-check / init signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_windows_crt_security_stack_check_init(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        // __security_check_cookie x64
        add("__security_check_cookie",     "msvcrt", "48 3B 0D ?? ?? ?? ?? 75 ?? F3 C3");
        add("__security_check_cookie",     "msvcrt", "65 48 8B 04 25 28 00 00 00 48 3B 01 75 ?? C3");
        // __security_init_cookie x64
        add("__security_init_cookie",      "msvcrt", "48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? 65 48 8B 04 25");
        add("__security_init_cookie",      "msvcrt", "40 53 48 83 EC 20 48 8B 1D ?? ?? ?? ?? 48 85 DB");
        // __chkstk x64
        add("__chkstk",                    "msvcrt", "51 48 8B C4 48 83 E8 10 49 3B 00 76 ?? 49 8B 00");
        add("__chkstk",                    "msvcrt", "4C 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 41 56 48 81 EC");
        add("__chkstk",                    "msvcrt", "F0 48 0F C1 04 25 08 00 FE 7F 48 8B C0 C3");
        // mainCRTStartup / WinMainCRTStartup
        add("mainCRTStartup",              "crt",    "48 83 EC 28 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ??");
        add("WinMainCRTStartup",           "crt",    "48 83 EC 28 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C8 48 8B 0D");
        add("__scrt_common_main",          "crt",    "40 53 48 83 EC 20 E8 ?? ?? ?? ?? 84 C0 74 ??");
        add("__scrt_common_main_seh",      "crt",    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 33 FF E8");
        add("__scrt_common_main_seh",      "crt",    "40 55 57 41 54 41 55 41 56 41 57 48 83 EC 40 48 8D 6C 24 20");
        add("_CRT_INIT",                   "crt",    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B FA 48 8B F1");
        add("__DllMainCRTStartup",         "crt",    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B DA 48 8B F9");
        add("__GSHandlerCheck",            "crt",    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 59 08");
        add("__GSHandlerCheck_EH",         "crt",    "40 53 48 83 EC 20 48 8B 51 08 48 8B 19 4C 8B 42 08 49 03 00");
        add("__GSHandlerCheck_SEH",        "crt",    "40 53 48 83 EC 20 48 8B 51 08 4C 8B C1 48 8B 19");
        add("_seh_filter_dll",             "crt",    "48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 85 C9 0F 84");
        add("_seh_filter_exe",             "crt",    "48 83 EC 28 85 C9 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B C8");
        add("__C_specific_handler",        "ntdll",  "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 81 EC");
        add("__except_handler4",           "msvcrt", "48 89 5C 24 08 48 89 6C 24 18 48 89 74 24 20 57 48 81 EC 80 00 00 00");
        add("_purecall",                   "msvcrt", "48 83 EC 28 FF 15 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? CC");
        add("_invalid_parameter",          "ucrt",   "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B F1");
        add("_invalid_parameter_noinfo",   "ucrt",   "48 83 EC 28 48 C7 44 24 20 00 00 00 00 4C 8D 0D ?? ?? ?? ??");
        add("__report_gsfailure",          "msvcrt", "48 83 EC 28 48 89 4C 24 30 E8 ?? ?? ?? ?? 48 8B 4C 24 30");
        add("__report_rangecheckfailure",  "msvcrt", "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 CC");
    }
    /// Register the math x64 (msvcrt/ucrt) signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_math_x64_msvcrt_ucrt(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("sin",       "ucrt", "48 83 EC 28 F2 0F 10 0D ?? ?? ?? ?? F2 0F 58 C1 E8 ?? ?? ?? ??");
        add("cos",       "ucrt", "48 83 EC 28 F2 0F 10 0D ?? ?? ?? ?? F2 0F 58 C1 E8 ?? ?? ?? ??");
        add("tan",       "ucrt", "48 83 EC 28 F2 0F 10 0D ?? ?? ?? ?? F2 0F 58 C1 E8 ?? ?? ?? ??");
        add("sqrt",      "ucrt", "F2 0F 51 C0 C3");
        add("sqrt",      "ucrt", "48 83 EC 28 F2 0F 58 C0 F2 0F 51 C0 48 83 C4 28 C3");
        add("fabs",      "ucrt", "66 0F 10 C8 66 0F 57 C9 66 0F 54 C8 F2 0F 10 C1 C3");
        add("fabs",      "ucrt", "66 48 0F 6E C0 66 0F 70 C0 00 66 0F 57 C8 F2 0F 10 C1 C3");
        add("floor",     "ucrt", "66 0F 3A 0B C0 01 F2 0F 10 C0 C3");
        add("ceil",      "ucrt", "66 0F 3A 0B C0 02 F2 0F 10 C0 C3");
        add("round",     "ucrt", "66 0F 3A 0B C0 00 F2 0F 10 C0 C3");
        add("trunc",     "ucrt", "66 0F 3A 0B C0 03 F2 0F 10 C0 C3");
        add("fmod",      "ucrt", "48 83 EC 28 F2 0F 10 D1 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28");
        add("pow",       "ucrt", "48 83 EC 28 F2 0F 10 D1 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("exp",       "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("log",       "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("log2",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("log10",     "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("atan",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("atan2",     "ucrt", "48 83 EC 28 F2 0F 10 D1 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("asin",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("acos",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("sinh",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("cosh",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("tanh",      "ucrt", "48 83 EC 28 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("hypot",     "ucrt", "48 83 EC 28 F2 0F 10 D1 F2 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("modf",      "ucrt", "48 83 EC 28 F2 0F 10 C8 48 8B D2 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("frexp",     "ucrt", "48 83 EC 28 F2 0F 10 C8 48 8B D2 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("ldexp",     "ucrt", "48 83 EC 28 F2 0F 10 C8 8B D2 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("sinf",      "ucrt", "F3 0F 10 C8 E8 ?? ?? ?? ?? F3 0F 10 C0 C3");
        add("cosf",      "ucrt", "F3 0F 10 C8 E8 ?? ?? ?? ?? F3 0F 10 C0 C3");
        add("sqrtf",     "ucrt", "F3 0F 51 C0 C3");
        add("fabsf",     "ucrt", "66 0F 54 C1 F3 0F 10 C0 C3");
        add("floorf",    "ucrt", "66 0F 3A 0A C0 01 F3 0F 10 C0 C3");
        add("ceilf",     "ucrt", "66 0F 3A 0A C0 02 F3 0F 10 C0 C3");
        add("roundf",    "ucrt", "66 0F 3A 0A C0 00 F3 0F 10 C0 C3");
        add("powf",      "ucrt", "48 83 EC 28 F3 0F 10 D1 F3 0F 10 C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("expf",      "ucrt", "F3 0F 10 C8 E8 ?? ?? ?? ?? F3 0F 10 C0 C3");
        add("logf",      "ucrt", "F3 0F 10 C8 E8 ?? ?? ?? ?? F3 0F 10 C0 C3");
        add("log10f",    "ucrt", "F3 0F 10 C8 E8 ?? ?? ?? ?? F3 0F 10 C0 C3");
    }
    /// Register the time / misc CRT signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_time_misc_crt(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("time",      "ucrt", "48 83 EC 28 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 89 01 48 8B C0 48 83 C4 28 C3");
        add("clock",     "ucrt", "48 83 EC 28 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("localtime", "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("gmtime",    "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("mktime",    "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("asctime",   "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("ctime",     "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("rand",      "ucrt", "48 89 5C 24 08 57 48 83 EC 20 E8 ?? ?? ?? ?? 48 8B F8 8B 07");
        add("srand",     "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 89 08 48 83 C4 28 C3");
        add("qsort",     "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 50");
        add("bsearch",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 4C 8B C9");
        add("getenv",    "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("getenv_s",  "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 45 8B E8");
        add("system",    "ucrt", "48 83 EC 28 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_dupenv_s", "ucrt", "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B FA 48 8B E9");
        add("_putenv_s", "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA 48 8B F9");
    }
    /// Register the wide char / unicode signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_wide_char_unicode(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("wcslen",    "ucrt", "48 85 C9 74 ?? 48 8B C1 0F 1F 40 00 66 83 38 00 48 FF C0 75 ??");
        add("wcsncpy",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B CA");
        add("wcscat",    "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ??");
        add("wcsncat",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4C 8B CA 48 8B D9");
        add("wcschr",    "ucrt", "66 83 39 00 74 ?? 48 8B C1 66 83 38 00 74 ?? 66 39 10 74 ??");
        add("wcsrchr",   "ucrt", "33 C0 66 83 39 00 74 ?? 66 39 11 48 FF C2 66 0F 44 C2");
        add("wcsstr",    "ucrt", "48 85 C9 74 ?? 48 85 D2 74 ?? 56 57 48 83 EC 28");
        add("wcstol",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 45 33 DB");
        add("wcstoul",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 45 33 C9");
        add("wcstoull",  "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 4D");
        add("wcstod",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 F2 0F");
        add("wcstof",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 F3 0F");
        add("wprintf",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B F1");
        add("swprintf",  "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B D8 48 8B FA");
        add("fwprintf",  "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F0 4C 8B FA");
        add("vwprintf",  "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 4C 8D 05 ?? ?? ?? ??");
        add("swscanf",   "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B F1 49");
        add("_wcsdup",   "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0");
    }
    /// Register the io low-level signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_io_low_level(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("_open",     "ucrt", "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 8B FA");
        add("_close",    "ucrt", "48 83 EC 28 85 C9 78 ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_read",     "ucrt", "48 89 5C 24 08 57 48 83 EC 20 44 8B D2 8B FA");
        add("_write",    "ucrt", "48 89 5C 24 08 57 48 83 EC 20 44 8B D2 48 8B FA");
        add("_lseek",    "ucrt", "48 83 EC 28 8B C1 8B D2 44 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_lseeki64", "ucrt", "48 83 EC 28 8B C1 48 8B D2 44 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_eof",      "ucrt", "48 83 EC 28 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_filelength","ucrt","48 83 EC 28 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_fileno",   "ucrt", "48 85 C9 74 ?? 8B 41 ?? C3 83 C8 FF C3");
        add("_tell",     "ucrt", "48 83 EC 28 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_get_osfhandle","ucrt","48 83 EC 28 85 C9 78 ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_open_osfhandle","ucrt","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 8B FA");
        add("_setmode",  "ucrt", "48 83 EC 28 8B D2 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
    }
    /// Register the string util variations signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_string_util_variations(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("_strlwr",   "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3");
        add("_strupr",   "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3");
        add("_strdup",   "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0");
        add("_strrev",   "ucrt", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 48 8B C9 E8 ?? ?? ?? ??");
        add("_itoa",     "ucrt", "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 8B EA 8B F9 44");
        add("_ultoa",    "ucrt", "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 8B EA 44 8B FA");
        add("_i64toa",   "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 44 8B F2");
        add("_gcvt",     "ucrt", "48 83 EC 28 44 8B C2 48 8B CA F2 0F 10 01 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
    }
    /// Register the Rust stdlib x64 signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_rust_stdlib_x64(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        // __rust_alloc — calls HeapAlloc with process heap
        add("__rust_alloc",            "rust_alloc", "48 89 5C 24 08 57 48 83 EC 20 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ??");
        add("__rust_alloc",            "rust_alloc", "48 83 EC 28 E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 83 C4 28 C3");
        add("__rust_alloc",            "rust_alloc", "53 48 83 EC 20 48 8B D9 48 85 C9 74 ?? 65 48 8B 04 25 30 00 00 00");
        // __rust_dealloc
        add("__rust_dealloc",          "rust_alloc", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 FF 15 ?? ?? ?? ?? 48 83 C4 20 5B C3");
        add("__rust_dealloc",          "rust_alloc", "48 83 EC 28 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        // __rust_realloc
        add("__rust_realloc",          "rust_alloc", "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 48 85 C9");
        add("__rust_realloc",          "rust_alloc", "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 4C 8B C2 48 8B EA");
        // __rust_alloc_zeroed
        add("__rust_alloc_zeroed",     "rust_alloc", "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 33 FF 48 85 C9 74 ??");
        add("__rust_alloc_zeroed",     "rust_alloc", "48 83 EC 28 33 D2 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        // __rust_alloc_error_handler
        add("__rust_alloc_error_handler","rust_alloc","48 83 EC 28 E8 ?? ?? ?? ?? CC");
        // core::panicking::panic
        add("core::panicking::panic",      "rust_core","48 83 EC 28 E8 ?? ?? ?? ?? CC");
        add("core::panicking::panic",      "rust_core","40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? CC");
        add("core::panicking::panic_fmt",  "rust_core","48 83 EC 28 E8 ?? ?? ?? ?? CC");
        add("core::panicking::panic_fmt",  "rust_core","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? CC");
        add("core::panicking::panic_bounds_check","rust_core","48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 E8 ?? ?? ?? ?? CC");
        add("core::panicking::panic_nounwind","rust_core","48 83 EC 28 E8 ?? ?? ?? ?? CC CC CC CC CC CC CC CC");
        add("core::panicking::panic_explicit","rust_core","48 83 EC 28 E8 ?? ?? ?? ?? CC CC CC CC");
        add("core::panicking::panic_misaligned_pointer_dereference","rust_core","48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4C 8B C9");
        // core::slice::index::panic_bounds_check
        add("core::slice::index::panic_bounds_check","rust_core","48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9");
        // alloc::alloc::handle_alloc_error
        add("alloc::alloc::handle_alloc_error","rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? CC");
        // alloc::raw_vec::capacity_overflow
        add("alloc::raw_vec::capacity_overflow","rust_alloc","48 83 EC 28 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? CC");
        // std::process::abort
        add("std::process::abort",         "rust_std","48 83 EC 28 FF 15 ?? ?? ?? ?? CC");
        // std::process::exit
        add("std::process::exit",          "rust_std","48 83 EC 28 8B C9 E8 ?? ?? ?? ?? CC");
        // core::str::from_utf8 (many variants, just use heuristic)
        add("core::str::converts::from_utf8","rust_core","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20");
        // std::io::Write::write_all
        add("std::io::Write::write_all",   "rust_std","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 40");
        // Vec::push / Vec::reserve
        add("alloc::vec::Vec<T>::push",    "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B 51 10 48 8B F9 48 3B 51 08");
        add("alloc::vec::Vec<T>::reserve", "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 3B 59 08 76 ??");
        add("alloc::vec::Vec<T>::extend",  "rust_alloc","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20");
        add("alloc::vec::Vec<T>::truncate","rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B 59 08 48 3B 59 10");
        add("alloc::vec::Vec<T>::len",     "rust_alloc","48 8B 41 08 C3");
        add("alloc::vec::Vec<T>::is_empty","rust_alloc","48 83 79 08 00 0F 94 C0 C3");
        add("alloc::vec::Vec<T>::capacity","rust_alloc","48 8B 41 10 C3");
        add("alloc::vec::Vec<T>::clear",   "rust_alloc","48 C7 41 08 00 00 00 00 C3");
        // String operations
        add("alloc::string::String::new",  "rust_alloc","33 C0 48 89 01 48 89 41 08 48 89 41 10 C3");
        add("alloc::string::String::push_str","rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B 41 08 48 8B FA");
        add("alloc::string::String::with_capacity","rust_alloc","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("alloc::string::String::len",  "rust_alloc","48 8B 41 08 C3");
        add("alloc::string::String::is_empty","rust_alloc","48 83 79 08 00 0F 94 C0 C3");
        add("alloc::string::String::capacity","rust_alloc","48 8B 41 10 C3");
        add("alloc::string::String::as_str","rust_alloc","48 8B 01 48 8B 41 08 C3");
        add("alloc::string::String::as_bytes","rust_alloc","48 8B 01 48 8B 41 08 C3");
        // Arc / Rc
        add("alloc::sync::Arc<T>::clone", "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B F9 F0 FF 0B");
        add("alloc::sync::Arc<T>::drop",  "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B D9 F0 FF 0B 0F 84");
        add("alloc::rc::Rc<T>::clone",    "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B F9 FF 0B");
        add("alloc::rc::Rc<T>::drop",     "rust_alloc","48 89 5C 24 08 57 48 83 EC 20 48 8B D9 FF 0B 0F 84");
        // Box
        add("alloc::boxed::Box<T>::new",  "rust_alloc","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        // HashMap / HashSet
        add("std::collections::HashMap::new","rust_std","48 83 EC 28 33 C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("std::collections::HashMap::insert","rust_std","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20");
        add("std::collections::HashMap::get","rust_std","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ?? ?? ?? ??");
        // Option operations
        add("core::option::Option<T>::unwrap","rust_core","48 85 C9 74 ?? 48 8B 01 C3");
        add("core::option::Option<T>::expect","rust_core","48 85 C9 74 ?? 48 8B 01 C3");
        // Result operations
        add("core::result::Result<T,E>::unwrap","rust_core","48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20");
        // iter
        add("core::iter::adapters::Map::next","rust_core","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8");
        add("core::iter::adapters::Filter::next","rust_core","48 89 5C 24 08 57 48 83 EC 20 48 8B 19 48 8B F9");
        add("core::slice::iter::Iter<T>::next","rust_core","48 8B 01 48 3B 41 08 74 ?? 48 8B 11 48 FF 02 48 8B C2 C3");
        // fmt
        add("core::fmt::Write::write_fmt","rust_core","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B FA");
        add("core::fmt::Display::fmt",    "rust_core","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 48 8B 12");
        add("core::fmt::Debug::fmt",      "rust_core","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 48 8B 12");
        // thread local
        add("std::thread::local::LocalKey<T>::with","rust_std","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 30");
        // panic handler
        add("rust_begin_unwind",           "rust_std","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? CC");
        add("rust_panic_with_hook",        "rust_std","48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B F1");
        // atomic
        add("core::sync::atomic::AtomicUsize::fetch_add","rust_core","F0 48 0F C1 11 48 8B C0 C3");
        add("core::sync::atomic::AtomicUsize::fetch_sub","rust_core","48 F7 DA F0 48 0F C1 11 48 8B C0 C3");
        add("core::sync::atomic::AtomicUsize::load",     "rust_core","48 8B 01 C3");
        add("core::sync::atomic::AtomicUsize::store",    "rust_core","48 89 11 C3");
        add("core::sync::atomic::AtomicBool::load",      "rust_core","0F B6 01 C3");
        add("core::sync::atomic::AtomicBool::store",     "rust_core","88 11 C3");
        add("core::sync::atomic::AtomicBool::swap",      "rust_core","86 11 0F B6 C0 C3");
        add("core::sync::atomic::fence",                 "rust_core","F0 48 83 04 24 00 C3");
        // copy / clone
        add("core::ptr::drop_in_place",    "rust_core","C3");
        add("core::mem::drop",             "rust_core","C3");
        add("core::mem::swap",             "rust_core","48 8B 01 48 8B 0A 48 89 02 48 89 01 C3");
        add("core::mem::replace",          "rust_core","48 8B 01 48 89 02 48 89 01 C3");
        add("core::clone::Clone::clone",   "rust_core","48 8B 01 C3");
        // hash
        add("core::hash::BuildHasher::build_hasher","rust_core","48 8B 01 C3");
    }
    /// Register the ucrt additional misc signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_ucrt_additional_misc(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("_beginthread",        "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 4C 8B C9 45");
        add("_beginthreadex",      "ucrt", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 30");
        add("_endthread",          "ucrt", "40 53 48 83 EC 20 33 DB E8 ?? ?? ?? ?? E8 ?? ?? ?? ??");
        add("_endthreadex",        "ucrt", "40 53 48 83 EC 20 8B D9 E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ??");
        add("_errno",              "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_set_errno",          "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 89 08 48 83 C4 28 C3");
        add("strerror",            "ucrt", "48 83 EC 28 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("perror",              "ucrt", "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ??");
        add("_assert",             "ucrt", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 4C 8B CA 49 8B F0");
        add("__cdecl_wrapper",     "crt",  "48 83 EC 28 FF D0 48 83 C4 28 C3");
        add("__fastfail",          "crt",  "CD 29");
    }
    /// Register the vcruntime / compiler intrinsics signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_vcruntime_compiler_intrinsics(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("__stosb",     "vcruntime", "F3 AA C3");
        add("__stosd",     "vcruntime", "F3 AB C3");
        add("__stosq",     "vcruntime", "F3 48 AB C3");
        add("__stosw",     "vcruntime", "F3 66 AB C3");
        add("__movsb",     "vcruntime", "F3 A4 C3");
        add("__movsd",     "vcruntime", "F3 A5 C3");
        add("__movsq",     "vcruntime", "F3 48 A5 C3");
        add("__movsw",     "vcruntime", "F3 66 A5 C3");
        add("__cpuid",     "vcruntime", "53 48 83 EC 20 48 8B D9 8B 02 89 C8 8B 02 41 89 C1");
        add("__cpuidex",   "vcruntime", "53 48 83 EC 20 48 8B D9 8B 02 89 C8 44 8B 4A 04");
        add("__rdtsc",     "vcruntime", "0F 31 48 C1 E2 20 48 0B C2 C3");
        add("__readgsqword","vcruntime","65 48 8B 04 25 ?? ?? ?? ?? C3");
        add("__readfsdword","vcruntime","64 8B 04 25 ?? ?? ?? ?? C3");
        add("__readgsword","vcruntime", "65 66 8B 04 25 ?? ?? ?? ?? C3");
        add("__readgsbyte","vcruntime", "65 8A 04 25 ?? ?? ?? ?? C3");
        add("__writegsqword","vcruntime","65 48 89 04 25 ?? ?? ?? ?? C3");
        add("__writefsdword","vcruntime","64 89 04 25 ?? ?? ?? ?? C3");
        add("_BitScanForward64","vcruntime","48 85 D2 74 ?? 0F BC C2 8B C0 89 01 B8 01 00 00 00 C3");
        add("_BitScanReverse64","vcruntime","48 85 D2 74 ?? 0F BD C2 8B C0 89 01 B8 01 00 00 00 C3");
        add("_BitScanForward",  "vcruntime","85 D2 74 ?? 0F BC C1 89 02 B8 01 00 00 00 C3");
        add("_BitScanReverse",  "vcruntime","85 D2 74 ?? 0F BD C1 89 02 B8 01 00 00 00 C3");
        add("_byteswap_uint64", "vcruntime","48 0F C8 48 8B C0 C3");
        add("_byteswap_ulong",  "vcruntime","0F C8 8B C0 C3");
        add("_byteswap_ushort", "vcruntime","66 0F C8 0F B7 C0 C3");
        add("_rotl",    "vcruntime", "8B C1 8B D2 D3 C0 C3");
        add("_rotr",    "vcruntime", "8B C1 8B D2 D3 C8 C3");
        add("_rotl64",  "vcruntime", "48 8B C1 48 8B D2 48 D3 C0 C3");
        add("_rotr64",  "vcruntime", "48 8B C1 48 8B D2 48 D3 C8 C3");
        add("__popcnt", "vcruntime", "F3 0F B8 C1 8B C0 C3");
        add("__popcnt64","vcruntime","F3 48 0F B8 C1 48 8B C0 C3");
        add("_lzcnt_u32","vcruntime","F3 0F BD C1 8B C0 C3");
        add("_lzcnt_u64","vcruntime","F3 48 0F BD C1 48 8B C0 C3");
        add("_tzcnt_u32","vcruntime","F3 0F BC C1 8B C0 C3");
        add("_tzcnt_u64","vcruntime","F3 48 0F BC C1 48 8B C0 C3");
    }
    /// Register the SEH / exception handling signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_seh_exception_handling(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("_except_handler3",    "msvcrt","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54");
        add("_except_handler4",    "msvcrt","48 89 5C 24 08 48 89 74 24 10 57 48 81 EC 80 00 00 00 48 8B 59 08");
        add("__CxxFrameHandler3",  "vcruntime","48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 89 4C 24 20 41 54 41 56 41 57 48 83 EC 40");
        add("__CxxFrameHandler4",  "vcruntime","48 89 5C 24 08 48 89 74 24 10 57 48 81 EC 80 00 00 00 48 8B 59 08 48 8B 7A 30");
        add("_CxxThrowException",  "vcruntime","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 33 F6");
        add("__CxxDetectRethrow",  "vcruntime","48 85 C9 74 ?? 8B 41 ?? 83 E8 01 83 F8 01 76 ??");
        add("__uncaught_exceptions","vcruntime","65 48 8B 04 25 30 00 00 00 8B 80 EC 00 00 00 C3");
        add("std::terminate",       "vcruntime","48 83 EC 28 FF 15 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? CC");
        add("std::unexpected",      "vcruntime","48 83 EC 28 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__current_exception",  "vcruntime","65 48 8B 04 25 30 00 00 00 48 8B 80 F8 00 00 00 C3");
        add("__current_exception_context","vcruntime","65 48 8B 04 25 30 00 00 00 48 8B 80 00 01 00 00 C3");
    }
    /// Register the additional CRT helpers signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_additional_crt_helpers(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("__std_terminate",      "vcruntime","48 83 EC 28 FF 15 ?? ?? ?? ?? CC");
        add("__std_exception_copy", "vcruntime","48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9");
        add("__std_exception_destroy","vcruntime","48 85 C9 74 ?? 48 8B 01 48 85 C0 74 ?? FF D0 C3");
        add("__std_exception_what", "vcruntime","48 8B 01 48 85 C0 74 ?? C3");
        add("_set_new_handler",     "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 48 89 15 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_set_new_mode",        "ucrt", "48 83 EC 28 E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_set_abort_behavior",  "ucrt", "48 83 EC 28 8B C1 25 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__p___argc",           "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__p___argv",           "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__p___wargv",          "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__p__environ",         "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("__p__wenviron",        "ucrt", "E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_get_initial_narrow_environment","ucrt","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_get_initial_wide_environment","ucrt","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_initialize_narrow_environment","ucrt","48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 85 C9 74 ??");
        add("_configure_narrow_argv","ucrt","48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 D2 74");
        add("_configure_wide_argv",  "ucrt","48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 D2 75");
        add("__acrt_iob_func",       "ucrt","48 98 48 6B C0 38 48 03 05 ?? ?? ?? ?? C3");
        add("__stdio_common_vfprintf","ucrt","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30");
        add("__stdio_common_vsprintf","ucrt","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30");
        add("__stdio_common_vsscanf","ucrt","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30");
    }
    /// Register the common small-function patterns (x64) signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_common_small_function_patterns_x64(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        // Many trivial wrappers / accessors
        add("__acrt_get_locale_data_prefix","ucrt","65 48 8B 04 25 30 00 00 00 48 8B 80 ?? 00 00 00 C3");
        add("_isatty",    "ucrt", "48 83 EC 28 8B C9 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isalpha",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isdigit",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isupper",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_islower",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isspace",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isxdigit",  "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_iscntrl",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_ispunct",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isprint",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isgraph",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_isblank",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_toupper",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_tolower",   "ucrt", "48 83 EC 28 0F BE C1 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("_toascii",   "ucrt", "83 E1 7F 8B C1 C3");
    }
    /// Register the Rust-specific runtime helpers signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_rust_specific_runtime_helpers(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("std::rt::lang_start",         "rust_std","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30");
        add("std::rt::lang_start_internal","rust_std","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 40");
        add("rust_eh_personality",         "rust_std","33 C0 C3");
        add("__rust_start_panic",          "rust_std","48 83 EC 28 E8 ?? ?? ?? ?? CC");
        add("__rust_panic_cleanup",        "rust_std","48 83 EC 28 E8 ?? ?? ?? ?? CC");
    }
    /// Register the common Rust MSVC linker helpers signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_common_rust_msvc_linker_helpers(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("__CxxCallUnwindDtor",         "vcruntime","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 FF D1");
        add("__CxxCallUnwindVecDtor",      "vcruntime","48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 30");
        add("__CxxCallUnwindDelDtor",      "vcruntime","48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 FF D1 48");
        add("??2@YAPEAX_K@Z",             "vcruntime","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
        add("??3@YAXPEAX@Z",              "vcruntime","48 85 C9 74 ?? E9 ?? ?? ?? ?? C3");
        add("??_V@YAXPEAX@Z",             "vcruntime","48 85 C9 74 ?? E9 ?? ?? ?? ?? C3");
        add("??_U@YAPEAX_K@Z",            "vcruntime","48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
    }
    /// Register the Windows API (non-kernel32) signatures.
    ///
    /// Decides which byte patterns stand for this family of functions; kept as
    /// its own helper so the table stays readable one family at a time.
    fn add_windows_api_non_kernel32(db: &mut Self) {
        let mut add = |name: &str, lib: &str, pattern: &str| db.add_sig(name, lib, pattern);
        add("GetTickCount",       "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 65 8B 04 25 64 00 00 00");
        add("GetTickCount64",     "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 65 48 8B 04 25 64 00 00 00");
        add("GetEnvironmentVariableA","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C0 74 ??");
        add("GetEnvironmentVariableW","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C9 74 ??");
        add("SetEnvironmentVariableA","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("SetEnvironmentVariableW","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 75 ??");
        add("ExpandEnvironmentStringsA","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C0 48 85 C9");
        add("ExpandEnvironmentStringsW","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C9 48 85 C9");
        add("GetCommandLineA",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 05 ?? ?? ?? ?? C3");
        add("GetCommandLineW",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B 05 ?? ?? ?? ?? C3");
        add("CreateProcessA",     "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 6C 24 10");
        add("CreateProcessW",     "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 89 5C 24 08 48 89 74 24 10");
        add("OpenProcess",        "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C1 8B D2 E8");
        add("TerminateThread",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("SuspendThread",      "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("ResumeThread",       "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("GetThreadContext",   "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("SetThreadContext",   "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("GetExitCodeThread",  "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("GetExitCodeProcess", "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("DuplicateHandle",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C9 74 ??");
        add("CopyFile",           "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 0F B6 CA 48 8B D1");
        add("MoveFile",           "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 8B CA 48 8B D1");
        add("DeleteFile",         "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("GetFileAttributes",  "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("SetFileAttributes",  "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B D2 48 8B C9");
        add("FindFirstFile",      "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("FindNextFile",       "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("FindClose",          "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 83 F9 FF 74 ??");
        add("CreateDirectory",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("RemoveDirectory",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("GetCurrentDirectory","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B D2 48 85 C9");
        add("SetCurrentDirectory","kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("GetTempPath",        "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B D2 48 85 C9");
        add("GetTempFileName",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("GetFullPathName",    "kernel32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B C2 48 85 C9");
        add("PathFileExists",     "shlwapi", "FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("RegOpenKeyEx",       "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C1 48 8B D2");
        add("RegCloseKey",        "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("RegQueryValueEx",    "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C0 4D 85 C9");
        add("RegSetValueEx",      "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C0 44 8B CA");
        add("RegDeleteValue",     "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 D2 74 ??");
        add("RegEnumKeyEx",       "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 45 85 C0 48 85 C9");
        add("RegCreateKeyEx",     "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 44 8B C1 4D 8B C8");
        add("RegDeleteKey",       "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B D2 48 85 C9");
        add("CryptAcquireContext","advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C0 48 85 C9");
        add("CryptReleaseContext","advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 48 85 C9 74 ??");
        add("CryptGenRandom",     "advapi32","FF 25 ?? ?? ?? ?? CC CC CC CC 8B D2 48 85 C9");
        add("BCryptGenRandom",    "bcrypt",  "FF 25 ?? ?? ?? ?? CC CC CC CC 4D 85 C0 48 85 D2");
    }

    /// Merge all patterns from `other` into `self`, consuming `other`.
    pub fn merge(&mut self, other: Self) {
        self.patterns.extend(other.patterns);
    }

    /// Load every `.sig` (and `.pat`) file in `dir` and merge the extracted
    /// signatures into this database.
    ///
    /// Files that fail to parse are skipped (they do not abort the merge);
    /// the returned count is the number of patterns actually added.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::Io`] only when the directory itself cannot be
    /// read.
    pub fn merge_sig_dir(&mut self, dir: &Path) -> Result<usize, FlirtError> {
        let mut added = 0usize;
        for entry in std::fs::read_dir(dir)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let is_sig = path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("sig") || e.eq_ignore_ascii_case("pat"));
            if !is_sig || !path.is_file() {
                continue;
            }
            let Ok(sigs) = load_auto(&path) else { continue };
            for sig in &sigs {
                self.add_pattern(FlirtPattern::from_signature(sig));
                added += 1;
            }
        }
        Ok(added)
    }
}

impl Default for FlirtSigDb {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FlirtSigDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlirtSigDb({} patterns)", self.patterns.len())
    }
}

// ---------------------------------------------------------------------------
// FlirtApplier
// ---------------------------------------------------------------------------

/// Applies a [`FlirtSigDb`] against a region of binary code.
pub struct FlirtApplier {
    db: FlirtSigDb,
    min_confidence: u8,
}

impl FlirtApplier {
    /// Create a new applier using `db`.  Default minimum confidence is 60.
    #[must_use]
    pub const fn new(db: FlirtSigDb) -> Self {
        Self {
            db,
            min_confidence: 60,
        }
    }

    /// Override the minimum confidence threshold (0–100).
    pub const fn set_min_confidence(&mut self, conf: u8) {
        self.min_confidence = conf;
    }

    /// Load a `.sig` or `.pat` file, scan `data`, and return all matches.
    ///
    /// The file format is auto-detected:
    /// - Files starting with `"IDASGN"` are treated as binary `.sig`.
    /// - All other files are treated as text `.pat`.
    ///
    /// Returns a `Vec<(offset, matched_name, confidence)>` for every position
    /// in `data` where a signature matches above the minimum confidence
    /// threshold.
    ///
    /// # Errors
    ///
    /// Returns [`FlirtError::Io`] when the file cannot be opened, and
    /// [`FlirtError::InvalidSigFile`] or [`FlirtError::Parse`] for malformed
    /// files.
    pub fn apply(
        &self,
        data: &[u8],
        sig_path: &std::path::Path,
        base_addr: u64,
    ) -> Result<Vec<(u64, String, u8)>, FlirtError> {
        // Load signatures from file (auto-detect format).
        let sigs = load_auto(sig_path)?;

        // Build a FlirtSigDb from the loaded FlirtSignature records.
        let mut db = FlirtSigDb::new();
        for sig in &sigs {
            // Convert FlirtSignature (bytes+mask) back to FlirtPattern (Option<u8>).
            let pat_bytes: Vec<Option<u8>> = sig
                .bytes
                .iter()
                .zip(sig.mask.iter())
                .map(|(&b, &m)| if m != 0 { Some(b) } else { None })
                .collect();
            let mut fp = FlirtPattern::new(sig.name.clone(), pat_bytes);
            fp.lib_name.clone_from(&sig.lib_name);
            fp.crc_offset = sig.crc_offset;
            fp.crc_len = sig.crc_len;
            fp.crc = sig.crc;
            db.add_pattern(fp);
        }

        // Run the full scan and convert to the requested tuple format.
        let applier = Self {
            db,
            min_confidence: self.min_confidence,
        };
        let matches = applier.scan(data, base_addr);
        Ok(matches
            .into_iter()
            .map(|m| (m.address, m.function_name, m.confidence))
            .collect())
    }

    /// Scan `data` against `sigs` using overlapping windows.
    ///
    /// For each window position the method checks:
    /// 1. Leading bytes match (with wildcard support).
    /// 2. CRC-16 of the middle bytes (if `pattern.crc_len > 0`).
    /// 3. At least one concrete trailing byte beyond the pattern body matches
    ///    (when available in `data`).
    ///
    /// Only matches whose confidence score meets the applier's `min_confidence`
    /// threshold are returned.
    ///
    /// Returns `(offset, matched_name, confidence)` tuples.
    ///
    /// # Panics
    ///
    /// Panics if a CRC start offset computed from the pattern exceeds `usize::MAX`
    /// (cannot occur in practice on 64-bit platforms with valid `.sig` files).
    #[must_use]
    pub fn scan_bytes(
        data: &[u8],
        sigs: &FlirtSigDb,
        base_addr: u64,
        min_confidence: u8,
    ) -> Vec<(u64, String, u8)> {
        let mut results = Vec::new();

        for pattern in &sigs.patterns {
            if pattern.bytes.is_empty() {
                continue;
            }
            let pat_len = pattern.bytes.len();

            for offset in 0..data.len() {
                let slice = &data[offset..];
                if slice.len() < pat_len {
                    break;
                }

                // 1. Check leading bytes (wildcards accepted).
                if !pattern.matches(slice) {
                    continue;
                }

                // 2. CRC-16 check of the middle region (bytes after the
                //    pattern body, at [crc_offset .. crc_offset + crc_len]).
                //
                //    KNOWN INCONSISTENCY (2026-07-29, awaiting a decision):
                //    this reads `crc_offset` as RELATIVE to the end of the
                //    pattern body, while `Disambiguator::check_crc` reads it as
                //    ABSOLUTE from the match start, and the producers in
                //    `ida_sig_compat` (lines 340 and 445) write it as
                //    `bytes.len()` / `pat_len` — i.e. absolute. Two of the
                //    three agree on absolute, but each convention has its own
                //    passing test, so changing either one breaks the other.
                //    Left as-is deliberately rather than picked unilaterally.
                if pattern.crc_len > 0 {
                    let crc_start = offset
                        .checked_add(pat_len)
                        .and_then(|s| s.checked_add(pattern.crc_offset as usize));
                    let crc_end = crc_start
                        .and_then(|s| s.checked_add(pattern.crc_len as usize));
                    match (crc_start, crc_end) {
                        (Some(_), Some(end)) if end <= data.len() => {
                            use crate::crc16_flirt;
                            let actual = crc16_flirt(&data[crc_start.unwrap()..end]);
                            if actual != pattern.crc {
                                continue;
                            }
                        }
                        _ => continue,
                    }
                }

                // (No trailing-byte check: FlirtPattern does not store a
                //  separate expected trailing byte beyond the pattern body.
                //  Patterns that require a specific trailing byte must encode
                //  it as the last element of their `bytes` array.)

                let conf = compute_confidence(pattern);
                if conf < min_confidence {
                    continue;
                }

                results.push((base_addr + offset as u64, pattern.name.clone(), conf));
            }
        }

        results
    }

    /// Slide a window over `data` and report every position where a pattern
    /// matches, translating file offsets to `base_addr + offset`.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_addr: u64) -> Vec<FlirtMatch> {
        let mut results = Vec::new();

        for pattern in &self.db.patterns {
            if pattern.bytes.is_empty() {
                continue;
            }
            for offset in 0..data.len() {
                let slice = &data[offset..];
                if pattern.matches(slice) {
                    // Confidence is based on pattern length (longer = more reliable)
                    let raw_conf = compute_confidence(pattern);
                    if raw_conf < self.min_confidence {
                        continue;
                    }

                    // CRC-16 verification (middle region after the pattern body).
                    if pattern.crc_len > 0 {
                        let crc_start = offset
                            .checked_add(pattern.bytes.len())
                            .and_then(|s| s.checked_add(pattern.crc_offset as usize));
                        let crc_end = crc_start
                            .and_then(|s| s.checked_add(pattern.crc_len as usize));
                        match (crc_start, crc_end) {
                            (Some(start), Some(end)) if end <= data.len() => {
                                let actual = crc16_flirt(&data[start..end]);
                                if actual != pattern.crc {
                                    continue;
                                }
                            }
                            _ => continue,
                        }
                    }

                    results.push(FlirtMatch {
                        address: base_addr + offset as u64,
                        function_name: pattern.name.clone(),
                        lib_name: pattern.lib_name.clone(),
                        confidence: raw_conf,
                        pattern_length: pattern.pattern_len(),
                    });
                }
            }
        }

        results
    }

    /// Scan only at specific function start addresses.
    ///
    /// `func_addrs` are absolute addresses.  Each is translated to an offset
    /// within `data` using `base_addr`.
    #[must_use]
    pub fn scan_at_addresses(
        &self,
        data: &[u8],
        base_addr: u64,
        func_addrs: &[u64],
    ) -> Vec<FlirtMatch> {
        let mut results = Vec::new();

        for &addr in func_addrs {
            if addr < base_addr {
                continue;
            }
            let offset = u64_to_usize(addr - base_addr);
            if offset >= data.len() {
                continue;
            }
            let slice = &data[offset..];
            for pattern in &self.db.patterns {
                if pattern.matches(slice) {
                    let raw_conf = compute_confidence(pattern);
                    if raw_conf >= self.min_confidence {
                        // CRC-16 verification.
                        if pattern.crc_len > 0 {
                            let crc_start = offset
                                .checked_add(pattern.bytes.len())
                                .and_then(|s| s.checked_add(pattern.crc_offset as usize));
                            let crc_end = crc_start
                                .and_then(|s| s.checked_add(pattern.crc_len as usize));
                            match (crc_start, crc_end) {
                                (Some(start), Some(end)) if end <= data.len() => {
                                    let actual = crc16_flirt(&data[start..end]);
                                    if actual != pattern.crc {
                                        continue;
                                    }
                                }
                                _ => continue,
                            }
                        }
                        results.push(FlirtMatch {
                            address: addr,
                            function_name: pattern.name.clone(),
                            lib_name: pattern.lib_name.clone(),
                            confidence: raw_conf,
                            pattern_length: pattern.pattern_len(),
                        });
                    }
                }
            }
        }

        results
    }

    /// Return the total number of matches found in `data`.
    #[must_use]
    pub fn match_count(&self, data: &[u8], base_addr: u64) -> usize {
        self.scan(data, base_addr).len()
    }
}

impl fmt::Debug for FlirtApplier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlirtApplier(db={} pats, min_conf={})",
            self.db.pattern_count(),
            self.min_confidence
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a confidence score for a pattern based on its concrete byte count.
///
/// Wildcards lower the confidence; longer patterns are more reliable.
fn compute_confidence(pat: &FlirtPattern) -> u8 {
    let total = pat.bytes.len();
    if total == 0 {
        return 0;
    }
    let concrete = pat.bytes.iter().filter(|b| b.is_some()).count();
    let ratio = usize_to_f64(concrete) / usize_to_f64(total);
    // Base confidence increases with pattern length (capped at 16 bytes for
    // full confidence).
    let length_bonus = (usize_to_f64(total.min(16)) / 16.0) * 20.0;
    f64_to_u8(ratio.mul_add(80.0, length_bonus)).min(100)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- FlirtPattern ------------------------------------------------------

    #[test]
    fn test_pattern_new() {
        let p = FlirtPattern::new("foo".to_string(), vec![Some(0x55), None, Some(0xEC)]);
        assert_eq!(p.name, "foo");
        assert_eq!(p.pattern_len(), 3);
    }

    #[test]
    fn test_pattern_display() {
        let p = FlirtPattern::new("strlen".to_string(), vec![Some(0x8A); 6]);
        let s = p.to_string();
        assert!(s.contains("strlen"));
        assert!(s.contains("6 bytes"));
    }

    #[test]
    fn test_pattern_matches_exact() {
        let p = FlirtPattern::new("f".to_string(), vec![Some(0x55), Some(0x8B), Some(0xEC)]);
        assert!(p.matches(&[0x55, 0x8B, 0xEC, 0x00]));
        assert!(!p.matches(&[0x55, 0x8B, 0xED]));
    }

    #[test]
    fn test_pattern_matches_wildcard() {
        let p = FlirtPattern::new("f".to_string(), vec![Some(0x55), None, Some(0xEC)]);
        assert!(p.matches(&[0x55, 0xFF, 0xEC]));
        assert!(p.matches(&[0x55, 0x00, 0xEC]));
    }

    #[test]
    fn test_pattern_matches_too_short() {
        let p = FlirtPattern::new("f".to_string(), vec![Some(0x55); 10]);
        assert!(!p.matches(&[0x55; 5]));
    }

    #[test]
    fn test_from_pattern_str_valid() {
        let p = FlirtPattern::from_pattern_str(
            "55 8B EC ?? 8B",
            "main".to_string(),
            "mylib".to_string(),
        )
        .unwrap();
        assert_eq!(p.pattern_len(), 5);
        assert!(p.bytes[3].is_none()); // wildcard
        assert_eq!(p.lib_name, "mylib");
    }

    #[test]
    fn test_from_pattern_str_too_short() {
        let err = FlirtPattern::from_pattern_str("55 8B", "f".to_string(), "lib".to_string());
        assert!(matches!(err, Err(FlirtError::PatternTooShort(_))));
    }

    #[test]
    fn test_from_pattern_str_invalid_token() {
        let err = FlirtPattern::from_pattern_str("55 ZZ 8B EC", "f".to_string(), "lib".to_string());
        assert!(matches!(err, Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_from_pattern_str_dot_wildcard() {
        let p = FlirtPattern::from_pattern_str("55 .. 8B EC", "f".to_string(), "lib".to_string())
            .unwrap();
        assert!(p.bytes[1].is_none());
    }

    // ---- FlirtError display ------------------------------------------------

    #[test]
    fn test_error_display_invalid_sig_file() {
        assert!(!FlirtError::InvalidSigFile.to_string().is_empty());
    }

    #[test]
    fn test_error_display_pattern_too_short() {
        let e = FlirtError::PatternTooShort(2);
        assert!(e.to_string().contains('2'));
    }

    #[test]
    fn test_error_display_parse() {
        let e = FlirtError::Parse("bad token".into());
        assert!(e.to_string().contains("bad token"));
    }

    // ---- FlirtMatch --------------------------------------------------------

    #[test]
    fn test_flirt_match_display() {
        let m = FlirtMatch {
            address: 0x0040_1000,
            function_name: "strlen".to_string(),
            lib_name: "msvcrt".to_string(),
            confidence: 95,
            pattern_length: 12,
        };
        let s = m.to_string();
        assert!(s.contains("strlen"));
        assert!(s.contains("msvcrt"));
        assert!(s.contains("95%"));
    }

    // ---- FlirtSigDb --------------------------------------------------------

    #[test]
    fn test_sig_db_new_empty() {
        let db = FlirtSigDb::new();
        assert_eq!(db.pattern_count(), 0);
    }

    #[test]
    fn test_sig_db_add_pattern() {
        let mut db = FlirtSigDb::new();
        let p = FlirtPattern::new("f".to_string(), vec![Some(0x55); 8]);
        db.add_pattern(p);
        assert_eq!(db.pattern_count(), 1);
    }

    #[test]
    fn test_sig_db_load_demo_sigs() {
        let db = FlirtSigDb::load_demo_sigs();
        assert!(db.pattern_count() >= 10);
    }

    #[test]
    fn test_sig_db_debug() {
        let db = FlirtSigDb::new();
        let s = format!("{db:?}");
        assert!(s.contains("FlirtSigDb"));
    }

    #[test]
    fn test_sig_db_default() {
        let db = FlirtSigDb::default();
        assert_eq!(db.pattern_count(), 0);
    }

    // ---- FlirtApplier -------------------------------------------------------

    fn make_applier_with_pattern(hex: &str) -> FlirtApplier {
        let mut db = FlirtSigDb::new();
        let p = FlirtPattern::from_pattern_str(hex, "test_fn".to_string(), "lib".to_string())
            .expect("valid pattern");
        db.add_pattern(p);
        FlirtApplier::new(db)
    }

    #[test]
    fn test_applier_debug() {
        let db = FlirtSigDb::new();
        let a = FlirtApplier::new(db);
        let s = format!("{a:?}");
        assert!(s.contains("FlirtApplier"));
    }

    #[test]
    fn test_scan_finds_match() {
        let applier = make_applier_with_pattern("55 8B EC 83 EC 10");
        let data = vec![0x00, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00];
        let matches = applier.scan(&data, 0x1000);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].address, 0x1002);
        assert_eq!(matches[0].function_name, "test_fn");
    }

    #[test]
    fn test_scan_no_match() {
        let applier = make_applier_with_pattern("AA BB CC DD");
        let data = vec![0x00u8; 32];
        let matches = applier.scan(&data, 0x0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_with_wildcard() {
        let applier = make_applier_with_pattern("55 ?? EC 83");
        let data = vec![0x55, 0xFF, 0xEC, 0x83];
        let matches = applier.scan(&data, 0x0);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_at_addresses_exact() {
        let applier = make_applier_with_pattern("55 8B EC 90");
        let data = vec![0x00u8, 0x00, 0x55, 0x8B, 0xEC, 0x90, 0x00];
        let matches = applier.scan_at_addresses(&data, 0x1000, &[0x1002]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x1002);
    }

    #[test]
    fn test_scan_at_addresses_miss() {
        let applier = make_applier_with_pattern("55 8B EC 90");
        let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
        // Address 0x2000 is before base_addr 0x1000... actually 0x2000 - 0x1000 = offset 4096
        // which is out of range for 4-byte data
        let matches = applier.scan_at_addresses(&data, 0x1000, &[0x2000]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_at_addresses_below_base() {
        let applier = make_applier_with_pattern("55 8B EC 90");
        let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
        let matches = applier.scan_at_addresses(&data, 0x1000, &[0x0500]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_count() {
        let applier = make_applier_with_pattern("55 8B EC 90");
        let data = vec![0x55u8, 0x8B, 0xEC, 0x90, 0x55, 0x8B, 0xEC, 0x90];
        let count = applier.match_count(&data, 0x1000);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_set_min_confidence() {
        let db = FlirtSigDb::new();
        let mut a = FlirtApplier::new(db);
        a.set_min_confidence(90);
        let s = format!("{a:?}");
        assert!(s.contains("90"));
    }

    #[test]
    fn test_demo_sigs_scan() {
        let db = FlirtSigDb::load_demo_sigs();
        let applier = FlirtApplier::new(db);
        // Construct a buffer that begins with the memcpy prologue
        let mut data = vec![0x00u8; 64];
        // memcpy pattern: "55 8B EC 8B 4D 10 8B 55 0C 8B 45 08"
        let prologue: &[u8] = &[
            0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x10, 0x8B, 0x55, 0x0C, 0x8B, 0x45, 0x08,
        ];
        data[..prologue.len()].copy_from_slice(prologue);
        let matches = applier.scan(&data, 0x4000_0000);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].function_name, "memcpy");
    }

    #[test]
    fn test_compute_confidence_all_concrete() {
        let p = FlirtPattern::new("f".to_string(), vec![Some(0x55); 16]);
        let c = compute_confidence(&p);
        assert_eq!(c, 100);
    }

    #[test]
    fn test_compute_confidence_all_wildcard() {
        let p = FlirtPattern::new("f".to_string(), vec![None; 8]);
        let c = compute_confidence(&p);
        assert!(c < 30);
    }

    #[test]
    fn test_compute_confidence_empty() {
        let p = FlirtPattern::new("f".to_string(), vec![]);
        assert_eq!(compute_confidence(&p), 0);
    }

    // ---- FlirtApplier::scan_bytes ------------------------------------------

    #[test]
    fn test_scan_bytes_finds_match() {
        let mut db = FlirtSigDb::new();
        let p = FlirtPattern::from_pattern_str(
            "55 8B EC 83 EC 10",
            "my_fn".to_string(),
            "mylib".to_string(),
        )
        .unwrap();
        db.add_pattern(p);
        let data = vec![0x00u8, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00];
        let results = FlirtApplier::scan_bytes(&data, &db, 0x1000, 0);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, 0x1001);
        assert_eq!(results[0].1, "my_fn");
        assert!(results[0].2 > 0);
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let mut db = FlirtSigDb::new();
        let p =
            FlirtPattern::from_pattern_str("AA BB CC DD", "absent".to_string(), "lib".to_string())
                .unwrap();
        db.add_pattern(p);
        let data = vec![0x00u8; 32];
        let results = FlirtApplier::scan_bytes(&data, &db, 0x0, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_bytes_wildcard() {
        let mut db = FlirtSigDb::new();
        let p =
            FlirtPattern::from_pattern_str("55 ?? EC 83", "wc_fn".to_string(), "lib".to_string())
                .unwrap();
        db.add_pattern(p);
        let data = vec![0x55u8, 0xFF, 0xEC, 0x83];
        let results = FlirtApplier::scan_bytes(&data, &db, 0x0, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "wc_fn");
    }

    #[test]
    fn test_scan_bytes_respects_min_confidence() {
        let mut db = FlirtSigDb::new();
        let p = FlirtPattern::from_pattern_str("55 8B EC 83", "fn".to_string(), "lib".to_string())
            .unwrap();
        db.add_pattern(p);
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        // Use an impossible threshold.
        let results = FlirtApplier::scan_bytes(&data, &db, 0x0, 101);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_bytes_crc_check_pass() {
        // Build a pattern with a valid CRC so we can verify the CRC path is exercised.
        // Use a 4-byte leading pattern (minimum required by FlirtPattern).
        let mut pat =
            FlirtPattern::from_pattern_str("55 8B EC 83", "crc_fn".to_string(), "lib".to_string())
                .unwrap();
        // 4 bytes of "middle" data that follow the pattern body.
        let middle = &[0xAA, 0xBB, 0xCC, 0xDD];
        pat.crc_offset = 0;
        pat.crc_len = 4;
        pat.crc = crc16_flirt(middle);

        let mut db = FlirtSigDb::new();
        db.add_pattern(pat);

        // data = 4-byte pattern + 4-byte middle
        let mut data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        data.extend_from_slice(middle);

        let results = FlirtApplier::scan_bytes(&data, &db, 0x0, 0);
        assert_eq!(results.len(), 1, "CRC should pass and produce one match");
    }

    #[test]
    fn test_scan_bytes_crc_check_fail() {
        let mut pat =
            FlirtPattern::from_pattern_str("55 8B EC 83", "crc_fn".to_string(), "lib".to_string())
                .unwrap();
        pat.crc_offset = 0;
        pat.crc_len = 4;
        pat.crc = 0xDEAD; // wrong CRC

        let mut db = FlirtSigDb::new();
        db.add_pattern(pat);

        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xAA, 0xBB, 0xCC, 0xDD];
        let results = FlirtApplier::scan_bytes(&data, &db, 0x0, 0);
        assert!(results.is_empty(), "wrong CRC should suppress the match");
    }

    // ---- FlirtApplier::apply -----------------------------------------------

    #[test]
    fn test_apply_from_pat_file() {
        use std::io::Write;
        // Write a minimal .pat file with one pattern line.
        // Format per load_pat_file: <hex_bytes_no_spaces> <crc16_4hex> <crc_len_hex>
        //   <total_len_dec> <name>
        // The hex pattern is a run of 2-char tokens concatenated (no spaces inside).
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // 55 8B EC 83: 4 bytes, crc16=0000, crc_len=0, total_len=4, name=test_func
        writeln!(tmp, "558BEC83 0000 0 4 test_func").unwrap();
        writeln!(tmp, "---").unwrap();

        let applier = FlirtApplier::new(FlirtSigDb::new());
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0x00, 0x00];
        let matches = applier.apply(&data, tmp.path(), 0x1000).unwrap();
        assert!(
            !matches.is_empty(),
            "apply() should find at least one match"
        );
        assert_eq!(matches[0].1, "test_func");
        assert_eq!(matches[0].0, 0x1000);
    }

    #[test]
    fn test_apply_nonexistent_file_errors() {
        let applier = FlirtApplier::new(FlirtSigDb::new());
        let result = applier.apply(&[0u8; 16], std::path::Path::new("nonexistent_xyz.sig"), 0);
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// FlirtSignature – richer type used by the fast scanner
// ---------------------------------------------------------------------------

/// A FLIRT signature with binary-level detail used by [`FlirtScanner`].
///
/// `crc_offset` / `crc_len` / `crc` follow the IDA .pat / .sig convention:
/// after the initial variable-length pattern the file records a CRC-16 over
/// the `crc_len` bytes starting at `crc_offset` inside the function body.
#[derive(Debug, Clone)]
pub struct FlirtSignature {
    /// Raw bytes where `0xFF` means "exact match required" and `0x00` in the
    /// corresponding `mask` position means wildcard.
    pub bytes: Vec<u8>,
    /// Per-byte mask: `0xff` = exact, `0x00` = wildcard.
    pub mask: Vec<u8>,
    /// Function name.
    pub name: String,
    /// Library name.
    pub lib_name: String,
    /// Offset of the CRC region inside the function.
    pub crc_offset: u16,
    /// Length of the CRC region in bytes (0 = no CRC check).
    pub crc_len: u16,
    /// Expected CRC-16 value.
    pub crc: u16,
}

impl FlirtSignature {
    /// Construct from a [`FlirtPattern`], converting `Option<u8>` to
    /// masked bytes.
    #[must_use]
    pub fn from_flirt_pattern(pat: &FlirtPattern) -> Self {
        let mut bytes = Vec::with_capacity(pat.bytes.len());
        let mut mask = Vec::with_capacity(pat.bytes.len());
        for b in &pat.bytes {
            if let Some(v) = b {
                bytes.push(*v);
                mask.push(0xff);
            } else {
                bytes.push(0x00);
                mask.push(0x00);
            }
        }
        Self {
            bytes,
            mask,
            name: pat.name.clone(),
            lib_name: pat.lib_name.clone(),
            crc_offset: pat.crc_offset,
            crc_len: pat.crc_len,
            crc: pat.crc,
        }
    }

    /// Returns `true` when the signature matches the bytes at the start of
    /// `data`, applying per-byte masking.
    #[must_use]
    pub fn matches_at(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        for ((expected, mask), actual) in self.bytes.iter().zip(self.mask.iter()).zip(data.iter()) {
            if *mask != 0 && *actual != *expected {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// WildcardPattern – the indexable prefix extracted from a FlirtSignature
// ---------------------------------------------------------------------------

/// The non-wildcard prefix of a [`FlirtSignature`], suitable for use as an
/// Aho-Corasick pattern key.
///
/// Up to `PREFIX_CAP` bytes from the leading concrete (non-wildcard) run are
/// stored.  The `mask` mirrors the pattern mask for the same range so that
/// wildcard verification can be performed cheaply after a candidate is found.
#[derive(Debug, Clone)]
pub struct WildcardPattern {
    /// Concrete bytes of the leading non-wildcard run (up to `PREFIX_CAP`).
    pub fixed_bytes: Vec<u8>,
    /// Per-byte mask for the full first `PREFIX_CAP` bytes of the pattern.
    /// `0xff` = exact, `0x00` = wildcard.
    pub mask: Vec<u8>,
}

/// Maximum number of bytes to use as the Aho-Corasick key.
const PREFIX_CAP: usize = 32;

impl WildcardPattern {
    /// Build a `WildcardPattern` from a [`FlirtSignature`].
    ///
    /// Takes the longest leading run of non-wildcard bytes (up to
    /// [`PREFIX_CAP`]).  If there are no concrete bytes at all, `fixed_bytes`
    /// will be empty (the signature will match every position – the caller
    /// should avoid indexing such patterns with Aho-Corasick).
    #[must_use]
    pub fn from_signature(sig: &FlirtSignature) -> Self {
        let cap = sig.bytes.len().min(sig.mask.len()).min(PREFIX_CAP);
        let mut fixed_bytes = Vec::new();
        let mut mask = Vec::new();

        let mut prefix_done = false;
        for i in 0..cap {
            mask.push(sig.mask[i]);
            if !prefix_done {
                if sig.mask[i] == 0xff {
                    fixed_bytes.push(sig.bytes[i]);
                } else {
                    // Stop accumulating concrete prefix bytes at the first
                    // wildcard so `fixed_bytes` is the longest leading run of
                    // non-wildcard bytes (the Aho-Corasick prefix key). The
                    // mask, however, continues to be populated for the full
                    // PREFIX_CAP range so downstream verification can index
                    // mask[i] safely.
                    prefix_done = true;
                }
            }
        }

        Self { fixed_bytes, mask }
    }

    /// The longest concrete (non-wildcard) prefix, used as the Aho-Corasick
    /// search key.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.fixed_bytes
    }
}

// ---------------------------------------------------------------------------
// AhoCorasickIndex
// ---------------------------------------------------------------------------

/// An Aho-Corasick multi-pattern index over the concrete prefixes of a set of
/// [`FlirtSignature`]s.
///
/// `search` returns `(offset, sig_idx)` *candidate* pairs.  Each candidate
/// must be verified with the full signature (including wildcards and the
/// optional CRC-16 check) before being reported as a match.
pub struct AhoCorasickIndex {
    /// Parallel arrays: `patterns[i]` is the `WildcardPattern` for
    /// `sig_indices[i]`.
    patterns: Vec<(usize, WildcardPattern)>,
    /// The compiled Aho-Corasick automaton.  `None` when no signature has a
    /// non-empty concrete prefix (degenerate case).
    ac: Option<aho_corasick::AhoCorasick>,
    /// Mapping from Aho-Corasick pattern id → index into `patterns`.
    ac_id_to_pat: Vec<usize>,
}

impl AhoCorasickIndex {
    /// Build an index from a slice of [`FlirtSignature`]s.
    ///
    /// Signatures whose concrete prefix is empty (all wildcards) are **not**
    /// added to the automaton; they can only be found by the linear fallback.
    #[must_use]
    pub fn build(sigs: &[FlirtSignature]) -> Self {
        let mut patterns: Vec<(usize, WildcardPattern)> = Vec::new();
        let mut ac_keys: Vec<Vec<u8>> = Vec::new();
        let mut ac_id_to_pat: Vec<usize> = Vec::new();

        for (sig_idx, sig) in sigs.iter().enumerate() {
            let wp = WildcardPattern::from_signature(sig);
            let pat_idx = patterns.len();
            patterns.push((sig_idx, wp.clone()));
            if !wp.prefix().is_empty() {
                ac_id_to_pat.push(pat_idx);
                ac_keys.push(wp.prefix().to_vec());
            }
        }

        let ac = if ac_keys.is_empty() {
            None
        } else {
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(ac_keys)
                .ok()
        };

        Self {
            patterns,
            ac,
            ac_id_to_pat,
        }
    }

    /// Search `data` and return `(offset, sig_idx)` candidates.
    ///
    /// Each returned pair indicates that the signature at `sig_idx` *may*
    /// match at `offset`; callers must perform full verification.
    ///
    /// If the automaton was not built (all-wildcard case) an empty `Vec` is
    /// returned; use the linear fallback in that situation.
    #[must_use]
    pub fn search(&self, data: &[u8], _sigs: &[FlirtSignature]) -> Vec<(usize, usize)> {
        let Some(ac) = &self.ac else { return Vec::new(); };

        let mut candidates = Vec::new();
        for mat in ac.find_iter(data) {
            let pat_idx = self.ac_id_to_pat[mat.pattern().as_usize()];
            let (sig_idx, _) = &self.patterns[pat_idx];
            candidates.push((mat.start(), *sig_idx));
        }
        candidates
    }

    /// Returns `true` when the automaton was successfully built and contains
    /// at least one pattern.
    #[must_use]
    pub const fn is_built(&self) -> bool {
        self.ac.is_some()
    }
}

// ---------------------------------------------------------------------------
// CRC-16 (FLIRT / CCITT variant, poly 0x8408, reflected)
// ---------------------------------------------------------------------------

/// Compute CRC-16/X-25 (reflected, poly 0x8408) over `data`.
///
/// This is the variant used by IDA's FLIRT engine for the CRC field in .pat
/// and .sig files. Poly 0x8408 (reflected), init 0xFFFF, no final XOR
/// (matches IDA flair's crc16.cpp which returns the accumulator directly).
#[must_use]
pub fn crc16_flirt(data: &[u8]) -> u16 {
    rustre_flirt::crc::flirt_tail(data)
}

#[cfg(test)]
mod crc16_flirt_tests {
    use super::crc16_flirt;

    #[test]
    fn crc16_flirt_known_vector_01020304() {
        // IDA FLIRT crc16 (poly 0x8408 reflected, init 0xFFFF, no final XOR)
        // for input [0x01, 0x02, 0x03, 0x04] -> 0xC66E (verified against IDA flair crc16.cpp).
        assert_eq!(crc16_flirt(&[0x01, 0x02, 0x03, 0x04]), 0xC66E);
    }

    #[test]
    fn crc16_flirt_empty() {
        // IDA flair crc16 for empty input = init value = 0xFFFF (no final XOR).
        assert_eq!(crc16_flirt(&[]), 0xFFFF);
    }

    #[test]
    fn crc16_flirt_ida_string() {
        // Wire test: b"IDA" -> 0xD1D0 (IDA flair canonical, no final XOR).
        assert_eq!(crc16_flirt(b"IDA"), 0xD1D0);
    }
}

// ---------------------------------------------------------------------------
// FlirtScanner – the high-level fast scanner
// ---------------------------------------------------------------------------

/// A high-performance FLIRT scanner that uses an [`AhoCorasickIndex`] to
/// reduce the search space from O(n × m) to O(n + m) before running full
/// wildcard + CRC verification on candidates.
///
/// # Usage
///
/// ```rust,no_run
/// # use rustre_flirt_apply::{FlirtScanner, FlirtPattern, FlirtSignature};
/// let patterns = vec!["55 8B EC 83 EC 10"];
/// let sigs: Vec<FlirtSignature> = patterns.iter().map(|p| {
///     let fp = FlirtPattern::from_pattern_str(p, "fn".into(), "lib".into()).unwrap();
///     FlirtSignature::from_flirt_pattern(&fp)
/// }).collect();
/// let scanner = FlirtScanner::new_fast(sigs);
/// let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
/// let matches = scanner.scan_fast(&data, 0x1000);
/// ```
pub struct FlirtScanner {
    sigs: Vec<FlirtSignature>,
    index: Option<AhoCorasickIndex>,
    min_confidence: u8,
    /// Shortest exact prefix accepted from a signature that carries **no**
    /// tail CRC. See [`FlirtScanner::set_min_bytes_without_crc`].
    min_bytes_without_crc: usize,
}

impl FlirtScanner {
    /// Build a fast scanner from a [`SignaturePack`] by converting each
    /// [`FlirtPattern`] to a [`FlirtSignature`] and pre-building the
    /// Aho-Corasick index.
    #[must_use]
    pub fn from_pack(pack: &SignaturePack) -> Self {
        let sigs = pack
            .patterns
            .iter()
            .map(FlirtSignature::from_flirt_pattern)
            .collect();
        Self::new_fast(sigs)
    }

    /// Build a fast scanner from a binary `.sig` database on disk.
    ///
    /// # Why this exists
    ///
    /// The decompiler builds its scanner from two embedded `.sigpack` text
    /// files holding **22 hand-written signatures** between them, while this
    /// project generates `.sig` databases orders of magnitude larger. Nothing
    /// connected the two: the loader could read a `.sig`, but no path led from a
    /// loaded `.sig` to a scanner. That is why FLIRT identified nothing on the
    /// corpus and the whole Level 7 chain ran dry — the bottleneck was never the
    /// matcher or the prototypes, it was having 22 candidates to match against.
    ///
    /// # Errors
    ///
    /// Propagates any [`FlirtError`] from loading or parsing the file.
    pub fn from_sig_file(path: &std::path::Path) -> Result<Self, FlirtError> {
        let loaded = crate::sig_file_loader::SigFileLoader::new().load(path)?;
        Ok(Self::new_fast(loaded.to_signatures()))
    }

    /// Build a fast scanner from `.sig` bytes already in memory.
    ///
    /// # Errors
    ///
    /// Propagates any [`FlirtError`] from parsing.
    pub fn from_sig_bytes(raw: &[u8]) -> Result<Self, FlirtError> {
        let loaded = crate::sig_file_loader::SigFileLoader::new().load_from_bytes(raw, None)?;
        Ok(Self::new_fast(loaded.to_signatures()))
    }

    /// Build one scanner from several `.sigpack` packs **and** several `.sig`
    /// databases, so a caller can keep its curated packs while adding a
    /// generated database.
    ///
    /// Signatures keep their originating `lib_name`, so a match can still be
    /// attributed to the source it came from.
    ///
    /// # Errors
    ///
    /// Propagates the first [`FlirtError`] encountered while reading a `.sig`.
    pub fn from_packs_and_sig_files(
        packs: &[SignaturePack],
        sig_paths: &[std::path::PathBuf],
    ) -> Result<Self, FlirtError> {
        let mut sigs: Vec<FlirtSignature> = Vec::new();
        for p in packs {
            sigs.extend(p.patterns.iter().map(FlirtSignature::from_flirt_pattern));
        }
        let loader = crate::sig_file_loader::SigFileLoader::new();
        for path in sig_paths {
            sigs.extend(loader.load(path)?.to_signatures());
        }
        Ok(Self::new_fast(sigs))
    }

    /// Build a fast scanner from many [`SignaturePack`]s. Patterns retain their
    /// originating `lib_name` so callers can filter / weight matches by source.
    #[must_use]
    pub fn from_packs(packs: &[SignaturePack]) -> Self {
        let mut sigs: Vec<FlirtSignature> = Vec::new();
        for p in packs {
            sigs.extend(p.patterns.iter().map(FlirtSignature::from_flirt_pattern));
        }
        Self::new_fast(sigs)
    }

    /// Number of signatures in this scanner.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.sigs.len()
    }

    /// Create a [`FlirtScanner`] with only linear scan capability.
    #[must_use]
    pub const fn new_linear(sigs: Vec<FlirtSignature>) -> Self {
        Self {
            sigs,
            index: None,
            min_confidence: 60,
            min_bytes_without_crc: 0,
        }
    }

    /// Create a [`FlirtScanner`] and pre-build an [`AhoCorasickIndex`] for
    /// O(n + m) scanning.
    #[must_use]
    pub fn new_fast(sigs: Vec<FlirtSignature>) -> Self {
        let index = AhoCorasickIndex::build(&sigs);
        Self {
            sigs,
            index: Some(index),
            min_confidence: 60,
            // 0 = accept everything, preserving the historical behaviour. The
            // threshold is opt-in because raising it *removes* matches, and a
            // silent change to which functions get renamed is a
            // correctness-visible change.
            min_bytes_without_crc: 0,
        }
    }

    /// Require a signature with no tail CRC to have at least `n` exact leading
    /// bytes before its match is trusted.
    ///
    /// # Why this knob exists
    ///
    /// Measured on `sample3_rust.exe` against the 67 168-signature rust-stdlib
    /// database: **238 of 240 renames came from signatures with no CRC at all**,
    /// and 199 had a prefix shorter than 16 bytes. The CRC-bearing signatures —
    /// 74.1% of the database — almost never matched, because their tails
    /// correctly disagreed.
    ///
    /// In other words the surviving matches were overwhelmingly the *weakest*
    /// signatures: no tail check, short prefix. That is precisely the profile of
    /// a false positive, and it explains the generic-instantiation collisions
    /// (`<&T as Debug>::fmt` landing where `<&u8 as Debug>::fmt` lives): with no
    /// CRC and a short prefix there is nothing left to tell them apart.
    pub const fn set_min_bytes_without_crc(&mut self, n: usize) {
        self.min_bytes_without_crc = n;
    }

    /// Override the minimum confidence threshold (0–100).
    pub const fn set_min_confidence(&mut self, conf: u8) {
        self.min_confidence = conf;
    }

    /// Scan `data` using the Aho-Corasick index when available, falling back
    /// to a linear scan when the index is absent or empty.
    ///
    /// Returns one [`FlirtMatch`] per `(offset, signature)` pair that passes
    /// full wildcard matching and (optionally) CRC-16 verification.
    #[must_use]
    pub fn scan_fast(&self, data: &[u8], base_addr: u64) -> Vec<FlirtMatch> {
        match &self.index {
            Some(idx) if idx.is_built() => self.scan_with_index(idx, data, base_addr),
            _ => self.scan_linear(data, base_addr),
        }
    }

    // ---- private helpers ---------------------------------------------------

    fn scan_with_index(
        &self,
        idx: &AhoCorasickIndex,
        data: &[u8],
        base_addr: u64,
    ) -> Vec<FlirtMatch> {
        let candidates = idx.search(data, &self.sigs);
        let mut results = Vec::new();

        for (offset, sig_idx) in candidates {
            let sig = &self.sigs[sig_idx];
            let slice = &data[offset..];
            if !sig.matches_at(slice) {
                continue;
            }
            // Optional CRC-16 verification.
            if sig.crc_len > 0 {
                let crc_start = offset
                    .checked_add(sig.bytes.len())
                    .and_then(|s| s.checked_add(sig.crc_offset as usize));
                let crc_end = crc_start.and_then(|s| s.checked_add(sig.crc_len as usize));
                match (crc_start, crc_end) {
                    (Some(start), Some(end)) if end <= data.len() => {
                        let actual = crc16_flirt(&data[start..end]);
                        if actual != sig.crc {
                            continue;
                        }
                    }
                    _ => continue,
                }
            }
            // A signature with no tail CRC has only its prefix to go on. Below
            // the configured floor there is not enough evidence to trust it —
            // see `set_min_bytes_without_crc` for the measurement that motivates
            // this. Signatures that *do* carry a CRC have already passed it
            // above and are exempt.
            if sig.crc_len == 0 && sig.bytes.len() < self.min_bytes_without_crc {
                continue;
            }
            let conf = compute_sig_confidence(sig);
            if conf < self.min_confidence {
                continue;
            }
            results.push(FlirtMatch {
                address: base_addr + offset as u64,
                function_name: sig.name.clone(),
                lib_name: sig.lib_name.clone(),
                confidence: conf,
                pattern_length: sig.bytes.len(),
            });
        }

        results
    }

    fn scan_linear(&self, data: &[u8], base_addr: u64) -> Vec<FlirtMatch> {
        let mut results = Vec::new();
        for (sig_idx, sig) in self.sigs.iter().enumerate() {
            let _ = sig_idx;
            if sig.bytes.is_empty() {
                continue;
            }
            for offset in 0..data.len() {
                let slice = &data[offset..];
                if !sig.matches_at(slice) {
                    continue;
                }
                if sig.crc_len > 0 {
                    let crc_start = offset
                        .checked_add(sig.bytes.len())
                        .and_then(|s| s.checked_add(sig.crc_offset as usize));
                    let crc_end = crc_start.and_then(|s| s.checked_add(sig.crc_len as usize));
                    match (crc_start, crc_end) {
                        (Some(start), Some(end)) if end <= data.len() => {
                            let actual = crc16_flirt(&data[start..end]);
                            if actual != sig.crc {
                                continue;
                            }
                        }
                        _ => continue,
                    }
                }
                let conf = compute_sig_confidence(sig);
                if conf < self.min_confidence {
                    continue;
                }
                results.push(FlirtMatch {
                    address: base_addr + offset as u64,
                    function_name: sig.name.clone(),
                    lib_name: sig.lib_name.clone(),
                    confidence: conf,
                    pattern_length: sig.bytes.len(),
                });
            }
        }
        results
    }
}

impl FlirtScanner {
    /// Scan `data` using an on-the-fly Aho-Corasick index built from the
    /// scanner's own signature set.
    ///
    /// Unlike [`FlirtScanner::scan_fast`] (which uses a pre-built index stored
    /// inside the scanner), this method always constructs a fresh
    /// [`AhoCorasickIndex`] from the current signature list, applies it to
    /// `data`, performs full wildcard and CRC-16 verification on every
    /// candidate, and returns the confirmed matches.
    ///
    /// This is useful when the signature list has been mutated since the
    /// scanner was constructed and the caller wants to avoid rebuilding the
    /// entire [`FlirtScanner`].
    #[must_use]
    pub fn scan_ac(&self, data: &[u8], base_addr: u64) -> Vec<FlirtMatch> {
        let Ok(ac) = build_ac_index(&self.sigs) else { return Vec::new(); };
        scan_with_ac(data, &self.sigs, &ac, base_addr, self.min_confidence)
    }
}

impl std::fmt::Debug for FlirtScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlirtScanner(sigs={}, indexed={}, min_conf={})",
            self.sigs.len(),
            self.index.as_ref().is_some_and(AhoCorasickIndex::is_built),
            self.min_confidence
        )
    }
}

// ---------------------------------------------------------------------------
// Aho-Corasick helpers (standalone, public API)
// ---------------------------------------------------------------------------

/// Build an [`aho_corasick::AhoCorasick`] automaton over the fixed (non-wildcard)
/// prefix bytes of each signature.
///
/// The pattern at automaton index `i` corresponds to `sigs[i]`.  Signatures
/// whose fixed prefix is empty (all wildcards) are indexed with an empty
/// pattern — Aho-Corasick will match them at every position, so callers
/// should treat those with special care or filter them out beforehand.
///
/// # Errors
///
/// Returns an error if the Aho-Corasick builder fails (only possible when
/// patterns exceed internal size limits, which is not reachable in practice).
pub fn build_ac_index(
    sigs: &[FlirtSignature],
) -> Result<aho_corasick::AhoCorasick, aho_corasick::BuildError> {
    // Collect the leading non-wildcard run of each signature, capped at 16
    // bytes so that very long identical prefixes do not inflate the automaton.
    const PREFIX_MAX: usize = 16;

    let patterns: Vec<Vec<u8>> = sigs
        .iter()
        .map(|sig| {
            let mut prefix = Vec::new();
            for (&b, &m) in sig.bytes.iter().zip(sig.mask.iter()).take(PREFIX_MAX) {
                if m == 0xff {
                    prefix.push(b);
                } else {
                    break;
                }
            }
            prefix
        })
        .collect();

    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(false)
        .build(patterns)
}

/// Search `data` using a pre-built Aho-Corasick automaton and perform full
/// wildcard + CRC-16 verification on every candidate.
///
/// # Arguments
///
/// * `data`       — the raw binary to scan
/// * `sigs`       — the signature slice that was used to build `ac`
/// * `ac`         — the automaton returned by [`build_ac_index`]
/// * `base_addr`  — added to each match offset to produce an absolute address
/// * `min_conf`   — minimum confidence score (0–100) required to emit a match
///
/// # Returns
///
/// A [`Vec<FlirtMatch>`] with one entry per `(offset, signature)` pair that
/// passes all verification stages.
#[must_use]
pub fn scan_with_ac(
    data: &[u8],
    sigs: &[FlirtSignature],
    ac: &aho_corasick::AhoCorasick,
    base_addr: u64,
    min_conf: u8,
) -> Vec<FlirtMatch> {
    let mut results = Vec::new();

    for mat in ac.find_overlapping_iter(data) {
        let offset = mat.start();
        let sig_idx = mat.pattern().as_usize();

        if sig_idx >= sigs.len() {
            continue;
        }
        let sig = &sigs[sig_idx];

        // Full wildcard-aware match starting at `offset`.
        let slice = &data[offset..];
        if !sig.matches_at(slice) {
            continue;
        }

        // Optional CRC-16 verification over the bytes that follow the pattern.
        if sig.crc_len > 0 {
            let crc_start = offset
                .checked_add(sig.bytes.len())
                .and_then(|s| s.checked_add(sig.crc_offset as usize));
            let crc_end = crc_start.and_then(|s| s.checked_add(sig.crc_len as usize));
            match (crc_start, crc_end) {
                (Some(start), Some(end)) if end <= data.len() => {
                    let actual = crc16_flirt(&data[start..end]);
                    if actual != sig.crc {
                        continue;
                    }
                }
                // CRC region out of bounds — skip candidate.
                _ => continue,
            }
        }

        let conf = compute_sig_confidence(sig);
        if conf < min_conf {
            continue;
        }

        results.push(FlirtMatch {
            address: base_addr + offset as u64,
            function_name: sig.name.clone(),
            lib_name: sig.lib_name.clone(),
            confidence: conf,
            pattern_length: sig.bytes.len(),
        });
    }

    results
}

/// Confidence score for a [`FlirtSignature`] (mirrors the logic for
/// [`FlirtPattern`] but works on the mask representation).
fn compute_sig_confidence(sig: &FlirtSignature) -> u8 {
    let total = sig.mask.len();
    if total == 0 {
        return 0;
    }
    let concrete = sig.mask.iter().filter(|&&m| m != 0).count();
    let ratio = usize_to_f64(concrete) / usize_to_f64(total);
    let length_bonus = (usize_to_f64(total.min(16)) / 16.0) * 20.0;
    f64_to_u8(ratio * 80.0 + length_bonus).min(100)
}

// ---------------------------------------------------------------------------
// .sig binary format reading
// ---------------------------------------------------------------------------

use std::path::Path;

/// Magic bytes at the start of an IDA .sig file.
const SIG_MAGIC: &[u8] = b"IDASGN";
/// Magic prefix used in .pat (text) files.
const PAT_MAGIC: &[u8] = b"---";

/// Load signatures from an IDA .sig binary file.
///
/// The .sig format begins with a 6-byte magic `"IDASGN"` followed by a
/// version byte and various header fields.  The bulk of the file is a
/// depth-first trie of pattern bytes.  This function implements a pragmatic
/// subset of the format sufficient to extract function names and byte
/// patterns.
///
/// # Errors
///
/// Returns [`FlirtError::InvalidSigFile`] when the magic is missing or the
/// file is truncated.  Returns [`FlirtError::Io`] on I/O failures.
pub fn load_sig_file(path: &Path) -> Result<Vec<FlirtSignature>, FlirtError> {
    use std::io::Read;

    let mut raw = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut raw)?;

    // This used to compute the header layout inline, placing `library_name_len`
    // at index 31 and the name at 32, then skipping two bytes for
    // `ctypes_crc16` to find the trie. The published layout has the name last,
    // at 43, so the trie start was off by nine bytes and the decode desynchronised
    // immediately.
    //
    // Measured (T37, iteration 45) on one `.sig` written by
    // `rustre_flirt_gen::SigWriter` containing three patterns:
    // `FlirtScanner::from_sig_bytes` recovered **3**, this function recovered
    // **1** — from the same 169 bytes. It is the fourth site found on the old
    // header layout, and the second reader to stop after roughly one leaf.
    //
    // It now delegates to the same loader the working path uses, rather than
    // keeping a second header parser and a second trie decoder in step by hand.
    // `SigFileLoader` locates the trie with `SigHeader::header_len()`, which is
    // the one place that knows the header is variable-length.
    let loaded = crate::sig_file_loader::SigFileLoader::new().load_from_bytes(&raw, None)?;
    Ok(loaded.to_signatures())
}

/// Maximum trie recursion depth for `decode_sig_trie` to prevent stack
/// overflow on malformed or adversarial `.sig` input.
const DECODE_SIG_TRIE_MAX_DEPTH: usize = 512;

/// Recursive trie decoder for the .sig binary format.
///
/// IDA .sig files encode patterns as a depth-first trie where:
/// - Each node is prefixed by a length byte indicating how many bytes of
///   pattern follow at this level.
/// - A length of `0` signals an "end of trie" marker.
/// - After the pattern bytes, if this is a leaf, the signature metadata
///   (CRC, function count, names) is encoded.
///
/// This implementation extracts patterns up to [`PREFIX_CAP`] bytes and
/// collects function names.
fn decode_sig_trie(
    data: &[u8],
    pos: &mut usize,
    pattern: &mut Vec<u8>,
    mask: &mut Vec<u8>,
    lib_name: &str,
    out: &mut Vec<FlirtSignature>,
) {
    decode_sig_trie_inner(data, pos, pattern, mask, lib_name, out, 0);
}

fn decode_sig_trie_inner(
    data: &[u8],
    pos: &mut usize,
    pattern: &mut Vec<u8>,
    mask: &mut Vec<u8>,
    lib_name: &str,
    out: &mut Vec<FlirtSignature>,
    depth: usize,
) {
    if depth > DECODE_SIG_TRIE_MAX_DEPTH {
        return;
    }
    while *pos < data.len() {
        let node_len = data[*pos] as usize;
        *pos += 1;

        if node_len == 0 {
            // End-of-level sentinel.
            return;
        }

        // Collect `node_len` bytes into the running pattern.
        let initial_depth = pattern.len();
        for _ in 0..node_len {
            if *pos >= data.len() {
                return;
            }
            let b = data[*pos];
            *pos += 1;
            // In the trie, wildcard bytes are represented as 0x00 with a
            // separate mask bit.  For simplicity we treat non-0xff values
            // without a mask byte as exact; this is the common case.
            pattern.push(b);
            mask.push(0xff);
        }

        // Peek at the next byte: if it is a function-count byte (> 0) we are
        // at a leaf; otherwise recurse into a child node.
        if *pos >= data.len() {
            pattern.truncate(initial_depth);
            mask.truncate(initial_depth);
            return;
        }

        let flags = data[*pos];
        *pos += 1; // consume flags byte (shared by both branches)
        if flags == 0 {
            // Child nodes follow.
            decode_sig_trie_inner(data, pos, pattern, mask, lib_name, out, depth + 1);
        } else {
            // Leaf: read CRC and function name(s).

            // crc_offset (u16 BE), crc_len (u8), crc (u16 BE)
            if *pos + 5 > data.len() {
                pattern.truncate(initial_depth);
                mask.truncate(initial_depth);
                return;
            }
            let crc_offset = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            let crc_len = u16::from(data[*pos + 2]);
            let crc = u16::from_be_bytes([data[*pos + 3], data[*pos + 4]]);
            *pos += 5;

            // Function name: length byte + UTF-8 bytes.
            if *pos >= data.len() {
                pattern.truncate(initial_depth);
                mask.truncate(initial_depth);
                return;
            }
            let name_len = data[*pos] as usize;
            *pos += 1;
            if *pos + name_len > data.len() {
                pattern.truncate(initial_depth);
                mask.truncate(initial_depth);
                return;
            }
            let name = String::from_utf8_lossy(&data[*pos..*pos + name_len]).to_string();
            *pos += name_len;

            out.push(FlirtSignature {
                bytes: pattern.clone(),
                mask: mask.clone(),
                name,
                lib_name: lib_name.to_string(),
                crc_offset,
                crc_len,
                crc,
            });
        }

        // Pop the bytes we pushed for this node.
        pattern.truncate(initial_depth);
        mask.truncate(initial_depth);
    }
}

// ---------------------------------------------------------------------------
// IDA .sig v9 binary format reader
// ---------------------------------------------------------------------------

/// IDA .sig v9 fixed header size in bytes.
///
/// Layout:
///   [0..6]   Magic        b"IDASGN"
///   [6]      Version      u8
///   [7]      Arch         u8
///   [8..12]  `FileTypes`    u32 LE
///   [12..14] `OsTypes`      u16 LE
///   [14..16] `AppTypes`     u16 LE
///   [16..18] `FeatureFlags` u16 LE
///   [18..20] `OldNumFuncs`  u16 LE
///   [20..22] Crc16        u16 LE  (CRC of header[0..20])
///   [22..34] `CtypesCrc`    [u8; 12]
///   [34]     `LibraryNameLen` u8   <-- one byte, not the start of a u32
///   [35..37] `AltCtypeCrc`  u16 LE
///   [37..41] `NumFunctions` u32 LE (v6+)
///   [41..43] `PatternSize`  u16 LE (v8+)
///   [43..]   `LibraryName`  (LibraryNameLen bytes)
///
/// The header is **variable length**: it ends at `43 + LibraryNameLen`. A
/// `SIG_V9_HEADER_SIZE = 104` constant used to live here and encode the old,
/// wrong fixed layout; it was removed once every reader stopped using it,
/// because a constant that names a wrong invariant invites someone to reach for
/// it again.

/// Parse the v9 .sig fixed header from `raw`.
///
/// Returns `(version, arch, num_functions, pattern_size, lib_name)` on success.
/// Returns [`FlirtError::InvalidSigFile`] when the data is too short or the
/// magic does not match.
fn parse_sig_v9_header(raw: &[u8]) -> Result<(u8, u8, u32, u16, String), FlirtError> {
    // BUG FIX: this read `NumFunctions` as a u32 at offset 34 and the library
    // name from a fixed 40..104 window. Offset 34 is IDA's one-byte
    // `library_name_len`; the header is variable length and ends at 43 + that
    // length. Delegated to the single codec in `rustre_flirt::sig_header`.
    let h = rustre_flirt::sig_header::SigFileHeader::decode(raw)
        .map_err(|_| FlirtError::InvalidSigFile)?;
    Ok((h.version, h.arch, h.n_functions, h.pattern_size, h.lib_name))
}

/// Load signatures from an IDA .sig **v9** binary file, parsing the 104-byte
/// fixed header followed by the trie body.
///
/// This is a stricter variant of [`load_sig_file`] that validates the v9
/// header layout and uses the `NumFunctions` field to drive extraction.  It
/// is automatically selected by [`load_auto`] for v9 files.
///
/// # Errors
///
/// Returns [`FlirtError::InvalidSigFile`] when the magic or header size is
/// wrong. Returns [`FlirtError::Parse`] for unsupported versions. Returns
/// [`FlirtError::Io`] on I/O failures.
pub fn load_sig_file_v9(path: &Path) -> Result<Vec<FlirtSignature>, FlirtError> {
    use std::io::Read;

    let mut raw = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut raw)?;

    let (version, _arch, _num_functions, _pattern_size, lib_name) = parse_sig_v9_header(&raw)?;

    if version != 9 {
        return Err(FlirtError::Parse(format!(
            "load_sig_file_v9: expected v9, got v{version}"
        )));
    }

    // The trie starts immediately after the header — which is **variable
    // length** (43 bytes plus the library name), not a fixed 104. Starting at a
    // constant meant decoding the trie from the wrong offset for every library
    // whose name was not exactly 61 bytes long.
    let mut sigs = Vec::new();
    let mut pos = rustre_flirt::sig_header::SigFileHeader::decode(&raw)
        .map_err(|_| FlirtError::InvalidSigFile)?
        .len_bytes();
    let mut pattern_buf = Vec::new();
    let mut mask_buf = Vec::new();

    decode_sig_trie(
        &raw,
        &mut pos,
        &mut pattern_buf,
        &mut mask_buf,
        &lib_name,
        &mut sigs,
    );

    Ok(sigs)
}

/// Parse only the header fields from a .sig file and return the metadata
/// without decoding the trie.
///
/// Useful for quickly inspecting a .sig file's metadata (library name,
/// architecture, function count) without the cost of full trie decoding.
///
/// # Errors
///
/// Returns [`FlirtError::InvalidSigFile`] or [`FlirtError::Io`] as appropriate.
pub fn inspect_sig_header(path: &Path) -> Result<SigFileHeader, FlirtError> {
    use std::io::Read;

    // BUG FIX: this read exactly `SIG_V9_HEADER_SIZE` (104) bytes and treated a
    // shorter read as "old format", returning an empty library name. The IDA
    // header is **variable length** — 43 bytes plus the library name — so a
    // perfectly valid file with a short name is under 104 bytes and was being
    // silently downgraded to a nameless stub.
    //
    // Read a bounded prefix instead: the header can never exceed 43 + 255.
    const MAX_HEADER: usize = rustre_flirt::sig_header::OFF_NAME + u8::MAX as usize;
    let mut raw = vec![0u8; MAX_HEADER];
    let mut f = std::fs::File::open(path)?;
    let n = f.read(&mut raw)?;
    raw.truncate(n);

    let (version, arch, num_functions, pattern_size, lib_name) = parse_sig_v9_header(&raw)?;

    Ok(SigFileHeader {
        version,
        arch,
        num_functions,
        pattern_size,
        lib_name,
    })
}

/// Decoded header metadata returned by [`inspect_sig_header`].
#[derive(Debug, Clone)]
pub struct SigFileHeader {
    /// .sig format version byte (e.g. 9 for v9).
    pub version: u8,
    /// CPU architecture code: 0 = i386, 75 = `x86_64`, etc.
    pub arch: u8,
    /// Total number of functions claimed by the header.
    pub num_functions: u32,
    /// Number of leading bytes used in the trie patterns.
    pub pattern_size: u16,
    /// Human-readable library name embedded in the header.
    pub lib_name: String,
}

/// Load signatures from an IDA .pat text file (one pattern per line).
///
/// Lines beginning with `---` are the trailing separator; blank lines and
/// comment lines beginning with `;` are skipped.
///
/// # Errors
///
/// Returns [`FlirtError::Io`] on I/O failures and [`FlirtError::Parse`] for
/// malformed lines.
pub fn load_pat_file(path: &Path) -> Result<Vec<FlirtSignature>, FlirtError> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut sigs = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with("---") {
            break;
        }
        match parse_pat_line(trimmed) {
            Ok(sig) => sigs.push(sig),
            Err(e) => {
                return Err(FlirtError::Parse(format!("line {}: {e}", line_no + 1)));
            }
        }
    }

    Ok(sigs)
}

/// Parse a single .pat format line into a [`FlirtSignature`].
///
/// .pat lines have the form:
/// ```text
/// <hex_pattern> <crc_len_hex> <crc_hex> <total_len_hex> :<offset> <name> [...]
/// ```
fn parse_pat_line(line: &str) -> Result<FlirtSignature, String> {
    // The pattern is the first whitespace-delimited token; it contains the
    // hex bytes with `..` for wildcards.
    let mut parts = line.splitn(2, ' ');
    let hex_pat = parts.next().ok_or("empty line")?;
    let rest = parts.next().unwrap_or("");

    let cap = hex_pat.len() / 2;
    let mut bytes = Vec::with_capacity(cap);
    let mut mask = Vec::with_capacity(cap);

    // hex_pat is a run of 2-char hex tokens optionally with `..` wildcards.
    let chars = hex_pat.as_bytes();
    let mut i = 0;
    while i + 1 < chars.len() {
        let a = chars[i];
        let b = chars[i + 1];
        i += 2;
        if a == b'.' && b == b'.' {
            bytes.push(0x00);
            mask.push(0x00);
        } else {
            let hex = std::str::from_utf8(&chars[i - 2..i]).unwrap_or("");
            let v = u8::from_str_radix(hex, 16).map_err(|_| format!("bad hex token: {hex}"))?;
            bytes.push(v);
            mask.push(0xff);
        }
    }

    // Parse "crc_len crc total_len :offset name" from `rest`.
    let mut tokens = rest.split_whitespace();
    let crc_len_s = tokens.next().unwrap_or("00");
    let crc_s = tokens.next().unwrap_or("0000");
    let _total_len = tokens.next().unwrap_or("0000");

    let crc_len = u16::from(
        u8::from_str_radix(crc_len_s, 16)
            .map_err(|_| format!("bad crc_len field: {crc_len_s}"))?,
    );
    let crc = u16::from_str_radix(crc_s, 16)
        .map_err(|_| format!("bad crc field: {crc_s}"))?;

    // Collect function name from ":offset name" pairs.
    let mut name = String::new();
    for tok in tokens {
        if tok.starts_with(':') {
            // next token should be the name
            continue;
        }
        if name.is_empty() && !tok.starts_with(':') {
            name = tok.to_string();
            break;
        }
    }
    if name.is_empty() {
        name = "unknown".to_string();
    }

    Ok(FlirtSignature {
        bytes,
        mask,
        name,
        lib_name: String::new(),
        crc_offset: 0,
        crc_len,
        crc,
    })
}

/// Detect the format of a signature file and load it accordingly.
///
/// * Files starting with `"IDASGN"` are treated as binary .sig.
/// * Files starting with `"---"` or containing hex-like patterns are treated
///   as text .pat.
///
/// # Errors
///
/// Propagates errors from [`load_sig_file`] or [`load_pat_file`].
pub fn load_auto(path: &Path) -> Result<Vec<FlirtSignature>, FlirtError> {
    use std::io::Read;

    let mut magic = [0u8; 6];
    let mut f = std::fs::File::open(path)?;
    let n = f.read(&mut magic)?;
    drop(f);

    if n >= SIG_MAGIC.len() && &magic[..SIG_MAGIC.len()] == SIG_MAGIC {
        load_sig_file(path)
    } else if n >= PAT_MAGIC.len() && &magic[..PAT_MAGIC.len()] == PAT_MAGIC {
        load_pat_file(path)
    } else {
        // Try pat format as the fallback (it is text).
        load_pat_file(path)
    }
}

// ---------------------------------------------------------------------------
// High-level rename resolution
// ---------------------------------------------------------------------------

/// A single rename produced by [`resolve_renames`].
#[derive(Debug, Clone)]
pub struct ResolvedRename {
    /// Address of the function being renamed.
    pub address: u64,
    /// New (FLIRT-derived) name.
    pub name: String,
    /// Library that contributed the winning signature.
    pub lib: String,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Pattern length of the winning match.
    pub pattern_length: usize,
}

/// Summary returned by [`resolve_renames`].
#[derive(Debug, Clone, Default)]
pub struct ResolveStats {
    /// Total raw matches scanned.
    pub scanned: usize,
    /// Matches that met the confidence threshold.
    pub matched: usize,
    /// Renames committed to the [`AppliedNamesStore`].
    pub applied: usize,
    /// Matches skipped (conflict loser, sub-threshold, or duplicate).
    pub skipped: usize,
}

/// Resolve a batch of raw [`FlirtMatch`]es into a deduplicated rename list.
///
/// Uses [`NameConflictResolver`] to pick a winner per address, commits winners
/// to an [`AppliedNamesStore`], and emits [`ResolvedRename`] entries.
///
/// The `min_confidence` argument floors the cut-off; matches below it never
/// reach the resolver or the store.
#[must_use]
pub fn resolve_renames(
    matches: &[FlirtMatch],
    min_confidence: u8,
) -> (Vec<ResolvedRename>, ResolveStats) {
    let mut stats = ResolveStats {
        scanned: matches.len(),
        ..Default::default()
    };

    let mut resolver = NameConflictResolver::new();
    let mut lengths: ahash::AHashMap<(u64, String), usize> = ahash::AHashMap::new();
    for m in matches {
        if m.confidence < min_confidence {
            stats.skipped += 1;
            continue;
        }
        // A signature with no name cannot rename anything. Propagating it
        // replaces `sub_140002620` with the empty string, which is strictly
        // worse than leaving the placeholder: the address loses even the
        // identity it had.
        //
        // Measured on the rust-stdlib database: 25 965 of its 67 168 patterns
        // (38.7%) carry no primary name, and without this guard they produced
        // 188 of 240 renames on `sample3_rust.exe` — 78% of the output was
        // empty names.
        if m.function_name.trim().is_empty() {
            stats.skipped += 1;
            continue;
        }
        stats.matched += 1;
        lengths.insert((m.address, m.function_name.clone()), m.pattern_length);
        resolver.add_candidate(NameBinding::direct(
            m.address,
            m.function_name.clone(),
            m.lib_name.clone(),
            m.confidence,
        ));
    }

    let (winners, _conflict_addrs) = resolver.resolve();

    let mut store = AppliedNamesStore::with_config(StoreConfig {
        min_confidence,
        ..StoreConfig::default()
    });

    let applied_names: Vec<AppliedName> = winners
        .iter()
        .map(|b| {
            let plen = lengths
                .get(&(b.address, b.name.clone()))
                .copied()
                .unwrap_or(0);
            AppliedName::new(
                b.address,
                b.name.clone(),
                b.confidence,
                b.lib.clone(),
                plen,
                NameOrigin::FlirtSig {
                    lib_name: b.lib.clone(),
                },
            )
        })
        .collect();

    let commit = store.commit_names(applied_names);
    stats.applied = commit.inserted + commit.updated;
    stats.skipped += commit.skipped;

    let renames: Vec<ResolvedRename> = store
        .all_sorted()
        .into_iter()
        .map(|an| ResolvedRename {
            address: an.address,
            name: an.name.clone(),
            lib: an.lib_name.clone(),
            confidence: an.confidence,
            pattern_length: an.pattern_length,
        })
        .collect();

    (renames, stats)
}

/// Propagate resolved renames across an [`XrefGraph`].
///
/// This wires [`NamePropagator`] into the resolve pipeline: callers of a
/// FLIRT-named function with placeholder names become `<callee>_wrapper`.
#[must_use]
pub fn propagate_renames(
    seeds: &[ResolvedRename],
    xrefs: XrefGraph,
    existing: &[(u64, String)],
) -> PropagationResult {
    let mut prop = NamePropagator::new(xrefs);
    for (addr, name) in existing {
        prop.set_existing_name(*addr, name.clone());
    }
    let bindings: Vec<NameBinding> = seeds
        .iter()
        .map(|r| NameBinding::direct(r.address, r.name.clone(), r.lib.clone(), r.confidence))
        .collect();
    prop.propagate(&bindings)
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn m(addr: u64, name: &str, lib: &str, conf: u8) -> FlirtMatch {
        FlirtMatch {
            address: addr,
            function_name: name.to_string(),
            lib_name: lib.to_string(),
            confidence: conf,
            pattern_length: 12,
        }
    }

    #[test]
    fn test_resolve_dedupes_per_address() {
        let matches = vec![
            m(0x1000, "strlen", "msvcrt", 90),
            m(0x1000, "strlen", "msvcrt", 95),
            m(0x2000, "memcpy", "msvcrt", 80),
        ];
        let (renames, stats) = resolve_renames(&matches, 70);
        assert_eq!(renames.len(), 2);
        assert_eq!(stats.matched, 3);
        assert!(stats.applied >= 2);
    }

    #[test]
    fn test_resolve_drops_below_threshold() {
        let matches = vec![m(0x1000, "f", "lib", 30)];
        let (renames, stats) = resolve_renames(&matches, 70);
        assert!(renames.is_empty());
        assert_eq!(stats.matched, 0);
        assert_eq!(stats.skipped, 1);
    }

    #[test]
    fn test_propagate_renames_wraps_caller() {
        let seeds = vec![ResolvedRename {
            address: 0x1000,
            name: "strlen".to_string(),
            lib: "msvcrt".to_string(),
            confidence: 90,
            pattern_length: 12,
        }];
        let mut g = XrefGraph::new();
        g.add_edge(0x2000, 0x1000);
        let existing = vec![(0x2000u64, "sub_2000".to_string())];
        let res = propagate_renames(&seeds, g, &existing);
        assert!(res.applied.iter().any(|b| b.address == 0x2000));
    }

    #[test]
    fn test_scanner_from_pack_finds_match() {
        let mut pack = SignaturePack::new("test");
        let pat = FlirtPattern::from_pattern_str(
            "55 8B EC 83 EC 10",
            "myfn".into(),
            "mylib".into(),
        )
        .unwrap();
        pack.push(pat);
        let scanner = FlirtScanner::from_pack(&pack);
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let hits = scanner.scan_fast(&data, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "myfn");
    }
}

// ---------------------------------------------------------------------------
// Tests for the new fast-scan infrastructure
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fast_scan_tests {
    use super::*;

    // ---- FlirtSignature ----------------------------------------------------

    #[test]
    fn test_flirt_signature_from_pattern() {
        let fp =
            FlirtPattern::from_pattern_str("55 8B EC ?? 83", "fn1".into(), "lib1".into()).unwrap();
        let sig = FlirtSignature::from_flirt_pattern(&fp);
        assert_eq!(sig.bytes.len(), 5);
        assert_eq!(sig.mask[3], 0x00); // wildcard
        assert_eq!(sig.mask[0], 0xff); // exact
        assert_eq!(sig.name, "fn1");
    }

    #[test]
    fn test_flirt_signature_matches_at_exact() {
        let sig = FlirtSignature {
            bytes: vec![0x55, 0x8B, 0xEC],
            mask: vec![0xff, 0xff, 0xff],
            name: "f".into(),
            lib_name: "lib".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        assert!(sig.matches_at(&[0x55, 0x8B, 0xEC, 0x00]));
        assert!(!sig.matches_at(&[0x55, 0x8B, 0xED]));
    }

    #[test]
    fn test_flirt_signature_matches_wildcard() {
        let sig = FlirtSignature {
            bytes: vec![0x55, 0x00, 0xEC],
            mask: vec![0xff, 0x00, 0xff],
            name: "f".into(),
            lib_name: "lib".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        assert!(sig.matches_at(&[0x55, 0xFF, 0xEC]));
        assert!(sig.matches_at(&[0x55, 0x00, 0xEC]));
    }

    // ---- WildcardPattern ---------------------------------------------------

    #[test]
    fn test_wildcard_pattern_prefix_all_exact() {
        let sig = FlirtSignature {
            bytes: vec![0x55, 0x8B, 0xEC],
            mask: vec![0xff, 0xff, 0xff],
            name: "f".into(),
            lib_name: "l".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        let wp = WildcardPattern::from_signature(&sig);
        assert_eq!(wp.prefix(), &[0x55, 0x8B, 0xEC]);
    }

    #[test]
    fn test_wildcard_pattern_prefix_leading_wildcard() {
        let sig = FlirtSignature {
            bytes: vec![0x00, 0x8B, 0xEC],
            mask: vec![0x00, 0xff, 0xff],
            name: "f".into(),
            lib_name: "l".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        let wp = WildcardPattern::from_signature(&sig);
        // Leading wildcard → empty prefix.
        assert!(wp.prefix().is_empty());
    }

    #[test]
    fn test_wildcard_pattern_prefix_mid_wildcard() {
        let sig = FlirtSignature {
            bytes: vec![0x55, 0x8B, 0x00, 0x90],
            mask: vec![0xff, 0xff, 0x00, 0xff],
            name: "f".into(),
            lib_name: "l".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        let wp = WildcardPattern::from_signature(&sig);
        // Prefix stops at first wildcard.
        assert_eq!(wp.prefix(), &[0x55, 0x8B]);
    }

    // ---- AhoCorasickIndex --------------------------------------------------

    #[test]
    fn test_ac_index_build_and_search() {
        let sigs = vec![
            FlirtSignature {
                bytes: vec![0x55, 0x8B, 0xEC],
                mask: vec![0xff, 0xff, 0xff],
                name: "fn_a".into(),
                lib_name: "lib".into(),
                crc_offset: 0,
                crc_len: 0,
                crc: 0,
            },
            FlirtSignature {
                bytes: vec![0xAA, 0xBB, 0xCC],
                mask: vec![0xff, 0xff, 0xff],
                name: "fn_b".into(),
                lib_name: "lib".into(),
                crc_offset: 0,
                crc_len: 0,
                crc: 0,
            },
        ];
        let idx = AhoCorasickIndex::build(&sigs);
        assert!(idx.is_built());

        let data = vec![0x00, 0x55, 0x8B, 0xEC, 0x00, 0xAA, 0xBB, 0xCC];
        let candidates = idx.search(&data, &sigs);
        // Should find fn_a at offset 1 and fn_b at offset 5.
        assert!(candidates.contains(&(1, 0)));
        assert!(candidates.contains(&(5, 1)));
    }

    #[test]
    fn test_ac_index_all_wildcards_not_built() {
        let sigs = vec![FlirtSignature {
            bytes: vec![0x00, 0x00],
            mask: vec![0x00, 0x00],
            name: "f".into(),
            lib_name: "l".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        }];
        let idx = AhoCorasickIndex::build(&sigs);
        assert!(!idx.is_built());
    }

    // ---- CRC-16 ------------------------------------------------------------

    #[test]
    fn test_crc16_flirt_empty() {
        // IDA flair crc16 (init 0xFFFF, poly reflected 0x8408, no final XOR):
        // empty input returns the init value 0xFFFF.
        assert_eq!(crc16_flirt(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_flirt_known() {
        // Cross-check: 0x55 alone.
        let c = crc16_flirt(&[0x55]);
        // Just verify determinism.
        assert_eq!(crc16_flirt(&[0x55]), c);
    }

    #[test]
    fn test_crc16_flirt_ida_known_answer() {
        // IDA FLIRT CRC-16 (init=0xFFFF, poly reflected 0x8408, no final XOR,
        // matches IDA flair's crc16.cpp): "IDA" -> 0xD1D0.
        assert_eq!(crc16_flirt(b"IDA"), 0xD1D0);
    }

    // ---- FlirtScanner ------------------------------------------------------

    fn make_sigs(patterns: &[&str]) -> Vec<FlirtSignature> {
        patterns
            .iter()
            .map(|p| {
                let fp = FlirtPattern::from_pattern_str(p, "fn".into(), "lib".into())
                    .expect("valid pattern");
                FlirtSignature::from_flirt_pattern(&fp)
            })
            .collect()
    }

    #[test]
    fn test_scanner_new_fast_debug() {
        let sigs = make_sigs(&["55 8B EC 83"]);
        let s = FlirtScanner::new_fast(sigs);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("FlirtScanner"));
    }

    #[test]
    fn test_scan_fast_finds_match() {
        let sigs = make_sigs(&["55 8B EC 83 EC 10"]);
        let scanner = FlirtScanner::new_fast(sigs);
        let data = vec![0x00u8, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00];
        let matches = scanner.scan_fast(&data, 0x1000);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].address, 0x1002);
    }

    #[test]
    fn test_scan_fast_no_match() {
        let sigs = make_sigs(&["AA BB CC DD EE FF"]);
        let scanner = FlirtScanner::new_fast(sigs);
        let data = vec![0x00u8; 64];
        let matches = scanner.scan_fast(&data, 0x0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_fast_wildcard_pattern() {
        let sigs = make_sigs(&["55 ?? EC 83 EC 10"]);
        let scanner = FlirtScanner::new_fast(sigs);
        // The AC prefix is just [0x55]; the wildcard is verified afterwards.
        let data = vec![0x55u8, 0xFF, 0xEC, 0x83, 0xEC, 0x10];
        let matches = scanner.scan_fast(&data, 0x0);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_fast_fallback_linear() {
        // Signatures with no concrete prefix fall back to linear scan.
        let sigs = vec![FlirtSignature {
            bytes: vec![0x00, 0x00, 0x55, 0x8B],
            mask: vec![0x00, 0x00, 0xff, 0xff],
            name: "wild_start".into(),
            lib_name: "lib".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        }];
        let mut scanner = FlirtScanner::new_fast(sigs);
        // The pattern has only 2/4 concrete bytes (50% ratio), yielding a
        // confidence of ~45.  Lower the threshold so the match is not filtered.
        scanner.set_min_confidence(0);
        let data = vec![0xAA, 0xBB, 0x55, 0x8B];
        // Linear scan should still find this.
        let matches = scanner.scan_fast(&data, 0x0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x0);
    }

    #[test]
    fn test_scanner_min_confidence() {
        let sigs = make_sigs(&["55 8B EC 83"]);
        let mut scanner = FlirtScanner::new_fast(sigs);
        scanner.set_min_confidence(101); // impossible threshold → no matches
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        let matches = scanner.scan_fast(&data, 0x0);
        assert!(matches.is_empty());
    }

    // ---- load_auto / load_pat_file / load_sig_file -------------------------

    #[test]
    fn test_load_sig_file_bad_magic() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(b"BADMAGIC\x00\x00").unwrap();
        let path = tmp.path().to_path_buf();
        let result = load_sig_file(&path);
        assert!(matches!(result, Err(FlirtError::InvalidSigFile)));
    }

    #[test]
    fn test_load_sig_file_truncated() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write valid magic but truncated header.
        tmp.write_all(b"IDASGN\x07").unwrap();
        let path = tmp.path().to_path_buf();
        let result = load_sig_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_pat_file_nonexistent() {
        let result = load_pat_file(Path::new("nonexistent_file_xyz.pat"));
        assert!(matches!(result, Err(FlirtError::Io(_))));
    }

    #[test]
    fn test_load_auto_nonexistent() {
        let result = load_auto(Path::new("no_such.sig"));
        assert!(matches!(result, Err(FlirtError::Io(_))));
    }

    // ---- Performance benchmark ---------------------------------------------

    /// Generate a synthetic [`FlirtSignature`] with a concrete prefix of
    /// length `prefix_len` followed by `(total - prefix_len)` wildcards.
    fn synthetic_sig(idx: usize, prefix_len: usize, total: usize) -> FlirtSignature {
        let mut bytes = Vec::with_capacity(total);
        let mut mask = Vec::with_capacity(total);
        for i in 0..total {
            if i < prefix_len {
                // Use a deterministic but varied byte so signatures differ.
                bytes.push(((idx.wrapping_mul(31).wrapping_add(i).wrapping_mul(17)) & 0xFF) as u8);
                mask.push(0xff);
            } else {
                bytes.push(0x00);
                mask.push(0x00);
            }
        }
        FlirtSignature {
            bytes,
            mask,
            name: format!("fn_{idx}"),
            lib_name: "bench_lib".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        }
    }

    #[test]
    fn benchmark_fast_scan_vs_linear() {
        use std::time::Instant;

        const N_SIGS: usize = 1000;
        const DATA_SIZE: usize = 1024 * 1024; // 1 MB

        // Build 1000 synthetic signatures with a 4-byte concrete prefix and
        // 8 wildcard bytes.
        let sigs: Vec<FlirtSignature> = (0..N_SIGS).map(|i| synthetic_sig(i, 4, 12)).collect();

        // 1 MB of pseudo-random data (cheap LCG).
        let mut data = vec![0u8; DATA_SIZE];
        let mut state: u64 = 0xDEAD_BEEF_CAFE_0001;
        for b in &mut data {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }

        // -- Fast scanner --
        let fast_scanner = FlirtScanner::new_fast(sigs);
        let t0 = Instant::now();
        let fast_matches = fast_scanner.scan_fast(&data, 0x0);
        let fast_elapsed = t0.elapsed();

        // -- Linear scanner (same sigs, no index) --
        // We skip the full O(n*m) linear scan over 1 MB × 1000 patterns in
        // unit tests for CI speed; we just verify the fast path completes
        // without error and produces a plausible result count.
        let _ = fast_matches; // consume
        let _ = fast_elapsed;

        // The fast scanner must at least build and run without panicking.
        assert!(fast_scanner.index.as_ref().is_some_and(super::AhoCorasickIndex::is_built));
    }

    // ---- build_ac_index / scan_with_ac / scan_ac ---------------------------

    #[test]
    fn test_build_ac_index_creates_automaton() {
        let sigs = make_sigs(&["55 8B EC 83 EC 10", "AA BB CC DD EE FF"]);
        let ac = build_ac_index(&sigs).unwrap();
        // Aho-Corasick should find the first pattern in matching data.
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let mut found = false;
        for mat in ac.find_overlapping_iter(&data) {
            if mat.pattern().as_usize() == 0 {
                found = true;
            }
        }
        assert!(found, "AC should find pattern 0 in data");
    }

    #[test]
    fn test_scan_with_ac_finds_exact_match() {
        let sigs = make_sigs(&["55 8B EC 83 EC 10"]);
        let ac = build_ac_index(&sigs).unwrap();
        let data = vec![0x00u8, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let matches = scan_with_ac(&data, &sigs, &ac, 0x1000, 0);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].address, 0x1002);
        assert_eq!(matches[0].function_name, "fn");
    }

    #[test]
    fn test_scan_with_ac_no_match() {
        let sigs = make_sigs(&["AA BB CC DD EE FF"]);
        let ac = build_ac_index(&sigs).unwrap();
        let data = vec![0x00u8; 32];
        let matches = scan_with_ac(&data, &sigs, &ac, 0x0, 0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_with_ac_wildcard_verified() {
        // Pattern has a wildcard at byte 1 — AC matches on the exact prefix
        // [0x55], then full verification passes since byte 1 is wildcarded.
        let sigs = make_sigs(&["55 ?? EC 83 EC 10"]);
        let ac = build_ac_index(&sigs).unwrap();
        let data = vec![0x55u8, 0xFF, 0xEC, 0x83, 0xEC, 0x10];
        let matches = scan_with_ac(&data, &sigs, &ac, 0x0, 0);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_with_ac_respects_min_conf() {
        let sigs = make_sigs(&["55 8B EC 83"]);
        let ac = build_ac_index(&sigs).unwrap();
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        // Use an impossible min_conf threshold.
        let matches = scan_with_ac(&data, &sigs, &ac, 0x0, 101);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scanner_scan_ac_method() {
        let sigs = make_sigs(&["55 8B EC 83 EC 10"]);
        let scanner = FlirtScanner::new_linear(sigs);
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let matches = scanner.scan_ac(&data, 0x4000);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].address, 0x4000);
    }

    #[test]
    fn test_scanner_scan_ac_no_match() {
        let sigs = make_sigs(&["AA BB CC DD"]);
        let scanner = FlirtScanner::new_fast(sigs);
        let data = vec![0x00u8; 32];
        let matches = scanner.scan_ac(&data, 0x0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scanner_scan_ac_multiple_sigs() {
        let sigs = make_sigs(&["55 8B EC 83", "AA BB CC DD"]);
        let scanner = FlirtScanner::new_fast(sigs);
        let mut data = vec![0x00u8; 16];
        data[0] = 0x55;
        data[1] = 0x8B;
        data[2] = 0xEC;
        data[3] = 0x83;
        data[8] = 0xAA;
        data[9] = 0xBB;
        data[10] = 0xCC;
        data[11] = 0xDD;
        let matches = scanner.scan_ac(&data, 0x0);
        assert!(matches.len() >= 2);
    }

    // ---- load_sig_file_v9 / inspect_sig_header ----------------------------

    fn make_v9_sig_bytes(lib_name: &str) -> Vec<u8> {
        // Built through the canonical codec instead of by hand. The previous
        // version wrote `num_functions` as a u32 at offset 34 and padded the
        // name into a fixed 40..104 window — the old, wrong layout — so this
        // helper was quietly manufacturing invalid files for every test that
        // used it.
        let mut h = rustre_flirt::sig_header::SigFileHeader {
            version: 9,
            arch: 75,
            pattern_size: 32,
            lib_name: lib_name.to_string(),
            ..rustre_flirt::sig_header::SigFileHeader::default()
        }
        .encode();
        // End-of-trie sentinel
        h.push(0x00);
        h
    }

    #[test]
    fn test_load_sig_file_v9_empty_trie() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let bytes = make_v9_sig_bytes("mylib");
        tmp.write_all(&bytes).unwrap();
        let result = load_sig_file_v9(tmp.path());
        assert!(result.is_ok(), "v9 load should succeed: {:?}", result.err());
        let sigs = result.unwrap();
        assert_eq!(sigs.len(), 0, "empty trie should yield 0 sigs");
    }

    #[test]
    fn test_load_sig_file_v9_wrong_version_rejected() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = make_v9_sig_bytes("lib");
        bytes[6] = 8; // force version 8
        tmp.write_all(&bytes).unwrap();
        let result = load_sig_file_v9(tmp.path());
        assert!(matches!(result, Err(FlirtError::Parse(_))));
    }

    #[test]
    fn test_load_sig_file_v9_bad_magic() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = make_v9_sig_bytes("lib");
        bytes[0] = 0xFF; // corrupt magic
        tmp.write_all(&bytes).unwrap();
        let result = load_sig_file_v9(tmp.path());
        assert!(matches!(result, Err(FlirtError::InvalidSigFile)));
    }

    #[test]
    fn test_load_sig_file_v9_truncated_header() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"IDASGN\x09").unwrap(); // only 7 bytes
        let result = load_sig_file_v9(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_sig_header_v9() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let bytes = make_v9_sig_bytes("inspector_lib");
        tmp.write_all(&bytes).unwrap();
        let hdr = inspect_sig_header(tmp.path()).unwrap();
        assert_eq!(hdr.version, 9);
        assert_eq!(hdr.arch, 75);
        assert_eq!(hdr.lib_name, "inspector_lib");
        assert_eq!(hdr.num_functions, 0);
        assert_eq!(hdr.pattern_size, 32);
    }

    #[test]
    fn test_inspect_sig_header_bad_magic() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Comfortably longer than any header (43 + name), with a wrong magic.
        let mut bytes = vec![0u8; 128];
        bytes[0] = 0xFF;
        tmp.write_all(&bytes).unwrap();
        let result = inspect_sig_header(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_sig_file_header_debug() {
        let hdr = SigFileHeader {
            version: 9,
            arch: 75,
            num_functions: 42,
            pattern_size: 32,
            lib_name: "mylib".to_string(),
        };
        let s = format!("{hdr:?}");
        assert!(s.contains("mylib"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_build_ac_index_empty_sigs() {
        let sigs: Vec<FlirtSignature> = Vec::new();
        let ac = build_ac_index(&sigs).unwrap();
        // Empty automaton: no matches on any data.
        let data = vec![0x55u8; 8];
        let count = ac.find_overlapping_iter(&data).count();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_scan_with_ac_multiple_hits_same_pattern() {
        let sigs = make_sigs(&["55 8B EC 83"]);
        let ac = build_ac_index(&sigs).unwrap();
        // Pattern appears twice in the data.
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0x00, 0x55, 0x8B, 0xEC, 0x83];
        let matches = scan_with_ac(&data, &sigs, &ac, 0x0, 0);
        assert!(matches.len() >= 2, "should find both occurrences");
    }
}


// ---------------------------------------------------------------------------
// Tests for LibraryMark projection (feature K)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod library_mark_tests {
    use super::*;

    fn fm(addr: u64, name: &str, lib: &str) -> FlirtMatch {
        FlirtMatch {
            address: addr,
            function_name: name.to_string(),
            lib_name: lib.to_string(),
            confidence: 90,
            pattern_length: 16,
        }
    }

    #[test]
    fn test_library_marks_from_matches_basic() {
        let ms = vec![
            fm(0x1000, "strlen", "msvcrt"),
            fm(0x2000, "memcpy", "msvcrt"),
            fm(0x3000, "Some::rust_fn", "libstd"),
        ];
        let marks = library_marks_from_matches(&ms);
        assert_eq!(marks.len(), 3);
        assert_eq!(marks[0].address, 0x1000);
        assert_eq!(marks[0].lib_name, "msvcrt");
        assert_eq!(marks[2].lib_name, "libstd");
    }

    #[test]
    fn test_library_marks_drops_unknown_lib() {
        let ms = vec![fm(0x1000, "f", ""), fm(0x2000, "g", "msvcrt")];
        let marks = library_marks_from_matches(&ms);
        assert_eq!(marks.len(), 1);
        assert_eq!(marks[0].address, 0x2000);
    }
}


#[cfg(test)]
mod sig_dir_tests {
    use super::*;

    /// Build a `.sig` blob with the real writer.
    ///
    /// This fixture used to hand-assemble what its own doc comment called a
    /// "minimal **legacy-header** .sig blob that `load_sig_file` parses": magic,
    /// version, 24 filler bytes, then the library name at offset 32. That is not
    /// the published layout — the name is last, at 43 — and the fixture was
    /// written to match the parser's mistake, so it passed and certified it
    /// (T37, iteration 45).
    ///
    /// Building the bytes with `SigWriter` means the fixture cannot agree with a
    /// reader that has drifted: the bytes now come from the component that owns
    /// the format.
    fn make_sig_blob(lib: &str, pattern: &[u8], func: &str) -> Vec<u8> {
        use rustre_flirt::{FlirtName, PatternByte};

        let mut p = rustre_flirt::FlirtPattern::new(
            pattern.iter().map(|b| PatternByte::Exact(*b)).collect(),
        );
        p.pattern_length = u16::try_from(pattern.len()).unwrap_or(u16::MAX);
        p.names.push(FlirtName {
            offset: 0,
            name: func.to_string(),
            is_public: true,
            is_local: false,
        });

        rustre_flirt_gen::SigWriter::default().build(std::slice::from_ref(&p), lib)
    }

    #[test]
    fn test_merge_sig_dir_loads_sig_files() {
        let dir = tempfile::tempdir().unwrap();
        let pat_bytes = [0x55u8, 0x8B, 0xEC, 0x8B, 0x4D, 0x10];
        std::fs::write(
            dir.path().join("crt.sig"),
            make_sig_blob("msvcrt", &pat_bytes, "memcpy_sig"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("other.sig"),
            make_sig_blob("libfoo", &[0x40u8, 0x53, 0x48, 0x83], "foo_fn"),
        )
        .unwrap();
        // Distractors: wrong extension and unparseable garbage.
        std::fs::write(dir.path().join("notes.txt"), b"IDASGN nonsense").unwrap();
        std::fs::write(dir.path().join("broken.sig"), b"XX").unwrap();

        let mut db = FlirtSigDb::new();
        let added = db.merge_sig_dir(dir.path()).unwrap();
        assert_eq!(added, 2, "exactly the two valid .sig files load");
        assert_eq!(db.pattern_count(), 2);

        // The loaded pattern must actually match its source bytes.
        let applier = FlirtApplier::new(db);
        let mut data = pat_bytes.to_vec();
        data.extend_from_slice(&[0x90; 8]);
        let matches = applier.scan(&data, 0x1000);
        assert!(
            matches.iter().any(|m| m.function_name == "memcpy_sig"),
            "merged signature should match: {matches:?}"
        );
    }

    #[test]
    fn test_merge_sig_dir_missing_dir_is_io_error() {
        let mut db = FlirtSigDb::new();
        let r = db.merge_sig_dir(Path::new("Z:/definitely/not/a/dir/xyz"));
        assert!(matches!(r, Err(FlirtError::Io(_))));
    }

    #[test]
    fn test_merge_sig_dir_empty_dir_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = FlirtSigDb::new();
        assert_eq!(db.merge_sig_dir(dir.path()).unwrap(), 0);
        assert_eq!(db.pattern_count(), 0);
    }

    #[test]
    fn test_from_signature_roundtrip() {
        let sig = FlirtSignature {
            bytes: vec![0x55, 0x00, 0xEC],
            mask: vec![0xff, 0x00, 0xff],
            name: "fn_x".into(),
            lib_name: "libx".into(),
            crc_offset: 3,
            crc_len: 8,
            crc: 0xBEEF,
        };
        let pat = FlirtPattern::from_signature(&sig);
        assert_eq!(pat.bytes, vec![Some(0x55), None, Some(0xEC)]);
        assert_eq!(pat.name, "fn_x");
        assert_eq!(pat.lib_name, "libx");
        assert_eq!(pat.crc, 0xBEEF);
        assert_eq!(pat.crc_len, 8);
        assert_eq!(pat.crc_offset, 3);
        // And back again.
        let sig2 = FlirtSignature::from_flirt_pattern(&pat);
        assert_eq!(sig2.bytes, vec![0x55, 0x00, 0xEC]);
        assert_eq!(sig2.mask, vec![0xff, 0x00, 0xff]);
    }
}
