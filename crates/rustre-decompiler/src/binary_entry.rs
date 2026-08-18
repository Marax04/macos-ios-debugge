//! `binary_entry.rs` — Glue between the binary I/O layer and the decompiler pipeline.
//!
//! Provides the integrated `binary path + function address → DecompiledFunction`
//! entry point used by the MCP `decompile.function` tool, the batch decompiler,
//! and any other consumer that wants the full pipeline behind one call.
//!
//! Pipeline:
//!   1. Load the file via [`rustre_loader::MultiFormatRegistry::auto_load`].
//!   2. Locate the byte slice that backs the function (section map or raw image).
//!   3. Decode each instruction with [`rustre_arch_x86::X86Arch::disassemble`]
//!      until the first `RET` or invalid encoding.
//!   4. Run the standard [`crate::DecompilerPipeline`] over the resulting
//!      `Vec<Instruction>` via `run_with_structured_emit`.
//!
//! Function enumeration over a whole binary uses
//! [`rustre_analysis_fn::FunctionDetector`] feeding the same per-function path.

use crate::{
    DecompOptions, DecompiledFunction, DecompilerError, DecompilerPipeline,
    DefaultPipelineFactory, SymbolMap, SymbolResolver,
};
use crate::jump_table::{
    JumpTableInfo, ResolvedJumpTable, detect_all_jump_tables, resolve_table_targets,
};
use rustre_analysis_fn::{DetectedArch, FunctionBoundary, FunctionDetector, MemorySlice};
use rustre_arch_x86::X86Arch;
use rustre_core::address::Address;
use rustre_core::arch::{Architecture, Instruction};
use rustre_loader::{RichLoadResult, SectionInfo, SymbolInfo, default_multi_format_registry};
use parking_lot::Mutex;
use rustre_flirt_apply::{FlirtScanner, SignaturePack, resolve_renames};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, OnceLock};

/// Heuristic: a section is executable if its name looks like code or its
/// platform-specific flags have any "exec" bit set. Covers ELF (`SHF_EXECINSTR
/// = 0x4`), PE (`IMAGE_SCN_MEM_EXECUTE = 0x2000_0000`), and Mach-O segments by
/// name (`__TEXT`, `.text`).
fn is_executable_section(s: &SectionInfo) -> bool {
    if s.flags & 0x2000_0000 != 0 || s.flags & 0x4 != 0 {
        return true;
    }
    let n = s.name.to_lowercase();
    n.contains(".text") || n.contains("__text") || n.contains("text")
}

// ─────────────────────────────────────────────────────────────────────────────
// DataOracle — read-only view of the loaded image's section table
// ─────────────────────────────────────────────────────────────────────────────

/// Coarse classification of the section a virtual address falls in.
///
/// `None` means "not mapped by any section" — the honest answer for an address
/// outside the image, which callers must not confuse with "initialized data".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Executable code (`.text`, `__TEXT`, `SHF_EXECINSTR`/`MEM_EXECUTE`).
    Text,
    /// Import descriptors / IAT (`.idata`, PE `.rdata$.idata` style names).
    Idata,
    /// Initialized data backed by bytes in the file (`.rdata`, `.data`, …).
    Init,
    /// Uninitialized data (`.bss`, or a section whose virtual size exceeds its
    /// raw size — the tail of such a section is zero-filled at load time).
    Bss,
    /// Address not covered by any section.
    None,
}

/// One section, reduced to what classification and byte lookup need.
#[derive(Debug, Clone)]
struct OracleSection {
    va: u64,
    vsize: u64,
    raw_offset: u64,
    raw_size: u64,
    kind: SectionKind,
}

/// Read-only oracle over the loaded image: answers "what kind of section is
/// this VA in" and "give me the bytes at this VA".
///
/// Built once by [`binary_entry`] from the section table the loader already
/// parsed ([`RichLoadResult::sections`]) — it performs no parsing of its own
/// and holds only a copy of the image bytes plus the reduced section list.
/// Threaded into the pipeline as an *optional* handle; `None` (the default)
/// must always reproduce the oracle-less behaviour exactly.
#[derive(Debug, Clone, Default)]
pub struct DataOracle {
    sections: Vec<OracleSection>,
    image: Vec<u8>,
}

impl DataOracle {
    /// Build from an already-loaded image. No new parsing.
    #[must_use]
    pub fn from_load(load: &RichLoadResult) -> Self {
        let is_elf = load.format.starts_with("ELF");
        let sections = load
            .sections
            .iter()
            .map(|s| {
                let n = s.name.to_lowercase();
                let exec = s.flags & 0x2000_0000 != 0
                    || (is_elf && s.flags & 0x4 != 0)
                    || n.contains(".text")
                    || n.contains("__text");
                let kind = if exec {
                    SectionKind::Text
                } else if n.contains("idata") || n.contains("iat") {
                    SectionKind::Idata
                } else if s.raw_size == 0 || n.contains("bss") || n.contains("__common") {
                    SectionKind::Bss
                } else {
                    SectionKind::Init
                };
                OracleSection {
                    va: s.virtual_addr,
                    vsize: if s.virtual_size == 0 { s.raw_size } else { s.virtual_size },
                    raw_offset: s.raw_offset,
                    raw_size: s.raw_size,
                    kind,
                }
            })
            .collect();
        Self { sections, image: load.data.clone() }
    }

    /// Build directly from a section list (test/synthetic use).
    #[must_use]
    pub fn from_parts(
        sections: Vec<(u64, u64, u64, u64, SectionKind)>,
        image: Vec<u8>,
    ) -> Self {
        Self {
            sections: sections
                .into_iter()
                .map(|(va, vsize, raw_offset, raw_size, kind)| OracleSection {
                    va,
                    vsize,
                    raw_offset,
                    raw_size,
                    kind,
                })
                .collect(),
            image,
        }
    }

    fn section_at(&self, va: u64) -> Option<&OracleSection> {
        self.sections.iter().find(|s| va >= s.va && va < s.va.saturating_add(s.vsize))
    }

    /// Classify `va`. Returns [`SectionKind::None`] when unmapped.
    #[must_use]
    pub fn section_kind(&self, va: u64) -> SectionKind {
        self.section_at(va).map_or(SectionKind::None, |s| s.kind)
    }

    /// `len` bytes of file-backed image content at `va`, if the whole range is
    /// backed by raw bytes. `.bss` tails and unmapped addresses yield `None`.
    #[must_use]
    pub fn data_at(&self, va: u64, len: usize) -> Option<&[u8]> {
        let s = self.section_at(va)?;
        let off_in_sec = va - s.va;
        if off_in_sec >= s.raw_size {
            return None;
        }
        let avail = usize::try_from(s.raw_size - off_in_sec).ok()?;
        if len > avail {
            return None;
        }
        let start = usize::try_from(s.raw_offset + off_in_sec).ok()?;
        self.image.get(start..start.checked_add(len)?)
    }
}

/// Maximum bytes we will scan from `fn_address` when no end address is known.
/// 64 KiB is generous: real functions rarely exceed a few KiB.
const MAX_FN_SCAN_BYTES: usize = 64 * 1024;

/// Maximum instructions decoded per function. Mirrors the pipeline's
/// `max_function_size` so we don't waste cycles on runaway scans.
const MAX_FN_INSTRUCTIONS: usize = 10_000;

// ─────────────────────────────────────────────────────────────────────────────
// FLIRT library-function naming
// ─────────────────────────────────────────────────────────────────────────────

/// Baseline signature packs shared with the PE loader's autoname hook.
const BASELINE_MSVCRT_X64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rustre-loader-pe/assets/baseline/msvcrt-x64.sigpack"
));
const BASELINE_RUST_STDLIB_X64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rustre-loader-pe/assets/baseline/rust-stdlib-x64.sigpack"
));

/// The baseline packs carry short wildcard-heavy prologue signatures; 50 keeps
/// real matches while rejecting near-random hits.
const FLIRT_MIN_CONFIDENCE: u8 = 50;

/// Lazily-built scanner over the embedded baseline packs plus any `*.sigpack`
/// files found in `$RUSTRE_SIGPACK_DIR`. Malformed packs are skipped silently.
fn baseline_flirt_scanner() -> &'static FlirtScanner {
    static SCANNER: OnceLock<FlirtScanner> = OnceLock::new();
    SCANNER.get_or_init(|| build_scanner(true))
}

/// Scanner WITHOUT the Rust-stdlib pack, for binaries that are not Rust.
///
/// The Rust pack's prologue signatures are short and wildcard-heavy, so on a
/// non-Rust image they fabricate plausible-but-invented names. Measured on the
/// corpus before this gate existed, the pack scored **36 false positives and 0
/// true positives**: both C# NativeAOT binaries got 18 bogus
/// `core__ops__function__FnOnce__call_once` / `alloc__sync__Arc__new` names
/// each, while the two REAL Rust binaries matched nothing at all.
///
/// Note the fix is a language gate, NOT a higher `FLIRT_MIN_CONFIDENCE`:
/// raising the threshold would also discard genuine matches from the MSVCRT
/// pack, trading one silent error for another.
fn non_rust_flirt_scanner() -> &'static FlirtScanner {
    static SCANNER: OnceLock<FlirtScanner> = OnceLock::new();
    SCANNER.get_or_init(|| build_scanner(false))
}

fn build_scanner(include_rust_stdlib: bool) -> FlirtScanner {
    {
        let mut packs: Vec<SignaturePack> = Vec::new();
        let baselines: &[&str] = if include_rust_stdlib {
            &[BASELINE_MSVCRT_X64, BASELINE_RUST_STDLIB_X64]
        } else {
            &[BASELINE_MSVCRT_X64]
        };
        for text in baselines {
            if let Ok(p) = SignaturePack::parse(text) {
                packs.push(p);
            }
        }
        if let Some(dir) = std::env::var_os("RUSTRE_SIGPACK_DIR")
            && let Ok(rd) = std::fs::read_dir(&dir)
        {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "sigpack")
                    && let Ok(text) = std::fs::read_to_string(&path)
                    && let Ok(pack) = SignaturePack::parse(&text)
                {
                    packs.push(pack);
                }
            }
        }
        // Binary `.sig` databases, in addition to the text packs above.
        //
        // The two embedded packs hold **22 signatures** between them, which was
        // the entire FLIRT capability of this pipeline. A generated `.sig`
        // carries orders of magnitude more (the repo's rust-stdlib database
        // holds 67 168 patterns), but until now nothing could feed one to a
        // scanner: `SignaturePack` only parses the `SIGPACK 1` text format.
        //
        // Opt-in via `RUSTRE_SIGDB_DIR` rather than automatic, because adding
        // signatures changes which functions get renamed — that is a
        // correctness-visible change and should be a deliberate one.
        let mut sig_files: Vec<std::path::PathBuf> = Vec::new();
        if let Some(dir) = std::env::var_os("RUSTRE_SIGDB_DIR")
            && let Ok(rd) = std::fs::read_dir(&dir)
        {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "sig") {
                    sig_files.push(path);
                }
            }
            sig_files.sort(); // deterministic order regardless of readdir
        }

        // A malformed `.sig` must not silently reduce the scanner to the packs
        // alone: that would look like "this binary has no known functions".
        let mut scanner = match FlirtScanner::from_packs_and_sig_files(&packs, &sig_files) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[flirt] .sig non caricabile ({e:?}); proseguo con i soli sigpack"
                );
                FlirtScanner::from_packs(&packs)
            }
        };
        scanner.set_min_confidence(FLIRT_MIN_CONFIDENCE);
        if std::env::var_os("RUSTRE_FLIRT_DEBUG").is_some() {
            eprintln!(
                "[flirt] scanner: {} pack + {} database .sig = {} firme",
                packs.len(),
                sig_files.len(),
                scanner.signature_count()
            );
        }
        scanner
    }
}

/// FLIRT scan of one loaded image → `(va, name)` pairs, memoized per image so
/// the batch path (one `RichLoadResult`, many functions) scans exactly once.
/// Set `RUSTRE_NO_FLIRT=1` to disable.
#[must_use]
pub fn flirt_pairs_for_load(load: &RichLoadResult) -> Arc<Vec<(u64, String)>> {
    static CACHE: OnceLock<Mutex<HashMap<(usize, usize, u64), Arc<Vec<(u64, String)>>>>> =
        OnceLock::new();
    if std::env::var_os("RUSTRE_NO_FLIRT").is_some() {
        return Arc::new(Vec::new());
    }
    let key = (load.data.as_ptr() as usize, load.data.len(), load.base_address);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().get(&key) {
        return Arc::clone(hit);
    }
    // Language gate (D22): only scan a binary against the Rust-stdlib pack when
    // the image actually looks like Rust. Detection is evidence-based and
    // returns `None` when nothing matches; an UNKNOWN language keeps the full
    // pack set, so this can only ever remove scanning from images positively
    // identified as some OTHER language — never from an unrecognised one.
    let looks_rust = matches!(
        crate::reconstruction::toolchain::detect(&load.data).language,
        None | Some(crate::reconstruction::toolchain::Language::Rust)
    );
    let scanner = if looks_rust { baseline_flirt_scanner() } else { non_rust_flirt_scanner() };
    let pairs = Arc::new(flirt_pairs_with_scanner(scanner, load, FLIRT_MIN_CONFIDENCE));
    let mut guard = cache.lock();
    if guard.len() > 64 {
        guard.clear(); // crude bound; images are transient in batch runs
    }
    guard.insert(key, Arc::clone(&pairs));
    pairs
}

/// Core scan: executable sections (or the whole image when no section table
/// exists) → resolved, conflict-free renames, filtered so FLIRT never
/// overrides a name the loader already provided via symbols/exports.
fn flirt_pairs_with_scanner(
    scanner: &FlirtScanner,
    load: &RichLoadResult,
    min_confidence: u8,
) -> Vec<(u64, String)> {
    if scanner.signature_count() == 0 {
        return Vec::new();
    }
    let mut matches = Vec::new();
    if load.sections.is_empty() {
        matches.extend(scanner.scan_fast(&load.data, load.base_address));
    } else {
        for section in &load.sections {
            if !is_executable_section(section) {
                continue;
            }
            let start = usize::try_from(section.raw_offset).unwrap_or(usize::MAX);
            let end = start
                .saturating_add(usize::try_from(section.raw_size).unwrap_or(0))
                .min(load.data.len());
            if start >= end {
                continue;
            }
            matches.extend(scanner.scan_fast(&load.data[start..end], section.virtual_addr));
        }
    }
    let raw_matches = matches.len();
    let (renames, _stats) = resolve_renames(&matches, min_confidence);
    if std::env::var_os("RUSTRE_FLIRT_DEBUG").is_some() {
        eprintln!(
            "[flirt] firme caricate {}, match grezzi {}, dopo resolve {}",
            scanner.signature_count(),
            raw_matches,
            renames.len()
        );
    }
    renames
        .into_iter()
        .filter(|r| {
            !load
                .symbols
                .iter()
                .any(|s| s.addr == r.address && !s.name.is_empty())
                && !load
                    .exports
                    .iter()
                    .any(|e| e.addr == r.address && !e.name.is_empty())
        })
        .map(|r| (r.address, r.name))
        .collect::<Vec<_>>()
        .pipe_drop_ambiguous_flirt_names()
        .pipe_publish_to_type_recovery()
}

/// Level 7: hand FLIRT identifications to type recovery.
trait PublishToTypeRecovery {
    fn pipe_publish_to_type_recovery(self) -> Self;
}

impl PublishToTypeRecovery for Vec<(u64, String)> {
    /// Publish each identified function's *published* prototype into the type
    /// recovery signature registry.
    ///
    /// This is the last link of the `size → … → signature` chain: FLIRT supplies
    /// the identity, and a known identity means a known prototype — no inference
    /// required. Runs **after** `pipe_drop_ambiguous_flirt_names`, deliberately:
    /// a name claimed at several addresses has contradicted itself, and
    /// publishing a prototype for a contradicted identity would spread the error
    /// into every caller's recovered types instead of containing it.
    ///
    /// Names without a published prototype publish nothing. A wrong prototype
    /// *overrides* a correct inference downstream, so silence is the safe answer.
    fn pipe_publish_to_type_recovery(self) -> Self {
        let stats = rustre_flirt_apply::typerecov_bridge::publish_identifications(
            self.iter().map(|(addr, name)| (*addr, name.as_str())),
        );
        if std::env::var_os("RUSTRE_FLIRT_DEBUG").is_some() {
            eprintln!(
                "[flirt→typerecov] considerate {}, pubblicate {}, senza prototipo {}",
                stats.considered, stats.published, stats.skipped_unknown_prototype
            );
        }
        self
    }
}

/// Small extension trait so the ambiguity filter reads as a pipeline step.
trait DropAmbiguousFlirtNames {
    fn pipe_drop_ambiguous_flirt_names(self) -> Self;
}

impl DropAmbiguousFlirtNames for Vec<(u64, String)> {
    /// Drop any FLIRT name claimed at MORE THAN ONE address in the same image.
    ///
    /// A library function occupies one address, so a signature that names
    /// several distinct addresses the same thing has **contradicted itself** —
    /// at most one can be right and nothing here says which. Emitting all of
    /// them would hand the user several functions with one identity.
    ///
    /// Measured cause (D22 follow-up): the MSVCRT pack named **7 different
    /// addresses `_CRT_INIT`** in each C# NativeAOT binary. Confirmed to be
    /// FLIRT and not something else by re-running with `RUSTRE_NO_FLIRT=1`,
    /// which took that binary's duplicate count 1 → 0.
    ///
    /// Scope note: this filter is for FABRICATED collisions only. It does NOT
    /// address the much larger, *different* duplicate-name population in C++
    /// (110 in `sample7_cpp`), which survives `RUSTRE_NO_FLIRT` and comes from
    /// demangled overloads collapsing — e.g. 26 distinct `std::string::string`
    /// constructors all rendering as `std__string__string` once parameter
    /// types are dropped. Those names are *correct but ambiguous*, not wrong,
    /// and need disambiguation rather than removal.
    fn pipe_drop_ambiguous_flirt_names(self) -> Self {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (_, name) in &self {
            *counts.entry(name.as_str()).or_default() += 1;
        }
        let ambiguous: std::collections::HashSet<String> = counts
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(k, _)| (*k).to_string())
            .collect();
        self.into_iter().filter(|(_, n)| !ambiguous.contains(n)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Load `binary_path` through the multi-format loader registry.
/// # Errors
/// Returns an error if the binary file cannot be read or the format is not recognized.
pub fn load_binary(binary_path: &Path) -> Result<RichLoadResult, DecompilerError> {
    let bytes = std::fs::read(binary_path)
        .map_err(|e| DecompilerError::Other(format!("read {}: {e}", binary_path.display())))?;
    let registry = default_multi_format_registry();
    let mut load = registry
        .auto_load(&bytes)
        .map_err(|e| DecompilerError::Other(format!("loader: {e}")))?;
    // The lightweight PE probe does not read the COFF symbol table (mingw/gcc,
    // and any non-stripped COFF, keep function names there). Enrich so
    // functions get their real names (`accumulate` instead of `sub_…`) —
    // exactly what IDA does. Only runs when the loader found no symbols.
    if load.symbols.is_empty() {
        let syms = parse_coff_symbols(&bytes, &load.sections);
        load.symbols = syms;
    }
    Ok(load)
}

/// Parse the PE/COFF symbol table (function names) into [`SymbolInfo`]s. Returns
/// empty for non-PE, stripped, or malformed inputs (never panics). Only FUNCTION
/// symbols in a real section are returned, so function detection is not polluted
/// by data symbols.
fn parse_coff_symbols(bytes: &[u8], sections: &[SectionInfo]) -> Vec<SymbolInfo> {
    let mut out = Vec::new();
    let rd_u32 = |o: usize| -> Option<u32> {
        bytes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return out;
    }
    let Some(pe_off) = rd_u32(0x3C).map(|v| v as usize) else { return out };
    if pe_off + 24 > bytes.len() || bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return out;
    }
    let fh = pe_off + 4; // COFF file header
    let Some(ptr_symtab) = rd_u32(fh + 8).map(|v| v as usize) else { return out };
    let Some(num_syms) = rd_u32(fh + 12).map(|v| v as usize) else { return out };
    if ptr_symtab == 0 || num_syms == 0 {
        return out; // stripped or PDB-based (MSVC)
    }
    let symtab_end = ptr_symtab.saturating_add(num_syms.saturating_mul(18));
    if symtab_end + 4 > bytes.len() {
        return out;
    }
    let strtab = &bytes[symtab_end..];
    let read_name = |raw: &[u8]| -> String {
        if raw[0..4] == [0, 0, 0, 0] {
            let off = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
            let end = strtab
                .get(off..)
                .and_then(|s| s.iter().position(|&b| b == 0))
                .map_or(strtab.len(), |p| off + p);
            strtab.get(off..end).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default()
        } else {
            let end = raw[..8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        }
    };
    let mut i = 0;
    while i < num_syms {
        let rec = ptr_symtab + i * 18;
        let Some(raw) = bytes.get(rec..rec + 18) else { break };
        let value = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let sect_num = i16::from_le_bytes(raw[12..14].try_into().unwrap());
        let typ = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        let n_aux = raw[17] as usize;
        // Derived type 0x2 (DTYPE_FUNCTION) → a function symbol.
        let is_func = (typ >> 4) == 0x2;
        if is_func
            && sect_num >= 1
            && let Some(sec) = sections.get((sect_num - 1) as usize)
        {
            let name = read_name(raw);
            if !name.is_empty() && !name.starts_with('.') {
                out.push(SymbolInfo::new(name, sec.virtual_addr + u64::from(value), "function", 0));
            }
        }
        i += 1 + n_aux; // aux records belong to the preceding symbol
    }
    out
}

/// Map `bits` (loader-reported) to a `DetectedArch` for function detection.
fn detected_arch_for(load: &RichLoadResult) -> DetectedArch {
    let a = load.arch.to_lowercase();
    if a.contains("x86_64") || a.contains("amd64") || a.contains("x86-64") || load.bits == 64 {
        DetectedArch::X86_64
    } else if a.contains("x86") || a.contains("i386") || load.bits == 32 {
        DetectedArch::X86_32
    } else if a.contains("aarch64") || a.contains("arm64") {
        DetectedArch::Arm64
    } else {
        DetectedArch::Unknown
    }
}

/// Returns the bit-width to use for x86 decoding.
pub(crate) const fn x86_bits_for(load: &RichLoadResult) -> u8 {
    match load.bits {
        32 => 32,
        16 => 16,
        _ => 64,
    }
}

/// Locate a contiguous byte slice that backs the virtual address `va`.
///
/// Returns `(base_va, &bytes)` where `bytes` extends to the end of the
/// containing region. Falls back to a window into the raw image when no
/// section table is available.
#[must_use]
pub fn slice_at_va(load: &RichLoadResult, va: u64) -> Option<(u64, &[u8])> {
    // Prefer section-backed mapping. `section_at` only checks against
    // `virtual_size`; some PE producers ship sections with `virtual_size==0`
    // and rely on `raw_size`, so do a widened manual scan when the strict
    // lookup misses. This is what unblocks kg-detected function VAs that
    // sit just past `virtual_addr + virtual_size` but still inside the
    // raw-mapped extent.
    let section_hit = load.section_at(va).or_else(|| {
        load.sections.iter().find(|s| {
            let span = s.virtual_size.max(s.raw_size);
            span > 0 && va >= s.virtual_addr && va < s.virtual_addr.saturating_add(span)
        })
    });
    if let Some(section) = section_hit {
        let file_off = section.raw_offset.saturating_add(va - section.virtual_addr);
        let end_file = section
            .raw_offset
            .saturating_add(section.raw_size.max(section.virtual_size));
        let start = usize::try_from(file_off).ok()?;
        let end = usize::try_from(end_file).ok()?.min(load.data.len());
        if start >= end || start >= load.data.len() {
            return None;
        }
        return Some((va, &load.data[start..end]));
    }
    // No section covered `va`. Try the image-base-relative fallback (the
    // loader gave us a section table but the kg-supplied VA isn't inside
    // any section — e.g. .pdata-only or merged-section layouts). When a
    // base address is set, prefer `va - base` as a raw file offset; only
    // fall back to treating `va` itself as the offset when no base is
    // available, since `unwrap_or(va)` silently corrupts huge VAs into
    // out-of-bounds reads and was the source of the "address not mapped"
    // errors for valid kg entries.
    let base = load.base_address;
    let off = if base == 0 {
        va
    } else if va >= base {
        va - base
    } else {
        // VA below image base can't be a file offset of this image.
        return None;
    };
    let start = usize::try_from(off).ok()?;
    if start >= load.data.len() {
        return None;
    }
    Some((va, &load.data[start..]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Jump-table entry resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Read and resolve the entries of a detected jump table from `load`.
///
/// Reads `info.case_count` entries of `info.entry_size` bytes starting at
/// `info.table_addr` (via [`slice_at_va`]) and resolves each case to a
/// concrete target VA through [`resolve_table_targets`]. A candidate target
/// validates when it falls inside an executable section, inside the section
/// containing the indirect jump itself (which holds code by construction),
/// or — for sectionless images — inside the mapped image extent.
///
/// Returns `None` when the table bytes are unmapped, the info is degenerate,
/// or no entry interpretation validates unambiguously. Callers must keep
/// their existing `goto` fallback in that case: this function never
/// fabricates targets.
#[must_use]
pub fn resolve_jump_table(
    load: &RichLoadResult,
    info: &JumpTableInfo,
) -> Option<ResolvedJumpTable> {
    let table_addr = info.table_addr?;
    let (_, bytes) = slice_at_va(load, table_addr)?;
    resolve_table_targets(info, bytes, load.base_address, |va| {
        is_plausible_code_target(load, info.jump_addr, va)
    })
}

/// Rewrite each ADJACENT `lea d(%rip), %R` + `jmp *%R` pair into a direct
/// `jmp 0xTARGET` (target = address after the lea + d) and nop out the lea.
///
/// Go's gc emits dispatch ladders in exactly this shape; the target is a
/// compile-time constant, so the pair is a direct jump the `JUMPOUT` idiom
/// would otherwise hide from CFG construction. Adjacency is required — a
/// farther lea could be reordered with a redefinition of `R` in between —
/// and the target must land on plausible code (never fabricate an edge).
/// Riconosce `0xHEX` come `parse_hex_target` in `lib.rs`, per la sola SONDA
/// #6550: serve a distinguere un `jmp` DIRETTO (gia' gestito) da uno indiretto.
fn parse_hex_target_probe(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn fold_lea_direct_jumps(instructions: &mut [Instruction], load: &RichLoadResult) {
    for i in 1..instructions.len() {
        let jm = instructions[i].mnemonic.trim().to_ascii_lowercase();
        if jm != "jmp" && jm != "jmpq" {
            continue;
        }
        let jr = instructions[i].operands.trim();
        // SONDA #6550: PRIMA del filtro `*%`, perche' i JUMPOUT di
        // `sub_140001aa0` non compaiono affatto nella sonda #6540 — l'indirizzo
        // piu' basso dei suoi 43 scatti e' 0x1400025F4, OLTRE la fine della
        // funzione. Quindi li' il `jmp` NON ha forma `*%reg`: stampare l'ope-
        // rando GREZZO di ogni `jmp` non diretto e' l'unico modo per vederla.
        if std::env::var("RUSTRE_DBG_JMPFORM").is_ok() && parse_hex_target_probe(jr).is_none() {
            eprintln!("JMPFORM 0x{:X} ops=[{jr}]", instructions[i].address.as_u64());
        }
        let Some(jr) = jr.strip_prefix("*%") else {
            continue;
        };
        // SONDA #6540 (effetto ZERO, gated): il fold richiede il `lea`
        // IMMEDIATAMENTE prima (`instructions[i - 1]`). I JUMPOUT residui — 8
        // su tutto path B, e MISURATO che i loro target sono INTERNI alla
        // funzione secondo `.pdata` — potrebbero nascere proprio da una coppia
        // NON adiacente. Qui si stampa, per ogni `jmp *%R` che il fold NON
        // piega, a quale distanza indietro sta il `lea` che carica lo stesso
        // registro: se la distanza e' 2..N il fold va esteso, se il `lea` non
        // c'e' affatto la causa e' un'altra e va cercata altrove.
        if std::env::var("RUSTRE_DBG_LEAJMP").is_ok()
            && !instructions[i - 1].mnemonic.trim().eq_ignore_ascii_case("lea")
        {
            let dietro = (1..=8usize)
                .find(|k| {
                    i.checked_sub(*k).is_some_and(|j| {
                        instructions[j].mnemonic.trim().eq_ignore_ascii_case("lea")
                            && instructions[j]
                                .operands
                                .rsplit_once(',')
                                .is_some_and(|(_, d)| d.trim().trim_start_matches('%') == jr)
                    })
                })
                .map_or("NESSUNO_ENTRO_8".to_string(), |k| format!("distanza_{k}"));
            // Le 6 istruzioni precedenti: solo cosi' si vede la FORMA del
            // dispatch (dove nasce la base, se c'e' una maschera, ecc.).
            // `disasm_dump` non serve: TRONCA prima di questo codice.
            let ctx = (1..=6usize)
                .rev()
                .filter_map(|k| i.checked_sub(k))
                .map(|j| {
                    format!(
                        "{} {}",
                        instructions[j].mnemonic.trim(),
                        instructions[j].operands.trim()
                    )
                })
                .collect::<Vec<_>>()
                .join(" ; ");
            eprintln!(
                "LEAJMP 0x{:X} jmp *%{jr} lea={dietro} ctx=[{ctx}]",
                instructions[i].address.as_u64(),
            );
        }
        let prev = &instructions[i - 1];
        if !prev.mnemonic.trim().eq_ignore_ascii_case("lea") {
            continue;
        }
        // `lea d(%rip), %R` with R matching the jump register exactly (both
        // are 64-bit spellings in AT&T disassembly).
        let Some((src, dst)) = prev.operands.rsplit_once(',') else {
            continue;
        };
        if dst.trim().trim_start_matches('%') != jr {
            continue;
        }
        let src = src.trim();
        let Some(open) = src.find('(') else { continue };
        if src[open..].trim_start_matches('(').trim_end_matches(')').trim() != "%rip" {
            continue;
        }
        let disp = src[..open].trim();
        let (neg, body) = disp.strip_prefix('-').map_or((false, disp), |r| (true, r));
        let parsed = if let Some(hex) = body.strip_prefix("0x") {
            i64::from_str_radix(hex, 16)
        } else {
            body.parse::<i64>()
        };
        let Ok(mag) = parsed else { continue };
        let disp = if neg { -mag } else { mag };
        // RIP = address of the instruction after the lea (= the jmp itself).
        let target = instructions[i].address.as_u64().wrapping_add_signed(disp);
        if !is_plausible_code_target(load, instructions[i].address.as_u64(), target) {
            continue;
        }
        instructions[i].operands = format!("0x{target:X}");
        instructions[i - 1].mnemonic = "nop".to_string();
        instructions[i - 1].operands = String::new();
    }
}

/// True when `va` plausibly points at code in `load`: inside an executable
/// section (per `is_executable_section`), inside the section containing
/// `jump_addr`, or — for images with no section table — anywhere inside the
/// mapped image extent.
fn is_plausible_code_target(load: &RichLoadResult, jump_addr: u64, va: u64) -> bool {
    if va == 0 {
        return false;
    }
    if load.sections.is_empty() {
        let len = u64::try_from(load.data.len()).unwrap_or(u64::MAX);
        let end = load.base_address.saturating_add(len);
        return va >= load.base_address && va < end;
    }
    let Some(sec) = load.section_at(va) else {
        return false;
    };
    if is_executable_section(sec) {
        return true;
    }
    load.section_at(jump_addr)
        .is_some_and(|js| std::ptr::eq(js, sec))
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-function disassembly
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `bytes` starting at `ip` (in `bits`-bit x86 mode) into instructions.
///
/// Stops at the first `RET`, the first invalid encoding, after `max_bytes`
/// consumed, or after `max_instr` instructions.
///
/// # Errors
/// Returns an error if no instructions can be decoded.
/// x86 conditional-branch mnemonics (both plain and AT&T size-suffixed spellings
/// share the same base). Excludes the unconditional `jmp`, which may be a tail
/// call into a different function.
fn is_conditional_branch(mnem: &str) -> bool {
    matches!(
        mnem,
        "je" | "jz" | "jne" | "jnz" | "jl" | "jle" | "jg" | "jge"
            | "ja" | "jae" | "jb" | "jbe" | "js" | "jns" | "jo" | "jno"
            | "jp" | "jnp" | "jpe" | "jpo" | "jc" | "jnc" | "jnb" | "jnbe"
            | "jna" | "jnae" | "jnl" | "jnle" | "jng" | "jnge" | "jcxz" | "jecxz" | "jrcxz"
    )
}

/// Parse an absolute hex branch target operand (`0x14000191C`) → its value.
/// Returns `None` for register/memory-indirect operands.
fn parse_abs_hex_operand(operands: &str) -> Option<u64> {
    let t = operands.trim();
    let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

pub fn disassemble_function_x86(
    bytes: &[u8],
    ip: u64,
    bits: u8,
    max_bytes: usize,
    max_instr: usize,
) -> Result<Vec<Instruction>, DecompilerError> {
    disassemble_function_x86_ext(bytes, ip, bits, max_bytes, max_instr, 0)
}

/// Fine DICHIARATA della funzione che contiene `fn_va`, letta da `.pdata`
/// (`RUNTIME_FUNCTION`), oppure `None` se il binario non ne ha o l'indirizzo
/// non e' coperto.
///
/// Perche' serve (misurato su `sample7_cpp`, `0x14001bbd0`):
/// ```text
/// 0x14001bc19  ret                      <- congela lo span
/// 0x14001bcf8  jmp  0x14001BD07         <- AVANTI, +311 byte, DENTRO la funzione
/// fn instr range: 0x14001bbd0..=0x14001bcf8
/// ```
/// La passata si ferma sul `jmp` e **la coda della funzione non viene emessa**:
/// il salto diventa `return sub_14001BD07();`, una chiamata a un simbolo che
/// nessuno definisce. L'euristica intra-funzione esistente e' disattivata dopo
/// il primo `ret` (`!span_frozen`), e non puo' distinguere questo caso da una
/// tail call — mentre `.pdata` si', perche' e' dichiarata dal COMPILATORE.
///
/// ⚠ Limite dichiarato: le funzioni foglia senza unwind info non stanno in
/// `.pdata`, quindi qui si torna `None` e il comportamento resta quello di
/// prima. E' un miglioramento dove la verita' esiste, mai un'euristica nuova.
#[must_use]
pub fn pdata_declared_end(load: &RichLoadResult, fn_va: u64) -> Option<u64> {
    let base = load.base_address;
    let sec = load
        .sections
        .iter()
        .find(|s| s.name == ".pdata" || s.name == "pdata")?;
    let bytes = slice_at_va(load, sec.virtual_addr)?.1;
    let n = usize::try_from(sec.virtual_size).unwrap_or(bytes.len()).min(bytes.len());
    let table = rustre_analysis_cfg::seh::parse_pdata(&bytes[..n]);
    let rva = u32::try_from(fn_va.checked_sub(base)?).ok()?;
    let rf = rustre_analysis_cfg::seh::find_runtime_function(&table, rva)?;
    // ⚠ Esistono DUE tipi `RuntimeFunction`: quello di `rustre-analysis-fn`
    // espone `begin_rva`/`end_rva`, questo di `rustre_analysis_cfg` espone
    // `begin_address`/`end_address`. Nomi diversi per lo stesso concetto.
    (rf.end_address > rf.begin_address).then(|| base + u64::from(rf.end_address))
}

/// Like [`disassemble_function_x86`] but seeds the sweep's forward-extent bound
/// with `min_extent` — the highest known intra-function address the walk must
/// reach before a terminator (`ret` / unconditional `jmp`) may end it. The
/// caller passes the resolved jump-table case/default targets here on a second
/// pass, so switch case bodies past the first `ret` are recovered without the
/// terminator stop cutting them, while functions with no such targets stop at
/// their real end instead of bleeding into the next one.
///
/// # Errors
/// Returns an error if no instructions can be decoded at `ip`.
pub fn disassemble_function_x86_ext(
    bytes: &[u8],
    ip: u64,
    bits: u8,
    max_bytes: usize,
    max_instr: usize,
    min_extent: u64,
) -> Result<Vec<Instruction>, DecompilerError> {
    let arch = match bits {
        16 => X86Arch::new_16bit(),
        32 => X86Arch::new_32bit(),
        _ => X86Arch::new_64bit(),
    };

    let window = &bytes[..bytes.len().min(max_bytes)];
    let mut out = Vec::new();
    let mut cursor = 0usize;
    // Highest forward target of a *conditional* branch seen so far. A `ret`
    // before this address is not the function end: switch case bodies (and
    // other multi-return shapes) live past the first `ret`, reached via a
    // conditional branch such as the `ja default` bound check. Only conditional
    // branches extend the walk — an unconditional `jmp` can be a tail call into
    // another function, which must not pull that function's body in.
    // Frozen once the first `ret` is seen: case bodies are reached by the bound
    // check that precedes the first `ret`, so the switch's span is already known
    // by then. Not extending it afterwards stops case-body branches from
    // chaining the walk forward into unrelated adjacent functions.
    let mut max_cond_target: u64 = min_extent;
    let mut span_frozen = false;
    while cursor < window.len() && out.len() < max_instr {
        let cur_addr = Address::new(ip.wrapping_add(cursor as u64));
        let remaining = &window[cursor..];
        let Ok(instr) = arch.disassemble(cur_addr, remaining) else { break };
        let len = instr.bytes.len().max(1);
        let mnem = instr.mnemonic.to_lowercase();
        if !span_frozen
            && is_conditional_branch(&mnem)
            && let Some(t) = parse_abs_hex_operand(&instr.operands)
        {
            max_cond_target = max_cond_target.max(t);
        }
        // A direct unconditional `jmp` is a terminator like `ret`: bytes after
        // it are only reachable via a label, so a tail `jmp` must not run the
        // sweep into the next function. Case bodies stay intact because the
        // second pass seeds `max_cond_target` with the resolved case targets.
        //
        // Exception — intra-procedural forward `jmp` (loop rotation): gcc -O1
        // emits `jmp <cond_test>` over a bottom-tested loop body, so a
        // two-loop function carries a mid-function forward jmp whose target
        // sits BEFORE the next function boundary. The sweep window is already
        // capped at the nearest next symbol/export/known-function start
        // (`max_bytes`), so a forward target strictly inside the window is
        // this function's own code, not a tail call — extend the walk to it
        // instead of terminating. Genuine tail calls jump backward or to/past
        // the next function's start (== outside the window) and still
        // terminate; a split there is preserved.
        let jmp_target = matches!(mnem.as_str(), "jmp" | "jmpq")
            .then(|| parse_abs_hex_operand(&instr.operands))
            .flatten();
        let intra_fn_jmp = !span_frozen
            && jmp_target.is_some_and(|t| {
                let next_va = ip.wrapping_add((cursor + len) as u64);
                t > next_va && t.wrapping_sub(ip) < window.len() as u64
            });
        if intra_fn_jmp && let Some(t) = jmp_target {
            max_cond_target = max_cond_target.max(t);
        }
        let is_terminator = matches!(mnem.as_str(), "ret" | "retn" | "retf" | "iret" | "iretq")
            || (jmp_target.is_some() && !intra_fn_jmp);
        out.push(instr);
        cursor += len;
        if is_terminator {
            span_frozen = true;
            let next_va = ip.wrapping_add(cursor as u64);
            if next_va > max_cond_target {
                break;
            }
        }
    }

    if out.is_empty() {
        return Err(DecompilerError::LiftError(format!(
            "no instructions decoded at {ip:#x}"
        )));
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point: decompile one function from a binary path
// ─────────────────────────────────────────────────────────────────────────────

/// Decompile the function at `fn_address` inside the binary at `binary_path`.
///
/// Performs load → locate → disassemble → lift → pipeline in one call. The
/// pipeline used is [`DefaultPipelineFactory::standard`] with `opts`.
///
/// # Errors
/// Returns an error if the binary cannot be loaded or the function cannot be decompiled.
pub fn decompile_function_from_binary(
    binary_path: &Path,
    fn_address: u64,
    opts: DecompOptions,
) -> Result<DecompiledFunction, DecompilerError> {
    let load = load_binary(binary_path)?;
    decompile_function_in_load(&load, fn_address, opts)
}

/// Same as [`decompile_function_from_binary`] but takes an already-loaded
/// `RichLoadResult` — used by the batch path so we load the file once.
///
/// # Errors
/// Returns an error if the address is not mapped or the function cannot be decompiled.
pub fn decompile_function_in_load(
    load: &RichLoadResult,
    fn_address: u64,
    opts: DecompOptions,
) -> Result<DecompiledFunction, DecompilerError> {
    decompile_function_in_load_bounded(load, fn_address, opts, None)
}

/// Same as [`decompile_function_in_load`] but with an explicit next-function
/// start address as a hard upper bound on the linear sweep. The batch path
/// passes this (from its already-computed function-boundary set) so functions
/// that carry no symbol still cannot bleed into their neighbour.
///
/// # Errors
/// Returns an error if the address is not mapped or the function cannot be decompiled.
pub fn decompile_function_in_load_bounded(
    load: &RichLoadResult,
    fn_address: u64,
    opts: DecompOptions,
    next_fn_start: Option<u64>,
) -> Result<DecompiledFunction, DecompilerError> {
    decompile_function_in_load_cached(load, fn_address, opts, next_fn_start, None)
}

/// Type of the precomputed whole-image arity/return-type cache.
/// #6800: il terzo elemento e' la vista sui SITI DI CHIAMATA
/// (`callsite_argc_from_bodies`) — quanti registri argomento i chiamanti
/// PREPARANO davvero per ciascun bersaglio. E' l'unica evidenza che possa
/// SMENTIRE un parametro dedotto dal corpo del callee.
pub type ArityCache = (
    HashMap<u64, usize>,
    HashMap<u64, String>,
    HashMap<u64, (usize, usize, usize, usize, usize)>,
);

/// Same as [`decompile_function_in_load_bounded`] but accepts the whole-image
/// callee-arity cache from [`image_callee_arities`]. Passing `None` recomputes
/// per function (the historical behaviour).
///
/// # Errors
/// Returns an error if the address is not mapped or the function cannot be decompiled.
pub fn decompile_function_in_load_cached(
    load: &RichLoadResult,
    fn_address: u64,
    opts: DecompOptions,
    next_fn_start: Option<u64>,
    arity_cache: Option<&ArityCache>,
) -> Result<DecompiledFunction, DecompilerError> {
    let (base_va, slice) = slice_at_va(load, fn_address).ok_or_else(|| {
        DecompilerError::Other(format!(
            "address {fn_address:#x} not mapped in binary (sections={}, data_len={})",
            load.sections.len(),
            load.data.len()
        ))
    })?;

    let bits = x86_bits_for(load);
    // Cap the linear sweep at the next function boundary so the walk (which now
    // continues past the first `ret` to recover switch case bodies) cannot bleed
    // the following function's body into this one. The bound is the nearest of:
    // any later symbol/export address, and the caller-supplied next-function
    // start (covers symbol-less `sub_X` neighbours). Falls back to
    // MAX_FN_SCAN_BYTES when nothing bounds the function above.
    let scan_cap = load
        .symbols
        .iter()
        .map(|s| s.addr)
        .chain(load.exports.iter().map(|e| e.addr))
        .chain(next_fn_start)
        .filter(|&a| a > base_va)
        .min()
        .map_or(MAX_FN_SCAN_BYTES, |next| {
            usize::try_from(next - base_va).unwrap_or(MAX_FN_SCAN_BYTES).min(MAX_FN_SCAN_BYTES)
        });
    // Pass 1: bounded sweep (terminators end the walk at the real function end,
    // so a symbol-less neighbour is not pulled in). This is enough to see the
    // jump-table dispatch and bound check, which sit before the first `ret`.
    let perf_d = crate::perf::scope(crate::perf::Stage::Disassemble);
    // Gate `RUSTRE_PDATA_EXTENT`: semina l'estensione con la fine DICHIARATA
    // da `.pdata`, cosi' un `jmp` in avanti dopo il primo `ret` non tronca la
    // funzione. Vedi `pdata_declared_end`. Senza `.pdata` (o a gate spento) il
    // valore e' 0 e il comportamento e' identico a prima.
    let pdata_extent = if matches!(
        std::env::var("RUSTRE_PDATA_EXTENT").as_deref(),
        Ok("0") | Ok("false")
    ) {
        0
    } else {
        pdata_declared_end(load, base_va).map_or(0, |e| e.saturating_sub(1))
    };
    let mut pass1 =
        disassemble_function_x86_ext(slice, base_va, bits, scan_cap, MAX_FN_INSTRUCTIONS, pdata_extent)?;
    drop(perf_d);

    let mut pipeline = DefaultPipelineFactory::standard(opts);
    let flirt_pairs = flirt_pairs_for_load(load);
    let symbol_map = build_symbol_map_from_load(load, &flirt_pairs);
    let func_name = resolve_name_for(load, &flirt_pairs, fn_address);
    // Jump-table plumbing: detect the bounds-checked indirect-jmp idiom in the
    // disassembly, then resolve concrete case targets by reading table bytes
    // from the image — only possible here, where `load` is in scope. Detection
    // or resolution failure attaches nothing, preserving the `goto` fallback
    // (never fabricate targets).
    let perf_jt = crate::perf::scope(crate::perf::Stage::JumpTables);
    let detected_jt = detect_all_jump_tables(&pass1);
    let mut resolved: Vec<ResolvedJumpTable> = detected_jt
        .iter()
        .filter_map(|info| resolve_jump_table(load, info))
        .collect();
    // SONDA #4690: distingue «la DETECTION non trova» da «il RESOLVE rifiuta».
    // Sono due difetti diversi e il NO-OP di #4670 non dice quale sia.
    if std::env::var("RUSTRE_DBG_JTRES").is_ok_and(|v| v != "0") && !detected_jt.is_empty() {
        eprintln!(
            "JTRES fn={fn_address:X} rilevate={} risolte={} basi=[{}]",
            detected_jt.len(),
            resolved.len(),
            detected_jt
                .iter()
                .map(|i| format!(
                    "{}@{:X}/e{}",
                    i.table_addr.map_or("?".into(), |a| format!("{a:X}")),
                    i.jump_addr,
                    i.entry_size
                ))
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    // Fold `lea d(%rip),R; jmp *R` (adjacent pair, Go dispatch ladders) into a
    // direct `jmp 0xTARGET`: the target is a compile-time constant, so leaving
    // it as `JUMPOUT(R)` hides a fully-static edge from structuring. The lea is
    // neutralized to a nop so no stray `R = &off_X;` line survives.
    fold_lea_direct_jumps(&mut pass1, load);

    // Pass 2 (only when a switch was resolved): switch case bodies live past the
    // first `ret`, so re-sweep seeding the forward-extent bound with the highest
    // resolved case/default target — recovering the case bodies without letting
    // the terminator stop cut them. No table → keep the bounded pass-1 result.
    let instructions = if resolved.is_empty() {
        pass1
    } else {
        let max_target = resolved
            .iter()
            .flat_map(|t| t.cases.iter().map(|&(_, tgt)| tgt).chain(t.default_target))
            .max()
            .unwrap_or(0);
        if max_target > base_va {
            let mut ext = disassemble_function_x86_ext(
                slice,
                base_va,
                bits,
                scan_cap,
                MAX_FN_INSTRUCTIONS,
                max_target,
            )?;
            fold_lea_direct_jumps(&mut ext, load);
            ext
        } else {
            pass1
        }
    };
    // Pass-2 tables: the re-sweep above pulls in the switch CASE BODIES, and
    // those bodies can hold FURTHER jump tables (a multi-stage dispatch). Pass 1
    // never saw that code, so those tables were left as `JUMPOUT(reg)` even
    // though detection handles their shape perfectly — the gap was the analysed
    // range, not the detector. Re-detect on the extended stream and merge what
    // is genuinely new (same `jump_addr` = same table).
    if !resolved.is_empty() {
        let known: std::collections::HashSet<u64> =
            resolved.iter().map(|t| t.jump_addr).collect();
        let extra: Vec<ResolvedJumpTable> = detect_all_jump_tables(&instructions)
            .iter()
            .filter(|info| !known.contains(&info.jump_addr))
            .filter_map(|info| resolve_jump_table(load, info))
            .collect();
        resolved.extend(extra);
    }
    drop(perf_jt);
    if !resolved.is_empty() {
        pipeline.set_jump_tables(resolved);
    }
    // Section-table seam: hand the pipeline a read-only view of the image so a
    // later landing can classify data addresses (.text/.idata/.rdata/.bss/
    // unmapped) instead of blindly naming them `off_<VA>`. Nothing consults it
    // yet — this landing is output-neutral by construction.
    let perf_sym = crate::perf::scope(crate::perf::Stage::SymbolsLiterals);
    pipeline.set_data_oracle(Arc::new(DataOracle::from_load(load)));
    // String-literal recovery: name every rip-referenced data address that
    // holds a plausible ASCII/UTF-16 string with a quoted C literal, so
    // `resolve_symbols` can render `lea`-loaded addresses (`&off_X`) as
    // `"literal"`. Loader-provided names (imports, exports, symbols) win —
    // a literal is only added for otherwise-anonymous addresses.
    // Address-of-code labels (`&off_<text_va>` → `&sub_<va>`) and string
    // literals are both harvested from `lea (%rip)` targets; merge both into
    // the map, never shadowing a name the loader/FLIRT/fn-ptr passes already
    // assigned (they win — an import/export name is more specific than `sub_`).
    let mut extra_pairs = harvest_string_literals(load, &instructions);
    extra_pairs.extend(harvest_code_pointer_labels(load, &instructions));
    // Vtable labels come AFTER the code-pointer labels so that, at an equal
    // address, the more specific name already present wins the merge below.
    // Gated by `RUSTRE_VTABLE_LABELS` (default OFF) — see `harvest_vtable_labels`.
    extra_pairs.extend(harvest_vtable_labels(load));
    // The image base itself (`&off_140000000` — a `lea` of the PE header base,
    // used in PIC/relocation code as `&sym - &__ImageBase`) resolves to the
    // linker-provided `__ImageBase` symbol, as IDA labels it. The header is not
    // in an executable section so `harvest_code_pointer_labels` skips it; add it
    // explicitly. `resolve_symbols` substitutes it only in the `&off_X` position.
    if load.base_address != 0 {
        extra_pairs.push((load.base_address, "__ImageBase".to_string()));
    }
    let final_map = match (symbol_map, extra_pairs.is_empty()) {
        (Some(mut m), false) => {
            for (va, name) in extra_pairs {
                if m.resolve(va).is_none() {
                    m.insert(va, name);
                }
            }
            Some(m)
        }
        (m, true) => m,
        (None, false) => {
            let mut m = SymbolMap::new();
            for (va, name) in extra_pairs {
                if m.resolve(va).is_none() {
                    m.insert(va, name);
                }
            }
            Some(m)
        }
    };
    if let Some(m) = final_map {
        pipeline.set_symbol_resolver(Arc::new(m));
    }
    drop(perf_sym);
    let perf_ar = crate::perf::scope(crate::perf::Stage::CalleeArities);
    // Memoized fast path: the batch driver precomputes the whole-image arity
    // map once (it is a property of the IMAGE, not of the function being
    // decompiled) and hands the same immutable map to every worker.
    match arity_cache {
        Some(c) => {
            pipeline.set_callee_arities(c.0.clone());
            pipeline.set_callee_return_types(c.1.clone());
            pipeline.set_callsite_argc(c.2.clone());
        }
        None => {
            let (arities, ret_types, argc) = callee_arities_for(load, &instructions, bits);
            pipeline.set_callee_arities(arities);
            pipeline.set_callee_return_types(ret_types);
            pipeline.set_callsite_argc(argc);
        }
    }
    drop(perf_ar);
    pipeline.run_with_structured_emit(fn_address, &func_name, &instructions)
}

/// Recover the Windows-x64 arity of every direct call target of `instructions`
/// by disassembling each callee and running the same live-in argument-register
/// scan the emitter uses on the caller (bug D9).
///
/// Targets that cannot be sliced or disassembled are simply omitted, so a
/// missing entry can never invent a parameter.
fn callee_arities_for(
    load: &RichLoadResult,
    instructions: &[Instruction],
    bits: u8,
) -> ArityCache {
    let seeds: Vec<u64> = instructions.iter().filter_map(crate::direct_call_target).collect();
    arities_from_seeds(load, seeds, bits, CALLEE_MAX_NODES)
}

const CALLEE_MAX_NODES: usize = 4096;

/// Whole-image variant of [`callee_arities_for`]: seeds the same transitive
/// disassembly + fixpoint with EVERY detected function start, so the batch
/// driver can compute the map ONCE and hand the identical (immutable) map to
/// every function instead of recomputing a whole-binary property per function.
///
/// The node cap is lifted for this mode: the per-function map must be a SUBSET
/// of this one with identical values, and a 4096-node truncation over the whole
/// image could drop a VA that a per-function run would have kept.
#[must_use]
pub fn image_callee_arities(
    load: &RichLoadResult,
    starts: &[u64],
    bits: u8,
) -> ArityCache {
    arities_from_seeds(load, starts.to_vec(), bits, usize::MAX)
}

/// Un THUNK di import: la prima istruzione e' un `jmp` INDIRETTO (`jmp
/// *0x24212(%rip)`), il salto di sei byte che la PE Import Address Table
/// interpone davanti a ogni funzione importata.
///
/// Serve a `arities_from_seeds` per NON inferire un'arita' da un corpo che non
/// esiste. Il vincolo dell'asterisco e' deliberato: un tail-call DIRETTO
/// (`jmp target`) e' una funzione vera e va misurata normalmente.
/// Riconosce il prologo di salvataggio registri di una funzione VARIADICA.
///
/// Forma cercata (Win64, AT&T): un registro argomento viene salvato in uno slot
/// dello shadow space e subito dopo si prende l'INDIRIZZO di quello slot — cioe'
/// si costruisce la `va_list`:
/// ```asm
///     mov  %r9, 0x58(%rsp)
///     lea  0x58(%rsp), %r9
/// ```
/// E' l'`lea` sullo stesso offset a distinguere una variadica da un normale
/// spill di parametro: un prologo qualunque salva i registri, solo una variadica
/// ne prende l'indirizzo per scorrerli.
///
/// Si scorre TUTTO il corpo, non solo le prime istruzioni. Misurato: nel caso
/// che ha motivato questa guardia (`0x140011230` in `sample7_cpp`) la coppia
/// `mov`/`lea` sta a `0x140011284`, ~0x54 byte dopo l'ingresso — una prima
/// versione limitata alle prime 16 istruzioni non la vedeva e la guardia
/// risultava a effetto zero.
///
/// Il pattern resta specifico abbastanza: il `lea` deve puntare ESATTAMENTE
/// allo slot in cui un registro argomento e' stato salvato. E la conseguenza di
/// un falso positivo e' solo «nessuna evidenza di arita' per quel callee», che
/// e' la direzione prudente.
fn ha_prologo_variadico(body: &[Instruction]) -> bool {
    let head = body;
    // Offset di stack in cui e' stato salvato un registro argomento.
    let mut spilled: Vec<String> = Vec::new();
    for ins in head {
        let m = ins.mnemonic.to_ascii_lowercase();
        let o = ins.operands.to_ascii_lowercase();
        let Some((dst, src)) = crate::split_two(&o) else { continue };
        if crate::att_mnemonic_stem(&m) == "mov"
            && dst.contains("(%rsp)")
            && ["%rcx", "%rdx", "%r8", "%r9"].iter().any(|r| src.trim() == *r)
            && let Some(off) = dst.split('(').next()
        {
            spilled.push(off.trim().to_string());
            continue;
        }
        // `lea OFF(%rsp), reg` sullo STESSO offset appena salvato.
        if m.starts_with("lea")
            && src.contains("(%rsp)")
            && let Some(off) = src.split('(').next()
            && spilled.iter().any(|s| s == off.trim())
        {
            return true;
        }
    }
    false
}

fn e_thunk_di_import(body: &[Instruction]) -> bool {
    body.first().is_some_and(|i| {
        i.mnemonic.to_lowercase().starts_with("jmp") && i.operands.contains('*')
    })
}

/// Shared engine: transitively disassemble from `seeds`, then run the arity
/// fixpoint. Extracted verbatim from `callee_arities_for` so the per-function
/// and whole-image paths cannot drift.
/// Massimo numero di registri-argomento PREPARATI prima di una chiamata a
/// ciascun bersaglio, osservato su TUTTI i siti di chiamata dell'immagine.
///
/// E' la vista complementare a `out` (l'arieta' dedotta dal CORPO del callee) e
/// serve a una cosa sola: **smentire i parametri fantasma**. Se nessun chiamante
/// prepara mai `rcx` prima di chiamare `f`, allora il primo parametro che la
/// definizione di `f` dichiara non lo passa nessuno.
///
/// MISURATO sul testo emesso prima di scrivere questo codice: 681 funzioni di
/// path B dichiarano parametri mentre TUTTI i loro siti passano zero argomenti.
/// Incrociando con path A come controllo indipendente: **196 sono confermate**
/// (anche A passa sempre zero), 68 sono argomenti che B perde per il suo clamp,
/// 417 non sono chiamate in A e restano senza controllo.
///
/// ⚠ Assenza dalla mappa significa NESSUNA EVIDENZA, non «zero argomenti»: una
/// funzione mai chiamata nell'immagine (entry point, callback registrata,
/// export) non compare, e chi consuma questa mappa deve lasciarla stare. E' la
/// stessa disciplina delle guardie D9-THUNK e D9-NORETURN qui sopra: meglio
/// nessuna evidenza di una falsa.
///
/// Il conteggio e' un PREFISSO: `rcx,rdx,r8,r9` in ordine. Se un sito prepara
/// `rcx` e `r8` ma non `rdx`, conta 1 — perche' un buco nella sequenza vuol
/// dire che `r8` e' scratch, non il terzo argomento.
/// Ritorna, per bersaglio, `(massimo, minimo, siti, minimo_non_nullo,
/// siti_non_nulli)`.
///
/// #6840 — il minimo su TUTTI i siti e' schiacciato a zero da una sola tabella
/// di thunk o di stub: `runtime_callbackasm1_abi0` ha 2000 siti che non
/// preparano nulla, e basta uno di quelli perche' il minimo dica zero e la
/// direzione «alza» non possa mai scattare. Il minimo calcolato SOLO sui siti
/// che passano almeno un argomento e' la statistica che quella distorsione non
/// ha.
///
/// #6830 — servono ENTRAMBI gli estremi, e per ragioni opposte:
/// * il **massimo** SMENTISCE: se nessun sito prepara mai piu' di N registri,
///   i parametri oltre l'N-esimo non li passa nessuno;
/// * il **minimo** AFFERMA: se OGNI sito ne prepara almeno N, quegli N sono
///   certamente passati.
///
/// Usare il massimo per affermare e' l'errore che ho misurato: un solo sito con
/// 4 argomenti alzava la firma e le altre centinaia di chiamate a zero
/// diventavano incoerenti — `UNDER` 2448 -> **27958**.
///
/// #6810 — il CONTEGGIO DEI SITI non e' un di piu': un corpo che
/// `arities_from_seeds` tronca (`CALLEE_SCAN_BYTES` = 4096, 2000 istruzioni)
/// puo' nascondere proprio il sito informativo, e allora uno zero significa
/// «non ho guardato abbastanza», non «nessuno passa argomenti». MISURATO: col
/// clamp che si fidava di qualunque zero, 7 funzioni perdevano parametri VERI
/// (path A gliene passa). Chi consuma la mappa deve poter chiedere un minimo di
/// evidenza.
fn callsite_argc_from_bodies(
    bodies: &HashMap<u64, Vec<Instruction>>,
) -> HashMap<u64, (usize, usize, usize, usize, usize)> {
    const ARG_REGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
    let mut osservato: HashMap<u64, (usize, usize, usize, usize, usize)> = HashMap::new();
    for body in bodies.values() {
        // Stato scorrevole: quali registri argomento sono stati SCRITTI da
        // quando e' iniziata la funzione. Non si azzera a ogni blocco: un
        // argomento puo' essere preparato in un blocco e la chiamata trovarsi
        // in quello dopo.
        let mut pronto = [false; 4];
        for ins in body {
            if let Some(tgt) = crate::direct_call_target(ins) {
                // Prefisso contiguo dei registri pronti.
                let mut n = 0usize;
                while n < 4 && pronto[n] {
                    n += 1;
                }
                let e = osservato.entry(tgt).or_insert((0, usize::MAX, 0, usize::MAX, 0));
                e.0 = e.0.max(n);
                e.1 = e.1.min(n);
                e.2 += 1;
                if n > 0 {
                    e.3 = e.3.min(n);
                    e.4 += 1;
                }
                // Una chiamata CONSUMA i registri argomento: quelli del sito
                // successivo vanno preparati di nuovo. Senza questo, la prima
                // chiamata della funzione «insegnerebbe» i suoi argomenti a
                // tutte quelle dopo.
                pronto = [false; 4];
                continue;
            }
            // ⚠ #6870 — NON ogni istruzione SCRIVE il proprio operando di
            // destinazione. `cmp %rax, %rcx` e `test %rcx, %rcx` leggono
            // soltanto, e contarli come preparazione di un argomento gonfia il
            // minimo osservato. E' il difetto che ha fatto fallire la direzione
            // «alza» (§83.2): la mappa affermava che ogni sito preparava almeno
            // N registri quando non era vero, e le firme alzate a quel N
            // producevano incoerenze.
            //
            // Lista in POSITIVO (solo istruzioni che scrivono davvero), non in
            // negativo: un elenco di esclusioni dimentica sempre qualcosa, e
            // qui sbagliare per difetto e' sicuro — un'evidenza in meno non
            // inventa nulla.
            let mn = ins.mnemonic.to_ascii_lowercase();
            let m = crate::att_mnemonic_stem(&mn);
            let scrive = matches!(
                m,
                "mov" | "movz" | "movs" | "movzx" | "movsx" | "movabs" | "lea"
                    | "add" | "sub" | "and" | "or" | "xor" | "imul" | "mul"
                    | "shl" | "shr" | "sar" | "neg" | "not" | "inc" | "dec"
                    | "pop" | "cmov" | "sete" | "setne" | "xchg" | "adc" | "sbb"
            ) || m.starts_with("cmov")
                || m.starts_with("set")
                || m.starts_with("movz")
                || m.starts_with("movs");
            if !scrive {
                continue;
            }
            let o = ins.operands.to_ascii_lowercase();
            // `split_two` restituisce (destinazione, sorgente) gestendo gia'
            // l'ordine AT&T, dove la destinazione e' l'ULTIMO operando.
            let Some((dst, _src)) = crate::split_two(&o) else {
                continue;
            };
            let reg = dst.trim().trim_start_matches('%');
            if let Some(i) = ARG_REGS.iter().position(|r| *r == reg) {
                pronto[i] = true;
            } else if let Some(i) = ["ecx", "edx", "r8d", "r9d"]
                .iter()
                .position(|r| *r == reg)
            {
                // Anche la meta' a 32 bit conta: `mov $1, %ecx` prepara il
                // primo argomento tanto quanto `mov $1, %rcx`.
                pronto[i] = true;
            }
        }
    }
    osservato
}

fn arities_from_seeds(
    load: &RichLoadResult,
    seed_targets: Vec<u64>,
    bits: u8,
    max_nodes: usize,
) -> ArityCache {
    const CALLEE_SCAN_BYTES: usize = 4096;
    const CALLEE_MAX_INSTRS: usize = 2000;
    const MAX_ROUNDS: usize = 8;


    // ── Step 1: transitively disassemble the call graph reachable from this
    //    function. Transitivity is required for CONSISTENCY, not just reach:
    //    a callee's own arity can depend (via the D9 forwarding rule) on the
    //    arity of ITS callees, which are not direct targets of the root. If we
    //    stopped at depth 1 the same VA would recover a different arity
    //    depending on which unit asked, which is exactly the divergence bug.
    let mut bodies: HashMap<u64, Vec<Instruction>> = HashMap::new();
    let mut work: Vec<u64> = seed_targets;
    while let Some(tgt) = work.pop() {
        if bodies.contains_key(&tgt) || bodies.len() >= max_nodes {
            continue;
        }
        let Some((base, slice)) = slice_at_va(load, tgt) else { continue };
        let Ok(callee) =
            disassemble_function_x86(slice, base, bits, CALLEE_SCAN_BYTES, CALLEE_MAX_INSTRS)
        else {
            continue;
        };
        work.extend(callee.iter().filter_map(crate::direct_call_target));
        bodies.insert(tgt, callee);
    }

    // ── Step 2: fixed point. `win64_recovered_arity` alone passes an EMPTY
    //    map, so the D9 "argument forwarded straight to a callee" rule can
    //    never fire for a callee — while the DEFINITION path does pass the
    //    map. That asymmetry made `f21_0` recover as 2 parameters where it is
    //    defined and 1 where it is called, and the D10 clamp then trimmed the
    //    callsite to `f21_0(-15)`. Iterating with the map in hand applies the
    //    identical rule on both sides. Arities only ever grow here (the D9
    //    rule only EXTENDS an existing parameter prefix and never creates the
    //    first parameter), so the iteration is monotone and terminates.
    //    `bodies` is a `HashMap`, whose iteration order is randomised per
    //    process. Since `out` is read AND written within the same round (a
    //    later VA in this round's iteration order can see an EARLIER VA's
    //    just-bumped arity, or not, depending purely on hash order), the
    //    number of forwarding "hops" that land within a single round — and
    //    therefore which arity a VA converges to before `MAX_ROUNDS` runs out
    //    — varied between two runs over the identical binary. Sorting the
    //    processing order by VA makes that deterministic and reproducible.
    let mut order: Vec<u64> = bodies.keys().copied().collect();
    order.sort_unstable();
    // ── D9-THUNK (#6600, gate `RUSTRE_THUNK_NO_ARITY`, default ON).
    //    Un THUNK di import (`jmp *0x24212(%rip)`, sei byte attraverso la IAT)
    //    NON HA UN CORPO da cui ricavare un'arita': il passo 1 qui sopra ne
    //    disassembla `CALLEE_SCAN_BYTES` = 4096, cioe' l'INTERA TABELLA dei
    //    thunk successivi, e l'inferenza gira su quella spazzatura. L'arita'
    //    che ne esce e' un artefatto, e la regola D9 la propaga nel CHIAMANTE
    //    come parametro fantasma.
    //    MISURATO con la sonda `RUSTRE_DBG_PARAMREG`: i due soli inconsistenti
    //    di `cross_build.py` nascono entrambi cosi' in `sample7_cpp` —
    //    `__acrt_iob_func` <- thunk 0x1400173b0 arity=2, `_FindPESectionByName`
    //    <- thunk 0x1400174b0 arity=2 — mentre le altre cinque build emettono
    //    la forma giusta.
    //    ⚠ Si richiede il jump INDIRETTO (`*`): un tail-call diretto
    //    (`jmp target`) e' una funzione vera e resta misurata.
    //    Assenza dalla mappa e' il comportamento corretto: D9 e' gia' scritta
    //    per non fare nulla quando il callee non ha un'arita' nota — meglio
    //    NESSUNA evidenza di una FALSA.
    if !matches!(std::env::var("RUSTRE_THUNK_NO_ARITY").as_deref(), Ok("0") | Ok("false")) {
        order.retain(|va| !e_thunk_di_import(&bodies[va]));
    }
    // ── D9-NORETURN (#6670, gate `RUSTRE_NORETURN_NO_ARITY`, opt-in) ──────────
    //
    // Stessa logica della guardia D9-THUNK qui sopra, applicata a una seconda
    // classe di arita' che e' un ARTEFATTO e non una misura.
    //
    // Una funzione `noreturn` NON RITORNA MAI: salta nel gestore (`__stack_chk_fail`
    // -> `abort`), quindi i registri che il suo corpo "legge prima di scrivere"
    // sono quelli che il CHIAMANTE ha lasciato vivi, non i suoi parametri. La
    // liveness ne ricava 4 sistematicamente, e la regola D9 propaga quel 4 nei
    // chiamanti come parametri fantasma.
    //
    // MISURATO su `sample7_cpp` con la sonda `RUSTRE_DBG_PARAMREG`: 476
    // attivazioni della regola D9, di cui
    //     85 x callee=0x140011230 arity=4   <- `__stack_chk_fail`, che di
    //                                          parametri ne prende ZERO
    //     48 x callee=0x14002bec0 arity=4
    //     46 x callee=0x14002bc50 arity=4
    //     46 x callee=0x140022170 arity=4
    //     42 x callee=0x140022430 arity=4
    // e i 5 OVER `pthread_*` (tutti con esattamente +2 parametri, corpo che non
    // usa mai `a3`/`a4`) nascono proprio da qui: la sonda mostra
    // `fn=pthread_join callee=0x140011230 arity=4 accende a3/a4`.
    //
    // `__stack_chk_fail` NON e' nei prototipi pubblicati, quindi la strada delle
    // firme (#6650) non lo copre: serve questa regola, che e' semantica e non
    // euristica. Il bucket contiene 231 funzioni gia' riconosciute `__noreturn`.
    //
    // Assenza dalla mappa e' il comportamento corretto: D9 e' gia' scritta per
    // non fare nulla quando il callee non ha un'arita' nota — meglio NESSUNA
    // evidenza di una FALSA (stessa frase della guardia thunk, stesso motivo).
    if matches!(
        std::env::var("RUSTRE_NORETURN_NO_ARITY").as_deref(),
        Ok("1") | Ok("true")
    ) {
        order.retain(|va| !crate::detect_noreturn(&bodies[va]));
    }
    // ── D9-VARIADIC (#6680, gate `RUSTRE_VARIADIC_NO_ARITY`, opt-in) ─────────
    //
    // Terza classe di arita' che e' un ARTEFATTO, dopo i thunk (#6600) e il
    // tentativo `noreturn` (#6670, misurato a effetto zero: quelle funzioni
    // RITORNANO, vedi STATUS §32).
    //
    // Una funzione VARIADICA apre salvando i registri argomento nello shadow
    // space e prendendo l'indirizzo dello slot, per costruire la `va_list`:
    //     mov  %r9, 0x58(%rsp)     <- spill
    //     lea  0x58(%rsp), %r9     <- indirizzo dello spill = va_list
    //     mov  %r9, 0x28(%rsp)
    // Legge quindi TUTTI e quattro i registri argomento, e la sua arita' 4 e'
    // corretta PER LEI. Ma la regola D9 la propaga nei chiamanti, che variadici
    // non sono: da qui i 5 OVER `pthread_*` con esattamente +2 parametri
    // (STATUS §31.1), misurati sulla sonda come
    // `fn=pthread_join callee=0x140011230 arity=4 accende a3/a4`.
    //
    // `published_lib_arity` scarta gia' le variadiche (`if sig.is_variadic`),
    // ma li' il callee e' noto per NOME; qui e' noto solo per VA, quindi serve
    // riconoscere il prologo.
    //
    // Assenza dalla mappa e' il comportamento corretto: D9 non fa nulla quando
    // il callee non ha un'arita' nota — meglio NESSUNA evidenza di una FALSA
    // (stessa motivazione della guardia thunk).
    if matches!(
        std::env::var("RUSTRE_VARIADIC_NO_ARITY").as_deref(),
        Ok("1") | Ok("true")
    ) {
        order.retain(|va| !ha_prologo_variadico(&bodies[va]));
    }
    let mut out: HashMap<u64, usize> =
        order.iter().map(|&va| (va, crate::win64_recovered_arity(&bodies[&va]))).collect();
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for &va in &order {
            let body = &bodies[&va];
            let arity = crate::win64_recovered_arity_with(body, &out);
            if arity > out[&va] {
                out.insert(va, arity);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // D18: alongside the arity, predict each callee's RETURN TYPE from the same
    // disassembled body, so `emit_callee_forward_decls` can declare a callee
    // that resolved to a real symbol name with a prototype that matches the
    // definition its own emit will print. Callees whose return type cannot be
    // predicted confidently are simply absent, and are then never declared.
    let ret_types: HashMap<u64, String> = bodies
        .iter()
        .filter_map(|(&va, b)| crate::predicted_return_type(b).map(|t| (va, t.to_string())))
        .collect();
    // SONDA #6800 (`RUSTRE_DBG_ARGC=1`, effetto ZERO): confronta l'arieta'
    // dedotta dal CORPO con gli argomenti che i chiamanti PREPARANO davvero.
    // Serve a validare la mappa PRIMA di collegarla a qualunque decisione.
    let argc = callsite_argc_from_bodies(&bodies);
    if std::env::var("RUSTRE_DBG_ARGC").is_ok_and(|v| v != "0") {
        let (mut sopra, mut pari, mut sotto, mut senza) = (0usize, 0usize, 0usize, 0usize);
        let mut fantasmi = 0usize;
        for (&va, &ar) in &out {
            match argc.get(&va) {
                None => senza += 1,
                Some(&(c, ..)) if ar > c => {
                    sopra += 1;
                    fantasmi += ar - c;
                }
                Some(&(c, ..)) if ar < c => sotto += 1,
                _ => pari += 1,
            }
        }
        eprintln!(
            "[argc] bersagli={} con_siti={} arita>argc={sopra} (parametri_smentiti={fantasmi}) arita<argc={sotto} pari={pari} senza_siti={senza}",
            out.len(),
            argc.len()
        );
    }
    (out, ret_types, argc)
}

/// Scan a function's instructions for rip-relative data references whose
/// target bytes look like a NUL-terminated ASCII or UTF-16LE string, and
/// return `(va, "escaped literal")` pairs. Only `lea` references are
/// harvested — `lea` yields the string's ADDRESS (emitted `&off_VA`), which is
/// the only form the emitter rewrites to a literal; a load (`mov reg,
/// [rip+X]`) reads the string BYTES and must keep its data-symbol spelling.
fn harvest_string_literals(
    load: &RichLoadResult,
    instructions: &[Instruction],
) -> Vec<(u64, String)> {
    let mut pairs: Vec<(u64, String)> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for ins in instructions {
        if !ins.mnemonic.eq_ignore_ascii_case("lea") || !ins.operands.contains("(%rip)") {
            continue;
        }
        for va in crate::rip_ref_targets(&ins.operands, ins.next_address().0) {
            if !seen.insert(va) {
                continue;
            }
            if let Some((_, bytes)) = slice_at_va(load, va)
                && let Some(lit) = read_string_literal(bytes)
            {
                pairs.push((va, lit));
            }
        }
    }
    pairs
}

/// Scan a function's instructions for `lea reg, [rip+X]` references whose
/// target VA lands inside an executable section, and return `(va, "sub_<VA>")`
/// pairs. Such a `lea` takes the ADDRESS of code — a function pointer handed to
/// `atexit`/`__do_global_ctors`/`_register_frame` — which the disassembler
/// labels as an anonymous data symbol (`&off_140009580`). Naming the target
/// `sub_<VA>` lets `resolve_symbols` render it `&sub_140009580` (a genuine
/// function pointer, as IDA does) and `emit_callee_forward_decls` prototype it.
/// Only `lea` (address-of) is harvested — a load through the address reads code
/// bytes and must keep its data spelling. Mirrors `harvest_string_literals`.
fn harvest_code_pointer_labels(
    load: &RichLoadResult,
    instructions: &[Instruction],
) -> Vec<(u64, String)> {
    // Executable-section ranges (PE IMAGE_SCN_MEM_EXECUTE / ELF SHF_EXECINSTR,
    // or the canonical `.text` name as a fallback).
    let exec_ranges: Vec<(u64, u64)> = load
        .sections
        .iter()
        .filter(|s| {
            (s.flags & 0x2000_0000 != 0
                || s.flags & 0x4 != 0 && load.format.starts_with("ELF")
                || s.name == ".text")
                && s.virtual_size > 0
        })
        .map(|s| (s.virtual_addr, s.virtual_addr + s.virtual_size))
        .collect();
    if exec_ranges.is_empty() {
        return Vec::new();
    }
    let in_exec = |va: u64| exec_ranges.iter().any(|&(lo, hi)| va >= lo && va < hi);
    let mut pairs: Vec<(u64, String)> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for ins in instructions {
        if !ins.mnemonic.eq_ignore_ascii_case("lea") || !ins.operands.contains("(%rip)") {
            continue;
        }
        for va in crate::rip_ref_targets(&ins.operands, ins.next_address().0) {
            if !seen.insert(va) {
                continue;
            }
            if in_exec(va) {
                pairs.push((va, format!("sub_{va:X}")));
            }
        }
    }
    pairs
}

/// Name high-confidence C++ vtables found by `rustre-analysis-vtable`, so a
/// data address that is really a vtable renders as `vtable_<VA>` instead of the
/// anonymous `off_<VA>`.
///
/// GATED, default OFF: this CHANGES emitted text (path A included), so it only
/// runs when `RUSTRE_VTABLE_LABELS` is `1`/`true`.  With the variable unset the
/// function returns an empty vector and the merge at the call site is a no-op,
/// leaving the output byte-identical.
///
/// The merge rule at the call site is "whoever is already there wins", so a
/// loader/import/export/FLIRT name is never shadowed by a synthetic label.
#[cfg(feature = "cpp")]
fn harvest_vtable_labels(load: &RichLoadResult) -> Vec<(u64, String)> {
    if !matches!(std::env::var("RUSTRE_VTABLE_LABELS").as_deref(), Ok("1") | Ok("true")) {
        return Vec::new();
    }
    let secs: Vec<(String, u64, u64, u64, u64, u32)> = load
        .sections
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                s.virtual_addr,
                s.virtual_size,
                s.raw_offset,
                s.raw_size,
                s.flags,
            )
        })
        .collect();
    crate::analysis_bridge::cpp::scan_vtables(&secs, &load.data, u32::from(load.bits))
        .into_iter()
        .filter(|&(_, slots, conf)| slots >= 3 && conf >= 0.80)
        .map(|(addr, _, _)| (addr, format!("vtable_{addr:X}")))
        .collect()
}

/// Feature-off stub: without the `cpp` feature there is no vtable analyser, so
/// the harvest is empty and the call site stays identical either way.
#[cfg(not(feature = "cpp"))]
fn harvest_vtable_labels(_load: &RichLoadResult) -> Vec<(u64, String)> {
    Vec::new()
}

/// Decode a plausible C string literal from raw section bytes: an ASCII (or
/// UTF-16LE with ASCII code points) run of at least 4 printable characters
/// terminated by NUL within the scan window. Returns the escaped, quoted C
/// literal (truncated with `...` past 60 chars), or `None` when the bytes
/// don't look like a string. UTF-16 strings are emitted with an `L` prefix.
fn read_string_literal(bytes: &[u8]) -> Option<String> {
    const MIN_LEN: usize = 4;
    const MAX_SCAN: usize = 512;
    const MAX_EMIT: usize = 60;
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r';
    let escape = |s: &[u8]| {
        let mut out = String::new();
        for &b in s.iter().take(MAX_EMIT) {
            match b {
                b'\\' => out.push_str("\\\\"),
                b'"' => out.push_str("\\\""),
                b'\n' => out.push_str("\\n"),
                b'\t' => out.push_str("\\t"),
                b'\r' => out.push_str("\\r"),
                _ => out.push(b as char),
            }
        }
        if s.len() > MAX_EMIT {
            out.push_str("...");
        }
        out
    };
    let window = &bytes[..bytes.len().min(MAX_SCAN)];
    // ASCII: printable run then NUL.
    let run = window.iter().take_while(|&&b| printable(b)).count();
    if run >= MIN_LEN && window.get(run) == Some(&0) {
        return Some(format!("\"{}\"", escape(&window[..run])));
    }
    // UTF-16LE with ASCII code points: (printable, 0) pairs then 00 00.
    if run <= 1 {
        let mut chars: Vec<u8> = Vec::new();
        let mut k = 0;
        while k + 1 < window.len() && printable(window[k]) && window[k + 1] == 0 {
            chars.push(window[k]);
            k += 2;
        }
        if chars.len() >= MIN_LEN
            && k + 1 < window.len()
            && window[k] == 0
            && window[k + 1] == 0
        {
            return Some(format!("L\"{}\"", escape(&chars)));
        }
    }
    None
}

/// Build a `SymbolMap` from a loader result's `symbols` + `exports`. Returns
/// `None` when no names are available. Names are pushed through the
/// Rust-aware demangler so PDB-emitted symbols on Rust binaries render as
/// short `module::function` instead of the raw mangled form. Used to wire
/// PDB/FLIRT bindings into the pipeline so call-site `sub_<HEX>` placeholders
/// are rewritten to readable names.
/// Demangle a symbol name for display: C++ (Itanium `_Z…` / MSVC `?…`), Go, and
/// other schemes the dispatcher recognises render as readable
/// `namespace::function(args)` instead of the raw mangled form — matching
/// Hex-Rays. Rust names are left to the SymbolMap's own Rust demangler. A name
/// that is not mangled (or fails to demangle) is returned unchanged.
fn demangle_name(name: &str) -> String {
    match rustre_demangle::demangle(name) {
        Some(d) if !d.demangled.is_empty() => d.demangled,
        _ => name.to_string(),
    }
}

/// Demangled name suitable for a function *declaration*: the readable
/// `namespace::class::function` form with the parameter list dropped. A name
/// carrying `(args)` would give the signature line two paren groups and break
/// the downstream signature/calling-convention parsers, which key on the first
/// `(`. Un-mangled names pass through unchanged.
fn demangle_decl_name(name: &str) -> String {
    let full = demangle_name(name);
    // Strip the argument list: cut at the first top-level `(`.
    let mut depth = 0i32;
    for (i, c) in full.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth == 0 => return full[..i].trim_end().to_string(),
            _ => {}
        }
    }
    full
}

/// Statically-initialized function pointers: `(slot VA, target VA)` pairs
/// harvested from initialized data sections whose stored qword points into an
/// executable section. mingw/MSVC emit callback tables and lazy-init thunk
/// slots this way (`call [rip+off_X]` where `off_X` lives in `.data`/`.rdata`
/// and is seeded at link time with a real function address). Mapping the slot
/// to its initial target lets the call-position symbol rewrite render
/// `off_14002D100(2)` as `sub_140016F00(2)` — the same resolution IDA shows.
/// Only call/JUMPOUT positions consume these names, so a false positive (e.g.
/// a jump-table entry) costs nothing unless the code actually calls through
/// the slot.
fn static_fn_ptr_pairs(load: &RichLoadResult) -> Vec<(u64, u64)> {
    if load.bits != 64 || load.endian == "big" {
        return Vec::new();
    }
    let is_code = |s: &SectionInfo| {
        // PE IMAGE_SCN_MEM_EXECUTE / ELF SHF_EXECINSTR, plus the canonical name
        // as a fallback for formats that don't surface flags.
        s.flags & 0x2000_0000 != 0 || s.flags & 0x4 != 0 && load.format.starts_with("ELF")
            || s.name == ".text"
    };
    let code_ranges: Vec<(u64, u64)> = load
        .sections
        .iter()
        .filter(|s| is_code(s) && s.virtual_size > 0)
        .map(|s| (s.virtual_addr, s.virtual_addr + s.virtual_size))
        .collect();
    if code_ranges.is_empty() {
        return Vec::new();
    }
    let in_code = |va: u64| code_ranges.iter().any(|&(lo, hi)| va >= lo && va < hi);
    let mut out = Vec::new();
    for s in &load.sections {
        // Initialized, non-executable data with backing bytes in the file.
        if is_code(s) || s.raw_size == 0 || s.raw_offset == 0 {
            continue;
        }
        let start = s.raw_offset as usize;
        let len = (s.raw_size.min(s.virtual_size.max(s.raw_size)) as usize)
            .min(load.data.len().saturating_sub(start));
        let bytes = &load.data[start..start + len];
        for off in (0..len.saturating_sub(7)).step_by(8) {
            let v = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            if v != 0 && in_code(v) {
                out.push((s.virtual_addr + off as u64, v));
            }
        }
    }
    out
}

fn build_symbol_map_from_load(
    load: &RichLoadResult,
    flirt_pairs: &[(u64, String)],
) -> Option<SymbolMap> {
    // Call-site names become C call expressions, so each must be a valid C
    // identifier. Go method symbols (`runtime.(*mspan).heapBitsSmallForAddr`)
    // and C++ demangled names carry `.`/`(`/`)`/`*`/`<>`/`::` that the emitter
    // otherwise leaves as broken tokens (`runtime_(*mspan).heapBits…`, where
    // `mspan` then reads as an undeclared variable). Sanitize the whole name to
    // one identifier at the map source so every call site is compilable.
    let clean_name = |n: &str| crate::sanitize_c_identifier(&demangle_name(n));
    let pairs = load
        .symbols
        .iter()
        .filter(|s| s.addr != 0 && !s.name.is_empty())
        .map(|s| (s.addr, clean_name(&s.name)))
        .chain(
            load.exports
                .iter()
                .filter(|e| e.addr != 0 && !e.name.is_empty())
                .map(|e| (e.addr, clean_name(&e.name))),
        )
        // Dynamic imports: map each IAT slot address to its WinAPI/CRT name so a
        // call through the slot renders as `GetProcAddress(...)` instead of an
        // anonymous `off_<hex>(...)`. IDA labels these the same way.
        .chain(
            load.imports
                .iter()
                .filter(|i| i.addr != 0 && !i.name.is_empty())
                .map(|i| (i.addr, i.name.clone())),
        )
        // FLIRT-derived names last: flirt_pairs_with_scanner already excludes
        // any address the loader named, so these never shadow real symbols.
        .chain(flirt_pairs.iter().map(|(a, n)| (*a, clean_name(n))));
    let pairs: Vec<(u64, String)> = pairs.collect();
    // Statically-initialized function-pointer slots resolve to their initial
    // target's name (or `sub_<hex>` for an unnamed target, which the
    // forward-decl pass prototypes). Never shadow a slot the loader already
    // named (an IAT entry is also such a slot — its import name must win).
    let named: std::collections::HashSet<u64> = pairs.iter().map(|(a, _)| *a).collect();
    let target_name = |t: u64| {
        pairs
            .iter()
            .find(|(a, _)| *a == t)
            .map_or_else(|| format!("sub_{t:X}"), |(_, n)| n.clone())
    };
    let fn_ptr_pairs: Vec<(u64, String)> = static_fn_ptr_pairs(load)
        .into_iter()
        .filter(|(slot, _)| !named.contains(slot))
        .map(|(slot, target)| (slot, target_name(target)))
        .collect();
    let mut map = SymbolMap::from_flirt_pairs(pairs.into_iter().chain(fn_ptr_pairs));
    // Tag IAT slot addresses so `resolve_symbols` can render bare data
    // references to them as `__imp_<Name>` (IDA convention) while call
    // positions keep the bare API name.
    for imp in load.imports.iter().filter(|i| i.addr != 0 && !i.name.is_empty()) {
        map.mark_import(imp.addr);
    }
    // If absolutely nothing was harvested, return None so the pipeline keeps
    // its default behavior unchanged.
    if map.is_empty() { None } else {
        // Already Rust-demangle enabled via `from_flirt_pairs`.
        // Keep an explicit re-enable to make intent crystal clear.
        map.enable_rust_demangling(true);
        Some(map)
    }
}

/// Choose a display name for the function at `va` — prefer a matching symbol,
/// fall back to `sub_<hex>`.
fn resolve_name_for(load: &RichLoadResult, flirt_pairs: &[(u64, String)], va: u64) -> String {
    // The declaration name becomes the C function signature identifier, so it
    // MUST be a valid C identifier — Go (`runtime.makechan`) and mangled names
    // carry `.`/`:`/`/` that are hard syntax errors. Sanitize at this source so
    // the signature is born clean; body call sites are cleaned by the
    // `sanitize_symbol_names` emit pass.
    // `demangle_decl_name` cuts a demangled name at its first top-level `(` —
    // for an operator/thunk symbol whose canonical form has no identifier
    // before that paren (or any other input that sanitizes down to nothing),
    // this can yield an EMPTY string. An empty function name is a hard syntax
    // error (`void __fastcall () {`), strictly worse than the honest
    // `sub_<hex>` fallback, so every branch below must reject an empty
    // cleaned result and keep looking rather than return it.
    let clean = |n: &str| crate::sanitize_c_identifier(&demangle_decl_name(n));
    if let Some(sym) = load.symbols.iter().find(|s| s.addr == va) {
        let c = clean(&sym.name);
        if !c.is_empty() {
            return c;
        }
    }
    if let Some(exp) = load.exports.iter().find(|e| e.addr == va) {
        let c = clean(&exp.name);
        if !c.is_empty() {
            return c;
        }
    }
    if let Some((_, name)) = flirt_pairs.iter().find(|(a, _)| *a == va) {
        let c = clean(name);
        if !c.is_empty() {
            return c;
        }
    }
    format!("sub_{va:X}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Whole-binary function enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Discover every function inside `load` using prologue scan + call-target
/// collection. Returns `(boundary, name)` pairs.
#[must_use] 
pub fn detect_functions_in_load(load: &RichLoadResult) -> Vec<FunctionBoundary> {
    let arch = detected_arch_for(load);
    let detector = FunctionDetector::new(arch);

    // Seed hints from loader symbols + exports + entry point.
    let mut hints: Vec<FunctionBoundary> = Vec::new();
    if let Some(ep) = load.entry_point {
        hints.push(
            FunctionBoundary::new(
                Address::new(ep),
                rustre_analysis_fn::Confidence::Certain,
                rustre_analysis_fn::DetectionSource::EntryPoint,
            )
            .with_name("entry"),
        );
    }
    for sym in &load.symbols {
        if sym.addr == 0 || sym.name.is_empty() || sym.kind != "function" {
            continue;
        }
        hints.push(
            FunctionBoundary::new(
                Address::new(sym.addr),
                rustre_analysis_fn::Confidence::Certain,
                rustre_analysis_fn::DetectionSource::SymbolTable,
            )
            .with_name(sym.name.clone()),
        );
    }
    for exp in &load.exports {
        if exp.addr == 0 || exp.name.is_empty() {
            continue;
        }
        hints.push(
            FunctionBoundary::new(
                Address::new(exp.addr),
                rustre_analysis_fn::Confidence::Certain,
                rustre_analysis_fn::DetectionSource::SymbolTable,
            )
            .with_name(exp.name.clone()),
        );
    }

    // Sonda a EFFETTO ZERO: dice se un nome atteso e' fra i SEMI. Serve perche'
    // due ipotesi su `find_max` (sample3_rust, NOT_EMITTED) sono gia' cadute e
    // il dato mancante e' proprio questo — misurare DOVE si decide.
    if let Ok(cercato) = std::env::var("RUSTRE_DBG_HINTS") {
        let trovati: Vec<String> = hints
            .iter()
            .filter(|h| h.name.as_deref().is_some_and(|n| n.contains(cercato.as_str())))
            .map(|h| format!("{}@{:#x}", h.name.clone().unwrap_or_default(), h.start.0))
            .collect();
        eprintln!("[hints] totale={} cercato={cercato:?} trovati={trovati:?}", hints.len());
    }

    // Run the detector over each executable section in turn, then merge.
    let mut all: Vec<FunctionBoundary> = Vec::new();
    if load.sections.is_empty() {
        let mem = MemorySlice::new(Address::new(load.base_address), &load.data);
        all.extend(detector.analyze(&mem, hints));
    } else {
        for section in &load.sections {
            if !is_executable_section(section) {
                continue;
            }
            let start = usize::try_from(section.raw_offset).unwrap_or(usize::MAX);
            let end = start
                .saturating_add(usize::try_from(section.raw_size).unwrap_or(0))
                .min(load.data.len());
            if start >= end {
                continue;
            }
            let mem = MemorySlice::new(Address::new(section.virtual_addr), &load.data[start..end]);
            // Pass hints only on the first iteration; the detector merges anyway.
            let h = if all.is_empty() { hints.clone() } else { Vec::new() };
            all.extend(detector.analyze(&mem, h));
        }
    }

    // Drop spurious prologue-scan starts. The prologue scanner matches at
    // every byte offset, so mid-function `push rbp; mov rbp,rsp` sequences
    // and padding-embedded patterns dominate over-detection. Keep a
    // ProloguePattern boundary only when it is corroborated (call target,
    // symbol, export, entry point, or a non-heuristic detector source at the
    // same address) or when it sits at a plausible function boundary
    // (section start, or immediately after int3/nop/zero padding or a ret).
    let corroborated = collect_corroborated_addrs(load, &detector, &all);
    all.retain(|b| !is_spurious_prologue_start(b, &corroborated, load));

    // Deduplicate by start address.
    all.sort_by_key(|b| b.start.as_u64());
    all.dedup_by_key(|b| b.start.as_u64());
    all
}

/// Gather every address with non-prologue-heuristic evidence of being a
/// function start: loader entry point, function symbols, exports, direct
/// call targets inside each executable section, and any detector-reported
/// boundary whose source is authoritative (pdata/unwind, FLIRT, symbols,
/// call targets, entry, user). Needed because `merge_results` in the
/// detector dedups by address keeping only the highest-confidence entry, so
/// a High ProloguePattern hit hides a coincident CallTarget entry.
fn collect_corroborated_addrs(
    load: &RichLoadResult,
    detector: &FunctionDetector,
    detected: &[FunctionBoundary],
) -> HashSet<u64> {
    let mut set: HashSet<u64> = HashSet::new();
    if let Some(ep) = load.entry_point {
        set.insert(ep);
    }
    set.extend(load.symbols.iter().filter(|s| s.addr != 0).map(|s| s.addr));
    set.extend(load.exports.iter().filter(|e| e.addr != 0).map(|e| e.addr));

    // Direct call targets, re-collected per executable section (same slicing
    // as the main detection loop) because the merged results may have lost
    // the CallTarget source to a higher-confidence prologue entry.
    if load.sections.is_empty() {
        let mem = MemorySlice::new(Address::new(load.base_address), &load.data);
        set.extend(
            detector
                .collect_call_targets(&mem)
                .iter()
                .map(|fb| fb.start.as_u64()),
        );
    } else {
        for section in &load.sections {
            if !is_executable_section(section) {
                continue;
            }
            let start = usize::try_from(section.raw_offset).unwrap_or(usize::MAX);
            let end = start
                .saturating_add(usize::try_from(section.raw_size).unwrap_or(0))
                .min(load.data.len());
            if start >= end {
                continue;
            }
            let mem =
                MemorySlice::new(Address::new(section.virtual_addr), &load.data[start..end]);
            set.extend(
                detector
                    .collect_call_targets(&mem)
                    .iter()
                    .map(|fb| fb.start.as_u64()),
            );
        }
    }

    // Anything the detector itself attributed to an authoritative source
    // (unwind/pdata, FLIRT, symbol table, entry, user hints, call targets).
    set.extend(
        detected
            .iter()
            .filter(|b| {
                !matches!(
                    b.source,
                    rustre_analysis_fn::DetectionSource::ProloguePattern
                        | rustre_analysis_fn::DetectionSource::HeuristicGap
                )
            })
            .map(|b| b.start.as_u64()),
    );
    set
}

/// A ProloguePattern-only boundary is spurious unless it is corroborated,
/// Certain, or begins at a plausible function boundary: the start of its
/// section, or immediately after alignment padding (0xCC int3, 0x90 nop,
/// 0x00 zero fill) or a near/far ret (0xC3/0xCB). Mid-function prologue
/// re-matches are preceded by arbitrary code bytes and get dropped.
/// Subsumes the old Low+ProloguePattern rule.
fn is_spurious_prologue_start(
    b: &FunctionBoundary,
    corroborated: &HashSet<u64>,
    load: &RichLoadResult,
) -> bool {
    use rustre_analysis_fn::{Confidence, DetectionSource};
    if !matches!(b.source, DetectionSource::ProloguePattern) {
        return false;
    }
    let va = b.start.as_u64();
    if matches!(b.confidence, Confidence::Certain) || corroborated.contains(&va) {
        return false;
    }
    if matches!(b.confidence, Confidence::Low) {
        // Uncorroborated Low prologue guess: always spurious (existing rule).
        return true;
    }
    // Medium/High uncorroborated: require a boundary-shaped predecessor.
    !starts_at_function_boundary(load, va)
}

/// True when `va` is the first byte of an executable region or the byte
/// immediately before it is padding/terminator material.
fn starts_at_function_boundary(load: &RichLoadResult, va: u64) -> bool {
    if load.sections.is_empty() {
        if va == load.base_address {
            return true;
        }
    } else if load
        .sections
        .iter()
        .any(|s| is_executable_section(s) && s.virtual_addr == va)
    {
        return true;
    }
    let Some(prev) = va.checked_sub(1) else {
        return true;
    };
    match slice_at_va(load, prev).and_then(|(_, s)| s.first().copied()) {
        Some(0xCC | 0x90 | 0x00 | 0xC3 | 0xCB) => true,
        Some(_) => false,
        // Predecessor unmapped: cannot disprove a boundary, so keep it.
        None => true,
    }
}

/// A boundary that is only a low-confidence prologue guess, with no other
/// evidence, is likely spurious.
///
/// ⚠ The previous sentence here read "Used to curb over-detection". That was
/// false: this predicate had **no caller anywhere in the workspace**, so no
/// over-detection was ever curbed by it. The claim was hidden behind an
/// `#[allow(dead_code)]`; removing the attribute surfaced it.
///
/// It is exposed rather than wired into the boundary filter on purpose.
/// Dropping every `Low`+`ProloguePattern` boundary changes which functions the
/// batch path emits, so it moves `c_files`, `arity_*` and `behaviour_*` at
/// once. That is a fidelity change and belongs to a measured before/after run
/// via `measure.sh`, not to a warning cleanup. Until such a run exists, the
/// honest state is: the predicate is available and unused, and this comment
/// says so instead of claiming otherwise.
pub const fn is_weak_false_positive(b: &FunctionBoundary) -> bool {
    matches!(b.confidence, rustre_analysis_fn::Confidence::Low)
        && matches!(b.source, rustre_analysis_fn::DetectionSource::ProloguePattern)
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: build a pre-configured pipeline for the batch path
// ─────────────────────────────────────────────────────────────────────────────

/// Construct the standard decompiler pipeline wrapped in an `Arc` so callers
/// (e.g. `BatchDecompiler::new`) can share it across worker threads.
#[must_use]
pub fn standard_pipeline_arc(opts: DecompOptions) -> Arc<DecompilerPipeline> {
    Arc::new(DefaultPipelineFactory::standard(opts))
}
// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_analysis_fn::{Confidence, DetectionSource};
    use rustre_core::address::Address;

    fn istr(addr: u64, mnem: &str, ops: &str) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 6, mnem.to_string(), vec![0x90]);
        i.operands = ops.to_string();
        i
    }

    /// #6600: il thunk di import va riconosciuto — e' la forma da cui NON si
    /// puo' ricavare un'arita'.
    #[test]
    fn thunk_di_import_riconosciuto() {
        let corpo = vec![
            istr(0x1400173b0, "jmpq", "*0x24212(%rip)"),
            istr(0x1400173b6, "nop", ""),
        ];
        assert!(e_thunk_di_import(&corpo));
    }

    /// ⚠ Il vincolo dell'asterisco: un tail-call DIRETTO e' una funzione vera.
    #[test]
    fn tail_call_diretto_non_e_un_thunk() {
        let corpo = vec![istr(0x140001000, "jmp", "0x140002000")];
        assert!(!e_thunk_di_import(&corpo));
    }

    /// Una funzione normale non viene mai scambiata per un thunk.
    #[test]
    fn funzione_normale_non_e_un_thunk() {
        let corpo = vec![
            istr(0x140001000, "push", "%rbp"),
            istr(0x140001001, "jmpq", "*%rax"),
        ];
        assert!(!e_thunk_di_import(&corpo));
    }

    /// Synthetic layout: .text / .rdata (init) / .idata / .bss, image base 0x1000.
    fn synthetic_oracle() -> DataOracle {
        // (va, vsize, raw_offset, raw_size, kind)
        let secs = vec![
            (0x1000, 0x100, 0x00, 0x100, SectionKind::Text),
            (0x2000, 0x100, 0x100, 0x100, SectionKind::Init),
            (0x3000, 0x100, 0x200, 0x100, SectionKind::Idata),
            (0x4000, 0x100, 0x300, 0x000, SectionKind::Bss),
        ];
        let mut image = vec![0u8; 0x300];
        image[0x100..0x104].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        DataOracle::from_parts(secs, image)
    }

    #[test]
    fn data_oracle_classifies_each_section_and_unmapped() {
        let o = synthetic_oracle();
        assert_eq!(o.section_kind(0x1040), SectionKind::Text);
        assert_eq!(o.section_kind(0x2000), SectionKind::Init);
        assert_eq!(o.section_kind(0x3080), SectionKind::Idata);
        assert_eq!(o.section_kind(0x40FF), SectionKind::Bss);
        // Gaps between sections and addresses past the image are unmapped.
        assert_eq!(o.section_kind(0x1500), SectionKind::None);
        assert_eq!(o.section_kind(0xDEAD_0000), SectionKind::None);
    }

    #[test]
    fn data_oracle_reads_file_backed_bytes_only() {
        let o = synthetic_oracle();
        assert_eq!(o.data_at(0x2000, 4), Some(&[0xDEu8, 0xAD, 0xBE, 0xEF][..]));
        // .bss has no raw bytes; unmapped has no section; over-long reads fail.
        assert_eq!(o.data_at(0x4000, 1), None);
        assert_eq!(o.data_at(0x1500, 1), None);
        assert_eq!(o.data_at(0x20FF, 4), None);
    }

    #[test]
    fn pipeline_without_oracle_matches_pipeline_with_none() {
        // The seam is optional: a default-constructed pipeline carries no
        // oracle, and the context it builds carries none either.
        let p = DefaultPipelineFactory::standard(DecompOptions::default());
        assert!(!format!("{p:?}").is_empty());
        let ctx =
            crate::DecompilerContext::new(0x1000, "f", DecompOptions::default());
        assert!(ctx.data_oracle.is_none());
    }

    #[test]
    fn harvest_code_pointer_labels_names_lea_of_text_addr() {
        use rustre_core::arch::Instruction;
        let mut load = RichLoadResult::new(vec![0u8; 0x10]);
        load.bits = 64;
        load.endian = "little".into();
        load.format = "PE64".into();
        // .text 0x140001000..0x140003000 (exec), .data 0x140004000..0x140006000.
        load.sections.push(SectionInfo::new(
            ".text", 0x1_4000_1000, 0x2000, 0, 0, 0x2000_0020,
        ));
        load.sections.push(SectionInfo::new(
            ".data", 0x1_4000_4000, 0x2000, 0, 0, 0xC000_0040,
        ));
        // `lea` at 0x140001000 (size 7, next=0x140001007) with disp 0x14F9 →
        // target 0x140002500 (inside .text) → harvested as sub_140002500.
        let mut lea_code = Instruction::new(Address::new(0x1_4000_1000), 7, "lea", vec![]);
        lea_code.operands = "0x14F9(%rip), %rcx".into();
        // `lea` to a .data address (0x140005000) → must be ignored.
        let mut lea_data = Instruction::new(Address::new(0x1_4000_1010), 7, "lea", vec![]);
        lea_data.operands = "0x3FE9(%rip), %rdx".into();
        // A non-lea rip ref (a load) → must be ignored even if it targets code.
        let mut mov = Instruction::new(Address::new(0x1_4000_1020), 7, "mov", vec![]);
        mov.operands = "0x14D9(%rip), %rax".into();
        let pairs = harvest_code_pointer_labels(&load, &[lea_code, lea_data, mov]);
        assert_eq!(pairs, vec![(0x1_4000_2500, "sub_140002500".to_string())]);
    }

    #[cfg(feature = "cpp")]
    #[test]
    fn harvest_vtable_labels_is_gated_off_by_default() {
        // File layout: 0x00..0x40 = .text raw, 0x40..0x70 = .rdata raw.
        // .rdata+0x00 holds an RTTI-descriptor pointer (aligned, non-code, not
        // in the null page), and .rdata+0x08..0x28 holds four pointers into
        // .text — a textbook 4-slot vtable preceded by its RTTI word.
        let mut data = vec![0u8; 0x70];
        data[0x40..0x48].copy_from_slice(&0x1_4000_4100u64.to_le_bytes());
        for (i, target) in [0x1_4000_1000u64, 0x1_4000_1010, 0x1_4000_1020, 0x1_4000_1030]
            .into_iter()
            .enumerate()
        {
            let off = 0x48 + i * 8;
            data[off..off + 8].copy_from_slice(&target.to_le_bytes());
        }
        let mut load = RichLoadResult::new(data);
        load.bits = 64;
        load.endian = "little".into();
        load.format = "PE64".into();
        load.sections.push(SectionInfo::new(
            ".text",
            0x1_4000_1000,
            0x2000,
            0x00,
            0x40,
            0x2000_0020,
        ));
        load.sections.push(SectionInfo::new(
            ".rdata",
            0x1_4000_4000,
            0x2000,
            0x40,
            0x30,
            0x4000_0040,
        ));

        // The scanner itself sees the vtable — the crate IS wired in.
        let secs: Vec<(String, u64, u64, u64, u64, u32)> = load
            .sections
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    s.virtual_addr,
                    s.virtual_size,
                    s.raw_offset,
                    s.raw_size,
                    s.flags,
                )
            })
            .collect();
        let found =
            crate::analysis_bridge::cpp::scan_vtables(&secs, &load.data, u32::from(load.bits));
        assert!(
            found.iter().any(|&(a, slots, _)| a == 0x1_4000_4008 && slots == 4),
            "scanner should find the 4-slot vtable at .rdata+8, got {found:?}"
        );

        // …but the harvest is a no-op unless the gate is explicitly ON.
        // SAFETY: single-threaded test; the variable is restored before return.
        let prev = std::env::var("RUSTRE_VTABLE_LABELS").ok();
        unsafe { std::env::remove_var("RUSTRE_VTABLE_LABELS") };
        assert_eq!(harvest_vtable_labels(&load), Vec::new(), "gate must default OFF");

        unsafe { std::env::set_var("RUSTRE_VTABLE_LABELS", "1") };
        let on = harvest_vtable_labels(&load);
        match prev {
            Some(v) => unsafe { std::env::set_var("RUSTRE_VTABLE_LABELS", v) },
            None => unsafe { std::env::remove_var("RUSTRE_VTABLE_LABELS") },
        }
        assert_eq!(on, vec![(0x1_4000_4008, "vtable_140004008".to_string())]);
    }

    #[test]
    fn static_fn_ptr_pairs_finds_data_slot_pointing_into_text() {
        // File layout: 0x00..0x40 = .text raw, 0x40..0x60 = .data raw.
        let mut data = vec![0u8; 0x60];
        // .data+0x08 holds a pointer to VA 0x140001010 (inside .text).
        data[0x48..0x50].copy_from_slice(&0x1_4000_1010u64.to_le_bytes());
        // .data+0x10 holds a non-code value — must be ignored.
        data[0x50..0x58].copy_from_slice(&0xDEADu64.to_le_bytes());
        let mut load = RichLoadResult::new(data);
        load.bits = 64;
        load.endian = "little".into();
        load.format = "PE64".into();
        load.sections.push(SectionInfo::new(
            ".text",
            0x1_4000_1000,
            0x40,
            0x00,
            0x40,
            0x2000_0020,
        ));
        load.sections.push(SectionInfo::new(
            ".data",
            0x1_4000_2000,
            0x20,
            0x40,
            0x20,
            0xC000_0040,
        ));
        assert_eq!(
            static_fn_ptr_pairs(&load),
            vec![(0x1_4000_2008, 0x1_4000_1010)]
        );
    }

    #[test]
    fn weak_prologue_guesses_are_false_positives() {
        // Low-confidence prologue guess -> dropped.
        let weak = FunctionBoundary::new(
            Address::new(0x1000),
            Confidence::Low,
            DetectionSource::ProloguePattern,
        );
        assert!(is_weak_false_positive(&weak));

        // Medium prologue -> kept.
        let medium = FunctionBoundary::new(
            Address::new(0x2000),
            Confidence::Medium,
            DetectionSource::ProloguePattern,
        );
        assert!(!is_weak_false_positive(&medium));

        // Low confidence but corroborated by a call target -> kept.
        let call = FunctionBoundary::new(
            Address::new(0x3000),
            Confidence::Low,
            DetectionSource::CallTarget,
        );
        assert!(!is_weak_false_positive(&call));

        // Symbol/export -> kept.
        let sym = FunctionBoundary::new(
            Address::new(0x4000),
            Confidence::Certain,
            DetectionSource::SymbolTable,
        );
        assert!(!is_weak_false_positive(&sym));
    }

    #[test]
    fn flirt_match_names_stripped_function() {
        let pack_text = "SIGPACK 1\npack t\n---\n558BEC83EC10 | 0 0 0000 6 | libt | crt_memset\n";
        let pack = SignaturePack::parse(pack_text).unwrap();
        let mut scanner = FlirtScanner::from_pack(&pack);
        scanner.set_min_confidence(0);

        // push rbp; mov ebp,esp; sub esp,0x10; ret — stripped image, no symbols.
        let blob = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0xC3];
        let load = RichLoadResult::new(blob)
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);

        let pairs = flirt_pairs_with_scanner(&scanner, &load, 0);
        assert_eq!(pairs, vec![(0x1000_u64, "crt_memset".to_string())]);

        assert_eq!(resolve_name_for(&load, &pairs, 0x1000), "crt_memset");
        assert_eq!(resolve_name_for(&load, &pairs, 0x2000), "sub_2000");
    }

    #[test]
    fn resolve_name_for_falls_back_when_cleaned_name_is_empty() {
        // A symbol whose demangled form has nothing before its first
        // top-level `(` (e.g. an operator/thunk symbol whose canonical text
        // is essentially just an argument list) cleans down to an empty
        // string — must fall back to `sub_<hex>`, NEVER return "" (which
        // would emit an invalid `void __fastcall () {` signature).
        let load = RichLoadResult::new(vec![0x90; 0x10])
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000)
            .with_symbol(SymbolInfo::new("(", 0x1000, "function", 1));
        let pairs: Vec<(u64, String)> = Vec::new();
        assert_eq!(resolve_name_for(&load, &pairs, 0x1000), "sub_1000");
    }

    #[test]
    fn uncorroborated_mid_function_prologue_is_dropped_but_called_and_padded_kept() {
        // Layout at base 0x1000 (sectionless => MemorySlice over whole blob):
        //   0x1000 fn A: push rbp; mov rbp,rsp; call ->0x100B; pop rbp; ret
        //   0x100B fn B: call target of A (corroborated)
        //   0x1012 FAKE prologue, preceded by code byte 0x48, never called
        //   0x101B fn C: uncalled but preceded by 0xCC int3 padding
        let blob: Vec<u8> = vec![
            0x55, 0x48, 0x89, 0xE5, // 0x1000 push rbp; mov rbp,rsp
            0xE8, 0x02, 0x00, 0x00, 0x00, // 0x1004 call rel32 -> 0x1009+2 = 0x100B
            0x5D, 0xC3, // 0x1009 pop rbp; ret
            0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, // 0x100B fn B
            0x48, // 0x1011 stray code byte
            0x55, 0x48, 0x89, 0xE5, // 0x1012 fake prologue (preceded by 0x48)
            0x5D, // 0x1016 filler
            0xCC, 0xCC, 0xCC, 0xCC, // 0x1017 int3 padding
            0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, // 0x101B fn C
            0xCC, 0xCC,
        ];
        let load = RichLoadResult::new(blob)
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);

        let starts: Vec<u64> = detect_functions_in_load(&load)
            .iter()
            .map(|b| b.start.as_u64())
            .collect();

        assert!(starts.contains(&0x1000), "section-start fn A must be kept");
        assert!(starts.contains(&0x100B), "call-target fn B must be kept");
        assert!(
            starts.contains(&0x101B),
            "padding-preceded fn C must be kept"
        );
        assert!(
            !starts.contains(&0x1012),
            "mid-function prologue at 0x1012 must be filtered as spurious"
        );
    }

    /// 64-bit x86 "ret" instruction.
    fn ret_only_blob() -> Vec<u8> {
        vec![0xC3]
    }

    #[test]
    fn disasm_stops_at_ret() {
        let bytes = [0x48, 0x89, 0xE5, 0xC3, 0x90, 0x90]; // mov rbp,rsp; ret; nop;nop
        let ins = disassemble_function_x86(&bytes, 0x1000, 64, 1024, 1024).unwrap();
        assert_eq!(ins.len(), 2, "should stop after ret");
        assert!(ins[1].mnemonic.to_lowercase().starts_with("ret"));
    }

    /// Two sequential bottom-tested loops (gcc -O1 loop rotation): the first
    /// loop ends with a forward `jmp` over alignment nops to the second
    /// loop's condition test. The forward target lies INSIDE the sweep
    /// window (i.e. before the next function boundary), so it is
    /// intra-procedural control flow — the sweep must walk through it and
    /// reach the final `ret`, not stop at the jmp and let the tail be
    /// misclassified as a separate function / fabricated tail call (bug D4).
    #[test]
    fn disasm_two_loop_forward_jmp_is_not_a_function_boundary() {
        let bytes = [
            0x48, 0xFF, 0xC0, // 0x1000 inc rax
            0x48, 0xFF, 0xC8, // 0x1003 dec rax
            0x75, 0xFB,       // 0x1006 jne 0x1003        (loop 1)
            0xE9, 0x05, 0x00, 0x00, 0x00, // 0x1008 jmp 0x1012 (rotation jmp)
            0x48, 0xFF, 0xC1, // 0x100D inc rcx           (loop 2 body)
            0x90, 0x90,       // 0x1010 nop; nop
            0x48, 0xFF, 0xC9, // 0x1012 dec rcx           (loop 2 test)
            0x75, 0xF9,       // 0x1015 jne 0x1010
            0xC3,             // 0x1017 ret
            0xCC, 0xCC,       // padding past the function
        ];
        let ins = disassemble_function_x86(&bytes, 0x1000, 64, 0x18, 1024).unwrap();
        let last = ins.last().unwrap();
        assert!(
            last.mnemonic.to_lowercase().starts_with("ret"),
            "sweep must reach the ret past the intra-function forward jmp; stopped at {} {}",
            last.mnemonic,
            last.operands
        );
    }

    /// A forward `jmp` whose target is AT/PAST the window end (the next
    /// function's start caps the window) is a genuine tail call and must
    /// still terminate the sweep — adjacent sibling functions stay split.
    #[test]
    fn disasm_forward_tail_call_outside_window_still_terminates() {
        let bytes = [
            0x48, 0xFF, 0xC0, // 0x1000 inc rax
            0xE9, 0x03, 0x00, 0x00, 0x00, // 0x1003 jmp 0x100B (next function)
            0x90, 0x90, 0x90, // padding
            0x48, 0xFF, 0xC8, // 0x100B next function (outside max_bytes)
            0xC3,
        ];
        // Window capped at the next function start (0x100B → 0xB bytes).
        let ins = disassemble_function_x86(&bytes, 0x1000, 64, 0x0B, 1024).unwrap();
        assert_eq!(ins.len(), 2, "sweep must stop at the tail-call jmp");
        assert!(ins[1].mnemonic.to_lowercase().starts_with("jmp"));
    }

    #[test]
    fn disasm_empty_errors() {
        let err = disassemble_function_x86(&[], 0x0, 64, 1024, 1024).unwrap_err();
        assert!(matches!(err, DecompilerError::LiftError(_)));
    }

    #[test]
    fn ret_blob_pipeline_emits_function() {
        // Build a synthetic RichLoadResult containing just a `ret`.
        let load = RichLoadResult::new(ret_only_blob())
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);
        let out = decompile_function_in_load(&load, 0x1000, DecompOptions::default()).unwrap();
        assert_eq!(out.address, 0x1000);
        assert!(!out.pseudo_code.is_empty());
    }

    /// FLIRT/PDB integration: a `RichLoadResult` carrying a `SymbolInfo`
    /// for a call-site target must cause the rendered pseudo-C to use the
    /// real name (here `my_resolved_symbol`) instead of the
    /// `sub_<HEX>` placeholder. This locks in the binary_entry → SymbolMap
    /// → DecompilerPipeline → resolve_symbols wiring end-to-end.
    #[test]
    fn pdb_symbol_replaces_sub_hex_placeholder() {
        use rustre_loader::SymbolInfo;

        // call rel32 → +0x100 (target = 0x1005 + 0x100 = 0x1105), then ret.
        // E8 00 01 00 00 = call 0x100; C3 = ret.
        let mut blob = vec![0xE8, 0x00, 0x01, 0x00, 0x00, 0xC3];
        // Pad so the loader can map further VAs even if it tries.
        blob.resize(0x2000, 0x90);

        let load = RichLoadResult::new(blob)
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000)
            .with_symbol(SymbolInfo::new("my_resolved_symbol", 0x1105, "function", 4));

        let out =
            decompile_function_in_load(&load, 0x1000, DecompOptions::default()).unwrap();
        assert!(!out.pseudo_code.is_empty());

        // The hex address may still appear as a literal in some emitted
        // forms; what must NOT appear is the `sub_1105` placeholder for
        // an address we explicitly named.
        assert!(
            !out.pseudo_code.contains("sub_1105"),
            "expected `sub_1105` placeholder to be rewritten to the bound \
             symbol; got:\n{}",
            out.pseudo_code
        );
        // And the resolved name should appear somewhere in the output.
        assert!(
            out.pseudo_code.contains("my_resolved_symbol"),
            "expected resolved symbol name in output; got:\n{}",
            out.pseudo_code
        );
    }

    // ── resolve_jump_table ───────────────────────────────────────────────

    /// Synthetic PE-like image: `.text` (executable) at VA `0x40_1000`
    /// backed by `file[0..0x100]`, `.rdata` (data) at VA `0x40_8000` backed
    /// by `file[0x100..0x200]`, with `entries` written at the table base.
    fn sectioned_load_with_table(entries: &[u8]) -> RichLoadResult {
        let mut data = vec![0_u8; 0x200];
        data[0x100..0x100 + entries.len()].copy_from_slice(entries);
        RichLoadResult::new(data)
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x0040_0000)
            .with_section(SectionInfo::new(".text", 0x0040_1000, 0x100, 0, 0x100, 0x6000_0020))
            .with_section(SectionInfo::new(
                ".rdata",
                0x0040_8000,
                0x100,
                0x100,
                0x100,
                0x4000_0040,
            ))
    }

    fn abs32_table_info() -> JumpTableInfo {
        JumpTableInfo {
            index: "eax".to_string(),
            case_count: 3,
            table_addr: Some(0x0040_8000),
            entry_size: 4,
            default_target: Some(0x0040_1090),
            jump_addr: 0x0040_1005,
            arith_addrs: Vec::new(),
            code_base: None,
        }
    }

    #[test]
    fn resolve_jump_table_reads_abs32_entries_from_rdata() {
        let entries: Vec<u8> = [0x0040_1010_u32, 0x0040_1020, 0x0040_1030]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let load = sectioned_load_with_table(&entries);
        let resolved = resolve_jump_table(&load, &abs32_table_info()).expect("resolved");
        assert_eq!(
            resolved.cases,
            vec![(0, 0x0040_1010), (1, 0x0040_1020), (2, 0x0040_1030)]
        );
        assert_eq!(resolved.default_target, Some(0x0040_1090));
    }

    #[test]
    fn resolve_jump_table_rejects_targets_outside_code() {
        // Entries point back into `.rdata` itself — not code under any
        // reading, so the resolver must refuse rather than fabricate.
        let entries: Vec<u8> = [0x0040_8010_u32, 0x0040_8020, 0x0040_8030]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let load = sectioned_load_with_table(&entries);
        assert_eq!(resolve_jump_table(&load, &abs32_table_info()), None);
    }

    #[test]
    fn resolve_jump_table_sectionless_uses_image_extent() {
        // No section table: raw blob mapped at base 0x1000. The table at
        // 0x1020 holds absolute 32-bit targets inside the mapped extent.
        let mut data = vec![0x90_u8; 0x40];
        data[0x20..0x28].copy_from_slice(&[0x04, 0x10, 0x00, 0x00, 0x08, 0x10, 0x00, 0x00]);
        let load = RichLoadResult::new(data)
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);
        let info = JumpTableInfo {
            index: "ecx".to_string(),
            case_count: 2,
            table_addr: Some(0x1020),
            entry_size: 4,
            default_target: None,
            jump_addr: 0x1002,
            arith_addrs: Vec::new(),
            code_base: None,
        };
        let resolved = resolve_jump_table(&load, &info).expect("resolved");
        assert_eq!(resolved.cases, vec![(0, 0x1004), (1, 0x1008)]);
    }

    // ── lea+jmp direct-jump folding ──────────────────────────────────────

    fn mk_ins(addr: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction {
            address: rustre_core::Address::new(addr),
            size: 4,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            operand_list: Vec::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
            bytes: Vec::new(),
            comment: None,
        }
    }

    #[test]
    fn folds_adjacent_lea_rip_jmp_into_direct_jump() {
        let load = RichLoadResult::new(vec![0x90_u8; 0x1000])
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);
        // Go ladder shape: `lea 0x1EF(%rip),%rax; jmp *%rax` at 0x1100/0x1107.
        let mut ins = vec![
            mk_ins(0x1100, "lea", "0x1EF(%rip), %rax"),
            mk_ins(0x1107, "jmp", "*%rax"),
        ];
        fold_lea_direct_jumps(&mut ins, &load);
        // target = jmp address (RIP after lea) + 0x1EF = 0x12F6.
        assert_eq!(ins[1].operands, "0x12F6");
        assert_eq!(ins[0].mnemonic, "nop");
    }

    #[test]
    fn fold_rejects_register_mismatch_and_out_of_image_targets() {
        let load = RichLoadResult::new(vec![0x90_u8; 0x100])
            .with_arch("x86_64")
            .with_bits(64)
            .with_base_address(0x1000);
        // Register mismatch: lea writes rcx, jmp reads rax.
        let mut a = vec![
            mk_ins(0x1000, "lea", "0x10(%rip), %rcx"),
            mk_ins(0x1007, "jmp", "*%rax"),
        ];
        fold_lea_direct_jumps(&mut a, &load);
        assert_eq!(a[1].operands, "*%rax");
        // Target far outside the mapped image: never fabricate the edge.
        let mut b = vec![
            mk_ins(0x1000, "lea", "0x999999(%rip), %rax"),
            mk_ins(0x1007, "jmp", "*%rax"),
        ];
        fold_lea_direct_jumps(&mut b, &load);
        assert_eq!(b[1].operands, "*%rax");
        assert_eq!(b[0].mnemonic, "lea");
    }

    // ── string literal recovery ─────────────────────────────────────────

    #[test]
    fn read_string_literal_ascii() {
        assert_eq!(
            read_string_literal(b"hello world\0junk"),
            Some("\"hello world\"".to_string())
        );
        // Escapes: quote, backslash, newline.
        assert_eq!(
            read_string_literal(b"a\"b\\c\nd\0"),
            Some("\"a\\\"b\\\\c\\nd\"".to_string())
        );
    }

    #[test]
    fn read_string_literal_rejects_short_or_unterminated() {
        assert_eq!(read_string_literal(b"hi\0"), None); // too short
        assert_eq!(read_string_literal(b"\x01\x02\x03\x04"), None); // binary
        assert_eq!(read_string_literal(b"abcdef"), None); // no NUL in window
        assert_eq!(read_string_literal(b""), None);
    }

    #[test]
    fn read_string_literal_utf16() {
        let bytes = b"w\0i\0d\0e\0!\0\0\0";
        assert_eq!(read_string_literal(bytes), Some("L\"wide!\"".to_string()));
        // Unterminated UTF-16 is rejected.
        assert_eq!(read_string_literal(b"w\0i\0d\0e\0"), None);
    }

    #[test]
    fn read_string_literal_truncates_long_strings() {
        let mut long = vec![b'A'; 100];
        long.push(0);
        let lit = read_string_literal(&long).unwrap();
        assert!(lit.starts_with('"') && lit.ends_with("...\""), "{lit}");
        assert!(lit.len() < 70);
    }

    #[test]
    fn rip_ref_targets_matches_off_naming() {
        // `lea 0x2000(%rip), %rax` with next instruction at 0x140001007
        // references VA 0x140003007 — the same VA `resolve_rip_relative`
        // names `off_140003007`.
        let vas = crate::rip_ref_targets("0x2000(%rip), %rax", 0x1400_0100_7);
        assert_eq!(vas, vec![0x1400_0300_7]);
        // Negative displacement.
        let vas = crate::rip_ref_targets("-0x10(%rip), %rcx", 0x1000);
        assert_eq!(vas, vec![0xFF0]);
        // No rip reference → empty.
        assert!(crate::rip_ref_targets("%rax, %rcx", 0x1000).is_empty());
    }
}


#[cfg(test)]
mod arity_memo_equivalence_tests {
    use super::*;

    /// The memoized whole-image arity map must be IDENTICAL (same value for
    /// every shared VA, and a superset of keys) to the per-function map that
    /// `callee_arities_for` computes fresh. If it is not, the memoization is
    /// not sound and must be scoped rather than forced.
    fn check(bin: &str) {
        let path = std::path::Path::new("../../tests/decompiler_corpus/bin").join(bin);
        if !path.exists() {
            return;
        }
        let load = load_binary(&path).expect("load");
        let bits = x86_bits_for(&load);
        let starts: Vec<u64> = detect_functions_in_load(&load).iter().map(|f| f.start.0).collect();
        let (img_ar, img_rt, _img_argc) = image_callee_arities(&load, &starts, bits);

        // Sample real functions (cap the count so the test stays fast — the
        // per-function path is the slow one we are removing).
        for &va in starts.iter().step_by(starts.len() / 40 + 1) {
            let Some((base, slice)) = slice_at_va(&load, va) else { continue };
            let Ok(instrs) =
                disassemble_function_x86(slice, base, bits, MAX_FN_SCAN_BYTES, MAX_FN_INSTRUCTIONS)
            else {
                continue;
            };
            let (fn_ar, fn_rt, _fn_argc) = callee_arities_for(&load, &instrs, bits);
            for (k, v) in &fn_ar {
                assert_eq!(
                    img_ar.get(k),
                    Some(v),
                    "{bin}: arity mismatch for callee {k:#x} (from fn {va:#x})"
                );
            }
            for (k, v) in &fn_rt {
                assert_eq!(
                    img_rt.get(k),
                    Some(v),
                    "{bin}: ret-type mismatch for callee {k:#x} (from fn {va:#x})"
                );
            }
        }
    }

    #[test]
    fn memoized_arities_match_per_function_c() {
        check("sample1_c.exe");
    }

    #[test]
    fn memoized_arities_match_per_function_cpp() {
        check("sample7_cpp.exe");
    }

    #[test]
    fn memoized_arities_match_per_function_rust() {
        check("sample8_rust.exe");
    }

    #[test]
    fn memoized_arities_match_per_function_cs() {
        check("sample5_cs.exe");
    }
}
