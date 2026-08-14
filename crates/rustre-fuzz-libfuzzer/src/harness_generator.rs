//! Automatic fuzz harness generator.
//!
//! Given a target binary or shared library, this module:
//! 1. Detects potential fuzz entry points by scanning exported symbols and
//!    heuristically ranking them by argument complexity.
//! 2. Infers argument types from symbol names and (optionally) DWARF info.
//! 3. Emits a complete Rust fuzz harness (`fuzz_targets/fuzz_<name>.rs`)
//!    with linker script, sanitizer hooks, and `cargo-fuzz` scaffolding.

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── Entry point descriptor ───────────────────────────────────────────────────

/// How a candidate entry point was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntrySource {
    ExportedSymbol,
    DwarfDwarf,
    HeuristicName,
    ManualAnnotation,
}

/// C-level type category for one function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InferredParamType {
    /// `const uint8_t *data, size_t size` — the canonical libFuzzer pattern.
    DataSizePtr,
    /// An integer (u8/u16/u32/u64/i32 etc.).
    Integer { signed: bool, bits: u8 },
    /// A null-terminated C string.
    CString,
    /// An opaque pointer (struct/handle).
    OpaquePtr { type_hint: Option<String> },
    /// A boolean flag.
    Bool,
    /// A slice / array reference.
    Slice,
    /// Unknown / infer at codegen time.
    Unknown,
}

impl InferredParamType {
    /// Returns the Rust type token for this parameter.
    #[must_use] 
    pub const fn rust_type(&self) -> &str {
        match self {
            Self::Integer { signed: true, bits: 8 } => "i8",
            Self::Integer { signed: false, bits: 8 } => "u8",
            Self::Integer { signed: true, bits: 16 } => "i16",
            Self::Integer { signed: false, bits: 16 } => "u16",
            Self::Integer { signed: true, bits: 32 } => "i32",
            Self::Integer { signed: false, bits: 32 } => "u32",
            Self::Integer { signed: true, bits: 64 } => "i64",
            Self::CString => "*const std::os::raw::c_char",
            Self::OpaquePtr { .. } => "*mut std::ffi::c_void",
            Self::Bool => "bool",
            Self::DataSizePtr | Self::Slice => "&[u8]",
            Self::Integer { signed: false, bits: 64 } | Self::Integer { .. } | Self::Unknown => "u64",
        }
    }

    /// Returns a safe default value to pass when we cannot derive one from
    /// the fuzzer input.
    #[must_use] 
    pub const fn default_value(&self) -> &str {
        match self {
            Self::Integer { .. } | Self::Unknown => "0",
            Self::CString => "std::ptr::null()",
            Self::OpaquePtr { .. } => "std::ptr::null_mut()",
            Self::Bool => "false",
            Self::DataSizePtr | Self::Slice => "data",
            }
    }
}

/// One candidate function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzParam {
    pub name: String,
    pub ty: InferredParamType,
    pub is_output: bool,
}

/// A candidate fuzz entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzEntryPoint {
    pub name: String,
    pub address: u64,
    pub params: Vec<FuzzParam>,
    pub return_type: InferredParamType,
    pub source: EntrySource,
    /// Heuristic score: higher = better fuzz candidate.
    pub score: u32,
    pub notes: Vec<String>,
}

impl FuzzEntryPoint {
    /// Construct a barebones [`FuzzEntryPoint`] with default parameters and a
    /// neutral heuristic score. Exposed so external candidate-discovery passes
    /// (e.g. symbol-table scanners) can seed the entry-point list before the
    /// internal heuristic refines it.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: name.into(),
            address,
            params: Vec::new(),
            return_type: InferredParamType::Integer { signed: true, bits: 32 },
            source: EntrySource::HeuristicName,
            score: 50,
            notes: Vec::new(),
        }
    }
}

// ─── Heuristic name-based type inference ─────────────────────────────────────

/// Infer parameter types from a function's symbol name using naming conventions.
#[must_use] 
pub fn infer_params_from_name(name: &str) -> Vec<FuzzParam> {
    let name_lower = name.to_lowercase();

    // Pattern: `parse_*`, `decode_*`, `process_*`, `handle_*` → data+size
    let data_size_patterns = [
        "parse", "decode", "deserialize", "unpack", "inflate",
        "decompress", "process", "handle", "input", "feed", "load",
        "read", "consume",
    ];
    if data_size_patterns.iter().any(|p| name_lower.contains(p)) {
        return vec![
            FuzzParam { name: "data".into(), ty: InferredParamType::DataSizePtr, is_output: false },
            FuzzParam {
                name: "size".into(),
                ty: InferredParamType::Integer { signed: false, bits: 64 },
                is_output: false,
            },
        ];
    }

    // `*_open`, `*_init`, `*_create` → likely a single config/flags int
    let init_patterns = ["open", "init", "create", "new", "setup", "alloc"];
    if init_patterns.iter().any(|p| name_lower.contains(p)) {
        return vec![
            FuzzParam {
                name: "flags".into(),
                ty: InferredParamType::Integer { signed: false, bits: 32 },
                is_output: false,
            },
        ];
    }

    // Default: single data+size
    vec![
        FuzzParam { name: "data".into(), ty: InferredParamType::DataSizePtr, is_output: false },
        FuzzParam {
            name: "size".into(),
            ty: InferredParamType::Integer { signed: false, bits: 64 },
            is_output: false,
        },
    ]
}

/// Score a candidate entry point: higher = better fuzz target.
#[must_use] 
pub fn score_entry(name: &str, arity: usize) -> u32 {
    let name_lower = name.to_lowercase();
    let mut score: u32 = 50;

    // Prefer parsing / processing functions
    let boost = ["parse", "decode", "process", "handle", "deserialize", "inflate", "uncompress"];
    if boost.iter().any(|p| name_lower.contains(p)) { score += 30; }

    // Penalize cleanup / init / getters
    let penalty = ["free", "destroy", "get_", "set_", "print", "log", "debug"];
    if penalty.iter().any(|p| name_lower.contains(p)) { score = score.saturating_sub(20); }

    // Prefer functions with 2-4 args
    match arity {
        2 | 3 => score += 20,
        4 | 5 => score += 10,
        0 | 1 => score = score.saturating_sub(10),
        _ => score = score.saturating_sub(5),
    }

    score
}

// ─── Binary scanner ───────────────────────────────────────────────────────────

/// Configuration for the harness generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessGenConfig {
    /// Path to the target binary or shared library.
    pub target_path: PathBuf,
    /// Output directory for generated harness files.
    pub output_dir: PathBuf,
    /// Maximum number of entry points to generate harnesses for.
    pub max_harnesses: usize,
    /// Minimum score threshold for a candidate.
    pub min_score: u32,
    /// Whether to emit `#[no_mangle] extern "C"` wrappers.
    pub emit_c_wrappers: bool,
    /// Enable `AddressSanitizer` hooks in the generated code.
    pub enable_asan: bool,
    /// Enable `UndefinedBehaviorSanitizer`.
    pub enable_ubsan: bool,
    /// Library name used in extern declarations.
    pub lib_name: Option<String>,
}

impl Default for HarnessGenConfig {
    fn default() -> Self {
        Self {
            target_path: PathBuf::from("target.so"),
            output_dir: PathBuf::from("fuzz/fuzz_targets"),
            max_harnesses: 10,
            min_score: 40,
            emit_c_wrappers: false,
            enable_asan: true,
            enable_ubsan: false,
            lib_name: None,
        }
    }
}

/// Represents a parsed export from an ELF/PE symbol table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    /// Estimated parameter count from relocation / call-site analysis.
    pub param_count_hint: usize,
}

/// Scan a raw ELF export table (simplified: reads `.dynsym` names).
/// In a real implementation, use `goblin` or `object` crate.
#[must_use] 
pub fn scan_elf_exports_from_bytes(bytes: &[u8]) -> Vec<ExportedSymbol> {
    // Simplified heuristic: look for null-terminated strings that look like
    // C identifiers following the ELF magic.
    // A production implementation would use goblin::elf::Elf::parse.
    let mut results = Vec::new();
    if bytes.len() < 4 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return results;
    }

    // Walk byte-by-byte looking for C identifier runs (cheap approximation)
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let name = std::str::from_utf8(&bytes[start..i]).unwrap_or("").to_string();
            if name.len() >= 4 && bytes.get(i).copied() == Some(0) {
                let addr = (start as u64).wrapping_mul(0x1337) & 0xffff_f000 | 0x1000;
                results.push(ExportedSymbol { name, address: addr, size: 0, param_count_hint: 2 });
            }
        } else {
            i += 1;
        }
        if results.len() > 512 { break; }
    }
    results
}

// ─── Harness codegen ──────────────────────────────────────────────────────────

/// Generated harness file content.
#[derive(Debug, Clone)]
pub struct GeneratedHarness {
    pub entry_name: String,
    pub file_name: String,
    pub code: String,
}

/// Code generator for a single fuzz harness.
pub struct HarnessCodegen<'a> {
    config: &'a HarnessGenConfig,
}

impl<'a> HarnessCodegen<'a> {
    #[must_use] 
    pub const fn new(config: &'a HarnessGenConfig) -> Self {
        Self { config }
    }

    /// Generate a complete `fuzz_targets/fuzz_<name>.rs` file.
    #[must_use] 
    pub fn generate(&self, entry: &FuzzEntryPoint) -> GeneratedHarness {
        let mut code = String::new();
        let _lib = self.config.lib_name.as_deref().unwrap_or("target");

        // Header
        writeln!(code, "#![no_main]").ok();
        if self.config.enable_asan {
            writeln!(code, "#![cfg_attr(fuzzing, sanitize = \"address\")]").ok();
        }
        if self.config.enable_ubsan {
            writeln!(code, "#![cfg_attr(fuzzing, sanitize = \"undefined\")]").ok();
        }
        writeln!(code).ok();
        writeln!(code, "// Auto-generated fuzz harness for: {}", entry.name).ok();
        writeln!(code, "// Source: {:?}  Score: {}", entry.source, entry.score).ok();
        for note in &entry.notes {
            writeln!(code, "// Note: {note}").ok();
        }
        writeln!(code).ok();
        writeln!(code, "use libfuzzer_sys::fuzz_target;").ok();
        writeln!(code).ok();

        // Extern declaration
        writeln!(code, "extern \"C\" {{").ok();
        write!(code, "    fn {}(", entry.name).ok();
        for (i, param) in entry.params.iter().enumerate() {
            if i > 0 { write!(code, ", ").ok(); }
            write!(code, "{}: {}", param.name, param.ty.rust_type()).ok();
        }
        writeln!(code, ") -> {};", entry.return_type.rust_type()).ok();
        writeln!(code, "}}").ok();
        writeln!(code).ok();

        // fuzz_target! macro
        writeln!(code, "fuzz_target!(|data: &[u8]| {{").ok();
        writeln!(code, "    if data.is_empty() {{ return; }}").ok();
        writeln!(code).ok();

        // Argument binding
        for param in &entry.params {
            match &param.ty {
                InferredParamType::DataSizePtr => {
                    writeln!(code, "    let {n}_ptr = data.as_ptr();", n = param.name).ok();
                    writeln!(code, "    let {n}_len = data.len();", n = param.name).ok();
                }
                InferredParamType::Integer { bits, .. } => {
                    let bytes_needed = (*bits as usize).div_ceil(8);
                    writeln!(code,
                        "    let {n} = if data.len() >= {b} {{ u{bits}::from_le_bytes(data[..{b}].try_into().unwrap_or_default()) }} else {{ 0 }};",
                        n = param.name, b = bytes_needed, bits = bits
                    ).ok();
                }
                InferredParamType::CString => {
                    writeln!(code, "    // Ensure null-termination for CString arg '{}'", param.name).ok();
                    writeln!(code, "    let mut {n}_buf = data.to_vec(); {n}_buf.push(0);", n = param.name).ok();
                    writeln!(code, "    let {n} = {n}_buf.as_ptr() as *const std::os::raw::c_char;", n = param.name).ok();
                }
                InferredParamType::Bool => {
                    writeln!(code, "    let {} = data[0] & 1 != 0;", param.name).ok();
                }
                _ => {
                    writeln!(code, "    let {} = {};", param.name, param.ty.default_value()).ok();
                }
            }
        }

        writeln!(code).ok();
        writeln!(code, "    // Safety: calling C function with controlled input").ok();
        writeln!(code, "    unsafe {{").ok();
        write!(code, "        let _ret = {}(", entry.name).ok();
        for (i, param) in entry.params.iter().enumerate() {
            if i > 0 { write!(code, ", ").ok(); }
            match &param.ty {
                InferredParamType::DataSizePtr => {
                    write!(code, "{n}_ptr, {n}_len", n = param.name).ok();
                }
                _ => { write!(code, "{}", param.name).ok(); }
            }
        }
        writeln!(code, ");").ok();
        writeln!(code, "    }}").ok();
        writeln!(code, "}});").ok();

        let file_name = format!("fuzz_{}.rs", sanitize_name(&entry.name));
        GeneratedHarness { entry_name: entry.name.clone(), file_name, code }
    }

    /// Generate a `fuzz/Cargo.toml` manifest for a cargo-fuzz project.
#[must_use] 
pub fn generate_fuzz_cargo_toml(&self, harnesses: &[GeneratedHarness]) -> String {
    let _lib = self.config.lib_name.as_deref().unwrap_or("target");
    let mut out = String::new();
    writeln!(out, "[package]").ok();
    writeln!(out, "name = \"fuzz\"").ok();
    writeln!(out, "version = \"0.0.1\"").ok();
    writeln!(out, "authors = [\"auto-generated\"]").ok();
    writeln!(out, "edition = \"2021\"").ok();
    writeln!(out, "publish = false").ok();
    writeln!(out).ok();
    writeln!(out, "[package.metadata]").ok();
    writeln!(out, "cargo-fuzz = true").ok();
    writeln!(out).ok();
    writeln!(out, "[dependencies]").ok();
    writeln!(out, "libfuzzer-sys = \"0.4\"").ok();
    writeln!(out).ok();
    if self.config.enable_asan {
        writeln!(out, "[profile.release]").ok();
        writeln!(out, "debug = true").ok();
        writeln!(out, "opt-level = 3").ok();
        writeln!(out).ok();
    }
    for h in harnesses {
        let target_name = sanitize_name(&h.entry_name);
        writeln!(out, "[[bin]]").ok();
        writeln!(out, "name = \"fuzz_{target_name}\"").ok();
        writeln!(out, "path = \"fuzz_targets/{target_name}.rs\"").ok();
        writeln!(out, "test = false").ok();
        writeln!(out, "doc = false").ok();
        writeln!(out).ok();
    }
    out
}

/// Generate `Cargo.toml` `[[bin]]` entries for all harnesses.
    #[must_use] 
    pub fn generate_cargo_toml_bins(&self, harnesses: &[GeneratedHarness]) -> String {
        let mut out = String::new();
        for h in harnesses {
            writeln!(out, "[[bin]]").ok();
            writeln!(out, "name = \"fuzz_{}\"", sanitize_name(&h.entry_name)).ok();
            writeln!(out, "path = \"fuzz_targets/{}\"", h.file_name).ok();
            writeln!(out, "test = false").ok();
            writeln!(out, "doc = false").ok();
            writeln!(out).ok();
        }
        out
    }

    /// Generate a linker script that exposes the target library symbols.
    #[must_use] 
    pub fn generate_linker_script(&self) -> String {
        let lib = self.config.lib_name.as_deref().unwrap_or("target");
        format!(
            "/* Auto-generated linker script for fuzz harness */\nINPUT(-l{lib})\n"
        )
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

// ─── High-level facade ────────────────────────────────────────────────────────

/// Orchestrates the full harness-generation pipeline.
pub struct HarnessGenerator {
    config: HarnessGenConfig,
}

impl HarnessGenerator {
    #[must_use] 
    pub const fn new(config: HarnessGenConfig) -> Self {
        Self { config }
    }

    /// Given a list of exported symbols, produce ranked entry points and
    /// generate harness files.
    #[must_use] 
    pub fn generate_from_symbols(
        &self,
        symbols: &[ExportedSymbol],
    ) -> Vec<GeneratedHarness> {
        let codegen = HarnessCodegen::new(&self.config);

        let mut entries: Vec<FuzzEntryPoint> = symbols
            .iter()
            .map(|sym| {
                let params = infer_params_from_name(&sym.name);
                let score = score_entry(&sym.name, sym.param_count_hint);
                FuzzEntryPoint {
                    name: sym.name.clone(),
                    address: sym.address,
                    params,
                    return_type: InferredParamType::Integer { signed: true, bits: 32 },
                    source: EntrySource::ExportedSymbol,
                    score,
                    notes: Vec::new(),
                }
            })
            .filter(|e| e.score >= self.config.min_score)
            .collect();

        entries.sort_by(|a, b| b.score.cmp(&a.score));
        entries.truncate(self.config.max_harnesses);

        entries.iter().map(|e| codegen.generate(e)).collect()
    }

    /// Print a summary of what would be generated.
    #[must_use] 
    pub fn print_plan(&self, harnesses: &[GeneratedHarness]) -> String {
        let mut out = String::new();
        writeln!(out, "Harness Generation Plan").ok();
        writeln!(out, "  Target    : {}", self.config.target_path.display()).ok();
        writeln!(out, "  Output    : {}", self.config.output_dir.display()).ok();
        writeln!(out, "  ASAN      : {}", self.config.enable_asan).ok();
        writeln!(out, "  UBSAN     : {}", self.config.enable_ubsan).ok();
        writeln!(out, "  Harnesses : {}", harnesses.len()).ok();
        for h in harnesses {
            writeln!(out, "    {}", h.file_name).ok();
        }
        out
    }
}

// ─── Sanitizer hook stubs ─────────────────────────────────────────────────────

/// Generate sanitizer hook stub code to be compiled into the harness.
#[must_use] 
pub fn generate_sanitizer_hooks(enable_asan: bool, enable_ubsan: bool) -> String {
    let mut out = String::new();
    writeln!(out, "// ── Sanitizer hooks ──────────────────────────────────────").ok();
    if enable_asan {
        writeln!(out, "#[cfg(sanitize = \"address\")]").ok();
        writeln!(out, "extern \"C\" {{").ok();
        writeln!(out, "    fn __asan_describe_address(addr: *const u8);").ok();
        writeln!(out, "    fn __asan_region_is_poisoned(addr: *const u8, size: usize) -> *const u8;").ok();
        writeln!(out, "}}").ok();
        writeln!(out).ok();
        writeln!(out, "/// Check if a memory region is accessible (ASAN-aware).").ok();
        writeln!(out, "pub fn is_accessible(ptr: *const u8, size: usize) -> bool {{").ok();
        writeln!(out, "    #[cfg(sanitize = \"address\")] unsafe {{").ok();
        writeln!(out, "        __asan_region_is_poisoned(ptr, size).is_null()").ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "    #[cfg(not(sanitize = \"address\"))]").ok();
        writeln!(out, "    {{ !ptr.is_null() }}").ok();
        writeln!(out, "}}").ok();
    }
    if enable_ubsan {
        writeln!(out).ok();
        writeln!(out, "#[no_mangle]").ok();
        writeln!(out, "pub extern \"C\" fn __ubsan_on_report() {{").ok();
        writeln!(out, "    // Called by UBSan on undefined behaviour — treat as crash.").ok();
        writeln!(out, "    std::process::abort();").ok();
        writeln!(out, "}}").ok();
    }
    out
}

// ─── Coverage-guided entry point prioritization ───────────────────────────────

/// Priority tier for an entry point based on coverage potential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EntryPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl EntryPriority {
    #[must_use] 
    pub const fn from_score(score: u32) -> Self {
        match score {
            0..=39 => Self::Low,
            40..=59 => Self::Medium,
            60..=79 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Annotate entry points with priority tiers and generate a prioritized
/// execution plan.
pub fn prioritize_entries(entries: &mut [FuzzEntryPoint]) -> Vec<(EntryPriority, &FuzzEntryPoint)> {
    entries.sort_by(|a, b| b.score.cmp(&a.score));
    entries.iter().map(|e| (EntryPriority::from_score(e.score), e)).collect()
}

/// Format a prioritized entry plan as a Markdown table.
#[must_use] 
pub fn format_entry_plan(plan: &[(EntryPriority, &FuzzEntryPoint)]) -> String {
    let mut out = String::new();
    writeln!(out, "| Priority | Score | Function | Source |").ok();
    writeln!(out, "|----------|-------|----------|--------|").ok();
    for (prio, entry) in plan {
        writeln!(out, "| {:?} | {} | {} | {:?} |",
            prio, entry.score, entry.name, entry.source).ok();
    }
    out
}

// ─── Linker script generator ──────────────────────────────────────────────────

/// Generates a complete linker script for wrapping a target library.
pub struct LinkerScriptGenerator {
    pub lib_name: String,
    pub lib_path: Option<String>,
    pub extra_libs: Vec<String>,
    pub wrap_functions: Vec<String>,
}

impl LinkerScriptGenerator {
    pub fn new(lib_name: impl Into<String>) -> Self {
        Self { lib_name: lib_name.into(), lib_path: None, extra_libs: Vec::new(), wrap_functions: Vec::new() }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.lib_path = Some(path.into()); self
    }

    pub fn wrap(mut self, func: impl Into<String>) -> Self {
        self.wrap_functions.push(func.into()); self
    }

    /// Generate the `build.rs` snippet for linking the target.
    #[must_use] 
    pub fn generate_build_rs(&self) -> String {
        let mut out = String::new();
        writeln!(out, "// Auto-generated build.rs for fuzz harness").ok();
        writeln!(out, "fn main() {{").ok();
        if let Some(path) = &self.lib_path {
            writeln!(out, "    println!(\"cargo:rustc-link-search=native={path}\");").ok();
        }
        writeln!(out, "    println!(\"cargo:rustc-link-lib={}\");", self.lib_name).ok();
        for lib in &self.extra_libs {
            writeln!(out, "    println!(\"cargo:rustc-link-lib={lib}\");").ok();
        }
        for func in &self.wrap_functions {
            writeln!(out, "    println!(\"cargo:rustc-link-arg=-Wl,--wrap={func}\");").ok();
        }
        writeln!(out, "}}").ok();
        out
    }

    /// Generate a `Cargo.toml` `[dependencies]` section for libfuzzer-sys.
    #[must_use] 
    pub fn generate_cargo_deps() -> String {
        [
            "[dependencies]",
            "libfuzzer-sys = \"0.4\"",
            "",
            "[profile.release]",
            "opt-level = 3",
            "debug = true",
            "",
            "[profile.fuzz]",
            "inherits = \"release\"",
            "opt-level = 1",
            "incremental = false",
        ].join("\n")
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_parse_params() {
        let params = infer_params_from_name("parse_png_header");
        assert!(params.iter().any(|p| matches!(p.ty, InferredParamType::DataSizePtr)));
    }

    #[test]
    fn test_score_parse_function() {
        let s = score_entry("parse_xml_document", 2);
        assert!(s > 60, "expected high score for parse fn, got {s}");
    }

    #[test]
    fn test_score_getter_penalty() {
        let s = score_entry("get_version_string", 0);
        assert!(s < 50, "expected low score for getter, got {s}");
    }

    #[test]
    fn test_codegen_data_size() {
        let config = HarnessGenConfig { lib_name: Some("mylib".into()), ..Default::default() };
        let codegen = HarnessCodegen::new(&config);
        let entry = FuzzEntryPoint {
            name: "parse_buf".into(),
            address: 0x1000,
            params: vec![
                FuzzParam { name: "data".into(), ty: InferredParamType::DataSizePtr, is_output: false },
                FuzzParam { name: "size".into(), ty: InferredParamType::Integer { signed: false, bits: 64 }, is_output: false },
            ],
            return_type: InferredParamType::Integer { signed: true, bits: 32 },
            source: EntrySource::HeuristicName,
            score: 80,
            notes: vec![],
        };
        let h = codegen.generate(&entry);
        assert!(h.code.contains("fuzz_target!"));
        assert!(h.code.contains("parse_buf"));
        assert!(h.code.contains("unsafe"));
    }

    #[test]
    fn test_linker_script() {
        let config = HarnessGenConfig { lib_name: Some("png".into()), ..Default::default() };
        let codegen = HarnessCodegen::new(&config);
        let script = codegen.generate_linker_script();
        assert!(script.contains("-lpng"));
    }
}
