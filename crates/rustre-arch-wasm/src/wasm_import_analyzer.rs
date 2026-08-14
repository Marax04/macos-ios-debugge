//! Analyze WebAssembly imports/exports: categorize imports by module
//! (wasi_snapshot_preview1, env, emscripten), identify WASI syscall wrappers,
//! detect Emscripten stdlib functions, find imported memory and table entries,
//! compute import complexity score.

use std::collections::HashMap;
use std::fmt;

// ── ImportModule ─────────────────────────────────────────────────────────────

/// Categorization of a known WebAssembly import module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportModule {
    /// WASI snapshot_preview1 (`wasi_snapshot_preview1`).
    WasiSnapshotPreview1,
    /// WASI unstable (`wasi_unstable`).
    WasiUnstable,
    /// Generic environment imports (`env`).
    Env,
    /// Emscripten runtime imports (`emscripten` or `emenv`).
    Emscripten,
    /// GOT function table imports (Emscripten PIC).
    GotFunc,
    /// GOT memory imports (Emscripten PIC).
    GotMem,
    /// WebAssembly component model imports.
    WasiIO,
    /// An unrecognized module with the given name.
    Unknown(String),
}

impl ImportModule {
    /// Parse a module name string into a categorized `ImportModule`.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "wasi_snapshot_preview1" => Self::WasiSnapshotPreview1,
            "wasi_unstable" => Self::WasiUnstable,
            "env" => Self::Env,
            "emscripten" | "emenv" => Self::Emscripten,
            "GOT.func" => Self::GotFunc,
            "GOT.mem" => Self::GotMem,
            "wasi:io/streams" | "wasi:cli/stdin" | "wasi:cli/stdout" | "wasi:cli/stderr" => {
                Self::WasiIO
            }
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Return the canonical module name string.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        match self {
            Self::WasiSnapshotPreview1 => "wasi_snapshot_preview1",
            Self::WasiUnstable => "wasi_unstable",
            Self::Env => "env",
            Self::Emscripten => "emscripten",
            Self::GotFunc => "GOT.func",
            Self::GotMem => "GOT.mem",
            Self::WasiIO => "wasi:io",
            Self::Unknown(n) => n.as_str(),
        }
    }

    /// Returns `true` for any WASI module variant.
    #[must_use]
    pub fn is_wasi(&self) -> bool {
        matches!(
            self,
            Self::WasiSnapshotPreview1 | Self::WasiUnstable | Self::WasiIO
        )
    }

    /// Returns `true` for Emscripten-related modules.
    #[must_use]
    pub fn is_emscripten(&self) -> bool {
        matches!(self, Self::Emscripten | Self::GotFunc | Self::GotMem)
    }
}

impl fmt::Display for ImportModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_name())
    }
}

// ── WasiFunction ─────────────────────────────────────────────────────────────

/// A known WASI function with its syscall number and category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiFunction {
    /// WASI function name (e.g. `"fd_write"`).
    pub name: &'static str,
    /// POSIX-equivalent syscall name, if applicable.
    pub posix_equiv: Option<&'static str>,
    /// Category of the function.
    pub category: WasiCategory,
}

/// Category of a WASI function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasiCategory {
    FileSystem,
    Process,
    Clock,
    Socket,
    Random,
    Args,
    Environ,
    Memory,
    Scheduling,
    Other,
}

impl fmt::Display for WasiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileSystem => "filesystem",
            Self::Process => "process",
            Self::Clock => "clock",
            Self::Socket => "socket",
            Self::Random => "random",
            Self::Args => "args",
            Self::Environ => "environ",
            Self::Memory => "memory",
            Self::Scheduling => "scheduling",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Lookup table for known WASI preview1 functions.
static WASI_PREVIEW1_FUNCTIONS: &[WasiFunction] = &[
    WasiFunction { name: "fd_write", posix_equiv: Some("write"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_read", posix_equiv: Some("read"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_seek", posix_equiv: Some("lseek"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_close", posix_equiv: Some("close"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_fdstat_get", posix_equiv: None, category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_fdstat_set_flags", posix_equiv: None, category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_prestat_get", posix_equiv: None, category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_prestat_dir_name", posix_equiv: None, category: WasiCategory::FileSystem },
    WasiFunction { name: "path_open", posix_equiv: Some("open"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_filestat_get", posix_equiv: Some("stat"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_unlink_file", posix_equiv: Some("unlink"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_rename", posix_equiv: Some("rename"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_create_directory", posix_equiv: Some("mkdir"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_remove_directory", posix_equiv: Some("rmdir"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_readlink", posix_equiv: Some("readlink"), category: WasiCategory::FileSystem },
    WasiFunction { name: "path_symlink", posix_equiv: Some("symlink"), category: WasiCategory::FileSystem },
    WasiFunction { name: "proc_exit", posix_equiv: Some("exit"), category: WasiCategory::Process },
    WasiFunction { name: "proc_raise", posix_equiv: Some("raise"), category: WasiCategory::Process },
    WasiFunction { name: "clock_time_get", posix_equiv: Some("clock_gettime"), category: WasiCategory::Clock },
    WasiFunction { name: "clock_res_get", posix_equiv: Some("clock_getres"), category: WasiCategory::Clock },
    WasiFunction { name: "poll_oneoff", posix_equiv: Some("select"), category: WasiCategory::Scheduling },
    WasiFunction { name: "random_get", posix_equiv: Some("getrandom"), category: WasiCategory::Random },
    WasiFunction { name: "args_get", posix_equiv: None, category: WasiCategory::Args },
    WasiFunction { name: "args_sizes_get", posix_equiv: None, category: WasiCategory::Args },
    WasiFunction { name: "environ_get", posix_equiv: None, category: WasiCategory::Environ },
    WasiFunction { name: "environ_sizes_get", posix_equiv: None, category: WasiCategory::Environ },
    WasiFunction { name: "sock_recv", posix_equiv: Some("recv"), category: WasiCategory::Socket },
    WasiFunction { name: "sock_send", posix_equiv: Some("send"), category: WasiCategory::Socket },
    WasiFunction { name: "sock_shutdown", posix_equiv: Some("shutdown"), category: WasiCategory::Socket },
    WasiFunction { name: "fd_allocate", posix_equiv: Some("posix_fallocate"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_datasync", posix_equiv: Some("fdatasync"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_sync", posix_equiv: Some("fsync"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_tell", posix_equiv: None, category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_readdir", posix_equiv: Some("readdir"), category: WasiCategory::FileSystem },
    WasiFunction { name: "fd_renumber", posix_equiv: Some("dup2"), category: WasiCategory::FileSystem },
    WasiFunction { name: "sched_yield", posix_equiv: Some("sched_yield"), category: WasiCategory::Scheduling },
];

/// Look up a WASI function by name.
#[must_use]
pub fn lookup_wasi_function(name: &str) -> Option<&'static WasiFunction> {
    WASI_PREVIEW1_FUNCTIONS.iter().find(|f| f.name == name)
}

// ── WasmImport ───────────────────────────────────────────────────────────────

/// The kind of a WebAssembly import or export.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportKind {
    Function { type_index: u32 },
    Table { element_type: u8, min: u32, max: Option<u32> },
    Memory { min: u32, max: Option<u32> },
    Global { val_type: u8, mutable: bool },
}

impl ImportKind {
    /// Return the category name string.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Function { .. } => "function",
            Self::Table { .. } => "table",
            Self::Memory { .. } => "memory",
            Self::Global { .. } => "global",
        }
    }
}

/// A single WebAssembly import entry.
#[derive(Debug, Clone)]
pub struct WasmImport {
    /// Module name (e.g. `"wasi_snapshot_preview1"`).
    pub module: String,
    /// Field/function name (e.g. `"fd_write"`).
    pub name: String,
    /// Import kind.
    pub kind: ImportKind,
    /// Parsed module category.
    pub module_category: ImportModule,
}

impl WasmImport {
    /// Create a function import.
    #[must_use]
    pub fn function(module: impl Into<String>, name: impl Into<String>, type_index: u32) -> Self {
        let module = module.into();
        let module_category = ImportModule::from_name(&module);
        Self {
            module,
            name: name.into(),
            kind: ImportKind::Function { type_index },
            module_category,
        }
    }

    /// Create a memory import.
    #[must_use]
    pub fn memory(module: impl Into<String>, name: impl Into<String>, min: u32, max: Option<u32>) -> Self {
        let module = module.into();
        let module_category = ImportModule::from_name(&module);
        Self {
            module,
            name: name.into(),
            kind: ImportKind::Memory { min, max },
            module_category,
        }
    }

    /// Create a table import.
    #[must_use]
    pub fn table(
        module: impl Into<String>,
        name: impl Into<String>,
        element_type: u8,
        min: u32,
        max: Option<u32>,
    ) -> Self {
        let module = module.into();
        let module_category = ImportModule::from_name(&module);
        Self {
            module,
            name: name.into(),
            kind: ImportKind::Table { element_type, min, max },
            module_category,
        }
    }

    /// Returns `true` when this is an `env.memory` import.
    #[must_use]
    pub fn is_imported_memory(&self) -> bool {
        matches!(self.kind, ImportKind::Memory { .. })
    }

    /// Returns `true` when this is an `env.__table_base` or similar table import.
    #[must_use]
    pub fn is_imported_table(&self) -> bool {
        matches!(self.kind, ImportKind::Table { .. })
    }

    /// Look up the WASI descriptor for this import, if applicable.
    #[must_use]
    pub fn wasi_descriptor(&self) -> Option<&'static WasiFunction> {
        if self.module_category.is_wasi() {
            lookup_wasi_function(&self.name)
        } else {
            None
        }
    }
}

impl fmt::Display for WasmImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "import {}::{} ({})", self.module, self.name, self.kind.kind_name())
    }
}

// ── WasmExport ───────────────────────────────────────────────────────────────

/// A WebAssembly export entry.
#[derive(Debug, Clone)]
pub struct WasmExport {
    /// Export name.
    pub name: String,
    /// Export kind.
    pub kind: ImportKind,
    /// Index into the relevant index space.
    pub index: u32,
}

impl WasmExport {
    /// Create a function export.
    #[must_use]
    pub fn function(name: impl Into<String>, func_index: u32) -> Self {
        Self {
            name: name.into(),
            kind: ImportKind::Function { type_index: 0 },
            index: func_index,
        }
    }

    /// Create a memory export.
    #[must_use]
    pub fn memory(name: impl Into<String>, mem_index: u32) -> Self {
        Self {
            name: name.into(),
            kind: ImportKind::Memory { min: 0, max: None },
            index: mem_index,
        }
    }

    /// Returns `true` for `_start` or `main` exports.
    #[must_use]
    pub fn is_entry_point(&self) -> bool {
        matches!(self.name.as_str(), "_start" | "main" | "__main_argc_argv")
    }
}

impl fmt::Display for WasmExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "export {} ({})", self.name, self.kind.kind_name())
    }
}

// ── ImportAnalysis ────────────────────────────────────────────────────────────

/// The result of analyzing all imports/exports in a WebAssembly module.
#[derive(Debug, Clone)]
pub struct ImportAnalysis {
    /// All raw imports.
    pub imports: Vec<WasmImport>,
    /// All raw exports.
    pub exports: Vec<WasmExport>,
    /// Breakdown of imports by module category.
    pub by_module: HashMap<String, Vec<usize>>,
    /// Set of WASI categories used (if any WASI imports are present).
    pub wasi_categories: Vec<WasiCategory>,
    /// Whether the module uses Emscripten runtime.
    pub is_emscripten: bool,
    /// Whether the module uses WASI.
    pub is_wasi: bool,
    /// Whether the module imports memory (as opposed to defining it locally).
    pub has_imported_memory: bool,
    /// Whether the module imports a table.
    pub has_imported_table: bool,
    /// Number of imported functions.
    pub imported_func_count: usize,
    /// Number of exported functions.
    pub exported_func_count: usize,
    /// Complexity score in `[0.0, 1.0]`.
    pub complexity_score: f32,
    /// Detected Emscripten stdlib functions.
    pub emscripten_funcs: Vec<String>,
    /// Unknown/unrecognized imports.
    pub unknown_imports: Vec<WasmImport>,
}

impl ImportAnalysis {
    /// Build an `ImportAnalysis` from a list of imports and exports.
    #[must_use]
    pub fn analyze(imports: Vec<WasmImport>, exports: Vec<WasmExport>) -> Self {
        let mut by_module: HashMap<String, Vec<usize>> = HashMap::new();
        let mut wasi_categories_set: HashMap<WasiCategory, ()> = HashMap::new();
        let mut is_emscripten = false;
        let mut is_wasi = false;
        let mut has_imported_memory = false;
        let mut has_imported_table = false;
        let mut imported_func_count = 0usize;
        let mut emscripten_funcs: Vec<String> = Vec::new();
        let mut unknown_imports: Vec<WasmImport> = Vec::new();

        for (idx, imp) in imports.iter().enumerate() {
            by_module
                .entry(imp.module.clone())
                .or_default()
                .push(idx);

            match &imp.kind {
                ImportKind::Function { .. } => imported_func_count += 1,
                ImportKind::Memory { .. } => has_imported_memory = true,
                ImportKind::Table { .. } => has_imported_table = true,
                ImportKind::Global { .. } => {}
            }

            match &imp.module_category {
                ImportModule::WasiSnapshotPreview1 | ImportModule::WasiUnstable | ImportModule::WasiIO => {
                    is_wasi = true;
                    if let Some(wf) = imp.wasi_descriptor() {
                        wasi_categories_set.insert(wf.category, ());
                    }
                }
                ImportModule::Emscripten | ImportModule::GotFunc | ImportModule::GotMem => {
                    is_emscripten = true;
                    emscripten_funcs.push(imp.name.clone());
                }
                ImportModule::Env => {
                    // Check if this is an Emscripten env import.
                    if is_emscripten_env_func(&imp.name) {
                        is_emscripten = true;
                        emscripten_funcs.push(imp.name.clone());
                    } else if imp.module_category == ImportModule::Unknown(imp.module.clone()) {
                        unknown_imports.push(imp.clone());
                    }
                }
                ImportModule::Unknown(_) => {
                    unknown_imports.push(imp.clone());
                }
            }
        }

        let exported_func_count = exports
            .iter()
            .filter(|e| matches!(e.kind, ImportKind::Function { .. }))
            .count();

        let wasi_categories: Vec<WasiCategory> =
            wasi_categories_set.into_keys().collect();

        let complexity_score =
            compute_complexity_score(&imports, &exports, imported_func_count, is_wasi, is_emscripten);

        Self {
            imports,
            exports,
            by_module,
            wasi_categories,
            is_emscripten,
            is_wasi,
            has_imported_memory,
            has_imported_table,
            imported_func_count,
            exported_func_count,
            complexity_score,
            emscripten_funcs,
            unknown_imports,
        }
    }

    /// Return all WASI imports, grouped by category.
    #[must_use]
    pub fn wasi_imports_by_category(&self) -> HashMap<String, Vec<&WasmImport>> {
        let mut map: HashMap<String, Vec<&WasmImport>> = HashMap::new();
        for imp in &self.imports {
            if imp.module_category.is_wasi() {
                if let Some(wf) = imp.wasi_descriptor() {
                    map.entry(wf.category.to_string())
                        .or_default()
                        .push(imp);
                }
            }
        }
        map
    }

    /// Return the total number of imports.
    #[must_use]
    pub fn total_imports(&self) -> usize {
        self.imports.len()
    }

    /// Return all imports from a specific module name.
    #[must_use]
    pub fn imports_from(&self, module: &str) -> Vec<&WasmImport> {
        self.imports.iter().filter(|i| i.module == module).collect()
    }

    /// Return the entry-point export, if present.
    #[must_use]
    pub fn entry_point(&self) -> Option<&WasmExport> {
        self.exports.iter().find(|e| e.is_entry_point())
    }

    /// Return a human-readable summary of the analysis.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("imports={}", self.total_imports()));
        parts.push(format!("exports={}", self.exports.len()));
        if self.is_wasi {
            parts.push(format!("wasi({})", self.wasi_categories.len()));
        }
        if self.is_emscripten {
            parts.push(format!("emscripten({})", self.emscripten_funcs.len()));
        }
        if self.has_imported_memory {
            parts.push("imported_memory".into());
        }
        parts.push(format!("complexity={:.2}", self.complexity_score));
        parts.join(" ")
    }
}

// ── Emscripten detection helpers ──────────────────────────────────────────────

/// Common Emscripten `env` import prefixes/names.
static EMSCRIPTEN_ENV_PREFIXES: &[&str] = &[
    "emscripten_",
    "_emscripten",
    "__emscripten",
    "invoke_",
    "_abort",
    "__assert_fail",
    "__cxa_throw",
    "__cxa_allocate_exception",
    "__cxa_begin_catch",
    "__cxa_end_catch",
    "__cxa_find_matching_catch",
    "__resumeException",
    "__stack_chk_fail",
    "__setjmp_test",
    "_longjmp",
    "_setjmp",
    "setThrew",
    "getTempRet0",
    "setTempRet0",
    "abortStackOverflow",
    "nullFunc_",
    "dynCall_",
    "asm2wasm_",
];

/// Returns `true` when `name` appears to be an Emscripten env import.
#[must_use]
pub fn is_emscripten_env_func(name: &str) -> bool {
    EMSCRIPTEN_ENV_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix) || name == *prefix)
}

// ── complexity score ──────────────────────────────────────────────────────────

/// Compute an import complexity score in `[0.0, 1.0]`.
///
/// Factors:
/// - Number of imported functions (capped at 100).
/// - WASI usage adds +0.15.
/// - Emscripten usage adds +0.20.
/// - Imported memory adds +0.10.
#[must_use]
fn compute_complexity_score(
    imports: &[WasmImport],
    _exports: &[WasmExport],
    imported_func_count: usize,
    is_wasi: bool,
    is_emscripten: bool,
) -> f32 {
    let func_score = (imported_func_count as f32 / 100.0).min(1.0) * 0.55;
    let wasi_bonus = if is_wasi { 0.15 } else { 0.0 };
    let emsc_bonus = if is_emscripten { 0.20 } else { 0.0 };
    let mem_bonus = if imports.iter().any(|i| i.is_imported_memory()) { 0.10 } else { 0.0 };
    (func_score + wasi_bonus + emsc_bonus + mem_bonus).clamp(0.0, 1.0)
}

// ── ImportAnalyzer ────────────────────────────────────────────────────────────

/// Builder/analyzer for WebAssembly module import/export analysis.
#[derive(Debug, Default)]
pub struct ImportAnalyzer {
    imports: Vec<WasmImport>,
    exports: Vec<WasmExport>,
}

impl ImportAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an import entry.
    pub fn add_import(&mut self, imp: WasmImport) {
        self.imports.push(imp);
    }

    /// Add an export entry.
    pub fn add_export(&mut self, exp: WasmExport) {
        self.exports.push(exp);
    }

    /// Run the analysis and return the result.
    #[must_use]
    pub fn analyze(self) -> ImportAnalysis {
        ImportAnalysis::analyze(self.imports, self.exports)
    }

    /// Parse a minimal import section from raw binary bytes.
    ///
    /// Expects the byte slice to start with the count (as ULEB128), followed by
    /// each import entry encoded as:
    ///   `uleb128(mod_len) mod_bytes uleb128(name_len) name_bytes 0x00 uleb128(type_idx)`
    ///
    /// Returns the number of successfully parsed imports.
    pub fn parse_import_section(&mut self, bytes: &[u8]) -> usize {
        let Some((count, mut pos)) = decode_uleb128_simple(bytes, 0) else {
            return 0;
        };
        let mut parsed = 0usize;
        for _ in 0..count {
            let Some((mod_len, n)) = decode_uleb128_simple(bytes, pos) else { break };
            let mod_len = mod_len as usize;
            pos += n;
            if pos + mod_len > bytes.len() { break; }
            let module = String::from_utf8_lossy(&bytes[pos..pos + mod_len]).into_owned();
            pos += mod_len;

            let Some((name_len, n2)) = decode_uleb128_simple(bytes, pos) else { break };
            let name_len = name_len as usize;
            pos += n2;
            if pos + name_len > bytes.len() { break; }
            let name = String::from_utf8_lossy(&bytes[pos..pos + name_len]).into_owned();
            pos += name_len;

            if pos >= bytes.len() { break; }
            let kind_byte = bytes[pos];
            pos += 1;

            let import = match kind_byte {
                0x00 => {
                    // Function: type index
                    let Some((type_idx, n3)) = decode_uleb128_simple(bytes, pos) else { break };
                    pos += n3;
                    WasmImport::function(module, name, type_idx as u32)
                }
                0x01 => {
                    // Table: element_type, limits
                    if pos + 2 > bytes.len() { break; }
                    let elem_type = bytes[pos];
                    pos += 1;
                    let kind = bytes[pos];
                    pos += 1;
                    let Some((min, n4)) = decode_uleb128_simple(bytes, pos) else { break };
                    pos += n4;
                    let max = if kind == 1 {
                        let Some((m, n5)) = decode_uleb128_simple(bytes, pos) else { break };
                        pos += n5;
                        Some(m as u32)
                    } else { None };
                    WasmImport::table(module, name, elem_type, min as u32, max)
                }
                0x02 => {
                    // Memory: limits
                    if pos >= bytes.len() { break; }
                    let kind = bytes[pos];
                    pos += 1;
                    let Some((min, n4)) = decode_uleb128_simple(bytes, pos) else { break };
                    pos += n4;
                    let max = if kind == 1 {
                        let Some((m, n5)) = decode_uleb128_simple(bytes, pos) else { break };
                        pos += n5;
                        Some(m as u32)
                    } else { None };
                    WasmImport::memory(module, name, min as u32, max)
                }
                _ => break,
            };
            self.imports.push(import);
            parsed += 1;
        }
        parsed
    }
}

/// Simple ULEB128 decoder returning `(value, bytes_consumed)`.
#[must_use]
fn decode_uleb128_simple(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= bytes.len() { return None; }
        let b = bytes[pos];
        pos += 1;
        result |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
        if shift >= 64 { return None; }
    }
    Some((result, pos - start))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_module_from_name() {
        assert_eq!(
            ImportModule::from_name("wasi_snapshot_preview1"),
            ImportModule::WasiSnapshotPreview1
        );
        assert_eq!(ImportModule::from_name("env"), ImportModule::Env);
        assert!(matches!(
            ImportModule::from_name("custom_module"),
            ImportModule::Unknown(_)
        ));
    }

    #[test]
    fn test_import_module_is_wasi() {
        assert!(ImportModule::WasiSnapshotPreview1.is_wasi());
        assert!(!ImportModule::Env.is_wasi());
    }

    #[test]
    fn test_lookup_wasi_function() {
        let f = lookup_wasi_function("fd_write").unwrap();
        assert_eq!(f.name, "fd_write");
        assert_eq!(f.posix_equiv, Some("write"));
        assert_eq!(f.category, WasiCategory::FileSystem);
        assert!(lookup_wasi_function("unknown_func").is_none());
    }

    #[test]
    fn test_wasm_import_function() {
        let imp = WasmImport::function("wasi_snapshot_preview1", "fd_write", 3);
        assert_eq!(imp.module, "wasi_snapshot_preview1");
        assert_eq!(imp.name, "fd_write");
        assert!(matches!(imp.kind, ImportKind::Function { type_index: 3 }));
        let wd = imp.wasi_descriptor().unwrap();
        assert_eq!(wd.name, "fd_write");
    }

    #[test]
    fn test_wasm_import_memory() {
        let imp = WasmImport::memory("env", "memory", 1, Some(10));
        assert!(imp.is_imported_memory());
        assert!(!imp.is_imported_table());
    }

    #[test]
    fn test_import_analysis_wasi() {
        let mut analyzer = ImportAnalyzer::new();
        analyzer.add_import(WasmImport::function("wasi_snapshot_preview1", "fd_write", 0));
        analyzer.add_import(WasmImport::function("wasi_snapshot_preview1", "proc_exit", 1));
        analyzer.add_import(WasmImport::memory("env", "memory", 1, None));
        analyzer.add_export(WasmExport::function("_start", 0));
        let analysis = analyzer.analyze();
        assert!(analysis.is_wasi);
        assert!(!analysis.is_emscripten);
        assert!(analysis.has_imported_memory);
        assert_eq!(analysis.imported_func_count, 2);
        assert!(analysis.entry_point().is_some());
        assert!(analysis.complexity_score > 0.0);
    }

    #[test]
    fn test_import_analysis_emscripten() {
        let mut analyzer = ImportAnalyzer::new();
        analyzer.add_import(WasmImport::function("env", "emscripten_memcpy_big", 0));
        analyzer.add_import(WasmImport::function("env", "_abort", 1));
        let analysis = analyzer.analyze();
        assert!(analysis.is_emscripten);
        assert!(!analysis.is_wasi);
        assert!(!analysis.emscripten_funcs.is_empty());
    }

    #[test]
    fn test_wasi_imports_by_category() {
        let mut analyzer = ImportAnalyzer::new();
        analyzer.add_import(WasmImport::function("wasi_snapshot_preview1", "fd_write", 0));
        analyzer.add_import(WasmImport::function("wasi_snapshot_preview1", "clock_time_get", 1));
        let analysis = analyzer.analyze();
        let by_cat = analysis.wasi_imports_by_category();
        assert!(by_cat.contains_key("filesystem"));
        assert!(by_cat.contains_key("clock"));
    }

    #[test]
    fn test_complexity_score_bounds() {
        let analysis = ImportAnalysis::analyze(vec![], vec![]);
        assert!(analysis.complexity_score >= 0.0);
        assert!(analysis.complexity_score <= 1.0);
    }

    #[test]
    fn test_is_emscripten_env_func() {
        assert!(is_emscripten_env_func("emscripten_memcpy_big"));
        assert!(is_emscripten_env_func("invoke_v"));
        assert!(is_emscripten_env_func("dynCall_ii"));
        assert!(!is_emscripten_env_func("malloc"));
        assert!(!is_emscripten_env_func("fd_write"));
    }

    #[test]
    fn test_entry_point_detection() {
        let mut analyzer = ImportAnalyzer::new();
        analyzer.add_export(WasmExport::function("_start", 5));
        analyzer.add_export(WasmExport::function("some_other", 3));
        let analysis = analyzer.analyze();
        let ep = analysis.entry_point().unwrap();
        assert_eq!(ep.name, "_start");
    }

    #[test]
    fn test_imports_from() {
        let imports = vec![
            WasmImport::function("wasi_snapshot_preview1", "fd_write", 0),
            WasmImport::function("env", "malloc", 1),
        ];
        let analysis = ImportAnalysis::analyze(imports, vec![]);
        let wasi = analysis.imports_from("wasi_snapshot_preview1");
        assert_eq!(wasi.len(), 1);
        assert_eq!(wasi[0].name, "fd_write");
    }

    #[test]
    fn test_export_is_entry_point() {
        assert!(WasmExport::function("_start", 0).is_entry_point());
        assert!(WasmExport::function("main", 0).is_entry_point());
        assert!(!WasmExport::function("helper", 0).is_entry_point());
    }
}
