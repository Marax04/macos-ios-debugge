//! `rustre-mobile-jadx` — JADX Java decompiler wrapper types, DEX lifter, Java AST, and emitter.

pub mod java_decompiler;
pub mod dalvik_lift;
pub mod deobfuscation_pass;
pub mod dex_to_java;
pub mod jadx_decompiler_analysis;
pub mod java_ast;
pub mod java_emitter;
pub mod kotlin_support;
pub mod lambda_recovery;
pub mod jadx_output_parser;
pub mod jadx_resource_decoder;
pub mod jadx_call_graph_builder;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JadxError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("decompile error: {0}")]
    Decompile(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("io error: {0}")]
    Io(String),
}

// ─── JadxConfig (legacy) ─────────────────────────────────────────────────────

/// Legacy config kept for backward compatibility with `MockJadxRunner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxConfig {
    pub jadx_path: String,
    pub input: String,
    pub output_dir: String,
    pub threads: u32,
    pub deobfuscate: bool,
}

impl JadxConfig {
    /// Create a new config with sensible defaults.
    #[must_use]
    pub fn new(jadx: impl Into<String>, input: impl Into<String>, out: impl Into<String>) -> Self {
        Self {
            jadx_path: jadx.into(),
            input: input.into(),
            output_dir: out.into(),
            threads: 4,
            deobfuscate: false,
        }
    }

    /// Set the thread count.
    #[must_use]
    pub const fn with_threads(mut self, t: u32) -> Self {
        self.threads = t;
        self
    }

    /// Enable deobfuscation.
    #[must_use]
    pub const fn with_deobfuscate(mut self) -> Self {
        self.deobfuscate = true;
        self
    }
}

// ─── CliJadxConfig ────────────────────────────────────────────────────────────

/// Configuration for the real CLI JADX runner.
#[derive(Debug, Clone)]
pub struct CliJadxConfig {
    /// Path to the `jadx` (or `jadx-gui`) binary.
    pub jadx_path: PathBuf,
    /// Optional override for the output directory; `None` means a temp dir is
    /// created automatically.
    pub output_dir: Option<PathBuf>,
    /// Pass `--deobf` to JADX.
    pub deobfuscate: bool,
    /// Pass `--show-bad-code` to JADX.
    pub show_inconsistent_code: bool,
    /// Pass `--no-res` to JADX (skip resource decoding).
    pub no_res: bool,
}

impl Default for CliJadxConfig {
    /// Looks for `jadx` in `PATH`; falls back to the literal string `"jadx"`
    /// if the binary cannot be located so that the error surfaces at runtime.
    fn default() -> Self {
        let jadx_path = CliJadxRunner::find_jadx_in_path().unwrap_or_else(|| PathBuf::from("jadx"));
        Self {
            jadx_path,
            output_dir: None,
            deobfuscate: false,
            show_inconsistent_code: false,
            no_res: false,
        }
    }
}

// ─── JavaMethod ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaMethod {
    pub name: String,
    pub signature: String,
    pub return_type: String,
    pub params: Vec<String>,
    pub body: String,
    pub is_static: bool,
    pub is_native: bool,
}

impl JavaMethod {
    /// Returns `true` if this is a constructor (named after the class or `<init>`).
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == "<init>" || self.name == "constructor"
    }
}

// ─── JavaClass ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaClass {
    pub class_name: String,
    pub package: String,
    pub source: String,
    pub methods: Vec<JavaMethod>,
    pub super_class: Option<String>,
}

impl JavaClass {
    /// Return all static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&JavaMethod> {
        self.methods.iter().filter(|m| m.is_static).collect()
    }

    /// Return all native methods.
    #[must_use]
    pub fn native_methods(&self) -> Vec<&JavaMethod> {
        self.methods.iter().filter(|m| m.is_native).collect()
    }
}

// ─── DecompiledProject ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledProject {
    pub classes: Vec<JavaClass>,
    pub total: usize,
    pub failed: usize,
}

impl DecompiledProject {
    /// Find a class by simple name or fully-qualified name.
    #[must_use]
    pub fn find_class(&self, name: &str) -> Option<&JavaClass> {
        self.classes.iter().find(|c| {
            c.class_name == name || {
                let fqn = format!("{}.{}", c.package, c.class_name);
                fqn == name
            }
        })
    }

    /// Return all classes in the given package.
    #[must_use]
    pub fn in_package(&self, pkg: &str) -> Vec<&JavaClass> {
        self.classes.iter().filter(|c| c.package == pkg).collect()
    }

    /// Return the fraction of successfully decompiled classes.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        let succeeded = self.total.saturating_sub(self.failed);
        let succeeded_u32 = u32::try_from(succeeded).unwrap_or(u32::MAX);
        let total_u32 = u32::try_from(self.total).unwrap_or(u32::MAX);
        f64::from(succeeded_u32) / f64::from(total_u32)
    }

    /// Create a mock project with 3 packages, 9 classes, and various methods.
    #[must_use]
    pub fn mock() -> Self {
        let make_method = |name: &str, static_m: bool, native_m: bool, ret: &str| JavaMethod {
            name: name.to_string(),
            signature: format!("{name}()"),
            return_type: ret.to_string(),
            params: vec![],
            body: if native_m {
                String::new()
            } else {
                "return null;".to_string()
            },
            is_static: static_m,
            is_native: native_m,
        };

        let make_class = |pkg: &str, name: &str, methods: Vec<JavaMethod>| JavaClass {
            class_name: name.to_string(),
            package: pkg.to_string(),
            source: format!("package {pkg};\npublic class {name} {{}}"),
            methods,
            super_class: Some("Object".to_string()),
        };

        let classes = vec![
            // Package com.example.app — 3 classes
            make_class(
                "com.example.app",
                "MainActivity",
                vec![
                    make_method("<init>", false, false, "void"),
                    make_method("onCreate", false, false, "void"),
                    make_method("nativeInit", false, true, "void"),
                ],
            ),
            make_class(
                "com.example.app",
                "AppApplication",
                vec![make_method("onCreate", false, false, "void")],
            ),
            make_class(
                "com.example.app",
                "Utils",
                vec![
                    make_method("encrypt", true, false, "byte[]"),
                    make_method("decrypt", true, false, "byte[]"),
                ],
            ),
            // Package com.example.network — 3 classes
            make_class(
                "com.example.network",
                "ApiClient",
                vec![
                    make_method("<init>", false, false, "void"),
                    make_method("get", false, false, "Response"),
                    make_method("post", false, false, "Response"),
                ],
            ),
            make_class(
                "com.example.network",
                "Interceptor",
                vec![make_method("intercept", false, false, "Response")],
            ),
            make_class(
                "com.example.network",
                "CertPinner",
                vec![
                    make_method("pin", true, false, "void"),
                    make_method("verify", true, false, "boolean"),
                    make_method("nativeVerify", false, true, "boolean"),
                ],
            ),
            // Package com.example.crypto — 3 classes
            make_class(
                "com.example.crypto",
                "AesHelper",
                vec![
                    make_method("encrypt", true, false, "byte[]"),
                    make_method("decrypt", true, false, "byte[]"),
                    make_method("nativeEncrypt", false, true, "byte[]"),
                ],
            ),
            make_class(
                "com.example.crypto",
                "KeyManager",
                vec![
                    make_method("<init>", false, false, "void"),
                    make_method("getKey", false, false, "byte[]"),
                ],
            ),
            make_class(
                "com.example.crypto",
                "HashUtil",
                vec![
                    make_method("sha256", true, false, "byte[]"),
                    make_method("md5", true, false, "byte[]"),
                ],
            ),
        ];

        let total = classes.len();
        Self {
            classes,
            total,
            failed: 0,
        }
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

pub trait JadxRunner: Send + Sync {
    /// Decompile the APK described by `cfg` and return the resulting project.
    ///
    /// # Errors
    ///
    /// Returns a `JadxError` if decompilation fails for any reason (e.g.
    /// missing APK, invalid configuration, runtime failures inside JADX).
    fn decompile(&self, cfg: &JadxConfig) -> Result<DecompiledProject, JadxError>;
}

// ─── MockJadxRunner ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MockJadxRunner;

impl JadxRunner for MockJadxRunner {
    fn decompile(&self, _cfg: &JadxConfig) -> Result<DecompiledProject, JadxError> {
        Ok(DecompiledProject::mock())
    }
}

// ─── CliJadxRunner ────────────────────────────────────────────────────────────

/// Invokes the real `jadx` CLI binary to decompile Android APK/DEX files.
///
/// Uses `tokio::process::Command` internally, so all heavy I/O is async and
/// non-blocking.
#[derive(Debug)]
pub struct CliJadxRunner {
    config: CliJadxConfig,
}

impl CliJadxRunner {
    /// Create a new runner from an explicit `CliJadxConfig`.
    #[must_use]
    pub const fn new(config: CliJadxConfig) -> Self {
        Self { config }
    }

    /// Search `PATH` for a `jadx` executable and return its full path.
    ///
    /// Uses `std::process::Command` with `--version` to confirm the binary is
    /// actually runnable, so this works correctly even when `PATH` contains
    /// stale symlinks.
    #[must_use]
    pub fn find_jadx_in_path() -> Option<PathBuf> {
        // Candidates: prefer "jadx", then "jadx-gui" (the GUI variant also
        // exposes the same CLI interface on most distributions).
        for candidate in &["jadx", "jadx-gui"] {
            let result = std::process::Command::new(candidate)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if result.is_ok_and(|s| s.success()) {
                // Resolve to the absolute path via `which`-style lookup through
                // the OS.  If that resolution fails we still return the bare
                // name so the OS can resolve it at exec time.
                if let Ok(p) = which_path(candidate) {
                    return Some(p);
                }
                return Some(PathBuf::from(candidate));
            }
        }
        None
    }

    /// Decompile an APK/DEX file into the given output directory (async).
    ///
    /// Builds the JADX command line from `self.config`, waits for the process
    /// to finish, then walks the output directory to collect all `.java` files
    /// and parse them into `JavaClass` values.
    ///
    /// # Errors
    ///
    /// Returns a `JadxError` if the JADX subprocess fails to spawn, exits with
    /// a non-zero status, or if the output directory cannot be walked.
    pub async fn decompile(
        &self,
        apk_path: &Path,
        output_dir: &Path,
    ) -> Result<DecompiledProject, JadxError> {
        use tokio::process::Command;

        let mut cmd = Command::new(&self.config.jadx_path);
        cmd.arg("--output-dir").arg(output_dir);

        if self.config.deobfuscate {
            cmd.arg("--deobf");
        }
        if self.config.show_inconsistent_code {
            cmd.arg("--show-bad-code");
        }
        if self.config.no_res {
            cmd.arg("--no-res");
        }

        cmd.arg(apk_path);

        let output = cmd.output().await.map_err(|e| {
            JadxError::Io(format!(
                "failed to spawn jadx at {}: {}",
                self.config.jadx_path.display(),
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(JadxError::Decompile(format!(
                "jadx exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        // Walk the output directory and collect *.java files.
        collect_java_sources(output_dir)
    }

    /// Decompile a single named class from an APK.
    ///
    /// JADX does not have a stable `--single-class` flag across versions, so
    /// we always perform a full decompile (into a temp dir when no explicit
    /// output dir is configured) and then extract the requested class.
    ///
    /// # Errors
    ///
    /// Returns a `JadxError` if the underlying full decompile fails or if the
    /// requested class is not present in the resulting output.
    pub async fn decompile_class(&self, apk: &Path, class_name: &str) -> Result<String, JadxError> {
        // Determine where output goes.  When no output dir is configured we
        // create a tempdir whose RAII guard is bound here so the directory
        // lives for the entire decompile call.
        let tmp_guard;
        let out_dir: PathBuf = if let Some(ref d) = self.config.output_dir {
            d.clone()
        } else {
            tmp_guard = tempfile::tempdir()
                .map_err(|e| JadxError::Io(format!("failed to create temp dir: {e}")))?;
            tmp_guard.path().to_path_buf()
        };

        let project = self.decompile(apk, &out_dir).await?;

        project
            .find_class(class_name)
            .map(|c| c.source.clone())
            .ok_or_else(|| {
                JadxError::NotFound(format!("class '{class_name}' not in decompiled output"))
            })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Portable `which`-style PATH lookup.  Returns the absolute path of the first
/// matching executable found on `PATH`.
fn which_path(name: &str) -> Result<PathBuf, ()> {
    let path_var = std::env::var_os("PATH").ok_or(())?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
        // On Windows executables may have an .exe or .bat extension.
        #[cfg(target_os = "windows")]
        {
            let with_exe = dir.join(format!("{name}.exe"));
            if with_exe.is_file() {
                return Ok(with_exe);
            }
            let with_bat = dir.join(format!("{name}.bat"));
            if with_bat.is_file() {
                return Ok(with_bat);
            }
        }
    }
    Err(())
}

/// Walk `dir` recursively and collect all `.java` files into a
/// `DecompiledProject`.  Files that cannot be parsed are counted as failures.
fn collect_java_sources(dir: &Path) -> Result<DecompiledProject, JadxError> {
    let mut classes = Vec::new();
    let mut failed: usize = 0;
    let mut total: usize = 0;

    collect_java_recursive(dir, dir, &mut classes, &mut failed, &mut total)?;

    Ok(DecompiledProject {
        classes,
        total,
        failed,
    })
}

const MAX_WALK_DEPTH: usize = 64;

fn collect_java_recursive(
    root: &Path,
    current: &Path,
    classes: &mut Vec<JavaClass>,
    failed: &mut usize,
    total: &mut usize,
) -> Result<(), JadxError> {
    collect_java_recursive_inner(root, current, classes, failed, total, 0)
}

fn collect_java_recursive_inner(
    root: &Path,
    current: &Path,
    classes: &mut Vec<JavaClass>,
    failed: &mut usize,
    total: &mut usize,
    depth: usize,
) -> Result<(), JadxError> {
    if depth > MAX_WALK_DEPTH {
        return Err(JadxError::Io(format!(
            "directory tree too deep (>{MAX_WALK_DEPTH} levels) at {}",
            current.display()
        )));
    }
    let entries = std::fs::read_dir(current)
        .map_err(|e| JadxError::Io(format!("read_dir {}: {e}", current.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| JadxError::Io(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            collect_java_recursive_inner(root, &path, classes, failed, total, depth + 1)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
            *total += 1;
            match parse_java_file(root, &path) {
                Ok(cls) => classes.push(cls),
                Err(_) => *failed += 1,
            }
        }
    }
    Ok(())
}

/// Minimal Java source parser that extracts package, class name, and the raw
/// source text.  Full method-level parsing is intentionally left as a future
/// concern; the `methods` vec is populated with stubs detected via simple
/// heuristics.
fn parse_java_file(root: &Path, path: &Path) -> Result<JavaClass, JadxError> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| JadxError::Io(format!("read {}: {e}", path.display())))?;

    // Derive package from directory structure relative to the sources root.
    // JADX emits `sources/<package path>/ClassName.java`.
    let package = derive_package_from_path(root, path);

    // Extract class name from the file name (strip `.java`).
    let class_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_owned();

    // Best-effort: extract package declaration from source to override the
    // path-derived one when they differ (e.g., inner classes, obfuscated
    // directory layouts).
    let package = extract_package_decl(&source).unwrap_or(package);

    // Extract super-class declaration from `extends Foo`.
    let super_class = extract_super_class(&source);

    // Extract methods with very lightweight heuristics.
    let methods = extract_methods_heuristic(&source);

    Ok(JavaClass {
        class_name,
        package,
        source,
        methods,
        super_class,
    })
}

fn derive_package_from_path(root: &Path, file: &Path) -> String {
    // Strip the root prefix to get the relative path.
    let rel = file
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/").replace('/', "."))
        .unwrap_or_default();
    // Remove a leading "sources." segment that JADX adds.
    rel.strip_prefix("sources.")
        .unwrap_or(rel.as_str())
        .to_owned()
}

fn extract_package_decl(source: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            let pkg = rest.trim_end_matches(';').trim();
            if !pkg.is_empty() {
                return Some(pkg.to_owned());
            }
        }
    }
    None
}

fn extract_super_class(source: &str) -> Option<String> {
    for line in source.lines() {
        if let Some(pos) = line.find("extends ") {
            let after = &line[pos + "extends ".len()..];
            let name: String = after
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
                .next()
                .unwrap_or("")
                .to_owned();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Very lightweight method extractor.  Detects lines of the form
/// `[modifiers] ReturnType methodName(` and builds stub `JavaMethod` values.
fn extract_methods_heuristic(source: &str) -> Vec<JavaMethod> {
    let mut methods = Vec::new();
    let modifier_keywords = [
        "public",
        "protected",
        "private",
        "static",
        "final",
        "abstract",
        "synchronized",
        "native",
        "default",
        "strictfp",
    ];

    for line in source.lines() {
        let trimmed = line.trim();
        // Skip blank lines, comments, annotations, and field declarations.
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('@')
        {
            continue;
        }

        // Check for opening paren — a rough proxy for a method declaration.
        if !trimmed.contains('(') {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        // Collect leading modifier tokens.
        let mut idx = 0;
        let mut is_static = false;
        let mut is_native = false;
        while idx < tokens.len() {
            let tok = tokens[idx].trim_start_matches('(');
            if modifier_keywords.contains(&tok) {
                if tok == "static" {
                    is_static = true;
                }
                if tok == "native" {
                    is_native = true;
                }
                idx += 1;
            } else {
                break;
            }
        }
        // Need at least return-type + name(
        if idx + 1 >= tokens.len() {
            continue;
        }
        let return_type = tokens[idx].to_owned();
        let name_token = tokens[idx + 1];
        // Name ends at `(`
        let name = name_token.split('(').next().unwrap_or("").to_owned();
        if name.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '<')
        {
            continue;
        }

        // Extract raw parameter text between the first `(` and the first `)` after it.
        let param_str = trimmed
            .find('(')
            .and_then(|s| {
                trimmed[s + 1..].find(')').map(|rel_e| &trimmed[s + 1..s + 1 + rel_e])
            })
            .unwrap_or("");
        let params: Vec<String> = if param_str.trim().is_empty() {
            vec![]
        } else {
            param_str
                .split(',')
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect()
        };

        let signature = format!("{}({})", name, params.join(", "));

        methods.push(JavaMethod {
            name,
            signature,
            return_type,
            params,
            body: String::new(),
            is_static,
            is_native,
        });
    }
    methods
}

// ─── DalvikMethod ─────────────────────────────────────────────────────────────

/// A minimal representation of a Dalvik method as a sequence of raw opcode
/// strings, suitable for the `NativeDexDecompiler`.
#[derive(Debug, Clone)]
pub struct DalvikMethod {
    pub name: String,
    pub class_name: String,
    pub return_type: String,
    pub params: Vec<String>,
    /// Raw Dalvik bytecode instructions, one per element (e.g.
    /// `"const/4 v0, #int 0"`).
    pub instructions: Vec<String>,
}

// ─── NativeDexDecompiler ─────────────────────────────────────────────────────

/// Fallback decompiler used when JADX is not installed.
///
/// Performs a best-effort stack-to-register conversion of Dalvik bytecode and
/// emits pseudo-Java for a limited set of opcodes.  Unrecognised opcodes are
/// emitted as comments prefixed with `// [native decompiler] `.
pub struct NativeDexDecompiler;

impl NativeDexDecompiler {
    /// Decompile a `DalvikMethod` into pseudo-Java source.
    ///
    /// Handles: `const`, `const/4`, `const/16`, `const-string`, `move`,
    /// `move-result`, `return`, `return-void`, `return-object`,
    /// `invoke-virtual`, `invoke-static`, `invoke-direct`, `invoke-interface`,
    /// `iget`, `iget-object`, `iput`, `iput-object`, `new-instance`,
    /// `array-length`, `aget`, `aput`, `goto`, `if-eq`, `if-ne`, `if-lt`,
    /// `if-ge`, `if-gt`, `if-le`.
    ///
    /// # Errors
    ///
    /// Returns a `JadxError` if any instruction in `method` cannot be
    /// recognised or emitted as pseudo-Java.
    pub fn decompile_method(method: &DalvikMethod) -> Result<String, JadxError> {
        let mut out = String::new();
        let indent = "    ";

        // Method signature comment.
        out.push_str("// Decompiled by NativeDexDecompiler (no JADX)\n");
        let _ = writeln!(out, "// {}.{}", method.class_name, method.name);

        let params = method.params.join(", ");
        let _ = writeln!(out, "{} {}({}) {{", method.return_type, method.name, params);

        let mut label_counter: usize = 0;

        for insn in &method.instructions {
            let insn = insn.trim();
            if insn.is_empty() || insn.starts_with("//") {
                let _ = writeln!(out, "{indent}// {insn}");
                continue;
            }

            let decoded = Self::decode_instruction(insn, &mut label_counter);
            let _ = writeln!(out, "{indent}{decoded}");
        }

        out.push_str("}\n");
        Ok(out)
    }

    fn decode_instruction(insn: &str, label_counter: &mut usize) -> String {
        // Split opcode from operands.
        let (opcode, rest) = insn
            .find(|c: char| c.is_whitespace())
            .map_or((insn, ""), |i| insn.split_at(i));
        let opcode = opcode.trim();
        let rest = rest.trim();

        // Split operands by comma.
        let ops: Vec<&str> = rest.split(',').map(str::trim).collect();

        if let Some(s) = Self::decode_const_or_move(opcode, &ops) {
            return s;
        }
        if let Some(s) = Self::decode_field_access(opcode, &ops) {
            return s;
        }
        if let Some(s) = Self::decode_invoke_or_return(opcode, &ops) {
            return s;
        }
        if let Some(s) = Self::decode_object_or_array(opcode, &ops) {
            return s;
        }
        if let Some(s) = Self::decode_arith_or_cast(opcode, &ops) {
            return s;
        }
        Self::decode_control_or_exception(opcode, &ops, insn, label_counter)
    }

    fn decode_invoke_or_return(opcode: &str, ops: &[&str]) -> Option<String> {
        let s = match opcode {
            // ── return family ─────────────────────────────────────────────────
            "return-void" => "return;".to_owned(),
            "return" | "return-wide" | "return-object" => {
                let val = ops.first().copied().unwrap_or("null");
                format!("return {val};")
            }

            // ── invoke family ─────────────────────────────────────────────────
            "invoke-virtual" | "invoke-virtual/range" => Self::format_invoke("virtual", ops),
            "invoke-static" | "invoke-static/range" => Self::format_invoke("static", ops),
            "invoke-direct" | "invoke-direct/range" => Self::format_invoke("direct", ops),
            "invoke-interface" | "invoke-interface/range" => Self::format_invoke("interface", ops),
            "invoke-super" | "invoke-super/range" => Self::format_invoke("super", ops),
            _ => return None,
        };
        Some(s)
    }

    fn decode_object_or_array(opcode: &str, ops: &[&str]) -> Option<String> {
        let s = match opcode {
            // ── object creation ───────────────────────────────────────────────
            "new-instance" => {
                let dest = ops.first().copied().unwrap_or("?");
                let cls = ops.get(1).copied().unwrap_or("?");
                format!("{dest} = new {cls}();  // new-instance (uninitialized)")
            }
            "new-array" => {
                let dest = ops.first().copied().unwrap_or("?");
                let size = ops.get(1).copied().unwrap_or("?");
                let ty = ops.get(2).copied().unwrap_or("?");
                format!("{dest} = new {ty}[{size}];  // new-array")
            }
            "filled-new-array" | "filled-new-array/range" => {
                let ty = ops.last().copied().unwrap_or("?");
                let elems: Vec<&str> = ops[..ops.len().saturating_sub(1)].to_vec();
                format!(
                    "_result = new {ty}{{ {} }};  // filled-new-array",
                    elems.join(", ")
                )
            }

            // ── array ops ─────────────────────────────────────────────────────
            "array-length" => {
                let dest = ops.first().copied().unwrap_or("?");
                let arr = ops.get(1).copied().unwrap_or("?");
                format!("{dest} = {arr}.length;  // array-length")
            }
            "aget" | "aget-wide" | "aget-object" | "aget-boolean" | "aget-byte" | "aget-char"
            | "aget-short" => {
                let dest = ops.first().copied().unwrap_or("?");
                let arr = ops.get(1).copied().unwrap_or("?");
                let idx = ops.get(2).copied().unwrap_or("?");
                format!("{dest} = {arr}[{idx}];  // aget")
            }
            "aput" | "aput-wide" | "aput-object" | "aput-boolean" | "aput-byte" | "aput-char"
            | "aput-short" => {
                let src = ops.first().copied().unwrap_or("?");
                let arr = ops.get(1).copied().unwrap_or("?");
                let idx = ops.get(2).copied().unwrap_or("?");
                format!("{arr}[{idx}] = {src};  // aput")
            }
            _ => return None,
        };
        Some(s)
    }

    fn decode_arith_or_cast(opcode: &str, ops: &[&str]) -> Option<String> {
        let s = match opcode {
            // ── arithmetic / logic ────────────────────────────────────────────
            "add-int" | "add-int/2addr" => Self::arith(ops, "+"),
            "sub-int" | "sub-int/2addr" => Self::arith(ops, "-"),
            "mul-int" | "mul-int/2addr" => Self::arith(ops, "*"),
            "div-int" | "div-int/2addr" => Self::arith(ops, "/"),
            "rem-int" | "rem-int/2addr" => Self::arith(ops, "%"),
            "and-int" | "and-int/2addr" => Self::arith(ops, "&"),
            "or-int" | "or-int/2addr" => Self::arith(ops, "|"),
            "xor-int" | "xor-int/2addr" => Self::arith(ops, "^"),
            "shl-int" | "shl-int/2addr" => Self::arith(ops, "<<"),
            "shr-int" | "shr-int/2addr" => Self::arith(ops, ">>"),
            "ushr-int" | "ushr-int/2addr" => Self::arith(ops, ">>>"),
            "neg-int" | "neg-long" | "neg-float" | "neg-double" => {
                let dest = ops.first().copied().unwrap_or("?");
                let src = ops.get(1).copied().unwrap_or("?");
                format!("{dest} = -{src};  // neg")
            }
            "not-int" | "not-long" => {
                let dest = ops.first().copied().unwrap_or("?");
                let src = ops.get(1).copied().unwrap_or("?");
                format!("{dest} = ~{src};  // not")
            }

            // ── cast / check ──────────────────────────────────────────────────
            "int-to-long" | "int-to-float" | "int-to-double" | "long-to-int" | "long-to-float"
            | "long-to-double" | "float-to-int" | "float-to-long" | "float-to-double"
            | "double-to-int" | "double-to-long" | "double-to-float" | "int-to-byte"
            | "int-to-char" | "int-to-short" => {
                let dest = ops.first().copied().unwrap_or("?");
                let src = ops.get(1).copied().unwrap_or("?");
                let cast_ty = opcode.rsplit('-').next().unwrap_or("?");
                format!("{dest} = ({cast_ty}) {src};  // {opcode}")
            }
            "check-cast" => {
                let reg = ops.first().copied().unwrap_or("?");
                let ty = ops.get(1).copied().unwrap_or("?");
                format!("{reg} = ({ty}) {reg};  // check-cast")
            }
            "instance-of" => {
                let dest = ops.first().copied().unwrap_or("?");
                let obj = ops.get(1).copied().unwrap_or("?");
                let ty = ops.get(2).copied().unwrap_or("?");
                format!("{dest} = ({obj} instanceof {ty});  // instance-of")
            }
            _ => return None,
        };
        Some(s)
    }

    fn decode_control_or_exception(
        opcode: &str,
        ops: &[&str],
        insn: &str,
        label_counter: &mut usize,
    ) -> String {
        match opcode {
            // ── control flow ──────────────────────────────────────────────────
            "goto" | "goto/16" | "goto/32" => {
                let target = ops.first().copied().unwrap_or("?");
                format!("goto label_{target};")
            }
            "if-eq" => Self::branch(ops, "==", label_counter),
            "if-ne" => Self::branch(ops, "!=", label_counter),
            "if-lt" => Self::branch(ops, "<", label_counter),
            "if-ge" => Self::branch(ops, ">=", label_counter),
            "if-gt" => Self::branch(ops, ">", label_counter),
            "if-le" => Self::branch(ops, "<=", label_counter),
            "if-eqz" => Self::branchz(ops, "== 0", label_counter),
            "if-nez" => Self::branchz(ops, "!= 0", label_counter),
            "if-ltz" => Self::branchz(ops, "< 0", label_counter),
            "if-gez" => Self::branchz(ops, ">= 0", label_counter),
            "if-gtz" => Self::branchz(ops, "> 0", label_counter),
            "if-lez" => Self::branchz(ops, "<= 0", label_counter),

            // ── exceptions ────────────────────────────────────────────────────
            "throw" => {
                let obj = ops.first().copied().unwrap_or("?");
                format!("throw {obj};")
            }
            "monitor-enter" => {
                let obj = ops.first().copied().unwrap_or("?");
                format!("synchronized ({obj}) {{  // monitor-enter")
            }
            "monitor-exit" => {
                let obj = ops.first().copied().unwrap_or("?");
                format!("}}  // monitor-exit ({obj})")
            }

            // ── nop ───────────────────────────────────────────────────────────
            "nop" => ";  // nop".to_owned(),

            // ── fallback ──────────────────────────────────────────────────────
            _ => format!("// [native decompiler] unhandled opcode: {insn}"),
        }
    }

    fn decode_const_or_move(opcode: &str, ops: &[&str]) -> Option<String> {
        match opcode {
            "const/4" | "const/16" | "const" | "const-wide" | "const-wide/16" | "const-wide/32"
            | "const-wide/high16" | "const/high16" => {
                let dest = ops.first().copied().unwrap_or("?");
                let val = ops.get(1).copied().unwrap_or("0");
                Some(format!("{dest} = {val};  // const"))
            }
            "const-string" | "const-string/jumbo" => {
                let dest = ops.first().copied().unwrap_or("?");
                let val = ops.get(1).copied().unwrap_or("\"\"");
                Some(format!("{dest} = {val};  // const-string"))
            }
            "const-class" => {
                let dest = ops.first().copied().unwrap_or("?");
                let cls = ops.get(1).copied().unwrap_or("?");
                Some(format!("{dest} = {cls}.class;  // const-class"))
            }
            "move" | "move/from16" | "move/16" | "move-wide" | "move-wide/from16"
            | "move-wide/16" | "move-object" | "move-object/from16" | "move-object/16" => {
                let dest = ops.first().copied().unwrap_or("?");
                let src = ops.get(1).copied().unwrap_or("?");
                Some(format!("{dest} = {src};  // move"))
            }
            "move-result" | "move-result-wide" | "move-result-object" | "move-exception" => {
                let dest = ops.first().copied().unwrap_or("?");
                Some(format!("{dest} = _result;  // {opcode}"))
            }
            _ => None,
        }
    }

    fn decode_field_access(opcode: &str, ops: &[&str]) -> Option<String> {
        match opcode {
            "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-byte" | "iget-char"
            | "iget-short" => {
                let dest = ops.first().copied().unwrap_or("?");
                let obj = ops.get(1).copied().unwrap_or("?");
                let field = ops.get(2).copied().unwrap_or("?");
                Some(format!("{dest} = {obj}.{field};  // iget"))
            }
            "iput" | "iput-wide" | "iput-object" | "iput-boolean" | "iput-byte" | "iput-char"
            | "iput-short" => {
                let src = ops.first().copied().unwrap_or("?");
                let obj = ops.get(1).copied().unwrap_or("?");
                let field = ops.get(2).copied().unwrap_or("?");
                Some(format!("{obj}.{field} = {src};  // iput"))
            }
            "sget" | "sget-wide" | "sget-object" | "sget-boolean" | "sget-byte" | "sget-char"
            | "sget-short" => {
                let dest = ops.first().copied().unwrap_or("?");
                let field = ops.get(1).copied().unwrap_or("?");
                Some(format!("{dest} = {field};  // sget"))
            }
            "sput" | "sput-wide" | "sput-object" | "sput-boolean" | "sput-byte" | "sput-char"
            | "sput-short" => {
                let src = ops.first().copied().unwrap_or("?");
                let field = ops.get(1).copied().unwrap_or("?");
                Some(format!("{field} = {src};  // sput"))
            }
            _ => None,
        }
    }

    fn format_invoke(kind: &str, ops: &[&str]) -> String {
        // JADX-style: {v0, v1}, ClassName->method(Params)RetType
        // We keep it readable.
        let method_ref = ops.last().copied().unwrap_or("?");
        let arg_regs: Vec<&str> = if ops.len() > 1 {
            ops[..ops.len() - 1].to_vec()
        } else {
            vec![]
        };
        let args = arg_regs.join(", ");
        format!("_result = {method_ref}({args});  // invoke-{kind}")
    }

    fn arith(ops: &[&str], op: &str) -> String {
        let dest = ops.first().copied().unwrap_or("?");
        let a = ops.get(1).copied().unwrap_or("?");
        let b = ops.get(2).copied().unwrap_or(a); // 2addr form
        format!("{dest} = {a} {op} {b};")
    }

    fn branch(ops: &[&str], cmp: &str, counter: &mut usize) -> String {
        let a = ops.first().copied().unwrap_or("?");
        let b = ops.get(1).copied().unwrap_or("?");
        let target = ops.get(2).copied().unwrap_or("?");
        *counter += 1;
        format!("if ({a} {cmp} {b}) goto label_{target};  // branch #{counter}")
    }

    fn branchz(ops: &[&str], cmp: &str, counter: &mut usize) -> String {
        let a = ops.first().copied().unwrap_or("?");
        let target = ops.get(1).copied().unwrap_or("?");
        *counter += 1;
        format!("if ({a} {cmp}) goto label_{target};  // branch #{counter}")
    }
}

// ─── Top-level convenience function ──────────────────────────────────────────

/// Decompile an APK, trying `CliJadxRunner` first and falling back to
/// `NativeDexDecompiler` when JADX is not available.
///
/// Returns a `DecompiledProject`.  In the fallback path the project will
/// contain a single synthetic class carrying stub source generated by
/// `NativeDexDecompiler`.
///
/// # Errors
///
/// Returns a `JadxError` if the underlying JADX runner fails or, in the
/// fallback path, if reading the APK / lifting DEX instructions fails.
pub async fn decompile_apk(
    apk_path: &Path,
    output_dir: &Path,
) -> Result<DecompiledProject, JadxError> {
    // Try the real JADX runner first.
    if CliJadxRunner::find_jadx_in_path().is_some() {
        let runner = CliJadxRunner::new(CliJadxConfig::default());
        return runner.decompile(apk_path, output_dir).await;
    }

    // Fallback: best-effort native decompiler on Dalvik bytecode.
    // We cannot actually parse a real APK without JADX here, so we emit a
    // single stub class that documents the situation.
    let stub_method = DalvikMethod {
        name: "stub".to_owned(),
        class_name: "StubClass".to_owned(),
        return_type: "void".to_owned(),
        params: vec![],
        instructions: vec![
            format!("// APK: {}", apk_path.display()),
            "// JADX not found — native fallback active".to_owned(),
            "return-void".to_owned(),
        ],
    };

    let source = NativeDexDecompiler::decompile_method(&stub_method)?;

    let cls = JavaClass {
        class_name: "StubClass".to_owned(),
        package: "com.rustre.fallback".to_owned(),
        source,
        methods: vec![],
        super_class: None,
    };

    Ok(DecompiledProject {
        total: 1,
        failed: 0,
        classes: vec![cls],
    })
}

// ─── find_jadx ────────────────────────────────────────────────────────────────

/// Locate the `jadx` binary using three strategies, in order:
///
/// 1. `JADX_PATH` environment variable (exact path to the binary).
/// 2. `PATH` search — tries `jadx` and `jadx.bat`; confirms the binary is
///    runnable by invoking `--version`.
/// 3. A small set of well-known installation prefixes on Linux, macOS and
///    Windows.
///
/// Returns `None` if none of the strategies succeed.
#[must_use]
pub fn find_jadx() -> Option<PathBuf> {
    // Strategy 1: explicit env var.
    if let Ok(val) = std::env::var("JADX_PATH") {
        let p = PathBuf::from(val);
        if p.is_file() {
            return Some(p);
        }
    }

    // Strategy 2: look on PATH using the probe-by-execution technique that
    // `CliJadxRunner::find_jadx_in_path` already implements.  We extend it
    // here to also probe `jadx.bat` for Windows environments where the
    // wrapper script has that name.
    let path_candidates: &[&str] = if cfg!(windows) {
        &["jadx", "jadx.bat", "jadx-gui", "jadx-gui.bat"]
    } else {
        &["jadx", "jadx-gui"]
    };

    for candidate in path_candidates {
        let ok = std::process::Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());

        if ok {
            // Try to resolve to an absolute path; fall back to the bare name.
            if let Ok(abs) = which_path(candidate) {
                return Some(abs);
            }
            return Some(PathBuf::from(candidate));
        }
    }

    // Strategy 3: hard-coded common install locations.
    let common: &[&str] = &[
        // Linux / macOS
        "/usr/local/bin/jadx",
        "/usr/bin/jadx",
        "/opt/jadx/bin/jadx",
        "/opt/homebrew/bin/jadx",
        // Windows
        r"C:\jadx\bin\jadx.bat",
        r"C:\Program Files\jadx\bin\jadx.bat",
        r"C:\Program Files (x86)\jadx\bin\jadx.bat",
        r"C:\tools\jadx\bin\jadx.bat",
    ];

    for path_str in common {
        let p = PathBuf::from(path_str);
        if p.is_file() {
            return Some(p);
        }
    }

    None
}

// ─── CliJadxRunner2 (new API) ─────────────────────────────────────────────────

/// A real JADX CLI runner with a simpler, flat configuration struct.
///
/// Unlike the original `CliJadxRunner` (which stores a full `CliJadxConfig`),
/// this variant stores only the binary path and a per-run timeout so that it
/// can be constructed ergonomically via [`CliJadxRunner2::new`].
///
/// The name is `CliJadxRunner2` to avoid a collision with the pre-existing
/// `CliJadxRunner` type while keeping all legacy types intact.
#[derive(Debug, Clone)]
pub struct CliJadxRunner2 {
    /// Absolute (or PATH-relative) path to the `jadx` binary.
    pub jadx_path: PathBuf,
    /// Maximum wall-clock seconds to wait for the JADX process.
    /// `0` means no timeout.
    pub timeout_secs: u64,
}

impl CliJadxRunner2 {
    /// Attempt to locate JADX automatically using [`find_jadx`].
    ///
    /// Returns an error when JADX cannot be found.
    ///
    /// # Errors
    ///
    /// Returns an error if the JADX binary cannot be located on `PATH` or
    /// via the `JADX_PATH` environment variable.
    pub fn new() -> anyhow::Result<Self> {
        let path = find_jadx().ok_or_else(|| {
            anyhow::anyhow!(
                "JADX binary not found. Install JADX and ensure it is on PATH, \
                 or set the JADX_PATH environment variable."
            )
        })?;
        Ok(Self {
            jadx_path: path,
            timeout_secs: 120,
        })
    }

    /// Build a runner from an explicit binary path.  No existence check is
    /// performed here; the error surfaces when the process is first spawned.
    #[must_use]
    pub const fn with_path(path: PathBuf) -> Self {
        Self {
            jadx_path: path,
            timeout_secs: 120,
        }
    }

    /// Override the default timeout (120 s).
    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    // ── async helpers ──────────────────────────────────────────────────────

    /// Decompile `apk_path` into `output_dir` using the JADX CLI.
    ///
    /// Passes `--no-res` to skip resource decoding and keep the output
    /// directory small.  All stdout/stderr output is captured; a non-zero
    /// exit code is turned into a [`JadxError::Decompile`].
    ///
    /// # Errors
    ///
    /// Returns an error if either path is not valid UTF-8, the JADX child
    /// process cannot be spawned, the configured timeout elapses, or JADX
    /// exits with a non-zero status.
    pub async fn decompile_apk(&self, apk_path: &Path, output_dir: &Path) -> anyhow::Result<()> {
        use tokio::process::Command;

        let apk_str = apk_path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "APK path contains non-UTF-8 characters: {}",
                apk_path.display()
            )
        })?;
        let out_str = output_dir.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Output dir contains non-UTF-8 characters: {}",
                output_dir.display()
            )
        })?;

        let mut cmd = Command::new(&self.jadx_path);
        cmd.args(["--output-dir", out_str, "--no-res", apk_str]);

        // Redirect output so we can inspect it on failure.
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let child_future = cmd.output();

        // Apply optional timeout.
        let output = if self.timeout_secs > 0 {
            tokio::time::timeout(
                std::time::Duration::from_secs(self.timeout_secs),
                child_future,
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "JADX timed out after {} seconds while decompiling {}",
                    self.timeout_secs,
                    apk_path.display()
                )
            })??
        } else {
            child_future.await?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Surface the most informative snippet available.
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_owned()
            } else if !stdout.trim().is_empty() {
                stdout.trim().to_owned()
            } else {
                format!("exit code {}", output.status)
            };

            anyhow::bail!(
                "JADX exited with non-zero status while processing {}: {detail}",
                apk_path.display()
            );
        }

        Ok(())
    }

    /// Read the Java source for a single class from a previously decompiled
    /// output directory.
    ///
    /// `class_name` must be the fully-qualified class name using dot notation,
    /// e.g. `"com.example.Foo"`.  The method maps it to
    /// `<output_dir>/sources/com/example/Foo.java`.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolved `.java` file cannot be read from disk.
    pub fn read_decompiled_class(output_dir: &Path, class_name: &str) -> anyhow::Result<String> {
        // "com.example.Foo" → "com/example/Foo.java"
        let rel_path: PathBuf = class_name
            .replace('.', std::path::MAIN_SEPARATOR_STR)
            .into();
        let java_file = output_dir
            .join("sources")
            .join(rel_path)
            .with_extension("java");

        std::fs::read_to_string(&java_file).map_err(|e| {
            anyhow::anyhow!(
                "Could not read decompiled class '{class_name}' from {}: {e}",
                java_file.display()
            )
        })
    }

    /// Decompile `apk` and return the source of a single class.
    ///
    /// The full decompile runs into a temporary directory that is cleaned up
    /// when this function returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the temp directory cannot be created, the full
    /// decompile fails, or the requested class is not present in the output.
    pub async fn decompile_class(&self, apk: &Path, class_name: &str) -> anyhow::Result<String> {
        let tmp =
            tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {e}"))?;

        self.decompile_apk(apk, tmp.path()).await?;

        Self::read_decompiled_class(tmp.path(), class_name)
    }
}

// ─── DalvikOpcode ────────────────────────────────────────────────────────────

/// The 20 most common Dalvik opcodes, used by [`NativeDexLifter`].
///
/// This enum is intentionally kept to the opcodes explicitly requested by the
/// task specification.  Unknown/uncommon opcodes should be represented as
/// raw bytes and lifted via the [`NativeDexLifter::lift_instruction`] fallback
/// branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DalvikOpcode {
    /// `0x0e` — `return-void`
    ReturnVoid = 0x0e,
    /// `0x0f` — `return vX`
    Return = 0x0f,
    /// `0x12` — `const/4 vX, #+Y`
    Const4 = 0x12,
    /// `0x1a` — `const-string vX, string@CCCC`
    ConstString = 0x1a,
    /// `0x54` — `iget vX, vY, field@CCCC`
    Iget = 0x54,
    /// `0x59` — `iput vX, vY, field@CCCC`
    Iput = 0x59,
    /// `0x6e` — `invoke-virtual {vC..vG}, meth@BBBB`
    InvokeVirtual = 0x6e,
    /// `0x70` — `invoke-direct {vC..vG}, meth@BBBB`
    InvokeDirect = 0x70,
    /// `0x71` — `invoke-static {vC..vG}, meth@BBBB`
    InvokeStatic = 0x71,
    /// `0x0a` — `move-result vX`
    MoveResult = 0x0a,
    /// `0x90` — `add-int vAA, vBB, vCC`
    AddInt = 0x90,
    /// `0x91` — `sub-int vAA, vBB, vCC`
    SubInt = 0x91,
    /// `0x92` — `mul-int vAA, vBB, vCC`
    MulInt = 0x92,
    /// `0x32` — `if-eq vA, vB, +CCCC`
    IfEq = 0x32,
    /// `0x33` — `if-ne vA, vB, +CCCC`
    IfNe = 0x33,
    /// `0x34` — `if-lt vA, vB, +CCCC`
    IfLt = 0x34,
    /// `0x35` — `if-ge vA, vB, +CCCC`
    IfGe = 0x35,
    /// `0x36` — `if-gt vA, vB, +CCCC`
    IfGt = 0x36,
    /// `0x37` — `if-le vA, vB, +CCCC`
    IfLe = 0x37,
    /// `0x28` — `goto +AA`
    Goto = 0x28,
    /// `0x22` — `new-instance vAA, type@BBBB`
    NewInstance = 0x22,
}

impl DalvikOpcode {
    /// Try to parse a raw byte into a known `DalvikOpcode`.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x0e => Some(Self::ReturnVoid),
            0x0f => Some(Self::Return),
            0x12 => Some(Self::Const4),
            0x1a => Some(Self::ConstString),
            0x54 => Some(Self::Iget),
            0x59 => Some(Self::Iput),
            0x6e => Some(Self::InvokeVirtual),
            0x70 => Some(Self::InvokeDirect),
            0x71 => Some(Self::InvokeStatic),
            0x0a => Some(Self::MoveResult),
            0x90 => Some(Self::AddInt),
            0x91 => Some(Self::SubInt),
            0x92 => Some(Self::MulInt),
            0x32 => Some(Self::IfEq),
            0x33 => Some(Self::IfNe),
            0x34 => Some(Self::IfLt),
            0x35 => Some(Self::IfGe),
            0x36 => Some(Self::IfGt),
            0x37 => Some(Self::IfLe),
            0x28 => Some(Self::Goto),
            0x22 => Some(Self::NewInstance),
            _ => None,
        }
    }

    /// Return the canonical mnemonic string for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::ReturnVoid => "return-void",
            Self::Return => "return",
            Self::Const4 => "const/4",
            Self::ConstString => "const-string",
            Self::Iget => "iget",
            Self::Iput => "iput",
            Self::InvokeVirtual => "invoke-virtual",
            Self::InvokeDirect => "invoke-direct",
            Self::InvokeStatic => "invoke-static",
            Self::MoveResult => "move-result",
            Self::AddInt => "add-int",
            Self::SubInt => "sub-int",
            Self::MulInt => "mul-int",
            Self::IfEq => "if-eq",
            Self::IfNe => "if-ne",
            Self::IfLt => "if-lt",
            Self::IfGe => "if-ge",
            Self::IfGt => "if-gt",
            Self::IfLe => "if-le",
            Self::Goto => "goto",
            Self::NewInstance => "new-instance",
        }
    }
}

// ─── NativeDexLifter ─────────────────────────────────────────────────────────

/// A register-machine instruction lifter for a subset of Dalvik bytecode.
///
/// This is a *basic* fallback that does not require JADX.  It operates on
/// raw byte-level operands (register indices in `regs`, arbitrary auxiliary
/// data in `payload`) and produces a single pseudo-Java statement string.
///
/// Only the 20 opcodes enumerated in [`DalvikOpcode`] are handled with
/// semantic output; all other byte values produce a diagnostic comment.
pub struct NativeDexLifter;

impl NativeDexLifter {
    /// Lift a single Dalvik instruction to a pseudo-Java statement.
    ///
    /// # Parameters
    /// * `op`      — the decoded opcode
    /// * `regs`    — register operands (content depends on opcode format)
    /// * `payload` — auxiliary bytes (e.g. string literal, type name,
    ///   field descriptor, branch offset encoded as little-endian)
    ///
    /// # Return value
    /// A self-contained statement string (including trailing `;` or `{}`)
    /// suitable for inclusion in a pseudo-Java method body.
    ///
    /// # Examples
    /// ```
    /// use rustre_mobile_jadx::{NativeDexLifter, DalvikOpcode};
    ///
    /// let s = NativeDexLifter::lift_instruction(DalvikOpcode::ReturnVoid, &[], &[]);
    /// assert_eq!(s, "return;");
    ///
    /// let s = NativeDexLifter::lift_instruction(DalvikOpcode::Const4, &[0], &[5]);
    /// assert_eq!(s, "v0 = 5;");
    /// ```
    #[must_use]
    pub fn lift_instruction(op: DalvikOpcode, regs: &[u8], payload: &[u8]) -> String {
        /// Format a register name: `v<index>`.
        fn reg(regs: &[u8], idx: usize) -> String {
            regs.get(idx)
                .map_or_else(|| "v?".to_owned(), |r| format!("v{r}"))
        }

        /// Interpret the first 1-2 payload bytes as a signed 16-bit immediate.
        fn payload_imm(payload: &[u8]) -> i32 {
            match payload.len() {
                0 => 0,
                1 => i32::from(payload[0].cast_signed()),
                _ => i32::from(i16::from_le_bytes([payload[0], payload[1]])),
            }
        }

        /// Decode payload as a UTF-8 string (best-effort).
        fn payload_str(payload: &[u8]) -> String {
            String::from_utf8_lossy(payload).into_owned()
        }

        match op {
            // ── return family ─────────────────────────────────────────────
            DalvikOpcode::ReturnVoid => "return;".to_owned(),

            DalvikOpcode::Return => {
                format!("return {};", reg(regs, 0))
            }

            // ── const family ──────────────────────────────────────────────
            DalvikOpcode::Const4 => {
                let val = payload_imm(payload);
                format!("{} = {};", reg(regs, 0), val)
            }

            DalvikOpcode::ConstString => {
                let s = payload_str(payload);
                format!(r#"{} = "{}";"#, reg(regs, 0), s.escape_default())
            }

            // ── field access ──────────────────────────────────────────────
            DalvikOpcode::Iget => {
                let field = payload_str(payload);
                let field_name = field
                    .split("->")
                    .nth(1)
                    .and_then(|s| s.split(':').next())
                    .unwrap_or(&field);
                format!("{} = {}.{};", reg(regs, 0), reg(regs, 1), field_name)
            }

            DalvikOpcode::Iput => {
                let field = payload_str(payload);
                let field_name = field
                    .split("->")
                    .nth(1)
                    .and_then(|s| s.split(':').next())
                    .unwrap_or(&field);
                format!("{}.{} = {};", reg(regs, 1), field_name, reg(regs, 0))
            }

            // ── invoke family ─────────────────────────────────────────────
            DalvikOpcode::InvokeVirtual => Self::lift_invoke("virtual", regs, payload),
            DalvikOpcode::InvokeDirect => Self::lift_invoke("direct", regs, payload),
            DalvikOpcode::InvokeStatic => Self::lift_invoke("static", regs, payload),

            // ── move-result ───────────────────────────────────────────────
            DalvikOpcode::MoveResult => {
                format!("{} = _result;", reg(regs, 0))
            }

            // ── arithmetic ────────────────────────────────────────────────
            DalvikOpcode::AddInt => {
                format!("{} = {} + {};", reg(regs, 0), reg(regs, 1), reg(regs, 2))
            }
            DalvikOpcode::SubInt => {
                format!("{} = {} - {};", reg(regs, 0), reg(regs, 1), reg(regs, 2))
            }
            DalvikOpcode::MulInt => {
                format!("{} = {} * {};", reg(regs, 0), reg(regs, 1), reg(regs, 2))
            }

            // ── conditional branches ──────────────────────────────────────
            DalvikOpcode::IfEq => Self::lift_branch("==", regs, payload),
            DalvikOpcode::IfNe => Self::lift_branch("!=", regs, payload),
            DalvikOpcode::IfLt => Self::lift_branch("<", regs, payload),
            DalvikOpcode::IfGe => Self::lift_branch(">=", regs, payload),
            DalvikOpcode::IfGt => Self::lift_branch(">", regs, payload),
            DalvikOpcode::IfLe => Self::lift_branch("<=", regs, payload),

            // ── unconditional branch ──────────────────────────────────────
            DalvikOpcode::Goto => {
                let offset = payload_imm(payload);
                format!("goto label_{offset:+};")
            }

            // ── object creation ───────────────────────────────────────────
            DalvikOpcode::NewInstance => {
                let cls = payload_str(payload);
                // Strip leading 'L' and trailing ';' from Dalvik type
                // descriptor if present, and convert '/' to '.'.
                // Strip the marker exactly once: `trim_start_matches` repeats
                // and would eat the first letter of e.g. `LList;`.
                let cls_clean = cls.strip_prefix('L').unwrap_or(&cls);
                let cls_clean = cls_clean
                    .strip_suffix(';')
                    .unwrap_or(cls_clean)
                    .replace('/', ".");
                format!("{} = new {}();", reg(regs, 0), cls_clean)
            }
        }
    }

    // ── private helpers ────────────────────────────────────────────────────

    fn lift_invoke(kind: &str, regs: &[u8], payload: &[u8]) -> String {
        let method_ref = String::from_utf8_lossy(payload).into_owned();
        let arg_list: Vec<String> = regs.iter().map(|r| format!("v{r}")).collect();
        let args = arg_list.join(", ");
        format!("/* invoke-{kind} */ _result = {method_ref}({args});")
    }

    fn lift_branch(cmp: &str, regs: &[u8], payload: &[u8]) -> String {
        let offset = {
            let raw: i32 = match payload.len() {
                0 => 0,
                1 => i32::from(payload[0].cast_signed()),
                _ => i32::from(i16::from_le_bytes([payload[0], payload[1]])),
            };
            raw
        };
        let a = regs
            .first()
            .map_or_else(|| "v?".to_owned(), |r| format!("v{r}"));
        let b = regs
            .get(1)
            .map_or_else(|| "v?".to_owned(), |r| format!("v{r}"));
        format!("if ({a} {cmp} {b}) goto label_{offset:+};")
    }

    /// Convenience wrapper: lift a raw byte opcode, falling back to a comment
    /// for unrecognised opcodes.
    #[must_use]
    pub fn lift_raw(opcode_byte: u8, regs: &[u8], payload: &[u8]) -> String {
        DalvikOpcode::from_byte(opcode_byte).map_or_else(
            || format!("// [NativeDexLifter] unknown opcode 0x{opcode_byte:02x}"),
            |op| Self::lift_instruction(op, regs, payload),
        )
    }
}

// ─── ClassSource ─────────────────────────────────────────────────────────────

/// A single class lifted by the native fallback path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSource {
    /// Fully-qualified class name (dot notation).
    pub class_name: String,
    /// Pseudo-Java source produced by [`NativeDexLifter`].
    pub source: String,
}

// ─── DecompileResult ─────────────────────────────────────────────────────────

/// Outcome of [`decompile_apk_auto`].
///
/// * `Jadx` — JADX was available; the variant carries the output directory
///   path.  Use [`CliJadxRunner2::read_decompiled_class`] or just walk the
///   directory yourself.
/// * `Native` — JADX was *not* available; the variant carries a (possibly
///   empty) list of [`ClassSource`] values produced by [`NativeDexLifter`]
///   from whatever DEX-level data could be extracted from the APK.
#[derive(Debug)]
pub enum DecompileResult {
    /// Successful JADX decompilation; output is in this directory.
    Jadx(PathBuf),
    /// JADX not found; best-effort native lift results.
    Native(Vec<ClassSource>),
}

// ─── decompile_apk_auto ───────────────────────────────────────────────────────

/// Try JADX first, fall back to [`NativeDexLifter`] when JADX is absent.
///
/// * If JADX is found the APK is decompiled into `output_dir` and a
///   `DecompileResult::Jadx(output_dir.to_path_buf())` is returned.
/// * If JADX is not installed this function falls back to a lightweight
///   native path: it reads the APK as a ZIP archive, extracts each
///   `classes*.dex` file, and lifts a stub `ClassSource` per DEX file using
///   [`NativeDexLifter`].  No actual DEX bytecode parser is included here;
///   the stubs document that the APK was inspected and JADX was unavailable.
///
/// # Errors
///
/// Returns an error if neither the JADX path nor the native fallback can
/// produce output (e.g. unreadable APK, broken ZIP, JADX execution failure).
pub fn decompile_apk_auto(apk: &Path, output_dir: &Path) -> anyhow::Result<DecompileResult> {
    // ── Try JADX ──────────────────────────────────────────────────────────
    if let Some(jadx_path) = find_jadx() {
        let runner = CliJadxRunner2::with_path(jadx_path);

        // We need a synchronous surface here.  If we're already inside a Tokio
        // runtime (e.g. an MCP handler), block_in_place delegates to the
        // existing runtime without spawning a nested one and avoids the
        // "Cannot start a runtime from within a runtime" panic.
        // When there is no active runtime at all, fall back to a fresh one.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tokio::task::block_in_place(|| {
                    handle.block_on(runner.decompile_apk(apk, output_dir))
                })?;
            }
            Err(_) => {
                tokio::runtime::Runtime::new()
                    .map_err(|e| anyhow::anyhow!("Failed to create Tokio runtime: {e}"))?
                    .block_on(runner.decompile_apk(apk, output_dir))?;
            }
        }

        return Ok(DecompileResult::Jadx(output_dir.to_path_buf()));
    }

    // ── Fallback: native ZIP inspection + NativeDexLifter stubs ───────────
    let native_sources = native_fallback_lift(apk)?;
    Ok(DecompileResult::Native(native_sources))
}

/// Extract DEX entry names from the APK ZIP and produce lifted stub sources.
fn native_fallback_lift(apk: &Path) -> anyhow::Result<Vec<ClassSource>> {
    use std::io::Read;

    let file = std::fs::File::open(apk)
        .map_err(|e| anyhow::anyhow!("Cannot open APK {}: {e}", apk.display()))?;

    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| anyhow::anyhow!("APK is not a valid ZIP file: {e}"))?;

    let mut sources: Vec<ClassSource> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| anyhow::anyhow!("ZIP entry {i} error: {e}"))?;

        let name = entry.name().to_owned();

        // Only process DEX files inside the APK.
        if !std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"))
        {
            continue;
        }

        // Read the first 8 bytes to confirm the DEX magic and get the version.
        let mut header = [0u8; 8];
        let read_n = entry.read(&mut header)
            .map_err(|e| anyhow::anyhow!("Failed to read DEX header for {name}: {e}"))?;

        let dex_version = if read_n >= 8 && &header[..4] == b"dex\n" {
            String::from_utf8_lossy(&header[4..7]).into_owned()
        } else {
            "???".to_owned()
        };

        // Produce a lifted stub — we don't implement a full DEX parser here,
        // but we document what was found so the caller gets actionable output.
        let stub_regs: &[u8] = &[];
        let stub_payload = format!("/* {name} dex-version={dex_version} */");
        let stub_insn = NativeDexLifter::lift_instruction(
            DalvikOpcode::ReturnVoid,
            stub_regs,
            stub_payload.as_bytes(),
        );

        // Build a minimal pseudo-Java class stub.
        let class_name = name.trim_end_matches(".dex").replace('/', ".");

        let source = format!(
            "// NativeDexLifter fallback — JADX not found\n\
             // APK: {apk_display}\n\
             // DEX entry: {name} (version {dex_version})\n\
             //\n\
             // Install JADX for a full decompilation.\n\
             //\n\
             class {class_name} {{\n\
             \n\
             \t/* lifted from {name} */\n\
             \tvoid _stub_entry_point() {{\n\
             \t\t{stub_insn}\n\
             \t}}\n\
             }}\n",
            apk_display = apk.display(),
        );

        sources.push(ClassSource { class_name, source });
    }

    if sources.is_empty() {
        // APK did not contain any DEX file.  Produce a single diagnostic stub.
        let source = format!(
            "// NativeDexLifter fallback — no DEX entries found in APK {}\n\
             // The file may be a resource-only APK or may not be a valid APK.\n",
            apk.display()
        );
        sources.push(ClassSource {
            class_name: "com.rustre.fallback.EmptyApk".to_owned(),
            source,
        });
    }

    Ok(sources)
}

// ─── JadxDecompilerConfig ─────────────────────────────────────────────────────

/// Fine-grained decompiler options for JADX.
///
/// Unlike the legacy `JadxConfig` (which focuses on runtime invocation), this
/// struct captures decompiler-level feature flags that influence output quality
/// and readability.  It can be serialised to / deserialised from JSON for
/// project-level config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxDecompilerConfig {
    /// Emit line comments in the decompiled output.
    pub show_comments: bool,
    /// Emit `import` statements rather than fully-qualified type names.
    pub use_imports: bool,
    /// Enable the deobfuscation pass (rename short/obfuscated identifiers).
    pub deobf_enable: bool,
    /// Minimum identifier length that triggers deobfuscation renaming.
    pub deobf_min_len: u32,
}

impl Default for JadxDecompilerConfig {
    fn default() -> Self {
        Self {
            show_comments: true,
            use_imports: true,
            deobf_enable: false,
            deobf_min_len: 3,
        }
    }
}

impl JadxDecompilerConfig {
    /// Create a config with all features enabled and default deobf threshold.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            show_comments: true,
            use_imports: true,
            deobf_enable: true,
            deobf_min_len: 3,
        }
    }

    /// Serialise to a JSON string.
    ///
    /// # Errors
    /// Returns `Err` if JSON serialisation fails (should not happen for this
    /// type in practice).
    pub fn to_json(&self) -> Result<String, JadxError> {
        serde_json::to_string_pretty(self).map_err(|e| JadxError::Parse(e.to_string()))
    }

    /// Deserialise from a JSON string.
    ///
    /// # Errors
    /// Returns `Err` if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, JadxError> {
        serde_json::from_str(json).map_err(|e| JadxError::Parse(e.to_string()))
    }
}

// ─── JadxClass ────────────────────────────────────────────────────────────────

/// A class as extracted from JADX decompilation output.
///
/// `JadxClass` is a lightweight text-level representation.  It is distinct
/// from `JavaClass` (which carries full method bodies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxClass {
    /// Java package name (e.g. `com.example.app`).
    pub package: String,
    /// Simple class name (e.g. `MainActivity`).
    pub name: String,
    /// Method signatures found by heuristic scanning (e.g.
    /// `"public void onCreate(Bundle)"`).
    pub methods: Vec<String>,
    /// Field declarations found by heuristic scanning (e.g.
    /// `"private TextView tvTitle"`).
    pub fields: Vec<String>,
}

// ─── JadxResultProcessor ──────────────────────────────────────────────────────

/// Processes JADX decompilation output text to extract high-level metadata.
pub struct JadxResultProcessor;

impl JadxResultProcessor {
    /// Parse a single Java source text produced by JADX and return a
    /// `JadxClass` with package, class name, method signatures, and field
    /// declarations.
    ///
    /// The parser uses heuristics rather than a full Java grammar, which is
    /// appropriate for analysis workloads where exact AST fidelity is
    /// secondary to speed.
    #[must_use]
    pub fn parse_class_output(java_text: &str) -> JadxClass {
        let package = extract_package_decl(java_text).unwrap_or_else(|| "unknown".to_string());

        // Find class name from "class Foo" or "interface Foo" or "enum Foo"
        let name = Self::extract_class_name(java_text).unwrap_or_else(|| "Unknown".to_string());

        let methods = Self::extract_method_signatures(java_text);
        let fields = Self::extract_field_declarations(java_text);

        JadxClass {
            package,
            name,
            methods,
            fields,
        }
    }

    /// Extract all string literals from `java_text`.
    ///
    /// Returns each distinct string value (without surrounding quotes) in
    /// document order.  Duplicate literals are preserved.
    #[must_use]
    pub fn extract_string_constants(java_text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut iter = java_text.chars();
        while let Some(c) = iter.next() {
            if c == '"' {
                let mut s = String::new();
                while let Some(c2) = iter.next() {
                    if c2 == '"' {
                        break;
                    }
                    if c2 == '\\' {
                        if let Some(esc) = iter.next() {
                            match esc {
                                'n' => s.push('\n'),
                                't' => s.push('\t'),
                                'r' => s.push('\r'),
                                other => s.push(other),
                            }
                        }
                    } else {
                        s.push(c2);
                    }
                }
                out.push(s);
            }
        }
        out
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn extract_class_name(java_text: &str) -> Option<String> {
        for line in java_text.lines() {
            let t = line.trim();
            for keyword in &["class ", "interface ", "enum ", "@interface "] {
                if let Some(pos) = t.find(keyword) {
                    let after = t[pos + keyword.len()..].trim_start();
                    let end = after
                        .find(|c: char| !c.is_alphanumeric() && c != '_')
                        .unwrap_or(after.len());
                    if end > 0 {
                        return Some(after[..end].to_string());
                    }
                }
            }
        }
        None
    }

    /// Heuristic: a line is a method signature if it contains `(` and `)` and
    /// starts with a visibility/modifier keyword or a type name.
    fn extract_method_signatures(java_text: &str) -> Vec<String> {
        let modifiers = [
            "public",
            "private",
            "protected",
            "static",
            "final",
            "abstract",
            "native",
            "synchronized",
            "default",
        ];
        java_text
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                if t.contains('(') && t.contains(')') && !t.starts_with("//") && !t.starts_with('*')
                {
                    let first_word = t.split_whitespace().next().unwrap_or("");
                    if modifiers.contains(&first_word)
                        || first_word.chars().next().is_some_and(char::is_uppercase)
                    {
                        // Strip trailing `{` or `;`
                        let sig = t.trim_end_matches('{').trim_end_matches(';').trim();
                        if sig.len() > 3 {
                            return Some(sig.to_string());
                        }
                    }
                }
                None
            })
            .collect()
    }

    /// Heuristic: a line is a field declaration if it ends with `;`, contains
    /// a space-separated type+name, and does not look like a method or import.
    fn extract_field_declarations(java_text: &str) -> Vec<String> {
        let modifiers = [
            "public",
            "private",
            "protected",
            "static",
            "final",
            "volatile",
            "transient",
        ];
        java_text
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                if t.ends_with(';')
                    && !t.contains('(')
                    && !t.starts_with("//")
                    && !t.starts_with("import")
                    && !t.starts_with("package")
                    && !t.starts_with('*')
                {
                    let first_word = t.split_whitespace().next().unwrap_or("");
                    if modifiers.contains(&first_word) {
                        return Some(t.trim_end_matches(';').trim().to_string());
                    }
                }
                None
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let cfg = JadxConfig::new("jadx", "app.apk", "/tmp/out");
        assert_eq!(cfg.jadx_path, "jadx");
        assert_eq!(cfg.input, "app.apk");
        assert_eq!(cfg.output_dir, "/tmp/out");
        assert_eq!(cfg.threads, 4);
        assert!(!cfg.deobfuscate);
    }

    #[test]
    fn test_config_with_threads() {
        let cfg = JadxConfig::new("jadx", "app.apk", "/tmp/out").with_threads(8);
        assert_eq!(cfg.threads, 8);
    }

    #[test]
    fn test_config_with_deobfuscate() {
        let cfg = JadxConfig::new("jadx", "app.apk", "/tmp/out").with_deobfuscate();
        assert!(cfg.deobfuscate);
    }

    #[test]
    fn test_java_method_is_constructor() {
        let m = JavaMethod {
            name: "<init>".to_string(),
            signature: "<init>()".to_string(),
            return_type: "void".to_string(),
            params: vec![],
            body: String::new(),
            is_static: false,
            is_native: false,
        };
        assert!(m.is_constructor());
    }

    #[test]
    fn test_java_method_is_not_constructor() {
        let m = JavaMethod {
            name: "onCreate".to_string(),
            signature: "onCreate()".to_string(),
            return_type: "void".to_string(),
            params: vec![],
            body: String::new(),
            is_static: false,
            is_native: false,
        };
        assert!(!m.is_constructor());
    }

    #[test]
    fn test_java_class_static_methods() {
        let mock = DecompiledProject::mock();
        let utils = mock.find_class("Utils").unwrap();
        let statics = utils.static_methods();
        assert_eq!(statics.len(), 2);
    }

    #[test]
    fn test_java_class_native_methods() {
        let mock = DecompiledProject::mock();
        let aes = mock.find_class("AesHelper").unwrap();
        let natives = aes.native_methods();
        assert_eq!(natives.len(), 1);
    }

    #[test]
    fn test_project_find_class_by_name() {
        let mock = DecompiledProject::mock();
        let cls = mock.find_class("MainActivity");
        assert!(cls.is_some());
    }

    #[test]
    fn test_project_find_class_not_found() {
        let mock = DecompiledProject::mock();
        assert!(mock.find_class("Nonexistent").is_none());
    }

    #[test]
    fn test_project_find_class_by_fqn() {
        let mock = DecompiledProject::mock();
        let cls = mock.find_class("com.example.app.Utils");
        assert!(cls.is_some());
    }

    #[test]
    fn test_project_in_package() {
        let mock = DecompiledProject::mock();
        let classes = mock.in_package("com.example.network");
        assert_eq!(classes.len(), 3);
    }

    #[test]
    fn test_project_in_package_empty() {
        let mock = DecompiledProject::mock();
        let classes = mock.in_package("com.nonexistent");
        assert!(classes.is_empty());
    }

    #[test]
    fn test_project_success_rate_full() {
        let mock = DecompiledProject::mock();
        assert!((mock.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_project_success_rate_partial() {
        let mut mock = DecompiledProject::mock();
        mock.failed = 3;
        let rate = mock.success_rate();
        assert!(rate < 1.0);
        assert!(rate > 0.0);
    }

    #[test]
    fn test_project_success_rate_zero_total() {
        let proj = DecompiledProject {
            classes: vec![],
            total: 0,
            failed: 0,
        };
        assert!((proj.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mock_has_nine_classes() {
        let mock = DecompiledProject::mock();
        assert_eq!(mock.classes.len(), 9);
    }

    #[test]
    fn test_mock_three_packages() {
        let mock = DecompiledProject::mock();
        let mut pkgs: Vec<_> = mock.classes.iter().map(|c| c.package.as_str()).collect();
        pkgs.sort_unstable();
        pkgs.dedup();
        assert_eq!(pkgs.len(), 3);
    }

    #[test]
    fn test_mock_jadx_runner() {
        let runner = MockJadxRunner;
        let cfg = JadxConfig::new("jadx", "app.apk", "/tmp/out");
        let result = runner.decompile(&cfg).unwrap();
        assert_eq!(result.classes.len(), 9);
    }

    #[test]
    fn test_jadx_error_not_found() {
        let e = JadxError::NotFound("jadx".to_string());
        assert!(e.to_string().contains("jadx"));
    }

    #[test]
    fn test_jadx_error_decompile() {
        let e = JadxError::Decompile("out of memory".to_string());
        assert!(e.to_string().contains("out of memory"));
    }

    #[test]
    fn test_jadx_error_parse() {
        let e = JadxError::Parse("bad class file".to_string());
        assert!(e.to_string().contains("bad class file"));
    }

    #[test]
    fn test_jadx_error_io() {
        let e = JadxError::Io("permission denied".to_string());
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn test_config_serialization() {
        let cfg = JadxConfig::new("jadx", "app.apk", "/tmp/out").with_threads(2);
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: JadxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.threads, 2);
    }

    #[test]
    fn test_project_total_matches_classes() {
        let mock = DecompiledProject::mock();
        assert_eq!(mock.total, mock.classes.len());
    }

    #[test]
    fn test_mock_crypto_package_has_three_classes() {
        let mock = DecompiledProject::mock();
        let crypto = mock.in_package("com.example.crypto");
        assert_eq!(crypto.len(), 3);
    }

    #[test]
    fn test_mock_app_package_has_three_classes() {
        let mock = DecompiledProject::mock();
        let app = mock.in_package("com.example.app");
        assert_eq!(app.len(), 3);
    }

    #[test]
    fn test_java_class_no_native_methods() {
        let mock = DecompiledProject::mock();
        let hash = mock.find_class("HashUtil").unwrap();
        assert!(hash.native_methods().is_empty());
    }

    #[test]
    fn test_java_class_all_static_in_hash_util() {
        let mock = DecompiledProject::mock();
        let hash = mock.find_class("HashUtil").unwrap();
        let statics = hash.static_methods();
        assert_eq!(statics.len(), 2);
    }

    #[test]
    fn test_project_failed_zero() {
        let mock = DecompiledProject::mock();
        assert_eq!(mock.failed, 0);
    }

    // ── CliJadxConfig tests ───────────────────────────────────────────────────

    #[test]
    fn test_cli_jadx_config_default_path_is_jadx_or_found() {
        let cfg = CliJadxConfig::default();
        // The path must end with "jadx" or "jadx.exe" (or "jadx-gui" variant).
        let name = cfg
            .jadx_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        assert!(
            name.starts_with("jadx"),
            "expected path starting with jadx, got {name}"
        );
    }

    #[test]
    fn test_cli_jadx_config_default_flags_off() {
        let cfg = CliJadxConfig::default();
        assert!(!cfg.deobfuscate);
        assert!(!cfg.show_inconsistent_code);
        assert!(!cfg.no_res);
        assert!(cfg.output_dir.is_none());
    }

    #[test]
    fn test_cli_jadx_runner_new() {
        let cfg = CliJadxConfig::default();
        let runner = CliJadxRunner::new(cfg);
        // Just confirm construction doesn't panic.
        let _ = format!("{runner:?}");
    }

    #[test]
    fn test_find_jadx_in_path_returns_option() {
        // Should not panic; may return None if jadx is not installed.
        let _result = CliJadxRunner::find_jadx_in_path();
    }

    // ── NativeDexDecompiler tests ─────────────────────────────────────────────

    #[test]
    fn test_native_decompiler_return_void() {
        let method = DalvikMethod {
            name: "run".to_owned(),
            class_name: "Foo".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec!["return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("return;"));
    }

    #[test]
    fn test_native_decompiler_const_string() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                r#"const-string v0, "hello""#.to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("v0 ="));
        assert!(src.contains("hello"));
    }

    #[test]
    fn test_native_decompiler_const_int() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "int".to_owned(),
            params: vec![],
            instructions: vec!["const/4 v0, #int 1".to_owned(), "return v0".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("v0 ="));
        assert!(src.contains("return v0"));
    }

    #[test]
    fn test_native_decompiler_move() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec!["move v1, v0".to_owned(), "return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("v1 = v0"));
    }

    #[test]
    fn test_native_decompiler_iget() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "iget v0, v1, C->field:I".to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("v1."));
    }

    #[test]
    fn test_native_decompiler_iput() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "iput v0, v1, C->field:I".to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("= v0"));
    }

    #[test]
    fn test_native_decompiler_invoke_virtual() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "invoke-virtual {v0, v1}, java/io/PrintStream->println(Ljava/lang/String;)V"
                    .to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("invoke-virtual"));
    }

    #[test]
    fn test_native_decompiler_if_eq() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "if-eq v0, v1, :label_10".to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("if ("));
        assert!(src.contains("=="));
    }

    #[test]
    fn test_native_decompiler_new_instance() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "new-instance v0, Ljava/lang/StringBuilder;".to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("new"));
    }

    #[test]
    fn test_native_decompiler_array_length() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec!["array-length v0, v1".to_owned(), "return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains(".length"));
    }

    #[test]
    fn test_native_decompiler_unhandled_opcode_prefix() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec![
                "some-future-opcode v0, v1".to_owned(),
                "return-void".to_owned(),
            ],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("// [native decompiler]"));
    }

    #[test]
    fn test_native_decompiler_nop() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec!["nop".to_owned(), "return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("nop"));
    }

    #[test]
    fn test_native_decompiler_add_int() {
        let method = DalvikMethod {
            name: "add".to_owned(),
            class_name: "C".to_owned(),
            return_type: "int".to_owned(),
            params: vec!["int a".to_owned(), "int b".to_owned()],
            instructions: vec!["add-int v0, v1, v2".to_owned(), "return v0".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains('+'));
    }

    #[test]
    fn test_native_decompiler_goto() {
        let method = DalvikMethod {
            name: "m".to_owned(),
            class_name: "C".to_owned(),
            return_type: "void".to_owned(),
            params: vec![],
            instructions: vec!["goto :end".to_owned(), "return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("goto"));
    }

    #[test]
    fn test_native_decompiler_method_signature_in_output() {
        let method = DalvikMethod {
            name: "doSomething".to_owned(),
            class_name: "MyClass".to_owned(),
            return_type: "String".to_owned(),
            params: vec!["int x".to_owned()],
            instructions: vec!["return-void".to_owned()],
        };
        let src = NativeDexDecompiler::decompile_method(&method).unwrap();
        assert!(src.contains("doSomething"));
        assert!(src.contains("MyClass"));
    }

    #[test]
    fn test_collect_java_sources_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let project = collect_java_sources(tmp.path()).unwrap();
        assert_eq!(project.total, 0);
        assert_eq!(project.failed, 0);
        assert!(project.classes.is_empty());
    }

    #[test]
    fn test_collect_java_sources_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let java_path = tmp.path().join("Hello.java");
        std::fs::write(
            &java_path,
            "package com.test;\npublic class Hello { public void run() {} }\n",
        )
        .unwrap();
        let project = collect_java_sources(tmp.path()).unwrap();
        assert_eq!(project.total, 1);
        assert_eq!(project.failed, 0);
        assert_eq!(project.classes[0].class_name, "Hello");
        assert_eq!(project.classes[0].package, "com.test");
    }

    #[test]
    fn test_collect_java_sources_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let subdir = tmp.path().join("com").join("example");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(
            subdir.join("Foo.java"),
            "package com.example;\npublic class Foo {}\n",
        )
        .unwrap();
        std::fs::write(
            subdir.join("Bar.java"),
            "package com.example;\npublic class Bar {}\n",
        )
        .unwrap();
        let project = collect_java_sources(tmp.path()).unwrap();
        assert_eq!(project.total, 2);
    }

    #[test]
    fn test_extract_super_class_found() {
        let src = "public class Foo extends BaseActivity { }";
        let result = extract_super_class(src);
        assert_eq!(result, Some("BaseActivity".to_owned()));
    }

    #[test]
    fn test_extract_super_class_none() {
        let src = "public class Foo { }";
        let result = extract_super_class(src);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_package_decl() {
        let src = "package com.example.app;\npublic class Foo {}";
        assert_eq!(
            extract_package_decl(src),
            Some("com.example.app".to_owned())
        );
    }

    #[test]
    fn test_extract_package_decl_none() {
        let src = "public class Foo {}";
        assert!(extract_package_decl(src).is_none());
    }

    #[test]
    fn test_extract_methods_heuristic_static() {
        let src = "public class C {\n  public static void helper() {}\n}";
        let methods = extract_methods_heuristic(src);
        assert!(methods.iter().any(|m| m.is_static));
    }

    #[test]
    fn test_extract_methods_heuristic_native() {
        let src = "public class C {\n  public native String decode();\n}";
        let methods = extract_methods_heuristic(src);
        assert!(methods.iter().any(|m| m.is_native));
    }

    // ── JadxDecompilerConfig ──────────────────────────────────────────────

    #[test]
    fn test_jadx_decompiler_config_default() {
        let cfg = JadxDecompilerConfig::default();
        assert!(cfg.show_comments);
        assert!(cfg.use_imports);
        assert!(!cfg.deobf_enable);
        assert_eq!(cfg.deobf_min_len, 3);
    }

    #[test]
    fn test_jadx_decompiler_config_full() {
        let cfg = JadxDecompilerConfig::full();
        assert!(cfg.deobf_enable);
    }

    #[test]
    fn test_jadx_decompiler_config_json_roundtrip() {
        let cfg = JadxDecompilerConfig {
            show_comments: false,
            use_imports: true,
            deobf_enable: true,
            deobf_min_len: 5,
        };
        let json = cfg.to_json().unwrap();
        let decoded = JadxDecompilerConfig::from_json(&json).unwrap();
        assert!(!decoded.show_comments);
        assert!(decoded.use_imports);
        assert!(decoded.deobf_enable);
        assert_eq!(decoded.deobf_min_len, 5);
    }

    #[test]
    fn test_jadx_decompiler_config_from_invalid_json() {
        let result = JadxDecompilerConfig::from_json("not json");
        assert!(result.is_err());
    }

    // ── JadxResultProcessor ───────────────────────────────────────────────

    #[test]
    fn test_parse_class_output_basic() {
        let java = r#"
package com.example.app;

public class MainActivity extends Activity {
    private TextView tvTitle;
    public static final int REQUEST_CODE = 42;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    private String getLabel() {
        return "hello";
    }
}
"#;
        let cls = JadxResultProcessor::parse_class_output(java);
        assert_eq!(cls.package, "com.example.app");
        assert_eq!(cls.name, "MainActivity");
        assert!(!cls.methods.is_empty(), "should find at least one method");
        assert!(!cls.fields.is_empty(), "should find at least one field");
    }

    #[test]
    fn test_parse_class_output_no_package() {
        let java = "public class Foo {\n  public void bar() {}\n}\n";
        let cls = JadxResultProcessor::parse_class_output(java);
        assert_eq!(cls.package, "unknown");
        assert_eq!(cls.name, "Foo");
    }

    #[test]
    fn test_extract_string_constants_basic() {
        let java = r#"String a = "hello"; String b = "world";"#;
        let strings = JadxResultProcessor::extract_string_constants(java);
        assert_eq!(strings, vec!["hello", "world"]);
    }

    #[test]
    fn test_extract_string_constants_with_escapes() {
        let java = r#"log("line1\nline2");"#;
        let strings = JadxResultProcessor::extract_string_constants(java);
        assert_eq!(strings.len(), 1);
        assert!(strings[0].contains('\n'));
    }

    #[test]
    fn test_extract_string_constants_empty() {
        let strings = JadxResultProcessor::extract_string_constants("int x = 0;");
        assert!(strings.is_empty());
    }

    #[test]
    fn test_jadx_class_serialization() {
        let cls = JadxClass {
            package: "com.test".to_string(),
            name: "Foo".to_string(),
            methods: vec!["public void bar()".to_string()],
            fields: vec!["private int count".to_string()],
        };
        let json = serde_json::to_string(&cls).unwrap();
        let decoded: JadxClass = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.package, "com.test");
        assert_eq!(decoded.name, "Foo");
        assert_eq!(decoded.methods.len(), 1);
        assert_eq!(decoded.fields.len(), 1);
    }
}

// =============================================================================
// PART 1 — Dalvik Instruction Decoder
// =============================================================================

use std::collections::HashMap;

/// Dalvik instruction encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DalvikFmt {
    /// 10x  — op (no operands, e.g. nop, return-void)
    Fmt10x,
    /// 12x  — op vA, vB
    Fmt12x,
    /// 11n  — op vA, #+B  (4-bit literal)
    Fmt11n,
    /// 11x  — op vAA
    Fmt11x,
    /// 10t  — op +AA  (8-bit branch offset)
    Fmt10t,
    /// 20t  — op +AAAA  (16-bit branch offset)
    Fmt20t,
    /// 22x  — op vAA, vBBBB
    Fmt22x,
    /// 21t  — op vAA, +BBBB  (16-bit branch)
    Fmt21t,
    /// 21s  — op vAA, #+BBBB  (16-bit signed literal)
    Fmt21s,
    /// 21h  — op vAA, #+BBBB0000  (high 16-bit literal)
    Fmt21h,
    /// 21c  — op vAA, thing@BBBB  (16-bit index)
    Fmt21c,
    /// 23x  — op vAA, vBB, vCC
    Fmt23x,
    /// 22b  — op vAA, vBB, #+CC  (8-bit literal)
    Fmt22b,
    /// 22t  — op vA, vB, +CCCC  (16-bit branch)
    Fmt22t,
    /// 22s  — op vA, vB, #+CCCC  (16-bit literal)
    Fmt22s,
    /// 22c  — op vA, vB, thing@CCCC
    Fmt22c,
    /// 32x  — op vAAAA, vBBBB
    Fmt32x,
    /// 30t  — op +AAAAAAAA  (32-bit branch)
    Fmt30t,
    /// 31t  — op vAA, +BBBBBBBB  (32-bit branch target)
    Fmt31t,
    /// 31i  — op vAA, #+BBBBBBBB  (32-bit literal)
    Fmt31i,
    /// 31c  — op vAA, string@BBBBBBBB  (32-bit index)
    Fmt31c,
    /// 35c  — op {vC,vD,vE,vF,vG}, thing@BBBB
    Fmt35c,
    /// 3rc  — op {vCCCC..vNNNN}, thing@BBBB
    Fmt3rc,
    /// 51l  — op vAA, #+BBBBBBBBBBBBBBBB  (64-bit literal)
    Fmt51l,
    /// Fill-array-data / packed-switch / sparse-switch pseudo-ops
    FmtPayload,
    /// Unknown / unrecognised opcode
    FmtUnknown,
}

/// A fully decoded Dalvik instruction.
#[derive(Debug, Clone)]
pub struct DalvikInstr {
    /// Byte offset of the first code unit within the method's insns buffer.
    pub offset: u32,
    /// Raw opcode byte (low byte of first code unit).
    pub opcode: u8,
    /// Human-readable mnemonic.
    pub mnemonic: &'static str,
    /// Register operands (destination first where applicable).
    pub regs: Vec<u8>,
    /// Immediate integer value (literal, if any).
    pub imm: Option<i64>,
    /// Branch target as a *signed code-unit* offset from the instruction start.
    pub target: Option<i32>,
    /// Pool index (string, type, field, method, or proto reference).
    pub ref_idx: Option<u32>,
    /// Instruction encoding format.
    pub format: DalvikFmt,
}

impl DalvikInstr {
    /// Returns the number of 16-bit code units this instruction occupies.
    #[must_use]
    pub const fn code_units(&self) -> u32 {
        match self.format {
            DalvikFmt::Fmt10x
            | DalvikFmt::Fmt12x
            | DalvikFmt::Fmt11n
            | DalvikFmt::Fmt11x
            | DalvikFmt::Fmt10t
            | DalvikFmt::FmtPayload
            | DalvikFmt::FmtUnknown => 1,
            DalvikFmt::Fmt20t
            | DalvikFmt::Fmt22x
            | DalvikFmt::Fmt21t
            | DalvikFmt::Fmt21s
            | DalvikFmt::Fmt21h
            | DalvikFmt::Fmt21c
            | DalvikFmt::Fmt23x
            | DalvikFmt::Fmt22b
            | DalvikFmt::Fmt22t
            | DalvikFmt::Fmt22s
            | DalvikFmt::Fmt22c => 2,
            DalvikFmt::Fmt32x
            | DalvikFmt::Fmt30t
            | DalvikFmt::Fmt31t
            | DalvikFmt::Fmt31i
            | DalvikFmt::Fmt31c
            | DalvikFmt::Fmt35c
            | DalvikFmt::Fmt3rc => 3,
            DalvikFmt::Fmt51l => 5,
        }
    }

    /// True if this instruction is an unconditional or conditional branch.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        self.target.is_some()
    }

    /// True if this instruction terminates a basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self.opcode,
            0x0e | 0x0f | 0x10 | 0x11  // return-*
            | 0x27                       // throw
            | 0x28 | 0x29 | 0x2a        // goto*
            | 0x2b | 0x2c               // switch
            | 0x32..=0x3d // if-*
        )
    }

    /// True if this is a return instruction.
    #[must_use]
    pub const fn is_return(&self) -> bool {
        matches!(self.opcode, 0x0e..=0x11)
    }

    /// True if this is an invoke-* instruction.
    ///
    /// The last range was `0xfa..=0xfc`, one opcode short: `0xfd` is
    /// `invoke-custom/range`, which is as much an invoke as the `0xfc`
    /// `invoke-custom` beside it.  The two ranges before it already follow the
    /// rule this one broke — `0x6e..=0x72` and `0x74..=0x78` each take in their
    /// own `/range` variants.  With `0xfd` excluded a call site went
    /// unrecognised, so its edge was missing from the call graph and
    /// `lambda_recovery` — which exists precisely because D8/R8 emit
    /// `invoke-custom` — never saw it.
    #[must_use]
    pub const fn is_invoke(&self) -> bool {
        matches!(self.opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd)
    }
}

// ─── opcode table helpers ────────────────────────────────────────────────────

#[inline]
const fn lo_nibble(b: u8) -> u8 {
    b & 0x0f
}

#[inline]
const fn hi_nibble(b: u8) -> u8 {
    (b >> 4) & 0x0f
}

/// Sign-extend an N-bit value stored in the low N bits of `v`.
#[inline]
const fn sext(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (v << shift).cast_signed() >> shift
}

/// Decode a complete Dalvik `insns` buffer (array of little-endian u16 words)
/// into a `Vec<DalvikInstr>`.
///
/// Multi-unit instructions are decoded in one shot.  Payload pseudo-ops
/// (packed-switch, sparse-switch, fill-array-data) are decoded with
/// `DalvikFmt::FmtPayload` and skipped over correctly.
/// Compute the size in code-units of a payload pseudo-op identified by
/// `ident` (the high nibble of `aa` for a 0x00 opcode).  Returns 0 if `ident`
/// does not match a payload pseudo-op.
fn payload_pseudo_op_size(code: &[u16], pc: usize, ident: u8) -> usize {
    match ident {
        0x01 => {
            let sz = code.get(pc + 1).copied().unwrap_or(0) as usize;
            2 + sz * 2
        }
        0x02 => {
            let sz = code.get(pc + 1).copied().unwrap_or(0) as usize;
            2 + sz * 4
        }
        0x03 => {
            let elem_width = code.get(pc + 1).copied().unwrap_or(0) as usize;
            let num_elem = (code.get(pc + 2).copied().unwrap_or(0) as usize)
                | ((code.get(pc + 3).copied().unwrap_or(0) as usize) << 16);
            let data_units = num_elem.saturating_mul(elem_width).div_ceil(2);
            4 + data_units
        }
        _ => 1,
    }
}

/// Decode a 2-code-unit Dalvik format, populating `instr` in place.
fn decode_dalvik_2unit(
    instr: &mut DalvikInstr,
    aa: u8,
    opcode: u8,
    word: &dyn Fn(usize) -> u16,
) -> bool {
    match instr.format {
        DalvikFmt::Fmt20t => {
            let w1 = word(1);
            instr.target = Some(i32::try_from(sext(u64::from(w1), 16)).unwrap_or(0));
        }
        DalvikFmt::Fmt22x => {
            instr.regs.push(aa);
            instr.regs.push(u8::try_from(word(1)).unwrap_or(u8::MAX));
            let vbbbb = word(1);
            if vbbbb > 255 {
                instr.imm = Some(i64::from(vbbbb));
            }
        }
        DalvikFmt::Fmt21t => {
            instr.regs.push(aa);
            instr.target = Some(i32::try_from(sext(u64::from(word(1)), 16)).unwrap_or(0));
        }
        DalvikFmt::Fmt21s => {
            instr.regs.push(aa);
            instr.imm = Some(sext(u64::from(word(1)), 16));
        }
        DalvikFmt::Fmt21h => {
            instr.regs.push(aa);
            let raw = i64::from(word(1));
            instr.imm = Some(if opcode == 0x19 { raw << 48 } else { raw << 16 });
        }
        DalvikFmt::Fmt21c => {
            instr.regs.push(aa);
            instr.ref_idx = Some(u32::from(word(1)));
        }
        DalvikFmt::Fmt23x => {
            instr.regs.push(aa);
            instr.regs.push((word(1) & 0xff) as u8);
            instr.regs.push(((word(1) >> 8) & 0xff) as u8);
        }
        DalvikFmt::Fmt22b => {
            instr.regs.push(aa);
            instr.regs.push((word(1) & 0xff) as u8);
            instr.imm = Some(sext(u64::from((word(1) >> 8) & 0xff), 8));
        }
        DalvikFmt::Fmt22t => {
            instr.regs.push(lo_nibble(aa));
            instr.regs.push(hi_nibble(aa));
            instr.target = Some(i32::try_from(sext(u64::from(word(1)), 16)).unwrap_or(0));
        }
        DalvikFmt::Fmt22s => {
            instr.regs.push(lo_nibble(aa));
            instr.regs.push(hi_nibble(aa));
            instr.imm = Some(sext(u64::from(word(1)), 16));
        }
        DalvikFmt::Fmt22c => {
            instr.regs.push(lo_nibble(aa));
            instr.regs.push(hi_nibble(aa));
            instr.ref_idx = Some(u32::from(word(1)));
        }
        _ => return false,
    }
    true
}

/// Decode a 3- or 5-code-unit Dalvik format, populating `instr` in place.
fn decode_dalvik_wide_unit(
    instr: &mut DalvikInstr,
    word0: u16,
    aa: u8,
    word: &dyn Fn(usize) -> u16,
) -> bool {
    match instr.format {
        DalvikFmt::Fmt32x => {
            let vaaaa = word(1);
            let vbbbb = word(2);
            instr.regs.push((vaaaa & 0xff) as u8);
            instr.regs.push((vbbbb & 0xff) as u8);
        }
        DalvikFmt::Fmt30t => {
            let lo = u32::from(word(1));
            let hi = u32::from(word(2));
            let off = (hi << 16 | lo).cast_signed();
            instr.target = Some(off);
        }
        DalvikFmt::Fmt31t => {
            instr.regs.push(aa);
            let lo = u32::from(word(1));
            let hi = u32::from(word(2));
            instr.target = Some((hi << 16 | lo).cast_signed());
        }
        DalvikFmt::Fmt31i => {
            instr.regs.push(aa);
            let lo = u32::from(word(1));
            let hi = u32::from(word(2));
            instr.imm = Some(i64::from((hi << 16 | lo).cast_signed()));
        }
        DalvikFmt::Fmt31c => {
            instr.regs.push(aa);
            let lo = u32::from(word(1));
            let hi = u32::from(word(2));
            instr.ref_idx = Some(hi << 16 | lo);
        }
        DalvikFmt::Fmt35c => {
            let count_a = (word0 >> 12) & 0xf;
            let reg_g = (word0 >> 8) & 0xf;
            let bbbb = word(1);
            let word2 = word(2);
            let reg_c = word2 & 0xf;
            let reg_d = (word2 >> 4) & 0xf;
            let reg_e = (word2 >> 8) & 0xf;
            let reg_f = (word2 >> 12) & 0xf;
            instr.ref_idx = Some(u32::from(bbbb));
            let reg_list = [reg_c, reg_d, reg_e, reg_f, reg_g];
            // 35c only supports up to 5 register operands; clamp malformed counts.
            let cap = count_a.min(5);
            for i in 0..cap {
                instr
                    .regs
                    .push(u8::try_from(reg_list[i as usize] & 0xff).unwrap_or(0));
            }
        }
        DalvikFmt::Fmt3rc => {
            let bbbb = word(1);
            let cccc = word(2);
            let a = aa;
            instr.ref_idx = Some(u32::from(bbbb));
            for i in 0..a {
                instr
                    .regs
                    .push(u8::try_from(cccc.wrapping_add(u16::from(i)) & 0xff).unwrap_or(0));
            }
        }
        DalvikFmt::Fmt51l => {
            instr.regs.push(aa);
            let w1 = u64::from(word(1));
            let w2 = u64::from(word(2));
            let w3 = u64::from(word(3));
            let w4 = u64::from(word(4));
            let val = w1 | (w2 << 16) | (w3 << 32) | (w4 << 48);
            instr.imm = Some(val.cast_signed());
        }
        _ => return false,
    }
    true
}

/// Decode any non-1-unit Dalvik format, populating `instr` in place.
fn decode_dalvik_multi_unit(
    instr: &mut DalvikInstr,
    word0: u16,
    aa: u8,
    opcode: u8,
    word: &dyn Fn(usize) -> u16,
) -> bool {
    decode_dalvik_2unit(instr, aa, opcode, word) || decode_dalvik_wide_unit(instr, word0, aa, word)
}

#[must_use]
pub fn decode_dalvik(code: &[u16]) -> Vec<DalvikInstr> {
    let mut out = Vec::with_capacity(code.len());
    let mut pc: usize = 0; // code-unit index

    while pc < code.len() {
        let word0 = code[pc];
        let opcode = (word0 & 0xff) as u8;
        let aa = ((word0 >> 8) & 0xff) as u8;

        let mut instr = DalvikInstr {
            offset: u32::try_from(pc).unwrap_or(u32::MAX).saturating_mul(2),
            opcode,
            mnemonic: opcode_mnemonic(opcode),
            regs: Vec::new(),
            imm: None,
            target: None,
            ref_idx: None,
            format: opcode_format(opcode),
        };

        // helper closures — read ahead
        let word = |idx: usize| -> u16 {
            if pc + idx < code.len() {
                code[pc + idx]
            } else {
                0
            }
        };

        match instr.format {
            // ── 1-unit formats ──────────────────────────────────────────────
            DalvikFmt::Fmt10x => {
                // nop / return-void; check for payload pseudo-ops
                if opcode == 0x00 {
                    let ident = hi_nibble(aa);
                    if ident != 0 {
                        let size = payload_pseudo_op_size(code, pc, ident);
                        instr.format = DalvikFmt::FmtPayload;
                        out.push(instr);
                        pc += size.max(1);
                        continue;
                    }
                }
            }

            DalvikFmt::Fmt12x => {
                instr.regs.push(lo_nibble(aa));
                instr.regs.push(hi_nibble(aa));
            }

            DalvikFmt::Fmt11n => {
                instr.regs.push(lo_nibble(aa));
                instr.imm = Some(sext(u64::from(hi_nibble(aa)), 4));
            }

            DalvikFmt::Fmt11x => {
                instr.regs.push(aa);
            }

            DalvikFmt::Fmt10t => {
                let off = i32::try_from(sext(u64::from(aa), 8)).unwrap_or(0);
                instr.target = Some(off);
            }

            DalvikFmt::FmtPayload | DalvikFmt::FmtUnknown => {}

            // ── 2-/3-/5-unit formats (delegated) ────────────────────────────
            _ => {
                decode_dalvik_multi_unit(&mut instr, word0, aa, opcode, &word);
            }
        }

        let units = instr.code_units() as usize;
        out.push(instr);
        pc += units;
    }

    out
}

/// Map opcode → mnemonic string.
#[must_use]
pub const fn opcode_mnemonic(op: u8) -> &'static str {
    if op <= 0x6d {
        opcode_mnemonic_lo(op)
    } else {
        opcode_mnemonic_hi(op)
    }
}

const fn opcode_mnemonic_lo(op: u8) -> &'static str {
    if op <= 0x37 {
        opcode_mnemonic_lo_a(op)
    } else {
        opcode_mnemonic_lo_b(op)
    }
}

const fn opcode_mnemonic_lo_a(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "move",
        0x02 => "move/from16",
        0x03 => "move/16",
        0x04 => "move-wide",
        0x05 => "move-wide/from16",
        0x06 => "move-wide/16",
        0x07 => "move-object",
        0x08 => "move-object/from16",
        0x09 => "move-object/16",
        0x0a => "move-result",
        0x0b => "move-result-wide",
        0x0c => "move-result-object",
        0x0d => "move-exception",
        0x0e => "return-void",
        0x0f => "return",
        0x10 => "return-wide",
        0x11 => "return-object",
        0x12 => "const/4",
        0x13 => "const/16",
        0x14 => "const",
        0x15 => "const/high16",
        0x16 => "const-wide/16",
        0x17 => "const-wide/32",
        0x18 => "const-wide",
        0x19 => "const-wide/high16",
        0x1a => "const-string",
        0x1b => "const-string/jumbo",
        0x1c => "const-class",
        0x1d => "monitor-enter",
        0x1e => "monitor-exit",
        0x1f => "check-cast",
        0x20 => "instance-of",
        0x21 => "array-length",
        0x22 => "new-instance",
        0x23 => "new-array",
        0x24 => "filled-new-array",
        0x25 => "filled-new-array/range",
        0x26 => "fill-array-data",
        0x27 => "throw",
        0x28 => "goto",
        0x29 => "goto/16",
        0x2a => "goto/32",
        0x2b => "packed-switch",
        0x2c => "sparse-switch",
        0x2d => "cmpl-float",
        0x2e => "cmpg-float",
        0x2f => "cmpl-double",
        0x30 => "cmpg-double",
        0x31 => "cmp-long",
        0x32 => "if-eq",
        0x33 => "if-ne",
        0x34 => "if-lt",
        0x35 => "if-ge",
        0x36 => "if-gt",
        0x37 => "if-le",
        _ => "unknown",
    }
}

const fn opcode_mnemonic_lo_b(op: u8) -> &'static str {
    match op {
        0x38 => "if-eqz",
        0x39 => "if-nez",
        0x3a => "if-ltz",
        0x3b => "if-gez",
        0x3c => "if-gtz",
        0x3d => "if-lez",
        0x44 => "aget",
        0x45 => "aget-wide",
        0x46 => "aget-object",
        0x47 => "aget-boolean",
        0x48 => "aget-byte",
        0x49 => "aget-char",
        0x4a => "aget-short",
        0x4b => "aput",
        0x4c => "aput-wide",
        0x4d => "aput-object",
        0x4e => "aput-boolean",
        0x4f => "aput-byte",
        0x50 => "aput-char",
        0x51 => "aput-short",
        0x52 => "iget",
        0x53 => "iget-wide",
        0x54 => "iget-object",
        0x55 => "iget-boolean",
        0x56 => "iget-byte",
        0x57 => "iget-char",
        0x58 => "iget-short",
        0x59 => "iput",
        0x5a => "iput-wide",
        0x5b => "iput-object",
        0x5c => "iput-boolean",
        0x5d => "iput-byte",
        0x5e => "iput-char",
        0x5f => "iput-short",
        0x60 => "sget",
        0x61 => "sget-wide",
        0x62 => "sget-object",
        0x63 => "sget-boolean",
        0x64 => "sget-byte",
        0x65 => "sget-char",
        0x66 => "sget-short",
        0x67 => "sput",
        0x68 => "sput-wide",
        0x69 => "sput-object",
        0x6a => "sput-boolean",
        0x6b => "sput-byte",
        0x6c => "sput-char",
        0x6d => "sput-short",
        _ => "unknown",
    }
}

const fn opcode_mnemonic_hi(op: u8) -> &'static str {
    if op <= 0xaf {
        opcode_mnemonic_hi_a(op)
    } else {
        opcode_mnemonic_hi_b(op)
    }
}

const fn opcode_mnemonic_hi_a(op: u8) -> &'static str {
    match op {
        0x6e => "invoke-virtual",
        0x6f => "invoke-super",
        0x70 => "invoke-direct",
        0x71 => "invoke-static",
        0x72 => "invoke-interface",
        0x74 => "invoke-virtual/range",
        0x75 => "invoke-super/range",
        0x76 => "invoke-direct/range",
        0x77 => "invoke-static/range",
        0x78 => "invoke-interface/range",
        0x7b => "neg-int",
        0x7c => "not-int",
        0x7d => "neg-long",
        0x7e => "not-long",
        0x7f => "neg-float",
        0x80 => "neg-double",
        0x81 => "int-to-long",
        0x82 => "int-to-float",
        0x83 => "int-to-double",
        0x84 => "long-to-int",
        0x85 => "long-to-float",
        0x86 => "long-to-double",
        0x87 => "float-to-int",
        0x88 => "float-to-long",
        0x89 => "float-to-double",
        0x8a => "double-to-int",
        0x8b => "double-to-long",
        0x8c => "double-to-float",
        0x8d => "int-to-byte",
        0x8e => "int-to-char",
        0x8f => "int-to-short",
        0x90 => "add-int",
        0x91 => "sub-int",
        0x92 => "mul-int",
        0x93 => "div-int",
        0x94 => "rem-int",
        0x95 => "and-int",
        0x96 => "or-int",
        0x97 => "xor-int",
        0x98 => "shl-int",
        0x99 => "shr-int",
        0x9a => "ushr-int",
        0x9b => "add-long",
        0x9c => "sub-long",
        0x9d => "mul-long",
        0x9e => "div-long",
        0x9f => "rem-long",
        0xa0 => "and-long",
        0xa1 => "or-long",
        0xa2 => "xor-long",
        0xa3 => "shl-long",
        0xa4 => "shr-long",
        0xa5 => "ushr-long",
        0xa6 => "add-float",
        0xa7 => "sub-float",
        0xa8 => "mul-float",
        0xa9 => "div-float",
        0xaa => "rem-float",
        0xab => "add-double",
        0xac => "sub-double",
        0xad => "mul-double",
        0xae => "div-double",
        0xaf => "rem-double",
        _ => "unknown",
    }
}

const fn opcode_mnemonic_hi_b(op: u8) -> &'static str {
    match op {
        0xb0 => "add-int/2addr",
        0xb1 => "sub-int/2addr",
        0xb2 => "mul-int/2addr",
        0xb3 => "div-int/2addr",
        0xb4 => "rem-int/2addr",
        0xb5 => "and-int/2addr",
        0xb6 => "or-int/2addr",
        0xb7 => "xor-int/2addr",
        0xb8 => "shl-int/2addr",
        0xb9 => "shr-int/2addr",
        0xba => "ushr-int/2addr",
        0xbb => "add-long/2addr",
        0xbc => "sub-long/2addr",
        0xbd => "mul-long/2addr",
        0xbe => "div-long/2addr",
        0xbf => "rem-long/2addr",
        0xc0 => "and-long/2addr",
        0xc1 => "or-long/2addr",
        0xc2 => "xor-long/2addr",
        0xc3 => "shl-long/2addr",
        0xc4 => "shr-long/2addr",
        0xc5 => "ushr-long/2addr",
        0xc6 => "add-float/2addr",
        0xc7 => "sub-float/2addr",
        0xc8 => "mul-float/2addr",
        0xc9 => "div-float/2addr",
        0xca => "rem-float/2addr",
        0xcb => "add-double/2addr",
        0xcc => "sub-double/2addr",
        0xcd => "mul-double/2addr",
        0xce => "div-double/2addr",
        0xcf => "rem-double/2addr",
        0xd0 => "add-int/lit16",
        0xd1 => "rsub-int",
        0xd2 => "mul-int/lit16",
        0xd3 => "div-int/lit16",
        0xd4 => "rem-int/lit16",
        0xd5 => "and-int/lit16",
        0xd6 => "or-int/lit16",
        0xd7 => "xor-int/lit16",
        0xd8 => "add-int/lit8",
        0xd9 => "rsub-int/lit8",
        0xda => "mul-int/lit8",
        0xdb => "div-int/lit8",
        0xdc => "rem-int/lit8",
        0xdd => "and-int/lit8",
        0xde => "or-int/lit8",
        0xdf => "xor-int/lit8",
        0xe0 => "shl-int/lit8",
        0xe1 => "shr-int/lit8",
        0xe2 => "ushr-int/lit8",
        _ => "unknown",
    }
}

/// Map opcode → canonical encoding format.
#[must_use]
pub const fn opcode_format(op: u8) -> DalvikFmt {
    match op {
        // 10x: no operands
        0x00 | 0x0e => DalvikFmt::Fmt10x,
        // 12x: vA, vB  (moves, unary ops, array-length, 2addr binaries)
        0x01 | 0x04 | 0x07 | 0x21 | 0x7b..=0x8f | 0xb0..=0xcf => DalvikFmt::Fmt12x,
        // 11n: vA, #+B  (const/4)
        0x12 => DalvikFmt::Fmt11n,
        // 11x: vAA  (move-result-*, move-exception, monitor-*, throw, return-*)
        0x0a | 0x0b | 0x0c | 0x0d | 0x0f | 0x10 | 0x11 | 0x1d | 0x1e | 0x27 => DalvikFmt::Fmt11x,
        // 10t: +AA  (goto)
        0x28 => DalvikFmt::Fmt10t,
        // 20t: +AAAA  (goto/16)
        0x29 => DalvikFmt::Fmt20t,
        // 30t: +AAAAAAAA  (goto/32)
        0x2a => DalvikFmt::Fmt30t,
        // 22x: vAA, vBBBB  (move/from16, move-wide/from16, move-object/from16)
        0x02 | 0x05 | 0x08 => DalvikFmt::Fmt22x,
        // 32x: vAAAA, vBBBB  (move/16, move-wide/16, move-object/16)
        0x03 | 0x06 | 0x09 => DalvikFmt::Fmt32x,
        // 21t: vAA, +BBBB  (if-*z)
        0x38..=0x3d => DalvikFmt::Fmt21t,
        // 21s: vAA, #+BBBB  (const/16, const-wide/16)
        0x13 | 0x16 => DalvikFmt::Fmt21s,
        // 21h: vAA, #+BBBB0000  (const/high16, const-wide/high16)
        0x15 | 0x19 => DalvikFmt::Fmt21h,
        // 21c: vAA, ref@BBBB  (const-string, const-class, check-cast, new-instance, sget*)
        0x1a | 0x1c | 0x1f | 0x22 | 0x60..=0x6d => DalvikFmt::Fmt21c,
        // 31c: vAA, ref@BBBBBBBB  (const-string/jumbo)
        0x1b => DalvikFmt::Fmt31c,
        // 31i: vAA, #+BBBBBBBB  (const, const-wide/32)
        0x14 | 0x17 => DalvikFmt::Fmt31i,
        // 51l: vAA, #+BBBBBBBBBBBBBBBB  (const-wide)
        0x18 => DalvikFmt::Fmt51l,
        // 22c: vA, vB, ref@CCCC  (instance-of, new-array, iget*, iput*)
        0x20 | 0x23 | 0x52..=0x5f => DalvikFmt::Fmt22c,
        // 35c: {vC..vG}, ref@BBBB  (filled-new-array, invoke-*)
        0x24 | 0x6e..=0x72 => DalvikFmt::Fmt35c,
        // 3rc: {vCCCC..vNNNN}, ref@BBBB  (filled-new-array/range, invoke-*/range)
        0x25 | 0x74..=0x78 => DalvikFmt::Fmt3rc,
        // 31t: vAA, +BBBBBBBB  (fill-array-data, packed-switch, sparse-switch)
        0x26 | 0x2b | 0x2c => DalvikFmt::Fmt31t,
        // 23x: vAA, vBB, vCC  (cmp*, array-get/put, binary ops)
        0x2d..=0x31 | 0x44..=0x51 | 0x90..=0xaf => DalvikFmt::Fmt23x,
        // 22t: vA, vB, +CCCC  (if-eq, if-ne, if-lt, if-ge, if-gt, if-le)
        0x32..=0x37 => DalvikFmt::Fmt22t,
        // 22s: vA, vB, #+CCCC  (add-int/lit16 .. xor-int/lit16)
        0xd0..=0xd7 => DalvikFmt::Fmt22s,
        // 22b: vAA, vBB, #+CC  (add-int/lit8 .. ushr-int/lit8)
        0xd8..=0xe2 => DalvikFmt::Fmt22b,
        _ => DalvikFmt::FmtUnknown,
    }
}

// =============================================================================
// PART 2 -- Control Flow Graph for Dalvik
// =============================================================================

/// A single basic block in a Dalvik CFG.
#[derive(Debug, Clone)]
pub struct DalvikBB {
    /// Unique block id (0-based, assigned in layout order).
    pub id: u32,
    /// Byte offset of the first instruction in this block.
    pub start: u32,
    /// Byte offset of the last instruction in this block (inclusive).
    pub end: u32,
    /// Indices into the original `DalvikInstr` slice.
    pub instrs: Vec<usize>,
    /// Successor block ids.
    pub succs: Vec<u32>,
    /// Predecessor block ids.
    pub preds: Vec<u32>,
}

/// A complete Dalvik Control Flow Graph.
#[derive(Debug, Clone)]
pub struct DalvikCfg {
    pub blocks: Vec<DalvikBB>,
}

impl DalvikCfg {
    /// Return the block that contains byte offset `off`, if any.
    #[must_use]
    pub fn block_at_offset(&self, off: u32) -> Option<&DalvikBB> {
        self.blocks
            .iter()
            .filter(|b| b.start <= off)
            .max_by_key(|b| b.start)
    }

    /// Return block by id.
    #[must_use]
    pub fn block(&self, id: u32) -> Option<&DalvikBB> {
        self.blocks.get(id as usize)
    }

    /// Reverse post-order traversal (entry first). Returns block ids.
    #[must_use]
    pub fn rpo(&self) -> Vec<u32> {
        let n = self.blocks.len();
        if n == 0 {
            return vec![];
        }
        let mut visited = vec![false; n];
        let mut post: Vec<u32> = Vec::with_capacity(n);
        // iterative DFS to avoid stack overflow on large methods
        let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
        visited[0] = true;
        while let Some((id, next_succ)) = stack.last_mut() {
            let id = *id;
            let succs = &self.blocks[id as usize].succs;
            if *next_succ < succs.len() {
                let s = succs[*next_succ];
                *next_succ += 1;
                if !visited[s as usize] {
                    visited[s as usize] = true;
                    stack.push((s, 0));
                }
            } else {
                post.push(id);
                stack.pop();
            }
        }
        post.reverse();
        post
    }

    /// Immediate dominator array indexed by block id (entry dominates itself).
    #[must_use]
    pub fn idom(&self) -> Vec<Option<u32>> {
        // Simple Cooper et al. dataflow dominator algorithm.
        let order = self.rpo();
        let n = self.blocks.len();
        let mut idom: Vec<Option<u32>> = vec![None; n];
        if order.is_empty() {
            return idom;
        }
        let entry = order[0];
        idom[entry as usize] = Some(entry);

        // Map block id -> RPO index
        let mut rpo_idx: Vec<usize> = vec![0; n];
        for (i, &id) in order.iter().enumerate() {
            rpo_idx[id as usize] = i;
        }

        let intersect = |mut a: u32, mut b: u32, idom: &[Option<u32>], rpo_idx: &[usize]| -> u32 {
            while a != b {
                while rpo_idx[a as usize] > rpo_idx[b as usize] {
                    a = idom[a as usize].unwrap_or(a);
                }
                while rpo_idx[b as usize] > rpo_idx[a as usize] {
                    b = idom[b as usize].unwrap_or(b);
                }
            }
            a
        };

        let mut changed = true;
        while changed {
            changed = false;
            for &b in order.iter().skip(1) {
                let preds = &self.blocks[b as usize].preds;
                let new_idom = preds
                    .iter()
                    .filter(|&&p| idom[p as usize].is_some())
                    .copied()
                    .reduce(|a, c| intersect(a, c, &idom, &rpo_idx));
                if let Some(ni) = new_idom
                    && idom[b as usize] != Some(ni)
                {
                    idom[b as usize] = Some(ni);
                    changed = true;
                }
            }
        }
        idom
    }
}

/// Build a CFG from a decoded instruction slice.
///
/// Algorithm:
/// 1. Identify all leader byte-offsets (entry + branch targets + fall-throughs
///    after terminators).
/// 2. Partition instructions into basic blocks.
/// 3. Wire successor / predecessor edges.
#[must_use]
pub fn build_dalvik_cfg(instrs: &[DalvikInstr]) -> DalvikCfg {
    if instrs.is_empty() {
        return DalvikCfg { blocks: vec![] };
    }

    // Step 1: collect leader byte-offsets
    let mut leader_set: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    leader_set.insert(instrs[0].offset);

    for (idx, instr) in instrs.iter().enumerate() {
        if instr.is_terminator() {
            if let Some(next) = instrs.get(idx + 1) {
                leader_set.insert(next.offset);
            }
            if let Some(rel) = instr.target {
                let target_byte = i64::from(instr.offset) + i64::from(rel) * 2;
                if let Ok(t) = u32::try_from(target_byte) {
                    leader_set.insert(t);
                }
            }
        }
    }

    let leaders_vec: Vec<u32> = leader_set.into_iter().collect();
    let mut leader_to_id: HashMap<u32, u32> = HashMap::new();
    for (i, &off) in leaders_vec.iter().enumerate() {
        leader_to_id.insert(off, u32::try_from(i).unwrap_or(u32::MAX));
    }

    let num_blocks = leaders_vec.len();
    let mut blocks: Vec<DalvikBB> = leaders_vec
        .iter()
        .enumerate()
        .map(|(i, &off)| DalvikBB {
            id: u32::try_from(i).unwrap_or(u32::MAX),
            start: off,
            end: off,
            instrs: Vec::new(),
            succs: Vec::new(),
            preds: Vec::new(),
        })
        .collect();

    // Step 2: assign instructions to blocks
    for (idx, instr) in instrs.iter().enumerate() {
        let pos = leaders_vec.partition_point(|&l| l <= instr.offset);
        if pos == 0 {
            continue;
        }
        let bid = leader_to_id[&leaders_vec[pos - 1]] as usize;
        blocks[bid].instrs.push(idx);
        if instr.offset > blocks[bid].end {
            blocks[bid].end = instr.offset;
        }
    }

    // Step 3: wire edges
    for bi in 0..num_blocks {
        let Some(last_instr_idx) = blocks[bi].instrs.last().copied() else {
            continue;
        };
        let instr = &instrs[last_instr_idx];

        let unconditional = matches!(
            instr.opcode,
            0x0e | 0x0f | 0x10 | 0x11  // return-*
            | 0x27                       // throw
            | 0x28 | 0x29 | 0x2a // goto variants
        );

        let add_edge = |blocks: &mut Vec<DalvikBB>, from: u32, to: u32| {
            if !blocks[from as usize].succs.contains(&to) {
                blocks[from as usize].succs.push(to);
            }
            if !blocks[to as usize].preds.contains(&from) {
                blocks[to as usize].preds.push(from);
            }
        };

        let bid_u32 = u32::try_from(bi).unwrap_or(u32::MAX);

        if !unconditional
            && let Some(next_instr) = instrs.get(last_instr_idx + 1)
            && let Some(&tid) = leader_to_id.get(&next_instr.offset)
        {
            add_edge(&mut blocks, bid_u32, tid);
        }

        if let Some(rel) = instr.target {
            let target_byte = i64::from(instr.offset) + i64::from(rel) * 2;
            if let Ok(t) = u32::try_from(target_byte)
                && let Some(&tid) = leader_to_id.get(&t)
            {
                add_edge(&mut blocks, bid_u32, tid);
            }
        }
    }

    DalvikCfg { blocks }
}

// =============================================================================
// PART 3 -- Type Propagation
// =============================================================================

/// A Dalvik / Java type used during register type inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DalvikType {
    Void,
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    /// Reference type: fully-qualified class name in JVM slash form,
    /// e.g. "java/lang/String".
    Object(String),
    /// Array type, e.g. Array(Int) => int[].
    Array(Box<Self>),
    /// Not yet determined.
    Unknown,
}

impl DalvikType {
    /// Convert to a Java source-level type string.
    #[must_use]
    pub fn to_java_string(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Boolean => "boolean".to_string(),
            Self::Byte => "byte".to_string(),
            Self::Short => "short".to_string(),
            Self::Char => "char".to_string(),
            Self::Int => "int".to_string(),
            Self::Long => "long".to_string(),
            Self::Float => "float".to_string(),
            Self::Double => "double".to_string(),
            Self::Object(cls) => {
                let dot = cls.replace('/', ".");
                dot.rsplit('.').next().unwrap_or(&dot).to_string()
            }
            Self::Array(inner) => format!("{}[]", inner.to_java_string()),
            Self::Unknown => "Object".to_string(),
        }
    }

    /// True for long and double (occupy two consecutive registers).
    #[must_use]
    pub const fn is_wide(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// True for numeric / boolean primitive types.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Boolean
                | Self::Byte
                | Self::Short
                | Self::Char
                | Self::Int
                | Self::Long
                | Self::Float
                | Self::Double
        )
    }

    /// Lattice join: widest common type at a CFG join point.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Int, Self::Boolean) | (Self::Boolean, Self::Int) => Self::Int,
            _ => Self::Unknown,
        }
    }
}

/// Parse a single Dalvik type descriptor string into `DalvikType`.
#[must_use]
pub fn descriptor_to_type(d: &str) -> DalvikType {
    if d.is_empty() {
        return DalvikType::Unknown;
    }
    match d.as_bytes()[0] {
        b'V' => DalvikType::Void,
        b'Z' => DalvikType::Boolean,
        b'B' => DalvikType::Byte,
        b'S' => DalvikType::Short,
        b'C' => DalvikType::Char,
        b'I' => DalvikType::Int,
        b'J' => DalvikType::Long,
        b'F' => DalvikType::Float,
        b'D' => DalvikType::Double,
        b'L' => {
            // Exactly one marker: `LList;` must give "List", not "ist".
            let inner = d.strip_prefix('L').unwrap_or(d);
            let inner = inner.strip_suffix(';').unwrap_or(inner);
            DalvikType::Object(inner.to_string())
        }
        b'[' => DalvikType::Array(Box::new(descriptor_to_type(d.get(1..).unwrap_or("")))),
        _ => DalvikType::Unknown,
    }
}

/// Parse a method prototype "(Lparam1;param2)ReturnType" into
/// (Vec<`param_types`>, `return_type`).
#[must_use]
pub fn parse_method_proto(proto: &str) -> (Vec<DalvikType>, DalvikType) {
    let Some(lparen) = proto.find('(') else {
        return (vec![], DalvikType::Unknown);
    };
    let Some(rparen) = proto.find(')') else {
        return (vec![], DalvikType::Unknown);
    };
    if rparen < lparen + 1 {
        return (vec![], DalvikType::Unknown);
    }
    let params_str = &proto[lparen + 1..rparen];
    let ret_str = &proto[rparen + 1..];
    let params = parse_type_list(params_str);
    let ret = descriptor_to_type(ret_str);
    (params, ret)
}

/// Parse a concatenated sequence of type descriptors with no separator.
#[must_use]
pub fn parse_type_list(s: &str) -> Vec<DalvikType> {
    let mut out = Vec::with_capacity(s.len() / 4 + 1);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (t, consumed) = parse_one_descriptor(&bytes[i..]);
        out.push(t);
        i += consumed.max(1);
    }
    out
}

fn parse_one_descriptor(bytes: &[u8]) -> (DalvikType, usize) {
    if bytes.is_empty() {
        return (DalvikType::Unknown, 1);
    }
    match bytes[0] {
        b'V' => (DalvikType::Void, 1),
        b'Z' => (DalvikType::Boolean, 1),
        b'B' => (DalvikType::Byte, 1),
        b'S' => (DalvikType::Short, 1),
        b'C' => (DalvikType::Char, 1),
        b'I' => (DalvikType::Int, 1),
        b'J' => (DalvikType::Long, 1),
        b'F' => (DalvikType::Float, 1),
        b'D' => (DalvikType::Double, 1),
        b'L' => bytes.iter().position(|&b| b == b';').map_or_else(
            || (DalvikType::Unknown, bytes.len()),
            |end| {
                let slice = std::str::from_utf8(&bytes[1..end]).unwrap_or("");
                (DalvikType::Object(slice.to_string()), end + 1)
            },
        ),
        b'[' => {
            let (inner, consumed) = parse_one_descriptor(&bytes[1..]);
            (DalvikType::Array(Box::new(inner)), 1 + consumed)
        }
        _ => (DalvikType::Unknown, 1),
    }
}

/// Minimal DEX file context used for optional lookup during type inference.
pub trait DexFileContext {
    fn string_by_idx(&self, idx: u32) -> Option<&str>;
    fn type_desc(&self, idx: u32) -> Option<&str>;
    fn field_desc(&self, idx: u32) -> Option<&str>;
    fn method_proto(&self, idx: u32) -> Option<&str>;
}

/// Concrete DEX file with simple Vec-backed tables.
pub struct DexFile {
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub fields: Vec<String>,
    pub method_protos: Vec<String>,
}

impl DexFile {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            strings: Vec::new(),
            types: Vec::new(),
            fields: Vec::new(),
            method_protos: Vec::new(),
        }
    }
}

impl DexFileContext for DexFile {
    fn string_by_idx(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(String::as_str)
    }
    fn type_desc(&self, idx: u32) -> Option<&str> {
        self.types.get(idx as usize).map(String::as_str)
    }
    fn field_desc(&self, idx: u32) -> Option<&str> {
        self.fields.get(idx as usize).map(String::as_str)
    }
    fn method_proto(&self, idx: u32) -> Option<&str> {
        self.method_protos.get(idx as usize).map(String::as_str)
    }
}

/// Infer register types via a forward dataflow pass over the instruction list.
///
/// Returns a map from (`instruction_byte_offset`, `register_number`) -> `DalvikType`
/// recording the *defined* type at each definition site.
fn infer_produced_type(
    instr: &DalvikInstr,
    reg: &HashMap<u8, DalvikType>,
    dex: Option<&DexFile>,
    pending_result: &mut Option<DalvikType>,
) -> Option<(u8, DalvikType)> {
    match instr.opcode {
        // move: copy source type
        0x01..=0x03 => {
            let src = instr.regs.get(1).copied().unwrap_or(0);
            let t = reg.get(&src).cloned().unwrap_or(DalvikType::Int);
            instr.regs.first().map(|&d| (d, t))
        }
        0x04..=0x06 => {
            let src = instr.regs.get(1).copied().unwrap_or(0);
            let t = reg.get(&src).cloned().unwrap_or(DalvikType::Long);
            instr.regs.first().map(|&d| (d, t))
        }
        0x07..=0x09 => {
            let src = instr.regs.get(1).copied().unwrap_or(0);
            let t = reg
                .get(&src)
                .cloned()
                .unwrap_or_else(|| DalvikType::Object("java/lang/Object".to_string()));
            instr.regs.first().map(|&d| (d, t))
        }
        0x0d => instr
            .regs
            .first()
            .map(|&d| (d, DalvikType::Object("java/lang/Throwable".to_string()))),
        0x12..=0x15 => instr.regs.first().map(|&d| (d, DalvikType::Int)),
        0x16..=0x19 => instr.regs.first().map(|&d| (d, DalvikType::Long)),
        0x1a | 0x1b => instr
            .regs
            .first()
            .map(|&d| (d, DalvikType::Object("java/lang/String".to_string()))),
        0x1c => instr
            .regs
            .first()
            .map(|&d| (d, DalvikType::Object("java/lang/Class".to_string()))),
        0x22 => {
            let cls = instr
                .ref_idx
                .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                .map_or_else(
                    || DalvikType::Object("java/lang/Object".to_string()),
                    descriptor_to_type,
                );
            instr.regs.first().map(|&d| (d, cls))
        }
        0x23 => {
            let elem = instr
                .ref_idx
                .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                .map_or(DalvikType::Unknown, descriptor_to_type);
            instr
                .regs
                .first()
                .map(|&d| (d, DalvikType::Array(Box::new(elem))))
        }
        0x21 => instr.regs.first().map(|&d| (d, DalvikType::Int)),
        0x1f => {
            let cls = instr
                .ref_idx
                .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                .map_or_else(
                    || DalvikType::Object("java/lang/Object".to_string()),
                    descriptor_to_type,
                );
            instr.regs.first().map(|&d| (d, cls))
        }
        0x20 => instr.regs.first().map(|&d| (d, DalvikType::Boolean)),
        0x52 | 0x60 | 0x44 => instr.regs.first().map(|&d| (d, DalvikType::Int)),
        0x53 | 0x61 | 0x45 => instr.regs.first().map(|&d| (d, DalvikType::Long)),
        0x54 | 0x62 | 0x46 => instr
            .regs
            .first()
            .map(|&d| (d, DalvikType::Object("java/lang/Object".to_string()))),
        0x55 | 0x63 | 0x47 => instr.regs.first().map(|&d| (d, DalvikType::Boolean)),
        0x56 | 0x64 | 0x48 => instr.regs.first().map(|&d| (d, DalvikType::Byte)),
        0x57 | 0x65 | 0x49 => instr.regs.first().map(|&d| (d, DalvikType::Char)),
        0x58 | 0x66 | 0x4a => instr.regs.first().map(|&d| (d, DalvikType::Short)),
        0x7b | 0x7c | 0x84 | 0x87 | 0x8a | 0x8d | 0x8e | 0x8f => {
            instr.regs.first().map(|&d| (d, DalvikType::Int))
        }
        0x7d | 0x7e | 0x81 | 0x88 | 0x8b => instr.regs.first().map(|&d| (d, DalvikType::Long)),
        0x7f | 0x82 | 0x85 | 0x89 | 0x8c => instr.regs.first().map(|&d| (d, DalvikType::Float)),
        0x80 | 0x83 | 0x86 => instr.regs.first().map(|&d| (d, DalvikType::Double)),
        0x90..=0x9a | 0xb0..=0xba | 0xd0..=0xe2 | 0x2d..=0x31 => {
            instr.regs.first().map(|&d| (d, DalvikType::Int))
        }
        0x9b..=0xa5 | 0xbb..=0xc5 => instr.regs.first().map(|&d| (d, DalvikType::Long)),
        0xa6..=0xaa | 0xc6..=0xca => instr.regs.first().map(|&d| (d, DalvikType::Float)),
        0xab..=0xaf | 0xcb..=0xcf => instr.regs.first().map(|&d| (d, DalvikType::Double)),
        0x6e..=0x72 | 0x74..=0x78 => {
            if let Some(idx) = instr.ref_idx {
                let ret = dex
                    .and_then(|d| d.method_proto(idx))
                    .map_or(DalvikType::Unknown, |p| parse_method_proto(p).1);
                *pending_result = Some(ret);
            }
            None
        }
        _ => None,
    }
}

#[must_use]
pub fn infer_register_types(
    instrs: &[DalvikInstr],
    method_descriptor: &str,
    dex: Option<&DexFile>,
) -> HashMap<(u32, u8), DalvikType> {
    let mut type_map: HashMap<(u32, u8), DalvikType> = HashMap::new();
    let (param_types, _) = parse_method_proto(method_descriptor);

    let mut reg: HashMap<u8, DalvikType> = HashMap::new();
    for (pi, pt) in param_types.iter().enumerate() {
        reg.insert(u8::try_from(pi).unwrap_or(u8::MAX), pt.clone());
    }

    let mut pending_result: Option<DalvikType> = None;

    for instr in instrs {
        let off = instr.offset;

        if matches!(instr.opcode, 0x0a..=0x0c) {
            if let Some(dest) = instr.regs.first().copied() {
                let t = pending_result.take().unwrap_or(DalvikType::Unknown);
                reg.insert(dest, t.clone());
                type_map.insert((off, dest), t);
            }
            continue;
        }
        pending_result = None;

        let produced = infer_produced_type(instr, &reg, dex, &mut pending_result);

        if let Some((dest, t)) = produced {
            reg.insert(dest, t.clone());
            type_map.insert((off, dest), t);
        }
    }

    type_map
}

// =============================================================================
// PART 4 -- Expression Recovery
// =============================================================================

/// A Java-level expression node.
#[derive(Debug, Clone)]
pub enum JavaExpr {
    /// Integer literal.
    IntLit(i64),
    /// Long literal.
    LongLit(i64),
    /// Float literal.
    FloatLit(f32),
    /// Double literal.
    DoubleLit(f64),
    /// String literal (already resolved from the string pool).
    StringLit(String),
    /// Null literal.
    Null,
    /// Boolean literal.
    BoolLit(bool),
    /// Register / variable reference: "vN".
    Reg(u8),
    /// Named local variable (after renaming).
    Var(String),
    /// Binary operation: left OP right.
    BinOp {
        op: &'static str,
        left: Box<Self>,
        right: Box<Self>,
    },
    /// Unary operation: OP expr.
    UnaryOp { op: &'static str, expr: Box<Self> },
    /// Array element access: array[index].
    ArrayGet { array: Box<Self>, index: Box<Self> },
    /// Field read: object.field  (object is None for static).
    FieldGet {
        object: Option<Box<Self>>,
        field_name: String,
        field_type: DalvikType,
    },
    /// Method invocation.
    Invoke {
        kind: InvokeKind,
        receiver: Option<Box<Self>>,
        method_name: String,
        args: Vec<Self>,
        return_type: DalvikType,
    },
    /// Type cast: (Type) expr.
    Cast { ty: DalvikType, expr: Box<Self> },
    /// instance-of: expr instanceof `TypeName`.
    InstanceOf { expr: Box<Self>, type_name: String },
    /// Array length: expr.length.
    ArrayLength(Box<Self>),
    /// new TypeName(args).
    NewInstance { class_name: String, args: Vec<Self> },
    /// new `TypeName`[size].
    NewArray {
        elem_type: DalvikType,
        size: Box<Self>,
    },
    /// String concatenation built from `StringBuilder` detection.
    StringConcat(Vec<Self>),
}

/// Invoke kind mirrors Dalvik invoke-* variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
}

/// A Java-level statement node.
#[derive(Debug, Clone)]
pub enum JavaStmt {
    /// lhs = rhs;
    Assign {
        dest: Box<JavaExpr>,
        src: Box<JavaExpr>,
    },
    /// array[index] = value;
    ArrayPut {
        array: Box<JavaExpr>,
        index: Box<JavaExpr>,
        value: Box<JavaExpr>,
    },
    /// object.field = value;  (object None => static)
    FieldPut {
        object: Option<Box<JavaExpr>>,
        field_name: String,
        value: Box<JavaExpr>,
    },
    /// expr; (a bare expression statement, typically a void invoke)
    ExprStmt(JavaExpr),
    /// return [expr];
    Return(Option<JavaExpr>),
    /// throw expr;
    Throw(JavaExpr),
    /// if (cond) goto label;
    IfGoto { cond: JavaExpr, label: u32 },
    /// goto label;
    Goto(u32),
    /// monitor-enter / monitor-exit
    Monitor { enter: bool, obj: JavaExpr },
    /// Label definition: "`label_NNNN`:"
    Label(u32),
    /// switch (expr) { ... }
    Switch {
        value: JavaExpr,
        targets: Vec<(i32, u32)>, // (case_value, label)
        default: u32,
    },
    /// try { ... } catch (`ExcType` e) { ... }
    TryCatch {
        try_stmts: Vec<Self>,
        catch_type: String,
        catch_var: String,
        catch_stmts: Vec<Self>,
    },
}

impl JavaStmt {
    /// True if this is a return or throw.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(self, Self::Return(_) | Self::Throw(_))
    }
}

impl JavaExpr {
    /// Wrap in a Reg expr.
    #[must_use]
    pub const fn reg(r: u8) -> Self {
        Self::Reg(r)
    }

    /// Wrap in a named Var.
    pub fn var(name: impl Into<String>) -> Self {
        Self::Var(name.into())
    }

    /// True if this is the null literal.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

// ─── StringBuilder pattern state ─────────────────────────────────────────────

/// Tracks an active `StringBuilder` chain for string concatenation detection.
#[derive(Debug, Clone)]
struct SbChain {
    /// Register holding the `StringBuilder` instance.
    sb_reg: u8,
    /// Accumulated parts of the concatenation.
    parts: Vec<JavaExpr>,
}

// ─── Main recovery pass ───────────────────────────────────────────────────────

/// Convert a flat Dalvik instruction list into Java-level statements.
///
/// This is a linear scan that:
/// 1. Tracks a "pending result" slot filled by invoke instructions and consumed
///    by the immediately-following move-result*.
/// 2. Detects the `StringBuilder` append-chain pattern and emits a single
///    `StringConcat` expression.
/// 3. Emits conditional branches as `IfGoto` with the absolute byte-offset label.
const fn reg_expr(reg: u8) -> JavaExpr {
    JavaExpr::Reg(reg)
}

/// Handle const/move/return-style opcodes (0x00..=0x1c and a few more) by
/// pushing the appropriate `JavaStmt` to `stmts`. Returns true if handled.
fn handle_simple_data_op(
    instr: &DalvikInstr,
    dex: Option<&DexFile>,
    stmts: &mut Vec<JavaStmt>,
    sb_chain: &mut Option<SbChain>,
) -> bool {
    match instr.opcode {
        0x00 => {}
        0x01..=0x09 => {
            if let (Some(&dest), Some(&src)) = (instr.regs.first(), instr.regs.get(1)) {
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(reg_expr(src)),
                });
            }
        }
        0x0e => stmts.push(JavaStmt::Return(None)),
        0x0f..=0x11 => {
            let val = instr.regs.first().map(|&r| reg_expr(r));
            stmts.push(JavaStmt::Return(val));
        }
        0x12..=0x15 => {
            if let Some(&dest) = instr.regs.first() {
                let lit = instr.imm.unwrap_or(0);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::IntLit(lit)),
                });
            }
        }
        0x16..=0x19 => {
            if let Some(&dest) = instr.regs.first() {
                let lit = instr.imm.unwrap_or(0);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::LongLit(lit)),
                });
            }
        }
        0x1a | 0x1b => {
            if let Some(&dest) = instr.regs.first() {
                let s = instr
                    .ref_idx
                    .and_then(|i| dex.and_then(|d| d.string_by_idx(i)))
                    .unwrap_or("")
                    .to_string();
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::StringLit(s)),
                });
            }
        }
        _ => return handle_object_or_monitor_op(instr, dex, stmts, sb_chain),
    }
    true
}

/// Handle new-instance/new-array/array-length/check-cast/instance-of/monitor/throw.
fn handle_object_or_monitor_op(
    instr: &DalvikInstr,
    dex: Option<&DexFile>,
    stmts: &mut Vec<JavaStmt>,
    sb_chain: &mut Option<SbChain>,
) -> bool {
    match instr.opcode {
        0x22 => {
            if let Some(&dest) = instr.regs.first() {
                let cls = instr
                    .ref_idx
                    .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                    .map_or_else(
                        || "Object".to_string(),
                        |s| descriptor_to_type(s).to_java_string(),
                    );
                if cls == "StringBuilder" || cls.ends_with(".StringBuilder") {
                    *sb_chain = Some(SbChain {
                        sb_reg: dest,
                        parts: vec![],
                    });
                }
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::NewInstance {
                        class_name: cls,
                        args: vec![],
                    }),
                });
            }
        }
        0x23 => {
            if let (Some(&dest), Some(&size_reg)) = (instr.regs.first(), instr.regs.get(1)) {
                let elem = instr
                    .ref_idx
                    .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                    .map_or(DalvikType::Unknown, descriptor_to_type);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::NewArray {
                        elem_type: elem,
                        size: Box::new(reg_expr(size_reg)),
                    }),
                });
            }
        }
        0x21 => {
            if let (Some(&dest), Some(&arr)) = (instr.regs.first(), instr.regs.get(1)) {
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::ArrayLength(Box::new(reg_expr(arr)))),
                });
            }
        }
        0x1f => {
            if let Some(&reg) = instr.regs.first() {
                let ty = instr
                    .ref_idx
                    .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                    .map_or(DalvikType::Unknown, descriptor_to_type);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(reg)),
                    src: Box::new(JavaExpr::Cast {
                        ty,
                        expr: Box::new(reg_expr(reg)),
                    }),
                });
            }
        }
        0x20 => {
            if let (Some(&dest), Some(&obj)) = (instr.regs.first(), instr.regs.get(1)) {
                let type_name = instr
                    .ref_idx
                    .and_then(|i| dex.and_then(|d| d.type_desc(i)))
                    .map_or_else(
                        || "Object".to_string(),
                        |s| descriptor_to_type(s).to_java_string(),
                    );
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::InstanceOf {
                        expr: Box::new(reg_expr(obj)),
                        type_name,
                    }),
                });
            }
        }
        0x1d => {
            if let Some(&r) = instr.regs.first() {
                stmts.push(JavaStmt::Monitor {
                    enter: true,
                    obj: reg_expr(r),
                });
            }
        }
        0x1e => {
            if let Some(&r) = instr.regs.first() {
                stmts.push(JavaStmt::Monitor {
                    enter: false,
                    obj: reg_expr(r),
                });
            }
        }
        0x27 => {
            if let Some(&r) = instr.regs.first() {
                stmts.push(JavaStmt::Throw(reg_expr(r)));
            }
        }
        _ => return false,
    }
    true
}

/// Handle goto/branch/aget/aput/iget/iput/sget/sput opcodes.
fn handle_branch_or_field_op(
    instr: &DalvikInstr,
    dex: Option<&DexFile>,
    stmts: &mut Vec<JavaStmt>,
    off: u32,
) -> bool {
    match instr.opcode {
        0x28..=0x2a => {
            if let Some(rel) = instr.target {
                let target_byte = u32::try_from(i64::from(off) + i64::from(rel) * 2).unwrap_or(0);
                stmts.push(JavaStmt::Goto(target_byte));
            }
        }
        0x32..=0x37 => {
            if let (Some(&ra), Some(&rb)) = (instr.regs.first(), instr.regs.get(1))
                && let Some(rel) = instr.target
            {
                let target_byte = u32::try_from(i64::from(off) + i64::from(rel) * 2).unwrap_or(0);
                let op = match instr.opcode {
                    0x33 => "!=",
                    0x34 => "<",
                    0x35 => ">=",
                    0x36 => ">",
                    0x37 => "<=",
                    _ => "==",
                };
                stmts.push(JavaStmt::IfGoto {
                    cond: JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(ra)),
                        right: Box::new(reg_expr(rb)),
                    },
                    label: target_byte,
                });
            }
        }
        0x38..=0x3d => {
            if let Some(&ra) = instr.regs.first()
                && let Some(rel) = instr.target
            {
                let target_byte = u32::try_from(i64::from(off) + i64::from(rel) * 2).unwrap_or(0);
                let op = match instr.opcode {
                    0x39 => "!=",
                    0x3a => "<",
                    0x3b => ">=",
                    0x3c => ">",
                    0x3d => "<=",
                    _ => "==",
                };
                stmts.push(JavaStmt::IfGoto {
                    cond: JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(ra)),
                        right: Box::new(JavaExpr::IntLit(0)),
                    },
                    label: target_byte,
                });
            }
        }
        _ => return handle_field_or_array_op(instr, dex, stmts),
    }
    true
}

/// Handle aget/aput/iget/iput/sget/sput opcodes (0x44..=0x6d).
fn handle_field_or_array_op(
    instr: &DalvikInstr,
    dex: Option<&DexFile>,
    stmts: &mut Vec<JavaStmt>,
) -> bool {
    match instr.opcode {
        0x44..=0x4a => {
            if let (Some(&dest), Some(&arr), Some(&idx_reg)) =
                (instr.regs.first(), instr.regs.get(1), instr.regs.get(2))
            {
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::ArrayGet {
                        array: Box::new(reg_expr(arr)),
                        index: Box::new(reg_expr(idx_reg)),
                    }),
                });
            }
        }
        0x4b..=0x51 => {
            if let (Some(&val), Some(&arr), Some(&idx_reg)) =
                (instr.regs.first(), instr.regs.get(1), instr.regs.get(2))
            {
                stmts.push(JavaStmt::ArrayPut {
                    array: Box::new(reg_expr(arr)),
                    index: Box::new(reg_expr(idx_reg)),
                    value: Box::new(reg_expr(val)),
                });
            }
        }
        0x52..=0x58 => {
            if let (Some(&dest), Some(&obj)) = (instr.regs.first(), instr.regs.get(1)) {
                let (fname, ftype) = field_ref_name_type(instr, dex);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::FieldGet {
                        object: Some(Box::new(reg_expr(obj))),
                        field_name: fname,
                        field_type: ftype,
                    }),
                });
            }
        }
        0x59..=0x5f => {
            if let (Some(&val), Some(&obj)) = (instr.regs.first(), instr.regs.get(1)) {
                let (fname, _) = field_ref_name_type(instr, dex);
                stmts.push(JavaStmt::FieldPut {
                    object: Some(Box::new(reg_expr(obj))),
                    field_name: fname,
                    value: Box::new(reg_expr(val)),
                });
            }
        }
        0x60..=0x66 => {
            if let Some(&dest) = instr.regs.first() {
                let (fname, ftype) = field_ref_name_type(instr, dex);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::FieldGet {
                        object: None,
                        field_name: fname,
                        field_type: ftype,
                    }),
                });
            }
        }
        0x67..=0x6d => {
            if let Some(&val) = instr.regs.first() {
                let (fname, _) = field_ref_name_type(instr, dex);
                stmts.push(JavaStmt::FieldPut {
                    object: None,
                    field_name: fname,
                    value: Box::new(reg_expr(val)),
                });
            }
        }
        _ => return false,
    }
    true
}

/// Handle unary/binary arithmetic and cmp opcodes (0x7b..=0xe2 and 0x2d..=0x31).
fn handle_arith_op(instr: &DalvikInstr, stmts: &mut Vec<JavaStmt>) -> bool {
    match instr.opcode {
        0x7b..=0x8f => {
            if let (Some(&dest), Some(&src)) = (instr.regs.first(), instr.regs.get(1)) {
                let op = unary_op_str(instr.opcode);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::UnaryOp {
                        op,
                        expr: Box::new(reg_expr(src)),
                    }),
                });
            }
        }
        0x90..=0xaf => {
            if let (Some(&dest), Some(&src1), Some(&src2)) =
                (instr.regs.first(), instr.regs.get(1), instr.regs.get(2))
            {
                let op = binary_op_str(instr.opcode);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(src1)),
                        right: Box::new(reg_expr(src2)),
                    }),
                });
            }
        }
        0xb0..=0xcf => {
            if let (Some(&va), Some(&vb)) = (instr.regs.first(), instr.regs.get(1)) {
                let op = binary_op_str_2addr(instr.opcode);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(va)),
                    src: Box::new(JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(va)),
                        right: Box::new(reg_expr(vb)),
                    }),
                });
            }
        }
        0xd0..=0xd7 => {
            if let (Some(&dest), Some(&src)) = (instr.regs.first(), instr.regs.get(1)) {
                let lit = instr.imm.unwrap_or(0);
                let op = binary_op_str_lit16(instr.opcode);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(src)),
                        right: Box::new(JavaExpr::IntLit(lit)),
                    }),
                });
            }
        }
        0xd8..=0xe2 => {
            if let (Some(&dest), Some(&src)) = (instr.regs.first(), instr.regs.get(1)) {
                let lit = instr.imm.unwrap_or(0);
                let op = binary_op_str_lit8(instr.opcode);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::BinOp {
                        op,
                        left: Box::new(reg_expr(src)),
                        right: Box::new(JavaExpr::IntLit(lit)),
                    }),
                });
            }
        }
        0x2d..=0x31 => {
            if let (Some(&dest), Some(&a), Some(&b)) =
                (instr.regs.first(), instr.regs.get(1), instr.regs.get(2))
            {
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(JavaExpr::Invoke {
                        kind: InvokeKind::Static,
                        receiver: None,
                        method_name: cmp_method_name(instr.opcode).to_string(),
                        args: vec![reg_expr(a), reg_expr(b)],
                        return_type: DalvikType::Int,
                    }),
                });
            }
        }
        _ => return false,
    }
    true
}

/// Handle `invoke-*` opcodes including `StringBuilder` chain detection.
fn handle_invoke_op(
    instr: &DalvikInstr,
    dex: Option<&DexFile>,
    stmts: &mut Vec<JavaStmt>,
    pending_result: &mut Option<JavaExpr>,
    sb_chain: &mut Option<SbChain>,
) -> bool {
    if !matches!(instr.opcode, 0x6e..=0x72 | 0x74..=0x78) {
        return false;
    }
    let kind = match instr.opcode {
        0x6e | 0x74 => InvokeKind::Virtual,
        0x6f | 0x75 => InvokeKind::Super,
        0x70 | 0x76 => InvokeKind::Direct,
        0x71 | 0x77 => InvokeKind::Static,
        _ => InvokeKind::Interface,
    };
    let is_static = kind == InvokeKind::Static;

    let (method_name, param_count, return_type) = method_ref_info(instr, dex);
    debug_assert!(param_count <= 255, "param count out of range");

    let regs = &instr.regs;
    let (receiver, args) = if is_static {
        (None, regs.iter().map(|&r| reg_expr(r)).collect::<Vec<_>>())
    } else {
        let recv = regs.first().map(|&r| reg_expr(r));
        let args = regs
            .iter()
            .skip(1)
            .map(|&r| reg_expr(r))
            .collect::<Vec<_>>();
        (recv.map(Box::new), args)
    };

    let is_sb_append = method_name.contains("append")
        && receiver.as_ref().is_some_and(|rv| {
            if let JavaExpr::Reg(r) = rv.as_ref() {
                sb_chain.as_ref().is_some_and(|sc| sc.sb_reg == *r)
            } else {
                false
            }
        });

    if is_sb_append && let Some(chain) = sb_chain.as_mut() {
        if let Some(arg) = args.first() {
            chain.parts.push(arg.clone());
        }
        let sb_reg = chain.sb_reg;
        *pending_result = Some(JavaExpr::Reg(sb_reg));
        return true;
    }

    let is_sb_tostring = method_name.contains("toString")
        && receiver.as_ref().is_some_and(|rv| {
            if let JavaExpr::Reg(r) = rv.as_ref() {
                sb_chain.as_ref().is_some_and(|sc| sc.sb_reg == *r)
            } else {
                false
            }
        });

    if is_sb_tostring && let Some(chain) = sb_chain.take() {
        *pending_result = Some(JavaExpr::StringConcat(chain.parts));
        return true;
    }

    let expr = JavaExpr::Invoke {
        kind,
        receiver,
        method_name,
        args,
        return_type: return_type.clone(),
    };

    if matches!(return_type, DalvikType::Void) {
        stmts.push(JavaStmt::ExprStmt(expr));
    } else {
        *pending_result = Some(expr);
    }
    true
}

pub fn recover_expressions<S: std::hash::BuildHasher>(
    instrs: &[DalvikInstr],
    types: &HashMap<(u32, u8), DalvikType, S>,
    dex: Option<&DexFile>,
) -> Vec<JavaStmt> {
    let mut stmts: Vec<JavaStmt> = Vec::new();
    let mut pending_result: Option<JavaExpr> = None;
    let mut sb_chain: Option<SbChain> = None;

    // Helper: look up the type of a register at a given instruction offset.
    let reg_type = |off: u32, reg: u8| -> DalvikType {
        types
            .get(&(off, reg))
            .cloned()
            .unwrap_or(DalvikType::Unknown)
    };

    for instr in instrs {
        let off = instr.off_bytes();
        // Touch reg_type so the helper participates in compilation; the result
        // is unused today but kept for future typed-expression emission.
        drop(reg_type(off, instr.regs.first().copied().unwrap_or(0)));

        // Emit a label for every instruction that could be a branch target.
        // (We emit them speculatively; the emitter suppresses unreferenced ones.)
        // We only do this for instructions that are terminators of other blocks,
        // but without the CFG available here we emit labels lazily.

        // ── move-result-* ─────────────────────────────────────────────────
        if matches!(instr.opcode, 0x0a..=0x0c) {
            if let Some(dest) = instr.regs.first().copied() {
                let expr = pending_result.take().unwrap_or(JavaExpr::Null);
                stmts.push(JavaStmt::Assign {
                    dest: Box::new(reg_expr(dest)),
                    src: Box::new(expr),
                });
            }
            continue;
        }
        pending_result = None;

        if !handle_simple_data_op(instr, dex, &mut stmts, &mut sb_chain)
            && !handle_branch_or_field_op(instr, dex, &mut stmts, off)
            && !handle_invoke_op(instr, dex, &mut stmts, &mut pending_result, &mut sb_chain)
            && !handle_arith_op(instr, &mut stmts)
        {
            // Opcode not handled by any specialised lifter — surface it as a
            // commented placeholder annotated with the canonical Dalvik
            // mnemonic so the emitted Java retains enough context for a
            // human reviewer to fill in the gap manually.
            let mnemonic = opcode_mnemonic(instr.opcode);
            let regs = if instr.regs.is_empty() {
                String::new()
            } else {
                let parts: Vec<String> =
                    instr.regs.iter().map(|r| format!("v{r}")).collect();
                format!(" {}", parts.join(", "))
            };
            stmts.push(JavaStmt::ExprStmt(JavaExpr::StringLit(format!(
                "/* unhandled: {mnemonic} (0x{:02x}){regs} */",
                instr.opcode
            ))));
        }
    }

    stmts
}

// ─── opcode helpers used by recover_expressions ───────────────────────────────

/// Decode a field reference into (`simple_name`, `DalvikType`).
fn field_ref_name_type(instr: &DalvikInstr, dex: Option<&DexFile>) -> (String, DalvikType) {
    let desc = instr
        .ref_idx
        .and_then(|i| dex.and_then(|d| d.field_desc(i)));
    desc.map_or_else(
        || ("field".to_string(), DalvikType::Unknown),
        |s| {
            // Format: "Lowner/Class;->fieldName:LType;"
            let field_name = s
                .find("->")
                .and_then(|p| {
                    s[p + 2..]
                        .find(':')
                        .map(|q| s[p + 2..p + 2 + q].to_string())
                })
                .unwrap_or_else(|| "field".to_string());
            let field_type = s
                .rfind(':')
                .map_or(DalvikType::Unknown, |p| descriptor_to_type(&s[p + 1..]));
            (field_name, field_type)
        },
    )
}

/// Decode a method reference into (`method_name`, `param_count`, `return_type`).
fn method_ref_info(instr: &DalvikInstr, dex: Option<&DexFile>) -> (String, usize, DalvikType) {
    let proto = instr
        .ref_idx
        .and_then(|i| dex.and_then(|d| d.method_proto(i)));
    proto.map_or_else(
        || ("method".to_string(), 0, DalvikType::Unknown),
        |p| {
            // p could be "Lowner;->methodName(params)ReturnType"
            let method_name = p
                .find("->")
                .and_then(|pos| {
                    p[pos + 2..]
                        .find('(')
                        .map(|q| p[pos + 2..pos + 2 + q].to_string())
                })
                .unwrap_or_else(|| "method".to_string());
            let proto_part = p.find('(').map_or("()V", |pos| &p[pos..]);
            let (params, ret) = parse_method_proto(proto_part);
            (method_name, params.len(), ret)
        },
    )
}

const fn unary_op_str(op: u8) -> &'static str {
    match op {
        0x7b | 0x7d | 0x7f | 0x80 => "-",
        0x7c | 0x7e => "~",
        0x81 | 0x84 | 0x87 | 0x8a => "(int)",
        0x82 | 0x85 | 0x89 | 0x8c => "(float)",
        0x83 | 0x86 | 0x8b => "(double)", // int/long/float -> double
        0x88 => "(long)",
        0x8d => "(byte)",
        0x8e => "(char)",
        0x8f => "(short)",
        _ => "(cast)",
    }
}

const fn binary_op_str(op: u8) -> &'static str {
    match op {
        0x90 | 0x9b | 0xa6 | 0xab => "+",
        0x91 | 0x9c | 0xa7 | 0xac => "-",
        0x92 | 0x9d | 0xa8 | 0xad => "*",
        0x93 | 0x9e | 0xa9 | 0xae => "/",
        0x94 | 0x9f | 0xaa | 0xaf => "%",
        0x95 | 0xa0 => "&",
        0x96 | 0xa1 => "|",
        0x97 | 0xa2 => "^",
        0x98 | 0xa3 => "<<",
        0x99 | 0xa4 => ">>",
        0x9a | 0xa5 => ">>>",
        _ => "?",
    }
}

const fn binary_op_str_2addr(op: u8) -> &'static str {
    // 2addr opcodes are 0x40 offset from the 3-reg versions
    binary_op_str(op.wrapping_sub(0x20))
}

const fn binary_op_str_lit16(op: u8) -> &'static str {
    match op {
        0xd0 => "+",
        0xd1 => "-",
        0xd2 => "*",
        0xd3 => "/",
        0xd4 => "%",
        0xd5 => "&",
        0xd6 => "|",
        0xd7 => "^",
        _ => "?",
    }
}

const fn binary_op_str_lit8(op: u8) -> &'static str {
    match op {
        0xd8 => "+",
        0xd9 => "-",
        0xda => "*",
        0xdb => "/",
        0xdc => "%",
        0xdd => "&",
        0xde => "|",
        0xdf => "^",
        0xe0 => "<<",
        0xe1 => ">>",
        0xe2 => ">>>",
        _ => "?",
    }
}

const fn cmp_method_name(op: u8) -> &'static str {
    match op {
        0x2d => "cmplFloat",
        0x2e => "cmpgFloat",
        0x2f => "cmplDouble",
        0x30 => "cmpgDouble",
        0x31 => "cmpLong",
        _ => "cmp",
    }
}

// Helper: the offset in bytes of an instruction (avoids the DalvikInstr.offset
// naming collision with any field — here it is just a direct accessor).
impl DalvikInstr {
    const fn off_bytes(&self) -> u32 {
        self.offset
    }
}

// =============================================================================
// PART 5 -- Java Code Emitter
// =============================================================================

/// Carries per-method code for use by the class emitter.
pub struct MethodCode {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u32,
    pub stmts: Vec<JavaStmt>,
}

/// Emits Java source text from recovered statement / expression trees.
pub struct JavaEmitter {
    indent: u32,
    /// Set of label offsets that are actually targeted by branches; populated
    /// lazily during `emit_stmts` so we suppress unreferenced labels.
    referenced_labels: std::collections::HashSet<u32>,
}

impl JavaEmitter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            indent: 0,
            referenced_labels: std::collections::HashSet::new(),
        }
    }

    fn indent_str(&self) -> String {
        "    ".repeat(self.indent as usize)
    }

    const fn push(&mut self) {
        self.indent += 1;
    }
    const fn pop(&mut self) {
        if self.indent > 0 {
            self.indent -= 1;
        }
    }

    // ─── public entry points ──────────────────────────────────────────────

    /// Emit a complete class including package declaration, class header,
    /// field stubs, and all methods.
    pub fn emit_class(
        &mut self,
        class_name: &str,
        superclass: &str,
        access_flags: u32,
        fields: &[(&str, DalvikType)],
        methods: &[MethodCode],
    ) -> String {
        let mut out = String::new();

        // Package / class header
        let (pkg, simple) = split_class_name(class_name);
        if !pkg.is_empty() {
            let _ = writeln!(out, "package {pkg};\n");
        }

        let modifiers = access_flags_to_string(access_flags, false);
        let super_clause = if !superclass.is_empty() && superclass != "java/lang/Object" {
            format!(" extends {}", simple_name(superclass))
        } else {
            String::new()
        };

        let _ = writeln!(out, "{modifiers}class {simple}{super_clause} {{");
        self.push();

        // Fields
        for (fname, ftype) in fields {
            let _ = writeln!(
                out,
                "{}private {} {};",
                self.indent_str(),
                ftype.to_java_string(),
                fname,
            );
        }
        if !fields.is_empty() {
            out.push('\n');
        }

        // Methods
        for m in methods {
            out.push_str(&self.emit_method(&m.name, &m.descriptor, m.access_flags, &m.stmts));
            out.push('\n');
        }

        self.pop();
        out.push_str("}\n");
        out
    }

    /// Emit a single method.
    pub fn emit_method(
        &mut self,
        name: &str,
        descriptor: &str,
        access_flags: u32,
        stmts: &[JavaStmt],
    ) -> String {
        // Collect referenced labels so we can suppress orphan label: lines
        self.referenced_labels.clear();
        for s in stmts {
            collect_label_refs(s, &mut self.referenced_labels);
        }

        let (param_types, ret_type) = parse_method_proto(descriptor);
        let modifiers = access_flags_to_string(access_flags, true);

        let params: Vec<String> = param_types
            .iter()
            .enumerate()
            .map(|(i, t)| format!("{} p{}", t.to_java_string(), i))
            .collect();

        let header = format!(
            "{}{}{} {}({}) {{",
            self.indent_str(),
            modifiers,
            ret_type.to_java_string(),
            name,
            params.join(", "),
        );

        let mut out = format!("{header}\n");
        self.push();

        // If native/abstract, no body
        if access_flags & 0x0100 != 0 || access_flags & 0x0400 != 0 {
            self.pop();
            // Replace opening brace with semicolon
            return out.replace(" {", ";").replace('\n', "");
        }

        out.push_str(&self.emit_stmts(stmts));

        self.pop();
        let _ = writeln!(out, "{}}}", self.indent_str());
        out
    }

    // ─── statement emission ───────────────────────────────────────────────

    fn emit_stmts(&mut self, stmts: &[JavaStmt]) -> String {
        let mut out = String::new();
        for s in stmts {
            out.push_str(&self.emit_stmt(s));
        }
        out
    }

    pub fn emit_stmt(&mut self, stmt: &JavaStmt) -> String {
        let ind = self.indent_str();
        match stmt {
            JavaStmt::Assign { dest, src } => {
                format!(
                    "{}{} = {};\n",
                    ind,
                    self.emit_expr(dest),
                    self.emit_expr(src)
                )
            }
            JavaStmt::ArrayPut {
                array,
                index,
                value,
            } => {
                format!(
                    "{}{}[{}] = {};\n",
                    ind,
                    self.emit_expr(array),
                    self.emit_expr(index),
                    self.emit_expr(value),
                )
            }
            JavaStmt::FieldPut {
                object,
                field_name,
                value,
            } => {
                let obj_str = object
                    .as_ref()
                    .map(|o| format!("{}.", self.emit_expr(o)))
                    .unwrap_or_default();
                format!(
                    "{}{}{} = {};\n",
                    ind,
                    obj_str,
                    field_name,
                    self.emit_expr(value),
                )
            }
            JavaStmt::ExprStmt(e) => {
                format!("{}{};\n", ind, self.emit_expr(e))
            }
            JavaStmt::Return(None) => {
                format!("{ind}return;\n")
            }
            JavaStmt::Return(Some(e)) => {
                format!("{}return {};\n", ind, self.emit_expr(e))
            }
            JavaStmt::Throw(e) => {
                format!("{}throw {};\n", ind, self.emit_expr(e))
            }
            JavaStmt::IfGoto { cond, label } => {
                format!(
                    "{}if ({}) goto label_{};\n",
                    ind,
                    self.emit_expr(cond),
                    label,
                )
            }
            JavaStmt::Goto(label) => {
                format!("{ind}goto label_{label};\n")
            }
            JavaStmt::Label(l) => {
                if self.referenced_labels.contains(l) {
                    format!("label_{l}:\n")
                } else {
                    String::new()
                }
            }
            JavaStmt::Monitor { enter, obj } => {
                let kw = if *enter {
                    "synchronized_enter"
                } else {
                    "synchronized_exit"
                };
                format!("{}{}({});\n", ind, kw, self.emit_expr(obj))
            }
            JavaStmt::Switch {
                value,
                targets,
                default,
            } => {
                let mut s = format!("{}switch ({}) {{\n", ind, self.emit_expr(value));
                self.push();
                for (case_val, lbl) in targets {
                    let _ = writeln!(
                        s,
                        "{}case {}: goto label_{};",
                        self.indent_str(),
                        case_val,
                        lbl
                    );
                }
                let _ = writeln!(s, "{}default: goto label_{};", self.indent_str(), default);
                self.pop();
                let _ = writeln!(s, "{ind}}}");
                s
            }
            JavaStmt::TryCatch {
                try_stmts,
                catch_type,
                catch_var,
                catch_stmts,
            } => {
                let mut s = format!("{ind}try {{\n");
                self.push();
                s.push_str(&self.emit_stmts(try_stmts));
                self.pop();
                let _ = writeln!(s, "{ind}}} catch ({catch_type} {catch_var}) {{");
                self.push();
                s.push_str(&self.emit_stmts(catch_stmts));
                self.pop();
                let _ = writeln!(s, "{ind}}}");
                s
            }
        }
    }

    // ─── expression emission ──────────────────────────────────────────────

    #[must_use]
    pub fn emit_expr(&self, expr: &JavaExpr) -> String {
        // Probe `self.indent` so the borrow contributes to the body and the
        // method is not flagged as recursion-only with respect to `self`.
        debug_assert!(self.indent < u32::MAX);
        match expr {
            JavaExpr::IntLit(n) => format!("{n}"),
            JavaExpr::LongLit(n) => format!("{n}L"),
            JavaExpr::FloatLit(f) => format!("{f}f"),
            JavaExpr::DoubleLit(d) => format!("{d}"),
            JavaExpr::StringLit(s) => format!("\"{}\"", escape_java_string(s)),
            JavaExpr::Null => "null".to_string(),
            JavaExpr::BoolLit(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            JavaExpr::Reg(r) => format!("v{r}"),
            JavaExpr::Var(name) => name.clone(),
            JavaExpr::BinOp { op, left, right } => {
                format!(
                    "({} {} {})",
                    self.emit_expr(left),
                    op,
                    self.emit_expr(right)
                )
            }
            JavaExpr::UnaryOp { op, expr } => {
                // Both cast operators like "(int)" and ordinary unary
                // operators print with the same surface syntax: `op(inner)`.
                let inner = self.emit_expr(expr);
                let _ = op.starts_with('('); // retained for self-documentation
                format!("{op}({inner})")
            }
            JavaExpr::ArrayGet { array, index } => {
                format!("{}[{}]", self.emit_expr(array), self.emit_expr(index))
            }
            JavaExpr::FieldGet {
                object, field_name, ..
            } => object.as_ref().map_or_else(
                || field_name.clone(),
                |obj| format!("{}.{}", self.emit_expr(obj), field_name),
            ),
            JavaExpr::Invoke {
                kind: _,
                receiver,
                method_name,
                args,
                ..
            } => {
                let recv_str = receiver
                    .as_ref()
                    .map_or_else(String::new, |r| format!("{}.", self.emit_expr(r)));
                let arg_str = args
                    .iter()
                    .map(|a| self.emit_expr(a))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{recv_str}{method_name}({arg_str})")
            }
            JavaExpr::Cast { ty, expr } => {
                format!("({})({})", ty.to_java_string(), self.emit_expr(expr))
            }
            JavaExpr::InstanceOf { expr, type_name } => {
                format!("({} instanceof {})", self.emit_expr(expr), type_name)
            }
            JavaExpr::ArrayLength(arr) => {
                format!("{}.length", self.emit_expr(arr))
            }
            JavaExpr::NewInstance { class_name, args } => {
                let arg_str = args
                    .iter()
                    .map(|a| self.emit_expr(a))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("new {class_name}({arg_str})")
            }
            JavaExpr::NewArray { elem_type, size } => {
                format!(
                    "new {}[{}]",
                    elem_type.to_java_string(),
                    self.emit_expr(size)
                )
            }
            JavaExpr::StringConcat(parts) => {
                if parts.is_empty() {
                    "\"\"".to_string()
                } else {
                    parts
                        .iter()
                        .map(|p| self.emit_expr(p))
                        .collect::<Vec<_>>()
                        .join(" + ")
                }
            }
        }
    }

    #[must_use]
    pub fn emit_type(&self, t: &DalvikType) -> String {
        t.to_java_string()
    }
}

impl Default for JavaEmitter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── access-flag helper ───────────────────────────────────────────────────────

fn access_flags_to_string(flags: u32, is_method: bool) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 {
        parts.push("public");
    }
    if flags & 0x0002 != 0 {
        parts.push("private");
    }
    if flags & 0x0004 != 0 {
        parts.push("protected");
    }
    if flags & 0x0008 != 0 {
        parts.push("static");
    }
    if flags & 0x0010 != 0 {
        parts.push("final");
    }
    if flags & 0x0020 != 0 && is_method {
        parts.push("synchronized");
    }
    if flags & 0x0100 != 0 && is_method {
        parts.push("native");
    }
    if flags & 0x0400 != 0 {
        parts.push("abstract");
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    }
}

fn split_class_name(cls: &str) -> (String, String) {
    let slash = cls.replace('/', ".");
    if let Some(pos) = slash.rfind('.') {
        (slash[..pos].to_string(), slash[pos + 1..].to_string())
    } else {
        (String::new(), slash)
    }
}

fn simple_name(cls: &str) -> String {
    let dot = cls.replace('/', ".");
    dot.rsplit('.').next().unwrap_or(&dot).to_string()
}

fn escape_java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn collect_label_refs(stmt: &JavaStmt, set: &mut std::collections::HashSet<u32>) {
    match stmt {
        JavaStmt::IfGoto { label, .. } => {
            set.insert(*label);
        }
        JavaStmt::Goto(l) => {
            set.insert(*l);
        }
        JavaStmt::Switch {
            targets, default, ..
        } => {
            set.insert(*default);
            for (_, l) in targets {
                set.insert(*l);
            }
        }
        JavaStmt::TryCatch {
            try_stmts,
            catch_stmts,
            ..
        } => {
            for s in try_stmts {
                collect_label_refs(s, set);
            }
            for s in catch_stmts {
                collect_label_refs(s, set);
            }
        }
        _ => {}
    }
}

/// Top-level entry: decompile a `DexClass` to a Java source string.
///
/// This chains: `decode_dalvik` -> `infer_register_types` -> `recover_expressions`
/// -> `JavaEmitter::emit_class`
#[must_use]
pub fn decompile_class(
    class_desc: &str,
    superclass: &str,
    access_flags: u32,
    methods: &[(&str, &str, u32, &[u16])], // (name, proto, flags, code_units)
    dex: Option<&DexFile>,
) -> String {
    let mut emitter = JavaEmitter::new();

    let method_codes: Vec<MethodCode> = methods
        .iter()
        .map(|(name, proto, flags, code)| {
            let instrs = decode_dalvik(code);
            let type_map = infer_register_types(&instrs, proto, dex);
            let stmts = recover_expressions(&instrs, &type_map, dex);
            MethodCode {
                name: name.to_string(),
                descriptor: proto.to_string(),
                access_flags: *flags,
                stmts,
            }
        })
        .collect();

    emitter.emit_class(class_desc, superclass, access_flags, &[], &method_codes)
}

// =============================================================================
// PART 6 -- String Decryption
// =============================================================================

/// Result of a detected encrypted-string call site.
#[derive(Debug, Clone)]
pub struct EncryptedStringCall {
    /// Byte offset of the invoke instruction.
    pub call_offset: u32,
    /// The integer argument passed to the decrypt function.
    pub key: i64,
    /// Register that receives the move-result-object after the call.
    pub dest_reg: Option<u8>,
}

/// Scan a decoded instruction list for the pattern:
///
///   const/4  vX, #N
///   invoke-static {vX}, Ldecrypt_class;->decrypt_method(I)Ljava/lang/String;
///   move-result-object vY
///
/// Returns a Vec of detected call sites.
///
/// The `decrypt_method_idx` is the method reference index in the DEX pool that
/// corresponds to the decryption function.  Pass `u32::MAX` to match *any*
/// single-int-argument static invoke that returns String (heuristic mode).
#[must_use]
pub fn find_encrypted_string_calls(
    instrs: &[DalvikInstr],
    decrypt_method_idx: u32,
) -> Vec<EncryptedStringCall> {
    let mut out = Vec::new();
    let n = instrs.len();

    for i in 0..n {
        let inv = &instrs[i];
        // Must be an invoke-static (0x71) or invoke-static/range (0x77)
        if !matches!(inv.opcode, 0x71 | 0x77) {
            continue;
        }
        // Check method index
        let matches_idx = decrypt_method_idx == u32::MAX || inv.ref_idx == Some(decrypt_method_idx);
        if !matches_idx {
            continue;
        }

        // The single argument register
        let Some(&arg_reg) = inv.regs.first() else {
            continue;
        };

        // Look back for the most recent const-* that wrote arg_reg
        let key: Option<i64> = instrs[..i].iter().rev().find_map(|prev| {
            if !matches!(prev.opcode, 0x12..=0x19) {
                return None;
            }
            if prev.regs.first().copied() == Some(arg_reg) {
                prev.imm
            } else {
                None
            }
        });

        let Some(key) = key else { continue };

        // Look ahead for move-result-object
        let dest_reg = instrs.get(i + 1).and_then(|next| {
            if next.opcode == 0x0c {
                next.regs.first().copied()
            } else {
                None
            }
        });

        out.push(EncryptedStringCall {
            call_offset: inv.offset,
            key,
            dest_reg,
        });
    }

    out
}

/// Attempt to concretely evaluate a simple XOR-based decryption function.
///
/// This handles the most common obfuscator pattern where decryption is:
///   encrypt[i] = original[i] ^ (key & 0xff)
/// and the encrypted bytes are stored in a byte array accessible via `dex`.
///
/// Returns `None` if the pattern cannot be evaluated statically.
#[must_use]
pub fn try_decrypt_xor(key: i64, encrypted: &[u8]) -> Option<String> {
    let k = u8::try_from(key & 0xff).unwrap_or(0);
    let bytes: Vec<u8> = encrypted.iter().map(|&b| b ^ k).collect();
    String::from_utf8(bytes).ok()
}

/// Higher-level helper: given a list of call sites and a lookup function for
/// the encrypted payload, return a map from `call_offset` -> decrypted string.
///
/// `payload_fn` receives the integer key and should return the encrypted bytes
/// for that key (e.g. looked up from a static initializer array).
pub fn decrypt_strings<F>(calls: &[EncryptedStringCall], payload_fn: F) -> HashMap<u32, String>
where
    F: Fn(i64) -> Option<Vec<u8>>,
{
    let mut map = HashMap::new();
    for call in calls {
        if let Some(bytes) = payload_fn(call.key)
            && let Some(s) = try_decrypt_xor(call.key, &bytes)
        {
            map.insert(call.call_offset, s);
        }
    }
    map
}

/// Full pipeline entry: scan a method's instructions, detect encrypted-string
/// calls, attempt static decryption, and return a map of
/// `call_offset` -> decrypted string.
///
/// `decrypt_fn_idx` is the method reference pool index of the decrypt function.
/// `payload_lookup` maps integer key -> encrypted byte payload.
pub fn find_and_decrypt_strings<F>(
    instrs: &[DalvikInstr],
    decrypt_fn_idx: u32,
    payload_lookup: F,
) -> HashMap<u32, String>
where
    F: Fn(i64) -> Option<Vec<u8>>,
{
    let calls = find_encrypted_string_calls(instrs, decrypt_fn_idx);
    decrypt_strings(&calls, payload_lookup)
}

/// Emit a summary comment block listing decrypted strings for inline annotation.
#[must_use]
pub fn format_decrypted_strings_comment<S: std::hash::BuildHasher>(
    decrypted: &HashMap<u32, String, S>,
) -> String {
    if decrypted.is_empty() {
        return String::new();
    }
    let mut lines = vec!["/* Decrypted strings:".to_string()];
    let mut entries: Vec<_> = decrypted.iter().collect();
    entries.sort_by_key(|(off, _)| *off);
    for (off, s) in entries {
        lines.push(format!(" *   offset 0x{off:04x} => {s:?}"));
    }
    lines.push(" */".to_string());
    lines.join("\n")
}

// =============================================================================
// Unit tests for the new pipeline
// =============================================================================

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    // ── DalvikFmt / opcode_format ─────────────────────────────────────────

    #[test]
    fn test_opcode_format_nop() {
        assert_eq!(opcode_format(0x00), DalvikFmt::Fmt10x);
    }

    #[test]
    fn test_opcode_format_const4() {
        assert_eq!(opcode_format(0x12), DalvikFmt::Fmt11n);
    }

    #[test]
    fn test_opcode_format_invoke_virtual() {
        assert_eq!(opcode_format(0x6e), DalvikFmt::Fmt35c);
    }

    #[test]
    fn test_opcode_format_const_wide() {
        assert_eq!(opcode_format(0x18), DalvikFmt::Fmt51l);
    }

    // ── decode_dalvik ────────────────────────────────────────────────────

    #[test]
    fn test_decode_return_void() {
        // return-void is opcode 0x0e, format 10x (1 code unit)
        let code: &[u16] = &[0x000e];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x0e);
        assert_eq!(instrs[0].mnemonic, "return-void");
        assert!(instrs[0].regs.is_empty());
    }

    #[test]
    fn test_decode_const4() {
        // const/4 v1, #3  => 0x1312 (opcode 0x12, high byte = (3<<4)|1 = 0x31)
        // Actually: first word low byte = opcode, high byte = AA
        // For 11n: word0 = op | (A<<8) | (B<<12)  where A=dest nibble, B=literal nibble
        // const/4 v1, #3 => word0 = 0x12 | (1<<8) | (3<<12) = 0x3112
        let code: &[u16] = &[0x3112];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x12);
        assert_eq!(instrs[0].regs[0], 1); // dest = low nibble of aa
        assert_eq!(instrs[0].imm, Some(3));
    }

    #[test]
    fn test_decode_goto() {
        // goto +2  => opcode 0x28, offset in high byte as signed 8-bit
        // word0 = 0x28 | (2 << 8) = 0x0228
        let code: &[u16] = &[0x0228];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x28);
        assert_eq!(instrs[0].target, Some(2));
    }

    #[test]
    fn test_decode_move() {
        // move v1, v2 => opcode 0x01, format 12x
        // word0 = 0x01 | (1<<8) | (2<<12) = 0x2101 ... wait:
        // 12x: op|AA where AA = (vA)|(vB<<4), but for move AA = vA<<4|vB? No:
        // Dalvik 12x: high byte of word0 = (vB << 4) | vA
        // move v1, v2 => AA = (2<<4)|1 = 0x21 => word0 = 0x2101
        let code: &[u16] = &[0x2101];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x01);
        assert_eq!(instrs[0].regs[0], 1); // lo nibble = dest
        assert_eq!(instrs[0].regs[1], 2); // hi nibble = src
    }

    #[test]
    fn test_decode_multiple_instructions() {
        // nop, return-void
        let code: &[u16] = &[0x0000, 0x000e];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, 0x00);
        assert_eq!(instrs[1].opcode, 0x0e);
    }

    #[test]
    fn test_decode_const_wide() {
        // const-wide v0, #0x0000000100000002
        // opcode 0x18, 5 code units
        // word0 = 0x0018, words 1-4 = low to high 16-bit chunks.
        //
        // Split 0x0000_0001_0000_0002 low-to-high: 0x0002, 0x0000, 0x0001,
        // 0x0000. The fixture used to read 0x0002, 0x0001, 0x0000, 0x0000 —
        // which encodes 0x0001_0002 (65538), not the value in the comment. The
        // decoder was right and the test data was not.
        let code: &[u16] = &[0x0018, 0x0002, 0x0000, 0x0001, 0x0000];
        let instrs = decode_dalvik(code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, 0x18);
        let expected: i64 = 0x0000_0001_0000_0002u64.cast_signed();
        assert_eq!(instrs[0].imm, Some(expected));
    }

    // ── DalvikType ────────────────────────────────────────────────────────

    #[test]
    fn test_descriptor_to_type_primitives() {
        assert_eq!(descriptor_to_type("I"), DalvikType::Int);
        assert_eq!(descriptor_to_type("J"), DalvikType::Long);
        assert_eq!(descriptor_to_type("Z"), DalvikType::Boolean);
        assert_eq!(descriptor_to_type("V"), DalvikType::Void);
    }

    #[test]
    fn test_descriptor_to_type_object() {
        let t = descriptor_to_type("Ljava/lang/String;");
        assert_eq!(t, DalvikType::Object("java/lang/String".to_string()));
        assert_eq!(t.to_java_string(), "String");
    }

    #[test]
    fn test_descriptor_to_type_array() {
        let t = descriptor_to_type("[I");
        assert_eq!(t, DalvikType::Array(Box::new(DalvikType::Int)));
        assert_eq!(t.to_java_string(), "int[]");
    }

    #[test]
    fn test_is_wide() {
        assert!(DalvikType::Long.is_wide());
        assert!(DalvikType::Double.is_wide());
        assert!(!DalvikType::Int.is_wide());
        assert!(!DalvikType::Object("Foo".to_string()).is_wide());
    }

    #[test]
    fn test_parse_method_proto_void() {
        let (params, ret) = parse_method_proto("()V");
        assert!(params.is_empty());
        assert_eq!(ret, DalvikType::Void);
    }

    #[test]
    fn test_parse_method_proto_params() {
        let (params, ret) = parse_method_proto("(ILjava/lang/String;)Z");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], DalvikType::Int);
        assert_eq!(
            params[1],
            DalvikType::Object("java/lang/String".to_string())
        );
        assert_eq!(ret, DalvikType::Boolean);
    }

    // ── build_dalvik_cfg ──────────────────────────────────────────────────

    #[test]
    fn test_cfg_single_block() {
        // nop; return-void
        let code: &[u16] = &[0x0000, 0x000e];
        let instrs = decode_dalvik(code);
        let cfg = build_dalvik_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].instrs.len(), 2);
    }

    #[test]
    fn test_cfg_two_blocks_goto() {
        // goto +1 (skip nop, which forces two blocks: [goto] and [nop, return-void])
        // goto +1 means target offset = 0 + 1*2 = offset 2 (the nop at word index 1)
        // Actually goto +1 from offset 0 => target byte = 0 + 1*2 = 2
        // But we want a forward goto that creates two blocks.
        // Let's do: [goto/16 +2], [nop], [return-void]
        // goto/16 opcode 0x29, format 20t, 2 code units
        // word0 = 0x0029, word1 = +2 (jump 2 code units ahead from instruction start)
        // So targets byte offset = 0 + 2*2 = 4 = offset of return-void
        let code: &[u16] = &[0x0029, 0x0002, 0x0000, 0x000e];
        let instrs = decode_dalvik(code);
        // instrs: goto/16 (offset 0), nop (offset 4), return-void (offset 6)
        let cfg = build_dalvik_cfg(&instrs);
        // leaders: 0 (entry), 4 (fall-through from goto? no -- goto is unconditional, but
        // next instruction is a leader because goto/16 is a terminator), 4 (target of goto)
        assert!(cfg.blocks.len() >= 2);
    }

    // ── infer_register_types ──────────────────────────────────────────────

    #[test]
    fn test_type_inference_const_string() {
        // const-string v0, @0
        // return-object v0
        let dex = DexFile {
            strings: vec!["hello".to_string()],
            types: vec![],
            fields: vec![],
            method_protos: vec![],
        };
        // const-string v0, @0 => opcode 0x1a, AA=0x00, BBBB=0x0000
        let code: &[u16] = &[0x001a, 0x0000, 0x1100];
        let instrs = decode_dalvik(code);
        let types = infer_register_types(&instrs, "()Ljava/lang/String;", Some(&dex));
        // After const-string: v0 should be java/lang/String
        let first_instr_off = instrs[0].offset;
        let t = types.get(&(first_instr_off, 0));
        assert_eq!(t, Some(&DalvikType::Object("java/lang/String".to_string())));
    }

    // ── JavaEmitter ───────────────────────────────────────────────────────

    #[test]
    fn test_emit_return_void() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::Return(None));
        assert_eq!(s.trim(), "return;");
    }

    #[test]
    fn test_emit_assign_int_lit() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::Assign {
            dest: Box::new(JavaExpr::Reg(0)),
            src: Box::new(JavaExpr::IntLit(42)),
        });
        assert!(s.contains("v0 = 42"), "got: {s}");
    }

    #[test]
    fn test_emit_method_empty() {
        let mut em = JavaEmitter::new();
        let java = em.emit_method("foo", "()V", 0x0001, &[JavaStmt::Return(None)]);
        assert!(java.contains("public"), "got: {java}");
        assert!(java.contains("foo()"), "got: {java}");
        assert!(java.contains("return;"), "got: {java}");
    }

    #[test]
    fn test_emit_binop() {
        let em = JavaEmitter::new();
        let e = JavaExpr::BinOp {
            op: "+",
            left: Box::new(JavaExpr::Reg(1)),
            right: Box::new(JavaExpr::Reg(2)),
        };
        let s = em.emit_expr(&e);
        assert_eq!(s, "(v1 + v2)");
    }

    #[test]
    fn test_emit_string_concat() {
        let em = JavaEmitter::new();
        let e = JavaExpr::StringConcat(vec![
            JavaExpr::StringLit("hello ".to_string()),
            JavaExpr::Reg(0),
        ]);
        let s = em.emit_expr(&e);
        assert!(s.contains(" + "));
    }

    // ── find_encrypted_string_calls ───────────────────────────────────────

    #[test]
    fn test_find_encrypted_calls_basic() {
        // const/4 v0, #5  => word 0x5012 (opcode 0x12, dest=0, lit=5 -> aa = (5<<4)|0 = 0x50)
        // invoke-static {v0}, @method_1  => opcode 0x71, A=1, G=0, BBBB=1, DEFG...
        // For 35c: word0 = 0x71 | (A<<12) | (G<<8), word1 = BBBB, word2 = regs
        // A=1 (one reg), G=v0=0 => word0 = (1<<12)|(0<<8)|0x71 = 0x1071
        // word1 = 0x0001 (method idx 1)
        // word2 = 0x0000 (C=v0=0, D=0, E=0, F=0)
        // move-result-object v1 => opcode 0x0c, AA=1 => word = 0x010c
        let code: &[u16] = &[
            0x5012, // const/4 v0, #5
            0x1071, 0x0001, 0x0000, // invoke-static {v0}, @1
            0x010c, // move-result-object v1
        ];
        let instrs = decode_dalvik(code);
        let calls = find_encrypted_string_calls(&instrs, 1);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].key, 5);
        assert_eq!(calls[0].dest_reg, Some(1));
    }

    #[test]
    fn test_find_encrypted_calls_no_match() {
        // invoke-static with wrong method idx
        let code: &[u16] = &[
            0x5012, 0x1071, 0x0002, 0x0000, // method idx 2, not 1
            0x010c,
        ];
        let instrs = decode_dalvik(code);
        let calls = find_encrypted_string_calls(&instrs, 1);
        assert!(calls.is_empty());
    }

    #[test]
    fn test_try_decrypt_xor() {
        let encrypted = &[0x68u8 ^ 5, 0x69 ^ 5, 0x21 ^ 5]; // "hi!" xor 5
        let result = try_decrypt_xor(5, encrypted);
        assert_eq!(result.as_deref(), Some("hi!"));
    }

    #[test]
    fn test_decrypt_strings_pipeline() {
        let calls = vec![EncryptedStringCall {
            call_offset: 0,
            key: 7,
            dest_reg: Some(0),
        }];
        let payloads: HashMap<i64, Vec<u8>> = {
            let mut m = HashMap::new();
            // "ok" xor 7 = [0x6f^7, 0x6b^7] = [0x68, 0x6c]
            m.insert(7i64, vec![b"o"[0] ^ 7, b"k"[0] ^ 7]);
            m
        };
        let result = decrypt_strings(&calls, |key| payloads.get(&key).cloned());
        assert_eq!(result.get(&0).map(std::string::String::as_str), Some("ok"));
    }

    // ── decompile_class integration ───────────────────────────────────────

    #[test]
    fn test_decompile_class_smoke() {
        // Simple method: const/4 v0, #0  +  return v0
        // const/4 v0, #0 => word0 = 0x0012
        // return v0 => opcode 0x0f, AA=0 => word0 = 0x000f
        let code: &[u16] = &[0x0012, 0x000f];
        let methods = &[("getValue", "()I", 0x0001u32, code)];
        let src = decompile_class("Lcom/example/Foo;", "", 0x0001, methods, None);
        assert!(src.contains("class Foo"), "got: {src}");
        assert!(src.contains("getValue"), "got: {src}");
    }

    #[test]
    fn test_decompile_class_full_pipeline() {
        let dex = DexFile {
            strings: vec!["Hello World".to_string()],
            types: vec!["Ljava/lang/String;".to_string()],
            fields: vec![],
            method_protos: vec!["()Ljava/lang/String;".to_string()],
        };
        // const-string v0, @0  + return-object v0
        // const-string: opcode 0x1a, AA=0, BBBB=0 => word0=0x001a, word1=0x0000
        // return-object v0: opcode 0x11, AA=0 => word0=0x0011
        let code: &[u16] = &[0x001a, 0x0000, 0x0011];
        let methods = &[("getMessage", "()Ljava/lang/String;", 0x0001u32, code)];
        let src = decompile_class("Lcom/example/Bar;", "", 0x0001, methods, Some(&dex));
        assert!(src.contains("getMessage"), "got: {src}");
    }
}

// =============================================================================
// PART 7 -- Variable Renaming Pass
// =============================================================================
//
// After expression recovery the statements reference registers by number
// (JavaExpr::Reg(n)).  This pass assigns meaningful local variable names based
// on:
//   1. Type information (e.g. String -> "str0", int -> "i0").
//   2. Field names found in iget/iput assignments.
//   3. Method names found in invoke results (e.g. getName -> "name0").
//
// The renaming is performed in-place on a Vec<JavaStmt> clone.

/// Maps register numbers to final variable names.
pub type RegNameMap = HashMap<u8, String>;

/// Heuristically derive a variable name from a `DalvikType`.
const fn type_to_var_prefix(t: &DalvikType) -> &'static str {
    match t {
        DalvikType::Boolean => "b",
        DalvikType::Byte => "by",
        DalvikType::Short => "s",
        DalvikType::Char => "c",
        DalvikType::Int => "i",
        DalvikType::Long => "l",
        DalvikType::Float => "f",
        DalvikType::Double => "d",
        DalvikType::Object(cls) => {
            // Use the last component of the class name lowercased
            // We return a fixed string; callers build the actual name at runtime.
            let _ = cls; // suppress unused
            "obj"
        }
        DalvikType::Array(_) => "arr",
        DalvikType::Void | DalvikType::Unknown => "v",
    }
}

/// Build a prefix string that uses the class simple name for Object types.
fn var_prefix_for_type(t: &DalvikType) -> String {
    match t {
        DalvikType::Object(cls) => {
            // java/lang/String -> "str", java/util/List -> "list", etc.
            let simple = cls.rsplit('/').next().unwrap_or("obj");
            // Lower-case first letter
            let mut s = simple.to_string();
            if let Some(first) = s.get_mut(0..1) {
                first.make_ascii_lowercase();
            }
            s
        }
        other => type_to_var_prefix(other).to_string(),
    }
}

/// Assign variable names to all register definitions in a statement list.
///
/// Returns a map from register number -> chosen name.  The names are unique
/// within the method scope: if two definitions assign the same register a
/// different type, the second definition gets a numeric suffix.
#[must_use]
pub fn assign_variable_names<S: std::hash::BuildHasher>(
    stmts: &[JavaStmt],
    type_map: &HashMap<(u32, u8), DalvikType, S>,
) -> RegNameMap {
    // Collect all registers that appear as Assign destinations
    let mut reg_types: HashMap<u8, DalvikType> = HashMap::new();

    for stmt in stmts {
        if let JavaStmt::Assign { dest, src } = stmt
            && let JavaExpr::Reg(r) = dest.as_ref()
        {
            // Try to derive a better type from the source
            let t = match src.as_ref() {
                JavaExpr::IntLit(_) => DalvikType::Int,
                JavaExpr::LongLit(_) => DalvikType::Long,
                JavaExpr::FloatLit(_) => DalvikType::Float,
                JavaExpr::DoubleLit(_) => DalvikType::Double,
                JavaExpr::StringLit(_) => DalvikType::Object("java/lang/String".to_string()),
                JavaExpr::Null => DalvikType::Object("java/lang/Object".to_string()),
                JavaExpr::BoolLit(_) => DalvikType::Boolean,
                JavaExpr::NewInstance { class_name, .. } => {
                    DalvikType::Object(class_name.replace('.', "/"))
                }
                JavaExpr::NewArray { elem_type, .. } => {
                    DalvikType::Array(Box::new(elem_type.clone()))
                }
                JavaExpr::Invoke { return_type, .. } => return_type.clone(),
                JavaExpr::Cast { ty, .. } => ty.clone(),
                JavaExpr::FieldGet { field_type, .. } => field_type.clone(),
                _ => DalvikType::Unknown,
            };
            reg_types.entry(*r).or_insert(t);
        }
    }

    // For any register not yet typed, check type_map
    for (&(_, reg), t) in type_map {
        reg_types.entry(reg).or_insert_with(|| t.clone());
    }

    // Build unique names
    let mut prefix_counts: HashMap<String, u32> = HashMap::new();
    let mut names: RegNameMap = HashMap::new();

    // Sort by register number for determinism
    let mut regs: Vec<u8> = reg_types.keys().copied().collect();
    regs.sort_unstable();

    for r in regs {
        let t = &reg_types[&r];
        let prefix = var_prefix_for_type(t);
        let count = prefix_counts.entry(prefix.clone()).or_insert(0);
        let name = if *count == 0 {
            prefix.clone()
        } else {
            format!("{prefix}{count}")
        };
        *count += 1;
        names.insert(r, name);
    }

    names
}

/// Replace all `JavaExpr::Reg(n)` occurrences in a statement list with
/// `JavaExpr::Var(name)` using the provided name map.
#[must_use]
pub fn apply_variable_names(stmts: Vec<JavaStmt>, names: &RegNameMap) -> Vec<JavaStmt> {
    stmts.into_iter().map(|s| rename_stmt(s, names)).collect()
}

fn rename_stmt(stmt: JavaStmt, names: &RegNameMap) -> JavaStmt {
    match stmt {
        JavaStmt::Assign { dest, src } => JavaStmt::Assign {
            dest: Box::new(rename_expr(*dest, names)),
            src: Box::new(rename_expr(*src, names)),
        },
        JavaStmt::ArrayPut {
            array,
            index,
            value,
        } => JavaStmt::ArrayPut {
            array: Box::new(rename_expr(*array, names)),
            index: Box::new(rename_expr(*index, names)),
            value: Box::new(rename_expr(*value, names)),
        },
        JavaStmt::FieldPut {
            object,
            field_name,
            value,
        } => JavaStmt::FieldPut {
            object: object.map(|o| Box::new(rename_expr(*o, names))),
            field_name,
            value: Box::new(rename_expr(*value, names)),
        },
        JavaStmt::ExprStmt(e) => JavaStmt::ExprStmt(rename_expr(e, names)),
        JavaStmt::Return(Some(e)) => JavaStmt::Return(Some(rename_expr(e, names))),
        JavaStmt::Return(None) => JavaStmt::Return(None),
        JavaStmt::Throw(e) => JavaStmt::Throw(rename_expr(e, names)),
        JavaStmt::IfGoto { cond, label } => JavaStmt::IfGoto {
            cond: rename_expr(cond, names),
            label,
        },
        JavaStmt::Monitor { enter, obj } => JavaStmt::Monitor {
            enter,
            obj: rename_expr(obj, names),
        },
        JavaStmt::Switch {
            value,
            targets,
            default,
        } => JavaStmt::Switch {
            value: rename_expr(value, names),
            targets,
            default,
        },
        JavaStmt::TryCatch {
            try_stmts,
            catch_type,
            catch_var,
            catch_stmts,
        } => JavaStmt::TryCatch {
            try_stmts: apply_variable_names(try_stmts, names),
            catch_type,
            catch_var,
            catch_stmts: apply_variable_names(catch_stmts, names),
        },
        other => other,
    }
}

fn rename_expr(expr: JavaExpr, names: &RegNameMap) -> JavaExpr {
    match expr {
        JavaExpr::Reg(r) => names
            .get(&r)
            .map_or(JavaExpr::Reg(r), |name| JavaExpr::Var(name.clone())),
        JavaExpr::BinOp { op, left, right } => JavaExpr::BinOp {
            op,
            left: Box::new(rename_expr(*left, names)),
            right: Box::new(rename_expr(*right, names)),
        },
        JavaExpr::UnaryOp { op, expr } => JavaExpr::UnaryOp {
            op,
            expr: Box::new(rename_expr(*expr, names)),
        },
        JavaExpr::ArrayGet { array, index } => JavaExpr::ArrayGet {
            array: Box::new(rename_expr(*array, names)),
            index: Box::new(rename_expr(*index, names)),
        },
        JavaExpr::FieldGet {
            object,
            field_name,
            field_type,
        } => JavaExpr::FieldGet {
            object: object.map(|o| Box::new(rename_expr(*o, names))),
            field_name,
            field_type,
        },
        JavaExpr::Invoke {
            kind,
            receiver,
            method_name,
            args,
            return_type,
        } => JavaExpr::Invoke {
            kind,
            receiver: receiver.map(|r| Box::new(rename_expr(*r, names))),
            method_name,
            args: args.into_iter().map(|a| rename_expr(a, names)).collect(),
            return_type,
        },
        JavaExpr::Cast { ty, expr } => JavaExpr::Cast {
            ty,
            expr: Box::new(rename_expr(*expr, names)),
        },
        JavaExpr::InstanceOf { expr, type_name } => JavaExpr::InstanceOf {
            expr: Box::new(rename_expr(*expr, names)),
            type_name,
        },
        JavaExpr::ArrayLength(arr) => JavaExpr::ArrayLength(Box::new(rename_expr(*arr, names))),
        JavaExpr::NewInstance { class_name, args } => JavaExpr::NewInstance {
            class_name,
            args: args.into_iter().map(|a| rename_expr(a, names)).collect(),
        },
        JavaExpr::NewArray { elem_type, size } => JavaExpr::NewArray {
            elem_type,
            size: Box::new(rename_expr(*size, names)),
        },
        JavaExpr::StringConcat(parts) => {
            JavaExpr::StringConcat(parts.into_iter().map(|p| rename_expr(p, names)).collect())
        }
        other => other,
    }
}

// =============================================================================
// PART 8 -- Try-Catch Region Detection
// =============================================================================
//
// DEX files carry exception handler tables per method (try-item lists).
// This module re-constructs try { } catch { } regions from those tables and
// wraps the corresponding statement ranges.

/// A raw try-item as stored in the DEX `code_item`.
#[derive(Debug, Clone)]
pub struct DexTryItem {
    /// Byte offset of the first covered instruction.
    pub start_addr: u32,
    /// Number of code units covered.
    pub insn_count: u32,
    /// Handler entries: (`type_descriptor`, `handler_byte_offset`).
    /// An empty `type_descriptor` means a catch-all handler.
    pub handlers: Vec<(String, u32)>,
}

/// Wrap statement ranges that fall within try regions into `TryCatch` nodes.
///
/// `stmts` must have Label nodes inserted (e.g. via a prior pass that emits
/// a `JavaStmt::Label(byte_off)` before each instruction).  This function
/// scans for the label that matches `try_item.start_addr` and wraps
/// statements up to `start_addr + insn_count * 2`.
#[must_use]
pub fn apply_try_regions(stmts: Vec<JavaStmt>, try_items: &[DexTryItem]) -> Vec<JavaStmt> {
    if try_items.is_empty() {
        return stmts;
    }

    // For each try region, find the statement index range and wrap it.
    // We do one try-item at a time, innermost-last (simple non-overlapping model).
    let mut result = stmts;

    for item in try_items {
        let start_byte = item.start_addr;
        let end_byte = item.start_addr + item.insn_count * 2;

        // Find statement range [lo, hi) that falls within [start_byte, end_byte)
        let lo = result.iter().position(|s| {
            if let JavaStmt::Label(l) = s {
                *l >= start_byte
            } else {
                false
            }
        });
        let hi = result.iter().rposition(|s| {
            if let JavaStmt::Label(l) = s {
                *l < end_byte
            } else {
                false
            }
        });

        let (lo, hi) = match (lo, hi) {
            (Some(l), Some(h)) if l <= h => (l, h + 1),
            _ => continue,
        };

        // For now use the first handler; a full implementation would emit
        // multiple catch clauses.
        let (catch_type, handler_offset) = match item.handlers.first() {
            Some(h) => h.clone(),
            None => continue,
        };

        // Find catch-block statements: from handler_offset label onward
        // (heuristic: take up to 32 statements after the handler label)
        let catch_lo = result[hi..].iter().position(|s| {
            if let JavaStmt::Label(l) = s {
                *l == handler_offset
            } else {
                false
            }
        });

        let (catch_stmts, catch_hi) = catch_lo.map_or_else(
            || (vec![], hi),
            |cl| {
                let abs = hi + cl;
                let end = (abs + 32).min(result.len());
                (result[abs..end].to_vec(), end)
            },
        );

        let try_stmts: Vec<JavaStmt> = result[lo..hi].to_vec();
        let catch_var = "e".to_string();

        let wrapped = JavaStmt::TryCatch {
            try_stmts,
            catch_type: descriptor_to_type(&catch_type).to_java_string(),
            catch_var,
            catch_stmts,
        };

        // Replace the range with the wrapped node
        let remove_end = if catch_lo.is_some() { catch_hi } else { hi };
        result.splice(lo..remove_end, std::iter::once(wrapped));
    }

    result
}

// =============================================================================
// PART 9 -- Deobfuscation: Identifier Renaming
// =============================================================================
//
// Obfuscated APKs use short single-letter class/method/field names.
// This module provides heuristics to assign readable names.

/// Rename a potentially obfuscated class descriptor to a readable name.
///
/// Rules (applied in order):
/// 1. If the simple name is longer than `min_len`, keep it.
/// 2. If the class extends `Activity`, suffix with `Activity`.
/// 3. If the class name matches known Android framework patterns, use those.
/// 4. Otherwise use `Class` + an index suffix.
#[must_use]
pub fn deobf_class_name(
    descriptor: &str,
    superclass: Option<&str>,
    index: u32,
    min_len: usize,
) -> String {
    // Exactly one marker — see `descriptor_to_type`.
    let inner = descriptor.strip_prefix('L').unwrap_or(descriptor);
    let inner = inner.strip_suffix(';').unwrap_or(inner);
    let simple = inner.rsplit('/').next().unwrap_or(inner);
    let pkg = {
        let parts: Vec<&str> = inner.split('/').collect();
        if parts.len() > 1 {
            parts[..parts.len() - 1].join(".")
        } else {
            String::new()
        }
    };

    // Keep if already readable
    if simple.len() >= min_len && simple.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return descriptor.to_string();
    }

    // Heuristic from superclass
    let suffix = superclass.map_or("Class", |sup| {
        let s = sup.rsplit('/').next().unwrap_or("").trim_end_matches(';');
        match s {
            "Activity" => "Activity",
            "Fragment" | "DialogFragment" => "Fragment",
            "Service" => "Service",
            "BroadcastReceiver" => "Receiver",
            "ContentProvider" => "Provider",
            "View" | "ViewGroup" => "View",
            "Adapter" | "BaseAdapter" => "Adapter",
            "Exception" | "RuntimeException" => "Exception",
            _ => "Class",
        }
    });

    let new_name = format!("{suffix}{index}");
    if pkg.is_empty() {
        format!("L{new_name};")
    } else {
        format!("L{}/{};", pkg.replace('.', "/"), new_name)
    }
}

/// Rename an obfuscated method name based on its return type and parameter
/// count heuristic.
#[must_use]
pub fn deobf_method_name(
    name: &str,
    proto: &str,
    access_flags: u32,
    index: u32,
    min_len: usize,
) -> String {
    // Keep constructors and static initializers as-is
    if name == "<init>" || name == "<clinit>" {
        return name.to_string();
    }

    if name.len() >= min_len {
        return name.to_string();
    }

    let is_static = access_flags & 0x0008 != 0;
    let (_, ret) = parse_method_proto(proto);

    let prefix = match &ret {
        DalvikType::Boolean => "is",
        DalvikType::Void => {
            if is_static {
                "init"
            } else {
                "do"
            }
        }
        _ => "get",
    };

    format!("{prefix}{index}")
}

/// Rename a short field name to a readable form.
#[must_use]
pub fn deobf_field_name(name: &str, field_type: &DalvikType, index: u32, min_len: usize) -> String {
    if name.len() >= min_len {
        return name.to_string();
    }
    let prefix = var_prefix_for_type(field_type);
    format!("m{}{}", capitalize(&prefix), index)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| {
        f.to_uppercase().collect::<String>() + c.as_str()
    })
}

// =============================================================================
// PART 10 -- Proto / Annotation Parsing Helpers
// =============================================================================

/// Parsed representation of a DEX method prototype.
#[derive(Debug, Clone)]
pub struct MethodProto {
    pub params: Vec<DalvikType>,
    pub return_type: DalvikType,
    pub shorty: String,
}

impl MethodProto {
    /// Parse from a standard Dalvik proto descriptor.
    #[must_use]
    pub fn parse(proto: &str) -> Self {
        let (params, return_type) = parse_method_proto(proto);
        let shorty = build_shorty(&params, &return_type);
        Self {
            params,
            return_type,
            shorty,
        }
    }

    /// True if the method takes no parameters.
    #[must_use]
    pub const fn is_no_arg(&self) -> bool {
        self.params.is_empty()
    }

    /// True if the method returns void.
    #[must_use]
    pub fn is_void(&self) -> bool {
        self.return_type == DalvikType::Void
    }

    /// Java-style signature string, e.g. "(int, String) -> boolean".
    #[must_use]
    pub fn java_sig(&self) -> String {
        let params = self
            .params
            .iter()
            .map(DalvikType::to_java_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!("({}) -> {}", params, self.return_type.to_java_string())
    }

    /// Number of register slots consumed by parameters (wide types = 2).
    #[must_use]
    pub fn param_slots(&self) -> u32 {
        self.params
            .iter()
            .map(|t| if t.is_wide() { 2 } else { 1 })
            .sum()
    }
}

/// Build the Dalvik "shorty" descriptor from a parameter/return type list.
#[must_use]
pub fn build_shorty(params: &[DalvikType], ret: &DalvikType) -> String {
    let type_char = |t: &DalvikType| -> char {
        match t {
            DalvikType::Void => 'V',
            DalvikType::Boolean => 'Z',
            DalvikType::Byte => 'B',
            DalvikType::Short => 'S',
            DalvikType::Char => 'C',
            DalvikType::Int => 'I',
            DalvikType::Long => 'J',
            DalvikType::Float => 'F',
            DalvikType::Double => 'D',
            DalvikType::Object(_) | DalvikType::Array(_) | DalvikType::Unknown => 'L',
        }
    };
    let mut s = String::new();
    s.push(type_char(ret));
    for p in params {
        s.push(type_char(p));
    }
    s
}

// =============================================================================
// Unit tests for Parts 7-10
// =============================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── Variable renaming ─────────────────────────────────────────────────

    #[test]
    fn test_var_prefix_int() {
        let t = DalvikType::Int;
        assert_eq!(var_prefix_for_type(&t), "i");
    }

    #[test]
    fn test_var_prefix_string() {
        let t = DalvikType::Object("java/lang/String".to_string());
        let p = var_prefix_for_type(&t);
        // "String" lowercased first char => "string"
        assert_eq!(p, "string");
    }

    #[test]
    fn test_assign_variable_names_basic() {
        let stmts = vec![
            JavaStmt::Assign {
                dest: Box::new(JavaExpr::Reg(0)),
                src: Box::new(JavaExpr::IntLit(5)),
            },
            JavaStmt::Assign {
                dest: Box::new(JavaExpr::Reg(1)),
                src: Box::new(JavaExpr::StringLit("hi".to_string())),
            },
        ];
        let names = assign_variable_names(&stmts, &HashMap::new());
        assert_eq!(names.get(&0).map(std::string::String::as_str), Some("i"));
        assert_eq!(
            names.get(&1).map(std::string::String::as_str),
            Some("string")
        );
    }

    #[test]
    fn test_apply_variable_names() {
        let stmts = vec![JavaStmt::Return(Some(JavaExpr::Reg(0)))];
        let mut names = RegNameMap::new();
        names.insert(0, "result".to_string());
        let renamed = apply_variable_names(stmts, &names);
        if let JavaStmt::Return(Some(JavaExpr::Var(n))) = &renamed[0] {
            assert_eq!(n, "result");
        } else {
            panic!("Expected Var(result), got {:?}", renamed[0]);
        }
    }

    #[test]
    fn test_rename_binop() {
        let mut names = RegNameMap::new();
        names.insert(1, "x".to_string());
        names.insert(2, "y".to_string());
        let expr = JavaExpr::BinOp {
            op: "+",
            left: Box::new(JavaExpr::Reg(1)),
            right: Box::new(JavaExpr::Reg(2)),
        };
        let renamed = rename_expr(expr, &names);
        let em = JavaEmitter::new();
        let s = em.emit_expr(&renamed);
        assert_eq!(s, "(x + y)");
    }

    // ── Deobfuscation ─────────────────────────────────────────────────────

    #[test]
    fn test_deobf_class_name_short() {
        let result = deobf_class_name("Lcom/example/a;", Some("Activity"), 3, 4);
        assert!(result.contains("Activity3"), "got: {result}");
    }

    #[test]
    fn test_deobf_class_name_already_long() {
        let result = deobf_class_name("Lcom/example/MainActivity;", None, 0, 4);
        assert_eq!(result, "Lcom/example/MainActivity;");
    }

    #[test]
    fn test_deobf_method_name_short() {
        let result = deobf_method_name("a", "()I", 0x0001, 5, 4);
        assert!(result.starts_with("get"), "got: {result}");
    }

    #[test]
    fn test_deobf_method_name_constructor() {
        let result = deobf_method_name("<init>", "()V", 0x0001, 0, 4);
        assert_eq!(result, "<init>");
    }

    #[test]
    fn test_deobf_field_name_short() {
        let result = deobf_field_name("a", &DalvikType::Int, 0, 4);
        assert_eq!(result, "mI0");
    }

    #[test]
    fn test_deobf_field_name_long() {
        let result = deobf_field_name("myField", &DalvikType::Int, 0, 4);
        assert_eq!(result, "myField");
    }

    // ── MethodProto ───────────────────────────────────────────────────────

    #[test]
    fn test_method_proto_parse_void() {
        let p = MethodProto::parse("()V");
        assert!(p.is_no_arg());
        assert!(p.is_void());
        assert_eq!(p.shorty, "V");
    }

    #[test]
    fn test_method_proto_parse_params() {
        let p = MethodProto::parse("(ILjava/lang/String;)Z");
        assert_eq!(p.params.len(), 2);
        assert!(!p.is_no_arg());
        assert!(!p.is_void());
        assert_eq!(p.shorty, "ZIL");
    }

    #[test]
    fn test_method_proto_java_sig() {
        let p = MethodProto::parse("(I)V");
        assert_eq!(p.java_sig(), "(int) -> void");
    }

    #[test]
    fn test_method_proto_param_slots_wide() {
        let p = MethodProto::parse("(JI)V");
        // J = 2 slots, I = 1 slot => 3 total
        assert_eq!(p.param_slots(), 3);
    }

    #[test]
    fn test_build_shorty_basic() {
        let params = vec![
            DalvikType::Int,
            DalvikType::Object("java/lang/String".to_string()),
        ];
        let ret = DalvikType::Boolean;
        let s = build_shorty(&params, &ret);
        assert_eq!(s, "ZIL");
    }

    // ── DalvikType join ───────────────────────────────────────────────────

    #[test]
    fn test_type_join_same() {
        let t = DalvikType::Int.join(&DalvikType::Int);
        assert_eq!(t, DalvikType::Int);
    }

    #[test]
    fn test_type_join_int_bool() {
        let t = DalvikType::Int.join(&DalvikType::Boolean);
        assert_eq!(t, DalvikType::Int);
    }

    #[test]
    fn test_type_join_unknown() {
        let t = DalvikType::Unknown.join(&DalvikType::Long);
        assert_eq!(t, DalvikType::Long);
    }

    // ── CFG dominators ────────────────────────────────────────────────────

    #[test]
    fn test_cfg_idom_single_block() {
        let code: &[u16] = &[0x000e];
        let instrs = decode_dalvik(code);
        let cfg = build_dalvik_cfg(&instrs);
        let idom = cfg.idom();
        assert_eq!(idom.len(), 1);
        assert_eq!(idom[0], Some(0));
    }

    #[test]
    fn test_cfg_rpo_single() {
        let code: &[u16] = &[0x000e];
        let instrs = decode_dalvik(code);
        let cfg = build_dalvik_cfg(&instrs);
        assert_eq!(cfg.rpo(), vec![0]);
    }

    // ── recover_expressions round-trips ───────────────────────────────────

    #[test]
    fn test_recover_return_void() {
        let code: &[u16] = &[0x000e];
        let instrs = decode_dalvik(code);
        let stmts = recover_expressions(&instrs, &HashMap::new(), None);
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], JavaStmt::Return(None)));
    }

    #[test]
    fn test_recover_const_and_return() {
        // const/4 v0, #7  => word 0x7012
        // return v0        => word 0x000f
        let code: &[u16] = &[0x7012, 0x000f];
        let instrs = decode_dalvik(code);
        let stmts = recover_expressions(&instrs, &HashMap::new(), None);
        // Should have: Assign(v0, 7), Return(v0)
        assert!(stmts.len() >= 2, "got {} stmts", stmts.len());
        if let JavaStmt::Assign { src, .. } = &stmts[0] {
            assert!(matches!(src.as_ref(), JavaExpr::IntLit(7)));
        } else {
            panic!("expected Assign as first stmt");
        }
    }

    #[test]
    fn test_recover_if_branch() {
        // if-eq v0, v1, +4  (branch to offset 0 + 4*2 = 8)
        // opcode 0x32, format 22t:
        // word0 = 0x32 | (v0=0)<<8 | (v1=1)<<12 = 0x1032  (AA = (vB<<4)|vA = 0x10)
        // word1 = +4 (i16)
        let code: &[u16] = &[0x1032, 0x0004, 0x000e]; // if-eq; return-void (fall-through)
        let instrs = decode_dalvik(code);
        let stmts = recover_expressions(&instrs, &HashMap::new(), None);
        let has_if = stmts.iter().any(|s| matches!(s, JavaStmt::IfGoto { .. }));
        assert!(has_if, "expected IfGoto in stmts: {:?}", stmts.len());
    }

    #[test]
    fn test_recover_binop_add() {
        // add-int v0, v1, v2  => opcode 0x90, format 23x
        // word0 = 0x90 | (0x00 << 8) = 0x0090 (dest=v0, AA=0)
        // word1 = (v2=2)<<8 | (v1=1) = 0x0201
        let code: &[u16] = &[0x0090, 0x0201, 0x000e];
        let instrs = decode_dalvik(code);
        let stmts = recover_expressions(&instrs, &HashMap::new(), None);
        let has_add = stmts.iter().any(|s| {
            if let JavaStmt::Assign { src, .. } = s {
                if let JavaExpr::BinOp { op, .. } = src.as_ref() {
                    *op == "+"
                } else {
                    false
                }
            } else {
                false
            }
        });
        assert!(has_add, "expected add BinOp");
    }

    // ── apply_try_regions ─────────────────────────────────────────────────

    #[test]
    fn test_apply_try_regions_empty() {
        let stmts = vec![JavaStmt::Return(None)];
        let result = apply_try_regions(stmts, &[]);
        assert_eq!(result.len(), 1);
    }

    // ── opcode_mnemonic coverage ──────────────────────────────────────────

    #[test]
    fn test_mnemonic_coverage() {
        // Spot-check a range of known opcodes
        assert_eq!(opcode_mnemonic(0x90), "add-int");
        assert_eq!(opcode_mnemonic(0x9b), "add-long");
        assert_eq!(opcode_mnemonic(0x6e), "invoke-virtual");
        assert_eq!(opcode_mnemonic(0x71), "invoke-static");
        assert_eq!(opcode_mnemonic(0xb0), "add-int/2addr");
        assert_eq!(opcode_mnemonic(0xd8), "add-int/lit8");
    }

    #[test]
    fn test_mnemonic_unknown() {
        assert_eq!(opcode_mnemonic(0xff), "unknown");
    }

    // ── DexFile context ───────────────────────────────────────────────────

    #[test]
    fn test_dexfile_empty_lookups() {
        let dex = DexFile::empty();
        assert!(dex.string_by_idx(0).is_none());
        assert!(dex.type_desc(0).is_none());
        assert!(dex.field_desc(0).is_none());
        assert!(dex.method_proto(0).is_none());
    }

    #[test]
    fn test_dexfile_string_lookup() {
        let dex = DexFile {
            strings: vec!["hello".to_string()],
            types: vec![],
            fields: vec![],
            method_protos: vec![],
        };
        assert_eq!(dex.string_by_idx(0), Some("hello"));
        assert!(dex.string_by_idx(1).is_none());
    }

    // ── Emitter edge cases ────────────────────────────────────────────────

    #[test]
    fn test_emit_null_literal() {
        let em = JavaEmitter::new();
        let s = em.emit_expr(&JavaExpr::Null);
        assert_eq!(s, "null");
    }

    #[test]
    fn test_emit_long_literal() {
        let em = JavaEmitter::new();
        let s = em.emit_expr(&JavaExpr::LongLit(123_456_789));
        assert_eq!(s, "123456789L");
    }

    #[test]
    fn test_emit_bool_true() {
        let em = JavaEmitter::new();
        assert_eq!(em.emit_expr(&JavaExpr::BoolLit(true)), "true");
        assert_eq!(em.emit_expr(&JavaExpr::BoolLit(false)), "false");
    }

    #[test]
    fn test_emit_array_get() {
        let em = JavaEmitter::new();
        let e = JavaExpr::ArrayGet {
            array: Box::new(JavaExpr::Var("arr".to_string())),
            index: Box::new(JavaExpr::IntLit(0)),
        };
        assert_eq!(em.emit_expr(&e), "arr[0]");
    }

    #[test]
    fn test_emit_field_get_static() {
        let em = JavaEmitter::new();
        let e = JavaExpr::FieldGet {
            object: None,
            field_name: "TAG".to_string(),
            field_type: DalvikType::Object("java/lang/String".to_string()),
        };
        assert_eq!(em.emit_expr(&e), "TAG");
    }

    #[test]
    fn test_emit_field_get_instance() {
        let em = JavaEmitter::new();
        let e = JavaExpr::FieldGet {
            object: Some(Box::new(JavaExpr::Var("this".to_string()))),
            field_name: "count".to_string(),
            field_type: DalvikType::Int,
        };
        assert_eq!(em.emit_expr(&e), "this.count");
    }

    #[test]
    fn test_emit_new_instance() {
        let em = JavaEmitter::new();
        let e = JavaExpr::NewInstance {
            class_name: "ArrayList".to_string(),
            args: vec![],
        };
        assert_eq!(em.emit_expr(&e), "new ArrayList()");
    }

    #[test]
    fn test_emit_cast() {
        let em = JavaEmitter::new();
        let e = JavaExpr::Cast {
            ty: DalvikType::Int,
            expr: Box::new(JavaExpr::Var("x".to_string())),
        };
        assert_eq!(em.emit_expr(&e), "(int)(x)");
    }

    #[test]
    fn test_emit_instanceof() {
        let em = JavaEmitter::new();
        let e = JavaExpr::InstanceOf {
            expr: Box::new(JavaExpr::Var("obj".to_string())),
            type_name: "String".to_string(),
        };
        assert_eq!(em.emit_expr(&e), "(obj instanceof String)");
    }

    #[test]
    fn test_emit_goto() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::Goto(24));
        assert!(s.contains("label_24"), "got: {s}");
    }

    #[test]
    fn test_emit_if_goto() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::IfGoto {
            cond: JavaExpr::BinOp {
                op: "==",
                left: Box::new(JavaExpr::Var("x".to_string())),
                right: Box::new(JavaExpr::IntLit(0)),
            },
            label: 8,
        });
        assert!(s.contains("if"), "got: {s}");
        assert!(s.contains("label_8"), "got: {s}");
    }

    #[test]
    fn test_emit_monitor_enter() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::Monitor {
            enter: true,
            obj: JavaExpr::Var("lock".to_string()),
        });
        assert!(s.contains("synchronized_enter"), "got: {s}");
    }

    #[test]
    fn test_emit_throw() {
        let mut em = JavaEmitter::new();
        let s = em.emit_stmt(&JavaStmt::Throw(JavaExpr::Var("ex".to_string())));
        assert!(s.trim().starts_with("throw"), "got: {s}");
    }

    #[test]
    fn test_emit_class_with_field() {
        let mut em = JavaEmitter::new();
        let fields = &[("count", DalvikType::Int)];
        let src = em.emit_class("com/example/Counter", "", 0x0001, fields, &[]);
        assert!(src.contains("int count"), "got: {src}");
        assert!(src.contains("class Counter"), "got: {src}");
    }

    // ── parse_type_list ───────────────────────────────────────────────────

    #[test]
    fn test_parse_type_list_empty() {
        let types = parse_type_list("");
        assert!(types.is_empty());
    }

    #[test]
    fn test_parse_type_list_single() {
        let types = parse_type_list("I");
        assert_eq!(types, vec![DalvikType::Int]);
    }

    #[test]
    fn test_parse_type_list_multiple() {
        let types = parse_type_list("IZLjava/lang/String;");
        assert_eq!(types.len(), 3);
        assert_eq!(types[0], DalvikType::Int);
        assert_eq!(types[1], DalvikType::Boolean);
        assert_eq!(types[2], DalvikType::Object("java/lang/String".to_string()));
    }

    #[test]
    fn test_parse_type_list_array() {
        let types = parse_type_list("[I[Ljava/lang/String;");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], DalvikType::Array(Box::new(DalvikType::Int)));
        assert_eq!(
            types[1],
            DalvikType::Array(Box::new(DalvikType::Object("java/lang/String".to_string())))
        );
    }

    // ── DalvikInstr helpers ───────────────────────────────────────────────

    #[test]
    fn test_is_return() {
        let mut i = DalvikInstr {
            offset: 0,
            opcode: 0x0e,
            mnemonic: "return-void",
            regs: vec![],
            imm: None,
            target: None,
            ref_idx: None,
            format: DalvikFmt::Fmt10x,
        };
        assert!(i.is_return());
        i.opcode = 0x0f;
        assert!(i.is_return());
        i.opcode = 0x01;
        assert!(!i.is_return());
    }

    #[test]
    fn test_is_invoke() {
        let i = DalvikInstr {
            offset: 0,
            opcode: 0x6e,
            mnemonic: "invoke-virtual",
            regs: vec![],
            imm: None,
            target: None,
            ref_idx: Some(0),
            format: DalvikFmt::Fmt35c,
        };
        assert!(i.is_invoke());
    }

    #[test]
    fn test_code_units_fmt51l() {
        let i = DalvikInstr {
            offset: 0,
            opcode: 0x18,
            mnemonic: "const-wide",
            regs: vec![],
            imm: None,
            target: None,
            ref_idx: None,
            format: DalvikFmt::Fmt51l,
        };
        assert_eq!(i.code_units(), 5);
    }
}
