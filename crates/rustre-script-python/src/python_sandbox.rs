// python_sandbox.rs — Pure-Rust Python execution sandbox.
// Provides import filtering, execution timeout tracking, output capture,
// and a sandboxed execution context for the built-in Python interpreter.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

// ── Import filter ─────────────────────────────────────────────────────────────

/// Policy for an import request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportPolicy {
    Allow,
    Deny,
    AllowWithRestrictions { forbidden_attrs: Vec<String> },
}

impl fmt::Display for ImportPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::AllowWithRestrictions { forbidden_attrs } => {
                write!(f, "AllowRestricted({forbidden_attrs:?})")
            }
        }
    }
}

/// Filters Python `import` statements.
#[derive(Debug, Clone)]
pub struct ImportFilter {
    /// Explicitly allowed modules.
    allowlist: HashSet<String>,
    /// Explicitly denied modules.
    denylist: HashSet<String>,
    /// Default policy when a module matches neither list.
    default_allow: bool,
    /// Per-module attribute restrictions.
    restrictions: HashMap<String, Vec<String>>,
}

impl ImportFilter {
    /// Create a strict filter: deny everything not on the allowlist.
    #[must_use] 
    pub fn strict() -> Self {
        Self {
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            default_allow: false,
            restrictions: HashMap::new(),
        }
    }

    /// Create a permissive filter with a default denylist for dangerous modules.
    #[must_use] 
    pub fn permissive() -> Self {
        let mut f = Self {
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            default_allow: true,
            restrictions: HashMap::new(),
        };
        // Deny dangerous modules by default.
        for m in &[
            "os", "subprocess", "socket", "ctypes", "cffi", "importlib",
            "sys", "builtins", "__builtin__", "pty", "posix", "signal",
            "threading", "multiprocessing", "gc",
        ] {
            f.denylist.insert(m.to_string());
        }
        // Allow os.path with restrictions.
        f.allowlist.insert("os.path".to_string());
        f
    }

    /// Create the `RustRE` default sandbox filter.
    #[must_use] 
    pub fn rustre_default() -> Self {
        let mut f = Self::strict();
        // Allow safe stdlib modules.
        for m in &[
            "math", "re", "json", "struct", "binascii", "hashlib",
            "base64", "itertools", "functools", "collections", "string",
            "textwrap", "enum", "dataclasses", "typing",
        ] {
            f.allowlist.insert(m.to_string());
        }
        // Allow rustre API namespace.
        f.allowlist.insert("rustre".to_string());
        f
    }

    pub fn allow(&mut self, module: impl Into<String>) {
        self.allowlist.insert(module.into());
    }

    pub fn deny(&mut self, module: impl Into<String>) {
        let m = module.into();
        self.allowlist.remove(&m);
        self.denylist.insert(m);
    }

    pub fn restrict_attrs(
        &mut self,
        module: impl Into<String>,
        forbidden: Vec<String>,
    ) {
        self.restrictions.insert(module.into(), forbidden);
    }

    #[must_use] 
    pub fn check(&self, module: &str) -> ImportPolicy {
        if self.denylist.contains(module) {
            return ImportPolicy::Deny;
        }
        if self.allowlist.contains(module) {
            if let Some(attrs) = self.restrictions.get(module) {
                return ImportPolicy::AllowWithRestrictions {
                    forbidden_attrs: attrs.clone(),
                };
            }
            return ImportPolicy::Allow;
        }
        if self.default_allow {
            ImportPolicy::Allow
        } else {
            ImportPolicy::Deny
        }
    }

    #[must_use] 
    pub fn is_allowed(&self, module: &str) -> bool {
        self.check(module) != ImportPolicy::Deny
    }

    #[must_use] 
    pub fn allowed_modules(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.allowlist.iter().map(std::string::String::as_str).collect();
        v.sort_unstable();
        v
    }
}

// ── Output capture ────────────────────────────────────────────────────────────

/// Captured standard output and error from a script execution.
#[derive(Debug, Clone, Default)]
pub struct OutputCapture {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub truncated: bool,
}

impl OutputCapture {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_limit: 10_000,
            stderr_limit: 1_000,
            truncated: false,
        }
    }

    #[must_use] 
    pub const fn with_limits(stdout_limit: usize, stderr_limit: usize) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_limit,
            stderr_limit,
            truncated: false,
        }
    }

    pub fn write_stdout(&mut self, line: impl Into<String>) {
        if self.stdout.len() < self.stdout_limit {
            self.stdout.push(line.into());
        } else {
            self.truncated = true;
        }
    }

    pub fn write_stderr(&mut self, line: impl Into<String>) {
        if self.stderr.len() < self.stderr_limit {
            self.stderr.push(line.into());
        } else {
            self.truncated = true;
        }
    }

    #[must_use] 
    pub fn stdout_text(&self) -> String {
        self.stdout.join("\n")
    }

    #[must_use] 
    pub fn stderr_text(&self) -> String {
        self.stderr.join("\n")
    }

    #[must_use] 
    pub const fn line_count(&self) -> usize {
        self.stdout.len() + self.stderr.len()
    }

    pub fn clear(&mut self) {
        self.stdout.clear();
        self.stderr.clear();
        self.truncated = false;
    }
}

// ── Execution timer ───────────────────────────────────────────────────────────

/// Tracks elapsed time for script execution and enforces a timeout.
#[derive(Debug)]
pub struct ExecTimeout {
    pub limit: Duration,
    start: Option<Instant>,
    pub step_count: u64,
    /// Check interval: check timeout every N steps to avoid calling `Instant::now()` too often.
    pub check_every: u64,
}

impl ExecTimeout {
    #[must_use] 
    pub const fn new(limit: Duration) -> Self {
        Self {
            limit,
            start: None,
            step_count: 0,
            check_every: 1000,
        }
    }

    #[must_use] 
    pub const fn unlimited() -> Self {
        Self::new(Duration::from_secs(u64::MAX / 2))
    }

    pub fn start(&mut self) {
        self.start = Some(Instant::now());
        self.step_count = 0;
    }

    pub fn tick(&mut self) -> bool {
        self.step_count += 1;
        if !self.step_count.is_multiple_of(self.check_every) {
            return false;
        }
        self.is_expired()
    }

    #[must_use] 
    pub fn is_expired(&self) -> bool {
        self.start.is_some_and(|start| start.elapsed() > self.limit)
    }

    #[must_use] 
    pub fn elapsed(&self) -> Duration {
        self.start.map_or(Duration::ZERO, |s| s.elapsed())
    }

    #[must_use] 
    pub fn remaining(&self) -> Duration {
        self.start.map_or(self.limit, |start| self.limit.saturating_sub(start.elapsed()))
    }
}

// ── Sandbox configuration ─────────────────────────────────────────────────────

/// Full configuration for the Python sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum execution time.
    pub timeout: Duration,
    /// Maximum number of interpreter steps (0 = unlimited).
    pub max_steps: u64,
    /// Maximum recursion depth.
    pub max_recursion: usize,
    /// Maximum total memory for Python objects in bytes (0 = unlimited).
    pub max_memory_bytes: usize,
    /// Maximum output lines.
    pub max_output_lines: usize,
    /// Import policy.
    pub import_filter: ImportFilter,
    /// Allow `print()` to write to captured stdout.
    pub allow_print: bool,
    /// Allow file read access within a restricted path set.
    pub allowed_paths: Vec<String>,
    /// Expose rustre API functions.
    pub expose_rustre_api: bool,
}

impl SandboxConfig {
    /// Safe default: 5-second timeout, `rustre_default` import filter, no file access.
    #[must_use] 
    pub fn safe_default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_steps: 1_000_000,
            max_recursion: 50,
            max_memory_bytes: 64 * 1024 * 1024,
            max_output_lines: 10_000,
            import_filter: ImportFilter::rustre_default(),
            allow_print: true,
            allowed_paths: Vec::new(),
            expose_rustre_api: true,
        }
    }

    /// Minimal sandbox for trusted internal scripts.
    #[must_use] 
    pub fn trusted() -> Self {
        Self {
            timeout: Duration::from_mins(1),
            max_steps: 0,
            max_recursion: 200,
            max_memory_bytes: 0,
            max_output_lines: 100_000,
            import_filter: ImportFilter::permissive(),
            allow_print: true,
            allowed_paths: Vec::new(),
            expose_rustre_api: true,
        }
    }

    /// Ultra-restrictive: evaluate expressions only, no imports.
    #[must_use] 
    pub fn expr_only() -> Self {
        Self {
            timeout: Duration::from_millis(500),
            max_steps: 10_000,
            max_recursion: 10,
            max_memory_bytes: 1024 * 1024,
            max_output_lines: 100,
            import_filter: ImportFilter::strict(),
            allow_print: false,
            allowed_paths: Vec::new(),
            expose_rustre_api: false,
        }
    }

    #[must_use] 
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if self.allowed_paths.is_empty() {
            return false;
        }
        self.allowed_paths.iter().any(|p| path.starts_with(p.as_str()))
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self::safe_default()
    }
}

// ── Sandbox violation ─────────────────────────────────────────────────────────

/// The reason execution was halted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    Timeout { elapsed_ms: u64 },
    StepLimitExceeded { steps: u64 },
    RecursionLimitExceeded { depth: usize },
    MemoryLimitExceeded { bytes: usize },
    ForbiddenImport { module: String },
    ForbiddenFileAccess { path: String },
    ForbiddenBuiltin { name: String },
    ForbiddenAttribute { object: String, attr: String },
    OutputLimitExceeded,
}

impl fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { elapsed_ms } => {
                write!(f, "Execution timed out after {elapsed_ms}ms")
            }
            Self::StepLimitExceeded { steps } => {
                write!(f, "Step limit exceeded ({steps} steps)")
            }
            Self::RecursionLimitExceeded { depth } => {
                write!(f, "Recursion depth {depth} exceeded limit")
            }
            Self::MemoryLimitExceeded { bytes } => {
                write!(f, "Memory limit exceeded ({bytes} bytes)")
            }
            Self::ForbiddenImport { module } => {
                write!(f, "Import of '{module}' is not allowed")
            }
            Self::ForbiddenFileAccess { path } => {
                write!(f, "File access to '{path}' is not allowed")
            }
            Self::ForbiddenBuiltin { name } => {
                write!(f, "Use of builtin '{name}' is not allowed")
            }
            Self::ForbiddenAttribute { object, attr } => {
                write!(f, "Access to '{object}.{attr}' is not allowed")
            }
            Self::OutputLimitExceeded => {
                write!(f, "Output line limit exceeded")
            }
        }
    }
}

// ── Sandbox result ────────────────────────────────────────────────────────────

/// The outcome of a sandboxed script execution.
#[derive(Debug, Clone)]
pub enum SandboxResult {
    Ok {
        return_value: Option<String>,
        output: OutputCapture,
        steps_taken: u64,
        elapsed_ms: u64,
    },
    ScriptError {
        error_type: String,
        message: String,
        line: Option<u32>,
        output: OutputCapture,
        steps_taken: u64,
        elapsed_ms: u64,
    },
    Violation {
        violation: SandboxViolation,
        output: OutputCapture,
        steps_taken: u64,
        elapsed_ms: u64,
    },
}

impl SandboxResult {
    #[must_use] 
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }

    #[must_use] 
    pub const fn output(&self) -> &OutputCapture {
        match self {
            Self::Ok { output, .. } | Self::ScriptError { output, .. } | Self::Violation { output, .. } => output,
        }
    }

    #[must_use] 
    pub const fn steps_taken(&self) -> u64 {
        match self {
            Self::Ok { steps_taken, .. } | Self::ScriptError { steps_taken, .. } | Self::Violation { steps_taken, .. } => *steps_taken,
        }
    }

    #[must_use] 
    pub const fn elapsed_ms(&self) -> u64 {
        match self {
            Self::Ok { elapsed_ms, .. } | Self::ScriptError { elapsed_ms, .. } | Self::Violation { elapsed_ms, .. } => *elapsed_ms,
        }
    }

    #[must_use] 
    pub fn error_message(&self) -> Option<String> {
        match self {
            Self::ScriptError { error_type, message, .. } => {
                Some(format!("{error_type}: {message}"))
            }
            Self::Violation { violation, .. } => Some(violation.to_string()),
            Self::Ok { .. } => None,
        }
    }
}

// ── Sandbox executor ──────────────────────────────────────────────────────────

/// A sandboxed Python execution environment.
/// The actual interpreter is provided by the pure-Rust `PythonEngine` in lib.rs;
/// this struct wraps it with policy enforcement.
pub struct PythonSandbox {
    pub config: SandboxConfig,
    exec_count: u64,
    violation_log: Vec<SandboxViolation>,
}

impl PythonSandbox {
    #[must_use] 
    pub const fn new(config: SandboxConfig) -> Self {
        Self { config, exec_count: 0, violation_log: Vec::new() }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(SandboxConfig::safe_default())
    }

    /// Check whether an import is allowed, returning a violation if not.
    pub fn check_import(&self, module: &str) -> Result<ImportPolicy, SandboxViolation> {
        let policy = self.config.import_filter.check(module);
        if policy == ImportPolicy::Deny {
            Err(SandboxViolation::ForbiddenImport {
                module: module.to_string(),
            })
        } else {
            Ok(policy)
        }
    }

    pub fn check_file_access(&self, path: &str) -> Result<(), SandboxViolation> {
        if !self.config.is_path_allowed(path) {
            return Err(SandboxViolation::ForbiddenFileAccess {
                path: path.to_string(),
            });
        }
        Ok(())
    }

    pub const fn check_recursion(&self, depth: usize) -> Result<(), SandboxViolation> {
        if self.config.max_recursion > 0 && depth > self.config.max_recursion {
            return Err(SandboxViolation::RecursionLimitExceeded { depth });
        }
        Ok(())
    }

    pub const fn check_steps(&self, steps: u64) -> Result<(), SandboxViolation> {
        if self.config.max_steps > 0 && steps > self.config.max_steps {
            return Err(SandboxViolation::StepLimitExceeded { steps });
        }
        Ok(())
    }

    /// Log a sandbox violation for audit purposes.
    pub fn log_violation(&mut self, v: SandboxViolation) {
        self.violation_log.push(v);
    }

    #[must_use] 
    pub fn violations(&self) -> &[SandboxViolation] {
        &self.violation_log
    }

    #[must_use] 
    pub const fn exec_count(&self) -> u64 {
        self.exec_count
    }

    /// Simulate executing a script (used by tests and the interpreter integration).
    /// Returns Ok with empty output if the script passes policy checks.
    pub fn precheck(&self, source: &str) -> Result<(), SandboxViolation> {
        // Basic static checks: scan for forbidden import statements.
        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("import ") {
                let module = rest.split_whitespace().next().unwrap_or("").trim_end_matches(';');
                self.check_import(module)?;
            } else if let Some(rest) = trimmed.strip_prefix("from ") {
                let module = rest.split_whitespace().next().unwrap_or("");
                self.check_import(module)?;
            }
        }
        Ok(())
    }

    /// Build a `SandboxResult` for a successful execution.
    #[must_use] 
    pub fn make_ok_result(
        &self,
        return_value: Option<String>,
        output: OutputCapture,
        steps: u64,
        elapsed: Duration,
    ) -> SandboxResult {
        SandboxResult::Ok {
            return_value,
            output,
            steps_taken: steps,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Build a `SandboxResult` for a script error.
    pub fn make_error_result(
        &self,
        error_type: impl Into<String>,
        message: impl Into<String>,
        line: Option<u32>,
        output: OutputCapture,
        steps: u64,
        elapsed: Duration,
    ) -> SandboxResult {
        SandboxResult::ScriptError {
            error_type: error_type.into(),
            message: message.into(),
            line,
            output,
            steps_taken: steps,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Build a `SandboxResult` for a policy violation.
    #[must_use] 
    pub fn make_violation_result(
        &self,
        violation: SandboxViolation,
        output: OutputCapture,
        steps: u64,
        elapsed: Duration,
    ) -> SandboxResult {
        SandboxResult::Violation {
            violation,
            output,
            steps_taken: steps,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Increment execution count and return it.
    pub const fn next_exec_id(&mut self) -> u64 {
        self.exec_count += 1;
        self.exec_count
    }

    #[must_use] 
    pub fn allowed_imports(&self) -> Vec<&str> {
        self.config.import_filter.allowed_modules()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_filter_strict_denies_unknown() {
        let f = ImportFilter::strict();
        assert!(!f.is_allowed("os"));
        assert!(!f.is_allowed("math"));
    }

    #[test]
    fn test_import_filter_strict_allows_listed() {
        let mut f = ImportFilter::strict();
        f.allow("math");
        assert!(f.is_allowed("math"));
        assert!(!f.is_allowed("os"));
    }

    #[test]
    fn test_import_filter_permissive_denies_os() {
        let f = ImportFilter::permissive();
        assert!(!f.is_allowed("os"));
        assert!(!f.is_allowed("subprocess"));
        assert!(f.is_allowed("os.path"));
    }

    #[test]
    fn test_import_filter_rustre_default() {
        let f = ImportFilter::rustre_default();
        assert!(f.is_allowed("math"));
        assert!(f.is_allowed("rustre"));
        assert!(f.is_allowed("re"));
        assert!(!f.is_allowed("os"));
        assert!(!f.is_allowed("socket"));
    }

    #[test]
    fn test_import_filter_deny_overrides_allow() {
        let mut f = ImportFilter::strict();
        f.allow("sys");
        f.deny("sys");
        assert!(!f.is_allowed("sys"));
    }

    #[test]
    fn test_import_filter_restrictions() {
        let mut f = ImportFilter::strict();
        f.allow("os");
        f.restrict_attrs("os", vec!["system".to_string(), "popen".to_string()]);
        let policy = f.check("os");
        match policy {
            ImportPolicy::AllowWithRestrictions { forbidden_attrs } => {
                assert!(forbidden_attrs.contains(&"system".to_string()));
            }
            _ => panic!("expected AllowWithRestrictions"),
        }
    }

    #[test]
    fn test_output_capture_limits() {
        let mut out = OutputCapture::with_limits(3, 2);
        out.write_stdout("a");
        out.write_stdout("b");
        out.write_stdout("c");
        out.write_stdout("d"); // exceeds limit
        assert_eq!(out.stdout.len(), 3);
        assert!(out.truncated);
    }

    #[test]
    fn test_output_capture_clear() {
        let mut out = OutputCapture::new();
        out.write_stdout("x");
        out.clear();
        assert!(out.stdout.is_empty());
        assert!(!out.truncated);
    }

    #[test]
    fn test_output_text_join() {
        let mut out = OutputCapture::new();
        out.write_stdout("line1");
        out.write_stdout("line2");
        assert_eq!(out.stdout_text(), "line1\nline2");
    }

    #[test]
    fn test_exec_timeout_not_started() {
        let t = ExecTimeout::new(Duration::from_secs(1));
        assert!(!t.is_expired());
    }

    #[test]
    fn test_exec_timeout_started_not_expired() {
        let mut t = ExecTimeout::new(Duration::from_secs(60));
        t.start();
        assert!(!t.is_expired());
    }

    #[test]
    fn test_sandbox_config_defaults() {
        let cfg = SandboxConfig::safe_default();
        assert_eq!(cfg.timeout, Duration::from_secs(5));
        assert_eq!(cfg.max_steps, 1_000_000);
        assert!(cfg.allow_print);
        assert!(cfg.expose_rustre_api);
    }

    #[test]
    fn test_sandbox_precheck_allows_math() {
        let sb = PythonSandbox::with_defaults();
        let src = "import math\nx = math.sqrt(4)";
        assert!(sb.precheck(src).is_ok());
    }

    #[test]
    fn test_sandbox_precheck_denies_os() {
        let sb = PythonSandbox::with_defaults();
        let src = "import os\nos.system('ls')";
        assert!(sb.precheck(src).is_err());
    }

    #[test]
    fn test_sandbox_precheck_denies_from_os() {
        let sb = PythonSandbox::with_defaults();
        let src = "from os import path";
        assert!(sb.precheck(src).is_err());
    }

    #[test]
    fn test_sandbox_check_recursion() {
        let sb = PythonSandbox::with_defaults();
        assert!(sb.check_recursion(10).is_ok());
        assert!(sb.check_recursion(1000).is_err());
    }

    #[test]
    fn test_sandbox_check_steps() {
        let sb = PythonSandbox::with_defaults();
        assert!(sb.check_steps(100).is_ok());
        assert!(sb.check_steps(2_000_000).is_err());
    }

    #[test]
    fn test_sandbox_violation_display() {
        let v = SandboxViolation::ForbiddenImport { module: "os".to_string() };
        assert!(v.to_string().contains("os"));
        let v2 = SandboxViolation::Timeout { elapsed_ms: 5000 };
        assert!(v2.to_string().contains("5000"));
    }

    #[test]
    fn test_sandbox_result_is_ok() {
        let sb = PythonSandbox::with_defaults();
        let result = sb.make_ok_result(Some("42".to_string()), OutputCapture::new(), 100, Duration::from_millis(10));
        assert!(result.is_ok());
        assert_eq!(result.steps_taken(), 100);
    }

    #[test]
    fn test_sandbox_result_error() {
        let sb = PythonSandbox::with_defaults();
        let result = sb.make_error_result("NameError", "x not defined", Some(3), OutputCapture::new(), 50, Duration::ZERO);
        assert!(!result.is_ok());
        assert!(result.error_message().unwrap().contains("NameError"));
    }

    #[test]
    fn test_sandbox_path_check() {
        let mut cfg = SandboxConfig::safe_default();
        cfg.allowed_paths.push("/tmp/rustre".to_string());
        let sb = PythonSandbox::new(cfg);
        assert!(sb.check_file_access("/tmp/rustre/data.bin").is_ok());
        assert!(sb.check_file_access("/etc/passwd").is_err());
    }
}
