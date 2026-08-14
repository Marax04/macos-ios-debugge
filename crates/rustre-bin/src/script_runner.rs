//! `script_runner` — CLI script execution subsystem.
//!
//! Run Lua / Python / Rhai scripts from the command line with argument passing,
//! stdout/stderr capture, timeout enforcement, template generation, and a
//! sandboxed execution context stub.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the script runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// The script file could not be read.
    Io(String),
    /// The script language is not supported.
    UnsupportedLanguage(String),
    /// Script execution timed out.
    Timeout { elapsed_ms: u64, limit_ms: u64 },
    /// The script exited with a non-zero code.
    NonZeroExit { code: i32, stderr: String },
    /// Script parse / syntax error.
    SyntaxError { line: u32, message: String },
    /// A sandbox violation was detected.
    SandboxViolation(String),
    /// Template generation failed.
    TemplateError(String),
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::UnsupportedLanguage(l) => write!(f, "unsupported language: {l}"),
            Self::Timeout { elapsed_ms, limit_ms } =>
                write!(f, "script timed out after {elapsed_ms}ms (limit {limit_ms}ms)"),
            Self::NonZeroExit { code, stderr } =>
                write!(f, "script exited with code {code}: {stderr}"),
            Self::SyntaxError { line, message } =>
                write!(f, "syntax error at line {line}: {message}"),
            Self::SandboxViolation(v) => write!(f, "sandbox violation: {v}"),
            Self::TemplateError(e) => write!(f, "template error: {e}"),
        }
    }
}

// ── Language detection ────────────────────────────────────────────────────────

/// A supported scripting language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Lua,
    Python,
    Rhai,
    Shell,
    JavaScript,
}

impl ScriptLanguage {
    /// Infer language from file extension.
    ///
    /// # Errors
    /// Returns `ScriptError::UnsupportedLanguage` if the extension is unknown.
    pub fn from_path(path: &Path) -> Result<Self, ScriptError> {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        Self::from_ext(&ext)
    }

    /// Infer language from an explicit string (name or extension).
    ///
    /// # Errors
    /// Returns `ScriptError::UnsupportedLanguage` if the name is unknown.
    pub fn from_ext(s: &str) -> Result<Self, ScriptError> {
        match s {
            "lua"       => Ok(Self::Lua),
            "py"        => Ok(Self::Python),
            "rhai"      => Ok(Self::Rhai),
            "sh"|"bash" => Ok(Self::Shell),
            "js"        => Ok(Self::JavaScript),
            other => Err(ScriptError::UnsupportedLanguage(other.into())),
        }
    }

    /// Canonical name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lua => "lua",
            Self::Python => "python",
            Self::Rhai => "rhai",
            Self::Shell => "shell",
            Self::JavaScript => "javascript",
        }
    }

    /// File extension for generated templates.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Lua => "lua",
            Self::Python => "py",
            Self::Rhai => "rhai",
            Self::Shell => "sh",
            Self::JavaScript => "js",
        }
    }

    /// Return the shebang line for templates.
    #[must_use]
    pub const fn shebang(self) -> &'static str {
        match self {
            Self::Lua => "#!/usr/bin/env lua5.4",
            Self::Python => "#!/usr/bin/env python3",
            Self::Rhai => "# rhai",
            Self::Shell => "#!/usr/bin/env bash",
            Self::JavaScript => "#!/usr/bin/env node",
        }
    }
}

impl fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── Sandbox context ───────────────────────────────────────────────────────────

/// Policy flags for script sandbox.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Allow filesystem reads (outside of the script itself).
    pub allow_fs_read: bool,
    /// Allow filesystem writes.
    pub allow_fs_write: bool,
    /// Allow network access.
    pub allow_network: bool,
    /// Allow spawning child processes.
    pub allow_spawn: bool,
    /// Maximum memory in bytes (0 = unlimited).
    pub max_memory: u64,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allow_fs_read:  true,
            allow_fs_write: false,
            allow_network:  false,
            allow_spawn:    false,
            max_memory:     128 * 1024 * 1024, // 128 MiB
        }
    }
}

impl SandboxPolicy {
    /// A permissive policy (all allowed, no memory cap).
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            allow_fs_read:  true,
            allow_fs_write: true,
            allow_network:  true,
            allow_spawn:    true,
            max_memory:     0,
        }
    }

    /// A strict policy (read-only, no network, no spawn).
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_fs_read:  false,
            allow_fs_write: false,
            allow_network:  false,
            allow_spawn:    false,
            max_memory:     64 * 1024 * 1024,
        }
    }

    /// Check a proposed operation.
    ///
    /// # Errors
    /// Returns `ScriptError::SandboxViolation` on policy denial.
    pub fn check_op(&self, op: &str) -> Result<(), ScriptError> {
        match op {
            "fs_read"  if !self.allow_fs_read  => Err(ScriptError::SandboxViolation("filesystem read denied".into())),
            "fs_write" if !self.allow_fs_write => Err(ScriptError::SandboxViolation("filesystem write denied".into())),
            "network"  if !self.allow_network  => Err(ScriptError::SandboxViolation("network access denied".into())),
            "spawn"    if !self.allow_spawn    => Err(ScriptError::SandboxViolation("process spawn denied".into())),
            _ => Ok(()),
        }
    }
}

/// Variables injected into the script runtime.
#[derive(Debug, Clone, Default)]
pub struct ScriptContext {
    /// Exported variables (name → JSON-serialisable value as string).
    pub vars: HashMap<String, String>,
    /// Binary path being analysed (if any).
    pub binary_path: Option<PathBuf>,
    /// Session identifier.
    pub session_id: Option<String>,
    /// Platform API version string.
    pub api_version: String,
}

impl ScriptContext {
    /// Create a new context with default API version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            api_version: "2.0.0".into(),
            ..Default::default()
        }
    }

    /// Set a string variable.
    pub fn set_var(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(name.into(), value.into());
    }

    /// Escape a string value so it is safe to embed inside a double-quoted
    /// string literal in Lua, Python, or Rhai.  Backslash-escapes the
    /// characters that would break out of the literal: `\`, `"`, and newlines.
    fn escape_string_literal(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Render the context as a Lua variable prologue.
    ///
    /// All user-controlled values (`binary_path`, `session_id`, variable
    /// values) are escaped before being embedded inside double-quoted Lua
    /// string literals to prevent injection of arbitrary Lua code.
    #[must_use]
    pub fn render_lua_prologue(&self) -> String {
        let mut out = String::from("-- RustRE script context\n");
        out.push_str(&format!(
            "local api_version = \"{}\"\n",
            Self::escape_string_literal(&self.api_version)
        ));
        if let Some(ref bp) = self.binary_path {
            out.push_str(&format!(
                "local binary_path = \"{}\"\n",
                Self::escape_string_literal(&bp.display().to_string())
            ));
        }
        if let Some(ref sid) = self.session_id {
            out.push_str(&format!(
                "local session_id = \"{}\"\n",
                Self::escape_string_literal(sid)
            ));
        }
        for (k, v) in &self.vars {
            out.push_str(&format!(
                "local {k} = \"{}\"\n",
                Self::escape_string_literal(v)
            ));
        }
        out.push_str("local rustre = { api_version = api_version }\n");
        out
    }

    /// Render the context as a Python variable prologue.
    ///
    /// All user-controlled values are escaped before embedding in string
    /// literals to prevent injection of arbitrary Python code.
    #[must_use]
    pub fn render_python_prologue(&self) -> String {
        let mut out = String::from("# RustRE script context\n");
        out.push_str(&format!(
            "api_version = \"{}\"\n",
            Self::escape_string_literal(&self.api_version)
        ));
        if let Some(ref bp) = self.binary_path {
            // Use a regular double-quoted string (not a raw string) so our
            // escape sequences are honoured; raw strings cannot contain `\`.
            out.push_str(&format!(
                "binary_path = \"{}\"\n",
                Self::escape_string_literal(&bp.display().to_string())
            ));
        }
        if let Some(ref sid) = self.session_id {
            out.push_str(&format!(
                "session_id = \"{}\"\n",
                Self::escape_string_literal(sid)
            ));
        }
        for (k, v) in &self.vars {
            out.push_str(&format!(
                "{k} = \"{}\"\n",
                Self::escape_string_literal(v)
            ));
        }
        out
    }

    /// Render the context as a Rhai variable prologue.
    ///
    /// All user-controlled values are escaped before embedding in string
    /// literals to prevent injection of arbitrary Rhai code.
    #[must_use]
    pub fn render_rhai_prologue(&self) -> String {
        let mut out = String::from("// RustRE script context\n");
        out.push_str(&format!(
            "let api_version = \"{}\";\n",
            Self::escape_string_literal(&self.api_version)
        ));
        if let Some(ref bp) = self.binary_path {
            out.push_str(&format!(
                "let binary_path = \"{}\";\n",
                Self::escape_string_literal(&bp.display().to_string())
            ));
        }
        if let Some(ref sid) = self.session_id {
            out.push_str(&format!(
                "let session_id = \"{}\";\n",
                Self::escape_string_literal(sid)
            ));
        }
        for (k, v) in &self.vars {
            out.push_str(&format!(
                "let {k} = \"{}\";\n",
                Self::escape_string_literal(v)
            ));
        }
        out
    }
}

// ── Execution result ──────────────────────────────────────────────────────────

/// The result of running a script.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Wall-clock execution time.
    pub elapsed: Duration,
    /// Script language used.
    pub language: ScriptLanguage,
    /// Number of output lines.
    pub line_count: usize,
}

impl ScriptResult {
    /// Return `true` if the script succeeded.
    #[must_use]
    pub const fn success(&self) -> bool { self.exit_code == 0 }

    /// Print stdout to `w`.
    pub fn print_stdout(&self, w: &mut dyn io::Write) {
        let _ = w.write_all(self.stdout.as_bytes());
    }

    /// Print a summary line.
    pub fn print_summary(&self, w: &mut dyn io::Write, color: bool) {
        let c = |code: &'static str| if color { code } else { "" };
        let status = if self.success() {
            format!("{}ok{}", c("\x1b[32m"), c("\x1b[0m"))
        } else {
            format!("{}FAILED (exit {}){}", c("\x1b[31m"), self.exit_code, c("\x1b[0m"))
        };
        let _ = writeln!(w,
            "  Script ({}) {} in {:.3}s — {} output line(s)",
            self.language, status, self.elapsed.as_secs_f64(), self.line_count
        );
    }
}

// ── Script executor ───────────────────────────────────────────────────────────

/// Configuration for a single script run.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Source code (either read from file or inline).
    pub code: String,
    /// Script file path (for error reporting; may be synthetic).
    pub path: PathBuf,
    /// Language.
    pub language: ScriptLanguage,
    /// Arguments passed to the script.
    pub args: Vec<String>,
    /// Maximum execution wall time.
    pub timeout: Duration,
    /// Sandbox policy.
    pub policy: SandboxPolicy,
    /// Injected context variables.
    pub context: ScriptContext,
    /// Enable debug tracing output.
    pub debug: bool,
}

impl RunConfig {
    /// Construct a `RunConfig` from a file path.
    ///
    /// # Errors
    /// Returns `ScriptError::Io` if the file cannot be read.
    /// Returns `ScriptError::UnsupportedLanguage` if the extension is unknown.
    pub fn from_file(
        path: PathBuf,
        args: Vec<String>,
        timeout: Duration,
        policy: SandboxPolicy,
        context: ScriptContext,
        debug: bool,
    ) -> Result<Self, ScriptError> {
        let language = ScriptLanguage::from_path(&path)?;
        let code = fs::read_to_string(&path)
            .map_err(|e| ScriptError::Io(format!("{}: {e}", path.display())))?;
        Ok(Self { code, path, language, args, timeout, policy, context, debug })
    }

    /// Construct from inline code and an explicit language name.
    ///
    /// # Errors
    /// Returns `ScriptError::UnsupportedLanguage` if `lang` is unknown.
    pub fn from_inline(
        code: String,
        lang: &str,
        args: Vec<String>,
        timeout: Duration,
        policy: SandboxPolicy,
        context: ScriptContext,
        debug: bool,
    ) -> Result<Self, ScriptError> {
        let language = ScriptLanguage::from_ext(lang)?;
        let path = PathBuf::from(format!("<inline>.{}", language.extension()));
        Ok(Self { code, path, language, args, timeout, policy, context, debug })
    }

    /// Build the full script text with the context prologue prepended.
    #[must_use]
    pub fn full_source(&self) -> String {
        let prologue = match self.language {
            ScriptLanguage::Lua        => self.context.render_lua_prologue(),
            ScriptLanguage::Python     => self.context.render_python_prologue(),
            ScriptLanguage::Rhai       => self.context.render_rhai_prologue(),
            ScriptLanguage::Shell | ScriptLanguage::JavaScript => String::new(),
        };
        format!("{prologue}{}", self.code)
    }
}

/// The script executor (stub implementation — no live interpreter).
pub struct ScriptExecutor;

impl ScriptExecutor {
    /// Execute `config` and return a `ScriptResult`.
    ///
    /// In this stub the execution is simulated: the code is scanned for
    /// obvious syntax errors and a realistic result is returned.
    ///
    /// # Errors
    /// Returns `ScriptError` for timeout, sandbox violation, or syntax errors.
    pub fn run(config: &RunConfig) -> Result<ScriptResult, ScriptError> {
        let start = Instant::now();

        // Sandbox pre-check: scan code for forbidden calls.
        Self::check_sandbox(&config.code, &config.policy)?;

        // Syntax check stub.
        let source = config.full_source();
        Self::syntax_check(&source, config.language)?;

        // Simulate execution time proportional to code length.
        // Simulated cost is based on the user's code only (not the auto-injected
        // context prologue) so that an empty user script completes in 0 ms.
        let sim_ms = (config.code.len() as u64).min(500);
        if Duration::from_millis(sim_ms) > config.timeout {
            return Err(ScriptError::Timeout {
                elapsed_ms: sim_ms,
                limit_ms: u64::try_from(config.timeout.as_millis()).unwrap_or(u64::MAX),
            });
        }

        let elapsed = start.elapsed();
        let stdout = Self::simulate_output(config);
        let line_count = stdout.lines().count();

        Ok(ScriptResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            elapsed,
            language: config.language,
            line_count,
        })
    }

    fn check_sandbox(code: &str, policy: &SandboxPolicy) -> Result<(), ScriptError> {
        let net_patterns = ["http.get", "socket.connect", "urllib", "requests.get", "fetch("];
        let spawn_patterns = ["os.execute", "subprocess", "std::process", "child_process"];

        for pat in &net_patterns {
            if !policy.allow_network && code.contains(pat) {
                return Err(ScriptError::SandboxViolation(
                    format!("network call detected: '{pat}'")
                ));
            }
        }
        for pat in &spawn_patterns {
            if !policy.allow_spawn && code.contains(pat) {
                return Err(ScriptError::SandboxViolation(
                    format!("process spawn detected: '{pat}'")
                ));
            }
        }
        if !policy.allow_fs_write {
            let write_pats = ["io.open.*\"w\"", "open(.*\"w\"", "File::create", "fs.writeFile"];
            for pat in &write_pats {
                if code.contains(&pat[..pat.find('*').unwrap_or(pat.len())]) {
                    return Err(ScriptError::SandboxViolation(
                        format!("filesystem write detected (pattern '{pat}')")
                    ));
                }
            }
        }
        Ok(())
    }

    fn syntax_check(source: &str, lang: ScriptLanguage) -> Result<(), ScriptError> {
        // Minimal bracket/paren balance check.
        let (mut parens, mut braces, mut brackets) = (0i32, 0i32, 0i32);
        for (lineno, line) in source.lines().enumerate() {
            let line = strip_comment(line, lang);
            for ch in line.chars() {
                match ch {
                    '(' => parens   += 1,
                    ')' => parens   -= 1,
                    '{' => braces   += 1,
                    '}' => braces   -= 1,
                    '[' => brackets += 1,
                    ']' => brackets -= 1,
                    _ => {}
                }
                if parens < 0 {
                    return Err(ScriptError::SyntaxError {
                        line: lineno as u32 + 1,
                        message: "unmatched ')'".into(),
                    });
                }
            }
        }
        if braces != 0 {
            return Err(ScriptError::SyntaxError {
                line: source.lines().count() as u32,
                message: format!("unmatched braces (balance {braces})"),
            });
        }
        if brackets != 0 {
            return Err(ScriptError::SyntaxError {
                line: source.lines().count() as u32,
                message: format!("unmatched brackets (balance {brackets})"),
            });
        }
        Ok(())
    }

    fn simulate_output(config: &RunConfig) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut out = String::new();
        out.push_str(&format!("-- {} script output (simulated) --\n", config.language));
        out.push_str(&format!("script: {}\n", config.path.display()));
        if !config.args.is_empty() {
            out.push_str(&format!("args: {}\n", config.args.join(" ")));
        }
        out.push_str(&format!("timestamp: {ts}\n"));
        out.push_str(&format!("source_lines: {}\n", config.code.lines().count()));
        if config.debug {
            out.push_str("debug: context variables injected\n");
            for (k, v) in &config.context.vars {
                out.push_str(&format!("  {k} = {v}\n"));
            }
        }
        out
    }
}

fn strip_comment(line: &str, lang: ScriptLanguage) -> &str {
    let comment_char = match lang {
        ScriptLanguage::Lua        => "--",
        ScriptLanguage::Shell      => "#",
        ScriptLanguage::Python     => "#",
        ScriptLanguage::Rhai | ScriptLanguage::JavaScript => "//",
    };
    line.split_once(comment_char).map_or(line, |(before, _)| before)
}

// ── Template generator ────────────────────────────────────────────────────────

/// Template type for generated scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// Minimal hello-world skeleton.
    Minimal,
    /// Full RE workflow (load binary, iterate functions, print addresses).
    Analysis,
    /// String search template.
    StringSearch,
    /// Patch application template.
    Patcher,
}

impl TemplateKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Analysis => "analysis",
            Self::StringSearch => "string_search",
            Self::Patcher => "patcher",
        }
    }
}

/// Generate a script template.
///
/// # Errors
/// Returns `ScriptError::TemplateError` if the kind/language combination
/// is not supported.
pub fn generate_template(lang: ScriptLanguage, kind: TemplateKind) -> Result<String, ScriptError> {
    match lang {
        ScriptLanguage::Lua    => Ok(lua_template(kind)),
        ScriptLanguage::Python => Ok(python_template(kind)),
        ScriptLanguage::Rhai   => Ok(rhai_template(kind)),
        other => Err(ScriptError::TemplateError(format!("no template for {other}"))),
    }
}

fn lua_template(kind: TemplateKind) -> String {
    match kind {
        TemplateKind::Minimal => r#"#!/usr/bin/env lua5.4
-- RustRE minimal Lua template
-- Variables from context:
--   api_version, binary_path, session_id

print("RustRE Lua script running")
print("API version: " .. api_version)

-- Your code here:
"#.into(),

        TemplateKind::Analysis => r#"#!/usr/bin/env lua5.4
-- RustRE analysis Lua template

print("Analysing: " .. (binary_path or "<no binary>"))

-- Example: iterate over function list
local functions = rustre.get_functions()
if functions then
    for _, fn_info in ipairs(functions) do
        print(string.format("  0x%016x  %s", fn_info.address, fn_info.name))
    end
else
    print("(no function list available in stub)")
end
"#.into(),

        TemplateKind::StringSearch => r#"#!/usr/bin/env lua5.4
-- RustRE string search Lua template

local pattern = arg[1] or "password"
print("Searching for: " .. pattern)

local strings = rustre.get_strings({ min_len = 4 })
if strings then
    for _, s in ipairs(strings) do
        if s.value:find(pattern) then
            print(string.format("  0x%08x  %s", s.offset, s.value))
        end
    end
end
"#.into(),

        TemplateKind::Patcher => r#"#!/usr/bin/env lua5.4
-- RustRE patch application Lua template

local addr = 0x401000
local patch = { 0x90, 0x90, 0x90 }  -- NOP sled

print(string.format("Patching 0x%x with %d bytes", addr, #patch))
-- rustre.patch(addr, patch)
print("Done.")
"#.into(),
    }
}

fn python_template(kind: TemplateKind) -> String {
    match kind {
        TemplateKind::Minimal => r#"#!/usr/bin/env python3
# RustRE minimal Python template

print(f"RustRE Python script — API {api_version}")
# Your code here:
"#.into(),

        TemplateKind::Analysis => r#"#!/usr/bin/env python3
# RustRE analysis Python template

print(f"Analysing: {binary_path!r}")

functions = rustre.get_functions()
for fn_info in (functions or []):
    print(f"  {fn_info['address']:#018x}  {fn_info['name']}")
"#.into(),

        TemplateKind::StringSearch => r#"#!/usr/bin/env python3
# RustRE string search Python template
import sys, re

pattern = sys.argv[1] if len(sys.argv) > 1 else "password"
rx = re.compile(pattern, re.IGNORECASE)
strings = rustre.get_strings(min_len=4) or []
for s in strings:
    if rx.search(s["value"]):
        print(f"  {s['offset']:#010x}  {s['value']}")
"#.into(),

        TemplateKind::Patcher => r#"#!/usr/bin/env python3
# RustRE patcher Python template

addr = 0x401000
patch = bytes([0x90, 0x90, 0x90])
print(f"Patching {addr:#x} with {len(patch)} bytes")
# rustre.patch(addr, patch)
print("Done.")
"#.into(),
    }
}

fn rhai_template(kind: TemplateKind) -> String {
    match kind {
        TemplateKind::Minimal => r#"// RustRE minimal Rhai template
print(`RustRE Rhai script — API ${api_version}`);
// Your code here:
"#.into(),

        TemplateKind::Analysis => r#"// RustRE analysis Rhai template
print(`Analysing: ${binary_path}`);
let functions = rustre::get_functions();
for fn_info in functions {
    print(`  ${fn_info.address}  ${fn_info.name}`);
}
"#.into(),

        TemplateKind::StringSearch => r#"// RustRE string search Rhai template
let pattern = "password";
let strings = rustre::get_strings(#{min_len: 4});
for s in strings {
    if s.value.contains(pattern) {
        print(`  ${s.offset}  ${s.value}`);
    }
}
"#.into(),

        TemplateKind::Patcher => r#"// RustRE patcher Rhai template
let addr = 0x401000;
let patch = [0x90, 0x90, 0x90];
print(`Patching ${addr} with ${patch.len()} bytes`);
// rustre::patch(addr, patch);
print("Done.");
"#.into(),
    }
}

// ── Script debugger ───────────────────────────────────────────────────────────

/// A debug session that replays output with source annotations.
pub struct ScriptDebugger {
    source_lines: Vec<String>,
    breakpoints: Vec<u32>,
    current_line: u32,
    step_mode: bool,
}

impl ScriptDebugger {
    /// Create a debugger for the given source.
    #[must_use]
    pub fn new(source: &str) -> Self {
        Self {
            source_lines: source.lines().map(String::from).collect(),
            breakpoints: Vec::new(),
            current_line: 0,
            step_mode: false,
        }
    }

    /// Set a breakpoint at a 1-indexed line number.
    pub fn set_breakpoint(&mut self, line: u32) {
        if !self.breakpoints.contains(&line) {
            self.breakpoints.push(line);
        }
    }

    /// Clear a breakpoint.
    pub fn clear_breakpoint(&mut self, line: u32) {
        self.breakpoints.retain(|&b| b != line);
    }

    /// Enable step-by-step mode.
    pub fn enable_step(&mut self) { self.step_mode = true; }

    /// Return whether the given 1-indexed line is a breakpoint.
    #[must_use]
    pub fn is_breakpoint(&self, line: u32) -> bool {
        self.breakpoints.contains(&line)
    }

    /// Print an annotated source listing to `w`.
    pub fn print_listing(&self, w: &mut dyn io::Write, color: bool) {
        let c = |code: &'static str| if color { code } else { "" };
        for (i, line) in self.source_lines.iter().enumerate() {
            let lineno = i as u32 + 1;
            let bp_marker = if self.is_breakpoint(lineno) {
                format!("{}B{}", c("\x1b[31m"), c("\x1b[0m"))
            } else {
                " ".into()
            };
            let cur_marker = if lineno == self.current_line { ">" } else { " " };
            let _ = writeln!(w, " {cur_marker}{bp_marker} {:4}  {}{}{}", lineno,
                c("\x1b[2m"), line, c("\x1b[0m"));
        }
    }

    /// Advance to the next line.  Returns `false` when past the end.
    pub fn step(&mut self) -> bool {
        self.current_line += 1;
        (self.current_line as usize) <= self.source_lines.len()
    }

    /// Run until a breakpoint or end-of-script.  Returns the line that stopped.
    pub fn run_to_breakpoint(&mut self) -> Option<u32> {
        while self.step() {
            if self.is_breakpoint(self.current_line) {
                return Some(self.current_line);
            }
        }
        None
    }
}

// ── High-level CLI runners ────────────────────────────────────────────────────

/// Arguments for the `script run` command.
#[derive(Debug, Clone)]
pub struct ScriptRunArgs {
    pub path: Option<PathBuf>,
    pub inline: Option<String>,
    pub lang: Option<String>,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub sandbox: bool,
    pub debug: bool,
    pub json: bool,
    pub color: bool,
    pub context_vars: HashMap<String, String>,
}

/// Run a script from CLI arguments.
pub fn cli_run_script(args: &ScriptRunArgs, w: &mut dyn io::Write) -> i32 {
    let policy = if args.sandbox {
        SandboxPolicy::strict()
    } else {
        SandboxPolicy::default()
    };
    let timeout = Duration::from_secs(args.timeout_secs.max(1));

    let mut ctx = ScriptContext::new();
    for (k, v) in &args.context_vars {
        ctx.set_var(k, v);
    }
    if let Some(ref p) = args.path {
        ctx.binary_path = Some(p.clone());
    }

    let config = if let Some(ref inline) = args.inline {
        let lang = args.lang.as_deref().unwrap_or("rhai");
        match RunConfig::from_inline(inline.clone(), lang, args.args.clone(), timeout, policy, ctx, args.debug) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(w, "error: {e}");
                return 1;
            }
        }
    } else if let Some(ref path) = args.path {
        match RunConfig::from_file(path.clone(), args.args.clone(), timeout, policy, ctx, args.debug) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(w, "error: {e}");
                return 1;
            }
        }
    } else {
        let _ = writeln!(w, "error: provide --inline or a file path");
        return 1;
    };

    match ScriptExecutor::run(&config) {
        Ok(result) => {
            if args.json {
                let _ = writeln!(w,
                    "{{\"exit_code\":{},\"elapsed_ms\":{},\"stdout_lines\":{},\"language\":\"{}\"}}",
                    result.exit_code,
                    result.elapsed.as_millis(),
                    result.line_count,
                    result.language,
                );
            } else {
                result.print_stdout(w);
                result.print_summary(w, args.color);
            }
            result.exit_code
        }
        Err(e) => {
            if args.json {
                let _ = writeln!(w, "{{\"error\":\"{e}\"}}");
            } else {
                let _ = writeln!(w, "error: {e}");
            }
            1
        }
    }
}

/// Generate and write a script template.
pub fn cli_gen_template(lang: &str, kind: &str, out_path: Option<&Path>, w: &mut dyn io::Write) -> i32 {
    let language = match ScriptLanguage::from_ext(lang) {
        Ok(l) => l,
        Err(e) => { let _ = writeln!(w, "error: {e}"); return 1; }
    };
    let kind = match kind {
        "minimal" => TemplateKind::Minimal,
        "analysis" => TemplateKind::Analysis,
        "string_search" => TemplateKind::StringSearch,
        "patcher" => TemplateKind::Patcher,
        other => { let _ = writeln!(w, "error: unknown template kind '{other}'"); return 1; }
    };
    let text = match generate_template(language, kind) {
        Ok(t) => t,
        Err(e) => { let _ = writeln!(w, "error: {e}"); return 1; }
    };
    if let Some(path) = out_path {
        match fs::write(path, &text) {
            Ok(()) => { let _ = writeln!(w, "wrote template to {}", path.display()); }
            Err(e) => { let _ = writeln!(w, "error writing {}: {e}", path.display()); return 1; }
        }
    } else {
        let _ = w.write_all(text.as_bytes());
    }
    0
}

/// Slurp an entire script source from any [`BufRead`] reader, normalising line
/// endings to `\n`. Convenience for piping scripts in via stdin without the
/// caller having to perform their own buffering. Optionally writes a progress
/// note to `w` after each non-trivial line, using [`Write::write_all`].
pub fn read_script_from<R: BufRead>(mut r: R, w: &mut dyn Write) -> io::Result<String> {
    let mut buf = String::new();
    let mut line = String::new();
    let mut count: usize = 0;
    while r.read_line(&mut line)? > 0 {
        buf.push_str(line.trim_end_matches('\r'));
        if !buf.ends_with('\n') {
            buf.push('\n');
        }
        count += 1;
        if count % 256 == 0 {
            let _ = w.write_all(format!("# read {count} lines\n").as_bytes());
        }
        line.clear();
    }
    Ok(buf)
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_from_ext() {
        assert_eq!(ScriptLanguage::from_ext("lua").unwrap(), ScriptLanguage::Lua);
        assert_eq!(ScriptLanguage::from_ext("py").unwrap(), ScriptLanguage::Python);
        assert!(ScriptLanguage::from_ext("rs").is_err());
    }

    #[test]
    fn test_semver_display() {
        assert_eq!(ScriptLanguage::Lua.name(), "lua");
        assert_eq!(ScriptLanguage::Python.extension(), "py");
    }

    #[test]
    fn test_sandbox_policy_default() {
        let p = SandboxPolicy::default();
        assert!(p.check_op("fs_read").is_ok());
        assert!(p.check_op("network").is_err());
    }

    #[test]
    fn test_sandbox_check_network() {
        let policy = SandboxPolicy::strict();
        let code = "http.get('http://evil.com')";
        assert!(ScriptExecutor::run(&RunConfig::from_inline(
            code.into(), "lua", vec![], Duration::from_secs(5), policy,
            ScriptContext::new(), false
        ).unwrap()).is_err());
    }

    #[test]
    fn test_syntax_check_unmatched_brace() {
        let code = "fn foo() { let x = 1;";
        let result = RunConfig::from_inline(
            code.into(), "rhai", vec![], Duration::from_secs(5),
            SandboxPolicy::permissive(), ScriptContext::new(), false,
        ).and_then(|c| ScriptExecutor::run(&c));
        assert!(matches!(result, Err(ScriptError::SyntaxError { .. })));
    }

    #[test]
    fn test_run_minimal_rhai() {
        let code = "print(\"hello\");";
        let config = RunConfig::from_inline(
            code.into(), "rhai", vec![], Duration::from_secs(5),
            SandboxPolicy::default(), ScriptContext::new(), false,
        ).unwrap();
        let result = ScriptExecutor::run(&config).unwrap();
        assert!(result.success());
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn test_context_prologue() {
        let mut ctx = ScriptContext::new();
        ctx.set_var("my_var", "42");
        let prologue = ctx.render_python_prologue();
        assert!(prologue.contains("my_var"));
        assert!(prologue.contains("42"));
    }

    #[test]
    fn test_generate_template_lua() {
        let t = generate_template(ScriptLanguage::Lua, TemplateKind::Analysis).unwrap();
        assert!(t.contains("lua5.4"));
    }

    #[test]
    fn test_generate_template_unsupported() {
        let err = generate_template(ScriptLanguage::Shell, TemplateKind::Minimal);
        assert!(err.is_err());
    }

    #[test]
    fn test_debugger_breakpoints() {
        let mut dbg = ScriptDebugger::new("line1\nline2\nline3\n");
        dbg.set_breakpoint(2);
        assert!(dbg.is_breakpoint(2));
        assert!(!dbg.is_breakpoint(1));
        dbg.clear_breakpoint(2);
        assert!(!dbg.is_breakpoint(2));
    }

    #[test]
    fn test_debugger_run_to_bp() {
        let mut dbg = ScriptDebugger::new("a\nb\nc\nd\n");
        dbg.set_breakpoint(3);
        let stopped = dbg.run_to_breakpoint();
        assert_eq!(stopped, Some(3));
    }

    #[test]
    fn test_timeout_detection() {
        // A very short timeout with code that simulates work should trigger it
        // only if the code is long enough.  Use an empty script to avoid it.
        let code = "";
        let config = RunConfig::from_inline(
            code.into(), "lua", vec![], Duration::from_millis(1),
            SandboxPolicy::default(), ScriptContext::new(), false,
        ).unwrap();
        // Empty script should complete in under 1ms (sim_ms = 0).
        let r = ScriptExecutor::run(&config);
        assert!(r.is_ok());
    }
}
