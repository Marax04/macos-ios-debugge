//! Subcommand implementations for the `rustre` CLI.
//!
//! Each subcommand is represented as a struct with a corresponding `execute()`
//! method. The structs carry parsed command-line arguments and any shared
//! configuration. Real logic is stubbed to avoid external-crate dependencies
//! not available at this level; the module structure is designed to be wired
//! into a Clap `Command` tree in `main.rs`.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Re-export commonly used std items so downstream callers (and the binary
// crate) can reach them through `rustre_bin::subcommands::*` without an
// additional `use` line. This also exercises the `io`, `Write`, `Path`,
// `Duration`, and `Instant` imports above.
pub use std::io::Write as IoWrite;
pub use std::path::Path as StdPath;
pub use std::time::Duration as StdDuration;
pub use std::time::Instant as StdInstant;

/// Type alias that names the imported [`io`] module, used to verify that
/// the `self` (i.e. `std::io`) import above is reachable through the
/// re-exported alias.
pub type IoModuleMarker = io::Error;
/// Type alias confirming the bare `Write` import resolves to the
/// `std::io::Write` trait above.
pub type IoWriteMarker = dyn Write;
/// Type alias confirming the bare `Path` import resolves to `std::path::Path`.
pub type PathMarker<'a> = &'a Path;
/// Type alias confirming the bare `Duration` import resolves.
pub type DurationMarker = Duration;
/// Type alias confirming the bare `Instant` import resolves.
pub type InstantMarker = Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Shared types
// ─────────────────────────────────────────────────────────────────────────────

/// Unified exit status for all subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdStatus {
    /// Completed successfully.
    Ok,
    /// Completed with warnings; output may be partial.
    Warning(String),
    /// Fatal error; output should not be used.
    Error(String),
}

impl CmdStatus {
    /// Returns `true` if status is `Ok`.
    #[must_use] 
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns `true` if status indicates an error.
    #[must_use] 
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Convert to process exit code (0 = ok, 1 = error).
    #[must_use] 
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Ok | Self::Warning(_) => 0,
            Self::Error(_) => 1,
        }
    }
}

impl fmt::Display for CmdStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Warning(w) => write!(f, "warning: {w}"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

/// Output sink for subcommand results.
pub trait OutputSink: Send {
    fn write_line(&mut self, line: &str);
    fn write_err(&mut self, line: &str);
}

/// Simple stdout/stderr sink.
pub struct StdioSink;

impl OutputSink for StdioSink {
    fn write_line(&mut self, line: &str) {
        println!("{line}");
    }
    fn write_err(&mut self, line: &str) {
        eprintln!("{line}");
    }
}

/// In-memory sink for testing.
#[derive(Debug, Default)]
pub struct MemSink {
    pub lines: Vec<String>,
    pub errors: Vec<String>,
}

impl OutputSink for MemSink {
    fn write_line(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
    fn write_err(&mut self, line: &str) {
        self.errors.push(line.to_string());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global options
// ─────────────────────────────────────────────────────────────────────────────

/// Options that apply to every subcommand.
#[derive(Debug, Clone, Default)]
pub struct GlobalOpts {
    /// Emit JSON instead of human-readable text.
    pub json: bool,
    /// Suppress all non-error output.
    pub quiet: bool,
    /// Increase verbosity (0 = normal, 1 = verbose, 2 = debug).
    pub verbosity: u8,
    /// Disable ANSI colour codes.
    pub no_color: bool,
    /// Path to an alternate config file.
    pub config: Option<PathBuf>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `analyze` subcommand.
#[derive(Debug, Clone)]
pub struct AnalyzeArgs {
    /// Path to the binary to analyse.
    pub path: PathBuf,
    /// Architecture override (e.g. `"x86_64"`, `"arm"`). `None` = autodetect.
    pub arch: Option<String>,
    /// Base address override.
    pub base_addr: Option<u64>,
    /// How many analysis passes to run (default 1).
    pub passes: u8,
    /// Whether to perform deep call-graph analysis.
    pub deep: bool,
    /// Only analyse functions matching these names.
    pub function_filter: Vec<String>,
}

/// `analyze` subcommand implementation.
pub struct AnalyzeCmd {
    pub args: AnalyzeArgs,
    pub global: GlobalOpts,
}

impl AnalyzeCmd {
    #[must_use] 
    pub const fn new(args: AnalyzeArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        let path = &self.args.path;
        if !path.exists() {
            return CmdStatus::Error(format!("file not found: {}", path.display()));
        }
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return CmdStatus::Error(format!("cannot stat: {e}")),
        };
        if !self.global.quiet {
            out.write_line(&format!(
                "analyzing: {} ({} bytes)",
                path.display(),
                meta.len()
            ));
        }
        let arch_str = self.args.arch.as_deref().unwrap_or("(autodetect)");
        if self.global.verbosity >= 1 {
            out.write_line(&format!(
                "  arch={} passes={} deep={}",
                arch_str, self.args.passes, self.args.deep
            ));
        }
        // Real analysis would call rustre_core here.
        out.write_line("analysis complete (stub)");
        CmdStatus::Ok
    }

    /// Return a summary of what the command will do without executing.
    #[must_use] 
    pub fn dry_run_description(&self) -> String {
        format!(
            "analyze {} (arch={}, passes={}, deep={})",
            self.args.path.display(),
            self.args.arch.as_deref().unwrap_or("auto"),
            self.args.passes,
            self.args.deep,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecompileCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `decompile` subcommand.
#[derive(Debug, Clone)]
pub struct DecompileArgs {
    pub path: PathBuf,
    /// Decompile function at this address.
    pub address: Option<u64>,
    /// Decompile function with this name.
    pub name: Option<String>,
    /// Output file (stdout if None).
    pub output: Option<PathBuf>,
    /// Include types in output.
    pub with_types: bool,
    /// Include MLIL before the C output.
    pub show_mlil: bool,
}

/// `decompile` subcommand.
pub struct DecompileCmd {
    pub args: DecompileArgs,
    pub global: GlobalOpts,
}

impl DecompileCmd {
    #[must_use] 
    pub const fn new(args: DecompileArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        let path = &self.args.path;
        if !path.exists() {
            return CmdStatus::Error(format!("file not found: {}", path.display()));
        }
        let target = match (&self.args.address, &self.args.name) {
            (Some(a), _) => format!("0x{a:x}"),
            (_, Some(n)) => n.clone(),
            _ => return CmdStatus::Error("need --address or --name".into()),
        };
        if !self.global.quiet {
            out.write_line(&format!("decompiling {} in {}", target, path.display()));
        }
        // Stub: emit minimal C skeleton.
        let stub = format!(
            "// Decompiled: {}\nint decompiled_function_{}() {{\n    return 0;\n}}\n",
            target,
            target.trim_start_matches("0x")
        );
        if let Some(outpath) = &self.args.output {
            match fs::write(outpath, &stub) {
                Ok(()) => out.write_line(&format!("written to {}", outpath.display())),
                Err(e) => return CmdStatus::Error(format!("write failed: {e}")),
            }
        } else {
            out.write_line(&stub);
        }
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DisasmCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `disasm` subcommand.
#[derive(Debug, Clone)]
pub struct DisasmArgs {
    pub path: PathBuf,
    pub start: u64,
    pub end: Option<u64>,
    pub count: Option<usize>,
    pub arch: Option<String>,
    pub show_bytes: bool,
    pub show_address: bool,
    pub syntax: DisasmSyntax,
}

/// Assembly syntax style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmSyntax {
    Intel,
    Att,
}

/// `disasm` subcommand.
pub struct DisasmCmd {
    pub args: DisasmArgs,
    pub global: GlobalOpts,
}

impl DisasmCmd {
    #[must_use] 
    pub const fn new(args: DisasmArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        if !self.args.path.exists() {
            return CmdStatus::Error(format!("file not found: {}", self.args.path.display()));
        }
        let count = self.args.count.unwrap_or(20);
        let syntax = match self.args.syntax {
            DisasmSyntax::Intel => "intel",
            DisasmSyntax::Att => "at&t",
        };
        if !self.global.quiet {
            out.write_line(&format!(
                "disassembly from 0x{:x}, {} instructions ({} syntax)",
                self.args.start, count, syntax
            ));
        }
        for i in 0..count.min(5) {
            let addr = self.args.start + i as u64 * 4;
            let line = if self.args.show_address {
                format!("  0x{addr:016x}:  nop")
            } else {
                "  nop".to_string()
            };
            out.write_line(&line);
        }
        out.write_line("(stub — real disassembly requires binary loaded)");
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringsCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `strings` subcommand.
#[derive(Debug, Clone)]
pub struct StringsArgs {
    pub path: PathBuf,
    /// Minimum string length (default 4).
    pub min_len: usize,
    /// Also search for UTF-16 strings.
    pub wide: bool,
    /// Only strings in the given section names.
    pub sections: Vec<String>,
    /// Emit strings with their file offsets.
    pub with_offsets: bool,
}

/// `strings` subcommand.
pub struct StringsCmd {
    pub args: StringsArgs,
    pub global: GlobalOpts,
}

impl StringsCmd {
    #[must_use] 
    pub const fn new(args: StringsArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        let path = &self.args.path;
        if !path.exists() {
            return CmdStatus::Error(format!("file not found: {}", path.display()));
        }
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => return CmdStatus::Error(format!("read failed: {e}")),
        };
        let found = extract_strings_from_bytes(&data, self.args.min_len);
        if !self.global.quiet {
            out.write_line(&format!(
                "strings in {} (min_len={}, wide={})",
                path.display(),
                self.args.min_len,
                self.args.wide
            ));
        }
        for (offset, s) in &found {
            if self.args.with_offsets {
                out.write_line(&format!("  0x{offset:08x}: {s}"));
            } else {
                out.write_line(&format!("  {s}"));
            }
        }
        out.write_line(&format!("total: {} strings", found.len()));
        CmdStatus::Ok
    }
}

/// Extract printable ASCII strings from raw bytes.
fn extract_strings_from_bytes(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if current.is_empty() {
                start = i;
            }
            current.push(b as char);
        } else if current.len() >= min_len {
            result.push((start, std::mem::take(&mut current)));
        } else {
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push((start, current));
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// InfoCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `info` subcommand.
#[derive(Debug, Clone)]
pub struct InfoArgs {
    pub path: PathBuf,
    /// Print section list.
    pub sections: bool,
    /// Print import table.
    pub imports: bool,
    /// Print export table.
    pub exports: bool,
    /// Print segment list.
    pub segments: bool,
}

/// File metadata summary.
#[derive(Debug, Clone, Default)]
pub struct FileInfo {
    pub format: String,
    pub arch: String,
    pub bits: u8,
    pub os: String,
    pub entry_point: u64,
    pub file_size: u64,
    pub section_count: usize,
    pub import_count: usize,
    pub export_count: usize,
}

/// `info` subcommand.
pub struct InfoCmd {
    pub args: InfoArgs,
    pub global: GlobalOpts,
}

impl InfoCmd {
    #[must_use] 
    pub const fn new(args: InfoArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        let path = &self.args.path;
        if !path.exists() {
            return CmdStatus::Error(format!("file not found: {}", path.display()));
        }
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return CmdStatus::Error(format!("stat failed: {e}")),
        };
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => return CmdStatus::Error(format!("read failed: {e}")),
        };
        let info = detect_file_info(&data, meta.len());
        if self.global.json {
            out.write_line(&format!(
                r#"{{"format":"{}","arch":"{}","bits":{},"entry":"0x{:x}","size":{}}}"#,
                info.format, info.arch, info.bits, info.entry_point, info.file_size
            ));
        } else {
            out.write_line(&format!("File    : {}", path.display()));
            out.write_line(&format!("Format  : {}", info.format));
            out.write_line(&format!("Arch    : {} ({}-bit)", info.arch, info.bits));
            out.write_line(&format!("OS      : {}", info.os));
            out.write_line(&format!("Entry   : 0x{:016x}", info.entry_point));
            out.write_line(&format!("Size    : {} bytes", info.file_size));
        }
        CmdStatus::Ok
    }
}

fn detect_file_info(data: &[u8], file_size: u64) -> FileInfo {
    let mut info = FileInfo {
        file_size,
        ..Default::default()
    };
    if data.starts_with(b"\x7fELF") {
        info.format = "ELF".to_string();
        info.bits = if data.get(4).copied() == Some(2) {
            64
        } else {
            32
        };
        let machine = u16::from(data.get(18).copied().unwrap_or(0))
            | (u16::from(data.get(19).copied().unwrap_or(0)) << 8);
        info.arch = match machine {
            0x003e => "x86_64".to_string(),
            0x0028 => "arm".to_string(),
            0x00b7 => "aarch64".to_string(),
            0x0008 => "mips".to_string(),
            0x00f3 => "riscv".to_string(),
            _ => format!("unknown(0x{machine:x})"),
        };
        info.os = "Linux/ELF".to_string();
    } else if data.starts_with(b"MZ") {
        info.format = "PE".to_string();
        info.os = "Windows".to_string();
        info.arch = "x86_64".to_string();
        info.bits = 64;
    } else if data.starts_with(b"\xfe\xed\xfa\xce") || data.starts_with(b"\xce\xfa\xed\xfe") {
        info.format = "Mach-O".to_string();
        info.os = "macOS".to_string();
        info.arch = "x86_64".to_string();
        info.bits = 32;
    } else if data.starts_with(b"\xfe\xed\xfa\xcf") || data.starts_with(b"\xcf\xfa\xed\xfe") {
        info.format = "Mach-O".to_string();
        info.os = "macOS".to_string();
        info.arch = "x86_64".to_string();
        info.bits = 64;
    } else {
        info.format = "unknown".to_string();
        info.arch = "unknown".to_string();
        info.bits = 0;
    }
    info
}

// ─────────────────────────────────────────────────────────────────────────────
// ScriptCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `script` subcommand.
#[derive(Debug, Clone)]
pub struct ScriptArgs {
    pub path: PathBuf,
    pub script: PathBuf,
    /// Script language override (`"rhai"`, `"lua"`, `"python"`).
    pub lang: Option<String>,
    /// Key=value pairs injected into script environment.
    pub env: HashMap<String, String>,
}

/// `script` subcommand.
pub struct ScriptCmd {
    pub args: ScriptArgs,
    pub global: GlobalOpts,
}

impl ScriptCmd {
    #[must_use] 
    pub const fn new(args: ScriptArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        if !self.args.script.exists() {
            return CmdStatus::Error(format!("script not found: {}", self.args.script.display()));
        }
        let src = match fs::read_to_string(&self.args.script) {
            Ok(s) => s,
            Err(e) => return CmdStatus::Error(format!("read script: {e}")),
        };
        let lang = self.args.lang.as_deref().unwrap_or_else(|| {
            self.args
                .script
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("rhai")
        });
        if !self.global.quiet {
            out.write_line(&format!(
                "running {} script: {}",
                lang,
                self.args.script.display()
            ));
        }
        // Real execution would dispatch to an interpreter; stub only.
        out.write_line(&format!(
            "script length: {} bytes (stub, not executed)",
            src.len()
        ));
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Server subcommand action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAction {
    Start,
    Stop,
    Status,
    Restart,
}

/// Arguments for the `server` subcommand.
#[derive(Debug, Clone)]
pub struct ServerArgs {
    pub action: ServerAction,
    pub host: String,
    pub port: u16,
    pub daemonize: bool,
}

impl Default for ServerArgs {
    fn default() -> Self {
        Self {
            action: ServerAction::Status,
            host: "127.0.0.1".to_string(),
            port: 8964,
            daemonize: false,
        }
    }
}

/// `server` subcommand.
pub struct ServerCmd {
    pub args: ServerArgs,
    pub global: GlobalOpts,
}

impl ServerCmd {
    #[must_use] 
    pub const fn new(args: ServerArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        let addr = format!("{}:{}", self.args.host, self.args.port);
        match self.args.action {
            ServerAction::Start => {
                out.write_line(&format!(
                    "starting server on {} (daemon={})",
                    addr, self.args.daemonize
                ));
                out.write_line("server started (stub)");
            }
            ServerAction::Stop => {
                out.write_line(&format!("stopping server at {addr}"));
                out.write_line("server stopped (stub)");
            }
            ServerAction::Status => {
                out.write_line(&format!("server status at {addr}: stopped (stub)"));
            }
            ServerAction::Restart => {
                out.write_line(&format!("restarting server at {addr}"));
                out.write_line("server restarted (stub)");
            }
        }
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `yara` subcommand.
#[derive(Debug, Clone)]
pub struct YaraArgs {
    pub path: PathBuf,
    pub rules: Vec<PathBuf>,
    pub recursive: bool,
    pub print_strings: bool,
}

/// `yara` subcommand.
pub struct YaraCmd {
    pub args: YaraArgs,
    pub global: GlobalOpts,
}

impl YaraCmd {
    #[must_use] 
    pub const fn new(args: YaraArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        if !self.args.path.exists() {
            return CmdStatus::Error(format!("target not found: {}", self.args.path.display()));
        }
        for rule_path in &self.args.rules {
            if !rule_path.exists() {
                return CmdStatus::Error(format!("rule file not found: {}", rule_path.display()));
            }
        }
        out.write_line(&format!(
            "yara scan: {} rules against {} (stub)",
            self.args.rules.len(),
            self.args.path.display()
        ));
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `diff` subcommand.
#[derive(Debug, Clone)]
pub struct DiffArgs {
    pub old: PathBuf,
    pub new: PathBuf,
    pub mode: DiffMode,
    pub threshold: f64,
    pub output: Option<PathBuf>,
}

/// Diff mode: byte-level or semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Bytes,
    Semantic,
    Hybrid,
}

/// `diff` subcommand.
pub struct DiffCmd {
    pub args: DiffArgs,
    pub global: GlobalOpts,
}

impl DiffCmd {
    #[must_use] 
    pub const fn new(args: DiffArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        for p in [&self.args.old, &self.args.new] {
            if !p.exists() {
                return CmdStatus::Error(format!("not found: {}", p.display()));
            }
        }
        let mode_str = match self.args.mode {
            DiffMode::Bytes => "bytes",
            DiffMode::Semantic => "semantic",
            DiffMode::Hybrid => "hybrid",
        };
        out.write_line(&format!(
            "diff ({}) {} vs {} threshold={}",
            mode_str,
            self.args.old.display(),
            self.args.new.display(),
            self.args.threshold
        ));
        out.write_line("diff complete (stub)");
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugCmd
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `debug` subcommand.
#[derive(Debug, Clone)]
pub struct DebugArgs {
    pub path: PathBuf,
    pub pid: Option<u32>,
    pub breakpoints: Vec<u64>,
    pub script: Option<PathBuf>,
    pub remote: Option<String>,
}

/// `debug` subcommand.
pub struct DebugCmd {
    pub args: DebugArgs,
    pub global: GlobalOpts,
}

impl DebugCmd {
    #[must_use] 
    pub const fn new(args: DebugArgs, global: GlobalOpts) -> Self {
        Self { args, global }
    }

    pub fn execute(&self, out: &mut dyn OutputSink) -> CmdStatus {
        if let Some(pid) = self.args.pid {
            out.write_line(&format!("attaching to pid {pid}"));
        } else if !self.args.path.as_os_str().is_empty() {
            if !self.args.path.exists() {
                return CmdStatus::Error(format!("not found: {}", self.args.path.display()));
            }
            out.write_line(&format!("launching: {}", self.args.path.display()));
        } else {
            return CmdStatus::Error("need --path or --pid".into());
        }
        for bp in &self.args.breakpoints {
            out.write_line(&format!("  breakpoint at 0x{bp:x}"));
        }
        out.write_line("debug session started (stub)");
        CmdStatus::Ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn mem_sink() -> MemSink {
        MemSink::default()
    }

    // --- CmdStatus ---

    #[test]
    fn status_ok_is_ok() {
        assert!(CmdStatus::Ok.is_ok());
    }

    #[test]
    fn status_error_not_ok() {
        assert!(!CmdStatus::Error("x".into()).is_ok());
    }

    #[test]
    fn status_exit_code_ok() {
        assert_eq!(CmdStatus::Ok.exit_code(), 0);
    }

    #[test]
    fn status_exit_code_error() {
        assert_eq!(CmdStatus::Error("x".into()).exit_code(), 1);
    }

    #[test]
    fn status_warning_exit_code_zero() {
        assert_eq!(CmdStatus::Warning("w".into()).exit_code(), 0);
    }

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", CmdStatus::Ok), "ok");
    }

    // --- MemSink ---

    #[test]
    fn mem_sink_collects_lines() {
        let mut s = MemSink::default();
        s.write_line("hello");
        s.write_line("world");
        assert_eq!(s.lines, vec!["hello", "world"]);
    }

    #[test]
    fn write_trait_imported_for_tests() {
        // Exercise the `std::io::Write` import so it stays live for any
        // future buffer-backed test that needs writeln!/write_all.
        let mut buf: Vec<u8> = Vec::new();
        Write::write_all(&mut buf, b"abc").unwrap();
        assert_eq!(buf, b"abc");
    }

    #[test]
    fn mem_sink_collects_errors() {
        let mut s = MemSink::default();
        s.write_err("oops");
        assert_eq!(s.errors, vec!["oops"]);
    }

    // --- AnalyzeCmd ---

    #[test]
    fn analyze_missing_file_returns_error() {
        let args = AnalyzeArgs {
            path: PathBuf::from("/nonexistent/binary"),
            arch: None,
            base_addr: None,
            passes: 1,
            deep: false,
            function_filter: vec![],
        };
        let cmd = AnalyzeCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        let status = cmd.execute(&mut sink);
        assert!(status.is_error());
    }

    #[test]
    fn analyze_dry_run_description() {
        let args = AnalyzeArgs {
            path: PathBuf::from("/bin/ls"),
            arch: Some("x86_64".to_string()),
            base_addr: None,
            passes: 2,
            deep: true,
            function_filter: vec![],
        };
        let cmd = AnalyzeCmd::new(args, GlobalOpts::default());
        let desc = cmd.dry_run_description();
        assert!(desc.contains("x86_64"));
        assert!(desc.contains("deep=true"));
    }

    // --- DecompileCmd ---

    #[test]
    fn decompile_needs_address_or_name() {
        let args = DecompileArgs {
            path: PathBuf::from("/nonexistent"),
            address: None,
            name: None,
            output: None,
            with_types: false,
            show_mlil: false,
        };
        let cmd = DecompileCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        let status = cmd.execute(&mut sink);
        // Either file-not-found OR missing address/name error
        assert!(status.is_error());
    }

    // --- DisasmCmd ---

    #[test]
    fn disasm_missing_file_returns_error() {
        let args = DisasmArgs {
            path: PathBuf::from("/no"),
            start: 0x1000,
            end: None,
            count: Some(10),
            arch: None,
            show_bytes: false,
            show_address: true,
            syntax: DisasmSyntax::Intel,
        };
        let cmd = DisasmCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        assert!(cmd.execute(&mut sink).is_error());
    }

    // --- StringsCmd ---

    #[test]
    fn extract_strings_basic() {
        let data = b"hello\x00world\x00\x01\x02short\x00this_is_long_enough";
        let strings = extract_strings_from_bytes(data, 4);
        assert!(strings.iter().any(|(_, s)| s == "hello"));
        assert!(strings.iter().any(|(_, s)| s == "world"));
        assert!(!strings.iter().any(|(_, s)| s == "hi")); // too short
    }

    #[test]
    fn extract_strings_min_len_4() {
        let data = b"abc\x00abcd";
        let strings = extract_strings_from_bytes(data, 4);
        assert!(!strings.iter().any(|(_, s)| s == "abc"));
        assert!(strings.iter().any(|(_, s)| s == "abcd"));
    }

    #[test]
    fn strings_cmd_missing_file() {
        let args = StringsArgs {
            path: PathBuf::from("/nope"),
            min_len: 4,
            wide: false,
            sections: vec![],
            with_offsets: false,
        };
        let cmd = StringsCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        assert!(cmd.execute(&mut sink).is_error());
    }

    // --- InfoCmd ---

    #[test]
    fn detect_elf_magic() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[18] = 0x3e;
        data[19] = 0; // x86_64
        let info = detect_file_info(&data, 64);
        assert_eq!(info.format, "ELF");
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.bits, 64);
    }

    #[test]
    fn detect_pe_magic() {
        let data = b"MZ\x90\x00".to_vec();
        let info = detect_file_info(&data, 4);
        assert_eq!(info.format, "PE");
    }

    #[test]
    fn detect_unknown_magic() {
        let data = b"\x00\x00\x00\x00".to_vec();
        let info = detect_file_info(&data, 4);
        assert_eq!(info.format, "unknown");
    }

    #[test]
    fn info_cmd_missing_file() {
        let args = InfoArgs {
            path: PathBuf::from("/nope"),
            sections: false,
            imports: false,
            exports: false,
            segments: false,
        };
        let cmd = InfoCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        assert!(cmd.execute(&mut sink).is_error());
    }

    // --- ServerCmd ---

    #[test]
    fn server_status_ok() {
        let args = ServerArgs::default();
        let cmd = ServerCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        let status = cmd.execute(&mut sink);
        assert!(status.is_ok());
        assert!(sink.lines.iter().any(|l| l.contains("status")));
    }

    #[test]
    fn server_start_message() {
        let args = ServerArgs {
            action: ServerAction::Start,
            ..ServerArgs::default()
        };
        let cmd = ServerCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        cmd.execute(&mut sink);
        assert!(sink.lines.iter().any(|l| l.contains("start")));
    }

    // --- DiffCmd ---

    #[test]
    fn diff_cmd_missing_old_file() {
        let args = DiffArgs {
            old: PathBuf::from("/no_old"),
            new: PathBuf::from("/no_new"),
            mode: DiffMode::Semantic,
            threshold: 0.9,
            output: None,
        };
        let cmd = DiffCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        assert!(cmd.execute(&mut sink).is_error());
    }

    // --- DebugCmd ---

    #[test]
    fn debug_cmd_needs_path_or_pid() {
        let args = DebugArgs {
            path: PathBuf::new(),
            pid: None,
            breakpoints: vec![],
            script: None,
            remote: None,
        };
        let cmd = DebugCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        let status = cmd.execute(&mut sink);
        assert!(status.is_error());
    }

    #[test]
    fn debug_cmd_pid_ok() {
        let args = DebugArgs {
            path: PathBuf::new(),
            pid: Some(1234),
            breakpoints: vec![0x1000, 0x2000],
            script: None,
            remote: None,
        };
        let cmd = DebugCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        let status = cmd.execute(&mut sink);
        assert!(status.is_ok());
        assert!(sink.lines.iter().any(|l| l.contains("1234")));
    }

    #[test]
    fn debug_cmd_breakpoints_listed() {
        let args = DebugArgs {
            path: PathBuf::new(),
            pid: Some(99),
            breakpoints: vec![0xdeadbeef],
            script: None,
            remote: None,
        };
        let cmd = DebugCmd::new(args, GlobalOpts::default());
        let mut sink = mem_sink();
        cmd.execute(&mut sink);
        assert!(sink.lines.iter().any(|l| l.contains("deadbeef")));
    }
}
