//! Full clap 4 derive-based CLI definition for `RustRE`.
//!
//! Defines the top-level `RustreArgs` struct and all subcommands:
//! - `analyze`    — full static analysis of a binary
//! - `disasm`     — disassemble a function or address range
//! - `decompile`  — decompile a single function
//! - `strings`    — extract strings
//! - `imports`    — list imported symbols
//! - `exports`    — list exported symbols
//! - `entropy`    — compute section entropy
//! - `diff`       — diff two binaries
//! - `yara`       — run YARA rules
//! - `sandbox`    — submit to sandbox
//! - `debug`      — launch interactive debugger
//! - `script`     — execute a Lua/Python/Rhai script

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Output format
// ──────────────────────────────────────────────────────────────────────────────

/// Output format selection (shared by most subcommands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    JsonPretty,
    Csv,
    Html,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::JsonPretty => "json-pretty",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Sarif => "sarif",
        };
        f.write_str(s)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Top-level CLI
// ──────────────────────────────────────────────────────────────────────────────

/// `RustRE` — modular reverse-engineering platform.
#[derive(Debug, Parser)]
#[command(
    name = "rustre",
    version = env!("CARGO_PKG_VERSION"),
    author,
    about = "Modular reverse-engineering platform",
    long_about = None,
    propagate_version = true,
)]
pub struct RustreArgs {
    /// Path to the configuration file.
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,

    /// Daemon socket / URL to connect to.
    #[arg(long, global = true, default_value = "unix:///tmp/rustre.sock")]
    pub daemon: String,

    /// Suppress all non-essential output.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Increase verbosity (repeat for more: -v, -vv, -vvv).
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format.
    #[arg(long, short = 'f', global = true, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(long, short = 'o', global = true)]
    pub output: Option<PathBuf>,

    /// Disable ANSI colors.
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: RustreCommand,
}

// ──────────────────────────────────────────────────────────────────────────────
// Subcommand enum
// ──────────────────────────────────────────────────────────────────────────────

/// All top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum RustreCommand {
    /// Run full static analysis on a binary.
    Analyze(AnalyzeArgs),
    /// Disassemble a function or address range.
    Disasm(DisasmArgs),
    /// Decompile a single function to pseudo-C.
    Decompile(DecompileArgs),
    /// Extract printable strings from a binary.
    Strings(StringsArgs),
    /// List imported symbols.
    Imports(ImportsArgs),
    /// List exported symbols.
    Exports(ExportsArgs),
    /// Compute Shannon entropy per section.
    Entropy(EntropyArgs),
    /// Diff two binaries structurally.
    Diff(DiffArgs),
    /// Run YARA rules against a binary.
    Yara(YaraArgs),
    /// Submit a binary to the sandbox for dynamic analysis.
    Sandbox(SandboxArgs),
    /// Launch interactive debugger session.
    Debug(DebugArgs),
    /// Execute a Lua, Python, or Rhai analysis script.
    Script(ScriptArgs),
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-subcommand argument structs
// ──────────────────────────────────────────────────────────────────────────────

/// Arguments for `rustre analyze`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct AnalyzeArgs {
    /// Path to the binary to analyze.
    pub binary: PathBuf,

    /// Analysis profile: quick | full | deep.
    #[arg(long, short = 'p', default_value = "full")]
    pub profile: AnalysisProfile,

    /// Architecture hint (auto-detected if omitted).
    #[arg(long, short = 'a')]
    pub arch: Option<String>,

    /// Base address override (hex or decimal).
    #[arg(long)]
    pub base_addr: Option<String>,

    /// Open an existing project file instead of creating a new one.
    #[arg(long, short = 'P')]
    pub project: Option<PathBuf>,

    /// Save analysis project to this path.
    #[arg(long, short = 's')]
    pub save: Option<PathBuf>,

    /// Number of analysis threads.
    #[arg(long, short = 'j', default_value = "4")]
    pub jobs: usize,

    /// Apply YARA rules from this file after analysis.
    #[arg(long, short = 'y')]
    pub yara: Option<PathBuf>,

    /// Skip function discovery (analyse only the entry point).
    #[arg(long)]
    pub no_functions: bool,

    /// Include cross-reference analysis.
    #[arg(long)]
    pub xrefs: bool,
}

/// Analysis depth profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
pub enum AnalysisProfile {
    /// Fast scan: entry point + headers + strings.
    Quick,
    #[default]
    /// Standard analysis: full function discovery + imports/exports.
    Full,
    /// Deep: full + type recovery + xrefs + decompilation.
    Deep,
}

/// Arguments for `rustre disasm`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct DisasmArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Start address (hex, e.g. `0x1000`).
    #[arg(long, short = 'A')]
    pub addr: Option<String>,

    /// Function name to disassemble.
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Number of instructions to emit (default: all in function).
    #[arg(long, short = 'N')]
    pub count: Option<usize>,

    /// Show bytes alongside mnemonics.
    #[arg(long)]
    pub bytes: bool,

    /// Show branch targets as labels.
    #[arg(long)]
    pub labels: bool,

    /// Syntax flavour: intel | att.
    #[arg(long, value_enum, default_value = "intel")]
    pub syntax: AsmSyntax,
}

/// Assembly syntax flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
pub enum AsmSyntax {
    #[default]
    Intel,
    Att,
}

/// Arguments for `rustre decompile`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct DecompileArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Address of the function to decompile (hex).
    #[arg(long, short = 'A')]
    pub addr: Option<String>,

    /// Name of the function to decompile.
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Decompiler backend: pcode | ghidra | retdec.
    #[arg(long, default_value = "pcode")]
    pub backend: String,

    /// Decompile all functions (may be slow).
    #[arg(long)]
    pub all: bool,
}

/// Arguments for `rustre strings`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct StringsArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Minimum string length (default 4).
    #[arg(long, short = 'm', default_value = "4")]
    pub min_len: usize,

    /// Filter strings matching this regex pattern.
    #[arg(long, short = 'r')]
    pub regex: Option<String>,

    /// Include wide (UTF-16) strings.
    #[arg(long)]
    pub wide: bool,

    /// Limit output to this many strings.
    #[arg(long, short = 'l')]
    pub limit: Option<usize>,

    /// Show virtual address of each string.
    #[arg(long)]
    pub addrs: bool,

    /// Show section name for each string.
    #[arg(long)]
    pub sections: bool,
}

/// Arguments for `rustre imports`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct ImportsArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Filter by library name (substring).
    #[arg(long, short = 'L')]
    pub library: Option<String>,

    /// Filter by symbol name regex.
    #[arg(long, short = 'r')]
    pub regex: Option<String>,

    /// Include ordinal imports (PE only).
    #[arg(long)]
    pub ordinals: bool,
}

/// Arguments for `rustre exports`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct ExportsArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Filter by symbol name regex.
    #[arg(long, short = 'r')]
    pub regex: Option<String>,

    /// Show addresses alongside names.
    #[arg(long)]
    pub addrs: bool,
}

/// Arguments for `rustre entropy`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct EntropyArgs {
    /// Path to the binary.
    pub binary: PathBuf,

    /// Block size for entropy computation in bytes (default: per-section).
    #[arg(long)]
    pub block_size: Option<usize>,

    /// Warn when a section exceeds this entropy (default: 7.2).
    #[arg(long, default_value = "7.2")]
    pub warn_threshold: f64,
}

/// Arguments for `rustre diff`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct DiffArgs {
    /// First binary.
    pub binary_a: PathBuf,
    /// Second binary.
    pub binary_b: PathBuf,

    /// Diff algorithm: bindiff | diaphora | simple.
    #[arg(long, default_value = "simple")]
    pub algorithm: String,

    /// Minimum similarity score to include in output (0.0–1.0).
    #[arg(long, default_value = "0.5")]
    pub min_similarity: f64,

    /// Include unmatched functions.
    #[arg(long)]
    pub unmatched: bool,
}

/// Arguments for `rustre yara`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct YaraArgs {
    /// Path to the binary to scan.
    pub binary: PathBuf,

    /// YARA rules file or directory.
    #[arg(required = true)]
    pub rules: Vec<PathBuf>,

    /// Scan entire file content (not just mapped sections).
    #[arg(long)]
    pub full_file: bool,

    /// Stop after first match.
    #[arg(long)]
    pub first_match: bool,

    /// Timeout for YARA scanning in seconds.
    #[arg(long, default_value = "60")]
    pub timeout: u32,
}

/// Arguments for `rustre sandbox`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct SandboxArgs {
    /// Path to the binary to execute in the sandbox.
    pub binary: PathBuf,

    /// Sandbox backend: unicorn | qiling | native.
    #[arg(long, default_value = "unicorn")]
    pub backend: String,

    /// Maximum execution time in seconds.
    #[arg(long, default_value = "60")]
    pub timeout: u32,

    /// Enable network access inside the sandbox.
    #[arg(long)]
    pub network: bool,

    /// Arguments to pass to the binary.
    #[arg(last = true)]
    pub args: Vec<String>,

    /// Wait for completion and print full report.
    #[arg(long)]
    pub wait: bool,
}

/// Arguments for `rustre debug`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct DebugArgs {
    /// Binary to debug (pass PID with `--pid` to attach instead).
    pub binary: Option<PathBuf>,

    /// PID to attach to.
    #[arg(long, short = 'p', conflicts_with = "binary")]
    pub pid: Option<u32>,

    /// Debugger backend: gdb | lldb | windbg | frida.
    #[arg(long, default_value = "gdb")]
    pub backend: String,

    /// Remote GDB stub address (e.g. `localhost:1234`).
    #[arg(long)]
    pub remote: Option<String>,

    /// Execute these debugger commands on attach.
    #[arg(long, short = 'x')]
    pub commands: Vec<String>,
}

/// Arguments for `rustre script`.
#[derive(Debug, Args, Serialize, Deserialize)]
pub struct ScriptArgs {
    /// Path to the binary to operate on.
    pub binary: PathBuf,

    /// Script file to execute (.lua, .py, or .rhai).
    pub script: PathBuf,

    /// Extra arguments forwarded to the script as `argv`.
    #[arg(last = true)]
    pub script_args: Vec<String>,

    /// Script engine override: lua | python | rhai (auto-detected from extension).
    #[arg(long, short = 'e')]
    pub engine: Option<ScriptEngine>,
}

/// Scripting engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ScriptEngine {
    Lua,
    Python,
    Rhai,
}

// ──────────────────────────────────────────────────────────────────────────────
// Resolved CLI context (passed to command handlers)
// ──────────────────────────────────────────────────────────────────────────────

/// Resolved execution context derived from the parsed CLI arguments.
#[derive(Debug)]
pub struct CliContext {
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub quiet: bool,
    pub verbose: u8,
    pub no_color: bool,
    pub daemon_addr: String,
    pub config_path: Option<PathBuf>,
}

impl CliContext {
    /// Build from a parsed `RustreArgs`.
    #[must_use]
    pub fn from_args(args: &RustreArgs) -> Self {
        Self {
            format: args.format,
            output: args.output.clone(),
            quiet: args.quiet,
            verbose: args.verbose,
            no_color: args.no_color,
            daemon_addr: args.daemon.clone(),
            config_path: args.config.clone(),
        }
    }

    /// Whether verbose output at level `n` is enabled.
    #[must_use]
    pub const fn is_verbose(&self, level: u8) -> bool {
        self.verbose >= level
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Address parsing utilities
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a hex or decimal address string.
///
/// # Errors
/// Returns a `String` describing the parse error.
pub fn parse_addr(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex address '{s}': {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid decimal address '{s}': {e}"))
    }
}

/// Resolve the optional address from `DisasmArgs`, preferring `--addr` over `--name`.
///
/// # Errors
/// Returns a `String` if `--addr` is present but not parseable.
pub fn resolve_disasm_addr(args: &DisasmArgs) -> Result<Option<u64>, String> {
    match &args.addr {
        Some(s) => parse_addr(s).map(Some),
        None => Ok(None),
    }
}

/// Resolve the optional address from `DecompileArgs`.
///
/// # Errors
/// Returns a `String` if `--addr` is present but not parseable.
pub fn resolve_decompile_addr(args: &DecompileArgs) -> Result<Option<u64>, String> {
    match &args.addr {
        Some(s) => parse_addr(s).map(Some),
        None => Ok(None),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatch helper
// ──────────────────────────────────────────────────────────────────────────────

/// Dispatch result type for command handlers.
pub type CmdResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Command dispatch trait — implemented by each command handler.
pub trait CommandHandler {
    fn run(&self, ctx: &CliContext) -> CmdResult;
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> RustreArgs {
        RustreArgs::parse_from(args)
    }

    #[test]
    fn analyze_basic() {
        let a = parse(&["rustre", "analyze", "/tmp/a.out"]);
        if let RustreCommand::Analyze(ref args) = a.command {
            assert_eq!(args.binary, PathBuf::from("/tmp/a.out"));
        } else {
            panic!("expected Analyze");
        }
    }

    #[test]
    fn analyze_profile_quick() {
        let a = parse(&["rustre", "analyze", "/tmp/a.out", "--profile", "quick"]);
        if let RustreCommand::Analyze(ref args) = a.command {
            assert_eq!(args.profile, AnalysisProfile::Quick);
        } else {
            panic!();
        }
    }

    #[test]
    fn analyze_jobs_flag() {
        let a = parse(&["rustre", "analyze", "/tmp/a.out", "--jobs", "8"]);
        if let RustreCommand::Analyze(ref args) = a.command {
            assert_eq!(args.jobs, 8);
        } else {
            panic!();
        }
    }

    #[test]
    fn disasm_addr() {
        let a = parse(&["rustre", "disasm", "/tmp/a.out", "--addr", "0x1000"]);
        if let RustreCommand::Disasm(ref args) = a.command {
            assert_eq!(resolve_disasm_addr(args).unwrap(), Some(0x1000));
        } else {
            panic!();
        }
    }

    #[test]
    fn disasm_syntax_att() {
        let a = parse(&["rustre", "disasm", "/tmp/b.elf", "--syntax", "att"]);
        if let RustreCommand::Disasm(ref args) = a.command {
            assert_eq!(args.syntax, AsmSyntax::Att);
        } else {
            panic!();
        }
    }

    #[test]
    fn decompile_name() {
        let a = parse(&["rustre", "decompile", "/tmp/a.out", "--name", "main"]);
        if let RustreCommand::Decompile(ref args) = a.command {
            assert_eq!(args.name.as_deref(), Some("main"));
        } else {
            panic!();
        }
    }

    #[test]
    fn strings_min_len() {
        let a = parse(&["rustre", "strings", "/tmp/a.out", "--min-len", "8"]);
        if let RustreCommand::Strings(ref args) = a.command {
            assert_eq!(args.min_len, 8);
        } else {
            panic!();
        }
    }

    #[test]
    fn strings_wide_flag() {
        let a = parse(&["rustre", "strings", "/tmp/a.out", "--wide"]);
        if let RustreCommand::Strings(ref args) = a.command {
            assert!(args.wide);
        } else {
            panic!();
        }
    }

    #[test]
    fn imports_library_filter() {
        let a = parse(&["rustre", "imports", "/tmp/a.dll", "--library", "kernel32"]);
        if let RustreCommand::Imports(ref args) = a.command {
            assert_eq!(args.library.as_deref(), Some("kernel32"));
        } else {
            panic!();
        }
    }

    #[test]
    fn exports_addr_flag() {
        let a = parse(&["rustre", "exports", "/tmp/a.so", "--addrs"]);
        if let RustreCommand::Exports(ref args) = a.command {
            assert!(args.addrs);
        } else {
            panic!();
        }
    }

    #[test]
    fn entropy_warn_threshold() {
        let a = parse(&["rustre", "entropy", "/tmp/a.out", "--warn-threshold", "6.5"]);
        if let RustreCommand::Entropy(ref args) = a.command {
            assert!((args.warn_threshold - 6.5).abs() < 1e-9);
        } else {
            panic!();
        }
    }

    #[test]
    fn diff_min_similarity() {
        let a = parse(&["rustre", "diff", "/tmp/a.out", "/tmp/b.out", "--min-similarity", "0.8"]);
        if let RustreCommand::Diff(ref args) = a.command {
            assert!((args.min_similarity - 0.8).abs() < 1e-9);
        } else {
            panic!();
        }
    }

    #[test]
    fn yara_rules_required() {
        let a = parse(&["rustre", "yara", "/tmp/a.out", "rules.yar"]);
        if let RustreCommand::Yara(ref args) = a.command {
            assert_eq!(args.rules[0], PathBuf::from("rules.yar"));
        } else {
            panic!();
        }
    }

    #[test]
    fn sandbox_timeout() {
        let a = parse(&["rustre", "sandbox", "/tmp/a.out", "--timeout", "120"]);
        if let RustreCommand::Sandbox(ref args) = a.command {
            assert_eq!(args.timeout, 120);
        } else {
            panic!();
        }
    }

    #[test]
    fn sandbox_network_flag() {
        let a = parse(&["rustre", "sandbox", "/tmp/a.out", "--network"]);
        if let RustreCommand::Sandbox(ref args) = a.command {
            assert!(args.network);
        } else {
            panic!();
        }
    }

    #[test]
    fn debug_pid() {
        let a = parse(&["rustre", "debug", "--pid", "1234"]);
        if let RustreCommand::Debug(ref args) = a.command {
            assert_eq!(args.pid, Some(1234));
        } else {
            panic!();
        }
    }

    #[test]
    fn debug_backend_frida() {
        let a = parse(&["rustre", "debug", "--backend", "frida", "--pid", "42"]);
        if let RustreCommand::Debug(ref args) = a.command {
            assert_eq!(args.backend, "frida");
        } else {
            panic!();
        }
    }

    #[test]
    fn script_engine_python() {
        let a = parse(&["rustre", "script", "/tmp/a.out", "script.py", "--engine", "python"]);
        if let RustreCommand::Script(ref args) = a.command {
            assert_eq!(args.engine, Some(ScriptEngine::Python));
        } else {
            panic!();
        }
    }

    #[test]
    fn global_format_json() {
        let a = parse(&["rustre", "--format", "json", "strings", "/tmp/a.out"]);
        assert_eq!(a.format, OutputFormat::Json);
    }

    #[test]
    fn global_quiet_flag() {
        let a = parse(&["rustre", "--quiet", "strings", "/tmp/a.out"]);
        assert!(a.quiet);
    }

    #[test]
    fn global_verbose_count() {
        let a = parse(&["rustre", "-vvv", "strings", "/tmp/a.out"]);
        assert_eq!(a.verbose, 3);
    }

    #[test]
    fn parse_addr_hex() {
        assert_eq!(parse_addr("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_addr("0X1A2B").unwrap(), 0x1a2b);
    }

    #[test]
    fn parse_addr_decimal() {
        assert_eq!(parse_addr("4096").unwrap(), 4096);
    }

    #[test]
    fn parse_addr_invalid() {
        assert!(parse_addr("not-an-addr").is_err());
    }

    #[test]
    fn cli_context_verbose_levels() {
        let args = parse(&["rustre", "-vv", "strings", "/tmp/a.out"]);
        let ctx = CliContext::from_args(&args);
        assert!(ctx.is_verbose(1));
        assert!(ctx.is_verbose(2));
        assert!(!ctx.is_verbose(3));
    }

    #[test]
    fn output_format_display() {
        assert_eq!(OutputFormat::Table.to_string(), "table");
        assert_eq!(OutputFormat::JsonPretty.to_string(), "json-pretty");
        assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
    }
}
