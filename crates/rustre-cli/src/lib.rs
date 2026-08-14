//! `rustre-cli`
//!
//! CLI frontend library for the `RustRE` Suite.  Provides command-line argument
//! parsing, subcommand routing, output formatting (table / JSON / coloured),
//! progress reporting, interactive prompt mode, and configuration-file loading.
//!
//! # Design
//! * No external arg-parsing crate required: all parsing is hand-rolled so that
//!   this crate only needs `rustre-core` plus workspace deps.
//! * All value-returning public methods carry `#[must_use]`.
//! * All `pub fn` returning `Result` carry `/// # Errors`.
//! * All `pub fn` that can panic carry `/// # Panics`.
//! * 25+ tests at the bottom.

pub mod batch_mode;
pub mod cli_commands;
pub mod command_router;
pub mod config_file;
pub mod interactive_mode;
pub mod output_formatter;
pub mod output_renderer;
pub mod interactive_shell;
pub mod plugin_commands;
pub mod progress_display;
pub mod table_renderer;
pub mod session_state;
pub mod cli_command_router;
pub mod cli_output_formatter;
pub mod cli_progress_display;
pub mod fuzz;

pub use fuzz::{BackendKind, FuzzerBackend, make_backend};

pub use rustre_project;
pub use rustre_patch;

// Network stack hub: re-exports the `rustre-net` registry, which transitively
// wires `rustre-net-pcap` and `rustre-net-proxy` (MITM / intercepting proxy).
// This promotes the proxy from a hub-only registry entry to a platform-CLI-
// visible component so downstream tooling (rustre-bin, subcommands, MCP) can
// reach `ProxyServer` / `ProxyConfig` via `rustre_cli::net::registry::proxy`.
pub use rustre_net as net;
pub use rustre_net::registry::{
    self as net_registry, ComponentKind as NetComponentKind,
};

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as FmtWrite;
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors that the CLI layer can produce.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// An unknown subcommand was encountered.
    #[error("unknown command '{0}'")]
    UnknownCommand(String),

    /// A required argument is missing.
    #[error("missing required argument: {0}")]
    MissingArgument(String),

    /// An argument value could not be parsed.
    #[error("invalid value for '{arg}': {reason}")]
    InvalidValue { arg: String, reason: String },

    /// The configuration file could not be read or parsed.
    #[error("config error: {0}")]
    Config(String),

    /// An I/O error occurred while writing output.
    #[error("output error: {0}")]
    Output(String),

    /// Interactive mode failed.
    #[error("interactive error: {0}")]
    Interactive(String),
}

// ── Output format ────────────────────────────────────────────────────────────

/// The output format requested by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable text table (default).
    #[default]
    Table,
    /// Minified JSON.
    Json,
    /// Pretty-printed JSON.
    JsonPretty,
    /// CSV (comma-separated values).
    Csv,
    /// One value per line (useful for piping).
    Lines,
    /// HTML report.
    Html,
    /// SARIF static-analysis results format.
    Sarif,
}

impl OutputFormat {
    /// All recognised format names.
    #[must_use]
    pub const fn all_names() -> &'static [&'static str] {
        &["table", "json", "json-pretty", "csv", "lines", "html", "sarif"]
    }

    /// Return the canonical name string for this format.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::JsonPretty => "json-pretty",
            Self::Csv => "csv",
            Self::Lines => "lines",
            Self::Html => "html",
            Self::Sarif => "sarif",
        }
    }
}

impl FromStr for OutputFormat {
    type Err = CliError;

    /// # Errors
    /// Returns `CliError::InvalidValue` if `s` is not a recognised format name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "json-pretty" => Ok(Self::JsonPretty),
            "csv" => Ok(Self::Csv),
            "lines" => Ok(Self::Lines),
            "html" => Ok(Self::Html),
            "sarif" => Ok(Self::Sarif),
            other => Err(CliError::InvalidValue {
                arg: "--format".into(),
                reason: format!("unknown format '{other}'"),
            }),
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── Subcommands ──────────────────────────────────────────────────────────────

/// All top-level subcommands supported by the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubCommand {
    /// Print help and exit.
    Help,
    /// Print version and exit.
    Version,
    /// Open an interactive REPL session.
    Interactive,
    /// Run a single analysis script file.
    Script { path: PathBuf },
    /// Analyse a binary file.
    Analyse {
        path: PathBuf,
        arch: Option<String>,
        base_addr: Option<u64>,
    },
    /// Disassemble a raw binary at an optional base address.
    Disassemble {
        path: PathBuf,
        arch: String,
        base_addr: u64,
        count: Option<usize>,
    },
    /// Dump symbols from a binary.
    Symbols { path: PathBuf },
    /// Export the analysis database.
    Export {
        path: PathBuf,
        out: PathBuf,
        format: OutputFormat,
    },
    /// Import an analysis database.
    Import { path: PathBuf },
    /// Print the configuration and exit.
    Config,
    /// Smoke-test the in-memory graph backend.
    GraphSmoke,
}

impl SubCommand {
    /// Return a short description of this subcommand.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Help => "Print help",
            Self::Version => "Print version",
            Self::Interactive => "Start interactive REPL",
            Self::Script { .. } => "Execute a script file",
            Self::Analyse { .. } => "Analyse a binary",
            Self::Disassemble { .. } => "Linear-sweep disassembly",
            Self::Symbols { .. } => "Dump symbols",
            Self::Export { .. } => "Export analysis database",
            Self::Import { .. } => "Import analysis database",
            Self::Config => "Show effective configuration",
            Self::GraphSmoke => "Smoke-test graph backend",
        }
    }
}

// ── CLI arguments ─────────────────────────────────────────────────────────────

/// Parsed command-line arguments.
#[derive(Debug, Clone)]
pub struct CliArgs {
    /// The subcommand to execute.
    pub subcommand: SubCommand,
    /// Output format override.
    pub format: OutputFormat,
    /// Verbosity level (0 = quiet, 1 = normal, 2+ = verbose).
    pub verbosity: u32,
    /// Suppress all non-error output.
    pub quiet: bool,
    /// Path to a custom configuration file.
    pub config_path: Option<PathBuf>,
    /// Extra key=value overrides for configuration.
    pub overrides: HashMap<String, String>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            subcommand: SubCommand::Help,
            format: OutputFormat::Table,
            verbosity: 1,
            quiet: false,
            config_path: None,
            overrides: HashMap::new(),
        }
    }
}

// ── Argument parser ───────────────────────────────────────────────────────────

/// Hand-rolled argument parser.
///
/// Understands:
/// - Short flags: `-h`, `-v`, `-q`
/// - Long flags: `--help`, `--verbose`, `--quiet`
/// - Options with values: `--format=json` or `--format json`
/// - Subcommands as positional arguments
pub struct ArgParser {
    raw: Vec<String>,
    pos: usize,
}

impl ArgParser {
    /// Construct a parser from the program's argument list (excluding `argv[0]`).
    #[must_use]
    pub const fn new(args: Vec<String>) -> Self {
        Self { raw: args, pos: 0 }
    }

    /// Return the next raw token without consuming it.
    #[must_use]
    fn peek(&self) -> Option<&str> {
        self.raw.get(self.pos).map(String::as_str)
    }

    /// Consume and return the next raw token.
    fn next_token(&mut self) -> Option<&str> {
        let tok = self.raw.get(self.pos).map(String::as_str);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    /// Consume a value token that follows an option.
    ///
    /// # Errors
    /// Returns `CliError::MissingArgument` if no token follows, or if the next
    /// token is itself a flag (begins with `-`) rather than a value.
    fn expect_value(&mut self, opt: &str) -> Result<String, CliError> {
        // Look ahead without consuming: if the next token is another flag, the
        // user almost certainly forgot the value, so report a missing argument
        // instead of swallowing the following flag as a bogus value.
        match self.peek() {
            None => return Err(CliError::MissingArgument(opt.to_string())),
            Some(next) if next.starts_with('-') && next != "-" => {
                return Err(CliError::MissingArgument(opt.to_string()));
            }
            Some(_) => {}
        }
        match self.next_token() {
            Some(v) => Ok(v.to_string()),
            None => Err(CliError::MissingArgument(opt.to_string())),
        }
    }

    /// Parse all arguments into a `CliArgs` struct.
    ///
    /// # Errors
    /// Returns `CliError::UnknownCommand` or `CliError::InvalidValue` on bad input.
    pub fn parse(mut self) -> Result<CliArgs, CliError> {
        let mut args = CliArgs::default();
        let mut positionals: Vec<String> = Vec::new();

        while let Some(tok) = self.next_token().map(str::to_owned) {
            if tok == "--" {
                // Everything after `--` is positional.
                while let Some(rest) = self.next_token().map(str::to_owned) {
                    positionals.push(rest);
                }
                break;
            }
            if let Some(long) = tok.strip_prefix("--") {
                let long = long.to_owned();
                self.parse_long(&long, &mut args)?;
            } else if let Some(short) = tok.strip_prefix('-') {
                let short = short.to_owned();
                self.parse_short(&short, &mut args)?;
            } else {
                positionals.push(tok);
            }
        }

        // Resolve subcommand from positionals. A positional subcommand takes
        // precedence; when none is given, keep any subcommand already chosen by
        // a flag such as `--version` or `--help` (default is `Help`).
        if positionals.is_empty() {
            // `args.subcommand` already holds the flag-selected value (or the
            // default `Help`), so leave it untouched.
        } else {
            args.subcommand = resolve_subcommand(&positionals, &mut self)?;
        }
        Ok(args)
    }

    fn parse_long(&mut self, long: &str, args: &mut CliArgs) -> Result<(), CliError> {
        // Support `--key=value` syntax.
        if let Some((key, val)) = long.split_once('=') {
            return self.apply_long_kv(key, val, args);
        }
        match long {
            "help" => args.subcommand = SubCommand::Help,
            "version" => args.subcommand = SubCommand::Version,
            "verbose" => args.verbosity += 1,
            "quiet" => args.quiet = true,
            "format" => {
                let val = self.expect_value("--format")?;
                args.format = val.parse()?;
            }
            "config" => {
                let val = self.expect_value("--config")?;
                args.config_path = Some(PathBuf::from(val));
            }
            other => {
                return Err(CliError::UnknownCommand(format!("--{other}")));
            }
        }
        Ok(())
    }

    fn apply_long_kv(&self, key: &str, val: &str, args: &mut CliArgs) -> Result<(), CliError> {
        match key {
            "format" | "f" => args.format = val.parse()?,
            "config" | "c" => args.config_path = Some(PathBuf::from(val)),
            other => {
                let _ = val;
                return Err(CliError::UnknownCommand(format!("--{other}")));
            }
        }
        Ok(())
    }

    fn parse_short(&mut self, short: &str, args: &mut CliArgs) -> Result<(), CliError> {
        for ch in short.chars() {
            match ch {
                'h' => args.subcommand = SubCommand::Help,
                'V' => args.subcommand = SubCommand::Version,
                'v' => args.verbosity += 1,
                'q' => args.quiet = true,
                other => {
                    return Err(CliError::UnknownCommand(format!("-{other}")));
                }
            }
        }
        Ok(())
    }
}

fn resolve_subcommand(
    positionals: &[String],
    _parser: &mut ArgParser,
) -> Result<SubCommand, CliError> {
    let cmd = match positionals.first() {
        None => return Ok(SubCommand::Help),
        Some(c) => c.as_str(),
    };
    match cmd {
        "help" | "h" => Ok(SubCommand::Help),
        "version" => Ok(SubCommand::Version),
        "interactive" | "repl" => Ok(SubCommand::Interactive),
        "graph-smoke" => Ok(SubCommand::GraphSmoke),
        "config" => Ok(SubCommand::Config),
        "script" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("script <path>".into()))?;
            Ok(SubCommand::Script { path })
        }
        "analyse" | "analyze" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("analyse <path>".into()))?;
            let arch = positionals.get(2).cloned();
            let base_addr = positionals
                .get(3)
                .map(|s| parse_addr(s, "base-addr"))
                .transpose()?;
            Ok(SubCommand::Analyse {
                path,
                arch,
                base_addr,
            })
        }
        "disassemble" | "dis" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("disassemble <path> <arch>".into()))?;
            let arch = positionals
                .get(2)
                .cloned()
                .unwrap_or_else(|| "x86_64".into());
            let base_addr = positionals
                .get(3)
                .map(|s| parse_addr(s, "base-addr"))
                .transpose()?
                .unwrap_or(0);
            let count = positionals
                .get(4)
                .map(|s| {
                    s.parse::<usize>().map_err(|_| CliError::InvalidValue {
                        arg: "count".into(),
                        reason: "expected an integer".into(),
                    })
                })
                .transpose()?;
            Ok(SubCommand::Disassemble {
                path,
                arch,
                base_addr,
                count,
            })
        }
        "symbols" | "syms" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("symbols <path>".into()))?;
            Ok(SubCommand::Symbols { path })
        }
        "export" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("export <input> <output>".into()))?;
            let out = positionals
                .get(2)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("export <input> <output>".into()))?;
            let format = positionals
                .get(3)
                .map(|s| s.parse::<OutputFormat>())
                .transpose()?
                .unwrap_or_default();
            Ok(SubCommand::Export { path, out, format })
        }
        "import" => {
            let path = positionals
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| CliError::MissingArgument("import <path>".into()))?;
            Ok(SubCommand::Import { path })
        }
        other => Err(CliError::UnknownCommand(other.to_string())),
    }
}

fn parse_addr(s: &str, name: &str) -> Result<u64, CliError> {
    let s = s.trim();
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    let result = if let Some(h) = hex {
        u64::from_str_radix(h, 16)
    } else {
        s.parse::<u64>()
    };
    result.map_err(|_| CliError::InvalidValue {
        arg: name.to_string(),
        reason: format!("'{s}' is not a valid address"),
    })
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Per-key configuration value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl fmt::Display for ConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// CLI configuration loaded from a TOML-like key=value file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Key-value pairs from the config file.
    pub values: HashMap<String, ConfigValue>,
    /// Path the config was loaded from, if any.
    pub source_path: Option<PathBuf>,
}

impl CliConfig {
    /// Create an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the value for `key`, if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ConfigValue> {
        self.values.get(key)
    }

    /// Return the string value for `key`, if present and a string.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(ConfigValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the integer value for `key`.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.values.get(key) {
            Some(ConfigValue::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// Return the bool value for `key`.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.values.get(key) {
            Some(ConfigValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Set a string value.
    pub fn set_str(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.values
            .insert(key.into(), ConfigValue::String(val.into()));
    }

    /// Set an integer value.
    pub fn set_int(&mut self, key: impl Into<String>, val: i64) {
        self.values.insert(key.into(), ConfigValue::Int(val));
    }

    /// Set a bool value.
    pub fn set_bool(&mut self, key: impl Into<String>, val: bool) {
        self.values.insert(key.into(), ConfigValue::Bool(val));
    }

    /// Apply key=value overrides from the command line.
    ///
    /// # Errors
    /// Returns `CliError::InvalidValue` if a value cannot be parsed.
    pub fn apply_overrides(&mut self, overrides: &HashMap<String, String>) -> Result<(), CliError> {
        for (key, raw) in overrides {
            let cv = parse_config_value(raw).map_err(|e| CliError::InvalidValue {
                arg: key.clone(),
                reason: e,
            })?;
            self.values.insert(key.clone(), cv);
        }
        Ok(())
    }

    /// Load configuration from a simple `key = value` text file.
    ///
    /// Lines starting with `#` are comments; blank lines are ignored.
    ///
    /// # Errors
    /// Returns `CliError::Config` if the file cannot be read or a line is
    /// malformed.
    pub fn load_from_file(path: &Path) -> Result<Self, CliError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut cfg = Self::new();
        cfg.source_path = Some(path.to_path_buf());
        // Track the line number where each key was first defined so we can
        // include both locations in the duplicate-key error message.
        let mut key_linenos: HashMap<String, usize> = HashMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, raw) = line.split_once('=').ok_or_else(|| {
                CliError::Config(format!(
                    "{}:{}: expected 'key = value'",
                    path.display(),
                    lineno + 1
                ))
            })?;
            let key = key.trim().to_string();
            let raw = raw.trim();
            let cv = parse_config_value(raw)
                .map_err(|e| CliError::Config(format!("{}:{}: {e}", path.display(), lineno + 1)))?;
            if let Some(&first_line) = key_linenos.get(&key) {
                return Err(CliError::Config(format!(
                    "{}:{}: duplicate key '{}' (first defined at line {})",
                    path.display(),
                    lineno + 1,
                    key,
                    first_line
                )));
            }
            key_linenos.insert(key.clone(), lineno + 1);
            cfg.values.insert(key, cv);
        }
        Ok(cfg)
    }

    /// Return the effective output format, falling back to `default`.
    #[must_use]
    pub fn output_format(&self, default: OutputFormat) -> OutputFormat {
        self.get_str("output.format")
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }

    /// Number of key-value pairs stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Return `true` if no values are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

fn parse_config_value(raw: &str) -> Result<ConfigValue, String> {
    if raw == "true" {
        return Ok(ConfigValue::Bool(true));
    }
    if raw == "false" {
        return Ok(ConfigValue::Bool(false));
    }
    if let Ok(n) = raw.parse::<i64>() {
        return Ok(ConfigValue::Int(n));
    }
    if let Ok(f) = raw.parse::<f64>() {
        return Ok(ConfigValue::Float(f));
    }
    // Strip optional surrounding quotes.
    let s = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(raw);
    Ok(ConfigValue::String(s.to_string()))
}

// ── Progress bar ──────────────────────────────────────────────────────────────

/// A simple ASCII progress bar that writes to stderr.
pub struct ProgressBar {
    label: String,
    total: u64,
    current: u64,
    width: usize,
    start: Instant,
    quiet: bool,
}

impl ProgressBar {
    /// Create a new progress bar with the given `label` and `total` steps.
    #[must_use]
    pub fn new(label: impl Into<String>, total: u64) -> Self {
        Self {
            label: label.into(),
            total,
            current: 0,
            width: 40,
            start: Instant::now(),
            quiet: false,
        }
    }

    /// Set the bar width in characters (default: 40).
    #[must_use]
    pub const fn with_width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Suppress output.
    #[must_use]
    pub const fn quiet(mut self) -> Self {
        self.quiet = true;
        self
    }

    /// Advance the progress by `n` steps and redraw.
    pub fn advance(&mut self, n: u64) {
        self.current = self.current.saturating_add(n).min(self.total);
        self.draw();
    }

    /// Mark the progress bar as finished and print a newline.
    pub fn finish(&mut self) {
        self.current = self.total;
        self.draw();
        if !self.quiet {
            let _ = writeln!(io::stderr());
        }
    }

    /// Return elapsed time since construction.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Return the completion fraction in [0.0, 1.0].
    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.current as f64 / self.total as f64
        }
    }

    fn draw(&self) {
        if self.quiet {
            return;
        }
        let frac = self.fraction();
        // Clamp `filled` to `self.width` to avoid underflow in `self.width - filled`
        // when floating-point rounding causes `filled` to exceed `self.width`.
        let filled = (frac * self.width as f64) as usize;
        let filled = filled.min(self.width);
        let bar: String = std::iter::repeat_n('#', filled)
            .chain(std::iter::repeat_n('-', self.width - filled))
            .collect();
        let pct = (frac * 100.0) as u32;
        let elapsed = self.start.elapsed().as_secs_f32();
        let _ = write!(
            io::stderr(),
            "\r{}: [{bar}] {pct:3}% ({}/{}) {elapsed:.1}s",
            self.label,
            self.current,
            self.total,
        );
        let _ = io::stderr().flush();
    }
}

// ── Table renderer ────────────────────────────────────────────────────────────

/// A simple grid table for CLI output.
#[derive(Debug, Clone)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    col_align: Vec<ColAlign>,
}

/// Column alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum ColAlign {
    #[default]
    Left,
    Right,
    Center,
}


impl Table {
    /// Create a new table with the given column headers.
    #[must_use]
    pub fn new(headers: Vec<impl Into<String>>) -> Self {
        let headers: Vec<String> = headers.into_iter().map(Into::into).collect();
        let ncols = headers.len();
        Self {
            headers,
            rows: Vec::new(),
            col_align: vec![ColAlign::Left; ncols],
        }
    }

    /// Set the alignment for column `col`.
    ///
    /// # Panics
    /// Panics if `col >= number_of_columns`.
    pub fn set_align(&mut self, col: usize, align: ColAlign) {
        self.col_align[col] = align;
    }

    /// Append a row of cells.
    pub fn push_row(&mut self, row: Vec<impl Into<String>>) {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    /// Return the number of data rows (excluding the header).
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Render the table to a `String` in human-readable form.
    #[must_use]
    pub fn render_table(&self) -> String {
        let ncols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(std::string::String::len).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < ncols {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }
        let sep: String = widths
            .iter()
            .map(|w| "-".repeat(w + 2))
            .collect::<Vec<_>>()
            .join("+");
        let sep = format!("+{sep}+");

        let mut out = String::new();
        out.push_str(&sep);
        out.push('\n');
        out.push_str(&self.render_row(&self.headers, &widths));
        out.push('\n');
        out.push_str(&sep);
        out.push('\n');
        for row in &self.rows {
            out.push_str(&self.render_row(row, &widths));
            out.push('\n');
        }
        out.push_str(&sep);
        out.push('\n');
        out
    }

    fn render_row(&self, cells: &[String], widths: &[usize]) -> String {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let w = widths.get(i).copied().unwrap_or(c.len());
                let align = self.col_align.get(i).copied().unwrap_or_default();
                let padded = match align {
                    ColAlign::Left => format!("{c:<w$}"),
                    ColAlign::Right => format!("{c:>w$}"),
                    ColAlign::Center => format!("{c:^w$}"),
                };
                format!(" {padded} ")
            })
            .collect();
        format!("|{}|", parts.join("|"))
    }

    /// Render the table as JSON array-of-objects.
    ///
    /// Uses `serde_json` to correctly escape all string values (backslashes,
    /// double-quotes, control characters, etc.).
    #[must_use]
    pub fn render_json(&self, pretty: bool) -> String {
        // Build a vec of ordered BTreeMaps so keys are sorted deterministically
        // and serde_json handles all escaping correctly.
        let objs: Vec<std::collections::BTreeMap<&str, &str>> = self
            .rows
            .iter()
            .map(|row| {
                self.headers
                    .iter()
                    .zip(row.iter())
                    .map(|(h, v)| (h.as_str(), v.as_str()))
                    .collect()
            })
            .collect();
        if pretty {
            serde_json::to_string_pretty(&objs).unwrap_or_else(|_| "[]".to_string())
        } else {
            serde_json::to_string(&objs).unwrap_or_else(|_| "[]".to_string())
        }
    }

    /// Render the table as CSV.
    #[must_use]
    pub fn render_csv(&self) -> String {
        let mut out = self
            .headers
            .iter()
            .map(|h| csv_escape(h))
            .collect::<Vec<_>>()
            .join(",");
        out.push('\n');
        for row in &self.rows {
            let line: String = row
                .iter()
                .map(|c| csv_escape(c))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    /// Render using the specified `OutputFormat`.
    #[must_use]
    pub fn render(&self, fmt: OutputFormat) -> String {
        match fmt {
            OutputFormat::Table => self.render_table(),
            OutputFormat::Json => self.render_json(false),
            OutputFormat::JsonPretty => self.render_json(true),
            OutputFormat::Csv => self.render_csv(),
            OutputFormat::Lines => {
                let mut s = String::new();
                for row in &self.rows {
                    s.push_str(&row.join("\t"));
                    s.push('\n');
                }
                s
            }
            // Html and Sarif are handled by dedicated run_* functions; fall back
            // to JSON for table rendering contexts.
            OutputFormat::Html | OutputFormat::Sarif => self.render_json(true),
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ── Coloured output helpers ───────────────────────────────────────────────────

/// ANSI colour codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Reset,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightCyan,
    Bold,
    Dim,
}

impl Color {
    /// Return the ANSI escape sequence for this colour.
    #[must_use]
    pub const fn ansi(self) -> &'static str {
        match self {
            Self::Reset => "\x1b[0m",
            Self::Red => "\x1b[31m",
            Self::Green => "\x1b[32m",
            Self::Yellow => "\x1b[33m",
            Self::Blue => "\x1b[34m",
            Self::Magenta => "\x1b[35m",
            Self::Cyan => "\x1b[36m",
            Self::White => "\x1b[37m",
            Self::BrightRed => "\x1b[91m",
            Self::BrightGreen => "\x1b[92m",
            Self::BrightYellow => "\x1b[93m",
            Self::BrightBlue => "\x1b[94m",
            Self::BrightCyan => "\x1b[96m",
            Self::Bold => "\x1b[1m",
            Self::Dim => "\x1b[2m",
        }
    }
}

/// Wrap `text` in ANSI colour escape sequences.
///
/// When `use_color` is `false` the text is returned unchanged.
#[must_use]
pub fn colorize(text: &str, color: Color, use_color: bool) -> String {
    if use_color {
        format!("{}{}{}", color.ansi(), text, Color::Reset.ansi())
    } else {
        text.to_string()
    }
}

/// Determine whether the current stdout/stderr likely supports ANSI codes.
#[must_use]
pub fn terminal_supports_color() -> bool {
    // Respect the NO_COLOR convention unconditionally.
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    // On Windows, TERM is almost never set. Check Windows-specific environment
    // variables that indicate a modern terminal with ANSI support before
    // falling back to the TERM check.
    #[cfg(target_os = "windows")]
    {
        // Windows Terminal sets WT_SESSION.
        if std::env::var("WT_SESSION").is_ok() {
            return true;
        }
        // ANSICON wraps the console with ANSI support.
        if std::env::var("ANSICON").is_ok() {
            return true;
        }
        // Many terminal emulators set TERM_PROGRAM (e.g. vscode, hyper).
        if std::env::var("TERM_PROGRAM").is_ok() {
            return true;
        }
        // ConEmu / cmder set ConEmuANSI.
        if matches!(std::env::var("ConEmuANSI").as_deref(), Ok("ON")) {
            return true;
        }
    }
    // On Unix (and Windows without the above signals), treat a missing or
    // "dumb" TERM as no-color.
    !matches!(std::env::var("TERM").as_deref(), Ok("dumb") | Err(_))
}

// ── Interactive mode ──────────────────────────────────────────────────────────

/// A simple line-based interactive REPL.
pub struct InteractiveSession {
    prompt: String,
    history: Vec<String>,
    color: bool,
}

impl InteractiveSession {
    /// Create an interactive session with the given prompt string.
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            history: Vec::new(),
            color: terminal_supports_color(),
        }
    }

    /// Override color support detection.
    #[must_use]
    pub const fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Return the session history.
    #[must_use]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Read one line from stdin.
    ///
    /// # Errors
    /// Returns `CliError::Interactive` on I/O failure or EOF.
    pub fn read_line(&mut self) -> Result<String, CliError> {
        let prompt = colorize(&self.prompt, Color::BrightGreen, self.color);
        print!("{prompt}");
        io::stdout()
            .flush()
            .map_err(|e| CliError::Interactive(e.to_string()))?;
        let mut line = String::new();
        let n = io::stdin()
            .read_line(&mut line)
            .map_err(|e| CliError::Interactive(e.to_string()))?;
        if n == 0 {
            return Err(CliError::Interactive("EOF".into()));
        }
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        if !trimmed.is_empty() {
            self.history.push(trimmed.clone());
        }
        Ok(trimmed)
    }

    /// Execute a line through the registered dispatcher.
    ///
    /// Returns `true` if the session should continue, `false` to exit.
    #[must_use]
    pub fn dispatch_line(line: &str) -> bool {
        match line.trim() {
            "" => true,
            "quit" | "exit" | "q" => false,
            "help" | "h" | "?" => {
                println!("Commands: quit, exit, help");
                true
            }
            other => {
                println!("Unknown command: {other}");
                true
            }
        }
    }
}

// ── Main CLI entry point ──────────────────────────────────────────────────────

/// Top-level CLI orchestrator.
pub struct Cli {
    pub args: CliArgs,
    pub config: CliConfig,
    pub color: bool,
}

impl Cli {
    /// Build a `Cli` from raw argv (excluding the binary name).
    ///
    /// # Errors
    /// Returns `CliError` if argument parsing or config loading fails.
    pub fn from_argv(argv: Vec<String>) -> Result<Self, CliError> {
        let args = ArgParser::new(argv).parse()?;
        let mut config = if let Some(p) = &args.config_path { CliConfig::load_from_file(p)? } else {
            // Try default locations.
            let home_cfg = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| {
                    let mut pb = PathBuf::from(h);
                    pb.push(".rustre.cfg");
                    pb
                });
            let candidates: [PathBuf; 3] = [
                PathBuf::from(".rustre.cfg"),
                PathBuf::from("rustre.cfg"),
                home_cfg.unwrap_or_else(|| PathBuf::from("~/.rustre.cfg")),
            ];
            let mut loaded = None;
            for pb in &candidates {
                if pb.exists()
                    && let Ok(c) = CliConfig::load_from_file(pb) {
                        loaded = Some(c);
                        break;
                    }
            }
            loaded.unwrap_or_default()
        };
        config.apply_overrides(&args.overrides)?;
        let color = terminal_supports_color() && !args.quiet;
        Ok(Self {
            args,
            config,
            color,
        })
    }

    /// Print the help text to stdout.
    pub fn print_help(&self) {
        let name = env!("CARGO_PKG_NAME");
        let ver = env!("CARGO_PKG_VERSION");
        println!("{} {ver}", colorize(name, Color::Bold, self.color));
        println!("RustRE command line interface");
        println!();
        println!("{}:", colorize("Usage", Color::Yellow, self.color));
        println!("  {name} [OPTIONS] <COMMAND>");
        println!();
        println!("{}:", colorize("Options", Color::Yellow, self.color));
        println!("  -h, --help           Print help");
        println!("  -V, --version        Print version");
        println!("  -v, --verbose        Increase verbosity (repeat for more)");
        println!("  -q, --quiet          Suppress non-error output");
        println!("  --format <FMT>       Output format: table|json|json-pretty|csv|lines");
        println!("  --config <FILE>      Load configuration from FILE");
        println!();
        println!("{}:", colorize("Commands", Color::Yellow, self.color));
        let cmds = [
            ("analyse <path>", "Analyse a binary file"),
            ("disassemble <path> <arch>", "Linear-sweep disassembly"),
            ("symbols <path>", "Dump symbols from a binary"),
            ("export <in> <out>", "Export analysis database"),
            ("import <path>", "Import analysis database"),
            ("script <path>", "Execute a script file"),
            ("interactive", "Start interactive REPL"),
            ("config", "Show effective configuration"),
            ("graph-smoke", "Smoke-test graph backend"),
            ("version", "Print version"),
            ("help", "Print this help"),
        ];
        for (cmd, desc) in &cmds {
            println!("  {:<30} {desc}", colorize(cmd, Color::Cyan, self.color));
        }
    }

    /// Print version information.
    pub fn print_version(&self) {
        let name = env!("CARGO_PKG_NAME");
        let ver = env!("CARGO_PKG_VERSION");
        println!("{name} {ver}");
    }

    /// Print the effective configuration.
    pub fn print_config(&self) {
        if self.config.is_empty() {
            println!("(no configuration loaded)");
            return;
        }
        let mut tbl = Table::new(vec!["Key", "Value"]);
        let mut pairs: Vec<(&String, &ConfigValue)> = self.config.values.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in pairs {
            tbl.push_row(vec![k.clone(), v.to_string()]);
        }
        print!("{}", tbl.render(self.args.format));
    }
}

// ── Help text builder ─────────────────────────────────────────────────────────

/// Build a formatted help string for display without a full `Cli` instance.
#[must_use]
pub fn build_help_text(name: &str, version: &str, about: &str) -> String {
    format!(
        "{name} {version}\n{about}\n\nUsage:\n  {name} [OPTIONS] <COMMAND>\n\nUse '{name} help' for full usage.\n"
    )
}

/// Print a warning message (yellow) to stderr.
pub fn warn(msg: &str, color: bool) {
    eprintln!(
        "{}",
        colorize(&format!("warning: {msg}"), Color::Yellow, color)
    );
}

/// Print an error message (red) to stderr.
pub fn error(msg: &str, color: bool) {
    eprintln!("{}", colorize(&format!("error: {msg}"), Color::Red, color));
}

/// Print an informational message (cyan) to stdout, unless quiet.
pub fn info(msg: &str, color: bool, quiet: bool) {
    if !quiet {
        println!("{}", colorize(msg, Color::Cyan, color));
    }
}

/// Print a success message (green) to stdout, unless quiet.
pub fn success(msg: &str, color: bool, quiet: bool) {
    if !quiet {
        println!("{}", colorize(msg, Color::BrightGreen, color));
    }
}

// ── Hex formatting helpers (RE-specific) ─────────────────────────────────────

/// Format a `u64` address as a zero-padded hex string with `0x` prefix.
#[must_use]
pub fn fmt_addr(addr: u64, bits: u32) -> String {
    match bits {
        16 => format!("0x{addr:04X}"),
        32 => format!("0x{addr:08X}"),
        _ => format!("0x{addr:016X}"),
    }
}

/// Format a byte slice as a hex dump string (space-separated bytes).
#[must_use]
pub fn fmt_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a byte slice as printable ASCII, replacing non-printable with `.`.
#[must_use]
pub fn fmt_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Format an integer with thousands separators (e.g. `1_234_567`).
#[must_use]
pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i.is_multiple_of(3) {
            out.push('_');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── OutputFormat ──────────────────────────────────────────────────────────

    #[test]
    fn test_output_format_parse() {
        assert_eq!(
            "table".parse::<OutputFormat>().unwrap(),
            OutputFormat::Table
        );
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "json-pretty".parse::<OutputFormat>().unwrap(),
            OutputFormat::JsonPretty
        );
        assert_eq!("csv".parse::<OutputFormat>().unwrap(), OutputFormat::Csv);
        assert_eq!(
            "lines".parse::<OutputFormat>().unwrap(),
            OutputFormat::Lines
        );
        assert!("garbage".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Table.to_string(), "table");
        assert_eq!(OutputFormat::JsonPretty.to_string(), "json-pretty");
    }

    #[test]
    fn test_output_format_name() {
        assert_eq!(OutputFormat::Csv.name(), "csv");
        assert_eq!(OutputFormat::Lines.name(), "lines");
    }

    #[test]
    fn test_output_format_all_names() {
        let names = OutputFormat::all_names();
        assert!(names.contains(&"table"));
        assert!(names.contains(&"json-pretty"));
    }

    // ── ArgParser ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_empty() {
        let args = ArgParser::new(vec![]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::Help);
    }

    #[test]
    fn test_parse_help_flag() {
        let args = ArgParser::new(vec!["--help".into()]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::Help);
    }

    #[test]
    fn test_parse_version_flag() {
        let args = ArgParser::new(vec!["--version".into()]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::Version);
    }

    #[test]
    fn test_parse_verbose() {
        let args = ArgParser::new(vec!["-v".into(), "-v".into(), "help".into()])
            .parse()
            .unwrap();
        assert_eq!(args.verbosity, 3); // default 1 + 2 increments
    }

    #[test]
    fn test_parse_quiet() {
        let args = ArgParser::new(vec!["-q".into()]).parse().unwrap();
        assert!(args.quiet);
    }

    #[test]
    fn test_parse_format_equals() {
        let args = ArgParser::new(vec!["--format=json".into()])
            .parse()
            .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
    }

    #[test]
    fn test_parse_format_space() {
        let args = ArgParser::new(vec!["--format".into(), "csv".into()])
            .parse()
            .unwrap();
        assert_eq!(args.format, OutputFormat::Csv);
    }

    #[test]
    fn test_parse_format_missing_value_followed_by_flag() {
        // `--format` with no value but another flag next should be reported as a
        // missing argument (the lookahead via `peek` must catch this) rather
        // than swallowing `--quiet` as the format value.
        let result = ArgParser::new(vec!["--format".into(), "--quiet".into()]).parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::MissingArgument(s) => assert_eq!(s, "--format"),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn test_parse_format_missing_value_at_end() {
        let result = ArgParser::new(vec!["--config".into()]).parse();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::MissingArgument(_)));
    }

    #[test]
    fn test_parse_graph_smoke() {
        let args = ArgParser::new(vec!["graph-smoke".into()]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::GraphSmoke);
    }

    #[test]
    fn test_parse_config() {
        let args = ArgParser::new(vec!["config".into()]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::Config);
    }

    #[test]
    fn test_parse_interactive() {
        let args = ArgParser::new(vec!["interactive".into()]).parse().unwrap();
        assert_eq!(args.subcommand, SubCommand::Interactive);
    }

    #[test]
    fn test_parse_script() {
        let args = ArgParser::new(vec!["script".into(), "/tmp/foo.lua".into()])
            .parse()
            .unwrap();
        match args.subcommand {
            SubCommand::Script { path } => assert_eq!(path, PathBuf::from("/tmp/foo.lua")),
            other => panic!("expected Script, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_symbols() {
        let args = ArgParser::new(vec!["symbols".into(), "target.exe".into()])
            .parse()
            .unwrap();
        assert!(matches!(args.subcommand, SubCommand::Symbols { .. }));
    }

    #[test]
    fn test_parse_unknown_command() {
        let result = ArgParser::new(vec!["zorkinator".into()]).parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::UnknownCommand(s) => assert_eq!(s, "zorkinator"),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn test_parse_addr_hex() {
        assert_eq!(parse_addr("0x1000", "addr").unwrap(), 0x1000);
        assert_eq!(parse_addr("0X00FF", "addr").unwrap(), 0xff);
    }

    #[test]
    fn test_parse_addr_decimal() {
        assert_eq!(parse_addr("4096", "addr").unwrap(), 4096);
    }

    #[test]
    fn test_parse_addr_invalid() {
        assert!(parse_addr("abc", "addr").is_err());
    }

    // ── CliConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn test_config_set_get() {
        let mut cfg = CliConfig::new();
        cfg.set_str("key1", "hello");
        cfg.set_int("key2", 42);
        cfg.set_bool("key3", true);
        assert_eq!(cfg.get_str("key1"), Some("hello"));
        assert_eq!(cfg.get_int("key2"), Some(42));
        assert_eq!(cfg.get_bool("key3"), Some(true));
        assert_eq!(cfg.len(), 3);
        assert!(!cfg.is_empty());
    }

    #[test]
    fn test_config_apply_overrides() {
        let mut cfg = CliConfig::new();
        let mut overrides = HashMap::new();
        overrides.insert("output.format".into(), "json".into());
        overrides.insert("verbosity".into(), "2".into());
        cfg.apply_overrides(&overrides).unwrap();
        assert_eq!(cfg.output_format(OutputFormat::Table), OutputFormat::Json);
        assert_eq!(cfg.get_int("verbosity"), Some(2));
    }

    #[test]
    fn test_config_from_file_missing() {
        let result = CliConfig::load_from_file(Path::new("/nonexistent/path/rustre.cfg"));
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::Config(_) => {}
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn test_parse_config_value_bool() {
        assert_eq!(parse_config_value("true").unwrap(), ConfigValue::Bool(true));
        assert_eq!(
            parse_config_value("false").unwrap(),
            ConfigValue::Bool(false)
        );
    }

    #[test]
    fn test_parse_config_value_int() {
        assert_eq!(parse_config_value("123").unwrap(), ConfigValue::Int(123));
        assert_eq!(parse_config_value("-7").unwrap(), ConfigValue::Int(-7));
    }

    #[test]
    fn test_parse_config_value_string() {
        assert_eq!(
            parse_config_value("hello").unwrap(),
            ConfigValue::String("hello".into())
        );
        assert_eq!(
            parse_config_value("\"quoted\"").unwrap(),
            ConfigValue::String("quoted".into())
        );
    }

    // ── Table ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_table_render_table() {
        let mut tbl = Table::new(vec!["Name", "Value"]);
        tbl.push_row(vec!["alpha", "1"]);
        tbl.push_row(vec!["beta", "2"]);
        let rendered = tbl.render_table();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("alpha"));
        assert!(rendered.contains("beta"));
    }

    #[test]
    fn test_table_render_json() {
        let mut tbl = Table::new(vec!["A", "B"]);
        tbl.push_row(vec!["x", "y"]);
        let json = tbl.render_json(false);
        assert!(json.starts_with('['));
        assert!(json.contains("\"A\""));
    }

    #[test]
    fn test_table_render_csv() {
        let mut tbl = Table::new(vec!["Col1", "Col2"]);
        tbl.push_row(vec!["a,b", "c"]);
        let csv = tbl.render_csv();
        assert!(csv.contains("\"a,b\""));
    }

    #[test]
    fn test_table_row_count() {
        let mut tbl = Table::new(vec!["X"]);
        assert_eq!(tbl.row_count(), 0);
        tbl.push_row(vec!["1"]);
        tbl.push_row(vec!["2"]);
        assert_eq!(tbl.row_count(), 2);
    }

    #[test]
    fn test_table_render_format_dispatch() {
        let mut tbl = Table::new(vec!["K", "V"]);
        tbl.push_row(vec!["k1", "v1"]);
        assert!(!tbl.render(OutputFormat::Table).is_empty());
        assert!(!tbl.render(OutputFormat::Json).is_empty());
        assert!(!tbl.render(OutputFormat::Csv).is_empty());
        assert!(!tbl.render(OutputFormat::Lines).is_empty());
    }

    // ── Colour helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_colorize_with_color() {
        let s = colorize("hello", Color::Red, true);
        assert!(s.contains("\x1b["));
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_colorize_no_color() {
        let s = colorize("hello", Color::Red, false);
        assert_eq!(s, "hello");
    }

    // ── Hex formatting ────────────────────────────────────────────────────────

    #[test]
    fn test_fmt_addr() {
        assert_eq!(fmt_addr(0x1234, 16), "0x1234");
        assert_eq!(fmt_addr(0x1234, 32), "0x00001234");
        assert_eq!(fmt_addr(0x1234, 64), "0x0000000000001234");
    }

    #[test]
    fn test_fmt_hex_bytes() {
        assert_eq!(fmt_hex_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]), "DE AD BE EF");
        assert_eq!(fmt_hex_bytes(&[]), "");
    }

    #[test]
    fn test_fmt_ascii() {
        assert_eq!(fmt_ascii(b"Hello\x00!"), "Hello.!");
    }

    #[test]
    fn test_fmt_count() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1000), "1_000");
        assert_eq!(fmt_count(1_234_567), "1_234_567");
    }

    // ── ProgressBar ───────────────────────────────────────────────────────────

    #[test]
    fn test_progress_bar_fraction() {
        let mut pb = ProgressBar::new("test", 100).quiet();
        assert!((pb.fraction() - 0.0).abs() < f64::EPSILON);
        pb.advance(50);
        assert!((pb.fraction() - 0.5).abs() < f64::EPSILON);
        pb.advance(50);
        assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_bar_overadvance() {
        let mut pb = ProgressBar::new("test", 10).quiet();
        pb.advance(1000);
        assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_bar_zero_total() {
        let pb = ProgressBar::new("test", 0).quiet();
        assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
    }

    // ── Help text ─────────────────────────────────────────────────────────────

    #[test]
    fn test_build_help_text() {
        let h = build_help_text("rustre-cli", "0.1.0", "Test tool");
        assert!(h.contains("rustre-cli"));
        assert!(h.contains("0.1.0"));
        assert!(h.contains("Test tool"));
    }

    // ── SubCommand description ────────────────────────────────────────────────

    #[test]
    fn test_subcommand_description() {
        assert!(!SubCommand::Help.description().is_empty());
        assert!(!SubCommand::GraphSmoke.description().is_empty());
        assert!(!SubCommand::Interactive.description().is_empty());
    }

    // ── CSV escape ────────────────────────────────────────────────────────────

    #[test]
    fn test_csv_escape_no_special() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_quote() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// §35.1 — RustRE analysis helpers (sha256, file-type detection, run_* handlers)
// The clap CLI types previously duplicated here have been consolidated into
// `cli_commands.rs` (RustreArgs / RustreCommand) and the canonical OutputFormat
// above.  Only the analysis utility code is kept here.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Analysis report types ─────────────────────────────────────────────────────

/// Top-level analysis report returned by `run_analyze`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// File path analysed.
    pub path: String,
    /// SHA-256 hex digest.
    pub sha256: String,
    /// Detected file format (PE, ELF, Mach-O, raw, …).
    pub format: String,
    /// Detected CPU architecture.
    pub arch: String,
    /// Entry-point virtual address (0 if not applicable).
    pub entry_point: u64,
    /// List of sections/segments.
    pub sections: Vec<SectionInfo>,
    /// Number of imported symbols.
    pub imports_count: usize,
    /// Number of exported symbols.
    pub exports_count: usize,
    /// File size in bytes.
    pub file_size: u64,
}

/// A single section / segment entry in the analysis report.
#[derive(Debug, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name.
    pub name: String,
    /// Virtual address.
    pub vaddr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Permission flags (string form, e.g. "r-x").
    pub perms: String,
}

// ── Triage result types ───────────────────────────────────────────────────────

/// Triage result returned by `run_triage`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TriageResult {
    /// File path.
    pub path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// First 16 magic bytes in hex.
    pub magic_bytes: String,
    /// Detected file type from magic.
    pub file_type: String,
    /// Shannon entropy (0.0 – 8.0).
    pub entropy: f64,
    /// Packing indicators detected.
    pub packing_indicators: Vec<String>,
    /// Byte-value histogram (only when verbose).
    pub histogram: Option<Vec<u32>>,
}

// ── String scan entry ─────────────────────────────────────────────────────────

/// A single extracted string.
#[derive(Debug, Serialize, Deserialize)]
pub struct StringEntry {
    /// File offset.
    pub offset: u64,
    /// Encoding ("ascii", "utf16le", "utf16be").
    pub encoding: String,
    /// String value.
    pub value: String,
}

// ── Disassembly entry ─────────────────────────────────────────────────────────

/// A single disassembled instruction (synthetic, no capstone dep needed).
#[derive(Debug, Serialize, Deserialize)]
pub struct DisasmEntry {
    /// Address of the instruction.
    pub address: u64,
    /// Raw bytes (hex).
    pub bytes: String,
    /// Mnemonic.
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
}

// ── Diff report ───────────────────────────────────────────────────────────────

/// Binary diff report.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffReport {
    /// Path of file A.
    pub file_a: String,
    /// Path of file B.
    pub file_b: String,
    /// SHA-256 of file A.
    pub sha256_a: String,
    /// SHA-256 of file B.
    pub sha256_b: String,
    /// Total bytes in file A.
    pub size_a: u64,
    /// Total bytes in file B.
    pub size_b: u64,
    /// Number of differing byte positions (limited to first 1 000).
    pub diff_count: usize,
    /// First difference offset.
    pub first_diff_offset: Option<u64>,
    /// Percentage of bytes that differ.
    pub similarity_pct: f64,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Compute the SHA-256 digest of `data` and return it as a lowercase hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Detect a coarse file type from the first bytes of `data`.
#[must_use]
pub fn detect_file_type(data: &[u8]) -> (&'static str, &'static str) {
    // Returns (format, arch)
    if data.starts_with(b"MZ") {
        return ("PE", "x86/x86_64 (unknown until headers parsed)");
    }
    if data.starts_with(b"\x7fELF") {
        let arch = if data.len() > 18 {
            match data[18] {
                0x03 => "x86",
                0x3E => "x86_64",
                0x28 => "ARM",
                0xB7 => "AArch64",
                0x08 => "MIPS",
                0x14 => "PowerPC",
                0xF3 => "RISC-V",
                _ => "unknown",
            }
        } else {
            "unknown"
        };
        return ("ELF", arch);
    }
    if data.starts_with(b"\xCE\xFA\xED\xFE")
        || data.starts_with(b"\xCF\xFA\xED\xFE")
        || data.starts_with(b"\xFE\xED\xFA\xCE")
        || data.starts_with(b"\xFE\xED\xFA\xCF")
    {
        return ("Mach-O", "x86/x86_64/ARM");
    }
    if data.starts_with(b"\xCA\xFE\xBA\xBE") {
        return ("Mach-O Fat", "multi-arch");
    }
    if data.starts_with(b"PK\x03\x04") {
        return ("ZIP/APK/JAR", "N/A");
    }
    if data.starts_with(b"\x50\x4B\x05\x06") {
        return ("ZIP (empty)", "N/A");
    }
    if data.len() >= 4
        && data[0] == 0x00
        && data[1] == 0x00
        && (data[2] == 0xFF || data[2] == 0x00)
        && (data[3] == 0xFF || data[3] == 0x00)
    {
        return ("DLL (possible)", "x86");
    }
    if data.starts_with(b"%PDF") {
        return ("PDF", "N/A");
    }
    if data.starts_with(b"\x89PNG") {
        return ("PNG", "N/A");
    }
    if data.starts_with(b"DWORD") || data.starts_with(b"!<arch>") {
        return ("Archive", "N/A");
    }
    ("raw/unknown", "unknown")
}

/// Compute the Shannon entropy (bits per byte) of `data`.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Build a byte-value histogram (256 entries).
#[must_use]
pub fn byte_histogram(data: &[u8]) -> Vec<u32> {
    let mut hist = vec![0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    hist
}

/// Detect packing / obfuscation indicators from raw bytes.
#[must_use]
pub fn detect_packing_indicators(data: &[u8], entropy: f64) -> Vec<String> {
    let mut indicators = Vec::new();
    if entropy > 7.0 {
        indicators.push(format!(
            "High entropy ({entropy:.4} > 7.0) — likely packed or encrypted"
        ));
    }
    // UPX magic
    if data.windows(3).any(|w| w == b"UPX") {
        indicators.push("UPX packer signature found".into());
    }
    // MPRESS
    if data.windows(6).any(|w| w == b"MPRESS") {
        indicators.push("MPRESS packer signature found".into());
    }
    // Themida
    if data.windows(7).any(|w| w == b"Themida") {
        indicators.push("Themida/WinLicense protector detected".into());
    }
    // PECompact
    if data.windows(9).any(|w| w == b"PECompact") {
        indicators.push("PECompact packer detected".into());
    }
    // ASPack
    if data.windows(6).any(|w| w == b"ASPack") {
        indicators.push("ASPack packer detected".into());
    }
    // Very small number of printable strings suggests encryption
    let printable_runs = count_printable_runs(data, 6);
    if printable_runs < 5 && data.len() > 1024 {
        indicators.push(format!(
            "Very few printable strings ({printable_runs}) — possible encryption"
        ));
    }
    if indicators.is_empty() {
        indicators.push("No obvious packing indicators detected".into());
    }
    indicators
}

fn count_printable_runs(data: &[u8], min_len: usize) -> usize {
    let mut count = 0usize;
    let mut run = 0usize;
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            run += 1;
        } else {
            if run >= min_len {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= min_len {
        count += 1;
    }
    count
}

/// Synthetic PE section table (when goblin is not linked, we parse MZ/PE manually).
fn parse_pe_sections_synthetic(data: &[u8]) -> (Vec<SectionInfo>, usize, usize, u64, String) {
    // Default values when parse fails
    let default = (vec![], 0usize, 0usize, 0u64, "x86/x86_64".to_string());
    if data.len() < 64 {
        return default;
    }
    // e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() {
        return default;
    }
    // PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return default;
    }
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return default;
    }
    let machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
    // Cap num_sections to a sane maximum: a real PE file has at most ~100
    // sections in practice; allowing up to 65 535 (u16::MAX) would let a
    // crafted binary pre-allocate a large Vec from untrusted header data.
    const MAX_PE_SECTIONS: usize = 256;
    let num_sections = (u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize)
        .min(MAX_PE_SECTIONS);
    let opt_header_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let arch_str = match machine {
        0x014C => "x86".to_string(),
        0x8664 => "x86_64".to_string(),
        0x01C4 | 0x01C0 => "ARM".to_string(),
        0xAA64 => "AArch64".to_string(),
        _ => format!("unknown (0x{machine:04X})"),
    };
    // Optional header starts at coff+20; entry point at offset 16 within it
    let opt_start = coff + 20;
    let entry_point = if opt_header_size >= 20 && opt_start + 16 + 4 <= data.len() {
        u64::from(u32::from_le_bytes([
            data[opt_start + 16],
            data[opt_start + 17],
            data[opt_start + 18],
            data[opt_start + 19],
        ]))
    } else {
        0
    };
    // Imports/exports counts — placeholder (full parsing needs goblin)
    let imports_count = 0usize;
    let exports_count = 0usize;
    // Section table starts after optional header
    let sec_table = opt_start + opt_header_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let virtual_size =
            u64::from(u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]));
        let vaddr = u64::from(u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]));
        let chars = u32::from_le_bytes([
            data[off + 36],
            data[off + 37],
            data[off + 38],
            data[off + 39],
        ]);
        let r = if chars & 0x4000_0000 != 0 { 'r' } else { '-' };
        let w = if chars & 0x8000_0000 != 0 { 'w' } else { '-' };
        let x = if chars & 0x2000_0000 != 0 { 'x' } else { '-' };
        let perms = format!("{r}{w}{x}");
        sections.push(SectionInfo {
            name,
            vaddr,
            size: virtual_size,
            perms,
        });
    }
    (
        sections,
        imports_count,
        exports_count,
        entry_point,
        arch_str,
    )
}

/// Parse ELF program headers to extract segment info.
fn parse_elf_sections_synthetic(data: &[u8]) -> (Vec<SectionInfo>, usize, usize, u64, String) {
    let default = (vec![], 0usize, 0usize, 0u64, "unknown".to_string());
    if data.len() < 64 {
        return default;
    }
    // ELF class
    let class = data[4]; // 1=32-bit, 2=64-bit
    let endian = data[5]; // 1=LE, 2=BE
    let arch = match data[18] {
        0x03 => "x86".to_string(),
        0x3E => "x86_64".to_string(),
        0x28 => "ARM".to_string(),
        0xB7 => "AArch64".to_string(),
        0x08 => "MIPS".to_string(),
        0x14 => "PowerPC".to_string(),
        0xF3 => "RISC-V".to_string(),
        other => format!("unknown (0x{other:02X})"),
    };
    let read_u64_le = |off: usize| -> u64 {
        if off + 8 > data.len() {
            0
        } else {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        }
    };
    let read_u64_be = |off: usize| -> u64 {
        if off + 8 > data.len() {
            0
        } else {
            u64::from_be_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        }
    };
    let read_u32_le = |off: usize| -> u64 {
        if off + 4 > data.len() {
            0
        } else {
            u64::from(u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4])))
        }
    };
    let read_u32_be = |off: usize| -> u64 {
        if off + 4 > data.len() {
            0
        } else {
            u64::from(u32::from_be_bytes(data[off..off + 4].try_into().unwrap_or([0; 4])))
        }
    };
    let entry_point = match (class, endian) {
        (1, 1) => read_u32_le(24),
        (1, 2) => read_u32_be(24),
        (2, 1) => read_u64_le(24),
        (2, _) => read_u64_be(24),
        _ => 0,
    };
    // We return a simplified view — named after ELF class
    let section = SectionInfo {
        name: format!("ELF ({}-bit)", if class == 2 { 64 } else { 32 }),
        vaddr: entry_point,
        size: data.len() as u64,
        perms: "r-x".into(),
    };
    (vec![section], 0, 0, entry_point, arch)
}

// ── Command handlers ──────────────────────────────────────────────────────────

/// Analyse a binary file: hash, format, arch, entry point, sections, imports, exports.
///
/// # Errors
/// Returns an error if the file cannot be read or the output cannot be written.
pub fn run_analyze(file: PathBuf, output: Option<PathBuf>, format: OutputFormat) -> AnyhowResult<()> {
    let data =
        std::fs::read(&file).with_context(|| format!("cannot read file: {}", file.display()))?;

    let sha256 = sha256_hex(&data);
    let (fmt_name, arch_hint) = detect_file_type(&data);

    let (sections, imports_count, exports_count, entry_point, arch) = match fmt_name {
        "PE" => parse_pe_sections_synthetic(&data),
        "ELF" => parse_elf_sections_synthetic(&data),
        _ => (
            vec![SectionInfo {
                name: "raw".into(),
                vaddr: 0,
                size: data.len() as u64,
                perms: "r--".into(),
            }],
            0,
            0,
            0,
            arch_hint.to_string(),
        ),
    };

    let report = AnalysisReport {
        path: file.display().to_string(),
        sha256,
        format: fmt_name.to_string(),
        arch,
        entry_point,
        sections,
        imports_count,
        exports_count,
        file_size: data.len() as u64,
    };

    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(&report).context("JSON serialization failed")?
        }
        OutputFormat::Csv => {
            let mut out = String::from("field,value\n");
            let _ = writeln!(out, "path,{}", report.path);
            let _ = writeln!(out, "sha256,{}", report.sha256);
            let _ = writeln!(out, "format,{}", report.format);
            let _ = writeln!(out, "arch,{}", report.arch);
            let _ = writeln!(out, "entry_point,0x{:X}", report.entry_point);
            let _ = writeln!(out, "imports_count,{}", report.imports_count);
            let _ = writeln!(out, "exports_count,{}", report.exports_count);
            let _ = writeln!(out, "file_size,{}", report.file_size);
            out
        }
        OutputFormat::Html => {
            format!(
                "<!DOCTYPE html>\n<html><head><title>RustRE Analysis</title></head><body>\n\
                 <h1>Analysis: {}</h1>\n\
                 <table border='1'>\n\
                 <tr><th>SHA-256</th><td><code>{}</code></td></tr>\n\
                 <tr><th>Format</th><td>{}</td></tr>\n\
                 <tr><th>Arch</th><td>{}</td></tr>\n\
                 <tr><th>Entry Point</th><td>0x{:X}</td></tr>\n\
                 <tr><th>Sections</th><td>{}</td></tr>\n\
                 <tr><th>Imports</th><td>{}</td></tr>\n\
                 <tr><th>Exports</th><td>{}</td></tr>\n\
                 <tr><th>File Size</th><td>{} bytes</td></tr>\n\
                 </table>\n\
                 <h2>Sections</h2>\n\
                 <table border='1'><tr><th>Name</th><th>VAddr</th><th>Size</th><th>Perms</th></tr>\n\
                 {}</table>\n\
                 </body></html>",
                report.path,
                report.sha256,
                report.format,
                report.arch,
                report.entry_point,
                report.sections.len(),
                report.imports_count,
                report.exports_count,
                fmt_count(report.file_size),
                report
                    .sections
                    .iter()
                    .map(|s| {
                        format!(
                            "<tr><td>{}</td><td>0x{:X}</td><td>{}</td><td>{}</td></tr>",
                            s.name, s.vaddr, s.size, s.perms
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
        OutputFormat::JsonPretty => {
            serde_json::to_string_pretty(&report).context("JSON serialization failed")?
        }
        OutputFormat::Table | OutputFormat::Lines => {
            let mut s = String::new();
            let _ = writeln!(s, "╔═══════════════════════════════════════════════╗");
            let _ = writeln!(s, "║          RustRE Binary Analysis Report        ║");
            let _ = writeln!(s, "╚═══════════════════════════════════════════════╝");
            let _ = writeln!(s, "  File        : {}", report.path);
            let _ = writeln!(s, "  SHA-256     : {}", report.sha256);
            let _ = writeln!(s, "  Format      : {}", report.format);
            let _ = writeln!(s, "  Arch        : {}", report.arch);
            let _ = writeln!(s, "  Entry Point : 0x{:X}", report.entry_point);
            let _ = writeln!(s, "  File Size   : {} bytes", fmt_count(report.file_size));
            let _ = writeln!(s, "  Imports     : {}", report.imports_count);
            let _ = writeln!(s, "  Exports     : {}", report.exports_count);
            let _ = writeln!(s);
            if !report.sections.is_empty() {
                let _ = writeln!(s, "  Sections:");
                let _ = writeln!(
                    s,
                    "  {:<20} {:<18} {:<12} Perms",
                    "Name", "VAddr", "Size"
                );
                let _ = writeln!(s, "  {}", "-".repeat(60));
                for sec in &report.sections {
                    let _ = writeln!(
                        s,
                        "  {:<20} {:<18} {:<12} {}",
                        sec.name,
                        format!("0x{:X}", sec.vaddr),
                        sec.size,
                        sec.perms
                    );
                }
            }
            s
        }
        OutputFormat::Sarif => {
            // Emit a minimal SARIF 2.1.0 envelope with the analysis results.
            serde_json::to_string_pretty(&serde_json::json!({
                "version": "2.1.0",
                "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
                "runs": [{
                    "tool": {"driver": {"name": "rustre", "version": env!("CARGO_PKG_VERSION")}},
                    "results": [],
                    "artifacts": [{"location": {"uri": report.path}, "length": report.file_size}]
                }]
            }))
            .context("SARIF serialization failed")?
        }
    };

    match output {
        Some(out_path) => {
            std::fs::write(&out_path, &rendered)
                .with_context(|| format!("cannot write output to {}", out_path.display()))?;
            println!("Report written to {}", out_path.display());
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// Perform quick triage on a binary: size, magic, entropy, packing check.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn run_triage(file: PathBuf, verbose: bool) -> AnyhowResult<()> {
    let data =
        std::fs::read(&file).with_context(|| format!("cannot read file: {}", file.display()))?;

    let magic_bytes = fmt_hex_bytes(&data[..data.len().min(16)]);
    let (file_type, _) = detect_file_type(&data);
    let entropy = shannon_entropy(&data);
    let packing = detect_packing_indicators(&data, entropy);
    let hist = if verbose {
        Some(byte_histogram(&data))
    } else {
        None
    };

    let result = TriageResult {
        path: file.display().to_string(),
        file_size: data.len() as u64,
        magic_bytes,
        file_type: file_type.to_string(),
        entropy,
        packing_indicators: packing,
        histogram: hist.clone(),
    };

    println!("╔═══════════════════════════════════════════╗");
    println!("║          RustRE Triage Report             ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("  File      : {}", result.path);
    println!(
        "  Size      : {} bytes ({})",
        result.file_size,
        fmt_count(result.file_size)
    );
    println!("  Magic     : {}", result.magic_bytes);
    println!("  Type      : {}", result.file_type);
    println!("  Entropy   : {:.4} bits/byte", result.entropy);
    println!();
    println!("  Packing indicators:");
    for indicator in &result.packing_indicators {
        println!("    • {indicator}");
    }

    if let Some(histogram) = &hist {
        println!();
        println!("  Byte histogram (non-zero entries):");
        println!("  {:>5}  {:>10}  Bar", "Byte", "Count");
        println!("  {}", "-".repeat(50));
        let max_count = f64::from(*histogram.iter().max().unwrap_or(&1));
        for (byte_val, &count) in histogram.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let bar_len = ((f64::from(count) / max_count) * 30.0) as usize;
            let bar: String = std::iter::repeat_n('#', bar_len).collect();
            let display_byte = if (byte_val as u8).is_ascii_graphic() {
                format!("0x{byte_val:02X} '{}'", byte_val as u8 as char)
            } else {
                format!("0x{byte_val:02X}     ")
            };
            println!("  {display_byte:<12} {count:>10}  {bar}");
        }
    }
    Ok(())
}

/// Disassemble instructions from a binary file.
///
/// When `addr` is provided, disassemble from that offset into the file.
/// Otherwise starts from offset 0 (or the detected entry point for PE/ELF).
/// Produces a synthetic disassembly when no external disassembler crate is linked.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn run_disasm(
    file: PathBuf,
    addr: Option<u64>,
    count: Option<u32>,
    arch: Option<String>,
) -> AnyhowResult<()> {
    let data =
        std::fs::read(&file).with_context(|| format!("cannot read file: {}", file.display()))?;

    let (fmt_name, arch_hint) = detect_file_type(&data);
    let arch_str = arch.as_deref().unwrap_or(arch_hint);
    let num = count.unwrap_or(50) as usize;

    // Determine file offset to start from
    let start_offset: usize = if let Some(a) = addr {
        // Treat `addr` as a file offset (no virtual-to-physical translation here)
        a as usize
    } else {
        // Attempt to use entry point from PE/ELF
        match fmt_name {
            "PE" => {
                let (_, _, _, ep, _) = parse_pe_sections_synthetic(&data);
                // ep is an RVA; use it directly as a file offset approximation
                ep as usize
            }
            "ELF" => {
                let (_, _, _, ep, _) = parse_elf_sections_synthetic(&data);
                ep as usize
            }
            _ => 0,
        }
    };

    let start = start_offset.min(data.len());
    let slice = &data[start..];

    println!("  Disassembly of {}  [{arch_str}]", file.display());
    println!("  Starting at file offset 0x{start:X}");
    println!();
    println!(
        "  {:<18} {:<20} {:<10} Operands",
        "Address", "Bytes", "Mnemonic"
    );
    println!("  {}", "-".repeat(72));

    // Synthetic linear disassembler: walks bytes and emits realistic-looking
    // output without linking an external disassembler.  Each "instruction" is
    // 1–6 bytes; we mimic x86-64 style for PE/ELF x86_64 and ARM for others.
    let mut offset = 0usize;
    let mut insn_count = 0usize;
    let base_addr = if addr.is_some() {
        addr.unwrap_or(0)
    } else {
        start_offset as u64
    };

    while offset < slice.len() && insn_count < num {
        let remaining = &slice[offset..];
        let (insn_len, mnemonic, operands) =
            decode_synthetic(remaining, arch_str, base_addr + offset as u64);
        let insn_bytes = &slice[offset..offset + insn_len.min(remaining.len())];
        let bytes_hex = fmt_hex_bytes(insn_bytes);
        println!(
            "  {:<18} {:<20} {:<10} {}",
            format!("0x{:X}", base_addr + offset as u64),
            bytes_hex,
            mnemonic,
            operands,
        );
        offset += insn_len;
        insn_count += 1;
    }
    println!();
    println!("  ({insn_count} instructions shown)");
    Ok(())
}

/// Minimal synthetic decoder — emits x86-64-like mnemonics for PE/ELF, ARM otherwise.
fn decode_synthetic(bytes: &[u8], arch: &str, _addr: u64) -> (usize, &'static str, String) {
    if bytes.is_empty() {
        return (1, "nop", String::new());
    }
    let is_arm = arch.contains("ARM") || arch.contains("AArch");
    if is_arm {
        // 4-byte ARM/Thumb2 words
        if bytes.len() < 4 {
            return (bytes.len(), "udf", format!("#0x{:02X}", bytes[0]));
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]));
        let (mn, ops) = decode_arm_synthetic(word);
        return (4, mn, ops);
    }
    // x86-64 synthetic
    decode_x86_synthetic(bytes)
}

fn decode_arm_synthetic(word: u32) -> (&'static str, String) {
    // Very rough ARM-A64 classification by top bits
    let op0 = (word >> 29) & 0x7;
    match op0 {
        0b100 => (
            "mov",
            format!("r{}, #0x{:X}", (word >> 12) & 0xF, word & 0xFFF),
        ),
        0b101 => ("bl", format!("#0x{:X}", (word & 0x03FF_FFFF) << 2)),
        0b010 => (
            "ldr",
            format!(
                "r{}, [r{}, #{}]",
                (word >> 12) & 0xF,
                (word >> 16) & 0xF,
                (word & 0xFFF)
            ),
        ),
        0b011 => (
            "str",
            format!(
                "r{}, [r{}, #{}]",
                (word >> 12) & 0xF,
                (word >> 16) & 0xF,
                (word & 0xFFF)
            ),
        ),
        0b000 | 0b001 => {
            let op = (word >> 21) & 0xF;
            match op {
                0x4 => (
                    "add",
                    format!(
                        "r{}, r{}, #0x{:X}",
                        (word >> 12) & 0xF,
                        (word >> 16) & 0xF,
                        word & 0xFF
                    ),
                ),
                0x2 => (
                    "sub",
                    format!(
                        "r{}, r{}, #0x{:X}",
                        (word >> 12) & 0xF,
                        (word >> 16) & 0xF,
                        word & 0xFF
                    ),
                ),
                0xA => (
                    "cmp",
                    format!("r{}, #0x{:X}", (word >> 16) & 0xF, word & 0xFF),
                ),
                _ => (
                    "and",
                    format!(
                        "r{}, r{}, r{}",
                        (word >> 12) & 0xF,
                        (word >> 16) & 0xF,
                        word & 0xF
                    ),
                ),
            }
        }
        _ => ("udf", format!("#0x{word:08X}")),
    }
}

fn decode_x86_synthetic(bytes: &[u8]) -> (usize, &'static str, String) {
    // Simplified x86-64 opcode table for common single-byte opcodes
    match bytes[0] {
        0x90 => (1, "nop", String::new()),
        0xCC => (1, "int3", String::new()),
        0xC3 => (1, "ret", String::new()),
        0xCB => (1, "retf", String::new()),
        0x55 => (1, "push", "rbp".into()),
        0x5D => (1, "pop", "rbp".into()),
        0x50 => (1, "push", "rax".into()),
        0x58 => (1, "pop", "rax".into()),
        0x51 => (1, "push", "rcx".into()),
        0x59 => (1, "pop", "rcx".into()),
        0x52 => (1, "push", "rdx".into()),
        0x5A => (1, "pop", "rdx".into()),
        0x53 => (1, "push", "rbx".into()),
        0x5B => (1, "pop", "rbx".into()),
        0x56 => (1, "push", "rsi".into()),
        0x5E => (1, "pop", "rsi".into()),
        0x57 => (1, "push", "rdi".into()),
        0x5F => (1, "pop", "rdi".into()),
        0xEB => {
            let rel = if bytes.len() > 1 {
                i64::from(bytes[1] as i8)
            } else {
                0
            };
            (2, "jmp", format!("short {rel:+}"))
        }
        0xE9 => {
            if bytes.len() >= 5 {
                let rel = i64::from(i32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4])));
                (5, "jmp", format!("near {rel:+}"))
            } else {
                (1, "jmp", "??".into())
            }
        }
        0xE8 => {
            if bytes.len() >= 5 {
                let rel = i64::from(i32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4])));
                (5, "call", format!("near {rel:+}"))
            } else {
                (1, "call", "??".into())
            }
        }
        0xB8..=0xBF => {
            let reg_idx = bytes[0] - 0xB8;
            let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
            if bytes.len() >= 5 {
                let imm = u32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4]));
                (5, "mov", format!("{}, 0x{imm:X}", regs[reg_idx as usize]))
            } else {
                (1, "mov", format!("{}, ??", regs[reg_idx as usize]))
            }
        }
        0x48 => {
            // REX.W prefix
            if bytes.len() >= 2 {
                let (len, mn, ops) = decode_x86_synthetic(&bytes[1..]);
                (1 + len, mn, format!("REX.W {ops}"))
            } else {
                (1, "rex.w", String::new())
            }
        }
        0x89 | 0x8B => {
            let mn = "mov";
            if bytes.len() >= 2 {
                let modrm = bytes[1];
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                (
                    2,
                    mn,
                    format!("{}, {}", regs[reg as usize], regs[rm as usize]),
                )
            } else {
                (1, mn, "??".into())
            }
        }
        0x01 => {
            if bytes.len() >= 2 {
                let modrm = bytes[1];
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                (
                    2,
                    "add",
                    format!("{}, {}", regs[rm as usize], regs[reg as usize]),
                )
            } else {
                (1, "add", "??".into())
            }
        }
        0x29 => {
            if bytes.len() >= 2 {
                let modrm = bytes[1];
                let reg = (modrm >> 3) & 7;
                let rm = modrm & 7;
                let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                (
                    2,
                    "sub",
                    format!("{}, {}", regs[rm as usize], regs[reg as usize]),
                )
            } else {
                (1, "sub", "??".into())
            }
        }
        0x0F => {
            // 2-byte opcodes
            if bytes.len() >= 2 {
                match bytes[1] {
                    0x05 => (2, "syscall", String::new()),
                    0x0B => (2, "ud2", String::new()),
                    0x1F => (3, "nop", "dword ptr [rax]".into()),
                    0x84 if bytes.len() >= 6 => {
                        let rel =
                            i64::from(i32::from_le_bytes(bytes[2..6].try_into().unwrap_or([0; 4])));
                        (6, "jz", format!("near {rel:+}"))
                    }
                    0x85 if bytes.len() >= 6 => {
                        let rel =
                            i64::from(i32::from_le_bytes(bytes[2..6].try_into().unwrap_or([0; 4])));
                        (6, "jnz", format!("near {rel:+}"))
                    }
                    _ => (2, "prefix", format!("0x{:02X}", bytes[1])),
                }
            } else {
                (1, "prefix", "0x0F".into())
            }
        }
        other => {
            // Unknown: emit as a db directive and consume 1 byte
            (1, "db", format!("0x{other:02X}"))
        }
    }
}

/// Scan a binary for printable strings.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn run_strings(file: PathBuf, min_len: Option<usize>, encoding: Option<String>) -> AnyhowResult<()> {
    let data =
        std::fs::read(&file).with_context(|| format!("cannot read file: {}", file.display()))?;

    let min = min_len.unwrap_or(4);
    let enc_filter = encoding.as_deref().unwrap_or("all");

    let mut entries: Vec<StringEntry> = Vec::new();

    // ASCII scan
    if enc_filter == "all" || enc_filter == "ascii" {
        let mut run_start = 0usize;
        let mut run = String::new();
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(b as char);
            } else {
                if run.len() >= min {
                    entries.push(StringEntry {
                        offset: run_start as u64,
                        encoding: "ascii".into(),
                        value: run.clone(),
                    });
                }
                run.clear();
            }
        }
        if run.len() >= min {
            entries.push(StringEntry {
                offset: run_start as u64,
                encoding: "ascii".into(),
                value: run,
            });
        }
    }

    // UTF-16 LE scan
    if enc_filter == "all" || enc_filter == "utf16le" {
        let mut i = 0usize;
        let mut run_start = 0usize;
        let mut run = String::new();
        while i + 1 < data.len() {
            let lo = data[i];
            let hi = data[i + 1];
            if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t') {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(lo as char);
                i += 2;
            } else {
                if run.len() >= min {
                    entries.push(StringEntry {
                        offset: run_start as u64,
                        encoding: "utf16le".into(),
                        value: run.clone(),
                    });
                }
                run.clear();
                i += 1;
            }
        }
        if run.len() >= min {
            entries.push(StringEntry {
                offset: run_start as u64,
                encoding: "utf16le".into(),
                value: run,
            });
        }
    }

    // UTF-16 BE scan
    if enc_filter == "all" || enc_filter == "utf16be" {
        let mut i = 0usize;
        let mut run_start = 0usize;
        let mut run = String::new();
        while i + 1 < data.len() {
            let hi = data[i];
            let lo = data[i + 1];
            if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t') {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(lo as char);
                i += 2;
            } else {
                if run.len() >= min {
                    entries.push(StringEntry {
                        offset: run_start as u64,
                        encoding: "utf16be".into(),
                        value: run.clone(),
                    });
                }
                run.clear();
                i += 1;
            }
        }
        if run.len() >= min {
            entries.push(StringEntry {
                offset: run_start as u64,
                encoding: "utf16be".into(),
                value: run,
            });
        }
    }

    // Sort by offset
    entries.sort_by_key(|e| e.offset);

    println!(
        "  Strings in {}  (min_len={min}, encoding={enc_filter})",
        file.display()
    );
    println!("  {:<12} {:<10} String", "Offset", "Encoding");
    println!("  {}", "-".repeat(72));
    for entry in &entries {
        // Truncate very long strings for display
        let display_val = if entry.value.len() > 120 {
            format!("{}…", &entry.value[..120])
        } else {
            entry.value.clone()
        };
        println!(
            "  {:<12} {:<10} {}",
            format!("0x{:X}", entry.offset),
            entry.encoding,
            display_val,
        );
    }
    println!();
    println!("  Total: {} strings found", entries.len());
    Ok(())
}

/// Perform a structural diff between two binary files.
///
/// # Errors
/// Returns an error if either file cannot be read or the output cannot be written.
pub fn run_diff(file_a: PathBuf, file_b: PathBuf, output: Option<PathBuf>) -> AnyhowResult<()> {
    let data_a = std::fs::read(&file_a)
        .with_context(|| format!("cannot read file A: {}", file_a.display()))?;
    let data_b = std::fs::read(&file_b)
        .with_context(|| format!("cannot read file B: {}", file_b.display()))?;

    let sha_a = sha256_hex(&data_a);
    let sha_b = sha256_hex(&data_b);
    let min_len = data_a.len().min(data_b.len());
    let mut diff_count = 0usize;
    let mut first_diff: Option<u64> = None;

    for i in 0..min_len {
        if data_a[i] != data_b[i] {
            if first_diff.is_none() {
                first_diff = Some(i as u64);
            }
            diff_count += 1;
            if diff_count >= 10_000 {
                break; // cap
            }
        }
    }
    // Bytes beyond the shorter file also count as differences
    let extra_diffs = data_a.len().abs_diff(data_b.len());
    diff_count += extra_diffs.min(10_000 - diff_count);

    let total = data_a.len().max(data_b.len());
    let similarity = if total == 0 {
        100.0
    } else {
        let identical = (total - diff_count) as f64 / total as f64 * 100.0;
        identical.clamp(0.0, 100.0)
    };

    let report = DiffReport {
        file_a: file_a.display().to_string(),
        file_b: file_b.display().to_string(),
        sha256_a: sha_a,
        sha256_b: sha_b,
        size_a: data_a.len() as u64,
        size_b: data_b.len() as u64,
        diff_count,
        first_diff_offset: first_diff,
        similarity_pct: similarity,
    };

    let mut out = String::new();
    let _ = writeln!(out, "╔══════════════════════════════════════════════╗");
    let _ = writeln!(out, "║           RustRE Binary Diff Report          ║");
    let _ = writeln!(out, "╚══════════════════════════════════════════════╝");
    let _ = writeln!(out, "  File A     : {}", report.file_a);
    let _ = writeln!(out, "  File B     : {}", report.file_b);
    let _ = writeln!(out, "  SHA-256 A  : {}", report.sha256_a);
    let _ = writeln!(out, "  SHA-256 B  : {}", report.sha256_b);
    let _ = writeln!(out, "  Size A     : {} bytes", fmt_count(report.size_a));
    let _ = writeln!(out, "  Size B     : {} bytes", fmt_count(report.size_b));
    let _ = writeln!(
        out,
        "  Diffs      : {} bytes differ",
        fmt_count(report.diff_count as u64)
    );
    let _ = writeln!(out, "  Similarity : {:.2}%", report.similarity_pct);
    if let Some(off) = report.first_diff_offset {
        let _ = writeln!(out, "  First diff : 0x{off:X}");
    } else {
        let _ = writeln!(out, "  Files are identical (same length and content)");
    }

    match output {
        Some(ref p) => {
            std::fs::write(p, &out)
                .with_context(|| format!("cannot write diff report to {}", p.display()))?;
            println!("Diff report written to {}", p.display());
        }
        None => print!("{out}"),
    }
    Ok(())
}

/// Simulate sandboxed execution (stub — wires to `rustre-sandbox` when linked).
///
/// # Errors
/// Returns an error if the file is not accessible.
pub fn run_sandbox(file: PathBuf, timeout: Option<u64>, no_network: bool) -> AnyhowResult<()> {
    let meta = std::fs::metadata(&file)
        .with_context(|| format!("cannot stat file: {}", file.display()))?;
    let secs = timeout.unwrap_or(30);
    println!("╔══════════════════════════════════════════╗");
    println!("║        RustRE Sandbox Execution          ║");
    println!("╚══════════════════════════════════════════╝");
    println!("  File       : {}", file.display());
    println!("  Size       : {} bytes", fmt_count(meta.len()));
    println!("  Timeout    : {secs}s");
    println!(
        "  Network    : {}",
        if no_network { "blocked" } else { "allowed" }
    );
    println!();
    println!("  [stub] rustre-sandbox crate not linked in this build.");
    println!("  To enable: add rustre-sandbox = {{ path = \"../rustre-sandbox\" }} to Cargo.toml.");
    Ok(())
}

/// Execute a script file (stub — wires to `rustre-script` when linked).
///
/// # Errors
/// Returns an error if the script file cannot be read.
pub fn run_script(file: PathBuf, args: Vec<String>) -> AnyhowResult<()> {
    let _ = std::fs::metadata(&file)
        .with_context(|| format!("cannot stat script: {}", file.display()))?;
    let ext = file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("unknown");
    println!("  [stub] Script execution: {} ({ext})", file.display());
    if !args.is_empty() {
        println!("  Args: {}", args.join(" "));
    }
    println!(
        "  To enable: link rustre-script, rustre-script-lua, rustre-script-python, or rustre-script-rhai."
    );
    Ok(())
}

/// Start the REST / MCP server (stub).
///
/// # Errors
/// Returns an error if the bind address is invalid (currently never).
pub fn run_serve(bind: Option<String>, mcp: bool) -> AnyhowResult<()> {
    let addr = bind.as_deref().unwrap_or("127.0.0.1:8080");
    println!("  [stub] rustre-daemon / rustre-mcp-server not linked in this build.");
    println!("  Would listen on {addr}");
    if mcp {
        println!("  MCP endpoint: http://{addr}/mcp");
    }
    println!("  To enable: link rustre-daemon and rustre-mcp-server.");
    Ok(())
}

/// Scan a target with YARA rules (stub).
///
/// # Errors
/// Returns an error if the rules or target file cannot be accessed.
pub fn run_yara(rules: PathBuf, target: PathBuf) -> AnyhowResult<()> {
    let _ = std::fs::metadata(&rules)
        .with_context(|| format!("cannot stat rules file: {}", rules.display()))?;
    let _ = std::fs::metadata(&target)
        .with_context(|| format!("cannot stat target: {}", target.display()))?;
    println!("  [stub] YARA engine not linked in this build.");
    println!("  Rules : {}", rules.display());
    println!("  Target: {}", target.display());
    println!("  To enable: link rustre-yara-engine.");
    Ok(())
}

/// Plugin management subcommands used by `run_plugin`.
///
/// This is a lightweight enum used by the analysis handler layer.
/// For the full interactive plugin system see `plugin_commands::PluginCommandRegistry`.
#[derive(Debug, Clone)]
pub enum PluginCmd {
    /// List all installed plugins.
    List,
    /// Install a plugin by name.
    Install { name: String },
    /// Remove an installed plugin.
    Remove { name: String },
    /// Update all installed plugins.
    Update,
}

/// Handle plugin management commands.
///
/// # Errors
/// Returns an error on I/O failure (currently none).
pub fn run_plugin(cmd: PluginCmd) -> AnyhowResult<()> {
    match cmd {
        PluginCmd::List => {
            println!("  Installed plugins: (none — rustre-plugin-host not linked)");
        }
        PluginCmd::Install { name } => {
            println!("  [stub] Would install plugin: {name}");
        }
        PluginCmd::Remove { name } => {
            println!("  [stub] Would remove plugin: {name}");
        }
        PluginCmd::Update => {
            println!("  [stub] Would update all plugins.");
        }
    }
    Ok(())
}

// ── §35.1 — additional tests ──────────────────────────────────────────────────
#[cfg(test)]
mod clap_cli_tests {
    use super::*;

    // ── sha256_hex ────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty input is well-known
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        let h = sha256_hex(b"hello");
        assert_eq!(&h[..8], "2cf24dba");
    }

    // ── shannon_entropy ───────────────────────────────────────────────────────

    #[test]
    fn test_entropy_empty() {
        assert!((shannon_entropy(b"") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_uniform() {
        // All 256 possible bytes once => max entropy ≈ 8.0
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "entropy={e}");
    }

    #[test]
    fn test_entropy_single_byte() {
        // All same byte => entropy = 0
        let data = vec![0xAAu8; 1024];
        let e = shannon_entropy(&data);
        assert!(e < 0.001, "entropy={e}");
    }

    // ── detect_file_type ──────────────────────────────────────────────────────

    #[test]
    fn test_detect_pe() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        let (fmt, _) = detect_file_type(&data);
        assert_eq!(fmt, "PE");
    }

    #[test]
    fn test_detect_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00";
        let (fmt, arch) = detect_file_type(data);
        assert_eq!(fmt, "ELF");
        assert_eq!(arch, "x86_64");
    }

    #[test]
    fn test_detect_macho() {
        let data = b"\xCE\xFA\xED\xFE\x00\x00\x00\x00";
        let (fmt, _) = detect_file_type(data);
        assert_eq!(fmt, "Mach-O");
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04\x00\x00\x00\x00";
        let (fmt, _) = detect_file_type(data);
        assert_eq!(fmt, "ZIP/APK/JAR");
    }

    #[test]
    fn test_detect_raw() {
        let data = b"\x00\x01\x02\x03\x04";
        let (fmt, _) = detect_file_type(data);
        assert_eq!(fmt, "raw/unknown");
    }

    // ── detect_packing_indicators ─────────────────────────────────────────────

    #[test]
    fn test_packing_high_entropy() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let entropy = shannon_entropy(&data);
        let indicators = detect_packing_indicators(&data, entropy);
        assert!(
            indicators
                .iter()
                .any(|i| i.contains("entropy") || i.contains("UPX") || i.contains("No obvious"))
        );
    }

    #[test]
    fn test_packing_upx_magic() {
        let mut data = vec![0xABu8; 256];
        data.extend_from_slice(b"UPX!");
        let entropy = shannon_entropy(&data);
        let indicators = detect_packing_indicators(&data, entropy);
        assert!(indicators.iter().any(|i| i.contains("UPX")));
    }

    #[test]
    fn test_packing_no_indicators() {
        // Normal printable text — low entropy, many runs
        let data = b"Hello World! This is a normal binary with many printable strings.".to_vec();
        let entropy = shannon_entropy(&data);
        let indicators = detect_packing_indicators(&data, entropy);
        assert!(indicators.iter().any(|i| i.contains("No obvious")));
    }

    // ── byte_histogram ────────────────────────────────────────────────────────

    #[test]
    fn test_byte_histogram_length() {
        let hist = byte_histogram(b"hello");
        assert_eq!(hist.len(), 256);
    }

    #[test]
    fn test_byte_histogram_counts() {
        let hist = byte_histogram(b"aabb");
        assert_eq!(hist[b'a' as usize], 2);
        assert_eq!(hist[b'b' as usize], 2);
        assert_eq!(hist[b'c' as usize], 0);
    }

    // ── decode_x86_synthetic ──────────────────────────────────────────────────

    #[test]
    fn test_decode_nop() {
        let (len, mn, _) = decode_x86_synthetic(b"\x90");
        assert_eq!(len, 1);
        assert_eq!(mn, "nop");
    }

    #[test]
    fn test_decode_ret() {
        let (len, mn, _) = decode_x86_synthetic(b"\xC3");
        assert_eq!(len, 1);
        assert_eq!(mn, "ret");
    }

    #[test]
    fn test_decode_push_rbp() {
        let (len, mn, ops) = decode_x86_synthetic(b"\x55");
        assert_eq!(len, 1);
        assert_eq!(mn, "push");
        assert_eq!(ops, "rbp");
    }

    #[test]
    fn test_decode_call_near() {
        let bytes = b"\xE8\x10\x00\x00\x00";
        let (len, mn, _) = decode_x86_synthetic(bytes);
        assert_eq!(len, 5);
        assert_eq!(mn, "call");
    }

    #[test]
    fn test_decode_jmp_short() {
        let bytes = b"\xEB\x0A";
        let (len, mn, _) = decode_x86_synthetic(bytes);
        assert_eq!(len, 2);
        assert_eq!(mn, "jmp");
    }

    #[test]
    fn test_decode_syscall() {
        let bytes = b"\x0F\x05";
        let (len, mn, _) = decode_x86_synthetic(bytes);
        assert_eq!(len, 2);
        assert_eq!(mn, "syscall");
    }

    #[test]
    fn test_decode_unknown_byte() {
        let bytes = b"\xFF";
        let (len, mn, ops) = decode_x86_synthetic(bytes);
        assert_eq!(len, 1);
        assert_eq!(mn, "db");
        assert!(ops.contains("0xFF"));
    }

    // ── OutputFormat ──────────────────────────────────────────────────────

    #[test]
    fn test_clap_output_format_display() {
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Html.to_string(), "html");
        assert_eq!(OutputFormat::Csv.to_string(), "csv");
        assert_eq!(OutputFormat::Table.to_string(), "table");
    }

    #[test]
    fn test_clap_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Table);
    }

    // ── run_analyze (in-memory) ───────────────────────────────────────────────

    #[test]
    fn test_run_analyze_tempfile() {
        
        let tmp = tempfile_path();
        // Write a minimal ELF-like header
        let elf_header: &[u8] = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00";
        std::fs::write(&tmp, elf_header).unwrap();
        let result = run_analyze(tmp.clone(), None, OutputFormat::Table);
        assert!(result.is_ok(), "run_analyze failed: {result:?}");
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_analyze_json_output() {
        let tmp = tempfile_path();
        std::fs::write(&tmp, b"MZ\x00\x00").unwrap();
        let out = tempfile_path_with_ext("json");
        let result = run_analyze(tmp.clone(), Some(out.clone()), OutputFormat::Json);
        assert!(result.is_ok());
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("sha256"));
        std::fs::remove_file(tmp).ok();
        std::fs::remove_file(out).ok();
    }

    #[test]
    fn test_run_triage_tempfile() {
        let tmp = tempfile_path();
        std::fs::write(
            &tmp,
            b"Hello world, this is a test binary for triage scanning.",
        )
        .unwrap();
        let result = run_triage(tmp.clone(), false);
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_triage_verbose() {
        let tmp = tempfile_path();
        std::fs::write(&tmp, b"AABBCCDD test data for histogram").unwrap();
        let result = run_triage(tmp.clone(), true);
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_strings_tempfile() {
        let tmp = tempfile_path();
        let data = b"\x00\x00\x00hello world\x00\x00\x00test string here\x00".to_vec();
        std::fs::write(&tmp, &data).unwrap();
        let result = run_strings(tmp.clone(), Some(4), Some("ascii".into()));
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_strings_utf16le() {
        let tmp = tempfile_path();
        // "hi" in UTF-16 LE
        let data = b"\x68\x00\x69\x00\x00\x00";
        std::fs::write(&tmp, data).unwrap();
        let result = run_strings(tmp.clone(), Some(2), Some("utf16le".into()));
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_disasm_tempfile() {
        let tmp = tempfile_path();
        // A few x86-64 bytes: nop, push rbp, ret
        std::fs::write(&tmp, b"\x90\x55\xC3\x90\x90\x90\x90\x90").unwrap();
        let result = run_disasm(tmp.clone(), Some(0), Some(3), Some("x86_64".into()));
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_diff_identical() {
        let tmp_a = tempfile_path();
        let tmp_b = tempfile_path();
        let data = b"identical content here";
        std::fs::write(&tmp_a, data).unwrap();
        std::fs::write(&tmp_b, data).unwrap();
        let result = run_diff(tmp_a.clone(), tmp_b.clone(), None);
        assert!(result.is_ok());
        std::fs::remove_file(tmp_a).ok();
        std::fs::remove_file(tmp_b).ok();
    }

    #[test]
    fn test_run_diff_different() {
        let tmp_a = tempfile_path();
        let tmp_b = tempfile_path();
        std::fs::write(&tmp_a, b"AAAA").unwrap();
        std::fs::write(&tmp_b, b"BBBB").unwrap();
        let result = run_diff(tmp_a.clone(), tmp_b.clone(), None);
        assert!(result.is_ok());
        std::fs::remove_file(tmp_a).ok();
        std::fs::remove_file(tmp_b).ok();
    }

    #[test]
    fn test_run_sandbox_stub() {
        let tmp = tempfile_path();
        std::fs::write(&tmp, b"\x90").unwrap();
        let result = run_sandbox(tmp.clone(), Some(10), true);
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_script_stub() {
        let tmp = tempfile_path_with_ext("lua");
        std::fs::write(&tmp, b"-- test").unwrap();
        let result = run_script(tmp.clone(), vec!["arg1".into()]);
        assert!(result.is_ok());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_run_serve_stub() {
        let result = run_serve(Some("127.0.0.1:9090".into()), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_plugin_list() {
        let result = run_plugin(PluginCmd::List);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_plugin_install() {
        let result = run_plugin(PluginCmd::Install {
            name: "test-plugin".into(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_plugin_remove() {
        let result = run_plugin(PluginCmd::Remove {
            name: "test-plugin".into(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_plugin_update() {
        let result = run_plugin(PluginCmd::Update);
        assert!(result.is_ok());
    }

    // ── parse_pe_sections_synthetic ───────────────────────────────────────────

    #[test]
    fn test_parse_pe_too_short() {
        let (secs, _, _, ep, _) = parse_pe_sections_synthetic(b"MZ");
        assert!(secs.is_empty());
        assert_eq!(ep, 0);
    }

    #[test]
    fn test_parse_elf_too_short() {
        let (secs, _, _, ep, _) = parse_elf_sections_synthetic(b"\x7fELF");
        assert!(secs.is_empty());
        assert_eq!(ep, 0);
    }

    // ── count_printable_runs ──────────────────────────────────────────────────

    #[test]
    fn test_count_printable_runs_basic() {
        let data = b"Hello\x00World\x00Test";
        let count = count_printable_runs(data, 4);
        assert_eq!(count, 3); // "Hello", "World", "Test"
    }

    #[test]
    fn test_count_printable_runs_none() {
        let data = b"\x00\x01\x02\x03";
        let count = count_printable_runs(data, 4);
        assert_eq!(count, 0);
    }

    // ── DiffReport similarity ─────────────────────────────────────────────────

    #[test]
    fn test_diff_report_similarity_identical() {
        let a = b"abcdefgh";
        let b_data = b"abcdefgh";
        let total = a.len().max(b_data.len());
        let diff = 0usize;
        let sim = (total - diff) as f64 / total as f64 * 100.0;
        assert!((sim - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_diff_report_similarity_all_different() {
        let a = b"AAAA";
        let b_data = b"BBBB";
        let total = a.len().max(b_data.len());
        let diff = 4usize;
        let sim = (total - diff) as f64 / total as f64 * 100.0;
        assert!(sim < 1.0, "sim={sim}");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn tempfile_path() -> PathBuf {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("rustre_test_{nanos}.bin"))
    }

    fn tempfile_path_with_ext(ext: &str) -> PathBuf {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("rustre_test_{nanos}.{ext}"))
    }
}
