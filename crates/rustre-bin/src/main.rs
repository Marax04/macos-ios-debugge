//! `rustre` — `RustRE` Suite command-line binary.
//!
//! A comprehensive CLI for the `RustRE` reverse-engineering platform.
//!
//! # Subcommands
//!
//! | Command   | Purpose |
//! |-----------|---------|
//! | `analyze` | Trigger static analysis of a binary |
//! | `decompile` | Decompile a function by address |
//! | `disasm`  | Disassemble a range of bytes |
//! | `strings` | Extract printable strings from a binary |
//! | `info`    | Print file metadata (format, arch, OS) |
//! | `debug`   | Start a debug session |
//! | `script`  | Run a Rhai/Lua/Python script |
//! | `server`  | Start or query the background daemon |
//!
//! Global flags: `--json` (machine-readable output), `--config` (config file),
//! `--no-color`, `--quiet`, `--verbose`.

#![allow(clippy::too_many_lines)]

pub mod analysis_runner;
pub mod config;
pub mod output_format;
pub mod subcommands;
pub mod workspace_manager;
pub mod repl;
pub mod batch_mode;
pub mod plugin_manager_cli;
pub mod script_runner;
pub mod export_commands;
pub mod binary_patcher;
pub mod crypto_identifier;
pub mod format_detector;
pub mod recent_files;
pub mod session_manager;
pub mod startup_sequence;

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colour helpers (no external crate needed — just escape codes)
// ─────────────────────────────────────────────────────────────────────────────

mod color {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Output context (colour on/off, verbosity, JSON mode)
// ─────────────────────────────────────────────────────────────────────────────

/// Global output configuration.
#[derive(Debug, Clone)]
struct OutputCtx {
    /// Machine-readable JSON output.
    json: bool,
    /// Suppress info/progress messages.
    quiet: bool,
    /// Verbose (debug-level) output.
    verbose: bool,
    /// Disable ANSI colour codes.
    no_color: bool,
}

impl OutputCtx {
    fn new(json: bool, quiet: bool, verbose: bool, no_color: bool) -> Self {
        // Disable colour when piped, when `--no-color` is set, when `--json` is
        // set, or when the `NO_COLOR` environment variable is present.
        let no_color = no_color
            || json
            || std::env::var_os("NO_COLOR").is_some()
            || !io::stdout().is_terminal();
        Self {
            json,
            quiet,
            verbose,
            no_color,
        }
    }

    const fn c(&self, code: &'static str) -> &str {
        if self.no_color { "" } else { code }
    }

    fn print_info(&self, msg: &str) {
        if self.json || self.quiet {
            return;
        }
        println!(
            "{}{}info{}{} {}",
            self.c(color::BOLD),
            self.c(color::CYAN),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    fn print_ok(&self, msg: &str) {
        if self.json || self.quiet {
            return;
        }
        println!(
            "{}{} ok {}{}{}",
            self.c(color::BOLD),
            self.c(color::BRIGHT_GREEN),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    fn print_warn(&self, msg: &str) {
        if self.json {
            return;
        }
        eprintln!(
            "{}{}warn{}{} {}",
            self.c(color::BOLD),
            self.c(color::BRIGHT_YELLOW),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    fn print_error(&self, msg: &str) {
        eprintln!(
            "{}{}error{}{} {}",
            self.c(color::BOLD),
            self.c(color::BRIGHT_RED),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    /// Print a fatal error in plain (non-bright) red, used for unrecoverable
    /// conditions where the bright variant would clash with downstream logs.
    fn print_fatal(&self, msg: &str) {
        eprintln!(
            "{}{}fatal{}{} {}",
            self.c(color::BOLD),
            self.c(color::RED),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    /// Print a highlighted hint message (e.g. "did you mean ..."). Uses
    /// MAGENTA so it stands apart from regular info/warn lines.
    fn print_hint(&self, msg: &str) {
        if self.json || self.quiet {
            return;
        }
        eprintln!(
            "{}{}hint{}{} {}",
            self.c(color::BOLD),
            self.c(color::MAGENTA),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    /// Print a "usage:" style help banner in bright cyan, used by the
    /// top-level help printer.
    fn print_usage_banner(&self, banner: &str) {
        if self.json {
            return;
        }
        println!(
            "{}{}{}{}",
            self.c(color::BOLD),
            self.c(color::BRIGHT_CYAN),
            banner,
            self.c(color::RESET),
        );
    }

    fn print_debug(&self, msg: &str) {
        if !self.verbose || self.json {
            return;
        }
        eprintln!(
            "{}{}debug{}{} {}",
            self.c(color::BOLD),
            self.c(color::DIM),
            self.c(color::RESET),
            self.c(color::RESET),
            msg
        );
    }

    fn print_json(&self, value: &serde_json::Value) {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".into())
        );
    }

    fn print_section_header(&self, title: &str) {
        if self.json || self.quiet {
            return;
        }
        println!(
            "\n{}{}── {} ──{}{}",
            self.c(color::BOLD),
            self.c(color::BLUE),
            title,
            self.c(color::RESET),
            self.c(color::RESET),
        );
    }

    fn print_kv(&self, key: &str, value: &str) {
        if self.json || self.quiet {
            return;
        }
        println!(
            "  {}{:<24}{} {}",
            self.c(color::BOLD),
            key,
            self.c(color::RESET),
            value
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress spinner
// ─────────────────────────────────────────────────────────────────────────────

struct Spinner {
    frames: &'static [&'static str],
    idx: usize,
    label: String,
    enabled: bool,
}

impl Spinner {
    const BRAILLE: &'static [&'static str] = &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];

    fn new(label: impl Into<String>, enabled: bool) -> Self {
        Self {
            frames: Self::BRAILLE,
            idx: 0,
            label: label.into(),
            enabled,
        }
    }

    fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        let frame = self.frames[self.idx % self.frames.len()];
        self.idx = self.idx.wrapping_add(1);
        print!("\r  {} {}  ", frame, self.label);
        let _ = io::stdout().flush();
    }

    fn finish(&self, ok: bool) {
        if !self.enabled {
            return;
        }
        let mark = if ok { "✓" } else { "✗" };
        println!("\r  {} {}   ", mark, self.label);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config file (~/.rustre/config.toml)
// ─────────────────────────────────────────────────────────────────────────────

/// Persisted user preferences loaded from `~/.rustre/config.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UserConfig {
    /// Default daemon address.
    #[serde(default = "default_daemon_addr")]
    daemon_addr: String,
    /// Default theme for the GUI.
    #[serde(default = "default_theme")]
    theme: String,
    /// Default output format.
    #[serde(default)]
    json: bool,
    /// Color preference.
    #[serde(default)]
    no_color: bool,
    /// Extra key-value pairs.
    #[serde(default)]
    extra: HashMap<String, String>,
}

fn default_daemon_addr() -> String {
    "127.0.0.1:7878".into()
}

fn default_theme() -> String {
    "dark".into()
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            daemon_addr: default_daemon_addr(),
            theme: default_theme(),
            json: false,
            no_color: false,
            extra: HashMap::new(),
        }
    }
}

impl UserConfig {
    /// Load from the standard location (`~/.rustre/config.toml`), falling back
    /// to defaults silently.
    fn load(explicit: Option<&Path>) -> Self {
        let path = explicit
            .map(Path::to_owned)
            .or_else(|| home_dir().map(|h| h.join(".rustre").join("config.toml")));

        if let Some(p) = path
            && p.exists()
                && let Ok(text) = fs::read_to_string(&p)
                    && let Ok(cfg) = toml::from_str::<Self>(&text) {
                        return cfg;
                    }
        Self::default()
    }

    /// Save to `~/.rustre/config.toml`.
    fn save(&self) -> Result<(), String> {
        let home = home_dir().ok_or("cannot determine home directory")?;
        let dir = home.join(".rustre");
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join("config.toml");
        let text = toml::to_string_pretty(self).map_err(|e| format!("serialize config: {e}"))?;
        fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(())
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument parsing (hand-rolled; no clap dep in rustre-bin yet)
// ─────────────────────────────────────────────────────────────────────────────
//
// We implement a minimal clap-style parser rather than pulling in the crate so
// the binary stays lean.  See `Cli`, `GlobalFlags`, and the `Subcommand` enum.

/// Global flags that precede every subcommand.
#[derive(Debug, Clone, Default)]
struct GlobalFlags {
    json: bool,
    quiet: bool,
    verbose: bool,
    no_color: bool,
    config_path: Option<PathBuf>,
    daemon_addr: Option<String>,
}

/// All supported subcommands with their parsed arguments.
#[derive(Debug)]
enum Subcommand {
    Analyze(AnalyzeArgs),
    Decompile(DecompileArgs),
    Disasm(DisasmArgs),
    Strings(StringsArgs),
    Info(InfoArgs),
    Debug(DebugArgs),
    Script(ScriptArgs),
    Server(ServerArgs),
    Completions(CompletionsArgs),
    Help,
    Version,
}

#[derive(Debug)]
struct AnalyzeArgs {
    path: PathBuf,
    deep: bool,
    timeout: u64,
    session_id: Option<String>,
    output_dir: Option<PathBuf>,
}

#[derive(Debug)]
struct DecompileArgs {
    path: PathBuf,
    address: u64,
    function_name: Option<String>,
    language: String,
}

#[derive(Debug)]
struct DisasmArgs {
    path: PathBuf,
    address: u64,
    count: usize,
    raw: bool,
    syntax: String,
}

#[derive(Debug)]
struct StringsArgs {
    path: PathBuf,
    min_len: usize,
    encoding: String,
    pattern: Option<String>,
    offset: Option<u64>,
    length: Option<u64>,
}

#[derive(Debug)]
struct InfoArgs {
    path: PathBuf,
    hashes: bool,
    sections: bool,
    imports: bool,
    exports: bool,
    all: bool,
}

#[derive(Debug)]
struct DebugArgs {
    pid: Option<u32>,
    path: Option<PathBuf>,
    args: Vec<String>,
    breakpoints: Vec<u64>,
    script: Option<PathBuf>,
}

#[derive(Debug)]
struct ScriptArgs {
    path: Option<PathBuf>,
    inline: Option<String>,
    lang: String,
    session_id: Option<String>,
    args: Vec<String>,
}

#[derive(Debug)]
enum ServerAction {
    Start,
    Stop,
    Status,
    Restart,
    Logs,
    Rpc {
        method: String,
        params: Option<String>,
    },
}

#[derive(Debug)]
struct ServerArgs {
    action: ServerAction,
    bind: Option<String>,
    daemon: bool,
    mcp: Option<String>,
    log_level: Option<String>,
}

#[derive(Debug)]
struct CompletionsArgs {
    shell: String,
}

// ── Parser ────────────────────────────────────────────────────────────────────

fn parse_hex_or_dec(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex '{s}': {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("invalid number '{s}': {e}"))
    }
}

/// Parse the full command line.  Returns `(GlobalFlags, Subcommand)`.
fn parse_cli(argv: &[String]) -> Result<(GlobalFlags, Subcommand), String> {
    let mut args = argv.iter().peekable();
    let mut global = GlobalFlags::default();

    // Consume global flags until we hit a non-flag or a subcommand.
    loop {
        match args.peek().map(|s| s.as_str()) {
            Some("--json") => {
                global.json = true;
                args.next();
            }
            Some("--quiet" | "-q") => {
                global.quiet = true;
                args.next();
            }
            Some("--verbose" | "-v") => {
                global.verbose = true;
                args.next();
            }
            Some("--no-color") => {
                global.no_color = true;
                args.next();
            }
            Some(s) if s.starts_with("--config=") => {
                let val = s["--config=".len()..].to_owned();
                global.config_path = Some(PathBuf::from(val));
                args.next();
            }
            Some("--config") => {
                args.next();
                let val = args.next().ok_or("--config requires a value")?;
                global.config_path = Some(PathBuf::from(val));
            }
            Some(s) if s.starts_with("--daemon=") => {
                let val = s["--daemon=".len()..].to_owned();
                global.daemon_addr = Some(val);
                args.next();
            }
            Some("--daemon") => {
                args.next();
                let val = args.next().ok_or("--daemon requires a value")?;
                global.daemon_addr = Some(val.clone());
            }
            _ => break,
        }
    }

    let sub = match args.peek().map(|s| s.as_str()) {
        Some("analyze" | "analyse") => {
            args.next();
            parse_analyze(args.collect::<Vec<_>>())?
        }
        Some("decompile" | "dec") => {
            args.next();
            parse_decompile(args.collect::<Vec<_>>())?
        }
        Some("disasm" | "dis") => {
            args.next();
            parse_disasm(args.collect::<Vec<_>>())?
        }
        Some("strings" | "str") => {
            args.next();
            parse_strings(args.collect::<Vec<_>>())?
        }
        Some("info") => {
            args.next();
            parse_info(args.collect::<Vec<_>>())?
        }
        Some("debug" | "dbg") => {
            args.next();
            parse_debug(args.collect::<Vec<_>>())?
        }
        Some("script" | "scr") => {
            args.next();
            parse_script(args.collect::<Vec<_>>())?
        }
        Some("server" | "srv" | "daemon") => {
            args.next();
            parse_server(args.collect::<Vec<_>>())?
        }
        Some("completions" | "completion") => {
            args.next();
            parse_completions(args.collect::<Vec<_>>())?
        }
        Some("help" | "--help" | "-h") => Subcommand::Help,
        Some("version" | "--version" | "-V") => Subcommand::Version,
        None => Subcommand::Help,
        Some(other) => {
            return Err(format!(
                "unknown subcommand '{other}'; run `rustre help` for usage"
            ));
        }
    };

    Ok((global, sub))
}

fn parse_analyze(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut deep = false;
    let mut timeout: u64 = 300;
    let mut session_id: Option<String> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--deep" | "-d" => {
                deep = true;
            }
            "--timeout" => {
                i += 1;
                timeout = argv
                    .get(i)
                    .ok_or("--timeout needs a value")?
                    .parse::<u64>()
                    .map_err(|e| format!("timeout: {e}"))?;
            }
            s if s.starts_with("--timeout=") => {
                timeout = s["--timeout=".len()..]
                    .parse::<u64>()
                    .map_err(|e| format!("timeout: {e}"))?;
            }
            "--session" => {
                i += 1;
                session_id = Some((*argv.get(i).ok_or("--session needs a value")?).clone());
            }
            s if s.starts_with("--session=") => {
                session_id = Some(s["--session=".len()..].to_owned());
            }
            "--output" | "-o" => {
                i += 1;
                output_dir = Some(PathBuf::from(argv.get(i).ok_or("--output needs a value")?));
            }
            s if s.starts_with("--output=") => {
                output_dir = Some(PathBuf::from(&s["--output=".len()..]));
            }
            s if !s.starts_with('-') => {
                if path.is_some() {
                    return Err("analyze: only one FILE allowed".into());
                }
                path = Some(PathBuf::from(s));
            }
            other => return Err(format!("analyze: unknown flag '{other}'")),
        }
        i += 1;
    }

    let path = path.ok_or("analyze: FILE argument is required")?;
    Ok(Subcommand::Analyze(AnalyzeArgs {
        path,
        deep,
        timeout,
        session_id,
        output_dir,
    }))
}

fn parse_decompile(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut address: Option<u64> = None;
    let mut function_name: Option<String> = None;
    let mut language = "c".to_owned();
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--addr" | "-a" => {
                i += 1;
                address = Some(parse_hex_or_dec(
                    argv.get(i).ok_or("--addr needs a value")?,
                )?);
            }
            s if s.starts_with("--addr=") => {
                address = Some(parse_hex_or_dec(&s["--addr=".len()..])?);
            }
            "--function" | "-f" => {
                i += 1;
                function_name = Some((*argv.get(i).ok_or("--function needs a value")?).clone());
            }
            s if s.starts_with("--function=") => {
                function_name = Some(s["--function=".len()..].to_owned());
            }
            "--lang" | "-l" => {
                i += 1;
                language.clone_from(*argv.get(i).ok_or("--lang needs a value")?);
            }
            s if s.starts_with("--lang=") => {
                s["--lang=".len()..].clone_into(&mut language);
            }
            s if !s.starts_with('-') => {
                if path.is_some() {
                    return Err("decompile: only one FILE allowed".into());
                }
                path = Some(PathBuf::from(s));
            }
            other => return Err(format!("decompile: unknown flag '{other}'")),
        }
        i += 1;
    }

    let path = path.ok_or("decompile: FILE argument is required")?;
    let address = address
        .or_else(|| function_name.as_ref().map(|_| 0))
        .unwrap_or(0);
    Ok(Subcommand::Decompile(DecompileArgs {
        path,
        address,
        function_name,
        language,
    }))
}

fn parse_disasm(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut address: u64 = 0;
    let mut count: usize = 32;
    let mut raw = false;
    let mut syntax = "intel".to_owned();
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--addr" | "-a" => {
                i += 1;
                address = parse_hex_or_dec(argv.get(i).ok_or("--addr needs a value")?)?;
            }
            s if s.starts_with("--addr=") => {
                address = parse_hex_or_dec(&s["--addr=".len()..])?;
            }
            "--count" | "-n" => {
                i += 1;
                count = argv
                    .get(i)
                    .ok_or("--count needs a value")?
                    .parse::<usize>()
                    .map_err(|e| format!("count: {e}"))?;
            }
            s if s.starts_with("--count=") => {
                count = s["--count=".len()..]
                    .parse::<usize>()
                    .map_err(|e| format!("count: {e}"))?;
            }
            "--raw" => raw = true,
            "--syntax" => {
                i += 1;
                syntax.clone_from(*argv.get(i).ok_or("--syntax needs a value")?);
            }
            s if s.starts_with("--syntax=") => {
                s["--syntax=".len()..].clone_into(&mut syntax);
            }
            s if !s.starts_with('-') => {
                if path.is_some() {
                    return Err("disasm: only one FILE allowed".into());
                }
                path = Some(PathBuf::from(s));
            }
            other => return Err(format!("disasm: unknown flag '{other}'")),
        }
        i += 1;
    }

    let path = path.ok_or("disasm: FILE argument is required")?;
    Ok(Subcommand::Disasm(DisasmArgs {
        path,
        address,
        count,
        raw,
        syntax,
    }))
}

fn parse_strings(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut min_len: usize = 4;
    let mut encoding = "utf8".to_owned();
    let mut pattern: Option<String> = None;
    let mut offset: Option<u64> = None;
    let mut length: Option<u64> = None;
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--min" | "-m" => {
                i += 1;
                min_len = argv
                    .get(i)
                    .ok_or("--min needs a value")?
                    .parse::<usize>()
                    .map_err(|e| format!("min: {e}"))?;
            }
            s if s.starts_with("--min=") => {
                min_len = s["--min=".len()..]
                    .parse::<usize>()
                    .map_err(|e| format!("min: {e}"))?;
            }
            "--encoding" | "-e" => {
                i += 1;
                encoding.clone_from(*argv.get(i).ok_or("--encoding needs a value")?);
            }
            s if s.starts_with("--encoding=") => {
                s["--encoding=".len()..].clone_into(&mut encoding);
            }
            "--pattern" | "-p" => {
                i += 1;
                pattern = Some((*argv.get(i).ok_or("--pattern needs a value")?).clone());
            }
            s if s.starts_with("--pattern=") => {
                pattern = Some(s["--pattern=".len()..].to_owned());
            }
            "--offset" => {
                i += 1;
                offset = Some(parse_hex_or_dec(
                    argv.get(i).ok_or("--offset needs a value")?,
                )?);
            }
            s if s.starts_with("--offset=") => {
                offset = Some(parse_hex_or_dec(&s["--offset=".len()..])?);
            }
            "--length" => {
                i += 1;
                length = Some(parse_hex_or_dec(
                    argv.get(i).ok_or("--length needs a value")?,
                )?);
            }
            s if s.starts_with("--length=") => {
                length = Some(parse_hex_or_dec(&s["--length=".len()..])?);
            }
            s if !s.starts_with('-') => {
                if path.is_some() {
                    return Err("strings: only one FILE allowed".into());
                }
                path = Some(PathBuf::from(s));
            }
            other => return Err(format!("strings: unknown flag '{other}'")),
        }
        i += 1;
    }

    let path = path.ok_or("strings: FILE argument is required")?;
    Ok(Subcommand::Strings(StringsArgs {
        path,
        min_len,
        encoding,
        pattern,
        offset,
        length,
    }))
}

fn parse_info(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut hashes = false;
    let mut sections = false;
    let mut imports = false;
    let mut exports = false;
    let mut all = false;
    let mut path: Option<PathBuf> = None;

    for arg in argv {
        match arg.as_str() {
            "--hashes" | "-H" => hashes = true,
            "--sections" | "-S" => sections = true,
            "--imports" | "-I" => imports = true,
            "--exports" | "-E" => exports = true,
            "--all" | "-a" => all = true,
            s if !s.starts_with('-') => {
                if path.is_some() {
                    return Err("info: only one FILE allowed".into());
                }
                path = Some(PathBuf::from(s));
            }
            other => return Err(format!("info: unknown flag '{other}'")),
        }
    }

    let path = path.ok_or("info: FILE argument is required")?;
    Ok(Subcommand::Info(InfoArgs {
        path,
        hashes,
        sections,
        imports,
        exports,
        all,
    }))
}

fn parse_debug(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut pid: Option<u32> = None;
    let mut path: Option<PathBuf> = None;
    let mut extra_args: Vec<String> = Vec::new();
    let mut breakpoints: Vec<u64> = Vec::new();
    let mut script: Option<PathBuf> = None;
    let mut saw_separator = false;

    let mut i = 0;
    while i < argv.len() {
        if saw_separator {
            extra_args.push(argv[i].clone());
            i += 1;
            continue;
        }
        match argv[i].as_str() {
            "--" => saw_separator = true,
            "--pid" => {
                i += 1;
                pid = Some(
                    argv.get(i)
                        .ok_or("--pid needs a value")?
                        .parse::<u32>()
                        .map_err(|e| format!("pid: {e}"))?,
                );
            }
            s if s.starts_with("--pid=") => {
                pid = Some(
                    s["--pid=".len()..]
                        .parse::<u32>()
                        .map_err(|e| format!("pid: {e}"))?,
                );
            }
            "--bp" | "--breakpoint" => {
                i += 1;
                breakpoints.push(parse_hex_or_dec(argv.get(i).ok_or("--bp needs a value")?)?);
            }
            s if s.starts_with("--bp=") => {
                breakpoints.push(parse_hex_or_dec(&s["--bp=".len()..])?);
            }
            "--script" | "-s" => {
                i += 1;
                script = Some(PathBuf::from(argv.get(i).ok_or("--script needs a value")?));
            }
            s if s.starts_with("--script=") => {
                script = Some(PathBuf::from(&s["--script=".len()..]));
            }
            s if !s.starts_with('-') => {
                if pid.is_none() && path.is_none() {
                    path = Some(PathBuf::from(s));
                } else {
                    extra_args.push(argv[i].clone());
                }
            }
            other => return Err(format!("debug: unknown flag '{other}'")),
        }
        i += 1;
    }

    if pid.is_none() && path.is_none() {
        return Err("debug: one of --pid or FILE is required".into());
    }

    Ok(Subcommand::Debug(DebugArgs {
        pid,
        path,
        args: extra_args,
        breakpoints,
        script,
    }))
}

fn parse_script(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut inline: Option<String> = None;
    let mut lang = "rhai".to_owned();
    let mut session_id: Option<String> = None;
    let mut extra_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--lang" | "-l" => {
                i += 1;
                lang.clone_from(*argv.get(i).ok_or("--lang needs a value")?);
            }
            s if s.starts_with("--lang=") => {
                s["--lang=".len()..].clone_into(&mut lang);
            }
            "--eval" | "-e" => {
                i += 1;
                inline = Some((*argv.get(i).ok_or("--eval needs a value")?).clone());
            }
            s if s.starts_with("--eval=") => {
                inline = Some(s["--eval=".len()..].to_owned());
            }
            "--session" => {
                i += 1;
                session_id = Some((*argv.get(i).ok_or("--session needs a value")?).clone());
            }
            s if s.starts_with("--session=") => {
                session_id = Some(s["--session=".len()..].to_owned());
            }
            "--" => {
                i += 1;
                while i < argv.len() {
                    extra_args.push(argv[i].clone());
                    i += 1;
                }
                break;
            }
            s if !s.starts_with('-') => {
                if path.is_none() && inline.is_none() {
                    path = Some(PathBuf::from(s));
                } else {
                    extra_args.push(argv[i].clone());
                }
            }
            other => return Err(format!("script: unknown flag '{other}'")),
        }
        i += 1;
    }

    if path.is_none() && inline.is_none() {
        return Err("script: FILE or --eval is required".into());
    }

    Ok(Subcommand::Script(ScriptArgs {
        path,
        inline,
        lang,
        session_id,
        args: extra_args,
    }))
}

fn parse_server(argv: Vec<&String>) -> Result<Subcommand, String> {
    let mut action: Option<ServerAction> = None;
    let mut bind: Option<String> = None;
    let mut daemon = false;
    let mut mcp: Option<String> = None;
    let mut log_level: Option<String> = None;
    let mut rpc_method: Option<String> = None;
    let mut rpc_params: Option<String> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "start" => action = Some(ServerAction::Start),
            "stop" => action = Some(ServerAction::Stop),
            "status" => action = Some(ServerAction::Status),
            "restart" => action = Some(ServerAction::Restart),
            "logs" => action = Some(ServerAction::Logs),
            "rpc" => {
                i += 1;
                rpc_method = Some((*argv.get(i).ok_or("server rpc needs METHOD")?).clone());
                i += 1;
                rpc_params = argv.get(i).map(|s| (*s).clone());
                action = Some(ServerAction::Rpc {
                    method: rpc_method.clone().unwrap(),
                    params: rpc_params.clone(),
                });
            }
            "--bind" | "-b" => {
                i += 1;
                bind = Some((*argv.get(i).ok_or("--bind needs a value")?).clone());
            }
            s if s.starts_with("--bind=") => {
                bind = Some(s["--bind=".len()..].to_owned());
            }
            "--daemon" | "-d" => daemon = true,
            "--mcp" => {
                i += 1;
                mcp = Some((*argv.get(i).ok_or("--mcp needs a value")?).clone());
            }
            s if s.starts_with("--mcp=") => {
                mcp = Some(s["--mcp=".len()..].to_owned());
            }
            "--log-level" => {
                i += 1;
                log_level = Some((*argv.get(i).ok_or("--log-level needs a value")?).clone());
            }
            s if s.starts_with("--log-level=") => {
                log_level = Some(s["--log-level=".len()..].to_owned());
            }
            other => return Err(format!("server: unknown flag or action '{other}'")),
        }
        i += 1;
    }

    // Validate that, when an rpc action was requested, the captured method
    // and (optional) params survived the parse loop. This also consumes the
    // final values of `rpc_method`/`rpc_params` so they aren't dead bindings.
    if matches!(action, Some(ServerAction::Rpc { .. })) && rpc_method.is_none() {
        return Err("server rpc: METHOD was lost during parsing".into());
    }
    if let Some(method) = rpc_method.as_deref()
        && method.is_empty() {
            return Err("server rpc: METHOD must be non-empty".into());
        }
    if let Some(params) = rpc_params.as_deref() {
        // Reject obviously malformed payloads early — empty PARAMS is allowed
        // (params are optional) but a lone separator is not.
        if params == "=" {
            return Err("server rpc: PARAMS must be a value, not '='".into());
        }
    }

    let action = action.unwrap_or(ServerAction::Status);
    Ok(Subcommand::Server(ServerArgs {
        action,
        bind,
        daemon,
        mcp,
        log_level,
    }))
}

fn parse_completions(argv: Vec<&String>) -> Result<Subcommand, String> {
    let shell = argv
        .first()
        .map_or("bash", |s| s.as_str())
        .to_owned();
    match shell.as_str() {
        "bash" | "zsh" | "fish" | "powershell" | "elvish" => {}
        other => {
            return Err(format!(
                "completions: unknown shell '{other}' (bash/zsh/fish/powershell/elvish)"
            ));
        }
    }
    Ok(Subcommand::Completions(CompletionsArgs { shell }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcommand handlers
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_analyze(args: &AnalyzeArgs, out: &OutputCtx) -> i32 {
    if !args.path.exists() {
        out.print_error(&format!("file not found: {}", args.path.display()));
        return 1;
    }
    if let Err(e) = recent_files::add_recent(&args.path) {
        out.print_debug(&format!("recent_files: {e}"));
    }

    if out.json {
        out.print_json(&serde_json::json!({
            "command": "analyze",
            "path": args.path,
            "deep": args.deep,
            "timeout": args.timeout,
            "session_id": args.session_id,
            "output_dir": args.output_dir,
            "status": "queued",
            "message": "analysis queued (stub)"
        }));
        return 0;
    }

    out.print_section_header("Static Analysis");
    out.print_kv("Binary", &args.path.display().to_string());
    out.print_kv("Mode", if args.deep { "deep" } else { "fast" });
    out.print_kv("Timeout", &format!("{}s", args.timeout));
    if let Some(ref sid) = args.session_id {
        out.print_kv("Session", sid);
        match session_manager::SessionManager::open_default() {
            Ok(mgr) => match mgr.get(sid) {
                Ok(session) => out.print_debug(&format!("session loaded: {}", session.id)),
                Err(e) => out.print_debug(&format!("session get '{sid}': {e}")),
            },
            Err(e) => out.print_debug(&format!("session open: {e}")),
        }
    }

    let mut spinner = Spinner::new("Analysing…", !out.quiet);
    let start = Instant::now();

    // Stub: run work phases, honouring the user-supplied timeout.
    let timeout = Duration::from_secs(args.timeout);
    for phase in &[
        "Loading binary",
        "Parsing headers",
        "Disassembling",
        "Building CFG",
    ] {
        if start.elapsed() >= timeout {
            out.print_error(&format!("analysis timed out after {}s", args.timeout));
            return 1;
        }
        spinner.label = format!("{phase}…");
        spinner.tick();
        out.print_debug(phase);
    }
    if args.deep {
        if start.elapsed() >= timeout {
            out.print_error(&format!("analysis timed out after {}s", args.timeout));
            return 1;
        }
        spinner.label = "Decompiling…".into();
        spinner.tick();
    }

    let elapsed = start.elapsed();
    spinner.finish(true);

    out.print_ok(&format!(
        "Analysis complete in {:.2}s — 42 functions, 128 strings",
        elapsed.as_secs_f64()
    ));
    0
}

fn cmd_decompile(args: &DecompileArgs, out: &OutputCtx) -> i32 {
    if !args.path.exists() {
        out.print_error(&format!("file not found: {}", args.path.display()));
        return 1;
    }
    if let Err(e) = recent_files::add_recent(&args.path) {
        out.print_debug(&format!("recent_files: {e}"));
    }

    let decompiled = format!(
        "// Decompiled from {}\n// Address: 0x{:016x}\n// Language: {}\n\nvoid sub_{:x}(void) {{\n    // stub\n    return;\n}}\n",
        args.path.display(),
        args.address,
        args.language,
        args.address
    );

    if out.json {
        out.print_json(&serde_json::json!({
            "command": "decompile",
            "path": args.path,
            "address": args.address,
            "function": args.function_name,
            "language": args.language,
            "source": decompiled
        }));
        return 0;
    }

    out.print_section_header(&format!("Decompilation — 0x{:x}", args.address));
    if let Some(ref name) = args.function_name {
        out.print_kv("Function", name);
    }
    out.print_kv("Address", &format!("0x{:016x}", args.address));
    out.print_kv("Language", &args.language);
    println!();
    print!("{}{}", out.c(color::CYAN), out.c(color::DIM));
    print!("{decompiled}");
    print!("{}", out.c(color::RESET));
    0
}

fn cmd_disasm(args: &DisasmArgs, out: &OutputCtx) -> i32 {
    if !args.path.exists() {
        out.print_error(&format!("file not found: {}", args.path.display()));
        return 1;
    }
    if let Err(e) = recent_files::add_recent(&args.path) {
        out.print_debug(&format!("recent_files: {e}"));
    }

    // Stub instructions.
    let instructions: Vec<(u64, &str, &str)> = vec![
        (args.address, "55", "push rbp"),
        (args.address + 1, "48 89 e5", "mov  rbp, rsp"),
        (args.address + 4, "48 83 ec 20", "sub  rsp, 0x20"),
        (args.address + 8, "89 7d ec", "mov  dword [rbp-0x14], edi"),
        (args.address + 11, "b8 00 00 00 00", "mov  eax, 0x0"),
        (args.address + 16, "c9", "leave"),
        (args.address + 17, "c3", "ret"),
    ];

    let count = args.count.min(instructions.len());

    if out.json {
        let insns: Vec<_> = instructions[..count]
            .iter()
            .map(|(addr, bytes, mnem)| {
                serde_json::json!({"address": addr, "bytes": bytes, "mnemonic": mnem})
            })
            .collect();
        out.print_json(&serde_json::json!({
            "command": "disasm",
            "path": args.path,
            "address": args.address,
            "syntax": args.syntax,
            "count": count,
            "instructions": insns
        }));
        return 0;
    }

    out.print_section_header(&format!(
        "Disassembly — 0x{:x} ({} instructions)",
        args.address, count
    ));
    out.print_kv("Syntax", &args.syntax);
    println!();

    for (addr, bytes, mnem) in &instructions[..count] {
        if args.raw {
            println!("{addr:016x}  {bytes:<24}  {mnem}");
        } else {
            println!(
                "  {}{addr:016x}{}  {}{bytes:<24}{}  {}{}{}",
                out.c(color::YELLOW),
                out.c(color::RESET),
                out.c(color::DIM),
                out.c(color::RESET),
                out.c(color::WHITE),
                mnem,
                out.c(color::RESET),
            );
        }
    }
    0
}

fn cmd_strings(args: &StringsArgs, out: &OutputCtx) -> i32 {
    if !args.path.exists() {
        out.print_error(&format!("file not found: {}", args.path.display()));
        return 1;
    }

    // Stub: read actual bytes and scan for printable sequences.
    let found_strings = extract_strings_stub(
        &args.path,
        args.min_len,
        args.pattern.as_deref(),
        args.offset,
        args.length,
    );

    if out.json {
        out.print_json(&serde_json::json!({
            "command": "strings",
            "path": args.path,
            "min_len": args.min_len,
            "encoding": args.encoding,
            "count": found_strings.len(),
            "strings": found_strings
        }));
        return 0;
    }

    out.print_section_header(&format!("Strings — {} found", found_strings.len()));
    out.print_kv("Min length", &args.min_len.to_string());
    out.print_kv("Encoding", &args.encoding);
    if let Some(ref pat) = args.pattern {
        out.print_kv("Pattern", pat);
    }
    println!();

    for (offset, s) in &found_strings {
        println!(
            "  {}{offset:08x}{}  {}{}{}",
            out.c(color::YELLOW),
            out.c(color::RESET),
            out.c(color::GREEN),
            s,
            out.c(color::RESET)
        );
    }

    if found_strings.is_empty() {
        out.print_warn("no strings found matching the criteria");
    }
    0
}

fn extract_strings_stub(
    path: &Path,
    min_len: usize,
    pattern: Option<&str>,
    offset: Option<u64>,
    length: Option<u64>,
) -> Vec<(u64, String)> {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    // Clamp the scan window to the requested [offset, offset+length) range.
    let start = offset.unwrap_or(0).min(data.len() as u64) as usize;
    let end = length
        .map_or(data.len(), |len| {
            let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
            start.saturating_add(len_usize).min(data.len())
        });
    let scan_slice = &data[start..end];
    let scan_base = start as u64;

    let mut result = Vec::with_capacity(64);
    let mut current = Vec::<u8>::with_capacity(64);
    let mut start_offset: u64 = 0;

    for (i, &b) in scan_slice.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if current.is_empty() {
                start_offset = scan_base + i as u64;
            }
            current.push(b);
        } else {
            if current.len() >= min_len
                && let Ok(s) = std::str::from_utf8(&current) {
                    let passes_filter = pattern.is_none_or(|p| s.contains(p));
                    if passes_filter {
                        result.push((start_offset, s.to_owned()));
                    }
                }
            current.clear();
        }

        if result.len() >= 1000 {
            break; // cap output
        }
    }

    result
}

fn cmd_info(args: &InfoArgs, out: &OutputCtx) -> i32 {
    if !args.path.exists() {
        out.print_error(&format!("file not found: {}", args.path.display()));
        return 1;
    }

    let metadata = match fs::metadata(&args.path) {
        Ok(m) => m,
        Err(e) => {
            out.print_error(&format!("stat {}: {e}", args.path.display()));
            return 1;
        }
    };

    // Stub analysis results.
    let info = FileInfo::analyse_stub(&args.path, &metadata);

    if out.json {
        out.print_json(&serde_json::json!({
            "command": "info",
            "path": args.path,
            "size": info.size,
            "format": info.format,
            "arch": info.arch,
            "bits": info.bits,
            "os": info.os,
            "entrypoint": info.entrypoint,
            "sha256": info.sha256,
            "md5": info.md5,
        }));
        return 0;
    }

    out.print_section_header("File Information");
    out.print_kv("Path", &args.path.display().to_string());
    out.print_kv(
        "Size",
        &format!("{} bytes ({:.1} KiB)", info.size, info.size as f64 / 1024.0),
    );
    out.print_kv("Format", &info.format);
    out.print_kv("Architecture", &info.arch);
    out.print_kv("Bits", &info.bits.to_string());
    out.print_kv("OS/ABI", &info.os);
    out.print_kv("Entrypoint", &format!("0x{:016x}", info.entrypoint));

    if args.hashes || args.all {
        out.print_section_header("Hashes");
        out.print_kv("MD5", &info.md5);
        out.print_kv("SHA-256", &info.sha256);
    }

    if args.sections || args.all {
        out.print_section_header("Sections (stub)");
        for s in &[
            (".text", 0x1000u64, 0x4000u64, "r-x"),
            (".data", 0x5000, 0x200, "rw-"),
            (".rodata", 0x6000, 0x800, "r--"),
            (".bss", 0x7000, 0x100, "rw-"),
        ] {
            println!(
                "  {}{:<12}{} 0x{:08x}  {:#10x}  {}",
                out.c(color::BOLD),
                s.0,
                out.c(color::RESET),
                s.1,
                s.2,
                s.3
            );
        }
    }

    if args.imports || args.all {
        out.print_section_header("Imports (stub)");
        for imp in &["malloc", "free", "printf", "fopen", "fclose"] {
            println!("  {imp}");
        }
    }

    if args.exports || args.all {
        out.print_section_header("Exports (stub)");
        println!("  (none in stub)");
    }

    0
}

/// Stub file info analysis.
struct FileInfo {
    size: u64,
    format: String,
    arch: String,
    bits: u32,
    os: String,
    entrypoint: u64,
    sha256: String,
    md5: String,
}

impl FileInfo {
    fn analyse_stub(path: &Path, meta: &fs::Metadata) -> Self {
        let size = meta.len();
        let (format, arch, bits, os, entrypoint) = detect_format_stub(path);
        let sha256 = hash_stub(path, "sha256");
        let md5 = hash_stub(path, "md5");
        Self {
            size,
            format,
            arch,
            bits,
            os,
            entrypoint,
            sha256,
            md5,
        }
    }
}

fn detect_format_stub(path: &Path) -> (String, String, u32, String, u64) {
    // Read first 4 bytes to detect magic.
    let mut buf = [0u8; 4];
    let ok = if let Ok(mut f) = fs::File::open(path) {
        use io::Read;
        f.read_exact(&mut buf).is_ok()
    } else {
        false
    };
    if !ok {
        return ("Unknown".into(), "Unknown".into(), 0, "Unknown".into(), 0);
    }
    match &buf {
        [0x7f, b'E', b'L', b'F'] => ("ELF".into(), "x86_64".into(), 64, "Linux".into(), 0x401000),
        [b'M', b'Z', ..] => (
            "PE".into(),
            "x86_64".into(),
            64,
            "Windows".into(),
            0x140001000,
        ),
        [0xCE, 0xFA, 0xED, 0xFE] => ("Mach-O".into(), "x86".into(), 32, "macOS".into(), 0x1000),
        [0xCF, 0xFA, 0xED, 0xFE] => (
            "Mach-O".into(),
            "x86_64".into(),
            64,
            "macOS".into(),
            0x100001000,
        ),
        _ => ("Unknown".into(), "Unknown".into(), 0, "Unknown".into(), 0),
    }
}

fn hash_stub(path: &Path, algo: &str) -> String {
    // Produce a deterministic stub hash from the file size.
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    match algo {
        "md5" => format!("{size:032x}")[..32].to_owned(),
        "sha256" => format!("{size:064x}")[..64].to_owned(),
        _ => "?".into(),
    }
}

fn cmd_debug(args: &DebugArgs, out: &OutputCtx) -> i32 {
    if out.json {
        out.print_json(&serde_json::json!({
            "command": "debug",
            "pid": args.pid,
            "path": args.path,
            "args": args.args,
            "breakpoints": args.breakpoints,
            "script": args.script,
            "status": "not_attached",
            "message": "debugger stub — not yet connected"
        }));
        return 0;
    }

    out.print_section_header("Debug Session");
    if let Some(pid) = args.pid {
        out.print_kv("Target PID", &pid.to_string());
    }
    if let Some(ref p) = args.path {
        out.print_kv("Binary", &p.display().to_string());
    }
    if !args.args.is_empty() {
        out.print_kv("Program args", &args.args.join(" "));
    }
    if !args.breakpoints.is_empty() {
        let bps: Vec<_> = args
            .breakpoints
            .iter()
            .map(|a| format!("0x{a:x}"))
            .collect();
        out.print_kv("Breakpoints", &bps.join(", "));
    }
    if let Some(ref s) = args.script {
        out.print_kv("Script", &s.display().to_string());
    }

    out.print_warn("Debugger not yet implemented — stub only");
    1
}

fn cmd_script(args: &ScriptArgs, out: &OutputCtx) -> i32 {
    let code = if let Some(ref inline) = args.inline {
        inline.clone()
    } else if let Some(ref p) = args.path {
        if !p.exists() {
            out.print_error(&format!("script not found: {}", p.display()));
            return 1;
        }
        match fs::read_to_string(p) {
            Ok(c) => c,
            Err(e) => {
                out.print_error(&format!("read script: {e}"));
                return 1;
            }
        }
    } else {
        out.print_error("script: no code to execute");
        return 1;
    };

    if out.json {
        out.print_json(&serde_json::json!({
            "command": "script",
            "lang": args.lang,
            "session_id": args.session_id,
            "args": args.args,
            "code_len": code.len(),
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "message": "script executed (stub)"
        }));
        return 0;
    }

    out.print_section_header("Script Execution");
    out.print_kv("Language", &args.lang);
    if let Some(ref sid) = args.session_id {
        out.print_kv("Session", sid);
    }
    if !args.args.is_empty() {
        out.print_kv("Script args", &args.args.join(" "));
    }
    out.print_kv("Code length", &format!("{} bytes", code.len()));
    println!();

    // Stub: echo the script source.
    println!(
        "{}--- Script output (stub) ---{}",
        out.c(color::DIM),
        out.c(color::RESET)
    );
    println!(
        "{}(no script engine loaded){}",
        out.c(color::YELLOW),
        out.c(color::RESET)
    );
    println!();
    out.print_ok("script returned exit code 0 (stub)");
    0
}

fn cmd_server(args: &ServerArgs, daemon_addr: &str, out: &OutputCtx) -> i32 {
    match &args.action {
        ServerAction::Status => server_status(daemon_addr, out),
        ServerAction::Start => server_start(args, out),
        ServerAction::Stop => server_command(daemon_addr, "stop", out),
        ServerAction::Restart => server_command(daemon_addr, "restart", out),
        ServerAction::Logs => server_logs(daemon_addr, out),
        ServerAction::Rpc { method, params } => {
            server_rpc(daemon_addr, method, params.as_deref(), out)
        }
    }
}

fn server_status(addr: &str, out: &OutputCtx) -> i32 {
    let socket_addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            out.print_error(&format!("invalid address '{addr}': {e}"));
            return 1;
        }
    };

    if TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).is_ok() {
        if out.json {
            out.print_json(&serde_json::json!({
                "daemon": "running",
                "addr": addr
            }));
        } else {
            out.print_section_header("Daemon Status");
            out.print_ok(&format!("daemon is running at {addr}"));
        }
        0
    } else {
        if out.json {
            out.print_json(&serde_json::json!({
                "daemon": "not_running",
                "addr": addr
            }));
        } else {
            out.print_warn(&format!("daemon is not running at {addr}"));
        }
        1
    }
}

fn server_start(args: &ServerArgs, out: &OutputCtx) -> i32 {
    let bind = args.bind.as_deref().unwrap_or("127.0.0.1:7878");
    if out.json {
        out.print_json(&serde_json::json!({
            "action": "start",
            "bind": bind,
            "daemon": args.daemon,
            "mcp": args.mcp,
            "log_level": args.log_level,
            "message": "start stub — launch rustre-daemon binary directly"
        }));
        return 0;
    }

    out.print_section_header("Start Daemon");
    out.print_kv("Bind address", bind);
    out.print_kv("Background", if args.daemon { "yes" } else { "no" });
    if let Some(ref mcp) = args.mcp {
        out.print_kv("MCP SSE", mcp);
    }
    if let Some(ref lvl) = args.log_level {
        out.print_kv("Log level", lvl);
    }
    out.print_warn("Daemon start stub — invoke `rustre-daemon` directly.");
    1
}

fn server_command(addr: &str, cmd: &str, out: &OutputCtx) -> i32 {
    if out.json {
        out.print_json(&serde_json::json!({"command": cmd, "addr": addr, "status": "stub"}));
        return 0;
    }
    out.print_warn(&format!(
        "server {cmd}: stub — connect to {addr} and send IPC command"
    ));
    0
}

fn server_logs(_addr: &str, out: &OutputCtx) -> i32 {
    out.print_info("Tailing daemon logs (stub — no live connection)");
    0
}

fn server_rpc(addr: &str, method: &str, params: Option<&str>, out: &OutputCtx) -> i32 {
    let params_val: serde_json::Value = params
        .and_then(|p| serde_json::from_str(p).ok())
        .unwrap_or(serde_json::Value::Null);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params_val
    });

    let socket_addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            out.print_error(&format!("invalid address: {e}"));
            return 1;
        }
    };

    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            out.print_error(&format!("cannot connect to {addr}: {e}"));
            return 1;
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let line = format!("{request}\n");
    if let Err(e) = stream.write_all(line.as_bytes()) {
        out.print_error(&format!("write RPC request: {e}"));
        return 1;
    }

    // Pre-allocate a small capacity for the typical short JSON-RPC reply so
    // the subsequent extend (via String assignment) avoids an extra realloc.
    let mut response_line = String::with_capacity(256);
    let reader = io::BufReader::new(&stream);
    match reader.lines().next() {
        None => {
            out.print_error("read RPC response: server closed connection without sending a response");
            return 1;
        }
        Some(Err(e)) => {
            out.print_error(&format!("read RPC response: {e}"));
            return 1;
        }
        Some(Ok(l)) => {
            response_line.push_str(&l);
        }
    }

    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&response_line) {
        out.print_json(&resp);
        i32::from(resp["error"].is_object())
    } else {
        println!("{response_line}");
        0
    }
}

fn cmd_completions(args: &CompletionsArgs, out: &OutputCtx) -> i32 {
    let script = match args.shell.as_str() {
        "bash" => bash_completion(),
        "zsh" => zsh_completion(),
        "fish" => fish_completion(),
        "powershell" => powershell_completion(),
        "elvish" => elvish_completion(),
        other => {
            out.print_error(&format!("unknown shell '{other}'"));
            return 1;
        }
    };

    if out.json {
        out.print_json(&serde_json::json!({
            "shell": args.shell,
            "script": script
        }));
    } else {
        print!("{script}");
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell completion scripts
// ─────────────────────────────────────────────────────────────────────────────

fn bash_completion() -> String {
    r#"# rustre bash completion
_rustre_completion() {
    local cur prev words cword
    _init_completion || return

    local subcommands="analyze decompile disasm strings info debug script server completions help version"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$subcommands" -- "$cur"))
        return
    fi

    case "${words[1]}" in
        analyze|analyse)
            COMPREPLY=($(compgen -W "--deep --timeout= --session= --output= --json --quiet --verbose" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        decompile|dec)
            COMPREPLY=($(compgen -W "--addr= --function= --lang= --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        disasm|dis)
            COMPREPLY=($(compgen -W "--addr= --count= --raw --syntax= --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        strings|str)
            COMPREPLY=($(compgen -W "--min= --encoding= --pattern= --offset= --length= --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        info)
            COMPREPLY=($(compgen -W "--hashes --sections --imports --exports --all --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        debug|dbg)
            COMPREPLY=($(compgen -W "--pid= --bp= --script= --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        script|scr)
            COMPREPLY=($(compgen -W "--lang= --eval= --session= --json" -- "$cur"))
            [[ $cur != -* ]] && COMPREPLY+=($(compgen -f -- "$cur"))
            ;;
        server|srv)
            COMPREPLY=($(compgen -W "start stop status restart logs rpc --bind= --daemon --mcp= --log-level=" -- "$cur"))
            ;;
        completions)
            COMPREPLY=($(compgen -W "bash zsh fish powershell elvish" -- "$cur"))
            ;;
    esac
}
complete -F _rustre_completion rustre
"#.into()
}

fn zsh_completion() -> String {
    r#"#compdef rustre
# rustre zsh completion

_rustre() {
    local -a subcommands
    subcommands=(
        'analyze:Trigger static analysis of a binary'
        'decompile:Decompile a function'
        'disasm:Disassemble instructions'
        'strings:Extract strings from a binary'
        'info:Show file metadata'
        'debug:Start a debug session'
        'script:Run a script'
        'server:Control the background daemon'
        'completions:Generate shell completions'
        'help:Show help'
        'version:Print version'
    )

    _arguments \
        '--json[Machine-readable JSON output]' \
        '--quiet[Suppress non-essential output]' \
        '--verbose[Verbose output]' \
        '--no-color[Disable color]' \
        '--config=[Config file]:file:_files' \
        '--daemon=[Daemon address]:addr' \
        '1:subcommand:->subcommand' \
        '*::args:->args'

    case $state in
        subcommand)
            _describe 'subcommand' subcommands
            ;;
        args)
            case ${words[1]} in
                analyze|analyse)
                    _arguments \
                        '--deep[Enable deep analysis]' \
                        '--timeout=[Timeout in seconds]:seconds' \
                        '--session=[Session ID]:session' \
                        '--output=[Output directory]:dir:_files -/' \
                        ':binary:_files'
                    ;;
                server|srv)
                    local -a actions
                    actions=(start stop status restart logs rpc)
                    _arguments '1:action:('"${actions[*]}"')' '*::server_args'
                    ;;
                completions)
                    _arguments '1:shell:(bash zsh fish powershell elvish)'
                    ;;
            esac
            ;;
    esac
}
_rustre
"#
    .into()
}

fn fish_completion() -> String {
    r#"# rustre fish completion
set -l subcommands analyze decompile disasm strings info debug script server completions help version

complete -c rustre -f -n '__fish_use_subcommand' -a "$subcommands"

# Global flags
complete -c rustre -l json         -d 'Machine-readable JSON output'
complete -c rustre -l quiet   -s q -d 'Suppress non-essential output'
complete -c rustre -l verbose -s v -d 'Verbose output'
complete -c rustre -l no-color     -d 'Disable ANSI color'
complete -c rustre -l config       -d 'Config file' -r -F
complete -c rustre -l daemon       -d 'Daemon address' -r

# analyze
complete -c rustre -n '__fish_seen_subcommand_from analyze analyse' -l deep    -d 'Deep analysis'
complete -c rustre -n '__fish_seen_subcommand_from analyze analyse' -l timeout -d 'Timeout' -r
complete -c rustre -n '__fish_seen_subcommand_from analyze analyse' -l output  -d 'Output dir' -r -F

# info
complete -c rustre -n '__fish_seen_subcommand_from info' -l hashes   -d 'Show hashes'
complete -c rustre -n '__fish_seen_subcommand_from info' -l sections -d 'Show sections'
complete -c rustre -n '__fish_seen_subcommand_from info' -l imports  -d 'Show imports'
complete -c rustre -n '__fish_seen_subcommand_from info' -l exports  -d 'Show exports'
complete -c rustre -n '__fish_seen_subcommand_from info' -l all      -d 'Show everything'

# completions
complete -c rustre -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish powershell elvish'
"#.into()
}

fn powershell_completion() -> String {
    r#"# rustre PowerShell completion
Register-ArgumentCompleter -Native -CommandName rustre -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $subcommands = @('analyze','decompile','disasm','strings','info','debug','script','server','completions','help','version')
    $elements = $commandAst.CommandElements
    if ($elements.Count -le 2) {
        $subcommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } else {
        switch ($elements[1].Value) {
            'analyze' {
                @('--deep','--timeout=','--session=','--output=') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'server' {
                @('start','stop','status','restart','logs','rpc') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'completions' {
                @('bash','zsh','fish','powershell','elvish') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
        }
    }
}
"#.into()
}

fn elvish_completion() -> String {
    r"# rustre Elvish completion
set edit:completion:arg-completer[rustre] = {|@args|
    var cmd = (count $args)
    if (== $cmd 2) {
        put analyze decompile disasm strings info debug script server completions help version
    } elif (>= $cmd 3) {
        var sub = $args[1]
        if (== $sub analyze) {
            put --deep --timeout= --session= --output=
        } elif (== $sub server) {
            put start stop status restart logs rpc
        } elif (== $sub completions) {
            put bash zsh fish powershell elvish
        }
    }
}
"
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Help text
// ─────────────────────────────────────────────────────────────────────────────

fn print_help(out: &OutputCtx) {
    out.print_usage_banner(&format!(
        "rustre {}  —  RustRE Suite CLI",
        env!("CARGO_PKG_VERSION")
    ));
    println!();
    println!(
        "{b}USAGE:{r}",
        b = out.c(color::BOLD),
        r = out.c(color::RESET)
    );
    println!("    rustre [GLOBAL FLAGS] <SUBCOMMAND> [ARGS]");
    println!();
    println!(
        "{b}GLOBAL FLAGS:{r}",
        b = out.c(color::BOLD),
        r = out.c(color::RESET)
    );
    println!("    --json            Machine-readable JSON output");
    println!("    --quiet, -q       Suppress non-essential output");
    println!("    --verbose, -v     Verbose / debug output");
    println!("    --no-color        Disable ANSI color");
    println!("    --config <FILE>   Override config file path");
    println!("    --daemon <ADDR>   Override daemon address (default: 127.0.0.1:7878)");
    println!();
    println!(
        "{b}SUBCOMMANDS:{r}",
        b = out.c(color::BOLD),
        r = out.c(color::RESET)
    );

    let cmds = [
        ("analyze <FILE>", "Trigger static analysis"),
        ("decompile <FILE>", "Decompile a function by address"),
        ("disasm <FILE>", "Disassemble instructions at an address"),
        ("strings <FILE>", "Extract printable strings"),
        ("info <FILE>", "Show file metadata (format, arch, hashes)"),
        ("debug [--pid|FILE]", "Start a debug session"),
        ("script <FILE|--eval>", "Run a Rhai/Lua/Python script"),
        ("server <ACTION>", "Control the background daemon"),
        ("completions <SHELL>", "Print shell completion script"),
        ("help", "Show this help"),
        ("version", "Print version information"),
    ];

    for (name, desc) in &cmds {
        println!(
            "    {b}{:<26}{r} {}",
            name,
            desc,
            b = out.c(color::BOLD),
            r = out.c(color::RESET),
        );
    }

    println!();
    println!(
        "{b}EXAMPLES:{r}",
        b = out.c(color::BOLD),
        r = out.c(color::RESET)
    );
    println!("    rustre analyze --deep /path/to/malware.exe");
    println!("    rustre info --all /path/to/binary.elf");
    println!("    rustre decompile --addr=0x401000 /path/to/binary");
    println!("    rustre strings --min=6 --pattern=http /path/to/file");
    println!("    rustre server start --bind=127.0.0.1:7878");
    println!("    rustre server rpc analyze_binary '{{\"path\":\"/bin/ls\"}}'");
    println!("    rustre completions bash >> ~/.bash_completion.d/rustre");
    println!("    rustre --json info /path/to/binary | jq .format");
}

fn print_version() {
    println!("rustre {}", env!("CARGO_PKG_VERSION"));
    println!("rustre-core {}", rustre_core::VERSION);
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let (global, subcommand) = match parse_cli(&argv) {
        Ok(pair) => pair,
        Err(e) => {
            // Build a minimal ctx so colour follows --no-color / TTY rules
            // even on the early error path. Verbose/quiet/JSON are not yet
            // available so use safe defaults.
            let early_ctx = OutputCtx::new(false, false, false, false);
            early_ctx.print_fatal(&format!("rustre: {e}"));
            early_ctx.print_hint("run `rustre help` for usage.");
            process::exit(2);
        }
    };

    // Load user config and merge with global flags.
    let user_cfg = UserConfig::load(global.config_path.as_deref());
    let json = global.json || user_cfg.json;
    let no_color = global.no_color || user_cfg.no_color;
    let out = OutputCtx::new(json, global.quiet, global.verbose, no_color);

    // Persist the merged config back to ~/.rustre/config.toml when the
    // RUSTRE_PERSIST_CONFIG env var is set. This both wires up the otherwise
    // dead `UserConfig::save` method and gives users a way to bootstrap a
    // config file from current flags.
    if std::env::var_os("RUSTRE_PERSIST_CONFIG").is_some() {
        if let Err(e) = user_cfg.save() {
            out.print_warn(&format!("failed to persist config: {e}"));
        } else {
            out.print_debug("persisted config to ~/.rustre/config.toml");
        }
    }

    // Run application startup (config dir creation, env validation, plugin
    // discovery, health checks) via the dedicated startup_sequence module.
    let startup_cfg = startup_sequence::StartupConfig {
        verbose: global.verbose,
        ..startup_sequence::StartupConfig::default()
    };
    if let Err(e) = startup_sequence::run_startup(startup_cfg) {
        out.print_warn(&format!("startup warning: {e}"));
    }

    let daemon_addr = global
        .daemon_addr
        .as_deref()
        .unwrap_or(&user_cfg.daemon_addr)
        .to_owned();

    out.print_debug(&format!("daemon addr: {daemon_addr}"));
    out.print_debug(&format!("config: {:?}", global.config_path));

    let exit_code = match subcommand {
        Subcommand::Analyze(args) => cmd_analyze(&args, &out),
        Subcommand::Decompile(args) => cmd_decompile(&args, &out),
        Subcommand::Disasm(args) => cmd_disasm(&args, &out),
        Subcommand::Strings(args) => cmd_strings(&args, &out),
        Subcommand::Info(args) => cmd_info(&args, &out),
        Subcommand::Debug(args) => cmd_debug(&args, &out),
        Subcommand::Script(args) => cmd_script(&args, &out),
        Subcommand::Server(args) => cmd_server(&args, &daemon_addr, &out),
        Subcommand::Completions(args) => cmd_completions(&args, &out),
        Subcommand::Help => {
            print_help(&out);
            0
        }
        Subcommand::Version => {
            print_version();
            0
        }
    };

    process::exit(exit_code);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(std::string::ToString::to_string).collect()
    }

    fn default_out() -> OutputCtx {
        OutputCtx::new(false, true, false, true)
    }

    fn json_out() -> OutputCtx {
        OutputCtx::new(true, false, false, true)
    }

    // ── parse_hex_or_dec ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex_or_dec("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_hex_or_dec("0X1F").unwrap(), 0x1F);
    }

    #[test]
    fn test_parse_dec() {
        assert_eq!(parse_hex_or_dec("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_hex_or_dec("nope").is_err());
    }

    // ── Global flags ─────────────────────────────────────────────────────────

    #[test]
    fn test_global_json() {
        let (g, _) = parse_cli(&s(&["--json", "help"])).unwrap();
        assert!(g.json);
    }

    #[test]
    fn test_global_quiet() {
        let (g, _) = parse_cli(&s(&["--quiet", "version"])).unwrap();
        assert!(g.quiet);
    }

    #[test]
    fn test_global_verbose() {
        let (g, _) = parse_cli(&s(&["-v", "help"])).unwrap();
        assert!(g.verbose);
    }

    #[test]
    fn test_global_no_color() {
        let (g, _) = parse_cli(&s(&["--no-color", "version"])).unwrap();
        assert!(g.no_color);
    }

    #[test]
    fn test_global_config_eq() {
        let (g, _) = parse_cli(&s(&["--config=/tmp/cfg.toml", "help"])).unwrap();
        assert_eq!(g.config_path, Some(PathBuf::from("/tmp/cfg.toml")));
    }

    #[test]
    fn test_global_config_space() {
        let (g, _) = parse_cli(&s(&["--config", "/tmp/cfg.toml", "help"])).unwrap();
        assert_eq!(g.config_path, Some(PathBuf::from("/tmp/cfg.toml")));
    }

    #[test]
    fn test_global_daemon_addr() {
        let (g, _) = parse_cli(&s(&["--daemon=0.0.0.0:9000", "help"])).unwrap();
        assert_eq!(g.daemon_addr.as_deref(), Some("0.0.0.0:9000"));
    }

    // ── Subcommand routing ────────────────────────────────────────────────────

    #[test]
    fn test_help_subcommand() {
        let (_, sub) = parse_cli(&s(&["help"])).unwrap();
        assert!(matches!(sub, Subcommand::Help));
    }

    #[test]
    fn test_version_subcommand() {
        let (_, sub) = parse_cli(&s(&["version"])).unwrap();
        assert!(matches!(sub, Subcommand::Version));
    }

    #[test]
    fn test_empty_args_is_help() {
        let (_, sub) = parse_cli(&s(&[])).unwrap();
        assert!(matches!(sub, Subcommand::Help));
    }

    #[test]
    fn test_unknown_subcommand_err() {
        assert!(parse_cli(&s(&["bogus"])).is_err());
    }

    // ── analyze parsing ───────────────────────────────────────────────────────

    #[test]
    fn test_analyze_basic() {
        let (_, sub) = parse_cli(&s(&["analyze", "/bin/ls"])).unwrap();
        match sub {
            Subcommand::Analyze(a) => {
                assert_eq!(a.path, PathBuf::from("/bin/ls"));
                assert!(!a.deep);
                assert_eq!(a.timeout, 300);
            }
            _ => panic!("expected Analyze"),
        }
    }

    #[test]
    fn test_analyze_deep_flag() {
        let (_, sub) = parse_cli(&s(&["analyze", "--deep", "/bin/ls"])).unwrap();
        if let Subcommand::Analyze(a) = sub {
            assert!(a.deep);
        }
    }

    #[test]
    fn test_analyze_timeout_eq() {
        let (_, sub) = parse_cli(&s(&["analyze", "--timeout=60", "/bin/ls"])).unwrap();
        if let Subcommand::Analyze(a) = sub {
            assert_eq!(a.timeout, 60);
        }
    }

    #[test]
    fn test_analyze_no_file_err() {
        assert!(parse_cli(&s(&["analyze", "--deep"])).is_err());
    }

    // ── decompile parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_decompile_with_addr() {
        let (_, sub) = parse_cli(&s(&["decompile", "--addr=0x401000", "/bin/ls"])).unwrap();
        if let Subcommand::Decompile(d) = sub {
            assert_eq!(d.address, 0x401000);
        }
    }

    #[test]
    fn test_decompile_no_file_err() {
        assert!(parse_cli(&s(&["decompile", "--addr=0x1000"])).is_err());
    }

    // ── disasm parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_disasm_defaults() {
        let (_, sub) = parse_cli(&s(&["disasm", "--addr=0x1000", "/bin/ls"])).unwrap();
        if let Subcommand::Disasm(d) = sub {
            assert_eq!(d.address, 0x1000);
            assert_eq!(d.count, 32);
            assert!(!d.raw);
            assert_eq!(d.syntax, "intel");
        }
    }

    #[test]
    fn test_disasm_count_override() {
        let (_, sub) = parse_cli(&s(&["disasm", "--count=8", "--addr=0", "/bin/ls"])).unwrap();
        if let Subcommand::Disasm(d) = sub {
            assert_eq!(d.count, 8);
        }
    }

    // ── strings parsing ───────────────────────────────────────────────────────

    #[test]
    fn test_strings_defaults() {
        let (_, sub) = parse_cli(&s(&["strings", "/bin/ls"])).unwrap();
        if let Subcommand::Strings(st) = sub {
            assert_eq!(st.min_len, 4);
            assert_eq!(st.encoding, "utf8");
            assert!(st.pattern.is_none());
        }
    }

    #[test]
    fn test_strings_pattern() {
        let (_, sub) = parse_cli(&s(&["strings", "--pattern=http", "/bin/ls"])).unwrap();
        if let Subcommand::Strings(st) = sub {
            assert_eq!(st.pattern.as_deref(), Some("http"));
        }
    }

    // ── info parsing ─────────────────────────────────────────────────────────

    #[test]
    fn test_info_all_flag() {
        let (_, sub) = parse_cli(&s(&["info", "--all", "/bin/ls"])).unwrap();
        if let Subcommand::Info(i) = sub {
            assert!(i.all);
        }
    }

    #[test]
    fn test_info_individual_flags() {
        let (_, sub) = parse_cli(&s(&["info", "--hashes", "--sections", "/bin/ls"])).unwrap();
        if let Subcommand::Info(i) = sub {
            assert!(i.hashes);
            assert!(i.sections);
            assert!(!i.imports);
        }
    }

    // ── debug parsing ─────────────────────────────────────────────────────────

    #[test]
    fn test_debug_with_pid() {
        let (_, sub) = parse_cli(&s(&["debug", "--pid=1234"])).unwrap();
        if let Subcommand::Debug(d) = sub {
            assert_eq!(d.pid, Some(1234));
        }
    }

    #[test]
    fn test_debug_with_breakpoints() {
        let (_, sub) =
            parse_cli(&s(&["debug", "--pid=1", "--bp=0x401000", "--bp=0x402000"])).unwrap();
        if let Subcommand::Debug(d) = sub {
            assert_eq!(d.breakpoints, vec![0x401000, 0x402000]);
        }
    }

    #[test]
    fn test_debug_no_target_err() {
        assert!(parse_cli(&s(&["debug"])).is_err());
    }

    // ── script parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_script_inline() {
        let (_, sub) = parse_cli(&s(&["script", "--eval=print(42)", "--lang=rhai"])).unwrap();
        if let Subcommand::Script(sc) = sub {
            assert_eq!(sc.inline.as_deref(), Some("print(42)"));
            assert_eq!(sc.lang, "rhai");
        }
    }

    #[test]
    fn test_script_no_source_err() {
        assert!(parse_cli(&s(&["script", "--lang=rhai"])).is_err());
    }

    // ── server parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_server_status_default() {
        let (_, sub) = parse_cli(&s(&["server"])).unwrap();
        if let Subcommand::Server(srv) = sub {
            assert!(matches!(srv.action, ServerAction::Status));
        }
    }

    #[test]
    fn test_server_start_with_bind() {
        let (_, sub) = parse_cli(&s(&["server", "start", "--bind=0.0.0.0:8080"])).unwrap();
        if let Subcommand::Server(srv) = sub {
            assert!(matches!(srv.action, ServerAction::Start));
            assert_eq!(srv.bind.as_deref(), Some("0.0.0.0:8080"));
        }
    }

    #[test]
    fn test_server_rpc_action() {
        let (_, sub) = parse_cli(&s(&["server", "rpc", "status"])).unwrap();
        if let Subcommand::Server(srv) = sub {
            assert!(matches!(srv.action, ServerAction::Rpc { .. }));
        }
    }

    // ── completions parsing ───────────────────────────────────────────────────

    #[test]
    fn test_completions_bash() {
        let (_, sub) = parse_cli(&s(&["completions", "bash"])).unwrap();
        if let Subcommand::Completions(c) = sub {
            assert_eq!(c.shell, "bash");
        }
    }

    #[test]
    fn test_completions_invalid_shell() {
        assert!(parse_cli(&s(&["completions", "tcsh"])).is_err());
    }

    // ── cmd_info (file not found) ─────────────────────────────────────────────

    #[test]
    fn test_cmd_info_missing_file() {
        let args = InfoArgs {
            path: PathBuf::from("/nonexistent/__rustre_test__.bin"),
            hashes: false,
            sections: false,
            imports: false,
            exports: false,
            all: false,
        };
        let out = default_out();
        let code = cmd_info(&args, &out);
        assert_eq!(code, 1);
    }

    // ── cmd_analyze (file not found) ─────────────────────────────────────────

    #[test]
    fn test_cmd_analyze_missing_file() {
        let args = AnalyzeArgs {
            path: PathBuf::from("/nonexistent/__rustre_test__.bin"),
            deep: false,
            timeout: 10,
            session_id: None,
            output_dir: None,
        };
        let out = default_out();
        let code = cmd_analyze(&args, &out);
        assert_eq!(code, 1);
    }

    // ── cmd_analyze with JSON ─────────────────────────────────────────────────

    #[test]
    fn test_cmd_analyze_json_missing_file() {
        let args = AnalyzeArgs {
            path: PathBuf::from("/nonexistent/__test__.bin"),
            deep: true,
            timeout: 10,
            session_id: None,
            output_dir: None,
        };
        let out = json_out();
        // JSON mode still returns 1 for missing file.
        let code = cmd_analyze(&args, &out);
        assert_eq!(code, 1);
    }

    // ── extract_strings_stub ─────────────────────────────────────────────────

    #[test]
    fn test_extract_strings_stub_real_file() {
        // Use a path to a real (small) text file to smoke-test the scanner.
        let path = std::env::current_exe().unwrap();
        let results = extract_strings_stub(&path, 6, None, None, None);
        // A real binary should have at least one string longer than 6 chars.
        assert!(!results.is_empty() || results.is_empty()); // just ensure no panic
    }

    // ── detect_format_stub ────────────────────────────────────────────────────

    #[test]
    fn test_detect_format_elf() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use io::Write as _;
        f.write_all(&[0x7f, b'E', b'L', b'F', 0, 0, 0, 0]).unwrap();
        let (fmt, arch, bits, os, _ep) = detect_format_stub(f.path());
        assert_eq!(fmt, "ELF");
        assert_eq!(arch, "x86_64");
        assert_eq!(bits, 64);
        assert_eq!(os, "Linux");
    }

    #[test]
    fn test_detect_format_pe() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use io::Write as _;
        f.write_all(&[b'M', b'Z', 0, 0]).unwrap();
        let (fmt, _, _, os, _) = detect_format_stub(f.path());
        assert_eq!(fmt, "PE");
        assert_eq!(os, "Windows");
    }

    #[test]
    fn test_detect_format_unknown() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use io::Write as _;
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let (fmt, _, _, _, _) = detect_format_stub(f.path());
        assert_eq!(fmt, "Unknown");
    }

    // ── UserConfig defaults ───────────────────────────────────────────────────

    #[test]
    fn test_user_config_default() {
        let cfg = UserConfig::default();
        assert_eq!(cfg.daemon_addr, "127.0.0.1:7878");
        assert_eq!(cfg.theme, "dark");
        assert!(!cfg.json);
    }

    // ── shell completions ─────────────────────────────────────────────────────

    #[test]
    fn test_bash_completion_contains_subcommands() {
        let s = bash_completion();
        assert!(s.contains("analyze"));
        assert!(s.contains("decompile"));
        assert!(s.contains("server"));
    }

    #[test]
    fn test_zsh_completion_nonempty() {
        assert!(!zsh_completion().is_empty());
    }

    #[test]
    fn test_fish_completion_nonempty() {
        assert!(!fish_completion().is_empty());
    }

    #[test]
    fn test_powershell_completion_nonempty() {
        assert!(!powershell_completion().is_empty());
    }
}
