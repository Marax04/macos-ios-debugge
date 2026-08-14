//! `interactive_shell` — Interactive REPL shell for `RustRE`.
//!
//! Provides readline-style line editing (via a simple ring-buffer history),
//! tab completion infrastructure, built-in help, command aliases, session
//! state management, and coloured output.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, BufRead as _};
use std::path::PathBuf;
use std::time::Duration;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the interactive shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellError {
    Io(String),
    UnknownCommand(String),
    MissingArgument(String),
    InvalidArgument { arg: String, reason: String },
    SessionError(String),
    CompletionError(String),
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e)                 => write!(f, "I/O error: {e}"),
            Self::UnknownCommand(c)     => write!(f, "unknown command: {c}"),
            Self::MissingArgument(a)    => write!(f, "missing argument: {a}"),
            Self::InvalidArgument{arg,reason} => write!(f, "invalid argument '{arg}': {reason}"),
            Self::SessionError(e)       => write!(f, "session error: {e}"),
            Self::CompletionError(e)    => write!(f, "completion error: {e}"),
        }
    }
}

// ── Command history ───────────────────────────────────────────────────────────

/// Ring-buffer command history.
pub struct History {
    entries: VecDeque<String>,
    capacity: usize,
    cursor: usize,
}

impl History {
    /// Create a history with `capacity` slots.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            cursor: 0,
        }
    }

    /// Push a new entry. Duplicate of the most-recent entry is ignored.
    pub fn push(&mut self, entry: impl Into<String>) {
        let entry = entry.into();
        if entry.is_empty() { return; }
        if self.entries.front() == Some(&entry) { return; }
        if self.entries.len() >= self.capacity {
            self.entries.pop_back();
        }
        self.entries.push_front(entry);
        self.cursor = 0;
    }

    /// Navigate up (older) in history. Returns `None` when at the oldest entry.
    #[must_use]
    pub fn prev(&mut self) -> Option<&str> {
        if self.entries.is_empty() { return None; }
        if self.cursor < self.entries.len() {
            let e = self.entries.get(self.cursor).map(String::as_str);
            self.cursor += 1;
            e
        } else {
            None
        }
    }

    /// Navigate down (newer) in history.
    #[must_use]
    pub fn next(&mut self) -> Option<&str> {
        if self.cursor == 0 { return None; }
        self.cursor -= 1;
        self.entries.get(self.cursor).map(String::as_str)
    }

    /// Reset cursor to the newest entry.
    pub const fn reset_cursor(&mut self) { self.cursor = 0; }

    /// Return all entries in order (newest first).
    #[must_use]
    pub fn entries(&self) -> Vec<&str> {
        self.entries.iter().map(String::as_str).collect()
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Whether the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Clear all history.
    pub fn clear(&mut self) { self.entries.clear(); self.cursor = 0; }

    /// Search for entries containing `query`.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&str> {
        self.entries.iter()
            .filter(|e| e.contains(query))
            .map(String::as_str)
            .collect()
    }

    /// Save history to a file (one entry per line, newest last).
    ///
    /// # Errors
    /// Returns `ShellError::Io` on write failure.
    pub fn save(&self, path: &std::path::Path) -> Result<(), ShellError> {
        let mut lines = self.entries.iter().rev().cloned().collect::<Vec<_>>().join("\n");
        lines.push('\n');
        std::fs::write(path, lines).map_err(|e| ShellError::Io(e.to_string()))
    }

    /// Load history from a file.
    ///
    /// # Errors
    /// Returns `ShellError::Io` on read failure.
    pub fn load(&mut self, path: &std::path::Path) -> Result<(), ShellError> {
        let text = std::fs::read_to_string(path).map_err(|e| ShellError::Io(e.to_string()))?;
        for line in text.lines().rev() {
            self.push(line);
        }
        Ok(())
    }
}

// ── Tab completion ────────────────────────────────────────────────────────────

/// A completion candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    /// The text to complete to.
    pub text: String,
    /// Optional description shown alongside.
    pub description: String,
    /// Completion kind for display.
    pub kind: CompletionKind,
}

/// Type of a completion candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    Command,
    Argument,
    FilePath,
    Address,
    Symbol,
    Alias,
}

impl fmt::Display for CompletionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command   => f.write_str("cmd"),
            Self::Argument  => f.write_str("arg"),
            Self::FilePath  => f.write_str("file"),
            Self::Address   => f.write_str("addr"),
            Self::Symbol    => f.write_str("sym"),
            Self::Alias     => f.write_str("alias"),
        }
    }
}

/// Tab completion provider.
pub struct Completer {
    /// Registered top-level commands.
    commands: Vec<(String, String)>,   // (name, description)
    /// Known symbols in the loaded binary.
    symbols: Vec<String>,
    /// Custom static completions per command.
    per_command: HashMap<String, Vec<String>>,
}

impl Completer {
    /// Create a completer with built-in commands pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut c = Self {
            commands: Vec::new(),
            symbols: Vec::new(),
            per_command: HashMap::new(),
        };
        c.register_builtins();
        c
    }

    fn register_builtins(&mut self) {
        let builtins = [
            ("help",       "Show help"),
            ("quit",       "Exit the shell"),
            ("exit",       "Exit the shell"),
            ("analyze",    "Analyse a binary"),
            ("disasm",     "Disassemble instructions"),
            ("strings",    "Extract strings"),
            ("symbols",    "List symbols"),
            ("functions",  "List functions"),
            ("info",       "Show binary info"),
            ("hexdump",    "Hex dump memory"),
            ("cross-refs", "Show cross-references"),
            ("decompile",  "Decompile a function"),
            ("history",    "Show command history"),
            ("clear",      "Clear the screen"),
            ("set",        "Set a variable"),
            ("get",        "Get a variable value"),
            ("load",       "Load a binary"),
            ("unload",     "Unload the current binary"),
            ("script",     "Run a script"),
            ("alias",      "Define a command alias"),
            ("unalias",    "Remove a command alias"),
            ("version",    "Print version"),
        ];
        for (name, desc) in &builtins {
            self.commands.push(((*name).into(), (*desc).into()));
        }
    }

    /// Register a new command.
    pub fn register_command(&mut self, name: impl Into<String>, desc: impl Into<String>) {
        self.commands.push((name.into(), desc.into()));
    }

    /// Update the symbol list.
    pub fn set_symbols(&mut self, symbols: Vec<String>) {
        self.symbols = symbols;
    }

    /// Register per-command argument completions.
    pub fn register_args(&mut self, command: impl Into<String>, args: Vec<String>) {
        self.per_command.insert(command.into(), args);
    }

    /// Compute completions for the current `line` up to `cursor`.
    #[must_use]
    pub fn complete(&self, line: &str, cursor: usize) -> Vec<Completion> {
        let prefix = &line[..cursor.min(line.len())];
        let tokens: Vec<&str> = prefix.split_whitespace().collect();

        if tokens.is_empty() || (tokens.len() == 1 && !prefix.ends_with(' ')) {
            // Complete the command name.
            let partial = tokens.first().copied().unwrap_or("");
            return self.complete_command(partial);
        }

        let command = tokens[0];
        let partial = if prefix.ends_with(' ') { "" } else { tokens.last().copied().unwrap_or("") };

        // Per-command completions.
        if let Some(args) = self.per_command.get(command) {
            return args.iter()
                .filter(|a| a.starts_with(partial))
                .map(|a| Completion { text: a.clone(), description: String::new(), kind: CompletionKind::Argument })
                .collect();
        }

        // Symbol completions for commands that take symbol names.
        match command {
            "disasm" | "decompile" | "cross-refs" | "symbols" => {
                self.complete_symbol(partial)
            }
            _ => Vec::new(),
        }
    }

    fn complete_command(&self, partial: &str) -> Vec<Completion> {
        self.commands.iter()
            .filter(|(name, _)| name.starts_with(partial))
            .map(|(name, desc)| Completion {
                text: name.clone(),
                description: desc.clone(),
                kind: CompletionKind::Command,
            })
            .collect()
    }

    fn complete_symbol(&self, partial: &str) -> Vec<Completion> {
        self.symbols.iter()
            .filter(|s| s.starts_with(partial))
            .map(|s| Completion { text: s.clone(), description: String::new(), kind: CompletionKind::Symbol })
            .collect()
    }
}

impl Default for Completer {
    fn default() -> Self { Self::new() }
}

// ── Session state ─────────────────────────────────────────────────────────────

/// Persistent session state for the interactive shell.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// Currently loaded binary path.
    pub binary_path: Option<PathBuf>,
    /// Arbitrary user variables (set by the `set` command).
    pub variables: HashMap<String, String>,
    /// Command aliases.
    pub aliases: HashMap<String, String>,
    /// Timestamp of session start (UNIX seconds).
    pub started_at: u64,
    /// Number of commands executed this session.
    pub command_count: u64,
    /// Monotonic instant of session creation, used for uptime calculation.
    /// Stored separately from `started_at` because `SystemTime` can jump
    /// backwards on NTP corrections; `Instant` is guaranteed monotonic.
    created_instant: Option<std::time::Instant>,
}

impl SessionState {
    /// Create a new session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: unix_now(),
            created_instant: Some(std::time::Instant::now()),
            ..Default::default()
        }
    }

    /// Set a user variable.
    pub fn set_var(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(name.into(), value.into());
    }

    /// Get a user variable.
    #[must_use]
    pub fn get_var(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(String::as_str)
    }

    /// Define an alias (`alias.insert`).
    pub fn set_alias(&mut self, alias: impl Into<String>, command: impl Into<String>) {
        self.aliases.insert(alias.into(), command.into());
    }

    /// Remove an alias.
    pub fn remove_alias(&mut self, alias: &str) -> bool {
        self.aliases.remove(alias).is_some()
    }

    /// Expand an alias if one exists for `name`.
    #[must_use]
    pub fn expand_alias<'a>(&'a self, name: &'a str) -> &'a str {
        self.aliases.get(name).map_or(name, String::as_str)
    }

    /// Session uptime in seconds.
    ///
    /// Uses a monotonic `Instant` (recorded at construction) so that NTP clock
    /// corrections or daylight-saving transitions cannot cause the reported
    /// uptime to jump or go negative.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        match self.created_instant {
            Some(instant) => instant.elapsed().as_secs(),
            // Fallback for states deserialized from disk (no Instant available).
            None => unix_now().saturating_sub(self.started_at),
        }
    }
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

// ── Parsed command line ───────────────────────────────────────────────────────

/// A parsed command with its arguments.
#[derive(Debug, Clone)]
pub struct ParsedLine {
    /// The primary command name (alias-expanded).
    pub command: String,
    /// Positional arguments.
    pub args: Vec<String>,
    /// Flag arguments (e.g. `--json`, `--verbose`).
    pub flags: HashMap<String, Option<String>>,
    /// The original raw line.
    pub raw: String,
}

impl ParsedLine {
    /// Parse a raw line into a `ParsedLine`.
    #[must_use]
    pub fn parse(raw: &str, session: &SessionState) -> Self {
        let raw = raw.trim().to_owned();
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.is_empty() {
            return Self { command: String::new(), args: Vec::new(), flags: HashMap::new(), raw };
        }
        let command_raw = tokens[0];
        let command = session.expand_alias(command_raw).to_owned();

        let mut args = Vec::new();
        let mut flags: HashMap<String, Option<String>> = HashMap::new();
        let mut i = 1;
        while i < tokens.len() {
            let tok = tokens[i];
            if let Some(long) = tok.strip_prefix("--") {
                if let Some((key, val)) = long.split_once('=') {
                    flags.insert(key.into(), Some(val.into()));
                } else if i + 1 < tokens.len() && !tokens[i + 1].starts_with('-') {
                    flags.insert(long.into(), Some(tokens[i + 1].into()));
                    i += 1;
                } else {
                    flags.insert(long.into(), None);
                }
            } else if let Some(short) = tok.strip_prefix('-') {
                for ch in short.chars() {
                    flags.insert(ch.to_string(), None);
                }
            } else {
                args.push(tok.to_owned());
            }
            i += 1;
        }
        Self { command, args, flags, raw }
    }

    /// Return `true` if the flag is present.
    #[must_use]
    pub fn has_flag(&self, name: &str) -> bool { self.flags.contains_key(name) }

    /// Return the value of a `--key=value` flag.
    #[must_use]
    pub fn flag_value(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(Option::as_deref)
    }
}

// ── Built-in command dispatcher ───────────────────────────────────────────────

/// The result of dispatching a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// Continue the session.
    Continue,
    /// Exit the session.
    Exit,
    /// The command produced output (already written to the writer).
    Output(String),
    /// An error occurred.
    Err(ShellError),
}

/// Dispatch a `ParsedLine` to a built-in handler.
pub fn dispatch(line: &ParsedLine, state: &mut SessionState, out: &mut dyn io::Write) -> DispatchResult {
    match line.command.as_str() {
        "" => DispatchResult::Continue,
        "quit" | "exit" | "q" => DispatchResult::Exit,
        "help" | "h" | "?" => {
            dispatch_help(line, out);
            DispatchResult::Continue
        }
        "history" => {
            // history is maintained by the shell; here we just acknowledge.
            let _ = writeln!(out, "(history displayed by shell)");
            DispatchResult::Continue
        }
        "clear" => {
            // Emit ANSI clear screen.
            let _ = write!(out, "\x1b[2J\x1b[H");
            DispatchResult::Continue
        }
        "version" => {
            let _ = writeln!(out, "RustRE interactive shell — session v{}", env!("CARGO_PKG_VERSION"));
            DispatchResult::Continue
        }
        "set" => dispatch_set(line, state, out),
        "get" => dispatch_get(line, state, out),
        "alias" => dispatch_alias(line, state, out),
        "unalias" => dispatch_unalias(line, state, out),
        "load" => {
            if let Some(path) = line.args.first() {
                state.binary_path = Some(PathBuf::from(path));
                let _ = writeln!(out, "loaded: {path}");
            } else {
                let _ = writeln!(out, "usage: load <path>");
            }
            DispatchResult::Continue
        }
        "unload" => {
            state.binary_path = None;
            let _ = writeln!(out, "binary unloaded");
            DispatchResult::Continue
        }
        "info" => {
            if let Some(ref p) = state.binary_path {
                let _ = writeln!(out, "binary: {}", p.display());
                let _ = writeln!(out, "uptime: {}s", state.uptime_secs());
                let _ = writeln!(out, "commands run: {}", state.command_count);
            } else {
                let _ = writeln!(out, "(no binary loaded — use `load <path>`)");
            }
            DispatchResult::Continue
        }
        other => DispatchResult::Err(ShellError::UnknownCommand(other.into())),
    }
}

fn dispatch_help(line: &ParsedLine, out: &mut dyn io::Write) {
    if let Some(topic) = line.args.first() {
        let topic_help = match topic.as_str() {
            "set"     => "set <name> <value>    — Set a shell variable",
            "get"     => "get <name>            — Print a shell variable",
            "alias"   => "alias <name> <cmd>    — Define a command alias",
            "unalias" => "unalias <name>        — Remove an alias",
            "load"    => "load <path>           — Load a binary for analysis",
            "disasm"  => "disasm [addr] [count] — Disassemble instructions",
            _         => "(no help for this topic)",
        };
        let _ = writeln!(out, "{topic_help}");
        return;
    }
    let _ = writeln!(out, "RustRE Interactive Shell");
    let _ = writeln!(out, "  help [topic]   Show help");
    let _ = writeln!(out, "  quit / exit    Exit the shell");
    let _ = writeln!(out, "  version        Print version");
    let _ = writeln!(out, "  load <path>    Load a binary");
    let _ = writeln!(out, "  unload         Unload the binary");
    let _ = writeln!(out, "  info           Show session info");
    let _ = writeln!(out, "  set <k> <v>    Set variable");
    let _ = writeln!(out, "  get <k>        Get variable");
    let _ = writeln!(out, "  alias <a> <c>  Define alias");
    let _ = writeln!(out, "  unalias <a>    Remove alias");
    let _ = writeln!(out, "  history        Show command history");
    let _ = writeln!(out, "  clear          Clear screen");
    let _ = writeln!(out, "  disasm         Disassemble (stub)");
    let _ = writeln!(out, "  strings        List strings (stub)");
    let _ = writeln!(out, "  symbols        List symbols (stub)");
    let _ = writeln!(out, "  functions      List functions (stub)");
}

fn dispatch_set(line: &ParsedLine, state: &mut SessionState, out: &mut dyn io::Write) -> DispatchResult {
    match (line.args.first(), line.args.get(1)) {
        (Some(name), Some(val)) => {
            state.set_var(name.clone(), val.clone());
            let _ = writeln!(out, "{name} = {val}");
            DispatchResult::Continue
        }
        _ => DispatchResult::Err(ShellError::MissingArgument("set <name> <value>".into())),
    }
}

fn dispatch_get(line: &ParsedLine, state: &SessionState, out: &mut dyn io::Write) -> DispatchResult {
    match line.args.first() {
        Some(name) => {
            let val = state.get_var(name).unwrap_or("(unset)");
            let _ = writeln!(out, "{name} = {val}");
            DispatchResult::Continue
        }
        None => DispatchResult::Err(ShellError::MissingArgument("get <name>".into())),
    }
}

fn dispatch_alias(line: &ParsedLine, state: &mut SessionState, out: &mut dyn io::Write) -> DispatchResult {
    match (line.args.first(), line.args.get(1)) {
        (Some(alias), Some(cmd)) => {
            state.set_alias(alias.clone(), cmd.clone());
            let _ = writeln!(out, "alias {alias}={cmd}");
            DispatchResult::Continue
        }
        (None, _) => {
            for (a, c) in &state.aliases {
                let _ = writeln!(out, "  {a} = {c}");
            }
            DispatchResult::Continue
        }
        _ => DispatchResult::Err(ShellError::MissingArgument("alias <name> <command>".into())),
    }
}

fn dispatch_unalias(line: &ParsedLine, state: &mut SessionState, out: &mut dyn io::Write) -> DispatchResult {
    match line.args.first() {
        Some(alias) => {
            if state.remove_alias(alias) {
                let _ = writeln!(out, "removed alias: {alias}");
            } else {
                let _ = writeln!(out, "no such alias: {alias}");
            }
            DispatchResult::Continue
        }
        None => DispatchResult::Err(ShellError::MissingArgument("unalias <name>".into())),
    }
}

// ── Shell driver ──────────────────────────────────────────────────────────────

/// Configuration for the interactive shell.
#[derive(Debug, Clone)]
pub struct ShellConfig {
    /// Prompt string (may contain ANSI codes when `color` is true).
    pub prompt: String,
    /// Enable ANSI colour output.
    pub color: bool,
    /// Maximum history entries.
    pub history_capacity: usize,
    /// Path to persist history across sessions.
    pub history_file: Option<PathBuf>,
    /// Maximum lines before paging (0 = no limit).
    pub page_limit: usize,
    /// Welcome banner.
    pub banner: Option<String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            prompt: "rustre> ".into(),
            color: true,
            history_capacity: 500,
            history_file: None,
            page_limit: 0,
            banner: Some(format!("RustRE {}", env!("CARGO_PKG_VERSION"))),
        }
    }
}

/// The interactive REPL shell.
pub struct InteractiveShell {
    pub config: ShellConfig,
    pub history: History,
    pub state: SessionState,
    pub completer: Completer,
}

impl InteractiveShell {
    /// Create a shell with the given config.
    #[must_use]
    pub fn new(config: ShellConfig) -> Self {
        let history = History::new(config.history_capacity);
        Self {
            config,
            history,
            state: SessionState::new(),
            completer: Completer::new(),
        }
    }

    /// Create with default config.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(ShellConfig::default())
    }

    /// Print the welcome banner.
    pub fn print_banner(&self, out: &mut dyn io::Write) {
        if let Some(ref banner) = self.config.banner {
            let c = |code: &'static str| if self.config.color { code } else { "" };
            let _ = writeln!(out, "{}{}{}{}", c("\x1b[1m"), c("\x1b[36m"), banner, c("\x1b[0m"));
            let _ = writeln!(out, "Type 'help' for available commands.");
        }
    }

    /// Print the prompt.
    pub fn print_prompt(&self, out: &mut dyn io::Write) {
        let c = |code: &'static str| if self.config.color { code } else { "" };
        let binary = self.state.binary_path.as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if binary.is_empty() {
            let _ = write!(out, "{}{}{}", c("\x1b[32m"), self.config.prompt, c("\x1b[0m"));
        } else {
            let _ = write!(out, "{}({}){}{}", c("\x1b[36m"), binary, c("\x1b[0m"), c("\x1b[32m"));
            let _ = write!(out, "{}{}", self.config.prompt, c("\x1b[0m"));
        }
        let _ = out.flush();
    }

    /// Read a line from `stdin`.
    ///
    /// # Errors
    /// Returns `ShellError::Io` on I/O failure, or a special EOF marker.
    pub fn read_line(&mut self) -> Result<Option<String>, ShellError> {
        let mut line = String::new();
        let n = io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| ShellError::Io(e.to_string()))?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
        Ok(Some(trimmed))
    }

    /// Process a single input line.
    ///
    /// Returns `false` when the shell should terminate.
    pub fn process_line(&mut self, raw: &str, out: &mut dyn io::Write) -> bool {
        let raw = raw.trim();
        if raw.is_empty() { return true; }

        self.history.push(raw);
        self.state.command_count += 1;

        let parsed = ParsedLine::parse(raw, &self.state);
        let result = dispatch(&parsed, &mut self.state, out);

        match result {
            DispatchResult::Exit => false,
            DispatchResult::Err(ref e) => {
                let c = |code: &'static str| if self.config.color { code } else { "" };
                let _ = writeln!(out, "{}error:{} {}", c("\x1b[31m"), c("\x1b[0m"), e);
                true
            }
            _ => true,
        }
    }

    /// Run the shell loop until exit.
    ///
    /// Reads from `stdin` and writes to `stdout`.
    pub fn run(&mut self) {
        let mut stdout = io::stdout();
        self.print_banner(&mut stdout);

        loop {
            self.print_prompt(&mut stdout);
            match self.read_line() {
                Ok(Some(line)) => {
                    if !self.process_line(&line, &mut stdout) {
                        break;
                    }
                }
                Ok(None) => break, // EOF
                Err(e) => {
                    eprintln!("shell error: {e}");
                    break;
                }
            }
        }

        if let Some(ref path) = self.config.history_file {
            let _ = self.history.save(path);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_push_and_entries() {
        let mut h = History::new(5);
        h.push("cmd1");
        h.push("cmd2");
        h.push("cmd3");
        assert_eq!(h.len(), 3);
        assert_eq!(h.entries()[0], "cmd3"); // newest first
    }

    #[test]
    fn test_history_dedup() {
        let mut h = History::new(5);
        h.push("cmd1");
        h.push("cmd1");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_capacity() {
        let mut h = History::new(3);
        for i in 0..10 { h.push(format!("cmd{i}")); }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_search() {
        let mut h = History::new(10);
        h.push("analyze foo");
        h.push("disasm 0x1000");
        h.push("analyze bar");
        let results = h.search("analyze");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_history_clear() {
        let mut h = History::new(10);
        h.push("cmd1");
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn test_completer_command() {
        let c = Completer::new();
        let completions = c.complete("he", 2);
        assert!(completions.iter().any(|c| c.text == "help"));
    }

    #[test]
    fn test_completer_symbol() {
        let mut c = Completer::new();
        c.set_symbols(vec!["main".into(), "malloc".into(), "free".into()]);
        let completions = c.complete("disasm ma", 9);
        assert!(completions.iter().any(|c| c.text == "main"));
    }

    #[test]
    fn test_parsed_line_basic() {
        let state = SessionState::new();
        let p = ParsedLine::parse("set foo bar", &state);
        assert_eq!(p.command, "set");
        assert_eq!(p.args, vec!["foo", "bar"]);
    }

    #[test]
    fn test_parsed_line_flags() {
        let state = SessionState::new();
        let p = ParsedLine::parse("disasm --count=10 0x1000", &state);
        assert_eq!(p.command, "disasm");
        assert_eq!(p.flag_value("count"), Some("10"));
        assert_eq!(p.args, vec!["0x1000"]);
    }

    #[test]
    fn test_alias_expand() {
        let mut state = SessionState::new();
        state.set_alias("d", "disasm");
        let p = ParsedLine::parse("d 0x1000", &state);
        assert_eq!(p.command, "disasm");
    }

    #[test]
    fn test_dispatch_set_get() {
        let mut state = SessionState::new();
        let mut buf = Vec::<u8>::new();
        let set_line = ParsedLine::parse("set myvar hello", &state);
        dispatch(&set_line, &mut state, &mut buf);
        assert_eq!(state.get_var("myvar"), Some("hello"));

        let get_line = ParsedLine::parse("get myvar", &state);
        dispatch(&get_line, &mut state, &mut buf);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("hello"));
    }

    #[test]
    fn test_dispatch_quit() {
        let mut state = SessionState::new();
        let mut buf = Vec::<u8>::new();
        let line = ParsedLine::parse("quit", &state);
        let result = dispatch(&line, &mut state, &mut buf);
        assert_eq!(result, DispatchResult::Exit);
    }

    #[test]
    fn test_dispatch_unknown() {
        let mut state = SessionState::new();
        let mut buf = Vec::<u8>::new();
        let line = ParsedLine::parse("frobnicate", &state);
        let result = dispatch(&line, &mut state, &mut buf);
        assert!(matches!(result, DispatchResult::Err(ShellError::UnknownCommand(_))));
    }

    #[test]
    fn test_shell_process_line() {
        let mut shell = InteractiveShell::default_config();
        let mut buf = Vec::<u8>::new();
        assert!(shell.process_line("set x 1", &mut buf));
        assert!(!shell.process_line("exit", &mut buf));
    }

    #[test]
    fn test_session_state_uptime() {
        let state = SessionState::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.uptime_secs() <= 1);
    }
}
