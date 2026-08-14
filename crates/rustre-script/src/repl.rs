//! Interactive REPL for the `RustRE` scripting engine.
//!
//! Provides readline-style line editing with history, tab completion for
//! variable and function names, ANSI syntax highlighting, multiline input
//! support, and a set of built-in REPL commands.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ScriptContext, ScriptError, ScriptValue};

// ── ReplError ─────────────────────────────────────────────────────────────────

/// Errors that can occur inside the REPL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplError {
    /// The user asked to quit the session.
    Quit,
    /// An I/O error occurred while reading input.
    Io(String),
    /// The scripting engine reported an error.
    Script(String),
    /// A REPL command was not recognised.
    UnknownCommand(String),
    /// A history entry index was out of range.
    HistoryOutOfRange { index: usize, len: usize },
    /// The load/save path was invalid.
    InvalidPath(String),
}

impl fmt::Display for ReplError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quit => write!(f, "quit"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Script(msg) => write!(f, "script error: {msg}"),
            Self::UnknownCommand(cmd) => write!(f, "unknown command: {cmd}"),
            Self::HistoryOutOfRange { index, len } => {
                write!(f, "history index {index} out of range (len={len})")
            }
            Self::InvalidPath(p) => write!(f, "invalid path: {p}"),
        }
    }
}

impl std::error::Error for ReplError {}

impl From<ScriptError> for ReplError {
    fn from(e: ScriptError) -> Self {
        Self::Script(e.to_string())
    }
}

// ── ReplCommand ───────────────────────────────────────────────────────────────

/// Built-in REPL meta-commands (prefixed with `.` or `:`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplCommand {
    /// Quit the REPL session (`:quit` / `.q`).
    Quit,
    /// Show help text (`:help` / `.h`).
    Help,
    /// Show the command history (`:history` / `.hist`).
    History,
    /// Clear the screen (`:clear` / `.cls`).
    Clear,
    /// Load a script file and execute it (`:load <path>`).
    Load(String),
    /// Save the current session history to a file (`:save <path>`).
    Save(String),
    /// Reset the session context — clears all variables (`:reset`).
    Reset,
    /// Print all bound variable names and their types (`:vars`).
    Vars,
    /// Evaluate a single expression silently and print its type (`:type <expr>`).
    TypeOf(String),
    /// Toggle verbose output (`:verbose`).
    Verbose,
}

impl ReplCommand {
    /// Try to parse a REPL command from a raw input line.
    ///
    /// Returns `None` if the line is not a meta-command.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        // Accept both `:cmd` and `.cmd` prefixes.
        let line = if let Some(rest) = line.strip_prefix(':') {
            rest
        } else if let Some(rest) = line.strip_prefix('.') {
            rest
        } else {
            return None;
        };

        let mut parts = line.splitn(2, char::is_whitespace);
        let cmd = parts.next().unwrap_or("").trim();
        let arg = parts.next().unwrap_or("").trim();

        let command = match cmd {
            "quit" | "q" | "exit" => Self::Quit,
            "help" | "h" | "?" => Self::Help,
            "history" | "hist" => Self::History,
            "clear" | "cls" => Self::Clear,
            "load" => {
                if arg.is_empty() {
                    return None;
                }
                Self::Load(arg.to_owned())
            }
            "save" => {
                if arg.is_empty() {
                    return None;
                }
                Self::Save(arg.to_owned())
            }
            "reset" => Self::Reset,
            "vars" | "variables" => Self::Vars,
            "type" | "typeof" => Self::TypeOf(arg.to_owned()),
            "verbose" | "v" => Self::Verbose,
            _ => return None,
        };
        Some(command)
    }

    /// Return a short human-readable description for the help text.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Quit => "Quit the REPL session",
            Self::Help => "Show this help message",
            Self::History => "Display the command history",
            Self::Clear => "Clear the terminal screen",
            Self::Load(_) => "Load and execute a script file",
            Self::Save(_) => "Save the session history to a file",
            Self::Reset => "Reset the session context (clears variables)",
            Self::Vars => "List all bound variable names and types",
            Self::TypeOf(_) => "Print the type of an expression",
            Self::Verbose => "Toggle verbose output mode",
        }
    }
}

// ── ANSI colour helpers ───────────────────────────────────────────────────────

/// ANSI colour codes used by the syntax highlighter.
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
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

    /// Wrap `text` in the given ANSI code.
    #[must_use]
    pub fn colorize(code: &str, text: &str) -> String {
        format!("{code}{text}{RESET}")
    }
}

// ── SyntaxHighlighter ─────────────────────────────────────────────────────────

/// Applies ANSI colour codes to a script source line.
///
/// Supports highlighting of:
/// - Language keywords
/// - String literals (single- and double-quoted)
/// - Integer and float literals
/// - Comments (`//`, `#`)
/// - REPL meta-commands
pub struct SyntaxHighlighter {
    /// Keywords that should be highlighted.
    pub keywords: Vec<String>,
    /// Whether ANSI colour output is enabled.
    pub enabled: bool,
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self {
            keywords: vec![
                "let", "fn", "if", "else", "while", "for", "in", "return", "true", "false", "null",
                "and", "or", "not", "break", "continue", "import", "export", "const", "mut",
                "loop", "match", "struct", "enum", "use", "pub", "mod", "type",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            enabled: true,
        }
    }
}

impl SyntaxHighlighter {
    /// Create a highlighter with default keywords.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a disabled (no-colour) highlighter.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Highlight a single input line.
    ///
    /// Returns the original line if colour output is disabled.
    #[must_use]
    pub fn highlight(&self, line: &str) -> String {
        if !self.enabled {
            return line.to_owned();
        }

        // Handle REPL meta-commands
        if line.trim_start().starts_with(':') || line.trim_start().starts_with('.') {
            return ansi::colorize(ansi::MAGENTA, line);
        }

        let mut out = String::with_capacity(line.len() * 2);
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Comment: // or #
            if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
                let rest: String = chars[i..].iter().collect();
                out.push_str(&ansi::colorize(ansi::GREEN, &rest));
                break;
            }
            if chars[i] == '#' {
                let rest: String = chars[i..].iter().collect();
                out.push_str(&ansi::colorize(ansi::GREEN, &rest));
                break;
            }

            // String literals
            if chars[i] == '"' || chars[i] == '\'' {
                let delim = chars[i];
                let start = i;
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2; // skip escape
                    } else if chars[i] == delim {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                let s: String = chars[start..i].iter().collect();
                out.push_str(&ansi::colorize(ansi::YELLOW, &s));
                continue;
            }

            // Number literals
            if chars[i].is_ascii_digit()
                || (chars[i] == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit())
            {
                let start = i;
                if chars[i] == '-' {
                    i += 1;
                }
                while i < chars.len()
                    && (chars[i].is_ascii_digit() || chars[i] == '.' || chars[i] == '_')
                {
                    i += 1;
                }
                let n: String = chars[start..i].iter().collect();
                out.push_str(&ansi::colorize(ansi::CYAN, &n));
                continue;
            }

            // Identifiers / keywords
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if self.keywords.iter().any(|k| k == &word) {
                    out.push_str(&ansi::colorize(ansi::BLUE, &word));
                } else {
                    out.push_str(&word);
                }
                continue;
            }

            // Hex address literals (0x...)
            if chars[i] == '0'
                && i + 1 < chars.len()
                && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            {
                let start = i;
                i += 2;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let hex: String = chars[start..i].iter().collect();
                out.push_str(&ansi::colorize(ansi::BRIGHT_CYAN, &hex));
                continue;
            }

            out.push(chars[i]);
            i += 1;
        }

        out
    }

    /// Add a custom keyword.
    pub fn add_keyword(&mut self, kw: impl Into<String>) {
        self.keywords.push(kw.into());
    }
}

// ── CompletionEngine ──────────────────────────────────────────────────────────

/// Tab-completion engine that suggests variable names, function names, and
/// REPL meta-commands.
#[derive(Debug, Default, Clone)]
pub struct CompletionEngine {
    /// Known variable names (from the session context).
    pub variable_names: Vec<String>,
    /// Known function names (from the engine or module).
    pub function_names: Vec<String>,
    /// REPL meta-command names.
    pub command_names: Vec<String>,
}

impl CompletionEngine {
    /// Create an engine pre-loaded with the standard REPL commands.
    #[must_use]
    pub fn new() -> Self {
        Self {
            variable_names: Vec::new(),
            function_names: Vec::new(),
            command_names: vec![
                ":quit", ":help", ":history", ":clear", ":load", ":save", ":reset", ":vars",
                ":type", ":verbose",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }

    /// Sync variable names from a [`ScriptContext`].
    pub fn sync_from_context(&mut self, ctx: &ScriptContext) {
        self.variable_names = ctx.global_names().into_iter().map(String::from).collect();
        self.function_names = ctx.native_fns.keys().map(String::from).collect();
    }

    /// Return all completions matching `prefix`.
    ///
    /// Completions are drawn from REPL commands (if prefix starts with `:` or
    /// `.`), then function names, then variable names.
    #[must_use]
    pub fn complete(&self, prefix: &str) -> Vec<String> {
        let mut results = Vec::new();

        if prefix.starts_with(':') || prefix.starts_with('.') {
            let norm = prefix.trim_start_matches(':').trim_start_matches('.');
            for cmd in &self.command_names {
                let cmd_norm = cmd.trim_start_matches(':');
                if cmd_norm.starts_with(norm) {
                    results.push(cmd.clone());
                }
            }
            return results;
        }

        for name in &self.function_names {
            if name.starts_with(prefix) {
                results.push(name.clone());
            }
        }
        for name in &self.variable_names {
            if name.starts_with(prefix) {
                results.push(name.clone());
            }
        }

        results.sort();
        results.dedup();
        results
    }

    /// Return a single best completion, or `None` if there is no unique match.
    #[must_use]
    pub fn complete_single(&self, prefix: &str) -> Option<String> {
        let mut c = self.complete(prefix);
        if c.len() == 1 { c.pop() } else { None }
    }

    /// Return the longest common prefix of all completions.
    #[must_use]
    pub fn longest_common_prefix(&self, prefix: &str) -> String {
        let completions = self.complete(prefix);
        if completions.is_empty() {
            return prefix.to_owned();
        }
        let first = &completions[0];
        let mut len = first.len();
        for other in &completions[1..] {
            len = len.min(
                first
                    .chars()
                    .zip(other.chars())
                    .take_while(|(a, b)| a == b)
                    .count(),
            );
        }
        first[..len].to_owned()
    }
}

// ── ReplHistoryEntry ──────────────────────────────────────────────────────────

/// A single entry in the REPL history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplHistoryEntry {
    /// The raw input line(s) entered by the user.
    pub input: String,
    /// The display value of the result (if any).
    pub result_display: Option<String>,
    /// Whether the entry produced an error.
    pub had_error: bool,
}

impl ReplHistoryEntry {
    /// Create a successful entry.
    #[must_use]
    pub fn success(input: impl Into<String>, result: Option<String>) -> Self {
        Self {
            input: input.into(),
            result_display: result,
            had_error: false,
        }
    }

    /// Create a failed entry.
    #[must_use]
    pub fn error(input: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            result_display: None,
            had_error: true,
        }
    }
}

// ── OutputFormatter ───────────────────────────────────────────────────────────

/// Formats a [`ScriptValue`] for human-readable REPL output.
pub struct OutputFormatter {
    /// Maximum depth for nested collections.
    pub max_depth: usize,
    /// Maximum number of items to show in a list before truncating.
    pub max_list_items: usize,
    /// Whether to use ANSI colour codes.
    pub coloured: bool,
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_list_items: 20,
            coloured: true,
        }
    }
}

impl OutputFormatter {
    /// Create a formatter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Format `value` at indent depth `depth`.
    #[must_use]
    pub fn format(&self, value: &ScriptValue) -> String {
        self.format_depth(value, 0)
    }

    fn format_depth(&self, value: &ScriptValue, depth: usize) -> String {
        if depth > self.max_depth {
            return if self.coloured {
                ansi::colorize(ansi::WHITE, "...")
            } else {
                "...".to_owned()
            };
        }
        match value {
            ScriptValue::Null => {
                if self.coloured {
                    ansi::colorize(ansi::WHITE, "null")
                } else {
                    "null".into()
                }
            }
            ScriptValue::Bool(b) => {
                let s = b.to_string();
                if self.coloured {
                    ansi::colorize(ansi::BLUE, &s)
                } else {
                    s
                }
            }
            ScriptValue::Int(n) => {
                let s = n.to_string();
                if self.coloured {
                    ansi::colorize(ansi::CYAN, &s)
                } else {
                    s
                }
            }
            ScriptValue::Float(f) => {
                let s = f.to_string();
                if self.coloured {
                    ansi::colorize(ansi::CYAN, &s)
                } else {
                    s
                }
            }
            ScriptValue::String(s) => {
                let quoted = format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
                if self.coloured {
                    ansi::colorize(ansi::YELLOW, &quoted)
                } else {
                    quoted
                }
            }
            ScriptValue::Bytes(b) => {
                let hex: String = b.iter().take(32).fold(String::new(), |mut acc, x| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{x:02x}");
                    acc
                });
                let suffix = if b.len() > 32 {
                    format!("... ({} bytes total)", b.len())
                } else {
                    format!(" ({} bytes)", b.len())
                };
                let s = format!("0x{hex}{suffix}");
                if self.coloured {
                    ansi::colorize(ansi::BRIGHT_CYAN, &s)
                } else {
                    s
                }
            }
            ScriptValue::Address(a) => {
                let s = format!("0x{a:x}");
                if self.coloured {
                    ansi::colorize(ansi::BRIGHT_YELLOW, &s)
                } else {
                    s
                }
            }
            ScriptValue::Callable(name) => {
                let s = format!("<fn:{name}>");
                if self.coloured {
                    ansi::colorize(ansi::MAGENTA, &s)
                } else {
                    s
                }
            }
            ScriptValue::List(items) => {
                if items.is_empty() {
                    return "[]".to_owned();
                }
                let show = items.len().min(self.max_list_items);
                let parts: Vec<String> = items[..show]
                    .iter()
                    .map(|v| self.format_depth(v, depth + 1))
                    .collect();
                let truncated = if items.len() > self.max_list_items {
                    format!(", ... ({} more)", items.len() - self.max_list_items)
                } else {
                    String::new()
                };
                format!("[{}{}]", parts.join(", "), truncated)
            }
            ScriptValue::Map(m) => {
                if m.is_empty() {
                    return "{}".to_owned();
                }
                let mut keys: Vec<&str> = m.keys().map(String::as_str).collect();
                keys.sort_unstable();
                let show = keys.len().min(self.max_list_items);
                let parts: Vec<String> = keys[..show]
                    .iter()
                    .map(|k| {
                        let key = if self.coloured {
                            ansi::colorize(ansi::BRIGHT_GREEN, k)
                        } else {
                            (*k).to_owned()
                        };
                        format!("{}: {}", key, self.format_depth(&m[*k], depth + 1))
                    })
                    .collect();
                let truncated = if keys.len() > self.max_list_items {
                    format!(", ... ({} more)", keys.len() - self.max_list_items)
                } else {
                    String::new()
                };
                format!("{{{}{}}}", parts.join(", "), truncated)
            }
        }
    }

    /// Format the type annotation for a value.
    #[must_use]
    pub fn format_type(&self, value: &ScriptValue) -> String {
        let t = value.type_name();
        if self.coloured {
            ansi::colorize(ansi::MAGENTA, t)
        } else {
            t.to_owned()
        }
    }
}

// ── ReplSession ───────────────────────────────────────────────────────────────

/// Persistent REPL session context. Maintains variable bindings, history,
/// and configuration across multiple line evaluations.
pub struct ReplSession {
    /// Underlying scripting context (globals, native functions).
    pub context: ScriptContext,
    /// Command history (bounded).
    pub history: VecDeque<ReplHistoryEntry>,
    /// Maximum number of history entries to keep.
    pub max_history: usize,
    /// Whether verbose mode is on (prints evaluation timing).
    pub verbose: bool,
    /// ANSI syntax highlighter.
    pub highlighter: SyntaxHighlighter,
    /// Tab-completion engine.
    pub completion: CompletionEngine,
    /// Value formatter.
    pub formatter: OutputFormatter,
    /// Number of evaluations performed.
    pub eval_count: u64,
    /// User-defined session variables (separate from script globals).
    pub session_vars: HashMap<String, ScriptValue>,
    /// Accumulated multiline input buffer.
    multiline_buf: Vec<String>,
}

impl Default for ReplSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplSession {
    /// Create a new empty REPL session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: ScriptContext::new(),
            history: VecDeque::new(),
            max_history: 1000,
            verbose: false,
            highlighter: SyntaxHighlighter::new(),
            completion: CompletionEngine::new(),
            formatter: OutputFormatter::new(),
            eval_count: 0,
            session_vars: HashMap::new(),
            multiline_buf: Vec::new(),
        }
    }

    /// Record a history entry, evicting the oldest if the buffer is full.
    pub fn push_history(&mut self, entry: ReplHistoryEntry) {
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(entry);
    }

    /// Retrieve a history entry by 1-based index.
    ///
    /// # Errors
    /// Returns [`ReplError::HistoryOutOfRange`] if index is out of bounds.
    pub fn get_history(&self, index: usize) -> Result<&ReplHistoryEntry, ReplError> {
        let len = self.history.len();
        if index == 0 || index > len {
            return Err(ReplError::HistoryOutOfRange { index, len });
        }
        Ok(&self.history[index - 1])
    }

    /// Return the last successfully entered (non-error) input, if any.
    #[must_use]
    pub fn last_input(&self) -> Option<&str> {
        self.history
            .iter()
            .rev()
            .find(|e| !e.had_error)
            .map(|e| e.input.as_str())
    }

    /// Reset the session: clear globals, history, and the multiline buffer.
    pub fn reset(&mut self) {
        self.context = ScriptContext::new();
        self.history.clear();
        self.multiline_buf.clear();
        self.session_vars.clear();
        self.eval_count = 0;
    }

    /// Handle a single line of user input. Returns a `ReplAction` to the caller.
    ///
    /// This is the main entry point used by the outer I/O loop (see [`Repl`]).
    pub fn handle_line(&mut self, line: &str) -> ReplAction {
        let trimmed = line.trim();

        // Try to parse as a REPL meta-command first.
        if let Some(cmd) = ReplCommand::parse(trimmed) {
            return ReplAction::Command(cmd);
        }

        // Multiline continuation: if line ends with `\`, buffer it.
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            self.multiline_buf.push(stripped.to_owned());
            return ReplAction::Continuation;
        }

        // Check for open brackets / parentheses suggesting incomplete input.
        let full_input = if self.multiline_buf.is_empty() {
            trimmed.to_owned()
        } else {
            let mut buf = self.multiline_buf.join("\n");
            buf.push('\n');
            buf.push_str(trimmed);
            self.multiline_buf.clear();
            buf
        };

        if is_expression_incomplete(&full_input) {
            self.multiline_buf.push(full_input);
            return ReplAction::Continuation;
        }

        self.eval_count += 1;
        ReplAction::Evaluate(full_input)
    }

    /// Whether the session is waiting for multiline continuation.
    #[must_use]
    pub const fn in_multiline(&self) -> bool {
        !self.multiline_buf.is_empty()
    }

    /// Discard the current multiline buffer (e.g. user pressed Ctrl-C).
    pub fn cancel_multiline(&mut self) {
        self.multiline_buf.clear();
    }

    /// Sync completion engine from the current context.
    pub fn sync_completion(&mut self) {
        self.completion.sync_from_context(&self.context);
    }

    /// Serialize the history to a newline-delimited string.
    #[must_use]
    pub fn history_to_string(&self) -> String {
        self.history
            .iter()
            .map(|e| e.input.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Number of history entries.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

// ── ReplAction ────────────────────────────────────────────────────────────────

/// Action returned by [`ReplSession::handle_line`] to the outer I/O loop.
#[derive(Debug, Clone)]
pub enum ReplAction {
    /// The user entered a complete expression to evaluate.
    Evaluate(String),
    /// The user entered a REPL meta-command.
    Command(ReplCommand),
    /// The input was incomplete — request another line.
    Continuation,
    /// The input was empty — do nothing.
    Empty,
}

// ── Repl ──────────────────────────────────────────────────────────────────────

/// The top-level REPL object. Owns a [`ReplSession`] and implements the
/// control loop for processing input events.
pub struct Repl {
    /// The current session.
    pub session: ReplSession,
    /// REPL prompt string for regular input.
    pub prompt: String,
    /// REPL prompt string for multiline continuation.
    pub continuation_prompt: String,
    /// Whether the REPL is active.
    pub running: bool,
    /// Lines of output produced by the last evaluation.
    pub last_output: Vec<String>,
}

impl Default for Repl {
    fn default() -> Self {
        Self::new()
    }
}

impl Repl {
    /// Create a REPL with the default `>>> ` prompt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: ReplSession::new(),
            prompt: ">>> ".to_owned(),
            continuation_prompt: "... ".to_owned(),
            running: true,
            last_output: Vec::new(),
        }
    }

    /// Return the current prompt string (depends on multiline state).
    #[must_use]
    pub fn current_prompt(&self) -> &str {
        if self.session.in_multiline() {
            &self.continuation_prompt
        } else {
            &self.prompt
        }
    }

    /// Feed a line of input to the REPL and return the resulting output lines.
    ///
    /// This is the primary method called by the I/O loop.
    pub fn feed(&mut self, line: &str) -> Vec<String> {
        if line.trim().is_empty() {
            return Vec::new();
        }

        let action = self.session.handle_line(line);
        match action {
            ReplAction::Empty | ReplAction::Continuation => Vec::new(),
            ReplAction::Command(cmd) => self.handle_command(cmd),
            ReplAction::Evaluate(code) => {
                let highlighted = self.session.highlighter.highlight(&code);
                let mut out = vec![highlighted];
                // In a real integration, eval happens here. We simulate it.
                let result = self.simulate_eval(&code);
                match result {
                    Ok(value) => {
                        let formatted = self.session.formatter.format(&value);
                        let type_str = self.session.formatter.format_type(&value);
                        let line = format!("= {formatted}  : {type_str}");
                        out.push(line.clone());
                        self.session
                            .push_history(ReplHistoryEntry::success(&code, Some(line)));
                        self.session.sync_completion();
                    }
                    Err(e) => {
                        let err_line = if self.session.highlighter.enabled {
                            ansi::colorize(ansi::BRIGHT_RED, &format!("error: {e}"))
                        } else {
                            format!("error: {e}")
                        };
                        out.push(err_line);
                        self.session.push_history(ReplHistoryEntry::error(&code));
                    }
                }
                self.last_output.clone_from(&out);
                out
            }
        }
    }

    /// Simulate evaluation (placeholder — real engines implement `ScriptEngine`).
    const fn simulate_eval(&self, _code: &str) -> Result<ScriptValue, ScriptError> {
        // Placeholder: returns Null. Real integrations call the engine.
        Ok(ScriptValue::Null)
    }

    /// Handle a REPL meta-command, returning output lines.
    fn handle_command(&mut self, cmd: ReplCommand) -> Vec<String> {
        match cmd {
            ReplCommand::Quit => {
                self.running = false;
                vec!["Goodbye.".to_owned()]
            }
            ReplCommand::Help => {
                let commands = [
                    (":quit / .q", "Quit the REPL"),
                    (":help / .h", "Show this help"),
                    (":history", "Show command history"),
                    (":clear", "Clear the screen"),
                    (":load <f>", "Load and execute a script file"),
                    (":save <f>", "Save history to a file"),
                    (":reset", "Reset session variables"),
                    (":vars", "List all bound variables"),
                    (":type <e>", "Print the type of an expression"),
                    (":verbose", "Toggle verbose timing output"),
                ];
                let mut out = vec!["RustRE REPL — built-in commands:".to_owned()];
                for (name, desc) in &commands {
                    out.push(format!("  {name:<18} {desc}"));
                }
                out
            }
            ReplCommand::History => {
                if self.session.history.is_empty() {
                    return vec!["(history is empty)".to_owned()];
                }
                self.session
                    .history
                    .iter()
                    .enumerate()
                    .map(|(i, e)| format!("{:>4}  {}", i + 1, e.input))
                    .collect()
            }
            ReplCommand::Clear => vec!["\x1b[2J\x1b[H".to_owned()],
            ReplCommand::Load(path) => {
                vec![format!("(load {path} — not implemented in stub)")]
            }
            ReplCommand::Save(path) => {
                let text = self.session.history_to_string();
                match std::fs::write(&path, text) {
                    Ok(()) => vec![format!("History saved to {path}")],
                    Err(e) => vec![format!("error saving: {e}")],
                }
            }
            ReplCommand::Reset => {
                self.session.reset();
                vec!["Session reset.".to_owned()]
            }
            ReplCommand::Vars => {
                let names = self.session.context.global_names();
                if names.is_empty() {
                    return vec!["(no variables bound)".to_owned()];
                }
                let mut sorted = names;
                sorted.sort_unstable();
                sorted.iter().map(|n| format!("  {n}")).collect::<Vec<_>>()
            }
            ReplCommand::TypeOf(expr) => {
                if expr.is_empty() {
                    return vec!["usage: :type <expression>".to_owned()];
                }
                vec![format!("(typeof '{expr}' — not implemented in stub)")]
            }
            ReplCommand::Verbose => {
                self.session.verbose = !self.session.verbose;
                vec![format!("Verbose: {}", self.session.verbose)]
            }
        }
    }

    /// Return `true` if the REPL is still running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }
}

// ── Multiline detection ───────────────────────────────────────────────────────

/// Detect whether `code` is likely an incomplete expression (more input needed).
///
/// Checks for unbalanced brackets, parentheses, and braces.
#[must_use]
pub fn is_expression_incomplete(code: &str) -> bool {
    let mut depth_paren = 0i32;
    let mut depth_bracket = 0i32;
    let mut depth_brace = 0i32;
    let mut in_string = false;
    let mut string_delim = '"';
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == string_delim {
                in_string = false;
            }
        } else {
            match c {
                '"' | '\'' => {
                    in_string = true;
                    string_delim = c;
                }
                '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                    // Line comment — skip rest of line
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                    continue;
                }
                '(' => depth_paren += 1,
                ')' => depth_paren -= 1,
                '[' => depth_bracket += 1,
                ']' => depth_bracket -= 1,
                '{' => depth_brace += 1,
                '}' => depth_brace -= 1,
                _ => {}
            }
        }
        i += 1;
    }

    in_string || depth_paren > 0 || depth_bracket > 0 || depth_brace > 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReplCommand parsing ───────────────────────────────────────────────────

    #[test]
    fn test_parse_quit_colon() {
        assert_eq!(ReplCommand::parse(":quit"), Some(ReplCommand::Quit));
    }

    #[test]
    fn test_parse_quit_dot() {
        assert_eq!(ReplCommand::parse(".q"), Some(ReplCommand::Quit));
    }

    #[test]
    fn test_parse_help() {
        assert_eq!(ReplCommand::parse(":help"), Some(ReplCommand::Help));
        assert_eq!(ReplCommand::parse(".h"), Some(ReplCommand::Help));
        assert_eq!(ReplCommand::parse(":?"), Some(ReplCommand::Help));
    }

    #[test]
    fn test_parse_history() {
        assert_eq!(ReplCommand::parse(":history"), Some(ReplCommand::History));
        assert_eq!(ReplCommand::parse(":hist"), Some(ReplCommand::History));
    }

    #[test]
    fn test_parse_clear() {
        assert_eq!(ReplCommand::parse(":clear"), Some(ReplCommand::Clear));
        assert_eq!(ReplCommand::parse(".cls"), Some(ReplCommand::Clear));
    }

    #[test]
    fn test_parse_load() {
        assert_eq!(
            ReplCommand::parse(":load my_script.rhai"),
            Some(ReplCommand::Load("my_script.rhai".to_owned()))
        );
    }

    #[test]
    fn test_parse_save() {
        assert_eq!(
            ReplCommand::parse(":save output.txt"),
            Some(ReplCommand::Save("output.txt".to_owned()))
        );
    }

    #[test]
    fn test_parse_reset() {
        assert_eq!(ReplCommand::parse(":reset"), Some(ReplCommand::Reset));
    }

    #[test]
    fn test_parse_vars() {
        assert_eq!(ReplCommand::parse(":vars"), Some(ReplCommand::Vars));
    }

    #[test]
    fn test_parse_typeof() {
        match ReplCommand::parse(":type 42") {
            Some(ReplCommand::TypeOf(expr)) => assert_eq!(expr, "42"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_parse_verbose() {
        assert_eq!(ReplCommand::parse(":verbose"), Some(ReplCommand::Verbose));
    }

    #[test]
    fn test_parse_unknown_returns_none() {
        assert_eq!(ReplCommand::parse(":unknown_xyz"), None);
    }

    #[test]
    fn test_parse_plain_code_returns_none() {
        assert_eq!(ReplCommand::parse("let x = 1;"), None);
        assert_eq!(ReplCommand::parse("x + 1"), None);
    }

    // ── SyntaxHighlighter ─────────────────────────────────────────────────────

    #[test]
    fn test_highlighter_disabled_passthrough() {
        let h = SyntaxHighlighter::disabled();
        assert_eq!(h.highlight("let x = 1;"), "let x = 1;");
    }

    #[test]
    fn test_highlighter_enabled_contains_ansi() {
        let h = SyntaxHighlighter::new();
        let out = h.highlight("let x = 1;");
        // Should contain the ANSI reset code somewhere.
        assert!(out.contains('\x1b'), "expected ANSI codes in: {out}");
    }

    #[test]
    fn test_highlighter_meta_command() {
        let h = SyntaxHighlighter::new();
        let out = h.highlight(":quit");
        assert!(out.contains('\x1b'));
    }

    #[test]
    fn test_highlighter_comment_line() {
        let h = SyntaxHighlighter::new();
        let out = h.highlight("// this is a comment");
        // Comment should be coloured (contains ANSI)
        assert!(out.contains('\x1b'));
    }

    #[test]
    fn test_highlighter_add_keyword() {
        let mut h = SyntaxHighlighter::new();
        h.add_keyword("my_keyword");
        assert!(h.keywords.contains(&"my_keyword".to_owned()));
    }

    // ── CompletionEngine ──────────────────────────────────────────────────────

    #[test]
    fn test_completion_engine_new() {
        let e = CompletionEngine::new();
        assert!(!e.command_names.is_empty());
    }

    #[test]
    fn test_completion_command_prefix() {
        let e = CompletionEngine::new();
        let c = e.complete(":q");
        assert!(c.iter().any(|s| s == ":quit"), "completions: {c:?}");
    }

    #[test]
    fn test_completion_function_name() {
        let mut e = CompletionEngine::new();
        e.function_names = vec!["hex_to_bytes".into(), "bytes_to_hex".into()];
        let c = e.complete("hex");
        assert!(c.iter().any(|s| s == "hex_to_bytes"), "{c:?}");
    }

    #[test]
    fn test_completion_variable_name() {
        let mut e = CompletionEngine::new();
        e.variable_names = vec!["my_var".into(), "my_other".into()];
        let c = e.complete("my_");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn test_complete_single_unique() {
        let mut e = CompletionEngine::new();
        e.function_names = vec!["unique_fn".into()];
        assert_eq!(e.complete_single("unique"), Some("unique_fn".to_owned()));
    }

    #[test]
    fn test_complete_single_ambiguous_returns_none() {
        let mut e = CompletionEngine::new();
        e.function_names = vec!["foo_a".into(), "foo_b".into()];
        assert_eq!(e.complete_single("foo"), None);
    }

    #[test]
    fn test_longest_common_prefix() {
        let mut e = CompletionEngine::new();
        e.function_names = vec!["foo_alpha".into(), "foo_beta".into()];
        let lcp = e.longest_common_prefix("foo");
        assert_eq!(lcp, "foo_");
    }

    // ── OutputFormatter ───────────────────────────────────────────────────────

    #[test]
    fn test_formatter_null() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::Null), "null");
    }

    #[test]
    fn test_formatter_bool() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::Bool(true)), "true");
        assert_eq!(f.format(&ScriptValue::Bool(false)), "false");
    }

    #[test]
    fn test_formatter_int() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::Int(42)), "42");
    }

    #[test]
    fn test_formatter_string_quoted() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::String("hello".into())), "\"hello\"");
    }

    #[test]
    fn test_formatter_address() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::Address(0xDEAD)), "0xdead");
    }

    #[test]
    fn test_formatter_list() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        let v = ScriptValue::List(vec![ScriptValue::Int(1), ScriptValue::Int(2)]);
        assert_eq!(f.format(&v), "[1, 2]");
    }

    #[test]
    fn test_formatter_empty_list() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(f.format(&ScriptValue::List(vec![])), "[]");
    }

    #[test]
    fn test_formatter_empty_map() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        assert_eq!(
            f.format(&ScriptValue::Map(std::collections::HashMap::new())),
            "{}"
        );
    }

    #[test]
    fn test_formatter_bytes_short() {
        let f = OutputFormatter {
            coloured: false,
            ..OutputFormatter::new()
        };
        let out = f.format(&ScriptValue::Bytes(vec![0xDE, 0xAD]));
        assert!(out.contains("dead"), "{out}");
    }

    // ── ReplSession ───────────────────────────────────────────────────────────

    #[test]
    fn test_session_push_and_get_history() {
        let mut s = ReplSession::new();
        s.push_history(ReplHistoryEntry::success("let x = 1", None));
        let e = s.get_history(1).unwrap();
        assert_eq!(e.input, "let x = 1");
    }

    #[test]
    fn test_session_history_overflow_evicts_oldest() {
        let mut s = ReplSession::new();
        s.max_history = 3;
        for i in 0..5 {
            s.push_history(ReplHistoryEntry::success(format!("line {i}"), None));
        }
        assert_eq!(s.history_len(), 3);
    }

    #[test]
    fn test_session_reset_clears_history() {
        let mut s = ReplSession::new();
        s.push_history(ReplHistoryEntry::success("x", None));
        s.reset();
        assert_eq!(s.history_len(), 0);
    }

    #[test]
    fn test_session_multiline_continuation() {
        let mut s = ReplSession::new();
        let action = s.handle_line("let x = (");
        assert!(matches!(
            action,
            ReplAction::Continuation | ReplAction::Evaluate(_)
        ));
    }

    #[test]
    fn test_session_command_action() {
        let mut s = ReplSession::new();
        let action = s.handle_line(":quit");
        assert!(matches!(action, ReplAction::Command(ReplCommand::Quit)));
    }

    #[test]
    fn test_session_in_multiline_false_initially() {
        let s = ReplSession::new();
        assert!(!s.in_multiline());
    }

    #[test]
    fn test_session_cancel_multiline() {
        let mut s = ReplSession::new();
        s.multiline_buf.push("partial".to_owned());
        s.cancel_multiline();
        assert!(!s.in_multiline());
    }

    // ── Multiline detection ───────────────────────────────────────────────────

    #[test]
    fn test_incomplete_open_paren() {
        assert!(is_expression_incomplete("fn foo("));
    }

    #[test]
    fn test_incomplete_open_bracket() {
        assert!(is_expression_incomplete("[1, 2,"));
    }

    #[test]
    fn test_incomplete_open_brace() {
        assert!(is_expression_incomplete("let m = {"));
    }

    #[test]
    fn test_complete_balanced() {
        assert!(!is_expression_incomplete("let x = (1 + 2);"));
    }

    #[test]
    fn test_complete_empty_string() {
        assert!(!is_expression_incomplete(""));
    }

    #[test]
    fn test_incomplete_open_string() {
        assert!(is_expression_incomplete("let s = \"hello"));
    }

    // ── Repl integration ──────────────────────────────────────────────────────

    #[test]
    fn test_repl_feed_quit_command() {
        let mut r = Repl::new();
        let out = r.feed(":quit");
        assert!(!r.is_running());
        assert!(!out.is_empty());
    }

    #[test]
    fn test_repl_feed_help() {
        let mut r = Repl::new();
        let out = r.feed(":help");
        assert!(!out.is_empty());
    }

    #[test]
    fn test_repl_feed_history_empty() {
        let mut r = Repl::new();
        let out = r.feed(":history");
        assert_eq!(out, vec!["(history is empty)"]);
    }

    #[test]
    fn test_repl_feed_reset() {
        let mut r = Repl::new();
        let out = r.feed(":reset");
        assert!(!out.is_empty());
    }

    #[test]
    fn test_repl_prompt_regular() {
        let r = Repl::new();
        assert_eq!(r.current_prompt(), ">>> ");
    }

    #[test]
    fn test_repl_is_running_initially() {
        let r = Repl::new();
        assert!(r.is_running());
    }

    // ── ReplHistoryEntry ──────────────────────────────────────────────────────

    #[test]
    fn test_history_entry_success() {
        let e = ReplHistoryEntry::success("code", Some("result".into()));
        assert!(!e.had_error);
        assert_eq!(e.input, "code");
        assert_eq!(e.result_display.as_deref(), Some("result"));
    }

    #[test]
    fn test_history_entry_error() {
        let e = ReplHistoryEntry::error("bad code");
        assert!(e.had_error);
        assert!(e.result_display.is_none());
    }
}
