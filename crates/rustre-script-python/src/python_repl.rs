// python_repl.rs — Python REPL with persistent state and history.
// Implements a read-eval-print loop over the pure-Rust Python interpreter,
// with command history, completion hints, multi-line input buffering, and
// introspection helpers.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ── Completion hints ──────────────────────────────────────────────────────────

/// A single completion suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionHint {
    pub text: String,
    pub kind: CompletionKind,
    pub doc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionKind {
    Variable,
    Function,
    Keyword,
    Module,
    Attribute,
    Builtin,
}

impl fmt::Display for CompletionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Variable => write!(f, "var"),
            Self::Function => write!(f, "fn"),
            Self::Keyword => write!(f, "kw"),
            Self::Module => write!(f, "mod"),
            Self::Attribute => write!(f, "attr"),
            Self::Builtin => write!(f, "builtin"),
        }
    }
}

impl CompletionHint {
    pub fn var(text: impl Into<String>) -> Self {
        Self { text: text.into(), kind: CompletionKind::Variable, doc: None }
    }

    pub fn func(text: impl Into<String>, doc: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: CompletionKind::Function,
            doc: Some(doc.into()),
        }
    }

    pub fn keyword(text: impl Into<String>) -> Self {
        Self { text: text.into(), kind: CompletionKind::Keyword, doc: None }
    }

    pub fn builtin(text: impl Into<String>) -> Self {
        Self { text: text.into(), kind: CompletionKind::Builtin, doc: None }
    }
}

// ── Command history ───────────────────────────────────────────────────────────

/// Bounded ring-buffer of previously executed commands.
#[derive(Debug, Clone)]
pub struct CommandHistory {
    entries: VecDeque<String>,
    max_size: usize,
    cursor: Option<usize>,
}

impl CommandHistory {
    #[must_use] 
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_size: max_size.max(1),
            cursor: None,
        }
    }

    pub fn push(&mut self, cmd: impl Into<String>) {
        let s = cmd.into();
        if s.trim().is_empty() {
            return;
        }
        // Deduplicate adjacent identical entries.
        if self.entries.front().is_some_and(|e| e == &s) {
            return;
        }
        if self.entries.len() >= self.max_size {
            self.entries.pop_back();
        }
        self.entries.push_front(s);
        self.cursor = None;
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub fn get(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(std::string::String::as_str)
    }

    /// Navigate backward (older entries).
    pub fn prev(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let next = match self.cursor {
            None => 0,
            Some(c) => (c + 1).min(self.entries.len() - 1),
        };
        self.cursor = Some(next);
        self.entries.get(next).map(std::string::String::as_str)
    }

    /// Navigate forward (newer entries).
    pub fn forward(&mut self) -> Option<&str> {
        match self.cursor {
            None | Some(0) => {
                self.cursor = None;
                None
            }
            Some(c) => {
                self.cursor = Some(c - 1);
                self.entries.get(c - 1).map(std::string::String::as_str)
            }
        }
    }

    pub const fn reset_cursor(&mut self) {
        self.cursor = None;
    }

    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(std::string::String::as_str)
    }

    /// Search backward for an entry containing `query`.
    #[must_use] 
    pub fn search(&self, query: &str) -> Option<&str> {
        self.entries.iter().find(|e| e.contains(query)).map(std::string::String::as_str)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = None;
    }
}

// ── REPL state ────────────────────────────────────────────────────────────────

/// The mutable state carried across REPL iterations.
#[derive(Debug, Clone, Default)]
pub struct ReplState {
    /// Named variables visible in the REPL scope.
    pub variables: HashMap<String, String>,
    /// Imported module names.
    pub imports: Vec<String>,
    /// Accumulated output lines from the session.
    pub output_lines: Vec<String>,
    /// Session-level error count.
    pub error_count: u32,
    /// Total lines executed.
    pub lines_executed: u64,
    /// Whether the interpreter is in a multi-line block.
    pub in_block: bool,
    /// Buffered lines for a multi-line statement.
    pub block_buffer: Vec<String>,
    /// Block indentation level (for pretty printing continuation prompt).
    pub block_indent: usize,
}

impl ReplState {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_var(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(name.into(), value.into());
    }

    #[must_use] 
    pub fn get_var(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(std::string::String::as_str)
    }

    pub fn del_var(&mut self, name: &str) -> bool {
        self.variables.remove(name).is_some()
    }

    pub fn add_import(&mut self, module: impl Into<String>) {
        let m = module.into();
        if !self.imports.contains(&m) {
            self.imports.push(m);
        }
    }

    pub fn push_output(&mut self, line: impl Into<String>) {
        self.output_lines.push(line.into());
    }

    /// Begin a multi-line block.
    pub fn begin_block(&mut self, first_line: impl Into<String>) {
        self.in_block = true;
        self.block_buffer.clear();
        let line = first_line.into();
        // Infer indent from trailing colon.
        self.block_indent = line.len() - line.trim_start().len() + 4;
        self.block_buffer.push(line);
    }

    /// Add a continuation line to the current block.
    pub fn append_block(&mut self, line: impl Into<String>) {
        self.block_buffer.push(line.into());
    }

    /// Complete the block and return the assembled source.
    pub fn finish_block(&mut self) -> String {
        self.in_block = false;
        let src = self.block_buffer.join("\n");
        self.block_buffer.clear();
        self.block_indent = 0;
        src
    }

    #[must_use] 
    pub fn is_block_complete(&self, line: &str) -> bool {
        line.trim().is_empty() && self.in_block
    }

    #[must_use] 
    pub fn continuation_prompt(&self) -> String {
        format!("{}... ", " ".repeat(self.block_indent.saturating_sub(4)))
    }

    #[must_use] 
    pub fn var_names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.variables.keys().map(std::string::String::as_str).collect();
        v.sort_unstable();
        v
    }
}

// ── REPL result ───────────────────────────────────────────────────────────────

/// The result of evaluating a single REPL input line.
#[derive(Debug, Clone)]
pub enum ReplResult {
    /// Expression evaluated to a value (display it).
    Value(String),
    /// Statement executed with no display value.
    Ok,
    /// Collecting more input for a multi-line block.
    Incomplete,
    /// Python error in user code.
    Error { error_type: String, message: String, line: Option<u32> },
    /// Sandbox policy violation.
    SecurityError(String),
    /// Special REPL command (e.g. `%reset`, `%history`).
    CommandResult(String),
    /// Session should exit.
    Exit,
}

impl ReplResult {
    #[must_use] 
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. } | Self::SecurityError(_))
    }

    #[must_use] 
    pub const fn display_str(&self) -> Option<&str> {
        match self {
            Self::Value(v) => Some(v.as_str()),
            Self::CommandResult(s) | Self::SecurityError(s) => Some(s.as_str()),
            Self::Error { message, .. } => Some(message.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for ReplResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(v) => write!(f, "{v}"),
            Self::Ok => Ok(()),
            Self::Incomplete => write!(f, "..."),
            Self::Error { error_type, message, line } => {
                if let Some(l) = line {
                    write!(f, "{error_type} (line {l}): {message}")
                } else {
                    write!(f, "{error_type}: {message}")
                }
            }
            Self::SecurityError(s) => write!(f, "SecurityError: {s}"),
            Self::CommandResult(s) => write!(f, "{s}"),
            Self::Exit => write!(f, ""),
        }
    }
}

// ── REPL magic commands ───────────────────────────────────────────────────────

/// Built-in REPL magic commands prefixed with `%`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicCommand {
    Reset,
    History { count: usize },
    Vars,
    Help { topic: Option<String> },
    Imports,
    Clear,
    Quit,
    Load { path: String },
    Save { path: String },
    Time,
    Unknown(String),
}

impl MagicCommand {
    #[must_use] 
    pub fn parse(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if !trimmed.starts_with('%') {
            return None;
        }
        let rest = &trimmed[1..];
        let mut parts = rest.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().unwrap_or("").trim();
        Some(match cmd.as_str() {
            "reset" => Self::Reset,
            "history" | "hist" => {
                let count = arg.parse().unwrap_or(20);
                Self::History { count }
            }
            "vars" | "who" | "whos" => Self::Vars,
            "help" | "?" => {
                let topic = if arg.is_empty() { None } else { Some(arg.to_string()) };
                Self::Help { topic }
            }
            "imports" => Self::Imports,
            "clear" | "cls" => Self::Clear,
            "quit" | "exit" => Self::Quit,
            "load" => Self::Load { path: arg.to_string() },
            "save" => Self::Save { path: arg.to_string() },
            "time" | "timeit" => Self::Time,
            other => Self::Unknown(other.to_string()),
        })
    }
}

// ── Completer ─────────────────────────────────────────────────────────────────

pub const PYTHON_KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from",
    "global", "if", "import", "in", "is", "lambda", "not", "or", "pass",
    "raise", "return", "try", "while", "with", "yield", "True", "False", "None",
];

pub const PYTHON_BUILTINS: &[&str] = &[
    "abs", "all", "any", "bin", "bool", "bytes", "callable", "chr", "dict",
    "dir", "divmod", "enumerate", "filter", "float", "format", "frozenset",
    "getattr", "hasattr", "hash", "hex", "id", "input", "int", "isinstance",
    "issubclass", "iter", "len", "list", "map", "max", "min", "next", "object",
    "oct", "ord", "pow", "print", "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "str", "sum", "tuple", "type",
    "vars", "zip",
];

/// Provides tab-completion suggestions given the current REPL state.
pub struct ReplCompleter;

impl ReplCompleter {
    #[must_use] 
    pub fn complete(prefix: &str, state: &ReplState) -> Vec<CompletionHint> {
        let mut hints: Vec<CompletionHint> = Vec::new();

        // Keywords.
        for &kw in PYTHON_KEYWORDS {
            if kw.starts_with(prefix) {
                hints.push(CompletionHint::keyword(kw));
            }
        }

        // Builtins.
        for &b in PYTHON_BUILTINS {
            if b.starts_with(prefix) {
                hints.push(CompletionHint::builtin(b));
            }
        }

        // Variables in current scope.
        for name in state.var_names() {
            if name.starts_with(prefix) {
                hints.push(CompletionHint::var(name));
            }
        }

        // Imported modules.
        for m in &state.imports {
            if m.starts_with(prefix) {
                hints.push(CompletionHint {
                    text: m.clone(),
                    kind: CompletionKind::Module,
                    doc: None,
                });
            }
        }

        // Sort by text.
        hints.sort_by(|a, b| a.text.cmp(&b.text));
        hints.dedup_by(|a, b| a.text == b.text);
        hints
    }
}

// ── Python REPL ───────────────────────────────────────────────────────────────

/// Configuration for the REPL.
#[derive(Debug, Clone)]
pub struct ReplConfig {
    pub prompt: String,
    pub history_size: usize,
    pub show_result_type: bool,
    pub color_output: bool,
    pub auto_indent: bool,
}

impl Default for ReplConfig {
    fn default() -> Self {
        Self {
            prompt: ">>> ".to_string(),
            history_size: 500,
            show_result_type: false,
            color_output: false,
            auto_indent: true,
        }
    }
}

/// The REPL driver. Manages per-session state, history, and command dispatch.
pub struct PythonRepl {
    pub config: ReplConfig,
    pub state: ReplState,
    pub history: CommandHistory,
    session_id: u64,
    line_no: u64,
}

impl PythonRepl {
    #[must_use] 
    pub fn new(config: ReplConfig) -> Self {
        let history_size = config.history_size;
        Self {
            config,
            state: ReplState::new(),
            history: CommandHistory::new(history_size),
            session_id: 0,
            line_no: 0,
        }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(ReplConfig::default())
    }

    #[must_use] 
    pub fn prompt(&self) -> &str {
        if self.state.in_block {
            "... "
        } else {
            &self.config.prompt
        }
    }

    /// Feed a single line of user input. Returns the REPL result.
    pub fn feed(&mut self, line: &str) -> ReplResult {
        self.line_no += 1;

        // Magic command?
        if let Some(cmd) = MagicCommand::parse(line) {
            return self.handle_magic(cmd);
        }

        // Exit shorthand.
        let trimmed = line.trim();
        if trimmed == "exit" || trimmed == "quit" || trimmed == "exit()" || trimmed == "quit()" {
            return ReplResult::Exit;
        }

        // Multi-line block accumulation.
        if self.state.in_block {
            if self.state.is_block_complete(line) {
                let src = self.state.finish_block();
                self.history.push(src.clone());
                self.state.lines_executed += 1;
                return self.eval_source(&src);
            }
            self.state.append_block(line);
            return ReplResult::Incomplete;
        }

        // Detect block starters.
        if is_block_start(trimmed) {
            self.state.begin_block(line);
            return ReplResult::Incomplete;
        }

        if trimmed.is_empty() {
            return ReplResult::Ok;
        }

        self.history.push(line);
        self.state.lines_executed += 1;
        self.eval_source(line)
    }

    /// Evaluate source and return a `ReplResult`.
    /// In the pure-Rust interpreter, this dispatches to `PyScope`; here we implement
    /// the subset needed for REPL meta-operations and delegate the rest.
    fn eval_source(&mut self, source: &str) -> ReplResult {
        let trimmed = source.trim();

        // Handle assignment: `name = value` — store in REPL state.
        if let Some((lhs, rhs)) = parse_simple_assignment(trimmed) {
            let evaluated = self.simple_eval(rhs.trim());
            self.state.set_var(lhs.trim(), &evaluated);
            return ReplResult::Ok;
        }

        // Handle `import module`.
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let module = rest.trim();
            self.state.add_import(module);
            return ReplResult::Ok;
        }

        // Handle `del name`.
        if let Some(rest) = trimmed.strip_prefix("del ") {
            let name = rest.trim();
            if self.state.del_var(name) {
                ReplResult::Ok
            } else {
                ReplResult::Error {
                    error_type: "NameError".to_string(),
                    message: format!("name '{name}' is not defined"),
                    line: Some(u32::try_from(self.line_no).unwrap_or(u32::MAX)),
                }
            }
        } else if let Some(val) = self.try_eval_expr(trimmed) {
            // Expression evaluation.
            ReplResult::Value(val)
        } else {
            // Unhandled — just record as executed.
            ReplResult::Ok
        }
    }

    /// Very simple expression evaluator for REPL introspection.
    fn try_eval_expr(&self, expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        // Variable lookup.
        if let Some(v) = self.state.get_var(trimmed) {
            return Some(v.to_string());
        }
        // Numeric literal.
        if trimmed.parse::<i64>().is_ok() || trimmed.parse::<f64>().is_ok() {
            return Some(trimmed.to_string());
        }
        // String literal.
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        {
            // The outer quotes are always single ASCII bytes, so advancing by 1
            // and retreating by 1 from the char boundary is safe.
            let inner_start = trimmed.char_indices().nth(1).map_or(trimmed.len(), |(i, _)| i);
            let inner_end = trimmed.char_indices().next_back().map_or(0, |(i, _)| i);
            if inner_start <= inner_end {
                return Some(trimmed[inner_start..inner_end].to_string());
            }
            return Some(String::new());
        }
        None
    }

    fn simple_eval(&self, expr: &str) -> String {
        self.try_eval_expr(expr).unwrap_or_else(|| expr.to_string())
    }

    fn handle_magic(&mut self, cmd: MagicCommand) -> ReplResult {
        match cmd {
            MagicCommand::Reset => {
                self.state = ReplState::new();
                ReplResult::CommandResult("REPL state reset.".to_string())
            }
            MagicCommand::History { count } => {
                let entries: Vec<String> = self
                    .history
                    .entries()
                    .take(count)
                    .enumerate()
                    .map(|(i, s)| format!("{i:4}: {s}"))
                    .collect();
                ReplResult::CommandResult(entries.join("\n"))
            }
            MagicCommand::Vars => {
                let vars: Vec<String> = self
                    .state
                    .var_names()
                    .iter()
                    .map(|n| {
                        let v = self.state.get_var(n).unwrap_or("");
                        format!("{n} = {v}")
                    })
                    .collect();
                if vars.is_empty() {
                    ReplResult::CommandResult("(no variables)".to_string())
                } else {
                    ReplResult::CommandResult(vars.join("\n"))
                }
            }
            MagicCommand::Imports => {
                let list = self.state.imports.join(", ");
                ReplResult::CommandResult(if list.is_empty() {
                    "(no imports)".to_string()
                } else {
                    list
                })
            }
            MagicCommand::Help { topic } => {
                let text = topic.as_deref().map_or_else(|| HELP_TEXT.to_string(), |t| format!("Help for '{t}': see https://docs.python.org/3/library/{t}.html"));
                ReplResult::CommandResult(text)
            }
            MagicCommand::Clear => {
                self.state.output_lines.clear();
                ReplResult::Ok
            }
            MagicCommand::Quit => ReplResult::Exit,
            MagicCommand::Load { path } => {
                ReplResult::CommandResult(format!("(load '{path}' requires filesystem access)"))
            }
            MagicCommand::Save { path } => {
                ReplResult::CommandResult(format!("(save '{path}' requires filesystem access)"))
            }
            MagicCommand::Time => {
                ReplResult::CommandResult(format!("lines executed: {}", self.state.lines_executed))
            }
            MagicCommand::Unknown(s) => {
                ReplResult::Error {
                    error_type: "MagicError".to_string(),
                    message: format!("unknown magic command '%{s}'"),
                    line: None,
                }
            }
        }
    }

    #[must_use] 
    pub fn completions(&self, prefix: &str) -> Vec<CompletionHint> {
        ReplCompleter::complete(prefix, &self.state)
    }

    #[must_use] 
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    #[must_use] 
    pub const fn line_no(&self) -> u64 {
        self.line_no
    }

    pub const fn set_session_id(&mut self, id: u64) {
        self.session_id = id;
    }
}

const HELP_TEXT: &str = "\
RustRE Python REPL
Magic commands:
  %reset          — clear all variables and imports
  %history [N]    — show last N history entries (default 20)
  %vars           — list all defined variables
  %imports        — list imported modules
  %clear          — clear output buffer
  %help [topic]   — show help
  %quit / %exit   — exit the REPL
Type Python expressions or statements at the >>> prompt.
Multi-line blocks are supported (end with a blank line).";

fn is_block_start(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.ends_with(':')
        && (trimmed.starts_with("def ")
            || trimmed.starts_with("class ")
            || trimmed.starts_with("if ")
            || trimmed.starts_with("elif ")
            || trimmed.starts_with("else")
            || trimmed.starts_with("for ")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("try")
            || trimmed.starts_with("except")
            || trimmed.starts_with("finally")
            || trimmed.starts_with("with "))
}

fn parse_simple_assignment(line: &str) -> Option<(&str, &str)> {
    // Very simple: look for `name = expr` where name has no spaces.
    let eq = line.find('=')?;
    let lhs = &line[..eq];
    let rhs = &line[eq + 1..];
    // Make sure LHS is a plain identifier (no spaces, no operators).
    let lhs_trimmed = lhs.trim();
    if lhs_trimmed.is_empty()
        || lhs_trimmed.contains(' ')
        || lhs_trimmed.contains('!')
        || lhs_trimmed.contains('<')
        || lhs_trimmed.contains('>')
    {
        return None;
    }
    // Ensure it's not `==`.
    if rhs.starts_with('=') {
        return None;
    }
    Some((lhs, rhs))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_push_and_get() {
        let mut h = CommandHistory::new(10);
        h.push("x = 1");
        h.push("y = 2");
        assert_eq!(h.len(), 2);
        assert_eq!(h.get(0).unwrap(), "y = 2"); // most recent first
    }

    #[test]
    fn test_history_dedup_adjacent() {
        let mut h = CommandHistory::new(10);
        h.push("x = 1");
        h.push("x = 1");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_limit() {
        let mut h = CommandHistory::new(3);
        for i in 0..5 {
            h.push(format!("cmd{i}"));
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_prev_next() {
        let mut h = CommandHistory::new(10);
        h.push("a");
        h.push("b");
        assert_eq!(h.prev().unwrap(), "b");
        assert_eq!(h.prev().unwrap(), "a");
        assert_eq!(h.forward().unwrap(), "b");
    }

    #[test]
    fn test_history_search() {
        let mut h = CommandHistory::new(10);
        h.push("import math");
        h.push("x = math.pi");
        assert!(h.search("math.pi").is_some());
        assert!(h.search("nonexistent").is_none());
    }

    #[test]
    fn test_repl_state_vars() {
        let mut s = ReplState::new();
        s.set_var("x", "42");
        assert_eq!(s.get_var("x").unwrap(), "42");
        assert!(s.del_var("x"));
        assert!(s.get_var("x").is_none());
    }

    #[test]
    fn test_repl_state_block() {
        let mut s = ReplState::new();
        s.begin_block("for i in range(10):");
        assert!(s.in_block);
        s.append_block("    print(i)");
        let src = s.finish_block();
        assert!(src.contains("for i"));
        assert!(src.contains("print(i)"));
        assert!(!s.in_block);
    }

    #[test]
    fn test_magic_command_parse_reset() {
        assert_eq!(MagicCommand::parse("%reset"), Some(MagicCommand::Reset));
    }

    #[test]
    fn test_magic_command_parse_history() {
        assert_eq!(
            MagicCommand::parse("%history 10"),
            Some(MagicCommand::History { count: 10 })
        );
    }

    #[test]
    fn test_magic_command_parse_none() {
        assert_eq!(MagicCommand::parse("x = 1"), None);
    }

    #[test]
    fn test_magic_command_parse_quit() {
        assert_eq!(MagicCommand::parse("%quit"), Some(MagicCommand::Quit));
    }

    #[test]
    fn test_repl_assignment() {
        let mut repl = PythonRepl::with_defaults();
        let r = repl.feed("x = 42");
        assert!(matches!(r, ReplResult::Ok));
        assert_eq!(repl.state.get_var("x").unwrap(), "42");
    }

    #[test]
    fn test_repl_expr_lookup() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("answer = 42");
        let r = repl.feed("answer");
        assert!(matches!(r, ReplResult::Value(_)));
    }

    #[test]
    fn test_repl_import() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("import math");
        assert!(repl.state.imports.contains(&"math".to_string()));
    }

    #[test]
    fn test_repl_del() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("z = 99");
        let r = repl.feed("del z");
        assert!(matches!(r, ReplResult::Ok));
        assert!(repl.state.get_var("z").is_none());
    }

    #[test]
    fn test_repl_del_missing() {
        let mut repl = PythonRepl::with_defaults();
        let r = repl.feed("del nonexistent");
        assert!(r.is_error());
    }

    #[test]
    fn test_repl_exit() {
        let mut repl = PythonRepl::with_defaults();
        assert!(matches!(repl.feed("exit"), ReplResult::Exit));
        assert!(matches!(repl.feed("quit()"), ReplResult::Exit));
    }

    #[test]
    fn test_repl_magic_reset() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("x = 1");
        repl.feed("%reset");
        assert!(repl.state.get_var("x").is_none());
    }

    #[test]
    fn test_repl_magic_vars() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("abc = 123");
        let r = repl.feed("%vars");
        match r {
            ReplResult::CommandResult(s) => assert!(s.contains("abc")),
            _ => panic!("expected CommandResult"),
        }
    }

    #[test]
    fn test_completion_keywords() {
        let state = ReplState::new();
        let hints = ReplCompleter::complete("fo", &state);
        assert!(hints.iter().any(|h| h.text == "for"));
    }

    #[test]
    fn test_completion_builtins() {
        let state = ReplState::new();
        let hints = ReplCompleter::complete("pri", &state);
        assert!(hints.iter().any(|h| h.text == "print"));
    }

    #[test]
    fn test_completion_variables() {
        let mut state = ReplState::new();
        state.set_var("my_var", "5");
        let hints = ReplCompleter::complete("my", &state);
        assert!(hints.iter().any(|h| h.text == "my_var"));
    }

    #[test]
    fn test_repl_line_no() {
        let mut repl = PythonRepl::with_defaults();
        repl.feed("x = 1");
        repl.feed("y = 2");
        assert_eq!(repl.line_no(), 2);
    }
}
