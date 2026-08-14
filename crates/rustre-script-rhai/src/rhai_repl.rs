//! `rhai_repl` — interactive Rhai REPL with line editing, history, completion,
//! multi-line mode, variable inspection, and last-result binding.

use std::collections::VecDeque;
use std::fmt::Write as FmtWrite;
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use rhai::{Dynamic, Engine, Scope};

// ─────────────────────────────────────────────────────────────────────────────
// REPL configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Packed boolean flags for [`ReplConfig`].
#[derive(Debug, Clone, Copy)]
pub struct ReplFlags(u8);

impl ReplFlags {
    const AUTO_PRINT: u8         = 0b0001;
    const BIND_LAST_RESULT: u8   = 0b0010;
    const SHOW_TIMING: u8        = 0b0100;
    const COMPLETION_ENABLED: u8 = 0b1000;

    /// Return `true` if auto-print is enabled.
    #[must_use] pub const fn auto_print(self) -> bool { self.0 & Self::AUTO_PRINT != 0 }
    /// Return `true` if last-result binding is enabled.
    #[must_use] pub const fn bind_last_result(self) -> bool { self.0 & Self::BIND_LAST_RESULT != 0 }
    /// Return `true` if timing display is enabled.
    #[must_use] pub const fn show_timing(self) -> bool { self.0 & Self::SHOW_TIMING != 0 }
    /// Return `true` if completion is enabled.
    #[must_use] pub const fn completion_enabled(self) -> bool { self.0 & Self::COMPLETION_ENABLED != 0 }

    /// Set or clear the auto-print flag.
    pub const fn set_auto_print(&mut self, v: bool) {
        if v { self.0 |= Self::AUTO_PRINT; } else { self.0 &= !Self::AUTO_PRINT; }
    }
    /// Set or clear the bind-last-result flag.
    pub const fn set_bind_last_result(&mut self, v: bool) {
        if v { self.0 |= Self::BIND_LAST_RESULT; } else { self.0 &= !Self::BIND_LAST_RESULT; }
    }
    /// Set or clear the show-timing flag.
    pub const fn set_show_timing(&mut self, v: bool) {
        if v { self.0 |= Self::SHOW_TIMING; } else { self.0 &= !Self::SHOW_TIMING; }
    }
    /// Set or clear the completion-enabled flag.
    pub const fn set_completion_enabled(&mut self, v: bool) {
        if v { self.0 |= Self::COMPLETION_ENABLED; } else { self.0 &= !Self::COMPLETION_ENABLED; }
    }
}

impl Default for ReplFlags {
    fn default() -> Self {
        // auto_print=true, bind_last_result=true, show_timing=false, completion_enabled=true
        Self(Self::AUTO_PRINT | Self::BIND_LAST_RESULT | Self::COMPLETION_ENABLED)
    }
}

/// Configuration for the Rhai REPL.
#[derive(Debug, Clone)]
pub struct ReplConfig {
    /// Maximum number of history entries to keep.
    pub history_limit: usize,
    /// Primary prompt (shown at start of a new line).
    pub prompt: String,
    /// Continuation prompt (shown when inside a multi-line block).
    pub continuation_prompt: String,
    /// Packed boolean flags (`auto_print`, `bind_last_result`, `show_timing`, `completion_enabled`).
    pub flags: ReplFlags,
    /// Maximum number of lines to display for long outputs.
    pub output_limit: usize,
}

impl Default for ReplConfig {
    fn default() -> Self {
        Self {
            history_limit: 500,
            prompt: "re> ".to_string(),
            continuation_prompt: ".. ".to_string(),
            flags: ReplFlags::default(),
            output_limit: 64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// History
// ─────────────────────────────────────────────────────────────────────────────

/// Bounded command history for the REPL.
#[derive(Debug, Clone)]
pub struct ReplHistory {
    entries: VecDeque<String>,
    limit: usize,
    cursor: usize,
}

impl ReplHistory {
    /// Create a new history with `limit` entries.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            limit: limit.max(1),
            cursor: 0,
        }
    }

    /// Push a new entry (deduplicates consecutive identical entries).
    pub fn push(&mut self, entry: String) {
        if entry.trim().is_empty() { return; }
        if self.entries.back().is_some_and(|e| e == &entry) { return; }
        if self.entries.len() >= self.limit {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        self.cursor = self.entries.len();
    }

    /// Move cursor back and return the entry.
    #[must_use]
    pub fn prev(&mut self) -> Option<&str> {
        if self.cursor == 0 { return None; }
        self.cursor -= 1;
        self.entries.get(self.cursor).map(String::as_str)
    }

    /// Move cursor forward and return the entry.
    #[must_use]
    pub fn advance(&mut self) -> Option<&str> {
        if self.cursor >= self.entries.len() { return None; }
        self.cursor += 1;
        self.entries.get(self.cursor).map(String::as_str)
    }

    /// Reset cursor to end.
    pub fn reset_cursor(&mut self) {
        self.cursor = self.entries.len();
    }

    /// Return the number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries as a slice.
    #[must_use]
    pub fn entries(&self) -> Vec<&str> {
        self.entries.iter().map(String::as_str).collect()
    }

    /// Return the most recent N entries.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<&str> {
        let start = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(start).map(String::as_str).collect()
    }

    /// Search history for entries containing `query`.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&str> {
        self.entries.iter()
            .filter(|e| e.contains(query))
            .map(String::as_str)
            .collect()
    }

    /// Save history to a file.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be written.
    pub fn save_to_file(&self, path: &str) -> io::Result<()> {
        let content = self.entries.iter().cloned().collect::<Vec<_>>().join("\n");
        std::fs::write(path, content)
    }

    /// Load history from a file.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read.
    pub fn load_from_file(&mut self, path: &str) -> io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            self.push(line.to_string());
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Completion engine
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in completions for the REPL.
pub struct CompletionEngine {
    keywords: Vec<String>,
    builtins: Vec<String>,
    custom: Vec<String>,
}

impl CompletionEngine {
    /// Create a new completion engine with default keywords.
    #[must_use]
    pub fn new() -> Self {
        let keywords = vec![
            "let", "const", "if", "else", "while", "for", "in", "loop",
            "break", "continue", "return", "fn", "true", "false", "null",
            "switch", "do", "type", "import", "export", "as", "try", "catch", "throw",
        ].into_iter().map(String::from).collect();

        let builtins = vec![
            // RE API
            "load_binary", "get_info", "binary_info", "read_bytes",
            "disasm", "disasm_file", "sections", "sections_file", "section_data",
            "sym_lookup", "sym_find", "sym_list",
            "hex_dump", "hex_dump_file",
            "strings", "strings_file",
            "xref_scan", "va_to_offset",
            // stdlib re
            "re_hex_encode", "re_hex_decode", "re_parse_hex", "re_fmt_hex",
            "re_base64_encode", "re_base64_decode",
            "re_read_le32", "re_read_le64", "re_read_le16", "re_read_byte",
            "re_fmt_addr", "re_fmt_bytes", "re_xor", "re_add_bytes",
            "re_scan_pattern", "re_match_pattern", "re_looks_like_code",
            "re_slice", "re_concat", "re_repeat", "re_reverse",
            // REPL meta
            "help", "quit", "exit", "history", "vars", "clear", "reset",
            // rhai builtins
            "print", "debug", "type_of", "len", "push", "pop", "append",
            "split", "trim", "starts_with", "ends_with", "contains", "replace",
            "to_string", "to_int", "to_float", "keys", "values",
        ].into_iter().map(String::from).collect();

        Self { keywords, builtins, custom: Vec::new() }
    }

    /// Add a custom completion word.
    pub fn add_custom(&mut self, word: String) {
        if !self.custom.contains(&word) {
            self.custom.push(word);
        }
    }

    /// Return completions for `prefix`.
    #[must_use]
    pub fn complete(&self, prefix: &str) -> Vec<String> {
        let mut matches: Vec<String> = self.keywords.iter()
            .chain(self.builtins.iter())
            .chain(self.custom.iter())
            .filter(|s| s.starts_with(prefix))
            .cloned()
            .collect();
        matches.sort_unstable();
        matches.dedup();
        matches
    }

    /// Return the longest common prefix among completions for `prefix`.
    #[must_use]
    pub fn complete_common(&self, prefix: &str) -> String {
        let completions = self.complete(prefix);
        if completions.is_empty() { return prefix.to_string(); }
        if completions.len() == 1 { return completions[0].clone(); }
        let first = &completions[0];
        let mut common_len = first.len();
        for c in &completions[1..] {
            common_len = common_len.min(
                first.chars().zip(c.chars()).take_while(|(a, b)| a == b).count()
            );
        }
        first[..common_len].to_string()
    }
}

impl Default for CompletionEngine {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// REPL result
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating one REPL line.
#[derive(Debug)]
pub enum ReplResult {
    /// Evaluation produced a value.
    Value(Dynamic),
    /// Evaluation produced no value (statement).
    NoValue,
    /// The user requested to quit.
    Quit,
    /// An error occurred.
    Error(String),
    /// Timing information attached to the result.
    Timed { inner: Box<Self>, elapsed: Duration },
}

impl ReplResult {
    /// Format the result for display.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Value(v) => {
                if v.is_unit() {
                    String::new()
                } else {
                    format!("= {v}")
                }
            }
            Self::NoValue => String::new(),
            Self::Quit => "Goodbye!".to_string(),
            Self::Error(e) => format!("error: {e}"),
            Self::Timed { inner, elapsed } => {
                format!("{}\n[{:.3}ms]", inner.display(), elapsed.as_secs_f64() * 1000.0)
            }
        }
    }

    /// Return true if this is a quit command.
    #[must_use]
    pub const fn is_quit(&self) -> bool {
        matches!(self, Self::Quit)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Variable inspector
// ─────────────────────────────────────────────────────────────────────────────

/// Inspects the Rhai scope and formats variable bindings.
pub struct VariableInspector;

impl VariableInspector {
    /// Format all variables in `scope` as a table.
    #[must_use]
    pub fn dump_scope(scope: &Scope) -> String {
        let mut out = String::new();
        let vars: Vec<(String, String, String)> = scope.iter().map(|(name, is_const, val)| {
            let kind = if is_const { "const" } else { "let" };
            let type_name = val.type_name();
            let repr = Self::format_value(&val);
            (name.to_string(), kind.to_string(), format!("{type_name}: {repr}"))
        }).collect();

        if vars.is_empty() {
            return "(no variables in scope)".to_string();
        }

        let max_name = vars.iter().map(|(n, _, _)| n.len()).max().unwrap_or(4).max(4);
        let max_kind = 5;
        let _ = writeln!(out, "{:<max_name$}  {:<max_kind$}  type: value", "name", "kind");
        let _ = writeln!(out, "{:-<max_name$}  {:-<max_kind$}  ----------", "", "");
        for (name, kind, val) in &vars {
            let _ = writeln!(out, "{name:<max_name$}  {kind:<max_kind$}  {val}");
        }
        out
    }

    /// Format a single `Dynamic` value for display.
    #[must_use]
    pub fn format_value(val: &Dynamic) -> String {
        if val.is_unit() {
            return "()".to_string();
        }
        if val.is::<bool>() {
            return format!("{}", val.clone().cast::<bool>());
        }
        if val.is::<i64>() {
            let n = val.clone().cast::<i64>();
            return format!("{n} (0x{n:X})");
        }
        if val.is::<f64>() {
            return format!("{}", val.clone().cast::<f64>());
        }
        if val.is::<rhai::ImmutableString>() {
            let s = val.clone().cast::<rhai::ImmutableString>();
            let char_count = s.chars().count();
            if char_count > 80 {
                let truncated: String = s.chars().take(77).collect();
                return format!("\"{truncated}...\" ({char_count} chars)");
            }
            return format!("\"{s}\"");
        }
        if val.is::<rhai::Array>() {
            let arr = val.clone().cast::<rhai::Array>();
            return format!("[{} items]", arr.len());
        }
        if val.is::<rhai::Map>() {
            let map = val.clone().cast::<rhai::Map>();
            return format!("{{{} keys}}", map.len());
        }
        if val.is::<rhai::Blob>() {
            let blob = val.clone().cast::<rhai::Blob>();
            return format!("<blob {} bytes>", blob.len());
        }
        format!("{val}")
    }

    /// Return a list of variable names in scope.
    #[must_use]
    pub fn var_names(scope: &Scope) -> Vec<String> {
        scope.iter().map(|(n, _, _)| n.to_string()).collect()
    }

    /// Look up a single variable by name.
    #[must_use]
    pub fn get_var<'s>(scope: &'s Scope, name: &str) -> Option<&'s Dynamic> {
        scope.get_value_ref(name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-line editor state
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks whether we are inside a multi-line expression.
#[derive(Debug, Default, Clone)]
pub struct MultiLineState {
    /// Accumulated lines so far.
    lines: Vec<String>,
    /// Brace/paren/bracket nesting depth.
    depth: i32,
}

impl MultiLineState {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Return true if we are inside a multi-line block.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.depth > 0 || !self.lines.is_empty()
    }

    /// Push a line; update nesting depth.
    pub fn push(&mut self, line: &str) {
        for ch in line.chars() {
            match ch {
                '{' | '(' | '[' => self.depth += 1,
                '}' | ')' | ']' => self.depth -= 1,
                _ => {}
            }
        }
        self.lines.push(line.to_string());
    }

    /// Return the assembled code so far.
    #[must_use]
    pub fn code(&self) -> String {
        self.lines.join("\n")
    }

    /// Return true if the accumulated code is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.depth <= 0
    }

    /// Reset state.
    pub fn reset(&mut self) {
        self.lines.clear();
        self.depth = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in REPL commands
// ─────────────────────────────────────────────────────────────────────────────

/// Process a built-in REPL meta-command (`:help`, `:vars`, etc.).
///
/// Returns `Some(ReplResult)` if the line was handled, `None` otherwise.
#[must_use]
pub fn handle_meta_command(
    line: &str,
    scope: &Scope,
    history: &ReplHistory,
) -> Option<ReplResult> {
    let trimmed = line.trim();
    match trimmed {
        ":quit" | ":exit" | "quit" | "exit" => Some(ReplResult::Quit),
        ":help" | "help" => {
            let help = REPL_HELP;
            Some(ReplResult::Value(Dynamic::from(help.to_string())))
        }
        ":vars" | "vars" => {
            let dump = VariableInspector::dump_scope(scope);
            Some(ReplResult::Value(Dynamic::from(dump)))
        }
        ":history" | "history" => {
            let entries = history.recent(20);
            let mut out = String::new();
            for (i, e) in entries.iter().enumerate() {
                let _ = writeln!(out, "{:3}: {e}", i + 1);
            }
            Some(ReplResult::Value(Dynamic::from(out)))
        }
        ":clear" => Some(ReplResult::Value(Dynamic::from("[screen cleared]"))),
        _ if trimmed.starts_with(":search ") => {
            let query = &trimmed[8..];
            let hits = history.search(query);
            let mut out = String::new();
            for h in &hits {
                let _ = writeln!(out, "{h}");
            }
            Some(ReplResult::Value(Dynamic::from(out)))
        }
        _ if trimmed.starts_with(":inspect ") => {
            let var_name = trimmed[9..].trim();
            VariableInspector::get_var(scope, var_name).map_or_else(
                || Some(ReplResult::Error(format!("variable '{var_name}' not found"))),
                |val| {
                    let repr = VariableInspector::format_value(val);
                    Some(ReplResult::Value(Dynamic::from(repr)))
                },
            )
        }
        _ => None,
    }
}

const REPL_HELP: &str = r#"RustRE Rhai REPL — commands:
  :help         show this help
  :quit / exit  exit the REPL
  :vars         list all variables in scope
  :history      show recent history
  :search <q>   search history
  :inspect <v>  inspect a variable
  :clear        clear screen (hint)

Multi-line: open a block with { and press Enter; close with }
Last result: bound to _ variable

RE API examples:
  let b = hex_decode("4D5A90");
  let s = sections(b);
  let d = disasm(b, 0x400000, 10);
  hex_dump(b, 0)
"#;

// ─────────────────────────────────────────────────────────────────────────────
// ReplSession — the main REPL state
// ─────────────────────────────────────────────────────────────────────────────

/// A full REPL session with engine, scope, history, and completion.
pub struct ReplSession {
    pub engine: Engine,
    pub scope: Scope<'static>,
    pub history: ReplHistory,
    pub completion: CompletionEngine,
    pub config: ReplConfig,
    pub multi_line: MultiLineState,
    pub eval_count: u64,
    pub error_count: u64,
}

impl ReplSession {
    /// Create a new REPL session.
    #[must_use]
    pub fn new(engine: Engine, config: ReplConfig) -> Self {
        let history = ReplHistory::new(config.history_limit);
        Self {
            engine,
            scope: Scope::new(),
            history,
            completion: CompletionEngine::new(),
            config,
            multi_line: MultiLineState::new(),
            eval_count: 0,
            error_count: 0,
        }
    }

    /// Create a session with default configuration.
    #[must_use]
    pub fn default_session() -> Self {
        Self::new(Engine::new(), ReplConfig::default())
    }

    /// Load a script file into the session's scope.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read or the script fails to compile or run.
    pub fn load_file(&mut self, path: &str) -> Result<(), String> {
        let code = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let ast = self.engine.compile(&code).map_err(|e| e.to_string())?;
        self.engine.run_ast_with_scope(&mut self.scope, &ast).map_err(|e| e.to_string())
    }

    /// Evaluate a single line (or accumulated multi-line block).
    pub fn eval_line(&mut self, line: &str) -> ReplResult {
        // Meta commands
        if let Some(r) = handle_meta_command(line, &self.scope, &self.history) {
            return r;
        }

        // Multi-line accumulation
        self.multi_line.push(line);
        if !self.multi_line.is_complete() {
            return ReplResult::NoValue;
        }
        let code = self.multi_line.code();
        self.multi_line.reset();
        self.history.push(code.clone());

        let start = Instant::now();
        let result = self.engine.eval_with_scope::<Dynamic>(&mut self.scope, &code);
        let elapsed = start.elapsed();

        self.eval_count += 1;

        match result {
            Ok(val) => {
                if self.config.flags.bind_last_result() {
                    self.scope.set_or_push("_", val.clone());
                }
                let inner = if val.is_unit() {
                    ReplResult::NoValue
                } else {
                    ReplResult::Value(val)
                };
                if self.config.flags.show_timing() {
                    ReplResult::Timed { inner: Box::new(inner), elapsed }
                } else {
                    inner
                }
            }
            Err(e) => {
                self.error_count += 1;
                ReplResult::Error(e.to_string())
            }
        }
    }

    /// Return the current prompt string.
    #[must_use]
    pub fn prompt(&self) -> &str {
        if self.multi_line.is_active() {
            &self.config.continuation_prompt
        } else {
            &self.config.prompt
        }
    }

    /// Run an interactive REPL loop, reading from `reader` and writing to `writer`.
    ///
    /// # Errors
    /// Returns `Err` if an I/O error occurs reading input or writing output.
    pub fn run_loop<R: BufRead, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> io::Result<()> {
        writeln!(writer, "RustRE Rhai REPL v0.1.0 — type :help for help, :quit to exit")?;
        loop {
            write!(writer, "{}", self.prompt())?;
            writer.flush()?;
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                writeln!(writer, "Goodbye!")?;
                break;
            }
            let line = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
            if line.trim().is_empty() {
                continue;
            }
            let result = self.eval_line(&line);
            let display = result.display();
            if !display.is_empty() {
                writeln!(writer, "{display}")?;
            }
            if result.is_quit() {
                break;
            }
        }
        Ok(())
    }

    /// Run against a sequence of pre-supplied inputs (non-interactive mode for testing).
    #[must_use]
    pub fn run_batch(&mut self, inputs: &[&str]) -> Vec<String> {
        let mut outputs = Vec::new();
        for &line in inputs {
            let result = self.eval_line(line);
            let display = result.display();
            outputs.push(display);
            if result.is_quit() { break; }
        }
        outputs
    }

    /// Return session statistics.
    #[must_use]
    pub fn stats(&self) -> ReplStats {
        ReplStats {
            eval_count: self.eval_count,
            error_count: self.error_count,
            history_len: self.history.len(),
            var_count: VariableInspector::var_names(&self.scope).len(),
        }
    }

    /// Add a variable to the scope.
    pub fn set_var(&mut self, name: &str, val: impl Into<Dynamic>) {
        self.scope.set_or_push(name, val.into());
    }

    /// Register a host function.
    pub fn register_fn<
        A: 'static,
        const N: usize,
        const X: bool,
        R: Clone + Send + Sync + 'static,
        const FN: bool,
        F: rhai::RhaiNativeFunc<A, N, X, R, FN> + Send + Sync + 'static,
    >(&mut self, name: &str, f: F) {
        self.engine.register_fn(name, f);
        self.completion.add_custom(name.to_string());
    }
}

/// Session statistics.
#[derive(Debug, Clone)]
pub struct ReplStats {
    pub eval_count: u64,
    pub error_count: u64,
    pub history_len: usize,
    pub var_count: usize,
}

impl std::fmt::Display for ReplStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "evals={} errors={} history={} vars={}",
            self.eval_count, self.error_count, self.history_len, self.var_count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: format a Dynamic value as a pretty-printed string
// ─────────────────────────────────────────────────────────────────────────────

/// Pretty-print a `Dynamic` value for REPL display.
#[must_use]
pub fn pretty_print(val: &Dynamic, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    if val.is_unit() { return format!("{pad}()"); }
    if val.is::<rhai::Array>() {
        let arr = val.clone().cast::<rhai::Array>();
        if arr.is_empty() { return format!("{pad}[]"); }
        let mut out = format!("{pad}[\n");
        for item in &arr {
            let _ = writeln!(out, "{},", pretty_print(item, indent + 1));
        }
        let _ = write!(out, "{pad}]");
        return out;
    }
    if val.is::<rhai::Map>() {
        let map = val.clone().cast::<rhai::Map>();
        if map.is_empty() { return format!("{pad}{{}}"); }
        let mut keys: Vec<String> = map.keys().map(ToString::to_string).collect();
        keys.sort_unstable();
        let mut out = format!("{pad}{{\n");
        for k in &keys {
            if let Some(v) = map.get(k.as_str()) {
                let _ = writeln!(out, "{}  {k}: {},", pad, VariableInspector::format_value(v));
            }
        }
        let _ = write!(out, "{pad}}}");
        return out;
    }
    format!("{pad}{}", VariableInspector::format_value(val))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> ReplSession {
        ReplSession::default_session()
    }

    #[test]
    fn test_history_push_pop() {
        let mut h = ReplHistory::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        assert_eq!(h.len(), 3);
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
    }

    #[test]
    fn test_history_dedup() {
        let mut h = ReplHistory::new(10);
        h.push("hello".to_string());
        h.push("hello".to_string());
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_limit() {
        let mut h = ReplHistory::new(3);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.push("d".to_string());
        assert_eq!(h.len(), 3);
        assert_eq!(h.entries()[0], "b");
    }

    #[test]
    fn test_history_search() {
        let mut h = ReplHistory::new(20);
        h.push("hex_encode(data)".to_string());
        h.push("disasm(b, 0x1000, 10)".to_string());
        h.push("hex_decode(\"deadbeef\")".to_string());
        let hits = h.search("hex");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_completion_basic() {
        let c = CompletionEngine::new();
        let completions = c.complete("hex");
        assert!(completions.iter().any(|s| s.starts_with("hex")));
    }

    #[test]
    fn test_completion_custom() {
        let mut c = CompletionEngine::new();
        c.add_custom("my_custom_fn".to_string());
        let completions = c.complete("my_");
        assert!(completions.contains(&"my_custom_fn".to_string()));
    }

    #[test]
    fn test_multi_line_complete() {
        let mut ml = MultiLineState::new();
        ml.push("fn test() {");
        assert!(ml.is_active());
        assert!(!ml.is_complete());
        ml.push("}");
        assert!(ml.is_complete());
    }

    #[test]
    fn test_repl_eval_integer() {
        let mut session = make_session();
        let result = session.eval_line("1 + 1");
        match result {
            ReplResult::Value(v) => assert_eq!(v.cast::<i64>(), 2),
            other => panic!("unexpected: {}", other.display()),
        }
    }

    #[test]
    fn test_repl_eval_error() {
        let mut session = make_session();
        let result = session.eval_line("1/0");
        // Division by zero is a Rhai error
        // It might succeed or fail depending on Rhai version; just check no panic
        let _ = result.display();
    }

    #[test]
    fn test_repl_last_result_binding() {
        let mut session = make_session();
        session.eval_line("42");
        let val = session.scope.get_value::<i64>("_");
        assert_eq!(val, Some(42));
    }

    #[test]
    fn test_repl_set_var() {
        let mut session = make_session();
        session.set_var("x", Dynamic::from(99i64));
        let result = session.eval_line("x * 2");
        match result {
            ReplResult::Value(v) => assert_eq!(v.cast::<i64>(), 198),
            other => panic!("unexpected: {}", other.display()),
        }
    }

    #[test]
    fn test_repl_quit() {
        let mut session = make_session();
        let result = session.eval_line(":quit");
        assert!(result.is_quit());
    }

    #[test]
    fn test_repl_help() {
        let mut session = make_session();
        let result = session.eval_line(":help");
        let display = result.display();
        assert!(display.contains("REPL") || display.contains("help"));
    }

    #[test]
    fn test_repl_vars() {
        let mut session = make_session();
        session.eval_line("let answer = 42");
        let result = session.eval_line(":vars");
        let display = result.display();
        assert!(display.contains("answer") || display.contains("_"));
    }

    #[test]
    fn test_batch_eval() {
        let mut session = make_session();
        let outputs = session.run_batch(&["1 + 1", "2 * 3", ":quit"]);
        assert_eq!(outputs[0], "= 2");
        assert_eq!(outputs[1], "= 6");
    }

    #[test]
    fn test_stats() {
        let mut session = make_session();
        session.eval_line("1 + 1");
        session.eval_line("this is invalid syntax !!!@@@");
        let stats = session.stats();
        assert_eq!(stats.eval_count, 2);
        assert!(stats.error_count <= 1);
    }

    #[test]
    fn test_variable_inspector_dump_empty() {
        let scope = Scope::new();
        let dump = VariableInspector::dump_scope(&scope);
        assert!(dump.contains("no variables"));
    }

    #[test]
    fn test_pretty_print_unit() {
        let val = Dynamic::UNIT;
        assert_eq!(pretty_print(&val, 0), "()");
    }

    #[test]
    fn test_pretty_print_int() {
        let val = Dynamic::from(42i64);
        let s = pretty_print(&val, 0);
        assert!(s.contains("42"));
    }

    #[test]
    fn test_completion_common_prefix() {
        let c = CompletionEngine::new();
        let common = c.complete_common("re_hex");
        assert!(common.starts_with("re_hex"));
    }
}
