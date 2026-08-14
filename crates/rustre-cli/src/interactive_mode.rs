//! Interactive CLI session mode.
//!
//! Provides [`InteractiveSession`], [`CommandHistory`], [`Autocompleter`],
//! and all built-in commands (analyze / decompile / disasm / goto / search /
//! xrefs / comment / rename / script / breakpoint / memory / registers /
//! help / quit).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

// Re-export the standard formatting module so downstream consumers of
// the interactive-session API can implement custom `Display` impls for
// session-related types without importing `std::fmt` separately.
pub use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InteractiveError {
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("command parse error: {0}")]
    ParseError(String),
    #[error("no file loaded — use 'analyze <path>' first")]
    NoFileLoaded,
    #[error("address parse error: {0}")]
    BadAddress(String),
    #[error("session already terminated")]
    Terminated,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("script error: {0}")]
    ScriptError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionState
// ─────────────────────────────────────────────────────────────────────────────

/// All mutable state held by an [`InteractiveSession`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SessionState {
    /// Path of the currently loaded binary (if any).
    pub loaded_file: Option<PathBuf>,
    /// Current navigation address (program counter equivalent).
    pub current_address: u64,
    /// User-defined comments keyed by virtual address.
    pub comments: HashMap<u64, String>,
    /// User-defined symbol renames keyed by virtual address.
    pub renames: HashMap<u64, String>,
    /// Active breakpoints (virtual addresses).
    pub breakpoints: Vec<u64>,
    /// Whether emulation/debugging is active.
    pub emulation_active: bool,
    /// Register file snapshot (name → value).
    pub registers: HashMap<String, u64>,
    /// Raw memory snapshot (address → bytes).
    pub memory_snapshots: HashMap<u64, Vec<u8>>,
    /// Last executed script path.
    pub last_script: Option<PathBuf>,
}


impl SessionState {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if a file is currently loaded.
    #[must_use]
    pub const fn has_file(&self) -> bool {
        self.loaded_file.is_some()
    }

    /// Check whether a breakpoint is set at the given address.
    #[must_use]
    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains(&addr)
    }

    /// Toggle a breakpoint at the given address.
    pub fn toggle_breakpoint(&mut self, addr: u64) -> bool {
        if let Some(pos) = self.breakpoints.iter().position(|&a| a == addr) {
            self.breakpoints.remove(pos);
            false
        } else {
            self.breakpoints.push(addr);
            true
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommandHistory
// ─────────────────────────────────────────────────────────────────────────────

/// Readline-style command history with navigation.
#[derive(Debug, Clone, Default)]
pub struct CommandHistory {
    entries: Vec<String>,
    cursor: usize,
    max_size: usize,
}

impl CommandHistory {
    /// Create a history with a maximum size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            cursor: 0,
            max_size: max_size.max(1),
        }
    }

    /// Push a command to the history.  Duplicates of the last entry are skipped.
    pub fn push(&mut self, cmd: impl Into<String>) {
        let cmd = cmd.into();
        if cmd.trim().is_empty() {
            return;
        }
        if self.entries.last().map(std::string::String::as_str) == Some(cmd.as_str()) {
            return;
        }
        if self.entries.len() >= self.max_size {
            self.entries.remove(0);
        }
        self.entries.push(cmd);
        self.cursor = self.entries.len();
    }

    /// Navigate backwards (↑).  Returns the previous entry if available.
    #[must_use]
    pub fn prev(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        if self.cursor > 0 {
            self.cursor -= 1;
        }
        self.entries.get(self.cursor).map(std::string::String::as_str)
    }

    /// Navigate forwards (↓).
    #[must_use]
    pub fn next(&mut self) -> Option<&str> {
        if self.cursor + 1 < self.entries.len() {
            self.cursor += 1;
            self.entries.get(self.cursor).map(std::string::String::as_str)
        } else {
            self.cursor = self.entries.len();
            None
        }
    }

    /// Return all entries.
    #[must_use]
    pub fn all(&self) -> &[String] {
        &self.entries
    }

    /// Search history for entries matching a prefix.
    #[must_use]
    pub fn search_prefix(&self, prefix: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.starts_with(prefix))
            .map(std::string::String::as_str)
            .collect()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = 0;
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Autocompleter
// ─────────────────────────────────────────────────────────────────────────────

/// Provides tab-completion suggestions.
#[derive(Debug, Clone)]
pub struct Autocompleter {
    commands: Vec<String>,
    symbols: Vec<String>,
}

impl Autocompleter {
    /// Create with the built-in command list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            commands: builtin_command_names()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            symbols: Vec::new(),
        }
    }

    /// Register a symbol for completion.
    pub fn add_symbol(&mut self, sym: impl Into<String>) {
        self.symbols.push(sym.into());
    }

    /// Return completions for the given partial input.
    #[must_use]
    pub fn complete(&self, partial: &str) -> Vec<String> {
        let mut results: Vec<String> = self
            .commands
            .iter()
            .filter(|c| c.starts_with(partial))
            .cloned()
            .collect();
        let sym_matches: Vec<String> = self
            .symbols
            .iter()
            .filter(|s| s.starts_with(partial))
            .cloned()
            .collect();
        results.extend(sym_matches);
        results.sort();
        results.dedup();
        results
    }
}

impl Default for Autocompleter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in command names
// ─────────────────────────────────────────────────────────────────────────────

const fn builtin_command_names() -> &'static [&'static str] {
    &[
        "analyze",
        "decompile",
        "disasm",
        "goto",
        "search",
        "xrefs",
        "comment",
        "rename",
        "script",
        "breakpoint",
        "memory",
        "registers",
        "help",
        "quit",
        "exit",
        "info",
        "strings",
        "imports",
        "exports",
        "segments",
        "functions",
        "clear",
        "save",
        "load",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// CommandOutput
// ─────────────────────────────────────────────────────────────────────────────

/// The output produced by executing a command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Primary text output.
    pub text: String,
    /// Whether the session should terminate after this command.
    pub should_quit: bool,
    /// Optional address navigation request.
    pub navigate_to: Option<u64>,
    /// Time taken to execute the command.
    pub elapsed_ms: u64,
}

impl CommandOutput {
    fn text(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            should_quit: false,
            navigate_to: None,
            elapsed_ms: 0,
        }
    }
    fn quit() -> Self {
        Self {
            text: "Goodbye.".into(),
            should_quit: true,
            navigate_to: None,
            elapsed_ms: 0,
        }
    }
    fn navigate(addr: u64, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            should_quit: false,
            navigate_to: Some(addr),
            elapsed_ms: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuiltinCommand dispatcher
// ─────────────────────────────────────────────────────────────────────────────

fn parse_address(s: &str) -> Result<u64, InteractiveError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    }
    .map_err(|_| InteractiveError::BadAddress(s.to_owned()))
}

fn cmd_analyze(args: &[&str], state: &mut SessionState) -> Result<CommandOutput, InteractiveError> {
    let path = args
        .first()
        .ok_or_else(|| InteractiveError::ParseError("usage: analyze <path>".into()))?;
    state.loaded_file = Some(PathBuf::from(path));
    Ok(CommandOutput::text(format!(
        "Loaded '{path}' — analysis would run here."
    )))
}

fn cmd_decompile(
    args: &[&str],
    state: &SessionState,
) -> Result<CommandOutput, InteractiveError> {
    if !state.has_file() {
        return Err(InteractiveError::NoFileLoaded);
    }
    let addr = if let Some(a) = args.first() {
        parse_address(a)?
    } else {
        state.current_address
    };
    Ok(CommandOutput::text(format!(
        "Decompile @ {addr:#010x} — stub output."
    )))
}

fn cmd_disasm(args: &[&str], state: &SessionState) -> Result<CommandOutput, InteractiveError> {
    if !state.has_file() {
        return Err(InteractiveError::NoFileLoaded);
    }
    let addr = if let Some(a) = args.first() {
        parse_address(a)?
    } else {
        state.current_address
    };
    let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    Ok(CommandOutput::text(format!(
        "Disasm {count} instructions @ {addr:#010x} — stub output."
    )))
}

fn cmd_goto(args: &[&str], state: &mut SessionState) -> Result<CommandOutput, InteractiveError> {
    let addr = args
        .first()
        .ok_or_else(|| InteractiveError::ParseError("usage: goto <addr>".into()))?;
    let addr = parse_address(addr)?;
    state.current_address = addr;
    Ok(CommandOutput::navigate(
        addr,
        format!("Navigated to {addr:#010x}"),
    ))
}

fn cmd_search(args: &[&str], state: &SessionState) -> Result<CommandOutput, InteractiveError> {
    if !state.has_file() {
        return Err(InteractiveError::NoFileLoaded);
    }
    let pattern = args.join(" ");
    if pattern.is_empty() {
        return Err(InteractiveError::ParseError(
            "usage: search <pattern>".into(),
        ));
    }
    Ok(CommandOutput::text(format!(
        "Search for '{pattern}' — stub (0 results)."
    )))
}

fn cmd_xrefs(args: &[&str], state: &SessionState) -> Result<CommandOutput, InteractiveError> {
    if !state.has_file() {
        return Err(InteractiveError::NoFileLoaded);
    }
    let addr = if let Some(a) = args.first() {
        parse_address(a)?
    } else {
        state.current_address
    };
    Ok(CommandOutput::text(format!(
        "XRefs @ {addr:#010x} — stub (0 references)."
    )))
}

fn cmd_comment(args: &[&str], state: &mut SessionState) -> Result<CommandOutput, InteractiveError> {
    match args {
        [addr, rest @ ..] => {
            let addr = parse_address(addr)?;
            let text = rest.join(" ");
            if text.is_empty() {
                state.comments.remove(&addr);
                Ok(CommandOutput::text(format!(
                    "Comment at {addr:#010x} removed."
                )))
            } else {
                state.comments.insert(addr, text);
                Ok(CommandOutput::text(format!("Comment at {addr:#010x} set.")))
            }
        }
        _ => Err(InteractiveError::ParseError(
            "usage: comment <addr> [text]".into(),
        )),
    }
}

fn cmd_rename(args: &[&str], state: &mut SessionState) -> Result<CommandOutput, InteractiveError> {
    match args {
        [addr, name] => {
            let addr = parse_address(addr)?;
            state.renames.insert(addr, name.to_string());
            Ok(CommandOutput::text(format!(
                "Renamed {addr:#010x} to '{name}'."
            )))
        }
        _ => Err(InteractiveError::ParseError(
            "usage: rename <addr> <name>".into(),
        )),
    }
}

fn cmd_script(args: &[&str], state: &mut SessionState) -> Result<CommandOutput, InteractiveError> {
    let path = args
        .first()
        .ok_or_else(|| InteractiveError::ParseError("usage: script <path>".into()))?;
    state.last_script = Some(PathBuf::from(path));
    Ok(CommandOutput::text(format!(
        "Script '{path}' — execution stub."
    )))
}

fn cmd_breakpoint(
    args: &[&str],
    state: &mut SessionState,
) -> Result<CommandOutput, InteractiveError> {
    if let Some(addr_str) = args.first() {
        let addr = parse_address(addr_str)?;
        let set = state.toggle_breakpoint(addr);
        Ok(CommandOutput::text(if set {
            format!("Breakpoint set at {addr:#010x}")
        } else {
            format!("Breakpoint removed from {addr:#010x}")
        }))
    } else {
        // List breakpoints.
        let list: Vec<_> = state
            .breakpoints
            .iter()
            .map(|a| format!("{a:#010x}"))
            .collect();
        Ok(CommandOutput::text(if list.is_empty() {
            "No breakpoints.".into()
        } else {
            format!("Breakpoints:\n{}", list.join("\n"))
        }))
    }
}

fn cmd_memory(args: &[&str], state: &SessionState) -> Result<CommandOutput, InteractiveError> {
    if !state.has_file() {
        return Err(InteractiveError::NoFileLoaded);
    }
    let addr = if let Some(a) = args.first() {
        parse_address(a)?
    } else {
        state.current_address
    };
    let len: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    Ok(CommandOutput::text(format!(
        "Memory @ {addr:#010x} [{len} bytes] — stub hex dump."
    )))
}

fn cmd_registers(state: &SessionState) -> Result<CommandOutput, InteractiveError> {
    if state.registers.is_empty() {
        return Ok(CommandOutput::text("No registers captured."));
    }
    let mut lines: Vec<_> = state
        .registers
        .iter()
        .map(|(k, v)| format!("{k:>6} = {v:#018x}"))
        .collect();
    lines.sort();
    Ok(CommandOutput::text(lines.join("\n")))
}

fn cmd_help() -> CommandOutput {
    let lines: Vec<&str> = vec![
        "Built-in commands:",
        "  analyze  <path>              Load and analyse a binary",
        "  decompile [addr]             Decompile function at addr (or current)",
        "  disasm   [addr] [n]          Disassemble n instructions",
        "  goto     <addr>              Navigate to address",
        "  search   <pattern>           Search binary for pattern",
        "  xrefs    [addr]              Show cross-references",
        "  comment  <addr> [text]       Set or clear comment",
        "  rename   <addr> <name>       Rename symbol",
        "  script   <path>              Run script file",
        "  breakpoint [addr]            Toggle/list breakpoints",
        "  memory   [addr] [len]        Hex-dump memory",
        "  registers                    Show register state",
        "  info                         Show session info",
        "  strings                      List discovered strings",
        "  imports                      List imports",
        "  exports                      List exports",
        "  segments                     List segments",
        "  functions                    List functions",
        "  save     [path]              Save session",
        "  load     <path>              Load session",
        "  clear                        Clear screen",
        "  help                         Show this help",
        "  quit / exit                  Quit",
    ];
    CommandOutput::text(lines.join("\n"))
}

fn cmd_info(state: &SessionState) -> CommandOutput {
    let file = state
        .loaded_file
        .as_ref().map_or_else(|| "<none>".into(), |p| p.display().to_string());
    CommandOutput::text(format!(
        "File:        {file}\n\
         Address:     {:#010x}\n\
         Breakpoints: {}\n\
         Comments:    {}\n\
         Renames:     {}",
        state.current_address,
        state.breakpoints.len(),
        state.comments.len(),
        state.renames.len(),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// InteractiveSession
// ─────────────────────────────────────────────────────────────────────────────

/// An interactive analysis session.
#[derive(Debug)]
pub struct InteractiveSession {
    /// Session mutable state.
    pub state: SessionState,
    /// Command history.
    pub history: CommandHistory,
    /// Tab-completer.
    pub completer: Autocompleter,
    /// Prompt string (customisable).
    pub prompt: String,
    /// Whether the session has been terminated.
    terminated: bool,
}

impl InteractiveSession {
    /// Create a new session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SessionState::new(),
            history: CommandHistory::new(1000),
            completer: Autocompleter::new(),
            prompt: "rustre> ".to_owned(),
            terminated: false,
        }
    }

    /// Set a custom prompt string.
    pub fn set_prompt(&mut self, p: impl Into<String>) {
        self.prompt = p.into();
    }

    /// Return `true` if the session is still active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.terminated
    }

    /// Execute a single input line.
    ///
    /// # Errors
    /// Returns [`InteractiveError`] on parse or execution failure.
    pub fn execute(&mut self, line: &str) -> Result<CommandOutput, InteractiveError> {
        if self.terminated {
            return Err(InteractiveError::Terminated);
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(CommandOutput::text(""));
        }

        self.history.push(line);

        let t0 = Instant::now();
        let tokens: Vec<&str> = line.splitn(32, ' ').filter(|s| !s.is_empty()).collect();
        let cmd = tokens[0];
        let args = &tokens[1..];

        let mut out = match cmd {
            "analyze" | "open" => cmd_analyze(args, &mut self.state)?,
            "decompile" | "decomp" => cmd_decompile(args, &self.state)?,
            "disasm" | "dis" | "d" => cmd_disasm(args, &self.state)?,
            "goto" | "g" => cmd_goto(args, &mut self.state)?,
            "search" | "s" => cmd_search(args, &self.state)?,
            "xrefs" | "x" => cmd_xrefs(args, &self.state)?,
            "comment" | "c" => cmd_comment(args, &mut self.state)?,
            "rename" | "r" => cmd_rename(args, &mut self.state)?,
            "script" => cmd_script(args, &mut self.state)?,
            "breakpoint" | "bp" | "b" => cmd_breakpoint(args, &mut self.state)?,
            "memory" | "mem" | "m" => cmd_memory(args, &self.state)?,
            "registers" | "reg" => cmd_registers(&self.state)?,
            "help" | "h" | "?" => cmd_help(),
            "info" => cmd_info(&self.state),
            "strings" => {
                if !self.state.has_file() {
                    return Err(InteractiveError::NoFileLoaded);
                }
                CommandOutput::text("Strings — stub.")
            }
            "imports" => {
                if !self.state.has_file() {
                    return Err(InteractiveError::NoFileLoaded);
                }
                CommandOutput::text("Imports — stub.")
            }
            "exports" => {
                if !self.state.has_file() {
                    return Err(InteractiveError::NoFileLoaded);
                }
                CommandOutput::text("Exports — stub.")
            }
            "segments" => {
                if !self.state.has_file() {
                    return Err(InteractiveError::NoFileLoaded);
                }
                CommandOutput::text("Segments — stub.")
            }
            "functions" => {
                if !self.state.has_file() {
                    return Err(InteractiveError::NoFileLoaded);
                }
                CommandOutput::text("Functions — stub.")
            }
            "clear" => CommandOutput::text("\x1b[2J\x1b[H"),
            "save" => CommandOutput::text("Session save — stub."),
            "load" => CommandOutput::text("Session load — stub."),
            "quit" | "exit" | "q" => {
                self.terminated = true;
                CommandOutput::quit()
            }
            other => return Err(InteractiveError::UnknownCommand(other.to_owned())),
        };
        out.elapsed_ms = t0.elapsed().as_millis() as u64;
        Ok(out)
    }

    /// Reset session state (keeps history).
    pub fn reset(&mut self) {
        self.state = SessionState::new();
        self.terminated = false;
    }

    /// Feed multiple lines at once (e.g. from a test or script).
    ///
    /// Stops at the first error or quit command.
    pub fn execute_batch(
        &mut self,
        lines: &[&str],
    ) -> Vec<Result<CommandOutput, InteractiveError>> {
        let mut results = Vec::new();
        for &line in lines {
            let r = self.execute(line);
            let quit = r.as_ref().map(|o| o.should_quit).unwrap_or(false);
            results.push(r);
            if quit {
                break;
            }
        }
        results
    }
}

impl Default for InteractiveSession {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> InteractiveSession {
        InteractiveSession::new()
    }

    // -- SessionState --------------------------------------------------------

    #[test]
    fn test_session_state_default_no_file() {
        let s = SessionState::new();
        assert!(!s.has_file());
    }

    #[test]
    fn test_toggle_breakpoint() {
        let mut s = SessionState::new();
        assert!(s.toggle_breakpoint(0x1000));
        assert!(s.has_breakpoint(0x1000));
        assert!(!s.toggle_breakpoint(0x1000));
        assert!(!s.has_breakpoint(0x1000));
    }

    // -- CommandHistory -------------------------------------------------------

    #[test]
    fn test_history_push_and_len() {
        let mut h = CommandHistory::new(10);
        h.push("analyze foo");
        h.push("disasm");
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn test_history_dedup_consecutive() {
        let mut h = CommandHistory::new(10);
        h.push("help");
        h.push("help");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_max_size() {
        let mut h = CommandHistory::new(3);
        h.push("a");
        h.push("b");
        h.push("c");
        h.push("d");
        assert_eq!(h.len(), 3);
        assert_eq!(h.all()[0], "b");
    }

    #[test]
    fn test_history_prev_next() {
        let mut h = CommandHistory::new(10);
        h.push("a");
        h.push("b");
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.prev(), Some("a"));
        assert_eq!(h.next(), Some("b"));
    }

    #[test]
    fn test_history_search_prefix() {
        let mut h = CommandHistory::new(10);
        h.push("analyze foo");
        h.push("analyze bar");
        h.push("disasm 0x1000");
        let hits = h.search_prefix("analyze");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_history_clear() {
        let mut h = CommandHistory::new(10);
        h.push("help");
        h.clear();
        assert!(h.is_empty());
    }

    // -- Autocompleter -------------------------------------------------------

    #[test]
    fn test_autocompleter_builtin_commands() {
        let ac = Autocompleter::new();
        let results = ac.complete("an");
        assert!(results.contains(&"analyze".to_owned()));
    }

    #[test]
    fn test_autocompleter_symbol() {
        let mut ac = Autocompleter::new();
        ac.add_symbol("sub_401000");
        let results = ac.complete("sub_40");
        assert!(results.contains(&"sub_401000".to_owned()));
    }

    #[test]
    fn test_autocompleter_no_match() {
        let ac = Autocompleter::new();
        assert!(ac.complete("zzzz").is_empty());
    }

    // -- InteractiveSession --------------------------------------------------

    #[test]
    fn test_empty_line_ok() {
        let mut s = session();
        let r = s.execute("   ");
        assert!(r.is_ok());
        assert!(r.unwrap().text.is_empty());
    }

    #[test]
    fn test_comment_line_ok() {
        let mut s = session();
        let r = s.execute("# a comment");
        assert!(r.is_ok());
    }

    #[test]
    fn test_help_command() {
        let mut s = session();
        let out = s.execute("help").unwrap();
        assert!(out.text.contains("analyze"));
    }

    #[test]
    fn test_unknown_command_error() {
        let mut s = session();
        let err = s.execute("frobnicate").unwrap_err();
        assert!(matches!(err, InteractiveError::UnknownCommand(_)));
    }

    #[test]
    fn test_analyze_sets_file() {
        let mut s = session();
        s.execute("analyze /tmp/test.bin").unwrap();
        assert!(s.state.has_file());
    }

    #[test]
    fn test_disasm_without_file_errors() {
        let mut s = session();
        let err = s.execute("disasm").unwrap_err();
        assert!(matches!(err, InteractiveError::NoFileLoaded));
    }

    #[test]
    fn test_goto_sets_address() {
        let mut s = session();
        s.execute("goto 0x1000").unwrap();
        assert_eq!(s.state.current_address, 0x1000);
    }

    #[test]
    fn test_goto_decimal_address() {
        let mut s = session();
        s.execute("goto 4096").unwrap();
        assert_eq!(s.state.current_address, 4096);
    }

    #[test]
    fn test_comment_set_and_clear() {
        let mut s = session();
        s.execute("comment 0x1000 some note").unwrap();
        assert_eq!(
            s.state.comments.get(&0x1000).map(std::string::String::as_str),
            Some("some note")
        );
        s.execute("comment 0x1000").unwrap();
        assert!(!s.state.comments.contains_key(&0x1000));
    }

    #[test]
    fn test_rename_sets_name() {
        let mut s = session();
        s.execute("rename 0x401000 main").unwrap();
        assert_eq!(
            s.state.renames.get(&0x401000).map(std::string::String::as_str),
            Some("main")
        );
    }

    #[test]
    fn test_breakpoint_toggle() {
        let mut s = session();
        s.execute("bp 0x401000").unwrap();
        assert!(s.state.has_breakpoint(0x401000));
        s.execute("bp 0x401000").unwrap();
        assert!(!s.state.has_breakpoint(0x401000));
    }

    #[test]
    fn test_quit_terminates_session() {
        let mut s = session();
        let out = s.execute("quit").unwrap();
        assert!(out.should_quit);
        assert!(!s.is_active());
    }

    #[test]
    fn test_execute_after_quit_errors() {
        let mut s = session();
        s.execute("quit").unwrap();
        let err = s.execute("help").unwrap_err();
        assert!(matches!(err, InteractiveError::Terminated));
    }

    #[test]
    fn test_batch_execute_stops_on_quit() {
        let mut s = session();
        let results = s.execute_batch(&["help", "quit", "help"]);
        assert_eq!(results.len(), 2); // stops after quit
    }

    #[test]
    fn test_info_command() {
        let mut s = session();
        let out = s.execute("info").unwrap();
        assert!(out.text.contains("File:"));
    }

    #[test]
    fn test_history_recorded() {
        let mut s = session();
        s.execute("help").unwrap();
        s.execute("info").unwrap();
        assert_eq!(s.history.len(), 2);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut s = session();
        s.execute("analyze /tmp/x").unwrap();
        s.reset();
        assert!(!s.state.has_file());
        assert!(s.is_active());
    }

    #[test]
    fn test_parse_address_hex() {
        assert_eq!(parse_address("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_address("0X1A2B").unwrap(), 0x1A2B);
    }

    #[test]
    fn test_parse_address_decimal() {
        assert_eq!(parse_address("4096").unwrap(), 4096);
    }

    #[test]
    fn test_parse_address_bad() {
        assert!(parse_address("not_an_addr").is_err());
    }
}
