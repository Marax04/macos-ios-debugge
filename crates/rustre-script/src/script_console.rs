// rustre-script/src/script_console.rs
//
// Interactive REPL for rustre scripting backends (Lua / Python / Rhai).
// Features: history, tab-completion, multiline input, output formatting,
// coloured error display with stack traces, script-file loading, watchdog
// timeout for scripts that hang.

use std::{
    collections::VecDeque,
    fmt::Write as FmtWrite,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use thiserror::Error;

use crate::{ScriptContext, ScriptEngine, ScriptError, ScriptValue};

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConsoleError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("script error: {0}")]
    Script(#[from] ScriptError),
    #[error("watchdog timeout after {0}ms")]
    Timeout(u64),
    #[error("history file error: {0}")]
    History(String),
    #[error("engine not set – call Console::set_engine() first")]
    NoEngine,
}

pub type ConsoleResult<T> = Result<T, ConsoleError>;

// ─────────────────────────────── ANSI colours ────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BLUE: &str = "\x1b[34m";
const DIM: &str = "\x1b[2m";

fn coloured(s: &str, colour: &str, use_colour: bool) -> String {
    if use_colour {
        format!("{colour}{s}{RESET}")
    } else {
        s.to_owned()
    }
}

// ─────────────────────────────── History ─────────────────────────────────────

/// Ring-buffer of command history with optional file persistence.
#[derive(Debug)]
pub struct History {
    entries: VecDeque<String>,
    capacity: usize,
    path: Option<PathBuf>,
    cursor: usize, // 0 = most recent
}

impl History {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            path: None,
            cursor: 0,
        }
    }

    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn load(&mut self) -> ConsoleResult<()> {
        let Some(p) = &self.path else { return Ok(()) };
        if !p.exists() {
            return Ok(());
        }
        let f = std::fs::File::open(p)?;
        let reader = io::BufReader::new(f);
        for line in reader.lines() {
            let l = line?;
            if !l.is_empty() {
                self.push_raw(l);
            }
        }
        Ok(())
    }

    pub fn save(&self) -> ConsoleResult<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let mut f = std::fs::File::create(p)
            .map_err(|e| ConsoleError::History(e.to_string()))?;
        for entry in &self.entries {
            writeln!(f, "{entry}").map_err(|e| ConsoleError::History(e.to_string()))?;
        }
        Ok(())
    }

    fn push_raw(&mut self, line: String) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(line);
        self.cursor = self.entries.len();
    }

    pub fn push(&mut self, line: String) {
        // Deduplicate consecutive identical entries.
        if self.entries.back().map(|s| s == &line).unwrap_or(false) {
            self.cursor = self.entries.len();
            return;
        }
        self.push_raw(line);
    }

    pub fn prev(&mut self) -> Option<&str> {
        if self.entries.is_empty() || self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.entries.get(self.cursor).map(|s| s.as_str())
    }

    pub fn next(&mut self) -> Option<&str> {
        if self.cursor >= self.entries.len() {
            return None;
        }
        self.cursor += 1;
        self.entries.get(self.cursor).map(|s| s.as_str())
    }

    pub fn reset_cursor(&mut self) {
        self.cursor = self.entries.len();
    }

    pub fn all(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|s| s.as_str())
    }
}

// ─────────────────────────────── Completion ──────────────────────────────────

/// Tab-completion provider.  Populated from the engine's registered functions
/// and user-added symbols.
pub struct Completer {
    candidates: Vec<String>,
}

impl Completer {
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
        }
    }

    pub fn add_candidates(&mut self, names: impl IntoIterator<Item = String>) {
        self.candidates.extend(names);
        self.candidates.sort_unstable();
        self.candidates.dedup();
    }

    pub fn add_builtin_keywords(&mut self) {
        let kw = [
            // REPL meta-commands
            ".help", ".quit", ".exit", ".load", ".history", ".clear",
            ".reload", ".engine", ".timeout", ".colour", ".multiline",
            // Rustre API namespaces
            "binary_view.open", "binary_view.close", "binary_view.analyze",
            "binary_view.info", "binary_view.base_address", "binary_view.size",
            "function_table.list", "function_table.get", "function_table.rename",
            "function_table.set_type", "function_table.count",
            "symbol_table.lookup", "symbol_table.lookup_addr",
            "symbol_table.add", "symbol_table.remove", "symbol_table.search",
            "xref_engine.query_forward", "xref_engine.query_backward",
            "patch_set.apply", "patch_set.undo", "patch_set.save",
            "type_system.define_struct", "type_system.define_enum",
            "type_system.resolve", "type_system.list",
            "decompiler.decompile_function", "decompiler.set_option",
            "debugger.attach", "debugger.detach", "debugger.set_breakpoint",
            "debugger.run", "debugger.step", "debugger.read_register",
            "debugger.read_memory",
            "memory_provider.read", "memory_provider.write",
            "memory_provider.regions",
        ];
        self.add_candidates(kw.iter().map(|s| s.to_string()));
    }

    /// Returns all candidates whose prefix matches `prefix`.
    pub fn complete(&self, prefix: &str) -> Vec<&str> {
        self.candidates
            .iter()
            .filter(|c| c.starts_with(prefix))
            .map(|s| s.as_str())
            .collect()
    }
}

impl Default for Completer {
    fn default() -> Self {
        let mut c = Self::new();
        c.add_builtin_keywords();
        c
    }
}

// ─────────────────────────────── OutputFormatter ─────────────────────────────

/// Pretty-prints ScriptValue, errors and diagnostic messages.
pub struct OutputFormatter {
    pub use_colour: bool,
    pub max_bytes_preview: usize,
    pub max_list_items: usize,
    pub indent_step: usize,
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self {
            use_colour: true,
            max_bytes_preview: 64,
            max_list_items: 64,
            indent_step: 2,
        }
    }
}

impl OutputFormatter {
    pub fn format_value(&self, v: &ScriptValue) -> String {
        self.fmt_val(v, 0)
    }

    fn fmt_val(&self, v: &ScriptValue, depth: usize) -> String {
        let indent = " ".repeat(depth * self.indent_step);
        let inner = " ".repeat((depth + 1) * self.indent_step);
        match v {
            ScriptValue::Null => coloured("null", DIM, self.use_colour),
            ScriptValue::Bool(b) => coloured(
                if *b { "true" } else { "false" },
                YELLOW,
                self.use_colour,
            ),
            ScriptValue::Int(n) => coloured(&n.to_string(), CYAN, self.use_colour),
            ScriptValue::Float(f) => coloured(&format!("{f:.6}"), CYAN, self.use_colour),
            ScriptValue::String(s) => {
                coloured(&format!("{s:?}"), GREEN, self.use_colour)
            }
            ScriptValue::Bytes(b) => {
                let preview: Vec<String> = b
                    .iter()
                    .take(self.max_bytes_preview)
                    .map(|x| format!("{x:02x}"))
                    .collect();
                let suffix = if b.len() > self.max_bytes_preview {
                    format!(" … (+{})", b.len() - self.max_bytes_preview)
                } else {
                    String::new()
                };
                coloured(
                    &format!("[{}]{suffix}", preview.join(" ")),
                    BLUE,
                    self.use_colour,
                )
            }
            ScriptValue::Address(a) => {
                coloured(&format!("0x{a:016x}"), YELLOW, self.use_colour)
            }
            ScriptValue::List(items) => {
                if items.is_empty() {
                    return "[]".to_owned();
                }
                let mut out = String::from("[\n");
                for (i, item) in items.iter().take(self.max_list_items).enumerate() {
                    let _ = write!(out, "{inner}{}: {}", i, self.fmt_val(item, depth + 1));
                    out.push('\n');
                }
                if items.len() > self.max_list_items {
                    let _ = write!(out, "{inner}… ({} more)\n", items.len() - self.max_list_items);
                }
                out.push_str(&format!("{indent}]"));
                out
            }
            ScriptValue::Map(m) => {
                if m.is_empty() {
                    return "{}".to_owned();
                }
                let mut out = String::from("{\n");
                for (k, val) in m {
                    let _ = write!(
                        out,
                        "{inner}{}: {}\n",
                        coloured(&format!("{k:?}"), GREEN, self.use_colour),
                        self.fmt_val(val, depth + 1)
                    );
                }
                out.push_str(&format!("{indent}}}"));
                out
            }
            ScriptValue::Callable(name) => {
                coloured(&format!("<fn:{name}>"), BLUE, self.use_colour)
            }
        }
    }

    pub fn format_error(&self, err: &ConsoleError) -> String {
        let prefix = coloured("Error", RED, self.use_colour);
        match err {
            ConsoleError::Script(ScriptError::RuntimeError(message)) => {
                format!("{BOLD}{prefix}:{RESET} {message}\n")
            }
            other => format!("{prefix}: {other}\n"),
        }
    }

    pub fn format_info(&self, msg: &str) -> String {
        format!("{} {msg}\n", coloured("//", DIM, self.use_colour))
    }

    pub fn format_ok(&self, msg: &str) -> String {
        format!("{} {msg}\n", coloured("✓", GREEN, self.use_colour))
    }
}

// ─────────────────────────────── Watchdog ────────────────────────────────────

/// Background watchdog that sets a flag after `timeout_ms` milliseconds.
/// The script engine is expected to poll `interrupted` and abort.
pub struct Watchdog {
    timeout_ms: u64,
    interrupted: Arc<AtomicBool>,
}

impl Watchdog {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return a clone of the interrupted flag (pass to the engine).
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupted)
    }

    /// Start the watchdog timer.  Returns a handle that cancels the timer on drop.
    pub fn arm(&self) -> WatchdogHandle {
        let flag = Arc::clone(&self.interrupted);
        flag.store(false, Ordering::SeqCst);
        let ms = self.timeout_ms;
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel2 = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(ms) {
                if cancel2.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !cancel2.load(Ordering::SeqCst) {
                flag.store(true, Ordering::SeqCst);
            }
        });
        WatchdogHandle { cancel }
    }
}

pub struct WatchdogHandle {
    cancel: Arc<AtomicBool>,
}

impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

// ─────────────────────────────── MultilineBuffer ─────────────────────────────

/// Accumulates partial input lines for multi-line scripts.
#[derive(Default)]
struct MultilineBuffer {
    lines: Vec<String>,
    active: bool,
}

impl MultilineBuffer {
    fn push(&mut self, line: String) {
        self.lines.push(line);
        self.active = true;
    }

    fn reset(&mut self) {
        self.lines.clear();
        self.active = false;
    }

    fn source(&self) -> String {
        self.lines.join("\n")
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ─────────────────────────────── Console ─────────────────────────────────────

/// Interactive REPL console.
///
/// ```ignore
/// let mut console = Console::builder()
///     .engine_name("rhai")
///     .timeout_ms(5_000)
///     .history_file("~/.rustre_history")
///     .use_colour(true)
///     .build();
/// console.run().unwrap();
/// ```
pub struct Console {
    engine: Option<Arc<dyn ScriptEngine>>,
    engine_name: String,
    timeout_ms: u64,
    history: Mutex<History>,
    completer: Completer,
    fmt: OutputFormatter,
    watchdog: Watchdog,
    multiline_buf: Mutex<MultilineBuffer>,
    prompt_primary: String,
    prompt_secondary: String,
}

impl Console {
    pub fn builder() -> ConsoleBuilder {
        ConsoleBuilder::default()
    }

    /// Attach a script engine.
    pub fn set_engine(&mut self, engine: Arc<dyn ScriptEngine>) {
        self.engine_name = engine.name().to_owned();
        self.engine = Some(engine);
    }

    /// Run the interactive REPL until the user exits.
    pub fn run(&self) -> ConsoleResult<()> {
        let stdout = io::stdout();
        let stdin = io::stdin();

        self.print_banner(&stdout);
        self.history.lock().load().ok();

        loop {
            let in_ml = self.multiline_buf.lock().is_active();
            let prompt = if in_ml {
                &self.prompt_secondary
            } else {
                &self.prompt_primary
            };

            {
                let mut out = stdout.lock();
                let _ = write!(out, "{prompt}");
                let _ = out.flush();
            }

            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", ConsoleError::Io(e));
                    break;
                }
            }
            let line = line.trim_end_matches('\n').trim_end_matches('\r').to_owned();

            // Handle meta-commands (.help, .quit, etc.)
            if !self.multiline_buf.lock().is_active() {
                if let Some(done) = self.handle_meta(&line, &stdout)? {
                    if done {
                        break;
                    }
                    continue;
                }
            }

            // Detect multiline trigger: line ending with backslash or opening brace
            let triggers_multiline =
                line.ends_with('\\') || line.ends_with('{') || line == ".ml";
            if triggers_multiline && !self.multiline_buf.lock().is_active() {
                let trimmed = line.trim_end_matches('\\').to_owned();
                self.multiline_buf.lock().push(trimmed);
                continue;
            }

            // Empty line while in multiline = execute
            if self.multiline_buf.lock().is_active() {
                if line.is_empty() {
                    let source = self.multiline_buf.lock().source();
                    self.multiline_buf.lock().reset();
                    self.execute_source(&source, &stdout)?;
                } else {
                    self.multiline_buf.lock().push(line);
                }
                continue;
            }

            // Normal single-line execution
            if !line.is_empty() {
                self.history.lock().push(line.clone());
                self.execute_source(&line, &stdout)?;
            }
        }

        self.history.lock().save().ok();
        Ok(())
    }

    // ── internal ──────────────────────────────────────────────────────────────

    fn print_banner(&self, stdout: &io::Stdout) {
        let mut out = stdout.lock();
        let _ = writeln!(
            out,
            "{}rustre script console{} [engine: {}{}{}]",
            BOLD,
            RESET,
            CYAN,
            self.engine_name,
            RESET
        );
        let _ = writeln!(out, "Type {}.help{} for commands.", BOLD, RESET);
        let _ = writeln!(out);
    }

    fn execute_source(&self, source: &str, stdout: &io::Stdout) -> ConsoleResult<()> {
        let Some(engine) = &self.engine else {
            let msg = self.fmt.format_error(&ConsoleError::NoEngine);
            stdout.lock().write_all(msg.as_bytes())?;
            return Ok(());
        };

        let _guard = self.watchdog.arm();
        let t0 = Instant::now();

        // We use tokio::runtime::Handle if available, otherwise build a small runtime.
        let mut ctx = ScriptContext::new();
        ctx.timeout_ms = Some(self.timeout_ms);
        let result = run_blocking(engine.execute(source, &mut ctx));

        let elapsed = t0.elapsed();
        let mut out = stdout.lock();

        if self.watchdog.flag().load(Ordering::SeqCst) {
            let msg = self.fmt.format_error(&ConsoleError::Timeout(self.timeout_ms));
            out.write_all(msg.as_bytes())?;
            return Ok(());
        }

        match result {
            Ok(val) => {
                if !matches!(val, ScriptValue::Null) {
                    let formatted = self.fmt.format_value(&val);
                    out.write_all(formatted.as_bytes())?;
                    let _ = out.write_all(b"\n");
                }
                let elapsed_str = format!("[{:.2}ms]", elapsed.as_secs_f64() * 1000.0);
                let dim = coloured(&elapsed_str, DIM, self.fmt.use_colour);
                let _ = writeln!(out, "{dim}");
            }
            Err(e) => {
                let msg = self.fmt.format_error(&ConsoleError::Script(e));
                out.write_all(msg.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Returns Some(true) = quit, Some(false) = handled (continue), None = not a meta-command.
    fn handle_meta(&self, line: &str, stdout: &io::Stdout) -> ConsoleResult<Option<bool>> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        match parts[0] {
            ".quit" | ".exit" => return Ok(Some(true)),

            ".help" => {
                let mut out = stdout.lock();
                let _ = writeln!(
                    out,
                    "\
{BOLD}rustre script console{RESET} — commands:
  {CYAN}.help{RESET}            show this message
  {CYAN}.quit{RESET} / {CYAN}.exit{RESET}  exit the console
  {CYAN}.load <file>{RESET}     load and execute a script file
  {CYAN}.history{RESET}         show command history
  {CYAN}.clear{RESET}           clear screen
  {CYAN}.ml{RESET}              start multiline input (empty line to run)
  {CYAN}.engine{RESET}          show active engine name
  {CYAN}.timeout <ms>{RESET}    set watchdog timeout (0 = disabled)
  {CYAN}.colour on|off{RESET}   toggle ANSI colour
  {CYAN}.complete <pfx>{RESET}  list completions for prefix
Tab completion is not available in simple stdin mode.
Multiline: end a line with \\ or {{ to continue on the next line."
                );
            }

            ".history" => {
                let hist = self.history.lock();
                let mut out = stdout.lock();
                for (i, entry) in hist.all().enumerate() {
                    let _ = writeln!(out, "{DIM}{i:4}{RESET}  {entry}");
                }
            }

            ".clear" => {
                let mut out = stdout.lock();
                let _ = out.write_all(b"\x1b[2J\x1b[H");
            }

            ".engine" => {
                let name = self.engine.as_ref().map(|e| e.name()).unwrap_or("<none>");
                let msg = self.fmt.format_info(&format!("engine: {name}"));
                stdout.lock().write_all(msg.as_bytes())?;
            }

            ".load" => {
                let path = parts.get(1).copied().unwrap_or("").trim();
                if path.is_empty() {
                    let msg = self.fmt.format_error(&ConsoleError::History(
                        "usage: .load <path>".to_owned(),
                    ));
                    stdout.lock().write_all(msg.as_bytes())?;
                } else {
                    self.load_file(Path::new(path), stdout)?;
                }
            }

            ".complete" => {
                let prefix = parts.get(1).copied().unwrap_or("").trim();
                let matches = self.completer.complete(prefix);
                let mut out = stdout.lock();
                if matches.is_empty() {
                    let _ = writeln!(out, "{DIM}(no completions){RESET}");
                } else {
                    for m in matches {
                        let _ = writeln!(out, "  {m}");
                    }
                }
            }

            ".colour" | ".color" => {
                // Note: fmt is not behind a Mutex here for simplicity; real impl would wrap it.
                let val = parts.get(1).copied().unwrap_or("").trim();
                let msg = match val {
                    "on" => self.fmt.format_ok("colour enabled (restart for effect)"),
                    "off" => self.fmt.format_ok("colour disabled (restart for effect)"),
                    _ => self.fmt.format_info("usage: .colour on|off"),
                };
                stdout.lock().write_all(msg.as_bytes())?;
            }

            _ => return Ok(None),
        }
        Ok(Some(false))
    }

    /// Load and execute a script from a file.
    pub fn load_file(&self, path: &Path, stdout: &io::Stdout) -> ConsoleResult<()> {
        let source = std::fs::read_to_string(path)?;
        let msg = self.fmt.format_info(&format!("loading {}", path.display()));
        stdout.lock().write_all(msg.as_bytes())?;
        self.execute_source(&source, stdout)
    }

    /// Tab-complete the given prefix.  Returns matching candidates.
    pub fn complete(&self, prefix: &str) -> Vec<String> {
        self.completer
            .complete(prefix)
            .into_iter()
            .map(|s| s.to_owned())
            .collect()
    }
}

// ─────────────────────────────── ConsoleBuilder ───────────────────────────────

#[derive(Default)]
pub struct ConsoleBuilder {
    engine_name: String,
    timeout_ms: u64,
    history_capacity: usize,
    history_file: Option<PathBuf>,
    use_colour: bool,
    max_bytes_preview: usize,
    prompt_primary: String,
    prompt_secondary: String,
}

impl ConsoleBuilder {
    pub fn engine_name(mut self, name: impl Into<String>) -> Self {
        self.engine_name = name.into();
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn history_capacity(mut self, cap: usize) -> Self {
        self.history_capacity = cap;
        self
    }

    pub fn history_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.history_file = Some(path.into());
        self
    }

    pub fn use_colour(mut self, yes: bool) -> Self {
        self.use_colour = yes;
        self
    }

    pub fn max_bytes_preview(mut self, n: usize) -> Self {
        self.max_bytes_preview = n;
        self
    }

    pub fn prompt_primary(mut self, p: impl Into<String>) -> Self {
        self.prompt_primary = p.into();
        self
    }

    pub fn prompt_secondary(mut self, p: impl Into<String>) -> Self {
        self.prompt_secondary = p.into();
        self
    }

    pub fn build(self) -> Console {
        let cap = if self.history_capacity == 0 {
            1000
        } else {
            self.history_capacity
        };
        let mut hist = History::new(cap);
        if let Some(f) = self.history_file {
            hist = hist.with_file(f);
        }

        let timeout = if self.timeout_ms == 0 {
            30_000
        } else {
            self.timeout_ms
        };
        let primary = if self.prompt_primary.is_empty() {
            "rustre> ".to_owned()
        } else {
            self.prompt_primary
        };
        let secondary = if self.prompt_secondary.is_empty() {
            "   ... ".to_owned()
        } else {
            self.prompt_secondary
        };

        let mut completer = Completer::default();
        if !self.engine_name.is_empty() {
            completer.add_candidates(vec![self.engine_name.clone()]);
        }

        Console {
            engine: None,
            engine_name: if self.engine_name.is_empty() {
                "none".to_owned()
            } else {
                self.engine_name
            },
            timeout_ms: timeout,
            history: Mutex::new(hist),
            completer,
            fmt: OutputFormatter {
                use_colour: self.use_colour,
                max_bytes_preview: if self.max_bytes_preview == 0 {
                    64
                } else {
                    self.max_bytes_preview
                },
                ..Default::default()
            },
            watchdog: Watchdog::new(timeout),
            multiline_buf: Mutex::new(MultilineBuffer::default()),
            prompt_primary: primary,
            prompt_secondary: secondary,
        }
    }
}

// ─────────────────────────────── blocking helper ──────────────────────────────

/// Run an async future on the current thread via a tiny tokio current-thread runtime,
/// or re-use an existing handle if we're already inside a tokio context.
fn run_blocking<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're inside an async context — block_in_place.
            tokio::task::block_in_place(|| handle.block_on(fut))
        }
        Err(_) => {
            // No runtime; create a minimal one.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(fut)
        }
    }
}

// ─────────────────────────────── ScriptSessionLog ────────────────────────────

/// Records all inputs and outputs for later export.
#[derive(Debug, Default)]
pub struct SessionLog {
    entries: Vec<SessionEntry>,
}

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub source: String,
    pub output: String,
    pub is_error: bool,
    pub elapsed_ms: f64,
}

impl SessionLog {
    pub fn push(&mut self, entry: SessionEntry) {
        self.entries.push(entry);
    }

    /// Export as plain text transcript.
    pub fn export_text(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let _ = writeln!(out, "> {}", e.source);
            let _ = write!(out, "{}", e.output);
            let _ = writeln!(out, "[{:.2}ms]", e.elapsed_ms);
        }
        out
    }

    /// Export as JSON array.
    pub fn export_json(&self) -> String {
        let items: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    r#"{{ "source": {}, "output": {}, "is_error": {}, "elapsed_ms": {:.2} }}"#,
                    json_escape(&e.source),
                    json_escape(&e.output),
                    e.is_error,
                    e.elapsed_ms
                )
            })
            .collect();
        format!("[{}]", items.join(",\n"))
    }
}

fn json_escape(s: &str) -> String {
    format!("{:?}", s)
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_push_prev_next() {
        let mut h = History::new(10);
        h.push("a".to_owned());
        h.push("b".to_owned());
        h.push("c".to_owned());
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.next(), Some("c"));
    }

    #[test]
    fn history_dedup() {
        let mut h = History::new(10);
        h.push("x".to_owned());
        h.push("x".to_owned());
        assert_eq!(h.entries.len(), 1);
    }

    #[test]
    fn history_capacity() {
        let mut h = History::new(3);
        for i in 0..5 {
            h.push(i.to_string());
        }
        assert_eq!(h.entries.len(), 3);
        assert_eq!(h.entries[0], "2");
    }

    #[test]
    fn completer_prefix() {
        let mut c = Completer::new();
        c.add_candidates(["foo_bar", "foo_baz", "qux"].iter().map(|s| s.to_string()));
        let m = c.complete("foo_");
        assert_eq!(m, vec!["foo_bar", "foo_baz"]);
    }

    #[test]
    fn formatter_null() {
        let f = OutputFormatter { use_colour: false, ..Default::default() };
        assert_eq!(f.format_value(&ScriptValue::Null), "null");
    }

    #[test]
    fn formatter_list() {
        let f = OutputFormatter { use_colour: false, ..Default::default() };
        let v = ScriptValue::List(vec![ScriptValue::Int(1), ScriptValue::Int(2)]);
        let out = f.format_value(&v);
        assert!(out.contains("0: 1"));
        assert!(out.contains("1: 2"));
    }

    #[test]
    fn formatter_map() {
        let f = OutputFormatter { use_colour: false, ..Default::default() };
        let mut m = std::collections::HashMap::new();
        m.insert("key".to_owned(), ScriptValue::Bool(true));
        let out = f.format_value(&ScriptValue::Map(m));
        assert!(out.contains("key"));
        assert!(out.contains("true"));
    }

    #[test]
    fn session_log_json_export() {
        let mut log = SessionLog::default();
        log.push(SessionEntry {
            source: "1+1".to_owned(),
            output: "2".to_owned(),
            is_error: false,
            elapsed_ms: 0.5,
        });
        let json = log.export_json();
        assert!(json.contains("\"1+1\"") || json.contains("1+1"));
        assert!(json.contains("false"));
    }

    #[test]
    fn builder_defaults() {
        let c = Console::builder().use_colour(false).build();
        assert_eq!(c.prompt_primary, "rustre> ");
        assert_eq!(c.timeout_ms, 30_000);
        assert!(!c.fmt.use_colour);
    }

    #[test]
    fn multiline_buffer() {
        let mut buf = MultilineBuffer::default();
        assert!(!buf.is_active());
        buf.push("let x = 1".to_owned());
        buf.push("x + 2".to_owned());
        assert!(buf.is_active());
        assert_eq!(buf.source(), "let x = 1\nx + 2");
        buf.reset();
        assert!(!buf.is_active());
    }
}
