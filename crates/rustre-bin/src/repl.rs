use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, Context};
use rustyline::{Editor, Config, CompletionType, EditMode};
use rustyline::completion::FilenameCompleter;
use rustyline::hint::HistoryHinter;
use rustyline_derive::{Completer, Helper, Highlighter, Hinter, Validator};
use crossterm::style::Stylize;

#[derive(Debug, Clone, PartialEq)]
pub enum ReplMode {
    Main,
    Disassembly,
    HexDump,
    Graph,
    Symbols,
    Strings,
    Script,
}

impl std::fmt::Display for ReplMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplMode::Main => write!(f, "main"),
            ReplMode::Disassembly => write!(f, "disasm"),
            ReplMode::HexDump => write!(f, "hex"),
            ReplMode::Graph => write!(f, "graph"),
            ReplMode::Symbols => write!(f, "syms"),
            ReplMode::Strings => write!(f, "strs"),
            ReplMode::Script => write!(f, "script"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplContext {
    pub loaded_file: Option<PathBuf>,
    pub current_address: u64,
    pub mode: ReplMode,
    pub architecture: String,
    pub base_address: u64,
    pub history_file: PathBuf,
    pub variables: HashMap<String, String>,
    pub aliases: HashMap<String, String>,
    pub last_result: Option<String>,
    pub bookmarks: HashMap<String, u64>,
}

impl Default for ReplContext {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            loaded_file: None,
            current_address: 0,
            mode: ReplMode::Main,
            architecture: "x86_64".to_string(),
            base_address: 0x400000,
            history_file: home.join(".rustre_history"),
            variables: HashMap::new(),
            aliases: HashMap::new(),
            last_result: None,
            bookmarks: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub output: String,
    pub success: bool,
    pub side_effect: Option<SideEffect>,
}

#[derive(Debug, Clone)]
pub enum SideEffect {
    LoadFile(PathBuf),
    ChangeAddress(u64),
    ChangeMode(ReplMode),
    ExitRepl,
    ExecScript(PathBuf),
}

impl CommandResult {
    pub fn ok(output: impl Into<String>) -> Self {
        Self { output: output.into(), success: true, side_effect: None }
    }
    pub fn err(output: impl Into<String>) -> Self {
        Self { output: output.into(), success: false, side_effect: None }
    }
    pub fn with_effect(mut self, effect: SideEffect) -> Self {
        self.side_effect = Some(effect);
        self
    }
}

#[derive(Helper, Completer, Hinter, Highlighter, Validator)]
pub struct ReplHelper {
    #[rustyline(Completer)]
    completer: FilenameCompleter,
    #[rustyline(Hinter)]
    hinter: HistoryHinter,
    pub commands: Vec<String>,
}

impl ReplHelper {
    pub fn new(commands: Vec<String>) -> Self {
        Self {
            completer: FilenameCompleter::new(),
            hinter: HistoryHinter {},
            commands,
        }
    }
}

pub struct Repl {
    context: Arc<RwLock<ReplContext>>,
    commands: HashMap<String, Box<dyn Command + Send + Sync>>,
    prompt_prefix: String,
}

impl Repl {
    /// Construct a new top-level `Repl` with no commands registered.
    pub fn new(prompt_prefix: impl Into<String>) -> Self {
        Self {
            context: Arc::new(RwLock::new(ReplContext::default())),
            commands: HashMap::new(),
            prompt_prefix: prompt_prefix.into(),
        }
    }

    /// Register a command, replacing any prior registration with the same name.
    pub fn register(&mut self, cmd: Box<dyn Command + Send + Sync>) {
        self.commands.insert(cmd.name().to_string(), cmd);
    }

    /// Returns a clone of the shared context handle.
    pub fn context(&self) -> Arc<RwLock<ReplContext>> {
        Arc::clone(&self.context)
    }

    /// List the names of every registered command, sorted alphabetically.
    pub fn command_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.commands.keys().cloned().collect();
        names.sort();
        names
    }

    /// Write the current prompt to `out`, flushing afterward. The prompt has
    /// the form `<prefix>> `.
    pub fn write_prompt<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        write!(out, "{}> ", self.prompt_prefix)?;
        out.flush()
    }
}

impl Default for Repl {
    fn default() -> Self {
        Self::new("rustre")
    }
}

pub trait Command: Send + Sync {
    fn name(&self) -> &str;
    fn aliases(&self) -> &[&str] { &[] }
    fn help(&self) -> &str;
    fn usage(&self) -> &str;
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult;
}

pub struct HelpCommand;
impl Command for HelpCommand {
    fn name(&self) -> &str { "help" }
    fn aliases(&self) -> &[&str] { &["h", "?"] }
    fn help(&self) -> &str { "Show help for commands" }
    fn usage(&self) -> &str { "help [command]" }
    fn execute(&self, args: &[&str], _ctx: &mut ReplContext) -> CommandResult {
        if args.is_empty() {
            CommandResult::ok(HELP_TEXT)
        } else {
            CommandResult::ok(format!("No specific help for '{}'", args[0]))
        }
    }
}

pub struct OpenCommand;
impl Command for OpenCommand {
    fn name(&self) -> &str { "open" }
    fn aliases(&self) -> &[&str] { &["o", "load"] }
    fn help(&self) -> &str { "Open a binary file for analysis" }
    fn usage(&self) -> &str { "open <path> [--base <addr>]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        if args.is_empty() {
            return CommandResult::err("Usage: open <path>");
        }
        let path = PathBuf::from(args[0]);
        if !path.exists() {
            return CommandResult::err(format!("File not found: {}", args[0]));
        }
        let mut base = ctx.base_address;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--base" || args[i] == "-b" {
                if let Some(addr_str) = args.get(i + 1) {
                    let addr_str = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        base = addr;
                    }
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }
        ctx.loaded_file = Some(path.clone());
        ctx.base_address = base;
        ctx.current_address = base;
        CommandResult::ok(format!("Loaded: {} (base: {:#x})", path.display(), base))
            .with_effect(SideEffect::LoadFile(path))
    }
}

pub struct SeekCommand;
impl Command for SeekCommand {
    fn name(&self) -> &str { "seek" }
    fn aliases(&self) -> &[&str] { &["s", "goto"] }
    fn help(&self) -> &str { "Move to an address or symbol" }
    fn usage(&self) -> &str { "seek <addr|symbol|+/-offset>" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        if args.is_empty() {
            return CommandResult::ok(format!("Current address: {:#x}", ctx.current_address));
        }
        let arg = args[0];
        let new_addr = if let Some(stripped) = arg.strip_prefix('+') {
            let offset = parse_addr(stripped).unwrap_or(0);
            ctx.current_address.wrapping_add(offset)
        } else if let Some(stripped) = arg.strip_prefix('-') {
            let offset = parse_addr(stripped).unwrap_or(0);
            ctx.current_address.wrapping_sub(offset)
        } else if let Some(bookmark) = ctx.bookmarks.get(arg) {
            *bookmark
        } else {
            match parse_addr(arg) {
                Some(a) => a,
                None => return CommandResult::err(format!("Cannot parse address: {}", arg)),
            }
        };
        ctx.current_address = new_addr;
        CommandResult::ok(format!("=> {:#x}", new_addr))
            .with_effect(SideEffect::ChangeAddress(new_addr))
    }
}

pub struct PrintCommand;
impl Command for PrintCommand {
    fn name(&self) -> &str { "print" }
    fn aliases(&self) -> &[&str] { &["p", "px"] }
    fn help(&self) -> &str { "Print hex dump at current address" }
    fn usage(&self) -> &str { "print [len] [addr]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        let len: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(256);
        let addr = args.get(1).and_then(|s| parse_addr(s)).unwrap_or(ctx.current_address);
        CommandResult::ok(format!("Hex dump at {:#x}, {} bytes (file not loaded in repl mode)", addr, len))
    }
}

pub struct InfoCommand;
impl Command for InfoCommand {
    fn name(&self) -> &str { "info" }
    fn aliases(&self) -> &[&str] { &["i", "status"] }
    fn help(&self) -> &str { "Show current analysis status" }
    fn usage(&self) -> &str { "info [sections|imports|exports|headers]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        let sub = args.first().copied().unwrap_or("all");
        match sub {
            "sections" => CommandResult::ok("Sections: (load a file first)"),
            "imports" => CommandResult::ok("Imports: (load a file first)"),
            "exports" => CommandResult::ok("Exports: (load a file first)"),
            "headers" => CommandResult::ok("Headers: (load a file first)"),
            _ => {
                let file = ctx.loaded_file.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_string());
                CommandResult::ok(format!(
                    "File:    {}\nArch:    {}\nBase:    {:#x}\nCursor:  {:#x}\nMode:    {}",
                    file, ctx.architecture, ctx.base_address, ctx.current_address, ctx.mode
                ))
            }
        }
    }
}

pub struct ModeCommand;
impl Command for ModeCommand {
    fn name(&self) -> &str { "mode" }
    fn aliases(&self) -> &[&str] { &["m"] }
    fn help(&self) -> &str { "Switch REPL mode" }
    fn usage(&self) -> &str { "mode <main|disasm|hex|graph|symbols|strings|script>" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        let m = match args.first().copied() {
            Some("main") | Some("m") => ReplMode::Main,
            Some("disasm") | Some("d") => ReplMode::Disassembly,
            Some("hex") | Some("h") => ReplMode::HexDump,
            Some("graph") | Some("g") => ReplMode::Graph,
            Some("symbols") | Some("syms") | Some("s") => ReplMode::Symbols,
            Some("strings") | Some("strs") => ReplMode::Strings,
            Some("script") => ReplMode::Script,
            Some(other) => return CommandResult::err(format!("Unknown mode: {}", other)),
            None => return CommandResult::ok(format!("Current mode: {}", ctx.mode)),
        };
        let prev = ctx.mode.clone();
        ctx.mode = m.clone();
        CommandResult::ok(format!("{} -> {}", prev, m))
            .with_effect(SideEffect::ChangeMode(m))
    }
}

pub struct BookmarkCommand;
impl Command for BookmarkCommand {
    fn name(&self) -> &str { "bookmark" }
    fn aliases(&self) -> &[&str] { &["bm", "b"] }
    fn help(&self) -> &str { "Set/list bookmarks" }
    fn usage(&self) -> &str { "bookmark [name] [addr]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        if args.is_empty() {
            if ctx.bookmarks.is_empty() {
                return CommandResult::ok("No bookmarks set");
            }
            let mut out = String::from("Bookmarks:\n");
            let mut bm: Vec<_> = ctx.bookmarks.iter().collect();
            bm.sort_by_key(|(_, v)| *v);
            for (name, addr) in bm {
                out.push_str(&format!("  {:20} {:#x}\n", name, addr));
            }
            return CommandResult::ok(out);
        }
        let name = args[0].to_string();
        let addr = if let Some(s) = args.get(1) {
            parse_addr(s).unwrap_or(ctx.current_address)
        } else {
            ctx.current_address
        };
        ctx.bookmarks.insert(name.clone(), addr);
        CommandResult::ok(format!("Bookmark '{}' -> {:#x}", name, addr))
    }
}

pub struct QuitCommand;
impl Command for QuitCommand {
    fn name(&self) -> &str { "quit" }
    fn aliases(&self) -> &[&str] { &["q", "exit", "bye"] }
    fn help(&self) -> &str { "Exit the REPL" }
    fn usage(&self) -> &str { "quit" }
    fn execute(&self, _args: &[&str], _ctx: &mut ReplContext) -> CommandResult {
        CommandResult::ok("Goodbye.").with_effect(SideEffect::ExitRepl)
    }
}

pub struct SetCommand;
impl Command for SetCommand {
    fn name(&self) -> &str { "set" }
    fn aliases(&self) -> &[&str] { &[] }
    fn help(&self) -> &str { "Set/get variables" }
    fn usage(&self) -> &str { "set [name [value]]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        match args.len() {
            0 => {
                if ctx.variables.is_empty() {
                    return CommandResult::ok("No variables set");
                }
                let mut out = String::new();
                let mut vars: Vec<_> = ctx.variables.iter().collect();
                vars.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in vars {
                    out.push_str(&format!("{}={}\n", k, v));
                }
                CommandResult::ok(out)
            }
            1 => {
                let val = ctx.variables.get(args[0]).cloned().unwrap_or_default();
                CommandResult::ok(format!("{}={}", args[0], val))
            }
            _ => {
                ctx.variables.insert(args[0].to_string(), args[1..].join(" "));
                CommandResult::ok(format!("{}={}", args[0], args[1..].join(" ")))
            }
        }
    }
}

pub struct AliasCommand;
impl Command for AliasCommand {
    fn name(&self) -> &str { "alias" }
    fn aliases(&self) -> &[&str] { &[] }
    fn help(&self) -> &str { "Define command aliases" }
    fn usage(&self) -> &str { "alias [name [expansion]]" }
    fn execute(&self, args: &[&str], ctx: &mut ReplContext) -> CommandResult {
        match args.len() {
            0 => {
                let mut out = String::new();
                let mut aliases: Vec<_> = ctx.aliases.iter().collect();
                aliases.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in aliases {
                    out.push_str(&format!("{}='{}'\n", k, v));
                }
                if out.is_empty() { CommandResult::ok("No aliases defined") }
                else { CommandResult::ok(out) }
            }
            1 => {
                let val = ctx.aliases.get(args[0]).cloned().unwrap_or_default();
                CommandResult::ok(format!("{}='{}'", args[0], val))
            }
            _ => {
                ctx.aliases.insert(args[0].to_string(), args[1..].join(" "));
                CommandResult::ok(format!("alias {}='{}'", args[0], args[1..].join(" ")))
            }
        }
    }
}

fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() >= 4 {
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

const HELP_TEXT: &str = r#"RustRE Interactive Shell
========================
Navigation:
  open <file>         Load binary for analysis
  seek <addr>         Move cursor to address
  info [sections|imports|exports]  Show analysis info

Display:
  print [len] [addr]  Hex dump
  mode <mode>         Switch mode: main/disasm/hex/graph/symbols/strings/script

Bookmarks:
  bookmark [name] [addr]   Set/list bookmarks

Variables:
  set [name] [value]  Set shell variables
  alias [name] [cmd]  Define aliases

Misc:
  help [cmd]          Show help
  quit                Exit
"#;

pub struct ReplEngine {
    context: ReplContext,
    commands: Vec<Box<dyn Command + Send + Sync>>,
}

impl ReplEngine {
    pub fn new() -> Self {
        let commands: Vec<Box<dyn Command + Send + Sync>> = vec![
            Box::new(HelpCommand),
            Box::new(OpenCommand),
            Box::new(SeekCommand),
            Box::new(PrintCommand),
            Box::new(InfoCommand),
            Box::new(ModeCommand),
            Box::new(BookmarkCommand),
            Box::new(QuitCommand),
            Box::new(SetCommand),
            Box::new(AliasCommand),
        ];
        Self { context: ReplContext::default(), commands }
    }

    fn find_command(&self, name: &str) -> Option<&dyn Command> {
        // Check aliases first
        let expanded = self.context.aliases.get(name).cloned();
        let name = expanded.as_deref().unwrap_or(name);
        for cmd in &self.commands {
            if cmd.name() == name || cmd.aliases().contains(&name) {
                return Some(cmd.as_ref());
            }
        }
        None
    }

    fn execute_line(&mut self, line: &str) -> Option<SideEffect> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // Variable interpolation
        let line = self.interpolate_vars(line);
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { return None; }

        let cmd_name = parts[0];
        let args = &parts[1..];

        // Pre-flight via [`Self::find_command`] so unknown commands short-circuit
        // before we scan the command vector twice. The same lookup is re-run
        // below in order to obtain the mutable execution slot.
        if self.find_command(cmd_name).is_none() {
            eprintln!("{}", format!("Unknown command: '{}'. Type 'help' for commands.", cmd_name).red());
            return None;
        }
        let cmd_idx = self.commands.iter().position(|cmd| {
            let expanded = self.context.aliases.get(cmd_name).cloned();
            let name = expanded.as_deref().unwrap_or(cmd_name);
            cmd.name() == name || cmd.aliases().contains(&name)
        });

        if let Some(idx) = cmd_idx {
            let cmd = &self.commands[idx];
            let result = cmd.execute(args, &mut self.context);
            if result.success {
                if !result.output.is_empty() {
                    println!("{}", result.output.clone().green());
                }
            } else {
                eprintln!("{}", result.output.clone().red());
            }
            self.context.last_result = Some(result.output);
            result.side_effect
        } else {
            eprintln!("{}", format!("Unknown command: '{}'. Type 'help' for commands.", cmd_name).red());
            None
        }
    }

    fn interpolate_vars(&self, line: &str) -> String {
        let mut result = line.to_string();
        for (k, v) in &self.context.variables {
            result = result.replace(&format!("${}", k), v);
            result = result.replace(&format!("${{{}}}", k), v);
        }
        // Special variables
        result = result.replace("$addr", &format!("{:#x}", self.context.current_address));
        result = result.replace("$mode", &self.context.mode.to_string());
        result
    }

    pub fn make_prompt(&self) -> String {
        let file = self.context.loaded_file.as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("(none)");
        format!(
            "[{}|{}|{:#010x}]> ",
            file, self.context.mode, self.context.current_address
        )
    }

    pub fn run_interactive(&mut self) -> Result<()> {
        let config = Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .build();

        let cmd_names: Vec<String> = self.commands.iter()
            .flat_map(|c| {
                let mut names = vec![c.name().to_string()];
                names.extend(c.aliases().iter().map(|s| s.to_string()));
                names
            })
            .collect();

        let helper = ReplHelper::new(cmd_names);
        let mut rl = Editor::with_config(config)?;
        rl.set_helper(Some(helper));

        let _ = rl.load_history(&self.context.history_file);

        println!("{}", "RustRE Interactive Shell - type 'help' for commands".bold().cyan());
        println!("{}", format!("Version {}", env!("CARGO_PKG_VERSION")).dim());

        loop {
            let prompt = self.make_prompt();
            match rl.readline(&prompt) {
                Ok(line) => {
                    let _ = rl.add_history_entry(&line);
                    if let Some(SideEffect::ExitRepl) = self.execute_line(&line) {
                        break;
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    println!("^C");
                    continue;
                }
                Err(rustyline::error::ReadlineError::Eof) => {
                    println!("^D");
                    break;
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    break;
                }
            }
        }

        let _ = rl.save_history(&self.context.history_file);
        Ok(())
    }

    pub fn run_script(&mut self, path: &std::path::Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read script: {}", path.display()))?;
        for (lineno, line) in content.lines().enumerate() {
            let effect = self.execute_line(line);
            if let Some(SideEffect::ExitRepl) = effect {
                break;
            }
            if let Some(SideEffect::ExecScript(script_path)) = effect {
                self.run_script(&script_path)
                    .with_context(|| format!("Script error at line {}", lineno + 1))?;
            }
        }
        Ok(())
    }
}

impl Default for ReplEngine {
    fn default() -> Self {
        Self::new()
    }
}
