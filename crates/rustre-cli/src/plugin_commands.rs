//! `plugin_commands` — CLI plugin command system.
//!
//! Provides a `PluginCommand` trait, `PluginCommandRegistry`, `HelpFormatter`,
//! `AutocompleteProvider`, and built-in commands: yara, flirt, deobf, crypto,
//! script, triage, debug, diff, network.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ────────────────────────────────────────────────────────────────────

/// Errors from the plugin command subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandError {
    #[error("command not found: '{0}'")]
    NotFound(String),
    #[error("subcommand not found: '{parent} {sub}'")]
    SubCommandNotFound { parent: String, sub: String },
    #[error("missing required argument: {0}")]
    MissingArg(String),
    #[error("invalid argument '{arg}': {reason}")]
    InvalidArg { arg: String, reason: String },
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("already registered: '{0}'")]
    AlreadyRegistered(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

// ─── ArgSpec ──────────────────────────────────────────────────────────────────

/// Describes a single command argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgSpec {
    /// Argument name (positional) or flag name (e.g. `--output`).
    pub name: String,
    /// Short form, e.g. `-o`.
    pub short: Option<String>,
    /// Whether this argument is required.
    pub required: bool,
    /// Human-readable description.
    pub description: String,
    /// Default value if not supplied.
    pub default: Option<String>,
    /// Whether this is a boolean flag (no value).
    pub is_flag: bool,
    /// Allowed values, if restricted.
    pub choices: Vec<String>,
}

impl ArgSpec {
    /// Create a required positional argument.
    #[must_use]
    pub fn required(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            required: true,
            description: description.into(),
            default: None,
            is_flag: false,
            choices: vec![],
        }
    }

    /// Create an optional argument.
    #[must_use]
    pub fn optional(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            required: false,
            description: description.into(),
            default: None,
            is_flag: false,
            choices: vec![],
        }
    }

    /// Create a boolean flag.
    #[must_use]
    pub fn flag(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            required: false,
            description: description.into(),
            default: None,
            is_flag: true,
            choices: vec![],
        }
    }

    /// Builder: set short form.
    #[must_use]
    pub fn with_short(mut self, short: impl Into<String>) -> Self {
        self.short = Some(short.into());
        self
    }

    /// Builder: set default value.
    #[must_use]
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }

    /// Builder: restrict to a set of choices.
    #[must_use]
    pub fn with_choices(mut self, choices: Vec<String>) -> Self {
        self.choices = choices;
        self
    }
}

// ─── CommandArgs ──────────────────────────────────────────────────────────────

/// Parsed command arguments passed to a `PluginCommand`.
#[derive(Debug, Clone, Default)]
pub struct CommandArgs {
    /// Positional arguments in order.
    pub positionals: Vec<String>,
    /// Named arguments (--key value or --flag).
    pub named: HashMap<String, String>,
    /// Boolean flags that are set.
    pub flags: std::collections::HashSet<String>,
}

impl CommandArgs {
    /// Create empty args.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the positional argument at `index`, or `None`.
    #[must_use]
    pub fn positional(&self, index: usize) -> Option<&str> {
        self.positionals.get(index).map(String::as_str)
    }

    /// Return a named argument, or its default from `spec`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.named.get(name).map(String::as_str)
    }

    /// Return a named argument, falling back to `default`.
    #[must_use]
    pub fn get_or_default<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.named.get(name).map_or(default, String::as_str)
    }

    /// Return `true` if the boolean flag is set.
    #[must_use]
    pub fn has_flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    /// Parse a slice of raw string tokens into `CommandArgs`.
    ///
    /// Recognises `--key value`, `--key=value`, and `--flag` forms.
    #[must_use]
    pub fn parse(tokens: &[String]) -> Self {
        let mut args = Self::default();
        let mut i = 0;
        while i < tokens.len() {
            let tok = &tokens[i];
            if let Some(long) = tok.strip_prefix("--") {
                if let Some((k, v)) = long.split_once('=') {
                    args.named.insert(k.to_string(), v.to_string());
                } else if i + 1 < tokens.len() && !tokens[i + 1].starts_with('-') {
                    args.named.insert(long.to_string(), tokens[i + 1].clone());
                    i += 1;
                } else {
                    args.flags.insert(long.to_string());
                }
            } else if let Some(short) = tok.strip_prefix('-') {
                if short.len() == 1 && i + 1 < tokens.len() && !tokens[i + 1].starts_with('-') {
                    args.named.insert(short.to_string(), tokens[i + 1].clone());
                    i += 1;
                } else {
                    args.flags.insert(short.to_string());
                }
            } else {
                args.positionals.push(tok.clone());
            }
            i += 1;
        }
        args
    }
}

// ─── CommandOutput ────────────────────────────────────────────────────────────

/// Output from a successful command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    /// Plain-text output lines.
    pub lines: Vec<String>,
    /// Optional structured JSON output.
    pub json: Option<serde_json::Value>,
    /// Exit code (0 = success).
    pub exit_code: i32,
}

impl CommandOutput {
    /// Create a simple success output.
    #[must_use]
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            lines: vec![text.into()],
            json: None,
            exit_code: 0,
        }
    }

    /// Create output with multiple lines.
    #[must_use]
    pub const fn lines(lines: Vec<String>) -> Self {
        Self { lines, json: None, exit_code: 0 }
    }

    /// Create output with JSON data.
    #[must_use]
    pub fn with_json(mut self, json: serde_json::Value) -> Self {
        self.json = Some(json);
        self
    }

    /// Concatenate all lines.
    #[must_use]
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// Return `true` if the exit code indicates success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

// ─── PluginCommand trait ───────────────────────────────────────────────────────

/// A plugin-provided CLI command.
pub trait PluginCommand: Send + Sync {
    /// Short command name (no spaces), e.g. `"yara"`.
    fn name(&self) -> &str;

    /// Short description for `--help`.
    fn description(&self) -> &str;

    /// Long help text.
    fn long_help(&self) -> &str;

    /// Argument specifications.
    fn args(&self) -> Vec<ArgSpec>;

    /// Subcommands (empty for leaf commands).
    fn subcommands(&self) -> Vec<String> {
        vec![]
    }

    /// Execute the command.
    ///
    /// # Errors
    /// Returns `CommandError` on any failure.
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError>;

    /// Tab-completion candidates for an argument at position `index`.
    fn complete(&self, _index: usize, _partial: &str) -> Vec<String> {
        vec![]
    }
}

// ─── PluginCommandRegistry ────────────────────────────────────────────────────

/// Registry of all plugin-provided CLI commands.
pub struct PluginCommandRegistry {
    commands: HashMap<String, Arc<dyn PluginCommand>>,
}

impl Default for PluginCommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginCommandRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { commands: HashMap::new() }
    }

    /// Create a registry pre-populated with all built-in commands.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        reg.register_builtin(Arc::new(YaraCommand));
        reg.register_builtin(Arc::new(FlirtCommand));
        reg.register_builtin(Arc::new(DeobfCommand));
        reg.register_builtin(Arc::new(CryptoCommand));
        reg.register_builtin(Arc::new(ScriptCommand));
        reg.register_builtin(Arc::new(TriageCommand));
        reg.register_builtin(Arc::new(DebugCommand));
        reg.register_builtin(Arc::new(DiffCommand));
        reg.register_builtin(Arc::new(NetworkCommand));
        reg
    }

    fn register_builtin(&mut self, cmd: Arc<dyn PluginCommand>) {
        self.commands.insert(cmd.name().to_string(), cmd);
    }

    /// Register a new command.
    ///
    /// # Errors
    /// Returns `CommandError::AlreadyRegistered` if the command name is taken.
    pub fn register(&mut self, cmd: Arc<dyn PluginCommand>) -> Result<(), CommandError> {
        let name = cmd.name().to_string();
        if self.commands.contains_key(&name) {
            return Err(CommandError::AlreadyRegistered(name));
        }
        self.commands.insert(name, cmd);
        Ok(())
    }

    /// Replace an existing command (or register if not present).
    pub fn register_or_replace(&mut self, cmd: Arc<dyn PluginCommand>) {
        self.commands.insert(cmd.name().to_string(), cmd);
    }

    /// Remove a command by name. Returns `true` if a command was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.commands.remove(name).is_some()
    }

    /// Look up a command by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<dyn PluginCommand>> {
        self.commands.get(name).cloned()
    }

    /// All registered command names, sorted.
    #[must_use]
    pub fn command_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.commands.keys().cloned().collect();
        names.sort();
        names
    }

    /// Number of registered commands.
    #[must_use]
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// Dispatch a full command line (first token is command name, rest are args).
    ///
    /// # Errors
    /// Returns `CommandError::NotFound` if the command is not registered.
    pub fn dispatch(&self, tokens: &[String]) -> Result<CommandOutput, CommandError> {
        let name = tokens
            .first()
            .ok_or_else(|| CommandError::NotFound("<empty>".into()))?;
        let cmd = self
            .find(name)
            .ok_or_else(|| CommandError::NotFound(name.clone()))?;
        let args = CommandArgs::parse(&tokens[1..]);
        cmd.execute(&args)
    }

    /// Dispatch from a raw string (split on whitespace).
    ///
    /// # Errors
    /// Returns `CommandError::NotFound` if the command is not registered.
    pub fn dispatch_str(&self, line: &str) -> Result<CommandOutput, CommandError> {
        let tokens: Vec<String> = line
            .split_whitespace()
            .map(str::to_string)
            .collect();
        self.dispatch(&tokens)
    }
}

impl fmt::Debug for PluginCommandRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PluginCommandRegistry({} commands)", self.commands.len())
    }
}

// ─── HelpFormatter ────────────────────────────────────────────────────────────

/// Generates `--help` text from a registered command.
pub struct HelpFormatter {
    /// Width of the terminal (used for line wrapping).
    pub width: usize,
}

impl Default for HelpFormatter {
    fn default() -> Self {
        Self { width: 80 }
    }
}

impl HelpFormatter {
    /// Create a formatter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate help text for a single command.
    #[must_use]
    pub fn format(&self, cmd: &dyn PluginCommand) -> String {
        let mut out = String::new();
        out.push_str(&format!("USAGE:\n  {} [OPTIONS]\n\n", cmd.name()));
        out.push_str(&format!("DESCRIPTION:\n  {}\n\n", cmd.description()));

        let long = cmd.long_help();
        if !long.is_empty() {
            out.push_str(&format!("{long}\n\n"));
        }

        let args = cmd.args();
        if !args.is_empty() {
            out.push_str("OPTIONS:\n");
            for arg in &args {
                let name_part = if arg.is_flag {
                    format!("  --{}", arg.name)
                } else if arg.required {
                    format!("  --{} <VALUE>", arg.name)
                } else {
                    format!("  --{} [VALUE]", arg.name)
                };
                let short_part = arg
                    .short
                    .as_deref()
                    .map(|s| format!(", -{s}"))
                    .unwrap_or_default();
                let req = if arg.required { " (required)" } else { "" };
                out.push_str(&format!(
                    "{name_part}{short_part}\n      {}{req}\n",
                    arg.description
                ));
                if let Some(default) = &arg.default {
                    out.push_str(&format!("      [default: {default}]\n"));
                }
                if !arg.choices.is_empty() {
                    out.push_str(&format!("      [choices: {}]\n", arg.choices.join(", ")));
                }
            }
            out.push('\n');
        }

        let subs = cmd.subcommands();
        if !subs.is_empty() {
            out.push_str("SUBCOMMANDS:\n");
            for sub in &subs {
                out.push_str(&format!("  {sub}\n"));
            }
        }
        out
    }

    /// Generate a summary table of all commands in the registry.
    #[must_use]
    pub fn format_all(&self, registry: &PluginCommandRegistry) -> String {
        let mut out = String::from("Available commands:\n\n");
        let max_name = registry
            .commands
            .values()
            .map(|c| c.name().len())
            .max()
            .unwrap_or(10);
        for name in registry.command_names() {
            if let Some(cmd) = registry.find(&name) {
                out.push_str(&format!(
                    "  {:width$}  {}\n",
                    name,
                    cmd.description(),
                    width = max_name
                ));
            }
        }
        out
    }
}

// ─── AutocompleteProvider ─────────────────────────────────────────────────────

/// Provides tab-completion suggestions.
pub struct AutocompleteProvider {
    registry: Arc<PluginCommandRegistry>,
}

impl AutocompleteProvider {
    /// Create a new provider backed by the given registry.
    #[must_use]
    pub const fn new(registry: Arc<PluginCommandRegistry>) -> Self {
        Self { registry }
    }

    /// Complete a partial command line.
    ///
    /// If only one token: complete command names.
    /// If more tokens: delegate to the matched command's `complete`.
    #[must_use]
    pub fn complete(&self, line: &str) -> Vec<String> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() || (tokens.len() == 1 && !line.ends_with(' ')) {
            let partial = tokens.first().copied().unwrap_or("");
            return self
                .registry
                .command_names()
                .into_iter()
                .filter(|n| n.starts_with(partial))
                .collect();
        }
        let cmd_name = tokens[0];
        if let Some(cmd) = self.registry.find(cmd_name) {
            let index = tokens.len() - 1;
            let partial = tokens.last().copied().unwrap_or("");
            let mut candidates = cmd.complete(index, partial);
            // Also add subcommand names.
            for sub in cmd.subcommands() {
                if sub.starts_with(partial) {
                    candidates.push(sub);
                }
            }
            return candidates;
        }
        vec![]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Built-in Commands
// ═══════════════════════════════════════════════════════════════════════════════

// ─── yara ────────────────────────────────────────────────────────────────────

/// The `yara` command: scan files/memory with YARA rules.
pub struct YaraCommand;

impl PluginCommand for YaraCommand {
    fn name(&self) -> &'static str { "yara" }
    fn description(&self) -> &'static str { "Scan targets with YARA rules" }
    fn long_help(&self) -> &'static str {
        "Scan a file, directory, or memory region with one or more YARA rule sets."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("rules", "Path to YARA rules file (.yar / .yara)")
                .with_short("-r"),
            ArgSpec::required("target", "File or directory to scan").with_short("-t"),
            ArgSpec::optional("format", "Output format")
                .with_default("text")
                .with_choices(vec!["text".into(), "json".into(), "csv".into()]),
            ArgSpec::flag("recursive", "Scan directories recursively").with_short("-R"),
            ArgSpec::flag("fast", "Enable fast-scan mode"),
            ArgSpec::optional("timeout", "Per-file timeout in seconds").with_default("30"),
            ArgSpec::optional("max-matches", "Maximum matches per rule").with_default("100"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["scan".into(), "compile".into(), "test".into(), "stats".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let rules = args.get("rules").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("rules".into()))?;
        let target = args.get("target").or_else(|| args.positional(1)).ok_or_else(|| CommandError::MissingArg("target".into()))?;
        let recursive = args.has_flag("recursive");
        let fast = args.has_flag("fast");
        let timeout = args.get_or_default("timeout", "30");
        let max_matches = args.get_or_default("max-matches", "100");
        let format = args.get_or_default("format", "text");
        Ok(CommandOutput::ok(format!(
            "yara: scanning '{target}' with rules '{rules}' \
             [recursive={recursive} fast={fast} timeout={timeout}s \
             max_matches={max_matches} format={format}]"
        )))
    }
    fn complete(&self, index: usize, partial: &str) -> Vec<String> {
        match index {
            0 => vec!["--rules".into(), "--target".into(), "scan".into()],
            _ if partial.starts_with("--format") => {
                vec!["--format=text".into(), "--format=json".into(), "--format=csv".into()]
            }
            _ => vec![],
        }
    }
}

// ─── flirt ────────────────────────────────────────────────────────────────────

/// The `flirt` command: FLIRT signature matching.
pub struct FlirtCommand;

impl PluginCommand for FlirtCommand {
    fn name(&self) -> &'static str { "flirt" }
    fn description(&self) -> &'static str { "FLIRT signature matching against functions" }
    fn long_help(&self) -> &'static str {
        "Apply FLIRT (.sig) library signatures to identify known library functions."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("binary", "Binary to analyse").with_short("-b"),
            ArgSpec::optional("sig-dir", "Directory containing .sig files"),
            ArgSpec::flag("apply", "Apply identified names to the binary"),
            ArgSpec::flag("show-unmatched", "Show functions that did not match"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["match".into(), "list".into(), "apply".into(), "create".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let binary = args.get("binary").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("binary".into()))?;
        let apply = args.has_flag("apply");
        let sig_dir = args.get_or_default("sig-dir", "./sigs");
        Ok(CommandOutput::ok(format!(
            "flirt: matching signatures in '{sig_dir}' against '{binary}' [apply={apply}]"
        )))
    }
}

// ─── deobf ────────────────────────────────────────────────────────────────────

/// The `deobf` command: de-obfuscation passes.
pub struct DeobfCommand;

impl PluginCommand for DeobfCommand {
    fn name(&self) -> &'static str { "deobf" }
    fn description(&self) -> &'static str { "Run de-obfuscation passes on a binary" }
    fn long_help(&self) -> &'static str {
        "Apply de-obfuscation transformations: XOR decryption, constant folding, \
         opaque predicate removal, and stack-string reconstruction."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("binary", "Target binary").with_short("-b"),
            ArgSpec::optional("passes", "Comma-separated pass names"),
            ArgSpec::optional("output", "Output file for patched binary").with_short("-o"),
            ArgSpec::flag("xor", "Run XOR key search"),
            ArgSpec::flag("stack-strings", "Reconstruct stack-built strings"),
            ArgSpec::flag("opaque", "Remove opaque predicates"),
            ArgSpec::flag("const-fold", "Apply constant folding"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["xor".into(), "stack-strings".into(), "opaque".into(), "const-fold".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let binary = args.get("binary").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("binary".into()))?;
        let passes: Vec<&str> = [
            ("xor", args.has_flag("xor")),
            ("stack-strings", args.has_flag("stack-strings")),
            ("opaque", args.has_flag("opaque")),
            ("const-fold", args.has_flag("const-fold")),
        ]
        .iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(p, _)| *p)
        .collect();
        let pass_list = if passes.is_empty() { "all".to_string() } else { passes.join(",") };
        Ok(CommandOutput::ok(format!(
            "deobf: running passes [{pass_list}] on '{binary}'"
        )))
    }
}

// ─── crypto ───────────────────────────────────────────────────────────────────

/// The `crypto` command: cryptographic primitive detection.
pub struct CryptoCommand;

impl PluginCommand for CryptoCommand {
    fn name(&self) -> &'static str { "crypto" }
    fn description(&self) -> &'static str { "Detect cryptographic primitives in a binary" }
    fn long_help(&self) -> &'static str {
        "Identify cryptographic constants (S-boxes, round constants) and algorithm \
         implementations (AES, RSA, ChaCha20, etc.)."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("binary", "Target binary").with_short("-b"),
            ArgSpec::optional("algorithms", "Comma-separated algorithm names to search for"),
            ArgSpec::flag("verbose", "Show matching byte offsets").with_short("-v"),
            ArgSpec::flag("only-used", "Only show cryptographic code that is reachable"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["detect".into(), "list-algorithms".into(), "entropy".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let binary = args.get("binary").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("binary".into()))?;
        let algorithms = args.get_or_default("algorithms", "all");
        let verbose = args.has_flag("verbose");
        Ok(CommandOutput::ok(format!(
            "crypto: scanning '{binary}' for {algorithms} [verbose={verbose}]"
        )))
    }
}

// ─── script ───────────────────────────────────────────────────────────────────

/// The `script` command: execute RE scripts.
pub struct ScriptCommand;

impl PluginCommand for ScriptCommand {
    fn name(&self) -> &'static str { "script" }
    fn description(&self) -> &'static str { "Execute a RustRE script" }
    fn long_help(&self) -> &'static str {
        "Load and execute a Lua, Python, or Rhai script in the RustRE environment."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("file", "Script file to execute").with_short("-f"),
            ArgSpec::optional("lang", "Script language (lua/python/rhai)"),
            ArgSpec::flag("sandbox", "Execute in restricted sandbox mode"),
            ArgSpec::optional("timeout", "Execution timeout in seconds").with_default("60"),
            ArgSpec::optional("arg", "Arguments passed to the script"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["run".into(), "eval".into(), "repl".into(), "lint".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let file = args.get("file").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("file".into()))?;
        let lang = args.get_or_default("lang", "auto");
        let sandbox = args.has_flag("sandbox");
        let timeout = args.get_or_default("timeout", "60");
        Ok(CommandOutput::ok(format!(
            "script: executing '{file}' (lang={lang} sandbox={sandbox} timeout={timeout}s)"
        )))
    }
}

// ─── triage ───────────────────────────────────────────────────────────────────

/// The `triage` command: quick binary triage.
pub struct TriageCommand;

impl PluginCommand for TriageCommand {
    fn name(&self) -> &'static str { "triage" }
    fn description(&self) -> &'static str { "Quick automated triage of a binary" }
    fn long_help(&self) -> &'static str {
        "Run entropy analysis, magic detection, packing checks, import analysis, \
         and string heuristics to quickly classify a binary's threat level."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("binary", "Binary to triage").with_short("-b"),
            ArgSpec::optional("format", "Report format")
                .with_default("text")
                .with_choices(vec!["text".into(), "json".into(), "html".into()]),
            ArgSpec::flag("full", "Run all analysis passes"),
            ArgSpec::flag("strings", "Include string extraction"),
            ArgSpec::flag("imports", "Analyse import table"),
            ArgSpec::optional("output", "Write report to file").with_short("-o"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["analyze".into(), "report".into(), "classify".into(), "score".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let binary = args.get("binary").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("binary".into()))?;
        let full = args.has_flag("full");
        let format = args.get_or_default("format", "text");
        let output = args.get("output").unwrap_or("stdout");
        Ok(CommandOutput::ok(format!(
            "triage: analysing '{binary}' [full={full} format={format} output={output}]"
        )))
    }
}

// ─── debug ────────────────────────────────────────────────────────────────────

/// The `debug` command: debugger integration.
pub struct DebugCommand;

impl PluginCommand for DebugCommand {
    fn name(&self) -> &'static str { "debug" }
    fn description(&self) -> &'static str { "Attach debugger to a process or file" }
    fn long_help(&self) -> &'static str {
        "Launch or attach to a process using the platform debugger backend \
         (ptrace on Linux, Mach ports on macOS, WinDbg on Windows)."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::optional("pid", "Process ID to attach to").with_short("-p"),
            ArgSpec::optional("binary", "Binary to launch under debugger").with_short("-b"),
            ArgSpec::flag("stop-at-entry", "Break at program entry point"),
            ArgSpec::flag("no-aslr", "Disable ASLR for launched processes"),
            ArgSpec::optional("port", "Remote debug port").with_default("9999"),
            ArgSpec::optional("host", "Remote debug host").with_default("localhost"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec![
            "attach".into(),
            "launch".into(),
            "detach".into(),
            "continue".into(),
            "break".into(),
            "step".into(),
            "registers".into(),
            "memory".into(),
        ]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        if let Some(pid) = args.get("pid").or_else(|| args.positional(0)) {
            let stop = args.has_flag("stop-at-entry");
            return Ok(CommandOutput::ok(format!(
                "debug: attaching to PID {pid} [stop_at_entry={stop}]"
            )));
        }
        if let Some(binary) = args.get("binary") {
            let no_aslr = args.has_flag("no-aslr");
            return Ok(CommandOutput::ok(format!(
                "debug: launching '{binary}' [no_aslr={no_aslr}]"
            )));
        }
        Err(CommandError::MissingArg("pid or binary".into()))
    }
}

// ─── diff ─────────────────────────────────────────────────────────────────────

/// The `diff` command: binary diff.
pub struct DiffCommand;

impl PluginCommand for DiffCommand {
    fn name(&self) -> &'static str { "diff" }
    fn description(&self) -> &'static str { "Compare two binary files" }
    fn long_help(&self) -> &'static str {
        "Perform a structural diff of two binaries: byte-level, function-level, \
         and import-table comparison."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::required("a", "First binary").with_short("-a"),
            ArgSpec::required("b", "Second binary").with_short("-b"),
            ArgSpec::optional("mode", "Diff mode")
                .with_default("bytes")
                .with_choices(vec!["bytes".into(), "functions".into(), "imports".into(), "all".into()]),
            ArgSpec::optional("output", "Output file").with_short("-o"),
            ArgSpec::flag("html", "Produce HTML report"),
            ArgSpec::optional("threshold", "Similarity threshold 0-100").with_default("70"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["bytes".into(), "functions".into(), "imports".into(), "report".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        let a = args.get("a").or_else(|| args.positional(0)).ok_or_else(|| CommandError::MissingArg("a".into()))?;
        let b = args.get("b").or_else(|| args.positional(1)).ok_or_else(|| CommandError::MissingArg("b".into()))?;
        let mode = args.get_or_default("mode", "bytes");
        let threshold = args.get_or_default("threshold", "70");
        Ok(CommandOutput::ok(format!(
            "diff: comparing '{a}' vs '{b}' [mode={mode} threshold={threshold}%]"
        )))
    }
}

// ─── network ─────────────────────────────────────────────────────────────────

/// The `network` command: network traffic analysis.
pub struct NetworkCommand;

impl PluginCommand for NetworkCommand {
    fn name(&self) -> &'static str { "network" }
    fn description(&self) -> &'static str { "Capture and analyse network traffic" }
    fn long_help(&self) -> &'static str {
        "Capture live traffic or analyse a PCAP file for protocol dissection, \
         C2 detection, and IOC extraction."
    }
    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::optional("pcap", "PCAP file to analyse").with_short("-p"),
            ArgSpec::optional("interface", "Live capture interface").with_short("-i"),
            ArgSpec::optional("filter", "BPF filter expression").with_short("-f"),
            ArgSpec::flag("c2-detect", "Run C2 beacon detection heuristics"),
            ArgSpec::flag("ioc-extract", "Extract indicators of compromise"),
            ArgSpec::optional("output", "Output file").with_short("-o"),
            ArgSpec::optional("timeout", "Capture duration in seconds").with_default("60"),
        ]
    }
    fn subcommands(&self) -> Vec<String> {
        vec!["capture".into(), "analyse".into(), "decode".into(), "ioc".into(), "stats".into()]
    }
    fn execute(&self, args: &CommandArgs) -> Result<CommandOutput, CommandError> {
        if let Some(pcap) = args.get("pcap") {
            let ioc = args.has_flag("ioc-extract");
            let c2 = args.has_flag("c2-detect");
            return Ok(CommandOutput::ok(format!(
                "network: analysing '{pcap}' [c2={c2} ioc={ioc}]"
            )));
        }
        if let Some(iface) = args.get("interface") {
            let timeout = args.get_or_default("timeout", "60");
            let filter = args.get_or_default("filter", "");
            return Ok(CommandOutput::ok(format!(
                "network: capturing on '{iface}' for {timeout}s [filter='{filter}']"
            )));
        }
        Err(CommandError::MissingArg("pcap or interface".into()))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> PluginCommandRegistry {
        PluginCommandRegistry::with_builtins()
    }

    fn tokens(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    // ── ArgSpec ───────────────────────────────────────────────────────────────

    #[test]
    fn test_argspec_required() {
        let a = ArgSpec::required("file", "The file");
        assert!(a.required);
        assert!(!a.is_flag);
    }

    #[test]
    fn test_argspec_flag() {
        let a = ArgSpec::flag("verbose", "Verbose output");
        assert!(a.is_flag);
        assert!(!a.required);
    }

    #[test]
    fn test_argspec_optional_with_default() {
        let a = ArgSpec::optional("format", "Output format").with_default("json");
        assert_eq!(a.default.as_deref(), Some("json"));
    }

    #[test]
    fn test_argspec_with_choices() {
        let a = ArgSpec::optional("mode", "mode").with_choices(vec!["a".into(), "b".into()]);
        assert_eq!(a.choices.len(), 2);
    }

    #[test]
    fn test_argspec_with_short() {
        let a = ArgSpec::required("file", "f").with_short("-f");
        assert_eq!(a.short.as_deref(), Some("-f"));
    }

    // ── CommandArgs ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_positionals() {
        let args = CommandArgs::parse(&tokens("foo bar"));
        assert_eq!(args.positional(0), Some("foo"));
        assert_eq!(args.positional(1), Some("bar"));
    }

    #[test]
    fn test_parse_named_long_space() {
        let args = CommandArgs::parse(&tokens("--output report.txt"));
        assert_eq!(args.get("output"), Some("report.txt"));
    }

    #[test]
    fn test_parse_named_long_equals() {
        let args = CommandArgs::parse(&tokens("--format=json"));
        assert_eq!(args.get("format"), Some("json"));
    }

    #[test]
    fn test_parse_flag() {
        let args = CommandArgs::parse(&tokens("--verbose"));
        assert!(args.has_flag("verbose"));
        assert!(!args.has_flag("quiet"));
    }

    #[test]
    fn test_parse_short_arg() {
        let args = CommandArgs::parse(&tokens("-o result.bin"));
        assert_eq!(args.get("o"), Some("result.bin"));
    }

    #[test]
    fn test_parse_short_flag() {
        let args = CommandArgs::parse(&tokens("-v"));
        assert!(args.has_flag("v"));
    }

    #[test]
    fn test_get_or_default_missing() {
        let args = CommandArgs::new();
        assert_eq!(args.get_or_default("x", "fallback"), "fallback");
    }

    #[test]
    fn test_get_or_default_present() {
        let args = CommandArgs::parse(&tokens("--x value"));
        assert_eq!(args.get_or_default("x", "fallback"), "value");
    }

    // ── CommandOutput ─────────────────────────────────────────────────────────

    #[test]
    fn test_command_output_ok() {
        let o = CommandOutput::ok("done");
        assert!(o.is_success());
        assert_eq!(o.text(), "done");
    }

    #[test]
    fn test_command_output_lines() {
        let o = CommandOutput::lines(vec!["a".into(), "b".into()]);
        assert_eq!(o.text(), "a\nb");
    }

    #[test]
    fn test_command_output_with_json() {
        let o = CommandOutput::ok("x").with_json(serde_json::json!({"k": 1}));
        assert!(o.json.is_some());
    }

    // ── Registry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_registry_with_builtins_count() {
        let r = reg();
        assert!(r.command_count() >= 9);
    }

    #[test]
    fn test_registry_find_existing() {
        let r = reg();
        assert!(r.find("yara").is_some());
        assert!(r.find("flirt").is_some());
        assert!(r.find("diff").is_some());
    }

    #[test]
    fn test_registry_find_absent() {
        assert!(reg().find("nonexistent").is_none());
    }

    #[test]
    fn test_registry_register_duplicate() {
        let mut r = PluginCommandRegistry::new();
        r.register(Arc::new(YaraCommand)).unwrap();
        let result = r.register(Arc::new(YaraCommand));
        assert!(matches!(result, Err(CommandError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_registry_remove() {
        let mut r = reg();
        assert!(r.remove("yara"));
        assert!(r.find("yara").is_none());
    }

    #[test]
    fn test_registry_command_names_sorted() {
        let r = reg();
        let names = r.command_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_registry_dispatch_yara() {
        let r = reg();
        let out = r.dispatch(&tokens("yara --rules test.yar --target /bin/ls")).unwrap();
        assert!(out.text().contains("test.yar"));
    }

    #[test]
    fn test_registry_dispatch_str() {
        let r = reg();
        let out = r.dispatch_str("flirt --binary /bin/ls").unwrap();
        assert!(out.is_success());
    }

    #[test]
    fn test_registry_dispatch_not_found() {
        let r = reg();
        let result = r.dispatch_str("zork --flag");
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    // ── HelpFormatter ─────────────────────────────────────────────────────────

    #[test]
    fn test_help_format_yara() {
        let fmt = HelpFormatter::new();
        let cmd = YaraCommand;
        let help = fmt.format(&cmd);
        assert!(help.contains("yara"));
        assert!(help.contains("--rules"));
    }

    #[test]
    fn test_help_format_all() {
        let fmt = HelpFormatter::new();
        let r = reg();
        let help = fmt.format_all(&r);
        assert!(help.contains("yara"));
        assert!(help.contains("diff"));
    }

    // ── AutocompleteProvider ──────────────────────────────────────────────────

    #[test]
    fn test_autocomplete_command_names() {
        let r = Arc::new(reg());
        let ac = AutocompleteProvider::new(r);
        let cands = ac.complete("ya");
        assert!(cands.contains(&"yara".to_string()));
    }

    #[test]
    fn test_autocomplete_empty_returns_all() {
        let r = Arc::new(reg());
        let ac = AutocompleteProvider::new(r.clone());
        let cands = ac.complete("");
        assert!(cands.len() >= r.command_count());
    }

    #[test]
    fn test_autocomplete_subcommands() {
        let r = Arc::new(reg());
        let ac = AutocompleteProvider::new(r);
        let cands = ac.complete("yara ");
        assert!(cands.contains(&"scan".to_string()));
    }

    // ── Individual commands ───────────────────────────────────────────────────

    #[test]
    fn test_yara_missing_rules() {
        let r = reg();
        let result = r.dispatch_str("yara --target /bin/ls");
        assert!(matches!(result, Err(CommandError::MissingArg(_))));
    }

    #[test]
    fn test_yara_success() {
        let r = reg();
        let out = r.dispatch_str("yara --rules r.yar --target t").unwrap();
        assert!(out.text().contains("r.yar"));
    }

    #[test]
    fn test_flirt_missing_binary() {
        let r = reg();
        let result = r.dispatch_str("flirt");
        assert!(result.is_err());
    }

    #[test]
    fn test_deobf_flags() {
        let r = reg();
        let out = r.dispatch_str("deobf --binary malware.bin --xor --stack-strings").unwrap();
        assert!(out.text().contains("xor"));
        assert!(out.text().contains("stack-strings"));
    }

    #[test]
    fn test_crypto_success() {
        let r = reg();
        let out = r.dispatch_str("crypto --binary prog.exe --algorithms AES").unwrap();
        assert!(out.text().contains("AES"));
    }

    #[test]
    fn test_triage_success() {
        let r = reg();
        let out = r.dispatch_str("triage --binary sample.exe --full").unwrap();
        assert!(out.text().contains("sample.exe"));
    }

    #[test]
    fn test_debug_attach_pid() {
        let r = reg();
        let out = r.dispatch_str("debug --pid 1234").unwrap();
        assert!(out.text().contains("1234"));
    }

    #[test]
    fn test_debug_launch_binary() {
        let r = reg();
        let out = r.dispatch_str("debug --binary /bin/ls").unwrap();
        assert!(out.text().contains("/bin/ls"));
    }

    #[test]
    fn test_debug_no_args_error() {
        let r = reg();
        assert!(r.dispatch_str("debug").is_err());
    }

    #[test]
    fn test_diff_success() {
        let r = reg();
        let out = r.dispatch_str("diff --a old.exe --b new.exe --mode functions").unwrap();
        assert!(out.text().contains("old.exe"));
        assert!(out.text().contains("functions"));
    }

    #[test]
    fn test_diff_missing_b() {
        let r = reg();
        let result = r.dispatch_str("diff --a only.exe");
        assert!(matches!(result, Err(CommandError::MissingArg(_))));
    }

    #[test]
    fn test_network_pcap() {
        let r = reg();
        let out = r.dispatch_str("network --pcap capture.pcap --c2-detect").unwrap();
        assert!(out.text().contains("capture.pcap"));
        assert!(out.text().contains("c2=true"));
    }

    #[test]
    fn test_network_live() {
        let r = reg();
        let out = r.dispatch_str("network --interface eth0 --timeout 10").unwrap();
        assert!(out.text().contains("eth0"));
        assert!(out.text().contains("10s"));
    }

    #[test]
    fn test_network_no_args_error() {
        let r = reg();
        assert!(r.dispatch_str("network").is_err());
    }

    #[test]
    fn test_script_success() {
        let r = reg();
        let out = r.dispatch_str("script --file analyze.lua --lang lua").unwrap();
        assert!(out.text().contains("analyze.lua"));
    }

    #[test]
    fn test_yara_subcommands() {
        let cmd = YaraCommand;
        assert!(cmd.subcommands().contains(&"scan".to_string()));
        assert!(cmd.subcommands().contains(&"compile".to_string()));
    }
}
