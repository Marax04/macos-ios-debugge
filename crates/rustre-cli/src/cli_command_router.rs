//! CLI command routing infrastructure.
//!
//! This module implements the `CommandHandler` trait and the `CliCommandRouter`
//! dispatcher that maps command names to their handlers.  It sits between the
//! argument parser (which produces a [`CliCommand`]) and the actual business
//! logic implemented in other crates.
//!
//! # Design
//! * [`CommandHandler`] – object-safe trait implemented by each command.
//! * [`CliCommandRouter`] – registry that maps command name strings to boxed handlers.
//! * [`route_command`] – free function for single-shot routing without a router.
//! * [`CliCommand`] – the enum of all known commands (mirrors the parser output).

use std::collections::HashMap;
use std::fmt;

// ── CliCommand ────────────────────────────────────────────────────────────────

/// A parsed CLI command with its arguments.
///
/// Each variant carries only the data it needs; optional fields use `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Print help text.
    Help,
    /// Print version.
    Version,
    /// Analyse a binary file.
    Analyze {
        /// Path to the binary.
        path: String,
        /// Optional architecture override (e.g. `"x86_64"`, `"arm"`).
        arch: Option<String>,
    },
    /// Disassemble bytes from a file.
    Disassemble {
        /// Path to the binary.
        path: String,
        /// Architecture identifier.
        arch: String,
        /// Base address in the virtual address space.
        base_addr: u64,
        /// Maximum number of instructions.
        count: Option<usize>,
    },
    /// Dump symbols from a binary.
    Symbols {
        /// Path to the binary.
        path: String,
    },
    /// Start an interactive REPL.
    Interactive,
    /// Run a script file.
    Script {
        /// Script file path.
        path: String,
        /// Arguments forwarded to the script.
        args: Vec<String>,
    },
    /// Show effective configuration.
    Config,
    /// A custom/plugin command identified by name.
    Custom {
        /// Command name.
        name: String,
        /// Remaining arguments.
        args: Vec<String>,
    },
}

impl CliCommand {
    /// Return the canonical name of this command.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Help => "help",
            Self::Version => "version",
            Self::Analyze { .. } => "analyze",
            Self::Disassemble { .. } => "disassemble",
            Self::Symbols { .. } => "symbols",
            Self::Interactive => "interactive",
            Self::Script { .. } => "script",
            Self::Config => "config",
            Self::Custom { name, .. } => name.as_str(),
        }
    }

    /// Return a one-line description of the command.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Help => "Print help text",
            Self::Version => "Print version information",
            Self::Analyze { .. } => "Analyse a binary file",
            Self::Disassemble { .. } => "Disassemble bytes from a binary",
            Self::Symbols { .. } => "Dump symbols from a binary",
            Self::Interactive => "Start an interactive REPL session",
            Self::Script { .. } => "Execute a script file",
            Self::Config => "Show effective configuration",
            Self::Custom { .. } => "Custom or plugin command",
        }
    }
}

impl fmt::Display for CliCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── CommandContext ─────────────────────────────────────────────────────────────

/// Execution context passed to every command handler.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// Output format requested by the user.
    pub format: OutputFormat,
    /// Verbosity level (0 = quiet, 1 = normal, 2+ = verbose).
    pub verbosity: u32,
    /// Whether to suppress non-error output.
    pub quiet: bool,
    /// Whether the terminal supports ANSI colour.
    pub color: bool,
    /// Extra key=value options passed after `--`.
    pub extras: HashMap<String, String>,
}

impl Default for CommandContext {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            verbosity: 1,
            quiet: false,
            color: false,
            extras: HashMap::new(),
        }
    }
}

/// Output format codes understood by the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Csv,
}

impl OutputFormat {
    /// Return the format name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

// ── CommandResult ─────────────────────────────────────────────────────────────

/// The outcome of executing a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// Exit code (0 = success, non-zero = failure).
    pub exit_code: i32,
    /// Primary output text (may be JSON, a table, etc.).
    pub output: String,
    /// Any diagnostic or warning messages (shown only if not quiet).
    pub diagnostics: Vec<String>,
}

impl CommandResult {
    /// Construct a successful result.
    #[must_use]
    pub fn success(output: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            output: output.into(),
            diagnostics: Vec::new(),
        }
    }

    /// Construct a failure result.
    #[must_use]
    pub fn failure(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            output: String::new(),
            diagnostics: vec![message.into()],
        }
    }

    /// Return `true` if the command succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// Append a diagnostic message.
    pub fn add_diagnostic(&mut self, msg: impl Into<String>) {
        self.diagnostics.push(msg.into());
    }
}

// ── CommandHandler trait ───────────────────────────────────────────────────────

/// Object-safe trait implemented by every command.
///
/// Implementors receive the parsed [`CliCommand`] and a [`CommandContext`] and
/// return a [`CommandResult`].  Errors are expressed through the `exit_code`
/// field of [`CommandResult`] rather than a `Result` type, matching conventional
/// CLI behaviour.
pub trait CommandHandler: Send + Sync {
    /// Execute the command and return its result.
    fn execute(&self, command: &CliCommand, ctx: &CommandContext) -> CommandResult;

    /// Return `true` if this handler can process `command`.
    ///
    /// The default implementation matches by `CliCommand::name()`.
    fn can_handle(&self, command: &CliCommand) -> bool {
        self.handled_names().iter().any(|n| *n == command.name())
    }

    /// Return the list of command names this handler accepts.
    fn handled_names(&self) -> &[&str];

    /// Return a one-line description of this handler.
    fn description(&self) -> &str;
}

// ── Built-in no-op handlers ───────────────────────────────────────────────────

/// Handler for `help`.
struct HelpHandler;

impl CommandHandler for HelpHandler {
    fn execute(&self, _: &CliCommand, _: &CommandContext) -> CommandResult {
        CommandResult::success(
            "Usage: rustre <command> [options]\n\
             Commands: help, version, analyze, disassemble, symbols, interactive, script, config",
        )
    }
    fn handled_names(&self) -> &[&str] { &["help"] }
    fn description(&self) -> &'static str { "Print usage information" }
}

/// Handler for `version`.
struct VersionHandler {
    version: String,
}

impl CommandHandler for VersionHandler {
    fn execute(&self, _: &CliCommand, _: &CommandContext) -> CommandResult {
        CommandResult::success(format!("rustre {}", self.version))
    }
    fn handled_names(&self) -> &[&str] { &["version"] }
    fn description(&self) -> &'static str { "Print version" }
}

/// Fallback handler that returns an error for unknown commands.
struct UnknownHandler;

impl CommandHandler for UnknownHandler {
    fn execute(&self, cmd: &CliCommand, _: &CommandContext) -> CommandResult {
        CommandResult::failure(1, format!("unknown command: {}", cmd.name()))
    }
    fn handled_names(&self) -> &[&str] { &[] }
    fn can_handle(&self, _: &CliCommand) -> bool { true } // catches anything
    fn description(&self) -> &'static str { "Fallback handler for unknown commands" }
}

// ── CliCommandRouter ──────────────────────────────────────────────────────────

/// Registry that maps command names to their handlers.
///
/// ```ignore
/// let mut router = CliCommandRouter::new("1.0.0");
/// router.register(Box::new(MyAnalyzeHandler));
/// let result = router.route(&CliCommand::Help, &CommandContext::default());
/// ```
pub struct CliCommandRouter {
    /// Registered handlers, in insertion order.
    handlers: Vec<Box<dyn CommandHandler>>,
    /// Index: command name → position in `handlers`.
    index: HashMap<String, usize>,
}

impl CliCommandRouter {
    /// Create a new router with the built-in help and version handlers.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        let mut router = Self {
            handlers: Vec::new(),
            index: HashMap::new(),
        };
        router.register(Box::new(HelpHandler));
        router.register(Box::new(VersionHandler { version: version.into() }));
        // Install the unknown-command fallback first so it is tried *last*
        // (handlers are scanned in reverse order in [`route_command`]).
        router.handlers.insert(0, Box::new(UnknownHandler));
        router
    }

    /// Register a new handler.  If the handler's name(s) are already registered,
    /// the new handler takes precedence.
    pub fn register(&mut self, handler: Box<dyn CommandHandler>) {
        let idx = self.handlers.len();
        for name in handler.handled_names() {
            self.index.insert((*name).to_string(), idx);
        }
        self.handlers.push(handler);
    }

    /// Find and execute the handler for `command`.
    ///
    /// If no specific handler is registered, the unknown-command fallback is used.
    #[must_use] 
    pub fn route(&self, command: &CliCommand, ctx: &CommandContext) -> CommandResult {
        route_command(command, ctx, &self.handlers)
    }

    /// Return the number of registered handlers (including built-ins).
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Return `true` if a handler for `name` is registered.
    #[must_use]
    pub fn has_handler(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    /// List all registered command names.
    #[must_use]
    pub fn registered_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.index.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

// ── route_command (free function) ─────────────────────────────────────────────

/// Route `command` through `handlers`, returning the first matching result.
///
/// Handlers are tried in reverse registration order (last registered = highest
/// priority).  If no handler matches, a built-in fallback error is returned.
#[must_use] 
pub fn route_command(
    command: &CliCommand,
    ctx: &CommandContext,
    handlers: &[Box<dyn CommandHandler>],
) -> CommandResult {
    // Try handlers in reverse order for override semantics.
    for handler in handlers.iter().rev() {
        if handler.can_handle(command) {
            return handler.execute(command, ctx);
        }
    }
    // No handler found.
    CommandResult::failure(127, format!("no handler registered for '{}'", command.name()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> CommandContext {
        CommandContext::default()
    }

    // ── CliCommand ──────────────────────────────────────────────────────────────

    #[test]
    fn test_command_name() {
        assert_eq!(CliCommand::Help.name(), "help");
        assert_eq!(CliCommand::Version.name(), "version");
        assert_eq!(
            CliCommand::Analyze { path: "a.exe".into(), arch: None }.name(),
            "analyze"
        );
    }

    #[test]
    fn test_command_description_not_empty() {
        assert!(!CliCommand::Help.description().is_empty());
        assert!(!CliCommand::Interactive.description().is_empty());
    }

    #[test]
    fn test_command_display() {
        assert_eq!(CliCommand::Config.to_string(), "config");
    }

    #[test]
    fn test_custom_command_name() {
        let cmd = CliCommand::Custom { name: "my-plugin".into(), args: vec![] };
        assert_eq!(cmd.name(), "my-plugin");
    }

    // ── CommandResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_result_success() {
        let r = CommandResult::success("done");
        assert!(r.is_success());
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.output, "done");
        assert!(r.diagnostics.is_empty());
    }

    #[test]
    fn test_result_failure() {
        let r = CommandResult::failure(2, "bad arg");
        assert!(!r.is_success());
        assert_eq!(r.exit_code, 2);
        assert_eq!(r.diagnostics[0], "bad arg");
    }

    #[test]
    fn test_result_add_diagnostic() {
        let mut r = CommandResult::success("ok");
        r.add_diagnostic("warn: foo");
        assert_eq!(r.diagnostics.len(), 1);
    }

    // ── CliCommandRouter ────────────────────────────────────────────────────────

    #[test]
    fn test_router_help() {
        let router = CliCommandRouter::new("0.1.0");
        let r = router.route(&CliCommand::Help, &ctx());
        assert!(r.is_success());
        assert!(!r.output.is_empty());
    }

    #[test]
    fn test_router_version() {
        let router = CliCommandRouter::new("1.2.3");
        let r = router.route(&CliCommand::Version, &ctx());
        assert!(r.is_success());
        assert!(r.output.contains("1.2.3"));
    }

    #[test]
    fn test_router_unknown_command() {
        let router = CliCommandRouter::new("0.0.1");
        let cmd = CliCommand::Custom { name: "ghost".into(), args: vec![] };
        let r = router.route(&cmd, &ctx());
        assert!(!r.is_success());
    }

    #[test]
    fn test_router_has_handler() {
        let router = CliCommandRouter::new("0.0.1");
        assert!(router.has_handler("help"));
        assert!(router.has_handler("version"));
        assert!(!router.has_handler("analyze"));
    }

    #[test]
    fn test_router_registered_names() {
        let router = CliCommandRouter::new("0.0.1");
        let names = router.registered_names();
        assert!(names.contains(&"help"));
        assert!(names.contains(&"version"));
    }

    #[test]
    fn test_router_handler_count() {
        let router = CliCommandRouter::new("0.0.1");
        // Built-ins registered by `new`: help + version + unknown-fallback.
        assert_eq!(router.handler_count(), 3);
    }

    struct EchoHandler;
    impl CommandHandler for EchoHandler {
        fn execute(&self, cmd: &CliCommand, _: &CommandContext) -> CommandResult {
            CommandResult::success(format!("echo:{}", cmd.name()))
        }
        fn handled_names(&self) -> &[&str] { &["echo"] }
        fn description(&self) -> &str { "Echo command name" }
    }

    #[test]
    fn test_router_custom_handler() {
        let mut router = CliCommandRouter::new("0.0.1");
        router.register(Box::new(EchoHandler));
        let cmd = CliCommand::Custom { name: "echo".into(), args: vec![] };
        let r = router.route(&cmd, &ctx());
        assert!(r.is_success());
        assert_eq!(r.output, "echo:echo");
    }

    #[test]
    fn test_route_command_free_fn_no_handlers() {
        let handlers: Vec<Box<dyn CommandHandler>> = vec![];
        let r = route_command(&CliCommand::Help, &ctx(), &handlers);
        assert!(!r.is_success());
        assert_eq!(r.exit_code, 127);
    }

    #[test]
    fn test_output_format_name() {
        assert_eq!(OutputFormat::Text.name(), "text");
        assert_eq!(OutputFormat::Json.name(), "json");
        assert_eq!(OutputFormat::Csv.name(), "csv");
    }

    #[test]
    fn test_context_default() {
        let ctx = CommandContext::default();
        assert_eq!(ctx.verbosity, 1);
        assert!(!ctx.quiet);
        assert!(!ctx.color);
        assert!(ctx.extras.is_empty());
    }
}
