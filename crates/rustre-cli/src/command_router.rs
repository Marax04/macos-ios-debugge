//! CLI command routing: command registry, subcommand dispatch, argument
//! validation, and help generation.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("unknown command: '{0}'")]
    UnknownCommand(String),
    #[error("missing required argument: '{0}'")]
    MissingArgument(String),
    #[error("invalid argument '{name}': {reason}")]
    InvalidArgument { name: String, reason: String },
    #[error("too many positional arguments (expected at most {max}, got {got})")]
    TooManyPositional { max: usize, got: usize },
    #[error("ambiguous command: '{prefix}' matches {count} commands")]
    Ambiguous { prefix: String, count: usize },
    #[error("subcommand '{0}' does not accept subcommands")]
    NotAGroup(String),
    #[error("dispatch failed: {0}")]
    DispatchFailed(String),
}

pub type RoutingResult<T> = Result<T, RoutingError>;

// ─── Argument Descriptor ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgType {
    String,
    Integer,
    Float,
    Bool,
    Path,
    Address,  // hex address
    Enum(Vec<String>),
}

impl ArgType {
    #[must_use] 
    pub fn validate(&self, value: &str) -> bool {
        match self {
            Self::String | Self::Path => !value.is_empty(),
            Self::Integer => value.parse::<i64>().is_ok(),
            Self::Float => value.parse::<f64>().is_ok(),
            Self::Bool => matches!(value.to_lowercase().as_str(), "true" | "false" | "1" | "0" | "yes" | "no"),
            Self::Address => {
                let v = value.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(v, 16).is_ok()
            }
            Self::Enum(choices) => choices.iter().any(|c| c == value),
        }
    }

    #[must_use] 
    pub fn coerce_bool(s: &str) -> bool {
        matches!(s.to_lowercase().as_str(), "true" | "1" | "yes")
    }

    #[must_use] 
    pub fn coerce_address(s: &str) -> Option<u64> {
        let v = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(v, 16).ok()
    }
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "<string>"),
            Self::Integer => write!(f, "<integer>"),
            Self::Float => write!(f, "<float>"),
            Self::Bool => write!(f, "<bool>"),
            Self::Path => write!(f, "<path>"),
            Self::Address => write!(f, "<address>"),
            Self::Enum(choices) => write!(f, "{{{}}}", choices.join("|")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgDescriptor {
    pub name: String,
    pub short: Option<char>,
    pub arg_type: ArgType,
    pub required: bool,
    pub default: Option<String>,
    pub help: String,
    pub is_positional: bool,
    pub multi: bool,
}

impl ArgDescriptor {
    pub fn required(name: impl Into<String>, ty: ArgType, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            arg_type: ty,
            required: true,
            default: None,
            help: help.into(),
            is_positional: false,
            multi: false,
        }
    }

    pub fn optional(name: impl Into<String>, ty: ArgType, default: Option<&str>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            arg_type: ty,
            required: false,
            default: default.map(std::string::ToString::to_string),
            help: help.into(),
            is_positional: false,
            multi: false,
        }
    }

    pub fn positional(name: impl Into<String>, ty: ArgType, required: bool, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            arg_type: ty,
            required,
            default: None,
            help: help.into(),
            is_positional: true,
            multi: false,
        }
    }

    #[must_use] 
    pub const fn with_short(mut self, c: char) -> Self {
        self.short = Some(c);
        self
    }
}

// ─── Parsed Arguments ─────────────────────────────────────────────────────────

/// The result of parsing a command line against a command's arg descriptors.
#[derive(Debug, Default, Clone)]
pub struct ParsedArgs {
    pub named: HashMap<String, Vec<String>>,
    pub positional: Vec<String>,
    pub flags: std::collections::HashSet<String>,
}

impl ParsedArgs {
    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&str> {
        self.named.get(key).and_then(|v| v.first()).map(std::string::String::as_str)
    }

    #[must_use] 
    pub fn get_all(&self, key: &str) -> &[String] {
        self.named.get(key).map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use] 
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.contains(flag)
    }

    #[must_use] 
    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_string()
    }

    #[must_use] 
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.get(key)?.parse().ok()
    }

    pub fn get_address(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(ArgType::coerce_address)
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).map(ArgType::coerce_bool)
    }
}

// ─── Argument Parser ─────────────────────────────────────────────────────────

pub struct ArgParser<'a> {
    descriptors: &'a [ArgDescriptor],
}

impl<'a> ArgParser<'a> {
    #[must_use] 
    pub const fn new(descriptors: &'a [ArgDescriptor]) -> Self {
        Self { descriptors }
    }

    pub fn parse(&self, argv: &[&str]) -> RoutingResult<ParsedArgs> {
        let mut result = ParsedArgs::default();
        let mut pos_idx = 0usize;
        let positionals: Vec<&ArgDescriptor> = self.descriptors.iter().filter(|d| d.is_positional).collect();
        // Pre-allocate owned strings for single-char short options so we avoid
        // the previous Box::leak approach which permanently leaked memory on
        // every parse() call.
        let short_strings: Vec<(String, &ArgDescriptor)> = self.descriptors.iter()
            .filter(|d| !d.is_positional && d.short.is_some())
            .map(|d| (d.short.unwrap().to_string(), d))
            .collect();
        let named: HashMap<&str, &ArgDescriptor> = self.descriptors.iter()
            .filter(|d| !d.is_positional)
            .map(|d| (d.name.as_str(), d))
            .chain(
                short_strings.iter().map(|(s, d)| (s.as_str(), *d))
            )
            .collect();

        let mut i = 0;
        while i < argv.len() {
            let arg = argv[i];
            if arg == "--" {
                // Everything after -- is positional.
                i += 1;
                while i < argv.len() && pos_idx < positionals.len() {
                    result.positional.push(argv[i].to_string());
                    pos_idx += 1;
                    i += 1;
                }
                break;
            }
            if let Some(rest) = arg.strip_prefix("--") {
                // Long option: --key or --key=value or --key value
                if rest.is_empty() {
                    i += 1;
                    continue;
                }
                let (key, value) = if let Some((k, v)) = rest.split_once('=') {
                    (k, Some(v.to_string()))
                } else {
                    (rest, None)
                };
                if let Some(desc) = named.get(key) {
                    if desc.arg_type.validate("true") && matches!(desc.arg_type, ArgType::Bool) {
                        // Bool flag — no value needed.
                        let val = value.unwrap_or_else(|| "true".to_string());
                        result.named.entry(desc.name.clone()).or_default().push(val);
                    } else if let Some(v) = value {
                        validate_and_insert(desc, &v, &mut result)?;
                    } else if i + 1 < argv.len() {
                        i += 1;
                        let v = argv[i].to_string();
                        validate_and_insert(desc, &v, &mut result)?;
                    } else if desc.arg_type.validate("true") {
                        result.flags.insert(key.to_string());
                    }
                } else {
                    // Treat as a flag.
                    result.flags.insert(key.to_string());
                }
            } else if let Some(rest) = arg.strip_prefix('-') {
                // Short options: -x or -xVAL
                if rest.is_empty() {
                    i += 1;
                    continue;
                }
                let short_key = &rest[..1];
                if let Some(desc) = named.get(short_key) {
                    let value = if rest.len() > 1 {
                        rest[1..].to_string()
                    } else if i + 1 < argv.len() {
                        i += 1;
                        argv[i].to_string()
                    } else {
                        "true".to_string()
                    };
                    validate_and_insert(desc, &value, &mut result)?;
                } else {
                    result.flags.insert(short_key.to_string());
                }
            } else {
                // Positional.
                if pos_idx < positionals.len() {
                    result.positional.push(arg.to_string());
                    pos_idx += 1;
                } else {
                    return Err(RoutingError::TooManyPositional {
                        max: positionals.len(),
                        got: pos_idx + 1,
                    });
                }
            }
            i += 1;
        }

        // Fill defaults and check required.
        for desc in self.descriptors {
            let has_value = if desc.is_positional {
                !result.positional.is_empty()
            } else {
                result.named.contains_key(&desc.name)
            };
            if !has_value {
                if let Some(def) = &desc.default {
                    result.named.entry(desc.name.clone()).or_default().push(def.clone());
                } else if desc.required {
                    return Err(RoutingError::MissingArgument(desc.name.clone()));
                }
            }
        }
        Ok(result)
    }
}

fn validate_and_insert(desc: &ArgDescriptor, value: &str, result: &mut ParsedArgs) -> RoutingResult<()> {
    if !desc.arg_type.validate(value) {
        return Err(RoutingError::InvalidArgument {
            name: desc.name.clone(),
            reason: format!("'{}' is not a valid {}", value, desc.arg_type),
        });
    }
    result.named.entry(desc.name.clone()).or_default().push(value.to_string());
    Ok(())
}

// ─── Command Definition ───────────────────────────────────────────────────────

pub type DispatchFn = fn(&ParsedArgs) -> RoutingResult<()>;

#[derive(Clone)]
pub struct CommandDef {
    pub name: String,
    pub aliases: Vec<String>,
    pub args: Vec<ArgDescriptor>,
    pub help: String,
    pub examples: Vec<String>,
    pub handler: Option<DispatchFn>,
    pub subcommands: Vec<Self>,
    pub hidden: bool,
}

impl CommandDef {
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            args: Vec::new(),
            help: help.into(),
            examples: Vec::new(),
            handler: None,
            subcommands: Vec::new(),
            hidden: false,
        }
    }

    pub fn with_handler(mut self, f: DispatchFn) -> Self {
        self.handler = Some(f);
        self
    }

    #[must_use] 
    pub fn with_arg(mut self, arg: ArgDescriptor) -> Self {
        self.args.push(arg);
        self
    }

    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    #[must_use] 
    pub fn with_subcommand(mut self, sub: Self) -> Self {
        self.subcommands.push(sub);
        self
    }

    pub fn with_example(mut self, ex: impl Into<String>) -> Self {
        self.examples.push(ex.into());
        self
    }

    #[must_use] 
    pub const fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    #[must_use] 
    pub const fn is_group(&self) -> bool {
        !self.subcommands.is_empty()
    }

    #[must_use] 
    pub fn matches(&self, name: &str) -> bool {
        self.name == name || self.aliases.iter().any(|a| a == name)
    }

    #[must_use] 
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        self.name.starts_with(prefix) || self.aliases.iter().any(|a| a.starts_with(prefix))
    }
}

impl fmt::Debug for CommandDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommandDef({})", self.name)
    }
}

// ─── Command Registry ─────────────────────────────────────────────────────────

pub struct CommandRegistry {
    commands: Vec<CommandDef>,
}

impl CommandRegistry {
    #[must_use] 
    pub const fn new() -> Self {
        Self { commands: Vec::new() }
    }

    pub fn register(&mut self, cmd: CommandDef) -> &mut Self {
        self.commands.push(cmd);
        self
    }

    pub fn find(&self, name: &str) -> RoutingResult<&CommandDef> {
        let exact: Vec<&CommandDef> = self.commands.iter().filter(|c| c.matches(name)).collect();
        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(RoutingError::Ambiguous { prefix: name.to_string(), count: exact.len() });
        }
        // Prefix match.
        let prefix_matches: Vec<&CommandDef> = self.commands.iter().filter(|c| c.matches_prefix(name)).collect();
        match prefix_matches.len() {
            0 => Err(RoutingError::UnknownCommand(name.to_string())),
            1 => Ok(prefix_matches[0]),
            n => Err(RoutingError::Ambiguous { prefix: name.to_string(), count: n }),
        }
    }

    #[must_use] 
    pub fn commands(&self) -> &[CommandDef] {
        &self.commands
    }

    #[must_use] 
    pub fn visible_commands(&self) -> Vec<&CommandDef> {
        self.commands.iter().filter(|c| !c.hidden).collect()
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Router ──────────────────────────────────────────────────────────────────

pub struct CommandRouter {
    pub registry: CommandRegistry,
    pub program_name: String,
    pub version: String,
}

impl CommandRouter {
    pub fn new(program_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            registry: CommandRegistry::new(),
            program_name: program_name.into(),
            version: version.into(),
        }
    }

    pub fn register(&mut self, cmd: CommandDef) -> &mut Self {
        self.registry.register(cmd);
        self
    }

    /// Dispatch a top-level argv slice to the appropriate handler.
    pub fn dispatch(&self, argv: &[&str]) -> RoutingResult<()> {
        if argv.is_empty() {
            self.print_top_help();
            return Ok(());
        }
        let cmd_name = argv[0];
        if cmd_name == "--help" || cmd_name == "-h" || cmd_name == "help" {
            if argv.len() > 1 {
                return self.print_command_help(argv[1]);
            }
            self.print_top_help();
            return Ok(());
        }
        if cmd_name == "--version" || cmd_name == "-V" {
            println!("{} {}", self.program_name, self.version);
            return Ok(());
        }

        let cmd = self.registry.find(cmd_name)?;
        let rest = &argv[1..];

        if cmd.is_group() {
            // Recurse into subcommand.
            if rest.is_empty() || rest[0] == "--help" || rest[0] == "-h" {
                self.print_group_help(cmd);
                return Ok(());
            }
            let sub_name = rest[0];
            let sub = cmd.subcommands.iter().find(|s| s.matches(sub_name))
                .ok_or_else(|| RoutingError::UnknownCommand(sub_name.to_string()))?;
            let sub_rest = &rest[1..];
            return self.invoke(sub, sub_rest);
        }
        self.invoke(cmd, rest)
    }

    fn invoke(&self, cmd: &CommandDef, argv: &[&str]) -> RoutingResult<()> {
        let parser = ArgParser::new(&cmd.args);
        let parsed = parser.parse(argv)?;
        if let Some(handler) = cmd.handler {
            handler(&parsed)
        } else {
            Err(RoutingError::DispatchFailed(format!("command '{}' has no handler", cmd.name)))
        }
    }

    pub fn print_top_help(&self) {
        println!("{} {}", self.program_name, self.version);
        println!();
        println!("USAGE:");
        println!("    {} <COMMAND> [OPTIONS]", self.program_name);
        println!();
        println!("COMMANDS:");
        for cmd in self.registry.visible_commands() {
            println!("    {:20} {}", cmd.name, cmd.help);
        }
        println!();
        println!("Run '{} help <COMMAND>' for more details.", self.program_name);
    }

    pub fn print_command_help(&self, name: &str) -> RoutingResult<()> {
        let cmd = self.registry.find(name)?;
        print_command_help_text(cmd, &self.program_name);
        Ok(())
    }

    pub fn print_group_help(&self, cmd: &CommandDef) {
        println!("{} {}:", self.program_name, cmd.name);
        println!("    {}", cmd.help);
        println!();
        println!("SUBCOMMANDS:");
        for sub in &cmd.subcommands {
            if !sub.hidden {
                println!("    {:20} {}", sub.name, sub.help);
            }
        }
    }

    /// Generate help text for all commands as a single string.
    #[must_use] 
    pub fn generate_full_help(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{} {}\n\n", self.program_name, self.version));
        for cmd in self.registry.visible_commands() {
            out.push_str(&command_help_text(cmd, &self.program_name));
            out.push('\n');
        }
        out
    }

    /// Return all command names (including aliases) for tab completion.
    #[must_use] 
    pub fn completion_words(&self) -> Vec<String> {
        let mut words = Vec::new();
        for cmd in &self.registry.commands {
            words.push(cmd.name.clone());
            words.extend(cmd.aliases.clone());
        }
        words
    }
}

fn print_command_help_text(cmd: &CommandDef, prog: &str) {
    print!("{}", command_help_text(cmd, prog));
}

fn command_help_text(cmd: &CommandDef, prog: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} {}\n", prog, cmd.name));
    out.push_str(&format!("    {}\n", cmd.help));
    if !cmd.aliases.is_empty() {
        out.push_str(&format!("    Aliases: {}\n", cmd.aliases.join(", ")));
    }
    if !cmd.args.is_empty() {
        out.push_str("\nOPTIONS:\n");
        for arg in &cmd.args {
            let prefix = if arg.is_positional {
                format!("  {}", arg.name)
            } else if let Some(short) = arg.short {
                format!("  -{}, --{}", short, arg.name)
            } else {
                format!("      --{}", arg.name)
            };
            let req = if arg.required { " [required]" } else { "" };
            let def = arg.default.as_deref().map(|d| format!(" (default: {d})")).unwrap_or_default();
            out.push_str(&format!("{:30} {}{}{}\n", prefix, arg.help, req, def));
        }
    }
    if !cmd.examples.is_empty() {
        out.push_str("\nEXAMPLES:\n");
        for ex in &cmd.examples {
            out.push_str(&format!("    {ex}\n"));
        }
    }
    out
}

// ─── Built-in Command Handlers ────────────────────────────────────────────────

/// Handler for the `project` command.
///
/// Routes to [`rustre_project::Project::new`] (action="init") or
/// [`rustre_project::Project::open`] (action="info"), wiring the project
/// persistence layer through the CLI dispatcher so the `rustre-project`
/// crate is actually exercised at runtime.
fn project_handler(args: &ParsedArgs) -> RoutingResult<()> {
    let action = args
        .positional
        .first()
        .map(String::as_str)
        .ok_or_else(|| RoutingError::MissingArgument("action".into()))?;
    let root = args
        .positional
        .get(1)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| RoutingError::MissingArgument("root".into()))?;
    match action {
        "init" => {
            let name = args.get("name").unwrap_or("rustre-project");
            let project = rustre_project::Project::new(name, &root)
                .map_err(|e| RoutingError::DispatchFailed(format!("project init failed: {e}")))?;
            println!(
                "Created project '{}' at {}",
                project.name(),
                root.display()
            );
            Ok(())
        }
        "info" => {
            let project = rustre_project::Project::open(&root)
                .map_err(|e| RoutingError::DispatchFailed(format!("project open failed: {e}")))?;
            let meta = project.metadata();
            println!("Project: {}", meta.name);
            println!("Created: {}", meta.created_at_iso);
            println!("Version: {}", meta.version);
            println!("Binaries: {}", project.list_binaries().len());
            Ok(())
        }
        other => Err(RoutingError::InvalidArgument {
            name: "action".into(),
            reason: format!("unknown action '{other}', expected 'init' or 'info'"),
        }),
    }
}

// ─── Built-in RustRE Commands ─────────────────────────────────────────────────

pub fn build_rustre_router() -> CommandRouter {
    let mut router = CommandRouter::new("rustre", env!("CARGO_PKG_VERSION"));

    router.register(
        CommandDef::new("open", "Open a binary file for analysis")
            .with_arg(ArgDescriptor::positional("file", ArgType::Path, true, "Path to the binary"))
            .with_arg(ArgDescriptor::optional("arch", ArgType::Enum(vec!["x86".into(), "x86_64".into(), "arm".into(), "arm64".into()]), Some("x86_64"), "Override architecture detection"))
            .with_arg(ArgDescriptor::optional("base", ArgType::Address, None, "Override image base address"))
            .with_example("rustre open /path/to/malware.exe")
            .with_example("rustre open --arch arm64 libnative.so")
    );

    router.register(
        CommandDef::new("disasm", "Disassemble at address or function")
            .with_arg(ArgDescriptor::required("address", ArgType::Address, "Start address or function name"))
            .with_arg(ArgDescriptor::optional("count", ArgType::Integer, Some("32"), "Number of instructions"))
            .with_arg(ArgDescriptor::optional("format", ArgType::Enum(vec!["intel".into(), "att".into()]), Some("intel"), "Disassembly syntax"))
            .with_example("rustre disasm 0x401000")
            .with_example("rustre disasm WinMain --count 100")
    );

    router.register(
        CommandDef::new("decompile", "Decompile a function")
            .with_arg(ArgDescriptor::required("address", ArgType::Address, "Function address"))
            .with_arg(ArgDescriptor::optional("output", ArgType::Enum(vec!["c".into(), "pseudo".into(), "json".into()]), Some("c"), "Output format"))
    );

    router.register(
        CommandDef::new("strings", "Extract strings from the binary")
            .with_arg(ArgDescriptor::optional("min-len", ArgType::Integer, Some("4"), "Minimum string length"))
            .with_arg(ArgDescriptor::optional("encoding", ArgType::Enum(vec!["utf8".into(), "utf16".into(), "all".into()]), Some("all"), "Encoding filter"))
    );

    router.register(
        CommandDef::new("imports", "List imported functions")
            .with_arg(ArgDescriptor::optional("filter", ArgType::String, None, "Filter by name substring"))
    );

    router.register(
        CommandDef::new("exports", "List exported symbols")
    );

    router.register(
        CommandDef::new("xrefs", "Cross-references to/from an address")
            .with_arg(ArgDescriptor::required("address", ArgType::Address, "Target address"))
            .with_arg(ArgDescriptor::optional("direction", ArgType::Enum(vec!["to".into(), "from".into(), "both".into()]), Some("to"), "Direction"))
    );

    router.register(
        CommandDef::new("yara", "Run YARA rules against the binary")
            .with_arg(ArgDescriptor::optional("rules", ArgType::Path, None, "Path to .yar file (default: builtin)"))
    );

    router.register(
        CommandDef::new("triage", "Automated triage of the binary")
            .with_arg(ArgDescriptor::optional("level", ArgType::Enum(vec!["quick".into(), "full".into()]), Some("quick"), "Analysis depth"))
            .with_arg(ArgDescriptor::optional("report", ArgType::Path, None, "Save triage report to file"))
    );

    router.register(
        CommandDef::new("diff", "Diff two binaries")
            .with_arg(ArgDescriptor::positional("file_a", ArgType::Path, true, "First binary"))
            .with_arg(ArgDescriptor::positional("file_b", ArgType::Path, true, "Second binary"))
            .with_arg(ArgDescriptor::optional("threshold", ArgType::Float, Some("0.5"), "Similarity threshold"))
    );

    router.register(
        CommandDef::new("project", "Initialize or open a RustRE project directory")
            .with_arg(ArgDescriptor::positional("action", ArgType::Enum(vec!["init".into(), "info".into()]), true, "Action: init | info"))
            .with_arg(ArgDescriptor::positional("root", ArgType::Path, true, "Project root directory"))
            .with_arg(ArgDescriptor::optional("name", ArgType::String, Some("rustre-project"), "Project name (for init)"))
            .with_handler(project_handler)
            .with_example("rustre project init ./my-re-workspace --name my-target")
            .with_example("rustre project info ./my-re-workspace")
    );

    router.register(
        CommandDef::new("help", "Show help for a command")
            .with_arg(ArgDescriptor::positional("command", ArgType::String, false, "Command name"))
    );

    router.register(
        CommandDef::new("version", "Print version information").hidden()
    );

    router
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_handler(_: &ParsedArgs) -> RoutingResult<()> { Ok(()) }

    #[test]
    fn test_arg_parser_named() {
        let descs = vec![
            ArgDescriptor::optional("count", ArgType::Integer, Some("10"), "Count"),
        ];
        let parser = ArgParser::new(&descs);
        let parsed = parser.parse(&["--count", "42"]).unwrap();
        assert_eq!(parsed.get("count"), Some("42"));
        assert_eq!(parsed.get_int("count"), Some(42));
    }

    #[test]
    fn test_arg_parser_positional() {
        let descs = vec![
            ArgDescriptor::positional("file", ArgType::Path, true, "File"),
        ];
        let parser = ArgParser::new(&descs);
        let parsed = parser.parse(&["/tmp/test.exe"]).unwrap();
        assert_eq!(parsed.positional[0], "/tmp/test.exe");
    }

    #[test]
    fn test_arg_parser_default() {
        let descs = vec![
            ArgDescriptor::optional("arch", ArgType::String, Some("x86_64"), "Arch"),
        ];
        let parser = ArgParser::new(&descs);
        let parsed = parser.parse(&[]).unwrap();
        assert_eq!(parsed.get("arch"), Some("x86_64"));
    }

    #[test]
    fn test_arg_parser_missing_required() {
        let descs = vec![
            ArgDescriptor::required("file", ArgType::Path, "File"),
        ];
        let parser = ArgParser::new(&descs);
        let result = parser.parse(&[]);
        assert!(matches!(result, Err(RoutingError::MissingArgument(_))));
    }

    #[test]
    fn test_address_arg_type() {
        let ty = ArgType::Address;
        assert!(ty.validate("0x401000"));
        assert!(ty.validate("401000"));
        assert!(!ty.validate("xyz"));
        assert_eq!(ArgType::coerce_address("0x401000"), Some(0x401000));
    }

    #[test]
    fn test_enum_arg_type() {
        let ty = ArgType::Enum(vec!["a".into(), "b".into(), "c".into()]);
        assert!(ty.validate("a"));
        assert!(!ty.validate("d"));
    }

    #[test]
    fn test_registry_find_exact() {
        let mut reg = CommandRegistry::new();
        reg.register(CommandDef::new("open", "open").with_handler(noop_handler));
        reg.register(CommandDef::new("dump", "dump").with_handler(noop_handler));
        let cmd = reg.find("open").unwrap();
        assert_eq!(cmd.name, "open");
    }

    #[test]
    fn test_registry_find_prefix() {
        let mut reg = CommandRegistry::new();
        reg.register(CommandDef::new("disassemble", "disasm").with_handler(noop_handler));
        let cmd = reg.find("dis").unwrap();
        assert_eq!(cmd.name, "disassemble");
    }

    #[test]
    fn test_registry_find_unknown() {
        let reg = CommandRegistry::new();
        let result = reg.find("nonexistent");
        assert!(matches!(result, Err(RoutingError::UnknownCommand(_))));
    }

    #[test]
    fn test_router_dispatch_version() {
        let router = build_rustre_router();
        let result = router.dispatch(&["--version"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_router_dispatch_help() {
        let router = build_rustre_router();
        assert!(router.dispatch(&["help"]).is_ok());
    }

    #[test]
    fn test_router_unknown_command() {
        let router = build_rustre_router();
        let result = router.dispatch(&["unknown_cmd_xyz"]);
        assert!(matches!(result, Err(RoutingError::UnknownCommand(_))));
    }

    #[test]
    fn test_command_def_aliases() {
        let cmd = CommandDef::new("disassemble", "d").with_alias("disasm").with_alias("d");
        assert!(cmd.matches("disassemble"));
        assert!(cmd.matches("disasm"));
        assert!(cmd.matches("d"));
        assert!(!cmd.matches("other"));
    }

    #[test]
    fn test_completion_words_include_aliases() {
        let mut reg = CommandRegistry::new();
        reg.register(CommandDef::new("open", "").with_alias("o"));
        let mut router = CommandRouter::new("test", "0.1");
        router.registry = reg;
        let words = router.completion_words();
        assert!(words.contains(&"open".to_string()));
        assert!(words.contains(&"o".to_string()));
    }
}
