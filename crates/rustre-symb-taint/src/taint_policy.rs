//! Taint policy: sources, sinks, sanitizers, and propagation rules.
//!
//! Defines the full policy that governs how taint labels attach to values and
//! how they propagate through operations.  The policy is separate from the
//! analysis engine so it can be swapped or extended without touching core logic.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{TaintId, taint_bits};

// ─── Source kind ──────────────────────────────────────────────────────────────

/// Known taint source categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// `argv`, `argc`.
    CommandLineArg,
    /// Bytes read from `stdin`.
    Stdin,
    /// Data read from a file (`read`, `fread`, `mmap`…).
    FileRead,
    /// Data received from a network socket (`recv`, `recvfrom`…).
    NetworkRecv,
    /// Environment variable (`getenv`, `environ`).
    EnvVar,
    /// Windows registry value (`RegQueryValueEx`…).
    RegistryRead,
    /// Data from `getline` / `fgets` / `scanf`.
    UserInput,
    /// Custom source defined by the policy author.
    Custom(u8),
}

impl SourceKind {
    /// Map to the corresponding [`TaintId`] bitmask bit.
    pub fn taint_bit(self) -> TaintId {
        match self {
            Self::CommandLineArg => taint_bits::COMMAND_LINE,
            Self::Stdin | Self::UserInput => taint_bits::USER_INPUT,
            Self::FileRead => taint_bits::FILE,
            Self::NetworkRecv => taint_bits::NETWORK,
            Self::EnvVar => taint_bits::ENVIRONMENT,
            Self::RegistryRead => taint_bits::REGISTRY,
            Self::Custom(idx) => taint_bits::custom(idx),
        }
    }
}

// ─── Source definition ────────────────────────────────────────────────────────

/// A taint source: a specific API entry point that introduces tainted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Unique name (e.g. "stdin_read").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The source category.
    pub kind: SourceKind,
    /// The taint bitmask assigned to data from this source.
    pub taint_mask: TaintId,
    /// Names of API functions that act as this source.
    pub api_functions: Vec<String>,
    /// Which argument index carries the tainted output (0 = return value,
    /// 1 = first arg, etc.).
    pub output_arg: usize,
}

impl TaintSource {
    pub fn new(name: impl Into<String>, kind: SourceKind) -> Self {
        let k = kind;
        Self {
            name: name.into(),
            description: String::new(),
            kind,
            taint_mask: k.taint_bit(),
            api_functions: Vec::new(),
            output_arg: 0,
        }
    }

    pub fn with_api(mut self, apis: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.api_functions = apis.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_output_arg(mut self, idx: usize) -> Self {
        self.output_arg = idx;
        self
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }
}

// ─── Sink kind ────────────────────────────────────────────────────────────────

/// Known taint sink categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    /// Shell command execution (`execve`, `system`, `popen`…).
    CommandExec,
    /// Write to a file (`write`, `fwrite`, `fprintf`…).
    FileWrite,
    /// SQL query execution.
    SqlQuery,
    /// Format string argument to `printf`-family functions.
    FormatString,
    /// Network send (`send`, `sendto`…).
    NetworkSend,
    /// Dynamic memory operation (`memcpy`, `strcpy`…) with tainted length.
    MemoryCopy,
    /// Custom sink.
    Custom(u8),
}

// ─── Sink definition ──────────────────────────────────────────────────────────

/// A taint sink: an API entry point that is dangerous when reached by tainted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub name: String,
    pub description: String,
    pub kind: SinkKind,
    /// API functions that are sinks.
    pub api_functions: Vec<String>,
    /// Which argument index is the sensitive argument (0 = return, 1 = first…).
    pub sensitive_arg: usize,
    /// The set of taint sources that make this sink dangerous.
    /// If empty, *any* taint is dangerous.
    pub dangerous_sources: TaintId,
}

impl TaintSink {
    pub fn new(name: impl Into<String>, kind: SinkKind) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            kind,
            api_functions: Vec::new(),
            sensitive_arg: 1,
            dangerous_sources: taint_bits::ALL,
        }
    }

    pub fn with_api(mut self, apis: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.api_functions = apis.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_sensitive_arg(mut self, idx: usize) -> Self {
        self.sensitive_arg = idx;
        self
    }

    pub fn dangerous_if(mut self, sources: TaintId) -> Self {
        self.dangerous_sources = sources;
        self
    }

    /// Return `true` if `taint` (the label on a reaching value) makes this
    /// sink dangerous.
    pub fn is_dangerous(&self, taint: TaintId) -> bool {
        taint_bits::is_tainted(taint & self.dangerous_sources)
    }
}

// ─── Sanitizer ────────────────────────────────────────────────────────────────

/// A sanitizer: an API call that can neutralise some taint bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sanitizer {
    pub name: String,
    pub description: String,
    /// API functions that perform this sanitisation.
    pub api_functions: Vec<String>,
    /// The taint bits *removed* from the output of this call.
    pub cleared_bits: TaintId,
    /// Which argument is sanitised (0 = return, 1 = first arg…).
    pub sanitized_arg: usize,
    /// Conditions under which sanitization is effective (e.g. "result == true").
    pub condition: Option<String>,
}

impl Sanitizer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            api_functions: Vec::new(),
            cleared_bits: taint_bits::ALL,
            sanitized_arg: 0,
            condition: None,
        }
    }

    pub fn clearing(mut self, bits: TaintId) -> Self {
        self.cleared_bits = bits;
        self
    }

    pub fn with_api(mut self, apis: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.api_functions = apis.into_iter().map(Into::into).collect();
        self
    }

    pub fn when(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Apply this sanitizer to `taint` → return the resulting (cleaned) taint.
    pub fn apply(&self, taint: TaintId) -> TaintId {
        taint & !self.cleared_bits
    }
}

// ─── Propagation rules ────────────────────────────────────────────────────────

/// How taint propagates through a binary/unary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationRule {
    /// Output is tainted if *any* operand is tainted (union of masks).
    AnyOperand,
    /// Output is tainted if *all* operands are tainted (intersection of masks).
    AllOperands,
    /// Output is tainted only if the first operand is tainted.
    FirstOnly,
    /// Taint propagates only when the comparison is true (conditional propagation).
    ConditionalOnTrue,
    /// Taint does not propagate (output is always clean).
    NoPropagation,
    /// Custom rule: output is the OR of all operand taints, then a fixed mask is AND-ed.
    MaskedUnion(TaintId),
}

impl PropagationRule {
    /// Compute the output taint given a list of operand taints.
    pub fn apply(&self, operands: &[TaintId]) -> TaintId {
        match self {
            Self::AnyOperand => operands.iter().fold(0, |acc, &t| acc | t),
            Self::AllOperands => {
                if operands.is_empty() {
                    return 0;
                }
                operands.iter().fold(taint_bits::ALL, |acc, &t| acc & t)
            }
            Self::FirstOnly => operands.first().copied().unwrap_or(0),
            Self::ConditionalOnTrue => operands.first().copied().unwrap_or(0),
            Self::NoPropagation => 0,
            Self::MaskedUnion(mask) => {
                let union = operands.iter().fold(0, |acc, &t| acc | t);
                union & mask
            }
        }
    }
}

// ─── Operation class ─────────────────────────────────────────────────────────

/// High-level category of a machine operation for rule lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationClass {
    /// Arithmetic: add, sub, mul, div.
    Arithmetic,
    /// Bitwise: and, or, xor, not, shift.
    Bitwise,
    /// Comparison: eq, ne, lt, …
    Comparison,
    /// Memory load.
    Load,
    /// Memory store.
    Store,
    /// Function call.
    Call,
    /// Data copy (memcpy, strcpy, …).
    Copy,
    /// Type conversion / cast.
    Cast,
    /// Other / unknown.
    Other,
}

// ─── Full policy ─────────────────────────────────────────────────────────────

/// The complete taint policy.
///
/// Collects all sources, sinks, sanitizers, and per-operation propagation
/// rules.  Can be loaded from JSON or built programmatically.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TaintPolicy {
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<Sanitizer>,
    pub propagation_rules: HashMap<String, PropagationRule>,
}

impl TaintPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the default policy covering common C/POSIX sources and sinks.
    pub fn default_c_policy() -> Self {
        let mut p = Self::new();

        // ── Sources ──────────────────────────────────────────────────────
        p.add_source(
            TaintSource::new("argv", SourceKind::CommandLineArg)
                .with_description("Command-line arguments (argv[i])")
                .with_api(["main"]),
        );
        p.add_source(
            TaintSource::new("stdin_read", SourceKind::Stdin)
                .with_description("Data read from stdin via fgets/scanf/read")
                .with_api(["fgets", "scanf", "fscanf", "gets", "read"])
                .with_output_arg(1),
        );
        p.add_source(
            TaintSource::new("file_read", SourceKind::FileRead)
                .with_description("Data read from a file descriptor")
                .with_api(["read", "fread", "pread", "mmap"])
                .with_output_arg(1),
        );
        p.add_source(
            TaintSource::new("network_recv", SourceKind::NetworkRecv)
                .with_description("Data received from a network socket")
                .with_api(["recv", "recvfrom", "recvmsg", "read"])
                .with_output_arg(1),
        );
        p.add_source(
            TaintSource::new("getenv", SourceKind::EnvVar)
                .with_description("Environment variable value")
                .with_api(["getenv", "secure_getenv"]),
        );
        p.add_source(
            TaintSource::new("registry_read", SourceKind::RegistryRead)
                .with_description("Windows registry value")
                .with_api(["RegQueryValueExA", "RegQueryValueExW"])
                .with_output_arg(5),
        );

        // ── Sinks ────────────────────────────────────────────────────────
        p.add_sink(
            TaintSink::new("command_exec", SinkKind::CommandExec)
                .with_api(["execve", "execvp", "execl", "system", "popen", "execlp"])
                .with_sensitive_arg(1),
        );
        p.add_sink(
            TaintSink::new("file_write", SinkKind::FileWrite)
                .with_api(["write", "fwrite", "fputs", "fprintf", "pwrite"])
                .with_sensitive_arg(1),
        );
        p.add_sink(
            TaintSink::new("sql_query", SinkKind::SqlQuery)
                .with_api(["sqlite3_exec", "mysql_query", "PQexec"])
                .with_sensitive_arg(2),
        );
        p.add_sink(
            TaintSink::new("format_string", SinkKind::FormatString)
                .with_api(["printf", "fprintf", "sprintf", "snprintf", "vprintf", "syslog"])
                .with_sensitive_arg(1),
        );
        p.add_sink(
            TaintSink::new("network_send", SinkKind::NetworkSend)
                .with_api(["send", "sendto", "sendmsg", "write"])
                .with_sensitive_arg(2),
        );
        p.add_sink(
            TaintSink::new("memory_copy", SinkKind::MemoryCopy)
                .with_api(["memcpy", "memmove", "strcpy", "strcat", "strncat"])
                .with_sensitive_arg(3), // length argument
        );

        // ── Sanitizers ───────────────────────────────────────────────────
        p.add_sanitizer(
            Sanitizer::new("strlen_check")
                .with_api(["strlen"])
                .clearing(taint_bits::ALL)
                .when("result < buffer_size"),
        );
        p.add_sanitizer(
            Sanitizer::new("isalnum_sanitizer")
                .with_api(["isalnum", "isalpha", "isdigit", "isprint"])
                .clearing(taint_bits::ALL)
                .when("result != 0"),
        );
        p.add_sanitizer(
            Sanitizer::new("strtol_sanitizer")
                .with_api(["strtol", "strtoul", "atoi", "atol"])
                .clearing(
                    // integer conversion removes injection risk but not overflow risk
                    taint_bits::USER_INPUT | taint_bits::NETWORK | taint_bits::FILE,
                ),
        );
        p.add_sanitizer(
            Sanitizer::new("html_escape")
                .with_api(["htmlspecialchars", "htmlentities"])
                .clearing(taint_bits::ALL),
        );

        // ── Default propagation rules ────────────────────────────────────
        p.set_rule("arithmetic", PropagationRule::AnyOperand);
        p.set_rule("bitwise", PropagationRule::AnyOperand);
        p.set_rule("comparison", PropagationRule::AnyOperand);
        p.set_rule("load", PropagationRule::AnyOperand);
        p.set_rule("store", PropagationRule::AnyOperand);
        p.set_rule("cast", PropagationRule::FirstOnly);
        p.set_rule("copy", PropagationRule::AnyOperand);

        p
    }

    // ─── Mutation ─────────────────────────────────────────────────────────

    pub fn add_source(&mut self, s: TaintSource) {
        self.sources.push(s);
    }

    pub fn add_sink(&mut self, s: TaintSink) {
        self.sinks.push(s);
    }

    pub fn add_sanitizer(&mut self, s: Sanitizer) {
        self.sanitizers.push(s);
    }

    pub fn set_rule(&mut self, op: impl Into<String>, rule: PropagationRule) {
        self.propagation_rules.insert(op.into(), rule);
    }

    // ─── Lookup helpers ───────────────────────────────────────────────────

    /// Find the source definition for a given API function name.
    pub fn source_for_api(&self, api: &str) -> Option<&TaintSource> {
        self.sources
            .iter()
            .find(|s| s.api_functions.iter().any(|f| f == api))
    }

    /// Find all sink definitions for a given API function name.
    pub fn sinks_for_api(&self, api: &str) -> Vec<&TaintSink> {
        self.sinks
            .iter()
            .filter(|s| s.api_functions.iter().any(|f| f == api))
            .collect()
    }

    /// Find a sanitizer definition for a given API function name.
    pub fn sanitizer_for_api(&self, api: &str) -> Option<&Sanitizer> {
        self.sanitizers
            .iter()
            .find(|s| s.api_functions.iter().any(|f| f == api))
    }

    /// Compute the output taint for an operation class given operand taints.
    pub fn propagate(&self, op_class: OperationClass, operands: &[TaintId]) -> TaintId {
        let key = match op_class {
            OperationClass::Arithmetic => "arithmetic",
            OperationClass::Bitwise => "bitwise",
            OperationClass::Comparison => "comparison",
            OperationClass::Load => "load",
            OperationClass::Store => "store",
            OperationClass::Copy => "copy",
            OperationClass::Cast => "cast",
            OperationClass::Call => "arithmetic",
            OperationClass::Other => "arithmetic",
        };
        let rule = self
            .propagation_rules
            .get(key)
            .copied()
            .unwrap_or(PropagationRule::AnyOperand);
        rule.apply(operands)
    }

    /// Apply a sanitizer (by name) to `taint`.
    pub fn sanitize(&self, sanitizer_name: &str, taint: TaintId) -> TaintId {
        if let Some(san) = self.sanitizers.iter().find(|s| s.name == sanitizer_name) {
            san.apply(taint)
        } else {
            taint
        }
    }

    /// Return all API function names that are sources.
    pub fn all_source_apis(&self) -> HashSet<&str> {
        self.sources
            .iter()
            .flat_map(|s| s.api_functions.iter().map(String::as_str))
            .collect()
    }

    /// Return all API function names that are sinks.
    pub fn all_sink_apis(&self) -> HashSet<&str> {
        self.sinks
            .iter()
            .flat_map(|s| s.api_functions.iter().map(String::as_str))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_lookup() {
        let policy = TaintPolicy::default_c_policy();
        let src = policy.source_for_api("fgets");
        assert!(src.is_some());
        assert_eq!(src.unwrap().kind, SourceKind::Stdin);
    }

    #[test]
    fn test_sink_lookup() {
        let policy = TaintPolicy::default_c_policy();
        let sinks = policy.sinks_for_api("execve");
        assert!(!sinks.is_empty());
        assert_eq!(sinks[0].kind, SinkKind::CommandExec);
    }

    #[test]
    fn test_sanitizer_apply() {
        let san = Sanitizer::new("test").clearing(taint_bits::USER_INPUT);
        let t = taint_bits::USER_INPUT | taint_bits::NETWORK;
        let cleaned = san.apply(t);
        assert_eq!(cleaned & taint_bits::USER_INPUT, 0);
        assert_ne!(cleaned & taint_bits::NETWORK, 0);
    }

    #[test]
    fn test_propagation_any_operand() {
        let rule = PropagationRule::AnyOperand;
        let result = rule.apply(&[taint_bits::USER_INPUT, 0, taint_bits::NETWORK]);
        assert_ne!(result & taint_bits::USER_INPUT, 0);
        assert_ne!(result & taint_bits::NETWORK, 0);
    }

    #[test]
    fn test_propagation_no_propagation() {
        let rule = PropagationRule::NoPropagation;
        let result = rule.apply(&[taint_bits::ALL]);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_policy_propagate() {
        let policy = TaintPolicy::default_c_policy();
        let t = policy.propagate(
            OperationClass::Arithmetic,
            &[taint_bits::USER_INPUT, 0],
        );
        assert_ne!(t, 0);
    }

    #[test]
    fn test_sink_is_dangerous() {
        let policy = TaintPolicy::default_c_policy();
        let sinks = policy.sinks_for_api("printf");
        assert!(!sinks.is_empty());
        assert!(sinks[0].is_dangerous(taint_bits::USER_INPUT));
        assert!(!sinks[0].is_dangerous(taint_bits::NONE));
    }

    #[test]
    fn test_all_source_apis_non_empty() {
        let policy = TaintPolicy::default_c_policy();
        assert!(!policy.all_source_apis().is_empty());
    }

    #[test]
    fn test_source_kind_taint_bit() {
        assert_eq!(SourceKind::CommandLineArg.taint_bit(), taint_bits::COMMAND_LINE);
        assert_eq!(SourceKind::NetworkRecv.taint_bit(), taint_bits::NETWORK);
    }
}
