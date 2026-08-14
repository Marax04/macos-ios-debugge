//! `taint_sinks` — Extended taint sink database.
//!
//! Covers 100+ dangerous function signatures for Linux, Windows, and macOS,
//! organised by:
//! - Platform (cross-platform, Linux, Windows, macOS)
//! - Category (command injection, buffer overflow, format string, network,
//!   file write, registry write, SQL, heap management, crypto misuse, etc.)
//! - Severity level (Critical, High, Medium, Low)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{FindingType, TaintExpr, TaintFinding, TaintId, TaintState, eval_taint, taint_bits};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("sink not found: {0}")]
    NotFound(String),
    #[error("sink match error: {0}")]
    MatchError(String),
}

// ─── SinkSeverity ─────────────────────────────────────────────────────────────

/// Severity level of a taint sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SinkSeverity {
    /// Low-risk sink: informational finding.
    Low = 1,
    /// Medium-risk: may lead to data leakage or DoS.
    Medium = 2,
    /// High-risk: direct vulnerability class.
    High = 3,
    /// Critical: remote code execution / privilege escalation class.
    Critical = 4,
}

impl SinkSeverity {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for SinkSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── SinkPlatform ─────────────────────────────────────────────────────────────

/// Target platform the sink applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkPlatform {
    /// Sink is present on all POSIX-compatible platforms.
    CrossPlatform,
    /// Linux-specific (syscall wrappers, proc filesystem, etc.).
    Linux,
    /// Windows-specific (Win32 API, COM, registry).
    Windows,
    /// macOS / Darwin / iOS.
    MacOs,
}

impl std::fmt::Display for SinkPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossPlatform => write!(f, "cross-platform"),
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOs => write!(f, "macos"),
        }
    }
}

// ─── TaintedArgSpec ───────────────────────────────────────────────────────────

/// Specifies which argument(s) of a function must be tainted to trigger the
/// finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintedArgSpec {
    /// Argument at the given 0-based position.
    Position(usize),
    /// Any argument position must be tainted.
    Any,
    /// All arguments must be tainted.
    All,
    /// A specific positional list.
    AnyOf(Vec<usize>),
}

impl TaintedArgSpec {
    /// Return `true` if the condition is met given the per-argument taint masks.
    #[must_use]
    pub fn is_triggered(&self, arg_taints: &[TaintId]) -> bool {
        match self {
            Self::Position(i) => {
                arg_taints.get(*i).copied().unwrap_or(taint_bits::NONE) != taint_bits::NONE
            }
            Self::Any => arg_taints.iter().any(|&t| t != taint_bits::NONE),
            Self::All => {
                !arg_taints.is_empty() && arg_taints.iter().all(|&t| t != taint_bits::NONE)
            }
            Self::AnyOf(positions) => positions.iter().any(|&i| {
                arg_taints.get(i).copied().unwrap_or(taint_bits::NONE) != taint_bits::NONE
            }),
        }
    }

    /// Return the combined taint mask of triggering arguments.
    #[must_use]
    pub fn triggering_taint(&self, arg_taints: &[TaintId]) -> TaintId {
        match self {
            Self::Position(i) => arg_taints.get(*i).copied().unwrap_or(taint_bits::NONE),
            Self::Any | Self::All => arg_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t),
            Self::AnyOf(positions) => positions
                .iter()
                .filter_map(|&i| arg_taints.get(i).copied())
                .fold(taint_bits::NONE, |acc, t| acc | t),
        }
    }
}

// ─── TaintSinkDef ─────────────────────────────────────────────────────────────

/// Definition of a single dangerous sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSinkDef {
    /// Function name (exact match or wildcard).
    pub name: String,
    /// Which arguments to check.
    pub arg_spec: TaintedArgSpec,
    /// Type of vulnerability this sink exposes.
    pub finding_type: FindingType,
    /// Severity level.
    pub severity: SinkSeverity,
    /// Platform applicability.
    pub platform: SinkPlatform,
    /// Human-readable description.
    pub description: String,
    /// Tags for categorisation (e.g. ["exec", "os-cmd"]).
    pub tags: Vec<String>,
    /// CWE identifier if known (e.g. 78 for OS Command Injection).
    pub cwe: Option<u32>,
}

impl TaintSinkDef {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        arg_spec: TaintedArgSpec,
        finding_type: FindingType,
        severity: SinkSeverity,
        platform: SinkPlatform,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            arg_spec,
            finding_type,
            severity,
            platform,
            description: description.into(),
            tags: Vec::new(),
            cwe: None,
        }
    }

    #[must_use]
    pub fn with_cwe(mut self, cwe: u32) -> Self {
        self.cwe = Some(cwe);
        self
    }

    #[must_use]
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Check whether this sink is triggered by `arg_taints` and, if so,
    /// build a `TaintFinding`.
    #[must_use]
    pub fn match_call(&self, arg_taints: &[TaintId], call_addr: u64) -> Option<TaintFinding> {
        if !self.arg_spec.is_triggered(arg_taints) {
            return None;
        }
        let taint_mask = self.arg_spec.triggering_taint(arg_taints);
        let desc = format!(
            "[{}] Tainted data flows into {}() — {}",
            self.severity, self.name, self.description
        );
        Some(TaintFinding::new(
            self.finding_type.clone(),
            call_addr,
            taint_mask,
            desc,
        ))
    }
}

// ─── TaintSinkDb ──────────────────────────────────────────────────────────────

/// Database of all registered taint sinks.
#[derive(Debug, Default)]
pub struct TaintSinkDb {
    /// Function name → list of sink definitions (one function may have
    /// multiple definitions for different argument positions).
    sinks: HashMap<String, Vec<TaintSinkDef>>,
}

impl TaintSinkDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fully pre-populated database with 100+ sinks.
    #[must_use]
    pub fn with_all_sinks() -> Self {
        let mut db = Self::new();
        db.populate_command_injection_sinks();
        db.populate_buffer_overflow_sinks();
        db.populate_format_string_sinks();
        db.populate_sql_injection_sinks();
        db.populate_path_traversal_sinks();
        db.populate_network_sinks();
        db.populate_file_write_sinks();
        db.populate_windows_registry_sinks();
        db.populate_windows_exec_sinks();
        db.populate_macos_exec_sinks();
        db.populate_linux_syscall_sinks();
        db.populate_heap_management_sinks();
        db.populate_crypto_misuse_sinks();
        db.populate_misc_sinks();
        db
    }

    /// Insert a sink definition.
    pub fn insert(&mut self, def: TaintSinkDef) {
        self.sinks.entry(def.name.clone()).or_default().push(def);
    }

    /// Look up all sink definitions for a function name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[TaintSinkDef]> {
        self.sinks.get(name).map(Vec::as_slice)
    }

    /// Match a function call against all registered sinks.
    ///
    /// Returns the first (or highest-severity) finding if any sink matches.
    #[must_use]
    pub fn match_sink(
        &self,
        func_name: &str,
        args: &[TaintExpr],
        state: &TaintState,
        call_addr: u64,
    ) -> Option<TaintFinding> {
        let arg_taints: Vec<TaintId> = args.iter().map(|a| eval_taint(a, state)).collect();
        let defs = self.sinks.get(func_name)?;
        let mut best: Option<TaintFinding> = None;
        let mut best_sev = SinkSeverity::Low;
        for def in defs {
            if let Some(finding) = def.match_call(&arg_taints, call_addr) && (best.is_none() || def.severity > best_sev) {
                best = Some(finding);
                best_sev = def.severity;
            }
        }
        best
    }

    /// Return all registered sink names.
    #[must_use]
    pub fn sink_names(&self) -> Vec<&str> {
        self.sinks.keys().map(String::as_str).collect()
    }

    /// Return the total number of sink definitions.
    #[must_use]
    pub fn total_defs(&self) -> usize {
        self.sinks.values().map(Vec::len).sum()
    }

    /// Return sinks of a given severity.
    #[must_use]
    pub fn sinks_by_severity(&self, sev: SinkSeverity) -> Vec<&TaintSinkDef> {
        self.sinks
            .values()
            .flatten()
            .filter(|d| d.severity == sev)
            .collect()
    }

    // ── Populate helpers ──────────────────────────────────────────────────────

    fn populate_command_injection_sinks(&mut self) {
        let sinks = vec![
            // POSIX
            (
                "system",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "system() executes a shell command",
                Some(78),
            ),
            (
                "popen",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "popen() opens a shell command pipe",
                Some(78),
            ),
            (
                "execve",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execve() executes a program",
                Some(78),
            ),
            (
                "execl",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execl() executes a program",
                Some(78),
            ),
            (
                "execle",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execle() executes a program",
                Some(78),
            ),
            (
                "execlp",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execlp() executes a program",
                Some(78),
            ),
            (
                "execv",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execv() executes a program",
                Some(78),
            ),
            (
                "execvp",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "execvp() executes a program",
                Some(78),
            ),
            (
                "execvpe",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::Linux,
                "execvpe() executes a program",
                Some(78),
            ),
            (
                "posix_spawn",
                0,
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                SinkPlatform::CrossPlatform,
                "posix_spawn() creates a new process",
                Some(78),
            ),
        ];
        for (name, arg, ft, sev, plat, desc, cwe) in sinks {
            let mut d = TaintSinkDef::new(name, TaintedArgSpec::Position(arg), ft, sev, plat, desc);
            if let Some(c) = cwe {
                d = d.with_cwe(c);
            }
            self.insert(d);
        }
    }

    fn populate_buffer_overflow_sinks(&mut self) {
        // Length-tainted copies.
        let length_sinks = vec![
            (
                "memcpy",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in memcpy()",
                Some(122u32),
            ),
            (
                "memmove",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in memmove()",
                Some(122),
            ),
            (
                "memset",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in memset()",
                Some(122),
            ),
            (
                "bcopy",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in bcopy()",
                Some(122),
            ),
            (
                "bzero",
                1,
                SinkPlatform::CrossPlatform,
                "tainted length in bzero()",
                Some(122),
            ),
            (
                "wmemcpy",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in wmemcpy()",
                Some(122),
            ),
            (
                "alloca",
                0,
                SinkPlatform::CrossPlatform,
                "tainted size in alloca()",
                Some(770),
            ),
            (
                "calloc",
                1,
                SinkPlatform::CrossPlatform,
                "tainted count in calloc()",
                Some(122),
            ),
            (
                "realloc",
                1,
                SinkPlatform::CrossPlatform,
                "tainted size in realloc()",
                Some(122),
            ),
            (
                "read",
                2,
                SinkPlatform::Linux,
                "tainted length in read()",
                Some(122),
            ),
            (
                "recv",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in recv()",
                Some(122),
            ),
            (
                "recvfrom",
                2,
                SinkPlatform::CrossPlatform,
                "tainted length in recvfrom()",
                Some(122),
            ),
        ];
        for (name, arg, plat, desc, cwe) in length_sinks {
            let mut d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::BufferOverflow,
                SinkSeverity::High,
                plat,
                desc,
            );
            if let Some(c) = cwe {
                d = d.with_cwe(c);
            }
            self.insert(d);
        }
        // Source-tainted unbounded copies.
        let source_sinks = vec![
            (
                "strcpy",
                1,
                SinkPlatform::CrossPlatform,
                "tainted source in strcpy()",
                Some(120),
            ),
            (
                "strcat",
                1,
                SinkPlatform::CrossPlatform,
                "tainted source in strcat()",
                Some(120),
            ),
            (
                "gets",
                0,
                SinkPlatform::CrossPlatform,
                "tainted input in gets()",
                Some(120),
            ),
            (
                "sprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in sprintf()",
                Some(134),
            ),
            (
                "vsprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in vsprintf()",
                Some(134),
            ),
        ];
        for (name, arg, plat, desc, cwe) in source_sinks {
            let mut d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::BufferOverflow,
                SinkSeverity::High,
                plat,
                desc,
            );
            if let Some(c) = cwe {
                d = d.with_cwe(c);
            }
            self.insert(d);
        }
    }

    fn populate_format_string_sinks(&mut self) {
        let sinks = vec![
            (
                "printf",
                0,
                SinkPlatform::CrossPlatform,
                "tainted format in printf()",
                Some(134u32),
            ),
            (
                "fprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in fprintf()",
                Some(134),
            ),
            (
                "sprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in sprintf()",
                Some(134),
            ),
            (
                "snprintf",
                2,
                SinkPlatform::CrossPlatform,
                "tainted format in snprintf()",
                Some(134),
            ),
            (
                "vprintf",
                0,
                SinkPlatform::CrossPlatform,
                "tainted format in vprintf()",
                Some(134),
            ),
            (
                "vfprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in vfprintf()",
                Some(134),
            ),
            (
                "vsprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in vsprintf()",
                Some(134),
            ),
            (
                "vsnprintf",
                2,
                SinkPlatform::CrossPlatform,
                "tainted format in vsnprintf()",
                Some(134),
            ),
            (
                "wprintf",
                0,
                SinkPlatform::CrossPlatform,
                "tainted format in wprintf()",
                Some(134),
            ),
            (
                "swprintf",
                2,
                SinkPlatform::CrossPlatform,
                "tainted format in swprintf()",
                Some(134),
            ),
            (
                "syslog",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in syslog()",
                Some(134),
            ),
            (
                "err",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in err()",
                Some(134),
            ),
            (
                "warn",
                1,
                SinkPlatform::CrossPlatform,
                "tainted format in warn()",
                Some(134),
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let mut d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::FormatString,
                SinkSeverity::High,
                plat,
                desc,
            );
            if let Some(c) = cwe {
                d = d.with_cwe(c);
            }
            self.insert(d);
        }
    }

    fn populate_sql_injection_sinks(&mut self) {
        let sinks = vec![
            (
                "sqlite3_exec",
                1,
                SinkPlatform::CrossPlatform,
                "tainted SQL in sqlite3_exec()",
                89u32,
            ),
            (
                "mysql_query",
                1,
                SinkPlatform::Linux,
                "tainted SQL in mysql_query()",
                89,
            ),
            (
                "mysql_real_query",
                1,
                SinkPlatform::Linux,
                "tainted SQL in mysql_real_query()",
                89,
            ),
            (
                "PQexec",
                1,
                SinkPlatform::Linux,
                "tainted SQL in PQexec()",
                89,
            ),
            (
                "PQexecParams",
                1,
                SinkPlatform::Linux,
                "tainted SQL in PQexecParams()",
                89,
            ),
            (
                "sql_exec",
                1,
                SinkPlatform::CrossPlatform,
                "tainted SQL in sql_exec()",
                89,
            ),
            (
                "db_exec",
                1,
                SinkPlatform::CrossPlatform,
                "tainted SQL in db_exec()",
                89,
            ),
            (
                "SQLExecDirect",
                1,
                SinkPlatform::Windows,
                "tainted SQL in SQLExecDirect()",
                89,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::SqlInjection,
                SinkSeverity::High,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_path_traversal_sinks(&mut self) {
        let sinks = vec![
            (
                "fopen",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in fopen()",
                22u32,
            ),
            ("open", 0, SinkPlatform::Linux, "tainted path in open()", 22),
            (
                "openat",
                1,
                SinkPlatform::Linux,
                "tainted path in openat()",
                22,
            ),
            (
                "creat",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in creat()",
                22,
            ),
            (
                "unlink",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in unlink()",
                22,
            ),
            (
                "unlinkat",
                1,
                SinkPlatform::Linux,
                "tainted path in unlinkat()",
                22,
            ),
            (
                "rename",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in rename()",
                22,
            ),
            (
                "mkdir",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in mkdir()",
                22,
            ),
            (
                "rmdir",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in rmdir()",
                22,
            ),
            (
                "chmod",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in chmod()",
                22,
            ),
            (
                "chown",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in chown()",
                22,
            ),
            (
                "stat",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in stat()",
                22,
            ),
            (
                "lstat",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in lstat()",
                22,
            ),
            (
                "access",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in access()",
                22,
            ),
            (
                "dlopen",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in dlopen()",
                114,
            ),
            (
                "LoadLibrary",
                0,
                SinkPlatform::Windows,
                "tainted path in LoadLibrary()",
                114,
            ),
            (
                "LoadLibraryA",
                0,
                SinkPlatform::Windows,
                "tainted path in LoadLibraryA()",
                114,
            ),
            (
                "LoadLibraryW",
                0,
                SinkPlatform::Windows,
                "tainted path in LoadLibraryW()",
                114,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::PathTraversal,
                SinkSeverity::High,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_network_sinks(&mut self) {
        // Network send sinks (tainted data goes to network).
        let sinks = vec![
            (
                "send",
                1,
                SinkPlatform::CrossPlatform,
                "tainted data in send()",
                319u32,
            ),
            (
                "sendto",
                1,
                SinkPlatform::CrossPlatform,
                "tainted data in sendto()",
                319,
            ),
            (
                "sendmsg",
                1,
                SinkPlatform::CrossPlatform,
                "tainted data in sendmsg()",
                319,
            ),
            (
                "write",
                1,
                SinkPlatform::Linux,
                "tainted data in write()",
                319,
            ),
            (
                "fwrite",
                0,
                SinkPlatform::CrossPlatform,
                "tainted data in fwrite()",
                319,
            ),
            (
                "fputs",
                0,
                SinkPlatform::CrossPlatform,
                "tainted data in fputs()",
                319,
            ),
            (
                "puts",
                0,
                SinkPlatform::CrossPlatform,
                "tainted data in puts()",
                319,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("NetworkLeak".into()),
                SinkSeverity::Medium,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_file_write_sinks(&mut self) {
        let sinks = vec![
            (
                "fprintf",
                1,
                SinkPlatform::CrossPlatform,
                "tainted data in fprintf()",
                200u32,
            ),
            (
                "fputs",
                0,
                SinkPlatform::CrossPlatform,
                "tainted data in fputs()",
                200,
            ),
            (
                "fwrite",
                0,
                SinkPlatform::CrossPlatform,
                "tainted data in fwrite()",
                200,
            ),
            (
                "pwrite",
                1,
                SinkPlatform::Linux,
                "tainted data in pwrite()",
                200,
            ),
            (
                "write",
                1,
                SinkPlatform::Linux,
                "tainted data in write()",
                200,
            ),
            (
                "WriteFile",
                1,
                SinkPlatform::Windows,
                "tainted data in WriteFile()",
                200,
            ),
            (
                "WriteFileEx",
                1,
                SinkPlatform::Windows,
                "tainted data in WriteFileEx()",
                200,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("FileWrite".into()),
                SinkSeverity::Medium,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_windows_registry_sinks(&mut self) {
        let sinks = vec![
            (
                "RegSetValueEx",
                4,
                SinkPlatform::Windows,
                "tainted value in RegSetValueEx()",
                200u32,
            ),
            (
                "RegSetValueExA",
                4,
                SinkPlatform::Windows,
                "tainted value in RegSetValueExA()",
                200,
            ),
            (
                "RegSetValueExW",
                4,
                SinkPlatform::Windows,
                "tainted value in RegSetValueExW()",
                200,
            ),
            (
                "RegSetValue",
                3,
                SinkPlatform::Windows,
                "tainted value in RegSetValue()",
                200,
            ),
            (
                "RegCreateKeyEx",
                1,
                SinkPlatform::Windows,
                "tainted key name in RegCreateKeyEx()",
                200,
            ),
            (
                "RegOpenKeyEx",
                1,
                SinkPlatform::Windows,
                "tainted key name in RegOpenKeyEx()",
                200,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("RegistryWrite".into()),
                SinkSeverity::Medium,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_windows_exec_sinks(&mut self) {
        let sinks = vec![
            (
                "WinExec",
                0,
                SinkPlatform::Windows,
                "tainted cmd in WinExec()",
                78u32,
            ),
            (
                "ShellExecute",
                2,
                SinkPlatform::Windows,
                "tainted file in ShellExecute()",
                78,
            ),
            (
                "ShellExecuteA",
                2,
                SinkPlatform::Windows,
                "tainted file in ShellExecuteA()",
                78,
            ),
            (
                "ShellExecuteW",
                2,
                SinkPlatform::Windows,
                "tainted file in ShellExecuteW()",
                78,
            ),
            (
                "ShellExecuteEx",
                0,
                SinkPlatform::Windows,
                "tainted info in ShellExecuteEx()",
                78,
            ),
            (
                "CreateProcess",
                0,
                SinkPlatform::Windows,
                "tainted path in CreateProcess()",
                78,
            ),
            (
                "CreateProcessA",
                0,
                SinkPlatform::Windows,
                "tainted path in CreateProcessA()",
                78,
            ),
            (
                "CreateProcessW",
                0,
                SinkPlatform::Windows,
                "tainted path in CreateProcessW()",
                78,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_macos_exec_sinks(&mut self) {
        let sinks = vec![
            (
                "NSTask_launch",
                0,
                SinkPlatform::MacOs,
                "tainted path in NSTask launch",
                78u32,
            ),
            (
                "popen",
                0,
                SinkPlatform::MacOs,
                "tainted cmd in popen()",
                78,
            ),
            (
                "system",
                0,
                SinkPlatform::MacOs,
                "tainted cmd in system()",
                78,
            ),
            (
                "AuthorizationExecuteWithPrivileges",
                0,
                SinkPlatform::MacOs,
                "tainted path in AuthorizationExecuteWithPrivileges()",
                78,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::CommandInjection,
                SinkSeverity::Critical,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_linux_syscall_sinks(&mut self) {
        let sinks = vec![
            (
                "syscall",
                0,
                SinkPlatform::Linux,
                "tainted syscall number",
                200u32,
            ),
            (
                "ioctl",
                1,
                SinkPlatform::Linux,
                "tainted ioctl request",
                200,
            ),
            ("prctl", 0, SinkPlatform::Linux, "tainted prctl option", 200),
            (
                "ptrace",
                0,
                SinkPlatform::Linux,
                "tainted ptrace request",
                200,
            ),
            (
                "mount",
                0,
                SinkPlatform::Linux,
                "tainted device in mount()",
                200,
            ),
            (
                "umount",
                0,
                SinkPlatform::Linux,
                "tainted path in umount()",
                22,
            ),
            (
                "socket",
                0,
                SinkPlatform::Linux,
                "tainted domain in socket()",
                200,
            ),
            (
                "connect",
                1,
                SinkPlatform::CrossPlatform,
                "tainted addr in connect()",
                200,
            ),
            (
                "bind",
                1,
                SinkPlatform::CrossPlatform,
                "tainted addr in bind()",
                200,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("SyscallMisuse".into()),
                SinkSeverity::High,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_heap_management_sinks(&mut self) {
        let sinks = vec![
            (
                "free",
                0,
                SinkPlatform::CrossPlatform,
                "tainted pointer in free()",
                416u32,
            ),
            (
                "delete",
                0,
                SinkPlatform::CrossPlatform,
                "tainted pointer in delete",
                416,
            ),
            (
                "realloc",
                0,
                SinkPlatform::CrossPlatform,
                "tainted pointer in realloc()",
                416,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::UseAfterFree,
                SinkSeverity::High,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_crypto_misuse_sinks(&mut self) {
        let sinks = vec![
            (
                "srand",
                0,
                SinkPlatform::CrossPlatform,
                "tainted seed in srand()",
                338u32,
            ),
            (
                "srandom",
                0,
                SinkPlatform::CrossPlatform,
                "tainted seed in srandom()",
                338,
            ),
            (
                "EVP_EncryptInit",
                3,
                SinkPlatform::CrossPlatform,
                "tainted key in EVP_EncryptInit()",
                321,
            ),
            (
                "EVP_DecryptInit",
                3,
                SinkPlatform::CrossPlatform,
                "tainted key in EVP_DecryptInit()",
                321,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("CryptoMisuse".into()),
                SinkSeverity::Medium,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }

    fn populate_misc_sinks(&mut self) {
        let sinks = vec![
            (
                "setenv",
                1,
                SinkPlatform::CrossPlatform,
                "tainted value in setenv()",
                200u32,
            ),
            (
                "putenv",
                0,
                SinkPlatform::CrossPlatform,
                "tainted string in putenv()",
                200,
            ),
            (
                "symlink",
                0,
                SinkPlatform::Linux,
                "tainted target in symlink()",
                59,
            ),
            ("link", 0, SinkPlatform::Linux, "tainted path in link()", 59),
            (
                "chdir",
                0,
                SinkPlatform::CrossPlatform,
                "tainted path in chdir()",
                22,
            ),
            (
                "chroot",
                0,
                SinkPlatform::Linux,
                "tainted path in chroot()",
                22,
            ),
            (
                "mprotect",
                2,
                SinkPlatform::Linux,
                "tainted flags in mprotect()",
                755,
            ),
            (
                "mmap",
                3,
                SinkPlatform::Linux,
                "tainted flags in mmap()",
                755,
            ),
        ];
        for (name, arg, plat, desc, cwe) in sinks {
            let d = TaintSinkDef::new(
                name,
                TaintedArgSpec::Position(arg),
                FindingType::Custom("MiscSink".into()),
                SinkSeverity::Medium,
                plat,
                desc,
            )
            .with_cwe(cwe);
            self.insert(d);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaintState;

    fn make_db() -> TaintSinkDb {
        TaintSinkDb::with_all_sinks()
    }
    fn clean() -> TaintId {
        taint_bits::NONE
    }
    fn user() -> TaintId {
        taint_bits::USER_INPUT
    }
    fn net() -> TaintId {
        taint_bits::NETWORK
    }

    #[test]
    fn test_total_defs_over_100() {
        let db = make_db();
        assert!(
            db.total_defs() >= 100,
            "expected >= 100 sink defs, got {}",
            db.total_defs()
        );
    }

    #[test]
    fn test_system_command_injection() {
        let db = make_db();
        let _args = [TaintExpr::Const(0x1000)];
        let mut state = TaintState::new();
        state.taint_reg("rdi", user());
        let args_tainted = vec![TaintExpr::Reg("rdi".into())];
        let f = db
            .match_sink("system", &args_tainted, &state, 0x100)
            .unwrap();
        assert_eq!(f.finding_type, FindingType::CommandInjection);
    }

    #[test]
    fn test_system_clean_no_finding() {
        let db = make_db();
        let state = TaintState::new();
        let args = vec![TaintExpr::Const(0x1000)]; // clean
        let f = db.match_sink("system", &args, &state, 0x100);
        assert!(f.is_none());
    }

    #[test]
    fn test_memcpy_length_tainted() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rdx", user());
        let args = vec![
            TaintExpr::Const(0x1000),
            TaintExpr::Const(0x2000),
            TaintExpr::Reg("rdx".into()),
        ];
        let f = db.match_sink("memcpy", &args, &state, 0x200).unwrap();
        assert_eq!(f.finding_type, FindingType::BufferOverflow);
    }

    #[test]
    fn test_printf_format_string() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", net());
        let args = vec![TaintExpr::Reg("rdi".into())];
        let f = db.match_sink("printf", &args, &state, 0x300).unwrap();
        assert_eq!(f.finding_type, FindingType::FormatString);
    }

    #[test]
    fn test_sqlite3_sql_injection() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rsi", user());
        let args = vec![
            TaintExpr::Const(0),          // db handle (clean)
            TaintExpr::Reg("rsi".into()), // tainted query
        ];
        let f = db.match_sink("sqlite3_exec", &args, &state, 0x400).unwrap();
        assert_eq!(f.finding_type, FindingType::SqlInjection);
    }

    #[test]
    fn test_fopen_path_traversal() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::COMMAND_LINE);
        let args = vec![TaintExpr::Reg("rdi".into()), TaintExpr::Const(0)];
        let f = db.match_sink("fopen", &args, &state, 0x500).unwrap();
        assert_eq!(f.finding_type, FindingType::PathTraversal);
    }

    #[test]
    fn test_windows_createprocess() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rcx", net());
        let args = vec![TaintExpr::Reg("rcx".into())];
        let f = db
            .match_sink("CreateProcess", &args, &state, 0x600)
            .unwrap();
        assert_eq!(f.finding_type, FindingType::CommandInjection);
    }

    #[test]
    fn test_registry_write() {
        let db = make_db();
        let mut state = TaintState::new();
        // arg4 (index 4) is the data pointer.
        state.taint_reg("r9", user());
        let args = vec![
            TaintExpr::Const(0),
            TaintExpr::Const(0),
            TaintExpr::Const(0),
            TaintExpr::Const(0),
            TaintExpr::Reg("r9".into()),
        ];
        let f = db
            .match_sink("RegSetValueEx", &args, &state, 0x700)
            .unwrap();
        assert!(matches!(f.finding_type, FindingType::Custom(_)));
    }

    #[test]
    fn test_free_use_after_free() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", user());
        let args = vec![TaintExpr::Reg("rdi".into())];
        let f = db.match_sink("free", &args, &state, 0x800).unwrap();
        assert_eq!(f.finding_type, FindingType::UseAfterFree);
    }

    #[test]
    fn test_sink_severity_order() {
        assert!(SinkSeverity::Critical > SinkSeverity::High);
        assert!(SinkSeverity::High > SinkSeverity::Medium);
        assert!(SinkSeverity::Medium > SinkSeverity::Low);
    }

    #[test]
    fn test_tainted_arg_spec_position() {
        let spec = TaintedArgSpec::Position(1);
        assert!(spec.is_triggered(&[clean(), user()]));
        assert!(!spec.is_triggered(&[user(), clean()]));
    }

    #[test]
    fn test_tainted_arg_spec_any() {
        let spec = TaintedArgSpec::Any;
        assert!(spec.is_triggered(&[clean(), user()]));
        assert!(!spec.is_triggered(&[clean(), clean()]));
    }

    #[test]
    fn test_tainted_arg_spec_any_of() {
        let spec = TaintedArgSpec::AnyOf(vec![0, 2]);
        assert!(spec.is_triggered(&[user(), clean(), clean()]));
        assert!(spec.is_triggered(&[clean(), clean(), net()]));
        assert!(!spec.is_triggered(&[clean(), user(), clean()]));
    }

    #[test]
    fn test_sink_names_nonempty() {
        let db = make_db();
        assert!(!db.sink_names().is_empty());
    }

    #[test]
    fn test_sinks_by_severity_critical() {
        let db = make_db();
        let critical = db.sinks_by_severity(SinkSeverity::Critical);
        assert!(!critical.is_empty(), "expected some critical sinks");
    }

    #[test]
    fn test_unknown_sink_returns_none() {
        let db = make_db();
        let state = TaintState::new();
        let f = db.match_sink("nonexistent_func_xyz", &[], &state, 0x0);
        assert!(f.is_none());
    }

    #[test]
    fn test_srand_crypto_misuse() {
        let db = make_db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", net());
        let args = vec![TaintExpr::Reg("rdi".into())];
        let f = db.match_sink("srand", &args, &state, 0x900).unwrap();
        assert!(matches!(f.finding_type, FindingType::Custom(_)));
    }
}
