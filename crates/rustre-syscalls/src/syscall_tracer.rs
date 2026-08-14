//! Syscall tracer: capturing, filtering, formatting, and pattern-matching syscall sequences.
//!
//! Provides [`SyscallTrace`], [`SyscallFilter`], [`TracerStats`], [`StraceLike`] formatter,
//! and [`SyscallPatternMatcher`] for detecting interesting patterns in syscall sequences.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::OsFamily;
use crate::syscall_table::SyscallDb;

// â"€â"€â"€ ArgValue â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A concrete runtime argument value captured during a syscall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgValue {
    Int(i64),
    UInt(u64),
    Ptr(u64),
    Str(String),
    Buffer(Vec<u8>),
    Unknown,
}

impl fmt::Display for ArgValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::UInt(v) => write!(f, "{v}"),
            Self::Ptr(v) => write!(f, "0x{v:016x}"),
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Buffer(b) => {
                write!(f, "<{} bytes>", b.len())
            }
            Self::Unknown => write!(f, "?"),
        }
    }
}

// â"€â"€â"€ SyscallTrace â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One captured syscall invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTrace {
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Syscall number.
    pub number: u64,
    /// Syscall name (resolved at capture time).
    pub name: String,
    /// Argument values at call time.
    pub args: Vec<ArgValue>,
    /// Return value (None while in-progress).
    pub return_value: Option<i64>,
    /// Timestamp of the call (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Duration in nanoseconds (None while in-progress).
    pub duration_ns: Option<u64>,
    /// Operating system.
    pub os: OsFamily,
}

impl SyscallTrace {
    /// Create a new in-progress trace entry.
    #[must_use]
    pub fn new(
        pid: u32,
        tid: u32,
        number: u64,
        name: String,
        args: Vec<ArgValue>,
        os: OsFamily,
    ) -> Self {
        let timestamp_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        Self {
            pid,
            tid,
            number,
            name,
            args,
            return_value: None,
            timestamp_ns,
            duration_ns: None,
            os,
        }
    }

    /// Mark the syscall as complete with a return value.
    pub const fn complete(&mut self, ret: i64, duration_ns: u64) {
        self.return_value = Some(ret);
        self.duration_ns = Some(duration_ns);
    }

    /// True if the syscall returned an error (negative value on Linux).
    #[must_use]
    pub const fn is_error(&self) -> bool {
        match self.return_value {
            Some(v) => v < 0,
            None => false,
        }
    }

    /// True if the syscall has not yet completed.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.return_value.is_none()
    }

    /// Duration as a human-readable string.
    #[must_use]
    pub fn duration_str(&self) -> String {
        match self.duration_ns {
            None => "pending".to_string(),
            Some(ns) if ns < 1_000 => format!("{ns}ns"),
            Some(ns) if ns < 1_000_000 => format!("{:.1}Âµs", crate::u64_to_f64(ns) / 1e3),
            Some(ns) => format!("{:.3}ms", crate::u64_to_f64(ns) / 1e6),
        }
    }
}

// â"€â"€â"€ SyscallFilter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Composable predicate for filtering syscall traces.
#[derive(Debug, Clone, Default)]
pub struct SyscallFilter {
    /// Only include these PIDs (empty = all PIDs).
    pub pid_allow: Vec<u32>,
    /// Exclude these PIDs.
    pub pid_deny: Vec<u32>,
    /// Only include syscalls with these names (empty = all).
    pub name_allow: Vec<String>,
    /// Exclude syscalls with these names.
    pub name_deny: Vec<String>,
    /// Only include syscalls that returned an error.
    pub errors_only: bool,
    /// Only include syscalls longer than this (nanoseconds).
    pub min_duration_ns: Option<u64>,
    /// Only include syscalls with these tags (requires a `SyscallDb`).
    pub tag_filter: Vec<String>,
}

impl SyscallFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid_allow.push(pid);
        self
    }

    #[must_use]
    pub fn deny_pid(mut self, pid: u32) -> Self {
        self.pid_deny.push(pid);
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name_allow.push(name.to_string());
        self
    }

    #[must_use]
    pub fn deny_name(mut self, name: &str) -> Self {
        self.name_deny.push(name.to_string());
        self
    }

    #[must_use]
    pub const fn errors_only(mut self) -> Self {
        self.errors_only = true;
        self
    }

    #[must_use]
    pub const fn with_min_duration_ns(mut self, ns: u64) -> Self {
        self.min_duration_ns = Some(ns);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tag_filter.push(tag.to_string());
        self
    }

    /// Test whether a trace entry passes this filter.
    /// `db` is optional —" required only when `tag_filter` is non-empty.
    #[must_use]
    pub fn matches(&self, trace: &SyscallTrace, db: Option<&SyscallDb>) -> bool {
        // PID allow/deny
        if !self.pid_allow.is_empty() && !self.pid_allow.contains(&trace.pid) {
            return false;
        }
        if self.pid_deny.contains(&trace.pid) {
            return false;
        }

        // Name allow/deny
        if !self.name_allow.is_empty() && !self.name_allow.contains(&trace.name) {
            return false;
        }
        if self.name_deny.contains(&trace.name) {
            return false;
        }

        // Errors only
        if self.errors_only && !trace.is_error() {
            return false;
        }

        // Min duration
        if let Some(min) = self.min_duration_ns {
            match trace.duration_ns {
                None => return false,
                Some(d) if d < min => return false,
                _ => {}
            }
        }

        // Tag filter
        if !self.tag_filter.is_empty()
            && let Some(db) = db
        {
            if let Some(entry) = db.lookup_by_name(trace.os, &trace.name) {
                if !self.tag_filter.iter().any(|t| entry.tags.contains(t)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

// â"€â"€â"€ TracerStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregate statistics for a captured syscall session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracerStats {
    pub total_calls: u64,
    pub error_calls: u64,
    pub pending_calls: u64,
    pub total_duration_ns: u64,
    /// Per-name call counts.
    pub by_name: HashMap<String, u64>,
    /// Per-PID call counts.
    pub by_pid: HashMap<u32, u64>,
    /// Slowest calls (name, `duration_ns`).
    pub top_slow: Vec<(String, u64)>,
}

impl TracerStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one trace record into the stats.
    pub fn record(&mut self, t: &SyscallTrace) {
        self.total_calls += 1;
        if t.is_error() {
            self.error_calls += 1;
        }
        if t.is_pending() {
            self.pending_calls += 1;
        }
        if let Some(d) = t.duration_ns {
            self.total_duration_ns = self.total_duration_ns.saturating_add(d);
        }
        *self.by_name.entry(t.name.clone()).or_insert(0) += 1;
        *self.by_pid.entry(t.pid).or_insert(0) += 1;
    }

    /// Compute stats from a slice of trace entries.
    #[must_use]
    pub fn from_traces(traces: &[SyscallTrace]) -> Self {
        let mut s = Self::new();
        for t in traces {
            s.record(t);
        }
        // Compute top_slow
        let mut by_name_duration: HashMap<&str, u64> = HashMap::new();
        for t in traces {
            if let Some(d) = t.duration_ns {
                let e = by_name_duration.entry(&t.name).or_insert(0);
                *e = (*e).max(d);
            }
        }
        let mut slow: Vec<(String, u64)> = by_name_duration
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        slow.sort_by(|a, b| b.1.cmp(&a.1));
        slow.truncate(10);
        s.top_slow = slow;
        s
    }

    #[must_use]
    pub fn mean_duration_ns(&self) -> f64 {
        if self.total_calls == 0 {
            return 0.0;
        }
        crate::u64_to_f64(self.total_duration_ns) / crate::u64_to_f64(self.total_calls)
    }

    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.total_calls == 0 {
            return 0.0;
        }
        crate::u64_to_f64(self.error_calls) / crate::u64_to_f64(self.total_calls)
    }

    /// Most-called syscall name.
    #[must_use]
    pub fn most_called(&self) -> Option<(&str, u64)> {
        self.by_name
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, &v)| (k.as_str(), v))
    }
}

// â"€â"€â"€ StraceLike â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Formats syscall traces in an strace-like text format.
pub struct StraceLike {
    /// Show timestamps.
    pub show_timestamps: bool,
    /// Show PID prefix.
    pub show_pid: bool,
    /// Show duration in brackets.
    pub show_duration: bool,
}

impl Default for StraceLike {
    fn default() -> Self {
        Self {
            show_timestamps: false,
            show_pid: true,
            show_duration: false,
        }
    }
}

impl StraceLike {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Format a single trace entry.
    #[must_use]
    pub fn format(&self, t: &SyscallTrace) -> String {
        let mut out = String::new();

        if self.show_pid {
            write!(out, "[{:6}] ", t.pid).ok();
        }

        if self.show_timestamps {
            let secs = t.timestamp_ns / 1_000_000_000;
            let ns = t.timestamp_ns % 1_000_000_000;
            write!(out, "{secs}.{ns:09} ").ok();
        }

        out.push_str(&t.name);
        out.push('(');

        for (i, arg) in t.args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write!(out, "{arg}").ok();
        }
        out.push(')');

        match t.return_value {
            Some(v) if v < 0 => {
                // v.checked_neg() guards against i64::MIN overflow before casting
                let code = v.checked_neg()
                    .and_then(|pos| u32::try_from(pos).ok())
                    .map_or_else(|| "?".to_string(), linux_errno_name);
                write!(out, " = {v} {code}").ok();
            }
            Some(v) => {
                write!(out, " = {v}").ok();
            }
            None => out.push_str(" = <unfinished>"),
        }

        if self.show_duration {
            write!(out, " <{}>", t.duration_str()).ok();
        }

        out
    }

    /// Format a slice of traces.
    #[must_use]
    pub fn format_all(&self, traces: &[SyscallTrace]) -> Vec<String> {
        traces.iter().map(|t| self.format(t)).collect()
    }
}

/// Map a Linux errno number to a name string.
fn linux_errno_name(errno: u32) -> String {
    let name = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        17 => "EEXIST",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        28 => "ENOSPC",
        29 => "ESPIPE",
        32 => "EPIPE",
        36 => "ERANGE",
        38 => "ENOSYS",
        40 => "ELOOP",
        111 => "ECONNREFUSED",
        _ => return format!("E{errno}"),
    };
    name.to_string()
}

// â"€â"€â"€ Pattern kinds â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A pattern of syscall names to look for (ordered sequence).
#[derive(Debug, Clone)]
pub struct SyscallPattern {
    pub name: String,
    pub sequence: Vec<String>,
    pub description: String,
}

impl SyscallPattern {
    #[must_use]
    pub fn new(name: &str, sequence: &[&str], description: &str) -> Self {
        Self {
            name: name.to_string(),
            sequence: sequence
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            description: description.to_string(),
        }
    }
}

/// A match found by the pattern matcher.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub start_index: usize,
    pub end_index: usize,
    pub pid: u32,
}

// â"€â"€â"€ SyscallPatternMatcher â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Detects interesting ordered syscall sequences in a trace stream.
pub struct SyscallPatternMatcher {
    patterns: Vec<SyscallPattern>,
}

impl SyscallPatternMatcher {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Create a matcher pre-loaded with common interesting patterns.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut m = Self::new();
        m.add_pattern(SyscallPattern::new(
            "exec_chain",
            &["fork", "execve"],
            "Process spawning via fork+execve",
        ));
        m.add_pattern(SyscallPattern::new(
            "file_write",
            &["open", "write", "close"],
            "Full file write sequence",
        ));
        m.add_pattern(SyscallPattern::new(
            "file_read",
            &["open", "read", "close"],
            "Full file read sequence",
        ));
        m.add_pattern(SyscallPattern::new(
            "socket_connect",
            &["socket", "connect"],
            "TCP/UDP outbound connection",
        ));
        m.add_pattern(SyscallPattern::new(
            "socket_server",
            &["socket", "bind", "listen", "accept"],
            "TCP server bind+listen+accept",
        ));
        m.add_pattern(SyscallPattern::new(
            "mmap_exec",
            &["mmap", "mprotect"],
            "Executable memory creation (possible shellcode/JIT)",
        ));
        m.add_pattern(SyscallPattern::new(
            "ptrace_attach",
            &["ptrace", "waitpid"],
            "Debugger or anti-debug ptrace sequence",
        ));
        m.add_pattern(SyscallPattern::new(
            "privilege_escalation",
            &["setuid", "execve"],
            "setuid + exec (possible privilege escalation)",
        ));
        m.add_pattern(SyscallPattern::new(
            "pipe_exec",
            &["pipe", "fork", "dup2", "execve"],
            "Shell pipeline setup (pipe+fork+dup2+exec)",
        ));
        m.add_pattern(SyscallPattern::new(
            "clone_exec",
            &["clone", "execve"],
            "Thread/process spawn via clone+exec",
        ));
        m
    }

    pub fn add_pattern(&mut self, p: SyscallPattern) {
        self.patterns.push(p);
    }

    /// Search for all pattern occurrences in a per-pid trace window.
    #[must_use]
    pub fn find_matches(&self, traces: &[SyscallTrace]) -> Vec<PatternMatch> {
        let mut results = Vec::new();

        // Group by pid
        let mut by_pid: HashMap<u32, Vec<(usize, &SyscallTrace)>> = HashMap::new();
        for (i, t) in traces.iter().enumerate() {
            by_pid.entry(t.pid).or_default().push((i, t));
        }

        for (pid, pid_traces) in &by_pid {
            for pattern in &self.patterns {
                let mut seq_pos = 0;
                let mut start_idx: Option<usize> = None;

                for (global_idx, trace) in pid_traces {
                    if trace.name == pattern.sequence[seq_pos] {
                        if seq_pos == 0 {
                            start_idx = Some(*global_idx);
                        }
                        seq_pos += 1;
                        if seq_pos == pattern.sequence.len() {
                            results.push(PatternMatch {
                                pattern_name: pattern.name.clone(),
                                start_index: start_idx.unwrap_or(*global_idx),
                                end_index: *global_idx,
                                pid: *pid,
                            });
                            seq_pos = 0;
                            start_idx = None;
                        }
                    }
                }
            }
        }

        results
    }

    /// Return descriptions of all loaded patterns.
    #[must_use]
    pub fn pattern_descriptions(&self) -> Vec<(String, String)> {
        self.patterns
            .iter()
            .map(|p| (p.name.clone(), p.description.clone()))
            .collect()
    }
}

impl Default for SyscallPatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ TraceLog â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An append-only log of syscall traces.
#[derive(Debug, Default)]
pub struct TraceLog {
    entries: Vec<SyscallTrace>,
}

impl TraceLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, trace: SyscallTrace) {
        self.entries.push(trace);
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Filter entries using a [`SyscallFilter`].
    pub fn filter<'a>(
        &'a self,
        filter: &'a SyscallFilter,
        db: Option<&'a SyscallDb>,
    ) -> impl Iterator<Item = &'a SyscallTrace> + 'a {
        self.entries.iter().filter(move |t| filter.matches(t, db))
    }

    #[must_use]
    pub fn stats(&self) -> TracerStats {
        TracerStats::from_traces(&self.entries)
    }

    #[must_use]
    pub fn entries(&self) -> &[SyscallTrace] {
        &self.entries
    }

    /// Find the latest entry for a given (pid, name).
    #[must_use]
    pub fn find_latest(&self, pid: u32, name: &str) -> Option<&SyscallTrace> {
        self.entries
            .iter()
            .rev()
            .find(|t| t.pid == pid && t.name == name)
    }
}

// â"€â"€â"€ Builder helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build a synthetic trace entry for testing / simulation.
#[must_use]
pub fn make_trace(
    pid: u32,
    tid: u32,
    number: u64,
    name: &str,
    args: Vec<ArgValue>,
    ret: Option<i64>,
    os: OsFamily,
) -> SyscallTrace {
    let mut t = SyscallTrace::new(pid, tid, number, name.to_string(), args, os);
    if let Some(r) = ret {
        t.complete(r, 1000);
    }
    t
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsFamily;

    fn sample_trace(name: &str, ret: Option<i64>) -> SyscallTrace {
        make_trace(100, 100, 0, name, vec![], ret, OsFamily::Linux)
    }

    #[test]
    fn test_trace_creation() {
        let t = sample_trace("read", Some(10));
        assert_eq!(t.name, "read");
        assert_eq!(t.return_value, Some(10));
        assert!(!t.is_error());
        assert!(!t.is_pending());
    }

    #[test]
    fn test_trace_error() {
        let t = sample_trace("open", Some(-2)); // -ENOENT
        assert!(t.is_error());
        assert_eq!(t.return_value, Some(-2));
    }

    #[test]
    fn test_trace_pending() {
        let t = sample_trace("futex", None);
        assert!(t.is_pending());
    }

    #[test]
    fn test_duration_str_ns() {
        let mut t = sample_trace("read", Some(5));
        t.duration_ns = Some(500);
        assert!(t.duration_str().contains("ns"));
    }

    #[test]
    fn test_duration_str_us() {
        let mut t = sample_trace("read", Some(5));
        t.duration_ns = Some(15_000);
        assert!(t.duration_str().contains("Âµs"));
    }

    #[test]
    fn test_duration_str_ms() {
        let mut t = sample_trace("read", Some(5));
        t.duration_ns = Some(5_000_000);
        assert!(t.duration_str().contains("ms"));
    }

    #[test]
    fn test_filter_pid_allow() {
        let t = sample_trace("read", Some(5));
        let f = SyscallFilter::new().with_pid(100);
        assert!(f.matches(&t, None));
        let f2 = SyscallFilter::new().with_pid(999);
        assert!(!f2.matches(&t, None));
    }

    #[test]
    fn test_filter_pid_deny() {
        let t = sample_trace("read", Some(5));
        let f = SyscallFilter::new().deny_pid(100);
        assert!(!f.matches(&t, None));
    }

    #[test]
    fn test_filter_name_allow() {
        let t = sample_trace("write", Some(1));
        let f = SyscallFilter::new().with_name("write");
        assert!(f.matches(&t, None));
        let f2 = SyscallFilter::new().with_name("read");
        assert!(!f2.matches(&t, None));
    }

    #[test]
    fn test_filter_name_deny() {
        let t = sample_trace("write", Some(1));
        let f = SyscallFilter::new().deny_name("write");
        assert!(!f.matches(&t, None));
    }

    #[test]
    fn test_filter_errors_only() {
        let ok = sample_trace("read", Some(5));
        let err = sample_trace("open", Some(-2));
        let f = SyscallFilter::new().errors_only();
        assert!(!f.matches(&ok, None));
        assert!(f.matches(&err, None));
    }

    #[test]
    fn test_filter_min_duration() {
        let mut t = sample_trace("read", Some(5));
        t.duration_ns = Some(10_000);
        let f = SyscallFilter::new().with_min_duration_ns(5_000);
        assert!(f.matches(&t, None));
        let f2 = SyscallFilter::new().with_min_duration_ns(50_000);
        assert!(!f2.matches(&t, None));
    }

    #[test]
    fn test_tracer_stats_basic() {
        let traces = vec![
            sample_trace("read", Some(5)),
            sample_trace("write", Some(1)),
            sample_trace("open", Some(-2)),
        ];
        let s = TracerStats::from_traces(&traces);
        assert_eq!(s.total_calls, 3);
        assert_eq!(s.error_calls, 1);
    }

    #[test]
    fn test_tracer_stats_by_name() {
        let traces = vec![
            sample_trace("read", Some(5)),
            sample_trace("read", Some(3)),
            sample_trace("write", Some(1)),
        ];
        let s = TracerStats::from_traces(&traces);
        assert_eq!(s.by_name["read"], 2);
        assert_eq!(s.by_name["write"], 1);
    }

    #[test]
    fn test_tracer_stats_most_called() {
        let traces = vec![
            sample_trace("read", Some(5)),
            sample_trace("read", Some(3)),
            sample_trace("write", Some(1)),
        ];
        let s = TracerStats::from_traces(&traces);
        let (name, count) = s.most_called().unwrap();
        assert_eq!(name, "read");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_strace_format_basic() {
        let t = sample_trace("read", Some(5));
        let fmt = StraceLike::new();
        let s = fmt.format(&t);
        assert!(s.contains("read"));
        assert!(s.contains("= 5"));
    }

    #[test]
    fn test_strace_format_error() {
        let t = sample_trace("open", Some(-2));
        let fmt = StraceLike::new();
        let s = fmt.format(&t);
        assert!(s.contains("ENOENT") || s.contains("-2"));
    }

    #[test]
    fn test_strace_format_pending() {
        let t = sample_trace("futex", None);
        let fmt = StraceLike::new();
        let s = fmt.format(&t);
        assert!(s.contains("unfinished"));
    }

    #[test]
    fn test_pattern_matcher_defaults() {
        let m = SyscallPatternMatcher::with_defaults();
        assert!(!m.patterns.is_empty());
    }

    #[test]
    fn test_pattern_matcher_exec_chain() {
        let traces = vec![
            sample_trace("fork", Some(1234)),
            sample_trace("execve", Some(0)),
        ];
        let m = SyscallPatternMatcher::with_defaults();
        let matches = m.find_matches(&traces);
        assert!(matches.iter().any(|m| m.pattern_name == "exec_chain"));
    }

    #[test]
    fn test_pattern_matcher_socket_connect() {
        let traces = vec![
            sample_trace("socket", Some(3)),
            sample_trace("connect", Some(0)),
        ];
        let m = SyscallPatternMatcher::with_defaults();
        let matches = m.find_matches(&traces);
        assert!(matches.iter().any(|m| m.pattern_name == "socket_connect"));
    }

    #[test]
    fn test_pattern_matcher_no_match() {
        let traces = vec![
            sample_trace("read", Some(5)),
            sample_trace("write", Some(1)),
        ];
        let m = SyscallPatternMatcher::with_defaults();
        let matches = m.find_matches(&traces);
        assert!(matches.iter().all(|m| m.pattern_name != "exec_chain"));
    }

    #[test]
    fn test_trace_log_push_and_len() {
        let mut log = TraceLog::new();
        log.push(sample_trace("read", Some(5)));
        log.push(sample_trace("write", Some(1)));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_trace_log_filter() {
        let mut log = TraceLog::new();
        log.push(sample_trace("read", Some(5)));
        log.push(sample_trace("open", Some(-2)));
        let f = SyscallFilter::new().errors_only();
        let filtered: Vec<_> = log.filter(&f, None).collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "open");
    }

    #[test]
    fn test_trace_log_find_latest() {
        let mut log = TraceLog::new();
        log.push(sample_trace("read", Some(5)));
        log.push(sample_trace("read", Some(10)));
        let latest = log.find_latest(100, "read").unwrap();
        assert_eq!(latest.return_value, Some(10));
    }

    #[test]
    fn test_arg_value_display() {
        assert_eq!(ArgValue::Int(-1).to_string(), "-1");
        assert_eq!(ArgValue::UInt(42).to_string(), "42");
        assert!(ArgValue::Ptr(0xdead_beef).to_string().contains("dead"));
        assert_eq!(ArgValue::Str("hello".to_string()).to_string(), "\"hello\"");
    }

    #[test]
    fn test_linux_errno_name() {
        assert_eq!(linux_errno_name(2), "ENOENT");
        assert_eq!(linux_errno_name(13), "EACCES");
        assert_eq!(linux_errno_name(22), "EINVAL");
    }

    #[test]
    fn test_error_rate() {
        let traces = vec![
            sample_trace("read", Some(5)),
            sample_trace("open", Some(-2)),
        ];
        let s = TracerStats::from_traces(&traces);
        assert!((s.error_rate() - 0.5).abs() < 1e-9);
    }
}

// â"€â"€â"€ SyscallCategory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Broad category for a syscall sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SyscallCategory {
    FileSystem,
    Network,
    Process,
    Memory,
    Security,
    Synchronization,
    Time,
    Debug,
    Unknown,
}

impl std::fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::Memory => write!(f, "memory"),
            Self::Security => write!(f, "security"),
            Self::Synchronization => write!(f, "sync"),
            Self::Time => write!(f, "time"),
            Self::Debug => write!(f, "debug"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Classify a syscall name into a broad category.
#[must_use]
pub fn classify_syscall(name: &str) -> SyscallCategory {
    let n = name.to_lowercase();
    if n.contains("read")
        || n.contains("write")
        || n.contains("open")
        || n.contains("close")
        || n.contains("stat")
        || n.contains("rename")
        || n.contains("unlink")
        || n.contains("mkdir")
        || n.contains("link")
        || n.contains("chmod")
        || n.contains("chown")
        || n.contains("sync")
        || n.contains("fcntl")
        || n.contains("ioctl")
        || n.contains("lseek")
        || n.contains("flock")
        || n.contains("getdent")
        || n.contains("getcwd")
        || n.contains("chdir")
        || n.contains("truncate")
    {
        return SyscallCategory::FileSystem;
    }
    if n.contains("socket")
        || n.contains("connect")
        || n.contains("bind")
        || n.contains("listen")
        || n.contains("accept")
        || n.contains("send")
        || n.contains("recv")
        || n.contains("shutdown")
        || n.contains("setsockopt")
        || n.contains("getsockopt")
        || n.contains("getpeername")
    {
        return SyscallCategory::Network;
    }
    if n.contains("fork")
        || n.contains("exec")
        || n.contains("clone")
        || n.contains("exit")
        || n.contains("wait")
        || n.contains("getpid")
        || n.contains("getppid")
        || n.contains("kill")
        || n.contains("signal")
        || n.contains("setuid")
        || n.contains("getuid")
        || n.contains("setgid")
    {
        return SyscallCategory::Process;
    }
    if n.contains("mmap")
        || n.contains("mprotect")
        || n.contains("munmap")
        || n.contains("brk")
        || n.contains("mlock")
        || n.contains("mremap")
        || n.contains("madvise")
        || n.contains("mincore")
        || n.contains("alloc")
        || n.contains("free")
        || n.contains("virtual")
    {
        return SyscallCategory::Memory;
    }
    if n.contains("ptrace") || n.contains("debug") {
        return SyscallCategory::Debug;
    }
    if n.contains("time") || n.contains("sleep") || n.contains("alarm") || n.contains("clock") {
        return SyscallCategory::Time;
    }
    if n.contains("futex")
        || n.contains("semaphore")
        || n.contains("mutex")
        || n.contains("event")
        || n.contains("wait")
        || n.contains("signal")
    {
        return SyscallCategory::Synchronization;
    }
    if n.contains("seccomp")
        || n.contains("getrandom")
        || n.contains("token")
        || n.contains("privilege")
    {
        return SyscallCategory::Security;
    }
    SyscallCategory::Unknown
}

// â"€â"€â"€ SyscallSummary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Aggregate summary of syscall activity grouped by category.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyscallSummary {
    pub by_category: std::collections::HashMap<String, u64>,
    pub unique_calls: std::collections::HashSet<String>,
    pub top_calls: Vec<(String, u64)>,
    pub total: u64,
    pub error_count: u64,
}

impl SyscallSummary {
    #[must_use]
    pub fn from_log(log: &TraceLog) -> Self {
        let mut by_cat: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut by_name: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut unique = std::collections::HashSet::new();
        let mut total = 0u64;
        let mut errors = 0u64;

        for t in log.entries() {
            total += 1;
            if t.is_error() {
                errors += 1;
            }
            unique.insert(t.name.clone());
            let cat = classify_syscall(&t.name).to_string();
            *by_cat.entry(cat).or_insert(0) += 1;
            *by_name.entry(t.name.clone()).or_insert(0) += 1;
        }

        let mut top: Vec<(String, u64)> = by_name.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10);

        Self {
            by_category: by_cat,
            unique_calls: unique,
            top_calls: top,
            total,
            error_count: errors,
        }
    }

    #[must_use]
    pub fn dominant_category(&self) -> Option<&str> {
        self.by_category
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, _)| k.as_str())
    }
}

// â"€â"€â"€ Additional tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::OsFamily;

    fn st(name: &str, ret: Option<i64>) -> SyscallTrace {
        make_trace(1, 1, 0, name, vec![], ret, OsFamily::Linux)
    }

    #[test]
    fn test_classify_filesystem() {
        assert_eq!(classify_syscall("read"), SyscallCategory::FileSystem);
        assert_eq!(classify_syscall("openat"), SyscallCategory::FileSystem);
    }

    #[test]
    fn test_classify_network() {
        assert_eq!(classify_syscall("socket"), SyscallCategory::Network);
        assert_eq!(classify_syscall("connect"), SyscallCategory::Network);
    }

    #[test]
    fn test_classify_memory() {
        assert_eq!(classify_syscall("mmap"), SyscallCategory::Memory);
        assert_eq!(classify_syscall("mprotect"), SyscallCategory::Memory);
    }

    #[test]
    fn test_classify_process() {
        assert_eq!(classify_syscall("fork"), SyscallCategory::Process);
        assert_eq!(classify_syscall("execve"), SyscallCategory::Process);
    }

    #[test]
    fn test_classify_debug() {
        assert_eq!(classify_syscall("ptrace"), SyscallCategory::Debug);
    }

    #[test]
    fn test_classify_unknown() {
        assert_eq!(
            classify_syscall("xyzzy_nonexistent"),
            SyscallCategory::Unknown
        );
    }

    #[test]
    fn test_syscall_summary_from_log() {
        let mut log = TraceLog::new();
        log.push(st("read", Some(5)));
        log.push(st("write", Some(3)));
        log.push(st("open", Some(-2)));
        let summary = SyscallSummary::from_log(&log);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.unique_calls.len(), 3);
    }

    #[test]
    fn test_syscall_summary_dominant_category() {
        let mut log = TraceLog::new();
        for _ in 0..5 {
            log.push(st("read", Some(1)));
        }
        log.push(st("socket", Some(3)));
        let summary = SyscallSummary::from_log(&log);
        assert_eq!(summary.dominant_category(), Some("filesystem"));
    }

    #[test]
    fn test_syscall_summary_top_calls() {
        let mut log = TraceLog::new();
        for _ in 0..3 {
            log.push(st("read", Some(1)));
        }
        for _ in 0..2 {
            log.push(st("write", Some(1)));
        }
        let summary = SyscallSummary::from_log(&log);
        assert_eq!(summary.top_calls[0].0, "read");
        assert_eq!(summary.top_calls[0].1, 3);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SyscallCategory::FileSystem.to_string(), "filesystem");
        assert_eq!(SyscallCategory::Network.to_string(), "network");
        assert_eq!(SyscallCategory::Memory.to_string(), "memory");
    }
}
