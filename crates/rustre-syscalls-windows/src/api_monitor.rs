//! Windows API hooking model.
//!
//! Provides a policy-based API monitoring framework that abstracts over the
//! three common Windows API hook strategies: IAT patching, inline (trampoline)
//! patching, and EAT patching.  All types are pure-Rust models; the actual
//! low-level patching is left to the platform layer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::WinArch;
pub use crate::WinVersion;

// ─── HookPoint ────────────────────────────────────────────────────────────────

/// The hook strategy / location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookPoint {
    /// Import Address Table hook — patch the function pointer in the IAT of the
    /// importing module.
    Iat,
    /// Inline (trampoline) hook — overwrite the first bytes of the target
    /// function with a JMP.
    Inline,
    /// Export Address Table hook — patch the EAT entry in the exporting DLL.
    Eat,
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iat => write!(f, "IAT"),
            Self::Inline => write!(f, "Inline"),
            Self::Eat => write!(f, "EAT"),
        }
    }
}

// ─── DllFilter ────────────────────────────────────────────────────────────────

/// Restricts which DLLs are monitored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DllFilter {
    /// Monitor all DLLs.
    All,
    /// Monitor only a specific set of DLL names (case-insensitive).
    Include(Vec<String>),
    /// Monitor all DLLs except those listed (case-insensitive).
    Exclude(Vec<String>),
}

impl DllFilter {
    /// Return `true` if `dll` (case-insensitive) should be monitored.
    #[must_use]
    pub fn allows(&self, dll: &str) -> bool {
        let lower = dll.to_ascii_lowercase();
        match self {
            Self::All => true,
            Self::Include(list) => list.iter().any(|d| d.to_ascii_lowercase() == lower),
            Self::Exclude(list) => !list.iter().any(|d| d.to_ascii_lowercase() == lower),
        }
    }

    /// Build an include filter from an iterable of names.
    #[must_use]
    pub fn include(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Include(names.into_iter().map(Into::into).collect())
    }

    /// Build an exclude filter from an iterable of names.
    #[must_use]
    pub fn exclude(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Exclude(names.into_iter().map(Into::into).collect())
    }
}

// ─── ApiCallRecord ────────────────────────────────────────────────────────────

/// A record of a single intercepted API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    /// Unique call sequence number within the session.
    pub seq: u64,
    /// Name of the DLL exporting the function.
    pub dll: String,
    /// Name of the API function.
    pub function: String,
    /// Raw argument values captured at the hook point.
    pub args: Vec<u64>,
    /// Return value (populated after the function returns).
    pub return_value: Option<u64>,
    /// Thread ID that made the call.
    pub tid: u32,
    /// Monotonic timestamp (nanoseconds from session start).
    pub timestamp_ns: u64,
    /// Elapsed time inside the function in nanoseconds.
    pub elapsed_ns: Option<u64>,
    /// Whether the call was blocked by a rule.
    pub blocked: bool,
}

impl ApiCallRecord {
    #[must_use]
    pub fn new(
        seq: u64,
        dll: impl Into<String>,
        function: impl Into<String>,
        args: Vec<u64>,
        tid: u32,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            seq,
            dll: dll.into(),
            function: function.into(),
            args,
            return_value: None,
            tid,
            timestamp_ns,
            elapsed_ns: None,
            blocked: false,
        }
    }

    /// Mark the call as returned with `retval` and `elapsed_ns`.
    pub const fn complete(&mut self, retval: u64, elapsed_ns: u64) {
        self.return_value = Some(retval);
        self.elapsed_ns = Some(elapsed_ns);
    }
}

// ─── ApiHookRule ──────────────────────────────────────────────────────────────

/// Policy for a single monitored function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHookRule {
    /// Unique rule ID.
    pub id: u64,
    /// DLL name (case-insensitive).
    pub dll: String,
    /// Function name.
    pub function: String,
    /// Hook strategy.
    pub hook_point: HookPoint,
    /// Whether to log every call.
    pub log: bool,
    /// Whether to block calls (returning `blocked_retval`).
    pub block: bool,
    /// Return value to inject when blocking.
    pub blocked_retval: u64,
    /// Whether the rule is active.
    pub enabled: bool,
}

impl ApiHookRule {
    #[must_use]
    pub fn new(
        id: u64,
        dll: impl Into<String>,
        function: impl Into<String>,
        hook_point: HookPoint,
    ) -> Self {
        Self {
            id,
            dll: dll.into(),
            function: function.into(),
            hook_point,
            log: true,
            block: false,
            blocked_retval: 0,
            enabled: true,
        }
    }

    /// Match a call record against this rule (case-insensitive).
    #[must_use]
    pub fn matches(&self, dll: &str, function: &str) -> bool {
        self.dll.eq_ignore_ascii_case(dll) && self.function.eq_ignore_ascii_case(function)
    }
}

// ─── ApiMonitorSession ────────────────────────────────────────────────────────

/// An active API monitoring session.
#[derive(Debug, Default)]
pub struct ApiMonitorSession {
    /// All captured call records.
    records: Vec<ApiCallRecord>,
    /// Per-function call counts.
    call_counts: HashMap<String, u64>,
    /// Sequence counter.
    next_seq: u64,
}

impl ApiMonitorSession {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an incoming call.  Returns the assigned sequence number.
    pub fn record_call(
        &mut self,
        dll: impl Into<String>,
        function: impl Into<String>,
        args: Vec<u64>,
        tid: u32,
        timestamp_ns: u64,
        blocked: bool,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        let dll_s: String = dll.into();
        let fn_s: String = function.into();
        if let Some(c) = self.call_counts.get_mut(fn_s.as_str()) {
            *c += 1;
        } else {
            self.call_counts.insert(fn_s.clone(), 1);
        }
        let mut rec = ApiCallRecord::new(seq, dll_s, fn_s, args, tid, timestamp_ns);
        rec.blocked = blocked;
        self.records.push(rec);
        seq
    }

    /// Complete a pending call by sequence number.
    pub fn complete_call(&mut self, seq: u64, retval: u64, elapsed_ns: u64) -> bool {
        self.records
            .iter_mut()
            .find(|r| r.seq == seq)
            .is_some_and(|rec| {
                rec.complete(retval, elapsed_ns);
                true
            })
    }

    /// All call records.
    #[must_use]
    pub fn records(&self) -> &[ApiCallRecord] {
        &self.records
    }

    /// Number of calls recorded.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.records.len()
    }

    /// Number of calls to a specific function.
    #[must_use]
    pub fn count_for(&self, function: &str) -> u64 {
        self.call_counts.get(function).copied().unwrap_or(0)
    }

    /// Return records filtered by function name.
    #[must_use]
    pub fn by_function(&self, function: &str) -> Vec<&ApiCallRecord> {
        self.records
            .iter()
            .filter(|r| r.function == function)
            .collect()
    }

    /// Return records where the call was blocked.
    #[must_use]
    pub fn blocked_calls(&self) -> Vec<&ApiCallRecord> {
        self.records.iter().filter(|r| r.blocked).collect()
    }
}

// ─── ApiMonitor ───────────────────────────────────────────────────────────────

/// Central API monitor that holds rules, the DLL filter, and an active session.
#[derive(Debug)]
pub struct ApiMonitor {
    rules: Vec<ApiHookRule>,
    next_rule_id: u64,
    dll_filter: DllFilter,
    session: ApiMonitorSession,
    arch: WinArch,
}

impl ApiMonitor {
    /// Create a new monitor for the given architecture.
    #[must_use]
    pub fn new(arch: WinArch) -> Self {
        Self {
            rules: Vec::new(),
            next_rule_id: 0,
            dll_filter: DllFilter::All,
            session: ApiMonitorSession::new(),
            arch,
        }
    }

    /// Set the DLL filter.
    pub fn set_filter(&mut self, filter: DllFilter) {
        self.dll_filter = filter;
    }

    /// Add a hook rule.  Returns the assigned rule ID.
    pub fn add_rule(
        &mut self,
        dll: impl Into<String>,
        function: impl Into<String>,
        hook_point: HookPoint,
    ) -> u64 {
        let id = self.next_rule_id;
        self.next_rule_id += 1;
        self.rules
            .push(ApiHookRule::new(id, dll, function, hook_point));
        id
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < before
    }

    /// Enable or disable a rule.
    pub fn set_rule_enabled(&mut self, id: u64, enabled: bool) {
        for r in &mut self.rules {
            if r.id == id {
                r.enabled = enabled;
            }
        }
    }

    /// Process an incoming API call and return whether it should be blocked.
    pub fn on_call(
        &mut self,
        dll: &str,
        function: &str,
        args: Vec<u64>,
        tid: u32,
        timestamp_ns: u64,
    ) -> (u64, bool) {
        if !self.dll_filter.allows(dll) {
            let seq = self
                .session
                .record_call(dll, function, args, tid, timestamp_ns, false);
            return (seq, false);
        }
        let blocked = self
            .rules
            .iter()
            .any(|r| r.enabled && r.block && r.matches(dll, function));
        let seq = self
            .session
            .record_call(dll, function, args, tid, timestamp_ns, blocked);
        (seq, blocked)
    }

    /// Notify completion of a call.
    pub fn on_return(&mut self, seq: u64, retval: u64, elapsed_ns: u64) -> bool {
        self.session.complete_call(seq, retval, elapsed_ns)
    }

    /// Return all call records.
    #[must_use]
    pub fn records(&self) -> &[ApiCallRecord] {
        self.session.records()
    }

    /// Number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Reference to the active session.
    #[must_use]
    pub const fn session(&self) -> &ApiMonitorSession {
        &self.session
    }

    /// Architecture.
    #[must_use]
    pub const fn arch(&self) -> WinArch {
        self.arch
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinArch;

    // --- HookPoint ---

    #[test]
    fn hook_point_display() {
        assert_eq!(HookPoint::Iat.to_string(), "IAT");
        assert_eq!(HookPoint::Inline.to_string(), "Inline");
        assert_eq!(HookPoint::Eat.to_string(), "EAT");
    }

    #[test]
    fn hook_point_eq() {
        assert_eq!(HookPoint::Iat, HookPoint::Iat);
        assert_ne!(HookPoint::Iat, HookPoint::Inline);
    }

    // --- DllFilter ---

    #[test]
    fn dll_filter_all_allows_any() {
        assert!(DllFilter::All.allows("ntdll.dll"));
        assert!(DllFilter::All.allows("kernel32.dll"));
    }

    #[test]
    fn dll_filter_include() {
        let f = DllFilter::include(["ntdll.dll"]);
        assert!(f.allows("ntdll.dll"));
        assert!(f.allows("NTDLL.DLL")); // case-insensitive
        assert!(!f.allows("kernel32.dll"));
    }

    #[test]
    fn dll_filter_exclude() {
        let f = DllFilter::exclude(["ntdll.dll"]);
        assert!(!f.allows("ntdll.dll"));
        assert!(f.allows("kernel32.dll"));
    }

    #[test]
    fn dll_filter_case_insensitive() {
        let f = DllFilter::include(["NTDLL.DLL"]);
        assert!(f.allows("ntdll.dll"));
    }

    // --- ApiCallRecord ---

    #[test]
    fn api_call_record_complete() {
        let mut rec = ApiCallRecord::new(0, "ntdll.dll", "NtCreateFile", vec![1, 2], 1, 100);
        assert!(rec.return_value.is_none());
        rec.complete(0xC000_0022, 1500);
        assert_eq!(rec.return_value, Some(0xC000_0022));
        assert_eq!(rec.elapsed_ns, Some(1500));
    }

    #[test]
    fn api_call_record_blocked_flag() {
        let mut rec = ApiCallRecord::new(0, "x", "f", vec![], 1, 0);
        rec.blocked = true;
        assert!(rec.blocked);
    }

    // --- ApiHookRule ---

    #[test]
    fn api_hook_rule_matches_case_insensitive_dll() {
        let rule = ApiHookRule::new(0, "ntdll.dll", "NtCreateFile", HookPoint::Iat);
        assert!(rule.matches("NTDLL.DLL", "NtCreateFile"));
        assert!(!rule.matches("ntdll.dll", "NtOpenFile"));
    }

    #[test]
    fn api_hook_rule_enabled_by_default() {
        let rule = ApiHookRule::new(0, "x", "y", HookPoint::Inline);
        assert!(rule.enabled);
    }

    // --- ApiMonitorSession ---

    #[test]
    fn session_record_call_increments_seq() {
        let mut s = ApiMonitorSession::new();
        let a = s.record_call("ntdll.dll", "NtReadFile", vec![], 1, 0, false);
        let b = s.record_call("ntdll.dll", "NtWriteFile", vec![], 1, 1, false);
        assert_eq!(b, a + 1);
    }

    #[test]
    fn session_complete_call() {
        let mut s = ApiMonitorSession::new();
        let seq = s.record_call("ntdll", "NtReadFile", vec![], 1, 0, false);
        assert!(s.complete_call(seq, 0, 200));
        let rec = s.records().first().unwrap();
        assert_eq!(rec.return_value, Some(0));
    }

    #[test]
    fn session_complete_unknown_seq_returns_false() {
        let mut s = ApiMonitorSession::new();
        assert!(!s.complete_call(999, 0, 0));
    }

    #[test]
    fn session_by_function() {
        let mut s = ApiMonitorSession::new();
        s.record_call("ntdll", "NtReadFile", vec![], 1, 0, false);
        s.record_call("ntdll", "NtWriteFile", vec![], 1, 0, false);
        s.record_call("ntdll", "NtReadFile", vec![], 1, 0, false);
        assert_eq!(s.by_function("NtReadFile").len(), 2);
    }

    #[test]
    fn session_blocked_calls() {
        let mut s = ApiMonitorSession::new();
        s.record_call("ntdll", "NtReadFile", vec![], 1, 0, true);
        s.record_call("ntdll", "NtWriteFile", vec![], 1, 0, false);
        assert_eq!(s.blocked_calls().len(), 1);
    }

    #[test]
    fn session_count_for() {
        let mut s = ApiMonitorSession::new();
        for _ in 0..4 {
            s.record_call("ntdll", "NtReadFile", vec![], 1, 0, false);
        }
        assert_eq!(s.count_for("NtReadFile"), 4);
        assert_eq!(s.count_for("NtWriteFile"), 0);
    }

    // --- ApiMonitor ---

    #[test]
    fn monitor_add_remove_rule() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        let id = mon.add_rule("ntdll.dll", "NtCreateFile", HookPoint::Iat);
        assert_eq!(mon.rule_count(), 1);
        assert!(mon.remove_rule(id));
        assert_eq!(mon.rule_count(), 0);
    }

    #[test]
    fn monitor_on_call_no_block() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        mon.add_rule("ntdll.dll", "NtReadFile", HookPoint::Iat);
        let (_, blocked) = mon.on_call("ntdll.dll", "NtReadFile", vec![1], 1, 0);
        assert!(!blocked);
    }

    #[test]
    fn monitor_on_call_block_rule() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        let id = mon.add_rule("ntdll.dll", "NtCreateFile", HookPoint::Inline);
        for r in &mut mon.rules {
            if r.id == id {
                r.block = true;
            }
        }
        let (_, blocked) = mon.on_call("ntdll.dll", "NtCreateFile", vec![], 1, 0);
        assert!(blocked);
    }

    #[test]
    fn monitor_dll_filter_skips_excluded() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        mon.set_filter(DllFilter::exclude(["blocked.dll"]));
        mon.add_rule("blocked.dll", "Func", HookPoint::Iat);
        // Rule has block=false, but DLL is excluded from filter — still recorded
        let (seq, _blocked) = mon.on_call("blocked.dll", "Func", vec![], 1, 0);
        // should still be in records (just bypasses rule evaluation)
        assert_eq!(mon.records().len(), 1);
        assert_eq!(seq, 0);
    }

    #[test]
    fn monitor_on_return_completes_record() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        mon.add_rule("ntdll", "NtReadFile", HookPoint::Iat);
        let (seq, _) = mon.on_call("ntdll", "NtReadFile", vec![], 1, 0);
        assert!(mon.on_return(seq, 0, 300));
        assert_eq!(mon.records()[0].return_value, Some(0));
    }

    #[test]
    fn monitor_arch() {
        let mon = ApiMonitor::new(WinArch::Arm64);
        assert_eq!(mon.arch(), WinArch::Arm64);
    }

    #[test]
    fn monitor_disabled_rule_not_blocking() {
        let mut mon = ApiMonitor::new(WinArch::X64);
        let id = mon.add_rule("ntdll.dll", "NtCreateFile", HookPoint::Inline);
        for r in &mut mon.rules {
            if r.id == id {
                r.block = true;
            }
        }
        mon.set_rule_enabled(id, false);
        let (_, blocked) = mon.on_call("ntdll.dll", "NtCreateFile", vec![], 1, 0);
        assert!(!blocked);
    }
}
