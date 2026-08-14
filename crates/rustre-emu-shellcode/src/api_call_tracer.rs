//! `api_call_tracer` — Trace Windows API calls during shellcode emulation.
//!
//! Intercepts calls by virtual address, records argument registers and return
//! values, and exposes a filterable log of [`ApiCallEntry`] records.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ApiCallEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single intercepted API call recorded during shellcode emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallEntry {
    /// Virtual address of the call site (instruction that transferred control).
    pub call_site: u64,
    /// Virtual address of the API stub being called.
    pub target_address: u64,
    /// Resolved API name, if known.
    pub api_name: Option<String>,
    /// Argument values at the time of the call.
    /// For x86-64 Windows: [rcx, rdx, r8, r9, stack_arg0, stack_arg1].
    /// For x86-32 Windows: [esp+4, esp+8, esp+12, esp+16].
    pub args: Vec<u64>,
    /// Return value placed in rax/eax after the stub returns.
    pub return_value: u64,
    /// Ordinal index of this call in the overall trace (0-based).
    pub sequence: u32,
    /// Whether this call was part of an import resolution chain.
    pub is_import_resolution: bool,
}

impl ApiCallEntry {
    /// Returns the API name if resolved, otherwise a hex address string.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.api_name
            .clone()
            .unwrap_or_else(|| format!("{:#x}", self.target_address))
    }

    /// Returns `true` if this call matches the given API name (case-insensitive).
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        self.api_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiCallTrace
// ─────────────────────────────────────────────────────────────────────────────

/// Complete ordered trace of API calls intercepted during one emulation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiCallTrace {
    entries: Vec<ApiCallEntry>,
}

impl ApiCallTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the trace.
    pub fn push(&mut self, entry: ApiCallEntry) {
        self.entries.push(entry);
    }

    /// Return a slice of all recorded entries.
    #[must_use]
    pub fn entries(&self) -> &[ApiCallEntry] {
        &self.entries
    }

    /// Number of recorded API calls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no calls were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the first entry whose `api_name` matches `name` (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&ApiCallEntry> {
        self.entries.iter().find(|e| e.matches_name(name))
    }

    /// Return all entries whose `api_name` matches `name` (case-insensitive).
    #[must_use]
    pub fn filter_by_name(&self, name: &str) -> Vec<&ApiCallEntry> {
        self.entries
            .iter()
            .filter(|e| e.matches_name(name))
            .collect()
    }

    /// Return all entries whose `target_address` is in `[lo, hi]`.
    #[must_use]
    pub fn filter_by_address_range(&self, lo: u64, hi: u64) -> Vec<&ApiCallEntry> {
        self.entries
            .iter()
            .filter(|e| e.target_address >= lo && e.target_address <= hi)
            .collect()
    }

    /// Return counts of each unique API name.
    #[must_use]
    pub fn call_frequency(&self) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            let key = e.display_name();
            *freq.entry(key).or_insert(0) += 1;
        }
        freq
    }

    /// Return all entries that belong to a given DLL category.
    ///
    /// `category` is matched against the start of the API name:
    /// - `"kernel32"` matches VirtualAlloc, CreateThread, etc.
    /// - `"ws2_32"` matches socket, connect, send, recv, etc.
    /// - `"wininet"` matches InternetOpen*, HttpSend*, etc.
    #[must_use]
    pub fn filter_by_category(&self, category: &str) -> Vec<&ApiCallEntry> {
        let kernel32_apis = [
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualProtect",
            "VirtualFree",
            "LoadLibraryA",
            "LoadLibraryW",
            "GetProcAddress",
            "CreateThread",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "OpenProcess",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "CreateProcessA",
            "CreateProcessW",
        ];
        let ws2_apis = [
            "socket",
            "connect",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "closesocket",
            "WSAStartup",
            "WSASocketA",
            "WSASocketW",
            "WSAConnect",
            "WSASend",
            "WSARecv",
            "bind",
            "listen",
            "accept",
        ];
        let wininet_apis = [
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpOpenRequestA",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "InternetReadFile",
            "InternetCloseHandle",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
        ];

        let api_list: &[&str] = match category.to_ascii_lowercase().as_str() {
            "kernel32" => &kernel32_apis,
            "ws2_32" | "winsock" => &ws2_apis,
            "wininet" => &wininet_apis,
            _ => return vec![],
        };

        self.entries
            .iter()
            .filter(|e| {
                e.api_name
                    .as_deref()
                    .is_some_and(|n| api_list.iter().any(|a| a.eq_ignore_ascii_case(n)))
            })
            .collect()
    }

    /// Serialise the trace to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Build a human-readable summary of the trace.
    #[must_use]
    pub fn summary(&self) -> String {
        let freq = self.call_frequency();
        let mut lines = vec![format!("API call trace ({} calls):", self.entries.len())];
        let mut sorted: Vec<(&String, &usize)> = freq.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (name, count) in sorted.iter().take(20) {
            lines.push(format!("  {name:<40} x{count}"));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiCallFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Criteria for filtering an [`ApiCallTrace`].
#[derive(Debug, Clone, Default)]
pub struct ApiCallFilter {
    /// Keep only entries whose name matches one of these strings (case-insensitive).
    pub name_allowlist: Vec<String>,
    /// Drop entries whose name matches any of these strings (case-insensitive).
    pub name_blocklist: Vec<String>,
    /// Keep only entries with `target_address >= min_address`.
    pub min_address: Option<u64>,
    /// Keep only entries with `target_address <= max_address`.
    pub max_address: Option<u64>,
    /// Keep only entries where `sequence` is within this range (inclusive).
    pub sequence_range: Option<(u32, u32)>,
    /// Keep only import-resolution calls.
    pub import_resolution_only: bool,
}

impl ApiCallFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an API name to the allowlist.
    pub fn allow_name(&mut self, name: impl Into<String>) {
        self.name_allowlist.push(name.into());
    }

    /// Add an API name to the blocklist.
    pub fn block_name(&mut self, name: impl Into<String>) {
        self.name_blocklist.push(name.into());
    }

    /// Set an address range filter.
    pub fn set_address_range(&mut self, lo: u64, hi: u64) {
        self.min_address = Some(lo);
        self.max_address = Some(hi);
    }

    /// Set a sequence range filter.
    pub fn set_sequence_range(&mut self, start: u32, end: u32) {
        self.sequence_range = Some((start, end));
    }

    /// Apply this filter to a trace, returning the matching entries.
    #[must_use]
    pub fn apply<'a>(&self, trace: &'a ApiCallTrace) -> Vec<&'a ApiCallEntry> {
        trace
            .entries()
            .iter()
            .filter(|e| self.matches(e))
            .collect()
    }

    fn matches(&self, entry: &ApiCallEntry) -> bool {
        // Import-resolution-only check
        if self.import_resolution_only && !entry.is_import_resolution {
            return false;
        }

        // Address range
        if let Some(lo) = self.min_address {
            if entry.target_address < lo {
                return false;
            }
        }
        if let Some(hi) = self.max_address {
            if entry.target_address > hi {
                return false;
            }
        }

        // Sequence range
        if let Some((start, end)) = self.sequence_range {
            if entry.sequence < start || entry.sequence > end {
                return false;
            }
        }

        // Blocklist
        if !self.name_blocklist.is_empty() {
            if let Some(name) = &entry.api_name {
                if self
                    .name_blocklist
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(name))
                {
                    return false;
                }
            }
        }

        // Allowlist (if non-empty, entry must match at least one)
        if !self.name_allowlist.is_empty() {
            let name_ok = entry.api_name.as_deref().is_some_and(|n| {
                self.name_allowlist
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(n))
            });
            if !name_ok {
                return false;
            }
        }

        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiCallTracer
// ─────────────────────────────────────────────────────────────────────────────

/// Maps virtual addresses to API names and accumulates an [`ApiCallTrace`]
/// during shellcode emulation.
///
/// Callers integrate this by calling [`ApiCallTracer::intercept`] from their
/// emulator code-hook for every instruction whose address appears in the
/// address-to-name map.
#[derive(Debug)]
pub struct ApiCallTracer {
    /// Address → (name, default_return_value) mapping.
    stubs: HashMap<u64, (String, u64)>,
    /// Accumulated trace.
    trace: ApiCallTrace,
    /// Next sequence number.
    next_seq: u32,
}

impl ApiCallTracer {
    /// Create a new tracer with an empty stub table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stubs: HashMap::new(),
            trace: ApiCallTrace::new(),
            next_seq: 0,
        }
    }

    /// Register an API stub at `address` with the given `name` and
    /// `default_return` value that will be placed in rax when intercepted.
    pub fn register_stub(&mut self, address: u64, name: impl Into<String>, default_return: u64) {
        self.stubs.insert(address, (name.into(), default_return));
    }

    /// Register many stubs from an iterator of `(address, name, default_return)`.
    pub fn register_stubs(
        &mut self,
        stubs: impl IntoIterator<Item = (u64, String, u64)>,
    ) {
        for (addr, name, ret) in stubs {
            self.stubs.insert(addr, (name, ret));
        }
    }

    /// Check whether `target_address` is a known stub.
    #[must_use]
    pub fn is_stub(&self, target_address: u64) -> bool {
        self.stubs.contains_key(&target_address)
    }

    /// Retrieve the default return value for a stub at `address`, if registered.
    #[must_use]
    pub fn default_return(&self, address: u64) -> Option<u64> {
        self.stubs.get(&address).map(|(_, r)| *r)
    }

    /// Called by the emulator hook when control reaches `target_address`.
    ///
    /// Records an [`ApiCallEntry`] with the supplied `call_site`, `args`, and
    /// `return_value`. If `target_address` is a known stub, the return value
    /// is taken from the stub table unless overridden by `return_value != 0`.
    pub fn intercept(
        &mut self,
        call_site: u64,
        target_address: u64,
        args: Vec<u64>,
        return_value: u64,
    ) {
        let (api_name, stub_ret) = if let Some((name, ret)) = self.stubs.get(&target_address) {
            (Some(name.clone()), *ret)
        } else {
            (None, 0u64)
        };

        let effective_return = if return_value != 0 {
            return_value
        } else {
            stub_ret
        };

        let entry = ApiCallEntry {
            call_site,
            target_address,
            api_name,
            args,
            return_value: effective_return,
            sequence: self.next_seq,
            is_import_resolution: false,
        };
        self.next_seq += 1;
        self.trace.push(entry);
    }

    /// Mark the most recently recorded call as an import-resolution call.
    pub fn mark_last_as_import_resolution(&mut self) {
        if let Some(last) = self.trace.entries.last_mut() {
            last.is_import_resolution = true;
        }
    }

    /// Return a reference to the accumulated trace.
    #[must_use]
    pub fn trace(&self) -> &ApiCallTrace {
        &self.trace
    }

    /// Consume the tracer and return the accumulated trace.
    #[must_use]
    pub fn into_trace(self) -> ApiCallTrace {
        self.trace
    }

    /// Reset the trace but keep the stub table.
    pub fn reset_trace(&mut self) {
        self.trace = ApiCallTrace::new();
        self.next_seq = 0;
    }

    /// Number of registered stubs.
    #[must_use]
    pub fn stub_count(&self) -> usize {
        self.stubs.len()
    }

    /// Return all registered stub addresses.
    #[must_use]
    pub fn stub_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.stubs.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }

    /// Build a default Windows shellcode stub table covering the most common
    /// APIs encountered in malware, pre-populated with typical return values.
    #[must_use]
    pub fn with_windows_defaults() -> Self {
        let mut t = Self::new();
        let stubs: &[(&str, u64, u64)] = &[
            ("VirtualAlloc",       0x7700_1000, 0x0020_0000),
            ("VirtualAllocEx",     0x7700_1010, 0x0020_0000),
            ("VirtualProtect",     0x7700_1020, 1),
            ("VirtualFree",        0x7700_1030, 1),
            ("LoadLibraryA",       0x7700_1040, 0x7700_0000),
            ("LoadLibraryW",       0x7700_1050, 0x7700_0000),
            ("GetProcAddress",     0x7700_1060, 0x7700_2000),
            ("CreateThread",       0x7700_1070, 0x0000_0AAA),
            ("CreateRemoteThread", 0x7700_1080, 0x0000_0BBB),
            ("WriteProcessMemory", 0x7700_1090, 1),
            ("ReadProcessMemory",  0x7700_10A0, 1),
            ("OpenProcess",        0x7700_10B0, 0x0000_0CCC),
            ("WinExec",            0x7700_10C0, 32),
            ("ShellExecuteA",      0x7700_10D0, 42),
            ("ShellExecuteW",      0x7700_10E0, 42),
            ("CreateProcessA",     0x7700_10F0, 1),
            ("CreateProcessW",     0x7700_1100, 1),
            ("ExitProcess",        0x7700_1110, 0),
            ("GetLastError",       0x7700_1120, 0),
            ("SetLastError",       0x7700_1130, 0),
            ("socket",             0x7700_2000, 0x0000_0DDD),
            ("connect",            0x7700_2010, 0),
            ("send",               0x7700_2020, 1),
            ("recv",               0x7700_2030, 1),
            ("WSAStartup",         0x7700_2040, 0),
            ("WSASocketA",         0x7700_2050, 0x0000_0EEE),
            ("closesocket",        0x7700_2060, 0),
            ("InternetOpenA",      0x7700_3000, 0x7700_4000),
            ("InternetConnectA",   0x7700_3010, 0x7700_4010),
            ("HttpSendRequestA",   0x7700_3020, 1),
            ("InternetReadFile",   0x7700_3030, 1),
        ];
        for &(name, addr, ret) in stubs {
            t.register_stub(addr, name, ret);
        }
        t
    }
}

impl Default for ApiCallTracer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiSequencePattern
// ─────────────────────────────────────────────────────────────────────────────

/// A named sequence of API calls that indicates a specific behaviour.
#[derive(Debug, Clone)]
pub struct ApiSequencePattern {
    /// Human-readable name for the pattern.
    pub name: String,
    /// Ordered list of API names that must appear (in any window of consecutive calls).
    pub sequence: Vec<String>,
    /// Brief description of what the pattern represents.
    pub description: String,
}

impl ApiSequencePattern {
    /// Create a new pattern.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        sequence: Vec<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sequence,
            description: description.into(),
        }
    }

    /// Return `true` if the trace contains this pattern as a subsequence.
    ///
    /// The pattern matches if its API names appear in order anywhere in `trace`,
    /// ignoring unrelated calls in between.
    #[must_use]
    pub fn matches(&self, trace: &ApiCallTrace) -> bool {
        if self.sequence.is_empty() {
            return true;
        }
        let mut pattern_idx = 0usize;
        for entry in trace.entries() {
            if let Some(name) = &entry.api_name {
                if name.eq_ignore_ascii_case(&self.sequence[pattern_idx]) {
                    pattern_idx += 1;
                    if pattern_idx == self.sequence.len() {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// A set of [`ApiSequencePattern`]s used to classify shellcode behaviour.
#[derive(Debug, Default)]
pub struct ApiPatternMatcher {
    patterns: Vec<ApiSequencePattern>,
}

impl ApiPatternMatcher {
    /// Create an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern.
    pub fn add_pattern(&mut self, p: ApiSequencePattern) {
        self.patterns.push(p);
    }

    /// Return all patterns that match `trace`.
    #[must_use]
    pub fn matched_patterns<'a>(&'a self, trace: &ApiCallTrace) -> Vec<&'a ApiSequencePattern> {
        self.patterns.iter().filter(|p| p.matches(trace)).collect()
    }

    /// Build a matcher pre-loaded with common shellcode behaviour patterns.
    #[must_use]
    pub fn with_common_patterns() -> Self {
        let mut m = Self::new();

        m.add_pattern(ApiSequencePattern::new(
            "process_injection",
            vec![
                "OpenProcess".to_string(),
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
                "CreateRemoteThread".to_string(),
            ],
            "Classic remote process injection (OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)",
        ));

        m.add_pattern(ApiSequencePattern::new(
            "download_and_exec",
            vec![
                "InternetOpenA".to_string(),
                "InternetConnectA".to_string(),
                "HttpSendRequestA".to_string(),
                "WinExec".to_string(),
            ],
            "WinINet download-and-execute",
        ));

        m.add_pattern(ApiSequencePattern::new(
            "reverse_shell",
            vec![
                "WSAStartup".to_string(),
                "WSASocketA".to_string(),
                "connect".to_string(),
            ],
            "Reverse shell using Winsock",
        ));

        m.add_pattern(ApiSequencePattern::new(
            "reflective_load",
            vec![
                "VirtualAlloc".to_string(),
                "WriteProcessMemory".to_string(),
                "CreateThread".to_string(),
            ],
            "Reflective DLL loading pattern",
        ));

        m.add_pattern(ApiSequencePattern::new(
            "api_resolution",
            vec![
                "LoadLibraryA".to_string(),
                "GetProcAddress".to_string(),
            ],
            "Dynamic API resolution via LoadLibrary + GetProcAddress",
        ));

        m
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, seq: u32) -> ApiCallEntry {
        ApiCallEntry {
            call_site: 0x1000,
            target_address: 0x7000,
            api_name: Some(name.to_string()),
            args: vec![1, 2, 3],
            return_value: 0,
            sequence: seq,
            is_import_resolution: false,
        }
    }

    #[test]
    fn test_trace_push_and_len() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("CreateThread", 1));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn test_trace_find_by_name() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("CreateThread", 1));
        assert!(t.find_by_name("VirtualAlloc").is_some());
        assert!(t.find_by_name("Missing").is_none());
    }

    #[test]
    fn test_trace_filter_by_name_case_insensitive() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("virtualalloc", 1));
        assert_eq!(t.filter_by_name("VIRTUALALLOC").len(), 2);
    }

    #[test]
    fn test_trace_call_frequency() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("VirtualAlloc", 1));
        t.push(make_entry("CreateThread", 2));
        let freq = t.call_frequency();
        assert_eq!(freq["VirtualAlloc"], 2);
        assert_eq!(freq["CreateThread"], 1);
    }

    #[test]
    fn test_trace_filter_by_address_range() {
        let mut t = ApiCallTrace::new();
        let mut e = make_entry("A", 0);
        e.target_address = 0x1000;
        t.push(e);
        let mut e2 = make_entry("B", 1);
        e2.target_address = 0x9000;
        t.push(e2);
        let filtered = t.filter_by_address_range(0x0000, 0x5000);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches_name("A"));
    }

    #[test]
    fn test_filter_allowlist() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("CreateThread", 1));
        t.push(make_entry("socket", 2));
        let mut f = ApiCallFilter::new();
        f.allow_name("VirtualAlloc");
        f.allow_name("socket");
        let result = f.apply(&t);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_blocklist() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("CreateThread", 1));
        let mut f = ApiCallFilter::new();
        f.block_name("CreateThread");
        let result = f.apply(&t);
        assert_eq!(result.len(), 1);
        assert!(result[0].matches_name("VirtualAlloc"));
    }

    #[test]
    fn test_filter_sequence_range() {
        let mut t = ApiCallTrace::new();
        for i in 0..5u32 {
            t.push(make_entry("X", i));
        }
        let mut f = ApiCallFilter::new();
        f.set_sequence_range(1, 3);
        let result = f.apply(&t);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].sequence, 1);
        assert_eq!(result[2].sequence, 3);
    }

    #[test]
    fn test_tracer_intercept() {
        let mut tracer = ApiCallTracer::new();
        tracer.register_stub(0x7000, "VirtualAlloc", 0x2000_0000);
        tracer.intercept(0x1000, 0x7000, vec![0x1000, 0x40, 4, 0], 0);
        assert_eq!(tracer.trace().len(), 1);
        let entry = &tracer.trace().entries()[0];
        assert!(entry.matches_name("VirtualAlloc"));
        assert_eq!(entry.return_value, 0x2000_0000);
    }

    #[test]
    fn test_tracer_reset_trace() {
        let mut tracer = ApiCallTracer::new();
        tracer.register_stub(0x7000, "VirtualAlloc", 0);
        tracer.intercept(0x1000, 0x7000, vec![], 0);
        assert_eq!(tracer.trace().len(), 1);
        tracer.reset_trace();
        assert_eq!(tracer.trace().len(), 0);
        assert_eq!(tracer.stub_count(), 1); // stubs preserved
    }

    #[test]
    fn test_windows_defaults() {
        let t = ApiCallTracer::with_windows_defaults();
        assert!(t.stub_count() >= 20);
        assert!(t.is_stub(0x7700_1000));
        assert!(t.is_stub(0x7700_2000));
    }

    #[test]
    fn test_pattern_matcher_process_injection() {
        let mut trace = ApiCallTrace::new();
        trace.push(make_entry("OpenProcess", 0));
        trace.push(make_entry("VirtualAllocEx", 1));
        trace.push(make_entry("WriteProcessMemory", 2));
        trace.push(make_entry("CreateRemoteThread", 3));
        let m = ApiPatternMatcher::with_common_patterns();
        let matched = m.matched_patterns(&trace);
        let names: Vec<&str> = matched.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"process_injection"));
    }

    #[test]
    fn test_pattern_matcher_reverse_shell() {
        let mut trace = ApiCallTrace::new();
        trace.push(make_entry("WSAStartup", 0));
        trace.push(make_entry("WSASocketA", 1));
        trace.push(make_entry("connect", 2));
        let m = ApiPatternMatcher::with_common_patterns();
        let matched = m.matched_patterns(&trace);
        let names: Vec<&str> = matched.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"reverse_shell"));
    }

    #[test]
    fn test_pattern_no_match() {
        let trace = ApiCallTrace::new();
        let m = ApiPatternMatcher::with_common_patterns();
        let matched = m.matched_patterns(&trace);
        assert!(matched.is_empty());
    }

    #[test]
    fn test_trace_category_filter_kernel32() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        t.push(make_entry("socket", 1));
        let result = t.filter_by_category("kernel32");
        assert_eq!(result.len(), 1);
        assert!(result[0].matches_name("VirtualAlloc"));
    }

    #[test]
    fn test_trace_is_empty() {
        let t = ApiCallTrace::new();
        assert!(t.is_empty());
    }

    #[test]
    fn test_entry_display_name_resolved() {
        let e = make_entry("VirtualAlloc", 0);
        assert_eq!(e.display_name(), "VirtualAlloc");
    }

    #[test]
    fn test_entry_display_name_unresolved() {
        let e = ApiCallEntry {
            call_site: 0x1000,
            target_address: 0xDEAD,
            api_name: None,
            args: vec![],
            return_value: 0,
            sequence: 0,
            is_import_resolution: false,
        };
        assert!(e.display_name().starts_with("0x"));
    }

    #[test]
    fn test_trace_to_json() {
        let mut t = ApiCallTrace::new();
        t.push(make_entry("VirtualAlloc", 0));
        let json = t.to_json().unwrap();
        assert!(json.contains("VirtualAlloc"));
    }

    #[test]
    fn test_tracer_mark_import_resolution() {
        let mut tracer = ApiCallTracer::new();
        tracer.register_stub(0x7000, "GetProcAddress", 0x1000);
        tracer.intercept(0x2000, 0x7000, vec![], 0);
        tracer.mark_last_as_import_resolution();
        assert!(tracer.trace().entries()[0].is_import_resolution);
    }

    #[test]
    fn test_stub_addresses_sorted() {
        let mut tracer = ApiCallTracer::new();
        tracer.register_stub(0x3000, "C", 0);
        tracer.register_stub(0x1000, "A", 0);
        tracer.register_stub(0x2000, "B", 0);
        let addrs = tracer.stub_addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }
}
