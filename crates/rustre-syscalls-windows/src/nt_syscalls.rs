//! NT syscall number tables and interception model.
//!
//! Provides a per-Windows-version NT syscall service-number (SSN) table,
//! `SysEnter` stub detection, a user-mode hook model, and a call interceptor
//! that can log, block or modify NT calls.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{WinArch, WinVersion};
pub use crate::{WinNtSyscall, WinSyscallError};

// ─── SysEnterPattern ──────────────────────────────────────────────────────────

/// The expected stub bytes for the syscall entry on a given arch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysEnterPattern {
    /// Architecture this pattern applies to.
    pub arch: WinArch,
    /// Windows version this pattern was observed on.
    pub version: WinVersion,
    /// Byte pattern (may contain wildcards represented as `None`).
    pub bytes: Vec<Option<u8>>,
    /// Human-readable description.
    pub description: String,
}

impl SysEnterPattern {
    #[must_use]
    pub fn new(
        arch: WinArch,
        version: WinVersion,
        bytes: Vec<Option<u8>>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            arch,
            version,
            bytes,
            description: description.into(),
        }
    }

    /// Return `true` if `actual` matches this pattern (wildcard bytes always
    /// match).
    #[must_use]
    pub fn matches(&self, actual: &[u8]) -> bool {
        if actual.len() != self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(actual.iter())
            .all(|(p, b)| p.is_none_or(|expected| expected == *b))
    }
}

// ─── NtSyscallEntry ───────────────────────────────────────────────────────────

/// A single entry in an NT syscall table, pairing the function name with its
/// SSN on a specific Windows version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtSyscallEntry {
    /// NT function name (e.g. `"NtCreateFile"`).
    pub name: String,
    /// Service-number for this function on this version.
    pub ssn: u32,
    /// Windows version.
    pub version: WinVersion,
}

impl NtSyscallEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, ssn: u32, version: WinVersion) -> Self {
        Self {
            name: name.into(),
            ssn,
            version,
        }
    }
}

// ─── NtSyscallTable ───────────────────────────────────────────────────────────

/// A complete NT syscall number table for one Windows version and architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtSyscallTable {
    /// Windows version.
    pub version: WinVersion,
    /// Architecture.
    pub arch: WinArch,
    /// Entries indexed by SSN.
    entries_by_ssn: HashMap<u32, NtSyscallEntry>,
    /// Entries indexed by function name.
    entries_by_name: HashMap<String, NtSyscallEntry>,
}

impl NtSyscallTable {
    /// Build an empty table for the given version and arch.
    #[must_use]
    pub fn new(version: WinVersion, arch: WinArch) -> Self {
        Self {
            version,
            arch,
            entries_by_ssn: HashMap::new(),
            entries_by_name: HashMap::new(),
        }
    }

    /// Insert an entry.
    pub fn insert(&mut self, name: impl Into<String>, ssn: u32) {
        let name: String = name.into();
        let entry = NtSyscallEntry::new(name.clone(), ssn, self.version);
        self.entries_by_ssn.insert(ssn, entry.clone());
        self.entries_by_name.insert(name, entry);
    }

    /// Look up by SSN.
    #[must_use]
    pub fn by_ssn(&self, ssn: u32) -> Option<&NtSyscallEntry> {
        self.entries_by_ssn.get(&ssn)
    }

    /// Look up by function name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&NtSyscallEntry> {
        self.entries_by_name.get(name)
    }

    /// Return all entries sorted by SSN.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&NtSyscallEntry> {
        let mut v: Vec<&NtSyscallEntry> = self.entries_by_ssn.values().collect();
        v.sort_by_key(|e| e.ssn);
        v
    }

    /// Number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries_by_ssn.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries_by_ssn.is_empty()
    }

    /// Build a default Windows 10 x64 table with commonly used NT functions.
    #[must_use]
    pub fn win10_x64() -> Self {
        let mut t = Self::new(WinVersion::Windows10, WinArch::X64);
        for (name, ssn) in Self::win10_x64_entries() {
            t.insert(*name, *ssn);
        }
        t
    }

    /// Static table of (name, SSN) pairs for Windows 10 x64 (build 1909).
    #[must_use]
    const fn win10_x64_entries() -> &'static [(&'static str, u32)] {
        &[
            ("NtAccessCheck", 0x00),
            ("NtWorkerFactoryWorkerReady", 0x01),
            ("NtAcceptConnectPort", 0x02),
            ("NtMapUserPhysicalPagesScatter", 0x03),
            ("NtWaitForSingleObject", 0x04),
            ("NtCallbackReturn", 0x05),
            ("NtReadFile", 0x06),
            ("NtDeviceIoControlFile", 0x07),
            ("NtWriteFile", 0x08),
            ("NtRemoveIoCompletion", 0x09),
            ("NtReleaseSemaphore", 0x0a),
            ("NtReplyWaitReceivePort", 0x0b),
            ("NtReplyPort", 0x0c),
            ("NtSetInformationThread", 0x0d),
            ("NtSetEvent", 0x0e),
            ("NtClose", 0x0f),
            ("NtQueryObject", 0x10),
            ("NtQueryInformationFile", 0x11),
            ("NtOpenKey", 0x12),
            ("NtEnumerateValueKey", 0x13),
            ("NtFindAtom", 0x14),
            ("NtQueryDefaultLocale", 0x15),
            ("NtQueryKey", 0x16),
            ("NtQueryValueKey", 0x17),
            ("NtAllocateVirtualMemory", 0x18),
            ("NtQueryInformationProcess", 0x19),
            ("NtWaitForMultipleObjects32", 0x1a),
            ("NtWriteFileGather", 0x1b),
            ("NtSetInformationProcess", 0x1c),
            ("NtCreateKey", 0x1d),
            ("NtFreeVirtualMemory", 0x1e),
            ("NtImpersonateClientOfPort", 0x1f),
            ("NtReleaseMutant", 0x20),
            ("NtQueryInformationToken", 0x21),
            ("NtRequestWaitReplyPort", 0x22),
            ("NtQueryVirtualMemory", 0x23),
            ("NtOpenThreadToken", 0x24),
            ("NtQueryInformationThread", 0x25),
            ("NtOpenProcess", 0x26),
            ("NtSetInformationFile", 0x27),
            ("NtMapViewOfSection", 0x28),
            ("NtAccessCheckAndAuditAlarm", 0x29),
            ("NtUnmapViewOfSection", 0x2a),
            ("NtReplyWaitReceivePortEx", 0x2b),
            ("NtTerminateProcess", 0x2c),
            ("NtSetEventBoostPriority", 0x2d),
            ("NtReadFileScatter", 0x2e),
            ("NtOpenThreadTokenEx", 0x2f),
            ("NtOpenProcessTokenEx", 0x30),
            ("NtQueryPerformanceCounter", 0x31),
            ("NtEnumerateKey", 0x32),
            ("NtOpenFile", 0x33),
            ("NtDelayExecution", 0x34),
            ("NtQueryDirectoryFile", 0x35),
            ("NtQuerySystemInformation", 0x36),
            ("NtOpenSection", 0x37),
            ("NtQueryTimer", 0x38),
            ("NtFsControlFile", 0x39),
            ("NtWriteVirtualMemory", 0x3a),
            ("NtCloseObjectAuditAlarm", 0x3b),
            ("NtDuplicateObject", 0x3c),
            ("NtQueryAttributesFile", 0x3d),
            ("NtClearEvent", 0x3e),
            ("NtReadVirtualMemory", 0x3f),
            ("NtOpenEvent", 0x40),
            ("NtAdjustPrivilegesToken", 0x41),
            ("NtDuplicateToken", 0x42),
            ("NtContinue", 0x43),
            ("NtQueryDefaultUILanguage", 0x44),
            ("NtQueueApcThread", 0x45),
            ("NtYieldExecution", 0x46),
            ("NtAddAtom", 0x47),
            ("NtCreateEvent", 0x48),
            ("NtQueryVolumeInformationFile", 0x49),
            ("NtCreateSection", 0x4a),
            ("NtFlushBuffersFile", 0x4b),
            ("NtApphelpCacheControl", 0x4c),
            ("NtCreateProcessEx", 0x4d),
            ("NtCreateThread", 0x4e),
            ("NtIsProcessInJob", 0x4f),
            ("NtProtectVirtualMemory", 0x50),
            ("NtQuerySectionAttributes", 0x51),
            ("NtOpenObjectAuditAlarm", 0x52),
            ("NtAccessCheckByType", 0x53),
            ("NtCreateSemaphore", 0x54),
            ("NtCreateFile", 0x55),
            ("NtOpenSemaphore", 0x56),
            ("NtCreatePort", 0x57),
            ("NtCreateWaitablePort", 0x58),
            ("NtQuerySystemTime", 0x59),
            ("NtOpenTimer", 0x5a),
            ("NtSetTimer", 0x5b),
            ("NtCancelTimer", 0x5c),
            ("NtSetTimerEx", 0x5d),
            ("NtCreateTimer", 0x5f),
        ]
    }
}

// ─── UserModeHook ─────────────────────────────────────────────────────────────

/// Represents a user-mode hook installed on an NT function stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModeHook {
    /// The NT function name being hooked.
    pub function: String,
    /// The SSN of the function on the current OS version.
    pub ssn: u32,
    /// Address of the original bytes saved for trampoline restoration.
    pub original_bytes: Vec<u8>,
    /// Address of the hook handler.
    pub hook_handler_rva: u64,
    /// Whether the hook is currently active.
    pub active: bool,
}

impl UserModeHook {
    #[must_use]
    pub fn new(
        function: impl Into<String>,
        ssn: u32,
        original_bytes: Vec<u8>,
        hook_handler_rva: u64,
    ) -> Self {
        Self {
            function: function.into(),
            ssn,
            original_bytes,
            hook_handler_rva,
            active: true,
        }
    }
}

// ─── NtCallRecord ─────────────────────────────────────────────────────────────

/// A recorded NT call event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtCallRecord {
    /// Sequence number.
    pub seq: u64,
    /// Function name.
    pub name: String,
    /// SSN.
    pub ssn: u32,
    /// Raw argument values.
    pub args: Vec<u64>,
    /// Return value (NTSTATUS), available after the call completes.
    pub ntstatus: Option<u32>,
    /// Whether the call was intercepted and blocked.
    pub blocked: bool,
    /// Thread ID.
    pub tid: u32,
    /// Timestamp nanoseconds.
    pub timestamp_ns: u64,
}

impl NtCallRecord {
    #[must_use]
    pub fn new(
        seq: u64,
        name: impl Into<String>,
        ssn: u32,
        args: Vec<u64>,
        tid: u32,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            seq,
            name: name.into(),
            ssn,
            args,
            ntstatus: None,
            blocked: false,
            tid,
            timestamp_ns,
        }
    }

    /// Return `true` if the NTSTATUS indicates success (high bit clear).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.ntstatus.is_some_and(|s| s >> 31 == 0)
    }
}

// ─── NtCallInterceptor ────────────────────────────────────────────────────────

/// Intercepts NT calls by SSN, logging and optionally blocking them.
#[derive(Debug, Default)]
pub struct NtCallInterceptor {
    /// Blocked SSNs.
    blocked_ssns: HashSet<u32>,
    /// All recorded calls.
    records: Vec<NtCallRecord>,
    next_seq: u64,
    /// Hook table reference (names).
    table: Option<NtSyscallTable>,
}

impl NtCallInterceptor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an NT syscall table for name resolution.
    pub fn set_table(&mut self, table: NtSyscallTable) {
        self.table = Some(table);
    }

    /// Block calls to the given SSN.
    pub fn block_ssn(&mut self, ssn: u32) {
        self.blocked_ssns.insert(ssn);
    }

    /// Unblock calls to the given SSN.
    pub fn unblock_ssn(&mut self, ssn: u32) {
        self.blocked_ssns.remove(&ssn);
    }

    /// Process an NT call.  Returns `(seq, blocked)`.
    pub fn on_call(&mut self, ssn: u32, args: Vec<u64>, tid: u32, ts: u64) -> (u64, bool) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let name = self
            .table
            .as_ref()
            .and_then(|t| t.by_ssn(ssn))
            .map_or_else(|| format!("NtUnknown_{ssn:#010x}"), |e| e.name.clone());
        let blocked = self.blocked_ssns.contains(&ssn);
        let mut rec = NtCallRecord::new(seq, name, ssn, args, tid, ts);
        rec.blocked = blocked;
        self.records.push(rec);
        (seq, blocked)
    }

    /// Complete a pending call.
    pub fn on_return(&mut self, seq: u64, ntstatus: u32) -> bool {
        if let Some(r) = self.records.iter_mut().find(|r| r.seq == seq) {
            r.ntstatus = Some(ntstatus);
            true
        } else {
            false
        }
    }

    /// All records.
    #[must_use]
    pub fn records(&self) -> &[NtCallRecord] {
        &self.records
    }

    /// Count of calls to the given SSN.
    #[must_use]
    pub fn count_ssn(&self, ssn: u32) -> usize {
        self.records.iter().filter(|r| r.ssn == ssn).count()
    }

    /// Count of blocked calls.
    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.records.iter().filter(|r| r.blocked).count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- SysEnterPattern ---

    #[test]
    fn pattern_exact_match() {
        let p = SysEnterPattern::new(
            WinArch::X64,
            WinVersion::Windows10,
            vec![Some(0x4C), Some(0x8B), Some(0xD1), Some(0xB8)],
            "mov r10, rcx",
        );
        assert!(p.matches(&[0x4C, 0x8B, 0xD1, 0xB8]));
    }

    #[test]
    fn pattern_wildcard() {
        let p = SysEnterPattern::new(
            WinArch::X64,
            WinVersion::Windows10,
            vec![Some(0x4C), None, Some(0xD1)],
            "wildcard",
        );
        assert!(p.matches(&[0x4C, 0x99, 0xD1]));
    }

    #[test]
    fn pattern_too_short_fails() {
        let p = SysEnterPattern::new(
            WinArch::X64,
            WinVersion::Windows10,
            vec![Some(0x4C), Some(0x8B)],
            "short",
        );
        assert!(!p.matches(&[0x4C]));
    }

    // --- NtSyscallTable ---

    #[test]
    fn table_insert_lookup_by_ssn() {
        let mut t = NtSyscallTable::new(WinVersion::Windows10, WinArch::X64);
        t.insert("NtCreateFile", 0x55);
        let e = t.by_ssn(0x55).unwrap();
        assert_eq!(e.name, "NtCreateFile");
    }

    #[test]
    fn table_lookup_by_name() {
        let mut t = NtSyscallTable::new(WinVersion::Windows10, WinArch::X64);
        t.insert("NtOpenKey", 0x12);
        assert_eq!(t.by_name("NtOpenKey").unwrap().ssn, 0x12);
    }

    #[test]
    fn table_all_sorted_order() {
        let mut t = NtSyscallTable::new(WinVersion::Windows10, WinArch::X64);
        t.insert("C", 3);
        t.insert("A", 1);
        t.insert("B", 2);
        let sorted = t.all_sorted();
        assert_eq!(sorted[0].ssn, 1);
        assert_eq!(sorted[1].ssn, 2);
        assert_eq!(sorted[2].ssn, 3);
    }

    #[test]
    fn table_win10_x64_not_empty() {
        let t = NtSyscallTable::win10_x64();
        assert!(!t.is_empty());
    }

    #[test]
    fn table_missing_ssn_returns_none() {
        let t = NtSyscallTable::new(WinVersion::Windows10, WinArch::X64);
        assert!(t.by_ssn(999).is_none());
    }

    // --- UserModeHook ---

    #[test]
    fn user_mode_hook_active() {
        let h = UserModeHook::new("NtCreateFile", 0x55, vec![0x4C, 0x8B], 0xDEAD);
        assert!(h.active);
        assert_eq!(h.original_bytes.len(), 2);
    }

    // --- NtCallRecord ---

    #[test]
    fn nt_call_record_success_status() {
        let mut r = NtCallRecord::new(0, "NtOpenKey", 0x12, vec![], 1, 0);
        r.ntstatus = Some(0x0000_0000);
        assert!(r.is_success());
    }

    #[test]
    fn nt_call_record_error_status() {
        let mut r = NtCallRecord::new(0, "NtOpenKey", 0x12, vec![], 1, 0);
        r.ntstatus = Some(0xC000_0034); // STATUS_OBJECT_NAME_NOT_FOUND
        assert!(!r.is_success());
    }

    #[test]
    fn nt_call_record_no_status_not_success() {
        let r = NtCallRecord::new(0, "NtOpenKey", 0x12, vec![], 1, 0);
        assert!(!r.is_success());
    }

    // --- NtCallInterceptor ---

    #[test]
    fn interceptor_records_call() {
        let mut ic = NtCallInterceptor::new();
        let (seq, blocked) = ic.on_call(0x0f, vec![], 1, 0);
        assert!(!blocked);
        assert_eq!(ic.records().len(), 1);
        assert_eq!(ic.records()[0].seq, seq);
    }

    #[test]
    fn interceptor_block_ssn() {
        let mut ic = NtCallInterceptor::new();
        ic.block_ssn(0x0f);
        let (_, blocked) = ic.on_call(0x0f, vec![], 1, 0);
        assert!(blocked);
        assert_eq!(ic.blocked_count(), 1);
    }

    #[test]
    fn interceptor_unblock_ssn() {
        let mut ic = NtCallInterceptor::new();
        ic.block_ssn(0x0f);
        ic.unblock_ssn(0x0f);
        let (_, blocked) = ic.on_call(0x0f, vec![], 1, 0);
        assert!(!blocked);
    }

    #[test]
    fn interceptor_on_return_completes() {
        let mut ic = NtCallInterceptor::new();
        let (seq, _) = ic.on_call(0x0f, vec![], 1, 0);
        assert!(ic.on_return(seq, 0));
        assert_eq!(ic.records()[0].ntstatus, Some(0));
    }

    #[test]
    fn interceptor_on_return_unknown_seq_false() {
        let mut ic = NtCallInterceptor::new();
        assert!(!ic.on_return(999, 0));
    }

    #[test]
    fn interceptor_with_table_resolves_name() {
        let mut ic = NtCallInterceptor::new();
        let t = NtSyscallTable::win10_x64();
        ic.set_table(t);
        ic.on_call(0x0f, vec![], 1, 0);
        // Should have a resolved name (not the fallback)
        let rec = &ic.records()[0];
        assert!(!rec.name.starts_with("NtUnknown_"));
    }

    #[test]
    fn interceptor_count_ssn() {
        let mut ic = NtCallInterceptor::new();
        for _ in 0..3 {
            ic.on_call(0x06, vec![], 1, 0);
        }
        ic.on_call(0x07, vec![], 1, 0);
        assert_eq!(ic.count_ssn(0x06), 3);
        assert_eq!(ic.count_ssn(0x07), 1);
    }

    #[test]
    fn interceptor_no_duplicate_blocked_ssn() {
        let mut ic = NtCallInterceptor::new();
        ic.block_ssn(5);
        ic.block_ssn(5);
        assert_eq!(ic.blocked_ssns.len(), 1);
    }

    #[test]
    fn nt_syscall_entry_new() {
        let e = NtSyscallEntry::new("NtReadFile", 0x06, WinVersion::Windows10);
        assert_eq!(e.name, "NtReadFile");
        assert_eq!(e.ssn, 0x06);
    }
}
