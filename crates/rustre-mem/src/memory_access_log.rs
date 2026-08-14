//! Memory access logging and replay.
//!
//! Provides [`MemoryAccessLog`], [`AccessEntry`], [`AccessKind`],
//! [`log_access()`], and [`replay_accesses()`] for recording every read and
//! write performed on a memory provider and replaying them against an arbitrary
//! target.
//!
//! # Distinction from `access_log`
//!
//! This module is a *standalone* log that callers fill manually (or via the
//! free functions [`log_access`] / [`replay_accesses`]).  It carries richer
//! access metadata: execute fetches, permission checks, timestamps, thread IDs,
//! and string tags.
//!
//! [`crate::access_log`] is a *provider wrapper* (`LoggingMemoryProvider`)
//! that intercepts every `MemoryProvider::read` / `write` call automatically.
//! Its `AccessKind` is a simple `Read | Write` enum; this module's `AccessKind`
//! additionally tracks `Execute` and `PermCheck` variants.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustre_core::address::Address;
use rustre_core::permissions::Permissions;

// ─────────────────────────────────────────────────────────────────────────────
// AccessKind
// ─────────────────────────────────────────────────────────────────────────────

/// The type of memory access that was observed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccessKind {
    /// A read of `size` bytes starting at an address.
    Read { size: usize },
    /// A write of `size` bytes starting at an address.
    Write { size: usize },
    /// An execute fetch (instruction fetch).
    Execute,
    /// A permission query (checking whether access is allowed).
    PermCheck { requested: Permissions },
}

impl AccessKind {
    #[must_use] 
    pub const fn is_read(&self) -> bool {
        matches!(self, Self::Read { .. })
    }

    #[must_use] 
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Write { .. })
    }

    #[must_use] 
    pub const fn is_execute(&self) -> bool {
        matches!(self, Self::Execute)
    }

    #[must_use] 
    pub const fn size(&self) -> usize {
        match self {
            Self::Read { size } | Self::Write { size } => *size,
            Self::Execute => 0,
            Self::PermCheck { .. } => 0,
        }
    }
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { size } => write!(f, "R{size}"),
            Self::Write { size } => write!(f, "W{size}"),
            Self::Execute => write!(f, "X"),
            Self::PermCheck { requested } => write!(f, "PCHECK({requested:?})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessResult
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the access succeeded or was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessResult {
    Success,
    Denied(String),
    Fault(String),
}

impl fmt::Display for AccessResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "ok"),
            Self::Denied(msg) => write!(f, "denied: {msg}"),
            Self::Fault(msg) => write!(f, "fault: {msg}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single logged memory access.
#[derive(Debug, Clone)]
pub struct AccessEntry {
    /// Sequence number (monotonically increasing).
    pub sequence: u64,
    /// Virtual address of the access.
    pub address: Address,
    /// Kind and size of the access.
    pub kind: AccessKind,
    /// Whether the access succeeded.
    pub result: AccessResult,
    /// Bytes that were read or written (empty for execute / perm-check).
    pub data: Vec<u8>,
    /// Optional identifier of the thread or CPU that performed the access.
    pub tid: Option<u32>,
    /// Timestamp in microseconds since the Unix epoch.
    pub timestamp_us: u64,
    /// Optional tag for grouping related accesses (e.g. a function name).
    pub tag: Option<String>,
}

impl AccessEntry {
    #[must_use] 
    pub fn new(
        sequence: u64,
        address: Address,
        kind: AccessKind,
        result: AccessResult,
    ) -> Self {
        let us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_micros() as u64;
        Self {
            sequence,
            address,
            kind,
            result,
            data: Vec::new(),
            tid: None,
            timestamp_us: us,
            tag: None,
        }
    }

    #[must_use] 
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    #[must_use] 
    pub const fn with_tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    #[must_use] 
    pub fn is_successful(&self) -> bool {
        self.result == AccessResult::Success
    }

    /// One-line human-readable description.
    #[must_use] 
    pub fn format_line(&self) -> String {
        format!(
            "#{} {} @ {:#x} [{}] {}",
            self.sequence,
            self.kind,
            self.address.0,
            self.result,
            if self.data.is_empty() {
                String::new()
            } else {
                format!("data={:?}", &self.data[..self.data.len().min(8)])
            }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LogFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Optional filter applied when querying the log.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub address_range: Option<(Address, Address)>,
    pub kind_reads: bool,
    pub kind_writes: bool,
    pub kind_executes: bool,
    pub only_failures: bool,
    pub tag: Option<String>,
}

impl LogFilter {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            kind_reads: true,
            kind_writes: true,
            kind_executes: true,
            ..Default::default()
        }
    }

    #[must_use] 
    pub fn reads_only() -> Self {
        Self { kind_reads: true, ..Default::default() }
    }

    #[must_use] 
    pub fn writes_only() -> Self {
        Self { kind_writes: true, ..Default::default() }
    }

    #[must_use] 
    pub const fn in_range(mut self, start: Address, end: Address) -> Self {
        self.address_range = Some((start, end));
        self
    }

    #[must_use] 
    pub const fn failures_only(mut self) -> Self {
        self.only_failures = true;
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    #[must_use] 
    pub fn matches(&self, entry: &AccessEntry) -> bool {
        // Kind filter.
        let kind_ok = match &entry.kind {
            AccessKind::Read { .. } => self.kind_reads,
            AccessKind::Write { .. } => self.kind_writes,
            AccessKind::Execute => self.kind_executes,
            AccessKind::PermCheck { .. } => true,
        };
        if !kind_ok {
            return false;
        }

        // Address range.
        if let Some((start, end)) = self.address_range
            && (entry.address.0 < start.0 || entry.address.0 >= end.0) {
                return false;
            }

        // Failure filter.
        if self.only_failures && entry.is_successful() {
            return false;
        }

        // Tag filter.
        if let Some(ref tag) = self.tag
            && entry.tag.as_deref() != Some(tag.as_str()) {
                return false;
            }

        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryAccessLog
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-local memory access logger with bounded capacity.
///
/// When the log reaches `capacity` entries, the oldest entry is evicted
/// (ring-buffer behaviour).
#[derive(Debug)]
pub struct MemoryAccessLog {
    entries: VecDeque<AccessEntry>,
    capacity: usize,
    sequence: u64,
    total_reads: u64,
    total_writes: u64,
    total_executes: u64,
    total_failures: u64,
}

impl MemoryAccessLog {
    /// Create a new log with the given capacity (maximum number of retained
    /// entries).
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            sequence: 0,
            total_reads: 0,
            total_writes: 0,
            total_executes: 0,
            total_failures: 0,
        }
    }

    /// Create a log with a default capacity of 65 536 entries.
    #[must_use] 
    pub fn default_capacity() -> Self {
        Self::new(65_536)
    }

    // ── Logging ────────────────────────────────────────────────────────────

    /// Record a memory access; returns the assigned sequence number.
    pub fn log_access(
        &mut self,
        address: Address,
        kind: AccessKind,
        result: AccessResult,
        data: Vec<u8>,
    ) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;

        match &kind {
            AccessKind::Read { .. } => self.total_reads += 1,
            AccessKind::Write { .. } => self.total_writes += 1,
            AccessKind::Execute => self.total_executes += 1,
            AccessKind::PermCheck { .. } => {}
        }
        if result != AccessResult::Success {
            self.total_failures += 1;
        }

        let entry = AccessEntry::new(seq, address, kind, result).with_data(data);

        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        seq
    }

    /// Convenience: log a successful read.
    pub fn log_read(&mut self, address: Address, data: Vec<u8>) -> u64 {
        let size = data.len();
        self.log_access(address, AccessKind::Read { size }, AccessResult::Success, data)
    }

    /// Convenience: log a successful write.
    pub fn log_write(&mut self, address: Address, data: Vec<u8>) -> u64 {
        let size = data.len();
        self.log_access(address, AccessKind::Write { size }, AccessResult::Success, data)
    }

    /// Convenience: log a failed access.
    pub fn log_failure(
        &mut self,
        address: Address,
        kind: AccessKind,
        reason: impl Into<String>,
    ) -> u64 {
        self.log_access(address, kind, AccessResult::Fault(reason.into()), Vec::new())
    }

    // ── Query ──────────────────────────────────────────────────────────────

    /// All entries in chronological order.
    #[must_use] 
    pub fn entries(&self) -> Vec<&AccessEntry> {
        self.entries.iter().collect()
    }

    /// Number of entries currently in the log.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries matching `filter` in chronological order.
    #[must_use] 
    pub fn query(&self, filter: &LogFilter) -> Vec<&AccessEntry> {
        self.entries.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Entries touching `address` (any access kind).
    #[must_use] 
    pub fn accesses_at(&self, address: Address) -> Vec<&AccessEntry> {
        self.entries.iter().filter(|e| e.address == address).collect()
    }

    /// The `n` most recent entries.
    #[must_use] 
    pub fn tail(&self, n: usize) -> Vec<&AccessEntry> {
        let start = self.entries.len().saturating_sub(n);
        self.entries.range(start..).collect()
    }

    // ── Statistics ─────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn total_reads(&self) -> u64 {
        self.total_reads
    }

    #[must_use] 
    pub const fn total_writes(&self) -> u64 {
        self.total_writes
    }

    #[must_use] 
    pub const fn total_executes(&self) -> u64 {
        self.total_executes
    }

    #[must_use] 
    pub const fn total_failures(&self) -> u64 {
        self.total_failures
    }

    #[must_use] 
    pub const fn next_sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use] 
    pub fn stats_summary(&self) -> String {
        format!(
            "log: {} entries ({} reads, {} writes, {} executes, {} failures)",
            self.entries.len(),
            self.total_reads,
            self.total_writes,
            self.total_executes,
            self.total_failures,
        )
    }

    // ── Mutation ───────────────────────────────────────────────────────────

    /// Remove all log entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Trim entries older than `keep_count` from the front of the log.
    pub fn trim_oldest(&mut self, keep_count: usize) {
        while self.entries.len() > keep_count {
            self.entries.pop_front();
        }
    }

    /// Export all entries as a `Vec<AccessEntry>` (cloned).
    #[must_use] 
    pub fn export(&self) -> Vec<AccessEntry> {
        self.entries.iter().cloned().collect()
    }
}

impl Default for MemoryAccessLog {
    fn default() -> Self {
        Self::default_capacity()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Log a memory access to `log`.
pub fn log_access(
    log: &mut MemoryAccessLog,
    address: Address,
    kind: AccessKind,
    result: AccessResult,
    data: Vec<u8>,
) -> u64 {
    log.log_access(address, kind, result, data)
}

/// Replay all entries from `log` to `target`, applying writes and skipping
/// reads.  Returns the number of entries replayed.
///
/// `target` is a callback that receives `(address, data_to_write)` for each
/// write entry.  On error the replay continues (errors are counted).
pub fn replay_accesses<F>(log: &MemoryAccessLog, mut target: F) -> ReplayStats
where
    F: FnMut(Address, &[u8]) -> Result<(), String>,
{
    let mut stats = ReplayStats::default();
    for entry in &log.entries {
        stats.total += 1;
        if entry.kind.is_write() && entry.is_successful() {
            match target(entry.address, &entry.data) {
                Ok(()) => stats.applied += 1,
                Err(msg) => {
                    stats.errors += 1;
                    stats.error_messages.push(msg);
                }
            }
        } else {
            stats.skipped += 1;
        }
    }
    stats
}

/// Statistics returned by [`replay_accesses`].
#[derive(Debug, Default)]
pub struct ReplayStats {
    pub total: u64,
    pub applied: u64,
    pub skipped: u64,
    pub errors: u64,
    pub error_messages: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn log_reads_and_writes() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x1000), vec![0xAA; 4]);
        log.log_write(addr(0x1004), vec![0xBB; 4]);
        assert_eq!(log.len(), 2);
        assert_eq!(log.total_reads(), 1);
        assert_eq!(log.total_writes(), 1);
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut log = MemoryAccessLog::new(4);
        for i in 0..6u64 {
            log.log_read(addr(i * 4), vec![0u8; 4]);
        }
        assert_eq!(log.len(), 4);
        // The oldest 2 entries should have been evicted.
        assert_eq!(log.entries()[0].address, addr(8));
    }

    #[test]
    fn query_reads_only() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x100), vec![1, 2]);
        log.log_write(addr(0x200), vec![3, 4]);
        let filter = LogFilter::reads_only();
        let results = log.query(&filter);
        assert_eq!(results.len(), 1);
        assert!(results[0].kind.is_read());
    }

    #[test]
    fn query_writes_only() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x100), vec![]);
        log.log_write(addr(0x200), vec![0xAB]);
        let filter = LogFilter::writes_only();
        let results = log.query(&filter);
        assert_eq!(results.len(), 1);
        assert!(results[0].kind.is_write());
    }

    #[test]
    fn query_in_range() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x1000), vec![]);
        log.log_read(addr(0x2000), vec![]);
        log.log_read(addr(0x3000), vec![]);
        let filter = LogFilter::new().in_range(addr(0x1500), addr(0x2500));
        let results = log.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, addr(0x2000));
    }

    #[test]
    fn log_failure_increments_counter() {
        let mut log = MemoryAccessLog::new(16);
        log.log_failure(addr(0xDEAD), AccessKind::Read { size: 4 }, "not mapped");
        assert_eq!(log.total_failures(), 1);
        let failures = log.query(&LogFilter::new().failures_only());
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn accesses_at() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x100), vec![]);
        log.log_write(addr(0x100), vec![0xFF]);
        log.log_read(addr(0x200), vec![]);
        let hits = log.accesses_at(addr(0x100));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn tail_returns_last_n() {
        let mut log = MemoryAccessLog::new(100);
        for i in 0..10u64 {
            log.log_read(addr(i * 4), vec![]);
        }
        let tail = log.tail(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].address, addr(28));
    }

    #[test]
    fn trim_oldest_reduces_size() {
        let mut log = MemoryAccessLog::new(100);
        for i in 0..10u64 {
            log.log_read(addr(i), vec![]);
        }
        log.trim_oldest(4);
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn replay_applies_writes() {
        let mut log = MemoryAccessLog::new(16);
        log.log_write(addr(0x1000), vec![0xAA, 0xBB]);
        log.log_read(addr(0x1000), vec![0xAA, 0xBB]); // should be skipped

        let mut written: Vec<(u64, Vec<u8>)> = Vec::new();
        let stats = replay_accesses(&log, |a, d| {
            written.push((a.0, d.to_vec()));
            Ok(())
        });
        assert_eq!(stats.applied, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(written[0], (0x1000, vec![0xAA, 0xBB]));
    }

    #[test]
    fn replay_counts_errors() {
        let mut log = MemoryAccessLog::new(16);
        log.log_write(addr(0x2000), vec![0xCC]);
        let stats = replay_accesses(&log, |_, _| Err("write denied".to_string()));
        assert_eq!(stats.errors, 1);
        assert!(stats.error_messages.contains(&"write denied".to_string()));
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let mut log = MemoryAccessLog::new(16);
        let s0 = log.log_read(addr(0), vec![]);
        let s1 = log.log_write(addr(4), vec![]);
        let s2 = log.log_read(addr(8), vec![]);
        assert!(s0 < s1 && s1 < s2);
    }

    #[test]
    fn clear_resets_entries() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0), vec![]);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn export_clones_entries() {
        let mut log = MemoryAccessLog::new(16);
        log.log_read(addr(0x100), vec![0xAB]);
        let exported = log.export();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].data, vec![0xAB]);
    }
}
