//! Memory access logging: wraps any `MemoryProvider` and records every read
//! and write with optional stack-trace context.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// AccessKind
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the access is a read or a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessKind {
    Read,
    Write,
}

impl std::fmt::Display for AccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => f.write_str("R"),
            Self::Write => f.write_str("W"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessRecord
// ─────────────────────────────────────────────────────────────────────────────

/// One recorded memory access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    /// Sequential access number (monotonically increasing).
    pub seq: u64,
    /// Read or write.
    pub kind: AccessKind,
    /// Starting virtual address.
    pub addr: Address,
    /// Number of bytes accessed.
    pub len: usize,
    /// For writes, the bytes written (may be truncated to `max_capture_bytes`).
    pub data: Option<Vec<u8>>,
    /// Optional tag set by the caller (e.g. instruction address, thread id).
    pub tag: Option<u64>,
}

impl std::fmt::Display for AccessRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "#{} {} 0x{:x} len={}",
            self.seq, self.kind, self.addr.0, self.len
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessLog
// ─────────────────────────────────────────────────────────────────────────────

/// A thread-safe access log shared between the provider and any observer.
#[derive(Debug, Clone)]
pub struct AccessLog {
    inner: Arc<Mutex<AccessLogInner>>,
}

#[derive(Debug)]
struct AccessLogInner {
    records: VecDeque<AccessRecord>,
    next_seq: u64,
    /// Maximum bytes to capture per write (0 = no capture).
    max_capture_bytes: usize,
    /// Address filter: only log accesses to this range, or log everything when
    /// `None`.
    filter: Option<(Address, Address)>,
    /// Maximum records to keep (oldest are dropped when exceeded).
    capacity: usize,
    /// Whether logging is currently enabled.
    enabled: bool,
}

impl AccessLog {
    /// Create a new log with default settings (captures all accesses, no
    /// write-data capture, unbounded capacity).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AccessLogInner {
                records: VecDeque::new(),
                next_seq: 0,
                max_capture_bytes: 0,
                filter: None,
                capacity: usize::MAX,
                enabled: true,
            })),
        }
    }

    /// Set the maximum number of write-data bytes to capture per access.
    pub fn set_capture_bytes(&self, n: usize) {
        self.inner.lock().unwrap().max_capture_bytes = n;
    }

    /// Restrict logging to accesses overlapping `[start, end)`.
    pub fn set_filter(&self, start: Address, end: Address) {
        self.inner.lock().unwrap().filter = Some((start, end));
    }

    /// Remove the address filter.
    pub fn clear_filter(&self) {
        self.inner.lock().unwrap().filter = None;
    }

    /// Set the maximum number of records to retain (ring buffer semantics).
    pub fn set_capacity(&self, cap: usize) {
        self.inner.lock().unwrap().capacity = cap;
    }

    /// Enable or disable logging.
    pub fn set_enabled(&self, enabled: bool) {
        self.inner.lock().unwrap().enabled = enabled;
    }

    /// Number of records currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().records.len()
    }

    /// Returns `true` if no records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().records.is_empty()
    }

    /// Clear all records.
    pub fn clear(&self) {
        self.inner.lock().unwrap().records.clear();
    }

    /// Snapshot all current records.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AccessRecord> {
        self.inner.lock().unwrap().records.iter().cloned().collect()
    }

    /// Records matching the given `kind`.
    #[must_use]
    pub fn by_kind(&self, kind: AccessKind) -> Vec<AccessRecord> {
        self.inner
            .lock()
            .unwrap()
            .records
            .iter()
            .filter(|r| r.kind == kind)
            .cloned()
            .collect()
    }

    /// Records touching `addr`.
    #[must_use]
    pub fn touching(&self, addr: Address) -> Vec<AccessRecord> {
        self.inner
            .lock()
            .unwrap()
            .records
            .iter()
            .filter(|r| {
                let end = r.addr.0 + r.len as u64;
                r.addr.0 <= addr.0 && addr.0 < end
            })
            .cloned()
            .collect()
    }

    /// Records with the given tag.
    #[must_use]
    pub fn by_tag(&self, tag: u64) -> Vec<AccessRecord> {
        self.inner
            .lock()
            .unwrap()
            .records
            .iter()
            .filter(|r| r.tag == Some(tag))
            .cloned()
            .collect()
    }

    /// Record an access (internal).
    fn record(
        &self,
        kind: AccessKind,
        addr: Address,
        len: usize,
        data: Option<&[u8]>,
        tag: Option<u64>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.enabled {
            return;
        }
        // Apply address filter.
        if let Some((fstart, fend)) = inner.filter {
            let acc_end = addr.0 + len as u64;
            if addr.0 >= fend.0 || acc_end <= fstart.0 {
                return;
            }
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        let captured_data = data.map(|d| {
            let cap = inner.max_capture_bytes;
            if cap == 0 {
                Vec::new()
            } else {
                d[..d.len().min(cap)].to_vec()
            }
        });
        let record = AccessRecord {
            seq,
            kind,
            addr,
            len,
            data: captured_data,
            tag,
        };
        if inner.records.len() >= inner.capacity {
            inner.records.pop_front();
        }
        inner.records.push_back(record);
    }
}

impl Default for AccessLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoggingMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a `MemoryProvider` and records all reads and writes to an `AccessLog`.
pub struct LoggingMemoryProvider<P: MemoryProvider> {
    inner: P,
    log: AccessLog,
    /// Tag to attach to each logged access (e.g. emulated instruction address).
    tag: Option<u64>,
}

impl<P: MemoryProvider> LoggingMemoryProvider<P> {
    /// Wrap `provider` with a fresh `AccessLog`.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            log: AccessLog::new(),
            tag: None,
        }
    }

    /// Wrap `provider` with an existing shared `AccessLog`.
    #[must_use]
    pub const fn with_log(provider: P, log: AccessLog) -> Self {
        Self {
            inner: provider,
            log,
            tag: None,
        }
    }

    /// Set the tag applied to all subsequent accesses.
    pub const fn set_tag(&mut self, tag: u64) {
        self.tag = Some(tag);
    }

    /// Clear the tag.
    pub const fn clear_tag(&mut self) {
        self.tag = None;
    }

    /// Return a reference to the access log.
    #[must_use]
    pub const fn log(&self) -> &AccessLog {
        &self.log
    }

    /// Consume the provider and return the inner provider and access log.
    pub fn into_parts(self) -> (P, AccessLog) {
        (self.inner, self.log)
    }
}

impl<P: MemoryProvider + Send + Sync> std::fmt::Debug for LoggingMemoryProvider<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoggingMemoryProvider")
            .field("log_len", &self.log.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for LoggingMemoryProvider<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let result = self.inner.read(addr, len);
        if result.is_ok() {
            self.log.record(AccessKind::Read, addr, len, None, self.tag);
        }
        result
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        let result = self.inner.write(addr, data);
        if result.is_ok() {
            self.log
                .record(AccessKind::Write, addr, data.len(), Some(data), self.tag);
        }
        result
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.inner.regions()
    }

    fn is_live(&self) -> bool {
        self.inner.is_live()
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.inner.refresh().await
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        self.inner.snapshot().await
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.inner.restore(id).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;

    fn make_provider(size: usize) -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(
            vec![0u8; size],
            Address::new(0),
            rustre_core::permissions::Permissions::READ
                | rustre_core::permissions::Permissions::WRITE,
        )
    }

    #[test]
    fn test_log_read_is_recorded() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.read(Address::new(0), 4).unwrap();
        assert_eq!(logger.log().len(), 1);
        let snap = logger.log().snapshot();
        assert_eq!(snap[0].kind, AccessKind::Read);
        assert_eq!(snap[0].len, 4);
    }

    #[test]
    fn test_log_write_is_recorded() {
        let base = make_provider(0x100);
        let mut logger = LoggingMemoryProvider::new(base);
        logger.write(Address::new(0), &[1, 2, 3]).unwrap();
        assert_eq!(logger.log().len(), 1);
        let snap = logger.log().snapshot();
        assert_eq!(snap[0].kind, AccessKind::Write);
        assert_eq!(snap[0].len, 3);
    }

    #[test]
    fn test_log_data_capture() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.log().set_capture_bytes(64);
        logger.read(Address::new(0), 4).unwrap();
        // Reads don't have data captured (data is None for reads).
        let snap = logger.log().snapshot();
        // Reads record without data (data is None).
        assert!(snap[0].data.is_none());
    }

    #[test]
    fn test_log_write_data_captured() {
        let base = make_provider(0x100);
        let mut logger = LoggingMemoryProvider::new(base);
        logger.log().set_capture_bytes(64);
        logger
            .write(Address::new(0), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        let snap = logger.log().snapshot();
        let data = snap[0].data.as_ref().unwrap();
        assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_log_filter() {
        let base = make_provider(0x2000);
        let logger = LoggingMemoryProvider::new(base);
        logger
            .log()
            .set_filter(Address::new(0x1000), Address::new(0x2000));
        logger.read(Address::new(0), 4).unwrap(); // outside filter
        logger.read(Address::new(0x1000), 4).unwrap(); // inside filter
        assert_eq!(logger.log().len(), 1);
    }

    #[test]
    fn test_log_enabled_disabled() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.log().set_enabled(false);
        logger.read(Address::new(0), 4).unwrap();
        assert_eq!(logger.log().len(), 0);
        logger.log().set_enabled(true);
        logger.read(Address::new(0), 4).unwrap();
        assert_eq!(logger.log().len(), 1);
    }

    #[test]
    fn test_log_capacity_ring_buffer() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.log().set_capacity(3);
        for _ in 0..5 {
            logger.read(Address::new(0), 1).unwrap();
        }
        assert_eq!(logger.log().len(), 3);
    }

    #[test]
    fn test_log_by_kind() {
        let base = make_provider(0x100);
        let mut logger = LoggingMemoryProvider::new(base);
        logger.read(Address::new(0), 1).unwrap();
        logger.write(Address::new(0), &[1]).unwrap();
        logger.read(Address::new(0), 1).unwrap();
        let reads = logger.log().by_kind(AccessKind::Read);
        let writes = logger.log().by_kind(AccessKind::Write);
        assert_eq!(reads.len(), 2);
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn test_log_touching() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.read(Address::new(0x10), 8).unwrap(); // covers 0x10..0x18
        logger.read(Address::new(0x20), 4).unwrap();
        let touching = logger.log().touching(Address::new(0x14));
        assert_eq!(touching.len(), 1);
    }

    #[test]
    fn test_log_clear() {
        let base = make_provider(0x100);
        let logger = LoggingMemoryProvider::new(base);
        logger.read(Address::new(0), 4).unwrap();
        assert!(!logger.log().is_empty());
        logger.log().clear();
        assert!(logger.log().is_empty());
    }

    #[test]
    fn test_log_tag() {
        let base = make_provider(0x100);
        let mut logger = LoggingMemoryProvider::new(base);
        logger.set_tag(0xDEAD);
        logger.read(Address::new(0), 1).unwrap();
        logger.clear_tag();
        logger.read(Address::new(0), 1).unwrap();
        let tagged = logger.log().by_tag(0xDEAD);
        assert_eq!(tagged.len(), 1);
    }

    #[test]
    fn test_access_record_display() {
        let r = AccessRecord {
            seq: 5,
            kind: AccessKind::Write,
            addr: Address::new(0x1000),
            len: 4,
            data: None,
            tag: None,
        };
        let s = r.to_string();
        assert!(s.contains('W'));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_log_shared_between_providers() {
        let base1 = make_provider(0x100);
        let base2 = make_provider(0x100);
        let shared_log = AccessLog::new();
        let p1 = LoggingMemoryProvider::with_log(base1, shared_log.clone());
        let mut p2 = LoggingMemoryProvider::with_log(base2, shared_log.clone());
        p1.read(Address::new(0), 1).unwrap();
        p2.write(Address::new(0), &[1]).unwrap();
        assert_eq!(shared_log.len(), 2);
    }
}
