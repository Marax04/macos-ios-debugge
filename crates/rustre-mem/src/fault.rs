//! Memory fault injection: wraps any `MemoryProvider` and injects faults
//! according to configurable policies (probability, address ranges, access
//! kind filters).

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use parking_lot::Mutex;
use rustre_core::address::{Address, AddressRange};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// FaultPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// When and how to inject a fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultPolicy {
    /// Inject a fault on every `n`-th access (1 = every access).
    Every(u64),
    /// Inject a fault on accesses within the given virtual address range.
    AddressRange(AddressRange),
    /// Inject a fault with the given probability denominator: 1-in-N accesses.
    /// 0 means never.
    OneInN(u64),
    /// Inject a fault after `n` accesses have succeeded.
    AfterN(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// FaultKind
// ─────────────────────────────────────────────────────────────────────────────

/// Which accesses to fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    ReadsOnly,
    WritesOnly,
    Both,
}

// ─────────────────────────────────────────────────────────────────────────────
// FaultInjector
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a single fault injection rule.
#[derive(Debug, Clone)]
pub struct FaultRule {
    pub policy: FaultPolicy,
    pub kind: FaultKind,
    pub error: FaultError,
}

/// The error type to inject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultError {
    NotMapped,
    PermissionDenied,
    OutOfBounds,
    Io(String),
    Other(String),
}

impl FaultError {
    fn to_mem_error(&self, addr: Address) -> MemError {
        match self {
            Self::NotMapped => MemError::NotMapped(addr),
            Self::PermissionDenied => MemError::PermissionDenied(addr),
            Self::OutOfBounds => MemError::OutOfBounds(addr, 0),
            Self::Io(s) => MemError::Io(s.clone()),
            Self::Other(s) => MemError::Other(s.clone()),
        }
    }
}

/// State for one fault rule.
#[derive(Debug)]
struct RuleState {
    rule: FaultRule,
    /// Total accesses seen by this rule.
    access_count: u64,
    /// Number of faults injected.
    fault_count: u64,
    /// Simple LCG state for deterministic pseudo-randomness.
    rng_state: u64,
}

impl RuleState {
    const fn new(rule: FaultRule) -> Self {
        Self {
            rng_state: 0x853C_49E6_748F_EA9B,
            rule,
            access_count: 0,
            fault_count: 0,
        }
    }

    /// Returns `true` if this access should be faulted.
    const fn should_fault(&mut self, addr: Address, is_write: bool) -> bool {
        // Check access kind filter.
        match self.rule.kind {
            FaultKind::ReadsOnly if is_write => return false,
            FaultKind::WritesOnly if !is_write => return false,
            _ => {}
        }
        self.access_count += 1;
        let inject = match &self.rule.policy {
            FaultPolicy::Every(n) => *n > 0 && self.access_count.is_multiple_of(*n),
            FaultPolicy::AddressRange(r) => r.contains(addr),
            FaultPolicy::OneInN(n) => {
                if *n == 0 {
                    false
                } else {
                    self.rng_state = self
                        .rng_state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (self.rng_state >> 33).is_multiple_of(*n)
                }
            }
            FaultPolicy::AfterN(n) => self.access_count > *n,
        };
        if inject {
            self.fault_count += 1;
        }
        inject
    }
}

/// Statistics for a `FaultingMemoryProvider`.
#[derive(Debug, Clone, Default)]
pub struct FaultStats {
    pub total_reads: u64,
    pub total_writes: u64,
    pub faulted_reads: u64,
    pub faulted_writes: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// FaultingMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Interior-mutable state for `FaultingMemoryProvider`.
struct FaultInner {
    rules: Vec<RuleState>,
    stats: FaultStats,
    enabled: bool,
}

/// Wraps a `MemoryProvider` with configurable fault injection.
pub struct FaultingMemoryProvider<P: MemoryProvider> {
    inner: P,
    state: Mutex<FaultInner>,
}

impl<P: MemoryProvider> FaultingMemoryProvider<P> {
    /// Wrap `provider` with no fault rules.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            state: Mutex::new(FaultInner {
                rules: Vec::new(),
                stats: FaultStats::default(),
                enabled: true,
            }),
        }
    }

    /// Add a fault rule.
    pub fn add_rule(&mut self, rule: FaultRule) {
        self.state.lock().rules.push(RuleState::new(rule));
    }

    /// Enable or disable all fault injection.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.state.lock().enabled = enabled;
    }

    /// Snapshot current statistics.
    #[must_use]
    pub fn stats(&self) -> FaultStats {
        self.state.lock().stats.clone()
    }

    /// Clear all rules.
    pub fn clear_rules(&mut self) {
        self.state.lock().rules.clear();
    }
}

impl<P: MemoryProvider + Send + Sync> std::fmt::Debug for FaultingMemoryProvider<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.state.lock();
        f.debug_struct("FaultingMemoryProvider")
            .field("rules", &guard.rules.len())
            .field("enabled", &guard.enabled)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for FaultingMemoryProvider<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let maybe_err = {
            let mut st = self.state.lock();
            st.stats.total_reads += 1;
            if st.enabled {
                let mut fault_err = None;
                for rule_state in &mut st.rules {
                    if rule_state.should_fault(addr, false) {
                        fault_err = Some(rule_state.rule.error.to_mem_error(addr));
                        break;
                    }
                }
                if fault_err.is_some() {
                    st.stats.faulted_reads += 1;
                }
                fault_err
            } else {
                None
            }
        };
        if let Some(err) = maybe_err {
            return Err(err);
        }
        self.inner.read(addr, len)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        let maybe_err = {
            let mut st = self.state.lock();
            st.stats.total_writes += 1;
            if st.enabled {
                let mut fault_err = None;
                for rule_state in &mut st.rules {
                    if rule_state.should_fault(addr, true) {
                        fault_err = Some(rule_state.rule.error.to_mem_error(addr));
                        break;
                    }
                }
                if fault_err.is_some() {
                    st.stats.faulted_writes += 1;
                }
                fault_err
            } else {
                None
            }
        };
        if let Some(err) = maybe_err {
            return Err(err);
        }
        self.inner.write(addr, data)
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
    use rustre_core::permissions::Permissions;

    fn make_inner() -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(
            vec![0u8; 0x1000],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        )
    }

    #[test]
    fn test_fault_every_read() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::ReadsOnly,
            error: FaultError::NotMapped,
        });
        let result = fp.read(Address::new(0), 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_fault_every_write() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::WritesOnly,
            error: FaultError::PermissionDenied,
        });
        assert!(fp.write(Address::new(0), &[1]).is_err());
    }

    #[test]
    fn test_fault_address_range() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::AddressRange(AddressRange::new(
                Address::new(0x100),
                Address::new(0x200),
            )),
            kind: FaultKind::Both,
            error: FaultError::Other("injected".into()),
        });
        // Outside range: ok
        assert!(fp.read(Address::new(0), 4).is_ok());
        // Inside range: faulted
        assert!(fp.read(Address::new(0x150), 4).is_err());
    }

    #[test]
    fn test_fault_after_n() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::AfterN(2),
            kind: FaultKind::Both,
            error: FaultError::OutOfBounds,
        });
        // First two succeed.
        assert!(fp.read(Address::new(0), 1).is_ok());
        assert!(fp.read(Address::new(0), 1).is_ok());
        // Third faults.
        assert!(fp.read(Address::new(0), 1).is_err());
    }

    #[test]
    fn test_fault_disabled() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::Both,
            error: FaultError::NotMapped,
        });
        fp.set_enabled(false);
        assert!(fp.read(Address::new(0), 4).is_ok());
    }

    #[test]
    fn test_fault_stats_tracking() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(2),
            kind: FaultKind::Both,
            error: FaultError::NotMapped,
        });
        let _ = fp.read(Address::new(0), 1); // access 1: ok
        let _ = fp.read(Address::new(0), 1); // access 2: fault
        assert_eq!(fp.stats().total_reads, 2);
        assert_eq!(fp.stats().faulted_reads, 1);
    }

    #[test]
    fn test_fault_reads_only_does_not_affect_writes() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::ReadsOnly,
            error: FaultError::NotMapped,
        });
        // Write should succeed even though every read is faulted.
        assert!(fp.write(Address::new(0), &[0xAB]).is_ok());
    }

    #[test]
    fn test_fault_writes_only_does_not_affect_reads() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::WritesOnly,
            error: FaultError::PermissionDenied,
        });
        assert!(fp.read(Address::new(0), 4).is_ok());
    }

    #[test]
    fn test_fault_clear_rules() {
        let inner = make_inner();
        let mut fp = FaultingMemoryProvider::new(inner);
        fp.add_rule(FaultRule {
            policy: FaultPolicy::Every(1),
            kind: FaultKind::Both,
            error: FaultError::NotMapped,
        });
        fp.clear_rules();
        assert!(fp.read(Address::new(0), 4).is_ok());
    }

    #[test]
    fn test_fault_error_to_mem_error_variants() {
        let addr = Address::new(0x1234);
        assert!(matches!(
            FaultError::NotMapped.to_mem_error(addr),
            MemError::NotMapped(_)
        ));
        assert!(matches!(
            FaultError::PermissionDenied.to_mem_error(addr),
            MemError::PermissionDenied(_)
        ));
        assert!(matches!(
            FaultError::OutOfBounds.to_mem_error(addr),
            MemError::OutOfBounds(_, _)
        ));
        assert!(matches!(
            FaultError::Io("x".into()).to_mem_error(addr),
            MemError::Io(_)
        ));
        assert!(matches!(
            FaultError::Other("y".into()).to_mem_error(addr),
            MemError::Other(_)
        ));
    }
}
