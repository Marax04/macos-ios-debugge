//! Watchpoint management: track memory reads, writes, and read/write accesses
//! that should pause the debugger.
//!
//! **Intentionally distinct from [`crate::watchpoint_engine`].**
//! This module is the *portable, session-facing* watchpoint store.  It operates
//! on `rustre_core::Address` values and does not know about CPU debug registers.
//! Hardware register allocation, DR7/DBGWCR building, and page-protect fallback
//! live in [`crate::watchpoint_engine`], which is the lower-level, architecture-
//! aware counterpart.  A debugger backend is expected to consult `watchpoint_engine`
//! when setting a watchpoint obtained from this manager.

use std::collections::HashMap;
use std::fmt;

use rustre_core::address::Address;

// ── WatchpointKind ────────────────────────────────────────────────────────────

/// The type of memory access that triggers a watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchpointKind {
    /// Fires on any write to the watched range.
    Write,
    /// Fires on any read from the watched range (rare on real hardware).
    Read,
    /// Fires on either read or write.
    ReadWrite,
    /// Fires only when the value actually changes (write + value comparison).
    ValueChange,
    /// Fires when the value equals a specific target.
    ValueEquals,
}

impl fmt::Display for WatchpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AccessKind ────────────────────────────────────────────────────────────────

/// The kind of memory access that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── WatchpointId ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchpointId(pub u32);

impl fmt::Display for WatchpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WP#{}", self.0)
    }
}

// ── Watchpoint ────────────────────────────────────────────────────────────────

/// A watchpoint that monitors a contiguous byte range in the target's address space.
#[derive(Debug, Clone)]
pub struct Watchpoint {
    pub id: WatchpointId,
    /// Start address of the watched range.
    pub address: Address,
    /// Number of bytes covered by this watchpoint.
    pub size: usize,
    /// Kind of access that triggers the watchpoint.
    pub kind: WatchpointKind,
    /// Optional description / label.
    pub label: Option<String>,
    /// Whether the watchpoint is currently active.
    pub enabled: bool,
    /// Number of times this watchpoint has fired.
    pub hit_count: u64,
    /// For `ValueChange` / `ValueEquals`: the value to compare against (up to 8 bytes, LE).
    pub compare_value: Option<u64>,
    /// Last observed value (updated on each `check_access` call).
    pub last_value: Option<u64>,
    /// Maximum number of times to fire before auto-disabling (0 = unlimited).
    pub max_hits: u64,
}

impl Watchpoint {
    #[must_use]
    pub const fn new(id: WatchpointId, address: Address, size: usize, kind: WatchpointKind) -> Self {
        Self {
            id,
            address,
            size,
            kind,
            label: None,
            enabled: true,
            hit_count: 0,
            compare_value: None,
            last_value: None,
            max_hits: 0,
        }
    }

    /// Builder: set a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set compare value (for `ValueChange` / `ValueEquals`).
    #[must_use]
    pub const fn with_compare_value(mut self, value: u64) -> Self {
        self.compare_value = Some(value);
        self
    }

    /// Builder: auto-disable after `n` hits.
    #[must_use]
    pub const fn with_max_hits(mut self, n: u64) -> Self {
        self.max_hits = n;
        self
    }

    /// Returns `true` if `addr` falls within `[self.address, self.address + self.size)`.
    #[must_use]
    /// The end is never materialised: `start + size` saturates at `u64::MAX`,
    /// which an EXCLUSIVE upper bound then excludes, losing the last byte of the
    /// address space. Comparing the offset is exact everywhere and cannot
    /// overflow after the lower-bound check. Third and fourth site of the shape
    /// first corrected in iter 273.
    #[must_use]
    pub fn covers(&self, addr: Address) -> bool {
        let start = u64::from(self.address);
        let a = u64::from(addr);
        a >= start && a - start < self.size as u64
    }

    /// Returns `true` if the byte range `[addr, addr+width)` overlaps with this watchpoint.
    #[must_use]
    /// Exact intersection, without materialising either end — see `covers`.
    /// A watchpoint on the last bytes of memory used to miss the access that
    /// touched it, which for a watchpoint is a MISSED STOP: invisible.
    #[must_use]
    pub fn overlaps(&self, addr: Address, width: usize) -> bool {
        let wp_start = u64::from(self.address);
        let acc_start = u64::from(addr);
        if wp_start <= acc_start {
            acc_start - wp_start < self.size as u64
        } else {
            wp_start - acc_start < width as u64
        }
    }
}

impl fmt::Display for Watchpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {}+{} [{:?}] hits={} {}",
            self.id,
            self.address,
            self.size,
            self.kind,
            self.hit_count,
            if self.enabled { "enabled" } else { "disabled" }
        )
    }
}

// ── AccessEvent ───────────────────────────────────────────────────────────────

/// Describes a single memory access event.
#[derive(Debug, Clone)]
pub struct AccessEvent {
    /// The address that was accessed.
    pub addr: Address,
    /// Number of bytes accessed.
    pub width: usize,
    /// Kind of access.
    pub access: AccessKind,
    /// Current value at `addr` (caller-supplied, up to 8 bytes as LE u64).
    pub current_value: Option<u64>,
}

impl AccessEvent {
    #[must_use]
    pub const fn write(addr: Address, width: usize, value: u64) -> Self {
        Self {
            addr,
            width,
            access: AccessKind::Write,
            current_value: Some(value),
        }
    }

    #[must_use]
    pub const fn read(addr: Address, width: usize, value: u64) -> Self {
        Self {
            addr,
            width,
            access: AccessKind::Read,
            current_value: Some(value),
        }
    }
}

// ── check_access ──────────────────────────────────────────────────────────────

/// Check whether `event` triggers `wp`.
///
/// Returns `true` if the watchpoint should fire.  Updates `wp.hit_count`
/// and `wp.last_value` on a match.
pub fn check_access(wp: &mut Watchpoint, event: &AccessEvent) -> bool {
    if !wp.enabled {
        return false;
    }
    if !wp.overlaps(event.addr, event.width) {
        return false;
    }

    let access_matches = match wp.kind {
        WatchpointKind::Write => event.access == AccessKind::Write,
        WatchpointKind::Read => event.access == AccessKind::Read,
        WatchpointKind::ReadWrite => true,
        WatchpointKind::ValueChange => {
            if event.access != AccessKind::Write {
                return false;
            }
            let new_val = event.current_value.unwrap_or(0);
            let changed = wp.last_value.is_none_or(|old| old != new_val);
            wp.last_value = Some(new_val);
            changed
        }
        WatchpointKind::ValueEquals => {
            let target = wp.compare_value.unwrap_or(0);
            event.current_value.is_some_and(|v| v == target)
        }
    };

    if access_matches {
        wp.hit_count += 1;
        if let Some(v) = event.current_value {
            wp.last_value = Some(v);
        }
        if wp.max_hits > 0 && wp.hit_count >= wp.max_hits {
            wp.enabled = false;
        }
        true
    } else {
        false
    }
}

// ── WatchpointManager ────────────────────────────────────────────────────────

/// Manages a set of watchpoints for a debug session.
#[derive(Debug, Default)]
pub struct WatchpointManager {
    watchpoints: HashMap<WatchpointId, Watchpoint>,
    next_id: u32,
}

impl WatchpointManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new watchpoint and return its ID.
    pub fn add(
        &mut self,
        address: Address,
        size: usize,
        kind: WatchpointKind,
    ) -> WatchpointId {
        let id = WatchpointId(self.next_id);
        self.next_id += 1;
        let wp = Watchpoint::new(id, address, size, kind);
        self.watchpoints.insert(id, wp);
        id
    }

    /// Add a pre-built watchpoint, assigning it a fresh ID.
    pub fn insert(&mut self, mut wp: Watchpoint) -> WatchpointId {
        let id = WatchpointId(self.next_id);
        self.next_id += 1;
        wp.id = id;
        self.watchpoints.insert(id, wp);
        id
    }

    /// Remove a watchpoint by ID.
    pub fn remove(&mut self, id: WatchpointId) -> Option<Watchpoint> {
        self.watchpoints.remove(&id)
    }

    /// Enable or disable a watchpoint.
    pub fn set_enabled(&mut self, id: WatchpointId, enabled: bool) -> bool {
        if let Some(wp) = self.watchpoints.get_mut(&id) {
            wp.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get a watchpoint by ID.
    #[must_use]
    pub fn get(&self, id: WatchpointId) -> Option<&Watchpoint> {
        self.watchpoints.get(&id)
    }

    /// Get a mutable reference to a watchpoint by ID.
    pub fn get_mut(&mut self, id: WatchpointId) -> Option<&mut Watchpoint> {
        self.watchpoints.get_mut(&id)
    }

    /// Iterate over all watchpoints.
    pub fn iter(&self) -> impl Iterator<Item = &Watchpoint> {
        self.watchpoints.values()
    }

    /// Number of registered watchpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.watchpoints.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.watchpoints.is_empty()
    }

    /// Process an access event against all watchpoints.
    ///
    /// Returns the IDs of watchpoints that fired.
    pub fn process_access(&mut self, event: &AccessEvent) -> Vec<WatchpointId> {
        let mut fired = Vec::new();
        for (id, wp) in &mut self.watchpoints {
            if check_access(wp, event) {
                fired.push(*id);
            }
        }
        fired.sort_by_key(|id| id.0);
        fired
    }

    /// Disable all watchpoints.
    pub fn disable_all(&mut self) {
        for wp in self.watchpoints.values_mut() {
            wp.enabled = false;
        }
    }

    /// Enable all watchpoints.
    pub fn enable_all(&mut self) {
        for wp in self.watchpoints.values_mut() {
            wp.enabled = true;
        }
    }

    /// Remove all watchpoints.
    pub fn clear(&mut self) {
        self.watchpoints.clear();
    }

    /// Total number of hits across all watchpoints.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.watchpoints.values().map(|w| w.hit_count).sum()
    }

    /// Watchpoints that cover `addr`.
    #[must_use]
    pub fn covering(&self, addr: Address) -> Vec<&Watchpoint> {
        self.watchpoints
            .values()
            .filter(|w| w.covers(addr))
            .collect()
    }

    /// Reset hit counts on all watchpoints.
    pub fn reset_all_counts(&mut self) {
        for wp in self.watchpoints.values_mut() {
            wp.hit_count = 0;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::from(v)
    }

    /// A watchpoint on the last bytes of memory must still see the access.
    ///
    /// `covers`/`overlaps` computed the watched end with `saturating_add`, so a
    /// watchpoint that runs to the top of the address space reported `u64::MAX`
    /// as its end where the true end is one past it. The exclusive `<` then
    /// denied a real hit, and the watchpoint never fired — a MISSED STOP, which
    /// is the failure mode a watchpoint user cannot detect: the program simply
    /// runs past the write they were waiting for. Kernel-space addresses live
    /// exactly here.
    ///
    /// Fourth occurrence of the shape first corrected in iter 273
    /// (`Symbol::contains`), then 310 (`race_detector`); the sweep for
    /// `saturating_add` followed by `<` is what found the rest.
    #[test]
    fn a_watchpoint_on_the_last_byte_of_memory_still_fires() {
        let top = u64::MAX;
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(top), 1, WatchpointKind::Write);
        let ev = AccessEvent::write(addr(top), 1, 0xAB);
        assert!(
            !mgr.process_access(&ev).is_empty(),
            "a write to the watched final byte did not fire the watchpoint"
        );
        mgr.remove(id);

        // A write one byte BELOW must still not fire it.
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(top), 1, WatchpointKind::Write);
        let ev = AccessEvent::write(addr(top - 1), 1, 0xAB);
        assert!(
            mgr.process_access(&ev).is_empty(),
            "an adjacent, non-overlapping write must not fire it"
        );
    }

    #[test]
    fn add_and_remove_watchpoint() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        assert_eq!(mgr.len(), 1);
        mgr.remove(id);
        assert!(mgr.is_empty());
    }

    #[test]
    fn write_watchpoint_fires_on_write() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        let ev = AccessEvent::write(addr(0x1000), 4, 0xFF);
        let fired = mgr.process_access(&ev);
        assert_eq!(fired, vec![id]);
    }

    #[test]
    fn write_watchpoint_does_not_fire_on_read() {
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        let ev = AccessEvent::read(addr(0x1000), 4, 0xFF);
        assert!(mgr.process_access(&ev).is_empty());
    }

    #[test]
    fn read_watchpoint_fires_on_read() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x2000), 8, WatchpointKind::Read);
        let ev = AccessEvent::read(addr(0x2000), 8, 0);
        let fired = mgr.process_access(&ev);
        assert_eq!(fired, vec![id]);
    }

    #[test]
    fn readwrite_watchpoint_fires_on_both() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x3000), 4, WatchpointKind::ReadWrite);
        assert!(!mgr.process_access(&AccessEvent::read(addr(0x3000), 4, 0)).is_empty());
        let fired = mgr.process_access(&AccessEvent::write(addr(0x3000), 4, 1));
        assert_eq!(fired, vec![id]);
    }

    #[test]
    fn watchpoint_does_not_fire_on_non_overlapping_access() {
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        let ev = AccessEvent::write(addr(0x2000), 4, 0);
        assert!(mgr.process_access(&ev).is_empty());
    }

    #[test]
    fn overlapping_access_fires_watchpoint() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1002), 4, WatchpointKind::Write);
        // Write starts at 0x1000, 8 bytes → covers 0x1000..0x1008, overlaps WP at 0x1002
        let ev = AccessEvent::write(addr(0x1000), 8, 0);
        let fired = mgr.process_access(&ev);
        assert_eq!(fired, vec![id]);
    }

    #[test]
    fn disabled_watchpoint_does_not_fire() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        mgr.set_enabled(id, false);
        let ev = AccessEvent::write(addr(0x1000), 4, 0);
        assert!(mgr.process_access(&ev).is_empty());
    }

    #[test]
    fn value_change_watchpoint() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::ValueChange);
        // First write — previous value unknown, should fire.
        let ev1 = AccessEvent::write(addr(0x1000), 4, 0xAABB);
        assert_eq!(mgr.process_access(&ev1), vec![id]);
        // Same value again — should not fire.
        let ev2 = AccessEvent::write(addr(0x1000), 4, 0xAABB);
        assert!(mgr.process_access(&ev2).is_empty());
        // Changed value — should fire.
        let ev3 = AccessEvent::write(addr(0x1000), 4, 0xCCDD);
        assert_eq!(mgr.process_access(&ev3), vec![id]);
    }

    #[test]
    fn value_equals_watchpoint() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::ValueEquals);
        mgr.get_mut(id).unwrap().compare_value = Some(0xDEAD);
        // Wrong value.
        assert!(mgr.process_access(&AccessEvent::write(addr(0x1000), 4, 0xBEEF)).is_empty());
        // Correct value.
        let fired = mgr.process_access(&AccessEvent::write(addr(0x1000), 4, 0xDEAD));
        assert_eq!(fired, vec![id]);
    }

    #[test]
    fn max_hits_auto_disables() {
        let mut mgr = WatchpointManager::new();
        let id = mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        mgr.get_mut(id).unwrap().max_hits = 2;
        let ev = || AccessEvent::write(addr(0x1000), 4, 0);
        assert!(!mgr.process_access(&ev()).is_empty()); // hit 1
        assert!(!mgr.process_access(&ev()).is_empty()); // hit 2 → auto-disable
        assert!(mgr.process_access(&ev()).is_empty());  // disabled
    }

    #[test]
    fn total_hits_counts_across_watchpoints() {
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        mgr.add(addr(0x2000), 4, WatchpointKind::Write);
        mgr.process_access(&AccessEvent::write(addr(0x1000), 4, 0));
        mgr.process_access(&AccessEvent::write(addr(0x2000), 4, 0));
        assert_eq!(mgr.total_hits(), 2);
    }

    #[test]
    fn covering_returns_watchpoints_at_address() {
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(0x1000), 8, WatchpointKind::Write);
        mgr.add(addr(0x2000), 8, WatchpointKind::Write);
        let covering = mgr.covering(addr(0x1004));
        assert_eq!(covering.len(), 1);
        assert_eq!(u64::from(covering[0].address), 0x1000);
    }

    #[test]
    fn disable_all_and_enable_all() {
        let mut mgr = WatchpointManager::new();
        mgr.add(addr(0x1000), 4, WatchpointKind::Write);
        mgr.add(addr(0x2000), 4, WatchpointKind::Write);
        mgr.disable_all();
        for wp in mgr.iter() {
            assert!(!wp.enabled);
        }
        mgr.enable_all();
        for wp in mgr.iter() {
            assert!(wp.enabled);
        }
    }
}
