//! `ttd_watchpoint_manager` — Watchpoint management for TTD replay sessions.
//!
//! Provides [`TtdWatchpointManager`] which tracks memory-range watchpoints
//! and evaluates them against memory write/read events during replay.

use rustre_ttd::TracePosition;
use serde::{Deserialize, Serialize};

use crate::{MemoryState, WatchpointKind};

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointHit
// ─────────────────────────────────────────────────────────────────────────────

/// Record produced when a watchpoint fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointHit {
    /// The watchpoint that fired.
    pub wp_id: u32,
    /// The trace position at which the hit occurred.
    pub position: TracePosition,
    /// The memory address that was accessed.
    pub address: u64,
    /// Number of bytes accessed.
    pub size: usize,
    /// Whether this was a read or a write.
    pub access_kind: AccessKind,
    /// Bytes before the write (only meaningful for write accesses).
    pub old_value: Vec<u8>,
    /// Bytes written (write) or read (read).
    pub new_value: Vec<u8>,
    /// Sequential hit number for this watchpoint.
    pub hit_number: u64,
}

impl std::fmt::Display for WatchpointHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WP#{} {:?} @ {:#x}+{} pos={} hit#{}",
            self.wp_id, self.access_kind, self.address, self.size, self.position, self.hit_number
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessKind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    Read,
    Write,
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdWatchpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A memory watchpoint registered with the [`TtdWatchpointManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdWatchpoint {
    /// Unique identifier.
    pub id: u32,
    /// Start address of the watched memory range.
    pub address: u64,
    /// Number of bytes to watch.
    pub size: usize,
    /// Which access kinds trigger this watchpoint.
    pub kind: WatchpointKind,
    /// Whether the watchpoint is currently active.
    pub enabled: bool,
    /// Total number of times this watchpoint has fired.
    pub hit_count: u64,
    /// Optional descriptive label.
    pub label: Option<String>,
    /// One-shot mode: automatically disables after the first hit.
    pub one_shot: bool,
    /// Optional condition: only fire if memory at `cond_addr` equals `cond_value`.
    pub condition: Option<WatchpointCondition>,
}

/// Optional condition attached to a watchpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointCondition {
    pub cond_addr: u64,
    pub cond_value: Vec<u8>,
}

impl TtdWatchpoint {
    #[must_use]
    pub const fn new(id: u32, address: u64, size: usize, kind: WatchpointKind) -> Self {
        Self {
            id,
            address,
            size,
            kind,
            enabled: true,
            hit_count: 0,
            label: None,
            one_shot: false,
            condition: None,
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub const fn one_shot(mut self) -> Self {
        self.one_shot = true;
        self
    }

    #[must_use]
    pub fn with_condition(mut self, cond_addr: u64, cond_value: Vec<u8>) -> Self {
        self.condition = Some(WatchpointCondition { cond_addr, cond_value });
        self
    }

    /// Return `true` if the memory range `[addr, addr+len)` overlaps this watchpoint.
    #[must_use]
    pub const fn overlaps(&self, addr: u64, len: usize) -> bool {
        let wp_end = self.address.saturating_add(self.size as u64);
        let acc_end = addr.saturating_add(len as u64);
        self.address < acc_end && addr < wp_end
    }

    /// Check whether this watchpoint fires for a memory access.
    ///
    /// `access_addr` and `access_size` describe the accessed range.
    /// `access_kind` specifies whether it was a read or write.
    /// `memory` is used to evaluate any attached condition.
    #[must_use]
    pub fn check_memory_write(
        &self,
        access_addr: u64,
        access_size: usize,
        access_kind: AccessKind,
        memory: &MemoryState,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.overlaps(access_addr, access_size) {
            return false;
        }
        // Check kind
        let kind_matches = matches!(
            (&self.kind, access_kind),
            (WatchpointKind::Read, AccessKind::Read)
                | (WatchpointKind::Write, AccessKind::Write)
                | (WatchpointKind::ReadWrite, _)
        );
        if !kind_matches {
            return false;
        }
        // Evaluate optional condition
        if let Some(cond) = &self.condition
            && memory.read(cond.cond_addr, cond.cond_value.len()).as_deref()
                != Some(cond.cond_value.as_slice())
            {
                return false;
            }
        true
    }
}

impl std::fmt::Display for TtdWatchpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = self.label.as_deref().unwrap_or("-");
        write!(
            f,
            "WP#{} [{:?}] {:#x}+{} enabled={} hits={} label={}",
            self.id, self.kind, self.address, self.size, self.enabled, self.hit_count, label
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdWatchpointManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a collection of [`TtdWatchpoint`] objects for a TTD replay session.
pub struct TtdWatchpointManager {
    watchpoints: Vec<TtdWatchpoint>,
    next_id: u32,
    /// Global hit log across all watchpoints.
    hit_log: Vec<WatchpointHit>,
    /// Most recently observed memory state (used for old-value capture).
    memory: MemoryState,
}

impl TtdWatchpointManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            watchpoints: Vec::new(),
            next_id: 1,
            hit_log: Vec::new(),
            memory: MemoryState::new(),
        }
    }

    /// Update the manager's view of memory (call after each replay step).
    pub fn update_memory(&mut self, memory: MemoryState) {
        self.memory = memory;
    }

    /// Register a write watchpoint.  Returns the assigned ID.
    pub fn add_write(&mut self, address: u64, size: usize) -> u32 {
        self.add(TtdWatchpoint::new(self.next_id, address, size, WatchpointKind::Write))
    }

    /// Register a read watchpoint.  Returns the assigned ID.
    pub fn add_read(&mut self, address: u64, size: usize) -> u32 {
        self.add(TtdWatchpoint::new(self.next_id, address, size, WatchpointKind::Read))
    }

    /// Register a read/write watchpoint.  Returns the assigned ID.
    pub fn add_readwrite(&mut self, address: u64, size: usize) -> u32 {
        self.add(TtdWatchpoint::new(self.next_id, address, size, WatchpointKind::ReadWrite))
    }

    /// Register a fully-constructed watchpoint.  Returns the assigned ID.
    pub fn add(&mut self, mut wp: TtdWatchpoint) -> u32 {
        let id = self.next_id;
        wp.id = id;
        self.next_id += 1;
        self.watchpoints.push(wp);
        id
    }

    pub fn remove(&mut self, wp_id: u32) -> bool {
        let before = self.watchpoints.len();
        self.watchpoints.retain(|wp| wp.id != wp_id);
        self.watchpoints.len() < before
    }

    pub fn enable(&mut self, wp_id: u32) -> bool {
        if let Some(wp) = self.watchpoints.iter_mut().find(|w| w.id == wp_id) {
            wp.enabled = true;
            return true;
        }
        false
    }

    pub fn disable(&mut self, wp_id: u32) -> bool {
        if let Some(wp) = self.watchpoints.iter_mut().find(|w| w.id == wp_id) {
            wp.enabled = false;
            return true;
        }
        false
    }

    /// Notify the manager of a memory write event.
    ///
    /// Returns a list of [`WatchpointHit`] records for any watchpoints that fired.
    pub fn on_memory_write(
        &mut self,
        position: TracePosition,
        addr: u64,
        new_data: &[u8],
    ) -> Vec<WatchpointHit> {
        let old_data = self.memory.read(addr, new_data.len()).unwrap_or_default();
        let mut hits = Vec::new();
        for wp in &mut self.watchpoints {
            if wp.check_memory_write(addr, new_data.len(), AccessKind::Write, &self.memory) {
                wp.hit_count += 1;
                let hit = WatchpointHit {
                    wp_id: wp.id,
                    position,
                    address: addr,
                    size: new_data.len(),
                    access_kind: AccessKind::Write,
                    old_value: old_data.clone(),
                    new_value: new_data.to_vec(),
                    hit_number: wp.hit_count,
                };
                hits.push(hit.clone());
                self.hit_log.push(hit);
                if wp.one_shot {
                    wp.enabled = false;
                }
            }
        }
        // Update our memory view after the write
        self.memory.apply_write(addr, new_data);
        hits
    }

    /// Notify the manager of a memory read event.
    ///
    /// Returns a list of [`WatchpointHit`] records for any watchpoints that fired.
    pub fn on_memory_read(
        &mut self,
        position: TracePosition,
        addr: u64,
        size: usize,
    ) -> Vec<WatchpointHit> {
        let read_data = self.memory.read(addr, size).unwrap_or_default();
        let mut hits = Vec::new();
        for wp in &mut self.watchpoints {
            if wp.check_memory_write(addr, size, AccessKind::Read, &self.memory) {
                wp.hit_count += 1;
                let hit = WatchpointHit {
                    wp_id: wp.id,
                    position,
                    address: addr,
                    size,
                    access_kind: AccessKind::Read,
                    old_value: read_data.clone(),
                    new_value: read_data.clone(),
                    hit_number: wp.hit_count,
                };
                hits.push(hit.clone());
                self.hit_log.push(hit);
                if wp.one_shot {
                    wp.enabled = false;
                }
            }
        }
        hits
    }

    // ── query accessors ───────────────────────────────────────────────────────

    #[must_use]
    pub const fn count(&self) -> usize {
        self.watchpoints.len()
    }

    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.watchpoints.iter().filter(|w| w.enabled).count()
    }

    #[must_use]
    pub fn find(&self, wp_id: u32) -> Option<&TtdWatchpoint> {
        self.watchpoints.iter().find(|w| w.id == wp_id)
    }

    #[must_use]
    pub fn all(&self) -> &[TtdWatchpoint] {
        &self.watchpoints
    }

    #[must_use]
    pub fn hit_log(&self) -> &[WatchpointHit] {
        &self.hit_log
    }

    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.watchpoints.iter().map(|w| w.hit_count).sum()
    }

    /// Return all watchpoints whose range overlaps `[addr, addr+size)`.
    #[must_use]
    pub fn overlapping(&self, addr: u64, size: usize) -> Vec<&TtdWatchpoint> {
        self.watchpoints
            .iter()
            .filter(|w| w.overlaps(addr, size))
            .collect()
    }

    /// Return positions in the hit log where a specific watchpoint fired.
    #[must_use]
    pub fn hits_for(&self, wp_id: u32) -> Vec<&WatchpointHit> {
        self.hit_log.iter().filter(|h| h.wp_id == wp_id).collect()
    }

    pub fn clear_hit_log(&mut self) {
        self.hit_log.clear();
    }

    pub fn clear_all(&mut self) {
        self.watchpoints.clear();
        self.hit_log.clear();
    }
}

impl Default for TtdWatchpointManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> TtdWatchpointManager {
        TtdWatchpointManager::new()
    }

    fn pos() -> TracePosition {
        TracePosition::default()
    }

    #[test]
    fn test_add_write_wp() {
        let mut m = mgr();
        let id = m.add_write(0x5000, 8);
        assert_eq!(m.count(), 1);
        assert_eq!(m.find(id).unwrap().address, 0x5000);
    }

    #[test]
    fn test_remove_wp() {
        let mut m = mgr();
        let id = m.add_write(0x100, 4);
        assert!(m.remove(id));
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut m = mgr();
        assert!(!m.remove(999));
    }

    #[test]
    fn test_enable_disable() {
        let mut m = mgr();
        let id = m.add_write(0x200, 4);
        assert!(m.disable(id));
        assert!(!m.find(id).unwrap().enabled);
        assert!(m.enable(id));
        assert!(m.find(id).unwrap().enabled);
    }

    #[test]
    fn test_on_memory_write_fires() {
        let mut m = mgr();
        m.add_write(0x1000, 8);
        let hits = m.on_memory_write(pos(), 0x1000, &[0xAA; 8]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].access_kind, AccessKind::Write);
    }

    #[test]
    fn test_on_memory_write_no_match() {
        let mut m = mgr();
        m.add_write(0x1000, 8);
        let hits = m.on_memory_write(pos(), 0x2000, &[0x00; 4]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_on_memory_write_partial_overlap() {
        let mut m = mgr();
        m.add_write(0x1000, 8);
        // Access starts at 0x1007 — overlaps by 1 byte
        let hits = m.on_memory_write(pos(), 0x1007, &[0xFF; 4]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_hit_count_increments() {
        let mut m = mgr();
        let id = m.add_write(0x1000, 4);
        m.on_memory_write(pos(), 0x1000, &[1, 2, 3, 4]);
        m.on_memory_write(pos(), 0x1000, &[5, 6, 7, 8]);
        assert_eq!(m.find(id).unwrap().hit_count, 2);
    }

    #[test]
    fn test_one_shot_disables_after_hit() {
        let mut m = mgr();
        let wp = TtdWatchpoint::new(1, 0x1000, 4, WatchpointKind::Write).one_shot();
        m.add(wp);
        m.on_memory_write(pos(), 0x1000, &[0; 4]);
        let hits2 = m.on_memory_write(pos(), 0x1000, &[1; 4]);
        assert!(hits2.is_empty());
    }

    #[test]
    fn test_read_watchpoint() {
        let mut m = mgr();
        m.add_read(0x3000, 4);
        let hits = m.on_memory_read(pos(), 0x3000, 4);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].access_kind, AccessKind::Read);
    }

    #[test]
    fn test_readwrite_watchpoint_fires_on_write() {
        let mut m = mgr();
        m.add_readwrite(0x4000, 8);
        let hits = m.on_memory_write(pos(), 0x4000, &[0xFF; 4]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_readwrite_watchpoint_fires_on_read() {
        let mut m = mgr();
        m.add_readwrite(0x4000, 8);
        let hits = m.on_memory_read(pos(), 0x4002, 4);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_write_wp_does_not_fire_on_read() {
        let mut m = mgr();
        m.add_write(0x5000, 8);
        let hits = m.on_memory_read(pos(), 0x5000, 8);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_hit_log() {
        let mut m = mgr();
        m.add_write(0x1000, 4);
        m.on_memory_write(pos(), 0x1000, &[1, 2, 3, 4]);
        assert_eq!(m.hit_log().len(), 1);
    }

    #[test]
    fn test_total_hits() {
        let mut m = mgr();
        m.add_write(0x100, 4);
        m.add_write(0x200, 4);
        m.on_memory_write(pos(), 0x100, &[0; 4]);
        m.on_memory_write(pos(), 0x200, &[0; 4]);
        assert_eq!(m.total_hits(), 2);
    }

    #[test]
    fn test_hits_for() {
        let mut m = mgr();
        let id1 = m.add_write(0x100, 4);
        m.add_write(0x200, 4);
        m.on_memory_write(pos(), 0x100, &[0; 4]);
        m.on_memory_write(pos(), 0x200, &[0; 4]);
        m.on_memory_write(pos(), 0x100, &[1; 4]);
        assert_eq!(m.hits_for(id1).len(), 2);
    }

    #[test]
    fn test_overlapping() {
        let mut m = mgr();
        m.add_write(0x1000, 8);
        m.add_write(0x2000, 8);
        let ov = m.overlapping(0x1004, 4);
        assert_eq!(ov.len(), 1);
        assert_eq!(ov[0].address, 0x1000);
    }

    #[test]
    fn test_clear_all() {
        let mut m = mgr();
        m.add_write(0x1, 4);
        m.on_memory_write(pos(), 0x1, &[0; 4]);
        m.clear_all();
        assert_eq!(m.count(), 0);
        assert!(m.hit_log().is_empty());
    }

    #[test]
    fn test_clear_hit_log() {
        let mut m = mgr();
        m.add_write(0x1, 4);
        m.on_memory_write(pos(), 0x1, &[0; 4]);
        m.clear_hit_log();
        assert!(m.hit_log().is_empty());
    }

    #[test]
    fn test_watchpoint_display() {
        let wp = TtdWatchpoint::new(3, 0xabcd, 16, WatchpointKind::Write)
            .with_label("stack_cookie");
        let s = wp.to_string();
        assert!(s.contains("WP#3"));
        assert!(s.contains("stack_cookie"));
    }

    #[test]
    fn test_watchpoint_hit_display() {
        let h = WatchpointHit {
            wp_id: 2,
            position: pos(),
            address: 0x1234,
            size: 8,
            access_kind: AccessKind::Write,
            old_value: vec![0; 8],
            new_value: vec![1; 8],
            hit_number: 1,
        };
        let s = h.to_string();
        assert!(s.contains("WP#2"));
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn test_conditional_watchpoint() {
        let mut m = mgr();
        // Only fire if memory at 0x8000 equals [0xAA]
        let wp = TtdWatchpoint::new(1, 0x1000, 4, WatchpointKind::Write)
            .with_condition(0x8000, vec![0xAA]);
        m.add(wp);
        // Condition not met (memory at 0x8000 is zero-initialized)
        let hits = m.on_memory_write(pos(), 0x1000, &[0; 4]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_update_memory() {
        let mut m = mgr();
        let mut new_mem = MemoryState::new();
        new_mem.apply_write(0x5000, &[1, 2, 3, 4]);
        m.update_memory(new_mem);
        // Just ensure it doesn't panic and count unchanged
        assert_eq!(m.count(), 0);
    }
}
