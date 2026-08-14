//! `TSan` (Thread Sanitizer) model.
//!
//! Pure-Rust happens-before data-race detector and lock-order graph for
//! deadlock detection, without requiring any real `TSan` instrumentation.
//!
//! The model is sufficient for testing race detectors, writing property-based
//! tests, and understanding `TSan`'s algorithm.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
pub use std::sync::Arc;
pub use std::sync::atomic::{AtomicU64, Ordering};

// ─── ThreadId ─────────────────────────────────────────────────────────────────

/// Opaque thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(pub u32);

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}", self.0)
    }
}

// ─── VectorClock ──────────────────────────────────────────────────────────────

/// A vector clock (happens-before relation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VectorClock {
    /// Per-thread timestamp.
    clocks: BTreeMap<ThreadId, u64>,
}

impl VectorClock {
    /// Create an empty clock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the timestamp for thread `tid`.
    #[must_use]
    pub fn get(&self, tid: ThreadId) -> u64 {
        self.clocks.get(&tid).copied().unwrap_or(0)
    }

    /// Increment the timestamp for thread `tid`.
    pub fn tick(&mut self, tid: ThreadId) {
        *self.clocks.entry(tid).or_insert(0) += 1;
    }

    /// Merge with `other` by taking the element-wise maximum.
    pub fn join(&mut self, other: &Self) {
        for (&tid, &ts) in &other.clocks {
            let entry = self.clocks.entry(tid).or_insert(0);
            *entry = (*entry).max(ts);
        }
    }

    /// Return `true` if `self` happens-before or equals `other` (`self <= other`).
    #[must_use]
    pub fn happens_before(&self, other: &Self) -> bool {
        // For all tid: self[tid] <= other[tid]
        for (&tid, &ts) in &self.clocks {
            if ts > other.get(tid) {
                return false;
            }
        }
        true
    }

    /// Return `true` if neither `self <= other` nor `other <= self`.
    #[must_use]
    pub fn is_concurrent_with(&self, other: &Self) -> bool {
        !self.happens_before(other) && !other.happens_before(self)
    }
}

// ─── AccessEvent ──────────────────────────────────────────────────────────────

/// A memory access event (read or write) by a thread.
#[derive(Debug, Clone)]
pub struct AccessEvent {
    /// Which thread performed the access.
    pub thread_id: ThreadId,
    /// Whether this is a write (false = read).
    pub is_write: bool,
    /// Size of the access in bytes.
    pub size: usize,
    /// Vector clock at the time of access.
    pub clock: VectorClock,
}

impl AccessEvent {
    /// Create an event.
    #[must_use]
    pub const fn new(thread_id: ThreadId, is_write: bool, size: usize, clock: VectorClock) -> Self {
        Self {
            thread_id,
            is_write,
            size,
            clock,
        }
    }
}

// ─── AccessHistory ────────────────────────────────────────────────────────────

/// Per-memory-location access history.
///
/// Stores a bounded history of recent accesses for race detection.
#[derive(Debug, Clone)]
pub struct AccessHistory {
    /// Recent accesses (most recent first).
    events: VecDeque<AccessEvent>,
    /// Maximum history length.
    pub max_len: usize,
}

impl Default for AccessHistory {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            max_len: Self::DEFAULT_MAX,
        }
    }
}

impl AccessHistory {
    /// Default history depth.
    pub const DEFAULT_MAX: usize = 4;

    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an access.
    pub fn record(&mut self, event: AccessEvent) {
        self.events.push_front(event);
        if self.events.len() > self.max_len {
            self.events.pop_back();
        }
    }

    /// Return all stored events.
    #[must_use]
    pub const fn events(&self) -> &VecDeque<AccessEvent> {
        &self.events
    }
}

// ─── ThreadState ──────────────────────────────────────────────────────────────

/// State of a single thread in the `TSan` model.
#[derive(Debug, Clone)]
pub struct ThreadState {
    /// Thread ID.
    pub id: ThreadId,
    /// Current vector clock of this thread.
    pub clock: VectorClock,
    /// Set of locks currently held by this thread.
    pub held_locks: HashSet<u64>,
    /// Whether the thread is active (not yet joined).
    pub active: bool,
}

impl ThreadState {
    /// Create a new thread state with a zero clock.
    #[must_use]
    pub fn new(id: ThreadId) -> Self {
        let mut clock = VectorClock::new();
        clock.tick(id);
        Self {
            id,
            clock,
            held_locks: HashSet::new(),
            active: true,
        }
    }

    /// Tick this thread's own clock.
    pub fn tick(&mut self) {
        self.clock.tick(self.id);
    }

    /// Acquire `lock_addr`.
    pub fn lock_acquire(&mut self, lock_addr: u64) {
        self.held_locks.insert(lock_addr);
    }

    /// Release `lock_addr`.
    pub fn lock_release(&mut self, lock_addr: u64) {
        self.held_locks.remove(&lock_addr);
    }
}

// ─── LockState ────────────────────────────────────────────────────────────────

/// State of a single lock.
#[derive(Debug, Clone, Default)]
pub struct LockState {
    /// Lock address.
    pub addr: u64,
    /// Thread currently holding the lock (None = unlocked).
    pub owner: Option<ThreadId>,
    /// Vector clock at the moment of last unlock (for sync).
    pub release_clock: VectorClock,
    /// Total acquire count.
    pub acquire_count: u64,
}

impl LockState {
    /// Create a new unlocked lock.
    #[must_use]
    pub fn new(addr: u64) -> Self {
        Self {
            addr,
            ..Default::default()
        }
    }

    /// Return `true` if the lock is currently held.
    #[must_use]
    pub const fn is_held(&self) -> bool {
        self.owner.is_some()
    }
}

// ─── DataRaceDetector ─────────────────────────────────────────────────────────

/// Happens-before data-race detector.
///
/// Tracks per-address access histories and vector clocks to detect races.
#[derive(Debug, Default)]
pub struct DataRaceDetector {
    /// Thread states, by ID.
    threads: HashMap<ThreadId, ThreadState>,
    /// Per-address access history.
    access_history: HashMap<u64, AccessHistory>,
    /// Detected races.
    pub races: Vec<TsanReport>,
    /// Lock states.
    locks: HashMap<u64, LockState>,
}

impl DataRaceDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create or return a thread.
    pub fn create_thread(&mut self, id: ThreadId) {
        self.threads
            .entry(id)
            .or_insert_with(|| ThreadState::new(id));
    }

    /// Record a memory access.  Returns `true` if a race is detected.
    pub fn access(&mut self, tid: ThreadId, addr: u64, is_write: bool, size: usize) -> bool {
        // Ensure thread exists
        self.threads
            .entry(tid)
            .or_insert_with(|| ThreadState::new(tid));
        let thread_clock = self.threads[&tid].clock.clone();

        let history = self.access_history.entry(addr).or_default();

        let mut race = false;
        for prev in history.events() {
            // A race requires: different threads, at least one write,
            // and concurrent vector clocks (neither happens-before the other).
            if prev.thread_id != tid
                && (is_write || prev.is_write)
                && thread_clock.is_concurrent_with(&prev.clock)
            {
                let report =
                    TsanReport::new_race(tid, prev.thread_id, addr, is_write, prev.is_write);
                self.races.push(report);
                race = true;
                break; // report one race per access
            }
        }

        // Record this access
        let event = AccessEvent::new(tid, is_write, size, thread_clock);
        self.access_history.entry(addr).or_default().record(event);

        // Tick thread clock
        if let Some(t) = self.threads.get_mut(&tid) {
            t.tick();
        }

        race
    }

    /// Simulate a lock acquire: thread `tid` acquires `lock_addr`.
    pub fn lock_acquire(&mut self, tid: ThreadId, lock_addr: u64) {
        self.threads
            .entry(tid)
            .or_insert_with(|| ThreadState::new(tid));
        let lock = self
            .locks
            .entry(lock_addr)
            .or_insert_with(|| LockState::new(lock_addr));
        // Sync thread clock with lock's release clock
        let release_clock = lock.release_clock.clone();
        lock.owner = Some(tid);
        lock.acquire_count += 1;
        if let Some(t) = self.threads.get_mut(&tid) {
            t.clock.join(&release_clock);
            t.lock_acquire(lock_addr);
        }
    }

    /// Simulate a lock release.
    pub fn lock_release(&mut self, tid: ThreadId, lock_addr: u64) {
        let thread_clock = self
            .threads
            .get(&tid)
            .map(|t| t.clock.clone())
            .unwrap_or_default();
        if let Some(lock) = self.locks.get_mut(&lock_addr) {
            lock.owner = None;
            lock.release_clock = thread_clock;
        }
        if let Some(t) = self.threads.get_mut(&tid) {
            t.lock_release(lock_addr);
            t.tick();
        }
    }

    /// Simulate a thread synchronisation (join / signal).
    pub fn sync(&mut self, from: ThreadId, to: ThreadId) {
        let from_clock = self.threads.get(&from).map(|t| t.clock.clone());
        if let (Some(clock), Some(to_thread)) = (from_clock, self.threads.get_mut(&to)) {
            to_thread.clock.join(&clock);
        }
    }

    /// Number of detected races.
    #[must_use]
    pub const fn race_count(&self) -> usize {
        self.races.len()
    }

    /// Clear races.
    pub fn clear_races(&mut self) {
        self.races.clear();
    }
}

// ─── LockOrder ────────────────────────────────────────────────────────────────

/// Lock-order graph for deadlock detection.
///
/// Records the order in which threads acquire locks.  If a cycle is detected,
/// a potential deadlock is reported.
#[derive(Debug, Default)]
pub struct LockOrder {
    /// `lock_a -> set<lock_b>`: `lock_a` was held when `lock_b` was acquired.
    edges: HashMap<u64, HashSet<u64>>,
    /// Detected cycles.
    pub cycles: Vec<Vec<u64>>,
}

impl LockOrder {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `lock_b` was acquired while `lock_a` was held.
    pub fn record_order(&mut self, lock_a: u64, lock_b: u64) {
        self.edges.entry(lock_a).or_default().insert(lock_b);
    }

    /// Record all lock-order pairs for a new acquisition of `lock_b` given
    /// that `held_locks` are currently held.
    pub fn record_acquisition(&mut self, held_locks: &HashSet<u64>, new_lock: u64) {
        for &held in held_locks {
            self.record_order(held, new_lock);
        }
        // After recording, check for cycles
        if let Some(cycle) = self.find_cycle()
            && !self.cycles.iter().any(|c| c == &cycle)
        {
            self.cycles.push(cycle);
        }
    }

    /// BFS cycle detection.
    ///
    /// # Panics
    ///
    /// Panics if a path popped from the BFS queue is empty (unreachable
    /// by construction since paths always start with a single node).
    #[must_use]
    pub fn find_cycle(&self) -> Option<Vec<u64>> {
        let nodes: Vec<u64> = self.edges.keys().copied().collect();
        for &start in &nodes {
            let mut visited: HashSet<u64> = HashSet::new();
            let mut queue: VecDeque<Vec<u64>> = VecDeque::new();
            queue.push_back(vec![start]);
            while let Some(path) = queue.pop_front() {
                let last = *path.last().unwrap();
                if let Some(nexts) = self.edges.get(&last) {
                    for &next in nexts {
                        if next == start {
                            let mut cycle = path;
                            cycle.push(next);
                            return Some(cycle);
                        }
                        if visited.insert(next) {
                            let mut new_path = path.clone();
                            new_path.push(next);
                            queue.push_back(new_path);
                        }
                    }
                }
            }
        }
        None
    }

    /// Number of lock-order edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(HashSet::len).sum()
    }
}

// ─── TsanReport ───────────────────────────────────────────────────────────────

/// A `TSan` report: data race or potential deadlock.
#[derive(Debug, Clone)]
pub enum TsanReport {
    /// Data race between two threads.
    DataRace {
        /// Thread performing the current access.
        current_thread: ThreadId,
        /// Thread that performed the conflicting access.
        prior_thread: ThreadId,
        /// Memory address.
        addr: u64,
        /// Whether the current access is a write.
        current_is_write: bool,
        /// Whether the prior access was a write.
        prior_is_write: bool,
    },
    /// Potential deadlock (lock-order cycle).
    PotentialDeadlock {
        /// Locks involved in the cycle.
        cycle: Vec<u64>,
    },
}

impl TsanReport {
    /// Create a data race report.
    #[must_use]
    pub const fn new_race(
        current: ThreadId,
        prior: ThreadId,
        addr: u64,
        cur_write: bool,
        prior_write: bool,
    ) -> Self {
        Self::DataRace {
            current_thread: current,
            prior_thread: prior,
            addr,
            current_is_write: cur_write,
            prior_is_write: prior_write,
        }
    }

    /// Create a deadlock report.
    #[must_use]
    pub const fn new_deadlock(cycle: Vec<u64>) -> Self {
        Self::PotentialDeadlock { cycle }
    }

    /// Is this a data race?
    #[must_use]
    pub const fn is_race(&self) -> bool {
        matches!(self, Self::DataRace { .. })
    }
}

impl fmt::Display for TsanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataRace {
                current_thread,
                prior_thread,
                addr,
                current_is_write,
                prior_is_write,
            } => {
                write!(
                    f,
                    "DATA RACE: {} {} on {:#x} (prior {} by {})",
                    current_thread,
                    if *current_is_write { "WRITE" } else { "READ" },
                    addr,
                    if *prior_is_write { "WRITE" } else { "READ" },
                    prior_thread
                )
            }
            Self::PotentialDeadlock { cycle } => {
                let s: Vec<String> = cycle.iter().map(|l| format!("{l:#x}")).collect();
                write!(f, "POTENTIAL DEADLOCK: {}", s.join(" → "))
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u32) -> ThreadId {
        ThreadId(n)
    }

    // ── VectorClock ───────────────────────────────────────────────────────────

    #[test]
    fn vector_clock_tick_and_get() {
        let mut vc = VectorClock::new();
        vc.tick(tid(0));
        vc.tick(tid(0));
        assert_eq!(vc.get(tid(0)), 2);
    }

    #[test]
    fn vector_clock_join() {
        let mut a = VectorClock::new();
        a.tick(tid(0)); // T0=1
        let mut b = VectorClock::new();
        b.tick(tid(1)); // T1=1
        a.join(&b);
        assert_eq!(a.get(tid(0)), 1);
        assert_eq!(a.get(tid(1)), 1);
    }

    #[test]
    fn vector_clock_happens_before() {
        let mut a = VectorClock::new();
        a.tick(tid(0));
        let mut b = VectorClock::new();
        b.tick(tid(0));
        b.tick(tid(0));
        assert!(a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn vector_clock_concurrent() {
        let mut a = VectorClock::new();
        a.tick(tid(0));
        let mut b = VectorClock::new();
        b.tick(tid(1));
        assert!(a.is_concurrent_with(&b));
    }

    // ── ThreadState ───────────────────────────────────────────────────────────

    #[test]
    fn thread_state_initial_clock() {
        let t = ThreadState::new(tid(0));
        assert_eq!(t.clock.get(tid(0)), 1);
    }

    #[test]
    fn thread_state_lock_acquire_release() {
        let mut t = ThreadState::new(tid(0));
        t.lock_acquire(0x1000);
        assert!(t.held_locks.contains(&0x1000));
        t.lock_release(0x1000);
        assert!(!t.held_locks.contains(&0x1000));
    }

    // ── AccessHistory ────────────────────────────────────────────────────────

    #[test]
    fn access_history_bounded() {
        let mut h = AccessHistory::new();
        h.max_len = 2;
        for i in 0..5u32 {
            h.record(AccessEvent::new(tid(i), true, 4, VectorClock::new()));
        }
        assert_eq!(h.events().len(), 2);
    }

    // ── DataRaceDetector ──────────────────────────────────────────────────────

    #[test]
    fn race_detector_detects_race() {
        let mut d = DataRaceDetector::new();
        d.create_thread(tid(0));
        d.create_thread(tid(1));
        // T0 writes to addr 0x1000
        d.access(tid(0), 0x1000, true, 4);
        // T1 reads from addr 0x1000 — concurrent → race
        let race = d.access(tid(1), 0x1000, false, 4);
        assert!(race);
        assert!(d.race_count() > 0);
    }

    #[test]
    fn race_detector_no_race_with_sync() {
        let mut d = DataRaceDetector::new();
        d.create_thread(tid(0));
        d.create_thread(tid(1));
        // T0 writes
        d.access(tid(0), 0x2000, true, 4);
        // T0 → T1 sync (e.g. T0 joins T1, or signal)
        d.sync(tid(0), tid(1));
        // T1 reads — T0 happens-before T1, so no race
        let race = d.access(tid(1), 0x2000, false, 4);
        assert!(!race);
    }

    #[test]
    fn race_detector_lock_synchronises() {
        let mut d = DataRaceDetector::new();
        d.create_thread(tid(0));
        d.create_thread(tid(1));
        let lock = 0xDEAD_1234u64;
        // T0 acquires lock, writes, releases
        d.lock_acquire(tid(0), lock);
        d.access(tid(0), 0x3000, true, 8);
        d.lock_release(tid(0), lock);
        // T1 acquires lock (synchronises with T0's release), reads
        d.lock_acquire(tid(1), lock);
        let race = d.access(tid(1), 0x3000, false, 8);
        d.lock_release(tid(1), lock);
        assert!(!race, "lock should prevent race");
    }

    #[test]
    fn race_detector_clear_races() {
        let mut d = DataRaceDetector::new();
        d.create_thread(tid(0));
        d.create_thread(tid(1));
        d.access(tid(0), 0x4000, true, 4);
        d.access(tid(1), 0x4000, true, 4);
        assert!(d.race_count() > 0);
        d.clear_races();
        assert_eq!(d.race_count(), 0);
    }

    // ── LockOrder ─────────────────────────────────────────────────────────────

    #[test]
    fn lock_order_no_cycle() {
        let mut lo = LockOrder::new();
        lo.record_order(0x1, 0x2);
        lo.record_order(0x2, 0x3);
        // No cycle: 1→2→3 is a chain
        assert!(lo.find_cycle().is_none());
    }

    #[test]
    fn lock_order_detects_cycle() {
        let mut lo = LockOrder::new();
        lo.record_order(0x1, 0x2);
        lo.record_order(0x2, 0x1); // 1→2→1 cycle
        assert!(lo.find_cycle().is_some());
    }

    #[test]
    fn lock_order_edge_count() {
        let mut lo = LockOrder::new();
        lo.record_order(0x1, 0x2);
        lo.record_order(0x1, 0x3);
        assert_eq!(lo.edge_count(), 2);
    }

    #[test]
    fn lock_order_record_acquisition_detects_cycle() {
        let mut lo = LockOrder::new();
        // Thread A: acquire lock1, then lock2
        let mut held_a: HashSet<u64> = HashSet::new();
        held_a.insert(0x1);
        lo.record_acquisition(&held_a, 0x2);
        // Thread B: acquire lock2, then lock1 — creates cycle
        let mut held_b: HashSet<u64> = HashSet::new();
        held_b.insert(0x2);
        lo.record_acquisition(&held_b, 0x1);
        assert!(!lo.cycles.is_empty());
    }

    // ── TsanReport ───────────────────────────────────────────────────────────

    #[test]
    fn tsan_report_race_display() {
        let r = TsanReport::new_race(tid(0), tid(1), 0x1000, true, false);
        let s = r.to_string();
        assert!(s.contains("DATA RACE"));
        assert!(s.contains("WRITE"));
    }

    #[test]
    fn tsan_report_deadlock_display() {
        let r = TsanReport::new_deadlock(vec![0x1, 0x2, 0x1]);
        let s = r.to_string();
        assert!(s.contains("POTENTIAL DEADLOCK"));
    }

    #[test]
    fn tsan_report_is_race() {
        let r = TsanReport::new_race(tid(0), tid(1), 0, false, false);
        assert!(r.is_race());
        let d = TsanReport::new_deadlock(vec![]);
        assert!(!d.is_race());
    }

    #[test]
    fn thread_id_display() {
        assert_eq!(tid(3).to_string(), "T3");
    }
}
