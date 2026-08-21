//! Thread context recorder for TTD traces.
//!
//! Captures full x86-64 register state at configurable intervals, computes
//! deltas between snapshots, and supports time-travel restoration.

use std::collections::HashMap;

// ─── ThreadRegisters ─────────────────────────────────────────────────────────

/// Full set of general-purpose and segment registers for an x86-64 thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

impl ThreadRegisters {
    /// Read a register by name (case-insensitive).
    #[must_use]
    pub fn read(&self, name: &str) -> Option<u64> {
        match name.to_lowercase().as_str() {
            "rax" => Some(self.rax),
            "rbx" => Some(self.rbx),
            "rcx" => Some(self.rcx),
            "rdx" => Some(self.rdx),
            "rsi" => Some(self.rsi),
            "rdi" => Some(self.rdi),
            "rbp" => Some(self.rbp),
            "rsp" => Some(self.rsp),
            "rip" => Some(self.rip),
            "r8"  => Some(self.r8),
            "r9"  => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            "eflags" => Some(u64::from(self.eflags)),
            "cs" => Some(u64::from(self.cs)),
            "ds" => Some(u64::from(self.ds)),
            "es" => Some(u64::from(self.es)),
            "fs" => Some(u64::from(self.fs)),
            "gs" => Some(u64::from(self.gs)),
            "ss" => Some(u64::from(self.ss)),
            _ => None,
        }
    }

    /// Write a register by name.  Returns false if the name is unknown.
    #[must_use]
    pub fn write(&mut self, name: &str, value: u64) -> bool {
        match name.to_lowercase().as_str() {
            "rax" => { self.rax = value; true }
            "rbx" => { self.rbx = value; true }
            "rcx" => { self.rcx = value; true }
            "rdx" => { self.rdx = value; true }
            "rsi" => { self.rsi = value; true }
            "rdi" => { self.rdi = value; true }
            "rbp" => { self.rbp = value; true }
            "rsp" => { self.rsp = value; true }
            "rip" => { self.rip = value; true }
            "r8"  => { self.r8  = value; true }
            "r9"  => { self.r9  = value; true }
            "r10" => { self.r10 = value; true }
            "r11" => { self.r11 = value; true }
            "r12" => { self.r12 = value; true }
            "r13" => { self.r13 = value; true }
            "r14" => { self.r14 = value; true }
            "r15" => { self.r15 = value; true }
            "eflags" => { self.eflags = u32::try_from(value).unwrap_or(u32::MAX); true }
            "cs" => { self.cs = u16::try_from(value).unwrap_or(u16::MAX); true }
            "ds" => { self.ds = u16::try_from(value).unwrap_or(u16::MAX); true }
            "es" => { self.es = u16::try_from(value).unwrap_or(u16::MAX); true }
            "fs" => { self.fs = u16::try_from(value).unwrap_or(u16::MAX); true }
            "gs" => { self.gs = u16::try_from(value).unwrap_or(u16::MAX); true }
            "ss" => { self.ss = u16::try_from(value).unwrap_or(u16::MAX); true }
            _ => false,
        }
    }

    /// All register names in a consistent order.
    #[must_use]
    pub const fn register_names() -> &'static [&'static str] {
        &[
            "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
            "r8","r9","r10","r11","r12","r13","r14","r15",
            "eflags","cs","ds","es","fs","gs","ss",
        ]
    }
}

// ─── FpuState ────────────────────────────────────────────────────────────────

/// x87 FPU + SSE/AVX register state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpuState {
    pub fpu_cw: u16,
    pub fpu_sw: u16,
    pub fpu_tag: u16,
    pub fip: u64,
    pub fdp: u64,
    /// Eight 80-bit x87 ST registers (10 bytes each).
    pub st: [[u8; 10]; 8],
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    /// Sixteen 128-bit XMM registers.
    pub xmm: [[u8; 16]; 16],
}

impl Default for FpuState {
    fn default() -> Self {
        Self {
            fpu_cw: 0x037F,
            fpu_sw: 0,
            fpu_tag: 0xFFFF,
            fip: 0,
            fdp: 0,
            st: [[0u8; 10]; 8],
            mxcsr: 0x1F80,
            mxcsr_mask: 0xFFFF,
            xmm: [[0u8; 16]; 16],
        }
    }
}

impl FpuState {
    /// Return the XMM register as a pair of u64s (low, high).
    #[must_use]
    pub fn xmm_as_u64_pair(&self, idx: usize) -> (u64, u64) {
        let r = &self.xmm[idx % 16];
        let lo = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(r[8..16].try_into().unwrap());
        (lo, hi)
    }

    /// Compare two `FpuStates`; return list of changed XMM indices.
    #[must_use]
    pub fn changed_xmm(&self, other: &Self) -> Vec<u8> {
        (0..16u8)
            .filter(|&i| self.xmm[usize::from(i)] != other.xmm[usize::from(i)])
            .collect()
    }
}

// ─── ThreadContext ────────────────────────────────────────────────────────────

/// Complete architectural state of a thread at a single point in time.
#[derive(Debug, Clone)]
pub struct ThreadContext {
    pub thread_id: u32,
    pub process_id: u32,
    pub timestamp_ns: u64,
    pub regs: ThreadRegisters,
    pub float_state: FpuState,
}

impl ThreadContext {
    #[must_use]
    pub fn new(thread_id: u32, process_id: u32, timestamp_ns: u64) -> Self {
        Self {
            thread_id,
            process_id,
            timestamp_ns,
            regs: ThreadRegisters::default(),
            float_state: FpuState::default(),
        }
    }
}

// ─── ContextDelta ────────────────────────────────────────────────────────────

/// Compact representation of the difference between two `ThreadContext`s.
#[derive(Debug, Clone, Default)]
pub struct ContextDelta {
    pub thread_id: u32,
    /// Changed GPR/segment register (name, new value).
    pub changed_regs: Vec<(String, u64)>,
    /// Changed XMM register (index, new 16-byte value).
    pub changed_xmm: Vec<(u8, [u8; 16])>,
    pub timestamp_before_ns: u64,
    pub timestamp_after_ns: u64,
}

/// Compute the delta from `before` to `after`.
#[must_use]
pub fn compute_delta(before: &ThreadContext, after: &ThreadContext) -> ContextDelta {
    let mut delta = ContextDelta {
        thread_id: after.thread_id,
        timestamp_before_ns: before.timestamp_ns,
        timestamp_after_ns: after.timestamp_ns,
        ..Default::default()
    };

    for name in ThreadRegisters::register_names() {
        let v_before = before.regs.read(name).unwrap_or(0);
        let v_after = after.regs.read(name).unwrap_or(0);
        if v_before != v_after {
            delta.changed_regs.push((name.to_string(), v_after));
        }
    }

    for idx in 0..16u8 {
        if before.float_state.xmm[usize::from(idx)] != after.float_state.xmm[usize::from(idx)] {
            delta.changed_xmm.push((idx, after.float_state.xmm[usize::from(idx)]));
        }
    }

    delta
}

/// Apply a delta onto a mutable base context (forward application).
pub fn apply_delta(base: &mut ThreadContext, delta: &ContextDelta) {
    for (name, value) in &delta.changed_regs {
        let _ = base.regs.write(name, *value);
    }
    for (idx, xmm_val) in &delta.changed_xmm {
        base.float_state.xmm[usize::from(*idx)] = *xmm_val;
    }
    base.timestamp_ns = delta.timestamp_after_ns;
}

const fn u64_to_f64_lossy(v: u64) -> f64 {
    v as f64
}

const fn i64_to_f64_lossy(v: i64) -> f64 {
    v as f64
}

const fn f64_to_u64_lossy(v: f64) -> u64 {
    v as u64
}

/// Linear interpolation of a single register value between two contexts.
///
/// Returns the before value if `ts` is at or before `t1.timestamp_ns`,
/// the after value if at or beyond `t2.timestamp_ns`, or a linearly
/// blended u64 otherwise.
#[must_use]
pub fn interpolate_reg(reg: &str, t1: &ThreadContext, t2: &ThreadContext, ts: u64) -> u64 {
    let v1 = t1.regs.read(reg).unwrap_or(0);
    let v2 = t2.regs.read(reg).unwrap_or(0);
    if ts <= t1.timestamp_ns || t2.timestamp_ns <= t1.timestamp_ns {
        return v1;
    }
    if ts >= t2.timestamp_ns {
        return v2;
    }
    let span = t2.timestamp_ns - t1.timestamp_ns;
    let elapsed = ts - t1.timestamp_ns;
    // Linearly blend as i64 to handle wrap-arounds sensibly.
    let diff = (v2.cast_signed()).wrapping_sub(v1.cast_signed());
    let frac = u64_to_f64_lossy(elapsed) / u64_to_f64_lossy(span);
    v1.wrapping_add(f64_to_u64_lossy(i64_to_f64_lossy(diff) * frac))
}

// ─── ContextStore ────────────────────────────────────────────────────────────

/// Stores periodically-snapshotted thread contexts and allows time-travel
/// restoration and delta reconstruction.
pub struct ContextStore {
    /// All snapshots, sorted by `timestamp_ns`.
    snapshots: Vec<ThreadContext>,
    /// Snapshot interval in nanoseconds.
    pub interval_ns: u64,
    /// Maximum number of snapshots retained before oldest are evicted.
    pub max_snapshots: usize,
    /// Accumulated deltas (index = gap between consecutive snapshots).
    deltas: Vec<ContextDelta>,
}

impl ContextStore {
    #[must_use]
    pub const fn new(interval_ns: u64, max_snapshots: usize) -> Self {
        Self {
            snapshots: Vec::new(),
            interval_ns,
            max_snapshots,
            deltas: Vec::new(),
        }
    }

    /// Record a new context snapshot.
    pub fn record_context(&mut self, ctx: ThreadContext) {
        // Compute delta from last snapshot for same thread.
        if let Some(prev) = self.snapshots.iter().rev()
            .find(|s| s.thread_id == ctx.thread_id)
        {
            let delta = compute_delta(prev, &ctx);
            self.deltas.push(delta);
        }

        self.snapshots.push(ctx);
        self.snapshots.sort_by_key(|s| s.timestamp_ns);

        // Evict oldest if over limit.
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }
    }

    /// Find the nearest snapshot at or before `timestamp_ns` for any thread.
    #[must_use]
    pub fn restore_at(&self, timestamp_ns: u64) -> Option<ThreadContext> {
        self.snapshots.iter().rfind(|s| s.timestamp_ns <= timestamp_ns)
            .cloned()
    }

    /// Find the nearest snapshot at or before `timestamp_ns` for a specific thread.
    #[must_use]
    pub fn restore_thread_at(&self, thread_id: u32, timestamp_ns: u64) -> Option<ThreadContext> {
        self.snapshots.iter().rfind(|s| s.thread_id == thread_id && s.timestamp_ns <= timestamp_ns)
            .cloned()
    }

    /// Find the two snapshots bracketing `timestamp_ns` for a thread and
    /// interpolate the named register.
    #[must_use]
    pub fn interpolate_at(&self, thread_id: u32, reg: &str, timestamp_ns: u64) -> Option<u64> {
        let thread_snaps: Vec<&ThreadContext> = self.snapshots.iter()
            .filter(|s| s.thread_id == thread_id)
            .collect();

        if thread_snaps.is_empty() {
            return None;
        }

        // Find bracketing pair.
        let before = thread_snaps.iter().rev()
            .find(|&&s| s.timestamp_ns <= timestamp_ns)?;
        let after = thread_snaps.iter()
            .find(|&&s| s.timestamp_ns > timestamp_ns);

        after.map_or_else(
            || before.regs.read(reg),
            |a| Some(interpolate_reg(reg, before, a, timestamp_ns)),
        )
    }

    /// Return all snapshots for a given thread, sorted by time.
    #[must_use]
    pub fn snapshots_for_thread(&self, thread_id: u32) -> Vec<&ThreadContext> {
        self.snapshots.iter()
            .filter(|s| s.thread_id == thread_id)
            .collect()
    }

    /// Return the total number of snapshots held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.snapshots.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Return all deltas computed so far.
    #[must_use]
    pub fn deltas(&self) -> &[ContextDelta] {
        &self.deltas
    }

    /// Reconstruct the context at `timestamp_ns` by replaying deltas forward
    /// from the nearest earlier snapshot.
    #[must_use]
    pub fn reconstruct_at(&self, thread_id: u32, timestamp_ns: u64) -> Option<ThreadContext> {
        let mut base = self.restore_thread_at(thread_id, timestamp_ns)?;
        // Apply any deltas whose after-timestamp <= target and > base snapshot time.
        let base_ts = base.timestamp_ns;
        for delta in &self.deltas {
            if delta.thread_id == thread_id
                && delta.timestamp_before_ns >= base_ts
                && delta.timestamp_after_ns <= timestamp_ns
            {
                apply_delta(&mut base, delta);
            }
        }
        Some(base)
    }

    /// Find the first snapshot where a register equals a given value.
    #[must_use]
    pub fn find_reg_value(&self, thread_id: u32, reg: &str, value: u64) -> Option<&ThreadContext> {
        self.snapshots.iter()
            .filter(|s| s.thread_id == thread_id)
            .find(|s| s.regs.read(reg) == Some(value))
    }

    /// Return summary stats: min/max/avg value of a register across all snapshots of a thread.
    #[must_use]
    pub fn reg_stats(&self, thread_id: u32, reg: &str) -> Option<(u64, u64, f64)> {
        let vals: Vec<u64> = self.snapshots.iter()
            .filter(|s| s.thread_id == thread_id)
            .filter_map(|s| s.regs.read(reg))
            .collect();
        if vals.is_empty() {
            return None;
        }
        let min = *vals.iter().min().unwrap();
        let max = *vals.iter().max().unwrap();
        let avg = u64_to_f64_lossy(vals.iter().copied().sum::<u64>())
            / u64_to_f64_lossy(u64::try_from(vals.len()).unwrap_or(u64::MAX));
        Some((min, max, avg))
    }
}

// ─── ThreadContextRecorder ────────────────────────────────────────────────────

/// High-level recorder that manages per-thread stores and decides when to
/// snapshot based on time intervals.
pub struct ThreadContextRecorder {
    stores: HashMap<u32, ContextStore>,
    interval_ns: u64,
    max_snapshots_per_thread: usize,
    last_snapshot_ns: HashMap<u32, u64>,
}

impl ThreadContextRecorder {
    #[must_use]
    pub fn new(interval_ns: u64, max_snapshots_per_thread: usize) -> Self {
        Self {
            stores: HashMap::new(),
            interval_ns,
            max_snapshots_per_thread,
            last_snapshot_ns: HashMap::new(),
        }
    }

    /// Offer a context for recording.  Snapshots when interval has elapsed.
    pub fn offer(&mut self, ctx: ThreadContext) {
        let tid = ctx.thread_id;
        let ts = ctx.timestamp_ns;
        let last = self.last_snapshot_ns.get(&tid).copied().unwrap_or(0);
        if ts.saturating_sub(last) >= self.interval_ns || last == 0 {
            let store = self.stores.entry(tid).or_insert_with(|| {
                ContextStore::new(self.interval_ns, self.max_snapshots_per_thread)
            });
            store.record_context(ctx);
            self.last_snapshot_ns.insert(tid, ts);
        }
    }

    /// Force a snapshot regardless of interval.
    pub fn force_snapshot(&mut self, ctx: ThreadContext) {
        let tid = ctx.thread_id;
        let ts = ctx.timestamp_ns;
        let store = self.stores.entry(tid).or_insert_with(|| {
            ContextStore::new(self.interval_ns, self.max_snapshots_per_thread)
        });
        store.record_context(ctx);
        self.last_snapshot_ns.insert(tid, ts);
    }

    /// Restore the context of a thread at a given timestamp.
    #[must_use]
    pub fn restore(&self, thread_id: u32, timestamp_ns: u64) -> Option<ThreadContext> {
        self.stores.get(&thread_id)?.restore_at(timestamp_ns)
    }

    /// Return all known thread IDs.
    #[must_use]
    pub fn thread_ids(&self) -> Vec<u32> {
        self.stores.keys().copied().collect()
    }

    /// Total snapshots across all threads.
    #[must_use]
    pub fn total_snapshots(&self) -> usize {
        self.stores.values().map(ContextStore::len).sum()
    }

    #[must_use]
    pub fn store_for(&self, thread_id: u32) -> Option<&ContextStore> {
        self.stores.get(&thread_id)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(tid: u32, pid: u32, ts: u64, rip: u64, rsp: u64) -> ThreadContext {
        let mut ctx = ThreadContext::new(tid, pid, ts);
        ctx.regs.rip = rip;
        ctx.regs.rsp = rsp;
        ctx
    }

    #[test]
    fn test_register_read_write() {
        let mut regs = ThreadRegisters::default();
        regs.rax = 0xDEAD_BEEF;
        assert_eq!(regs.read("rax"), Some(0xDEAD_BEEF));
        assert!(regs.write("rbx", 0x1234));
        assert_eq!(regs.rbx, 0x1234);
    }

    #[test]
    fn test_register_names_all_readable() {
        let regs = ThreadRegisters::default();
        for name in ThreadRegisters::register_names() {
            assert!(regs.read(name).is_some(), "register {name} unreadable");
        }
    }

    #[test]
    fn test_unknown_register() {
        let regs = ThreadRegisters::default();
        assert_eq!(regs.read("zz99"), None);
    }

    #[test]
    fn test_fpu_xmm_as_u64_pair() {
        let mut fpu = FpuState::default();
        fpu.xmm[0] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (lo, hi) = fpu.xmm_as_u64_pair(0);
        assert_eq!(lo, 1);
        assert_eq!(hi, 2);
    }

    #[test]
    fn test_compute_delta_rip_changed() {
        let before = make_ctx(1, 100, 1000, 0x1000, 0x7FFF_0000);
        let after  = make_ctx(1, 100, 2000, 0x1010, 0x7FFF_0000);
        let delta = compute_delta(&before, &after);
        assert_eq!(delta.thread_id, 1);
        let rip_entry = delta.changed_regs.iter().find(|(n, _)| n == "rip");
        assert!(rip_entry.is_some());
        assert_eq!(rip_entry.unwrap().1, 0x1010);
        // rsp unchanged, so not in delta
        assert!(!delta.changed_regs.iter().any(|(n, _)| n == "rsp"));
    }

    #[test]
    fn test_apply_delta() {
        let before = make_ctx(1, 100, 1000, 0x1000, 0x7FFF_0000);
        let after  = make_ctx(1, 100, 2000, 0x1010, 0x7FFF_0008);
        let delta = compute_delta(&before, &after);
        let mut reconstructed = before;
        apply_delta(&mut reconstructed, &delta);
        assert_eq!(reconstructed.regs.rip, 0x1010);
        assert_eq!(reconstructed.regs.rsp, 0x7FFF_0008);
        assert_eq!(reconstructed.timestamp_ns, 2000);
    }

    #[test]
    fn test_interpolate_reg_midpoint() {
        let t1 = make_ctx(1, 100, 1000, 0x1000, 0x2000);
        let t2 = make_ctx(1, 100, 3000, 0x2000, 0x2000);
        let midpoint = 2000u64;
        let v = interpolate_reg("rip", &t1, &t2, midpoint);
        // At midpoint should be halfway between 0x1000 and 0x2000
        assert!((0x1000..=0x2000).contains(&v));
    }

    #[test]
    fn test_interpolate_reg_at_boundary() {
        let t1 = make_ctx(1, 100, 1000, 0x1000, 0);
        let t2 = make_ctx(1, 100, 2000, 0x2000, 0);
        assert_eq!(interpolate_reg("rip", &t1, &t2, 1000), 0x1000);
        assert_eq!(interpolate_reg("rip", &t1, &t2, 2000), 0x2000);
    }

    #[test]
    fn test_context_store_record_and_restore() {
        let mut store = ContextStore::new(1_000, 100);
        for ts in [1000u64, 2000, 3000, 4000] {
            store.record_context(make_ctx(1, 100, ts, ts, 0));
        }
        let ctx = store.restore_at(2500).unwrap();
        assert_eq!(ctx.timestamp_ns, 2000);
    }

    #[test]
    fn test_context_store_restore_none_before_all() {
        let mut store = ContextStore::new(1_000, 100);
        store.record_context(make_ctx(1, 100, 5000, 0x1000, 0));
        assert!(store.restore_at(1000).is_none());
    }

    #[test]
    fn test_context_store_max_snapshots() {
        let mut store = ContextStore::new(100, 5);
        for i in 0u64..10 {
            store.record_context(make_ctx(1, 100, i * 100, i * 0x10, 0));
        }
        assert!(store.len() <= 5);
    }

    #[test]
    fn test_context_store_delta_count() {
        let mut store = ContextStore::new(100, 100);
        for i in 0u64..5 {
            store.record_context(make_ctx(1, 100, i * 1000, i * 0x10, 0));
        }
        // 5 snapshots → 4 deltas
        assert_eq!(store.deltas().len(), 4);
    }

    #[test]
    fn test_context_store_reg_stats() {
        let mut store = ContextStore::new(100, 100);
        for i in 0u64..4 {
            let mut ctx = ThreadContext::new(1, 100, i * 1000);
            ctx.regs.rax = i * 100;
            store.record_context(ctx);
        }
        let (min, max, avg) = store.reg_stats(1, "rax").unwrap();
        assert_eq!(min, 0);
        assert_eq!(max, 300);
        assert!((avg - 150.0).abs() < 0.001);
    }

    #[test]
    fn test_thread_context_recorder_interval() {
        let mut rec = ThreadContextRecorder::new(1000, 50);
        // Two contexts 500 ns apart — only first should be recorded.
        rec.offer(make_ctx(1, 100, 0, 0x1000, 0));
        rec.offer(make_ctx(1, 100, 500, 0x1010, 0));
        rec.offer(make_ctx(1, 100, 1200, 0x1020, 0));
        let store = rec.store_for(1).unwrap();
        // Snapshots at t=0 and t=1200
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_thread_context_recorder_force_snapshot() {
        let mut rec = ThreadContextRecorder::new(10_000, 50);
        rec.force_snapshot(make_ctx(1, 100, 0, 0, 0));
        rec.force_snapshot(make_ctx(1, 100, 100, 0, 0)); // within interval but forced
        assert_eq!(rec.total_snapshots(), 2);
    }

    #[test]
    fn test_fpu_changed_xmm() {
        let a = FpuState::default();
        let mut b = FpuState::default();
        b.xmm[3][0] = 0xFF;
        b.xmm[7][0] = 0xAA;
        let changed = a.changed_xmm(&b);
        assert_eq!(changed, vec![3, 7]);
        // Symmetry
        let changed2 = b.changed_xmm(&a);
        assert_eq!(changed2, vec![3, 7]);
        // Self-compare
        assert!(a.changed_xmm(&a).is_empty());
    }
}
