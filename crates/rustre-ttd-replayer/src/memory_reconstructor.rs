// Memory State Reconstructor — reconstructs the memory contents at any tick
// using an efficient delta chain with page-granular snapshots.
//
// Design:
//   * The trace is divided into segments of `SEGMENT_LEN` events.
//   * For each segment boundary a full page-set snapshot is persisted.
//   * To read memory at tick T: load the nearest preceding snapshot, then
//     replay only the memory writes from that snapshot's tick to T.
//   * Pages are represented as 4 KiB byte arrays for alignment with OS.
//   * A compact DeltaEntry stores (tick, addr, size, new_bytes) for write ops.

use std::collections::BTreeMap;

pub type Tick = u64;
pub type Addr = u64;

// ── Page ─────────────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

#[derive(Clone)]
pub struct Page(Box<[u8; PAGE_SIZE]>);

impl Page {
    #[must_use] 
    pub fn new() -> Self { Self(Box::new([0u8; PAGE_SIZE])) }
    #[must_use] 
    pub fn data(&self) -> &[u8; PAGE_SIZE] { &self.0 }
    pub fn data_mut(&mut self) -> &mut [u8; PAGE_SIZE] { &mut self.0 }
    #[must_use] 
    pub fn read_byte(&self, offset: usize) -> u8 { self.0[offset] }
    pub fn write_byte(&mut self, offset: usize, val: u8) { self.0[offset] = val; }
    #[must_use] 
    pub fn read_u64_le(&self, offset: usize) -> u64 {
        // Guard: offset + 8 must be within the page to avoid a panic.
        if offset + 8 > PAGE_SIZE {
            return 0;
        }
        u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap_or([0; 8]))
    }
    pub fn write_u64_le(&mut self, offset: usize, val: u64) {
        // Guard: offset + 8 must be within the page to avoid a panic.
        if offset + 8 > PAGE_SIZE {
            return;
        }
        self.0[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
    }
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Page({PAGE_SIZE} bytes)")
    }
}

impl Default for Page { fn default() -> Self { Self::new() } }

// ── PageSet — sparse address space ──────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct PageSet {
    pub pages: BTreeMap<Addr, Page>,
}

impl PageSet {
    const fn page_base(addr: Addr) -> Addr { addr & PAGE_MASK }
    const fn page_offset(addr: Addr) -> usize { (addr & (PAGE_SIZE as u64 - 1)) as usize }

    #[must_use] 
    pub fn read_byte(&self, addr: Addr) -> u8 {
        let base = Self::page_base(addr);
        let off = Self::page_offset(addr);
        self.pages.get(&base).map_or(0, |p| p.read_byte(off))
    }

    pub fn write_byte(&mut self, addr: Addr, val: u8) {
        let base = Self::page_base(addr);
        let off = Self::page_offset(addr);
        self.pages.entry(base).or_default().write_byte(off, val);
    }

    #[must_use] 
    pub fn read_slice(&self, addr: Addr, len: usize) -> Vec<u8> {
        (0..len as u64).map(|i| self.read_byte(addr + i)).collect()
    }

    pub fn write_slice(&mut self, addr: Addr, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.write_byte(addr + i as u64, b);
        }
    }

    #[must_use] 
    pub fn read_u64_le(&self, addr: Addr) -> u64 {
        let bytes: [u8; 8] = self.read_slice(addr, 8).try_into().unwrap_or([0; 8]);
        u64::from_le_bytes(bytes)
    }

    #[must_use] 
    pub fn read_u32_le(&self, addr: Addr) -> u32 {
        let bytes: [u8; 4] = self.read_slice(addr, 4).try_into().unwrap_or([0; 4]);
        u32::from_le_bytes(bytes)
    }

    #[must_use] 
    pub fn read_u16_le(&self, addr: Addr) -> u16 {
        let bytes: [u8; 2] = self.read_slice(addr, 2).try_into().unwrap_or([0; 2]);
        u16::from_le_bytes(bytes)
    }

    pub fn write_u64_le(&mut self, addr: Addr, val: u64) {
        self.write_slice(addr, &val.to_le_bytes());
    }

    pub fn write_u32_le(&mut self, addr: Addr, val: u32) {
        self.write_slice(addr, &val.to_le_bytes());
    }

    #[must_use] 
    pub fn mapped_pages(&self) -> usize { self.pages.len() }

    #[must_use] 
    pub fn mapped_bytes(&self) -> u64 { self.pages.len() as u64 * PAGE_SIZE as u64 }

    /// Diff two snapshots; returns (addr, old, new) for changed bytes.
    #[must_use] 
    pub fn diff(&self, other: &Self) -> Vec<(Addr, u8, u8)> {
        let mut diffs = Vec::new();
        let all_pages: std::collections::BTreeSet<Addr> = self.pages.keys()
            .chain(other.pages.keys()).copied().collect();
        for pa in all_pages {
            let old_page = self.pages.get(&pa);
            let new_page = other.pages.get(&pa);
            for off in 0..PAGE_SIZE {
                let ob = old_page.map_or(0, |p| p.read_byte(off));
                let nb = new_page.map_or(0, |p| p.read_byte(off));
                if ob != nb {
                    diffs.push((pa + off as u64, ob, nb));
                }
            }
        }
        diffs
    }
}

// ── Delta entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeltaEntry {
    pub tick: Tick,
    pub thread_id: u32,
    pub addr: Addr,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
}

impl DeltaEntry {
    #[must_use] 
    pub const fn size(&self) -> usize { self.new_bytes.len() }

    pub fn apply(&self, mem: &mut PageSet) {
        mem.write_slice(self.addr, &self.new_bytes);
    }

    pub fn unapply(&self, mem: &mut PageSet) {
        if !self.old_bytes.is_empty() {
            mem.write_slice(self.addr, &self.old_bytes);
        }
    }

    #[must_use] 
    pub const fn overlaps(&self, addr: Addr, len: usize) -> bool {
        // Use saturating_add to prevent u64 overflow when addr or size is near MAX.
        let end = self.addr.saturating_add(self.size() as u64);
        let q_end = addr.saturating_add(len as u64);
        self.addr < q_end && end > addr
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemoryCheckpoint {
    pub tick: Tick,
    pub memory: PageSet,
}

// ── Memory reconstructor ──────────────────────────────────────────────────────

pub struct MemoryReconstructor {
    /// Checkpoints indexed by tick.
    checkpoints: BTreeMap<Tick, MemoryCheckpoint>,
    /// All delta entries sorted by tick.
    deltas: Vec<DeltaEntry>,
    /// Segment length: a checkpoint is taken every this many ticks.
    pub segment_len: Tick,
    /// Statistics.
    pub stats: ReconstructorStats,
}

#[derive(Debug, Default, Clone)]
pub struct ReconstructorStats {
    pub checkpoints_taken: u64,
    pub checkpoints_loaded: u64,
    pub deltas_replayed: u64,
    pub total_bytes_tracked: u64,
    pub queries: u64,
}

impl MemoryReconstructor {
    #[must_use] 
    pub fn new(segment_len: Tick) -> Self {
        let mut r = Self {
            checkpoints: BTreeMap::new(),
            deltas: Vec::new(),
            segment_len,
            stats: ReconstructorStats::default(),
        };
        // Epoch 0 checkpoint
        r.checkpoints.insert(0, MemoryCheckpoint { tick: 0, memory: PageSet::default() });
        r.stats.checkpoints_taken = 1;
        r
    }

    /// Record a memory write delta.
    pub fn record_write(&mut self, tick: Tick, thread_id: u32, addr: Addr, old_bytes: Vec<u8>, new_bytes: Vec<u8>) {
        self.stats.total_bytes_tracked += new_bytes.len() as u64;
        self.deltas.push(DeltaEntry { tick, thread_id, addr, old_bytes, new_bytes });
    }

    /// Record a write when old value is not known (stores zero old bytes).
    pub fn record_write_new_only(&mut self, tick: Tick, thread_id: u32, addr: Addr, new_bytes: Vec<u8>) {
        self.record_write(tick, thread_id, addr, Vec::new(), new_bytes);
    }

    /// Sort deltas by tick (must be called once before any queries).
    pub fn finalize(&mut self) {
        self.deltas.sort_by_key(|d| d.tick);
    }

    /// Add a full-memory checkpoint at `tick`.
    pub fn add_checkpoint(&mut self, tick: Tick, memory: PageSet) {
        self.checkpoints.insert(tick, MemoryCheckpoint { tick, memory });
        self.stats.checkpoints_taken += 1;
    }

    /// Reconstruct memory state at exactly `tick`.
    pub fn reconstruct_at(&mut self, tick: Tick) -> PageSet {
        self.stats.queries += 1;
        // Find nearest checkpoint <= tick
        let (cp_tick, base_memory) = self.checkpoints.range(..=tick)
            .next_back()
            .map_or((0, PageSet::default()), |(&t, cp)| (t, cp.memory.clone()));
        self.stats.checkpoints_loaded += 1;

        // Apply all deltas in range (cp_tick, tick]
        let mut memory = base_memory;
        let deltas_to_apply: Vec<_> = self.deltas.iter()
            .skip_while(|d| d.tick <= cp_tick)
            .take_while(|d| d.tick <= tick)
            .collect();

        for delta in &deltas_to_apply {
            delta.apply(&mut memory);
            self.stats.deltas_replayed += 1;
        }

        memory
    }

    /// Read a single byte at `addr` at time `tick`.
    pub fn read_byte_at(&mut self, tick: Tick, addr: Addr) -> u8 {
        self.reconstruct_at(tick).read_byte(addr)
    }

    /// Read `len` bytes starting at `addr` at time `tick`.
    pub fn read_slice_at(&mut self, tick: Tick, addr: Addr, len: usize) -> Vec<u8> {
        self.reconstruct_at(tick).read_slice(addr, len)
    }

    /// Read a u64 LE at `addr` at time `tick`.
    pub fn read_u64_at(&mut self, tick: Tick, addr: Addr) -> u64 {
        self.reconstruct_at(tick).read_u64_le(addr)
    }

    /// Return all ticks at which `addr` was written.
    #[must_use] 
    pub fn write_ticks(&self, addr: Addr, len: usize) -> Vec<Tick> {
        self.deltas.iter()
            .filter(|d| d.overlaps(addr, len))
            .map(|d| d.tick)
            .collect()
    }

    /// Return all deltas that modified address range [addr, addr+len).
    #[must_use] 
    pub fn deltas_affecting(&self, addr: Addr, len: usize) -> Vec<&DeltaEntry> {
        self.deltas.iter().filter(|d| d.overlaps(addr, len)).collect()
    }

    /// Find the tick of the write immediately before `tick` that affected `addr`.
    #[must_use] 
    pub fn prev_write_tick(&self, tick: Tick, addr: Addr, len: usize) -> Option<Tick> {
        self.deltas.iter()
            .rev()
            .find(|d| d.tick < tick && d.overlaps(addr, len))
            .map(|d| d.tick)
    }

    /// Find the tick of the next write at or after `tick` to `addr`.
    #[must_use] 
    pub fn next_write_tick(&self, tick: Tick, addr: Addr, len: usize) -> Option<Tick> {
        self.deltas.iter()
            .find(|d| d.tick >= tick && d.overlaps(addr, len))
            .map(|d| d.tick)
    }

    /// Diff memory between two ticks.
    pub fn diff(&mut self, tick_a: Tick, tick_b: Tick) -> Vec<(Addr, u8, u8)> {
        let mem_a = self.reconstruct_at(tick_a);
        let mem_b = self.reconstruct_at(tick_b);
        mem_a.diff(&mem_b)
    }

    /// Compact delta chain: rebuild checkpoints at the current `segment_len`.
    pub fn compact(&mut self) {
        // A segment_len of 0 would cause an infinite loop; skip compaction.
        if self.segment_len == 0 {
            return;
        }
        let last_tick = self.deltas.last().map_or(0, |d| d.tick);
        let mut t = self.segment_len;
        while t <= last_tick {
            if !self.checkpoints.contains_key(&t) {
                let snap = self.reconstruct_at(t);
                self.add_checkpoint(t, snap);
            }
            t = match t.checked_add(self.segment_len) {
                Some(next) => next,
                None => break, // overflow guard
            };
        }
    }

    #[must_use] 
    pub fn checkpoint_count(&self) -> usize { self.checkpoints.len() }
    #[must_use] 
    pub const fn delta_count(&self) -> usize { self.deltas.len() }
}

// ── Allocation tracker ────────────────────────────────────────────────────────

/// Tracks heap allocations recorded in the trace (malloc/free-style).
#[derive(Debug, Default)]
pub struct AllocationTracker {
    /// addr → (size, `alloc_tick`)
    pub allocations: BTreeMap<Addr, (usize, Tick)>,
    /// Freed: addr → `free_tick`
    pub freed: Vec<(Addr, Tick)>,
}

impl AllocationTracker {
    pub fn alloc(&mut self, addr: Addr, size: usize, tick: Tick) {
        self.allocations.insert(addr, (size, tick));
    }

    pub fn free(&mut self, addr: Addr, tick: Tick) {
        self.allocations.remove(&addr);
        self.freed.push((addr, tick));
    }

    #[must_use] 
    pub fn find_containing(&self, addr: Addr) -> Option<(Addr, usize, Tick)> {
        // Find the largest key <= addr
        for (&base, &(size, alloc_tick)) in self.allocations.range(..=addr).rev() {
            if addr < base + size as u64 {
                return Some((base, size, alloc_tick));
            }
        }
        None
    }

    #[must_use] 
    pub fn is_freed(&self, addr: Addr) -> bool {
        !self.allocations.contains_key(&addr)
            && self.freed.iter().any(|(a, _)| *a == addr)
    }

    #[must_use] 
    pub fn use_after_free_candidates(&self) -> Vec<(Addr, Tick)> {
        self.freed.iter()
            .filter(|(addr, _)| !self.allocations.contains_key(addr))
            .copied()
            .collect()
    }

    #[must_use] 
    pub fn total_live_bytes(&self) -> usize {
        self.allocations.values().map(|(s, _)| s).sum()
    }
}

// ── Memory range watcher ──────────────────────────────────────────────────────

/// Watch a set of memory ranges and report any writes to them.
pub struct MemoryWatcher {
    ranges: Vec<(Addr, usize, String)>, // (addr, len, label)
}

impl MemoryWatcher {
    #[must_use] 
    pub const fn new() -> Self { Self { ranges: Vec::new() } }

    pub fn watch(&mut self, addr: Addr, len: usize, label: String) {
        self.ranges.push((addr, len, label));
    }

    #[must_use] 
    pub fn check_delta(&self, delta: &DeltaEntry) -> Vec<&str> {
        self.ranges.iter()
            .filter(|(a, l, _)| delta.overlaps(*a, *l))
            .map(|(_, _, label)| label.as_str())
            .collect()
    }

    #[must_use] 
    pub fn scan_deltas<'a>(&self, deltas: &'a [DeltaEntry]) -> Vec<(&'a DeltaEntry, Vec<&str>)> {
        deltas.iter()
            .filter_map(|d| {
                let hits: Vec<_> = self.check_delta(d);
                if hits.is_empty() { None } else { Some((d, hits)) }
            })
            .collect()
    }
}

impl Default for MemoryWatcher { fn default() -> Self { Self::new() } }

// ── String scanner ────────────────────────────────────────────────────────────

/// Scan a reconstructed memory region for printable ASCII strings.
#[must_use] 
pub fn scan_strings(mem: &PageSet, start: Addr, len: u64, min_len: usize) -> Vec<(Addr, String)> {
    let mut result = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut run_start = start;
    for i in 0..len {
        let b = mem.read_byte(start + i);
        if (0x20..0x7f).contains(&b) {
            if run.is_empty() { run_start = start + i; }
            run.push(b);
        } else {
            if run.len() >= min_len
                && let Ok(s) = String::from_utf8(run.clone()) {
                    result.push((run_start, s));
                }
            run.clear();
        }
    }
    if run.len() >= min_len
        && let Ok(s) = String::from_utf8(run) {
            result.push((run_start, s));
        }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_rw() {
        let mut ps = PageSet::default();
        ps.write_byte(0x1000, 0xAB);
        ps.write_byte(0x1001, 0xCD);
        assert_eq!(ps.read_byte(0x1000), 0xAB);
        assert_eq!(ps.read_byte(0x1001), 0xCD);
        assert_eq!(ps.read_byte(0x1002), 0x00); // unmapped
    }

    #[test]
    fn test_page_u64() {
        let mut ps = PageSet::default();
        ps.write_u64_le(0x2000, 0x0102_0304_0506_0708);
        assert_eq!(ps.read_u64_le(0x2000), 0x0102_0304_0506_0708);
        assert_eq!(ps.read_byte(0x2000), 0x08);
    }

    #[test]
    fn test_reconstruct_basic() {
        let mut rec = MemoryReconstructor::new(100);
        rec.record_write(10, 1, 0x1000, vec![0], vec![0xAA]);
        rec.record_write(20, 1, 0x1001, vec![0], vec![0xBB]);
        rec.record_write(30, 1, 0x1000, vec![0xAA], vec![0xCC]);
        rec.finalize();

        // At tick 15: 0x1000 = 0xAA, 0x1001 = 0x00
        let mem15 = rec.reconstruct_at(15);
        assert_eq!(mem15.read_byte(0x1000), 0xAA);
        assert_eq!(mem15.read_byte(0x1001), 0x00);

        // At tick 25: 0x1000 = 0xAA, 0x1001 = 0xBB
        let mem25 = rec.reconstruct_at(25);
        assert_eq!(mem25.read_byte(0x1000), 0xAA);
        assert_eq!(mem25.read_byte(0x1001), 0xBB);

        // At tick 35: 0x1000 = 0xCC
        let mem35 = rec.reconstruct_at(35);
        assert_eq!(mem35.read_byte(0x1000), 0xCC);
    }

    #[test]
    fn test_write_ticks() {
        let mut rec = MemoryReconstructor::new(100);
        rec.record_write(5, 1, 0x4000, vec![0], vec![1]);
        rec.record_write(15, 1, 0x4001, vec![0], vec![2]);
        rec.record_write(25, 1, 0x4000, vec![1], vec![3]);
        rec.finalize();

        let ticks = rec.write_ticks(0x4000, 1);
        assert_eq!(ticks, vec![5, 25]);
    }

    #[test]
    fn test_prev_next_write() {
        let mut rec = MemoryReconstructor::new(100);
        rec.record_write(10, 1, 0x8000, vec![], vec![1]);
        rec.record_write(30, 1, 0x8000, vec![], vec![2]);
        rec.finalize();

        assert_eq!(rec.prev_write_tick(25, 0x8000, 1), Some(10));
        assert_eq!(rec.next_write_tick(15, 0x8000, 1), Some(30));
        assert_eq!(rec.prev_write_tick(5, 0x8000, 1), None);
    }

    #[test]
    fn test_alloc_tracker() {
        let mut at = AllocationTracker::default();
        at.alloc(0xC000, 128, 10);
        assert!(at.find_containing(0xC040).is_some());
        at.free(0xC000, 20);
        assert!(at.find_containing(0xC040).is_none());
        assert!(at.is_freed(0xC000));
    }

    #[test]
    fn test_scan_strings() {
        let mut ps = PageSet::default();
        let s = b"hello world\x00dead";
        ps.write_slice(0x1000, s);
        let found = scan_strings(&ps, 0x1000, s.len() as u64, 5);
        assert!(found.iter().any(|(_, s)| s == "hello world"));
    }

    #[test]
    fn test_compact_builds_checkpoints() {
        let mut rec = MemoryReconstructor::new(10);
        for i in 0..50u64 {
            rec.record_write(i, 1, 0x100 + i, vec![], vec![i as u8]);
        }
        rec.finalize();
        rec.compact();
        assert!(rec.checkpoint_count() > 1);
    }

    #[test]
    fn test_diff() {
        let mut rec = MemoryReconstructor::new(100);
        rec.record_write(10, 1, 0x2000, vec![0], vec![0xFF]);
        rec.finalize();
        let diffs = rec.diff(5, 15);
        assert!(diffs.iter().any(|(addr, old, new)| *addr == 0x2000 && *old == 0 && *new == 0xFF));
    }
}
