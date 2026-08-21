//! Memory access timeline analysis.
//!
//! Tracks which addresses were read/written at each trace position, detects
//! memory patterns (repeated writes, UAF patterns, stack pivots), builds
//! memory access heatmaps, and correlates memory accesses with code locations.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── AccessType ───────────────────────────────────────────────────────────────

/// The type of a memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    /// Both read and write in the same event (e.g., RMW).
    ReadWrite,
}

impl std::fmt::Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "R"),
            Self::Write => write!(f, "W"),
            Self::ReadWrite => write!(f, "RW"),
        }
    }
}

// ─── MemoryAccessEvent ────────────────────────────────────────────────────────

/// A single memory access recorded during trace replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccessEvent {
    /// Trace position when this access occurred.
    pub position: TracePosition,
    /// Virtual address accessed.
    pub addr: u64,
    /// Size in bytes of the access.
    pub size: usize,
    /// Access type.
    pub access_type: AccessType,
    /// Thread that performed the access.
    pub thread_id: u32,
    /// Data written (None for reads or if not captured).
    pub data: Option<Vec<u8>>,
    /// Code address that triggered this access (from call/return events context).
    pub code_location: Option<u64>,
}

impl MemoryAccessEvent {
    /// Returns the last byte address (inclusive) of this access.
    #[must_use]
    pub const fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.size as u64).saturating_sub(1)
    }

    /// Returns true if this access overlaps with the range `[start, end)`.
    #[must_use]
    pub const fn overlaps_range(&self, start: u64, end: u64) -> bool {
        let self_end = self.addr.saturating_add(self.size as u64);
        self.addr < end && self_end > start
    }

    /// Returns true if this access is a write.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(self.access_type, AccessType::Write | AccessType::ReadWrite)
    }

    /// Returns true if this access is a read.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self.access_type, AccessType::Read | AccessType::ReadWrite)
    }
}

impl std::fmt::Display for MemoryAccessEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} @ {:#x}+{} tid={}",
            self.position, self.access_type, self.addr, self.size, self.thread_id
        )
    }
}

// ─── AccessPattern ────────────────────────────────────────────────────────────

/// A detected memory access pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPattern {
    /// The same address was written N times in a row.
    RepeatedWrite {
        addr: u64,
        count: u64,
        first: TracePosition,
        last: TracePosition,
    },
    /// Address was freed (pattern: write 0 or null-like value) then re-accessed.
    UseAfterFree {
        addr: u64,
        free_position: TracePosition,
        reuse_position: TracePosition,
        confidence: f64,
    },
    /// Stack pointer was written to a non-stack address.
    StackPivot {
        old_sp: u64,
        new_sp: u64,
        position: TracePosition,
        thread_id: u32,
    },
    /// Large block of memory written in sequence (memcpy-like).
    BulkWrite {
        start_addr: u64,
        end_addr: u64,
        total_bytes: u64,
        first: TracePosition,
        last: TracePosition,
    },
    /// An address is accessed by multiple threads (potential data race).
    CrossThreadAccess {
        addr: u64,
        threads: Vec<u32>,
        positions: Vec<TracePosition>,
    },
    /// An address accessed very frequently (hot spot).
    HotSpot {
        addr: u64,
        total_accesses: u64,
        read_count: u64,
        write_count: u64,
    },
    /// Write to executable region (potential code injection).
    WriteToExecutable {
        addr: u64,
        position: TracePosition,
        size: usize,
    },
}

impl std::fmt::Display for AccessPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RepeatedWrite { addr, count, .. } => {
                write!(f, "RepeatedWrite({addr:#x}, n={count})")
            }
            Self::UseAfterFree { addr, confidence, .. } => {
                write!(f, "UAF({addr:#x}, conf={confidence:.2})")
            }
            Self::StackPivot { old_sp, new_sp, .. } => {
                write!(f, "StackPivot({old_sp:#x} -> {new_sp:#x})")
            }
            Self::BulkWrite {
                start_addr,
                end_addr,
                ..
            } => {
                write!(f, "BulkWrite({start_addr:#x}..{end_addr:#x})")
            }
            Self::CrossThreadAccess { addr, threads, .. } => {
                write!(f, "CrossThread({addr:#x}, tids={threads:?})")
            }
            Self::HotSpot {
                addr,
                total_accesses,
                ..
            } => {
                write!(f, "HotSpot({addr:#x}, n={total_accesses})")
            }
            Self::WriteToExecutable { addr, .. } => {
                write!(f, "WriteToExec({addr:#x})")
            }
        }
    }
}

// ─── HeatmapCell ──────────────────────────────────────────────────────────────

/// One cell in a memory access heatmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    /// Aligned base address of this cell (cell_size-aligned).
    pub base_addr: u64,
    /// Cell size in bytes.
    pub cell_size: u64,
    /// Total read accesses to this cell.
    pub read_count: u64,
    /// Total write accesses to this cell.
    pub write_count: u64,
    /// Distinct threads that accessed this cell.
    pub thread_count: u32,
    /// Most recent access position.
    pub last_access: Option<TracePosition>,
    /// First access position.
    pub first_access: Option<TracePosition>,
    /// Heat score (normalized 0.0–1.0 across the heatmap).
    pub heat: f64,
}

impl HeatmapCell {
    const fn new(base_addr: u64, cell_size: u64) -> Self {
        Self {
            base_addr,
            cell_size,
            read_count: 0,
            write_count: 0,
            thread_count: 0,
            last_access: None,
            first_access: None,
            heat: 0.0,
        }
    }

    #[must_use]
    pub const fn total_accesses(&self) -> u64 {
        self.read_count + self.write_count
    }

    #[must_use]
    pub fn write_ratio(&self) -> f64 {
        let total = self.total_accesses();
        if total == 0 {
            0.0
        } else {
            self.write_count as f64 / total as f64
        }
    }
}

impl std::fmt::Display for HeatmapCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cell[{:#x}+{}] R={} W={} heat={:.3}",
            self.base_addr, self.cell_size, self.read_count, self.write_count, self.heat
        )
    }
}

// ─── MemoryTimeline ───────────────────────────────────────────────────────────

/// Full memory access timeline for a trace.
///
/// Indexes all memory accesses by address, position, and thread for fast
/// querying, pattern detection, and heatmap generation.
pub struct MemoryTimeline {
    /// All access events, sorted by position.
    pub events: Vec<MemoryAccessEvent>,
    /// Index: address -> list of indices into `events`.
    by_address: BTreeMap<u64, Vec<usize>>,
    /// Index: position -> list of indices into `events`.
    by_position: BTreeMap<TracePosition, Vec<usize>>,
    /// Index: `thread_id` -> list of indices into `events`.
    by_thread: HashMap<u32, Vec<usize>>,
    /// Total ticks span.
    pub tick_span: u64,
    /// Minimum position in the timeline.
    pub min_pos: Option<TracePosition>,
    /// Maximum position in the timeline.
    pub max_pos: Option<TracePosition>,
    /// Executable regions (for write-to-executable detection).
    executable_regions: Vec<(u64, u64)>,
}

#[derive(Debug, Error)]
pub enum TimelineError {
    #[error("empty trace")]
    EmptyTrace,
    #[error("cell size must be > 0")]
    ZeroCellSize,
    #[error("invalid address range: start >= end")]
    InvalidRange,
    #[error("heatmap would require too many cells ({0}); reduce the address range or increase cell size")]
    TooManyCells(u64),
}

impl MemoryTimeline {
    /// Build a memory timeline from a TTD trace.
    pub fn build(trace: &TtdTrace) -> Self {
        let mut events: Vec<MemoryAccessEvent> = Vec::new();
        let all_events = trace.all_events();

        for ev in &all_events {
            match &ev.kind {
                EventKind::MemRead { addr, len } => {
                    events.push(MemoryAccessEvent {
                        position: ev.position,
                        addr: *addr,
                        size: *len,
                        access_type: AccessType::Read,
                        thread_id: ev.thread_id,
                        data: None,
                        code_location: None,
                    });
                }
                EventKind::MemWrite { addr, data } => {
                    events.push(MemoryAccessEvent {
                        position: ev.position,
                        addr: *addr,
                        size: data.len(),
                        access_type: AccessType::Write,
                        thread_id: ev.thread_id,
                        data: Some(data.clone()),
                        code_location: None,
                    });
                }
                _ => {}
            }
        }

        events.sort_by_key(|e| e.position);

        let mut by_address: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut by_position: BTreeMap<TracePosition, Vec<usize>> = BTreeMap::new();
        let mut by_thread: HashMap<u32, Vec<usize>> = HashMap::new();

        for (idx, ev) in events.iter().enumerate() {
            by_address.entry(ev.addr).or_default().push(idx);
            by_position.entry(ev.position).or_default().push(idx);
            by_thread.entry(ev.thread_id).or_default().push(idx);
        }

        let min_pos = events.first().map(|e| e.position);
        let max_pos = events.last().map(|e| e.position);
        let tick_span = match (min_pos, max_pos) {
            (Some(mn), Some(mx)) => mx.sequence.saturating_sub(mn.sequence),
            _ => 0,
        };

        Self {
            events,
            by_address,
            by_position,
            by_thread,
            tick_span,
            min_pos,
            max_pos,
            executable_regions: Vec::new(),
        }
    }

    /// Register an executable address range for write-to-executable detection.
    pub fn add_executable_region(&mut self, start: u64, end: u64) {
        self.executable_regions.push((start, end));
    }

    /// Return all accesses to a specific address.
    #[must_use]
    pub fn accesses_to_addr(&self, addr: u64) -> Vec<&MemoryAccessEvent> {
        match self.by_address.get(&addr) {
            None => Vec::new(),
            Some(indices) => indices.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Return all accesses in an address range `[start, end)`.
    #[must_use]
    pub fn accesses_in_range(&self, start: u64, end: u64) -> Vec<&MemoryAccessEvent> {
        // An access COVERS `[addr, addr + size)`; indexing only its start
        // address made a write straddling `start` invisible. The correct
        // predicate already exists on the event and was simply not used.
        //
        // The index is still what bounds the scan: no access can begin before
        // `start - MAX_ACCESS_SPAN` and still reach into the range, so the
        // widened lower bound stays far cheaper than a full scan.
        const MAX_ACCESS_SPAN: u64 = 4096;
        let lower = start.saturating_sub(MAX_ACCESS_SPAN);
        let mut out: Vec<&MemoryAccessEvent> = self
            .by_address
            .range(lower..end)
            .flat_map(|(_, indices)| indices.iter().map(|&i| &self.events[i]))
            .filter(|e| e.overlaps_range(start, end))
            .collect();
        // Accesses larger than the widened window are rare but must not be
        // dropped; sweep only those.
        out.extend(
            self.by_address
                .range(..lower)
                .flat_map(|(_, indices)| indices.iter().map(|&i| &self.events[i]))
                .filter(|e| e.overlaps_range(start, end)),
        );
        out
    }

    /// Return all accesses at a specific trace position.
    #[must_use]
    pub fn accesses_at_position(&self, pos: TracePosition) -> Vec<&MemoryAccessEvent> {
        match self.by_position.get(&pos) {
            None => Vec::new(),
            Some(indices) => indices.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Return all accesses by a specific thread.
    #[must_use]
    pub fn accesses_by_thread(&self, tid: u32) -> Vec<&MemoryAccessEvent> {
        match self.by_thread.get(&tid) {
            None => Vec::new(),
            Some(indices) => indices.iter().map(|&i| &self.events[i]).collect(),
        }
    }

    /// Count total reads and writes to each address in a range.
    #[must_use]
    pub fn access_counts_in_range(
        &self,
        start: u64,
        end: u64,
    ) -> BTreeMap<u64, (u64, u64)> {
        let mut counts: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        for ev in self.accesses_in_range(start, end) {
            let entry = counts.entry(ev.addr).or_default();
            match ev.access_type {
                AccessType::Read => entry.0 += 1,
                AccessType::Write => entry.1 += 1,
                AccessType::ReadWrite => {
                    entry.0 += 1;
                    entry.1 += 1;
                }
            }
        }
        counts
    }

    // ─── Pattern detection ────────────────────────────────────────────────────

    /// Detect all memory access patterns in the timeline.
    #[must_use]
    pub fn detect_patterns(&self) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();
        patterns.extend(self.detect_repeated_writes(3));
        patterns.extend(self.detect_uaf_candidates());
        patterns.extend(self.detect_stack_pivots());
        patterns.extend(self.detect_bulk_writes(64));
        patterns.extend(self.detect_cross_thread_accesses());
        patterns.extend(self.detect_hot_spots(100));
        patterns.extend(self.detect_writes_to_executable());
        patterns
    }

    /// Detect addresses written more than `threshold` consecutive times.
    #[must_use]
    pub fn detect_repeated_writes(&self, threshold: u64) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();
        for (addr, indices) in &self.by_address {
            let writes: Vec<usize> = indices
                .iter()
                .copied()
                .filter(|&i| self.events[i].is_write())
                .collect();
            if writes.len() as u64 >= threshold {
                let first = self.events[writes[0]].position;
                let last = self.events[*writes.last().unwrap()].position;
                patterns.push(AccessPattern::RepeatedWrite {
                    addr: *addr,
                    count: writes.len() as u64,
                    first,
                    last,
                });
            }
        }
        patterns
    }

    /// Heuristic UAF detection: address written with zero/null-like data,
    /// then later written or read again.
    #[must_use]
    pub fn detect_uaf_candidates(&self) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();
        for (addr, indices) in &self.by_address {
            let mut free_candidate: Option<TracePosition> = None;
            for &i in indices {
                let ev = &self.events[i];
                if ev.is_write() {
                    if let Some(data) = &ev.data {
                        // Heuristic: a write of all zeros or a small value looks like a free.
                        let is_null_write =
                            data.iter().all(|b| *b == 0) || (data.len() <= 8 && {
                                let mut buf = [0u8; 8];
                                let n = data.len().min(8);
                                buf[..n].copy_from_slice(&data[..n]);
                                u64::from_le_bytes(buf) == 0
                            });
                        if is_null_write {
                            free_candidate = Some(ev.position);
                        } else if let Some(free_pos) = free_candidate {
                            patterns.push(AccessPattern::UseAfterFree {
                                addr: *addr,
                                free_position: free_pos,
                                reuse_position: ev.position,
                                confidence: 0.4,
                            });
                            free_candidate = None;
                        }
                    }
                } else if ev.is_read()
                    && let Some(free_pos) = free_candidate {
                        patterns.push(AccessPattern::UseAfterFree {
                            addr: *addr,
                            free_position: free_pos,
                            reuse_position: ev.position,
                            confidence: 0.6,
                        });
                        free_candidate = None;
                    }
            }
        }
        patterns
    }

    /// Detect stack pivots: writes to the stack pointer register reflected as
    /// memory writes to a non-typical stack region.
    ///
    /// Heuristic: we look for writes to addresses that look like stack pointer
    /// values (aligned, plausibly in stack range) that differ significantly from
    /// the most common stack base in the trace.
    #[must_use]
    pub fn detect_stack_pivots(&self) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();
        // Collect all write addresses to infer the stack region.
        let mut write_addrs: Vec<u64> = self
            .events
            .iter()
            .filter(|e| e.is_write())
            .map(|e| e.addr)
            .collect();

        if write_addrs.is_empty() {
            return patterns;
        }
        write_addrs.sort_unstable();

        // Compute median as rough stack base.
        let median_idx = write_addrs.len() / 2;
        let median_addr = write_addrs[median_idx];

        // Any write to an address more than 64 MiB away from the median and
        // 8-byte aligned is a stack pivot candidate.
        let pivot_threshold: u64 = 64 * 1024 * 1024;

        for ev in &self.events {
            if ev.is_write() && ev.size >= 8 {
                let delta = ev.addr.abs_diff(median_addr);
                if delta > pivot_threshold && ev.addr % 8 == 0
                    && let Some(data) = &ev.data
                        && data.len() >= 8 {
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&data[..8]);
                            let new_sp = u64::from_le_bytes(buf);
                            patterns.push(AccessPattern::StackPivot {
                                old_sp: ev.addr,
                                new_sp,
                                position: ev.position,
                                thread_id: ev.thread_id,
                            });
                        }
            }
        }
        patterns
    }

    /// Detect bulk writes: sequential writes that together cover a contiguous
    /// region of at least `min_bytes` bytes.
    #[must_use]
    pub fn detect_bulk_writes(&self, min_bytes: u64) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();
        let mut sorted_writes: Vec<&MemoryAccessEvent> = self
            .events
            .iter()
            .filter(|e| e.is_write())
            .collect();
        sorted_writes.sort_by_key(|e| e.addr);

        if sorted_writes.is_empty() {
            return patterns;
        }

        let mut run_start = sorted_writes[0].addr;
        let mut run_end = sorted_writes[0].end_addr() + 1;
        let mut run_bytes = sorted_writes[0].size as u64;
        let mut run_first = sorted_writes[0].position;
        let mut run_last = sorted_writes[0].position;

        for ev in &sorted_writes[1..] {
            if ev.addr <= run_end + 8 {
                // Adjacent or slightly overlapping.
                if ev.end_addr() + 1 > run_end {
                    run_bytes += (ev.end_addr() + 1).saturating_sub(run_end);
                    run_end = ev.end_addr() + 1;
                }
                run_last = run_last.max(ev.position);
            } else {
                if run_bytes >= min_bytes {
                    patterns.push(AccessPattern::BulkWrite {
                        start_addr: run_start,
                        end_addr: run_end,
                        total_bytes: run_bytes,
                        first: run_first,
                        last: run_last,
                    });
                }
                run_start = ev.addr;
                run_end = ev.end_addr() + 1;
                run_bytes = ev.size as u64;
                run_first = ev.position;
                run_last = ev.position;
            }
        }
        if run_bytes >= min_bytes {
            patterns.push(AccessPattern::BulkWrite {
                start_addr: run_start,
                end_addr: run_end,
                total_bytes: run_bytes,
                first: run_first,
                last: run_last,
            });
        }
        patterns
    }

    /// Detect addresses accessed by more than one thread.
    #[must_use]
    pub fn detect_cross_thread_accesses(&self) -> Vec<AccessPattern> {
        let mut addr_threads: BTreeMap<u64, HashSet<u32>> = BTreeMap::new();
        let mut addr_positions: BTreeMap<u64, Vec<TracePosition>> = BTreeMap::new();

        // Registered over every BYTE the access covers, not just its start
        // address. Two threads writing 0x1000..0x1008 and 0x1004..0x1008 race
        // on four bytes, yet comparing start addresses alone saw two unrelated
        // addresses and reported nothing.
        //
        // Bounded per access so a bogus huge size cannot blow up memory.
        const MAX_TRACKED_BYTES: usize = 4096;
        for ev in &self.events {
            let span = ev.size.max(1).min(MAX_TRACKED_BYTES) as u64;
            for off in 0..span {
                let byte = ev.addr.saturating_add(off);
                addr_threads.entry(byte).or_default().insert(ev.thread_id);
                addr_positions.entry(byte).or_default().push(ev.position);
            }
        }

        addr_threads
            .into_iter()
            .filter(|(_, threads)| threads.len() > 1)
            .map(|(addr, threads)| {
                let positions = addr_positions.remove(&addr).unwrap_or_default();
                AccessPattern::CrossThreadAccess {
                    addr,
                    threads: threads.into_iter().collect(),
                    positions,
                }
            })
            .collect()
    }

    /// Detect hot spot addresses accessed more than `threshold` times.
    #[must_use]
    pub fn detect_hot_spots(&self, threshold: u64) -> Vec<AccessPattern> {
        let mut read_counts: HashMap<u64, u64> = HashMap::new();
        let mut write_counts: HashMap<u64, u64> = HashMap::new();

        for ev in &self.events {
            if ev.is_read() {
                *read_counts.entry(ev.addr).or_default() += 1;
            }
            if ev.is_write() {
                *write_counts.entry(ev.addr).or_default() += 1;
            }
        }

        let all_addrs: HashSet<u64> = read_counts
            .keys()
            .chain(write_counts.keys())
            .copied()
            .collect();

        all_addrs
            .into_iter()
            .filter_map(|addr| {
                let reads = read_counts.get(&addr).copied().unwrap_or(0);
                let writes = write_counts.get(&addr).copied().unwrap_or(0);
                let total = reads + writes;
                if total >= threshold {
                    Some(AccessPattern::HotSpot {
                        addr,
                        total_accesses: total,
                        read_count: reads,
                        write_count: writes,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Detect writes into registered executable regions.
    #[must_use]
    pub fn detect_writes_to_executable(&self) -> Vec<AccessPattern> {
        if self.executable_regions.is_empty() {
            return Vec::new();
        }
        self.events
            .iter()
            .filter(|ev| ev.is_write())
            .filter(|ev| {
                self.executable_regions
                    .iter()
                    .any(|&(start, end)| ev.overlaps_range(start, end))
            })
            .map(|ev| AccessPattern::WriteToExecutable {
                addr: ev.addr,
                position: ev.position,
                size: ev.size,
            })
            .collect()
    }

    // ─── Heatmap ──────────────────────────────────────────────────────────────

    /// Build a memory access heatmap over `[start_addr, end_addr)` with the
    /// given cell size.
    pub fn build_heatmap(
        &self,
        start_addr: u64,
        end_addr: u64,
        cell_size: u64,
    ) -> Result<Vec<HeatmapCell>, TimelineError> {
        if cell_size == 0 {
            return Err(TimelineError::ZeroCellSize);
        }
        if start_addr >= end_addr {
            return Err(TimelineError::InvalidRange);
        }

        // Compute num_cells with overflow protection.
        // (end_addr - start_addr) is safe because start_addr < end_addr (checked above).
        let range = end_addr - start_addr;
        let num_cells = range
            .checked_add(cell_size - 1)
            .map_or(u64::MAX / cell_size, |v| v / cell_size);

        // Guard against DoS: reject absurdly large cell counts that would OOM.
        const MAX_HEATMAP_CELLS: u64 = 1 << 24; // 16 M cells
        if num_cells > MAX_HEATMAP_CELLS {
            return Err(TimelineError::TooManyCells(num_cells));
        }

        let mut cells: Vec<HeatmapCell> = (0..num_cells)
            .map(|i| HeatmapCell::new(start_addr + i * cell_size, cell_size))
            .collect();

        let mut thread_sets: Vec<HashSet<u32>> = vec![HashSet::new(); num_cells as usize];

        for ev in self.accesses_in_range(start_addr, end_addr) {
            // An access spans `[addr, addr + size)` and can straddle the range
            // start and several cells. Keying it only by `ev.addr` dropped
            // every access beginning below `start_addr` — leaving the cells it
            // actually touches stone cold — and credited a wide access to a
            // single cell.
            let ev_end = ev.addr.saturating_add(ev.size.max(1) as u64);
            let lo = ev.addr.max(start_addr);
            let hi = ev_end.min(end_addr);
            if lo >= hi {
                continue;
            }
            let first_cell = ((lo - start_addr) / cell_size) as usize;
            let last_cell = ((hi - 1 - start_addr) / cell_size) as usize;
            for cell_idx in first_cell..=last_cell.min(cells.len().saturating_sub(1)) {
                let cell = &mut cells[cell_idx];
                match ev.access_type {
                    AccessType::Read => cell.read_count += 1,
                    AccessType::Write => cell.write_count += 1,
                    AccessType::ReadWrite => {
                        cell.read_count += 1;
                        cell.write_count += 1;
                    }
                }
                thread_sets[cell_idx].insert(ev.thread_id);
                cell.last_access = Some(match cell.last_access {
                    None => ev.position,
                    Some(p) => p.max(ev.position),
                });
                cell.first_access = Some(match cell.first_access {
                    None => ev.position,
                    Some(p) => p.min(ev.position),
                });
            }
        }

        for (i, cell) in cells.iter_mut().enumerate() {
            cell.thread_count = thread_sets[i].len() as u32;
        }

        // Normalize heat scores.
        let max_total = cells
            .iter()
            .map(HeatmapCell::total_accesses)
            .max()
            .unwrap_or(1)
            .max(1);
        for cell in &mut cells {
            cell.heat = cell.total_accesses() as f64 / max_total as f64;
        }

        Ok(cells)
    }

    // ─── Code correlation ─────────────────────────────────────────────────────

    /// Correlate memory accesses with code locations by examining which call/return
    /// events immediately preceded each memory access in the trace.
    ///
    /// Returns a map: `code_addr` -> count of memory accesses attributed to it.
    #[must_use]
    pub fn correlate_with_code(
        &self,
        original_events: &[TraceEvent],
    ) -> BTreeMap<u64, u64> {
        let mut result: BTreeMap<u64, u64> = BTreeMap::new();

        let mut last_code_addr: Option<u64> = None;
        for ev in original_events {
            match &ev.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => last_code_addr = Some(*to),
                EventKind::MemRead { .. } | EventKind::MemWrite { .. } => {
                    if let Some(code_addr) = last_code_addr {
                        *result.entry(code_addr).or_default() += 1;
                    }
                }
                _ => {}
            }
        }
        result
    }

    // ─── Statistics ───────────────────────────────────────────────────────────

    /// Compute summary statistics for the timeline.
    #[must_use]
    pub fn statistics(&self) -> TimelineStats {
        let total = self.events.len() as u64;
        let reads = self.events.iter().filter(|e| e.is_read()).count() as u64;
        let writes = self.events.iter().filter(|e| e.is_write()).count() as u64;
        let unique_addrs = self.by_address.len() as u64;
        let unique_threads = self.by_thread.len() as u32;
        let total_bytes_read: u64 = self
            .events
            .iter()
            .filter(|e| e.is_read())
            .map(|e| e.size as u64)
            .sum();
        let total_bytes_written: u64 = self
            .events
            .iter()
            .filter(|e| e.is_write())
            .map(|e| e.size as u64)
            .sum();

        TimelineStats {
            total_accesses: total,
            read_count: reads,
            write_count: writes,
            unique_addresses: unique_addrs,
            unique_threads,
            total_bytes_read,
            total_bytes_written,
            tick_span: self.tick_span,
        }
    }
}

impl std::fmt::Debug for MemoryTimeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTimeline")
            .field("events", &self.events.len())
            .field("unique_addrs", &self.by_address.len())
            .finish_non_exhaustive()
    }
}

// ─── TimelineStats ────────────────────────────────────────────────────────────

/// Summary statistics for a [`MemoryTimeline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineStats {
    pub total_accesses: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub unique_addresses: u64,
    pub unique_threads: u32,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub tick_span: u64,
}

impl TimelineStats {
    #[must_use]
    pub fn read_write_ratio(&self) -> f64 {
        if self.write_count == 0 {
            f64::INFINITY
        } else {
            self.read_count as f64 / self.write_count as f64
        }
    }

    #[must_use]
    pub fn access_density(&self) -> f64 {
        if self.tick_span == 0 {
            0.0
        } else {
            self.total_accesses as f64 / self.tick_span as f64
        }
    }
}

impl std::fmt::Display for TimelineStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TimelineStats {{ total={}, reads={}, writes={}, addrs={}, threads={} }}",
            self.total_accesses,
            self.read_count,
            self.write_count,
            self.unique_addresses,
            self.unique_threads
        )
    }
}

// ─── Utility functions ────────────────────────────────────────────────────────

/// Find all addresses that are written before being read (write-first addresses).
#[must_use]
pub fn write_first_addresses(timeline: &MemoryTimeline) -> Vec<u64> {
    timeline
        .by_address
        .iter()
        .filter(|(_, indices)| {
            let first = indices.first().map(|&i| &timeline.events[i]);
            matches!(first, Some(ev) if ev.is_write())
        })
        .map(|(addr, _)| *addr)
        .collect()
}

/// Find all addresses that are read before being written (potentially uninitialized).
#[must_use]
pub fn read_before_write_addresses(timeline: &MemoryTimeline) -> Vec<u64> {
    timeline
        .by_address
        .iter()
        .filter(|(_, indices)| {
            let first = indices.first().map(|&i| &timeline.events[i]);
            matches!(first, Some(ev) if ev.is_read())
        })
        .map(|(addr, _)| *addr)
        .collect()
}

/// Compute the mean inter-access interval (in ticks) for a given address.
#[must_use]
pub fn mean_inter_access_interval(timeline: &MemoryTimeline, addr: u64) -> Option<f64> {
    let accesses = timeline.accesses_to_addr(addr);
    if accesses.len() < 2 {
        return None;
    }
    let intervals: Vec<u64> = accesses
        .windows(2)
        .map(|w| {
            w[1].position
                .sequence
                .saturating_sub(w[0].position.sequence)
        })
        .collect();
    let mean = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
    Some(mean)
}
