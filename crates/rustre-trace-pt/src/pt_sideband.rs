//! `pt_sideband` — Sideband data correlation for Intel PT.
//!
//! Correlates kernel sideband events (perf `mmap`, `comm`, `fork`, `exit`,
//! `switch`, `mmap2`) with the PT trace to produce per-process, per-thread,
//! and per-module attribution.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

// ─── MmapEvent ────────────────────────────────────────────────────────────────

/// A memory mapping event from the kernel sideband.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmapEvent {
    /// Timestamp (nanoseconds since boot, from `perf_event`).
    pub timestamp_ns: u64,
    /// Process ID that owns the mapping.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Virtual address base.
    pub addr: u64,
    /// Length of the mapping.
    pub len: u64,
    /// Page offset (for file-backed mappings).
    pub pgoff: u64,
    /// File path (empty for anonymous mappings).
    pub filename: String,
    /// Whether this mapping is executable.
    pub is_exec: bool,
    /// Whether this mapping is anonymous.
    pub is_anon: bool,
    /// Major device number.
    pub dev_major: u32,
    /// Minor device number.
    pub dev_minor: u32,
    /// Inode number.
    pub inode: u64,
}

impl MmapEvent {
    /// Create a new executable file mapping event.
    #[must_use]
    pub fn new_file(pid: u32, tid: u32, addr: u64, len: u64, filename: impl Into<String>) -> Self {
        Self {
            timestamp_ns: 0,
            pid,
            tid,
            addr,
            len,
            pgoff: 0,
            filename: filename.into(),
            is_exec: true,
            is_anon: false,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
        }
    }

    /// Create an anonymous mapping event.
    #[must_use]
    pub const fn new_anon(pid: u32, tid: u32, addr: u64, len: u64) -> Self {
        Self {
            timestamp_ns: 0,
            pid,
            tid,
            addr,
            len,
            pgoff: 0,
            filename: String::new(),
            is_exec: false,
            is_anon: true,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
        }
    }

    /// Return whether `addr` falls within this mapping.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.addr.saturating_add(self.len)
    }

    /// Return the file offset for an address within the mapping.
    #[must_use]
    pub const fn file_offset(&self, addr: u64) -> Option<u64> {
        if self.contains(addr) {
            Some(self.pgoff.saturating_add(addr - self.addr))
        } else {
            None
        }
    }
}

// ─── CommEvent ────────────────────────────────────────────────────────────────

/// A process name change event (execve / `PERF_RECORD_COMM`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommEvent {
    /// Timestamp.
    pub timestamp_ns: u64,
    /// PID.
    pub pid: u32,
    /// TID.
    pub tid: u32,
    /// New command name.
    pub comm: String,
    /// Whether this is an exec (vs a `prctl`).
    pub is_exec: bool,
}

// ─── ForkEvent ────────────────────────────────────────────────────────────────

/// A process/thread creation event (`PERF_RECORD_FORK`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkEvent {
    /// Timestamp.
    pub timestamp_ns: u64,
    /// New PID.
    pub pid: u32,
    /// New TID.
    pub tid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Parent TID.
    pub ptid: u32,
    /// Whether this is a thread (vs a process fork).
    pub is_thread: bool,
}

// ─── ExitEvent ────────────────────────────────────────────────────────────────

/// A process/thread exit event (`PERF_RECORD_EXIT`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitEvent {
    /// Timestamp.
    pub timestamp_ns: u64,
    /// PID.
    pub pid: u32,
    /// TID.
    pub tid: u32,
    /// Exit code.
    pub exit_code: i32,
}

// ─── ContextSwitchEvent ───────────────────────────────────────────────────────

/// A context switch event (`PERF_RECORD_SWITCH`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSwitchEvent {
    /// Timestamp.
    pub timestamp_ns: u64,
    /// CPU on which the switch occurred.
    pub cpu: u32,
    /// Whether this is a switch-out (vs switch-in).
    pub is_switch_out: bool,
    /// PID being scheduled in (if switch-in).
    pub next_pid: Option<u32>,
    /// TID being scheduled in.
    pub next_tid: Option<u32>,
    /// PID being scheduled out (if switch-out).
    pub prev_pid: Option<u32>,
    /// TID being scheduled out.
    pub prev_tid: Option<u32>,
}

// ─── ModuleLoadEvent ──────────────────────────────────────────────────────────

/// A shared library / kernel module load event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadEvent {
    /// Timestamp.
    pub timestamp_ns: u64,
    /// PID.
    pub pid: u32,
    /// Load base address.
    pub base: u64,
    /// Size of the loaded module.
    pub size: u64,
    /// Module path.
    pub path: String,
    /// Build ID (hex string, may be empty).
    pub build_id: String,
    /// Whether the module is a kernel module.
    pub is_kernel: bool,
}

impl ModuleLoadEvent {
    /// Create a user-space module load event.
    #[must_use]
    pub fn new_user(pid: u32, base: u64, size: u64, path: impl Into<String>) -> Self {
        Self {
            timestamp_ns: 0,
            pid,
            base,
            size,
            path: path.into(),
            build_id: String::new(),
            is_kernel: false,
        }
    }

    /// Create a kernel module load event.
    #[must_use]
    pub fn new_kernel(base: u64, size: u64, path: impl Into<String>) -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            base,
            size,
            path: path.into(),
            build_id: String::new(),
            is_kernel: true,
        }
    }
}

// ─── SidebandEvent ────────────────────────────────────────────────────────────

/// A discriminated union of all sideband event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SidebandEvent {
    /// Memory mapping.
    Mmap(MmapEvent),
    /// Process name.
    Comm(CommEvent),
    /// Fork / thread creation.
    Fork(ForkEvent),
    /// Exit.
    Exit(ExitEvent),
    /// Context switch.
    Switch(ContextSwitchEvent),
    /// Module load.
    ModuleLoad(ModuleLoadEvent),
}

impl SidebandEvent {
    /// Return the timestamp of the event.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Mmap(e) => e.timestamp_ns,
            Self::Comm(e) => e.timestamp_ns,
            Self::Fork(e) => e.timestamp_ns,
            Self::Exit(e) => e.timestamp_ns,
            Self::Switch(e) => e.timestamp_ns,
            Self::ModuleLoad(e) => e.timestamp_ns,
        }
    }

    /// Return the PID associated with the event.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Mmap(e) => Some(e.pid),
            Self::Comm(e) => Some(e.pid),
            Self::Fork(e) => Some(e.pid),
            Self::Exit(e) => Some(e.pid),
            Self::Switch(e) => e.next_pid.or(e.prev_pid),
            Self::ModuleLoad(e) => Some(e.pid),
        }
    }
}

// ─── ProcessInfo ──────────────────────────────────────────────────────────────

/// Aggregated information about a traced process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// PID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Command name.
    pub comm: String,
    /// All mmaps for this process (sorted by base address).
    pub mmaps: BTreeMap<u64, MmapEvent>,
    /// Thread IDs.
    pub tids: Vec<u32>,
    /// Whether the process has exited.
    pub exited: bool,
    /// Exit code (if exited).
    pub exit_code: Option<i32>,
}

impl ProcessInfo {
    /// Create a new process info entry.
    #[must_use]
    pub fn new(pid: u32, comm: impl Into<String>) -> Self {
        Self {
            pid,
            comm: comm.into(),
            tids: vec![pid],
            ..Self::default()
        }
    }

    /// Add a memory mapping.
    pub fn add_mmap(&mut self, event: MmapEvent) {
        self.mmaps.insert(event.addr, event);
    }

    /// Look up the mapping containing `addr`.
    #[must_use]
    pub fn mapping_for_addr(&self, addr: u64) -> Option<&MmapEvent> {
        // Find the last entry with key ≤ addr
        self.mmaps
            .range(..=addr)
            .next_back()
            .and_then(|(_, m)| if m.contains(addr) { Some(m) } else { None })
    }

    /// Return the module name for an address.
    #[must_use]
    pub fn module_name(&self, addr: u64) -> Option<&str> {
        self.mapping_for_addr(addr)
            .map(|m| m.filename.as_str())
            .filter(|s| !s.is_empty())
    }
}

// ─── SidebandCorrelator ───────────────────────────────────────────────────────

/// Correlates sideband events with an Intel PT trace.
///
/// Maintains per-PID process state, module maps, and context-switch history
/// to answer queries like:
/// - "Which process/thread was running at TSC X?"
/// - "What module does address Y belong to?"
/// - "What is the binary file offset of address Z?"
pub struct SidebandCorrelator {
    /// Sideband events in timestamp order.
    pub events: Vec<SidebandEvent>,
    /// Per-PID process information.
    pub processes: HashMap<u32, ProcessInfo>,
    /// Global kernel module map (base → module).
    pub kernel_modules: BTreeMap<u64, ModuleLoadEvent>,
    /// Context switch history (`timestamp_ns` → `ContextSwitchEvent`).
    pub context_switches: Vec<ContextSwitchEvent>,
    /// Mapping from CPU → currently scheduled PID.
    pub cpu_to_pid: HashMap<u32, u32>,
    /// TSC correlation: (TSC, `timestamp_ns`) pairs for wall-clock conversion.
    pub tsc_anchors: Vec<(u64, u64)>,
    /// CPU frequency in MHz (for TSC→ns conversion).
    pub cpu_mhz: f64,
}

impl SidebandCorrelator {
    /// Create a new correlator.
    #[must_use]
    pub fn new(cpu_mhz: f64) -> Self {
        Self {
            events: Vec::new(),
            processes: HashMap::new(),
            kernel_modules: BTreeMap::new(),
            context_switches: Vec::new(),
            cpu_to_pid: HashMap::new(),
            tsc_anchors: Vec::new(),
            cpu_mhz,
        }
    }

    /// Ingest a sideband event.
    pub fn ingest(&mut self, event: SidebandEvent) {
        match &event {
            SidebandEvent::Mmap(e) => {
                let proc = self
                    .processes
                    .entry(e.pid)
                    .or_insert_with(|| ProcessInfo::new(e.pid, ""));
                proc.add_mmap(e.clone());
            }
            SidebandEvent::Comm(e) => {
                let proc = self
                    .processes
                    .entry(e.pid)
                    .or_insert_with(|| ProcessInfo::new(e.pid, &e.comm));
                proc.comm.clone_from(&e.comm);
            }
            SidebandEvent::Fork(e) => {
                // Clone parent mappings to child
                let parent_mmaps = self
                    .processes
                    .get(&e.ppid)
                    .map(|p| p.mmaps.clone())
                    .unwrap_or_default();
                let parent_comm = self
                    .processes
                    .get(&e.ppid)
                    .map(|p| p.comm.clone())
                    .unwrap_or_default();
                let parent_tids = if e.is_thread {
                    self.processes
                        .get(&e.ppid)
                        .map(|p| p.tids.clone())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                let child = self
                    .processes
                    .entry(e.pid)
                    .or_insert_with(|| ProcessInfo::new(e.pid, &parent_comm));
                child.ppid = e.ppid;
                if e.is_thread {
                    // Thread: share mappings
                    child.tids = parent_tids;
                    child.tids.push(e.tid);
                } else {
                    // Process fork: copy-on-write mappings
                    child.mmaps = parent_mmaps;
                }
            }
            SidebandEvent::Exit(e) => {
                if let Some(proc) = self.processes.get_mut(&e.pid) {
                    proc.exited = true;
                    proc.exit_code = Some(e.exit_code);
                }
            }
            SidebandEvent::Switch(e) => {
                if let Some(pid) = e.next_pid {
                    self.cpu_to_pid.insert(e.cpu, pid);
                }
                self.context_switches.push(e.clone());
            }
            SidebandEvent::ModuleLoad(e) => {
                if e.is_kernel {
                    self.kernel_modules.insert(e.base, e.clone());
                } else if let Some(proc) = self.processes.get_mut(&e.pid) {
                    proc.add_mmap(MmapEvent {
                        timestamp_ns: e.timestamp_ns,
                        pid: e.pid,
                        tid: e.pid,
                        addr: e.base,
                        len: e.size,
                        pgoff: 0,
                        filename: e.path.clone(),
                        is_exec: true,
                        is_anon: false,
                        dev_major: 0,
                        dev_minor: 0,
                        inode: 0,
                    });
                }
            }
        }
        self.events.push(event);
    }

    /// Add a TSC ↔ wall-clock anchor.
    pub fn add_tsc_anchor(&mut self, tsc: u64, timestamp_ns: u64) {
        self.tsc_anchors.push((tsc, timestamp_ns));
    }

    /// Convert a TSC value to nanoseconds using the nearest anchor.
    #[must_use]
    pub fn tsc_to_ns(&self, tsc: u64) -> Option<u64> {
        if self.tsc_anchors.is_empty() {
            // Fall back to plain MHz conversion from TSC 0
            let ns = crate::cast_helpers::f64_to_u64(crate::cast_helpers::u64_to_f64(tsc) / self.cpu_mhz * 1000.0);
            return Some(ns);
        }
        // Find the closest anchor before `tsc`
        let anchor = self
            .tsc_anchors
            .iter()
            .rev()
            .find(|(anchor_tsc, _)| *anchor_tsc <= tsc)?;
        let (anchor_tsc, anchor_ns) = *anchor;
        let delta_tsc = tsc.wrapping_sub(anchor_tsc);
        let delta_ns = crate::cast_helpers::f64_to_u64(crate::cast_helpers::u64_to_f64(delta_tsc) / self.cpu_mhz * 1000.0);
        Some(anchor_ns.saturating_add(delta_ns))
    }

    /// Look up the module name for an address and PID.
    #[must_use]
    pub fn module_for_addr(&self, pid: u32, addr: u64) -> Option<&str> {
        // Check kernel modules first (they are globally mapped)
        if let Some((_, km)) = self.kernel_modules.range(..=addr).next_back()
            && addr < km.base.saturating_add(km.size)
        {
            return Some(km.path.as_str());
        }
        // Check per-process mappings
        self.processes
            .get(&pid)
            .and_then(|p| p.module_name(addr))
    }

    /// Look up the binary file offset for an address and PID.
    #[must_use]
    pub fn file_offset_for_addr(&self, pid: u32, addr: u64) -> Option<u64> {
        self.processes
            .get(&pid)
            .and_then(|p| p.mapping_for_addr(addr))
            .and_then(|m| m.file_offset(addr))
    }

    /// Return the PID running on CPU at the given time.
    ///
    /// Scans the context switch log backwards from `timestamp_ns`.
    #[must_use]
    pub fn pid_at_time(&self, cpu: u32, timestamp_ns: u64) -> Option<u32> {
        // Walk backwards through context switches
        for sw in self.context_switches.iter().rev() {
            if sw.cpu == cpu && sw.timestamp_ns <= timestamp_ns {
                if !sw.is_switch_out {
                    return sw.next_pid;
                }
                return sw.prev_pid;
            }
        }
        self.cpu_to_pid.get(&cpu).copied()
    }

    /// Return all PIDs seen.
    #[must_use]
    pub fn all_pids(&self) -> Vec<u32> {
        self.processes.keys().copied().collect()
    }

    /// Return all executable mappings for a PID.
    #[must_use]
    pub fn exec_mappings_for_pid(&self, pid: u32) -> Vec<&MmapEvent> {
        self.processes
            .get(&pid)
            .map(|p| p.mmaps.values().filter(|m| m.is_exec).collect())
            .unwrap_or_default()
    }

    /// Build a module load timeline: list of (`timestamp_ns`, path, base, size).
    #[must_use]
    pub fn module_timeline(&self) -> Vec<(u64, String, u64, u64)> {
        let mut timeline: Vec<_> = self
            .events
            .iter()
            .filter_map(|e| {
                if let SidebandEvent::ModuleLoad(m) = e {
                    Some((m.timestamp_ns, m.path.clone(), m.base, m.size))
                } else {
                    None
                }
            })
            .collect();
        timeline.sort_by_key(|(ts, _, _, _)| *ts);
        timeline
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "SidebandCorrelator {{ events={}, pids={}, kernel_modules={}, switches={} }}",
            self.events.len(),
            self.processes.len(),
            self.kernel_modules.len(),
            self.context_switches.len()
        )
    }

    /// Find all address-range lookups that don't resolve to a module.
    ///
    /// Returns a list of (pid, addr) pairs that have no associated module.
    #[must_use]
    pub fn unresolved_addresses(&self, queries: &[(u32, u64)]) -> Vec<(u32, u64)> {
        queries
            .iter()
            .filter(|(pid, addr)| self.module_for_addr(*pid, *addr).is_none())
            .copied()
            .collect()
    }

    /// Compute the number of context switches per CPU.
    #[must_use]
    pub fn switches_per_cpu(&self) -> HashMap<u32, usize> {
        let mut map: HashMap<u32, usize> = HashMap::new();
        for sw in &self.context_switches {
            *map.entry(sw.cpu).or_insert(0) += 1;
        }
        map
    }

    /// Ingest multiple sideband events at once.
    pub fn ingest_batch(&mut self, events: Vec<SidebandEvent>) {
        for event in events {
            self.ingest(event);
        }
    }

    /// Remove mappings that ended before `timestamp_ns` (munmap approximation).
    ///
    /// This is a heuristic: we don't have explicit unmap events, so we assume
    /// a mapping that starts a new mapping at the same address replaces the old.
    pub const fn gc_old_mappings(&mut self, _timestamp_ns: u64) {
        // For now, just a no-op — a real implementation would cross-reference
        // mmap2 PROT_NONE events and mremap records.
    }
}

// ─── SidebandStats ────────────────────────────────────────────────────────────

/// Statistics about the sideband data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SidebandStats {
    /// Total sideband events.
    pub total_events: usize,
    /// MMAP events.
    pub mmap_events: usize,
    /// COMM events.
    pub comm_events: usize,
    /// FORK events.
    pub fork_events: usize,
    /// EXIT events.
    pub exit_events: usize,
    /// Context switch events.
    pub switch_events: usize,
    /// Module load events.
    pub module_events: usize,
    /// Unique PIDs.
    pub unique_pids: usize,
}

impl SidebandStats {
    /// Compute stats from a correlator.
    #[must_use]
    pub fn from_correlator(sc: &SidebandCorrelator) -> Self {
        let mut stats = Self {
            total_events: sc.events.len(),
            unique_pids: sc.processes.len(),
            ..Self::default()
        };
        for e in &sc.events {
            match e {
                SidebandEvent::Mmap(_) => stats.mmap_events += 1,
                SidebandEvent::Comm(_) => stats.comm_events += 1,
                SidebandEvent::Fork(_) => stats.fork_events += 1,
                SidebandEvent::Exit(_) => stats.exit_events += 1,
                SidebandEvent::Switch(_) => stats.switch_events += 1,
                SidebandEvent::ModuleLoad(_) => stats.module_events += 1,
            }
        }
        stats
    }
}

// ─── PerfParsedRecord ─────────────────────────────────────────────────────────

/// A parsed `perf.data` record ready for ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfParsedRecord {
    /// Record type.
    pub record_type: u32,
    /// Miscellaneous bits.
    pub misc: u16,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Timestamp (if present).
    pub timestamp_ns: Option<u64>,
    /// CPU (if present).
    pub cpu: Option<u32>,
    /// PID (if present).
    pub pid: Option<u32>,
    /// TID (if present).
    pub tid: Option<u32>,
}

/// Parse a batch of raw `perf.data` record bytes into sideband events.
///
/// This is a simplified parser that handles `PERF_RECORD_MMAP2` (type 10),
/// `PERF_RECORD_COMM` (type 3), `PERF_RECORD_FORK` (type 7),
/// `PERF_RECORD_EXIT` (type 4), and `PERF_RECORD_SWITCH` (type 14/15).
#[must_use]
pub fn parse_perf_records(data: &[u8]) -> Vec<SidebandEvent> {
    let mut events = Vec::new();
    let mut pos = 0usize;

    while pos + 8 <= data.len() {
        let record_type = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        let misc = u16::from_le_bytes([data[pos+4], data[pos+5]]);
        let size = u16::from_le_bytes([data[pos+6], data[pos+7]]) as usize;
        if size < 8 || pos + size > data.len() {
            break;
        }
        let payload = &data[pos+8..pos+size];

        match record_type {
            // PERF_RECORD_MMAP (type 1) — basic mmap
            1 => {
                // Need at least 32 bytes for the fixed fields + pgoff before the filename.
                if payload.len() >= 32 {
                    let pid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let tid = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let addr = u64::from_le_bytes([payload[8], payload[9], payload[10], payload[11],
                                                   payload[12], payload[13], payload[14], payload[15]]);
                    let len = u64::from_le_bytes([payload[16], payload[17], payload[18], payload[19],
                                                  payload[20], payload[21], payload[22], payload[23]]);
                    let filename = std::str::from_utf8(&payload[32..])
                        .ok()
                        .map(|s| s.trim_end_matches('\0').to_string())
                        .unwrap_or_default();
                    events.push(SidebandEvent::Mmap(MmapEvent::new_file(pid, tid, addr, len, filename)));
                }
            }
            // PERF_RECORD_COMM (type 3)
            3 => {
                if payload.len() >= 8 {
                    let pid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let tid = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let comm = std::str::from_utf8(&payload[8..])
                        .ok()
                        .map(|s| s.trim_end_matches('\0').to_string())
                        .unwrap_or_default();
                    events.push(SidebandEvent::Comm(CommEvent {
                        timestamp_ns: 0,
                        pid,
                        tid,
                        comm,
                        is_exec: false,
                    }));
                }
            }
            // PERF_RECORD_EXIT (type 4)
            4 => {
                if payload.len() >= 16 {
                    let pid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let tid = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    events.push(SidebandEvent::Exit(ExitEvent {
                        timestamp_ns: 0,
                        pid,
                        tid,
                        exit_code: 0,
                    }));
                }
            }
            // PERF_RECORD_FORK (type 7)
            7 => {
                if payload.len() >= 16 {
                    let pid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let parent_proc_id = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let thread_id = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                    let parent_thread_id = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                    events.push(SidebandEvent::Fork(ForkEvent {
                        timestamp_ns: 0,
                        pid,
                        tid: thread_id,
                        ppid: parent_proc_id,
                        ptid: parent_thread_id,
                        is_thread: pid == parent_proc_id,
                    }));
                }
            }
            // PERF_RECORD_SWITCH (type 14) / PERF_RECORD_SWITCH_CPU_WIDE (type 15)
            14 | 15 => {
                let is_switch_out = misc & 0x2000 != 0;
                events.push(SidebandEvent::Switch(ContextSwitchEvent {
                    timestamp_ns: 0,
                    cpu: 0,
                    is_switch_out,
                    next_pid: None,
                    next_tid: None,
                    prev_pid: None,
                    prev_tid: None,
                }));
            }
            _ => {}
        }

        pos += size;
    }

    events
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmap_event_contains() {
        let m = MmapEvent::new_file(1, 1, 0x1000, 0x2000, "/lib/libc.so");
        assert!(m.contains(0x1000));
        assert!(m.contains(0x2FFF));
        assert!(!m.contains(0x3000));
    }

    #[test]
    fn test_mmap_event_file_offset() {
        let mut m = MmapEvent::new_file(1, 1, 0x1000, 0x2000, "/lib/libc.so");
        m.pgoff = 0x4000;
        assert_eq!(m.file_offset(0x1500), Some(0x4500));
        assert_eq!(m.file_offset(0x5000), None);
    }

    #[test]
    fn test_ingest_mmap_creates_process() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(42, 42, 0x0040_0000, 0x10000, "/bin/foo")));
        assert!(sc.processes.contains_key(&42));
    }

    #[test]
    fn test_module_for_addr_user() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(1, 1, 0x0040_0000, 0x1000, "/bin/app")));
        assert_eq!(sc.module_for_addr(1, 0x0040_0500), Some("/bin/app"));
        assert_eq!(sc.module_for_addr(1, 0x0050_0000), None);
    }

    #[test]
    fn test_module_for_addr_kernel() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::ModuleLoad(ModuleLoadEvent::new_kernel(
            0xFFFF_8000_0000, 0x0010_0000, "[kernel]",
        )));
        assert_eq!(sc.module_for_addr(1, 0xFFFF_8000_1000), Some("[kernel]"));
    }

    #[test]
    fn test_comm_updates_process_name() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Comm(CommEvent {
            timestamp_ns: 0,
            pid: 7,
            tid: 7,
            comm: "myapp".into(),
            is_exec: true,
        }));
        assert_eq!(sc.processes[&7].comm, "myapp");
    }

    #[test]
    fn test_fork_copies_mappings() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(1, 1, 0x1000, 0x1000, "/bin/p")));
        sc.ingest(SidebandEvent::Fork(ForkEvent {
            timestamp_ns: 0,
            pid: 2,
            tid: 2,
            ppid: 1,
            ptid: 1,
            is_thread: false,
        }));
        // Child should have inherited parent mappings
        assert!(sc.processes[&2].mmaps.contains_key(&0x1000));
    }

    #[test]
    fn test_exit_marks_process() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Comm(CommEvent {
            timestamp_ns: 0,
            pid: 5,
            tid: 5,
            comm: "foo".into(),
            is_exec: false,
        }));
        sc.ingest(SidebandEvent::Exit(ExitEvent {
            timestamp_ns: 0,
            pid: 5,
            tid: 5,
            exit_code: 0,
        }));
        assert!(sc.processes[&5].exited);
    }

    #[test]
    fn test_context_switch_pid_at_time() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Switch(ContextSwitchEvent {
            timestamp_ns: 1000,
            cpu: 0,
            is_switch_out: false,
            next_pid: Some(42),
            next_tid: Some(42),
            prev_pid: None,
            prev_tid: None,
        }));
        assert_eq!(sc.pid_at_time(0, 2000), Some(42));
    }

    #[test]
    fn test_tsc_to_ns_without_anchor() {
        let sc = SidebandCorrelator::new(1000.0); // 1 GHz
        // 1000 ticks at 1 GHz = 1 µs = 1000 ns
        let ns = sc.tsc_to_ns(1000).unwrap();
        assert_eq!(ns, 1000);
    }

    #[test]
    fn test_tsc_to_ns_with_anchor() {
        let mut sc = SidebandCorrelator::new(1000.0);
        sc.add_tsc_anchor(0, 500); // TSC 0 = 500 ns
        let ns = sc.tsc_to_ns(1000).unwrap();
        // delta_tsc = 1000, at 1000 MHz = 1000 ns, + 500 anchor = 1500 ns
        assert_eq!(ns, 1500);
    }

    #[test]
    fn test_sideband_stats() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(1, 1, 0x1000, 0x1000, "a")));
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(1, 1, 0x2000, 0x1000, "b")));
        sc.ingest(SidebandEvent::Comm(CommEvent {
            timestamp_ns: 0, pid: 1, tid: 1, comm: "a".into(), is_exec: true
        }));
        let stats = SidebandStats::from_correlator(&sc);
        assert_eq!(stats.mmap_events, 2);
        assert_eq!(stats.comm_events, 1);
        assert_eq!(stats.total_events, 3);
    }

    #[test]
    fn test_exec_mappings_for_pid() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_file(1, 1, 0x1000, 0x1000, "/a")));
        sc.ingest(SidebandEvent::Mmap(MmapEvent::new_anon(1, 1, 0x3000, 0x1000)));
        let exec_maps = sc.exec_mappings_for_pid(1);
        assert_eq!(exec_maps.len(), 1);
        assert_eq!(exec_maps[0].filename, "/a");
    }

    #[test]
    fn test_file_offset_for_addr() {
        let mut sc = SidebandCorrelator::new(3000.0);
        let mut m = MmapEvent::new_file(1, 1, 0x0040_0000, 0x10000, "/bin/x");
        m.pgoff = 0x1000;
        sc.ingest(SidebandEvent::Mmap(m));
        let off = sc.file_offset_for_addr(1, 0x0040_0100);
        assert_eq!(off, Some(0x1100));
    }

    #[test]
    fn test_switches_per_cpu() {
        let mut sc = SidebandCorrelator::new(3000.0);
        for _ in 0..3 {
            sc.ingest(SidebandEvent::Switch(ContextSwitchEvent {
                timestamp_ns: 0,
                cpu: 0,
                is_switch_out: false,
                next_pid: Some(1),
                next_tid: Some(1),
                prev_pid: None,
                prev_tid: None,
            }));
        }
        let counts = sc.switches_per_cpu();
        assert_eq!(counts[&0], 3);
    }

    #[test]
    fn test_parse_perf_records_empty() {
        let events = parse_perf_records(&[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_process_info_mapping_lookup() {
        let mut p = ProcessInfo::new(1, "test");
        p.add_mmap(MmapEvent::new_file(1, 1, 0x1000, 0x500, "/lib/a"));
        p.add_mmap(MmapEvent::new_file(1, 1, 0x2000, 0x500, "/lib/b"));
        assert_eq!(p.module_name(0x1200), Some("/lib/a"));
        assert_eq!(p.module_name(0x2300), Some("/lib/b"));
        assert_eq!(p.module_name(0x5000), None);
    }

    #[test]
    fn test_summary_string() {
        let sc = SidebandCorrelator::new(3000.0);
        let s = sc.summary();
        assert!(s.contains("SidebandCorrelator"));
    }

    #[test]
    fn test_all_pids() {
        let mut sc = SidebandCorrelator::new(3000.0);
        sc.ingest(SidebandEvent::Comm(CommEvent {
            timestamp_ns: 0, pid: 1, tid: 1, comm: "a".into(), is_exec: false,
        }));
        sc.ingest(SidebandEvent::Comm(CommEvent {
            timestamp_ns: 0, pid: 2, tid: 2, comm: "b".into(), is_exec: false,
        }));
        let pids = sc.all_pids();
        assert!(pids.contains(&1));
        assert!(pids.contains(&2));
    }
}
