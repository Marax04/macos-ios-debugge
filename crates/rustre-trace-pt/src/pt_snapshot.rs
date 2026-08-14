//! `pt_snapshot` — Kernel Intel PT snapshot infrastructure.
//!
//! Models the Linux `perf_event_open`-based PT capture path including:
//! - `perf_event_attr` configuration for Intel PT
//! - AUX buffer management and ring-buffer mechanics
//! - `ToPA` (Table of Physical Addresses) setup
//! - Overflow / TOPA-STOP handling
//! - Multi-CPU snapshot coordination

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── PerfEventType ────────────────────────────────────────────────────────────

/// `perf_event_attr.type` values relevant to Intel PT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum PerfEventType {
    /// `PERF_TYPE_HARDWARE`
    Hardware = 0,
    /// `PERF_TYPE_SOFTWARE`
    Software = 1,
    /// `PERF_TYPE_TRACEPOINT`
    Tracepoint = 2,
    /// `PERF_TYPE_RAW`
    Raw = 4,
    /// Intel PT — dynamic type from `/sys/bus/event_source/devices/intel_pt/type`
    IntelPt = 8,
}

// ─── PtPerfConfig ─────────────────────────────────────────────────────────────

/// Configuration bits for `perf_event_attr.config` (Intel PT-specific).
///
/// These correspond to the bits described in:
/// `/sys/bus/event_source/devices/intel_pt/format/`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PtPerfConfig {
    /// Enable cycle-accurate mode (CYC packets).
    pub cyc: bool,
    /// CYC threshold (0-15).
    pub cyc_thresh: u8,
    /// Enable MTC packets.
    pub mtc: bool,
    /// MTC frequency select (0-15).
    pub mtc_freq: u8,
    /// Enable timestamp (TSC) packets.
    pub tsc: bool,
    /// Enable power event (PWR) packets.
    pub pwr: bool,
    /// Enable branch tracing.
    pub branch: bool,
    /// Filter by CPL (ring level): 0=all, 1=kernel only, 2=user only.
    pub cpl: u8,
    /// Enable CR3 filtering (requires sideband).
    pub cr3_filter: bool,
    /// Enable address range filtering.
    pub addr_filter: bool,
    /// Number of address ranges (0-3).
    pub addr_filter_count: u8,
}

impl PtPerfConfig {
    /// Create a minimal configuration (branch trace + timestamps, user space only).
    #[must_use]
    pub const fn user_branch_trace() -> Self {
        Self {
            branch: true,
            tsc: true,
            cpl: 2, // user space only
            cyc: false,
            cyc_thresh: 0,
            mtc: false,
            mtc_freq: 0,
            pwr: false,
            cr3_filter: false,
            addr_filter: false,
            addr_filter_count: 0,
        }
    }

    /// Create a full kernel+user trace with cycle counting.
    #[must_use]
    pub const fn full_trace_with_cyc() -> Self {
        Self {
            branch: true,
            tsc: true,
            cpl: 0, // all levels
            cyc: true,
            cyc_thresh: 1,
            mtc: true,
            mtc_freq: 3,
            pwr: true,
            cr3_filter: false,
            addr_filter: false,
            addr_filter_count: 0,
        }
    }

    /// Encode as a 64-bit `perf_event_attr.config` field.
    ///
    /// Bit layout from Intel PT PMU format files:
    /// - bits[3:0]  = `cyc_thresh`
    /// - bit[4]     = cyc
    /// - bits[8:5]  = `mtc_freq`
    /// - bit[9]     = mtc
    /// - bit[10]    = tsc
    /// - bit[11]    = pwr
    /// - bit[12]    = branch
    /// - bits[14:13]= cpl
    /// - bit[15]    = `cr3_filter`
    /// - bit[16]    = `addr_filter`
    #[must_use]
    pub fn encode(&self) -> u64 {
        let mut v: u64 = 0;
        v |= u64::from(self.cyc_thresh) & 0xF;
        if self.cyc { v |= 1 << 4; }
        v |= (u64::from(self.mtc_freq) & 0xF) << 5;
        if self.mtc { v |= 1 << 9; }
        if self.tsc { v |= 1 << 10; }
        if self.pwr { v |= 1 << 11; }
        if self.branch { v |= 1 << 12; }
        v |= (u64::from(self.cpl) & 0x3) << 13;
        if self.cr3_filter { v |= 1 << 15; }
        if self.addr_filter { v |= 1 << 16; }
        v
    }

    /// Decode from a 64-bit `perf_event_attr.config` field.
    #[must_use]
    pub const fn decode(v: u64) -> Self {
        Self {
            cyc_thresh: (v & 0xF) as u8,
            cyc: (v >> 4) & 1 != 0,
            mtc_freq: ((v >> 5) & 0xF) as u8,
            mtc: (v >> 9) & 1 != 0,
            tsc: (v >> 10) & 1 != 0,
            pwr: (v >> 11) & 1 != 0,
            branch: (v >> 12) & 1 != 0,
            cpl: ((v >> 13) & 0x3) as u8,
            cr3_filter: (v >> 15) & 1 != 0,
            addr_filter: (v >> 16) & 1 != 0,
            addr_filter_count: 0,
        }
    }
}

// ─── AddressRangeFilter ───────────────────────────────────────────────────────

/// An IP address range filter for Intel PT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRangeFilter {
    /// Filter start (inclusive).
    pub start: u64,
    /// Filter end (exclusive).
    pub end: u64,
    /// Whether this is a stop filter (stop tracing in range) vs start filter.
    pub is_stop: bool,
}

impl AddressRangeFilter {
    /// Create a start-only filter (trace only when IP is in range).
    #[must_use]
    pub const fn trace_range(start: u64, end: u64) -> Self {
        Self { start, end, is_stop: false }
    }

    /// Create a stop filter (stop tracing when IP is in range).
    #[must_use]
    pub const fn stop_range(start: u64, end: u64) -> Self {
        Self { start, end, is_stop: true }
    }

    /// Check if `ip` falls in the filter range.
    #[must_use]
    pub const fn contains(&self, ip: u64) -> bool {
        ip >= self.start && ip < self.end
    }

    /// Encode as the two `RTIT_ADDR` MSR values.
    #[must_use]
    pub const fn encode_msrs(&self) -> (u64, u64) {
        (self.start, self.end)
    }
}

// ─── TopaEntry ────────────────────────────────────────────────────────────────

/// A single `ToPA` (Table of Physical Addresses) entry.
///
/// Each `ToPA` entry specifies a physical memory region and optional interrupt/
/// stop flags.  The hardware writes trace data sequentially through the table
/// and wraps to the beginning when the last entry with the STOP flag is hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopaEntry {
    /// Physical base address of the buffer (must be page-aligned).
    pub phys_addr: u64,
    /// Buffer size exponent (size = `2^(size_exp` + 12) bytes, min 4 KiB).
    pub size_exp: u8,
    /// Whether to generate an interrupt when this entry is filled.
    pub intr: bool,
    /// Whether to stop tracing when this entry is filled.
    pub stop: bool,
    /// Whether this is the end-of-table marker.
    pub end: bool,
}

impl TopaEntry {
    /// Create a normal trace buffer entry.
    ///
    /// `phys_addr`: physical address, must be page-aligned.
    /// `size_exp`: 0=4K, 1=8K, ..., 10=4M, etc.
    #[must_use]
    pub const fn new(phys_addr: u64, size_exp: u8) -> Self {
        Self {
            phys_addr,
            size_exp,
            intr: false,
            stop: false,
            end: false,
        }
    }

    /// Create an interrupt-on-fill entry.
    #[must_use]
    pub const fn with_intr(mut self) -> Self {
        self.intr = true;
        self
    }

    /// Create a stop-on-fill entry.
    #[must_use]
    pub const fn with_stop(mut self) -> Self {
        self.stop = true;
        self
    }

    /// Mark as the end-of-table entry (hardware loops back to start).
    #[must_use]
    pub const fn as_end_marker(phys_table_base: u64) -> Self {
        Self {
            phys_addr: phys_table_base,
            size_exp: 0,
            intr: false,
            stop: false,
            end: true,
        }
    }

    /// Return the size of this entry's buffer in bytes.
    #[must_use]
    pub const fn buffer_size(&self) -> u64 {
        4096 << self.size_exp as u64
    }

    /// Encode as a 64-bit `ToPA` hardware entry.
    ///
    /// `ToPA` entry format (from Intel SDM Volume 3C Table 36-5):
    /// - bits[63:12] = physical base address >> 12
    /// - bit[4]      = STOP
    /// - bit[2]      = INTR
    /// - bit[1]      = END
    /// - bits[11:6]  = size (2^(size+12) bytes)
    #[must_use]
    pub fn encode(&self) -> u64 {
        let mut v = self.phys_addr & !0xFFF;
        v |= (u64::from(self.size_exp) & 0x3F) << 6;
        if self.stop { v |= 1 << 4; }
        if self.intr { v |= 1 << 2; }
        if self.end  { v |= 1 << 1; }
        v
    }
}

// ─── TopaTable ────────────────────────────────────────────────────────────────

/// A complete `ToPA` (Table of Physical Addresses) for Intel PT.
///
/// On hardware, the `RTIT_OUTPUT_MASK_PTRS` MSR contains the current write
/// position within the table.  On overflow, the hardware stops or wraps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopaTable {
    /// Entries in the table.
    pub entries: Vec<TopaEntry>,
    /// Physical address of this table itself.
    pub table_phys_addr: u64,
    /// Current write position (entry index).
    pub write_entry: usize,
    /// Byte offset within the current entry's buffer.
    pub write_offset: u64,
    /// Total bytes captured.
    pub total_captured: u64,
    /// Total bytes lost due to overflow.
    pub bytes_lost: u64,
    /// Overflow count.
    pub overflow_count: u64,
}

impl TopaTable {
    /// Create a new single-entry `ToPA` for a contiguous `size`-byte buffer.
    ///
    /// `buf_phys`: physical address of the trace buffer.
    /// `size_exp`: buffer size exponent (4KiB * `2^size_exp`).
    #[must_use]
    pub fn new_single(table_phys: u64, buf_phys: u64, size_exp: u8) -> Self {
        let entry = TopaEntry::new(buf_phys, size_exp).with_intr();
        let end = TopaEntry::as_end_marker(table_phys);
        Self {
            entries: vec![entry, end],
            table_phys_addr: table_phys,
            write_entry: 0,
            write_offset: 0,
            total_captured: 0,
            bytes_lost: 0,
            overflow_count: 0,
        }
    }

    /// Create a multi-entry `ToPA` from a list of buffers.
    #[must_use]
    pub fn new_multi(table_phys: u64, buffers: &[(u64, u8)]) -> Self {
        let mut entries: Vec<TopaEntry> = buffers
            .iter()
            .enumerate()
            .map(|(i, (phys, exp))| {
                let mut e = TopaEntry::new(*phys, *exp);
                if i == buffers.len() - 1 {
                    e.intr = true; // interrupt on last entry
                }
                e
            })
            .collect();
        entries.push(TopaEntry::as_end_marker(table_phys));
        Self {
            entries,
            table_phys_addr: table_phys,
            write_entry: 0,
            write_offset: 0,
            total_captured: 0,
            bytes_lost: 0,
            overflow_count: 0,
        }
    }

    /// Return the total usable buffer size (excluding the END marker).
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| !e.end)
            .map(TopaEntry::buffer_size)
            .sum()
    }

    /// Simulate writing `n` bytes of trace data.
    ///
    /// Advances `write_entry`/`write_offset` and handles overflow.
    pub fn simulate_write(&mut self, n: u64) {
        let mut remaining = n;
        while remaining > 0 {
            if self.write_entry >= self.entries.len() {
                self.overflow_count += 1;
                self.bytes_lost += remaining;
                return;
            }
            let entry = &self.entries[self.write_entry];
            if entry.end {
                // Wrap around (ring buffer mode)
                self.write_entry = 0;
                continue;
            }
            let buf_size = entry.buffer_size();
            let space = buf_size - self.write_offset;
            if remaining <= space {
                self.write_offset += remaining;
                self.total_captured += remaining;
                remaining = 0;
            } else {
                self.total_captured += space;
                remaining -= space;
                self.write_offset = 0;
                self.write_entry += 1;
                // Check for STOP or INTR
                if entry.stop {
                    self.bytes_lost += remaining;
                    self.overflow_count += 1;
                    return;
                }
            }
        }
    }

    /// Return the percentage of the `ToPA` that has been used.
    #[must_use]
    pub fn usage_pct(&self) -> f64 {
        let total = self.total_size();
        if total == 0 { return 0.0; }
        crate::cast_helpers::u64_to_f64(self.total_captured) / crate::cast_helpers::u64_to_f64(total) * 100.0
    }

    /// Reset the write position to the start.
    pub const fn reset_write_ptr(&mut self) {
        self.write_entry = 0;
        self.write_offset = 0;
    }

    /// Return whether any entry has the STOP flag set.
    #[must_use]
    pub fn has_stop_entry(&self) -> bool {
        self.entries.iter().any(|e| e.stop)
    }
}

// ─── AuxBuffer ────────────────────────────────────────────────────────────────

/// Simulates a `perf_event` AUX ring buffer for Intel PT.
///
/// The AUX buffer is mapped by the kernel via `mmap` at offset
/// `perf_event_mmap_page.aux_offset`.  The ring buffer has separate head/tail
/// pointers managed by the kernel (producer) and user (consumer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxBuffer {
    /// Buffer capacity in bytes (must be a power of 2 for ring mode).
    pub capacity: usize,
    /// Data stored in the buffer.
    data: Vec<u8>,
    /// Kernel write head (bytes written mod capacity).
    pub head: usize,
    /// User read tail.
    pub tail: usize,
    /// Whether the buffer has overflowed.
    pub overflowed: bool,
    /// Total bytes produced.
    pub total_produced: u64,
    /// Total bytes consumed.
    pub total_consumed: u64,
}

impl AuxBuffer {
    /// Create a new AUX buffer of `capacity` bytes.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// Panics if `capacity` is not a power of two.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "AUX buffer size must be power of 2");
        Self {
            capacity,
            data: vec![0u8; capacity],
            head: 0,
            tail: 0,
            overflowed: false,
            total_produced: 0,
            total_consumed: 0,
        }
    }

    /// Write trace data (simulating the kernel DMA write path).
    pub fn write(&mut self, bytes: &[u8]) {
        let available = self.available_for_write();
        if bytes.len() > available {
            self.overflowed = true;
            return;
        }
        let mask = self.capacity - 1;
        for &b in bytes {
            self.data[self.head & mask] = b;
            self.head = self.head.wrapping_add(1);
        }
        self.total_produced += bytes.len() as u64;
    }

    /// Read and consume `n` bytes from the buffer.
    #[must_use]
    pub fn read(&mut self, n: usize) -> Vec<u8> {
        let mask = self.capacity - 1;
        let readable = self.available_for_read();
        let to_read = n.min(readable);
        let mut out = Vec::with_capacity(to_read);
        for _ in 0..to_read {
            out.push(self.data[self.tail & mask]);
            self.tail = self.tail.wrapping_add(1);
        }
        self.total_consumed += to_read as u64;
        out
    }

    /// Return the number of bytes available to read.
    #[must_use]
    pub const fn available_for_read(&self) -> usize {
        self.head.wrapping_sub(self.tail) & (self.capacity * 2 - 1)
    }

    /// Return the number of bytes available to write.
    #[must_use]
    pub const fn available_for_write(&self) -> usize {
        self.capacity - self.available_for_read()
    }

    /// Return whether the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.available_for_read() == 0
    }

    /// Return fill fraction (0.0 to 1.0).
    #[must_use]
    pub fn fill_fraction(&self) -> f64 {
        crate::cast_helpers::usize_to_f64(self.available_for_read()) / crate::cast_helpers::usize_to_f64(self.capacity)
    }

    /// Drain all available data.
    #[must_use]
    pub fn drain_all(&mut self) -> Vec<u8> {
        let n = self.available_for_read();
        self.read(n)
    }

    /// Reset the buffer (simulating a re-open).
    pub const fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.overflowed = false;
    }
}

// ─── PtCpuSnapshot ────────────────────────────────────────────────────────────

/// A snapshot of PT trace data from one CPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtCpuSnapshot {
    /// CPU number.
    pub cpu: u32,
    /// PID being traced (0 = whole system).
    pub pid: u32,
    /// Raw trace bytes captured.
    pub trace_data: Vec<u8>,
    /// Whether the snapshot is complete (no overflow).
    pub complete: bool,
    /// `ToPA` overflow count during this snapshot.
    pub overflow_count: u64,
    /// TSC at snapshot start.
    pub start_tsc: Option<u64>,
    /// TSC at snapshot end.
    pub end_tsc: Option<u64>,
    /// Perf AUX event sequence number.
    pub seq: u64,
}

impl PtCpuSnapshot {
    /// Create an empty snapshot for `cpu`.
    #[must_use]
    pub const fn new(cpu: u32, pid: u32) -> Self {
        Self {
            cpu,
            pid,
            trace_data: Vec::new(),
            complete: true,
            overflow_count: 0,
            start_tsc: None,
            end_tsc: None,
            seq: 0,
        }
    }

    /// Append trace data.
    pub fn append(&mut self, data: &[u8]) {
        self.trace_data.extend_from_slice(data);
    }

    /// Return the size of the trace data.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.trace_data.len()
    }
}

// ─── PtSnapshotSession ────────────────────────────────────────────────────────

/// Manages a multi-CPU PT trace snapshot session.
pub struct PtSnapshotSession {
    /// Configuration.
    pub config: PtPerfConfig,
    /// Per-CPU snapshots.
    pub snapshots: HashMap<u32, PtCpuSnapshot>,
    /// Per-CPU AUX buffers.
    pub aux_buffers: HashMap<u32, AuxBuffer>,
    /// Per-CPU `ToPA` tables.
    pub topa_tables: HashMap<u32, TopaTable>,
    /// Address range filters.
    pub addr_filters: Vec<AddressRangeFilter>,
    /// Whether the session is active.
    pub active: bool,
    /// Number of overflows since the session started.
    pub total_overflows: u64,
    /// Session sequence counter.
    pub seq: u64,
}

impl PtSnapshotSession {
    /// Create a new session with default configuration.
    #[must_use]
    pub fn new(config: PtPerfConfig) -> Self {
        Self {
            config,
            snapshots: HashMap::new(),
            aux_buffers: HashMap::new(),
            topa_tables: HashMap::new(),
            addr_filters: Vec::new(),
            active: false,
            total_overflows: 0,
            seq: 0,
        }
    }

    /// Configure a CPU for tracing.
    ///
    /// `cpu`: CPU number.
    /// `pid`: PID to trace (0 = all).
    /// `aux_size_kb`: AUX buffer size in KiB (must be power of 2, min 4).
    pub fn configure_cpu(&mut self, cpu: u32, pid: u32, aux_size_kb: usize) {
        let aux_size = aux_size_kb * 1024;
        // Round up to power of two
        let aux_size = if aux_size.is_power_of_two() {
            aux_size
        } else {
            aux_size.next_power_of_two()
        };
        self.aux_buffers.insert(cpu, AuxBuffer::new(aux_size));
        self.snapshots.insert(cpu, PtCpuSnapshot::new(cpu, pid));
        // Create a simple single-entry ToPA (simulated)
        let table_phys = 0x1000_0000 + u64::from(cpu) * 0x100_0000;
        let buf_phys   = 0x2000_0000 + u64::from(cpu) * 0x100_0000;
        let size_exp = crate::cast_helpers::u32_to_u8((aux_size / 4096).trailing_zeros());
        self.topa_tables.insert(
            cpu,
            TopaTable::new_single(table_phys, buf_phys, size_exp),
        );
    }

    /// Add an IP address range filter.
    pub fn add_filter(&mut self, filter: AddressRangeFilter) {
        self.addr_filters.push(filter);
    }

    /// Start the session.
    pub const fn start(&mut self) {
        self.active = true;
        self.seq += 1;
    }

    /// Stop the session and collect snapshots.
    pub fn stop(&mut self) {
        self.active = false;
        // Drain all AUX buffers into snapshots
        for (cpu, buf) in &mut self.aux_buffers {
            if let Some(snap) = self.snapshots.get_mut(cpu) {
                let data = buf.drain_all();
                snap.append(&data);
                snap.seq = self.seq;
                if buf.overflowed {
                    snap.complete = false;
                    snap.overflow_count += 1;
                    self.total_overflows += 1;
                }
            }
        }
    }

    /// Simulate writing trace data to a CPU's AUX buffer.
    pub fn write_trace(&mut self, cpu: u32, data: &[u8]) {
        if let Some(buf) = self.aux_buffers.get_mut(&cpu) {
            buf.write(data);
        }
        if let Some(topa) = self.topa_tables.get_mut(&cpu) {
            topa.simulate_write(data.len() as u64);
        }
    }

    /// Return the combined trace data from all CPUs in CPU order.
    #[must_use]
    pub fn all_trace_data(&self) -> Vec<(u32, &[u8])> {
        let mut cpus: Vec<u32> = Vec::with_capacity(self.snapshots.len());
        cpus.extend(self.snapshots.keys().copied());
        cpus.sort_unstable();
        cpus.iter()
            .filter_map(|cpu| {
                self.snapshots.get(cpu).map(|s| (*cpu, s.trace_data.as_slice()))
            })
            .collect()
    }

    /// Return a summary.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        let total_bytes: usize = self.snapshots.values().map(PtCpuSnapshot::size).sum();
        let cpus_configured = self.snapshots.len();
        let complete_snapshots = self.snapshots.values().filter(|s| s.complete).count();
        SessionSummary {
            active: self.active,
            cpus_configured,
            total_trace_bytes: total_bytes,
            complete_snapshots,
            total_overflows: self.total_overflows,
            seq: self.seq,
        }
    }

    /// Check whether any address passes the configured filters.
    #[must_use]
    pub fn address_passes_filters(&self, ip: u64) -> bool {
        if self.addr_filters.is_empty() {
            return true;
        }
        self.addr_filters.iter().any(|f| !f.is_stop && f.contains(ip))
    }
}

// ─── SessionSummary ───────────────────────────────────────────────────────────

/// Summary of a `PtSnapshotSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Whether the session is active.
    pub active: bool,
    /// Number of CPUs configured.
    pub cpus_configured: usize,
    /// Total trace bytes collected.
    pub total_trace_bytes: usize,
    /// Number of complete (no-overflow) snapshots.
    pub complete_snapshots: usize,
    /// Total overflow events.
    pub total_overflows: u64,
    /// Session sequence counter.
    pub seq: u64,
}

impl std::fmt::Display for SessionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session[seq={}, cpus={}, bytes={}, overflows={}, complete={}/{}]",
            self.seq,
            self.cpus_configured,
            self.total_trace_bytes,
            self.total_overflows,
            self.complete_snapshots,
            self.cpus_configured,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pt_perf_config_encode_decode() {
        let cfg = PtPerfConfig {
            cyc: true,
            cyc_thresh: 3,
            mtc: true,
            mtc_freq: 5,
            tsc: true,
            pwr: false,
            branch: true,
            cpl: 2,
            cr3_filter: false,
            addr_filter: false,
            addr_filter_count: 0,
        };
        let encoded = cfg.encode();
        let decoded = PtPerfConfig::decode(encoded);
        assert_eq!(decoded.cyc, cfg.cyc);
        assert_eq!(decoded.cyc_thresh, cfg.cyc_thresh);
        assert_eq!(decoded.mtc, cfg.mtc);
        assert_eq!(decoded.mtc_freq, cfg.mtc_freq);
        assert_eq!(decoded.tsc, cfg.tsc);
        assert_eq!(decoded.branch, cfg.branch);
        assert_eq!(decoded.cpl, cfg.cpl);
    }

    #[test]
    fn test_topa_entry_buffer_size() {
        let e = TopaEntry::new(0x1000, 0); // 4 KiB
        assert_eq!(e.buffer_size(), 4096);
        let e2 = TopaEntry::new(0x1000, 2); // 16 KiB
        assert_eq!(e2.buffer_size(), 16384);
    }

    #[test]
    fn test_topa_entry_encode() {
        let e = TopaEntry {
            phys_addr: 0x1000,
            size_exp: 0,
            intr: true,
            stop: false,
            end: false,
        };
        let enc = e.encode();
        assert!(enc & 0x1000 != 0); // base address
        assert!(enc & (1 << 2) != 0); // INTR bit
    }

    #[test]
    fn test_topa_table_single_total_size() {
        let t = TopaTable::new_single(0x1000, 0x2000, 0); // 4 KiB buffer
        assert_eq!(t.total_size(), 4096);
    }

    #[test]
    fn test_topa_table_simulate_write() {
        let mut t = TopaTable::new_single(0x1000, 0x2000, 0); // 4 KiB
        t.simulate_write(2048);
        assert_eq!(t.total_captured, 2048);
        assert_eq!(t.write_offset, 2048);
    }

    #[test]
    fn test_topa_table_overflow() {
        let mut t = TopaTable::new_single(0x1000, 0x2000, 0); // 4 KiB
        t.entries[0].stop = true;
        t.simulate_write(4096); // exactly fill
        t.simulate_write(100);  // overflow
        assert!(t.bytes_lost > 0);
        assert_eq!(t.overflow_count, 1);
    }

    #[test]
    fn test_aux_buffer_write_read() {
        let mut buf = AuxBuffer::new(4096);
        buf.write(b"hello");
        let data = buf.read(5);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_aux_buffer_fill_fraction() {
        let mut buf = AuxBuffer::new(1024);
        buf.write(&vec![0u8; 512]);
        assert!((buf.fill_fraction() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_aux_buffer_overflow() {
        let mut buf = AuxBuffer::new(1024);
        buf.write(&vec![0u8; 1025]); // one byte over capacity
        assert!(buf.overflowed);
    }

    #[test]
    fn test_aux_buffer_drain_all() {
        let mut buf = AuxBuffer::new(256);
        buf.write(b"trace_data");
        let d = buf.drain_all();
        assert_eq!(d, b"trace_data");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_snapshot_session_configure_and_write() {
        let cfg = PtPerfConfig::user_branch_trace();
        let mut sess = PtSnapshotSession::new(cfg);
        sess.configure_cpu(0, 1234, 64); // 64 KiB AUX
        sess.start();
        sess.write_trace(0, b"PTDATA");
        sess.stop();
        let all = sess.all_trace_data();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, b"PTDATA");
    }

    #[test]
    fn test_snapshot_session_summary() {
        let cfg = PtPerfConfig::user_branch_trace();
        let mut sess = PtSnapshotSession::new(cfg);
        sess.configure_cpu(0, 0, 64);
        sess.configure_cpu(1, 0, 64);
        sess.start();
        sess.stop();
        let s = sess.summary();
        assert_eq!(s.cpus_configured, 2);
        let _disp = s.to_string();
    }

    #[test]
    fn test_address_range_filter() {
        let f = AddressRangeFilter::trace_range(0x1000, 0x2000);
        assert!(f.contains(0x1500));
        assert!(!f.contains(0x2000));
        let (start, end) = f.encode_msrs();
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x2000);
    }

    #[test]
    fn test_session_addr_filter() {
        let cfg = PtPerfConfig::user_branch_trace();
        let mut sess = PtSnapshotSession::new(cfg);
        sess.add_filter(AddressRangeFilter::trace_range(0x1000, 0x2000));
        assert!(sess.address_passes_filters(0x1500));
        assert!(!sess.address_passes_filters(0x3000));
    }

    #[test]
    fn test_topa_multi_entry() {
        let buffers = vec![
            (0x1000u64, 0u8), // 4 KiB
            (0x2000u64, 1u8), // 8 KiB
        ];
        let t = TopaTable::new_multi(0x100, &buffers);
        assert_eq!(t.total_size(), 4096 + 8192);
    }

    #[test]
    fn test_cpu_snapshot_append() {
        let mut snap = PtCpuSnapshot::new(0, 1);
        snap.append(b"abc");
        snap.append(b"def");
        assert_eq!(snap.size(), 6);
        assert_eq!(&snap.trace_data, b"abcdef");
    }

    #[test]
    fn test_user_branch_trace_config() {
        let cfg = PtPerfConfig::user_branch_trace();
        assert!(cfg.branch);
        assert!(cfg.tsc);
        assert_eq!(cfg.cpl, 2);
        assert!(!cfg.cyc);
    }

    #[test]
    fn test_full_trace_config() {
        let cfg = PtPerfConfig::full_trace_with_cyc();
        assert!(cfg.cyc);
        assert!(cfg.mtc);
        assert_eq!(cfg.cpl, 0);
    }
}
