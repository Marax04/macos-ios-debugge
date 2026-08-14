//! `pt_timing_analyzer` — Analyze timing information from Intel Processor Trace.
//!
//! Intel PT encodes cycle-accurate timing via CYC (cycle count) and MTC
//! (mini time counter) packets.  This module reconstructs per-block timing,
//! computes IPC (instructions per cycle), and reports hot/slow regions.

use std::collections::HashMap;
use std::fmt;

// ── CycleCount ────────────────────────────────────────────────────────────────

/// A 64-bit cycle counter value.
///
/// In real PT the CYC packet carries a variable-width count; here we use the
/// full 64-bit accumulated TSC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CycleCount(pub u64);

impl CycleCount {
    /// Create from a raw u64.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Compute the difference to another (later) cycle count.
    #[must_use]
    pub const fn delta(self, later: Self) -> u64 {
        later.0.saturating_sub(self.0)
    }
}

impl fmt::Display for CycleCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for CycleCount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for CycleCount {
    type Output = u64;
    fn sub(self, rhs: Self) -> u64 {
        self.0.saturating_sub(rhs.0)
    }
}

// ── TimingPacket ──────────────────────────────────────────────────────────────

/// The kind of timing packet encountered in the PT stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingPacketKind {
    /// CYC packet — carries a differential cycle count.
    Cyc,
    /// MTC packet — mini time counter from the `IA32_TSC_ART` register.
    Mtc,
    /// TSC packet — full TSC value.
    Tsc,
    /// CBR packet — core bus ratio.
    Cbr,
    /// TRIG (trigger) extension packet (future use).
    Trig,
}

impl fmt::Display for TimingPacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Cyc => "CYC",
            Self::Mtc => "MTC",
            Self::Tsc => "TSC",
            Self::Cbr => "CBR",
            Self::Trig => "TRIG",
        };
        f.write_str(s)
    }
}

/// A decoded timing packet from the PT stream.
#[derive(Debug, Clone)]
pub struct TimingPacket {
    /// The kind of timing packet.
    pub kind: TimingPacketKind,
    /// Raw value carried by the packet.
    pub raw_value: u64,
    /// Reconstructed TSC value at the point this packet was emitted.
    pub tsc: CycleCount,
    /// Index of the basic block this packet is associated with.
    pub block_index: u64,
    /// Core bus ratio (only meaningful for CBR packets).
    pub core_bus_ratio: Option<u8>,
}

impl TimingPacket {
    /// Create a CYC packet.
    #[must_use]
    pub const fn cyc(raw: u64, tsc: CycleCount, block_index: u64) -> Self {
        Self {
            kind: TimingPacketKind::Cyc,
            raw_value: raw,
            tsc,
            block_index,
            core_bus_ratio: None,
        }
    }

    /// Create a TSC packet.
    #[must_use]
    pub const fn tsc(raw: u64, block_index: u64) -> Self {
        Self {
            kind: TimingPacketKind::Tsc,
            raw_value: raw,
            tsc: CycleCount::new(raw),
            block_index,
            core_bus_ratio: None,
        }
    }

    /// Create a CBR packet.
    #[must_use]
    pub fn cbr(ratio: u8, tsc: CycleCount, block_index: u64) -> Self {
        Self {
            kind: TimingPacketKind::Cbr,
            raw_value: u64::from(ratio),
            tsc,
            block_index,
            core_bus_ratio: Some(ratio),
        }
    }
}

impl fmt::Display for TimingPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[block={:08}] {} raw=0x{:x} tsc={}",
            self.block_index, self.kind, self.raw_value, self.tsc
        )
    }
}

// ── BlockTiming ───────────────────────────────────────────────────────────────

/// Timing information for a single decoded basic block.
#[derive(Debug, Clone)]
pub struct BlockTiming {
    /// Block sequence index.
    pub block_index: u64,
    /// Instruction pointer of the block.
    pub start_ip: u64,
    /// Number of instructions in the block.
    pub insn_count: u32,
    /// TSC at the start of the block (first timing packet before block).
    pub tsc_start: CycleCount,
    /// TSC at the end of the block (last timing packet before next block).
    pub tsc_end: CycleCount,
    /// Cycles consumed by this block.
    pub cycles: u64,
    /// Computed IPC (may be `f64::NAN` if cycles == 0).
    pub ipc: f64,
    /// Core-bus ratio at the time this block executed.
    pub core_bus_ratio: u8,
}

impl BlockTiming {
    /// Create a block timing record.
    #[must_use]
    pub fn new(
        block_index: u64,
        start_ip: u64,
        insn_count: u32,
        tsc_start: CycleCount,
        tsc_end: CycleCount,
        cbr: u8,
    ) -> Self {
        let cycles = tsc_start.delta(tsc_end);
        let ipc = if cycles == 0 {
            f64::NAN
        } else {
            f64::from(insn_count) / crate::cast_helpers::u64_to_f64(cycles)
        };
        Self {
            block_index,
            start_ip,
            insn_count,
            tsc_start,
            tsc_end,
            cycles,
            ipc,
            core_bus_ratio: cbr,
        }
    }

    /// Return the wall-clock time in nanoseconds given a TSC frequency.
    #[must_use]
    pub fn duration_ns(&self, tsc_hz: u64) -> f64 {
        if tsc_hz == 0 {
            return 0.0;
        }
        crate::cast_helpers::u64_to_f64(self.cycles) / crate::cast_helpers::u64_to_f64(tsc_hz) * 1e9
    }

    /// Return `true` if IPC is above the given threshold.
    #[must_use]
    pub fn is_hot(&self, threshold: f64) -> bool {
        !self.ipc.is_nan() && self.ipc >= threshold
    }
}

impl fmt::Display for BlockTiming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:08}] ip=0x{:x} insns={} cycles={} ipc={:.3} cbr={}",
            self.block_index,
            self.start_ip,
            self.insn_count,
            self.cycles,
            self.ipc,
            self.core_bus_ratio,
        )
    }
}

// ── PtTimingAnalyzer ──────────────────────────────────────────────────────────

/// Analyzes Intel PT timing packets to produce per-block IPC and timing data.
#[derive(Debug)]
pub struct PtTimingAnalyzer {
    /// Timing packets recorded from the PT stream.
    pub packets: Vec<TimingPacket>,
    /// Per-block timing results.
    pub block_timings: Vec<BlockTiming>,
    /// TSC frequency in Hz (for wall-clock conversion).
    pub tsc_hz: u64,
    /// Per-IP accumulated cycle counts (for hot-path detection).
    pub ip_cycles: HashMap<u64, u64>,
    /// Smoothed global IPC.
    pub global_ipc: f64,
}

impl PtTimingAnalyzer {
    /// Create a new analyzer with a TSC frequency.
    #[must_use]
    pub fn new(tsc_hz: u64) -> Self {
        Self {
            packets: Vec::new(),
            block_timings: Vec::new(),
            tsc_hz,
            ip_cycles: HashMap::new(),
            global_ipc: 0.0,
        }
    }

    /// Create with a default 3.0 GHz TSC.
    #[must_use]
    pub fn default_3ghz() -> Self {
        Self::new(3_000_000_000)
    }

    /// Feed a timing packet into the analyzer.
    pub fn push_packet(&mut self, pkt: TimingPacket) {
        self.packets.push(pkt);
    }

    /// Compute IPC across all decoded blocks given per-block information.
    ///
    /// `block_data` is a slice of `(block_index, start_ip, insn_count)`.
    /// The analyzer pairs each block with the timing packets whose
    /// `block_index` matches.
    pub fn compute_ipc(&mut self, block_data: &[(u64, u64, u32)]) {
        // Build a map: block_index -> list of TSC values from packets.
        let mut tsc_by_block: HashMap<u64, Vec<CycleCount>> = HashMap::new();
        let mut cbr_by_block: HashMap<u64, u8> = HashMap::new();
        for pkt in &self.packets {
            tsc_by_block
                .entry(pkt.block_index)
                .or_default()
                .push(pkt.tsc);
            if let Some(ratio) = pkt.core_bus_ratio {
                cbr_by_block.insert(pkt.block_index, ratio);
            }
        }

        let mut total_insns = 0u64;
        let mut total_cycles = 0u64;

        for &(idx, ip, insns) in block_data {
            let tscs = tsc_by_block.get(&idx).cloned().unwrap_or_default();
            let tsc_start = tscs.iter().copied().min().unwrap_or(CycleCount(0));
            let tsc_end = tscs.iter().copied().max().unwrap_or(CycleCount(0));
            let cbr = cbr_by_block.get(&idx).copied().unwrap_or(0);

            let bt = BlockTiming::new(idx, ip, insns, tsc_start, tsc_end, cbr);
            *self.ip_cycles.entry(ip).or_insert(0) += bt.cycles;
            total_insns += u64::from(insns);
            total_cycles += bt.cycles;
            self.block_timings.push(bt);
        }

        self.global_ipc = if total_cycles == 0 {
            0.0
        } else {
            crate::cast_helpers::u64_to_f64(total_insns) / crate::cast_helpers::u64_to_f64(total_cycles)
        };
    }

    /// Return the slowest N blocks (highest cycle count).
    #[must_use]
    pub fn slowest_blocks(&self, n: usize) -> Vec<&BlockTiming> {
        let mut sorted: Vec<&BlockTiming> = self.block_timings.iter().collect();
        sorted.sort_by(|a, b| b.cycles.cmp(&a.cycles));
        sorted.into_iter().take(n).collect()
    }

    /// Return the highest-IPC (hottest) N blocks.
    #[must_use]
    pub fn hottest_blocks(&self, n: usize) -> Vec<&BlockTiming> {
        let mut sorted: Vec<&BlockTiming> = self
            .block_timings
            .iter()
            .filter(|b| !b.ipc.is_nan())
            .collect();
        sorted.sort_by(|a, b| b.ipc.partial_cmp(&a.ipc).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(n).collect()
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        let total_cycles: u64 = self.block_timings.iter().map(|b| b.cycles).sum();
        let total_insns: u64 = self.block_timings.iter().map(|b| u64::from(b.insn_count)).sum();
        format!(
            "blocks={} packets={} total_insns={} total_cycles={} global_ipc={:.3} tsc_hz={}",
            self.block_timings.len(),
            self.packets.len(),
            total_insns,
            total_cycles,
            self.global_ipc,
            self.tsc_hz,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_analyzer_with_data() -> PtTimingAnalyzer {
        let mut a = PtTimingAnalyzer::new(3_000_000_000);
        // block 0: 10 insns, tsc 100..200 => 100 cycles, IPC=0.1
        a.push_packet(TimingPacket::cyc(100, CycleCount::new(100), 0));
        a.push_packet(TimingPacket::cyc(100, CycleCount::new(200), 0));
        // block 1: 200 insns, tsc 200..300 => 100 cycles, IPC=2.0
        a.push_packet(TimingPacket::cyc(100, CycleCount::new(200), 1));
        a.push_packet(TimingPacket::cyc(100, CycleCount::new(300), 1));
        a.compute_ipc(&[
            (0, 0x1000, 10),
            (1, 0x2000, 200),
        ]);
        a
    }

    #[test]
    fn test_cycle_count_delta() {
        let a = CycleCount::new(100);
        let b = CycleCount::new(250);
        assert_eq!(a.delta(b), 150);
    }

    #[test]
    fn test_cycle_count_add() {
        let a = CycleCount::new(100);
        let b = CycleCount::new(50);
        assert_eq!((a + b).0, 150);
    }

    #[test]
    fn test_cycle_count_sub() {
        let a = CycleCount::new(300);
        let b = CycleCount::new(100);
        assert_eq!(a - b, 200);
    }

    #[test]
    fn test_timing_packet_cyc() {
        let p = TimingPacket::cyc(50, CycleCount::new(1000), 3);
        assert_eq!(p.kind, TimingPacketKind::Cyc);
        assert_eq!(p.tsc.0, 1000);
        assert_eq!(p.block_index, 3);
    }

    #[test]
    fn test_timing_packet_tsc() {
        let p = TimingPacket::tsc(0xDEAD, 5);
        assert_eq!(p.kind, TimingPacketKind::Tsc);
        assert_eq!(p.raw_value, 0xDEAD);
    }

    #[test]
    fn test_timing_packet_cbr() {
        let p = TimingPacket::cbr(42, CycleCount::new(200), 2);
        assert_eq!(p.core_bus_ratio, Some(42));
    }

    #[test]
    fn test_timing_packet_display() {
        let p = TimingPacket::cyc(10, CycleCount::new(100), 7);
        let s = p.to_string();
        assert!(s.contains("CYC"));
        assert!(s.contains("block=00000007"));
    }

    #[test]
    fn test_block_timing_new() {
        let bt = BlockTiming::new(0, 0x1000, 10, CycleCount::new(100), CycleCount::new(200), 0);
        assert_eq!(bt.cycles, 100);
        assert!((bt.ipc - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_block_timing_zero_cycles() {
        let bt = BlockTiming::new(0, 0x1000, 10, CycleCount::new(0), CycleCount::new(0), 0);
        assert!(bt.ipc.is_nan());
    }

    #[test]
    fn test_block_timing_duration_ns() {
        let bt = BlockTiming::new(0, 0x1000, 5, CycleCount::new(0), CycleCount::new(3_000_000_000), 0);
        let ns = bt.duration_ns(3_000_000_000);
        assert!((ns - 1e9).abs() < 1.0);
    }

    #[test]
    fn test_block_timing_is_hot() {
        let bt = BlockTiming::new(0, 0x1000, 100, CycleCount::new(0), CycleCount::new(50), 0);
        assert!(bt.is_hot(1.0));
        assert!(!bt.is_hot(10.0));
    }

    #[test]
    fn test_block_timing_display() {
        let bt = BlockTiming::new(1, 0x2000, 4, CycleCount::new(0), CycleCount::new(4), 10);
        let s = bt.to_string();
        assert!(s.contains("0x2000"));
        assert!(s.contains("cbr=10"));
    }

    #[test]
    fn test_compute_ipc_basic() {
        let a = make_analyzer_with_data();
        assert_eq!(a.block_timings.len(), 2);
        assert!((a.block_timings[0].ipc - 0.1).abs() < 1e-9);
        assert!((a.block_timings[1].ipc - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_global_ipc() {
        let a = make_analyzer_with_data();
        // 210 insns / 200 cycles = 1.05
        assert!((a.global_ipc - 1.05).abs() < 1e-9);
    }

    #[test]
    fn test_slowest_blocks() {
        let a = make_analyzer_with_data();
        let slow = a.slowest_blocks(1);
        assert_eq!(slow.len(), 1);
        // Both blocks have 100 cycles; first in sort order wins
        assert_eq!(slow[0].cycles, 100);
    }

    #[test]
    fn test_hottest_blocks() {
        let a = make_analyzer_with_data();
        let hot = a.hottest_blocks(1);
        assert_eq!(hot.len(), 1);
        // block 1 has ipc=2.0
        assert!((hot[0].ipc - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_ip_cycles_accumulated() {
        let a = make_analyzer_with_data();
        assert_eq!(a.ip_cycles[&0x1000], 100);
        assert_eq!(a.ip_cycles[&0x2000], 100);
    }

    #[test]
    fn test_summary_contains_fields() {
        let a = make_analyzer_with_data();
        let s = a.summary();
        assert!(s.contains("blocks=2"));
        assert!(s.contains("packets=4"));
        assert!(s.contains("global_ipc="));
    }

    #[test]
    fn test_empty_compute_ipc() {
        let mut a = PtTimingAnalyzer::new(3_000_000_000);
        a.compute_ipc(&[]);
        assert_eq!(a.global_ipc, 0.0);
    }

    #[test]
    fn test_default_3ghz() {
        let a = PtTimingAnalyzer::default_3ghz();
        assert_eq!(a.tsc_hz, 3_000_000_000);
    }

    #[test]
    fn test_cycle_count_ord() {
        let a = CycleCount::new(50);
        let b = CycleCount::new(100);
        assert!(a < b);
    }

    #[test]
    fn test_timing_packet_kind_display() {
        assert_eq!(TimingPacketKind::Cyc.to_string(), "CYC");
        assert_eq!(TimingPacketKind::Tsc.to_string(), "TSC");
        assert_eq!(TimingPacketKind::Cbr.to_string(), "CBR");
    }
}
