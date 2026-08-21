//! `pt_timing` — Timing analysis for Intel PT traces.
//!
//! Reconstructs a continuous wall-clock timeline from the interleaved
//! TSC / MTC / CYC / CBR packet stream, provides per-instruction timing
//! estimates, hotpath identification, and call duration profiling.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{PtPacket, PtPacketKind};

// ─── CpuTopology ──────────────────────────────────────────────────────────────

/// CPU topology parameters needed for timing reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTopology {
    /// TSC frequency in MHz.
    pub tsc_mhz: f64,
    /// Bus frequency in MHz (usually 100 MHz on modern Intel).
    pub bus_mhz: f64,
    /// MTC frequency select (0-15; ART = bus / `2^mtc_freq`).
    pub mtc_freq: u8,
    /// Maximum CYC threshold exponent.
    pub cyc_threshold: u8,
    /// Core multiplier at start.
    pub cbr: u8,
}

impl Default for CpuTopology {
    fn default() -> Self {
        Self {
            tsc_mhz: 3000.0,
            bus_mhz: 100.0,
            mtc_freq: 3,
            cyc_threshold: 1,
            cbr: 30,
        }
    }
}

impl CpuTopology {
    /// Create a topology for a 3 GHz Intel Core with defaults.
    #[must_use]
    pub fn intel_3ghz() -> Self {
        Self::default()
    }

    /// Return the ART frequency in MHz.
    #[must_use]
    pub fn art_mhz(&self) -> f64 {
        self.bus_mhz / f64::from(1u32 << self.mtc_freq)
    }

    /// Return the ART period in nanoseconds.
    #[must_use]
    pub fn art_period_ns(&self) -> f64 {
        1000.0 / self.art_mhz()
    }

    /// Convert TSC ticks to nanoseconds.
    #[must_use]
    pub fn tsc_to_ns(&self, ticks: u64) -> f64 {
        crate::cast_helpers::u64_to_f64(ticks) / self.tsc_mhz * 1000.0
    }

    /// Convert nanoseconds to TSC ticks.
    #[must_use]
    pub fn ns_to_tsc(&self, ns: f64) -> u64 {
        crate::cast_helpers::f64_to_u64(ns * self.tsc_mhz / 1000.0)
    }

    /// Convert CYC delta to nanoseconds.
    ///
    /// CYC counts CPU core cycles.  With CBR = `core_freq` / `bus_freq`, the
    /// core frequency is `cbr * bus_mhz` and the CYC period is
    /// `1 / (cbr * bus_mhz)` microseconds.
    #[must_use]
    pub fn cyc_to_ns(&self, cyc: u64, cbr: u8) -> f64 {
        let core_mhz = f64::from(cbr) * self.bus_mhz;
        crate::cast_helpers::u64_to_f64(cyc) / core_mhz * 1000.0
    }
}

// ─── TimingPoint ──────────────────────────────────────────────────────────────

/// A single timing observation derived from PT packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPoint {
    /// Byte offset in the packet stream.
    pub offset: usize,
    /// TSC value (absolute, or interpolated).
    pub tsc: u64,
    /// Estimated wall-clock nanoseconds since the first TSC anchor.
    pub ns_since_start: f64,
    /// Whether this is an exact TSC (vs interpolated from CYC/MTC).
    pub is_exact: bool,
    /// Source of this timing point.
    pub source: TimingSource,
}

/// The packet type that produced a timing point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingSource {
    /// Direct TSC packet.
    Tsc,
    /// Interpolated from MTC.
    Mtc,
    /// Interpolated from CYC.
    Cyc,
    /// Anchor from the PSB header.
    Psb,
}

// ─── InstructionTiming ────────────────────────────────────────────────────────

/// Per-instruction timing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionTiming {
    /// Instruction address.
    pub address: u64,
    /// Estimated TSC at execution.
    pub tsc: u64,
    /// Estimated cycles from the previous instruction.
    pub cycles_from_prev: u64,
    /// Estimated nanoseconds from the previous instruction.
    pub ns_from_prev: f64,
    /// Cumulative nanoseconds from trace start.
    pub ns_cumulative: f64,
}

// ─── HotpathEntry ─────────────────────────────────────────────────────────────

/// An entry in a hot-path analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotpathEntry {
    /// Start address of the path.
    pub start: u64,
    /// End address of the path.
    pub end: u64,
    /// Total cycles spent in this path.
    pub total_cycles: u64,
    /// Number of times this path was executed.
    pub exec_count: u64,
    /// Average cycles per execution.
    pub avg_cycles: f64,
}

impl HotpathEntry {
    /// Compute the average cycles per execution.
    pub fn compute_avg(&mut self) {
        if self.exec_count > 0 {
            self.avg_cycles = crate::cast_helpers::u64_to_f64(self.total_cycles) / crate::cast_helpers::u64_to_f64(self.exec_count);
        }
    }
}

// ─── CallDuration ─────────────────────────────────────────────────────────────

/// Timing for a single call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallDuration {
    /// Call site address.
    pub call_site: u64,
    /// Callee address.
    pub callee: u64,
    /// TSC at call entry.
    pub entry_tsc: u64,
    /// TSC at return (0 if not yet returned).
    pub exit_tsc: u64,
    /// Whether the call has returned.
    pub returned: bool,
}

impl CallDuration {
    /// Create a new call duration record.
    #[must_use]
    pub const fn new(call_site: u64, callee: u64, entry_tsc: u64) -> Self {
        Self {
            call_site,
            callee,
            entry_tsc,
            exit_tsc: 0,
            returned: false,
        }
    }

    /// Mark as returned.
    pub const fn mark_returned(&mut self, exit_tsc: u64) {
        self.exit_tsc = exit_tsc;
        self.returned = true;
    }

    /// Return elapsed TSC ticks.
    #[must_use]
    pub const fn elapsed_tsc(&self) -> u64 {
        if self.returned {
            self.exit_tsc.saturating_sub(self.entry_tsc)
        } else {
            0
        }
    }

    /// Return elapsed nanoseconds.
    #[must_use]
    pub fn elapsed_ns(&self, tsc_mhz: f64) -> f64 {
        crate::cast_helpers::u64_to_f64(self.elapsed_tsc()) / tsc_mhz * 1000.0
    }
}

// ─── TimingAnalyzer ───────────────────────────────────────────────────────────

/// Full timing analysis engine for an Intel PT packet stream.
///
/// Algorithm overview:
/// 1. Walk the packet stream, recording TSC anchors.
/// 2. Between anchors, accumulate CYC deltas to interpolate sub-TSC timing.
/// 3. MTC packets provide an alternative interpolation when CYC is not enabled.
/// 4. Emit `TimingPoint` for every timing-relevant packet.
/// 5. Build a per-address execution frequency map.
/// 6. Identify hot paths (tight loops with high cycle counts).
/// 7. Profile call durations using a TSC-annotated call stack.
pub struct TimingAnalyzer {
    /// CPU topology.
    pub topology: CpuTopology,
    /// Reconstructed timing points.
    pub points: Vec<TimingPoint>,
    /// Per-address cycle accumulator (for hotpath identification).
    addr_cycles: HashMap<u64, u64>,
    /// Per-address execution count.
    addr_count: HashMap<u64, u64>,
    /// Call duration stack.
    call_stack: Vec<CallDuration>,
    /// Completed call durations.
    pub call_durations: Vec<CallDuration>,
    /// Current TSC value.
    current_tsc: u64,
    /// First TSC observed.
    first_tsc: Option<u64>,
    /// Accumulated CYC deltas since last TSC anchor.
    cyc_since_tsc: u64,
    /// Last MTC CTC value.
    last_ctc: Option<u8>,
    /// Last CBR value.
    cbr: u8,
    /// Total tsc elapsed.
    pub total_tsc: u64,
    /// Total CYC packets.
    pub total_cyc_packets: u64,
    /// Total MTC packets.
    pub total_mtc_packets: u64,
    /// Total TSC packets.
    pub total_tsc_packets: u64,
}

impl TimingAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new(topology: CpuTopology) -> Self {
        let cbr = topology.cbr;
        Self {
            topology,
            points: Vec::new(),
            addr_cycles: HashMap::new(),
            addr_count: HashMap::new(),
            call_stack: Vec::new(),
            call_durations: Vec::new(),
            current_tsc: 0,
            first_tsc: None,
            cyc_since_tsc: 0,
            last_ctc: None,
            cbr,
            total_tsc: 0,
            total_cyc_packets: 0,
            total_mtc_packets: 0,
            total_tsc_packets: 0,
        }
    }

    /// Process a single PT packet and update timing state.
    pub fn process_packet(&mut self, pkt: &PtPacket) {
        match &pkt.kind {
            PtPacketKind::Tsc(tsc) => {
                let ns_since = self.ns_since_start(*tsc);
                if self.first_tsc.is_none() {
                    self.first_tsc = Some(*tsc);
                }
                self.current_tsc = *tsc;
                self.cyc_since_tsc = 0;
                self.total_tsc_packets += 1;
                self.total_tsc = self.current_tsc;
                self.points.push(TimingPoint {
                    offset: pkt.offset,
                    tsc: *tsc,
                    ns_since_start: ns_since,
                    is_exact: true,
                    source: TimingSource::Tsc,
                });
            }

            PtPacketKind::Cbr(cbr) => {
                self.cbr = *cbr;
                self.topology.cbr = *cbr;
                // Recompute TSC MHz from CBR
                self.topology.tsc_mhz = f64::from(*cbr) * self.topology.bus_mhz;
            }

            PtPacketKind::Mtc { ctc } => {
                self.total_mtc_packets += 1;
                let tsc_est = self.interpolate_tsc_from_mtc(*ctc);
                let ns_since = self.ns_since_start(tsc_est);
                self.points.push(TimingPoint {
                    offset: pkt.offset,
                    tsc: tsc_est,
                    ns_since_start: ns_since,
                    is_exact: false,
                    source: TimingSource::Mtc,
                });
                self.last_ctc = Some(*ctc);
            }

            PtPacketKind::Cyc { value } => {
                self.total_cyc_packets += 1;
                self.cyc_since_tsc = self.cyc_since_tsc.wrapping_add(*value);
                // Interpolate current TSC from accumulated CYC
                let tsc_est = self.interpolate_tsc_from_cyc();
                let ns_since = self.ns_since_start(tsc_est);
                self.points.push(TimingPoint {
                    offset: pkt.offset,
                    tsc: tsc_est,
                    ns_since_start: ns_since,
                    is_exact: false,
                    source: TimingSource::Cyc,
                });
            }

            _ => {}
        }
    }

    /// Process all packets in a slice.
    pub fn process_packets(&mut self, packets: &[PtPacket]) {
        for pkt in packets {
            self.process_packet(pkt);
        }
    }

    /// Record a call for duration profiling.
    pub fn record_call(&mut self, call_site: u64, callee: u64) {
        self.call_stack
            .push(CallDuration::new(call_site, callee, self.current_tsc));
    }

    /// Record a return for duration profiling.
    pub fn record_return(&mut self) {
        if let Some(mut frame) = self.call_stack.pop() {
            frame.mark_returned(self.current_tsc);
            self.call_durations.push(frame);
        }
    }

    /// Record an instruction at `addr` as executed (for heatmap).
    pub fn record_instruction(&mut self, addr: u64, cycles: u64) {
        *self.addr_cycles.entry(addr).or_insert(0) += cycles;
        *self.addr_count.entry(addr).or_insert(0) += 1;
    }

    /// Return nanoseconds since the first TSC for a given TSC value.
    #[must_use]
    pub fn ns_since_start(&self, tsc: u64) -> f64 {
        self.first_tsc.map_or(0.0, |first| self.topology.tsc_to_ns(tsc.wrapping_sub(first)))
    }

    /// Interpolate current TSC from accumulated CYC deltas.
    #[must_use]
    fn interpolate_tsc_from_cyc(&self) -> u64 {
        // CYC counts core cycles.  TSC = anchor_tsc + cyc / (core_freq / tsc_freq)
        // For most Intel parts, core_freq == tsc_freq, so TSC delta ≈ CYC delta.
        // With turbo boost, core_freq > tsc_freq, so we scale.
        let scale = self.topology.tsc_mhz / (f64::from(self.cbr) * self.topology.bus_mhz);
        let tsc_delta = crate::cast_helpers::f64_to_u64(crate::cast_helpers::u64_to_f64(self.cyc_since_tsc) * scale);
        self.current_tsc.wrapping_add(tsc_delta)
    }

    /// Interpolate current TSC from an MTC CTC value.
    fn interpolate_tsc_from_mtc(&self, ctc: u8) -> u64 {
        let art_period_ns = self.topology.art_period_ns();
        let ctc_delta = self.last_ctc.map_or(0.0, |prev| f64::from(ctc.wrapping_sub(prev)));
        let ns_delta = ctc_delta * art_period_ns;
        let tsc_delta = self.topology.ns_to_tsc(ns_delta);
        self.current_tsc.wrapping_add(tsc_delta)
    }

    /// Return the total elapsed time in nanoseconds.
    #[must_use]
    pub fn total_elapsed_ns(&self) -> f64 {
        match (self.first_tsc, Some(self.current_tsc)) {
            (Some(first), Some(last)) => self.topology.tsc_to_ns(last.wrapping_sub(first)),
            _ => 0.0,
        }
    }

    /// Return the N hottest addresses by cycle count.
    #[must_use]
    pub fn top_n_by_cycles(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .addr_cycles
            .iter()
            .map(|(&a, &c)| (a, c))
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(n);
        v
    }

    /// Return the N hottest addresses by execution count.
    #[must_use]
    pub fn top_n_by_count(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .addr_count
            .iter()
            .map(|(&a, &c)| (a, c))
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(n);
        v
    }

    /// Identify hot paths (sequences of addresses with >N% total cycles).
    #[must_use]
    pub fn hotpaths(&self, threshold_pct: f64) -> Vec<HotpathEntry> {
        let total: u64 = self.addr_cycles.values().sum();
        if total == 0 {
            return Vec::new();
        }
        let threshold = crate::cast_helpers::f64_to_u64(crate::cast_helpers::u64_to_f64(total) * threshold_pct / 100.0);
        self.addr_cycles
            .iter()
            .filter(|&(_, &cycles)| cycles >= threshold)
            .map(|(&addr, &cycles)| {
                let count = self.addr_count.get(&addr).copied().unwrap_or(1);
                let avg = crate::cast_helpers::u64_to_f64(cycles) / crate::cast_helpers::u64_to_f64(count);
                HotpathEntry {
                    start: addr,
                    end: addr,
                    total_cycles: cycles,
                    exec_count: count,
                    avg_cycles: avg,
                }
            })
            .collect()
    }

    /// Return completed call duration statistics for `callee`.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn call_stats_for(&self, callee: u64) -> CallStats {
        let durations: Vec<u64> = self
            .call_durations
            .iter()
            .filter(|c| c.callee == callee && c.returned)
            .map(CallDuration::elapsed_tsc)
            .collect();

        if durations.is_empty() {
            return CallStats::default();
        }

        let count = durations.len() as u64;
        let total: u64 = durations.iter().sum();
        let min = *durations.iter().min().unwrap();
        let max = *durations.iter().max().unwrap();
        let mean = crate::cast_helpers::u64_to_f64(total) / crate::cast_helpers::u64_to_f64(count);
        let variance: f64 = durations
            .iter()
            .map(|&d| {
                let diff = crate::cast_helpers::u64_to_f64(d) - mean;
                diff * diff
            })
            .sum::<f64>()
            / crate::cast_helpers::u64_to_f64(count);
        let stddev = variance.sqrt();

        // Median
        let mut sorted = durations;
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];

        CallStats {
            callee,
            call_count: count,
            total_tsc: total,
            min_tsc: min,
            max_tsc: max,
            mean_tsc: mean,
            stddev_tsc: stddev,
            median_tsc: median,
            total_ns: self.topology.tsc_to_ns(total),
            mean_ns: mean / self.topology.tsc_mhz * 1000.0,
        }
    }

    /// Return all per-callee call statistics.
    #[must_use]
    pub fn all_call_stats(&self) -> Vec<CallStats> {
        let callees: std::collections::HashSet<u64> = self
            .call_durations
            .iter()
            .filter(|c| c.returned)
            .map(|c| c.callee)
            .collect();
        callees.iter().map(|&c| self.call_stats_for(c)).collect()
    }

    /// Return summary statistics.
    #[must_use]
    pub fn summary(&self) -> TimingSummary {
        TimingSummary {
            total_elapsed_ns: self.total_elapsed_ns(),
            tsc_packets: self.total_tsc_packets,
            mtc_packets: self.total_mtc_packets,
            cyc_packets: self.total_cyc_packets,
            timing_points: self.points.len(),
            cbr: self.cbr,
            first_tsc: self.first_tsc,
            last_tsc: if self.current_tsc != 0 { Some(self.current_tsc) } else { None },
        }
    }
}

// ─── CallStats ────────────────────────────────────────────────────────────────

/// Aggregate call duration statistics for a single callee.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallStats {
    /// Callee address.
    pub callee: u64,
    /// Number of calls.
    pub call_count: u64,
    /// Total TSC ticks.
    pub total_tsc: u64,
    /// Minimum TSC ticks.
    pub min_tsc: u64,
    /// Maximum TSC ticks.
    pub max_tsc: u64,
    /// Mean TSC ticks.
    pub mean_tsc: f64,
    /// Standard deviation.
    pub stddev_tsc: f64,
    /// Median TSC ticks.
    pub median_tsc: u64,
    /// Total nanoseconds.
    pub total_ns: f64,
    /// Mean nanoseconds.
    pub mean_ns: f64,
}

impl std::fmt::Display for CallStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallStats {{ callee=0x{:x}, count={}, mean={:.0}ns, min={}tsc, max={}tsc }}",
            self.callee, self.call_count, self.mean_ns, self.min_tsc, self.max_tsc
        )
    }
}

// ─── TimingSummary ────────────────────────────────────────────────────────────

/// High-level summary of timing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSummary {
    /// Total elapsed nanoseconds.
    pub total_elapsed_ns: f64,
    /// Number of TSC packets.
    pub tsc_packets: u64,
    /// Number of MTC packets.
    pub mtc_packets: u64,
    /// Number of CYC packets.
    pub cyc_packets: u64,
    /// Total timing points reconstructed.
    pub timing_points: usize,
    /// Last observed CBR.
    pub cbr: u8,
    /// First TSC observed.
    pub first_tsc: Option<u64>,
    /// Last TSC observed.
    pub last_tsc: Option<u64>,
}

impl std::fmt::Display for TimingSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TimingSummary {{ elapsed={:.0}ns, tsc={}, mtc={}, cyc={}, points={}, cbr={} }}",
            self.total_elapsed_ns,
            self.tsc_packets,
            self.mtc_packets,
            self.cyc_packets,
            self.timing_points,
            self.cbr
        )
    }
}

// ─── TscCalibrator ────────────────────────────────────────────────────────────

/// Calibrates the TSC frequency from CBR packets and known reference clock.
pub struct TscCalibrator {
    /// TSC / reference pairs: (`tsc_delta`, `reference_ns`).
    samples: Vec<(u64, u64)>,
    /// Estimated TSC MHz.
    pub estimated_mhz: f64,
}

impl TscCalibrator {
    /// Create a new calibrator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            samples: Vec::new(),
            estimated_mhz: 0.0,
        }
    }

    /// Add a calibration sample.
    pub fn add_sample(&mut self, tsc_delta: u64, reference_ns: u64) {
        self.samples.push((tsc_delta, reference_ns));
        self.recompute();
    }

    /// Recompute the estimated MHz from all samples.
    fn recompute(&mut self) {
        if self.samples.is_empty() {
            return;
        }
        let total_tsc: u64 = self.samples.iter().map(|(t, _)| t).sum();
        let total_ns: u64 = self.samples.iter().map(|(_, n)| n).sum();
        if total_ns > 0 {
            // MHz = ticks / ns * 1000 (since 1 MHz = 1e6 ticks / 1e6 ns * 1e6)
            self.estimated_mhz = crate::cast_helpers::u64_to_f64(total_tsc) / crate::cast_helpers::u64_to_f64(total_ns) * 1000.0;
        }
    }

    /// Add a CBR-derived estimate.
    pub fn add_cbr_estimate(&mut self, cbr: u8, bus_mhz: f64) {
        self.estimated_mhz = f64::from(cbr) * bus_mhz;
    }

    /// Return the estimated MHz.
    #[must_use]
    pub const fn mhz(&self) -> f64 {
        self.estimated_mhz
    }

    /// Return the number of calibration samples.
    #[must_use]
    pub const fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

impl Default for TscCalibrator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── IntervalTimer ────────────────────────────────────────────────────────────

/// Tracks time intervals between recurring events (e.g., loop iterations).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntervalTimer {
    /// List of observed TSC values at each event.
    pub events: Vec<u64>,
}

impl IntervalTimer {
    /// Create a new interval timer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event at `tsc`.
    pub fn record(&mut self, tsc: u64) {
        self.events.push(tsc);
    }

    /// Return the intervals (TSC deltas) between events.
    #[must_use]
    pub fn intervals(&self) -> Vec<u64> {
        self.events.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect()
    }

    /// Return mean interval in TSC ticks.
    #[must_use]
    pub fn mean_interval(&self) -> Option<f64> {
        let iv = self.intervals();
        if iv.is_empty() {
            return None;
        }
        let sum: u64 = iv.iter().sum();
        Some(crate::cast_helpers::u64_to_f64(sum) / crate::cast_helpers::usize_to_f64(iv.len()))
    }

    /// Return the jitter (stddev of intervals).
    #[must_use]
    pub fn jitter(&self) -> Option<f64> {
        let mean = self.mean_interval()?;
        let iv = self.intervals();
        if iv.is_empty() {
            return None;
        }
        let var: f64 = iv
            .iter()
            .map(|&x| {
                let d = crate::cast_helpers::u64_to_f64(x) - mean;
                d * d
            })
            .sum::<f64>()
            / crate::cast_helpers::usize_to_f64(iv.len());
        Some(var.sqrt())
    }

    /// Return minimum interval.
    #[must_use]
    pub fn min_interval(&self) -> Option<u64> {
        self.intervals().into_iter().min()
    }

    /// Return maximum interval.
    #[must_use]
    pub fn max_interval(&self) -> Option<u64> {
        self.intervals().into_iter().max()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tsc_pkt(tsc: u64, offset: usize) -> PtPacket {
        PtPacket::new(PtPacketKind::Tsc(tsc), offset, 9)
    }

    fn make_cbr_pkt(cbr: u8, offset: usize) -> PtPacket {
        PtPacket::new(PtPacketKind::Cbr(cbr), offset, 4)
    }

    fn make_mtc_pkt(ctc: u8, offset: usize) -> PtPacket {
        PtPacket::new(PtPacketKind::Mtc { ctc }, offset, 2)
    }

    fn make_cyc_pkt(value: u64, offset: usize) -> PtPacket {
        PtPacket::new(PtPacketKind::Cyc { value }, offset, 2)
    }

    #[test]
    fn test_cpu_topology_tsc_to_ns() {
        let t = CpuTopology::intel_3ghz();
        // 3_000 ticks at 3000 MHz = 1 µs = 1000 ns
        let ns = t.tsc_to_ns(3000);
        assert!((ns - 1000.0).abs() < 0.001, "got {ns}");
    }

    #[test]
    fn test_cpu_topology_art_period() {
        let t = CpuTopology { mtc_freq: 3, bus_mhz: 100.0, ..Default::default() };
        // ART = 100 / 8 = 12.5 MHz => period = 80 ns
        assert!((t.art_period_ns() - 80.0).abs() < 0.001);
    }

    #[test]
    fn test_cpu_topology_cyc_to_ns() {
        let t = CpuTopology { tsc_mhz: 3000.0, bus_mhz: 100.0, cbr: 30, ..Default::default() };
        // core_mhz = 30 * 100 = 3000, 3000 cyc = 1 µs = 1000 ns
        let ns = t.cyc_to_ns(3000, 30);
        assert!((ns - 1000.0).abs() < 0.001, "got {ns}");
    }

    #[test]
    fn test_timing_analyzer_tsc_processing() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_tsc_pkt(0, 0));
        ta.process_packet(&make_tsc_pkt(3_000_000, 9));
        assert_eq!(ta.total_tsc_packets, 2);
        let elapsed = ta.total_elapsed_ns();
        assert!((elapsed - 1_000_000.0).abs() < 1.0, "got {elapsed}");
    }

    #[test]
    fn test_timing_analyzer_cbr_updates_mhz() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_cbr_pkt(40, 0)); // 40 * 100 = 4000 MHz
        assert!((ta.topology.tsc_mhz - 4000.0).abs() < 0.001);
    }

    #[test]
    fn test_timing_analyzer_mtc_creates_point() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_tsc_pkt(1000, 0));
        ta.process_packet(&make_mtc_pkt(5, 9));
        assert_eq!(ta.total_mtc_packets, 1);
        assert!(ta.points.iter().any(|p| p.source == TimingSource::Mtc));
    }

    #[test]
    fn test_timing_analyzer_cyc_creates_point() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_tsc_pkt(1000, 0));
        ta.process_packet(&make_cyc_pkt(100, 9));
        assert_eq!(ta.total_cyc_packets, 1);
        assert!(ta.points.iter().any(|p| p.source == TimingSource::Cyc));
    }

    #[test]
    fn test_call_duration_elapsed() {
        let mut cd = CallDuration::new(0x1000, 0x2000, 1000);
        cd.mark_returned(4000);
        assert_eq!(cd.elapsed_tsc(), 3000);
        let ns = cd.elapsed_ns(3000.0); // 3000 ticks / 3000 MHz * 1000 = 1000 ns
        assert!((ns - 1000.0).abs() < 0.001, "got {ns}");
    }

    #[test]
    fn test_record_call_and_return() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_tsc_pkt(1000, 0));
        ta.record_call(0x100, 0x200);
        ta.process_packet(&make_tsc_pkt(4000, 9));
        ta.record_return();
        assert_eq!(ta.call_durations.len(), 1);
        let stats = ta.call_stats_for(0x200);
        assert_eq!(stats.call_count, 1);
        assert_eq!(stats.min_tsc, stats.max_tsc); // only one call
    }

    #[test]
    fn test_hotpath_identification() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.record_instruction(0x1000, 1000);
        ta.record_instruction(0x1000, 1000);
        ta.record_instruction(0x2000, 10);
        let hot = ta.hotpaths(50.0); // 50% threshold
        assert!(hot.iter().any(|h| h.start == 0x1000));
    }

    #[test]
    fn test_top_n_by_cycles() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.record_instruction(0xA000, 500);
        ta.record_instruction(0xB000, 300);
        ta.record_instruction(0xC000, 700);
        let top = ta.top_n_by_cycles(2);
        assert_eq!(top[0].0, 0xC000);
        assert_eq!(top[1].0, 0xA000);
    }

    #[test]
    fn test_timing_summary() {
        let mut ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        ta.process_packet(&make_tsc_pkt(0, 0));
        ta.process_packet(&make_tsc_pkt(3_000_000, 9));
        ta.process_packet(&make_cbr_pkt(30, 18));
        let s = ta.summary();
        assert_eq!(s.tsc_packets, 2);
        assert_eq!(s.cbr, 30);
        let _disp = s.to_string();
    }

    #[test]
    fn test_tsc_calibrator_cbr() {
        let mut c = TscCalibrator::new();
        c.add_cbr_estimate(30, 100.0);
        assert!((c.mhz() - 3000.0).abs() < 0.001);
    }

    #[test]
    fn test_tsc_calibrator_samples() {
        let mut c = TscCalibrator::new();
        c.add_sample(3_000_000, 1_000_000); // 3M ticks in 1M ns = 3000 MHz
        assert!((c.mhz() - 3000.0).abs() < 0.001, "got {}", c.mhz());
    }

    #[test]
    fn test_interval_timer() {
        let mut it = IntervalTimer::new();
        it.record(0);
        it.record(100);
        it.record(200);
        it.record(310);
        let iv = it.intervals();
        assert_eq!(iv, vec![100, 100, 110]);
        let mean = it.mean_interval().unwrap();
        assert!((mean - 310.0 / 3.0).abs() < 0.001, "got {mean}");
        assert!(it.jitter().is_some());
        assert_eq!(it.min_interval(), Some(100));
        assert_eq!(it.max_interval(), Some(110));
    }

    #[test]
    fn test_interval_timer_empty() {
        let it = IntervalTimer::new();
        assert!(it.mean_interval().is_none());
        assert!(it.jitter().is_none());
    }

    #[test]
    fn test_call_stats_display() {
        let cs = CallStats {
            callee: 0x1234,
            call_count: 5,
            mean_ns: 250.0,
            min_tsc: 100,
            max_tsc: 500,
            ..Default::default()
        };
        let s = cs.to_string();
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn test_ns_since_start_without_anchor() {
        let ta = TimingAnalyzer::new(CpuTopology::intel_3ghz());
        assert_eq!(ta.ns_since_start(1000), 0.0);
    }
}
