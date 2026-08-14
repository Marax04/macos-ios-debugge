//! `pt_filter` — Trace stream filtering for Intel PT.
//!
//! Provides composable, chainable filters for IP range, ring level, process,
//! time window, and instruction type.  Filters can be stacked and applied to
//! both raw packet streams and reconstructed flow event streams.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{PtPacket, PtPacketKind};

// ─── IpRange ──────────────────────────────────────────────────────────────────

/// A contiguous IP (instruction pointer) address range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRange {
    /// Start of the range (inclusive).
    pub start: u64,
    /// End of the range (exclusive).
    pub end: u64,
    /// Optional label for this range.
    pub label: Option<String>,
}

impl IpRange {
    /// Create a new range.
    ///
    /// # Panics
    /// May panic on invalid input.
    #[must_use]
    pub fn new(start: u64, end: u64) -> Self {
        assert!(end > start, "IpRange: end must be > start");
        Self { start, end, label: None }
    }

    /// Create a labelled range.
    #[must_use]
    pub fn labelled(start: u64, end: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: Some(label.into()),
        }
    }

    /// Return `true` if `addr` falls within this range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Return `true` if this range overlaps with `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Return the size of the range in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(label) = &self.label {
            write!(f, "{}[0x{:x}..0x{:x}]", label, self.start, self.end)
        } else {
            write!(f, "[0x{:x}..0x{:x}]", self.start, self.end)
        }
    }
}

// ─── RingFilter ───────────────────────────────────────────────────────────────

/// Filter by ring (privilege) level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingFilter {
    /// Accept all ring levels.
    All,
    /// Only accept ring-0 (kernel) traffic.
    KernelOnly,
    /// Only accept ring-3 (user) traffic.
    UserOnly,
    /// Only accept specific CPL bits.
    Cpl(u8),
}

impl RingFilter {
    /// Return `true` if the given CPL passes this filter.
    #[must_use]
    pub const fn passes(&self, cpl: u8) -> bool {
        match self {
            Self::All => true,
            Self::KernelOnly => cpl == 0,
            Self::UserOnly => cpl == 3,
            Self::Cpl(required) => cpl == *required,
        }
    }
}

// ─── TimeWindow ───────────────────────────────────────────────────────────────

/// A time window filter defined by TSC values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start of the window (inclusive, TSC ticks).
    pub start_tsc: u64,
    /// End of the window (exclusive, TSC ticks).
    pub end_tsc: u64,
}

impl TimeWindow {
    /// Create a time window.
    #[must_use]
    pub const fn new(start_tsc: u64, end_tsc: u64) -> Self {
        Self { start_tsc, end_tsc }
    }

    /// Return `true` if `tsc` falls within this window.
    #[must_use]
    pub const fn contains(&self, tsc: u64) -> bool {
        tsc >= self.start_tsc && tsc < self.end_tsc
    }

    /// Return the window duration in TSC ticks.
    #[must_use]
    pub const fn duration(&self) -> u64 {
        self.end_tsc.saturating_sub(self.start_tsc)
    }

    /// Return the window duration in nanoseconds at `tsc_mhz`.
    #[must_use]
    pub fn duration_ns(&self, tsc_mhz: f64) -> f64 {
        crate::cast_helpers::u64_to_f64(self.duration()) / tsc_mhz * 1000.0
    }
}

// ─── PacketTypeFilter ─────────────────────────────────────────────────────────

/// Filter by Intel PT packet type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketTypeFilter {
    /// Accept TNT/TntLong packets.
    pub accept_tnt: bool,
    /// Accept TIP/TIP.PGE/TIP.PGD packets.
    pub accept_tip: bool,
    /// Accept TSC packets.
    pub accept_tsc: bool,
    /// Accept MTC packets.
    pub accept_mtc: bool,
    /// Accept CYC packets.
    pub accept_cyc: bool,
    /// Accept CBR packets.
    pub accept_cbr: bool,
    /// Accept MODE packets.
    pub accept_mode: bool,
    /// Accept PIP packets.
    pub accept_pip: bool,
    /// Accept VMCS packets.
    pub accept_vmcs: bool,
    /// Accept EXSTOP/MWAIT/PWRE/PWRX packets.
    pub accept_power: bool,
    /// Accept PSB/PSBEND packets.
    pub accept_psb: bool,
    /// Accept OVF packets.
    pub accept_ovf: bool,
    /// Accept PAD packets.
    pub accept_pad: bool,
    /// Accept BBP/BIP/BEP packets.
    pub accept_bbp: bool,
}

impl PacketTypeFilter {
    /// Create a filter that accepts all packet types.
    #[must_use]
    pub const fn accept_all() -> Self {
        Self {
            accept_tnt: true,
            accept_tip: true,
            accept_tsc: true,
            accept_mtc: true,
            accept_cyc: true,
            accept_cbr: true,
            accept_mode: true,
            accept_pip: true,
            accept_vmcs: true,
            accept_power: true,
            accept_psb: true,
            accept_ovf: true,
            accept_pad: true,
            accept_bbp: true,
        }
    }

    /// Create a filter that accepts only flow-relevant packets.
    #[must_use]
    pub const fn flow_only() -> Self {
        Self {
            accept_tnt: true,
            accept_tip: true,
            accept_tsc: true,
            accept_ovf: true,
            accept_mode: true,
            accept_psb: true,
            accept_pad: false,
            accept_cyc: false,
            accept_mtc: false,
            accept_cbr: false,
            accept_pip: false,
            accept_vmcs: false,
            accept_power: false,
            accept_bbp: false,
        }
    }

    /// Create a filter that accepts only timing packets.
    #[must_use]
    pub const fn timing_only() -> Self {
        Self {
            accept_tsc: true,
            accept_mtc: true,
            accept_cyc: true,
            accept_cbr: true,
            accept_tnt: false,
            accept_tip: false,
            accept_mode: false,
            accept_pip: false,
            accept_vmcs: false,
            accept_power: false,
            accept_psb: false,
            accept_ovf: false,
            accept_pad: false,
            accept_bbp: false,
        }
    }

    /// Return `true` if `pkt` passes this filter.
    #[must_use]
    pub const fn passes(&self, pkt: &PtPacket) -> bool {
        match &pkt.kind {
            PtPacketKind::Tnt { .. } | PtPacketKind::TntLong { .. } => self.accept_tnt,
            PtPacketKind::Tip { .. }
            | PtPacketKind::TipPge { .. }
            | PtPacketKind::TipPgd { .. } => self.accept_tip,
            PtPacketKind::Tsc(_) => self.accept_tsc,
            PtPacketKind::Mtc { .. } => self.accept_mtc,
            PtPacketKind::Cyc { .. } => self.accept_cyc,
            PtPacketKind::Cbr(_) => self.accept_cbr,
            PtPacketKind::Mode { .. } => self.accept_mode,
            PtPacketKind::Pip { .. } => self.accept_pip,
            PtPacketKind::Vmcs { .. } => self.accept_vmcs,
            PtPacketKind::ExStop { .. }
            | PtPacketKind::Mwait { .. }
            | PtPacketKind::Pwre { .. }
            | PtPacketKind::Pwrx { .. } => self.accept_power,
            PtPacketKind::Psb | PtPacketKind::PsbEnd => self.accept_psb,
            PtPacketKind::Overflow => self.accept_ovf,
            PtPacketKind::Pad => self.accept_pad,
            PtPacketKind::Bbp { .. } | PtPacketKind::Bip { .. } | PtPacketKind::Bep { .. } => {
                self.accept_bbp
            }
        }
    }
}

// ─── FilterCriteria ───────────────────────────────────────────────────────────

/// Composable filter criteria for Intel PT trace streams.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterCriteria {
    /// Optional IP ranges (empty = accept all IPs).
    pub ip_ranges: Vec<IpRange>,
    /// Ring level filter.
    pub ring: Option<RingFilter>,
    /// Optional set of allowed PIDs (empty = accept all).
    pub allowed_pids: HashSet<u32>,
    /// Optional time window filter.
    pub time_window: Option<TimeWindow>,
    /// Packet type filter.
    pub packet_types: Option<PacketTypeFilter>,
    /// Whether to invert the IP range filter.
    pub invert_ip: bool,
    /// Whether to invert the PID filter.
    pub invert_pid: bool,
}

impl FilterCriteria {
    /// Create a pass-all filter.
    #[must_use]
    pub fn pass_all() -> Self {
        Self::default()
    }

    /// Restrict to a single IP range.
    #[must_use]
    pub fn ip_range(range: IpRange) -> Self {
        Self {
            ip_ranges: vec![range],
            ..Self::default()
        }
    }

    /// Restrict to a set of PIDs.
    #[must_use]
    pub fn pids(pids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_pids: pids.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Add an IP range.
    pub fn add_ip_range(&mut self, range: IpRange) -> &mut Self {
        self.ip_ranges.push(range);
        self
    }

    /// Add a PID.
    pub fn add_pid(&mut self, pid: u32) -> &mut Self {
        self.allowed_pids.insert(pid);
        self
    }

    /// Set ring filter.
    pub const fn set_ring(&mut self, ring: RingFilter) -> &mut Self {
        self.ring = Some(ring);
        self
    }

    /// Set time window.
    pub const fn set_time_window(&mut self, window: TimeWindow) -> &mut Self {
        self.time_window = Some(window);
        self
    }

    /// Test whether an IP address passes the IP range filter.
    #[must_use]
    pub fn ip_passes(&self, ip: u64) -> bool {
        if self.ip_ranges.is_empty() {
            return !self.invert_ip;
        }
        let in_range = self.ip_ranges.iter().any(|r| r.contains(ip));
        if self.invert_ip { !in_range } else { in_range }
    }

    /// Test whether a PID passes the PID filter.
    #[must_use]
    pub fn pid_passes(&self, pid: u32) -> bool {
        if self.allowed_pids.is_empty() {
            return !self.invert_pid;
        }
        let allowed = self.allowed_pids.contains(&pid);
        if self.invert_pid { !allowed } else { allowed }
    }

    /// Test whether a TSC passes the time window filter.
    #[must_use]
    pub fn tsc_passes(&self, tsc: u64) -> bool {
        self.time_window.as_ref().is_none_or(|w| w.contains(tsc))
    }

    /// Test whether a ring level passes the ring filter.
    #[must_use]
    pub fn ring_passes(&self, cpl: u8) -> bool {
        self.ring.as_ref().is_none_or(|r| r.passes(cpl))
    }

    /// Test whether a packet passes the type filter.
    #[must_use]
    pub fn packet_type_passes(&self, pkt: &PtPacket) -> bool {
        self.packet_types.as_ref().is_none_or(|f| f.passes(pkt))
    }
}

// ─── PacketFilter ─────────────────────────────────────────────────────────────

/// Applies `FilterCriteria` to a raw PT packet stream.
///
/// Maintains a running TSC so the time-window filter can be applied even to
/// non-TSC packets.
pub struct PacketFilter {
    /// Filter criteria.
    pub criteria: FilterCriteria,
    /// Current TSC (updated from TSC packets).
    current_tsc: u64,
    /// Current PID (from sideband correlation).
    pub current_pid: u32,
    /// Current ring level.
    pub current_cpl: u8,
    /// Number of packets accepted.
    pub accepted: u64,
    /// Number of packets rejected.
    pub rejected: u64,
    /// Number of packets total.
    pub total: u64,
}

impl PacketFilter {
    /// Create a new filter with the given criteria.
    #[must_use]
    pub const fn new(criteria: FilterCriteria) -> Self {
        Self {
            criteria,
            current_tsc: 0,
            current_pid: 0,
            current_cpl: 3, // user mode by default
            accepted: 0,
            rejected: 0,
            total: 0,
        }
    }

    /// Update internal state from a packet (TSC, MODE, etc.).
    pub fn update_state(&mut self, pkt: &PtPacket) {
        match &pkt.kind {
            PtPacketKind::Tsc(tsc) => self.current_tsc = *tsc,
            PtPacketKind::Mode { leaf: 0x43, bits } => {
                // Decode CPL from MODE.Exec
                self.current_cpl = (bits >> 2) & 0x03;
            }
            _ => {}
        }
    }

    /// Return `true` if `pkt` should be included in the filtered output.
    pub fn passes(&mut self, pkt: &PtPacket) -> bool {
        self.update_state(pkt);
        self.total += 1;

        // IP range check
        if let Some(ip) = pkt.kind.ip_addr()
            && !self.criteria.ip_passes(ip)
        {
            self.rejected += 1;
            return false;
        }

        // Timing window check
        if !self.criteria.tsc_passes(self.current_tsc) {
            self.rejected += 1;
            return false;
        }

        // Ring filter
        if !self.criteria.ring_passes(self.current_cpl) {
            self.rejected += 1;
            return false;
        }

        // PID filter
        if !self.criteria.pid_passes(self.current_pid) {
            self.rejected += 1;
            return false;
        }

        // Packet type filter
        if !self.criteria.packet_type_passes(pkt) {
            self.rejected += 1;
            return false;
        }

        self.accepted += 1;
        true
    }

    /// Apply the filter to a slice of packets.
    #[must_use]
    pub fn filter_packets(&mut self, packets: &[PtPacket]) -> Vec<PtPacket> {
        packets
            .iter()
            .filter(|pkt| self.passes(pkt))
            .cloned()
            .collect()
    }

    /// Return the accept rate (0.0–1.0).
    #[must_use]
    pub fn accept_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        crate::cast_helpers::u64_to_f64(self.accepted) / crate::cast_helpers::u64_to_f64(self.total)
    }

    /// Reset counters.
    pub const fn reset_stats(&mut self) {
        self.accepted = 0;
        self.rejected = 0;
        self.total = 0;
    }
}

// ─── FilterChain ──────────────────────────────────────────────────────────────

/// A chain of `FilterCriteria` applied in order (logical AND).
pub struct FilterChain {
    filters: Vec<PacketFilter>,
}

impl FilterChain {
    /// Create an empty filter chain (accepts everything).
    #[must_use]
    pub const fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Add a filter to the chain.
    pub fn push(&mut self, filter: PacketFilter) {
        self.filters.push(filter);
    }

    /// Return `true` if `pkt` passes all filters in the chain.
    pub fn passes(&mut self, pkt: &PtPacket) -> bool {
        self.filters.iter_mut().all(|f| f.passes(pkt))
    }

    /// Filter a slice of packets through the entire chain.
    #[must_use]
    pub fn filter_packets(&mut self, packets: &[PtPacket]) -> Vec<PtPacket> {
        packets
            .iter()
            .filter(|pkt| self.filters.iter_mut().all(|f| f.passes(pkt)))
            .cloned()
            .collect()
    }

    /// Return the total number of filters.
    #[must_use]
    pub const fn filter_count(&self) -> usize {
        self.filters.len()
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ─── IpRangeSet ───────────────────────────────────────────────────────────────

/// A set of non-overlapping IP ranges used for coverage analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpRangeSet {
    ranges: Vec<IpRange>,
}

impl IpRangeSet {
    /// Create an empty range set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range (ranges are kept sorted and merged).
    pub fn insert(&mut self, range: IpRange) {
        self.ranges.push(range);
        self.ranges.sort_by_key(|r| r.start);
        self.merge();
    }

    /// Return `true` if `addr` is in any range.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    /// Return the total number of bytes covered.
    #[must_use]
    pub fn total_coverage(&self) -> u64 {
        self.ranges.iter().map(IpRange::size).sum()
    }

    /// Return the number of ranges.
    #[must_use]
    pub const fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Merge adjacent / overlapping ranges.
    fn merge(&mut self) {
        if self.ranges.len() < 2 {
            return;
        }
        let mut merged: Vec<IpRange> = Vec::with_capacity(self.ranges.len());
        for r in &self.ranges {
            if let Some(last) = merged.last_mut()
                && r.start <= last.end
            {
                last.end = last.end.max(r.end);
                continue;
            }
            merged.push(r.clone());
        }
        self.ranges = merged;
    }

    /// Compute coverage hit count for a slice of IP addresses.
    #[must_use]
    pub fn coverage_count(&self, addresses: &[u64]) -> u64 {
        addresses.iter().filter(|&&a| self.contains(a)).count() as u64
    }
}

// ─── FilterStats ──────────────────────────────────────────────────────────────

/// Statistics from a filter pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterStats {
    /// Total packets examined.
    pub total: u64,
    /// Packets accepted.
    pub accepted: u64,
    /// Packets rejected.
    pub rejected: u64,
    /// Packets rejected due to IP filter.
    pub rejected_ip: u64,
    /// Packets rejected due to time window.
    pub rejected_time: u64,
    /// Packets rejected due to ring filter.
    pub rejected_ring: u64,
    /// Packets rejected due to PID filter.
    pub rejected_pid: u64,
    /// Packets rejected due to type filter.
    pub rejected_type: u64,
}

impl FilterStats {
    /// Return the acceptance rate.
    #[must_use]
    pub fn accept_rate(&self) -> f64 {
        if self.total == 0 { 1.0 } else { crate::cast_helpers::u64_to_f64(self.accepted) / crate::cast_helpers::u64_to_f64(self.total) }
    }
}

/// Apply a `FilterCriteria` to a packet slice and return both the filtered
/// packets and statistics.
#[must_use]
pub fn filter_with_stats(
    criteria: &FilterCriteria,
    packets: &[PtPacket],
) -> (Vec<PtPacket>, FilterStats) {
    let mut stats = FilterStats::default();
    let mut current_tsc = 0u64;
    let mut current_cpl = 3u8;
    let mut out = Vec::new();

    for pkt in packets {
        stats.total += 1;

        // Update state
        match &pkt.kind {
            PtPacketKind::Tsc(t) => current_tsc = *t,
            PtPacketKind::Mode { leaf: 0x43, bits } => {
                current_cpl = (bits >> 2) & 0x03;
            }
            _ => {}
        }

        // IP filter
        if let Some(ip) = pkt.kind.ip_addr()
            && !criteria.ip_passes(ip)
        {
            stats.rejected += 1;
            stats.rejected_ip += 1;
            continue;
        }

        // Time window filter
        if !criteria.tsc_passes(current_tsc) {
            stats.rejected += 1;
            stats.rejected_time += 1;
            continue;
        }

        // Ring filter
        if !criteria.ring_passes(current_cpl) {
            stats.rejected += 1;
            stats.rejected_ring += 1;
            continue;
        }

        // Packet type filter
        if !criteria.packet_type_passes(pkt) {
            stats.rejected += 1;
            stats.rejected_type += 1;
            continue;
        }

        stats.accepted += 1;
        out.push(pkt.clone());
    }

    (out, stats)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpCompression;

    fn tip(ip: u64) -> PtPacket {
        PtPacket::new(
            PtPacketKind::Tip { ip, compression: IpCompression::Full48 },
            0,
            7,
        )
    }

    fn tsc(v: u64) -> PtPacket {
        PtPacket::new(PtPacketKind::Tsc(v), 0, 9)
    }

    fn pad() -> PtPacket {
        PtPacket::new(PtPacketKind::Pad, 0, 1)
    }

    #[test]
    fn test_ip_range_contains() {
        let r = IpRange::new(0x1000, 0x2000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_ip_range_overlaps() {
        let a = IpRange::new(0x1000, 0x2000);
        let b = IpRange::new(0x1800, 0x3000);
        let c = IpRange::new(0x3000, 0x4000);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_ip_range_display() {
        let r = IpRange::labelled(0x1000, 0x2000, "test");
        let s = r.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_ring_filter() {
        assert!(RingFilter::All.passes(0));
        assert!(RingFilter::All.passes(3));
        assert!(RingFilter::KernelOnly.passes(0));
        assert!(!RingFilter::KernelOnly.passes(3));
        assert!(RingFilter::UserOnly.passes(3));
        assert!(!RingFilter::UserOnly.passes(0));
    }

    #[test]
    fn test_time_window() {
        let w = TimeWindow::new(1000, 2000);
        assert!(w.contains(1000));
        assert!(w.contains(1999));
        assert!(!w.contains(2000));
        assert_eq!(w.duration(), 1000);
    }

    #[test]
    fn test_filter_criteria_ip() {
        let mut fc = FilterCriteria::pass_all();
        fc.add_ip_range(IpRange::new(0x1000, 0x2000));
        assert!(fc.ip_passes(0x1500));
        assert!(!fc.ip_passes(0x5000));
    }

    #[test]
    fn test_filter_criteria_ip_inverted() {
        let mut fc = FilterCriteria::pass_all();
        fc.add_ip_range(IpRange::new(0x1000, 0x2000));
        fc.invert_ip = true;
        assert!(!fc.ip_passes(0x1500));
        assert!(fc.ip_passes(0x5000));
    }

    #[test]
    fn test_filter_criteria_pid() {
        let fc = FilterCriteria::pids([1, 2, 3]);
        assert!(fc.pid_passes(1));
        assert!(!fc.pid_passes(5));
    }

    #[test]
    fn test_filter_criteria_tsc() {
        let mut fc = FilterCriteria::pass_all();
        fc.set_time_window(TimeWindow::new(100, 200));
        assert!(fc.tsc_passes(150));
        assert!(!fc.tsc_passes(50));
    }

    #[test]
    fn test_packet_type_filter_accept_all() {
        let f = PacketTypeFilter::accept_all();
        assert!(f.passes(&tsc(0)));
        assert!(f.passes(&pad()));
    }

    #[test]
    fn test_packet_type_filter_timing_only() {
        let f = PacketTypeFilter::timing_only();
        assert!(f.passes(&tsc(0)));
        assert!(!f.passes(&pad()));
        assert!(!f.passes(&tip(0x1000)));
    }

    #[test]
    fn test_packet_filter_passes_all() {
        let mut pf = PacketFilter::new(FilterCriteria::pass_all());
        let pkts = vec![tsc(100), tsc(200), pad()];
        let out = pf.filter_packets(&pkts);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn test_packet_filter_ip_range() {
        let mut fc = FilterCriteria::pass_all();
        fc.add_ip_range(IpRange::new(0x1000, 0x2000));
        let mut pf = PacketFilter::new(fc);
        // TIP inside range → pass
        let in_range = tip(0x1500);
        // TIP outside range → reject
        let out_range = tip(0x5000);
        assert!(pf.passes(&in_range));
        assert!(!pf.passes(&out_range));
    }

    #[test]
    fn test_packet_filter_accept_rate() {
        let mut pf = PacketFilter::new(FilterCriteria::pass_all());
        pf.total = 10;
        pf.accepted = 8;
        pf.rejected = 2;
        assert!((pf.accept_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_filter_chain() {
        let fc1 = FilterCriteria::pass_all();
        let mut fc2 = FilterCriteria::pass_all();
        fc2.add_ip_range(IpRange::new(0x1000, 0x2000));
        let mut chain = FilterChain::new();
        chain.push(PacketFilter::new(fc1));
        chain.push(PacketFilter::new(fc2));
        assert_eq!(chain.filter_count(), 2);
        let out = chain.filter_packets(&[tip(0x1500), tip(0x5000), pad()]);
        // TIP at 0x1500 passes both; TIP at 0x5000 fails fc2; pad has no IP so passes
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_ip_range_set_insert_and_contains() {
        let mut rs = IpRangeSet::new();
        rs.insert(IpRange::new(0x1000, 0x2000));
        rs.insert(IpRange::new(0x3000, 0x4000));
        assert!(rs.contains(0x1500));
        assert!(rs.contains(0x3500));
        assert!(!rs.contains(0x2500));
    }

    #[test]
    fn test_ip_range_set_merge() {
        let mut rs = IpRangeSet::new();
        rs.insert(IpRange::new(0x1000, 0x2000));
        rs.insert(IpRange::new(0x1800, 0x3000)); // overlapping
        assert_eq!(rs.range_count(), 1);
        assert_eq!(rs.total_coverage(), 0x2000);
    }

    #[test]
    fn test_ip_range_set_coverage_count() {
        let mut rs = IpRangeSet::new();
        rs.insert(IpRange::new(0x1000, 0x2000));
        let addrs = vec![0x1100, 0x1200, 0x5000];
        assert_eq!(rs.coverage_count(&addrs), 2);
    }

    #[test]
    fn test_filter_with_stats() {
        let mut fc = FilterCriteria::pass_all();
        fc.add_ip_range(IpRange::new(0x1000, 0x2000));
        let pkts = vec![tip(0x1500), tip(0x5000), tsc(100), pad()];
        let (out, stats) = filter_with_stats(&fc, &pkts);
        assert_eq!(stats.total, 4);
        assert!(stats.accepted > 0);
        assert!(stats.rejected_ip > 0);
        let _ = out;
    }

    #[test]
    fn test_filter_stats_accept_rate() {
        let stats = FilterStats {
            total: 100,
            accepted: 75,
            rejected: 25,
            ..Default::default()
        };
        assert!((stats.accept_rate() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_time_window_duration_ns() {
        let w = TimeWindow::new(0, 3_000_000);
        // At 3000 MHz: 3_000_000 ticks = 1_000_000 ns = 1 ms
        let ns = w.duration_ns(3000.0);
        assert!((ns - 1_000_000.0).abs() < 1.0, "got {ns}");
    }
}
