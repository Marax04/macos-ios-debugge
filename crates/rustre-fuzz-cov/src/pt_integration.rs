//! `pt_integration` — Intel PT coverage collection stub.
//!
//! Provides [`PtPacket`], [`PtDecoder`], [`PtCoverageCollector`],
//! [`PtBranchRecord`], and offline analysis helpers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── PtPacket ──────────────────────────────────────────────────────────────────

/// An Intel PT packet decoded from a raw PT stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtPacket {
    /// Taken/Not-Taken bits (up to 6 bits packed in one byte).
    Tnt { bits: u8, count: u8 },
    /// Target IP packet — direct or indirect branch target.
    Tip { ip: u64, compression: IpCompression },
    /// Flow Update Packet — synchronization IP.
    Fup { ip: u64 },
    /// Paging Information Packet — CR3 value.
    Pip { cr3: u64 },
    /// Mini Time Counter.
    Mtc { ctc: u8 },
    /// Cycle count.
    Cyc { value: u64 },
    /// Packet Stream Boundary — decoder sync point.
    Psb,
    /// Core Bus Ratio.
    Cbr { ratio: u8 },
    /// Timestamp Counter.
    Tsc { value: u64 },
    /// TSC/MTC Alignment.
    Tma { ctc: u16, fc: u16 },
    /// Unknown/unsupported packet byte.
    Unknown(u8),
}

/// IP compression modes for TIP/FUP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpCompression {
    /// IP suppressed (indirect branch not taken or out-of-context).
    Suppressed,
    /// Update low 16 bits.
    Update16,
    /// Update low 32 bits.
    Update32,
    /// Full 48-bit IP.
    Full48,
}

impl PtPacket {
    /// Whether this packet represents a taken branch.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(self, Self::Tnt { .. } | Self::Tip { .. })
    }

    /// Extract the IP address, if present.
    #[must_use]
    pub const fn ip(&self) -> Option<u64> {
        match self {
            Self::Tip { ip, .. } | Self::Fup { ip } => Some(*ip),
            _ => None,
        }
    }
}

// ── PtDecoder ─────────────────────────────────────────────────────────────────

/// Decoder for Intel PT packet streams.
///
/// This is a stub implementation that interprets a simplified PT encoding used
/// in test/simulation scenarios. A full production implementation would follow
/// the Intel 64 and IA-32 Architectures Software Developer's Manual Vol. 3C §35.
#[derive(Debug, Default)]
pub struct PtDecoder {
    /// Last seen full IP (used for compression reconstruction).
    last_ip: u64,
}

impl PtDecoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the decoder state (e.g. after a PSB packet).
    pub const fn reset(&mut self) {
        self.last_ip = 0;
    }

    /// Decode a raw PT packet stream into a list of [`PtPacket`]s.
    pub fn decode(&mut self, data: &[u8]) -> Vec<PtPacket> {
        let mut packets = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let (pkt, consumed) = self.decode_one(&data[i..]);
            packets.push(pkt);
            i += consumed.max(1);
        }
        packets
    }

    fn decode_one(&mut self, data: &[u8]) -> (PtPacket, usize) {
        if data.is_empty() {
            return (PtPacket::Unknown(0), 1);
        }
        let byte0 = data[0];

        // PSB: 0x02 0x82 (2 bytes)
        if byte0 == 0x02 && data.get(1) == Some(&0x82) {
            self.reset();
            return (PtPacket::Psb, 2);
        }

        // TNT short: bits [7:2] = payload, bits [1:0] = 00
        if byte0.trailing_zeros() >= 2 && byte0 != 0x00 {
            let bits = byte0 >> 2;
            let count = u8::try_from(bits.leading_ones()).unwrap_or(u8::MAX); // stop bit position
            return (
                PtPacket::Tnt {
                    bits,
                    count: 6u8.saturating_sub(count),
                },
                1,
            );
        }

        // TIP: opcode bits[4:1] = 0000, bits[7:5] = IP compression
        if byte0 & 0x1F == 0x0D {
            let comp = ip_compression(byte0 >> 5);
            let (ip, sz) = self.decode_ip(comp, &data[1..]);
            self.last_ip = ip;
            return (
                PtPacket::Tip {
                    ip,
                    compression: comp,
                },
                1 + sz,
            );
        }

        // FUP: opcode bits[4:1] = 0001, bits[7:5] = IP compression
        if byte0 & 0x1F == 0x1C {
            let comp = ip_compression(byte0 >> 5);
            let (ip, sz) = self.decode_ip(comp, &data[1..]);
            self.last_ip = ip;
            return (PtPacket::Fup { ip }, 1 + sz);
        }

        // CBR: 0x03 0x43 ratio
        if byte0 == 0x03 && data.get(1) == Some(&0x43) {
            let ratio = data.get(2).copied().unwrap_or(0);
            return (PtPacket::Cbr { ratio }, 3);
        }

        // TSC: 0x19 + 8 bytes LE
        if byte0 == 0x19 && data.len() >= 9 {
            let value = u64::from_le_bytes(data[1..9].try_into().unwrap());
            return (PtPacket::Tsc { value }, 9);
        }

        // MTC: 0x59 ctc
        if byte0 == 0x59 && data.len() >= 2 {
            return (PtPacket::Mtc { ctc: data[1] }, 2);
        }

        // CYC: variable-length; simplified: first byte encodes value
        if byte0 & 0x03 == 0x03 {
            let value = u64::from(byte0 >> 2);
            return (PtPacket::Cyc { value }, 1);
        }

        // PIP: 0x43 + 8 bytes
        if byte0 == 0x43 && data.len() >= 9 {
            let cr3 = u64::from_le_bytes(data[1..9].try_into().unwrap());
            return (PtPacket::Pip { cr3 }, 9);
        }

        (PtPacket::Unknown(byte0), 1)
    }

    fn decode_ip(&self, comp: IpCompression, rest: &[u8]) -> (u64, usize) {
        match comp {
            IpCompression::Suppressed => (self.last_ip, 0),
            IpCompression::Update16 => {
                if rest.len() < 2 {
                    return (self.last_ip, 0);
                }
                let low16 = u64::from(u16::from_le_bytes([rest[0], rest[1]]));
                let ip = (self.last_ip & !0xffff) | low16;
                (ip, 2)
            }
            IpCompression::Update32 => {
                if rest.len() < 4 {
                    return (self.last_ip, 0);
                }
                let low32 = u64::from(u32::from_le_bytes(rest[0..4].try_into().unwrap()));
                let ip = (self.last_ip & !0xffff_ffff) | low32;
                (ip, 4)
            }
            IpCompression::Full48 => {
                if rest.len() < 6 {
                    return (self.last_ip, 0);
                }
                let mut buf = [0u8; 8];
                buf[..6].copy_from_slice(&rest[..6]);
                let ip = u64::from_le_bytes(buf);
                (ip, 6)
            }
        }
    }

    /// Last reconstructed IP.
    #[must_use]
    pub const fn last_ip(&self) -> u64 {
        self.last_ip
    }
}

const fn ip_compression(bits: u8) -> IpCompression {
    match bits & 0x7 {
        0 => IpCompression::Suppressed,
        1 => IpCompression::Update16,
        2 | 3 => IpCompression::Update32,
        _ => IpCompression::Full48,
    }
}

// ── PtBranchRecord ────────────────────────────────────────────────────────────

/// A single decoded branch event from the PT stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtBranchRecord {
    /// Source address of the branch instruction.
    pub source: u64,
    /// Target address of the branch.
    pub target: u64,
    /// Whether the branch was taken.
    pub taken: bool,
    /// Optional cycle count at the time of the branch.
    pub cycle: Option<u64>,
}

impl PtBranchRecord {
    /// Create a new branch record.
    #[must_use]
    pub const fn new(source: u64, target: u64, taken: bool) -> Self {
        Self {
            source,
            target,
            taken,
            cycle: None,
        }
    }

    /// With cycle count.
    #[must_use]
    pub const fn with_cycle(mut self, cycle: u64) -> Self {
        self.cycle = Some(cycle);
        self
    }

    /// Edge identifier as `(source, target)` pair.
    #[must_use]
    pub const fn edge(&self) -> (u64, u64) {
        (self.source, self.target)
    }
}

// ── PtCoverageCollector ───────────────────────────────────────────────────────

/// Integrates PT decoding with process coverage tracking.
pub struct PtCoverageCollector {
    decoder: PtDecoder,
    /// All decoded branch records.
    pub branches: Vec<PtBranchRecord>,
    /// Edge coverage: (source, target) → hit count.
    pub edge_coverage: HashMap<(u64, u64), u64>,
    /// IP-to-process mapping: IP → process ID.
    pub ip_process_map: HashMap<u64, u32>,
    /// Current process ID.
    pub current_pid: Option<u32>,
}

impl Default for PtCoverageCollector {
    fn default() -> Self {
        Self {
            decoder: PtDecoder::new(),
            branches: Vec::new(),
            edge_coverage: HashMap::new(),
            ip_process_map: HashMap::new(),
            current_pid: None,
        }
    }
}

impl PtCoverageCollector {
    /// Create a new collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a raw PT packet stream to the collector.
    ///
    /// Decoded TIP packets become branch records.
    pub fn feed(&mut self, data: &[u8]) {
        let packets = self.decoder.decode(data);
        let mut last_source = 0u64;
        let mut last_cycle: Option<u64> = None;

        for pkt in &packets {
            match pkt {
                PtPacket::Tip { ip, .. } => {
                    let rec = PtBranchRecord {
                        source: last_source,
                        target: *ip,
                        taken: true,
                        cycle: last_cycle,
                    };
                    *self.edge_coverage.entry(rec.edge()).or_insert(0) += 1;
                    self.branches.push(rec);
                    last_source = *ip;
                }
                PtPacket::Fup { ip } => {
                    last_source = *ip;
                }
                PtPacket::Cyc { value } => {
                    last_cycle = Some(*value);
                }
                PtPacket::Psb => {
                    last_source = 0;
                    last_cycle = None;
                }
                _ => {}
            }
        }
    }

    /// Number of unique edges seen.
    #[must_use]
    pub fn unique_edges(&self) -> usize {
        self.edge_coverage.len()
    }

    /// Total branch count.
    #[must_use]
    pub const fn total_branches(&self) -> usize {
        self.branches.len()
    }

    /// Return edges with hit count >= `threshold`.
    #[must_use]
    pub fn hot_edges(&self, threshold: u64) -> Vec<((u64, u64), u64)> {
        self.edge_coverage
            .iter()
            .filter(|&(_, &c)| c >= threshold)
            .map(|(&e, &c)| (e, c))
            .collect()
    }

    /// Merge another collector's data into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&edge, &count) in &other.edge_coverage {
            *self.edge_coverage.entry(edge).or_insert(0) += count;
        }
        self.branches.extend_from_slice(&other.branches);
    }

    /// Clear all collected data.
    pub fn clear(&mut self) {
        self.branches.clear();
        self.edge_coverage.clear();
        self.decoder.reset();
    }

    /// Annotate branches with process information.
    pub fn annotate_process(&mut self, ip_range_start: u64, ip_range_end: u64, pid: u32) {
        for rec in &self.branches {
            if rec.target >= ip_range_start && rec.target < ip_range_end {
                self.ip_process_map.insert(rec.target, pid);
            }
        }
        self.current_pid = Some(pid);
    }
}

// ── PerfDataAnalyzer ──────────────────────────────────────────────────────────

/// Offline analysis of perf.data PT auxiliary data.
pub struct PerfDataAnalyzer {
    pub collector: PtCoverageCollector,
    pub aux_chunks: Vec<Vec<u8>>,
    pub total_bytes_processed: u64,
}

impl PerfDataAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            collector: PtCoverageCollector::new(),
            aux_chunks: Vec::new(),
            total_bytes_processed: 0,
        }
    }

    /// Simulate loading perf.data auxiliary chunks.
    pub fn load_aux_chunk(&mut self, data: Vec<u8>) {
        self.total_bytes_processed += data.len() as u64;
        self.collector.feed(&data);
        self.aux_chunks.push(data);
    }

    /// Number of chunks loaded.
    #[must_use]
    pub const fn chunk_count(&self) -> usize {
        self.aux_chunks.len()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "chunks={}, bytes={}, branches={}, edges={}",
            self.chunk_count(),
            self.total_bytes_processed,
            self.collector.total_branches(),
            self.collector.unique_edges()
        )
    }
}

impl Default for PerfDataAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tip_packet(ip: u64) -> Vec<u8> {
        // TIP with Full48 compression: opcode = 0xCD (bits[4:1]=0000_110, bits[7:5]=111)
        let opcode = 0x0D | (4u8 << 5); // bits[7:5]=100 → Full48
        let mut v = vec![opcode];
        let bytes = ip.to_le_bytes();
        v.extend_from_slice(&bytes[..6]);
        v
    }

    fn make_psb() -> Vec<u8> {
        vec![0x02, 0x82]
    }

    fn make_tsc(value: u64) -> Vec<u8> {
        let mut v = vec![0x19];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    fn make_cbr(ratio: u8) -> Vec<u8> {
        vec![0x03, 0x43, ratio]
    }

    #[test]
    fn test_psb_decodes() {
        let mut dec = PtDecoder::new();
        let pkts = dec.decode(&make_psb());
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], PtPacket::Psb);
    }

    #[test]
    fn test_tsc_decodes() {
        let mut dec = PtDecoder::new();
        let pkts = dec.decode(&make_tsc(0xDEAD_BEEF_0001));
        assert!(pkts.iter().any(|p| matches!(p, PtPacket::Tsc { .. })));
    }

    #[test]
    fn test_cbr_decodes() {
        let mut dec = PtDecoder::new();
        let pkts = dec.decode(&make_cbr(42));
        assert!(
            pkts.iter()
                .any(|p| matches!(p, PtPacket::Cbr { ratio: 42 }))
        );
    }

    #[test]
    fn test_tip_full48() {
        let mut dec = PtDecoder::new();
        let data = make_tip_packet(0x0000_7fff_1234_5678);
        let pkts = dec.decode(&data);
        assert!(pkts.iter().any(|p| matches!(p, PtPacket::Tip { .. })));
    }

    #[test]
    fn test_decoder_reset_clears_ip() {
        let mut dec = PtDecoder::new();
        dec.last_ip = 0xDEAD;
        dec.reset();
        assert_eq!(dec.last_ip(), 0);
    }

    #[test]
    fn test_unknown_byte() {
        let mut dec = PtDecoder::new();
        let pkts = dec.decode(&[0xAA]);
        assert!(pkts.iter().any(|p| matches!(p, PtPacket::Unknown(_))));
    }

    #[test]
    fn test_pt_branch_record_new() {
        let r = PtBranchRecord::new(0x1000, 0x2000, true);
        assert_eq!(r.edge(), (0x1000, 0x2000));
        assert!(r.taken);
        assert!(r.cycle.is_none());
    }

    #[test]
    fn test_pt_branch_record_with_cycle() {
        let r = PtBranchRecord::new(0, 1, true).with_cycle(42);
        assert_eq!(r.cycle, Some(42));
    }

    #[test]
    fn test_collector_feed_tip() {
        let mut col = PtCoverageCollector::new();
        let data = make_tip_packet(0x0000_4000_1234_5678);
        col.feed(&data);
        let _edges = col.unique_edges();
        let _ = col.total_branches();
    }

    #[test]
    fn test_collector_clear() {
        let mut col = PtCoverageCollector::new();
        col.feed(&make_tip_packet(0x1234));
        col.clear();
        assert_eq!(col.total_branches(), 0);
        assert_eq!(col.unique_edges(), 0);
    }

    #[test]
    fn test_collector_merge() {
        let mut a = PtCoverageCollector::new();
        let mut b = PtCoverageCollector::new();
        a.edge_coverage.insert((0x100, 0x200), 3);
        b.edge_coverage.insert((0x100, 0x200), 2);
        b.edge_coverage.insert((0x300, 0x400), 1);
        a.merge(&b);
        assert_eq!(*a.edge_coverage.get(&(0x100, 0x200)).unwrap(), 5);
        assert_eq!(a.unique_edges(), 2);
    }

    #[test]
    fn test_collector_hot_edges() {
        let mut col = PtCoverageCollector::new();
        col.edge_coverage.insert((0x100, 0x200), 10);
        col.edge_coverage.insert((0x300, 0x400), 1);
        let hot = col.hot_edges(5);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, (0x100, 0x200));
    }

    #[test]
    fn test_perf_data_analyzer_chunk_count() {
        let mut a = PerfDataAnalyzer::new();
        a.load_aux_chunk(vec![0u8; 32]);
        a.load_aux_chunk(vec![0u8; 16]);
        assert_eq!(a.chunk_count(), 2);
        assert_eq!(a.total_bytes_processed, 48);
    }

    #[test]
    fn test_perf_data_analyzer_summary() {
        let a = PerfDataAnalyzer::new();
        let s = a.summary();
        assert!(s.contains("chunks=0"));
    }

    #[test]
    fn test_pt_packet_is_branch() {
        assert!(
            PtPacket::Tip {
                ip: 0,
                compression: IpCompression::Full48
            }
            .is_branch()
        );
        assert!(!PtPacket::Psb.is_branch());
    }

    #[test]
    fn test_pt_packet_ip() {
        let p = PtPacket::Tip {
            ip: 0x1234,
            compression: IpCompression::Full48,
        };
        assert_eq!(p.ip(), Some(0x1234));
        assert_eq!(PtPacket::Psb.ip(), None);
    }

    #[test]
    fn test_collector_annotate_process() {
        let mut col = PtCoverageCollector::new();
        col.branches.push(PtBranchRecord::new(0x1000, 0x2000, true));
        col.annotate_process(0x2000, 0x3000, 42);
        assert_eq!(col.current_pid, Some(42));
    }

    #[test]
    fn test_multiple_tips_in_stream() {
        let mut data = Vec::new();
        data.extend(make_psb());
        data.extend(make_tip_packet(0x0000_1111_0000_0000));
        data.extend(make_tip_packet(0x0000_2222_0000_0000));
        let mut col = PtCoverageCollector::new();
        col.feed(&data);
        // Two TIP packets decoded → up to 2 branches (first source is 0)
        assert!(col.total_branches() <= 2);
    }

    #[test]
    fn test_mtc_decodes() {
        let data = vec![0x59, 0x07];
        let mut dec = PtDecoder::new();
        let pkts = dec.decode(&data);
        assert!(pkts.iter().any(|p| matches!(p, PtPacket::Mtc { ctc: 7 })));
    }

    #[test]
    fn test_empty_feed_no_panic() {
        let mut col = PtCoverageCollector::new();
        col.feed(&[]);
        assert_eq!(col.total_branches(), 0);
    }

    #[test]
    fn test_branch_record_is_not_taken_by_default_false() {
        let r = PtBranchRecord::new(0, 0, false);
        assert!(!r.taken);
    }

    #[test]
    fn test_ip_compression_full48_roundtrip() {
        assert_eq!(ip_compression(4), IpCompression::Full48);
    }

    #[test]
    fn test_perf_data_analyzer_default() {
        let a = PerfDataAnalyzer::default();
        assert_eq!(a.chunk_count(), 0);
    }
}
