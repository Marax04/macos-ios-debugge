//! Protocol statistics, conversation matrices, and bandwidth accounting.
//!
//! Provides:
//! - [`ProtocolStats`] — per-protocol counters
//! - [`ConversationMatrix`] — per-host-pair traffic accounting
//! - [`BandwidthUsage`] — rolling bandwidth measurement
//! - [`ProtocolDistribution`] — percentage breakdown across protocols
//! - [`TimeSeriesData`] — timestamped measurement buckets
//! - [`StatExporter`] — JSON/CSV export

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::json;

// ────────────────────────────────────────────────────────────────────────────
// ProtocolStats
// ────────────────────────────────────────────────────────────────────────────

/// Per-protocol packet and byte counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    /// Protocol name → (`packet_count`, `byte_count`).
    pub counters: HashMap<String, (u64, u64)>,
}

impl ProtocolStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet for the given protocol.
    pub fn record(&mut self, protocol: &str, bytes: u64) {
        let entry = self.counters.entry(protocol.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    /// Packet count for a protocol.
    #[must_use]
    pub fn packets(&self, protocol: &str) -> u64 {
        self.counters.get(protocol).map_or(0, |&(p, _)| p)
    }

    /// Byte count for a protocol.
    #[must_use]
    pub fn bytes(&self, protocol: &str) -> u64 {
        self.counters.get(protocol).map_or(0, |&(_, b)| b)
    }

    /// Total packets across all protocols.
    #[must_use]
    pub fn total_packets(&self) -> u64 {
        self.counters.values().map(|&(p, _)| p).sum()
    }

    /// Total bytes across all protocols.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.counters.values().map(|&(_, b)| b).sum()
    }

    /// Protocols sorted by byte count descending.
    #[must_use]
    pub fn top_by_bytes(&self, n: usize) -> Vec<(&str, u64, u64)> {
        let mut entries: Vec<(&str, u64, u64)> = self
            .counters
            .iter()
            .map(|(k, &(p, b))| (k.as_str(), p, b))
            .collect();
        entries.sort_by(|a, b| b.2.cmp(&a.2));
        entries.truncate(n);
        entries
    }

    /// Merge another `ProtocolStats` into this one.
    pub fn merge(&mut self, other: &Self) {
        for (proto, &(p, b)) in &other.counters {
            let entry = self.counters.entry(proto.clone()).or_insert((0, 0));
            entry.0 += p;
            entry.1 += b;
        }
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.counters.clear();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ConversationKey
// ────────────────────────────────────────────────────────────────────────────

/// Identifies a bidirectional conversation between two endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationKey {
    /// Canonical ordering: (lower IP, higher IP).
    pub addr_a: IpAddr,
    pub port_a: u16,
    pub addr_b: IpAddr,
    pub port_b: u16,
    pub protocol: String,
}

impl ConversationKey {
    /// Build a canonical (sorted) conversation key.
    pub fn new(
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        let (addr_a, port_a, addr_b, port_b) = if (src, src_port) <= (dst, dst_port) {
            (src, src_port, dst, dst_port)
        } else {
            (dst, dst_port, src, src_port)
        };
        Self {
            addr_a,
            port_a,
            addr_b,
            port_b,
            protocol: protocol.into(),
        }
    }
}

impl fmt::Display for ConversationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{} [{}]",
            self.addr_a, self.port_a, self.addr_b, self.port_b, self.protocol,
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ConversationEntry
// ────────────────────────────────────────────────────────────────────────────

/// Traffic statistics for a single conversation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationEntry {
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl ConversationEntry {
    const fn touch(&mut self, now_ms: u64) {
        if self.first_seen_ms == 0 {
            self.first_seen_ms = now_ms;
        }
        self.last_seen_ms = now_ms;
    }

    /// Duration of the conversation in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.last_seen_ms.saturating_sub(self.first_seen_ms)
    }

    /// Total packets.
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    /// Total bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ConversationMatrix
// ────────────────────────────────────────────────────────────────────────────

/// Grouped parameters for [`ConversationMatrix::record`].
pub struct ConversationPacket<'a> {
    pub src:      IpAddr,
    pub src_port: u16,
    pub dst:      IpAddr,
    pub dst_port: u16,
    pub protocol: &'a str,
    pub bytes:    u64,
    pub now_ms:   u64,
}

/// Tracks per-conversation traffic across all observed host pairs.
#[derive(Debug, Default)]
pub struct ConversationMatrix {
    conversations: HashMap<ConversationKey, ConversationEntry>,
}

impl ConversationMatrix {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet using grouped parameters.
    pub fn record(&mut self, pkt: &ConversationPacket<'_>) {
        let key = ConversationKey::new(pkt.src, pkt.src_port, pkt.dst, pkt.dst_port, pkt.protocol);
        let entry = self.conversations.entry(key).or_default();
        entry.touch(pkt.now_ms);
        // Determine direction
        if (pkt.src, pkt.src_port) <= (pkt.dst, pkt.dst_port) {
            entry.packets_a_to_b += 1;
            entry.bytes_a_to_b += pkt.bytes;
        } else {
            entry.packets_b_to_a += 1;
            entry.bytes_b_to_a += pkt.bytes;
        }
    }

    /// Number of tracked conversations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.conversations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.conversations.is_empty()
    }

    /// Conversations sorted by total bytes (descending).
    #[must_use]
    pub fn top_by_bytes(&self, n: usize) -> Vec<(&ConversationKey, &ConversationEntry)> {
        let mut v: Vec<_> = self.conversations.iter().collect();
        v.sort_by(|a, b| b.1.total_bytes().cmp(&a.1.total_bytes()));
        v.truncate(n);
        v
    }

    /// Get a specific conversation entry.
    #[must_use]
    pub fn get(
        &self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        protocol: &str,
    ) -> Option<&ConversationEntry> {
        let key = ConversationKey::new(src, src_port, dst, dst_port, protocol);
        self.conversations.get(&key)
    }

    /// Total bytes across all conversations.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.conversations.values().map(ConversationEntry::total_bytes).sum()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// BandwidthUsage
// ────────────────────────────────────────────────────────────────────────────

/// Sliding-window bandwidth measurement.
///
/// Keeps a fixed-size circular buffer of (`timestamp_ms`, bytes) samples.
/// `current_bps()` computes the bits-per-second over the window.
#[derive(Debug)]
pub struct BandwidthUsage {
    window_ms: u64,
    samples: std::collections::VecDeque<(u64, u64)>, // (timestamp_ms, bytes)
}

impl BandwidthUsage {
    /// Create a bandwidth tracker with a given window in milliseconds.
    #[must_use]
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            samples: std::collections::VecDeque::new(),
        }
    }

    /// Record `bytes` received at `timestamp_ms`.
    pub fn record(&mut self, timestamp_ms: u64, bytes: u64) {
        // Prune stale samples
        let cutoff = timestamp_ms.saturating_sub(self.window_ms);
        while self
            .samples
            .front()
            .is_some_and(|&(ts, _)| ts < cutoff)
        {
            self.samples.pop_front();
        }
        self.samples.push_back((timestamp_ms, bytes));
    }

    /// Compute the current bandwidth in bits per second.
    #[must_use]
    pub fn current_bps(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let total_bytes: u64 = self.samples.iter().map(|&(_, b)| b).sum();
        let first_ts = self.samples.front().map_or(0, |&(ts, _)| ts);
        let last_ts = self.samples.back().map_or(0, |&(ts, _)| ts);
        let span_ms = last_ts.saturating_sub(first_ts).max(1);
        (f64::from(u32::try_from(total_bytes).unwrap_or(u32::MAX)) * 8.0 * 1000.0) / f64::from(u32::try_from(span_ms).unwrap_or(u32::MAX))
    }

    /// Total bytes in the current window.
    #[must_use]
    pub fn window_bytes(&self) -> u64 {
        self.samples.iter().map(|&(_, b)| b).sum()
    }

    /// Number of samples in the window.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ProtocolDistribution
// ────────────────────────────────────────────────────────────────────────────

/// Percentage distribution of traffic across protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDistribution {
    /// Protocol → percentage (0.0–100.0).
    pub shares: Vec<(String, f64)>,
    /// Total bytes used for percentage calculation.
    pub total_bytes: u64,
}

impl ProtocolDistribution {
    /// Compute distribution from a [`ProtocolStats`].
    #[must_use]
    pub fn from_stats(stats: &ProtocolStats) -> Self {
        let total = stats.total_bytes();
        let shares: Vec<(String, f64)> = if total == 0 {
            stats.counters.keys().map(|k| (k.clone(), 0.0)).collect()
        } else {
            stats
                .counters
                .iter()
                .map(|(k, &(_, b))| (k.clone(), f64::from(u32::try_from(b).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX)) * 100.0))
                .collect()
        };
        // Sort descending by share
        let mut shares = shares;
        shares.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            shares,
            total_bytes: total,
        }
    }

    /// Get the share for a specific protocol.
    #[must_use]
    pub fn share(&self, protocol: &str) -> f64 {
        self.shares
            .iter()
            .find(|(k, _)| k == protocol)
            .map_or(0.0, |(_, v)| *v)
    }

    /// Protocol with the highest share.
    #[must_use]
    pub fn dominant(&self) -> Option<&str> {
        self.shares.first().map(|(k, _)| k.as_str())
    }
}

impl fmt::Display for ProtocolDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (proto, pct) in &self.shares {
            writeln!(f, "  {proto}: {pct:.1}%")?;
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TimeSeriesData
// ────────────────────────────────────────────────────────────────────────────

/// A single time-series bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    /// Start of bucket (Unix ms).
    pub timestamp_ms: u64,
    /// Total bytes in this bucket.
    pub bytes: u64,
    /// Total packets in this bucket.
    pub packets: u64,
}

/// Timestamped measurement series with configurable bucket width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesData {
    pub bucket_width_ms: u64,
    pub buckets: Vec<TimeBucket>,
}

impl TimeSeriesData {
    /// Create a new time series with the given bucket width.
    #[must_use]
    pub fn new(bucket_width_ms: u64) -> Self {
        Self {
            bucket_width_ms: bucket_width_ms.max(1),
            buckets: Vec::new(),
        }
    }

    /// Record bytes and a packet at a given timestamp.
    pub fn record(&mut self, timestamp_ms: u64, bytes: u64) {
        let bucket_ts = (timestamp_ms / self.bucket_width_ms) * self.bucket_width_ms;
        if let Some(last) = self.buckets.last_mut()
            && last.timestamp_ms == bucket_ts {
                last.bytes += bytes;
                last.packets += 1;
                return;
            }
        self.buckets.push(TimeBucket {
            timestamp_ms: bucket_ts,
            bytes,
            packets: 1,
        });
    }

    /// Maximum bytes across all buckets.
    #[must_use]
    pub fn peak_bytes(&self) -> u64 {
        self.buckets.iter().map(|b| b.bytes).max().unwrap_or(0)
    }

    /// Average bytes per bucket.
    #[must_use]
    pub fn avg_bytes(&self) -> f64 {
        if self.buckets.is_empty() {
            return 0.0;
        }
        let total: u64 = self.buckets.iter().map(|b| b.bytes).sum();
        f64::from(u32::try_from(total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.buckets.len()).unwrap_or(u32::MAX))
    }

    /// Total bytes across all buckets.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.buckets.iter().map(|b| b.bytes).sum()
    }

    /// Number of buckets.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buckets.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// StatExporter
// ────────────────────────────────────────────────────────────────────────────

/// Exports statistics to JSON or CSV.
pub struct StatExporter;

impl StatExporter {
    /// Export [`ProtocolStats`] to a JSON string.
    #[must_use]
    pub fn stats_to_json(stats: &ProtocolStats) -> String {
        let items: Vec<serde_json::Value> = stats
            .counters
            .iter()
            .map(|(proto, &(pkts, bytes))| json!({
                "protocol": proto,
                "packets": pkts,
                "bytes": bytes,
            }))
            .collect();
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export [`ProtocolStats`] to CSV.
    #[must_use]
    pub fn stats_to_csv(stats: &ProtocolStats) -> String {
        let mut out = "protocol,packets,bytes\n".to_string();
        let mut entries: Vec<_> = stats.counters.iter().collect();
        entries.sort_by_key(|(k, _)| k.as_str());
        for (proto, &(pkts, bytes)) in entries {
            out.push_str(proto);
            out.push(',');
            out.push_str(&pkts.to_string());
            out.push(',');
            out.push_str(&bytes.to_string());
            out.push('\n');
        }
        out
    }

    /// Export a [`ConversationMatrix`] to JSON.
    #[must_use]
    pub fn matrix_to_json(matrix: &ConversationMatrix) -> String {
        let items: Vec<serde_json::Value> = matrix
            .conversations
            .iter()
            .map(|(key, entry)| json!({
                "src": format!("{}:{}", key.addr_a, key.port_a),
                "dst": format!("{}:{}", key.addr_b, key.port_b),
                "proto": key.protocol,
                "pkts_fwd": entry.packets_a_to_b,
                "pkts_rev": entry.packets_b_to_a,
                "bytes_fwd": entry.bytes_a_to_b,
                "bytes_rev": entry.bytes_b_to_a,
            }))
            .collect();
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export a [`TimeSeriesData`] to CSV.
    #[must_use]
    pub fn timeseries_to_csv(ts: &TimeSeriesData) -> String {
        let mut out = "timestamp_ms,bytes,packets\n".to_string();
        for b in &ts.buckets {
            out.push_str(&b.timestamp_ms.to_string());
            out.push(',');
            out.push_str(&b.bytes.to_string());
            out.push(',');
            out.push_str(&b.packets.to_string());
            out.push('\n');
        }
        out
    }

    /// Export a [`ProtocolDistribution`] to JSON.
    #[must_use]
    pub fn distribution_to_json(dist: &ProtocolDistribution) -> String {
        let items: Vec<serde_json::Value> = dist
            .shares
            .iter()
            .map(|(proto, pct)| json!({
                "protocol": proto,
                // Format with exactly two decimal places so downstream
                // consumers / tests get a predictable "NN.NN" string.
                "share_pct": format!("{:.2}", pct),
            }))
            .collect();
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    // ── ProtocolStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_stats_record_and_query() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1024);
        s.record("HTTP", 512);
        s.record("DNS", 64);
        assert_eq!(s.packets("HTTP"), 2);
        assert_eq!(s.bytes("HTTP"), 1536);
        assert_eq!(s.packets("DNS"), 1);
    }

    #[test]
    fn test_stats_total() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1000);
        s.record("DNS", 500);
        assert_eq!(s.total_packets(), 2);
        assert_eq!(s.total_bytes(), 1500);
    }

    #[test]
    fn test_stats_top_by_bytes() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1000);
        s.record("DNS", 50);
        s.record("SSH", 2000);
        let top = s.top_by_bytes(2);
        assert_eq!(top[0].0, "SSH");
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn test_stats_merge() {
        let mut a = ProtocolStats::new();
        a.record("HTTP", 100);
        let mut b = ProtocolStats::new();
        b.record("HTTP", 200);
        b.record("DNS", 50);
        a.merge(&b);
        assert_eq!(a.bytes("HTTP"), 300);
        assert_eq!(a.bytes("DNS"), 50);
    }

    #[test]
    fn test_stats_reset() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 100);
        s.reset();
        assert_eq!(s.total_packets(), 0);
    }

    #[test]
    fn test_stats_unknown_protocol() {
        let s = ProtocolStats::new();
        assert_eq!(s.packets("UNKNOWN"), 0);
        assert_eq!(s.bytes("UNKNOWN"), 0);
    }

    // ── ConversationKey ────────────────────────────────────────────────────────

    #[test]
    fn test_conversation_key_canonical() {
        let k1 = ConversationKey::new(ip(1), 80, ip(2), 54321, "TCP");
        let k2 = ConversationKey::new(ip(2), 54321, ip(1), 80, "TCP");
        assert_eq!(k1, k2); // bidirectional equality
    }

    #[test]
    fn test_conversation_key_display() {
        let k = ConversationKey::new(ip(1), 80, ip(2), 443, "TCP");
        let s = k.to_string();
        assert!(s.contains("<->"));
        assert!(s.contains("TCP"));
    }

    // ── ConversationEntry ─────────────────────────────────────────────────────

    #[test]
    fn test_conversation_entry_duration() {
        let e = ConversationEntry {
            first_seen_ms: 1000,
            last_seen_ms: 5000,
            ..ConversationEntry::default()
        };
        assert_eq!(e.duration_ms(), 4000);
    }

    #[test]
    fn test_conversation_entry_totals() {
        let e = ConversationEntry {
            packets_a_to_b: 10,
            packets_b_to_a: 5,
            bytes_a_to_b: 1000,
            bytes_b_to_a: 500,
            ..ConversationEntry::default()
        };
        assert_eq!(e.total_packets(), 15);
        assert_eq!(e.total_bytes(), 1500);
    }

    // ── ConversationMatrix ────────────────────────────────────────────────────

    #[test]
    fn test_matrix_record_and_retrieve() {
        let mut m = ConversationMatrix::new();
        m.record(&ConversationPacket { src: ip(1), src_port: 54321, dst: ip(2), dst_port: 80, protocol: "TCP", bytes: 512, now_ms: 1000 });
        let entry = m.get(ip(1), 54321, ip(2), 80, "TCP").unwrap();
        assert!(entry.total_bytes() == 512);
    }

    #[test]
    fn test_matrix_bidirectional() {
        let mut m = ConversationMatrix::new();
        m.record(&ConversationPacket { src: ip(1), src_port: 1000, dst: ip(2), dst_port: 80, protocol: "TCP", bytes: 100, now_ms: 1000 });
        m.record(&ConversationPacket { src: ip(2), src_port: 80, dst: ip(1), dst_port: 1000, protocol: "TCP", bytes: 200, now_ms: 2000 }); // reverse direction
        let entry = m.get(ip(1), 1000, ip(2), 80, "TCP").unwrap();
        assert_eq!(entry.total_bytes(), 300);
    }

    #[test]
    fn test_matrix_top_by_bytes() {
        let mut m = ConversationMatrix::new();
        m.record(&ConversationPacket { src: ip(1), src_port: 1, dst: ip(2), dst_port: 80, protocol: "TCP", bytes: 500, now_ms: 1000 });
        m.record(&ConversationPacket { src: ip(3), src_port: 2, dst: ip(4), dst_port: 80, protocol: "TCP", bytes: 200, now_ms: 1000 });
        let top = m.top_by_bytes(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].1.total_bytes(), 500);
    }

    #[test]
    fn test_matrix_total_bytes() {
        let mut m = ConversationMatrix::new();
        m.record(&ConversationPacket { src: ip(1), src_port: 1, dst: ip(2), dst_port: 80, protocol: "TCP", bytes: 300, now_ms: 1000 });
        m.record(&ConversationPacket { src: ip(3), src_port: 2, dst: ip(4), dst_port: 80, protocol: "TCP", bytes: 200, now_ms: 1000 });
        assert_eq!(m.total_bytes(), 500);
    }

    #[test]
    fn test_matrix_is_empty() {
        let m = ConversationMatrix::new();
        assert!(m.is_empty());
    }

    // ── BandwidthUsage ────────────────────────────────────────────────────────

    #[test]
    fn test_bandwidth_single_sample() {
        let mut bw = BandwidthUsage::new(1000);
        bw.record(0, 1000);
        assert_eq!(bw.window_bytes(), 1000);
        assert_eq!(bw.current_bps(), 0.0); // need at least 2 samples
    }

    #[test]
    fn test_bandwidth_two_samples() {
        let mut bw = BandwidthUsage::new(2000);
        bw.record(0, 1000);
        bw.record(1000, 1000);
        let bps = bw.current_bps();
        // 2000 bytes in 1000ms = 16000 bps
        assert!((bps - 16000.0).abs() < 1.0);
    }

    #[test]
    fn test_bandwidth_window_eviction() {
        let mut bw = BandwidthUsage::new(500); // 500ms window
        bw.record(0, 1000);
        bw.record(1000, 500); // 0ms sample now outside window
        assert_eq!(bw.sample_count(), 1); // old sample evicted
    }

    #[test]
    fn test_bandwidth_window_bytes() {
        let mut bw = BandwidthUsage::new(2000);
        bw.record(0, 100);
        bw.record(100, 200);
        assert_eq!(bw.window_bytes(), 300);
    }

    // ── ProtocolDistribution ──────────────────────────────────────────────────

    #[test]
    fn test_distribution_basic() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 750);
        s.record("DNS", 250);
        let dist = ProtocolDistribution::from_stats(&s);
        assert_eq!(dist.dominant(), Some("HTTP"));
        let http_share = dist.share("HTTP");
        assert!((http_share - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_distribution_unknown_protocol() {
        let s = ProtocolStats::new();
        let dist = ProtocolDistribution::from_stats(&s);
        assert_eq!(dist.share("MISSING"), 0.0);
    }

    #[test]
    fn test_distribution_sorted_descending() {
        let mut s = ProtocolStats::new();
        s.record("DNS", 100);
        s.record("HTTP", 900);
        let dist = ProtocolDistribution::from_stats(&s);
        assert_eq!(dist.shares[0].0, "HTTP");
    }

    #[test]
    fn test_distribution_display() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 100);
        let dist = ProtocolDistribution::from_stats(&s);
        let display = dist.to_string();
        assert!(display.contains("HTTP"));
        assert!(display.contains('%'));
    }

    // ── TimeSeriesData ────────────────────────────────────────────────────────

    #[test]
    fn test_timeseries_record_buckets() {
        let mut ts = TimeSeriesData::new(1000);
        ts.record(0, 100);
        ts.record(500, 200); // same bucket (0-999ms)
        ts.record(1000, 300); // new bucket
        assert_eq!(ts.len(), 2);
        assert_eq!(ts.buckets[0].bytes, 300);
        assert_eq!(ts.buckets[1].bytes, 300);
    }

    #[test]
    fn test_timeseries_peak_bytes() {
        let mut ts = TimeSeriesData::new(1000);
        ts.record(0, 100);
        ts.record(1000, 500);
        ts.record(2000, 200);
        assert_eq!(ts.peak_bytes(), 500);
    }

    #[test]
    fn test_timeseries_avg_bytes() {
        let mut ts = TimeSeriesData::new(1000);
        ts.record(0, 100);
        ts.record(1000, 300);
        assert!((ts.avg_bytes() - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_timeseries_total_bytes() {
        let mut ts = TimeSeriesData::new(1000);
        ts.record(0, 100);
        ts.record(1000, 200);
        assert_eq!(ts.total_bytes(), 300);
    }

    #[test]
    fn test_timeseries_empty() {
        let ts = TimeSeriesData::new(1000);
        assert!(ts.is_empty());
        assert_eq!(ts.peak_bytes(), 0);
        assert_eq!(ts.avg_bytes(), 0.0);
    }

    // ── StatExporter ──────────────────────────────────────────────────────────

    #[test]
    fn test_exporter_stats_to_json() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1000);
        let json = StatExporter::stats_to_json(&s);
        assert!(json.contains("HTTP"));
        assert!(json.contains("1000"));
        // Validate it's roughly JSON
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    #[test]
    fn test_exporter_stats_to_csv() {
        let mut s = ProtocolStats::new();
        s.record("DNS", 200);
        s.record("HTTP", 400);
        let csv = StatExporter::stats_to_csv(&s);
        assert!(csv.starts_with("protocol,packets,bytes\n"));
        assert!(csv.contains("DNS,1,200\n"));
    }

    #[test]
    fn test_exporter_matrix_to_json() {
        let mut m = ConversationMatrix::new();
        m.record(&ConversationPacket { src: ip(1), src_port: 1000, dst: ip(2), dst_port: 80, protocol: "TCP", bytes: 512, now_ms: 1000 });
        let json = StatExporter::matrix_to_json(&m);
        assert!(json.contains("TCP"));
        assert!(json.starts_with('['));
    }

    #[test]
    fn test_exporter_timeseries_to_csv() {
        let mut ts = TimeSeriesData::new(1000);
        ts.record(0, 100);
        let csv = StatExporter::timeseries_to_csv(&ts);
        assert!(csv.starts_with("timestamp_ms,bytes,packets\n"));
        assert!(csv.contains("0,100,1\n"));
    }

    #[test]
    fn test_exporter_distribution_to_json() {
        let mut s = ProtocolStats::new();
        s.record("HTTP", 1000);
        let dist = ProtocolDistribution::from_stats(&s);
        let json = StatExporter::distribution_to_json(&dist);
        assert!(json.contains("HTTP"));
        assert!(json.contains("100.00"));
    }
}
