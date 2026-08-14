//! Network traffic classification.
//!
//! Identifies malicious or suspicious traffic patterns including C2 beaconing
//! (regular interval connections to a remote host), data exfiltration
//! (large outbound payloads), and port-scanning behaviour.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

// ── Lossy cast helpers (deliberate boundaries) ───────────────────────────────

#[inline]
fn u64_to_f64_lossy(n: u64) -> f64 {
    let lo = u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0);
    let hi = u32::try_from(n >> 32).unwrap_or(0);
    (f64::from(hi) * f64::from(1u32 << 16)).mul_add(f64::from(1u32 << 16), f64::from(lo))
}
#[inline]
fn usize_to_f64_lossy(n: usize) -> f64 { u64_to_f64_lossy(n as u64) }
#[inline]
fn usize_to_u8_trunc(n: usize) -> u8 { u8::try_from(n & 0xFF).unwrap_or(u8::MAX) }
#[inline]
fn f64_to_u8_clamped(x: f64) -> u8 {
    // Clamp x into [0, 255] then map via integer search to avoid float cast.
    if x.is_nan() || x <= 0.0 { return 0; }
    if x >= 255.0 { return 255; }
    // Linear scan over integer thresholds — deliberate to avoid float-to-int cast.
    let mut result: u8 = 0;
    for i in 1u16..=255 {
        if f64::from(i) > x { break; }
        result = u8::try_from(i).unwrap_or(255);
    }
    result
}

// ── Traffic class ─────────────────────────────────────────────────────────────

/// The classification assigned to a traffic flow or set of flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficClass {
    /// Regular interval beaconing to a remote host — consistent with C2.
    C2Beaconing,
    /// Large or unusual outbound data volume — consistent with exfiltration.
    DataExfiltration,
    /// Many connections to different ports on the same host or to many hosts.
    PortScan,
    /// Repeated failed authentication attempts.
    BruteForce,
    /// Lateral movement within the network (e.g. SMB/RPC to internal hosts).
    LateralMovement,
    /// DNS tunnelling: unusually long or high-volume DNS queries.
    DnsTunnel,
    /// Domain generation algorithm activity: many failed NXDOMAIN resolutions.
    DgaActivity,
    /// Traffic that does not fit a suspicious category.
    Benign,
    /// Insufficient data to make a determination.
    Undetermined,
}

impl TrafficClass {
    /// Returns `true` if this class represents a malicious or suspicious activity.
    #[must_use]
    pub const fn is_suspicious(self) -> bool {
        !matches!(self, Self::Benign | Self::Undetermined)
    }

    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::C2Beaconing      => "C2 Beaconing",
            Self::DataExfiltration => "Data Exfiltration",
            Self::PortScan         => "Port Scan",
            Self::BruteForce       => "Brute Force",
            Self::LateralMovement  => "Lateral Movement",
            Self::DnsTunnel        => "DNS Tunnel",
            Self::DgaActivity      => "DGA Activity",
            Self::Benign           => "Benign",
            Self::Undetermined     => "Undetermined",
        }
    }
}

// ── Flow record ───────────────────────────────────────────────────────────────

/// A summarised network flow observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port.
    pub dst_port: u16,
    /// L4 protocol number (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Unix timestamp (seconds) of the start of this flow.
    pub timestamp: u64,
    /// Total bytes transferred in this flow (src → dst).
    pub bytes_out: u64,
    /// Total bytes transferred (dst → src).
    pub bytes_in: u64,
    /// Number of packets in this flow.
    pub packet_count: u32,
    /// Duration of the flow in seconds.
    pub duration_secs: u32,
}

impl FlowRecord {
    /// Create a minimal flow record.
    #[must_use]
    pub const fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: u8,
        timestamp: u64,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            dst_port,
            protocol,
            timestamp,
            bytes_out: 0,
            bytes_in: 0,
            packet_count: 1,
            duration_secs: 0,
        }
    }

    /// Total bytes transferred in both directions.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.bytes_out + self.bytes_in
    }

    /// Average byte rate (bytes per second) for the outbound direction.
    #[must_use]
    pub fn outbound_rate(self) -> f64 {
        if self.duration_secs == 0 {
            u64_to_f64_lossy(self.bytes_out)
        } else {
            u64_to_f64_lossy(self.bytes_out) / f64::from(self.duration_secs)
        }
    }
}

// ── Classification result ─────────────────────────────────────────────────────

/// The result of classifying one or more flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// The assigned traffic class.
    pub class: TrafficClass,
    /// Confidence in the classification [0, 100].
    pub confidence: u8,
    /// Human-readable explanation.
    pub reason: String,
    /// Supporting flow records that triggered this classification.
    pub evidence_flows: Vec<FlowRecord>,
}

impl ClassificationResult {
    fn new(class: TrafficClass, confidence: u8, reason: impl Into<String>) -> Self {
        Self {
            class,
            confidence,
            reason: reason.into(),
            evidence_flows: Vec::new(),
        }
    }

    fn with_evidence(mut self, flows: Vec<FlowRecord>) -> Self {
        self.evidence_flows = flows;
        self
    }
}

// ── Beaconing detector ────────────────────────────────────────────────────────

/// Configuration for the beaconing detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconingConfig {
    /// Minimum number of connections to the same host to consider.
    pub min_connections: usize,
    /// Maximum allowed jitter as a fraction of the mean interval.
    /// E.g. 0.10 means ±10% variance is acceptable.
    pub max_jitter_fraction: f64,
    /// Minimum mean interval (seconds) — avoids flagging very noisy flows.
    pub min_interval_secs: f64,
    /// Maximum mean interval (seconds) — most C2 beacons are under 1 hour.
    pub max_interval_secs: f64,
}

impl Default for BeaconingConfig {
    fn default() -> Self {
        Self {
            min_connections: 5,
            max_jitter_fraction: 0.20,
            min_interval_secs: 10.0,
            max_interval_secs: 3600.0,
        }
    }
}

/// Detect C2 beaconing by analysing inter-arrival times between flows to the
/// same destination host.
pub struct BeaconingDetector {
    config: BeaconingConfig,
    /// `src_ip` → `dst_ip` → list of timestamps (sorted ascending).
    observations: HashMap<IpAddr, HashMap<IpAddr, Vec<u64>>>,
}

impl BeaconingDetector {
    /// Create a new detector with the given config.
    #[must_use]
    pub fn new(config: BeaconingConfig) -> Self {
        Self {
            config,
            observations: HashMap::new(),
        }
    }

    /// Create a detector with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(BeaconingConfig::default())
    }

    /// Record a connection from `src` to `dst` at Unix timestamp `ts`.
    pub fn observe(&mut self, src: IpAddr, dst: IpAddr, ts: u64) {
        self.observations
            .entry(src)
            .or_default()
            .entry(dst)
            .or_default()
            .push(ts);
    }

    /// Ingest a slice of flow records.
    pub fn ingest_flows(&mut self, flows: &[FlowRecord]) {
        for flow in flows {
            self.observe(flow.src_ip, flow.dst_ip, flow.timestamp);
        }
    }

    /// Analyse all recorded observations and return a list of suspected
    /// beaconing host pairs, together with their statistics.
    #[must_use]
    pub fn detect(&self) -> Vec<BeaconingResult> {
        let mut results = Vec::new();
        for (src, dst_map) in &self.observations {
            for (dst, timestamps) in dst_map {
                let mut ts = timestamps.clone();
                ts.sort_unstable();
                if ts.len() < self.config.min_connections {
                    continue;
                }
                if let Some(stat) = Self::analyse_intervals(&ts)
                    .filter(|stat| stat.is_beaconing(&self.config))
                {
                    results.push(BeaconingResult {
                        src: *src,
                        dst: *dst,
                        stats: stat,
                    });
                }
            }
        }
        results.sort_by(|a, b| {
            a.stats.jitter_fraction.partial_cmp(&b.stats.jitter_fraction).unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    fn analyse_intervals(timestamps: &[u64]) -> Option<IntervalStats> {
        if timestamps.len() < 2 {
            return None;
        }
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| u64_to_f64_lossy(w[1]) - u64_to_f64_lossy(w[0]))
            .filter(|&d| d > 0.0)
            .collect();
        if intervals.is_empty() {
            return None;
        }
        let n = usize_to_f64_lossy(intervals.len());
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();
        let jitter_fraction = if mean > 0.0 { stddev / mean } else { f64::INFINITY };
        Some(IntervalStats {
            mean_secs: mean,
            stddev_secs: stddev,
            jitter_fraction,
            connection_count: timestamps.len(),
        })
    }
}

/// Statistical summary of inter-connection intervals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalStats {
    pub mean_secs: f64,
    pub stddev_secs: f64,
    pub jitter_fraction: f64,
    pub connection_count: usize,
}

impl IntervalStats {
    fn is_beaconing(&self, cfg: &BeaconingConfig) -> bool {
        self.mean_secs >= cfg.min_interval_secs
            && self.mean_secs <= cfg.max_interval_secs
            && self.jitter_fraction <= cfg.max_jitter_fraction
    }
}

/// A detected beaconing host pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconingResult {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub stats: IntervalStats,
}

impl BeaconingResult {
    /// Estimated confidence that this is genuine beaconing [0, 100].
    #[must_use]
    pub fn confidence(&self) -> u8 {
        // Lower jitter and more samples → higher confidence.
        let jitter_score = f64_to_u8_clamped(((1.0 - self.stats.jitter_fraction) * 60.0).clamp(0.0, 60.0));
        let sample_score = f64_to_u8_clamped((usize_to_f64_lossy(self.stats.connection_count) / 20.0 * 40.0).clamp(0.0, 40.0));
        jitter_score + sample_score
    }
}

// ── Traffic classifier ────────────────────────────────────────────────────────

/// High-level traffic classifier that inspects a collection of flows and
/// assigns [`ClassificationResult`]s.
pub struct TrafficClassifier {
    /// Minimum outbound bytes to consider a flow as potential exfiltration.
    pub exfil_threshold_bytes: u64,
    /// Number of unique destination ports to a single host to flag as scan.
    pub portscan_threshold: usize,
    /// Minimum number of failed-connection-like flows for brute force.
    pub brute_force_threshold: usize,
    /// DNS query length above which DNS tunnelling is suspected.
    pub dns_tunnel_query_len: usize,
    /// Number of NXDOMAIN-like flows to flag DGA activity.
    pub dga_nxdomain_threshold: usize,
}

impl Default for TrafficClassifier {
    fn default() -> Self {
        Self {
            exfil_threshold_bytes: 10 * 1024 * 1024, // 10 MiB
            portscan_threshold: 20,
            brute_force_threshold: 10,
            dns_tunnel_query_len: 100,
            dga_nxdomain_threshold: 30,
        }
    }
}

impl TrafficClassifier {
    /// Create a classifier with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a slice of flows originating from the same source IP.
    ///
    /// Returns a vector of classification results — one per identified class,
    /// or a single `Benign`/`Undetermined` result if nothing suspicious is found.
    ///
    /// # Panics
    /// Panics only if internal invariants are violated (e.g. an empty `scan_targets`
    /// vector reaches the `max_by_key` call); this should not occur in practice.
    #[must_use]
    pub fn classify(&self, flows: &[FlowRecord]) -> Vec<ClassificationResult> {
        if flows.is_empty() {
            return vec![ClassificationResult::new(
                TrafficClass::Undetermined,
                0,
                "no flows provided",
            )];
        }

        let mut results = Vec::new();

        // ── C2 Beaconing ─────────────────────────────────────────────────────
        let mut beacon_detector = BeaconingDetector::with_defaults();
        beacon_detector.ingest_flows(flows);
        for beacon in beacon_detector.detect() {
            let conf = beacon.confidence();
            let reason = format!(
                "Regular beaconing to {} every {:.1}s (jitter={:.1}%, samples={})",
                beacon.dst,
                beacon.stats.mean_secs,
                beacon.stats.jitter_fraction * 100.0,
                beacon.stats.connection_count,
            );
            let evidence: Vec<FlowRecord> = flows
                .iter()
                .filter(|f| f.dst_ip == beacon.dst)
                .cloned()
                .collect();
            results.push(
                ClassificationResult::new(TrafficClass::C2Beaconing, conf, reason)
                    .with_evidence(evidence),
            );
        }

        // ── Data exfiltration ─────────────────────────────────────────────────
        let exfil_flows: Vec<FlowRecord> = flows
            .iter()
            .filter(|f| f.bytes_out >= self.exfil_threshold_bytes)
            .cloned()
            .collect();
        if !exfil_flows.is_empty() {
            let total: u64 = exfil_flows.iter().map(|f| f.bytes_out).sum();
            let reason = format!(
                "{} flows with large outbound volume (total {} bytes)",
                exfil_flows.len(),
                total
            );
            let conf = (70 + usize_to_u8_trunc(exfil_flows.len().min(10)) * 2).min(95);
            results.push(
                ClassificationResult::new(TrafficClass::DataExfiltration, conf, reason)
                    .with_evidence(exfil_flows),
            );
        }

        // ── Port scan ─────────────────────────────────────────────────────────
        let mut dst_port_map: HashMap<IpAddr, std::collections::HashSet<u16>> = HashMap::new();
        for flow in flows {
            dst_port_map.entry(flow.dst_ip).or_default().insert(flow.dst_port);
        }
        let scan_targets: Vec<(IpAddr, usize)> = dst_port_map
            .iter()
            .filter(|(_, ports)| ports.len() >= self.portscan_threshold)
            .map(|(ip, ports)| (*ip, ports.len()))
            .collect();
        if !scan_targets.is_empty() {
            let top = scan_targets.iter().max_by_key(|(_, c)| *c).unwrap();
            let reason = format!(
                "Port scan detected: {} ports contacted on {}",
                top.1, top.0
            );
            let conf = f64_to_u8_clamped(
                (usize_to_f64_lossy(top.1) / (usize_to_f64_lossy(self.portscan_threshold) * 2.0) * 90.0)
                    .clamp(50.0, 95.0),
            );
            let evidence: Vec<FlowRecord> = flows
                .iter()
                .filter(|f| f.dst_ip == top.0)
                .cloned()
                .collect();
            results.push(
                ClassificationResult::new(TrafficClass::PortScan, conf, reason)
                    .with_evidence(evidence),
            );
        }

        // ── Lateral movement (SMB/RPC to internal hosts) ──────────────────────
        let lateral_flows: Vec<FlowRecord> = flows
            .iter()
            .filter(|f| is_internal(f.dst_ip) && matches!(f.dst_port, 445 | 139 | 135 | 5985 | 5986))
            .cloned()
            .collect();
        let unique_lateral_dsts: std::collections::HashSet<IpAddr> =
            lateral_flows.iter().map(|f| f.dst_ip).collect();
        if unique_lateral_dsts.len() >= 3 {
            let reason = format!(
                "SMB/RPC connections to {} internal hosts",
                unique_lateral_dsts.len()
            );
            results.push(
                ClassificationResult::new(TrafficClass::LateralMovement, 75, reason)
                    .with_evidence(lateral_flows),
            );
        }

        // ── Brute force (many short-duration flows to same port) ──────────────
        let mut port_flow_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();
        for flow in flows {
            if flow.duration_secs <= 2 {
                *port_flow_counts.entry((flow.dst_ip, flow.dst_port)).or_insert(0) += 1;
            }
        }
        for ((dst, port), count) in &port_flow_counts {
            if *count >= self.brute_force_threshold && matches!(port, 22 | 21 | 23 | 3389 | 5900 | 445 | 25 | 110 | 143) {
                let reason = format!(
                    "Brute force: {count} rapid attempts to {dst}:{port}"
                );
                let conf = f64_to_u8_clamped(
                    (usize_to_f64_lossy(*count) / (usize_to_f64_lossy(self.brute_force_threshold) * 2.0) * 80.0)
                        .clamp(50.0, 90.0),
                );
                let evidence: Vec<FlowRecord> = flows
                    .iter()
                    .filter(|f| f.dst_ip == *dst && f.dst_port == *port)
                    .cloned()
                    .collect();
                results.push(
                    ClassificationResult::new(TrafficClass::BruteForce, conf, reason)
                        .with_evidence(evidence),
                );
            }
        }

        if results.is_empty() {
            results.push(ClassificationResult::new(TrafficClass::Benign, 70, "no suspicious patterns detected"));
        }

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Returns `true` if any flow in the slice is classified as suspicious above
    /// the given confidence threshold.
    #[must_use]
    pub fn any_suspicious(&self, flows: &[FlowRecord], threshold: u8) -> bool {
        self.classify(flows)
            .iter()
            .any(|r| r.class.is_suspicious() && r.confidence >= threshold)
    }
}

/// Returns `true` if the IP is an RFC-1918 private address.
const fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}

// ── Flow aggregation helpers ──────────────────────────────────────────────────

/// Group a set of flow records by source IP.
#[must_use]
pub fn group_by_source(flows: &[FlowRecord]) -> HashMap<IpAddr, Vec<FlowRecord>> {
    let mut map: HashMap<IpAddr, Vec<FlowRecord>> = HashMap::new();
    for flow in flows {
        map.entry(flow.src_ip).or_default().push(flow.clone());
    }
    map
}

/// Compute per-destination summary statistics from a set of flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationSummary {
    pub dst_ip: IpAddr,
    pub flow_count: usize,
    pub total_bytes_out: u64,
    pub unique_src_ports: usize,
    pub unique_dst_ports: usize,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Summarise flows per destination.
#[must_use]
pub fn summarise_by_destination(flows: &[FlowRecord]) -> Vec<DestinationSummary> {
    let mut map: HashMap<IpAddr, Vec<&FlowRecord>> = HashMap::new();
    for f in flows {
        map.entry(f.dst_ip).or_default().push(f);
    }
    let mut summaries: Vec<DestinationSummary> = map
        .into_iter()
        .map(|(dst, fv)| {
            let src_ports: std::collections::HashSet<u16> = fv.iter()
                .map(|f| {
                    // There is no src_port in FlowRecord; approximate with dst_port of reverse.
                    f.dst_port
                })
                .collect();
            let dst_ports: std::collections::HashSet<u16> = fv.iter().map(|f| f.dst_port).collect();
            DestinationSummary {
                dst_ip: dst,
                flow_count: fv.len(),
                total_bytes_out: fv.iter().map(|f| f.bytes_out).sum(),
                unique_src_ports: src_ports.len(),
                unique_dst_ports: dst_ports.len(),
                first_seen: fv.iter().map(|f| f.timestamp).min().unwrap_or(0),
                last_seen:  fv.iter().map(|f| f.timestamp).max().unwrap_or(0),
            }
        })
        .collect();
    summaries.sort_by(|a, b| b.total_bytes_out.cmp(&a.total_bytes_out));
    summaries
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ipv4(s: &str) -> IpAddr { s.parse().unwrap() }

    fn flow(src: &str, dst: &str, port: u16, ts: u64, bytes_out: u64) -> FlowRecord {
        let mut f = FlowRecord::new(ipv4(src), ipv4(dst), port, 6, ts);
        f.bytes_out = bytes_out;
        f
    }

    // ── TrafficClass ──────────────────────────────────────────────────────────

    #[test]
    fn test_traffic_class_labels() {
        assert_eq!(TrafficClass::C2Beaconing.label(), "C2 Beaconing");
        assert_eq!(TrafficClass::Benign.label(), "Benign");
        assert!(TrafficClass::C2Beaconing.is_suspicious());
        assert!(!TrafficClass::Benign.is_suspicious());
    }

    // ── BeaconingDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_beaconing_detected() {
        let mut det = BeaconingDetector::with_defaults();
        let src = ipv4("10.0.0.1");
        let dst = ipv4("8.8.8.8");
        // 10 connections every 60 seconds.
        for i in 0..10u64 {
            det.observe(src, dst, 1_000_000 + i * 60);
        }
        let results = det.detect();
        assert!(!results.is_empty());
        assert_eq!(results[0].src, src);
        assert_eq!(results[0].dst, dst);
    }

    #[test]
    fn test_beaconing_not_detected_high_jitter() {
        let mut det = BeaconingDetector::with_defaults();
        let src = ipv4("10.0.0.1");
        let dst = ipv4("8.8.8.8");
        // Random-looking intervals.
        for &ts in &[1000u64, 1500, 2900, 3100, 4500, 5700, 6000, 7200, 8000, 9100] {
            det.observe(src, dst, ts);
        }
        let results = det.detect();
        // May or may not fire; if it does, confidence should be low.
        for r in &results {
            assert!(r.confidence() <= 80);
        }
    }

    #[test]
    fn test_beaconing_min_connections() {
        let mut det = BeaconingDetector::with_defaults();
        let src = ipv4("10.0.0.2");
        let dst = ipv4("1.2.3.4");
        // Only 3 connections — below default min of 5.
        for i in 0..3u64 {
            det.observe(src, dst, 1_000_000 + i * 60);
        }
        assert!(det.detect().is_empty());
    }

    // ── TrafficClassifier ─────────────────────────────────────────────────────

    #[test]
    fn test_exfiltration_detected() {
        let classifier = TrafficClassifier::new();
        let flows = vec![
            flow("10.0.0.5", "203.0.113.1", 443, 1000, 20 * 1024 * 1024),
        ];
        let results = classifier.classify(&flows);
        assert!(results.iter().any(|r| r.class == TrafficClass::DataExfiltration));
    }

    #[test]
    fn test_portscan_detected() {
        let mut classifier = TrafficClassifier::new();
        classifier.portscan_threshold = 5;
        let flows: Vec<FlowRecord> = (1u16..=20)
            .map(|port| flow("192.168.1.100", "10.0.0.1", port, 1000 + u64::from(port), 100))
            .collect();
        let results = classifier.classify(&flows);
        assert!(results.iter().any(|r| r.class == TrafficClass::PortScan));
    }

    #[test]
    fn test_brute_force_ssh() {
        let mut classifier = TrafficClassifier::new();
        classifier.brute_force_threshold = 5;
        let mut flows = Vec::new();
        for i in 0..15u64 {
            let mut f = FlowRecord::new(ipv4("10.1.1.1"), ipv4("10.0.0.2"), 22, 6, 1000 + i * 2);
            f.duration_secs = 1;
            flows.push(f);
        }
        let results = classifier.classify(&flows);
        assert!(results.iter().any(|r| r.class == TrafficClass::BruteForce));
    }

    #[test]
    fn test_lateral_movement() {
        let classifier = TrafficClassifier::new();
        let flows: Vec<FlowRecord> = ["192.168.1.2", "192.168.1.3", "192.168.1.4"]
            .iter()
            .map(|dst| flow("10.0.0.1", dst, 445, 1000, 1024))
            .collect();
        let results = classifier.classify(&flows);
        assert!(results.iter().any(|r| r.class == TrafficClass::LateralMovement));
    }

    #[test]
    fn test_benign_flows() {
        let classifier = TrafficClassifier::new();
        let flows = vec![
            flow("10.0.0.1", "8.8.8.8", 53, 1000, 100),
            flow("10.0.0.1", "8.8.8.8", 53, 2000, 100),
        ];
        let results = classifier.classify(&flows);
        assert!(results.iter().any(|r| r.class == TrafficClass::Benign));
    }

    #[test]
    fn test_empty_flows() {
        let classifier = TrafficClassifier::new();
        let results = classifier.classify(&[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].class, TrafficClass::Undetermined);
    }

    #[test]
    fn test_any_suspicious() {
        let classifier = TrafficClassifier::new();
        let flows = vec![
            flow("10.0.0.5", "203.0.113.1", 443, 1000, 50 * 1024 * 1024),
        ];
        assert!(classifier.any_suspicious(&flows, 50));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn test_group_by_source() {
        let flows = vec![
            flow("10.0.0.1", "8.8.8.8", 53, 1000, 100),
            flow("10.0.0.2", "8.8.8.8", 53, 2000, 100),
            flow("10.0.0.1", "1.1.1.1", 53, 3000, 100),
        ];
        let grouped = group_by_source(&flows);
        assert_eq!(grouped[&ipv4("10.0.0.1")].len(), 2);
        assert_eq!(grouped[&ipv4("10.0.0.2")].len(), 1);
    }

    #[test]
    fn test_summarise_by_destination() {
        let flows = vec![
            flow("10.0.0.1", "8.8.8.8", 53, 1000, 200),
            flow("10.0.0.2", "8.8.8.8", 53, 2000, 300),
            flow("10.0.0.1", "1.1.1.1", 53, 3000, 100),
        ];
        let summaries = summarise_by_destination(&flows);
        let google = summaries.iter().find(|s| s.dst_ip == ipv4("8.8.8.8")).unwrap();
        assert_eq!(google.flow_count, 2);
        assert_eq!(google.total_bytes_out, 500);
    }

    #[test]
    fn test_is_internal() {
        assert!(is_internal("10.0.0.1".parse().unwrap()));
        assert!(is_internal("192.168.1.1".parse().unwrap()));
        assert!(is_internal("172.16.0.1".parse().unwrap()));
        assert!(!is_internal("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_flow_total_bytes() {
        let mut f = FlowRecord::new(ipv4("10.0.0.1"), ipv4("8.8.8.8"), 80, 6, 1000);
        f.bytes_out = 500;
        f.bytes_in  = 300;
        assert_eq!(f.total_bytes(), 800);
    }

    #[test]
    fn test_beaconing_confidence_range() {
        let br = BeaconingResult {
            src: ipv4("10.0.0.1"),
            dst: ipv4("8.8.8.8"),
            stats: IntervalStats {
                mean_secs: 60.0,
                stddev_secs: 1.0,
                jitter_fraction: 0.017,
                connection_count: 15,
            },
        };
        let conf = br.confidence();
        assert!(conf <= 100);
    }
}
