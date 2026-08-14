//! Network activity timeline for sandbox reports.
//!
//! Provides [`NetworkEvent`], [`NetworkTimeline`], [`ConnectionMap`],
//! [`DnsResolution`], and Chart.js-compatible JSON data generation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("empty timeline")]
    EmptyTimeline,
}

// ── Protocol ──────────────────────────────────────────────────────────────────

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Dns,
    Http,
    Https,
    Smtp,
    Ftp,
    Unknown,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Smtp => "SMTP",
            Self::Ftp => "FTP",
            Self::Unknown => "?",
        }
    }

    /// Infer from port number.
    #[must_use]
    pub const fn from_port(port: u16) -> Self {
        match port {
            53 => Self::Dns,
            80 => Self::Http,
            443 => Self::Https,
            25 | 465 | 587 => Self::Smtp,
            21 => Self::Ftp,
            _ => Self::Tcp,
        }
    }
}

// ── NetworkDirection ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Outbound,
    Inbound,
    Unknown,
}

// ── NetworkEvent ──────────────────────────────────────────────────────────────

/// A single network event recorded during a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Milliseconds from sandbox start.
    pub timestamp_ms: u64,
    /// Source IP address (string form to avoid IPv4/IPv6 enum complexity).
    pub src_ip: String,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port (0 for ICMP / DNS).
    pub dst_port: u16,
    /// Source port (0 if unknown).
    pub src_port: u16,
    /// Protocol.
    pub protocol: Protocol,
    /// DNS query name (if this is a DNS event).
    pub dns_query: Option<String>,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_recv: u64,
    /// Direction.
    pub direction: Direction,
    /// Associated process ID.
    pub pid: Option<u32>,
}

impl NetworkEvent {
    /// Create a new outbound TCP event.
    pub fn tcp(
        timestamp_ms: u64,
        src_ip: impl Into<String>,
        dst_ip: impl Into<String>,
        dst_port: u16,
    ) -> Self {
        let proto = Protocol::from_port(dst_port);
        Self {
            timestamp_ms,
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            dst_port,
            src_port: 0,
            protocol: proto,
            dns_query: None,
            bytes_sent: 0,
            bytes_recv: 0,
            direction: Direction::Outbound,
            pid: None,
        }
    }

    /// Create a DNS query event.
    pub fn dns(timestamp_ms: u64, src_ip: impl Into<String>, query: impl Into<String>) -> Self {
        Self {
            timestamp_ms,
            src_ip: src_ip.into(),
            dst_ip: "8.8.8.8".into(),
            dst_port: 53,
            src_port: 0,
            protocol: Protocol::Dns,
            dns_query: Some(query.into()),
            bytes_sent: 0,
            bytes_recv: 0,
            direction: Direction::Outbound,
            pid: None,
        }
    }

    /// Return `true` if this is a DNS query event.
    #[must_use]
    pub fn is_dns(&self) -> bool {
        self.protocol == Protocol::Dns || self.dns_query.is_some()
    }

    /// Return `true` if this is an HTTPS connection.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.protocol == Protocol::Https || self.dst_port == 443
    }

    /// Return total bytes transferred.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_recv
    }
}

// ── NetworkTimeline ────────────────────────────────────────────────────────────

/// A sorted sequence of network events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkTimeline {
    events: Vec<NetworkEvent>,
}

impl NetworkTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Add an event, keeping the timeline sorted by timestamp.
    pub fn add(&mut self, event: NetworkEvent) {
        let pos = self
            .events
            .partition_point(|e| e.timestamp_ms <= event.timestamp_ms);
        self.events.insert(pos, event);
    }

    /// Add multiple events.
    pub fn extend(&mut self, events: impl IntoIterator<Item = NetworkEvent>) {
        for e in events {
            self.add(e);
        }
    }

    /// Return all events.
    #[must_use]
    pub fn events(&self) -> &[NetworkEvent] {
        &self.events
    }

    /// Return the number of events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if the timeline has no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Return all DNS events.
    #[must_use]
    pub fn dns_events(&self) -> Vec<&NetworkEvent> {
        self.events.iter().filter(|e| e.is_dns()).collect()
    }

    /// Return all HTTPS events.
    #[must_use]
    pub fn https_events(&self) -> Vec<&NetworkEvent> {
        self.events.iter().filter(|e| e.is_https()).collect()
    }

    /// Return events in a time window `[start_ms, end_ms]`.
    #[must_use]
    pub fn in_window(&self, start_ms: u64, end_ms: u64) -> Vec<&NetworkEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp_ms >= start_ms && e.timestamp_ms <= end_ms)
            .collect()
    }

    /// Return all unique destination IPs.
    #[must_use]
    pub fn unique_dst_ips(&self) -> Vec<&str> {
        let mut ips: Vec<&str> = self.events.iter().map(|e| e.dst_ip.as_str()).collect();
        ips.sort_unstable();
        ips.dedup();
        ips
    }

    /// Return total bytes transferred across all events.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.events.iter().map(NetworkEvent::total_bytes).sum()
    }

    /// Return events grouped by protocol.
    #[must_use]
    pub fn by_protocol(&self) -> HashMap<String, Vec<&NetworkEvent>> {
        let mut map: HashMap<String, Vec<&NetworkEvent>> = HashMap::new();
        for e in &self.events {
            map.entry(e.protocol.as_str().to_owned())
                .or_default()
                .push(e);
        }
        map
    }

    /// Build the [`ConnectionMap`] from this timeline.
    #[must_use]
    pub fn connection_map(&self) -> ConnectionMap {
        ConnectionMap::from_timeline(self)
    }

    /// Build the [`DnsResolution`] map from this timeline.
    #[must_use]
    pub fn dns_map(&self) -> DnsResolutionMap {
        DnsResolutionMap::from_timeline(self)
    }

    /// Generate Chart.js-compatible JSON data for a timeline chart.
    ///
    /// Returns a JSON object with `labels` (timestamps in seconds) and
    /// `datasets` (bytes per second buckets).
    #[must_use]
    pub fn chart_data_json(&self, bucket_ms: u64) -> String {
        const MAX_BUCKETS: usize = 100_000;

        if self.events.is_empty() {
            return r#"{"labels":[],"datasets":[]}"#.to_owned();
        }

        // Guard against division-by-zero and absurdly large allocations.
        let bucket_ms = if bucket_ms == 0 { 1 } else { bucket_ms };
        let max_ts = self.events.last().map_or(0, |e| e.timestamp_ms);
        let n_buckets = usize::try_from(max_ts / bucket_ms)
            .unwrap_or(MAX_BUCKETS)
            .saturating_add(1)
            .min(MAX_BUCKETS);

        let mut send_buckets = vec![0u64; n_buckets];
        let mut recv_buckets = vec![0u64; n_buckets];

        for ev in &self.events {
            let idx = usize::try_from(ev.timestamp_ms / bucket_ms).unwrap_or(usize::MAX);
            if idx < n_buckets {
                send_buckets[idx] += ev.bytes_sent;
                recv_buckets[idx] += ev.bytes_recv;
            }
        }

        // Compute `(i * bucket_ms) / 1000.0` without `as f64` precision-loss
        // casts: integer-divide for the seconds part, mod for the millisecond
        // remainder, then assemble a one-decimal label.  This is sufficient
        // for the chart display which only shows one fractional digit.
        let bucket_ms_u32 = u32::try_from(bucket_ms).unwrap_or(u32::MAX);
        let labels: Vec<String> = (0..n_buckets)
            .map(|i| {
                let i_u128 = u128::try_from(i).unwrap_or(u128::MAX);
                let total_ms = i_u128.saturating_mul(u128::from(bucket_ms_u32));
                let secs = total_ms / 1000;
                // Tenths-of-a-second precision: divide ms remainder by 100.
                let tenths = (total_ms % 1000) / 100;
                format!("{secs}.{tenths}")
            })
            .collect();

        let send_data: Vec<String> = send_buckets
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let recv_data: Vec<String> = recv_buckets
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        format!(
            r#"{{"labels":[{}],"datasets":[{{"label":"Bytes Sent","data":[{}]}},{{"label":"Bytes Received","data":[{}]}}]}}"#,
            labels
                .iter()
                .map(|l| format!("\"{l}\""))
                .collect::<Vec<_>>()
                .join(","),
            send_data.join(","),
            recv_data.join(","),
        )
    }
}

// ── ConnectionMap ─────────────────────────────────────────────────────────────

/// A (`dst_ip`, `dst_port`) → event list map for deduplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMap {
    pub connections: HashMap<String, Vec<u64>>, // key = "ip:port", values = timestamps
}

impl ConnectionMap {
    /// Build from a timeline.
    #[must_use]
    pub fn from_timeline(timeline: &NetworkTimeline) -> Self {
        let mut map: HashMap<String, Vec<u64>> = HashMap::new();
        for ev in timeline.events() {
            let key = format!("{}:{}", ev.dst_ip, ev.dst_port);
            map.entry(key).or_default().push(ev.timestamp_ms);
        }
        Self { connections: map }
    }

    /// Return all unique (`dst_ip`, `dst_port`) pairs.
    #[must_use]
    pub fn unique_endpoints(&self) -> Vec<&str> {
        self.connections
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Total number of unique connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// `true` if no connections were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Return all endpoints contacted on a specific port.
    #[must_use]
    pub fn on_port(&self, port: u16) -> Vec<&str> {
        let suffix = format!(":{port}");
        self.connections
            .keys()
            .filter(|k| k.ends_with(&suffix))
            .map(std::string::String::as_str)
            .collect()
    }

    /// Return how many times an endpoint was contacted.
    #[must_use]
    pub fn contact_count(&self, endpoint: &str) -> usize {
        self.connections.get(endpoint).map_or(0, std::vec::Vec::len)
    }
}

// ── DnsResolutionMap ──────────────────────────────────────────────────────────

/// A map of DNS query names to their response IPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolutionMap {
    /// query → list of resolved IPs.
    pub resolutions: HashMap<String, Vec<String>>,
}

impl DnsResolutionMap {
    /// Build from a timeline (DNS events only).
    #[must_use]
    pub fn from_timeline(timeline: &NetworkTimeline) -> Self {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for ev in timeline.dns_events() {
            if let Some(ref query) = ev.dns_query {
                // Use dst_ip as the "resolved IP" (in a real sandbox this would be the response).
                let entry = map.entry(query.clone()).or_default();
                if !entry.contains(&ev.dst_ip) {
                    entry.push(ev.dst_ip.clone());
                }
            }
        }
        Self { resolutions: map }
    }

    /// Return all queried domain names.
    #[must_use]
    pub fn domains(&self) -> Vec<&str> {
        self.resolutions
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Return `true` if a domain was queried.
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        self.resolutions.contains_key(domain)
    }

    /// Total number of unique DNS queries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resolutions.len()
    }

    /// `true` if no DNS queries were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resolutions.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_timeline() -> NetworkTimeline {
        let mut t = NetworkTimeline::new();
        t.add(NetworkEvent::tcp(1000, "192.168.1.1", "185.220.101.1", 443));
        t.add(NetworkEvent::tcp(2000, "192.168.1.1", "10.0.0.1", 80));
        t.add(NetworkEvent::dns(500, "192.168.1.1", "evil.c2.com"));
        t
    }

    #[test]
    fn test_timeline_sorted_by_timestamp() {
        let t = make_timeline();
        let ts: Vec<u64> = t.events().iter().map(|e| e.timestamp_ms).collect();
        let mut sorted = ts.clone();
        sorted.sort_unstable();
        assert_eq!(ts, sorted);
    }

    #[test]
    fn test_timeline_len() {
        let t = make_timeline();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn test_timeline_empty() {
        let t = NetworkTimeline::new();
        assert!(t.is_empty());
    }

    #[test]
    fn test_dns_events() {
        let t = make_timeline();
        let dns = t.dns_events();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].dns_query.as_deref(), Some("evil.c2.com"));
    }

    #[test]
    fn test_https_events() {
        let t = make_timeline();
        let https = t.https_events();
        assert_eq!(https.len(), 1);
        assert_eq!(https[0].dst_port, 443);
    }

    #[test]
    fn test_in_window() {
        let t = make_timeline();
        let evts = t.in_window(900, 1500);
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].dst_port, 443);
    }

    #[test]
    fn test_unique_dst_ips() {
        let t = make_timeline();
        let ips = t.unique_dst_ips();
        assert_eq!(ips.len(), 3); // dns to 8.8.8.8 + two unique dst IPs
    }

    #[test]
    fn test_total_bytes() {
        let mut t = NetworkTimeline::new();
        let mut ev = NetworkEvent::tcp(0, "1.1.1.1", "2.2.2.2", 80);
        ev.bytes_sent = 100;
        ev.bytes_recv = 200;
        t.add(ev);
        assert_eq!(t.total_bytes(), 300);
    }

    #[test]
    fn test_connection_map_from_timeline() {
        let t = make_timeline();
        let cm = t.connection_map();
        assert!(!cm.is_empty());
    }

    #[test]
    fn test_connection_map_on_port() {
        let t = make_timeline();
        let cm = t.connection_map();
        let https = cm.on_port(443);
        assert!(!https.is_empty());
    }

    #[test]
    fn test_dns_map() {
        let t = make_timeline();
        let dns_map = t.dns_map();
        assert!(dns_map.contains("evil.c2.com"));
    }

    #[test]
    fn test_dns_map_empty() {
        let t = NetworkTimeline::new();
        let dns_map = t.dns_map();
        assert!(dns_map.is_empty());
    }

    #[test]
    fn test_network_event_tcp_fields() {
        let ev = NetworkEvent::tcp(100, "192.0.2.1", "10.0.0.1", 443);
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.protocol, Protocol::Https);
        assert!(ev.is_https());
    }

    #[test]
    fn test_network_event_dns_fields() {
        let ev = NetworkEvent::dns(50, "192.0.2.1", "example.com");
        assert!(ev.is_dns());
        assert_eq!(ev.protocol, Protocol::Dns);
        assert_eq!(ev.dns_query.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_protocol_from_port() {
        assert_eq!(Protocol::from_port(80), Protocol::Http);
        assert_eq!(Protocol::from_port(443), Protocol::Https);
        assert_eq!(Protocol::from_port(53), Protocol::Dns);
        assert_eq!(Protocol::from_port(25), Protocol::Smtp);
    }

    #[test]
    fn test_chart_data_json_empty() {
        let t = NetworkTimeline::new();
        let json = t.chart_data_json(1000);
        assert!(json.contains("labels"));
    }

    #[test]
    fn test_chart_data_json_nonempty() {
        let mut t = NetworkTimeline::new();
        let mut ev = NetworkEvent::tcp(0, "1.1.1.1", "2.2.2.2", 80);
        ev.bytes_sent = 500;
        t.add(ev);
        let json = t.chart_data_json(1000);
        assert!(json.contains("Bytes Sent"));
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Https.as_str(), "HTTPS");
        assert_eq!(Protocol::Dns.as_str(), "DNS");
        assert_eq!(Protocol::Unknown.as_str(), "?");
    }

    #[test]
    fn test_by_protocol_grouping() {
        let t = make_timeline();
        let groups = t.by_protocol();
        assert!(
            groups.contains_key("DNS")
                || groups.contains_key("HTTPS")
                || groups.contains_key("HTTP")
        );
    }

    #[test]
    fn test_connection_map_contact_count() {
        let mut t = NetworkTimeline::new();
        t.add(NetworkEvent::tcp(100, "1.1.1.1", "8.8.8.8", 443));
        t.add(NetworkEvent::tcp(200, "1.1.1.1", "8.8.8.8", 443));
        let cm = t.connection_map();
        assert_eq!(cm.contact_count("8.8.8.8:443"), 2);
    }

    #[test]
    fn test_dns_map_domains() {
        let mut t = NetworkTimeline::new();
        t.add(NetworkEvent::dns(0, "1.1.1.1", "a.com"));
        t.add(NetworkEvent::dns(1, "1.1.1.1", "b.com"));
        let dns_map = t.dns_map();
        assert_eq!(dns_map.len(), 2);
    }

    #[test]
    fn test_network_event_total_bytes() {
        let mut ev = NetworkEvent::tcp(0, "a", "b", 80);
        ev.bytes_sent = 100;
        ev.bytes_recv = 50;
        assert_eq!(ev.total_bytes(), 150);
    }

    #[test]
    fn test_extend_timeline() {
        let mut t = NetworkTimeline::new();
        let events = vec![
            NetworkEvent::tcp(300, "1.1.1.1", "2.2.2.2", 80),
            NetworkEvent::tcp(100, "1.1.1.1", "3.3.3.3", 443),
        ];
        t.extend(events);
        assert_eq!(t.len(), 2);
        // Should be sorted
        assert_eq!(t.events()[0].timestamp_ms, 100);
    }
}
