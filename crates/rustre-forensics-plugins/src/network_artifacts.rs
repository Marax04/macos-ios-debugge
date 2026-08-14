//! `network_artifacts` — High-level network artifact aggregator.
//!
//! Provides [`NetworkArtifacts`] which orchestrates extraction of
//! [`TcpConnections`], [`UdpConnections`], [`DnsCache`], [`HttpCache`], and
//! produces a [`NetworkReport`].
//!
//! # Layer distinction
//! This module is the **high-level aggregator**: it stores typed connection
//! objects and produces structured reports.  The complementary low-level
//! scanner lives in [`crate::plugins::network_artifacts`] and deals with raw
//! binary formats (ARP records, DNS cache byte scanning, netstat diffing,
//! passive DNS reconstruction).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Map of remote endpoint -> aggregate byte-count, suitable for callers
/// building per-host network summaries on top of [`NetworkReport`].
pub type EndpointByteMap = HashMap<SocketAddr, u64>;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetArtifactError {
    #[error("read error at 0x{0:x}: {1}")]
    Read(u64, String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported architecture")]
    UnsupportedArch,
}

// ─── ConnectionState ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    Unknown(u32),
}

impl ConnectionState {
    #[must_use]
    pub const fn from_mib_state(s: u32) -> Self {
        match s {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Established | Self::Listen | Self::SynSent | Self::SynReceived
        )
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "Unknown({n})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ─── TcpEntry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpEntry {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: ConnectionState,
    pub pid: u32,
    pub process_name: Option<String>,
    pub create_time_ms: Option<u64>,
    pub kernel_obj: u64,
}

impl TcpEntry {
    #[must_use]
    pub const fn new(local: SocketAddr, remote: SocketAddr, state: ConnectionState, pid: u32) -> Self {
        Self {
            local_addr: local,
            remote_addr: remote,
            state,
            pid,
            process_name: None,
            create_time_ms: None,
            kernel_obj: 0,
        }
    }

    #[must_use]
    pub fn with_process(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    #[must_use]
    pub fn is_listening(&self) -> bool {
        self.state == ConnectionState::Listen
    }

    #[must_use]
    pub const fn is_outbound(&self) -> bool {
        self.local_addr.port() > 1024
    }

    #[must_use]
    pub const fn remote_ip(&self) -> IpAddr {
        self.remote_addr.ip()
    }

    #[must_use]
    pub const fn remote_port(&self) -> u16 {
        self.remote_addr.port()
    }
}

impl fmt::Display for TcpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {} → {} [{}] pid={}",
            self.local_addr, self.remote_addr, self.state, self.pid
        )
    }
}

// ─── TcpConnections ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TcpConnections {
    entries: Vec<TcpEntry>,
}

impl TcpConnections {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: TcpEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn all(&self) -> &[TcpEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn established(&self) -> Vec<&TcpEntry> {
        self.entries.iter().filter(|e| e.is_established()).collect()
    }

    #[must_use]
    pub fn listening(&self) -> Vec<&TcpEntry> {
        self.entries.iter().filter(|e| e.is_listening()).collect()
    }

    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Vec<&TcpEntry> {
        self.entries.iter().filter(|e| e.pid == pid).collect()
    }

    #[must_use]
    pub fn by_state(&self, state: ConnectionState) -> Vec<&TcpEntry> {
        self.entries.iter().filter(|e| e.state == state).collect()
    }

    #[must_use]
    pub fn unique_remote_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self
            .entries
            .iter()
            .map(TcpEntry::remote_ip)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ips.sort();
        ips
    }

    #[must_use]
    pub fn unique_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .entries
            .iter()
            .map(|e| e.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        pids.sort_unstable();
        pids
    }

    #[must_use]
    pub fn outbound_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_outbound()).count()
    }
}

// ─── UdpEntry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpEntry {
    pub local_addr: SocketAddr,
    pub pid: u32,
    pub process_name: Option<String>,
    pub kernel_obj: u64,
}

impl UdpEntry {
    #[must_use]
    pub const fn new(local: SocketAddr, pid: u32) -> Self {
        Self {
            local_addr: local,
            pid,
            process_name: None,
            kernel_obj: 0,
        }
    }

    #[must_use]
    pub fn with_process(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.local_addr.port()
    }
}

impl fmt::Display for UdpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP {} pid={}", self.local_addr, self.pid)
    }
}

// ─── UdpConnections ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct UdpConnections {
    entries: Vec<UdpEntry>,
}

impl UdpConnections {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: UdpEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn all(&self) -> &[UdpEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Vec<&UdpEntry> {
        self.entries.iter().filter(|e| e.pid == pid).collect()
    }

    #[must_use]
    pub fn listening_ports(&self) -> Vec<u16> {
        self.entries.iter().map(UdpEntry::local_port).collect()
    }

    #[must_use]
    pub fn unique_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .entries
            .iter()
            .map(|e| e.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        pids.sort_unstable();
        pids
    }
}

// ─── DnsRecordType ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Txt,
    Unknown(u16),
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "Unknown({n})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ─── DnsCacheEntry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub record_type: DnsRecordType,
    pub addresses: Vec<IpAddr>,
    pub ttl_secs: u32,
    pub flags: u32,
}

impl DnsCacheEntry {
    pub fn new(hostname: impl Into<String>, rtype: DnsRecordType) -> Self {
        Self {
            hostname: hostname.into(),
            record_type: rtype,
            addresses: Vec::new(),
            ttl_secs: 0,
            flags: 0,
        }
    }

    #[must_use]
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.addresses.push(ip);
        self
    }

    #[must_use]
    pub const fn has_expired(&self) -> bool {
        self.ttl_secs == 0
    }

    #[must_use]
    pub fn is_a_record(&self) -> bool {
        self.record_type == DnsRecordType::A
    }
}

// ─── DnsCache ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DnsCache {
    entries: Vec<DnsCacheEntry>,
}

impl DnsCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: DnsCacheEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn all(&self) -> &[DnsCacheEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn lookup(&self, hostname: &str) -> Option<&DnsCacheEntry> {
        self.entries.iter().find(|e| e.hostname == hostname)
    }

    #[must_use]
    pub fn a_records(&self) -> Vec<&DnsCacheEntry> {
        self.entries.iter().filter(|e| e.is_a_record()).collect()
    }

    #[must_use]
    pub fn for_ip(&self, ip: IpAddr) -> Vec<&DnsCacheEntry> {
        self.entries
            .iter()
            .filter(|e| e.addresses.contains(&ip))
            .collect()
    }

    #[must_use]
    pub fn unique_hostnames(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.hostname.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }
}

// ─── HttpCacheEntry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCacheEntry {
    pub url: String,
    pub method: String,
    pub host: String,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub timestamp_ms: Option<u64>,
    pub size_bytes: Option<u64>,
}

impl HttpCacheEntry {
    pub fn new(url: impl Into<String>, method: impl Into<String>) -> Self {
        let url = url.into();
        let host = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .to_owned();
        Self {
            url,
            method: method.into(),
            host,
            status_code: None,
            user_agent: None,
            content_type: None,
            timestamp_ms: None,
            size_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_status(mut self, code: u16) -> Self {
        self.status_code = Some(code);
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    #[must_use]
    pub fn is_post(&self) -> bool {
        self.method.eq_ignore_ascii_case("POST")
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET")
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status_code
            .is_some_and(|c| (200..300).contains(&c))
    }
}

impl fmt::Display for HttpCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.url)
    }
}

// ─── HttpCache ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct HttpCache {
    entries: Vec<HttpCacheEntry>,
}

impl HttpCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: HttpCacheEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn all(&self) -> &[HttpCacheEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn by_host(&self, host: &str) -> Vec<&HttpCacheEntry> {
        self.entries.iter().filter(|e| e.host == host).collect()
    }

    #[must_use]
    pub fn post_requests(&self) -> Vec<&HttpCacheEntry> {
        self.entries.iter().filter(|e| e.is_post()).collect()
    }

    #[must_use]
    pub fn unique_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.host.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        hosts.sort();
        hosts
    }

    #[must_use]
    pub fn suspicious_user_agents(&self) -> Vec<&HttpCacheEntry> {
        // Flag empty or very short user agents as suspicious
        self.entries
            .iter()
            .filter(|e| {
                e.user_agent
                    .as_ref()
                    .is_some_and(|ua| ua.len() < 5)
            })
            .collect()
    }
}

// ─── NetworkReport ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub tcp_total: usize,
    pub tcp_established: usize,
    pub tcp_listening: usize,
    pub tcp_outbound: usize,
    pub udp_total: usize,
    pub dns_total: usize,
    pub dns_unique_hosts: usize,
    pub http_total: usize,
    pub http_post_count: usize,
    pub unique_remote_ips: usize,
    pub suspicious_connections: Vec<String>,
    pub top_remote_ips: Vec<String>,
    pub summary: String,
}

impl NetworkReport {
    #[must_use]
    pub fn build(
        tcp: &TcpConnections,
        udp: &UdpConnections,
        dns: &DnsCache,
        http: &HttpCache,
    ) -> Self {
        let established = tcp.established().len();
        let listening = tcp.listening().len();
        let unique_ips = tcp.unique_remote_ips();
        let top_remote: Vec<String> = unique_ips.iter().take(5).map(ToString::to_string).collect();

        // Flag connections on unusual ports without known process
        let suspicious: Vec<String> = tcp
            .established()
            .iter()
            .filter(|e| e.process_name.is_none())
            .map(ToString::to_string)
            .collect();

        let summary = format!(
            "TCP: {} ({} established, {} listening) | UDP: {} | DNS: {} | HTTP: {} | IPs: {}",
            tcp.count(),
            established,
            listening,
            udp.count(),
            dns.count(),
            http.count(),
            unique_ips.len()
        );

        Self {
            tcp_total: tcp.count(),
            tcp_established: established,
            tcp_listening: listening,
            tcp_outbound: tcp.outbound_count(),
            udp_total: udp.count(),
            dns_total: dns.count(),
            dns_unique_hosts: dns.unique_hostnames().len(),
            http_total: http.count(),
            http_post_count: http.post_requests().len(),
            unique_remote_ips: unique_ips.len(),
            suspicious_connections: suspicious,
            top_remote_ips: top_remote,
            summary,
        }
    }

    #[must_use]
    pub const fn has_suspicious_activity(&self) -> bool {
        !self.suspicious_connections.is_empty()
    }
}

// ─── NetworkArtifacts ─────────────────────────────────────────────────────────

/// Top-level extractor aggregating all network artifacts from a memory image.
#[derive(Debug, Default)]
pub struct NetworkArtifacts {
    tcp: TcpConnections,
    udp: UdpConnections,
    dns: DnsCache,
    http: HttpCache,
}

impl NetworkArtifacts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Insertion ─────────────────────────────────────────────────────────

    pub fn add_tcp(&mut self, entry: TcpEntry) {
        self.tcp.add(entry);
    }

    pub fn add_udp(&mut self, entry: UdpEntry) {
        self.udp.add(entry);
    }

    pub fn add_dns(&mut self, entry: DnsCacheEntry) {
        self.dns.add(entry);
    }

    pub fn add_http(&mut self, entry: HttpCacheEntry) {
        self.http.add(entry);
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    #[must_use]
    pub const fn tcp(&self) -> &TcpConnections {
        &self.tcp
    }

    #[must_use]
    pub const fn udp(&self) -> &UdpConnections {
        &self.udp
    }

    #[must_use]
    pub const fn dns(&self) -> &DnsCache {
        &self.dns
    }

    #[must_use]
    pub const fn http(&self) -> &HttpCache {
        &self.http
    }

    // ── Analysis ──────────────────────────────────────────────────────────

    #[must_use]
    pub fn report(&self) -> NetworkReport {
        NetworkReport::build(&self.tcp, &self.udp, &self.dns, &self.http)
    }

    #[must_use]
    pub const fn total_artifacts(&self) -> usize {
        self.tcp.count() + self.udp.count() + self.dns.count() + self.http.count()
    }

    #[must_use]
    pub fn external_tcp(&self) -> Vec<&TcpEntry> {
        self.tcp
            .all()
            .iter()
            .filter(|e| {
                !e.remote_ip().is_loopback() && e.remote_ip() != IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            })
            .collect()
    }

    #[must_use]
    pub fn suspicious_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .tcp
            .established()
            .iter()
            .filter(|e| e.process_name.is_none())
            .map(|e| e.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        pids.sort_unstable();
        pids
    }

    /// Resolve remote IP of a TCP entry via the DNS cache.
    #[must_use]
    pub fn resolve_tcp_ip(&self, entry: &TcpEntry) -> Vec<String> {
        self.dns
            .for_ip(entry.remote_ip())
            .iter()
            .map(|e| e.hostname.clone())
            .collect()
    }

    /// All processes that have both TCP and UDP artifacts.
    ///
    /// Previously this method was misnamed `processes_with_http_and_tcp`; the
    /// implementation intersected TCP PIDs with UDP PIDs (never touching
    /// `self.http`), so the name was corrected to match the actual logic.
    #[must_use]
    pub fn processes_with_tcp_and_udp(&self) -> Vec<u32> {
        let tcp_pids: std::collections::HashSet<u32> = self.tcp.unique_pids().into_iter().collect();
        self.udp
            .unique_pids()
            .into_iter()
            .filter(|p| tcp_pids.contains(p))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn make_tcp(pid: u32, state: ConnectionState) -> TcpEntry {
        TcpEntry::new(
            sock([10, 0, 0, 1], 54321),
            sock([1, 2, 3, 4], 443),
            state,
            pid,
        )
    }

    // --- ConnectionState ---

    #[test]
    fn test_state_from_mib() {
        assert_eq!(
            ConnectionState::from_mib_state(5),
            ConnectionState::Established
        );
        assert_eq!(ConnectionState::from_mib_state(2), ConnectionState::Listen);
    }

    #[test]
    fn test_state_unknown() {
        assert_eq!(
            ConnectionState::from_mib_state(99),
            ConnectionState::Unknown(99)
        );
    }

    #[test]
    fn test_state_is_active() {
        assert!(ConnectionState::Established.is_active());
        assert!(!ConnectionState::Closed.is_active());
    }

    #[test]
    fn test_state_display() {
        assert_eq!(ConnectionState::Established.to_string(), "Established");
        assert_eq!(ConnectionState::Unknown(5).to_string(), "Unknown(5)");
    }

    // --- TcpEntry ---

    #[test]
    fn test_tcp_entry_is_established() {
        let e = make_tcp(1, ConnectionState::Established);
        assert!(e.is_established());
    }

    #[test]
    fn test_tcp_entry_is_listening() {
        let e = make_tcp(4, ConnectionState::Listen);
        assert!(e.is_listening());
    }

    #[test]
    fn test_tcp_entry_is_outbound() {
        // local port 54321 > 1024
        let e = make_tcp(1, ConnectionState::Established);
        assert!(e.is_outbound());
    }

    #[test]
    fn test_tcp_entry_with_process() {
        let e = make_tcp(1, ConnectionState::Established).with_process("chrome.exe");
        assert_eq!(e.process_name.as_deref(), Some("chrome.exe"));
    }

    #[test]
    fn test_tcp_entry_display() {
        let e = make_tcp(42, ConnectionState::Established);
        let s = e.to_string();
        assert!(s.contains("TCP"));
        assert!(s.contains("42"));
    }

    // --- TcpConnections ---

    #[test]
    fn test_tcp_connections_add_count() {
        let mut tc = TcpConnections::new();
        tc.add(make_tcp(1, ConnectionState::Established));
        assert_eq!(tc.count(), 1);
    }

    #[test]
    fn test_tcp_connections_established() {
        let mut tc = TcpConnections::new();
        tc.add(make_tcp(1, ConnectionState::Established));
        tc.add(make_tcp(2, ConnectionState::Listen));
        assert_eq!(tc.established().len(), 1);
    }

    #[test]
    fn test_tcp_connections_by_pid() {
        let mut tc = TcpConnections::new();
        tc.add(make_tcp(10, ConnectionState::Established));
        tc.add(make_tcp(20, ConnectionState::Established));
        assert_eq!(tc.by_pid(10).len(), 1);
    }

    #[test]
    fn test_tcp_connections_unique_remote_ips() {
        let mut tc = TcpConnections::new();
        tc.add(make_tcp(1, ConnectionState::Established));
        tc.add(make_tcp(2, ConnectionState::Established));
        assert_eq!(tc.unique_remote_ips().len(), 1); // both → 1.2.3.4
    }

    #[test]
    fn test_tcp_outbound_count() {
        let mut tc = TcpConnections::new();
        tc.add(make_tcp(1, ConnectionState::Established)); // port 54321 > 1024
        assert_eq!(tc.outbound_count(), 1);
    }

    // --- UdpEntry ---

    #[test]
    fn test_udp_entry_local_port() {
        let e = UdpEntry::new(sock([0, 0, 0, 0], 5353), 100);
        assert_eq!(e.local_port(), 5353);
    }

    #[test]
    fn test_udp_entry_with_process() {
        let e = UdpEntry::new(sock([0, 0, 0, 0], 53), 4).with_process("svchost.exe");
        assert!(e.process_name.is_some());
    }

    // --- UdpConnections ---

    #[test]
    fn test_udp_connections_count() {
        let mut uc = UdpConnections::new();
        uc.add(UdpEntry::new(sock([0, 0, 0, 0], 137), 4));
        assert_eq!(uc.count(), 1);
    }

    #[test]
    fn test_udp_listening_ports() {
        let mut uc = UdpConnections::new();
        uc.add(UdpEntry::new(sock([0, 0, 0, 0], 5353), 1));
        uc.add(UdpEntry::new(sock([0, 0, 0, 0], 137), 4));
        assert!(uc.listening_ports().contains(&5353));
        assert!(uc.listening_ports().contains(&137));
    }

    // --- DnsCacheEntry ---

    #[test]
    fn test_dns_entry_is_a_record() {
        let e = DnsCacheEntry::new("example.com", DnsRecordType::A);
        assert!(e.is_a_record());
    }

    #[test]
    fn test_dns_entry_with_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let e = DnsCacheEntry::new("dns.google", DnsRecordType::A).with_ip(ip);
        assert!(e.addresses.contains(&ip));
    }

    // --- DnsCache ---

    #[test]
    fn test_dns_cache_lookup() {
        let mut dc = DnsCache::new();
        dc.add(DnsCacheEntry::new("example.com", DnsRecordType::A));
        assert!(dc.lookup("example.com").is_some());
        assert!(dc.lookup("missing.com").is_none());
    }

    #[test]
    fn test_dns_cache_for_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mut dc = DnsCache::new();
        dc.add(DnsCacheEntry::new("evil.com", DnsRecordType::A).with_ip(ip));
        assert_eq!(dc.for_ip(ip).len(), 1);
    }

    #[test]
    fn test_dns_cache_unique_hostnames() {
        let mut dc = DnsCache::new();
        dc.add(DnsCacheEntry::new("a.com", DnsRecordType::A));
        dc.add(DnsCacheEntry::new("a.com", DnsRecordType::Aaaa));
        let names = dc.unique_hostnames();
        assert_eq!(names.len(), 1);
    }

    // --- HttpCacheEntry ---

    #[test]
    fn test_http_entry_host() {
        let e = HttpCacheEntry::new("http://evil.com/beacon", "GET");
        assert_eq!(e.host, "evil.com");
    }

    #[test]
    fn test_http_entry_is_post() {
        let e = HttpCacheEntry::new("http://c2.com/upload", "POST");
        assert!(e.is_post());
    }

    #[test]
    fn test_http_entry_is_success() {
        let e = HttpCacheEntry::new("http://c2.com/gate", "GET").with_status(200);
        assert!(e.is_success());
        let e2 = HttpCacheEntry::new("http://c2.com/gate", "GET").with_status(404);
        assert!(!e2.is_success());
    }

    #[test]
    fn test_http_entry_display() {
        let e = HttpCacheEntry::new("http://c2.com/gate", "POST");
        let s = e.to_string();
        assert!(s.contains("POST"));
    }

    // --- HttpCache ---

    #[test]
    fn test_http_cache_by_host() {
        let mut hc = HttpCache::new();
        hc.add(HttpCacheEntry::new("http://evil.com/a", "GET"));
        hc.add(HttpCacheEntry::new("http://good.com/b", "GET"));
        assert_eq!(hc.by_host("evil.com").len(), 1);
    }

    #[test]
    fn test_http_cache_unique_hosts() {
        let mut hc = HttpCache::new();
        hc.add(HttpCacheEntry::new("http://a.com/x", "GET"));
        hc.add(HttpCacheEntry::new("http://a.com/y", "POST"));
        hc.add(HttpCacheEntry::new("http://b.com/z", "GET"));
        assert_eq!(hc.unique_hosts().len(), 2);
    }

    #[test]
    fn test_http_suspicious_user_agents() {
        let mut hc = HttpCache::new();
        let mut e = HttpCacheEntry::new("http://c2.com/", "GET");
        e.user_agent = Some("Go".into()); // very short
        hc.add(e);
        assert_eq!(hc.suspicious_user_agents().len(), 1);
    }

    // --- NetworkArtifacts ---

    #[test]
    fn test_artifacts_total() {
        let mut na = NetworkArtifacts::new();
        na.add_tcp(make_tcp(1, ConnectionState::Established));
        na.add_udp(UdpEntry::new(sock([0, 0, 0, 0], 53), 4));
        na.add_dns(DnsCacheEntry::new("x.com", DnsRecordType::A));
        na.add_http(HttpCacheEntry::new("http://x.com/", "GET"));
        assert_eq!(na.total_artifacts(), 4);
    }

    #[test]
    fn test_artifacts_report_summary() {
        let mut na = NetworkArtifacts::new();
        na.add_tcp(make_tcp(1, ConnectionState::Established));
        let r = na.report();
        assert_eq!(r.tcp_total, 1);
        assert!(!r.summary.is_empty());
    }

    #[test]
    fn test_artifacts_external_tcp() {
        let mut na = NetworkArtifacts::new();
        na.add_tcp(make_tcp(1, ConnectionState::Established));
        let ext = na.external_tcp();
        assert_eq!(ext.len(), 1);
    }

    #[test]
    fn test_artifacts_suspicious_pids() {
        let mut na = NetworkArtifacts::new();
        // port 443 > 1024 → suspicious without process name
        na.add_tcp(make_tcp(999, ConnectionState::Established));
        let pids = na.suspicious_pids();
        assert!(pids.contains(&999));
    }

    #[test]
    fn test_artifacts_resolve_tcp_ip() {
        let mut na = NetworkArtifacts::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        na.add_dns(DnsCacheEntry::new("evil.com", DnsRecordType::A).with_ip(ip));
        let entry = make_tcp(1, ConnectionState::Established);
        let resolved = na.resolve_tcp_ip(&entry);
        assert!(resolved.contains(&"evil.com".to_string()));
    }

    #[test]
    fn test_report_has_suspicious() {
        let mut na = NetworkArtifacts::new();
        na.add_tcp(make_tcp(1, ConnectionState::Established));
        let r = na.report();
        assert!(r.has_suspicious_activity()); // port 443 > 1024, no process name
    }
}
