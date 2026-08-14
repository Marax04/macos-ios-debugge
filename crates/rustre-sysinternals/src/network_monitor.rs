//! `network_monitor` — TCPView-equivalent
//!
//! Active TCP/UDP connections, socket state, owning process, remote endpoints,
//! bandwidth tracking, DNS cache, and connection alerting.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{NetworkProtocol, SysinternalsError, TcpState};

/// Convert `u64` to `f64` via two `u32` halves to avoid precision-loss cast.
fn u64_to_f64(x: u64) -> f64 {
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}

// ─── ConnectionId ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId {
    pub protocol: NetworkProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

impl ConnectionId {
    #[must_use]
    pub fn new(
        protocol: NetworkProtocol,
        local_addr: impl Into<String>,
        local_port: u16,
        remote_addr: impl Into<String>,
        remote_port: u16,
    ) -> Self {
        Self {
            protocol,
            local_addr: local_addr.into(),
            local_port,
            remote_addr: remote_addr.into(),
            remote_port,
        }
    }

    #[must_use]
    pub fn local_socket_str(&self) -> String {
        format!("{}:{}", self.local_addr, self.local_port)
    }

    #[must_use]
    pub fn remote_socket_str(&self) -> String {
        format!("{}:{}", self.remote_addr, self.remote_port)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{} -> {}:{}",
            self.protocol,
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port
        )
    }
}

// ─── BandwidthSample ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BandwidthSample {
    pub timestamp_us: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

impl BandwidthSample {
    #[must_use]
    pub fn new(ts: u64, sent: u64, recv: u64) -> Self {
        Self {
            timestamp_us: ts,
            bytes_sent: sent,
            bytes_recv: recv,
            ..Default::default()
        }
    }
}

// ─── ConnectionEntry ──────────────────────────────────────────────────────────

/// Full connection record — equivalent to a row in `TCPView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub id: ConnectionId,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub state: TcpState,
    /// When the connection was first seen (UNIX micros).
    pub created_us: u64,
    /// When the connection was last updated.
    pub updated_us: u64,
    /// Total bytes sent since creation.
    pub total_bytes_sent: u64,
    /// Total bytes received since creation.
    pub total_bytes_recv: u64,
    /// Current send rate (bytes/sec), updated per sample.
    pub send_rate_bps: f64,
    /// Current receive rate (bytes/sec).
    pub recv_rate_bps: f64,
    /// Resolved remote hostname (may be empty if not resolved).
    pub remote_hostname: Option<String>,
    /// Whether the remote IP is in a known bad-IP list.
    pub flagged: bool,
    /// Bandwidth history (ring buffer).
    pub bandwidth_history: Vec<BandwidthSample>,
    /// Number of retransmissions observed.
    pub retransmissions: u64,
    /// Round-trip time estimate in microseconds.
    pub rtt_us: Option<u64>,
    /// Whether this is an IPv6 connection.
    pub is_ipv6: bool,
}

impl ConnectionEntry {
    #[must_use]
    pub fn new(
        id: ConnectionId,
        pid: u32,
        process_name: impl Into<String>,
        state: TcpState,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        let is_ipv6 = id.local_addr.contains(':');
        Self {
            id,
            pid,
            process_name: process_name.into(),
            process_path: String::new(),
            state,
            created_us: now,
            updated_us: now,
            total_bytes_sent: 0,
            total_bytes_recv: 0,
            send_rate_bps: 0.0,
            recv_rate_bps: 0.0,
            remote_hostname: None,
            flagged: false,
            bandwidth_history: Vec::new(),
            retransmissions: 0,
            rtt_us: None,
            is_ipv6,
        }
    }

    /// Update bandwidth rates based on a new sample vs previous totals.
    pub fn update_rates(&mut self, sent_delta: u64, recv_delta: u64, elapsed_secs: f64) {
        if elapsed_secs > 0.0 {
            self.send_rate_bps = u64_to_f64(sent_delta) / elapsed_secs;
            self.recv_rate_bps = u64_to_f64(recv_delta) / elapsed_secs;
        }
        self.total_bytes_sent += sent_delta;
        self.total_bytes_recv += recv_delta;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        self.updated_us = now;
        if self.bandwidth_history.len() >= 60 {
            self.bandwidth_history.remove(0);
        }
        self.bandwidth_history.push(BandwidthSample::new(now, sent_delta, recv_delta));
    }

    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    #[must_use]
    pub fn is_listening(&self) -> bool {
        self.state == TcpState::Listen
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes_sent.saturating_add(self.total_bytes_recv)
    }

    #[must_use]
    pub fn age_secs(&self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        u64_to_f64(now.saturating_sub(self.created_us)) / 1_000_000.0
    }

    /// CSV row.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{:.1},{:.1}",
            self.pid,
            self.process_name,
            self.id.protocol,
            self.id.local_socket_str(),
            self.id.remote_socket_str(),
            self.state,
            self.total_bytes_sent,
            self.send_rate_bps,
            self.recv_rate_bps,
        )
    }
}

// ─── ConnectionFilter ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ConnectionFilter {
    pub pids: Vec<u32>,
    pub protocols: Vec<NetworkProtocol>,
    pub states: Vec<TcpState>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub remote_addr_contains: Option<String>,
    pub process_name_contains: Option<String>,
    pub flagged_only: bool,
    pub established_only: bool,
    pub listening_only: bool,
    pub min_bytes: Option<u64>,
}

impl ConnectionFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn matches(&self, conn: &ConnectionEntry) -> bool {
        if !self.pids.is_empty() && !self.pids.contains(&conn.pid) {
            return false;
        }
        if !self.protocols.is_empty() && !self.protocols.contains(&conn.id.protocol) {
            return false;
        }
        if !self.states.is_empty() && !self.states.contains(&conn.state) {
            return false;
        }
        if let Some(lp) = self.local_port
            && conn.id.local_port != lp
        {
            return false;
        }
        if let Some(rp) = self.remote_port
            && conn.id.remote_port != rp
        {
            return false;
        }
        if let Some(ref ra) = self.remote_addr_contains
            && !conn.id.remote_addr.contains(ra.as_str())
        {
            return false;
        }
        if let Some(ref name) = self.process_name_contains
            && !conn
                .process_name
                .to_lowercase()
                .contains(name.to_lowercase().as_str())
        {
            return false;
        }
        if self.flagged_only && !conn.flagged {
            return false;
        }
        if self.established_only && !conn.is_established() {
            return false;
        }
        if self.listening_only && !conn.is_listening() {
            return false;
        }
        if let Some(min_b) = self.min_bytes
            && conn.total_bytes() < min_b
        {
            return false;
        }
        true
    }

    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pids.push(pid);
        self
    }

    #[must_use]
    pub fn with_protocol(mut self, p: NetworkProtocol) -> Self {
        self.protocols.push(p);
        self
    }

    #[must_use]
    pub const fn established_only(mut self) -> Self {
        self.established_only = true;
        self
    }

    #[must_use]
    pub const fn listening_only(mut self) -> Self {
        self.listening_only = true;
        self
    }

    #[must_use]
    pub const fn flagged_only(mut self) -> Self {
        self.flagged_only = true;
        self
    }
}

// ─── NetworkStatsSummary ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStatsSummary {
    pub total_connections: usize,
    pub established: usize,
    pub listening: usize,
    pub time_wait: usize,
    pub close_wait: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
    pub top_talker_pid: Option<u32>,
    pub top_talker_bytes: u64,
}

// ─── DnsEntry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntry {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub ttl_secs: u32,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub query_count: u64,
}

impl DnsEntry {
    #[must_use]
    pub fn new(hostname: impl Into<String>, addresses: Vec<IpAddr>, ttl: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        Self {
            hostname: hostname.into(),
            addresses,
            ttl_secs: ttl,
            first_seen_us: now,
            last_seen_us: now,
            query_count: 1,
        }
    }
}

// ─── Known-bad IP sets (placeholder) ─────────────────────────────────────────

/// A minimal set of well-known suspicious IP ranges/addresses.
pub struct ThreatIntelDb {
    bad_ips: Vec<IpAddr>,
    bad_subnets: Vec<(u32, u32)>, // (network, mask) for IPv4
}

impl ThreatIntelDb {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bad_ips: Vec::new(),
            bad_subnets: Vec::new(),
        }
    }

    pub fn add_bad_ip(&mut self, ip: IpAddr) {
        self.bad_ips.push(ip);
    }

    pub fn add_bad_subnet(&mut self, network: u32, mask: u32) {
        self.bad_subnets.push((network, mask));
    }

    #[must_use]
    pub fn is_flagged(&self, addr: &str) -> bool {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            if self.bad_ips.contains(&ip) {
                return true;
            }
            if let IpAddr::V4(v4) = ip {
                let n = u32::from(v4);
                for &(net, mask) in &self.bad_subnets {
                    if n & mask == net & mask {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl Default for ThreatIntelDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ConnectionEvent ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionEventKind {
    New,
    StateChange,
    Closed,
    BytesUpdate,
    Flagged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub timestamp_us: u64,
    pub kind: ConnectionEventKind,
    pub conn_id: ConnectionId,
    pub pid: u32,
    pub old_state: Option<TcpState>,
    pub new_state: Option<TcpState>,
}

// ─── NetworkMonitor ───────────────────────────────────────────────────────────

pub struct NetworkMonitor {
    /// Active connections keyed by `ConnectionId`.
    connections: HashMap<ConnectionId, ConnectionEntry>,
    /// Historical events ring buffer.
    events: VecDeque<ConnectionEvent>,
    events_capacity: usize,
    /// DNS cache.
    dns_cache: HashMap<String, DnsEntry>,
    /// Threat intel database.
    threat_intel: ThreatIntelDb,
    /// Per-process bandwidth totals.
    process_bandwidth: HashMap<u32, (u64, u64)>,
    /// Snapshot timestamp.
    last_snapshot: Option<Instant>,
}

impl NetworkMonitor {
    #[must_use]
    pub fn new(events_capacity: usize) -> Self {
        Self {
            connections: HashMap::new(),
            events: VecDeque::with_capacity(events_capacity),
            events_capacity,
            dns_cache: HashMap::new(),
            threat_intel: ThreatIntelDb::new(),
            process_bandwidth: HashMap::new(),
            last_snapshot: None,
        }
    }

    /// Record bandwidth delta for a process. `sent` and `recv` are added to the running totals.
    pub fn record_bandwidth(&mut self, pid: u32, sent: u64, recv: u64) {
        let e = self.process_bandwidth.entry(pid).or_insert((0, 0));
        e.0 = e.0.saturating_add(sent);
        e.1 = e.1.saturating_add(recv);
    }

    /// Get cumulative `(bytes_sent, bytes_recv)` for a process.
    #[must_use]
    pub fn bandwidth_for_pid(&self, pid: u32) -> (u64, u64) {
        self.process_bandwidth.get(&pid).copied().unwrap_or((0, 0))
    }

    /// Upsert a connection (insert new or update state).
    pub fn upsert_connection(&mut self, entry: ConnectionEntry) {
        let id = entry.id.clone();
        let pid = entry.pid;

        // Check threat intel.
        let flagged = self.threat_intel.is_flagged(&entry.id.remote_addr);

        let _old_state = self.connections.get(&id).map(|c| c.state);

        let mut entry = entry;
        entry.flagged = flagged;

        if flagged {
            self.push_event(ConnectionEvent {
                timestamp_us: entry.updated_us,
                kind: ConnectionEventKind::Flagged,
                conn_id: id.clone(),
                pid,
                old_state: None,
                new_state: Some(entry.state),
            });
        }

        if let Some(prev) = self.connections.get(&id) {
            if prev.state != entry.state {
                self.push_event(ConnectionEvent {
                    timestamp_us: entry.updated_us,
                    kind: ConnectionEventKind::StateChange,
                    conn_id: id.clone(),
                    pid,
                    old_state: Some(prev.state),
                    new_state: Some(entry.state),
                });
            }
        } else {
            self.push_event(ConnectionEvent {
                timestamp_us: entry.created_us,
                kind: ConnectionEventKind::New,
                conn_id: id.clone(),
                pid,
                old_state: None,
                new_state: Some(entry.state),
            });
        }

        self.connections.insert(id, entry);
        self.last_snapshot = Some(Instant::now());
    }

    /// Remove a connection (mark as closed).
    pub fn remove_connection(&mut self, id: &ConnectionId) {
        if let Some(conn) = self.connections.remove(id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
            self.push_event(ConnectionEvent {
                timestamp_us: now,
                kind: ConnectionEventKind::Closed,
                conn_id: id.clone(),
                pid: conn.pid,
                old_state: Some(conn.state),
                new_state: None,
            });
        }
    }

    fn push_event(&mut self, event: ConnectionEvent) {
        if self.events.len() >= self.events_capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn add_dns_entry(&mut self, entry: DnsEntry) {
        self.dns_cache
            .entry(entry.hostname.clone())
            .and_modify(|e| {
                e.query_count += 1;
                e.last_seen_us = entry.last_seen_us;
            })
            .or_insert(entry);
    }

    pub fn add_bad_ip(&mut self, ip: IpAddr) {
        self.threat_intel.add_bad_ip(ip);
    }

    /// Query active connections.
    #[must_use]
    pub fn query(&self, filter: &ConnectionFilter) -> Vec<&ConnectionEntry> {
        self.connections.values().filter(|c| filter.matches(c)).collect()
    }

    /// All active connections.
    #[must_use]
    pub fn all_connections(&self) -> Vec<&ConnectionEntry> {
        self.connections.values().collect()
    }

    /// Get a specific connection.
    #[must_use]
    pub fn get(&self, id: &ConnectionId) -> Option<&ConnectionEntry> {
        self.connections.get(id)
    }

    /// Compute summary statistics.
    #[must_use]
    pub fn summary(&self) -> NetworkStatsSummary {
        let mut s = NetworkStatsSummary {
            total_connections: self.connections.len(),
            ..Default::default()
        };
        let mut by_pid: HashMap<u32, u64> = HashMap::new();
        for c in self.connections.values() {
            match c.state {
                TcpState::Established => s.established += 1,
                TcpState::Listen => s.listening += 1,
                TcpState::TimeWait => s.time_wait += 1,
                TcpState::CloseWait => s.close_wait += 1,
                _ => {}
            }
            s.total_bytes_sent += c.total_bytes_sent;
            s.total_bytes_recv += c.total_bytes_recv;
            *by_pid.entry(c.pid).or_default() += c.total_bytes();
        }
        if let Some((top_pid, top_bytes)) = by_pid.iter().max_by_key(|(_, v)| *v).map(|(k, v)| (*k, *v)) {
            s.top_talker_pid = Some(top_pid);
            s.top_talker_bytes = top_bytes;
        }
        s
    }

    /// Top N connections by total bytes.
    #[must_use]
    pub fn top_by_bytes(&self, n: usize) -> Vec<&ConnectionEntry> {
        let mut v: Vec<&ConnectionEntry> = self.connections.values().collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.total_bytes()));
        v.truncate(n);
        v
    }

    /// Top N connections by send rate.
    #[must_use]
    pub fn top_by_send_rate(&self, n: usize) -> Vec<&ConnectionEntry> {
        let mut v: Vec<&ConnectionEntry> = self.connections.values().collect();
        v.sort_by(|a, b| {
            b.send_rate_bps
                .partial_cmp(&a.send_rate_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v.truncate(n);
        v
    }

    /// Flagged connections.
    #[must_use]
    pub fn flagged_connections(&self) -> Vec<&ConnectionEntry> {
        self.connections.values().filter(|c| c.flagged).collect()
    }

    /// Group active connections by process.
    #[must_use]
    pub fn by_process(&self) -> HashMap<u32, Vec<&ConnectionEntry>> {
        let mut map: HashMap<u32, Vec<&ConnectionEntry>> = HashMap::new();
        for c in self.connections.values() {
            map.entry(c.pid).or_default().push(c);
        }
        map
    }

    /// Resolve hostname hint (inserts or looks up DNS cache).
    #[must_use]
    pub fn resolve_hostname(&self, addr: &str) -> Option<String> {
        self.dns_cache
            .values()
            .find(|e| e.addresses.iter().any(|a| a.to_string() == addr))
            .map(|e| e.hostname.clone())
    }

    /// Export active connections as CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "PID,Process,Protocol,LocalSocket,RemoteSocket,State,BytesSent,SendRate,RecvRate\n",
        );
        let mut conns: Vec<&ConnectionEntry> = self.connections.values().collect();
        conns.sort_by_key(|c| c.pid);
        for c in conns {
            out.push_str(&c.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        let conns: Vec<&ConnectionEntry> = self.connections.values().collect();
        serde_json::to_string_pretty(&conns)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }

    /// Recent events.
    #[must_use]
    pub fn recent_events(&self, n: usize) -> Vec<&ConnectionEvent> {
        self.events.iter().rev().take(n).collect()
    }

    /// Number of active connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Listening ports and their owning PIDs.
    #[must_use]
    pub fn listening_ports(&self) -> Vec<(u16, u32, String)> {
        self.connections
            .values()
            .filter(|c| c.is_listening())
            .map(|c| (c.id.local_port, c.pid, c.process_name.clone()))
            .collect()
    }

    /// Check if a specific port is being listened on.
    #[must_use]
    pub fn is_port_listening(&self, port: u16) -> bool {
        self.connections
            .values()
            .any(|c| c.is_listening() && c.id.local_port == port)
    }
}

// ─── Connection builder ───────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConnectionBuilder {
    inner: ConnectionEntry,
}

impl ConnectionBuilder {
    #[must_use]
    pub fn tcp(pid: u32, process: &str, local: &str, lport: u16, remote: &str, rport: u16, state: TcpState) -> Self {
        let id = ConnectionId::new(NetworkProtocol::Tcp, local, lport, remote, rport);
        Self {
            inner: ConnectionEntry::new(id, pid, process, state),
        }
    }

    #[must_use]
    pub fn udp(pid: u32, process: &str, local: &str, lport: u16) -> Self {
        let id = ConnectionId::new(NetworkProtocol::Udp, local, lport, "0.0.0.0", 0);
        Self {
            inner: ConnectionEntry::new(id, pid, process, TcpState::Unknown),
        }
    }

    #[must_use]
    pub const fn with_bytes(mut self, sent: u64, recv: u64) -> Self {
        self.inner.total_bytes_sent = sent;
        self.inner.total_bytes_recv = recv;
        self
    }

    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.inner.remote_hostname = Some(hostname.into());
        self
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.inner.process_path = path.into();
        self
    }

    #[must_use]
    pub fn build(self) -> ConnectionEntry {
        self.inner
    }
}

// ─── Port service names ───────────────────────────────────────────────────────

pub mod well_known_ports {
    pub const HTTP: u16 = 80;
    pub const HTTPS: u16 = 443;
    pub const FTP: u16 = 21;
    pub const FTP_DATA: u16 = 20;
    pub const SSH: u16 = 22;
    pub const TELNET: u16 = 23;
    pub const SMTP: u16 = 25;
    pub const DNS: u16 = 53;
    pub const DHCP_SERVER: u16 = 67;
    pub const DHCP_CLIENT: u16 = 68;
    pub const TFTP: u16 = 69;
    pub const POP3: u16 = 110;
    pub const NTP: u16 = 123;
    pub const IMAP: u16 = 143;
    pub const SNMP: u16 = 161;
    pub const LDAP: u16 = 389;
    pub const SMB: u16 = 445;
    pub const IMAPS: u16 = 993;
    pub const POP3S: u16 = 995;
    pub const RDP: u16 = 3389;
    pub const MSSQL: u16 = 1433;
    pub const MYSQL: u16 = 3306;
    pub const POSTGRESQL: u16 = 5432;
    pub const REDIS: u16 = 6379;
    pub const MONGODB: u16 = 27017;
    pub const VNC: u16 = 5900;
    pub const KERBEROS: u16 = 88;

    #[must_use]
    pub const fn service_name(port: u16) -> Option<&'static str> {
        match port {
            HTTP => Some("HTTP"),
            HTTPS => Some("HTTPS"),
            FTP => Some("FTP"),
            SSH => Some("SSH"),
            TELNET => Some("Telnet"),
            SMTP => Some("SMTP"),
            DNS => Some("DNS"),
            POP3 => Some("POP3"),
            NTP => Some("NTP"),
            IMAP => Some("IMAP"),
            SNMP => Some("SNMP"),
            LDAP => Some("LDAP"),
            SMB => Some("SMB/CIFS"),
            IMAPS => Some("IMAPS"),
            POP3S => Some("POP3S"),
            RDP => Some("RDP"),
            MSSQL => Some("MSSQL"),
            MYSQL => Some("MySQL"),
            POSTGRESQL => Some("PostgreSQL"),
            REDIS => Some("Redis"),
            MONGODB => Some("MongoDB"),
            VNC => Some("VNC"),
            KERBEROS => Some("Kerberos"),
            _ => None,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkProtocol, TcpState};

    fn make_tcp_conn(pid: u32, lport: u16, raddr: &str, rport: u16, state: TcpState) -> ConnectionEntry {
        ConnectionBuilder::tcp(pid, "proc.exe", "0.0.0.0", lport, raddr, rport, state).build()
    }

    fn make_udp_conn(pid: u32, lport: u16) -> ConnectionEntry {
        ConnectionBuilder::udp(pid, "proc.exe", "0.0.0.0", lport).build()
    }

    #[test]
    fn test_connection_id_display() {
        let id = ConnectionId::new(NetworkProtocol::Tcp, "192.168.1.1", 1234, "8.8.8.8", 443);
        assert!(id.to_string().contains("TCP"));
        assert_eq!(id.remote_socket_str(), "8.8.8.8:443");
    }

    #[test]
    fn test_connection_entry_total_bytes() {
        let mut conn = make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established);
        conn.update_rates(1000, 2000, 1.0);
        assert_eq!(conn.total_bytes(), 3000);
        assert!((conn.send_rate_bps - 1000.0).abs() < 0.1);
    }

    #[test]
    fn test_connection_filter_established() {
        let filter = ConnectionFilter::new().established_only();
        let c1 = make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established);
        let c2 = make_tcp_conn(2, 80, "0.0.0.0", 0, TcpState::Listen);
        assert!(filter.matches(&c1));
        assert!(!filter.matches(&c2));
    }

    #[test]
    fn test_connection_filter_pid() {
        let filter = ConnectionFilter::new().with_pid(42);
        let c1 = make_tcp_conn(42, 80, "1.2.3.4", 443, TcpState::Established);
        let c2 = make_tcp_conn(99, 80, "1.2.3.4", 443, TcpState::Established);
        assert!(filter.matches(&c1));
        assert!(!filter.matches(&c2));
    }

    #[test]
    fn test_network_monitor_upsert_and_query() {
        let mut mon = NetworkMonitor::new(100);
        mon.upsert_connection(make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established));
        mon.upsert_connection(make_udp_conn(2, 53));
        assert_eq!(mon.connection_count(), 2);
        let filter = ConnectionFilter::new().established_only();
        let results = mon.query(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_network_monitor_listening_ports() {
        let mut mon = NetworkMonitor::new(100);
        mon.upsert_connection(make_tcp_conn(1, 443, "0.0.0.0", 0, TcpState::Listen));
        assert!(mon.is_port_listening(443));
        assert!(!mon.is_port_listening(80));
        let ports = mon.listening_ports();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].0, 443);
    }

    #[test]
    fn test_network_monitor_summary() {
        let mut mon = NetworkMonitor::new(100);
        mon.upsert_connection(make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established));
        mon.upsert_connection(make_tcp_conn(2, 443, "0.0.0.0", 0, TcpState::Listen));
        let s = mon.summary();
        assert_eq!(s.total_connections, 2);
        assert_eq!(s.established, 1);
        assert_eq!(s.listening, 1);
    }

    #[test]
    fn test_network_monitor_remove_connection() {
        let mut mon = NetworkMonitor::new(100);
        let conn = make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established);
        let id = conn.id.clone();
        mon.upsert_connection(conn);
        assert_eq!(mon.connection_count(), 1);
        mon.remove_connection(&id);
        assert_eq!(mon.connection_count(), 0);
    }

    #[test]
    fn test_network_monitor_flagged_connection() {
        let mut mon = NetworkMonitor::new(100);
        let bad_ip: IpAddr = "6.6.6.6".parse().unwrap();
        mon.add_bad_ip(bad_ip);
        let conn = make_tcp_conn(1, 80, "6.6.6.6", 443, TcpState::Established);
        mon.upsert_connection(conn);
        let flagged = mon.flagged_connections();
        assert_eq!(flagged.len(), 1);
    }

    #[test]
    fn test_network_monitor_csv() {
        let mut mon = NetworkMonitor::new(10);
        mon.upsert_connection(make_tcp_conn(1, 80, "1.2.3.4", 443, TcpState::Established));
        let csv = mon.to_csv();
        assert!(csv.contains("PID"));
    }

    #[test]
    fn test_threat_intel_bad_subnet() {
        let mut db = ThreatIntelDb::new();
        db.add_bad_subnet(0x0A00_0000, 0xFF00_0000); // 10.0.0.0/8
        assert!(db.is_flagged("10.5.6.7"));
        assert!(!db.is_flagged("192.168.1.1"));
    }

    #[test]
    fn test_dns_entry() {
        let entry = DnsEntry::new("evil.com", vec!["1.2.3.4".parse().unwrap()], 300);
        assert_eq!(entry.hostname, "evil.com");
        assert_eq!(entry.query_count, 1);
    }

    #[test]
    fn test_well_known_ports() {
        assert_eq!(well_known_ports::service_name(443), Some("HTTPS"));
        assert_eq!(well_known_ports::service_name(3389), Some("RDP"));
        assert_eq!(well_known_ports::service_name(12345), None);
    }

    #[test]
    fn test_top_by_bytes() {
        let mut mon = NetworkMonitor::new(100);
        let mut c1 = make_tcp_conn(1, 80, "1.1.1.1", 443, TcpState::Established);
        c1.total_bytes_sent = 1_000_000;
        let mut c2 = make_tcp_conn(2, 81, "2.2.2.2", 443, TcpState::Established);
        c2.total_bytes_sent = 500_000;
        mon.upsert_connection(c1);
        mon.upsert_connection(c2);
        let top = mon.top_by_bytes(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].pid, 1);
    }

    #[test]
    fn test_recent_events() {
        let mut mon = NetworkMonitor::new(100);
        mon.upsert_connection(make_tcp_conn(1, 80, "1.1.1.1", 443, TcpState::Established));
        let events = mon.recent_events(10);
        assert!(!events.is_empty());
        assert_eq!(events[0].kind, ConnectionEventKind::New);
    }
}
