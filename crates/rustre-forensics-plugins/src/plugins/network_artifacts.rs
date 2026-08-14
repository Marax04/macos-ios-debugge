//! Network forensics artifacts: ARP cache, DNS cache, Netstat state,
//! TCP connection timeline analysis, and network interface metadata.
//!
//! # Layer distinction
//! This module is the **low-level binary scanner**: it scans raw memory bytes
//! for tagged ARP/DNS/TCP records, builds timeline diffs between netstat
//! snapshots, and extracts passive DNS hostnames.  The high-level aggregator
//! that works with typed connection objects lives in
//! [`crate::network_artifacts`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NetworkArtifactError {
    #[error("invalid IP address bytes at offset {0}")]
    InvalidIpBytes(usize),
    #[error("invalid MAC address: {0}")]
    InvalidMac(String),
    #[error("truncated record at offset {0}")]
    Truncated(usize),
    #[error("unknown address family: {0}")]
    UnknownAddressFamily(u16),
}

// ─── MAC address ──────────────────────────────────────────────────────────────

/// A 48-bit IEEE 802 MAC address.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    #[must_use]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Parse a MAC address from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the slice is shorter than 6 bytes.
    pub fn from_slice(s: &[u8]) -> Result<Self, NetworkArtifactError> {
        if s.len() < 6 {
            return Err(NetworkArtifactError::InvalidMac(format!("{s:?}")));
        }
        let mut b = [0u8; 6];
        b.copy_from_slice(&s[..6]);
        Ok(Self(b))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Return the MAC address as a colon-separated hex string.
    #[must_use]
    pub fn to_string_colon(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    /// Return the OUI (first 3 bytes) as an uppercase hex string.
    #[must_use]
    pub fn oui(&self) -> String {
        format!("{:02X}-{:02X}-{:02X}", self.0[0], self.0[1], self.0[2])
    }

    /// Returns `true` if this is a multicast address (bit 0 of first octet set).
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
    /// Returns `true` if this is the broadcast address (FF:FF:FF:FF:FF:FF).
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }
    /// Returns `true` if this is a locally-administered address (bit 1 of first octet).
    #[must_use]
    pub const fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

// ─── ARP cache ────────────────────────────────────────────────────────────────

/// ARP entry state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpState {
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Incomplete,
    Permanent,
    Unknown(u32),
}

impl ArpState {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            2 => Self::Reachable,
            4 => Self::Stale,
            8 => Self::Delay,
            16 => Self::Probe,
            32 => Self::Failed,
            1 => Self::Incomplete,
            64 => Self::Permanent,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Reachable => "Reachable",
            Self::Stale => "Stale",
            Self::Delay => "Delay",
            Self::Probe => "Probe",
            Self::Failed => "Failed",
            Self::Incomplete => "Incomplete",
            Self::Permanent => "Permanent",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// A single ARP cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub interface_index: u32,
    pub ip_address: Ipv4Addr,
    pub mac_address: MacAddress,
    pub state: ArpState,
    pub is_router: bool,
    pub age_seconds: u32,
}

impl ArpEntry {
    /// Returns `true` if this entry is suspicious (local IP but a multicast MAC).
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.mac_address.is_multicast() && !self.ip_address.is_multicast()
    }
}

/// Scanner for ARP cache records in a memory dump.
pub struct ArpCacheScanner;

impl ArpCacheScanner {
    /// ARP entry sentinel used in mock memory dumps.
    /// Layout: `b"ARPE"` (4) | iface(4) | ip(4) | mac(6) | pad(2) | state(4) | age(4)
    const TAG: &'static [u8; 4] = b"ARPE";
    const RECORD_SIZE: usize = 28;

    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<ArpEntry> {
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos + Self::RECORD_SIZE <= data.len() {
            if &data[pos..pos + 4] == Self::TAG {
                let iface = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4]));
                let ip_bytes: [u8; 4] = data[pos + 8..pos + 12].try_into().unwrap_or([0; 4]);
                let ip = Ipv4Addr::from(ip_bytes);
                let mut mac_bytes = [0u8; 6];
                mac_bytes.copy_from_slice(&data[pos + 12..pos + 18]);
                let mac = MacAddress::new(mac_bytes);
                let state_raw =
                    u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap_or([0; 4]));
                let age = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap_or([0; 4]));
                entries.push(ArpEntry {
                    interface_index: iface,
                    ip_address: ip,
                    mac_address: mac,
                    state: ArpState::from_u32(state_raw),
                    is_router: false,
                    age_seconds: age,
                });
                pos += Self::RECORD_SIZE;
            } else {
                pos += 4;
            }
        }
        entries
    }
}

// ─── DNS cache entry ──────────────────────────────────────────────────────────

/// DNS record type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Mx,
    Cname,
    Ptr,
    Srv,
    Txt,
    Soa,
    Unknown(u16),
}

impl DnsRecordType {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::Aaaa,
            15 => Self::Mx,
            5 => Self::Cname,
            12 => Self::Ptr,
            33 => Self::Srv,
            16 => Self::Txt,
            6 => Self::Soa,
            n => Self::Unknown(n),
        }
    }
}

/// A cached DNS resolution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: u32,
    pub data: DnsRecordData,
    pub flags: u32,
    pub source: DnsSource,
}

/// Where the DNS record came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsSource {
    Cache,
    Hosts,
    Network,
    Unknown,
}

/// The actual data payload of a DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Raw(Vec<u8>),
}

impl DnsRecordData {
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::A(ip) => ip.to_string(),
            Self::Aaaa(ip) => ip.to_string(),
            Self::Name(n) => n.clone(),
            Self::Raw(b) => format!("<{} bytes>", b.len()),
        }
    }
}

/// Scanner for DNS cache records.
pub struct DnsCacheScanner;

impl DnsCacheScanner {
    const TAG: &'static [u8; 4] = b"DNSC";

    /// Scan for `DNSC` records.
    /// Layout: `b"DNSC"` (4) | type(2) | ttl(4) | `name_len`(2) | `name`(`name_len`)
    ///          | `data_type_indicator`(1) | ip4(4) or `name_len2`(2)+name2 | flags(4)
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<DnsCacheEntry> {
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos + 14 <= data.len() {
            if &data[pos..pos + 4] == Self::TAG {
                let rtype_raw =
                    u16::from_le_bytes(data[pos + 4..pos + 6].try_into().unwrap_or([0; 2]));
                let ttl = u32::from_le_bytes(data[pos + 6..pos + 10].try_into().unwrap_or([0; 4]));
                let name_len =
                    u16::from_le_bytes(data[pos + 10..pos + 12].try_into().unwrap_or([0; 2]))
                        as usize;
                if pos + 12 + name_len + 9 > data.len() {
                    pos += 4;
                    continue;
                }
                let name =
                    String::from_utf8_lossy(&data[pos + 12..pos + 12 + name_len]).to_string();
                let data_off = pos + 12 + name_len;
                let data_indicator = data[data_off];
                let record_data = if data_indicator == 0 && data_off + 5 <= data.len() {
                    let ip: [u8; 4] = data[data_off + 1..data_off + 5]
                        .try_into()
                        .unwrap_or([0; 4]);
                    DnsRecordData::A(Ipv4Addr::from(ip))
                } else if data_indicator == 1 && data_off + 3 <= data.len() {
                    let nl2 = u16::from_le_bytes(
                        data[data_off + 1..data_off + 3]
                            .try_into()
                            .unwrap_or([0; 2]),
                    ) as usize;
                    let end2 = (data_off + 3 + nl2).min(data.len());
                    DnsRecordData::Name(
                        String::from_utf8_lossy(&data[data_off + 3..end2]).to_string(),
                    )
                } else {
                    DnsRecordData::Raw(vec![])
                };
                entries.push(DnsCacheEntry {
                    name,
                    record_type: DnsRecordType::from_u16(rtype_raw),
                    ttl,
                    data: record_data,
                    flags: 0,
                    source: DnsSource::Cache,
                });
                pos += 12 + name_len + 10;
            } else {
                pos += 4;
            }
        }
        entries
    }

    /// Flag suspicious DNS entries (DGA-like names, known C2 TLDs, etc.).
    #[must_use]
    pub fn is_suspicious_domain(name: &str) -> bool {
        let lower = name.to_lowercase();
        // Very short TTLs or suspicious TLDs
        let suspicious_tlds = [".tk", ".cf", ".ga", ".ml", ".gq", ".pw", ".onion"];
        if suspicious_tlds.iter().any(|t| lower.ends_with(t)) {
            return true;
        }
        // DGA heuristic: long random-looking names
        let parts: Vec<&str> = lower.split('.').collect();
        if let Some(sub) = parts.first()
            && sub.len() > 15 && sub.chars().all(char::is_alphanumeric) {
                return true;
            }
        false
    }
}

// ─── Netstat / TCP connection ─────────────────────────────────────────────────

/// TCP connection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
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
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
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
            12 => Self::DeleteTcb,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// A network connection from the OS netstat table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetstatEntry {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: TcpState,
    pub pid: u32,
    pub process_name: String,
    /// Time the connection was created (if available).
    pub create_time: u64,
}

/// Network protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Tcp4 => "TCP",
            Self::Tcp6 => "TCP6",
            Self::Udp4 => "UDP",
            Self::Udp6 => "UDP6",
        }
    }
}

impl NetstatEntry {
    /// Returns `true` if this connection looks potentially malicious.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        let remote = self.remote_addr.as_str();
        // Connections on non-standard high ports to external IPs
        if self.remote_port > 1024 && self.remote_port != 443 && self.remote_port != 8080
            && !remote.starts_with("10.")
                && !remote.starts_with("192.168.")
                && !remote.starts_with("172.")
                && !remote.is_empty()
                && remote != "0.0.0.0"
                && remote != "127.0.0.1"
            {
                // Non-well-known port to external address
                return self.remote_port > 50000
                    || self.remote_port == 4444
                    || self.remote_port == 1337;
            }
        // Meterpreter default port
        if self.remote_port == 4444 {
            return true;
        }
        // Common C2 ports
        let suspicious_ports: &[u16] = &[1337, 31337, 8888, 9999, 6666, 1234, 12345];
        suspicious_ports.contains(&self.remote_port)
    }
}

// ─── TCP connection timeline ──────────────────────────────────────────────────

/// A point-in-time snapshot of a TCP connection for timeline analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTimelineEvent {
    pub timestamp: i64,
    pub event_type: TcpTimelineEventType,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpTimelineEventType {
    Connect,
    Listen,
    Accept,
    Close,
    Reset,
    DataTransfer,
}

impl TcpTimelineEventType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Connect => "CONNECT",
            Self::Listen => "LISTEN",
            Self::Accept => "ACCEPT",
            Self::Close => "CLOSE",
            Self::Reset => "RESET",
            Self::DataTransfer => "DATA",
        }
    }
}

/// Build a timeline of TCP events from netstat snapshots.
pub struct TcpTimeline;

impl TcpTimeline {
    /// Correlate two netstat snapshots to infer events.
    #[must_use]
    pub fn diff(
        before: &[NetstatEntry],
        after: &[NetstatEntry],
        timestamp: i64,
    ) -> Vec<TcpTimelineEvent> {
        let mut events = Vec::new();
        let make_key = |e: &NetstatEntry| {
            format!(
                "{}-{}-{}-{}",
                e.local_addr, e.local_port, e.remote_addr, e.remote_port
            )
        };
        let before_map: HashMap<String, &NetstatEntry> =
            before.iter().map(|e| (make_key(e), e)).collect();
        let after_map: HashMap<String, &NetstatEntry> =
            after.iter().map(|e| (make_key(e), e)).collect();

        // New connections: present in after, not in before
        for (key, entry) in &after_map {
            if !before_map.contains_key(key.as_str()) {
                let ev_type = if entry.state == TcpState::Listen {
                    TcpTimelineEventType::Listen
                } else {
                    TcpTimelineEventType::Connect
                };
                events.push(TcpTimelineEvent {
                    timestamp,
                    event_type: ev_type,
                    local_addr: entry.local_addr.clone(),
                    local_port: entry.local_port,
                    remote_addr: entry.remote_addr.clone(),
                    remote_port: entry.remote_port,
                    pid: entry.pid,
                });
            }
        }
        // Closed connections: present in before, not in after
        for (key, entry) in &before_map {
            if !after_map.contains_key(key.as_str()) {
                events.push(TcpTimelineEvent {
                    timestamp,
                    event_type: TcpTimelineEventType::Close,
                    local_addr: entry.local_addr.clone(),
                    local_port: entry.local_port,
                    remote_addr: entry.remote_addr.clone(),
                    remote_port: entry.remote_port,
                    pid: entry.pid,
                });
            }
        }
        events
    }
}

// ─── Network interface metadata ───────────────────────────────────────────────

/// Network interface information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub mac_address: Option<MacAddress>,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub ipv6_addresses: Vec<Ipv6Addr>,
    pub mtu: u32,
    pub speed_mbps: u64,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_promisc: bool,
}

impl NetworkInterface {
    /// Returns `true` if promiscuous mode is enabled (potential sniffer).
    #[must_use]
    pub const fn is_sniffer_indicator(&self) -> bool {
        self.is_promisc && !self.is_loopback
    }
}

// ─── Passive DNS reconstructor ────────────────────────────────────────────────

/// Reconstruct passive DNS history from raw DNS cache data.
pub struct PassiveDnsReconstructor;

impl PassiveDnsReconstructor {
    /// Scan raw bytes for DNS query patterns.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let tld_patterns: &[&[u8]] = &[
            b".com\x00",
            b".net\x00",
            b".org\x00",
            b".io\x00",
            b".gov\x00",
            b".edu\x00",
            b".co.uk\x00",
            b".de\x00",
        ];
        for tld in tld_patterns {
            let mut pos = 0;
            while pos + tld.len() <= data.len() {
                if data[pos..].starts_with(&tld[..tld.len() - 1]) {
                    let end = pos + tld.len() - 1;
                    // Walk backward for domain name
                    let start = data[..pos]
                        .iter()
                        .rev()
                        .position(|&b| !(0x20..=0x7E).contains(&b))
                        .map_or(0, |i| pos.saturating_sub(i));
                    if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        let s =
                            s.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
                        if s.len() > 3 && s.contains('.') {
                            names.push(s.to_string());
                        }
                    }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_address_formatting() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
        assert_eq!(mac.to_string_colon(), "aa:bb:cc:11:22:33");
        assert_eq!(mac.oui(), "AA-BB-CC");
    }

    #[test]
    fn mac_address_multicast() {
        let mc = MacAddress::new([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);
        assert!(mc.is_multicast());
        let uc = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert!(!uc.is_multicast());
    }

    #[test]
    fn mac_address_broadcast() {
        let bc = MacAddress::new([0xFF; 6]);
        assert!(bc.is_broadcast());
    }

    #[test]
    fn mac_locally_administered() {
        let la = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(la.is_locally_administered());
    }

    #[test]
    fn arp_state_conversion() {
        assert_eq!(ArpState::from_u32(2), ArpState::Reachable);
        assert_eq!(ArpState::from_u32(4), ArpState::Stale);
        assert_eq!(ArpState::from_u32(32), ArpState::Failed);
        assert_eq!(ArpState::Reachable.as_str(), "Reachable");
    }

    #[test]
    fn arp_scanner_finds_entries() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"ARPE");
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // iface
        data[8..12].copy_from_slice(&[192, 168, 1, 1]); // ip
        data[12..18].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]); // mac
        data[20..24].copy_from_slice(&2u32.to_le_bytes()); // state = Reachable
        data[24..28].copy_from_slice(&30u32.to_le_bytes()); // age = 30s
        let entries = ArpCacheScanner::scan(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].state, ArpState::Reachable);
    }

    #[test]
    fn tcp_state_as_str() {
        assert_eq!(TcpState::Established.as_str(), "ESTABLISHED");
        assert_eq!(TcpState::Listen.as_str(), "LISTEN");
        assert_eq!(TcpState::from_u32(5), TcpState::Established);
        assert_eq!(TcpState::from_u32(99), TcpState::Unknown(99));
    }

    #[test]
    fn netstat_suspicious_port_4444() {
        let e = NetstatEntry {
            protocol: Protocol::Tcp4,
            local_addr: "0.0.0.0".into(),
            local_port: 1234,
            remote_addr: "8.8.8.8".into(),
            remote_port: 4444,
            state: TcpState::Established,
            pid: 1234,
            process_name: "evil.exe".into(),
            create_time: 0,
        };
        assert!(e.is_suspicious());
    }

    #[test]
    fn netstat_not_suspicious_https() {
        let e = NetstatEntry {
            protocol: Protocol::Tcp4,
            local_addr: "10.0.0.1".into(),
            local_port: 49152,
            remote_addr: "1.1.1.1".into(),
            remote_port: 443,
            state: TcpState::Established,
            pid: 100,
            process_name: "browser.exe".into(),
            create_time: 0,
        };
        assert!(!e.is_suspicious());
    }

    #[test]
    fn dns_suspicious_domain() {
        assert!(DnsCacheScanner::is_suspicious_domain("c2server.tk"));
        assert!(DnsCacheScanner::is_suspicious_domain(
            "xkj3mf9dks2mfksdj.com"
        ));
        assert!(!DnsCacheScanner::is_suspicious_domain("google.com"));
    }

    #[test]
    fn dns_record_type_from_u16() {
        assert_eq!(DnsRecordType::from_u16(1), DnsRecordType::A);
        assert_eq!(DnsRecordType::from_u16(28), DnsRecordType::Aaaa);
        assert_eq!(DnsRecordType::from_u16(99), DnsRecordType::Unknown(99));
    }

    #[test]
    fn tcp_timeline_diff_detects_new_connection() {
        let before = vec![];
        let after = vec![NetstatEntry {
            protocol: Protocol::Tcp4,
            local_addr: "192.168.1.5".into(),
            local_port: 50000,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
            state: TcpState::Established,
            pid: 1234,
            process_name: "curl.exe".into(),
            create_time: 0,
        }];
        let events = TcpTimeline::diff(&before, &after, 1_700_000_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, TcpTimelineEventType::Connect);
    }

    #[test]
    fn tcp_timeline_diff_detects_closed_connection() {
        let before = vec![NetstatEntry {
            protocol: Protocol::Tcp4,
            local_addr: "192.168.1.5".into(),
            local_port: 50001,
            remote_addr: "1.2.3.4".into(),
            remote_port: 80,
            state: TcpState::Established,
            pid: 999,
            process_name: "wget.exe".into(),
            create_time: 0,
        }];
        let after = vec![];
        let events = TcpTimeline::diff(&before, &after, 1_700_000_100);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, TcpTimelineEventType::Close);
    }

    #[test]
    fn network_interface_sniffer_flag() {
        let iface = NetworkInterface {
            index: 1,
            name: "eth0".into(),
            description: "Ethernet".into(),
            mac_address: Some(MacAddress::new([0x00; 6])),
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            mtu: 1500,
            speed_mbps: 1000,
            is_up: true,
            is_loopback: false,
            is_promisc: true,
        };
        assert!(iface.is_sniffer_indicator());
    }

    #[test]
    fn passive_dns_scan() {
        let data = b"\x00example.com\x00github.net\x00evil.tk\x00";
        let names = PassiveDnsReconstructor::scan(data);
        assert!(!names.is_empty());
    }

    #[test]
    fn protocol_as_str() {
        assert_eq!(Protocol::Tcp4.as_str(), "TCP");
        assert_eq!(Protocol::Udp6.as_str(), "UDP6");
    }
}
