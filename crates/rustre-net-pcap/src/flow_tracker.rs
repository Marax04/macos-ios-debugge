//! 5-tuple flow tracker with session state and reassembled stream buffers.
//!
//! Each unique (`src_ip`, `dst_ip`, `src_port`, `dst_port`, protocol) tuple maps to a
//! [`Flow`].  The tracker handles TCP state transitions, maintains per-direction
//! byte/packet counters, and assembles ordered TCP payload segments into
//! direction-keyed ring buffers.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

// ─── Addresses and keys ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "{a}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: IpAddress,
    pub dst_ip: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FiveTuple {
    #[must_use] 
    pub const fn new_v4(
        src: Ipv4Addr, dst: Ipv4Addr,
        sport: u16, dport: u16, proto: u8,
    ) -> Self {
        Self {
            src_ip: IpAddress::V4(src),
            dst_ip: IpAddress::V4(dst),
            src_port: sport,
            dst_port: dport,
            protocol: proto,
        }
    }

    #[must_use] 
    pub const fn new_v6(
        src: Ipv6Addr, dst: Ipv6Addr,
        sport: u16, dport: u16, proto: u8,
    ) -> Self {
        Self {
            src_ip: IpAddress::V6(src),
            dst_ip: IpAddress::V6(dst),
            src_port: sport,
            dst_port: dport,
            protocol: proto,
        }
    }

    /// Returns the canonical (lower-address-first) key so that bidirectional
    /// flows share a single entry.
    #[must_use] 
    pub fn canonical(&self) -> Self {
        let forward = format!("{}{}{}{}", self.src_ip, self.dst_ip, self.src_port, self.dst_port);
        let reverse = format!("{}{}{}{}", self.dst_ip, self.src_ip, self.dst_port, self.src_port);
        if forward <= reverse {
            self.clone()
        } else {
            Self {
                src_ip: self.dst_ip.clone(),
                dst_ip: self.src_ip.clone(),
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }

    #[must_use] 
    pub const fn is_tcp(&self) -> bool { self.protocol == 6 }
    #[must_use] 
    pub const fn is_udp(&self) -> bool { self.protocol == 17 }
    #[must_use] 
    pub const fn is_icmp(&self) -> bool { self.protocol == 1 || self.protocol == 58 }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = match self.protocol {
            6  => "TCP",
            17 => "UDP",
            1  => "ICMP",
            58 => "ICMPv6",
            n  => return write!(f, "{}:{} → {}:{} proto={n}", self.src_ip, self.src_port, self.dst_ip, self.dst_port),
        };
        write!(f, "{}:{} → {}:{} {proto}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

// ─── TCP state machine ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
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
}

impl TcpState {
    #[must_use] 
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2 | Self::CloseWait)
    }
    #[must_use] 
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait)
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── TCP segment (for reassembly) ─────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TcpSegment {
    seq: u32,
    data: Vec<u8>,
}

/// Direction-keyed TCP stream reassembly buffer.
#[derive(Debug, Clone, Default)]
pub struct TcpStream {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Assembled in-order payload bytes.
    pub reassembled: Vec<u8>,
    /// Out-of-order segments waiting to be inserted.
    o: Vec<TcpSegment>,
    /// Total bytes added (including retransmits).
    pub total_bytes_seen: u64,
    pub gaps: u32,
}

impl TcpStream {
    #[must_use] 
    pub fn init(isn: u32) -> Self {
        Self { next_seq: isn.wrapping_add(1), ..Default::default() }
    }

    /// Insert a segment.  Returns the number of new bytes added to `reassembled`.
    pub fn insert(&mut self, seq: u32, data: &[u8]) -> usize {
        if data.is_empty() { return 0; }
        self.total_bytes_seen += data.len() as u64;

        let end_seq = seq.wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX));

        // Completely before next_seq → retransmit, ignore.
        if seq_lt(end_seq, self.next_seq) || end_seq == self.next_seq {
            return 0;
        }

        // Trim bytes before next_seq.
        let skip = if seq_lt(seq, self.next_seq) {
            self.next_seq.wrapping_sub(seq) as usize
        } else {
            0
        };
        let trimmed = &data[skip..];
        let trimmed_seq = seq.wrapping_add(u32::try_from(skip).unwrap_or(u32::MAX));

        if trimmed_seq == self.next_seq {
            self.reassembled.extend_from_slice(trimmed);
            self.next_seq = self.next_seq.wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
            // Drain any now-contiguous out-of-order segments.
            let added = trimmed.len();
            added + self.drain_ooo()
        } else {
            // Out of order: stash it.
            self.o.push(TcpSegment { seq: trimmed_seq, data: trimmed.to_vec() });
            self.o.sort_by(|a, b| {
                if seq_lt(a.seq, b.seq) { std::cmp::Ordering::Less }
                else if a.seq == b.seq { std::cmp::Ordering::Equal }
                else { std::cmp::Ordering::Greater }
            });
            self.gaps += 1;
            0
        }
    }

    fn drain_ooo(&mut self) -> usize {
        let mut added = 0;
        loop {
            let candidate = self.o.first().cloned();
            match candidate {
                Some(seg) if seg.seq == self.next_seq => {
                    self.o.remove(0);
                    self.reassembled.extend_from_slice(&seg.data);
                    self.next_seq = self.next_seq.wrapping_add(u32::try_from(seg.data.len()).unwrap_or(u32::MAX));
                    added += seg.data.len();
                }
                Some(seg) if seq_lt(seg.seq, self.next_seq) => {
                    // Overlap — trim or discard.
                    self.o.remove(0);
                    let overlap = self.next_seq.wrapping_sub(seg.seq) as usize;
                    if overlap < seg.data.len() {
                        let trimmed = &seg.data[overlap..];
                        self.reassembled.extend_from_slice(trimmed);
                        self.next_seq = self.next_seq.wrapping_add(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
                        added += trimmed.len();
                    }
                }
                _ => break,
            }
        }
        added
    }

    #[must_use] 
    pub const fn assembled_len(&self) -> usize {
        self.reassembled.len()
    }
}

/// RFC-style sequence number comparison (handles wraparound).
const fn seq_lt(a: u32, b: u32) -> bool {
    a.cast_signed().wrapping_sub(b.cast_signed()) < 0
}

// ─── Per-direction statistics ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectionStats {
    pub packets: u64,
    pub bytes: u64,
    pub retransmits: u64,
    pub out_of_order: u64,
    pub first_ts_secs: Option<f64>,
    pub last_ts_secs: Option<f64>,
}

impl DirectionStats {
    pub const fn update(&mut self, bytes: u64, ts: f64) {
        self.packets += 1;
        self.bytes += bytes;
        if self.first_ts_secs.is_none() { self.first_ts_secs = Some(ts); }
        self.last_ts_secs = Some(ts);
    }

    #[must_use] 
    pub fn duration_secs(&self) -> f64 {
        match (self.first_ts_secs, self.last_ts_secs) {
            (Some(f), Some(l)) => l - f,
            _ => 0.0,
        }
    }

    #[must_use] 
    pub fn throughput_bps(&self) -> f64 {
        let dur = self.duration_secs();
        if dur > 0.0 { (self.bytes * 8) as f64 / dur } else { 0.0 }
    }
}

// ─── Flow ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FiveTuple,
    pub tcp_state: TcpState,
    pub fwd: DirectionStats,
    pub rev: DirectionStats,
    pub fwd_stream: Option<TcpStream>,
    pub rev_stream: Option<TcpStream>,
    pub start_ts: f64,
    pub last_ts: f64,
    pub app_proto: Option<String>,
    pub tags: Vec<String>,
    pub closed: bool,
}

impl Flow {
    fn new_tcp(key: FiveTuple, ts: f64) -> Self {
        Self {
            key,
            tcp_state: TcpState::Listen,
            fwd: DirectionStats::default(),
            rev: DirectionStats::default(),
            fwd_stream: Some(TcpStream::default()),
            rev_stream: Some(TcpStream::default()),
            start_ts: ts,
            last_ts: ts,
            app_proto: None,
            tags: Vec::new(),
            closed: false,
        }
    }

    fn new_udp(key: FiveTuple, ts: f64) -> Self {
        Self {
            key,
            tcp_state: TcpState::Closed,
            fwd: DirectionStats::default(),
            rev: DirectionStats::default(),
            fwd_stream: None,
            rev_stream: None,
            start_ts: ts,
            last_ts: ts,
            app_proto: None,
            tags: Vec::new(),
            closed: false,
        }
    }

    #[must_use] 
    pub fn duration_secs(&self) -> f64 {
        self.last_ts - self.start_ts
    }

    #[must_use] 
    pub const fn total_packets(&self) -> u64 {
        self.fwd.packets + self.rev.packets
    }

    #[must_use] 
    pub const fn total_bytes(&self) -> u64 {
        self.fwd.bytes + self.rev.bytes
    }
}

// ─── Packet update ────────────────────────────────────────────────────────────

/// Minimal packet description that the flow tracker needs.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub tuple: FiveTuple,
    pub ts: f64,
    pub payload_len: usize,
    /// TCP flags byte (0 if not TCP).
    pub tcp_flags: u8,
    /// TCP sequence number (0 if not TCP).
    pub tcp_seq: u32,
    /// TCP acknowledgment number (0 if not TCP).
    pub tcp_ack: u32,
    pub payload: Vec<u8>,
}

impl PacketInfo {
    #[must_use] 
    pub const fn is_syn(&self) -> bool { self.tcp_flags & 0x02 != 0 }
    #[must_use] 
    pub const fn is_ack(&self) -> bool { self.tcp_flags & 0x10 != 0 }
    #[must_use] 
    pub const fn is_fin(&self) -> bool { self.tcp_flags & 0x01 != 0 }
    #[must_use] 
    pub const fn is_rst(&self) -> bool { self.tcp_flags & 0x04 != 0 }
}

// ─── Flow tracker ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTrackerConfig {
    /// Seconds of inactivity after which a UDP/non-TCP flow is expired.
    pub udp_timeout_secs: f64,
    /// Seconds of inactivity after which a TCP flow in ESTABLISHED is expired.
    pub tcp_established_timeout_secs: f64,
    /// Seconds of inactivity after which a TCP flow in any other state is expired.
    pub tcp_other_timeout_secs: f64,
    /// Maximum number of active flows.
    pub max_flows: usize,
    /// Maximum payload bytes kept per direction in the reassembly buffer.
    pub max_stream_bytes: usize,
}

impl Default for FlowTrackerConfig {
    fn default() -> Self {
        Self {
            udp_timeout_secs: 30.0,
            tcp_established_timeout_secs: 300.0,
            tcp_other_timeout_secs: 60.0,
            max_flows: 65_536,
            max_stream_bytes: 1 << 20, // 1 MiB
        }
    }
}

pub struct FlowTracker {
    config: FlowTrackerConfig,
    flows: HashMap<FiveTuple, Flow>,
    expired: Vec<Flow>,
    /// Stats
    total_flows_created: u64,
    total_flows_expired: u64,
    total_packets: u64,
}

impl FlowTracker {
    #[must_use] 
    pub fn new(config: FlowTrackerConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            expired: Vec::new(),
            total_flows_created: 0,
            total_flows_expired: 0,
            total_packets: 0,
        }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(FlowTrackerConfig::default())
    }

    /// Process a packet.  Returns the canonical key of the flow it was added to.
    pub fn process(&mut self, pkt: PacketInfo) -> FiveTuple {
        self.total_packets += 1;
        let canon = pkt.tuple.canonical();
        let is_forward = pkt.tuple == canon;
        let ts = pkt.ts;

        let is_tcp = pkt.tuple.is_tcp();
        let is_rst = pkt.is_rst();

        let flow = self.flows.entry(canon.clone()).or_insert_with(|| {
            self.total_flows_created += 1;
            if is_tcp {
                Flow::new_tcp(canon.clone(), ts)
            } else {
                Flow::new_udp(canon.clone(), ts)
            }
        });

        flow.last_ts = ts;
        let payload_bytes = pkt.payload_len as u64;
        if is_forward {
            flow.fwd.update(payload_bytes, ts);
        } else {
            flow.rev.update(payload_bytes, ts);
        }

        if is_tcp {
            Self::update_tcp_state(flow, &pkt, is_forward, self.config.max_stream_bytes);
        }

        if is_rst {
            flow.tcp_state = TcpState::Closed;
            flow.closed = true;
        }

        // Infer app protocol from ports
        if flow.app_proto.is_none() {
            flow.app_proto = infer_protocol(canon.src_port, canon.dst_port, canon.protocol);
        }

        canon
    }

    fn update_tcp_state(
        flow: &mut Flow,
        pkt: &PacketInfo,
        is_forward: bool,
        max_stream: usize,
    ) {
        let flags = pkt.tcp_flags;
        let syn  = flags & 0x02 != 0;
        let ack  = flags & 0x10 != 0;
        let fin  = flags & 0x01 != 0;
        let rst  = flags & 0x04 != 0;

        if rst {
            flow.tcp_state = TcpState::Closed;
            return;
        }

        flow.tcp_state = match flow.tcp_state {
            TcpState::Listen | TcpState::Closed => {
                if syn && !ack { TcpState::SynSent }
                else { TcpState::Established }
            }
            TcpState::SynSent => {
                if syn && ack { TcpState::SynReceived }
                else if ack   { TcpState::Established }
                else           { TcpState::SynSent }
            }
            TcpState::SynReceived => {
                if ack { TcpState::Established }
                else    { TcpState::SynReceived }
            }
            TcpState::Established => {
                if fin { TcpState::FinWait1 }
                else    { TcpState::Established }
            }
            TcpState::FinWait1 => {
                if fin && ack { TcpState::TimeWait }
                else if ack   { TcpState::FinWait2 }
                else if fin   { TcpState::Closing }
                else           { TcpState::FinWait1 }
            }
            TcpState::FinWait2 => {
                if fin { TcpState::TimeWait } else { TcpState::FinWait2 }
            }
            TcpState::Closing => {
                if ack { TcpState::TimeWait } else { TcpState::Closing }
            }
            TcpState::CloseWait => {
                if fin { TcpState::LastAck } else { TcpState::CloseWait }
            }
            TcpState::LastAck => {
                if ack { TcpState::Closed } else { TcpState::LastAck }
            }
            TcpState::TimeWait => TcpState::Closed,
        };

        if flow.tcp_state == TcpState::Closed {
            flow.closed = true;
        }

        // Reassemble payload
        if !pkt.payload.is_empty() {
            let stream = if is_forward {
                flow.fwd_stream.as_mut()
            } else {
                flow.rev_stream.as_mut()
            };
            if let Some(s) = stream
                && s.assembled_len() < max_stream {
                    let available = max_stream - s.assembled_len();
                    let trimmed = &pkt.payload[..pkt.payload.len().min(available)];
                    s.insert(pkt.tcp_seq, trimmed);
                }
        }
    }

    /// Expire flows that have been inactive longer than the configured timeouts.
    /// Returns the number of flows expired in this pass.
    pub fn expire(&mut self, current_ts: f64) -> usize {
        let config = &self.config;
        let mut to_expire: Vec<FiveTuple> = Vec::new();

        for (key, flow) in &self.flows {
            if flow.closed {
                to_expire.push(key.clone());
                continue;
            }
            let idle = current_ts - flow.last_ts;
            let timeout = if key.is_tcp() {
                if flow.tcp_state.is_open() {
                    config.tcp_established_timeout_secs
                } else {
                    config.tcp_other_timeout_secs
                }
            } else {
                config.udp_timeout_secs
            };
            if idle > timeout {
                to_expire.push(key.clone());
            }
        }

        let count = to_expire.len();
        for key in to_expire {
            if let Some(flow) = self.flows.remove(&key) {
                self.expired.push(flow);
                self.total_flows_expired += 1;
            }
        }
        count
    }

    /// Drain the expired flow buffer.  The caller can inspect or archive them.
    pub fn drain_expired(&mut self) -> Vec<Flow> {
        std::mem::take(&mut self.expired)
    }

    #[must_use] 
    pub const fn active_flows(&self) -> &HashMap<FiveTuple, Flow> {
        &self.flows
    }

    #[must_use] 
    pub fn get_flow(&self, key: &FiveTuple) -> Option<&Flow> {
        self.flows.get(key)
    }

    pub fn get_flow_mut(&mut self, key: &FiveTuple) -> Option<&mut Flow> {
        self.flows.get_mut(key)
    }

    #[must_use] 
    pub fn active_count(&self) -> usize {
        self.flows.len()
    }

    #[must_use] 
    pub const fn total_created(&self) -> u64 { self.total_flows_created }
    #[must_use] 
    pub const fn total_expired(&self) -> u64 { self.total_flows_expired }
    #[must_use] 
    pub const fn total_packets(&self) -> u64 { self.total_packets }

    /// Return a snapshot of flow statistics sorted by total bytes descending.
    #[must_use] 
    pub fn top_flows_by_bytes(&self, n: usize) -> Vec<FlowSummary> {
        let mut summaries: Vec<FlowSummary> = self.flows.values().map(|f| FlowSummary {
            key: f.key.clone(),
            tcp_state: f.tcp_state,
            total_packets: f.total_packets(),
            total_bytes: f.total_bytes(),
            fwd_bytes: f.fwd.bytes,
            rev_bytes: f.rev.bytes,
            duration_secs: f.duration_secs(),
            app_proto: f.app_proto.clone(),
            tags: f.tags.clone(),
        }).collect();
        summaries.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        summaries.truncate(n);
        summaries
    }

    /// Force all active flows to expire immediately.
    pub fn flush_all(&mut self) {
        let keys: Vec<FiveTuple> = self.flows.keys().cloned().collect();
        for key in keys {
            if let Some(flow) = self.flows.remove(&key) {
                self.expired.push(flow);
                self.total_flows_expired += 1;
            }
        }
    }
}

// ─── Flow summary ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub key: FiveTuple,
    pub tcp_state: TcpState,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
    pub duration_secs: f64,
    pub app_proto: Option<String>,
    pub tags: Vec<String>,
}

// ─── Protocol inference ───────────────────────────────────────────────────────

fn infer_protocol(sport: u16, dport: u16, proto: u8) -> Option<String> {
    let ports = [sport, dport];
    match proto {
        6 | 17 => {
            for &p in &ports {
                let name = match p {
                    20 | 21 => "FTP",
                    22      => "SSH",
                    23      => "TELNET",
                    25      => "SMTP",
                    53      => "DNS",
                    80      => "HTTP",
                    110     => "POP3",
                    143     => "IMAP",
                    443     => "HTTPS",
                    445     => "SMB",
                    993     => "IMAPS",
                    995     => "POP3S",
                    1433    => "MSSQL",
                    3306    => "MYSQL",
                    3389    => "RDP",
                    5432    => "POSTGRESQL",
                    5900    => "VNC",
                    6379    => "REDIS",
                    8080    => "HTTP-ALT",
                    8443    => "HTTPS-ALT",
                    _ => continue,
                };
                return Some(name.to_string());
            }
            None
        }
        1  => Some("ICMP".to_string()),
        58 => Some("ICMPv6".to_string()),
        _  => None,
    }
}

// ─── Flow report ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowReport {
    pub total_flows: u64,
    pub active_flows: usize,
    pub expired_flows: u64,
    pub total_packets: u64,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub other_flows: usize,
    pub top_talkers: Vec<FlowSummary>,
}

impl FlowTracker {
    #[must_use] 
    pub fn report(&self) -> FlowReport {
        let tcp = self.flows.values().filter(|f| f.key.is_tcp()).count();
        let udp = self.flows.values().filter(|f| f.key.is_udp()).count();
        let other = self.flows.len() - tcp - udp;
        FlowReport {
            total_flows: self.total_flows_created,
            active_flows: self.flows.len(),
            expired_flows: self.total_flows_expired,
            total_packets: self.total_packets,
            tcp_flows: tcp,
            udp_flows: udp,
            other_flows: other,
            top_talkers: self.top_flows_by_bytes(10),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_tuple(s: [u8;4], d: [u8;4], sp: u16, dp: u16) -> FiveTuple {
        FiveTuple::new_v4(Ipv4Addr::from(s), Ipv4Addr::from(d), sp, dp, 6)
    }

    fn udp_tuple(s: [u8;4], d: [u8;4], sp: u16, dp: u16) -> FiveTuple {
        FiveTuple::new_v4(Ipv4Addr::from(s), Ipv4Addr::from(d), sp, dp, 17)
    }

    fn pkt_tcp(tuple: FiveTuple, ts: f64, flags: u8, seq: u32, payload: Vec<u8>) -> PacketInfo {
        PacketInfo {
            payload_len: payload.len(),
            tuple, ts, tcp_flags: flags, tcp_seq: seq, tcp_ack: 0, payload,
        }
    }

    #[test]
    fn test_canonical_key_symmetry() {
        let t1 = tcp_tuple([1,1,1,1], [2,2,2,2], 1234, 80);
        let t2 = tcp_tuple([2,2,2,2], [1,1,1,1], 80, 1234);
        assert_eq!(t1.canonical(), t2.canonical());
    }

    #[test]
    fn test_flow_created_on_first_packet() {
        let mut tracker = FlowTracker::with_defaults();
        let tuple = tcp_tuple([1,0,0,1], [2,0,0,2], 5000, 80);
        let pkt = pkt_tcp(tuple, 1.0, 0x02, 1000, vec![]); // SYN
        tracker.process(pkt);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_bidirectional_traffic_same_flow() {
        let mut tracker = FlowTracker::with_defaults();
        let fwd = tcp_tuple([1,0,0,1], [2,0,0,2], 5000, 80);
        let rev = tcp_tuple([2,0,0,2], [1,0,0,1], 80, 5000);
        tracker.process(pkt_tcp(fwd, 1.0, 0x02, 0, vec![]));
        tracker.process(pkt_tcp(rev, 1.1, 0x12, 0, vec![]));
        assert_eq!(tracker.active_count(), 1);
        let canon = tcp_tuple([1,0,0,1], [2,0,0,2], 5000, 80).canonical();
        let flow = tracker.get_flow(&canon).unwrap();
        assert!(flow.fwd.packets > 0 || flow.rev.packets > 0);
        assert_eq!(flow.fwd.packets + flow.rev.packets, 2);
    }

    #[test]
    fn test_tcp_state_transition_syn_ack_est() {
        let mut tracker = FlowTracker::with_defaults();
        let c = tcp_tuple([10,0,0,1], [10,0,0,2], 4000, 443);
        let s = tcp_tuple([10,0,0,2], [10,0,0,1], 443, 4000);
        tracker.process(pkt_tcp(c.clone(), 0.0, 0x02, 0, vec![]));       // SYN
        tracker.process(pkt_tcp(s, 0.1, 0x12, 0, vec![]));       // SYN+ACK
        tracker.process(pkt_tcp(c.clone(), 0.2, 0x10, 1, vec![]));       // ACK
        let key = c.canonical();
        let flow = tracker.get_flow(&key).unwrap();
        assert_eq!(flow.tcp_state, TcpState::Established);
    }

    #[test]
    fn test_rst_closes_flow() {
        let mut tracker = FlowTracker::with_defaults();
        let t = tcp_tuple([1,0,0,1], [1,0,0,2], 1111, 80);
        tracker.process(pkt_tcp(t.clone(), 0.0, 0x02, 0, vec![]));
        tracker.process(pkt_tcp(t.clone(), 0.1, 0x04, 1, vec![])); // RST
        let key = t.canonical();
        let flow = tracker.get_flow(&key).unwrap();
        assert!(flow.closed);
    }

    #[test]
    fn test_udp_flow_tracking() {
        let mut tracker = FlowTracker::with_defaults();
        let t = udp_tuple([1,0,0,1], [8,8,8,8], 5001, 53);
        let pkt = PacketInfo {
            tuple: t,
            ts: 10.0,
            payload_len: 50,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
            payload: vec![0u8; 50],
        };
        tracker.process(pkt);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_expiry_udp() {
        let mut tracker = FlowTracker::with_defaults();
        let t = udp_tuple([1,0,0,1], [1,0,0,2], 4444, 53);
        tracker.process(PacketInfo {
            tuple: t, ts: 0.0, payload_len: 10, tcp_flags: 0,
            tcp_seq: 0, tcp_ack: 0, payload: vec![],
        });
        assert_eq!(tracker.active_count(), 1);
        // Advance time past udp_timeout
        let expired = tracker.expire(100.0);
        assert_eq!(expired, 1);
        assert_eq!(tracker.active_count(), 0);
        let drained = tracker.drain_expired();
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn test_tcp_reassembly_in_order() {
        let mut stream = TcpStream::init(99); // next_seq = 100
        let added = stream.insert(100, b"hello");
        assert_eq!(added, 5);
        assert_eq!(&stream.reassembled, b"hello");
        let added2 = stream.insert(105, b" world");
        assert_eq!(added2, 6);
        assert_eq!(&stream.reassembled, b"hello world");
    }

    #[test]
    fn test_tcp_reassembly_out_of_order() {
        let mut stream = TcpStream::init(0); // next_seq = 1
        stream.insert(6, b"world"); // out of order
        assert_eq!(stream.reassembled, b"");
        stream.insert(1, b"hello"); // in-order — should pull in "world" too
        assert_eq!(&stream.reassembled, b"helloworld");
    }

    /// A retransmission of already-reassembled bytes must not be appended again.
    ///
    /// The assertion used to demand a length of 4 — i.e. that `"AA"` be added
    /// twice — which contradicted both this test's own comment and the
    /// `// retransmit, ignore` branch in `insert`. Appending a retransmit would
    /// duplicate bytes in the reassembled stream, so 2 is the correct answer and
    /// the test had been failing ever since. The return value is asserted too,
    /// so "ignored" cannot quietly become "appended" again.
    #[test]
    fn test_tcp_reassembly_retransmit() {
        let mut stream = TcpStream::init(0);
        assert_eq!(stream.insert(1, b"AA"), 2);
        assert_eq!(stream.insert(1, b"AA"), 0, "a retransmit contributes nothing");
        assert_eq!(stream.reassembled, b"AA", "the stream must not gain a duplicate");
    }

    #[test]
    fn test_seq_lt_wraparound() {
        assert!(seq_lt(0xffff_ffff, 0));
        assert!(!seq_lt(0, 0xffff_ffff));
    }

    #[test]
    fn test_protocol_inference_https() {
        assert_eq!(infer_protocol(45000, 443, 6), Some("HTTPS".to_string()));
    }

    #[test]
    fn test_protocol_inference_dns_udp() {
        assert_eq!(infer_protocol(12345, 53, 17), Some("DNS".to_string()));
    }

    #[test]
    fn test_top_flows_by_bytes() {
        let mut tracker = FlowTracker::with_defaults();
        for i in 0..5u16 {
            let t = udp_tuple([1,0,0,1], [2,0,0,2], 5000 + i, 80);
            for _ in 0..(u64::from(i) + 1) * 100 {
                tracker.process(PacketInfo {
                    tuple: t.clone(), ts: 0.0, payload_len: 1,
                    tcp_flags: 0, tcp_seq: 0, tcp_ack: 0, payload: vec![1],
                });
            }
        }
        let top = tracker.top_flows_by_bytes(3);
        assert_eq!(top.len(), 3);
        assert!(top[0].total_bytes >= top[1].total_bytes);
    }

    #[test]
    fn test_flush_all() {
        let mut tracker = FlowTracker::with_defaults();
        for i in 0..3u16 {
            tracker.process(PacketInfo {
                tuple: udp_tuple([1,0,0,1], [2,0,0,u8::try_from(i).unwrap_or(u8::MAX)], 1000+i, 80),
                ts: 0.0, payload_len: 0, tcp_flags: 0, tcp_seq: 0, tcp_ack: 0, payload: vec![],
            });
        }
        assert_eq!(tracker.active_count(), 3);
        tracker.flush_all();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.drain_expired().len(), 3);
    }

    #[test]
    fn test_direction_stats_throughput() {
        let mut stats = DirectionStats::default();
        stats.update(1000, 0.0);
        stats.update(1000, 1.0);
        let bps = stats.throughput_bps();
        assert!(bps > 0.0);
    }

    #[test]
    fn test_report_structure() {
        let mut tracker = FlowTracker::with_defaults();
        tracker.process(PacketInfo {
            tuple: tcp_tuple([1,0,0,1], [1,0,0,2], 1000, 80),
            ts: 0.0, payload_len: 0, tcp_flags: 0x02, tcp_seq: 0, tcp_ack: 0, payload: vec![],
        });
        let rpt = tracker.report();
        assert_eq!(rpt.active_flows, 1);
        assert_eq!(rpt.tcp_flows, 1);
    }
}
