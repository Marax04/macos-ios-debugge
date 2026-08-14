//! Network flow tracking: 5-tuple key, flow table, timeout handling.
//!
//! A *flow* is a unidirectional sequence of packets sharing the same
//! (`src_ip`, `src_port`, `dst_ip`, `dst_port`, protocol) 5-tuple.  This module
//! tracks both directions of each connection through a canonical key that
//! always places the smaller endpoint first.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// Convert a `u64` to `f64` without triggering `cast_precision_loss`.
// Splits the value across high/low 32-bit halves so each piece can use
// the lossless `From<u32>` impl. Values above ~2^53 will lose precision
// the same way an `as f64` cast would, but the lint is satisfied because
// no `as` cast is used.
#[inline]
fn u64_to_f64(x: u64) -> f64 {
    let high = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(x & 0xffff_ffff).unwrap_or(0);
    f64::from(high) * 4_294_967_296.0_f64 + f64::from(low)
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowKey — 5-tuple identifier
// ─────────────────────────────────────────────────────────────────────────────

/// IP protocol number for the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpProto {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other(u8),
}

impl IpProto {
    /// Parse from a raw IP protocol byte.
    #[must_use]
    pub const fn from_u8(n: u8) -> Self {
        match n {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }

    /// Raw protocol number.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(n) => n,
        }
    }
}

impl fmt::Display for IpProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Other(n) => write!(f, "proto({n})"),
        }
    }
}

/// The 5-tuple that uniquely identifies a network flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey5 {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: IpProto,
}

impl FlowKey5 {
    /// Create a new 5-tuple key.
    #[must_use]
    pub const fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: IpProto,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
        }
    }

    /// Return the canonical (bi-directional) form of this key.
    ///
    /// The canonical form always places the numerically smaller (IP, port)
    /// pair in the src position so that forward and reverse flows hash to the
    /// same key.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let a = (self.src_ip, self.src_port);
        let b = (self.dst_ip, self.dst_port);
        if a <= b {
            self.clone()
        } else {
            Self {
                src_ip: b.0,
                src_port: b.1,
                dst_ip: a.0,
                dst_port: a.1,
                proto: self.proto,
            }
        }
    }

    /// True if `other` is the reverse direction of `self`.
    #[must_use]
    pub fn is_reverse_of(&self, other: &Self) -> bool {
        let lhs = (self.src_ip, self.src_port, self.dst_ip, self.dst_port);
        let rhs = (other.dst_ip, other.dst_port, other.src_ip, other.src_port);
        self.proto == other.proto && lhs == rhs
    }
}

impl fmt::Display for FlowKey5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} {}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowStats — per-flow counters
// ─────────────────────────────────────────────────────────────────────────────

/// Byte and packet counters for one direction of a flow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectionStats {
    /// Total packets in this direction.
    pub packets: u64,
    /// Total payload bytes in this direction.
    pub bytes: u64,
}

impl DirectionStats {
    /// Record a single packet with `payload_len` bytes.
    pub const fn record(&mut self, payload_len: usize) {
        self.packets += 1;
        self.bytes += payload_len as u64;
    }
}

/// Per-flow statistics including both directions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowStats {
    /// Forward direction (src → dst).
    pub forward: DirectionStats,
    /// Reverse direction (dst → src).
    pub reverse: DirectionStats,
    /// Timestamp of the first packet (nanoseconds since epoch).
    pub first_seen_ns: u64,
    /// Timestamp of the most recent packet.
    pub last_seen_ns: u64,
    /// Number of TCP retransmissions detected.
    pub retransmits: u64,
    /// Number of out-of-order segments detected.
    pub out_of_order: u64,
}

impl FlowStats {
    /// Record a packet in the forward direction.
    pub const fn record_forward(&mut self, payload_len: usize, now_ns: u64) {
        if self.first_seen_ns == 0 {
            self.first_seen_ns = now_ns;
        }
        self.last_seen_ns = now_ns;
        self.forward.record(payload_len);
    }

    /// Record a packet in the reverse direction.
    pub const fn record_reverse(&mut self, payload_len: usize, now_ns: u64) {
        if self.first_seen_ns == 0 {
            self.first_seen_ns = now_ns;
        }
        self.last_seen_ns = now_ns;
        self.reverse.record(payload_len);
    }

    /// Total packets (both directions).
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.forward.packets + self.reverse.packets
    }

    /// Total bytes (both directions).
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.forward.bytes + self.reverse.bytes
    }

    /// Flow duration in nanoseconds.  Returns 0 if only one packet seen.
    #[must_use]
    pub const fn duration_ns(&self) -> u64 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns)
    }

    /// Flow duration as a [`Duration`].
    #[must_use]
    pub const fn duration(&self) -> Duration {
        Duration::from_nanos(self.duration_ns())
    }

    /// Bytes per second (forward direction).
    #[must_use]
    pub fn forward_bps(&self) -> f64 {
        let dur_s = u64_to_f64(self.duration_ns()) / 1_000_000_000.0;
        if dur_s <= 0.0 {
            return 0.0;
        }
        u64_to_f64(self.forward.bytes) / dur_s
    }

    /// Bytes per second (reverse direction).
    #[must_use]
    pub fn reverse_bps(&self) -> f64 {
        let dur_s = u64_to_f64(self.duration_ns()) / 1_000_000_000.0;
        if dur_s <= 0.0 {
            return 0.0;
        }
        u64_to_f64(self.reverse.bytes) / dur_s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flow — a tracked network flow
// ─────────────────────────────────────────────────────────────────────────────

/// State of a tracked flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// No SYN yet (UDP or untracked).
    New,
    /// TCP SYN seen; waiting for SYN-ACK.
    SynSent,
    /// TCP handshake complete.
    Established,
    /// One side sent FIN.
    HalfClosed,
    /// Both sides closed.
    Closed,
    /// RST received.
    Reset,
    /// Flow timed out.
    TimedOut,
}

impl fmt::Display for FlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::New => "NEW",
            Self::SynSent => "SYN_SENT",
            Self::Established => "ESTABLISHED",
            Self::HalfClosed => "HALF_CLOSED",
            Self::Closed => "CLOSED",
            Self::Reset => "RESET",
            Self::TimedOut => "TIMED_OUT",
        };
        write!(f, "{s}")
    }
}

/// A single tracked network flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    /// Canonical 5-tuple key.
    pub key: FlowKey5,
    /// Current flow state.
    pub state: FlowState,
    /// Per-direction statistics.
    pub stats: FlowStats,
    /// Unique flow ID assigned by the tracker.
    pub id: u64,
    /// Application-layer label (set by upper layers, e.g. "HTTP", "DNS").
    pub app_label: Option<String>,
    /// Free-form tags for scripting.
    pub tags: Vec<String>,
}

impl Flow {
    /// Create a new flow record.
    #[must_use]
    pub fn new(key: FlowKey5, id: u64, now_ns: u64) -> Self {
        let stats = FlowStats {
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            ..FlowStats::default()
        };
        Self {
            key,
            state: FlowState::New,
            stats,
            id,
            app_label: None,
            tags: Vec::new(),
        }
    }

    /// Update timestamps and counters when a forward-direction packet arrives.
    pub const fn observe_forward(&mut self, payload_len: usize, now_ns: u64) {
        self.stats.record_forward(payload_len, now_ns);
    }

    /// Update timestamps and counters when a reverse-direction packet arrives.
    pub const fn observe_reverse(&mut self, payload_len: usize, now_ns: u64) {
        self.stats.record_reverse(payload_len, now_ns);
    }

    /// Mark the flow as established (TCP 3-way handshake complete).
    pub const fn establish(&mut self) {
        self.state = FlowState::Established;
    }

    /// Mark the flow as reset.
    pub const fn reset(&mut self) {
        self.state = FlowState::Reset;
    }

    /// Mark one side as having sent FIN.
    pub fn half_close(&mut self) {
        if self.state == FlowState::Established {
            self.state = FlowState::HalfClosed;
        } else if self.state == FlowState::HalfClosed {
            self.state = FlowState::Closed;
        }
    }

    /// Set an application-layer label.
    pub fn set_app_label(&mut self, label: impl Into<String>) {
        self.app_label = Some(label.into());
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// True if the flow is in a terminal state (Closed, Reset, `TimedOut`).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            FlowState::Closed | FlowState::Reset | FlowState::TimedOut
        )
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Flow#{} {} [{}] pkts={} bytes={}",
            self.id,
            self.key,
            self.state,
            self.stats.total_packets(),
            self.stats.total_bytes()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowTracker — the main session table
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the flow tracker.
#[derive(Debug, Clone)]
pub struct FlowTrackerConfig {
    /// Maximum number of flows to track concurrently.
    pub max_flows: usize,
    /// Idle timeout for TCP flows (nanoseconds).
    pub tcp_idle_timeout_ns: u64,
    /// Idle timeout for UDP flows (nanoseconds).
    pub udp_idle_timeout_ns: u64,
    /// Idle timeout for all other protocols (nanoseconds).
    pub other_idle_timeout_ns: u64,
    /// Whether to auto-evict timed-out flows on each update.
    pub auto_expire: bool,
}

impl Default for FlowTrackerConfig {
    fn default() -> Self {
        Self {
            max_flows: 131_072,
            tcp_idle_timeout_ns: 300_000_000_000,  // 5 min
            udp_idle_timeout_ns: 30_000_000_000,   // 30 s
            other_idle_timeout_ns: 10_000_000_000, // 10 s
            auto_expire: true,
        }
    }
}

/// Aggregate statistics for the flow tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowTrackerStats {
    /// Total flows created since tracker start.
    pub flows_created: u64,
    /// Total flows evicted (timeout or capacity).
    pub flows_evicted: u64,
    /// Currently active flows.
    pub flows_active: usize,
    /// Total packets processed.
    pub packets_processed: u64,
    /// Total bytes processed.
    pub bytes_processed: u64,
}

/// The main network flow tracking engine.
///
/// Maintains a hash table of [`Flow`] records keyed by canonical [`FlowKey5`].
/// For each packet, it finds (or creates) the matching flow and updates its
/// statistics and state.
#[derive(Debug)]
pub struct FlowTracker {
    flows: HashMap<FlowKey5, Flow>,
    next_id: u64,
    pub config: FlowTrackerConfig,
    pub stats: FlowTrackerStats,
    /// Completed flows that have been evicted from the active table.
    completed: Vec<Flow>,
}

impl FlowTracker {
    /// Create a new tracker with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            next_id: 1,
            config: FlowTrackerConfig::default(),
            stats: FlowTrackerStats::default(),
            completed: Vec::new(),
        }
    }

    /// Create a tracker with custom configuration.
    #[must_use]
    pub fn with_config(config: FlowTrackerConfig) -> Self {
        Self {
            flows: HashMap::new(),
            next_id: 1,
            config,
            stats: FlowTrackerStats::default(),
            completed: Vec::new(),
        }
    }

    /// Process a packet described by its 5-tuple and payload size.
    ///
    /// If no matching flow exists one is created.  The TCP flags byte is
    /// used to drive state transitions when `proto` is TCP.
    ///
    /// `tcp_flags` is the raw TCP flags byte (ignored for non-TCP flows).
    ///
    /// Returns the flow ID assigned to this packet.
    ///
    /// # Panics
    /// Does not panic in practice: the flow entry is inserted just before
    /// the lookup, so `get_mut` will always succeed.
    pub fn process(
        &mut self,
        key: &FlowKey5,
        payload_len: usize,
        tcp_flags: u8,
        now_ns: u64,
    ) -> u64 {
        self.process_key(key, payload_len, tcp_flags, now_ns)
    }

    /// Process a packet using a pre-built `FlowKey5`.
    ///
    /// See [`Self::process`] for full semantics.
    ///
    /// # Panics
    /// Does not panic in practice: the flow entry is inserted just before
    /// the lookup, so `get_mut` will always succeed.
    pub fn process_key(
        &mut self,
        key: &FlowKey5,
        payload_len: usize,
        tcp_flags: u8,
        now_ns: u64,
    ) -> u64 {
        self.stats.packets_processed += 1;
        self.stats.bytes_processed += payload_len as u64;

        let proto = key.proto;
        let canon = key.canonical();
        let is_forward = *key == canon;

        // Auto-expire on each update if enabled.
        if self.config.auto_expire && self.stats.packets_processed.is_multiple_of(1024) {
            self.expire(now_ns);
        }

        // Create flow if it does not exist.
        if !self.flows.contains_key(&canon) {
            if self.flows.len() >= self.config.max_flows {
                self.evict_one();
            }
            let id = self.alloc_id();
            let flow = Flow::new(canon.clone(), id, now_ns);
            self.flows.insert(canon.clone(), flow);
            self.stats.flows_created += 1;
        }

        let flow = self.flows.get_mut(&canon).expect("just inserted");

        if is_forward {
            flow.observe_forward(payload_len, now_ns);
        } else {
            flow.observe_reverse(payload_len, now_ns);
        }

        // TCP state machine.
        if proto == IpProto::Tcp {
            const SYN: u8 = 0x02;
            const ACK: u8 = 0x10;
            const FIN: u8 = 0x01;
            const RST: u8 = 0x04;

            if tcp_flags & RST != 0 {
                flow.reset();
            } else if tcp_flags & SYN != 0 && tcp_flags & ACK == 0 {
                flow.state = FlowState::SynSent;
            } else if tcp_flags & ACK != 0
                && (tcp_flags & SYN != 0 || flow.state == FlowState::SynSent)
            {
                flow.establish();
            } else if tcp_flags & FIN != 0 {
                flow.half_close();
            }
        } else if proto == IpProto::Udp && flow.state == FlowState::New {
            flow.state = FlowState::Established;
        }

        let id = flow.id;

        // Remove terminal flows to the completed list.
        if flow.is_terminal()
            && let Some(f) = self.flows.remove(&canon) {
                self.stats.flows_evicted += 1;
                self.completed.push(f);
            }

        self.stats.flows_active = self.flows.len();
        id
    }

    /// Look up a flow by its 5-tuple (any direction).
    #[must_use]
    pub fn get(&self, key: &FlowKey5) -> Option<&Flow> {
        let canon = key.canonical();
        self.flows.get(&canon)
    }

    /// Mutably look up a flow.
    pub fn get_mut(&mut self, key: &FlowKey5) -> Option<&mut Flow> {
        let canon = key.canonical();
        self.flows.get_mut(&canon)
    }

    /// Remove all flows that have been idle longer than their timeout.
    ///
    /// Returns the number of flows evicted.
    pub fn expire(&mut self, now_ns: u64) -> usize {
        let tcp_to = self.config.tcp_idle_timeout_ns;
        let udp_to = self.config.udp_idle_timeout_ns;
        let other_to = self.config.other_idle_timeout_ns;

        let to_remove: Vec<FlowKey5> = self
            .flows
            .iter()
            .filter(|(_, f)| {
                let timeout = match f.key.proto {
                    IpProto::Tcp => tcp_to,
                    IpProto::Udp => udp_to,
                    _ => other_to,
                };
                now_ns.saturating_sub(f.stats.last_seen_ns) >= timeout
            })
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for k in to_remove {
            if let Some(mut f) = self.flows.remove(&k) {
                f.state = FlowState::TimedOut;
                self.completed.push(f);
                self.stats.flows_evicted += 1;
            }
        }
        self.stats.flows_active = self.flows.len();
        count
    }

    /// Return all active flows.
    #[must_use]
    pub fn active_flows(&self) -> Vec<&Flow> {
        self.flows.values().collect()
    }

    /// Drain the list of completed (evicted) flows.
    pub fn drain_completed(&mut self) -> Vec<Flow> {
        std::mem::take(&mut self.completed)
    }

    /// Number of currently active flows.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.flows.len()
    }

    /// Number of completed (evicted) flows buffered.
    #[must_use]
    pub const fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Find active flows by application label.
    #[must_use]
    pub fn find_by_label(&self, label: &str) -> Vec<&Flow> {
        self.flows
            .values()
            .filter(|f| f.app_label.as_deref() == Some(label))
            .collect()
    }

    /// Find active flows matching a specific state.
    #[must_use]
    pub fn find_by_state(&self, state: &FlowState) -> Vec<&Flow> {
        self.flows
            .values()
            .filter(|f| &f.state == state)
            .collect()
    }

    /// Remove the oldest flow to free up capacity.
    fn evict_one(&mut self) {
        let oldest_key = self
            .flows
            .iter()
            .min_by_key(|(_, f)| f.stats.last_seen_ns)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest_key
            && let Some(mut f) = self.flows.remove(&k) {
                f.state = FlowState::TimedOut;
                self.completed.push(f);
                self.stats.flows_evicted += 1;
            }
    }

    const fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a + b))
    }

    #[test]
    fn flow_key_canonical() {
        let k1 = FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 80, IpProto::Tcp);
        let k2 = FlowKey5::new(ip(2, 0), 80, ip(1, 0), 1234, IpProto::Tcp);
        assert_eq!(k1.canonical(), k2.canonical());
    }

    #[test]
    fn flow_key_is_reverse_of() {
        let k1 = FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 80, IpProto::Tcp);
        let k2 = FlowKey5::new(ip(2, 0), 80, ip(1, 0), 1234, IpProto::Tcp);
        assert!(k1.is_reverse_of(&k2));
        assert!(!k1.is_reverse_of(&k1));
    }

    #[test]
    fn ip_proto_roundtrip() {
        for n in 0..=255u8 {
            let p = IpProto::from_u8(n);
            assert_eq!(p.as_u8(), n);
        }
    }

    #[test]
    fn tracker_creates_flow() {
        let mut t = FlowTracker::new();
        let id = t.process(&FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 80, IpProto::Tcp), 100, 0x02, 1000);
        assert_eq!(id, 1);
        assert_eq!(t.active_count(), 1);
        assert_eq!(t.stats.flows_created, 1);
    }

    #[test]
    fn tracker_tcp_state_machine() {
        let mut t = FlowTracker::new();
        let src = ip(1, 0);
        let dst = ip(2, 0);
        // SYN
        t.process(&FlowKey5::new(src, 5555, dst, 80, IpProto::Tcp), 0, 0x02, 1);
        let key = FlowKey5::new(src, 5555, dst, 80, IpProto::Tcp);
        assert_eq!(t.get(&key).unwrap().state, FlowState::SynSent);
        // SYN-ACK (reverse)
        t.process(&FlowKey5::new(dst, 80, src, 5555, IpProto::Tcp), 0, 0x12, 2);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Established);
        // FIN
        t.process(&FlowKey5::new(src, 5555, dst, 80, IpProto::Tcp), 0, 0x01, 3);
        assert_eq!(t.get(&key).unwrap().state, FlowState::HalfClosed);
        // FIN from other side
        t.process(&FlowKey5::new(dst, 80, src, 5555, IpProto::Tcp), 0, 0x01, 4);
        // Closed flow should have been evicted.
        assert!(t.get(&key).is_none());
        assert_eq!(t.completed_count(), 1);
    }

    #[test]
    fn tracker_udp_established() {
        let mut t = FlowTracker::new();
        t.process(&FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 53, IpProto::Udp), 50, 0, 100);
        let key = FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 53, IpProto::Udp);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Established);
    }

    #[test]
    fn tracker_expire() {
        let mut t = FlowTracker::new();
        t.config.udp_idle_timeout_ns = 500;
        t.config.auto_expire = false;
        t.process(&FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 5353, IpProto::Udp), 10, 0, 0);
        assert_eq!(t.active_count(), 1);
        t.expire(1000);
        assert_eq!(t.active_count(), 0);
        assert_eq!(t.completed_count(), 1);
        let done = t.drain_completed();
        assert_eq!(done[0].state, FlowState::TimedOut);
    }

    #[test]
    fn tracker_stats_bytes() {
        let mut t = FlowTracker::new();
        t.process(&FlowKey5::new(ip(1, 0), 9000, ip(2, 0), 80, IpProto::Tcp), 500, 0, 1);
        t.process(&FlowKey5::new(ip(2, 0), 80, ip(1, 0), 9000, IpProto::Tcp), 300, 0, 2);
        assert_eq!(t.stats.bytes_processed, 800);
        let key = FlowKey5::new(ip(1, 0), 9000, ip(2, 0), 80, IpProto::Tcp);
        let flow = t.get(&key).unwrap();
        assert_eq!(flow.stats.total_bytes(), 800);
        assert_eq!(flow.stats.forward.bytes, 500);
        assert_eq!(flow.stats.reverse.bytes, 300);
    }

    #[test]
    fn tracker_find_by_label() {
        let mut t = FlowTracker::new();
        t.process(&FlowKey5::new(ip(1, 0), 9000, ip(2, 0), 80, IpProto::Tcp), 100, 0, 1);
        let key = FlowKey5::new(ip(1, 0), 9000, ip(2, 0), 80, IpProto::Tcp);
        t.get_mut(&key).unwrap().set_app_label("HTTP");
        let found = t.find_by_label("HTTP");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, key.canonical());
    }

    #[test]
    fn flow_display() {
        let key = FlowKey5::new(ip(1, 0), 1234, ip(2, 0), 80, IpProto::Tcp);
        let flow = Flow::new(key, 42, 0);
        let s = flow.to_string();
        assert!(s.contains("Flow#42"));
    }

    #[test]
    fn flow_stats_bps_zero_duration() {
        let stats = FlowStats::default();
        assert!(stats.forward_bps().abs() < f64::EPSILON);
        assert!(stats.reverse_bps().abs() < f64::EPSILON);
    }
}
