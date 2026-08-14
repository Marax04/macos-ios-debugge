//! Packet filtering: BPF-style filter expressions with JIT-like evaluation.
//!
//! Provides a rich filter expression AST, a compiler that produces a
//! flat opcode list, and a fast evaluator that runs the compiled filter
//! against raw Ethernet/IPv4/IPv6 packet bytes.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Filter primitives ────────────────────────────────────────────────────────

/// An IPv4 address + prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Prefix {
    pub addr: [u8; 4],
    pub prefix_len: u8,
}

impl Ipv4Prefix {
    #[must_use] 
    pub const fn new(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Self {
        Self { addr: [a, b, c, d], prefix_len: prefix }
    }

    /// Returns `true` if `ip` matches this prefix.
    #[must_use] 
    pub fn matches(&self, ip: &[u8; 4]) -> bool {
        if self.prefix_len == 0 { return true; }
        if self.prefix_len >= 32 { return self.addr == *ip; }
        let mask = !((1u32 << (32 - self.prefix_len)) - 1);
        let self_addr = u32::from_be_bytes(self.addr);
        let other_addr = u32::from_be_bytes(*ip);
        (self_addr & mask) == (other_addr & mask)
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}/{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.prefix_len
        )
    }
}

// ─── FilterOp ─────────────────────────────────────────────────────────────────

/// A single compiled filter operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOp {
    /// Load 1 byte from packet at absolute offset into accumulator.
    LoadByte(u16),
    /// Load 2 bytes (big-endian) from packet at absolute offset.
    LoadHalf(u16),
    /// Load 4 bytes (big-endian) from packet at absolute offset.
    LoadWord(u16),
    /// AND accumulator with constant.
    AndImm(u32),
    /// Compare accumulator == constant; push bool.
    CmpEq(u32),
    /// Compare accumulator != constant.
    CmpNe(u32),
    /// Compare accumulator > constant (unsigned).
    CmpGt(u32),
    /// Compare accumulator >= constant (unsigned).
    CmpGe(u32),
    /// Compare accumulator < constant (unsigned).
    CmpLt(u32),
    /// Logical AND of top two stack booleans.
    BoolAnd,
    /// Logical OR of top two stack booleans.
    BoolOr,
    /// Logical NOT of top stack boolean.
    BoolNot,
    /// Push a literal boolean.
    PushBool(bool),
    /// Jump forward by N ops if top-of-stack is false (short-circuit AND).
    JumpIfFalse(usize),
    /// Jump forward by N ops if top-of-stack is true (short-circuit OR).
    JumpIfTrue(usize),
}

// ─── FilterExpr ───────────────────────────────────────────────────────────────

/// A hierarchical filter expression tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterExpr {
    /// Accepts every packet.
    True,
    /// Rejects every packet.
    False,
    /// Accept if Ethernet ethertype == value.
    EtherType(u16),
    /// Accept IPv4 packets.
    Ipv4,
    /// Accept IPv6 packets.
    Ipv6,
    /// Accept ARP packets.
    Arp,
    /// Accept packets with IP protocol == value (requires IPv4).
    IpProto(u8),
    /// Accept TCP packets.
    Tcp,
    /// Accept UDP packets.
    Udp,
    /// Accept ICMP packets.
    Icmp,
    /// Accept packets with src or dst port == value.
    Port(u16),
    /// Accept packets with TCP/UDP source port == value.
    SrcPort(u16),
    /// Accept packets with TCP/UDP destination port == value.
    DstPort(u16),
    /// Accept packets whose IPv4 source address matches the prefix.
    SrcHost(Ipv4Prefix),
    /// Accept packets whose IPv4 destination address matches the prefix.
    DstHost(Ipv4Prefix),
    /// Accept packets with a specific VLAN tag (802.1Q).
    Vlan(u16),
    /// Accept packets whose total length is greater than `n`.
    LenGt(u16),
    /// Accept packets whose total length is less than `n`.
    LenLt(u16),
    /// Accept packets whose total length equals `n`.
    LenEq(u16),
    /// Accept packets containing the given byte sequence at any offset.
    Contains(Vec<u8>),
    /// Logical AND of two expressions.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two expressions.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of an expression.
    Not(Box<Self>),
}

impl FilterExpr {
    /// Compile this expression into a flat list of [`FilterOp`]s.
    #[must_use] 
    pub fn compile(&self) -> CompiledFilter {
        let mut ops = Vec::new();
        emit_expr(self, &mut ops);
        CompiledFilter { ops }
    }

    /// Convenience: build `And`.
    #[must_use] 
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }

    /// Convenience: build `Or`.
    #[must_use] 
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }

    /// Convenience: build `Not`.
    #[must_use] 
    pub fn not(a: Self) -> Self {
        Self::Not(Box::new(a))
    }
}

impl fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::EtherType(et) => write!(f, "ether proto 0x{et:04x}"),
            Self::Ipv4 => write!(f, "ip"),
            Self::Ipv6 => write!(f, "ip6"),
            Self::Arp => write!(f, "arp"),
            Self::IpProto(p) => write!(f, "ip proto {p}"),
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Port(p) => write!(f, "port {p}"),
            Self::SrcPort(p) => write!(f, "src port {p}"),
            Self::DstPort(p) => write!(f, "dst port {p}"),
            Self::SrcHost(pfx) => write!(f, "src host {pfx}"),
            Self::DstHost(pfx) => write!(f, "dst host {pfx}"),
            Self::Vlan(id) => write!(f, "vlan {id}"),
            Self::LenGt(n) => write!(f, "len > {n}"),
            Self::LenLt(n) => write!(f, "len < {n}"),
            Self::LenEq(n) => write!(f, "len == {n}"),
            Self::Contains(_) => write!(f, "contains(...)"),
            Self::And(a, b) => write!(f, "({a} and {b})"),
            Self::Or(a, b) => write!(f, "({a} or {b})"),
            Self::Not(e) => write!(f, "not {e}"),
        }
    }
}

// ─── Compiler ─────────────────────────────────────────────────────────────────

/// Emit filter ops for `expr` into `out`.
fn emit_expr(expr: &FilterExpr, out: &mut Vec<FilterOp>) {
    match expr {
        FilterExpr::True => {
            out.push(FilterOp::PushBool(true));
        }
        FilterExpr::False => {
            out.push(FilterOp::PushBool(false));
        }
        FilterExpr::EtherType(et) => {
            // Ethernet type field is at offset 12 (16-bit, big-endian).
            out.push(FilterOp::LoadHalf(12));
            out.push(FilterOp::CmpEq(u32::from(*et)));
        }
        FilterExpr::Ipv4 => emit_expr(&FilterExpr::EtherType(0x0800), out),
        FilterExpr::Ipv6 => emit_expr(&FilterExpr::EtherType(0x86DD), out),
        FilterExpr::Arp => emit_expr(&FilterExpr::EtherType(0x0806), out),
        FilterExpr::IpProto(proto) => {
            // Requires IPv4: ethertype check + IP protocol byte at offset 23.
            emit_expr(&FilterExpr::Ipv4, out);
            let jump_over = 2usize;
            out.push(FilterOp::JumpIfFalse(jump_over));
            out.push(FilterOp::LoadByte(23));
            out.push(FilterOp::CmpEq(u32::from(*proto)));
        }
        FilterExpr::Tcp => emit_expr(&FilterExpr::IpProto(6), out),
        FilterExpr::Udp => emit_expr(&FilterExpr::IpProto(17), out),
        FilterExpr::Icmp => emit_expr(&FilterExpr::IpProto(1), out),
        FilterExpr::Port(p) => {
            emit_expr(&FilterExpr::Or(
                Box::new(FilterExpr::SrcPort(*p)),
                Box::new(FilterExpr::DstPort(*p)),
            ), out);
        }
        FilterExpr::SrcPort(p) => {
            // TCP/UDP src port at offset 34 (14 Eth + 20 IP).
            out.push(FilterOp::LoadHalf(34));
            out.push(FilterOp::CmpEq(u32::from(*p)));
        }
        FilterExpr::DstPort(p) => {
            // TCP/UDP dst port at offset 36.
            out.push(FilterOp::LoadHalf(36));
            out.push(FilterOp::CmpEq(u32::from(*p)));
        }
        FilterExpr::SrcHost(pfx) => {
            // IPv4 src addr at offset 26 (14 Eth + 12).
            out.push(FilterOp::LoadWord(26));
            let mask = if pfx.prefix_len >= 32 { 0xFFFF_FFFF } else {
                !((1u32 << (32 - pfx.prefix_len)) - 1)
            };
            out.push(FilterOp::AndImm(mask));
            let expected = u32::from_be_bytes(pfx.addr) & mask;
            out.push(FilterOp::CmpEq(expected));
        }
        FilterExpr::DstHost(pfx) => {
            // IPv4 dst addr at offset 30.
            out.push(FilterOp::LoadWord(30));
            let mask = if pfx.prefix_len >= 32 { 0xFFFF_FFFF } else {
                !((1u32 << (32 - pfx.prefix_len)) - 1)
            };
            out.push(FilterOp::AndImm(mask));
            let expected = u32::from_be_bytes(pfx.addr) & mask;
            out.push(FilterOp::CmpEq(expected));
        }
        FilterExpr::Vlan(id) => {
            // 802.1Q: ethertype 0x8100 at offset 12, VLAN ID in lower 12 bits at offset 14.
            emit_expr(&FilterExpr::EtherType(0x8100), out);
            let jump = 3usize;
            out.push(FilterOp::JumpIfFalse(jump));
            out.push(FilterOp::LoadHalf(14));
            out.push(FilterOp::AndImm(0x0FFF));
            out.push(FilterOp::CmpEq(u32::from(*id)));
        }
        FilterExpr::LenGt(n) => {
            // Packet length comparison — we encode this as a special CmpGt.
            out.push(FilterOp::LoadWord(0xFFFF)); // special sentinel: packet length
            out.push(FilterOp::CmpGt(u32::from(*n)));
        }
        FilterExpr::LenLt(n) => {
            out.push(FilterOp::LoadWord(0xFFFF));
            out.push(FilterOp::CmpLt(u32::from(*n)));
        }
        FilterExpr::LenEq(n) => {
            out.push(FilterOp::LoadWord(0xFFFF));
            out.push(FilterOp::CmpEq(u32::from(*n)));
        }
        FilterExpr::Contains(needle) => {
            // Inline contains as a PushBool placeholder — actual evaluation
            // is handled separately by the evaluator.
            let encoded: u32 = needle.iter().take(4).enumerate()
                .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (i * 8)));
            out.push(FilterOp::LoadWord(0xFFFE)); // sentinel: contains check
            out.push(FilterOp::CmpEq(encoded)); // evaluator uses needle via context
        }
        FilterExpr::And(a, b) => {
            emit_expr(a, out);
            // Short-circuit: if a is false, jump over b.
            let placeholder = out.len();
            out.push(FilterOp::JumpIfFalse(0)); // placeholder
            emit_expr(b, out);
            let jump_dist = out.len() - placeholder - 1;
            out[placeholder] = FilterOp::JumpIfFalse(jump_dist);
            out.push(FilterOp::BoolAnd);
        }
        FilterExpr::Or(a, b) => {
            emit_expr(a, out);
            // Short-circuit: if a is true, jump over b.
            let placeholder = out.len();
            out.push(FilterOp::JumpIfTrue(0)); // placeholder
            emit_expr(b, out);
            let jump_dist = out.len() - placeholder - 1;
            out[placeholder] = FilterOp::JumpIfTrue(jump_dist);
            out.push(FilterOp::BoolOr);
        }
        FilterExpr::Not(inner) => {
            emit_expr(inner, out);
            out.push(FilterOp::BoolNot);
        }
    }
}

// ─── CompiledFilter ───────────────────────────────────────────────────────────

/// A compiled filter ready for fast evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledFilter {
    pub ops: Vec<FilterOp>,
}

impl CompiledFilter {
    /// Return the number of ops.
    #[must_use] 
    pub const fn len(&self) -> usize { self.ops.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.ops.is_empty() }
}

// ─── PacketFilter ─────────────────────────────────────────────────────────────

/// Applies compiled filters to packet byte slices.
pub struct PacketFilter {
    filter: CompiledFilter,
    /// Optional contains needles for runtime checks.
    contains: Vec<Vec<u8>>,
}

impl PacketFilter {
    /// Create a filter from an expression.
    #[must_use] 
    pub fn from_expr(expr: &FilterExpr) -> Self {
        let contains = collect_contains(expr);
        Self { filter: expr.compile(), contains }
    }

    /// Create a filter from a pre-compiled filter (no contains support).
    #[must_use] 
    pub const fn from_compiled(filter: CompiledFilter) -> Self {
        Self { filter, contains: vec![] }
    }

    /// Apply the filter to a packet.  Returns `true` if the packet is accepted.
    #[must_use] 
    pub fn apply(&self, packet: &[u8]) -> bool {
        apply_filter(&self.filter.ops, packet, &self.contains)
    }

    /// Filter a slice of packets, returning indices that pass.
    #[must_use] 
    pub fn filter_indices(&self, packets: &[Vec<u8>]) -> Vec<usize> {
        packets
            .iter()
            .enumerate()
            .filter(|(_, p)| self.apply(p))
            .map(|(i, _)| i)
            .collect()
    }

    /// Return the number of ops in the compiled filter.
    #[must_use] 
    pub const fn op_count(&self) -> usize { self.filter.len() }
}

/// Collect all `Contains` needle vectors from an expression tree.
fn collect_contains(expr: &FilterExpr) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    collect_contains_inner(expr, &mut out);
    out
}

fn collect_contains_inner(expr: &FilterExpr, out: &mut Vec<Vec<u8>>) {
    match expr {
        FilterExpr::Contains(n) => out.push(n.clone()),
        FilterExpr::And(a, b) | FilterExpr::Or(a, b) => {
            collect_contains_inner(a, out);
            collect_contains_inner(b, out);
        }
        FilterExpr::Not(e) => collect_contains_inner(e, out),
        _ => {}
    }
}

// ─── Evaluator ────────────────────────────────────────────────────────────────

/// Execute `ops` against `packet`. Returns `true` if the filter accepts.
#[must_use] 
pub fn apply_filter(ops: &[FilterOp], packet: &[u8], needles: &[Vec<u8>]) -> bool {
    let mut stack: Vec<bool> = Vec::with_capacity(8);
    let mut acc: u32 = 0;
    let mut pc = 0usize;
    let plen = u32::try_from(packet.len()).unwrap_or(u32::MAX);

    while pc < ops.len() {
        match &ops[pc] {
            FilterOp::LoadByte(off) => {
                let off = *off as usize;
                acc = if off < packet.len() { u32::from(packet[off]) } else { 0 };
            }
            FilterOp::LoadHalf(off) => {
                let off = *off as usize;
                acc = if off + 1 < packet.len() {
                    u32::from(u16::from_be_bytes([packet[off], packet[off + 1]]))
                } else { 0 };
            }
            FilterOp::LoadWord(off) => {
                let off = *off as usize;
                if off == 0xFFFF {
                    acc = plen;
                } else if off == 0xFFFE {
                    // contains check — push result immediately
                    let found = needles.iter().any(|n| find_bytes(n, packet));
                    stack.push(found);
                    pc += 1;
                } else if off + 3 < packet.len() {
                    acc = u32::from_be_bytes([packet[off], packet[off+1], packet[off+2], packet[off+3]]);
                } else { acc = 0; }
            }
            FilterOp::AndImm(mask) => { acc &= mask; }
            FilterOp::CmpEq(v) => { stack.push(acc == *v); }
            FilterOp::CmpNe(v) => { stack.push(acc != *v); }
            FilterOp::CmpGt(v) => { stack.push(acc > *v); }
            FilterOp::CmpGe(v) => { stack.push(acc >= *v); }
            FilterOp::CmpLt(v) => { stack.push(acc < *v); }
            FilterOp::BoolAnd => {
                let b = stack.pop().unwrap_or(false);
                let a = stack.pop().unwrap_or(false);
                stack.push(a && b);
            }
            FilterOp::BoolOr => {
                let b = stack.pop().unwrap_or(false);
                let a = stack.pop().unwrap_or(false);
                stack.push(a || b);
            }
            FilterOp::BoolNot => {
                let v = stack.pop().unwrap_or(false);
                stack.push(!v);
            }
            FilterOp::PushBool(v) => { stack.push(*v); }
            FilterOp::JumpIfFalse(n) => {
                if !stack.last().copied().unwrap_or(false) {
                    pc += n;
                }
            }
            FilterOp::JumpIfTrue(n) => {
                if stack.last().copied().unwrap_or(false) {
                    pc += n;
                }
            }
        }
        pc += 1;
    }

    stack.pop().unwrap_or(false)
}

/// Naive substring search.
fn find_bytes(needle: &[u8], haystack: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── FilterStats ─────────────────────────────────────────────────────────────

/// Tracks how many packets passed/failed a filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterStats {
    pub total: u64,
    pub accepted: u64,
    pub rejected: u64,
}

impl FilterStats {
    pub const fn record(&mut self, accepted: bool) {
        self.total += 1;
        if accepted { self.accepted += 1; } else { self.rejected += 1; }
    }

    #[must_use] 
    pub fn acceptance_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.accepted as f64 / self.total as f64 }
    }
}

impl fmt::Display for FilterStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FilterStats: total={} accepted={} rejected={} rate={:.1}%",
            self.total, self.accepted, self.rejected,
            self.acceptance_rate() * 100.0,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/TCP packet.
    fn make_eth_ipv4_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 54];
        // Ethernet ethertype = 0x0800
        p[12] = 0x08; p[13] = 0x00;
        // IP protocol = 6 (TCP)
        p[23] = 6;
        // Src port
        // Big-endian, both bytes. `u8::try_from(port).unwrap_or(u8::MAX)` is
        // not a truncation: it *fails* above 255 and substitutes 0xFF, so
        // every port >= 256 was encoded wrong — 443 became 0x01FF (511), which
        // is why `test_filter_and` could not match its own packet.
        p[34..36].copy_from_slice(&src_port.to_be_bytes());
        p[36..38].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    fn make_eth_arp() -> Vec<u8> {
        let mut p = vec![0u8; 42];
        p[12] = 0x08; p[13] = 0x06;
        p
    }

    #[test]
    fn test_filter_true() {
        let f = PacketFilter::from_expr(&FilterExpr::True);
        assert!(f.apply(&[0u8; 64]));
    }

    #[test]
    fn test_filter_false() {
        let f = PacketFilter::from_expr(&FilterExpr::False);
        assert!(!f.apply(&[0u8; 64]));
    }

    #[test]
    fn test_filter_ipv4() {
        let f = PacketFilter::from_expr(&FilterExpr::Ipv4);
        let pkt = make_eth_ipv4_tcp(1234, 80);
        assert!(f.apply(&pkt));

        let arp = make_eth_arp();
        assert!(!f.apply(&arp));
    }

    #[test]
    fn test_filter_tcp() {
        let f = PacketFilter::from_expr(&FilterExpr::Tcp);
        let pkt = make_eth_ipv4_tcp(12345, 443);
        assert!(f.apply(&pkt));
    }

    #[test]
    fn test_filter_dst_port() {
        let f = PacketFilter::from_expr(&FilterExpr::DstPort(80));
        let hit = make_eth_ipv4_tcp(54321, 80);
        let miss = make_eth_ipv4_tcp(54321, 443);
        assert!(f.apply(&hit));
        assert!(!f.apply(&miss));
    }

    #[test]
    fn test_filter_src_host() {
        let pfx = Ipv4Prefix::new(10, 0, 0, 0, 8);
        let f = PacketFilter::from_expr(&FilterExpr::SrcHost(pfx));
        let mut pkt = vec![0u8; 54];
        pkt[12] = 0x08; pkt[13] = 0x00;
        pkt[26] = 10; pkt[27] = 1; pkt[28] = 2; pkt[29] = 3; // 10.1.2.3
        assert!(f.apply(&pkt));
        pkt[26] = 192; // 192.1.2.3
        assert!(!f.apply(&pkt));
    }

    #[test]
    fn test_filter_and() {
        let f = PacketFilter::from_expr(&FilterExpr::and(FilterExpr::Tcp, FilterExpr::DstPort(443)));
        let hit = make_eth_ipv4_tcp(1234, 443);
        let miss = make_eth_ipv4_tcp(1234, 80);
        assert!(f.apply(&hit));
        assert!(!f.apply(&miss));
    }

    #[test]
    fn test_filter_not() {
        let f = PacketFilter::from_expr(&FilterExpr::not(FilterExpr::Arp));
        let tcp = make_eth_ipv4_tcp(1, 2);
        let arp = make_eth_arp();
        assert!(f.apply(&tcp));
        assert!(!f.apply(&arp));
    }

    #[test]
    fn test_filter_contains() {
        let needle = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let f = PacketFilter::from_expr(&FilterExpr::Contains(needle.clone()));
        let mut pkt = vec![0u8; 64];
        pkt[20..24].copy_from_slice(&needle);
        assert!(f.apply(&pkt));
        let empty = vec![0u8; 64];
        assert!(!f.apply(&empty));
    }

    #[test]
    fn test_len_gt() {
        let f = PacketFilter::from_expr(&FilterExpr::LenGt(100));
        assert!(f.apply(&[0u8; 101]));
        assert!(!f.apply(&[0u8; 100]));
    }

    #[test]
    fn test_filter_stats() {
        let mut stats = FilterStats::default();
        let f = PacketFilter::from_expr(&FilterExpr::Ipv4);
        let pkt = make_eth_ipv4_tcp(1, 2);
        let arp = make_eth_arp();
        stats.record(f.apply(&pkt));
        stats.record(f.apply(&arp));
        assert_eq!(stats.total, 2);
        assert_eq!(stats.accepted, 1);
        assert!((stats.acceptance_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_ipv4_prefix_match() {
        let pfx = Ipv4Prefix::new(192, 168, 0, 0, 16);
        assert!(pfx.matches(&[192, 168, 1, 1]));
        assert!(!pfx.matches(&[10, 0, 0, 1]));
    }

    #[test]
    fn test_filter_indices() {
        let f = PacketFilter::from_expr(&FilterExpr::Arp);
        let pkts = vec![make_eth_arp(), make_eth_ipv4_tcp(1, 2), make_eth_arp()];
        let idx = f.filter_indices(&pkts);
        assert_eq!(idx, vec![0, 2]);
    }
}
