//! Deep adversarial coverage for `rustre-net` public API.
//!
//! These tests focus on parser robustness, round-trips, integer edge cases,
//! state-machine transitions, Hash/Eq consistency, Display/FromStr behaviour,
//! and Send+Sync threaded stress.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread;

use rustre_net::*;

// ────────────────────────────────────────────────────────────────────────────
// Seeded LCG
// ────────────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn next_u8(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap()
    }
    fn next_u16(&mut self) -> u16 {
        u16::try_from(self.next_u64() & 0xFFFF).unwrap()
    }
    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() & 0xFFFF_FFFF).unwrap()
    }
    fn next_usize_mod(&mut self, m: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(m).unwrap_or(u64::MAX)).unwrap_or(0)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let w = self.next_u64().to_le_bytes();
            for &b in &w {
                if v.len() < n {
                    v.push(b);
                }
            }
        }
        v
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn build_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut buf = vec![0u8; total];
    buf[0] = 0x45;
    buf[2] = u8::try_from((total >> 8) & 0xFF).unwrap();
    buf[3] = u8::try_from(total & 0xFF).unwrap();
    buf[8] = ttl;
    buf[9] = proto;
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    buf[20..].copy_from_slice(payload);
    buf
}

fn build_tcp(src: u16, dst: u16, seq: u32, ack: u32, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 20 + payload.len()];
    b[0..2].copy_from_slice(&src.to_be_bytes());
    b[2..4].copy_from_slice(&dst.to_be_bytes());
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    b[8..12].copy_from_slice(&ack.to_be_bytes());
    b[12] = 0x50;
    b[13] = flags.bits();
    b[14] = 0xFF;
    b[15] = 0xFF;
    b[20..].copy_from_slice(payload);
    b
}

fn build_udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut b = vec![0u8; 8 + payload.len()];
    b[0..2].copy_from_slice(&src.to_be_bytes());
    b[2..4].copy_from_slice(&dst.to_be_bytes());
    b[4..6].copy_from_slice(&len.to_be_bytes());
    b[8..].copy_from_slice(payload);
    b
}

// ────────────────────────────────────────────────────────────────────────────
// 1-10: parsers — round-trip and boundaries
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn ethernet_roundtrip_50_inputs() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let src = <[u8; 6]>::try_from(&lcg.bytes(6)[..]).unwrap();
        let dst = <[u8; 6]>::try_from(&lcg.bytes(6)[..]).unwrap();
        let etype = lcg.next_u16() & 0x7FFF; // avoid 0x8100 VLAN
        let etype = if etype == 0x8100 { 0x0800 } else { etype };
        let plen = lcg.next_usize_mod(64);
        let payload = lcg.bytes(plen);
        let f = EthernetFrame {
            src_mac: src,
            dst_mac: dst,
            ethertype: etype,
            payload: payload.clone(),
        };
        let raw = serialize_ethernet(&f);
        let parsed = parse_ethernet(&raw).unwrap();
        assert_eq!(parsed.src_mac, src);
        assert_eq!(parsed.dst_mac, dst);
        assert_eq!(parsed.ethertype, etype);
        assert_eq!(parsed.payload, payload);
    }
}

#[test]
fn ipv4_roundtrip_50_inputs() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let src = <[u8; 4]>::try_from(&lcg.bytes(4)[..]).unwrap();
        let dst = <[u8; 4]>::try_from(&lcg.bytes(4)[..]).unwrap();
        let proto = lcg.next_u8();
        let ttl = lcg.next_u8();
        let plen = lcg.next_usize_mod(256);
        let payload = lcg.bytes(plen);
        let pkt = IpPacket {
            src: IpAddr::V4(Ipv4Addr::from(src)),
            dst: IpAddr::V4(Ipv4Addr::from(dst)),
            protocol: proto,
            ttl,
            payload: payload.clone(),
        };
        let raw = serialize_ipv4(&pkt);
        let parsed = parse_ipv4(&raw).unwrap();
        assert_eq!(parsed.src, pkt.src);
        assert_eq!(parsed.dst, pkt.dst);
        assert_eq!(parsed.protocol, proto);
        assert_eq!(parsed.ttl, ttl);
        assert_eq!(parsed.payload, payload);
    }
}

#[test]
fn tcp_roundtrip_50_inputs() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let sp = lcg.next_u16();
        let dp = lcg.next_u16();
        let seq = lcg.next_u32();
        let ack = lcg.next_u32();
        let flags = TcpFlags::from_bits_truncate(lcg.next_u8());
        let plen = lcg.next_usize_mod(64);
        let payload = lcg.bytes(plen);
        let seg = TcpSegment {
            src_port: sp,
            dst_port: dp,
            seq,
            ack,
            flags,
            window: 0xFFFF,
            payload: payload.clone(),
        };
        let raw = serialize_tcp(&seg);
        let parsed = parse_tcp(&raw).unwrap();
        assert_eq!(parsed.src_port, sp);
        assert_eq!(parsed.dst_port, dp);
        assert_eq!(parsed.seq, seq);
        assert_eq!(parsed.ack, ack);
        assert_eq!(parsed.flags, flags);
        assert_eq!(parsed.payload, payload);
    }
}

#[test]
fn udp_roundtrip_50_inputs() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let sp = lcg.next_u16();
        let dp = lcg.next_u16();
        let plen = lcg.next_usize_mod(200);
        let payload = lcg.bytes(plen);
        let dg = UdpDatagram {
            src_port: sp,
            dst_port: dp,
            payload: payload.clone(),
        };
        let raw = serialize_udp(&dg);
        let parsed = parse_udp(&raw).unwrap();
        assert_eq!(parsed.src_port, sp);
        assert_eq!(parsed.dst_port, dp);
        assert_eq!(parsed.payload, payload);
    }
}

#[test]
fn parse_ethernet_boundary_lengths() {
    for n in 0..14 {
        let buf = vec![0u8; n];
        assert!(parse_ethernet(&buf).is_err());
    }
    // exactly 14 = ok (empty payload)
    let buf = vec![0u8; 14];
    let f = parse_ethernet(&buf).unwrap();
    assert!(f.payload.is_empty());
}

#[test]
fn parse_ipv4_boundary_lengths() {
    for n in 0..20 {
        let mut buf = vec![0u8; n];
        if n >= 1 {
            buf[0] = 0x45;
        }
        assert!(parse_ipv4(&buf).is_err());
    }
}

#[test]
fn parse_tcp_boundary_lengths() {
    for n in 0..20 {
        let buf = vec![0u8; n];
        assert!(parse_tcp(&buf).is_err());
    }
    // data offset claims 60 bytes but only 20 present
    let mut buf = vec![0u8; 20];
    buf[12] = 0xF0; // data offset = 15 * 4 = 60
    assert!(matches!(
        parse_tcp(&buf),
        Err(NetError::InvalidTcpSegment)
    ));
}

#[test]
fn parse_udp_boundary_lengths() {
    for n in 0..8 {
        let buf = vec![0u8; n];
        assert!(parse_udp(&buf).is_err());
    }
    // length field < 8
    let mut buf = vec![0u8; 8];
    buf[4] = 0;
    buf[5] = 4;
    assert!(matches!(parse_udp(&buf), Err(NetError::InvalidUdpDatagram)));
}

#[test]
fn parse_icmp_boundary_lengths() {
    for n in 0..4 {
        let buf = vec![0u8; n];
        assert!(parse_icmp(&buf).is_err());
    }
    let buf = vec![0u8; 4];
    let p = parse_icmp(&buf).unwrap();
    assert_eq!(p.payload.len(), 0);
}

#[test]
fn parse_ipv6_boundary_lengths() {
    for n in 0..40 {
        let buf = vec![0u8; n];
        assert!(parse_ipv6(&buf).is_err());
    }
    let mut buf = vec![0u8; 40];
    buf[0] = 0x60;
    assert!(parse_ipv6(&buf).is_ok());
}

// ────────────────────────────────────────────────────────────────────────────
// 11-15: LCG fuzz on every parser — must never panic
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn fuzz_parse_ethernet_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next_usize_mod(128);
        let buf = lcg.bytes(n);
        let _ = parse_ethernet(&buf);
    }
}

#[test]
fn fuzz_parse_ipv4_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next_usize_mod(128);
        let buf = lcg.bytes(n);
        let _ = parse_ipv4(&buf);
    }
}

#[test]
fn fuzz_parse_ipv6_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next_usize_mod(96);
        let buf = lcg.bytes(n);
        let _ = parse_ipv6(&buf);
    }
}

#[test]
fn fuzz_parse_tcp_udp_icmp_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next_usize_mod(64);
        let buf = lcg.bytes(n);
        let _ = parse_tcp(&buf);
        let _ = parse_udp(&buf);
        let _ = parse_icmp(&buf);
    }
}

#[test]
fn fuzz_parse_dns_arp_tls_http_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let n = lcg.next_usize_mod(128);
        let buf = lcg.bytes(n);
        let _ = parse_dns(&buf);
        let _ = parse_arp(&buf);
        let _ = parse_tls_records(&buf);
        let _ = parse_http_request(&buf);
        let _ = parse_http_response(&buf);
        let _ = decode_chunked(&buf);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 16-20: TcpFlags
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_flags_full_bits_roundtrip() {
    for b in 0u8..=255 {
        let f = TcpFlags::from_bits_truncate(b);
        assert_eq!(f.bits(), b);
    }
}

#[test]
fn tcp_flags_display_empty_brackets() {
    assert_eq!(TcpFlags::empty().to_string(), "[]");
}

#[test]
fn tcp_flags_display_all_combinations_contain_set_names() {
    let all = TcpFlags::SYN
        | TcpFlags::ACK
        | TcpFlags::FIN
        | TcpFlags::RST
        | TcpFlags::PSH
        | TcpFlags::URG
        | TcpFlags::ECE
        | TcpFlags::CWR;
    let s = all.to_string();
    for n in ["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"] {
        assert!(s.contains(n));
    }
}

#[test]
fn tcp_flags_hash_eq_30_pairs() {
    let mut set = HashSet::new();
    for b in 0u8..30 {
        let f = TcpFlags::from_bits_truncate(b);
        set.insert(f);
        let g = TcpFlags::from_bits_truncate(b);
        assert_eq!(f, g);
        assert!(set.contains(&g));
    }
    assert_eq!(set.len(), 30);
}

#[test]
fn tcp_flags_serde_json_roundtrip() {
    let f = TcpFlags::SYN | TcpFlags::ACK;
    let s = serde_json::to_string(&f).unwrap();
    let back: TcpFlags = serde_json::from_str(&s).unwrap();
    assert_eq!(f, back);
}

// ────────────────────────────────────────────────────────────────────────────
// 21-25: state machine
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_state_full_handshake_via_tracker() {
    let t = ConnectionTracker::new();
    let s = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let d = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    // SYN
    let ip = parse_ipv4(&build_ipv4(
        [1, 1, 1, 1],
        [2, 2, 2, 2],
        6,
        64,
        &build_tcp(100, 80, 0, 0, TcpFlags::SYN, &[]),
    ))
    .unwrap();
    t.process(&ip, 0).unwrap();
    // SYN-ACK
    let ip2 = parse_ipv4(&build_ipv4(
        [2, 2, 2, 2],
        [1, 1, 1, 1],
        6,
        64,
        &build_tcp(80, 100, 0, 1, TcpFlags::SYN | TcpFlags::ACK, &[]),
    ))
    .unwrap();
    t.process(&ip2, 1).unwrap();
    // ACK
    let ip3 = parse_ipv4(&build_ipv4(
        [1, 1, 1, 1],
        [2, 2, 2, 2],
        6,
        64,
        &build_tcp(100, 80, 1, 1, TcpFlags::ACK, &[]),
    ))
    .unwrap();
    t.process(&ip3, 2).unwrap();
    let key = FlowKey::new(s, 100, d, 80);
    let c = t.get(&key).unwrap();
    assert_eq!(c.state, TcpState::Established);
}

#[test]
fn tcp_state_rst_from_established_closes() {
    let t = ConnectionTracker::new();
    let mk = |flags| {
        parse_ipv4(&build_ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            6,
            64,
            &build_tcp(5000, 80, 0, 0, flags, &[]),
        ))
        .unwrap()
    };
    t.process(&mk(TcpFlags::SYN), 0).unwrap();
    t.process(&mk(TcpFlags::SYN | TcpFlags::ACK), 1).unwrap();
    t.process(&mk(TcpFlags::ACK), 2).unwrap();
    t.process(&mk(TcpFlags::RST), 3).unwrap();
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        5000,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        80,
    );
    let c = t.get(&key).unwrap();
    assert_eq!(c.state, TcpState::Closed);
}

#[test]
fn tcp_state_invalid_transition_keeps_state() {
    let t = ConnectionTracker::new();
    // FIN from SynSent should not advance (no SYN|ACK)
    let ip = parse_ipv4(&build_ipv4(
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        6,
        64,
        &build_tcp(1234, 80, 0, 0, TcpFlags::FIN, &[]),
    ))
    .unwrap();
    t.process(&ip, 0).unwrap();
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        1234,
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        80,
    );
    let c = t.get(&key).unwrap();
    assert_eq!(c.state, TcpState::SynSent);
}

#[test]
fn tcp_state_display_all_variants() {
    let names = [
        ("SYN_SENT", TcpState::SynSent),
        ("SYN_RECEIVED", TcpState::SynReceived),
        ("ESTABLISHED", TcpState::Established),
        ("FIN_WAIT_1", TcpState::FinWait1),
        ("FIN_WAIT_2", TcpState::FinWait2),
        ("CLOSE_WAIT", TcpState::CloseWait),
        ("CLOSING", TcpState::Closing),
        ("LAST_ACK", TcpState::LastAck),
        ("TIME_WAIT", TcpState::TimeWait),
        ("CLOSED", TcpState::Closed),
    ];
    for (s, v) in names {
        assert_eq!(v.to_string(), s);
    }
}

#[test]
fn tcp_state_eq_consistency() {
    assert_eq!(TcpState::Established, TcpState::Established);
    assert_ne!(TcpState::Established, TcpState::Closed);
}

// ────────────────────────────────────────────────────────────────────────────
// 26-30: FlowKey canonicalization & hash
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn flow_key_canonical_idempotent_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let a = Ipv4Addr::from(lcg.next_u32());
        let b = Ipv4Addr::from(lcg.next_u32());
        let pa = lcg.next_u16();
        let pb = lcg.next_u16();
        let k = FlowKey::new(IpAddr::V4(a), pa, IpAddr::V4(b), pb);
        let c1 = k.canonical();
        let c2 = c1.canonical();
        assert_eq!(c1, c2);
    }
}

#[test]
fn flow_key_canonical_reverse_equal() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let a = Ipv4Addr::from(lcg.next_u32());
        let b = Ipv4Addr::from(lcg.next_u32());
        let pa = lcg.next_u16();
        let pb = lcg.next_u16();
        let k1 = FlowKey::new(IpAddr::V4(a), pa, IpAddr::V4(b), pb);
        let k2 = FlowKey::new(IpAddr::V4(b), pb, IpAddr::V4(a), pa);
        assert_eq!(k1.canonical(), k2.canonical());
    }
}

#[test]
fn flow_key_hash_eq_30_pairs() {
    let mut set = HashSet::new();
    let mut lcg = Lcg::new();
    let mut keys = Vec::new();
    for _ in 0..30 {
        let a = Ipv4Addr::from(lcg.next_u32());
        let b = Ipv4Addr::from(lcg.next_u32());
        let pa = lcg.next_u16();
        let pb = lcg.next_u16();
        let k = FlowKey::new(IpAddr::V4(a), pa, IpAddr::V4(b), pb).canonical();
        keys.push(k.clone());
        set.insert(k);
    }
    for k in &keys {
        assert!(set.contains(k));
    }
}

#[test]
fn flow_key_display_contains_addresses() {
    let k = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        1111,
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        2222,
    );
    let s = k.to_string();
    assert!(s.contains("1.2.3.4"));
    assert!(s.contains("5.6.7.8"));
    assert!(s.contains("1111"));
    assert!(s.contains("2222"));
}

#[test]
fn flow_key_serde_roundtrip() {
    let k = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(9, 8, 7, 6)),
        42,
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        43,
    );
    let s = serde_json::to_string(&k).unwrap();
    let back: FlowKey = serde_json::from_str(&s).unwrap();
    assert_eq!(k, back);
}

// ────────────────────────────────────────────────────────────────────────────
// 31-35: misc helpers, integer edges
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn ip_checksum_known_value() {
    // RFC 1071 sample: 45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
    // (with zero in checksum field at offset 10-11) should produce 0xb861.
    let data: &[u8] = &[
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    let c = ip_checksum(data);
    assert_eq!(c, 0xb861);
}

#[test]
fn ip_checksum_odd_length() {
    let data: &[u8] = &[0x01, 0x02, 0x03];
    // must not panic and must produce some value
    let _ = ip_checksum(data);
}

#[test]
fn ip_checksum_empty() {
    assert_eq!(ip_checksum(&[]), !0u16);
}

#[test]
fn detect_protocol_well_known_ports() {
    assert_eq!(detect_protocol(12345, 80, b""), "HTTP");
    assert_eq!(detect_protocol(443, 12345, b""), "TLS");
    assert_eq!(detect_protocol(53, 12345, b""), "DNS");
    assert_eq!(detect_protocol(22, 65535, b""), "SSH");
    assert_eq!(detect_protocol(12345, 12346, b""), "Unknown");
}

#[test]
fn detect_protocol_magic_bytes() {
    assert_eq!(detect_protocol(50000, 50001, b"GET / HTTP/1.1\r\n"), "HTTP");
    assert_eq!(detect_protocol(50000, 50001, b"SSH-2.0-OpenSSH"), "SSH");
    // 0x16 = TLS handshake
    let buf = [0x16, 0x03, 0x01, 0x00, 0x10];
    assert_eq!(detect_protocol(50000, 50001, &buf), "TLS");
}

// ────────────────────────────────────────────────────────────────────────────
// 36-40: DNS / TLS / HTTP higher-level
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn dns_circular_compression_pointer_rejected() {
    // Header (12) + question with a pointer that points back to itself
    let mut data = vec![
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    // pointer to offset 12 (itself)
    data.push(0xC0);
    data.push(12);
    data.extend_from_slice(&[0, 1, 0, 1]);
    let r = parse_dns(&data);
    assert!(r.is_err());
}

#[test]
fn dns_decode_a_aaaa_lengths() {
    assert!(dns_decode_a(&[1, 2, 3]).is_err());
    assert_eq!(
        dns_decode_a(&[1, 2, 3, 4]).unwrap(),
        Ipv4Addr::new(1, 2, 3, 4)
    );
    assert!(dns_decode_aaaa(&[0u8; 15]).is_err());
    assert!(dns_decode_aaaa(&[0u8; 16]).is_ok());
}

#[test]
fn dns_type_name_known_and_unknown() {
    assert_eq!(dns_type_name(1), "A");
    assert_eq!(dns_type_name(28), "AAAA");
    assert_eq!(dns_type_name(255), "ANY");
    assert_eq!(dns_type_name(9999), "Unknown");
}

#[test]
fn http_request_missing_terminator_errs() {
    let r = parse_http_request(b"GET / HTTP/1.1\r\nHost: x\r\n");
    assert!(matches!(r, Err(NetError::InvalidHttpMessage)));
}

#[test]
fn http_response_invalid_status_errs() {
    let r = parse_http_response(b"HTTP/1.1 abc OK\r\n\r\n");
    assert!(matches!(r, Err(NetError::InvalidHttpMessage)));
}

#[test]
fn http_header_case_insensitive_lookup() {
    let raw =
        b"POST /api HTTP/1.1\r\nContent-Length: 7\r\nX-Foo: bar\r\n\r\npayload";
    let req = parse_http_request(raw).unwrap();
    assert_eq!(req.header("content-length"), Some("7"));
    assert_eq!(req.header("CONTENT-LENGTH"), Some("7"));
    assert_eq!(req.body, b"payload");
}

#[test]
fn http_chunked_decode_roundtrip() {
    let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let out = decode_chunked(body).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn http_chunked_malformed_errs() {
    let body = b"zz\r\nhello\r\n0\r\n\r\n";
    assert!(decode_chunked(body).is_err());
}

#[test]
fn tls_records_parse_multiple() {
    // Two records, each ApplicationData(23) v=0x0303 len=4
    let mut data = Vec::new();
    for _ in 0..2 {
        data.extend_from_slice(&[23, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]);
    }
    let recs = parse_tls_records(&data).unwrap();
    assert_eq!(recs.len(), 2);
    assert!(matches!(recs[0].content_type, TlsContentType::ApplicationData));
    assert_eq!(recs[0].version, 0x0303);
    assert_eq!(recs[0].payload, vec![1, 2, 3, 4]);
}

#[test]
fn tls_records_partial_trailing_ignored() {
    // One full + truncated header
    let data: &[u8] = &[22, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB, 22, 0x03];
    let recs = parse_tls_records(data).unwrap();
    assert_eq!(recs.len(), 1);
}

#[test]
fn tls_content_type_from_u8_unknown_path() {
    let t = TlsContentType::from_u8(99);
    assert!(matches!(t, TlsContentType::Unknown(99)));
    assert_eq!(t.to_string(), "Unknown(99)");
}

// ────────────────────────────────────────────────────────────────────────────
// 41-50: stream, sinks, builders, threading
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_stream_in_order_basic() {
    let mut s = TcpStream::new(1000);
    let added = s.feed(1000, b"abcd");
    assert_eq!(added, 4);
    assert_eq!(s.stream, b"abcd");
    let added2 = s.feed(1004, b"ef");
    assert_eq!(added2, 2);
    assert_eq!(s.stream, b"abcdef");
}

#[test]
fn tcp_stream_out_of_order_buffered_then_delivered() {
    let mut s = TcpStream::new(0);
    let r1 = s.feed(4, b"56");
    assert_eq!(r1, 0);
    assert_eq!(s.pending_bytes(), 2);
    let r2 = s.feed(0, b"1234");
    assert_eq!(r2, 6);
    assert_eq!(s.stream, b"123456");
    assert_eq!(s.pending_bytes(), 0);
}

#[test]
fn tcp_stream_duplicate_ignored() {
    let mut s = TcpStream::new(0);
    s.feed(0, b"abc");
    let r = s.feed(0, b"abc");
    assert_eq!(r, 0);
    assert_eq!(s.stream, b"abc");
}

#[test]
fn packet_builder_eth_ip_tcp_roundtrip() {
    let pkt = PacketBuilder::new()
        .ethernet([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], 0x0800)
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, 64, 20)
        .tcp(5000, 80, 0, 0, 0x02, 0xFFFF)
        .build();
    let eth = parse_ethernet(&pkt).unwrap();
    let ip = parse_ipv4(&eth.payload).unwrap();
    assert_eq!(ip.protocol, 6);
    let tcp = parse_tcp(&ip.payload).unwrap();
    assert_eq!(tcp.src_port, 5000);
    assert_eq!(tcp.dst_port, 80);
}

#[test]
fn packet_builder_default_and_empty() {
    let b = PacketBuilder::default();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
}

#[test]
fn blackhole_and_buffering_sinks_basic() {
    let bh = BlackholePacketSink;
    let buf = PacketBuffer::new(vec![1, 2, 3], 100, CaptureLink::Ethernet);
    bh.accept(&buf).unwrap();
    bh.flush().unwrap();

    let bs = BufferingPacketSink::new();
    bs.accept(&buf).unwrap();
    bs.accept(&buf).unwrap();
    let drained = bs.drain();
    assert_eq!(drained.len(), 2);
    let drained2 = bs.drain();
    assert!(drained2.is_empty());
}

#[test]
fn connection_tracker_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ConnectionTracker>();
    let t = Arc::new(ConnectionTracker::new());
    let mut handles = Vec::new();
    for tid in 0..4u8 {
        let t = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            for i in 0..100u16 {
                let ip = parse_ipv4(&build_ipv4(
                    [tid, 0, 0, 1],
                    [tid, 0, 0, 2],
                    6,
                    64,
                    &build_tcp(1000 + i, 80, 0, 0, TcpFlags::SYN, &[]),
                ))
                .unwrap();
                t.process(&ip, u64::from(i)).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(t.len(), 4 * 100);
}

#[test]
fn flow_stats_tracker_threaded() {
    let s = Arc::new(FlowStatsTracker::new());
    let mut handles = Vec::new();
    for tid in 0..4u8 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            let k = FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(tid, 0, 0, 1)),
                100,
                IpAddr::V4(Ipv4Addr::new(tid, 0, 0, 2)),
                200,
            );
            for i in 0..100u64 {
                s.record(&k, Direction::Inbound, 10, i);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.len(), 4);
}

#[test]
fn flow_stats_record_in_out_and_totals() {
    let mut st = FlowStats::new(0);
    st.record_in(100, 10);
    st.record_in(50, 20);
    st.record_out(200, 30);
    assert_eq!(st.packets_in, 2);
    assert_eq!(st.packets_out, 1);
    assert_eq!(st.bytes_in, 150);
    assert_eq!(st.bytes_out, 200);
    assert_eq!(st.total_packets(), 3);
    assert_eq!(st.total_bytes(), 350);
    assert_eq!(st.duration_us(), 30);
}

#[test]
fn flow_stats_record_direction_unknown_counts_as_inbound() {
    let mut st = FlowStats::new(0);
    st.record_direction(Direction::Unknown, 7, 1);
    st.record_direction(Direction::Outbound, 8, 2);
    assert_eq!(st.packets_in, 1);
    assert_eq!(st.packets_out, 1);
    assert_eq!(st.bytes_in, 7);
    assert_eq!(st.bytes_out, 8);
}

#[test]
fn flow_stats_duration_saturating() {
    let mut st = FlowStats::new(1000);
    st.record_in(1, 500); // last_seen now < first_seen
    assert_eq!(st.duration_us(), 0);
}

#[test]
fn arp_parse_request_reply() {
    let mut data = vec![0u8; 28];
    data[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype Ethernet
    data[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    data[4] = 6;
    data[5] = 4;
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
    let p = parse_arp(&data).unwrap();
    assert!(matches!(p.htype, ArpHwType::Ethernet));
    assert!(matches!(p.op, ArpOp::Request));

    data[6..8].copy_from_slice(&2u16.to_be_bytes());
    let p2 = parse_arp(&data).unwrap();
    assert!(matches!(p2.op, ArpOp::Reply));

    // malformed: hlen wrong
    data[4] = 8;
    assert!(matches!(parse_arp(&data), Err(NetError::MalformedPacket(_))));
}

#[test]
fn arp_too_short_errs() {
    for n in 0..28 {
        let buf = vec![0u8; n];
        assert!(matches!(
            parse_arp(&buf),
            Err(NetError::BufferTooShort { .. })
        ));
    }
}

#[test]
fn linktype_dlt_values() {
    assert_eq!(LinkType::Ethernet.dlt(), 1);
    assert_eq!(LinkType::Raw.dlt(), 12);
    assert_eq!(LinkType::Loopback.dlt(), 0);
    assert_eq!(LinkType::Null.dlt(), 0);
}

#[test]
fn linktype_from_capturelink_conversion() {
    assert_eq!(LinkType::from(CaptureLink::Ethernet), LinkType::Ethernet);
    assert_eq!(LinkType::from(CaptureLink::Raw), LinkType::Raw);
    assert_eq!(LinkType::from(CaptureLink::Loopback), LinkType::Loopback);
    assert_eq!(LinkType::from(CaptureLink::Null), LinkType::Null);
}

#[test]
fn is_private_addr_classes() {
    assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_private_addr(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 1))));
    assert!(!is_private_addr(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    assert!(!is_private_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn is_multicast_and_broadcast() {
    assert!(is_multicast_addr(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    assert!(!is_multicast_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(is_broadcast_addr(IpAddr::V4(Ipv4Addr::BROADCAST)));
    assert!(!is_broadcast_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
}

#[test]
fn ext_connection_tracker_combined() {
    let t = ExtConnectionTracker::new();
    let ip = parse_ipv4(&build_ipv4(
        [1, 1, 1, 1],
        [2, 2, 2, 2],
        6,
        64,
        &build_tcp(1234, 80, 0, 0, TcpFlags::SYN, b"hello"),
    ))
    .unwrap();
    t.process(&ip, Direction::Outbound, 100).unwrap();
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        1234,
        IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        80,
    );
    assert!(t.connection(&key).is_some());
    let s = t.flow_stats(&key).unwrap();
    assert_eq!(s.packets_out, 1);
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
}

#[test]
fn protocol_is_tls_helper() {
    assert!(protocol_is_tls(&Protocol::Https));
    assert!(!protocol_is_tls(&Protocol::Http));
    assert!(!protocol_is_tls(&Protocol::Tcp));
}

#[test]
fn connection_info_is_local() {
    let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let ci = ConnectionInfo::new(src, dst, Protocol::Udp, None);
    assert!(ci.is_local());
    let src2: SocketAddr = "1.2.3.4:1".parse().unwrap();
    let ci2 = ConnectionInfo::new(src2, dst, Protocol::Udp, None);
    assert!(!ci2.is_local());
}

#[test]
fn icmp_and_dns_type_name_helpers() {
    assert_eq!(icmp_type_name(0), "Echo Reply");
    assert_eq!(icmp_type_name(8), "Echo Request");
    assert_eq!(icmp_type_name(200), "Unknown");
    assert_eq!(dns_type_name(15), "MX");
}

#[test]
fn udp_helper_builds_valid_datagram() {
    let raw = build_udp(53, 12345, b"query");
    let dg = parse_udp(&raw).unwrap();
    assert_eq!(dg.src_port, 53);
    assert_eq!(dg.dst_port, 12345);
    assert_eq!(dg.payload, b"query");
}

#[test]
fn tcp_session_bidirectional_feed() {
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        100,
        IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        200,
    );
    let mut sess = TcpSession::new(key, 1000, 2000, 0);
    let n = sess.feed_client(1001, b"hello", 1);
    assert_eq!(n, 5);
    assert_eq!(sess.c2s_data(), b"hello");
    let m = sess.feed_server(2001, b"world", 2);
    assert_eq!(m, 5);
    assert_eq!(sess.s2c_data(), b"world");
}
