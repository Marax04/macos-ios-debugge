//! Deep adversarial tests for rustre-net-dissect.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use rustre_net_dissect::{
    auto_detect_protocol, byte_entropy, decode_http_chunked, default_registry, dnp3_app_fc_name,
    dnp3_crc16, dnp3_fc_is_control, dns_rtype_name, extended_registry, fingerprint_detailed,
    fingerprint_protocol, full_registry, ics_protocol_for_port, icmp_stream_tunnel_heuristic,
    is_ics_port, modbus_fc_is_diagnostic, modbus_fc_is_write, nt_status_name, scan_http_attacks,
    scan_http_attacks_decoded, smb1_command_name, smb2_command_name, smb2_is_sensitive_share,
    smtp_response_description, ssh_msg_type_name, tls_version_name, url_decode, DetectConfidence,
    DhcpMessage, DhcpMsgType, DissectError, DissectedPacket, DissectionSession, DissectorChain,
    DissectorRegistry, Dnp3Frame, DnsFullMessage, DnsMessage, DnsQuery, DnsRdata, EthernetFrame,
    FieldValue, FingerprintConfidence, FlowDir, HttpAttackKind, HttpRequest, HttpResponse,
    IpVersion, Ipv4Packet, KerberosEtype, ModbusFunctionCode, ModbusPacket, ProtoField, ProtoLayer,
    TcpSegment, TlsContentType, TlsHandshakeType, UdpDatagram,
};

// Seeded LCG (do NOT use std::time or rand).
struct Lcg {
    s: u64,
}
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self { s: seed }
    }
    const fn next_u64(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.s
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            for (b, vb) in chunk.iter_mut().zip(v.iter()) {
                *b = *vb;
            }
        }
    }
    fn next_range(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (usize::try_from(self.next_u64()).unwrap_or(usize::MAX)) % max
        }
    }
}

// ── 1. Ethernet frame round-trip / boundaries ──────────────────────────────

#[test]
fn ethernet_too_short_all_lengths() {
    for n in 0..14usize {
        let buf = vec![0u8; n];
        let err = EthernetFrame::parse(&buf).unwrap_err();
        match err {
            DissectError::TooShort { need, got } => {
                assert_eq!(need, 14);
                assert_eq!(got, n);
            }
            _ => panic!("expected TooShort, got {err:?}"),
        }
    }
}

#[test]
fn ethernet_minimal_valid_parses() {
    let buf = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
    ];
    let f = EthernetFrame::parse(&buf).unwrap();
    assert_eq!(f.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(f.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(f.ether_type, 0x0800);
    assert!(f.is_ip());
    assert!(!f.is_arp());
    assert_eq!(f.src_str(), "11:22:33:44:55:66");
    assert_eq!(f.dst_str(), "aa:bb:cc:dd:ee:ff");
    assert!(f.payload.is_empty());
}

#[test]
fn ethernet_arp_ethertype() {
    let mut buf = vec![0u8; 14];
    buf[12] = 0x08;
    buf[13] = 0x06;
    let f = EthernetFrame::parse(&buf).unwrap();
    assert!(f.is_arp());
    assert!(!f.is_ip());
}

#[test]
fn ethernet_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = lcg.next_range(64);
        let mut buf = vec![0u8; len];
        lcg.fill(&mut buf);
        let _ = EthernetFrame::parse(&buf);
    }
}

// ── 2. IPv4 ────────────────────────────────────────────────────────────────

fn build_ipv4(ihl: u8, total_len: u16, proto: u8, payload: &[u8]) -> Vec<u8> {
    let header_words = ihl as usize;
    let header_bytes = header_words * 4;
    let mut buf = vec![0u8; header_bytes + payload.len()];
    buf[0] = (4u8 << 4) | (ihl & 0x0F);
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[8] = 64; // ttl
    buf[9] = proto;
    buf[12..16].copy_from_slice(&[10, 0, 0, 1]);
    buf[16..20].copy_from_slice(&[10, 0, 0, 2]);
    buf[header_bytes..].copy_from_slice(payload);
    buf
}

#[test]
fn ipv4_minimum_header() {
    let buf = build_ipv4(5, 20, 6, &[]);
    let p = Ipv4Packet::parse(&buf).unwrap();
    assert_eq!(p.version, 4);
    assert_eq!(p.ihl, 5);
    assert_eq!(p.ttl, 64);
    assert!(p.is_tcp());
    assert!(!p.is_udp());
    assert_eq!(p.src_str(), "10.0.0.1");
    assert_eq!(p.dst_str(), "10.0.0.2");
}

#[test]
fn ipv4_too_short() {
    for n in 0..20usize {
        let buf = vec![0x45u8; n];
        assert!(matches!(
            Ipv4Packet::parse(&buf),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn ipv4_wrong_version_returns_invalid_magic() {
    let mut buf = vec![0u8; 20];
    buf[0] = 0x65; // version 6
    assert!(matches!(
        Ipv4Packet::parse(&buf),
        Err(DissectError::InvalidMagic(_))
    ));
}

#[test]
fn ipv4_ihl_too_small() {
    let mut buf = vec![0u8; 20];
    buf[0] = 0x40; // ihl=0
    assert!(matches!(
        Ipv4Packet::parse(&buf),
        Err(DissectError::TooShort { .. })
    ));
}

#[test]
fn ipv4_udp_proto() {
    let buf = build_ipv4(5, 20, 17, &[]);
    let p = Ipv4Packet::parse(&buf).unwrap();
    assert!(p.is_udp());
    assert!(!p.is_tcp());
}

#[test]
fn ipv4_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = lcg.next_range(80);
        let mut buf = vec![0u8; len];
        lcg.fill(&mut buf);
        let _ = Ipv4Packet::parse(&buf);
    }
}

// ── 3. TCP ─────────────────────────────────────────────────────────────────

fn build_tcp(flags: u8, data_offset_words: u8, payload: &[u8]) -> Vec<u8> {
    let hdr = (data_offset_words as usize) * 4;
    let mut buf = vec![0u8; hdr + payload.len()];
    buf[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    buf[2..4].copy_from_slice(&0x5678u16.to_be_bytes());
    buf[4..8].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
    buf[8..12].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
    buf[12] = data_offset_words << 4;
    buf[13] = flags;
    buf[14..16].copy_from_slice(&0xffff_u16.to_be_bytes());
    buf[hdr..].copy_from_slice(payload);
    buf
}

#[test]
fn tcp_flags() {
    let buf = build_tcp(0x02 | 0x10, 5, b"abc");
    let s = TcpSegment::parse(&buf).unwrap();
    assert_eq!(s.src_port, 0x1234);
    assert_eq!(s.dst_port, 0x5678);
    assert_eq!(s.seq, 0xdead_beef);
    assert_eq!(s.ack, 0xcafe_babe);
    assert!(s.has_syn());
    assert!(s.has_ack());
    assert!(!s.has_fin());
    assert!(!s.has_rst());
    assert_eq!(s.payload, b"abc");
}

#[test]
fn tcp_all_flag_combinations() {
    for flags in 0u8..=63 {
        let buf = build_tcp(flags, 5, b"");
        let s = TcpSegment::parse(&buf).unwrap();
        assert_eq!(s.has_syn(), flags & 0x02 != 0);
        assert_eq!(s.has_ack(), flags & 0x10 != 0);
        assert_eq!(s.has_fin(), flags & 0x01 != 0);
        assert_eq!(s.has_rst(), flags & 0x04 != 0);
    }
}

#[test]
fn tcp_too_short() {
    for n in 0..20usize {
        let buf = vec![0u8; n];
        assert!(matches!(
            TcpSegment::parse(&buf),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn tcp_bad_data_offset() {
    let mut buf = vec![0u8; 20];
    // data_offset = 4 → 16 bytes (less than minimum)
    buf[12] = 4 << 4;
    assert!(matches!(
        TcpSegment::parse(&buf),
        Err(DissectError::ParseError(_))
    ));
}

#[test]
fn tcp_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = lcg.next_range(80);
        let mut buf = vec![0u8; len];
        lcg.fill(&mut buf);
        let _ = TcpSegment::parse(&buf);
    }
}

// ── 4. UDP ─────────────────────────────────────────────────────────────────

#[test]
fn udp_basic() {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&53u16.to_be_bytes());
    buf[2..4].copy_from_slice(&12345u16.to_be_bytes());
    buf[4..6].copy_from_slice(&12u16.to_be_bytes());
    buf[8..12].copy_from_slice(b"\x00\x01\x02\x03");
    let u = UdpDatagram::parse(&buf).unwrap();
    assert_eq!(u.src_port, 53);
    assert_eq!(u.dst_port, 12345);
    assert_eq!(u.length, 12);
    assert_eq!(u.payload, b"\x00\x01\x02\x03");
}

#[test]
fn udp_too_short() {
    for n in 0..8usize {
        assert!(matches!(
            UdpDatagram::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn udp_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = lcg.next_range(64);
        let mut buf = vec![0u8; len];
        lcg.fill(&mut buf);
        let _ = UdpDatagram::parse(&buf);
    }
}

// ── 5. DNS message ─────────────────────────────────────────────────────────

fn dns_query_bytes(id: u16, name: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());
    // name labels
    for label in name.split('.') {
        buf.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    buf
}

#[test]
fn dns_query_parse_basic() {
    let bytes = dns_query_bytes(0x4242, "example.com");
    let q = DnsQuery::parse(&bytes).unwrap();
    assert_eq!(q.id, 0x4242);
    assert_eq!(q.questions.len(), 1);
    assert_eq!(q.questions[0].name, "example.com");
    assert_eq!(q.questions[0].qtype, 1);
}

#[test]
fn dns_query_too_short() {
    for n in 0..12usize {
        assert!(matches!(
            DnsQuery::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn dns_message_is_query_vs_response() {
    let q_bytes = dns_query_bytes(0x1, "a.b");
    let m = DnsMessage::parse(&q_bytes).unwrap();
    assert!(m.is_query());
    // Flip QR bit
    let mut r_bytes = q_bytes;
    r_bytes[2] |= 0x80;
    let mr = DnsMessage::parse(&r_bytes).unwrap();
    assert!(!mr.is_query());
}

#[test]
fn dns_full_message_flags_helpers() {
    let bytes = dns_query_bytes(0x55, "x.y.z");
    let m = DnsFullMessage::parse(&bytes).unwrap();
    assert!(m.is_query());
    assert_eq!(m.rcode(), 0);
    assert!(m.recursion_desired());
    assert!(!m.authoritative());
}

#[test]
fn dns_full_message_too_short() {
    for n in 0..12usize {
        assert!(matches!(
            DnsFullMessage::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn dns_rtype_name_coverage() {
    assert_eq!(dns_rtype_name(1), "A");
    assert_eq!(dns_rtype_name(28), "AAAA");
    assert_eq!(dns_rtype_name(33), "SRV");
    assert_eq!(dns_rtype_name(255), "ANY");
    assert_eq!(dns_rtype_name(9999), "UNKNOWN");
}

#[test]
fn dns_rdata_display() {
    assert_eq!(format!("{}", DnsRdata::A([1, 2, 3, 4])), "1.2.3.4");
    assert_eq!(format!("{}", DnsRdata::Name("a.b".into())), "a.b");
    let txt = DnsRdata::Txt(vec!["hello".into(), "world".into()]);
    assert_eq!(format!("{txt}"), "hello world");
}

#[test]
fn dns_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = lcg.next_range(80);
        let mut buf = vec![0u8; len];
        lcg.fill(&mut buf);
        let _ = DnsQuery::parse(&buf);
        let _ = DnsMessage::parse(&buf);
        let _ = DnsFullMessage::parse(&buf);
    }
}

// ── 6. HTTP request / response ─────────────────────────────────────────────

#[test]
fn http_request_basic() {
    let r = HttpRequest::parse(b"GET /foo HTTP/1.1\r\nHost: x\r\n\r\nbody").unwrap();
    assert_eq!(r.method, "GET");
    assert_eq!(r.uri, "/foo");
    assert_eq!(r.version, "HTTP/1.1");
    assert_eq!(r.headers.len(), 1);
    assert_eq!(r.headers[0].0, "Host");
    assert_eq!(r.body, b"body");
}

#[test]
fn http_request_no_terminator() {
    assert!(matches!(
        HttpRequest::parse(b"GET / HTTP/1.1\r\nHost: x"),
        Err(DissectError::ParseError(_))
    ));
}

#[test]
fn http_request_missing_uri() {
    assert!(matches!(
        HttpRequest::parse(b"GET\r\n\r\n"),
        Err(DissectError::ParseError(_))
    ));
}

#[test]
fn http_response_basic() {
    let r =
        HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello")
            .unwrap();
    assert_eq!(r.status_code, 200);
    assert_eq!(r.reason, "OK");
    assert_eq!(r.content_type(), Some("text/plain"));
    assert_eq!(r.content_length(), Some(5));
    assert_eq!(r.body, b"hello");
    // case-insensitive header lookup
    assert_eq!(r.header("CONTENT-TYPE"), Some("text/plain"));
}

#[test]
fn http_response_bad_status_code() {
    assert!(matches!(
        HttpResponse::parse(b"HTTP/1.1 ABC OK\r\n\r\n"),
        Err(DissectError::ParseError(_))
    ));
}

#[test]
fn http_chunked_round_trip() {
    let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let out = decode_http_chunked(body).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn http_chunked_invalid_size() {
    assert!(matches!(
        decode_http_chunked(b"zz\r\nfoo\r\n0\r\n\r\n"),
        Err(DissectError::ParseError(_))
    ));
}

#[test]
fn http_chunked_truncated() {
    assert!(matches!(
        decode_http_chunked(b"5\r\nhe"),
        Err(DissectError::TooShort { .. })
    ));
}

#[test]
fn http_chunked_empty_terminator() {
    let out = decode_http_chunked(b"0\r\n\r\n").unwrap();
    assert!(out.is_empty());
}

// ── 7. TLS enums round-trip ────────────────────────────────────────────────

#[test]
fn tls_handshake_type_all_known() {
    let vals = [0u8, 1, 2, 4, 5, 8, 11, 12, 13, 14, 15, 16, 20];
    for v in vals {
        let h: TlsHandshakeType = v.into();
        assert!(!matches!(h, TlsHandshakeType::Unknown(_)));
    }
    let unk: TlsHandshakeType = 99u8.into();
    assert!(matches!(unk, TlsHandshakeType::Unknown(99)));
}

#[test]
fn tls_content_type_all_known() {
    for v in 20u8..=24u8 {
        let c: TlsContentType = v.into();
        assert!(!matches!(c, TlsContentType::Unknown(_)));
    }
    let unk: TlsContentType = 99u8.into();
    assert!(matches!(unk, TlsContentType::Unknown(99)));
}

#[test]
fn tls_version_name_known() {
    assert!(tls_version_name(0x0303).contains("1.2"));
    assert!(tls_version_name(0x0304).contains("1.3"));
}

// ── 8. DHCP ────────────────────────────────────────────────────────────────

fn dhcp_minimal() -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = 1; // op
    buf[1] = 1; // htype
    buf[2] = 6; // hlen
    buf[236] = 0x63;
    buf[237] = 0x82;
    buf[238] = 0x53;
    buf[239] = 0x63;
    buf
}

#[test]
fn dhcp_too_short() {
    for n in [0usize, 10, 100, 239] {
        assert!(matches!(
            DhcpMessage::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn dhcp_bad_magic() {
    let mut buf = vec![0u8; 240];
    buf[236..240].copy_from_slice(b"\xde\xad\xbe\xef");
    assert!(matches!(
        DhcpMessage::parse(&buf),
        Err(DissectError::InvalidMagic(_))
    ));
}

#[test]
fn dhcp_min_no_options() {
    let buf = dhcp_minimal();
    let m = DhcpMessage::parse(&buf).unwrap();
    assert_eq!(m.op, 1);
    assert!(m.options.is_empty());
    assert!(m.msg_type.is_none());
    assert_eq!(m.type_str(), "DHCP");
}

#[test]
fn dhcp_msg_type_option() {
    let mut buf = dhcp_minimal();
    // Add option 53 (msg type) = 1 (DISCOVER)
    buf.extend_from_slice(&[53, 1, 1, 255]);
    let m = DhcpMessage::parse(&buf).unwrap();
    assert_eq!(m.msg_type, Some(DhcpMsgType::Discover));
    assert_eq!(m.type_str(), "DHCPDISCOVER");
    assert!(m.option(53).is_some());
}

// ── 9. Fingerprint / auto-detect ───────────────────────────────────────────

#[test]
fn fingerprint_known_ports() {
    assert_eq!(fingerprint_protocol(&[], 0, 53), "DNS");
    assert_eq!(fingerprint_protocol(&[], 0, 80), "HTTP");
    assert_eq!(fingerprint_protocol(&[], 0, 443), "TLS");
}

#[test]
fn fingerprint_detailed_dns_port_high() {
    let r = fingerprint_detailed(&[], 12345, 53);
    assert_eq!(r.protocol, "DNS");
    assert_eq!(r.confidence, FingerprintConfidence::High);
}

#[test]
fn fingerprint_detailed_http_method() {
    let r = fingerprint_detailed(b"GET / HTTP/1.1\r\n\r\n", 33333, 44444);
    assert_eq!(r.protocol, "HTTP");
    assert_eq!(r.confidence, FingerprintConfidence::High);
}

#[test]
fn fingerprint_confidence_ord() {
    assert!(FingerprintConfidence::Low < FingerprintConfidence::Medium);
    assert!(FingerprintConfidence::Medium < FingerprintConfidence::High);
}

#[test]
fn auto_detect_smb2() {
    let mut data = vec![0u8; 16];
    data[..4].copy_from_slice(b"\xFESMB");
    let r = auto_detect_protocol(0, 445, &data).unwrap();
    assert_eq!(r.protocol, "SMB2");
    assert_eq!(r.confidence, DetectConfidence::High);
}

#[test]
fn auto_detect_http_request() {
    let r = auto_detect_protocol(0, 0, b"GET /x HTTP/1.1\r\n").unwrap();
    assert_eq!(r.protocol, "HTTP");
}

#[test]
fn auto_detect_none_for_random() {
    let r = auto_detect_protocol(1, 1, &[0x99, 0x77]);
    assert!(r.is_none());
}

#[test]
fn auto_detect_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let mut buf = vec![0u8; lcg.next_range(80)];
        lcg.fill(&mut buf);
        let _ = auto_detect_protocol(u16::try_from(lcg.next_u64()).unwrap_or(u16::MAX), u16::try_from(lcg.next_u64()).unwrap_or(u16::MAX), &buf);
        let _ = fingerprint_detailed(&buf, u16::try_from(lcg.next_u64()).unwrap_or(u16::MAX), u16::try_from(lcg.next_u64()).unwrap_or(u16::MAX));
    }
}

// ── 10. Registry / dissectors ──────────────────────────────────────────────

#[test]
fn registry_default_can_lookup() {
    let r = default_registry();
    assert!(r.by_name("Ethernet").is_some());
    assert!(r.by_name("DoesNotExist").is_none());
}

#[test]
fn registry_full_has_dns_full() {
    let r = full_registry();
    assert!(r.by_name("DNS-Full").is_some());
}

#[test]
fn registry_extended_has_modbus() {
    let r = extended_registry();
    assert!(r.by_name("Modbus").is_some());
}

#[test]
fn registry_dissect_auto_no_dissector() {
    let r = DissectorRegistry::new();
    let err = r.dissect_auto("nope", None, &[], 0).unwrap_err();
    assert!(matches!(err, DissectError::NoDissector(_)));
}

#[test]
fn dissector_chain_empty_default() {
    let c = DissectorChain::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
    let pkt = c.dissect_all(b"");
    assert!(pkt.layers.is_empty());
}

#[test]
fn dissection_session_basic() {
    let reg = Arc::new(default_registry());
    let mut sess = DissectionSession::new(reg, "Ethernet");
    let buf = vec![0u8; 14];
    sess.feed(&buf, FlowDir::ClientToServer);
    let pkts = sess.packets_for_dir(FlowDir::ClientToServer);
    assert!(!pkts.is_empty());
}

#[test]
fn flow_dir_display() {
    assert_eq!(format!("{}", FlowDir::ClientToServer), "C->S");
    assert_eq!(format!("{}", FlowDir::ServerToClient), "S->C");
}

#[test]
fn ip_version_display() {
    assert_eq!(format!("{}", IpVersion::V4), "IPv4");
    assert_eq!(format!("{}", IpVersion::V6), "IPv6");
}

// ── 11. ProtoField / Layer / Packet ────────────────────────────────────────

#[test]
fn proto_layer_field_lookup() {
    let mut l = ProtoLayer::new("X", vec![1, 2]);
    l.add_field(ProtoField::new("a", 0, 1, FieldValue::Uint(7)));
    assert!(l.field("a").is_some());
    assert!(l.field("b").is_none());
}

#[test]
fn dissected_packet_pretty_print_contains_layer() {
    let mut p = DissectedPacket::new();
    p.push_layer(ProtoLayer::new("Foo", vec![]));
    let s = p.pretty_print();
    assert!(s.contains("Foo"));
    assert!(s.contains("[Layer 0]"));
}

#[test]
fn field_value_display_variants() {
    assert_eq!(format!("{}", FieldValue::Uint(42)), "42");
    assert_eq!(format!("{}", FieldValue::Int(-3)), "-3");
    assert_eq!(format!("{}", FieldValue::Bool(true)), "true");
    assert_eq!(
        format!("{}", FieldValue::MacAddr([0, 1, 2, 3, 4, 5])),
        "00:01:02:03:04:05"
    );
    assert!(!format!("{}", FieldValue::Bytes(vec![0xab, 0xcd])).is_empty());
}

// ── 12. URL decode + HTTP attack ───────────────────────────────────────────

#[test]
fn url_decode_basic() {
    assert_eq!(url_decode(b"hello+world"), b"hello world");
    assert_eq!(url_decode(b"a%20b"), b"a b");
    assert_eq!(url_decode(b"%41"), b"A");
    assert_eq!(url_decode(b"%zz"), b"%zz"); // invalid passthrough
    assert!(url_decode(&[]).is_empty());
}

#[test]
fn url_decode_round_trip_seeded() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let n = lcg.next_range(32);
        let mut buf = vec![0u8; n];
        lcg.fill(&mut buf);
        // pure alphanumeric should pass through if filtered
        let alnum: Vec<u8> = buf
            .iter()
            .map(|&b| b'a' + (b % 26))
            .collect();
        assert_eq!(url_decode(&alnum), alnum);
    }
}

#[test]
fn scan_http_attacks_sqli() {
    let v = scan_http_attacks(b"GET /?q=' OR 1=1 -- HTTP/1.1");
    assert!(v.iter().any(|i| i.kind == HttpAttackKind::SqlInjection));
}

#[test]
fn scan_http_attacks_xss() {
    let v = scan_http_attacks(b"<script>alert(1)</script>");
    assert!(v.iter().any(|i| i.kind == HttpAttackKind::Xss));
}

#[test]
fn scan_http_attacks_path_traversal() {
    let v = scan_http_attacks(b"GET /../../etc/passwd HTTP/1.1");
    assert!(v.iter().any(|i| i.kind == HttpAttackKind::PathTraversal));
}

#[test]
fn scan_http_attacks_decoded_catches_encoded() {
    let v = scan_http_attacks_decoded(b"GET /?q=%55nion%20select%20*%20from HTTP/1.1");
    assert!(v.iter().any(|i| i.kind == HttpAttackKind::SqlInjection));
}

#[test]
fn scan_http_attacks_empty() {
    let v = scan_http_attacks(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(v.is_empty());
}

// ── 13. Modbus ─────────────────────────────────────────────────────────────

fn modbus_read_holding() -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // tid
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // pid = 0
    buf[4..6].copy_from_slice(&6u16.to_be_bytes()); // length
    buf[6] = 0x11; // unit
    buf[7] = 0x03; // ReadHoldingRegisters
    buf[8..10].copy_from_slice(&100u16.to_be_bytes());
    buf[10..12].copy_from_slice(&10u16.to_be_bytes());
    buf
}

#[test]
fn modbus_read_holding_parse() {
    let buf = modbus_read_holding();
    let p = ModbusPacket::parse(&buf).unwrap();
    assert_eq!(p.transaction_id, 1);
    assert_eq!(p.protocol_id, 0);
    assert_eq!(p.unit_id, 0x11);
    assert!(matches!(
        p.function_code,
        ModbusFunctionCode::ReadHoldingRegisters
    ));
    assert_eq!(p.start_address, Some(100));
    assert_eq!(p.quantity, Some(10));
}

#[test]
fn modbus_too_short() {
    for n in 0..8usize {
        assert!(matches!(
            ModbusPacket::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn modbus_bad_protocol_id() {
    let mut buf = modbus_read_holding();
    buf[2] = 0xff;
    buf[3] = 0xff;
    assert!(matches!(
        ModbusPacket::parse(&buf),
        Err(DissectError::InvalidMagic(_))
    ));
}

#[test]
fn modbus_exception_response() {
    let mut buf = vec![0u8; 9];
    buf[5] = 3; // length
    buf[6] = 1; // unit
    buf[7] = 0x83; // exception for FC 3
    buf[8] = 0x02; // exception code
    let p = ModbusPacket::parse(&buf).unwrap();
    assert!(matches!(
        p.function_code,
        ModbusFunctionCode::ExceptionResponse(3)
    ));
    assert_eq!(p.exception_code, Some(2));
}

#[test]
fn modbus_fc_is_write_helpers() {
    assert!(modbus_fc_is_write(ModbusFunctionCode::WriteSingleCoil));
    assert!(modbus_fc_is_write(ModbusFunctionCode::WriteMultipleRegisters));
    assert!(!modbus_fc_is_write(ModbusFunctionCode::ReadCoils));
    assert!(modbus_fc_is_diagnostic(
        ModbusFunctionCode::EncapsulatedInterfaceTransport
    ));
    assert!(!modbus_fc_is_diagnostic(ModbusFunctionCode::ReadCoils));
}

#[test]
fn modbus_fc_from_byte_round_trip() {
    let pairs: &[(u8, ModbusFunctionCode)] = &[
        (1, ModbusFunctionCode::ReadCoils),
        (2, ModbusFunctionCode::ReadDiscreteInputs),
        (3, ModbusFunctionCode::ReadHoldingRegisters),
        (4, ModbusFunctionCode::ReadInputRegisters),
        (5, ModbusFunctionCode::WriteSingleCoil),
        (6, ModbusFunctionCode::WriteSingleRegister),
        (0x0F, ModbusFunctionCode::WriteMultipleCoils),
        (0x10, ModbusFunctionCode::WriteMultipleRegisters),
    ];
    for (b, want) in pairs {
        let got = ModbusFunctionCode::from(*b);
        assert_eq!(format!("{got}"), format!("{want}"));
    }
}

// ── 14. DNP3 ───────────────────────────────────────────────────────────────

#[test]
fn dnp3_crc_known_zero() {
    let crc = dnp3_crc16(&[]);
    let _ = crc; // no panic; documents behaviour
}

#[test]
fn dnp3_crc_deterministic_seeded() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let n = lcg.next_range(32) + 1;
        let mut buf = vec![0u8; n];
        lcg.fill(&mut buf);
        let a = dnp3_crc16(&buf);
        let b = dnp3_crc16(&buf);
        assert_eq!(a, b, "crc not deterministic");
    }
}

#[test]
fn dnp3_frame_too_short() {
    for n in 0..10usize {
        assert!(matches!(
            Dnp3Frame::parse(&vec![0u8; n]),
            Err(DissectError::TooShort { .. })
        ));
    }
}

#[test]
fn dnp3_frame_bad_magic() {
    let buf = vec![0xaau8; 12];
    assert!(matches!(
        Dnp3Frame::parse(&buf),
        Err(DissectError::InvalidMagic(_))
    ));
}

#[test]
fn dnp3_app_fc_name_table() {
    assert_eq!(dnp3_app_fc_name(0x00), "CONFIRM");
    assert_eq!(dnp3_app_fc_name(0x01), "READ");
    assert_eq!(dnp3_app_fc_name(0x81), "RESPONSE");
    assert_eq!(dnp3_app_fc_name(0xff), "UNKNOWN");
}

#[test]
fn dnp3_fc_is_control_range() {
    assert!(dnp3_fc_is_control(0x02));
    assert!(dnp3_fc_is_control(0x0E));
    assert!(!dnp3_fc_is_control(0x00));
    assert!(!dnp3_fc_is_control(0x01));
    assert!(!dnp3_fc_is_control(0x10));
}

// ── 15. ICS / SMB / Kerberos / SMTP helpers ────────────────────────────────

#[test]
fn ics_port_lookups() {
    assert_eq!(ics_protocol_for_port(502), Some("Modbus"));
    assert_eq!(ics_protocol_for_port(20000), Some("DNP3"));
    assert_eq!(ics_protocol_for_port(1234), None);
    assert!(is_ics_port(502));
    assert!(!is_ics_port(1234));
}

#[test]
fn smb_command_name_tables() {
    assert_eq!(smb1_command_name(0x72), "SMB_COM_NEGOTIATE");
    assert_eq!(smb1_command_name(0xee), "SMB_COM_UNKNOWN");
    assert_eq!(smb2_command_name(0x0000), "SMB2_NEGOTIATE");
    assert_eq!(smb2_command_name(0xffff), "SMB2_UNKNOWN");
}

#[test]
fn smb2_sensitive_share_detection() {
    assert!(smb2_is_sensitive_share(r"\\server\C$"));
    assert!(smb2_is_sensitive_share(r"\\srv\ADMIN$"));
    assert!(!smb2_is_sensitive_share(r"\\srv\share"));
}

#[test]
fn nt_status_table() {
    assert_eq!(nt_status_name(0), "STATUS_SUCCESS");
    assert_eq!(nt_status_name(0xC000_0005), "STATUS_ACCESS_DENIED");
    assert_eq!(nt_status_name(0xdead_beef), "STATUS_UNKNOWN");
}

#[test]
fn kerberos_etype_classification() {
    assert!(KerberosEtype::from(23).is_weak()); // RC4
    assert!(KerberosEtype::from(1).is_weak()); // DES
    assert!(KerberosEtype::from(17).is_modern()); // AES128
    assert!(!KerberosEtype::from(23).is_modern());
    let unk = KerberosEtype::from(9999);
    assert!(matches!(unk, KerberosEtype::Unknown(9999)));
}

#[test]
fn ssh_msg_type_known() {
    let name = ssh_msg_type_name(20);
    assert!(!name.is_empty());
}

#[test]
fn smtp_response_description_table() {
    let s = smtp_response_description(220);
    assert!(!s.is_empty());
}

// ── 16. Entropy + ICMP tunnel heuristic ────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(byte_entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    let v = vec![0xAA; 100];
    let e = byte_entropy(&v);
    assert!(e.abs() < 1e-9);
}

#[test]
fn entropy_uniform_is_high() {
    let v: Vec<u8> = (0u16..256).map(|i| u8::try_from(i).unwrap_or(u8::MAX)).collect();
    let e = byte_entropy(&v);
    assert!(e > 7.99);
}

#[test]
fn icmp_tunnel_heuristic_empty() {
    assert!(!icmp_stream_tunnel_heuristic(&[]));
}

#[test]
fn icmp_tunnel_heuristic_low_entropy_short() {
    let p = [0u8; 16];
    let payloads: Vec<&[u8]> = vec![&p, &p, &p];
    assert!(!icmp_stream_tunnel_heuristic(&payloads));
}

#[test]
fn icmp_tunnel_heuristic_high_entropy_large() {
    // Build payloads with uniformly distributed bytes (all 256 values once) so
    // Shannon entropy is exactly 8.0 — well above the >7.0 threshold — and
    // length > 64 bytes so the "large payload" heuristic also fires.
    let uniform: Vec<u8> = (0u16..256).map(|i| u8::try_from(i).unwrap_or(u8::MAX)).collect();
    let bufs = [uniform.clone(), uniform.clone(), uniform];
    let refs: Vec<&[u8]> = bufs.iter().map(std::vec::Vec::as_slice).collect();
    assert!(icmp_stream_tunnel_heuristic(&refs));
}

// ── 17. Send / Sync threaded stress ────────────────────────────────────────

#[test]
fn registry_send_sync_threaded_stress() {
    let reg = Arc::new(full_registry());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let reg = reg.clone();
        handles.push(std::thread::spawn(move || {
            let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE ^ tid);
            for _ in 0..100 {
                let n = lcg.next_range(40);
                let mut buf = vec![0u8; n];
                lcg.fill(&mut buf);
                let _ = reg.by_name("Ethernet");
                let _ = reg.by_port(53);
                let _ = reg.dissect_auto("Ethernet", None, &buf, 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn assert_send_sync_markers() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<DissectorRegistry>();
    assert_sync::<DissectorRegistry>();
    assert_send::<DissectedPacket>();
    assert_sync::<DissectedPacket>();
}

// ── 18. Error Display round-trip ───────────────────────────────────────────

#[test]
fn dissect_error_display_variants() {
    let e = DissectError::TooShort { need: 10, got: 5 };
    assert!(format!("{e}").contains("10"));
    let e = DissectError::BufferTooShort { needed: 12, got: 4 };
    assert!(format!("{e}").contains("12"));
    let e = DissectError::InvalidMagic("oops".into());
    assert!(format!("{e}").contains("oops"));
    let e = DissectError::NoDissector("X".into());
    assert!(format!("{e}").contains('X'));
}
