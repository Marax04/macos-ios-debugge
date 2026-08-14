//! Exhaustive test suite for rustre-net-pcap core API.

use rustre_net_pcap::*;

// ----- LinkType round-trip -----

#[test]
fn linktype_roundtrip_known() {
    for v in [0u16, 1, 3, 6, 7, 8, 9, 10, 50, 51, 100, 101, 102, 105, 107, 108, 113, 114, 117, 127, 129, 228, 229] {
        let lt = LinkType::from_u16(v);
        assert_eq!(lt.as_u16(), v, "round-trip failed for {v}");
    }
}

#[test]
fn linktype_unknown_roundtrip() {
    for v in [2u16, 4, 5, 999, 65535] {
        let lt = LinkType::from_u16(v);
        assert!(matches!(lt, LinkType::Unknown(x) if x == v));
        assert_eq!(lt.as_u16(), v);
    }
}

#[test]
fn linktype_eq_and_display() {
    assert_eq!(LinkType::Ethernet, LinkType::from_u16(1));
    assert_ne!(LinkType::Ethernet, LinkType::Null);
    let s = format!("{}", LinkType::Ethernet);
    assert!(s.contains("Ethernet"));
}

// ----- PcapWriter -> PcapReader round-trip -----

fn build_minimal_pcap(records: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut w = PcapWriter::new(u32::from(LinkType::Ethernet.as_u16()));
    for (s, u, d) in records {
        w.add_packet(*s, *u, d);
    }
    w.finish()
}

#[test]
fn pcapwriter_empty_finish_parses() {
    let bytes = PcapWriter::new(1).finish();
    assert_eq!(bytes.len(), 24);
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records.len(), 0);
    assert_eq!(r.global.network, 1);
    assert_eq!(r.global.version_major, 2);
}

#[test]
fn pcapwriter_to_bytes_does_not_consume() {
    let mut w = PcapWriter::new(1);
    w.add_packet(1, 2, b"hello");
    let a = w.to_bytes();
    let b = w.to_bytes();
    assert_eq!(a, b);
    assert!(!w.is_empty());
    assert_eq!(w.network(), 1);
}

#[test]
fn pcapwriter_multiple_packets_roundtrip() {
    let bytes = build_minimal_pcap(&[
        (10, 20, b"abc"),
        (30, 40, b"defghi"),
        (50, 60, b""),
    ]);
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records.len(), 3);
    assert_eq!(r.records[0].ts_sec, 10);
    assert_eq!(r.records[0].ts_usec, 20);
    assert_eq!(r.records[0].data, b"abc");
    assert_eq!(r.records[1].data, b"defghi");
    assert_eq!(r.records[2].data, b"");
    assert_eq!(r.records[2].incl_len, 0);
    assert_eq!(r.records[2].orig_len, 0);
}

#[test]
fn pcapfilewriter_roundtrip_matches_pcapwriter() {
    let mut a = PcapWriter::new(1);
    let mut b = PcapFileWriter::new(1);
    for i in 0u32..5 {
        let d = vec![u8::try_from(i).unwrap_or(u8::MAX); (i as usize) * 3];
        a.add_packet(i, i * 1000, &d);
        b.add_packet(i, i * 1000, &d);
    }
    assert_eq!(a.finish(), b.finish());
}

#[test]
fn pcapfilewriter_network_getter() {
    let w = PcapFileWriter::new(42);
    assert_eq!(w.network(), 42);
}

// ----- MemoryPcapReader -----

#[test]
fn memory_pcap_reader_basic() {
    let bytes = build_minimal_pcap(&[(1, 2, b"xyz"), (3, 4, b"q")]);
    let r = MemoryPcapReader::from_bytes(&bytes).unwrap();
    assert_eq!(r.len(), 2);
    assert!(!r.is_empty());
    assert!(r.header.little_endian);
    assert_eq!(r.header.version_major, 2);
    assert_eq!(r.iter().count(), 2);
    assert_eq!(r.records[0].captured_len(), 3);
}

#[test]
fn memory_pcap_reader_empty_records() {
    let bytes = PcapWriter::new(1).finish();
    let r = MemoryPcapReader::from_bytes(&bytes).unwrap();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

// ----- Header parsing errors -----

fn pcap_parse_err(b: &[u8]) -> PcapError {
    match PcapReader::parse(b) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    }
}
fn mem_parse_err(b: &[u8]) -> PcapError {
    match MemoryPcapReader::from_bytes(b) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    }
}
fn ng_parse_err(b: &[u8]) -> PcapError {
    match PcapNgReader::from_bytes(b) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    }
}

#[test]
fn parse_too_short() {
    let err = pcap_parse_err(&[0u8; 5]);
    assert!(matches!(err, PcapError::BufferTooShort { needed: 24, got: 5 }));
}

#[test]
fn parse_invalid_magic() {
    let mut bytes = vec![0u8; 24];
    bytes[0] = 0xFF;
    bytes[1] = 0xFF;
    bytes[2] = 0xFF;
    bytes[3] = 0xFF;
    let err = pcap_parse_err(&bytes);
    assert!(matches!(err, PcapError::InvalidMagic(_)));
}

#[test]
fn parse_truncated_record() {
    let mut bytes = build_minimal_pcap(&[(1, 2, b"hello world")]);
    bytes.truncate(bytes.len() - 3);
    let err = pcap_parse_err(&bytes);
    assert!(matches!(err, PcapError::RecordTruncated));
}

#[test]
fn parse_trailing_partial_header_is_ok_in_pcapreader() {
    // PcapReader::parse loop: `if offset + 16 > bytes.len() { break; }` — accepts trailing partial.
    let mut bytes = build_minimal_pcap(&[(1, 2, b"x")]);
    bytes.extend_from_slice(&[0, 0, 0]); // trailing junk less than 16 bytes
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records.len(), 1);
}

#[test]
fn memory_pcap_reader_be_magic() {
    // Build BE pcap header manually
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xD4C3_B2A1_u32.to_be_bytes());
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&0i32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&65535u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes()); // ethernet
    let r = MemoryPcapReader::from_bytes(&bytes).unwrap();
    assert!(!r.header.little_endian);
    assert_eq!(r.header.linktype, LinkType::Ethernet);
}

#[test]
fn parse_unsupported_version_via_memory_reader() {
    let mut bytes = PcapWriter::new(1).finish();
    // version_major lives at offset 4..6 little-endian.
    bytes[4] = 3;
    bytes[5] = 0;
    let err = mem_parse_err(&bytes);
    assert!(matches!(err, PcapError::UnsupportedVersion { major: 3, .. }));
}

// ----- Nanosecond magic -----

#[test]
fn parse_nano_magic_le() {
    let mut bytes = vec![0u8; 24];
    bytes[0..4].copy_from_slice(&0xA1B2_3C4D_u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&4u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&65535u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    let r = MemoryPcapReader::from_bytes(&bytes).unwrap();
    assert!(r.header.nanosecond_ts);
    assert!(r.header.little_endian);
}

// ----- PcapFile -----

#[test]
fn pcapfile_parse_iter_count_bytes() {
    // Payloads of *different* lengths on purpose. The fixture used to be two
    // single-byte packets, which made `total_bytes()` and `record_count()` both
    // equal 2 — the assertion could not tell "sums payload lengths" from
    // "counts records". (It was also asserting 8, a leftover from an older
    // fixture, and had been failing ever since.)
    let bytes = build_minimal_pcap(&[(0, 0, b"ab"), (0, 0, b"cdef")]);
    let f = PcapFile::parse(&bytes).unwrap();
    assert_eq!(f.record_count(), 2);
    assert_eq!(f.total_bytes(), 6, "2 + 4 payload bytes, headers excluded");
    assert_eq!(f.iter_records().count(), 2);
}

// ----- StreamPcapWriter -----

#[test]
fn stream_writer_roundtrip() {
    let mut buf = Vec::new();
    {
        let mut w = StreamPcapWriter::new(&mut buf, 65535, LinkType::Ethernet).unwrap();
        assert_eq!(w.record_count(), 0);
        assert_eq!(w.linktype(), LinkType::Ethernet);
        w.write_packet(1, 2, b"hello").unwrap();
        w.write_packet(3, 4, b"world!!").unwrap();
        assert_eq!(w.record_count(), 2);
        w.flush().unwrap();
    }
    let r = PcapReader::parse(&buf).unwrap();
    assert_eq!(r.records.len(), 2);
    assert_eq!(r.records[0].data, b"hello");
    assert_eq!(r.records[1].data, b"world!!");
}

#[test]
fn stream_writer_truncates_to_snaplen() {
    let mut buf = Vec::new();
    {
        let mut w = StreamPcapWriter::new(&mut buf, 4, LinkType::Ethernet).unwrap();
        w.write_packet(0, 0, b"abcdefghij").unwrap();
    }
    let r = PcapReader::parse(&buf).unwrap();
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.records[0].data, b"abcd");
    assert_eq!(r.records[0].incl_len, 4);
    assert_eq!(r.records[0].orig_len, 10);
}

// ----- PcapNgWriter / PcapNgReader round-trip -----

#[test]
fn pcapng_roundtrip_basic() {
    let mut w = PcapNgWriter::new(LinkType::Ethernet);
    w.add_packet(0x0000_0001_0000_0002, b"abcd");
    w.add_packet(0x0000_0001_0000_0003, b"xyz");
    assert_eq!(w.packet_count(), 2);
    let bytes = w.finish();
    let r = PcapNgReader::from_bytes(&bytes).unwrap();
    assert!(!r.is_empty());
    let epbs = r.enhanced_packets();
    assert_eq!(epbs.len(), 2);
    assert_eq!(epbs[0].data, b"abcd");
    assert_eq!(epbs[0].captured_len, 4);
    let ts = epbs[0].timestamp();
    assert_eq!(ts, 0x0000_0001_0000_0002);
    let ifaces = r.interfaces();
    assert_eq!(ifaces.len(), 1);
    assert_eq!(ifaces[0].link_type, LinkType::Ethernet);
}

#[test]
fn pcapng_reader_empty_writer() {
    let w = PcapNgWriter::new(LinkType::Ethernet);
    let bytes = w.finish();
    let r = PcapNgReader::from_bytes(&bytes).unwrap();
    assert_eq!(r.interfaces().len(), 1);
    assert_eq!(r.enhanced_packets().len(), 0);
    assert!(!r.is_empty()); // SHB + IDB
    assert_eq!(r.len(), 2);
}

#[test]
fn pcapng_no_section_header() {
    let mut bytes = vec![0u8; 16];
    bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let err = ng_parse_err(&bytes);
    assert!(matches!(err, PcapError::NoSectionHeader));
}

#[test]
fn pcapng_too_short() {
    let err = ng_parse_err(&[0u8; 4]);
    assert!(matches!(err, PcapError::BufferTooShort { .. }));
}

// ----- BPF VM basics -----

#[test]
fn bpf_ret_k_accept_reject() {
    let accept = BpfVm::new(vec![BpfInsn::new(bpf_ops::RET_K, 0, 0, BPF_ACCEPT)]);
    assert!(accept.accepts(&[]));
    assert_eq!(accept.run(&[1, 2, 3]), BPF_ACCEPT);
    let reject = BpfVm::new(vec![BpfInsn::new(bpf_ops::RET_K, 0, 0, BPF_REJECT)]);
    assert!(!reject.accepts(&[]));
    assert_eq!(reject.run(&[1]), BPF_REJECT);
}

#[test]
fn bpf_ld_len_ret_a() {
    let prog = vec![
        BpfInsn::new(bpf_ops::LD_LEN, 0, 0, 0),
        BpfInsn::new(bpf_ops::RET_A, 0, 0, 0),
    ];
    let vm = BpfVm::new(prog);
    assert_eq!(vm.run(&[0u8; 7]), 7);
}

#[test]
fn bpf_falls_off_end_rejects() {
    // No RET in program → falls off end → reject.
    let prog = vec![BpfInsn::new(bpf_ops::LD_IMM, 0, 0, 42)];
    assert_eq!(BpfVm::new(prog).run(&[]), BPF_REJECT);
}

#[test]
fn bpf_unknown_opcode_rejects() {
    let prog = vec![BpfInsn::new(0xFFFF, 0, 0, 0)];
    assert_eq!(BpfVm::new(prog).run(&[1, 2, 3]), BPF_REJECT);
}

#[test]
fn bpf_oob_load_rejects() {
    let prog = vec![
        BpfInsn::new(bpf_ops::LD_W_ABS, 0, 0, 100),
        BpfInsn::new(bpf_ops::RET_A, 0, 0, 0),
    ];
    assert_eq!(BpfVm::new(prog).run(&[1, 2, 3]), BPF_REJECT);
}

// ----- FilterExpr compiler -----

fn make_eth_ip_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 20 + payload_len];
    // Ethernet ethertype IPv4
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 protocol = TCP (6) at offset 23
    p[23] = 6;
    // src/dst IP
    p[26..30].copy_from_slice(&src_ip);
    p[30..34].copy_from_slice(&dst_ip);
    // TCP src/dst port
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p
}

fn make_eth_ip_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 8];
    p[12] = 0x08;
    p[13] = 0x00;
    p[23] = 17;
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p
}

#[test]
fn filter_all_accepts_everything() {
    let vm = FilterExpr::All.compile();
    assert!(vm.accepts(&[]));
    assert!(vm.accepts(&[1, 2, 3]));
}

#[test]
fn filter_none_rejects_everything() {
    let vm = FilterExpr::None.compile();
    assert!(!vm.accepts(&[]));
    assert!(!vm.accepts(&[1, 2, 3]));
}

#[test]
fn filter_ipv4_accepts_ipv4() {
    let vm = FilterExpr::Ipv4.compile();
    let p = make_eth_ip_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1000, 80, 0);
    assert!(vm.accepts(&p));
    let mut q = p;
    q[12] = 0x86;
    q[13] = 0xDD; // IPv6 ethertype
    assert!(!vm.accepts(&q));
}

#[test]
fn filter_ipv6_accepts_ipv6() {
    let vm = FilterExpr::Ipv6.compile();
    let mut p = vec![0u8; 40];
    p[12] = 0x86;
    p[13] = 0xDD;
    assert!(vm.accepts(&p));
}

#[test]
fn filter_tcp_udp() {
    let tcp_vm = FilterExpr::Tcp.compile();
    let udp_vm = FilterExpr::Udp.compile();
    let tcp = make_eth_ip_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1, 80, 0);
    let udp = make_eth_ip_udp(1, 53);
    assert!(tcp_vm.accepts(&tcp));
    assert!(!tcp_vm.accepts(&udp));
    assert!(udp_vm.accepts(&udp));
    assert!(!udp_vm.accepts(&tcp));
}

#[test]
fn filter_dst_port() {
    let vm = FilterExpr::DstPort(80).compile();
    let p80 = make_eth_ip_tcp([0; 4], [0; 4], 1000, 80, 0);
    let p443 = make_eth_ip_tcp([0; 4], [0; 4], 1000, 443, 0);
    assert!(vm.accepts(&p80));
    assert!(!vm.accepts(&p443));
}

#[test]
fn filter_src_port() {
    let vm = FilterExpr::SrcPort(1234).compile();
    let p = make_eth_ip_tcp([0; 4], [0; 4], 1234, 80, 0);
    assert!(vm.accepts(&p));
    let q = make_eth_ip_tcp([0; 4], [0; 4], 9999, 80, 0);
    assert!(!vm.accepts(&q));
}

#[test]
fn filter_not_inverts() {
    let vm = FilterExpr::Not(Box::new(FilterExpr::All)).compile();
    assert!(!vm.accepts(&[1, 2]));
    let vm2 = FilterExpr::Not(Box::new(FilterExpr::None)).compile();
    assert!(vm2.accepts(&[1, 2]));
}

#[test]
fn filter_len_gt_and_lt() {
    let gt = FilterExpr::LenGt(10).compile();
    assert!(gt.accepts(&[0u8; 11]));
    assert!(!gt.accepts(&[0u8; 10]));
    assert!(!gt.accepts(&[0u8; 5]));

    let lt = FilterExpr::LenLt(10).compile();
    assert!(lt.accepts(&[0u8; 5]));
    assert!(!lt.accepts(&[0u8; 10]));
    assert!(!lt.accepts(&[0u8; 11]));
}

#[test]
fn filter_and_combinator() {
    let expr = FilterExpr::And(
        Box::new(FilterExpr::Ipv4),
        Box::new(FilterExpr::Tcp),
    );
    let vm = expr.compile();
    let tcp = make_eth_ip_tcp([0; 4], [0; 4], 1, 80, 0);
    let udp = make_eth_ip_udp(1, 53);
    assert!(vm.accepts(&tcp));
    assert!(!vm.accepts(&udp));
}

#[test]
fn filter_or_combinator() {
    let expr = FilterExpr::Or(
        Box::new(FilterExpr::DstPort(80)),
        Box::new(FilterExpr::DstPort(443)),
    );
    let vm = expr.compile();
    let p80 = make_eth_ip_tcp([0; 4], [0; 4], 1, 80, 0);
    let p443 = make_eth_ip_tcp([0; 4], [0; 4], 1, 443, 0);
    let p22 = make_eth_ip_tcp([0; 4], [0; 4], 1, 22, 0);
    assert!(vm.accepts(&p80));
    assert!(vm.accepts(&p443));
    assert!(!vm.accepts(&p22));
}

#[test]
fn filter_port_either_direction() {
    let vm = FilterExpr::Port(53).compile();
    let dst = make_eth_ip_udp(1000, 53);
    let src = make_eth_ip_udp(53, 1000);
    let neither = make_eth_ip_udp(80, 443);
    assert!(vm.accepts(&dst));
    assert!(vm.accepts(&src));
    assert!(!vm.accepts(&neither));
}

#[test]
fn filter_pcap_records_applies_vm() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &make_eth_ip_tcp([0; 4], [0; 4], 1, 80, 0));
    w.add_packet(0, 0, &make_eth_ip_udp(1, 53));
    w.add_packet(0, 0, &make_eth_ip_tcp([0; 4], [0; 4], 1, 443, 0));
    let bytes = w.finish();
    let r = PcapReader::parse(&bytes).unwrap();
    let vm = FilterExpr::Tcp.compile();
    let filtered = filter_pcap_records(&r.records, &vm);
    assert_eq!(filtered.len(), 2);
}

// ----- PcapStats -----

#[test]
fn pcap_stats_empty() {
    let s = PcapStats::compute(&[]);
    assert_eq!(s.packet_count, 0);
    assert_eq!(s.total_bytes, 0);
    assert_eq!(s.min_pkt_size, 0);
    assert_eq!(s.max_pkt_size, 0);
    assert!((s.avg_pkt_size - 0.0).abs() < f64::EPSILON);
    assert!((s.duration_secs - 0.0).abs() < f64::EPSILON);
    assert!((s.pps - 0.0).abs() < f64::EPSILON);
    assert!((s.bps - 0.0).abs() < f64::EPSILON);
    assert_eq!(s.truncated, 0);
}

#[test]
fn pcap_stats_basic() {
    let bytes = build_minimal_pcap(&[(10, 0, b"abcd"), (20, 0, b"xyz")]);
    let f = PcapFile::parse(&bytes).unwrap();
    let s = PcapStats::from_file(&f);
    assert_eq!(s.packet_count, 2);
    assert_eq!(s.total_bytes, 7);
    assert_eq!(s.min_pkt_size, 3);
    assert_eq!(s.max_pkt_size, 4);
    assert!((s.duration_secs - 10.0).abs() < 1e-6);
    assert!((s.pps - 0.2).abs() < 1e-6);
    let disp = format!("{s}");
    assert!(disp.contains("2 pkts"));
}

#[test]
fn pcap_stats_truncated_counted() {
    let recs = vec![
        PcapFileRecord { ts_sec: 0, ts_usec: 0, incl_len: 4, orig_len: 100, data: vec![0; 4] },
        PcapFileRecord { ts_sec: 1, ts_usec: 0, incl_len: 5, orig_len: 5, data: vec![0; 5] },
    ];
    let s = PcapStats::compute(&recs);
    assert_eq!(s.truncated, 1);
}

// ----- PacketSummary -----

#[test]
fn summarize_tcp_packet() {
    let data = make_eth_ip_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, 0);
    let r = PcapFileRecord {
        ts_sec: 1, ts_usec: 2,
        incl_len: u32::try_from(data.len()).unwrap_or(u32::MAX), orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX), data,
    };
    let s = summarize_packet(0, &r);
    assert_eq!(s.protocol, "TCP");
    assert!(s.src.starts_with("10.0.0.1:1000"));
    assert!(s.dst.starts_with("10.0.0.2:80"));
    assert!(!s.truncated);
    let disp = format!("{s}");
    assert!(disp.contains("TCP"));
}

#[test]
fn summarize_udp_packet() {
    let data = make_eth_ip_udp(1234, 53);
    let r = PcapFileRecord {
        ts_sec: 0, ts_usec: 0,
        incl_len: u32::try_from(data.len()).unwrap_or(u32::MAX), orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX), data,
    };
    let s = summarize_packet(7, &r);
    assert_eq!(s.protocol, "UDP");
    assert_eq!(s.index, 7);
}

#[test]
fn summarize_arp() {
    let mut data = vec![0u8; 14];
    data[12] = 0x08;
    data[13] = 0x06;
    let r = PcapFileRecord {
        ts_sec: 0, ts_usec: 0, incl_len: 14, orig_len: 14, data,
    };
    let s = summarize_packet(0, &r);
    assert_eq!(s.protocol, "ARP");
}

#[test]
fn summarize_ipv6() {
    let mut data = vec![0u8; 40];
    data[12] = 0x86;
    data[13] = 0xDD;
    let r = PcapFileRecord {
        ts_sec: 0, ts_usec: 0, incl_len: 40, orig_len: 40, data,
    };
    let s = summarize_packet(0, &r);
    assert_eq!(s.protocol, "IPv6");
}

#[test]
fn summarize_truncated_flag() {
    let r = PcapFileRecord {
        ts_sec: 0, ts_usec: 0, incl_len: 14, orig_len: 1500, data: vec![0u8; 14],
    };
    let s = summarize_packet(0, &r);
    assert!(s.truncated);
}

#[test]
fn summarize_too_short_unknown() {
    let r = PcapFileRecord {
        ts_sec: 0, ts_usec: 0, incl_len: 5, orig_len: 5, data: vec![0u8; 5],
    };
    let s = summarize_packet(0, &r);
    assert_eq!(s.protocol, "Unknown");
}

// ----- FiveTuple -----

#[test]
fn five_tuple_canonical_symmetry() {
    let a = FiveTuple::canonical("1.1.1.1", "2.2.2.2", 100, 200, 6);
    let b = FiveTuple::canonical("2.2.2.2", "1.1.1.1", 200, 100, 6);
    assert_eq!(a, b);
}

#[test]
fn five_tuple_hash_consistent() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = FiveTuple::canonical("1.1.1.1", "2.2.2.2", 100, 200, 6);
    let b = FiveTuple::canonical("2.2.2.2", "1.1.1.1", 200, 100, 6);
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn five_tuple_display() {
    let t = FiveTuple::canonical("1.1.1.1", "2.2.2.2", 100, 200, 6);
    let s = format!("{t}");
    assert!(s.contains("<->"));
    assert!(s.contains("proto=6"));
}

// ----- PcapRecord display & captured_len -----

#[test]
fn pcaprecord_captured_len_and_display() {
    let r = PcapRecord { ts_sec: 5, ts_usec: 7, orig_len: 100, data: vec![0u8; 42] };
    assert_eq!(r.captured_len(), 42);
    let s = format!("{r}");
    assert!(s.contains("orig_len=100"));
    assert!(s.contains("cap_len=42"));
}

// ----- Error display -----

#[test]
fn error_display_messages() {
    let e = PcapError::InvalidMagic(0xDEAD_BEEF);
    assert!(format!("{e}").contains("deadbeef"));
    let e = PcapError::UnsupportedVersion { major: 3, minor: 1 };
    assert!(format!("{e}").contains("3.1"));
    let e = PcapError::BufferTooShort { needed: 100, got: 5 };
    assert!(format!("{e}").contains("100"));
    let e = PcapError::InterfaceNotFound(7);
    assert!(format!("{e}").contains('7'));
}

// ----- PCAPNG block parsing edge cases -----

#[test]
fn pcapng_block_length_mismatch() {
    // Build SHB with mismatched trailing length
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes()); // SHB
    bytes.extend_from_slice(&28u32.to_le_bytes()); // block_len
    bytes.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // BOM
    bytes.extend_from_slice(&1u16.to_le_bytes()); // major
    bytes.extend_from_slice(&0u16.to_le_bytes()); // minor
    bytes.extend_from_slice(&(-1i64).to_le_bytes()); // section_length
    bytes.extend_from_slice(&999u32.to_le_bytes()); // WRONG trailing length
    let err = ng_parse_err(&bytes);
    assert!(matches!(err, PcapError::BlockLengthMismatch));
}
