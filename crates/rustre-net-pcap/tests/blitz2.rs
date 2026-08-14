//! Deep adversarial tests for rustre-net-pcap public API.

use rustre_net_pcap::*;
use std::io::Cursor;

// ---------------- helpers ----------------

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn build_pcap(records: &[(u32, u32, Vec<u8>)], network: u32) -> Vec<u8> {
    let mut w = PcapWriter::new(network);
    for (s, u, d) in records {
        w.add_packet(*s, *u, d);
    }
    w.finish()
}

fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0xff; 6]); // dst mac
    v.extend_from_slice(&[0x00; 6]); // src mac
    v.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
    // IPv4: ver=4 ihl=5
    v.push(0x45);
    v.push(0); // dscp
    let ip_total_len = (20u16 + 20 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes();
    v.extend_from_slice(&ip_total_len);
    v.extend_from_slice(&[0, 0]); // id
    v.extend_from_slice(&[0, 0]); // flags/frag
    v.push(64); // ttl
    v.push(6); // proto TCP
    v.extend_from_slice(&[0, 0]); // checksum
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    // TCP header (20 bytes, data offset = 5 => 0x50)
    v.extend_from_slice(&sp.to_be_bytes());
    v.extend_from_slice(&dp.to_be_bytes());
    v.extend_from_slice(&[0; 4]); // seq
    v.extend_from_slice(&[0; 4]); // ack
    v.push(0x50); // data offset
    v.push(0x18); // flags
    v.extend_from_slice(&[0xff, 0xff]); // window
    v.extend_from_slice(&[0, 0]); // chk
    v.extend_from_slice(&[0, 0]); // urg
    v.extend_from_slice(payload);
    v
}

fn eth_ipv4_udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0xff; 6]);
    v.extend_from_slice(&[0x00; 6]);
    v.extend_from_slice(&[0x08, 0x00]);
    v.push(0x45);
    v.push(0);
    let ip_total_len = (20u16 + 8 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes();
    v.extend_from_slice(&ip_total_len);
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&[0, 0]);
    v.push(64);
    v.push(17);
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&sp.to_be_bytes());
    v.extend_from_slice(&dp.to_be_bytes());
    let ulen = (8u16 + u16::try_from(payload.len()).unwrap_or(u16::MAX)).to_be_bytes();
    v.extend_from_slice(&ulen);
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

// ---------------- LinkType ----------------

#[test]
fn linktype_full_roundtrip_known() {
    let known = [0u16, 1, 3, 6, 7, 8, 9, 10, 50, 51, 100, 101, 102, 105, 107, 108, 113, 114, 117, 127, 129, 228, 229];
    for v in known {
        let lt = LinkType::from_u16(v);
        assert_eq!(lt.as_u16(), v);
        assert_eq!(LinkType::from_u16(lt.as_u16()), lt);
    }
}

#[test]
fn linktype_unknown_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let v = u16::try_from(g()).unwrap_or(u16::MAX) ^ 0xABCD;
        let lt = LinkType::from_u16(v);
        assert_eq!(lt.as_u16(), v);
    }
}

#[test]
fn linktype_display_nonempty() {
    assert!(!LinkType::Ethernet.to_string().is_empty());
    assert!(!LinkType::Unknown(42).to_string().is_empty());
}

#[test]
fn linktype_boundaries() {
    assert_eq!(LinkType::from_u16(0), LinkType::Null);
    assert_eq!(LinkType::from_u16(u16::MAX), LinkType::Unknown(u16::MAX));
    assert_eq!(LinkType::from_u16(u16::MAX).as_u16(), u16::MAX);
}

// ---------------- PcapWriter / PcapReader / PcapFile ----------------

#[test]
fn pcap_writer_empty_header_only() {
    let w = PcapWriter::new(1);
    assert!(w.is_empty());
    let bytes = w.finish();
    assert_eq!(bytes.len(), 24);
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records.len(), 0);
    assert_eq!(r.global.network, 1);
    assert_eq!(r.global.version_major, 2);
    assert_eq!(r.global.version_minor, 4);
}

#[test]
fn pcap_writer_roundtrip_many() {
    let mut w = PcapWriter::new(1);
    let mut g = lcg();
    let mut expected = Vec::new();
    for i in 0..60u32 {
        let len = (g() % 200) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() & 0xff) as u8).collect();
        w.add_packet(i, i.wrapping_mul(7), &data);
        expected.push((i, i.wrapping_mul(7), data));
    }
    let bytes = w.finish();
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records.len(), expected.len());
    for (rec, (ts, tu, data)) in r.records.iter().zip(expected) {
        assert_eq!(rec.ts_sec, ts);
        assert_eq!(rec.ts_usec, tu);
        assert_eq!(rec.data, data);
        assert_eq!(rec.incl_len as usize, data.len());
        assert_eq!(rec.orig_len as usize, data.len());
    }
}

#[test]
fn pcap_to_bytes_idempotent() {
    let mut w = PcapWriter::new(1);
    w.add_packet(1, 2, &[1, 2, 3]);
    w.add_packet(3, 4, &[4, 5]);
    let a = w.to_bytes();
    let b = w.to_bytes();
    assert_eq!(a, b);
    assert_eq!(a, w.finish());
}

#[test]
fn pcap_reader_too_short() {
    for n in 0..24 {
        let b = vec![0u8; n];
        match PcapReader::parse(&b) {
            Err(PcapError::BufferTooShort { needed: 24, got }) => assert_eq!(got, n),
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}

#[test]
fn pcap_reader_invalid_magic_fuzz() {
    let mut g = lcg();
    for _ in 0..100 {
        let mut buf = build_pcap(&[], 1);
        let bad = u32::try_from(g()).unwrap_or(u32::MAX) | 0x8000_0000; // make it unlikely to be a valid magic
        if bad == 0xA1B2_C3D4 || bad == 0xD4C3_B2A1 || bad == 0xA1B2_3C4D || bad == 0x4D3C_B2A1 {
            continue;
        }
        buf[0..4].copy_from_slice(&bad.to_le_bytes());
        match PcapReader::parse(&buf) {
            Err(PcapError::InvalidMagic(_)) => {}
            other => panic!("expected InvalidMagic for {bad:#x}, got {other:?}"),
        }
    }
}

#[test]
fn pcap_reader_truncated_record() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &[1, 2, 3, 4, 5]);
    let mut bytes = w.finish();
    bytes.truncate(bytes.len() - 2);
    match PcapReader::parse(&bytes) {
        Err(PcapError::RecordTruncated) => {}
        other => panic!("expected RecordTruncated, got {other:?}"),
    }
}

#[test]
fn pcap_reader_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 200) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = PcapReader::parse(&buf);
        let _ = MemoryPcapReader::from_bytes(&buf);
        let _ = PcapFile::parse(&buf);
    }
}

#[test]
fn pcap_reader_overflow_incl_len() {
    // craft header + record with incl_len = u32::MAX
    let mut buf = build_pcap(&[], 1);
    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    buf.extend_from_slice(&u32::MAX.to_le_bytes()); // incl_len
    buf.extend_from_slice(&u32::MAX.to_le_bytes()); // orig_len
    match PcapReader::parse(&buf) {
        Err(PcapError::RecordTruncated) => {}
        other => panic!("expected RecordTruncated, got {other:?}"),
    }
}

#[test]
fn pcap_file_record_count_and_bytes() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &[1, 2, 3]);
    w.add_packet(1, 0, &[4, 5, 6, 7]);
    let bytes = w.finish();
    let pf = PcapFile::parse(&bytes).unwrap();
    assert_eq!(pf.record_count(), 2);
    assert_eq!(pf.total_bytes(), 7);
    assert_eq!(pf.iter_records().count(), 2);
}

#[test]
fn pcap_file_writer_roundtrip() {
    let mut w = PcapFileWriter::new(1);
    assert_eq!(w.network(), 1);
    w.add_packet(10, 20, &[0xAA, 0xBB]);
    let bytes = w.finish();
    let r = PcapReader::parse(&bytes).unwrap();
    assert_eq!(r.records[0].data, [0xAA, 0xBB]);
}

#[test]
fn stream_pcap_writer_roundtrip() {
    let mut buf = Vec::new();
    {
        let mut w =
            StreamPcapWriter::new(Cursor::new(&mut buf), 65535, LinkType::Ethernet).unwrap();
        for i in 0..20u32 {
            w.write_packet(i, i, &[u8::try_from(i).unwrap_or(u8::MAX); 8]).unwrap();
        }
        assert_eq!(w.record_count(), 20);
        w.flush().unwrap();
    }
    let r = MemoryPcapReader::from_bytes(&buf).unwrap();
    assert_eq!(r.len(), 20);
}

#[test]
fn stream_pcap_writer_snaplen_truncates() {
    let mut buf = Vec::new();
    {
        let mut w = StreamPcapWriter::new(Cursor::new(&mut buf), 3, LinkType::Ethernet).unwrap();
        w.write_packet(1, 2, &[10, 11, 12, 13, 14]).unwrap();
    }
    let r = MemoryPcapReader::from_bytes(&buf).unwrap();
    assert_eq!(r.records[0].data.len(), 3);
    assert_eq!(r.records[0].orig_len, 5);
}

// ---------------- MemoryPcapReader ----------------

#[test]
fn memory_reader_be_magic() {
    // build PCAP big-endian
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xA1B2_C3D4_u32.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&65535u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    let r = MemoryPcapReader::from_bytes(&buf).unwrap();
    assert!(!r.header.little_endian);
    assert_eq!(r.header.linktype, LinkType::Ethernet);
}

#[test]
fn memory_reader_nanosecond_magic() {
    let mut buf = build_pcap(&[], 1);
    buf[0..4].copy_from_slice(&0xA1B2_3C4D_u32.to_le_bytes());
    let r = MemoryPcapReader::from_bytes(&buf).unwrap();
    assert!(r.header.nanosecond_ts);
}

#[test]
fn memory_reader_unsupported_version() {
    let mut buf = build_pcap(&[], 1);
    buf[4..6].copy_from_slice(&3u16.to_le_bytes());
    match MemoryPcapReader::from_bytes(&buf) {
        Err(PcapError::UnsupportedVersion { major: 3, .. }) => {}
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

// ---------------- PcapRecord display ----------------

#[test]
fn pcap_record_display_format() {
    let r = PcapRecord {
        ts_sec: 5,
        ts_usec: 42,
        orig_len: 7,
        data: vec![1, 2, 3],
    };
    let s = r.to_string();
    assert!(s.contains("ts=5.000042"));
    assert!(s.contains("orig_len=7"));
    assert!(s.contains("cap_len=3"));
    assert_eq!(r.captured_len(), 3);
}

// ---------------- BPF VM ----------------

#[test]
fn bpf_accept_all() {
    let vm = FilterExpr::All.compile();
    assert!(vm.accepts(&[]));
    assert!(vm.accepts(&[1, 2, 3]));
    assert_eq!(vm.run(&[]), BPF_ACCEPT);
}

#[test]
fn bpf_reject_all() {
    let vm = FilterExpr::None.compile();
    assert!(!vm.accepts(&[]));
    assert!(!vm.accepts(&[9, 9, 9]));
    assert_eq!(vm.run(&[1, 2, 3]), BPF_REJECT);
}

#[test]
fn bpf_ipv4_filter_accepts_ipv4() {
    let vm = FilterExpr::Ipv4.compile();
    let pkt = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 80, 443, b"hi");
    assert!(vm.accepts(&pkt));
    // non-IPv4 packet (ethertype 0x86DD)
    let mut other = pkt;
    other[12] = 0x86;
    other[13] = 0xdd;
    assert!(!vm.accepts(&other));
}

#[test]
fn bpf_tcp_udp_distinct() {
    let tcp_vm = FilterExpr::Tcp.compile();
    let udp_vm = FilterExpr::Udp.compile();
    let tcp_pkt = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 80, 443, b"x");
    let udp_pkt = eth_ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 53, 53, b"x");
    assert!(tcp_vm.accepts(&tcp_pkt));
    assert!(!tcp_vm.accepts(&udp_pkt));
    assert!(udp_vm.accepts(&udp_pkt));
    assert!(!udp_vm.accepts(&tcp_pkt));
}

#[test]
fn bpf_dst_port_match() {
    let vm = FilterExpr::DstPort(443).compile();
    let pkt = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 80, 443, b"x");
    assert!(vm.accepts(&pkt));
    let pkt2 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 443, 80, b"x");
    assert!(!vm.accepts(&pkt2));
}

#[test]
fn bpf_src_port_match() {
    let vm = FilterExpr::SrcPort(80).compile();
    let pkt = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 80, 443, b"x");
    assert!(vm.accepts(&pkt));
    let pkt2 = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 81, 443, b"x");
    assert!(!vm.accepts(&pkt2));
}

#[test]
fn bpf_port_either() {
    let vm = FilterExpr::Port(8080).compile();
    let p1 = eth_ipv4_tcp([1; 4], [2; 4], 8080, 1234, b"x");
    let p2 = eth_ipv4_tcp([1; 4], [2; 4], 1234, 8080, b"x");
    let p3 = eth_ipv4_tcp([1; 4], [2; 4], 1000, 2000, b"x");
    assert!(vm.accepts(&p1));
    assert!(vm.accepts(&p2));
    assert!(!vm.accepts(&p3));
}

#[test]
fn bpf_not_inverts() {
    let vm_tcp = FilterExpr::Tcp.compile();
    let vm_not_tcp = FilterExpr::Not(Box::new(FilterExpr::Tcp)).compile();
    let tcp_pkt = eth_ipv4_tcp([1; 4], [2; 4], 80, 443, b"x");
    let udp_pkt = eth_ipv4_udp([1; 4], [2; 4], 53, 53, b"x");
    assert!(vm_tcp.accepts(&tcp_pkt));
    assert!(!vm_not_tcp.accepts(&tcp_pkt));
    assert!(!vm_tcp.accepts(&udp_pkt));
    assert!(vm_not_tcp.accepts(&udp_pkt));
}

#[test]
fn bpf_len_gt_lt() {
    let big = FilterExpr::LenGt(10).compile();
    let small = FilterExpr::LenLt(10).compile();
    assert!(big.accepts(&[0u8; 20]));
    assert!(!big.accepts(&[0u8; 5]));
    assert!(small.accepts(&[0u8; 5]));
    assert!(!small.accepts(&[0u8; 20]));
}

#[test]
fn bpf_short_packet_rejected_on_load() {
    let vm = FilterExpr::Ipv4.compile();
    // Packet too short for ethertype load at offset 12
    assert!(!vm.accepts(&[0u8; 5]));
}

#[test]
fn bpf_vm_unknown_opcode_rejects() {
    let prog = vec![BpfInsn::new(0xFFFF, 0, 0, 0)];
    let vm = BpfVm::new(prog);
    assert_eq!(vm.run(&[1, 2, 3]), BPF_REJECT);
}

#[test]
fn bpf_vm_alu_ops() {
    use bpf_ops::*;
    // LD_IMM 5; LDX_IMM 3; ALU_ADD_X; RET_A => 8
    let prog = vec![
        BpfInsn::new(LD_IMM, 0, 0, 5),
        BpfInsn::new(LDX_IMM, 0, 0, 3),
        BpfInsn::new(ALU_ADD_X, 0, 0, 0),
        BpfInsn::new(RET_A, 0, 0, 0),
    ];
    let vm = BpfVm::new(prog);
    assert_eq!(vm.run(&[]), 8);
}

#[test]
fn bpf_vm_rsh_overflow_safe() {
    use bpf_ops::*;
    let prog = vec![
        BpfInsn::new(LD_IMM, 0, 0, 0xFFFF_FFFF),
        BpfInsn::new(ALU_RSH_K, 0, 0, 64), // out of range
        BpfInsn::new(RET_A, 0, 0, 0),
    ];
    assert_eq!(BpfVm::new(prog).run(&[]), 0);
}

#[test]
fn bpf_vm_runs_off_end_rejects() {
    use bpf_ops::*;
    let prog = vec![BpfInsn::new(LD_IMM, 0, 0, 5)];
    let vm = BpfVm::new(prog);
    assert_eq!(vm.run(&[]), BPF_REJECT);
}

#[test]
fn bpf_fuzz_no_panic() {
    let mut g = lcg();
    let vm = FilterExpr::Or(
        Box::new(FilterExpr::Tcp),
        Box::new(FilterExpr::Udp),
    )
    .compile();
    for _ in 0..200 {
        let n = (g() % 100) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = vm.run(&buf);
    }
}

#[test]
fn filter_pcap_records_smoke() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &eth_ipv4_tcp([1; 4], [2; 4], 80, 443, b"x"));
    w.add_packet(1, 0, &eth_ipv4_udp([1; 4], [2; 4], 53, 53, b"x"));
    let bytes = w.finish();
    let r = PcapReader::parse(&bytes).unwrap();
    let vm = FilterExpr::Tcp.compile();
    let kept = filter_pcap_records(&r.records, &vm);
    assert_eq!(kept.len(), 1);
}

// ---------------- PcapStats ----------------

#[test]
fn pcap_stats_empty() {
    let s = PcapStats::compute(&[]);
    assert_eq!(s.packet_count, 0);
    assert_eq!(s.total_bytes, 0);
    assert!((s.duration_secs - 0.0).abs() < f64::EPSILON);
    assert!(s.to_string().contains("0 pkts"));
}

#[test]
fn pcap_stats_basic() {
    let recs = vec![
        PcapFileRecord {
            ts_sec: 10,
            ts_usec: 0,
            incl_len: 4,
            orig_len: 8, // truncated
            data: vec![0u8; 4],
        },
        PcapFileRecord {
            ts_sec: 20,
            ts_usec: 0,
            incl_len: 10,
            orig_len: 10,
            data: vec![0u8; 10],
        },
    ];
    let s = PcapStats::compute(&recs);
    assert_eq!(s.packet_count, 2);
    assert_eq!(s.total_bytes, 14);
    assert_eq!(s.min_pkt_size, 4);
    assert_eq!(s.max_pkt_size, 10);
    assert_eq!(s.truncated, 1);
    assert!((s.duration_secs - 10.0).abs() < f64::EPSILON);
}

#[test]
fn pcap_stats_from_file() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &[0u8; 5]);
    let bytes = w.finish();
    let pf = PcapFile::parse(&bytes).unwrap();
    let s = PcapStats::from_file(&pf);
    assert_eq!(s.packet_count, 1);
}

// ---------------- PacketSummary ----------------

#[test]
fn summarize_packet_tcp() {
    let pkt = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 80, 443, b"x");
    let rec = PcapFileRecord {
        ts_sec: 1,
        ts_usec: 2,
        incl_len: u32::try_from(pkt.len()).unwrap_or(u32::MAX),
        orig_len: u32::try_from(pkt.len()).unwrap_or(u32::MAX),
        data: pkt,
    };
    let s = summarize_packet(7, &rec);
    assert_eq!(s.index, 7);
    assert_eq!(s.protocol, "TCP");
    assert!(s.src.contains("1.2.3.4"));
    assert!(s.dst.contains("5.6.7.8"));
    assert!(!s.truncated);
}

#[test]
fn summarize_packet_udp() {
    let pkt = eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 53, 6000, b"data");
    let rec = PcapFileRecord {
        ts_sec: 0,
        ts_usec: 0,
        incl_len: u32::try_from(pkt.len()).unwrap_or(u32::MAX),
        orig_len: u32::try_from(pkt.len()).unwrap_or(u32::MAX),
        data: pkt,
    };
    let s = summarize_packet(0, &rec);
    assert_eq!(s.protocol, "UDP");
}

#[test]
fn summarize_packet_arp() {
    let mut pkt = vec![0u8; 14];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    let rec = PcapFileRecord {
        ts_sec: 0,
        ts_usec: 0,
        incl_len: 14,
        orig_len: 14,
        data: pkt,
    };
    let s = summarize_packet(0, &rec);
    assert_eq!(s.protocol, "ARP");
}

#[test]
fn summarize_packet_unknown_short() {
    let rec = PcapFileRecord {
        ts_sec: 0,
        ts_usec: 0,
        incl_len: 3,
        orig_len: 3,
        data: vec![1, 2, 3],
    };
    let s = summarize_packet(0, &rec);
    assert_eq!(s.protocol, "Unknown");
    assert!(!s.to_string().is_empty());
}

#[test]
fn summarize_truncated_flag() {
    let rec = PcapFileRecord {
        ts_sec: 0,
        ts_usec: 0,
        incl_len: 5,
        orig_len: 100,
        data: vec![0u8; 5],
    };
    let s = summarize_packet(0, &rec);
    assert!(s.truncated);
}

// ---------------- FiveTuple ----------------

#[test]
fn five_tuple_canonical_symmetric() {
    let a = FiveTuple::canonical("1.1.1.1", "2.2.2.2", 1234, 80, 6);
    let b = FiveTuple::canonical("2.2.2.2", "1.1.1.1", 80, 1234, 6);
    assert_eq!(a, b);
}

#[test]
fn five_tuple_hash_eq_consistency() {
    use std::collections::HashMap;
    let mut g = lcg();
    let mut h: HashMap<FiveTuple, u32> = HashMap::new();
    for _ in 0..40 {
        let ip1 = format!("{}.{}.{}.{}", g() & 0xff, g() & 0xff, g() & 0xff, g() & 0xff);
        let ip2 = format!("{}.{}.{}.{}", g() & 0xff, g() & 0xff, g() & 0xff, g() & 0xff);
        let p1 = (g() & 0xffff) as u16;
        let p2 = (g() & 0xffff) as u16;
        let t1 = FiveTuple::canonical(&ip1, &ip2, p1, p2, 6);
        let t2 = FiveTuple::canonical(&ip2, &ip1, p2, p1, 6);
        assert_eq!(t1, t2);
        h.insert(t1.clone(), 1);
        assert!(h.contains_key(&t2));
    }
}

#[test]
fn five_tuple_display() {
    let t = FiveTuple::canonical("1.1.1.1", "2.2.2.2", 80, 443, 6);
    let s = t.to_string();
    assert!(s.contains("proto=6"));
}

// ---------------- Connections & flows ----------------

#[test]
fn extract_connections_basic() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &eth_ipv4_tcp([1; 4], [2; 4], 80, 443, b"x"));
    w.add_packet(1, 0, &eth_ipv4_tcp([2; 4], [1; 4], 443, 80, b"y"));
    w.add_packet(2, 0, &eth_ipv4_udp([3; 4], [4; 4], 53, 53, b"q"));
    let bytes = w.finish();
    let pf = PcapFile::parse(&bytes).unwrap();
    let conns = extract_connections(&pf.records);
    assert_eq!(conns.len(), 2);
    let total: u64 = conns.iter().map(|c| c.packet_count).sum();
    assert_eq!(total, 3);
}

#[test]
fn extract_connections_ignores_non_ipv4() {
    let mut w = PcapWriter::new(1);
    let mut p = vec![0u8; 60];
    p[12] = 0x86;
    p[13] = 0xdd; // IPv6
    w.add_packet(0, 0, &p);
    let bytes = w.finish();
    let pf = PcapFile::parse(&bytes).unwrap();
    let conns = extract_connections(&pf.records);
    assert!(conns.is_empty());
}

#[test]
fn reconstruct_flows_basic() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &eth_ipv4_tcp([1; 4], [2; 4], 80, 443, b"hello"));
    w.add_packet(1, 0, &eth_ipv4_tcp([2; 4], [1; 4], 443, 80, b"world"));
    let bytes = w.finish();
    let pf = PcapFile::parse(&bytes).unwrap();
    let flows = reconstruct_flows(&pf.records);
    assert_eq!(flows.len(), 1);
    let combined = flows[0].combined_payload();
    assert!(combined.windows(5).any(|w| w == b"hello"));
    assert_eq!(flows[0].packet_count(), 2);
}

// ---------------- merge / split ----------------

#[test]
fn merge_pcap_files_sorts_by_timestamp() {
    let mut a = PcapWriter::new(1);
    a.add_packet(10, 0, &[1]);
    a.add_packet(30, 0, &[3]);
    let mut b = PcapWriter::new(1);
    b.add_packet(20, 0, &[2]);
    let ab = a.finish();
    let b = b.finish();
    let merged = merge_pcap_files(&[&ab, &b]).unwrap();
    let r = PcapReader::parse(&merged).unwrap();
    let ts: Vec<u32> = r.records.iter().map(|x| x.ts_sec).collect();
    assert_eq!(ts, vec![10, 20, 30]);
}

#[test]
fn merge_pcap_files_invalid_input() {
    let bad = vec![0u8; 10];
    assert!(merge_pcap_files(&[&bad]).is_err());
}

#[test]
fn split_pcap_by_count_basic() {
    let mut w = PcapWriter::new(1);
    for i in 0..10u32 {
        w.add_packet(i, 0, &[u8::try_from(i).unwrap_or(u8::MAX)]);
    }
    let bytes = w.finish();
    let chunks = split_pcap_by_count(&bytes, 3).unwrap();
    assert_eq!(chunks.len(), 4);
    // sum back to 10
    let total: usize = chunks
        .iter()
        .map(|c| PcapReader::parse(c).unwrap().records.len())
        .sum();
    assert_eq!(total, 10);
}

#[test]
fn split_pcap_by_count_zero() {
    let bytes = build_pcap(&[], 1);
    let chunks = split_pcap_by_count(&bytes, 0).unwrap();
    assert!(chunks.is_empty());
}

#[test]
fn split_pcap_by_time_buckets() {
    let mut w = PcapWriter::new(1);
    w.add_packet(0, 0, &[1]);
    w.add_packet(1, 0, &[2]);
    w.add_packet(10, 0, &[3]);
    w.add_packet(11, 0, &[4]);
    let bytes = w.finish();
    let chunks = split_pcap_by_time(&bytes, 5).unwrap();
    assert_eq!(chunks.len(), 2);
}

#[test]
fn split_pcap_by_time_zero_window() {
    let bytes = build_pcap(&[(0, 0, vec![1])], 1);
    let chunks = split_pcap_by_time(&bytes, 0).unwrap();
    assert!(chunks.is_empty());
}

// ---------------- PCAPNG ----------------

#[test]
fn pcapng_writer_reader_roundtrip() {
    let mut w = PcapNgWriter::new(LinkType::Ethernet);
    w.add_packet(1_000_000, &[0xDE, 0xAD, 0xBE, 0xEF]);
    w.add_packet(2_000_000, &[0xCA, 0xFE]);
    assert_eq!(w.packet_count(), 2);
    let bytes = w.finish();
    let r = PcapNgReader::from_bytes(&bytes).unwrap();
    let eps = r.enhanced_packets();
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0].data, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(eps[0].timestamp(), 1_000_000);
    let ifs = r.interfaces();
    assert_eq!(ifs.len(), 1);
    assert_eq!(ifs[0].link_type, LinkType::Ethernet);
}

#[test]
fn pcapng_reader_invalid_no_shb() {
    let buf = vec![0u8; 32];
    match PcapNgReader::from_bytes(&buf) {
        Err(PcapError::NoSectionHeader) => {}
        other => panic!("expected NoSectionHeader, got {other:?}"),
    }
}

#[test]
fn pcapng_reader_too_short() {
    let buf = vec![0u8; 8];
    assert!(PcapNgReader::from_bytes(&buf).is_err());
}

#[test]
fn pcapng_reader_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let n = (g() % 300) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = PcapNgReader::from_bytes(&buf);
    }
}

#[test]
fn enhanced_packet_block_timestamp() {
    let epb = EnhancedPacketBlock {
        interface_id: 0,
        timestamp_high: 1,
        timestamp_low: 2,
        captured_len: 0,
        original_len: 0,
        data: vec![],
        options: vec![],
    };
    assert_eq!(epb.timestamp(), (1u64 << 32) | 2);
}

// ---------------- Send/Sync stress ----------------

#[test]
fn send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;

    let mut w = PcapWriter::new(1);
    for i in 0..10u32 {
        w.add_packet(i, 0, &eth_ipv4_tcp([1; 4], [2; 4], 80, 443, b"x"));
    }
    let bytes = Arc::new(w.finish());
    let vm = Arc::new(FilterExpr::Tcp.compile());

    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = bytes.clone();
        let v = vm.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = PcapReader::parse(&b).unwrap();
                let kept = filter_pcap_records(&r.records, &v);
                assert_eq!(kept.len(), 10);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------- ConnectionInfo duration ----------------

#[test]
fn connection_info_duration() {
    let c = ConnectionInfo {
        key: FiveTuple::canonical("1.1.1.1", "2.2.2.2", 80, 443, 6),
        packet_count: 5,
        total_bytes: 100,
        first_seen: 10.0,
        last_seen: 25.5,
    };
    assert!((c.duration() - 15.5).abs() < 1e-9);
}
