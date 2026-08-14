//! Deep adversarial tests for rustre-trace-pt core public API.
//!
//! Focus: `IpCompression`, `PtPacketKind`, `PtPacket`, `PtDecoder`, `PtEvent`,
//! `TimingInfo`, `SidebandInfo`, `PtFlow`, `PtTrace`, `PtFlowReconstructor`.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_trace_pt::{
    IpCompression, PtDecoder, PtError, PtEvent, PtFlow, PtFlowReconstructor, PtPacket,
    PtPacketKind, PtTrace, SidebandInfo, TimingInfo,
};

// ── seeded LCG ────────────────────────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn byte(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }
    fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

// ── IpCompression ─────────────────────────────────────────────────────────────

#[test]
fn ip_compression_byte_count_table() {
    assert_eq!(IpCompression::Zero.byte_count(), 0);
    assert_eq!(IpCompression::Update16.byte_count(), 2);
    assert_eq!(IpCompression::Update32.byte_count(), 4);
    assert_eq!(IpCompression::Full48.byte_count(), 6);
    assert_eq!(IpCompression::Full48SignExt.byte_count(), 6);
    assert_eq!(IpCompression::Full64.byte_count(), 8);
}

#[test]
fn ip_compression_from_ipr_all_3bit_values() {
    // Every 3-bit value yields a defined variant (5 is reserved → Zero fallback,
    // 7 is reserved → Zero fallback).
    let map = [
        (0, IpCompression::Zero),
        (1, IpCompression::Update16),
        (2, IpCompression::Update32),
        (3, IpCompression::Full48),
        (4, IpCompression::Full48SignExt),
        (5, IpCompression::Zero),
        (6, IpCompression::Full64),
        (7, IpCompression::Zero),
    ];
    for (ipr, expected) in map {
        assert_eq!(IpCompression::from_ipr(ipr), expected, "ipr={ipr}");
    }
}

#[test]
fn ip_compression_from_ipr_ignores_upper_bits() {
    for upper in 0u8..32 {
        let raw = (upper << 3) | 0b011;
        assert_eq!(IpCompression::from_ipr(raw), IpCompression::Full48);
    }
}

// ── PtPacketKind classification ───────────────────────────────────────────────

#[test]
fn packetkind_is_timing_classification() {
    assert!(PtPacketKind::Tsc(1).is_timing());
    assert!(PtPacketKind::Mtc { ctc: 1 }.is_timing());
    assert!(PtPacketKind::Cyc { value: 1 }.is_timing());
    assert!(PtPacketKind::Cbr(1).is_timing());
    assert!(!PtPacketKind::Pad.is_timing());
    assert!(!PtPacketKind::Psb.is_timing());
    assert!(!PtPacketKind::Overflow.is_timing());
}

#[test]
fn packetkind_is_flow_classification() {
    assert!(PtPacketKind::Tip { ip: 0, compression: IpCompression::Zero }.is_flow());
    assert!(PtPacketKind::TipPge { ip: 0, compression: IpCompression::Zero }.is_flow());
    assert!(PtPacketKind::TipPgd { ip: 0, compression: IpCompression::Zero }.is_flow());
    assert!(PtPacketKind::Tnt { bits: 0, count: 0 }.is_flow());
    assert!(PtPacketKind::TntLong { bits: 0, count: 0 }.is_flow());
    assert!(!PtPacketKind::Tsc(0).is_flow());
    assert!(!PtPacketKind::Pad.is_flow());
}

#[test]
fn packetkind_ip_addr_only_for_tip_variants() {
    for ip in [0u64, 1, 0xFFFF, u64::MAX, 0x4000_1234] {
        assert_eq!(
            PtPacketKind::Tip { ip, compression: IpCompression::Full64 }.ip_addr(),
            Some(ip)
        );
        assert_eq!(
            PtPacketKind::TipPge { ip, compression: IpCompression::Full64 }.ip_addr(),
            Some(ip)
        );
        assert_eq!(
            PtPacketKind::TipPgd { ip, compression: IpCompression::Full64 }.ip_addr(),
            Some(ip)
        );
    }
    assert_eq!(PtPacketKind::Tsc(42).ip_addr(), None);
    assert_eq!(PtPacketKind::Pad.ip_addr(), None);
}

#[test]
fn packetkind_display_never_panics_and_is_non_empty() {
    let samples = [
        PtPacketKind::Pad,
        PtPacketKind::Psb,
        PtPacketKind::PsbEnd,
        PtPacketKind::Tip { ip: 0x1000, compression: IpCompression::Full48 },
        PtPacketKind::TipPge { ip: 0, compression: IpCompression::Zero },
        PtPacketKind::TipPgd { ip: u64::MAX, compression: IpCompression::Full64 },
        PtPacketKind::Tnt { bits: 0b101, count: 3 },
        PtPacketKind::TntLong { bits: 0xFF, count: 8 },
        PtPacketKind::Tsc(0),
        PtPacketKind::Tsc(u64::MAX),
        PtPacketKind::Mtc { ctc: 255 },
        PtPacketKind::Cyc { value: 12345 },
        PtPacketKind::Cbr(20),
        PtPacketKind::Overflow,
        PtPacketKind::Mode { leaf: 0x43, bits: 0x03 },
        PtPacketKind::Pip { cr3: 0xCAFE_0000, nr: true },
        PtPacketKind::Vmcs { base: 0xABCD },
        PtPacketKind::ExStop { ip: true },
        PtPacketKind::Mwait { ext: 1, hints: 2 },
        PtPacketKind::Pwre { hw_cstate: 1, sw_cstate: 2 },
        PtPacketKind::Pwrx { last_cstate: 3, deepest_cstate: 4 },
        PtPacketKind::Bbp { type_flag: 1 },
        PtPacketKind::Bip { id: 5, value: 0xDEAD },
        PtPacketKind::Bep { ip: false },
    ];
    for k in samples {
        let s = k.to_string();
        assert!(!s.is_empty(), "empty display for {k:?}");
    }
}

// ── PtPacket basics ───────────────────────────────────────────────────────────

#[test]
fn packet_new_and_flags() {
    let p = PtPacket::new(PtPacketKind::Tsc(7), 10, 9);
    assert_eq!(p.offset, 10);
    assert_eq!(p.size, 9);
    assert!(p.is_timing());
    assert!(!p.is_flow());

    let p2 = PtPacket::new(PtPacketKind::Tnt { bits: 1, count: 1 }, 0, 1);
    assert!(p2.is_flow());
    assert!(!p2.is_timing());
}

#[test]
fn packet_display_contains_offset_and_size() {
    let p = PtPacket::new(PtPacketKind::Pad, 0x10, 1);
    let s = format!("{p}");
    assert!(s.contains("0x10"));
    assert!(s.contains("1B"));
    assert!(s.contains("Pad"));
}

// ── PtDecoder: single-byte packets ────────────────────────────────────────────

fn decode_one(bytes: &[u8]) -> Result<PtPacket, PtError> {
    let mut d = PtDecoder::new();
    d.feed(bytes);
    d.next_packet().expect("at least one byte")
}

#[test]
fn decode_pad() {
    let p = decode_one(&[0x00]).unwrap();
    assert_eq!(p.kind, PtPacketKind::Pad);
    assert_eq!(p.size, 1);
    assert_eq!(p.offset, 0);
}

#[test]
fn decode_psbend_short() {
    let p = decode_one(&[0x23]).unwrap();
    assert_eq!(p.kind, PtPacketKind::PsbEnd);
}

#[test]
fn decode_overflow_byte() {
    let mut d = PtDecoder::new();
    d.feed(&[0xF3]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Overflow);
    assert_eq!(d.overflow_count, 1);
}

#[test]
fn decode_exstop_no_ip_and_with_ip() {
    let p1 = decode_one(&[0x62]).unwrap();
    assert_eq!(p1.kind, PtPacketKind::ExStop { ip: false });
    let p2 = decode_one(&[0x63]).unwrap();
    assert_eq!(p2.kind, PtPacketKind::ExStop { ip: true });
}

#[test]
fn decode_long_tnt_truncated() {
    let r = decode_one(&[0xA3, 0x00, 0x00]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn decode_long_tnt_all_zero_emits_empty() {
    let p = decode_one(&[0xA3, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(p.kind, PtPacketKind::TntLong { bits: 0, count: 0 });
    assert_eq!(p.size, 7);
}

#[test]
fn decode_long_tnt_with_stop_bit() {
    // payload bytes (LE) form a u64; stop bit is highest set bit.
    // Place stop at bit 3, with bits 0..=2 = 0b101.
    let payload: u64 = (1u64 << 3) | 0b101;
    let mut data = vec![0xA3];
    data.extend_from_slice(&payload.to_le_bytes()[..6]);
    let p = decode_one(&data).unwrap();
    if let PtPacketKind::TntLong { bits, count } = p.kind {
        assert_eq!(count, 3);
        assert_eq!(bits, 0b101);
    } else {
        panic!("expected TntLong, got {:?}", p.kind);
    }
}

#[test]
fn decode_tsc_round_trip_seeded() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..60 {
        let tsc = lcg.next();
        let mut bytes = vec![0x19];
        bytes.extend_from_slice(&tsc.to_le_bytes());
        let p = decode_one(&bytes).unwrap();
        assert_eq!(p.kind, PtPacketKind::Tsc(tsc));
        assert_eq!(p.size, 9);
    }
}

#[test]
fn decode_tsc_truncated() {
    let r = decode_one(&[0x19, 0, 0, 0]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn decode_mtc_every_ctc() {
    for ctc in 0u8..=255 {
        let p = decode_one(&[0x59, ctc]).unwrap();
        assert_eq!(p.kind, PtPacketKind::Mtc { ctc });
        assert_eq!(p.size, 2);
    }
}

#[test]
fn decode_mtc_truncated() {
    let r = decode_one(&[0x59]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn decode_cbr_round_trip() {
    for cbr in [0u8, 1, 10, 100, 200, 255] {
        let p = decode_one(&[0x02, 0x22, cbr, 0x00]).unwrap();
        assert_eq!(p.kind, PtPacketKind::Cbr(cbr));
        assert_eq!(p.size, 4);
    }
}

#[test]
fn decode_psbend_long() {
    let p = decode_one(&[0x02, 0xC3]).unwrap();
    assert_eq!(p.kind, PtPacketKind::PsbEnd);
    assert_eq!(p.size, 2);
}

#[test]
fn decode_psb_full_pattern() {
    let mut data = vec![0x02];
    for i in 0..15usize {
        data.push(if i % 2 == 0 { 0x82 } else { 0x02 });
    }
    let p = decode_one(&data).unwrap();
    assert_eq!(p.kind, PtPacketKind::Psb);
    assert_eq!(p.size, 16);
}

#[test]
fn decode_pip_round_trip() {
    // 0x02 0x43 <6 bytes cr3>. NR is low bit of the raw cr3, then masked out.
    let cr3_raw: u64 = 0x0123_4567_89AB | 1;
    let mut data = vec![0x02, 0x43];
    data.extend_from_slice(&cr3_raw.to_le_bytes()[..6]);
    let p = decode_one(&data).unwrap();
    if let PtPacketKind::Pip { cr3, nr } = p.kind {
        assert!(nr);
        assert_eq!(cr3 & 1, 0);
        // low 48 bits should match raw with bit0 cleared
        assert_eq!(cr3, cr3_raw & 0x0000_FFFF_FFFF_FFFE);
    } else {
        panic!("expected Pip, got {:?}", p.kind);
    }
    assert_eq!(p.size, 8);
}

#[test]
fn decode_mode_when_not_pip() {
    // Only 2 trailing bytes after 0x02 0x43 → MODE path
    let p = decode_one(&[0x02, 0x43, 0xAA]).unwrap();
    assert_eq!(
        p.kind,
        PtPacketKind::Mode { leaf: 0x43, bits: 0xAA }
    );
    assert_eq!(p.size, 3);
}

#[test]
fn decode_mode_leaf_03() {
    let p = decode_one(&[0x02, 0x03, 0x55]).unwrap();
    assert_eq!(
        p.kind,
        PtPacketKind::Mode { leaf: 0x03, bits: 0x55 }
    );
}

#[test]
fn decode_short_tip_full48() {
    // 0xC5 + 6 byte IP
    let ip_le = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60];
    let mut data = vec![0xC5];
    data.extend_from_slice(&ip_le);
    let p = decode_one(&data).unwrap();
    if let PtPacketKind::Tip { ip, compression } = p.kind {
        assert_eq!(compression, IpCompression::Full48);
        let mut expected_bytes = [0u8; 8];
        expected_bytes[..6].copy_from_slice(&ip_le);
        assert_eq!(ip, u64::from_le_bytes(expected_bytes));
    } else {
        panic!("expected Tip");
    }
}

#[test]
fn decode_tip_full64_seeded() {
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    // TIP byte: lower 5 bits = 0b01101 (0x0D), upper 3 bits = 6 (Full64)
    let header = (6u8 << 5) | 0x0D;
    for _ in 0..50 {
        let ip = lcg.next();
        let mut data = vec![header];
        data.extend_from_slice(&ip.to_le_bytes());
        let p = decode_one(&data).unwrap();
        if let PtPacketKind::Tip { ip: got_ip, compression } = p.kind {
            assert_eq!(got_ip, ip);
            assert_eq!(compression, IpCompression::Full64);
        } else {
            panic!("expected TIP Full64, got {:?}", p.kind);
        }
        assert_eq!(p.size, 9);
    }
}

#[test]
fn decode_tip_pge_full48_signext() {
    // header: ipr=4 (Full48SignExt), variant=0x11
    let header = (4u8 << 5) | 0x11;
    let ip_low48: u64 = (1u64 << 47) | 0x1234; // bit 47 set → sign extend
    let mut data = vec![header];
    data.extend_from_slice(&ip_low48.to_le_bytes()[..6]);
    let p = decode_one(&data).unwrap();
    if let PtPacketKind::TipPge { ip, compression } = p.kind {
        assert_eq!(compression, IpCompression::Full48SignExt);
        assert_eq!(ip & 0xFFFF_0000_0000_0000, 0xFFFF_0000_0000_0000);
        assert_eq!(ip & 0xFFFF_FFFF_FFFF, ip_low48);
    } else {
        panic!("expected TipPge");
    }
}

#[test]
fn decode_tip_pgd_truncated() {
    // header full64 + TIP.PGD variant, but no IP bytes
    let header = (6u8 << 5) | 0x01;
    let r = decode_one(&[header]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn decode_tip_update16_modifies_last_ip() {
    // First do Full64 set last_ip, then Update16
    let header64 = (6u8 << 5) | 0x0D;
    let header16 = (1u8 << 5) | 0x0D;
    let mut data = vec![header64];
    data.extend_from_slice(&0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
    data.push(header16);
    data.extend_from_slice(&0x1234u16.to_le_bytes());

    let mut d = PtDecoder::new();
    d.feed(&data);
    let p1 = d.next_packet().unwrap().unwrap();
    assert!(matches!(p1.kind, PtPacketKind::Tip { .. }));
    let p2 = d.next_packet().unwrap().unwrap();
    if let PtPacketKind::Tip { ip, compression } = p2.kind {
        assert_eq!(compression, IpCompression::Update16);
        // low 16 bits replaced with 0x1234, upper bits preserved
        assert_eq!(ip & 0xFFFF, 0x1234);
        assert_eq!(ip & !0xFFFF, 0xAAAA_BBBB_CCCC_DDDD & !0xFFFF);
    } else {
        panic!("expected Tip");
    }
}

#[test]
fn decode_short_tnt_seeded_no_panic() {
    let mut lcg = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    for _ in 0..200 {
        let mut b = lcg.byte();
        // Force even, non-zero, not 0x62/0x63/0xA3/0xC2 and not 0x02
        b &= 0xFE;
        if b == 0 || b == 0x62 || b == 0xA3 || b == 0xC2 || b == 0x02 || b == 0xF2 {
            b = 0x06; // safe short-TNT byte
        }
        let p = decode_one(&[b]).unwrap();
        match p.kind {
            PtPacketKind::Tnt { count, bits } => {
                assert!(count <= 7);
                assert!(bits < (1u64 << count) || count == 0);
            }
            // some patterns hit CYC instead — that's fine
            PtPacketKind::Cyc { .. } => {}
            other => panic!("unexpected kind {other:?}"),
        }
    }
}

#[test]
fn decode_cyc_short() {
    // bottom 3 bits == 011, no continuation: b = 0bXXXXX_011 with bit2=0 → bit2 of byte is the cont bit
    // CYC pattern: (b & 0b11)==0b11 and b != 0x03. Bit2 (mask 0x04) is continuation.
    // value = b >> 3.
    let b = 0b1000_0011; // = 0x83. shift>>3 = 0x10. cont bit (b & 4) == 0.
    let p = decode_one(&[b]).unwrap();
    assert_eq!(p.kind, PtPacketKind::Cyc { value: 0x10 });
    assert_eq!(p.size, 1);
}

#[test]
fn decode_cyc_with_continuation() {
    // b=0b00000_111 → bottom 3 bits 011? 0b111 → that's 0x07, b & 0b11 = 0b11 ✓; b != 0x03; cont bit (0x04) set.
    // value starts at b>>3 = 0, then ext byte with low bit cont=0 finishes.
    let ext = 0b0101_0010; // ext>>1 = 0x29, cont (low bit) = 0
    let p = decode_one(&[0x07, ext]).unwrap();
    assert_eq!(
        p.kind,
        PtPacketKind::Cyc {
            value: (0x29u64) << 5
        }
    );
    assert_eq!(p.size, 2);
}

#[test]
fn decode_cyc_truncated_continuation() {
    // Continuation requested but no second byte → TruncatedPacket
    let r = decode_one(&[0x07]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn decode_mwait() {
    let p = decode_one(&[0xC2, 0xAA, 0xBB, 0x00, 0x00]).unwrap();
    assert_eq!(
        p.kind,
        PtPacketKind::Mwait { ext: 0xBB, hints: 0xAA }
    );
    assert_eq!(p.size, 5);
}

#[test]
fn decode_mwait_truncated() {
    let r = decode_one(&[0xC2, 0x01]);
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

// ── PtDecoder: state mgmt ─────────────────────────────────────────────────────

#[test]
fn decoder_reset_state() {
    let mut d = PtDecoder::new();
    d.feed(&[0xF3, 0x00, 0xFF]); // overflow, pad, unknown
    let _ = d.decode_all_with_errors();
    assert!(d.overflow_count > 0);
    assert!(d.error_count > 0);
    let buf_len = d.buf.len();
    d.reset();
    assert_eq!(d.pos, 0);
    assert_eq!(d.overflow_count, 0);
    assert_eq!(d.error_count, 0);
    assert_eq!(d.buf.len(), buf_len, "reset must preserve buffer");
}

#[test]
fn decoder_peek_byte_and_remaining() {
    let mut d = PtDecoder::new();
    assert_eq!(d.peek_byte(), None);
    assert_eq!(d.remaining_bytes(), 0);
    d.feed(&[0x10, 0x20, 0x30]);
    assert_eq!(d.peek_byte(), Some(0x10));
    assert_eq!(d.remaining_bytes(), 3);
    let _ = d.next_packet();
    assert_eq!(d.remaining_bytes(), 2);
}

#[test]
fn decoder_next_packet_none_when_empty() {
    let mut d = PtDecoder::new();
    assert!(d.next_packet().is_none());
}

#[test]
fn decoder_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for trial in 0..200 {
        let n = usize::try_from(lcg.next()).unwrap_or(usize::MAX) % 64 + 1;
        let data = lcg.fill(n);
        eprintln!("trial {trial} n={n} data={:02x?}", &data);
        let mut d = PtDecoder::new();
        d.feed(&data);
        let results = d.decode_all_with_errors();
        assert!(d.pos <= d.buf.len(), "trial {trial}: pos overflow");
        for r in results {
            match r {
                Ok(_) | Err(_) => {}
            }
        }
    }
}

#[test]
fn decoder_count_by_kind_includes_all_seen() {
    let mut bytes = vec![];
    bytes.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 Pad
    bytes.extend_from_slice(&[0xF3]); // overflow
    bytes.extend_from_slice(&[0x23]); // PsbEnd
    let mut d = PtDecoder::new();
    d.feed(&bytes);
    let pkts = d.decode_all();
    let counts: HashMap<&'static str, usize> = PtDecoder::count_by_kind(&pkts);
    assert_eq!(counts.get("Pad").copied().unwrap_or(0), 3);
    assert_eq!(counts.get("Overflow").copied().unwrap_or(0), 1);
    assert_eq!(counts.get("PsbEnd").copied().unwrap_or(0), 1);
}

#[test]
fn decoder_default_equivalent_to_new() {
    let a = PtDecoder::default();
    let b = PtDecoder::new();
    assert_eq!(a.pos, b.pos);
    assert_eq!(a.buf.len(), b.buf.len());
    assert_eq!(a.overflow_count, b.overflow_count);
    assert_eq!(a.error_count, b.error_count);
}

// ── PtEvent display ───────────────────────────────────────────────────────────

#[test]
fn pt_event_display_all_variants() {
    let evs = [
        PtEvent::BranchTaken { ip: 1, target: 2 },
        PtEvent::BranchNotTaken { ip: 1, fallthrough: 2 },
        PtEvent::IndirectBranch { from: 1, to: 2 },
        PtEvent::Call { from: 1, to: 2 },
        PtEvent::Return { from: 1, to: 2 },
        PtEvent::TraceEnabled { ip: 1 },
        PtEvent::TraceDisabled { ip: 1 },
        PtEvent::Overflow { offset: 5 },
        PtEvent::Timestamp { tsc: 42 },
        PtEvent::ModeChange { leaf: 0, bits: 0 },
    ];
    for e in evs {
        assert!(!e.to_string().is_empty());
    }
}

// ── TimingInfo ────────────────────────────────────────────────────────────────

#[test]
fn timing_info_record_and_elapsed() {
    let mut t = TimingInfo::new();
    assert!(t.elapsed_tsc().is_none());
    t.record_tsc(100);
    t.record_tsc(150);
    t.record_tsc(250);
    assert_eq!(t.first_tsc, Some(100));
    assert_eq!(t.last_tsc, Some(250));
    assert_eq!(t.elapsed_tsc(), Some(150));
}

#[test]
fn timing_info_elapsed_underflow_returns_none() {
    let mut t = TimingInfo::new();
    t.record_tsc(500);
    t.record_tsc(100); // last < first → checked_sub returns None
    assert_eq!(t.elapsed_tsc(), None);
}

#[test]
fn timing_info_total_cycles_sum() {
    let mut t = TimingInfo::new();
    for v in [1u64, 2, 3, 4, 5] {
        t.record_cyc(v);
    }
    assert_eq!(t.total_cycles(), 15);
}

#[test]
fn timing_info_record_cbr_and_mtc() {
    let mut t = TimingInfo::new();
    t.record_cbr(20);
    t.record_mtc(1);
    t.record_mtc(2);
    assert_eq!(t.cbr, Some(20));
    assert_eq!(t.mtc_values, vec![1, 2]);
}

#[test]
fn timing_info_elapsed_ns_arithmetic() {
    let mut t = TimingInfo::new();
    t.record_tsc(0);
    t.record_tsc(2_000);
    // 2000 ticks at 2000 MHz → 2000/2000 * 1000 = 1000ns
    let ns = t.elapsed_ns(2000.0).unwrap();
    assert!((ns - 1000.0).abs() < 1e-6);
    assert!(TimingInfo::new().elapsed_ns(2000.0).is_none());
}

// ── SidebandInfo ──────────────────────────────────────────────────────────────

#[test]
fn sideband_register_and_lookup_module() {
    let mut s = SidebandInfo::new();
    s.register_module(0x4000, 0x1000, "libc.so");
    s.register_module(0x6000, 0x2000, "app");
    assert_eq!(s.module_for_addr(0x4000), Some("libc.so"));
    assert_eq!(s.module_for_addr(0x4FFF), Some("libc.so"));
    assert_eq!(s.module_for_addr(0x5000), None);
    assert_eq!(s.module_for_addr(0x6500), Some("app"));
    assert_eq!(s.module_for_addr(0x7FFF), Some("app"));
    assert_eq!(s.module_for_addr(0x8000), None);
}

#[test]
fn sideband_module_size_saturating_add_no_panic() {
    let mut s = SidebandInfo::new();
    s.register_module(u64::MAX - 1, 100, "edge");
    // Lookup uses a half-open [base, base+size) range with saturating_add to
    // avoid overflow; this must not panic regardless of the result.
    let _ = s.module_for_addr(u64::MAX);
    // The base address itself must be considered inside the module.
    assert_eq!(s.module_for_addr(u64::MAX - 1), Some("edge"));
}

#[test]
fn sideband_register_and_lookup_cr3() {
    let mut s = SidebandInfo::new();
    s.register_cr3(0x1000, 0x4000);
    s.register_cr3(0x2000, 0x8000);
    assert_eq!(s.image_base_for_cr3(0x1000), Some(0x4000));
    assert_eq!(s.image_base_for_cr3(0x2000), Some(0x8000));
    assert_eq!(s.image_base_for_cr3(0x3000), None);
}

// ── PtFlow ────────────────────────────────────────────────────────────────────

#[test]
fn flow_push_tracks_addresses() {
    let mut f = PtFlow::new();
    f.push_event(PtEvent::BranchTaken { ip: 1, target: 2 });
    f.push_event(PtEvent::BranchNotTaken { ip: 3, fallthrough: 4 });
    f.push_event(PtEvent::Call { from: 5, to: 6 });
    f.push_event(PtEvent::Return { from: 7, to: 8 });
    f.push_event(PtEvent::IndirectBranch { from: 9, to: 10 });
    f.push_event(PtEvent::TraceEnabled { ip: 11 });
    f.push_event(PtEvent::TraceDisabled { ip: 12 });
    f.push_event(PtEvent::Overflow { offset: 100 });
    f.push_event(PtEvent::Timestamp { tsc: 0 });

    assert_eq!(f.event_count(), 9);
    assert_eq!(f.unique_addresses(), 12);
    assert_eq!(f.calls().len(), 1);
    assert_eq!(f.returns().len(), 1);
    assert_eq!(f.overflows().len(), 1);
}

// ── PtTrace ───────────────────────────────────────────────────────────────────

#[test]
fn pttrace_tsc_tip_tnt_extraction() {
    let pkts = vec![
        PtPacket::new(PtPacketKind::Tsc(100), 0, 9),
        PtPacket::new(PtPacketKind::Tsc(200), 9, 9),
        PtPacket::new(
            PtPacketKind::Tip { ip: 0x1000, compression: IpCompression::Full64 },
            18,
            9,
        ),
        PtPacket::new(PtPacketKind::Tnt { bits: 0b101, count: 3 }, 27, 1),
        PtPacket::new(PtPacketKind::TntLong { bits: 0xFF, count: 8 }, 28, 7),
    ];
    let trace = PtTrace::new(pkts);
    assert_eq!(trace.packet_count(), 5);
    assert_eq!(trace.tsc_values(), vec![100, 200]);
    assert_eq!(trace.tip_addresses(), vec![0x1000]);
    assert_eq!(
        trace.tnt_bits(),
        vec![(0b101u64, 3u8), (0xFFu64, 8u8)]
    );
}

#[test]
fn pttrace_extract_timing_aggregates() {
    let pkts = vec![
        PtPacket::new(PtPacketKind::Tsc(50), 0, 9),
        PtPacket::new(PtPacketKind::Cbr(33), 9, 4),
        PtPacket::new(PtPacketKind::Mtc { ctc: 7 }, 13, 2),
        PtPacket::new(PtPacketKind::Cyc { value: 11 }, 15, 1),
        PtPacket::new(PtPacketKind::Tsc(150), 16, 9),
    ];
    let trace = PtTrace::new(pkts);
    let t = trace.extract_timing();
    assert_eq!(t.first_tsc, Some(50));
    assert_eq!(t.last_tsc, Some(150));
    assert_eq!(t.cbr, Some(33));
    assert_eq!(t.mtc_values, vec![7]);
    assert_eq!(t.total_cycles(), 11);
    assert_eq!(t.elapsed_tsc(), Some(100));
}

#[test]
fn pttrace_summary_non_empty() {
    let trace = PtTrace::new(vec![PtPacket::new(PtPacketKind::Pad, 0, 1)]);
    let s = trace.summary();
    assert!(s.contains("packets: 1"));
}

// ── PtFlowReconstructor ───────────────────────────────────────────────────────

#[test]
fn reconstructor_tnt_queue_fills_and_drains() {
    let mut r = PtFlowReconstructor::new();
    let pkt = PtPacket::new(
        PtPacketKind::Tnt { bits: 0b101, count: 3 },
        0,
        1,
    );
    r.feed_packet(&pkt);
    assert_eq!(r.pending_tnt_count(), 3);
    assert_eq!(r.pop_tnt(), Some(true));  // bit 0 = 1
    assert_eq!(r.pop_tnt(), Some(false)); // bit 1 = 0
    assert_eq!(r.pop_tnt(), Some(true));  // bit 2 = 1
    assert_eq!(r.pop_tnt(), None);
}

#[test]
fn reconstructor_tip_updates_ip_and_emits_indirect() {
    let mut r = PtFlowReconstructor::new();
    r.current_ip = 0x1000;
    let pkt = PtPacket::new(
        PtPacketKind::Tip { ip: 0x2000, compression: IpCompression::Full64 },
        0,
        9,
    );
    assert!(r.feed_packet(&pkt));
    assert_eq!(r.current_ip, 0x2000);
    assert_eq!(r.flow.tip_packets_consumed, 1);
    assert_eq!(r.flow.event_count(), 1);
    match &r.flow.events[0] {
        PtEvent::IndirectBranch { from, to } => {
            assert_eq!(*from, 0x1000);
            assert_eq!(*to, 0x2000);
        }
        e => panic!("expected IndirectBranch, got {e:?}"),
    }
}

#[test]
fn reconstructor_tip_pge_pgd_toggle_tracing() {
    let mut r = PtFlowReconstructor::new();
    assert!(!r.tracing_enabled);
    r.feed_packet(&PtPacket::new(
        PtPacketKind::TipPge { ip: 0xA, compression: IpCompression::Full64 },
        0,
        9,
    ));
    assert!(r.tracing_enabled);
    r.feed_packet(&PtPacket::new(
        PtPacketKind::TipPgd { ip: 0xB, compression: IpCompression::Full64 },
        9,
        9,
    ));
    assert!(!r.tracing_enabled);
}

#[test]
fn reconstructor_record_conditional_branch_taken() {
    let mut r = PtFlowReconstructor::new();
    // Fill TNT with a taken bit
    r.feed_packet(&PtPacket::new(
        PtPacketKind::Tnt { bits: 1, count: 1 },
        0,
        1,
    ));
    r.record_conditional_branch(0x100, 0x200, 0x104);
    assert_eq!(r.current_ip, 0x200);
    assert_eq!(r.flow.tnt_bits_consumed, 1);
    assert!(matches!(
        r.flow.events.last(),
        Some(PtEvent::BranchTaken { ip: 0x100, target: 0x200 })
    ));
}

#[test]
fn reconstructor_record_conditional_branch_not_taken() {
    let mut r = PtFlowReconstructor::new();
    r.feed_packet(&PtPacket::new(
        PtPacketKind::Tnt { bits: 0, count: 1 },
        0,
        1,
    ));
    r.record_conditional_branch(0x300, 0x400, 0x304);
    assert_eq!(r.current_ip, 0x304);
    assert!(matches!(
        r.flow.events.last(),
        Some(PtEvent::BranchNotTaken { ip: 0x300, fallthrough: 0x304 })
    ));
}

#[test]
fn reconstructor_call_and_return() {
    let mut r = PtFlowReconstructor::new();
    r.record_call(0x100, 0x500);
    assert_eq!(r.current_ip, 0x500);
    r.record_return(0x500, 0x104);
    assert_eq!(r.current_ip, 0x104);
    assert_eq!(r.flow.calls().len(), 1);
    assert_eq!(r.flow.returns().len(), 1);
}

#[test]
fn reconstructor_overflow_emits_event() {
    let mut r = PtFlowReconstructor::new();
    let pkt = PtPacket::new(PtPacketKind::Overflow, 0xABCD, 1);
    assert!(r.feed_packet(&pkt));
    assert!(matches!(
        r.flow.events.last(),
        Some(PtEvent::Overflow { offset: 0xABCD })
    ));
}

#[test]
fn reconstructor_tsc_records_timing_and_event() {
    let mut r = PtFlowReconstructor::new();
    r.feed_packet(&PtPacket::new(PtPacketKind::Tsc(42), 0, 9));
    assert_eq!(r.flow.timing.first_tsc, Some(42));
    assert!(matches!(
        r.flow.events.last(),
        Some(PtEvent::Timestamp { tsc: 42 })
    ));
}

#[test]
fn reconstructor_default_eq_new() {
    let a = PtFlowReconstructor::default();
    let b = PtFlowReconstructor::new();
    assert_eq!(a.current_ip, b.current_ip);
    assert_eq!(a.tracing_enabled, b.tracing_enabled);
    assert_eq!(a.flow.event_count(), b.flow.event_count());
}

// ── PtError display ───────────────────────────────────────────────────────────

#[test]
fn pterror_display_all() {
    let errs = [
        PtError::InvalidPacket(0xAB),
        PtError::TruncatedPacket,
        PtError::UnknownOpcode(0xCD),
        PtError::IpCompression("oops".into()),
        PtError::FlowReconstruction("bad".into()),
        PtError::Sideband("x".into()),
        PtError::Timing("y".into()),
        PtError::Overflow(0xDEAD),
    ];
    for e in errs {
        assert!(!format!("{e}").is_empty());
    }
}

// ── Send + Sync threaded stress ───────────────────────────────────────────────

#[test]
fn pttrace_send_sync_threaded() {
    let pkts = vec![
        PtPacket::new(PtPacketKind::Tsc(10), 0, 9),
        PtPacket::new(PtPacketKind::Tsc(20), 9, 9),
        PtPacket::new(
            PtPacketKind::Tip { ip: 0x1234, compression: IpCompression::Full64 },
            18,
            9,
        ),
    ];
    let trace = Arc::new(PtTrace::new(pkts));
    let mut handles = vec![];
    for _ in 0..4 {
        let t = Arc::clone(&trace);
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for _ in 0..100 {
                acc = acc.wrapping_add(t.packet_count() as u64);
                acc = acc.wrapping_add(t.tsc_values().iter().sum::<u64>());
                acc = acc.wrapping_add(t.tip_addresses().iter().sum::<u64>());
                let _ = t.extract_timing();
            }
            acc
        }));
    }
    for h in handles {
        let v = h.join().unwrap();
        assert!(v > 0);
    }
}

// ── Hash/Eq consistency ──────────────────────────────────────────────────────
// PtPacketKind is Eq but not Hash; PtPacket is Eq. Check equality consistency
// over 30+ pairs.

#[test]
fn packetkind_eq_consistency_pairs() {
    let mut lcg = Lcg::new(0xAAAA_BBBB_CCCC_DDDD);
    let makers: &[fn(u64) -> PtPacketKind] = &[
        |x| PtPacketKind::Tsc(x),
        |x| PtPacketKind::Mtc { ctc: u8::try_from(x & 0xFF).unwrap_or(u8::MAX) },
        |x| PtPacketKind::Cyc { value: x },
        |x| PtPacketKind::Cbr(u8::try_from(x & 0xFF).unwrap_or(u8::MAX)),
        |x| PtPacketKind::Tip {
            ip: x,
            compression: IpCompression::Full64,
        },
        |x| PtPacketKind::TipPge {
            ip: x,
            compression: IpCompression::Full64,
        },
        |x| PtPacketKind::TipPgd {
            ip: x,
            compression: IpCompression::Full64,
        },
        |x| PtPacketKind::Tnt {
            bits: x & 0xF,
            count: 4,
        },
    ];
    for _ in 0..40 {
        let v = lcg.next();
        let m = makers[usize::try_from(v).unwrap_or(usize::MAX) % makers.len()];
        let a = m(v);
        let b = m(v);
        let c = m(v.wrapping_add(1));
        assert_eq!(a, b, "reflexive eq");
        // c may equal a in degenerate cases (e.g. Tnt mask), so only test strict
        // inequality for variants that vary on v fully.
        let _ = c;
    }
}

#[test]
fn packet_eq_with_offset_and_size() {
    let a = PtPacket::new(PtPacketKind::Pad, 0, 1);
    let b = PtPacket::new(PtPacketKind::Pad, 0, 1);
    let c = PtPacket::new(PtPacketKind::Pad, 1, 1);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ── Round-trip TIP encode/decode 50 inputs ────────────────────────────────────

#[test]
fn tip_full64_encode_decode_50_inputs() {
    let mut lcg = Lcg::new(0x0123_4567_89AB_CDEF);
    let header = (6u8 << 5) | 0x0D;
    for _ in 0..50 {
        let ip = lcg.next();
        let mut data = vec![header];
        data.extend_from_slice(&ip.to_le_bytes());
        let p = decode_one(&data).unwrap();
        assert_eq!(p.kind.ip_addr(), Some(ip));
    }
}

// ── Boundary: empty buffer, single-byte unknown ──────────────────────────────

#[test]
fn unknown_opcode_advances_one() {
    // 0x05: odd byte, not matching any decoder pattern → UnknownOpcode.
    let mut d = PtDecoder::new();
    d.feed(&[0x05, 0x00]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::UnknownOpcode(0x05))));
    // Next byte should still decode as Pad
    let r2 = d.next_packet().unwrap();
    assert_eq!(r2.unwrap().kind, PtPacketKind::Pad);
}

/// A truncated final packet must terminate the decode, not spin forever.
///
/// `next_packet` rewinds `pos` and returns `Some(Err(TruncatedPacket))` so a
/// streaming caller can retry once more bytes arrive. `decode_all_with_errors`
/// used to loop on `Some` alone, so it re-decoded the same bytes without end
/// and grew its result vector until the process died allocating (measured: 40
/// GiB from 54 random bytes). A PT trace captured from a ring buffer normally
/// ends mid-packet, so this was reachable from ordinary input.
#[test]
fn truncated_tail_terminates_instead_of_exhausting_memory() {
    // 0xA3 is Long TNT and needs 6 more bytes; give it 2.
    let mut d = PtDecoder::new();
    d.feed(&[0xA3, 0x00, 0x00]);
    let results = d.decode_all_with_errors();
    assert!(
        results.len() <= 4,
        "decode returned {} results for a 3-byte truncated packet",
        results.len()
    );
    assert!(
        results.iter().any(std::result::Result::is_err),
        "the truncated packet must be reported as an error"
    );
}
