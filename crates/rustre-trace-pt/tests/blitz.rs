//! Exhaustive blitz test suite for the public surface of `rustre-trace-pt`.
//!
//! Targets the stable, documented public API in `lib.rs`:
//!   * `IpCompression`, `StreamIpMode` (mode tables)
//!   * `PtPacketKind`, `PtPacket` (helpers)
//!   * `PtDecoder` (stateful PT byte-stream decoder)
//!   * `PtPkt`, `PtPacketStream` (newer streaming decoder)
//!   * `StreamTraceEntry`, `StreamTrace`, `pt_to_coverage`,
//!     `pt_pkts_to_coverage`, `pt_to_drcov`, `pt_to_drcov_bytes`,
//!     `decode_pt_buffer`, `decode_pt_buffer_verbose`.

use rustre_trace_pt::{
    IpCompression, PtDecoder, PtError, PtPacket, PtPacketKind, PtPacketStream, PtPkt, StreamIpMode,
    StreamTrace, StreamTraceEntry, decode_pt_buffer, decode_pt_buffer_verbose,
    pt_pkts_to_coverage, pt_to_coverage, pt_to_drcov, pt_to_drcov_bytes,
};

// ─── IpCompression ────────────────────────────────────────────────────────────

#[test]
fn ipcompression_byte_count_table() {
    assert_eq!(IpCompression::Zero.byte_count(), 0);
    assert_eq!(IpCompression::Update16.byte_count(), 2);
    assert_eq!(IpCompression::Update32.byte_count(), 4);
    assert_eq!(IpCompression::Full48.byte_count(), 6);
    assert_eq!(IpCompression::Full48SignExt.byte_count(), 6);
    assert_eq!(IpCompression::Full64.byte_count(), 8);
}

#[test]
fn ipcompression_from_ipr_known() {
    assert_eq!(IpCompression::from_ipr(0), IpCompression::Zero);
    assert_eq!(IpCompression::from_ipr(1), IpCompression::Update16);
    assert_eq!(IpCompression::from_ipr(2), IpCompression::Update32);
    assert_eq!(IpCompression::from_ipr(3), IpCompression::Full48);
    assert_eq!(IpCompression::from_ipr(4), IpCompression::Full48SignExt);
    assert_eq!(IpCompression::from_ipr(6), IpCompression::Full64);
}

#[test]
fn ipcompression_from_ipr_undefined_maps_to_zero() {
    assert_eq!(IpCompression::from_ipr(5), IpCompression::Zero);
    assert_eq!(IpCompression::from_ipr(7), IpCompression::Zero);
}

#[test]
fn ipcompression_from_ipr_masks_upper_bits() {
    // Only bits 2:0 matter — upper bits should be masked.
    assert_eq!(IpCompression::from_ipr(0xF8 | 0x03), IpCompression::Full48);
    assert_eq!(IpCompression::from_ipr(!0b111), IpCompression::Zero);
}

// ─── StreamIpMode ─────────────────────────────────────────────────────────────

#[test]
fn streamipmode_from_ipr_full_table() {
    assert_eq!(StreamIpMode::from_ipr(0), StreamIpMode::Suppressed);
    assert_eq!(StreamIpMode::from_ipr(1), StreamIpMode::Upd16);
    assert_eq!(StreamIpMode::from_ipr(2), StreamIpMode::Upd32);
    assert_eq!(StreamIpMode::from_ipr(3), StreamIpMode::Upd48);
    assert_eq!(StreamIpMode::from_ipr(4), StreamIpMode::Sext48);
    assert_eq!(StreamIpMode::from_ipr(6), StreamIpMode::Full);
    assert_eq!(StreamIpMode::from_ipr(5), StreamIpMode::Suppressed);
    assert_eq!(StreamIpMode::from_ipr(7), StreamIpMode::Suppressed);
}

#[test]
fn streamipmode_payload_bytes_table() {
    assert_eq!(StreamIpMode::Suppressed.payload_bytes(), 0);
    assert_eq!(StreamIpMode::Upd16.payload_bytes(), 2);
    assert_eq!(StreamIpMode::Upd32.payload_bytes(), 4);
    assert_eq!(StreamIpMode::Upd48.payload_bytes(), 6);
    assert_eq!(StreamIpMode::Sext48.payload_bytes(), 6);
    assert_eq!(StreamIpMode::Full.payload_bytes(), 8);
}

// ─── PtPacketKind helpers ─────────────────────────────────────────────────────

#[test]
fn ptpacketkind_is_timing_true_for_timing_variants() {
    assert!(PtPacketKind::Tsc(0).is_timing());
    assert!(PtPacketKind::Mtc { ctc: 0 }.is_timing());
    assert!(PtPacketKind::Cyc { value: 0 }.is_timing());
    assert!(PtPacketKind::Cbr(0).is_timing());
}

#[test]
fn ptpacketkind_is_timing_false_for_others() {
    assert!(!PtPacketKind::Pad.is_timing());
    assert!(!PtPacketKind::Psb.is_timing());
    assert!(
        !PtPacketKind::Tip {
            ip: 1,
            compression: IpCompression::Full64
        }
        .is_timing()
    );
}

#[test]
fn ptpacketkind_is_flow_true_for_flow_variants() {
    let ip_kind = PtPacketKind::Tip {
        ip: 0x1000,
        compression: IpCompression::Full64,
    };
    assert!(ip_kind.is_flow());
    assert!(
        PtPacketKind::TipPge {
            ip: 0,
            compression: IpCompression::Zero
        }
        .is_flow()
    );
    assert!(
        PtPacketKind::TipPgd {
            ip: 0,
            compression: IpCompression::Zero
        }
        .is_flow()
    );
    assert!(PtPacketKind::Tnt { bits: 0, count: 0 }.is_flow());
    assert!(PtPacketKind::TntLong { bits: 0, count: 0 }.is_flow());
}

#[test]
fn ptpacketkind_ip_addr_returns_ip_for_tip_family_only() {
    assert_eq!(
        PtPacketKind::Tip {
            ip: 0xdead,
            compression: IpCompression::Full64
        }
        .ip_addr(),
        Some(0xdead)
    );
    assert_eq!(
        PtPacketKind::TipPge {
            ip: 0xbeef,
            compression: IpCompression::Full64
        }
        .ip_addr(),
        Some(0xbeef)
    );
    assert_eq!(
        PtPacketKind::TipPgd {
            ip: 0xcafe,
            compression: IpCompression::Full64
        }
        .ip_addr(),
        Some(0xcafe)
    );
    assert_eq!(PtPacketKind::Tsc(123).ip_addr(), None);
    assert_eq!(PtPacketKind::Pad.ip_addr(), None);
}

#[test]
fn ptpacketkind_display_basic_variants() {
    assert_eq!(format!("{}", PtPacketKind::Pad), "Pad");
    assert_eq!(format!("{}", PtPacketKind::Psb), "PSB");
    assert_eq!(format!("{}", PtPacketKind::PsbEnd), "PSBEND");
    assert_eq!(format!("{}", PtPacketKind::Overflow), "OVF");
    assert_eq!(format!("{}", PtPacketKind::Tsc(42)), "TSC(42)");
    assert_eq!(format!("{}", PtPacketKind::Cbr(7)), "CBR(7)");
}

// ─── PtPacket ─────────────────────────────────────────────────────────────────

#[test]
fn ptpacket_new_stores_fields() {
    let p = PtPacket::new(PtPacketKind::Pad, 12, 1);
    assert_eq!(p.offset, 12);
    assert_eq!(p.size, 1);
    assert_eq!(p.kind, PtPacketKind::Pad);
}

#[test]
fn ptpacket_is_timing_and_is_flow_delegate_to_kind() {
    let t = PtPacket::new(PtPacketKind::Tsc(0), 0, 9);
    assert!(t.is_timing());
    assert!(!t.is_flow());
    let f = PtPacket::new(PtPacketKind::Tnt { bits: 0, count: 1 }, 0, 1);
    assert!(!f.is_timing());
    assert!(f.is_flow());
}

#[test]
fn ptpacket_display_includes_offset_and_size() {
    let p = PtPacket::new(PtPacketKind::Pad, 0x10, 1);
    let s = format!("{p}");
    assert!(s.contains("@0x10"));
    assert!(s.contains("[1B]"));
    assert!(s.contains("Pad"));
}

#[test]
fn ptpacket_eq_clone_serde_roundtrip() {
    let p = PtPacket::new(
        PtPacketKind::Tip {
            ip: 0x4000,
            compression: IpCompression::Full48,
        },
        16,
        7,
    );
    let cloned = p.clone();
    assert_eq!(p, cloned);
    let j = serde_json::to_string(&p).unwrap();
    let back: PtPacket = serde_json::from_str(&j).unwrap();
    assert_eq!(p, back);
}

// ─── PtDecoder ────────────────────────────────────────────────────────────────

#[test]
fn ptdecoder_new_is_empty() {
    let d = PtDecoder::new();
    assert_eq!(d.remaining_bytes(), 0);
    assert_eq!(d.peek_byte(), None);
    assert_eq!(d.overflow_count, 0);
    assert_eq!(d.error_count, 0);
}

#[test]
fn ptdecoder_default_equals_new() {
    let d: PtDecoder = PtDecoder::default();
    assert_eq!(d.remaining_bytes(), 0);
}

#[test]
fn ptdecoder_feed_extends_buffer_and_remaining_tracks() {
    let mut d = PtDecoder::new();
    d.feed(&[1, 2, 3]);
    assert_eq!(d.remaining_bytes(), 3);
    assert_eq!(d.peek_byte(), Some(1));
    d.feed(&[4]);
    assert_eq!(d.remaining_bytes(), 4);
}

#[test]
fn ptdecoder_reset_clears_position_and_counters() {
    let mut d = PtDecoder::new();
    d.feed(&[0x00, 0x00, 0xF3]);
    let _ = d.decode_all();
    assert!(d.overflow_count > 0);
    d.reset();
    assert_eq!(d.pos, 0);
    assert_eq!(d.overflow_count, 0);
    assert_eq!(d.error_count, 0);
}

#[test]
fn ptdecoder_next_packet_none_on_empty() {
    let mut d = PtDecoder::new();
    assert!(d.next_packet().is_none());
}

#[test]
fn ptdecoder_decodes_pad_byte() {
    let mut d = PtDecoder::new();
    d.feed(&[0x00]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Pad);
    assert_eq!(p.size, 1);
    assert_eq!(p.offset, 0);
    assert!(d.next_packet().is_none());
}

#[test]
fn ptdecoder_decodes_psbend_short_form() {
    let mut d = PtDecoder::new();
    d.feed(&[0x23]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::PsbEnd);
}

#[test]
fn ptdecoder_decodes_overflow_and_counts_it() {
    let mut d = PtDecoder::new();
    d.feed(&[0xF3, 0xF3]);
    let _ = d.next_packet().unwrap().unwrap();
    let _ = d.next_packet().unwrap().unwrap();
    assert_eq!(d.overflow_count, 2);
}

#[test]
fn ptdecoder_decodes_exstop_no_ip_and_with_ip() {
    let mut d = PtDecoder::new();
    d.feed(&[0x62, 0x63]);
    let a = d.next_packet().unwrap().unwrap();
    let b = d.next_packet().unwrap().unwrap();
    assert_eq!(a.kind, PtPacketKind::ExStop { ip: false });
    assert_eq!(b.kind, PtPacketKind::ExStop { ip: true });
}

#[test]
fn ptdecoder_tsc_full() {
    let mut d = PtDecoder::new();
    let mut data = vec![0x19u8];
    data.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Tsc(0x1122_3344_5566_7788));
    assert_eq!(p.size, 9);
}

#[test]
fn ptdecoder_tsc_truncated_returns_err_and_rewinds() {
    let mut d = PtDecoder::new();
    d.feed(&[0x19, 0, 0, 0]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
    assert_eq!(d.pos, 0, "decoder must rewind on truncation");
}

#[test]
fn ptdecoder_mtc_basic() {
    let mut d = PtDecoder::new();
    d.feed(&[0x59, 0xAB]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Mtc { ctc: 0xAB });
}

#[test]
fn ptdecoder_mtc_truncated() {
    let mut d = PtDecoder::new();
    d.feed(&[0x59]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn ptdecoder_long_tnt() {
    // 0xA3 + 6-byte payload. Set stop bit at position 5 → 5 TNT bits below it.
    let mut payload = 0u64;
    payload |= 1 << 5; // stop bit
    payload |= 0b10101; // 5 decision bits
    let mut data = vec![0xA3];
    data.extend_from_slice(&payload.to_le_bytes()[..6]);
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::TntLong { bits, count } => {
            assert_eq!(count, 5);
            assert_eq!(bits, 0b10101);
        }
        other => panic!("expected TntLong, got {other:?}"),
    }
}

#[test]
fn ptdecoder_long_tnt_truncated() {
    let mut d = PtDecoder::new();
    d.feed(&[0xA3, 0, 0, 0]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
}

#[test]
fn ptdecoder_short_tnt_basic() {
    // Byte 0b01000110: stop bit at position 6, decision bits = 0b000110 below.
    // Actually decoder logic: stop_bit_pos = 7 - leading_zeros.
    // For 0x46 (0b0100_0110): leading_zeros = 1, stop_bit_pos = 6, count = 6,
    // bits = 0x46 & ((1<<6)-1) = 0x06.
    let mut d = PtDecoder::new();
    d.feed(&[0x46]);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::Tnt { bits, count } => {
            assert_eq!(count, 6);
            assert_eq!(bits, 0x06);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn ptdecoder_cyc_single_byte() {
    // 0b00010_011 = 0x13: value = 0x13 >> 3 = 2; bit 2 is 0 so no continuation.
    let mut d = PtDecoder::new();
    d.feed(&[0x13]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Cyc { value: 2 });
    assert_eq!(p.size, 1);
}

#[test]
fn ptdecoder_cyc_payload_upper_5_bits() {
    // CYC gate: `b & 0b111 == 0b011`. Bit 2 of `b` is therefore forced to 0,
    // which means the "continuation" check (`(b & 0x04) != 0`) on the lead byte
    // can NEVER fire — the lead byte alone always determines `value` as `b >> 3`.
    // 0xAB (0b10101_011): b & 7 == 3 ✓; value should be 0xAB >> 3 = 0x15.
    let mut d = PtDecoder::new();
    d.feed(&[0xAB]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Cyc { value: 0x15 });
    assert_eq!(p.size, 1);
}

#[test]
fn ptdecoder_tip_full64() {
    // lower nibble 0x0D = TIP; IPR=6 in bits[7:5] → byte = (6<<5)|0x0D = 0xCD.
    let mut data = vec![0xCDu8];
    let ip: u64 = 0xDEAD_BEEF_CAFE_BABE;
    data.extend_from_slice(&ip.to_le_bytes());
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::Tip {
            ip: got,
            compression,
        } => {
            assert_eq!(got, ip);
            assert_eq!(compression, IpCompression::Full64);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(p.size, 9);
}

#[test]
fn ptdecoder_tippge_full48() {
    // lower nibble 0x11 = TIP.PGE; IPR=3 → byte = (3<<5)|0x11 = 0x71.
    let mut data = vec![0x71u8];
    data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::TipPge { ip, compression } => {
            assert_eq!(ip, 0x0000_6655_4433_2211);
            assert_eq!(compression, IpCompression::Full48);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn ptdecoder_tippgd_truncated_ip_rewinds() {
    // TIP.PGD with IPR=6 (8 bytes IP), supply only 3 — expect TruncatedPacket.
    let mut d = PtDecoder::new();
    d.feed(&[(6 << 5) | 0x01, 1, 2, 3]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::TruncatedPacket)));
    assert_eq!(d.pos, 0);
}

#[test]
fn ptdecoder_legacy_c5_tip() {
    let mut data = vec![0xC5u8];
    data.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::Tip { ip, compression } => {
            assert_eq!(ip, 0x0000_6050_4030_2010);
            assert_eq!(compression, IpCompression::Full48);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(p.size, 7);
}

#[test]
fn ptdecoder_cbr_extended_opcode() {
    // 0x02 0x22 <ratio> 0x00
    let mut d = PtDecoder::new();
    d.feed(&[0x02, 0x22, 0x55, 0x00]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Cbr(0x55));
    assert_eq!(p.size, 4);
}

#[test]
fn ptdecoder_psbend_two_byte() {
    let mut d = PtDecoder::new();
    d.feed(&[0x02, 0xC3]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::PsbEnd);
    assert_eq!(p.size, 2);
}

#[test]
fn ptdecoder_pip_packet() {
    // 0x02 0x43 + 6 byte cr3, requires pos + 7 <= buf.len() after the 0x02 0x43 prefix.
    let mut data = vec![0x02u8, 0x43];
    data.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]); // 6 cr3 bytes
    data.push(0xAA); // need one extra trailing byte so pos+7 <= len
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    match p.kind {
        PtPacketKind::Pip { cr3, nr } => {
            // cr3 raw = 0x0000_6050_4030_2010, NR bit = bit0 = 0
            assert_eq!(cr3 & 1, 0);
            assert!(!nr);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn ptdecoder_psb_packet() {
    // 0x02 followed by 15 bytes of [0x82, 0x02, ...] alternating starting with 0x82.
    let mut data = vec![0x02u8];
    for i in 0..15 {
        data.push(if i % 2 == 0 { 0x82 } else { 0x02 });
    }
    let mut d = PtDecoder::new();
    d.feed(&data);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(p.kind, PtPacketKind::Psb);
    assert_eq!(p.size, 16);
}

#[test]
fn ptdecoder_unknown_opcode_increments_error_count() {
    let mut d = PtDecoder::new();
    // 0x05 — not pad, not in any known opcode group:
    // 0x05 & 1 == 1 so not TNT short; lower 5 bits = 0x05 not 0x0D/0x11/0x01.
    d.feed(&[0x05]);
    let r = d.next_packet().unwrap();
    assert!(matches!(r, Err(PtError::UnknownOpcode(0x05))));
    assert_eq!(d.error_count, 1);
}

#[test]
fn ptdecoder_mwait_basic() {
    let mut d = PtDecoder::new();
    d.feed(&[0xC2, 0x11, 0x22, 0x00, 0x00]);
    let p = d.next_packet().unwrap().unwrap();
    assert_eq!(
        p.kind,
        PtPacketKind::Mwait {
            ext: 0x22,
            hints: 0x11
        }
    );
}

#[test]
fn ptdecoder_decode_all_skips_errors() {
    let mut d = PtDecoder::new();
    d.feed(&[0x00, 0x05, 0x00]);
    let pkts = d.decode_all();
    // pad, then unknown (skipped), then pad → 2 packets.
    assert_eq!(pkts.len(), 2);
    assert!(pkts.iter().all(|p| p.kind == PtPacketKind::Pad));
}

#[test]
fn ptdecoder_decode_all_with_errors_preserves_errors() {
    let mut d = PtDecoder::new();
    d.feed(&[0x00, 0x05, 0x00]);
    let results = d.decode_all_with_errors();
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
}

#[test]
fn ptdecoder_count_by_kind_basic() {
    let pkts = vec![
        PtPacket::new(PtPacketKind::Pad, 0, 1),
        PtPacket::new(PtPacketKind::Pad, 1, 1),
        PtPacket::new(PtPacketKind::Tsc(1), 2, 9),
    ];
    let map = PtDecoder::count_by_kind(&pkts);
    assert_eq!(map.get("Pad").copied(), Some(2));
    assert_eq!(map.get("Tsc").copied(), Some(1));
}

// ─── PtPkt helpers ────────────────────────────────────────────────────────────

#[test]
fn ptpkt_is_timing_and_has_ip() {
    assert!(PtPkt::Tsc { tsc: 0 }.is_timing());
    assert!(PtPkt::Cbr { ratio: 0 }.is_timing());
    assert!(PtPkt::Mtc { ctc: 0 }.is_timing());
    assert!(!PtPkt::Pad.is_timing());

    assert!(
        PtPkt::Tip {
            ip: 1,
            compression: StreamIpMode::Full
        }
        .has_ip()
    );
    assert!(
        PtPkt::TipPgd {
            ip: 2,
            compression: StreamIpMode::Full
        }
        .has_ip()
    );
    assert!(
        PtPkt::TipPge {
            ip: 3,
            compression: StreamIpMode::Full
        }
        .has_ip()
    );
    assert!(
        PtPkt::TipFup {
            ip: 4,
            compression: StreamIpMode::Full
        }
        .has_ip()
    );
    assert!(!PtPkt::Pad.has_ip());
}

#[test]
fn ptpkt_ip_extracts_address() {
    assert_eq!(
        PtPkt::Tip {
            ip: 0xabc,
            compression: StreamIpMode::Full
        }
        .ip(),
        Some(0xabc)
    );
    assert_eq!(PtPkt::Pad.ip(), None);
    assert_eq!(PtPkt::Tsc { tsc: 1 }.ip(), None);
}

#[test]
fn ptpkt_mnemonic_table() {
    assert_eq!(PtPkt::Pad.mnemonic(), "PAD");
    assert_eq!(PtPkt::Psb.mnemonic(), "PSB");
    assert_eq!(PtPkt::PsbEnd.mnemonic(), "PSBEND");
    assert_eq!(PtPkt::Tnt8 { payload: 0, count: 0 }.mnemonic(), "TNT8");
    assert_eq!(PtPkt::Tnt64 { payload: 0, count: 0 }.mnemonic(), "TNT64");
    assert_eq!(PtPkt::TraceStop.mnemonic(), "TRACESTOP");
    assert_eq!(PtPkt::Ovf.mnemonic(), "OVF");
    assert_eq!(PtPkt::Unknown(0xFF).mnemonic(), "UNKNOWN");
}

#[test]
fn ptpkt_display_does_not_panic_for_all_variants() {
    let pkts = vec![
        PtPkt::Pad,
        PtPkt::Psb,
        PtPkt::PsbEnd,
        PtPkt::Tnt8 { payload: 1, count: 1 },
        PtPkt::Tnt64 { payload: 1, count: 1 },
        PtPkt::Tip {
            ip: 1,
            compression: StreamIpMode::Full,
        },
        PtPkt::TipPgd {
            ip: 2,
            compression: StreamIpMode::Upd16,
        },
        PtPkt::TipPge {
            ip: 3,
            compression: StreamIpMode::Upd32,
        },
        PtPkt::TipFup {
            ip: 4,
            compression: StreamIpMode::Sext48,
        },
        PtPkt::Tsc { tsc: 1 },
        PtPkt::Mtc { ctc: 1 },
        PtPkt::Cbr { ratio: 1 },
        PtPkt::TraceStop,
        PtPkt::Ovf,
        PtPkt::Unknown(0xAB),
    ];
    for p in pkts {
        let _ = format!("{p}");
    }
}

// ─── PtPacketStream ───────────────────────────────────────────────────────────

#[test]
fn ptpacketstream_empty() {
    let mut s = PtPacketStream::new(vec![]);
    assert!(s.is_empty());
    assert_eq!(s.remaining(), 0);
    assert!(s.next_packet().is_none());
}

#[test]
fn ptpacketstream_pad() {
    let mut s = PtPacketStream::from_slice(&[0x00]);
    assert_eq!(s.next_packet(), Some(PtPkt::Pad));
    assert!(s.next_packet().is_none());
}

#[test]
fn ptpacketstream_psb_detected() {
    let psb: [u8; 16] = [
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82,
    ];
    let mut s = PtPacketStream::from_slice(&psb);
    assert_eq!(s.next_packet(), Some(PtPkt::Psb));
    assert!(s.is_empty());
}

#[test]
fn ptpacketstream_psbend_extended() {
    let mut s = PtPacketStream::from_slice(&[0x02, 0x23]);
    assert_eq!(s.next_packet(), Some(PtPkt::PsbEnd));
}

#[test]
fn ptpacketstream_ovf_extended() {
    let mut s = PtPacketStream::from_slice(&[0x02, 0xF3]);
    assert_eq!(s.next_packet(), Some(PtPkt::Ovf));
}

#[test]
fn ptpacketstream_tsc_decodes_56_bit() {
    // 0x19 + 7 bytes LE
    let mut data = vec![0x19u8];
    data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    let mut s = PtPacketStream::from_slice(&data);
    assert_eq!(
        s.next_packet(),
        Some(PtPkt::Tsc {
            tsc: 0x77_6655_4433_2211
        })
    );
}

#[test]
fn ptpacketstream_mtc() {
    let mut s = PtPacketStream::from_slice(&[0x59, 0xAB]);
    assert_eq!(s.next_packet(), Some(PtPkt::Mtc { ctc: 0xAB }));
}

#[test]
fn ptpacketstream_cbr() {
    let mut s = PtPacketStream::from_slice(&[0x03, 0x00, 0x7F, 0x00]);
    assert_eq!(s.next_packet(), Some(PtPkt::Cbr { ratio: 0x7F }));
}

#[test]
fn ptpacketstream_tracestop_lookahead() {
    let mut s = PtPacketStream::from_slice(&[0x01, 0x83]);
    assert_eq!(s.next_packet(), Some(PtPkt::TraceStop));
}

#[test]
fn ptpacketstream_tip_full_64bit() {
    // lower 5 bits 0x0D, ipr = 6 (Full) → opcode = (6<<5)|0x0D = 0xCD.
    let mut data = vec![0xCDu8];
    let ip = 0x0123_4567_89AB_CDEFu64;
    data.extend_from_slice(&ip.to_le_bytes());
    let mut s = PtPacketStream::from_slice(&data);
    assert_eq!(
        s.next_packet(),
        Some(PtPkt::Tip {
            ip,
            compression: StreamIpMode::Full,
        })
    );
    assert_eq!(s.last_ip, ip);
}

#[test]
fn ptpacketstream_tip_upd16_keeps_upper_bits_from_last_ip() {
    // Seed last_ip via a full TIP, then update with Upd16.
    let mut data = vec![0xCDu8];
    let seed = 0xAABB_CCDD_EEFF_0011u64;
    data.extend_from_slice(&seed.to_le_bytes());
    // Upd16: ipr=1 → opcode = (1<<5)|0x0D = 0x2D, plus 2 bytes.
    data.push(0x2D);
    data.extend_from_slice(&[0x34, 0x12]);
    let mut s = PtPacketStream::from_slice(&data);
    let _ = s.next_packet();
    let upd = s.next_packet();
    let expected = (seed & !0xFFFF) | 0x1234;
    assert_eq!(
        upd,
        Some(PtPkt::Tip {
            ip: expected,
            compression: StreamIpMode::Upd16,
        })
    );
}

#[test]
fn ptpacketstream_tip_sext48_sign_extends() {
    // ipr=4 → opcode = (4<<5)|0x0D = 0x8D, 6 byte payload with bit47 set.
    let mut data = vec![0x8Du8];
    // 0x8000_0000_0000 → bit 47 set.
    let raw48: u64 = 0x8000_0000_0000;
    data.extend_from_slice(&raw48.to_le_bytes()[..6]);
    let mut s = PtPacketStream::from_slice(&data);
    match s.next_packet().unwrap() {
        PtPkt::Tip { ip, .. } => {
            assert_eq!(ip, 0xFFFF_8000_0000_0000);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn ptpacketstream_unknown_byte_advances() {
    // 0x05 is unrecognised single-byte.
    let mut s = PtPacketStream::from_slice(&[0x05, 0x00]);
    assert_eq!(s.next_packet(), Some(PtPkt::Unknown(0x05)));
    assert_eq!(s.next_packet(), Some(PtPkt::Pad));
}

#[test]
fn ptpacketstream_sync_forward_finds_psb() {
    let mut data = vec![0xAA, 0xBB, 0xCC];
    data.extend_from_slice(&PtPacketStream::from_slice(&[]).data); // no-op, keep type
    let psb: [u8; 16] = [
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82,
    ];
    data.extend_from_slice(&psb);
    let mut s = PtPacketStream::new(data);
    assert_eq!(s.sync_forward(), Some(3));
    assert_eq!(s.next_packet(), Some(PtPkt::Psb));
}

#[test]
fn ptpacketstream_sync_forward_returns_none_when_absent() {
    let mut s = PtPacketStream::from_slice(&[0u8; 32]);
    assert_eq!(s.sync_forward(), None);
}

#[test]
fn ptpacketstream_decode_all_and_flow_filtering() {
    // pad, tsc, pad, tip → decode_flow drops pad+tsc.
    let mut data = vec![0x00];
    data.push(0x19);
    data.extend_from_slice(&[0u8; 7]); // TSC 0
    data.push(0x00);
    // TIP full64 ip = 0x10
    data.push(0xCD);
    data.extend_from_slice(&0x10u64.to_le_bytes());

    let mut s1 = PtPacketStream::from_slice(&data);
    let all = s1.decode_all();
    assert_eq!(all.len(), 4);

    let mut s2 = PtPacketStream::from_slice(&data);
    let flow = s2.decode_flow();
    assert_eq!(flow.len(), 1);
    assert!(matches!(flow[0], PtPkt::Tip { .. }));
}

#[test]
fn ptpacketstream_seek_to_end_ok() {
    let mut s = PtPacketStream::from_slice(&[0u8; 4]);
    s.seek(4);
    assert!(s.is_empty());
}

#[test]
#[should_panic(expected = "")]
fn ptpacketstream_seek_past_end_panics() {
    // Documented panic — we test it actually panics. (Not masking a bug.)
    let mut s = PtPacketStream::from_slice(&[0u8; 4]);
    s.seek(5);
}

#[test]
fn ptpacketstream_decode_ip_suppressed_returns_last_ip() {
    let mut s = PtPacketStream::from_slice(&[]);
    s.last_ip = 0x4242;
    assert_eq!(s.decode_ip(StreamIpMode::Suppressed), Some(0x4242));
    assert_eq!(s.last_ip, 0x4242);
}

#[test]
fn ptpacketstream_decode_ip_full_reads_8_bytes() {
    let ip = 0x1122_3344_5566_7788u64;
    let mut s = PtPacketStream::new(ip.to_le_bytes().to_vec());
    assert_eq!(s.decode_ip(StreamIpMode::Full), Some(ip));
    assert_eq!(s.last_ip, ip);
}

// ─── StreamTraceEntry ─────────────────────────────────────────────────────────

#[test]
fn streamtraceentry_constructors() {
    let a = StreamTraceEntry::new(1, Some(10), Some(true));
    assert_eq!(a.ip, 1);
    assert_eq!(a.tsc, Some(10));
    assert_eq!(a.taken, Some(true));

    let b = StreamTraceEntry::from_ip(2);
    assert_eq!(b.ip, 2);
    assert_eq!(b.tsc, None);
    assert_eq!(b.taken, None);

    let c = StreamTraceEntry::with_tsc(3, 20);
    assert_eq!(c.ip, 3);
    assert_eq!(c.tsc, Some(20));
    assert_eq!(c.taken, None);
}

#[test]
fn streamtraceentry_display_format() {
    let e = StreamTraceEntry::new(0x4000, Some(7), Some(true));
    let s = format!("{e}");
    assert!(s.contains("0x0000000000004000"));
    assert!(s.contains("tsc=7"));
    assert!(s.contains("taken=true"));
}

#[test]
fn streamtraceentry_serde_roundtrip() {
    let e = StreamTraceEntry::new(0xff, Some(2), Some(false));
    let j = serde_json::to_string(&e).unwrap();
    let back: StreamTraceEntry = serde_json::from_str(&j).unwrap();
    assert_eq!(e, back);
}

// ─── StreamTrace ──────────────────────────────────────────────────────────────

#[test]
fn streamtrace_default_and_new_empty() {
    let t = StreamTrace::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.start_tsc(), None);
    assert_eq!(t.end_tsc(), None);
    assert_eq!(t.tsc_delta(), None);
}

#[test]
fn streamtrace_push_and_iter() {
    let mut t = StreamTrace::with_capacity(2);
    t.push(StreamTraceEntry::from_ip(1));
    t.push(StreamTraceEntry::from_ip(2));
    let ips: Vec<u64> = t.iter().map(|e| e.ip).collect();
    assert_eq!(ips, vec![1, 2]);
}

#[test]
fn streamtrace_unique_ips() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(1));
    t.push(StreamTraceEntry::from_ip(2));
    t.push(StreamTraceEntry::from_ip(1));
    let u = t.unique_ips();
    assert_eq!(u.len(), 2);
    assert!(u.contains(&1));
    assert!(u.contains(&2));
}

#[test]
fn streamtrace_tsc_endpoints() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(1)); // no tsc
    t.push(StreamTraceEntry::with_tsc(2, 100));
    t.push(StreamTraceEntry::from_ip(3));
    t.push(StreamTraceEntry::with_tsc(4, 200));
    assert_eq!(t.start_tsc(), Some(100));
    assert_eq!(t.end_tsc(), Some(200));
    assert_eq!(t.tsc_delta(), Some(100));
}

#[test]
fn streamtrace_filter_range_is_half_open() {
    let mut t = StreamTrace::new();
    for ip in 0..10u64 {
        t.push(StreamTraceEntry::from_ip(ip));
    }
    let sub = t.filter_range(2, 5);
    let ips: Vec<u64> = sub.iter().map(|e| e.ip).collect();
    assert_eq!(ips, vec![2, 3, 4]); // hi exclusive
}

#[test]
fn streamtrace_merge_appends() {
    let mut a = StreamTrace::new();
    a.push(StreamTraceEntry::from_ip(1));
    let mut b = StreamTrace::new();
    b.push(StreamTraceEntry::from_ip(2));
    b.push(StreamTraceEntry::from_ip(3));
    a.merge(&b);
    assert_eq!(a.len(), 3);
    assert_eq!(a.instructions[2].ip, 3);
}

#[test]
fn streamtrace_sort_by_ip_is_stable() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::new(3, Some(1), None));
    t.push(StreamTraceEntry::new(1, Some(2), None));
    t.push(StreamTraceEntry::new(2, Some(3), None));
    t.sort_by_ip();
    let ips: Vec<u64> = t.iter().map(|e| e.ip).collect();
    assert_eq!(ips, vec![1, 2, 3]);
}

#[test]
fn streamtrace_from_packets_tippge_starts_tracing() {
    let packets = vec![
        PtPkt::Tsc { tsc: 100 },
        PtPkt::TipPge {
            ip: 0x1000,
            compression: StreamIpMode::Full,
        },
        PtPkt::Tip {
            ip: 0x2000,
            compression: StreamIpMode::Full,
        },
        PtPkt::TipPgd {
            ip: 0x3000,
            compression: StreamIpMode::Full,
        },
        // After TipPgd, tracing is off — subsequent Tip should NOT be recorded.
        PtPkt::Tip {
            ip: 0x4000,
            compression: StreamIpMode::Full,
        },
    ];
    let t = StreamTrace::from_packets(&packets);
    let ips: Vec<u64> = t.iter().map(|e| e.ip).collect();
    assert_eq!(ips, vec![0x1000, 0x2000, 0x3000]);
    // TSC should be propagated.
    assert!(t.iter().all(|e| e.tsc == Some(100)));
}

#[test]
fn streamtrace_from_packets_ovf_synthesises_zero_entry() {
    let packets = vec![
        PtPkt::TipPge {
            ip: 0x10,
            compression: StreamIpMode::Full,
        },
        PtPkt::Ovf,
    ];
    let t = StreamTrace::from_packets(&packets);
    assert_eq!(t.len(), 2);
    assert_eq!(t.instructions[1].ip, 0);
}

#[test]
fn streamtrace_from_packets_tnt_consumed_by_tip() {
    let packets = vec![
        PtPkt::TipPge {
            ip: 0x10,
            compression: StreamIpMode::Full,
        },
        PtPkt::Tnt8 { payload: 0b1, count: 1 },
        PtPkt::Tip {
            ip: 0x20,
            compression: StreamIpMode::Full,
        },
    ];
    let t = StreamTrace::from_packets(&packets);
    assert_eq!(t.len(), 2);
    assert_eq!(t.instructions[1].taken, Some(true));
}

#[test]
fn streamtrace_from_packets_tip_without_tracing_is_skipped() {
    // No prior TipPge → tracing=false, Tip should be dropped (per from_packets logic).
    let packets = vec![PtPkt::Tip {
        ip: 0x10,
        compression: StreamIpMode::Full,
    }];
    let t = StreamTrace::from_packets(&packets);
    assert_eq!(t.len(), 0);
}

#[test]
fn streamtrace_from_packets_fup_recorded_even_when_not_tracing() {
    let packets = vec![PtPkt::TipFup {
        ip: 0x42,
        compression: StreamIpMode::Full,
    }];
    let t = StreamTrace::from_packets(&packets);
    assert_eq!(t.len(), 1);
    assert_eq!(t.instructions[0].ip, 0x42);
}

// ─── Module-level helpers ─────────────────────────────────────────────────────

#[test]
fn pt_to_coverage_extracts_unique_ips() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(1));
    t.push(StreamTraceEntry::from_ip(2));
    t.push(StreamTraceEntry::from_ip(1));
    let cov = pt_to_coverage(&t);
    assert_eq!(cov.len(), 2);
}

#[test]
fn pt_pkts_to_coverage_runs_through_from_packets() {
    let pkts = vec![PtPkt::TipPge {
        ip: 0xABC,
        compression: StreamIpMode::Full,
    }];
    let cov = pt_pkts_to_coverage(&pkts);
    assert!(cov.contains(&0xABC));
}

#[test]
fn pt_to_drcov_text_header_present() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(0x1000));
    t.push(StreamTraceEntry::from_ip(0x1010));
    let text = pt_to_drcov(&t, "modA");
    assert!(text.starts_with("DRCOV VERSION: 2\n"));
    assert!(text.contains("DRCOV FLAVOR: drcov\n"));
    assert!(text.contains("modA"));
    assert!(text.contains("BB Table: 2 bbs\n"));
}

#[test]
fn pt_to_drcov_bytes_starts_with_drcov_header() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(0x100));
    let bytes = pt_to_drcov_bytes(&t, "m");
    let head = std::str::from_utf8(&bytes[..16]).unwrap();
    assert!(head.starts_with("DRCOV VERSION: 2"));
}

#[test]
fn pt_to_drcov_empty_trace_has_zero_bbs() {
    let t = StreamTrace::new();
    let text = pt_to_drcov(&t, "x");
    assert!(text.contains("BB Table: 0 bbs\n"));
}

#[test]
fn pt_to_drcov_bytes_includes_binary_record_per_unique_ip() {
    let mut t = StreamTrace::new();
    t.push(StreamTraceEntry::from_ip(0x100));
    t.push(StreamTraceEntry::from_ip(0x200));
    let bytes = pt_to_drcov_bytes(&t, "m");
    // Find "bbs\n" terminator and assert remaining bytes are 2 * 8 = 16.
    let needle = b"bbs\n";
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let bin = &bytes[pos + needle.len()..];
    assert_eq!(bin.len(), 16);
}

// ─── decode_pt_buffer / decode_pt_buffer_verbose ──────────────────────────────

#[test]
fn decode_pt_buffer_empty() {
    let t = decode_pt_buffer(&[]);
    assert!(t.is_empty());
}

#[test]
fn decode_pt_buffer_pad_only_yields_empty_trace() {
    // PAD packets are dropped by StreamTrace::from_packets.
    let t = decode_pt_buffer(&[0x00, 0x00, 0x00]);
    assert!(t.is_empty());
}

#[test]
fn decode_pt_buffer_verbose_returns_packets_and_trace() {
    // TipPge + Tip → 2 trace entries.
    // TipPge in PtPacketStream: lower 5 bits = 0x01, IPR=6 → byte = (6<<5)|0x01 = 0xC1.
    let mut data = vec![0xC1u8];
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    data.push(0xCDu8); // Tip Full
    data.extend_from_slice(&0x2000u64.to_le_bytes());
    let (pkts, trace) = decode_pt_buffer_verbose(&data);
    assert_eq!(pkts.len(), 2);
    assert!(matches!(pkts[0], PtPkt::TipPge { .. }));
    assert!(matches!(pkts[1], PtPkt::Tip { .. }));
    assert_eq!(trace.len(), 2);
    assert_eq!(trace.instructions[0].ip, 0x1000);
    assert_eq!(trace.instructions[1].ip, 0x2000);
}

// ─── PtError formatting ───────────────────────────────────────────────────────

#[test]
fn pterror_display_strings() {
    assert_eq!(
        format!("{}", PtError::InvalidPacket(0x12)),
        "invalid packet byte 0x12"
    );
    assert_eq!(format!("{}", PtError::TruncatedPacket), "truncated packet");
    assert_eq!(
        format!("{}", PtError::UnknownOpcode(0xAB)),
        "unknown opcode 0xab"
    );
    assert_eq!(
        format!("{}", PtError::Overflow(0x100)),
        "trace overflow at offset 0x100"
    );
}
