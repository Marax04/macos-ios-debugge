//! Exhaustive blitz tests for `rustre-trace-coresight`.
//!
//! These tests target the public API surface of `lib.rs`:
//! decoders (CsDecoder, CoreSightDecoder, EtmDecoder, PtmDecoder, Etm3Decoder,
//! EteDecoder), packet & enum types, ROM table parsing, ETB/TMI buffers,
//! topology, filters, heatmap, branch trace, exec trace, shared index, and
//! reconstructor — including malformed/adversarial inputs and boundary cases.

use rustre_trace_coresight::*;

// ─── ExceptionType ────────────────────────────────────────────────────────

#[test]
fn excep_type_all_known_values() {
    let pairs = [
        (0u8, ExceptionType::Reset),
        (1, ExceptionType::Undefined),
        (2, ExceptionType::Svc),
        (3, ExceptionType::PrefetchAbort),
        (4, ExceptionType::DataAbort),
        (5, ExceptionType::Irq),
        (6, ExceptionType::Fiq),
        (7, ExceptionType::Hvc),
        (8, ExceptionType::Smc),
        (9, ExceptionType::SError),
        (10, ExceptionType::Debug),
    ];
    for (v, expected) in pairs {
        assert_eq!(ExceptionType::from_etm_field(v), expected, "value {v}");
    }
}

#[test]
fn excep_type_unknown_for_high_values() {
    for v in [11u8, 50, 200, 254, 255] {
        assert_eq!(ExceptionType::from_etm_field(v), ExceptionType::Unknown);
    }
}

#[test]
fn excep_type_display_all() {
    let cases = [
        (ExceptionType::Reset, "Reset"),
        (ExceptionType::Undefined, "Undefined"),
        (ExceptionType::Svc, "SVC"),
        (ExceptionType::PrefetchAbort, "PrefetchAbort"),
        (ExceptionType::DataAbort, "DataAbort"),
        (ExceptionType::Irq, "IRQ"),
        (ExceptionType::Fiq, "FIQ"),
        (ExceptionType::Hvc, "HVC"),
        (ExceptionType::Smc, "SMC"),
        (ExceptionType::SError, "SError"),
        (ExceptionType::Debug, "Debug"),
        (ExceptionType::Unknown, "Unknown"),
    ];
    for (et, expected) in cases {
        assert_eq!(et.to_string(), expected);
    }
}

#[test]
fn excep_type_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ExceptionType::Irq);
    s.insert(ExceptionType::Irq);
    s.insert(ExceptionType::Fiq);
    assert_eq!(s.len(), 2);
}

// ─── ExceptionLevel ───────────────────────────────────────────────────────

#[test]
fn excep_level_from_bits_masks_two_bits() {
    assert_eq!(ExceptionLevel::from_bits(0b0000_0100), ExceptionLevel::El0);
    assert_eq!(ExceptionLevel::from_bits(0b1111_1101), ExceptionLevel::El1);
    assert_eq!(ExceptionLevel::from_bits(0b1111_1110), ExceptionLevel::El2);
    assert_eq!(ExceptionLevel::from_bits(0b1111_1111), ExceptionLevel::El3);
}

#[test]
fn excep_level_numeric() {
    assert_eq!(ExceptionLevel::El0.level(), 0);
    assert_eq!(ExceptionLevel::El1.level(), 1);
    assert_eq!(ExceptionLevel::El2.level(), 2);
    assert_eq!(ExceptionLevel::El3.level(), 3);
}

#[test]
fn excep_level_display() {
    assert_eq!(ExceptionLevel::El0.to_string(), "EL0");
    assert_eq!(ExceptionLevel::El2.to_string(), "EL2");
}

// ─── IsaMode / SecurityState ──────────────────────────────────────────────

#[test]
fn isa_mode_display_arm_jazelle() {
    assert_eq!(IsaMode::Arm.to_string(), "A32");
    assert_eq!(IsaMode::Thumb16.to_string(), "T16");
    assert_eq!(IsaMode::Jazelle.to_string(), "Jazelle");
}

// ─── IsaType ──────────────────────────────────────────────────────────────

#[test]
fn isa_type_field_high_bits_ignored() {
    // Only low 2 bits used.
    assert_eq!(IsaType::from_etm_is_field(0b1111_1100, true), IsaType::AArch64);
    assert_eq!(IsaType::from_etm_is_field(0b1111_1101, false), IsaType::Thumb);
}

// ─── CsPacketKind Display ─────────────────────────────────────────────────

#[test]
fn cs_packet_kind_display_data_addr() {
    let s = CsPacketKind::DataAddress { addr: 0xABCD, is_write: true }.to_string();
    assert!(s.contains("DataAddr"));
    assert!(s.contains("abcd"));
    assert!(s.contains("true"));
}

#[test]
fn cs_packet_kind_display_data_value() {
    let s = CsPacketKind::DataValue { value: 0x1234, size: 4 }.to_string();
    assert!(s.contains("1234"));
    assert!(s.contains("4B"));
}

#[test]
fn cs_packet_kind_display_qelement_branch_future_indirect() {
    assert!(CsPacketKind::QElement { count: 7 }.to_string().contains("7"));
    assert!(CsPacketKind::BranchFuture { target: 0xCAFE }.to_string().contains("cafe"));
    assert!(CsPacketKind::IndirectBranch { target: 0xBEEF }.to_string().contains("beef"));
    assert_eq!(CsPacketKind::ExceptionReturn.to_string(), "ExceptionReturn");
    assert_eq!(CsPacketKind::Ignore.to_string(), "Ignore");
    assert_eq!(CsPacketKind::Sync.to_string(), "Sync");
}

#[test]
fn cs_packet_kind_eq() {
    let a = CsPacketKind::Address { addr: 0x100 };
    let b = CsPacketKind::Address { addr: 0x100 };
    let c = CsPacketKind::Address { addr: 0x200 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ─── EtmConfig builders ───────────────────────────────────────────────────

#[test]
fn etm_config_with_data_trace() {
    let c = EtmConfig::new(EtmVersion::Ete, "arm64").with_data_trace();
    assert!(c.data_trace_enabled);
    assert!(!c.cycle_counting);
}

#[test]
fn etm_config_with_cycle_count() {
    let c = EtmConfig::new(EtmVersion::Etm4, "arm64").with_cycle_count();
    assert!(c.cycle_counting);
}

#[test]
fn etm_config_default_fields() {
    let c = EtmConfig::new(EtmVersion::Etm4, "arm64");
    assert_eq!(c.addr_comparators, 4);
    assert_eq!(c.context_id_comparators, 1);
    assert!(c.timestamps);
    assert_eq!(c.trace_id, 0x10);
}

// ─── EtmContext ───────────────────────────────────────────────────────────

#[test]
fn etm_context_new_aarch64_defaults() {
    let c = EtmContext::new_aarch64();
    assert_eq!(c.isa, IsaMode::Aarch64);
    assert_eq!(c.security, SecurityState::NonSecure);
    assert!(!c.addr_valid);
}

#[test]
fn etm_context_apply_context_secure() {
    let mut c = EtmContext::default();
    c.apply_context(ExceptionLevel::El2, false);
    assert_eq!(c.el, ExceptionLevel::El2);
    assert_eq!(c.security, SecurityState::Secure);
}

#[test]
fn etm_context_apply_context_nonsecure() {
    let mut c = EtmContext::default();
    c.apply_context(ExceptionLevel::El1, true);
    assert_eq!(c.security, SecurityState::NonSecure);
}

#[test]
fn etm_context_advance_when_valid() {
    let mut c = EtmContext::default();
    c.apply_address(0x1000);
    c.advance(4);
    assert_eq!(c.current_addr, 0x1004);
}

#[test]
fn etm_context_advance_when_not_valid_does_nothing() {
    let mut c = EtmContext::default();
    c.advance(4);
    assert_eq!(c.current_addr, 0);
}

#[test]
fn etm_context_advance_wraps() {
    let mut c = EtmContext::default();
    c.apply_address(u64::MAX);
    c.advance(1);
    assert_eq!(c.current_addr, 0);
}

// ─── AtomPacket ───────────────────────────────────────────────────────────

#[test]
fn atom_packet_idx_at_or_above_count_is_false() {
    let p = AtomPacket::new(0xFFFF_FFFF, 4, 0);
    assert!(p.is_taken(0));
    assert!(p.is_taken(3));
    assert!(!p.is_taken(4)); // out of range
    assert!(!p.is_taken(31));
}

#[test]
fn atom_packet_to_vec_all_taken() {
    let p = AtomPacket::new(0xFF, 8, 0);
    assert_eq!(p.to_vec(), vec![true; 8]);
}

#[test]
fn atom_packet_to_vec_empty() {
    let p = AtomPacket::new(0, 0, 0);
    assert!(p.to_vec().is_empty());
}

// ─── EtmAddressUpdate ─────────────────────────────────────────────────────

#[test]
fn etm_address_update_partial() {
    let u = EtmAddressUpdate::partial(0xABCD, 2);
    assert!(!u.is_full);
    assert_eq!(u.bytes_valid, 2);
    assert_eq!(u.address, 0xABCD);
}

// ─── EtmTimestamp ─────────────────────────────────────────────────────────

#[test]
fn etm_timestamp_ord() {
    let a = EtmTimestamp::new(5);
    let b = EtmTimestamp::new(10);
    assert!(a < b);
}

#[test]
fn etm_timestamp_delta_wraps() {
    let a = EtmTimestamp::new(0);
    let b = EtmTimestamp::new(10);
    assert_eq!(a.delta_from(b), u64::MAX - 10 + 1);
}

#[test]
fn etm_timestamp_display() {
    assert_eq!(EtmTimestamp::new(42).to_string(), "ts:42");
}

// ─── DataTracePacket ──────────────────────────────────────────────────────

#[test]
fn data_trace_packet_no_value_default() {
    let p = DataTracePacket::new(0x1000, 8, false, 5);
    assert_eq!(p.value, None);
    assert!(!p.is_write);
    assert_eq!(p.size, 8);
    assert_eq!(p.byte_offset, 5);
}

// ─── ExceptionPacket ──────────────────────────────────────────────────────

#[test]
fn exception_packet_defaults() {
    let p = ExceptionPacket::new(ExceptionType::DataAbort, ExceptionLevel::El1, 99);
    assert!(p.target_addr.is_none());
    assert!(!p.previous_el);
}

// ─── CoreSightDecoder ─────────────────────────────────────────────────────

fn full() -> CoreSightDecoder {
    CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"))
}

#[test]
fn full_decoder_empty_returns_none() {
    let mut d = full();
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
    assert!(!d.is_synchronized());
}

#[test]
fn full_decoder_trace_on_sets_sync() {
    let mut d = full();
    d.feed(&[0x05]);
    let _ = d.next_packet();
    assert!(d.is_synchronized());
}

#[test]
fn full_decoder_sync_byte_marks_synchronized() {
    let mut d = full();
    d.feed(&[0x80]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Sync);
    assert!(d.is_synchronized());
}

#[test]
fn full_decoder_exception_return_byte_07() {
    let mut d = full();
    d.feed(&[0x07]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::ExceptionReturn);
}

#[test]
fn full_decoder_cycle_count_uleb128() {
    let mut d = full();
    // 0x0D header + ULEB128 of 300 = 0xAC 0x02
    d.feed(&[0x0D, 0xAC, 0x02]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::CycleCount(300));
    assert_eq!(d.context.cycle_count, 300);
}

#[test]
fn full_decoder_cycle_count_accumulates() {
    let mut d = full();
    d.feed(&[0x0D, 0x05, 0x0D, 0x03]);
    let _ = d.next_packet();
    let _ = d.next_packet();
    assert_eq!(d.context.cycle_count, 8);
}

#[test]
fn full_decoder_context_packet_nonsecure_el2() {
    let mut d = full();
    // 0x0E + ctx byte: bits[2:1]=EL, bit0=NS. EL2=0b10, ns=1 → 0b101 = 5
    d.feed(&[0x0E, 0b0000_0101]);
    let p = d.next_packet().unwrap();
    match p.kind {
        CsPacketKind::Context { el, ns } => {
            assert_eq!(el, Some(ExceptionLevel::El2));
            assert!(ns);
        }
        _ => panic!("expected Context"),
    }
    assert_eq!(d.context.el, ExceptionLevel::El2);
    assert_eq!(d.context.security, SecurityState::NonSecure);
}

#[test]
fn full_decoder_context_truncated_rewinds() {
    let mut d = full();
    d.feed(&[0x0E]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_timestamp_8byte() {
    let mut d = full();
    let ts: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut data = vec![0x43];
    data.extend_from_slice(&ts.to_le_bytes());
    d.feed(&data);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Timestamp(ts));
    assert_eq!(d.context.timestamp, ts);
}

#[test]
fn full_decoder_timestamp_truncated_rewinds() {
    let mut d = full();
    d.feed(&[0x43, 0, 1, 2, 3]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_context_id() {
    let mut d = full();
    d.feed(&[0x50, 0x78, 0x56, 0x34, 0x12]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::ContextId(0x1234_5678));
    assert_eq!(d.context.context_id, 0x1234_5678);
}

#[test]
fn full_decoder_context_id_truncated_rewinds() {
    let mut d = full();
    d.feed(&[0x50, 0x01, 0x02]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_vmid() {
    let mut d = full();
    d.feed(&[0x51, 0xEF, 0xBE, 0xAD, 0xDE]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::VmId(0xDEAD_BEEF));
    assert_eq!(d.context.vmid, 0xDEAD_BEEF);
}

#[test]
fn full_decoder_exception_packet() {
    let mut d = full();
    // 0x08 + type byte + level byte. type=5 (IRQ), level=2 → EL2.
    d.feed(&[0x08, 0x05, 0x02]);
    let p = d.next_packet().unwrap();
    assert!(matches!(p.kind, CsPacketKind::Exception { .. }));
    assert_eq!(d.exceptions.len(), 1);
    assert_eq!(d.exceptions[0].exc_type, ExceptionType::Irq);
    assert_eq!(d.exceptions[0].level, ExceptionLevel::El2);
}

#[test]
fn full_decoder_exception_truncated_rewinds() {
    let mut d = full();
    d.feed(&[0x08, 0x05]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_address_4byte_truncated() {
    let mut d = full();
    d.feed(&[0x9A, 0x01]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_address_8byte_truncated() {
    let mut d = full();
    d.feed(&[0x9B, 0x01, 0x02, 0x03]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_indirect_branch() {
    let mut d = full();
    let target: u64 = 0x8000_0000_DEAD_BEEF;
    let mut data = vec![0xAA];
    data.extend_from_slice(&target.to_le_bytes());
    d.feed(&data);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::IndirectBranch { target });
}

#[test]
fn full_decoder_indirect_branch_truncated() {
    let mut d = full();
    d.feed(&[0xAA, 0x01]);
    assert!(d.next_packet().is_none());
    assert_eq!(d.position(), 0);
}

#[test]
fn full_decoder_atom_pushes_to_atoms_vec() {
    let mut d = full();
    d.feed(&[0x00, 0x04, 0x00]);
    let _ = d.decode_all();
    assert_eq!(d.atoms.len(), 3);
    assert!(!d.atoms[0].is_taken(0));
    assert!(d.atoms[1].is_taken(0));
    assert!(!d.atoms[2].is_taken(0));
}

#[test]
fn full_decoder_unknown_byte_yields_overflow() {
    let mut d = full();
    d.feed(&[0x77]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Overflow);
}

#[test]
fn full_decoder_reset_clears_state() {
    let mut d = full();
    d.feed(&[0x05, 0x00, 0x04]);
    let _ = d.decode_all();
    assert!(d.is_synchronized());
    assert!(d.position() > 0);
    d.reset();
    assert_eq!(d.position(), 0);
    assert!(!d.is_synchronized());
}

#[test]
fn full_decoder_uleb128_overflow_returns_zero() {
    let mut d = full();
    // 10 continuation bytes — shift exceeds 64 → read_uleb128 returns None,
    // and the cycle count decoder treats None as 0.
    let mut data = vec![0x0D];
    for _ in 0..11 {
        data.push(0xFF);
    }
    data.push(0x00);
    d.feed(&data);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::CycleCount(0));
}

#[test]
fn full_decoder_find_sync_advances() {
    let mut d = full();
    let mut data = vec![0xAA, 0xBB, 0xCC];
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    data.push(0x05);
    d.feed(&data);
    assert!(d.find_sync());
    assert!(d.is_synchronized());
    // pos should now be just past the sync (15 = 3 + 12)
    assert_eq!(d.position(), 15);
}

#[test]
fn full_decoder_find_sync_none() {
    let mut d = full();
    d.feed(&[1, 2, 3, 4, 5]);
    assert!(!d.find_sync());
    assert_eq!(d.position(), 0);
}

// ─── CsDecoder (legacy) ───────────────────────────────────────────────────

#[test]
fn cs_decoder_address_4byte() {
    let mut d = CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    let addr: u32 = 0xCAFE_BABE;
    let mut data = vec![0x9A];
    data.extend_from_slice(&addr.to_le_bytes());
    d.feed(&data);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Address { addr: u64::from(addr) });
}

#[test]
fn cs_decoder_unknown_byte_overflow() {
    let mut d = CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    d.feed(&[0x33]);
    assert_eq!(d.next_packet().unwrap().kind, CsPacketKind::Overflow);
}

// ─── EtmTrace ─────────────────────────────────────────────────────────────

fn pk(kind: CsPacketKind) -> CsPacket {
    CsPacket { kind, byte_offset: 0 }
}

#[test]
fn etm_trace_taken_not_taken_split() {
    let trace = EtmTrace {
        packets: vec![
            pk(CsPacketKind::Atom { taken: true, count: 1 }),
            pk(CsPacketKind::Atom { taken: false, count: 1 }),
            pk(CsPacketKind::Atom { taken: true, count: 1 }),
        ],
        config: EtmConfig::new(EtmVersion::Etm4, "arm64"),
    };
    assert_eq!(trace.taken_atoms(), 2);
    assert_eq!(trace.not_taken_atoms(), 1);
}

#[test]
fn etm_trace_exception_count_last_ts() {
    let trace = EtmTrace {
        packets: vec![
            pk(CsPacketKind::Timestamp(10)),
            pk(CsPacketKind::Exception { exc_type: 5 }),
            pk(CsPacketKind::Timestamp(20)),
            pk(CsPacketKind::Exception { exc_type: 6 }),
        ],
        config: EtmConfig::new(EtmVersion::Etm4, "arm64"),
    };
    assert_eq!(trace.exception_count(), 2);
    assert_eq!(trace.last_timestamp(), Some(20));
}

#[test]
fn etm_trace_no_timestamp_returns_none() {
    let trace = EtmTrace {
        packets: vec![pk(CsPacketKind::TraceOn)],
        config: EtmConfig::new(EtmVersion::Etm4, "arm64"),
    };
    assert_eq!(trace.last_timestamp(), None);
}

// ─── PtmDecoder ───────────────────────────────────────────────────────────

#[test]
fn ptm_decoder_default_equals_new() {
    let d = PtmDecoder::default();
    assert!(matches!(d.config.version, EtmVersion::Ptm));
    assert_eq!(d.atom_queue.len(), 0);
}

#[test]
fn ptm_decoder_cycle_count() {
    let mut d = PtmDecoder::new();
    d.feed(&[0x12]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::CycleCount(1));
}

#[test]
fn ptm_decoder_branch_taken_queued() {
    let mut d = PtmDecoder::new();
    // bit0=1 (branch), bit1=1 (taken) → 0x03
    d.feed(&[0x03, 0x01]); // taken, then not-taken
    let _ = d.next_packet();
    let _ = d.next_packet();
    assert_eq!(d.next_atom(), Some(true));
    assert_eq!(d.next_atom(), Some(false));
    assert_eq!(d.next_atom(), None);
}

#[test]
fn ptm_decoder_async_byte() {
    let mut d = PtmDecoder::new();
    d.feed(&[0x00]);
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Sync);
}

// ─── Etm3Decoder ──────────────────────────────────────────────────────────

#[test]
fn etm3_default_branch_packet() {
    let mut d = Etm3Decoder::default();
    // bit0=1 → branch; bit2=1 (0x04) → taken. So 0x05 is taken branch.
    d.feed(&[0x05]);
    // NOTE: 0x05 also matches the explicit 0x05 arm above, which yields TraceOn.
    // Source: 0x05 => TraceOn, so this is TraceOn.
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::TraceOn);
}

#[test]
fn etm3_p_header_range() {
    let mut d = Etm3Decoder::new();
    d.feed(&[0x14]); // in 0x10..=0x1F, taken bit = (0x14 & 0x04) != 0 → true
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Atom { taken: true, count: 1 });
}

#[test]
fn etm3_unknown_byte() {
    let mut d = Etm3Decoder::new();
    d.feed(&[0xC0]); // bit0=0, not 0x05/0x08, not 0x10..=0x1F → overflow
    let p = d.next_packet().unwrap();
    assert_eq!(p.kind, CsPacketKind::Overflow);
}

// ─── EteDecoder ───────────────────────────────────────────────────────────

#[test]
fn ete_default_decode_all() {
    let mut d = EteDecoder::default();
    d.feed(&[0x01, 0x05]);
    let pkts = d.decode_all();
    assert_eq!(pkts.len(), 2);
}

// ─── CoreSightSynchronization ─────────────────────────────────────────────

#[test]
fn coresight_sync_short_buffer() {
    assert!(CoreSightSynchronization::find_sync_offsets(&[0; 5]).is_empty());
    assert!(!CoreSightSynchronization::is_valid_stream(&[0; 5]));
}

#[test]
fn coresight_sync_valid_stream() {
    let mut data = vec![1, 2, 3];
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    assert!(CoreSightSynchronization::is_valid_stream(&data));
}

#[test]
fn coresight_sync_multiple_offsets() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    data.extend_from_slice(&[0xAA; 5]);
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    let offs = CoreSightSynchronization::find_sync_offsets(&data);
    assert_eq!(offs.len(), 2);
    assert_eq!(offs[0], 0);
    assert_eq!(offs[1], 17);
}

#[test]
fn coresight_sync_no_pattern() {
    let data = vec![0xFFu8; 100];
    assert!(CoreSightSynchronization::find_sync_offsets(&data).is_empty());
    assert!(!CoreSightSynchronization::is_valid_stream(&data));
}

// ─── CoreSightTracePort ───────────────────────────────────────────────────

#[test]
fn trace_port_tpiu() {
    let p = CoreSightTracePort::new_tpiu(8, 100_000_000);
    assert!(matches!(p.mode, TracePortMode::Tpiu));
    assert_eq!(p.width, 8);
    assert_eq!(p.frequency_hz, 100_000_000);
    assert!(!p.ddr);
}

// ─── EmbeddedTraceBuffer ──────────────────────────────────────────────────

#[test]
fn etb_simple_write_no_wrap() {
    let mut etb = EmbeddedTraceBuffer::new(100);
    etb.write(&[1, 2, 3]);
    assert_eq!(etb.stored_bytes(), 3);
    assert!(!etb.wrapped);
    assert!(!etb.is_full());
    assert_eq!(etb.read_all(), &[1, 2, 3]);
}

#[test]
fn etb_exact_fill_is_full() {
    let mut etb = EmbeddedTraceBuffer::new(4);
    etb.write(&[1, 2, 3, 4]);
    assert!(etb.is_full());
    assert!(!etb.wrapped);
}

#[test]
fn etb_advance_read_clamps() {
    let mut etb = EmbeddedTraceBuffer::new(10);
    etb.write(&[1, 2, 3, 4]);
    etb.advance_read(100);
    assert_eq!(etb.read_bytes(10).len(), 0);
}

#[test]
fn etb_read_bytes_partial() {
    let mut etb = EmbeddedTraceBuffer::new(10);
    etb.write(&[10, 20, 30, 40]);
    assert_eq!(etb.read_bytes(2), &[10, 20]);
    etb.advance_read(2);
    assert_eq!(etb.read_bytes(10), &[30, 40]);
}

#[test]
fn etb_empty_capacity_always_wraps_on_write() {
    let mut etb = EmbeddedTraceBuffer::new(0);
    etb.write(&[1, 2, 3]);
    // Cap is 0, overflow = data.len() - 0 = 3 → drain all → wrapped=true.
    assert!(etb.wrapped);
    assert_eq!(etb.stored_bytes(), 0);
}

// ─── TraceMemoryInterface ─────────────────────────────────────────────────

#[test]
fn tmi_receive_accumulates() {
    let mut tmi = TraceMemoryInterface::new(0x1000, 0x100);
    tmi.receive(&[1, 2]);
    tmi.receive(&[3, 4]);
    assert_eq!(tmi.data.len(), 4);
    assert_eq!(tmi.write_ptr, 0x1004);
}

#[test]
fn tmi_drain_resets_read_ptr() {
    let mut tmi = TraceMemoryInterface::new(0, 100);
    tmi.receive(&[5, 6, 7]);
    let d = tmi.drain();
    assert_eq!(d, vec![5, 6, 7]);
    assert!(!tmi.has_data());
    assert_eq!(tmi.read_ptr, tmi.write_ptr);
}

#[test]
fn tmi_no_data_initially() {
    let tmi = TraceMemoryInterface::new(0x2000, 100);
    assert!(!tmi.has_data());
}

// ─── RomTable ─────────────────────────────────────────────────────────────

#[test]
fn rom_table_parse_zero_terminates() {
    let mut rt = RomTable::new(0xE000_0000);
    // Entry valid (bit0=1), offset=0x1000 (bit 12+), then zero entry.
    let regs = [0x0000_1001u32, 0x0000_2001, 0x0000_0000, 0x0000_3001];
    let pidrs = [0x9A0u16, 0x906, 0, 0];
    rt.parse_entries(0xE000_0000, &regs, &pidrs);
    assert_eq!(rt.entry_count(), 2);
    assert_eq!(rt.entries[0].base_addr, 0xE000_1000);
    assert_eq!(rt.entries[0].part_number, 0x9A0);
    assert!(rt.entries[0].is_etm());
    assert!(rt.entries[1].is_cti());
}

#[test]
fn rom_table_skip_not_present() {
    let mut rt = RomTable::new(0);
    let regs = [0x0000_1000u32, 0x0000_2001]; // first reg has bit0=0 → not present, but reg != 0 → continue
    let pidrs = [0u16, 0x9A0];
    rt.parse_entries(0, &regs, &pidrs);
    // First was not present (bit0=0) → skipped; second is present.
    assert_eq!(rt.entry_count(), 1);
    assert_eq!(rt.entries[0].part_number, 0x9A0);
}

#[test]
fn rom_table_negative_offset() {
    let mut rt = RomTable::new(0x1_0000);
    // 0xFFFF_F001 = present, offset bits = 0xFFFF_F000 (sign-extended as i32 → -0x1000)
    let regs = [0xFFFF_F001u32];
    let pidrs = [0u16];
    rt.parse_entries(0x1_0000, &regs, &pidrs);
    assert_eq!(rt.entry_count(), 1);
    assert_eq!(rt.entries[0].base_addr, 0xF000);
}

#[test]
fn rom_table_etm_entries_filter() {
    let mut rt = RomTable::new(0);
    rt.entries.push(RomTableEntry::new(0x1000, 9, 0x9A0));
    rt.entries.push(RomTableEntry::new(0x2000, 9, 0x1234));
    rt.entries.push(RomTableEntry::new(0x3000, 9, 0x9D0));
    assert_eq!(rt.etm_entries().len(), 2);
}

#[test]
fn rom_table_short_pidr_defaults_to_zero() {
    let mut rt = RomTable::new(0);
    let regs = [0x0000_1001u32];
    let pidrs: [u16; 0] = [];
    rt.parse_entries(0, &regs, &pidrs);
    assert_eq!(rt.entries[0].part_number, 0);
}

// ─── CoreSightTopology ────────────────────────────────────────────────────

#[test]
fn topology_counts_cti_and_etm_separately() {
    let mut t = CoreSightTopology::new();
    t.add_component(RomTableEntry::new(0x1, 9, 0x9A0)); // ETM
    t.add_component(RomTableEntry::new(0x2, 9, 0x906)); // CTI
    t.add_component(RomTableEntry::new(0x3, 9, 0x9D0)); // ETM
    assert_eq!(t.etm_count, 2);
    assert_eq!(t.cti_count, 1);
    assert_eq!(t.component_addresses(), vec![1, 2, 3]);
}

#[test]
fn topology_default_matches_new() {
    let t = CoreSightTopology::default();
    assert_eq!(t.etm_count, 0);
    assert_eq!(t.cti_count, 0);
    assert!(!t.has_funnel);
    assert!(!t.has_etf);
}

// ─── EtmConfiguration / TraceFilter ───────────────────────────────────────

#[test]
fn etm_configuration_default_passes_all() {
    let cfg = EtmConfiguration::default_all();
    assert!(cfg.passes(0xDEAD, ExceptionLevel::El0, false));
    assert!(cfg.passes(0xDEAD, ExceptionLevel::El3, true));
}

#[test]
fn etm_configuration_secure_only_blocks_nonsecure() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.filters.secure_only = true;
    assert!(!cfg.passes(0, ExceptionLevel::El0, false));
    assert!(cfg.passes(0, ExceptionLevel::El0, true));
}

#[test]
fn etm_configuration_non_secure_only_blocks_secure() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.filters.non_secure_only = true;
    assert!(cfg.passes(0, ExceptionLevel::El0, false));
    assert!(!cfg.passes(0, ExceptionLevel::El0, true));
}

#[test]
fn etm_configuration_el_filter() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.el_filter = Some(ExceptionLevel::El1);
    assert!(cfg.passes(0, ExceptionLevel::El1, false));
    assert!(!cfg.passes(0, ExceptionLevel::El0, false));
}

#[test]
fn etm_configuration_range_endpoints() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.add_range(0x1000, 0x2000);
    assert!(cfg.passes(0x1000, ExceptionLevel::El0, false));
    assert!(!cfg.passes(0x2000, ExceptionLevel::El0, false)); // exclusive end
    assert!(cfg.passes(0x1FFF, ExceptionLevel::El0, false));
}

#[test]
fn trace_filter_constructors() {
    assert!(TraceFilter::pass_all().passes_addr(0xDEAD));
    let f = TraceFilter::el0_only();
    assert_eq!(f.el_filter, Some(ExceptionLevel::El0));
    let f2 = TraceFilter::non_secure();
    assert!(f2.non_secure_only);
}

#[test]
fn trace_filter_addr_range_endpoints() {
    let mut f = TraceFilter::pass_all();
    f.addr_range = Some((100, 200));
    assert!(f.passes_addr(100));
    assert!(!f.passes_addr(200));
    assert!(!f.passes_addr(50));
}

// ─── IsochronousBranchTrace ───────────────────────────────────────────────

#[test]
fn ibt_default_empty() {
    let bt = IsochronousBranchTrace::default();
    assert!(bt.branches.is_empty());
    assert_eq!(bt.last_addr, 0);
    assert!(bt.taken_branches().is_empty());
    assert!(bt.unique_sources().is_empty());
}

#[test]
fn ibt_unique_sources_dedups() {
    let mut bt = IsochronousBranchTrace::new();
    bt.record(0x1000, 0x2000, true, 1);
    bt.record(0x1000, 0x3000, true, 2);
    bt.record(0x2000, 0x4000, false, 3);
    assert_eq!(bt.unique_sources().len(), 2);
}

// ─── FullExecutionTrace ───────────────────────────────────────────────────

#[test]
fn fet_default_empty() {
    let f = FullExecutionTrace::default();
    assert_eq!(f.instruction_count(), 0);
}

#[test]
fn fet_step_backward_at_zero_none() {
    let mut f = FullExecutionTrace::new();
    f.record_instruction(0x1000);
    assert_eq!(f.step_backward(), None);
}

#[test]
fn fet_seek_valid_and_invalid() {
    let mut f = FullExecutionTrace::new();
    f.record_instruction(0x1000);
    f.record_instruction(0x2000);
    assert!(f.seek(2));
    assert!(!f.seek(3));
    assert!(f.seek(0));
}

#[test]
fn fet_records_returns_and_exceptions() {
    let mut f = FullExecutionTrace::new();
    f.record_return(0x1000, 0x100);
    f.record_exception(0x2000, ExceptionType::Irq);
    assert_eq!(f.returns.len(), 1);
    assert_eq!(f.exceptions.len(), 1);
    assert_eq!(f.exceptions[0].1, ExceptionType::Irq);
}

#[test]
fn fet_coverage_dedups() {
    let mut f = FullExecutionTrace::new();
    f.record_instruction(0x1000);
    f.record_instruction(0x1000);
    f.record_instruction(0x2000);
    assert_eq!(f.coverage().len(), 2);
}

#[test]
fn fet_step_forward_past_end() {
    let mut f = FullExecutionTrace::new();
    f.record_instruction(0x1000);
    assert_eq!(f.step_forward(), Some(0x1000));
    assert_eq!(f.step_forward(), None);
    // Cursor should not advance past end.
    assert_eq!(f.cursor, 1);
}

// ─── TraceHeatmap ─────────────────────────────────────────────────────────

#[test]
fn heatmap_empty_state() {
    let h = TraceHeatmap::new();
    assert_eq!(h.total_hits(), 0);
    assert_eq!(h.unique_count(), 0);
    assert!(h.hotspot().is_none());
    assert!(h.top_n(5).is_empty());
}

#[test]
fn heatmap_top_n_ordering() {
    let mut h = TraceHeatmap::new();
    for _ in 0..5 { h.hit(0x1000); }
    for _ in 0..10 { h.hit(0x2000); }
    h.hit(0x3000);
    let top2 = h.top_n(2);
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0], (0x2000, 10));
    assert_eq!(top2[1], (0x1000, 5));
}

#[test]
fn heatmap_top_n_more_than_unique() {
    let mut h = TraceHeatmap::new();
    h.hit(1);
    h.hit(2);
    assert_eq!(h.top_n(100).len(), 2);
}

// ─── SharedTraceIndex ─────────────────────────────────────────────────────

#[test]
fn shared_index_set_returns_previous() {
    let idx = SharedTraceIndex::new();
    assert!(idx.set_symbol(0x1000, "old").is_none());
    assert_eq!(idx.set_symbol(0x1000, "new").as_deref(), Some("old"));
}

#[test]
fn shared_index_send_sync() {
    fn req<T: Send + Sync>() {}
    req::<SharedTraceIndex>();
}

#[test]
fn shared_index_concurrent_use() {
    use std::thread;
    let idx = SharedTraceIndex::new();
    let mut handles = Vec::new();
    for i in 0..8 {
        let c = idx.clone();
        handles.push(thread::spawn(move || {
            c.set_symbol(i * 0x1000, format!("sym{i}"));
            c.cached_kind(i as u8, || format!("k{i}"));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(idx.symbol_count(), 8);
    assert_eq!(idx.cache_len(), 8);
}

// ─── CoreSightTrace ───────────────────────────────────────────────────────

#[test]
fn coresight_trace_round_trip_bytes() {
    let raw: Vec<u8> = (0..255).collect();
    let t = CoreSightTrace::from_bytes(&raw);
    assert_eq!(t.raw_packets, raw);
    assert_eq!(t.len(), 255);
}

// ─── EtmDecoder (v4) ──────────────────────────────────────────────────────

#[test]
fn etm_v4_decoder_exception_packet() {
    // 0x06 + 2 bytes type (LE u16: 0x0005) + ULEB128 pc (0x80 -> needs more)
    let mut raw = vec![0x06u8, 0x05, 0x00];
    raw.push(0x10); // ULEB128 = 16, single byte (no continuation)
    let pkts = EtmDecoder::decode_packets(&raw);
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0], EtmPacket::Exception { type_: 0x0005, pc: 16 });
}

#[test]
fn etm_v4_decoder_exception_truncated() {
    let raw = [0x06u8, 0x05];
    let pkts = EtmDecoder::decode_packets(&raw);
    assert!(pkts.is_empty());
}

#[test]
fn etm_v4_decoder_uleb128_overflow_returns_zero_ts() {
    // Use 0xFE (continuation bit set, but not FF) so try_sync doesn't eat it.
    let mut raw = vec![0x02u8];
    for _ in 0..11 { raw.push(0xFE); }
    raw.push(0x01); // terminator (no continuation), but unreached due to overflow
    let pkts = EtmDecoder::decode_packets(&raw);
    assert!(!pkts.is_empty());
    assert_eq!(pkts[0], EtmPacket::Timestamp { value: 0 });
}

#[test]
fn etm_v4_async_then_data() {
    let mut raw = vec![0xFFu8; 8];
    raw.push(0x00);
    raw.push(0x05); // TraceOff
    let pkts = EtmDecoder::decode_packets(&raw);
    assert_eq!(pkts, vec![EtmPacket::TraceOff]);
}

#[test]
fn etm_v4_partial_ff_does_not_sync() {
    // 5 FF bytes — not enough for sync; should not crash and should consume bytes.
    let raw = vec![0xFFu8; 5];
    let pkts = EtmDecoder::decode_packets(&raw);
    // No user-visible packets emitted; just ensure no panic.
    let _ = pkts;
}

// ─── TraceReconstructor ───────────────────────────────────────────────────

#[test]
fn reconstructor_thumb_step_is_2() {
    let packets = vec![
        EtmPacket::Address { addr: 0x100, isa: IsaType::Thumb },
        EtmPacket::Atom { count: 1, pattern: 0 }, // not-taken
    ];
    let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
    assert_eq!(pcs, vec![0x100, 0x102]);
}

#[test]
fn reconstructor_multiple_not_taken() {
    let packets = vec![
        EtmPacket::Address { addr: 0x1000, isa: IsaType::AArch64 },
        EtmPacket::Atom { count: 3, pattern: 0 }, // 3 not-taken
    ];
    let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
    assert_eq!(pcs, vec![0x1000, 0x1004, 0x1008, 0x100C]);
}

#[test]
fn reconstructor_taken_without_address_stalls() {
    let packets = vec![
        EtmPacket::Address { addr: 0x1000, isa: IsaType::AArch64 },
        EtmPacket::Atom { count: 1, pattern: 1 },
    ];
    let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
    // No lookahead address — atom should stall.
    assert_eq!(pcs, vec![0x1000]);
}

#[test]
fn reconstructor_ignores_unknown_packets() {
    let packets = vec![
        EtmPacket::TraceOn,
        EtmPacket::Timestamp { value: 1 },
        EtmPacket::Cycle { count: 2 },
    ];
    let pcs = TraceReconstructor::reconstruct_pcs(&packets, &[], 0);
    assert!(pcs.is_empty());
}

// ─── require_linux_aarch64 / PerfEtmCapture ───────────────────────────────

#[test]
fn require_linux_aarch64_errors_off_platform() {
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let r = require_linux_aarch64();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("AArch64"));
    }
}

#[test]
fn perf_etm_stop_off_platform() {
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let r = PerfEtmCapture::start(1, EtmCaptureConfig::default());
        assert!(r.is_err());
    }
}

// ─── CsError ──────────────────────────────────────────────────────────────

#[test]
fn cs_error_variants_display() {
    assert!(CsError::SyncLost(0xAB).to_string().contains("ab"));
    assert!(CsError::UnsupportedIsa("foo".into()).to_string().contains("foo"));
    assert!(CsError::RomTable("bad".into()).to_string().contains("bad"));
    assert!(CsError::DataTrace("err".into()).to_string().contains("err"));
}

// ─── EtmPacket Atom display ───────────────────────────────────────────────

#[test]
fn etm_packet_atom_display_contains_count() {
    let p = EtmPacket::Atom { count: 3, pattern: 0b101 };
    let s = p.to_string();
    assert!(s.contains("count=3"));
}

// ─── Serialization round-trip via Debug as a smoke check ──────────────────

#[test]
fn debug_impls_smoke() {
    let _ = format!("{:?}", CsError::TruncatedBuffer);
    let _ = format!("{:?}", EtmContext::default());
    let _ = format!("{:?}", AtomPacket::new(1, 1, 0));
    let _ = format!("{:?}", DataTracePacket::new(0, 4, false, 0));
    let _ = format!("{:?}", EtmAddressUpdate::full(0));
}
