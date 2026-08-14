//! blitz2: deep adversarial coverage for rustre-trace-coresight public API.

use rustre_trace_coresight::*;
use std::collections::HashSet;

// ─── seeded LCG ──────────────────────────────────────────────────────────────

struct Lcg {
    s: u64,
}
impl Lcg {
    fn new() -> Self {
        Self {
            s: 0xDEAD_BEEF_CAFE_BABE,
        }
    }
    fn next(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.s
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

// ─── ExceptionType: full table + round-trip ──────────────────────────────────

#[test]
fn test_exception_type_full_field_mapping() {
    let pairs: &[(u8, ExceptionType)] = &[
        (0, ExceptionType::Reset),
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
    for (v, e) in pairs {
        assert_eq!(ExceptionType::from_etm_field(*v), *e);
    }
    // any value above 10 → Unknown
    for v in 11u8..=255 {
        assert_eq!(ExceptionType::from_etm_field(v), ExceptionType::Unknown);
    }
}

#[test]
fn test_exception_type_display_all() {
    for v in 0u8..=255 {
        let e = ExceptionType::from_etm_field(v);
        // Display must never panic, must produce non-empty string.
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

#[test]
fn test_exception_type_hash_eq_consistency() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    for v in 0u8..=20 {
        let e = ExceptionType::from_etm_field(v);
        *m.entry(e).or_insert(0u32) += 1;
    }
    // We saw values 0..=20, so 11 distinct named variants + Unknown.
    assert_eq!(m.len(), 12);
}

// ─── ExceptionLevel ──────────────────────────────────────────────────────────

#[test]
fn test_exception_level_bits_round_trip() {
    for b in 0u8..=255 {
        let el = ExceptionLevel::from_bits(b);
        // level() must equal (b & 3)
        assert_eq!(el.level(), b & 0b11);
    }
}

#[test]
fn test_exception_level_display_consistency() {
    assert_eq!(ExceptionLevel::El0.to_string(), "EL0");
    assert_eq!(ExceptionLevel::El1.to_string(), "EL1");
    assert_eq!(ExceptionLevel::El2.to_string(), "EL2");
    assert_eq!(ExceptionLevel::El3.to_string(), "EL3");
}

// ─── IsaMode / SecurityState ─────────────────────────────────────────────────

#[test]
fn test_isa_mode_display_all() {
    for m in [
        IsaMode::Aarch64,
        IsaMode::Arm,
        IsaMode::Thumb,
        IsaMode::Thumb16,
        IsaMode::Jazelle,
    ] {
        assert!(!m.to_string().is_empty());
    }
}

#[test]
fn test_security_state_display_all() {
    assert_eq!(SecurityState::Secure.to_string(), "S");
    assert_eq!(SecurityState::NonSecure.to_string(), "NS");
}

// ─── EtmTimestamp delta ──────────────────────────────────────────────────────

#[test]
fn test_etm_timestamp_delta_wrap() {
    let a = EtmTimestamp::new(5);
    let b = EtmTimestamp::new(10);
    assert_eq!(b.delta_from(a), 5);
    // wrap-around
    let lo = EtmTimestamp::new(2);
    let hi = EtmTimestamp::new(u64::MAX);
    assert_eq!(lo.delta_from(hi), 3); // 2 - MAX wraps to 3
}

#[test]
fn test_etm_timestamp_display() {
    let t = EtmTimestamp::new(42);
    assert_eq!(t.to_string(), "ts:42");
}

#[test]
fn test_etm_timestamp_ordering() {
    let a = EtmTimestamp::new(1);
    let b = EtmTimestamp::new(2);
    assert!(a < b);
    assert!(a != b);
}

// ─── AtomPacket ──────────────────────────────────────────────────────────────

#[test]
fn test_atom_packet_out_of_range_returns_false() {
    let p = AtomPacket::new(0xFFFF_FFFF, 5, 0);
    // indices >= count → false even though en_bits has them set
    assert!(p.is_taken(0));
    assert!(p.is_taken(4));
    assert!(!p.is_taken(5));
    assert!(!p.is_taken(255));
}

#[test]
fn test_atom_packet_to_vec_length_matches_count() {
    for count in 0u8..=20 {
        let p = AtomPacket::new(0xA5A5_A5A5, count, 0);
        assert_eq!(p.to_vec().len(), count as usize);
    }
}

// ─── EtmContext mutation ─────────────────────────────────────────────────────

#[test]
fn test_etm_context_advance_only_when_addr_valid() {
    let mut ctx = EtmContext::default();
    // not valid → no change
    ctx.advance(4);
    assert_eq!(ctx.current_addr, 0);
    assert!(!ctx.addr_valid);
    ctx.apply_address(0x1000);
    ctx.advance(4);
    assert_eq!(ctx.current_addr, 0x1004);
    // wrap
    ctx.apply_address(u64::MAX);
    ctx.advance(2);
    assert_eq!(ctx.current_addr, 1);
}

#[test]
fn test_etm_context_apply_context_ns_and_secure() {
    let mut ctx = EtmContext::new_aarch64();
    ctx.apply_context(ExceptionLevel::El2, true);
    assert_eq!(ctx.el, ExceptionLevel::El2);
    assert_eq!(ctx.security, SecurityState::NonSecure);
    ctx.apply_context(ExceptionLevel::El3, false);
    assert_eq!(ctx.security, SecurityState::Secure);
}

// ─── EtmConfig builder ───────────────────────────────────────────────────────

#[test]
fn test_etm_config_builders() {
    let c = EtmConfig::new(EtmVersion::Ete, "arm64")
        .with_data_trace()
        .with_cycle_count();
    assert!(c.data_trace_enabled);
    assert!(c.cycle_counting);
    assert_eq!(c.arch, "arm64");
}

// ─── EtmAddressUpdate ────────────────────────────────────────────────────────

#[test]
fn test_etm_address_update_partial_and_full() {
    let f = EtmAddressUpdate::full(0xAA_BB_CC_DD);
    assert!(f.is_full);
    assert_eq!(f.bytes_valid, 8);
    let p = EtmAddressUpdate::partial(0x1234, 2);
    assert!(!p.is_full);
    assert_eq!(p.bytes_valid, 2);
    assert!(p.el_hint.is_none());
}

// ─── CsDecoder: fuzz never panics ────────────────────────────────────────────

#[test]
fn test_cs_decoder_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 256) as usize;
        let buf = g.bytes(len);
        let mut dec = CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
        dec.feed(&buf);
        let _ = dec.decode_all();
    }
}

#[test]
fn test_coresight_decoder_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 300) as usize;
        let buf = g.bytes(len);
        let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
        dec.feed(&buf);
        let _ = dec.decode_all();
    }
}

#[test]
fn test_etm_decoder_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 300) as usize;
        let buf = g.bytes(len);
        let _ = EtmDecoder::decode_packets(&buf);
    }
}

#[test]
fn test_ptm_decoder_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 256) as usize;
        let buf = g.bytes(len);
        let mut dec = PtmDecoder::new();
        dec.feed(&buf);
        while dec.next_packet().is_some() {}
    }
}

#[test]
fn test_etm3_decoder_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 256) as usize;
        let buf = g.bytes(len);
        let mut dec = Etm3Decoder::new();
        dec.feed(&buf);
        while dec.next_packet().is_some() {}
    }
}

// ─── CsDecoder: truncated forms rewind ───────────────────────────────────────

#[test]
fn test_cs_decoder_truncated_timestamp_yields_none() {
    let mut dec = CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x43, 0, 0, 0]); // only 3 bytes after header instead of 8
    assert!(dec.next_packet().is_none());
    assert_eq!(dec.pos, 0);
}

#[test]
fn test_cs_decoder_truncated_address_yields_none() {
    let mut dec = CsDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x9A, 1, 2]);
    assert!(dec.next_packet().is_none());
}

// ─── CoreSightDecoder feature coverage ───────────────────────────────────────

#[test]
fn test_coresight_decoder_context_packet_updates_state() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    // 0x0E header, context byte: EL=2 (bits >>1 & 3 = 2 → ctx_byte=0b100=4), ns=0
    dec.feed(&[0x0E, 0b0000_0100]);
    let pkt = dec.next_packet().unwrap();
    if let CsPacketKind::Context { el, ns } = pkt.kind {
        assert_eq!(el, Some(ExceptionLevel::El2));
        assert!(!ns);
    } else {
        panic!("expected Context");
    }
    assert_eq!(dec.context.el, ExceptionLevel::El2);
}

#[test]
fn test_coresight_decoder_context_id_4byte() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x50, 0x78, 0x56, 0x34, 0x12]);
    let pkt = dec.next_packet().unwrap();
    assert_eq!(pkt.kind, CsPacketKind::ContextId(0x1234_5678));
    assert_eq!(dec.context.context_id, 0x1234_5678);
}

#[test]
fn test_coresight_decoder_vmid_4byte() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x51, 0xEF, 0xBE, 0xAD, 0xDE]);
    let pkt = dec.next_packet().unwrap();
    assert_eq!(pkt.kind, CsPacketKind::VmId(0xDEAD_BEEF));
}

#[test]
fn test_coresight_decoder_indirect_branch() {
    let target: u64 = 0xABCD_1234_5678_9ABC;
    let mut data = vec![0xAA];
    data.extend_from_slice(&target.to_le_bytes());
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&data);
    let pkt = dec.next_packet().unwrap();
    assert_eq!(pkt.kind, CsPacketKind::IndirectBranch { target });
}

#[test]
fn test_coresight_decoder_truncated_context_rewinds() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x0E]); // missing context byte
    assert!(dec.next_packet().is_none());
    assert_eq!(dec.position(), 0);
}

#[test]
fn test_coresight_decoder_reset_clears_state() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    dec.feed(&[0x05]); // TraceOn
    let _ = dec.next_packet();
    assert!(dec.is_synchronized());
    dec.reset();
    assert!(!dec.is_synchronized());
    assert_eq!(dec.position(), 0);
}

#[test]
fn test_coresight_decoder_cycle_count_accumulates() {
    let mut dec = CoreSightDecoder::new(EtmConfig::new(EtmVersion::Etm4, "arm64"));
    // 0x0D + ULEB128 5
    dec.feed(&[0x0D, 5, 0x0D, 7]);
    let _ = dec.next_packet();
    let _ = dec.next_packet();
    assert_eq!(dec.context.cycle_count, 12);
}

// ─── CoreSightSynchronization ────────────────────────────────────────────────

#[test]
fn test_sync_offsets_short_input() {
    assert!(CoreSightSynchronization::find_sync_offsets(&[]).is_empty());
    assert!(CoreSightSynchronization::find_sync_offsets(&[0u8; 11]).is_empty());
    assert!(!CoreSightSynchronization::is_valid_stream(&[0u8; 11]));
}

#[test]
fn test_sync_offsets_multiple_hits() {
    let mut data: Vec<u8> = vec![0xAA];
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    data.push(0xBB);
    data.extend_from_slice(&[0u8; 11]);
    data.push(0x80);
    let offs = CoreSightSynchronization::find_sync_offsets(&data);
    assert_eq!(offs.len(), 2);
    assert!(CoreSightSynchronization::is_valid_stream(&data));
}

#[test]
fn test_sync_fuzz_no_panic() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 300) as usize;
        let buf = g.bytes(len);
        let _ = CoreSightSynchronization::find_sync_offsets(&buf);
        let _ = CoreSightSynchronization::is_valid_stream(&buf);
    }
}

// ─── RomTable ────────────────────────────────────────────────────────────────

#[test]
fn test_rom_table_parse_empty_terminator() {
    let mut t = RomTable::new(0x8000_0000);
    t.parse_entries(0x8000_0000, &[0x0000_1001, 0, 0x0000_2001], &[0x9A0, 0, 0x950]);
    // The 0 terminator must stop parsing.
    assert_eq!(t.entry_count(), 1);
}

#[test]
fn test_rom_table_negative_offset() {
    let mut t = RomTable::new(0x8000_0000);
    // 0xFFFF_F001 means offset = 0xFFFF_F000 (sign-extended to -0x1000), present=1
    t.parse_entries(0x8000_0000, &[0xFFFF_F001], &[0x9A0]);
    assert_eq!(t.entry_count(), 1);
    assert_eq!(t.entries[0].base_addr, 0x7FFF_F000);
}

#[test]
fn test_rom_table_part_number_zero_when_short_pidr() {
    let mut t = RomTable::new(0);
    t.parse_entries(0, &[0x0000_1001], &[]); // pidr missing
    assert_eq!(t.entries[0].part_number, 0);
}

#[test]
fn test_rom_table_etm_filter() {
    let mut t = RomTable::new(0);
    t.parse_entries(0, &[0x1001, 0x2001, 0x3001], &[0x9A0, 0x1234, 0x950]);
    assert_eq!(t.etm_entries().len(), 2);
}

#[test]
fn test_rom_table_entry_is_etm_known_parts() {
    for p in [0x9A0, 0x9D0, 0x950, 0x955, 0x95A, 0x95B, 0x95D, 0x95F] {
        assert!(RomTableEntry::new(0, 9, p).is_etm());
    }
    assert!(!RomTableEntry::new(0, 9, 0x000).is_etm());
}

#[test]
fn test_rom_table_entry_is_cti_known_parts() {
    assert!(RomTableEntry::new(0, 9, 0x906).is_cti());
    assert!(RomTableEntry::new(0, 9, 0x9EE).is_cti());
    assert!(!RomTableEntry::new(0, 9, 0x123).is_cti());
}

// ─── CoreSightTopology ───────────────────────────────────────────────────────

#[test]
fn test_topology_counts_separately() {
    let mut t = CoreSightTopology::new();
    t.add_component(RomTableEntry::new(0, 9, 0x9A0));
    t.add_component(RomTableEntry::new(1, 9, 0x906));
    t.add_component(RomTableEntry::new(2, 9, 0xDEAD));
    assert_eq!(t.etm_count, 1);
    assert_eq!(t.cti_count, 1);
    assert_eq!(t.component_addresses(), vec![0, 1, 2]);
}

#[test]
fn test_topology_default_eq_new() {
    let a = CoreSightTopology::new();
    let b = CoreSightTopology::default();
    assert_eq!(a.etm_count, b.etm_count);
    assert_eq!(a.cti_count, b.cti_count);
}

// ─── EtmConfiguration filter ─────────────────────────────────────────────────

#[test]
fn test_etm_configuration_security_filters() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.filters.secure_only = true;
    assert!(cfg.passes(0x100, ExceptionLevel::El0, true));
    assert!(!cfg.passes(0x100, ExceptionLevel::El0, false));
    let mut cfg2 = EtmConfiguration::default_all();
    cfg2.filters.non_secure_only = true;
    assert!(!cfg2.passes(0x100, ExceptionLevel::El0, true));
    assert!(cfg2.passes(0x100, ExceptionLevel::El0, false));
}

#[test]
fn test_etm_configuration_el_filter() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.el_filter = Some(ExceptionLevel::El1);
    assert!(cfg.passes(0x10, ExceptionLevel::El1, false));
    assert!(!cfg.passes(0x10, ExceptionLevel::El0, false));
}

#[test]
fn test_etm_configuration_range_boundaries() {
    let mut cfg = EtmConfiguration::default_all();
    cfg.add_range(0x1000, 0x2000);
    // [start, end) — start inclusive, end exclusive
    assert!(cfg.passes(0x1000, ExceptionLevel::El0, false));
    assert!(cfg.passes(0x1FFF, ExceptionLevel::El0, false));
    assert!(!cfg.passes(0x2000, ExceptionLevel::El0, false));
    assert!(!cfg.passes(0x0FFF, ExceptionLevel::El0, false));
}

// ─── TraceFilter ─────────────────────────────────────────────────────────────

#[test]
fn test_trace_filter_constructors() {
    let p = TraceFilter::pass_all();
    assert!(p.passes_addr(0));
    assert!(p.passes_addr(u64::MAX));
    let e = TraceFilter::el0_only();
    assert_eq!(e.el_filter, Some(ExceptionLevel::El0));
    let ns = TraceFilter::non_secure();
    assert!(ns.non_secure_only);
}

#[test]
fn test_trace_filter_addr_range_bounds() {
    let mut f = TraceFilter::pass_all();
    f.addr_range = Some((10, 20));
    assert!(f.passes_addr(10));
    assert!(f.passes_addr(19));
    assert!(!f.passes_addr(20));
    assert!(!f.passes_addr(9));
}

// ─── EmbeddedTraceBuffer ─────────────────────────────────────────────────────

#[test]
fn test_etb_no_wrap_under_capacity() {
    let mut etb = EmbeddedTraceBuffer::new(100);
    etb.write(&[1, 2, 3]);
    assert!(!etb.wrapped);
    assert_eq!(etb.stored_bytes(), 3);
    assert!(!etb.is_full());
}

#[test]
fn test_etb_read_advance() {
    let mut etb = EmbeddedTraceBuffer::new(16);
    etb.write(&[1, 2, 3, 4, 5]);
    assert_eq!(etb.read_bytes(3), &[1, 2, 3]);
    etb.advance_read(3);
    assert_eq!(etb.read_bytes(10), &[4, 5]);
}

#[test]
fn test_etb_is_full_after_exact_fill() {
    let mut etb = EmbeddedTraceBuffer::new(4);
    etb.write(&[1, 2, 3, 4]);
    assert!(etb.is_full());
    assert!(!etb.wrapped);
}

#[test]
fn test_etb_advance_clamps() {
    let mut etb = EmbeddedTraceBuffer::new(16);
    etb.write(&[1, 2, 3]);
    etb.advance_read(99);
    assert_eq!(etb.read_bytes(10), &[] as &[u8]);
}

// ─── TraceMemoryInterface ────────────────────────────────────────────────────

#[test]
fn test_tmi_receive_updates_write_ptr() {
    let mut tmi = TraceMemoryInterface::new(0x1_0000, 0x1000);
    tmi.receive(&[1, 2, 3]);
    assert_eq!(tmi.write_ptr, 0x1_0000 + 3);
    assert!(tmi.has_data());
    let d = tmi.drain();
    assert_eq!(d, vec![1, 2, 3]);
    assert!(!tmi.has_data());
}

// ─── EtmTrace summary ────────────────────────────────────────────────────────

#[test]
fn test_etm_trace_summaries() {
    let cfg = EtmConfig::new(EtmVersion::Etm4, "arm64");
    let pkts = vec![
        CsPacket {
            kind: CsPacketKind::Atom {
                taken: true,
                count: 1,
            },
            byte_offset: 0,
        },
        CsPacket {
            kind: CsPacketKind::Atom {
                taken: false,
                count: 1,
            },
            byte_offset: 1,
        },
        CsPacket {
            kind: CsPacketKind::Atom {
                taken: true,
                count: 1,
            },
            byte_offset: 2,
        },
        CsPacket {
            kind: CsPacketKind::Timestamp(7),
            byte_offset: 3,
        },
        CsPacket {
            kind: CsPacketKind::Timestamp(11),
            byte_offset: 4,
        },
        CsPacket {
            kind: CsPacketKind::Exception { exc_type: 5 },
            byte_offset: 5,
        },
    ];
    let trace = EtmTrace { packets: pkts, config: cfg };
    assert_eq!(trace.taken_atoms(), 2);
    assert_eq!(trace.not_taken_atoms(), 1);
    assert_eq!(trace.atom_count(), 3);
    assert_eq!(trace.exception_count(), 1);
    assert_eq!(trace.last_timestamp(), Some(11));
}

// ─── FullExecutionTrace ──────────────────────────────────────────────────────

#[test]
fn test_full_execution_trace_seek_and_bounds() {
    let mut fet = FullExecutionTrace::new();
    fet.record_instruction(0x10);
    fet.record_instruction(0x20);
    fet.record_instruction(0x30);
    assert!(fet.seek(2));
    assert_eq!(fet.step_forward(), Some(0x30));
    assert_eq!(fet.step_forward(), None);
    assert!(fet.seek(3)); // pos == len is allowed
    assert!(!fet.seek(4)); // > len rejected
    fet.seek(0);
    assert!(fet.step_backward().is_none());
}

#[test]
fn test_full_execution_trace_coverage() {
    let mut fet = FullExecutionTrace::new();
    fet.record_instruction(1);
    fet.record_instruction(1);
    fet.record_instruction(2);
    fet.record_call(2, 100);
    fet.record_return(100, 3);
    fet.record_exception(3, ExceptionType::Irq);
    assert_eq!(fet.coverage().len(), 2);
    assert_eq!(fet.calls.len(), 1);
    assert_eq!(fet.returns.len(), 1);
    assert_eq!(fet.exceptions.len(), 1);
}

// ─── TraceHeatmap ────────────────────────────────────────────────────────────

#[test]
fn test_heatmap_top_n_ordering() {
    let mut hm = TraceHeatmap::new();
    for _ in 0..5 {
        hm.hit(0xA);
    }
    for _ in 0..2 {
        hm.hit(0xB);
    }
    hm.hit(0xC);
    let top = hm.top_n(2);
    assert_eq!(top[0], (0xA, 5));
    assert_eq!(top[1], (0xB, 2));
    assert_eq!(hm.unique_count(), 3);
    assert_eq!(hm.total_hits(), 8);
}

#[test]
fn test_heatmap_top_n_zero_and_more_than_len() {
    let mut hm = TraceHeatmap::new();
    hm.hit(1);
    assert!(hm.top_n(0).is_empty());
    assert_eq!(hm.top_n(10).len(), 1);
}

#[test]
fn test_heatmap_empty_hotspot() {
    let hm = TraceHeatmap::new();
    assert!(hm.hotspot().is_none());
}

// ─── IsochronousBranchTrace ──────────────────────────────────────────────────

#[test]
fn test_branch_trace_unique_sources_preserves_first_seen() {
    let mut bt = IsochronousBranchTrace::new();
    bt.record(1, 10, true, 0);
    bt.record(2, 20, false, 1);
    bt.record(1, 11, true, 2);
    let u = bt.unique_sources();
    assert_eq!(u, vec![1, 2]);
    assert_eq!(bt.last_addr, 11);
}

// ─── PtmDecoder / Etm3Decoder ────────────────────────────────────────────────

#[test]
fn test_ptm_decoder_branch_taken_bit() {
    let mut p = PtmDecoder::new();
    // header 0x03 = bit0=1 (branch), bit1=1 (taken)
    p.feed(&[0x03, 0x01]);
    let pkt1 = p.next_packet().unwrap();
    if let CsPacketKind::Atom { taken, .. } = pkt1.kind {
        assert!(taken);
    }
    let pkt2 = p.next_packet().unwrap();
    if let CsPacketKind::Atom { taken, .. } = pkt2.kind {
        // 0x01: bit0=1, bit1=0 → not taken
        assert!(!taken);
    }
    assert_eq!(p.next_atom(), Some(true));
    assert_eq!(p.next_atom(), Some(false));
    assert_eq!(p.next_atom(), None);
}

#[test]
fn test_ptm_decoder_async_zero() {
    let mut p = PtmDecoder::new();
    p.feed(&[0x00]);
    let pkt = p.next_packet().unwrap();
    assert_eq!(pkt.kind, CsPacketKind::Sync);
}

#[test]
fn test_etm3_decoder_p_header_branch() {
    let mut d = Etm3Decoder::new();
    // 0x10..0x1F: bit2 = (b & 4) -> taken
    d.feed(&[0x14, 0x10]);
    let pkt = d.next_packet().unwrap();
    if let CsPacketKind::Atom { taken, .. } = pkt.kind {
        assert!(taken);
    }
    let pkt2 = d.next_packet().unwrap();
    if let CsPacketKind::Atom { taken, .. } = pkt2.kind {
        assert!(!taken);
    }
}

// ─── EteDecoder ──────────────────────────────────────────────────────────────

#[test]
fn test_ete_decoder_decode_all_empty() {
    let mut d = EteDecoder::new();
    assert!(d.decode_all().is_empty());
}

// ─── IsaType ─────────────────────────────────────────────────────────────────

#[test]
fn test_isa_type_hash_eq_distinct() {
    let mut s = HashSet::new();
    s.insert(IsaType::ARM);
    s.insert(IsaType::Thumb);
    s.insert(IsaType::AArch64);
    s.insert(IsaType::Jazelle);
    s.insert(IsaType::ThumbEE);
    assert_eq!(s.len(), 5);
}

// ─── EtmDecoder more coverage ────────────────────────────────────────────────

#[test]
fn test_etm_decoder_exception_truncated_breaks() {
    // 0x06 with no payload bytes → loop break; nothing emitted.
    let pkts = EtmDecoder::decode_packets(&[0x06]);
    assert!(pkts.is_empty());
}

#[test]
fn test_etm_decoder_atom_f3_pattern() {
    // F3 header bits: 0b11010_EEE — try EEE = 0b101 → 0xD5
    let header = 0b1101_0101u8;
    let pkts = EtmDecoder::decode_packets(&[header]);
    assert_eq!(pkts.len(), 1);
    assert_eq!(
        pkts[0],
        EtmPacket::Atom {
            count: 3,
            pattern: 0b101
        }
    );
}

#[test]
fn test_etm_decoder_uleb128_too_long_returns_zero() {
    // 10 continuation bytes — read_uleb128 returns None, callers fall back to 0.
    let raw = vec![0x02, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
    let pkts = EtmDecoder::decode_packets(&raw);
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0], EtmPacket::Timestamp { value: 0 });
}

// ─── TraceReconstructor extra ────────────────────────────────────────────────

#[test]
fn test_trace_reconstructor_not_taken_without_address_is_noop() {
    let pkts = vec![EtmPacket::Atom {
        count: 3,
        pattern: 0,
    }];
    let out = TraceReconstructor::reconstruct_pcs(&pkts, &[], 0);
    assert!(out.is_empty()); // no current_pc → no advance
}

#[test]
fn test_trace_reconstructor_taken_no_future_address_stalls() {
    let pkts = vec![
        EtmPacket::Address {
            addr: 0x100,
            isa: IsaType::AArch64,
        },
        EtmPacket::Atom {
            count: 2,
            pattern: 0b11,
        }, // both taken, but no further Address packets
    ];
    let out = TraceReconstructor::reconstruct_pcs(&pkts, &[], 0);
    // Only the initial address appears.
    assert_eq!(out, vec![0x100]);
}

#[test]
fn test_trace_reconstructor_thumb_linear_step_is_2() {
    let pkts = vec![
        EtmPacket::Address {
            addr: 0x200,
            isa: IsaType::Thumb,
        },
        EtmPacket::Atom {
            count: 2,
            pattern: 0,
        },
    ];
    let out = TraceReconstructor::reconstruct_pcs(&pkts, &[], 0);
    assert_eq!(out, vec![0x200, 0x202, 0x204]);
}

// ─── SharedTraceIndex thread stress ──────────────────────────────────────────

#[test]
fn test_shared_index_thread_stress() {
    use std::thread;
    let idx = SharedTraceIndex::new();
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let idx = idx.clone();
            thread::spawn(move || {
                for i in 0..100u64 {
                    let addr = (t as u64) * 1000 + i;
                    idx.set_symbol(addr, format!("s_{t}_{i}"));
                    let _ = idx.resolve(addr);
                    let _ = idx.cached_kind((i as u8) ^ (t as u8), || format!("k_{i}"));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(idx.symbol_count(), 400);
}

// ─── CoreSightTrace ──────────────────────────────────────────────────────────

#[test]
fn test_coresight_trace_round_trip_bytes() {
    let bytes = vec![0u8, 1, 2, 3, 0xFF, 0x80];
    let t = CoreSightTrace::from_bytes(&bytes);
    assert_eq!(t.raw_packets, bytes);
    assert_eq!(t.len(), bytes.len());
    assert!(!t.is_empty());
}

// ─── EtmCaptureConfig ────────────────────────────────────────────────────────

#[test]
fn test_etm_capture_config_addr_filter_preserves_defaults() {
    let c = EtmCaptureConfig::with_addr_filter(0, u64::MAX);
    assert_eq!(c.addr_filter, Some((0, u64::MAX)));
    assert!(c.return_stack);
    assert!(c.flags.context_ids);
    assert!(c.timestamp);
    assert!(!c.flags.cycle_accurate);
}

// ─── require_linux_aarch64 ───────────────────────────────────────────────────

#[test]
fn test_require_linux_aarch64_errs_off_platform() {
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let r = require_linux_aarch64();
        assert!(r.is_err());
    }
}

// ─── CsError variants ────────────────────────────────────────────────────────

#[test]
fn test_cs_error_all_variants_display() {
    let errs = [
        CsError::InvalidPacket(0xAB),
        CsError::TruncatedBuffer,
        CsError::UnknownFormat("x".into()),
        CsError::SyncLost(123),
        CsError::UnsupportedIsa("y".into()),
        CsError::RomTable("z".into()),
        CsError::DataTrace("w".into()),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
    }
}

// ─── CoreSightTracePort ──────────────────────────────────────────────────────

#[test]
fn test_trace_port_tpiu() {
    let p = CoreSightTracePort::new_tpiu(16, 200_000_000);
    assert_eq!(p.width, 16);
    assert_eq!(p.frequency_hz, 200_000_000);
    assert_eq!(p.mode, TracePortMode::Tpiu);
    assert!(!p.ddr);
}
