//! Adversarial deep test suite Y086 for rustre-loader-luajit.
//!
//! Covers public API of `lib.rs`: LEB128 decoders, header/proto parsing,
//! `LjInstr` classification, KGC/KNumConst variants, `ProtoBuilder`, `BytecodeEncoder`,
//! `LjDisassembler`, `ProtoStats`, `UpvalInfo`, `LjVersion`, `LjFlags`, `DebugInfo`,
//! `VarName`, and the `LjLoader` async path.

use rustre_core::Loader;
use rustre_loader_luajit::*;

// Deterministic seeded LCG (Knuth MMIX constants).
const fn lcg_gen(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

const fn fresh_lcg() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

// ──────────────────────────────────────────────────────────────────────────────
// LEB128: never panic, exact bit patterns, overflow.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn uleb128_round_trip_50_inputs() {
    let mut s = fresh_lcg();
    for _ in 0..50 {
        let v = lcg_gen(&mut s) & 0x7FFF_FFFF; // limit to 31 bits
        // Hand-roll encode.
        let mut buf = Vec::<u8>::new();
        let mut x = v;
        loop {
            let byte = (x & 0x7F) as u8;
            x >>= 7;
            if x == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
        let (decoded, n) = read_uleb128(&buf, 0).expect("must decode");
        assert_eq!(decoded, v);
        assert_eq!(n, buf.len());
    }
}

#[test]
fn uleb128_zero_through_127_single_byte() {
    for v in 0u64..=127 {
        let (got, n) = read_uleb128(&[v as u8], 0).unwrap();
        assert_eq!(got, v);
        assert_eq!(n, 1);
    }
}

#[test]
fn uleb128_truncated_continuation_returns_none() {
    // 0x80 means "another byte follows" but the input ends.
    assert!(read_uleb128(&[0x80], 0).is_none());
    assert!(read_uleb128(&[0x80, 0x80, 0x80], 0).is_none());
}

#[test]
fn uleb128_overflow_returns_none() {
    // 11 continuation bytes - shift would exceed 64.
    let buf: [u8; 11] = [0x80; 11];
    let mut overflow = buf;
    overflow[10] = 0x01;
    // Result must not panic; either returns Some (if it fits) or None.
    // 11 bytes * 7 bits = 77 bits, so this MUST be None.
    assert!(read_uleb128(&overflow, 0).is_none());
}

#[test]
fn uleb128_fuzz_never_panics() {
    let mut s = fresh_lcg();
    for _ in 0..200 {
        let len = (lcg_gen(&mut s) % 20) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (lcg_gen(&mut s) & 0xFF) as u8).collect();
        let off = (lcg_gen(&mut s) as usize) % (bytes.len() + 1);
        let _ = read_uleb128(&bytes, off);
        let _ = read_sleb128(&bytes, off);
    }
}

#[test]
fn sleb128_signed_extension_works() {
    // 0x7F → -1 (sign bit set in low 7-bit chunk).
    assert_eq!(read_sleb128(&[0x7F], 0).unwrap().0, -1);
    // 0x40 → smallest single-byte negative = -64.
    assert_eq!(read_sleb128(&[0x40], 0).unwrap().0, -64);
    // 0x3F → +63
    assert_eq!(read_sleb128(&[0x3F], 0).unwrap().0, 63);
}

#[test]
fn sleb128_eof_is_none() {
    assert!(read_sleb128(&[], 0).is_none());
    assert!(read_sleb128(&[0x80], 0).is_none());
}

// ──────────────────────────────────────────────────────────────────────────────
// LjVersion: Display, FromByte round-trip.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn version_byte_round_trip_known() {
    assert_eq!(LjVersion::from_byte(LjVersion::Lj20.as_byte()), LjVersion::Lj20);
    assert_eq!(LjVersion::from_byte(LjVersion::Lj21.as_byte()), LjVersion::Lj21);
}

#[test]
fn version_unknown_preserves_byte() {
    for b in [0u8, 3, 99, 0xFF] {
        let v = LjVersion::from_byte(b);
        assert_eq!(v.as_byte(), b);
        assert!(!v.is_known());
    }
}

#[test]
fn version_hash_eq_consistency_30_pairs() {
    let known = [LjVersion::Lj20, LjVersion::Lj21];
    let mut s = fresh_lcg();
    for _ in 0..30 {
        let a = known[(lcg_gen(&mut s) as usize) % 2];
        let b = known[(lcg_gen(&mut s) as usize) % 2];
        // Eq is reflexive.
        assert_eq!(a, a);
        // Symmetric.
        assert_eq!(a == b, b == a);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// LjFlags / LjProtoFlags: bit flags round-trip.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn ljflags_bits_round_trip() {
    for b in 0u8..=0x0F {
        let f = LjFlags::from_bits_truncate(b);
        // Truncated bits cannot exceed defined set (0x0F).
        assert_eq!(f.bits(), b & 0x0F);
    }
}

#[test]
fn ljprotoflags_vararg_detect() {
    let f = LjProtoFlags::VARARG | LjProtoFlags::ILOOP;
    assert!(f.contains(LjProtoFlags::VARARG));
    assert!(f.contains(LjProtoFlags::ILOOP));
    assert!(!f.contains(LjProtoFlags::CHILD));
}

// ──────────────────────────────────────────────────────────────────────────────
// LjHeader: boundary truncation, magic.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn header_truncated_at_each_byte() {
    // \x1bLJ\x02 then flags ULEB128. Truncate each prefix length up to 4.
    let full: Vec<u8> = vec![0x1B, b'L', b'J', 0x02, 0x00]; // unstripped, flags=0
    for n in 0..full.len() {
        let r = LjHeader::parse(&full[..n]);
        assert!(r.is_err(), "len {n} should error");
    }
    // Full is missing the debug-name ULEB128 too (unstripped), so should error.
    let r = LjHeader::parse(&full);
    assert!(r.is_err(), "missing debug-name length should be TruncatedData");
}

#[test]
fn header_invalid_magic_variants() {
    // 5 wrong-magic patterns; ensure no panic, all yield InvalidMagic.
    let bads: Vec<&[u8]> = vec![
        b"\x00\x00\x00\x00",
        b"\x1bLU\x02",
        b"AAA\x02",
        b"\x1bL\x00\x02",
        b"LJ\x1b\x02",
    ];
    for d in bads {
        match LjHeader::parse(d) {
            Err(LjLoaderError::InvalidMagic | LjLoaderError::TruncatedData) => {}
            other => panic!("expected InvalidMagic/TruncatedData got {other:?}"),
        }
    }
}

#[test]
fn header_fuzz_no_panic() {
    let mut s = fresh_lcg();
    for _ in 0..200 {
        let len = (lcg_gen(&mut s) % 32) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (lcg_gen(&mut s) & 0xFF) as u8).collect();
        let _ = LjHeader::parse(&bytes);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// LjInstr: bit extraction and classification.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn instr_field_extraction_all_combos() {
    // For every opcode value 0..=0x60, build an instr with known A/B/C and verify.
    for op in 0u8..=0x60 {
        for a in [0u8, 1, 7, 255] {
            for b in [0u8, 1, 64, 200] {
                for c in [0u8, 1, 13, 0xFE] {
                    let word: u32 = u32::from(op)
                        | (u32::from(a) << 8)
                        | (u32::from(c) << 16)
                        | (u32::from(b) << 24);
                    let i = LjInstr(word);
                    assert_eq!(i.opcode(), op);
                    assert_eq!(i.a(), a);
                    assert_eq!(i.b(), b);
                    assert_eq!(i.c(), c);
                    let d = (u16::from(b) << 8) | u16::from(c);
                    assert_eq!(i.d(), d);
                }
            }
        }
    }
}

#[test]
fn instr_jump_offset_signed() {
    // d = 0x8000 → 0
    let i = LjInstr(0x58 | (0x80 << 24));
    assert_eq!(i.jump_offset(), 0);
    // d = 0x8001 → +1
    let i = LjInstr(0x58 | (0x01 << 16) | (0x80 << 24));
    assert_eq!(i.jump_offset(), 1);
    // d = 0x7FFF → -1
    let i = LjInstr(0x58 | (0xFF << 16) | (0x7F << 24));
    assert_eq!(i.jump_offset(), -1);
}

#[test]
fn instr_classifier_ranges_exclusive() {
    for op in 0u8..=0xFF {
        let i = LjInstr(u32::from(op));
        let call = i.is_call();
        let ret = i.is_return();
        let arith = i.is_arith();
        let upv = i.is_upvalue_op();
        let tab = i.is_table_op();
        let load = i.is_load_const();
        let cmp = i.is_compare();
        // No instruction is simultaneously call AND return AND arith.
        assert!(!(call && ret));
        assert!(!(arith && upv));
        assert!(!(tab && load));
        assert!(!(cmp && call));
    }
}

#[test]
fn instr_mnemonic_unknown_for_high_opcodes() {
    for op in 0x61u8..=0xFF {
        let i = LjInstr(u32::from(op));
        assert_eq!(i.mnemonic(), "UNK");
    }
}

#[test]
fn instr_display_contains_mnemonic() {
    let i = LjInstr(0x0000_0058); // JMP
    let s = i.to_string();
    assert!(s.contains("JMP"));
    assert!(s.contains("A="));
}

// ──────────────────────────────────────────────────────────────────────────────
// KGC and KNumConst behavior.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn kgc_kind_name_exhaustive() {
    assert_eq!(KGC::Tab.kind_name(), "tab");
    assert_eq!(KGC::I64(0).kind_name(), "i64");
    assert_eq!(KGC::U64(0).kind_name(), "u64");
    assert_eq!(KGC::Complex(0.0, 0.0).kind_name(), "complex");
    assert_eq!(KGC::String(String::new()).kind_name(), "string");
    assert_eq!(KGC::Unknown(7).kind_name(), "unknown");
    let proto = LjProto::mock();
    assert_eq!(KGC::Child(Box::new(proto)).kind_name(), "child");
}

#[test]
fn kgc_as_str_only_string_variant() {
    assert!(KGC::Tab.as_str().is_none());
    assert!(KGC::I64(1).as_str().is_none());
    assert!(KGC::U64(1).as_str().is_none());
    assert!(KGC::Complex(1.0, 0.0).as_str().is_none());
    assert!(KGC::Unknown(0).as_str().is_none());
    assert_eq!(KGC::String("x".into()).as_str(), Some("x"));
}

#[test]
fn kgc_extreme_integer_values() {
    assert!(KGC::I64(i64::MIN).to_string().contains(&i64::MIN.to_string()));
    assert!(KGC::I64(i64::MAX).to_string().contains(&i64::MAX.to_string()));
    assert!(KGC::U64(u64::MAX).to_string().contains(&u64::MAX.to_string()));
    assert!(KGC::U64(0).to_string().contains('0'));
}

#[test]
fn knumconst_extremes() {
    assert!(KNumConst::Int(i32::MIN).to_string().contains(&i32::MIN.to_string()));
    assert!(KNumConst::Int(i32::MAX).to_string().contains(&i32::MAX.to_string()));
    assert!(!KNumConst::Float(f64::NAN).to_string().is_empty());
    assert!(KNumConst::Float(f64::INFINITY).to_string().contains("inf"));
}

// ──────────────────────────────────────────────────────────────────────────────
// VarName / LjLocalVar: live-range boundaries.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn varname_boundary_off_by_ones() {
    let v = VarName { name: "v".into(), start_pc: 3, end_pc: 7 };
    assert!(!v.is_live_at(2));
    assert!(v.is_live_at(3));
    assert!(v.is_live_at(6));
    assert!(!v.is_live_at(7));
    assert!(!v.is_live_at(u32::MAX));
}

#[test]
fn varname_zero_length_never_live() {
    let v = VarName { name: "z".into(), start_pc: 10, end_pc: 10 };
    for pc in [0u32, 9, 10, 11, 100, u32::MAX] {
        assert!(!v.is_live_at(pc));
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DebugInfo.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn debug_info_default_is_empty() {
    assert!(DebugInfo::default().is_empty());
}

#[test]
fn debug_info_locals_filter() {
    let d = DebugInfo {
        local_vars: vec![
            LjLocalVar { name: "a".into(), start_pc: 0, end_pc: 5 },
            LjLocalVar { name: "b".into(), start_pc: 3, end_pc: 10 },
        ],
        ..Default::default()
    };
    assert_eq!(d.locals_at(0).len(), 1);
    assert_eq!(d.locals_at(4).len(), 2);
    assert_eq!(d.locals_at(5).len(), 1);
    assert_eq!(d.locals_at(99).len(), 0);
}

// ──────────────────────────────────────────────────────────────────────────────
// ProtoBuilder + ProtoStats.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn proto_builder_arith_counted_correctly() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_0016)) // ADDVN
        .add_instr(LjInstr(0x0000_0020)) // ADDVV
        .add_instr(LjInstr(0x0000_0042)) // CALL
        .build();
    let s = ProtoStats::compute(&p);
    assert_eq!(s.arith, 2);
    assert_eq!(s.calls, 1);
    assert_eq!(s.total, 3);
}

#[test]
fn proto_builder_loops_and_branches() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004D)) // FORI (loop & branch)
        .add_instr(LjInstr(0x0000_004F)) // FORL (loop & branch)
        .add_instr(LjInstr(0x0000_0058)) // JMP (branch, not loop)
        .build();
    let s = ProtoStats::compute(&p);
    assert_eq!(s.loop_instrs, 2);
    assert_eq!(s.branches, 3);
    assert!(p.has_loops());
}

#[test]
fn proto_builder_kn_int_stored() {
    let p = ProtoBuilder::new().add_kn_int(-7).add_kn_int(42).build();
    assert_eq!(p.kn[0], KNumConst::Int(-7));
    assert_eq!(p.kn[1], KNumConst::Int(42));
    assert_eq!(p.constants.len(), 2);
}

#[test]
fn proto_builder_source_set() {
    let p = ProtoBuilder::new().source("@a.lua").build();
    assert_eq!(p.source_name.as_deref(), Some("@a.lua"));
}

#[test]
fn proto_builder_upvalue_names_aligned() {
    let p = ProtoBuilder::new()
        .add_upvalue(0, true, Some("a".into()))
        .add_upvalue(1, false, None)
        .build();
    assert_eq!(p.upvalue_names, vec!["a".to_string(), String::new()]);
}

#[test]
fn proto_locals_at_pc_filter() {
    let mut p = ProtoBuilder::new().add_instr(LjInstr(0x4B)).build();
    p.local_vars.push(LjLocalVar { name: "x".into(), start_pc: 0, end_pc: 1 });
    p.local_vars.push(LjLocalVar { name: "y".into(), start_pc: 0, end_pc: 5 });
    assert_eq!(p.locals_at_pc(0).len(), 2);
    assert_eq!(p.locals_at_pc(1).len(), 1);
    assert_eq!(p.locals_at_pc(5).len(), 0);
}

// ──────────────────────────────────────────────────────────────────────────────
// UpvalInfo bit layout.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn upvalinfo_bit_round_trip() {
    let mut s = fresh_lcg();
    for _ in 0..50 {
        let raw = lcg_gen(&mut s) as u16;
        let ui = UpvalInfo::from_raw(raw);
        assert_eq!(ui.raw, raw);
        assert_eq!(ui.index, (raw & 0xFF) as u8);
        assert_eq!(ui.is_local, (raw >> 15) != 0);
        assert_eq!(ui.is_immutable, ((raw >> 8) & 0x01) != 0);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// BytecodeEncoder round-trip.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn encoder_round_trip_instruction_count() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004B))
        .add_instr(LjInstr(0x0000_0058))
        .add_instr(LjInstr(0x0000_0042))
        .build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let bc = LjBytecode::parse(&bytes).unwrap();
    assert_eq!(bc.protos.len(), 1);
    assert_eq!(bc.protos[0].instruction_count, 3);
    assert_eq!(bc.protos[0].instructions[0].0, 0x0000_004B);
}

#[test]
fn encoder_strings_preserved() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004B))
        .add_kgc_str("alpha")
        .add_kgc_str("beta")
        .build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let bc = LjBytecode::parse(&bytes).unwrap();
    let strings = bc.protos[0].kgc_strings();
    assert!(strings.contains(&"alpha"));
    assert!(strings.contains(&"beta"));
}

#[test]
fn encoder_lj20_version_preserved() {
    let p = ProtoBuilder::new().add_instr(LjInstr(0x0000_004B)).build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj20, &p);
    let bc = LjBytecode::parse(&bytes).unwrap();
    assert_eq!(bc.header.version, LjVersion::Lj20);
}

#[test]
fn encoder_starts_with_magic() {
    let p = ProtoBuilder::new().add_instr(LjInstr(0x0000_004B)).build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    assert!(is_luajit(&bytes));
    assert_eq!(&bytes[..3], &LJ_MAGIC);
}

// ──────────────────────────────────────────────────────────────────────────────
// LjBytecode and LjModule.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn bytecode_parse_random_bytes_no_panic() {
    let mut s = fresh_lcg();
    for _ in 0..50 {
        let len = (lcg_gen(&mut s) % 128) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| (lcg_gen(&mut s) & 0xFF) as u8).collect();
        // Inject magic 50% of the time so the parser tries to descend.
        if (lcg_gen(&mut s) & 1) != 0 && bytes.len() >= 4 {
            bytes[0] = 0x1B;
            bytes[1] = b'L';
            bytes[2] = b'J';
            bytes[3] = 2;
        }
        let _ = LjBytecode::parse(&bytes);
    }
}

#[test]
fn bytecode_total_instructions_zero_when_empty() {
    let mut data = vec![0x1Bu8, b'L', b'J', 2, LjFlags::STRIP.bits()];
    data.push(0x00); // end marker
    let bc = LjBytecode::parse(&data).unwrap();
    assert_eq!(bc.total_instructions(), 0);
    assert!(bc.all_strings().is_empty());
}

#[test]
fn bytecode_protos_referencing_string_finds_match() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004B))
        .add_kgc_str("needle")
        .build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let bc = LjBytecode::parse(&bytes).unwrap();
    let hits = bc.protos_referencing_string("needle");
    assert_eq!(hits, vec![0]);
    assert!(bc.protos_referencing_string("missing").is_empty());
}

// ──────────────────────────────────────────────────────────────────────────────
// LjLoader async loader (Send+Sync trait object stress).
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn loader_async_load_returns_view() {
    let data = vec![0x1Bu8, b'L', b'J', 2, LjFlags::STRIP.bits()];
    let input = rustre_core::LoaderInput::new("a.ljbc", data);
    let res = LjLoader::new().load(input).await.unwrap();
    assert_eq!(res.view.uri, "a.ljbc");
}

#[test]
fn loader_send_sync_marker() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LjLoader>();
    assert_send_sync::<LuaJitLoader>();
    assert_send_sync::<LjBytecode>();
    assert_send_sync::<LjModule>();
    assert_send_sync::<LjInstr>();
    assert_send_sync::<LjHeader>();
}

#[test]
fn threaded_instr_classification_stress() {
    use std::sync::Arc;
    use std::thread;
    let instrs: Arc<Vec<LjInstr>> = Arc::new(
        (0u8..=0xFF).map(|op| LjInstr(u32::from(op))).collect(),
    );
    let mut handles = Vec::new();
    for _ in 0..4 {
        let instrs = Arc::clone(&instrs);
        handles.push(thread::spawn(move || {
            let mut acc: usize = 0;
            for _ in 0..100 {
                for i in instrs.iter() {
                    if i.is_call() {
                        acc = acc.wrapping_add(1);
                    }
                    if i.is_return() {
                        acc = acc.wrapping_add(2);
                    }
                    let _ = i.mnemonic();
                }
            }
            acc
        }));
    }
    let vals: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // Same input → same output across all threads.
    let first = vals[0];
    for v in &vals[1..] {
        assert_eq!(*v, first);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// LjDisassembler smoke + state-machine coverage.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn disassembler_handles_unknown_opcode() {
    let p = ProtoBuilder::new().add_instr(LjInstr(0x0000_00FF)).build();
    let lines = LjDisassembler::disassemble_proto(&p);
    assert_eq!(lines.len(), 1);
}

#[test]
fn disassembler_kpri_false_branch() {
    let word = 0x2Bu32 | (1u32 << 16); // KPRI, D=1 → false
    let line = LjDisassembler::format_instr(0, LjInstr(word), &LjProto::mock());
    assert!(line.contains("false"), "got: {line}");
}

#[test]
fn disassembler_jmp_target_arithmetic() {
    // JMP at pc=10, D=0x8003 → offset = +3 → target = pc+1+3 = 14
    let d: u16 = 0x8003;
    let b = (d >> 8) as u8;
    let c = (d & 0xFF) as u8;
    let word = 0x58u32 | (u32::from(c) << 16) | (u32::from(b) << 24);
    let line = LjDisassembler::format_instr(10, LjInstr(word), &LjProto::mock());
    assert!(line.contains("0014"), "got: {line}");
}

// ──────────────────────────────────────────────────────────────────────────────
// LjConst Display variants.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn ljconst_proto_and_num_display() {
    assert_eq!(LjConst::Proto(2).to_string(), "proto[2]");
    assert!(LjConst::Num(1.5).to_string().contains("1.5"));
    assert_eq!(LjConst::Bool(false).to_string(), "false");
}
