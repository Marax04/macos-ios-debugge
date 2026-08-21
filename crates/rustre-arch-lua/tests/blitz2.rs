//! blitz2: deep adversarial tests for rustre-arch-lua.
//!
//! Focuses on public API: opcode tables, encoders/decoders, header parser,
//! constant pool parsers, CFG splitter, stats, classification, snapshots.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_lua::*;
use rustre_core::address::Address;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ─── Seeded LCG fuzzer ─────────────────────────────────────────────────────
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ─── Version helpers ────────────────────────────────────────────────────────

#[test]
fn version_names() {
    assert_eq!(LuaVersion::Lua51.name(), "lua51");
    assert_eq!(LuaVersion::Lua52.name(), "lua52");
    assert_eq!(LuaVersion::Lua53.name(), "lua53");
    assert_eq!(LuaVersion::Lua54.name(), "lua54");
}

#[test]
fn version_strings() {
    assert_eq!(LuaVersion::Lua51.version_string(), "Lua 5.1");
    assert_eq!(LuaVersion::Lua54.version_string(), "Lua 5.4");
}

#[test]
fn version_is_legacy() {
    for v in [LuaVersion::Lua51, LuaVersion::Lua52, LuaVersion::Lua53] {
        assert!(v.is_legacy());
    }
    assert!(!LuaVersion::Lua54.is_legacy());
}

#[test]
fn version_default_is_lua54() {
    assert_eq!(LuaVersion::default(), LuaVersion::Lua54);
}

#[test]
fn version_eq_hash_consistent() {
    let pairs = [
        LuaVersion::Lua51,
        LuaVersion::Lua52,
        LuaVersion::Lua53,
        LuaVersion::Lua54,
    ];
    for a in pairs {
        for b in pairs {
            if a == b {
                assert_eq!(hash_of(&a), hash_of(&b));
            }
        }
    }
}

#[test]
fn version_display_matches_version_string() {
    for v in [
        LuaVersion::Lua51,
        LuaVersion::Lua52,
        LuaVersion::Lua53,
        LuaVersion::Lua54,
    ] {
        assert_eq!(format!("{v}"), v.version_string());
    }
}

// ─── make_iabc / decode round-trip (Lua 5.4) ───────────────────────────────

#[test]
fn iabc_roundtrip_all_known_opcodes() {
    // Build with each opcode that uses ABC format, decode, ensure mnemonic non-empty.
    let arch = LuaArch::with_version(LuaVersion::Lua54);
    // We choose plain ABC ops avoiding special-form ones (sBx/Bx/Ax/sJ/TestJump).
    let plain_abc_ops: &[u8] = &[
        0, 5, 6, 7, 8, 9, 10, 14, 17, 18, 32, 33, 34, 35, 36, 37, 47, 48, 49, 50, 51,
    ];
    for &op in plain_abc_ops {
        let word = make_iabc(op, 1, 2, 3, 0);
        let bytes = word.to_le_bytes();
        let i = arch.disassemble(Address::new(0), &bytes).expect("decode ok");
        assert!(!i.mnemonic.is_empty());
        assert_eq!(i.size, 4);
    }
}

#[test]
fn iasbx_boundary_values() {
    for sbx in [-MAXARG_SBX, -1, 0, 1, MAXARG_SBX] {
        let w = make_iasbx(1, 5, sbx);
        let bytes = w.to_le_bytes();
        let arch = LuaArch::default();
        let i = arch.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "loadi");
        assert!(i.operands.contains(&sbx.to_string()) || i.operands.contains(&format!("{sbx:+}")));
    }
}

#[test]
#[should_panic(expected = "out of range")]
fn iasbx_over_max_panics() {
    let _ = make_iasbx(1, 0, MAXARG_SBX + 1);
}

#[test]
#[should_panic(expected = "out of range")]
fn iasbx_under_min_panics() {
    let _ = make_iasbx(1, 0, -MAXARG_SBX - 1);
}

#[test]
fn isj_boundary_values() {
    // JMP op is 54
    for sj in [-1, 0, 1, 100, -100] {
        let w = make_isj(54, sj);
        let bytes = w.to_le_bytes();
        let arch = LuaArch::default();
        let i = arch.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "jmp");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }
}

#[test]
#[should_panic(expected = "out of range")]
fn isj_over_max_panics() {
    // MAXARG_SJ private; compute upper bound from layout: 25-bit signed => 2^24 - 1.
    let _ = make_isj(54, (1 << 24) + 1);
}

#[test]
fn iabx_field_extraction() {
    for bx in [0u32, 1, 100, 1000, (1 << 17) - 1] {
        let w = make_iabx(3, 4, bx);
        assert_eq!(get_bx54(w), bx);
    }
}

#[test]
fn iax_field_extraction() {
    for ax in [0u32, 1, 100_000, (1 << 25) - 1] {
        let w = make_iax(80, ax);
        assert_eq!(get_ax54(w), ax);
    }
}

// ─── Opcode name lookup / find ──────────────────────────────────────────────

#[test]
fn opcode_name_in_range() {
    assert_eq!(opcode_name(LuaVersion::Lua54, 0), Some("MOVE"));
    assert_eq!(opcode_name(LuaVersion::Lua54, 80), Some("EXTRAARG"));
    assert_eq!(opcode_name(LuaVersion::Lua51, 0), Some("MOVE"));
    assert_eq!(opcode_name(LuaVersion::Lua51, 37), Some("VARARG"));
}

#[test]
fn opcode_name_out_of_range() {
    assert_eq!(opcode_name(LuaVersion::Lua54, 200), None);
    assert_eq!(opcode_name(LuaVersion::Lua51, 100), None);
}

#[test]
fn find_opcodes_case_insensitive() {
    let v = find_opcodes(LuaVersion::Lua54, "load");
    assert!(v.iter().any(|(_, n)| *n == "LOADK"));
    let v = find_opcodes(LuaVersion::Lua54, "LOAD");
    assert!(v.iter().any(|(_, n)| *n == "LOADK"));
}

#[test]
fn find_opcodes_no_match() {
    let v = find_opcodes(LuaVersion::Lua54, "ZZZZZ");
    assert!(v.is_empty());
}

#[test]
fn is_branch_opcode_for_known_jumps() {
    assert!(is_branch_opcode(LuaVersion::Lua54, 54)); // JMP
    assert!(is_branch_opcode(LuaVersion::Lua51, 22));
    assert!(is_branch_opcode(LuaVersion::Lua52, 23));
    assert!(is_branch_opcode(LuaVersion::Lua53, 30));
}

#[test]
fn is_call_opcode_known() {
    assert!(is_call_opcode(LuaVersion::Lua54, 66));
    assert!(is_call_opcode(LuaVersion::Lua54, 67));
    assert!(is_call_opcode(LuaVersion::Lua51, 28));
    assert!(!is_call_opcode(LuaVersion::Lua54, 0));
}

#[test]
fn is_return_opcode_known() {
    assert!(is_return_opcode(LuaVersion::Lua54, 68));
    assert!(is_return_opcode(LuaVersion::Lua54, 69));
    assert!(is_return_opcode(LuaVersion::Lua54, 70));
    assert!(is_return_opcode(LuaVersion::Lua51, 30));
    assert!(!is_return_opcode(LuaVersion::Lua51, 0));
}

// ─── Chunk header parsing ──────────────────────────────────────────────────

#[test]
fn parse_chunk_header_valid_54() {
    let data = [0x1b, b'L', b'u', b'a', 0x54, 1, 4, 8, 4];
    let h = parse_chunk_header(&data).unwrap();
    assert_eq!(h.version, LuaVersion::Lua54);
    assert_eq!(h.endian, 1);
}

#[test]
fn parse_chunk_header_valid_51_52_53() {
    for (vb, expect) in [
        (0x51u8, LuaVersion::Lua51),
        (0x52, LuaVersion::Lua52),
        (0x53, LuaVersion::Lua53),
    ] {
        let data = [0x1b, b'L', b'u', b'a', vb, 1, 4, 4, 4];
        let h = parse_chunk_header(&data).unwrap();
        assert_eq!(h.version, expect);
    }
}

#[test]
fn parse_chunk_header_too_short() {
    assert_eq!(parse_chunk_header(&[]), Err(ChunkHeaderError::TooShort));
    assert_eq!(parse_chunk_header(&[0; 7]), Err(ChunkHeaderError::TooShort));
}

#[test]
fn parse_chunk_header_bad_magic() {
    let data = [0, 0, 0, 0, 0x54, 0, 0, 0];
    assert_eq!(parse_chunk_header(&data), Err(ChunkHeaderError::BadMagic));
}

#[test]
fn parse_chunk_header_unsupported_version() {
    let data = [0x1b, b'L', b'u', b'a', 0x99, 0, 0, 0];
    assert_eq!(
        parse_chunk_header(&data),
        Err(ChunkHeaderError::UnsupportedVersion(0x99))
    );
}

#[test]
fn chunk_header_error_display() {
    assert!(!ChunkHeaderError::TooShort.to_string().is_empty());
    assert!(ChunkHeaderError::BadMagic.to_string().contains("Lua"));
    assert!(ChunkHeaderError::UnsupportedVersion(0xff)
        .to_string()
        .contains("0xff"));
}

#[test]
fn chunk_header_eq_hash_consistent() {
    let a = LuaChunkHeader {
        version: LuaVersion::Lua54,
        endian: 1,
        int_size: 4,
        size_t_size: 8,
        instr_size: 4,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// ─── Header fuzz ────────────────────────────────────────────────────────────

#[test]
fn parse_chunk_header_fuzz_never_panics() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..500 {
        let n = usize::try_from(g() % 40).unwrap_or(0);
        let mut buf = vec![0u8; n];
        for b in &mut buf {
            *b = (g() & 0xff) as u8;
        }
        let _ = parse_chunk_header(&buf);
    }
}

// ─── disassemble fuzz / never-panic ────────────────────────────────────────

#[test]
fn disassemble_fuzz_never_panics_all_versions() {
    let mut g = make_lcg(0x1234_5678_9abc_def0);
    for v in [
        LuaVersion::Lua51,
        LuaVersion::Lua52,
        LuaVersion::Lua53,
        LuaVersion::Lua54,
    ] {
        let arch = LuaArch::with_version(v);
        for _ in 0..1000 {
            let w = u32::try_from(g() & 0xFFFF_FFFF).unwrap_or(0);
            let _ = arch.disassemble(Address::new(0), &w.to_le_bytes());
        }
    }
}

#[test]
fn disassemble_chunk_fuzz_never_panics() {
    let mut g = make_lcg(0xFADE_C0DE_DEAD_F00D);
    let arch = LuaArch::default();
    for _ in 0..50 {
        let n_words = usize::try_from(g() % 30).unwrap_or(0) + 1;
        let mut bytes = Vec::with_capacity(n_words * 4);
        for _ in 0..n_words {
            let w = u32::try_from(g() & 0xFFFF_FFFF).unwrap_or(0);
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let out = disassemble_chunk(&arch, Address::new(0), &bytes);
        assert!(out.len() <= bytes.len() / 4 + 1);
    }
}

#[test]
fn disassemble_too_short_returns_err() {
    let arch = LuaArch::default();
    assert!(arch.disassemble(Address::new(0), &[]).is_err());
    assert!(arch.disassemble(Address::new(0), &[0, 1, 2]).is_err());
}

#[test]
fn unknown_opcode_returns_err() {
    let arch = LuaArch::default();
    // 5.4 max opcode = 80 (EXTRAARG). 0x7f = 127 > 80.
    let w: u32 = 0x7f;
    assert!(arch.disassemble(Address::new(0), &w.to_le_bytes()).is_err());
}

// ─── decode_by_version dispatch ────────────────────────────────────────────

#[test]
fn decode_by_version_dispatches_correctly() {
    // MOVE in all versions encodes op=0.
    let w_legacy = make_legacy_iabc(0, 1, 2, 0);
    for v in [LuaVersion::Lua51, LuaVersion::Lua52, LuaVersion::Lua53] {
        let r = decode_by_version(v, w_legacy, Address::new(0)).unwrap();
        assert_eq!(r.0, "move");
    }
    let w54 = make_iabc(0, 1, 2, 0, 0);
    let r = decode_by_version(LuaVersion::Lua54, w54, Address::new(0)).unwrap();
    assert_eq!(r.0, "move");
}

// ─── LuaConst behaviour ────────────────────────────────────────────────────

#[test]
fn luaconst_accessors() {
    assert!(LuaConst::Nil.is_nil());
    assert!(!LuaConst::Bool(true).is_nil());
    assert_eq!(LuaConst::Bool(true).as_bool(), Some(true));
    assert_eq!(LuaConst::Int(42).as_int(), Some(42));
    assert_eq!(LuaConst::Float(1.5).as_float(), Some(1.5));
    assert_eq!(LuaConst::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(LuaConst::Nil.as_int(), None);
    assert_eq!(LuaConst::Int(0).as_str(), None);
}

#[test]
fn luaconst_type_names() {
    assert_eq!(LuaConst::Nil.type_name(), "nil");
    assert_eq!(LuaConst::Bool(false).type_name(), "boolean");
    assert_eq!(LuaConst::Int(0).type_name(), "integer");
    assert_eq!(LuaConst::Float(0.0).type_name(), "float");
    assert_eq!(LuaConst::String(String::new()).type_name(), "string");
}

#[test]
fn luaconst_display_includes_value() {
    assert_eq!(format!("{}", LuaConst::Nil), "nil");
    assert_eq!(format!("{}", LuaConst::Int(7)), "7");
    assert_eq!(format!("{}", LuaConst::Bool(true)), "true");
    assert!(format!("{}", LuaConst::String("x".into())).contains('x'));
}

// ─── parse_const_pool_51 ───────────────────────────────────────────────────

#[test]
fn parse_const_pool_51_basic() {
    // 3 entries: nil, bool true, int as float 3.14
    let mut data = Vec::new();
    data.extend_from_slice(&3i32.to_le_bytes());
    data.push(0); // nil
    data.push(1); // bool
    data.push(1); // true
    data.push(3); // number
    data.extend_from_slice(&2.5f64.to_le_bytes());
    let pool = parse_const_pool_51(&data).unwrap();
    assert_eq!(pool.len(), 3);
    assert!(pool[0].is_nil());
    assert_eq!(pool[1].as_bool(), Some(true));
    assert_eq!(pool[2].as_float(), Some(2.5));
}

#[test]
fn parse_const_pool_51_string_strips_nul() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(4); // string
    data.extend_from_slice(&4i32.to_le_bytes()); // len incl nul
    data.extend_from_slice(b"abc\0");
    let pool = parse_const_pool_51(&data).unwrap();
    assert_eq!(pool[0].as_str(), Some("abc"));
}

#[test]
fn parse_const_pool_51_unknown_type_returns_none() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(99);
    assert!(parse_const_pool_51(&data).is_none());
}

#[test]
fn parse_const_pool_51_truncated_returns_none() {
    let data = [1, 0, 0, 0, 3, 0, 0, 0]; // 1 number but only 3 bytes of payload
    assert!(parse_const_pool_51(&data).is_none());
}

#[test]
fn parse_const_pool_51_fuzz_never_panics() {
    let mut g = make_lcg(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..300 {
        let n = usize::try_from(g() % 64).unwrap_or(0);
        let mut buf = vec![0u8; n];
        for b in &mut buf {
            *b = (g() & 0xff) as u8;
        }
        let _ = parse_const_pool_51(&buf);
    }
}

// ─── parse_const_pool_53 ───────────────────────────────────────────────────

#[test]
fn parse_const_pool_53_basic() {
    let mut data = Vec::new();
    data.extend_from_slice(&4i32.to_le_bytes());
    data.push(0x00); // nil
    data.push(0x01); // false
    data.push(0x11); // true
    data.push(0x13); // integer
    data.extend_from_slice(&7i64.to_le_bytes());
    let pool = parse_const_pool_53(&data).unwrap();
    assert_eq!(pool.len(), 4);
    assert!(pool[0].is_nil());
    assert_eq!(pool[1].as_bool(), Some(false));
    assert_eq!(pool[2].as_bool(), Some(true));
    assert_eq!(pool[3].as_int(), Some(7));
}

#[test]
fn parse_const_pool_53_short_string() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(0x04);
    // sz byte: length incl trailing nul. We have "ab\0" → len 3
    data.push(3);
    data.extend_from_slice(b"ab\0");
    let pool = parse_const_pool_53(&data).unwrap();
    assert_eq!(pool[0].as_str(), Some("ab"));
}

#[test]
fn parse_const_pool_53_fuzz_never_panics() {
    let mut g = make_lcg(0xFEED_FACE_DEAD_BEEF);
    for _ in 0..300 {
        let n = usize::try_from(g() % 64).unwrap_or(0);
        let mut buf = vec![0u8; n];
        for b in &mut buf {
            *b = (g() & 0xff) as u8;
        }
        let _ = parse_const_pool_53(&buf);
    }
}

// ─── classify_opcode ───────────────────────────────────────────────────────

#[test]
fn classify_opcode_categories() {
    assert_eq!(classify_opcode("MOVE"), OpcodeCategory::Move);
    assert_eq!(classify_opcode("loadk"), OpcodeCategory::Load);
    assert_eq!(classify_opcode("getupval"), OpcodeCategory::Upvalue);
    assert_eq!(classify_opcode("GETGLOBAL"), OpcodeCategory::Global);
    assert_eq!(classify_opcode("settable"), OpcodeCategory::TableSet);
    assert_eq!(classify_opcode("newtable"), OpcodeCategory::TableNew);
    assert_eq!(classify_opcode("ADD"), OpcodeCategory::Arithmetic);
    assert_eq!(classify_opcode("NOT"), OpcodeCategory::Unary);
    assert_eq!(classify_opcode("concat"), OpcodeCategory::Concat);
    assert_eq!(classify_opcode("jmp"), OpcodeCategory::Jump);
    assert_eq!(classify_opcode("eq"), OpcodeCategory::Compare);
    assert_eq!(classify_opcode("call"), OpcodeCategory::Call);
    assert_eq!(classify_opcode("return"), OpcodeCategory::Return);
    assert_eq!(classify_opcode("closure"), OpcodeCategory::Closure);
    assert_eq!(classify_opcode("vararg"), OpcodeCategory::Vararg);
    assert_eq!(classify_opcode("mmbin"), OpcodeCategory::Meta);
    assert_eq!(classify_opcode("???unknown???"), OpcodeCategory::Other);
}

#[test]
fn classify_opcode_eq_hash_consistent() {
    let cats = [
        OpcodeCategory::Move,
        OpcodeCategory::Load,
        OpcodeCategory::Arithmetic,
        OpcodeCategory::Return,
    ];
    for a in cats {
        for b in cats {
            if a == b {
                assert_eq!(hash_of(&a), hash_of(&b));
            }
        }
    }
}

#[test]
fn opcode_category_display_nonempty() {
    for c in [
        OpcodeCategory::Move,
        OpcodeCategory::Load,
        OpcodeCategory::Upvalue,
        OpcodeCategory::Global,
        OpcodeCategory::TableGet,
        OpcodeCategory::TableSet,
        OpcodeCategory::TableNew,
        OpcodeCategory::Arithmetic,
        OpcodeCategory::Unary,
        OpcodeCategory::Concat,
        OpcodeCategory::Jump,
        OpcodeCategory::Compare,
        OpcodeCategory::Loop,
        OpcodeCategory::Call,
        OpcodeCategory::Return,
        OpcodeCategory::Closure,
        OpcodeCategory::Vararg,
        OpcodeCategory::Meta,
        OpcodeCategory::Other,
    ] {
        assert!(!format!("{c}").is_empty());
    }
}

// ─── Stats ─────────────────────────────────────────────────────────────────

#[test]
fn stats_empty() {
    let s = LuaChunkStats::from_instructions(LuaVersion::Lua54, &[]);
    assert_eq!(s.total, 0);
    assert!(s.branch_ratio().abs() < f64::EPSILON);
}

#[test]
fn stats_branch_ratio_nontrivial() {
    let arch = LuaArch::default();
    // 1 jmp + 1 add → branch_ratio = 0.5
    let jmp = make_isj(54, 1).to_le_bytes();
    let add = make_iabc(32, 0, 1, 2, 0).to_le_bytes();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&jmp);
    bytes.extend_from_slice(&add);
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    assert_eq!(instrs.len(), 2);
    let s = LuaChunkStats::from_instructions(LuaVersion::Lua54, &instrs);
    assert_eq!(s.total, 2);
    assert_eq!(s.branches, 1);
    assert!((s.branch_ratio() - 0.5).abs() < 1e-9);
    assert!(!format!("{s}").is_empty());
}

// ─── CFG / basic blocks ───────────────────────────────────────────────────

#[test]
fn split_basic_blocks_single_block() {
    let arch = LuaArch::default();
    let bytes: Vec<u8> = [make_iabc(0, 0, 1, 0, 0), make_iabc(0, 1, 2, 0, 0)]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    let blocks = split_basic_blocks(&arch, &instrs);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].instructions.len(), 2);
    assert!(!blocks[0].is_terminal());
}

#[test]
fn split_basic_blocks_with_jump() {
    let arch = LuaArch::default();
    // jmp +1 (skip next), then move R1,R2, then move R0,R1.
    let words = [
        make_isj(54, 1),
        make_iabc(0, 1, 2, 0, 0),
        make_iabc(0, 0, 1, 0, 0),
    ];
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    let blocks = split_basic_blocks(&arch, &instrs);
    assert!(blocks.len() >= 2);
}

// ─── format_instruction / listing ─────────────────────────────────────────

#[test]
fn format_instruction_includes_addr_and_mnemonic() {
    let arch = LuaArch::default();
    let w = make_iabc(0, 0, 1, 0, 0);
    let i = arch.disassemble(Address::new(0x40), &w.to_le_bytes()).unwrap();
    let s = format_instruction(&i);
    assert!(s.contains("0x00000040"));
    assert!(s.contains("move"));
}

#[test]
fn format_listing_multiline() {
    let arch = LuaArch::default();
    let bytes: Vec<u8> = [make_iabc(0, 0, 1, 0, 0), make_iabc(0, 2, 3, 0, 0)]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    let listing = format_listing(&instrs);
    assert_eq!(listing.lines().count(), 2);
}

// ─── Detect version ───────────────────────────────────────────────────────

#[test]
fn detect_version_via_header() {
    let data = [0x1b, b'L', b'u', b'a', 0x53, 1, 4, 8];
    assert_eq!(detect_version(&data), Some(LuaVersion::Lua53));
}

#[test]
fn detect_version_too_short_is_none() {
    assert_eq!(detect_version(&[]), None);
    assert_eq!(detect_version(&[1, 2]), None);
}

#[test]
fn detect_version_fuzz_never_panics() {
    let mut g = make_lcg(0xC001_D00D_FACE_FEED);
    for _ in 0..500 {
        let n = usize::try_from(g() % 20).unwrap_or(0);
        let mut buf = vec![0u8; n];
        for b in &mut buf {
            *b = (g() & 0xff) as u8;
        }
        let _ = detect_version(&buf);
    }
}

// ─── extract_constants_from_proto ──────────────────────────────────────────

#[test]
fn extract_constants_finds_loadk_indices_54() {
    let words = [
        make_iabx(3, 0, 5), // LOADK R0, K[5]
        make_iabx(3, 1, 7), // LOADK R1, K[7]
        make_iabx(4, 2, 0), // LOADKX
        make_iabc(0, 0, 1, 0, 0), // MOVE — not a load
    ];
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let cs = extract_constants_from_proto(&bytes, LuaVersion::Lua54);
    let ints: Vec<i64> = cs.iter().filter_map(rustre_arch_lua::LuaConst::as_int).collect();
    assert!(ints.contains(&5));
    assert!(ints.contains(&7));
}

#[test]
fn extract_constants_empty_on_empty() {
    let cs = extract_constants_from_proto(&[], LuaVersion::Lua54);
    assert!(cs.is_empty());
}

#[test]
fn extract_constants_fuzz() {
    let mut g = make_lcg(0xBAAD_F00D_C0DE_DEAD);
    for v in [
        LuaVersion::Lua51,
        LuaVersion::Lua52,
        LuaVersion::Lua53,
        LuaVersion::Lua54,
    ] {
        for _ in 0..50 {
            let n_words = usize::try_from(g() % 16).unwrap_or(0);
            let mut buf = Vec::with_capacity(n_words * 4);
            for _ in 0..n_words {
                buf.extend_from_slice(&u32::try_from(g() & 0xFFFF_FFFF).unwrap_or(0).to_le_bytes());
            }
            let _ = extract_constants_from_proto(&buf, v);
        }
    }
}

// ─── Name generation ──────────────────────────────────────────────────────

#[test]
fn generate_local_var_names_min_one_max_64() {
    assert_eq!(generate_local_var_names(0).len(), 1);
    assert_eq!(generate_local_var_names(4).len(), 1);
    assert_eq!(generate_local_var_names(40).len(), 10);
    assert_eq!(generate_local_var_names(10_000).len(), 64);
}

#[test]
fn generate_upvalue_names_count() {
    let v = generate_upvalue_names(5);
    assert_eq!(v.len(), 5);
    assert_eq!(v[0], "upval_0");
    assert_eq!(v[4], "upval_4");
}

#[test]
fn generate_param_names_with_self() {
    let v = generate_param_names(3, true);
    assert_eq!(v[0], "self");
    assert_eq!(v.len(), 3); // self + 2 args
    assert_eq!(v[1], "arg1");
}

#[test]
fn generate_param_names_no_self() {
    let v = generate_param_names(2, false);
    assert_eq!(v, vec!["arg1".to_string(), "arg2".to_string()]);
}

#[test]
fn generate_param_names_zero() {
    assert!(generate_param_names(0, false).is_empty());
}

// ─── LuaProtoInfo ─────────────────────────────────────────────────────────

#[test]
fn lua_proto_info_basic() {
    let arch = LuaArch::default();
    let bytes: Vec<u8> = [make_iabc(0, 0, 1, 0, 0); 3]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    let p = LuaProtoInfo::new(LuaVersion::Lua54, instrs);
    assert_eq!(p.len(), 3);
    assert!(!p.is_empty());
    assert!(!p.listing().is_empty());
    assert!(!format!("{p}").is_empty());
    assert!(p.constant(0).is_none());
    assert!(!p.basic_blocks(&arch).is_empty());
}

#[test]
fn lua_proto_info_empty() {
    let p = LuaProtoInfo::new(LuaVersion::Lua54, vec![]);
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
}

// ─── RegisterSnapshot ──────────────────────────────────────────────────────

#[test]
fn register_snapshot_set_get() {
    let mut s = RegisterSnapshot::new(4);
    s.set(0, RegValue::Const(LuaConst::Int(42)));
    assert!(matches!(s.get(0), Some(RegValue::Const(LuaConst::Int(42)))));
    assert!(s.get(2).is_none());
}

#[test]
fn register_snapshot_grows_on_oob() {
    let mut s = RegisterSnapshot::new(2);
    s.set(10, RegValue::Const(LuaConst::Nil));
    assert!(s.get(10).is_some());
}

#[test]
fn register_snapshot_invalidate_from() {
    let mut s = RegisterSnapshot::new(8);
    for i in 0..8 {
        s.set(i, RegValue::Const(LuaConst::Int(i64::from(i))));
    }
    s.invalidate_from(4);
    assert!(s.get(3).is_some());
    assert!(s.get(4).is_none());
    assert!(s.get(7).is_none());
}

#[test]
fn register_snapshot_propagate_loadk_54() {
    let arch = LuaArch::default();
    let word = make_iabx(3, 0, 0); // LOADK R0, K[0]
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &word.to_le_bytes());
    let pool = vec![LuaConst::Int(99)];
    let mut snap = RegisterSnapshot::new(4);
    snap.propagate(&instrs, &pool, LuaVersion::Lua54);
    assert!(matches!(snap.get(0), Some(RegValue::Const(LuaConst::Int(99)))));
}

// ─── Annotate ─────────────────────────────────────────────────────────────

#[test]
fn annotate_loadk_includes_constant() {
    let arch = LuaArch::default();
    let word = make_iabx(3, 1, 0); // LOADK R1, K[0]
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &word.to_le_bytes());
    let pool = vec![LuaConst::String("hello".into())];
    let ann = annotate_instructions(&instrs, &pool, LuaVersion::Lua54);
    assert_eq!(ann.len(), 1);
    assert!(ann[0].annotation.as_ref().unwrap().contains("hello"));
}

#[test]
fn annotate_non_loadk_has_no_annotation() {
    let arch = LuaArch::default();
    let word = make_iabc(0, 0, 1, 0, 0); // MOVE
    let instrs = disassemble_chunk_lossy(&arch, Address::new(0), &word.to_le_bytes());
    let pool = vec![LuaConst::Int(0)];
    let ann = annotate_instructions(&instrs, &pool, LuaVersion::Lua54);
    assert!(ann[0].annotation.is_none());
    // Display still works.
    assert!(!format!("{}", ann[0]).is_empty());
}

// ─── LuaArch metadata ─────────────────────────────────────────────────────

#[test]
fn lua_arch_metadata_for_each_version() {
    let m = LuaArchMetadata::for_version(LuaVersion::Lua54);
    assert_eq!(m.instr_width, 4);
    assert_eq!(m.opcode_bits, 7);
    assert_eq!(m.opcode_count, 81);
    let m = LuaArchMetadata::for_version(LuaVersion::Lua51);
    assert_eq!(m.opcode_bits, 6);
    assert_eq!(m.opcode_count, 38);
}

#[test]
fn lua_arch_constructors() {
    assert_eq!(LuaArch::new().version, LuaVersion::Lua54);
    assert_eq!(
        LuaArch::with_version(LuaVersion::Lua52).version,
        LuaVersion::Lua52
    );
    assert_eq!(LuaArch::default().version, LuaVersion::Lua54);
    let arch = LuaArch::new();
    assert_eq!(arch.instruction_alignment(), 4);
    assert_eq!(arch.max_instruction_length(), 4);
}

// ─── Send + Sync threaded stress (LuaArch is Send+Sync) ───────────────────

#[test]
fn lua_arch_threaded_disassemble_stress() {
    use std::sync::Arc;
    use std::thread;
    let arch = Arc::new(LuaArch::default());
    let mut handles = Vec::new();
    for t in 0..4 {
        let arch = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut g = make_lcg(0x1_0000_0000_u64.wrapping_mul(u64::try_from(t).unwrap_or(0) + 1).wrapping_add(7));
            for _ in 0..100 {
                let w = u32::try_from(g() & 0xFFFF_FFFF).unwrap_or(0);
                let _ = arch.disassemble(Address::new(0), &w.to_le_bytes());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── LuaArch Clone / Debug ─────────────────────────────────────────────────

#[test]
fn lua_arch_clone_preserves_version() {
    let a = LuaArch::with_version(LuaVersion::Lua53);
    let b = a.clone();
    assert_eq!(a.version, b.version);
    assert!(!format!("{a:?}").is_empty());
}

// ─── is_branch_opcode comprehensive ─────────────────────────────────────────

#[test]
fn is_branch_opcode_negative_cases() {
    // MOVE (op 0) is never a branch.
    for v in [
        LuaVersion::Lua51,
        LuaVersion::Lua52,
        LuaVersion::Lua53,
        LuaVersion::Lua54,
    ] {
        assert!(!is_branch_opcode(v, 0));
    }
}

// ─── disassemble_chunk vs lossy ────────────────────────────────────────────

#[test]
fn disassemble_chunk_lossy_skips_errors() {
    let arch = LuaArch::default();
    // Mix of valid MOVE + invalid (opcode 127 padding to 4 bytes).
    let good = make_iabc(0, 0, 1, 0, 0);
    let bad: u32 = 0x7f; // op > 80
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&good.to_le_bytes());
    bytes.extend_from_slice(&bad.to_le_bytes());
    let lossy = disassemble_chunk_lossy(&arch, Address::new(0), &bytes);
    assert_eq!(lossy.len(), 1);

    let full = disassemble_chunk(&arch, Address::new(0), &bytes);
    assert_eq!(full.len(), 2);
    assert!(full[0].is_ok());
    assert!(full[1].is_err());
}
