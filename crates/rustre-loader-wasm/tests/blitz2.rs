//! Adversarial blitz tests (round 2) for rustre-loader-wasm.
//!
//! Focuses on LEB128 decoder edge cases, `WasmParser` malformed/truncated/oversized
//! inputs, value-type round-trips, security analyzers, and threaded stress.

use rustre_loader_wasm::wasm_security::*;
use rustre_loader_wasm::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn sleb(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut more = true;
    while more {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
            more = false;
            out.push(byte);
        } else {
            out.push(byte | 0x80);
        }
    }
    out
}

fn header() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
}

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push((self.next() >> 24) as u8);
        }
        v
    }
}

// ── LEB128 ──────────────────────────────────────────────────────────────────

#[test]
fn leb128_u32_roundtrip_50() {
    let mut s = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let v = (s.next() & 0xFFFF_FFFF) as u32;
        let enc = uleb(u64::from(v));
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_u32().unwrap(), v);
        assert!(d.is_done());
    }
}

#[test]
fn leb128_u64_roundtrip_50() {
    let mut s = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..50 {
        let v = s.next();
        let enc = uleb(v);
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_u64().unwrap(), v);
    }
}

#[test]
fn leb128_i32_roundtrip_50() {
    let mut s = Lcg::new(0xCAFEBABE_DEADBEEF);
    for _ in 0..50 {
        let v = s.next() as i32;
        let enc = sleb(i64::from(v));
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_i32().unwrap(), v);
    }
}

#[test]
fn leb128_i64_roundtrip_50() {
    let mut s = Lcg::new(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..50 {
        let v = s.next() as i64;
        let enc = sleb(v);
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_i64().unwrap(), v);
    }
}

#[test]
fn leb128_boundaries_u32() {
    for &v in &[0u32, 1, 127, 128, 16383, 16384, u32::MAX - 1, u32::MAX] {
        let enc = uleb(u64::from(v));
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_u32().unwrap(), v);
    }
}

#[test]
fn leb128_boundaries_i32() {
    for &v in &[0i32, 1, -1, i32::MIN, i32::MAX, 63, -64, 64, -65] {
        let enc = sleb(i64::from(v));
        let mut d = Leb128Decoder::new(&enc);
        assert_eq!(d.read_i32().unwrap(), v);
    }
}

#[test]
fn leb128_overflow_u32() {
    // 6 continuation bytes (35 bits) -> error
    let bad = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    let mut d = Leb128Decoder::new(&bad);
    assert!(d.read_u32().is_err());
}

#[test]
fn leb128_unexpected_eof() {
    // continuation bit set but no more bytes
    let bad = [0x80];
    let mut d = Leb128Decoder::new(&bad);
    assert!(matches!(d.read_u32(), Err(WasmError::UnexpectedEof(_))));
}

#[test]
fn leb128_empty_decoder() {
    let d = Leb128Decoder::new(&[]);
    assert!(d.is_done());
    assert_eq!(d.remaining(), 0);
    assert_eq!(d.offset(), 0);
}

#[test]
fn leb128_read_bytes_oob() {
    let mut d = Leb128Decoder::new(&[1, 2, 3]);
    assert!(d.read_bytes(4).is_err());
    assert_eq!(d.read_bytes(3).unwrap(), &[1, 2, 3]);
    assert!(d.is_done());
}

#[test]
fn leb128_read_name_invalid_utf8() {
    let mut data = uleb(2);
    data.extend_from_slice(&[0xFF, 0xFE]);
    let mut d = Leb128Decoder::new(&data);
    assert!(matches!(d.read_name(), Err(WasmError::InvalidUtf8)));
}

#[test]
fn leb128_read_name_ok() {
    let mut data = uleb(5);
    data.extend_from_slice(b"hello");
    let mut d = Leb128Decoder::new(&data);
    assert_eq!(d.read_name().unwrap(), "hello");
}

#[test]
fn leb128_remaining_offset_tracking() {
    let data = [0x01, 0x02, 0x03, 0x04];
    let mut d = Leb128Decoder::new(&data);
    assert_eq!(d.remaining(), 4);
    let _ = d.read_u8().unwrap();
    assert_eq!(d.remaining(), 3);
    assert_eq!(d.offset(), 1);
}

#[test]
fn leb128_fuzz_never_panics() {
    let mut s = Lcg::new(0xFEED_FACE_DEAD_BEEF);
    for _ in 0..200 {
        let len = (s.next() % 32) as usize;
        let data = s.bytes(len);
        let mut d = Leb128Decoder::new(&data);
        let _ = d.read_u32();
        let mut d = Leb128Decoder::new(&data);
        let _ = d.read_i32();
        let mut d = Leb128Decoder::new(&data);
        let _ = d.read_u64();
        let mut d = Leb128Decoder::new(&data);
        let _ = d.read_i64();
        let mut d = Leb128Decoder::new(&data);
        let _ = d.read_name();
    }
}

// ── WasmValType ─────────────────────────────────────────────────────────────

#[test]
fn valtype_from_byte_all_known() {
    for (b, expected) in [
        (0x7F, WasmValType::I32),
        (0x7E, WasmValType::I64),
        (0x7D, WasmValType::F32),
        (0x7C, WasmValType::F64),
        (0x7B, WasmValType::V128),
        (0x70, WasmValType::FuncRef),
        (0x6F, WasmValType::ExternRef),
    ] {
        assert_eq!(WasmValType::from_byte(b), Some(expected));
    }
}

#[test]
fn valtype_from_byte_unknown_all() {
    for b in 0u8..=255 {
        let known = matches!(b, 0x7F | 0x7E | 0x7D | 0x7C | 0x7B | 0x70 | 0x6F);
        assert_eq!(WasmValType::from_byte(b).is_some(), known);
    }
}

#[test]
fn valtype_display_matches_name() {
    let cases = [
        (WasmValType::I32, "i32"),
        (WasmValType::I64, "i64"),
        (WasmValType::F32, "f32"),
        (WasmValType::F64, "f64"),
        (WasmValType::V128, "v128"),
        (WasmValType::FuncRef, "funcref"),
        (WasmValType::ExternRef, "externref"),
    ];
    for (vt, name) in cases {
        assert_eq!(vt.name(), name);
        assert_eq!(format!("{vt}"), name);
    }
}

#[test]
fn valtype_byte_size() {
    assert_eq!(WasmValType::I32.byte_size(), 4);
    assert_eq!(WasmValType::F32.byte_size(), 4);
    assert_eq!(WasmValType::I64.byte_size(), 8);
    assert_eq!(WasmValType::F64.byte_size(), 8);
    assert_eq!(WasmValType::V128.byte_size(), 16);
    assert_eq!(WasmValType::FuncRef.byte_size(), 0);
    assert_eq!(WasmValType::ExternRef.byte_size(), 0);
}

#[test]
fn valtype_eq_consistency_30_pairs() {
    let all = [
        WasmValType::I32,
        WasmValType::I64,
        WasmValType::F32,
        WasmValType::F64,
        WasmValType::V128,
        WasmValType::FuncRef,
        WasmValType::ExternRef,
    ];
    let mut pairs = 0;
    for a in all {
        for b in all {
            if a == b {
                assert_eq!(a.name(), b.name());
            } else {
                assert_ne!(a.name(), b.name());
            }
            pairs += 1;
        }
    }
    assert!(pairs >= 30);
}

// ── WasmFuncType Display ────────────────────────────────────────────────────

#[test]
fn functype_display_zero_results() {
    let ft = WasmFuncType {
        params: vec![WasmValType::I32, WasmValType::I64],
        results: vec![],
    };
    assert_eq!(format!("{ft}"), "(i32, i64) -> ()");
}

#[test]
fn functype_display_one_result() {
    let ft = WasmFuncType {
        params: vec![],
        results: vec![WasmValType::F32],
    };
    assert_eq!(format!("{ft}"), "() -> f32");
}

#[test]
fn functype_display_multi_results() {
    let ft = WasmFuncType {
        params: vec![WasmValType::I32],
        results: vec![WasmValType::I32, WasmValType::I64],
    };
    assert_eq!(format!("{ft}"), "(i32) -> (i32, i64)");
}

// ── WasmCustomSection ───────────────────────────────────────────────────────

#[test]
fn custom_section_is_dwarf_and_is_name() {
    let cs = WasmCustomSection {
        name: ".debug_info".into(),
        data: vec![],
    };
    assert!(cs.is_dwarf());
    assert!(!cs.is_name());
    let cs2 = WasmCustomSection {
        name: "name".into(),
        data: vec![],
    };
    assert!(cs2.is_name());
    assert!(!cs2.is_dwarf());
    let cs3 = WasmCustomSection {
        name: "other".into(),
        data: vec![],
    };
    assert!(!cs3.is_name());
    assert!(!cs3.is_dwarf());
}

// ── WasmParser ──────────────────────────────────────────────────────────────

#[test]
fn parser_invalid_magic() {
    let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00];
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::InvalidMagic)
    ));
}

#[test]
fn parser_too_short() {
    for n in 0..8 {
        let bytes = vec![0u8; n];
        assert!(WasmParser::parse(&bytes).is_err());
    }
}

#[test]
fn parser_bad_version() {
    let mut bytes = vec![0x00, 0x61, 0x73, 0x6D];
    bytes.extend_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::UnsupportedVersion(2))
    ));
}

#[test]
fn parser_empty_module() {
    let bytes = header();
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.version, 1);
    assert!(m.types.is_empty());
    assert!(m.imports.is_empty());
    assert!(m.functions.is_empty());
    assert_eq!(m.total_function_count, 0);
}

#[test]
fn parser_section_too_large() {
    let mut bytes = header();
    bytes.push(1); // type section
    // claim section length > 256 MiB
    bytes.extend_from_slice(&uleb(300 * 1024 * 1024));
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::SectionTooLarge(_))
    ));
}

#[test]
fn parser_truncated_section() {
    let mut bytes = header();
    bytes.push(1);
    bytes.extend_from_slice(&uleb(100)); // claims 100 bytes but none follow
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::UnexpectedEof(_))
    ));
}

#[test]
fn parser_type_section_bad_tag() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1)); // 1 type
    sec.push(0x59); // wrong tag (not 0x60)
    bytes.push(1);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::InvalidSection(0x59))
    ));
}

#[test]
fn parser_type_section_bad_valtype() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1));
    sec.push(0x60);
    sec.extend_from_slice(&uleb(1));
    sec.push(0x55); // bad valtype
    sec.extend_from_slice(&uleb(0));
    bytes.push(1);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    assert!(WasmParser::parse(&bytes).is_err());
}

#[test]
fn parser_unknown_section_id_skipped() {
    // Future-compat: unknown section id should be skipped, not error.
    let mut bytes = header();
    bytes.push(99); // unknown
    let payload = vec![0xAA, 0xBB, 0xCC];
    bytes.extend_from_slice(&uleb(payload.len() as u64));
    bytes.extend_from_slice(&payload);
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.version, 1);
}

#[test]
fn parser_custom_section_kept() {
    let mut bytes = header();
    let mut sec = Vec::new();
    let name = b"mycustom";
    sec.extend_from_slice(&uleb(name.len() as u64));
    sec.extend_from_slice(name);
    sec.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    bytes.push(0);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.custom_sections.len(), 1);
    assert_eq!(m.custom_sections[0].name, "mycustom");
    assert_eq!(m.custom_sections[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn parser_start_section() {
    let mut bytes = header();
    let mut sec = uleb(42);
    bytes.push(8);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.append(&mut sec);
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.start_function, Some(42));
    assert!(m.has_start_function());
}

#[test]
fn parser_memory_section_with_max() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1));
    sec.push(0x01); // flag: has max
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(&uleb(10));
    bytes.push(5);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.memories.len(), 1);
    assert_eq!(m.memories[0].min, 1);
    assert_eq!(m.memories[0].max, Some(10));
    assert_eq!(m.memory_pages_min(), 1);
}

#[test]
fn parser_memory_section_no_max() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1));
    sec.push(0x00); // no max
    sec.extend_from_slice(&uleb(3));
    bytes.push(5);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    let m = WasmParser::parse(&bytes).unwrap();
    assert_eq!(m.memories[0].min, 3);
    assert_eq!(m.memories[0].max, None);
}

#[test]
fn parser_export_bad_kind() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(b"x");
    sec.push(0x07); // bad kind
    sec.extend_from_slice(&uleb(0));
    bytes.push(7);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::InvalidSection(0x07))
    ));
}

#[test]
fn parser_import_bad_kind() {
    let mut bytes = header();
    let mut sec = Vec::new();
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(b"a");
    sec.extend_from_slice(&uleb(1));
    sec.extend_from_slice(b"b");
    sec.push(0x09); // bad import kind
    bytes.push(2);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    assert!(matches!(
        WasmParser::parse(&bytes),
        Err(WasmError::InvalidSection(0x09))
    ));
}

#[test]
fn parser_fuzz_random_after_header_no_panic() {
    let mut s = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let mut bytes = header();
        let n = (s.next() % 256) as usize;
        bytes.extend(s.bytes(n));
        let _ = WasmParser::parse(&bytes);
    }
}

#[test]
fn parser_fuzz_completely_random_no_panic() {
    let mut s = Lcg::new(0xBABE_FACE_1234_5678);
    for _ in 0..50 {
        let n = (s.next() % 128) as usize;
        let bytes = s.bytes(n);
        let _ = WasmParser::parse(&bytes);
    }
}

// ── WasmNameSection ─────────────────────────────────────────────────────────

#[test]
fn name_section_empty_ok() {
    let ns = WasmNameSection::parse(&[]).unwrap();
    assert!(ns.module_name.is_none());
    assert!(ns.function_names.is_empty());
    assert!(ns.local_names.is_empty());
}

#[test]
fn name_section_module_name() {
    let mut data = Vec::new();
    data.push(0); // subsection id
    let mut sub = Vec::new();
    sub.extend_from_slice(&uleb(4));
    sub.extend_from_slice(b"mymod");
    // The reader sees: uleb(len=name_len_with_prefix)
    let inner_name = {
        let mut v = uleb(4);
        v.extend_from_slice(b"name");
        v
    };
    data.extend_from_slice(&uleb(inner_name.len() as u64));
    data.extend_from_slice(&inner_name);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert_eq!(ns.module_name.as_deref(), Some("name"));
    let _ = sub;
}

#[test]
fn name_section_function_names() {
    let mut sub = Vec::new();
    sub.extend_from_slice(&uleb(2)); // count
    sub.extend_from_slice(&uleb(0));
    sub.extend_from_slice(&uleb(3));
    sub.extend_from_slice(b"foo");
    sub.extend_from_slice(&uleb(7));
    sub.extend_from_slice(&uleb(3));
    sub.extend_from_slice(b"bar");

    let mut data = vec![1u8];
    data.extend_from_slice(&uleb(sub.len() as u64));
    data.extend_from_slice(&sub);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert_eq!(ns.function_names.get(&0).unwrap(), "foo");
    assert_eq!(ns.function_names.get(&7).unwrap(), "bar");
}

#[test]
fn name_section_unknown_subsection_skipped() {
    let mut data = vec![42u8]; // unknown id
    let payload = vec![0xAA, 0xBB];
    data.extend_from_slice(&uleb(payload.len() as u64));
    data.extend_from_slice(&payload);
    let ns = WasmNameSection::parse(&data).unwrap();
    assert!(ns.module_name.is_none());
}

#[test]
fn name_section_truncated_is_err() {
    let data = vec![1u8]; // says subsection id 1 but no size byte
    assert!(WasmNameSection::parse(&data).is_err());
}

// ── WasmError ───────────────────────────────────────────────────────────────

#[test]
fn wasm_error_display_distinct() {
    let errs = [
        WasmError::InvalidMagic,
        WasmError::UnsupportedVersion(99),
        WasmError::InvalidSection(0xAB),
        WasmError::Leb128Error(5),
        WasmError::UnexpectedEof(10),
        WasmError::InvalidUtf8,
        WasmError::SectionTooLarge(1000),
    ];
    let strs: Vec<String> = errs.iter().map(std::string::ToString::to_string).collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j]);
        }
    }
}

#[test]
fn wasm_error_into_core_error() {
    let e = WasmError::InvalidMagic;
    let core: rustre_core::errors::CoreError = e.into();
    let msg = format!("{core}");
    assert!(msg.contains("magic"));
}

// ── Security: Severity ordering & display ───────────────────────────────────

#[test]
fn severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn severity_eq_consistency() {
    let all = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for a in all {
        for b in all {
            assert_eq!(a == b, !(a < b || b < a));
        }
    }
}

// ── Security: WasmROP ───────────────────────────────────────────────────────

#[test]
fn rop_indirect_after_add_at_start() {
    let mut rop = WasmROP::new();
    // i32.add (0x6A), then call_indirect (0x11)
    let gadgets = rop.scan(0, &[0x6A, 0x11, 0x00, 0x00]);
    assert!(!gadgets.is_empty());
}

#[test]
fn rop_indirect_no_preceding_arith() {
    let mut rop = WasmROP::new();
    // 0x01 (nop) then call_indirect — not after arith
    let gadgets = rop.scan(0, &[0x01, 0x11, 0x00, 0x00]);
    assert!(gadgets.is_empty());
}

#[test]
fn rop_br_table_large_detected() {
    let mut rop = WasmROP::new();
    let mut code = vec![0x0E, 0x64]; // 100 labels
    code.resize(code.len() + 101, 0x00);
    let g = rop.scan(0, &code);
    assert!(!g.is_empty());
}

#[test]
fn rop_fuzz_no_panic() {
    let mut s = Lcg::new(0x9999_AAAA_BBBB_CCCC);
    for _ in 0..50 {
        let n = (s.next() % 256) as usize;
        let code = s.bytes(n);
        let mut rop = WasmROP::new();
        let _ = rop.scan(0, &code);
    }
}

// ── Security: MemoryGrowth ──────────────────────────────────────────────────

#[test]
fn memory_growth_unlimited_flagged() {
    let mut mg = MemoryGrowth::new();
    mg.set_limits(1, None);
    assert!(!mg.findings().is_empty());
}

#[test]
fn memory_growth_reasonable_ok() {
    let mut mg = MemoryGrowth::new();
    mg.set_limits(1, Some(100));
    assert!(mg.findings().is_empty());
}

// ── Security: HostFunctionAbuse ─────────────────────────────────────────────

#[test]
fn host_function_abuse_counts() {
    let mut hfa = HostFunctionAbuse::new();
    hfa.record_call("env", "malloc", 0);
    hfa.record_call("env", "malloc", 1);
    hfa.record_call("env", "free", 2);
    assert_eq!(hfa.call_count("env", "malloc"), 2);
    assert_eq!(hfa.call_count("env", "free"), 1);
    assert_eq!(hfa.call_count("env", "nope"), 0);
    assert_eq!(hfa.distinct_imports_called(), 2);
}

// ── Threaded stress ─────────────────────────────────────────────────────────

#[test]
fn threaded_valtype_4x100() {
    use std::sync::Arc;
    use std::thread;
    let bytes: Arc<Vec<u8>> = Arc::new((0u8..=255).collect());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let b = Arc::clone(&bytes);
            thread::spawn(move || {
                let mut sum = 0usize;
                for _ in 0..100 {
                    for &byte in b.iter() {
                        if let Some(vt) = WasmValType::from_byte(byte) {
                            sum += vt.byte_size();
                            let _ = vt.name();
                        }
                    }
                }
                sum
            })
        })
        .collect();
    for h in handles {
        let s = h.join().unwrap();
        assert!(s > 0);
    }
}

#[test]
fn threaded_parser_4x100() {
    use std::sync::Arc;
    use std::thread;
    let bytes: Arc<Vec<u8>> = Arc::new(header());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let b = Arc::clone(&bytes);
            thread::spawn(move || {
                for _ in 0..100 {
                    let m = WasmParser::parse(&b).unwrap();
                    assert_eq!(m.version, 1);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_leb_decoder_4x100() {
    use std::sync::Arc;
    use std::thread;
    let data: Arc<Vec<u8>> = Arc::new(uleb(123456789));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                for _ in 0..100 {
                    let mut dec = Leb128Decoder::new(&d);
                    assert_eq!(dec.read_u32().unwrap(), 123456789);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ── WasmModule helpers on empty module ──────────────────────────────────────

#[test]
fn module_function_type_oob_returns_none() {
    let m = WasmParser::parse(&header()).unwrap();
    assert!(m.function_type(0).is_none());
    assert!(m.function_type(u32::MAX).is_none());
}

#[test]
fn module_function_name_oob_returns_none() {
    let m = WasmParser::parse(&header()).unwrap();
    assert!(m.function_name(0).is_none());
}

#[test]
fn module_exported_function_missing() {
    let m = WasmParser::parse(&header()).unwrap();
    assert!(m.exported_function("nope").is_none());
    assert!(m.exported_function_names().is_empty());
}

#[test]
fn module_imports_from_empty() {
    let m = WasmParser::parse(&header()).unwrap();
    assert!(m.imports_from("env").is_empty());
}

#[test]
fn module_memory_pages_min_zero() {
    let m = WasmParser::parse(&header()).unwrap();
    assert_eq!(m.memory_pages_min(), 0);
    assert!(!m.has_start_function());
}

// ── WasmStats on empty module ───────────────────────────────────────────────

#[test]
fn stats_empty_module() {
    let m = WasmParser::parse(&header()).unwrap();
    let s = WasmStats::compute(&m);
    assert_eq!(s.function_count, 0);
    assert_eq!(s.import_count, 0);
    assert_eq!(s.export_count, 0);
    assert_eq!(s.data_size, 0);
    assert_eq!(s.code_size, 0);
    assert_eq!(s.custom_section_count, 0);
    assert!(!s.has_name_section);
    assert!(!s.has_dwarf);
    assert!(s.most_complex_function.is_none());
}

#[test]
fn stats_with_custom_section() {
    let mut bytes = header();
    let mut sec = Vec::new();
    let name = b".debug_info";
    sec.extend_from_slice(&uleb(name.len() as u64));
    sec.extend_from_slice(name);
    sec.extend_from_slice(&[0x00]);
    bytes.push(0);
    bytes.extend_from_slice(&uleb(sec.len() as u64));
    bytes.extend_from_slice(&sec);
    let m = WasmParser::parse(&bytes).unwrap();
    let s = WasmStats::compute(&m);
    assert!(s.has_dwarf);
    assert_eq!(s.custom_section_count, 1);
}

// ── WasmFunction local_count saturation ─────────────────────────────────────

#[test]
fn function_local_count_saturating() {
    let f = WasmFunction {
        index: 0,
        type_index: 0,
        func_type: None,
        locals: vec![
            WasmLocal {
                count: u32::MAX,
                val_type: WasmValType::I32,
            },
            WasmLocal {
                count: 5,
                val_type: WasmValType::I64,
            },
        ],
        code: vec![],
        offset_in_file: 0,
        size: 0,
        name: None,
    };
    assert_eq!(f.local_count(), u32::MAX);
    assert_eq!(f.code_size(), 0);
}
