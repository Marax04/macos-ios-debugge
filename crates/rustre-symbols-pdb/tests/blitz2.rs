//! blitz2 — deep adversarial tests for rustre-symbols-pdb root API and `stream_reader`.
//!
//! Covers:
//!   - `PdbGuid::to_string_fmt`: round-trip / format invariants
//!   - `PdbReader::from_bytes`: `BadMagic` on truncated / random data, LCG fuzz never panics
//!   - `PdbStreamReader::parse_pdb_info` / `parse_stream_names`: never panic on fuzz
//!   - `PdbPublicSymbolScanner::scan_public_symbols`: empty/garbage safe
//!   - `StreamReader`: `read_u8/16/32/64` boundaries, seek/skip/align, cstring, length-prefixed,
//!     `numeric_leaf`, slice/peek
//!   - `StringTable`: `from_stream` behavior, `get()` bounds
//!   - `RecordHeader`: `total_size` / `payload_size` invariants
//!   - Hash/Eq on `PdbSymbol`, `PdbType`, `PdbModule`, `PdbGuid`, `PdbAge`, `PdbPublicSymbol`
//!   - Send + Sync threaded stress
//!   - serde round-trip for serializable types

use rustre_symbols_pdb::{
    PdbAge, PdbError, PdbGuid, PdbModule, PdbPublicSymbol, PdbPublicSymbolScanner, PdbReader,
    PdbStreamInfo, PdbStreamReader, PdbSymbol, PdbType, SymbolKind, TypeKind, stream_indices,
};
use rustre_symbols_pdb::stream_reader::{RecordHeader, StreamReader, StringTable};

// ── Seeded LCG (no rand, no std::time) ───────────────────────────────────────

fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn rand_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut g = make_lcg(seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let v = g();
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ── PdbGuid ──────────────────────────────────────────────────────────────────

#[test]
fn guid_format_length_is_38() {
    for seed in 0..50u64 {
        let bytes = rand_bytes(0xAAAA_0000 ^ seed, 16);
        let mut data = [0u8; 16];
        data.copy_from_slice(&bytes);
        let g = PdbGuid { data };
        let s = g.to_string_fmt();
        assert_eq!(s.len(), 38, "seed={seed}");
        assert!(s.starts_with('{') && s.ends_with('}'));
        let inside = &s[1..s.len() - 1];
        let parts: Vec<&str> = inside.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }
}

#[test]
fn guid_format_zero_and_max() {
    let zero = PdbGuid { data: [0u8; 16] };
    assert_eq!(zero.to_string_fmt(), "{00000000-0000-0000-0000-000000000000}");
    let max = PdbGuid { data: [0xFFu8; 16] };
    assert_eq!(max.to_string_fmt(), "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}");
}

#[test]
fn guid_eq_and_copy() {
    let g1 = PdbGuid { data: [1u8; 16] };
    let g2 = g1; // Copy
    assert_eq!(g1, g2);
    let g3 = PdbGuid { data: [2u8; 16] };
    assert_ne!(g1, g3);
}

#[test]
fn guid_serde_round_trip() {
    let g = PdbGuid {
        data: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ],
    };
    let j = serde_json::to_string(&g).unwrap();
    let back: PdbGuid = serde_json::from_str(&j).unwrap();
    assert_eq!(g, back);
}

// ── PdbAge ───────────────────────────────────────────────────────────────────

#[test]
fn age_boundary_values() {
    assert_eq!(PdbAge(0).0, 0);
    assert_eq!(PdbAge(1).0, 1);
    assert_eq!(PdbAge(u32::MAX).0, u32::MAX);
    assert_eq!(PdbAge(42), PdbAge(42));
    assert_ne!(PdbAge(0), PdbAge(1));
}

// ── PdbReader::from_bytes adversarial ────────────────────────────────────────

#[test]
fn reader_bad_magic_on_zeros() {
    for size in [0usize, 1, 31, 32, 55, 56, 64, 1024] {
        let data = vec![0u8; size];
        let r = PdbReader::from_bytes(&data);
        assert!(r.is_err(), "size={size} should be err");
    }
}

#[test]
fn reader_lcg_fuzz_never_panics() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = usize::try_from(g()).unwrap_or(0) % 4096;
        let data = rand_bytes(g(), len);
        // Must return Result, not panic.
        let _ = PdbReader::from_bytes(&data);
    }
}

#[test]
fn reader_truncated_after_magic() {
    let mut buf = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00".to_vec();
    // Truncated — no block size etc.
    assert!(PdbReader::from_bytes(&buf).is_err());
    // Zero block size after magic.
    buf.extend_from_slice(&[0u8; 24]);
    assert!(matches!(
        PdbReader::from_bytes(&buf),
        Err(PdbError::CorruptData | PdbError::BadMagic | PdbError::StreamTooShort)
    ));
}

#[test]
fn reader_oversized_input_safe() {
    let mut data = vec![0u8; 65536];
    data[0..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00");
    // Random fields — must not panic.
    let mut g = make_lcg(0x1234_5678);
    for _ in 0..50 {
        for byte in &mut data[32..64] {
            *byte = (g() & 0xFF) as u8;
        }
        let _ = PdbReader::from_bytes(&data);
    }
}

// ── PdbStreamReader adversarial ──────────────────────────────────────────────

#[test]
fn stream_reader_parse_info_none_on_garbage() {
    for seed in 0..30u64 {
        let len = ((seed * 37) % 200) as usize;
        let data = rand_bytes(seed, len);
        let _ = PdbStreamReader::parse_pdb_info(&data); // never panic
    }
    assert!(PdbStreamReader::parse_pdb_info(&[]).is_none());
    assert!(PdbStreamReader::parse_pdb_info(&[0u8; 27]).is_none());
}

#[test]
fn stream_reader_parse_stream_names_empty_on_garbage() {
    for seed in 0..30u64 {
        let len = ((seed * 41) % 300) as usize;
        let data = rand_bytes(seed ^ 0xBEEF, len);
        let m = PdbStreamReader::parse_stream_names(&data);
        assert!(m.is_empty());
    }
}

// ── PdbPublicSymbolScanner ───────────────────────────────────────────────────

#[test]
fn public_scanner_garbage_safe() {
    for seed in 0..30u64 {
        let len = ((seed * 53) % 400) as usize;
        let data = rand_bytes(seed ^ 0xCAFE, len);
        let v = PdbPublicSymbolScanner::scan_public_symbols(&data);
        assert!(v.is_empty(), "seed={seed} returned {} syms", v.len());
    }
}

// ── SymbolKind / TypeKind hash & eq ──────────────────────────────────────────

#[test]
fn symbol_kind_eq_matrix() {
    let kinds = [
        SymbolKind::Function,
        SymbolKind::Data,
        SymbolKind::Label,
        SymbolKind::Thunk,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn symbol_kind_copy_and_clone() {
    let k = SymbolKind::Function;
    let k2 = k; // Copy
    let k3 = k;
    assert_eq!(k, k2);
    assert_eq!(k, k3);
}

#[test]
fn type_kind_variants_ne() {
    let kinds = [TypeKind::Primitive,
        TypeKind::Pointer,
        TypeKind::Array,
        TypeKind::Function,
        TypeKind::Struct { fields: vec!["a".into()] },
        TypeKind::Union { fields: vec!["b".into()] },
        TypeKind::Enum { variants: vec!["c".into()] }];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

// ── PdbSymbol / PdbType / PdbModule eq + clone + serde ───────────────────────

#[test]
fn pdb_symbol_eq_pairs() {
    let pairs: Vec<(PdbSymbol, PdbSymbol)> = (0..30)
        .map(|i| {
            let s = PdbSymbol {
                name: format!("sym_{i}"),
                address: 0x1000 + u64::try_from(i).unwrap(),
                size: u32::try_from(i).unwrap(),
                kind: if i % 2 == 0 {
                    SymbolKind::Function
                } else {
                    SymbolKind::Data
                },
            };
            (s.clone(), s)
        })
        .collect();
    for (a, b) in &pairs {
        assert_eq!(a, b);
    }
    // Distinct cross-pairs differ.
    for i in 0..pairs.len() {
        for j in 0..pairs.len() {
            if i != j {
                assert_ne!(pairs[i].0, pairs[j].0);
            }
        }
    }
}

#[test]
fn pdb_type_serde_round_trip() {
    let t = PdbType {
        name: "MyStruct".to_string(),
        kind: TypeKind::Struct {
            fields: vec!["a".into(), "b".into()],
        },
        size: 16,
    };
    let j = serde_json::to_string(&t).unwrap();
    let back: PdbType = serde_json::from_str(&j).unwrap();
    assert_eq!(t, back);
}

#[test]
fn pdb_module_eq_and_clone() {
    let m = PdbModule {
        name: "module.obj".into(),
        object_file: "foo.lib".into(),
        stream_index: 17,
    };
    assert_eq!(m, m.clone());
    let m2 = PdbModule {
        stream_index: 18,
        ..m.clone()
    };
    assert_ne!(m, m2);
}

#[test]
fn public_symbol_eq_pairs() {
    let mut v: Vec<PdbPublicSymbol> = Vec::new();
    let mut g = make_lcg(0xABCD_1234);
    for i in 0..30 {
        v.push(PdbPublicSymbol {
            name: format!("sym{i}"),
            offset: u32::try_from(g() & 0xFFFF_FFFF).unwrap(),
            section: u16::try_from(g() & 0xFFFF).unwrap(),
        });
    }
    for s in &v {
        assert_eq!(s, &s.clone());
    }
}

// ── stream_indices constants ─────────────────────────────────────────────────

#[test]
fn stream_indices_distinct() {
    let s = [
        stream_indices::OLD_DIRECTORY,
        stream_indices::PDB_INFO,
        stream_indices::TPI,
        stream_indices::DBI,
        stream_indices::IPI,
    ];
    for i in 0..s.len() {
        for j in i + 1..s.len() {
            assert_ne!(s[i], s[j]);
        }
    }
}

// ── PdbStreamInfo serde ──────────────────────────────────────────────────────

#[test]
fn stream_info_serde_round_trip() {
    let info = PdbStreamInfo {
        version: 20_000_404,
        signature: 0xDEAD_BEEF,
        age: 7,
        guid: [9u8; 16],
    };
    let j = serde_json::to_string(&info).unwrap();
    let back: PdbStreamInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(info, back);
}

// ── StreamReader: positional invariants ──────────────────────────────────────

#[test]
fn stream_reader_new_state() {
    let data = [0u8; 0];
    let r = StreamReader::new(&data);
    assert_eq!(r.pos(), 0);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
    assert_eq!(r.remaining(), 0);
}

#[test]
fn stream_reader_seek_clamps() {
    let data = [0u8; 10];
    let mut r = StreamReader::new(&data);
    r.seek(100);
    assert_eq!(r.pos(), 10);
    r.seek(5);
    assert_eq!(r.pos(), 5);
    r.seek(0);
    assert_eq!(r.pos(), 0);
}

#[test]
fn stream_reader_skip_bounds() {
    let data = [0u8; 8];
    let mut r = StreamReader::new(&data);
    assert!(r.skip(4).is_ok());
    assert_eq!(r.pos(), 4);
    assert!(r.skip(4).is_ok());
    assert_eq!(r.pos(), 8);
    assert!(r.skip(1).is_err());
}

#[test]
fn stream_reader_align_behaviour() {
    let data = [0u8; 16];
    let mut r = StreamReader::new(&data);
    r.seek(3);
    r.align(4);
    assert_eq!(r.pos(), 4);
    r.seek(7);
    r.align(4);
    assert_eq!(r.pos(), 8);
    r.seek(4);
    r.align(4); // already aligned
    assert_eq!(r.pos(), 4);
    r.seek(2);
    r.align(1); // no-op
    assert_eq!(r.pos(), 2);
    r.seek(2);
    r.align(0); // no-op (treated as <=1)
    assert_eq!(r.pos(), 2);
}

#[test]
fn stream_reader_read_u8_boundary() {
    let data = [0x01u8, 0x80, 0xFF];
    let mut r = StreamReader::new(&data);
    assert_eq!(r.read_u8().unwrap(), 0x01);
    assert_eq!(r.read_u8().unwrap(), 0x80);
    assert_eq!(r.read_u8().unwrap(), 0xFF);
    assert!(r.read_u8().is_err());
}

#[test]
fn stream_reader_read_u16_round_trip() {
    let values: [u16; 7] = [0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF, 0x1234];
    let mut buf = Vec::new();
    for v in &values {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    let mut r = StreamReader::new(&buf);
    for v in &values {
        assert_eq!(r.read_u16().unwrap(), *v);
    }
    assert!(r.read_u16().is_err());
}

#[test]
fn stream_reader_read_u32_u64_i_variants() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    buf.extend_from_slice(&(-1i32).to_le_bytes());
    buf.extend_from_slice(&u64::MAX.to_le_bytes());
    buf.extend_from_slice(&(i64::MIN).to_le_bytes());
    buf.extend_from_slice(&(-2i16).to_le_bytes());
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
    assert_eq!(r.read_i32().unwrap(), -1);
    assert_eq!(r.read_u64().unwrap(), u64::MAX);
    assert_eq!(r.read_i64().unwrap(), i64::MIN);
    assert_eq!(r.read_i16().unwrap(), -2);
}

#[test]
fn stream_reader_read_bytes_and_peek() {
    let data = [1u8, 2, 3, 4, 5];
    let mut r = StreamReader::new(&data);
    let peek = r.peek_bytes(3).unwrap();
    assert_eq!(peek, &[1, 2, 3]);
    assert_eq!(r.pos(), 0);
    let got = r.read_bytes(3).unwrap();
    assert_eq!(got, &[1, 2, 3]);
    assert_eq!(r.pos(), 3);
    assert!(r.read_bytes(3).is_err());
    assert!(r.peek_bytes(10).is_err());
}

#[test]
fn stream_reader_read_cstring_terminated_and_unterminated() {
    let data = b"hello\x00world";
    let mut r = StreamReader::new(data);
    assert_eq!(r.read_cstring().unwrap(), "hello");
    assert_eq!(r.pos(), 6);
    // Remainder has no NUL — read until end without error.
    assert_eq!(r.read_cstring().unwrap(), "world");
    assert!(r.is_empty());
}

#[test]
fn stream_reader_length_prefixed_string() {
    let mut buf = Vec::new();
    buf.push(5u8);
    buf.extend_from_slice(b"hello");
    buf.push(0u8);
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_length_prefixed_string().unwrap(), "hello");
    assert_eq!(r.read_length_prefixed_string().unwrap(), "");
    // Now a length that runs past end.
    let buf2 = [10u8, b'a', b'b'];
    let mut r2 = StreamReader::new(&buf2);
    assert!(r2.read_length_prefixed_string().is_err());
}

#[test]
fn stream_reader_numeric_leaf_small() {
    // tag < 0x8000 → value is the tag itself.
    let buf = 0x1234u16.to_le_bytes();
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_numeric_leaf().unwrap(), 0x1234);
}

#[test]
fn stream_reader_numeric_leaf_long() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x8003u16.to_le_bytes()); // LF_LONG
    buf.extend_from_slice(&(-12345i32).to_le_bytes());
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_numeric_leaf().unwrap(), -12345);
}

#[test]
fn stream_reader_numeric_leaf_ushort_and_ulong() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x8002u16.to_le_bytes()); // LF_USHORT
    buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
    buf.extend_from_slice(&0x8004u16.to_le_bytes()); // LF_ULONG
    buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_numeric_leaf().unwrap(), 0xFFFF);
    assert_eq!(r.read_numeric_leaf().unwrap(), 0xDEAD_BEEF);
}

#[test]
fn stream_reader_numeric_leaf_quadword() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x8009u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_numeric_leaf().unwrap(), -1);
}

#[test]
fn stream_reader_numeric_leaf_unknown_returns_zero() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x9999u16.to_le_bytes()); // unknown tag
    buf.extend_from_slice(&[0u8; 4]);
    let mut r = StreamReader::new(&buf);
    assert_eq!(r.read_numeric_leaf().unwrap(), 0);
}

#[test]
fn stream_reader_slice_and_remaining_data() {
    let data = [1u8, 2, 3, 4, 5];
    let r = StreamReader::new(&data);
    assert_eq!(r.slice(1, 4).unwrap(), &[2, 3, 4]);
    assert!(r.slice(0, 100).is_err());
    assert_eq!(r.remaining_data(), &data[..]);
    let mut r2 = StreamReader::new(&data);
    let _ = r2.skip(2);
    assert_eq!(r2.remaining_data(), &[3, 4, 5]);
}

#[test]
fn stream_reader_lcg_fuzz_never_panics() {
    let mut g = make_lcg(0xF00D_F00D_F00D_F00D);
    for _ in 0..200 {
        let len = usize::try_from(g()).unwrap_or(0) % 256;
        let data = rand_bytes(g(), len);
        let mut r = StreamReader::new(&data);
        for _ in 0..20 {
            let op = g() % 10;
            match op {
                0 => {
                    let _ = r.read_u8();
                }
                1 => {
                    let _ = r.read_u16();
                }
                2 => {
                    let _ = r.read_u32();
                }
                3 => {
                    let _ = r.read_u64();
                }
                4 => {
                    let _ = r.read_cstring();
                }
                5 => {
                    let _ = r.read_length_prefixed_string();
                }
                6 => {
                    let n = usize::try_from(g()).unwrap_or(0) % 8;
                    let _ = r.skip(n);
                }
                7 => {
                    let p = usize::try_from(g()).unwrap_or(0) % 64;
                    r.seek(p);
                }
                8 => r.align(4),
                _ => {
                    let _ = r.read_numeric_leaf();
                }
            }
        }
    }
}

// ── StringTable ──────────────────────────────────────────────────────────────

#[test]
fn string_table_from_short_stream_empty_heap() {
    let st = StringTable::from_stream(&[]);
    assert_eq!(st.heap_size(), 0);
    assert!(st.get(0).is_none());
    let st2 = StringTable::from_stream(&[0u8; 8]); // exactly 8 → still empty
    assert_eq!(st2.heap_size(), 0);
}

#[test]
fn string_table_get_normal() {
    let mut data = vec![0u8; 8]; // header
    data.extend_from_slice(b"\x00hello\x00world\x00");
    let st = StringTable::from_stream(&data);
    // heap_size = len - 8
    assert_eq!(st.heap_size(), 13);
    // offset 0 → empty string (NUL at offset 0)
    assert_eq!(st.get(0), Some(""));
    // offset 1 → "hello"
    assert_eq!(st.get(1), Some("hello"));
    // offset 7 → "world"
    assert_eq!(st.get(7), Some("world"));
}

#[test]
fn string_table_out_of_range() {
    let mut data = vec![0u8; 8];
    data.extend_from_slice(b"abc\x00");
    let st = StringTable::from_stream(&data);
    assert!(st.get(100).is_none());
    assert!(st.get(u32::MAX).is_none());
}

#[test]
fn string_table_new_default() {
    let st = StringTable::new();
    assert_eq!(st.heap_size(), 0);
    assert!(st.get(0).is_none());
}

// ── RecordHeader ─────────────────────────────────────────────────────────────

#[test]
fn record_header_size_invariants() {
    let cases: [u16; 6] = [2, 4, 10, 100, 0xFFFE, 0xFFFF];
    for &len in &cases {
        let h = RecordHeader { length: len, kind: 0x1234 };
        assert_eq!(h.total_size(), 2 + len as usize);
        assert_eq!(h.payload_size(), h.total_size().saturating_sub(4));
    }
}

#[test]
fn record_header_payload_saturates() {
    let h = RecordHeader { length: 0, kind: 0 };
    assert_eq!(h.total_size(), 2);
    // payload_size saturates at 0 for short total_size.
    assert_eq!(h.payload_size(), 0);
    let h2 = RecordHeader { length: 1, kind: 0 };
    assert_eq!(h2.total_size(), 3);
    assert_eq!(h2.payload_size(), 0);
}

#[test]
fn record_header_read_round_trip() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&10u16.to_le_bytes());
    buf.extend_from_slice(&0x1505u16.to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]);
    let mut r = StreamReader::new(&buf);
    let h = RecordHeader::read(&mut r).unwrap();
    assert_eq!(h.length, 10);
    assert_eq!(h.kind, 0x1505);
}

#[test]
fn record_header_read_short_errors() {
    let buf = [0u8, 1];
    let mut r = StreamReader::new(&buf);
    assert!(RecordHeader::read(&mut r).is_err());
}

// ── Error Display ────────────────────────────────────────────────────────────

#[test]
fn error_display_strings() {
    let e1 = PdbError::BadMagic;
    assert!(format!("{e1}").contains("MSF magic"));
    let e2 = PdbError::UnsupportedVersion;
    assert!(format!("{e2}").contains("Unsupported"));
    let e3 = PdbError::StreamOutOfRange(7);
    assert!(format!("{e3}").contains('7'));
    let e4 = PdbError::CorruptData;
    assert!(format!("{e4}").contains("Corrupt"));
    let e5 = PdbError::StreamTooShort;
    assert!(format!("{e5}").contains("short"));
}

// ── Send + Sync threaded stress ──────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<PdbSymbol>();
    assert_send_sync::<PdbType>();
    assert_send_sync::<PdbModule>();
    assert_send_sync::<PdbGuid>();
    assert_send_sync::<PdbAge>();
    assert_send_sync::<PdbPublicSymbol>();
    assert_send_sync::<PdbStreamInfo>();
    assert_send_sync::<PdbReader>();
}

#[test]
fn threaded_stress_guid_format() {
    use std::sync::Arc;
    let guid = Arc::new(PdbGuid { data: [0x55; 16] });
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let g = Arc::clone(&guid);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let s = g.to_string_fmt();
                assert_eq!(s.len(), 38, "thread {t} iter {i}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_stress_stream_reader_fuzz() {
    use std::sync::Arc;
    let data: Arc<Vec<u8>> = Arc::new(rand_bytes(0x1111_2222_3333_4444, 4096));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let d = Arc::clone(&data);
        handles.push(std::thread::spawn(move || {
            let mut g = make_lcg(0xABCDu64.wrapping_mul(t + 1));
            for _ in 0..100 {
                let mut r = StreamReader::new(&d);
                let p = usize::try_from(g()).unwrap_or(0) % d.len();
                r.seek(p);
                let _ = r.read_u32();
                let _ = r.read_cstring();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_stress_public_scanner() {
    use std::sync::Arc;
    let data: Arc<Vec<u8>> = Arc::new(rand_bytes(0xBADD_F00D_DEAD_BEEF, 1024));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let v = PdbPublicSymbolScanner::scan_public_symbols(&d);
                assert!(v.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── PdbReader round-trip on hand-built minimal PDB ───────────────────────────
//
// Build a minimal MSF v7 container with stream 1 containing valid Info data,
// confirm PdbReader::from_bytes succeeds and exposes guid/age correctly.

fn build_minimal_pdb(age: u32, guid_bytes: [u8; 16]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 512;
    // Layout (block-numbered):
    //  block 0: superblock
    //  block 1: stream-directory page
    //  block 2: block-map (lists [1] as the directory page)
    //  block 3: stream 0 data (old directory, empty)
    //  block 4: stream 1 data (Info stream)
    let mut buf = vec![0u8; BLOCK_SIZE * 5];

    // Superblock
    buf[0..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00");
    buf[32..36].copy_from_slice(&u32::try_from(BLOCK_SIZE).unwrap().to_le_bytes()); // block_size
    buf[36..40].copy_from_slice(&1u32.to_le_bytes()); // free_block_map_block
    buf[40..44].copy_from_slice(&5u32.to_le_bytes()); // num_blocks
    // num_dir_bytes — fits in 1 block.
    // Directory layout: num_streams(4) + sizes[num_streams](4*n) + per-stream block lists
    //   num_streams = 2 (streams 0 and 1)
    //   sizes: stream 0 = 0, stream 1 = 28 (info header)
    //   stream 0 block list: none (size 0)
    //   stream 1 block list: [4]   (1 block, holds 28 bytes)
    // = 4 + 4 + 4 + 4 = 16 bytes.
    buf[44..48].copy_from_slice(&16u32.to_le_bytes()); // num_dir_bytes
    buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // reserved
    buf[52..56].copy_from_slice(&2u32.to_le_bytes()); // block_map_addr = block 2

    // Directory at block 1.
    let dir = BLOCK_SIZE;
    buf[dir..dir + 4].copy_from_slice(&2u32.to_le_bytes()); // num_streams = 2
    buf[dir + 4..dir + 8].copy_from_slice(&0u32.to_le_bytes()); // stream 0 size
    buf[dir + 8..dir + 12].copy_from_slice(&28u32.to_le_bytes()); // stream 1 size
    // stream 0 has 0 blocks (no entries)
    // stream 1 has 1 block = 4
    buf[dir + 12..dir + 16].copy_from_slice(&4u32.to_le_bytes());

    // Block-map at block 2: lists block 1 as the directory page.
    let bm = 2 * BLOCK_SIZE;
    buf[bm..bm + 4].copy_from_slice(&1u32.to_le_bytes());

    // Stream 1 (Info) data at block 4.
    let info = 4 * BLOCK_SIZE;
    buf[info..info + 4].copy_from_slice(&20_000_404u32.to_le_bytes()); // version
    buf[info + 4..info + 8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // signature
    buf[info + 8..info + 12].copy_from_slice(&age.to_le_bytes()); // age
    buf[info + 12..info + 28].copy_from_slice(&guid_bytes); // guid

    buf
}

#[test]
fn reader_roundtrip_minimal_pdb() {
    let guid = [
        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    let pdb = build_minimal_pdb(42, guid);
    let r = PdbReader::from_bytes(&pdb).expect("minimal pdb should parse");
    assert_eq!(r.age().0, 42);
    assert_eq!(r.guid().data, guid);
    // No symbols/types/modules since streams 2 and 3 don't exist.
    assert!(r.symbols().is_empty());
    assert!(r.types().is_empty());
    assert!(r.modules().is_empty());
}

#[test]
fn reader_roundtrip_50_ages() {
    let mut g = make_lcg(0x9999_1111_2222_3333);
    for _ in 0..50 {
        let age = u32::try_from(g() & 0xFFFF_FFFF).unwrap();
        let mut guid = [0u8; 16];
        for b in &mut guid {
            *b = u8::try_from(g() & 0xFF).unwrap();
        }
        let pdb = build_minimal_pdb(age, guid);
        let r = PdbReader::from_bytes(&pdb).expect("must parse");
        assert_eq!(r.age().0, age);
        assert_eq!(r.guid().data, guid);
    }
}

#[test]
fn stream_info_via_stream_reader() {
    let guid = [0xAAu8; 16];
    let pdb = build_minimal_pdb(7, guid);
    let info = PdbStreamReader::parse_pdb_info(&pdb).expect("must parse");
    assert_eq!(info.version, 20_000_404);
    assert_eq!(info.signature, 0xDEAD_BEEF);
    assert_eq!(info.age, 7);
    assert_eq!(info.guid, guid);
}
