//! Deep adversarial test suite for `rustre-flirt-gen` (Y057).
//!
//! Covers `PatternGenerator`, `ElfObjectParser`, `LibraryBuilder`, `SigWriter`,
//! `SigTrieNode`, `crc16_sig_header`, and `write_sig_file` via the lib.rs public API.

use rustre_flirt::{FlirtArch, FlirtOs, FlirtPattern, PatternByte, ReferencedName, FlirtName};
use rustre_flirt_gen::{
    PatternGenerator, RelocationEntry, LibraryBuilder, ElfObjectParser, GenError,
    SigWriter, SigTrieNode, crc16_sig_header, write_sig_file, GenerationStats,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

// ── Seeded LCG ───────────────────────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn random_bytes(g: &mut impl FnMut() -> u64, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push((g() & 0xff) as u8);
    }
    v
}

// ── PatternGenerator basics & boundaries ─────────────────────────────────────

#[test]
fn pg_default_is_new() {
    let a = PatternGenerator::default();
    let b = PatternGenerator::new();
    assert_eq!(a.initial_length, b.initial_length);
    assert_eq!(a.crc_length, b.crc_length);
}

#[test]
fn pg_one_byte_input() {
    let pg = PatternGenerator::new();
    let pat = pg.generate(&[0xCC], &[], vec![]).unwrap();
    assert_eq!(pat.initial_bytes.len(), 1);
    assert_eq!(pat.crc_length, 0);
    assert_eq!(pat.pattern_length, 1);
    assert!(pat.tail_bytes.is_empty());
}

#[test]
fn pg_exactly_initial_length() {
    let pg = PatternGenerator::new();
    let bytes: Vec<u8> = (0u8..32).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert_eq!(pat.initial_bytes.len(), 32);
    assert_eq!(pat.crc_length, 0);
    assert!(pat.tail_bytes.is_empty());
}

#[test]
fn pg_initial_plus_one() {
    let pg = PatternGenerator::new();
    let bytes: Vec<u8> = (0u8..33).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert_eq!(pat.initial_bytes.len(), 32);
    assert_eq!(pat.crc_length, 1);
    assert_eq!(pat.pattern_length, 33);
}

#[test]
fn pg_empty_is_err() {
    let pg = PatternGenerator::new();
    assert!(pg.generate(&[], &[], vec![]).is_err());
}

#[test]
fn pg_from_ranges_empty_is_err() {
    let pg = PatternGenerator::new();
    assert!(pg.generate_from_ranges(&[], &[], vec![], vec![]).is_err());
}

#[test]
fn pg_pattern_length_clamped_to_u16_max() {
    // Function longer than u16::MAX should clamp pattern_length to u16::MAX without panicking.
    let pg = PatternGenerator { initial_length: 8, crc_length: 4 };
    let bytes = vec![0xAAu8; (u16::MAX as usize) + 50];
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert_eq!(pat.pattern_length, u16::MAX);
}

#[test]
fn pg_zero_initial_length_no_crc() {
    let pg = PatternGenerator { initial_length: 0, crc_length: 16 };
    let bytes: Vec<u8> = (0u8..40).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert_eq!(pat.initial_bytes.len(), 0);
    assert!(pat.crc_length <= 16);
}

#[test]
fn pg_initial_bytes_preserve_byte_values() {
    let pg = PatternGenerator::new();
    let bytes: Vec<u8> = (0u8..32).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    for (i, b) in pat.initial_bytes.iter().enumerate() {
        assert_eq!(*b, PatternByte::Exact(u8::try_from(i).unwrap()));
    }
}

#[test]
fn pg_full_initial_block_relocated_wildcards_only() {
    let pg = PatternGenerator { initial_length: 8, crc_length: 4 };
    let bytes = vec![0x11u8; 16];
    let relocs = vec![RelocationEntry { offset: 0, size: 8 }];
    let pat = pg.generate(&bytes, &relocs, vec![]).unwrap();
    assert!(pat.initial_bytes.iter().all(|b| *b == PatternByte::Wildcard));
}

#[test]
fn pg_overlapping_relocs_still_safe() {
    let pg = PatternGenerator { initial_length: 8, crc_length: 0 };
    let bytes = vec![0x11u8; 8];
    let relocs = vec![
        RelocationEntry { offset: 0, size: 4 },
        RelocationEntry { offset: 2, size: 4 },
    ];
    let pat = pg.generate(&bytes, &relocs, vec![]).unwrap();
    for i in 0..6 {
        assert_eq!(pat.initial_bytes[i], PatternByte::Wildcard);
    }
}

#[test]
fn pg_reloc_past_initial_does_not_panic() {
    let pg = PatternGenerator { initial_length: 4, crc_length: 4 };
    let bytes = vec![0x11u8; 8];
    let relocs = vec![RelocationEntry { offset: 100, size: 4 }];
    // saturating_sub clamps end-start to 0 → no panic, no effect on initial.
    let pat = pg.generate(&bytes, &relocs, vec![]).unwrap();
    for b in &pat.initial_bytes {
        assert!(matches!(b, PatternByte::Exact(_)));
    }
}

// ── from_ranges semantics ────────────────────────────────────────────────────

#[test]
fn pg_from_ranges_crc_stable_under_mask() {
    let pg = PatternGenerator { initial_length: 4, crc_length: 8 };
    let base: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x33, 0x44, 0xC3, 0x90];
    let mut alt = base.clone();
    alt[4] = 0xFF; alt[6] = 0xEE;
    let pa = pg.generate_from_ranges(&base, &[(4, 4)], vec![], vec![]).unwrap();
    let pb = pg.generate_from_ranges(&alt,  &[(4, 4)], vec![], vec![]).unwrap();
    assert_eq!(pa.crc16, pb.crc16);
    assert_eq!(pa.crc_length, pb.crc_length);
}

#[test]
fn pg_from_ranges_attaches_referenced() {
    let pg = PatternGenerator::new();
    let bytes: Vec<u8> = (0u8..40).collect();
    let refs = vec![ReferencedName { offset: 5, name: "x".into() }];
    let pat = pg.generate_from_ranges(&bytes, &[], vec![], refs).unwrap();
    assert_eq!(pat.referenced_names.len(), 1);
}

#[test]
fn pg_from_ranges_no_post_initial_zero_crc() {
    let pg = PatternGenerator { initial_length: 8, crc_length: 16 };
    let bytes = vec![0xAAu8; 8];
    let pat = pg.generate_from_ranges(&bytes, &[], vec![], vec![]).unwrap();
    assert_eq!(pat.crc_length, 0);
    assert_eq!(pat.crc16, 0);
}

#[test]
fn pg_from_ranges_all_masked_post_initial_zero_crc() {
    let pg = PatternGenerator { initial_length: 4, crc_length: 4 };
    let bytes = vec![0xAAu8; 8];
    let pat = pg.generate_from_ranges(&bytes, &[(4, 4)], vec![], vec![]).unwrap();
    // every post-initial byte is masked → no CRC contribution.
    assert_eq!(pat.crc_length, 0);
    assert_eq!(pat.crc16, 0);
}

// ── Tail bytes ───────────────────────────────────────────────────────────────

#[test]
fn pg_tail_skips_relocated_bytes() {
    let pg = PatternGenerator { initial_length: 4, crc_length: 0 };
    let bytes = vec![0u8, 1, 2, 3, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let relocs = vec![RelocationEntry { offset: 5, size: 2 }]; // mask 5,6
    let pat = pg.generate(&bytes, &relocs, vec![]).unwrap();
    for tb in &pat.tail_bytes {
        assert!(tb.offset != 5 && tb.offset != 6);
    }
}

#[test]
fn pg_tail_capped_at_eight() {
    let pg = PatternGenerator { initial_length: 0, crc_length: 0 };
    let bytes: Vec<u8> = (0u8..100).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert!(pat.tail_bytes.len() <= 8);
}

// ── Round-trip property over many inputs ────────────────────────────────────

#[test]
fn pg_round_trip_many_inputs() {
    let pg = PatternGenerator::new();
    let mut g = lcg();
    for _ in 0..60 {
        let len = usize::try_from((g() % 200) + 1).unwrap();
        let bytes = random_bytes(&mut g, len);
        let pat = pg.generate(&bytes, &[], vec![]).unwrap();
        assert_eq!(pat.pattern_length as usize, len.min(u16::MAX as usize));
        // matches_initial must succeed against original bytes.
        assert!(pat.matches_initial(&bytes));
        assert!(pat.matches_crc16(&bytes));
    }
}

#[test]
fn pg_fuzz_never_panics() {
    let pg = PatternGenerator::new();
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() % 80) as usize;
        let bytes = random_bytes(&mut g, len);
        let nrelocs = (g() % 5) as usize;
        let mut relocs = Vec::new();
        for _ in 0..nrelocs {
            let off = u16::try_from(g() % 80).unwrap();
            let size = u8::try_from((g() % 8) + 1).unwrap();
            relocs.push(RelocationEntry { offset: off, size });
        }
        let r = pg.generate(&bytes, &relocs, vec![]);
        if bytes.is_empty() {
            assert!(r.is_err());
        } else {
            assert!(r.is_ok());
        }
    }
}

#[test]
fn pg_fuzz_from_ranges_never_panics() {
    let pg = PatternGenerator::new();
    let mut g = lcg();
    for _ in 0..150 {
        let len = (g() % 80) as usize;
        let bytes = random_bytes(&mut g, len);
        let nranges = (g() % 4) as usize;
        let mut ranges = Vec::new();
        for _ in 0..nranges {
            ranges.push((u16::try_from(g() % 64).unwrap(), u8::try_from((g() % 5) + 1).unwrap()));
        }
        let r = pg.generate_from_ranges(&bytes, &ranges, vec![], vec![]);
        if bytes.is_empty() { assert!(r.is_err()); } else { assert!(r.is_ok()); }
    }
}

// ── generate_batch ───────────────────────────────────────────────────────────

#[test]
fn batch_filters_empty_inputs() {
    let pg = PatternGenerator::new();
    let funcs = vec![
        ("ok".to_string(), vec![0x55u8, 0x48], vec![]),
        ("bad".to_string(), vec![], vec![]),
        ("ok2".to_string(), vec![0x90u8; 4], vec![]),
    ];
    let pats = pg.generate_batch(funcs);
    assert_eq!(pats.len(), 2);
}

// ── LibraryBuilder ───────────────────────────────────────────────────────────

#[test]
fn builder_processes_many_functions() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    let mut g = lcg();
    for i in 0..50 {
        let bytes = random_bytes(&mut g, 8 + (i % 16));
        b.add_function(format!("fn{i}"), &bytes, vec![]);
    }
    let (lib, stats) = b.build();
    assert_eq!(stats.functions_processed, 50);
    assert_eq!(stats.patterns_generated, 50);
    assert_eq!(lib.pattern_count(), 50);
}

#[test]
fn builder_dedup_idempotent() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
    for _ in 0..5 {
        b.add_function("foo".into(), &bytes, vec![]);
    }
    b.dedup_patterns();
    let before = b.build();
    // Re-build with dedup once again — already deduped.
    let mut b2 = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    b2.add_function("foo".into(), &bytes, vec![]);
    b2.dedup_patterns();
    let after = b2.build();
    assert_eq!(before.0.pattern_count(), after.0.pattern_count());
}

#[test]
fn builder_add_elf_object_rejects_garbage() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X86, FlirtOs::Linux);
    let r = b.add_elf_object(b"not-elf-data-at-all");
    assert!(r.is_err());
}

#[test]
fn builder_default_stats_zero() {
    let s = GenerationStats::default();
    assert_eq!(s.functions_processed, 0);
    assert_eq!(s.patterns_generated, 0);
    assert_eq!(s.patterns_skipped, 0);
    assert_eq!(s.duplicates_removed, 0);
}

// ── ELF parser boundaries / fuzz ─────────────────────────────────────────────

#[test]
fn elf_zero_length_err() {
    assert!(ElfObjectParser::parse(&[]).is_err());
}

#[test]
fn elf_only_magic_too_short() {
    assert!(ElfObjectParser::parse(b"\x7fELF").is_err());
}

#[test]
fn elf_bad_class_byte() {
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 99; // invalid EI_CLASS
    bytes[5] = 1;
    assert!(ElfObjectParser::parse(&bytes).is_err());
}

#[test]
fn elf_truncated_after_ident() {
    // EI_CLASS=2 (64), EI_DATA=1 (LE), then truncated header.
    let mut bytes = vec![0u8; 20];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    assert!(ElfObjectParser::parse(&bytes).is_err());
}

#[test]
fn elf_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() % 200) as usize;
        let mut bytes = random_bytes(&mut g, len);
        // Half the time, make it look ELF-ish to exercise deeper paths.
        if !bytes.is_empty() && bytes.len() >= 4 && (g() & 1) == 0 {
            bytes[..4].copy_from_slice(b"\x7fELF");
            if bytes.len() > 4 { bytes[4] = ((g() & 3) as u8) + 1; }
            if bytes.len() > 5 { bytes[5] = ((g() & 1) as u8) + 1; }
        }
        let _ = ElfObjectParser::parse(&bytes); // must not panic
    }
}

// ── SigWriter / write_sig_file ───────────────────────────────────────────────

#[test]
fn sig_writer_empty_header_structure() {
    let w = SigWriter::default();
    let out = w.build(&[], "lib");
    assert_eq!(&out[..6], b"IDASGN");
    assert_eq!(out[6], 9);
    let num = rustre_flirt::sig_header::SigFileHeader::decode(&out)
        .expect("header decodificabile")
        .n_functions;
    assert_eq!(num, 0);
}

#[test]
fn sig_writer_header_crc_matches() {
    let w = SigWriter { arch: 0, file_types: 0xDEAD_BEEF, os_types: 0x1234, ..SigWriter::default() };
    let out = w.build(&[], "x");
    let stored = u16::from_le_bytes(out[20..22].try_into().unwrap());
    assert_eq!(stored, crc16_sig_header(&out[..20]));
}

#[test]
fn sig_writer_with_50_functions() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    let mut g = lcg();
    for i in 0..50 {
        let bytes = random_bytes(&mut g, 12);
        b.add_function(format!("fn{i}"), &bytes, vec![]);
    }
    let (lib, _) = b.build();
    let w = SigWriter::default();
    let out = w.build(&lib.patterns, "biglib");
    let h = rustre_flirt::sig_header::SigFileHeader::decode(&out)
        .expect("header decodificabile");
    assert_eq!(h.n_functions, 50);
    assert!(out.len() > h.len_bytes(), "trie must extend past header");
}

#[test]
fn sig_writer_lib_name_is_not_zero_padded() {
    // The old fixed layout padded the name into a 64-byte window. IDA does not:
    // the name is exactly `library_name_len` bytes and the header ends there.
    let w = SigWriter::default();
    let out = w.build(&[], "abc");
    let h = rustre_flirt::sig_header::SigFileHeader::decode(&out)
        .expect("header decodificabile");
    assert_eq!(h.lib_name, "abc");
    assert_eq!(h.len_bytes(), 43 + 3, "nessun padding dopo il nome");
    assert_eq!(&out[43..46], b"abc");
}

#[test]
fn sig_writer_pattern_size_field_is_32() {
    let w = SigWriter::default();
    let out = w.build(&[], "x");
    let ps = rustre_flirt::sig_header::SigFileHeader::decode(&out)
        .expect("header decodificabile")
        .pattern_size;
    assert_eq!(ps, 32, "pattern_size sta a offset 41, non a 38");
}

#[test]
fn write_sig_file_io() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    b.add_function("f".into(), &[0x55u8, 0x48, 0x89, 0xE5, 0xC3], vec![]);
    let (lib, _) = b.build();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("o.sig");
    write_sig_file(&lib.patterns, "lib", 75, &path).unwrap();
    let r = std::fs::read(&path).unwrap();
    assert_eq!(&r[..6], b"IDASGN");
    assert_eq!(r[6], 9);
    assert_eq!(r[7], 75);
}

#[test]
fn write_sig_file_bad_path_err() {
    // A path inside a non-existent directory must produce GenError::Serialize.
    let p = std::path::Path::new("Z:/__definitely_missing__/abc/x.sig");
    let r = write_sig_file(&[], "lib", 0, p);
    assert!(matches!(r, Err(GenError::Serialize(_))));
}

// ── SigTrieNode encoding ─────────────────────────────────────────────────────

#[test]
fn trie_branch_with_children() {
    let n = SigTrieNode::Branch {
        prefix: vec![0x55, 0x48],
        children: vec![SigTrieNode::Leaf {
            prefix: vec![0x89],
            crc_len: 0,
            crc16: 0,
            module_offset: 0,
            func_name: "x".into(),
            tail: Vec::new(),
            tail_mask: Vec::new(),
        }],
    };
    let mut buf = Vec::new();
    n.encode(&mut buf);
    assert_eq!(buf[0], 2);
    assert_eq!(buf[1], 0x55);
    assert_eq!(buf[2], 0x48);
    // child sentinel
    assert_eq!(buf[3], 0x00);
}

#[test]
fn trie_leaf_truncates_long_name() {
    let long = "A".repeat(500);
    let n = SigTrieNode::Leaf {
        prefix: vec![],
        crc_len: 0,
        crc16: 0,
        module_offset: 0,
        func_name: long,
        tail: Vec::new(),
        tail_mask: Vec::new(),
    };
    let mut buf = Vec::new();
    n.encode(&mut buf);
    // Layout (must match sig_file_loader::read_leaf_payload):
    // [plen=0][flags=1][crc_offset BE(2)][crc_len][crc BE(2)][name_len=255][name…][0x00]
    assert_eq!(buf[0], 0);   // prefix length
    assert_eq!(buf[1], 1);   // flags
    assert_eq!(buf[7], 255); // name length saturated
    // +1 for the extra-names terminator, without which the decoder runs into
    // the following node (that omission was T31).
    assert_eq!(buf.len(), 8 + 255 + 1);
    assert_eq!(*buf.last().unwrap(), 0x00, "terminatore della lista nomi");
}

#[test]
fn trie_leaf_truncates_long_prefix() {
    let n = SigTrieNode::Leaf {
        prefix: vec![0xABu8; 300],
        crc_len: 0,
        crc16: 0,
        module_offset: 0,
        func_name: "f".into(),
        tail: Vec::new(),
        tail_mask: Vec::new(),
    };
    let mut buf = Vec::new();
    n.encode(&mut buf);
    assert_eq!(buf[0], 255); // saturated prefix length
}

// ── crc16_sig_header ─────────────────────────────────────────────────────────

#[test]
fn crc_sig_header_deterministic_30_pairs() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = usize::try_from((g() % 64) + 1).unwrap();
        let bytes = random_bytes(&mut g, len);
        let a = crc16_sig_header(&bytes);
        let b = crc16_sig_header(&bytes);
        assert_eq!(a, b);
    }
}

#[test]
fn crc_sig_header_empty_is_ffff() {
    // Initial value 0xFFFF, no bytes processed → 0xFFFF.
    assert_eq!(crc16_sig_header(&[]), 0xFFFF);
}

#[test]
fn crc_sig_header_changes_with_input() {
    let mut g = lcg();
    let mut seen = HashSet::new();
    for _ in 0..40 {
        let len = usize::try_from((g() % 32) + 4).unwrap();
        let bytes = random_bytes(&mut g, len);
        seen.insert(crc16_sig_header(&bytes));
    }
    assert!(seen.len() > 5, "CRC should vary across distinct inputs");
}

// ── GenError From<FlirtError> ────────────────────────────────────────────────

#[test]
fn gen_error_from_flirt_error() {
    let pg = PatternGenerator::new();
    let err = pg.generate(&[], &[], vec![]).unwrap_err();
    let ge: GenError = err.into();
    assert!(matches!(ge, GenError::InvalidPattern(_)));
}

#[test]
fn gen_error_eq_hash_consistency() {
    let a = GenError::Parse("x".into());
    let b = GenError::Parse("x".into());
    let c = GenError::Parse("y".into());
    assert_eq!(a, b);
    assert_ne!(a, c);
    // Display format mirrors error variant for both equal values.
    assert_eq!(format!("{a}"), format!("{b}"));
}

// ── RelocationEntry Eq ───────────────────────────────────────────────────────

#[test]
fn reloc_entry_eq_30_pairs() {
    let mut g = lcg();
    let mut equal = 0;
    let mut unequal = 0;
    for _ in 0..30 {
        let r1 = RelocationEntry { offset: (g() & 0xff) as u16, size: (g() & 7) as u8 };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
        equal += 1;
        let r3 = RelocationEntry { offset: r1.offset.wrapping_add(1), size: r1.size };
        if r3 != r1 { unequal += 1; }
    }
    assert!(equal > 0 && unequal > 0);
}

// ── Threaded stress: PatternGenerator is Send+Sync (no interior mutability). ─

#[test]
fn pg_send_sync_threaded() {
    let pg = Arc::new(PatternGenerator::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let pg = Arc::clone(&pg);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE ^ u64::try_from(t).unwrap();
            let mut g = || {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                s
            };
            for _ in 0..100 {
                let len = usize::try_from((g() % 64) + 1).unwrap();
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len { bytes.push(u8::try_from(g() & 0xff).unwrap()); }
                let p = pg.generate(&bytes, &[], vec![]).unwrap();
                assert!(p.matches_initial(&bytes));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn sig_writer_send_sync_threaded() {
    let w = Arc::new(SigWriter::default());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let w = Arc::clone(&w);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let out = w.build(&[], "x");
                assert_eq!(&out[..6], b"IDASGN");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── FlirtName-bearing pattern carries primary_name through builder ───────────

#[test]
fn builder_pattern_has_primary_name() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    b.add_function("named".into(), &[0x55u8, 0x48, 0x89, 0xE5], vec![]);
    let (lib, _) = b.build();
    assert_eq!(lib.patterns[0].primary_name(), Some("named"));
}

#[test]
fn generate_with_supplied_names_preserved() {
    let pg = PatternGenerator::new();
    let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
    let names = vec![FlirtName { name: "primary".into(), offset: 0, is_public: true, is_local: false }];
    let pat = pg.generate(&bytes, &[], names).unwrap();
    assert_eq!(pat.primary_name(), Some("primary"));
}

// ── FlirtPattern.matches_initial via generated wildcards ────────────────────

#[test]
fn matches_initial_holds_under_relocation_replacement() {
    let pg = PatternGenerator { initial_length: 8, crc_length: 0 };
    let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x33, 0x44];
    let pat = pg.generate(&bytes, &[RelocationEntry { offset: 4, size: 4 }], vec![]).unwrap();
    // Replacement of masked bytes still matches.
    let mut alt = bytes.clone();
    alt[4] = 0xAA; alt[5] = 0xBB; alt[6] = 0xCC; alt[7] = 0xDD;
    assert!(pat.matches_initial(&alt));
    // Replacement of non-masked byte breaks the match.
    let mut bad = bytes;
    bad[0] = 0xFF;
    assert!(!pat.matches_initial(&bad));
}

// ── pattern_hex deterministic length ─────────────────────────────────────────

#[test]
fn pattern_hex_length_matches_initial_bytes() {
    let pg = PatternGenerator::new();
    let pat = pg.generate(&[0x55u8, 0x48, 0x89, 0xE5], &[], vec![]).unwrap();
    let hx = pat.pattern_hex();
    // 4 hex tokens joined by 3 spaces = 4*2 + 3 = 11
    assert_eq!(hx.len(), 11);
}

#[test]
fn flirt_pattern_new_zero_state() {
    // Use FlirtPattern type explicitly to anchor it in scope.
    let p: FlirtPattern = FlirtPattern::new(vec![PatternByte::Exact(0xAA)]);
    assert_eq!(p.crc16, 0);
    assert_eq!(p.crc_length, 0);
    assert_eq!(p.pattern_length, 0);
    assert!(p.names.is_empty());
}
