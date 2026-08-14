//! Blitz integration tests for rustre-flirt-gen.
//! Focused on round-trips, boundaries, and adversarial parser input.

use rustre_flirt::{FlirtArch, FlirtName, FlirtOs, FlirtPattern, PatternByte};
use rustre_flirt_gen::compiler_profile::{
    self as cp, CallingConvention, CompilerProfile, ProfileArch, ProfileOs, ProfileRegistry,
    ProloguePattern,
};
use rustre_flirt_gen::pat_sig_format::{
    crc16, pat_records_to_sig, PatFile, PatRecord, SigFile, SigHeader, SigModule, SigRef,
};
use rustre_flirt_gen::{
    crc16_sig_header, write_sig_file, ElfObjectParser, GenError, LibraryBuilder,
    PatternGenerator, RelocationEntry, SigTrieNode, SigWriter,
};

// ── crc16 (pat_sig_format) ────────────────────────────────────────────────────

#[test]
fn crc16_empty_is_initial_value() {
    // FLIRT poly 0x8408 initial 0xFFFF, no input → CRC stays 0xFFFF.
    assert_eq!(crc16(&[]), 0xFFFF);
}

#[test]
fn crc16_deterministic() {
    let data = b"abcdefghij";
    assert_eq!(crc16(data), crc16(data));
}

#[test]
fn crc16_changes_on_input_change() {
    assert_ne!(crc16(b"abc"), crc16(b"abd"));
}

// ── PatRecord round-trip ──────────────────────────────────────────────────────

#[test]
fn pat_record_roundtrip_simple() {
    let r = PatRecord::new("558BEC", 0x1234, 0x10, 0x0040, "foo");
    let line = r.to_pat_line();
    let parsed = PatRecord::from_pat_line(&line).expect("must parse own line");
    assert_eq!(parsed.hex_pattern, r.hex_pattern);
    assert_eq!(parsed.crc16, r.crc16);
    assert_eq!(parsed.crc_len, r.crc_len);
    assert_eq!(parsed.total_len, r.total_len);
    assert_eq!(parsed.name, r.name);
}

#[test]
fn pat_record_roundtrip_large_total_len() {
    // total_len rendered as {:04X}; values > 0xFFFF use wider rendering, but
    // hex parsing should still round-trip exactly.
    let r = PatRecord::new("AA", 0xBEEF, 0xFF, 0x12345, "big_func");
    let line = r.to_pat_line();
    let parsed = PatRecord::from_pat_line(&line).expect("parse");
    assert_eq!(parsed.total_len, 0x12345);
}

#[test]
fn pat_record_from_pat_line_returns_none_on_too_few_fields() {
    assert!(PatRecord::from_pat_line("aa bb cc dd").is_none());
}

#[test]
fn pat_record_from_pat_line_returns_none_on_bad_hex() {
    assert!(PatRecord::from_pat_line("AA ZZZZ 10 0040 foo").is_none());
}

#[test]
fn pat_record_from_bytes_pattern_len_caps_at_input_size() {
    let bytes = [0x55, 0x48, 0x89];
    let r = PatRecord::from_bytes(&bytes, "foo", 32, 16);
    // pat_len = min(3, 32) = 3 ⇒ hex is "554889"
    assert_eq!(r.hex_pattern, "554889");
    assert_eq!(r.total_len, 3);
    assert_eq!(r.crc_len, 0);
}

#[test]
fn pat_record_from_bytes_crc_window_caps_at_remaining_bytes() {
    let bytes: Vec<u8> = (0u8..40).collect();
    let r = PatRecord::from_bytes(&bytes, "foo", 32, 100);
    // crc region is bytes[32..40] → 8 bytes
    assert_eq!(r.crc_len, 8);
    assert_eq!(r.total_len, 40);
    assert_eq!(r.hex_pattern.len(), 32 * 2);
}

#[test]
fn pat_record_from_bytes_zero_window_yields_zero_crc_len() {
    let bytes: Vec<u8> = vec![0xAA; 40];
    let r = PatRecord::from_bytes(&bytes, "f", 32, 0);
    assert_eq!(r.crc_len, 0);
}

#[test]
fn pat_record_display_contains_name_and_pattern() {
    let r = PatRecord::new("AABB", 0x1234, 0, 2, "myfunc");
    let s = format!("{r}");
    assert!(s.contains("AABB"));
    assert!(s.contains("myfunc"));
    assert!(s.contains("1234"));
}

// ── PatFile parsing ───────────────────────────────────────────────────────────

#[test]
fn pat_file_skips_comments_and_terminator() {
    let s = "\
; this is a comment
AA 0000 00 0001 foo
BB 0001 00 0001 bar
---
";
    let pf = PatFile::parse_str(s);
    assert_eq!(pf.len(), 2);
    assert!(!pf.is_empty());
}

#[test]
fn pat_file_empty_is_empty() {
    let pf = PatFile::parse_str("");
    assert!(pf.is_empty());
}

#[test]
fn pat_file_display_terminates_with_dashes() {
    let mut pf = PatFile::new();
    pf.add(PatRecord::new("AA", 0, 0, 1, "x"));
    let out = format!("{pf}");
    assert!(out.trim_end().ends_with("---"));
}

#[test]
fn pat_file_roundtrip_via_display_and_from_str() {
    let mut pf = PatFile::new();
    pf.add(PatRecord::new("AABB", 0x1234, 2, 4, "a"));
    pf.add(PatRecord::new("CCDD", 0x5678, 2, 4, "b"));
    let s = pf.to_string();
    let pf2 = PatFile::parse_str(&s);
    assert_eq!(pf2.len(), 2);
    assert_eq!(pf2.records[0].name, "a");
    assert_eq!(pf2.records[1].name, "b");
}

// ── SigHeader round-trip ──────────────────────────────────────────────────────

#[test]
fn sig_header_roundtrip_preserves_fields() {
    let mut h = SigHeader::new("libfoo");
    h.arch = 0x4B;
    h.file_types = 0xDEADBEEF;
    h.os_types = 0xAB;
    h.app_types = 0xCD;
    h.feature_flags = 0xEF;
    h.num_functions = 12345;
    h.pattern_size = 32;
    h.crc16 = 0x9999;
    let buf = h.serialize();
    // The IDA header is variable length: it ends where the library name ends.
    assert_eq!(buf.len(), 43 + "libfoo".len());
    let h2 = SigHeader::deserialize(&buf).expect("deserialize");
    assert_eq!(h2.arch, 0x4B);
    assert_eq!(h2.file_types, 0xDEADBEEF);
    assert_eq!(h2.os_types, 0xAB);
    assert_eq!(h2.app_types, 0xCD);
    assert_eq!(h2.feature_flags, 0xEF);
    assert_eq!(h2.num_functions, 12345);
    assert_eq!(h2.pattern_size, 32);
    assert_eq!(h2.crc16, 0x9999);
    assert_eq!(h2.lib_name, "libfoo");
    assert_eq!(h2.magic, SigHeader::MAGIC);
    assert_eq!(h2.version, SigHeader::VERSION);
}

#[test]
fn sig_header_deserialize_rejects_short_buffer() {
    assert!(SigHeader::deserialize(&[0u8; 10]).is_none());
}

#[test]
fn sig_header_deserialize_rejects_bad_magic() {
    let mut buf = [0u8; 104];
    buf[..6].copy_from_slice(b"NOTSIG");
    assert!(SigHeader::deserialize(&buf).is_none());
}

#[test]
fn sig_header_truncates_long_lib_name_to_255_bytes() {
    // `library_name_len` is one byte, so 255 is the format's ceiling. The old
    // 63 came from the fixed 64-byte window, which was not IDA's layout.
    let h = SigHeader::new("x".repeat(300));
    let buf = h.serialize();
    let h2 = SigHeader::deserialize(&buf).expect("deserialize");
    assert!(h2.lib_name.len() <= 255);
    assert!(h2.lib_name.starts_with("xxx"));
}

// ── SigModule round-trip ──────────────────────────────────────────────────────

#[test]
fn sig_module_roundtrip_without_references() {
    let m = SigModule::new("hello", vec![0x55, 0x48, 0x89, 0xE5], 0xABCD, 16, 64);
    let buf = m.serialize();
    let (m2, consumed) = SigModule::deserialize(&buf, 0).expect("deserialize");
    assert_eq!(consumed, buf.len());
    assert_eq!(m2.name, "hello");
    assert_eq!(m2.crc16, 0xABCD);
    assert_eq!(m2.crc_len, 16);
    assert_eq!(m2.total_len, 64);
    assert_eq!(m2.first_bytes, vec![0x55, 0x48, 0x89, 0xE5]);
    assert!(m2.references.is_empty());
}

#[test]
fn sig_module_roundtrip_with_references() {
    let mut m = SigModule::new("withrefs", vec![0xAA, 0xBB], 0x1234, 4, 16);
    m.references.push(SigRef { offset: 8, name: "callee_a".to_string(), negative: false });
    m.references.push(SigRef { offset: 12, name: "callee_b".to_string(), negative: true });
    let buf = m.serialize();
    let (m2, consumed) = SigModule::deserialize(&buf, 0).expect("deserialize");
    assert_eq!(consumed, buf.len());
    assert_eq!(m2.references.len(), 2);
    assert_eq!(m2.references[0].offset, 8);
    assert_eq!(m2.references[0].name, "callee_a");
    assert!(!m2.references[0].negative);
    assert!(m2.references[1].negative);
    assert_eq!(m2.references[1].name, "callee_b");
}

#[test]
fn sig_module_deserialize_truncated_returns_none() {
    let m = SigModule::new("xyz", vec![1, 2, 3], 0, 0, 3);
    let buf = m.serialize();
    // Lopping off the last byte should make deserialization fail
    // (it expects a ref-count byte at the end).
    let truncated = &buf[..buf.len() - 1];
    assert!(SigModule::deserialize(truncated, 0).is_none());
}

#[test]
fn sig_module_deserialize_returns_none_on_empty() {
    assert!(SigModule::deserialize(&[], 0).is_none());
}

// ── SigFile round-trip ────────────────────────────────────────────────────────

#[test]
fn sig_file_roundtrip_multiple_modules() {
    let mut sig = SigFile::new("rtlib");
    sig.add_module(SigModule::new("a", vec![0x01], 0, 0, 1));
    sig.add_module(SigModule::new("b", vec![0x02], 0, 0, 1));
    sig.add_module(SigModule::new("c", vec![0x03], 0, 0, 1));
    assert_eq!(sig.header.num_functions, 3);
    assert_eq!(sig.module_count(), 3);
    let bytes = sig.serialize();
    let sig2 = SigFile::deserialize(&bytes).expect("deserialize");
    assert_eq!(sig2.module_count(), 3);
    assert_eq!(sig2.modules[1].name, "b");
}

#[test]
fn sig_file_deserialize_too_short_is_none() {
    assert!(SigFile::deserialize(&[0u8; 5]).is_none());
}

// ── pat_records_to_sig conversion ─────────────────────────────────────────────

#[test]
fn pat_records_to_sig_preserves_count_and_names() {
    let recs = vec![
        PatRecord::new("AABB", 0x1111, 2, 4, "alpha"),
        PatRecord::new("CCDD", 0x2222, 2, 4, "beta"),
    ];
    let sig = pat_records_to_sig(&recs, "conv");
    assert_eq!(sig.module_count(), 2);
    assert_eq!(sig.modules[0].name, "alpha");
    assert_eq!(sig.modules[1].name, "beta");
    assert_eq!(sig.modules[0].first_bytes, vec![0xAA, 0xBB]);
}

// ── PatternGenerator from the root crate ──────────────────────────────────────

#[test]
fn pattern_gen_initial_zero_makes_no_initial_bytes() {
    let pg = PatternGenerator { initial_length: 0, crc_length: 4 };
    let pat = pg.generate(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90], &[], vec![]).unwrap();
    assert!(pat.initial_bytes.is_empty());
    // CRC should now span the first 4 bytes.
    assert_eq!(pat.crc_length, 4);
}

#[test]
fn pattern_gen_reloc_past_end_does_not_panic() {
    let pg = PatternGenerator::new();
    let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
    // Relocation describing a byte range that extends well past the slice end.
    let relocs = vec![RelocationEntry { offset: 2, size: 200 }];
    let pat = pg.generate(&bytes, &relocs, vec![]).unwrap();
    // Bytes 2..4 (clamped) become wildcards.
    assert_eq!(pat.initial_bytes[0], PatternByte::Exact(0x55));
    assert_eq!(pat.initial_bytes[1], PatternByte::Exact(0x48));
    assert_eq!(pat.initial_bytes[2], PatternByte::Wildcard);
    assert_eq!(pat.initial_bytes[3], PatternByte::Wildcard);
}

#[test]
fn pattern_gen_huge_function_pattern_length_saturates() {
    let pg = PatternGenerator::new();
    let bytes = vec![0u8; 0x12345]; // > u16::MAX
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert_eq!(pat.pattern_length, u16::MAX);
}

#[test]
fn pattern_gen_tail_bytes_capped_at_eight() {
    let pg = PatternGenerator { initial_length: 4, crc_length: 4 };
    let bytes: Vec<u8> = (0u8..60).collect();
    let pat = pg.generate(&bytes, &[], vec![]).unwrap();
    assert!(pat.tail_bytes.len() <= 8);
}

#[test]
fn pattern_gen_from_ranges_initial_length_zero_path() {
    let pg = PatternGenerator { initial_length: 0, crc_length: 4 };
    let bytes = vec![0xAA; 16];
    let pat = pg.generate_from_ranges(&bytes, &[], vec![], vec![]).unwrap();
    assert!(pat.initial_bytes.is_empty());
}

#[test]
fn pattern_gen_from_ranges_masked_range_extending_past_end() {
    let pg = PatternGenerator::new();
    let bytes = vec![0xAA; 8];
    // size 255 with offset 4 → would touch byte 259 if not clamped.
    let res = pg.generate_from_ranges(&bytes, &[(4, 255)], vec![], vec![]);
    assert!(res.is_ok(), "should clamp rather than panic");
}

// ── LibraryBuilder / GenerationStats ──────────────────────────────────────────

#[test]
fn library_builder_dedup_keeps_distinct_names() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
    b.add_function("a".into(), &bytes, vec![]);
    b.add_function("b".into(), &bytes, vec![]); // same bytes, different name → not a dup
    b.dedup_patterns();
    let (lib, stats) = b.build();
    assert_eq!(lib.pattern_count(), 2);
    assert_eq!(stats.duplicates_removed, 0);
}

#[test]
fn library_builder_add_elf_object_rejects_non_elf() {
    let mut b = LibraryBuilder::new("L", FlirtArch::X64, FlirtOs::Linux);
    let res = b.add_elf_object(b"not elf at all");
    assert!(res.is_err());
}

#[test]
fn gen_error_from_flirt_error_invalid_pattern() {
    let pg = PatternGenerator::new();
    let err = pg.generate(&[], &[], vec![]).unwrap_err();
    let ge: GenError = err.into();
    assert!(matches!(ge, GenError::InvalidPattern(_)));
    // Display must mention "invalid pattern".
    assert!(format!("{ge}").contains("invalid pattern"));
}

#[test]
fn gen_error_variants_display() {
    let p = GenError::Parse("oops".into());
    assert!(format!("{p}").contains("parse error"));
    let s = GenError::Serialize("io".into());
    assert!(format!("{s}").contains("serialize error"));
}

// ── ElfObjectParser adversarial inputs ────────────────────────────────────────

#[test]
fn elf_parser_rejects_unknown_class() {
    // valid magic but EI_CLASS = 9 (neither 1 nor 2)
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 9;
    let r = ElfObjectParser::parse(&data);
    assert!(r.is_err());
}

#[test]
fn elf_parser_rejects_zero_shoff() {
    // valid magic, ELF64 LE, but section headers absent → error.
    let mut data = vec![0u8; 128];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    // e_shoff = 0 at offset 0x28, e_shnum = 0
    let r = ElfObjectParser::parse(&data);
    assert!(r.is_err());
}

#[test]
fn elf_parser_rejects_tiny_buffer() {
    assert!(ElfObjectParser::parse(b"").is_err());
    assert!(ElfObjectParser::parse(&[0x7f, b'E', b'L', b'F']).is_err());
}

// ── SigWriter / SigTrieNode ───────────────────────────────────────────────────

#[test]
fn sig_writer_default_is_x64() {
    let w = SigWriter::default();
    assert_eq!(w.arch, 75);
}

#[test]
fn sig_writer_header_crc_matches_crc16_sig_header() {
    let w = SigWriter::default();
    let buf = w.build(&[], "lib");
    let stored = u16::from_le_bytes(buf[20..22].try_into().unwrap());
    let recomputed = crc16_sig_header(&buf[..20]);
    assert_eq!(stored, recomputed);
}

#[test]
fn sig_writer_stops_prefix_at_first_wildcard() {
    // Build a pattern that begins with two exact bytes then a wildcard.
    let mut pat = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x48),
        PatternByte::Wildcard,
        PatternByte::Exact(0xE5),
    ]);
    pat.names.push(FlirtName {
        name: "frob".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    pat.crc16 = 0;
    pat.crc_length = 0;
    pat.pattern_length = 4;
    let w = SigWriter::default();
    let buf = w.build(&[pat], "L");
    // The trie starts where the header ends — variable length, not 104.
    let trie = rustre_flirt::sig_header::SigFileHeader::decode(&buf)
        .expect("header decodificabile")
        .len_bytes();
    let prefix_len = buf[trie] as usize;
    // Should be 2 (stops at wildcard).
    assert_eq!(prefix_len, 2);
    assert_eq!(&buf[trie + 1..trie + 3], &[0x55, 0x48]);
}

#[test]
fn sig_trie_branch_with_one_leaf_child_encodes_correctly() {
    let leaf = SigTrieNode::Leaf {
        prefix: vec![0xAA],
        crc_len: 1,
        crc16: 0x0102,
        module_offset: 0,
        func_name: "n".to_string(),
        tail: Vec::new(),
        tail_mask: Vec::new(),
    };
    let branch = SigTrieNode::Branch {
        prefix: vec![0x55],
        children: vec![leaf],
    };
    let mut buf = Vec::new();
    branch.encode(&mut buf);
    // length(1) byte0=0x55 child-sentinel(0) leaf-len(1) leaf-byte=0xAA flags(0x01)…
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1], 0x55);
    assert_eq!(buf[2], 0x00);
    assert_eq!(buf[3], 1);
    assert_eq!(buf[4], 0xAA);
    assert_eq!(buf[5], 0x01);
    // Final byte should be the end-of-children sentinel = 0.
    assert_eq!(*buf.last().unwrap(), 0);
}

#[test]
fn write_sig_file_io_error_returns_serialize_err() {
    // Invalid path → File::create fails → GenError::Serialize.
    let bad = std::path::Path::new("Z:/definitely/does/not/exist/abc.sig");
    let r = write_sig_file(&[], "lib", 75, bad);
    assert!(matches!(r, Err(GenError::Serialize(_))));
}

// ── compiler_profile ──────────────────────────────────────────────────────────

#[test]
fn profile_registry_with_builtins_has_known_ids() {
    let reg = ProfileRegistry::with_builtins();
    for id in [
        "msvc2015_x86",
        "msvc2017_x64",
        "msvc2019_x64",
        "msvc2022_x64",
        "gcc9_x64_linux",
        "gcc10_x64_linux",
        "gcc11_x64_linux",
        "gcc12_x64_linux",
        "clang_x64_linux",
        "clang_cl_x64_windows",
        "rust_std_x64_linux",
        "rust_std_x64_windows",
        "mingw_gcc12_x64",
        "mingw32_gcc9_x86",
    ] {
        assert!(reg.get(id).is_some(), "missing builtin: {id}");
    }
    assert!(!reg.is_empty());
}

#[test]
fn profile_registry_empty_is_empty() {
    let reg = ProfileRegistry::empty();
    assert_eq!(reg.len(), 0);
    assert!(reg.is_empty());
    assert!(reg.get("anything").is_none());
}

#[test]
fn profile_registry_for_arch_filters() {
    let reg = ProfileRegistry::with_builtins();
    let x64 = reg.for_arch(ProfileArch::X86_64);
    assert!(!x64.is_empty());
    assert!(x64.iter().all(|p| p.arch == ProfileArch::X86_64));
}

#[test]
fn profile_registry_for_library_is_case_insensitive() {
    let reg = ProfileRegistry::with_builtins();
    let a = reg.for_library("LIBCMT.LIB");
    let b = reg.for_library("libcmt.lib");
    assert_eq!(a.len(), b.len());
    assert!(!a.is_empty());
}

#[test]
fn profile_registry_iter_count_matches_len() {
    let reg = ProfileRegistry::with_builtins();
    assert_eq!(reg.iter().count(), reg.len());
}

#[test]
fn profile_registry_identify_function_finds_rust() {
    let reg = ProfileRegistry::with_builtins();
    let hits = reg.identify_function("__rust_alloc");
    assert!(hits.iter().any(|p| p.id.starts_with("rust_std")));
}

#[test]
fn compiler_profile_name_matches_msvc_rejects_itanium_mangling() {
    let p = cp::msvc2022_x64();
    // MSVC explicitly excludes Itanium-mangled names even if they share a prefix.
    assert!(!p.name_matches("_ZN3foo3barEv"));
    assert!(!p.name_matches("_Z3foo"));
}

#[test]
fn compiler_profile_match_prologue_none_on_short_data() {
    let p = cp::msvc2022_x64();
    // Far too short to satisfy any prologue.
    assert!(p.match_prologue(&[0x48]).is_none());
}

#[test]
fn compiler_profile_match_prologue_respects_wildcards() {
    let p = cp::gcc9_x64_linux();
    // GCC profile has prologue [0x53, 0x48, 0x83, 0xEC] with wildcard at index 4
    // (out of range — wildcard noted at idx 4 but the pattern only has 4 bytes).
    // The other prologue [0x55, 0x48, 0x89, 0xE5] has no wildcards.
    let data = [0x55u8, 0x48, 0x89, 0xE5, 0x00];
    let hit = p.match_prologue(&data).expect("must match push_rbp");
    assert_eq!(hit.label, "push_rbp");
}

#[test]
fn prologue_pattern_fields_present() {
    let p = cp::msvc2015_x86();
    assert!(!p.prologues.is_empty());
    let pr = &p.prologues[0];
    assert!(!pr.bytes.is_empty());
    assert!(!pr.label.is_empty());
}

#[test]
fn profile_arch_display_strings_are_distinct() {
    let a = format!("{}", ProfileArch::X86);
    let b = format!("{}", ProfileArch::X86_64);
    assert_ne!(a, b);
}

#[test]
fn profile_os_display_strings_are_distinct() {
    let a = format!("{}", ProfileOs::Linux);
    let b = format!("{}", ProfileOs::Windows);
    assert_ne!(a, b);
}

#[test]
fn calling_convention_display_works_for_all_variants() {
    // Just exercise Display for every variant we know exists.
    for cc in [
        CallingConvention::Cdecl,
        CallingConvention::Stdcall,
        CallingConvention::Fastcall,
        CallingConvention::MsX64,
        CallingConvention::SysVX64,
        CallingConvention::AapcsArm32,
        CallingConvention::AapcsAarch64,
        CallingConvention::Unknown,
    ] {
        let s = format!("{cc}");
        assert!(!s.is_empty());
    }
}

#[test]
fn profile_registry_register_overwrites_same_id() {
    let mut reg = ProfileRegistry::empty();
    let p1 = cp::msvc2022_x64();
    reg.register(p1);
    let len_before = reg.len();
    let p2 = cp::msvc2022_x64(); // same id
    reg.register(p2);
    assert_eq!(reg.len(), len_before, "same id should overwrite, not append");
}

#[test]
fn custom_profile_with_no_prologues_returns_none() {
    let p = CompilerProfile {
        id: "x",
        display_name: "X",
        arch: ProfileArch::X86_64,
        os: ProfileOs::Linux,
        calling_convention: CallingConvention::SysVX64,
        library_files: vec![],
        name_prefixes: vec![],
        name_suffixes: vec![],
        prologues: vec![],
        meta: std::collections::HashMap::new(),
    };
    assert!(p.match_prologue(&[0xAA; 16]).is_none());
}

#[test]
fn prologue_with_wildcard_matches_any_byte_at_position() {
    let p = CompilerProfile {
        id: "x",
        display_name: "X",
        arch: ProfileArch::X86_64,
        os: ProfileOs::Linux,
        calling_convention: CallingConvention::SysVX64,
        library_files: vec![],
        name_prefixes: vec![],
        name_suffixes: vec![],
        prologues: vec![ProloguePattern {
            bytes: vec![0x48, 0x83, 0xEC, 0x00],
            wildcards: vec![3],
            label: "sub_rsp_imm8",
        }],
        meta: std::collections::HashMap::new(),
    };
    assert!(p.match_prologue(&[0x48, 0x83, 0xEC, 0x42]).is_some());
    assert!(p.match_prologue(&[0x48, 0x83, 0xEC, 0xFF]).is_some());
    assert!(p.match_prologue(&[0x48, 0x83, 0xED, 0x00]).is_none());
}

// ── crc16_sig_header sanity ───────────────────────────────────────────────────

#[test]
fn crc16_sig_header_empty_returns_initial_value() {
    // Non-reflected variant with init 0xFFFF — on empty input crc is 0xFFFF.
    assert_eq!(crc16_sig_header(&[]), 0xFFFF);
}

#[test]
fn crc16_sig_header_differs_from_pat_crc16() {
    // The two CRC variants must not collapse onto each other for non-trivial input.
    let data = b"hello world";
    assert_ne!(crc16_sig_header(data), crc16(data));
}
