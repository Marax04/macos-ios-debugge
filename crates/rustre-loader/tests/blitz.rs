//! Exhaustive integration tests for rustre-loader public surface.
//! Tests are written against the public API only; they do not assume
//! any private implementation details.

use rustre_loader::*;

// ─── FormatDetector & AutoLoader cross-checks ────────────────────────────────

#[test]
fn fd_detect_unknown_short() {
    let d = FormatDetector::new();
    assert_eq!(d.detect(&[]), BinaryFormat::Unknown);
    assert_eq!(d.detect(&[0x7f]), BinaryFormat::Unknown);
    assert_eq!(d.detect(&[0x7f, b'E']), BinaryFormat::Unknown);
}

#[test]
fn fd_default_equals_new() {
    let a = FormatDetector::new();
    let b = FormatDetector;
    assert_eq!(a.detect(b"\x7fELF"), b.detect(b"\x7fELF"));
}

#[test]
fn fd_pe_partial_mz_only() {
    let d = FormatDetector::new();
    assert_eq!(d.detect(b"MZ"), BinaryFormat::Pe);
}

#[test]
fn fd_cafebabe_short_is_machofat() {
    // <8 bytes so Java disambiguation can't run → falls through to MachOFat
    let d = FormatDetector::new();
    assert_eq!(d.detect(&[0xCA, 0xFE, 0xBA, 0xBE]), BinaryFormat::MachOFat);
}

#[test]
fn fd_java_major_boundaries() {
    let d = FormatDetector::new();
    // major=44 is JavaClass
    assert_eq!(d.detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 44]), BinaryFormat::JavaClass);
    // major=80 is JavaClass (upper boundary inclusive)
    assert_eq!(d.detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 80]), BinaryFormat::JavaClass);
    // major=43 falls through to MachOFat
    assert_eq!(d.detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 43]), BinaryFormat::MachOFat);
    // major=81 falls through to MachOFat
    assert_eq!(d.detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 81]), BinaryFormat::MachOFat);
}

#[test]
fn fd_zip_eocd_central_dir() {
    let d = FormatDetector::new();
    assert_eq!(d.detect(b"PK\x05\x06rest"), BinaryFormat::Zip);
}

#[test]
fn auto_detect_short_inputs_unknown() {
    assert_eq!(AutoLoader::detect_format(&[]), DetectedFormat::Unknown);
    assert_eq!(AutoLoader::detect_format(b"M"), DetectedFormat::Unknown);
}

#[test]
fn auto_detect_elf_bad_class_endian() {
    // Bad class=0
    assert_eq!(
        AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 0, 1]),
        DetectedFormat::Unknown
    );
    // Bad endian=3
    assert_eq!(
        AutoLoader::detect_format(&[0x7f, b'E', b'L', b'F', 2, 3]),
        DetectedFormat::Unknown
    );
}

#[test]
fn auto_detect_srec_only_S_no_digit() {
    // "Sx" where x is not a digit → not srec
    assert_eq!(AutoLoader::detect_format(b"Sx"), DetectedFormat::Unknown);
}

#[test]
fn auto_detect_intel_hex_min_two_bytes() {
    // Single `:` is below the 2-byte minimum check → Unknown
    assert_eq!(AutoLoader::detect_format(b":"), DetectedFormat::Unknown);
    // Two bytes starting with `:` → IntelHex
    assert_eq!(AutoLoader::detect_format(b":1"), DetectedFormat::IntelHex);
}

#[test]
fn auto_loader_new_and_default_consistent() {
    let a = AutoLoader::new();
    let b = AutoLoader;
    let _ = (a, b);
    assert!(AutoLoader::is_elf(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]));
}

// ─── sha256 ──────────────────────────────────────────────────────────────────

#[test]
fn sha256_known_vectors() {
    assert_eq!(
        sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_length_is_64() {
    for n in [0, 1, 31, 32, 63, 64, 65, 1024] {
        let d = sha256(&vec![0xAA; n]);
        assert_eq!(d.len(), 64);
    }
}

// ─── RichLoadResult ──────────────────────────────────────────────────────────

#[test]
fn rich_load_result_builders() {
    let r = RichLoadResult::new(vec![1, 2, 3])
        .with_format("ELF")
        .with_arch("x86_64")
        .with_bits(64)
        .with_endian("little")
        .with_entry_point(0x1000)
        .with_base_address(0x0040_0000)
        .with_section(SectionInfo::new(".text", 0x1000, 0x100, 0x200, 0x100, 0x20))
        .with_symbol(SymbolInfo::new("main", 0x1000, "function", 16))
        .with_import(ImportInfo::named("libc.so", "printf", 0x2000))
        .with_export(ExportInfo::named("foo", 0x3000, 1));
    assert_eq!(r.format, "ELF");
    assert_eq!(r.bits, 64);
    assert_eq!(r.entry_point, Some(0x1000));
    assert_eq!(r.sections.len(), 1);
    assert_eq!(r.symbols.len(), 1);
    assert_eq!(r.imports.len(), 1);
    assert_eq!(r.exports.len(), 1);
}

#[test]
fn rich_load_result_sha256_matches_data() {
    let r = RichLoadResult::new(b"hello".to_vec());
    assert_eq!(r.sha256(), sha256(b"hello"));
}

// ─── md5 ─────────────────────────────────────────────────────────────────────

#[test]
fn md5_known_vectors() {
    assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        md5(b"The quick brown fox jumps over the lazy dog"),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
}

#[test]
fn md5_length_is_32() {
    for n in [0, 1, 31, 32, 63, 64, 65, 1024] {
        let d = md5(&vec![0xAA; n]);
        assert_eq!(d.len(), 32);
    }
}

#[test]
fn rich_load_result_md5_matches_data() {
    let r = RichLoadResult::new(b"hello".to_vec());
    assert_eq!(r.md5(), md5(b"hello"));
}

#[test]
fn rich_load_result_total_virtual_size_sum() {
    let r = RichLoadResult::new(vec![])
        .with_section(SectionInfo::new("a", 0, 100, 0, 0, 0))
        .with_section(SectionInfo::new("b", 200, 50, 0, 0, 0));
    assert_eq!(r.total_virtual_size(), 150);
}

#[test]
fn rich_load_result_section_at_finds_and_misses() {
    let r = RichLoadResult::new(vec![])
        .with_section(SectionInfo::new(".text", 0x1000, 0x100, 0, 0, 0))
        .with_section(SectionInfo::new(".data", 0x2000, 0x80, 0, 0, 0));
    assert_eq!(r.section_at(0x1000).unwrap().name, ".text");
    assert_eq!(r.section_at(0x10FF).unwrap().name, ".text");
    assert!(r.section_at(0x1100).is_none());
    assert_eq!(r.section_at(0x2000).unwrap().name, ".data");
    assert!(r.section_at(0xFFFF_FFFF).is_none());
}

#[test]
fn rich_load_result_section_at_saturating_va() {
    // size near u64::MAX must not panic
    let r = RichLoadResult::new(vec![])
        .with_section(SectionInfo::new("huge", u64::MAX - 10, 100, 0, 0, 0));
    // saturating_add(100) saturates at u64::MAX, va==u64::MAX is NOT < u64::MAX, so None
    assert!(r.section_at(u64::MAX).is_none());
    assert!(r.section_at(u64::MAX - 5).is_some());
}

#[test]
fn rich_load_result_serde_roundtrip() {
    let r = RichLoadResult::new(vec![1, 2, 3]).with_format("X").with_bits(32);
    let j = serde_json::to_string(&r).unwrap();
    let r2: RichLoadResult = serde_json::from_str(&j).unwrap();
    assert_eq!(r2.format, "X");
    assert_eq!(r2.bits, 32);
    assert_eq!(r2.data, vec![1, 2, 3]);
}

// ─── ImportInfo / ExportInfo constructors ───────────────────────────────────

#[test]
fn import_info_ordinal_has_empty_name() {
    let i = ImportInfo::ordinal("foo.dll", 42, 0x1000);
    assert_eq!(i.name, "");
    assert_eq!(i.ordinal, Some(42));
}

#[test]
fn export_info_forwarded_has_zero_addr() {
    let e = ExportInfo::forwarded("Bar", 1, "OTHER.DLL.Baz");
    assert_eq!(e.addr, 0);
    assert_eq!(e.forwarded_to.as_deref(), Some("OTHER.DLL.Baz"));
}

// ─── MultiLoaderInput ───────────────────────────────────────────────────────

#[test]
fn multi_input_bytes_to_bytes() {
    let r = MultiLoaderInput::Bytes(vec![1, 2, 3]).to_bytes().unwrap();
    assert_eq!(r, vec![1, 2, 3]);
}

#[test]
fn multi_input_memory_returns_data() {
    let r = MultiLoaderInput::Memory { base: 0x1000, data: vec![9, 8] }
        .to_bytes()
        .unwrap();
    assert_eq!(r, vec![9, 8]);
}

#[test]
fn multi_input_file_missing_errors() {
    let p = std::path::PathBuf::from("/definitely/does/not/exist/zzzz.bin");
    let r = MultiLoaderInput::File(p).to_bytes();
    assert!(r.is_err());
}

// ─── MultiFormatRegistry & stub loaders ─────────────────────────────────────

#[test]
fn default_registry_has_seven_loaders() {
    let r = default_multi_format_registry();
    assert_eq!(r.len(), 7);
    assert!(!r.is_empty());
    let names = r.loader_names();
    for n in ["elf", "pe", "wasm", "macho", "lua", "java-class", "android-dex"] {
        assert!(names.iter().any(|x| x == n), "missing loader: {n}");
    }
}

#[test]
fn registry_empty_state() {
    let r = MultiFormatRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.loader_names().is_empty());
    assert!(r.find("anything").is_none());
}

#[test]
fn registry_probe_all_sorts_descending() {
    let r = default_multi_format_registry();
    // ELF magic should score 255 from elf loader, 0 from others
    let results = r.probe_all(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    assert!(!results.is_empty());
    assert_eq!(results[0].0, "elf");
    assert_eq!(results[0].1, 255);
    for w in results.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn registry_auto_load_elf_dispatches() {
    let r = default_multi_format_registry();
    let bytes = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    let res = r.auto_load(&bytes).unwrap();
    assert_eq!(res.bits, 64);
    assert_eq!(res.endian, "little");
}

#[test]
fn registry_auto_load_unknown_errors() {
    let r = default_multi_format_registry();
    let res = r.auto_load(b"NO_MATCH_HERE_AT_ALL");
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("no") || msg.contains("loader"));
}

#[test]
fn registry_load_with_by_name() {
    let r = default_multi_format_registry();
    let res = r.load_with("wasm", &[0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]).unwrap();
    assert_eq!(res.arch, "wasm32");
}

#[test]
fn registry_load_with_unknown_name_errors() {
    let r = default_multi_format_registry();
    let res = r.load_with("not-a-real-loader", b"x");
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not found"));
}

#[test]
fn registry_load_with_wrong_data_for_loader_errors() {
    let r = default_multi_format_registry();
    // tell PE loader to load non-MZ data
    assert!(r.load_with("pe", b"NOPE").is_err());
}

#[test]
fn registry_find_returns_arc() {
    let r = default_multi_format_registry();
    let arc = r.find("elf").unwrap();
    assert_eq!(arc.name(), "elf");
    assert!(!arc.extensions().is_empty());
    assert!(!arc.description().is_empty());
}

// ─── Stub loaders directly ──────────────────────────────────────────────────

#[test]
fn elf_stub_probe_and_load() {
    let l = ElfStubLoader;
    assert_eq!(l.probe(&[0x7f, b'E', b'L', b'F']), 255);
    assert_eq!(l.probe(b"junk"), 0);
    assert!(l.load(b"short").is_err());
    let r = l.load(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    assert_eq!(r.bits, 64);
}

#[test]
fn pe_stub_probe_and_load() {
    let l = PeStubLoader;
    assert_eq!(l.probe(b"MZ"), 200);
    assert_eq!(l.probe(b"PE"), 0);
    assert!(l.load(b"x").is_err());
    // A 4-byte buffer is NOT a loadable PE: the DOS header is 0x40 bytes and
    // `e_lfanew` lives at 0x3c, so the loader rightly rejects it.
    assert!(l.load(b"MZ\x90\x00").is_err());
    let mut pe = vec![0u8; 0x40];
    pe[0..2].copy_from_slice(b"MZ");
    let r = l.load(&pe).unwrap();
    assert_eq!(r.format, "PE");
}

#[test]
fn wasm_stub_probe_and_load() {
    let l = WasmStubLoader;
    assert_eq!(l.probe(&[0x00, 0x61, 0x73, 0x6d]), 255);
    assert_eq!(l.probe(b"abcd"), 0);
    assert!(l.load(b"x").is_err());
    let r = l.load(&[0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]).unwrap();
    assert_eq!(r.bits, 32);
}

#[test]
fn macho_stub_probe_le64() {
    let l = MachoStubLoader;
    let bytes = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
    assert_eq!(l.probe(&bytes), 255);
    let r = l.load(&bytes).unwrap();
    assert_eq!(r.bits, 64);
    assert_eq!(r.endian, "little");
}

#[test]
fn macho_stub_fat_has_mixed_endian_tag() {
    let l = MachoStubLoader;
    let bytes = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2];
    let r = l.load(&bytes).unwrap();
    assert_eq!(r.endian, "mixed");
}

#[test]
fn lua_stub_lua_and_jit() {
    let l = LuaStubLoader;
    assert_eq!(l.probe(&[0x1b, b'L', b'u', b'a', 0x53]), 255);
    assert_eq!(l.probe(&[0x1b, b'L', b'J']), 240);
    assert!(l.load(b"junk").is_err());
    let r = l.load(&[0x1b, b'L', b'u', b'a', 0x53, 0]).unwrap();
    assert!(r.format.contains("Lua"));
}

#[test]
fn java_class_stub() {
    let l = JavaClassStubLoader;
    let data = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
    assert_eq!(l.probe(&data), 255);
    let r = l.load(&data).unwrap();
    assert_eq!(r.arch, "jvm");
    assert_eq!(r.endian, "big");
    assert!(l.load(b"NOPE").is_err());
}

#[test]
fn dex_stub() {
    let l = AndroidDexStubLoader;
    assert_eq!(l.probe(b"dex\n035\0"), 255);
    assert_eq!(l.probe(b"dexX"), 0);
    let r = l.load(b"dex\n035\0").unwrap();
    assert_eq!(r.arch, "dex");
    assert!(l.load(b"NOPE").is_err());
}

// ─── ihex_loader public API ─────────────────────────────────────────────────

use rustre_loader::ihex_loader as ih;

#[test]
fn ihex_record_type_all_variants() {
    for v in 0u8..=5 {
        assert_eq!(ih::RecordType::from_u8(v).unwrap().as_u8(), v);
    }
    for bad in [6u8, 100, 255] {
        assert!(ih::RecordType::from_u8(bad).is_none());
    }
}

#[test]
fn ihex_parse_line_truncated() {
    // EOF record is the minimum: ":00000001FF" (11 chars total)
    let r = ih::parse_ihex_line(":00000001FF");
    assert!(r.is_ok());
    assert!(ih::parse_ihex_line(":0000000").is_err());
}

#[test]
fn ihex_parse_line_unknown_record_type() {
    // record type byte = 0x06 (not 0..=5). Compute correct checksum to isolate the error.
    // byte_count=0, addr=0, type=6 → sum=6, cs=0xFA
    let r = ih::parse_ihex_line(":0000000600");
    // The parser checks the record type before checksum? Either way: error.
    assert!(r.is_err());
}

#[test]
fn ihex_parse_line_bad_hex_chars() {
    assert!(ih::parse_ihex_line(":ZZZZ0001FF").is_err());
}

#[test]
fn ihex_parse_line_byte_count_overflow() {
    // declared byte_count=0xFF but no data → not enough bytes
    assert!(ih::parse_ihex_line(":FF000000FF").is_err());
}

#[test]
fn ihex_parse_file_skips_blank_lines() {
    let txt = "\n\n:00000001FF\n\n";
    let recs = ih::parse_ihex_file(txt).unwrap();
    assert_eq!(recs.len(), 1);
}

#[test]
fn ihex_parse_file_stops_at_eof_record() {
    // After EOF, trailing garbage should not be parsed.
    let txt = ":00000001FF\nGARBAGE_NOT_PARSED";
    let recs = ih::parse_ihex_file(txt).unwrap();
    assert_eq!(recs.len(), 1);
}

#[test]
fn ihex_parse_file_reports_line_number_on_error() {
    let txt = ":00000001FF\nXNOPE";  // wait, EOF stops parsing. Use bad first line.
    let bad = "BAD_LINE\n:00000001FF\n";
    let e = ih::parse_ihex_file(bad).unwrap_err();
    assert_eq!(e.line, 1);
    let _ = txt;
}

#[test]
fn ihex_memory_segment_basics() {
    let mut s = ih::MemorySegment::new(0x1000);
    s.data = vec![0xAA, 0xBB, 0xCC];
    assert_eq!(s.end(), 0x1003);
    assert!(s.contains(0x1000));
    assert!(s.contains(0x1002));
    assert!(!s.contains(0x1003));
    assert!(!s.contains(0x0FFF));
    assert_eq!(s.read_u8(0x1001), Some(0xBB));
    assert_eq!(s.read_u8(0x1003), None);
    // Address below base → checked_sub returns None → None
    assert_eq!(s.read_u8(0x0FFF), None);
}

#[test]
fn ihex_find_gaps_empty_and_single() {
    let mem = ih::LoadedMemory::new();
    assert!(mem.find_gaps().is_empty());
    let mut mem2 = ih::LoadedMemory::new();
    let mut s = ih::MemorySegment::new(0);
    s.data = vec![0; 8];
    mem2.segments.push(s);
    assert!(mem2.find_gaps().is_empty());
}

#[test]
fn ihex_find_gaps_no_gap_when_adjacent() {
    let mut mem = ih::LoadedMemory::new();
    let mut s1 = ih::MemorySegment::new(0);
    s1.data = vec![0; 8];
    let mut s2 = ih::MemorySegment::new(8); // touches s1.end
    s2.data = vec![0; 8];
    mem.segments = vec![s1, s2];
    assert!(mem.find_gaps().is_empty());
}

#[test]
fn ihex_merge_threshold_zero_only_touching() {
    let mut mem = ih::LoadedMemory::new();
    let mut s1 = ih::MemorySegment::new(0);
    s1.data = vec![1; 4];
    let mut s2 = ih::MemorySegment::new(4);
    s2.data = vec![2; 4];
    mem.segments = vec![s1, s2];
    mem.merge_adjacent_segments(0);
    assert_eq!(mem.segments.len(), 1);
    assert_eq!(mem.segments[0].data.len(), 8);
}

#[test]
fn ihex_merge_no_merge_when_gap_exceeds_threshold() {
    let mut mem = ih::LoadedMemory::new();
    let mut s1 = ih::MemorySegment::new(0);
    s1.data = vec![1; 4];
    let mut s2 = ih::MemorySegment::new(100);
    s2.data = vec![2; 4];
    mem.segments = vec![s1, s2];
    mem.merge_adjacent_segments(4);
    assert_eq!(mem.segments.len(), 2);
}

#[test]
fn ihex_serialize_roundtrip_preserves_bytes() {
    let loader = ih::IhexLoader::new();
    let mut mem = ih::LoadedMemory::new();
    let mut s = ih::MemorySegment::new(0x1000);
    s.data = (0..32u8).collect();
    mem.segments.push(s);
    let text = loader.serialize_to_ihex(&mem);
    let parsed = loader.load_str(&text).unwrap();
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.segments[0].base, 0x1000);
    assert_eq!(parsed.segments[0].data, (0..32u8).collect::<Vec<_>>());
}

#[test]
fn ihex_serialize_with_extended_linear_address() {
    let loader = ih::IhexLoader::new();
    let mut mem = ih::LoadedMemory::new();
    let mut s = ih::MemorySegment::new(0x0010_0000);
    s.data = vec![0xAA; 16];
    mem.segments.push(s);
    let text = loader.serialize_to_ihex(&mem);
    // Must contain ELA record for upper 16 bits = 0x0010
    let parsed = loader.load_str(&text).unwrap();
    assert_eq!(parsed.segments[0].base, 0x0010_0000);
    assert_eq!(parsed.segments[0].data, vec![0xAA; 16]);
}

#[test]
fn ihex_checksum_eof_record_is_ff() {
    let rec = ih::IhexRecord::new(ih::RecordType::EndOfFile, 0, vec![]);
    assert_eq!(rec.checksum(), 0xFF);
    assert!(rec.is_end());
}

// ─── srec_loader public API ─────────────────────────────────────────────────

use rustre_loader::srec_loader as sr;

#[test]
fn srec_type_roundtrip_all() {
    for c in ['0', '1', '2', '3', '5', '7', '8', '9'] {
        assert_eq!(sr::SrecType::from_char(c).unwrap().as_char(), c);
    }
    for bad in ['4', '6', 'A', 'z'] {
        assert!(sr::SrecType::from_char(bad).is_none());
    }
}

#[test]
fn srec_type_addr_bytes_matrix() {
    assert_eq!(sr::SrecType::S0Header.addr_bytes(), 2);
    assert_eq!(sr::SrecType::S1Data16.addr_bytes(), 2);
    assert_eq!(sr::SrecType::S2Data24.addr_bytes(), 3);
    assert_eq!(sr::SrecType::S3Data32.addr_bytes(), 4);
    assert_eq!(sr::SrecType::S5Count16.addr_bytes(), 2);
    assert_eq!(sr::SrecType::S7Start32.addr_bytes(), 4);
    assert_eq!(sr::SrecType::S8Start24.addr_bytes(), 3);
    assert_eq!(sr::SrecType::S9Start16.addr_bytes(), 2);
}

#[test]
fn srec_type_classifiers() {
    assert!(sr::SrecType::S0Header.is_header());
    assert!(!sr::SrecType::S1Data16.is_header());
    assert!(sr::SrecType::S7Start32.is_start());
    assert!(sr::SrecType::S8Start24.is_start());
    assert!(sr::SrecType::S9Start16.is_start());
    assert!(!sr::SrecType::S0Header.is_start());
}

#[test]
fn srec_parse_too_short() {
    assert!(sr::parse_srec_line("").is_err());
    assert!(sr::parse_srec_line("S").is_err());
}

#[test]
fn srec_parse_no_S_prefix() {
    assert!(sr::parse_srec_line("X10B00000102").is_err());
}

#[test]
fn srec_parse_unknown_type() {
    assert!(sr::parse_srec_line("S4030000FC").is_err());
}

#[test]
fn srec_parse_bad_checksum() {
    assert!(sr::parse_srec_line("S9030000FF").is_err());
}

#[test]
fn srec_parse_odd_hex_length() {
    assert!(sr::parse_srec_line("S903000FC").is_err());
}

#[test]
fn srec_parse_s9_terminator() {
    let r = sr::parse_srec_line("S9030000FC").unwrap();
    assert_eq!(r.type_, sr::SrecType::S9Start16);
    assert_eq!(r.address, 0);
}

#[test]
fn srec_memory_segment_methods() {
    let mut s = sr::MemorySegment::new(0x2000);
    s.data = vec![1, 2, 3];
    assert_eq!(s.end(), 0x2003);
    assert!(s.contains(0x2000));
    assert!(!s.contains(0x2003));
    assert_eq!(s.read_u8(0x2002), Some(3));
    assert_eq!(s.read_u8(0x1FFF), None);
}

#[test]
fn srec_loader_serialize_roundtrip() {
    let loader = sr::SrecLoader::new();
    let mut mem = sr::SrecMemory::new();
    let mut seg = sr::MemorySegment::new(0x1000);
    seg.data = (0..64u8).collect();
    mem.segments.push(seg);
    let text = loader.serialize_to_srec(&mem, 4);
    let parsed = loader.load_str(&text).unwrap();
    assert!(parsed.total_bytes() >= 64);
    // Find segment that contains 0x1000
    let bytes_at = parsed.read_u8(0x1000);
    assert_eq!(bytes_at, Some(0));
    let bytes_at_last = parsed.read_u8(0x1000 + 63);
    assert_eq!(bytes_at_last, Some(63));
}

#[test]
fn srec_record_byte_count_formula() {
    let r = sr::SrecRecord::new(sr::SrecType::S1Data16, 0, vec![0; 10]);
    // addr_bytes(2) + data(10) + checksum(1) = 13
    assert_eq!(r.byte_count(), 13);
    let r3 = sr::SrecRecord::new(sr::SrecType::S3Data32, 0, vec![0; 16]);
    assert_eq!(r3.byte_count(), 4 + 16 + 1);
}

#[test]
fn srec_parse_skips_blank_lines() {
    let txt = "\nS9030000FC\n\n";
    let recs = sr::parse_srec_file(txt).unwrap();
    assert_eq!(recs.len(), 1);
}

// ─── raw_binary_loader ──────────────────────────────────────────────────────

use rustre_loader::raw_binary_loader as rb;

#[test]
fn raw_arch_hint_as_str_all() {
    assert_eq!(rb::ArchHint::X86.as_str(), "x86");
    assert_eq!(rb::ArchHint::X86_64.as_str(), "x86_64");
    assert_eq!(rb::ArchHint::Arm.as_str(), "arm");
    assert_eq!(rb::ArchHint::Arm64.as_str(), "aarch64");
    assert_eq!(rb::ArchHint::Mips.as_str(), "mips");
    assert_eq!(rb::ArchHint::Z80.as_str(), "z80");
    assert_eq!(rb::ArchHint::Avr.as_str(), "avr");
    assert_eq!(rb::ArchHint::Raw.as_str(), "raw");
}

#[test]
fn raw_load_config_constructors() {
    let c = rb::LoadConfig::x86(0x0040_0000);
    assert_eq!(c.base_addr, 0x0040_0000);
    assert_eq!(c.arch, rb::ArchHint::X86);
    assert_eq!(c.word_size, 4);
    let c64 = rb::LoadConfig::x86_64(0x0010_0000);
    assert_eq!(c64.word_size, 8);
    assert_eq!(c64.arch, rb::ArchHint::X86_64);
}

#[test]
fn raw_binary_region_size_saturating() {
    let r = rb::BinaryRegion::new(100, 50, rb::PERM_READ, "weird");
    // end < start → saturating_sub returns 0
    assert_eq!(r.size(), 0);
}

#[test]
fn raw_binary_region_perm_flags() {
    let r = rb::BinaryRegion::new(0, 0x100, rb::PERM_READ | rb::PERM_WRITE, "data");
    assert!(r.is_readable());
    assert!(r.is_writable());
    assert!(!r.is_executable());
}

#[test]
fn raw_loaded_read_u64_le_and_be() {
    let loader = rb::RawBinaryLoader::new();
    let data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let le = loader.load(&data, &rb::LoadConfig { base_addr: 0, is_big_endian: false, ..Default::default() });
    assert_eq!(le.read_u64(0), Some(0x0807_0605_0403_0201));
    let be = loader.load(&data, &rb::LoadConfig { base_addr: 0, is_big_endian: true, ..Default::default() });
    assert_eq!(be.read_u64(0), Some(0x0102_0304_0506_0708));
}

#[test]
fn raw_loaded_read_oob_returns_none() {
    let loader = rb::RawBinaryLoader::new();
    let data = vec![0u8; 4];
    let lb = loader.load(&data, &rb::LoadConfig { base_addr: 0x1000, ..Default::default() });
    assert_eq!(lb.read_u64(0x1000), None);
    assert_eq!(lb.read_u32(0x1001), None);
    assert_eq!(lb.read_u16(0x1003), None);
    // Below base
    assert_eq!(lb.read_u8(0x0FFF), None);
}

#[test]
fn raw_detect_arch_mach_o() {
    // FEEDFACE → X86
    let m32be = [0xFE, 0xED, 0xFA, 0xCE];
    assert_eq!(rb::detect_arch_from_content(&m32be), rb::ArchHint::X86);
    // CFFAEDFE → X86_64
    let m64le = [0xCF, 0xFA, 0xED, 0xFE];
    assert_eq!(rb::detect_arch_from_content(&m64le), rb::ArchHint::X86_64);
}

#[test]
fn raw_split_into_sections_empty() {
    assert!(rb::split_into_sections(&[], 0).is_empty());
}

#[test]
fn raw_auto_detect_base_no_candidates_returns_zero() {
    // small data with no aligned candidate
    let data = vec![0xFFu8; 8];
    let base = rb::auto_detect_base(&data, 4);
    assert_eq!(base, 0);
}

// ─── LoaderCoordinator/Pipeline/BatchLoader smoke ───────────────────────────

#[test]
fn coordinator_default_empty() {
    let c = LoaderCoordinator::default();
    assert_eq!(c.loader_count(), 0);
}

#[test]
fn coordinator_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LoaderCoordinator>();
    assert_send_sync::<MultiFormatRegistry>();
    assert_send_sync::<BatchLoader>();
}

#[test]
fn pipeline_detect_format_routes_to_detector() {
    let p = LoaderPipeline::new("test");
    assert_eq!(p.detect_format(b"\x7fELF"), BinaryFormat::Elf);
    assert_eq!(p.detect_format(b"MZ"), BinaryFormat::Pe);
    assert_eq!(p.detect_format(&[]), BinaryFormat::Unknown);
    assert_eq!(p.name(), "test");
}

// ─── BinaryFormat Display ───────────────────────────────────────────────────

#[test]
fn binary_format_display_all() {
    assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
    assert_eq!(BinaryFormat::Pe.to_string(), "PE");
    assert_eq!(BinaryFormat::MachO.to_string(), "Mach-O");
    assert_eq!(BinaryFormat::MachOFat.to_string(), "Mach-O Fat");
    assert_eq!(BinaryFormat::JavaClass.to_string(), "Java Class");
    assert_eq!(BinaryFormat::Zip.to_string(), "ZIP/JAR");
    assert_eq!(BinaryFormat::Wasm.to_string(), "WebAssembly");
    assert_eq!(BinaryFormat::Unknown.to_string(), "Unknown");
}

#[test]
fn binary_format_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(BinaryFormat::Elf);
    s.insert(BinaryFormat::Elf);
    s.insert(BinaryFormat::Pe);
    assert_eq!(s.len(), 2);
}

// ─── next_view_id uniqueness ────────────────────────────────────────────────

#[test]
fn next_view_id_monotonic_unique() {
    let a = next_view_id();
    let b = next_view_id();
    let c = next_view_id();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}
