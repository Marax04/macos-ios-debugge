//! blitz2 — deep adversarial tests targeting `ihex_loader`, `srec_loader`,
//! and `raw_binary_loader` modules. Uses a seeded LCG fuzzer; no `std::time`, no rand.

use rustre_loader::ihex_loader::{
    parse_ihex_line, parse_ihex_file, IhexLoader, IhexRecord, LoadedMemory,
    MemorySegment as IhexSeg, RecordType,
};
use rustre_loader::srec_loader::{
    parse_srec_line, parse_srec_file, SrecLoader, SrecMemory, SrecRecord, SrecType,
    MemorySegment as SrecSeg,
};
use rustre_loader::raw_binary_loader::{
    auto_detect_base, detect_arch_from_content, split_into_sections, ArchHint,
    BinaryRegion, LoadConfig, LoadedBinary, RawBinaryLoader, PERM_EXECUTE, PERM_READ, PERM_WRITE,
};

// ─── LCG fuzzer ──────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn next_u8(&mut self) -> u8 { (self.next_u64() >> 56) as u8 }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

// ─── ihex: RecordType round-trip ─────────────────────────────────────────────

#[test]
fn ihex_record_type_full_roundtrip() {
    for v in 0u8..=5 {
        let rt = RecordType::from_u8(v).expect("known");
        assert_eq!(rt.as_u8(), v);
    }
    for v in 6u8..=255u8 {
        assert!(RecordType::from_u8(v).is_none(), "{v} should be unknown");
    }
}

// ─── ihex: format/parse round-trip many seeded records ──────────────────────

fn format_ihex_record(rec: &IhexRecord) -> String {
    // Mirror src formatter via byte_count derivation
    let mut bytes = Vec::new();
    bytes.push(rec.byte_count);
    bytes.push((rec.address >> 8) as u8);
    bytes.push((rec.address & 0xFF) as u8);
    bytes.push(rec.record_type.as_u8());
    bytes.extend_from_slice(&rec.data);
    let cs = rec.checksum();
    bytes.push(cs);
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!(":{hex}")
}

#[test]
fn ihex_format_parse_roundtrip_seeded() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..60 {
        let addr = (g.next_u64() & 0xFFFF) as u16;
        let len = (g.next_u8() as usize) % 32;
        let data = g.next_bytes(len);
        let rec = IhexRecord::new(RecordType::Data, addr, data.clone());
        let s = format_ihex_record(&rec);
        let parsed = parse_ihex_line(&s).expect("parse");
        assert_eq!(parsed.record_type, RecordType::Data);
        assert_eq!(parsed.address, addr);
        assert_eq!(parsed.data, data);
        assert_eq!(parsed.byte_count, len as u8);
    }
}

#[test]
fn ihex_checksum_self_validates() {
    let mut g = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..50 {
        let len = (g.next_u8() as usize) % 16;
        let data = g.next_bytes(len);
        let addr = (g.next_u64() & 0xFFFF) as u16;
        let rec = IhexRecord::new(RecordType::Data, addr, data);
        let s = format_ihex_record(&rec);
        assert!(parse_ihex_line(&s).is_ok());
    }
}

#[test]
fn ihex_fuzz_never_panics() {
    let mut g = Lcg::new(0xCAFE_F00D_DEAD_C0DE);
    for _ in 0..200 {
        let len = (g.next_u8() as usize) % 80;
        let raw = g.next_bytes(len);
        let mut s = String::from(":");
        for b in &raw {
            s.push_str(&format!("{b:02X}"));
        }
        let _ = parse_ihex_line(&s);
    }
}

#[test]
fn ihex_fuzz_random_text_never_panics() {
    let mut g = Lcg::new(0xABCD_1234_5678_9ABC);
    for _ in 0..100 {
        let len = (g.next_u8() as usize) % 60;
        let bytes: Vec<u8> = (0..len).map(|_| {
            let v = g.next_u8();
            // mix in printable chars + ':' + hex
            match v % 4 {
                0 => b':',
                1 => b'0' + (v % 10),
                2 => b'A' + (v % 6),
                _ => b' ',
            }
        }).collect();
        let s = String::from_utf8(bytes).unwrap_or_default();
        let _ = parse_ihex_line(&s);
        let _ = parse_ihex_file(&s);
    }
}

#[test]
fn ihex_parse_no_colon_err() {
    assert!(parse_ihex_line("10010000000000F0").is_err());
}

#[test]
fn ihex_parse_too_short_err() {
    assert!(parse_ihex_line(":").is_err());
    assert!(parse_ihex_line(":00").is_err());
    assert!(parse_ihex_line(":000000").is_err());
}

#[test]
fn ihex_parse_odd_hex_len_err() {
    assert!(parse_ihex_line(":0000000F").is_err());
}

#[test]
fn ihex_parse_non_hex_err() {
    assert!(parse_ihex_line(":ZZ010000XX").is_err());
}

#[test]
fn ihex_parse_unknown_record_type_err() {
    // byte_count=0 addr=0 type=06 cs computed
    // sum = 0+0+0+6 = 6 → cs = (-6) & 0xff = 0xFA
    assert!(parse_ihex_line(":00000006FA").is_err());
}

#[test]
fn ihex_parse_bad_checksum_err() {
    assert!(parse_ihex_line(":00000001FE").is_err());
}

#[test]
fn ihex_parse_truncated_data_err() {
    // byte_count says 16 but only a few data bytes present
    assert!(parse_ihex_line(":1000000000FF").is_err());
}

#[test]
fn ihex_parse_eof_ok() {
    let rec = parse_ihex_line(":00000001FF").unwrap();
    assert!(rec.is_end());
}

#[test]
fn ihex_record_byte_count_saturates() {
    let big = vec![0u8; 300];
    let rec = IhexRecord::new(RecordType::Data, 0, big);
    assert_eq!(rec.byte_count, 255);
}

#[test]
fn ihex_loader_serialize_then_load_roundtrip() {
    let loader = IhexLoader::new();
    let mut mem = LoadedMemory::new();
    let mut seg = IhexSeg::new(0x1000);
    seg.data = (0..64u8).collect();
    mem.segments.push(seg);
    mem.start_address = Some(0x1000);
    let text = loader.serialize_to_ihex(&mem);
    let mem2 = loader.load_str(&text).expect("reload");
    assert_eq!(mem2.total_bytes(), 64);
    assert!(mem2.segments.iter().any(|s| s.base == 0x1000));
    assert_eq!(mem2.start_address, Some(0x1000));
}

#[test]
fn ihex_extended_linear_addr_high_segments() {
    let mut g = Lcg::new(0xAAAA_BBBB_CCCC_DDDD);
    let loader = IhexLoader::new();
    for _ in 0..10 {
        let upper = (g.next_u64() & 0xFFFF) as u16;
        let mut mem = LoadedMemory::new();
        let mut seg = IhexSeg::new((u32::from(upper) << 16) | 0x100);
        seg.data = g.next_bytes(32);
        mem.segments.push(seg);
        let text = loader.serialize_to_ihex(&mem);
        let mem2 = loader.load_str(&text).unwrap();
        assert_eq!(mem2.total_bytes(), 32);
    }
}

#[test]
fn ihex_find_gaps_empty_when_single() {
    let mut mem = LoadedMemory::new();
    let mut s = IhexSeg::new(0);
    s.data = vec![0; 16];
    mem.segments.push(s);
    assert!(mem.find_gaps().is_empty());
}

#[test]
fn ihex_find_gaps_unsorted_input() {
    let mut mem = LoadedMemory::new();
    let mut a = IhexSeg::new(0x200); a.data = vec![1; 16];
    let mut b = IhexSeg::new(0x000); b.data = vec![2; 16];
    mem.segments = vec![a, b];
    let gaps = mem.find_gaps();
    assert_eq!(gaps, vec![(0x10, 0x200)]);
}

#[test]
fn ihex_merge_threshold_boundary() {
    let mut mem = LoadedMemory::new();
    let mut a = IhexSeg::new(0); a.data = vec![1; 4];
    let mut b = IhexSeg::new(8); b.data = vec![2; 4]; // gap 4
    mem.segments = vec![a, b];
    mem.merge_adjacent_segments(3); // below gap
    assert_eq!(mem.segments.len(), 2);
    mem.merge_adjacent_segments(4); // at gap → merge
    assert_eq!(mem.segments.len(), 1);
    assert_eq!(mem.segments[0].data.len(), 12);
}

#[test]
fn ihex_memory_segment_end_saturates() {
    let mut s = IhexSeg::new(u32::MAX - 4);
    s.data = vec![0u8; 10];
    assert_eq!(s.end(), u32::MAX);
}

#[test]
fn ihex_memory_segment_read_u8_oob() {
    let mut s = IhexSeg::new(0x100);
    s.data = vec![0xAB; 8];
    assert_eq!(s.read_u8(0xFF), None);
    assert_eq!(s.read_u8(0x100), Some(0xAB));
    assert_eq!(s.read_u8(0x107), Some(0xAB));
    assert_eq!(s.read_u8(0x108), None);
}

#[test]
fn ihex_parse_empty_and_whitespace() {
    assert!(parse_ihex_file("").unwrap().is_empty());
    assert!(parse_ihex_file("   \n\n  \n").unwrap().is_empty());
}

#[test]
fn ihex_stops_at_eof_record() {
    let text = ":00000001FF\n:10010000214601360121470136007EFE09D2190140\n";
    let recs = parse_ihex_file(text).unwrap();
    assert_eq!(recs.len(), 1); // stops after EOF
}

// ─── srec: type round-trip ───────────────────────────────────────────────────

#[test]
fn srec_type_full_roundtrip() {
    for c in ['0','1','2','3','5','7','8','9'] {
        let t = SrecType::from_char(c).expect("known");
        assert_eq!(t.as_char(), c);
    }
    for c in ['4','6','a','A','x','!'] {
        assert!(SrecType::from_char(c).is_none(), "{c}");
    }
}

#[test]
fn srec_addr_bytes_matrix() {
    assert_eq!(SrecType::S0Header.addr_bytes(), 2);
    assert_eq!(SrecType::S1Data16.addr_bytes(), 2);
    assert_eq!(SrecType::S2Data24.addr_bytes(), 3);
    assert_eq!(SrecType::S3Data32.addr_bytes(), 4);
    assert_eq!(SrecType::S5Count16.addr_bytes(), 2);
    assert_eq!(SrecType::S7Start32.addr_bytes(), 4);
    assert_eq!(SrecType::S8Start24.addr_bytes(), 3);
    assert_eq!(SrecType::S9Start16.addr_bytes(), 2);
}

fn format_srec(rec: &SrecRecord) -> String {
    let addr_bytes = rec.type_.addr_bytes();
    let bc = (addr_bytes + rec.data.len() + 1) as u8;
    let mut bytes = vec![bc];
    for i in (0..addr_bytes).rev() {
        bytes.push(((rec.address >> (i * 8)) & 0xFF) as u8);
    }
    bytes.extend_from_slice(&rec.data);
    let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
    let cs = (0xFF - (sum & 0xFF)) as u8;
    bytes.push(cs);
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("S{}{}", rec.type_.as_char(), hex)
}

#[test]
fn srec_s1_format_parse_roundtrip_seeded() {
    let mut g = Lcg::new(0x1111_2222_3333_4444);
    for _ in 0..50 {
        let addr = (g.next_u64() & 0xFFFF) as u32;
        let len = (g.next_u8() as usize) % 30;
        let data = g.next_bytes(len);
        let rec = SrecRecord::new(SrecType::S1Data16, addr, data.clone());
        let s = format_srec(&rec);
        let p = parse_srec_line(&s).expect("parse");
        assert_eq!(p.address, addr);
        assert_eq!(p.data, data);
        assert_eq!(p.type_, SrecType::S1Data16);
    }
}

#[test]
fn srec_s2_s3_roundtrip_seeded() {
    let mut g = Lcg::new(0x5555_6666_7777_8888);
    for _ in 0..30 {
        let addr24 = g.next_u64() as u32 & 0x00FF_FFFF;
        let r = SrecRecord::new(SrecType::S2Data24, addr24, g.next_bytes(8));
        let p = parse_srec_line(&format_srec(&r)).unwrap();
        assert_eq!(p.address, addr24);

        let addr32 = g.next_u64() as u32;
        let r2 = SrecRecord::new(SrecType::S3Data32, addr32, g.next_bytes(12));
        let p2 = parse_srec_line(&format_srec(&r2)).unwrap();
        assert_eq!(p2.address, addr32);
    }
}

#[test]
fn srec_fuzz_never_panics() {
    let mut g = Lcg::new(0x99AA_BBCC_DDEE_FF00);
    for _ in 0..200 {
        let len = (g.next_u8() as usize) % 80;
        let raw = g.next_bytes(len);
        let mut s = String::from("S");
        s.push(char::from(b'0' + (g.next_u8() % 10)));
        for b in &raw {
            s.push_str(&format!("{b:02X}"));
        }
        let _ = parse_srec_line(&s);
    }
}

#[test]
fn srec_fuzz_file_never_panics() {
    let mut g = Lcg::new(0xFEED_FACE_BAAD_F00D);
    for _ in 0..50 {
        let n_lines = (g.next_u8() as usize) % 8;
        let mut text = String::new();
        for _ in 0..n_lines {
            let len = (g.next_u8() as usize) % 32;
            text.push('S');
            text.push(char::from(b'0' + (g.next_u8() % 10)));
            for b in g.next_bytes(len) {
                text.push_str(&format!("{b:02X}"));
            }
            text.push('\n');
        }
        let _ = parse_srec_file(&text);
    }
}

#[test]
fn srec_bad_starts() {
    assert!(parse_srec_line("").is_err());
    assert!(parse_srec_line("X1").is_err());
    assert!(parse_srec_line("S").is_err());
}

#[test]
fn srec_bad_type_char() {
    assert!(parse_srec_line("S4010203FF").is_err());
    assert!(parse_srec_line("S6010203FF").is_err());
}

#[test]
fn srec_bad_checksum_err() {
    assert!(parse_srec_line("S10B00000102030405060708090A00").is_err());
}

#[test]
fn srec_byte_count_too_small_err() {
    // S1 with bc=2 but needs at least addr(2)+cs(1)=3
    assert!(parse_srec_line("S102FFFFFF").is_err());
}

#[test]
fn srec_byte_count_exceeds_len_err() {
    // claim byte_count=20 but only a few bytes
    assert!(parse_srec_line("S114000000FF").is_err());
}

#[test]
fn srec_record_byte_count_saturates() {
    let huge = vec![0u8; 300];
    let r = SrecRecord::new(SrecType::S3Data32, 0, huge);
    assert_eq!(r.byte_count(), 0xFF);
}

#[test]
fn srec_predicate_helpers() {
    assert!(SrecType::S0Header.is_header());
    assert!(!SrecType::S1Data16.is_header());
    assert!(SrecType::S7Start32.is_start());
    assert!(SrecType::S8Start24.is_start());
    assert!(SrecType::S9Start16.is_start());
    assert!(!SrecType::S5Count16.is_start());
    assert!(SrecType::S3Data32.is_data());
    assert!(!SrecType::S5Count16.is_data());
}

#[test]
fn srec_loader_serialize_reload_roundtrip_seeded() {
    let mut g = Lcg::new(0xC0DE_BABE_F00D_FACE);
    let loader = SrecLoader::new();
    for _ in 0..10 {
        let mut mem = SrecMemory::new();
        let base = (g.next_u64() & 0xFFFF) as u32;
        let mut seg = SrecSeg::new(base);
        seg.data = g.next_bytes(48);
        let expected = seg.data.clone();
        mem.segments.push(seg);
        let text = loader.serialize_to_srec(&mem, 2);
        let mem2 = loader.load_str(&text).unwrap();
        assert_eq!(mem2.total_bytes(), expected.len());
    }
}

#[test]
fn srec_load_s3_terminator_entry() {
    let loader = SrecLoader::new();
    let recs = vec![
        SrecRecord::new(SrecType::S3Data32, 0xDEAD_BEEF, vec![1,2,3,4]),
        SrecRecord::new(SrecType::S7Start32, 0x1234_5678, vec![]),
    ];
    let mem = loader.load_from_records(&recs);
    assert_eq!(mem.entry_point(), Some(0x1234_5678));
}

#[test]
fn srec_memory_read_u8_misses() {
    let loader = SrecLoader::new();
    let recs = vec![SrecRecord::new(SrecType::S1Data16, 0x10, vec![0xAA,0xBB])];
    let mem = loader.load_from_records(&recs);
    assert_eq!(mem.read_u8(0x10), Some(0xAA));
    assert_eq!(mem.read_u8(0x12), None);
}

#[test]
fn srec_empty_file_returns_empty() {
    let v = parse_srec_file("").unwrap();
    assert!(v.is_empty());
}

#[test]
fn srec_whitespace_lines_skipped() {
    let v = parse_srec_file("\n  \n\n").unwrap();
    assert!(v.is_empty());
}

// ─── raw_binary: ArchHint round-trip & default_word_size ─────────────────────

#[test]
fn arch_hint_as_str_unique() {
    let all = [ArchHint::X86, ArchHint::X86_64, ArchHint::Arm, ArchHint::Arm64,
               ArchHint::Mips, ArchHint::Z80, ArchHint::Avr, ArchHint::Raw];
    let mut strs: Vec<_> = all.iter().map(rustre_loader::raw_binary_loader::ArchHint::as_str).collect();
    strs.sort_unstable();
    strs.dedup();
    assert_eq!(strs.len(), 8);
}

#[test]
fn arch_hint_word_sizes_matrix() {
    assert_eq!(ArchHint::X86.default_word_size(), 4);
    assert_eq!(ArchHint::X86_64.default_word_size(), 8);
    assert_eq!(ArchHint::Arm.default_word_size(), 4);
    assert_eq!(ArchHint::Arm64.default_word_size(), 8);
    assert_eq!(ArchHint::Mips.default_word_size(), 4);
    assert_eq!(ArchHint::Z80.default_word_size(), 2);
    assert_eq!(ArchHint::Avr.default_word_size(), 2);
    assert_eq!(ArchHint::Raw.default_word_size(), 4);
}

#[test]
fn detect_arch_elf_machines() {
    let mut d = vec![0u8; 32];
    d[0]=0x7F; d[1]=b'E'; d[2]=b'L'; d[3]=b'F';
    for (machine, expect) in [(3u16, ArchHint::X86), (62, ArchHint::X86_64),
                              (40, ArchHint::Arm), (183, ArchHint::Arm64),
                              (8, ArchHint::Mips), (10, ArchHint::Mips)] {
        d[18] = (machine & 0xFF) as u8;
        d[19] = (machine >> 8) as u8;
        assert_eq!(detect_arch_from_content(&d), expect, "machine={machine}");
    }
}

#[test]
fn detect_arch_macho_magics() {
    for (m, exp) in [(0xFEED_FACE_u32, ArchHint::X86), (0xCEFA_EDFE, ArchHint::X86),
                     (0xFEED_FACF, ArchHint::X86_64), (0xCFFA_EDFE, ArchHint::X86_64)] {
        let b = m.to_be_bytes();
        assert_eq!(detect_arch_from_content(&b), exp);
    }
}

#[test]
fn detect_arch_short_input() {
    assert_eq!(detect_arch_from_content(&[]), ArchHint::Raw);
    assert_eq!(detect_arch_from_content(&[0x55]), ArchHint::Raw);
    assert_eq!(detect_arch_from_content(&[0x55, 0x8B]), ArchHint::Raw);
}

#[test]
fn detect_arch_fuzz_never_panics() {
    let mut g = Lcg::new(0x0F0F_F0F0_5A5A_A5A5);
    for _ in 0..100 {
        let n = (g.next_u8() as usize) % 256;
        let data = g.next_bytes(n);
        let _ = detect_arch_from_content(&data);
    }
}

#[test]
fn auto_detect_base_empty_zero() {
    assert_eq!(auto_detect_base(&[], 4), 0);
    assert_eq!(auto_detect_base(&[0, 0, 0], 4), 0);
}

#[test]
fn auto_detect_base_finds_min_candidate() {
    // Two candidates: 0x00500000 then 0x00400000
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&0x0050_0000u32.to_le_bytes());
    data[4..8].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    assert_eq!(auto_detect_base(&data, 4), 0x0040_0000);
}

#[test]
fn auto_detect_base_word8() {
    let val: u64 = 0x0000_0000_0040_0000;
    let bytes = val.to_le_bytes();
    assert_eq!(auto_detect_base(&bytes, 8), val);
}

#[test]
fn split_into_sections_empty() {
    assert!(split_into_sections(&[], 0).is_empty());
}

#[test]
fn split_into_sections_all_data() {
    let data = vec![0u8; 8192]; // density 0 → all "data"
    let regs = split_into_sections(&data, 0x1000);
    assert!(!regs.is_empty());
    for r in &regs {
        assert!(r.is_readable());
        assert!(!r.is_executable());
    }
}

#[test]
fn split_into_sections_code_merging() {
    // Block full of single-byte opcodes → density > 0.04 → code
    let mut data = vec![0u8; 8192];
    for i in 0..4096 {
        data[i] = 0x90; // nop
    }
    let regs = split_into_sections(&data, 0x1000);
    assert!(regs.iter().any(rustre_loader::raw_binary_loader::BinaryRegion::is_executable));
}

#[test]
fn binary_region_size_perm_helpers() {
    let r = BinaryRegion::new(0x100, 0x200, PERM_READ | PERM_WRITE | PERM_EXECUTE, "x");
    assert_eq!(r.size(), 0x100);
    assert!(r.is_readable());
    assert!(r.is_writable());
    assert!(r.is_executable());
    let r2 = BinaryRegion::new(0x500, 0x400, 0, "n"); // inverted
    assert_eq!(r2.size(), 0); // saturating_sub
}

#[test]
fn binary_region_contains_boundaries() {
    let r = BinaryRegion::new(0x1000, 0x1010, PERM_READ, "x");
    assert!(!r.contains(0x0FFF));
    assert!(r.contains(0x1000));
    assert!(r.contains(0x100F));
    assert!(!r.contains(0x1010));
    assert!(!r.contains(0u64));
    assert!(!r.contains(u64::MAX));
}

#[test]
fn raw_loaded_binary_reads_endian() {
    let loader = RawBinaryLoader::new();
    let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let cfg = LoadConfig { base_addr: 0x100, is_big_endian: false, arch: ArchHint::X86, word_size: 4, entry_point: None };
    let b = loader.load(&data, &cfg);
    assert_eq!(b.read_u8(0x100), Some(0x12));
    assert_eq!(b.read_u16(0x100), Some(0x3412));
    assert_eq!(b.read_u32(0x100), Some(0x7856_3412));
    assert_eq!(b.read_u64(0x100), Some(0xF0DE_BC9A_7856_3412));

    let cfg_be = LoadConfig { base_addr: 0, is_big_endian: true, arch: ArchHint::X86, word_size: 4, entry_point: None };
    let b2 = loader.load(&data, &cfg_be);
    assert_eq!(b2.read_u32(0), Some(0x1234_5678));
    assert_eq!(b2.read_u64(0), Some(0x1234_5678_9ABC_DEF0));
}

#[test]
fn raw_loaded_binary_oob() {
    let loader = RawBinaryLoader::new();
    let data = vec![0u8; 2];
    let b = loader.load(&data, &LoadConfig { base_addr: 0x10, ..Default::default() });
    assert_eq!(b.read_u8(0x0F), None);
    assert_eq!(b.read_u16(0x11), None);
    assert_eq!(b.read_u32(0x10), None);
    assert_eq!(b.read_u64(0x10), None);
}

#[test]
fn raw_load_word_size_zero_uses_default() {
    let loader = RawBinaryLoader::new();
    let cfg = LoadConfig { base_addr: 0x4000, arch: ArchHint::X86_64, word_size: 0, ..Default::default() };
    let b = loader.load(&[0u8; 16], &cfg);
    assert_eq!(b.word_size, 8);
}

#[test]
fn raw_load_entry_default_is_base() {
    let loader = RawBinaryLoader::new();
    let b = loader.load(&[0u8; 8], &LoadConfig { base_addr: 0x9000, arch: ArchHint::X86, word_size: 4, ..Default::default() });
    assert_eq!(b.entry_point, 0x9000);
}

#[test]
fn raw_load_config_x86_helpers() {
    let c = LoadConfig::x86(0x0040_0000);
    assert_eq!(c.arch, ArchHint::X86);
    assert_eq!(c.word_size, 4);
    assert!(!c.is_big_endian);

    let c2 = LoadConfig::x86_64(0x0001_4000_0000);
    assert_eq!(c2.arch, ArchHint::X86_64);
    assert_eq!(c2.word_size, 8);
}

#[test]
fn raw_load_fuzz_never_panics() {
    let loader = RawBinaryLoader::new();
    let mut g = Lcg::new(0xABBA_DEAD_BEEF_CAFE);
    for _ in 0..50 {
        let len = (g.next_u8() as usize) % 256;
        let data = g.next_bytes(len);
        let cfg = LoadConfig {
            base_addr: g.next_u64() & 0xFFFF_F000,
            arch: ArchHint::Raw,
            entry_point: None,
            is_big_endian: (g.next_u8() & 1) == 1,
            word_size: 4,
        };
        let b = loader.load(&data, &cfg);
        assert_eq!(b.data.len(), len);
    }
}

#[test]
fn raw_region_at_finds_match_or_none() {
    let loader = RawBinaryLoader::new();
    let b = loader.load(&vec![0u8; 8192], &LoadConfig { base_addr: 0x2000, ..Default::default() });
    assert!(b.region_at(0x2000).is_some());
    assert!(b.region_at(0x1FFF).is_none());
}

// ─── Hash / Eq consistency on RecordType + ArchHint + SrecType ───────────────

#[test]
fn hash_eq_record_type_pairs() {
    use std::collections::HashSet;
    let mut s: HashSet<RecordType> = HashSet::new();
    // RecordType doesn't impl Hash; only PartialEq. So test PartialEq pairs.
    let _ = &mut s; // silence; switch to plain eq pairs:
    let all = [
        RecordType::Data, RecordType::EndOfFile, RecordType::ExtendedSegmentAddr,
        RecordType::StartSegmentAddr, RecordType::ExtendedLinearAddr, RecordType::StartLinearAddr,
    ];
    for a in &all {
        for b in &all {
            let eq = a == b;
            assert_eq!(eq, a.as_u8() == b.as_u8());
        }
    }
}

#[test]
fn eq_arch_hint_pairs() {
    let all = [ArchHint::X86, ArchHint::X86_64, ArchHint::Arm, ArchHint::Arm64,
               ArchHint::Mips, ArchHint::Z80, ArchHint::Avr, ArchHint::Raw];
    let mut count = 0;
    for a in &all {
        for b in &all {
            let eq = a == b;
            assert_eq!(eq, a.as_str() == b.as_str());
            count += 1;
        }
    }
    assert_eq!(count, 64);
}

#[test]
fn eq_srec_type_pairs() {
    let all = [SrecType::S0Header, SrecType::S1Data16, SrecType::S2Data24,
               SrecType::S3Data32, SrecType::S5Count16,
               SrecType::S7Start32, SrecType::S8Start24, SrecType::S9Start16];
    for a in &all {
        for b in &all {
            let eq = a == b;
            assert_eq!(eq, a.as_char() == b.as_char());
        }
    }
}

// ─── Send/Sync threaded stress on RawBinaryLoader & loaders ──────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn loaders_are_send_sync() {
    assert_send_sync::<RawBinaryLoader>();
    assert_send_sync::<IhexLoader>();
    assert_send_sync::<SrecLoader>();
    assert_send_sync::<LoadedBinary>();
}

#[test]
fn threaded_stress_raw_loader_4x100() {
    use std::sync::Arc;
    use std::thread;
    let loader = Arc::new(RawBinaryLoader::new());
    let mut handles = vec![];
    for tid in 0..4u64 {
        let l = loader.clone();
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new(0xBEEF_DEAD_0000_0000 ^ tid);
            for _ in 0..100 {
                let len = (g.next_u8() as usize) % 64;
                let data = g.next_bytes(len);
                let b = l.load(&data, &LoadConfig { base_addr: 0x1000, arch: ArchHint::X86, word_size: 4, ..Default::default() });
                assert_eq!(b.data.len(), len);
                let _ = b.read_u32(0x1000);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_stress_ihex_parse_4x100() {
    use std::sync::Arc;
    use std::thread;
    let loader = Arc::new(IhexLoader::new());
    let valid = ":10010000214601360121470136007EFE09D2190140\n:00000001FF\n".to_string();
    let mut handles = vec![];
    for _ in 0..4 {
        let l = loader.clone();
        let v = valid.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let m = l.load_str(&v).unwrap();
                assert!(m.total_bytes() == 16);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_stress_srec_parse_4x100() {
    use std::sync::Arc;
    use std::thread;
    let loader = Arc::new(SrecLoader::new());
    let valid = "S10B00000102030405060708D0\nS9030000FC\n".to_string();
    let mut handles = vec![];
    for _ in 0..4 {
        let l = loader.clone();
        let v = valid.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let m = l.load_str(&v).unwrap();
                assert_eq!(m.total_bytes(), 8);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ─── Boundary: max-of-type addresses & u32 segment end ───────────────────────

#[test]
fn ihex_segment_end_at_u32_max_saturates_not_panics() {
    let mut s = IhexSeg::new(u32::MAX);
    s.data.push(0);
    assert_eq!(s.end(), u32::MAX);
}

#[test]
fn srec_record_byte_count_S0_min() {
    let r = SrecRecord::new(SrecType::S0Header, 0, vec![]);
    // addr_bytes(2) + data(0) + cs(1) = 3
    assert_eq!(r.byte_count(), 3);
}

#[test]
fn ihex_extended_segment_addr_decoded() {
    // ESA setting segment to 0x1000 → upper = 0x10000
    // bc=2, addr=0, type=2, data=[0x10,0x00], cs = -(2+0+0+2+0x10+0) = -0x14 = 0xEC
    let text = ":020000021000EC\n:10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n";
    let loader = IhexLoader::new();
    let mem = loader.load_str(text).unwrap();
    assert_eq!(mem.segments[0].base, 0x10000);
}
