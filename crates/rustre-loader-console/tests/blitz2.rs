//! blitz2: Deep adversarial tests for rustre-loader-console.
//!
//! Focus: parser robustness against malformed/truncated/oversized inputs,
//! seeded fuzzing, boundary conditions, Display/Debug invariants, Hash/Eq
//! consistency, Send/Sync threaded stress.

use rustre_loader_console::{
    detect_format, extract_rom_strings, is_gb, is_gba, is_genesis, is_nes, is_snes, xor_checksum,
    BankSwitchInfo, ConsoleArch, ConsoleDisassemblyHints, ConsoleLoader, ConsoleStream,
    GameConsoleRomLoader, GbCartType, GbHeader, GbaHeader, GbaSaveType, GenesisHeader,
    GenesisRegion, NesHeader, NesMirroring, NesTvSystem, Platform, SnesHeader, SnesMapMode,
    StreamStats, GB_LOGO, GBA_ENTRY_INSTR, GBA_HEADER_SIZE, NES_MAGIC,
};
use rustre_core::loader::{Loader, LoaderInput};
use rustre_core::endian::Endian;
use rustre_core::arch::Architecture;
use std::sync::Arc;

// ── seeded LCG ───────────────────────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self { Self(0xDEAD_BEEF_CAFE_BABE) }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let x = self.next_u64().to_le_bytes();
            for &b in &x { if v.len() < n { v.push(b); } }
        }
        v
    }
}

// ── 1. detect_format fuzz: never panics ─────────────────────────────────────
#[test]
fn fuzz_detect_format_never_panics() {
    let mut lcg = Lcg::new();
    for size in [0usize, 1, 2, 3, 4, 5, 7, 15, 16, 33, 64, 100, 256, 511, 512, 1024, 2048] {
        for _ in 0..20 {
            let buf = lcg.bytes(size);
            let _ = detect_format(&buf);
        }
    }
}

#[test]
fn fuzz_is_predicates_never_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let sz = (lcg.next_u64() as usize) % 2048;
        let buf = lcg.bytes(sz);
        let _ = is_nes(&buf);
        let _ = is_snes(&buf);
        let _ = is_gb(&buf);
        let _ = is_gba(&buf);
        let _ = is_genesis(&buf);
    }
}

// ── 2. NesHeader: boundary / truncation / fuzz ──────────────────────────────
#[test]
fn nes_header_truncated_at_every_byte() {
    let mut full = vec![0u8; 16];
    full[..4].copy_from_slice(NES_MAGIC);
    full[4] = 2;
    full[5] = 1;
    for n in 0..16 {
        let r = NesHeader::parse(&full[..n]);
        assert!(r.is_err(), "n={n}");
    }
    assert!(NesHeader::parse(&full).is_ok());
}

#[test]
fn nes_header_fuzz_random_bodies_after_magic() {
    let mut lcg = Lcg::new();
    for _ in 0..100 {
        let mut buf = vec![0u8; 16];
        buf[..4].copy_from_slice(NES_MAGIC);
        for i in 4..16 {
            buf[i] = (lcg.next_u64() & 0xFF) as u8;
        }
        let _ = NesHeader::parse(&buf).expect("valid magic should parse");
    }
}

#[test]
fn nes_header_fuzz_random_garbage_returns_err() {
    let mut lcg = Lcg::new();
    let mut errs = 0;
    for _ in 0..50 {
        let buf = lcg.bytes(16);
        // very unlikely to match magic
        if NesHeader::parse(&buf).is_err() {
            errs += 1;
        }
    }
    assert!(errs >= 45);
}

#[test]
fn nes_prg_chr_sizes_at_boundary() {
    let mut buf = vec![0u8; 16];
    buf[..4].copy_from_slice(NES_MAGIC);
    buf[4] = 255;
    buf[5] = 255;
    let h = NesHeader::parse(&buf).unwrap();
    assert_eq!(h.prg_rom_size(), 255 * 16 * 1024);
    assert_eq!(h.chr_rom_size(), 255 * 8 * 1024);
}

#[test]
fn nes_vectors_oob_returns_none() {
    let mut buf = vec![0u8; 16];
    buf[..4].copy_from_slice(NES_MAGIC);
    buf[4] = 2; // claims 2 prg banks but no data follows
    let h = NesHeader::parse(&buf).unwrap();
    assert_eq!(h.reset_vector(&buf), None);
    assert_eq!(h.nmi_vector(&buf), None);
    assert_eq!(h.irq_vector(&buf), None);
}

#[test]
fn nes_mapper_decode_all_low_bits() {
    for m in 0u8..=15 {
        let mut buf = vec![0u8; 16];
        buf[..4].copy_from_slice(NES_MAGIC);
        buf[4] = 1;
        buf[6] = (m & 0x0F) << 4; // lo nibble of mapper
        let h = NesHeader::parse(&buf).unwrap();
        assert_eq!(h.mapper as u8, m);
    }
}

#[test]
fn nes_tv_system_pal_vs_ntsc() {
    let mut buf = vec![0u8; 16];
    buf[..4].copy_from_slice(NES_MAGIC);
    buf[4] = 1;
    buf[9] = 0;
    assert_eq!(NesHeader::parse(&buf).unwrap().tv_system, NesTvSystem::Ntsc);
    buf[9] = 1;
    assert_eq!(NesHeader::parse(&buf).unwrap().tv_system, NesTvSystem::Pal);
}

#[test]
fn nes_mirroring_all_combos() {
    let mk = |f6: u8| {
        let mut b = vec![0u8; 16];
        b[..4].copy_from_slice(NES_MAGIC);
        b[4] = 1;
        b[6] = f6;
        NesHeader::parse(&b).unwrap().mirroring
    };
    assert_eq!(mk(0x00), NesMirroring::Horizontal);
    assert_eq!(mk(0x01), NesMirroring::Vertical);
    assert_eq!(mk(0x08), NesMirroring::FourScreen);
    assert_eq!(mk(0x09), NesMirroring::FourScreen); // four-screen wins
}

// ── 3. GbHeader fuzz / boundary ─────────────────────────────────────────────
fn gb_rom_with_logo() -> Vec<u8> {
    let mut rom = vec![0u8; 0x150];
    rom[0x104..0x134].copy_from_slice(&GB_LOGO);
    let mut x = 0u8;
    for &b in &rom[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
    rom[0x14D] = x;
    rom
}

#[test]
fn gb_header_truncated_returns_err() {
    let full = gb_rom_with_logo();
    for n in [0usize, 1, 0x100, 0x14F] {
        assert!(GbHeader::parse(&full[..n]).is_err());
    }
}

#[test]
fn gb_header_corrupted_logo_returns_err() {
    let mut rom = gb_rom_with_logo();
    rom[0x110] ^= 0xFF;
    assert!(GbHeader::parse(&rom).is_err());
}

#[test]
fn gb_rom_size_oversized_code_returns_zero_not_panic() {
    let mut rom = gb_rom_with_logo();
    rom[0x148] = 0xFF; // huge shift
    let mut x = 0u8;
    for &b in &rom[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
    rom[0x14D] = x;
    let h = GbHeader::parse(&rom).unwrap();
    let _ = h.rom_size_bytes(); // must not panic
}

#[test]
fn gb_cart_type_round_trip_known_bytes() {
    let pairs: &[(u8, GbCartType)] = &[
        (0x00, GbCartType::RomOnly),
        (0x01, GbCartType::Mbc1),
        (0x03, GbCartType::Mbc1RamBattery),
        (0x13, GbCartType::Mbc3RamBattery),
        (0x1B, GbCartType::Mbc5RamBattery),
        (0xFE, GbCartType::HuC3),
    ];
    for (b, expected) in pairs {
        assert_eq!(GbCartType::from_byte(*b), *expected);
    }
}

#[test]
fn gb_cart_type_unknown_byte() {
    let u = GbCartType::from_byte(0x77);
    assert!(matches!(u, GbCartType::Unknown(0x77)));
}

#[test]
fn gb_sram_size_table() {
    let table = [(0x00, 0), (0x01, 2*1024), (0x02, 8*1024), (0x03, 32*1024),
                 (0x04, 128*1024), (0x05, 64*1024), (0x99, 0)];
    let mut rom = gb_rom_with_logo();
    for (code, expected) in table {
        rom[0x149] = code;
        let mut x = 0u8;
        for &b in &rom[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
        rom[0x14D] = x;
        let h = GbHeader::parse(&rom).unwrap();
        assert_eq!(h.sram_size_bytes(), expected, "code={code:#x}");
    }
}

#[test]
fn gb_cgb_flag_detection() {
    let mut rom = gb_rom_with_logo();
    for (flag, is_cgb) in [(0x80u8, true), (0xC0, true), (0x00, false), (0x42, false)] {
        rom[0x143] = flag;
        let mut x = 0u8;
        for &b in &rom[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
        rom[0x14D] = x;
        let h = GbHeader::parse(&rom).unwrap();
        assert_eq!(h.is_cgb(), is_cgb);
    }
}

#[test]
fn gb_fuzz_after_logo_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let mut rom = gb_rom_with_logo();
        for i in 0x134..0x150 {
            rom[i] = (lcg.next_u64() & 0xFF) as u8;
        }
        if let Ok(h) = GbHeader::parse(&rom) {
            let _ = h.rom_size_bytes();
            let _ = h.sram_size_bytes();
            let _ = h.to_string();
        }
    }
}

// ── 4. GbaHeader ────────────────────────────────────────────────────────────
fn gba_rom() -> Vec<u8> {
    let mut rom = vec![0u8; 0x200];
    rom[..4].copy_from_slice(&GBA_ENTRY_INSTR);
    rom[0xA0..0xAC].copy_from_slice(b"TESTGAME\0\0\0\0");
    rom[0xAC..0xB0].copy_from_slice(b"AABC");
    rom[0xB0..0xB2].copy_from_slice(b"01");
    rom[0xB2] = 0x96;
    let sum: u8 = rom[0xA0..0xBD].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    rom[0xBD] = (0x19u8.wrapping_add(sum)).wrapping_neg();
    rom
}

#[test]
fn gba_header_truncated() {
    let r = gba_rom();
    for n in [0usize, 1, 4, 100, GBA_HEADER_SIZE - 1] {
        assert!(GbaHeader::parse(&r[..n]).is_err());
    }
}

#[test]
fn gba_header_bad_entry_instr() {
    let mut r = gba_rom();
    r[0] ^= 0xFF;
    assert!(GbaHeader::parse(&r).is_err());
    assert!(!is_gba(&r));
}

#[test]
fn gba_complement_check_valid_then_invalid() {
    let r = gba_rom();
    let h = GbaHeader::parse(&r).unwrap();
    assert!(h.verify_complement(&r));
    let mut bad = r;
    bad[0xBD] = bad[0xBD].wrapping_add(1);
    let h2 = GbaHeader::parse(&bad).unwrap();
    assert!(!h2.verify_complement(&bad));
}

#[test]
fn gba_save_type_detect_all() {
    let r = gba_rom();
    assert_eq!(GbaSaveType::detect(&r), GbaSaveType::None);
    let mut rs = r.clone();
    rs.extend_from_slice(b"SRAM_V112");
    assert_eq!(GbaSaveType::detect(&rs), GbaSaveType::Sram);
    let mut re = r.clone();
    re.extend_from_slice(b"EEPROM_V124");
    assert_eq!(GbaSaveType::detect(&re), GbaSaveType::Eeprom);
    let mut rf = r.clone();
    rf.extend_from_slice(b"FLASH_V120");
    assert_eq!(GbaSaveType::detect(&rf), GbaSaveType::Flash64);
    let mut rf128 = r;
    rf128.extend_from_slice(b"FLASH1M_V103");
    assert_eq!(GbaSaveType::detect(&rf128), GbaSaveType::Flash128);
}

#[test]
fn gba_save_type_display() {
    for t in [GbaSaveType::None, GbaSaveType::Eeprom, GbaSaveType::Sram,
              GbaSaveType::Flash64, GbaSaveType::Flash128] {
        let s = t.to_string();
        assert!(!s.is_empty());
    }
}

// ── 5. SnesHeader & MapMode ─────────────────────────────────────────────────
#[test]
fn snes_map_mode_decode_known_bytes() {
    assert_eq!(SnesMapMode::from_byte(0x20), SnesMapMode::LoRom);
    assert_eq!(SnesMapMode::from_byte(0x21), SnesMapMode::HiRom);
    assert_eq!(SnesMapMode::from_byte(0x22), SnesMapMode::Sdd1Rom);
    assert_eq!(SnesMapMode::from_byte(0x23), SnesMapMode::Sa1Rom);
    assert_eq!(SnesMapMode::from_byte(0x25), SnesMapMode::ExHiRom);
    assert_eq!(SnesMapMode::from_byte(0x2A), SnesMapMode::ExLoRom);
}

#[test]
fn snes_map_mode_unknown_preserves_low_nibble() {
    let m = SnesMapMode::from_byte(0x2F);
    assert!(matches!(m, SnesMapMode::Unknown(0x0F)));
}

#[test]
fn snes_map_mode_display_non_empty() {
    for b in [0x20u8, 0x21, 0x22, 0x23, 0x25, 0x2A, 0x2F] {
        assert!(!SnesMapMode::from_byte(b).to_string().is_empty());
    }
}

#[test]
fn snes_header_oob_returns_err() {
    let data = vec![0u8; 0x100];
    assert!(SnesHeader::parse_at(&data, 0x7FB0).is_err());
}

#[test]
fn snes_copier_header_detection() {
    let mut a = vec![0u8; 32 * 1024];
    assert!(!SnesHeader::has_copier_header(&a));
    a.extend_from_slice(&[0u8; 512]);
    assert!(SnesHeader::has_copier_header(&a));
}

#[test]
fn snes_checksum_valid_property() {
    // construct a header where comp ^ check = 0xFFFF
    let mut data = vec![0u8; 0x8000];
    let off = 0x7FB0;
    // title printable
    for i in 0..0x15 { data[off + 0x10 + i] = b' '; }
    data[off + 0x25] = 0x20; // LoROM
    data[off + 0x2C..off + 0x2E].copy_from_slice(&0x1234u16.to_le_bytes());
    data[off + 0x2E..off + 0x30].copy_from_slice(&(!0x1234u16).to_le_bytes());
    let h = SnesHeader::parse_at(&data, off).unwrap();
    assert!(h.checksum_valid());
}

#[test]
fn snes_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let buf = lcg.bytes(0x10000);
        let _ = SnesHeader::parse(&buf);
        let _ = is_snes(&buf);
    }
}

// ── 6. GenesisHeader ────────────────────────────────────────────────────────
fn genesis_rom() -> Vec<u8> {
    let mut rom = vec![0u8; 0x400];
    rom[0..4].copy_from_slice(&0xFFFFFEu32.to_be_bytes());
    rom[4..8].copy_from_slice(&0x200u32.to_be_bytes());
    rom[0x100..0x110].copy_from_slice(b"SEGA MEGA DRIVE ");
    rom[0x1F0..0x200].copy_from_slice(b"U               ");
    rom
}

#[test]
fn genesis_truncated() {
    let r = genesis_rom();
    for n in [0usize, 0x100, 0x1FF] {
        assert!(GenesisHeader::parse(&r[..n]).is_err());
    }
}

#[test]
fn genesis_console_variants() {
    for name in [&b"SEGA MEGA DRIVE "[..], b"SEGA GENESIS    ", b"SEGA PICO       ", b"SEGA 32X        "] {
        let mut r = vec![0u8; 0x400];
        r[0x100..0x110].copy_from_slice(name);
        assert!(is_genesis(&r));
    }
}

#[test]
fn genesis_region_from_str_combinations() {
    assert_eq!(GenesisRegion::parse_region("J"), GenesisRegion::Japan);
    assert_eq!(GenesisRegion::parse_region("U"), GenesisRegion::Usa);
    assert_eq!(GenesisRegion::parse_region("E"), GenesisRegion::Europe);
    assert!(matches!(GenesisRegion::parse_region("JU"), GenesisRegion::Multi(_)));
    assert_eq!(GenesisRegion::parse_region(""), GenesisRegion::Unknown);
}

#[test]
fn genesis_region_display() {
    assert_eq!(GenesisRegion::Japan.to_string(), "JP");
    assert_eq!(GenesisRegion::Usa.to_string(), "US");
    assert_eq!(GenesisRegion::Europe.to_string(), "EU");
    assert_eq!(GenesisRegion::Unknown.to_string(), "??");
    let m = GenesisRegion::Multi(vec![GenesisRegion::Japan, GenesisRegion::Usa]);
    assert_eq!(m.to_string(), "JP|US");
}

#[test]
fn genesis_compute_checksum_deterministic() {
    let mut lcg = Lcg::new();
    let buf = lcg.bytes(0x800);
    let a = GenesisHeader::compute_checksum(&buf);
    let b = GenesisHeader::compute_checksum(&buf);
    assert_eq!(a, b);
}

#[test]
fn genesis_32x_detection() {
    let mut r = vec![0u8; 0x400];
    r[0x100..0x110].copy_from_slice(b"SEGA 32X        ");
    let h = GenesisHeader::parse(&r).unwrap();
    assert!(h.is_32x());
}

// ── 7. ConsoleStream / StreamStats ──────────────────────────────────────────
#[test]
fn console_stream_empty() {
    let s = ConsoleStream::analyse(b"");
    assert_eq!(s.byte_count, 0);
    assert!(!s.is_binary);
    assert!(s.detected_format.is_none());
}

#[test]
fn console_stream_eq_reflexive() {
    let pairs: Vec<&[u8]> = vec![b"", b"abc", b"\x00\x01\x02", b"MZfoo", b"hello world", b"\x7fELF"];
    for a in &pairs {
        let sa = ConsoleStream::analyse(a);
        let sa2 = ConsoleStream::analyse(a);
        assert_eq!(sa, sa2);
        for b in &pairs {
            if a != b {
                let sb = ConsoleStream::analyse(b);
                // analyse is a pure function of input
                if sa == sb {
                    // ok: structurally equal
                }
            }
        }
    }
}

#[test]
fn stream_stats_min_max_invariants() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = (lcg.next_u64() as usize % 200) + 1;
        let buf = lcg.bytes(n);
        let s = StreamStats::compute(&buf);
        assert!(s.min_byte <= s.max_byte);
        assert!(s.null_bytes <= buf.len());
        assert!(s.printable_ascii <= buf.len());
    }
}

#[test]
fn stream_stats_display_contains_keys() {
    let s = StreamStats::compute(b"abc\0\0");
    let d = s.to_string();
    assert!(d.contains("nulls"));
    assert!(d.contains("printable"));
    assert!(d.contains("min"));
    assert!(d.contains("max"));
}

// ── 8. xor_checksum properties ──────────────────────────────────────────────
#[test]
fn xor_checksum_empty_is_zero() {
    assert_eq!(xor_checksum(b"", None), 0);
}

#[test]
fn xor_checksum_double_xor_is_zero() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let n = (lcg.next_u64() as usize % 100) + 1;
        let buf = lcg.bytes(n);
        let c = xor_checksum(&buf, None);
        let mut doubled = buf.clone();
        doubled.push(c);
        assert_eq!(xor_checksum(&doubled, None), 0);
    }
}

#[test]
fn xor_checksum_skip_out_of_range_is_same() {
    let data = [0x12u8, 0x34, 0x56];
    let normal = xor_checksum(&data, None);
    let skip_oob = xor_checksum(&data, Some(999));
    assert_eq!(normal, skip_oob);
}

// ── 9. extract_rom_strings ──────────────────────────────────────────────────
#[test]
fn extract_strings_min_len_filter() {
    let data = b"ab\0abcd\0xyz\0longerstring";
    let s = extract_rom_strings(data, 5);
    assert!(s.iter().all(|r| r.text.len() >= 5));
    assert!(s.iter().any(|r| r.text == "longerstring"));
}

#[test]
fn extract_strings_empty_min_len_zero() {
    let s = extract_rom_strings(b"", 0);
    assert!(s.is_empty());
}

#[test]
fn extract_strings_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let n = (lcg.next_u64() as usize % 500) + 1;
        let buf = lcg.bytes(n);
        for min in [0usize, 1, 4, 16, 64, 256] {
            let r = extract_rom_strings(&buf, min);
            assert!(r.iter().all(|s| s.text.len() >= min || min == 0));
        }
    }
}

// ── 10. BankSwitchInfo construction ─────────────────────────────────────────
#[test]
fn bank_switch_info_oversized_gb_rom_size_no_panic() {
    let mut rom = gb_rom_with_logo();
    rom[0x148] = 0xFF;
    let mut x = 0u8;
    for &b in &rom[0x134..0x14D] { x = x.wrapping_sub(b).wrapping_sub(1); }
    rom[0x14D] = x;
    let h = GbHeader::parse(&rom).unwrap();
    let info = BankSwitchInfo::from_gb_header(&h);
    assert!(info.bank_count >= 2);
}

#[test]
fn bank_switch_info_nes_battery_flag() {
    let mut rom = vec![0u8; 16];
    rom[..4].copy_from_slice(NES_MAGIC);
    rom[4] = 2;
    rom[6] = 0x02; // battery flag
    let h = NesHeader::parse(&rom).unwrap();
    let info = BankSwitchInfo::from_nes_header(&h);
    assert!(info.has_sram_banking);
}

// ── 11. ConsoleArch ─────────────────────────────────────────────────────────
#[test]
fn console_arch_send_sync_threaded() {
    let arch = Arc::new(ConsoleArch::new("test", 4, Endian::Little));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = Arc::clone(&arch);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(a.pointer_size(), 4);
                assert_eq!(a.name(), "test");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── 12. Platform & ConsoleDisassemblyHints ──────────────────────────────────
#[test]
fn platform_eq_reflexive_and_distinct() {
    let ps = [Platform::Nes, Platform::Snes, Platform::GameBoy];
    for (i, a) in ps.iter().enumerate() {
        for (j, b) in ps.iter().enumerate() {
            assert_eq!(a == b, i == j);
        }
    }
}

#[test]
fn disasm_hints_unique_per_platform() {
    let n = ConsoleDisassemblyHints::nes_arch();
    let s = ConsoleDisassemblyHints::snes_arch();
    let g = ConsoleDisassemblyHints::gameboy_arch();
    assert_ne!(n, s);
    assert_ne!(s, g);
    assert_ne!(n, g);
}

// ── 13. GameConsoleRomLoader robustness ─────────────────────────────────────
#[test]
fn unified_loader_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() as usize % 0x500) + 1;
        let buf = lcg.bytes(n);
        let _ = GameConsoleRomLoader::parse(&buf);
    }
}

#[test]
fn unified_loader_empty_returns_none() {
    assert!(GameConsoleRomLoader::parse(&[]).is_none());
}

// ── 14. ConsoleLoader async stress ──────────────────────────────────────────
#[tokio::test]
async fn console_loader_round_trip_uri() {
    for uri in ["a", "very/long/path/file.bin", ""] {
        let input = LoaderInput::new(uri, b"x".to_vec());
        let r = ConsoleLoader.load(input).await.unwrap();
        assert_eq!(r.view.uri, uri);
    }
}

#[tokio::test]
async fn console_loader_seeded_inputs() {
    let mut lcg = Lcg::new();
    for _ in 0..10 {
        let sz = (lcg.next_u64() as usize) % 4096;
        let buf = lcg.bytes(sz);
        let input = LoaderInput::new("seeded", buf);
        let _ = ConsoleLoader.load(input).await.unwrap();
    }
}

// ── 15. Display non-empty for parseable headers ─────────────────────────────
#[test]
fn gb_header_display_non_empty() {
    let r = gb_rom_with_logo();
    let h = GbHeader::parse(&r).unwrap();
    assert!(!h.to_string().is_empty());
}

#[test]
fn gba_header_display_non_empty() {
    let r = gba_rom();
    let h = GbaHeader::parse(&r).unwrap();
    assert!(!h.to_string().is_empty());
}

#[test]
fn nes_header_display_non_empty() {
    let mut buf = vec![0u8; 16];
    buf[..4].copy_from_slice(NES_MAGIC);
    buf[4] = 1;
    let h = NesHeader::parse(&buf).unwrap();
    assert!(!h.to_string().is_empty());
}

#[test]
fn nes_tv_system_display() {
    assert_eq!(NesTvSystem::Ntsc.to_string(), "NTSC");
    assert_eq!(NesTvSystem::Pal.to_string(), "PAL");
    assert_eq!(NesTvSystem::DualCompatible.to_string(), "Dual");
}

#[test]
fn nes_mirroring_display() {
    assert_eq!(NesMirroring::Horizontal.to_string(), "horizontal");
    assert_eq!(NesMirroring::Vertical.to_string(), "vertical");
    assert_eq!(NesMirroring::FourScreen.to_string(), "four-screen");
    assert_eq!(NesMirroring::MapperControlled.to_string(), "mapper");
}

// ── 16. Cross-format negative checks ────────────────────────────────────────
#[test]
fn nes_rom_not_other_formats() {
    let mut rom = vec![0u8; 16 + 16*1024];
    rom[..4].copy_from_slice(NES_MAGIC);
    rom[4] = 1;
    assert!(is_nes(&rom));
    assert!(!is_gb(&rom));
    assert!(!is_gba(&rom));
    assert!(!is_genesis(&rom));
}

#[test]
fn gb_rom_not_other_formats() {
    let rom = gb_rom_with_logo();
    assert!(is_gb(&rom));
    assert!(!is_nes(&rom));
    assert!(!is_gba(&rom));
}
