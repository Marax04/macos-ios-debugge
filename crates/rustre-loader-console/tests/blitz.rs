//! Exhaustive integration tests for `rustre-loader-console`.
//!
//! Targets public APIs in `lib.rs`, `format_detection`, `switch_formats`,
//! and other modules. Focus: edge cases, malformed inputs, invariants.

use rustre_loader_console::format_detection::{
    ConsoleFormat, ConsoleFormatDetector, FormatDb, FormatFeatureSet, FormatSignature,
    LicenseRegion,
};
use rustre_loader_console::switch_formats::{
    AssetSection, ExefsSectionHeader, NcaContentType, NcaKeyAreaEntry, NroAssetHeader, NroHeader,
    NsoApiInfo, NsoBss, NsoHeader, NsoModuleInfo, NsoSegmentInfo, RomFsEntry, RomFsEntryIter,
    RomFsHeader, SwitchError, SwitchFormats, SwitchNpdm, SwitchRomFs, ASET_MAGIC, NRO_MAGIC,
    NSO_MAGIC,
};
use rustre_loader_console::{
    detect_format, extract_rom_strings, is_gb, is_gba, is_genesis, is_snes, xor_checksum,
    BankSwitchInfo, ConsoleArch, ConsoleDisassemblyHints, ConsoleStream,
    GameConsoleRomLoader, GbCartType, GbHeader, GbaHeader, GbaSaveType, GenesisHeader,
    GenesisRegion, NesHeader, NesMirroring, NesTvSystem, Platform, RomString, SnesHeader,
    SnesMapMode, StreamStats, GB_LOGO, GBA_ENTRY_INSTR, GBA_HEADER_SIZE, NES_MAGIC,
};

// ─────────────────────────────────────────────────────────────────────────────
// detect_format — broader coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_format_empty() {
    assert_eq!(detect_format(b""), None);
}

#[test]
fn detect_format_one_byte_mz() {
    // "MZ" is two bytes; one byte 'M' should not match
    assert_eq!(detect_format(b"M"), None);
}

#[test]
fn detect_format_prefix_only_pe() {
    assert_eq!(detect_format(b"MZ"), Some("pe".to_string()));
}

#[test]
fn detect_format_priority_order() {
    // PE magic at start wins even if elsewhere ELF bytes appear
    let mut data = b"MZ".to_vec();
    data.extend_from_slice(b"\x7fELF");
    assert_eq!(detect_format(&data), Some("pe".to_string()));
}

#[test]
fn detect_format_zeros_unknown() {
    assert_eq!(detect_format(&[0u8; 1024]), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// xor_checksum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xor_checksum_empty() {
    assert_eq!(xor_checksum(&[], None), 0);
}

#[test]
fn xor_checksum_skip_out_of_range() {
    // Skipping an out-of-range index should equal full XOR
    let data = [0x11u8, 0x22, 0x33];
    assert_eq!(xor_checksum(&data, Some(99)), 0x11 ^ 0x22 ^ 0x33);
}

#[test]
fn xor_checksum_skip_zero() {
    let data = [0xAAu8, 0xBB, 0xCC];
    assert_eq!(xor_checksum(&data, Some(0)), 0xBB ^ 0xCC);
}

#[test]
fn xor_checksum_single_byte_skipped() {
    let data = [0xFFu8];
    assert_eq!(xor_checksum(&data, Some(0)), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// extract_rom_strings
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn extract_rom_strings_empty() {
    let v = extract_rom_strings(&[], 3);
    assert!(v.is_empty());
}

#[test]
fn extract_rom_strings_tail() {
    // String at end of buffer (no terminator)
    let data = b"\x00abcdef";
    let v = extract_rom_strings(data, 3);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].text, "abcdef");
    assert_eq!(v[0].offset, 1);
}

#[test]
fn extract_rom_strings_min_len_zero() {
    // min_len 0 should collect every run including single chars
    let data = b"a\x00b";
    let v = extract_rom_strings(data, 0);
    assert!(v.len() >= 2);
}

#[test]
fn extract_rom_strings_only_terminators() {
    let data = vec![0u8; 16];
    let v = extract_rom_strings(&data, 4);
    assert!(v.is_empty());
}

#[test]
fn rom_string_eq() {
    let a = RomString { offset: 5, text: "x".into() };
    let b = RomString { offset: 5, text: "x".into() };
    assert_eq!(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// NesHeader — adversarial
// ─────────────────────────────────────────────────────────────────────────────

fn nes_header(prg: u8, chr: u8, flags6: u8, flags7: u8) -> Vec<u8> {
    let mut d = vec![0u8; 16];
    d[..4].copy_from_slice(NES_MAGIC);
    d[4] = prg;
    d[5] = chr;
    d[6] = flags6;
    d[7] = flags7;
    d
}

#[test]
fn nes_header_empty_data() {
    assert!(NesHeader::parse(&[]).is_err());
}

#[test]
fn nes_header_15_bytes_too_short() {
    assert!(NesHeader::parse(&[0u8; 15]).is_err());
}

#[test]
fn nes_header_exactly_16_bytes_zero_banks() {
    let h = NesHeader::parse(&nes_header(0, 0, 0, 0)).unwrap();
    assert_eq!(h.prg_rom_banks, 0);
    assert_eq!(h.chr_rom_banks, 0);
    assert_eq!(h.prg_rom_size(), 0);
    assert_eq!(h.chr_rom_size(), 0);
}

#[test]
fn nes_header_max_banks() {
    let h = NesHeader::parse(&nes_header(0xFF, 0xFF, 0, 0)).unwrap();
    assert_eq!(h.prg_rom_size(), 255 * 16 * 1024);
    assert_eq!(h.chr_rom_size(), 255 * 8 * 1024);
}

#[test]
fn nes_header_battery_flag() {
    let h = NesHeader::parse(&nes_header(1, 0, 0x02, 0)).unwrap();
    assert!(h.has_battery());
}

#[test]
fn nes_header_nes2_detected() {
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0x08)).unwrap();
    assert!(h.is_nes2());
}

#[test]
fn nes_header_vs_unisystem() {
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0x01)).unwrap();
    assert!(h.is_vs_unisystem());
}

#[test]
fn nes_header_playchoice() {
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0x02)).unwrap();
    assert!(h.is_playchoice());
}

#[test]
fn nes_header_horizontal_mirroring_default() {
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0)).unwrap();
    assert_eq!(h.mirroring, NesMirroring::Horizontal);
}

#[test]
fn nes_header_mapper_high_nibble() {
    // mapper = (flags7 & 0xF0) | (flags6 >> 4); flags6 = 0xA0 → low nibble A;
    // flags7 = 0xB0 → high nibble B; mapper = 0xBA
    let h = NesHeader::parse(&nes_header(1, 0, 0xA0, 0xB0)).unwrap();
    assert_eq!(h.mapper, 0xBA);
}

#[test]
fn nes_header_pal_tv_system() {
    let mut d = nes_header(1, 0, 0, 0);
    d[9] = 0x01;
    let h = NesHeader::parse(&d).unwrap();
    assert_eq!(h.tv_system, NesTvSystem::Pal);
}

#[test]
fn nes_header_trainer_offset() {
    let h = NesHeader::parse(&nes_header(1, 0, 0x04, 0)).unwrap();
    assert_eq!(h.prg_rom_offset(), 16 + 512);
}

#[test]
fn nes_header_no_trainer_offset() {
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0)).unwrap();
    assert_eq!(h.prg_rom_offset(), 16);
}

#[test]
fn nes_reset_vector_short_data() {
    // Header says 1 PRG bank (16 KiB) but data is just header
    let h = NesHeader::parse(&nes_header(1, 0, 0, 0)).unwrap();
    assert!(h.reset_vector(&nes_header(1, 0, 0, 0)).is_none());
}

#[test]
fn nes_reset_vector_zero_banks() {
    let h = NesHeader::parse(&nes_header(0, 0, 0, 0)).unwrap();
    assert!(h.reset_vector(&nes_header(0, 0, 0, 0)).is_none());
}

#[test]
fn nes_reset_vector_valid() {
    let mut d = nes_header(1, 0, 0, 0);
    d.extend(vec![0u8; 16 * 1024]);
    // Write reset vector at end-4
    let end = d.len();
    d[end - 4] = 0x34;
    d[end - 3] = 0x12;
    let h = NesHeader::parse(&d).unwrap();
    assert_eq!(h.reset_vector(&d), Some(0x1234));
}

#[test]
fn nes_nmi_vector_valid() {
    let mut d = nes_header(1, 0, 0, 0);
    d.extend(vec![0u8; 16 * 1024]);
    let end = d.len();
    d[end - 6] = 0xCD;
    d[end - 5] = 0xAB;
    let h = NesHeader::parse(&d).unwrap();
    assert_eq!(h.nmi_vector(&d), Some(0xABCD));
}

#[test]
fn nes_irq_vector_valid() {
    let mut d = nes_header(1, 0, 0, 0);
    d.extend(vec![0u8; 16 * 1024]);
    let end = d.len();
    d[end - 2] = 0xEF;
    d[end - 1] = 0xBE;
    let h = NesHeader::parse(&d).unwrap();
    assert_eq!(h.irq_vector(&d), Some(0xBEEF));
}

#[test]
fn nes_bank_switching_scheme_unknown() {
    let h = NesHeader::parse(&nes_header(1, 0, 0xF0, 0xF0)).unwrap();
    // mapper = 0xFF; not in table
    assert_eq!(h.bank_switching_scheme(), "unknown");
}

#[test]
fn nes_display_contains_fields() {
    let h = NesHeader::parse(&nes_header(2, 1, 0, 0)).unwrap();
    let s = format!("{h}");
    assert!(s.contains("NES"));
    assert!(s.contains("mapper=0"));
}

// ─────────────────────────────────────────────────────────────────────────────
// SNES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snes_map_mode_from_byte_lorom() {
    assert_eq!(SnesMapMode::from_byte(0x20), SnesMapMode::LoRom);
}

#[test]
fn snes_map_mode_from_byte_hirom() {
    assert_eq!(SnesMapMode::from_byte(0x21), SnesMapMode::HiRom);
}

#[test]
fn snes_map_mode_unknown_byte() {
    match SnesMapMode::from_byte(0x07) {
        SnesMapMode::Unknown(7) => {}
        other => panic!("expected Unknown(7), got {other:?}"),
    }
}

#[test]
fn snes_map_mode_display() {
    assert_eq!(SnesMapMode::LoRom.to_string(), "LoROM");
    assert_eq!(SnesMapMode::HiRom.to_string(), "HiROM");
    assert!(SnesMapMode::Unknown(0xCC).to_string().contains("Unknown"));
}

#[test]
fn snes_has_copier_header_512() {
    let data = vec![0u8; 1024 + 512];
    assert!(SnesHeader::has_copier_header(&data));
}

#[test]
fn snes_has_copier_header_false() {
    let data = vec![0u8; 1024];
    assert!(!SnesHeader::has_copier_header(&data));
}

#[test]
fn snes_parse_too_short() {
    assert!(SnesHeader::parse(&[0u8; 16]).is_err());
}

#[test]
fn snes_parse_at_out_of_bounds() {
    let data = vec![0u8; 100];
    assert!(SnesHeader::parse_at(&data, 0x7FB0).is_err());
}

#[test]
fn snes_checksum_valid_complement() {
    let h = SnesHeader {
        title: String::new(),
        map_mode: SnesMapMode::LoRom,
        chipset: 0,
        rom_size_kb_pow2: 0,
        sram_size_kb_pow2: 0,
        country: 0,
        licensee: 0,
        version: 0,
        complement: 0xAAAA,
        checksum: 0x5555,
        header_offset: 0,
    };
    assert!(h.checksum_valid());
}

#[test]
fn snes_checksum_invalid() {
    let h = SnesHeader {
        title: String::new(),
        map_mode: SnesMapMode::LoRom,
        chipset: 0,
        rom_size_kb_pow2: 0,
        sram_size_kb_pow2: 0,
        country: 0,
        licensee: 0,
        version: 0,
        complement: 0x1111,
        checksum: 0x2222,
        header_offset: 0,
    };
    assert!(!h.checksum_valid());
}

#[test]
fn snes_coprocessor_mapping() {
    let mut h = SnesHeader {
        title: String::new(),
        map_mode: SnesMapMode::LoRom,
        chipset: 0x00,
        rom_size_kb_pow2: 0,
        sram_size_kb_pow2: 0,
        country: 0,
        licensee: 0,
        version: 0,
        complement: 0,
        checksum: 0,
        header_offset: 0,
    };
    assert_eq!(h.coprocessor(), "none");
    h.chipset = 0x10;
    assert_eq!(h.coprocessor(), "DSP");
    h.chipset = 0x20;
    assert!(h.coprocessor().contains("SuperFX"));
    h.chipset = 0x40;
    assert_eq!(h.coprocessor(), "SA-1");
}

#[test]
fn is_snes_random_data_false() {
    assert!(!is_snes(&[0u8; 10_000]));
}

// ─────────────────────────────────────────────────────────────────────────────
// Game Boy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gb_cart_type_from_byte_all_documented() {
    assert_eq!(GbCartType::from_byte(0x00), GbCartType::RomOnly);
    assert_eq!(GbCartType::from_byte(0x13), GbCartType::Mbc3RamBattery);
    assert_eq!(GbCartType::from_byte(0xFF), GbCartType::HuC1RamBattery);
}

#[test]
fn gb_cart_type_unknown_byte() {
    match GbCartType::from_byte(0x77) {
        GbCartType::Unknown(0x77) => {}
        other => panic!("expected Unknown(0x77), got {other:?}"),
    }
}

#[test]
fn gb_cart_type_mbc_name_mbc1() {
    assert_eq!(GbCartType::Mbc1RamBattery.mbc_name(), "MBC1");
}

#[test]
fn gb_cart_type_mbc_name_none() {
    assert_eq!(GbCartType::RomOnly.mbc_name(), "None");
}

#[test]
fn gb_header_short_data() {
    assert!(GbHeader::parse(&[0u8; 0x100]).is_err());
}

#[test]
fn gb_header_bad_logo() {
    let data = vec![0u8; 0x150];
    // logo bytes wrong
    let h = GbHeader::parse(&data);
    assert!(h.is_err());
}

#[test]
fn is_gb_too_short() {
    assert!(!is_gb(&[0u8; 100]));
}

#[test]
fn gb_sram_size_codes() {
    let make = |code: u8| {
        let mut data = vec![0u8; 0x150];
        data[0x104..0x134].copy_from_slice(&GB_LOGO);
        data[0x149] = code;
        // compute checksum
        let mut x = 0u8;
        for &b in &data[0x134..0x14D] {
            x = x.wrapping_sub(b).wrapping_sub(1);
        }
        data[0x14D] = x;
        data
    };
    assert_eq!(GbHeader::parse(&make(0x00)).unwrap().sram_size_bytes(), 0);
    assert_eq!(GbHeader::parse(&make(0x01)).unwrap().sram_size_bytes(), 2 * 1024);
    assert_eq!(GbHeader::parse(&make(0x02)).unwrap().sram_size_bytes(), 8 * 1024);
    assert_eq!(GbHeader::parse(&make(0x03)).unwrap().sram_size_bytes(), 32 * 1024);
    assert_eq!(GbHeader::parse(&make(0x04)).unwrap().sram_size_bytes(), 128 * 1024);
    assert_eq!(GbHeader::parse(&make(0x05)).unwrap().sram_size_bytes(), 64 * 1024);
}

#[test]
fn gb_is_sgb_flag() {
    let mut data = vec![0u8; 0x150];
    data[0x104..0x134].copy_from_slice(&GB_LOGO);
    data[0x146] = 0x03;
    let mut x = 0u8;
    for &b in &data[0x134..0x14D] {
        x = x.wrapping_sub(b).wrapping_sub(1);
    }
    data[0x14D] = x;
    let h = GbHeader::parse(&data).unwrap();
    assert!(h.is_sgb());
}

// ─────────────────────────────────────────────────────────────────────────────
// GBA
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gba_header_short() {
    assert!(GbaHeader::parse(&[0u8; 10]).is_err());
}

#[test]
fn gba_header_bad_entry() {
    let data = vec![0u8; GBA_HEADER_SIZE];
    assert!(GbaHeader::parse(&data).is_err());
}

#[test]
fn gba_save_detect_none() {
    let data = vec![0u8; 100];
    assert_eq!(GbaSaveType::detect(&data), GbaSaveType::None);
}

#[test]
fn gba_save_detect_sram() {
    let mut data = vec![0u8; 100];
    data[10..14].copy_from_slice(b"SRAM");
    assert_eq!(GbaSaveType::detect(&data), GbaSaveType::Sram);
}

#[test]
fn gba_save_detect_flash128() {
    // Test-side update: real GBA Flash128 signature is "FLASH1M_Vnnn"; the
    // previous "FLASH_V12" string also matched all Flash64 carts.
    let mut data = vec![0u8; 100];
    data[10..19].copy_from_slice(b"FLASH1M_V");
    assert_eq!(GbaSaveType::detect(&data), GbaSaveType::Flash128);
}

#[test]
fn gba_save_detect_flash64() {
    let mut data = vec![0u8; 100];
    data[10..15].copy_from_slice(b"FLASH");
    assert_eq!(GbaSaveType::detect(&data), GbaSaveType::Flash64);
}

#[test]
fn gba_save_display() {
    assert_eq!(GbaSaveType::None.to_string(), "none");
    assert_eq!(GbaSaveType::Eeprom.to_string(), "EEPROM");
}

#[test]
fn is_gba_with_entry_only_not_full_header() {
    // Has entry instruction but smaller than GBA_HEADER_SIZE
    let mut data = vec![0u8; 100];
    data[..4].copy_from_slice(&GBA_ENTRY_INSTR);
    assert!(!is_gba(&data));
}

// ─────────────────────────────────────────────────────────────────────────────
// Genesis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn genesis_region_from_str_empty() {
    matches!(GenesisRegion::parse_region(""), GenesisRegion::Unknown);
}

#[test]
fn genesis_region_from_str_japan_only() {
    let r = GenesisRegion::parse_region("J");
    assert!(matches!(r, GenesisRegion::Japan));
}

#[test]
fn genesis_region_display_multi() {
    let r = GenesisRegion::Multi(vec![GenesisRegion::Japan, GenesisRegion::Usa]);
    let s = r.to_string();
    assert!(s.contains("JP"));
    assert!(s.contains("US"));
    assert!(s.contains('|'));
}

#[test]
fn genesis_header_too_short() {
    assert!(GenesisHeader::parse(&[0u8; 0x100]).is_err());
}

#[test]
fn genesis_header_bad_console_name() {
    let mut data = vec![0u8; 0x200];
    data[0x100..0x110].copy_from_slice(b"NOT A SEGA ROM!!");
    assert!(GenesisHeader::parse(&data).is_err());
}

#[test]
fn genesis_compute_checksum_empty() {
    let data = vec![0u8; 0x200];
    assert_eq!(GenesisHeader::compute_checksum(&data), 0);
}

#[test]
fn genesis_is_32x_detection() {
    let mut data = vec![0u8; 0x200];
    data[0x100..0x108].copy_from_slice(b"SEGA 32X");
    let h = GenesisHeader::parse(&data).unwrap();
    assert!(h.is_32x());
}

#[test]
fn is_genesis_pico() {
    let mut data = vec![0u8; 0x200];
    data[0x100..0x109].copy_from_slice(b"SEGA PICO");
    assert!(is_genesis(&data));
}

// ─────────────────────────────────────────────────────────────────────────────
// ConsoleStream / StreamStats
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn console_stream_empty() {
    let s = ConsoleStream::analyse(&[]);
    assert_eq!(s.byte_count, 0);
    assert!(!s.is_binary);
}

#[test]
fn console_stream_eq_clone() {
    let s = ConsoleStream::analyse(b"hello");
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn stream_stats_all_same_byte() {
    let data = vec![0x41u8; 16];
    let s = StreamStats::compute(&data);
    assert_eq!(s.min_byte, 0x41);
    assert_eq!(s.max_byte, 0x41);
    assert_eq!(s.null_bytes, 0);
    assert_eq!(s.printable_ascii, 16);
}

#[test]
fn stream_stats_eq_consistency() {
    let s1 = StreamStats::compute(b"abc");
    let s2 = StreamStats::compute(b"abc");
    assert_eq!(s1, s2);
}

// ─────────────────────────────────────────────────────────────────────────────
// ConsoleArch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn console_arch_disassemble_empty_bytes() {
    use rustre_core::address::Address;
    use rustre_core::arch::Architecture;
    use rustre_core::endian::Endian;
    let arch = ConsoleArch::new("test", 4, Endian::Little);
    let instr = arch.disassemble(Address::new(0), &[]).unwrap();
    assert_eq!(instr.size, 1);
}

#[test]
fn console_arch_no_registers() {
    use rustre_core::arch::Architecture;
    use rustre_core::endian::Endian;
    let arch = ConsoleArch::new("test", 4, Endian::Big);
    assert!(arch.registers().is_empty());
    assert!(arch.calling_conventions().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform & ConsoleDisassemblyHints
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn platform_eq() {
    assert_eq!(Platform::Nes, Platform::Nes);
    assert_ne!(Platform::Nes, Platform::Snes);
}

#[test]
fn arch_for_all_platforms() {
    assert!(!ConsoleDisassemblyHints::arch_for(Platform::Nes).is_empty());
    assert!(!ConsoleDisassemblyHints::arch_for(Platform::Snes).is_empty());
    assert!(!ConsoleDisassemblyHints::arch_for(Platform::GameBoy).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// GameConsoleRomLoader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn game_console_loader_empty() {
    assert!(GameConsoleRomLoader::parse(&[]).is_none());
}

#[test]
fn game_console_loader_random() {
    assert!(GameConsoleRomLoader::parse(&[0xAB; 128]).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// BankSwitchInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bank_switch_info_zero_prg_banks() {
    let h = NesHeader::parse(&nes_header(0, 0, 0, 0)).unwrap();
    let info = BankSwitchInfo::from_nes_header(&h);
    assert_eq!(info.bank_count, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// format_detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn format_signature_zero_min_size() {
    let sig = FormatSignature {
        format: ConsoleFormat::NesRom,
        offset: 0,
        magic: b"NES\x1a",
        description: "x",
        min_size: 0,
    };
    assert!(sig.matches(b"NES\x1afoo"));
    assert!(!sig.matches(b"NES")); // shorter than magic
}

#[test]
fn format_signature_offset_past_data_end() {
    let sig = FormatSignature {
        format: ConsoleFormat::NroExecutable,
        offset: 0x100,
        magic: b"X",
        description: "x",
        min_size: 0,
    };
    assert!(!sig.matches(b"short"));
}

#[test]
fn format_db_default_eq_new() {
    let a = FormatDb::default();
    let b = FormatDb::new();
    assert_eq!(a.signatures().len(), b.signatures().len());
}

#[test]
fn detector_detect_all_finds_zip_and_vpk() {
    let det = ConsoleFormatDetector::new();
    let data = b"PK\x03\x04rest";
    let all = det.detect_all(data);
    assert!(all.iter().any(|f| *f == ConsoleFormat::VpkPackage));
}

#[test]
fn detector_features_unknown_default() {
    let det = ConsoleFormatDetector::new();
    let (fmt, feats) = det.detect_with_features(&[0xFFu8; 16]);
    assert_eq!(fmt, ConsoleFormat::Unknown);
    assert!(!feats.is_executable());
    assert!(!feats.has_drm());
}

#[test]
fn console_format_extensions_all_nonempty_for_known() {
    // All known formats (excluding Unknown) should have at least one extension
    for f in [
        ConsoleFormat::NsoExecutable,
        ConsoleFormat::NroExecutable,
        ConsoleFormat::XexExecutable,
        ConsoleFormat::SelfExecutable,
        ConsoleFormat::PkgPackage,
        ConsoleFormat::GbaRom,
        ConsoleFormat::NesRom,
        ConsoleFormat::SnesRom,
        ConsoleFormat::GenesisRom,
        ConsoleFormat::GbRom,
        ConsoleFormat::GbcRom,
    ] {
        assert!(!f.typical_extensions().is_empty(), "no exts for {f:?}");
    }
}

#[test]
fn console_format_unknown_no_extensions() {
    assert!(ConsoleFormat::Unknown.typical_extensions().is_empty());
}

#[test]
fn console_format_is_handheld_subset() {
    assert!(ConsoleFormat::GbaRom.is_handheld());
    assert!(ConsoleFormat::GbRom.is_handheld());
    assert!(!ConsoleFormat::XexExecutable.is_handheld());
    assert!(!ConsoleFormat::GenesisRom.is_handheld());
}

#[test]
fn console_format_is_switch() {
    assert!(ConsoleFormat::NsoExecutable.is_switch());
    assert!(ConsoleFormat::NroExecutable.is_switch());
    assert!(ConsoleFormat::NcaContent.is_switch());
    assert!(!ConsoleFormat::GbaRom.is_switch());
}

#[test]
fn license_region_serde_roundtrip() {
    // Ensure all variants are constructable; covers the unknown arm too
    for v in [
        LicenseRegion::Japan,
        LicenseRegion::NorthAmerica,
        LicenseRegion::Europe,
        LicenseRegion::Australia,
        LicenseRegion::Korea,
        LicenseRegion::China,
        LicenseRegion::WorldWide,
        LicenseRegion::Unknown,
    ] {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn format_feature_set_default() {
    let f = FormatFeatureSet::default();
    assert!(!f.has_drm());
    assert!(!f.is_executable());
    assert_eq!(f.pointer_bits, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NsoHeader
// ─────────────────────────────────────────────────────────────────────────────

fn make_nso() -> Vec<u8> {
    let mut d = vec![0u8; NsoHeader::SIZE];
    d[..4].copy_from_slice(NSO_MAGIC);
    // version 0, reserved 0, flags 0x07 (all compressed)
    d[12..16].copy_from_slice(&0x07u32.to_le_bytes());
    // text seg: file=0x100, mem=0, size=0x200
    d[16..20].copy_from_slice(&0x100u32.to_le_bytes());
    d[20..24].copy_from_slice(&0u32.to_le_bytes());
    d[24..28].copy_from_slice(&0x200u32.to_le_bytes());
    // rodata seg
    d[32..36].copy_from_slice(&0x300u32.to_le_bytes());
    d[36..40].copy_from_slice(&0x200u32.to_le_bytes());
    d[40..44].copy_from_slice(&0x100u32.to_le_bytes());
    // data seg
    d[48..52].copy_from_slice(&0x400u32.to_le_bytes());
    d[52..56].copy_from_slice(&0x300u32.to_le_bytes());
    d[56..60].copy_from_slice(&0x100u32.to_le_bytes());
    // bss
    d[60..64].copy_from_slice(&0x200u32.to_le_bytes());
    d
}

#[test]
fn nso_header_parse_ok() {
    let d = make_nso();
    let h = NsoHeader::parse(&d).unwrap();
    assert_eq!(&h.magic, b"NSO0");
    assert!(h.text_compressed());
    assert!(h.rodata_compressed());
    assert!(h.data_compressed());
}

#[test]
fn nso_header_too_short() {
    let r = NsoHeader::parse(&[0u8; 0x80]);
    assert!(matches!(r, Err(SwitchError::TruncatedData { .. })));
}

#[test]
fn nso_header_bad_magic() {
    let mut d = vec![0u8; NsoHeader::SIZE];
    d[..4].copy_from_slice(b"XXXX");
    let r = NsoHeader::parse(&d);
    assert!(matches!(r, Err(SwitchError::InvalidMagic { .. })));
}

#[test]
fn nso_image_size_includes_bss() {
    let d = make_nso();
    let h = NsoHeader::parse(&d).unwrap();
    // data.memory_offset (0x300) + data.size (0x100) + bss (0x200) = 0x600
    assert_eq!(h.image_size(), 0x600);
}

#[test]
fn nso_compressed_flags_individual() {
    let mut d = make_nso();
    d[12..16].copy_from_slice(&0u32.to_le_bytes());
    let h = NsoHeader::parse(&d).unwrap();
    assert!(!h.text_compressed());
    assert!(!h.rodata_compressed());
    assert!(!h.data_compressed());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NsoSegmentInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nso_segment_info_empty() {
    let s = NsoSegmentInfo::new(0, 0, 0);
    assert!(s.is_empty());
}

#[test]
fn nso_segment_info_nonempty() {
    let s = NsoSegmentInfo::new(0, 0, 1);
    assert!(!s.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NsoBss
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nso_bss_from_header() {
    let d = make_nso();
    let h = NsoHeader::parse(&d).unwrap();
    let bss = NsoBss::from_header(&h);
    // data.memory_offset 0x300 + size 0x100 = 0x400
    assert_eq!(bss.offset, 0x400);
    assert_eq!(bss.size, 0x200);
    assert_eq!(bss.end_offset(), 0x600);
    assert!(!bss.is_empty());
}

#[test]
fn nso_bss_end_saturates() {
    let bss = NsoBss { offset: u32::MAX, size: 5 };
    assert_eq!(bss.end_offset(), u32::MAX);
}

#[test]
fn nso_bss_empty() {
    let bss = NsoBss { offset: 0, size: 0 };
    assert!(bss.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NroHeader
// ─────────────────────────────────────────────────────────────────────────────

fn make_nro() -> Vec<u8> {
    let mut d = vec![0u8; NroHeader::SIZE];
    // Magic at offset 4
    d[4..8].copy_from_slice(NRO_MAGIC);
    // version
    d[8..12].copy_from_slice(&0u32.to_le_bytes());
    d[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // size
    d[20..24].copy_from_slice(&0u32.to_le_bytes()); // text_offset
    d[24..28].copy_from_slice(&0x200u32.to_le_bytes()); // text_size
    d[28..32].copy_from_slice(&0x200u32.to_le_bytes()); // rodata_offset
    d[32..36].copy_from_slice(&0x100u32.to_le_bytes()); // rodata_size
    d[36..40].copy_from_slice(&0x300u32.to_le_bytes()); // data_offset
    d[40..44].copy_from_slice(&0x100u32.to_le_bytes()); // data_size
    d[44..48].copy_from_slice(&0x50u32.to_le_bytes()); // bss_size
    d
}

#[test]
fn nro_header_parse_ok() {
    let d = make_nro();
    let h = NroHeader::parse(&d).unwrap();
    assert_eq!(&h.magic, b"NRO0");
    assert_eq!(h.size, 0x1000);
    assert_eq!(h.text_size, 0x200);
    assert_eq!(h.bss_size, 0x50);
}

#[test]
fn nro_header_too_short() {
    let r = NroHeader::parse(&[0u8; 0x40]);
    assert!(matches!(r, Err(SwitchError::TruncatedData { .. })));
}

#[test]
fn nro_header_bad_magic() {
    let d = vec![0u8; NroHeader::SIZE];
    let r = NroHeader::parse(&d);
    assert!(matches!(r, Err(SwitchError::InvalidMagic { .. })));
}

#[test]
fn nro_total_size_includes_bss() {
    let d = make_nro();
    let h = NroHeader::parse(&d).unwrap();
    assert_eq!(h.total_size(), 0x1000 + 0x50);
}

#[test]
fn nro_total_size_saturates() {
    let h = NroHeader {
        magic: *b"NRO0",
        version: 0,
        size: u32::MAX,
        flags: 0,
        text_offset: 0,
        text_size: 0,
        rodata_offset: 0,
        rodata_size: 0,
        data_offset: 0,
        data_size: 0,
        bss_size: 100,
        build_id: [0; 16],
    };
    assert_eq!(h.total_size(), u32::MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NsoModuleInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nso_module_info_parse_ok() {
    let mut d = vec![0u8; NsoModuleInfo::SIZE];
    d[..4].copy_from_slice(&NsoModuleInfo::MAGIC.to_le_bytes());
    d[4..8].copy_from_slice(&100i32.to_le_bytes());
    let m = NsoModuleInfo::parse(&d).unwrap();
    assert!(m.is_valid());
    assert_eq!(m.dynamic_offset, 100);
}

#[test]
fn nso_module_info_too_short() {
    let r = NsoModuleInfo::parse(&[0u8; 10]);
    assert!(matches!(r, Err(SwitchError::TruncatedData { .. })));
}

#[test]
fn nso_module_info_bad_magic() {
    let d = vec![0u8; NsoModuleInfo::SIZE];
    let r = NsoModuleInfo::parse(&d);
    assert!(matches!(r, Err(SwitchError::InvalidModOffset(_))));
}

#[test]
fn nso_module_info_default_invalid() {
    let m = NsoModuleInfo::default();
    assert!(!m.is_valid());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NroAssetHeader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nro_asset_header_too_short() {
    assert!(NroAssetHeader::parse(&[0u8; 10]).is_none());
}

#[test]
fn nro_asset_header_bad_magic() {
    let d = vec![0u8; NroAssetHeader::SIZE];
    assert!(NroAssetHeader::parse(&d).is_none());
}

#[test]
fn nro_asset_header_ok() {
    let mut d = vec![0u8; NroAssetHeader::SIZE + 100];
    d[..4].copy_from_slice(ASET_MAGIC);
    d[4..8].copy_from_slice(&1u32.to_le_bytes());
    // romfs at 0x100, size 0x200
    d[8..16].copy_from_slice(&0x100u64.to_le_bytes());
    d[16..24].copy_from_slice(&0x200u64.to_le_bytes());
    // nacp
    d[24..32].copy_from_slice(&0u64.to_le_bytes());
    d[32..40].copy_from_slice(&0x100u64.to_le_bytes());
    // icon
    d[40..48].copy_from_slice(&0u64.to_le_bytes());
    d[48..56].copy_from_slice(&0x50u64.to_le_bytes());
    let a = NroAssetHeader::parse(&d).unwrap();
    assert!(a.has_romfs());
    assert!(a.has_nacp());
    assert!(a.has_icon());
}

#[test]
fn asset_section_present() {
    let s = AssetSection { offset: 0, size: 10 };
    assert!(s.is_present());
    let z = AssetSection { offset: 0, size: 0 };
    assert!(!z.is_present());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — ExefsSectionHeader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn exefs_section_too_short() {
    assert!(ExefsSectionHeader::parse(&[0u8; 10]).is_none());
}

#[test]
fn exefs_section_parse_ok() {
    let mut d = vec![0u8; ExefsSectionHeader::ENTRY_SIZE];
    d[..4].copy_from_slice(b"main");
    d[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
    d[12..16].copy_from_slice(&0x200u32.to_le_bytes());
    let s = ExefsSectionHeader::parse(&d).unwrap();
    assert_eq!(s.name, "main");
    assert_eq!(s.offset, 0x1000);
    assert_eq!(s.size, 0x200);
    assert!(!s.is_empty());
}

#[test]
fn exefs_section_empty() {
    let d = vec![0u8; ExefsSectionHeader::ENTRY_SIZE];
    let s = ExefsSectionHeader::parse(&d).unwrap();
    assert!(s.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — NsoApiInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nso_api_info_empty() {
    assert!(NsoApiInfo::parse(&[]).is_none());
}

#[test]
fn nso_api_info_basic() {
    let mut d = b"sdk-1.2.3".to_vec();
    d.push(0);
    d.extend_from_slice(b"nx");
    d.push(0);
    let api = NsoApiInfo::parse(&d).unwrap();
    assert_eq!(api.sdk_version, "sdk-1.2.3");
    assert_eq!(api.platform, "nx");
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — RomFs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn romfs_header_too_short() {
    let r = RomFsHeader::parse(&[0u8; 10]);
    assert!(matches!(r, Err(SwitchError::TruncatedData { .. })));
}

#[test]
fn romfs_header_bad_size() {
    // header_size < 0x50 → InvalidRomFsHeader
    let d = vec![0u8; RomFsHeader::SIZE];
    let r = RomFsHeader::parse(&d);
    assert!(matches!(r, Err(SwitchError::InvalidRomFsHeader)));
}

#[test]
fn romfs_header_ok() {
    let mut d = vec![0u8; RomFsHeader::SIZE];
    d[..8].copy_from_slice(&(RomFsHeader::SIZE as u64).to_le_bytes());
    let h = RomFsHeader::parse(&d).unwrap();
    assert_eq!(h.header_size, RomFsHeader::SIZE as u64);
}

#[test]
fn romfs_entry_file_vs_dir() {
    let f = RomFsEntry::new_file("a.txt", 0, 100);
    assert!(!f.is_directory);
    let d = RomFsEntry::new_dir("dir");
    assert!(d.is_directory);
    assert_eq!(d.size, 0);
}

#[test]
fn switch_romfs_add_and_find() {
    let mut r = SwitchRomFs::new();
    r.add_entry(RomFsEntry::new_file("a", 0, 10));
    r.add_entry(RomFsEntry::new_dir("d"));
    assert_eq!(r.file_count(), 1);
    assert_eq!(r.dir_count(), 1);
    assert!(r.find("a").is_some());
    assert!(r.find("missing").is_none());
}

#[test]
fn romfs_entry_iter_filter() {
    let entries = vec![
        RomFsEntry::new_file("a", 0, 10),
        RomFsEntry::new_dir("b"),
        RomFsEntry::new_file("c", 0, 20),
    ];
    let it = RomFsEntryIter::new(&entries, |e| !e.is_directory);
    let collected: Vec<&RomFsEntry> = it.collect();
    assert_eq!(collected.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// switch_formats — misc
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nca_key_area_empty_detection() {
    let k = NcaKeyAreaEntry::new(0, [0u8; 16]);
    assert!(k.is_empty());
    let k2 = NcaKeyAreaEntry::new(0, [1u8; 16]);
    assert!(!k2.is_empty());
}

#[test]
fn nca_content_type_from_u8() {
    assert_eq!(NcaContentType::from_u8(0), Some(NcaContentType::Program));
    assert_eq!(NcaContentType::from_u8(4), Some(NcaContentType::Data));
    assert_eq!(NcaContentType::from_u8(99), None);
}

#[test]
fn switch_npdm_defaults() {
    let n = SwitchNpdm::new(0xDEADBEEF);
    assert_eq!(n.title_id, 0xDEADBEEF);
    assert!(n.is_64bit());
    assert!(!n.is_system_process());
}

#[test]
fn switch_formats_load_nso() {
    let d = make_nso();
    let mut sf = SwitchFormats::new();
    sf.load_nso(&d).unwrap();
    assert!(sf.has_nso());
    assert!(!sf.has_nro());
    assert_eq!(sf.entry_point_offset(), 0); // text mem offset
    assert!(sf.bss.is_some());
}

#[test]
fn switch_formats_load_nro() {
    let d = make_nro();
    let mut sf = SwitchFormats::new();
    sf.load_nro(&d).unwrap();
    assert!(sf.has_nro());
    assert_eq!(sf.entry_point_offset(), 0); // text_offset
}

#[test]
fn switch_formats_empty_entry_point() {
    let sf = SwitchFormats::new();
    assert_eq!(sf.entry_point_offset(), 0);
}

#[test]
fn switch_error_display() {
    let e = SwitchError::InvalidMagic {
        expected: b"NSO0",
        got: vec![1, 2, 3, 4],
    };
    assert!(e.to_string().contains("invalid magic"));
}

#[test]
fn switch_error_eq() {
    let a = SwitchError::InvalidBssSize;
    let b = SwitchError::InvalidBssSize;
    assert_eq!(a, b);
}
