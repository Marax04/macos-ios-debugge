//! Comprehensive integration tests for `rustre-loader-firmware`.
//!
//! Exercises the public API surface re-exported from `lib.rs`: firmware kind
//! detection, byte histogram / entropy, architecture heuristics, U-Boot header
//! parsing, Intel HEX / SREC / UF2 record parsing, RTOS detection, string
//! extraction and classification, the four `Loader` implementations, and the
//! `FirmwareArch` `Architecture` impl.

use rustre_core::arch::Architecture;
use rustre_core::endian::Endian;
use rustre_core::{Loader, LoaderInput};
use rustre_loader_firmware::*;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_uboot_header(load: u32, entry: u32, arch_byte: u8, name: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&0x2705_1956_u32.to_be_bytes());
    data[12..16].copy_from_slice(&1024_u32.to_be_bytes());
    data[16..20].copy_from_slice(&load.to_be_bytes());
    data[20..24].copy_from_slice(&entry.to_be_bytes());
    data[29] = arch_byte;
    let name_len = name.len().min(31);
    data[32..32 + name_len].copy_from_slice(&name[..name_len]);
    data
}

fn ihex_checksum(body: &[u8]) -> u8 {
    let sum: u32 = body.iter().map(|&b| u32::from(b)).sum();
    ((0x100u32 - (sum & 0xFF)) & 0xFF) as u8
}

fn make_ihex_line(addr: u16, record_type: u8, data: &[u8]) -> Vec<u8> {
    let mut body = vec![
        data.len() as u8,
        (addr >> 8) as u8,
        (addr & 0xFF) as u8,
        record_type,
    ];
    body.extend_from_slice(data);
    let cs = ihex_checksum(&body);
    body.push(cs);
    let mut line = b":".to_vec();
    for b in &body {
        line.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    line
}

fn srec_checksum(body: &[u8]) -> u8 {
    let sum: u32 = body.iter().map(|&b| u32::from(b)).sum();
    (!(sum & 0xFF)) as u8
}

fn make_srec_s1(addr: u16, data: &[u8]) -> Vec<u8> {
    let byte_count = 2 + data.len() + 1;
    let mut body = Vec::new();
    body.push(byte_count as u8);
    body.push((addr >> 8) as u8);
    body.push(addr as u8);
    body.extend_from_slice(data);
    let cs = srec_checksum(&body);
    body.push(cs);
    let mut line = b"S1".to_vec();
    for b in &body {
        line.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    line
}

fn make_srec_s9(addr: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(3u8);
    body.push((addr >> 8) as u8);
    body.push(addr as u8);
    let cs = srec_checksum(&body);
    body.push(cs);
    let mut line = b"S9".to_vec();
    for b in &body {
        line.extend_from_slice(format!("{b:02X}").as_bytes());
    }
    line
}

fn make_uf2_block(target_addr: u32, payload: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8; 512];
    block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
    block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
    block[12..16].copy_from_slice(&target_addr.to_le_bytes());
    let size = payload.len().min(476) as u32;
    block[16..20].copy_from_slice(&size.to_le_bytes());
    block[24..28].copy_from_slice(&1u32.to_le_bytes());
    let plen = payload.len().min(476);
    block[32..32 + plen].copy_from_slice(&payload[..plen]);
    block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
    block
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_firmware_kind: boundary and all-variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_kind_empty_is_raw() {
    assert_eq!(detect_firmware_kind(&[]), FirmwareKind::Raw);
}

#[test]
fn detect_kind_single_byte_is_raw() {
    assert_eq!(detect_firmware_kind(&[0xAA]), FirmwareKind::Raw);
}

#[test]
fn detect_kind_three_bytes_unknown_returns_unknown() {
    assert_eq!(detect_firmware_kind(&[0xAA, 0xBB, 0xCC]), FirmwareKind::Unknown);
}

#[test]
fn detect_kind_all_known_magics() {
    assert_eq!(detect_firmware_kind(b"\x1f\x8bxx"), FirmwareKind::TarGz);
    assert_eq!(detect_firmware_kind(b"BZhxx"), FirmwareKind::Bzip2);
    assert_eq!(detect_firmware_kind(b"\xFD7zXZ\x00x"), FirmwareKind::Xz);
    assert_eq!(detect_firmware_kind(&[0x5D, 0x00, 0x00, 0xFF]), FirmwareKind::Lzma);
    assert_eq!(detect_firmware_kind(b":10"), FirmwareKind::IntelHex);
    assert_eq!(detect_firmware_kind(b"S1"), FirmwareKind::Srec);
    let mut uf2 = vec![0u8; 8];
    uf2[..4].copy_from_slice(b"UF2\n");
    assert_eq!(detect_firmware_kind(&uf2), FirmwareKind::Uf2);
    assert_eq!(detect_firmware_kind(&0x2705_1956_u32.to_be_bytes()), FirmwareKind::UBoot);
    assert_eq!(detect_firmware_kind(&0xD00D_FEED_u32.to_be_bytes()), FirmwareKind::UBootFit);
    assert_eq!(detect_firmware_kind(&0x1985_2003_u32.to_be_bytes()), FirmwareKind::Jffs2);
    assert_eq!(detect_firmware_kind(&0x28CD_3D45_u32.to_be_bytes()), FirmwareKind::CramFs);
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareKind classifications + Display for every variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn firmware_kind_is_compressed_matrix() {
    for k in [FirmwareKind::TarGz, FirmwareKind::Bzip2, FirmwareKind::Lzma, FirmwareKind::Xz] {
        assert!(k.is_compressed(), "{k:?} should be compressed");
    }
    for k in [FirmwareKind::Raw, FirmwareKind::UBoot, FirmwareKind::IntelHex,
              FirmwareKind::Srec, FirmwareKind::Uf2, FirmwareKind::SquashFs] {
        assert!(!k.is_compressed(), "{k:?} should not be compressed");
    }
}

#[test]
fn firmware_kind_is_filesystem_matrix() {
    for k in [FirmwareKind::SquashFs, FirmwareKind::Jffs2, FirmwareKind::CramFs,
              FirmwareKind::Ext2, FirmwareKind::Yaffs2] {
        assert!(k.is_filesystem());
    }
    for k in [FirmwareKind::Raw, FirmwareKind::UBoot, FirmwareKind::TarGz] {
        assert!(!k.is_filesystem());
    }
}

#[test]
fn firmware_kind_is_text_format_matrix() {
    assert!(FirmwareKind::IntelHex.is_text_format());
    assert!(FirmwareKind::Srec.is_text_format());
    assert!(!FirmwareKind::Raw.is_text_format());
    assert!(!FirmwareKind::Uf2.is_text_format());
}

#[test]
fn firmware_kind_display_all_variants() {
    let cases = [
        (FirmwareKind::Raw, "raw"),
        (FirmwareKind::UBoot, "uboot-legacy"),
        (FirmwareKind::UBootFit, "uboot-fit"),
        (FirmwareKind::SquashFs, "squashfs"),
        (FirmwareKind::Jffs2, "jffs2"),
        (FirmwareKind::CramFs, "cramfs"),
        (FirmwareKind::Ext2, "ext2"),
        (FirmwareKind::Yaffs2, "yaffs2"),
        (FirmwareKind::TarGz, "tar.gz"),
        (FirmwareKind::Bzip2, "bzip2"),
        (FirmwareKind::Lzma, "lzma"),
        (FirmwareKind::Xz, "xz"),
        (FirmwareKind::IntelHex, "intel-hex"),
        (FirmwareKind::Srec, "srec"),
        (FirmwareKind::Uf2, "uf2"),
        (FirmwareKind::Unknown, "unknown"),
    ];
    for (k, s) in cases {
        assert_eq!(k.to_string(), s);
    }
}

#[test]
fn firmware_kind_eq_and_copy() {
    let a = FirmwareKind::UBoot;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(FirmwareKind::Raw, FirmwareKind::UBoot);
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteHistogram
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn histogram_empty() {
    let h = ByteHistogram::from_data(&[]);
    assert_eq!(h.total, 0);
    assert_eq!(h.entropy(), 0.0);
    assert!(h.is_sparse());
    assert!(!h.is_high_entropy());
}

#[test]
fn histogram_single_byte() {
    let h = ByteHistogram::from_data(&[0x42]);
    assert_eq!(h.total, 1);
    assert_eq!(h.entropy(), 0.0);
    assert_eq!(h.most_common_byte(), 0x42);
}

#[test]
fn histogram_max_entropy() {
    let data: Vec<u8> = (0u8..=255).collect();
    let h = ByteHistogram::from_data(&data);
    assert!((h.entropy() - 8.0).abs() < 0.01);
    assert!(h.is_high_entropy());
    assert!(!h.is_sparse());
}

#[test]
fn histogram_most_common_byte_default_zero() {
    // all counts zero ⇒ position 0 wins
    let h = ByteHistogram::from_data(&[]);
    assert_eq!(h.most_common_byte(), 0);
}

#[test]
fn histogram_sliding_zero_window() {
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3, 4], 0, 1).is_empty());
}

#[test]
fn histogram_sliding_zero_step() {
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3, 4], 2, 0).is_empty());
}

#[test]
fn histogram_sliding_window_exceeds_data() {
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3], 100, 1).is_empty());
}

#[test]
fn histogram_sliding_basic() {
    let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let win = ByteHistogram::sliding_entropy(&data, 256, 128);
    // (1024-256)/128 + 1 = 7
    assert_eq!(win.len(), 7);
    for (_, e) in &win {
        assert!(*e > 7.9);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// scan_embedded_signatures
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn embedded_sigs_empty_input() {
    assert!(scan_embedded_signatures(&[]).is_empty());
}

#[test]
fn embedded_sigs_sorted_by_offset() {
    let mut data = vec![0u8; 200];
    data[100..104].copy_from_slice(b"7z\xBC\xAF");
    data[20..22].copy_from_slice(&[0x1F, 0x8B]);
    data[60..64].copy_from_slice(b"\x7fELF");
    let sigs = scan_embedded_signatures(&data);
    let offs: Vec<usize> = sigs.iter().map(|s| s.offset).collect();
    assert!(offs.windows(2).all(|w| w[0] <= w[1]));
    assert!(sigs.iter().any(|s| s.name == "gzip"));
    assert!(sigs.iter().any(|s| s.name == "elf"));
}

#[test]
fn embedded_signature_eq_and_clone() {
    let a = EmbeddedSignature { name: "x", offset: 1, sig_len: 2, description: "d".into() };
    let b = a.clone();
    assert_eq!(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture heuristics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_binary_arch_too_short() {
    assert_eq!(detect_binary_arch(&[0u8; 4]), BinaryArch::Unknown);
    assert_eq!(detect_binary_arch(&[]), BinaryArch::Unknown);
}

#[test]
fn detect_binary_arch_endbr64() {
    let mut data = vec![0u8; 64];
    data[32..36].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA]);
    assert_eq!(detect_binary_arch(&data), BinaryArch::X86_64);
}

#[test]
fn detect_raw_endian_all_variants() {
    assert_eq!(detect_raw_endian(BinaryArch::ArmThumb), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::ArmAarch32), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::Aarch64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::Mips32Le), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::Mips32Be), Some(Endian::Big));
    assert_eq!(detect_raw_endian(BinaryArch::X86), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::X86_64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::RiscV32), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::RiscV64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::PowerPcBe), Some(Endian::Big));
    assert_eq!(detect_raw_endian(BinaryArch::Unknown), None);
}

#[test]
fn binary_arch_display_all() {
    for (a, s) in [
        (BinaryArch::ArmThumb, "arm-thumb"),
        (BinaryArch::ArmAarch32, "arm-aarch32"),
        (BinaryArch::Aarch64, "aarch64"),
        (BinaryArch::Mips32Be, "mips32-be"),
        (BinaryArch::Mips32Le, "mips32-le"),
        (BinaryArch::X86, "x86"),
        (BinaryArch::X86_64, "x86_64"),
        (BinaryArch::RiscV32, "riscv32"),
        (BinaryArch::RiscV64, "riscv64"),
        (BinaryArch::PowerPcBe, "ppc-be"),
        (BinaryArch::Unknown, "unknown"),
    ] {
        assert_eq!(a.to_string(), s);
    }
}

#[test]
fn binary_arch_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(BinaryArch::X86);
    s.insert(BinaryArch::X86);
    s.insert(BinaryArch::Aarch64);
    assert_eq!(s.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// UBootHeader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn uboot_parse_too_short() {
    assert!(UBootHeader::parse(&[0u8; 63]).is_none());
}

#[test]
fn uboot_parse_bad_magic() {
    assert!(UBootHeader::parse(&[0xFFu8; 64]).is_none());
}

#[test]
fn uboot_parse_basic_fields() {
    let data = make_uboot_header(0x8000_0000, 0x8000_0100, 2, b"my-fw");
    let hdr = UBootHeader::parse(&data).unwrap();
    assert_eq!(hdr.magic, UBootHeader::MAGIC);
    assert_eq!(hdr.load_addr, 0x8000_0000);
    assert_eq!(hdr.entry_point, 0x8000_0100);
    assert_eq!(hdr.entry(), 0x8000_0100u64);
    assert_eq!(hdr.name, "my-fw");
}

#[test]
fn uboot_arch_str_all_known() {
    let cases = [
        (1u8, "alpha"), (2, "arm"), (3, "x86"), (4, "mips"), (5, "mips64"),
        (6, "ppc"), (7, "s390"), (8, "sh"), (9, "sparc"), (10, "sparc64"),
        (11, "m68k"), (13, "microblaze"), (14, "nios2"), (15, "blackfin"),
        (16, "avr32"), (17, "st200"), (22, "aarch64"), (23, "arc"),
        (24, "x86_64"), (25, "xtensa"), (26, "riscv"), (200, "unknown"),
    ];
    for (b, expected) in cases {
        let data = make_uboot_header(0, 0, b, b"");
        assert_eq!(UBootHeader::parse(&data).unwrap().arch_str(), expected);
    }
}

#[test]
fn uboot_os_str_all_known() {
    let data = make_uboot_header(0, 0, 2, b"");
    let mut hdr = UBootHeader::parse(&data).unwrap();
    let cases = [
        (1u8, "openbsd"), (5, "linux"), (14, "vxworks"), (16, "qnx"),
        (17, "u-boot"), (18, "rtems"), (21, "integrity"), (250, "unknown"),
    ];
    for (b, exp) in cases {
        hdr.os_type = b;
        assert_eq!(hdr.os_str(), exp);
    }
}

#[test]
fn uboot_comp_str_all_known() {
    let data = make_uboot_header(0, 0, 2, b"");
    let mut hdr = UBootHeader::parse(&data).unwrap();
    let cases = [
        (0u8, "none"), (1, "gzip"), (2, "bzip2"), (3, "lzma"),
        (4, "lzo"), (5, "lz4"), (6, "zstd"), (99, "unknown"),
    ];
    for (b, exp) in cases {
        hdr.comp_type = b;
        assert_eq!(hdr.comp_str(), exp);
    }
}

#[test]
fn uboot_image_type_str_all_known() {
    let data = make_uboot_header(0, 0, 2, b"");
    let mut hdr = UBootHeader::parse(&data).unwrap();
    let cases = [
        (1u8, "standalone"), (2, "kernel"), (3, "ramdisk"), (4, "multi"),
        (5, "firmware"), (6, "script"), (7, "filesystem"), (8, "flat_dt"),
        (99, "unknown"),
    ];
    for (b, exp) in cases {
        hdr.image_type = b;
        assert_eq!(hdr.image_type_str(), exp);
    }
}

#[test]
fn uboot_payload_in_bounds_and_out() {
    let mut data = make_uboot_header(0, 0, 2, b"");
    data[12..16].copy_from_slice(&4_u32.to_be_bytes());
    data.extend_from_slice(&[1, 2, 3, 4]);
    let hdr = UBootHeader::parse(&data).unwrap();
    assert_eq!(hdr.payload(&data).unwrap(), &[1, 2, 3, 4]);

    // Out of bounds: header says data_size = 1024 but no payload follows.
    let short = make_uboot_header(0, 0, 2, b"");
    let hdr2 = UBootHeader::parse(&short).unwrap();
    assert!(hdr2.payload(&short).is_none());
}

#[test]
fn uboot_display_contains_name() {
    let data = make_uboot_header(0x1000, 0x2000, 2, b"banana");
    let hdr = UBootHeader::parse(&data).unwrap();
    let s = hdr.to_string();
    assert!(s.contains("banana"));
    assert!(s.contains("arm"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Intel HEX
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ihex_record_type_from_byte() {
    assert!(matches!(IntelHexRecordType::from_byte(0x00), IntelHexRecordType::Data));
    assert!(matches!(IntelHexRecordType::from_byte(0x01), IntelHexRecordType::EndOfFile));
    assert!(matches!(IntelHexRecordType::from_byte(0x02), IntelHexRecordType::ExtendedSegmentAddress));
    assert!(matches!(IntelHexRecordType::from_byte(0x03), IntelHexRecordType::StartSegmentAddress));
    assert!(matches!(IntelHexRecordType::from_byte(0x04), IntelHexRecordType::ExtendedLinearAddress));
    assert!(matches!(IntelHexRecordType::from_byte(0x05), IntelHexRecordType::StartLinearAddress));
    assert!(matches!(IntelHexRecordType::from_byte(0x99), IntelHexRecordType::Unknown(0x99)));
}

#[test]
fn ihex_parse_line_missing_colon() {
    let res = IntelHexRecord::parse_line(b"00000001FF");
    assert!(matches!(res, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn ihex_parse_line_empty() {
    let res = IntelHexRecord::parse_line(b"");
    assert!(matches!(res, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn ihex_parse_line_too_short() {
    let res = IntelHexRecord::parse_line(b":00");
    assert!(matches!(res, Err(FirmwareError::TruncatedData)));
}

#[test]
fn ihex_parse_line_bad_hex_digit() {
    // ':' then non-hex chars: should produce a ParseError
    let res = IntelHexRecord::parse_line(b":ZZ00000099");
    assert!(matches!(res, Err(FirmwareError::ParseError(_))));
}

#[test]
fn ihex_parse_line_checksum_mismatch() {
    let mut line = make_ihex_line(0, 0, &[0xAA, 0xBB]);
    let len = line.len();
    line[len - 2] = b'0';
    line[len - 1] = b'0';
    let res = IntelHexRecord::parse_line(&line);
    assert!(matches!(res, Err(FirmwareError::ChecksumMismatch { .. })));
}

#[test]
fn ihex_round_trip_data() {
    let payload = [0x11, 0x22, 0x33, 0x44];
    let line = make_ihex_line(0xABCD, 0x00, &payload);
    let rec = IntelHexRecord::parse_line(&line).unwrap();
    assert_eq!(rec.address, 0xABCD);
    assert_eq!(rec.data, payload);
    assert_eq!(rec.byte_count, 4);
}

#[test]
fn ihex_image_parse_empty() {
    let img = IntelHexImage::parse(b"").unwrap();
    assert!(img.regions.is_empty());
    assert_eq!(img.start_address, None);
}

#[test]
fn ihex_image_extended_linear_then_data() {
    let mut hex = make_ihex_line(0, 0x04, &[0x08, 0x00]);
    hex.extend_from_slice(b"\n");
    hex.extend_from_slice(&make_ihex_line(0x1000, 0x00, &[0xAA, 0xBB]));
    hex.extend_from_slice(b"\n");
    hex.extend_from_slice(&make_ihex_line(0, 0x01, &[]));
    let img = IntelHexImage::parse(&hex).unwrap();
    assert_eq!(img.regions.len(), 1);
    assert_eq!(img.regions[0].0, 0x0800_1000);
    assert_eq!(img.regions[0].1, vec![0xAA, 0xBB]);
}

#[test]
fn ihex_image_start_linear_address() {
    let mut hex = make_ihex_line(0, 0x05, &[0x00, 0x00, 0x10, 0x00]);
    hex.extend_from_slice(b"\n");
    hex.extend_from_slice(&make_ihex_line(0, 0x01, &[]));
    let img = IntelHexImage::parse(&hex).unwrap();
    assert_eq!(img.start_address, Some(0x0000_1000));
}

// ─────────────────────────────────────────────────────────────────────────────
// SREC
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn srec_parse_missing_s() {
    let r = SrecRecord::parse_line(b"X1");
    assert!(matches!(r, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn srec_parse_unknown_type() {
    // S4 is reserved / unknown
    let line = b"S40400000000FB";
    let r = SrecRecord::parse_line(line);
    assert!(matches!(r, Err(FirmwareError::UnknownRecord(_))));
}

#[test]
fn srec_parse_s1_basic() {
    let line = make_srec_s1(0x1234, &[0xDE, 0xAD]);
    let r = SrecRecord::parse_line(&line).unwrap();
    assert_eq!(r.record_type, '1');
    assert_eq!(r.address, 0x1234);
    assert_eq!(r.data, vec![0xDE, 0xAD]);
}

#[test]
fn srec_parse_checksum_mismatch() {
    let mut line = make_srec_s1(0x1234, &[0xDE, 0xAD]);
    let len = line.len();
    line[len - 2] = b'0';
    line[len - 1] = b'0';
    let r = SrecRecord::parse_line(&line);
    assert!(matches!(r, Err(FirmwareError::ChecksumMismatch { .. })));
}

#[test]
fn srec_image_full_parse() {
    let mut input = make_srec_s1(0x1000, &[0xAA, 0xBB]);
    input.extend_from_slice(b"\r\n");
    input.extend_from_slice(&make_srec_s1(0x1002, &[0xCC, 0xDD]));
    input.extend_from_slice(b"\n");
    input.extend_from_slice(&make_srec_s9(0x1000));
    let img = SrecImage::parse(&input).unwrap();
    assert_eq!(img.entry_point, Some(0x1000));
    // Contiguous regions should be merged.
    assert_eq!(img.regions.len(), 1);
    assert_eq!(img.regions[0].1, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn srec_image_empty_input() {
    let img = SrecImage::parse(b"").unwrap();
    assert!(img.regions.is_empty());
    assert_eq!(img.entry_point, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// UF2
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn uf2_magic_constants() {
    assert_eq!(UF2_MAGIC_START0, 0x0A32_4655);
    assert_eq!(UF2_MAGIC_START1, 0x9E5D_5157);
    assert_eq!(UF2_MAGIC_END, 0x0AB1_6F30);
    assert_eq!(UF2_BLOCK_SIZE, 512);
}

#[test]
fn uf2_parse_too_short() {
    let r = Uf2Record::parse(&[0u8; 100]);
    assert!(matches!(r, Err(FirmwareError::TruncatedData)));
}

#[test]
fn uf2_parse_bad_start_magic() {
    let r = Uf2Record::parse(&vec![0u8; 512]);
    assert!(matches!(r, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn uf2_parse_bad_end_magic() {
    let mut block = make_uf2_block(0x1000, &[0; 4]);
    block[508..512].copy_from_slice(&[0u8; 4]);
    let r = Uf2Record::parse(&block);
    assert!(matches!(r, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn uf2_round_trip_fields() {
    let payload = [0xAA, 0xBB, 0xCC];
    let block = make_uf2_block(0x2000_0000, &payload);
    let rec = Uf2Record::parse(&block).unwrap();
    assert_eq!(rec.target_addr, 0x2000_0000);
    assert_eq!(rec.payload_size, payload.len() as u32);
    assert_eq!(rec.num_blocks, 1);
    assert_eq!(&rec.data[..payload.len()], &payload);
}

#[test]
fn uf2_parse_all_truncates_trailing_padding() {
    let mut input = make_uf2_block(0x1000, &[1, 2, 3]);
    input.extend_from_slice(&[0u8; 100]); // trailing garbage less than block size
    let recs = Uf2Record::parse_all(&input).unwrap();
    assert_eq!(recs.len(), 1);
}

#[test]
fn uf2_assemble_merges_contiguous() {
    let mut data = make_uf2_block(0x1000, &[0xAA, 0xBB]);
    data.extend_from_slice(&make_uf2_block(0x1002, &[0xCC, 0xDD]));
    let recs = Uf2Record::parse_all(&data).unwrap();
    let regions = Uf2Record::assemble(&recs);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].0, 0x1000);
    assert_eq!(regions[0].1, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn uf2_assemble_empty() {
    assert!(Uf2Record::assemble(&[]).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// RTOS detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rtos_all_signatures() {
    let cases: &[(&[u8], RtosKind)] = &[
        (b"FreeRTOS", RtosKind::FreeRtos),
        (b"VxWorks", RtosKind::VxWorks),
        (b"ThreadX", RtosKind::ThreadX),
        (b"RTEMS", RtosKind::Rtems),
        (b"QNX", RtosKind::QnxNeutrino),
        (b"Contiki", RtosKind::Contiki),
        (b"TIZEN", RtosKind::TizenRt),
        (b"Zephyr", RtosKind::Zephyr),
        (b"RIOT-OS", RtosKind::Riot),
        (b"NuttX", RtosKind::Nuttx),
        (b"LynxOS", RtosKind::LynxOs),
        (b"INTEGRITY", RtosKind::Integrity),
    ];
    for (needle, expected) in cases {
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(needle);
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_rtos(&buf), Some(*expected), "needle={needle:?}");
    }
}

#[test]
fn rtos_display_all() {
    for (k, s) in [
        (RtosKind::FreeRtos, "FreeRTOS"),
        (RtosKind::VxWorks, "VxWorks"),
        (RtosKind::ThreadX, "ThreadX"),
        (RtosKind::Rtems, "RTEMS"),
        (RtosKind::QnxNeutrino, "QNX Neutrino"),
        (RtosKind::Contiki, "Contiki"),
        (RtosKind::TizenRt, "Tizen RT"),
        (RtosKind::Zephyr, "Zephyr"),
        (RtosKind::Riot, "RIOT OS"),
        (RtosKind::Nuttx, "NuttX"),
        (RtosKind::LynxOs, "LynxOS"),
        (RtosKind::Integrity, "INTEGRITY"),
    ] {
        assert_eq!(k.to_string(), s);
    }
}

#[test]
fn rtos_none_on_random_data() {
    assert_eq!(detect_rtos(&[0u8; 1024]), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture and endian string hints
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn arch_hint_known_markers() {
    let cases: &[(&[u8], &str)] = &[
        (b"ARM Cortex-A", "arm"),
        (b"AArch64 system", "aarch64"),
        (b"MIPS rev 2", "mips"),
        (b"PowerPC e500", "ppc"),
        (b"RISC-V hart", "riscv"),
        (b"x86_64 ABI", "x86_64"),
        (b"i386 boot", "x86"),
        (b"ESP8266 sketch", "xtensa"),
        (b"MSP430 micro", "msp430"),
    ];
    for (needle, arch) in cases {
        assert_eq!(detect_arch_hint(needle).as_deref(), Some(*arch));
    }
}

#[test]
fn arch_hint_none() {
    assert_eq!(detect_arch_hint(b"no clue here"), None);
}

#[test]
fn endian_hint_short_data() {
    assert_eq!(detect_endian_hint(&[0u8; 4]), None);
}

#[test]
fn endian_hint_little_endian_pointers() {
    // Pattern: 4-byte words ending in 0x00 → little-endian
    let mut data = Vec::new();
    for _ in 0..32 {
        data.extend_from_slice(&[0x10, 0x20, 0x30, 0x00]);
    }
    assert_eq!(detect_endian_hint(&data).as_deref(), Some("little"));
}

#[test]
fn endian_hint_big_endian_pointers() {
    let mut data = Vec::new();
    for _ in 0..32 {
        data.extend_from_slice(&[0x00, 0x30, 0x20, 0x10]);
    }
    assert_eq!(detect_endian_hint(&data).as_deref(), Some("big"));
}

// ─────────────────────────────────────────────────────────────────────────────
// String extraction & classification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn classify_url_variants() {
    assert_eq!(classify_string("http://x.com"), StringCategory::Url);
    assert_eq!(classify_string("https://x.com"), StringCategory::Url);
    assert_eq!(classify_string("ftp://x.com"), StringCategory::Url);
}

#[test]
fn classify_path_variants() {
    assert_eq!(classify_string("/usr/bin"), StringCategory::Path);
    assert_eq!(classify_string("C:\\Windows"), StringCategory::Path);
}

#[test]
fn classify_ip_address() {
    assert_eq!(classify_string("10.0.0.1"), StringCategory::IpAddress);
    assert_eq!(classify_string("255.255.255.255"), StringCategory::IpAddress);
}

#[test]
fn classify_version_marker() {
    assert_eq!(classify_string("kernel v1.2"), StringCategory::Version);
}

#[test]
fn classify_generic_fallback() {
    assert_eq!(classify_string("plainword"), StringCategory::Generic);
}

#[test]
fn string_category_display_all() {
    assert_eq!(StringCategory::Version.to_string(), "version");
    assert_eq!(StringCategory::Url.to_string(), "url");
    assert_eq!(StringCategory::Path.to_string(), "path");
    assert_eq!(StringCategory::IpAddress.to_string(), "ip");
    assert_eq!(StringCategory::Generic.to_string(), "generic");
}

#[test]
fn extract_strings_skips_short() {
    let data = b"abc\x00helloworld\x00";
    let s = extract_firmware_strings(data, 6);
    assert!(s.iter().all(|x| x.text.len() >= 6));
    assert!(s.iter().any(|x| x.text == "helloworld"));
}

#[test]
fn extract_strings_trailing_string_at_eof() {
    let data = b"\x00trailing_string";
    let s = extract_firmware_strings(data, 4);
    assert!(s.iter().any(|x| x.text == "trailing_string"));
}

#[test]
fn extract_strings_empty_input() {
    assert!(extract_firmware_strings(&[], 4).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareInfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn firmware_info_analyse_raw_zero_bytes() {
    let info = FirmwareInfo::analyse(&[], 0);
    assert_eq!(info.size, 0);
    assert_eq!(info.kind, FirmwareKind::Raw);
    assert_eq!(info.entropy, 0.0);
    assert!(info.strings.is_empty());
}

#[test]
fn firmware_info_analyse_with_uboot() {
    let data = make_uboot_header(0x8000_0000, 0x8000_0000, 2, b"img");
    let info = FirmwareInfo::analyse(&data, 0x8000_0000);
    assert_eq!(info.kind, FirmwareKind::UBoot);
    assert_eq!(info.base_address, 0x8000_0000);
    assert_eq!(info.size, 64);
}

#[test]
fn firmware_info_display_includes_kind() {
    let info = FirmwareInfo::analyse(&[0u8; 16], 0);
    let s = info.to_string();
    assert!(s.contains("firmware"));
    assert!(s.contains("entropy"));
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareError
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn firmware_error_display_all_variants() {
    assert!(FirmwareError::TruncatedData.to_string().contains("truncated"));
    assert!(FirmwareError::InvalidMagic("foo".into()).to_string().contains("foo"));
    let e = FirmwareError::ChecksumMismatch { expected: 0x12, actual: 0x34 };
    let s = e.to_string();
    assert!(s.contains("0x12") && s.contains("0x34"));
    assert!(FirmwareError::UnknownRecord(0xFE).to_string().contains("0xfe"));
    assert!(FirmwareError::ParseError("oops".into()).to_string().contains("oops"));
    assert!(FirmwareError::AddressOverflow(7).to_string().contains('7'));
}

// ─────────────────────────────────────────────────────────────────────────────
// BootSection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn boot_sections_empty_data() {
    assert!(detect_boot_sections(&[], 0).is_empty());
}

#[test]
fn boot_sections_uboot_returns_header_and_payload() {
    let mut data = make_uboot_header(0x1000, 0x1000, 2, b"x");
    data[12..16].copy_from_slice(&16_u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 16]);
    let sections = detect_boot_sections(&data, 0);
    assert!(sections.iter().any(|s| s.name == "uboot-header"));
    assert!(sections.iter().any(|s| s.name == "uboot-payload"));
}

#[test]
fn boot_sections_detects_marker_string() {
    let mut data = vec![0u8; 64];
    data.extend_from_slice(b"U-Boot");
    let sections = detect_boot_sections(&data, 0);
    assert!(sections.iter().any(|s| s.name == "u-boot"));
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareArch (Architecture trait impl)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn firmware_arch_defaults() {
    let a = FirmwareArch::new("custom".into());
    assert_eq!(a.name(), "custom");
    assert_eq!(a.pointer_size(), 4);
    assert_eq!(a.endian(), Endian::Little);
}

#[test]
fn firmware_arch_with_params_overrides() {
    let a = FirmwareArch::with_params("ppc".into(), 8, Endian::Big);
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.endian(), Endian::Big);
}

#[test]
fn firmware_arch_disassemble_returns_nop_like() {
    // Name kept for continuity; the behaviour it described was the defect.
    // `FirmwareArch` used to answer `nop` with a length derived from the first
    // byte (`bytes[0] % 4 + 1`) for any input. It carries no instruction decoder
    // for ARM/Thumb/MIPS/RISC-V/Xtensa, so it now says so instead.
    use rustre_core::address::Address;
    let a = FirmwareArch::new("test".into());
    let err = a
        .disassemble(Address::new(0), &[0x04, 0x00, 0x00, 0x00])
        .expect_err("must not claim to have decoded anything");
    assert!(err.to_string().contains("test"), "error names the arch");
}

#[test]
fn firmware_arch_no_branches_no_regs() {
    // The intent of this test is `get_branches`/`registers`/`calling_conventions`,
    // not `disassemble`; it only used the latter to obtain an `Instruction`.
    // Since `disassemble` now refuses (no decoder for the detected ISA), the
    // instruction is built directly so the original three assertions survive.
    use rustre_core::address::Address;
    use rustre_core::arch::Instruction;
    let a = FirmwareArch::new("test".into());
    let instr = Instruction::new(Address::new(0), 4, "raw", vec![0u8; 4]);
    assert!(a.get_branches(&instr).is_empty());
    assert!(a.registers().is_empty());
    assert!(a.calling_conventions().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Loaders (FirmwareLoader, IntelHexLoader, SrecLoader, Uf2Loader)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn firmware_loader_name_and_default() {
    let l = FirmwareLoader;
    assert_eq!(l.name(), "firmware");
    let l2 = FirmwareLoader::new();
    assert_eq!(l2.name(), "firmware");
}

#[test]
fn firmware_loader_can_load_too_short() {
    assert!(!FirmwareLoader::new().can_load(&LoaderInput::new("x", vec![0; 3])));
}

#[test]
fn firmware_loader_rejects_elf_and_pe() {
    let l = FirmwareLoader::new();
    assert!(!l.can_load(&LoaderInput::new("a", b"\x7fELF\x00\x00\x00\x00".to_vec())));
    assert!(!l.can_load(&LoaderInput::new("b", b"MZ\x00\x00".to_vec())));
}

#[tokio::test]
async fn firmware_loader_loads_raw() {
    let result = FirmwareLoader::new()
        .load(LoaderInput::new("fw.bin", vec![0xAA; 256]))
        .await
        .unwrap();
    assert_eq!(result.view.uri, "fw.bin");
}

#[tokio::test]
async fn firmware_loader_loads_uboot_with_entry() {
    let mut data = make_uboot_header(0x4000_0000, 0x4000_0040, 2, b"k");
    data.extend_from_slice(&[0u8; 1024]);
    let r = FirmwareLoader::new().load(LoaderInput::new("u.img", data)).await.unwrap();
    assert_eq!(r.view.entry_points[0].as_u64(), 0x4000_0040);
}

#[tokio::test]
async fn firmware_loader_find_nested_empty() {
    let r = FirmwareLoader::new()
        .find_nested(&LoaderInput::new("a", vec![0xAA; 128]))
        .await
        .unwrap();
    assert!(r.is_empty());
}

#[test]
fn ihex_loader_can_load_only_ascii_colon() {
    let l = IntelHexLoader::new();
    assert!(l.can_load(&LoaderInput::new("x", b":0011".to_vec())));
    assert!(!l.can_load(&LoaderInput::new("x", b"\x00:".to_vec())));
}

#[tokio::test]
async fn ihex_loader_load_minimal() {
    let mut hex = make_ihex_line(0x0000, 0x00, &[0xAA, 0xBB]);
    hex.extend_from_slice(b"\n");
    hex.extend_from_slice(&make_ihex_line(0, 0x01, &[]));
    let r = IntelHexLoader::new().load(LoaderInput::new("a.hex", hex)).await.unwrap();
    assert_eq!(r.view.uri, "a.hex");
}

#[test]
fn srec_loader_name_and_can_load() {
    let l = SrecLoader::new();
    assert_eq!(l.name(), "srec");
    assert!(l.can_load(&LoaderInput::new("x", b"S1".to_vec())));
    assert!(!l.can_load(&LoaderInput::new("x", b"XS".to_vec())));
    assert!(!l.can_load(&LoaderInput::new("x", b"S".to_vec())));
}

#[tokio::test]
async fn srec_loader_load_with_entry() {
    let mut input = make_srec_s1(0x2000, &[0xAA, 0xBB]);
    input.extend_from_slice(b"\n");
    input.extend_from_slice(&make_srec_s9(0x2000));
    let r = SrecLoader::new().load(LoaderInput::new("a.srec", input)).await.unwrap();
    assert_eq!(r.view.entry_points[0].as_u64(), 0x2000);
}

#[test]
fn uf2_loader_can_load_requires_block_size_and_magic() {
    let l = Uf2Loader::new();
    assert!(!l.can_load(&LoaderInput::new("x", b"UF2\n".to_vec())));
    let block = make_uf2_block(0x1000, &[1, 2]);
    // Note: real uf2 starts with the binary magic UF2_MAGIC_START0 = 0x0A324655 LE,
    // which is "UF2\n" exactly. So block already begins with "UF2\n".
    assert!(l.can_load(&LoaderInput::new("x", block)));
}

#[tokio::test]
async fn uf2_loader_load_assembles_regions() {
    let block = make_uf2_block(0x0800_0000, &[0x11, 0x22, 0x33, 0x44]);
    let r = Uf2Loader::new().load(LoaderInput::new("a.uf2", block)).await.unwrap();
    assert_eq!(r.view.entry_points[0].as_u64(), 0x0800_0000);
}

#[tokio::test]
async fn all_loaders_find_nested_returns_empty() {
    let input = LoaderInput::new("x", vec![0; 128]);
    assert!(FirmwareLoader::new().find_nested(&input).await.unwrap().is_empty());
    assert!(IntelHexLoader::new().find_nested(&input).await.unwrap().is_empty());
    assert!(SrecLoader::new().find_nested(&input).await.unwrap().is_empty());
    assert!(Uf2Loader::new().find_nested(&input).await.unwrap().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Send / Sync bounds (Loader objects must be usable cross-thread)
// ─────────────────────────────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn loaders_are_send_sync() {
    assert_send_sync::<FirmwareLoader>();
    assert_send_sync::<IntelHexLoader>();
    assert_send_sync::<SrecLoader>();
    assert_send_sync::<Uf2Loader>();
    assert_send_sync::<FirmwareArch>();
    assert_send_sync::<UBootHeader>();
    assert_send_sync::<FirmwareError>();
}
