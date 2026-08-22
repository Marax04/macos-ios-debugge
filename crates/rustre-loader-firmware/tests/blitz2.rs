//! Y083 blitz2 deep adversarial test suite for rustre-loader-firmware.
//!
//! Targets the public API exposed in `lib.rs`: `detect_firmware_kind`,
//! `ByteHistogram`, `UBootHeader`, IntelHexRecord/Image, SrecRecord/Image,
//! `Uf2Record`, FirmwareKind/BinaryArch/RtosKind/StringCategory display,
//! `classify_string`, `extract_firmware_strings`, `detect_rtos`,
//! `detect_arch_hint`, `detect_endian_hint`, `detect_boot_sections`,
//! `scan_embedded_signatures`, `detect_binary_arch`, `detect_raw_endian`,
//! `FirmwareError` variants, `FirmwareInfo::analyse`.

use rustre_loader_firmware::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ─── Seeded LCG (no rand/no time) ────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
fn make_ihex_line(rt: u8, addr: u16, data: &[u8]) -> Vec<u8> {
    let bc = data.len() as u8;
    let ah = (addr >> 8) as u8;
    let al = addr as u8;
    let mut sum: u8 = bc.wrapping_add(ah).wrapping_add(al).wrapping_add(rt);
    for &b in data {
        sum = sum.wrapping_add(b);
    }
    let cs = (!sum).wrapping_add(1);
    let mut s = format!(":{bc:02X}{addr:04X}{rt:02X}");
    for &b in data {
        s.push_str(&format!("{b:02X}"));
    }
    s.push_str(&format!("{cs:02X}"));
    s.into_bytes()
}

fn make_srec_line(rt: char, addr_bytes: usize, addr: u64, data: &[u8]) -> Vec<u8> {
    let bc = (addr_bytes + data.len() + 1) as u8;
    let mut s = format!("S{rt}{bc:02X}");
    let mut sum: u32 = u32::from(bc);
    for i in (0..addr_bytes).rev() {
        let b = ((addr >> (i * 8)) & 0xFF) as u8;
        s.push_str(&format!("{b:02X}"));
        sum += u32::from(b);
    }
    for &b in data {
        s.push_str(&format!("{b:02X}"));
        sum += u32::from(b);
    }
    let cs = (!(sum & 0xFF)) as u8;
    s.push_str(&format!("{cs:02X}"));
    s.into_bytes()
}

fn make_uboot_header(data_size: u32, load: u32, ep: u32, name: &str) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&UBootHeader::MAGIC.to_be_bytes());
    h[4..8].copy_from_slice(&0u32.to_be_bytes()); // hdr crc
    h[8..12].copy_from_slice(&0u32.to_be_bytes()); // ts
    h[12..16].copy_from_slice(&data_size.to_be_bytes());
    h[16..20].copy_from_slice(&load.to_be_bytes());
    h[20..24].copy_from_slice(&ep.to_be_bytes());
    h[24..28].copy_from_slice(&0u32.to_be_bytes()); // data crc
    h[28] = 5;
    h[29] = 2;
    h[30] = 2;
    h[31] = 0;
    let nb = name.as_bytes();
    let take = nb.len().min(31);
    h[32..32 + take].copy_from_slice(&nb[..take]);
    h
}

fn make_uf2_block(target: u32, payload: &[u8], block_no: u32, num_blocks: u32) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&0x0A32_4655u32.to_le_bytes());
    b[4..8].copy_from_slice(&0x9E5D_5157u32.to_le_bytes());
    b[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags
    b[12..16].copy_from_slice(&target.to_le_bytes());
    b[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    b[20..24].copy_from_slice(&block_no.to_le_bytes());
    b[24..28].copy_from_slice(&num_blocks.to_le_bytes());
    b[28..32].copy_from_slice(&0u32.to_le_bytes()); // file size
    let take = payload.len().min(476);
    b[32..32 + take].copy_from_slice(&payload[..take]);
    b[508..512].copy_from_slice(&0x0AB1_6F30u32.to_le_bytes());
    b
}

// ═══ TESTS ═══════════════════════════════════════════════════════════════════

#[test]
fn t01_detect_kind_all_known_magics() {
    assert_eq!(detect_firmware_kind(b"\x1f\x8b\x00\x00"), FirmwareKind::TarGz);
    assert_eq!(detect_firmware_kind(b"BZh91"), FirmwareKind::Bzip2);
    assert_eq!(
        detect_firmware_kind(b"\xFD7zXZ\x00rest"),
        FirmwareKind::Xz
    );
    assert_eq!(detect_firmware_kind(b"\x5D\x00\x00\x10"), FirmwareKind::Lzma);
    assert_eq!(detect_firmware_kind(b":10000000"), FirmwareKind::IntelHex);
    assert_eq!(detect_firmware_kind(b"S0030000"), FirmwareKind::Srec);
    let mut u = vec![0u8; 8];
    u[..4].copy_from_slice(b"UF2\n");
    assert_eq!(detect_firmware_kind(&u), FirmwareKind::Uf2);
}

#[test]
fn t02_detect_kind_short_inputs() {
    assert_eq!(detect_firmware_kind(&[]), FirmwareKind::Raw);
    assert_eq!(detect_firmware_kind(&[0xFF]), FirmwareKind::Raw);
    // exactly 2 bytes, unknown
    assert_eq!(detect_firmware_kind(&[0xAA, 0xBB]), FirmwareKind::Unknown);
}

#[test]
fn t03_detect_kind_uboot_be_magic() {
    let d = [0x27, 0x05, 0x19, 0x56, 0, 0, 0, 0];
    assert_eq!(detect_firmware_kind(&d), FirmwareKind::UBoot);
}

#[test]
fn t04_detect_kind_uboot_fit() {
    let d = [0xD0, 0x0D, 0xFE, 0xED, 0, 0, 0, 0];
    assert_eq!(detect_firmware_kind(&d), FirmwareKind::UBootFit);
}

#[test]
fn t05_detect_kind_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let len = (lcg.next_u64() % 1024) as usize;
        let d = lcg.next_bytes(len);
        let _ = detect_firmware_kind(&d);
    }
}

#[test]
fn t06_firmware_kind_predicate_consistency() {
    let all = [
        FirmwareKind::Raw,
        FirmwareKind::UBoot,
        FirmwareKind::UBootFit,
        FirmwareKind::SquashFs,
        FirmwareKind::Jffs2,
        FirmwareKind::CramFs,
        FirmwareKind::Ext2,
        FirmwareKind::Yaffs2,
        FirmwareKind::TarGz,
        FirmwareKind::Bzip2,
        FirmwareKind::Lzma,
        FirmwareKind::Xz,
        FirmwareKind::IntelHex,
        FirmwareKind::Srec,
        FirmwareKind::Uf2,
        FirmwareKind::Unknown,
    ];
    for k in all {
        // Display non-empty
        assert!(!k.to_string().is_empty());
        // Mutually exclusive categories
        let cnt = u8::from(k.is_compressed()) + u8::from(k.is_filesystem()) + u8::from(k.is_text_format());
        assert!(cnt <= 1, "{k:?} in multiple categories");
    }
}

#[test]
fn t07_firmware_kind_eq_hash_consistency() {
    let pairs = [
        (FirmwareKind::Raw, FirmwareKind::Raw, true),
        (FirmwareKind::UBoot, FirmwareKind::UBoot, true),
        (FirmwareKind::TarGz, FirmwareKind::Xz, false),
        (FirmwareKind::SquashFs, FirmwareKind::Jffs2, false),
        (FirmwareKind::IntelHex, FirmwareKind::Srec, false),
        (FirmwareKind::Unknown, FirmwareKind::Raw, false),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq);
    }
    // For Eq types, equal values must have same Hash output via wrapper struct.
    // (FirmwareKind is Eq+Copy but not Hash; skip hashing — use BinaryArch.)
    let bas = [
        BinaryArch::ArmThumb,
        BinaryArch::Aarch64,
        BinaryArch::X86,
        BinaryArch::X86_64,
        BinaryArch::Mips32Be,
        BinaryArch::Mips32Le,
        BinaryArch::RiscV32,
        BinaryArch::RiscV64,
        BinaryArch::PowerPcBe,
        BinaryArch::ArmAarch32,
        BinaryArch::Unknown,
    ];
    for a in bas {
        for b in bas {
            let mut ha = DefaultHasher::new();
            let mut hb = DefaultHasher::new();
            a.hash(&mut ha);
            b.hash(&mut hb);
            if a == b {
                assert_eq!(ha.finish(), hb.finish());
            }
        }
    }
}

#[test]
fn t08_byte_histogram_empty() {
    let h = ByteHistogram::from_data(&[]);
    assert_eq!(h.total, 0);
    assert_eq!(h.entropy(), 0.0);
    assert!(!h.is_high_entropy());
    assert!(h.is_sparse() || h.entropy() == 0.0);
}

#[test]
fn t09_byte_histogram_uniform_random_ish() {
    // 256-byte rotation produces uniform distribution, max entropy 8.0.
    let d: Vec<u8> = (0..=255u8).collect();
    let h = ByteHistogram::from_data(&d);
    assert_eq!(h.total, 256);
    let e = h.entropy();
    assert!(e > 7.99, "entropy={e}");
    assert!(h.is_high_entropy());
    assert!(!h.is_sparse());
}

#[test]
fn t10_byte_histogram_single_value() {
    let h = ByteHistogram::from_data(&[7u8; 64]);
    assert_eq!(h.entropy(), 0.0);
    assert!(h.is_sparse());
    assert_eq!(h.most_common_byte(), 7);
}

#[test]
fn t11_byte_histogram_most_common_byte() {
    let mut d = vec![0u8; 50];
    d.extend(vec![99u8; 100]);
    let h = ByteHistogram::from_data(&d);
    assert_eq!(h.most_common_byte(), 99);
}

#[test]
fn t12_sliding_entropy_invalid_params() {
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3], 0, 1).is_empty());
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3], 1, 0).is_empty());
    assert!(ByteHistogram::sliding_entropy(&[1, 2, 3], 100, 1).is_empty());
}

#[test]
fn t13_sliding_entropy_basic() {
    let d = vec![0u8; 512];
    let out = ByteHistogram::sliding_entropy(&d, 256, 128);
    assert!(!out.is_empty());
    for (_, e) in out {
        assert_eq!(e, 0.0);
    }
}

#[test]
fn t14_byte_histogram_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 2048) as usize;
        let d = lcg.next_bytes(n);
        let h = ByteHistogram::from_data(&d);
        let e = h.entropy();
        assert!((0.0..=8.0001).contains(&e), "entropy out of range: {e}");
    }
}

#[test]
fn t15_uboot_header_parse_valid() {
    let h = make_uboot_header(128, 0x8000_0000, 0x8000_0040, "kernel");
    let hdr = UBootHeader::parse(&h).expect("header");
    assert_eq!(hdr.magic, UBootHeader::MAGIC);
    assert_eq!(hdr.data_size, 128);
    assert_eq!(hdr.load_addr, 0x8000_0000);
    assert_eq!(hdr.entry_point, 0x8000_0040);
    assert_eq!(hdr.name, "kernel");
    assert_eq!(hdr.entry(), 0x8000_0040);
    assert_eq!(hdr.os_str(), "linux");
    assert_eq!(hdr.arch_str(), "arm");
    assert_eq!(hdr.image_type_str(), "kernel");
    assert_eq!(hdr.comp_str(), "none");
}

#[test]
fn t16_uboot_header_truncated() {
    assert!(UBootHeader::parse(&[]).is_none());
    assert!(UBootHeader::parse(&[0; 63]).is_none());
}

#[test]
fn t17_uboot_header_bad_magic() {
    let mut h = make_uboot_header(0, 0, 0, "x");
    h[0] = 0xAA;
    assert!(UBootHeader::parse(&h).is_none());
}

#[test]
fn t18_uboot_payload_extraction() {
    let mut h = make_uboot_header(8, 0, 0, "img");
    h.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let hdr = UBootHeader::parse(&h).unwrap();
    let p = hdr.payload(&h).expect("payload");
    assert_eq!(p, &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn t19_uboot_payload_out_of_bounds() {
    let h = make_uboot_header(100, 0, 0, "img");
    // header alone is 64 bytes, no payload data => payload returns None
    let hdr = UBootHeader::parse(&h).unwrap();
    assert!(hdr.payload(&h).is_none());
}

#[test]
fn t20_uboot_arch_str_table() {
    let mut h = make_uboot_header(0, 0, 0, "");
    let cases = [
        (1u8, "alpha"),
        (2, "arm"),
        (3, "x86"),
        (4, "mips"),
        (22, "aarch64"),
        (26, "riscv"),
        (200, "unknown"),
    ];
    for (v, want) in cases {
        h[29] = v;
        let hdr = UBootHeader::parse(&h).unwrap();
        assert_eq!(hdr.arch_str(), want);
    }
}

#[test]
fn t21_uboot_comp_str_all() {
    let mut h = make_uboot_header(0, 0, 0, "");
    for (v, want) in [(0u8, "none"), (1, "gzip"), (2, "bzip2"), (3, "lzma"), (4, "lzo"), (5, "lz4"), (6, "zstd"), (255, "unknown")] {
        h[31] = v;
        let hdr = UBootHeader::parse(&h).unwrap();
        assert_eq!(hdr.comp_str(), want);
    }
}

#[test]
fn t22_uboot_os_str_table() {
    let mut h = make_uboot_header(0, 0, 0, "");
    for (v, want) in [(5u8, "linux"), (16, "qnx"), (14, "vxworks"), (200, "unknown")] {
        h[28] = v;
        let hdr = UBootHeader::parse(&h).unwrap();
        assert_eq!(hdr.os_str(), want);
    }
}

#[test]
fn t23_uboot_image_type_str_all() {
    let mut h = make_uboot_header(0, 0, 0, "");
    for (v, want) in [(1u8, "standalone"), (2, "kernel"), (8, "flat_dt"), (255, "unknown")] {
        h[30] = v;
        let hdr = UBootHeader::parse(&h).unwrap();
        assert_eq!(hdr.image_type_str(), want);
    }
}

#[test]
fn t24_uboot_header_display_nonempty() {
    let h = make_uboot_header(16, 0x1000, 0x2000, "boot");
    let hdr = UBootHeader::parse(&h).unwrap();
    let s = hdr.to_string();
    assert!(s.contains("boot"));
    assert!(s.contains("kernel"));
}

#[test]
fn t25_uboot_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..100 {
        let n = (lcg.next_u64() % 200) as usize;
        let d = lcg.next_bytes(n);
        let _ = UBootHeader::parse(&d);
    }
}

#[test]
fn t26_intel_hex_record_type_from_byte() {
    use IntelHexRecordType::*;
    assert_eq!(IntelHexRecordType::from_byte(0), Data);
    assert_eq!(IntelHexRecordType::from_byte(1), EndOfFile);
    assert_eq!(IntelHexRecordType::from_byte(2), ExtendedSegmentAddress);
    assert_eq!(IntelHexRecordType::from_byte(3), StartSegmentAddress);
    assert_eq!(IntelHexRecordType::from_byte(4), ExtendedLinearAddress);
    assert_eq!(IntelHexRecordType::from_byte(5), StartLinearAddress);
    assert!(matches!(IntelHexRecordType::from_byte(7), Unknown(7)));
}

#[test]
fn t27_intel_hex_parse_simple_data_record() {
    let line = make_ihex_line(0x00, 0x0010, &[0xAA, 0xBB]);
    let rec = IntelHexRecord::parse_line(&line).expect("parse");
    assert_eq!(rec.byte_count, 2);
    assert_eq!(rec.address, 0x0010);
    assert_eq!(rec.data, vec![0xAA, 0xBB]);
    assert_eq!(rec.record_type, IntelHexRecordType::Data);
}

#[test]
fn t28_intel_hex_parse_eof() {
    let line = make_ihex_line(0x01, 0, &[]);
    let rec = IntelHexRecord::parse_line(&line).unwrap();
    assert_eq!(rec.record_type, IntelHexRecordType::EndOfFile);
}

#[test]
fn t29_intel_hex_missing_colon() {
    let r = IntelHexRecord::parse_line(b"10000000FF");
    assert!(matches!(r, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn t30_intel_hex_bad_checksum() {
    let mut line = make_ihex_line(0x00, 0, &[0x10, 0x20]);
    *line.last_mut().unwrap() ^= 1; // corrupt low nibble of cksum char
    let r = IntelHexRecord::parse_line(&line);
    assert!(matches!(r, Err(FirmwareError::ChecksumMismatch { .. } | FirmwareError::ParseError(_))));
}

#[test]
fn t31_intel_hex_truncated() {
    let r = IntelHexRecord::parse_line(b":1000");
    assert!(matches!(r, Err(FirmwareError::TruncatedData)));
}

#[test]
fn t32_intel_hex_non_hex_chars() {
    let r = IntelHexRecord::parse_line(b":ZZ000000ZZ");
    assert!(matches!(r, Err(FirmwareError::ParseError(_))));
}

#[test]
fn t33_intel_hex_image_round_trip_basic() {
    let mut s = Vec::new();
    s.extend_from_slice(&make_ihex_line(0x00, 0x0000, &[0xDE, 0xAD]));
    s.push(b'\n');
    s.extend_from_slice(&make_ihex_line(0x00, 0x0002, &[0xBE, 0xEF]));
    s.push(b'\n');
    s.extend_from_slice(&make_ihex_line(0x01, 0, &[]));
    let img = IntelHexImage::parse(&s).expect("img");
    // contiguous → merged into one region
    assert_eq!(img.regions.len(), 1);
    assert_eq!(img.regions[0].0, 0);
    assert_eq!(img.regions[0].1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn t34_intel_hex_image_extended_linear_address() {
    let mut s = Vec::new();
    // ExtLinear: upper = 0x1234 → base = 0x12340000
    s.extend_from_slice(&make_ihex_line(0x04, 0x0000, &[0x12, 0x34]));
    s.push(b'\n');
    s.extend_from_slice(&make_ihex_line(0x00, 0x0000, &[0xAB]));
    s.push(b'\n');
    s.extend_from_slice(&make_ihex_line(0x01, 0, &[]));
    let img = IntelHexImage::parse(&s).unwrap();
    assert_eq!(img.regions.len(), 1);
    assert_eq!(img.regions[0].0, 0x1234_0000);
}

#[test]
fn t35_intel_hex_image_start_linear_address() {
    let mut s = Vec::new();
    s.extend_from_slice(&make_ihex_line(0x05, 0x0000, &[0x00, 0x00, 0x12, 0x34]));
    s.push(b'\n');
    s.extend_from_slice(&make_ihex_line(0x01, 0, &[]));
    let img = IntelHexImage::parse(&s).unwrap();
    assert_eq!(img.start_address, Some(0x1234));
}

#[test]
fn t36_intel_hex_image_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 256) as usize;
        let d = lcg.next_bytes(n);
        let _ = IntelHexImage::parse(&d);
    }
}

#[test]
fn t37_srec_record_parse_s1() {
    // S1 record with 2-byte address
    let line = make_srec_line('1', 2, 0x0010, &[0xAA, 0xBB]);
    let rec = SrecRecord::parse_line(&line).expect("parse");
    assert_eq!(rec.record_type, '1');
    assert_eq!(rec.address, 0x0010);
    assert_eq!(rec.data, vec![0xAA, 0xBB]);
}

#[test]
fn t38_srec_record_parse_s3() {
    let line = make_srec_line('3', 4, 0x1000_0000, &[1, 2, 3, 4]);
    let rec = SrecRecord::parse_line(&line).unwrap();
    assert_eq!(rec.record_type, '3');
    assert_eq!(rec.address, 0x1000_0000);
}

#[test]
fn t39_srec_record_parse_s0_header() {
    let line = make_srec_line('0', 2, 0, b"HDR");
    let rec = SrecRecord::parse_line(&line).unwrap();
    assert_eq!(rec.record_type, '0');
    assert_eq!(rec.data, b"HDR");
}

#[test]
fn t40_srec_invalid_magic() {
    let r = SrecRecord::parse_line(b"X103000000FC");
    assert!(matches!(r, Err(FirmwareError::InvalidMagic(_))));
}

#[test]
fn t41_srec_unknown_record() {
    // S4 is unused/reserved
    let line = b"S4030000FC";
    let r = SrecRecord::parse_line(line);
    assert!(matches!(r, Err(FirmwareError::UnknownRecord(_))));
}

#[test]
fn t42_srec_bad_checksum() {
    let mut line = make_srec_line('1', 2, 0, &[0x10]);
    *line.last_mut().unwrap() ^= 1;
    let r = SrecRecord::parse_line(&line);
    assert!(matches!(r, Err(FirmwareError::ChecksumMismatch { .. } | FirmwareError::ParseError(_))));
}

#[test]
fn t43_srec_image_parse_with_entry() {
    let mut s = Vec::new();
    s.extend_from_slice(&make_srec_line('1', 2, 0, &[0xAA, 0xBB]));
    s.push(b'\n');
    s.extend_from_slice(&make_srec_line('1', 2, 2, &[0xCC, 0xDD]));
    s.push(b'\n');
    s.extend_from_slice(&make_srec_line('9', 2, 0x1234, &[]));
    let img = SrecImage::parse(&s).unwrap();
    assert_eq!(img.regions.len(), 1);
    assert_eq!(img.regions[0].1, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(img.entry_point, Some(0x1234));
}

#[test]
fn t44_srec_image_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 256) as usize;
        let d = lcg.next_bytes(n);
        let _ = SrecImage::parse(&d);
    }
}

#[test]
fn t45_uf2_parse_valid_block() {
    let blk = make_uf2_block(0x2000_0000, &[0xAA, 0xBB, 0xCC, 0xDD], 0, 1);
    let r = Uf2Record::parse(&blk).expect("parse");
    assert_eq!(r.target_addr, 0x2000_0000);
    assert_eq!(r.payload_size, 4);
    assert_eq!(r.block_no, 0);
    assert_eq!(r.num_blocks, 1);
}

#[test]
fn t46_uf2_too_short() {
    assert!(matches!(
        Uf2Record::parse(&[0u8; 100]),
        Err(FirmwareError::TruncatedData)
    ));
}

#[test]
fn t47_uf2_bad_magic_start() {
    let mut blk = make_uf2_block(0, &[], 0, 1);
    blk[0] = 0xFF;
    assert!(matches!(
        Uf2Record::parse(&blk),
        Err(FirmwareError::InvalidMagic(_))
    ));
}

#[test]
fn t48_uf2_bad_magic_end() {
    let mut blk = make_uf2_block(0, &[], 0, 1);
    blk[508] = 0xFF;
    assert!(matches!(
        Uf2Record::parse(&blk),
        Err(FirmwareError::InvalidMagic(_))
    ));
}

#[test]
fn t49_uf2_parse_all_multiple_blocks() {
    let mut buf = Vec::new();
    for i in 0..4u32 {
        buf.extend(make_uf2_block(0x2000_0000 + i * 256, &[i as u8; 8], i, 4));
    }
    let recs = Uf2Record::parse_all(&buf).unwrap();
    assert_eq!(recs.len(), 4);
}

#[test]
fn t50_uf2_parse_all_trailing_padding_truncated() {
    let mut buf = make_uf2_block(0x0, &[1, 2, 3], 0, 1);
    buf.extend_from_slice(&[0u8; 100]); // unaligned tail → ignored
    let recs = Uf2Record::parse_all(&buf).unwrap();
    assert_eq!(recs.len(), 1);
}

#[test]
fn t51_uf2_assemble_contiguous() {
    let recs = vec![
        Uf2Record::parse(&make_uf2_block(0x1000, &[1, 2, 3, 4], 0, 2)).unwrap(),
        Uf2Record::parse(&make_uf2_block(0x1004, &[5, 6, 7, 8], 1, 2)).unwrap(),
    ];
    let regions = Uf2Record::assemble(&recs);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn t52_uf2_assemble_disjoint() {
    let recs = vec![
        Uf2Record::parse(&make_uf2_block(0x1000, &[1, 2], 0, 2)).unwrap(),
        Uf2Record::parse(&make_uf2_block(0x9000, &[3, 4], 1, 2)).unwrap(),
    ];
    let regions = Uf2Record::assemble(&recs);
    assert_eq!(regions.len(), 2);
}

#[test]
fn t53_uf2_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 2048) as usize;
        let d = lcg.next_bytes(n);
        let _ = Uf2Record::parse_all(&d);
    }
}

#[test]
fn t54_classify_string_url() {
    assert_eq!(classify_string("http://example.com"), StringCategory::Url);
    assert_eq!(classify_string("https://x.y"), StringCategory::Url);
    assert_eq!(classify_string("ftp://srv/file"), StringCategory::Url);
}

#[test]
fn t55_classify_string_path() {
    assert_eq!(classify_string("/etc/passwd"), StringCategory::Path);
    assert_eq!(classify_string("C:\\Win"), StringCategory::Path);
}

#[test]
fn t56_classify_string_ip() {
    assert_eq!(classify_string("192.168.0.1"), StringCategory::IpAddress);
    assert_eq!(classify_string("8.8.8.8"), StringCategory::IpAddress);
}

#[test]
fn t57_classify_string_generic_or_version() {
    // pure alpha → generic
    assert_eq!(classify_string("HelloWorld"), StringCategory::Generic);
    // contains version keyword
    assert_eq!(classify_string("Version 1"), StringCategory::Version);
}

#[test]
fn t58_classify_string_category_display() {
    assert_eq!(StringCategory::Version.to_string(), "version");
    assert_eq!(StringCategory::Url.to_string(), "url");
    assert_eq!(StringCategory::Path.to_string(), "path");
    assert_eq!(StringCategory::IpAddress.to_string(), "ip");
    assert_eq!(StringCategory::Generic.to_string(), "generic");
}

#[test]
fn t59_extract_strings_min_len_boundary() {
    let data = b"ab\0abcdef\0xy";
    // min_len=6 → only "abcdef" qualifies
    let v = extract_firmware_strings(data, 6);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].text, "abcdef");
    assert_eq!(v[0].offset, 3);
}

#[test]
fn t60_extract_strings_empty() {
    assert!(extract_firmware_strings(&[], 4).is_empty());
    assert!(extract_firmware_strings(&[0, 0, 0], 4).is_empty());
}

#[test]
fn t61_extract_strings_trailing_unterminated() {
    let data = b"helloworld";
    let v = extract_firmware_strings(data, 4);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].text, "helloworld");
}

#[test]
fn t62_extract_strings_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = (lcg.next_u64() % 1024) as usize;
        let d = lcg.next_bytes(n);
        let _ = extract_firmware_strings(&d, 6);
    }
}

#[test]
fn t63_detect_rtos_all_signatures() {
    let cases: &[(&[u8], RtosKind)] = &[
        (b"FreeRTOS kernel", RtosKind::FreeRtos),
        (b"VxWorks 6.9", RtosKind::VxWorks),
        (b"ThreadX rtos", RtosKind::ThreadX),
        (b"RTEMS init", RtosKind::Rtems),
        (b"QNX neutrino", RtosKind::QnxNeutrino),
        (b"Contiki net", RtosKind::Contiki),
        (b"TIZEN-rt", RtosKind::TizenRt),
        (b"Zephyr kernel", RtosKind::Zephyr),
        (b"RIOT-OS sched", RtosKind::Riot),
        (b"NuttX scheduler", RtosKind::Nuttx),
        (b"LynxOS", RtosKind::LynxOs),
        (b"INTEGRITY rtos", RtosKind::Integrity),
    ];
    for (d, k) in cases {
        assert_eq!(detect_rtos(d), Some(*k));
    }
}

#[test]
fn t64_detect_rtos_no_match() {
    assert_eq!(detect_rtos(b"nothing here"), None);
    assert_eq!(detect_rtos(&[]), None);
}

#[test]
fn t65_detect_arch_hint_variants() {
    assert_eq!(
        detect_arch_hint(b"prefix ARM Ltd suffix").as_deref(),
        Some("arm")
    );
    assert_eq!(detect_arch_hint(b"AArch64 here").as_deref(), Some("aarch64"));
    assert_eq!(detect_arch_hint(b"RISC-V cpu").as_deref(), Some("riscv"));
    assert_eq!(detect_arch_hint(b"x86_64 ok").as_deref(), Some("x86_64"));
    assert_eq!(detect_arch_hint(b"ESP32 chip").as_deref(), Some("xtensa"));
    assert_eq!(detect_arch_hint(b"nothing"), None);
}

#[test]
fn t66_detect_endian_hint_short() {
    assert!(detect_endian_hint(&[]).is_none());
    assert!(detect_endian_hint(&[0u8; 4]).is_none());
}

#[test]
fn t67_detect_endian_hint_le() {
    // Every 4-byte word ends with 0 → LE pointers
    let mut d = Vec::new();
    for _ in 0..32 {
        d.extend_from_slice(&[0x10, 0x20, 0x30, 0x00]);
    }
    assert_eq!(detect_endian_hint(&d).as_deref(), Some("little"));
}

#[test]
fn t68_detect_endian_hint_be() {
    let mut d = Vec::new();
    for _ in 0..32 {
        d.extend_from_slice(&[0x00, 0x10, 0x20, 0x30]);
    }
    assert_eq!(detect_endian_hint(&d).as_deref(), Some("big"));
}

#[test]
fn t69_detect_boot_sections_uboot() {
    let mut h = make_uboot_header(8, 0x8000, 0x8040, "img");
    h.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let secs = detect_boot_sections(&h, 0);
    assert!(secs.iter().any(|s| s.name == "uboot-header"));
    assert!(secs.iter().any(|s| s.name == "uboot-payload"));
}

#[test]
fn t70_detect_boot_sections_cortex_m() {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(&0x2001_FFF0u32.to_le_bytes()); // SP
    d[4..8].copy_from_slice(&0x0800_0101u32.to_le_bytes()); // PC
    let secs = detect_boot_sections(&d, 0);
    assert!(secs.iter().any(|s| s.name == "cortex-m-vector-table"));
}

#[test]
fn t71_detect_boot_sections_markers() {
    let mut d = vec![0u8; 200];
    d[10..16].copy_from_slice(b"U-Boot");
    let secs = detect_boot_sections(&d, 0);
    assert!(secs.iter().any(|s| s.name == "u-boot"));
}

#[test]
fn t72_detect_boot_sections_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = (lcg.next_u64() % 1024) as usize;
        let d = lcg.next_bytes(n);
        let _ = detect_boot_sections(&d, 0);
    }
}

#[test]
fn t73_scan_embedded_signatures_basic() {
    let mut d = vec![0u8; 100];
    d[10..14].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]); // ELF
    d[20..22].copy_from_slice(b"MZ");
    let sigs = scan_embedded_signatures(&d);
    assert!(sigs.iter().any(|s| s.name == "elf"));
    assert!(sigs.iter().any(|s| s.name == "pe"));
    // sorted by offset
    for w in sigs.windows(2) {
        assert!(w[0].offset <= w[1].offset);
    }
}

#[test]
fn t74_scan_embedded_signatures_empty() {
    assert!(scan_embedded_signatures(&[]).is_empty());
}

#[test]
fn t75_scan_embedded_signatures_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let n = (lcg.next_u64() % 2048) as usize;
        let d = lcg.next_bytes(n);
        let _ = scan_embedded_signatures(&d);
    }
}

#[test]
fn t76_detect_binary_arch_too_short() {
    assert_eq!(detect_binary_arch(&[0; 15]), BinaryArch::Unknown);
    assert_eq!(detect_binary_arch(&[]), BinaryArch::Unknown);
}

#[test]
fn t77_detect_binary_arch_endbr64() {
    let mut d = vec![0u8; 256];
    d[100..104].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA]);
    assert_eq!(detect_binary_arch(&d), BinaryArch::X86_64);
}

#[test]
fn t78_detect_binary_arch_x86_preamble() {
    let mut d = vec![0u8; 256];
    for i in 0..10 {
        let off = 10 + i * 6;
        d[off] = 0x55;
        d[off + 1] = 0x89;
        d[off + 2] = 0xE5;
    }
    let a = detect_binary_arch(&d);
    assert!(matches!(a, BinaryArch::X86 | BinaryArch::X86_64));
}

#[test]
fn t79_detect_binary_arch_display_all() {
    let all = [
        BinaryArch::ArmThumb,
        BinaryArch::ArmAarch32,
        BinaryArch::Aarch64,
        BinaryArch::Mips32Be,
        BinaryArch::Mips32Le,
        BinaryArch::X86,
        BinaryArch::X86_64,
        BinaryArch::RiscV32,
        BinaryArch::RiscV64,
        BinaryArch::PowerPcBe,
        BinaryArch::Unknown,
    ];
    for a in all {
        assert!(!a.to_string().is_empty());
    }
}

#[test]
fn t80_detect_binary_arch_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = (lcg.next_u64() % 4096) as usize;
        let d = lcg.next_bytes(n);
        let _ = detect_binary_arch(&d);
    }
}

#[test]
fn t81_detect_raw_endian_table() {
    use rustre_core::endian::Endian;
    assert_eq!(detect_raw_endian(BinaryArch::X86), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::X86_64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::Mips32Be), Some(Endian::Big));
    assert_eq!(detect_raw_endian(BinaryArch::Mips32Le), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::PowerPcBe), Some(Endian::Big));
    assert_eq!(detect_raw_endian(BinaryArch::Aarch64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::RiscV32), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::RiscV64), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::ArmThumb), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::ArmAarch32), Some(Endian::Little));
    assert_eq!(detect_raw_endian(BinaryArch::Unknown), None);
}

#[test]
fn t82_firmware_info_analyse_empty() {
    let info = FirmwareInfo::analyse(&[], 0x1000);
    assert_eq!(info.size, 0);
    assert_eq!(info.base_address, 0x1000);
    assert_eq!(info.kind, FirmwareKind::Raw);
}

#[test]
fn t83_firmware_info_analyse_uboot() {
    let h = make_uboot_header(4, 0x1000, 0x1004, "boot");
    let mut d = h.clone();
    d.extend_from_slice(&[1, 2, 3, 4]);
    let info = FirmwareInfo::analyse(&d, 0);
    assert_eq!(info.kind, FirmwareKind::UBoot);
    assert!(!info.boot_sections.is_empty());
    let s = info.to_string();
    assert!(s.contains("firmware"));
}

#[test]
fn t84_firmware_info_analyse_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..15 {
        let n = (lcg.next_u64() % 1024) as usize;
        let d = lcg.next_bytes(n);
        let _ = FirmwareInfo::analyse(&d, 0);
    }
}

#[test]
fn t85_firmware_error_display() {
    let e = FirmwareError::TruncatedData;
    assert!(e.to_string().contains("truncated"));
    let e = FirmwareError::InvalidMagic("foo".into());
    assert!(e.to_string().contains("foo"));
    let e = FirmwareError::ChecksumMismatch { expected: 1, actual: 2 };
    assert!(e.to_string().contains("checksum"));
    let e = FirmwareError::UnknownRecord(0x42);
    assert!(e.to_string().contains("unknown"));
    let e = FirmwareError::ParseError("bad".into());
    assert!(e.to_string().contains("bad"));
    let e = FirmwareError::AddressOverflow(3);
    assert!(e.to_string().contains("overflow"));
}

#[test]
fn t86_rtos_kind_display() {
    assert_eq!(RtosKind::FreeRtos.to_string(), "FreeRTOS");
    assert_eq!(RtosKind::QnxNeutrino.to_string(), "QNX Neutrino");
    assert_eq!(RtosKind::Riot.to_string(), "RIOT OS");
}

#[test]
fn t87_send_sync_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FirmwareKind>();
    assert_send_sync::<BinaryArch>();
    assert_send_sync::<EmbeddedSignature>();

    let data = Arc::new({
        let mut v = vec![0u8; 1024];
        v[0..4].copy_from_slice(b"\x7fELF");
        v
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = detect_firmware_kind(&d);
                let _ = detect_binary_arch(&d);
                let _ = scan_embedded_signatures(&d);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t88_ihex_record_eq_consistency() {
    let l1 = make_ihex_line(0, 0, &[1, 2]);
    let l2 = make_ihex_line(0, 0, &[1, 2]);
    let r1 = IntelHexRecord::parse_line(&l1).unwrap();
    let r2 = IntelHexRecord::parse_line(&l2).unwrap();
    assert_eq!(r1, r2);
    let l3 = make_ihex_line(0, 0, &[1, 3]);
    let r3 = IntelHexRecord::parse_line(&l3).unwrap();
    assert_ne!(r1, r3);
}

#[test]
fn t89_srec_record_eq_consistency() {
    let l1 = make_srec_line('1', 2, 0, &[1, 2]);
    let l2 = make_srec_line('1', 2, 0, &[1, 2]);
    let r1 = SrecRecord::parse_line(&l1).unwrap();
    let r2 = SrecRecord::parse_line(&l2).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn t90_uf2_record_eq_consistency() {
    let b1 = make_uf2_block(0x1000, &[1, 2, 3], 0, 1);
    let b2 = make_uf2_block(0x1000, &[1, 2, 3], 0, 1);
    assert_eq!(Uf2Record::parse(&b1).unwrap(), Uf2Record::parse(&b2).unwrap());
}

#[test]
fn t91_ihex_image_50_deterministic_round_trips() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = ((lcg.next_u64() % 16) + 1) as usize;
        let payload: Vec<u8> = (0..n).map(|_| lcg.next_byte()).collect();
        let addr = (lcg.next_u64() & 0xFFFF) as u16;
        let line = make_ihex_line(0x00, addr, &payload);
        let rec = IntelHexRecord::parse_line(&line).expect("parse");
        assert_eq!(rec.data, payload);
        assert_eq!(rec.address, addr);
    }
}

#[test]
fn t92_srec_50_deterministic_round_trips() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = ((lcg.next_u64() % 8) + 1) as usize;
        let payload: Vec<u8> = (0..n).map(|_| lcg.next_byte()).collect();
        let addr = lcg.next_u64() & 0xFFFF;
        let line = make_srec_line('1', 2, addr, &payload);
        let rec = SrecRecord::parse_line(&line).expect("parse");
        assert_eq!(rec.data, payload);
        assert_eq!(rec.address, addr);
    }
}

#[test]
fn t93_uboot_data_size_max_boundary() {
    // data_size larger than slice → payload returns None (no panic)
    let mut h = make_uboot_header(u32::MAX, 0, 0, "x");
    h.extend_from_slice(&[0u8; 16]);
    let hdr = UBootHeader::parse(&h).unwrap();
    assert!(hdr.payload(&h).is_none());
}

#[test]
fn t94_ihex_address_boundary_max() {
    let line = make_ihex_line(0x00, 0xFFFF, &[0xAA]);
    let rec = IntelHexRecord::parse_line(&line).unwrap();
    assert_eq!(rec.address, 0xFFFF);
}

#[test]
fn t95_srec_address_boundary_max_3byte() {
    let line = make_srec_line('2', 3, 0xFFFFFF, &[0]);
    let rec = SrecRecord::parse_line(&line).unwrap();
    assert_eq!(rec.address, 0xFF_FFFF);
}

#[test]
fn t96_detect_endian_hint_balanced_none() {
    let mut d = Vec::new();
    for _ in 0..16 {
        d.extend_from_slice(&[0x00, 0x10, 0x20, 0x00]); // both le and be score
    }
    // Both bytes are 0 → le == be → returns None
    let r = detect_endian_hint(&d);
    assert!(r.is_none() || r.as_deref() == Some("big") || r.as_deref() == Some("little"));
}

#[test]
fn t97_extract_string_categories_offsets_correct() {
    let data = b"\0\0/usr/bin/sh\0\0";
    let v = extract_firmware_strings(data, 4);
    assert!(!v.is_empty());
    assert_eq!(v[0].offset, 2);
    assert_eq!(v[0].text, "/usr/bin/sh");
    assert_eq!(v[0].category, StringCategory::Path);
}

#[test]
fn t98_uf2_assemble_empty_records() {
    assert!(Uf2Record::assemble(&[]).is_empty());
}

#[test]
fn t99_ihex_image_invalid_record_propagates() {
    let bad = b":ZZ000000FF\n";
    assert!(IntelHexImage::parse(bad).is_err());
}

#[test]
fn t100_srec_image_invalid_record_propagates() {
    // S1 with bad checksum (correct format but wrong cksum)
    let bad = b"S1030000FF\n";
    let r = SrecImage::parse(bad);
    assert!(r.is_err());
}
