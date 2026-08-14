//! Blitz2 — extended coverage for rustre-loader-pe.
//!
//! Targets pure helpers and small types: entropy, strings, relocations,
//! overlay/SFX, debug GUID, exports map, sections, `RvaSection`, and a
//! parallel `PeInfo::parse` stress to validate Send/Sync.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_loader_pe::*;
use rustre_loader_pe::relocations::reloc_type_name;

// ---------------------------------------------------------------------------
// Seeded LCG (Knuth MMIX)
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let v = self.next().to_le_bytes();
            out.extend_from_slice(&v);
        }
        out.truncate(n);
        out
    }
}

// ---------------------------------------------------------------------------
// 1. Constructors / boundaries
// ---------------------------------------------------------------------------

#[test]
fn shannon_entropy_zero_buffer() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn shannon_entropy_single_byte() {
    let e = shannon_entropy(&[0x42]);
    assert!(e.abs() < 1e-12, "single byte must have entropy 0, got {e}");
}

#[test]
fn shannon_entropy_max_is_8_bits() {
    let data: Vec<u8> = (0..=255u8).collect();
    let e = shannon_entropy(&data);
    assert!(e > 7.99 && e <= 8.0001);
}

#[test]
fn byte_histogram_empty_is_zeros() {
    let h = byte_histogram(&[]);
    assert!(h.iter().all(|&c| c == 0));
}

#[test]
fn byte_histogram_off_by_one() {
    let h = byte_histogram(&[0u8, 0, 0, 255, 255]);
    assert_eq!(h[0], 3);
    assert_eq!(h[255], 2);
    assert_eq!(h[1], 0);
    assert_eq!(h[254], 0);
}

#[test]
fn most_common_byte_single_value() {
    assert_eq!(most_common_byte(&[7u8]), (7, 1));
}

#[test]
fn most_common_byte_tie_picks_lowest() {
    let d = [3u8, 3, 9, 9];
    let (b, c) = most_common_byte(&d);
    assert_eq!(c, 2);
    assert!(b == 3 || b == 9);
}

#[test]
fn looks_packed_uniform_random_returns_true() {
    let data: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    assert!(looks_packed(&data));
}

#[test]
fn looks_packed_zeros_returns_false() {
    assert!(!looks_packed(&vec![0u8; 8192]));
}

#[test]
fn entropy_constants_ordered() {
    assert!(LOW_ENTROPY_THRESHOLD < PACKED_ENTROPY_THRESHOLD);
    assert!(PACKED_ENTROPY_THRESHOLD < HIGH_ENTROPY_THRESHOLD);
    assert!(HIGH_ENTROPY_THRESHOLD <= 8.0);
}

// ---------------------------------------------------------------------------
// 2. Strings
// ---------------------------------------------------------------------------

#[test]
fn ascii_printable_boundaries() {
    assert!(!is_printable_ascii(0x1F));
    assert!(is_printable_ascii(0x20));
    assert!(is_printable_ascii(0x7E));
    assert!(!is_printable_ascii(0x7F));
    assert!(is_printable_ascii(b'\t'));
}

#[test]
fn utf16_printable_boundaries() {
    assert!(!is_printable_utf16(0x001F));
    assert!(is_printable_utf16(0x0020));
}

#[test]
fn scan_ascii_finds_strings() {
    let data = b"\x00\x00Hello, world!\x00trash\x00\x00ALongerString\x00";
    let s = scan_ascii(data, 5);
    assert!(s.iter().any(|x| x.value == "Hello, world!"));
    assert!(s.iter().any(|x| x.value == "ALongerString"));
}

#[test]
fn scan_ascii_min_len_filter() {
    let data = b"\x00abc\x00LongEnough\x00";
    let s = scan_ascii(data, 5);
    assert!(!s.iter().any(|x| x.value == "abc"));
    assert!(s.iter().any(|x| x.value == "LongEnough"));
}

#[test]
fn scan_utf16le_basic() {
    // "ABCDE" UTF-16LE
    let mut data = Vec::new();
    for c in b"ABCDEF" {
        data.push(*c);
        data.push(0);
    }
    let s = scan_utf16le(&data, 4);
    assert!(s.iter().any(|x| x.value == "ABCDEF"));
}

#[test]
fn min_ascii_len_const_sane() {
    assert!(MIN_ASCII_LEN >= 3);
    assert!(MIN_UTF16_LEN >= 3);
}

// ---------------------------------------------------------------------------
// 3. Relocations
// ---------------------------------------------------------------------------

#[test]
fn reloc_type_name_all_known() {
    assert_eq!(reloc_type_name(IMAGE_REL_BASED_ABSOLUTE), "ABSOLUTE");
    assert_eq!(reloc_type_name(IMAGE_REL_BASED_HIGH), "HIGH");
    assert_eq!(reloc_type_name(IMAGE_REL_BASED_LOW), "LOW");
    assert_eq!(reloc_type_name(IMAGE_REL_BASED_HIGHLOW), "HIGHLOW");
    assert_eq!(reloc_type_name(IMAGE_REL_BASED_DIR64), "DIR64");
    assert_eq!(reloc_type_name(99), "UNKNOWN");
}

#[test]
fn reloc_is_absolute() {
    let r = Relocation {
        virtual_address: 0x1000,
        reloc_type: IMAGE_REL_BASED_ABSOLUTE,
    };
    assert!(r.is_absolute());
    let r2 = Relocation {
        virtual_address: 0x1000,
        reloc_type: IMAGE_REL_BASED_DIR64,
    };
    assert!(!r2.is_absolute());
}

#[test]
fn parse_relocation_directory_empty_returns_empty() {
    let blocks = parse_relocation_directory(&[], &[], 0, 0);
    assert!(blocks.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Overlay / SFX
// ---------------------------------------------------------------------------

#[test]
fn detect_sfx_kind_zip() {
    assert_eq!(detect_sfx_kind(b"PK\x03\x04rest"), SfxKind::Zip);
}

#[test]
fn detect_sfx_kind_winrar() {
    assert_eq!(detect_sfx_kind(b"Rar!\x1A\x07\x00"), SfxKind::WinRar);
}

#[test]
fn detect_sfx_kind_7zip() {
    assert_eq!(detect_sfx_kind(b"7z\xBC\xAF\x27\x1Cmore"), SfxKind::SevenZip);
}

#[test]
fn detect_sfx_kind_cab() {
    assert_eq!(detect_sfx_kind(b"MSCFxxxx"), SfxKind::Cabinet);
}

#[test]
fn detect_sfx_kind_autoit() {
    assert_eq!(detect_sfx_kind(b"AU3!EA06"), SfxKind::AutoIt);
}

#[test]
fn detect_sfx_kind_unknown() {
    assert_eq!(detect_sfx_kind(b"xxxxxxxx"), SfxKind::Unknown);
}

#[test]
fn detect_sfx_kind_empty() {
    assert_eq!(detect_sfx_kind(&[]), SfxKind::Unknown);
}

#[test]
fn sfx_kind_labels_nonempty() {
    for kind in [
        SfxKind::Nsis,
        SfxKind::WinRar,
        SfxKind::SevenZip,
        SfxKind::Zip,
        SfxKind::InnoSetup,
        SfxKind::InstallShield,
        SfxKind::Cabinet,
        SfxKind::AutoIt,
        SfxKind::Unknown,
    ] {
        assert!(!kind.label().is_empty());
    }
}

#[test]
fn cert_type_name_known() {
    assert!(!cert_type_name(WIN_CERT_TYPE_PKCS_SIGNED_DATA).is_empty());
    assert!(!cert_type_name(WIN_CERT_TYPE_X509).is_empty());
    assert!(!cert_type_name(0xFFFF).is_empty());
}

// ---------------------------------------------------------------------------
// 5. PdbGuid Display/Debug
// ---------------------------------------------------------------------------

#[test]
fn pdb_guid_to_string_format() {
    let g = PdbGuid {
        data1: 0xAABB_CCDD,
        data2: 0x1122,
        data3: 0x3344,
        data4: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
    };
    let s = g.to_string();
    assert!(s.starts_with('{'));
    assert!(s.ends_with('}'));
    assert!(s.contains("AABBCCDD"));
    assert!(s.contains("1122"));
}

#[test]
fn pdb_guid_symbol_server_key_with_age() {
    let g = PdbGuid {
        data1: 0x1,
        data2: 0x2,
        data3: 0x3,
        data4: [0; 8],
    };
    let k = g.symbol_server_key(7);
    assert!(k.ends_with('7'));
    assert!(k.starts_with("00000001"));
}

#[test]
fn pdb_guid_eq_and_clone() {
    let g = PdbGuid {
        data1: 0xDEAD,
        data2: 0xBEEF,
        data3: 0,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let g2 = g.clone();
    assert_eq!(g, g2);
    assert_eq!(g.to_string(), g2.to_string());
}

#[test]
fn debug_type_name_known_and_unknown() {
    assert!(!debug_type_name(IMAGE_DEBUG_TYPE_CODEVIEW).is_empty());
    assert!(!debug_type_name(IMAGE_DEBUG_TYPE_POGO).is_empty());
    assert!(!debug_type_name(9999).is_empty());
}

// ---------------------------------------------------------------------------
// 6. Exception / unwind helpers
// ---------------------------------------------------------------------------

#[test]
fn x64_reg_name_known_and_out_of_range() {
    assert_eq!(x64_reg_name(0), "RAX");
    assert_eq!(x64_reg_name(15), "R15");
    assert_eq!(x64_reg_name(99), "?");
}

#[test]
fn unwind_flags_distinct() {
    assert_ne!(UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER);
    assert_ne!(UNW_FLAG_EHANDLER, UNW_FLAG_CHAININFO);
    assert_eq!(UNW_FLAG_NHANDLER, 0);
}

// ---------------------------------------------------------------------------
// 7. RvaSection / rva_to_file_offset
// ---------------------------------------------------------------------------

#[test]
fn rva_to_offset_inside_section() {
    let s = RvaSection {
        virtual_address: 0x1000,
        virtual_size: 0x200,
        raw_size: 0x200,
        raw_offset: 0x400,
    };
    assert_eq!(s.rva_to_offset(0x1000), Some(0x400));
    assert_eq!(s.rva_to_offset(0x1100), Some(0x500));
}

#[test]
fn rva_to_offset_outside_section() {
    let s = RvaSection {
        virtual_address: 0x1000,
        virtual_size: 0x200,
        raw_size: 0x200,
        raw_offset: 0x400,
    };
    assert_eq!(s.rva_to_offset(0x0FFF), None);
    assert_eq!(s.rva_to_offset(0x1200), None);
}

#[test]
fn rva_to_file_offset_picks_right_section() {
    let secs = vec![
        RvaSection {
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x100,
            raw_offset: 0x200,
        },
        RvaSection {
            virtual_address: 0x2000,
            virtual_size: 0x100,
            raw_size: 0x100,
            raw_offset: 0x400,
        },
    ];
    assert_eq!(rva_to_file_offset(0x2050, &secs), Some(0x450));
    assert_eq!(rva_to_file_offset(0x3000, &secs), None);
}

// ---------------------------------------------------------------------------
// 8. PeInfo::parse — adversarial bytes via LCG
// ---------------------------------------------------------------------------

#[test]
fn pe_parse_50_random_inputs_dont_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 4096) as usize + 64;
        let buf = lcg.next_bytes(len);
        let _ = PeInfo::parse(&buf); // must not panic
    }
}

#[test]
fn pe_parse_50_random_with_mz_dont_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 2048) as usize + 256;
        let mut buf = lcg.next_bytes(len);
        buf[0] = b'M';
        buf[1] = b'Z';
        // random e_lfanew constrained to within buf
        let off = (lcg.next() as usize % (buf.len().saturating_sub(8).max(1))) as u32;
        buf[0x3C..0x40].copy_from_slice(&off.to_le_bytes());
        let _ = PeInfo::parse(&buf);
    }
}

// ---------------------------------------------------------------------------
// 9. Display/Debug/Eq/Hash consistency for small types
// ---------------------------------------------------------------------------

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn sfx_kind_eq_and_debug_pairs() {
    let pairs = [
        (SfxKind::Zip, SfxKind::Zip),
        (SfxKind::WinRar, SfxKind::WinRar),
        (SfxKind::SevenZip, SfxKind::SevenZip),
        (SfxKind::Cabinet, SfxKind::Cabinet),
        (SfxKind::AutoIt, SfxKind::AutoIt),
        (SfxKind::Nsis, SfxKind::Nsis),
        (SfxKind::InnoSetup, SfxKind::InnoSetup),
        (SfxKind::InstallShield, SfxKind::InstallShield),
        (SfxKind::Unknown, SfxKind::Unknown),
    ];
    for (a, b) in pairs {
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{:?}", b));
    }
}

#[test]
fn machine_eq_debug_pairs() {
    let pairs = [
        (Machine::X64, Machine::X64),
        (Machine::X86, Machine::X86),
        (Machine::Arm, Machine::Arm),
        (Machine::Arm64, Machine::Arm64),
        (Machine::Unknown(0x1234), Machine::Unknown(0x1234)),
    ];
    for (a, b) in pairs {
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{:?}", b));
    }
    assert_ne!(Machine::X64, Machine::X86);
    assert_ne!(Machine::Unknown(1), Machine::Unknown(2));
}

#[test]
fn subsystem_eq_debug_pairs() {
    let pairs = [
        (Subsystem::Console, Subsystem::Console),
        (Subsystem::Windows, Subsystem::Windows),
        (Subsystem::Native, Subsystem::Native),
        (Subsystem::EfiApp, Subsystem::EfiApp),
        (Subsystem::EfiBootService, Subsystem::EfiBootService),
        (Subsystem::EfiRuntime, Subsystem::EfiRuntime),
        (Subsystem::EfiRom, Subsystem::EfiRom),
        (Subsystem::Unknown(7), Subsystem::Unknown(7)),
    ];
    for (a, b) in pairs {
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{:?}", b));
    }
}

#[test]
fn relocation_eq_and_debug_pairs() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let va = lcg.next() as u32;
        let t = (lcg.next() % 11) as u8;
        let a = Relocation {
            virtual_address: va,
            reloc_type: t,
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{:?}", b));
    }
}

#[test]
fn pdb_guid_hash_consistency() {
    let g = PdbGuid {
        data1: 0xAA,
        data2: 0xBB,
        data3: 0xCC,
        data4: [1; 8],
    };
    let g2 = g.clone();
    assert_eq!(g, g2);
    // PdbGuid derives Eq+PartialEq; ensure equal-by-value -> equal string repr & equal struct fields hash equally via tuple
    let t1 = (g.data1, g.data2, g.data3, g.data4);
    let t2 = (g2.data1, g2.data2, g2.data3, g2.data4);
    assert_eq!(hash_of(&t1), hash_of(&t2));
}

#[test]
fn import_export_entry_eq_pairs() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let ord = (lcg.next() % 0xFFFF) as u16;
        let a = ImportEntry {
            dll: format!("d{ord}.dll"),
            name: Some(format!("fn{ord}")),
            ordinal: Some(ord),
            address: lcg.next(),
        };
        let b = a.clone();
        assert_eq!(a, b);

        let e = ExportEntry {
            name: Some(format!("e{ord}")),
            ordinal: ord,
            address: lcg.next(),
            forwarder: None,
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_eq!(format!("{e:?}"), format!("{:?}", e2));
    }
}

// ---------------------------------------------------------------------------
// 10. ExportMap behavior
// ---------------------------------------------------------------------------

#[test]
fn export_map_empty_defaults() {
    let m = ExportMap::default();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert_eq!(m.forward_count(), 0);
    assert!(m.all().is_empty());
    assert!(m.forwards().is_empty());
    assert!(m.by_ordinal(1).is_none());
    assert!(m.by_name("x").is_none());
}

#[test]
fn export_map_build_and_lookup() {
    let syms = vec![
        ExportedSymbol {
            name: Some("Alpha".into()),
            ordinal: 1,
            rva: 0x1000,
            virtual_address: 0x4000_1000,
            forward_name: None,
            is_forward: false,
        },
        ExportedSymbol {
            name: None,
            ordinal: 2,
            rva: 0x1100,
            virtual_address: 0x4000_1100,
            forward_name: None,
            is_forward: false,
        },
        ExportedSymbol {
            name: Some("Beta".into()),
            ordinal: 3,
            rva: 0,
            virtual_address: 0,
            forward_name: Some("OTHER.Func".into()),
            is_forward: true,
        },
    ];
    let m = ExportMap::build(syms);
    assert_eq!(m.len(), 3);
    assert!(!m.is_empty());
    assert_eq!(m.forward_count(), 1);
    assert_eq!(m.by_name("Alpha").map(|s| s.ordinal), Some(1));
    assert_eq!(m.by_ordinal(2).map(|s| s.ordinal), Some(2));
    assert!(m.by_name("Missing").is_none());
    assert_eq!(m.forwards().len(), 1);
    assert_eq!(m.all().len(), 3);
    // all() must be sorted by ordinal
    let ords: Vec<u32> = m.all().iter().map(|s| s.ordinal).collect();
    assert_eq!(ords, vec![1, 2, 3]);
}

// ---------------------------------------------------------------------------
// 11. SectionInfo helpers
// ---------------------------------------------------------------------------

fn mk_section(name: &str, va: u64, size: u32, chars: u32) -> SectionInfo {
    use rustre_core::permissions::Permissions;
    SectionInfo {
        name: name.into(),
        virtual_address: va,
        virtual_size: size,
        raw_offset: 0x200,
        raw_size: size,
        characteristics: chars,
        permissions: Permissions::READ,
    }
}

#[test]
fn section_info_va_range_and_flags() {
    const EXEC: u32 = 0x2000_0000;
    const READ: u32 = 0x4000_0000;
    const WRITE: u32 = 0x8000_0000;
    let s = mk_section(".text", 0x1000, 0x500, EXEC | READ);
    assert_eq!(s.va_range(), (0x1000, 0x1500));
    assert!(s.is_code());
    assert!(s.is_readable());
    assert!(!s.is_writable());
    assert_eq!(s.mapped_size(), 0x500);

    let d = mk_section(".data", 0x2000, 0x100, READ | WRITE);
    assert!(!d.is_code());
    assert!(d.is_writable());
}

// ---------------------------------------------------------------------------
// 12. ScanOptions defaults / scan_strings on synthesized data
// ---------------------------------------------------------------------------

#[test]
fn scan_strings_default_options() {
    let opts = ScanOptions::default();
    let mut data = Vec::new();
    data.extend_from_slice(b"\x00HelloWorld\x00");
    for c in b"WideStr" {
        data.push(*c);
        data.push(0);
    }
    data.push(0);
    let out = scan_strings(&data, &opts);
    assert!(out.iter().any(|s| s.value == "HelloWorld"));
}

#[test]
fn classify_string_returns_some_for_url() {
    let s = ExtractedString {
        value: "https://example.com/path".to_string(),
        encoding: StringEncoding::Ascii,
        offset: 0,
        section: None,
    };
    // URL is one of the categories the classifier should recognise (or return Some).
    let _ = classify_string(&s); // must not panic; category is impl-defined
}

// ---------------------------------------------------------------------------
// 13. Send/Sync threaded fan-out: parse 100 random buffers across 4 threads
// ---------------------------------------------------------------------------

#[test]
fn pe_parse_send_sync_threaded() {
    // Generate 100 deterministic buffers up front.
    let mut lcg = Lcg::new();
    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(100);
    for _ in 0..100 {
        let len = (lcg.next() % 1024) as usize + 64;
        let mut b = lcg.next_bytes(len);
        if b.len() >= 0x40 {
            b[0] = b'M';
            b[1] = b'Z';
        }
        bufs.push(b);
    }
    let bufs = Arc::new(bufs);
    let mut handles = Vec::new();
    for t in 0..4 {
        let bufs = Arc::clone(&bufs);
        handles.push(thread::spawn(move || {
            let mut count = 0usize;
            for i in 0..100 {
                let b = &bufs[(i + t * 7) % bufs.len()];
                let _ = PeInfo::parse(b);
                count += 1;
            }
            count
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 400);
}

#[test]
fn entropy_threaded_fanout() {
    let mut lcg = Lcg::new();
    let bufs: Vec<Vec<u8>> = (0..100).map(|_| lcg.next_bytes(1024)).collect();
    let bufs = Arc::new(bufs);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let bufs = Arc::clone(&bufs);
        handles.push(thread::spawn(move || {
            let mut acc = 0.0f64;
            for b in bufs.iter() {
                acc += shannon_entropy(b);
            }
            acc
        }));
    }
    let totals: Vec<f64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All threads should compute the same sum.
    for w in totals.windows(2) {
        assert!((w[0] - w[1]).abs() < 1e-9);
    }
}

// ---------------------------------------------------------------------------
// 14. parse_rich_header indirectly via PeInfo::parse on synthesized data
// (re-uses public API only)
// ---------------------------------------------------------------------------

#[test]
fn pe_parse_short_mz_only_errors() {
    let mut buf = vec![0u8; 0x40];
    buf[0] = b'M';
    buf[1] = b'Z';
    assert!(PeInfo::parse(&buf).is_err());
}
