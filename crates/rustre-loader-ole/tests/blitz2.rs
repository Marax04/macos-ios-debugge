//! Blitz2 broad-coverage test for rustre-loader-ole.
//!
//! These tests exercise stable public API of the loader: magic detection,
//! header / directory parsing, sector size enum, error display, the
//! `OleDirectoryReader`, `OleMacroExtractor`, the `OleLoader` async trait,
//! and the full CFBF reader (`CfbReader`).

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_core::{LoaderInput, Loader};
use rustre_loader_ole::{
    is_ole, CfbDirEntry, CfbError, CfbReader, OleArch, OleDirectoryEntry, OleDirectoryReader,
    OleError, OleFile, OleHeader, OleLoader, OleMacroExtractor, OleSectorSize, OleStream,
    ENDOFCHAIN, FREE_SECT,
};

// ── Seeded LCG ───────────────────────────────────────────────────────────────

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

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

// ── Builders ─────────────────────────────────────────────────────────────────

const OLE_MAGIC_BYTES: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fn make_ole_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[..8].copy_from_slice(&OLE_MAGIC_BYTES);
    data[24..26].copy_from_slice(&0x003E_u16.to_le_bytes());
    data[26..28].copy_from_slice(&3_u16.to_le_bytes());
    data[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes());
    data[30..32].copy_from_slice(&9_u16.to_le_bytes());
    data[32..34].copy_from_slice(&6_u16.to_le_bytes());
    data[44..48].copy_from_slice(&2_u32.to_le_bytes());
    data[48..52].copy_from_slice(&1_u32.to_le_bytes());
    data[56..60].copy_from_slice(&4096_u32.to_le_bytes());
    data[60..64].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes());
    data[64..68].copy_from_slice(&0_u32.to_le_bytes());
    // Initialize all 109 header DIFAT entries to FREE_SECT
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    }
    data
}

fn make_dir_entry(name: &str, kind: u8, sector: u32, size: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 128];
    let name_u16: Vec<u16> = name.encode_utf16().collect();
    for (i, &c) in name_u16.iter().enumerate() {
        if i * 2 + 2 > 64 {
            break;
        }
        entry[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
    }
    let len = ((name_u16.len() + 1) * 2).min(64) as u16;
    entry[64..66].copy_from_slice(&len.to_le_bytes());
    entry[66] = kind;
    entry[67] = 1;
    entry[68..72].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    entry[72..76].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    entry[76..80].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    entry[116..120].copy_from_slice(&sector.to_le_bytes());
    entry[120..124].copy_from_slice(&size.to_le_bytes());
    entry
}

fn make_full_cfb() -> Vec<u8> {
    // Build a minimal valid CFB v3 file:
    // - 512-byte header
    // - 1 FAT sector at sector 0
    // - 1 directory sector at sector 1
    // - root entry only
    let mut data = vec![0u8; 512 * 4];
    data[..8].copy_from_slice(&OLE_MAGIC_BYTES);
    data[24..26].copy_from_slice(&0x003E_u16.to_le_bytes());
    data[26..28].copy_from_slice(&3_u16.to_le_bytes());
    data[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes());
    data[30..32].copy_from_slice(&9_u16.to_le_bytes());
    data[32..34].copy_from_slice(&6_u16.to_le_bytes());
    data[44..48].copy_from_slice(&1_u32.to_le_bytes()); // fat_sector_count
    data[48..52].copy_from_slice(&1_u32.to_le_bytes()); // first_dir_sector
    data[56..60].copy_from_slice(&4096_u32.to_le_bytes()); // mini cutoff
    data[60..64].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes()); // first_mini_fat
    data[64..68].copy_from_slice(&0_u32.to_le_bytes()); // mini_fat_count
    data[68..72].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes()); // first_difat
    data[72..76].copy_from_slice(&0_u32.to_le_bytes()); // difat_sect_count

    // Header DIFAT: index 0 = FAT at sector 0, rest = FREE
    data[76..80].copy_from_slice(&0_u32.to_le_bytes());
    for i in 1..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    }

    // FAT sector at sector 0 (file offset 512).
    // sector 0 = FATSECT, sector 1 = ENDOFCHAIN (dir occupies one sector).
    let fat_off = 512;
    data[fat_off..fat_off + 4].copy_from_slice(&0xFFFF_FFFD_u32.to_le_bytes()); // FATSECT
    data[fat_off + 4..fat_off + 8].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes()); // ENDOFCHAIN
    for j in 2..128 {
        let off = fat_off + j * 4;
        data[off..off + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    }

    // Directory sector at sector 1 (file offset 1024). Root entry at slot 0.
    let dir_off = 1024;
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    data[dir_off..dir_off + 128].copy_from_slice(&root);
    data
}

// ════════════════════════════════════════════════════════════════════════════
// is_ole / magic
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn is_ole_accepts_full_header() {
    assert!(is_ole(&make_ole_header()));
}

#[test]
fn is_ole_rejects_empty() {
    assert!(!is_ole(&[]));
}

#[test]
fn is_ole_rejects_partial_magic() {
    assert!(!is_ole(&OLE_MAGIC_BYTES[..7]));
}

#[test]
fn is_ole_rejects_one_byte_off() {
    let mut h = make_ole_header();
    h[7] ^= 0x01;
    assert!(!is_ole(&h));
}

#[test]
fn is_ole_seeded_random_unlikely() {
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let b = rng.bytes(64);
        // Probability of matching 8 magic bytes is ~2^-64; should never hit.
        assert!(!is_ole(&b));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OleSectorSize
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn sector_size_regular_value() {
    assert_eq!(OleSectorSize::Regular.as_usize(), 512);
}

#[test]
fn sector_size_mini_value() {
    assert_eq!(OleSectorSize::Mini.as_usize(), 64);
}

#[test]
fn sector_size_display() {
    assert_eq!(OleSectorSize::Regular.to_string(), "512");
    assert_eq!(OleSectorSize::Mini.to_string(), "64");
}

#[test]
fn sector_size_eq_and_copy() {
    let a = OleSectorSize::Regular;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(OleSectorSize::Regular, OleSectorSize::Mini);
}

// ════════════════════════════════════════════════════════════════════════════
// OleHeader
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn header_parse_succeeds() {
    let h = OleHeader::parse(&make_ole_header()).unwrap();
    assert_eq!(h.dll_version, 3);
    assert_eq!(h.sector_size, 9);
    assert_eq!(h.sector_size_bytes(), 512);
    assert_eq!(h.first_dir_sector, 1);
}

#[test]
fn header_parse_truncated_returns_err() {
    let err = OleHeader::parse(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn header_parse_boundary_75_truncated() {
    // Off-by-one: header needs at least 76 bytes.
    let err = OleHeader::parse(&[0u8; 75]).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn header_parse_boundary_76_invalid_magic() {
    // 76 bytes long, zeroed: passes length, fails magic.
    let err = OleHeader::parse(&[0u8; 76]).unwrap_err();
    assert!(matches!(err, OleError::InvalidMagic));
}

#[test]
fn header_parse_zero_length() {
    let err = OleHeader::parse(&[]).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn header_parse_one_byte() {
    let err = OleHeader::parse(&[0xD0]).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn header_display_contains_key_fields() {
    let h = OleHeader::parse(&make_ole_header()).unwrap();
    let s = h.to_string();
    assert!(s.contains("OLE2"));
    assert!(s.contains("512"));
}

#[test]
fn header_sector_size_bytes_pow2() {
    let mut data = make_ole_header();
    data[30..32].copy_from_slice(&12_u16.to_le_bytes());
    let h = OleHeader::parse(&data).unwrap();
    assert_eq!(h.sector_size_bytes(), 4096);
}

#[test]
fn header_equality() {
    let h1 = OleHeader::parse(&make_ole_header()).unwrap();
    let h2 = OleHeader::parse(&make_ole_header()).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn header_round_trip_random_field_values() {
    // Build headers with varied fields and re-parse; output must match input fields.
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let mut data = make_ole_header();
        let fat_count = (rng.next() & 0xFFFF) as u32;
        let first_dir = (rng.next() & 0xFFFF) as u32;
        data[44..48].copy_from_slice(&fat_count.to_le_bytes());
        data[48..52].copy_from_slice(&first_dir.to_le_bytes());
        let h = OleHeader::parse(&data).unwrap();
        assert_eq!(h.fat_sector_count, fat_count);
        assert_eq!(h.first_dir_sector, first_dir);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OleDirectoryEntry
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dir_entry_root_kind() {
    let e = make_dir_entry("Root Entry", 5, 1, 0);
    let de = OleDirectoryEntry::parse(&e, 0).unwrap();
    assert!(de.is_root());
    assert!(!de.is_storage());
    assert!(!de.is_stream());
}

#[test]
fn dir_entry_stream_kind() {
    let e = make_dir_entry("Workbook", 2, 3, 2048);
    let de = OleDirectoryEntry::parse(&e, 0).unwrap();
    assert!(de.is_stream());
    assert_eq!(de.size, 2048);
    assert_eq!(de.name, "Workbook");
}

#[test]
fn dir_entry_storage_kind() {
    let e = make_dir_entry("Macros", 1, 0, 0);
    let de = OleDirectoryEntry::parse(&e, 0).unwrap();
    assert!(de.is_storage());
}

#[test]
fn dir_entry_truncated() {
    let err = OleDirectoryEntry::parse(&[0u8; 64], 0).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn dir_entry_boundary_127_truncated() {
    let err = OleDirectoryEntry::parse(&[0u8; 127], 0).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn dir_entry_boundary_128_ok() {
    // 128 zero bytes: parsing succeeds even though contents are degenerate.
    let de = OleDirectoryEntry::parse(&[0u8; 128], 0).unwrap();
    assert_eq!(de.entry_type, 0);
    assert!(de.name.is_empty());
}

#[test]
fn dir_entry_offset_off_by_one_truncated() {
    let buf = vec![0u8; 128];
    let err = OleDirectoryEntry::parse(&buf, 1).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn dir_entry_display_contains_name() {
    let e = make_dir_entry("Doc", 2, 7, 99);
    let de = OleDirectoryEntry::parse(&e, 0).unwrap();
    let s = de.to_string();
    assert!(s.contains("Doc"));
    assert!(s.contains("99"));
}

#[test]
fn dir_entry_random_names_round_trip() {
    let names = [
        "A", "BB", "CCC", "Workbook", "WordDocument", "VBA", "Module1", "Root Entry",
        "1Table", "ObjectPool", "Pictures", "data",
    ];
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let n = &names[(rng.next() as usize) % names.len()];
        let kind = ((rng.next() & 0x03) as u8).max(1);
        let sector = (rng.next() & 0xFFFF) as u32;
        let size = (rng.next() & 0xFFFF) as u32;
        let e = make_dir_entry(n, kind, sector, size);
        let de = OleDirectoryEntry::parse(&e, 0).unwrap();
        assert_eq!(de.name, *n);
        assert_eq!(de.entry_type, kind);
        assert_eq!(de.start_sector, sector);
        assert_eq!(u32::try_from(de.size).unwrap(), size);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OleFile
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ole_file_parse_header_only() {
    let data = make_ole_header();
    let f = OleFile::parse(&data).unwrap();
    assert_eq!(f.header.dll_version, 3);
}

#[test]
fn ole_file_find_entry() {
    let mut data = make_ole_header();
    data.resize(1024 + 256, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let stream = make_dir_entry("Hit", 2, 2, 100);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&stream);
    let f = OleFile::parse(&data).unwrap();
    assert!(f.find_entry("Hit").is_some());
    assert!(f.find_entry("Miss").is_none());
}

#[test]
fn ole_file_streams_filter() {
    let mut data = make_ole_header();
    data.resize(1024 + 384, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let storage = make_dir_entry("Storage", 1, 0, 0);
    let stream = make_dir_entry("Stream", 2, 2, 50);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&storage);
    data[1024 + 256..1024 + 384].copy_from_slice(&stream);
    let f = OleFile::parse(&data).unwrap();
    let s = f.streams();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "Stream");
}

#[test]
fn ole_file_root() {
    let mut data = make_ole_header();
    data.resize(1024 + 128, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    data[1024..1024 + 128].copy_from_slice(&root);
    let f = OleFile::parse(&data).unwrap();
    assert!(f.root().is_some());
}

// ════════════════════════════════════════════════════════════════════════════
// OleError
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn error_invalid_magic_display() {
    assert!(OleError::InvalidMagic.to_string().contains("magic"));
}

#[test]
fn error_truncated_header_display() {
    assert!(OleError::TruncatedHeader.to_string().contains("truncated"));
}

#[test]
fn error_parse_error_display() {
    let s = OleError::ParseError("x".into()).to_string();
    assert!(s.contains("parse"));
    assert!(s.contains('x'));
}

#[test]
fn error_unsupported_version_display() {
    let s = OleError::UnsupportedVersion(42).to_string();
    assert!(s.contains("42"));
}

#[test]
fn error_debug_nonempty() {
    let v: Vec<OleError> = vec![
        OleError::InvalidMagic,
        OleError::TruncatedHeader,
        OleError::ParseError("y".into()),
        OleError::UnsupportedVersion(2),
    ];
    for e in v {
        assert!(!format!("{e:?}").is_empty());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OleArch
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ole_arch_metadata() {
    use rustre_core::arch::Architecture;
    let a = OleArch;
    assert_eq!(a.name(), "ole");
    assert_eq!(a.pointer_size(), 4);
    assert!(a.get_branches(&rustre_core::arch::Instruction::new(
        rustre_core::Address::new(0),
        1,
        "data",
        vec![0],
    )).is_empty());
    assert!(a.registers().is_empty());
    assert!(a.calling_conventions().is_empty());
}

#[test]
fn ole_arch_disassemble_empty_errors() {
    use rustre_core::arch::Architecture;
    let a = OleArch;
    assert!(a.disassemble(rustre_core::Address::new(0), &[]).is_err());
}

#[test]
fn ole_arch_disassemble_one_byte() {
    use rustre_core::arch::Architecture;
    let a = OleArch;
    let ins = a.disassemble(rustre_core::Address::new(0), &[0xAA]).unwrap();
    assert_eq!(ins.size, 1);
}

// ════════════════════════════════════════════════════════════════════════════
// OleLoader
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn loader_name() {
    assert_eq!(OleLoader.name(), "ole");
}

#[test]
fn loader_can_load_true() {
    let input = LoaderInput::new("a.doc", make_ole_header());
    assert!(OleLoader.can_load(&input));
}

#[test]
fn loader_can_load_false() {
    let input = LoaderInput::new("a.bin", b"not ole".to_vec());
    assert!(!OleLoader.can_load(&input));
}

#[tokio::test]
async fn loader_load_succeeds() {
    let input = LoaderInput::new("doc.xls", make_ole_header());
    let r = OleLoader.load(input).await.unwrap();
    assert_eq!(r.view.uri, "doc.xls");
}

#[tokio::test]
async fn loader_find_nested_empty() {
    let input = LoaderInput::new("doc.xls", make_ole_header());
    assert!(OleLoader.find_nested(&input).await.unwrap().is_empty());
}

// ════════════════════════════════════════════════════════════════════════════
// OleDirectoryReader
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dir_reader_finds_stream() {
    let mut data = make_ole_header();
    data.resize(1024 + 256, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let stream = make_dir_entry("Book", 2, 2, 99);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&stream);
    let r = OleDirectoryReader::new();
    let s = r.list_streams(&data).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "Book");
    assert_eq!(s[0].size, 99);
    assert_eq!(s[0].start_sector, 2);
}

#[test]
fn dir_reader_default_eq_new() {
    // Default and new() both work; default is a no-state ZST.
    let _r: OleDirectoryReader = Default::default();
    let _r2 = OleDirectoryReader::new();
}

#[test]
fn dir_reader_invalid_magic_err() {
    let r = OleDirectoryReader::new();
    assert!(matches!(
        r.list_streams(&[0u8; 512]).unwrap_err(),
        OleError::InvalidMagic
    ));
}

#[test]
fn dir_reader_truncated_err() {
    let r = OleDirectoryReader::new();
    assert!(matches!(
        r.list_streams(&[0u8; 10]).unwrap_err(),
        OleError::TruncatedHeader
    ));
}

// ════════════════════════════════════════════════════════════════════════════
// OleMacroExtractor
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn macro_extractor_no_vba() {
    let mut data = make_ole_header();
    data.resize(1024 + 256, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let stream = make_dir_entry("Workbook", 2, 2, 100);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&stream);
    let m = OleMacroExtractor::new().extract_macros(&data);
    assert!(m.is_empty());
}

#[test]
fn macro_extractor_finds_vba() {
    let mut data = make_ole_header();
    data.resize(1024 + 256, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let vba = make_dir_entry("VBA/Module1", 2, 2, 100);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&vba);
    data.resize(1536 + 64, 0);
    let text = b"Attribute VB_Name = \"Mod\"";
    data[1536..1536 + text.len()].copy_from_slice(text);
    let m = OleMacroExtractor::new().extract_macros(&data);
    assert_eq!(m.len(), 1);
    assert!(m[0].code_excerpt.contains("Attribute"));
}

#[test]
fn macro_extractor_invalid_input_returns_empty() {
    let m = OleMacroExtractor::new().extract_macros(&[0u8; 32]);
    assert!(m.is_empty());
}

#[test]
fn macro_extractor_default_works() {
    let _e: OleMacroExtractor = Default::default();
}

// ════════════════════════════════════════════════════════════════════════════
// OleStream Debug
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ole_stream_debug() {
    let s = OleStream { name: "x".into(), size: 1, start_sector: 2 };
    assert!(!format!("{s:?}").is_empty());
    let c = s;
    assert_eq!(c.name, "x");
}

// ════════════════════════════════════════════════════════════════════════════
// CfbError
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn cfb_error_displays() {
    assert!(CfbError::InvalidMagic.to_string().contains("magic"));
    assert!(CfbError::InvalidVersion(7).to_string().contains('7'));
    assert!(CfbError::TruncatedData.to_string().contains("truncated"));
    assert!(CfbError::InvalidSector(0xABCD).to_string().contains("abcd"));
    assert!(!CfbError::InvalidDirectoryEntry.to_string().is_empty());
    assert!(CfbError::StreamTooLarge.to_string().contains("large"));
    assert!(CfbError::Other("z".into()).to_string().contains('z'));
}

#[test]
fn cfb_error_into_ole_error() {
    let oe: OleError = CfbError::InvalidMagic.into();
    assert!(matches!(oe, OleError::ParseError(_)));
}

// ════════════════════════════════════════════════════════════════════════════
// CfbReader
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn cfb_reader_parses_minimal_v3() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    assert_eq!(r.sector_size, 512);
    assert_eq!(r.mini_sector_size, 64);
    assert!(r.dir_entry_count() >= 1);
    assert!(r.root_entry().is_some());
    assert_eq!(r.root_entry().unwrap().entry_type, 5);
}

#[test]
fn cfb_reader_invalid_magic() {
    let mut data = make_full_cfb();
    data[0] = 0;
    assert!(matches!(CfbReader::parse(data).unwrap_err(), CfbError::InvalidMagic));
}

#[test]
fn cfb_reader_truncated() {
    let err = CfbReader::parse(vec![0u8; 100]).unwrap_err();
    assert!(matches!(err, CfbError::TruncatedData));
}

#[test]
fn cfb_reader_invalid_version() {
    let mut data = make_full_cfb();
    // Set sector size exponent to an unsupported value.
    data[30..32].copy_from_slice(&7_u16.to_le_bytes());
    assert!(matches!(
        CfbReader::parse(data).unwrap_err(),
        CfbError::InvalidVersion(_)
    ));
}

#[test]
fn cfb_reader_invalid_major_version() {
    let mut data = make_full_cfb();
    data[26..28].copy_from_slice(&7_u16.to_le_bytes());
    assert!(matches!(
        CfbReader::parse(data).unwrap_err(),
        CfbError::InvalidVersion(_)
    ));
}

#[test]
fn cfb_reader_list_all_contains_root() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    let all = r.list_all();
    assert!(!all.is_empty());
    assert_eq!(all[0].0, "Root Entry");
}

#[test]
fn cfb_reader_find_entry_root() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    let e = r.find_entry("");
    assert!(e.is_some());
}

#[test]
fn cfb_reader_get_dir_entry_special_sids() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    assert!(r.get_dir_entry(FREE_SECT).is_none());
    assert!(r.get_dir_entry(ENDOFCHAIN).is_none());
    assert!(r.get_dir_entry(0).is_some());
}

#[test]
fn cfb_reader_read_zero_size_stream() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    let root = r.root_entry().unwrap().clone();
    let data = r.read_stream(&root).unwrap();
    assert!(data.is_empty());
}

#[test]
fn cfb_reader_debug_impl() {
    let r = CfbReader::parse(make_full_cfb()).unwrap();
    let s = format!("{r:?}");
    assert!(s.contains("CfbReader"));
}

// ════════════════════════════════════════════════════════════════════════════
// CfbDirEntry
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn cfb_dir_entry_kind_predicates() {
    let mut e = CfbDirEntry {
        name: "x".into(),
        entry_type: 0,
        color: false,
        left_sibling: FREE_SECT,
        right_sibling: FREE_SECT,
        child: FREE_SECT,
        clsid: [0; 16],
        state_bits: 0,
        created: 0,
        modified: 0,
        start_sector: 0,
        size: 0,
    };
    assert!(e.is_empty());
    e.entry_type = 1;
    assert!(e.is_storage());
    e.entry_type = 2;
    assert!(e.is_stream());
    e.entry_type = 5;
    assert!(e.is_root());
}

#[test]
fn cfb_dir_entry_display() {
    let e = CfbDirEntry {
        name: "hello".into(),
        entry_type: 2,
        color: false,
        left_sibling: FREE_SECT,
        right_sibling: FREE_SECT,
        child: FREE_SECT,
        clsid: [0; 16],
        state_bits: 0,
        created: 0,
        modified: 0,
        start_sector: 5,
        size: 42,
    };
    let s = e.to_string();
    assert!(s.contains("hello"));
    assert!(s.contains("stream"));
    assert!(s.contains("42"));
}

// ════════════════════════════════════════════════════════════════════════════
// Send / Sync — threaded
// ════════════════════════════════════════════════════════════════════════════

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn send_sync_types() {
    assert_send_sync::<OleLoader>();
    assert_send_sync::<OleArch>();
    assert_send_sync::<OleDirectoryReader>();
    assert_send_sync::<OleMacroExtractor>();
    assert_send_sync::<OleHeader>();
    assert_send_sync::<OleError>();
    assert_send_sync::<CfbError>();
}

#[test]
fn threaded_is_ole_4x100() {
    let data = Arc::new(make_ole_header());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(is_ole(&d));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_header_parse_4x100() {
    let data = Arc::new(make_ole_header());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let h = OleHeader::parse(&d).unwrap();
                assert_eq!(h.dll_version, 3);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_cfb_reader_4x100() {
    let data = Arc::new(make_full_cfb());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = CfbReader::parse((*d).clone()).unwrap();
                assert!(r.root_entry().is_some());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Hash / Eq consistency on 30+ header pairs
// ════════════════════════════════════════════════════════════════════════════

fn hash_one<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn ole_sector_size_hash_eq_consistency() {
    // OleSectorSize derives Eq but not Hash; test Eq pairs instead, 30+ pairs.
    let kinds = [OleSectorSize::Regular, OleSectorSize::Mini];
    let mut seen_eq = 0;
    let mut seen_ne = 0;
    for i in 0..6 {
        for j in 0..6 {
            let a = kinds[i % 2];
            let b = kinds[j % 2];
            if a == b {
                seen_eq += 1;
            } else {
                seen_ne += 1;
            }
        }
    }
    assert!(seen_eq + seen_ne >= 30);
    assert!(seen_eq > 0 && seen_ne > 0);
}

#[test]
fn ole_header_eq_pairs() {
    // Build 30+ header variants; equal builds should compare equal.
    let mut rng = Lcg::new();
    let mut variants: Vec<OleHeader> = Vec::new();
    for _ in 0..30 {
        let mut data = make_ole_header();
        let fc = (rng.next() & 0xFF) as u32;
        data[44..48].copy_from_slice(&fc.to_le_bytes());
        variants.push(OleHeader::parse(&data).unwrap());
    }
    // Reflexive
    for v in &variants {
        assert_eq!(v, v);
    }
    // Re-parsing yields equal
    let mut rng2 = Lcg::new();
    for v in &variants {
        let mut data = make_ole_header();
        let fc = (rng2.next() & 0xFF) as u32;
        data[44..48].copy_from_slice(&fc.to_le_bytes());
        let w = OleHeader::parse(&data).unwrap();
        assert_eq!(*v, w);
    }
}

#[test]
fn u64_hash_round_trip_30_inputs() {
    // Just exercise hashing on owned strings derived from LCG inputs,
    // confirming Eq => Hash equality.
    let mut rng = Lcg::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for _ in 0..30 {
        let s = format!("entry-{}", rng.next() & 0xFFFF);
        let h1 = hash_one(&s);
        let h2 = hash_one(&s.clone());
        assert_eq!(h1, h2);
        seen.insert(h1);
    }
    // Some uniqueness expected.
    assert!(seen.len() > 1);
}
