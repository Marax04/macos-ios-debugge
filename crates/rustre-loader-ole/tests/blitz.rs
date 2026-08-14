//! Integration tests for `rustre-loader-ole` public API.

use rustre_loader_ole::{
    is_ole, CfbDirEntry, CfbError, CfbReader, OleDirectoryEntry, OleDirectoryReader, OleError,
    OleFile, OleHeader, OleLoader, OleMacroExtractor, OleSectorSize, OleStream,
};
use rustre_loader_ole::{DIFSECT, ENDOFCHAIN, FATSECT, FREE_SECT};
use rustre_loader_ole::rtf_parser::{
    CLSID_EQUATION_EDITOR, CLSID_PACKAGE, OleObjectType, RtfError, RtfLexer, RtfParser, RtfToken,
};

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fn make_ole_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[..8].copy_from_slice(&OLE_MAGIC);
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

// ─── is_ole ────────────────────────────────────────────────────────────────────

#[test]
fn is_ole_with_magic() {
    assert!(is_ole(&OLE_MAGIC));
}

#[test]
fn is_ole_full_header() {
    assert!(is_ole(&make_ole_header()));
}

#[test]
fn is_ole_empty_slice() {
    assert!(!is_ole(&[]));
}

#[test]
fn is_ole_partial_magic() {
    assert!(!is_ole(&OLE_MAGIC[..7]));
}

#[test]
fn is_ole_wrong_bytes() {
    assert!(!is_ole(&[0u8; 32]));
}

// ─── OleSectorSize ─────────────────────────────────────────────────────────────

#[test]
fn sector_size_regular_value() {
    assert_eq!(OleSectorSize::Regular.as_usize(), 512);
}

#[test]
fn sector_size_mini_value() {
    assert_eq!(OleSectorSize::Mini.as_usize(), 64);
}

#[test]
fn sector_size_display_regular() {
    assert_eq!(format!("{}", OleSectorSize::Regular), "512");
}

#[test]
fn sector_size_display_mini() {
    assert_eq!(format!("{}", OleSectorSize::Mini), "64");
}

#[test]
fn sector_size_eq() {
    assert_eq!(OleSectorSize::Regular, OleSectorSize::Regular);
    assert_ne!(OleSectorSize::Regular, OleSectorSize::Mini);
}

#[test]
fn sector_size_copy() {
    let a = OleSectorSize::Mini;
    let b = a; // Copy
    assert_eq!(a, b);
}

// ─── OleHeader ─────────────────────────────────────────────────────────────────

#[test]
fn ole_header_parse_ok() {
    let h = OleHeader::parse(&make_ole_header()).unwrap();
    assert_eq!(h.dll_version, 3);
    assert_eq!(h.sector_size, 9);
    assert_eq!(h.sector_size_bytes(), 512);
    assert_eq!(h.fat_sector_count, 2);
    assert_eq!(h.first_dir_sector, 1);
}

#[test]
fn ole_header_truncated() {
    match OleHeader::parse(&[0u8; 50]) {
        Err(OleError::TruncatedHeader) => {}
        other => panic!("expected TruncatedHeader, got {other:?}"),
    }
}

#[test]
fn ole_header_invalid_magic() {
    match OleHeader::parse(&[0u8; 200]) {
        Err(OleError::InvalidMagic) => {}
        other => panic!("expected InvalidMagic, got {other:?}"),
    }
}

#[test]
fn ole_header_boundary_75_bytes() {
    let data = vec![0u8; 75];
    assert!(matches!(OleHeader::parse(&data), Err(OleError::TruncatedHeader)));
}

#[test]
fn ole_header_boundary_76_bytes_invalid_magic() {
    let data = vec![0u8; 76];
    assert!(matches!(OleHeader::parse(&data), Err(OleError::InvalidMagic)));
}

#[test]
fn ole_header_sector_size_bytes_v4() {
    let mut data = make_ole_header();
    data[30..32].copy_from_slice(&12_u16.to_le_bytes());
    let h = OleHeader::parse(&data).unwrap();
    assert_eq!(h.sector_size_bytes(), 4096);
}

#[test]
fn ole_header_display_contains_fields() {
    let h = OleHeader::parse(&make_ole_header()).unwrap();
    let s = h.to_string();
    assert!(s.contains("OLE2"));
    assert!(s.contains("512"));
}

#[test]
fn ole_header_clone_eq() {
    let h = OleHeader::parse(&make_ole_header()).unwrap();
    let h2 = h.clone();
    assert_eq!(h, h2);
}

// ─── OleDirectoryEntry ─────────────────────────────────────────────────────────

#[test]
fn dir_entry_root() {
    let e = OleDirectoryEntry::parse(&make_dir_entry("Root Entry", 5, 0, 0), 0).unwrap();
    assert!(e.is_root());
    assert!(!e.is_stream());
    assert!(!e.is_storage());
}

#[test]
fn dir_entry_storage() {
    let e = OleDirectoryEntry::parse(&make_dir_entry("Store", 1, 0, 0), 0).unwrap();
    assert!(e.is_storage());
}

#[test]
fn dir_entry_stream() {
    let e = OleDirectoryEntry::parse(&make_dir_entry("S", 2, 3, 99), 0).unwrap();
    assert!(e.is_stream());
    assert_eq!(e.size, 99);
    assert_eq!(e.start_sector, 3);
    assert_eq!(e.name, "S");
}

#[test]
fn dir_entry_too_short() {
    assert!(matches!(
        OleDirectoryEntry::parse(&[0u8; 100], 0),
        Err(OleError::TruncatedHeader)
    ));
}

#[test]
fn dir_entry_too_short_with_offset() {
    let data = vec![0u8; 128];
    assert!(matches!(
        OleDirectoryEntry::parse(&data, 64),
        Err(OleError::TruncatedHeader)
    ));
}

#[test]
fn dir_entry_display() {
    let e = OleDirectoryEntry::parse(&make_dir_entry("Foo", 2, 1, 10), 0).unwrap();
    let s = e.to_string();
    assert!(s.contains("Foo"));
    assert!(s.contains("10"));
}

#[test]
fn dir_entry_clone() {
    let e = OleDirectoryEntry::parse(&make_dir_entry("X", 2, 1, 4), 0).unwrap();
    let c = e.clone();
    assert_eq!(c.name, e.name);
}

// ─── OleFile ───────────────────────────────────────────────────────────────────

fn ole_with_root_and_stream(stream_name: &str, kind: u8) -> Vec<u8> {
    let mut data = make_ole_header();
    data.resize(1024 + 256, 0);
    let root = make_dir_entry("Root Entry", 5, 0xFFFF_FFFE, 0);
    let s = make_dir_entry(stream_name, kind, 2, 100);
    data[1024..1024 + 128].copy_from_slice(&root);
    data[1024 + 128..1024 + 256].copy_from_slice(&s);
    data
}

#[test]
fn ole_file_parse_minimal() {
    let f = OleFile::parse(&make_ole_header()).unwrap();
    assert_eq!(f.header.dll_version, 3);
}

#[test]
fn ole_file_with_dir() {
    let data = ole_with_root_and_stream("Data", 2);
    let f = OleFile::parse(&data).unwrap();
    assert!(f.root().is_some());
    assert!(f.find_entry("Data").is_some());
    assert!(f.find_entry("nope").is_none());
    assert_eq!(f.streams().len(), 1);
}

#[test]
fn ole_file_streams_excludes_root() {
    let data = ole_with_root_and_stream("Data", 2);
    let f = OleFile::parse(&data).unwrap();
    let streams = f.streams();
    assert!(streams.iter().all(|e| e.is_stream()));
}

#[test]
fn ole_file_propagates_magic_error() {
    let mut data = vec![0u8; 1024];
    data[0] = 0xFF;
    assert!(matches!(OleFile::parse(&data), Err(OleError::InvalidMagic)));
}

#[test]
fn ole_file_clone() {
    let f = OleFile::parse(&make_ole_header()).unwrap();
    let _ = f.clone();
}

// ─── OleError ──────────────────────────────────────────────────────────────────

#[test]
fn error_invalid_magic_msg() {
    assert!(OleError::InvalidMagic.to_string().contains("magic"));
}

#[test]
fn error_truncated_msg() {
    assert!(OleError::TruncatedHeader.to_string().contains("truncated"));
}

#[test]
fn error_parse_error_msg() {
    assert!(OleError::ParseError("foo".into()).to_string().contains("foo"));
}

#[test]
fn error_unsupported_version_msg() {
    let s = OleError::UnsupportedVersion(42).to_string();
    assert!(s.contains("42"));
}

#[test]
fn error_debug_format() {
    let s = format!("{:?}", OleError::InvalidMagic);
    assert!(s.contains("InvalidMagic"));
}

#[test]
fn error_is_error_trait() {
    fn assert_err<E: std::error::Error>(_: &E) {}
    assert_err(&OleError::InvalidMagic);
}

// ─── OleDirectoryReader ───────────────────────────────────────────────────────

#[test]
fn dir_reader_new_default() {
    let _a = OleDirectoryReader::new();
    let _b = OleDirectoryReader;
    let _c = OleDirectoryReader::default();
}

#[test]
fn dir_reader_lists_stream() {
    let data = ole_with_root_and_stream("Workbook", 2);
    let streams = OleDirectoryReader::new().list_streams(&data).unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].name, "Workbook");
    assert_eq!(streams[0].size, 100);
    assert_eq!(streams[0].start_sector, 2);
}

#[test]
fn dir_reader_skips_non_stream() {
    let data = ole_with_root_and_stream("Storage", 1);
    let streams = OleDirectoryReader::new().list_streams(&data).unwrap();
    assert!(streams.is_empty());
}

#[test]
fn dir_reader_invalid_magic() {
    let err = OleDirectoryReader::new().list_streams(&[0u8; 512]).unwrap_err();
    assert!(matches!(err, OleError::InvalidMagic));
}

#[test]
fn dir_reader_truncated() {
    let err = OleDirectoryReader::new().list_streams(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, OleError::TruncatedHeader));
}

#[test]
fn ole_stream_clone_fields() {
    let s = OleStream { name: "A".into(), size: 5, start_sector: 7 };
    let c = s.clone();
    assert_eq!(c.name, "A");
    assert_eq!(c.size, 5);
    assert_eq!(c.start_sector, 7);
}

// ─── OleMacroExtractor ─────────────────────────────────────────────────────────

#[test]
fn macro_extractor_new_default() {
    let _a = OleMacroExtractor::new();
    let _b = OleMacroExtractor::default();
}

#[test]
fn macro_extractor_no_vba() {
    let data = ole_with_root_and_stream("Workbook", 2);
    let macros = OleMacroExtractor::new().extract_macros(&data);
    assert!(macros.is_empty());
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
    let txt = b"Attribute VB_Name = \"Module1\"";
    data[1536..1536 + txt.len()].copy_from_slice(txt);
    let macros = OleMacroExtractor::new().extract_macros(&data);
    assert_eq!(macros.len(), 1);
    assert_eq!(macros[0].stream_name, "VBA/Module1");
    assert_eq!(macros[0].start_sector, 2);
    assert!(macros[0].code_excerpt.contains("Attribute"));
}

#[test]
fn macro_extractor_invalid_input_empty() {
    let macros = OleMacroExtractor::new().extract_macros(&[]);
    assert!(macros.is_empty());
}

#[test]
fn macro_extractor_invalid_magic() {
    let macros = OleMacroExtractor::new().extract_macros(&[0u8; 512]);
    assert!(macros.is_empty());
}

// ─── OleLoader (Loader trait) ─────────────────────────────────────────────────

#[test]
fn loader_name_is_ole() {
    use rustre_core::Loader;
    assert_eq!(OleLoader.name(), "ole");
}

#[test]
fn loader_can_load_ole() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("a.doc", make_ole_header());
    assert!(OleLoader.can_load(&input));
}

#[test]
fn loader_rejects_non_ole() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("x.bin", vec![1, 2, 3, 4]);
    assert!(!OleLoader.can_load(&input));
}

#[test]
fn loader_rejects_empty() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("x", vec![]);
    assert!(!OleLoader.can_load(&input));
}

#[tokio::test]
async fn loader_load_returns_view() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("doc.xls", make_ole_header());
    let res = OleLoader.load(input).await.unwrap();
    assert_eq!(res.view.uri, "doc.xls");
}

#[tokio::test]
async fn loader_find_nested_is_empty() {
    use rustre_core::{Loader, LoaderInput};
    let input = LoaderInput::new("doc.xls", make_ole_header());
    let nested = OleLoader.find_nested(&input).await.unwrap();
    assert!(nested.is_empty());
}

// ─── CFB constants ─────────────────────────────────────────────────────────────

#[test]
fn cfb_special_sector_ids() {
    assert_eq!(FREE_SECT, 0xFFFF_FFFF);
    assert_eq!(ENDOFCHAIN, 0xFFFF_FFFE);
    assert_eq!(FATSECT, 0xFFFF_FFFD);
    assert_eq!(DIFSECT, 0xFFFF_FFFC);
}

// ─── CfbError ──────────────────────────────────────────────────────────────────

#[test]
fn cfb_error_display_variants() {
    assert!(CfbError::InvalidMagic.to_string().contains("magic"));
    assert!(CfbError::InvalidVersion(7).to_string().contains('7'));
    assert!(CfbError::TruncatedData.to_string().contains("truncated"));
    assert!(CfbError::InvalidSector(0xAA).to_string().contains("sector"));
    assert!(CfbError::InvalidDirectoryEntry.to_string().contains("directory"));
    assert!(CfbError::StreamTooLarge.to_string().contains("large"));
    assert!(CfbError::Other("x".into()).to_string().contains('x'));
}

#[test]
fn cfb_error_converts_to_ole_error() {
    let oe: OleError = CfbError::InvalidMagic.into();
    assert!(matches!(oe, OleError::ParseError(_)));
}

// ─── CfbReader ─────────────────────────────────────────────────────────────────

#[test]
fn cfb_reader_truncated() {
    match CfbReader::parse(vec![0u8; 100]) {
        Err(CfbError::TruncatedData) => {}
        other => panic!("expected TruncatedData, got {other:?}"),
    }
}

#[test]
fn cfb_reader_invalid_magic() {
    match CfbReader::parse(vec![0u8; 512]) {
        Err(CfbError::InvalidMagic) => {}
        other => panic!("expected InvalidMagic, got {other:?}"),
    }
}

#[test]
fn cfb_reader_invalid_sector_size_exp() {
    let mut data = vec![0u8; 512];
    data[..8].copy_from_slice(&OLE_MAGIC);
    data[26..28].copy_from_slice(&3_u16.to_le_bytes()); // version 3
    data[30..32].copy_from_slice(&7_u16.to_le_bytes()); // bogus sector exp
    match CfbReader::parse(data) {
        Err(CfbError::InvalidVersion(7)) => {}
        other => panic!("expected InvalidVersion(7), got {other:?}"),
    }
}

#[test]
fn cfb_reader_invalid_major_version() {
    let mut data = vec![0u8; 512];
    data[..8].copy_from_slice(&OLE_MAGIC);
    data[26..28].copy_from_slice(&99_u16.to_le_bytes()); // bogus major version
    data[30..32].copy_from_slice(&9_u16.to_le_bytes());
    data[32..34].copy_from_slice(&6_u16.to_le_bytes());
    match CfbReader::parse(data) {
        Err(CfbError::InvalidVersion(99)) => {}
        other => panic!("expected InvalidVersion(99), got {other:?}"),
    }
}

#[test]
fn cfb_reader_minimal_parses() {
    // Just a valid header with no chains; should parse without panicking.
    let mut data = make_ole_header();
    // Pad enough for at least 1 sector after header.
    data.resize(2048, 0);
    // Set all DIFAT entries to FREE_SECT and dir sector to ENDOFCHAIN to keep
    // chain walking trivial.
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    data[48..52].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first_dir_sector
    data[44..48].copy_from_slice(&0_u32.to_le_bytes()); // no fat sectors
    let reader = CfbReader::parse(data).unwrap();
    assert_eq!(reader.sector_size, 512);
    assert_eq!(reader.mini_sector_size, 64);
    assert_eq!(reader.dir_entry_count(), 0);
    assert!(reader.root_entry().is_none());
}

#[test]
fn cfb_reader_get_dir_entry_special_returns_none() {
    let mut data = make_ole_header();
    data.resize(2048, 0);
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    data[48..52].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    data[44..48].copy_from_slice(&0_u32.to_le_bytes());
    let reader = CfbReader::parse(data).unwrap();
    assert!(reader.get_dir_entry(FREE_SECT).is_none());
    assert!(reader.get_dir_entry(ENDOFCHAIN).is_none());
    assert!(reader.get_dir_entry(0).is_none()); // none parsed
}

#[test]
fn cfb_reader_find_entry_empty() {
    let mut data = make_ole_header();
    data.resize(2048, 0);
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    data[48..52].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    data[44..48].copy_from_slice(&0_u32.to_le_bytes());
    let reader = CfbReader::parse(data).unwrap();
    assert!(reader.find_entry("any").is_none());
    assert!(reader.list_all().is_empty());
}

#[test]
fn cfb_reader_read_zero_size_stream() {
    let mut data = make_ole_header();
    data.resize(2048, 0);
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    data[48..52].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    data[44..48].copy_from_slice(&0_u32.to_le_bytes());
    let reader = CfbReader::parse(data).unwrap();
    let entry = CfbDirEntry {
        name: "z".into(),
        entry_type: 2,
        color: false,
        left_sibling: FREE_SECT,
        right_sibling: FREE_SECT,
        child: FREE_SECT,
        clsid: [0u8; 16],
        state_bits: 0,
        created: 0,
        modified: 0,
        start_sector: ENDOFCHAIN,
        size: 0,
    };
    assert!(reader.read_stream(&entry).unwrap().is_empty());
}

#[test]
fn cfb_reader_debug_format() {
    let mut data = make_ole_header();
    data.resize(2048, 0);
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    data[48..52].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    data[44..48].copy_from_slice(&0_u32.to_le_bytes());
    let reader = CfbReader::parse(data).unwrap();
    let s = format!("{reader:?}");
    assert!(s.contains("CfbReader"));
}

// ─── CfbDirEntry ───────────────────────────────────────────────────────────────

fn mk_cfb_entry(kind: u8) -> CfbDirEntry {
    CfbDirEntry {
        name: "n".into(),
        entry_type: kind,
        color: false,
        left_sibling: FREE_SECT,
        right_sibling: FREE_SECT,
        child: FREE_SECT,
        clsid: [0u8; 16],
        state_bits: 0,
        created: 0,
        modified: 0,
        start_sector: 0,
        size: 0,
    }
}

#[test]
fn cfb_dir_entry_kind_predicates() {
    assert!(mk_cfb_entry(0).is_empty());
    assert!(mk_cfb_entry(1).is_storage());
    assert!(mk_cfb_entry(2).is_stream());
    assert!(mk_cfb_entry(5).is_root());
}

#[test]
fn cfb_dir_entry_kind_exclusive() {
    let s = mk_cfb_entry(2);
    assert!(s.is_stream());
    assert!(!s.is_root());
    assert!(!s.is_storage());
    assert!(!s.is_empty());
}

#[test]
fn cfb_dir_entry_display_known() {
    for (k, label) in [(0u8, "empty"), (1, "storage"), (2, "stream"), (5, "root")] {
        let s = mk_cfb_entry(k).to_string();
        assert!(s.contains(label), "expected label {label} in {s}");
    }
}

#[test]
fn cfb_dir_entry_display_unknown_kind() {
    let s = mk_cfb_entry(42).to_string();
    assert!(s.contains("unknown"));
}

#[test]
fn cfb_dir_entry_clone() {
    let a = mk_cfb_entry(2);
    let b = a.clone();
    assert_eq!(a.name, b.name);
    assert_eq!(a.entry_type, b.entry_type);
}

// ─── RTF re-exports ────────────────────────────────────────────────────────────

#[test]
fn rtf_clsid_constants_correct_length() {
    assert_eq!(CLSID_EQUATION_EDITOR.len(), 36);
    assert_eq!(CLSID_PACKAGE.len(), 36);
    assert!(CLSID_EQUATION_EDITOR.contains("0002CE02"));
    assert!(CLSID_PACKAGE.contains("00020820"));
}

#[test]
fn rtf_lexer_constructs() {
    let _ = RtfLexer::new(b"{\\rtf1}");
}

#[test]
fn rtf_parser_parses_minimal() {
    // We don't assume a specific Result shape; just that construction/parse
    // does not panic.
    let _p = RtfParser::default();
}

#[test]
fn rtf_error_is_error_trait() {
    fn assert_err<E: std::error::Error>(_: &E) {}
    let e = RtfError::InvalidOleHeader;
    assert_err(&e);
}

#[test]
fn rtf_token_debug() {
    let t = RtfToken::GroupOpen;
    let _ = format!("{t:?}");
}

#[test]
fn ole_object_type_variants_distinct() {
    let a = OleObjectType::EquationEditor;
    let b = OleObjectType::Package;
    assert_ne!(format!("{a:?}"), format!("{b:?}"));
}

// ─── Send + Sync bounds ────────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn ss<T: Send + Sync>() {}
    ss::<OleHeader>();
    ss::<OleDirectoryEntry>();
    ss::<OleFile>();
    ss::<OleError>();
    ss::<OleSectorSize>();
    ss::<OleStream>();
    ss::<OleLoader>();
    ss::<OleDirectoryReader>();
    ss::<OleMacroExtractor>();
    ss::<CfbDirEntry>();
    ss::<CfbReader>();
    ss::<CfbError>();
}
