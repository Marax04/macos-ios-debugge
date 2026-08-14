//! Hardening regression tests: malformed / adversarial PDB inputs must fail
//! fast without huge allocations, and DBI sub-stream layouts must match the
//! real Microsoft format.

use rustre_symbols_pdb::pdb_dbi_stream::parse_source_file_table;
use rustre_symbols_pdb::pdb_stream_parser::{parse_named_stream_map, MsfParser};
use rustre_symbols_pdb::pdb_symbol_info::parse_file_info;
use rustre_symbols_pdb::{PdbReader, PdbStreamReader};

const MSF_MAGIC_V7: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

/// Minimal superblock with attacker-controlled directory size / block map.
fn superblock(block_size: u32, num_dir_bytes: u32, block_map_addr: u32) -> Vec<u8> {
    let mut v = vec![0u8; 4096];
    v[0..32].copy_from_slice(MSF_MAGIC_V7);
    v[32..36].copy_from_slice(&block_size.to_le_bytes());
    v[36..40].copy_from_slice(&1u32.to_le_bytes()); // free block map
    v[40..44].copy_from_slice(&2u32.to_le_bytes()); // num blocks
    v[44..48].copy_from_slice(&num_dir_bytes.to_le_bytes());
    v[52..56].copy_from_slice(&block_map_addr.to_le_bytes());
    v
}

/// A superblock claiming a 4 GiB directory must not allocate gigabytes:
/// parsing has to fail (or return empty) quickly on a 4 KiB file.
#[test]
fn huge_num_dir_bytes_does_not_allocate() {
    let raw = superblock(1, u32::MAX, 1);
    let _ = PdbReader::from_bytes(&raw);
    let _ = MsfParser::from_bytes(&raw);
    let _ = PdbStreamReader::parse_pdb_info(&raw);
    let _ = PdbStreamReader::parse_stream_names(&raw);
}

/// A stream directory claiming `u32::MAX` streams must not pre-allocate.
#[test]
fn huge_stream_count_does_not_allocate() {
    // block_size 4096, directory = 1 block at page 1 containing stream_count.
    let mut raw = superblock(4096, 8, 2);
    raw.resize(4096 * 3, 0);
    // Block map at page 2: first directory page = 1.
    raw[4096 * 2..4096 * 2 + 4].copy_from_slice(&1u32.to_le_bytes());
    // Directory (page 1): num_streams = u32::MAX.
    raw[4096..4100].copy_from_slice(&u32::MAX.to_le_bytes());
    let _ = PdbReader::from_bytes(&raw);
    let _ = MsfParser::from_bytes(&raw);
}

/// A named-stream map with a huge `present_word_count` must return an empty
/// map quickly, without materialising a multi-gigabyte bitset.
#[test]
fn huge_present_words_named_stream_map() {
    let mut info = vec![0u8; 64];
    // header: version/signature/age/guid = 28 bytes, then strbuf_size = 0,
    // capacity, then present_word_count = u32::MAX.
    info[28..32].copy_from_slice(&0u32.to_le_bytes()); // strbuf_size
    info[36..40].copy_from_slice(&u32::MAX.to_le_bytes()); // present words
    let names = parse_named_stream_map(&info);
    assert!(names.is_empty());
}

/// Micro-benchmark for `parse_file_info` on a worst-case input (65 535
/// modules, one file each). Run with `cargo test --release -- --ignored
/// bench_file_info --nocapture`. Prior to the prefix-sum fix this path was
/// O(n²) over the module count.
#[test]
#[ignore = "manual micro-benchmark"]
fn bench_file_info_large() {
    let n: usize = 65_535;
    let mut fi = Vec::new();
    fi.extend_from_slice(&u16::try_from(n).unwrap().to_le_bytes());
    fi.extend_from_slice(&u16::try_from(n).unwrap().to_le_bytes());
    for i in 0..n {
        fi.extend_from_slice(&u16::try_from(i.min(0xFFFF)).unwrap().to_le_bytes());
    }
    for _ in 0..n {
        fi.extend_from_slice(&1u16.to_le_bytes());
    }
    for _ in 0..n {
        fi.extend_from_slice(&0u32.to_le_bytes());
    }
    fi.extend_from_slice(b"f.c\0");

    let size = u32::try_from(fi.len()).unwrap();
    let t = std::time::Instant::now();
    let files = parse_file_info(&fi, 0, size).unwrap();
    println!("parse_file_info: {} files in {:?}", files.len(), t.elapsed());
    assert_eq!(files.len(), n);
}

/// `FileInfo` sub-stream: the parser must read `mod_file_counts` (the second
/// u16 array), not `mod_indices` (the first), and must resolve names via the
/// running prefix sum.
#[test]
fn file_info_reads_second_u16_array() {
    // 2 modules, 3 files: module 0 -> [a.c, b.c], module 1 -> [c.c]
    let names: &[&[u8]] = &[b"a.c\0", b"b.c\0", b"c.c\0"];
    let mut fi = Vec::new();
    fi.extend_from_slice(&2u16.to_le_bytes()); // num_modules
    fi.extend_from_slice(&3u16.to_le_bytes()); // num_files
    // mod_indices (prefix sums): 0, 2 — deliberately NOT the counts.
    fi.extend_from_slice(&0u16.to_le_bytes());
    fi.extend_from_slice(&2u16.to_le_bytes());
    // mod_file_counts: 2, 1
    fi.extend_from_slice(&2u16.to_le_bytes());
    fi.extend_from_slice(&1u16.to_le_bytes());
    // file name offsets into the string buffer
    let mut off = 0u32;
    for n in names {
        fi.extend_from_slice(&off.to_le_bytes());
        off += u32::try_from(n.len()).unwrap();
    }
    for n in names {
        fi.extend_from_slice(n);
    }

    let size = u32::try_from(fi.len()).unwrap();
    let files = parse_file_info(&fi, 0, size).unwrap();
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, "a.c");
    assert_eq!(files[0].module_index, 0);
    assert_eq!(files[1].name, "b.c");
    assert_eq!(files[1].module_index, 0);
    assert_eq!(files[2].name, "c.c");
    assert_eq!(files[2].module_index, 1);

    let table = parse_source_file_table(&fi).unwrap();
    assert_eq!(table.modules.len(), 2);
    assert_eq!(table.modules[0].file_names, vec!["a.c", "b.c"]);
    assert_eq!(table.modules[1].file_names, vec!["c.c"]);
}

// ── try_* API: corruption must be distinguishable from absence ────────────────

/// Assemble a minimal but structurally valid MSF file out of `streams`.
/// Block size 512: page 0 superblock, page 1 free-page map, page 2 block map,
/// page 3 directory, pages 4.. the stream payloads.
fn build_msf(streams: &[Vec<u8>]) -> Vec<u8> {
    const BS: usize = 512;

    // Directory: num_streams, sizes[], then the page list of each stream.
    let mut dir = Vec::new();
    dir.extend_from_slice(&u32::try_from(streams.len()).unwrap().to_le_bytes());
    for s in streams {
        dir.extend_from_slice(&u32::try_from(s.len()).unwrap().to_le_bytes());
    }
    let mut next_page = 4u32;
    let mut placements: Vec<(u32, usize)> = Vec::new(); // (first page, block count)
    for s in streams {
        let blocks = s.len().div_ceil(BS);
        placements.push((next_page, blocks));
        for b in 0..blocks {
            dir.extend_from_slice(&(next_page + u32::try_from(b).unwrap()).to_le_bytes());
        }
        next_page += u32::try_from(blocks).unwrap();
    }
    assert!(dir.len() <= BS, "test directory must fit in one page");

    let total_pages = (next_page as usize).max(5);
    let mut raw = vec![0u8; BS * total_pages];
    raw[0..32].copy_from_slice(MSF_MAGIC_V7);
    raw[32..36].copy_from_slice(&u32::try_from(BS).unwrap().to_le_bytes());
    raw[36..40].copy_from_slice(&1u32.to_le_bytes()); // free page map
    raw[40..44].copy_from_slice(&u32::try_from(total_pages).unwrap().to_le_bytes());
    raw[44..48].copy_from_slice(&u32::try_from(dir.len()).unwrap().to_le_bytes());
    raw[52..56].copy_from_slice(&2u32.to_le_bytes()); // block map at page 2
    raw[BS * 2..BS * 2 + 4].copy_from_slice(&3u32.to_le_bytes()); // dir lives on page 3
    raw[BS * 3..BS * 3 + dir.len()].copy_from_slice(&dir);
    for (s, (first, _)) in streams.iter().zip(&placements) {
        let start = (*first as usize) * BS;
        raw[start..start + s.len()].copy_from_slice(s);
    }
    raw
}

/// Stream 1 (PDB info): 28 bytes is the minimum `parse_info_stream` accepts.
fn info_stream() -> Vec<u8> {
    vec![0u8; 28]
}

/// A 64-byte DBI header pointing `symbol_stream` at stream 4.
fn dbi_header(symbol_stream: u16) -> Vec<u8> {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(&(-1i32).to_le_bytes());
    d[20..22].copy_from_slice(&symbol_stream.to_le_bytes());
    // module_info_size (offset 24) stays 0.
    d
}

/// A symbol record stream truncated mid-record: the record declares 0x40 bytes
/// but only a handful follow. This is what an interrupted symbol-server
/// download looks like.
fn truncated_symbol_stream() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&0x40u16.to_le_bytes()); // length
    s.extend_from_slice(&0x110Eu16.to_le_bytes()); // S_PUB32
    s.extend_from_slice(&[0u8; 8]); // far short of 0x40
    s
}

#[test]
fn try_symbols_reports_corruption_while_symbols_returns_empty() {
    let raw = build_msf(&[
        Vec::new(),
        info_stream(),
        Vec::new(),
        dbi_header(4),
        truncated_symbol_stream(),
    ]);
    let reader = PdbReader::from_bytes(&raw).expect("superblock/info are intact");

    // The lossy API cannot tell "no symbols" from "truncated file".
    assert!(reader.symbols().is_empty());
    assert!(reader.symbols_with_segment().is_empty());

    // The fallible API can.
    assert!(reader.try_symbols().is_err(), "truncated record must surface an error");
    assert!(reader.try_symbols_with_segment().is_err());
}

#[test]
fn try_types_reports_a_truncated_tpi_stream() {
    // Stream 2 present but shorter than the 56-byte TPI header.
    let raw = build_msf(&[Vec::new(), info_stream(), vec![0u8; 10], dbi_header(4), Vec::new()]);
    let reader = PdbReader::from_bytes(&raw).unwrap();
    assert!(reader.types().is_empty());
    assert!(reader.try_types().is_err());
}

#[test]
fn try_modules_reports_a_missing_dbi_stream() {
    // Only streams 0 and 1 exist, so stream 3 (DBI) is absent entirely.
    let raw = build_msf(&[Vec::new(), info_stream()]);
    let reader = PdbReader::from_bytes(&raw).unwrap();
    assert!(reader.modules().is_empty());
    assert!(reader.module_proc_symbols().is_empty());
    assert!(reader.try_modules().is_err());
    assert!(reader.try_module_proc_symbols().is_err());
}

#[test]
fn try_apis_agree_with_the_lossy_ones_on_a_well_formed_pdb() {
    // No symbols, no types, no modules — but nothing corrupt either, so the
    // fallible variants must return `Ok(empty)`, not an error.
    let mut tpi = vec![0u8; 56];
    tpi[0..4].copy_from_slice(&20_040_203u32.to_le_bytes());
    let raw = build_msf(&[Vec::new(), info_stream(), tpi, dbi_header(4), Vec::new()]);
    let reader = PdbReader::from_bytes(&raw).unwrap();
    assert_eq!(reader.try_symbols().unwrap(), reader.symbols());
    assert_eq!(reader.try_types().unwrap().len(), reader.types().len());
    assert_eq!(reader.try_modules().unwrap().len(), reader.modules().len());
    assert!(reader.try_module_proc_symbols().unwrap().is_empty());
}
