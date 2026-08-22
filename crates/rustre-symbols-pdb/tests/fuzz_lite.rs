//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at every
//! byte-level parser entry point. The invariant under test is "no panic, no
//! runaway allocation, terminates fast" — return values are irrelevant.
//!
//! A real fuzzer (cargo-fuzz) needs nightly + libFuzzer; this file keeps a
//! reproducible subset of that coverage inside the normal test suite.

use rustre_symbols_pdb::global_symbols::parse_global_symbols;
use rustre_symbols_pdb::line_info::parse_line_info;
use rustre_symbols_pdb::module_symbols::parse_module_symbols;
use rustre_symbols_pdb::pdb_dbi_stream::{
    parse_module_info as dbi_parse_module_info, parse_section_contributions, parse_section_map,
    parse_source_file_table, scan_module_compile_flags,
};
use rustre_symbols_pdb::pdb_gsi::{collect_all_pub_symbols, collect_global_data};
use rustre_symbols_pdb::pdb_line_info::{
    parse_file_checksums, parse_inline_lines, parse_lines_subsection, split_c13_subsections,
};
use rustre_symbols_pdb::pdb_publics_reader::parse_sym_records;
use rustre_symbols_pdb::pdb_stream_parser::{parse_named_stream_map, MsfParser};
use rustre_symbols_pdb::pdb_symbol_info::{
    parse_file_info, parse_module_info, parse_section_contribs, parse_symbol_records,
};
use rustre_symbols_pdb::pdb_type_info::read_numeric_leaf;
use rustre_symbols_pdb::type_info::parse_type_stream;
use rustre_symbols_pdb::{parse_tpi_stream, PdbReader, PdbStreamReader};

/// xorshift64* — deterministic, no external crates.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

/// Run every stream-level parser over `data`. Panics/hangs are the failure mode.
fn exercise_stream_parsers(data: &[u8]) {
    let _ = parse_tpi_stream(data);
    let _ = parse_type_stream(data);
    let _ = parse_symbol_records(data);
    let _ = parse_global_symbols(data);
    let _ = parse_module_symbols(data);
    let _ = parse_sym_records(data);
    let _ = collect_all_pub_symbols(data);
    let _ = collect_global_data(data);
    let _ = dbi_parse_module_info(data);
    let _ = parse_section_contributions(data);
    let _ = parse_section_map(data);
    let _ = parse_source_file_table(data);
    let _ = scan_module_compile_flags(data);
    let _ = parse_module_info(data, u32::try_from(data.len()).unwrap_or(u32::MAX));
    let _ = parse_section_contribs(data, 0, u32::try_from(data.len()).unwrap_or(u32::MAX));
    let _ = parse_file_info(data, 0, u32::try_from(data.len()).unwrap_or(u32::MAX));
    let _ = parse_named_stream_map(data);
    let _ = parse_line_info(data, &rustre_symbols_pdb::stream_reader::StringTable::new());
    let _ = parse_file_checksums(data);
    let _ = parse_lines_subsection(data);
    let _ = parse_inline_lines(data);
    let _ = split_c13_subsections(data);
    let _ = read_numeric_leaf(data, 0);
}

/// Run the whole-file readers over `data`.
fn exercise_file_parsers(data: &[u8]) {
    let _ = PdbReader::from_bytes(data);
    let _ = MsfParser::from_bytes(data);
    let _ = PdbStreamReader::parse_pdb_info(data);
    let _ = PdbStreamReader::parse_stream_names(data);
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for &len in &[0usize, 1, 2, 3, 7, 8, 27, 55, 56, 64, 512, 4096, 65_536] {
        for _ in 0..8 {
            let data = rng.bytes(len);
            exercise_stream_parsers(&data);
            exercise_file_parsers(&data);
        }
    }
}

/// Noise behind a valid MSF magic, so parsing gets past the front door.
#[test]
fn valid_magic_random_body_never_panics() {
    const MSF_MAGIC_V7: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
    let mut rng = Rng(0xCAFE_F00D_DEAD_BEEF);
    for &len in &[64usize, 512, 4096, 16_384] {
        for _ in 0..16 {
            let mut data = rng.bytes(len);
            data[..32].copy_from_slice(MSF_MAGIC_V7);
            exercise_file_parsers(&data);
        }
    }
}

/// Structured-ish inputs: plausible record headers followed by noise, which
/// probes length-field handling much deeper than pure noise does.
#[test]
fn record_shaped_noise_never_panics() {
    let mut rng = Rng(0x0BAD_5EED_0BAD_5EED);
    // Symbol / leaf type codes seen across the crate, plus boundary values.
    let codes: &[u16] = &[
        0x1101, 0x1107, 0x1108, 0x110C, 0x110D, 0x110E, 0x1110, 0x1111, 0x1125, 0x1127, 0x113C,
        0x1503, 0x1504, 0x1505, 0x1506, 0x1507, 0x1601, 0x8000, 0x8004, 0x0000, 0xFFFF,
    ];
    for _ in 0..64 {
        let mut data = Vec::new();
        for _ in 0..8 {
            let len = (rng.next() % 96) as u16;
            let code = codes[usize::try_from(rng.next() % codes.len() as u64).unwrap_or(0)];
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&code.to_le_bytes());
            let n = (rng.next() % 64) as usize;
            data.extend_from_slice(&rng.bytes(n));
        }
        exercise_stream_parsers(&data);
    }
}

/// Single-byte mutations of a well-formed MSF file: the classic truncated /
/// bit-flipped symbol-server download.
#[test]
fn mutated_valid_msf_never_panics() {
    // Reuse the minimal-valid-file recipe from tests/hardening.rs.
    const MSF_MAGIC_V7: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
    const BS: usize = 512;
    let streams: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8; 28],           // info stream
        vec![0u8; 56],           // TPI header-sized stream
        {
            let mut d = vec![0u8; 64]; // DBI header
            d[0..4].copy_from_slice(&(-1i32).to_le_bytes());
            d[20..22].copy_from_slice(&4u16.to_le_bytes());
            d
        },
        vec![0u8; 32],
    ];
    let mut dir = Vec::new();
    dir.extend_from_slice(&u32::try_from(streams.len()).unwrap().to_le_bytes());
    for s in &streams {
        dir.extend_from_slice(&u32::try_from(s.len()).unwrap().to_le_bytes());
    }
    let mut next_page = 4u32;
    let mut placements = Vec::new();
    for s in &streams {
        let blocks = s.len().div_ceil(BS);
        placements.push(next_page);
        for b in 0..blocks {
            dir.extend_from_slice(&(next_page + u32::try_from(b).unwrap()).to_le_bytes());
        }
        next_page += u32::try_from(blocks).unwrap();
    }
    let total_pages = (next_page as usize).max(5);
    let mut base = vec![0u8; BS * total_pages];
    base[0..32].copy_from_slice(MSF_MAGIC_V7);
    base[32..36].copy_from_slice(&u32::try_from(BS).unwrap().to_le_bytes());
    base[36..40].copy_from_slice(&1u32.to_le_bytes());
    base[40..44].copy_from_slice(&u32::try_from(total_pages).unwrap().to_le_bytes());
    base[44..48].copy_from_slice(&u32::try_from(dir.len()).unwrap().to_le_bytes());
    base[52..56].copy_from_slice(&2u32.to_le_bytes());
    base[BS * 2..BS * 2 + 4].copy_from_slice(&3u32.to_le_bytes());
    base[BS * 3..BS * 3 + dir.len()].copy_from_slice(&dir);
    for (s, first) in streams.iter().zip(&placements) {
        let start = (*first as usize) * BS;
        base[start..start + s.len()].copy_from_slice(s);
    }
    assert!(PdbReader::from_bytes(&base).is_ok(), "base file must be valid");

    let mut rng = Rng(0xFEED_FACE_CAFE_D00D);
    // Random single-byte flips.
    for _ in 0..256 {
        let mut data = base.clone();
        let pos = usize::try_from(rng.next() % data.len() as u64).unwrap_or(0);
        data[pos] ^= (rng.next() & 0xFF) as u8 | 1;
        exercise_file_parsers(&data);
    }
    // Truncations at random points.
    for _ in 0..64 {
        let cut = usize::try_from(rng.next() % base.len() as u64).unwrap_or(0);
        exercise_file_parsers(&base[..cut]);
    }
}
