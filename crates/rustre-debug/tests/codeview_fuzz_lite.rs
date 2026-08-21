//! Fuzz-lite for the CodeView/MSF parsers in `rustre_debug::codeview`:
//! deterministic pseudo-random and structured-noise inputs. Invariant:
//! no panic, no runaway allocation, fast termination.

use rustre_debug::codeview::codeview_type_parser::decode_numeric_leaf;
use rustre_debug::codeview::codeview_types::{
    parse_type_record as types_parse_type_record, parse_type_stream,
};
use rustre_debug::codeview::codeview_parser::{
    find_debug_directory, parse_cv_debug_record, parse_file_checksums, parse_frame_data,
    parse_line_subsection, parse_module_contribs,
};
use rustre_debug::codeview::cv_function_info::CvFunctionInfo;
use rustre_debug::codeview::msf_reader::MsfReader;
use rustre_debug::codeview::{
    parse_cv8_lines, parse_cv_symbol, parse_cv_symbols, parse_cv_type_records,
};

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

fn exercise(data: &[u8]) {
    let _ = parse_cv_symbols(data);
    let _ = parse_cv_type_records(data);
    let _ = parse_cv8_lines(data);
    let _ = parse_cv_symbol(data, 0);
    let _ = types_parse_type_record(data);
    let _ = parse_type_stream(data);
    let _ = decode_numeric_leaf(data, 0);
    // Subsection parsers reached from a real `.pdb`/`.obj`, none of which this
    // fuzzer covered before. `parse_line_subsection` in particular is the twin
    // that was missing its allocation cap until iter 219 — its sibling in
    // `mod.rs` had one and it did not — so this family has already proved it
    // can diverge from itself.
    let _ = parse_cv_debug_record(data);
    let _ = parse_file_checksums(data);
    let _ = parse_line_subsection(data);
    let _ = parse_module_contribs(data);
    let _ = parse_frame_data(data);
    // Takes PE bytes rather than a CodeView stream: noise is exactly the input
    // that a wrong bounds check would fall over on.
    let _ = find_debug_directory(data);
    // Both branches: a global and a local function record read the same body
    // through different paths.
    let _ = CvFunctionInfo::parse(data, true);
    let _ = CvFunctionInfo::parse(data, false);
    if let Ok(msf) = MsfReader::parse(data) {
        for i in 0..msf.num_streams().min(8) {
            let _ = msf.read_stream(i);
        }
    }
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0xC0DE_51EF ^ 0xFACE_0FF0_1234_5678);
    for &len in &[0usize, 1, 2, 3, 4, 8, 16, 32, 56, 64, 512, 4096, 65_536] {
        for _ in 0..8 {
            exercise(&rng.bytes(len));
        }
    }
}

/// Record-shaped noise: plausible `(len, kind)` `CodeView` headers followed by
/// random payloads — probes each record decoder's length handling.
#[test]
fn record_shaped_noise_never_panics() {
    let mut rng = Rng(0x0DD5_EED5_0DD5_EED5);
    let kinds: &[u16] = &[
        0x1101, 0x1105, 0x1107, 0x1108, 0x110C, 0x110D, 0x110E, 0x1110, 0x1111, 0x1125, 0x1127,
        0x113C, 0x1503, 0x1504, 0x1505, 0x1506, 0x1507, 0x1601, 0x8000, 0x0000, 0xFFFF,
    ];
    for _ in 0..64 {
        let mut data = Vec::new();
        for _ in 0..8 {
            let len = (rng.next() % 96) as u16;
            let kind = kinds[(rng.next() as usize) % kinds.len()];
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&kind.to_le_bytes());
            let n = (rng.next() % 64) as usize;
            data.extend_from_slice(&rng.bytes(n));
        }
        exercise(&data);
    }
}

/// A valid MSF magic with adversarial superblock geometry: huge directory
/// sizes, page counts and stream counts must fail fast without allocating.
#[test]
fn adversarial_msf_superblocks_never_panic_or_alloc() {
    const MSF_MAGIC_V7: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
    let mut rng = Rng(0xDEAD_10CC_DEAD_10CC);
    for _ in 0..128 {
        let mut data = vec![0u8; 4096];
        data[..32].copy_from_slice(MSF_MAGIC_V7);
        // page_size, free_block_map, num_pages, num_dir_bytes, unknown, block_map_addr
        let fields: [u32; 6] = [
            [512u32, 1024, 4096, 3, 0, u32::MAX][(rng.next() as usize) % 6],
            (rng.next() % 4) as u32,
            [2u32, 8, u32::MAX, 0][(rng.next() as usize) % 4],
            [8u32, 4096, u32::MAX, 0xFFFF_FFF0][(rng.next() as usize) % 4],
            0,
            [1u32, 2, 3, u32::MAX][(rng.next() as usize) % 4],
        ];
        for (i, f) in fields.iter().enumerate() {
            data[32 + i * 4..36 + i * 4].copy_from_slice(&f.to_le_bytes());
        }
        exercise(&data);
    }
}

/// Truncations of a random buffer at every length below 256.
#[test]
fn truncations_never_panic() {
    let mut rng = Rng(0x7EA5_E77E_7EA5_E77E);
    let base = rng.bytes(256);
    for cut in 0..base.len() {
        exercise(&base[..cut]);
    }
}
