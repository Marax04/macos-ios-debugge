//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! PE parser entry points. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors rustre-symbols-pdb/tests/fuzz_lite.rs (xorshift64* PRNG,
//! fixed seeds, no external crates).

use rustre_loader_pe::headers::PeHeaders;
use rustre_loader_pe::pe_analyzer::PeAnalyzer;
use rustre_loader_pe::PeInfo;

/// xorshift64* — deterministic, no external crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
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

/// Run every whole-file parser entry point over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = PeInfo::parse(data);
    let _ = PeHeaders::parse(data);
    let _ = PeAnalyzer::is_pe(data);
}

/// Minimal valid 64-bit PE with one `.text` section (accepted by goblin).
fn minimal_pe64() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    // DOS header
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
    // PE signature
    b[0x40..0x44].copy_from_slice(b"PE\0\0");
    // COFF header at 0x44
    b[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x86-64
    b[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    b[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
    b[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes()); // characteristics EXE|LARGE
    // Optional header (PE32+) at 0x58
    let oh = 0x58;
    b[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // magic PE32+
    b[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    b[oh + 24..oh + 32].copy_from_slice(&0x1400_0000u64.to_le_bytes()); // image base
    b[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
    b[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    b[oh + 40..oh + 42].copy_from_slice(&6u16.to_le_bytes()); // os major
    b[oh + 48..oh + 50].copy_from_slice(&6u16.to_le_bytes()); // subsys major
    b[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
    b[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    b[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem CUI
    b[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    // 16 empty data directories occupy oh+112 .. oh+240 (already zero).
    // Section table at 0x58 + 0xF0 = 0x148
    let sh = 0x148;
    b[sh..sh + 5].copy_from_slice(b".text");
    b[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
    b[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual addr
    b[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    b[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
    b[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|R|X
    b
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for &len in &[0usize, 1, 2, 3, 7, 8, 63, 64, 65, 512, 1024, 4096, 8192] {
        for _ in 0..8 {
            let data = rng.bytes(len);
            exercise_parsers(&data);
        }
    }
}

/// Random bytes behind a valid MZ + PE front door so parsing goes deeper.
#[test]
fn valid_magic_random_body_never_panics() {
    let mut rng = Rng(0xCAFE_F00D_DEAD_BEEF);
    for &len in &[0x48usize, 0x100, 0x400, 0x2000] {
        for _ in 0..16 {
            let mut data = rng.bytes(len);
            data[0] = b'M';
            data[1] = b'Z';
            data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
            data[0x40..0x44].copy_from_slice(b"PE\0\0");
            exercise_parsers(&data);
        }
    }
}

/// Single-byte flips and truncations of a well-formed PE.
#[test]
fn mutated_valid_pe_never_panics() {
    let base = minimal_pe64();
    assert!(PeInfo::parse(&base).is_ok(), "base PE must be valid");

    let mut rng = Rng(0xFEED_FACE_CAFE_D00D);
    for _ in 0..256 {
        let mut data = base.clone();
        let pos = (rng.next() as usize) % data.len();
        data[pos] ^= (rng.next() as u8) | 1;
        exercise_parsers(&data);
    }
    // Truncations at every length up to the header region, then random cuts.
    for cut in 0..0x180 {
        exercise_parsers(&base[..cut]);
    }
    for _ in 0..64 {
        let cut = (rng.next() as usize) % base.len();
        exercise_parsers(&base[..cut]);
    }
}

/// Count/size header fields forced to extreme values on a valid file:
/// must not panic and must not allocate proportionally to the lie.
#[test]
fn extreme_header_fields_never_panic_or_alloc() {
    let base = minimal_pe64();
    // (offset, width) of interesting count/size/offset fields.
    let fields: &[(usize, usize)] = &[
        (0x3C, 4),        // e_lfanew
        (0x46, 2),        // NumberOfSections
        (0x54, 2),        // SizeOfOptionalHeader
        (0x58 + 32, 4),   // section alignment
        (0x58 + 36, 4),   // file alignment
        (0x58 + 56, 4),   // SizeOfImage
        (0x58 + 60, 4),   // SizeOfHeaders
        (0x58 + 108, 4),  // NumberOfRvaAndSizes
        (0x148 + 8, 4),   // section virtual size
        (0x148 + 16, 4),  // section raw size
        (0x148 + 20, 4),  // section raw offset
    ];
    for &(off, width) in fields {
        for val in [0u64, 1, u64::MAX] {
            let mut data = base.clone();
            let bytes = val.to_le_bytes();
            data[off..off + width].copy_from_slice(&bytes[..width]);
            exercise_parsers(&data);
        }
    }
}
