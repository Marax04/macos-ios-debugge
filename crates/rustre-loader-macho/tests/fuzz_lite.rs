//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! Mach-O parser entry points. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors rustre-symbols-pdb/tests/fuzz_lite.rs (xorshift64* PRNG,
//! fixed seeds, no external crates).

use rustre_loader_macho::{
    ChainedFixupsParser, CodeSignatureParser, DataInCodeParser, DyldInfoParser, FatBinaryParser,
    FunctionStartsParser, MachoAnalyzer, MachoLoadCommandEnum, MachoParser, RebaseParser,
};

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

/// Run every parser entry point over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = MachoParser::parse(data);
    let _ = MachoParser::parse_fat(data);
    let _ = MachoParser::parse_single(data);
    let _ = MachoAnalyzer::analyze(data);
    let _ = FatBinaryParser::detect_fat(data);
    let _ = FatBinaryParser::list_arches(data);
    let _ = MachoLoadCommandEnum::parse_all(data, 0, 16, false);
    let _ = MachoLoadCommandEnum::parse_all(data, 0, 16, true);
    let _ = FunctionStartsParser::parse(data, 0x1_0000_0000);
    let _ = DyldInfoParser::parse_exports(data);
    let _ = DyldInfoParser::parse_bind(data);
    let _ = DataInCodeParser::parse(data);
    let _ = RebaseParser::parse(data);
    let _ = CodeSignatureParser::parse(data);
    let _ = ChainedFixupsParser::parse_imports(data);
    let _ = ChainedFixupsParser::parse_segment_starts(data);
}

/// Minimal valid 64-bit Mach-O executable header (no load commands).
fn minimal_macho64() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes()); // MH_MAGIC_64
    b.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
    b.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
    b.extend_from_slice(&0x2u32.to_le_bytes()); // MH_EXECUTE
    b.extend_from_slice(&0u32.to_le_bytes()); // ncmds
    b.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
    b.extend_from_slice(&0x0020_0000u32.to_le_bytes()); // MH_PIE
    b.extend_from_slice(&0u32.to_le_bytes()); // reserved
    b.extend_from_slice(&[0u8; 64]); // room for mutated load commands
    b
}

/// Minimal fat binary wrapping one x86_64 slice.
fn minimal_fat() -> Vec<u8> {
    let slice = minimal_macho64();
    let mut b = Vec::new();
    b.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // FAT_MAGIC
    b.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
    b.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
    b.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
    b.extend_from_slice(&28u32.to_be_bytes()); // offset
    b.extend_from_slice(&u32::try_from(slice.len()).unwrap().to_be_bytes()); // size
    b.extend_from_slice(&0u32.to_be_bytes()); // align
    b.extend_from_slice(&slice);
    b
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for &len in &[0usize, 1, 2, 3, 4, 7, 8, 31, 32, 33, 512, 4096, 8192] {
        for _ in 0..8 {
            let data = rng.bytes(len);
            exercise_parsers(&data);
        }
    }
}

/// Random bytes behind valid MH_MAGIC_64 / MH_MAGIC / FAT_MAGIC front doors.
#[test]
fn valid_magic_random_body_never_panics() {
    let magics: &[[u8; 4]] = &[
        0xFEED_FACFu32.to_le_bytes(), // MH_MAGIC_64 LE
        0xFEED_FACEu32.to_le_bytes(), // MH_MAGIC LE
        0xFEED_FACFu32.to_be_bytes(), // MH_CIGAM_64
        0xCAFE_BABEu32.to_be_bytes(), // FAT_MAGIC
        0xCAFE_BABFu32.to_be_bytes(), // FAT_MAGIC_64
    ];
    let mut rng = Rng(0xCAFE_F00D_DEAD_BEEF);
    for magic in magics {
        for &len in &[8usize, 32, 64, 512, 4096] {
            for _ in 0..8 {
                let mut data = rng.bytes(len);
                data[0..4].copy_from_slice(magic);
                exercise_parsers(&data);
            }
        }
    }
}

/// Single-byte flips and truncations of well-formed thin and fat binaries.
#[test]
fn mutated_valid_macho_never_panics() {
    let thin = minimal_macho64();
    let fat = minimal_fat();
    assert!(MachoParser::parse(&thin).is_ok(), "base thin Mach-O must be valid");
    assert!(MachoParser::parse_fat(&fat).is_ok(), "base fat Mach-O must be valid");

    let mut rng = Rng(0xFEED_FACE_CAFE_D00D);
    for base in [&thin, &fat] {
        for _ in 0..192 {
            let mut data = base.clone();
            let pos = (rng.next() as usize) % data.len();
            data[pos] ^= (rng.next() as u8) | 1;
            exercise_parsers(&data);
        }
        // Truncation at every possible length.
        for cut in 0..base.len() {
            exercise_parsers(&base[..cut]);
        }
    }
}

/// Count/size fields forced to extreme values on valid files: must not panic
/// and must not allocate proportionally to the lie.
#[test]
fn extreme_header_fields_never_panic_or_alloc() {
    let thin = minimal_macho64();
    // ncmds (16) and sizeofcmds (20) in the mach_header_64.
    for off in [16usize, 20] {
        for val in [0u32, 1, u32::MAX] {
            let mut data = thin.clone();
            data[off..off + 4].copy_from_slice(&val.to_le_bytes());
            exercise_parsers(&data);
        }
    }
    // nfat_arch (4, BE) and slice offset/size (16/20, BE) in the fat header.
    let fat = minimal_fat();
    for off in [4usize, 16, 20] {
        for val in [0u32, 1, u32::MAX] {
            let mut data = fat.clone();
            data[off..off + 4].copy_from_slice(&val.to_be_bytes());
            exercise_parsers(&data);
        }
    }
}
