//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! ELF parser entry points. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors rustre-symbols-pdb/tests/fuzz_lite.rs (xorshift64* PRNG,
//! fixed seeds, no external crates).

use rustre_loader_elf::elf_analyzer::ElfAnalyzer;
use rustre_loader_elf::gnu_hash::GnuHashTable;
use rustre_loader_elf::headers::{Ehdr32, Ehdr64};
use rustre_loader_elf::notes::parse_note_section;
use rustre_loader_elf::program_headers::{Phdr32, Phdr64};
use rustre_loader_elf::symbols::{Sym32, Sym64};
use rustre_loader_elf::ElfInfo;

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

/// Run whole-file and section-level parser entry points over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = ElfInfo::parse(data);
    let _ = Ehdr32::parse(data);
    let _ = Ehdr64::parse(data);
    let _ = GnuHashTable::parse64(data, true);
    let _ = GnuHashTable::parse64(data, false);
    let _ = parse_note_section(data);
    let _ = Phdr32::parse(data, 0, true);
    let _ = Phdr64::parse(data, 0, true);
    let _ = Sym32::parse_table(data, 0, data.len() / 16 + 1, true);
    let _ = Sym64::parse_table(data, 0, data.len() / 24 + 1, true);
    let _ = ElfAnalyzer::new().parse_notes(data, 0, data.len());
    let _ = ElfAnalyzer::new().parse_dynamic(data, data);
}

/// Minimal valid 64-bit little-endian ELF executable (header only, one phdr).
fn minimal_elf64() -> Vec<u8> {
    let mut b = vec![0u8; 64 + 56];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little endian
    b[6] = 1; // EV_CURRENT
    b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
    b[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
    b[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // entry
    b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    b[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    // one PT_LOAD phdr at 64
    b[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[68..72].copy_from_slice(&5u32.to_le_bytes()); // R+X
    b[80..88].copy_from_slice(&0x40_0000u64.to_le_bytes()); // vaddr
    b[96..104].copy_from_slice(&120u64.to_le_bytes()); // filesz
    b[104..112].copy_from_slice(&120u64.to_le_bytes()); // memsz
    b[112..120].copy_from_slice(&0x1000u64.to_le_bytes()); // align
    b
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for &len in &[0usize, 1, 2, 3, 7, 8, 51, 52, 63, 64, 65, 512, 4096, 8192] {
        for _ in 0..8 {
            let data = rng.bytes(len);
            exercise_parsers(&data);
        }
    }
}

/// Random bytes behind a valid \x7fELF magic (both classes, both endians).
#[test]
fn valid_magic_random_body_never_panics() {
    let mut rng = Rng(0xCAFE_F00D_DEAD_BEEF);
    for &(class, endian) in &[(1u8, 1u8), (1, 2), (2, 1), (2, 2)] {
        for &len in &[16usize, 52, 64, 512, 4096] {
            for _ in 0..8 {
                let mut data = rng.bytes(len);
                data[0..4].copy_from_slice(b"\x7fELF");
                if len > 6 {
                    data[4] = class;
                    data[5] = endian;
                    data[6] = 1;
                }
                exercise_parsers(&data);
            }
        }
    }
}

/// Single-byte flips and truncations of a well-formed ELF.
#[test]
fn mutated_valid_elf_never_panics() {
    let base = minimal_elf64();
    assert!(ElfInfo::parse(&base).is_ok(), "base ELF must be valid");

    let mut rng = Rng(0xFEED_FACE_CAFE_D00D);
    for _ in 0..256 {
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

/// Count/size/offset header fields forced to extreme values on a valid file:
/// must not panic and must not allocate proportionally to the lie.
#[test]
fn extreme_header_fields_never_panic_or_alloc() {
    let base = minimal_elf64();
    // (offset, width) of count/size/offset fields in the ELF64 header + phdr.
    let fields: &[(usize, usize)] = &[
        (32, 8),  // e_phoff
        (40, 8),  // e_shoff
        (52, 2),  // e_ehsize
        (54, 2),  // e_phentsize
        (56, 2),  // e_phnum
        (58, 2),  // e_shentsize
        (60, 2),  // e_shnum
        (62, 2),  // e_shstrndx
        (72, 8),  // p_offset
        (96, 8),  // p_filesz
        (104, 8), // p_memsz
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
