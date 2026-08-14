//! Fuzz-lite for the STABS parsers: deterministic pseudo-random inputs.
//! Invariant: no panic, no runaway allocation, fast termination.

use rustre_symbols_stabs::stabs_full_parser::parse_stab_section;
use rustre_symbols_stabs::stabs_parser::parse_stab_section_raw;
use rustre_symbols_stabs::StabRecord;

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

fn exercise(stab: &[u8], strtab: &[u8]) {
    let _ = parse_stab_section(stab);
    let _ = parse_stab_section_raw(stab, false);
    let _ = parse_stab_section_raw(stab, true);
    let _ = StabRecord::parse_all(stab, strtab);
    let _ = StabRecord::parse_all_be(stab, strtab);
}

/// Pure random noise at several sizes, with random string tables.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0x5AB5_5AB5_5AB5_5AB5);
    for &len in &[0usize, 1, 11, 12, 13, 24, 120, 1200, 12_000, 65_532] {
        for _ in 0..8 {
            let stab = rng.bytes(len);
            let n = (rng.next() % 256) as usize;
            let strtab = rng.bytes(n);
            exercise(&stab, &strtab);
        }
    }
}

/// Records with extreme n_strx offsets pointing far past the string table.
#[test]
fn out_of_range_string_offsets_never_panic() {
    let mut rng = Rng(0xBEEF_CAFE_1234_5678);
    for _ in 0..64 {
        let mut stab = Vec::new();
        for _ in 0..16 {
            stab.extend_from_slice(&u32::MAX.to_le_bytes()); // n_strx
            stab.push(rng.next() as u8); // n_type
            stab.push(rng.next() as u8); // n_other
            stab.extend_from_slice(&(rng.next() as u16).to_le_bytes()); // n_desc
            stab.extend_from_slice(&(rng.next() as u32).to_le_bytes()); // n_value
        }
        let strtab = rng.bytes(8);
        exercise(&stab, &strtab);
    }
}

/// Truncated record streams: every prefix length of a valid-ish section.
#[test]
fn truncations_never_panic() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let base = rng.bytes(12 * 8);
    for cut in 0..base.len() {
        exercise(&base[..cut], b"a\0b\0c\0");
    }
}
