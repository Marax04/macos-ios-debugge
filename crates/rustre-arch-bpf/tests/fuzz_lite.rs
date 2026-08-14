//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! eBPF decoder and BTF parser entry points. Invariant under test: no panic,
//! no runaway allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! eBPF instructions are 8 bytes, except `BPF_LD | BPF_IMM | BPF_DW`
//! (opcode `0x18`) which is 16 — a two-slot encoding that is the classic place
//! for a decoder to read past the end. BTF, by contrast, is a header plus
//! offset-addressed sections, so it gets adversarial offsets and lengths.

use rustre_arch_bpf::btf_parser::BtfSection as BtfParserSection;
use rustre_arch_bpf::{BpfInstruction, BtfSection as LibBtfSection};

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
    let _ = BpfInstruction::decode(data);
    let _ = BtfParserSection::parse(data);
    let _ = LibBtfSection::parse(data);
}

/// Decode a whole instruction stream, advancing by the reported width.
///
/// A decoder that reports a width of zero would hang this loop, so the step is
/// forced forward; the point is to exercise the multi-instruction path.
fn walk_stream(data: &[u8]) {
    let mut pos = 0usize;
    let mut steps = 0;
    while pos < data.len() && steps < 4096 {
        match BpfInstruction::decode(&data[pos..]) {
            Ok((_, n)) => pos += n.max(1),
            Err(_) => break,
        }
        steps += 1;
    }
}

/// Pure random noise of assorted lengths.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..600 {
        let len = (rng.next() % 96) as usize;
        let buf = rng.bytes(len);
        exercise_parsers(&buf);
        walk_stream(&buf);
    }
}

/// Every opcode byte as the first byte of an 8-byte instruction.
///
/// This sweeps the whole opcode space including the wide-immediate `0x18`.
#[test]
fn every_opcode_byte_never_panics() {
    for op in 0u8..=255 {
        let mut insn = [0u8; 8];
        insn[0] = op;
        exercise_parsers(&insn);
        // Same opcode with a second slot present (wide-immediate form).
        let mut wide = [0u8; 16];
        wide[0] = op;
        exercise_parsers(&wide);
    }
}

/// The 16-byte wide-immediate encoding truncated at every length.
///
/// `0x18` promises a second 8-byte slot; cutting it short is the canonical
/// out-of-bounds trigger for an eBPF decoder.
#[test]
fn wide_immediate_truncations_never_panic() {
    let mut insn = [0u8; 16];
    insn[0] = 0x18; // BPF_LD | BPF_IMM | BPF_DW
    insn[1] = 0x01; // dst reg
    insn[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    insn[12..16].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    for cut in 0..=insn.len() {
        exercise_parsers(&insn[..cut]);
        walk_stream(&insn[..cut]);
    }
}

/// Bit flips of a valid instruction pair.
#[test]
fn bit_flips_never_panic() {
    let base: [u8; 16] = [
        0xB7, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, // mov64 r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];
    for byte_idx in 0..base.len() {
        for bit in 0..8 {
            let mut m = base;
            m[byte_idx] ^= 1 << bit;
            exercise_parsers(&m);
            walk_stream(&m);
        }
    }
}

/// BTF blobs behind a valid magic, with adversarial header fields.
///
/// The BTF header carries `hdr_len`, `type_off/len` and `str_off/len`; each is
/// an offset or length into the blob, so extreme values must be rejected
/// rather than used to index.
#[test]
fn btf_adversarial_headers_never_panic() {
    let extremes: [u32; 6] = [0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFF0, u32::MAX];
    for &v in &extremes {
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0x9F, 0xEB]); // BTF magic
        blob.push(0x01); // version
        blob.push(0x00); // flags
        blob.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        blob.extend_from_slice(&v.to_le_bytes()); // type_off
        blob.extend_from_slice(&v.to_le_bytes()); // type_len
        blob.extend_from_slice(&v.to_le_bytes()); // str_off
        blob.extend_from_slice(&v.to_le_bytes()); // str_len
        exercise_parsers(&blob);

        // Same, with a bogus hdr_len too.
        let mut blob2 = blob.clone();
        blob2[4..8].copy_from_slice(&v.to_le_bytes());
        exercise_parsers(&blob2);
    }
}

/// Truncations of a well-formed BTF header.
#[test]
fn btf_truncations_never_panic() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x9F, 0xEB, 0x01, 0x00]);
    blob.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
    blob.extend_from_slice(&0u32.to_le_bytes()); // type_off
    blob.extend_from_slice(&0u32.to_le_bytes()); // type_len
    blob.extend_from_slice(&0u32.to_le_bytes()); // str_off
    blob.extend_from_slice(&1u32.to_le_bytes()); // str_len
    blob.push(0); // one string byte
    for cut in 0..=blob.len() {
        exercise_parsers(&blob[..cut]);
    }
}

/// Long uniform buffers — the stream walk must terminate on all of them.
#[test]
fn oversized_uniform_buffers_never_panic() {
    for fill in [0x00u8, 0x18, 0x95, 0xB7, 0xFF] {
        for len in [256usize, 4096] {
            let buf = vec![fill; len];
            exercise_parsers(&buf);
            walk_stream(&buf);
        }
    }
}
