//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! CIL decoder and .NET metadata parser. Invariant under test: no panic, no
//! runaway allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! Two things make CIL worth fuzzing beyond the opcode table:
//!
//! * the `0xFE` two-byte prefix, which doubles the opcode space and is the
//!   usual place to read past the end of a one-byte buffer;
//! * the *compressed integer* encoding used throughout the metadata blobs,
//!   whose length is determined by the top bits of the first byte — a classic
//!   spot for reading more bytes than are present.

use rustre_arch_cil::cil_metadata::CilMetadataReader;
use rustre_arch_cil::{decode_compressed_int, decode_compressed_uint, CilInstr};

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

/// Run every parser entry point over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = CilInstr::decode(data);
    let _ = decode_compressed_uint(data);
    let _ = decode_compressed_int(data);
    let _ = CilMetadataReader::parse(data.to_vec());
}

/// Decode a whole instruction stream, advancing by the reported width.
fn walk_stream(data: &[u8]) {
    let mut pos = 0usize;
    let mut steps = 0;
    while pos < data.len() && steps < 4096 {
        match CilInstr::decode(&data[pos..]) {
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
        let len = (rng.next() % 64) as usize;
        let buf = rng.bytes(len);
        exercise_parsers(&buf);
        walk_stream(&buf);
    }
}

/// Every single byte as a one-byte method body.
#[test]
fn every_single_opcode_never_panics() {
    for b in 0u8..=255 {
        exercise_parsers(&[b]);
    }
}

/// The `0xFE` prefix followed by every possible second byte, with and without
/// trailing operand bytes.
#[test]
fn fe_prefix_pairs_never_panic() {
    for b in 0u8..=255 {
        exercise_parsers(&[0xFE, b]);
        exercise_parsers(&[0xFE, b, 0x00]);
        exercise_parsers(&[0xFE, b, 0x00, 0x01, 0x02, 0x03]);
    }
    // A wall of prefixes — a decoder that loops on 0xFE can run away here.
    exercise_parsers(&[0xFE; 64]);
    walk_stream(&[0xFE; 256]);
}

/// Compressed integers: every first byte, alone and with a short tail.
///
/// The top bits select a 1-, 2- or 4-byte form, so a first byte promising four
/// bytes over a one-byte buffer is the interesting case.
#[test]
fn compressed_int_first_byte_sweep_never_panics() {
    for b in 0u8..=255 {
        let _ = decode_compressed_uint(&[b]);
        let _ = decode_compressed_int(&[b]);
        let _ = decode_compressed_uint(&[b, 0xFF]);
        let _ = decode_compressed_int(&[b, 0xFF]);
        let _ = decode_compressed_uint(&[b, 0xFF, 0xFF]);
        let _ = decode_compressed_int(&[b, 0xFF, 0xFF]);
    }
    // Empty input must be handled too.
    let _ = decode_compressed_uint(&[]);
    let _ = decode_compressed_int(&[]);
}

/// Truncations of real CIL instruction encodings.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 5] = [
        &[0x28, 0x01, 0x00, 0x00, 0x0A],       // call <token>
        &[0x72, 0x01, 0x00, 0x00, 0x70],       // ldstr <token>
        &[0xFE, 0x09, 0x01, 0x00],             // ldarg <u16>
        &[0x38, 0x10, 0x00, 0x00, 0x00],       // br <int32>
        &[0x45, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // switch, 2 targets
    ];
    for seed in seeds {
        for cut in 0..=seed.len() {
            exercise_parsers(&seed[..cut]);
            walk_stream(&seed[..cut]);
        }
    }
}

/// `switch` (0x45) with adversarial target counts — the one CIL opcode whose
/// length is driven by a value read from the stream.
#[test]
fn switch_extreme_counts_never_panic() {
    for count in [0u32, 1, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
        let mut code = vec![0x45u8];
        code.extend_from_slice(&count.to_le_bytes());
        exercise_parsers(&code);
        walk_stream(&code);
        // With a couple of real targets present.
        code.extend_from_slice(&1i32.to_le_bytes());
        code.extend_from_slice(&2i32.to_le_bytes());
        exercise_parsers(&code);
        walk_stream(&code);
    }
}

/// Metadata blobs behind the `BSJB` magic with adversarial stream counts.
#[test]
fn metadata_adversarial_headers_never_panic() {
    for streams in [0u16, 1, 0x7FFF, u16::MAX] {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"BSJB");
        blob.extend_from_slice(&1u16.to_le_bytes()); // major
        blob.extend_from_slice(&1u16.to_le_bytes()); // minor
        blob.extend_from_slice(&0u32.to_le_bytes()); // reserved
        blob.extend_from_slice(&4u32.to_le_bytes()); // version length
        blob.extend_from_slice(b"v4.0");
        blob.extend_from_slice(&0u16.to_le_bytes()); // flags
        blob.extend_from_slice(&streams.to_le_bytes());
        let _ = CilMetadataReader::parse(blob.clone());
        for cut in 0..blob.len() {
            let _ = CilMetadataReader::parse(blob[..cut].to_vec());
        }
    }
}

/// Long uniform bodies — the stream walk must terminate on all of them.
#[test]
fn oversized_uniform_bodies_never_panic() {
    for fill in [0x00u8, 0x2A, 0x45, 0xFE, 0xFF] {
        for len in [256usize, 4096] {
            let buf = vec![fill; len];
            exercise_parsers(&buf);
            walk_stream(&buf);
        }
    }
}
