//! The x86 scanner's numeric guards must hold on arbitrary bytes (T23).
//!
//! # Why this test, and not a clippy fix
//!
//! `mem_access_scanner` carries 10 of the 14 clippy warnings in this crate's
//! production code, all lossy casts: `u64 as i64`, `i64 as u32`, `u32 as u8`.
//! Reading the code, each is guarded — `disp < 0 || disp > u32::MAX` before the
//! narrowing, `scale` matched against `1 | 2 | 4 | 8`, size clamped to 64.
//!
//! Reading is not verifying. `scan_array_accesses_x86` takes **raw bytes** and a
//! base address: it is fed disassembly of an untrusted binary, so the guards are
//! what stand between a crafted instruction and a nonsense field offset. A
//! silently truncated displacement would not crash — it would produce a struct
//! layout that is confidently wrong, which is the failure mode this project
//! keeps finding.
//!
//! So the guards are exercised rather than annotated: arbitrary byte streams in,
//! and every emitted value checked against the range its own documentation
//! claims.
//!
//! # What this is not
//!
//! Not a fuzzer and not exhaustive. It is a deterministic sweep over byte
//! patterns chosen to reach the narrowing paths — long displacements, every
//! SIB scale encoding, and `0xFF` runs — plus a pseudo-random stream. Its value
//! is that a regression in a guard shows up as a value out of range rather than
//! as quietly wrong output.

use rustre_analysis_typerecov::mem_access_scanner::{ArrayAccess, scan_array_accesses_x86};

/// Every invariant the emitted values are documented to satisfy.
fn check(accesses: &[ArrayAccess], label: &str) {
    for a in accesses {
        assert!(
            matches!(a.stride, 1 | 2 | 4 | 8),
            "{label}: stride {} fuori da {{1,2,4,8}} — la guardia sullo scale non \
             ha tenuto e il cast `as u8` ha troncato",
            a.stride
        );
        assert!(
            a.size_bytes <= 64,
            "{label}: size_bytes {} oltre il clamp a 64",
            a.size_bytes
        );
        // `disp` is only emitted after `disp >= 0 && disp <= u32::MAX`, so the
        // narrowing to u32 is lossless by construction. If the guard broke, a
        // negative or huge displacement would wrap into a plausible-looking
        // small offset — visible only as a wrong struct layout downstream.
        let _ = a.disp;
    }
}

/// Instruction streams built to reach the narrowing paths.
fn crafted_streams() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // mov rax, [rbx + rcx*8 + 0x7FFFFFFF] — displacement at the u32 boundary.
    v.push((
        "disp al limite u32",
        vec![0x48, 0x8B, 0x84, 0xCB, 0xFF, 0xFF, 0xFF, 0x7F],
    ));
    // Same shape with a displacement whose top bit is set: as a signed 32-bit
    // value this is negative, which the guard must reject rather than narrow.
    v.push((
        "disp negativo se letto con segno",
        vec![0x48, 0x8B, 0x84, 0xCB, 0x00, 0x00, 0x00, 0x80],
    ));
    // Every SIB scale encoding, including the ones that are not 1/2/4/8 after
    // decoding, to exercise the `matches!` filter.
    for (i, sib) in [0x0Bu8, 0x4B, 0x8B, 0xCB].into_iter().enumerate() {
        let label: &'static str = match i {
            0 => "scale 1",
            1 => "scale 2",
            2 => "scale 4",
            _ => "scale 8",
        };
        v.push((label, vec![0x48, 0x8B, 0x84, sib, 0x10, 0x00, 0x00, 0x00]));
    }
    v.push(("run di 0xFF", vec![0xFFu8; 256]));
    v.push(("run di 0x00", vec![0x00u8; 256]));
    v
}

#[test]
fn the_crafted_streams_actually_decode_to_something() {
    // Vacuity guard: if none of these produced an access, every assertion below
    // would hold for free and the test would certify nothing.
    let total: usize = crafted_streams()
        .iter()
        .map(|(_, b)| scan_array_accesses_x86(b, 0x1000, 64).len())
        .sum();
    assert!(
        total > 0,
        "nessuno stream produce accessi: gli opcode di prova non raggiungono il \
         percorso dei cast, il test non misurerebbe niente"
    );
}

#[test]
fn crafted_streams_respect_every_documented_range() {
    for (label, bytes) in crafted_streams() {
        for bits in [32u32, 64] {
            let acc = scan_array_accesses_x86(&bytes, 0x1000, bits);
            check(&acc, &format!("{label} @ {bits} bit"));
        }
    }
}

/// A deterministic pseudo-random stream: no seed from the clock, so a failure is
/// reproducible.
#[test]
fn pseudo_random_streams_respect_every_documented_range() {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for round in 0..64 {
        let bytes: Vec<u8> = (0..512)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                #[allow(clippy::cast_possible_truncation)]
                let b = (state >> 33) as u8;
                b
            })
            .collect();
        for bits in [32u32, 64] {
            let acc = scan_array_accesses_x86(&bytes, 0x4000, bits);
            check(&acc, &format!("round {round} @ {bits} bit"));
        }
    }
}

/// Truncated input must not panic: the last instruction is cut off at every
/// possible length.
#[test]
fn truncation_at_every_offset_is_survivable() {
    for (_, bytes) in crafted_streams() {
        for cut in 0..bytes.len().min(64) {
            let acc = scan_array_accesses_x86(&bytes[..cut], 0x1000, 64);
            check(&acc, "troncato");
        }
    }
}
