//! The ENCODING SPACE every differential sweep in this crate generates.
//!
//! # Why this is shared
//!
//! Three oracles (register effects, memory effects, control transfers) each had
//! their own copy of the byte-pattern generator, and they drifted. Two holes
//! found on 2026-07-29 were purely generator holes, not lifter holes:
//!
//! * every copy built the register-form ModRM as `0xC0 | (reg << 3)`, fixing
//!   **rm = 0** — so seven of the eight rm values were never generated, and the
//!   `0F 01 /r` space (which encodes DIFFERENT instructions in rm: `VMCALL` C1,
//!   `VMXOFF` C4, `SKINIT` DE, `ERETS`/`ERETU` CA) was invisible;
//! * the map list stopped at the legacy `0F`/`0F 38`/`0F 3A` escapes, so the
//!   whole **VEX and EVEX** space — all of AVX and AVX-512, including a
//!   `VZEROUPPER` that clobbers sixteen vector registers — was never generated.
//!
//! Widening those two axes produced 36 real lifter defects. Keeping the space
//! in ONE place means the next axis is widened once for every oracle instead of
//! three times, and no oracle can be silently narrower than its siblings.
//!
//! # Axes deliberately NOT generated yet
//!
//! Stated rather than left implicit, because an unstated limit is where the
//! next defect will hide: EVEX masking (`aaa != 0`) and broadcast (`b = 1`),
//! LOCK and segment-override prefixes, the address-size override `0x67`, SIB
//! addressing (`rm = 100`), `mod = 01/10` displacement forms, and non-zero
//! immediates.

/// Byte stems that precede the opcode. Legacy forms are (prefix × map); VEX and
/// EVEX carry the map inside the prefix, so they are stems in their own right.
pub fn opcode_stems() -> Vec<Vec<u8>> {
    let mut stems: Vec<Vec<u8>> = Vec::new();
    // Legacy prefixes. Beyond the operand-size/repeat group, three more groups
    // change what the instruction MEANS rather than which one it is, and each
    // is a place a lifter can drop a fact:
    //  * `F0` LOCK — an atomic read-modify-write, not a plain one;
    //  * `64`/`65` FS/GS segment override — this lifter turns those into
    //    `__readgsqword`/`__readfsdword`, so the address it computes differs;
    //  * `67` address-size override — changes the width of the address
    //    computation itself.
    for pfx in [
        vec![],
        vec![0xF3u8],
        vec![0xF2],
        vec![0x66],
        vec![0xF0],
        vec![0x64],
        vec![0x65],
        vec![0x67],
    ] {
        for map in [vec![], vec![0x0Fu8], vec![0x0F, 0x38], vec![0x0F, 0x3A]] {
            let mut s = pfx.clone();
            s.extend_from_slice(&map);
            stems.push(s);
        }
    }
    // VEX2: C5 [R vvvv L pp]. R=1, vvvv=1111 means "no extension".
    for l in 0u8..2 {
        for pp in 0u8..4 {
            stems.push(vec![0xC5, 0b1111_1000 | (l << 2) | pp]);
        }
    }
    // VEX3: C4 [RXB mmmmm] [W vvvv L pp], mmmmm = 0F / 0F38 / 0F3A.
    for mmmmm in 1u8..4 {
        for w in 0u8..2 {
            for l in 0u8..2 {
                for pp in 0u8..4 {
                    stems.push(vec![
                        0xC4,
                        0b1110_0000 | mmmmm,
                        (w << 7) | 0b0111_1000 | (l << 2) | pp,
                    ]);
                }
            }
        }
    }
    // EVEX: 62 [P0][P1][P2], with P2 = [z L'L b V' aaa].
    //
    // The mask field `aaa` is swept because merge-masking changes WHETHER a
    // destination is written at all, which is exactly what the register-effect
    // oracle measures: under `aaa != 0` the decoder reports a CondWrite rather
    // than a Write, and a lifter that models the unmasked form only would be
    // claiming an unconditional definition. `z` (zeroing vs merging) and `b`
    // (broadcast / embedded rounding) are swept for the same reason — `b` also
    // changes the memory operand's size.
    let p2_variants: [u8; 4] = [
        0b0000_1000, // no mask, merge, no broadcast
        0b0000_1001, // k1, merging
        0b1000_1001, // k1, zeroing
        0b0001_1000, // broadcast / embedded rounding
    ];
    for mm in 1u8..4 {
        for w in 0u8..2 {
            for pp in 0u8..4 {
                for p2 in p2_variants {
                    stems.push(vec![0x62, 0b1111_0000 | mm, (w << 7) | 0b0111_1100 | pp, p2]);
                }
            }
        }
    }
    stems
}

/// Trailing bytes appended after the ModRM byte, supplying displacement, SIB
/// and immediate fields.
///
/// Sweeping a NON-ZERO filler as well as zero is not cosmetic. The VEX
/// four-operand instructions (`VBLENDVPS`, `VPBLENDVB`, the FMA4 family) select
/// their third source register from the HIGH NIBBLE of the imm8 — the `/is4`
/// byte. With an all-zero filler that register is always `xmm0`, so an operand
/// role that exists only there is never exercised. Non-zero immediates also
/// change shift counts and the `AAM`/`AAD` divisor.
pub fn fillers() -> [[u8; 14]; 2] {
    [[0u8; 14], [0x5Au8; 14]]
}

/// All 64 register-form ModRM bytes (`mod=11`, every reg × every rm), plus the
/// memory forms with the given `rm`.
pub fn modrms(mem_rm: u8) -> Vec<u8> {
    (0u8..8)
        .flat_map(|reg| (0u8..8).map(move |rm| 0xC0 | (reg << 3) | rm))
        .chain((0u8..8).map(|reg| (reg << 3) | mem_rm))
        // `mod=01` and `mod=10` (8- and 32-bit displacement) and `rm=100` (SIB)
        // are DIFFERENT addressing forms, not decorations: `[rbx+disp]` and
        // `[base+index*scale]` are computed by different code paths in the
        // lifter than the bare `[rbx]` the memory form above produces. The
        // trailing zero bytes the sweeps append supply the displacement and SIB
        // byte, so no operand is truncated.
        .chain((0u8..8).map(|reg| 0b0100_0000 | (reg << 3) | mem_rm))
        .chain((0u8..8).map(|reg| 0b1000_0000 | (reg << 3) | mem_rm))
        .chain((0u8..8).map(|reg| (reg << 3) | 0b100))
        .chain((0u8..8).map(|reg| 0b0100_0000 | (reg << 3) | 0b100))
        .collect()
}
