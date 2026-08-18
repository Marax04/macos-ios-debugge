//! Canonical CRC-16 primitives for the FLIRT stack.
//!
//! # Why this module exists
//!
//! Before it, the three FLIRT crates carried **eight** hand-written CRC-16
//! loops. They were not eight copies of one algorithm — they were three
//! different algorithms, and at least two of them were each described in their
//! own doc comment as "the CRC used by IDA FLIRT". Two functions that disagree
//! cannot both be right, and because a CRC is written by the generator and
//! re-checked by the matcher, a disagreement means signatures that never
//! validate.
//!
//! Every CRC in this stack must come from here. Each variant is named after its
//! catalogue entry (per the Rocksoft model / CRC `RevEng` catalogue) rather than
//! after where it happened to be used, so that "which one is the FLIRT one?" is
//! answered in exactly one place: [`flirt_tail`].
//!
//! # Variants
//!
//! | fn | poly | init | refin/refout | xorout | check(`"123456789"`) |
//! |---|---|---|---|---|---|
//! | [`mcrf4xx`] | 0x1021 (rev 0x8408) | 0xFFFF | yes | 0x0000 | 0x6F91 |
//! | [`x25`]     | 0x1021 (rev 0x8408) | 0xFFFF | yes | 0xFFFF | 0x906E |
//! | [`arc`]     | 0x8005 (rev 0xA001) | 0x0000 | yes | 0x0000 | 0xBB3D |
//! | [`cms`]     | 0x8005              | 0xFFFF | no  | 0x0000 | 0xAEE7 |

/// Reflected (LSB-first) bitwise CRC-16 core.
///
/// `poly` is the **reversed** polynomial; `init` the register seed; `xorout` is
/// applied to the final register value.
#[inline]
fn reflected(data: &[u8], poly: u16, init: u16, xorout: u16) -> u16 {
    let mut crc = init;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ poly } else { crc >> 1 };
        }
    }
    crc ^ xorout
}

/// Non-reflected (MSB-first) bitwise CRC-16 core.
#[inline]
fn forward(data: &[u8], poly: u16, init: u16, xorout: u16) -> u16 {
    let mut crc = init;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ poly } else { crc << 1 };
        }
    }
    crc ^ xorout
}

/// CRC-16/MCRF4XX — reversed poly 0x8408, init 0xFFFF, **no** final XOR.
///
/// This is the FLIRT tail CRC; prefer the intention-revealing alias
/// [`flirt_tail`] at FLIRT call sites.
#[must_use]
#[inline]
pub fn mcrf4xx(data: &[u8]) -> u16 {
    reflected(data, 0x8408, 0xFFFF, 0x0000)
}

/// CRC-16/X-25 — same poly and init as [`mcrf4xx`] but **with** final XOR
/// 0xFFFF, so `x25(d) == mcrf4xx(d) ^ 0xFFFF` for every input.
///
/// Kept only so the distinction stays explicit and testable: the two differ on
/// *every* input, and confusing them was a real defect in this codebase.
#[must_use]
#[inline]
pub fn x25(data: &[u8]) -> u16 {
    reflected(data, 0x8408, 0xFFFF, 0xFFFF)
}

/// CRC-16/ARC (a.k.a. CRC-16/IBM) — reversed poly 0xA001, init 0, no final XOR.
#[must_use]
#[inline]
pub fn arc(data: &[u8]) -> u16 {
    reflected(data, 0xA001, 0x0000, 0x0000)
}

/// CRC-16/IBM-3740, a.k.a. "CCITT-FALSE" — forward poly 0x1021, init 0xFFFF,
/// no final XOR.
///
/// Despite the name this is **not** the FLIRT tail CRC: FLIRT's is reflected
/// (see [`flirt_tail`]). Several `.pat` code paths used to verify tail CRCs with
/// this variant, which is why the distinction is spelled out here.
#[must_use]
#[inline]
pub fn ccitt_false(data: &[u8]) -> u16 {
    forward(data, 0x1021, 0xFFFF, 0x0000)
}

/// CRC-16/CMS — forward poly 0x8005, init 0xFFFF, no final XOR.
///
/// Used for the `.sig` container header checksum, which is our own format and
/// therefore independent of the FLIRT tail CRC.
#[must_use]
#[inline]
pub fn cms(data: &[u8]) -> u16 {
    forward(data, 0x8005, 0xFFFF, 0x0000)
}

/// The CRC over a function's stable tail bytes, as stored in a FLIRT signature.
///
/// **This is the single answer to "which CRC does FLIRT use?"** Generator and
/// matcher must both route through this alias; if the definition ever changes,
/// it changes for both at once.
///
/// Currently [`mcrf4xx`]. See `.claude/TODO.md` T1 for the one open question:
/// IDA's `flair/crc16.cpp` appears to special-case a zero-length buffer and
/// return 0, where this returns the init value 0xFFFF. That edge case has not
/// been settled against a real flair-produced `.sig`.
#[must_use]
#[inline]
pub fn flirt_tail(data: &[u8]) -> u16 {
    mcrf4xx(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── catalogue check values ──────────────────────────────────────────────
    // Each variant's published `check` value: the CRC of the ASCII bytes
    // "123456789". These are the standard conformance vectors; they pin the
    // parameters so a future "cleanup" cannot silently change an algorithm.

    const CHECK: &[u8] = b"123456789";

    #[test]
    fn mcrf4xx_matches_catalogue_check_value() {
        assert_eq!(mcrf4xx(CHECK), 0x6F91);
    }

    #[test]
    fn x25_matches_catalogue_check_value() {
        assert_eq!(x25(CHECK), 0x906E);
    }

    #[test]
    fn arc_matches_catalogue_check_value() {
        assert_eq!(arc(CHECK), 0xBB3D);
    }

    // ── the distinction that used to be a bug ───────────────────────────────

    #[test]
    fn x25_is_mcrf4xx_complemented_on_every_input() {
        // Exhaustive over all 1-byte inputs plus a few longer ones: the two
        // differ on *every* input, never coincidentally agree. This is why
        // using one where the other was meant is never a silent no-op.
        for b in 0..=255u8 {
            assert_eq!(x25(&[b]), mcrf4xx(&[b]) ^ 0xFFFF);
            assert_ne!(x25(&[b]), mcrf4xx(&[b]));
        }
        for d in [&b""[..], b"IDA", b"123456789", &[0u8; 64][..]] {
            assert_eq!(x25(d), mcrf4xx(d) ^ 0xFFFF);
        }
    }

    #[test]
    fn variants_are_mutually_distinct() {
        let d = b"the quick brown fox";
        let vals = [mcrf4xx(d), x25(d), arc(d), cms(d)];
        for i in 0..vals.len() {
            for j in (i + 1)..vals.len() {
                assert_ne!(vals[i], vals[j], "variants {i} and {j} collide");
            }
        }
    }

    // ── edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn empty_input_returns_init_xor_xorout() {
        assert_eq!(mcrf4xx(&[]), 0xFFFF); // init, no xorout — see TODO T1
        assert_eq!(x25(&[]), 0x0000); // init ^ xorout
        assert_eq!(arc(&[]), 0x0000);
        assert_eq!(cms(&[]), 0xFFFF);
    }

    #[test]
    fn flirt_tail_is_mcrf4xx() {
        // Guards the alias: if someone repoints `flirt_tail`, this test names
        // the decision instead of letting it happen by accident.
        for d in [&b""[..], b"IDA", CHECK, &[0xFFu8; 33][..]] {
            assert_eq!(flirt_tail(d), mcrf4xx(d));
        }
    }

    /// Every CRC entry point in this crate must agree with [`flirt_tail`].
    ///
    /// This is the regression guard for the defect that motivated the module:
    /// the stack had split into two internally-consistent halves — the
    /// signature *writer* and the `flirt_engine` validator used X-25, while the
    /// top-level `crc16_flirt` and the apply-side validator used MCRF4XX — so a
    /// signature written by this crate could never be validated by it.
    #[test]
    fn all_crate_entry_points_agree_with_flirt_tail() {
        let cases: [&[u8]; 6] = [
            b"", b"IDA", CHECK, &[0x55; 32], &[0x00; 16], &[0xFF; 33],
        ];
        for d in cases {
            let want = flirt_tail(d);
            assert_eq!(crate::crc16_flirt(d), want, "lib::crc16_flirt");
            assert_eq!(crate::flirt_engine::crc16_flirt(d), want, "flirt_engine::crc16_flirt");
            assert_eq!(
                crate::flirt_signature_writer::compute_crc16(d),
                want,
                "signature writer (table-driven) diverged from the bitwise definition"
            );
        }
    }

    /// Everything that verifies a **tail CRC** must use [`flirt_tail`].
    ///
    /// The first sweep of this defect found two competing algorithms; a second
    /// sweep found a third (CCITT-FALSE, forward poly 0x1021) hiding in the
    /// `.pat` verifier and the pattern matcher, because the initial grep only
    /// looked for reflected polynomials. This test enumerates the consumers
    /// explicitly so that "did I find them all?" stops being a grep question.
    #[test]
    fn every_tail_crc_verifier_uses_the_same_algorithm() {
        let cases: [&[u8]; 5] = [b"", b"IDA", CHECK, &[0x55; 32], &[0xE8; 5]];
        for d in cases {
            let want = flirt_tail(d);
            assert_eq!(
                crate::signature_matcher::PatternMatcher::crc16(d),
                want,
                "PatternMatcher::crc16 must verify tail CRCs with the FLIRT CRC"
            );
        }
    }

    /// CCITT-FALSE is a genuinely different algorithm and must stay distinct —
    /// keeping it available is fine, silently using it as the tail CRC is not.
    #[test]
    fn ccitt_false_is_not_the_flirt_tail_crc() {
        assert_eq!(ccitt_false(CHECK), 0x29B1); // catalogue check value
        assert_ne!(ccitt_false(CHECK), flirt_tail(CHECK));
    }

    /// The table-driven writer path and the bitwise path must agree on *all*
    /// single bytes, not just a handful of samples — a bad table entry would
    /// otherwise only show up for the one byte value nobody sampled.
    #[test]
    fn table_driven_writer_matches_bitwise_for_every_byte() {
        for b in 0..=255u8 {
            assert_eq!(
                crate::flirt_signature_writer::compute_crc16(&[b]),
                flirt_tail(&[b]),
                "table/bitwise mismatch at byte {b:#04x}"
            );
        }
    }

    #[test]
    fn is_deterministic_and_length_sensitive() {
        assert_eq!(flirt_tail(b"abc"), flirt_tail(b"abc"));
        // Trailing zeros must change the CRC (a CRC with a zero init would not
        // detect them; MCRF4XX's 0xFFFF init is precisely why it does).
        assert_ne!(flirt_tail(b"abc"), flirt_tail(b"abc\0"));
    }
}
