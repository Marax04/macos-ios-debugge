//! FindCrypt-style cryptographic constant scanner.
//!
//! Mirrors what IDA's `FindCrypt` plugin reports: scans a buffer for known
//! crypto magic numbers (SHA IVs, AES tables, TEA delta, `ChaCha` sigma, ...).
//! Reports every byte-offset hit so the triage pipeline can flag binaries
//! that embed crypto primitives even when imports are stripped.

use serde::{Deserialize, Serialize};

/// Endianness in which a u32/u64 anchor was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    /// little-endian
    Le,
    /// big-endian
    Be,
    /// raw byte sequence — endianness not meaningful
    Raw,
}

/// What kind of constant matched (lets callers weight hits — a full S-box
/// anchor is much stronger evidence than a single u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchKind {
    /// N consecutive u32 anchor words (e.g. SHA-256 H0..H7).
    U32Sequence,
    /// Byte anchor (e.g. first 32 bytes of AES S-box).
    ByteAnchor,
    /// A literal ASCII string constant (`ChaCha20` sigma, "expand 32-byte k").
    AsciiLiteral,
    /// RC4-style 0..255 ascending byte ramp.
    BytePattern,
}

/// One match produced by [`scan`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHit {
    /// e.g. "SHA-256 H0..H7", "AES S-box", "TEA delta", "`ChaCha20` sigma 32".
    pub algo: &'static str,
    /// File-offset of the first byte of the matched sequence.
    pub address: usize,
    /// Strength/category of the anchor.
    pub match_kind: MatchKind,
    /// Endianness for word-anchored hits.
    pub endianness: Endianness,
}

// ---------------------------------------------------------------------------
// constant database
// ---------------------------------------------------------------------------

// SHA-256 initial hash values H0..H7.
const SHA256_H: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

// First 8 words of SHA-256 round constants K.
const SHA256_K8: [u32; 8] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
];

// SHA-1 / MD5 IV (MD5 is the first four).
const SHA1_IV: [u32; 5] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0,
];

// First 32 bytes of AES forward S-box — long enough to be unique, short
// enough to keep this file small.
const AES_SBOX_32: [u8; 32] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
];

// First 32 bytes of AES inverse S-box.
const AES_INV_SBOX_32: [u8; 32] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
];

// AES Rcon (first 10 entries) — the trailing 0x1b 0x36 is the unambiguous tail.
const AES_RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

// TEA / XTEA delta — single u32 is weak evidence, so we scan it but tag it.
const TEA_DELTA: u32 = 0x9e37_79b9;

// ChaCha20 / Salsa20 sigma constants.
const CHACHA_SIGMA_32: &[u8] = b"expand 32-byte k";
const CHACHA_SIGMA_16: &[u8] = b"expand 16-byte k";

// CRC32 (IEEE) table head — recognisable because the entries are derived,
// not arbitrary.
const CRC32_TABLE_HEAD: [u32; 3] = [0x7707_3096, 0xee0e_612c, 0x076d_c419];

// Blowfish P-array first words (derived from the fractional part of π).
const BLOWFISH_P_HEAD: [u32; 2] = [0x243f_6a88, 0x85a3_08d3];

// Camellia key schedule sigma constants (six 64-bit values derived from √2, √3, …).
const CAMELLIA_SIGMA: [u64; 6] = [
    0xa09e_667f_3bcc_908b,
    0xb67a_e858_4caa_73b2,
    0xc6ef_372f_e94f_82be,
    0x54ff_53a5_f1d3_6f1c,
    0x10e5_27fa_de68_2d1d,
    0xb056_88c2_b3e6_c1fd,
];

// Twofish q0/q1 permutation heads — 16 bytes is enough to be collision-free.
const TWOFISH_Q0_HEAD: [u8; 16] = [
    0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76,
    0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
];
const TWOFISH_Q1_HEAD: [u8; 16] = [
    0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8,
    0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
];

// RC5/RC6 magic words derived from e and φ; P32 == TEA delta so require both.
const RC5_P32: u32 = 0xb7e1_5163;
const RC5_Q32: u32 = 0x9e37_79b9;

// SHA-512 initial hash values H0..H7.
const SHA512_H: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

// First four Keccak/SHA-3 round constants (ι step); the sequence is unique
// enough — a full 24-constant match would be overkill given the prefix alone
// is derived from LFSR outputs.
const KECCAK_RC4: [u64; 4] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
];

// GOST 28147-89 default S-box (CryptoPro set), first 32 bytes.
const GOST_SBOX_32: [u8; 32] = [
    0x04, 0x0a, 0x09, 0x02, 0x0d, 0x08, 0x00, 0x0e,
    0x06, 0x0b, 0x01, 0x0c, 0x07, 0x0f, 0x05, 0x03,
    0x0e, 0x0b, 0x04, 0x0c, 0x06, 0x0d, 0x0f, 0x0a,
    0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09,
];

// ---------------------------------------------------------------------------
// scanner
// ---------------------------------------------------------------------------

/// Scan `buf` for every constant in the database; returns all hits.
#[must_use]
pub fn scan(buf: &[u8]) -> Vec<CryptoHit> {
    let mut hits = Vec::new();

    scan_u32_sequence(buf, &SHA256_H, "SHA-256 H0..H7", &mut hits);
    scan_u32_sequence(buf, &SHA256_K8, "SHA-256 K[0..8]", &mut hits);
    scan_u32_sequence(buf, &SHA1_IV, "SHA-1 IV", &mut hits);
    // MD5 IV is the SHA-1 IV minus the last word — only emit it when SHA-1
    // didn't already catch the same offset to avoid double-reporting.
    scan_u32_sequence_excl(
        buf,
        &SHA1_IV[..4],
        "MD5 IV",
        &hits.iter().map(|h| h.address).collect::<Vec<_>>(),
        &mut hits,
    );
    scan_u32_sequence(buf, &CRC32_TABLE_HEAD, "CRC32 IEEE table head", &mut hits);
    scan_u32_sequence(buf, &BLOWFISH_P_HEAD, "Blowfish P-array head", &mut hits);

    scan_byte_anchor(buf, &AES_SBOX_32, "AES S-box", &mut hits);
    scan_byte_anchor(buf, &AES_INV_SBOX_32, "AES inv S-box", &mut hits);
    scan_byte_anchor(buf, &AES_RCON, "AES Rcon", &mut hits);

    scan_ascii(buf, CHACHA_SIGMA_32, "ChaCha20/Salsa20 sigma 32", &mut hits);
    scan_ascii(buf, CHACHA_SIGMA_16, "ChaCha20/Salsa20 sigma 16", &mut hits);

    scan_tea_delta(buf, &mut hits);
    scan_rc4_init(buf, &mut hits);

    scan_u64_sequence(buf, &CAMELLIA_SIGMA, "Camellia sigma", &mut hits);
    scan_byte_anchor(buf, &TWOFISH_Q0_HEAD, "Twofish q0", &mut hits);
    scan_byte_anchor(buf, &TWOFISH_Q1_HEAD, "Twofish q1", &mut hits);
    scan_rc5_rc6(buf, &mut hits);
    scan_u64_sequence(buf, &SHA512_H, "SHA-512 H0..H7", &mut hits);
    scan_u64_sequence(buf, &KECCAK_RC4, "Keccak/SHA-3 round constants", &mut hits);
    scan_byte_anchor(buf, &GOST_SBOX_32, "GOST 28147-89 S-box", &mut hits);

    hits
}

fn scan_u32_sequence(
    buf: &[u8],
    words: &[u32],
    algo: &'static str,
    out: &mut Vec<CryptoHit>,
) {
    scan_u32_sequence_excl(buf, words, algo, &[], out);
}

fn scan_u32_sequence_excl(
    buf: &[u8],
    words: &[u32],
    algo: &'static str,
    skip_addrs: &[usize],
    out: &mut Vec<CryptoHit>,
) {
    let need = words.len() * 4;
    if buf.len() < need {
        return;
    }
    let last = buf.len() - need;
    let mut i = 0;
    while i <= last {
        if !skip_addrs.contains(&i) {
            if u32_match(buf, i, words, false) {
                out.push(CryptoHit {
                    algo,
                    address: i,
                    match_kind: MatchKind::U32Sequence,
                    endianness: Endianness::Le,
                });
            }
            if u32_match(buf, i, words, true) {
                out.push(CryptoHit {
                    algo,
                    address: i,
                    match_kind: MatchKind::U32Sequence,
                    endianness: Endianness::Be,
                });
            }
        }
        i += 1;
    }
}

fn u32_match(buf: &[u8], at: usize, words: &[u32], be: bool) -> bool {
    for (k, w) in words.iter().enumerate() {
        let off = at + k * 4;
        let raw = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
        let got = if be {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        };
        if got != *w {
            return false;
        }
    }
    true
}

fn scan_byte_anchor(
    buf: &[u8],
    needle: &[u8],
    algo: &'static str,
    out: &mut Vec<CryptoHit>,
) {
    if buf.len() < needle.len() {
        return;
    }
    for i in 0..=buf.len() - needle.len() {
        if &buf[i..i + needle.len()] == needle {
            out.push(CryptoHit {
                algo,
                address: i,
                match_kind: MatchKind::ByteAnchor,
                endianness: Endianness::Raw,
            });
        }
    }
}

fn scan_ascii(buf: &[u8], needle: &[u8], algo: &'static str, out: &mut Vec<CryptoHit>) {
    if buf.len() < needle.len() {
        return;
    }
    for i in 0..=buf.len() - needle.len() {
        if &buf[i..i + needle.len()] == needle {
            out.push(CryptoHit {
                algo,
                address: i,
                match_kind: MatchKind::AsciiLiteral,
                endianness: Endianness::Raw,
            });
        }
    }
}

fn scan_tea_delta(buf: &[u8], out: &mut Vec<CryptoHit>) {
    // Single u32 is fragile, so require it to appear twice within a 64-byte
    // window — TEA/XTEA loops keep the delta in code and tables nearby.
    if buf.len() < 4 {
        return;
    }
    let le = TEA_DELTA.to_le_bytes();
    let be = TEA_DELTA.to_be_bytes();
    let mut le_addrs = Vec::new();
    let mut be_addrs = Vec::new();
    for i in 0..=buf.len() - 4 {
        if buf[i..i + 4] == le {
            le_addrs.push(i);
        }
        if buf[i..i + 4] == be {
            be_addrs.push(i);
        }
    }
    emit_clustered(&le_addrs, "TEA/XTEA delta", Endianness::Le, out);
    emit_clustered(&be_addrs, "TEA/XTEA delta", Endianness::Be, out);
}

fn emit_clustered(addrs: &[usize], algo: &'static str, e: Endianness, out: &mut Vec<CryptoHit>) {
    // Emit only addresses that have another match within 64 bytes — kills
    // accidental hits in resource data.
    for (i, a) in addrs.iter().enumerate() {
        let near = addrs.iter().enumerate().any(|(j, b)| i != j && b.abs_diff(*a) <= 64);
        if near {
            out.push(CryptoHit {
                algo,
                address: *a,
                match_kind: MatchKind::U32Sequence,
                endianness: e,
            });
        }
    }
}

fn scan_rc4_init(buf: &[u8], out: &mut Vec<CryptoHit>) {
    // RC4 schedules a 256-byte identity permutation. An ascending 0..=255
    // ramp is a very strong giveaway because random data essentially never
    // contains it.
    if buf.len() < 256 {
        return;
    }
    for i in 0..=buf.len() - 256 {
        // Cheap reject: first byte must be 0, byte 255 must be 0xff.
        if buf[i] != 0 || buf[i + 255] != 0xff {
            continue;
        }
        if buf[i..i + 256].iter().enumerate().all(|(k, b)| *b as usize == k) {
            out.push(CryptoHit {
                algo: "RC4 identity sbox init",
                address: i,
                match_kind: MatchKind::BytePattern,
                endianness: Endianness::Raw,
            });
        }
    }
}

fn scan_u64_sequence(
    buf: &[u8],
    words: &[u64],
    algo: &'static str,
    out: &mut Vec<CryptoHit>,
) {
    let need = words.len() * 8;
    if buf.len() < need {
        return;
    }
    let last = buf.len() - need;
    let mut i = 0;
    while i <= last {
        if u64_match(buf, i, words, false) {
            out.push(CryptoHit {
                algo,
                address: i,
                match_kind: MatchKind::U32Sequence,
                endianness: Endianness::Le,
            });
        }
        if u64_match(buf, i, words, true) {
            out.push(CryptoHit {
                algo,
                address: i,
                match_kind: MatchKind::U32Sequence,
                endianness: Endianness::Be,
            });
        }
        i += 1;
    }
}

fn u64_match(buf: &[u8], at: usize, words: &[u64], be: bool) -> bool {
    for (k, w) in words.iter().enumerate() {
        let off = at + k * 8;
        let raw: [u8; 8] = buf[off..off + 8].try_into().unwrap();
        let got = if be {
            u64::from_be_bytes(raw)
        } else {
            u64::from_le_bytes(raw)
        };
        if got != *w {
            return false;
        }
    }
    true
}

fn scan_rc5_rc6(buf: &[u8], out: &mut Vec<CryptoHit>) {
    // P32 == TEA delta, so a lone P32 is ambiguous; require P32 and Q32 both
    // appear within 16 bytes of each other to confirm RC5/RC6 specifically.
    if buf.len() < 4 {
        return;
    }
    // constants[0] = P32 patterns, constants[1] = Q32 patterns
    // within each: [0] = little-endian, [1] = big-endian
    let constants: [[[u8; 4]; 2]; 2] = [
        [RC5_P32.to_le_bytes(), RC5_P32.to_be_bytes()],
        [RC5_Q32.to_le_bytes(), RC5_Q32.to_be_bytes()],
    ];
    let mut addrs: [[Vec<usize>; 2]; 2] = [
        [Vec::new(), Vec::new()],
        [Vec::new(), Vec::new()],
    ];

    for i in 0..=buf.len() - 4 {
        for ci in 0..2_usize {
            for ei in 0..2_usize {
                if buf[i..i + 4] == constants[ci][ei] {
                    addrs[ci][ei].push(i);
                }
            }
        }
    }

    for &pa in &addrs[0][0] {
        if addrs[1][0].iter().any(|&qa| pa.abs_diff(qa) <= 16) {
            out.push(CryptoHit {
                algo: "RC5/RC6 P32+Q32",
                address: pa,
                match_kind: MatchKind::U32Sequence,
                endianness: Endianness::Le,
            });
        }
    }
    for &pa in &addrs[0][1] {
        if addrs[1][1].iter().any(|&qa| pa.abs_diff(qa) <= 16) {
            out.push(CryptoHit {
                algo: "RC5/RC6 P32+Q32",
                address: pa,
                match_kind: MatchKind::U32Sequence,
                endianness: Endianness::Be,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embed(prefix_len: usize, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0xaa_u8; prefix_len];
        buf.extend_from_slice(payload);
        buf.extend(std::iter::repeat(0x55_u8).take(64));
        buf
    }

    #[test]
    fn finds_sha256_iv_le() {
        let mut payload = Vec::new();
        for w in SHA256_H {
            payload.extend_from_slice(&w.to_le_bytes());
        }
        let buf = embed(17, &payload);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "SHA-256 H0..H7"
            && h.address == 17
            && h.endianness == Endianness::Le));
    }

    #[test]
    fn finds_sha1_iv_be_and_md5_iv_separately() {
        let mut payload = Vec::new();
        for w in SHA1_IV {
            payload.extend_from_slice(&w.to_be_bytes());
        }
        let buf = embed(8, &payload);
        let hits = scan(&buf);
        // SHA-1 hit must be present; MD5 must not double-report at the same
        // offset (the dedup in scan_u32_sequence_excl handles that).
        let sha1 = hits.iter().filter(|h| h.algo == "SHA-1 IV").count();
        let md5_same = hits
            .iter()
            .filter(|h| h.algo == "MD5 IV" && h.address == 8)
            .count();
        assert_eq!(sha1, 1);
        assert_eq!(md5_same, 0);
    }

    #[test]
    fn finds_aes_sbox_and_rcon() {
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(&AES_SBOX_32);
        buf.extend(std::iter::repeat(0u8).take(16));
        buf.extend_from_slice(&AES_RCON);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "AES S-box"));
        assert!(hits.iter().any(|h| h.algo == "AES Rcon"));
    }

    #[test]
    fn finds_chacha_sigma() {
        let buf = embed(5, CHACHA_SIGMA_32);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "ChaCha20/Salsa20 sigma 32"));
    }

    #[test]
    fn finds_rc4_identity() {
        let mut ramp = vec![0u8; 256];
        for k in 0..256 {
            ramp[k] = k as u8;
        }
        let buf = embed(3, &ramp);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "RC4 identity sbox init"));
    }

    #[test]
    fn empty_buffer_yields_no_hits() {
        assert!(scan(&[]).is_empty());
    }

    #[test]
    fn finds_camellia_sigma_le() {
        let mut payload = Vec::new();
        for w in CAMELLIA_SIGMA {
            payload.extend_from_slice(&w.to_le_bytes());
        }
        let buf = embed(4, &payload);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "Camellia sigma"
            && h.address == 4
            && h.endianness == Endianness::Le));
    }

    #[test]
    fn finds_twofish_q0_and_q1() {
        let mut buf = vec![0xbb_u8; 8];
        buf.extend_from_slice(&TWOFISH_Q0_HEAD);
        buf.extend(std::iter::repeat(0u8).take(4));
        buf.extend_from_slice(&TWOFISH_Q1_HEAD);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "Twofish q0"));
        assert!(hits.iter().any(|h| h.algo == "Twofish q1"));
    }

    #[test]
    fn finds_rc5_rc6_pair_but_not_solo_p32() {
        // Lone P32 (== TEA delta) must NOT trigger RC5/RC6.
        let mut buf_solo = vec![0u8; 8];
        buf_solo.extend_from_slice(&RC5_P32.to_le_bytes());
        buf_solo.extend(vec![0u8; 64]);
        let hits_solo = scan(&buf_solo);
        assert!(!hits_solo.iter().any(|h| h.algo == "RC5/RC6 P32+Q32"));

        // P32 and Q32 within 16 bytes must trigger.
        let mut buf_pair = vec![0u8; 4];
        buf_pair.extend_from_slice(&RC5_P32.to_le_bytes());
        buf_pair.extend_from_slice(&RC5_Q32.to_le_bytes());
        buf_pair.extend(vec![0u8; 64]);
        let hits_pair = scan(&buf_pair);
        assert!(hits_pair.iter().any(|h| h.algo == "RC5/RC6 P32+Q32"));
    }

    #[test]
    fn finds_sha512_iv_le() {
        let mut payload = Vec::new();
        for w in SHA512_H {
            payload.extend_from_slice(&w.to_le_bytes());
        }
        let buf = embed(7, &payload);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "SHA-512 H0..H7"
            && h.address == 7
            && h.endianness == Endianness::Le));
    }

    #[test]
    fn finds_keccak_round_constants_be() {
        let mut payload = Vec::new();
        for w in KECCAK_RC4 {
            payload.extend_from_slice(&w.to_be_bytes());
        }
        let buf = embed(3, &payload);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "Keccak/SHA-3 round constants"
            && h.endianness == Endianness::Be));
    }

    #[test]
    fn finds_gost_sbox() {
        let buf = embed(11, &GOST_SBOX_32);
        let hits = scan(&buf);
        assert!(hits.iter().any(|h| h.algo == "GOST 28147-89 S-box" && h.address == 11));
    }
}
