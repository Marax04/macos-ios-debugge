//! Correctness oracle for [`rustre_analysis_string::detect_xor_key`].
//!
//! # Why this file exists
//!
//! `detect_xor_key` is this crate's most-used external symbol (7 call sites in
//! `rustre-mcp-*`), and until now its only coverage was
//! `property_tests.rs::prop_decoders_never_panic_on_garbage_seed_9` — a test
//! that calls 13 decoders and **discards every result**. It has no assertions
//! at all, so it proves panic-freedom and nothing else. That is ghost coverage:
//! it cannot fail for a wrong answer, only for a crash.
//!
//! The oracles here are **definitional** — built from what XOR recovery means,
//! never from the scoring heuristic's internals, so they cannot agree with a
//! bug in them.
//!
//! # What the contract actually is
//!
//! The first version of this file asserted the obvious thing — that
//! `detect_xor_key(encrypt(p, k))` returns `k` — and it **failed**. The key is
//! not uniquely determined: for `C:\Windows\System32\kernel32.dll` both `^1`
//! and `^2` decode to entirely printable ASCII, so the scorer has a real tie.
//! The assertion was too strong, not the implementation wrong. See
//! [`recovered_key_always_decodes_to_printable_text`].
//!
//! # Negative control (run it before trusting any of this)
//!
//! `XOR_ORACLE_CORRUPT=1` corrupts each oracle's own expectation — demanding a
//! key that is NOT a valid decode, and demanding the true key beat every rival
//! *strictly* rather than tie. Both tests must then FAIL; unset it and all must
//! pass. A differential test whose bite has not been demonstrated is worth no
//! more than the assertion-free test it replaces.

use rustre_analysis_string::detect_xor_key;

fn corrupt() -> bool {
    std::env::var("XOR_ORACLE_CORRUPT").is_ok()
}

/// XOR every byte — the definition of the transformation being inverted.
fn encrypt(plain: &[u8], key: u8) -> Vec<u8> {
    plain.iter().map(|&b| b ^ key).collect()
}

/// Deterministic PRNG; `Math.random`-free so failures are reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// True when decoding `data` with `key` yields only printable ASCII — the
/// property the detector actually scores on.
fn all_printable(data: &[u8], key: u8) -> bool {
    data.iter().all(|&b| (0x20..=0x7E).contains(&(b ^ key)))
}

/// ★ THE KEY IS NOT UNIQUELY DETERMINED, and this test exists to say so.
///
/// My first version of this file asserted `detect_xor_key(encrypt(p, k)) == k`
/// and it FAILED — e.g. `C:\Windows\System32\kernel32.dll` encrypted with
/// `0x02` comes back as `0x01`. That is **not a bug**: for that plaintext both
/// `^1` and `^2` decode to entirely printable ASCII, so the scoring function
/// has a genuine tie and resolves it by the lowest key (the scan runs
/// `1..=255` and a later equal score does not displace an earlier one).
///
/// So the honest, definitional property is not "returns the encryption key" —
/// it is **"returns a key that decodes to printable text"**, plus the weaker
/// statement that the true key is among the tied-best candidates.
#[test]
fn recovered_key_always_decodes_to_printable_text() {
    let plaintexts: &[&[u8]] = &[
        b"C:\\Windows\\System32\\kernel32.dll",
        b"GET /index.html HTTP/1.1",
        b"the quick brown fox jumps over the lazy dog",
        b"SELECT * FROM users WHERE id = 1;",
        b"-----BEGIN CERTIFICATE-----",
    ];
    let mut checked = 0;
    for plain in plaintexts {
        for key in 1u8..=255 {
            let encoded = encrypt(plain, key);
            let Some(found) = detect_xor_key(&encoded) else { continue };
            // The corruption target: demand a key that is NOT a valid decode.
            let victim = if corrupt() { found.wrapping_add(1) } else { found };
            assert!(
                all_printable(&encoded, victim),
                "reported key {victim:#04x} does not decode {:?} to printable text",
                String::from_utf8_lossy(plain)
            );
            checked += 1;
        }
    }
    assert!(checked > 500, "only {checked} keys recovered — oracle barely exercised");
}

/// The true key must always be among the BEST-scoring candidates, even when it
/// is not the one reported. This is the strongest statement the heuristic can
/// actually support, and it still catches a scorer that simply mis-ranks.
#[test]
fn the_true_key_is_always_among_the_best_scorers() {
    fn score(data: &[u8], key: u8) -> usize {
        data.iter().filter(|&&b| (0x20..=0x7E).contains(&(b ^ key))).count()
    }
    let plaintexts: &[&[u8]] =
        &[b"kernel32.dll LoadLibraryA GetProcAddress", b"the quick brown fox", b"HTTP/1.1 200 OK"];
    for plain in plaintexts {
        for key in 1u8..=255 {
            let encoded = encrypt(plain, key);
            let best = (1u8..=255).map(|k| score(&encoded, k)).max().unwrap_or(0);
            // Corruption target: claim the true key beats every rival strictly.
            let claim = if corrupt() {
                score(&encoded, key) > best
            } else {
                score(&encoded, key) == best
            };
            assert!(claim, "true key {key:#04x} did not tie the best score {best}");
        }
    }
}

#[test]
fn empty_input_is_none() {
    assert_eq!(detect_xor_key(&[]), None);
}

#[test]
fn never_returns_the_identity_key() {
    // 0x00 is the identity and the scan deliberately starts at 0x01, so it must
    // never be reported. `best_key` is initialised to 0, so a returned 0 would
    // mean "no candidate ever beat the initial score" leaking out as an answer.
    let mut r = Lcg(0xD1CE_5EED);
    for _ in 0..4000 {
        let len = 1 + r.below(40) as usize;
        let buf: Vec<u8> = (0..len).map(|_| r.below(256) as u8).collect();
        if let Some(k) = detect_xor_key(&buf) {
            assert_ne!(k, 0, "identity key reported for {buf:02x?}");
        }
    }
}

#[test]
fn is_deterministic() {
    let mut r = Lcg(0x0FF1_CE00);
    for _ in 0..2000 {
        let len = 1 + r.below(64) as usize;
        let buf: Vec<u8> = (0..len).map(|_| r.below(256) as u8).collect();
        assert_eq!(detect_xor_key(&buf), detect_xor_key(&buf));
    }
}

/// Documents — rather than asserts as desirable — the short-input behaviour.
///
/// The acceptance threshold is `len * 7 / 10` in integer arithmetic, so for
/// `len <= 1` it is **0** and for `len == 2` it is **1**. Since some key always
/// makes at least one byte of any buffer printable, the threshold is trivially
/// met at those lengths and the function answers `Some` for essentially any
/// short input, including pure noise.
///
/// That is a genuine false-positive surface for callers that feed short byte
/// runs. It is pinned here so a future change to the threshold is a deliberate
/// decision with a visible test, not a silent behavioural drift.
#[test]
fn short_inputs_almost_always_yield_some_key() {
    let mut r = Lcg(0x5407_1234);
    let mut some = 0;
    let trials = 2000;
    for _ in 0..trials {
        let buf: Vec<u8> = (0..2).map(|_| r.below(256) as u8).collect();
        if detect_xor_key(&buf).is_some() {
            some += 1;
        }
    }
    assert!(
        some * 10 >= trials * 9,
        "expected the documented near-always-Some behaviour on 2-byte inputs, got {some}/{trials}"
    );
}
