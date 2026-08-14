//! Randomized property / oracle tests for scanners, decoders and metrics.
//!
//! Every test here is deterministic: the PRNG is a fixed-seed xorshift64*, so a
//! failure is always reproducible from the seed cited in the test name.

#![cfg(test)]

use crate::similarity;
use crate::string_decoder;
use crate::{Address, FoundString, StringEncoding, StringScanner, StringScannerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic PRNG (xorshift64*) — no new dependencies.
// ─────────────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// Adversarial buffer generator: mixes pure noise, printable runs, NUL bytes,
/// UTF-16 lookalikes, and truncated multi-byte UTF-8 sequences (cut mid-sequence).
fn adversarial_buffer(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        match rng.below(8) {
            0 => out.push(0),
            1 => out.push(rng.byte()),
            2 => {
                // printable ASCII run
                let n = 1 + rng.below(12);
                for _ in 0..n {
                    out.push(0x20 + (rng.byte() % 0x5F));
                }
            }
            3 => {
                // UTF-16LE-looking run: printable, 0
                let n = 1 + rng.below(8);
                for _ in 0..n {
                    out.push(0x20 + (rng.byte() % 0x5F));
                    out.push(0);
                }
            }
            4 => {
                // a truncated multi-byte UTF-8 lead byte (cut mid-sequence)
                out.push(*[0xC2u8, 0xE0, 0xF0, 0xF4, 0xED].get(rng.below(5)).unwrap_or(&0xC2));
            }
            5 => {
                // valid 2-byte UTF-8
                out.push(0xC3);
                out.push(0x80 | (rng.byte() & 0x3F));
            }
            6 => {
                // Pascal-ish: length prefix then that many printables
                let n = rng.below(20) as u8;
                out.push(n);
                for _ in 0..n {
                    out.push(0x20 + (rng.byte() % 0x5F));
                }
            }
            _ => out.push(rng.byte() & 0x7F),
        }
    }
    out.truncate(len.max(0));
    out
}

fn configs() -> Vec<StringScannerConfig> {
    vec![
        StringScannerConfig::default(),
        StringScannerConfig::fast(),
        StringScannerConfig::all_encodings(),
        StringScannerConfig {
            min_length: 1,
            require_null_terminator: false,
            ..StringScannerConfig::default()
        },
        StringScannerConfig {
            min_length: 2,
            allow_high_ascii: true,
            require_null_terminator: false,
            ..StringScannerConfig::all_encodings()
        },
    ]
}

const BASE: Address = Address(0x1000);

fn offset_of(s: &FoundString) -> usize {
    usize::try_from(s.address.0 - BASE.0).expect("address below base")
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 1 — scanners never panic, never read out of bounds, and every
// reported string lies wholly inside the buffer.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_scanners_report_in_bounds_seed_1() {
    let mut rng = Rng::new(1);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 200);
        for cfg in configs() {
            let sc = StringScanner::new(cfg);
            let mut all = sc.scan(BASE, &buf);
            all.extend(sc.scan_pascal_strings(BASE, &buf));
            for s in &all {
                let off = offset_of(s);
                assert!(off <= buf.len(), "offset {off} past buffer {}", buf.len());
                assert!(
                    off + s.length <= buf.len(),
                    "string at {off} len {} escapes buffer {} ({:?})",
                    s.length,
                    buf.len(),
                    s.value
                );
                assert!(s.length >= s.value.len().min(s.length));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 2 — SOUNDNESS ORACLE: a reported ASCII string is genuinely present
// at the reported offset, byte-for-byte.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_ascii_strings_are_really_there_seed_2() {
    let mut rng = Rng::new(2);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 200);
        for cfg in configs() {
            let allow_high = cfg.allow_high_ascii;
            let sc = StringScanner::new(cfg);
            for s in sc.scan_ascii(BASE, &buf) {
                let off = offset_of(s_ref(&s));
                // The reported run occupies `length` bytes (minus any NUL).
                let raw_len = s.length - usize::from(s.is_null_terminated);
                let raw = &buf[off..off + raw_len];
                let expect: String = if allow_high {
                    raw.iter().map(|&b| b as char).collect()
                } else {
                    String::from_utf8_lossy(raw).into_owned()
                };
                assert_eq!(expect, s.value, "reported ASCII text absent at offset {off}");
                assert_eq!(s.char_count, raw_len, "char_count != accepted byte count");
                for &b in raw {
                    assert!(
                        (0x20..0x7F).contains(&b) || (allow_high && b >= 0x80),
                        "non-printable byte {b:#04x} inside reported ASCII string"
                    );
                }
                if s.is_null_terminated {
                    assert_eq!(buf[off + raw_len], 0, "claimed NUL terminator missing");
                }
            }
        }
    }
}

const fn s_ref(s: &FoundString) -> &FoundString {
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 3 — COMPLETENESS ORACLE for scan_ascii: an independent brute-force
// scan finds exactly the same set of strings.
// ─────────────────────────────────────────────────────────────────────────────

fn ascii_oracle(buf: &[u8], cfg: &StringScannerConfig) -> Vec<(usize, String, bool)> {
    let printable =
        |b: u8| (0x20..0x7F).contains(&b) || (cfg.allow_high_ascii && b >= 0x80);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if !printable(buf[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < buf.len() && printable(buf[i]) {
            i += 1;
        }
        let nul = i < buf.len() && buf[i] == 0;
        let len = i - start;
        if (nul || !cfg.require_null_terminator)
            && len >= cfg.min_length
            && len <= cfg.max_length
        {
            let run = &buf[start..i];
            let value: String = if cfg.allow_high_ascii {
                run.iter().map(|&b| b as char).collect()
            } else {
                String::from_utf8_lossy(run).into_owned()
            };
            out.push((start, value, nul));
        }
        if i < buf.len() {
            i += 1;
        }
    }
    out
}

#[test]
fn prop_ascii_matches_bruteforce_oracle_seed_3() {
    let mut rng = Rng::new(3);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 160);
        for cfg in configs() {
            let expect = ascii_oracle(&buf, &cfg);
            let got: Vec<(usize, String, bool)> = StringScanner::new(cfg)
                .scan_ascii(BASE, &buf)
                .into_iter()
                .map(|s| {
                    (
                        usize::try_from(s.address.0 - BASE.0).unwrap(),
                        s.value,
                        s.is_null_terminated,
                    )
                })
                .collect();
            assert_eq!(got, expect, "scan_ascii disagrees with brute-force oracle");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 4 — UTF-16LE strings re-encode to the exact bytes at the offset.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_utf16le_reencodes_to_source_bytes_seed_4() {
    let mut rng = Rng::new(4);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 200);
        for cfg in configs() {
            let sc = StringScanner::new(cfg);
            for s in sc.scan_utf16_le(BASE, &buf) {
                let off = offset_of(&s);
                let units: Vec<u16> = s.value.encode_utf16().collect();
                assert_eq!(units.len(), s.char_count, "char_count != code unit count");
                assert!(off + units.len() * 2 <= buf.len());
                for (k, u) in units.iter().enumerate() {
                    let got = u16::from_le_bytes([buf[off + k * 2], buf[off + k * 2 + 1]]);
                    assert_eq!(got, *u, "UTF-16LE unit {k} mismatch at offset {off}");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 5 — UTF-8 strings are the literal bytes at the offset.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_utf8_bytes_are_verbatim_seed_5() {
    let mut rng = Rng::new(5);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 200);
        for cfg in configs() {
            let sc = StringScanner::new(cfg);
            for s in sc.scan_utf8(BASE, &buf) {
                let off = offset_of(&s);
                let n = s.value.len();
                assert!(off + n <= buf.len());
                assert_eq!(&buf[off..off + n], s.value.as_bytes(), "UTF-8 bytes differ");
                assert_eq!(s.char_count, s.value.chars().count());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 6 — Pascal strings: prefix byte equals length, payload matches.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_pascal_prefix_matches_payload_seed_6() {
    let mut rng = Rng::new(6);
    for _ in 0..800 {
        let buf = adversarial_buffer(&mut rng, 200);
        for cfg in configs() {
            let sc = StringScanner::new(cfg);
            for s in sc.scan_pascal_strings(BASE, &buf) {
                let off = offset_of(&s);
                let n = s.value.len();
                assert_eq!(buf[off] as usize, n, "Pascal prefix != payload length");
                assert_eq!(s.length, n + 1);
                assert_eq!(&buf[off + 1..off + 1 + n], s.value.as_bytes());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 7 — read_cstring is total (never panics) and truthful for every
// address in and around the buffer.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_read_cstring_total_and_truthful_seed_7() {
    let mut rng = Rng::new(7);
    let sc = StringScanner::default();
    for _ in 0..500 {
        let buf = adversarial_buffer(&mut rng, 120);
        for probe in 0..(buf.len() + 8) {
            let addr = Address(BASE.0 + probe as u64);
            if let Some(s) = sc.read_cstring(BASE, &buf, addr) {
                assert_eq!(offset_of(&s), probe);
                assert!(probe + s.length <= buf.len());
                assert_eq!(buf[probe + s.length - 1], 0, "cstring not NUL-terminated");
                assert_eq!(
                    String::from_utf8_lossy(&buf[probe..probe + s.length - 1]),
                    s.value
                );
            }
        }
        // addresses below base must not panic
        assert!(sc.read_cstring(BASE, &buf, Address(0)).is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 8 — decoders round-trip where invertible, never panic on garbage.
// ─────────────────────────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63]);
        out.push(A[(n >> 12) as usize & 63]);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] } else { b'=' });
    }
    out
}

#[test]
fn prop_base64_hex_url_rot13_roundtrip_seed_8() {
    let mut rng = Rng::new(8);
    for _ in 0..1000 {
        let n = rng.below(48);
        let data: Vec<u8> = (0..n).map(|_| rng.byte()).collect();

        // base64 round-trip
        let enc = base64_encode(&data);
        assert_eq!(
            string_decoder::base64_decode_bytes(&enc).as_deref(),
            Some(data.as_slice()),
            "base64 round-trip failed"
        );

        // hex round-trip
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let text: String = data.iter().map(|&b| char::from(b & 0x7F)).collect();
        let hex_of_text: String = text.bytes().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            string_decoder::decode_hex_string(hex_of_text.as_bytes()).as_deref(),
            Some(text.as_str()),
            "hex round-trip failed"
        );
        // decoding arbitrary hex must not panic
        let _ = string_decoder::decode_hex_string(hex.as_bytes());

        // ROT-13 is an involution on any byte slice
        let once = string_decoder::rot13_decode(&data);
        let twice = string_decoder::rot13_decode(once.as_bytes());
        let orig: String = data.iter().map(|&b| char::from(b)).collect();
        if data.iter().all(u8::is_ascii) {
            assert_eq!(twice, orig, "rot13 is not an involution");
        }

        // URL encoding round-trip on ASCII text
        let urlenc: String = text
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        assert_eq!(
            string_decoder::decode_url_encoded(urlenc.as_bytes()).as_deref(),
            Some(text.as_str()),
            "url round-trip failed"
        );
    }
}

#[test]
fn prop_decoders_never_panic_on_garbage_seed_9() {
    let mut rng = Rng::new(9);
    for _ in 0..1500 {
        let buf = adversarial_buffer(&mut rng, 96);
        let _ = string_decoder::base64_decode_bytes(&buf);
        let _ = string_decoder::decode_base64(&buf);
        let _ = string_decoder::decode_hex_string(&buf);
        let _ = string_decoder::decode_url_encoded(&buf);
        let _ = string_decoder::rot13_decode(&buf);
        let _ = string_decoder::decode_ascii(&buf);
        let _ = string_decoder::decode_utf16_le(&buf);
        let _ = string_decoder::decode_utf16_be(&buf);
        let _ = string_decoder::decode_latin1(&buf);
        let _ = string_decoder::decode_cp1252(&buf);
        let _ = string_decoder::decode_shift_jis_approx(&buf);
        let _ = string_decoder::detect_encoding(&buf);
        let _ = crate::detect_xor_key(&buf);
        for key in [0u8, 1, 0x5A, 0xFF] {
            let _ = crate::decrypt::decrypt_xor_byte(&buf, key);
        }
        for n in [0u8, 1, 13, 25, 200] {
            let _ = crate::decrypt::decrypt_rot_n(&buf, n);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 10 — XOR decryption is an exact involution.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_xor_is_involution_seed_10() {
    let mut rng = Rng::new(10);
    for _ in 0..1000 {
        let n = rng.below(64);
        let data: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let key = rng.byte();
        let once = crate::decrypt::decrypt_xor_byte(&data, key);
        let twice = crate::decrypt::decrypt_xor_byte(&once.plaintext_bytes, key);
        assert_eq!(twice.plaintext_bytes, data, "single-byte XOR is not an involution");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 11 — entropy in [0, 8] and similarity metrics in [0, 1], for all
// inputs including empty.
// ─────────────────────────────────────────────────────────────────────────────

fn random_string(rng: &mut Rng) -> String {
    let n = rng.below(24);
    (0..n)
        .map(|_| match rng.below(4) {
            0 => char::from(0x20 + (rng.byte() % 0x5F)),
            1 => 'é',
            2 => '漢',
            _ => char::from(b'a' + rng.byte() % 26),
        })
        .collect()
}

#[test]
fn prop_entropy_and_similarity_in_range_seed_11() {
    let mut rng = Rng::new(11);
    for _ in 0..1200 {
        let a = random_string(&mut rng);
        let b = random_string(&mut rng);

        let fs = FoundString {
            address: BASE,
            length: a.len(),
            encoding: StringEncoding::Ascii,
            value: a.clone(),
            char_count: a.chars().count(),
            is_null_terminated: false,
            xref_count: 0,
        };
        let e = fs.entropy();
        assert!(
            (0.0..=8.0).contains(&e) && e.is_finite(),
            "entropy {e} out of [0,8] for {a:?}"
        );

        for (name, v) in [
            ("levenshtein_similarity", similarity::levenshtein_similarity(&a, &b)),
            ("lcs_similarity", similarity::lcs_similarity(&a, &b)),
            ("jaro", similarity::jaro(&a, &b)),
            ("jaro_winkler", similarity::jaro_winkler(&a, &b)),
            ("jaccard_ngram", similarity::jaccard_ngram(&a, &b, 3)),
        ] {
            assert!(
                (0.0..=1.0).contains(&v) && v.is_finite(),
                "{name} = {v} out of [0,1] for {a:?} / {b:?}"
            );
        }

        // identity and symmetry
        assert!((similarity::jaro_winkler(&a, &a) - 1.0).abs() < 1e-9);
        assert_eq!(similarity::levenshtein(&a, &b), similarity::levenshtein(&b, &a));
        assert!(
            (similarity::jaro(&a, &b) - similarity::jaro(&b, &a)).abs() < 1e-9,
            "jaro not symmetric"
        );
        // triangle-ish sanity: distance bounded by longer length
        let d = similarity::levenshtein(&a, &b);
        assert!(d <= a.chars().count().max(b.chars().count()));
    }
    // empty inputs
    assert_eq!(similarity::levenshtein_similarity("", ""), 1.0);
    assert_eq!(similarity::lcs_similarity("", ""), 1.0);
    assert!((0.0..=1.0).contains(&similarity::jaro("", "")));
    assert!((0.0..=1.0).contains(&similarity::jaro_winkler("", "x")));
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 12 — clustering is deterministic and partitions its input.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_clustering_deterministic_seed_12() {
    let mut rng = Rng::new(12);
    for _ in 0..300 {
        let n = rng.below(12);
        let owned: Vec<String> = (0..n).map(|_| random_string(&mut rng)).collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        for thr in [0.0_f64, 0.3, 0.7, 1.0] {
            let a = similarity::cluster_strings(&refs, thr);
            let b = similarity::cluster_strings(&refs, thr);
            let key = |c: &[similarity::StringCluster]| -> Vec<Vec<String>> {
                c.iter().map(|x| x.members.clone()).collect()
            };
            assert_eq!(key(&a), key(&b), "cluster_strings not deterministic");
            let total: usize = a.iter().map(|c| c.members.len()).sum();
            assert_eq!(total, refs.len(), "clustering lost or duplicated strings");
            for c in &a {
                let coh = c.cohesion();
                assert!(
                    (0.0..=1.0).contains(&coh) && coh.is_finite(),
                    "cohesion {coh} out of range"
                );
            }
        }
        let _ = similarity::extract_template(&refs);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REGRESSION — minimised from prop_ascii_strings_are_really_there_seed_2.
//
// With `allow_high_ascii`, bytes >= 0x80 are accepted into the run but were
// decoded with `String::from_utf8_lossy`, collapsing every high byte into the
// same U+FFFD replacement char.  The reported `value` then no longer matched
// the bytes at `address` (and `char_count`/`value.len()` disagreed with the
// scanner's own `length`), so distinct byte runs decoded to identical strings.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn regression_high_ascii_value_is_byte_recoverable() {
    let cfg = StringScannerConfig {
        min_length: 2,
        allow_high_ascii: true,
        require_null_terminator: false,
        ..StringScannerConfig::default()
    };
    let buf = [0x80u8, 0x71, 0x00];
    let found = StringScanner::new(cfg).scan_ascii(BASE, &buf);
    assert_eq!(found.len(), 1);
    let s = &found[0];
    assert_eq!(s.value, "\u{80}q");
    assert_eq!(s.char_count, 2);
    assert_eq!(s.length, 3); // 2 bytes + NUL
    // Two distinct high bytes must not decode to the same string.
    let a = StringScanner::new(StringScannerConfig {
        min_length: 2,
        allow_high_ascii: true,
        require_null_terminator: false,
        ..StringScannerConfig::default()
    });
    let x = a.scan_ascii(BASE, &[0x80, 0x71, 0x00]);
    let y = a.scan_ascii(BASE, &[0x81, 0x71, 0x00]);
    assert_ne!(x[0].value, y[0].value, "distinct high bytes collapsed");
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 13 — NEW ORACLE for `detect_xor_key` (7 external call sites in
// rustre-mcp-*, previously covered only by "does not panic").
//
// Oracle straight from the doc-comment DEFINITION: "the key that would produce
// the most printable bytes (0x20–0x7E) when XOR-applied to every byte wins …
// returns None when no key produces a majority of printable output (>= 70%)."
// The oracle recomputes the printable histogram itself; it never mirrors the
// scan loop's bookkeeping (best_key/best_score/nul_bonus).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_detect_xor_key_is_argmax_printable_seed_13() {
    let mut rng = Rng::new(13);
    let printable_after = |data: &[u8], key: u8| -> usize {
        data.iter().filter(|&&b| (0x20..=0x7E).contains(&(b ^ key))).count()
    };

    let mut saw_some = 0usize;
    let mut saw_none = 0usize;
    let mut saw_tie = 0usize;

    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0x41],
        vec![0xFF; 40],
        b"plain ascii text with no xor at all".to_vec(),
    ];
    for key in [0x01u8, 0x0D, 0x20, 0x5A, 0x7F, 0x80, 0xFF] {
        cases.push(b"C:/Windows/System32/kernel32.dll".iter().map(|b| b ^ key).collect());
    }
    for _ in 0..1200 {
        cases.push(adversarial_buffer(&mut rng, 64));
    }

    for data in &cases {
        let got = crate::detect_xor_key(data);

        let best = (1u8..=255).map(|k| printable_after(data, k)).max().unwrap_or(0);
        let threshold = (data.len() * 7) / 10;
        let expect_some = !data.is_empty() && best >= threshold;

        assert_eq!(
            got.is_some(),
            expect_some,
            "detect_xor_key Some/None disagrees with definition: data={data:?} best={best} thr={threshold}"
        );
        if let Some(k) = got {
            assert_ne!(k, 0, "identity key 0 must never be reported");
            assert_eq!(
                printable_after(data, k),
                best,
                "returned key {k:#04x} is not an argmax of printable count (data={data:?})"
            );
            saw_some += 1;
        } else {
            saw_none += 1;
        }
        if (1u8..=255).filter(|&k| printable_after(data, k) == best).count() > 1 {
            saw_tie += 1;
        }
        assert_eq!(got, crate::detect_xor_key(data), "detect_xor_key not deterministic");
    }
    assert!(saw_some > 50, "generator never produced a decodable buffer ({saw_some})");
    assert!(saw_none > 50, "generator never produced an undecodable buffer ({saw_none})");
    assert!(saw_tie > 10, "generator never produced an argmax tie ({saw_tie})");
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 14 — NEW ORACLE for `shannon_entropy` (4 external call sites).
// Oracle from information theory, NOT from the implementation: entropy is
// invariant under permutation and under ANY bijective relabelling of the
// alphabet (e.g. XOR by a constant), it is exactly log2(n) for n equally
// frequent symbols, exactly 0 for a constant buffer, and lies in [0, 8].
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_shannon_entropy_information_theoretic_seed_14() {
    use crate::classify::shannon_entropy;
    let mut rng = Rng::new(14);

    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(shannon_entropy(&[7u8; 33]), 0.0, "constant buffer must have zero entropy");

    for n in [1usize, 2, 3, 4, 16, 256] {
        let mut b = Vec::new();
        for _ in 0..3 {
            for i in 0..n {
                b.push(u8::try_from(i).unwrap());
            }
        }
        let e = shannon_entropy(&b);
        let expect = (n as f64).log2();
        assert!((e - expect).abs() < 1e-9, "H of {n} uniform symbols = {e}, want {expect}");
    }

    let mut saw_empty = 0usize;
    let mut saw_max = 0usize;
    for _ in 0..1500 {
        let data = adversarial_buffer(&mut rng, 200);
        let e = shannon_entropy(&data);
        assert!((0.0..=8.0).contains(&e) && e.is_finite(), "entropy {e} out of [0,8]");
        if data.is_empty() {
            saw_empty += 1;
        }
        if e > 5.0 {
            saw_max += 1;
        }
        let mut rev = data.clone();
        rev.reverse();
        assert!((shannon_entropy(&rev) - e).abs() < 1e-9, "entropy not permutation-invariant");
        let key = rng.byte();
        let mapped: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
        assert!(
            (shannon_entropy(&mapped) - e).abs() < 1e-9,
            "entropy changed under XOR relabelling (key {key:#04x})"
        );
        let mut doubled = data.clone();
        doubled.extend_from_slice(&data);
        assert!((shannon_entropy(&doubled) - e).abs() < 1e-9, "entropy not scale-invariant");
    }
    assert!(saw_empty > 0, "generator never produced an empty buffer");
    assert!(saw_max > 100, "generator never produced a high-entropy buffer ({saw_max})");
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY 15 — NEW ORACLE for `extract_urls` / `extract_ips` (6 external call
// sites). Definition: a URL is an input whose value begins (case-insensitively)
// with a known scheme; an IPv4 is four dot-separated decimal octets 0..=255.
// Both soundness (nothing invented) and completeness (nothing missed).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_url_ip_extraction_sound_and_complete_seed_15() {
    use crate::classify::{extract_ips, extract_urls};
    const SCHEMES: [&str; 7] =
        ["https://", "http://", "ftp://", "ftps://", "file://", "ws://", "wss://"];

    let mut rng = Rng::new(15);
    let mk = |v: &str| FoundString {
        address: BASE,
        length: v.len(),
        encoding: StringEncoding::Ascii,
        value: v.to_owned(),
        char_count: v.chars().count(),
        is_null_terminated: true,
        xref_count: 0,
    };

    let mut saw_url = 0usize;
    let mut saw_ip = 0usize;
    let mut saw_neither = 0usize;

    for _ in 0..2000 {
        let mut values: Vec<String> = Vec::new();
        for _ in 0..(1 + rng.below(5)) {
            values.push(match rng.below(7) {
                0 => String::new(),
                1 => {
                    let s = SCHEMES[rng.below(SCHEMES.len())];
                    let s = if rng.below(2) == 0 { s.to_uppercase() } else { s.to_owned() };
                    let tail = ["host.example/x", "", "1.2.3.4", "a/b/c"][rng.below(4)];
                    format!("{s}{tail}")
                }
                2 => format!(
                    "{}.{}.{}.{}",
                    rng.below(300),
                    rng.below(300),
                    rng.below(300),
                    rng.below(300)
                ),
                3 => "  10.0.0.1  ".to_owned(),
                4 => "fe80:0:0:0:1".to_owned(),
                5 => "not a url http://late".to_owned(),
                _ => random_string(&mut rng),
            });
        }
        let founds: Vec<FoundString> = values.iter().map(|v| mk(v)).collect();

        let urls = extract_urls(&founds);
        let expect_urls: Vec<&String> = values
            .iter()
            .filter(|v| {
                let l = v.to_ascii_lowercase();
                SCHEMES.iter().any(|s| l.starts_with(s))
            })
            .collect();
        assert_eq!(
            urls.len(),
            expect_urls.len(),
            "extract_urls count differs from definition for {values:?}"
        );
        for (u, want) in urls.iter().zip(expect_urls) {
            assert_eq!(&u.url, want, "extract_urls invented or reordered a URL");
            let l = u.url.to_ascii_lowercase();
            assert!(
                l.starts_with(&format!("{}://", u.scheme)),
                "reported scheme {:?} is not the actual prefix of {:?}",
                u.scheme,
                u.url
            );
            let rest = &u.url[u.scheme.len() + 3..];
            let recomposed = format!(
                "{}{}",
                u.host.clone().unwrap_or_default(),
                u.path.clone().unwrap_or_default()
            );
            assert_eq!(recomposed, rest, "host+path does not recompose the URL remainder");
            assert_eq!(u.well_formed, !u.host.as_deref().unwrap_or("").is_empty());
            saw_url += 1;
        }

        let ips = extract_ips(&founds);
        for ip in &ips {
            assert!(
                values.iter().any(|v| v.trim() == ip.raw),
                "extract_ips invented {:?}",
                ip.raw
            );
            if let Some(o) = ip.ipv4_octets {
                assert!(!ip.is_ipv6);
                assert_eq!(
                    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
                    ip.raw,
                    "octets do not re-render to the reported text"
                );
                let want_private = matches!(o[0], 10 | 127)
                    || (o[0] == 169 && o[1] == 254)
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168);
                assert_eq!(ip.is_private, want_private, "wrong private/public for {:?}", ip.raw);
                saw_ip += 1;
            } else {
                assert!(ip.is_ipv6);
            }
        }
        let expect_v4 = values
            .iter()
            .filter(|v| {
                let p: Vec<&str> = v.trim().split('.').collect();
                p.len() == 4
                    && p.iter().all(|q| {
                        !q.is_empty()
                            && q.len() <= 3
                            && q.bytes().all(|c| c.is_ascii_digit())
                            && q.parse::<u16>().is_ok_and(|n| n <= 255)
                    })
            })
            .count();
        let got_v4 = ips.iter().filter(|i| i.ipv4_octets.is_some()).count();
        assert_eq!(got_v4, expect_v4, "extract_ips missed/added a dotted quad in {values:?}");

        if urls.is_empty() && ips.is_empty() {
            saw_neither += 1;
        }
    }
    assert!(saw_url > 200, "generator never produced URLs ({saw_url})");
    assert!(saw_ip > 200, "generator never produced IPv4s ({saw_ip})");
    assert!(saw_neither > 20, "generator never produced a negative case ({saw_neither})");
}
