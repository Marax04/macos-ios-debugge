//! A signature with no tail CRC and a short prefix is not evidence.
//!
//! # The measurement behind this knob
//!
//! On `sample3_rust.exe` against the 67 168-signature rust-stdlib database,
//! **238 of 240 renames came from signatures carrying no CRC at all**, and 199
//! had a prefix under 16 bytes. The 74.1% of the database that *does* carry a
//! CRC almost never matched — correctly, because their tails disagreed.
//!
//! So the surviving matches were overwhelmingly the weakest signatures. Sweeping
//! the threshold against the corpus PDB:
//!
//! | min bytes (no CRC) | renames | AGREE | DISAGREE | precision |
//! |---|---|---|---|---|
//! | 0 (off) | 240 | 18 | 10 | 64.3% |
//! | 16 | 40 | 15 | **2** | **88.2%** |
//! | 24 | 21 | 6 | **0** | 100% |
//! | 32 | 1 | 0 | 0 | n/a |
//!
//! 16 keeps 15 of the 18 correct names while cutting false positives from 10 to
//! 2. 24 is perfect but discards two thirds of the correct ones. The knob is
//! **off by default**: raising it removes matches, and silently changing which
//! functions get renamed is a correctness-visible change.

use rustre_flirt_apply::{FlirtScanner, FlirtSignature};

fn sig(name: &str, bytes: &[u8], crc_len: u16) -> FlirtSignature {
    FlirtSignature {
        bytes: bytes.to_vec(),
        mask: vec![0xff; bytes.len()],
        name: name.to_string(),
        lib_name: "testlib".into(),
        crc_offset: 0,
        crc_len,
        crc: 0,
    }
}

/// 24 bytes of distinctive code, plus a short 4-byte signature sharing its
/// opening bytes — the shape that produces a collision.
fn haystack() -> Vec<u8> {
    let mut v = vec![0x55, 0x48, 0x89, 0xE5];
    v.extend_from_slice(&[0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54]);
    v.extend_from_slice(&[0x53, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05]);
    v.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00]);
    v
}

#[test]
fn by_default_even_a_very_short_crcless_signature_matches() {
    // The historical behaviour, kept as the default so enabling the threshold
    // is a deliberate act rather than a surprise.
    let s = FlirtScanner::new_fast(vec![sig("short_fn", &[0x55, 0x48, 0x89, 0xE5], 0)]);
    let hits = s.scan_fast(&haystack(), 0x1000);
    assert!(!hits.is_empty(), "col default la firma corta deve agganciare");
}

#[test]
fn the_threshold_rejects_short_crcless_signatures() {
    let mut s = FlirtScanner::new_fast(vec![sig("short_fn", &[0x55, 0x48, 0x89, 0xE5], 0)]);
    s.set_min_bytes_without_crc(16);
    assert!(
        s.scan_fast(&haystack(), 0x1000).is_empty(),
        "4 byte senza CRC non sono prova sufficiente"
    );
}

#[test]
fn a_long_crcless_signature_still_matches() {
    // The threshold must cut *weak* evidence, not all CRC-less signatures: a
    // long exact prefix is discriminating on its own.
    let long = &haystack()[..20];
    let mut s = FlirtScanner::new_fast(vec![sig("long_fn", long, 0)]);
    s.set_min_bytes_without_crc(16);
    let hits = s.scan_fast(&haystack(), 0x1000);
    assert_eq!(hits.len(), 1, "20 byte esatti sono prova sufficiente");
    assert_eq!(hits[0].function_name, "long_fn");
}

#[test]
fn a_signature_with_a_crc_is_exempt_from_the_length_floor() {
    // A short prefix backed by a tail CRC is still discriminating — the CRC is
    // the evidence the floor exists to substitute for. Exempting it is the
    // whole point; without that, raising the threshold would throw away the
    // *strongest* signatures along with the weakest.
    let data = haystack();
    let crc = rustre_flirt::crc::flirt_tail(&data[4..12]);
    let mut sg = sig("crc_fn", &data[..4], 8);
    sg.crc_offset = 0;
    sg.crc = crc;

    let mut s = FlirtScanner::new_fast(vec![sg]);
    s.set_min_bytes_without_crc(16);
    let hits = s.scan_fast(&data, 0x1000);
    assert_eq!(hits.len(), 1, "una firma con CRC non va scartata per lunghezza");
    assert_eq!(hits[0].function_name, "crc_fn");
}

#[test]
fn raising_the_threshold_never_adds_matches() {
    // Monotonicity: the knob is a filter, so more strictness can only remove.
    // If a higher threshold ever produced *more* matches, the filter would be
    // doing something other than filtering.
    let sigs = vec![
        sig("a", &[0x55, 0x48, 0x89, 0xE5], 0),
        sig("b", &haystack()[..20], 0),
        sig("c", &haystack()[..12], 0),
    ];
    let data = haystack();
    let mut previous = usize::MAX;
    for n in [0usize, 8, 12, 16, 20, 24, 32] {
        let mut s = FlirtScanner::new_fast(sigs.clone());
        s.set_min_bytes_without_crc(n);
        let count = s.scan_fast(&data, 0x1000).len();
        assert!(
            count <= previous,
            "soglia {n}: {count} match, ma con la soglia precedente erano {previous}"
        );
        previous = count;
    }
}
