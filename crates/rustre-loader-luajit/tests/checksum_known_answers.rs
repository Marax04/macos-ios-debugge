//! Known-answer tests for the checksums in `luajit_vm_analysis`.
//!
//! Both are published algorithms with published test vectors, so an exact
//! external oracle exists — yet nothing in this crate pinned either result. A
//! transcription slip (a wrong polynomial, the wrong Adler modulus, a missing
//! final complement) would not break any build, it would just make checksums
//! disagree silently.
//!
//! The workspace carries a dozen copies of each; `rustre-hex` and
//! `rustre-loader-firmware` anchor theirs with exactly these vectors.

use rustre_loader_luajit::luajit_vm_analysis::{adler32, crc32};

#[test]
fn crc32_matches_the_published_vectors() {
    // The canonical CRC-32 check value (reflected, polynomial 0xEDB88320,
    // init and final XOR 0xFFFFFFFF).
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    // Empty input: init ^ final leaves zero.
    assert_eq!(crc32(&[]), 0x0000_0000);
    assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
}

#[test]
fn adler32_matches_the_published_vectors() {
    // RFC 1950 §9 worked example.
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    assert_eq!(adler32(&[]), 0x0000_0001);
    assert_eq!(adler32(b"a"), 0x0062_0062);
}

#[test]
fn checksums_are_sensitive_to_order_and_length() {
    // The vectors alone would also be satisfied by a function that ignored the
    // order of the bytes, or the running sum; these pin the shape.
    assert_ne!(crc32(b"ab"), crc32(b"ba"));
    assert_ne!(adler32(b"ab"), adler32(b"ba"));
    assert_ne!(crc32(b"a"), crc32(b"aa"));
    assert_ne!(adler32(b"a"), adler32(b"aa"));
}
