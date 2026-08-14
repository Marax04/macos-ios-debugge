//! Known-answer tests for the checksums in `uefi_analysis`.
//!
//! Both functions are standard algorithms with published test vectors, so an
//! exact external oracle exists — yet this crate had no assertion pinning
//! either one. A transcription slip (a wrong polynomial, the wrong Adler
//! modulus, a missing final complement) would not break any build: firmware
//! images would simply stop verifying, which is a silent failure.
//!
//! The workspace carries a dozen copies of these two functions; `rustre-hex`
//! anchors its own pair with exactly these vectors, and this file follows it.

use rustre_loader_firmware::uefi_analysis::{adler32, crc32};

#[test]
fn crc32_matches_the_published_vectors() {
    // The canonical CRC-32 check value (reflected, polynomial 0xEDB88320,
    // init and final XOR 0xFFFFFFFF).
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    // Empty input: init ^ final leaves zero.
    assert_eq!(crc32(&[]), 0x0000_0000);
    // A single zero byte is a second, independent anchor.
    assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
}

#[test]
fn adler32_matches_the_published_vectors() {
    // RFC 1950 §9 worked example.
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    // Empty input is defined as 1 (a = 1, b = 0).
    assert_eq!(adler32(&[]), 0x0000_0001);
    assert_eq!(adler32(b"a"), 0x0062_0062);
}

#[test]
fn checksums_are_sensitive_to_order_and_length() {
    // A checksum that ignored order, or the running sum, would still pass the
    // vectors above by luck of a single input; these pin the shape.
    assert_ne!(crc32(b"ab"), crc32(b"ba"));
    assert_ne!(adler32(b"ab"), adler32(b"ba"));
    assert_ne!(crc32(b"a"), crc32(b"aa"));
    assert_ne!(adler32(b"a"), adler32(b"aa"));
}
