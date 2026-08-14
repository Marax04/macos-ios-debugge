//! Known-answer test for `CryptoFunctions::crc32`.
//!
//! This function is exposed to Rhai scripts, so its result is a contract with
//! script authors: a transcription slip (a wrong polynomial, a missing final
//! complement, a non-reflected shift direction) would not break any build, it
//! would just make every script's checksum disagree with every other CRC-32 in
//! the world. CRC-32 has a published check value, so the correct answer is
//! knowable exactly.
//!
//! `rustre-hex` and `rustre-loader-firmware` anchor their copies of this same
//! function with exactly these vectors, and this file follows them.

use rustre_script_rhai::rhai_stdlib::CryptoFunctions;

#[test]
fn crc32_matches_the_published_vectors() {
    // The canonical CRC-32 check value (reflected, polynomial 0xEDB88320,
    // init and final XOR 0xFFFFFFFF).
    assert_eq!(CryptoFunctions::crc32(b"123456789"), 0xCBF4_3926);
    // Empty input: init ^ final leaves zero.
    assert_eq!(CryptoFunctions::crc32(&[]), 0x0000_0000);
    assert_eq!(CryptoFunctions::crc32(&[0x00]), 0xD202_EF8D);
}

#[test]
fn crc32_is_sensitive_to_order_and_length() {
    // The vectors alone would also be satisfied by a function that ignored the
    // order of the bytes; these pin the shape.
    assert_ne!(CryptoFunctions::crc32(b"ab"), CryptoFunctions::crc32(b"ba"));
    assert_ne!(CryptoFunctions::crc32(b"a"), CryptoFunctions::crc32(b"aa"));
}
