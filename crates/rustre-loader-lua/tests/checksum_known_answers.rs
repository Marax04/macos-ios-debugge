//! Known-answer test for `lua_decompiler_full::adler32`.
//!
//! Adler-32 is a published algorithm with published test vectors, so an exact
//! external oracle exists — yet nothing in this crate pinned the result. A
//! transcription slip (the wrong modulus, the halves swapped, a missing initial
//! `a = 1`) would not break any build, it would just make checksums disagree
//! silently.
//!
//! The workspace carries a dozen copies of this function; `rustre-hex` and
//! `rustre-loader-firmware` anchor theirs with exactly these vectors, and this
//! file follows them.

use rustre_loader_lua::lua_decompiler_full::adler32;

#[test]
fn adler32_matches_the_published_vectors() {
    // RFC 1950 §9 worked example.
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    // Empty input is defined as 1 (a = 1, b = 0).
    assert_eq!(adler32(&[]), 0x0000_0001);
    assert_eq!(adler32(b"a"), 0x0062_0062);
}

#[test]
fn adler32_is_sensitive_to_order_and_length() {
    // The vectors alone would also be satisfied by a function that ignored the
    // order of the bytes, or the running sum; these pin the shape.
    assert_ne!(adler32(b"ab"), adler32(b"ba"));
    assert_ne!(adler32(b"a"), adler32(b"aa"));
}
