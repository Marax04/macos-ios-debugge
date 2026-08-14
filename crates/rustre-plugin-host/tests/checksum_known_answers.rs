//! Known-answer test for `FramedMessage::adler32`.
//!
//! This checksum guards every IPC frame, so a transcription slip (the wrong
//! modulus, the halves swapped, a missing initial `a = 1`) would not break any
//! build — it would silently reject or accept frames against a checksum no
//! other implementation agrees with. Adler-32 has published test vectors, so
//! the correct value is knowable exactly.
//!
//! `rustre-hex` and `rustre-loader-firmware` anchor their copies of this same
//! function with exactly these vectors, and this file follows them.

use rustre_plugin_host::plugin_ipc_v2::FramedMessage;

#[test]
fn adler32_matches_the_published_vectors() {
    // RFC 1950 §9 worked example.
    assert_eq!(FramedMessage::adler32(b"Wikipedia"), 0x11E6_0398);
    // Empty input is defined as 1 (a = 1, b = 0).
    assert_eq!(FramedMessage::adler32(&[]), 0x0000_0001);
    assert_eq!(FramedMessage::adler32(b"a"), 0x0062_0062);
}

#[test]
fn adler32_is_sensitive_to_order_and_length() {
    // The vectors alone would also be satisfied by a function that ignored the
    // order of the bytes, or the running sum; these pin the shape — and for a
    // frame checksum, insensitivity to order is exactly the failure that
    // matters.
    assert_ne!(FramedMessage::adler32(b"ab"), FramedMessage::adler32(b"ba"));
    assert_ne!(FramedMessage::adler32(b"a"), FramedMessage::adler32(b"aa"));
}
