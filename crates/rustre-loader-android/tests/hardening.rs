//! Hardening tests for `rustre-loader-android`.
//!
//! Most allocation sites in this crate were already capped by the earlier audit
//! passes (`lib.rs`, `apk_zip_reader.rs`, `oat_parser.rs`, `axml_full.rs`,
//! `vdex_parser.rs`, `art_method_resolver.rs`, `manifest_binary.rs`). The one
//! that was still open is `apk::ApkFile::read_entry_deflate`, which reserved a
//! buffer of `uncompressed_size` — a 32-bit field taken verbatim from the ZIP
//! central directory, so a few-byte entry could claim 4 GiB.

use rustre_loader_android::apk::{ApkFile, ZipEntry};

/// Build a minimal ZIP containing a single stored-deflate entry whose declared
/// `uncompressed_size` is absurd.
///
/// The layout only needs to satisfy `read_entry_stored`: a local file header at
/// offset 0 followed by `compressed_size` bytes of payload.
fn zip_with_entry(payload: &[u8], declared_uncompressed: u32) -> (Vec<u8>, ZipEntry) {
    let name = b"classes.dex";
    let mut data = Vec::new();
    data.extend_from_slice(b"PK\x03\x04"); // local file header signature
    data.extend_from_slice(&[0u8; 22]); // version..crc etc. (offsets 4..26)
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed size @26
    data.extend_from_slice(&declared_uncompressed.to_le_bytes()); // uncompressed @30 (unused here)
    // read_entry_stored reads the name/extra lengths at local-header offsets 26/28,
    // so pad the header out to the canonical 30 bytes and place them there.
    let mut hdr = vec![0u8; 30];
    hdr[0..4].copy_from_slice(b"PK\x03\x04");
    hdr[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
    hdr[28..30].copy_from_slice(&0u16.to_le_bytes()); // extra len
    data = hdr;
    data.extend_from_slice(name);
    data.extend_from_slice(payload);

    let entry = ZipEntry {
        name: "classes.dex".to_owned(),
        compression: 8, // DEFLATE
        crc32: 0,
        compressed_size: payload.len() as u32,
        uncompressed_size: declared_uncompressed,
        local_header_offset: 0,
        extra_field_len: 0,
        comment: String::new(),
    };
    (data, entry)
}

/// A tiny entry declaring a 4 GiB uncompressed size must not reserve 4 GiB.
///
/// The deflate stream is a single stored (BTYPE=00) block carrying 4 bytes.
#[test]
fn huge_uncompressed_size_does_not_allocate() {
    // BFINAL=1, BTYPE=00 → byte 0x01; then LEN=4, NLEN, then 4 payload bytes.
    let mut payload = vec![0x01u8];
    payload.extend_from_slice(&4u16.to_le_bytes()); // LEN
    payload.extend_from_slice(&(!4u16).to_le_bytes()); // NLEN
    payload.extend_from_slice(b"dex\n");

    let (data, entry) = zip_with_entry(&payload, u32::MAX);
    let out = ApkFile::read_entry_deflate(&data, &entry).expect("stored block should inflate");
    // The real content is what matters — the bogus declared size must not have
    // driven the allocation.
    assert_eq!(out, b"dex\n");
}

/// A legitimate entry whose declared size matches must still round-trip: the
/// cap bounds the reservation, it must not truncate output.
#[test]
fn wellformed_entry_still_inflates() {
    let content = b"hello android";
    let mut payload = vec![0x01u8]; // BFINAL=1, BTYPE=00
    payload.extend_from_slice(&(content.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(!(content.len() as u16)).to_le_bytes());
    payload.extend_from_slice(content);

    let (data, entry) = zip_with_entry(&payload, content.len() as u32);
    let out = ApkFile::read_entry_deflate(&data, &entry).expect("should inflate");
    assert_eq!(out, content);
}

/// A stored (compression == 0) entry bypasses inflate entirely and is returned
/// verbatim — verify the fix did not disturb that path.
#[test]
fn stored_entry_unaffected() {
    let content = b"raw bytes";
    let (data, mut entry) = zip_with_entry(content, u32::MAX);
    entry.compression = 0;
    let out = ApkFile::read_entry_stored(&data, &entry).expect("should read");
    assert_eq!(out, content);
}

/// Truncated payloads must fail cleanly rather than panic.
#[test]
fn truncated_deflate_never_panics() {
    let mut payload = vec![0x01u8];
    payload.extend_from_slice(&64u16.to_le_bytes()); // LEN claims 64 bytes...
    payload.extend_from_slice(&(!64u16).to_le_bytes());
    payload.extend_from_slice(b"only a few"); // ...but far fewer follow

    let (data, entry) = zip_with_entry(&payload, u32::MAX);
    let _ = ApkFile::read_entry_deflate(&data, &entry);

    for cut in 0..data.len() {
        let _ = ApkFile::read_entry_deflate(&data[..cut], &entry);
    }
}

/// Random noise through the APK entry readers must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0xDEAD_BEEF_CAFE_1234u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..200 {
        let len = (next() % 300) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let entry = ZipEntry {
            name: "x".to_owned(),
            compression: 8,
            crc32: 0,
            compressed_size: (next() % 0xFFFF) as u32,
            uncompressed_size: u32::MAX,
            local_header_offset: (next() % 64) as u32,
            extra_field_len: 0,
            comment: String::new(),
        };
        let _ = ApkFile::read_entry_deflate(&buf, &entry);
        let _ = ApkFile::read_entry_stored(&buf, &entry);
        let _ = ApkFile::parse(&buf);
    }
}
