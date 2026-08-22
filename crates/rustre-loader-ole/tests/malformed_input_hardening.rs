//! Regressions for allocation limits on attacker-controlled OLE/CFB headers.
//!
//! Each test here FAILS when the corresponding guard is removed — verified by
//! reintroducing the defect and re-running.

use rustre_loader_ole::ole_parser::OleParser;

/// A 512-byte CFB header claiming `fat_sector_count = u32::MAX` with a 4 GiB
/// sector size.
///
/// `build_fat` used to reserve `fat_sector_count * (sector_size / 4)` u32s
/// before reading a single FAT byte. With these header values that product is
/// about 2^62 elements, i.e. 2^64 bytes — `Vec::with_capacity` rejects it with
/// a `capacity overflow` panic, so the unguarded parser aborts on a 512-byte
/// file. The fix bounds the reservation by what the file could actually hold.
fn header_with_absurd_fat_count() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    data[26..28].copy_from_slice(&3u16.to_le_bytes()); // major version
    data[30..32].copy_from_slice(&32u16.to_le_bytes()); // sector size = 1 << 32
    data[44..48].copy_from_slice(&u32::MAX.to_le_bytes()); // fat_sector_count
    data[48..52].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // ENDOFCHAIN dir
    data[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    data[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    for i in 0..109 {
        data[76 + i * 4..80 + i * 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    data
}

#[test]
fn absurd_fat_sector_count_does_not_reserve_the_address_space() {
    let data = header_with_absurd_fat_count();
    // The only requirement is that this returns — successfully or with an
    // error — instead of panicking inside `Vec::with_capacity`.
    let _ = OleParser::parse(data);
}
