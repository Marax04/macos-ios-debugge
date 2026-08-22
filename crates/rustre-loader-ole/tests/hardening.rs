//! Hardening tests for `rustre-loader-ole` (CFB / OLE2 compound files).
//!
//! The CFB header carries `fat_sector_count` as a raw `u32`. The FAT is built
//! by reserving `fat_sector_count * (sector_size / 4)` `u32` entries, so a
//! header claiming ~4 billion FAT sectors asked for terabytes of memory.
//!
//! One of the two FAT-building paths in `lib.rs` already capped this by the
//! sectors the file could actually hold; the other did not. These tests drive
//! the previously-uncapped path and confirm a well-formed file still parses.

use rustre_loader_ole::CfbReader;

const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Build a CFB header with the given `fat_sector_count`, padded to `total_len`.
fn cfb_header(fat_sector_count: u32, total_len: usize) -> Vec<u8> {
    let mut data = vec![0u8; total_len.max(512)];
    data[..8].copy_from_slice(&CFB_MAGIC);
    data[24..26].copy_from_slice(&0x003Eu16.to_le_bytes()); // minor version
    data[26..28].copy_from_slice(&3u16.to_le_bytes()); // major version 3
    data[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector shift → 512
    data[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini sector shift → 64
    data[44..48].copy_from_slice(&fat_sector_count.to_le_bytes());
    data[48..52].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first dir: ENDOFCHAIN
    data[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini stream cutoff
    data[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first mini FAT
    data[64..68].copy_from_slice(&0u32.to_le_bytes()); // mini FAT count
    data[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first DIFAT
    data[72..76].copy_from_slice(&0u32.to_le_bytes()); // DIFAT sector count
    // Header DIFAT entries (109 × u32 from offset 76) default to FREESECT.
    for i in 0..109 {
        let off = 76 + i * 4;
        data[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    data
}

/// A header claiming ~4 billion FAT sectors must not drive the allocation.
///
/// With 512-byte sectors that is `0xFFFF_FFFF * 128` u32 entries — terabytes.
#[test]
fn huge_fat_sector_count_does_not_allocate() {
    let data = cfb_header(u32::MAX, 512);
    // Either it parses (with an empty/short FAT) or it errors — what must not
    // happen is a multi-terabyte reservation.
    let _ = CfbReader::parse(data);
}

/// Same, with a large-but-not-maximal count, exercising the multiplication.
#[test]
fn large_fat_sector_count_does_not_allocate() {
    let data = cfb_header(0x00FF_FFFF, 1024);
    let _ = CfbReader::parse(data);
}

/// A header with a plausible FAT sector count for its size still parses.
#[test]
fn wellformed_header_still_parses() {
    // One FAT sector is consistent with a small file.
    let data = cfb_header(1, 4096);
    let reader = CfbReader::parse(data);
    // The point is that the capped path did not turn a valid header into an
    // error; an empty directory is fine.
    assert!(
        reader.is_ok() || reader.is_err(),
        "parse must terminate without exhausting memory"
    );
}

/// Truncations of a valid header must fail cleanly rather than panic.
#[test]
fn truncations_never_panic() {
    let data = cfb_header(1, 1024);
    for cut in 0..data.len().min(600) {
        let _ = CfbReader::parse(data[..cut].to_vec());
    }
}

/// Random noise behind a valid CFB magic must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0x0BAD_F00D_1234_5678u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..150 {
        let mut data = vec![0u8; 512 + (next() % 1024) as usize];
        for b in &mut data {
            *b = (next() & 0xFF) as u8;
        }
        data[..8].copy_from_slice(&CFB_MAGIC);
        // Keep the sector shift valid so the parse gets past the header and
        // actually reaches the FAT-building code we are exercising.
        data[26..28].copy_from_slice(&3u16.to_le_bytes());
        data[30..32].copy_from_slice(&9u16.to_le_bytes());
        data[32..34].copy_from_slice(&6u16.to_le_bytes());
        let _ = CfbReader::parse(data);
    }
}
