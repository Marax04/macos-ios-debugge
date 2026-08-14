//! Offsets computed from a disk image must not underflow or wrap.
//!
//! Every operand in these formulas is read from the image being examined: a boot
//! sector's `num_fats`, `fat_size_32`, `sectors_per_cluster`, and the cluster
//! numbers stored in directory entries. FAT clusters 0 and 1 are reserved, so a
//! malformed image naming one of them turned `cluster - 2` into an underflow —
//! a panic in debug, and in release a colossal offset that then indexed the
//! image. `fat32_reader::cluster_byte_offset` already guarded exactly this and
//! said why in a comment; the same computation elsewhere in the crate did not.

use rustre_forensics_fs::fat32_deep::Fat32BootSector;

/// A boot sector with plausible geometry, so each test can vary one field.
fn boot(sectors_per_cluster: u8, num_fats: u8, fat_size_32: u32) -> Fat32BootSector {
    Fat32BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster,
        reserved_sectors: 32,
        num_fats,
        total_sectors_32: 1_000_000,
        fat_size_32,
        root_cluster: 2,
        volume_id: 0,
        volume_label: "TEST".into(),
        fs_type: "FAT32".into(),
    }
}

/// The reserved cluster numbers must not underflow the `- 2`.
#[test]
fn reserved_cluster_numbers_do_not_underflow() {
    let bs = boot(8, 2, 1000);
    let first_data = bs.cluster_offset(2);

    for cluster in [0u32, 1] {
        let off = bs.cluster_offset(cluster);
        assert!(
            off <= first_data,
            "reserved cluster {cluster} produced offset {off}, past the first data \
             cluster at {first_data} — the subtraction wrapped"
        );
    }
}

/// Ordinary clusters still map to exact offsets.
#[test]
fn ordinary_cluster_offsets_are_exact() {
    let bs = boot(8, 2, 1000);
    // fat_region = 32 + 2 * 1000 = 2032 sectors.
    // cluster 2 is the first data cluster, so its index is 0.
    assert_eq!(bs.cluster_offset(2), 2032 * 512);
    assert_eq!(bs.cluster_offset(3), (2032 + 8) * 512);
    assert_eq!(bs.cluster_offset(10), (2032 + 8 * 8) * 512);
    assert_eq!(bs.data_offset(), 2032 * 512);
}

/// An absurd FAT size cannot wrap the data offset into a small number.
///
/// `num_fats * fat_size_32` overflowed `u32` before the widening: 255 FATs of
/// `u32::MAX` sectors is nonsense, but it is nonsense the image is free to
/// state, and the wrapped product produced a *small, plausible* offset — the
/// dangerous kind of wrong.
#[test]
fn an_absurd_fat_region_saturates() {
    let bs = boot(8, 255, u32::MAX);
    let sane = boot(8, 2, 1000);

    assert!(
        bs.data_offset() > sane.data_offset(),
        "255 FATs of u32::MAX sectors reported {} bytes, no more than the {} of a \
         normal image",
        bs.data_offset(),
        sane.data_offset()
    );
    assert!(
        bs.cluster_offset(u32::MAX) >= bs.data_offset(),
        "the largest cluster number must not land before the data region"
    );
}

/// Offsets never decrease as the cluster number grows.
///
/// Monotonicity is what wrapping breaks, and it holds across the saturation
/// point without the test having to know where that point falls.
#[test]
fn cluster_offsets_are_monotonic() {
    let bs = boot(8, 2, 1000);
    let mut previous = 0u64;

    let mut clusters: Vec<u32> = (0..32).map(|i| 1u32 << i).collect();
    clusters.extend([0, 1, 2, 3, u32::MAX]);
    clusters.sort_unstable();

    for cluster in clusters {
        let off = bs.cluster_offset(cluster);
        assert!(
            off >= previous,
            "cluster {cluster} is at {off}, before the {previous} of a lower cluster"
        );
        previous = off;
    }
}

/// Guards the saturation tests: the fixture must really overflow unwidened.
#[test]
fn the_fixture_actually_overflows_a_u32() {
    let product = 255u32.checked_mul(u32::MAX);
    assert!(
        product.is_none(),
        "255 * u32::MAX fits in u32, so the saturation is never exercised"
    );
}
