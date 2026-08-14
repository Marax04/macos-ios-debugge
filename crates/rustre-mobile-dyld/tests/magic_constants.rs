//! The Mach-O magic table must match the published Apple values.
//!
//! These constants are duplicated in five crates. Four agreed on
//! `FAT_MAGIC_64 = 0xCAFE_BABF` (`rustre-loader` twice, `rustre-mobile-ios`,
//! `rustre-mobile-ipa`); this table alone carried `0xBFFF_AFFE`, so a 64-bit
//! fat binary was not recognised here while every other crate accepted it.
//! Nothing failed loudly: the file was simply treated as "not fat".
//!
//! Pinning the whole table, not just the one that was wrong, so the next
//! divergence fails here instead of silently splitting the crates again.

use rustre_mobile_dyld::macho_magic::*;

#[test]
fn magic_constants_match_apple_values() {
    assert_eq!(MH_MAGIC, 0xFEED_FACE, "mach_header magic");
    assert_eq!(MH_MAGIC_64, 0xFEED_FACF, "mach_header_64 magic");
    assert_eq!(FAT_MAGIC, 0xCAFE_BABE, "fat_header magic");
    assert_eq!(FAT_MAGIC_64, 0xCAFE_BABF, "fat_header 64-bit magic");
}

/// `CIGAM` is `MAGIC` spelled backwards: each one must be the byte-swap of its
/// partner. This is arithmetic, so it holds regardless of what Apple documents.
#[test]
fn cigam_constants_are_the_byte_swaps_of_their_magics() {
    assert_eq!(MH_CIGAM, MH_MAGIC.swap_bytes(), "MH_CIGAM vs MH_MAGIC");
    assert_eq!(MH_CIGAM_64, MH_MAGIC_64.swap_bytes(), "MH_CIGAM_64 vs MH_MAGIC_64");
    assert_eq!(FAT_CIGAM, FAT_MAGIC.swap_bytes(), "FAT_CIGAM vs FAT_MAGIC");
}
