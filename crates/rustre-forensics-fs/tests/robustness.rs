//! Adversarial input sweeps over the hostile-format parsers.
//!
//! These crates parse attacker-controlled filesystem and artifact
//! structures, so every public parse entry point must return an error
//! rather than panic on a truncated or corrupted buffer.

use rustre_forensics_fs::lnk_parser::LnkFile;
use rustre_forensics_fs::ntfs_analyzer::MftRecord;
use rustre_forensics_fs::prefetch_analyzer::PrefetchFile;
use rustre_forensics_fs::registry_hive_parser::{NkCell, RegHiveHeader, VkCell};

fn rng(st: &mut u64) -> u64 {
    *st ^= *st << 13;
    *st ^= *st >> 7;
    *st ^= *st << 17;
    *st
}

/// Drive one parser over truncations and header-targeted mutations of a seed.
fn sweep(seed: &[u8], f: impl Fn(&[u8])) {
    for n in 0..seed.len().min(1024) {
        f(&seed[..n]);
    }
    let mut st = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..60_000 {
        let mut m = seed.to_vec();
        if m.is_empty() {
            break;
        }
        for _ in 0..6 {
            let r = rng(&mut st);
            let i = (r as usize) % m.len().min(768);
            m[i] = (r >> 32) as u8;
        }
        f(&m);
    }
}

fn mft_seed() -> Vec<u8> {
    let mut d = vec![0u8; 1024];
    d[0..4].copy_from_slice(b"FILE");
    d[20..22].copy_from_slice(&56u16.to_le_bytes());
    d[28..32].copy_from_slice(&1024u32.to_le_bytes());
    d[32..36].copy_from_slice(&1024u32.to_le_bytes());
    // one resident $DATA attribute
    d[56..60].copy_from_slice(&0x80u32.to_le_bytes());
    d[60..64].copy_from_slice(&64u32.to_le_bytes());
    d[72..76].copy_from_slice(&16u32.to_le_bytes()); // content_len
    d[76..78].copy_from_slice(&24u16.to_le_bytes()); // content_off
    d
}

#[test]
fn mft_record_sweep() {
    sweep(&mft_seed(), |b| {
        let _ = MftRecord::parse(b, 0);
    });
}

#[test]
fn lnk_sweep() {
    let mut d = vec![0u8; 512];
    d[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
    d[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    sweep(&d, |b| {
        let _ = LnkFile::parse(b);
    });
}

#[test]
fn prefetch_sweep() {
    let mut d = vec![0u8; 512];
    d[0..4].copy_from_slice(&26u32.to_le_bytes());
    d[4..8].copy_from_slice(b"SCCA");
    sweep(&d, |b| {
        let _ = PrefetchFile::parse(b);
    });
}

#[test]
fn registry_hive_sweep() {
    let mut d = vec![0u8; 8192];
    d[0..4].copy_from_slice(b"regf");
    d[4096..4100].copy_from_slice(b"hbin");
    sweep(&d, |b| {
        let _ = RegHiveHeader::parse(b);
        let _ = NkCell::parse(b, 0);
        let _ = VkCell::parse(b, 0);
    });
}
