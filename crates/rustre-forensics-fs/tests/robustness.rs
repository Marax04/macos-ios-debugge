//! Adversarial input sweeps over the hostile-format parsers.
//!
//! These crates parse attacker-controlled filesystem and artifact
//! structures, so every public parse entry point must return an error
//! rather than panic on a truncated or corrupted buffer.

use rustre_forensics_fs::lnk_parser::LnkFile;
use rustre_forensics_fs::ntfs_analyzer::MftRecord;
use rustre_forensics_fs::prefetch_analyzer::PrefetchFile;
use rustre_forensics_fs::registry_hive_parser::{NkCell, RegHiveHeader, VkCell};
use rustre_forensics_fs::artifacts::ArtifactScanner;
use rustre_forensics_fs::carver::FileCarver;
use rustre_forensics_fs::inode::parse_mft_record_minimal;
use rustre_forensics_fs::ntfs_reader::{parse_mbr_partitions, NtfsVbr};
use rustre_forensics_fs::ext4_reader::Ext4Parser;
use rustre_forensics_fs::fat32_reader::{parse_directory, Fat32Bpb, Fat32Reader};
use rustre_forensics_fs::fat_analyzer::FatAnalyzer;
use rustre_forensics_fs::ntfs_mft_full::NtfsMftFull;

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

#[test]
fn fat32_sweep() {
    let mut d = vec![0u8; 64 * 1024];
    d[11..13].copy_from_slice(&512u16.to_le_bytes());
    d[13] = 1;
    d[14..16].copy_from_slice(&32u16.to_le_bytes());
    d[16] = 2;
    d[510] = 0x55;
    d[511] = 0xAA;
    sweep(&d, |b| {
        let _ = Fat32Bpb::parse(b);
        let _ = parse_directory(b);
        if let Ok(mut r) = Fat32Reader::new(b.to_vec()) {
            let _ = r.list_all();
        }
        let _ = FatAnalyzer::new(b);
    });
}

#[test]
fn ext4_sweep() {
    let mut d = vec![0u8; 64 * 1024];
    d[1024 + 56..1024 + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
    sweep(&d, |b| {
        if let Ok(p) = Ext4Parser::new(b) {
            let _ = p.parse_block_group_desc(0);
            let _ = p.parse_inode(2);
        }
    });
}

#[test]
fn mft_full_sweep() {
    sweep(&mft_seed(), |b| {
        let mut p = NtfsMftFull::new(Default::default());
        let _ = p.parse_image(b);
    });
}

#[test]
fn carver_sweep() {
    let mut d = vec![0u8; 16 * 1024];
    d[0..4].copy_from_slice(&[0x89, b'P', b'N', b'G']);
    d[4096..4098].copy_from_slice(&[0xFF, 0xD8]);
    sweep(&d, |b| {
        let c = FileCarver::new();
        let _ = c.carve(b);
    });
}

#[test]
fn ntfs_reader_sweep() {
    let mut d = vec![0u8; 4096];
    d[3..11].copy_from_slice(b"NTFS    ");
    d[11..13].copy_from_slice(&512u16.to_le_bytes());
    d[13] = 8;
    d[510] = 0x55;
    d[511] = 0xAA;
    sweep(&d, |b| {
        let _ = NtfsVbr::parse(b);
        let _ = parse_mbr_partitions(b);
    });
}

#[test]
fn inode_sweep() {
    sweep(&mft_seed(), |b| {
        let _ = parse_mft_record_minimal(b, 0);
    });
}

#[test]
fn artifacts_sweep() {
    let mut d = vec![0u8; 2048];
    d[0..4].copy_from_slice(&26u32.to_le_bytes());
    d[4..8].copy_from_slice(b"SCCA");
    sweep(&d, |b| {
        let mut s = ArtifactScanner::new();
        s.scan_path("C:/Windows/Prefetch/X.pf", b);
        s.scan_path("C:/x.lnk", b);
        s.scan_path("C:/SYSTEM", b);
    });
}
