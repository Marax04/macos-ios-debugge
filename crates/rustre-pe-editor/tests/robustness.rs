//! Adversarial input sweeps over the PE parsing entry points.

use rustre_pe_editor::pe_debug_directory::{CodeViewInfo, DebugEntry, Pdb70Info};
use rustre_pe_editor::pe_header_editor::{DosHeader, PeHeader};

fn seed() -> Vec<u8> {
    let mut d = vec![0u8; 4096];
    d[0] = b'M';
    d[1] = b'Z';
    d[60..64].copy_from_slice(&128u32.to_le_bytes());
    d[128..132].copy_from_slice(b"PE\0\0");
    d[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    d[134..136].copy_from_slice(&2u16.to_le_bytes()); // sections
    d[148..150].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size
    d[152..154].copy_from_slice(&0x020Bu16.to_le_bytes());
    d
}

fn sweep(seed: &[u8], f: impl Fn(&[u8])) {
    for n in 0..seed.len().min(1024) {
        f(&seed[..n]);
    }
    let mut st = 0x243F_6A88_85A3_08D3u64;
    for _ in 0..60_000 {
        let mut m = seed.to_vec();
        for _ in 0..6 {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            let i = (st as usize) % m.len().min(768);
            m[i] = (st >> 32) as u8;
        }
        f(&m);
    }
}

#[test]
fn pe_headers_sweep() {
    sweep(&seed(), |b| {
        let _ = DosHeader::parse(b);
        let _ = PeHeader::parse(b, 128);
    });
}

#[test]
fn debug_directory_sweep() {
    sweep(&seed(), |b| {
        let _ = DebugEntry::parse(b, 0, 0);
        let _ = CodeViewInfo::parse(b);
        let _ = Pdb70Info::parse(b);
    });
}
