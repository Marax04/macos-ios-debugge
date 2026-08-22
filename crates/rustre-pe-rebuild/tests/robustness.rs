//! Adversarial input sweeps over the PE reconstruction entry points.

use rustre_pe_rebuild::pe_dumper::PeContext;
use rustre_pe_rebuild::pe_reconstructor::parse_imports;

fn seed() -> Vec<u8> {
    let mut d = vec![0u8; 4096];
    d[0] = b'M';
    d[1] = b'Z';
    d[60..64].copy_from_slice(&128u32.to_le_bytes());
    d[128..132].copy_from_slice(b"PE\0\0");
    d[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    d[134..136].copy_from_slice(&2u16.to_le_bytes());
    d[148..150].copy_from_slice(&240u16.to_le_bytes());
    d[152..154].copy_from_slice(&0x020Bu16.to_le_bytes());
    d
}

fn sweep(seed: &[u8], f: impl Fn(&[u8])) {
    for n in 0..seed.len().min(1024) {
        f(&seed[..n]);
    }
    let mut st = 0xB5AD_4ECE_DA1C_E2A9u64;
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
fn pe_context_sweep() {
    sweep(&seed(), |b| {
        let _ = PeContext::parse(b);
    });
}

#[test]
fn parse_imports_sweep() {
    sweep(&seed(), |b| {
        let _ = parse_imports(b);
    });
}
