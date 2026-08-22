use rustre_pe_tools::*;

fn base() -> Vec<u8> {
    let mut b = PeBuilder::new_x64();
    b.add_section(".text", vec![0x90; 64], 0x6000_0020);
    b.add_section(".data", vec![0x11; 32], 0xC000_0040);
    b.build()
}

#[test]
fn truncation_sweep() {
    let d = base();
    for n in 0..d.len() {
        let s = &d[..n];
        if let Ok(mut pe) = PeFile::parse(s) {
            let _ = pe.parse_imports(s);
            let _ = pe.parse_exports(s);
        }
    }
}

#[test]
fn mutation_sweep() {
    let d = base();
    let mut st = 0x1234_5678u64;
    for _ in 0..150000 {
        let mut m = d.clone();
        for _ in 0..6 {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            let i = (st as usize) % 600.min(m.len());
            m[i] = (st >> 32) as u8;
        }
        if let Ok(mut pe) = PeFile::parse(&m) {
            let _ = pe.parse_imports(&m);
            let _ = pe.parse_exports(&m);
        }
    }
}
