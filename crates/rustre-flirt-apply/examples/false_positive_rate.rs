//! Specificity: how often does a signature database match code that provably
//! contains none of its functions?
//!
//! # Why this oracle is stronger than the PDB one
//!
//! The PDB measurement needs a binary with symbols, and the corpus only ships
//! two — both Rust, both linking the same stdlib. Their match sets differ but
//! their counts are identical, so they are one sample, not two.
//!
//! This test needs no symbols at all. Run a **rust-stdlib** database against a
//! binary built from C, C++, Go or C#: it contains no Rust standard library, so
//! **every match is a false positive by construction**. No oracle to trust, no
//! name normalisation to get wrong, no UNKNOWN bucket to argue about.
//!
//! It measures specificity, not precision — a database that matches nothing at
//! all would score perfectly here. Read it beside the PDB precision numbers,
//! never instead of them.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example false_positive_rate \
//!       -- <database.sig> <binary1> [binary2 …]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("uso: false_positive_rate <database.sig> <binary…>");
        std::process::exit(2);
    }

    let sig = std::fs::read(&args[1]).expect("lettura .sig");
    let thresholds = [0usize, 8, 12, 16, 20, 24, 32];

    println!("database: {}", args[1]);
    println!();
    println!(
        "{:<24} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "binario", "s=0", "s=8", "s=12", "s=16", "s=20", "s=24", "s=32"
    );

    let mut totals = vec![0usize; thresholds.len()];

    for path in &args[2..] {
        let Ok(bin) = std::fs::read(path) else {
            eprintln!("  (salto {path}: illeggibile)");
            continue;
        };
        let Ok(pe) = rustre_pe_tools::PeFile::parse(&bin) else {
            eprintln!("  (salto {path}: non è un PE)");
            continue;
        };

        let mut row = Vec::new();
        for (i, &n) in thresholds.iter().enumerate() {
            let mut scanner =
                rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner");
            scanner.set_min_bytes_without_crc(n);

            let mut matches = Vec::new();
            for s in &pe.sections {
                if s.characteristics & 0x2000_0000 == 0 || s.data.is_empty() {
                    continue;
                }
                let va = pe.image_base + u64::from(s.virtual_address);
                matches.extend(scanner.scan_fast(&s.data, va));
            }
            let (renames, _) = rustre_flirt_apply::resolve_renames(&matches, 0);
            // Distinct addresses: one wrong name on one address is one defect,
            // however many signatures voted for it.
            let distinct: std::collections::BTreeSet<u64> =
                renames.iter().map(|r| r.address).collect();
            row.push(distinct.len());
            totals[i] += distinct.len();
        }

        let name = std::path::Path::new(path)
            .file_name()
            .map_or_else(|| path.clone(), |s| s.to_string_lossy().into_owned());
        print!("{name:<24}");
        for v in &row {
            print!(" {v:>8}");
        }
        println!();
    }

    println!();
    print!("{:<24}", "TOTALE (falsi pos.)");
    for v in &totals {
        print!(" {v:>8}");
    }
    println!();
    println!();
    println!("Ogni match qui è un falso positivo: questi binari non contengono");
    println!("la libreria standard di Rust.");
}
