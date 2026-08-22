//! Throughput of the FLIRT scanner: signatures loaded, bytes scanned.
//!
//! D9 asks for recorded numbers plus a no-regression gate. This produces the
//! numbers; `tests/scan_performance_does_not_regress.rs` is the gate.
//!
//! Deliberately not criterion: adding a benchmark framework as a dependency to
//! answer "is this fast enough, and did it get slower?" is more machinery than
//! the question needs, and criterion's statistics would imply a precision that a
//! shared, concurrently-built machine cannot deliver.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example `scan_benchmark` \
//!       -- <database.sig> [binary…]

use std::time::Instant;

use rustre_flirt_apply::usize_to_f64;

fn human(bytes: usize) -> String {
    let b = usize_to_f64(bytes);
    if b >= 1024.0 * 1024.0 {
        format!("{:.1} MB", b / (1024.0 * 1024.0))
    } else if b >= 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("uso: scan_benchmark <database.sig> [binary…]");
        std::process::exit(2);
    }

    let sig = std::fs::read(&args[1]).expect("lettura .sig");
    println!("database : {} ({})", args[1], human(sig.len()));

    // ── build cost ───────────────────────────────────────────────────────────
    let t = Instant::now();
    let scanner =
        rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner dal .sig");
    let build_ms = t.elapsed().as_secs_f64() * 1000.0;
    let n = scanner.signature_count();
    println!("firme    : {n}");
    println!("build    : {build_ms:.0} ms  ({:.0} firme/ms)", f64::from(u32::try_from(n).unwrap_or(u32::MAX)) / build_ms.max(0.001));
    println!();

    // ── scan cost ────────────────────────────────────────────────────────────
    println!("{:<26} {:>10} {:>9} {:>12} {:>8}", "binario", "dimensione", "tempo", "throughput", "match");
    for path in &args[2..] {
        let Ok(bin) = std::fs::read(path) else {
            eprintln!("  (salto {path})");
            continue;
        };
        let Ok(pe) = rustre_pe_tools::PeFile::parse(&bin) else {
            eprintln!("  (salto {path}: non PE)");
            continue;
        };

        let mut byte_total = 0usize;
        let mut hits = 0usize;
        let t = Instant::now();
        for s in &pe.sections {
            if s.characteristics & 0x2000_0000 == 0 || s.data.is_empty() {
                continue;
            }
            byte_total += s.data.len();
            let va = pe.image_base + u64::from(s.virtual_address);
            hits += scanner.scan_fast(&s.data, va).len();
        }
        let secs = t.elapsed().as_secs_f64();

        let mbs = (usize_to_f64(byte_total) / (1024.0 * 1024.0)) / secs.max(1e-9);
        let name = std::path::Path::new(path)
            .file_name()
            .map_or_else(|| path.clone(), |s| s.to_string_lossy().into_owned());
        println!(
            "{name:<26} {:>10} {:>7.0} ms {:>9.1} MB/s {hits:>8}",
            human(byte_total),
            secs * 1000.0,
            mbs
        );
    }
}
