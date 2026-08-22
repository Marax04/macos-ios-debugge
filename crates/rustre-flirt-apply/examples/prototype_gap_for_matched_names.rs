//! Which matched names lack a prototype? (Level 7 / T17b)
//!
//! Running the decompiler on a corpus C binary with a `libmingw32`+`libmsvcrt`
//! signature database traces:
//!
//! ```text
//! [flirt] firme caricate 108634, match grezzi 65, dopo resolve 65
//! [flirt→typerecov] considerate 28, pubblicate 0, senza prototipo 28
//! ```
//!
//! So scanning works and the bridge publishes nothing: every matched name is
//! missing from the prototype database. That is the whole Level 7 multiplier
//! sitting at zero, and "no prototype" is a claim worth turning into a list —
//! a gap you can read is a gap you can close.
//!
//! Usage: `prototype_gap_for_matched_names` [<sig-dir>] [<binary>]

use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let sig_path = a.get(1).map_or(r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig", String::as_str);
    let bin_path = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);

    let (Ok(sig), Ok(bin)) = (std::fs::read(sig_path), std::fs::read(bin_path)) else {
        eprintln!("input mancante: {sig_path} / {bin_path}");
        std::process::exit(2);
    };

    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        eprintln!("il .sig non e' caricabile");
        std::process::exit(1);
    };

    let matched: HashSet<String> = scanner
        .scan_fast(&bin, 0)
        .into_iter()
        .map(|m| m.function_name)
        .filter(|n| !n.is_empty())
        .collect();

    let known: HashSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();

    let mut with: Vec<&String> = matched.iter().filter(|n| known.contains(*n)).collect();
    let mut without: Vec<&String> = matched.iter().filter(|n| !known.contains(*n)).collect();
    with.sort();
    without.sort();

    println!("firme che combaciano : {}", matched.len());
    println!("prototipi conosciuti : {}", known.len());
    println!("  con prototipo      : {}", with.len());
    println!("  SENZA prototipo    : {}", without.len());
    println!();
    if !with.is_empty() {
        println!("con prototipo:");
        for n in &with {
            println!("   {n}");
        }
        println!();
    }
    println!("senza prototipo (il divario da colmare):");
    for n in &without {
        println!("   {n}");
    }
}
