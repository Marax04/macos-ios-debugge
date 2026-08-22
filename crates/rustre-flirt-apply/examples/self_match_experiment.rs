//! The decisive experiment: can a signature find the code it was generated from?
//!
//! # What this settles
//!
//! Iteration 37 recorded a strong hypothesis: signatures carrying a CRC are
//! rejected **by construction**, because the generator drops masked bytes while
//! the scanner masks nothing, and `crc_length` means "bytes hashed" on one side
//! and "bytes to read" on the other. It was explicitly left unproven.
//!
//! This proves or refutes it directly. Harvest patterns from a real archive,
//! write them to a `.sig`, then scan **the very bytes they were generated from**.
//! A signature that cannot match its own source is broken beyond any question of
//! false positives or thresholds — there is no more favourable input possible.
//!
//! Reported separately for patterns **with** and **without** wildcards, because
//! the hypothesis predicts exactly that split: the wildcard-free ones should
//! match, the wildcarded ones should not.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example `self_match_experiment` \
//!       -- <archive.a>

use std::collections::HashSet;

use rustre_flirt_apply::usize_to_f64;

use rustre_flirt::PatternByte;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .map_or(r"C:\msys64\mingw64\lib\libz.a", String::as_str);

    let Ok(data) = std::fs::read(path) else {
        eprintln!("impossibile leggere {path}");
        std::process::exit(2);
    };

    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, stats) =
        rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts).expect("harvest");
    println!("archivio  : {path}");
    println!("membri    : {}, oggetti {}", stats.members, stats.objects_parsed);
    println!("pattern   : {}", pats.len());

    if pats.is_empty() {
        eprintln!("nessun pattern: l'esperimento non proverebbe nulla");
        std::process::exit(1);
    }

    let has_wc = |p: &rustre_flirt::FlirtPattern| {
        p.initial_bytes.iter().any(|b| matches!(b, PatternByte::Wildcard))
    };
    let with_wc: Vec<_> = pats.iter().filter(|p| has_wc(p)).cloned().collect();
    let no_wc: Vec<_> = pats.iter().filter(|p| !has_wc(p)).cloned().collect();
    println!("  con wildcard : {}", with_wc.len());
    println!("  senza        : {}", no_wc.len());
    println!();

    let run = |label: &str, subset: &[rustre_flirt::FlirtPattern]| {
        if subset.is_empty() {
            println!("{label:<22} (nessun pattern)");
            return;
        }
        let sig = rustre_flirt_gen::SigWriter::default().build(subset, "selftest");
        let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
            println!("{label:<22} .sig non caricabile");
            return;
        };
        let hits = scanner.scan_fast(&data, 0);
        let names: HashSet<&str> = hits.iter().map(|m| m.function_name.as_str()).collect();
        let expected: HashSet<&str> = subset
            .iter()
            .filter_map(rustre_flirt::FlirtPattern::primary_name)
            .collect();
        let found = expected.intersection(&names).count();
        let pct = usize_to_f64(found) * 100.0 / usize_to_f64(expected.len().max(1));
        println!(
            "{label:<22} attesi {:<5} ritrovati {:<5} ({pct:.1}%)",
            expected.len(),
            found
        );
    };

    run("tutti i pattern", &pats);
    run("solo SENZA wildcard", &no_wc);
    run("solo CON wildcard", &with_wc);

    // Isolate the CRC from the wildcard. Same patterns, CRC field cleared: if the
    // wildcarded subset recovers, the CRC is what rejects them; if it does not,
    // the defect is in prefix matching and the CRC is a bystander.
    println!();
    let strip_crc = |p: &rustre_flirt::FlirtPattern| {
        let mut q = p.clone();
        q.crc16 = 0;
        q.crc_length = 0;
        q
    };
    let no_crc_all: Vec<_> = pats.iter().map(strip_crc).collect();
    let no_crc_wc: Vec<_> = with_wc.iter().map(strip_crc).collect();
    run("senza CRC, tutti", &no_crc_all);
    run("senza CRC, con wc", &no_crc_wc);

    println!();
    println!("Una firma che non ritrova il codice da cui e' stata generata e'");
    println!("rotta: non esiste input piu' favorevole di quello di partenza.");
}
