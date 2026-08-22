//! Scan a binary with signatures generated from a **different** artefact (T14).
//!
//! # Why the round-trip was not enough
//!
//! `self_match_experiment.rs` scans the very bytes a signature was generated
//! from. That is the right instrument for proving a signature is broken — no
//! input is more favourable — but it cannot measure the thing FLIRT exists for:
//! recognising a function in a binary you did not generate from.
//!
//! It also cannot see wildcard loss. Iteration 45 measured that the `.sig`
//! container truncates a pattern at its first wildcard (`take_while(Exact)`), so
//! a 16-byte pattern with a relocation at offset 3 becomes a 3-byte pattern. On
//! self-match that is invisible: the exact prefix still matches, because the
//! bytes are the same bytes. Across binaries it is not invisible at all — a
//! 3-byte key matches everywhere, and a relocated instruction has *different*
//! bytes in a different link.
//!
//! # What this measures
//!
//! Signatures harvested from a real archive, then scanned against:
//!
//! * a **target** binary that statically links that archive — matches here are
//!   plausible;
//! * a **foreign** binary that does not — matches here are false positives by
//!   construction, the specificity oracle this project already uses.
//!
//! Reported split by pattern length, because that is what the truncation
//! produces: the short patterns are exactly the ones that lost their wildcards.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example `cross_binary_match` \
//!       -- <archive.a> <target.exe> <foreign.exe>

use std::collections::HashSet;

use rustre_flirt::PatternByte;

fn prefix_len(p: &rustre_flirt::FlirtPattern) -> usize {
    // What `SigWriter` will actually keep: bytes up to the first wildcard.
    p.initial_bytes
        .iter()
        .take_while(|b| matches!(b, PatternByte::Exact(_)))
        .count()
}

/// Resolve the three input paths from argv and read them.
///
/// Split out of `main` so neither half runs long: this half only does I/O
/// and exits with a diagnostic when a path is missing.
fn load_inputs() -> (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>) {
    let a: Vec<String> = std::env::args().collect();
    let archive = a.get(1).map_or(r"C:\msys64\mingw64\lib\libmingwex.a", String::as_str);
    let target = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);
    let foreign = a
        .get(3)
        .map_or(r"tests\decompiler_corpus\bin\sample4_go.exe", String::as_str);

    let Ok(arch_bytes) = std::fs::read(archive) else {
        eprintln!("impossibile leggere {archive}");
        std::process::exit(2);
    };
    let Ok(target_bytes) = std::fs::read(target) else {
        eprintln!("impossibile leggere {target}");
        std::process::exit(2);
    };
    let Ok(foreign_bytes) = std::fs::read(foreign) else {
        eprintln!("impossibile leggere {foreign}");
        std::process::exit(2);
    };

    (
        archive.to_string(),
        target.to_string(),
        foreign.to_string(),
        arch_bytes,
        target_bytes,
        foreign_bytes,
    )
}

fn main() {
    let (archive, target, foreign, arch_bytes, target_bytes, foreign_bytes) = load_inputs();

    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, stats) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&arch_bytes, &opts)
        .expect("harvest");
    if pats.is_empty() {
        eprintln!("nessun pattern: la misura non proverebbe nulla");
        std::process::exit(1);
    }

    println!("archivio : {archive}");
    println!("           {} membri, {} oggetti, {} pattern", stats.members, stats.objects_parsed, pats.len());
    println!("target   : {target} ({} byte)", target_bytes.len());
    println!("estraneo : {foreign} ({} byte)", foreign_bytes.len());
    println!();

    // How much the container will keep of each pattern.
    let truncated: Vec<_> = pats
        .iter()
        .filter(|p| prefix_len(p) < p.initial_bytes.len())
        .cloned()
        .collect();
    let intact: Vec<_> = pats
        .iter()
        .filter(|p| prefix_len(p) == p.initial_bytes.len())
        .cloned()
        .collect();
    let short: Vec<_> = pats.iter().filter(|p| prefix_len(p) < 8).cloned().collect();

    println!("troncati dal container (>=1 wildcard) : {}", truncated.len());
    println!("integri                                : {}", intact.len());
    println!("ridotti a meno di 8 byte               : {}", short.len());
    println!();

    let run = |label: &str, subset: &[rustre_flirt::FlirtPattern]| {
        if subset.is_empty() {
            println!("{label:<26} (nessun pattern)");
            return;
        }
        let sig = rustre_flirt_gen::SigWriter::default().build(subset, "crossbin");
        let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
            println!("{label:<26} .sig non caricabile");
            return;
        };
        let uniq = |data: &[u8]| -> usize {
            scanner
                .scan_fast(data, 0)
                .into_iter()
                .map(|m| m.function_name)
                .collect::<HashSet<_>>()
                .len()
        };
        println!(
            "{label:<26} target {:<6} estraneo {:<6}",
            uniq(&target_bytes),
            uniq(&foreign_bytes)
        );
    };

    println!("{:<26} {:<13} ", "sottoinsieme", "nomi distinti");
    run("tutti", &pats);
    run("solo integri", &intact);
    run("solo troncati", &truncated);
    run("solo <8 byte dopo troncam.", &short);

    println!();
    println!("I match sull'estraneo sono falsi positivi per costruzione:");
    println!("quel binario non collega questo archivio.");

    // The pending decision, measured on this corpus: does the minimum-length
    // threshold remove the false positives, and what does it cost on the target?
    println!();
    println!("Soglia minima di byte per una firma senza CRC:");
    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "crossbin");
    for min in [0usize, 4, 8, 16, 24] {
        let Ok(mut scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
            println!("  .sig non caricabile");
            break;
        };
        scanner.set_min_bytes_without_crc(min);
        let uniq = |data: &[u8], s: &rustre_flirt_apply::FlirtScanner| -> usize {
            s.scan_fast(data, 0)
                .into_iter()
                .map(|m| m.function_name)
                .collect::<HashSet<_>>()
                .len()
        };
        println!(
            "  min={min:<3} target {:<6} estraneo {:<6}",
            uniq(&target_bytes, &scanner),
            uniq(&foreign_bytes, &scanner)
        );
    }
}
