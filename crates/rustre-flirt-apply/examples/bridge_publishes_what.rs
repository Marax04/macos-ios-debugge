//! Does the bridge publish when handed the names our scanner produces?
//!
//! Iteration 57 measured a discrepancy it deliberately did not explain: of 29
//! matched names, 4 have a prototype, yet the decompiler's trace reported
//! `considerate 28, pubblicate 0, senza prototipo 28`.
//!
//! Two candidate explanations, and guessing between them would be exactly the
//! mistake this project keeps paying for. This runs the same pipeline the
//! decompiler runs — scan, then publish — inside the crates that own it, and
//! reports where the four go.

use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let sig_path = a
        .get(1)
        .map_or(r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig", String::as_str);
    let bin_path = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);

    let (Ok(sig), Ok(bin)) = (std::fs::read(sig_path), std::fs::read(bin_path)) else {
        eprintln!("input mancante");
        std::process::exit(2);
    };
    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        eprintln!("il .sig non e' caricabile");
        std::process::exit(1);
    };

    // The identifications, exactly as the decompiler builds them: (addr, name).
    let ids: Vec<(u64, String)> = scanner
        .scan_fast(&bin, 0)
        .into_iter()
        .map(|m| (m.address, m.function_name))
        .filter(|(_, n)| !n.is_empty())
        .collect();

    let distinct: HashSet<&String> = ids.iter().map(|(_, n)| n).collect();
    println!("identificazioni : {} ({} nomi distinti)", ids.len(), distinct.len());

    let refs: Vec<(u64, &str)> = ids.iter().map(|(a, n)| (*a, n.as_str())).collect();
    let stats = rustre_flirt_apply::typerecov_bridge::publish_identifications(refs);
    println!(
        "ponte           : considerate {}, pubblicate {}, senza prototipo {}",
        stats.considered, stats.published, stats.skipped_unknown_prototype
    );

    let known: HashSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();
    let hits: Vec<&&String> = distinct.iter().filter(|n| known.contains(**n)).collect();
    println!("nomi con prototipo fra questi: {hits:?}");

    // The decompiler drops names that appear at more than one address, to avoid
    // spreading a fabricated collision. If the duplicated names are exactly the
    // useful ones, that filter is removing precisely what the bridge needs.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, n) in &ids {
        *counts.entry(n.as_str()).or_default() += 1;
    }
    let mut dup: Vec<(&str, usize)> = counts.iter().filter(|(_, c)| **c > 1).map(|(n, c)| (*n, *c)).collect();
    dup.sort();
    println!("nomi a piu' indirizzi (scartati come ambigui): {dup:?}");

    let survivors: Vec<(u64, &str)> = ids
        .iter()
        .filter(|(_, n)| counts.get(n.as_str()).copied().unwrap_or(0) == 1)
        .map(|(a, n)| (*a, n.as_str()))
        .collect();
    let s2 = rustre_flirt_apply::typerecov_bridge::publish_identifications(survivors);
    println!(
        "ponte DOPO il filtro ambiguita': considerate {}, pubblicate {}, senza prototipo {}",
        s2.considered, s2.published, s2.skipped_unknown_prototype
    );
}
