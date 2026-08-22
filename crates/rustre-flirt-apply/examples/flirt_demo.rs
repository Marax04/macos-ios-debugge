//! End-to-end demo: from a bare archive and a bare binary to named functions.
//!
//! Runs the whole chain in one process and prints what each stage produced, so
//! the result can be checked rather than taken on faith:
//!
//! 1. harvest patterns from a static library (`.a` / `.lib`);
//! 2. write them as an `IDASGN` `.sig`;
//! 3. read that `.sig` back and scan a binary;
//! 4. report which functions were identified, and — the part that matters — how
//!    many of those identifications are believable.
//!
//! Stage 4 exists because stages 1–3 succeeding proves nothing on their own. A
//! scan that returns matches on a binary which cannot contain those functions is
//! worse than one that returns none, so the demo scans a **control** binary too
//! and prints both columns side by side.
//!
//! Usage:
//!   `flirt_demo` [<archive>] [<target.exe>] [<control.exe>]

use std::collections::HashSet;

use rustre_flirt::PatternByte;

fn kept_prefix(p: &rustre_flirt::FlirtPattern) -> usize {
    p.initial_bytes
        .iter()
        .take_while(|b| matches!(b, PatternByte::Exact(_)))
        .count()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let archive = a
        .get(1)
        .map_or(r"C:\msys64\mingw64\lib\libmingw32.a", String::as_str);
    let target = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);
    let control = a
        .get(3)
        .map_or(r"tests\decompiler_corpus\bin\sample4_go.exe", String::as_str);

    println!("== 1. archivio ==================================================");
    let Ok(arch_bytes) = std::fs::read(archive) else {
        eprintln!("impossibile leggere {archive}");
        std::process::exit(2);
    };
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, stats) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&arch_bytes, &opts)
        .expect("harvest");
    println!("   {archive}");
    println!(
        "   {} membri, {} oggetti  ->  {} pattern",
        stats.members,
        stats.objects_parsed,
        pats.len()
    );
    let with_wc = pats
        .iter()
        .filter(|p| kept_prefix(p) < p.initial_bytes.len())
        .count();
    println!("   di cui {with_wc} con wildcard (rilocazioni)");

    println!();
    println!("== 2. scrittura del .sig ========================================");
    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "demo");
    println!("   {} byte, magic {:?}", sig.len(), &sig[..6]);

    println!();
    println!("== 3. rilettura =================================================");
    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        eprintln!("il .sig appena scritto non e' rileggibile");
        std::process::exit(1);
    };
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let tmp = std::path::Path::new(&dir).join("rustre_flirt_demo.sig");
    std::fs::write(&tmp, &sig).ok();
    let reread = rustre_flirt_apply::load_sig_file(&tmp).map_or(0, |v| v.len());
    let _ = std::fs::remove_file(&tmp);
    println!("   firme rilette dal file: {reread} su {} scritte", pats.len());

    println!();
    println!("== 4. scansione =================================================");
    let scan = |path: &str| -> HashSet<String> {
        std::fs::read(path).map_or_else(
            |_| HashSet::new(),
            |b| {
                scanner
                    .scan_fast(&b, 0)
                    .into_iter()
                    .map(|m| m.function_name)
                    .filter(|n| !n.is_empty())
                    .collect()
            },
        )
    };
    let hit = scan(target);
    let ctrl = scan(control);

    println!("   target   {target}");
    println!("            {} funzioni identificate", hit.len());
    println!("   controllo {control}");
    println!("            {} identificazioni — devono essere ZERO:", ctrl.len());
    println!("            quel binario non collega questo archivio, quindi");
    println!("            ogni match li' e' un falso positivo per costruzione.");

    println!();
    println!("== prima / dopo =================================================");
    let mut names: Vec<&String> = hit.iter().collect();
    names.sort();
    for n in names.iter().take(15) {
        println!("   sub_????????  ->  {n}");
    }
    if names.len() > 15 {
        println!("   … e altre {}", names.len() - 15);
    }

    println!();
    if ctrl.is_empty() && !hit.is_empty() {
        println!("Esito: {} nomi sul target, 0 sul controllo.", hit.len());
    } else if ctrl.is_empty() {
        println!("Esito: nessun match, e nessun falso positivo.");
        println!("Il binario potrebbe non collegare questo archivio: verifica");
        println!("il tetto con examples/recall_ceiling.rs prima di concludere.");
    } else {
        println!("Esito: {} falsi positivi sul controllo — da investigare.", ctrl.len());
    }
}
