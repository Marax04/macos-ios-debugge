//! Measure how much of a ground-truth prototype set the Level 7 bridge can
//! actually serve.
//!
//! The bridge (`typerecov_bridge`) only publishes a signature for a name that
//! has a *published* prototype. So the real question is not "does the wire
//! work?" but "does the prototype database intersect the functions the corpus
//! actually contains?".
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example `prototype_coverage` \
//!       [path/to/prototypes.json]
//!
//! With no argument it just lists what the bridge knows.

use std::collections::BTreeSet;

fn main() {
    let known: BTreeSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();

    println!("prototipi pubblicati nel bridge: {}", known.len());

    let Some(path) = std::env::args().nth(1) else {
        println!("(nessun file di ground truth passato — elenco soltanto)");
        for n in &known {
            println!("  {n}");
        }
        return;
    };

    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("impossibile leggere {path}");
        std::process::exit(2);
    };

    // Deliberately dependency-free: pull every "name"-ish JSON key rather than
    // pulling in a JSON parser for a diagnostic tool. Ground-truth files here
    // are flat maps keyed by function name.
    let mut truth: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('"')
            && let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if rest[end..].trim_start_matches('"').trim_start().starts_with(':')
                    && !name.starts_with('_')
                    || !name.is_empty()
                {
                    truth.insert(name.to_string());
                }
            }
    }

    let covered = truth.iter().filter(|n| known.contains(*n)).count();
    let missing: Vec<&String> = truth.iter().filter(|n| !known.contains(*n)).collect();

    println!("nomi nella ground truth : {}", truth.len());
    println!("coperti dal bridge      : {covered}");
    println!("NON coperti             : {}", missing.len());
    if !missing.is_empty() {
        println!("\nprimi 20 non coperti (questi sono il lavoro da fare):");
        for n in missing.iter().take(20) {
            println!("  {n}");
        }
    }
}
