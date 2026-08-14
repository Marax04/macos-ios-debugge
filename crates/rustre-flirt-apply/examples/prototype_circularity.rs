//! How circular is the arity metric? (T17c)
//!
//! `tests/decompiler_corpus/prototypes.json` records its own provenance:
//! "mingw-w64 installed headers". The prototypes the bridge publishes were
//! extracted from the same headers. Where the two sets overlap, measuring
//! emitted arity against `prototypes.json` compares a value to its own source —
//! it cannot fail, and a metric that cannot fail measures nothing.
//!
//! T17c records that as a warning. This turns it into a number: how much of the
//! ground truth is shared with what we publish.

use std::collections::HashSet;

fn main() {
    let path = std::path::Path::new("tests/decompiler_corpus/prototypes.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("prototypes.json assente");
        std::process::exit(2);
    };

    // Parsed with `serde_json`, not by string matching. A first version scanned
    // for `": "` and reported 139 names where the file holds 136 — a 2% error in
    // the denominator of the very ratio this example exists to state.
    let doc: serde_json::Value =
        serde_json::from_str(&text).expect("prototypes.json deve essere JSON valido");
    let ground: HashSet<String> = doc
        .get("prototypes")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let ours: HashSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();

    let shared = ground.intersection(&ours).count();
    println!("prototypes.json (ground truth) : {}", ground.len());
    println!("prototipi pubblicati dal ponte  : {}", ours.len());
    println!("  in comune                     : {shared}");
    #[allow(clippy::cast_precision_loss)]
    let pct = shared as f64 * 100.0 / ground.len().max(1) as f64;
    println!("  quota della ground truth      : {pct:.1}%");
    println!();
    println!("Sui nomi in comune l'arieta' emessa e' confrontata con la stessa");
    println!("fonte da cui e' stata generata: il confronto non puo' fallire.");

    let only_ground: Vec<&String> = {
        let mut v: Vec<&String> = ground.difference(&ours).collect();
        v.sort();
        v
    };
    println!();
    println!("nomi che restano indipendenti ({}):", only_ground.len());
    for n in only_ground.iter().take(20) {
        println!("   {n}");
    }
}
