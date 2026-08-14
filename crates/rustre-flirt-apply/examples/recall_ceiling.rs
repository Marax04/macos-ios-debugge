//! Is the low cross-binary recall our fault, or the linker's? (T14)
//!
//! Self-match is 97.0%, but scanning a *different* mingw binary with 522
//! signatures harvested from `libmingwex.a` yields 2 names. Two very different
//! explanations produce that number:
//!
//! 1. the binary does not contain those functions — the linker only pulls in the
//!    archive members it needs, so recall is bounded by the target, not by us;
//! 2. the functions are there and the matcher misses them — our defect.
//!
//! Reporting "recall ≈ 1 of 522" without separating these would be dressing up
//! an unknown as a finding.
//!
//! This separates them with an oracle that needs no symbols: for each pattern,
//! search the target for its **concrete leading bytes** (the run before the first
//! wildcard, which is what identifies the function's entry). If those bytes are
//! absent, the function is not in the binary and no matcher could have found it.
//! The ceiling is how many patterns are *findable*; recall should be measured
//! against that, not against 522.

use std::collections::HashSet;

use rustre_flirt::PatternByte;

/// The concrete run at the start of a pattern — what a trie would key on.
fn concrete_prefix(p: &rustre_flirt::FlirtPattern) -> Vec<u8> {
    p.initial_bytes
        .iter()
        .take_while(|b| matches!(b, PatternByte::Exact(_)))
        .map(|b| match b {
            PatternByte::Exact(v) => *v,
            PatternByte::Wildcard => unreachable!(),
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let archive = a
        .get(1)
        .map_or(r"C:\msys64\mingw64\lib\libmingwex.a", String::as_str);
    let target = a
        .get(2)
        .map_or(r"tests\decompiler_corpus\bin\sample1_c.exe", String::as_str);

    let (Ok(arch_bytes), Ok(target_bytes)) = (std::fs::read(archive), std::fs::read(target)) else {
        eprintln!("input mancante");
        std::process::exit(2);
    };

    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, _) =
        rustre_flirt_gen::coff_archive::harvest_archive_bytes(&arch_bytes, &opts).expect("harvest");

    println!("archivio : {archive}");
    println!("target   : {target}");
    println!("firme    : {}", pats.len());

    // How many patterns could possibly be found: their entry bytes are present.
    // A very short prefix matches by chance, so report the ceiling at several
    // minimum lengths rather than one — a single number here would be the same
    // kind of over-claim the short-prefix false positives already were.
    for min_len in [4usize, 8, 12, 16] {
        let candidates: Vec<_> = pats
            .iter()
            .filter(|p| concrete_prefix(p).len() >= min_len)
            .collect();
        let present = candidates
            .iter()
            .filter(|p| contains(&target_bytes, &concrete_prefix(p)))
            .count();
        println!(
            "prefisso >= {min_len:>2} byte : {:>4} firme, {present:>3} con i byte presenti nel target",
            candidates.len()
        );
    }

    // What the scanner actually finds, for comparison.
    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "ceiling");
    let found = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).map_or(0, |s| {
        s.scan_fast(&target_bytes, 0)
            .into_iter()
            .map(|m| m.function_name)
            .collect::<HashSet<_>>()
            .len()
    });
    println!();
    println!("lo scanner ne trova: {found}");
    // Scale vs content: rebuild the database from only the findable signatures.
    // If the count jumps, the loss is in the database's size or trie shape; if
    // it stays put, it is in those patterns themselves.
    let findable: Vec<_> = pats
        .iter()
        .filter(|p| {
            let pre = concrete_prefix(p);
            pre.len() >= 8 && contains(&target_bytes, &pre)
        })
        .cloned()
        .collect();
    if !findable.is_empty() {
        let sig2 = rustre_flirt_gen::SigWriter::default().build(&findable, "subset");
        let found2 = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig2).map_or(0, |s| {
            s.scan_fast(&target_bytes, 0)
                .into_iter()
                .map(|m| m.function_name)
                .collect::<HashSet<_>>()
                .len()
        });
        println!(
            "database ridotto alle sole {} trovabili: ne trova {found2}",
            findable.len()
        );
    }

    println!();
    println!("Il recall va misurato contro il tetto (firme i cui byte esistono");
    println!("davvero nel target), non contro il totale delle firme generate.");
}
