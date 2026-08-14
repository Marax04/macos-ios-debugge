//! The bridge publishes what it can — the blocker is upstream (Level 7).
//!
//! # Why this test exists
//!
//! Iteration 57 read the decompiler's trace — `considerate 28, pubblicate 0,
//! senza prototipo 28` — and concluded that the matched names simply had no
//! prototypes, capping Level 7. Two things were wrong with that.
//!
//! **First, the measurement was contaminated.** The signature directory also
//! held `all.sig` and `pubonly.sig` from an earlier session, so the decompiler
//! loaded 108 634 signatures (mostly rust-stdlib) while the scan I compared it
//! against used 255. I was comparing two different runs and reading the
//! difference as a finding. Re-run with an isolated directory: 263 signatures,
//! 26 raw matches, and still **0 published**.
//!
//! **Second, the bridge is not the blocker.** Handed the identifications our own
//! scanner produces, it publishes:
//!
//! | | considered | published |
//! |---|---|---|
//! | all identifications | 33 | **4** |
//! | after dropping ambiguous names | 26 | **4** |
//!
//! The four are `__acrt_iob_func`, `__mingw_raise_matherr`, `_configthreadlocale`
//! and `_matherr`. The ambiguity filter is not what removes them either — it
//! drops `__cxa_atexit`, `__mingw_GetSectionForAddress` and `_setargv`, none of
//! which has a prototype.
//!
//! So the bridge works, and the decompiler's identification list is what does not
//! contain those names. That list is produced upstream, in the decompiler's own
//! scanning (which walks mapped sections at virtual addresses, where this test
//! scans the file at offset 0) — a different crate and a different measurement,
//! which is why this file asserts what it can observe and does not speculate
//! about the rest.

use std::collections::{HashMap, HashSet};

const SIG: &str = r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig";

fn corpus_binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("il crate deve stare in <root>/crates/<name>")
        .join("tests/decompiler_corpus/bin/sample1_c.exe")
}

fn identifications() -> Option<Vec<(u64, String)>> {
    let sig = std::fs::read(SIG).ok()?;
    let bin = std::fs::read(corpus_binary()).ok()?;
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).ok()?;
    let ids: Vec<(u64, String)> = scanner
        .scan_fast(&bin, 0)
        .into_iter()
        .map(|m| (m.address, m.function_name))
        .filter(|(_, n)| !n.is_empty())
        .collect();
    (!ids.is_empty()).then_some(ids)
}

#[test]
fn the_bridge_publishes_the_names_that_have_prototypes() {
    let Some(ids) = identifications() else {
        eprintln!("SKIP: sigdb o corpus assenti");
        return;
    };

    let known: HashSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();
    let distinct: HashSet<&str> = ids.iter().map(|(_, n)| n.as_str()).collect();
    let expected = distinct.iter().filter(|n| known.contains(**n)).count();

    assert!(
        expected > 0,
        "nessuno dei nomi combacianti ha un prototipo: il test non distinguerebbe \
         un ponte rotto da un divario di prototipi"
    );

    let refs: Vec<(u64, &str)> = ids.iter().map(|(a, n)| (*a, n.as_str())).collect();
    let stats = rustre_flirt_apply::typerecov_bridge::publish_identifications(refs);

    assert_eq!(
        stats.published, expected,
        "il ponte ha pubblicato {} dei {expected} nomi che hanno un prototipo: \
         se scende a 0, il difetto e' nel ponte e non a monte",
        stats.published
    );
}

/// The ambiguity filter must not be what removes the useful names. Measured: it
/// drops three names, none of which has a prototype, and the published count is
/// unchanged.
#[test]
fn the_ambiguity_filter_does_not_remove_publishable_names() {
    let Some(ids) = identifications() else {
        eprintln!("SKIP: sigdb o corpus assenti");
        return;
    };

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (_, n) in &ids {
        *counts.entry(n.as_str()).or_default() += 1;
    }

    let all: Vec<(u64, &str)> = ids.iter().map(|(a, n)| (*a, n.as_str())).collect();
    let before = rustre_flirt_apply::typerecov_bridge::publish_identifications(all).published;

    let survivors: Vec<(u64, &str)> = ids
        .iter()
        .filter(|(_, n)| counts.get(n.as_str()).copied().unwrap_or(0) == 1)
        .map(|(a, n)| (*a, n.as_str()))
        .collect();
    let after = rustre_flirt_apply::typerecov_bridge::publish_identifications(survivors).published;

    assert_eq!(
        before, after,
        "il filtro ambiguita' fa scendere le pubblicazioni da {before} a {after}: \
         starebbe scartando proprio i nomi utili, e andrebbe ristretto"
    );
}
