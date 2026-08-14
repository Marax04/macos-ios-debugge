//! The arity metric shares its ground truth with what we publish (T17c).
//!
//! # The problem, as a number
//!
//! `tests/decompiler_corpus/prototypes.json` records its own provenance:
//! `"source": "mingw-w64 installed headers"`. The prototypes this crate
//! publishes were extracted from the same headers. Wherever the two sets
//! overlap, checking emitted arity against that file compares a value with its
//! own source: the comparison cannot fail, and a check that cannot fail measures
//! nothing.
//!
//! T17c carries this as a warning. Measured (iteration 71):
//!
//! | | count |
//! |---|---|
//! | names in `prototypes.json` | 136 |
//! | prototypes the bridge publishes | 227 |
//! | in both | **126** |
//! | share of the ground truth | **92.6%** |
//! | genuinely independent | **10** |
//!
//! So the metric is circular for more than nine names in ten. Its published
//! figure (122/135) is, for those, a statement that a file agrees with itself.
//!
//! # What to use instead
//!
//! The independent evidence is elsewhere: `behavior.py` compiles and runs the
//! emitted function beside the original (7/14), and `cross_build.py` compares
//! reconstructions of the same runtime from independently compiled binaries
//! (2 inconsistent of 1359). Those have ground truth the emitter never saw.
//!
//! # Why this is a test and not a comment
//!
//! A note in a TODO is read by whoever opens the TODO. This fails when the
//! overlap changes — if someone adds prototypes, independence shrinks further
//! and the number here stops matching, which is exactly the moment somebody
//! needs to be told.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

fn ground_truth() -> Option<(serde_json::Value, HashSet<String>)> {
    let path = repo_root().join("tests/decompiler_corpus/prototypes.json");
    let text = std::fs::read_to_string(path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&text).ok()?;
    let names = doc
        .get("prototypes")?
        .as_object()?
        .keys()
        .cloned()
        .collect();
    Some((doc, names))
}

fn published() -> HashSet<String> {
    rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

#[test]
fn the_ground_truth_declares_the_source_that_makes_it_circular() {
    let Some((doc, names)) = ground_truth() else {
        eprintln!("SKIP: prototypes.json assente");
        return;
    };
    assert!(names.len() > 100, "ground truth troppo piccola: {}", names.len());

    let source = doc
        .get("_provenance")
        .and_then(|p| p.get("source"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    assert!(
        source.contains("mingw"),
        "la provenienza non nomina piu' gli header mingw ({source:?}): se la \
         fonte e' cambiata, la circolarita' va rimisurata invece di assunta"
    );
}

/// The measurement itself. An inequality, because the point is to notice if the
/// overlap moves — in either direction.
#[test]
fn most_of_the_ground_truth_is_shared_with_what_we_publish() {
    let Some((_, ground)) = ground_truth() else {
        eprintln!("SKIP: prototypes.json assente");
        return;
    };
    let ours = published();
    let shared = ground.intersection(&ours).count();

    assert!(
        shared * 10 >= ground.len() * 9,
        "condivisi {shared} su {}: la sovrapposizione e' scesa sotto il 90%, \
         quindi la metrica di arieta' e' meno circolare di quanto registrato — \
         aggiorna T17c con la nuova misura",
        ground.len()
    );
}

/// The independent remainder, named. These are the only prototypes for which an
/// arity check says something the emitter did not already know.
#[test]
fn the_independent_remainder_is_small_and_enumerable() {
    let Some((_, ground)) = ground_truth() else {
        eprintln!("SKIP: prototypes.json assente");
        return;
    };
    let ours = published();
    let mut independent: Vec<&String> = ground.difference(&ours).collect();
    independent.sort();

    assert!(
        independent.len() <= 20,
        "{} nomi indipendenti: piu' di quanti ne registri T17c, rimisura",
        independent.len()
    );
    assert!(
        !independent.is_empty(),
        "zero nomi indipendenti: la metrica sarebbe interamente tautologica, e \
         andrebbe ritirata invece che annotata"
    );
    eprintln!("nomi indipendenti ({}): {independent:?}", independent.len());
}
