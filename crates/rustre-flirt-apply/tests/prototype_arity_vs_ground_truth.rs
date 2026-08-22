//! Check the Level 7 prototype database against the corpus ground truth.
//!
//! # On circularity — read before trusting this test
//!
//! `tests/decompiler_corpus/prototypes.json` and
//! `runtime_prototypes.rs` are both derived from the same mingw-w64 headers, so
//! this is **not** an independent oracle for whether those headers are right.
//!
//! What it *is* independent for: the two were produced by different extractors,
//! at different times, recording different things — the ground truth records
//! only an arity, this database records full parameter types. So a disagreement
//! means one of the two extractors is wrong, which is exactly the failure this
//! guards against: a regex that silently drops a parameter, mis-parses a
//! function-pointer argument, or counts `void` as one argument.
//!
//! What it can never tell us is whether the *emitted decompiler output* is
//! right. Once these prototypes feed the pipeline, `fidelity_arity.py` stops
//! being an independent check for these names, and the load-bearing metrics
//! become `behavior.py` (which runs the code) and `cross_build.py`.

use std::collections::HashMap;

use rustre_flirt_apply::runtime_prototypes::runtime_prototypes;

/// Minimal extraction of `{"name": {"arity": N, ...}}` without a JSON dependency.
fn ground_truth_arities(text: &str) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix('"')
            && let Some(end) = rest.find('"') {
                let key = &rest[..end];
                let after = rest[end + 1..].trim_start();
                if after.starts_with(':') && after.trim_start_matches(':').trim_start().starts_with('{') {
                    current = Some(key.to_string());
                    continue;
                }
                if key == "arity"
                    && let Some(name) = current.clone() {
                        let v: String = after
                            .trim_start_matches(':')
                            .trim()
                            .chars()
                            .take_while(|c| c.is_ascii_digit() || *c == '-')
                            .collect();
                        if let Ok(n) = v.parse::<i64>() {
                            out.insert(name, n);
                        }
                    }
            }
    }
    out
}

fn load_ground_truth() -> Option<HashMap<String, i64>> {
    // tests/ -> crate -> crates/ -> repo root
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    let path = root.join("tests/decompiler_corpus/prototypes.json");
    let text = std::fs::read_to_string(path).ok()?;
    Some(ground_truth_arities(&text))
}

#[test]
fn extracted_arity_matches_ground_truth_for_every_shared_name() {
    let Some(truth) = load_ground_truth() else {
        eprintln!("prototypes.json non trovato — test saltato (non è un pass silenzioso: \
                   il corpus non è presente in questo checkout)");
        return;
    };

    let db: HashMap<String, usize> = runtime_prototypes()
        .into_iter()
        .map(|s| (s.name, s.params.len()))
        .collect();

    let mut shared = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for (name, &want) in &truth {
        // Arity -1 marks a variadic prototype in the ground truth; we omit
        // variadics from the database on purpose, so absence is correct.
        if want < 0 {
            assert!(
                !db.contains_key(name),
                "`{name}` is variadic in the ground truth but was published anyway"
            );
            continue;
        }
        let Some(&got) = db.get(name) else { continue };
        shared += 1;
        if got as i64 != want {
            mismatches.push(format!("{name}: estratto {got}, ground truth {want}"));
        }
    }

    assert!(shared > 0, "nessun nome in comune: l'estrazione non ha prodotto nulla di utile");
    assert!(
        mismatches.is_empty(),
        "{} prototipi con arità divergente su {shared} confrontati:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    eprintln!("arità concordi su {shared} prototipi condivisi");
}

#[test]
fn known_unwind_prototypes_have_their_published_arity() {
    // Spot checks that do not depend on the corpus being present. These come
    // from unwind.h and are the ones the decompiler is measured on.
    let db: HashMap<String, usize> = runtime_prototypes()
        .into_iter()
        .map(|s| (s.name, s.params.len()))
        .collect();
    for (name, arity) in [
        ("_Unwind_GetIP", 1),
        ("_Unwind_SetIP", 2),
        ("_Unwind_GetCFA", 1),
        ("_Unwind_GetGR", 2),
        ("_Unwind_SetGR", 3),
        ("_Unwind_GetRegionStart", 1),
        ("_Unwind_GetLanguageSpecificData", 1),
        ("_Unwind_FindEnclosingFunction", 1),
        ("_Unwind_DeleteException", 1),
    ] {
        let got = db
            .get(name)
            .unwrap_or_else(|| panic!("`{name}` manca dal database dei prototipi"));
        assert_eq!(*got, arity, "arità di `{name}`");
    }
}

#[test]
fn no_prototype_has_a_zero_named_parameter_placeholder_collision() {
    // The extractor falls back to `argN` when a parameter is unnamed. Two
    // parameters sharing a name is not a cosmetic problem: it is C that does
    // not compile, and it was a real defect class in this project.
    for sig in runtime_prototypes() {
        let mut seen = std::collections::HashSet::new();
        for (name, _) in &sig.params {
            assert!(
                seen.insert(name.clone()),
                "`{}` ha due parametri chiamati `{name}`",
                sig.name
            );
        }
    }
}
