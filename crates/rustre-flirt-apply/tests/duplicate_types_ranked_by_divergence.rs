//! Ranks the 52 duplicated public types by whether they actually diverge (T37).
//!
//! # Why a count of 52 is not yet actionable
//!
//! `duplication_inventory.rs` measures that 52 public type names are declared
//! more than once across the four crates. That number says the duplication
//! exists; it does not say which instances can hurt, and "fix all 52" is exactly
//! the sweeping unverified refactor this effort forbids.
//!
//! Two types sharing a name is not automatically a defect. What produced every
//! real failure in this session was a narrower thing: two types with the **same
//! name and different fields**, each round-tripping happily through its own half
//! of the stack and disagreeing only where the halves meet. That is how a
//! `FlirtPattern` without `crc_offset` silently built a CRC window in the wrong
//! place (iteration 38), and how two `SigHeader` layouts coexisted for eleven
//! green tests (T27).
//!
//! So this splits the 52 by field-set divergence:
//!
//! * **CONGRUENT** — every declaration has the same set of public field names.
//!   Mechanical to merge, and harmless until then: code written against one
//!   works against the other.
//! * **DIVERGENT** — the declarations disagree on their fields. A value of one
//!   cannot stand in for the other, and any code that assumes it can is wrong in
//!   the silent way.
//!
//! Measured on 2026-07-29: **50 divergent, 2 congruent** of the 52.
//!
//! # Divergent is necessary for harm, not sufficient
//!
//! That 50 must not be read as "50 defects". The scan groups by *name*, and two
//! unrelated types can legitimately share one: `Confidence` is an enum in
//! `typerecov` and a struct in `flirt_applicator`, `CollisionResolver` names a
//! strategy enum in one crate and a weight table in another. Those are name
//! collisions across module boundaries, which Rust handles; nobody can pass one
//! for the other.
//!
//! The harmful subset is narrower: duplicates that model the **same concept**,
//! so that code, data or a serialised layout can cross between them. Those are
//! the ones that produced real failures. The clearest instances the scan
//! surfaces:
//!
//! * `FlirtPattern` — the one that has already cost errors (see the test below);
//! * `CoffSection` / `CoffSymbol` — **two parsers of the same COFF structures
//!   inside one crate**, `library_scanner.rs` and `pattern_extractor.rs`, which
//!   even disagree on spelling (`section_num` vs `section_number`, `type_field`
//!   vs `type_`). Same crate, same file format, two decoders;
//! * `SigHeader` x5 — the layout family that took eleven green tests to unmask.
//!
//! So the ranking this test produces is a *shortlist to triage*, not a work
//! order. The next iterations should take same-concept duplicates one at a time
//! and leave the coincidental ones alone.
//!
//! # Honest limits of this measurement
//!
//! It is a source scan, not a compile-time analysis. It matches `pub struct` /
//! `pub enum` declarations and their `pub` field names by pattern. Consequences,
//! stated rather than hidden:
//!
//! * enums are compared on their **variant** names, structs on their **public
//!   field** names; a struct whose fields are all private reads as an empty set,
//!   so two such types count as congruent on no evidence;
//! * field **types** are not compared, only names — two `crc: u16` and
//!   `crc: u32` read as congruent;
//! * a type behind `#[cfg]` is counted like any other.
//!
//! Each of those makes the divergent count an **under**-estimate. That is the
//! safe direction for a number used to decide what to fix, but it means
//! "CONGRUENT" here means "not shown to diverge", never "proven identical".

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

const CRATES: &[&str] = &[
    "rustre-flirt",
    "rustre-flirt-gen",
    "rustre-flirt-apply",
    "rustre-analysis-typerecov",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// One declaration of a public type: where it is, and what it exposes.
#[derive(Debug, Clone)]
struct Decl {
    file: String,
    members: BTreeSet<String>,
}

/// Parse the member set of the declaration starting at `lines[start]`, by
/// brace-depth scanning to the closing brace of the body.
fn members_of(lines: &[&str], start: usize, is_enum: bool) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    let mut depth = 0usize;
    let mut started = false;

    for line in &lines[start..] {
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        if started && depth > 0 {
            let t = line.trim();
            // Skip attributes, doc comments, comments and nested-brace noise.
            if !t.starts_with('#') && !t.starts_with("//") && !t.is_empty() {
                let candidate = if is_enum {
                    // `Variant,` / `Variant {` / `Variant(..)` at depth 1 only.
                    if depth == 1 {
                        t.split(['(', '{', ',', ' ']).next().unwrap_or("")
                    } else {
                        ""
                    }
                } else if let Some(rest) = t.strip_prefix("pub ") {
                    // `pub name: Type,` — a field, not `pub fn` inside an impl.
                    rest.split(':').next().unwrap_or("").trim()
                } else {
                    ""
                };
                let ok = !candidate.is_empty()
                    && candidate
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_')
                    && candidate.chars().next().is_some_and(char::is_alphabetic);
                if ok {
                    members.insert(candidate.to_string());
                }
            }
        }

        depth += opens;
        if opens > 0 {
            started = true;
        }
        depth = depth.saturating_sub(closes);
        if started && depth == 0 {
            break;
        }
    }
    members
}

/// Every public struct/enum declaration, grouped by type name.
fn declarations() -> BTreeMap<String, Vec<Decl>> {
    let mut map: BTreeMap<String, Vec<Decl>> = BTreeMap::new();
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&crates_root().join(c).join("src"), &mut files);
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            let lines: Vec<&str> = text.lines().collect();
            let rel = format!(
                "{c}/{}",
                f.file_name().unwrap_or_default().to_string_lossy()
            );
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                let (kw, is_enum) = if t.starts_with("pub struct ") {
                    ("pub struct ", false)
                } else if t.starts_with("pub enum ") {
                    ("pub enum ", true)
                } else {
                    continue;
                };
                let name: String = t[kw.len()..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if name.is_empty() {
                    continue;
                }
                map.entry(name).or_default().push(Decl {
                    file: rel.clone(),
                    members: members_of(&lines, i, is_enum),
                });
            }
        }
    }
    map
}

fn duplicated() -> BTreeMap<String, Vec<Decl>> {
    declarations()
        .into_iter()
        .filter(|(_, d)| d.len() > 1)
        .collect()
}

fn is_divergent(decls: &[Decl]) -> bool {
    let first = &decls[0].members;
    decls.iter().any(|d| &d.members != first)
}

#[test]
fn report_the_split_between_congruent_and_divergent() {
    let dup = duplicated();
    let (divergent, congruent): (Vec<_>, Vec<_>) =
        dup.iter().partition(|(_, d)| is_divergent(d));

    println!("nomi duplicati: {}", dup.len());
    println!("  DIVERGENTI (campi diversi): {}", divergent.len());
    println!("  congruenti  (stessi campi): {}", congruent.len());
    println!();
    for (name, decls) in &divergent {
        println!("DIVERGENTE {name} x{}", decls.len());
        for d in *decls {
            let mut m: Vec<&str> = d.members.iter().map(String::as_str).collect();
            m.truncate(8);
            println!("    {:<44} [{}]", d.file, m.join(", "));
        }
    }

    assert!(
        !dup.is_empty(),
        "zero duplicati: lo scanner non sta trovando le dichiarazioni, non e' \
         il debito che e' sparito — controlla il parsing prima di esultare"
    );
}

/// The parser must actually find members, or every type would read as congruent
/// on an empty set and the divergent count would be a comfortable zero.
#[test]
fn the_member_parser_is_not_vacuous() {
    let decls = declarations();
    let with_members = decls
        .values()
        .flatten()
        .filter(|d| !d.members.is_empty())
        .count();
    let total = decls.values().map(Vec::len).sum::<usize>();

    assert!(total > 100, "attese molte dichiarazioni, trovate {total}");
    assert!(
        with_members * 2 > total,
        "solo {with_members} dichiarazioni su {total} hanno membri: il parser \
         e' vacuo e la classificazione non significa nulla"
    );
}

/// The known-harmful case, asserted by name so a merge of it is visible.
/// `FlirtPattern` is the duplicate that has already cost this project real
/// errors: the `rustre-flirt` one carries `crc16`/`crc_length`, the
/// `flirt-apply` one `crc_offset`/`crc_len`/`crc`, and code written against one
/// builds the CRC window in the wrong place against the other.
#[test]
fn flirt_pattern_is_still_a_divergent_duplicate() {
    let dup = duplicated();
    let Some(decls) = dup.get("FlirtPattern") else {
        panic!("FlirtPattern non risulta piu' duplicato: se e' stato unificato, \
                aggiorna questo test, T29 e T37 con la misura");
    };
    assert!(
        is_divergent(decls),
        "FlirtPattern risulta congruente: o e' stato unificato, o il parser dei \
         campi ha smesso di vedere le differenze — verifica quale dei due"
    );
}

/// Same-concept duplicates **inside a single crate** are the strongest signal
/// the scan produces: a name collision across crates can be coincidence, two
/// decoders of the same file format in one crate cannot.
///
/// `rustre-flirt-gen` parses COFF twice, in `library_scanner.rs` and
/// `pattern_extractor.rs`, and the two disagree even on how to spell the same
/// COFF fields. Pinned as the recommended next target for T37: it is bounded
/// (one crate, one format), it has ground truth (the published COFF layout), and
/// the round-trip of T14 can measure whether unifying it is emission-neutral.
#[test]
fn the_two_coff_decoders_in_one_crate_are_still_separate() {
    let dup = duplicated();
    for name in ["CoffSection", "CoffSymbol"] {
        let Some(decls) = dup.get(name) else {
            panic!("{name} non risulta piu' duplicato: se i due decoder COFF \
                    sono stati unificati, aggiorna questo test e T37 con la misura");
        };
        let same_crate = decls
            .iter()
            .filter(|d| d.file.starts_with("rustre-flirt-gen/"))
            .count();
        assert!(
            same_crate >= 2,
            "{name}: attese >=2 dichiarazioni in rustre-flirt-gen, trovate \
             {same_crate} — la duplicazione intra-crate e' cambiata, rimisura"
        );
    }
}

/// The gate: the divergent set must not grow silently. Deliberately an
/// inequality against a measured baseline, not an exact pin — this iteration's
/// job is to rank the debt, not to freeze it.
///
/// The baseline is **50, measured**. An earlier draft of this test guessed 40
/// and failed on the spot; recorded because it is the rule this effort keeps
/// relearning — a constant written from intuition is not a baseline, and the
/// only reason it did not become a published number is that the assertion
/// happened to point the right way.
#[test]
fn the_divergent_set_does_not_grow() {
    const BASELINE: usize = 50;
    let n = duplicated().values().filter(|d| is_divergent(d)).count();
    assert!(
        n <= BASELINE,
        "duplicati divergenti passati da {BASELINE} a {n}: due tipi omonimi con \
         campi diversi sono la forma che ha prodotto ogni difetto reale della \
         sessione"
    );
}
