//! The `this`-pointer cv byte has four states, and two were unrepresentable.
//!
//! An MSVC non-static member function encodes `<access><this-cv><cc><ret>…`,
//! and the cv byte is `A` none, `B` const, `C` volatile, `D` const volatile.
//! The parser stored it as a **`bool`**, `cv == 'B' || cv == 'D'`, so
//! `volatile` was dropped entirely and `const volatile` rendered as plain
//! `const`:
//!
//! ```text
//!   ?foo@Cls@@QCAXXZ
//!     was  public: void __cdecl Cls::foo(void)
//!     want public: void __cdecl Cls::foo(void) volatile
//! ```
//!
//! Distinct symbols therefore collapsed in pairs — `QAA…`/`QCA…` and
//! `QBA…`/`QDA…`. Unlike the D and Swift collisions found by the same
//! cross-product method, this one is **decidable**: MSVC has an oracle, and
//! `msvc-demangler` renders all four.
//!
//! Found by crossing access × this-cv × calling convention × return × params,
//! which no test crossed. The three-axis version of the same sweep (without the
//! cv slot) agreed with the oracle on all 640 shapes and reported no
//! collisions — the defect needed the fourth axis to express.
//!
//! **A note on the probe, which over-generated twice.** Static access chars
//! (`C D K L S T`) and global ones (`Y Z`) have no `this`, so no cv slot; a
//! uniform four-slot generator shifts every following byte for them and
//! produces symbols that mean something else. And `E`/`F`/`I` in that position
//! are `this`-pointer *modifiers* (`__ptr64`, `__unaligned`, `__restrict`), not
//! cv bytes. Restricting to the twelve non-static access chars is what turned
//! 261 apparent disagreements into zero.

use std::collections::BTreeMap;

fn oracle(sym: &str) -> Option<String> {
    msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::llvm()).ok()
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// The crate omits the space in `int *`; that is presentation, not content.
fn normalise(s: &str) -> String {
    s.replace(' ', "")
}

/// Access chars for functions that HAVE a `this` pointer, and therefore a cv
/// slot. Static and global forms are deliberately excluded — see the module
/// note.
const NON_STATIC_ACCESS: [&str; 12] =
    ["A", "B", "E", "F", "I", "J", "M", "N", "Q", "R", "U", "V"];

const THIS_CV: [&str; 4] = ["A", "B", "C", "D"];
const CALLING_CONV: [&str; 8] = ["A", "E", "G", "I", "C", "K", "M", "O"];
const RETURNS: [&str; 8] = ["H", "X", "D", "N", "_N", "J", "K", "PAH"];
const PARAMS: [&str; 5] = ["XZ", "HZ", "H@Z", "HH@Z", "PAH@Z"];

/// **The defect.** All four cv states, against the oracle.
#[test]
fn every_this_cv_state_matches_the_oracle() {
    let mut seen = BTreeMap::new();
    for cv in THIS_CV {
        let sym = format!("?foo@Cls@@Q{cv}AXXZ");
        let want = oracle(&sym).unwrap_or_else(|| panic!("{sym}: generator produced invalid input"));
        let got = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(normalise(&got), normalise(&want), "cv byte {cv}");
        assert!(seen.insert(got, cv).is_none(), "cv byte {cv} collides with an earlier one");
    }
    assert_eq!(seen.len(), 4, "four cv states must give four renderings");

    // Spelled out, so a regression names the missing qualifier rather than just
    // failing a comparison.
    assert!(ours("?foo@Cls@@QCAXXZ").unwrap().ends_with(" volatile"));
    assert!(ours("?foo@Cls@@QDAXXZ").unwrap().ends_with(" const volatile"));
}

/// The full cross-product differential: every oracle-valid shape must agree.
#[test]
fn the_member_function_grammar_agrees_with_the_oracle() {
    let mut compared = 0;
    let mut differ = Vec::new();

    for a in NON_STATIC_ACCESS {
        for cv in THIS_CV {
            for cc in CALLING_CONV {
                for r in RETURNS {
                    for p in PARAMS {
                        let sym = format!("?foo@Cls@@{a}{cv}{cc}{r}{p}");
                        // The oracle arbitrates validity: a shape it rejects is
                        // a generator artefact, not a finding.
                        let Some(want) = oracle(&sym) else { continue };
                        compared += 1;
                        match ours(&sym) {
                            Some(g) if normalise(&g) == normalise(&want) => {}
                            other => differ.push(format!(
                                "{sym}\n  oracle: {want}\n  ours:   {other:?}"
                            )),
                        }
                    }
                }
            }
        }
    }

    assert!(compared > 5000, "vacuous: only {compared} shapes had ground truth");
    assert!(
        differ.is_empty(),
        "{} of {compared} disagree:\n{:#?}",
        differ.len(),
        &differ[..differ.len().min(6)]
    );
}

/// Where renderings still collapse, the oracle must collapse them too.
///
/// The access chars come in pairs (`A`/`B`, `Q`/`R`, `U`/`V`, …) differing only
/// in a 16-bit-era near/far marker that `undname` does not print. Sharing a
/// rendering there is correct, not a defect — but it has to be *checked*
/// against the oracle rather than assumed, which is the difference between this
/// and the D `K`/`R` collision that had to be parked.
#[test]
fn every_remaining_collision_is_one_the_oracle_shares() {
    let mut by_output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in NON_STATIC_ACCESS {
        for cv in THIS_CV {
            let sym = format!("?foo@Cls@@{a}{cv}A_NH@Z");
            if oracle(&sym).is_some()
                && let Some(g) = ours(&sym)
            {
                by_output.entry(g).or_default().push(sym);
            }
        }
    }

    let mut groups = 0;
    for (rendered, syms) in &by_output {
        if syms.len() < 2 {
            continue;
        }
        groups += 1;
        let first = oracle(&syms[0]);
        for s in syms {
            assert_eq!(oracle(s), first, "{s} collapses for us but not for the oracle: {rendered}");
        }
    }
    assert!(groups > 0, "vacuous: no collision groups to check");
}
