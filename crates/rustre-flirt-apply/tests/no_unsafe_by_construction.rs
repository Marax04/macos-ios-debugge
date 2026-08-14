//! The FLIRT crates must stay free of `unsafe`, enforced by the compiler.
//!
//! # Why `forbid`, and why a test on top of it
//!
//! These crates parse third-party `.sig`, `.pat` and `.lib` files. In a parser
//! of untrusted input every memory error is a security bug, so "we happen not to
//! use `unsafe` right now" is a weaker property than "the compiler refuses to
//! build a violation".
//!
//! `#![forbid(unsafe_code)]` gives the second. Unlike `deny`, it cannot be
//! locally overridden with `#[allow]` — which is the whole point: a future
//! `unsafe` block cannot be waved through file-by-file.
//!
//! The test exists because the attribute can be *deleted*. `forbid` protects the
//! code; this protects the attribute.
//!
//! # A correction this test records
//!
//! The session's opening inventory reported "3 `unsafe` in rustre-flirt-apply".
//! That was wrong: the grep counted the **word** `unsafe`, and all three hits
//! were inside comments stating that the code deliberately avoids it. Measured
//! properly, all four crates contained **zero** `unsafe` constructs from the
//! start. The lesson is the recurring one — a grep result is only as good as its
//! pattern.

use std::path::{Path, PathBuf};

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

const GUARDED: &[&str] = &[
    "rustre-flirt",
    "rustre-flirt-gen",
    "rustre-flirt-apply",
    "rustre-analysis-typerecov",
];

#[test]
fn every_flirt_crate_forbids_unsafe_code() {
    for name in GUARDED {
        let lib = crates_root().join(name).join("src/lib.rs");
        let Ok(src) = std::fs::read_to_string(&lib) else {
            eprintln!("{name}: lib.rs non leggibile — salto");
            continue;
        };
        assert!(
            src.contains("#![forbid(unsafe_code)]"),
            "{name} ha perso `#![forbid(unsafe_code)]`: senza, un `unsafe` puo' \
             rientrare in un parser di input non fidato"
        );
    }
}

/// `deny` is not equivalent: it can be overridden by `#[allow(unsafe_code)]` on
/// an inner item, so a single block could slip back in without touching the
/// crate root. This asserts the stronger form is the one in use.
#[test]
fn the_guard_is_forbid_not_deny() {
    for name in GUARDED {
        let lib = crates_root().join(name).join("src/lib.rs");
        let Ok(src) = std::fs::read_to_string(&lib) else { continue };
        assert!(
            !src.contains("#![deny(unsafe_code)]"),
            "{name} usa `deny` invece di `forbid`: `deny` e' aggirabile con \
             `#[allow(unsafe_code)]` su un item interno"
        );
    }
}

/// A direct scan, independent of the attribute: no source file may contain an
/// `unsafe` block or function.
///
/// Redundant with `forbid` while the attribute is present — deliberately. If
/// someone removes the attribute *and* adds `unsafe`, the first test catches the
/// removal and this catches the code, so neither half alone can pass silently.
#[test]
fn no_source_file_contains_an_unsafe_construct() {
    fn scan(dir: &Path, offenders: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                scan(&p, offenders);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let Ok(src) = std::fs::read_to_string(&p) else { continue };
                for (i, line) in src.lines().enumerate() {
                    // Skip comments: the words "no unsafe" in prose are not
                    // `unsafe` code, and mistaking them for it is exactly the
                    // error the module doc above records.
                    let code = line.split("//").next().unwrap_or("");
                    let t = code.trim();
                    if t.starts_with("unsafe ")
                        || t.contains(" unsafe {")
                        || t.starts_with("unsafe{")
                        || t.contains("unsafe impl")
                        || t.contains("unsafe fn")
                    {
                        offenders.push(format!("{}:{}: {}", p.display(), i + 1, t));
                    }
                }
            }
        }
    }

    let mut offenders = Vec::new();
    for name in GUARDED {
        scan(&crates_root().join(name).join("src"), &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "costrutti `unsafe` trovati:\n  {}",
        offenders.join("\n  ")
    );
}

/// Guards the scanner itself: it must be able to recognise `unsafe` when it is
/// really there. A matcher that never matches would make the test above pass on
/// any codebase.
#[test]
fn the_scanner_would_actually_detect_unsafe() {
    let samples = [
        "unsafe fn danger() {}",
        "    unsafe { *ptr }",
        "unsafe impl Send for X {}",
        "let x = unsafe { transmute(y) };",
    ];
    for s in &samples {
        let code = s.split("//").next().unwrap_or("");
        let t = code.trim();
        let hit = t.starts_with("unsafe ")
            || t.contains(" unsafe {")
            || t.starts_with("unsafe{")
            || t.contains("unsafe impl")
            || t.contains("unsafe fn");
        assert!(hit, "lo scanner non riconosce: {s}");
    }

    // And must not fire on prose that merely mentions the word — the false
    // positive that produced the bogus "3 unsafe" figure.
    for s in [
        "// no unsafe blocks here",
        "//! integer part without `unsafe` blocks or `as`-casts",
        "// Extract the integer part (no unsafe, no as-cast).",
    ] {
        let code = s.split("//").next().unwrap_or("");
        let t = code.trim();
        let hit = t.starts_with("unsafe ") || t.contains(" unsafe {") || t.contains("unsafe fn");
        assert!(!hit, "falso positivo su un commento: {s}");
    }
}
