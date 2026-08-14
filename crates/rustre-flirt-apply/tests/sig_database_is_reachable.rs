//! How many signatures can the FLIRT stack actually offer the decompiler?
//!
//! # The finding this test exists to pin down
//!
//! The decompiler builds its `FlirtScanner` from two embedded `.sigpack` text
//! files: `msvcrt-x64.sigpack` (**8** signatures) and `rust-stdlib-x64.sigpack`
//! (**14**). Twenty-two hand-written signatures are the entire FLIRT capability
//! of the pipeline.
//!
//! Meanwhile `assets/rust-stdlib.sig` is a 10.8 MB generated database in this
//! project's own `RFLIRTBIN` format, and `sig_file_loader` can read it — but
//! `SignaturePack::parse` only accepts the `SIGPACK 1` text format, so nothing
//! connects the two. The database is generated, committed, and never loaded.
//!
//! That is why the Level 7 work measured `considerate 0`: prototypes for 126 of
//! the corpus's 136 runtime functions cannot help if the identification step
//! offers 22 candidates. This test measures the gap so it stops being a guess.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

/// Count the `name |` entries in a `.sigpack` text file.
fn sigpack_signature_count(path: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(
        text.lines()
            .filter(|l| l.contains('|') && !l.starts_with("SIGPACK") && !l.starts_with("pack "))
            .count(),
    )
}

#[test]
fn the_packs_the_decompiler_loads_are_tiny() {
    let base = repo_root().join("crates/rustre-loader-pe/assets/baseline");
    let msvcrt = base.join("msvcrt-x64.sigpack");
    let rust = base.join("rust-stdlib-x64.sigpack");

    let Some(a) = sigpack_signature_count(&msvcrt) else {
        eprintln!("sigpack non presenti in questo checkout — test saltato");
        return;
    };
    let b = sigpack_signature_count(&rust).unwrap_or(0);

    eprintln!("firme nei sigpack caricati dal decompiler: msvcrt={a}, rust={b}, totale={}", a + b);

    // Not an aspiration — a tripwire. If someone grows these packs, this test
    // fails and the new number gets recorded deliberately instead of drifting.
    assert!(
        a + b < 100,
        "i sigpack sono cresciuti a {} firme: aggiorna la baseline in .claude/PROGRESS.md",
        a + b
    );
}

/// The signature stack has split into **three** islands that cannot exchange a
/// single signature. This test pins that down so it is a recorded fact rather
/// than a suspicion.
///
/// | format | written by | read by |
/// |---|---|---|
/// | `SIGPACK 1` (text) | hand-authored, 22 entries | the decompiler's scanner |
/// | `RFLIRTBIN\0` | `flirt-gen`'s `rust_stdlib_sigs` bin | `rustre-gui` only |
/// | `IDASGN` (IDA) | `rustre-flirt::lib` writer | `flirt-apply`'s `sig_file_loader` |
///
/// So the 10.8 MB generated database is read by the GUI and by nothing on the
/// decompilation path, while the loader that *could* feed the scanner speaks a
/// format the generator never emits. This is why Level 7 measured
/// `considerate 0`: the identification step has 22 candidates, not thousands.
#[test]
fn the_generated_database_and_the_loader_speak_different_formats() {
    let sig = repo_root().join("assets/rust-stdlib.sig");
    let Ok(bytes) = std::fs::read(&sig) else {
        eprintln!("assets/rust-stdlib.sig non presente — test saltato");
        return;
    };

    eprintln!("assets/rust-stdlib.sig: {} byte", bytes.len());

    // What the generator writes.
    assert!(
        bytes.starts_with(b"RFLIRTBIN\0"),
        "il database generato dovrebbe avere magic RFLIRTBIN, trovato {:?}",
        &bytes[..bytes.len().min(10)]
    );

    // What the loader demands.
    assert_eq!(
        rustre_flirt_apply::sig_file_loader::SIG_MAGIC,
        b"IDASGN",
        "il loader dichiara un magic diverso da quello atteso da questo test"
    );

    // Therefore: the loader cannot read it. Asserting the failure keeps the
    // defect visible; the day someone bridges the formats, this test fails and
    // forces the win to be recorded rather than slipping by unnoticed.
    let loader = rustre_flirt_apply::sig_file_loader::SigFileLoader::new();
    assert!(
        loader.load(&sig).is_err(),
        "il loader ora legge il database generato: il divario e' chiuso, \
         aggiorna .claude/PROGRESS.md e questo test"
    );
}

#[test]
fn sigpack_parser_rejects_the_binary_database_which_is_why_it_is_unused() {
    // Documents the actual disconnect: the scanner is fed by `SignaturePack`,
    // which only speaks the `SIGPACK 1` text format. Handing it the binary
    // database fails — so the two halves cannot meet without a conversion step.
    let sig = repo_root().join("assets/rust-stdlib.sig");
    let Ok(bytes) = std::fs::read(&sig) else {
        eprintln!("assets/rust-stdlib.sig non presente — test saltato");
        return;
    };
    let as_text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let parsed = rustre_flirt_apply::SignaturePack::parse(&as_text);
    assert!(
        parsed.is_err(),
        "SignaturePack ha accettato il formato binario: se ora lo supporta, \
         il collegamento e' piu' semplice di quanto documentato qui"
    );
}
