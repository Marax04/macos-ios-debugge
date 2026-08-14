//! The shipping `.pat` reader reads what our writers produce (T4).
//!
//! # A correction to iteration 48
//!
//! Iteration 48 measured the writer × parser matrix at **0 of 6** and published
//! the conclusion that the `.pat` writers were "effectively write-only". The
//! measurement was right; the conclusion was too strong.
//!
//! The matrix covered the three **public** parsers. It missed a fourth: a
//! private `parse_pat_line` in `flirt-apply/src/lib.rs`, reached through
//! `load_pat_file` and `load_auto` — which is the path a real caller takes. That
//! one reads the canonical format, so the files we write are readable by the
//! code that ships.
//!
//! Measured (iteration 50), writer → `load_pat_file`: **3 signatures of 3**,
//! wildcards preserved (4 in the wildcarded pattern), `crc_len` 8 and `crc`
//! 0xBEEF intact.
//!
//! What survives from iteration 48 is narrower and still worth fixing: three
//! public parsers each implement a mutually incompatible dialect, none of which
//! reads the documented format, and one of them (`parse_pat_text`) swallows
//! errors so that reading nothing looks like success. That is T4. But the defect
//! is duplication and a misleading public API, **not** data loss on the shipping
//! path — and the difference matters, because it changes whether this is urgent.
//!
//! These tests pin the production path so a future consolidation cannot quietly
//! break the one reader that currently works.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

fn sample_patterns() -> Vec<FlirtPattern> {
    let mk = |name: &str, wildcards: &[usize], crc_len: u8| {
        let bytes: Vec<PatternByte> = (0u8..32)
            .map(|i| {
                if wildcards.contains(&(i as usize)) {
                    PatternByte::Wildcard
                } else {
                    PatternByte::Exact(0x40u8.wrapping_add(i))
                }
            })
            .collect();
        let mut p = FlirtPattern::new(bytes);
        p.crc_length = crc_len;
        p.crc16 = if crc_len > 0 { 0xBEEF } else { 0 };
        p.pattern_length = 64;
        p.names.push(FlirtName {
            offset: 0,
            name: name.to_string(),
            is_public: true,
            is_local: false,
        });
        p
    };
    vec![
        mk("exact_fn", &[], 0),
        mk("wildcard_fn", &[3, 4, 5, 6], 0),
        mk("crc_fn", &[], 8),
    ]
}

fn write_and_load(tag: &str) -> Vec<rustre_flirt_apply::FlirtSignature> {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let path = std::path::Path::new(&dir).join(format!("rustre_prod_{tag}.pat"));
    rustre_flirt_gen::pat_file_writer::write_pat_file(&sample_patterns(), "prod", &path)
        .expect("scrittura .pat");
    let sigs = rustre_flirt_apply::load_pat_file(&path).expect("load_pat_file deve riuscire");
    let _ = std::fs::remove_file(&path);
    sigs
}

#[test]
fn every_written_pattern_is_loaded() {
    let sigs = write_and_load("count");
    assert_eq!(
        sigs.len(),
        3,
        "il percorso di produzione deve rileggere tutti i pattern scritti"
    );
}

#[test]
fn the_names_survive_the_production_path() {
    let sigs = write_and_load("names");
    let mut names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["crc_fn", "exact_fn", "wildcard_fn"]);
}

/// A `.pat` is text, so unlike the binary `.sig` container it *can* carry
/// wildcards — and here it does. Pinned as the contrast: the same three patterns
/// lose their wildcards entirely through `.sig`.
#[test]
fn the_wildcards_survive_at_the_right_offsets() {
    let sigs = write_and_load("wc");
    let wc = sigs
        .iter()
        .find(|s| s.name == "wildcard_fn")
        .expect("il pattern con wildcard deve essere caricato");

    let positions: Vec<usize> = wc
        .mask
        .iter()
        .enumerate()
        .filter(|(_, m)| **m == 0)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(positions, vec![3, 4, 5, 6], "wildcard spostati o persi");
    assert_eq!(wc.bytes.len(), 32, "lunghezza del pattern cambiata");
}

#[test]
fn the_crc_fields_survive_the_production_path() {
    let sigs = write_and_load("crc");
    let crc = sigs
        .iter()
        .find(|s| s.name == "crc_fn")
        .expect("il pattern con CRC deve essere caricato");
    assert_eq!(crc.crc_len, 8, "crc_len perso");
    assert_eq!(crc.crc, 0xBEEF, "crc perso");
}

/// The production reader and the canonical parser must agree on the same file.
/// If they diverge, consolidating on either one silently changes behaviour.
#[test]
fn the_production_reader_and_the_canonical_parser_agree() {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let path = std::path::Path::new(&dir).join("rustre_prod_agree.pat");
    rustre_flirt_gen::pat_file_writer::write_pat_file(&sample_patterns(), "prod", &path)
        .expect("scrittura .pat");
    let sigs = rustre_flirt_apply::load_pat_file(&path).expect("load_pat_file");
    let text = std::fs::read_to_string(&path).expect("rilettura");
    let _ = std::fs::remove_file(&path);

    let (canon, errs) = rustre_flirt::pat_canonical::parse_text(&text);
    assert!(errs.is_empty(), "il parser canonico riporta errori: {errs:?}");
    assert_eq!(
        sigs.len(),
        canon.len(),
        "i due lettori recuperano un numero diverso di pattern dallo stesso file"
    );

    let mut a: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
    let mut b: Vec<&str> = canon.iter().filter_map(FlirtPattern::primary_name).collect();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b, "i due lettori recuperano nomi diversi");
}
