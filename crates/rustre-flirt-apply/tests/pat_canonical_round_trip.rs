//! The canonical `.pat` parser reads what this workspace writes (T4, step 1).
//!
//! # What this closes, and what it does not
//!
//! Iteration 48 measured the writer × parser matrix at **0 of 6**: neither
//! `.pat` writer's output was readable by any of the three parsers, each of
//! which implements its own dialect. `tests/pat_round_trip_is_broken.rs` pins
//! that.
//!
//! `rustre_flirt::pat_canonical` implements the documented IDA format — the one
//! both writers emit and the only one an external tool produces — so the
//! round-trip closes. The tests below measure it end to end: write with the real
//! writer, read with the canonical parser, compare against the patterns that
//! went in.
//!
//! It is deliberately **additive**. The three dialect parsers are untouched and
//! their tests still pass; collapsing them into re-exports of this one is the
//! rest of T4, and it needs a decision about which callers move first. So
//! `pat_round_trip_is_broken.rs` still passes too: those parsers still cannot
//! read our output, and that stays recorded until they are actually moved.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte, pat_canonical};

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

fn write_with_real_writer(tag: &str) -> String {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let path = std::path::Path::new(&dir).join(format!("rustre_pat_canon_{tag}.pat"));
    rustre_flirt_gen::pat_file_writer::write_pat_file(&sample_patterns(), "canon", &path)
        .expect("scrittura .pat");
    let text = std::fs::read_to_string(&path).expect("rilettura");
    let _ = std::fs::remove_file(&path);
    text
}

#[test]
fn every_written_line_is_recovered() {
    let text = write_with_real_writer("all");
    let (pats, errs) = pat_canonical::parse_text(&text);

    assert!(errs.is_empty(), "errori di parsing: {errs:?}");
    assert_eq!(
        pats.len(),
        3,
        "attesi 3 pattern, recuperati {} — la matrice era 0 su 6 prima di T4",
        pats.len()
    );
}

#[test]
fn the_names_survive() {
    let text = write_with_real_writer("names");
    let (pats, _) = pat_canonical::parse_text(&text);

    let mut names: Vec<&str> = pats.iter().filter_map(FlirtPattern::primary_name).collect();
    names.sort_unstable();
    assert_eq!(names, ["crc_fn", "exact_fn", "wildcard_fn"]);
}

#[test]
fn the_wildcards_survive_at_the_right_offsets() {
    // A `.pat` is text, so unlike the `.sig` container it *can* carry wildcards.
    // If they shifted, the pattern would compare different bytes — the same
    // failure mode measured for the binary container, but silent here too.
    let text = write_with_real_writer("wc");
    let (pats, _) = pat_canonical::parse_text(&text);

    let wc = pats
        .iter()
        .find(|p| p.primary_name() == Some("wildcard_fn"))
        .expect("il pattern con wildcard deve essere recuperato");

    let positions: Vec<usize> = wc
        .initial_bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b, PatternByte::Wildcard))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(positions, vec![3, 4, 5, 6], "wildcard spostati o persi");
    assert_eq!(wc.initial_bytes.len(), 32, "lunghezza del pattern cambiata");
}

#[test]
fn the_crc_fields_survive() {
    let text = write_with_real_writer("crc");
    let (pats, _) = pat_canonical::parse_text(&text);

    let crc = pats
        .iter()
        .find(|p| p.primary_name() == Some("crc_fn"))
        .expect("il pattern con CRC deve essere recuperato");
    assert_eq!(crc.crc_length, 8, "crc_length perso");
    assert_eq!(crc.crc16, 0xBEEF, "crc16 perso");
    assert_eq!(crc.pattern_length, 64, "pattern_length perso");
}

/// Comments and the `---` terminator are part of the format, not noise to be
/// tolerated by accident: the writers emit a header, and IDA ends files with
/// `---`. Anything after the terminator must be ignored.
#[test]
fn comments_and_the_terminator_are_honoured() {
    let text = "\
; commento di intestazione
# altro stile di commento

404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 primo
---
404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 dopo_il_terminatore
";
    let (pats, errs) = pat_canonical::parse_text(text);
    assert!(errs.is_empty(), "errori inattesi: {errs:?}");
    assert_eq!(pats.len(), 1, "il terminatore --- deve fermare la lettura");
    assert_eq!(pats[0].primary_name(), Some("primo"));
}

/// A malformed line must be reported, not silently dropped.
/// `SimpleFlirtDatabase::parse_pat_text` swallows errors, which is precisely how
/// "zero patterns recovered" could look like a successful parse.
#[test]
fn malformed_lines_are_reported_not_swallowed() {
    let text = "\
404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 buono
ZZZZ 00 0000 0040 pattern_non_hex
4041 GG 0000 0040 crc_len_non_hex
4041
";
    let (pats, errs) = pat_canonical::parse_text(text);
    assert_eq!(pats.len(), 1, "solo la riga valida deve essere accettata");
    assert_eq!(
        errs.len(),
        3,
        "le 3 righe malformate devono essere segnalate, non scartate in silenzio"
    );
}
