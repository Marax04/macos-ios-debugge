//! Tre parser `.pat` pubblici non leggono cio' che i nostri writer producono (T4b).
//!
//! # What T4b said, and what was missing
//!
//! T4b measured that the four `.pat` parsers accept three different formats, and
//! concluded that "a `.pat` written for one part of the stack is not readable by
//! another". True, but it left the sharper question unasked: is any of it
//! readable by *anyone*?
//!
//! Measured (iteration 48) with `examples/pat_writer_parser_matrix.rs`, feeding
//! each writer's output to each parser — three patterns, one exact, one
//! wildcarded, one carrying a CRC:
//!
//! | writer \ parser | `apply::pat_parser` | `flirt::pat_parser_v2` | `flirt::parse_pat_text` |
//! |---|---|---|---|
//! | `gen::pat_file_writer` | ERR | 0 | 0 |
//! | `flirt::signature_writer` | ERR | 0 | 0 |
//!
//! **Six of six combinations recover nothing**, including each writer paired
//! with the parser in its own crate. The lines themselves look like canonical
//! IDA `.pat`:
//!
//! ```text
//! 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 exact_fn
//! 404142........4748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 wildcard_fn
//! ```
//!
//! Measured separately with and without the header comments, so that "cannot
//! handle a `;` header" is not confused with "cannot parse the line". Both fail:
//! `apply::pat_parser` reports `InvalidHex` on the full file and `InvalidLine`
//! on the data lines alone.
//!
//! # CORREZIONE (iterazione 50): la conclusione era troppo forte
//!
//! Da questa misura avevo concluso che i writer `.pat` fossero "di fatto
//! write-only". **Falso.** La matrice copriva i tre parser *pubblici*; ne
//! esisteva un quarto, privato — `parse_pat_line` in `flirt-apply/src/lib.rs`,
//! raggiunto da `load_pat_file` e `load_auto`, cioe' il percorso che un
//! chiamante reale prende davvero. Quello legge il formato canonico: misurato
//! 3 firme su 3, wildcard conservati, campi CRC intatti
//! (`tests/pat_production_path_reads_our_output.rs`).
//!
//! Cio' che resta vero e' piu' ristretto: tre parser pubblici implementano
//! dialetti mutuamente incompatibili, nessuno legge il formato documentato, e
//! `parse_pat_text` scarta gli errori in silenzio. E' duplicazione e un'API
//! pubblica fuorviante — non perdita di dati sul percorso che spedisce. La
//! differenza conta, perche' cambia l'urgenza.
//!
//! # Scope: this test pins, it does not fix
//!
//! Making a parser accept this is T4 (collapse the parsers into one). Each of
//! the three dialects has its own passing tests, so changing one breaks the
//! others; that is a job with its own iteration and its own decision about which
//! dialect is canonical. What is recorded here is the harm, so the fix can be
//! measured against it rather than argued about.

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

fn written_by_gen(tag: &str) -> String {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let path = std::path::Path::new(&dir).join(format!("rustre_pat_rt_{tag}.pat"));
    rustre_flirt_gen::pat_file_writer::write_pat_file(&sample_patterns(), "rt", &path)
        .expect("scrittura .pat");
    let text = std::fs::read_to_string(&path).expect("rilettura");
    let _ = std::fs::remove_file(&path);
    text
}

/// Data lines only: no blanks, no `---`, no comments.
fn data_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with("---") && !l.starts_with(';') && !l.starts_with('#')
        })
        .collect()
}

#[test]
fn the_writer_produces_lines_that_look_like_pat() {
    // Guard against a vacuous finding: if the writer emitted nothing, or emitted
    // garbage, "no parser reads it" would be trivially true and would say
    // nothing about the parsers.
    let text = written_by_gen("shape");
    let lines = data_lines(&text);
    assert_eq!(lines.len(), 3, "attese 3 righe dati, ottenute {}", lines.len());

    for l in &lines {
        let fields: Vec<&str> = l.split_whitespace().collect();
        assert!(
            fields.len() >= 5,
            "una riga .pat ha almeno 5 campi (pattern, crc_len, crc, len, nome): {l}"
        );
        assert!(
            fields[0].len() == 64 && fields[0].chars().all(|c| c.is_ascii_hexdigit() || c == '.'),
            "il primo campo deve essere 64 caratteri esadecimali o '.': {}",
            fields[0]
        );
    }
    assert!(
        lines.iter().any(|l| l.contains("..")),
        "una delle righe deve contenere wildcard, altrimenti il caso interessante manca"
    );
}

/// The headline: not one of the three parsers recovers a single line.
#[test]
fn no_parser_reads_what_our_own_writer_produces() {
    let text = written_by_gen("all");
    let joined = data_lines(&text).join("\n");

    let apply_ok = rustre_flirt_apply::pat_parser::parse_pat_text(&joined)
        .map_or(0, |v| v.len());
    let v2_ok = data_lines(&text)
        .iter()
        .enumerate()
        .filter(|(i, l)| rustre_flirt::pat_parser_v2::parse_pat_line(l, *i).is_ok())
        .count();
    let text_ok = rustre_flirt::SimpleFlirtDatabase::parse_pat_text(&text).len();

    assert_eq!(
        (apply_ok, v2_ok, text_ok),
        (0, 0, 0),
        "almeno un parser ora rilegge l'output del nostro writer \
         (apply={apply_ok}, v2={v2_ok}, text={text_ok}): e' esattamente cio' che \
         T4 deve ottenere — aggiorna questo test e PROGRESS.md con la misura"
    );
}

/// Distinguishing the two failure modes: a parser that only chokes on the header
/// comment is a different, much smaller defect than one that cannot parse the
/// line at all. Both are measured so a partial fix is visible as partial.
#[test]
fn the_failure_is_the_line_not_the_header_comment() {
    let text = written_by_gen("header");
    let with_header = rustre_flirt_apply::pat_parser::parse_pat_text(&text);
    let without_header =
        rustre_flirt_apply::pat_parser::parse_pat_text(&data_lines(&text).join("\n"));

    assert!(
        with_header.is_err(),
        "il file completo ora si legge: il difetto e' cambiato, rimisura"
    );
    assert!(
        without_header.is_err(),
        "senza commenti il parser riesce: allora il difetto era solo l'header, \
         che e' molto piu' piccolo di quanto registrato — aggiorna T4b"
    );
}
