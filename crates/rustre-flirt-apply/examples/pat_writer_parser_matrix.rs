//! Can this workspace read the `.pat` files it writes? (T4b)
//!
//! T4b measured that the `.pat` **parsers** accept three different formats. That
//! is untidiness until you know whether anything actually crosses between them.
//! This crosses them: every writer's output is fed to every parser, and the cell
//! says how many lines that parser recovered.
//!
//! A `.pat` is a text interchange format — its whole purpose is to be handed to
//! another tool. A writer whose output our own parsers reject is not a style
//! problem.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

/// Three patterns: exact, wildcarded, and one with a CRC — the shapes a `.pat`
/// line has to encode.
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

/// Content lines: not blank, not the `---` terminator, and not a comment.
/// Both writers emit a header (`;` and `#` respectively), so counting raw lines
/// would overstate what a parser is expected to recover.
fn count_lines(s: &str) -> usize {
    s.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with("---") && !l.starts_with(';') && !l.starts_with('#')
        })
        .count()
}

fn main() {
    let pats = sample_patterns();

    // ── the writers ──
    let mut written: Vec<(&str, String)> = Vec::new();

    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let out_path = std::path::Path::new(&dir).join("rustre_matrix.pat");
    rustre_flirt_gen::pat_file_writer::write_pat_file(&pats, "matrix", &out_path)
        .expect("scrittura .pat");
    written.push((
        "gen/pat_file_writer",
        std::fs::read_to_string(&out_path).expect("rilettura"),
    ));
    let _ = std::fs::remove_file(&out_path);

    let mut sw = rustre_flirt::flirt_signature_writer::FlirtSignatureWriter::new("matrix");
    for p in &pats {
        let bytes: Vec<Option<u8>> = p
            .initial_bytes
            .iter()
            .map(|b| match b {
                PatternByte::Exact(v) => Some(*v),
                PatternByte::Wildcard => None,
            })
            .collect();
        sw.insert_pattern(
            &bytes,
            rustre_flirt::flirt_signature_writer::FunctionDescriptor::new(
                0,
                p.crc16,
                p.crc_length,
                p.primary_name().unwrap_or("anon"),
            ),
        );
    }
    written.push(("flirt/signature_writer", sw.write_pat_file()));

    for (name, text) in &written {
        println!("--- writer {name}: {} righe utili", count_lines(text));
        for l in text.lines() {
            println!("    | {l}");
        }
    }
    println!();

    // ── the parsers ──
    println!(
        "{:<24} {:>16} {:>16} {:>14}",
        "writer \\ parser", "apply::pat_parser", "flirt::pat_v2", "flirt::pat_text"
    );
    // Two passes per writer: the file as written (with its header comments), and
    // only the data lines. A parser that fails on the first but succeeds on the
    // second cannot handle comments; one that fails on both cannot parse the
    // line. Conflating those would be a wrong diagnosis.
    let data_only = |text: &str| -> String {
        text.lines()
            .map(str::trim)
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with("---")
                    && !l.starts_with(';')
                    && !l.starts_with('#')
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    for (name, full) in &written {
        for (suffix, text) in [("(intero)", full.clone()), ("(solo dati)", data_only(full))] {
            let text = &text;
            let n_expected = count_lines(text);
            let apply_n = rustre_flirt_apply::pat_parser::parse_pat_text(text).map_or_else(
                |e| format!("ERR {e:?}").chars().take(14).collect::<String>(),
                |v| v.len().to_string(),
            );
            let v2_n = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with("---") && !l.starts_with(';') && !l.starts_with('#'))
                .enumerate()
                .filter(|(i, l)| rustre_flirt::pat_parser_v2::parse_pat_line(l, *i).is_ok())
                .count();
            let text_n = rustre_flirt::SimpleFlirtDatabase::parse_pat_text(text).len();
            let label = format!("{name} {suffix}");
            println!("{label:<36} {apply_n:>16} {v2_n:>14} {text_n:>14}   (scritte {n_expected})");
        }
    }

    println!();
    println!("Una cella < 'scritte' significa che quel parser non rilegge cio'");
    println!("che quel writer produce, nello stesso workspace.");
}
