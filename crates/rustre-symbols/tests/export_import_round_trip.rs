//! `SymbolExporter` and `SymbolImporter` are a producer/consumer pair inside one
//! crate: whatever one writes, the other must read back. No external oracle is
//! needed for that property.
//!
//! The interesting inputs are the names, because each format delimits them
//! differently — CSV quotes and doubles embedded quotes, IDC wraps them in
//! `"` and backslash-escapes, MAP separates on whitespace. A name containing
//! the delimiter is exactly the shape that broke the STIX exporter in
//! `rustre-threatintel`, where the value came back silently truncated.

use rustre_symbols::symbol_exporter::{ExportOptions, SymbolExporter};
use rustre_symbols::symbol_importer::{ImportOptions, SymbolImporter};
use rustre_symbols::{SymKind, Symbol};

/// Names that stress each format's delimiter, plus ordinary controls.
fn names() -> Vec<(&'static str, &'static str)> {
    vec![
        ("plain", "simple_symbol"),
        ("mangled", "_ZN4core3fmt5Debug3fmt17h1234567890abcdefE"),
        ("with space", "operator new"),
        ("with comma", "std::pair<int,int>::first"),
        ("with double quote", "sym_with_\"quote\""),
        ("with single quote", "don't_call_me"),
        ("with backslash", "ns\\sub\\sym"),
        ("non ascii", "función_ñ"),
    ]
}

fn symbols() -> Vec<Symbol> {
    names()
        .iter()
        .enumerate()
        .map(|(i, (_, n))| Symbol::new((*n).to_string(), 0x1000 + (i as u64) * 0x10, SymKind::Function))
        .collect()
}

/// Round trip through one format, returning the names that came back.
fn round_trip_csv(syms: &[Symbol]) -> Vec<String> {
    let text = SymbolExporter::to_csv(syms, &ExportOptions::default()).content;
    SymbolImporter::from_csv(&text, &ImportOptions::default())
        .expect("premise: our own CSV must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

fn round_trip_json(syms: &[Symbol]) -> Vec<String> {
    let text = SymbolExporter::to_json(syms, &ExportOptions::default())
        .expect("premise: exporting JSON must succeed")
        .content;
    SymbolImporter::from_json(&text, &ImportOptions::default())
        .expect("premise: our own JSON must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

#[test]
fn csv_reads_back_every_name_it_wrote() {
    let syms = symbols();
    let back = round_trip_csv(&syms);

    assert_eq!(
        back.len(),
        syms.len(),
        "CSV round trip lost symbols: wrote {}, read {}",
        syms.len(),
        back.len()
    );

    let mut divergences = Vec::new();
    for ((label, want), got) in names().iter().zip(back.iter()) {
        if want != got {
            divergences.push(format!("{label}: wrote `{want}`, read back `{got}`"));
        }
    }
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn json_reads_back_every_name_it_wrote() {
    let syms = symbols();
    let back = round_trip_json(&syms);

    assert_eq!(
        back.len(),
        syms.len(),
        "JSON round trip lost symbols: wrote {}, read {}",
        syms.len(),
        back.len()
    );

    let mut divergences = Vec::new();
    for ((label, want), got) in names().iter().zip(back.iter()) {
        if want != got {
            divergences.push(format!("{label}: wrote `{want}`, read back `{got}`"));
        }
    }
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn addresses_survive_the_csv_round_trip() {
    let syms = symbols();
    let text = SymbolExporter::to_csv(&syms, &ExportOptions::default()).content;
    let back = SymbolImporter::from_csv(&text, &ImportOptions::default())
        .expect("premise: our own CSV must be parseable")
        .into_symbols();

    // Addresses are what a symbol is *for*; a name that survives at the wrong
    // address is not a successful round trip.
    let wrote: Vec<u64> = syms.iter().map(|s| s.address).collect();
    let read: Vec<u64> = back.iter().map(|s| s.address).collect();
    assert_eq!(wrote, read, "addresses changed across the CSV round trip");
}

/// The remaining formats that have both a producer and a consumer.
///
/// `to_ghidra_bookmarks` / `from_ghidra_export` are deliberately excluded: the
/// names differ, so they may be two different Ghidra formats rather than a
/// pair, and pairing them here would manufacture a divergence that says nothing
/// about the code.
type RoundTrip = fn(&[Symbol]) -> Vec<(String, u64)>;

fn via_idc(syms: &[Symbol]) -> Vec<(String, u64)> {
    let text = SymbolExporter::to_idc(syms, &ExportOptions::default()).content;
    SymbolImporter::from_idc(&text, &ImportOptions::default())
        .expect("premise: our own IDC must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| (s.name, s.address))
        .collect()
}

fn via_map(syms: &[Symbol]) -> Vec<(String, u64)> {
    let text = SymbolExporter::to_map(syms, &ExportOptions::default()).content;
    SymbolImporter::from_map(&text, &ImportOptions::default())
        .expect("premise: our own MAP must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| (s.name, s.address))
        .collect()
}

fn via_radare2(syms: &[Symbol]) -> Vec<(String, u64)> {
    let text = SymbolExporter::to_radare2_flags(syms, &ExportOptions::default()).content;
    SymbolImporter::from_radare2_flags(&text, &ImportOptions::default())
        .expect("premise: our own radare2 flags must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| (s.name, s.address))
        .collect()
}

fn via_lldb(syms: &[Symbol]) -> Vec<(String, u64)> {
    let text = SymbolExporter::to_lldb(syms, &ExportOptions::default()).content;
    SymbolImporter::from_lldb(&text, &ImportOptions::default())
        .expect("premise: our own LLDB script must be parseable")
        .into_symbols()
        .into_iter()
        .map(|s| (s.name, s.address))
        .collect()
}

#[test]
fn every_paired_format_reads_back_what_it_wrote() {
    let formats: [(&str, RoundTrip); 4] = [
        ("idc", via_idc),
        ("map", via_map),
        ("radare2", via_radare2),
        ("lldb", via_lldb),
    ];

    let syms = symbols();
    let want: Vec<(String, u64)> = syms
        .iter()
        .map(|s| (s.name.clone(), s.address))
        .collect();

    // Accumulate every divergence across every format instead of stopping at the
    // first: one run then reports the whole shape of the problem.
    let mut divergences = Vec::new();
    for (format, round_trip) in formats {
        let got = round_trip(&syms);
        if got.len() != want.len() {
            divergences.push(format!(
                "{format}: wrote {} symbols, read back {}",
                want.len(),
                got.len()
            ));
            continue;
        }
        for ((label, _), (w, g)) in names().iter().zip(want.iter().zip(got.iter())) {
            // radare2 flag syntax is whitespace-delimited (`f name size addr`),
            // so a space in a name would make the line unparseable. The exporter
            // replaces spaces with underscores on purpose: this round trip is
            // lossy *by necessity*, and the expectation encodes that rather than
            // pretending the format can carry what it cannot.
            let expected_name = if format == "radare2" {
                w.0.replace(' ', "_")
            } else {
                w.0.clone()
            };
            if expected_name != g.0 || w.1 != g.1 {
                divergences.push(format!(
                    "{format}, {label}: expected ({expected_name}, {:#x}), read back ({}, {:#x})",
                    w.1, g.0, g.1
                ));
            }
        }
    }

    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn the_corpus_actually_stresses_the_delimiters() {
    // Anti-vacuity: the assertions above are only meaningful because the corpus
    // contains names carrying each format's delimiter.
    let all: Vec<&str> = names().iter().map(|(_, n)| *n).collect();
    assert!(all.iter().any(|n| n.contains(',')), "no name with a comma");
    assert!(all.iter().any(|n| n.contains('"')), "no name with a quote");
    assert!(all.iter().any(|n| n.contains(' ')), "no name with a space");
    assert!(all.iter().any(|n| !n.is_ascii()), "no non-ASCII name");
    assert_eq!(all.len(), 8, "anti-vacuity: the full corpus is exercised");
}
