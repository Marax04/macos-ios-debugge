//! `unified_to_legacy` converts `SymbolKind` (9 variants) into `SymKind`, and
//! `symbol_merger::legacy_to_unified_kind` converts back. The reverse map is
//! **exhaustive** — the compiler checks it — while the forward one used a
//! `_ => SymKind::Function` catch-all, so every kind nobody listed silently
//! became executable code.
//!
//! `Module` was the casualty: the reverse map pairs `SymKind::File` with
//! `SymbolKind::Module`, yet a compilation unit came out of the exporter
//! labelled `Function`, i.e. "executable code with a call target at `address`".
//!
//! Both helpers are private, so the property is asserted through the public
//! `SymbolExporter::unified_to_json`, which is what actually reaches a user.

use rustre_symbols::symbol_exporter::SymbolExporter;
use rustre_symbols::{SymbolKind, SymbolSource, UnifiedSymbol, UnifiedSymbolTable};

/// Every variant, and the `SymKind` name each must be emitted as.
///
/// `Thunk`, `Import` and `Export` legitimately collapse onto `Function`:
/// `SymKind` has no counterpart for them and the reverse map never produces
/// them, so that is a deliberate choice rather than a forgotten branch.
fn expected() -> Vec<(SymbolKind, &'static str)> {
    vec![
        (SymbolKind::Function, "Function"),
        (SymbolKind::Variable, "Data"),
        (SymbolKind::Label, "Label"),
        (SymbolKind::Section, "Section"),
        (SymbolKind::Namespace, "Namespace"),
        (SymbolKind::Module, "File"),
        (SymbolKind::Thunk, "Function"),
        (SymbolKind::Import, "Function"),
        (SymbolKind::Export, "Function"),
    ]
}

fn export_one(kind: SymbolKind) -> String {
    let mut table = UnifiedSymbolTable::new();
    table.add(UnifiedSymbol::new(
        "the_symbol".to_string(),
        0x1000,
        kind,
        SymbolSource::Manual,
    ));
    SymbolExporter::unified_to_json(&table).expect("premise: exporting one symbol must succeed")
}

#[test]
fn every_symbol_kind_reaches_the_exporter_as_its_documented_counterpart() {
    let cases = expected();
    assert_eq!(cases.len(), 9, "anti-vacuity: every SymbolKind variant listed");

    let mut divergences = Vec::new();
    let mut distinct: Vec<&str> = Vec::new();

    for (kind, want) in &cases {
        let json = export_one(*kind);
        let needle = format!("\"{want}\"");
        if !json.contains(&needle) {
            divergences.push(format!(
                "{kind:?} was not emitted as {want}; exported JSON was:\n{json}"
            ));
        }
        if !distinct.contains(want) {
            distinct.push(want);
        }
    }

    // Both outcomes must occur: if everything collapsed onto one kind the
    // per-case assertions would still be satisfiable by a constant mapping.
    assert!(
        distinct.len() >= 5,
        "anti-vacuity: expected several distinct emitted kinds, got {distinct:?}"
    );
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_module_is_not_exported_as_executable_code() {
    // The decisive consequence, not merely "the mapping changed": `SymKind`
    // documents `Function` as "executable code with a call target at address".
    // A compilation unit is not that.
    let json = export_one(SymbolKind::Module);

    assert!(
        json.contains("\"File\""),
        "a Module must be exported as File; got:\n{json}"
    );
    assert!(
        !json.contains("\"Function\""),
        "a Module was exported as executable code; got:\n{json}"
    );
}

#[test]
fn a_function_is_still_exported_as_a_function() {
    // Premise: the assertions above are not passing because the exporter stopped
    // emitting `Function` altogether.
    let json = export_one(SymbolKind::Function);
    assert!(
        json.contains("\"Function\""),
        "premise: a Function must still be exported as Function; got:\n{json}"
    );
}
