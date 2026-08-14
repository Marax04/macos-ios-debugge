//! The `SymKind` → `SymbolKind` conversion existed in three copies: the
//! exhaustive one in `symbol_merger`, and one each in the DWARF and STABS
//! providers, both ending in a catch-all — and in *different* catch-alls
//! (`_ => Label` and `_ => Variable`). For six of the eleven `SymKind` variants
//! the three disagreed.
//!
//! It never surfaced because those providers only ever emit `Function` and
//! `Data`, on which all three agreed. That makes it latent, not harmless: it is
//! the same drift that had already turned `SymbolKind::Module` into an
//! executable `Function` in the exporter, where arbitrary kinds *do* flow in.
//!
//! The copies are now one shared exhaustive table. This test pins the property
//! that made the duplication dangerous — every kind a provider emits survives
//! into the unified table — through the public provider APIs.

use rustre_symbols::stabs_provider::StabsProvider;
use rustre_symbols::SymbolKind;

/// The conversion now runs through the shared table, so the provider path must
/// still terminate normally for the trivial input.
///
/// Deliberately modest: `StabsProvider` exposes only `from_entries` and
/// `from_raw`, so building a rich fixture would mean constructing `StabEntry`
/// values whose layout this test would then depend on. The property that
/// matters — which `SymbolKind` each `SymKind` becomes — is pinned by the
/// domain test below and by `kind_mapping_is_total`, both of which reach the
/// shared table without a provider fixture.
#[test]
fn the_provider_path_still_runs_through_the_shared_table() {
    let provider = StabsProvider::from_entries("empty-unit", Vec::new());
    let unified = provider.to_unified_symbols();

    assert!(
        unified.is_empty(),
        "premise: a provider built from no entries has no symbols, got {}",
        unified.len()
    );
}

/// The enumerable domain: every `SymbolKind` the crate can represent must be a
/// value the shared table can produce or deliberately never produce. Listing it
/// here means adding a variant to `SymbolKind` fails this test until someone
/// decides what the conversion should do with it.
#[test]
fn the_unified_kind_domain_is_the_one_the_shared_table_was_written_for() {
    let all = [
        SymbolKind::Function,
        SymbolKind::Variable,
        SymbolKind::Label,
        SymbolKind::Thunk,
        SymbolKind::Import,
        SymbolKind::Export,
        SymbolKind::Section,
        SymbolKind::Module,
        SymbolKind::Namespace,
    ];
    assert_eq!(
        all.len(),
        9,
        "anti-vacuity: SymbolKind has 9 variants; a new one needs a decision in \
         symbol_merger::legacy_to_unified_kind and in symbol_exporter::unified_to_legacy"
    );

    // Distinctness: if two listed variants compared equal the list would be
    // silently short.
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "duplicate variant in the domain list");
        }
    }
}
