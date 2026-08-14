//! Symbol enrichment: FLIRT-based name resolution + multi-ABI demangling.
//!
//! [`FlirtDemanglerResolver`] implements [`crate::SymbolResolver`].  Construct
//! it once (scanning the binary bytes with the built-in FLIRT signature DB),
//! then hand it to [`crate::DecompilerPipeline::set_symbol_resolver`].  All
//! subsequent calls to `resolve(addr)` are O(1) hash-map lookups; the
//! demangling pass fires automatically via the trait's `demangle` hook.

use std::collections::HashMap;

use rustre_flirt_apply::{FlirtApplier, FlirtSigDb};

use crate::SymbolResolver;

// ─────────────────────────────────────────────────────────────────────────────
// FlirtDemanglerResolver
// ─────────────────────────────────────────────────────────────────────────────

/// A [`SymbolResolver`] that combines FLIRT pattern-matching with multi-ABI
/// symbol demangling (Rust, Itanium, MSVC, D, Swift, Go).
///
/// Construct via [`FlirtDemanglerResolver::from_binary`] or
/// [`FlirtDemanglerResolver::new`] (pre-built table).
pub struct FlirtDemanglerResolver {
    /// Address → raw (un-demangled) name, populated at construction time.
    names: HashMap<u64, String>,
}

impl FlirtDemanglerResolver {
    /// Build a resolver by scanning `binary_data` with the built-in FLIRT
    /// signature database, plus any extra `(address, name)` pairs already
    /// known (e.g. from an export table or PDB).
    ///
    /// `base_addr` is the preferred load address of the binary image (used
    /// so that FLIRT match offsets are translated to the same VA space as
    /// the addresses passed to `resolve`).
    pub fn from_binary(
        binary_data: &[u8],
        base_addr: u64,
        extra: impl IntoIterator<Item = (u64, String)>,
    ) -> Self {
        let mut db = FlirtSigDb::load_demo_sigs();
        db.merge(FlirtSigDb::load_extended_sigs());
        let applier = FlirtApplier::new(db);
        let matches = applier.scan(binary_data, base_addr);

        let mut names: HashMap<u64, String> = matches
            .into_iter()
            .map(|m| (m.address, m.function_name))
            .collect();

        for (addr, name) in extra {
            // Extra / export-table names win over FLIRT guesses.
            names.insert(addr, name);
        }

        Self { names }
    }

    /// Build a resolver from a pre-built address→name table (e.g. assembled
    /// from PDB, DWARF, or a prior FLIRT scan).  Demangling still fires on
    /// every `demangle()` call.
    pub fn new(pairs: impl IntoIterator<Item = (u64, String)>) -> Self {
        Self {
            names: pairs.into_iter().collect(),
        }
    }

    /// Number of names in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True when the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl SymbolResolver for FlirtDemanglerResolver {
    fn resolve(&self, address: u64) -> Option<String> {
        let raw = self.names.get(&address)?;
        // Return the demangled form immediately so callers don't have to call
        // `demangle()` separately.
        Some(self.demangle(raw))
    }

    fn demangle(&self, raw: &str) -> String {
        // Try the multi-ABI demangler (Rust legacy v0, Itanium, MSVC, D, Go…).
        if let Some(result) = rustre_demangle::demangle(raw) {
            return result.demangled;
        }
        raw.to_string()
    }
}
