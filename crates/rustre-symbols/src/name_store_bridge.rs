//! Bridge from loaded symbol providers to the decompiler's `name_store`.
//!
//! The decompiler (and the MCP server's `BinaryRegistry`) keep user-visible
//! names in simple maps: `(binary_id, address) -> name` or `address -> name`.
//! This module populates such stores from any [`SymbolProvider`] at binary
//! load time, WITHOUT this crate depending on the decompiler: the target is
//! abstracted behind [`NameStoreSink`], which is already implemented for the
//! standard map shapes.

use std::collections::HashMap;

use crate::{SymKind, SymbolProvider, UnifiedSymbolTable};

/// Anything that can receive `(address, name)` pairs.
pub trait NameStoreSink {
    /// Record `name` as the user-visible name for `addr`, overwriting any prior.
    fn set_name(&mut self, addr: u64, name: &str);
}

impl NameStoreSink for HashMap<u64, String> {
    fn set_name(&mut self, addr: u64, name: &str) {
        self.insert(addr, name.to_string());
    }
}

/// Adapter for the MCP-server-shaped store: `(binary_id, addr) -> name`.
pub struct KeyedNameStore<'a> {
    /// Identifier of the binary whose names are being written.
    pub binary_id: String,
    /// The backing `(binary_id, address) -> name` map being populated.
    pub store: &'a mut HashMap<(String, u64), String>,
}

impl NameStoreSink for KeyedNameStore<'_> {
    fn set_name(&mut self, addr: u64, name: &str) {
        self.store
            .insert((self.binary_id.clone(), addr), name.to_string());
    }
}

/// Options controlling which symbols flow into the name store.
#[derive(Debug, Clone)]
pub struct PopulateOptions {
    /// Include data/variable symbols (functions are always included).
    pub include_data: bool,
    /// Prefer the demangled name when available.
    pub prefer_demangled: bool,
    /// Skip compiler-generated placeholder names (`?`, empty, `sub_…`).
    pub skip_placeholders: bool,
}

impl Default for PopulateOptions {
    fn default() -> Self {
        Self {
            include_data: true,
            prefer_demangled: true,
            skip_placeholders: true,
        }
    }
}

fn is_placeholder(name: &str) -> bool {
    name.is_empty()
        || name == "?"
        || name.starts_with("sub_")
        || name.starts_with("loc_")
        || name.starts_with("unk_")
}

/// Populate `sink` with names from one provider. Returns the number of names
/// written.
pub fn populate_from_provider(
    provider: &dyn SymbolProvider,
    sink: &mut dyn NameStoreSink,
    opts: &PopulateOptions,
) -> usize {
    let mut written = 0;
    for sym in provider.all_symbols() {
        let is_fn = sym.kind == SymKind::Function;
        let is_data = matches!(sym.kind, SymKind::Data | SymKind::Common | SymKind::TLS);
        if !is_fn && !(opts.include_data && is_data) {
            continue;
        }
        let name = if opts.prefer_demangled {
            sym.display_name()
        } else {
            &sym.name
        };
        if opts.skip_placeholders && is_placeholder(name) {
            continue;
        }
        sink.set_name(sym.address, name);
        written += 1;
    }
    written
}

/// Populate `sink` from several providers in priority order: earlier
/// providers win — a later provider never overwrites an address already
/// named by an earlier one.
pub fn populate_from_providers(
    providers: &[&dyn SymbolProvider],
    sink: &mut dyn NameStoreSink,
    opts: &PopulateOptions,
) -> usize {
    // Collect into a map first so priority is enforced regardless of sink.
    let mut merged: HashMap<u64, String> = HashMap::new();
    for provider in providers {
        let mut tmp: HashMap<u64, String> = HashMap::new();
        populate_from_provider(*provider, &mut tmp, opts);
        for (addr, name) in tmp {
            merged.entry(addr).or_insert(name);
        }
    }
    let written = merged.len();
    for (addr, name) in merged {
        sink.set_name(addr, &name);
    }
    written
}

/// Build a fresh `address -> name` map from providers (convenience for
/// callers that own the decompiler-side store).
#[must_use]
pub fn build_name_map(
    providers: &[&dyn SymbolProvider],
    opts: &PopulateOptions,
) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    populate_from_providers(providers, &mut map, opts);
    map
}

/// Populate from a [`UnifiedSymbolTable`] (spec §7 taxonomy).
pub fn populate_from_unified_table(
    table: &UnifiedSymbolTable,
    sink: &mut dyn NameStoreSink,
    opts: &PopulateOptions,
) -> usize {
    let mut written = 0;
    for (addr, syms) in &table.symbols {
        // First non-placeholder symbol at this address wins.
        for sym in syms {
            let name = if opts.prefer_demangled {
                sym.display_name()
            } else {
                &sym.name
            };
            if opts.skip_placeholders && is_placeholder(name) {
                continue;
            }
            sink.set_name(*addr, name);
            written += 1;
            break;
        }
    }
    written
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf_provider::DwarfSymbolProvider;
    use crate::{Symbol, SymbolKind, SymbolSource, UnifiedSymbol};

    fn provider_with(symbols: &[(&str, u64, SymKind)]) -> DwarfSymbolProvider {
        let mut p = DwarfSymbolProvider::new("test");
        for (name, addr, kind) in symbols {
            p.add_symbol(Symbol::new((*name).to_string(), *addr, *kind));
        }
        p
    }

    #[test]
    fn populates_functions_and_data() {
        let p = provider_with(&[
            ("main", 0x1000, SymKind::Function),
            ("g_count", 0x2000, SymKind::Data),
        ]);
        let mut store: HashMap<u64, String> = HashMap::new();
        let n = populate_from_provider(&p, &mut store, &PopulateOptions::default());
        assert_eq!(n, 2);
        assert_eq!(store[&0x1000], "main");
        assert_eq!(store[&0x2000], "g_count");
    }

    #[test]
    fn excludes_data_when_disabled() {
        let p = provider_with(&[
            ("main", 0x1000, SymKind::Function),
            ("g", 0x2000, SymKind::Data),
        ]);
        let mut store: HashMap<u64, String> = HashMap::new();
        let opts = PopulateOptions {
            include_data: false,
            ..Default::default()
        };
        assert_eq!(populate_from_provider(&p, &mut store, &opts), 1);
        assert!(!store.contains_key(&0x2000));
    }

    #[test]
    fn skips_placeholder_names() {
        let p = provider_with(&[
            ("?", 0x1000, SymKind::Function),
            ("sub_401000", 0x2000, SymKind::Function),
            ("real_fn", 0x3000, SymKind::Function),
        ]);
        let mut store: HashMap<u64, String> = HashMap::new();
        assert_eq!(
            populate_from_provider(&p, &mut store, &PopulateOptions::default()),
            1
        );
        assert_eq!(store[&0x3000], "real_fn");
    }

    #[test]
    fn prefers_demangled_name() {
        let mut p = DwarfSymbolProvider::new("t");
        let mut s = Symbol::new("_Z3fooi".to_string(), 0x100, SymKind::Function);
        s.demangled_name = Some("foo(int)".to_string());
        p.add_symbol(s);
        let mut store: HashMap<u64, String> = HashMap::new();
        populate_from_provider(&p, &mut store, &PopulateOptions::default());
        assert_eq!(store[&0x100], "foo(int)");
    }

    #[test]
    fn earlier_provider_wins() {
        let p1 = provider_with(&[("from_pdb", 0x1000, SymKind::Function)]);
        let p2 = provider_with(&[
            ("from_dwarf", 0x1000, SymKind::Function),
            ("extra", 0x2000, SymKind::Function),
        ]);
        let mut store: HashMap<u64, String> = HashMap::new();
        let n = populate_from_providers(&[&p1, &p2], &mut store, &PopulateOptions::default());
        assert_eq!(n, 2);
        assert_eq!(store[&0x1000], "from_pdb");
        assert_eq!(store[&0x2000], "extra");
    }

    #[test]
    fn keyed_store_shape() {
        let p = provider_with(&[("main", 0x1000, SymKind::Function)]);
        let mut raw: HashMap<(String, u64), String> = HashMap::new();
        let mut sink = KeyedNameStore {
            binary_id: "bin-0001".into(),
            store: &mut raw,
        };
        populate_from_provider(&p, &mut sink, &PopulateOptions::default());
        assert_eq!(raw[&("bin-0001".to_string(), 0x1000)], "main");
    }

    #[test]
    fn build_name_map_convenience() {
        let p = provider_with(&[("f", 0x10, SymKind::Function)]);
        let map = build_name_map(&[&p], &PopulateOptions::default());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn unified_table_populates() {
        let mut t = UnifiedSymbolTable::new();
        t.add(UnifiedSymbol::new(
            "sub_1000".into(),
            0x1000,
            SymbolKind::Function,
            SymbolSource::Dwarf,
        ));
        t.add(UnifiedSymbol::new(
            "real_name".into(),
            0x1000,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        let mut store: HashMap<u64, String> = HashMap::new();
        let n = populate_from_unified_table(&t, &mut store, &PopulateOptions::default());
        assert_eq!(n, 1);
        assert_eq!(store[&0x1000], "real_name");
    }
}
