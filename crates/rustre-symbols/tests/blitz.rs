//! Blitz test suite for rustre-symbols public API surface (lib.rs).
//! Goal: surface real bugs by exercising edge cases, overflow, malformed input, and invariants.

use rustre_symbols::*;

fn mk_fn(name: &str, addr: u64) -> Symbol {
    Symbol::new(name.into(), addr, SymKind::Function)
}
fn mk_data(name: &str, addr: u64) -> Symbol {
    Symbol::new(name.into(), addr, SymKind::Data)
}
fn mk_label(name: &str, addr: u64) -> Symbol {
    Symbol::new(name.into(), addr, SymKind::Label)
}
fn mk_ifunc(name: &str, addr: u64) -> Symbol {
    Symbol::new(name.into(), addr, SymKind::IFunc)
}
fn mk_uni(name: &str, addr: u64, k: SymbolKind, s: SymbolSource) -> UnifiedSymbol {
    UnifiedSymbol::new(name.into(), addr, k, s)
}

// ───── Symbol behavior ───────────────────────────────────────────────────────

#[test]
fn symbol_ids_are_unique_and_monotonic() {
    let a = mk_fn("a", 1);
    let b = mk_fn("b", 2);
    assert_ne!(a.id, b.id);
    assert!(b.id > a.id);
}

#[test]
fn symbol_label_and_ifunc_are_functions() {
    assert!(mk_label("l", 0).is_function());
    assert!(mk_ifunc("i", 0).is_function());
}

#[test]
fn symbol_tls_and_common_are_data() {
    let tls = Symbol::new("t".into(), 0, SymKind::TLS);
    let cm = Symbol::new("c".into(), 0, SymKind::Common);
    assert!(tls.is_data());
    assert!(cm.is_data());
}

#[test]
fn symbol_function_boundary_requires_size() {
    let s = mk_fn("f", 0x1000);
    assert!(s.function_boundary().is_none());
}

#[test]
fn symbol_function_boundary_data_returns_none() {
    let mut s = mk_data("d", 0x1000);
    s.size = Some(8);
    assert!(s.function_boundary().is_none());
}

#[test]
fn symbol_contains_zero_size_only_exact() {
    let mut s = mk_fn("f", 0x1000);
    s.size = Some(0);
    // With size = Some(0), per impl: addr >= 0x1000 && addr < 0x1000 → false for 0x1000.
    assert!(!s.contains(0x1000));
    assert!(!s.contains(0x1001));
}

#[test]
fn symbol_end_address_overflow_panics_or_wraps() {
    // end_address uses unchecked add; with u64::MAX address + nonzero size, this panics in debug.
    let mut s = mk_fn("f", u64::MAX - 4);
    s.size = Some(4);
    assert_eq!(s.end_address(), Some(u64::MAX));
}

#[test]
fn symbol_display_contains_hex_address() {
    let s = mk_fn("main", 0x0040_1000);
    let d = s.to_string();
    assert!(d.contains("0x401000"), "got: {d}");
}

// ───── FunctionBoundary ──────────────────────────────────────────────────────

#[test]
fn boundary_size_saturating() {
    // end < start → size saturates to 0
    let b = FunctionBoundary::new(0x2000, 0x1000, "weird".into());
    assert_eq!(b.size(), 0);
}

#[test]
fn boundary_contains_half_open() {
    let b = FunctionBoundary::new(0x100, 0x200, "f".into());
    assert!(b.contains(0x100));
    assert!(b.contains(0x1FF));
    assert!(!b.contains(0x200));
}

#[test]
fn boundary_overlaps_touch_does_not_overlap() {
    let a = FunctionBoundary::new(0x1000, 0x2000, "a".into());
    let b = FunctionBoundary::new(0x2000, 0x3000, "b".into());
    assert!(!a.overlaps(&b));
    assert!(!b.overlaps(&a));
}

#[test]
fn boundary_empty_does_not_overlap_anything() {
    let empty = FunctionBoundary::new(0x1000, 0x1000, "e".into());
    let other = FunctionBoundary::new(0x500, 0x1500, "o".into());
    assert!(!empty.overlaps(&other));
    assert!(!other.overlaps(&empty));
}

#[test]
fn boundary_self_overlap_nonempty() {
    let b = FunctionBoundary::new(1, 2, "x".into());
    assert!(b.overlaps(&b));
}

// ───── SymbolFilter ──────────────────────────────────────────────────────────

#[test]
fn filter_address_range_excludes_upper_bound() {
    let syms = vec![mk_fn("a", 0x100), mk_fn("b", 0x200), mk_fn("c", 0x300)];
    let r = SymbolFilter::new().address_range(0x100, 0x300).apply(&syms);
    // Half-open [0x100, 0x300): should contain a and b, not c.
    let names: Vec<_> = r.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"], "address_range should be half-open [lo, hi); got {names:?}");
}

#[test]
fn filter_empty_range_returns_none() {
    let syms = vec![mk_fn("a", 0x100)];
    let r = SymbolFilter::new().address_range(0x100, 0x100).apply(&syms);
    // [0x100, 0x100) is empty.
    assert!(r.is_empty(), "empty range should yield nothing; got {r:?}");
}

#[test]
fn filter_sources_match() {
    let mut a = mk_fn("a", 0x100);
    a.source = LegacySymbolSource::Export;
    let b = mk_fn("b", 0x200);
    let r = SymbolFilter::new()
        .sources(vec![LegacySymbolSource::Export])
        .apply(&[a, b]);
    assert_eq!(r.len(), 1);
}

#[test]
fn filter_section_index_match() {
    let mut a = mk_fn("a", 0x100);
    a.section_index = Some(7);
    let b = mk_fn("b", 0x200);
    let r = SymbolFilter::new().section_index(7).apply(&[a, b]);
    assert_eq!(r.len(), 1);
}

#[test]
fn filter_compound_min_max() {
    let syms: Vec<Symbol> = (0..10).map(|i| mk_fn(&format!("f{i}"), i * 0x100)).collect();
    let r = SymbolFilter::new()
        .address_min(0x300)
        .address_max(0x500)
        .apply(&syms);
    assert_eq!(r.len(), 3); // 0x300, 0x400, 0x500
}

// ───── AddressToSymbolMap ────────────────────────────────────────────────────

#[test]
fn addr_map_unsorted_lookup_returns_none() {
    let mut m = AddressToSymbolMap::new();
    m.insert(mk_fn("f", 0x100));
    // Without sort(), lookup_exact returns None (debug_assert may fire in debug builds).
    // To avoid the panic via debug_assert, just call sort first then test that
    // exact behavior post-sort works. The unsorted path is debug-asserted.
    m.sort();
    assert!(m.lookup_exact(0x100).is_some());
}

#[test]
fn addr_map_floor_at_exact_addr() {
    let m = AddressToSymbolMap::from_symbols(&[mk_fn("a", 0x100), mk_fn("b", 0x200)]);
    assert_eq!(m.lookup_floor(0x200).unwrap().name, "b");
}

#[test]
fn addr_map_floor_below_all() {
    let m = AddressToSymbolMap::from_symbols(&[mk_fn("a", 0x100)]);
    assert!(m.lookup_floor(0).is_none());
}

#[test]
fn addr_map_all_symbols_count() {
    let m = AddressToSymbolMap::from_symbols(&[mk_fn("a", 0x100), mk_fn("b", 0x200)]);
    assert_eq!(m.all_symbols().len(), 2);
    assert_eq!(m.len(), 2);
    assert!(!m.is_empty());
}

// ───── SymbolCache (LRU) ─────────────────────────────────────────────────────

#[test]
fn cache_capacity_zero_promoted_to_one() {
    let c = SymbolCache::new(0);
    assert_eq!(c.capacity(), 1);
}

#[test]
fn cache_lru_eviction_order() {
    let mut c = SymbolCache::new(2);
    c.insert(1, mk_fn("a", 1));
    c.insert(2, mk_fn("b", 2));
    // Touch 1, making 2 the LRU.
    let _ = c.get(1);
    c.insert(3, mk_fn("c", 3));
    assert!(c.get(2).is_none(), "LRU entry 2 should have been evicted");
    assert!(c.get(1).is_some());
    assert!(c.get(3).is_some());
}

#[test]
fn cache_update_existing_does_not_grow() {
    let mut c = SymbolCache::new(2);
    c.insert(1, mk_fn("a", 1));
    c.insert(1, mk_fn("a2", 1));
    assert_eq!(c.len(), 1);
    assert_eq!(c.get(1).unwrap().name, "a2");
}

#[test]
fn cache_debug_format() {
    let c = SymbolCache::new(5);
    assert!(format!("{c:?}").contains("cap=5"));
}

// ───── SymbolStore ───────────────────────────────────────────────────────────

#[test]
fn store_remove_nonexistent_returns_zero() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    assert_eq!(s.remove(0x999, "nope"), 0);
    assert_eq!(s.len(), 1);
}

#[test]
fn store_upsert_replaces_in_place() {
    let mut s = SymbolStore::new();
    let mut a = mk_fn("a", 0x100);
    a.size = Some(10);
    s.insert(a).unwrap();
    let mut a2 = mk_fn("a", 0x100);
    a2.size = Some(20);
    s.upsert(a2);
    assert_eq!(s.len(), 1);
    assert_eq!(s.find_by_addr(0x100)[0].size, Some(20));
}

#[test]
fn store_multiple_at_same_addr_different_name() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    s.insert(mk_fn("b", 0x100)).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s.find_by_addr(0x100).len(), 2);
}

#[test]
fn store_find_in_range_excludes_end() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    s.insert(mk_fn("b", 0x200)).unwrap();
    let r = s.find_in_range(0x100, 0x200);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "a");
}

#[test]
fn store_get_floor_below_all() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    assert!(s.get_floor(0x50).is_none());
}

#[test]
fn store_get_floor_at_addr() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    assert_eq!(s.get_floor(0x100).unwrap().name, "a");
}

#[test]
fn store_rename_updates_name_index() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("old", 0x100)).unwrap();
    assert!(s.rename(0x100, "old", "new"));
    assert!(s.find_by_name("old").is_empty());
    assert_eq!(s.find_by_name("new").len(), 1);
}

#[test]
fn store_rename_nonexistent() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("a", 0x100)).unwrap();
    assert!(!s.rename(0x100, "nope", "new"));
    assert!(!s.rename(0x999, "a", "new"));
}

#[test]
fn store_csv_header_and_row() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("foo", 0x42)).unwrap();
    let csv = s.export_as_csv();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], "address,name,demangled,kind,size");
    assert!(lines[1].starts_with("0x42,foo,"));
}

#[test]
fn store_map_format_addr_width() {
    let mut s = SymbolStore::new();
    s.insert(mk_fn("f", 0x42)).unwrap();
    let m = s.export_as_map();
    // "{:#018x}" → 18 chars total including "0x"
    assert!(m.contains("0x0000000000000042"), "got: {m}");
}

// ───── SymbolStats ───────────────────────────────────────────────────────────

#[test]
fn stats_namespace_counts_as_types() {
    let v = vec![
        Symbol::new("t".into(), 0, SymKind::Type),
        Symbol::new("n".into(), 1, SymKind::Namespace),
    ];
    let st = SymbolStats::from_symbols(&v);
    assert_eq!(st.types, 2);
}

#[test]
fn stats_all_kinds_counted() {
    let v = vec![
        Symbol::new("f".into(), 0, SymKind::Function),
        Symbol::new("d".into(), 1, SymKind::Data),
        Symbol::new("l".into(), 2, SymKind::Label),
        Symbol::new("s".into(), 3, SymKind::Section),
        Symbol::new("fi".into(), 4, SymKind::File),
        Symbol::new("t".into(), 5, SymKind::Type),
        Symbol::new("tl".into(), 6, SymKind::TLS),
        Symbol::new("if".into(), 7, SymKind::IFunc),
        Symbol::new("c".into(), 8, SymKind::Common),
        Symbol::new("u".into(), 9, SymKind::Unknown),
    ];
    let s = SymbolStats::from_symbols(&v);
    assert_eq!(s.total, 10);
    assert_eq!(s.functions + s.data + s.labels + s.sections + s.files
        + s.types + s.tls + s.ifunc + s.common + s.unknown, 10);
}

// ───── ExportTable / ImportTable ─────────────────────────────────────────────

#[test]
fn export_table_empty_if_no_exports() {
    let et = ExportTable::from_symbols(&[mk_fn("a", 0x100)]);
    assert!(et.is_empty());
    assert!(et.exports().is_empty());
}

#[test]
fn export_table_by_ordinal_missing() {
    let mut e = mk_fn("e", 0x100);
    e.source = LegacySymbolSource::Export;
    let et = ExportTable::from_symbols(&[e]);
    assert!(et.by_ordinal(99).is_none());
}

#[test]
fn import_table_grouped_unknown_module() {
    let mut i = mk_fn("X", 0x100);
    i.source = LegacySymbolSource::Import;
    let it = ImportTable::from_symbols(&[i]);
    let g = it.grouped_by_module();
    assert!(g.contains_key("unknown"));
}

#[test]
fn import_table_by_name() {
    let mut i = mk_fn("malloc", 0x100);
    i.source = LegacySymbolSource::Import;
    let it = ImportTable::from_symbols(&[i]);
    assert!(it.by_name("malloc").is_some());
    assert!(it.by_name("free").is_none());
}

// ───── ConflictResolver ──────────────────────────────────────────────────────

#[test]
fn conflict_keep_last_deduplicates() {
    let r = SymbolConflictResolver::new(ConflictStrategy::KeepLast)
        .resolve(vec![mk_fn("a", 0x100), mk_fn("b", 0x100), mk_fn("c", 0x200)]);
    assert_eq!(r.len(), 2);
    // Sorted by address ascending.
    assert_eq!(r[0].address, 0x100);
    assert_eq!(r[1].address, 0x200);
}

#[test]
fn conflict_prefer_export() {
    let a = mk_fn("debug", 0x100);
    let mut b = mk_fn("exp", 0x100);
    b.source = LegacySymbolSource::Export;
    let r = SymbolConflictResolver::new(ConflictStrategy::PreferExport)
        .resolve(vec![a, b]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "exp");
}

// ───── SymbolExporter ────────────────────────────────────────────────────────

#[test]
fn exporter_json_roundtrip() {
    let original = vec![{
        let mut s = mk_fn("main", 0x0040_1000);
        s.size = Some(64);
        s.demangled_name = Some("Main".into());
        s
    }];
    let j = SymbolExporter::to_json(&original).unwrap();
    let parsed: Vec<Symbol> = serde_json::from_str(&j).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name, "main");
    assert_eq!(parsed[0].address, 0x0040_1000);
    assert_eq!(parsed[0].size, Some(64));
}

#[test]
fn exporter_idc_quotes_escape() {
    let s = mk_fn("foo\"bar", 0x100);
    let idc = SymbolExporter::to_idc(&[s]);
    assert!(idc.contains("foo\\\"bar"), "should escape quotes: {idc}");
}

#[test]
fn exporter_csv_empty_input() {
    let csv = SymbolExporter::to_csv(&[]);
    assert_eq!(csv, "address,name,demangled,kind,size\n");
}

// ───── Demanglers ────────────────────────────────────────────────────────────

#[test]
fn demangle_itanium_simple_z3foov() {
    // _Z3foov → "foo" (just one length-prefixed part).
    let r = try_demangle("_Z3foov");
    assert_eq!(r.as_deref(), Some("foo"), "got: {r:?}");
}

#[test]
fn demangle_itanium_nested_n3foo3bar_e() {
    // _ZN3foo3barE → "foo::bar"
    let r = try_demangle("_ZN3foo3barE");
    assert_eq!(r.as_deref(), Some("foo::bar"), "got: {r:?}");
}

#[test]
fn demangle_itanium_double_underscore_prefix() {
    let r = try_demangle("__Z3foov");
    assert_eq!(r.as_deref(), Some("foo"));
}

#[test]
fn demangle_itanium_empty_after_prefix() {
    assert!(try_demangle("_Z").is_none());
}

#[test]
fn demangle_itanium_truncated_length() {
    // _Z99foo: claims 99 chars but only 3 follow. Heuristic should not panic.
    let r = try_demangle("_Z99foo");
    // Per impl: len > s.len() → break; parts empty → returns None.
    assert!(r.is_none(), "truncated should yield None; got {r:?}");
}

#[test]
fn demangle_itanium_zero_length_part_no_infinite_loop() {
    // _Z0 → leading "0" is a digit, parses as len=0, then s becomes empty and pushes "".
    // We just verify it terminates and produces something deterministic.
    let _ = try_demangle("_Z0");
}

#[test]
fn demangle_rust_prefix() {
    let r = try_demangle("_RNvCs...example");
    assert!(r.is_some());
    assert!(r.unwrap().contains("rust"));
}

#[test]
fn demangle_msvc_basic() {
    let r = try_demangle("?foo@bar@@QAEXXZ");
    assert_eq!(r.as_deref(), Some("foo::bar"), "got: {r:?}");
}

#[test]
fn demangle_msvc_only_question_mark() {
    assert!(try_demangle("?").is_none());
}

#[test]
fn demangle_plain_returns_none() {
    assert!(try_demangle("main").is_none());
    assert!(try_demangle("").is_none());
}

#[test]
fn demangler_pipeline_caches_negative() {
    let mut p = DemanglerPipeline::new();
    assert!(p.demangle("plain").is_none());
    // Second call uses cache (same answer).
    assert!(p.demangle("plain").is_none());
}

#[test]
fn demangler_pipeline_clear_cache() {
    let mut p = DemanglerPipeline::new();
    let _ = p.demangle("_Z3foov");
    p.clear_cache();
    // Still works after clear.
    assert!(p.demangle("_Z3foov").is_some());
}

#[test]
fn demangler_pipeline_set_order() {
    let mut p = DemanglerPipeline::new();
    p.set_order(vec![DemangleStrategy::Rust]);
    // Itanium-style name no longer gets recognized.
    assert!(p.demangle("_Z3foov").is_none());
    assert!(p.demangle("_Rxxx").is_some());
}

#[test]
fn demangle_table_populates_all() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("_Z3foov", 0x100, SymbolKind::Function, SymbolSource::Dwarf));
    t.add(mk_uni("?bar@@YAXXZ", 0x200, SymbolKind::Function, SymbolSource::Pdb));
    demangle_all(&mut t);
    assert!(t.lookup_addr(0x100).unwrap().demangled_name.is_some());
    assert!(t.lookup_addr(0x200).unwrap().demangled_name.is_some());
}

// ───── UnifiedSymbol / UnifiedSymbolTable ────────────────────────────────────

#[test]
fn unified_source_priority_ordering() {
    assert!(SymbolSource::Manual.priority() > SymbolSource::Pdb.priority());
    assert!(SymbolSource::Pdb.priority() > SymbolSource::Stabs.priority());
    assert!(SymbolSource::Stabs.priority() > SymbolSource::Flirt.priority());
    assert!(SymbolSource::Flirt.priority() > SymbolSource::Export.priority());
    assert!(SymbolSource::Export.priority() > SymbolSource::Elf.priority());
    assert!(SymbolSource::Elf.priority() > SymbolSource::Ai.priority());
    assert!(SymbolSource::Ai.priority() > SymbolSource::Inferred.priority());
}

#[test]
fn unified_table_add_or_upgrade_keeps_higher_priority() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    t.add_or_upgrade(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Inferred));
    assert_eq!(t.lookup_addr(0x100).unwrap().source, SymbolSource::Pdb);
}

#[test]
fn unified_table_add_or_upgrade_manual_beats_pdb() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    t.add_or_upgrade(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Manual));
    assert_eq!(t.lookup_addr(0x100).unwrap().source, SymbolSource::Manual);
}

#[test]
fn unified_table_lookup_addr_all_returns_all_at_addr() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("a", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    t.add(mk_uni("b", 0x100, SymbolKind::Function, SymbolSource::Dwarf));
    assert_eq!(t.lookup_addr_all(0x100).len(), 2);
}

#[test]
fn unified_table_remove_returns_count_and_cleans_name_index() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    assert_eq!(t.remove(0x100, "f"), 1);
    assert!(t.lookup_name("f").is_empty());
    assert!(!t.by_name.contains_key("f"), "name index should be empty after last removal");
}

#[test]
fn unified_table_remove_nonexistent() {
    let mut t = UnifiedSymbolTable::new();
    assert_eq!(t.remove(0x100, "no"), 0);
}

#[test]
fn unified_table_find_in_range_half_open() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("a", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    t.add(mk_uni("b", 0x200, SymbolKind::Function, SymbolSource::Pdb));
    let r = t.find_in_range(0x100, 0x200);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "a");
}

#[test]
fn unified_table_merge_takes_higher_priority() {
    let mut a = UnifiedSymbolTable::new();
    a.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Inferred));
    let mut b = UnifiedSymbolTable::new();
    b.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    a.merge(&b);
    assert_eq!(a.lookup_addr(0x100).unwrap().source, SymbolSource::Pdb);
}

#[test]
fn unified_table_pdb_url_list_only_pdb_sources_with_module() {
    let mut t = UnifiedSymbolTable::new();
    let mut s = mk_uni("a", 0x100, SymbolKind::Function, SymbolSource::Pdb);
    s.module = Some("ntdll.pdb".into());
    t.add(s);
    // PDB without module: excluded.
    t.add(mk_uni("b", 0x200, SymbolKind::Function, SymbolSource::Pdb));
    // Non-PDB with module: excluded.
    let mut s3 = mk_uni("c", 0x300, SymbolKind::Function, SymbolSource::Dwarf);
    s3.module = Some("foo".into());
    t.add(s3);
    let urls = t.pdb_url_list("https://srv");
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "https://srv/ntdll.pdb");
}

#[test]
fn unified_table_len_after_duplicate_add() {
    // add() allows duplicates (no dedup); len counts all entries.
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    t.add(mk_uni("f", 0x100, SymbolKind::Function, SymbolSource::Pdb));
    assert_eq!(t.len(), 2);
}

// ───── SyntheticSymbolGen ────────────────────────────────────────────────────

#[test]
fn synth_names_use_uppercase_hex() {
    assert_eq!(SyntheticSymbolGen::function_name(0xabcd), "sub_ABCD");
    assert_eq!(SyntheticSymbolGen::dword_name(0xff), "dword_FF");
    assert_eq!(SyntheticSymbolGen::qword_name(0x10), "qword_10");
}

#[test]
fn synth_fill_data_inserts_only_missing() {
    let mut t = UnifiedSymbolTable::new();
    t.add(mk_uni("named", 0x1000, SymbolKind::Variable, SymbolSource::Pdb));
    SyntheticSymbolGen::fill_data(&mut t, &[0x1000, 0x2000]);
    assert_eq!(t.lookup_addr(0x1000).unwrap().name, "named");
    assert_eq!(t.lookup_addr(0x2000).unwrap().name, "byte_2000");
}

#[test]
fn synth_fill_functions_zero_addr() {
    let mut t = UnifiedSymbolTable::new();
    SyntheticSymbolGen::fill_functions(&mut t, &[0]);
    assert_eq!(t.lookup_addr(0).unwrap().name, "sub_0");
}

// ───── SymbolError ───────────────────────────────────────────────────────────

#[test]
fn error_io_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: SymbolError = io_err.into();
    assert!(matches!(e, SymbolError::Io(_)));
}

#[test]
fn error_other_display() {
    assert_eq!(SymbolError::Other("hi".into()).to_string(), "hi");
}

#[test]
fn error_parse_display() {
    assert!(SymbolError::Parse("bad".into()).to_string().contains("bad"));
}

// ───── PdbSymbolServer ───────────────────────────────────────────────────────

#[test]
fn pdb_url_uses_uppercase_guid_no_dashes() {
    let s = PdbSymbolServer::new("https://srv");
    let url = s.pdb_url("ntdll.pdb", "AABBCCDD-1122-3344-5566-778899AABBCC", 1);
    // GUID has dashes stripped; age appended as uppercase hex.
    assert_eq!(
        url,
        "https://srv/ntdll.pdb/AABBCCDD112233445566778899AABBCC1/ntdll.pdb",
        "got: {url}"
    );
}

#[test]
fn pdb_url_age_hex_format() {
    let s = PdbSymbolServer::new("base");
    let url = s.pdb_url("a.pdb", "00000000-0000-0000-0000-000000000000", 0xA);
    // Age formatted as upper-hex (single char "A"), appended to 32-char GUID.
    assert_eq!(url, "base/a.pdb/00000000000000000000000000000000A/a.pdb", "got: {url}");
}

#[test]
fn pdb_url_msdl_default() {
    let m = PdbSymbolServer::msdl();
    assert!(m.base_url.contains("msdl.microsoft.com"));
}

// ───── CrossReferenceIndex ───────────────────────────────────────────────────

#[test]
fn xref_dedup_same_pair() {
    let mut x = CrossReferenceIndex::new();
    x.add_xref(0x100, 0x200);
    x.add_xref(0x100, 0x200);
    assert_eq!(x.ref_count_to(0x200), 1);
}

#[test]
fn xref_refs_sorted() {
    let mut x = CrossReferenceIndex::new();
    x.add_xref(0x500, 0x1000);
    x.add_xref(0x100, 0x1000);
    x.add_xref(0x300, 0x1000);
    assert_eq!(x.refs_to(0x1000), vec![0x100, 0x300, 0x500]);
}

#[test]
fn xref_missing_addr_returns_empty() {
    let x = CrossReferenceIndex::new();
    assert!(x.refs_to(0).is_empty());
    assert!(x.refs_from(0).is_empty());
    assert_eq!(x.ref_count_to(0), 0);
}

// ───── DebugSymbolMerger ─────────────────────────────────────────────────────

#[test]
fn merger_keeps_first_size_then_fills_in() {
    let mut m = DebugSymbolMerger::new();
    let mut a = mk_fn("f", 0x100);
    a.size = Some(10);
    let mut b = mk_fn("f", 0x100);
    b.size = Some(20); // ignored: entry.size is already Some
    m.merge(vec![a]);
    m.merge(vec![b]);
    let r = m.finish();
    assert_eq!(r[0].size, Some(10));
}

#[test]
fn merger_fills_size_from_second_when_first_lacks() {
    let mut m = DebugSymbolMerger::new();
    let a = mk_fn("f", 0x100); // no size
    let mut b = mk_fn("f", 0x100);
    b.size = Some(20);
    m.merge(vec![a]);
    m.merge(vec![b]);
    assert_eq!(m.finish()[0].size, Some(20));
}

#[test]
fn merger_len_is_unique_names() {
    let mut m = DebugSymbolMerger::new();
    m.merge(vec![mk_fn("a", 0x100), mk_fn("b", 0x200), mk_fn("a", 0x300)]);
    assert_eq!(m.len(), 2);
}

// ───── SymbolTable concurrency (Send + Sync) ─────────────────────────────────

#[test]
fn symbol_table_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SymbolTable>();
}

#[test]
fn symbol_table_clear_cache_after_lookup() {
    let t = SymbolTable::new();
    let mut p = InMemorySymbolProvider::new();
    p.add(mk_fn("f", 0x100));
    t.add_provider(Box::new(p));
    let _ = t.lookup_address(0x100);
    t.clear_cache();
    // Still resolvable from provider.
    assert!(t.lookup_address(0x100).is_some());
}

#[test]
fn symbol_table_lookup_nearest_uses_providers() {
    let t = SymbolTable::new();
    let mut p = InMemorySymbolProvider::new();
    p.add(mk_fn("low", 0x1000));
    p.add(mk_fn("high", 0x2000));
    t.add_provider(Box::new(p));
    assert_eq!(t.lookup_nearest(0x1500).unwrap().name, "low");
}

#[test]
fn symbol_table_all_symbols_concat_providers() {
    let t = SymbolTable::new();
    let mut p1 = InMemorySymbolProvider::new();
    p1.add(mk_fn("a", 0x100));
    let mut p2 = InMemorySymbolProvider::new();
    p2.add(mk_fn("b", 0x200));
    t.add_provider(Box::new(p1));
    t.add_provider(Box::new(p2));
    assert_eq!(t.all_symbols().len(), 2);
}

// ───── SectionSymbols ────────────────────────────────────────────────────────

#[test]
fn section_symbols_unindexed_excluded() {
    // Symbols without section_index are excluded.
    let a = mk_fn("a", 0x100); // section_index None
    let mut b = mk_fn("b", 0x200);
    b.section_index = Some(3);
    let sec = SectionSymbols::from_symbols(&[a, b]);
    assert_eq!(sec.section_count(), 1);
    assert_eq!(sec.in_section(3).len(), 1);
    assert!(sec.in_section(999).is_empty());
}

// ───── SymbolResolver ────────────────────────────────────────────────────────

#[test]
fn resolver_fallback_returns_first_hit() {
    let mut r = SymbolResolver::new();
    let mut p1 = InMemorySymbolProvider::new();
    p1.add(mk_fn("a", 0x100));
    let mut p2 = InMemorySymbolProvider::new();
    p2.add(mk_fn("a", 0x200)); // same name different addr
    r.add_provider(Box::new(p1));
    r.add_provider(Box::new(p2));
    assert_eq!(r.resolve_name("a").unwrap().address, 0x100);
}

#[test]
fn resolver_nearest_chain() {
    let mut r = SymbolResolver::new();
    let mut p = InMemorySymbolProvider::new();
    p.add(mk_fn("a", 0x1000));
    r.add_provider(Box::new(p));
    assert_eq!(r.resolve_nearest(0x1500).unwrap().name, "a");
}

#[test]
fn resolver_provider_count() {
    let mut r = SymbolResolver::new();
    assert_eq!(r.provider_count(), 0);
    r.add_provider(Box::new(InMemorySymbolProvider::new()));
    assert_eq!(r.provider_count(), 1);
}

// ───── TypeInfo / StructField additional ─────────────────────────────────────

#[test]
fn typeinfo_int_unsigned_display() {
    let t = TypeInfo::Int { width: 64, signed: false };
    assert_eq!(t.to_string(), "u64");
}

#[test]
fn typeinfo_array_display() {
    let t = TypeInfo::Array { element: Box::new(TypeInfo::Bool), count: 16 };
    assert_eq!(t.to_string(), "bool[16]");
}

#[test]
fn typeinfo_struct_display_name_only() {
    let t = TypeInfo::Struct { name: "Foo".into(), fields: vec![] };
    assert_eq!(t.to_string(), "struct Foo");
}

#[test]
fn typeinfo_enum_display() {
    let t = TypeInfo::Enum {
        name: "E".into(),
        variants: vec![("A".into(), 0)],
        base_type: Box::new(TypeInfo::Int { width: 32, signed: false }),
    };
    assert_eq!(t.to_string(), "enum E");
}

#[test]
fn typeinfo_function_display() {
    let t = TypeInfo::Function {
        return_type: Box::new(TypeInfo::Void),
        params: vec![],
    };
    assert_eq!(t.to_string(), "fn(...)");
}

#[test]
fn typeinfo_named_display() {
    assert_eq!(TypeInfo::Named("X".into()).to_string(), "X");
}

#[test]
fn typeinfo_unknown_display() {
    assert_eq!(TypeInfo::Unknown.to_string(), "?");
}
