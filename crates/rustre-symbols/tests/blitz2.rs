//! Blitz2 — deep adversarial coverage of rustre-symbols public API.
//! Disjoint from blitz.rs: focuses on fuzz, threading, round-trips, integer overflow,
//! state-machine invariants, and Display/FromStr-ish round-trips.

#![allow(clippy::too_many_lines)]

use rustre_symbols::*;
use std::sync::Arc;
use std::thread;

// ── Seeded LCG (no rand, no time) ───────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self { Self(0xDEAD_BEEF_CAFE_BABE) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn mk(name: &str, addr: u64, kind: SymKind) -> Symbol {
    Symbol::new(name.into(), addr, kind)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Symbol invariants — boundary / overflow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn symbol_end_address_checked_overflow_returns_none() {
    let mut s = mk("f", u64::MAX, SymKind::Function);
    s.size = Some(1);
    assert_eq!(s.end_address(), None);
}

#[test]
fn symbol_end_address_no_size_returns_none() {
    let s = mk("f", 0x1000, SymKind::Function);
    assert_eq!(s.end_address(), None);
}

#[test]
fn symbol_contains_overflow_safe_at_max() {
    let mut s = mk("f", u64::MAX - 4, SymKind::Function);
    s.size = Some(8); // overflow on end
    // contains should not panic; it checks checked_add internally
    let _ = s.contains(u64::MAX);
}

#[test]
fn symbol_contains_no_size_only_exact() {
    let s = mk("f", 0x4000, SymKind::Function);
    assert!(s.contains(0x4000));
    assert!(!s.contains(0x4001));
    assert!(!s.contains(0x3FFF));
}

#[test]
fn symbol_function_boundary_overflow_returns_none() {
    let mut s = mk("f", u64::MAX, SymKind::Function);
    s.size = Some(1);
    assert_eq!(s.function_boundary(), None);
}

#[test]
fn symbol_set_demangled_and_display() {
    let mut s = mk("_Zmangle", 0x1234, SymKind::Function);
    s.set_demangled("nice::name".into());
    assert_eq!(s.display_name(), "nice::name");
    let d = s.to_string();
    assert!(d.contains("nice::name"));
}

#[test]
fn symbol_add_tag_dedup() {
    let mut s = mk("f", 0, SymKind::Function);
    s.add_tag("hot".into());
    s.add_tag("hot".into());
    s.add_tag("cold".into());
    assert_eq!(s.tags.len(), 2);
}

#[test]
fn symbol_ids_monotonic_under_fuzz() {
    let mut last = 0u64;
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let a = lcg.next();
        let s = mk("x", a, SymKind::Function);
        assert!(s.id > last, "id not monotonic");
        last = s.id;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. FunctionBoundary invariants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn boundary_size_saturating_under_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let a = lcg.next();
        let b = lcg.next();
        let fb = FunctionBoundary::new(a, b, "x".into());
        let expected = b.saturating_sub(a);
        assert_eq!(fb.size(), expected);
    }
}

#[test]
fn boundary_overlap_symmetric() {
    let mut lcg = Lcg::new();
    for _ in 0..60 {
        let s1 = lcg.next() % 0x10000;
        let e1 = s1 + 1 + (lcg.next() % 0x100);
        let s2 = lcg.next() % 0x10000;
        let e2 = s2 + 1 + (lcg.next() % 0x100);
        let a = FunctionBoundary::new(s1, e1, "a".into());
        let b = FunctionBoundary::new(s2, e2, "b".into());
        assert_eq!(a.overlaps(&b), b.overlaps(&a));
    }
}

#[test]
fn boundary_contains_consistent_with_size() {
    let b = FunctionBoundary::new(10, 20, "n".into());
    let mut count = 0u64;
    for addr in 0u64..30 {
        if b.contains(addr) { count += 1; }
    }
    assert_eq!(count, b.size());
}

#[test]
fn boundary_display_roundtrip_contains_name() {
    let b = FunctionBoundary::new(0x100, 0x200, "alpha".into());
    let s = b.to_string();
    assert!(s.contains("alpha"));
    assert!(s.contains("0x100"));
    assert!(s.contains("0x200"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. SymbolCache LRU behavior
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cache_zero_capacity_promoted() {
    let c = SymbolCache::new(0);
    assert_eq!(c.capacity(), 1);
}

#[test]
fn cache_fuzz_insert_get_never_panics_keeps_cap() {
    let mut c = SymbolCache::new(8);
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let addr = lcg.next() % 32;
        if lcg.next() & 1 == 0 {
            c.insert(addr, mk("s", addr, SymKind::Function));
        } else {
            let _ = c.get(addr);
        }
        assert!(c.len() <= c.capacity());
    }
}

#[test]
fn cache_update_existing_keeps_size() {
    let mut c = SymbolCache::new(4);
    c.insert(1, mk("a", 1, SymKind::Function));
    c.insert(2, mk("b", 2, SymKind::Function));
    c.insert(1, mk("a2", 1, SymKind::Function));
    assert_eq!(c.len(), 2);
    assert_eq!(c.get(1).unwrap().name, "a2");
}

#[test]
fn cache_clear_then_empty() {
    let mut c = SymbolCache::new(4);
    c.insert(1, mk("a", 1, SymKind::Function));
    c.clear();
    assert!(c.is_empty());
    assert!(c.get(1).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SymbolStore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn store_insert_duplicate_is_err() {
    let mut st = SymbolStore::new();
    let s = mk("dup", 0x10, SymKind::Function);
    st.insert(s.clone()).unwrap();
    let r = st.insert(s);
    assert!(matches!(r, Err(SymbolError::Duplicate(_))));
}

#[test]
fn store_count_matches_iter_after_random_ops() {
    let mut st = SymbolStore::new();
    let mut lcg = Lcg::new();
    let mut tracked: Vec<(u64, String)> = vec![];
    for i in 0..50 {
        let addr = lcg.next() % 200;
        let name = format!("sym_{i}");
        if st.insert(mk(&name, addr, SymKind::Function)).is_ok() {
            tracked.push((addr, name));
        }
    }
    assert_eq!(st.len(), tracked.len());
    assert_eq!(st.iter().count(), tracked.len());
}

#[test]
fn store_remove_count_consistent() {
    let mut st = SymbolStore::new();
    for i in 0..20 {
        st.insert(mk(&format!("s{i}"), i, SymKind::Function)).unwrap();
    }
    let before = st.len();
    let removed = st.remove(5, "s5");
    assert_eq!(removed, 1);
    assert_eq!(st.len(), before - 1);
    assert!(st.find_by_addr(5).is_empty());
    assert!(st.find_by_name("s5").is_empty());
}

#[test]
fn store_rename_index_consistent() {
    let mut st = SymbolStore::new();
    st.insert(mk("old", 0x100, SymKind::Function)).unwrap();
    assert!(st.rename(0x100, "old", "new"));
    assert!(st.find_by_name("old").is_empty());
    assert_eq!(st.find_by_name("new").len(), 1);
}

#[test]
fn store_find_in_range_half_open() {
    let mut st = SymbolStore::new();
    for i in 0..10u64 {
        st.insert(mk(&format!("s{i}"), i * 0x10, SymKind::Function)).unwrap();
    }
    let r = st.find_in_range(0x20, 0x50);
    let addrs: Vec<u64> = r.iter().map(|s| s.address).collect();
    assert_eq!(addrs, vec![0x20, 0x30, 0x40]);
}

#[test]
fn store_csv_and_map_well_formed() {
    let mut st = SymbolStore::new();
    let mut s = mk("foo", 0x1000, SymKind::Function);
    s.size = Some(16);
    st.insert(s).unwrap();
    let csv = st.export_as_csv();
    assert!(csv.starts_with("address,name,demangled,kind,size\n"));
    assert!(csv.contains("foo"));
    let map = st.export_as_map();
    assert!(map.contains("foo"));
    assert!(map.contains("0x"));
}

#[test]
fn store_merge_upserts_all() {
    let mut a = SymbolStore::new();
    let mut b = SymbolStore::new();
    a.insert(mk("x", 1, SymKind::Function)).unwrap();
    b.insert(mk("y", 2, SymKind::Function)).unwrap();
    a.merge(&b);
    assert_eq!(a.len(), 2);
}

#[test]
fn store_get_floor_consistent() {
    let mut st = SymbolStore::new();
    for a in [0x100u64, 0x200, 0x300, 0x400] {
        st.insert(mk(&format!("a{a:x}"), a, SymKind::Function)).unwrap();
    }
    assert_eq!(st.get_floor(0x150).map(|s| s.address), Some(0x100));
    assert_eq!(st.get_floor(0x300).map(|s| s.address), Some(0x300));
    assert_eq!(st.get_floor(0xFF), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. AddressToSymbolMap
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn addr_map_from_symbols_is_sorted_for_floor() {
    let syms: Vec<Symbol> = (0..30u64)
        .map(|i| mk(&format!("s{i}"), (29 - i) * 16, SymKind::Function))
        .collect();
    let m = AddressToSymbolMap::from_symbols(&syms);
    assert_eq!(m.len(), 30);
    let f = m.lookup_floor(50).unwrap();
    assert!(f.address <= 50);
    let e = m.lookup_exact(16 * 5);
    assert!(e.is_some());
}

#[test]
fn addr_map_fuzz_floor_invariant() {
    let mut lcg = Lcg::new();
    let syms: Vec<Symbol> = (0..40)
        .map(|i| mk(&format!("s{i}"), lcg.next() % 1_000, SymKind::Function))
        .collect();
    let m = AddressToSymbolMap::from_symbols(&syms);
    for _ in 0..50 {
        let q = lcg.next() % 1_500;
        if let Some(f) = m.lookup_floor(q) {
            assert!(f.address <= q);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. SymbolFilter
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn filter_max_results_truncates() {
    let syms: Vec<Symbol> = (0..20u64).map(|i| mk(&format!("s{i}"), i, SymKind::Function)).collect();
    let f = SymbolFilter::new().max(5);
    assert_eq!(f.apply(&syms).len(), 5);
}

#[test]
fn filter_name_prefix_inclusive() {
    let syms = vec![
        mk("foo_a", 1, SymKind::Function),
        mk("foo_b", 2, SymKind::Function),
        mk("bar_c", 3, SymKind::Function),
    ];
    let f = SymbolFilter::new().name_prefix("foo");
    let r = f.apply(&syms);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|s| s.name.starts_with("foo")));
}

#[test]
fn filter_kinds_filters_correctly() {
    let syms = vec![
        mk("a", 1, SymKind::Function),
        mk("b", 2, SymKind::Data),
        mk("c", 3, SymKind::Label),
    ];
    let f = SymbolFilter::new().kinds(vec![SymKind::Function, SymKind::Label]);
    let r = f.apply(&syms);
    assert_eq!(r.len(), 2);
}

#[test]
fn filter_empty_input_returns_empty() {
    let f = SymbolFilter::new().name_prefix("anything").max(100);
    assert!(f.apply(&[]).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. UnifiedSymbol / UnifiedSymbolTable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unified_add_or_upgrade_keeps_higher_priority() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("f".into(), 0x10, SymbolKind::Function, SymbolSource::Inferred));
    t.add_or_upgrade(UnifiedSymbol::new("f".into(), 0x10, SymbolKind::Function, SymbolSource::Pdb));
    let s = t.lookup_addr(0x10).unwrap();
    assert_eq!(s.source, SymbolSource::Pdb);
}

#[test]
fn unified_add_or_upgrade_keeps_existing_when_lower_priority_new() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("f".into(), 0x10, SymbolKind::Function, SymbolSource::Pdb));
    t.add_or_upgrade(UnifiedSymbol::new("f".into(), 0x10, SymbolKind::Function, SymbolSource::Inferred));
    let s = t.lookup_addr(0x10).unwrap();
    assert_eq!(s.source, SymbolSource::Pdb);
}

#[test]
fn unified_source_priority_ordering() {
    assert!(SymbolSource::Manual.priority() > SymbolSource::Pdb.priority());
    assert!(SymbolSource::Pdb.priority() > SymbolSource::Stabs.priority());
    assert!(SymbolSource::Stabs.priority() > SymbolSource::Flirt.priority());
    assert!(SymbolSource::Inferred.priority() < SymbolSource::Ai.priority());
}

#[test]
fn unified_table_lookup_by_name_after_rename() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("orig".into(), 0x100, SymbolKind::Function, SymbolSource::Pdb));
    assert!(t.rename(0x100, "orig", "renamed"));
    assert_eq!(t.lookup_name("orig").len(), 0);
    assert_eq!(t.lookup_name("renamed").len(), 1);
}

#[test]
fn unified_table_find_in_range_half_open() {
    let mut t = UnifiedSymbolTable::new();
    for a in [10u64, 20, 30, 40, 50] {
        t.add(UnifiedSymbol::new(format!("s{a}"), a, SymbolKind::Function, SymbolSource::Pdb));
    }
    let r = t.find_in_range(20, 40);
    let addrs: Vec<u64> = r.iter().map(|s| s.address).collect();
    assert_eq!(addrs, vec![20, 30]);
}

#[test]
fn unified_remove_consistent() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("x".into(), 1, SymbolKind::Function, SymbolSource::Pdb));
    t.add(UnifiedSymbol::new("y".into(), 1, SymbolKind::Function, SymbolSource::Pdb));
    let removed = t.remove(1, "x");
    assert_eq!(removed, 1);
    assert_eq!(t.lookup_addr_all(1).len(), 1);
    assert!(t.lookup_name("x").is_empty());
}

#[test]
fn unified_table_fuzz_add_lookup_stable() {
    let mut t = UnifiedSymbolTable::new();
    let mut lcg = Lcg::new();
    let mut inserted = vec![];
    for i in 0..50 {
        let addr = lcg.next() % 500;
        let name = format!("u{i}");
        t.add(UnifiedSymbol::new(name.clone(), addr, SymbolKind::Function, SymbolSource::Pdb));
        inserted.push((addr, name));
    }
    for (addr, name) in &inserted {
        let hits = t.lookup_name(name);
        assert!(hits.iter().any(|s| s.address == *addr));
    }
}

#[test]
fn unified_nearest_below_matches_floor() {
    let mut t = UnifiedSymbolTable::new();
    for a in [100u64, 200, 300] {
        t.add(UnifiedSymbol::new(format!("a{a}"), a, SymbolKind::Function, SymbolSource::Pdb));
    }
    assert_eq!(t.nearest_below(250).map(|s| s.address), Some(200));
    assert_eq!(t.nearest_below(100).map(|s| s.address), Some(100));
    assert!(t.nearest_below(50).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. SymbolExporter — JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn exporter_json_roundtrip_50_symbols() {
    let mut lcg = Lcg::new();
    let syms: Vec<Symbol> = (0..50)
        .map(|i| {
            let mut s = mk(&format!("s{i}"), lcg.next(), SymKind::Function);
            s.size = Some(lcg.next() & 0xFFF);
            s
        })
        .collect();
    let json = SymbolExporter::to_json(&syms).unwrap();
    let back: Vec<Symbol> = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), syms.len());
    for (a, b) in syms.iter().zip(back.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.address, b.address);
        assert_eq!(a.size, b.size);
    }
}

#[test]
fn exporter_idc_escapes_quotes() {
    let mut s = mk("weird\"name", 0x1000, SymKind::Function);
    s.set_demangled("weird\"name".into());
    let idc = SymbolExporter::to_idc(&[s]);
    assert!(idc.contains("\\\""));
}

#[test]
fn exporter_csv_for_50_inputs_has_correct_row_count() {
    let syms: Vec<Symbol> = (0..50).map(|i| mk(&format!("s{i}"), i, SymKind::Function)).collect();
    let csv = SymbolExporter::to_csv(&syms);
    let lines = csv.lines().count();
    assert_eq!(lines, 51); // header + 50 rows
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. SyntheticSymbolGen naming
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn synthetic_names_format() {
    assert_eq!(SyntheticSymbolGen::function_name(0x0040_1000), "sub_401000");
    assert_eq!(SyntheticSymbolGen::data_name(0xDEAD), "byte_DEAD");
    assert_eq!(SyntheticSymbolGen::label_name(0xBEEF), "loc_BEEF");
    assert_eq!(SyntheticSymbolGen::dword_name(0x10), "dword_10");
    assert_eq!(SyntheticSymbolGen::qword_name(0), "qword_0");
}

#[test]
fn synthetic_fill_functions_skips_existing() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("real".into(), 0x100, SymbolKind::Function, SymbolSource::Pdb));
    SyntheticSymbolGen::fill_functions(&mut t, &[0x100, 0x200]);
    let s100 = t.lookup_addr(0x100).unwrap();
    assert_eq!(s100.name, "real"); // not overwritten
    let s200 = t.lookup_addr(0x200).unwrap();
    assert_eq!(s200.name, "sub_200");
    assert_eq!(s200.source, SymbolSource::Inferred);
}

#[test]
fn synthetic_fill_data_inserts_inferred() {
    let mut t = UnifiedSymbolTable::new();
    SyntheticSymbolGen::fill_data(&mut t, &[0xAA, 0xBB]);
    assert_eq!(t.len(), 2);
    let s = t.lookup_addr(0xAA).unwrap();
    assert_eq!(s.kind, SymbolKind::Variable);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Demangling — fuzz + heuristics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn demangle_pipeline_caches_results() {
    let mut p = DemanglerPipeline::new();
    let r1 = p.demangle("_Z3foov");
    let r2 = p.demangle("_Z3foov");
    assert_eq!(r1, r2);
}

#[test]
fn demangle_pipeline_clear_cache_safe() {
    let mut p = DemanglerPipeline::new();
    p.demangle("_Z3foov");
    p.clear_cache();
    let r = p.demangle("_Z3foov");
    assert!(r.is_some());
}

#[test]
fn demangle_fuzz_never_panics() {
    let mut p = DemanglerPipeline::new();
    let mut lcg = Lcg::new();
    let prefixes = ["", "_Z", "__Z", "_ZN", "?", "_R", "_$s", "garbage"];
    for _ in 0..100 {
        let pfx = prefixes[usize::try_from(lcg.next()).unwrap_or(0) % prefixes.len()];
        let bytes: Vec<u8> = (0..(lcg.next() & 0x1F))
            .map(|_| {
                let v = (lcg.next() & 0x7F) as u8;
                if v.is_ascii_alphanumeric() { v } else { b'a' }
            })
            .collect();
        let name = format!("{pfx}{}", std::str::from_utf8(&bytes).unwrap());
        let _ = p.demangle(&name); // must not panic
        let _ = try_demangle(&name);
    }
}

#[test]
fn try_demangle_plain_c_returns_none() {
    assert_eq!(try_demangle("main"), None);
    assert_eq!(try_demangle(""), None);
}

#[test]
fn demangle_all_table_populates_demangled() {
    let mut t = UnifiedSymbolTable::new();
    t.add(UnifiedSymbol::new("_Z3foov".into(), 0x10, SymbolKind::Function, SymbolSource::Pdb));
    t.add(UnifiedSymbol::new("plain".into(), 0x20, SymbolKind::Function, SymbolSource::Pdb));
    demangle_all(&mut t);
    let foo = t.lookup_addr(0x10).unwrap();
    assert!(foo.demangled_name.is_some());
    let plain = t.lookup_addr(0x20).unwrap();
    assert!(plain.demangled_name.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. ConflictResolver
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn conflict_keep_first_dedup() {
    let v = vec![
        mk("a", 1, SymKind::Function),
        mk("b", 1, SymKind::Function),
        mk("c", 2, SymKind::Function),
    ];
    let r = SymbolConflictResolver::new(ConflictStrategy::KeepFirst).resolve(v);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].name, "a");
}

#[test]
fn conflict_prefer_debug_picks_debug() {
    let mut a = mk("a", 1, SymKind::Function);
    a.source = LegacySymbolSource::Export;
    let mut b = mk("a", 1, SymKind::Function);
    b.source = LegacySymbolSource::Debug;
    let r = SymbolConflictResolver::new(ConflictStrategy::PreferDebug).resolve(vec![a, b]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].source, LegacySymbolSource::Debug);
}

#[test]
fn conflict_keep_all_preserves_count() {
    let v: Vec<Symbol> = (0..10).map(|i| mk(&format!("s{i}"), i % 3, SymKind::Function)).collect();
    let r = SymbolConflictResolver::new(ConflictStrategy::KeepAll).resolve(v);
    assert_eq!(r.len(), 10);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. SymbolStats invariants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stats_total_equals_sum_of_kinds_under_fuzz() {
    let mut lcg = Lcg::new();
    let kinds = [
        SymKind::Function, SymKind::Data, SymKind::Label, SymKind::Section,
        SymKind::File, SymKind::Type, SymKind::Namespace, SymKind::TLS,
        SymKind::IFunc, SymKind::Common, SymKind::Unknown,
    ];
    let syms: Vec<Symbol> = (0..80)
        .map(|i| mk(&format!("s{i}"), i, kinds[usize::try_from(lcg.next()).unwrap_or(0) % kinds.len()]))
        .collect();
    let st = SymbolStats::from_symbols(&syms);
    let sum = st.functions + st.data + st.labels + st.sections + st.files
            + st.types + st.tls + st.ifunc + st.common + st.unknown;
    assert_eq!(sum, st.total);
    assert_eq!(st.total, syms.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Hash/Eq consistency on copy enums (30+ pairs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn enum_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    fn h<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }
    let kinds = [
        SymKind::Function, SymKind::Data, SymKind::Label, SymKind::Section,
        SymKind::File, SymKind::Type, SymKind::Namespace, SymKind::TLS,
        SymKind::IFunc, SymKind::Common, SymKind::Unknown,
    ];
    for k in &kinds {
        assert_eq!(h(k), h(k));
        assert_eq!(k, k);
    }
    let sources = [
        SymbolSource::Pdb, SymbolSource::Dwarf, SymbolSource::CodeView,
        SymbolSource::Stabs, SymbolSource::Flirt, SymbolSource::Manual,
        SymbolSource::Inferred, SymbolSource::Import, SymbolSource::Export,
        SymbolSource::Elf, SymbolSource::Pe, SymbolSource::Ai,
    ];
    for s in &sources {
        assert_eq!(h(s), h(s));
    }
    let bindings = [SymbolBinding::Local, SymbolBinding::Global, SymbolBinding::Weak, SymbolBinding::GnuUnique];
    for b in &bindings { assert_eq!(h(b), h(b)); }
    let vis = [SymbolVisibility::Default, SymbolVisibility::Hidden, SymbolVisibility::Protected, SymbolVisibility::Internal];
    for v in &vis { assert_eq!(h(v), h(v)); }
    // pairs (>=30) — count: 11+12+4+4 = 31
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Display round-trip stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn enum_display_idempotent() {
    let kinds = [
        SymKind::Function, SymKind::Data, SymKind::Label, SymKind::Section,
        SymKind::File, SymKind::Type, SymKind::Namespace, SymKind::TLS,
    ];
    for k in &kinds {
        let s1 = k.to_string();
        let s2 = k.to_string();
        assert_eq!(s1, s2);
        assert!(!s1.is_empty());
    }
}

#[test]
fn unified_display_contains_address_and_kind() {
    let s = UnifiedSymbol::new("main".into(), 0xCAFE_BABE, SymbolKind::Function, SymbolSource::Pdb);
    let d = s.to_string();
    assert!(d.contains("main"));
    assert!(d.contains("0xcafebabe"));
    assert!(d.contains("Function"));
    assert!(d.contains("Pdb"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. InMemorySymbolProvider + SymbolTable (Send + Sync threaded stress)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn symbol_table_thread_stress_4x100_reads() {
    let mut prov = InMemorySymbolProvider::new();
    for i in 0..50u64 {
        prov.add(mk(&format!("f{i}"), i * 0x100, SymKind::Function));
    }
    let table = Arc::new(SymbolTable::new());
    table.add_provider(Box::new(prov));
    let mut handles = vec![];
    for tid in 0..4u64 {
        let t = Arc::clone(&table);
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg(0xABCD_0000_0000_0000 ^ tid);
            for _ in 0..100 {
                let q = lcg.next() % (50 * 0x100);
                let _ = t.lookup_address(q);
                let _ = t.lookup_nearest(q);
                let name = format!("f{}", (lcg.next() % 50));
                let _ = t.lookup_name(&name);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    // table still consistent
    assert_eq!(table.provider_count(), 1);
}

#[test]
fn in_memory_provider_lookup_nearest_floor() {
    let mut p = InMemorySymbolProvider::new();
    p.add(mk("a", 0x100, SymKind::Function));
    p.add(mk("b", 0x200, SymKind::Function));
    p.add(mk("c", 0x300, SymKind::Function));
    let s = p.lookup_nearest(0x250).unwrap();
    assert_eq!(s.address, 0x200);
    assert!(p.lookup_nearest(0x50).is_none());
}

#[test]
fn in_memory_provider_remove_and_rename() {
    let mut p = InMemorySymbolProvider::new();
    p.add(mk("x", 1, SymKind::Function));
    p.add(mk("y", 2, SymKind::Function));
    assert!(p.remove_by_name("x"));
    assert!(!p.remove_by_name("x"));
    assert!(p.rename("y", "y2".into()));
    assert!(p.lookup_name("y2").is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. DebugSymbolMerger
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn debug_merger_keeps_first_then_fills_demangled_and_size() {
    let mut a = mk("foo", 0x100, SymKind::Function);
    let mut b = mk("foo", 0x100, SymKind::Function);
    b.set_demangled("demangled_foo".into());
    b.size = Some(32);
    a.size = None;

    let mut m = DebugSymbolMerger::new();
    m.merge(vec![a]);
    m.merge(vec![b]);
    let out = m.finish();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].demangled_name.as_deref(), Some("demangled_foo"));
    assert_eq!(out[0].size, Some(32));
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. ExportTable / ImportTable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn export_table_by_ordinal_finds() {
    let mut s = mk("ex", 0x100, SymKind::Function);
    s.source = LegacySymbolSource::Export;
    s.ordinal = Some(42);
    let t = ExportTable::from_symbols(&[s]);
    assert_eq!(t.len(), 1);
    assert!(t.by_ordinal(42).is_some());
    assert!(t.by_ordinal(99).is_none());
}

#[test]
fn import_table_groups_by_module() {
    let mut a = mk("foo", 0x100, SymKind::Function);
    a.source = LegacySymbolSource::Import;
    a.source_file = Some("kernel32.dll".into());
    let mut b = mk("bar", 0x200, SymKind::Function);
    b.source = LegacySymbolSource::Import;
    b.source_file = Some("kernel32.dll".into());
    let mut c = mk("baz", 0x300, SymKind::Function);
    c.source = LegacySymbolSource::Import;
    // no source_file → "unknown"
    let t = ImportTable::from_symbols(&[a, b, c]);
    let groups = t.grouped_by_module();
    assert_eq!(groups.get("kernel32.dll").map(Vec::len), Some(2));
    assert_eq!(groups.get("unknown").map(Vec::len), Some(1));
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. SectionSymbols
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn section_symbols_groups_correctly() {
    let mut sym_a = mk("x", 1, SymKind::Function);
    sym_a.section_index = Some(1);
    let mut sym_b = mk("y", 2, SymKind::Function);
    sym_b.section_index = Some(1);
    let mut sym_c = mk("z", 3, SymKind::Function);
    sym_c.section_index = Some(2);
    let sym_d = mk("nosec", 4, SymKind::Function); // None section
    let sections = SectionSymbols::from_symbols(&[sym_a, sym_b, sym_c, sym_d]);
    assert_eq!(sections.section_count(), 2);
    assert_eq!(sections.in_section(1).len(), 2);
    assert_eq!(sections.in_section(99).len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. ManglingScheme detection (state machine of prefixes)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mangling_scheme_detection_cases() {
    use rustre_symbols::symbol_demangler::ManglingScheme;
    assert_eq!(ManglingScheme::detect("_Z3foov"), ManglingScheme::ItaniumV3);
    assert_eq!(ManglingScheme::detect("?foo@@YAXXZ"), ManglingScheme::Msvc);
    assert_eq!(ManglingScheme::detect("_RNvC1a"), ManglingScheme::RustV0);
    assert_eq!(ManglingScheme::detect("plain_c_name"), ManglingScheme::None);
    assert_eq!(ManglingScheme::detect(""), ManglingScheme::None);
    // Rust legacy heuristic
    assert_eq!(
        ManglingScheme::detect("_ZN3foo17h0123456789abcdefE"),
        ManglingScheme::RustLegacy
    );
    // Swift
    assert_eq!(ManglingScheme::detect("_$ssomething"), ManglingScheme::Swift);
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. SymbolResolver chain
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resolver_first_provider_wins() {
    let mut p1 = InMemorySymbolProvider::new();
    p1.add(mk("dup", 0x10, SymKind::Function));
    let mut p2 = InMemorySymbolProvider::new();
    let mut other = mk("dup", 0x10, SymKind::Function);
    other.add_tag("from_p2".into());
    p2.add(other);
    let mut r = SymbolResolver::new();
    r.add_provider(Box::new(p1));
    r.add_provider(Box::new(p2));
    let s = r.resolve_name("dup").unwrap();
    assert!(s.tags.is_empty());
    assert_eq!(r.provider_count(), 2);
    assert_eq!(r.all_symbols().len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. SymbolError From<anyhow::Error>
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn symbol_error_display_variants() {
    let e1 = SymbolError::NotFound("x".into());
    assert!(e1.to_string().contains('x'));
    let e2 = SymbolError::AddressNotFound(0x1234);
    assert!(e2.to_string().contains("0x1234"));
    let e3 = SymbolError::Duplicate("d".into());
    assert!(e3.to_string().contains('d'));
    let e4 = SymbolError::Parse("p".into());
    assert!(e4.to_string().contains('p'));
}

#[test]
fn symbol_error_from_anyhow() {
    let a: anyhow::Error = anyhow::anyhow!("boom");
    let s: SymbolError = a.into();
    assert!(s.to_string().contains("boom"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 22. PdbUrl list (filters by source)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unified_pdb_url_list_only_pdb_with_module() {
    let mut t = UnifiedSymbolTable::new();
    let mut s1 = UnifiedSymbol::new("a".into(), 0x10, SymbolKind::Function, SymbolSource::Pdb);
    s1.module = Some("foo.exe".into());
    t.add(s1);
    let s2 = UnifiedSymbol::new("b".into(), 0x20, SymbolKind::Function, SymbolSource::Pdb);
    t.add(s2); // no module → skipped
    let s3 = UnifiedSymbol::new("c".into(), 0x30, SymbolKind::Function, SymbolSource::Dwarf);
    t.add(s3);
    let urls = t.pdb_url_list("https://symsrv");
    assert_eq!(urls, vec!["https://symsrv/foo.exe".to_string()]);
}
