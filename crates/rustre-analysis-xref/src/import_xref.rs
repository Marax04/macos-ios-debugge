//! Import API cross-reference analysis for `rustre-analysis-xref`.
//!
//! For every imported symbol (Win32 API call, libc function, …) this module
//! builds a usage database that answers:
//!
//! * Which functions call `CreateFileW`?
//! * What are the (statically-determinable) argument values at each call site?
//! * What is the dominant usage pattern (e.g. `CreateFileW` always with
//!   `GENERIC_READ` → read-only opener)?
//! * Which sets of imports are used together by the same function (import
//!   co-occurrence clusters)?

use std::collections::{HashMap, HashSet};

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Argument value
// ─────────────────────────────────────────────────────────────────────────────

/// A statically-determinable argument value at a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgValue {
    /// A concrete immediate integer (e.g. flag constant).
    Immediate(u64),
    /// A pointer to a statically-known string.
    StringPtr(String),
    /// A NULL pointer.
    Null,
    /// Could not be determined statically.
    Unknown,
}

impl ArgValue {
    /// Return `true` if the value is a known constant.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Call site argument
// ─────────────────────────────────────────────────────────────────────────────

/// One argument at a specific call site.
#[derive(Debug, Clone)]
pub struct CallSiteArg {
    /// Zero-based argument index (0 = first argument).
    pub index: usize,
    /// Statically-determined value, if any.
    pub value: ArgValue,
    /// The register or stack slot that carries this argument.
    pub location: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportCallSite
// ─────────────────────────────────────────────────────────────────────────────

/// One invocation of an imported function at a specific instruction address.
#[derive(Debug, Clone)]
pub struct ImportCallSite {
    /// Address of the `CALL` instruction.
    pub call_addr: Address,
    /// Address of the function that contains the call.
    pub caller_function: Address,
    /// Statically-determined arguments at this site.
    pub args: Vec<CallSiteArg>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportRecord
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate information about one imported symbol.
#[derive(Debug, Clone)]
pub struct ImportRecord {
    /// Canonical import name (e.g. `"CreateFileW"`, `"printf"`).
    pub name: String,
    /// DLL / library providing this import (e.g. `"kernel32.dll"`).
    pub library: Option<String>,
    /// Import-by-ordinal number, if applicable.
    pub ordinal: Option<u32>,
    /// Virtual address of the IAT/GOT entry that resolves to this import.
    pub thunk_addr: Address,
    /// All call sites found in the binary.
    pub call_sites: Vec<ImportCallSite>,
}

impl ImportRecord {
    /// Number of distinct caller functions.
    #[must_use]
    pub fn distinct_callers(&self) -> HashSet<u64> {
        self.call_sites
            .iter()
            .map(|cs| cs.caller_function.as_u64())
            .collect()
    }

    /// Return the most common concrete value for argument `index`, if any site
    /// provides a known value.
    #[must_use]
    pub fn dominant_arg_value(&self, index: usize) -> Option<ArgValue> {
        let mut freq: HashMap<String, (usize, ArgValue)> = HashMap::new();
        for cs in &self.call_sites {
            for arg in &cs.args {
                if arg.index == index && arg.value.is_known() {
                    let key = format!("{:?}", arg.value);
                    freq.entry(key)
                        .or_insert_with(|| (0, arg.value.clone()))
                        .0 += 1;
                }
            }
        }
        // Iterate in sorted key order before taking the max: `freq` is a
        // `HashMap`, and `Iterator::max_by_key` returns the *last* maximal
        // element on ties, so an unsorted iteration would let hash iteration
        // order decide which equally-frequent value wins (nondeterministic
        // across runs/processes).
        let mut entries: Vec<(String, (usize, ArgValue))> = freq.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
            .into_iter()
            .max_by_key(|(_, (count, _))| *count)
            .map(|(_, (_, v))| v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportXrefDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// Central database of import cross-references.
#[derive(Debug, Default)]
pub struct ImportXrefDatabase {
    /// Map from import name to record.
    pub imports: HashMap<String, ImportRecord>,
    /// Map from thunk address to import name (for fast lookup).
    thunk_index: HashMap<u64, String>,
}

impl ImportXrefDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an import.
    pub fn register_import(&mut self, record: ImportRecord) {
        self.thunk_index
            .insert(record.thunk_addr.as_u64(), record.name.clone());
        self.imports.insert(record.name.clone(), record);
    }

    /// Look up the import name by thunk/PLT stub address.
    #[must_use]
    pub fn name_by_thunk(&self, thunk_addr: Address) -> Option<&str> {
        self.thunk_index
            .get(&thunk_addr.as_u64())
            .map(String::as_str)
    }

    /// Add a call site to an existing import record.
    pub fn add_call_site(&mut self, import_name: &str, site: ImportCallSite) {
        if let Some(rec) = self.imports.get_mut(import_name) {
            rec.call_sites.push(site);
        }
    }

    /// Return all imports called by `function_addr`, sorted by import name for
    /// deterministic output (`self.imports` is a `HashMap`; its iteration
    /// order is not stable across runs).
    #[must_use]
    pub fn imports_by_caller(&self, function_addr: Address) -> Vec<&ImportRecord> {
        let mut v: Vec<&ImportRecord> = self
            .imports
            .values()
            .filter(|rec| {
                rec.call_sites
                    .iter()
                    .any(|cs| cs.caller_function == function_addr)
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Number of registered imports.
    #[must_use]
    pub fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Number of total call sites across all imports.
    #[must_use]
    pub fn total_call_sites(&self) -> usize {
        self.imports.values().map(|r| r.call_sites.len()).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Usage pattern analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A usage pattern for an import: which argument index always (or mostly)
/// carries a specific value across all call sites.
#[derive(Debug, Clone)]
pub struct UsagePattern {
    /// Import name.
    pub import_name: String,
    /// Argument index.
    pub arg_index: usize,
    /// The dominant value.
    pub dominant_value: ArgValue,
    /// Fraction of call sites where this value is observed.
    pub coverage: f64,
    /// Human-readable description.
    pub description: String,
}

/// Analyse all imports in `db` and return any statistically-significant usage
/// patterns (coverage ≥ `min_coverage`).
#[must_use]
pub fn find_usage_patterns(db: &ImportXrefDatabase, min_coverage: f64) -> Vec<UsagePattern> {
    let mut patterns = Vec::new();

    for rec in db.imports.values() {
        if rec.call_sites.is_empty() {
            continue;
        }
        // Check argument indices 0..4.
        for arg_idx in 0..4usize {
            let mut freq: HashMap<String, (usize, ArgValue)> = HashMap::new();
            let mut total = 0usize;

            for cs in &rec.call_sites {
                for arg in &cs.args {
                    if arg.index == arg_idx && arg.value.is_known() {
                        let key = format!("{:?}", arg.value);
                        freq.entry(key)
                            .or_insert_with(|| (0, arg.value.clone()))
                            .0 += 1;
                        total += 1;
                    }
                }
            }

            if total == 0 {
                continue;
            }

            // See comment in `dominant_arg_value`: sort by key first so that
            // ties on `count` resolve deterministically instead of depending
            // on `HashMap` iteration order.
            let mut freq_entries: Vec<(String, (usize, ArgValue))> = freq.into_iter().collect();
            freq_entries.sort_by(|a, b| a.0.cmp(&b.0));
            if let Some((_, (count, value))) = freq_entries.into_iter().max_by_key(|(_, (c, _))| *c) {
                let coverage = f64::from(u32::try_from(count).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(rec.call_sites.len()).unwrap_or(u32::MAX));
                if coverage >= min_coverage {
                    patterns.push(UsagePattern {
                        import_name: rec.name.clone(),
                        arg_index: arg_idx,
                        dominant_value: value.clone(),
                        coverage,
                        description: format!(
                            "{} arg[{}] = {:?} ({:.0}% of sites)",
                            rec.name,
                            arg_idx,
                            value,
                            coverage * 100.0
                        ),
                    });
                }
            }
        }
    }

    patterns
}

// ─────────────────────────────────────────────────────────────────────────────
// Import co-occurrence clustering
// ─────────────────────────────────────────────────────────────────────────────

/// A cluster of imports that are frequently used together by the same function.
#[derive(Debug, Clone)]
pub struct ImportCluster {
    /// Imports that co-occur in the cluster.
    pub imports: Vec<String>,
    /// Number of functions that use all imports in this cluster.
    pub co_occurrence_count: usize,
    /// Suggested semantic label (heuristic).
    pub label: Option<String>,
}

/// Build import co-occurrence clusters for all functions in `db`.
///
/// Two imports are in the same cluster when they are both used by at least
/// `min_co_occurrence` functions.
#[must_use]
pub fn build_import_clusters(
    db: &ImportXrefDatabase,
    min_co_occurrence: usize,
) -> Vec<ImportCluster> {
    // Build per-function import sets.
    let mut fn_imports: HashMap<u64, HashSet<String>> = HashMap::new();
    for rec in db.imports.values() {
        for cs in &rec.call_sites {
            fn_imports
                .entry(cs.caller_function.as_u64())
                .or_default()
                .insert(rec.name.clone());
        }
    }

    // Count co-occurrences for each pair.
    let mut pair_count: HashMap<(String, String), usize> = HashMap::new();

    for set in fn_imports.values() {
        let names: Vec<&String> = set.iter().collect();
        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                let mut a = names[i].clone();
                let mut b = names[j].clone();
                if a > b {
                    std::mem::swap(&mut a, &mut b);
                }
                *pair_count.entry((a, b)).or_insert(0) += 1;
            }
        }
    }

    // Simple single-link clustering: merge pairs with count >= threshold.
    // `pair_count` is a `HashMap`, and this greedy single-link merge is
    // order-sensitive (which cluster a pair merges into, or whether a new
    // cluster is created, depends on processing order) — so iterate the
    // pairs in a fixed, sorted order to make the resulting clusters
    // deterministic across runs.
    let mut sorted_pairs: Vec<(&(String, String), &usize)> = pair_count.iter().collect();
    sorted_pairs.sort_by(|a, b| a.0.cmp(b.0));

    let mut clusters: Vec<HashSet<String>> = Vec::new();

    for ((a, b), count) in sorted_pairs {
        if *count < min_co_occurrence {
            continue;
        }
        // Find existing cluster containing a or b.
        let mut merged_idx = None;
        for (idx, cluster) in clusters.iter_mut().enumerate() {
            if cluster.contains(a) || cluster.contains(b) {
                cluster.insert(a.clone());
                cluster.insert(b.clone());
                merged_idx = Some(idx);
                break;
            }
        }
        if merged_idx.is_none() {
            let mut c = HashSet::new();
            c.insert(a.clone());
            c.insert(b.clone());
            clusters.push(c);
        }
    }

    // Convert to ImportCluster, then sort the outer Vec so that the returned
    // order is fully deterministic regardless of `clusters`' construction
    // order above.
    let mut result: Vec<ImportCluster> = clusters
        .into_iter()
        .map(|set| {
            let imports: Vec<String> = {
                let mut v: Vec<String> = set.into_iter().collect();
                v.sort();
                v
            };
            let co_occurrence_count = fn_imports
                .values()
                .filter(|f| imports.iter().all(|name| f.contains(name)))
                .count();
            ImportCluster {
                imports,
                co_occurrence_count,
                label: None,
            }
        })
        .collect();
    result.sort_by(|a, b| a.imports.cmp(&b.imports));
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// x86-64 IAT call scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a code slice for `CALL [RIP+rel32]` (`FF 15 …`) instructions that
/// target IAT/GOT slots, and record them as import call sites.
///
/// Returns a list of `(call_addr, thunk_addr)` pairs.
#[must_use]
pub fn scan_iat_calls_x86_64(code: &[u8], code_base: u64) -> Vec<(Address, Address)> {
    let mut results = Vec::new();
    let len = code.len();
    let mut i = 0usize;

    while i + 6 <= len {
        // FF 15 = CALL [RIP+disp32]
        if code[i] == 0xFF && code[i + 1] == 0x15 {
            let disp = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
            let next_pc = code_base.wrapping_add(i as u64).wrapping_add(6);
            let got_slot = u64::from_ne_bytes(
                (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                    .to_ne_bytes(),
            );
            // code_base comes from the (possibly adversarial) PE image base
            // and can be arbitrarily large; use wrapping_add like `next_pc`
            // above to avoid a debug-build overflow panic.
            results.push((
                Address::new(code_base.wrapping_add(i as u64)),
                Address::new(got_slot),
            ));
            i += 6;
            continue;
        }
        i += 1;
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument pre-value extraction (x86-64 heuristic)
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to extract the immediate value of the first argument register
/// (`RCX` / `RDI`) from up to `look_back` bytes before a `CALL` instruction.
///
/// Looks for `MOV RCX, imm64` (`48 B9 …`) or `MOV EDI, imm32` (`BF …`).
#[must_use]
pub fn extract_first_arg_imm(code: &[u8], call_offset: usize, look_back: usize) -> Option<u64> {
    // `call_offset` may come from analysis of untrusted/malformed binary data
    // and could exceed the code slice's bounds; clamp both ends so this can
    // never panic on out-of-range input.
    let call_offset = call_offset.min(code.len());
    let start = call_offset.saturating_sub(look_back);
    let window = &code[start..call_offset];
    let mut i = 0usize;

    while i + 2 < window.len() {
        // MOV RCX, imm64 (48 B9 lo lo lo lo hi hi hi hi)
        if window[i] == 0x48 && window[i + 1] == 0xB9 && i + 10 <= window.len() {
            let val = u64::from_le_bytes(window[i + 2..i + 10].try_into().ok()?);
            return Some(val);
        }
        // MOV ECX, imm32 (B9 lo lo lo lo)
        if window[i] == 0xB9 && i + 5 <= window.len() {
            let val = u64::from(u32::from_le_bytes(window[i + 1..i + 5].try_into().ok()?));
            return Some(val);
        }
        // MOV EDI, imm32 (BF lo lo lo lo) — System V arg0
        if window[i] == 0xBF && i + 5 <= window.len() {
            let val = u64::from(u32::from_le_bytes(window[i + 1..i + 5].try_into().ok()?));
            return Some(val);
        }
        i += 1;
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn make_import(name: &str, thunk: u64) -> ImportRecord {
        ImportRecord {
            name: name.into(),
            library: Some("kernel32.dll".into()),
            ordinal: None,
            thunk_addr: addr(thunk),
            call_sites: Vec::new(),
        }
    }

    #[test]
    fn database_register_and_lookup() {
        let mut db = ImportXrefDatabase::new();
        db.register_import(make_import("CreateFileW", 0x9000));
        assert!(db.imports.contains_key("CreateFileW"));
        assert_eq!(db.name_by_thunk(addr(0x9000)), Some("CreateFileW"));
    }

    #[test]
    fn database_add_call_site() {
        let mut db = ImportXrefDatabase::new();
        db.register_import(make_import("ReadFile", 0x9010));
        db.add_call_site(
            "ReadFile",
            ImportCallSite {
                call_addr: addr(0x1100),
                caller_function: addr(0x1000),
                args: vec![CallSiteArg {
                    index: 0,
                    value: ArgValue::Immediate(0x80000000),
                    location: "rcx".into(),
                }],
            },
        );
        let rec = db.imports.get("ReadFile").unwrap();
        assert_eq!(rec.call_sites.len(), 1);
    }

    #[test]
    fn dominant_arg_value() {
        let mut rec = make_import("CreateFileW", 0x9020);
        for _ in 0..3 {
            rec.call_sites.push(ImportCallSite {
                call_addr: addr(0x100),
                caller_function: addr(0x50),
                args: vec![CallSiteArg {
                    index: 1,
                    value: ArgValue::Immediate(0x80000000),
                    location: "rdx".into(),
                }],
            });
        }
        rec.call_sites.push(ImportCallSite {
            call_addr: addr(0x200),
            caller_function: addr(0x60),
            args: vec![CallSiteArg {
                index: 1,
                value: ArgValue::Immediate(0x40000000),
                location: "rdx".into(),
            }],
        });
        let dom = rec.dominant_arg_value(1);
        assert_eq!(dom, Some(ArgValue::Immediate(0x80000000)));
    }

    // Regression: when two argument values are equally frequent, the winner
    // must be deterministic (previously depended on HashMap iteration order).
    #[test]
    fn dominant_arg_value_tie_is_deterministic() {
        let mut rec = make_import("SetFilePointer", 0x9030);
        rec.call_sites.push(ImportCallSite {
            call_addr: addr(0x100),
            caller_function: addr(0x50),
            args: vec![CallSiteArg {
                index: 0,
                value: ArgValue::Immediate(0x2),
                location: "rcx".into(),
            }],
        });
        rec.call_sites.push(ImportCallSite {
            call_addr: addr(0x200),
            caller_function: addr(0x60),
            args: vec![CallSiteArg {
                index: 0,
                value: ArgValue::Immediate(0x1),
                location: "rcx".into(),
            }],
        });
        let first = rec.dominant_arg_value(0);
        for _ in 0..10 {
            assert_eq!(rec.dominant_arg_value(0), first);
        }
    }

    // Regression: `imports_by_caller` and `build_import_clusters` must return
    // a stable order across repeated calls.
    #[test]
    fn imports_by_caller_and_clusters_are_deterministic() {
        let mut db = ImportXrefDatabase::new();
        let names = ["Zeta", "Alpha", "Mid", "Beta", "Omega"];
        for (i, name) in names.iter().enumerate() {
            let mut rec = make_import(name, 0xB000 + i as u64);
            rec.call_sites.push(ImportCallSite {
                call_addr: addr(0x100 + i as u64),
                caller_function: addr(0x50),
                args: vec![],
            });
            db.register_import(rec);
        }
        let first = db.imports_by_caller(addr(0x50));
        let first_names: Vec<&str> = first.iter().map(|r| r.name.as_str()).collect();
        for _ in 0..10 {
            let again: Vec<&str> = db
                .imports_by_caller(addr(0x50))
                .iter()
                .map(|r| r.name.as_str())
                .collect();
            assert_eq!(again, first_names);
        }
        let mut sorted = first_names.clone();
        sorted.sort_unstable();
        assert_eq!(first_names, sorted);

        let clusters1 = build_import_clusters(&db, 1);
        for _ in 0..5 {
            let clusters_again = build_import_clusters(&db, 1);
            let names1: Vec<&Vec<String>> = clusters1.iter().map(|c| &c.imports).collect();
            let names2: Vec<&Vec<String>> = clusters_again.iter().map(|c| &c.imports).collect();
            assert_eq!(names1, names2);
        }
    }

    #[test]
    fn scan_iat_calls_found() {
        // FF 15 00 00 00 00 — CALL [RIP+0] → thunk = next_pc = base+6
        let code: &[u8] = &[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xCC];
        let base = 0x5000u64;
        let calls = scan_iat_calls_x86_64(code, base);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, addr(base));
        assert_eq!(calls[0].1, addr(base + 6)); // RIP+0
    }

    /// Regression: a malformed/adversarial image can report a `code_base`
    /// near `u64::MAX` (e.g. a corrupted PE image base). The call-address
    /// arithmetic must wrap instead of panicking on overflow.
    #[test]
    fn scan_iat_calls_near_u64_max_base_does_not_panic() {
        let code: &[u8] = &[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xCC];
        let base = u64::MAX - 2;
        let calls = scan_iat_calls_x86_64(code, base);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, addr(base.wrapping_add(0)));
    }

    #[test]
    fn extract_first_arg_imm_mov_ecx() {
        // B9 34 12 00 00  (MOV ECX, 0x1234) at offset 0, call at offset 5
        let code: &[u8] = &[0xB9, 0x34, 0x12, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
        let val = extract_first_arg_imm(code, 5, 10);
        assert_eq!(val, Some(0x1234));
    }

    #[test]
    fn extract_first_arg_imm_call_offset_beyond_code_does_not_panic() {
        // `call_offset` can come from analysis of malformed/adversarial input
        // and exceed the code slice's length; this must not panic.
        let code: &[u8] = &[0xB9, 0x34, 0x12, 0x00, 0x00];
        // Clamped to code.len(): the MOV ECX pattern is still found within bounds.
        assert_eq!(extract_first_arg_imm(code, code.len() + 1000, 10), Some(0x1234));
        assert_eq!(extract_first_arg_imm(code, usize::MAX, 10), Some(0x1234));
        // With a tiny look_back that excludes the pattern, nothing is found
        // but it still must not panic.
        assert_eq!(extract_first_arg_imm(code, usize::MAX, 1), None);
    }

    #[test]
    fn usage_pattern_detected() {
        let mut db = ImportXrefDatabase::new();
        let mut rec = make_import("VirtualAlloc", 0xA000);
        // 4 call sites all with arg[3] = 0x40 (PAGE_EXECUTE_READWRITE)
        for i in 0..4u64 {
            rec.call_sites.push(ImportCallSite {
                call_addr: addr(0x1000 + i),
                caller_function: addr(0x1000 + i * 100),
                args: vec![CallSiteArg {
                    index: 3,
                    value: ArgValue::Immediate(0x40),
                    location: "r9".into(),
                }],
            });
        }
        db.register_import(rec);

        let patterns = find_usage_patterns(&db, 0.5);
        assert!(!patterns.is_empty());
        let p = patterns.iter().find(|p| p.import_name == "VirtualAlloc").unwrap();
        assert_eq!(p.arg_index, 3);
        assert!((p.coverage - 1.0).abs() < 1e-6);
    }

    #[test]
    fn import_clusters_detected() {
        let mut db = ImportXrefDatabase::new();
        db.register_import(make_import("CreateFileW", 0x1));
        db.register_import(make_import("ReadFile", 0x2));

        // Both used by the same function.
        for name in ["CreateFileW", "ReadFile"] {
            db.add_call_site(
                name,
                ImportCallSite {
                    call_addr: addr(0x100),
                    caller_function: addr(0x1000),
                    args: vec![],
                },
            );
        }

        let clusters = build_import_clusters(&db, 1);
        assert!(!clusters.is_empty());
        let cluster = &clusters[0];
        assert!(cluster.imports.contains(&"CreateFileW".to_string()));
        assert!(cluster.imports.contains(&"ReadFile".to_string()));
    }
}
