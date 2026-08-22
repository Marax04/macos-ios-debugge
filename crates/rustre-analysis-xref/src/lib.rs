//! `rustre-analysis-xref`
//!
//! Cross-reference analysis: given code and data references between addresses.
//! Provides a bidirectional xref database, an x86/x64 byte-level scanner,
//! xref graphs, filtering, serialization, string xrefs, import xrefs, type
//! xrefs, and statistical summaries.

pub mod call_graph_builder;
pub mod data_flow_xrefs;
pub mod string_xref_finder;
pub mod xref_database;
pub mod data_xref;
pub mod extract;
pub mod global_xref_analysis;
pub mod import_xref;
pub mod string_xref;
pub mod transitive_closure;
pub mod xref_graph;
pub mod xref_heuristics;
pub mod xref_query;
pub mod xref_call_graph;
pub mod xref_query_engine;
pub mod indirect_call_resolver;
pub mod xref_index;
pub mod call_hierarchy;

#[cfg(test)]
mod soundness_fuzz;

/// Shared test-only PRNG for the crate's fuzz/property tests.
///
/// One definition instead of the per-module copies (Rng ×2, free `xorshift`,
/// nested `xs`). `below` is the zero-guarded form; `soundness_fuzz`'s old copy
/// was plain `% n` but every call site passes n >= 1, so the sequences are
/// identical.
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Seeded xorshift64 PRNG (state forced odd to avoid the zero fixed point).
    pub(crate) struct Rng(pub(crate) u64);
    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        pub(crate) fn next_u64(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
        pub(crate) fn below(&mut self, n: usize) -> usize {
            if n == 0 { 0 } else { (self.next_u64() % (n as u64)) as usize }
        }
        pub(crate) fn byte(&mut self) -> u8 {
            (self.next_u64() >> 24) as u8
        }
    }
}

#[cfg(test)]
mod index_property_tests;

pub use extract::{
    Region, RegionClass, RegionMap, XrefIndex, extract_all, extract_code_to_code,
    extract_code_to_data_riprel, extract_data_pointers,
};
pub use xref_query::{CallGraph, CallGraphMetrics, TransitiveClosure, XrefQueryEngine};
// Persistent xref index / database. Re-exported under disambiguated names so
// callers can build a one-shot index once and answer xrefs_to / xrefs_from in
// O(1) rather than re-scanning the code section per query.
pub use xref_index::{
    IndexStats as XrefIndexStats, XrefEntry, XrefEntryKind,
    XrefIndex as XrefIndexDb, add_xref as add_xref_entry,
};
pub use xref_database::{
    XrefContext, XrefDb, XrefDbStats, XrefMerge, XrefQuery,
    XrefRecord as XrefDbRecord, XrefType,
};
pub use xref_database::{Architecture as XrefArch, build_xref_db_from_path};

use rustre_core::address::{Address, AddressRange};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// XrefKind
// ---------------------------------------------------------------------------

/// The nature of a cross-reference between two addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum XrefKind {
    /// CALL instruction — direct or indirect.
    CodeCall,
    /// JMP / branch instruction.
    CodeJump,
    /// RET to address (rare; useful for indirect dispatch).
    CodeReturn,
    /// Instruction reads from address.
    DataRead,
    /// Instruction writes to address.
    DataWrite,
    /// Address is taken (LEA, MOV imm).
    DataAddress,
    /// Data section contains a pointer to this address.
    DataPointer,
    /// Import-by-name reference.
    ImportByName,
    /// Import-by-ordinal reference.
    ImportByOrdinal,
    /// Reference to an interned string literal.
    StringRef,
    /// Type-level reference (vtable slot, RTTI, etc.).
    TypeRef,
    /// Thunk / tail-call forwarding stub.
    ThunkCall,
}

impl XrefKind {
    /// Whether this kind represents a code-flow transfer.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(
            self,
            Self::CodeCall | Self::CodeJump | Self::CodeReturn | Self::ThunkCall
        )
    }

    /// Whether this kind represents a data access.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(
            self,
            Self::DataRead | Self::DataWrite | Self::DataAddress | Self::DataPointer
        )
    }

    /// Whether this kind is an import reference.
    #[must_use]
    pub const fn is_import(&self) -> bool {
        matches!(self, Self::ImportByName | Self::ImportByOrdinal)
    }

    /// All variants in a deterministic order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::CodeCall,
            Self::CodeJump,
            Self::CodeReturn,
            Self::DataRead,
            Self::DataWrite,
            Self::DataAddress,
            Self::DataPointer,
            Self::ImportByName,
            Self::ImportByOrdinal,
            Self::StringRef,
            Self::TypeRef,
            Self::ThunkCall,
        ]
    }
}

impl fmt::Display for XrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CodeCall => "CodeCall",
            Self::CodeJump => "CodeJump",
            Self::CodeReturn => "CodeReturn",
            Self::DataRead => "DataRead",
            Self::DataWrite => "DataWrite",
            Self::DataAddress => "DataAddress",
            Self::DataPointer => "DataPointer",
            Self::ImportByName => "ImportByName",
            Self::ImportByOrdinal => "ImportByOrdinal",
            Self::StringRef => "StringRef",
            Self::TypeRef => "TypeRef",
            Self::ThunkCall => "ThunkCall",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Xref
// ---------------------------------------------------------------------------

/// A single cross-reference record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    /// Where the reference originates.
    pub from: Address,
    /// Where the reference points.
    pub to: Address,
    /// The kind of reference.
    pub kind: XrefKind,
    /// Size of the instruction that generates this xref (0 for data refs).
    pub instr_size: u8,
    /// Optional human-readable tag (e.g., import name or string content).
    pub tag: Option<String>,
}

impl Xref {
    /// Construct a new `Xref` without a tag.
    #[must_use]
    pub const fn new(from: Address, to: Address, kind: XrefKind, instr_size: u8) -> Self {
        Self {
            from,
            to,
            kind,
            instr_size,
            tag: None,
        }
    }

    /// Construct a new `Xref` with a string tag.
    #[must_use]
    pub fn with_tag(
        from: Address,
        to: Address,
        kind: XrefKind,
        instr_size: u8,
        tag: impl Into<String>,
    ) -> Self {
        Self {
            from,
            to,
            kind,
            instr_size,
            tag: Some(tag.into()),
        }
    }

    /// Whether this xref transfers code execution.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.kind.is_code()
    }

    /// Whether this xref is a data-access reference.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.kind.is_data()
    }
}

impl fmt::Display for Xref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x} -> {:#010x} [{}]",
            self.from.0, self.to.0, self.kind
        )?;
        if let Some(tag) = &self.tag {
            write!(f, " \"{tag}\"")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// XrefFilter — predicate-based xref selection
// ---------------------------------------------------------------------------

/// Builder for filtering xref records.
#[derive(Default)]
pub struct XrefFilter {
    kinds: Option<HashSet<XrefKind>>,
    from_range: Option<AddressRange>,
    to_range: Option<AddressRange>,
    require_tag: bool,
    tag_contains: Option<String>,
    min_from: Option<u64>,
    max_to: Option<u64>,
}

impl XrefFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only include xrefs with these kinds.
    #[must_use]
    pub fn with_kinds(mut self, kinds: impl IntoIterator<Item = XrefKind>) -> Self {
        self.kinds = Some(kinds.into_iter().collect());
        self
    }

    /// Only include xrefs originating within `range`.
    #[must_use]
    pub const fn from_range(mut self, range: AddressRange) -> Self {
        self.from_range = Some(range);
        self
    }

    /// Only include xrefs pointing within `range`.
    #[must_use]
    pub const fn to_range(mut self, range: AddressRange) -> Self {
        self.to_range = Some(range);
        self
    }

    /// Only include xrefs that have a tag.
    #[must_use]
    pub const fn with_tag_required(mut self) -> Self {
        self.require_tag = true;
        self
    }

    /// Only include xrefs whose tag contains `s`.
    #[must_use]
    pub fn tag_contains(mut self, s: impl Into<String>) -> Self {
        self.tag_contains = Some(s.into());
        self.require_tag = true;
        self
    }

    /// Only include xrefs where `from >= addr`.
    #[must_use]
    pub const fn min_from(mut self, addr: u64) -> Self {
        self.min_from = Some(addr);
        self
    }

    /// Only include xrefs where `to <= addr`.
    #[must_use]
    pub const fn max_to(mut self, addr: u64) -> Self {
        self.max_to = Some(addr);
        self
    }

    /// Return `true` if `xref` passes all filter conditions.
    #[must_use]
    pub fn matches(&self, xref: &Xref) -> bool {
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&xref.kind) {
                return false;
            }
        if let Some(r) = &self.from_range
            && !r.contains(xref.from) {
                return false;
            }
        if let Some(r) = &self.to_range
            && !r.contains(xref.to) {
                return false;
            }
        if self.require_tag && xref.tag.is_none() {
            return false;
        }
        if let Some(needle) = &self.tag_contains {
            match &xref.tag {
                Some(t) if t.contains(needle.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(min) = self.min_from
            && xref.from.0 < min {
                return false;
            }
        if let Some(max) = self.max_to
            && xref.to.0 > max {
                return false;
            }
        true
    }
}

// ---------------------------------------------------------------------------
// XrefDatabase
// ---------------------------------------------------------------------------

/// Bidirectional store of all cross-references in a binary.
pub struct XrefDatabase {
    from_map: HashMap<u64, Vec<Xref>>,
    to_map: HashMap<u64, Vec<Xref>>,
    string_refs: HashMap<String, Vec<Address>>, // string content -> addresses
    import_refs: HashMap<String, Vec<Xref>>,    // import name -> xrefs
    type_refs: HashMap<String, Vec<Xref>>,      // type name -> xrefs
    total: usize,
}

impl Default for XrefDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl XrefDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            from_map: HashMap::new(),
            to_map: HashMap::new(),
            string_refs: HashMap::new(),
            import_refs: HashMap::new(),
            type_refs: HashMap::new(),
            total: 0,
        }
    }

    /// Insert a raw [`Xref`] record.
    pub fn add(&mut self, xref: Xref) {
        // Update secondary indices
        if (xref.kind == XrefKind::ImportByName || xref.kind == XrefKind::ImportByOrdinal)
            && let Some(tag) = &xref.tag {
                self.import_refs
                    .entry(tag.clone())
                    .or_default()
                    .push(xref.clone());
            }
        if xref.kind == XrefKind::StringRef
            && let Some(tag) = &xref.tag {
                self.string_refs
                    .entry(tag.clone())
                    .or_default()
                    .push(xref.from);
            }
        if xref.kind == XrefKind::TypeRef
            && let Some(tag) = &xref.tag {
                self.type_refs
                    .entry(tag.clone())
                    .or_default()
                    .push(xref.clone());
            }
        self.from_map
            .entry(xref.from.0)
            .or_default()
            .push(xref.clone());
        self.to_map.entry(xref.to.0).or_default().push(xref);
        self.total += 1;
    }

    /// Add a `CALL` cross-reference.
    pub fn add_call(&mut self, from: Address, to: Address, instr_size: u8) {
        self.add(Xref::new(from, to, XrefKind::CodeCall, instr_size));
    }

    /// Add a `JMP` / branch cross-reference.
    pub fn add_jump(&mut self, from: Address, to: Address, instr_size: u8) {
        self.add(Xref::new(from, to, XrefKind::CodeJump, instr_size));
    }

    /// Add a `RET` cross-reference.
    pub fn add_return(&mut self, from: Address, to: Address) {
        self.add(Xref::new(from, to, XrefKind::CodeReturn, 0));
    }

    /// Add a data-read cross-reference.
    pub fn add_data_read(&mut self, from: Address, to: Address) {
        self.add(Xref::new(from, to, XrefKind::DataRead, 0));
    }

    /// Add a data-write cross-reference.
    pub fn add_data_write(&mut self, from: Address, to: Address) {
        self.add(Xref::new(from, to, XrefKind::DataWrite, 0));
    }

    /// Add a data-address (LEA / MOV-imm) cross-reference.
    pub fn add_data_addr(&mut self, from: Address, to: Address) {
        self.add(Xref::new(from, to, XrefKind::DataAddress, 0));
    }

    /// Add a data-section pointer cross-reference.
    pub fn add_data_pointer(&mut self, from: Address, to: Address) {
        self.add(Xref::new(from, to, XrefKind::DataPointer, 0));
    }

    /// Add an import-by-name cross-reference.
    pub fn add_import_by_name(&mut self, from: Address, to: Address, name: impl Into<String>) {
        self.add(Xref::with_tag(from, to, XrefKind::ImportByName, 0, name));
    }

    /// Add an import-by-ordinal cross-reference.
    pub fn add_import_by_ordinal(&mut self, from: Address, to: Address, ordinal: u32) {
        self.add(Xref::with_tag(
            from,
            to,
            XrefKind::ImportByOrdinal,
            0,
            ordinal.to_string(),
        ));
    }

    /// Add a string reference from `from` to the string data at `to`.
    pub fn add_string_ref(&mut self, from: Address, to: Address, content: impl Into<String>) {
        self.add(Xref::with_tag(from, to, XrefKind::StringRef, 0, content));
    }

    /// Add a type reference from `from` to `to` for type `type_name`.
    pub fn add_type_ref(&mut self, from: Address, to: Address, type_name: impl Into<String>) {
        self.add(Xref::with_tag(from, to, XrefKind::TypeRef, 0, type_name));
    }

    /// Add a thunk/tail-call xref.
    pub fn add_thunk(&mut self, from: Address, to: Address, instr_size: u8) {
        self.add(Xref::new(from, to, XrefKind::ThunkCall, instr_size));
    }

    /// All xrefs originating at `addr`.
    #[must_use]
    pub fn xrefs_from(&self, addr: Address) -> &[Xref] {
        self.from_map.get(&addr.0).map_or(&[], Vec::as_slice)
    }

    /// All xrefs pointing to `addr`.
    #[must_use]
    pub fn xrefs_to(&self, addr: Address) -> &[Xref] {
        self.to_map.get(&addr.0).map_or(&[], Vec::as_slice)
    }

    /// Addresses of all `CALL` instructions that call `addr`.
    #[must_use]
    pub fn callers_of(&self, addr: Address) -> Vec<Address> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.from)
            .collect()
    }

    /// Addresses that `addr` calls (via `CALL` instructions).
    #[must_use]
    pub fn callees_of(&self, addr: Address) -> Vec<Address> {
        self.xrefs_from(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.to)
            .collect()
    }

    /// Addresses of all jump instructions that branch to `addr`.
    #[must_use]
    pub fn jumpers_to(&self, addr: Address) -> Vec<Address> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeJump)
            .map(|x| x.from)
            .collect()
    }

    /// Addresses of data references (reads, writes, addresses, pointers) to `addr`.
    #[must_use]
    pub fn data_refs_to(&self, addr: Address) -> Vec<Address> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| x.kind.is_data())
            .map(|x| x.from)
            .collect()
    }

    /// All xrefs that reference the named import symbol.
    #[must_use]
    pub fn xrefs_to_import(&self, name: &str) -> &[Xref] {
        self.import_refs.get(name).map_or(&[], Vec::as_slice)
    }

    /// All xrefs that reference the named type.
    #[must_use]
    pub fn xrefs_to_type(&self, name: &str) -> &[Xref] {
        self.type_refs.get(name).map_or(&[], Vec::as_slice)
    }

    /// All addresses that reference the given string content.
    #[must_use]
    pub fn string_ref_sites(&self, content: &str) -> &[Address] {
        self.string_refs.get(content).map_or(&[], Vec::as_slice)
    }

    /// All unique strings referenced in the database, sorted lexicographically
    /// for deterministic output (`string_refs` is a `HashMap`; its iteration
    /// order is not stable across runs).
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.string_refs.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// All unique import names referenced in the database, sorted
    /// lexicographically for deterministic output (`import_refs` is a
    /// `HashMap`; its iteration order is not stable across runs).
    #[must_use]
    pub fn all_import_names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.import_refs.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// Filter xrefs from `addr` using the given `filter`.
    #[must_use]
    pub fn filter_from(&self, addr: Address, filter: &XrefFilter) -> Vec<&Xref> {
        self.xrefs_from(addr)
            .iter()
            .filter(|x| filter.matches(x))
            .collect()
    }

    /// Filter xrefs to `addr` using the given `filter`.
    #[must_use]
    pub fn filter_to(&self, addr: Address, filter: &XrefFilter) -> Vec<&Xref> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| filter.matches(x))
            .collect()
    }

    /// Filter all xrefs in the database using the given `filter`.
    #[must_use]
    pub fn filter_all(&self, filter: &XrefFilter) -> Vec<&Xref> {
        self.iter_all().filter(|x| filter.matches(x)).collect()
    }

    /// Remove all xrefs originating at `from`. Returns the count removed.
    pub fn remove_from(&mut self, from: Address) -> usize {
        let removed = self.from_map.remove(&from.0).map_or(0, |v| v.len());
        if removed > 0 {
            for to_vec in self.to_map.values_mut() {
                to_vec.retain(|x| x.from != from);
            }
            self.to_map.retain(|_, v| !v.is_empty());
            self.rebuild_secondary_indices();
            // Recompute total from the source of truth (from_map) to stay consistent.
            self.total = self.from_map.values().map(Vec::len).sum();
        }
        removed
    }

    /// Remove all xrefs pointing to `to`. Returns the count removed.
    pub fn remove_to(&mut self, to: Address) -> usize {
        let removed = self.to_map.remove(&to.0).map_or(0, |v| v.len());
        if removed > 0 {
            for from_vec in self.from_map.values_mut() {
                from_vec.retain(|x| x.to != to);
            }
            self.from_map.retain(|_, v| !v.is_empty());
            self.rebuild_secondary_indices();
            // Recompute total from the source of truth (from_map) to stay consistent.
            self.total = self.from_map.values().map(Vec::len).sum();
        }
        removed
    }

    /// Remove a specific xref matching `from`, `to`, and `kind`. Returns `true` if found.
    pub fn remove_exact(&mut self, from: Address, to: Address, kind: XrefKind) -> bool {
        let before = self.total;
        if let Some(v) = self.from_map.get_mut(&from.0) {
            v.retain(|x| !(x.to == to && x.kind == kind));
        }
        self.from_map.retain(|_, v| !v.is_empty());
        if let Some(v) = self.to_map.get_mut(&to.0) {
            v.retain(|x| !(x.from == from && x.kind == kind));
        }
        self.to_map.retain(|_, v| !v.is_empty());
        self.rebuild_secondary_indices();
        let after: usize = self.from_map.values().map(std::vec::Vec::len).sum::<usize>();
        self.total = after;
        after < before
    }

    fn rebuild_secondary_indices(&mut self) {
        self.string_refs.clear();
        self.import_refs.clear();
        self.type_refs.clear();
        // Collect all xrefs into a temporary vec to avoid borrow conflict
        let all_xrefs: Vec<Xref> = self
            .from_map
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();
        for xref in &all_xrefs {
            if xref.kind == XrefKind::StringRef
                && let Some(tag) = &xref.tag {
                    self.string_refs
                        .entry(tag.clone())
                        .or_default()
                        .push(xref.from);
                }
            if matches!(
                xref.kind,
                XrefKind::ImportByName | XrefKind::ImportByOrdinal
            )
                && let Some(tag) = &xref.tag {
                    self.import_refs
                        .entry(tag.clone())
                        .or_default()
                        .push(xref.clone());
                }
            if xref.kind == XrefKind::TypeRef
                && let Some(tag) = &xref.tag {
                    self.type_refs
                        .entry(tag.clone())
                        .or_default()
                        .push(xref.clone());
                }
        }
    }

    /// Total number of xref records stored.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.total
    }

    /// Whether the database contains any xrefs.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Iterate over every xref record stored (order is unspecified).
    pub fn iter_all(&self) -> impl Iterator<Item = &Xref> {
        self.from_map.values().flat_map(|v| v.iter())
    }

    /// How many unique functions `addr` calls (distinct callee addresses).
    #[must_use]
    pub fn callee_count(&self, addr: Address) -> usize {
        let targets: HashSet<u64> = self
            .xrefs_from(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.to.0)
            .collect();
        targets.len()
    }

    /// How many unique callers call `addr`.
    #[must_use]
    pub fn caller_count(&self, addr: Address) -> usize {
        let sources: HashSet<u64> = self
            .xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.from.0)
            .collect();
        sources.len()
    }

    /// Whether `addr` makes no outgoing `CALL` xrefs **recorded in this
    /// index**.
    ///
    /// ⚠ This is not the same as "`addr` calls nothing". An address the
    /// analysis never visited has no xrefs either, so it answers `true` here
    /// exactly like a genuine leaf — the index holds xrefs, not a record of
    /// what was examined. Callers that need the difference must pair this with
    /// [`Self::has_any_xrefs`]: a "leaf" that appears nowhere in the index at
    /// all is far more likely to be unanalysed than childless.
    ///
    /// It also sees only DIRECT calls; a function that dispatches exclusively
    /// through `FF /2` looks like a leaf (same caveat as [`Self::roots`]).
    #[must_use]
    pub fn is_leaf_function(&self, addr: Address) -> bool {
        self.callee_count(addr) == 0
    }

    /// Whether this index mentions `addr` at all, as the source or the target
    /// of any xref.
    ///
    /// The distinguishing fact behind [`Self::is_leaf_function`]: `false` here
    /// means the address never appeared in the analysis, so any "no outgoing
    /// calls" answer about it is an absence of data, not a finding.
    #[must_use]
    pub fn has_any_xrefs(&self, addr: Address) -> bool {
        self.from_map.contains_key(&addr.0) || self.to_map.contains_key(&addr.0)
    }

    /// The `top_n` most-called function addresses (by call-site count).
    #[must_use]
    pub fn hot_functions(&self, top_n: usize) -> Vec<(Address, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for xref in self.iter_all() {
            if xref.kind == XrefKind::CodeCall {
                *counts.entry(xref.to.0).or_insert(0) += 1;
            }
        }
        let mut list: Vec<(Address, usize)> = counts
            .into_iter()
            .map(|(k, v)| (Address::new(k), v))
            .collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.0.cmp(&b.0.0)));
        list.truncate(top_n);
        list
    }

    /// Collect all unique addresses that are referenced as targets, sorted
    /// ascending for deterministic output (`to_map` is a `HashMap`; its
    /// iteration order is not stable across runs).
    #[must_use]
    pub fn all_targets(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self.to_map.keys().map(|&k| Address::new(k)).collect();
        v.sort_unstable();
        v
    }

    /// Collect all unique addresses that appear as source (from) addresses,
    /// sorted ascending for deterministic output (`from_map` is a `HashMap`;
    /// its iteration order is not stable across runs).
    #[must_use]
    pub fn all_sources(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self.from_map.keys().map(|&k| Address::new(k)).collect();
        v.sort_unstable();
        v
    }

    /// Collect all unique addresses that are referenced by code calls,
    /// sorted ascending for deterministic output.
    #[must_use]
    pub fn all_call_targets(&self) -> Vec<Address> {
        let mut set = HashSet::new();
        for xref in self.iter_all() {
            if xref.kind == XrefKind::CodeCall {
                set.insert(xref.to.0);
            }
        }
        let mut v: Vec<Address> = set.into_iter().map(Address::new).collect();
        v.sort_unstable();
        v
    }

    /// Merge another database into this one (consuming it).
    pub fn merge(&mut self, other: Self) {
        for xref in other.from_map.into_values().flat_map(std::iter::IntoIterator::into_iter) {
            self.add(xref);
        }
    }

    /// Serialize the entire database to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let records: Vec<XrefJsonRecord> = self
            .iter_all()
            .map(|x| XrefJsonRecord {
                from: x.from.0,
                to: x.to.0,
                kind: x.kind.to_string(),
                instr_size: x.instr_size,
                tag: x.tag.clone(),
            })
            .collect();
        serde_json::to_string_pretty(&records)
    }

    /// Deserialize a database from JSON produced by [`Self::to_json`].
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or contains unknown kind strings.
    pub fn from_json(json: &str) -> Result<Self, XrefError> {
        let records: Vec<XrefJsonRecord> = serde_json::from_str(json).map_err(XrefError::Json)?;
        let mut db = Self::new();
        for rec in records {
            let kind = parse_xref_kind(&rec.kind)?;
            let xref = if let Some(tag) = rec.tag {
                Xref::with_tag(
                    Address::new(rec.from),
                    Address::new(rec.to),
                    kind,
                    rec.instr_size,
                    tag,
                )
            } else {
                Xref::new(
                    Address::new(rec.from),
                    Address::new(rec.to),
                    kind,
                    rec.instr_size,
                )
            };
            db.add(xref);
        }
        Ok(db)
    }
}

fn parse_xref_kind(s: &str) -> Result<XrefKind, XrefError> {
    match s {
        "CodeCall" => Ok(XrefKind::CodeCall),
        "CodeJump" => Ok(XrefKind::CodeJump),
        "CodeReturn" => Ok(XrefKind::CodeReturn),
        "DataRead" => Ok(XrefKind::DataRead),
        "DataWrite" => Ok(XrefKind::DataWrite),
        "DataAddress" => Ok(XrefKind::DataAddress),
        "DataPointer" => Ok(XrefKind::DataPointer),
        "ImportByName" => Ok(XrefKind::ImportByName),
        "ImportByOrdinal" => Ok(XrefKind::ImportByOrdinal),
        "StringRef" => Ok(XrefKind::StringRef),
        "TypeRef" => Ok(XrefKind::TypeRef),
        "ThunkCall" => Ok(XrefKind::ThunkCall),
        other => Err(XrefError::UnknownKind(other.to_owned())),
    }
}

// ---------------------------------------------------------------------------
// XrefRecord — public API type (MCP-facing)
// ---------------------------------------------------------------------------

/// A thin, serialisable cross-reference record returned by [`xrefs_to`] and
/// [`xrefs_from`].  This is the canonical shape consumed by the MCP wrapper.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XrefRecord {
    /// Address of the instruction or datum that contains the reference.
    pub from_addr: u64,
    /// Target address being referenced.
    pub to_addr: u64,
    /// Human-readable kind string (e.g. `"CodeCall"`, `"DataRead"`).
    pub kind: String,
}

/// Return all cross-references that point **to** `addr` from the given
/// [`XrefDatabase`].  This is the explicit-database form used internally.
#[must_use]
pub fn xrefs_to_in(db: &XrefDatabase, addr: u64) -> Vec<XrefRecord> {
    db.xrefs_to(rustre_core::address::Address::new(addr))
        .iter()
        .map(|x| XrefRecord {
            from_addr: x.from.0,
            to_addr: x.to.0,
            kind: x.kind.to_string(),
        })
        .collect()
}

/// Return all cross-references that originate **from** `addr` in the given
/// [`XrefDatabase`].  This is the explicit-database form used internally.
#[must_use]
pub fn xrefs_from_in(db: &XrefDatabase, addr: u64) -> Vec<XrefRecord> {
    db.xrefs_from(rustre_core::address::Address::new(addr))
        .iter()
        .map(|x| XrefRecord {
            from_addr: x.from.0,
            to_addr: x.to.0,
            kind: x.kind.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Global default database — backing storage for the thin top-level API
// ---------------------------------------------------------------------------

static GLOBAL_XREF_DB: std::sync::OnceLock<parking_lot::RwLock<XrefDatabase>> =
    std::sync::OnceLock::new();

fn global_db() -> &'static parking_lot::RwLock<XrefDatabase> {
    GLOBAL_XREF_DB.get_or_init(|| parking_lot::RwLock::new(XrefDatabase::new()))
}

/// Mutable access to the crate-global [`XrefDatabase`].
///
/// Used as backing store for the thin top-level [`xrefs_to`] / [`xrefs_from`] API.
/// Callers populate this database (typically once, during analysis) and then query
/// it through the address-only functions below.
#[must_use]
pub fn global_xref_db() -> &'static parking_lot::RwLock<XrefDatabase> {
    global_db()
}

/// Return all cross-references that point **to** `addr` from the crate-global
/// [`XrefDatabase`].
#[must_use]
pub fn xrefs_to(addr: u64) -> Vec<XrefRecord> {
    xrefs_to_in(&global_db().read(), addr)
}

/// Return all cross-references that originate **from** `addr` in the crate-global
/// [`XrefDatabase`].
#[must_use]
pub fn xrefs_from(addr: u64) -> Vec<XrefRecord> {
    xrefs_from_in(&global_db().read(), addr)
}

#[cfg(test)]
mod global_xref_api_tests {
    use super::*;
    use rustre_core::address::Address;

    #[test]
    fn global_xrefs_to_returns_incoming_call_record() {
        let addr_target: u64 = 0x0BAD_F00D_DEAD_0001;
        let addr_caller: u64 = 0x0BAD_F00D_DEAD_0100;
        {
            let mut db = global_xref_db().write();
            db.add_call(Address::new(addr_caller), Address::new(addr_target), 5);
        }
        let recs = xrefs_to(addr_target);
        assert!(recs.iter().any(|r| r.from_addr == addr_caller
            && r.to_addr == addr_target
            && r.kind == "CodeCall"));
    }

    #[test]
    fn global_xrefs_from_returns_outgoing_data_record() {
        let addr_src: u64 = 0x0BAD_F00D_BEEF_0200;
        let addr_dst: u64 = 0x0BAD_F00D_BEEF_0300;
        {
            let mut db = global_xref_db().write();
            db.add_data_read(Address::new(addr_src), Address::new(addr_dst));
        }
        let recs = xrefs_from(addr_src);
        assert!(recs.iter().any(|r| r.from_addr == addr_src
            && r.to_addr == addr_dst
            && r.kind == "DataRead"));
    }
}

// ---------------------------------------------------------------------------
// Path-based bootstrap for XrefIndex
// ---------------------------------------------------------------------------

/// Convenience: load a PE from disk and build a fully-populated `XrefIndex` over it.
///
/// Finds the primary executable section (`.text`, falling back to the first
/// `IMAGE_SCN_MEM_EXECUTE` section). Non-PE inputs and missing executable sections
/// return an empty index.
///
/// # Errors
///
/// Returns `std::io::Error` if the file cannot be read.
pub fn xref_index_from_path(path: &std::path::Path) -> std::io::Result<XrefIndexDb> {
    let data = std::fs::read(path)?;
    Ok(xref_index_from_bytes(&data))
}

/// In-memory variant of [`xref_index_from_path`].
///
/// Parses `data` as a PE, locates the primary executable section (`.text`, falling
/// back to the first `IMAGE_SCN_MEM_EXECUTE` section), and returns a populated
/// [`XrefIndexDb`]. Non-PE buffers and PEs with no executable section produce an
/// empty index.
#[must_use]
pub fn xref_index_from_bytes(data: &[u8]) -> XrefIndexDb {
    if let Ok(info) = rustre_loader_pe::PeInfo::parse(data) {
        let sec = info
            .sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(".text"))
            .or_else(|| {
                info.sections
                    .iter()
                    .find(|s| s.characteristics & 0x2000_0000 != 0)
            });
        if let Some(sec) = sec {
            let start = sec.raw_offset as usize;
            let end = (start + sec.raw_size as usize).min(data.len());
            if start < end {
                // image_base and virtual_address are both attacker-controlled
                // (read straight from the PE header); a malformed/adversarial
                // PE can set image_base near u64::MAX, so use wrapping
                // arithmetic to avoid a debug-build panic / release UB and to
                // match the wraparound semantics `Address` uses everywhere else.
                let base = info.image_base.wrapping_add(sec.virtual_address);
                return XrefIndexDb::build(base, &data[start..end]);
            }
        }
    }
    XrefIndexDb::new()
}

#[cfg(test)]
mod xref_index_from_path_tests {
    use super::*;

    #[test]
    fn nonexistent_path_returns_io_error() {
        let result = xref_index_from_path(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist.exe",
        ));
        assert!(result.is_err());
    }

    #[test]
    fn non_pe_bytes_return_empty_index() {
        let zeros = [0u8; 64];
        let idx = xref_index_from_bytes(&zeros);
        assert_eq!(idx.total(), 0);
    }
}

// ---------------------------------------------------------------------------
// XrefJsonRecord — internal serde helper for XrefDatabase::to_json / from_json
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct XrefJsonRecord {
    from: u64,
    to: u64,
    kind: String,
    instr_size: u8,
    tag: Option<String>,
}

// ---------------------------------------------------------------------------
// XrefError
// ---------------------------------------------------------------------------

/// Errors produced by xref operations.
#[derive(Debug, thiserror::Error)]
pub enum XrefError {
    #[error("unknown xref kind: {0}")]
    UnknownKind(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("database is empty")]
    EmptyDatabase,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// XrefGraph — call-graph / reference-graph
// ---------------------------------------------------------------------------

/// A directed call/reference graph built from an [`XrefDatabase`].
///
/// Each node is an `Address`; each directed edge represents one or more
/// xrefs of the filtered kind. This is suitable for reachability queries,
/// dominator computation, and SCC detection.
pub struct XrefGraph {
    /// Adjacency list: node -> list of (neighbour, `xref_kind`, `edge_count`).
    adj: HashMap<u64, Vec<(u64, XrefKind, usize)>>,
    /// Precomputed in-degree per node (number of distinct incoming edges),
    /// so [`Self::in_degree`] is O(1) instead of an O(V+E) scan of `adj`.
    in_degree: HashMap<u64, usize>,
    /// All nodes present in the graph.
    nodes: HashSet<u64>,
    /// The kind(s) of xrefs included in this graph.
    pub kinds: Vec<XrefKind>,
}

impl XrefGraph {
    /// Build a call graph (only `CodeCall` edges).
    #[must_use]
    pub fn call_graph(db: &XrefDatabase) -> Self {
        Self::build(db, &[XrefKind::CodeCall])
    }

    /// Build a full code graph (calls and jumps).
    #[must_use]
    pub fn code_graph(db: &XrefDatabase) -> Self {
        Self::build(db, &[XrefKind::CodeCall, XrefKind::CodeJump])
    }

    /// Build a data-reference graph.
    #[must_use]
    pub fn data_graph(db: &XrefDatabase) -> Self {
        Self::build(
            db,
            &[
                XrefKind::DataRead,
                XrefKind::DataWrite,
                XrefKind::DataAddress,
                XrefKind::DataPointer,
            ],
        )
    }

    /// Build a graph including all xref kinds.
    #[must_use]
    pub fn full_graph(db: &XrefDatabase) -> Self {
        Self::build(db, XrefKind::all())
    }

    /// Build a graph from specific `kinds`.
    #[must_use]
    pub fn build(db: &XrefDatabase, kinds: &[XrefKind]) -> Self {
        let kind_set: HashSet<XrefKind> = kinds.iter().copied().collect();
        let mut adj: HashMap<u64, Vec<(u64, XrefKind, usize)>> = HashMap::new();
        let mut nodes: HashSet<u64> = HashSet::new();
        // Accumulate edges with counts
        let mut edge_counts: HashMap<(u64, u64, XrefKind), usize> = HashMap::new();

        for xref in db.iter_all() {
            if kind_set.contains(&xref.kind) {
                nodes.insert(xref.from.0);
                nodes.insert(xref.to.0);
                *edge_counts
                    .entry((xref.from.0, xref.to.0, xref.kind))
                    .or_insert(0) += 1;
            }
        }
        // Track *distinct source nodes* per target, matching the original
        // `in_degree` semantics (count of callers/referrers, not of edge-kind
        // entries — a (from, to) pair with edges of two different kinds must
        // still count as a single incoming source).
        let mut incoming_sources: HashMap<u64, HashSet<u64>> = HashMap::new();
        for ((from, to, kind), count) in edge_counts {
            adj.entry(from).or_default().push((to, kind, count));
            incoming_sources.entry(to).or_default().insert(from);
        }
        let in_degree: HashMap<u64, usize> = incoming_sources
            .into_iter()
            .map(|(to, srcs)| (to, srcs.len()))
            .collect();
        Self {
            adj,
            in_degree,
            nodes,
            kinds: kinds.to_vec(),
        }
    }

    /// Total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.adj.values().map(std::vec::Vec::len).sum()
    }

    /// Neighbours of `addr` (nodes this node has edges to).
    #[must_use]
    pub fn successors(&self, addr: Address) -> Vec<Address> {
        self.adj
            .get(&addr.0)
            .map(|v| v.iter().map(|(to, _, _)| Address::new(*to)).collect())
            .unwrap_or_default()
    }

    /// Whether the graph contains `addr` as a node.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.nodes.contains(&addr.0)
    }

    /// BFS reachability: addresses reachable from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: Address) -> HashSet<Address> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start.0);
        visited.insert(start);
        while let Some(cur) = queue.pop_front() {
            if let Some(succs) = self.adj.get(&cur) {
                for (next, _, _) in succs {
                    let a = Address::new(*next);
                    if visited.insert(a) {
                        queue.push_back(*next);
                    }
                }
            }
        }
        visited
    }

    /// Whether `target` is reachable from `start` via the edges in this graph.
    #[must_use]
    pub fn is_reachable(&self, start: Address, target: Address) -> bool {
        if start == target {
            return true;
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start.0);
        visited.insert(start.0);
        while let Some(cur) = queue.pop_front() {
            if let Some(succs) = self.adj.get(&cur) {
                for (next, _, _) in succs {
                    if *next == target.0 {
                        return true;
                    }
                    if visited.insert(*next) {
                        queue.push_back(*next);
                    }
                }
            }
        }
        false
    }

    /// Strongly connected components via Tarjan's algorithm.
    /// Returns a list of SCCs (each an unordered set of `Address`), largest first.
    #[must_use]
    pub fn strongly_connected_components(&self) -> Vec<Vec<Address>> {
        struct LibTarjanState<'a> {
            nodes: &'a [u64],
            adj: &'a HashMap<u64, Vec<(u64, XrefKind, usize)>>,
            idx_map: &'a HashMap<u64, usize>,
            index_counter: usize,
            stack: Vec<usize>,
            on_stack: Vec<bool>,
            indices: Vec<usize>,
            lowlink: Vec<usize>,
            sccs: Vec<Vec<Address>>,
        }

        impl LibTarjanState<'_> {
            fn run(&mut self, root: usize) {
                // Iterative Tarjan with an explicit (node, next-successor-index)
                // work stack to avoid recursing once per node along long paths.
                let mut work: Vec<(usize, usize)> = vec![(root, 0)];
                while let Some(&mut (v, ref mut si)) = work.last_mut() {
                    if *si == 0 {
                        self.indices[v] = self.index_counter;
                        self.lowlink[v] = self.index_counter;
                        self.index_counter += 1;
                        self.stack.push(v);
                        self.on_stack[v] = true;
                    }

                    let node_addr = self.nodes[v];
                    let succs = self.adj.get(&node_addr).map_or(&[][..], Vec::as_slice);
                    let mut descended = false;
                    while *si < succs.len() {
                        let succ_addr = succs[*si].0;
                        *si += 1;
                        if let Some(&w) = self.idx_map.get(&succ_addr) {
                            if self.indices[w] == usize::MAX {
                                work.push((w, 0));
                                descended = true;
                                break;
                            } else if self.on_stack[w] {
                                self.lowlink[v] = self.lowlink[v].min(self.indices[w]);
                            }
                        }
                    }
                    if descended {
                        continue;
                    }

                    if self.lowlink[v] == self.indices[v] {
                        let mut scc = Vec::new();
                        loop {
                            let w = self.stack.pop().unwrap();
                            self.on_stack[w] = false;
                            scc.push(Address::new(self.nodes[w]));
                            if w == v { break; }
                        }
                        self.sccs.push(scc);
                    }

                    work.pop();
                    if let Some(&(parent, _)) = work.last() {
                        self.lowlink[parent] = self.lowlink[parent].min(self.lowlink[v]);
                    }
                }
            }
        }

        // Sort nodes so Tarjan's DFS visitation order (and therefore SCC
        // discovery order / node numbering) is deterministic across runs,
        // rather than depending on `HashSet` iteration order. Mirrors the
        // fix applied to `GlobalTarjanState` in `global_xref_analysis.rs`
        // for the same class of bug (order-dependent root/visit selection
        // over a bare hash-container iteration).
        let mut nodes: Vec<u64> = self.nodes.iter().copied().collect();
        nodes.sort_unstable();
        let idx_map: HashMap<u64, usize> = nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let n = nodes.len();

        let mut state = LibTarjanState {
            nodes: &nodes,
            adj: &self.adj,
            idx_map: &idx_map,
            index_counter: 0,
            stack: Vec::new(),
            on_stack: vec![false; n],
            indices: vec![usize::MAX; n],
            lowlink: vec![0usize; n],
            sccs: Vec::new(),
        };

        for i in 0..n {
            if state.indices[i] == usize::MAX {
                state.run(i);
            }
        }
        let mut sccs = state.sccs;

        sccs.sort_unstable_by_key(|b| std::cmp::Reverse(b.len()));
        sccs
    }

    /// BFS distance from `start` to all reachable nodes.
    /// Returns a map from `Address` to BFS depth.
    #[must_use]
    pub fn bfs_distances(&self, start: Address) -> HashMap<Address, usize> {
        let mut dist = HashMap::new();
        let mut queue = VecDeque::new();
        dist.insert(start, 0usize);
        queue.push_back((start.0, 0usize));
        while let Some((cur, d)) = queue.pop_front() {
            if let Some(succs) = self.adj.get(&cur) {
                for (next, _, _) in succs {
                    let a = Address::new(*next);
                    if let std::collections::hash_map::Entry::Vacant(e) = dist.entry(a) {
                        e.insert(d + 1);
                        queue.push_back((*next, d + 1));
                    }
                }
            }
        }
        dist
    }

    /// All nodes (as `Address`) in the graph.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<Address> {
        self.nodes.iter().map(|&a| Address::new(a)).collect()
    }

    /// In-degree of `addr` (how many nodes have an edge to it).
    #[must_use]
    pub fn in_degree(&self, addr: Address) -> usize {
        self.in_degree.get(&addr.0).copied().unwrap_or(0)
    }

    /// Out-degree of `addr` (how many edges leave it).
    #[must_use]
    pub fn out_degree(&self, addr: Address) -> usize {
        self.adj.get(&addr.0).map_or(0, std::vec::Vec::len)
    }

    /// Topological sort of the graph (Kahn's algorithm).
    /// Returns `None` if the graph has cycles.
    #[must_use]
    pub fn topological_sort(&self) -> Option<Vec<Address>> {
        let mut in_degree: HashMap<u64, usize> = HashMap::new();
        for &n in &self.nodes {
            in_degree.entry(n).or_insert(0);
        }
        for succs in self.adj.values() {
            for (to, _, _) in succs {
                *in_degree.entry(*to).or_insert(0) += 1;
            }
        }
        // Seed the queue in a deterministic (sorted) order: `in_degree` is a
        // `HashMap`, so iterating it directly would make the initial root
        // ordering — and therefore the resulting topological order whenever
        // more than one node has in-degree 0 — depend on hash iteration
        // order rather than on graph structure. Mirrors the HashMap-order
        // fixes already applied elsewhere in this crate.
        let mut roots: Vec<u64> = in_degree
            .iter()
            .filter(|&(_, d)| *d == 0)
            .map(|(&n, _)| n)
            .collect();
        roots.sort_unstable();
        let mut queue: VecDeque<u64> = roots.into_iter().collect();
        let mut sorted = Vec::new();
        while let Some(cur) = queue.pop_front() {
            sorted.push(Address::new(cur));
            if let Some(succs) = self.adj.get(&cur) {
                for (next, _, _) in succs {
                    let d = in_degree.entry(*next).or_insert(0);
                    *d = d.saturating_sub(1);
                    if *d == 0 {
                        queue.push_back(*next);
                    }
                }
            }
        }
        if sorted.len() == self.nodes.len() {
            Some(sorted)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// X86XrefScanner
// ---------------------------------------------------------------------------

/// Scans raw x86 / x86-64 byte slices and populates an [`XrefDatabase`].
pub struct X86XrefScanner {
    /// The address range that contains executable code.
    pub code_range: AddressRange,
    /// Additional data ranges (for filtering pointer targets).
    pub data_ranges: Vec<AddressRange>,
    /// 4 for 32-bit, 8 for 64-bit.
    pub pointer_size: usize,
    /// Whether to emit `DataAddress` xrefs for LEA/MOV-imm.
    pub scan_lea: bool,
    /// Whether to scan for thunk patterns (single JMP at function start).
    pub detect_thunks: bool,
    /// Known function-entry offsets relative to the `base` address passed to
    /// [`scan_code`].  An E9 (JMP rel32) whose byte offset from `base` matches
    /// one of these values will be classified as a [`ThunkCall`] rather than a
    /// plain [`CodeJump`].  When empty, thunk detection only fires at offset 0
    /// (legacy behaviour, suitable for per-function byte slices).
    pub function_entries: HashSet<u64>,
}

impl X86XrefScanner {
    /// Create a new scanner for the given code range and pointer width.
    #[must_use]
    pub fn new(code_range: AddressRange, pointer_size: usize) -> Self {
        Self {
            code_range,
            data_ranges: Vec::new(),
            pointer_size,
            scan_lea: true,
            detect_thunks: true,
            function_entries: HashSet::new(),
        }
    }

    /// Register a set of known function-entry offsets (relative to the `base`
    /// address used in [`scan_code`]).  E9 instructions at these offsets will
    /// be classified as thunk tail-calls instead of plain jumps.
    #[must_use]
    pub fn with_function_entries(mut self, entries: impl IntoIterator<Item = u64>) -> Self {
        self.function_entries.extend(entries);
        self
    }

    /// Add a data range whose pointers should be scanned.
    #[must_use]
    pub fn add_data_range(mut self, range: AddressRange) -> Self {
        self.data_ranges.push(range);
        self
    }

    /// Disable LEA/MOV-immediate scanning.
    #[must_use]
    pub const fn without_lea(mut self) -> Self {
        self.scan_lea = false;
        self
    }

    /// Disable thunk detection.
    #[must_use]
    pub const fn without_thunk_detection(mut self) -> Self {
        self.detect_thunks = false;
        self
    }

    fn is_known_address(&self, addr: u64) -> bool {
        let a = Address::new(addr);
        self.code_range.contains(a) || self.data_ranges.iter().any(|r| r.contains(a))
    }

    /// Scan a code byte slice starting at `base`, looking for CALL / JMP / LEA.
    pub fn scan_code(&self, base: Address, bytes: &[u8], db: &mut XrefDatabase) {
        let len = bytes.len();
        let mut i = 0usize;
        while i < len {
            let addr = base + i as u64;
            let remaining = &bytes[i..];
            match remaining[0] {
                0xE8 => {
                    self.try_call_rel32(addr, remaining, db);
                    i += 5;
                }
                0xE9 => {
                    // Classify as ThunkCall if thunk detection is enabled and
                    // the current offset is a known function-entry point.  When
                    // no function_entries are registered the legacy behaviour of
                    // triggering only at offset 0 is preserved (suitable for
                    // callers that pass per-function byte slices).
                    let is_entry = self.detect_thunks
                        && (self.function_entries.contains(&(i as u64))
                            || (self.function_entries.is_empty() && i == 0));
                    if is_entry {
                        self.try_thunk_rel32(addr, remaining, db);
                    } else {
                        self.try_jmp_rel32(addr, remaining, db);
                    }
                    i += 5;
                }
                0xEB | 0x70..=0x7F => {
                    self.try_jmp_short(addr, remaining, db);
                    i += 2;
                }
                0x0F if remaining.len() >= 6 && (0x80..=0x8F).contains(&remaining[1]) => {
                    // Jcc rel32 (0F 8x ...)
                    let rel = i32::from_le_bytes([
                        remaining[2],
                        remaining[3],
                        remaining[4],
                        remaining[5],
                    ]);
                    let target_raw = addr.0.cast_signed().wrapping_add(6).wrapping_add(i64::from(rel));
                    if target_raw > 0 {
                        let target = Address::new(target_raw.cast_unsigned());
                        if self.code_range.contains(target) {
                            db.add_jump(addr, target, 6);
                        }
                    }
                    i += 6;
                }
                0x8D if self.scan_lea && remaining.len() >= 6 => {
                    self.try_lea_imm(addr, remaining, db);
                    // 8D /r disp32 (mod=00, rm=101) is 6 bytes; skip the displacement
                    // so its bytes aren't re-decoded as opcodes.
                    i += if remaining[1] >> 6 == 0x00 && remaining[1] & 0x07 == 0x05 {
                        6
                    } else {
                        2
                    };
                }
                0xFF if remaining.len() >= 2 => {
                    // FF /2 = CALL r/m, FF /4 = JMP r/m — indirect
                    let modrm = remaining[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 2 {
                        // indirect CALL — we can't resolve target statically
                        i += 2;
                    } else if reg == 4 {
                        // indirect JMP
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }
    }

    /// Scan a data byte slice for pointer-sized values that point into the code range.
    pub fn scan_data_pointers(&self, base: Address, bytes: &[u8], db: &mut XrefDatabase) {
        let step = self.pointer_size;
        if step == 0 || bytes.len() < step {
            return;
        }
        let mut i = 0usize;
        while i + step <= bytes.len() {
            let ptr_val = if step == 4 {
                u64::from(u32::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                ]))
            } else {
                let n = step.min(8);
                let mut buf = [0u8; 8];
                buf[..n].copy_from_slice(&bytes[i..i + n]);
                u64::from_le_bytes(buf)
            };
            let target = Address::new(ptr_val);
            if self.code_range.contains(target) || self.is_known_address(ptr_val) {
                let from = base + i as u64;
                db.add_data_pointer(from, target);
            }
            i += step;
        }
    }

    fn try_call_rel32(&self, addr: Address, bytes: &[u8], db: &mut XrefDatabase) {
        if bytes.len() < 5 {
            return;
        }
        let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let target_raw = addr.0.cast_signed().wrapping_add(5).wrapping_add(i64::from(rel));
        if target_raw <= 0 {
            return;
        }
        let target = Address::new(target_raw.cast_unsigned());
        if self.code_range.contains(target) || self.is_known_address(target.0) {
            db.add_call(addr, target, 5);
        }
    }

    fn try_thunk_rel32(&self, addr: Address, bytes: &[u8], db: &mut XrefDatabase) {
        if bytes.len() < 5 {
            return;
        }
        let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let target_raw = addr.0.cast_signed().wrapping_add(5).wrapping_add(i64::from(rel));
        if target_raw <= 0 {
            return;
        }
        let target = Address::new(target_raw.cast_unsigned());
        if self.code_range.contains(target) {
            db.add_thunk(addr, target, 5);
        }
    }

    fn try_jmp_rel32(&self, addr: Address, bytes: &[u8], db: &mut XrefDatabase) {
        if bytes.len() < 5 {
            return;
        }
        let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let target_raw = addr.0.cast_signed().wrapping_add(5).wrapping_add(i64::from(rel));
        if target_raw <= 0 {
            return;
        }
        let target = Address::new(target_raw.cast_unsigned());
        if self.code_range.contains(target) {
            db.add_jump(addr, target, 5);
        }
    }

    fn try_jmp_short(&self, addr: Address, bytes: &[u8], db: &mut XrefDatabase) {
        if bytes.len() < 2 {
            return;
        }
        let rel = bytes[1].cast_signed();
        let target_raw = addr.0.cast_signed().wrapping_add(2).wrapping_add(i64::from(rel));
        if target_raw <= 0 {
            return;
        }
        let target = Address::new(target_raw.cast_unsigned());
        if self.code_range.contains(target) {
            db.add_jump(addr, target, 2);
        }
    }

    fn try_lea_imm(&self, addr: Address, bytes: &[u8], db: &mut XrefDatabase) {
        if bytes.len() < 6 {
            return;
        }
        let modrm = bytes[1];
        let modrm_mod = modrm >> 6;
        let modrm_rm = modrm & 0x07;
        // mod=00, rm=101: disp32 absolute (32-bit) or RIP+disp32 (64-bit)
        if modrm_mod == 0x00 && modrm_rm == 0x05 {
            let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let target_raw = if self.pointer_size == 8 {
                addr.0.cast_signed()
                    .wrapping_add(6)
                    .wrapping_add(i64::from(disp))
            } else {
                i64::from(disp)
            };
            if target_raw > 0 {
                let target = Address::new(target_raw.cast_unsigned());
                if self.code_range.contains(target) || self.is_known_address(target.0) {
                    db.add_data_addr(addr, target);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// XrefSummary — per-address summary
// ---------------------------------------------------------------------------

/// Summary of all xrefs involving a single address.
#[derive(Debug)]
pub struct XrefSummary {
    pub address: Address,
    pub total_in: usize,
    pub total_out: usize,
    pub call_in: usize,
    pub call_out: usize,
    pub jump_in: usize,
    pub jump_out: usize,
    pub data_in: usize,
    pub data_out: usize,
    pub import_in: usize,
    pub string_in: usize,
    pub type_in: usize,
}

impl XrefSummary {
    /// Compute the summary for `addr` from `db`.
    #[must_use]
    pub fn compute(db: &XrefDatabase, addr: Address) -> Self {
        let xrefs_in = db.xrefs_to(addr);
        let xrefs_out = db.xrefs_from(addr);

        let count_kind_in = |k: XrefKind| xrefs_in.iter().filter(|x| x.kind == k).count();
        let count_kind_out = |k: XrefKind| xrefs_out.iter().filter(|x| x.kind == k).count();
        let count_pred_in =
            |pred: fn(&XrefKind) -> bool| xrefs_in.iter().filter(|x| pred(&x.kind)).count();
        let count_pred_out =
            |pred: fn(&XrefKind) -> bool| xrefs_out.iter().filter(|x| pred(&x.kind)).count();

        Self {
            address: addr,
            total_in: xrefs_in.len(),
            total_out: xrefs_out.len(),
            call_in: count_kind_in(XrefKind::CodeCall),
            call_out: count_kind_out(XrefKind::CodeCall),
            jump_in: count_kind_in(XrefKind::CodeJump),
            jump_out: count_kind_out(XrefKind::CodeJump),
            data_in: count_pred_in(XrefKind::is_data),
            data_out: count_pred_out(XrefKind::is_data),
            import_in: count_pred_in(XrefKind::is_import),
            string_in: count_kind_in(XrefKind::StringRef),
            type_in: count_kind_in(XrefKind::TypeRef),
        }
    }

    /// Whether this address has no incoming references at all.
    #[must_use]
    pub const fn is_unreferenced(&self) -> bool {
        self.total_in == 0
    }

    /// Whether this address is a potential function entry (has call-in xrefs).
    #[must_use]
    pub const fn is_function_entry(&self) -> bool {
        self.call_in > 0
    }
}

// ---------------------------------------------------------------------------
// XrefStats
// ---------------------------------------------------------------------------

/// Aggregated statistics over an [`XrefDatabase`].
pub struct XrefStats {
    pub total: usize,
    /// Kind name -> count.
    pub by_kind: HashMap<String, usize>,
    pub unique_callers: usize,
    pub unique_callees: usize,
    pub leaf_functions: usize,
    /// Top 10 most-called functions.
    pub top_called: Vec<(Address, usize)>,
    pub total_imports: usize,
    pub total_strings: usize,
    pub total_types: usize,
    pub unique_import_names: usize,
}

impl XrefStats {
    /// Compute statistics from the given database.
    #[must_use]
    pub fn compute(db: &XrefDatabase) -> Self {
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        let mut call_sources: HashSet<u64> = HashSet::new();
        let mut call_targets: HashSet<u64> = HashSet::new();
        let mut import_count = 0usize;
        let mut string_count = 0usize;
        let mut type_count = 0usize;

        for xref in db.iter_all() {
            *by_kind.entry(xref.kind.to_string()).or_insert(0) += 1;
            if xref.kind == XrefKind::CodeCall {
                call_sources.insert(xref.from.0);
                call_targets.insert(xref.to.0);
            }
            if xref.kind.is_import() {
                import_count += 1;
            }
            if xref.kind == XrefKind::StringRef {
                string_count += 1;
            }
            if xref.kind == XrefKind::TypeRef {
                type_count += 1;
            }
        }

        let leaf_functions = call_targets
            .iter()
            .filter(|&&addr| db.is_leaf_function(Address::new(addr)))
            .count();

        let top_called = db.hot_functions(10);
        let unique_import_names = db.import_refs.len();

        Self {
            total: db.total_count(),
            by_kind,
            unique_callers: call_sources.len(),
            unique_callees: call_targets.len(),
            leaf_functions,
            top_called,
            total_imports: import_count,
            total_strings: string_count,
            total_types: type_count,
            unique_import_names,
        }
    }

    /// Display a human-readable summary.
    #[must_use]
    pub fn format_report(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Total xrefs  : {}", self.total);
        let _ = writeln!(s, "Call targets : {} (leaf: {})", self.unique_callees, self.leaf_functions);
        let _ = writeln!(s, "Callers      : {}", self.unique_callers);
        let _ = writeln!(s, "Imports      : {} ({} unique names)", self.total_imports, self.unique_import_names);
        let _ = writeln!(s, "String refs  : {}", self.total_strings);
        let _ = writeln!(s, "Type refs    : {}", self.total_types);
        s.push_str("By kind:\n");
        let mut kinds: Vec<(&String, &usize)> = self.by_kind.iter().collect();
        kinds.sort_unstable_by_key(|(k, _)| k.as_str());
        for (kind, count) in kinds {
            let _ = writeln!(s, "  {kind:20} {count}");
        }
        if !self.top_called.is_empty() {
            s.push_str("Top called:\n");
            for (addr, count) in &self.top_called {
                let _ = writeln!(s, "  {:#010x}  {} calls", addr.0, count);
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// XrefDiff — diff two databases
// ---------------------------------------------------------------------------

/// The result of comparing two [`XrefDatabase`] instances.
pub struct XrefDiff {
    /// Xrefs present in `b` but not in `a`.
    pub added: Vec<Xref>,
    /// Xrefs present in `a` but not in `b`.
    pub removed: Vec<Xref>,
}

impl XrefDiff {
    /// Compute the diff between two databases (based on from/to/kind identity).
    #[must_use]
    pub fn compute(a: &XrefDatabase, b: &XrefDatabase) -> Self {
        let a_set: HashSet<(u64, u64, XrefKind)> =
            a.iter_all().map(|x| (x.from.0, x.to.0, x.kind)).collect();
        let b_set: HashSet<(u64, u64, XrefKind)> =
            b.iter_all().map(|x| (x.from.0, x.to.0, x.kind)).collect();

        let added = b
            .iter_all()
            .filter(|x| !a_set.contains(&(x.from.0, x.to.0, x.kind)))
            .cloned()
            .collect();
        let removed = a
            .iter_all()
            .filter(|x| !b_set.contains(&(x.from.0, x.to.0, x.kind)))
            .cloned()
            .collect();

        Self { added, removed }
    }

    /// Number of changes (added + removed).
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len()
    }

    /// Whether there are no differences.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StringXrefScanner — scan binary for string references
// ---------------------------------------------------------------------------

/// Scans a binary for string literals and records xrefs to code that references them.
pub struct StringXrefScanner {
    /// Minimum string length to record.
    pub min_length: usize,
    /// If `true`, scan for UTF-16LE strings as well.
    pub scan_utf16: bool,
}

impl StringXrefScanner {
    /// Create a scanner with the given minimum string length.
    #[must_use]
    pub const fn new(min_length: usize) -> Self {
        Self {
            min_length,
            scan_utf16: false,
        }
    }

    /// Enable UTF-16LE string scanning.
    #[must_use]
    pub const fn with_utf16(mut self) -> Self {
        self.scan_utf16 = true;
        self
    }

    /// Scan a data section for null-terminated ASCII strings. Returns (address, string) pairs.
    #[must_use]
    pub fn scan_ascii(&self, base: Address, data: &[u8]) -> Vec<(Address, String)> {
        let mut results = Vec::new();
        let mut start = None;
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                if start.is_none() {
                    start = Some(i);
                }
            } else if b == 0 {
                if let Some(s) = start.take() {
                    let len = i - s;
                    if len >= self.min_length
                        && let Ok(text) = std::str::from_utf8(&data[s..i]) {
                            results.push((base + s as u64, text.to_owned()));
                        }
                }
            } else {
                start = None;
            }
        }
        results
    }

    /// Scan a data section for null-terminated UTF-16LE strings.
    #[must_use]
    pub fn scan_utf16le(&self, base: Address, data: &[u8]) -> Vec<(Address, String)> {
        if !self.scan_utf16 || data.len() < 4 {
            return Vec::new();
        }
        let mut results = Vec::new();
        let mut i = 0usize;
        while i + 1 < data.len() {
            let ch = u16::from_le_bytes([data[i], data[i + 1]]);
            if (0x20..=0x7E).contains(&ch) {
                let start = i;
                let mut chars = Vec::new();
                while i + 1 < data.len() {
                    let c = u16::from_le_bytes([data[i], data[i + 1]]);
                    if c == 0 {
                        i += 2;
                        break;
                    }
                    if c < 0x20 && c != 9 && c != 10 && c != 13 {
                        break;
                    }
                    chars.push(c);
                    i += 2;
                }
                if chars.len() >= self.min_length {
                    let text = String::from_utf16_lossy(&chars);
                    results.push((base + start as u64, text));
                }
                continue;
            }
            i += 2;
        }
        results
    }

    /// Find all string xrefs: given the xref database (which has data-address refs), look up
    /// which code addresses reference each known string.
    #[must_use]
    pub fn find_string_refs<'a>(
        &self,
        db: &'a XrefDatabase,
        strings: &[(Address, String)],
    ) -> Vec<(Address, &'a [Xref])> {
        strings
            .iter()
            .map(|(addr, _)| (*addr, db.xrefs_to(*addr)))
            .filter(|(_, refs)| !refs.is_empty())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ImportXrefScanner — record import table entries
// ---------------------------------------------------------------------------

/// Records import-table entries as xrefs into the database.
pub struct ImportXrefScanner {
    /// Base address of the import address table (IAT).
    pub iat_base: Address,
    /// Pointer size (4 or 8).
    pub pointer_size: usize,
}

impl ImportXrefScanner {
    /// Create a new import scanner.
    #[must_use]
    pub const fn new(iat_base: Address, pointer_size: usize) -> Self {
        Self {
            iat_base,
            pointer_size,
        }
    }

    /// Record a named import at `thunk_addr` that calls into `target`.
    pub fn record_named_import(
        &self,
        db: &mut XrefDatabase,
        thunk_addr: Address,
        target: Address,
        name: impl Into<String>,
    ) {
        db.add_import_by_name(thunk_addr, target, name);
    }

    /// Record an ordinal import.
    pub fn record_ordinal_import(
        &self,
        db: &mut XrefDatabase,
        thunk_addr: Address,
        target: Address,
        ordinal: u32,
    ) {
        db.add_import_by_ordinal(thunk_addr, target, ordinal);
    }

    /// Scan an IAT byte slice, producing data-pointer xrefs at each slot.
    pub fn scan_iat(&self, bytes: &[u8], db: &mut XrefDatabase) {
        let step = self.pointer_size;
        if step == 0 || bytes.len() < step {
            return;
        }
        let mut i = 0usize;
        while i + step <= bytes.len() {
            let ptr_val = if step == 4 {
                u64::from(u32::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                ]))
            } else {
                u64::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                    bytes[i + 6],
                    bytes[i + 7],
                ])
            };
            if ptr_val != 0 {
                let slot = self.iat_base + i as u64;
                db.add_data_pointer(slot, Address::new(ptr_val));
            }
            i += step;
        }
    }
}

// ---------------------------------------------------------------------------
// XrefGrouper — group xrefs by region / function
// ---------------------------------------------------------------------------

/// Groups xrefs by which function (or region) they originate from.
pub struct XrefGrouper {
    /// Sorted list of function starts. The grouper assigns each from-address to the nearest start.
    function_starts: Vec<u64>,
}

impl XrefGrouper {
    /// Create a grouper from a sorted list of function start addresses.
    #[must_use]
    pub fn new(mut starts: Vec<Address>) -> Self {
        starts.sort_unstable_by_key(|a| a.0);
        Self {
            function_starts: starts.iter().map(|a| a.0).collect(),
        }
    }

    /// Find the enclosing function start for `addr`, or `None` if before all known starts.
    #[must_use]
    pub fn enclosing_function(&self, addr: Address) -> Option<Address> {
        match self.function_starts.binary_search(&addr.0) {
            Ok(i) => Some(Address::new(self.function_starts[i])),
            Err(0) => None,
            Err(i) => Some(Address::new(self.function_starts[i - 1])),
        }
    }

    /// Group all xrefs in `db` by enclosing function start.
    /// Returns a map from function start address to the xrefs whose `from` is in that function.
    #[must_use]
    pub fn group_by_function<'a>(&self, db: &'a XrefDatabase) -> HashMap<Address, Vec<&'a Xref>> {
        let mut groups: HashMap<Address, Vec<&Xref>> = HashMap::new();
        for xref in db.iter_all() {
            if let Some(func) = self.enclosing_function(xref.from) {
                groups.entry(func).or_default().push(xref);
            }
        }
        // `db.iter_all()` walks a `HashMap` internally, so the order xrefs are
        // pushed into each group's `Vec` is not stable across runs. Sort each
        // group's entries by (from, to) so the per-group order is
        // deterministic regardless of the top-level `HashMap`'s own order.
        for v in groups.values_mut() {
            v.sort_by_key(|a| (a.from.0, a.to.0));
        }
        groups
    }

    /// Return functions that call each other (mutual callers) as pairs.
    #[must_use]
    pub fn mutual_callers(&self, db: &XrefDatabase) -> Vec<(Address, Address)> {
        let mut pairs = Vec::new();
        for xref in db.iter_all() {
            if xref.kind != XrefKind::CodeCall {
                continue;
            }
            let from_fn = self.enclosing_function(xref.from);
            let to_fn = self.enclosing_function(xref.to);
            if let (Some(f), Some(t)) = (from_fn, to_fn)
                && f != t
                    && db
                        .callers_of(xref.from)
                        .iter()
                        .any(|&c| self.enclosing_function(c) == Some(t))
                {
                    pairs.push((f, t));
                }
        }
        pairs.sort_unstable_by_key(|(a, b)| (a.0, b.0));
        pairs.dedup();
        pairs
    }
}

// ---------------------------------------------------------------------------
// SimpleXrefKind — lightweight enum for XrefIndex
// ---------------------------------------------------------------------------

/// A simplified cross-reference kind used by `BinaryXrefIndex` and `build_from_binary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimpleXrefKind {
    /// Direct or indirect CALL instruction.
    Call,
    /// JMP / branch instruction (conditional or unconditional).
    Jump,
    /// Data is read from this address (LEA / MOV load).
    DataRead,
    /// Data is written to this address.
    DataWrite,
    /// Address-of reference (address taken but not dereferenced).
    DataAddr,
}

impl fmt::Display for SimpleXrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call => "Call",
            Self::Jump => "Jump",
            Self::DataRead => "DataRead",
            Self::DataWrite => "DataWrite",
            Self::DataAddr => "DataAddr",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// SimpleXref — a single record in an XrefIndex
// ---------------------------------------------------------------------------

/// A lightweight cross-reference record used by `BinaryXrefIndex`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleXref {
    /// Address of the instruction that generates the reference.
    pub from: u64,
    /// Target address referenced by the instruction.
    pub to: u64,
    /// The nature of the reference.
    pub kind: SimpleXrefKind,
    /// Byte length of the instruction at `from` (0 = unknown).
    pub instr_len: u8,
}

impl SimpleXref {
    /// Construct a new `SimpleXref`.
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: SimpleXrefKind, instr_len: u8) -> Self {
        Self {
            from,
            to,
            kind,
            instr_len,
        }
    }
}

// ---------------------------------------------------------------------------
// XrefIndex — compact bidirectional xref store
// ---------------------------------------------------------------------------

/// A compact, bidirectional cross-reference index.
///
/// Internally keeps two `HashMap<u64, Vec<SimpleXref>>` tables: one indexed
/// by the *source* address and one by the *target* address, enabling O(1)
/// average lookup in both directions.
///
/// Build from raw binary bytes with [`BinaryXrefIndex::build_from_binary`], or
/// populate programmatically with the `add_*` methods.
#[derive(Debug, Default)]
pub struct BinaryXrefIndex {
    /// Source address → xrefs originating there.
    from_map: HashMap<u64, Vec<SimpleXref>>,
    /// Target address → xrefs pointing there.
    to_map: HashMap<u64, Vec<SimpleXref>>,
}

impl BinaryXrefIndex {
    /// Create an empty `BinaryXrefIndex`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Population helpers ─────────────────────────────────────────────────

    /// Insert a `SimpleXref` into both direction maps.
    pub fn add(&mut self, xref: SimpleXref) {
        self.from_map
            .entry(xref.from)
            .or_default()
            .push(xref.clone());
        self.to_map.entry(xref.to).or_default().push(xref);
    }

    /// Record a CALL xref from `from` to `to`.
    pub fn add_call(&mut self, from: u64, to: u64, instr_len: u8) {
        self.add(SimpleXref::new(from, to, SimpleXrefKind::Call, instr_len));
    }

    /// Record a JMP xref from `from` to `to`.
    pub fn add_jump(&mut self, from: u64, to: u64, instr_len: u8) {
        self.add(SimpleXref::new(from, to, SimpleXrefKind::Jump, instr_len));
    }

    /// Record a data-read xref (e.g., a MOV load from an immediate address).
    pub fn add_data_read(&mut self, from: u64, to: u64) {
        self.add(SimpleXref::new(from, to, SimpleXrefKind::DataRead, 0));
    }

    /// Record a data-write xref.
    pub fn add_data_write(&mut self, from: u64, to: u64) {
        self.add(SimpleXref::new(from, to, SimpleXrefKind::DataWrite, 0));
    }

    /// Record a data-address (LEA / address-of) xref.
    pub fn add_data_addr(&mut self, from: u64, to: u64) {
        self.add(SimpleXref::new(from, to, SimpleXrefKind::DataAddr, 0));
    }

    // ── Lookup API ─────────────────────────────────────────────────────────

    /// All xrefs originating at `addr`.
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> &[SimpleXref] {
        self.from_map.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// All xrefs whose target is `addr`.
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> &[SimpleXref] {
        self.to_map.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// Addresses of all CALL instructions that call `addr` (call-sites).
    #[must_use]
    pub fn callers_of(&self, addr: u64) -> Vec<u64> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| x.kind == SimpleXrefKind::Call)
            .map(|x| x.from)
            .collect()
    }

    /// Addresses that `addr` calls (direct call targets of instructions at `addr`).
    ///
    /// Note: all call xrefs whose `from` field equals `addr` (not the function
    /// entry — use a range query when the function spans multiple addresses).
    #[must_use]
    pub fn callees_of(&self, addr: u64) -> Vec<u64> {
        self.xrefs_from(addr)
            .iter()
            .filter(|x| x.kind == SimpleXrefKind::Call)
            .map(|x| x.to)
            .collect()
    }

    /// Addresses of instructions that read / write / take the address of `addr`.
    #[must_use]
    pub fn data_refs_to(&self, addr: u64) -> Vec<u64> {
        self.xrefs_to(addr)
            .iter()
            .filter(|x| {
                matches!(
                    x.kind,
                    SimpleXrefKind::DataRead | SimpleXrefKind::DataWrite | SimpleXrefKind::DataAddr
                )
            })
            .map(|x| x.from)
            .collect()
    }

    /// Total number of xref records stored.
    #[must_use]
    pub fn total(&self) -> usize {
        self.from_map.values().map(std::vec::Vec::len).sum()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.from_map.is_empty()
    }

    /// All unique source addresses, sorted ascending for deterministic output
    /// (`from_map` is a `HashMap`; its iteration order is not stable across
    /// runs).
    #[must_use]
    pub fn all_sources(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.from_map.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// All unique target addresses, sorted ascending for deterministic output
    /// (`to_map` is a `HashMap`; its iteration order is not stable across
    /// runs).
    #[must_use]
    pub fn all_targets(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.to_map.keys().copied().collect();
        v.sort_unstable();
        v
    }

    // ── Binary scanner ─────────────────────────────────────────────────────

    /// Read a little-endian `i32` displacement from `code` at `at`.
    fn rel32(code: &[u8], at: usize) -> i32 {
        i32::from_le_bytes([code[at], code[at + 1], code[at + 2], code[at + 3]])
    }

    /// Build a `BinaryXrefIndex` by scanning `code` for x86/x86-64 CALL, JMP, and
    /// LEA instructions.
    ///
    /// * `base`  — virtual address of the first byte in `code`.
    /// * `arch`  — `"x86"` (32-bit) or `"x86_64"` (64-bit); any other value
    ///   is treated as `"x86_64"`.
    ///
    /// The scanner recognises:
    /// * `E8 rel32` — near CALL (relative 32-bit).
    /// * `FF /2`    — indirect CALL through r/m (target not resolved statically).
    /// * `E9 rel32` — near JMP (relative 32-bit).
    /// * `EB rel8`  — short JMP (relative 8-bit).
    /// * `70–7F rel8`, `0F 8x rel32` — conditional jumps.
    /// * `8D /r` with `mod=00, rm=101` — LEA r, [RIP + disp32] (data-addr xref).
    /// * `48 8D` / `4C 8D` (REX + LEA) — likewise on x86-64.
    #[must_use]
    pub fn build_from_binary(code: &[u8], base: u64, arch: &str) -> Self {
        let mut idx = Self::new();
        let is_64 = arch != "x86";
        let len = code.len();
        let mut i = 0usize;

        while i < len {
            let addr = base.wrapping_add(i as u64);
            // Handle REX prefix on x86-64 (40–4F).
            let (rex, start) = if is_64 && code[i] >= 0x40 && code[i] <= 0x4F && i + 1 < len {
                (code[i], i + 1)
            } else {
                (0u8, i)
            };
            let _ = rex; // rex would be used for further decoding if needed

            if start >= len {
                i += 1;
                continue;
            }

            match code[start] {
                // ── E8: CALL rel32 ─────────────────────────────────────────
                0xE8 if start + 4 < len => {
                    let rel = Self::rel32(code, start + 1);
                    let instr_end = base.wrapping_add(start as u64).wrapping_add(5);
                    let target = instr_end.cast_signed().wrapping_add(i64::from(rel)).cast_unsigned();
                    let instr_len = u8::try_from(start - i + 5).unwrap_or(u8::MAX);
                    idx.add_call(addr, target, instr_len);
                    i = start + 5;
                }

                // ── FF /2: indirect CALL (target unknown statically) ───────
                // We record it as a call from `addr` to 0 (unknown target).
                0xFF if start + 1 < len => {
                    let modrm = code[start + 1];
                    let reg = (modrm >> 3) & 0x07;
                    match reg {
                        2 => {
                            // CALL r/m — we cannot resolve without register values.
                            // Emit a placeholder xref to address 0 so callers know
                            // that an indirect call exists here.
                            idx.add_call(addr, 0, u8::try_from(start - i + 2).unwrap_or(u8::MAX));
                            i = start + 2;
                        }
                        4 => {
                            // JMP r/m — same reasoning.
                            idx.add_jump(addr, 0, u8::try_from(start - i + 2).unwrap_or(u8::MAX));
                            i = start + 2;
                        }
                        _ => {
                            i = start + 1;
                        }
                    }
                }

                // ── E9: JMP rel32 ──────────────────────────────────────────
                0xE9 if start + 4 < len => {
                    let rel = Self::rel32(code, start + 1);
                    let instr_end = base.wrapping_add(start as u64).wrapping_add(5);
                    let target = instr_end.cast_signed().wrapping_add(i64::from(rel)).cast_unsigned();
                    let instr_len = u8::try_from(start - i + 5).unwrap_or(u8::MAX);
                    idx.add_jump(addr, target, instr_len);
                    i = start + 5;
                }

                // ── EB / 70–7F: short jumps (rel8) ────────────────────────
                0xEB | 0x70..=0x7F if start + 1 < len => {
                    let rel = code[start + 1].cast_signed();
                    let instr_end = base.wrapping_add(start as u64).wrapping_add(2);
                    let target = instr_end.cast_signed().wrapping_add(i64::from(rel)).cast_unsigned();
                    let instr_len = u8::try_from(start - i + 2).unwrap_or(u8::MAX);
                    idx.add_jump(addr, target, instr_len);
                    i = start + 2;
                }

                // ── 0F 8x: Jcc near (rel32) ───────────────────────────────
                0x0F if start + 5 < len && (0x80..=0x8F).contains(&code[start + 1]) => {
                    let rel = Self::rel32(code, start + 2);
                    let instr_end = base.wrapping_add(start as u64).wrapping_add(6);
                    let target = instr_end.cast_signed().wrapping_add(i64::from(rel)).cast_unsigned();
                    let instr_len = u8::try_from(start - i + 6).unwrap_or(u8::MAX);
                    idx.add_jump(addr, target, instr_len);
                    i = start + 6;
                }

                // ── 8D: LEA (RIP-relative on x86-64) ──────────────────────
                0x8D if is_64 && start + 5 < len => {
                    let modrm = code[start + 1];
                    let mod_ = modrm >> 6;
                    let rm = modrm & 0x07;
                    // mod=00, rm=101: RIP+disp32
                    if mod_ == 0x00 && rm == 0x05 {
                        let disp = Self::rel32(code, start + 2);
                        let instr_end = base.wrapping_add(start as u64).wrapping_add(6);
                        let target = instr_end.cast_signed().wrapping_add(i64::from(disp)).cast_unsigned();
                        idx.add_data_addr(addr, target);
                    }
                    i = start + 2;
                }

                _ => {
                    i = start + 1;
                }
            }
        }

        idx
    }

    // ── Statistics ─────────────────────────────────────────────────────────

    /// Count xrefs of a specific kind.
    #[must_use]
    pub fn count_kind(&self, kind: SimpleXrefKind) -> usize {
        self.from_map
            .values()
            .flat_map(|v| v.iter())
            .filter(|x| x.kind == kind)
            .count()
    }

    /// Returns the `top_n` most-called addresses (most call xrefs to them).
    #[must_use]
    pub fn hot_call_targets(&self, top_n: usize) -> Vec<(u64, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for xref in self.to_map.values().flat_map(|v| v.iter()) {
            if xref.kind == SimpleXrefKind::Call {
                *counts.entry(xref.to).or_insert(0) += 1;
            }
        }
        let mut list: Vec<(u64, usize)> = counts.into_iter().collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        list.truncate(top_n);
        list
    }

    /// Whether `addr` has no outgoing CALL xrefs **recorded in this index**
    /// (leaf-function heuristic).
    ///
    /// ⚠ An address the analysis never visited answers `true` here too — the
    /// index stores xrefs, not coverage. Pair with [`Self::has_any_xrefs`] to
    /// tell a genuine leaf from an unexamined address.
    #[must_use]
    pub fn is_leaf(&self, addr: u64) -> bool {
        self.callees_of(addr).is_empty()
    }

    /// Whether this index mentions `addr` at all, as source or target.
    ///
    /// See [`Self::is_leaf`] for why that distinction matters.
    #[must_use]
    pub fn has_any_xrefs(&self, addr: u64) -> bool {
        self.from_map.contains_key(&addr) || self.to_map.contains_key(&addr)
    }

    /// Root functions of the static call graph: function entries that have
    /// **zero** incoming `Call` xrefs in this index.
    ///
    /// Roots are the natural starting points for top-down call-graph traversal
    /// (entry points, exported APIs, thread-procs). Note the heuristic only
    /// observes *direct* calls — functions reached exclusively via indirect
    /// `FF /2` dispatch will appear as roots even when they are conceptually
    /// callees.
    #[must_use]
    pub fn root_functions(&self, function_entries: &[u64]) -> Vec<u64> {
        let mut roots: Vec<u64> = function_entries
            .iter()
            .copied()
            .filter(|entry| {
                !self
                    .xrefs_to(*entry)
                    .iter()
                    .any(|x| x.kind == SimpleXrefKind::Call)
            })
            .collect();
        roots.sort_unstable();
        roots.dedup();
        roots
    }

    /// Count incoming references to each address in `string_addrs`.
    ///
    /// For every requested string base address this returns the number of
    /// xrefs (any kind) whose `to` field equals that address. Intended for
    /// "how often is this literal touched?" reports over already-discovered
    /// string locations.
    #[must_use]
    pub fn count_string_refs(
        &self,
        string_addrs: impl IntoIterator<Item = u64>,
    ) -> HashMap<u64, usize> {
        string_addrs
            .into_iter()
            .map(|addr| (addr, self.xrefs_to(addr).len()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// XrefRecoveryPass — AnalysisPass implementation
// ---------------------------------------------------------------------------

/// An [`rustre_analysis::AnalysisPass`] that scans every executable segment
///
/// of a [`BinaryView`] for x86/x86-64 CALL and JMP instructions and records
/// the discovered cross-references in a [`BinaryXrefIndex`].
///
/// After [`run`](rustre_analysis::AnalysisPass::run) completes the results are
/// stored inside the pass itself and can be retrieved via
/// [`XrefRecoveryPass::index`].
pub struct XrefRecoveryPass {
    index: parking_lot::Mutex<BinaryXrefIndex>,
}

impl XrefRecoveryPass {
    /// Create a new, empty `XrefRecoveryPass`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: parking_lot::Mutex::new(BinaryXrefIndex::new()),
        }
    }

    /// Access the cross-reference index built by the last [`run`] call.
    pub fn index(&self) -> parking_lot::MutexGuard<'_, BinaryXrefIndex> {
        self.index.lock()
    }
}

impl Default for XrefRecoveryPass {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for XrefRecoveryPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XrefRecoveryPass")
            .field("xref_count", &self.index.lock().total())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for XrefRecoveryPass {
    fn name(&self) -> &'static str {
        "xref_recovery"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::XrefRecovery
    }

    fn description(&self) -> &'static str {
        "Scans executable segments for CALL/JMP xrefs using a byte-level x86/x86-64 scanner"
    }

    fn priority(&self) -> i32 {
        10
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        use rustre_core::permissions::Permissions;

        let start_time = std::time::Instant::now();
        let mut new_index = BinaryXrefIndex::new();

        let arch_name = view.arch.name().to_lowercase();
        let arch = if arch_name.contains("x86_64")
            || arch_name.contains("amd64")
            || arch_name.contains("x64")
        {
            "x86_64"
        } else {
            "x86"
        };

        // Scan each executable segment.
        {
            let mem = view.mem.read();
            for seg in &mem.segments {
                if !seg.permissions.contains(Permissions::EXECUTE) {
                    continue;
                }
                let base = seg.range.start.0;
                let partial = BinaryXrefIndex::build_from_binary(&seg.data, base, arch);
                // Merge partial results.
                for xref in partial.all_sources() {
                    for x in partial.xrefs_from(xref) {
                        new_index.add(x.clone());
                    }
                }
            }
        }

        let data_refs_found = new_index.count_kind(SimpleXrefKind::DataRead)
            + new_index.count_kind(SimpleXrefKind::DataWrite)
            + new_index.count_kind(SimpleXrefKind::DataAddr);
        let calls_found = new_index.count_kind(SimpleXrefKind::Call);
        let duration_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);

        *self.index.lock() = new_index;

        Ok(rustre_analysis::AnalysisResult {
            kind: rustre_analysis::AnalysisKind::XrefRecovery,
            functions_found: 0,
            data_refs_found: data_refs_found + calls_found,
            strings_found: 0,
            duration_ms,
            warnings: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn range(start: u64, end: u64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    // Regression: all_targets/all_sources/all_strings/all_import_names must
    // be sorted and deterministic across repeated calls (previously leaked
    // HashMap/HashSet iteration order).
    #[test]
    fn test_all_targets_sources_strings_imports_deterministic() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x3000), addr(0x1000), 5);
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x4000), 5);
        db.add_string_ref(addr(0x1000), addr(0x5000), "zeta");
        db.add_string_ref(addr(0x1010), addr(0x5010), "alpha");
        db.add_string_ref(addr(0x1020), addr(0x5020), "mid");
        db.add_import_by_name(addr(0x1000), addr(0x6000), "Zeta32");
        db.add_import_by_name(addr(0x1010), addr(0x6010), "Alpha32");

        let targets1 = db.all_targets();
        let sources1 = db.all_sources();
        let strings1 = db.all_strings();
        let imports1 = db.all_import_names();
        for _ in 0..5 {
            assert_eq!(db.all_targets(), targets1);
            assert_eq!(db.all_sources(), sources1);
            assert_eq!(db.all_strings(), strings1);
            assert_eq!(db.all_import_names(), imports1);
        }
        let mut sorted_targets = targets1.clone();
        sorted_targets.sort_unstable();
        assert_eq!(targets1, sorted_targets);
        let mut sorted_strings = strings1.clone();
        sorted_strings.sort_unstable();
        assert_eq!(strings1, sorted_strings);
    }

    // 1. add_call and callers_of
    #[test]
    fn test_add_call_and_callers() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1005), addr(0x2000), 5);
        db.add_call(addr(0x3000), addr(0x4000), 5);

        let callers = db.callers_of(addr(0x2000));
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&addr(0x1000)));
        assert!(callers.contains(&addr(0x1005)));
        assert_eq!(db.callers_of(addr(0x4000)).len(), 1);
        assert_eq!(db.callers_of(addr(0xDEAD)).len(), 0);
    }

    // 2. callees_of and callee_count deduplication
    #[test]
    fn test_callees_of() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1000), addr(0x3000), 5);
        db.add_call(addr(0x1000), addr(0x2000), 5); // duplicate target

        let callees = db.callees_of(addr(0x1000));
        assert_eq!(callees.len(), 3); // raw storage preserves duplicates
        assert_eq!(db.callee_count(addr(0x1000)), 2); // deduplication
    }

    // 3. add_jump and jumpers_to
    #[test]
    fn test_add_jump_and_jumpers() {
        let mut db = XrefDatabase::new();
        db.add_jump(addr(0x1010), addr(0x1020), 2);
        db.add_jump(addr(0x1030), addr(0x1020), 5);

        let jumpers = db.jumpers_to(addr(0x1020));
        assert_eq!(jumpers.len(), 2);
        assert!(jumpers.contains(&addr(0x1010)));
        assert!(jumpers.contains(&addr(0x1030)));
    }

    // 4. data_refs_to covers all data kinds
    #[test]
    fn test_data_refs_to() {
        let mut db = XrefDatabase::new();
        db.add_data_read(addr(0x1000), addr(0x5000));
        db.add_data_write(addr(0x1010), addr(0x5000));
        db.add_data_addr(addr(0x1020), addr(0x5000));
        db.add_data_pointer(addr(0x6000), addr(0x5000));
        db.add_call(addr(0x1030), addr(0x5000), 5); // not a data ref

        let refs = db.data_refs_to(addr(0x5000));
        assert_eq!(refs.len(), 4);
    }

    // 5. remove_from
    #[test]
    fn test_remove_from() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1000), addr(0x3000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);

        assert_eq!(db.total_count(), 3);
        let removed = db.remove_from(addr(0x1000));
        assert_eq!(removed, 2);
        assert_eq!(db.total_count(), 1);
        assert!(db.xrefs_from(addr(0x1000)).is_empty());
        assert_eq!(db.callers_of(addr(0x2000)).len(), 1);
    }

    // 6. remove_to
    #[test]
    fn test_remove_to() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x3000), 5);

        let removed = db.remove_to(addr(0x2000));
        assert_eq!(removed, 2);
        assert_eq!(db.total_count(), 1);
        assert!(db.callers_of(addr(0x2000)).is_empty());
        assert_eq!(db.callees_of(addr(0x1010)).len(), 1);
    }

    // 7. is_leaf_function
    #[test]
    fn test_is_leaf_function() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        assert!(db.is_leaf_function(addr(0x2000)));
        assert!(!db.is_leaf_function(addr(0x1000)));
        assert!(db.is_leaf_function(addr(0xDEAD)));
    }

    // 8. hot_functions top-N
    #[test]
    fn test_hot_functions() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);
        db.add_call(addr(0x1020), addr(0x2000), 5);
        db.add_call(addr(0x1000), addr(0x3000), 5);

        let hot = db.hot_functions(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, addr(0x2000));
        assert_eq!(hot[0].1, 3);

        let hot2 = db.hot_functions(5);
        assert_eq!(hot2.len(), 2);
    }

    // 9. caller_count deduplication
    #[test]
    fn test_caller_count() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x5000), 5);
        db.add_call(addr(0x1000), addr(0x5000), 5); // same caller twice
        db.add_call(addr(0x2000), addr(0x5000), 5);
        assert_eq!(db.caller_count(addr(0x5000)), 2);
    }

    // 10. X86XrefScanner: CALL rel32 (E8)
    #[test]
    fn test_scanner_call_rel32() {
        let code_range = range(0x1000, 0x2000);
        let scanner = X86XrefScanner::new(code_range, 8);
        let rel: i32 = 0x1100_i64.wrapping_sub(0x1005_i64) as i32;
        let rel_bytes = rel.to_le_bytes();
        let mut bytes = vec![0u8; 10];
        bytes[0] = 0xE8;
        bytes[1..5].copy_from_slice(&rel_bytes);

        let mut db = XrefDatabase::new();
        scanner.scan_code(addr(0x1000), &bytes, &mut db);

        let xrefs = db.xrefs_from(addr(0x1000));
        let call = xrefs.iter().find(|x| x.kind == XrefKind::CodeCall).unwrap();
        assert_eq!(call.to, addr(0x1100));
        assert_eq!(call.instr_size, 5);
    }

    // 11. X86XrefScanner: JMP rel32 (E9)
    #[test]
    fn test_scanner_jmp_rel32() {
        let code_range = range(0x1000, 0x2000);
        let scanner = X86XrefScanner::new(code_range, 8);
        let rel: i32 = 0x1050_i64.wrapping_sub(0x1005_i64) as i32;
        let rel_bytes = rel.to_le_bytes();
        let mut bytes = vec![0u8; 10];
        bytes[0] = 0xE9;
        bytes[1..5].copy_from_slice(&rel_bytes);

        let mut db = XrefDatabase::new();
        scanner.scan_code(addr(0x1000), &bytes, &mut db);

        let xrefs = db.xrefs_from(addr(0x1000));
        // At offset 0 with detect_thunks=true this becomes ThunkCall
        assert!(!xrefs.is_empty());
    }

    // 12. X86XrefScanner: scan_data_pointers (32-bit)
    #[test]
    fn test_scanner_data_pointers_32bit() {
        let code_range = range(0x1000, 0x2000);
        let scanner = X86XrefScanner::new(code_range, 4);
        let mut bytes = vec![0u8; 8];
        bytes[0..4].copy_from_slice(&0x0000_1050_u32.to_le_bytes()); // in code
        bytes[4..8].copy_from_slice(&0x0000_5000_u32.to_le_bytes()); // not in code

        let mut db = XrefDatabase::new();
        scanner.scan_data_pointers(addr(0x4000), &bytes, &mut db);

        assert_eq!(db.total_count(), 1);
        let xref = &db.xrefs_from(addr(0x4000))[0];
        assert_eq!(xref.kind, XrefKind::DataPointer);
        assert_eq!(xref.to, addr(0x1050));
    }

    // 13. XrefStats::compute
    #[test]
    fn test_xref_stats_compute() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);
        db.add_jump(addr(0x1020), addr(0x1030), 2);
        db.add_data_read(addr(0x1040), addr(0x5000));

        let stats = XrefStats::compute(&db);
        assert_eq!(stats.total, 5);
        assert_eq!(*stats.by_kind.get("CodeCall").unwrap(), 3);
        assert_eq!(*stats.by_kind.get("CodeJump").unwrap(), 1);
        assert_eq!(*stats.by_kind.get("DataRead").unwrap(), 1);
        assert_eq!(stats.unique_callers, 3);
        assert_eq!(stats.unique_callees, 2);
        assert!(stats.leaf_functions >= 1);
    }

    // 14. XrefKind Display
    #[test]
    fn test_xref_kind_display() {
        assert_eq!(XrefKind::CodeCall.to_string(), "CodeCall");
        assert_eq!(XrefKind::DataPointer.to_string(), "DataPointer");
        assert_eq!(XrefKind::ImportByOrdinal.to_string(), "ImportByOrdinal");
        assert_eq!(XrefKind::StringRef.to_string(), "StringRef");
        assert_eq!(XrefKind::TypeRef.to_string(), "TypeRef");
        assert_eq!(XrefKind::ThunkCall.to_string(), "ThunkCall");
    }

    // 15. iter_all yields all xrefs
    #[test]
    fn test_iter_all() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1005), addr(0x1010), 2);
        db.add_data_pointer(addr(0x4000), addr(0x2000));

        assert_eq!(db.iter_all().count(), 3);
    }

    // 16. callee_count and callee_of
    #[test]
    fn test_callee_count() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x3000), 5);
        db.add_call(addr(0x1020), addr(0x2000), 5); // duplicate callee
        assert_eq!(db.callee_count(addr(0x1000)), 1);
        let callees = db.callees_of(addr(0x1000));
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0], addr(0x2000));
    }

    // 17. jumpers_to
    #[test]
    fn test_jumpers_to() {
        let mut db = XrefDatabase::new();
        db.add_jump(addr(0x1000), addr(0x2000), 2);
        db.add_jump(addr(0x1010), addr(0x2000), 5);
        let jumpers = db.jumpers_to(addr(0x2000));
        assert_eq!(jumpers.len(), 2);
        assert!(jumpers.contains(&addr(0x1000)));
        assert!(jumpers.contains(&addr(0x1010)));
    }

    // 18. hot_functions top_n ordering
    #[test]
    fn test_hot_functions_ordering() {
        let mut db = XrefDatabase::new();
        for i in 0..3u64 {
            db.add_call(addr(0x1000 + i * 0x10), addr(0x3000), 5);
        }
        db.add_call(addr(0x1100), addr(0x2000), 5);
        let hot = db.hot_functions(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, addr(0x3000));
        assert_eq!(hot[0].1, 3);
    }

    // 19. add_data_read and add_data_write kinds
    #[test]
    fn test_data_read_write_kinds() {
        let mut db = XrefDatabase::new();
        db.add_data_read(addr(0x1000), addr(0x4000));
        db.add_data_write(addr(0x1005), addr(0x4000));
        let to = db.xrefs_to(addr(0x4000));
        assert_eq!(to.len(), 2);
        let kinds: Vec<XrefKind> = to.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&XrefKind::DataRead));
        assert!(kinds.contains(&XrefKind::DataWrite));
    }

    // 20. add_data_addr kind
    #[test]
    fn test_data_addr_kind() {
        let mut db = XrefDatabase::new();
        db.add_data_addr(addr(0x1000), addr(0x5000));
        let from = db.xrefs_from(addr(0x1000));
        assert_eq!(from.len(), 1);
        assert_eq!(from[0].kind, XrefKind::DataAddress);
    }

    // 21. total_count tracks correctly
    #[test]
    fn test_total_count() {
        let mut db = XrefDatabase::new();
        assert_eq!(db.total_count(), 0);
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1000), addr(0x3000), 5);
        assert_eq!(db.total_count(), 2);
        db.remove_from(addr(0x1000));
        assert_eq!(db.total_count(), 0);
    }

    // 22. import xrefs secondary index
    #[test]
    fn test_import_xrefs() {
        let mut db = XrefDatabase::new();
        db.add_import_by_name(addr(0x5000), addr(0x7000), "printf");
        db.add_import_by_name(addr(0x5010), addr(0x7000), "printf");
        db.add_import_by_ordinal(addr(0x5020), addr(0x7100), 42);

        let printf_xrefs = db.xrefs_to_import("printf");
        assert_eq!(printf_xrefs.len(), 2);
        let names = db.all_import_names();
        assert!(names.contains(&"printf"));
        assert!(names.contains(&"42"));
    }

    // 23. string xrefs secondary index
    #[test]
    fn test_string_xrefs() {
        let mut db = XrefDatabase::new();
        db.add_string_ref(addr(0x1000), addr(0x3000), "hello world");
        db.add_string_ref(addr(0x1010), addr(0x3000), "hello world");
        db.add_string_ref(addr(0x1020), addr(0x4000), "goodbye");

        let sites = db.string_ref_sites("hello world");
        assert_eq!(sites.len(), 2);
        let strings = db.all_strings();
        assert_eq!(strings.len(), 2);
    }

    // 24. type xrefs secondary index
    #[test]
    fn test_type_xrefs() {
        let mut db = XrefDatabase::new();
        db.add_type_ref(addr(0x1000), addr(0x8000), "std::string");
        db.add_type_ref(addr(0x1010), addr(0x8000), "std::string");

        let type_xrefs = db.xrefs_to_type("std::string");
        assert_eq!(type_xrefs.len(), 2);
    }

    // 25. JSON serialization round-trip
    #[test]
    fn test_json_round_trip() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1010), addr(0x1020), 2);
        db.add_string_ref(addr(0x1020), addr(0x5000), "test string");
        db.add_import_by_name(addr(0x1030), addr(0x6000), "malloc");

        let json = db.to_json().unwrap();
        let db2 = XrefDatabase::from_json(&json).unwrap();
        assert_eq!(db2.total_count(), db.total_count());
        assert_eq!(db2.callers_of(addr(0x2000)).len(), 1);
    }

    // 26. XrefFilter: kind filter
    #[test]
    fn test_xref_filter_kind() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1010), addr(0x1020), 2);
        db.add_data_read(addr(0x1020), addr(0x3000));

        let filter = XrefFilter::new().with_kinds([XrefKind::CodeCall]);
        let results = db.filter_all(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, XrefKind::CodeCall);
    }

    // 27. XrefFilter: tag_contains
    #[test]
    fn test_xref_filter_tag() {
        let mut db = XrefDatabase::new();
        db.add_string_ref(addr(0x1000), addr(0x2000), "error: bad input");
        db.add_string_ref(addr(0x1010), addr(0x2010), "hello world");
        db.add_call(addr(0x1020), addr(0x3000), 5);

        let filter = XrefFilter::new().tag_contains("error");
        let results = db.filter_all(&filter);
        assert_eq!(results.len(), 1);
        assert!(results[0].tag.as_deref().unwrap_or("").contains("error"));
    }

    // 28. XrefFilter: from_range and to_range
    #[test]
    fn test_xref_filter_ranges() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x3000), addr(0x4000), 5);
        db.add_call(addr(0x1010), addr(0x5000), 5);

        let filter = XrefFilter::new().from_range(range(0x1000, 0x2000));
        let results = db.filter_all(&filter);
        assert_eq!(results.len(), 2);
    }

    // 29. XrefGraph: call graph reachability
    #[test]
    fn test_xref_graph_reachability() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);
        db.add_call(addr(0x3000), addr(0x4000), 5);

        let graph = XrefGraph::call_graph(&db);
        assert!(graph.is_reachable(addr(0x1000), addr(0x4000)));
        assert!(!graph.is_reachable(addr(0x4000), addr(0x1000)));
        assert!(graph.is_reachable(addr(0x1000), addr(0x1000)));
    }

    // 30. XrefGraph: node and edge counts
    #[test]
    fn test_xref_graph_counts() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);

        let graph = XrefGraph::call_graph(&db);
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
    }

    // 31. XrefGraph: SCC detection (no cycle)
    #[test]
    fn test_xref_graph_scc_no_cycle() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);

        let graph = XrefGraph::call_graph(&db);
        let sccs = graph.strongly_connected_components();
        // All SCCs have size 1 (no cycles)
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }
    }

    // 32. XrefGraph: SCC detection (with cycle)
    #[test]
    fn test_xref_graph_scc_with_cycle() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);
        db.add_call(addr(0x3000), addr(0x1000), 5); // cycle

        let graph = XrefGraph::call_graph(&db);
        let sccs = graph.strongly_connected_components();
        let large_scc = sccs.iter().find(|s| s.len() > 1).unwrap();
        assert_eq!(large_scc.len(), 3);
    }

    // 33. XrefGraph: topological sort (DAG)
    #[test]
    fn test_xref_graph_topo_sort() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);

        let graph = XrefGraph::call_graph(&db);
        let order = graph.topological_sort();
        assert!(order.is_some());
        let order = order.unwrap();
        assert_eq!(order.len(), 3);
        // 0x1000 must come before 0x2000
        let pos_1000 = order.iter().position(|a| a.0 == 0x1000).unwrap();
        let pos_2000 = order.iter().position(|a| a.0 == 0x2000).unwrap();
        assert!(pos_1000 < pos_2000);
    }

    // 33b. XrefGraph: topological sort is deterministic across repeated runs
    // when several nodes tie at in-degree 0 (regression test for a
    // HashMap-iteration-order dependency in the initial root seeding).
    #[test]
    fn test_xref_graph_topo_sort_deterministic_multi_root() {
        let mut db = XrefDatabase::new();
        // Several independent roots (in-degree 0), each feeding a shared sink.
        for root in [0x1000u64, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000] {
            db.add_call(addr(root), addr(0x9000), 5);
        }
        let graph = XrefGraph::call_graph(&db);
        let first = graph.topological_sort().unwrap();
        for _ in 0..20 {
            let again = graph.topological_sort().unwrap();
            assert_eq!(first, again, "topological_sort order must be stable across calls");
        }
    }

    // 34. XrefGraph: topo sort fails on cycle
    #[test]
    fn test_xref_graph_topo_sort_cycle() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x1000), 5); // cycle

        let graph = XrefGraph::call_graph(&db);
        assert!(graph.topological_sort().is_none());
    }

    // 35. XrefGraph: BFS distances
    #[test]
    fn test_xref_graph_bfs_distances() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);
        db.add_call(addr(0x1000), addr(0x3000), 5);

        let graph = XrefGraph::call_graph(&db);
        let dist = graph.bfs_distances(addr(0x1000));
        assert_eq!(*dist.get(&addr(0x1000)).unwrap(), 0);
        assert_eq!(*dist.get(&addr(0x2000)).unwrap(), 1);
        assert_eq!(*dist.get(&addr(0x3000)).unwrap(), 1); // direct edge exists
    }

    // 36. XrefDiff: detect added and removed
    #[test]
    fn test_xref_diff() {
        let mut db_a = XrefDatabase::new();
        db_a.add_call(addr(0x1000), addr(0x2000), 5);
        db_a.add_call(addr(0x1010), addr(0x3000), 5);

        let mut db_b = XrefDatabase::new();
        db_b.add_call(addr(0x1000), addr(0x2000), 5); // same
        db_b.add_call(addr(0x1020), addr(0x4000), 5); // new

        let diff = XrefDiff::compute(&db_a, &db_b);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.total_changes(), 2);
    }

    // 37. XrefDiff: no changes
    #[test]
    fn test_xref_diff_empty() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);

        let diff = XrefDiff::compute(&db, &db);
        assert!(diff.is_empty());
    }

    // 38. XrefSummary: basic computation
    #[test]
    fn test_xref_summary() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);
        db.add_jump(addr(0x1020), addr(0x2000), 2);
        db.add_data_read(addr(0x2000), addr(0x5000));

        let summary = XrefSummary::compute(&db, addr(0x2000));
        assert_eq!(summary.total_in, 3);
        assert_eq!(summary.total_out, 1);
        assert_eq!(summary.call_in, 2);
        assert_eq!(summary.jump_in, 1);
        assert_eq!(summary.data_out, 1);
        assert!(summary.is_function_entry());
        assert!(!summary.is_unreferenced());
    }

    // 39. StringXrefScanner: scan_ascii
    #[test]
    fn test_string_scanner_ascii() {
        let scanner = StringXrefScanner::new(4);
        let data = b"hello world\0AB\0test data here\0";
        let results = scanner.scan_ascii(addr(0x3000), data);
        assert!(results.len() >= 2);
        assert!(results.iter().any(|(_, s)| s == "hello world"));
        assert!(results.iter().any(|(_, s)| s == "test data here"));
    }

    // 40. StringXrefScanner: short strings ignored
    #[test]
    fn test_string_scanner_min_length() {
        let scanner = StringXrefScanner::new(5);
        let data = b"hi\0hello world\0";
        let results = scanner.scan_ascii(addr(0), data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "hello world");
    }

    // 41. XrefGrouper: enclosing_function
    #[test]
    fn test_xref_grouper_enclosing() {
        let grouper = XrefGrouper::new(vec![addr(0x1000), addr(0x2000), addr(0x3000)]);
        assert_eq!(grouper.enclosing_function(addr(0x1500)), Some(addr(0x1000)));
        assert_eq!(grouper.enclosing_function(addr(0x2000)), Some(addr(0x2000)));
        assert_eq!(grouper.enclosing_function(addr(0x3FFF)), Some(addr(0x3000)));
        assert_eq!(grouper.enclosing_function(addr(0x0100)), None);
    }

    // 42. XrefGrouper: group_by_function
    #[test]
    fn test_xref_grouper_group() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1005), addr(0x2000), 5); // inside fn 0x1000
        db.add_call(addr(0x1010), addr(0x3000), 5); // inside fn 0x1000
        db.add_call(addr(0x2005), addr(0x4000), 5); // inside fn 0x2000

        let grouper = XrefGrouper::new(vec![addr(0x1000), addr(0x2000)]);
        let groups = grouper.group_by_function(&db);
        assert_eq!(groups.get(&addr(0x1000)).map_or(0, std::vec::Vec::len), 2);
        assert_eq!(groups.get(&addr(0x2000)).map_or(0, std::vec::Vec::len), 1);
    }

    // 43. merge two databases
    #[test]
    fn test_database_merge() {
        let mut db1 = XrefDatabase::new();
        db1.add_call(addr(0x1000), addr(0x2000), 5);

        let mut db2 = XrefDatabase::new();
        db2.add_call(addr(0x3000), addr(0x4000), 5);
        db2.add_jump(addr(0x3010), addr(0x3020), 2);

        db1.merge(db2);
        assert_eq!(db1.total_count(), 3);
    }

    // 44. remove_exact
    #[test]
    fn test_remove_exact() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1000), addr(0x2000), 2);

        let removed = db.remove_exact(addr(0x1000), addr(0x2000), XrefKind::CodeCall);
        assert!(removed);
        assert_eq!(db.total_count(), 1);
        assert_eq!(db.xrefs_from(addr(0x1000))[0].kind, XrefKind::CodeJump);
    }

    // 45. XrefKind::is_code / is_data / is_import
    #[test]
    fn test_xref_kind_predicates() {
        assert!(XrefKind::CodeCall.is_code());
        assert!(XrefKind::CodeJump.is_code());
        assert!(XrefKind::ThunkCall.is_code());
        assert!(!XrefKind::DataRead.is_code());
        assert!(XrefKind::DataRead.is_data());
        assert!(XrefKind::DataWrite.is_data());
        assert!(!XrefKind::CodeCall.is_data());
        assert!(XrefKind::ImportByName.is_import());
        assert!(XrefKind::ImportByOrdinal.is_import());
        assert!(!XrefKind::CodeCall.is_import());
    }

    // 46. Xref Display
    #[test]
    fn test_xref_display() {
        let x = Xref::new(addr(0x1000), addr(0x2000), XrefKind::CodeCall, 5);
        let s = x.to_string();
        assert!(s.contains("CodeCall"));
        assert!(s.contains("0x00001000") || s.contains("1000"));
    }

    // 47. XrefGraph: in_degree and out_degree
    #[test]
    fn test_xref_graph_degrees() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x3000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x4000), 5);

        let graph = XrefGraph::call_graph(&db);
        assert_eq!(graph.in_degree(addr(0x2000)), 2);
        assert_eq!(graph.out_degree(addr(0x2000)), 1);
        assert_eq!(graph.out_degree(addr(0x1000)), 1);
    }

    // 47b. XrefGraph::in_degree must count *distinct source nodes*, not
    // distinct (source, kind) edge entries — a single caller that both calls
    // and jumps to the same target is still one incoming reference.
    #[test]
    fn test_xref_graph_in_degree_dedups_multi_kind_same_pair() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x3000), addr(0x2000), 5);

        let graph = XrefGraph::code_graph(&db);
        // 0x1000 -> 0x2000 via two kinds should count once, plus 0x3000 -> 0x2000.
        assert_eq!(graph.in_degree(addr(0x2000)), 2);
    }

    // 47c. strongly_connected_components must be deterministic across
    // rebuilds of the same logical graph (guards against relying on
    // `HashSet`/`HashMap` iteration order for Tarjan's visitation order).
    #[test]
    fn test_scc_deterministic_across_rebuilds() {
        let mut db = XrefDatabase::new();
        // A moderately sized cycle plus some branches, to make order-
        // dependent bugs likely to surface if reintroduced.
        for i in 0..20u64 {
            let from = 0x1000 + i * 0x10;
            let to = 0x1000 + ((i + 1) % 20) * 0x10;
            db.add_call(addr(from), addr(to), 1);
        }
        db.add_call(addr(0x1000), addr(0x9000), 1);

        let first = {
            let graph = XrefGraph::call_graph(&db);
            graph.strongly_connected_components()
        };
        for _ in 0..5 {
            let graph = XrefGraph::call_graph(&db);
            let sccs = graph.strongly_connected_components();
            assert_eq!(sccs, first, "SCC output must not depend on hash iteration order");
        }
    }

    // 48. all_call_targets
    #[test]
    fn test_all_call_targets() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1010), addr(0x2000), 5);
        db.add_call(addr(0x1020), addr(0x3000), 5);
        db.add_jump(addr(0x1030), addr(0x4000), 2); // not a call

        let targets = db.all_call_targets();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&addr(0x2000)));
        assert!(targets.contains(&addr(0x3000)));
    }

    // 49. is_empty
    #[test]
    fn test_is_empty() {
        let mut db = XrefDatabase::new();
        assert!(db.is_empty());
        db.add_call(addr(0x1000), addr(0x2000), 5);
        assert!(!db.is_empty());
    }

    // 50. XrefStats::format_report smoke test
    #[test]
    fn test_stats_format_report() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1010), addr(0x1020), 2);

        let stats = XrefStats::compute(&db);
        let report = stats.format_report();
        assert!(report.contains("Total xrefs"));
        assert!(report.contains("CodeCall"));
    }

    // ── XrefIndex ─────────────────────────────────────────────────────────

    #[test]
    fn test_xref_index_add_and_callers() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1010, 0x2000, 5);
        idx.add_call(0x3000, 0x4000, 5);

        let callers = idx.callers_of(0x2000);
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x1010));
        assert_eq!(idx.callers_of(0xDEAD).len(), 0);
    }

    #[test]
    fn test_xref_index_callees() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1000, 0x3000, 5);
        idx.add_jump(0x1000, 0x4000, 2); // not a call

        let callees = idx.callees_of(0x1000);
        assert_eq!(callees.len(), 2);
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_xref_index_data_refs() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_data_read(0x1000, 0x5000);
        idx.add_data_write(0x1010, 0x5000);
        idx.add_data_addr(0x1020, 0x5000);
        idx.add_call(0x1030, 0x5000, 5); // not a data ref

        let refs = idx.data_refs_to(0x5000);
        assert_eq!(refs.len(), 3);
        assert!(refs.contains(&0x1000));
        assert!(refs.contains(&0x1010));
        assert!(refs.contains(&0x1020));
    }

    #[test]
    fn test_xref_index_total_and_is_empty() {
        let mut idx = BinaryXrefIndex::new();
        assert!(idx.is_empty());
        idx.add_call(0x1000, 0x2000, 5);
        assert!(!idx.is_empty());
        assert_eq!(idx.total(), 1);
    }

    #[test]
    fn test_xref_index_is_leaf() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        // 0x2000 has no outgoing calls at instruction level
        assert!(idx.is_leaf(0x2000));
        assert!(!idx.is_leaf(0x1000));
    }

    #[test]
    fn test_xref_index_count_kind() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1010, 0x3000, 5);
        idx.add_jump(0x1020, 0x1030, 2);
        idx.add_data_read(0x1040, 0x5000);

        assert_eq!(idx.count_kind(SimpleXrefKind::Call), 2);
        assert_eq!(idx.count_kind(SimpleXrefKind::Jump), 1);
        assert_eq!(idx.count_kind(SimpleXrefKind::DataRead), 1);
    }

    #[test]
    fn test_xref_index_hot_call_targets() {
        let mut idx = BinaryXrefIndex::new();
        for i in 0..3u64 {
            idx.add_call(0x1000 + i * 0x10, 0x2000, 5);
        }
        idx.add_call(0x1100, 0x3000, 5);

        let hot = idx.hot_call_targets(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].0, 0x2000);
        assert_eq!(hot[0].1, 3);
    }

    // ── build_from_binary ──────────────────────────────────────────────────

    #[test]
    fn test_build_from_binary_call_rel32() {
        // E8 00 10 00 00 at VA 0x1000 → calls 0x1000+5+0x1000 = 0x2005
        let base: u64 = 0x1000;
        let rel: i32 = 0x1000; // target = 0x1000+5+0x1000 = 0x2005
        let mut code = vec![0u8; 10];
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&rel.to_le_bytes());

        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let callees = idx.callees_of(base);
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0], 0x2005);
    }

    #[test]
    fn test_build_from_binary_jmp_rel32() {
        let base: u64 = 0x1000;
        let rel: i32 = 0x50; // target = 0x1000+5+0x50 = 0x1055
        let mut code = vec![0u8; 10];
        code[0] = 0xE9;
        code[1..5].copy_from_slice(&rel.to_le_bytes());

        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let xrefs = idx.xrefs_from(base);
        let jmp = xrefs.iter().find(|x| x.kind == SimpleXrefKind::Jump);
        assert!(jmp.is_some());
        assert_eq!(jmp.unwrap().to, 0x1055);
    }

    #[test]
    fn test_build_from_binary_jmp_short() {
        let base: u64 = 0x1000;
        // EB 0A at 0x1000 → target = 0x1000+2+0x0A = 0x100C
        let code = vec![0xEB_u8, 0x0A, 0x90, 0x90];
        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let xrefs = idx.xrefs_from(base);
        let jmp = xrefs
            .iter()
            .find(|x| x.kind == SimpleXrefKind::Jump)
            .unwrap();
        assert_eq!(jmp.to, 0x100C);
    }

    #[test]
    fn test_build_from_binary_conditional_jcc_short() {
        let base: u64 = 0x2000;
        // 74 05 (JZ +5) at 0x2000 → target = 0x2000+2+5 = 0x2007
        let code = vec![0x74_u8, 0x05, 0x90, 0x90, 0x90];
        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let xrefs = idx.xrefs_from(base);
        let jmp = xrefs
            .iter()
            .find(|x| x.kind == SimpleXrefKind::Jump)
            .unwrap();
        assert_eq!(jmp.to, 0x2007);
    }

    #[test]
    fn test_build_from_binary_jcc_near() {
        let base: u64 = 0x1000;
        // 0F 84 00 10 00 00 (JZ rel32 = 0x1000) at 0x1000 → target = 0x1000+6+0x1000 = 0x2006
        let mut code = vec![0u8; 10];
        code[0] = 0x0F;
        code[1] = 0x84;
        let rel: i32 = 0x1000;
        code[2..6].copy_from_slice(&rel.to_le_bytes());

        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let xrefs = idx.xrefs_from(base);
        let jmp = xrefs
            .iter()
            .find(|x| x.kind == SimpleXrefKind::Jump)
            .unwrap();
        assert_eq!(jmp.to, 0x2006);
    }

    #[test]
    fn test_build_from_binary_lea_rip_rel() {
        let base: u64 = 0x1000;
        // 48 8D 05 10 00 00 00: REX.W LEA rax, [RIP+0x10]
        // at 0x1000: instr_end = 0x1007; target = 0x1007+0x10 = 0x1017
        let code: Vec<u8> = vec![0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, 0x90];
        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        let xrefs = idx.xrefs_from(base);
        let lea = xrefs
            .iter()
            .find(|x| x.kind == SimpleXrefKind::DataAddr)
            .unwrap();
        assert_eq!(lea.to, 0x1017);
    }

    #[test]
    fn test_build_from_binary_indirect_call_ff2() {
        let base: u64 = 0x1000;
        // FF D0 (CALL rax) — indirect, target unknown → recorded as call to 0.
        let code = vec![0xFF_u8, 0xD0, 0x90];
        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        // ModRM D0 = 11 010 000 → mod=3, reg=2, rm=0 → CALL r/m
        let xrefs = idx.xrefs_from(base);
        let call = xrefs.iter().find(|x| x.kind == SimpleXrefKind::Call);
        assert!(call.is_some());
        assert_eq!(call.unwrap().to, 0); // unknown target
    }

    #[test]
    fn test_build_from_binary_multiple_insns() {
        let base: u64 = 0x1000;
        // E8 00 00 00 00 (CALL $+5 = 0x1005)
        // 90 90 90
        // E9 00 00 00 00 (JMP $+5 = at 0x1008+5 = 0x100D)
        let mut code = vec![0x90u8; 20];
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&0i32.to_le_bytes()); // CALL rel32=0 → target = 0x1005
        // 3 nops
        code[8] = 0xE9;
        code[9..13].copy_from_slice(&0i32.to_le_bytes()); // JMP rel32=0 → target = 0x100D

        let idx = BinaryXrefIndex::build_from_binary(&code, base, "x86_64");
        assert!(idx.count_kind(SimpleXrefKind::Call) >= 1);
        assert!(idx.count_kind(SimpleXrefKind::Jump) >= 1);
    }

    #[test]
    fn test_xref_index_all_sources_targets() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1010, 0x3000, 5);
        idx.add_jump(0x1020, 0x2000, 2);

        let sources = idx.all_sources();
        let targets = idx.all_targets();
        assert_eq!(sources.len(), 3);
        assert_eq!(targets.len(), 2); // 0x2000 appears twice but deduped
    }

    #[test]
    fn test_simple_xref_kind_display() {
        assert_eq!(SimpleXrefKind::Call.to_string(), "Call");
        assert_eq!(SimpleXrefKind::Jump.to_string(), "Jump");
        assert_eq!(SimpleXrefKind::DataRead.to_string(), "DataRead");
        assert_eq!(SimpleXrefKind::DataWrite.to_string(), "DataWrite");
        assert_eq!(SimpleXrefKind::DataAddr.to_string(), "DataAddr");
    }

    #[test]
    fn test_root_functions_filters_called_entries() {
        let mut idx = BinaryXrefIndex::new();
        // 0x1000 is a root, calls 0x2000; 0x2000 calls 0x3000; 0x4000 isolated.
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x2000, 0x3000, 5);

        let entries = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let roots = idx.root_functions(&entries);
        assert_eq!(roots, vec![0x1000, 0x4000]);
    }

    #[test]
    fn test_root_functions_ignores_non_call_incoming() {
        let mut idx = BinaryXrefIndex::new();
        // Jump-only inbound is *not* a call — entry must still be a root.
        idx.add_jump(0x1000, 0x2000, 5);
        idx.add_data_addr(0x1010, 0x2000);
        let roots = idx.root_functions(&[0x2000]);
        assert_eq!(roots, vec![0x2000]);
    }

    #[test]
    fn test_count_string_refs_matches_xrefs_to() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_data_addr(0x1000, 0x9000);
        idx.add_data_addr(0x1010, 0x9000);
        idx.add_data_addr(0x1020, 0x9100);
        // 0x9200 unreferenced.

        let counts = idx.count_string_refs([0x9000u64, 0x9100, 0x9200]);
        assert_eq!(counts.get(&0x9000).copied(), Some(2));
        assert_eq!(counts.get(&0x9100).copied(), Some(1));
        assert_eq!(counts.get(&0x9200).copied(), Some(0));
    }

    // ── Tests for pub fn xrefs_to / xrefs_from and XrefRecord ────────────────

    #[test]
    fn test_xrefs_from_returns_correct_records() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_jump(addr(0x1000), addr(0x3000), 5);
        db.add_call(addr(0x4000), addr(0x2000), 5);

        let recs = xrefs_from_in(&db, 0x1000);
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.from_addr == 0x1000));
        let kinds: Vec<&str> = recs.iter().map(|r| r.kind.as_str()).collect();
        assert!(kinds.contains(&"CodeCall"));
        assert!(kinds.contains(&"CodeJump"));
    }

    #[test]
    fn test_xrefs_to_returns_correct_records() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x1005), addr(0x2000), 5);
        db.add_data_read(addr(0x3000), addr(0x2000));

        let recs = xrefs_to_in(&db, 0x2000);
        assert_eq!(recs.len(), 3);
        assert!(recs.iter().all(|r| r.to_addr == 0x2000));
    }

    #[test]
    fn test_xrefs_from_empty_for_unknown_addr() {
        let db = XrefDatabase::new();
        assert!(xrefs_from_in(&db, 0xDEAD_BEEF).is_empty());
    }

    #[test]
    fn test_xrefs_to_empty_for_unknown_addr() {
        let db = XrefDatabase::new();
        assert!(xrefs_to_in(&db, 0xDEAD_BEEF).is_empty());
    }

    #[test]
    fn test_xref_record_serde_roundtrip() {
        let rec = XrefRecord {
            from_addr: 0x1000,
            to_addr: 0x2000,
            kind: "CodeCall".to_owned(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let decoded: XrefRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.from_addr, 0x1000);
        assert_eq!(decoded.to_addr, 0x2000);
        assert_eq!(decoded.kind, "CodeCall");
    }

    #[test]
    fn test_xref_record_json_shape() {
        let rec = XrefRecord {
            from_addr: 0x400,
            to_addr: 0x800,
            kind: "DataRead".to_owned(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"from_addr\""));
        assert!(json.contains("\"to_addr\""));
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"DataRead\""));
    }

    // ---- Coverage additions: previously-untested public API surface ----

    #[test]
    fn test_filter_from_and_filter_to() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_data_read(addr(0x1000), addr(0x3000));
        let filter = XrefFilter::new().with_kinds([XrefKind::CodeCall]);
        let from_results = db.filter_from(addr(0x1000), &filter);
        assert_eq!(from_results.len(), 1);
        assert_eq!(from_results[0].kind, XrefKind::CodeCall);

        let to_results = db.filter_to(addr(0x2000), &filter);
        assert_eq!(to_results.len(), 1);
        assert_eq!(to_results[0].from, addr(0x1000));
    }

    #[test]
    fn test_graph_successors_reachable_and_all_nodes() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_call(addr(0x2000), addr(0x3000), 5);

        let graph = XrefGraph::call_graph(&db);
        assert_eq!(graph.successors(addr(0x1000)), vec![addr(0x2000)]);
        assert!(graph.successors(addr(0x3000)).is_empty());

        let reachable = graph.reachable_from(addr(0x1000));
        assert!(reachable.contains(&addr(0x1000)));
        assert!(reachable.contains(&addr(0x2000)));
        assert!(reachable.contains(&addr(0x3000)));

        let mut nodes = graph.all_nodes();
        nodes.sort_unstable();
        assert_eq!(nodes, vec![addr(0x1000), addr(0x2000), addr(0x3000)]);
    }

    #[test]
    fn test_reachable_from_unknown_start_is_singleton() {
        let db = XrefDatabase::new();
        let graph = XrefGraph::call_graph(&db);
        let reachable = graph.reachable_from(addr(0xDEAD_BEEF));
        // Not present in the graph, but BFS always seeds the start node itself.
        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&addr(0xDEAD_BEEF)));
    }

    #[test]
    fn test_data_graph_and_full_graph() {
        let mut db = XrefDatabase::new();
        db.add_call(addr(0x1000), addr(0x2000), 5);
        db.add_data_read(addr(0x1000), addr(0x4000));
        db.add_data_addr(addr(0x1000), addr(0x5000));

        let data_graph = XrefGraph::data_graph(&db);
        assert!(data_graph.contains(addr(0x4000)));
        assert!(data_graph.contains(addr(0x5000)));
        assert!(!data_graph.contains(addr(0x2000)));

        let full = XrefGraph::full_graph(&db);
        assert!(full.contains(addr(0x2000)));
        assert!(full.contains(addr(0x4000)));
        assert!(full.contains(addr(0x5000)));
    }

    #[test]
    fn test_group_by_function_and_mutual_callers() {
        let mut db = XrefDatabase::new();
        // Function A (0x1000) calls function B (0x2000).
        db.add_call(addr(0x1000), addr(0x2000), 5);
        // Function B calls back into function A (mutual recursion).
        db.add_call(addr(0x2010), addr(0x1000), 5);

        let grouper = XrefGrouper::new(vec![addr(0x1000), addr(0x2000)]);
        let groups = grouper.group_by_function(&db);
        assert_eq!(groups.get(&addr(0x1000)).map(Vec::len), Some(1));
        assert_eq!(groups.get(&addr(0x2000)).map(Vec::len), Some(1));

        let mutual = grouper.mutual_callers(&db);
        assert!(mutual.contains(&(addr(0x1000), addr(0x2000))));
    }

    #[test]
    fn test_scan_utf16le_finds_string() {
        let scanner = StringXrefScanner::new(3).with_utf16();
        // "hi" in UTF-16LE, null-terminated.
        let mut data = Vec::new();
        for ch in "hiya".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
        let results = scanner.scan_utf16le(addr(0x1000), &data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "hiya");
    }

    #[test]
    fn test_scan_utf16le_disabled_returns_empty() {
        let scanner = StringXrefScanner::new(3); // utf16 not enabled
        let mut data = Vec::new();
        for ch in "hiya".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        assert!(scanner.scan_utf16le(addr(0x1000), &data).is_empty());
    }

    #[test]
    fn test_import_scanner_record_named_and_ordinal() {
        let mut db = XrefDatabase::new();
        let scanner = ImportXrefScanner::new(addr(0x9000), 8);
        scanner.record_named_import(&mut db, addr(0x1000), addr(0x9000), "GetProcAddress");
        scanner.record_ordinal_import(&mut db, addr(0x1010), addr(0x9008), 42);

        let from_named = db.xrefs_from(addr(0x1000));
        assert_eq!(from_named[0].kind, XrefKind::ImportByName);
        assert_eq!(from_named[0].tag.as_deref(), Some("GetProcAddress"));

        let from_ordinal = db.xrefs_from(addr(0x1010));
        assert_eq!(from_ordinal[0].kind, XrefKind::ImportByOrdinal);
    }

    #[test]
    fn test_add_return_records_code_return_xref() {
        let mut db = XrefDatabase::new();
        db.add_return(addr(0x1000), addr(0x2000));
        let xrefs = db.xrefs_from(addr(0x1000));
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, XrefKind::CodeReturn);
    }

    // Regression test: `with_function_entries` / `add_data_range` builders
    // are exercised indirectly by scanner tests elsewhere, but not with an
    // explicit assertion that thunk classification actually depends on the
    // registered entry offset. Also exercises `AddressRange` data pointer
    // scanning end-to-end.
    #[test]
    fn test_scanner_with_function_entries_and_data_range() {
        let mut code = vec![0u8; 16];
        code[0] = 0xE9; // JMP rel32 at offset 0, registered as a function entry
        let rel: i32 = 0; // target = base + 5
        code[1..5].copy_from_slice(&rel.to_le_bytes());

        let scanner = X86XrefScanner {
            code_range: AddressRange::new(addr(0x1000), addr(0x2000)),
            data_ranges: Vec::new(),
            pointer_size: 8,
            scan_lea: true,
            detect_thunks: true,
            function_entries: HashSet::new(),
        }
        .with_function_entries([0u64])
        .add_data_range(AddressRange::new(addr(0x3000), addr(0x4000)));

        let mut db = XrefDatabase::new();
        scanner.scan_code(addr(0x1000), &code, &mut db);
        let xrefs = db.xrefs_from(addr(0x1000));
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, XrefKind::ThunkCall);
    }
}

#[cfg(test)]
mod leaf_vs_unanalysed {
    use super::*;

    /// A "leaf" verdict must be distinguishable from "never analysed".
    ///
    /// Both `XrefDatabase` and `BinaryXrefIndex` store xrefs, not coverage, so
    /// an address the analysis never visited has no outgoing calls exactly
    /// like a genuine leaf and `is_leaf*` answers `true` for both. That answer
    /// is a finding in one case and an absence of data in the other, and
    /// nothing in the API let a caller tell them apart. `has_any_xrefs` is
    /// that missing fact.
    #[test]
    fn database_separates_a_real_leaf_from_an_unseen_address() {
        let mut db = XrefDatabase::new();
        // `caller` calls `leaf`; `leaf` itself calls nothing.
        let caller = Address::new(0x1000);
        let leaf = Address::new(0x2000);
        db.add(Xref::new(caller, leaf, XrefKind::CodeCall, 5));

        let never_seen = Address::new(0xDEAD_0000);

        // Both look like leaves...
        assert!(db.is_leaf_function(leaf), "the callee makes no calls");
        assert!(
            db.is_leaf_function(never_seen),
            "an unseen address also has no recorded calls — that is the trap"
        );

        // ...but only one of them is actually present in the analysis.
        assert!(
            db.has_any_xrefs(leaf),
            "a real leaf appears as the target of its caller"
        );
        assert!(
            !db.has_any_xrefs(never_seen),
            "an address the analysis never visited must be reported as absent"
        );
    }

    #[test]
    fn binary_index_separates_a_real_leaf_from_an_unseen_address() {
        let mut idx = BinaryXrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);

        assert!(idx.is_leaf(0x2000), "the callee makes no calls");
        assert!(idx.is_leaf(0xDEAD_0000), "an unseen address looks the same");

        assert!(idx.has_any_xrefs(0x2000), "the callee is a target in the index");
        assert!(
            !idx.has_any_xrefs(0xDEAD_0000),
            "the unseen address must be reported as absent"
        );
        // The caller is present as a source, and is NOT a leaf.
        assert!(idx.has_any_xrefs(0x1000));
        assert!(!idx.is_leaf(0x1000), "the caller makes a call");
    }
}
