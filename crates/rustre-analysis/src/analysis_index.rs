/// Fast address, function, string and cross-reference indices.
///
/// All indices are built in bulk and then available for O(log n) or O(1)
/// lookups.  The combined [`AnalysisIndex`] aggregates all sub-indices.
use std::collections::HashMap;
use std::fmt;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

// ── Shared address type ───────────────────────────────────────────────────────

pub type Addr = u64;

// ── Address range ─────────────────────────────────────────────────────────────

/// A [start, end) address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddrRange {
    pub start: Addr,
    /// Exclusive end.
    pub end: Addr,
}

impl AddrRange {
    #[must_use]
    pub fn new(start: Addr, end: Addr) -> Self {
        debug_assert!(end >= start, "end must be >= start");
        Self { start, end }
    }

    #[must_use]
    pub const fn with_length(start: Addr, len: u64) -> Self {
        Self { start, end: start + len }
    }

    #[must_use]
    pub const fn contains(&self, addr: Addr) -> bool {
        addr >= self.start && addr < self.end
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl fmt::Display for AddrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:x}, 0x{:x})", self.start, self.end)
    }
}

// ── FunctionEntry ─────────────────────────────────────────────────────────────

/// Lightweight function record held in the index.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub start: Addr,
    pub length: u64,
    pub name: Option<String>,
}

impl FunctionEntry {
    #[must_use]
    pub const fn new(start: Addr, length: u64, name: Option<String>) -> Self {
        Self { start, length, name }
    }

    #[must_use]
    pub const fn range(&self) -> AddrRange {
        AddrRange::with_length(self.start, self.length)
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", self.start))
    }
}

// ── FunctionIndex ─────────────────────────────────────────────────────────────

/// Sorted address → [`FunctionEntry`] index.
#[derive(Debug, Default, Clone)]
pub struct FunctionIndex {
    /// Sorted by start address.
    by_start: BTreeMap<Addr, FunctionEntry>,
    /// Name (lowercase) → start address, for name lookups.
    by_name: HashMap<String, Addr>,
}

impl FunctionIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: FunctionEntry) {
        if let Some(name) = &entry.name {
            self.by_name.insert(name.to_lowercase(), entry.start);
        }
        self.by_start.insert(entry.start, entry);
    }

    /// Look up by exact start address.
    #[must_use]
    pub fn get(&self, addr: Addr) -> Option<&FunctionEntry> {
        self.by_start.get(&addr)
    }

    /// Find the function that contains `addr` (overlapping range query).
    #[must_use]
    pub fn find_containing(&self, addr: Addr) -> Option<&FunctionEntry> {
        // Walk BACKWARDS through every function starting at or before `addr`
        // and return the first one that actually covers it.
        //
        // Testing only `next_back()` — the single nearest preceding start —
        // meant a short function nested inside a longer one hid the rest of the
        // enclosing function: with `outer` at 0x1000..0x1100 and a 4-byte thunk
        // at 0x1010, every address from 0x1014 up to 0x1100 resolved to
        // nothing. Because the walk starts at the nearest, the tightest
        // enclosing function still wins where several overlap, and addresses in
        // a genuine gap still resolve to `None`.
        self.by_start
            .range(..=addr)
            .rev()
            .find(|(_, entry)| entry.length == 0 || entry.range().contains(addr))
            .map(|(_, entry)| entry)
    }

    /// Find all functions whose names contain `query` (case-insensitive).
    #[must_use]
    pub fn search_by_name(&self, query: &str) -> Vec<&FunctionEntry> {
        let q = query.to_lowercase();
        self.by_start
            .values()
            .filter(|e| {
                e.name
                    .as_ref()
                    .is_some_and(|n| n.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Functions in address order.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&FunctionEntry> {
        self.by_start.values().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_start.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }
}

// ── StringEntry ───────────────────────────────────────────────────────────────

/// Lightweight string record.
#[derive(Debug, Clone)]
pub struct StringEntry {
    pub address: Addr,
    pub value: String,
    pub byte_length: usize,
}

impl StringEntry {
    #[must_use]
    pub fn new(address: Addr, value: impl Into<String>) -> Self {
        let value = value.into();
        let byte_length = value.len() + 1;
        Self { address, value, byte_length }
    }
}

// ── StringIndex ───────────────────────────────────────────────────────────────

/// Address → string index with full-text search capability.
#[derive(Debug, Default, Clone)]
pub struct StringIndex {
    by_address: BTreeMap<Addr, StringEntry>,
    /// Reverse mapping: string value (lowercased) → list of addresses.
    by_value: HashMap<String, Vec<Addr>>,
}

impl StringIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: StringEntry) {
        let key = entry.value.to_lowercase();
        self.by_value.entry(key).or_default().push(entry.address);
        self.by_address.insert(entry.address, entry);
    }

    #[must_use]
    pub fn get(&self, addr: Addr) -> Option<&StringEntry> {
        self.by_address.get(&addr)
    }

    /// Find all string entries whose value contains `query` (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&StringEntry> {
        let q = query.to_lowercase();
        self.by_address
            .values()
            .filter(|e| e.value.to_lowercase().contains(&q))
            .collect()
    }

    /// Find entries by exact value match.
    #[must_use]
    pub fn find_exact(&self, value: &str) -> Vec<&StringEntry> {
        let key = value.to_lowercase();
        self.by_value
            .get(&key)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| self.by_address.get(a))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    #[must_use]
    pub fn all_sorted(&self) -> Vec<&StringEntry> {
        self.by_address.values().collect()
    }
}

// ── XrefKind ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    Call,
    Jump,
    Data,
    StringRef,
    Other,
}

// ── XrefIndex ─────────────────────────────────────────────────────────────────

/// Adjacency-list cross-reference index.
#[derive(Debug, Default, Clone)]
pub struct XrefIndex {
    /// from → list of (to, kind)
    outgoing: HashMap<Addr, Vec<(Addr, XrefKind)>>,
    /// to → list of (from, kind)
    incoming: HashMap<Addr, Vec<(Addr, XrefKind)>>,
}

impl XrefIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, from: Addr, to: Addr, kind: XrefKind) {
        self.outgoing.entry(from).or_default().push((to, kind));
        self.incoming.entry(to).or_default().push((from, kind));
    }

    #[must_use]
    pub fn outgoing_from(&self, addr: Addr) -> &[(Addr, XrefKind)] {
        self.outgoing.get(&addr).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn incoming_to(&self, addr: Addr) -> &[(Addr, XrefKind)] {
        self.incoming.get(&addr).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn callers_of(&self, addr: Addr) -> Vec<Addr> {
        self.incoming_to(addr)
            .iter()
            .filter(|(_, k)| *k == XrefKind::Call)
            .map(|(a, _)| *a)
            .collect()
    }

    #[must_use]
    pub fn callees_of(&self, addr: Addr) -> Vec<Addr> {
        self.outgoing_from(addr)
            .iter()
            .filter(|(_, k)| *k == XrefKind::Call)
            .map(|(a, _)| *a)
            .collect()
    }

    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.outgoing.values().map(std::vec::Vec::len).sum()
    }
}

// ── AddressIndex ──────────────────────────────────────────────────────────────

/// Generic sorted address set with range query support.
#[derive(Debug, Default, Clone)]
pub struct AddressIndex {
    sorted: BTreeSet<Addr>,
}

impl AddressIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, addr: Addr) {
        self.sorted.insert(addr);
    }

    #[must_use]
    pub fn contains(&self, addr: Addr) -> bool {
        self.sorted.contains(&addr)
    }

    /// All addresses in [lo, hi).
    #[must_use]
    pub fn range(&self, lo: Addr, hi: Addr) -> Vec<Addr> {
        self.sorted
            .range(lo..hi)
            .copied()
            .collect()
    }

    /// The nearest address ≤ `addr`.
    #[must_use]
    pub fn floor(&self, addr: Addr) -> Option<Addr> {
        self.sorted
            .range(..=addr)
            .next_back()
            .copied()
    }

    /// The nearest address ≥ `addr`.
    #[must_use]
    pub fn ceil(&self, addr: Addr) -> Option<Addr> {
        self.sorted
            .range(addr..)
            .next()
            .copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }
}

// ── SectionIndex ─────────────────────────────────────────────────────────────

/// Maps sections (name + range) for fast address → section lookups.
#[derive(Debug, Default, Clone)]
pub struct SectionIndex {
    sections: Vec<(String, AddrRange)>,
}

impl SectionIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_section(&mut self, name: impl Into<String>, range: AddrRange) {
        self.sections.push((name.into(), range));
    }

    #[must_use]
    pub fn section_name_for(&self, addr: Addr) -> Option<&str> {
        self.sections
            .iter()
            .find(|(_, r)| r.contains(addr))
            .map(|(n, _)| n.as_str())
    }

    #[must_use]
    pub fn is_code(&self, addr: Addr) -> bool {
        self.section_name_for(addr)
            .is_some_and(|n| n.starts_with(".text") || n == "__text")
    }
}

// ── AnalysisIndex ─────────────────────────────────────────────────────────────

/// Combined index aggregating all sub-indices.
#[derive(Debug, Default, Clone)]
pub struct AnalysisIndex {
    pub functions: FunctionIndex,
    pub strings: StringIndex,
    pub xrefs: XrefIndex,
    pub code_addresses: AddressIndex,
    pub sections: SectionIndex,
}

impl AnalysisIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the index from raw slices.
    #[must_use] 
    pub fn build(
        functions: Vec<FunctionEntry>,
        strings: Vec<StringEntry>,
        xrefs: Vec<(Addr, Addr, XrefKind)>,
        sections: Vec<(String, AddrRange)>,
    ) -> Self {
        let mut idx = Self::new();
        for f in functions {
            idx.code_addresses.insert(f.start);
            idx.functions.insert(f);
        }
        for s in strings {
            idx.strings.insert(s);
        }
        for (from, to, kind) in xrefs {
            idx.xrefs.add(from, to, kind);
        }
        for (name, range) in sections {
            idx.sections.add_section(name, range);
        }
        idx
    }

    /// Statistics about the index.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        IndexStats {
            function_count: self.functions.len(),
            string_count: self.strings.len(),
            xref_count: self.xrefs.total_edges(),
            code_address_count: self.code_addresses.len(),
        }
    }
}

/// Summary statistics for an `AnalysisIndex`.
#[derive(Debug, Clone, Default)]
pub struct IndexStats {
    pub function_count: usize,
    pub string_count: usize,
    pub xref_count: usize,
    pub code_address_count: usize,
}

impl fmt::Display for IndexStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "functions={} strings={} xrefs={} code_addrs={}",
            self.function_count, self.string_count, self.xref_count, self.code_address_count
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_index() {
        let mut idx = FunctionIndex::new();
        idx.insert(FunctionEntry::new(0x1000, 100, Some("main".to_owned())));
        idx.insert(FunctionEntry::new(0x2000, 200, Some("helper".to_owned())));
        assert!(idx.get(0x1000).is_some());
        assert!(idx.find_containing(0x1050).is_some());
        assert!(idx.find_containing(0x1100).is_none()); // past end
        assert_eq!(idx.search_by_name("hel").len(), 1);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn test_string_index() {
        let mut idx = StringIndex::new();
        idx.insert(StringEntry::new(0x3000, "hello world"));
        idx.insert(StringEntry::new(0x3100, "password"));
        assert_eq!(idx.search("hello").len(), 1);
        assert_eq!(idx.search("xyz").len(), 0);
        assert_eq!(idx.find_exact("hello world").len(), 1);
    }

    #[test]
    fn test_xref_index() {
        let mut idx = XrefIndex::new();
        idx.add(0x1000, 0x2000, XrefKind::Call);
        idx.add(0x1010, 0x2000, XrefKind::Call);
        idx.add(0x1020, 0x3000, XrefKind::Jump);
        assert_eq!(idx.callers_of(0x2000).len(), 2);
        assert_eq!(idx.callees_of(0x1000).len(), 1);
        assert_eq!(idx.total_edges(), 3);
    }

    #[test]
    fn test_address_index() {
        let mut idx = AddressIndex::new();
        for addr in [0x1000u64, 0x1010, 0x2000, 0x3000] {
            idx.insert(addr);
        }
        assert_eq!(idx.range(0x1000, 0x2000).len(), 2);
        assert_eq!(idx.floor(0x1005), Some(0x1000));
        assert_eq!(idx.ceil(0x1005), Some(0x1010));
    }

    #[test]
    fn test_analysis_index_build() {
        let functions = vec![
            FunctionEntry::new(0x1000, 100, Some("main".to_owned())),
        ];
        let strings = vec![StringEntry::new(0x5000, "hello")];
        let xrefs = vec![(0x1000, 0x2000, XrefKind::Call)];
        let sections = vec![
            (".text".to_owned(), AddrRange::new(0x1000, 0x4000)),
        ];
        let idx = AnalysisIndex::build(functions, strings, xrefs, sections);
        let stats = idx.stats();
        assert_eq!(stats.function_count, 1);
        assert_eq!(stats.string_count, 1);
        assert_eq!(stats.xref_count, 1);
        assert!(idx.sections.is_code(0x1000));
    }

    #[test]
    fn test_addr_range() {
        let r = AddrRange::new(0x1000, 0x2000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1fff));
        assert!(!r.contains(0x2000));
        assert_eq!(r.len(), 0x1000);
    }
}
