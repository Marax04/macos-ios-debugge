//! Symbol cross-reference engine.
//!
//! Finds all references to a symbol (call, data read, data write,
//! address-taken), builds reference graphs, finds unreferenced symbols
//! (dead code), computes reference counts, and exports XREF tables.
//!
//! Types: [`XrefEntry`], [`XrefType`], [`XrefGraph`], [`UnreferencedSymbol`],
//! [`XrefTable`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

// ─── XrefType ─────────────────────────────────────────────────────────────────

/// The kind of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum XrefType {
    /// A direct call instruction (`CALL target`).
    Call,
    /// An indirect call through a register or memory operand.
    IndirectCall,
    /// A data read (load) from the target address.
    DataRead,
    /// A data write (store) to the target address.
    DataWrite,
    /// The target address is taken (loaded into a register / pointer).
    AddressTaken,
    /// An unconditional jump to the target.
    Jump,
    /// A conditional branch to the target.
    ConditionalBranch,
    /// The target is imported from another module.
    Import,
    /// The target is exported to other modules.
    Export,
    /// A string or data reference.
    Data,
    /// Unknown or unclassified reference.
    Unknown,
}

impl XrefType {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::IndirectCall => "indirect_call",
            Self::DataRead => "data_read",
            Self::DataWrite => "data_write",
            Self::AddressTaken => "address_taken",
            Self::Jump => "jump",
            Self::ConditionalBranch => "conditional_branch",
            Self::Import => "import",
            Self::Export => "export",
            Self::Data => "data",
            Self::Unknown => "unknown",
        }
    }

    /// True if this xref represents a code flow transfer.
    #[must_use]
    pub const fn is_code(self) -> bool {
        matches!(
            self,
            Self::Call | Self::IndirectCall | Self::Jump | Self::ConditionalBranch
        )
    }

    /// True if this xref reads or writes data.
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(
            self,
            Self::DataRead | Self::DataWrite | Self::AddressTaken | Self::Data
        )
    }
}

impl fmt::Display for XrefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── XrefEntry ────────────────────────────────────────────────────────────────

/// A single cross-reference record: an instruction at `from` references `to`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XrefEntry {
    /// Address of the instruction that generates this reference.
    pub from: u64,
    /// Address being referenced.
    pub to: u64,
    /// Type of reference.
    pub xref_type: XrefType,
    /// Optional name of the referencing symbol (function / variable).
    pub from_name: Option<String>,
    /// Optional name of the referenced symbol.
    pub to_name: Option<String>,
    /// Instruction offset within the enclosing function, if known.
    pub func_offset: Option<u32>,
}

impl XrefEntry {
    /// Create a new xref entry.
    #[must_use]
    pub const fn new(from: u64, to: u64, xref_type: XrefType) -> Self {
        Self {
            from,
            to,
            xref_type,
            from_name: None,
            to_name: None,
            func_offset: None,
        }
    }

    /// Create a named xref entry.
    #[must_use]
    pub fn named(
        from: u64,
        to: u64,
        xref_type: XrefType,
        from_name: impl Into<String>,
        to_name: impl Into<String>,
    ) -> Self {
        Self {
            from,
            to,
            xref_type,
            from_name: Some(from_name.into()),
            to_name: Some(to_name.into()),
            func_offset: None,
        }
    }
}

impl fmt::Display for XrefEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let from_n = self.from_name.as_deref().unwrap_or("?");
        let to_n = self.to_name.as_deref().unwrap_or("?");
        write!(
            f,
            "{from_n}({:#x}) --{}--> {to_n}({:#x})",
            self.from, self.xref_type, self.to
        )
    }
}

// ─── XrefGraph ────────────────────────────────────────────────────────────────

/// A directed xref graph.
///
/// Edges are stored in two adjacency lists:
/// - `edges_from[addr]` → all xrefs originating at `addr`.
/// - `edges_to[addr]`   → all xrefs targeting `addr`.
#[derive(Debug, Default)]
pub struct XrefGraph {
    /// Outgoing edges: from → Vec<XrefEntry>.
    edges_from: HashMap<u64, Vec<XrefEntry>>,
    /// Incoming edges: to → Vec<XrefEntry>.
    edges_to: HashMap<u64, Vec<XrefEntry>>,
    /// All known addresses (nodes).
    nodes: HashSet<u64>,
    /// Total edge count.
    edge_count: usize,
}

impl XrefGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single xref edge.
    pub fn add_xref(&mut self, entry: XrefEntry) {
        self.nodes.insert(entry.from);
        self.nodes.insert(entry.to);
        self.edges_to
            .entry(entry.to)
            .or_default()
            .push(entry.clone());
        self.edges_from.entry(entry.from).or_default().push(entry);
        self.edge_count += 1;
    }

    /// Add many xref entries at once.
    pub fn add_xrefs(&mut self, entries: impl IntoIterator<Item = XrefEntry>) {
        for e in entries {
            self.add_xref(e);
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// All xrefs pointing TO `addr`.
    #[must_use]
    pub fn refs_to(&self, addr: u64) -> Vec<&XrefEntry> {
        self.edges_to
            .get(&addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// All xrefs originating FROM `addr`.
    #[must_use]
    pub fn refs_from(&self, addr: u64) -> Vec<&XrefEntry> {
        self.edges_from
            .get(&addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// How many times is `addr` referenced (in-degree)?
    #[must_use]
    pub fn ref_count(&self, addr: u64) -> usize {
        self.edges_to.get(&addr).map_or(0, Vec::len)
    }

    /// How many addresses does `addr` reference (out-degree)?
    #[must_use]
    pub fn out_degree(&self, addr: u64) -> usize {
        self.edges_from.get(&addr).map_or(0, Vec::len)
    }

    /// All xrefs to `addr` of a specific type.
    #[must_use]
    pub fn refs_to_typed(&self, addr: u64, xref_type: XrefType) -> Vec<&XrefEntry> {
        self.refs_to(addr)
            .into_iter()
            .filter(|e| e.xref_type == xref_type)
            .collect()
    }

    /// All call sites that call `addr`.
    #[must_use]
    pub fn callers(&self, addr: u64) -> Vec<&XrefEntry> {
        self.edges_to
            .get(&addr)
            .map(|v| {
                v.iter()
                    .filter(|e| {
                        matches!(e.xref_type, XrefType::Call | XrefType::IndirectCall)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All addresses called by the code at `addr`.
    #[must_use]
    pub fn callees(&self, addr: u64) -> Vec<&XrefEntry> {
        self.edges_from
            .get(&addr)
            .map(|v| {
                v.iter()
                    .filter(|e| {
                        matches!(e.xref_type, XrefType::Call | XrefType::IndirectCall)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── Graph algorithms ──────────────────────────────────────────────────────

    /// BFS from `start`, following outgoing call edges. Returns visited addresses.
    #[must_use]
    pub fn reachable_from(&self, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(addr) = queue.pop_front() {
            for e in self.refs_from(addr) {
                if e.xref_type.is_code() && !visited.contains(&e.to) {
                    visited.insert(e.to);
                    queue.push_back(e.to);
                }
            }
        }
        visited
    }

    /// Reverse BFS: find all addresses that can reach `target` via call edges.
    #[must_use]
    pub fn can_reach(&self, target: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(target);
        visited.insert(target);

        while let Some(addr) = queue.pop_front() {
            for e in self.refs_to(addr) {
                if e.xref_type.is_code() && !visited.contains(&e.from) {
                    visited.insert(e.from);
                    queue.push_back(e.from);
                }
            }
        }
        visited
    }

    /// Detect simple cycles using DFS. Returns a set of addresses on any cycle.
    #[must_use]
    pub fn find_cycles(&self) -> HashSet<u64> {
        let mut on_cycle = HashSet::new();
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();

        for &start in &self.nodes {
            if !visited.contains(&start) {
                self.dfs_cycle(start, &mut visited, &mut stack, &mut on_cycle);
            }
        }
        on_cycle
    }

    /// Iterative DFS with an explicit frame stack. A recursive version
    /// overflowed the call stack on long call chains (one frame per node),
    /// which is a `DoS` vector when the graph comes from attacker-influenced
    /// xref extraction.
    fn dfs_cycle(
        &self,
        start: u64,
        visited: &mut HashSet<u64>,
        stack: &mut HashSet<u64>,
        on_cycle: &mut HashSet<u64>,
    ) {
        let code_succs = |node: u64| -> Vec<u64> {
            self.refs_from(node)
                .into_iter()
                .filter(|e| e.xref_type.is_code())
                .map(|e| e.to)
                .collect()
        };

        visited.insert(start);
        stack.insert(start);
        // Each frame: (node, successors materialised once, next successor idx).
        let mut frames: Vec<(u64, Vec<u64>, usize)> = vec![(start, code_succs(start), 0)];

        while let Some(frame) = frames.last_mut() {
            let node = frame.0;
            if frame.2 < frame.1.len() {
                let next = frame.1[frame.2];
                frame.2 += 1;
                // `insert` returns false when the node was already present, so
                // this is the `contains` + `insert` pair in one hash lookup.
                if visited.insert(next) {
                    stack.insert(next);
                    let next_succs = code_succs(next);
                    frames.push((next, next_succs, 0));
                } else if stack.contains(&next) {
                    // Found back-edge → cycle.
                    on_cycle.insert(next);
                    on_cycle.insert(node);
                }
            } else {
                stack.remove(&node);
                frames.pop();
            }
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// Top-N most-referenced addresses (by in-degree).
    #[must_use]
    pub fn top_referenced(&self, n: usize) -> Vec<(u64, usize)> {
        let mut counts: Vec<(u64, usize)> = self
            .edges_to
            .iter()
            .map(|(&addr, v)| (addr, v.len()))
            .collect();
        // Total order, like the sorts at `xrefs_to_sorted`/`all_xrefs_sorted`
        // below: `edges_to` is a `HashMap`, whose iteration order differs
        // between processes, and `sort_by_key` is stable — so ranking by count
        // alone left ties in hash order. With ties straddling the `n` cutoff
        // (single-reference addresses are the common case) the *membership* of
        // the top-N changed from run to run, not just the order within it.
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        counts.truncate(n);
        counts
    }
}

// ─── UnreferencedSymbol ───────────────────────────────────────────────────────

/// A symbol with no incoming cross-references (potential dead code).
#[derive(Debug, Clone)]
pub struct UnreferencedSymbol {
    /// Address of the symbol.
    pub address: u64,
    /// Symbol name.
    pub name: String,
    /// Whether the symbol is exported (exported but unreferenced internally).
    pub is_exported: bool,
    /// Size of the symbol in bytes, if known.
    pub size: Option<u64>,
    /// Score: 0.0 = definitively dead, 1.0 = likely live but not locally referenced.
    pub dead_score: f64,
}

impl UnreferencedSymbol {
    /// Create a new unreferenced symbol record.
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            is_exported: false,
            size: None,
            dead_score: 0.5,
        }
    }
}

impl fmt::Display for UnreferencedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} (exported={} dead_score={:.2})",
            self.name, self.address, self.is_exported, self.dead_score
        )
    }
}

// ─── XrefTable ────────────────────────────────────────────────────────────────

/// A flat, sorted xref table with lookup and export capabilities.
pub struct XrefTable {
    /// All xref entries, sorted by (to, from).
    entries: Vec<XrefEntry>,
    /// Index: to → range of entry indices.
    to_index: BTreeMap<u64, (usize, usize)>,
    /// Index: from → range of entry indices.
    from_index: BTreeMap<u64, Vec<usize>>,
    sorted: bool,
}

impl XrefTable {
    /// Create an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            to_index: BTreeMap::new(),
            from_index: BTreeMap::new(),
            sorted: true,
        }
    }

    /// Build a table from a slice of entries.
    #[must_use]
    pub fn from_entries(mut entries: Vec<XrefEntry>) -> Self {
        entries.sort_by(|a, b| a.to.cmp(&b.to).then(a.from.cmp(&b.from)));
        let mut t = Self {
            entries,
            to_index: BTreeMap::new(),
            from_index: BTreeMap::new(),
            sorted: true,
        };
        t.rebuild_index();
        t
    }

    /// Add an entry and mark as unsorted.
    pub fn add(&mut self, entry: XrefEntry) {
        self.entries.push(entry);
        self.sorted = false;
    }

    /// Sort and rebuild the index.
    pub fn finalize(&mut self) {
        self.entries
            .sort_by(|a, b| a.to.cmp(&b.to).then(a.from.cmp(&b.from)));
        self.sorted = true;
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.to_index.clear();
        self.from_index.clear();

        let mut i = 0usize;
        while i < self.entries.len() {
            let target = self.entries[i].to;
            let start = i;
            while i < self.entries.len() && self.entries[i].to == target {
                i += 1;
            }
            self.to_index.insert(target, (start, i));
        }

        for (idx, e) in self.entries.iter().enumerate() {
            self.from_index.entry(e.from).or_default().push(idx);
        }
    }

    /// All xrefs to `addr`.
    #[must_use]
    pub fn refs_to(&self, addr: u64) -> &[XrefEntry] {
        if let Some(&(start, end)) = self.to_index.get(&addr) {
            &self.entries[start..end]
        } else {
            &[]
        }
    }

    /// All xrefs from `addr`.
    #[must_use]
    pub fn refs_from(&self, addr: u64) -> Vec<&XrefEntry> {
        self.from_index
            .get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Reference count to `addr`.
    #[must_use]
    pub fn ref_count(&self, addr: u64) -> usize {
        self.refs_to(addr).len()
    }

    /// Total number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> std::slice::Iter<'_, XrefEntry> {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a XrefTable {
    type Item = &'a XrefEntry;
    type IntoIter = std::slice::Iter<'a, XrefEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl XrefTable {

    /// Export to CSV.
    #[must_use]
    pub fn export_csv(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("from_addr,to_addr,type,from_name,to_name\n");
        for e in &self.entries {
            writeln!(
                out,
                "{:#x},{:#x},{},{},{}",
                e.from,
                e.to,
                e.xref_type,
                e.from_name.as_deref().unwrap_or(""),
                e.to_name.as_deref().unwrap_or(""),
            )
            .expect("writing to String never fails");
        }
        out
    }

    /// Find xrefs to any address in the given set.
    #[must_use]
    pub fn refs_to_any(&self, addrs: &HashSet<u64>) -> Vec<&XrefEntry> {
        self.entries
            .iter()
            .filter(|e| addrs.contains(&e.to))
            .collect()
    }
}

impl Default for XrefTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─── XrefAnalyzer ─────────────────────────────────────────────────────────────

/// High-level analyzer: given a set of known symbols and xref entries, computes
/// unreferenced symbols, dead code, and rich statistics.
pub struct XrefAnalyzer {
    graph: XrefGraph,
    table: XrefTable,
    /// Known symbol addresses and names.
    symbols: HashMap<u64, String>,
    /// Whether the symbol is exported.
    exported_symbols: HashSet<u64>,
}

impl XrefAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: XrefGraph::new(),
            table: XrefTable::new(),
            symbols: HashMap::new(),
            exported_symbols: HashSet::new(),
        }
    }

    /// Register a symbol.
    pub fn add_symbol(&mut self, addr: u64, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
    }

    /// Mark a symbol as exported.
    pub fn mark_exported(&mut self, addr: u64) {
        self.exported_symbols.insert(addr);
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, entry: XrefEntry) {
        self.graph.add_xref(entry.clone());
        self.table.add(entry);
    }

    /// Finalize indexes.
    pub fn finalize(&mut self) {
        self.table.finalize();
    }

    /// Find all unreferenced symbols.
    ///
    /// A symbol is unreferenced if it has zero incoming xrefs.
    #[must_use]
    pub fn find_unreferenced(&self) -> Vec<UnreferencedSymbol> {
        let mut result = Vec::new();
        for (&addr, name) in &self.symbols {
            if self.graph.ref_count(addr) == 0 {
                let is_exported = self.exported_symbols.contains(&addr);
                let dead_score = if is_exported { 0.3 } else { 0.9 };
                result.push(UnreferencedSymbol {
                    address: addr,
                    name: name.clone(),
                    is_exported,
                    size: None,
                    dead_score,
                });
            }
        }
        result.sort_by_key(|a| a.address);
        result
    }

    /// Compute reference counts for all known symbols.
    #[must_use]
    pub fn reference_counts(&self) -> HashMap<u64, usize> {
        self.symbols
            .keys()
            .map(|&addr| (addr, self.graph.ref_count(addr)))
            .collect()
    }

    /// Return the xref graph.
    #[must_use]
    pub const fn graph(&self) -> &XrefGraph {
        &self.graph
    }

    /// Return the xref table.
    #[must_use]
    pub const fn table(&self) -> &XrefTable {
        &self.table
    }

    /// Generate a summary report as a string.
    #[must_use]
    pub fn report(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "=== XRef Analysis Report ===").ok();
        writeln!(out, "Symbols:         {}", self.symbols.len()).ok();
        writeln!(out, "Xref edges:      {}", self.graph.edge_count()).ok();
        writeln!(out, "Graph nodes:     {}", self.graph.node_count()).ok();

        let unreferenced = self.find_unreferenced();
        writeln!(out, "Unreferenced:    {}", unreferenced.len()).ok();

        let top = self.graph.top_referenced(5);
        writeln!(out, "\nTop-5 most referenced:").ok();
        for (addr, count) in &top {
            let name = self.symbols.get(addr).map_or("<?>", String::as_str);
            writeln!(out, "  {name}({addr:#x}): {count}x").ok();
        }

        if !unreferenced.is_empty() {
            writeln!(out, "\nUnreferenced symbols (sample, max 10):").ok();
            for sym in unreferenced.iter().take(10) {
                writeln!(out, "  {sym}").ok();
            }
        }
        out
    }
}

impl Default for XrefAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── XrefStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics over a set of xref entries.
#[derive(Debug, Clone, Default)]
pub struct XrefStats {
    /// Total number of cross-references counted.
    pub total: usize,
    /// Direct call references.
    pub calls: usize,
    /// Indirect (register/memory) call references.
    pub indirect_calls: usize,
    /// Data read references.
    pub data_reads: usize,
    /// Data write references.
    pub data_writes: usize,
    /// References that take the address of a symbol (without reading/writing it).
    pub address_taken: usize,
    /// Unconditional jump references.
    pub jumps: usize,
    /// Conditional branch references.
    pub branches: usize,
    /// References to imported symbols.
    pub imports: usize,
    /// References to exported symbols.
    pub exports: usize,
    /// References of an unclassified kind.
    pub unknown: usize,
}

impl XrefStats {
    /// Compute stats from a slice of entries.
    #[must_use]
    pub fn from_entries(entries: &[XrefEntry]) -> Self {
        let mut s = Self {
            total: entries.len(),
            ..Self::default()
        };
        for e in entries {
            match e.xref_type {
                XrefType::Call => s.calls += 1,
                XrefType::IndirectCall => s.indirect_calls += 1,
                XrefType::DataRead => s.data_reads += 1,
                XrefType::DataWrite => s.data_writes += 1,
                XrefType::AddressTaken => s.address_taken += 1,
                XrefType::Jump => s.jumps += 1,
                XrefType::ConditionalBranch => s.branches += 1,
                XrefType::Import => s.imports += 1,
                XrefType::Export => s.exports += 1,
                XrefType::Data | XrefType::Unknown => s.unknown += 1,
            }
        }
        s
    }
}

impl fmt::Display for XrefStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XrefStats {{ total={} calls={} reads={} writes={} jumps={} }}",
            self.total, self.calls, self.data_reads, self.data_writes, self.jumps
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call(from: u64, to: u64) -> XrefEntry {
        XrefEntry::new(from, to, XrefType::Call)
    }

    fn read(from: u64, to: u64) -> XrefEntry {
        XrefEntry::new(from, to, XrefType::DataRead)
    }

    #[test]
    fn find_cycles_deep_chain_no_stack_overflow() {
        /// Chain length: a 200k-node linear chain used to overflow the stack in
        /// the recursive DFS; the iterative version must handle it.
        const N: u64 = 200_000;
        let mut g = XrefGraph::new();
        for i in 0..N {
            g.add_xref(call(i, i + 1));
        }
        // Close a small cycle at the far end so cycle detection still works.
        g.add_xref(call(N, N - 1));
        let cycles = g.find_cycles();
        assert!(cycles.contains(&N));
        assert!(cycles.contains(&(N - 1)));
        assert!(!cycles.contains(&0));
    }

    #[test]
    fn xref_type_names() {
        assert_eq!(XrefType::Call.name(), "call");
        assert_eq!(XrefType::DataWrite.name(), "data_write");
    }

    #[test]
    fn xref_type_is_code() {
        assert!(XrefType::Call.is_code());
        assert!(XrefType::Jump.is_code());
        assert!(!XrefType::DataRead.is_code());
    }

    #[test]
    fn xref_entry_display() {
        let e = XrefEntry::named(0x1000, 0x2000, XrefType::Call, "caller", "callee");
        let s = e.to_string();
        assert!(s.contains("caller"));
        assert!(s.contains("callee"));
        assert!(s.contains("call"));
    }

    #[test]
    fn graph_add_and_query() {
        let mut g = XrefGraph::new();
        g.add_xref(call(0x1000, 0x2000));
        g.add_xref(call(0x1500, 0x2000));
        assert_eq!(g.ref_count(0x2000), 2);
        assert_eq!(g.out_degree(0x1000), 1);
    }

    #[test]
    fn graph_callers() {
        let mut g = XrefGraph::new();
        g.add_xref(call(0x1000, 0x3000));
        g.add_xref(read(0x2000, 0x3000));
        let callers = g.callers(0x3000);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].from, 0x1000);
    }

    #[test]
    fn graph_reachable_from() {
        let mut g = XrefGraph::new();
        g.add_xref(call(0x1000, 0x2000));
        g.add_xref(call(0x2000, 0x3000));
        let reachable = g.reachable_from(0x1000);
        assert!(reachable.contains(&0x1000));
        assert!(reachable.contains(&0x2000));
        assert!(reachable.contains(&0x3000));
    }

    #[test]
    fn graph_can_reach() {
        let mut g = XrefGraph::new();
        g.add_xref(call(0x1000, 0x2000));
        g.add_xref(call(0x2000, 0x3000));
        let can_reach = g.can_reach(0x3000);
        assert!(can_reach.contains(&0x1000));
        assert!(can_reach.contains(&0x2000));
        assert!(can_reach.contains(&0x3000));
    }

    #[test]
    fn graph_cycle_detection() {
        let mut g = XrefGraph::new();
        g.add_xref(call(0x1000, 0x2000));
        g.add_xref(call(0x2000, 0x1000)); // cycle
        let cycles = g.find_cycles();
        assert!(cycles.contains(&0x1000) || cycles.contains(&0x2000));
    }

    #[test]
    fn graph_top_referenced() {
        let mut g = XrefGraph::new();
        for i in 0..5u64 {
            g.add_xref(call(0x1000 + i, 0xdead_beef));
        }
        g.add_xref(call(0x2000, 0xcafe));
        let top = g.top_referenced(1);
        assert_eq!(top[0].0, 0xdead_beef);
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn xref_table_from_entries() {
        let entries = vec![call(0x1000, 0x5000), call(0x2000, 0x5000)];
        let t = XrefTable::from_entries(entries);
        assert_eq!(t.ref_count(0x5000), 2);
    }

    #[test]
    fn xref_table_refs_from() {
        let mut t = XrefTable::new();
        t.add(call(0x1000, 0x2000));
        t.add(call(0x1000, 0x3000));
        t.finalize();
        assert_eq!(t.refs_from(0x1000).len(), 2);
    }

    #[test]
    fn xref_table_csv() {
        let mut t = XrefTable::new();
        t.add(XrefEntry::named(0x1000, 0x2000, XrefType::Call, "caller", "callee"));
        t.finalize();
        let csv = t.export_csv();
        assert!(csv.contains("from_addr"));
        assert!(csv.contains("caller"));
    }

    #[test]
    fn analyzer_unreferenced() {
        let mut a = XrefAnalyzer::new();
        a.add_symbol(0x1000, "referenced");
        a.add_symbol(0x2000, "orphan");
        a.add_xref(call(0x3000, 0x1000));
        a.finalize();
        let unreferenced = a.find_unreferenced();
        assert_eq!(unreferenced.len(), 1);
        assert_eq!(unreferenced[0].name, "orphan");
    }

    #[test]
    fn analyzer_exported_has_lower_dead_score() {
        let mut a = XrefAnalyzer::new();
        a.add_symbol(0x1000, "exported_orphan");
        a.mark_exported(0x1000);
        a.finalize();
        let unreferenced = a.find_unreferenced();
        assert!(!unreferenced.is_empty());
        assert!(unreferenced[0].dead_score < 0.5);
    }

    #[test]
    fn analyzer_reference_counts() {
        let mut a = XrefAnalyzer::new();
        a.add_symbol(0x2000, "hot_func");
        for i in 0..3u64 {
            a.add_xref(call(0x1000 + i, 0x2000));
        }
        a.finalize();
        let counts = a.reference_counts();
        assert_eq!(counts[&0x2000], 3);
    }

    #[test]
    fn xref_stats_from_entries() {
        let entries = vec![
            call(0x1000, 0x2000),
            read(0x1000, 0x3000),
            XrefEntry::new(0x1000, 0x4000, XrefType::DataWrite),
        ];
        let s = XrefStats::from_entries(&entries);
        assert_eq!(s.total, 3);
        assert_eq!(s.calls, 1);
        assert_eq!(s.data_reads, 1);
        assert_eq!(s.data_writes, 1);
    }

    #[test]
    fn unreferenced_symbol_display() {
        let u = UnreferencedSymbol::new(0x1000, "dead_func");
        let s = u.to_string();
        assert!(s.contains("dead_func"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn analyzer_report_string() {
        let mut a = XrefAnalyzer::new();
        a.add_symbol(0x1000, "main");
        a.add_xref(call(0x2000, 0x1000));
        a.finalize();
        let report = a.report();
        assert!(report.contains("XRef Analysis"));
        assert!(report.contains("main"));
    }
}
