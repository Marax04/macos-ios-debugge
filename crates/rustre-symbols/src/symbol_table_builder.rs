//! Unified symbol table builder.
//!
//! Merges ELF symbols, PE exports, PDB, debug info, FLIRT matches, and
//! user-defined names from multiple sources.  Resolves conflicts by priority
//! ordering, tracks symbol source, and computes symbol confidence.
//!
//! Types: [`SymbolEntry`], [`SymbolSource`], [`SymbolTable`], [`ConflictResolver`],
//! [`SymbolConfidence`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::SystemTime;

// ─── SymbolSource ─────────────────────────────────────────────────────────────

/// The origin of a [`SymbolEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolSource {
    /// Highest trust: analyst-supplied name.
    User,
    /// PDB symbols.
    Pdb,
    /// DWARF debug info.
    Dwarf,
    /// `CodeView` debug info.
    CodeView,
    /// STABS debug info.
    Stabs,
    /// ELF symbol table.
    Elf,
    /// PE export directory.
    PeExport,
    /// PE import directory.
    PeImport,
    /// FLIRT pattern match.
    Flirt,
    /// AI / machine-learning inferred.
    Ai,
    /// Inferred from calling conventions or data-flow analysis.
    Inferred,
    /// Unknown / synthetic placeholder.
    Unknown,
}

impl SymbolSource {
    /// Trust priority: higher = more authoritative.  Used to resolve conflicts.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::User => 100,
            Self::Pdb | Self::Dwarf | Self::CodeView => 90,
            Self::Stabs => 80,
            Self::Elf => 70,
            Self::PeExport => 65,
            Self::Flirt => 60,
            Self::PeImport => 55,
            Self::Ai => 40,
            Self::Inferred => 30,
            Self::Unknown => 0,
        }
    }
}

impl fmt::Display for SymbolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── SymbolConfidence ─────────────────────────────────────────────────────────

/// Confidence in a [`SymbolEntry`]'s name and metadata.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SymbolConfidence(pub f64);

impl SymbolConfidence {
    /// Maximum confidence (1.0).
    pub const MAX: Self = Self(1.0);
    /// Minimum confidence (0.0).
    pub const MIN: Self = Self(0.0);

    /// Create confidence from a value in [0.0, 1.0], clamped.
    ///
    /// NaN maps to [`Self::MIN`]: `clamp` *propagates* NaN rather than bounding
    /// it, so the previous `v.clamp(0.0, 1.0)` returned a value outside the
    /// range this constructor documents. A NaN confidence is not merely odd —
    /// every comparison with it is false, so such an entry fails
    /// [`Self::meets_threshold`] at *every* threshold (including 0.0), is never
    /// replaced by a better one during merging, and is not reported by
    /// `low_confidence` either. It becomes silently unusable and invisible.
    #[must_use]
    pub const fn new(v: f64) -> Self {
        // Plain comparisons, not `clamp`: comparisons with NaN are all false,
        // so NaN falls through to the 0.0 branch instead of surviving.
        if v >= 1.0 {
            Self::MAX
        } else if v > 0.0 {
            Self(v)
        } else {
            Self::MIN
        }
    }

    /// Compute confidence from a [`SymbolSource`].
    #[must_use]
    pub fn from_source(source: SymbolSource) -> Self {
        Self::new(f64::from(source.priority()) / 100.0)
    }

    /// Raw value.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }

    /// True if confidence is at or above a threshold.
    #[must_use]
    pub fn meets_threshold(self, threshold: f64) -> bool {
        self.0 >= threshold
    }
}

impl fmt::Display for SymbolConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

// ─── SymbolKind ───────────────────────────────────────────────────────────────

/// Semantic kind of a [`SymbolEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// An executable function.
    Function,
    /// A data object / global variable.
    Variable,
    /// A code label (non-function jump target).
    Label,
    /// A thunk / trampoline.
    Thunk,
    /// An import-table entry.
    Import,
    /// An export-table entry.
    Export,
    /// A section / segment descriptor.
    Section,
    /// Kind could not be determined.
    Unknown,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── SymbolEntry ─────────────────────────────────────────────────────────────

/// A single symbol in the unified table.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Canonical name (best available).
    pub name: String,
    /// Demangled / human-readable name, if different from `name`.
    pub demangled_name: Option<String>,
    /// Virtual address.
    pub address: u64,
    /// Size in bytes (if known).
    pub size: Option<u64>,
    /// Kind of symbol.
    pub kind: SymbolKind,
    /// Primary source this name came from.
    pub source: SymbolSource,
    /// All sources that contributed to this entry.
    pub sources: HashSet<SymbolSource>,
    /// Confidence in this entry.
    pub confidence: SymbolConfidence,
    /// When this entry was last updated.
    pub updated_at: SystemTime,
    /// Optional module / object file the symbol belongs to.
    pub module: Option<String>,
    /// Optional ordinal (PE exports).
    pub ordinal: Option<u32>,
    /// Whether the symbol is externally visible.
    pub is_external: bool,
    /// User notes.
    pub notes: String,
}

impl SymbolEntry {
    /// Create a new symbol entry from the required fields.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, kind: SymbolKind, source: SymbolSource) -> Self {
        let name = name.into();
        let confidence = SymbolConfidence::from_source(source);
        let mut sources = HashSet::new();
        sources.insert(source);
        Self {
            name,
            demangled_name: None,
            address,
            size: None,
            kind,
            source,
            sources,
            confidence,
            updated_at: SystemTime::now(),
            module: None,
            ordinal: None,
            is_external: false,
            notes: String::new(),
        }
    }

    /// Display name: demangled if available, else raw.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.name)
    }

    /// End address (exclusive), if size is known.
    #[must_use]
    pub fn end_address(&self) -> Option<u64> {
        self.size.map(|s| self.address + s)
    }

    /// True if `addr` falls within this symbol's range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        match self.size {
            Some(s) => addr >= self.address && addr < self.address + s,
            None => addr == self.address,
        }
    }

    /// Merge metadata from `other` into `self` without changing the name.
    pub fn merge_metadata(&mut self, other: &Self) {
        for &src in &other.sources {
            self.sources.insert(src);
        }
        if self.size.is_none() && other.size.is_some() {
            self.size = other.size;
        }
        if self.demangled_name.is_none() && other.demangled_name.is_some() {
            self.demangled_name.clone_from(&other.demangled_name);
        }
        if self.module.is_none() && other.module.is_some() {
            self.module.clone_from(&other.module);
        }
        if other.confidence.value() > self.confidence.value() {
            self.confidence = other.confidence;
        }
        self.updated_at = SystemTime::now();
    }
}

impl fmt::Display for SymbolEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({} / {} / conf={})",
            self.display_name(),
            self.address,
            self.kind,
            self.source,
            self.confidence
        )
    }
}

// ─── ConflictPolicy ──────────────────────────────────────────────────────────

/// How to resolve naming conflicts when two sources provide different names for the
/// same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Keep whichever name has higher source priority.
    HighestPriority,
    /// Keep the first name added.
    KeepFirst,
    /// Keep the last name added.
    KeepLast,
    /// Keep all names (results in multiple entries per address).
    KeepAll,
    /// Prefer the longer name (more descriptive).
    PreferLonger,
}

// ─── ConflictResolver ────────────────────────────────────────────────────────

/// Resolves conflicts between competing symbol entries at the same address.
#[derive(Debug)]
pub struct ConflictResolver {
    /// The policy used to choose between colliding entries.
    pub policy: ConflictPolicy,
}

impl ConflictResolver {
    /// Create a new resolver with the given policy.
    #[must_use]
    pub const fn new(policy: ConflictPolicy) -> Self {
        Self { policy }
    }

    /// Resolve a conflict between `existing` and `incoming`.
    ///
    /// Returns `true` if `incoming` should replace `existing`.
    #[must_use]
    pub const fn should_replace(&self, existing: &SymbolEntry, incoming: &SymbolEntry) -> bool {
        match self.policy {
            ConflictPolicy::KeepFirst => false,
            // `KeepAll` is handled differently in the table; here we treat it
            // the same as `KeepLast` (allow replacement / append).
            ConflictPolicy::KeepLast | ConflictPolicy::KeepAll => true,
            ConflictPolicy::HighestPriority => {
                incoming.source.priority() > existing.source.priority()
            }
            ConflictPolicy::PreferLonger => incoming.name.len() > existing.name.len(),
        }
    }

    /// Choose the winner from a list of entries (for `KeepAll` aggregation).
    #[must_use]
    pub fn pick_best<'a>(&self, entries: &'a [SymbolEntry]) -> Option<&'a SymbolEntry> {
        match self.policy {
            ConflictPolicy::HighestPriority => {
                entries.iter().max_by_key(|e| e.source.priority())
            }
            // `KeepAll` aggregation also picks the first entry as the
            // representative for the single-result API.
            ConflictPolicy::KeepFirst | ConflictPolicy::KeepAll => entries.first(),
            ConflictPolicy::KeepLast => entries.last(),
            ConflictPolicy::PreferLonger => {
                entries.iter().max_by_key(|e| e.name.len())
            }
        }
    }
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self::new(ConflictPolicy::HighestPriority)
    }
}

// ─── SymbolTableStats ─────────────────────────────────────────────────────────

/// Statistics snapshot of the symbol table.
#[derive(Debug, Clone, Default)]
pub struct SymbolTableStats {
    /// Total number of entries.
    pub total: usize,
    /// Number of function entries.
    pub functions: usize,
    /// Number of variable entries.
    pub variables: usize,
    /// Number of import entries.
    pub imports: usize,
    /// Number of export entries.
    pub exports: usize,
    /// Number of thunk entries.
    pub thunks: usize,
    /// Entries sourced from PDB.
    pub from_pdb: usize,
    /// Entries sourced from DWARF.
    pub from_dwarf: usize,
    /// Entries sourced from ELF/PE tables.
    pub from_elf: usize,
    /// Entries sourced from FLIRT signatures.
    pub from_flirt: usize,
    /// Entries supplied by the user.
    pub from_user: usize,
    /// Entries inferred by analysis.
    pub from_inferred: usize,
    /// Number of same-address conflicts resolved while building.
    pub conflicts_resolved: usize,
}

impl fmt::Display for SymbolTableStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTableStats {{ total={} fn={} var={} import={} export={} pdb={} dwarf={} elf={} }}",
            self.total,
            self.functions,
            self.variables,
            self.imports,
            self.exports,
            self.from_pdb,
            self.from_dwarf,
            self.from_elf
        )
    }
}

// ─── SymbolTable ─────────────────────────────────────────────────────────────

/// Unified symbol table assembled from multiple sources.
///
/// Primary index: `BTreeMap<address, Vec<SymbolEntry>>`.
/// Name index:    `HashMap<name, Vec<address>>`.
pub struct SymbolTable {
    by_addr: BTreeMap<u64, Vec<SymbolEntry>>,
    by_name: HashMap<String, Vec<u64>>,
    resolver: ConflictResolver,
    conflicts_resolved: usize,
    entry_count: usize,
}

impl SymbolTable {
    /// Create an empty table with the default conflict policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(ConflictPolicy::HighestPriority)
    }

    /// Create an empty table with a specific conflict policy.
    #[must_use]
    pub fn with_policy(policy: ConflictPolicy) -> Self {
        Self {
            by_addr: BTreeMap::new(),
            by_name: HashMap::new(),
            resolver: ConflictResolver::new(policy),
            conflicts_resolved: 0,
            entry_count: 0,
        }
    }

    // ── Insert / merge ────────────────────────────────────────────────────────

    /// Insert a single entry.
    pub fn insert(&mut self, entry: SymbolEntry) {
        let addr = entry.address;
        let name = entry.name.clone();

        if self.resolver.policy == ConflictPolicy::KeepAll {
            self.by_addr.entry(addr).or_default().push(entry);
            self.by_name.entry(name).or_default().push(addr);
            self.entry_count += 1;
            return;
        }

        let existing = self.by_addr.entry(addr).or_default();
        if let Some(same_name_pos) = existing.iter().position(|e| e.name == name) {
            // Same address + same name: merge metadata.
            existing[same_name_pos].merge_metadata(&entry);
        } else if let Some(conflict_pos) = existing.iter().position(|_| true) {
            // Different name, same address: resolve conflict.
            if self.resolver.should_replace(&existing[conflict_pos], &entry) {
                let old_name = existing[conflict_pos].name.clone();
                existing[conflict_pos] = entry;
                // Update name index.
                if let Some(addrs) = self.by_name.get_mut(&old_name) {
                    addrs.retain(|&a| a != addr);
                }
                self.by_name.entry(name).or_default().push(addr);
            }
            // Either replaced or kept the existing entry — both count as a
            // resolved conflict.
            self.conflicts_resolved += 1;
        } else {
            // No existing entry at this address.
            self.by_name.entry(name).or_default().push(addr);
            existing.push(entry);
            self.entry_count += 1;
        }
    }

    /// Batch-insert many entries.
    pub fn insert_many(&mut self, entries: impl IntoIterator<Item = SymbolEntry>) {
        for e in entries {
            self.insert(e);
        }
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Lookup by exact address.
    #[must_use]
    pub fn lookup_addr(&self, addr: u64) -> Option<&SymbolEntry> {
        self.by_addr.get(&addr).and_then(|v| v.first())
    }

    /// Lookup all entries at an exact address.
    #[must_use]
    pub fn lookup_addr_all(&self, addr: u64) -> Vec<&SymbolEntry> {
        self.by_addr
            .get(&addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Lookup by name.
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Vec<&SymbolEntry> {
        self.by_name
            .get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .flat_map(|&a| self.by_addr.get(&a).into_iter().flatten())
                    .filter(|e| e.name == name)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Floor lookup: find the symbol with the largest address ≤ `addr`.
    #[must_use]
    pub fn lookup_floor(&self, addr: u64) -> Option<&SymbolEntry> {
        self.by_addr
            .range(..=addr)
            .next_back()
            .and_then(|(_, v)| v.first())
    }

    /// Find symbols whose name starts with `prefix`.
    #[must_use]
    pub fn lookup_prefix(&self, prefix: &str) -> Vec<&SymbolEntry> {
        self.by_addr
            .values()
            .flatten()
            .filter(|e| e.name.starts_with(prefix))
            .collect()
    }

    /// Find symbols in `[start, end)`.
    #[must_use]
    pub fn lookup_range(&self, start: u64, end: u64) -> Vec<&SymbolEntry> {
        self.by_addr
            .range(start..end)
            .flat_map(|(_, v)| v.iter())
            .collect()
    }

    // ── Remove / rename ───────────────────────────────────────────────────────

    /// Remove the entry at `addr` with the given `name`. Returns true if removed.
    pub fn remove(&mut self, addr: u64, name: &str) -> bool {
        let mut removed = false;
        if let Some(entries) = self.by_addr.get_mut(&addr) {
            let before = entries.len();
            entries.retain(|e| e.name != name);
            let after = entries.len();
            removed = before != after;
            if entries.is_empty() {
                self.by_addr.remove(&addr);
            }
        }
        if removed {
            if let Some(addrs) = self.by_name.get_mut(name) {
                addrs.retain(|&a| a != addr);
                if addrs.is_empty() {
                    self.by_name.remove(name);
                }
            }
            self.entry_count = self.entry_count.saturating_sub(1);
        }
        removed
    }

    /// Rename a symbol at `addr` from `old_name` to `new_name`.
    pub fn rename(&mut self, addr: u64, old_name: &str, new_name: &str) -> bool {
        if let Some(entries) = self.by_addr.get_mut(&addr)
            && let Some(e) = entries.iter_mut().find(|e| e.name == old_name) {
                e.name = new_name.to_string();
                e.source = SymbolSource::User;
                e.confidence = SymbolConfidence::MAX;
                e.updated_at = SystemTime::now();

                // Update name index.
                if let Some(addrs) = self.by_name.get_mut(old_name) {
                    addrs.retain(|&a| a != addr);
                    if addrs.is_empty() {
                        self.by_name.remove(old_name);
                    }
                }
                self.by_name.entry(new_name.to_string()).or_default().push(addr);
                return true;
            }
        false
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_addr.values().map(Vec::len).sum()
    }

    /// True if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    /// Iterate over all entries in address order.
    pub fn iter(&self) -> impl Iterator<Item = &SymbolEntry> {
        self.by_addr.values().flatten()
    }

    /// Compute table statistics.
    #[must_use]
    pub fn stats(&self) -> SymbolTableStats {
        let mut s = SymbolTableStats {
            conflicts_resolved: self.conflicts_resolved,
            ..Default::default()
        };
        for e in self.iter() {
            s.total += 1;
            match e.kind {
                SymbolKind::Function => s.functions += 1,
                SymbolKind::Variable => s.variables += 1,
                SymbolKind::Import => s.imports += 1,
                SymbolKind::Export => s.exports += 1,
                SymbolKind::Thunk => s.thunks += 1,
                _ => {}
            }
            match e.source {
                SymbolSource::Pdb => s.from_pdb += 1,
                SymbolSource::Dwarf => s.from_dwarf += 1,
                SymbolSource::Elf => s.from_elf += 1,
                SymbolSource::Flirt => s.from_flirt += 1,
                SymbolSource::User => s.from_user += 1,
                SymbolSource::Inferred => s.from_inferred += 1,
                _ => {}
            }
        }
        s
    }

    // ── Merge ─────────────────────────────────────────────────────────────────

    /// Merge all entries from `other` into this table.
    pub fn merge(&mut self, other: &Self) {
        for e in other.iter() {
            self.insert(e.clone());
        }
    }

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export to MAP format (address + name).
    #[must_use]
    pub fn export_map(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("# Address           Name\n");
        for e in self.iter() {
            writeln!(out, "{:#018x}  {}", e.address, e.name)
                .expect("writing to String never fails");
        }
        out
    }

    /// Export to CSV.
    #[must_use]
    pub fn export_csv(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("address,name,demangled,kind,source,confidence,size\n");
        for e in self.iter() {
            writeln!(
                out,
                "{:#x},{},{},{},{},{:.2},{}",
                e.address,
                e.name,
                e.demangled_name.as_deref().unwrap_or(""),
                e.kind,
                e.source,
                e.confidence.value(),
                e.size.map_or_else(|| "?".into(), |n| n.to_string()),
            )
            .expect("writing to String never fails");
        }
        out
    }

    /// Find symbols with confidence below `threshold`.
    #[must_use]
    pub fn low_confidence(&self, threshold: f64) -> Vec<&SymbolEntry> {
        self.iter()
            .filter(|e| !e.confidence.meets_threshold(threshold))
            .collect()
    }

    /// Count how many conflicts were resolved during assembly.
    #[must_use]
    pub const fn conflicts_resolved(&self) -> usize {
        self.conflicts_resolved
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SymbolTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymbolTable(entries={})", self.len())
    }
}

// ─── SymbolTableBuilder ───────────────────────────────────────────────────────

/// Fluent builder for assembling a [`SymbolTable`] from multiple sources.
pub struct SymbolTableBuilder {
    entries: Vec<SymbolEntry>,
    policy: ConflictPolicy,
}

impl SymbolTableBuilder {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            policy: ConflictPolicy::HighestPriority,
        }
    }

    /// Set the conflict resolution policy.
    #[must_use]
    pub const fn policy(mut self, p: ConflictPolicy) -> Self {
        self.policy = p;
        self
    }

    // ── Source importers ─────────────────────────────────────────────────────

    /// Import ELF symbol table entries.
    pub fn add_elf_symbols(&mut self, syms: impl IntoIterator<Item = (String, u64, SymbolKind, Option<u64>)>) -> &mut Self {
        for (name, addr, kind, size) in syms {
            let mut e = SymbolEntry::new(name, addr, kind, SymbolSource::Elf);
            e.size = size;
            self.entries.push(e);
        }
        self
    }

    /// Import PE export table entries.
    pub fn add_pe_exports(
        &mut self,
        syms: impl IntoIterator<Item = (String, u64, Option<u32>)>,
    ) -> &mut Self {
        for (name, addr, ordinal) in syms {
            let mut e = SymbolEntry::new(name, addr, SymbolKind::Export, SymbolSource::PeExport);
            e.ordinal = ordinal;
            e.is_external = true;
            self.entries.push(e);
        }
        self
    }

    /// Import PE import table entries.
    pub fn add_pe_imports(
        &mut self,
        syms: impl IntoIterator<Item = (String, u64, String)>,
    ) -> &mut Self {
        for (name, addr, module) in syms {
            let mut e = SymbolEntry::new(name, addr, SymbolKind::Import, SymbolSource::PeImport);
            e.module = Some(module);
            self.entries.push(e);
        }
        self
    }

    /// Import PDB symbol records.
    pub fn add_pdb_symbols(
        &mut self,
        syms: impl IntoIterator<Item = (String, u64, SymbolKind, Option<u64>)>,
    ) -> &mut Self {
        for (name, addr, kind, size) in syms {
            let mut e = SymbolEntry::new(name, addr, kind, SymbolSource::Pdb);
            e.size = size;
            self.entries.push(e);
        }
        self
    }

    /// Import FLIRT matches.
    pub fn add_flirt_matches(
        &mut self,
        syms: impl IntoIterator<Item = (String, u64, u64)>,
    ) -> &mut Self {
        for (name, addr, size) in syms {
            let mut e = SymbolEntry::new(name, addr, SymbolKind::Function, SymbolSource::Flirt);
            e.size = Some(size);
            self.entries.push(e);
        }
        self
    }

    /// Import user-defined names (highest priority).
    pub fn add_user_names(
        &mut self,
        syms: impl IntoIterator<Item = (String, u64)>,
    ) -> &mut Self {
        for (name, addr) in syms {
            let e = SymbolEntry::new(name, addr, SymbolKind::Unknown, SymbolSource::User);
            self.entries.push(e);
        }
        self
    }

    /// Add arbitrary entries.
    pub fn add_entries(
        &mut self,
        entries: impl IntoIterator<Item = SymbolEntry>,
    ) -> &mut Self {
        self.entries.extend(entries);
        self
    }

    /// Finalize and build the [`SymbolTable`].
    #[must_use]
    pub fn build(self) -> SymbolTable {
        let mut table = SymbolTable::with_policy(self.policy);
        for e in self.entries {
            table.insert(e);
        }
        table
    }
}

impl Default for SymbolTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, addr: u64, source: SymbolSource) -> SymbolEntry {
        SymbolEntry::new(name, addr, SymbolKind::Function, source)
    }

    #[test]
    fn source_priority_ordering() {
        assert!(SymbolSource::User.priority() > SymbolSource::Pdb.priority());
        assert!(SymbolSource::Pdb.priority() > SymbolSource::Flirt.priority());
        assert!(SymbolSource::Flirt.priority() > SymbolSource::Inferred.priority());
    }

    #[test]
    fn confidence_from_source() {
        let c = SymbolConfidence::from_source(SymbolSource::User);
        assert!((c.value() - 1.0).abs() < 1e-9);
        let c2 = SymbolConfidence::from_source(SymbolSource::Inferred);
        assert!(c2.value() < c.value());
    }

    #[test]
    fn confidence_clamp() {
        let c = SymbolConfidence::new(1.5);
        assert!((c.value() - 1.0).abs() < 1e-9);
        let c2 = SymbolConfidence::new(-0.1);
        assert!((c2.value()).abs() < 1e-9);
    }

    #[test]
    fn symbol_entry_display() {
        let e = make_entry("foo", 0x1000, SymbolSource::Elf);
        let s = e.to_string();
        assert!(s.contains("foo"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn symbol_entry_contains() {
        let mut e = make_entry("f", 0x1000, SymbolSource::Elf);
        e.size = Some(0x100);
        assert!(e.contains(0x1000));
        assert!(e.contains(0x10ff));
        assert!(!e.contains(0x1100));
    }

    #[test]
    fn symbol_entry_merge_metadata() {
        let mut a = make_entry("foo", 0x1000, SymbolSource::Elf);
        let mut b = make_entry("foo", 0x1000, SymbolSource::Pdb);
        b.size = Some(0x80);
        a.merge_metadata(&b);
        assert_eq!(a.size, Some(0x80));
        assert!(a.sources.contains(&SymbolSource::Pdb));
    }

    #[test]
    fn table_insert_single() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("main", 0x0040_1000, SymbolSource::Elf));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_lookup_addr() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("main", 0x0040_1000, SymbolSource::Elf));
        assert!(t.lookup_addr(0x0040_1000).is_some());
        assert!(t.lookup_addr(0x0040_2000).is_none());
    }

    #[test]
    fn table_lookup_name() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("foo", 0x1000, SymbolSource::Elf));
        assert!(!t.lookup_name("foo").is_empty());
        assert!(t.lookup_name("bar").is_empty());
    }

    #[test]
    fn table_conflict_highest_priority() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("elf_name", 0x1000, SymbolSource::Elf));
        t.insert(make_entry("pdb_name", 0x1000, SymbolSource::Pdb));
        // PDB has higher priority → pdb_name wins.
        let e = t.lookup_addr(0x1000).unwrap();
        assert_eq!(e.name, "pdb_name");
    }

    #[test]
    fn table_conflict_keep_first() {
        let mut t = SymbolTable::with_policy(ConflictPolicy::KeepFirst);
        t.insert(make_entry("first", 0x1000, SymbolSource::Elf));
        t.insert(make_entry("second", 0x1000, SymbolSource::Pdb));
        let e = t.lookup_addr(0x1000).unwrap();
        assert_eq!(e.name, "first");
    }

    #[test]
    fn table_rename() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("old_name", 0x1000, SymbolSource::Elf));
        assert!(t.rename(0x1000, "old_name", "new_name"));
        let e = t.lookup_addr(0x1000).unwrap();
        assert_eq!(e.name, "new_name");
        assert_eq!(e.source, SymbolSource::User);
    }

    #[test]
    fn table_remove() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("foo", 0x1000, SymbolSource::Elf));
        assert!(t.remove(0x1000, "foo"));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn table_stats() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("a", 0x1000, SymbolSource::Pdb));
        t.insert(make_entry("b", 0x2000, SymbolSource::Elf));
        let s = t.stats();
        assert_eq!(s.total, 2);
        assert_eq!(s.functions, 2);
        assert_eq!(s.from_pdb, 1);
        assert_eq!(s.from_elf, 1);
    }

    #[test]
    fn table_floor_lookup() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("a", 0x1000, SymbolSource::Elf));
        t.insert(make_entry("b", 0x3000, SymbolSource::Elf));
        let e = t.lookup_floor(0x2000).unwrap();
        assert_eq!(e.name, "a");
    }

    #[test]
    fn table_merge() {
        let mut t1 = SymbolTable::new();
        let mut t2 = SymbolTable::new();
        t1.insert(make_entry("a", 0x1000, SymbolSource::Elf));
        t2.insert(make_entry("b", 0x2000, SymbolSource::Pdb));
        t1.merge(&t2);
        assert_eq!(t1.len(), 2);
    }

    #[test]
    fn builder_add_elf_and_pdb() {
        let mut b = SymbolTableBuilder::new();
        b.add_elf_symbols(vec![("elf_func".to_string(), 0x1000, SymbolKind::Function, Some(64))]);
        b.add_pdb_symbols(vec![("pdb_func".to_string(), 0x2000, SymbolKind::Function, None)]);
        let t = b.build();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn builder_pe_exports() {
        let mut b = SymbolTableBuilder::new();
        b.add_pe_exports(vec![("ExportedFn".to_string(), 0x4000, Some(1))]);
        let t = b.build();
        let e = t.lookup_addr(0x4000).unwrap();
        assert_eq!(e.kind, SymbolKind::Export);
        assert_eq!(e.ordinal, Some(1));
    }

    #[test]
    fn export_csv_contains_header() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("foo", 0x1000, SymbolSource::Elf));
        let csv = t.export_csv();
        assert!(csv.starts_with("address,name"));
        assert!(csv.contains("foo"));
    }

    #[test]
    fn low_confidence_filter() {
        let mut t = SymbolTable::new();
        t.insert(make_entry("inferred_fn", 0x1000, SymbolSource::Inferred));
        t.insert(make_entry("user_fn", 0x2000, SymbolSource::User));
        let low = t.low_confidence(0.5);
        assert_eq!(low.len(), 1);
        assert_eq!(low[0].name, "inferred_fn");
    }
}
