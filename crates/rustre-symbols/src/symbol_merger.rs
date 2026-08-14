//! `symbol_merger.rs` — Multi-source symbol merger.
//!
//! [`SymbolMerger`] aggregates symbols from multiple [`SymbolProvider`]s,
//! resolves conflicts using a configurable priority order, optionally applies
//! demangling, and produces a [`UnifiedSymbolTable`].
//!
//! Default source priority (highest → lowest):
//! 1. Manual  (user annotations)
//! 2. PDB
//! 3. DWARF
//! 4. `CodeView` / STABS
//! 5. FLIRT
//! 6. ELF / PE symbol tables
//! 7. Synthetic (auto-generated `sub_XXXX`)
//!
//! [`MergeConflict`] records every address where two providers gave different
//! names, allowing audit after the merge.
//!
//! The merger also deduplicates by (address, name), strips null symbols, and
//! optionally filters to a given address range.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DemanglerPipeline, LegacySymbolSource, SymKind, Symbol, SymbolKind, SymbolProvider,
    SymbolSource, SyntheticSymbolGen, UnifiedSymbol, UnifiedSymbolTable,
};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors raised while merging symbols from multiple providers.
#[derive(Debug, Error)]
pub enum MergeError {
    /// A provider supplied no symbols.
    #[error("provider '{0}' is empty")]
    EmptyProvider(String),
    /// No providers were registered to merge.
    #[error("no providers registered")]
    NoProviders,
    /// A demangler failed on the given name (name, reason).
    #[error("demangling failed for '{0}': {1}")]
    DemanglingFailed(String, String),
    /// Any other error, carrying a message.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias for merge operations.
pub type Result<T> = std::result::Result<T, MergeError>;

// ── MergeConflict ─────────────────────────────────────────────────────────────

/// Recorded when two providers supply different names for the same address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeConflict {
    /// Address where the conflict occurred.
    pub address: u64,
    /// Name chosen (winner).
    pub winner_name: String,
    /// Source of the winner.
    pub winner_source: SymbolSource,
    /// Name discarded (loser).
    pub loser_name: String,
    /// Source of the loser.
    pub loser_source: SymbolSource,
}

impl MergeConflict {
    /// Record a conflict between a chosen (winner) and discarded (loser) symbol
    /// at the same address.
    pub fn new(
        address: u64,
        winner_name: impl Into<String>,
        winner_source: SymbolSource,
        loser_name: impl Into<String>,
        loser_source: SymbolSource,
    ) -> Self {
        Self {
            address,
            winner_name: winner_name.into(),
            winner_source,
            loser_name: loser_name.into(),
            loser_source,
        }
    }
}

impl std::fmt::Display for MergeConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#x}: {:?}/'{}' beats {:?}/'{}'",
            self.address, self.winner_source, self.winner_name, self.loser_source, self.loser_name
        )
    }
}

// ── MergeStats ────────────────────────────────────────────────────────────────

/// Summary statistics from a merge operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MergeStats {
    /// Number of providers merged.
    pub providers_consulted: usize,
    /// Total symbols read across all providers, before merging.
    pub total_symbols_input: usize,
    /// Symbols remaining after merging and conflict resolution.
    pub total_symbols_output: usize,
    /// Number of same-address conflicts resolved.
    pub conflicts_resolved: usize,
    /// Number of empty/null-named symbols dropped.
    pub null_symbols_skipped: usize,
    /// Number of symbols that were successfully demangled.
    pub demangled_count: usize,
    /// Number of synthetic symbols added for otherwise-unnamed addresses.
    pub synthetic_added: usize,
}

impl std::fmt::Display for MergeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MergeStats {{ providers={}, input={}, output={}, conflicts={}, demangled={}, synthetic={} }}",
            self.providers_consulted,
            self.total_symbols_input,
            self.total_symbols_output,
            self.conflicts_resolved,
            self.demangled_count,
            self.synthetic_added,
        )
    }
}

// ── MergeConfig ───────────────────────────────────────────────────────────────

/// Policy for handling multiple symbols at the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicatePolicy {
    /// Keep one symbol per address (default winner-takes-all).
    Deduplicate,
    /// Keep multiple symbols at the same address (one per provider).
    Keep,
}

/// Configuration for a merge operation.
#[derive(Debug, Clone)]
pub struct MergeConfig {
    /// Apply demangling pipeline to all symbols.
    pub demangle: bool,
    /// Add synthetic `sub_XXXX` symbols for any addresses without a name.
    pub fill_synthetic: bool,
    /// Address range to restrict output to (if set).
    pub addr_range: Option<(u64, u64)>,
    /// If true, skip symbols whose name is empty or starts with `__unnamed`.
    pub skip_unnamed: bool,
    /// Minimum name length to include (0 = include all).
    pub min_name_len: usize,
    /// Policy for multiple symbols at the same address.
    pub duplicate_policy: DuplicatePolicy,
    /// Extra function addresses to fill with synthetic names.
    pub synthetic_addrs: Vec<u64>,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            demangle: true,
            fill_synthetic: false,
            addr_range: None,
            skip_unnamed: true,
            min_name_len: 1,
            duplicate_policy: DuplicatePolicy::Deduplicate,
            synthetic_addrs: Vec::new(),
        }
    }
}

impl MergeConfig {
    /// Create a config with default settings (demangle on, skip unnamed, dedupe).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Disable the demangling pass (builder style).
    #[must_use]
    pub const fn no_demangle(mut self) -> Self {
        self.demangle = false;
        self
    }
    /// Enable synthetic-name filling for unnamed addresses (builder style).
    #[must_use]
    pub const fn fill_synthetic(mut self) -> Self {
        self.fill_synthetic = true;
        self
    }
    /// Restrict output to the half-open address range `[lo, hi)` (builder style).
    #[must_use]
    pub const fn addr_range(mut self, lo: u64, hi: u64) -> Self {
        self.addr_range = Some((lo, hi));
        self
    }
    /// Keep empty/`__unnamed` symbols instead of skipping them (builder style).
    #[must_use]
    pub const fn keep_unnamed(mut self) -> Self {
        self.skip_unnamed = false;
        self
    }
    /// Set the extra addresses to fill with synthetic names (builder style).
    #[must_use]
    pub fn with_synthetic_addrs(mut self, addrs: Vec<u64>) -> Self {
        self.synthetic_addrs = addrs;
        self
    }

    const fn passes_range(&self, addr: u64) -> bool {
        match self.addr_range {
            Some((lo, hi)) => addr >= lo && addr < hi,
            None => true,
        }
    }

    fn passes_name(&self, name: &str) -> bool {
        if self.skip_unnamed && (name.is_empty() || name.starts_with("__unnamed")) {
            return false;
        }
        name.len() >= self.min_name_len
    }
}

// ── ProviderEntry ─────────────────────────────────────────────────────────────

/// A registered provider with its declared source type.
struct ProviderEntry {
    provider: Box<dyn SymbolProvider>,
    source: SymbolSource,
}

// ── SymbolMerger ──────────────────────────────────────────────────────────────

/// Aggregates symbols from multiple [`SymbolProvider`]s into a
/// [`UnifiedSymbolTable`].
pub struct SymbolMerger {
    providers: Vec<ProviderEntry>,
    config: MergeConfig,
    conflicts: Vec<MergeConflict>,
    stats: MergeStats,
}

impl SymbolMerger {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create an empty merger with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            config: MergeConfig::default(),
            conflicts: Vec::new(),
            stats: MergeStats::default(),
        }
    }

    /// Create an empty merger with the given config.
    #[must_use]
    pub fn with_config(config: MergeConfig) -> Self {
        Self {
            providers: Vec::new(),
            config,
            conflicts: Vec::new(),
            stats: MergeStats::default(),
        }
    }

    // ── Provider registration ─────────────────────────────────────────────────

    /// Register a provider with an explicit source tag.
    pub fn add_provider(&mut self, provider: Box<dyn SymbolProvider>, source: SymbolSource) {
        self.providers.push(ProviderEntry { provider, source });
    }

    /// Register a provider, inferring source from `SymbolSource::Pdb`.
    pub fn add_pdb_provider(&mut self, provider: Box<dyn SymbolProvider>) {
        self.add_provider(provider, SymbolSource::Pdb);
    }

    /// Register a DWARF provider.
    pub fn add_dwarf_provider(&mut self, provider: Box<dyn SymbolProvider>) {
        self.add_provider(provider, SymbolSource::Dwarf);
    }

    /// Register an ELF/PE symbol table provider.
    pub fn add_elf_provider(&mut self, provider: Box<dyn SymbolProvider>) {
        self.add_provider(provider, SymbolSource::Elf);
    }

    /// Register a synthetic / auto-generated provider.
    pub fn add_synthetic_provider(&mut self, provider: Box<dyn SymbolProvider>) {
        self.add_provider(provider, SymbolSource::Inferred);
    }

    /// Number of registered providers.
    #[must_use]
    pub const fn provider_count(&self) -> usize {
        self.providers.len()
    }

    // ── Config ────────────────────────────────────────────────────────────────

    /// Replace the merge configuration.
    pub fn set_config(&mut self, config: MergeConfig) {
        self.config = config;
    }
    /// Borrow the merge configuration.
    #[must_use]
    pub const fn config(&self) -> &MergeConfig {
        &self.config
    }
    /// Mutably borrow the merge configuration.
    pub const fn config_mut(&mut self) -> &mut MergeConfig {
        &mut self.config
    }

    // ── Results ───────────────────────────────────────────────────────────────

    /// The conflicts recorded by the last merge.
    #[must_use]
    pub fn conflicts(&self) -> &[MergeConflict] {
        &self.conflicts
    }
    /// The statistics from the last merge.
    #[must_use]
    pub const fn stats(&self) -> &MergeStats {
        &self.stats
    }
    /// Take ownership of the recorded conflicts, clearing them from the merger.
    pub fn take_conflicts(&mut self) -> Vec<MergeConflict> {
        std::mem::take(&mut self.conflicts)
    }

    // ── Core merge ────────────────────────────────────────────────────────────

    /// Run the merge and return the unified symbol table.
    ///
    /// # Errors
    ///
    /// Returns `MergeError::NoProviders` if no providers have been registered.
    pub fn merge_all(&mut self) -> Result<UnifiedSymbolTable> {
        if self.providers.is_empty() {
            return Err(MergeError::NoProviders);
        }

        let mut table = UnifiedSymbolTable::new();
        let mut stats = MergeStats {
            providers_consulted: self.providers.len(),
            ..MergeStats::default()
        };

        // Gather all symbols from all providers, tagged with source.
        let mut all: Vec<(Symbol, SymbolSource)> = Vec::new();
        for entry in &self.providers {
            let syms = entry.provider.all_symbols();
            stats.total_symbols_input += syms.len();
            for sym in syms {
                all.push((sym, entry.source));
            }
        }

        // Sort by source priority descending (highest first) so that when we
        // add_or_upgrade, higher-priority sources win.
        all.sort_by_key(|(_, src)| std::cmp::Reverse(src.priority()));

        // Conflict detection: track (address → first chosen symbol)
        let mut seen_at: HashMap<u64, (String, SymbolSource)> = HashMap::new();

        for (sym, source) in all {
            if sym.name.is_empty() {
                stats.null_symbols_skipped += 1;
                continue;
            }
            if !self.config.passes_name(&sym.name) {
                stats.null_symbols_skipped += 1;
                continue;
            }
            if !self.config.passes_range(sym.address) {
                continue;
            }

            // Convert to UnifiedSymbol
            let kind = legacy_to_unified_kind(sym.kind);
            let mut usym = UnifiedSymbol::new(sym.name.clone(), sym.address, kind, source);
            usym.size = sym.size;
            usym.is_external = matches!(
                sym.binding,
                crate::SymbolBinding::Global | crate::SymbolBinding::Weak
            );
            // Track the legacy provenance tag on the unified record so that
            // round-trips back through the v1 [`Symbol`] taxonomy stay faithful
            // (e.g. preserving the Debug/Dynamic/Import/Export distinction that
            // `SymbolSource` collapses into a coarser bucket).
            let legacy: LegacySymbolSource = sym.source;
            usym.module = Some(format!("{legacy:?}"));

            // Conflict detection
            if let Some((existing_name, existing_src)) = seen_at.get(&sym.address) {
                if *existing_name != sym.name {
                    // Only log if the new symbol would actually win
                    match source.priority().cmp(&existing_src.priority()) {
                        std::cmp::Ordering::Greater => {
                            self.conflicts.push(MergeConflict::new(
                                sym.address,
                                sym.name.clone(),
                                source,
                                existing_name.clone(),
                                *existing_src,
                            ));
                            stats.conflicts_resolved += 1;
                            seen_at.insert(sym.address, (sym.name.clone(), source));
                        }
                        std::cmp::Ordering::Less => {
                            self.conflicts.push(MergeConflict::new(
                                sym.address,
                                existing_name.clone(),
                                *existing_src,
                                sym.name.clone(),
                                source,
                            ));
                            stats.conflicts_resolved += 1;
                        }
                        std::cmp::Ordering::Equal => {
                            // Equal priority: log conflict, existing entry keeps seen_at
                            self.conflicts.push(MergeConflict::new(
                                sym.address,
                                existing_name.clone(),
                                *existing_src,
                                sym.name.clone(),
                                source,
                            ));
                            stats.conflicts_resolved += 1;
                        }
                    }
                }
            } else {
                seen_at.insert(sym.address, (sym.name.clone(), source));
            }

            // Add to table (add_or_upgrade respects source priority)
            table.add_or_upgrade(usym);
        }

        stats.total_symbols_output = table.len();

        // Demangling pass
        if self.config.demangle {
            let mut pipeline = DemanglerPipeline::new();
            pipeline.demangle_table(&mut table);
            // Count how many got a demangled_name
            stats.demangled_count = table
                .iter_by_address()
                .filter(|s| s.demangled_name.is_some())
                .count();
        }

        // Synthetic fill
        if self.config.fill_synthetic && !self.config.synthetic_addrs.is_empty() {
            let before = table.len();
            SyntheticSymbolGen::fill_functions(&mut table, &self.config.synthetic_addrs);
            stats.synthetic_added = table.len() - before;
        }

        self.stats = stats;
        Ok(table)
    }

    /// Convenience: register providers and merge in one call.
    ///
    /// # Errors
    ///
    /// Propagates `MergeError` from the underlying `merge_all` invocation.
    pub fn merge_providers(
        providers: Vec<(Box<dyn SymbolProvider>, SymbolSource)>,
        config: MergeConfig,
    ) -> Result<(UnifiedSymbolTable, MergeStats, Vec<MergeConflict>)> {
        let mut merger = Self::with_config(config);
        for (p, s) in providers {
            merger.add_provider(p, s);
        }
        let table = merger.merge_all()?;
        let stats = merger.stats().clone();
        let conflicts = merger.take_conflicts();
        Ok((table, stats, conflicts))
    }
}

impl Default for SymbolMerger {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The single `SymKind` → `SymbolKind` mapping for the whole crate.
///
/// Exhaustive on purpose: the compiler, not a reviewer, is what guarantees a
/// new `SymKind` variant gets a deliberate answer here. The DWARF and STABS
/// providers used to carry their own copies of this conversion, each ending in
/// a *different* catch-all (`_ => Label` and `_ => Variable`), so the three
/// disagreed for six of the eleven variants. They agreed on the only kinds
/// those providers actually emit — `Function` and `Data` — which is why the
/// divergence never surfaced; it was latent, not harmless.
pub(crate) const fn legacy_to_unified_kind(k: SymKind) -> SymbolKind {
    // Data-like, Type, and Unknown all map onto the catch-all Variable kind.
    match k {
        SymKind::Function | SymKind::IFunc => SymbolKind::Function,
        SymKind::Data | SymKind::Common | SymKind::TLS | SymKind::Type | SymKind::Unknown => {
            SymbolKind::Variable
        }
        SymKind::Label => SymbolKind::Label,
        SymKind::Section => SymbolKind::Section,
        SymKind::File => SymbolKind::Module,
        SymKind::Namespace => SymbolKind::Namespace,
    }
}

// ── PriorityMergePolicy ────────────────────────────────────────────────────────

/// A standalone policy object for choosing between two conflicting symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePriority {
    /// Use source priority from [`SymbolSource::priority`].
    BySourcePriority,
    /// Always prefer the longer name (heuristic: more descriptive).
    LongerName,
    /// Always prefer the shorter name.
    ShorterName,
    /// Keep the symbol that was encountered first.
    KeepFirst,
    /// Keep the symbol that was encountered last.
    KeepLast,
}

impl MergePriority {
    /// Choose the winner between `a` (`source_a`) and `b` (`source_b`).
    /// Returns `true` if `a` wins, `false` if `b` wins.
    #[must_use]
    pub const fn a_wins(
        self,
        name_a: &str,
        source_a: SymbolSource,
        name_b: &str,
        source_b: SymbolSource,
    ) -> bool {
        match self {
            Self::BySourcePriority => source_a.priority() >= source_b.priority(),
            Self::LongerName => name_a.len() >= name_b.len(),
            Self::ShorterName => name_a.len() <= name_b.len(),
            Self::KeepFirst => true,
            Self::KeepLast => false,
        }
    }
}

// ── DeduplicatedMerge ─────────────────────────────────────────────────────────

/// Simple helper to merge two [`UnifiedSymbolTable`]s without full [`SymbolMerger`].
#[must_use]
pub fn merge_tables(
    mut primary: UnifiedSymbolTable,
    secondary: &UnifiedSymbolTable,
) -> UnifiedSymbolTable {
    for sym in secondary.iter_by_address() {
        // If primary has any symbol at this address whose source has strictly
        // lower priority than the secondary's, replace it with the secondary
        // entry (upgrade). Otherwise, add (or upgrade by name) normally.
        let addr = sym.address;
        let should_upgrade_by_addr = primary
            .symbols
            .get(&addr)
            .is_some_and(|v| {
                v.iter()
                    .any(|existing| sym.source.priority() > existing.source.priority())
            });
        if should_upgrade_by_addr {
            // Collect existing names to drop those of lower priority.
            let to_remove: Vec<String> = primary
                .symbols
                .get(&addr)
                .map(|v| {
                    v.iter()
                        .filter(|e| sym.source.priority() > e.source.priority())
                        .map(|e| e.name.clone())
                        .collect()
                })
                .unwrap_or_default();
            for n in to_remove {
                primary.remove(addr, &n);
            }
            primary.add(sym.clone());
        } else {
            primary.add_or_upgrade(sym.clone());
        }
    }
    primary
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemorySymbolProvider, SymbolSource};

    fn make_fn_sym(name: &str, addr: u64) -> Symbol {
        Symbol::new(name.to_string(), addr, SymKind::Function)
    }

    fn make_data_sym(name: &str, addr: u64) -> Symbol {
        Symbol::new(name.to_string(), addr, SymKind::Data)
    }

    fn in_mem_provider(syms: Vec<Symbol>) -> Box<dyn SymbolProvider> {
        let mut p = InMemorySymbolProvider::new();
        for s in syms {
            p.add(s);
        }
        Box::new(p)
    }

    // ── MergeConflict ──────────────────────────────────────────────────────────

    #[test]
    fn conflict_new() {
        let c = MergeConflict::new(
            0x1000,
            "pdb_name",
            SymbolSource::Pdb,
            "elf_name",
            SymbolSource::Elf,
        );
        assert_eq!(c.address, 0x1000);
        assert_eq!(c.winner_name, "pdb_name");
    }
    #[test]
    fn conflict_display() {
        let c = MergeConflict::new(0x1000, "a", SymbolSource::Pdb, "b", SymbolSource::Elf);
        assert!(c.to_string().contains("0x1000"));
    }

    // ── MergeStats ─────────────────────────────────────────────────────────────

    #[test]
    fn stats_default() {
        let s = MergeStats::default();
        assert_eq!(s.total_symbols_input, 0);
    }
    #[test]
    fn stats_display() {
        let s = MergeStats::default();
        assert!(s.to_string().contains("providers=0"));
    }

    // ── MergeConfig ────────────────────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let c = MergeConfig::default();
        assert!(c.demangle);
        assert!(!c.fill_synthetic);
    }
    #[test]
    fn config_builders() {
        let c = MergeConfig::new()
            .no_demangle()
            .fill_synthetic()
            .addr_range(0x1000, 0x9000)
            .keep_unnamed();
        assert!(!c.demangle);
        assert!(c.fill_synthetic);
        assert_eq!(c.addr_range, Some((0x1000, 0x9000)));
        assert!(!c.skip_unnamed);
    }
    #[test]
    fn config_passes_range() {
        let c = MergeConfig::new().addr_range(0x1000, 0x2000);
        assert!(c.passes_range(0x1500));
        assert!(!c.passes_range(0x500));
        assert!(!c.passes_range(0x2000));
    }
    #[test]
    fn config_passes_range_none() {
        assert!(MergeConfig::new().passes_range(u64::MAX));
    }
    #[test]
    fn config_passes_name_empty() {
        let c = MergeConfig::new();
        assert!(!c.passes_name(""));
    }
    #[test]
    fn config_passes_name_ok() {
        assert!(MergeConfig::new().passes_name("main"));
    }
    #[test]
    fn config_passes_name_unnamed() {
        assert!(!MergeConfig::new().passes_name("__unnamed_0"));
    }
    #[test]
    fn config_keep_unnamed() {
        let c = MergeConfig::new().keep_unnamed();
        assert!(c.passes_name("__unnamed_0"));
    }

    // ── MergePriority ──────────────────────────────────────────────────────────

    #[test]
    fn priority_by_source() {
        assert!(MergePriority::BySourcePriority.a_wins(
            "a",
            SymbolSource::Pdb,
            "b",
            SymbolSource::Elf
        ));
        assert!(!MergePriority::BySourcePriority.a_wins(
            "a",
            SymbolSource::Inferred,
            "b",
            SymbolSource::Pdb
        ));
    }
    #[test]
    fn priority_longer_name() {
        assert!(MergePriority::LongerName.a_wins(
            "longer_name",
            SymbolSource::Elf,
            "sh",
            SymbolSource::Pdb
        ));
    }
    #[test]
    fn priority_shorter_name() {
        assert!(MergePriority::ShorterName.a_wins(
            "a",
            SymbolSource::Elf,
            "bbb",
            SymbolSource::Pdb
        ));
    }
    #[test]
    fn priority_keep_first() {
        assert!(MergePriority::KeepFirst.a_wins(
            "x",
            SymbolSource::Inferred,
            "y",
            SymbolSource::Pdb
        ));
    }
    #[test]
    fn priority_keep_last() {
        assert!(!MergePriority::KeepLast.a_wins(
            "x",
            SymbolSource::Pdb,
            "y",
            SymbolSource::Inferred
        ));
    }

    // ── SymbolMerger — basic ───────────────────────────────────────────────────

    #[test]
    fn merger_no_providers() {
        let mut m = SymbolMerger::new();
        assert!(matches!(m.merge_all(), Err(MergeError::NoProviders)));
    }
    #[test]
    fn merger_single_provider() {
        let mut m = SymbolMerger::new();
        m.add_elf_provider(in_mem_provider(vec![
            make_fn_sym("main", 0x1000),
            make_fn_sym("init", 0x2000),
        ]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.len(), 2);
    }
    #[test]
    fn merger_two_providers_no_overlap() {
        let mut m = SymbolMerger::new();
        m.add_pdb_provider(in_mem_provider(vec![make_fn_sym("foo", 0x1000)]));
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("bar", 0x2000)]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.len(), 2);
    }
    #[test]
    fn merger_two_providers_overlap_pdb_wins() {
        let mut m = SymbolMerger::new();
        // PDB provides a good name; ELF has a generic placeholder
        m.add_pdb_provider(in_mem_provider(vec![make_fn_sym("RealName", 0x1000)]));
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("sub_1000", 0x1000)]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.lookup_addr(0x1000).unwrap().name, "RealName");
    }
    #[test]
    fn merger_conflict_logged() {
        let mut m = SymbolMerger::new();
        m.add_pdb_provider(in_mem_provider(vec![make_fn_sym("pdb_fn", 0x1000)]));
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("elf_fn", 0x1000)]));
        let _ = m.merge_all().unwrap();
        assert!(!m.conflicts().is_empty());
    }
    #[test]
    fn merger_provider_count() {
        let mut m = SymbolMerger::new();
        assert_eq!(m.provider_count(), 0);
        m.add_elf_provider(in_mem_provider(vec![]));
        assert_eq!(m.provider_count(), 1);
    }
    #[test]
    fn merger_stats() {
        let mut m = SymbolMerger::new();
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("f", 0x100)]));
        m.merge_all().unwrap();
        assert_eq!(m.stats().providers_consulted, 1);
        assert_eq!(m.stats().total_symbols_input, 1);
        assert_eq!(m.stats().total_symbols_output, 1);
    }
    #[test]
    fn merger_skips_empty_names() {
        let mut m = SymbolMerger::new();
        m.add_elf_provider(in_mem_provider(vec![
            make_fn_sym("", 0x100),
            make_fn_sym("real_func", 0x200),
        ]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(m.stats().null_symbols_skipped, 1);
    }
    #[test]
    fn merger_addr_range_filter() {
        let mut m = SymbolMerger::with_config(MergeConfig::new().addr_range(0x1000, 0x2000));
        m.add_elf_provider(in_mem_provider(vec![
            make_fn_sym("in_range", 0x1500),
            make_fn_sym("out_of_range", 0x3000),
        ]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.lookup_addr(0x1500).is_some());
    }
    #[test]
    fn merger_synthetic_fill() {
        let config = MergeConfig::new()
            .fill_synthetic()
            .with_synthetic_addrs(vec![0x9000, 0x9100]);
        let mut m = SymbolMerger::with_config(config);
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("existing", 0x1000)]));
        let table = m.merge_all().unwrap();
        assert!(table.lookup_addr(0x9000).is_some());
        assert!(table.lookup_addr(0x9100).is_some());
        assert!(m.stats().synthetic_added > 0);
    }
    #[test]
    fn merger_no_demangle() {
        let config = MergeConfig::new().no_demangle();
        let mut m = SymbolMerger::with_config(config);
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("_ZN3fooEv", 0x1000)]));
        let table = m.merge_all().unwrap();
        // With no_demangle, demangled_name should be None
        assert!(table.lookup_addr(0x1000).unwrap().demangled_name.is_none());
    }
    #[test]
    fn merger_take_conflicts() {
        let mut m = SymbolMerger::new();
        m.add_pdb_provider(in_mem_provider(vec![make_fn_sym("pdb_fn", 0x1000)]));
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("elf_fn", 0x1000)]));
        m.merge_all().unwrap();
        let conflicts = m.take_conflicts();
        assert!(!conflicts.is_empty());
        assert!(m.conflicts().is_empty()); // taken away
    }
    #[test]
    fn merger_multiple_data_symbols() {
        let mut m = SymbolMerger::new();
        m.add_elf_provider(in_mem_provider(vec![
            make_data_sym("g_foo", 0x5000),
            make_data_sym("g_bar", 0x6000),
            make_fn_sym("process", 0x7000),
        ]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.len(), 3);
    }
    #[test]
    fn merger_dwarf_over_elf() {
        let mut m = SymbolMerger::new();
        m.add_dwarf_provider(in_mem_provider(vec![make_fn_sym("dwarf_name", 0x1000)]));
        m.add_elf_provider(in_mem_provider(vec![make_fn_sym("elf_name", 0x1000)]));
        let table = m.merge_all().unwrap();
        assert_eq!(table.lookup_addr(0x1000).unwrap().name, "dwarf_name");
    }

    // ── merge_providers convenience ────────────────────────────────────────────

    #[test]
    fn merge_providers_convenience() {
        let providers: Vec<(Box<dyn SymbolProvider>, SymbolSource)> = vec![
            (
                in_mem_provider(vec![make_fn_sym("a", 0x100)]),
                SymbolSource::Elf,
            ),
            (
                in_mem_provider(vec![make_fn_sym("b", 0x200)]),
                SymbolSource::Dwarf,
            ),
        ];
        let (table, stats, _conflicts) =
            SymbolMerger::merge_providers(providers, MergeConfig::default()).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(stats.providers_consulted, 2);
    }
    #[test]
    fn merge_providers_no_providers() {
        let result = SymbolMerger::merge_providers(vec![], MergeConfig::default());
        assert!(result.is_err());
    }

    // ── merge_tables ──────────────────────────────────────────────────────────

    #[test]
    fn merge_tables_basic() {
        let mut t1 = UnifiedSymbolTable::new();
        t1.add(UnifiedSymbol::new(
            "a".into(),
            0x100,
            SymbolKind::Function,
            SymbolSource::Elf,
        ));
        let mut t2 = UnifiedSymbolTable::new();
        t2.add(UnifiedSymbol::new(
            "b".into(),
            0x200,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        let merged = merge_tables(t1, &t2);
        assert_eq!(merged.len(), 2);
    }
    #[test]
    fn merge_tables_upgrade() {
        let mut t1 = UnifiedSymbolTable::new();
        t1.add(UnifiedSymbol::new(
            "inferred".into(),
            0x100,
            SymbolKind::Function,
            SymbolSource::Inferred,
        ));
        let mut t2 = UnifiedSymbolTable::new();
        t2.add(UnifiedSymbol::new(
            "pdb_name".into(),
            0x100,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        let merged = merge_tables(t1, &t2);
        assert_eq!(merged.lookup_addr(0x100).unwrap().source, SymbolSource::Pdb);
    }

    // ── legacy_to_unified_kind ────────────────────────────────────────────────

    #[test]
    fn kind_fn() {
        assert_eq!(
            legacy_to_unified_kind(SymKind::Function),
            SymbolKind::Function
        );
    }
    #[test]
    fn kind_data() {
        assert_eq!(legacy_to_unified_kind(SymKind::Data), SymbolKind::Variable);
    }
    #[test]
    fn kind_label() {
        assert_eq!(legacy_to_unified_kind(SymKind::Label), SymbolKind::Label);
    }
    #[test]
    fn kind_section() {
        assert_eq!(
            legacy_to_unified_kind(SymKind::Section),
            SymbolKind::Section
        );
    }
    #[test]
    fn kind_tls() {
        assert_eq!(legacy_to_unified_kind(SymKind::TLS), SymbolKind::Variable);
    }
    #[test]
    fn kind_ifunc() {
        assert_eq!(legacy_to_unified_kind(SymKind::IFunc), SymbolKind::Function);
    }
}
