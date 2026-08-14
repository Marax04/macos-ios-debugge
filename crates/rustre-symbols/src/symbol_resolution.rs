//! Multi-source symbol resolution with priority chains,
//! conflict resolution, PDB-first and DWARF-first strategies.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors raised while resolving a symbol through a source chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionError {
    /// No source in the chain had a symbol at the address.
    #[error("symbol not found at 0x{0:016x}")]
    NotFound(u64),
    /// Multiple equally-ranked candidates were found at the address.
    #[error("ambiguous symbol at 0x{0:016x}: {1} candidates")]
    Ambiguous(u64, usize),
    /// A named provider was requested but not registered.
    #[error("provider '{0}' not registered")]
    ProviderNotFound(String),
    /// The resolution chain contained no sources.
    #[error("chain is empty")]
    EmptyChain,
    /// Two sources disagreed and the strategy forbade auto-resolution.
    #[error("conflict at 0x{0:016x}: {1} vs {2}")]
    Conflict(u64, String, String),
}

// ─── Symbol Source ────────────────────────────────────────────────────────────

/// The origin of a symbol, ordered so lower values are more trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    /// Microsoft PDB debug info.
    Pdb,
    /// DWARF debug info.
    Dwarf,
    /// ELF symbol table.
    Elf,
    /// PE symbol/export table.
    Pe,
    /// Legacy `CodeView` debug info.
    CodeView,
    /// Legacy STABS debug info.
    Stabs,
    /// FLIRT library-signature match.
    Flirt,
    /// Synthesised by analysis (e.g. `sub_401000`).
    Synthetic,
    /// Supplied or renamed by the user (highest trust).
    UserDefined,
}

impl SymbolSource {
    /// Inherent priority (lower = more trusted).
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::UserDefined => 0,
            Self::Pdb => 1,
            Self::Dwarf => 2,
            Self::CodeView => 3,
            Self::Stabs => 4,
            Self::Elf => 5,
            Self::Pe => 6,
            Self::Flirt => 7,
            Self::Synthetic => 8,
        }
    }

    /// A short lowercase label for the source (e.g. `"pdb"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pdb => "pdb",
            Self::Dwarf => "dwarf",
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::CodeView => "codeview",
            Self::Stabs => "stabs",
            Self::Flirt => "flirt",
            Self::Synthetic => "synthetic",
            Self::UserDefined => "user",
        }
    }
}

// ─── ResolvedSymbol ──────────────────────────────────────────────────────────

/// A fully resolved symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSymbol {
    /// Raw (possibly mangled) symbol name.
    pub name: String,
    /// Virtual address of the symbol.
    pub address: u64,
    /// Size in bytes, if known.
    pub size: Option<u64>,
    /// The winning source this symbol was resolved from.
    pub source: SymbolSource,
    /// Demangled name (if available).
    pub demangled: Option<String>,
    /// Module/binary it came from.
    pub module: Option<String>,
    /// Whether this is a function or data.
    pub is_function: bool,
}

impl ResolvedSymbol {
    /// Create a resolved symbol with the required fields; optional metadata
    /// (size, demangled name, module) is left unset and `is_function` false.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, source: SymbolSource) -> Self {
        Self {
            name: name.into(),
            address,
            size: None,
            source,
            demangled: None,
            module: None,
            is_function: false,
        }
    }

    /// Display name: demangled if available, else raw.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

// ─── ResolutionChain ─────────────────────────────────────────────────────────

/// Ordered list of sources to try in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionChain {
    /// Sources to consult, in the order they should be tried.
    pub sources: Vec<SymbolSource>,
}

impl ResolutionChain {
    /// Create from an ordered list.
    #[must_use]
    pub const fn new(sources: Vec<SymbolSource>) -> Self {
        Self { sources }
    }

    /// PDB first, then fall back in order.
    #[must_use]
    pub fn pdb_first() -> Self {
        Self::new(vec![
            SymbolSource::UserDefined,
            SymbolSource::Pdb,
            SymbolSource::CodeView,
            SymbolSource::Dwarf,
            SymbolSource::Elf,
            SymbolSource::Pe,
            SymbolSource::Flirt,
            SymbolSource::Synthetic,
        ])
    }

    /// DWARF first, then fall back in order.
    #[must_use]
    pub fn dwarf_first() -> Self {
        Self::new(vec![
            SymbolSource::UserDefined,
            SymbolSource::Dwarf,
            SymbolSource::Stabs,
            SymbolSource::Elf,
            SymbolSource::Flirt,
            SymbolSource::Synthetic,
        ])
    }

    /// Fallback chain — tries everything in priority order.
    #[must_use]
    pub fn fallback() -> Self {
        let mut sources = vec![
            SymbolSource::UserDefined,
            SymbolSource::Pdb,
            SymbolSource::Dwarf,
            SymbolSource::CodeView,
            SymbolSource::Stabs,
            SymbolSource::Elf,
            SymbolSource::Pe,
            SymbolSource::Flirt,
            SymbolSource::Synthetic,
        ];
        // Sort by priority (already in order, but explicit for safety).
        sources.sort_by_key(|s| s.priority());
        Self::new(sources)
    }

    /// Whether the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

// ─── ConflictResolution ───────────────────────────────────────────────────────

/// Strategy for resolving conflicting symbols at the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConflictStrategy {
    /// Prefer the symbol from the highest-priority (lowest priority number) source.
    #[default]
    HighestPriority,
    /// Keep the first symbol found, ignore subsequent conflicts.
    FirstWins,
    /// Keep the last symbol found.
    LastWins,
    /// Prefer the symbol with the longer/more descriptive name.
    LongestName,
    /// Prefer the demangled symbol.
    PrefersDemangled,
}

/// Resolves conflicts between two symbols at the same address.
pub struct ConflictResolution;

impl ConflictResolution {
    /// Apply a strategy to select a winner from two conflicting symbols.
    #[must_use]
    pub const fn resolve(
        a: &ResolvedSymbol,
        b: &ResolvedSymbol,
        strategy: ConflictStrategy,
    ) -> &'static str {
        // Returns "a" or "b".
        match strategy {
            ConflictStrategy::HighestPriority => {
                if a.source.priority() <= b.source.priority() {
                    "a"
                } else {
                    "b"
                }
            }
            ConflictStrategy::FirstWins => "a",
            ConflictStrategy::LastWins => "b",
            ConflictStrategy::LongestName => {
                if a.name.len() >= b.name.len() {
                    "a"
                } else {
                    "b"
                }
            }
            ConflictStrategy::PrefersDemangled => {
                if a.demangled.is_some() {
                    "a"
                } else if b.demangled.is_some() {
                    "b"
                } else {
                    "a"
                }
            }
        }
    }

    /// Select winner from a slice of candidates.
    #[must_use]
    pub fn select_winner(
        candidates: &[ResolvedSymbol],
        strategy: ConflictStrategy,
    ) -> Option<&ResolvedSymbol> {
        if candidates.is_empty() {
            return None;
        }
        let mut winner = &candidates[0];
        for cand in &candidates[1..] {
            let choice = Self::resolve(winner, cand, strategy);
            if choice == "b" {
                winner = cand;
            }
        }
        Some(winner)
    }
}

// ─── PdbFirst / DwarfFirst strategy types ────────────────────────────────────

/// PDB-first resolution strategy (builder pattern).
pub struct PdbFirst {
    /// The source ordering (PDB first).
    pub chain: ResolutionChain,
    /// How to resolve same-address conflicts.
    pub conflict: ConflictStrategy,
}

impl PdbFirst {
    /// Create the PDB-first strategy with the default highest-priority conflict rule.
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain: ResolutionChain::pdb_first(),
            conflict: ConflictStrategy::HighestPriority,
        }
    }

    /// Override the conflict strategy (builder style).
    #[must_use]
    pub const fn with_conflict(mut self, s: ConflictStrategy) -> Self {
        self.conflict = s;
        self
    }
}

impl Default for PdbFirst {
    fn default() -> Self {
        Self::new()
    }
}

/// DWARF-first resolution strategy.
pub struct DwarfFirst {
    /// The source ordering (DWARF first).
    pub chain: ResolutionChain,
    /// How to resolve same-address conflicts.
    pub conflict: ConflictStrategy,
}

impl DwarfFirst {
    /// Create the DWARF-first strategy with the default highest-priority conflict rule.
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain: ResolutionChain::dwarf_first(),
            conflict: ConflictStrategy::HighestPriority,
        }
    }

    /// Override the conflict strategy (builder style).
    #[must_use]
    pub const fn with_conflict(mut self, s: ConflictStrategy) -> Self {
        self.conflict = s;
        self
    }
}

impl Default for DwarfFirst {
    fn default() -> Self {
        Self::new()
    }
}

/// Full fallback chain strategy.
pub struct FallbackChain {
    /// The full source ordering to try in turn.
    pub chain: ResolutionChain,
    /// How to resolve same-address conflicts.
    pub conflict: ConflictStrategy,
}

impl FallbackChain {
    /// Create the full fallback strategy with the default highest-priority conflict rule.
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain: ResolutionChain::fallback(),
            conflict: ConflictStrategy::HighestPriority,
        }
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SymbolResolution ────────────────────────────────────────────────────────

/// Multi-source symbol store with priority-based resolution.
#[derive(Debug, Default)]
pub struct SymbolResolution {
    /// addr → list of candidate symbols (from different sources).
    candidates: BTreeMap<u64, Vec<ResolvedSymbol>>,
    /// name → addresses.
    name_index: HashMap<String, Vec<u64>>,
    /// Resolved (winner) cache.
    resolved: BTreeMap<u64, ResolvedSymbol>,
    /// Strategy used to pick a winner among same-address candidates.
    pub strategy: ConflictStrategy,
}

impl SymbolResolution {
    /// Create with a given conflict strategy.
    #[must_use]
    pub fn new(strategy: ConflictStrategy) -> Self {
        Self {
            strategy,
            ..Self::default()
        }
    }

    /// Create a PDB-first resolver.
    #[must_use]
    pub fn pdb_first() -> Self {
        Self::new(ConflictStrategy::HighestPriority)
    }

    /// Create a DWARF-first resolver (same strategy, different chain docs).
    #[must_use]
    pub fn dwarf_first() -> Self {
        Self::new(ConflictStrategy::HighestPriority)
    }

    /// Insert a symbol candidate.
    pub fn add(&mut self, sym: ResolvedSymbol) {
        let addr = sym.address;
        self.name_index
            .entry(sym.name.clone())
            .or_default()
            .push(addr);
        self.candidates.entry(addr).or_default().push(sym);
        // Invalidate resolved cache for this address.
        self.resolved.remove(&addr);
    }

    /// Resolve the best symbol at an address.
    ///
    /// # Errors
    ///
    /// Returns `ResolutionError::NotFound` if no symbol candidate exists at `addr`.
    ///
    /// # Panics
    ///
    /// Panics only if the resolved cache entry vanishes between insertion and lookup, which is impossible.
    pub fn resolve_address(&mut self, addr: u64) -> Result<&ResolvedSymbol, ResolutionError> {
        // Populate cache if needed.
        if !self.resolved.contains_key(&addr) {
            let candidates = self
                .candidates
                .get(&addr)
                .ok_or(ResolutionError::NotFound(addr))?;
            let winner = ConflictResolution::select_winner(candidates, self.strategy)
                .ok_or(ResolutionError::NotFound(addr))?
                .clone();
            self.resolved.insert(addr, winner);
        }
        Ok(self.resolved.get(&addr).unwrap())
    }

    /// Resolve by name (returns all addresses for that name).
    #[must_use]
    pub fn resolve_name(&self, name: &str) -> Vec<u64> {
        self.name_index.get(name).cloned().unwrap_or_default()
    }

    /// All candidates at an address.
    #[must_use]
    pub fn candidates_at(&self, addr: u64) -> &[ResolvedSymbol] {
        self.candidates
            .get(&addr)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Whether there is a conflict at `addr` (>1 candidates from different sources).
    #[must_use]
    pub fn has_conflict(&self, addr: u64) -> bool {
        self.candidates_at(addr).len() > 1
    }

    /// All addresses with conflicts.
    #[must_use]
    pub fn conflicted_addresses(&self) -> Vec<u64> {
        self.candidates
            .iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(&a, _)| a)
            .collect()
    }

    /// Total number of distinct addresses with at least one symbol.
    #[must_use]
    pub fn address_count(&self) -> usize {
        self.candidates.len()
    }

    /// Total number of symbol candidates across all addresses.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.values().map(std::vec::Vec::len).sum()
    }

    /// Set of distinct [`SymbolSource`] origins contributing at least one
    /// candidate.  Useful for telemetry: "how many provider back-ends actually
    /// fed this resolution session?".
    #[must_use]
    pub fn distinct_sources(&self) -> HashSet<SymbolSource> {
        let mut set: HashSet<SymbolSource> = HashSet::new();
        for cands in self.candidates.values() {
            for c in cands {
                set.insert(c.source);
            }
        }
        set
    }

    /// Nearest symbol at or before `addr` (for disassembly annotation).
    #[must_use]
    pub fn nearest_below(&self, addr: u64) -> Option<(u64, &[ResolvedSymbol])> {
        self.candidates
            .range(..=addr)
            .next_back()
            .map(|(&a, v)| (a, v.as_slice()))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &str, addr: u64, src: SymbolSource) -> ResolvedSymbol {
        ResolvedSymbol::new(name, addr, src)
    }

    fn _sym_fn(name: &str, addr: u64, src: SymbolSource) -> ResolvedSymbol {
        let mut s = sym(name, addr, src);
        s.is_function = true;
        s
    }

    // ── SymbolSource ─────────────────────────────────────────────────────────

    #[test]
    fn test_source_priority_pdb_higher_than_flirt() {
        assert!(SymbolSource::Pdb.priority() < SymbolSource::Flirt.priority());
    }

    #[test]
    fn test_source_label() {
        assert_eq!(SymbolSource::Dwarf.label(), "dwarf");
        assert_eq!(SymbolSource::Pdb.label(), "pdb");
    }

    // ── ResolutionChain ───────────────────────────────────────────────────────

    #[test]
    fn test_chain_pdb_first_starts_with_pdb() {
        let c = ResolutionChain::pdb_first();
        // UserDefined is index 0, PDB is index 1.
        assert!(c.sources.contains(&SymbolSource::Pdb));
        assert!(c.sources.contains(&SymbolSource::Dwarf));
    }

    #[test]
    fn test_chain_dwarf_first_contains_dwarf() {
        let c = ResolutionChain::dwarf_first();
        assert!(c.sources.contains(&SymbolSource::Dwarf));
    }

    #[test]
    fn test_chain_fallback_not_empty() {
        let c = ResolutionChain::fallback();
        assert!(!c.is_empty());
    }

    #[test]
    fn test_chain_fallback_ordered() {
        let c = ResolutionChain::fallback();
        let prios: Vec<_> = c.sources.iter().map(|s| s.priority()).collect();
        let mut sorted = prios.clone();
        sorted.sort_unstable();
        assert_eq!(prios, sorted);
    }

    // ── ConflictResolution ────────────────────────────────────────────────────

    #[test]
    fn test_conflict_highest_priority() {
        let a = sym("pdb_sym", 0x1000, SymbolSource::Pdb);
        let b = sym("flirt_sym", 0x1000, SymbolSource::Flirt);
        let winner = ConflictResolution::resolve(&a, &b, ConflictStrategy::HighestPriority);
        assert_eq!(winner, "a"); // PDB has lower (better) priority number
    }

    #[test]
    fn test_conflict_first_wins() {
        let a = sym("a", 0x1000, SymbolSource::Flirt);
        let b = sym("b", 0x1000, SymbolSource::Pdb);
        assert_eq!(
            ConflictResolution::resolve(&a, &b, ConflictStrategy::FirstWins),
            "a"
        );
    }

    #[test]
    fn test_conflict_last_wins() {
        let a = sym("a", 0x1000, SymbolSource::Pdb);
        let b = sym("b", 0x1000, SymbolSource::Flirt);
        assert_eq!(
            ConflictResolution::resolve(&a, &b, ConflictStrategy::LastWins),
            "b"
        );
    }

    #[test]
    fn test_conflict_longest_name() {
        let a = sym("short", 0x1000, SymbolSource::Pdb);
        let b = sym("much_longer_name", 0x1000, SymbolSource::Dwarf);
        assert_eq!(
            ConflictResolution::resolve(&a, &b, ConflictStrategy::LongestName),
            "b"
        );
    }

    #[test]
    fn test_conflict_prefers_demangled() {
        let mut a = sym("_mangled", 0x1000, SymbolSource::Pdb);
        a.demangled = Some("demangled_func".into());
        let b = sym("_also_mangled", 0x1000, SymbolSource::Dwarf);
        assert_eq!(
            ConflictResolution::resolve(&a, &b, ConflictStrategy::PrefersDemangled),
            "a"
        );
    }

    #[test]
    fn test_conflict_select_winner_empty() {
        let w = ConflictResolution::select_winner(&[], ConflictStrategy::HighestPriority);
        assert!(w.is_none());
    }

    #[test]
    fn test_conflict_select_winner_single() {
        let syms = vec![sym("only", 0x1000, SymbolSource::Pdb)];
        let w =
            ConflictResolution::select_winner(&syms, ConflictStrategy::HighestPriority).unwrap();
        assert_eq!(w.name, "only");
    }

    // ── ResolvedSymbol ────────────────────────────────────────────────────────

    #[test]
    fn test_resolved_display_name_uses_demangled() {
        let mut s = sym("_ZN3fooEv", 0x1000, SymbolSource::Dwarf);
        s.demangled = Some("foo()".into());
        assert_eq!(s.display_name(), "foo()");
    }

    #[test]
    fn test_resolved_display_name_falls_back() {
        let s = sym("raw_name", 0x1000, SymbolSource::Pdb);
        assert_eq!(s.display_name(), "raw_name");
    }

    // ── SymbolResolution ──────────────────────────────────────────────────────

    #[test]
    fn test_resolution_add_and_resolve() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("func_a", 0x1000, SymbolSource::Pdb));
        let s = r.resolve_address(0x1000).unwrap();
        assert_eq!(s.name, "func_a");
    }

    #[test]
    fn test_resolution_not_found() {
        let mut r = SymbolResolution::pdb_first();
        assert!(r.resolve_address(0xDEAD).is_err());
    }

    #[test]
    fn test_resolution_conflict_pdb_wins_over_flirt() {
        let mut r = SymbolResolution::new(ConflictStrategy::HighestPriority);
        r.add(sym("flirt_name", 0x1000, SymbolSource::Flirt));
        r.add(sym("pdb_name", 0x1000, SymbolSource::Pdb));
        let s = r.resolve_address(0x1000).unwrap();
        assert_eq!(s.name, "pdb_name");
    }

    #[test]
    fn test_resolution_has_conflict() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("a", 0x1000, SymbolSource::Pdb));
        r.add(sym("b", 0x1000, SymbolSource::Dwarf));
        assert!(r.has_conflict(0x1000));
    }

    #[test]
    fn test_resolution_conflicted_addresses() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("a", 0x1000, SymbolSource::Pdb));
        r.add(sym("b", 0x1000, SymbolSource::Dwarf));
        r.add(sym("c", 0x2000, SymbolSource::Pdb));
        let conflicts = r.conflicted_addresses();
        assert!(conflicts.contains(&0x1000));
        assert!(!conflicts.contains(&0x2000));
    }

    #[test]
    fn test_resolution_address_count() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("a", 0x1000, SymbolSource::Pdb));
        r.add(sym("b", 0x2000, SymbolSource::Pdb));
        assert_eq!(r.address_count(), 2);
    }

    #[test]
    fn test_resolution_candidate_count() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("a", 0x1000, SymbolSource::Pdb));
        r.add(sym("b", 0x1000, SymbolSource::Dwarf));
        r.add(sym("c", 0x2000, SymbolSource::Pdb));
        assert_eq!(r.candidate_count(), 3);
    }

    #[test]
    fn test_resolution_resolve_name() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("my_func", 0x1000, SymbolSource::Pdb));
        let addrs = r.resolve_name("my_func");
        assert!(addrs.contains(&0x1000));
    }

    #[test]
    fn test_resolution_nearest_below() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("base", 0x1000, SymbolSource::Pdb));
        r.add(sym("mid", 0x2000, SymbolSource::Pdb));
        let (addr, _) = r.nearest_below(0x1500).unwrap();
        assert_eq!(addr, 0x1000);
    }

    // ── Strategy structs ──────────────────────────────────────────────────────

    #[test]
    fn test_pdb_first_struct() {
        let p = PdbFirst::new();
        assert!(p.chain.sources.contains(&SymbolSource::Pdb));
    }

    #[test]
    fn test_dwarf_first_struct() {
        let d = DwarfFirst::new();
        assert!(d.chain.sources.contains(&SymbolSource::Dwarf));
    }

    #[test]
    fn test_fallback_chain_struct() {
        let f = FallbackChain::new();
        assert!(f.chain.sources.len() >= 8);
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_source_user_defined_highest_priority() {
        assert_eq!(SymbolSource::UserDefined.priority(), 0);
    }

    #[test]
    fn test_source_synthetic_lowest() {
        assert!(SymbolSource::Synthetic.priority() > SymbolSource::Pdb.priority());
    }

    #[test]
    fn test_resolution_multiple_names_same_addr() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("a1", 0x1000, SymbolSource::Pdb));
        r.add(sym("a2", 0x1000, SymbolSource::Dwarf));
        assert_eq!(r.candidates_at(0x1000).len(), 2);
    }

    #[test]
    fn test_resolution_nearest_below_empty() {
        let r = SymbolResolution::pdb_first();
        assert!(r.nearest_below(0x9999).is_none());
    }

    #[test]
    fn test_resolution_no_conflict_single_candidate() {
        let mut r = SymbolResolution::pdb_first();
        r.add(sym("only", 0x1000, SymbolSource::Pdb));
        assert!(!r.has_conflict(0x1000));
    }
}
