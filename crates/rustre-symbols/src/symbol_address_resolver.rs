//! Symbol address resolver: translate raw addresses into symbolic names with
//! offset information, and back again.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;

use crate::Symbol;

// ── ResolveError ──────────────────────────────────────────────────────────────

/// Errors raised while resolving an address or name to a symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No symbols have been loaded into the resolver.
    NoSymbolsLoaded,
    /// The queried address has no symbol at or below it.
    AddressNotMapped(u64),
    /// No symbol matched the queried name.
    SymbolNotFound(String),
    /// The queried name matched more than one symbol.
    AmbiguousSymbol {
        /// The ambiguous name.
        name: String,
        /// Number of matching symbols.
        count: usize,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSymbolsLoaded => write!(f, "no symbols have been loaded"),
            Self::AddressNotMapped(a) => write!(f, "address {a:#018x} has no symbol mapping"),
            Self::SymbolNotFound(n) => write!(f, "symbol not found: {n}"),
            Self::AmbiguousSymbol { name, count } => {
                write!(f, "symbol {name} is ambiguous ({count} matches)")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

// ── Resolution ────────────────────────────────────────────────────────────────

/// The result of resolving an address to a symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The closest symbol whose start address is ≤ the queried address.
    pub symbol: Symbol,
    /// Byte offset from `symbol.address` to the queried address.
    pub offset: u64,
    /// Whether the queried address falls within the symbol's size range.
    pub within_bounds: bool,
}

impl Resolution {
    /// Build an exact (zero-offset, in-bounds) resolution for `symbol`.
    #[must_use]
    pub const fn exact(symbol: Symbol) -> Self {
        Self {
            symbol,
            offset: 0,
            within_bounds: true,
        }
    }

    /// Format as `"symbol_name+0x1c"` (or just `"symbol_name"` when offset is 0).
    #[must_use]
    pub fn display_name(&self) -> String {
        if self.offset == 0 {
            self.symbol.name.clone()
        } else {
            format!("{}+{:#x}", self.symbol.name, self.offset)
        }
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ── ResolveResult ─────────────────────────────────────────────────────────────

/// Convenience alias for a resolution result.
pub type ResolveResult = Result<Resolution, ResolveError>;

// ── SymbolAddressResolver ─────────────────────────────────────────────────────

/// Maps addresses ↔ symbol names bidirectionally.
///
/// Internally uses a `BTreeMap<u64, Symbol>` keyed on start address for
/// O(log n) floor queries.
pub struct SymbolAddressResolver {
    /// Sorted map: symbol start address → symbol.
    by_address: BTreeMap<u64, Symbol>,
    /// Map: symbol name → start address(es).
    by_name: BTreeMap<String, Vec<u64>>,
    /// Base address added to all stored addresses when loading a module at
    /// a non-default base.
    base_offset: u64,
}

impl SymbolAddressResolver {
    /// Create an empty resolver with a zero base offset.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            base_offset: 0,
        }
    }

    /// Create with an explicit base address (ASLR/rebase offset).
    #[must_use]
    pub const fn with_base(base_offset: u64) -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            base_offset,
        }
    }

    // ── Loading ───────────────────────────────────────────────────────────────

    /// Insert a single symbol.
    pub fn insert(&mut self, sym: Symbol) {
        let addr: u64 = sym.address;
        let addr_rebased = addr + self.base_offset;
        self.by_name
            .entry(sym.name.clone())
            .or_default()
            .push(addr_rebased);
        self.by_address.insert(addr_rebased, sym);
    }

    /// Insert many symbols.
    pub fn insert_all(&mut self, symbols: impl IntoIterator<Item = Symbol>) {
        for sym in symbols {
            self.insert(sym);
        }
    }

    /// Remove a symbol at `address`.  Returns it if found.
    pub fn remove_at(&mut self, address: u64) -> Option<Symbol> {
        if let Some(sym) = self.by_address.remove(&address) {
            if let Some(addrs) = self.by_name.get_mut(&sym.name) {
                addrs.retain(|&a| a != address);
                if addrs.is_empty() {
                    self.by_name.remove(&sym.name);
                }
            }
            Some(sym)
        } else {
            None
        }
    }

    /// Remove all symbols with `name`.
    pub fn remove_by_name(&mut self, name: &str) -> Vec<Symbol> {
        let Some(addrs) = self.by_name.remove(name) else {
            return Vec::new();
        };
        addrs
            .into_iter()
            .filter_map(|a| self.by_address.remove(&a))
            .collect()
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.by_name.clear();
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Resolve an absolute `address` to a symbol.
    ///
    /// Uses a floor query to find the nearest symbol whose start ≤ `address`.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::NoSymbolsLoaded`] when the resolver is empty,
    /// or [`ResolveError::AddressNotMapped`] when no symbol covers `address`.
    pub fn resolve_address(&self, address: u64) -> ResolveResult {
        if self.by_address.is_empty() {
            return Err(ResolveError::NoSymbolsLoaded);
        }

        // Floor: largest key ≤ address.
        let entry = self
            .by_address
            .range(..=address)
            .next_back()
            .map(|(_, v)| v);

        entry.map_or(Err(ResolveError::AddressNotMapped(address)), |sym| {
            let sym_addr: u64 = sym.address;
            let offset = address.saturating_sub(sym_addr + self.base_offset);
            let within_bounds = sym.size.is_some_and(|s| s == 0 || offset < s);
            Ok(Resolution {
                symbol: sym.clone(),
                offset,
                within_bounds,
            })
        })
    }

    /// Look up the address(es) of symbols named `name`.
    #[must_use]
    pub fn address_of(&self, name: &str) -> Vec<u64> {
        self.by_name.get(name).cloned().unwrap_or_default()
    }

    /// Resolve a name to a single symbol.
    ///
    /// Returns `Err(AmbiguousSymbol)` if there are multiple addresses for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::SymbolNotFound`] when `name` is unknown, or
    /// [`ResolveError::AmbiguousSymbol`] when several symbols share the name.
    pub fn resolve_name(&self, name: &str) -> ResolveResult {
        let addrs = self.address_of(name);
        match addrs.as_slice() {
            [] => Err(ResolveError::SymbolNotFound(name.to_owned())),
            [addr] => {
                self.resolve_address(*addr)
            }
            multiple => Err(ResolveError::AmbiguousSymbol {
                name: name.to_owned(),
                count: multiple.len(),
            }),
        }
    }

    /// Resolve a name to a single address (convenience).
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::SymbolNotFound`] or
    /// [`ResolveError::AmbiguousSymbol`] as in [`Self::resolve_name`].
    pub fn address_of_unique(&self, name: &str) -> Result<u64, ResolveError> {
        let addrs = self.address_of(name);
        match addrs.as_slice() {
            [] => Err(ResolveError::SymbolNotFound(name.to_owned())),
            [addr] => Ok(*addr),
            _ => Err(ResolveError::AmbiguousSymbol {
                name: name.to_owned(),
                count: addrs.len(),
            }),
        }
    }

    /// Return all symbols in address order.
    pub fn symbols_in_order(&self) -> impl Iterator<Item = &Symbol> {
        self.by_address.values()
    }

    /// Return symbols overlapping `[start, end)`.
    #[must_use]
    pub fn symbols_in_range(&self, start: u64, end: u64) -> Vec<&Symbol> {
        self.by_address
            .range(start..end)
            .map(|(_, v)| v)
            .collect()
    }

    /// Find the symbol immediately before `address` (the one just below it).
    #[must_use]
    pub fn preceding_symbol(&self, address: u64) -> Option<&Symbol> {
        self.by_address
            .range(..address)
            .next_back()
            .map(|(_, v)| v)
    }

    /// Find the symbol immediately after `address`.
    #[must_use]
    pub fn following_symbol(&self, address: u64) -> Option<&Symbol> {
        self.by_address
            .range((Bound::Excluded(address), Bound::Unbounded))
            .next()
            .map(|(_, v)| v)
    }

    /// Number of symbols loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Whether no symbols are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Update the base offset (e.g. after ASLR relocation).
    ///
    /// All stored addresses are shifted by `new_base - old_base`.
    pub fn rebase(&mut self, new_base: u64) {
        // Compute the signed delta via wrapping arithmetic on signed values.
        let delta = new_base.cast_signed().wrapping_sub(self.base_offset.cast_signed());
        if delta == 0 {
            return;
        }

        let shift = |addr: u64| -> u64 {
            addr.cast_signed().wrapping_add(delta).cast_unsigned()
        };

        let old_map: BTreeMap<u64, Symbol> = std::mem::take(&mut self.by_address);
        let old_by_name: BTreeMap<String, Vec<u64>> = std::mem::take(&mut self.by_name);

        for (old_addr, sym) in old_map {
            self.by_address.insert(shift(old_addr), sym);
        }
        for (name, addrs) in old_by_name {
            let new_addrs: Vec<u64> = addrs.into_iter().map(shift).collect();
            self.by_name.insert(name, new_addrs);
        }

        self.base_offset = new_base;
    }
}

impl Default for SymbolAddressResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SymbolAddressResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolAddressResolver")
            .field("symbols", &self.by_address.len())
            .field("names", &self.by_name.len())
            .field("base_offset", &format_args!("{:#x}", self.base_offset))
            .finish()
    }
}

// ── Free function resolve_address ─────────────────────────────────────────────

/// Convenience: resolve `address` from a slice of symbols without constructing
/// a full [`SymbolAddressResolver`].
///
/// # Errors
///
/// Returns the same errors as [`SymbolAddressResolver::resolve_address`].
pub fn resolve_address(symbols: &[Symbol], address: u64) -> ResolveResult {
    let mut r = SymbolAddressResolver::new();
    r.insert_all(symbols.iter().cloned());
    r.resolve_address(address)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymKind;

    fn make_sym(name: &str, addr: u64, size: u64, kind: SymKind) -> Symbol {
        let mut sym = Symbol::new(name.to_owned(), addr, kind);
        sym.size = Some(size);
        sym
    }

    fn resolver_with_syms() -> SymbolAddressResolver {
        let mut r = SymbolAddressResolver::new();
        r.insert(make_sym("main", 0x1000, 0x100, SymKind::Function));
        r.insert(make_sym("helper", 0x1200, 0x80, SymKind::Function));
        r.insert(make_sym("global_var", 0x2000, 8, SymKind::Data));
        r
    }

    #[test]
    fn resolve_exact_address() {
        let r = resolver_with_syms();
        let res = r.resolve_address(0x1000).unwrap();
        assert_eq!(res.symbol.name, "main");
        assert_eq!(res.offset, 0);
        assert!(res.within_bounds);
    }

    #[test]
    fn resolve_address_with_offset() {
        let r = resolver_with_syms();
        let res = r.resolve_address(0x1010).unwrap();
        assert_eq!(res.symbol.name, "main");
        assert_eq!(res.offset, 0x10);
    }

    #[test]
    fn resolve_address_out_of_bounds_still_returns_sym() {
        let r = resolver_with_syms();
        // 0x1100 + 0x100 = 0x1200 which is exactly `helper`, but 0x1100 is after main ends
        let res = r.resolve_address(0x1100).unwrap();
        assert_eq!(res.symbol.name, "main");
        assert!(!res.within_bounds);
    }

    #[test]
    fn resolve_address_below_all_symbols() {
        let r = resolver_with_syms();
        let err = r.resolve_address(0x0FF0).unwrap_err();
        assert!(matches!(err, ResolveError::AddressNotMapped(_)));
    }

    #[test]
    fn resolve_name_success() {
        let r = resolver_with_syms();
        let res = r.resolve_name("helper").unwrap();
        assert_eq!(res.symbol.name, "helper");
        assert_eq!(res.offset, 0);
    }

    #[test]
    fn resolve_name_not_found() {
        let r = resolver_with_syms();
        let err = r.resolve_name("nonexistent").unwrap_err();
        assert!(matches!(err, ResolveError::SymbolNotFound(_)));
    }

    #[test]
    fn ambiguous_symbol() {
        let mut r = SymbolAddressResolver::new();
        r.insert(make_sym("dup", 0x1000, 0x10, SymKind::Function));
        r.insert(make_sym("dup", 0x2000, 0x10, SymKind::Function));
        let err = r.resolve_name("dup").unwrap_err();
        assert!(matches!(err, ResolveError::AmbiguousSymbol { count: 2, .. }));
    }

    #[test]
    fn address_of_returns_multiple() {
        let mut r = SymbolAddressResolver::new();
        r.insert(make_sym("dup", 0x1000, 0x10, SymKind::Function));
        r.insert(make_sym("dup", 0x2000, 0x10, SymKind::Function));
        let addrs = r.address_of("dup");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn remove_at() {
        let mut r = resolver_with_syms();
        let removed = r.remove_at(0x1000).unwrap();
        assert_eq!(removed.name, "main");
        assert_eq!(r.len(), 2);
        assert!(r.address_of("main").is_empty());
    }

    #[test]
    fn remove_by_name() {
        let mut r = resolver_with_syms();
        let removed = r.remove_by_name("helper");
        assert_eq!(removed.len(), 1);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn symbols_in_range() {
        let r = resolver_with_syms();
        let syms = r.symbols_in_range(0x1000, 0x2001);
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"main"));
        assert!(names.contains(&"helper"));
        assert!(names.contains(&"global_var"));
    }

    #[test]
    fn preceding_and_following() {
        let r = resolver_with_syms();
        let prec = r.preceding_symbol(0x1200).unwrap();
        assert_eq!(prec.name, "main");
        let foll = r.following_symbol(0x1000).unwrap();
        assert_eq!(foll.name, "helper");
    }

    #[test]
    fn rebase_shifts_all_addresses() {
        let mut r = SymbolAddressResolver::new();
        r.insert(make_sym("foo", 0x1000, 0x10, SymKind::Function));
        r.rebase(0x10000);
        // foo is now at 0x10000 + 0x1000 = 0x11000
        let res = r.resolve_address(0x11000).unwrap();
        assert_eq!(res.symbol.name, "foo");
        assert_eq!(res.offset, 0);
    }

    #[test]
    fn display_name_with_offset() {
        let sym = make_sym("myFunc", 0x1000, 0x100, SymKind::Function);
        let r = Resolution {
            symbol: sym,
            offset: 0x42,
            within_bounds: true,
        };
        assert_eq!(r.display_name(), "myFunc+0x42");
    }

    #[test]
    fn display_name_no_offset() {
        let sym = make_sym("myFunc", 0x1000, 0x100, SymKind::Function);
        let r = Resolution::exact(sym);
        assert_eq!(r.display_name(), "myFunc");
    }

    #[test]
    fn free_resolve_address() {
        let syms = vec![make_sym("entry", 0x0040_0000, 0x1000, SymKind::Function)];
        let res = resolve_address(&syms, 0x0040_0010).unwrap();
        assert_eq!(res.symbol.name, "entry");
        assert_eq!(res.offset, 0x10);
    }

    #[test]
    fn no_symbols_returns_error() {
        let r = SymbolAddressResolver::new();
        assert!(matches!(
            r.resolve_address(0x1000),
            Err(ResolveError::NoSymbolsLoaded)
        ));
    }
}
