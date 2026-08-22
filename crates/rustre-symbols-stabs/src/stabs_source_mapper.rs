//! STABS-to-source mapper.
//!
//! Reconstructs the mapping from virtual addresses to source file/line
//! information by processing `N_FUN`, `N_SO`, `N_SOL`, and `N_SLINE` STABS
//! entries.
//!
//! ## Entry types
//! | STABS type | Code | Meaning |
//! |------------|------|---------|
//! | `N_SO`     | 0x64 | Compilation unit source file |
//! | `N_SOL`    | 0x84 | Included sub-file (e.g. from `#include`) |
//! | `N_FUN`    | 0x24 | Function start (string = `name:type`) |
//! | `N_SLINE`  | 0x44 | Source line within the current function |

use std::collections::BTreeMap;
use std::fmt;
use rustre_core::address::Address;

// ── LineEntry ─────────────────────────────────────────────────────────────────

/// A single source-line-to-address mapping entry.
#[derive(Debug, Clone)]
pub struct LineEntry {
    /// Absolute virtual address.
    pub address: Address,
    /// 1-based source line number.
    pub line: u32,
    /// Source file path (may be a sub-file if `N_SOL` was in effect).
    pub file: String,
    /// Function that contains this line (empty string if unknown).
    pub function: String,
}

impl fmt::Display for LineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x} → {}:{} ({})",
            self.address.as_u64(),
            self.file,
            self.line,
            self.function
        )
    }
}

// ── SourceLocation ────────────────────────────────────────────────────────────

/// The result of a source-location lookup.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    /// Source file path.
    pub file: String,
    /// 1-based source line.
    pub line: u32,
    /// Column (always 0 — STABS does not carry column information).
    pub column: u32,
    /// Enclosing function name (empty if not known).
    pub function: String,
    /// The exact virtual address of the closest preceding line entry.
    pub nearest_address: Address,
}

impl SourceLocation {
    /// Returns a display string `file:line`.
    #[must_use]
    pub fn short(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} in {} @ {:#x}",
            self.file,
            self.line,
            self.function,
            self.nearest_address.as_u64()
        )
    }
}

// ── MapperError ───────────────────────────────────────────────────────────────

/// Errors from the STABS source mapper.
#[derive(Debug, Clone)]
pub enum MapperError {
    /// An `N_SLINE` entry was received with no active function.
    SlineOutsideFunction {
        /// Absolute address of the offending line entry.
        address: u64,
    },
    /// An `N_FUN` entry was received with no active source file.
    FunWithoutSourceFile {
        /// Raw `N_FUN` string of the offending record.
        name: String,
    },
}

impl fmt::Display for MapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlineOutsideFunction { address } => {
                write!(f, "N_SLINE at {address:#x} outside any function")
            }
            Self::FunWithoutSourceFile { name } => {
                write!(f, "N_FUN '{name}' has no active source file")
            }
        }
    }
}

// ── StabsSourceMapper ─────────────────────────────────────────────────────────

/// Accumulates STABS entries and builds a sorted address→source mapping.
///
/// Usage:
/// 1. Feed entries in address order.
/// 2. Call [`StabsSourceMapper::finalise`] once all entries have been fed.
/// 3. Query with [`StabsSourceMapper::source_at_address`] or the free function
///    [`source_at_address`].
pub struct StabsSourceMapper {
    /// The sorted map from absolute address to line entry.
    map: BTreeMap<u64, LineEntry>,
    /// Current compilation unit source file.
    current_so: String,
    /// Current sub-file (from `N_SOL`); falls back to `current_so`.
    current_sol: Option<String>,
    /// Name of the current function.
    current_function: String,
    /// Absolute base address of the current function (from `N_FUN`).
    function_base: u64,
    /// Whether the mapper has been finalised.
    finalised: bool,
    /// Number of `N_SLINE` entries processed.
    sline_count: usize,
    /// Number of `N_FUN` entries processed.
    fun_count: usize,
}

impl StabsSourceMapper {
    /// Create a new, empty mapper.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            current_so: String::new(),
            current_sol: None,
            current_function: String::new(),
            function_base: 0,
            finalised: false,
            sline_count: 0,
            fun_count: 0,
        }
    }

    // ── Entry feeding ─────────────────────────────────────────────────────────

    /// Feed an `N_SO` entry.
    /// `name` is the source file path; `address` is the CU load address.
    pub fn feed_so(&mut self, name: &str, _address: u64) {
        self.current_so = name.to_owned();
        self.current_sol = None;
    }

    /// Feed an `N_SOL` entry (sub-file / `#include`).
    pub fn feed_sol(&mut self, name: &str) {
        if name.is_empty() {
            self.current_sol = None;
        } else {
            self.current_sol = Some(name.to_owned());
        }
    }

    /// Feed an `N_FUN` entry.
    ///
    /// `name` is the raw STABS string (e.g. `foo:F(0,1)`); the function name
    /// is the part before the colon.
    /// `address` is the absolute virtual address of the function's first byte.
    pub fn feed_fun(&mut self, name: &str, address: u64) -> Result<(), MapperError> {
        if name.is_empty() {
            // End-of-function marker from some toolchains.
            self.current_function.clear();
            self.function_base = 0;
            return Ok(());
        }
        if self.current_so.is_empty() {
            return Err(MapperError::FunWithoutSourceFile { name: name.to_owned() });
        }
        // Strip type descriptor: take everything before the first ':'.
        let fname = crate::stab_name_of(name);
        self.current_function = fname.to_owned();
        self.function_base = address;
        self.fun_count += 1;
        Ok(())
    }

    /// Feed an `N_SLINE` entry.
    ///
    /// `line` is the source line number (1-based).
    /// `offset` is the byte offset *from the current function base*.
    pub fn feed_sline(&mut self, line: u32, offset: u32) -> Result<(), MapperError> {
        if self.current_function.is_empty() {
            let abs_addr = self.function_base.saturating_add(u64::from(offset));
            return Err(MapperError::SlineOutsideFunction { address: abs_addr });
        }
        let abs_addr = self.function_base.saturating_add(u64::from(offset));
        let file = self
            .current_sol
            .as_deref()
            .unwrap_or(&self.current_so)
            .to_owned();
        self.map.insert(
            abs_addr,
            LineEntry {
                address: Address::new(abs_addr),
                line,
                file,
                function: self.current_function.clone(),
            },
        );
        self.sline_count += 1;
        Ok(())
    }

    /// Mark the mapper as finalised (no more entries).
    pub const fn finalise(&mut self) {
        self.finalised = true;
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Look up the source location for a given absolute virtual address.
    ///
    /// Returns the nearest preceding `LineEntry` if one exists.
    #[must_use]
    pub fn source_at_address(&self, address: Address) -> Option<SourceLocation> {
        let addr = address.as_u64();
        // BTreeMap::range gives us entries with key ≤ addr.
        let (_, entry) = self.map.range(..=addr).next_back()?;
        Some(SourceLocation {
            file: entry.file.clone(),
            line: entry.line,
            column: 0,
            function: entry.function.clone(),
            nearest_address: entry.address,
        })
    }

    /// Return all line entries for a given source file (path suffix match).
    #[must_use]
    pub fn lines_for_file(&self, file_suffix: &str) -> Vec<&LineEntry> {
        self.map
            .values()
            .filter(|e| e.file.ends_with(file_suffix))
            .collect()
    }

    /// Return all line entries for a given function name.
    #[must_use]
    pub fn lines_for_function(&self, function: &str) -> Vec<&LineEntry> {
        self.map
            .values()
            .filter(|e| e.function == function)
            .collect()
    }

    /// All line entries sorted by address.
    #[must_use]
    pub fn all_entries(&self) -> impl Iterator<Item = &LineEntry> {
        self.map.values()
    }

    /// Total number of line entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.map.len()
    }

    /// Number of `N_FUN` entries processed.
    #[must_use]
    pub const fn fun_count(&self) -> usize {
        self.fun_count
    }

    /// Number of `N_SLINE` entries processed.
    #[must_use]
    pub const fn sline_count(&self) -> usize {
        self.sline_count
    }

    /// Returns `true` after [`Self::finalise`] has been called.
    #[must_use]
    pub const fn is_finalised(&self) -> bool {
        self.finalised
    }

    /// Address range covered by this mapper: `(min, max)` inclusive.
    #[must_use]
    pub fn address_range(&self) -> Option<(Address, Address)> {
        let first = self.map.keys().next()?;
        let last = self.map.keys().next_back()?;
        Some((Address::new(*first), Address::new(*last)))
    }
}

impl Default for StabsSourceMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free function: source_at_address ─────────────────────────────────────────

/// Convenience wrapper — look up `address` in a finalised [`StabsSourceMapper`].
///
/// ```rust
/// use rustre_symbols_stabs::stabs_source_mapper::{StabsSourceMapper, source_at_address};
/// use rustre_core::address::Address;
/// let mut m = StabsSourceMapper::new();
/// m.feed_so("main.c", 0);
/// m.feed_fun("main", 0x1000).unwrap();
/// m.feed_sline(10, 0).unwrap();
/// m.feed_sline(11, 4).unwrap();
/// m.finalise();
/// let loc = source_at_address(&m, Address::new(0x1002));
/// assert!(loc.is_some());
/// ```
#[must_use]
pub fn source_at_address(mapper: &StabsSourceMapper, address: Address) -> Option<SourceLocation> {
    mapper.source_at_address(address)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn build_mapper() -> StabsSourceMapper {
        let mut m = StabsSourceMapper::new();
        m.feed_so("src/main.c", 0);
        m.feed_fun("main", 0x1000).unwrap();
        m.feed_sline(10, 0).unwrap();
        m.feed_sline(11, 4).unwrap();
        m.feed_sline(12, 8).unwrap();
        m.feed_fun("helper", 0x2000).unwrap();
        m.feed_sol("src/helper.h");
        m.feed_sline(5, 0).unwrap();
        m.feed_sline(6, 4).unwrap();
        m.feed_sol("");
        m.finalise();
        m
    }

    #[test]
    fn entry_count() {
        let m = build_mapper();
        assert_eq!(m.entry_count(), 5);
    }

    #[test]
    fn source_at_exact_address() {
        let m = build_mapper();
        let loc = m.source_at_address(Address::new(0x1000)).unwrap();
        assert_eq!(loc.line, 10);
        assert_eq!(loc.function, "main");
    }

    #[test]
    fn source_at_between_lines() {
        let m = build_mapper();
        // 0x1002 is between line 10 (0x1000) and line 11 (0x1004).
        let loc = m.source_at_address(Address::new(0x1002)).unwrap();
        assert_eq!(loc.line, 10);
    }

    #[test]
    fn source_at_second_function() {
        let m = build_mapper();
        let loc = m.source_at_address(Address::new(0x2004)).unwrap();
        assert_eq!(loc.line, 6);
        assert_eq!(loc.function, "helper");
    }

    #[test]
    fn source_before_any_line_returns_none() {
        let m = build_mapper();
        let loc = m.source_at_address(Address::new(0x0001));
        assert!(loc.is_none());
    }

    #[test]
    fn lines_for_function() {
        let m = build_mapper();
        let lines = m.lines_for_function("main");
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn lines_for_file_suffix() {
        let m = build_mapper();
        let lines = m.lines_for_file("helper.h");
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn sol_overrides_file() {
        let m = build_mapper();
        let loc = m.source_at_address(Address::new(0x2000)).unwrap();
        assert!(loc.file.contains("helper.h"), "expected helper.h, got {}", loc.file);
    }

    #[test]
    fn address_range() {
        let m = build_mapper();
        let (lo, hi) = m.address_range().unwrap();
        assert_eq!(lo.as_u64(), 0x1000);
        assert_eq!(hi.as_u64(), 0x2004);
    }

    #[test]
    fn fun_count_and_sline_count() {
        let m = build_mapper();
        assert_eq!(m.fun_count(), 2);
        assert_eq!(m.sline_count(), 5);
    }

    #[test]
    fn is_finalised() {
        let mut m = StabsSourceMapper::new();
        assert!(!m.is_finalised());
        m.finalise();
        assert!(m.is_finalised());
    }

    #[test]
    fn free_fn_source_at_address() {
        let m = build_mapper();
        let loc = source_at_address(&m, Address::new(0x1008)).unwrap();
        assert_eq!(loc.line, 12);
    }

    #[test]
    fn sline_outside_function_returns_error() {
        let mut m = StabsSourceMapper::new();
        m.feed_so("x.c", 0);
        // No N_FUN fed, current_function is empty.
        let r = m.feed_sline(1, 0);
        assert!(r.is_err());
    }

    #[test]
    fn fun_without_source_file_returns_error() {
        let mut m = StabsSourceMapper::new();
        let r = m.feed_fun("foo", 0x1000);
        assert!(r.is_err());
    }

    #[test]
    fn source_location_display() {
        let loc = SourceLocation {
            file: "main.c".to_owned(),
            line: 42,
            column: 0,
            function: "main".to_owned(),
            nearest_address: Address::new(0x1000),
        };
        let s = loc.to_string();
        assert!(s.contains("main.c"));
        assert!(s.contains("42"));
    }

    #[test]
    fn source_location_short() {
        let loc = SourceLocation {
            file: "foo.c".to_owned(),
            line: 7,
            column: 0,
            function: String::new(),
            nearest_address: Address::new(0),
        };
        assert_eq!(loc.short(), "foo.c:7");
    }

    #[test]
    fn all_entries_ordered() {
        let m = build_mapper();
        let addrs: Vec<u64> = m.all_entries().map(|e| e.address.as_u64()).collect();
        for w in addrs.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }
}
