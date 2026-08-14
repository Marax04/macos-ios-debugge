//! `dyld_symbol_table.rs` — dyld shared-cache symbol table parsing and lookup.
//!
//! Provides:
//!   - [`DyldSymbolTable`] — high-level symbol table with bulk lookup
//!   - [`ExportedSymbol`] — name / address / flags for exported symbols
//!   - [`ImportedSymbol`] — ordinal / stub address for imported symbols
//!   - [`SymbolFlags`] — bitflags for symbol kind
//!   - [`SymbolLookup`] — index for O(1) lookups by name or address
//!   - [`RebaseInfo`] — ASLR rebase fixup descriptor

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use bitflags::bitflags;

// ─── SymbolFlags ─────────────────────────────────────────────────────────────

bitflags! {
    /// Mach-O / dyld symbol flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct SymbolFlags: u32 {
        /// Ordinary (non-special) symbol.
        const REGULAR       = 0x0000_0001;
        /// Weak definition (can be overridden).
        const WEAK          = 0x0000_0002;
        /// Thread-local storage symbol.
        const THREAD_LOCAL  = 0x0000_0004;
        /// Absolute symbol (address does not slide).
        const ABSOLUTE      = 0x0000_0008;
        /// Stub-helper trampoline.
        const STUB          = 0x0000_0010;
        /// Re-exported symbol.
        const REEXPORT      = 0x0000_0020;
        /// Symbol is defined in a resolver.
        const RESOLVER      = 0x0000_0040;
    }
}

impl SymbolFlags {
    /// Return `true` if this is a regular (non-special) symbol.
    #[must_use]
    pub const fn is_regular(self) -> bool {
        self.contains(Self::REGULAR)
    }

    /// Return `true` if this is a weak symbol.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        self.contains(Self::WEAK)
    }

    /// Return `true` if this is a thread-local storage symbol.
    #[must_use]
    pub const fn is_thread_local(self) -> bool {
        self.contains(Self::THREAD_LOCAL)
    }

    /// Return `true` if this is an absolute symbol.
    #[must_use]
    pub const fn is_absolute(self) -> bool {
        self.contains(Self::ABSOLUTE)
    }
}

// ─── ExportedSymbol ──────────────────────────────────────────────────────────

/// A symbol exported by a dylib in the dyld shared cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    /// Demangled or raw symbol name.
    pub name: String,
    /// Virtual address in the shared cache address space.
    pub address: u64,
    /// Symbol attribute flags.
    pub flags: SymbolFlags,
    /// Path of the dylib that exports this symbol.
    pub dylib_path: String,
    /// Symbol size hint in bytes (0 when unknown).
    pub size: u64,
}

impl ExportedSymbol {
    /// Return `true` if this is an Objective-C class or method symbol.
    #[must_use]
    pub fn is_objc(&self) -> bool {
        self.name.starts_with("_OBJC_")
            || self.name.starts_with("+[")
            || self.name.starts_with("-[")
    }

    /// Return `true` if this is a Swift symbol.
    #[must_use]
    pub fn is_swift(&self) -> bool {
        self.name.starts_with("$s") || self.name.starts_with("_$s")
    }

    /// Return `true` if this is a C++ mangled symbol.
    #[must_use]
    pub fn is_cxx(&self) -> bool {
        self.name.starts_with("__Z") || self.name.starts_with("_Z")
    }

    /// Return the library name (last path component without extension).
    #[must_use]
    pub fn library_name(&self) -> &str {
        let base = self.dylib_path.rsplit('/').next().unwrap_or(&self.dylib_path);
        // strip .dylib
        if let Some(s) = base.strip_suffix(".dylib") {
            s
        } else {
            base
        }
    }
}

// ─── ImportedSymbol ──────────────────────────────────────────────────────────

/// A symbol imported by a Mach-O image (referenced via a stub).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSymbol {
    /// Symbol name (may be mangled).
    pub name: String,
    /// Ordinal / library index within the load commands.
    pub ordinal: u32,
    /// Address of the GOT entry / stub in the importing image.
    pub stub_address: u64,
    /// Name of the dylib that is expected to provide this symbol.
    pub source_dylib: String,
    /// Whether this import was found as weak (can be null at runtime).
    pub is_weak: bool,
}

impl ImportedSymbol {
    /// Return `true` if the stub address is non-zero (resolved).
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.stub_address != 0
    }
}

// ─── RebaseInfo ──────────────────────────────────────────────────────────────

/// ASLR rebase fixup descriptor for a single pointer location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebaseInfo {
    /// Virtual address of the pointer that must be slid.
    pub target_address: u64,
    /// Rebase type code (matches Mach-O `REBASE_TYPE_*` constants).
    pub rebase_type: u8,
    /// Number of consecutive pointer slots at `target_address`.
    pub count: u32,
    /// Stride between consecutive slots (typically 8 bytes for 64-bit).
    pub skip: u32,
}

impl RebaseInfo {
    /// Return the end address of this rebase range.
    #[must_use]
    pub fn end_address(&self) -> u64 {
        self.target_address
            + u64::from(self.count).saturating_mul(u64::from(self.skip))
    }

    /// Apply `slide` to the in-memory value at `target_address` within `data`.
    ///
    /// Returns the number of pointers patched (up to `self.count`).
    #[must_use]
    pub fn apply_to_slice(&self, data: &mut [u8], base_va: u64, slide: u64) -> usize {
        let mut patched = 0usize;
        for i in 0..self.count as usize {
            let va_offset = (i as u64) * u64::from(self.skip);
            let target_va = self.target_address + va_offset;
            if target_va < base_va {
                continue;
            }
            let file_offset = (target_va - base_va) as usize;
            if file_offset + 8 > data.len() {
                break;
            }
            let raw = u64::from_le_bytes(data[file_offset..file_offset + 8].try_into().unwrap());
            let rebased = raw.wrapping_add(slide);
            data[file_offset..file_offset + 8].copy_from_slice(&rebased.to_le_bytes());
            patched += 1;
        }
        patched
    }
}

// ─── SymbolLookup ─────────────────────────────────────────────────────────────

/// Prebuilt index for O(1) symbol lookups by name or by address.
#[derive(Debug, Default)]
pub struct SymbolLookup {
    /// name → index into `symbols` vec.
    by_name: HashMap<String, usize>,
    /// address → index into `symbols` vec.
    by_address: HashMap<u64, usize>,
    /// Stored symbols (source of truth).
    symbols: Vec<ExportedSymbol>,
}

impl SymbolLookup {
    /// Create an empty lookup index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the lookup index from a list of exported symbols.
    #[must_use]
    pub fn build(symbols: Vec<ExportedSymbol>) -> Self {
        let mut lookup = Self::new();
        for sym in symbols {
            lookup.insert(sym);
        }
        lookup
    }

    /// Insert a symbol into the index.
    pub fn insert(&mut self, sym: ExportedSymbol) {
        let idx = self.symbols.len();
        self.by_name.insert(sym.name.clone(), idx);
        self.by_address.insert(sym.address, idx);
        self.symbols.push(sym);
    }

    /// Look up a symbol by exact name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&ExportedSymbol> {
        self.by_name.get(name).map(|&i| &self.symbols[i])
    }

    /// Look up the symbol whose address matches exactly.
    #[must_use]
    pub fn by_address(&self, addr: u64) -> Option<&ExportedSymbol> {
        self.by_address.get(&addr).map(|&i| &self.symbols[i])
    }

    /// Find the closest symbol whose address is ≤ `addr` (nearest-prev).
    #[must_use]
    pub fn nearest_before(&self, addr: u64) -> Option<&ExportedSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.address <= addr)
            .max_by_key(|s| s.address)
    }

    /// Return all symbols whose name contains `fragment` (case-insensitive).
    #[must_use]
    pub fn search(&self, fragment: &str) -> Vec<&ExportedSymbol> {
        let frag = fragment.to_ascii_lowercase();
        self.symbols
            .iter()
            .filter(|s| s.name.to_ascii_lowercase().contains(&frag))
            .collect()
    }

    /// Return all symbols from a specific dylib path.
    #[must_use]
    pub fn from_dylib(&self, dylib_path: &str) -> Vec<&ExportedSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.dylib_path == dylib_path)
            .collect()
    }

    /// Total number of symbols in the index.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Return `true` if the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Iterate all symbols.
    pub fn iter(&self) -> impl Iterator<Item = &ExportedSymbol> {
        self.symbols.iter()
    }
}

// ─── DyldSymbolTable ─────────────────────────────────────────────────────────

/// High-level dyld shared cache symbol table.
///
/// Aggregates exported symbols from all images in the cache plus imported
/// symbol stubs and rebase information.
#[derive(Debug, Default)]
pub struct DyldSymbolTable {
    /// Index of exported symbols.
    pub exports: SymbolLookup,
    /// Imported symbol stubs (per-image).
    pub imports: Vec<ImportedSymbol>,
    /// Rebase fixup descriptors.
    pub rebases: Vec<RebaseInfo>,
    /// Image path → number of exported symbols.
    pub exports_per_image: HashMap<String, usize>,
}

impl DyldSymbolTable {
    /// Create an empty symbol table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an exported symbol.
    pub fn add_export(&mut self, sym: ExportedSymbol) {
        *self.exports_per_image.entry(sym.dylib_path.clone()).or_insert(0) += 1;
        self.exports.insert(sym);
    }

    /// Add an imported symbol stub.
    pub fn add_import(&mut self, imp: ImportedSymbol) {
        self.imports.push(imp);
    }

    /// Add a rebase descriptor.
    pub fn add_rebase(&mut self, rebase: RebaseInfo) {
        self.rebases.push(rebase);
    }

    /// Total exported symbol count.
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.exports.len()
    }

    /// Total imported symbol count.
    #[must_use]
    pub const fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Total rebase entry count.
    #[must_use]
    pub const fn rebase_count(&self) -> usize {
        self.rebases.len()
    }

    /// Look up an exported symbol by name.
    #[must_use]
    pub fn lookup_export(&self, name: &str) -> Option<&ExportedSymbol> {
        self.exports.by_name(name)
    }

    /// Look up an exported symbol by address.
    #[must_use]
    pub fn lookup_by_address(&self, addr: u64) -> Option<&ExportedSymbol> {
        self.exports.by_address(addr)
    }

    /// Search exports by name fragment.
    #[must_use]
    pub fn search_exports(&self, fragment: &str) -> Vec<&ExportedSymbol> {
        self.exports.search(fragment)
    }

    /// Return all `ObjC` symbols.
    #[must_use]
    pub fn objc_symbols(&self) -> Vec<&ExportedSymbol> {
        self.exports.iter().filter(|s| s.is_objc()).collect()
    }

    /// Return all Swift symbols.
    #[must_use]
    pub fn swift_symbols(&self) -> Vec<&ExportedSymbol> {
        self.exports.iter().filter(|s| s.is_swift()).collect()
    }

    /// Return all weak symbols.
    #[must_use]
    pub fn weak_symbols(&self) -> Vec<&ExportedSymbol> {
        self.exports
            .iter()
            .filter(|s| s.flags.is_weak())
            .collect()
    }

    /// Return all thread-local symbols.
    #[must_use]
    pub fn thread_local_symbols(&self) -> Vec<&ExportedSymbol> {
        self.exports
            .iter()
            .filter(|s| s.flags.is_thread_local())
            .collect()
    }

    /// Populate the table with mock data for unit tests.
    #[must_use]
    pub fn mock() -> Self {
        let mut t = Self::new();

        t.add_export(ExportedSymbol {
            name: "_malloc".to_string(),
            address: 0x1_8000_1000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libSystem.B.dylib".to_string(),
            size: 64,
        });
        t.add_export(ExportedSymbol {
            name: "_free".to_string(),
            address: 0x1_8000_2000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libSystem.B.dylib".to_string(),
            size: 32,
        });
        t.add_export(ExportedSymbol {
            name: "objc_msgSend".to_string(),
            address: 0x1_8010_1000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libobjc.A.dylib".to_string(),
            size: 128,
        });
        t.add_export(ExportedSymbol {
            name: "_OBJC_CLASS_$_NSString".to_string(),
            address: 0x1_8020_0000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            size: 0,
        });
        t.add_export(ExportedSymbol {
            name: "$sSS19stringInterpolationSSs013DefaultStringB0VzlufC".to_string(),
            address: 0x1_8030_0000,
            flags: SymbolFlags::WEAK,
            dylib_path: "/usr/lib/swift/libswiftCore.dylib".to_string(),
            size: 0,
        });
        t.add_import(ImportedSymbol {
            name: "_NSLog".to_string(),
            ordinal: 1,
            stub_address: 0x0010_1000,
            source_dylib: "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            is_weak: false,
        });
        t.add_rebase(RebaseInfo {
            target_address: 0x0020_0000,
            rebase_type: 1,
            count: 4,
            skip: 8,
        });

        t
    }
}

// ─── parse helpers ────────────────────────────────────────────────────────────

/// Parse a trie-encoded export table via depth-first traversal.
///
/// The `trie_data` is the raw export trie blob from a Mach-O `LC_DYLD_EXPORTS_TRIE`
/// or from a dyld cache export trie.  Each node consists of:
///  - A ULEB128 *terminal size* (0 = non-terminal interior node).
///  - If terminal: ULEB128 flags, then ULEB128 address (or ordinal for re-exports).
///  - A one-byte child count.
///  - For each child: NUL-terminated edge label, then ULEB128 child offset.
///
/// Returns a list of `(name, address, flags_bits)` tuples.
#[must_use]
pub fn parse_export_trie_flat(trie_data: &[u8]) -> Vec<(String, u64, u32)> {
    if trie_data.is_empty() {
        return Vec::new();
    }
    let mut results = Vec::new();
    // Stack entries: (trie_offset, name_so_far)
    let mut stack: Vec<(usize, String)> = vec![(0, String::new())];

    while let Some((offset, prefix)) = stack.pop() {
        if offset >= trie_data.len() {
            continue;
        }

        // Read terminal size.
        let (terminal_size, consumed) = decode_uleb128(trie_data, offset);
        let mut pos = offset + consumed;

        if terminal_size != 0 {
            // Terminal node: read flags and address.
            let terminal_end = pos + terminal_size as usize;
            let (flags, fl_consumed) = decode_uleb128(trie_data, pos);
            pos += fl_consumed;
            // Bit 3 (0x08) marks a re-export; those encode an ordinal, not an address.
            let address = if flags & 0x08 == 0 {
                let (addr, addr_consumed) = decode_uleb128(trie_data, pos);
                // Sanity-check: the ULEB128 address must fit within the terminal
                // block. A malformed trie can over-consume; if so we abandon
                // this node to avoid emitting bogus entries.
                let next_pos = pos + addr_consumed;
                debug_assert!(next_pos <= terminal_end, "export trie address overruns terminal block");
                if next_pos > terminal_end {
                    // Skip this malformed terminal entirely.
                    continue;
                }
                addr
            } else {
                // Re-export: skip ordinal; address is not defined for re-exports.
                let (_ordinal, _ord_consumed) = decode_uleb128(trie_data, pos);
                0u64
            };
            results.push((prefix.clone(), address, flags as u32));
            // Advance past remaining terminal bytes.
            pos = terminal_end;
        }

        // Read children.
        if pos >= trie_data.len() {
            continue;
        }
        let child_count = trie_data[pos] as usize;
        pos += 1;

        for _ in 0..child_count {
            // Edge label: NUL-terminated string.
            let label_start = pos;
            while pos < trie_data.len() && trie_data[pos] != 0 {
                pos += 1;
            }
            let label = String::from_utf8_lossy(&trie_data[label_start..pos]).into_owned();
            pos += 1; // skip NUL

            // Child offset: ULEB128.
            let (child_offset, child_consumed) = decode_uleb128(trie_data, pos);
            pos += child_consumed;

            let child_name = format!("{prefix}{label}");
            stack.push((child_offset as usize, child_name));
        }
    }

    results
}

/// Decode a ULEB128-encoded unsigned integer from `data` starting at `offset`.
///
/// Returns `(value, bytes_consumed)`.
#[must_use]
pub fn decode_uleb128(data: &[u8], offset: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut pos = offset;
    loop {
        if pos >= data.len() {
            break;
        }
        let byte = data[pos];
        pos += 1;
        result |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    (result, pos - offset)
}

/// Encode `value` as a ULEB128 byte sequence.
#[must_use]
pub fn encode_uleb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_table() -> DyldSymbolTable {
        DyldSymbolTable::mock()
    }

    // ── SymbolFlags ─────────────────────────────────────────────────────────

    #[test]
    fn test_flags_regular() {
        assert!(SymbolFlags::REGULAR.is_regular());
        assert!(!SymbolFlags::REGULAR.is_weak());
    }

    #[test]
    fn test_flags_weak() {
        assert!(SymbolFlags::WEAK.is_weak());
        assert!(!SymbolFlags::WEAK.is_regular());
    }

    #[test]
    fn test_flags_thread_local() {
        assert!(SymbolFlags::THREAD_LOCAL.is_thread_local());
    }

    #[test]
    fn test_flags_absolute() {
        assert!(SymbolFlags::ABSOLUTE.is_absolute());
    }

    #[test]
    fn test_flags_combined() {
        let f = SymbolFlags::REGULAR | SymbolFlags::WEAK;
        assert!(f.is_regular());
        assert!(f.is_weak());
        assert!(!f.is_thread_local());
    }

    // ── ExportedSymbol ──────────────────────────────────────────────────────

    #[test]
    fn test_exported_is_objc() {
        let s = ExportedSymbol {
            name: "_OBJC_CLASS_$_NSObject".to_string(),
            address: 0x1000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libobjc.A.dylib".to_string(),
            size: 0,
        };
        assert!(s.is_objc());
    }

    #[test]
    fn test_exported_is_swift() {
        let s = ExportedSymbol {
            name: "$sSS4descSSvg".to_string(),
            address: 0x2000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/swift/libswiftCore.dylib".to_string(),
            size: 0,
        };
        assert!(s.is_swift());
    }

    #[test]
    fn test_exported_is_cxx() {
        let s = ExportedSymbol {
            name: "__ZN3Foo3barEv".to_string(),
            address: 0x3000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libstdc++.dylib".to_string(),
            size: 0,
        };
        assert!(s.is_cxx());
    }

    #[test]
    fn test_exported_library_name() {
        let s = ExportedSymbol {
            name: "_malloc".to_string(),
            address: 0x1000,
            flags: SymbolFlags::REGULAR,
            dylib_path: "/usr/lib/libSystem.B.dylib".to_string(),
            size: 0,
        };
        assert_eq!(s.library_name(), "libSystem.B");
    }

    // ── ImportedSymbol ──────────────────────────────────────────────────────

    #[test]
    fn test_imported_is_resolved() {
        let i = ImportedSymbol {
            name: "_NSLog".to_string(),
            ordinal: 1,
            stub_address: 0x1000,
            source_dylib: "Foundation".to_string(),
            is_weak: false,
        };
        assert!(i.is_resolved());
    }

    #[test]
    fn test_imported_not_resolved() {
        let i = ImportedSymbol {
            name: "_NSLog".to_string(),
            ordinal: 1,
            stub_address: 0,
            source_dylib: "Foundation".to_string(),
            is_weak: false,
        };
        assert!(!i.is_resolved());
    }

    // ── RebaseInfo ──────────────────────────────────────────────────────────

    #[test]
    fn test_rebase_end_address() {
        let r = RebaseInfo {
            target_address: 0x1000,
            rebase_type: 1,
            count: 4,
            skip: 8,
        };
        assert_eq!(r.end_address(), 0x1020);
    }

    #[test]
    fn test_rebase_apply_to_slice() {
        let mut data = vec![0u8; 64];
        // Write a pointer at offset 0
        data[0..8].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        let r = RebaseInfo {
            target_address: 0x4000,
            rebase_type: 1,
            count: 1,
            skip: 8,
        };
        let patched = r.apply_to_slice(&mut data, 0x4000, 0x100);
        assert_eq!(patched, 1);
        let rebased = u64::from_le_bytes(data[0..8].try_into().unwrap());
        assert_eq!(rebased, 0x1_8000_0100);
    }

    #[test]
    fn test_rebase_apply_out_of_bounds() {
        let mut data = vec![0u8; 4]; // too small
        let r = RebaseInfo {
            target_address: 0x4000,
            rebase_type: 1,
            count: 1,
            skip: 8,
        };
        let patched = r.apply_to_slice(&mut data, 0x4000, 0x100);
        assert_eq!(patched, 0);
    }

    // ── SymbolLookup ────────────────────────────────────────────────────────

    #[test]
    fn test_lookup_by_name() {
        let t = mock_table();
        let sym = t.exports.by_name("_malloc");
        assert!(sym.is_some());
        assert_eq!(sym.unwrap().address, 0x1_8000_1000);
    }

    #[test]
    fn test_lookup_by_name_missing() {
        let t = mock_table();
        assert!(t.exports.by_name("_nonexistent").is_none());
    }

    #[test]
    fn test_lookup_by_address() {
        let t = mock_table();
        let sym = t.exports.by_address(0x1_8000_2000);
        assert!(sym.is_some());
        assert_eq!(sym.unwrap().name, "_free");
    }

    #[test]
    fn test_lookup_by_address_missing() {
        let t = mock_table();
        assert!(t.exports.by_address(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn test_lookup_nearest_before() {
        let t = mock_table();
        // Address slightly above _malloc
        let sym = t.exports.nearest_before(0x1_8000_1010);
        assert!(sym.is_some());
        assert_eq!(sym.unwrap().name, "_malloc");
    }

    #[test]
    fn test_lookup_search() {
        let t = mock_table();
        let results = t.exports.search("malloc");
        assert!(!results.is_empty());
        assert!(results.iter().any(|s| s.name == "_malloc"));
    }

    #[test]
    fn test_lookup_search_case_insensitive() {
        let t = mock_table();
        let results = t.exports.search("MALLOC");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_lookup_from_dylib() {
        let t = mock_table();
        let syms = t.exports.from_dylib("/usr/lib/libSystem.B.dylib");
        assert_eq!(syms.len(), 2);
    }

    // ── DyldSymbolTable ─────────────────────────────────────────────────────

    #[test]
    fn test_table_export_count() {
        let t = mock_table();
        assert_eq!(t.export_count(), 5);
    }

    #[test]
    fn test_table_import_count() {
        let t = mock_table();
        assert_eq!(t.import_count(), 1);
    }

    #[test]
    fn test_table_rebase_count() {
        let t = mock_table();
        assert_eq!(t.rebase_count(), 1);
    }

    #[test]
    fn test_table_lookup_export() {
        let t = mock_table();
        assert!(t.lookup_export("_malloc").is_some());
        assert!(t.lookup_export("missing").is_none());
    }

    #[test]
    fn test_table_lookup_by_address() {
        let t = mock_table();
        assert!(t.lookup_by_address(0x1_8010_1000).is_some());
    }

    #[test]
    fn test_table_objc_symbols() {
        let t = mock_table();
        let objc = t.objc_symbols();
        assert!(!objc.is_empty());
        assert!(objc.iter().all(|s| s.is_objc()));
    }

    #[test]
    fn test_table_swift_symbols() {
        let t = mock_table();
        let swift = t.swift_symbols();
        assert!(!swift.is_empty());
        assert!(swift.iter().all(|s| s.is_swift()));
    }

    #[test]
    fn test_table_weak_symbols() {
        let t = mock_table();
        let weak = t.weak_symbols();
        assert_eq!(weak.len(), 1);
        assert!(weak[0].flags.is_weak());
    }

    #[test]
    fn test_table_exports_per_image() {
        let t = mock_table();
        assert!(t.exports_per_image.contains_key("/usr/lib/libSystem.B.dylib"));
    }

    #[test]
    fn test_table_search_exports() {
        let t = mock_table();
        let results = t.search_exports("objc");
        assert!(!results.is_empty());
    }

    // ── ULEB128 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_uleb128_decode_single_byte() {
        let data = [0x05u8];
        let (val, consumed) = decode_uleb128(&data, 0);
        assert_eq!(val, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_uleb128_decode_multi_byte() {
        // 300 = 0b1_0010_1100 → [0xAC, 0x02]
        let data = [0xACu8, 0x02u8];
        let (val, consumed) = decode_uleb128(&data, 0);
        assert_eq!(val, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_uleb128_roundtrip() {
        for val in [0u64, 1, 127, 128, 300, 0xFFFF, 0x1_0000_0000] {
            let encoded = encode_uleb128(val);
            let (decoded, _) = decode_uleb128(&encoded, 0);
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_uleb128_encode_single_byte() {
        let enc = encode_uleb128(0);
        assert_eq!(enc, vec![0x00]);
        let enc2 = encode_uleb128(127);
        assert_eq!(enc2, vec![0x7F]);
    }

    #[test]
    fn test_uleb128_encode_128() {
        let enc = encode_uleb128(128);
        assert_eq!(enc, vec![0x80, 0x01]);
    }
}
