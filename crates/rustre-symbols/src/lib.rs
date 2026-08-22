//! `rustre-symbols` — unified symbol types, providers, and infrastructure.
//!
//! Spec §7: symbol unification across PDB, DWARF, `CodeView`, STABS, FLIRT, PE/ELF tables.
//!
//! # Key types
//!
//! * [`Symbol`] — canonical low-level symbol record (ELF-style fields).
//! * [`UnifiedSymbol`] / [`UnifiedSymbolTable`] — spec §7 high-level layer.
//! * [`SymbolKind`] / [`SymbolSource`] — spec §7 taxonomy.
//! * [`SymbolProvider`] trait — any back-end that can produce symbols.
//! * [`SymbolTable`] — aggregates providers with caching.
//! * [`SymbolFilter`] — builder for filtered queries.

// The spec-§7 layer is documented; the legacy layer is being documented
// top-down (errors, kinds, `Symbol` fields first — those carry the most
// semantic ambiguity). Promote to `deny` once clean.
#![warn(missing_docs)]
//! * [`SymbolCache`] — LRU address→symbol cache.
//! * [`SymbolStore`] — in-process, BTreeMap-backed store with name index.
//! * [`SymbolResolver`] — chains providers with fallback logic.
//! * [`SymbolExporter`] — serialise to JSON, CSV, IDA-IDC, MAP.
//! * [`AddressToSymbolMap`] — fast binary-search reverse lookup.
//! * [`FunctionBoundary`] — half-open address range.
//! * [`ExportTable`] / [`ImportTable`] — specialised views.
//! * [`SectionSymbols`] — symbols grouped by section index.
//! * [`SymbolStats`] — per-kind counts.
//! * [`SymbolConflictResolver`] — winner selection when addresses collide.
//! * [`SyntheticSymbolGen`] — auto-generates "`sub_XXXX`" / "`byte_XXXX`" names.
//! * [`DemanglerPipeline`] — try multiple demanglers in order with caching.

pub mod codeview_provider;
pub mod dwarf_provider;
pub mod elf_provider;
pub mod pdb_provider;
pub mod stabs_provider;
pub mod symbol_cross_ref;
pub mod symbol_demangler;
pub mod symbol_merger;
pub mod symbol_resolution;
pub mod symbol_table_builder;
pub mod symbol_exporter;
pub mod symbol_importer;
pub mod symbol_search;
pub mod symbol_versioning;
pub mod symbol_address_resolver;
pub mod symbol_enrichment;
pub mod pdb_discovery;
pub mod symbol_server;
pub mod name_store_bridge;

pub use pdb_discovery::discover_pdb_for_binary;
pub use symbol_server::{
    HttpCommandFetcher, MockFetcher, SymSrvError, SymbolFetcher, SymbolServerClient, msdl_url,
    symbol_server_key,
};
pub use name_store_bridge::{
    KeyedNameStore, NameStoreSink, PopulateOptions, build_name_map, populate_from_provider,
    populate_from_providers, populate_from_unified_table,
};

// ── Sub-crate backend registry ────────────────────────────────────────────────
//
// Each wired sub-crate is re-exported here under `backends::*` and registered
// in the [`backends::registry`] list so downstream code can enumerate which
// debug-format readers are compiled into this build.

pub mod backends {
    //! Wired symbol-backend sub-crates.
    //!
    //! Re-exports the principal types from every `rustre-symbols-*` companion
    //! crate and provides a [`registry`] dispatcher listing them.

    // NOTE: the re-exports of the four sub-crate providers were removed
    // to break the workspace dep cycle (`rustre-symbols` → sub-crate →
    // `rustre-symbols` for the shared `SymbolProvider`/`Symbol` types).
    // Consumers should depend on each `rustre-symbols-*` crate
    // directly. The descriptor table below still names the providers
    // for tools that want to introspect the available backends.

    /// One descriptor per wired sub-crate backend.
    #[derive(Debug, Clone, Copy)]
    pub struct BackendDescriptor {
        /// Sub-crate name (matches the Cargo package name).
        pub crate_name: &'static str,
        /// Human-readable debug-format label.
        pub format: &'static str,
        /// Type name of the principal exported reader/provider.
        pub provider_type: &'static str,
    }

    /// Enumerate every wired backend sub-crate.
    #[must_use]
    pub fn registry() -> Vec<BackendDescriptor> {
        vec![
            BackendDescriptor {
                crate_name: "rustre-symbols-codeview",
                format: "CodeView",
                provider_type: "rustre_symbols_codeview::CodeViewProvider",
            },
            BackendDescriptor {
                crate_name: "rustre-symbols-dwarf",
                format: "DWARF",
                provider_type: "rustre_symbols_dwarf::DwarfSymbolProvider",
            },
            BackendDescriptor {
                crate_name: "rustre-symbols-pdb",
                format: "PDB",
                provider_type: "rustre_symbols_pdb::PdbReader",
            },
            BackendDescriptor {
                crate_name: "rustre-symbols-stabs",
                format: "STABS",
                provider_type: "rustre_symbols_stabs::StabsProvider",
            },
        ]
    }
}

use crate::symbol_exporter::csv_escape;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
pub use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

static SYMBOL_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error returned by symbol-store and provider operations.
#[derive(Debug, Error)]
pub enum SymbolError {
    /// No symbol matched the requested name.
    #[error("symbol not found: {0}")]
    NotFound(String),
    /// No symbol was found at (or covering) the requested address.
    #[error("address not found: {0:#x}")]
    AddressNotFound(u64),
    /// A symbol with the same identity (address + name) already exists.
    #[error("duplicate symbol: {0}")]
    Duplicate(String),
    /// A backing debug/symbol format could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
    /// An I/O error occurred while reading a symbol source.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Any other error, carrying a human-readable message.
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for SymbolError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}

// ── SymbolKind (legacy low-level) ─────────────────────────────────────────────

/// What a [`Symbol`] denotes, in the low-level (ELF-flavoured) taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymKind {
    /// Executable code with a call target at `address`.
    Function,
    /// Initialised or uninitialised data object.
    Data,
    /// A named code address that is not a function entry point.
    Label,
    /// A section header symbol (ELF `STT_SECTION`).
    Section,
    /// A source-file name symbol (ELF `STT_FILE`); carries no address.
    File,
    /// A type definition recovered from debug info, not a runtime object.
    Type,
    /// A namespace / module scope, not a runtime object.
    Namespace,
    /// Thread-local storage object; `address` is a TLS-block offset, not a VA.
    TLS,
    /// GNU indirect function. `address` holds a *resolver* that returns the
    /// real implementation — it is not the implementation itself.
    IFunc,
    /// Common (tentatively defined) object; `size` is an alignment request.
    Common,
    /// Kind could not be determined.
    Unknown,
}

impl fmt::Display for SymKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SymbolBinding / Visibility ────────────────────────────────────────────────

/// Linkage binding of a symbol (ELF `st_bind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolBinding {
    /// Not visible outside its object file.
    Local,
    /// Visible to all objects being combined.
    Global,
    /// Like `Global`, but a strong definition elsewhere overrides it.
    Weak,
    /// GNU extension: unique across the whole process, even in `dlopen`ed objects.
    GnuUnique,
}
impl fmt::Display for SymbolBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Symbol visibility (ELF `st_other`), controlling cross-object reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolVisibility {
    /// Visibility as specified by the symbol's binding.
    Default,
    /// Not visible to other components.
    Hidden,
    /// Visible to others, but references inside the defining component always
    /// resolve to the local definition.
    Protected,
    /// Processor-specific; stricter than `Hidden`.
    Internal,
}
impl fmt::Display for SymbolVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Backwards-compatible alias kept for older call sites; despite the name it
/// aliases [`SymbolBinding`] (ELF `st_bind`), not [`SymbolVisibility`].
pub type SymVisibility = SymbolBinding;

// ── LegacySymbolSource ────────────────────────────────────────────────────────

/// Where a [`Symbol`] came from, in the legacy (pre-spec-§7) taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LegacySymbolSource {
    /// An export table entry (PE exports, ELF `.dynsym` defined).
    Export,
    /// An import / undefined reference resolved at load time.
    Import,
    /// Debug information: PDB, DWARF, `CodeView`, or STABS.
    Debug,
    /// Generated by analysis (e.g. `sub_401000`), not present in the binary.
    Synthetic,
    /// Supplied or renamed by the user; highest trust.
    User,
}
impl fmt::Display for LegacySymbolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Symbol (low-level canonical record) ──────────────────────────────────────

/// The canonical low-level symbol record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Stable identity for this record. Providers conventionally set it to
    /// `address`; it is not guaranteed unique across merged tables.
    pub id: u64,
    /// Raw, still-mangled name exactly as it appears in the binary.
    pub name: String,
    /// Human-readable name, if demangling succeeded. `None` means either not
    /// attempted or not a mangled name — not that demangling failed.
    pub demangled_name: Option<String>,
    /// Virtual address (not an RVA). Providers that read RVAs add the image
    /// base before constructing the symbol.
    pub address: u64,
    /// Size in bytes. `None` means *unknown* — distinct from `Some(0)`, which
    /// means the producer explicitly recorded a zero-length symbol.
    pub size: Option<u64>,
    /// What this symbol denotes.
    pub kind: SymKind,
    /// Linkage binding.
    pub binding: SymbolBinding,
    /// Cross-object visibility.
    pub visibility: SymbolVisibility,
    /// 1-based section index the symbol lives in, if known.
    pub section_index: Option<u16>,
    /// Offset of the symbol's bytes within the file on disk, if known. This is
    /// a file offset, not a virtual address.
    pub file_offset: Option<u64>,
    /// Which kind of producer emitted this record.
    pub source: LegacySymbolSource,
    /// Declaring source file, from debug info.
    pub source_file: Option<String>,
    /// Declaring source line, from debug info.
    pub source_line: Option<u32>,
    /// Export ordinal (PE), if this symbol is an ordinal export.
    pub ordinal: Option<u32>,
    /// Free-form provider annotations, e.g. `"codeview"`, `"cv_type:7"`.
    pub tags: Vec<String>,
}

impl Symbol {
    /// Create a symbol with the given name, virtual address and kind,
    /// assigning a fresh process-unique [`Symbol::id`] and leaving all optional
    /// fields empty (global binding, default visibility, `Debug` source).
    #[must_use]
    pub fn new(name: String, address: u64, kind: SymKind) -> Self {
        Self {
            id: SYMBOL_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            name,
            demangled_name: None,
            address,
            size: None,
            kind,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: None,
            file_offset: None,
            source: LegacySymbolSource::Debug,
            source_file: None,
            source_line: None,
            ordinal: None,
            tags: vec![],
        }
    }

    /// The demangled name if present, otherwise the raw name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.name)
    }
    /// One-past-the-end virtual address (`address + size`), or `None` when the
    /// size is unknown or the addition would overflow.
    #[must_use]
    pub fn end_address(&self) -> Option<u64> {
        self.size.and_then(|s| self.address.checked_add(s))
    }
    /// Whether `addr` falls within this symbol's `[address, address+size)`
    /// range; when the size is unknown, only an exact address match counts.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.size.map_or(self.address == addr, |s| {
            addr >= self.address
                && self.address.checked_add(s).is_some_and(|end| addr < end)
        })
    }
    /// Whether this symbol denotes executable code (`Function`, `Label` or `IFunc`).
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(
            self.kind,
            SymKind::Function | SymKind::Label | SymKind::IFunc
        )
    }
    /// Whether this symbol denotes a data object (`Data`, `Common` or `TLS`).
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self.kind, SymKind::Data | SymKind::Common | SymKind::TLS)
    }
    /// Set the demangled name.
    pub fn set_demangled(&mut self, name: String) {
        self.demangled_name = Some(name);
    }
    /// Add a provider annotation tag, ignoring duplicates.
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }
    /// Derive a [`FunctionBoundary`] from this symbol, or `None` if it is not a
    /// function or its size is unknown.
    #[must_use]
    pub fn function_boundary(&self) -> Option<FunctionBoundary> {
        if !self.is_function() {
            return None;
        }
        let size = self.size?;
        let end = self.address.checked_add(size)?;
        Some(FunctionBoundary {
            start: self.address,
            end,
            name: self.name.clone(),
        })
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({:?})",
            self.display_name(),
            self.address,
            self.kind
        )
    }
}

// ── FunctionBoundary ──────────────────────────────────────────────────────────

/// Half-open virtual-address range `[start, end)` naming one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionBoundary {
    /// Inclusive start virtual address (the function's entry point).
    pub start: u64,
    /// Exclusive end virtual address (one past the last instruction byte).
    pub end: u64,
    /// The function's (raw) name.
    pub name: String,
}

impl FunctionBoundary {
    /// Construct a boundary from an explicit `[start, end)` range and name.
    #[must_use]
    pub const fn new(start: u64, end: u64, name: String) -> Self {
        Self { start, end, name }
    }
    /// Length of the range in bytes (`end - start`), saturating at zero.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    /// Whether `addr` lies within `[start, end)`.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
    /// Whether this range and `other` overlap; empty/inverted ranges never overlap.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let self_valid = self.start < self.end;
        let other_valid = other.start < other.end;
        let intervals_overlap = self.start < other.end && other.start < self.end;
        self_valid && other_valid && intervals_overlap
    }
}

impl fmt::Display for FunctionBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{:#x}..{:#x})", self.name, self.start, self.end)
    }
}

// ── TypeInfo ──────────────────────────────────────────────────────────────────

/// A recovered type description, as attached to symbols by debug-info readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeInfo {
    /// The `void` type (no value / unknown-but-empty).
    Void,
    /// A boolean.
    Bool,
    /// An integer of `width` bytes, signed or unsigned.
    Int {
        /// Width of the integer in bytes (1, 2, 4, 8, …).
        width: u8,
        /// `true` for a signed integer, `false` for unsigned.
        signed: bool,
    },
    /// A floating-point number of `width` bytes (4 = `f32`, 8 = `f64`).
    Float {
        /// Width of the float in bytes.
        width: u8,
    },
    /// A pointer to `target`.
    Pointer {
        /// The pointed-to type.
        target: Box<Self>,
        /// Size of the pointer itself in bytes (4 on 32-bit, 8 on 64-bit).
        size: u8,
    },
    /// A fixed-length array of `element`.
    Array {
        /// Element type.
        element: Box<Self>,
        /// Number of elements.
        count: u64,
    },
    /// A struct/record type with named, offset-placed fields.
    Struct {
        /// The struct's tag/name.
        name: String,
        /// Member fields in declaration order.
        fields: Vec<StructField>,
    },
    /// An enumeration type over a fixed integer base type.
    Enum {
        /// The enum's tag/name.
        name: String,
        /// `(name, value)` pairs of enumerators.
        variants: Vec<(String, i64)>,
        /// Underlying integer representation type.
        base_type: Box<Self>,
    },
    /// A function type (used for function pointers / subroutine types).
    Function {
        /// Return type.
        return_type: Box<Self>,
        /// Parameter types in order.
        params: Vec<Self>,
    },
    /// A named type reference that has not been (or need not be) expanded.
    Named(String),
    /// The type could not be recovered.
    Unknown,
}

impl fmt::Display for TypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::Int { width, signed } => write!(f, "{}{width}", if *signed { "i" } else { "u" }),
            Self::Float { width } => write!(f, "f{width}"),
            Self::Pointer { target, size } => write!(f, "*{target}[{size}]"),
            Self::Array { element, count } => write!(f, "{element}[{count}]"),
            Self::Struct { name, .. } => write!(f, "struct {name}"),
            Self::Enum { name, .. } => write!(f, "enum {name}"),
            Self::Function { .. } => write!(f, "fn(...)"),
            Self::Named(n) => write!(f, "{n}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// One member of a [`TypeInfo::Struct`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    /// Member name.
    pub name: String,
    /// Byte offset of the member from the start of the struct.
    pub offset: u32,
    /// Member type.
    pub type_info: TypeInfo,
}
impl fmt::Display for StructField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "+{:#x} {}: {}", self.offset, self.name, self.type_info)
    }
}

// ── SourceLocation ────────────────────────────────────────────────────────────

/// A source-code position (file, 1-based line, 1-based column) recovered from
/// debug line tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file path or name.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (0 when unknown).
    pub column: u32,
}
impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

// ── SymbolProvider trait ──────────────────────────────────────────────────────

/// A back-end that can supply [`Symbol`]s (PDB, DWARF, `CodeView`, STABS, ELF/PE
/// tables, …). All methods are read-only lookups over the provider's contents.
pub trait SymbolProvider: Send + Sync + fmt::Debug {
    /// Short human-readable identifier for this provider (e.g. `"dwarf"`).
    fn name(&self) -> &str;
    /// Find the symbol with an exactly matching name, if any.
    fn lookup_name(&self, name: &str) -> Option<Symbol>;
    /// Find the symbol whose address exactly equals `addr`, if any.
    fn lookup_address(&self, addr: u64) -> Option<Symbol>;
    /// Find the symbol with the largest address not exceeding `addr`.
    fn lookup_nearest(&self, addr: u64) -> Option<Symbol>;
    /// Return every symbol this provider knows about.
    fn all_symbols(&self) -> Vec<Symbol>;
    /// Return only the function symbols.
    fn all_functions(&self) -> Vec<Symbol>;
    /// Map a virtual address to its source location, if line info is available.
    fn source_line_for_address(&self, addr: u64) -> Option<SourceLocation>;
}

// ── SymbolTable ───────────────────────────────────────────────────────────────

/// Aggregates several [`SymbolProvider`]s behind a shared, thread-safe façade
/// with an address→symbol cache. Providers are queried in insertion order and
/// the first match wins.
pub struct SymbolTable {
    providers: RwLock<Vec<Box<dyn SymbolProvider>>>,
    cache: RwLock<HashMap<u64, Symbol>>,
}

impl SymbolTable {
    /// Create an empty table with no providers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(vec![]),
            cache: RwLock::new(HashMap::new()),
        }
    }
    /// Append a provider; later providers are consulted only if earlier ones miss.
    pub fn add_provider(&self, provider: Box<dyn SymbolProvider>) {
        self.providers.write().push(provider);
    }
    /// Look up a symbol by name across all providers (first match wins).
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.providers
            .read()
            .iter()
            .find_map(|p| p.lookup_name(name))
    }
    /// Look up a symbol by exact address, caching the result for reuse.
    #[must_use]
    pub fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        if let Some(sym) = self.cache.read().get(&addr) {
            return Some(sym.clone());
        }
        let sym = self
            .providers
            .read()
            .iter()
            .find_map(|p| p.lookup_address(addr))?;
        self.cache.write().insert(addr, sym.clone());
        Some(sym)
    }
    /// Look up the nearest symbol at or below `addr` across all providers.
    #[must_use]
    pub fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        self.providers
            .read()
            .iter()
            .find_map(|p| p.lookup_nearest(addr))
    }
    /// Collect every symbol from every provider (duplicates are not removed).
    #[must_use]
    pub fn all_symbols(&self) -> Vec<Symbol> {
        self.providers
            .read()
            .iter()
            .flat_map(|p| p.all_symbols())
            .collect()
    }
    /// Number of registered providers.
    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.read().len()
    }
    /// Drop all cached address→symbol lookups.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }
    /// Compute per-kind statistics over all symbols from all providers.
    #[must_use]
    pub fn stats(&self) -> SymbolStats {
        SymbolStats::from_symbols(&self.all_symbols())
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for SymbolTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymbolTable({} providers)", self.providers.read().len())
    }
}

// ── InMemorySymbolProvider ────────────────────────────────────────────────────

/// A simple [`SymbolProvider`] backed by an in-memory `Vec<Symbol>`; useful for
/// tests and for injecting user-supplied symbols.
#[derive(Debug, Default)]
pub struct InMemorySymbolProvider {
    symbols: Vec<Symbol>,
}

impl InMemorySymbolProvider {
    /// Create an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a symbol.
    pub fn add(&mut self, sym: Symbol) {
        self.symbols.push(sym);
    }
    /// Number of stored symbols.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }
    /// Whether no symbols are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
    /// Remove every symbol with the given name; returns `true` if any were removed.
    pub fn remove_by_name(&mut self, name: &str) -> bool {
        let before = self.symbols.len();
        self.symbols.retain(|s| s.name != name);
        self.symbols.len() != before
    }
    /// Sort the stored symbols by ascending address.
    pub fn sort_by_address(&mut self) {
        self.symbols.sort_by_key(|s| s.address);
    }
    /// Rename the first symbol matching `old_name`; returns `true` on success.
    pub fn rename(&mut self, old_name: &str, new_name: String) -> bool {
        if let Some(s) = self.symbols.iter_mut().find(|s| s.name == old_name) {
            s.name = new_name;
            true
        } else {
            false
        }
    }
}

impl SymbolProvider for InMemorySymbolProvider {
    fn name(&self) -> &'static str {
        "in-memory"
    }
    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.symbols.iter().find(|s| s.name == name).cloned()
    }
    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.symbols.iter().find(|s| s.address == addr).cloned()
    }
    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.address <= addr)
            .min_by_key(|s| addr - s.address)
            .cloned()
    }
    fn all_symbols(&self) -> Vec<Symbol> {
        self.symbols.clone()
    }
    fn all_functions(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }
    fn source_line_for_address(&self, _addr: u64) -> Option<SourceLocation> {
        None
    }
}

// ── SymbolFilter ─────────────────────────────────────────────────────────────

/// A composable, builder-style predicate over [`Symbol`]s. Unset criteria match
/// everything; call [`SymbolFilter::apply`] to run it over a slice.
#[derive(Debug, Default)]
pub struct SymbolFilter {
    addr_min: Option<u64>,
    addr_max: Option<u64>,
    kinds: Vec<SymKind>,
    name_prefix: Option<String>,
    sources: Vec<LegacySymbolSource>,
    section_index: Option<u16>,
    max_results: Option<usize>,
}

impl SymbolFilter {
    /// Create a filter that matches every symbol.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Keep only symbols with address `>= min`.
    #[must_use]
    pub const fn address_min(mut self, min: u64) -> Self {
        self.addr_min = Some(min);
        self
    }
    /// Keep only symbols with address `<= max`.
    #[must_use]
    pub const fn address_max(mut self, max: u64) -> Self {
        self.addr_max = Some(max);
        self
    }
    /// Keep only symbols in the half-open address range `[lo, hi)`.
    #[must_use]
    pub const fn address_range(mut self, lo: u64, hi: u64) -> Self {
        self.addr_min = Some(lo);
        self.addr_max = Some(hi.saturating_sub(1));
        self
    }
    /// Keep only symbols whose kind is in `kinds` (empty = all kinds).
    #[must_use]
    pub fn kinds(mut self, kinds: Vec<SymKind>) -> Self {
        self.kinds = kinds;
        self
    }
    /// Keep only symbols whose name starts with `prefix`.
    #[must_use]
    pub fn name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = Some(prefix.into());
        self
    }
    /// Keep only symbols whose source is in `sources` (empty = all sources).
    #[must_use]
    pub fn sources(mut self, sources: Vec<LegacySymbolSource>) -> Self {
        self.sources = sources;
        self
    }
    /// Keep only symbols in the given section index.
    #[must_use]
    pub const fn section_index(mut self, idx: u16) -> Self {
        self.section_index = Some(idx);
        self
    }
    /// Cap the number of returned results at `n`.
    #[must_use]
    pub const fn max(mut self, n: usize) -> Self {
        self.max_results = Some(n);
        self
    }
    /// Apply the filter to `symbols`, returning matching clones (respecting the
    /// result cap, if any).
    #[must_use]
    pub fn apply(&self, symbols: &[Symbol]) -> Vec<Symbol> {
        let mut result: Vec<Symbol> = symbols
            .iter()
            .filter(|s| {
                if let Some(lo) = self.addr_min
                    && s.address < lo
                {
                    return false;
                }
                if let Some(hi) = self.addr_max
                    && s.address > hi
                {
                    return false;
                }
                if !self.kinds.is_empty() && !self.kinds.contains(&s.kind) {
                    return false;
                }
                if let Some(ref pfx) = self.name_prefix
                    && !s.name.starts_with(pfx.as_str())
                {
                    return false;
                }
                if !self.sources.is_empty() && !self.sources.contains(&s.source) {
                    return false;
                }
                if let Some(sec) = self.section_index
                    && s.section_index != Some(sec)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        if let Some(max) = self.max_results {
            result.truncate(max);
        }
        result
    }
}

// ── AddressToSymbolMap ────────────────────────────────────────────────────────

/// A sorted array of `(address, symbol)` pairs supporting fast binary-search
/// exact and floor lookups. Must be [`sort`](Self::sort)ed before querying.
#[derive(Debug, Default)]
pub struct AddressToSymbolMap {
    entries: Vec<(u64, Symbol)>,
    sorted: bool,
}

impl AddressToSymbolMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Build a sorted map from a slice of symbols (ready to query immediately).
    #[must_use]
    pub fn from_symbols(symbols: &[Symbol]) -> Self {
        let mut m = Self::new();
        for s in symbols {
            m.insert(s.clone());
        }
        m.sort();
        m
    }
    /// Insert one symbol, marking the map unsorted.
    pub fn insert(&mut self, sym: Symbol) {
        self.entries.push((sym.address, sym));
        self.sorted = false;
    }
    /// Sort entries by address; required before any lookup.
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|(a, _)| *a);
        self.sorted = true;
    }
    /// Return the symbol whose address exactly equals `addr`, or `None`.
    #[must_use]
    pub fn lookup_exact(&self, addr: u64) -> Option<&Symbol> {
        debug_assert!(self.sorted, "AddressToSymbolMap::lookup_exact called on unsorted map; call sort() first");
        if !self.sorted {
            return None;
        }
        let idx = self.entries.binary_search_by_key(&addr, |(a, _)| *a).ok()?;
        Some(&self.entries[idx].1)
    }
    /// Return the symbol with the largest address `<= addr`, or `None`.
    #[must_use]
    pub fn lookup_floor(&self, addr: u64) -> Option<&Symbol> {
        debug_assert!(self.sorted, "AddressToSymbolMap::lookup_floor called on unsorted map; call sort() first");
        if !self.sorted {
            return None;
        }
        let idx = match self.entries.binary_search_by_key(&addr, |(a, _)| *a) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        Some(&self.entries[idx].1)
    }
    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Borrow every stored symbol.
    #[must_use]
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.entries.iter().map(|(_, s)| s).collect()
    }
}

// ── SymbolCache ───────────────────────────────────────────────────────────────

/// A small fixed-capacity, move-to-front LRU cache mapping address→[`Symbol`].
pub struct SymbolCache {
    cap: usize,
    entries: Vec<(u64, Symbol)>,
}

impl SymbolCache {
    /// Create a cache holding at most `capacity` entries (clamped to at least 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            cap: capacity.max(1),
            entries: Vec::new(),
        }
    }
    /// Insert or update `addr`→`sym`, evicting the least-recently-used entry
    /// when at capacity.
    pub fn insert(&mut self, addr: u64, sym: Symbol) {
        if let Some(pos) = self.entries.iter().position(|(a, _)| *a == addr) {
            self.entries[pos].1 = sym;
            self.touch(addr);
            return;
        }
        if self.entries.len() >= self.cap {
            self.entries.pop();
        }
        self.entries.insert(0, (addr, sym));
    }
    /// Fetch the symbol cached for `addr`, promoting it to most-recently-used.
    pub fn get(&mut self, addr: u64) -> Option<Symbol> {
        let pos = self.entries.iter().position(|(a, _)| *a == addr)?;
        let entry = self.entries.remove(pos);
        let sym = entry.1.clone();
        self.entries.insert(0, entry);
        Some(sym)
    }
    fn touch(&mut self, addr: u64) {
        if let Some(pos) = self.entries.iter().position(|(a, _)| *a == addr) {
            let entry = self.entries.remove(pos);
            self.entries.insert(0, entry);
        }
    }
    /// Number of currently cached entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the cache holds no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Drop all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    /// The configured maximum number of entries.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.cap
    }
}

impl fmt::Debug for SymbolCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolCache(cap={}, len={})",
            self.cap,
            self.entries.len()
        )
    }
}

// ── SymbolStore ───────────────────────────────────────────────────────────────

/// In-process symbol store: `BTreeMap`<address, Vec<Symbol>> primary,
/// `HashMap`<name, Vec<addr>> secondary index.
#[derive(Debug, Default)]
pub struct SymbolStore {
    by_addr: BTreeMap<u64, Vec<Symbol>>,
    by_name: HashMap<String, Vec<u64>>,
    count: usize,
}

impl SymbolStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol; returns `Err(Duplicate)` if the exact (addr, name) pair exists.
    ///
    /// # Errors
    ///
    /// Returns `SymbolError::Duplicate` if a symbol with the same address and name is already stored.
    pub fn insert(&mut self, sym: Symbol) -> Result<(), SymbolError> {
        let addr = sym.address;
        let name = sym.name.clone();
        // Check for duplicate (addr + name)
        if let Some(syms) = self.by_addr.get(&addr)
            && syms.iter().any(|s| s.name == name)
        {
            return Err(SymbolError::Duplicate(name));
        }
        self.by_addr.entry(addr).or_default().push(sym);
        self.by_name.entry(name).or_default().push(addr);
        self.count += 1;
        Ok(())
    }

    /// Upsert: insert or update in place.
    pub fn upsert(&mut self, sym: Symbol) {
        let addr = sym.address;
        let name = sym.name.clone();
        if let Some(syms) = self.by_addr.get_mut(&addr)
            && let Some(existing) = syms.iter_mut().find(|s| s.name == name)
        {
            *existing = sym;
            return;
        }
        let _ = self.insert(sym);
    }

    /// Remove all symbols at `addr` with given `name`. Returns removed count.
    pub fn remove(&mut self, addr: u64, name: &str) -> usize {
        let mut removed = 0;
        if let Some(syms) = self.by_addr.get_mut(&addr) {
            let before = syms.len();
            syms.retain(|s| s.name != name);
            removed = before - syms.len();
            if syms.is_empty() {
                self.by_addr.remove(&addr);
            }
        }
        if removed > 0 {
            if let Some(addrs) = self.by_name.get_mut(name) {
                addrs.retain(|&a| a != addr);
                if addrs.is_empty() {
                    self.by_name.remove(name);
                }
            }
            self.count -= removed;
        }
        removed
    }

    /// All symbols recorded at exactly `addr` (an address may host several).
    #[must_use]
    pub fn find_by_addr(&self, addr: u64) -> Vec<&Symbol> {
        self.by_addr
            .get(&addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// All symbols whose name equals `name`, via the secondary name index.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&Symbol> {
        self.by_name
            .get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .flat_map(|&a| self.by_addr.get(&a).into_iter().flatten())
                    .filter(|s| s.name == name)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All symbols whose name starts with `prefix` (linear scan).
    #[must_use]
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&Symbol> {
        self.by_addr
            .values()
            .flatten()
            .filter(|s| s.name.starts_with(prefix))
            .collect()
    }

    /// All symbols with address in the half-open range `[start, end)`.
    #[must_use]
    pub fn find_in_range(&self, start: u64, end: u64) -> Vec<&Symbol> {
        self.by_addr
            .range(start..end)
            .flat_map(|(_, v)| v.iter())
            .collect()
    }

    /// Rename the symbol at `addr` from `old_name` to `new_name`, keeping the
    /// name index consistent; returns `true` if a matching symbol was found.
    pub fn rename(&mut self, addr: u64, old_name: &str, new_name: &str) -> bool {
        if let Some(syms) = self.by_addr.get_mut(&addr)
            && let Some(sym) = syms.iter_mut().find(|s| s.name == old_name)
        {
            // Update name index
            if let Some(addrs) = self.by_name.get_mut(old_name) {
                addrs.retain(|&a| a != addr);
            }
            sym.name = new_name.to_string();
            self.by_name
                .entry(new_name.to_string())
                .or_default()
                .push(addr);
            return true;
        }
        false
    }

    /// Merge another `SymbolStore` into this one (upsert all symbols).
    pub fn merge(&mut self, other: &Self) {
        for sym in other.iter() {
            self.upsert(sym.clone());
        }
    }

    /// Total number of stored symbols.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }
    /// Whether the store holds no symbols.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    /// Iterate over all symbols in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.by_addr.values().flatten()
    }
    /// Compute per-kind statistics over the stored symbols.
    #[must_use]
    pub fn stats(&self) -> SymbolStats {
        SymbolStats::from_symbols_iter(self.iter())
    }

    /// Floor lookup: find symbol with largest address <= addr.
    #[must_use]
    pub fn get_floor(&self, addr: u64) -> Option<&Symbol> {
        self.by_addr
            .range(..=addr)
            .next_back()
            .and_then(|(_, v)| v.first())
    }

    /// Export as a simple `.map` file (Watcom/GNU linker format).
    #[must_use]
    pub fn export_as_map(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("# Symbol map\n");
        for sym in self.iter() {
            writeln!(out, "{:#018x}  {}", sym.address, sym.name)
                .expect("writing to String never fails");
        }
        out
    }

    /// Export as CSV.
    #[must_use]
    pub fn export_as_csv(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("address,name,demangled,kind,size\n");
        for s in self.iter() {
            writeln!(
                out,
                "{:#x},{},{},{},{}",
                s.address,
                csv_escape(&s.name),
                csv_escape(s.demangled_name.as_deref().unwrap_or("")),
                csv_escape(&format!("{:?}", s.kind)),
                s.size.map_or_else(|| "?".into(), |n| n.to_string())
            )
            .expect("writing to String never fails");
        }
        out
    }
}

// ── SymbolStats ───────────────────────────────────────────────────────────────

/// Per-[`SymKind`] symbol counts.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SymbolStats {
    /// Count of `Function` symbols.
    pub functions: usize,
    /// Count of `Data` symbols.
    pub data: usize,
    /// Count of `Label` symbols.
    pub labels: usize,
    /// Count of `Section` symbols.
    pub sections: usize,
    /// Count of `File` symbols.
    pub files: usize,
    /// Count of `Type` symbols.
    pub types: usize,
    /// Count of `TLS` (thread-local) symbols.
    pub tls: usize,
    /// Count of `IFunc` (GNU indirect function) symbols.
    pub ifunc: usize,
    /// Count of `Common` (tentative) symbols.
    pub common: usize,
    /// Count of `Unknown`-kind symbols.
    pub unknown: usize,
    /// Total number of symbols counted.
    pub total: usize,
}

impl SymbolStats {
    /// Tally per-kind counts over a slice of symbols.
    #[must_use]
    pub fn from_symbols(symbols: &[Symbol]) -> Self {
        Self::from_symbols_iter(symbols.iter())
    }
    /// Tally per-kind counts over any iterator of symbols.
    #[must_use]
    pub fn from_symbols_iter<'a>(iter: impl Iterator<Item = &'a Symbol>) -> Self {
        let mut s = Self::default();
        for sym in iter {
            s.total += 1;
            match sym.kind {
                SymKind::Function => s.functions += 1,
                SymKind::Data => s.data += 1,
                SymKind::Label => s.labels += 1,
                SymKind::Section => s.sections += 1,
                SymKind::File => s.files += 1,
                SymKind::Type | SymKind::Namespace => s.types += 1,
                SymKind::TLS => s.tls += 1,
                SymKind::IFunc => s.ifunc += 1,
                SymKind::Common => s.common += 1,
                SymKind::Unknown => s.unknown += 1,
            }
        }
        s
    }
}

impl fmt::Display for SymbolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolStats {{ total={} fn={} data={} label={} sec={} }}",
            self.total, self.functions, self.data, self.labels, self.sections
        )
    }
}

// ── ExportTable ───────────────────────────────────────────────────────────────

/// A view over the exported symbols (`LegacySymbolSource::Export`) of a binary.
#[derive(Debug, Default)]
pub struct ExportTable {
    symbols: Vec<Symbol>,
}

impl ExportTable {
    /// Build the table by selecting the `Export`-sourced symbols from `all`.
    #[must_use]
    pub fn from_symbols(all: &[Symbol]) -> Self {
        Self {
            symbols: all
                .iter()
                .filter(|s| s.source == LegacySymbolSource::Export)
                .cloned()
                .collect(),
        }
    }
    /// All export symbols.
    #[must_use]
    pub fn exports(&self) -> &[Symbol] {
        &self.symbols
    }
    /// Find the export with the given PE ordinal.
    #[must_use]
    pub fn by_ordinal(&self, ordinal: u32) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.ordinal == Some(ordinal))
    }
    /// Find the export with the given name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }
    /// Number of exports.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }
    /// Whether there are no exports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ── ImportTable ───────────────────────────────────────────────────────────────

/// A view over the imported symbols (`LegacySymbolSource::Import`) of a binary.
#[derive(Debug, Default)]
pub struct ImportTable {
    symbols: Vec<Symbol>,
}

impl ImportTable {
    /// Build the table by selecting the `Import`-sourced symbols from `all`.
    #[must_use]
    pub fn from_symbols(all: &[Symbol]) -> Self {
        Self {
            symbols: all
                .iter()
                .filter(|s| s.source == LegacySymbolSource::Import)
                .cloned()
                .collect(),
        }
    }
    /// All import symbols.
    #[must_use]
    pub fn imports(&self) -> &[Symbol] {
        &self.symbols
    }
    /// Find the import with the given name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }
    /// Number of imports.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }
    /// Whether there are no imports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
    /// Group imports by originating module (`source_file`), bucketing entries
    /// with no recorded module under `"unknown"`.
    #[must_use]
    pub fn grouped_by_module(&self) -> HashMap<String, Vec<&Symbol>> {
        let mut m: HashMap<String, Vec<&Symbol>> = HashMap::new();
        for sym in &self.symbols {
            m.entry(
                sym.source_file
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
            .or_default()
            .push(sym);
        }
        m
    }
}

// ── SectionSymbols ────────────────────────────────────────────────────────────

/// Symbols grouped by their section index; symbols without a section are dropped.
#[derive(Debug, Default)]
pub struct SectionSymbols {
    sections: HashMap<u16, Vec<Symbol>>,
}

impl SectionSymbols {
    /// Bucket `symbols` by their `section_index` (symbols with none are skipped).
    #[must_use]
    pub fn from_symbols(symbols: &[Symbol]) -> Self {
        let mut m = Self::default();
        for s in symbols {
            if let Some(sec) = s.section_index {
                m.sections.entry(sec).or_default().push(s.clone());
            }
        }
        m
    }
    /// Symbols in section `idx` (empty slice if the section is unknown/empty).
    #[must_use]
    pub fn in_section(&self, idx: u16) -> &[Symbol] {
        self.sections.get(&idx).map_or(&[], Vec::as_slice)
    }
    /// Number of distinct sections that contain at least one symbol.
    #[must_use]
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
}

// ── SymbolConflictResolver ────────────────────────────────────────────────────

/// Policy for choosing among symbols that share the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictStrategy {
    /// Prefer a debug-info symbol over other sources.
    PreferDebug,
    /// Prefer an export-table symbol over other sources.
    PreferExport,
    /// Keep the first symbol encountered at each address.
    KeepFirst,
    /// Keep the last symbol encountered at each address.
    KeepLast,
    /// Keep every symbol, resolving no conflicts.
    KeepAll,
}

/// Deduplicates address-colliding symbols according to a [`ConflictStrategy`].
pub struct SymbolConflictResolver {
    strategy: ConflictStrategy,
}

impl SymbolConflictResolver {
    /// Create a resolver using the given strategy.
    #[must_use]
    pub const fn new(strategy: ConflictStrategy) -> Self {
        Self { strategy }
    }
    /// Apply the strategy, returning the surviving symbols.
    #[must_use]
    pub fn resolve(&self, symbols: Vec<Symbol>) -> Vec<Symbol> {
        match self.strategy {
            ConflictStrategy::KeepAll => symbols,
            ConflictStrategy::KeepFirst => {
                let mut seen: HashSet<u64> = HashSet::new();
                symbols
                    .into_iter()
                    .filter(|s| seen.insert(s.address))
                    .collect()
            }
            ConflictStrategy::KeepLast => {
                let mut map: HashMap<u64, Symbol> = HashMap::new();
                for s in symbols {
                    map.insert(s.address, s);
                }
                let mut v: Vec<Symbol> = map.into_values().collect();
                v.sort_by_key(|s| s.address);
                v
            }
            ConflictStrategy::PreferDebug => {
                Self::resolve_by_source(symbols, LegacySymbolSource::Debug)
            }
            ConflictStrategy::PreferExport => {
                Self::resolve_by_source(symbols, LegacySymbolSource::Export)
            }
        }
    }
    fn resolve_by_source(symbols: Vec<Symbol>, preferred: LegacySymbolSource) -> Vec<Symbol> {
        let mut map: HashMap<u64, Symbol> = HashMap::new();
        for s in symbols {
            let entry = map.entry(s.address).or_insert_with(|| s.clone());
            if s.source == preferred && entry.source != preferred {
                *entry = s;
            }
        }
        let mut v: Vec<Symbol> = map.into_values().collect();
        v.sort_by_key(|s| s.address);
        v
    }
}

// ── SymbolResolver ────────────────────────────────────────────────────────────

/// Chains several [`SymbolProvider`]s and resolves queries by consulting them in
/// order, returning the first hit (an owned, non-caching variant of [`SymbolTable`]).
#[derive(Debug, Default)]
pub struct SymbolResolver {
    providers: Vec<Box<dyn SymbolProvider>>,
}

impl SymbolResolver {
    /// Create a resolver with no providers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a provider; later providers are fallbacks for earlier ones.
    pub fn add_provider(&mut self, provider: Box<dyn SymbolProvider>) {
        self.providers.push(provider);
    }
    /// Resolve a symbol by name (first provider to match wins).
    #[must_use]
    pub fn resolve_name(&self, name: &str) -> Option<Symbol> {
        self.providers.iter().find_map(|p| p.lookup_name(name))
    }
    /// Resolve a symbol by exact address (first provider to match wins).
    #[must_use]
    pub fn resolve_address(&self, addr: u64) -> Option<Symbol> {
        self.providers.iter().find_map(|p| p.lookup_address(addr))
    }
    /// Resolve the nearest symbol at or below `addr` (first provider to match wins).
    #[must_use]
    pub fn resolve_nearest(&self, addr: u64) -> Option<Symbol> {
        self.providers.iter().find_map(|p| p.lookup_nearest(addr))
    }
    /// Collect all symbols from every chained provider.
    #[must_use]
    pub fn all_symbols(&self) -> Vec<Symbol> {
        self.providers
            .iter()
            .flat_map(|p| p.all_symbols())
            .collect()
    }
    /// Number of chained providers.
    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

// ── DebugSymbolMerger ─────────────────────────────────────────────────────────

/// Merges debug symbols keyed by name, filling in missing demangled names and
/// sizes from later records so that partial entries are progressively completed.
#[derive(Debug, Default)]
pub struct DebugSymbolMerger {
    symbols: HashMap<String, Symbol>,
}

impl DebugSymbolMerger {
    /// Create an empty merger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Fold `symbols` in, completing any already-seen entry's missing
    /// `demangled_name`/`size` from the new records.
    pub fn merge(&mut self, symbols: impl IntoIterator<Item = Symbol>) {
        for sym in symbols {
            let entry = self
                .symbols
                .entry(sym.name.clone())
                .or_insert_with(|| sym.clone());
            if entry.demangled_name.is_none() && sym.demangled_name.is_some() {
                entry.demangled_name = sym.demangled_name;
            }
            if entry.size.is_none() && sym.size.is_some() {
                entry.size = sym.size;
            }
        }
    }
    /// Consume the merger and return the merged symbols sorted by address.
    #[must_use]
    pub fn finish(self) -> Vec<Symbol> {
        let mut v: Vec<Symbol> = self.symbols.into_values().collect();
        // Total order. This map is keyed by NAME, so several distinct names can
        // share one address — C++ constructor variants, weak aliases and
        // `main`/`_main` all do. Sorting on the address alone left those ties to
        // the stable sort, which preserved `HashMap` iteration order; Rust seeds
        // that per process, so the output varied between runs. The name is the
        // map key and therefore unique, which makes this ordering total.
        v.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)));
        v
    }
    /// Number of distinct (by name) symbols accumulated so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }
    /// Whether nothing has been merged yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ── SymbolExporter ────────────────────────────────────────────────────────────

/// Stateless serializer of [`Symbol`] slices to common on-disk formats
/// (JSON, CSV, IDA IDC script, linker `.map`).
pub struct SymbolExporter;

impl SymbolExporter {
    /// Serialize symbols to pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns `SymbolError::Other` wrapping any serde serialization failure.
    pub fn to_json(symbols: &[Symbol]) -> Result<String, SymbolError> {
        serde_json::to_string_pretty(symbols).map_err(|e| SymbolError::Other(e.to_string()))
    }
    /// Serialize symbols to CSV with `address,name,demangled,kind,size` columns.
    #[must_use]
    pub fn to_csv(symbols: &[Symbol]) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("address,name,demangled,kind,size\n");
        for s in symbols {
            writeln!(
                out,
                "{:#x},{},{},{},{}",
                s.address,
                csv_escape(&s.name),
                csv_escape(s.demangled_name.as_deref().unwrap_or("")),
                csv_escape(&format!("{:?}", s.kind)),
                s.size.map_or_else(|| "?".into(), |n| n.to_string())
            )
            .expect("writing to String never fails");
        }
        out
    }
    /// Emit an IDA `.idc` script of `MakeName` calls, one per symbol address.
    #[must_use]
    pub fn to_idc(symbols: &[Symbol]) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("#include <idc.idc>\nstatic main() {\n");
        for s in symbols {
            writeln!(
                out,
                "  MakeName({:#x}, \"{}\");",
                s.address,
                s.display_name().replace('"', "\\\"")
            )
            .expect("writing to String never fails");
        }
        out.push_str("}\n");
        out
    }
    /// Emit a linker-style `.map` listing of `address  name` lines.
    #[must_use]
    pub fn to_map(symbols: &[Symbol]) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("# Address         Name\n");
        for s in symbols {
            writeln!(out, "{:#018x}  {}", s.address, s.name)
                .expect("writing to String never fails");
        }
        out
    }
}

// ── Spec §7: SymbolKind, SymbolSource, UnifiedSymbol ─────────────────────────

/// Semantic kind of a [`UnifiedSymbol`] (spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    /// Executable function.
    Function,
    /// Data / global variable.
    Variable,
    /// Code label (non-function jump target).
    Label,
    /// Thunk / trampoline.
    Thunk,
    /// Import table entry (e.g. PE IAT).
    Import,
    /// Export table entry.
    Export,
    /// Section / segment descriptor.
    Section,
    /// Module / compilation-unit.
    Module,
    /// Namespace.
    Namespace,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Origin of a [`UnifiedSymbol`] (spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    /// Microsoft Program Database debug info.
    Pdb,
    /// DWARF debug info (ELF/Mach-O).
    Dwarf,
    /// Legacy `CodeView` debug info.
    CodeView,
    /// Legacy STABS debug info.
    Stabs,
    /// FLIRT library-signature match.
    Flirt,
    /// Manually supplied or renamed by the user.
    Manual,
    /// Inferred by analysis (lowest trust after AI).
    Inferred,
    /// Import table entry.
    Import,
    /// Export table entry.
    Export,
    /// ELF symbol table (`.symtab`/`.dynsym`).
    Elf,
    /// PE symbol/export table.
    Pe,
    /// Produced by an AI/heuristic naming model.
    Ai,
}

impl fmt::Display for SymbolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl SymbolSource {
    /// Confidence priority: higher = more trusted.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Pdb | Self::Dwarf | Self::CodeView => 90,
            Self::Stabs => 80,
            Self::Flirt => 70,
            Self::Export | Self::Import => 60,
            Self::Elf | Self::Pe => 55,
            Self::Manual => 100,
            Self::Ai => 50,
            Self::Inferred => 30,
        }
    }
}

/// Canonical unified symbol (spec §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedSymbol {
    /// Raw (possibly mangled) symbol name.
    pub name: String,
    /// Demangled name if available.
    pub demangled_name: Option<String>,
    /// Virtual address of the symbol.
    pub address: u64,
    /// Size in bytes; `None` when unknown.
    pub size: Option<u64>,
    /// Semantic kind of the symbol.
    pub kind: SymbolKind,
    /// Producer this symbol came from.
    pub source: SymbolSource,
    /// Whether the symbol is externally visible (exported / global linkage).
    pub is_external: bool,
    /// Owning module / compilation unit, if known.
    pub module: Option<String>,
    /// Index into an external type store describing this symbol's type, if any.
    pub type_id: Option<u64>,
}

impl UnifiedSymbol {
    /// Create a unified symbol with the required fields, leaving optional
    /// metadata (demangled name, size, module, type) unset and `is_external` false.
    #[must_use]
    pub const fn new(name: String, address: u64, kind: SymbolKind, source: SymbolSource) -> Self {
        Self {
            name,
            demangled_name: None,
            address,
            size: None,
            kind,
            source,
            is_external: false,
            module: None,
            type_id: None,
        }
    }
    /// The demangled name if present, otherwise the raw name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.name)
    }
    /// One-past-the-end address (`address + size`), or `None` if size is unknown
    /// or the addition overflows.
    #[must_use]
    pub fn end_address(&self) -> Option<u64> {
        self.size.and_then(|s| self.address.checked_add(s))
    }
}

impl fmt::Display for UnifiedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({:?}/{:?})",
            self.display_name(),
            self.address,
            self.kind,
            self.source
        )
    }
}

// ── UnifiedSymbolTable ────────────────────────────────────────────────────────

/// Symbol table for [`UnifiedSymbol`]s (spec §7).
///
/// Primary: `BTreeMap<address, Vec<UnifiedSymbol>>` (multiple per address).
/// Name index: `HashMap<name, Vec<address>>`.
/// Floor search via `BTreeMap::range`.
#[derive(Debug, Default)]
pub struct UnifiedSymbolTable {
    /// Primary index: address → the symbols located there (several may coincide).
    pub symbols: BTreeMap<u64, Vec<UnifiedSymbol>>,
    /// Secondary index: symbol name → the addresses that carry that name.
    pub by_name: HashMap<String, Vec<u64>>,
}

impl UnifiedSymbolTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol, preserving multiple symbols at the same address.
    pub fn add(&mut self, sym: UnifiedSymbol) {
        let addr = sym.address;
        let name = sym.name.clone();
        self.symbols.entry(addr).or_default().push(sym);
        self.by_name.entry(name).or_default().push(addr);
    }

    /// Remove all symbols at `addr` with given `name`.
    pub fn remove(&mut self, addr: u64, name: &str) -> usize {
        let mut removed = 0;
        if let Some(syms) = self.symbols.get_mut(&addr) {
            let before = syms.len();
            syms.retain(|s| s.name != name);
            removed = before - syms.len();
            if syms.is_empty() {
                self.symbols.remove(&addr);
            }
        }
        if removed > 0
            && let Some(addrs) = self.by_name.get_mut(name)
        {
            addrs.retain(|&a| a != addr);
            if addrs.is_empty() {
                self.by_name.remove(name);
            }
        }
        removed
    }

    /// The first symbol recorded at exactly `addr`, if any.
    #[must_use]
    pub fn lookup_addr(&self, addr: u64) -> Option<&UnifiedSymbol> {
        self.symbols.get(&addr).and_then(|v| v.first())
    }

    /// Every symbol recorded at exactly `addr`.
    #[must_use]
    pub fn lookup_addr_all(&self, addr: u64) -> Vec<&UnifiedSymbol> {
        self.symbols
            .get(&addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Every symbol whose name equals `name`, via the name index.
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Vec<&UnifiedSymbol> {
        self.by_name
            .get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .flat_map(|&a| self.symbols.get(&a).into_iter().flatten())
                    .filter(|s| s.name == name)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every symbol whose name starts with `prefix`.
    #[must_use]
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&UnifiedSymbol> {
        self.symbols
            .values()
            .flatten()
            .filter(|s| s.name.starts_with(prefix))
            .collect()
    }

    /// Every symbol with address in the half-open range `[start, end)`.
    #[must_use]
    pub fn find_in_range(&self, start: u64, end: u64) -> Vec<&UnifiedSymbol> {
        self.symbols
            .range(start..end)
            .flat_map(|(_, v)| v.iter())
            .collect()
    }

    /// The symbol with the largest address `<= addr` (floor lookup).
    #[must_use]
    pub fn nearest_below(&self, addr: u64) -> Option<&UnifiedSymbol> {
        self.symbols
            .range(..=addr)
            .next_back()
            .and_then(|(_, v)| v.first())
    }

    /// Rename the symbol at `addr` from `old_name` to `new_name`, keeping the
    /// name index consistent; returns `true` if a matching symbol was found.
    pub fn rename(&mut self, addr: u64, old_name: &str, new_name: &str) -> bool {
        if let Some(syms) = self.symbols.get_mut(&addr)
            && let Some(sym) = syms.iter_mut().find(|s| s.name == old_name)
        {
            if let Some(addrs) = self.by_name.get_mut(old_name) {
                addrs.retain(|&a| a != addr);
            }
            sym.name = new_name.to_string();
            self.by_name
                .entry(new_name.to_string())
                .or_default()
                .push(addr);
            return true;
        }
        false
    }

    /// Total number of symbols across all addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.values().map(std::vec::Vec::len).sum()
    }
    /// Whether the table holds no symbols.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
    /// Iterate all symbols in ascending address order.
    pub fn iter_by_address(&self) -> impl Iterator<Item = &UnifiedSymbol> {
        self.symbols.values().flatten()
    }

    /// Merge another table, keeping higher-priority source on conflict.
    pub fn merge(&mut self, other: &Self) {
        for sym in other.iter_by_address() {
            self.add_or_upgrade(sym.clone());
        }
    }

    /// Add `sym` or replace an existing symbol at the same address+name if the
    /// new source has higher priority.
    pub fn add_or_upgrade(&mut self, sym: UnifiedSymbol) {
        let addr = sym.address;
        let name = sym.name.clone();
        if let Some(syms) = self.symbols.get_mut(&addr)
            && let Some(existing) = syms.iter_mut().find(|s| s.name == name)
        {
            if sym.source.priority() > existing.source.priority() {
                *existing = sym;
            }
            return;
        }
        self.add(sym);
    }

    /// Export to symbol server URL list (for PDB download).
    #[must_use]
    pub fn pdb_url_list(&self, base_url: &str) -> Vec<String> {
        self.iter_by_address()
            .filter(|s| s.source == SymbolSource::Pdb)
            .filter_map(|s| s.module.as_deref().map(|m| format!("{base_url}/{m}")))
            .collect()
    }
}

// ── SyntheticSymbolGen ────────────────────────────────────────────────────────

/// Generates synthetic symbol names for unnamed functions and data.
pub struct SyntheticSymbolGen;

impl SyntheticSymbolGen {
    /// Generate a "`sub_XXXX`" name for a function at `addr`.
    #[must_use]
    pub fn function_name(addr: u64) -> String {
        format!("sub_{addr:X}")
    }
    /// Generate a "`byte_XXXX`" name for unknown data at `addr`.
    #[must_use]
    pub fn data_name(addr: u64) -> String {
        format!("byte_{addr:X}")
    }
    /// Generate a "`loc_XXXX`" name for a branch target that isn't a function start.
    #[must_use]
    pub fn label_name(addr: u64) -> String {
        format!("loc_{addr:X}")
    }
    /// Generate a "`dword_XXXX`" name for a 4-byte data item.
    #[must_use]
    pub fn dword_name(addr: u64) -> String {
        format!("dword_{addr:X}")
    }
    /// Generate a "`qword_XXXX`" name for an 8-byte data item.
    #[must_use]
    pub fn qword_name(addr: u64) -> String {
        format!("qword_{addr:X}")
    }

    /// Auto-populate the table: for every address in `function_addrs` that has no
    /// symbol, insert a synthetic Function symbol.
    pub fn fill_functions(table: &mut UnifiedSymbolTable, function_addrs: &[u64]) {
        for &addr in function_addrs {
            if table.lookup_addr(addr).is_none() {
                table.add(UnifiedSymbol::new(
                    Self::function_name(addr),
                    addr,
                    SymbolKind::Function,
                    SymbolSource::Inferred,
                ));
            }
        }
    }

    /// Auto-populate: for every address in `data_addrs` that has no symbol, insert
    /// a synthetic Variable symbol.
    pub fn fill_data(table: &mut UnifiedSymbolTable, data_addrs: &[u64]) {
        for &addr in data_addrs {
            if table.lookup_addr(addr).is_none() {
                table.add(UnifiedSymbol::new(
                    Self::data_name(addr),
                    addr,
                    SymbolKind::Variable,
                    SymbolSource::Inferred,
                ));
            }
        }
    }
}

// ── DemanglerPipeline ─────────────────────────────────────────────────────────

/// Demangling strategy in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemangleStrategy {
    /// Itanium C++ ABI mangling (GCC/Clang).
    Itanium,
    /// Rust symbol mangling (legacy and v0).
    Rust,
    /// Microsoft Visual C++ mangling.
    Msvc,
}

/// Tries multiple demanglers in order; caches results.
pub struct DemanglerPipeline {
    order: Vec<DemangleStrategy>,
    cache: HashMap<String, Option<String>>,
}

impl DemanglerPipeline {
    /// Create a pipeline with the default order (Itanium, then Rust, then MSVC).
    #[must_use]
    pub fn new() -> Self {
        Self {
            order: vec![
                DemangleStrategy::Itanium,
                DemangleStrategy::Rust,
                DemangleStrategy::Msvc,
            ],
            cache: HashMap::new(),
        }
    }

    /// Replace the strategy order tried by [`Self::demangle`].
    pub fn set_order(&mut self, order: Vec<DemangleStrategy>) {
        self.order = order;
    }
    /// Drop the memoized demangling results.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Attempt to demangle `name`. Returns `Some(demangled)` or `None`.
    pub fn demangle(&mut self, name: &str) -> Option<String> {
        if let Some(cached) = self.cache.get(name) {
            return cached.clone();
        }
        let result = self.order.iter().find_map(|&strategy| match strategy {
            DemangleStrategy::Itanium => demangle_itanium_heuristic(name),
            DemangleStrategy::Rust => demangle_rust_heuristic(name),
            DemangleStrategy::Msvc => demangle_msvc_heuristic(name),
        });
        self.cache.insert(name.to_string(), result.clone());
        result
    }

    /// Apply demangling to a whole `UnifiedSymbolTable`.
    pub fn demangle_table(&mut self, table: &mut UnifiedSymbolTable) {
        let addrs: Vec<u64> = table.symbols.keys().copied().collect();
        for addr in addrs {
            if let Some(syms) = table.symbols.get_mut(&addr) {
                for sym in syms.iter_mut() {
                    if sym.demangled_name.is_none() {
                        sym.demangled_name = self.demangle(&sym.name);
                    }
                }
            }
        }
    }
}

impl Default for DemanglerPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ── demangle_all (free function kept for compat) ──────────────────────────────

/// Demangle every symbol in `table` in place using a fresh default
/// [`DemanglerPipeline`]; kept as a convenience wrapper for older call sites.
pub fn demangle_all(table: &mut UnifiedSymbolTable) {
    let mut pipeline = DemanglerPipeline::new();
    pipeline.demangle_table(table);
}

// ── Demangling heuristics ─────────────────────────────────────────────────────

/// Try every demangling heuristic in sequence (Itanium, Rust, MSVC).
///
/// Returns the first successful result, or `None` if every strategy fails.
/// Stateless alternative to [`DemanglerPipeline::demangle`] — no caching.
#[must_use]
pub fn try_demangle(name: &str) -> Option<String> {
    demangle_itanium_heuristic(name)
        .or_else(|| demangle_rust_heuristic(name))
        .or_else(|| demangle_msvc_heuristic(name))
}

fn demangle_itanium_heuristic(name: &str) -> Option<String> {
    if !name.starts_with("_Z") && !name.starts_with("__Z") {
        return None;
    }
    let s = if let Some(r) = name.strip_prefix("__Z") { r } else { name.strip_prefix("_Z")? };
    if s.is_empty() {
        return None;
    }
    if s.starts_with('N') {
        let inner = s.strip_prefix('N')?.strip_suffix('E').unwrap_or(s);
        let parts = decode_itanium_parts(inner);
        if parts.is_empty() {
            return None;
        }
        return Some(parts.join("::"));
    }
    let parts = decode_itanium_parts(s);
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("::"))
}

fn decode_itanium_parts(mut s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    while let Some(c) = s.chars().next() {
        if !c.is_ascii_digit() {
            break;
        }
        let len_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let Ok(len) = s[..len_end].parse::<usize>() else {
            break;
        };
        s = &s[len_end..];
        if len > s.len() {
            break;
        }
        // Use get() to avoid panicking if `len` falls on a multibyte UTF-8 boundary.
        let Some(part) = s.get(..len) else { break };
        parts.push(part.to_string());
        let Some(rest) = s.get(len..) else { break };
        s = rest;
    }
    parts
}

fn demangle_rust_heuristic(name: &str) -> Option<String> {
    if name.starts_with("_R") {
        return Some(format!("<rust>{name}"));
    }
    None
}

fn demangle_msvc_heuristic(name: &str) -> Option<String> {
    let inner = name.strip_prefix('?')?;
    let base = inner.split("@@").next().unwrap_or(inner);
    let result = base.replace('@', "::");
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ── PdbSymbolInfo ─────────────────────────────────────────────────────────────

/// Minimal PDB symbol server download info.
pub struct PdbSymbolServer {
    /// Base URL of the symbol server (e.g. the Microsoft MSDL endpoint).
    pub base_url: String,
}

impl PdbSymbolServer {
    /// Create a server client pointed at `base_url`.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
    /// Construct a Microsoft Symbol Server download URL for a PDB.
    #[must_use]
    pub fn pdb_url(&self, pdb_name: &str, guid: &str, age: u32) -> String {
        format!(
            "{}/{}/{}{:X}/{}",
            self.base_url,
            pdb_name,
            guid.replace(['-', '{', '}'], "").to_ascii_uppercase(),
            age,
            pdb_name
        )
    }
    /// Default MSDL URL.
    #[must_use]
    pub fn msdl() -> Self {
        Self::new("https://msdl.microsoft.com/download/symbols")
    }
}

// ── CrossReferenceIndex ───────────────────────────────────────────────────────

/// Maps symbols to the addresses that reference them (call/data xrefs).
#[derive(Debug, Default)]
pub struct CrossReferenceIndex {
    /// addr → set of addresses that reference addr
    xrefs_to: HashMap<u64, HashSet<u64>>,
    /// addr → set of addresses that addr references
    xrefs_from: HashMap<u64, HashSet<u64>>,
}

impl CrossReferenceIndex {
    /// Create an empty cross-reference index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Record that address `from` references address `to` (both directions indexed).
    pub fn add_xref(&mut self, from: u64, to: u64) {
        self.xrefs_to.entry(to).or_default().insert(from);
        self.xrefs_from.entry(from).or_default().insert(to);
    }
    /// Sorted list of addresses that reference `addr`.
    #[must_use]
    pub fn refs_to(&self, addr: u64) -> Vec<u64> {
        self.xrefs_to
            .get(&addr)
            .map(|s| {
                let mut v: Vec<u64> = s.iter().copied().collect();
                v.sort_unstable();
                v
            })
            .unwrap_or_default()
    }
    /// Sorted list of addresses that `addr` references.
    #[must_use]
    pub fn refs_from(&self, addr: u64) -> Vec<u64> {
        self.xrefs_from
            .get(&addr)
            .map(|s| {
                let mut v: Vec<u64> = s.iter().copied().collect();
                v.sort_unstable();
                v
            })
            .unwrap_or_default()
    }
    /// Number of distinct addresses that reference `addr`.
    #[must_use]
    pub fn ref_count_to(&self, addr: u64) -> usize {
        self.xrefs_to
            .get(&addr)
            .map_or(0, std::collections::HashSet::len)
    }
    /// Remove all recorded cross-references.
    pub fn clear(&mut self) {
        self.xrefs_to.clear();
        self.xrefs_from.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fn(name: &str, addr: u64) -> Symbol {
        Symbol::new(name.to_string(), addr, SymKind::Function)
    }
    fn make_data(name: &str, addr: u64) -> Symbol {
        Symbol::new(name.to_string(), addr, SymKind::Data)
    }
    fn make_unified(name: &str, addr: u64, kind: SymbolKind, src: SymbolSource) -> UnifiedSymbol {
        UnifiedSymbol::new(name.to_string(), addr, kind, src)
    }

    // ── Symbol basics ──────────────────────────────────────────────────────────

    #[test]
    fn test_symbol_new_defaults() {
        let s = make_fn("foo", 0x1000);
        assert_eq!(s.name, "foo");
        assert_eq!(s.address, 0x1000);
        assert_eq!(s.kind, SymKind::Function);
        assert!(s.demangled_name.is_none());
        assert!(s.size.is_none());
    }
    #[test]
    fn test_symbol_display_name_fallback() {
        assert_eq!(make_fn("_m", 0).display_name(), "_m");
    }
    #[test]
    fn test_symbol_display_name_demangled() {
        let mut s = make_fn("_m", 0);
        s.demangled_name = Some("foo::bar".into());
        assert_eq!(s.display_name(), "foo::bar");
    }
    #[test]
    fn test_symbol_end_address_none() {
        assert!(make_fn("f", 0x1000).end_address().is_none());
    }
    #[test]
    fn test_symbol_end_address_some() {
        let mut s = make_fn("f", 0x1000);
        s.size = Some(0x40);
        assert_eq!(s.end_address(), Some(0x1040));
    }
    #[test]
    fn test_symbol_contains_no_size() {
        let s = make_fn("f", 0x1000);
        assert!(s.contains(0x1000));
        assert!(!s.contains(0x1001));
    }
    #[test]
    fn test_symbol_contains_with_size() {
        let mut s = make_fn("f", 0x1000);
        s.size = Some(0x10);
        assert!(s.contains(0x1000));
        assert!(s.contains(0x100F));
        assert!(!s.contains(0x1010));
    }
    #[test]
    fn test_symbol_display() {
        let s = make_fn("main", 0x0040_1000);
        assert!(s.to_string().contains("main"));
    }
    #[test]
    fn test_symbol_is_function() {
        assert!(make_fn("f", 0).is_function());
        assert!(!make_data("d", 0).is_function());
    }
    #[test]
    fn test_symbol_is_data() {
        assert!(make_data("d", 0).is_data());
        assert!(!make_fn("f", 0).is_data());
    }
    #[test]
    fn test_symbol_add_tag_dedup() {
        let mut s = make_fn("f", 0);
        s.add_tag("x".into());
        s.add_tag("x".into());
        assert_eq!(s.tags.len(), 1);
    }
    #[test]
    fn test_symbol_function_boundary() {
        let mut s = make_fn("f", 0x1000);
        s.size = Some(0x100);
        let b = s.function_boundary().unwrap();
        assert_eq!(b.size(), 0x100);
        assert!(b.contains(0x1050));
    }

    // ── SymKind display ────────────────────────────────────────────────────────

    #[test]
    fn test_sym_kind_display() {
        assert_eq!(SymKind::Function.to_string(), "Function");
        assert_eq!(SymKind::TLS.to_string(), "TLS");
    }

    // ── TypeInfo ───────────────────────────────────────────────────────────────

    #[test]
    fn test_type_void() {
        assert_eq!(TypeInfo::Void.to_string(), "void");
    }
    #[test]
    fn test_type_int() {
        assert_eq!(
            TypeInfo::Int {
                width: 32,
                signed: true
            }
            .to_string(),
            "i32"
        );
    }
    #[test]
    fn test_type_float() {
        assert_eq!(TypeInfo::Float { width: 64 }.to_string(), "f64");
    }
    #[test]
    fn test_type_pointer() {
        let t = TypeInfo::Pointer {
            target: Box::new(TypeInfo::Void),
            size: 8,
        };
        assert_eq!(t.to_string(), "*void[8]");
    }
    #[test]
    fn test_struct_field() {
        let f = StructField {
            name: "x".into(),
            offset: 4,
            type_info: TypeInfo::Int {
                width: 32,
                signed: true,
            },
        };
        assert_eq!(f.to_string(), "+0x4 x: i32");
    }

    // ── FunctionBoundary ───────────────────────────────────────────────────────

    #[test]
    fn test_boundary_overlaps() {
        let a = FunctionBoundary::new(0x1000, 0x2000, "a".into());
        let b = FunctionBoundary::new(0x1500, 0x3000, "b".into());
        let c = FunctionBoundary::new(0x2000, 0x3000, "c".into());
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }
    #[test]
    fn test_boundary_display() {
        let b = FunctionBoundary::new(0x1000, 0x2000, "f".into());
        assert!(b.to_string().contains("0x1000"));
    }

    // ── InMemorySymbolProvider ─────────────────────────────────────────────────

    #[test]
    fn test_inmem_empty() {
        let p = InMemorySymbolProvider::new();
        assert!(p.is_empty());
    }
    #[test]
    fn test_inmem_add() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x100));
        assert_eq!(p.len(), 1);
    }
    #[test]
    fn test_inmem_lookup_name() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("alpha", 0x100));
        assert!(p.lookup_name("alpha").is_some());
        assert!(p.lookup_name("beta").is_none());
    }
    #[test]
    fn test_inmem_lookup_address() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x400));
        assert!(p.lookup_address(0x400).is_some());
        assert!(p.lookup_address(0x401).is_none());
    }
    #[test]
    fn test_inmem_lookup_nearest() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x1000));
        p.add(make_fn("g", 0x2000));
        assert_eq!(p.lookup_nearest(0x1500).unwrap().name, "f");
    }
    #[test]
    fn test_inmem_all_functions() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x100));
        p.add(make_data("x", 0x200));
        assert_eq!(p.all_functions().len(), 1);
    }
    #[test]
    fn test_inmem_remove() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x100));
        assert!(p.remove_by_name("f"));
        assert!(p.is_empty());
    }
    #[test]
    fn test_inmem_rename() {
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("old", 0x100));
        assert!(p.rename("old", "new".into()));
        assert!(p.lookup_name("new").is_some());
    }

    // ── SymbolTable ────────────────────────────────────────────────────────────

    #[test]
    fn test_symtable_empty() {
        let t = SymbolTable::new();
        assert_eq!(t.provider_count(), 0);
    }
    #[test]
    fn test_symtable_add_provider() {
        let t = SymbolTable::new();
        let p = InMemorySymbolProvider::new();
        t.add_provider(Box::new(p));
        assert_eq!(t.provider_count(), 1);
    }
    #[test]
    fn test_symtable_lookup() {
        let t = SymbolTable::new();
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("main", 0x0040_1000));
        t.add_provider(Box::new(p));
        assert_eq!(t.lookup_name("main").unwrap().address, 0x0040_1000);
    }
    #[test]
    fn test_symtable_cache() {
        let t = SymbolTable::new();
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("start", 0x0040_1000));
        t.add_provider(Box::new(p));
        let a = t.lookup_address(0x0040_1000).unwrap();
        let b = t.lookup_address(0x0040_1000).unwrap();
        assert_eq!(a.name, b.name);
    }
    #[test]
    fn test_symtable_stats() {
        let t = SymbolTable::new();
        let mut p = InMemorySymbolProvider::new();
        p.add(make_fn("f", 0x100));
        p.add(make_data("d", 0x200));
        t.add_provider(Box::new(p));
        let s = t.stats();
        assert_eq!(s.functions, 1);
        assert_eq!(s.data, 1);
    }

    // ── SymbolFilter ───────────────────────────────────────────────────────────

    #[test]
    fn test_filter_range() {
        let syms = vec![
            make_fn("a", 0x100),
            make_fn("b", 0x200),
            make_fn("c", 0x300),
        ];
        let r = SymbolFilter::new().address_range(0x150, 0x300).apply(&syms);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "b");
    }
    #[test]
    fn test_filter_kind() {
        let syms = vec![make_fn("f", 0x100), make_data("d", 0x200)];
        assert_eq!(
            SymbolFilter::new()
                .kinds(vec![SymKind::Data])
                .apply(&syms)
                .len(),
            1
        );
    }
    #[test]
    fn test_filter_prefix() {
        let syms = vec![make_fn("my_f", 0x100), make_fn("other", 0x200)];
        assert_eq!(SymbolFilter::new().name_prefix("my_").apply(&syms).len(), 1);
    }
    #[test]
    fn test_filter_max() {
        let syms: Vec<Symbol> = (0..10)
            .map(|i| make_fn(&format!("f{i}"), i * 0x100))
            .collect();
        assert_eq!(SymbolFilter::new().max(3).apply(&syms).len(), 3);
    }

    // ── AddressToSymbolMap ─────────────────────────────────────────────────────

    #[test]
    fn test_addr_map_exact() {
        let m = AddressToSymbolMap::from_symbols(&[make_fn("f1", 0x100), make_fn("f2", 0x200)]);
        assert_eq!(m.lookup_exact(0x100).unwrap().name, "f1");
        assert!(m.lookup_exact(0x150).is_none());
    }
    #[test]
    fn test_addr_map_floor() {
        let m = AddressToSymbolMap::from_symbols(&[make_fn("f1", 0x100), make_fn("f2", 0x200)]);
        assert_eq!(m.lookup_floor(0x180).unwrap().name, "f1");
        assert!(m.lookup_floor(0x50).is_none());
    }

    // ── SymbolCache ────────────────────────────────────────────────────────────

    #[test]
    fn test_cache_basic() {
        let mut c = SymbolCache::new(3);
        c.insert(0x100, make_fn("f1", 0x100));
        assert_eq!(c.get(0x100).unwrap().name, "f1");
    }
    #[test]
    fn test_cache_eviction() {
        let mut c = SymbolCache::new(2);
        c.insert(0x100, make_fn("f1", 0x100));
        c.insert(0x200, make_fn("f2", 0x200));
        let _ = c.get(0x100);
        c.insert(0x300, make_fn("f3", 0x300));
        assert_eq!(c.len(), 2);
        assert!(c.get(0x200).is_none());
        assert!(c.get(0x100).is_some());
    }
    #[test]
    fn test_cache_clear() {
        let mut c = SymbolCache::new(5);
        c.insert(0x100, make_fn("f", 0x100));
        c.clear();
        assert!(c.is_empty());
    }

    // ── SymbolStore ────────────────────────────────────────────────────────────

    #[test]
    fn test_store_insert_get() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("main", 0x1000)).unwrap();
        assert!(!s.find_by_addr(0x1000).is_empty());
        assert!(!s.find_by_name("main").is_empty());
    }
    #[test]
    fn test_store_duplicate_err() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("f", 0x100)).unwrap();
        assert!(matches!(
            s.insert(make_fn("f", 0x100)),
            Err(SymbolError::Duplicate(_))
        ));
    }
    #[test]
    fn test_store_floor() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("a", 0x1000)).unwrap();
        s.insert(make_fn("b", 0x2000)).unwrap();
        assert_eq!(s.get_floor(0x1500).unwrap().name, "a");
    }
    #[test]
    fn test_store_upsert() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("f", 0x100)).unwrap();
        s.upsert(make_fn("f", 0x100));
        assert_eq!(s.len(), 1);
    }
    #[test]
    fn test_store_remove() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("f", 0x100)).unwrap();
        assert_eq!(s.remove(0x100, "f"), 1);
        assert_eq!(s.len(), 0);
    }
    #[test]
    fn test_store_prefix() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("my_f1", 0x100)).unwrap();
        s.insert(make_fn("other", 0x200)).unwrap();
        assert_eq!(s.find_by_prefix("my_").len(), 1);
    }
    #[test]
    fn test_store_in_range() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("a", 0x1000)).unwrap();
        s.insert(make_fn("b", 0x2000)).unwrap();
        s.insert(make_fn("c", 0x3000)).unwrap();
        let r = s.find_in_range(0x1000, 0x3000);
        assert_eq!(r.len(), 2);
    }
    #[test]
    fn test_store_rename() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("old", 0x100)).unwrap();
        assert!(s.rename(0x100, "old", "new"));
        assert!(!s.find_by_name("new").is_empty());
        assert!(s.find_by_name("old").is_empty());
    }
    #[test]
    fn test_store_merge() {
        let mut a = SymbolStore::new();
        a.insert(make_fn("f1", 0x100)).unwrap();
        let mut b = SymbolStore::new();
        b.insert(make_fn("f2", 0x200)).unwrap();
        a.merge(&b);
        assert_eq!(a.len(), 2);
    }
    #[test]
    fn test_store_export_csv() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("main", 0x1000)).unwrap();
        let csv = s.export_as_csv();
        assert!(csv.contains("main"));
    }
    #[test]
    fn test_store_export_map() {
        let mut s = SymbolStore::new();
        s.insert(make_fn("main", 0x1000)).unwrap();
        let map = s.export_as_map();
        assert!(map.contains("main"));
    }

    // ── SymbolStats ────────────────────────────────────────────────────────────

    #[test]
    fn test_stats() {
        let v = vec![
            make_fn("f1", 0x100),
            make_fn("f2", 0x200),
            make_data("d", 0x300),
        ];
        let s = SymbolStats::from_symbols(&v);
        assert_eq!(s.functions, 2);
        assert_eq!(s.data, 1);
        assert_eq!(s.total, 3);
    }
    #[test]
    fn test_stats_display() {
        let s = SymbolStats::default();
        assert!(s.to_string().contains("total=0"));
    }

    // ── ExportTable ────────────────────────────────────────────────────────────

    #[test]
    fn test_export_table() {
        let mut e = make_fn("exp_fn", 0x100);
        e.source = LegacySymbolSource::Export;
        e.ordinal = Some(1);
        let et = ExportTable::from_symbols(&[e, make_fn("dbg", 0x200)]);
        assert_eq!(et.len(), 1);
        assert!(et.by_ordinal(1).is_some());
        assert!(et.by_name("exp_fn").is_some());
    }

    // ── ImportTable ────────────────────────────────────────────────────────────

    #[test]
    fn test_import_table() {
        let mut imp = make_fn("CreateFile", 0x100);
        imp.source = LegacySymbolSource::Import;
        imp.source_file = Some("kernel32.dll".into());
        let it = ImportTable::from_symbols(&[imp]);
        let g = it.grouped_by_module();
        assert!(g.contains_key("kernel32.dll"));
    }

    // ── SectionSymbols ─────────────────────────────────────────────────────────

    #[test]
    fn test_section_symbols() {
        let mut s1 = make_fn("f", 0x100);
        s1.section_index = Some(1);
        let mut s2 = make_fn("g", 0x200);
        s2.section_index = Some(2);
        let sec = SectionSymbols::from_symbols(&[s1, s2]);
        assert_eq!(sec.in_section(1).len(), 1);
        assert_eq!(sec.section_count(), 2);
    }

    // ── ConflictResolver ───────────────────────────────────────────────────────

    #[test]
    fn test_conflict_keep_first() {
        let r = SymbolConflictResolver::new(ConflictStrategy::KeepFirst)
            .resolve(vec![make_fn("f", 0x100), make_fn("g", 0x100)]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "f");
    }
    #[test]
    fn test_conflict_prefer_debug() {
        let s1 = make_fn("debug_name", 0x100);
        let mut s2 = make_fn("export_name", 0x100);
        s2.source = LegacySymbolSource::Export;
        let r = SymbolConflictResolver::new(ConflictStrategy::PreferDebug).resolve(vec![s2, s1]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "debug_name");
    }
    #[test]
    fn test_conflict_keep_all() {
        let r = SymbolConflictResolver::new(ConflictStrategy::KeepAll)
            .resolve(vec![make_fn("f", 0x100), make_fn("g", 0x100)]);
        assert_eq!(r.len(), 2);
    }

    // ── DebugSymbolMerger ──────────────────────────────────────────────────────

    #[test]
    fn test_merger() {
        let mut m = DebugSymbolMerger::new();
        let s1 = make_fn("foo", 0x100);
        let mut s2 = make_fn("foo", 0x100);
        s2.demangled_name = Some("Foo::bar()".into());
        m.merge(vec![s1]);
        m.merge(vec![s2]);
        let r = m.finish();
        assert_eq!(r.len(), 1);
        assert!(r[0].demangled_name.is_some());
    }

    // ── SymbolExporter ─────────────────────────────────────────────────────────

    #[test]
    fn test_exporter_json() {
        let j = SymbolExporter::to_json(&[make_fn("main", 0x1000)]).unwrap();
        assert!(j.contains("main"));
    }
    #[test]
    fn test_exporter_csv() {
        let csv = SymbolExporter::to_csv(&[make_fn("main", 0x1000)]);
        assert!(csv.contains("main"));
        assert!(csv.contains("address"));
    }
    #[test]
    fn test_exporter_idc() {
        let idc = SymbolExporter::to_idc(&[make_fn("WinMain", 0x1000)]);
        assert!(idc.contains("MakeName"));
    }
    #[test]
    fn test_exporter_map() {
        let map = SymbolExporter::to_map(&[make_fn("f", 0x1000)]);
        assert!(map.contains('f'));
    }

    // ── SymbolResolver ─────────────────────────────────────────────────────────

    #[test]
    fn test_resolver_chain() {
        let mut r = SymbolResolver::new();
        let mut p1 = InMemorySymbolProvider::new();
        p1.add(make_fn("a", 0x100));
        let mut p2 = InMemorySymbolProvider::new();
        p2.add(make_fn("b", 0x200));
        r.add_provider(Box::new(p1));
        r.add_provider(Box::new(p2));
        assert!(r.resolve_name("a").is_some());
        assert!(r.resolve_name("b").is_some());
        assert!(r.resolve_name("c").is_none());
    }

    // ── SymbolError ────────────────────────────────────────────────────────────

    #[test]
    fn test_symbol_error_display() {
        assert!(
            SymbolError::NotFound("foo".into())
                .to_string()
                .contains("foo")
        );
        assert!(
            SymbolError::AddressNotFound(0xdead)
                .to_string()
                .contains("0xdead")
        );
        assert!(
            SymbolError::Duplicate("bar".into())
                .to_string()
                .contains("bar")
        );
    }
    #[test]
    fn test_symbol_error_from_anyhow() {
        let e = SymbolError::from(anyhow::anyhow!("test"));
        assert!(e.to_string().contains("test"));
    }

    // ── UnifiedSymbol ──────────────────────────────────────────────────────────

    #[test]
    fn test_unified_new() {
        let s = make_unified("foo", 0x1000, SymbolKind::Function, SymbolSource::Pdb);
        assert_eq!(s.name, "foo");
        assert_eq!(s.kind, SymbolKind::Function);
    }
    #[test]
    fn test_unified_display_name() {
        let mut s = make_unified("_Z3foov", 0x100, SymbolKind::Function, SymbolSource::Dwarf);
        assert_eq!(s.display_name(), "_Z3foov");
        s.demangled_name = Some("foo()".into());
        assert_eq!(s.display_name(), "foo()");
    }
    #[test]
    fn test_unified_end_address() {
        let mut s = make_unified("f", 0x1000, SymbolKind::Function, SymbolSource::Elf);
        s.size = Some(0x40);
        assert_eq!(s.end_address(), Some(0x1040));
    }

    // ── SymbolKind / SymbolSource ──────────────────────────────────────────────

    #[test]
    fn test_symbol_kind_variants() {
        assert_eq!(SymbolKind::Function.to_string(), "Function");
        assert_eq!(SymbolKind::Thunk.to_string(), "Thunk");
    }
    #[test]
    fn test_symbol_source_priority() {
        assert!(SymbolSource::Pdb.priority() > SymbolSource::Inferred.priority());
        assert_eq!(SymbolSource::Manual.priority(), 100);
    }

    // ── UnifiedSymbolTable ─────────────────────────────────────────────────────

    #[test]
    fn test_unified_table_add_lookup() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "main",
            0x1000,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        assert!(t.lookup_addr(0x1000).is_some());
        assert_eq!(t.lookup_addr(0x1000).unwrap().name, "main");
    }
    #[test]
    fn test_unified_table_multi_name() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "func_a",
            0x1000,
            SymbolKind::Function,
            SymbolSource::Elf,
        ));
        t.add(make_unified(
            "func_a",
            0x2000,
            SymbolKind::Function,
            SymbolSource::Dwarf,
        ));
        assert_eq!(t.lookup_name("func_a").len(), 2);
    }
    #[test]
    fn test_unified_table_nearest_below() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "a",
            0x1000,
            SymbolKind::Function,
            SymbolSource::Pe,
        ));
        t.add(make_unified(
            "b",
            0x2000,
            SymbolKind::Function,
            SymbolSource::Pe,
        ));
        assert_eq!(t.nearest_below(0x1800).unwrap().name, "a");
    }
    #[test]
    fn test_unified_table_nearest_below_none() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "h",
            0x9000,
            SymbolKind::Function,
            SymbolSource::Flirt,
        ));
        assert!(t.nearest_below(0x1000).is_none());
    }
    #[test]
    fn test_unified_table_remove() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "f",
            0x100,
            SymbolKind::Function,
            SymbolSource::Manual,
        ));
        assert_eq!(t.remove(0x100, "f"), 1);
        assert!(t.is_empty());
    }
    #[test]
    fn test_unified_table_rename() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "old",
            0x100,
            SymbolKind::Label,
            SymbolSource::Manual,
        ));
        assert!(t.rename(0x100, "old", "new"));
        assert!(t.lookup_addr(0x100).is_some());
        assert_eq!(t.lookup_addr(0x100).unwrap().name, "new");
    }
    #[test]
    fn test_unified_table_prefix() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "my_fn",
            0x100,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        t.add(make_unified(
            "other",
            0x200,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        assert_eq!(t.find_by_prefix("my_").len(), 1);
    }
    #[test]
    fn test_unified_table_merge_upgrade() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "f",
            0x100,
            SymbolKind::Function,
            SymbolSource::Inferred,
        ));
        t.add_or_upgrade(make_unified(
            "f",
            0x100,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        assert_eq!(t.lookup_addr(0x100).unwrap().source, SymbolSource::Pdb);
    }
    #[test]
    fn test_unified_table_len() {
        let mut t = UnifiedSymbolTable::new();
        assert!(t.is_empty());
        t.add(make_unified(
            "f",
            0x100,
            SymbolKind::Function,
            SymbolSource::Ai,
        ));
        assert_eq!(t.len(), 1);
    }

    // ── SyntheticSymbolGen ─────────────────────────────────────────────────────

    #[test]
    fn test_synth_function_name() {
        assert_eq!(SyntheticSymbolGen::function_name(0x1234), "sub_1234");
    }
    #[test]
    fn test_synth_data_name() {
        assert_eq!(SyntheticSymbolGen::data_name(0x5678), "byte_5678");
    }
    #[test]
    fn test_synth_label_name() {
        assert_eq!(SyntheticSymbolGen::label_name(0xABCD), "loc_ABCD");
    }
    #[test]
    fn test_synth_fill_functions() {
        let mut t = UnifiedSymbolTable::new();
        SyntheticSymbolGen::fill_functions(&mut t, &[0x1000, 0x2000]);
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup_addr(0x1000).unwrap().name, "sub_1000");
    }
    #[test]
    fn test_synth_no_overwrite_existing() {
        let mut t = UnifiedSymbolTable::new();
        t.add(make_unified(
            "main",
            0x1000,
            SymbolKind::Function,
            SymbolSource::Pdb,
        ));
        SyntheticSymbolGen::fill_functions(&mut t, &[0x1000, 0x2000]);
        assert_eq!(t.lookup_addr(0x1000).unwrap().name, "main");
    }

    // ── DemanglerPipeline ─────────────────────────────────────────────────────

    #[test]
    fn test_demangle_itanium() {
        let mut p = DemanglerPipeline::new();
        let r = p.demangle("_Z3foov");
        let _ = r;
    }
    #[test]
    fn test_demangle_rust() {
        let mut p = DemanglerPipeline::new();
        let r = p.demangle("_Rsome_rust_symbol");
        assert!(r.is_some());
    }
    #[test]
    fn test_demangle_msvc() {
        let mut p = DemanglerPipeline::new();
        let r = p.demangle("?foo@bar@@QAEXXZ");
        assert!(r.is_some());
    }
    #[test]
    fn test_demangle_plain_none() {
        let mut p = DemanglerPipeline::new();
        assert!(p.demangle("main").is_none());
    }
    #[test]
    fn test_demangle_caches() {
        let mut p = DemanglerPipeline::new();
        let _ = p.demangle("_Z3foov");
        assert!(p.cache.contains_key("_Z3foov"));
    }
    #[test]
    fn test_demangle_already_set_unchanged() {
        let mut t = UnifiedSymbolTable::new();
        let mut s = make_unified("_Z3foov", 0x1000, SymbolKind::Function, SymbolSource::Dwarf);
        s.demangled_name = Some("already set".into());
        t.add(s);
        demangle_all(&mut t);
        assert_eq!(
            t.lookup_addr(0x1000).unwrap().demangled_name.as_deref(),
            Some("already set")
        );
    }

    // ── PdbSymbolServer ────────────────────────────────────────────────────────

    #[test]
    fn test_pdb_url() {
        let s = PdbSymbolServer::new("https://msdl.microsoft.com/download/symbols");
        let url = s.pdb_url("ntdll.pdb", "AABBCCDD-1122-3344-5566-778899AABBCC", 1);
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntdll.pdb/AABBCCDD1122334455 66778899AABBCC1/ntdll.pdb"
                .replace(' ', "")
        );
    }

    #[test]
    fn pdb_url_uppercases_lowercase_guid() {
        // The symbol-server path segment is case-sensitive: a lowercase GUID
        // 404s on msdl.microsoft.com.
        let s = PdbSymbolServer::msdl();
        let url = s.pdb_url("ntdll.pdb", "1f2e3d4c-5b6a-7988-9a0b-c1d2e3f4a5b6", 1);
        assert!(
            url.contains("/1F2E3D4C5B6A79889A0BC1D2E3F4A5B61/"),
            "expected an uppercase 32-hex key, got {url}"
        );
    }

    #[test]
    fn pdb_url_strips_braces_and_dashes() {
        let s = PdbSymbolServer::msdl();
        let url = s.pdb_url("a.pdb", "{1f2e3d4c-5b6a-7988-9a0b-c1d2e3f4a5b6}", 2);
        assert!(url.contains("/1F2E3D4C5B6A79889A0BC1D2E3F4A5B62/"), "{url}");
    }

    // ── CSV field escaping ────────────────────────────────────────────────────

    #[test]
    fn export_as_csv_escapes_commas_in_names() {
        // A demangled C++ name contains commas; unescaped it would turn a
        // 5-field row into 7 fields.
        let mut sym = Symbol::new("_ZN6Widget4drawEiPKc".to_string(), 0x0040_1000, SymKind::Function);
        sym.demangled_name = Some("Widget::draw(int, char const*)".to_string());
        sym.size = Some(64);
        let mut t = SymbolStore::new();
        t.upsert(sym.clone());

        for csv in [t.export_as_csv(), SymbolExporter::to_csv(&[sym])] {
            let row = csv.lines().nth(1).expect("a data row");
            assert!(
                row.contains("\"Widget::draw(int, char const*)\""),
                "demangled name must be quoted: {row}"
            );
            assert_eq!(
                count_csv_fields(row),
                5,
                "row must still have exactly 5 fields: {row}"
            );
        }
    }

    #[test]
    fn export_as_csv_escapes_embedded_quotes() {
        let mut sym = Symbol::new("odd\"name".to_string(), 0x10, SymKind::Data);
        sym.size = Some(1);
        let csv = SymbolExporter::to_csv(&[sym]);
        let row = csv.lines().nth(1).unwrap();
        assert!(row.contains("\"odd\"\"name\""), "{row}");
        assert_eq!(count_csv_fields(row), 5, "{row}");
    }

    /// Count RFC 4180 fields, honouring quoted sections.
    fn count_csv_fields(row: &str) -> usize {
        let mut fields = 1;
        let mut in_quotes = false;
        for c in row.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => fields += 1,
                _ => {}
            }
        }
        fields
    }

    // ── CrossReferenceIndex ────────────────────────────────────────────────────

    #[test]
    fn test_xref_add_and_query() {
        let mut x = CrossReferenceIndex::new();
        x.add_xref(0x1000, 0x2000);
        x.add_xref(0x1500, 0x2000);
        let to = x.refs_to(0x2000);
        assert_eq!(to.len(), 2);
        assert!(to.contains(&0x1000));
        let from = x.refs_from(0x1000);
        assert_eq!(from.len(), 1);
        assert!(from.contains(&0x2000));
    }
    #[test]
    fn test_xref_ref_count() {
        let mut x = CrossReferenceIndex::new();
        x.add_xref(0x100, 0x200);
        x.add_xref(0x300, 0x200);
        assert_eq!(x.ref_count_to(0x200), 2);
    }
    #[test]
    fn test_xref_clear() {
        let mut x = CrossReferenceIndex::new();
        x.add_xref(0x100, 0x200);
        x.clear();
        assert_eq!(x.ref_count_to(0x200), 0);
    }

    // ── Source location ────────────────────────────────────────────────────────

    #[test]
    fn test_source_location() {
        let l = SourceLocation {
            file: "main.c".into(),
            line: 42,
            column: 7,
        };
        assert_eq!(l.to_string(), "main.c:42:7");
    }
}

