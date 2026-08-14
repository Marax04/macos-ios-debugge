//! `pdb_provider.rs` — PDB (Program Database) symbol provider stub.
//!
//! Parses Microsoft PDB files by reading the MSF (Multi-Stream File) container
//! and extracting symbols from the core PDB streams:
//!
//! - **Type Information Stream (TPI)** — type records (`LF_PROCEDURE`, `LF_CLASS`, …)
//! - **Global Symbol Stream (GSI/Publics)** — PROC32, DATA32, PUB32 records
//! - **Name Map** — PDB string table for file names
//! - **Symbol Server** — constructs Microsoft Symbol Server URLs for download
//!
//! This is a **self-contained stub**: it does not link to the `pdb` crate so
//! that the crate compiles without extra dependencies.  All parsing is done
//! against raw byte slices.  Replace the parse functions with real PDB crate
//! calls when integrating.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding, SymbolKind, SymbolProvider,
    SymbolSource, SymbolVisibility, UnifiedSymbol,
};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors raised while reading a PDB (or fetching one from a symbol server).
#[derive(Debug, Error)]
pub enum PdbError {
    /// The PDB file could not be found at the given path.
    #[error("PDB file not found: {0}")]
    NotFound(PathBuf),
    /// The MSF superblock magic did not match a known PDB signature.
    #[error("invalid PDB signature")]
    InvalidSignature,
    /// The PDB stream declared a version this reader does not support.
    #[error("unsupported PDB stream version: {0}")]
    UnsupportedVersion(u32),
    /// A stream ended or was malformed while being read.
    #[error("stream read error at offset {offset}: {msg}")]
    StreamRead {
        /// Byte offset within the stream where the read failed.
        offset: usize,
        /// Human-readable description of the failure.
        msg: String,
    },
    /// An I/O error occurred while reading the PDB.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A symbol-server HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(String),
    /// The requested symbol was not present in the PDB.
    #[error("symbol not found: {0}")]
    NotFoundSym(String),
    /// Any other error, carrying a message.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias for PDB operations.
pub type Result<T> = std::result::Result<T, PdbError>;

// ── PDB constants ─────────────────────────────────────────────────────────────

/// The old-style (`JG`) MSF superblock magic (PDB 2.00).
pub const MSF_MAGIC_OLD: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";
/// The new-style (`DS`) MSF superblock magic (PDB 7.00).
pub const MSF_MAGIC_NEW: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// Fixed stream index of the PDB information stream.
pub const PDB_STREAM_PDB: u32 = 1;
/// Fixed stream index of the TPI (type information) stream.
pub const PDB_STREAM_TPI: u32 = 2;
/// Fixed stream index of the DBI (debug information) stream.
pub const PDB_STREAM_DBI: u32 = 3;
/// Fixed stream index of the IPI (id information) stream.
pub const PDB_STREAM_IPI: u32 = 4;

// ── PdbGuid ───────────────────────────────────────────────────────────────────

/// GUID embedded in PDB header (used for symbol server URL construction).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PdbGuid {
    /// First 32-bit component (`Data1`).
    pub data1: u32,
    /// Second 16-bit component (`Data2`).
    pub data2: u16,
    /// Third 16-bit component (`Data3`).
    pub data3: u16,
    /// Final 8 bytes (`Data4`).
    pub data4: [u8; 8],
}

impl PdbGuid {
    /// Construct a GUID from its four raw components.
    #[must_use]
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Parse a GUID from a 16-byte LE slice.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        Some(Self {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        })
    }

    /// Format as the uppercase hex string used in symbol server URLs.
    /// Format: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (32 hex chars, no dashes).
    #[must_use]
    pub fn to_server_string(&self) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }

    /// Dashed string representation: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
    #[must_use]
    pub fn to_dashed_string(&self) -> String {
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl std::fmt::Display for PdbGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_dashed_string())
    }
}

// ── PdbSymbolRecord kinds ─────────────────────────────────────────────────────

/// The record kind tag for a `CodeView` symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PdbRecordKind {
    /// `S_PUB32` — public symbol (no type info).
    Pub32,
    /// `S_GPROC32` — global procedure.
    GProc32,
    /// `S_LPROC32` — local procedure.
    LProc32,
    /// `S_GDATA32` — global data item.
    GData32,
    /// `S_LDATA32` — local data item.
    LData32,
    /// `S_CONSTANT` — numeric constant.
    Constant,
    /// `S_UDT` — user-defined type name.
    Udt,
    /// Unknown / unsupported.
    Unknown(u16),
}

impl PdbRecordKind {
    /// Map a raw `CodeView` symbol record tag (`S_*`) to a [`PdbRecordKind`].
    #[must_use]
    pub const fn from_u16(tag: u16) -> Self {
        match tag {
            0x110e => Self::Pub32,
            0x1110 => Self::GProc32,
            0x110f => Self::LProc32,
            0x110d => Self::GData32,
            0x110c => Self::LData32,
            0x1107 => Self::Constant,
            0x1108 => Self::Udt,
            other => Self::Unknown(other),
        }
    }
}

// ── PdbTypeInfo ───────────────────────────────────────────────────────────────

/// A parsed type record from the TPI stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbTypeInfo {
    /// Type index (TI).
    pub type_index: u32,
    /// Leaf kind from the TPI record.
    pub leaf: PdbLeafKind,
    /// Name of the type, if available.
    pub name: Option<String>,
    /// Size in bytes if the leaf carries size information.
    pub size: Option<u64>,
}

/// The leaf kind of a TPI type record (`LF_*`); `Unknown` keeps the raw leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdbLeafKind {
    /// `LF_STRUCTURE` — a struct type.
    Struct,
    /// `LF_CLASS` — a class type.
    Class,
    /// `LF_UNION` — a union type.
    Union,
    /// `LF_ENUM` — an enumeration type.
    Enum,
    /// `LF_POINTER` — a pointer type.
    Pointer,
    /// `LF_PROCEDURE` — a free-function/procedure type.
    Procedure,
    /// `LF_MFUNCTION` — a member-function type.
    MemberFunction,
    /// `LF_ARRAY` — an array type.
    Array,
    /// A built-in primitive type (encoded in the type index, not a leaf).
    Primitive,
    /// Any other leaf, preserving its raw value.
    Unknown(u16),
}

impl PdbLeafKind {
    /// Map a raw TPI leaf value (`LF_*`) to a [`PdbLeafKind`].
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x1505 => Self::Struct,
            0x1504 => Self::Class,
            0x1506 => Self::Union,
            0x1507 => Self::Enum,
            0x1002 => Self::Pointer,
            0x1008 => Self::Procedure,
            0x1009 => Self::MemberFunction,
            0x1503 => Self::Array,
            _ => Self::Unknown(v),
        }
    }
}

// ── PdbSymbolRecord ───────────────────────────────────────────────────────────

/// A single parsed symbol record from the Global Symbol or Public symbol stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbSymbolRecord {
    /// The record's `CodeView` kind.
    pub kind: PdbRecordKind,
    /// The symbol name (still mangled for `S_PUB32`).
    pub name: String,
    /// Relative Virtual Address (segment:offset resolved).
    pub rva: u64,
    /// Section index.
    pub section: u16,
    /// Offset within the section.
    pub offset: u32,
    /// Type index, if present.
    pub type_index: Option<u32>,
    /// Length (for procedures).
    pub length: Option<u32>,
}

impl PdbSymbolRecord {
    /// Whether the record is a procedure (`S_GPROC32`/`S_LPROC32`).
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self.kind, PdbRecordKind::GProc32 | PdbRecordKind::LProc32)
    }

    /// Whether the record is a data item (`S_GDATA32`/`S_LDATA32`).
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self.kind, PdbRecordKind::GData32 | PdbRecordKind::LData32)
    }

    /// Whether the record is a public symbol (`S_PUB32`).
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self.kind, PdbRecordKind::Pub32)
    }

    /// Convert to the crate's unified [`Symbol`].
    #[must_use]
    pub fn to_symbol(&self, section_base: u64) -> Symbol {
        let addr = section_base + u64::from(self.offset);
        let kind = if self.is_function() {
            SymKind::Function
        } else {
            SymKind::Data
        };
        let mut sym = Symbol::new(self.name.clone(), addr, kind);
        sym.source = LegacySymbolSource::Debug;
        // PDB record-kind → ELF-style binding/visibility taxonomy.
        sym.binding = match self.kind {
            PdbRecordKind::LProc32 | PdbRecordKind::LData32 => SymbolBinding::Local,
            _ => SymbolBinding::Global,
        };
        sym.visibility = if self.is_public() {
            SymbolVisibility::Default
        } else {
            SymbolVisibility::Hidden
        };
        if let Some(len) = self.length {
            sym.size = Some(u64::from(len));
        }
        sym
    }

    /// Convert to [`UnifiedSymbol`].
    #[must_use]
    pub fn to_unified(&self, section_base: u64) -> UnifiedSymbol {
        let addr = section_base + u64::from(self.offset);
        let kind = if self.is_function() {
            SymbolKind::Function
        } else {
            SymbolKind::Variable
        };
        let mut u = UnifiedSymbol::new(self.name.clone(), addr, kind, SymbolSource::Pdb);
        if let Some(len) = self.length {
            u.size = Some(u64::from(len));
        }
        u
    }
}

// ── PdbHeader ────────────────────────────────────────────────────────────────

/// Minimal information extracted from the PDB header streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbHeader {
    /// PDB GUID for symbol server lookup.
    pub guid: PdbGuid,
    /// Age (incremented on each edit).
    pub age: u32,
    /// PDB version.
    pub version: u32,
    /// Original PDB file name (from name map).
    pub pdb_file_name: String,
}

// ── PdbNameMap ────────────────────────────────────────────────────────────────

/// PDB string table (name map stream).  Maps offset → string.
#[derive(Debug, Default, Clone)]
pub struct PdbNameMap {
    strings: HashMap<u32, String>,
}

impl PdbNameMap {
    /// Create an empty name map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that byte `offset` in the string heap holds `name`.
    pub fn insert(&mut self, offset: u32, name: impl Into<String>) {
        self.strings.insert(offset, name.into());
    }

    /// The string at byte `offset`, if any.
    pub fn get(&self, offset: u32) -> Option<&str> {
        self.strings.get(&offset).map(String::as_str)
    }

    /// Number of distinct strings held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the map holds no strings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Parse a simple contiguous string heap: null-terminated strings packed
    /// end-to-end, each accessible by byte offset.
    #[must_use]
    pub fn parse_heap(data: &[u8]) -> Self {
        let mut map = Self::new();
        let mut offset = 0u32;
        let mut start = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if b == 0 {
                if start < i {
                    let s = std::str::from_utf8(&data[start..i])
                        .unwrap_or("?")
                        .to_string();
                    map.insert(offset, s);
                }
                start = i + 1;
                offset = u32::try_from(i + 1).unwrap_or(u32::MAX);
            }
        }
        map
    }
}

// ── PdbSectionContrib ─────────────────────────────────────────────────────────

/// Section contribution entry — maps (section, offset) → RVA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbSectionContrib {
    /// 1-based section index the contribution belongs to.
    pub section: u16,
    /// Offset of the contribution within its section.
    pub offset: u32,
    /// Size of the contribution in bytes.
    pub size: u32,
    /// Resolved relative virtual address of the contribution.
    pub rva: u64,
}

// ── PdbSymbolProvider ─────────────────────────────────────────────────────────

/// Implements [`SymbolProvider`] for PDB files.
///
/// In real code, construct via `PdbSymbolProvider::load(path)`.  This stub
/// exposes a pre-populated provider for testing.
#[derive(Debug)]
pub struct PdbSymbolProvider {
    name: String,
    symbols: Vec<PdbSymbolRecord>,
    types: Vec<PdbTypeInfo>,
    name_map: PdbNameMap,
    header: Option<PdbHeader>,
    section_bases: HashMap<u16, u64>,
    /// `name → index into symbols` (first occurrence wins).
    by_name: HashMap<String, usize>,
    /// `(resolved VA, index into symbols)` sorted ascending, for O(log n)
    /// address lookups.
    addr_sorted: Vec<(u64, usize)>,
}

impl PdbSymbolProvider {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create an empty provider identified by `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            symbols: Vec::new(),
            types: Vec::new(),
            name_map: PdbNameMap::new(),
            header: None,
            section_bases: HashMap::new(),
            by_name: HashMap::new(),
            addr_sorted: Vec::new(),
        }
    }

    /// Construct from pre-parsed records (for testing / in-memory use).
    pub fn from_records(name: impl Into<String>, records: Vec<PdbSymbolRecord>) -> Self {
        let mut p = Self::new(name);
        p.symbols = records;
        p.rebuild_index();
        p
    }

    /// Stub loader: read a file and parse what we can.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, cannot be read, or has an invalid PDB signature.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PdbError::NotFound(path.to_path_buf()));
        }
        let data = std::fs::read(path)?;
        Self::parse(&data, path.to_string_lossy().as_ref())
    }

    /// Parse raw PDB bytes (stub: detect signature, extract basic info).
    ///
    /// # Errors
    ///
    /// Returns an error if the PDB data is too short or has an invalid signature.
    pub fn parse(data: &[u8], name: &str) -> Result<Self> {
        if data.len() < 32 {
            return Err(PdbError::InvalidSignature);
        }
        if !data.starts_with(&MSF_MAGIC_NEW[..8]) && !data.starts_with(&MSF_MAGIC_OLD[..8]) {
            return Err(PdbError::InvalidSignature);
        }
        // Real parsing would extract page size, stream directory, etc.
        //
        // NOTE: the PDB GUID/age live in the PDB info stream (stream 1), which
        // requires walking the MSF stream directory. The bytes at superblock
        // offsets 0x18/0x20 are MSF fields (NumDirectoryBytes / block map),
        // NOT the GUID/age; a previous version read them anyway and produced
        // confident-looking wrong headers, breaking symbol-server URL
        // construction downstream. This stub therefore leaves `header` as
        // `None` — use the `rustre-symbols-pdb` crate to parse the real info
        // stream and call [`Self::set_header`] with the result.
        Ok(Self::new(name))
    }

    // ── Mutation helpers ─────────────────────────────────────────────────────

    /// Append a symbol record and incrementally update the name/address indexes.
    pub fn add_record(&mut self, rec: PdbSymbolRecord) {
        self.symbols.push(rec);
        let idx = self.symbols.len() - 1;
        let rec = &self.symbols[idx];
        self.by_name.entry(rec.name.clone()).or_insert(idx);
        let va = self.section_bases.get(&rec.section).copied().unwrap_or(0)
            + u64::from(rec.offset);
        let pos = self.addr_sorted.partition_point(|&e| e <= (va, idx));
        self.addr_sorted.insert(pos, (va, idx));
    }
    /// Append a parsed type record.
    pub fn add_type(&mut self, ty: PdbTypeInfo) {
        self.types.push(ty);
    }
    /// Set the parsed PDB header (GUID/age/version).
    pub fn set_header(&mut self, header: PdbHeader) {
        self.header = Some(header);
    }
    /// Set the resolved base VA for a section, rebuilding the address index
    /// since resolved symbol addresses depend on it.
    pub fn set_section_base(&mut self, section: u16, base: u64) {
        self.section_bases.insert(section, base);
        // Resolved VAs changed; rebuild the address index.
        self.rebuild_index();
    }

    /// Rebuild the name / address lookup indexes from `symbols`.
    fn rebuild_index(&mut self) {
        self.by_name.clear();
        self.addr_sorted.clear();
        self.addr_sorted.reserve(self.symbols.len());
        for (i, r) in self.symbols.iter().enumerate() {
            self.by_name.entry(r.name.clone()).or_insert(i);
            let va = self.section_bases.get(&r.section).copied().unwrap_or(0)
                + u64::from(r.offset);
            self.addr_sorted.push((va, i));
        }
        self.addr_sorted.sort_unstable();
    }
    /// Replace the PDB name map (string heap).
    pub fn set_name_map(&mut self, map: PdbNameMap) {
        self.name_map = map;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The parsed PDB header, if one has been set.
    #[must_use]
    pub const fn header(&self) -> Option<&PdbHeader> {
        self.header.as_ref()
    }
    /// The symbol records held.
    #[must_use]
    pub fn records(&self) -> &[PdbSymbolRecord] {
        &self.symbols
    }
    /// The type records held.
    #[must_use]
    pub fn types(&self) -> &[PdbTypeInfo] {
        &self.types
    }
    /// The PDB name map (string heap).
    #[must_use]
    pub const fn name_map(&self) -> &PdbNameMap {
        &self.name_map
    }
    /// Number of symbol records held.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.symbols.len()
    }
    /// Number of type records held.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.types.len()
    }

    fn section_base(&self, section: u16) -> u64 {
        self.section_bases.get(&section).copied().unwrap_or(0)
    }

    fn to_symbols_vec(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .map(|r| r.to_symbol(self.section_base(r.section)))
            .collect()
    }
}

impl SymbolProvider for PdbSymbolProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        let r = &self.symbols[*self.by_name.get(name)?];
        Some(r.to_symbol(self.section_base(r.section)))
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        let start = self.addr_sorted.partition_point(|&(a, _)| a < addr);
        let &(a, i) = self.addr_sorted.get(start)?;
        if a != addr {
            return None;
        }
        let r = &self.symbols[i];
        Some(r.to_symbol(self.section_base(r.section)))
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        let ub = self.addr_sorted.partition_point(|&(a, _)| a <= addr);
        let &(best, _) = self.addr_sorted[..ub].last()?;
        // Among ties at the same address, return the first-inserted record.
        let start = self.addr_sorted[..ub].partition_point(|&(a, _)| a < best);
        let (_, i) = self.addr_sorted[start];
        let r = &self.symbols[i];
        Some(r.to_symbol(self.section_base(r.section)))
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.to_symbols_vec()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|r| r.is_function())
            .map(|r| r.to_symbol(self.section_base(r.section)))
            .collect()
    }

    fn source_line_for_address(&self, _addr: u64) -> Option<SourceLocation> {
        // PDB line number info requires the DBI stream; stub returns None.
        None
    }
}

// ── SymbolServerClient ────────────────────────────────────────────────────────

/// HTTP stub for downloading PDB files from a Microsoft Symbol Server.
///
/// Real implementation would use `reqwest` or `ureq`; this stub only constructs
/// URLs and validates them.
#[derive(Debug, Clone)]
pub struct SymbolServerClient {
    /// Base URL of the symbol server (no trailing slash required).
    pub base_url: String,
    /// Optional local symbol cache directory.
    pub cache_dir: Option<PathBuf>,
}

impl SymbolServerClient {
    /// Microsoft default symbol server.
    #[must_use]
    pub fn msdl() -> Self {
        Self {
            base_url: "https://msdl.microsoft.com/download/symbols".into(),
            cache_dir: None,
        }
    }

    /// Create a client pointed at `base_url` with no local cache.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            cache_dir: None,
        }
    }

    /// Set the local cache directory (builder style).
    #[must_use]
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    /// Construct the symbol server URL for a PDB file.
    ///
    /// URL format: `{base}/{pdb_name}/{guid}{age:X}/{pdb_name}`
    #[must_use]
    pub fn build_url(&self, pdb_name: &str, guid: &PdbGuid, age: u32) -> String {
        format!(
            "{}/{}/{}{:X}/{}",
            self.base_url.trim_end_matches('/'),
            pdb_name,
            guid.to_server_string(),
            age,
            pdb_name,
        )
    }

    /// Construct a local cache path for the PDB.
    #[must_use]
    pub fn cache_path(&self, pdb_name: &str, guid: &PdbGuid, age: u32) -> Option<PathBuf> {
        self.cache_dir.as_ref().map(|d| {
            d.join(pdb_name)
                .join(format!("{}{:X}", guid.to_server_string(), age))
                .join(pdb_name)
        })
    }

    /// Stub download: check local cache, then return the URL that *would* be
    /// used for HTTP GET.  Returns `Ok(path)` if cached, `Err(Http(url))` if not.
    ///
    /// # Errors
    ///
    /// Returns `PdbError::Http` if the file is not present in the local cache.
    pub fn download_pdb(&self, pdb_name: &str, guid: &PdbGuid, age: u32) -> Result<PathBuf> {
        // Check local cache first
        if let Some(cache) = self.cache_path(pdb_name, guid, age)
            && cache.exists()
        {
            return Ok(cache);
        }
        // In a real implementation: HTTP GET the URL and save to cache_dir.
        let url = self.build_url(pdb_name, guid, age);
        Err(PdbError::Http(format!("would fetch: {url}")))
    }

    /// Return the URL string for a given PDB (no I/O).
    #[must_use]
    pub fn url_for(&self, pdb_name: &str, guid: &PdbGuid, age: u32) -> String {
        self.build_url(pdb_name, guid, age)
    }
}

// ── PdbParser ─────────────────────────────────────────────────────────────────

/// Low-level parser helpers for PDB byte streams.
pub struct PdbParser;

impl PdbParser {
    /// Detect whether `data` looks like a PDB file.
    #[must_use]
    pub fn detect(data: &[u8]) -> bool {
        data.starts_with(&MSF_MAGIC_NEW[..8]) || data.starts_with(&MSF_MAGIC_OLD[..8])
    }

    /// Detect PDB format version (new MSF7 vs old JG).
    #[must_use]
    pub fn format_version(data: &[u8]) -> Option<&'static str> {
        if data.starts_with(&MSF_MAGIC_NEW[..8]) {
            return Some("MSF7");
        }
        if data.starts_with(&MSF_MAGIC_OLD[..8]) {
            return Some("JG");
        }
        None
    }

    /// Parse a null-terminated UTF-8 name from `data` at `offset`.
    #[must_use]
    pub fn read_name(data: &[u8], offset: usize) -> Option<String> {
        let slice = data.get(offset..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&slice[..end])
            .ok()
            .map(std::string::ToString::to_string)
    }

    /// Parse a GUID from `data` at `offset` (16 bytes, little-endian).
    ///
    /// # Panics
    ///
    /// Does not panic; returns `None` if `offset + 16` exceeds the data length.
    #[must_use]
    pub fn read_guid(data: &[u8], offset: usize) -> Option<PdbGuid> {
        PdbGuid::from_bytes(data.get(offset..offset + 16)?)
    }

    /// Read a `u32` (LE) at `offset`.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `try_into` conversion of a 4-byte slice fails, which is impossible by construction.
    #[must_use]
    pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
        data.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read a `u16` (LE) at `offset`.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `try_into` conversion of a 2-byte slice fails, which is impossible by construction.
    #[must_use]
    pub fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
        data.get(offset..offset + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    }

    /// Stub: parse symbol records from a raw Public Symbols stream blob.
    /// In a real implementation this would iterate CV `S_PUB32` records.
    #[must_use]
    pub fn parse_publics_stream(data: &[u8]) -> Vec<PdbSymbolRecord> {
        // The real format: list of cv_symbol_t records:
        //   u16 length, u16 kind, then kind-specific bytes.
        let mut records = Vec::new();
        let mut cursor = 0;
        while cursor + 4 <= data.len() {
            let length = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
            let kind_raw = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]);
            if length < 2 || cursor + 2 + length > data.len() {
                break;
            }
            let kind = PdbRecordKind::from_u16(kind_raw);
            let record_data = &data[cursor + 4..cursor + 2 + length];
            match kind {
                PdbRecordKind::GProc32 | PdbRecordKind::LProc32 => {
                    // Minimal PROC32: u32 parent, u32 end, u32 next, u32 len, u32 dbgStart,
                    //                  u32 dbgEnd, u32 typind, u32 off, u16 seg, u8 flags, name
                    if record_data.len() >= 35 {
                        let length = u32::from_le_bytes([
                            record_data[12],
                            record_data[13],
                            record_data[14],
                            record_data[15],
                        ]);
                        let type_index = u32::from_le_bytes([
                            record_data[24],
                            record_data[25],
                            record_data[26],
                            record_data[27],
                        ]);
                        let offset = u32::from_le_bytes([
                            record_data[28],
                            record_data[29],
                            record_data[30],
                            record_data[31],
                        ]);
                        let section = u16::from_le_bytes([record_data[32], record_data[33]]);
                        let name = Self::read_name(record_data, 35)
                            .unwrap_or_else(|| format!("sub_{offset:x}"));
                        records.push(PdbSymbolRecord {
                            kind,
                            name,
                            rva: 0,
                            section,
                            offset,
                            type_index: Some(type_index),
                            length: Some(length),
                        });
                    }
                }
                PdbRecordKind::GData32 | PdbRecordKind::LData32 => {
                    // DATA32: u32 typind, u32 off, u16 seg, name (name starts at byte 10)
                    if record_data.len() >= 10 {
                        let type_index = u32::from_le_bytes([
                            record_data[0],
                            record_data[1],
                            record_data[2],
                            record_data[3],
                        ]);
                        let offset = u32::from_le_bytes([
                            record_data[4],
                            record_data[5],
                            record_data[6],
                            record_data[7],
                        ]);
                        let section = u16::from_le_bytes([record_data[8], record_data[9]]);
                        let name = Self::read_name(record_data, 10)
                            .unwrap_or_else(|| format!("data_{offset:x}"));
                        records.push(PdbSymbolRecord {
                            kind,
                            name,
                            rva: 0,
                            section,
                            offset,
                            type_index: Some(type_index),
                            length: None,
                        });
                    }
                }
                // PUB32: u32 flags, u32 off, u16 seg, name (name starts at byte 10)
                PdbRecordKind::Pub32 if record_data.len() >= 10 => {
                    let offset = u32::from_le_bytes([
                        record_data[4],
                        record_data[5],
                        record_data[6],
                        record_data[7],
                    ]);
                    let section = u16::from_le_bytes([record_data[8], record_data[9]]);
                    let name = Self::read_name(record_data, 10)
                        .unwrap_or_else(|| format!("pub_{offset:x}"));
                    records.push(PdbSymbolRecord {
                        kind,
                        name,
                        rva: 0,
                        section,
                        offset,
                        type_index: None,
                        length: None,
                    });
                }
                _ => {}
            }
            cursor += 2 + length;
        }
        records
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rec(name: &str, addr: u64, kind: PdbRecordKind) -> PdbSymbolRecord {
        PdbSymbolRecord {
            kind,
            name: name.to_string(),
            rva: addr,
            section: 1,
            offset: u32::try_from(addr & u64::from(u32::MAX)).unwrap_or(u32::MAX),
            type_index: None,
            length: None,
        }
    }

    fn make_proc(name: &str, offset: u32, len: u32) -> PdbSymbolRecord {
        PdbSymbolRecord {
            kind: PdbRecordKind::GProc32,
            name: name.to_string(),
            rva: 0,
            section: 1,
            offset,
            type_index: None,
            length: Some(len),
        }
    }

    // ── PdbGuid ────────────────────────────────────────────────────────────────

    #[test]
    fn guid_from_bytes_too_short() {
        assert!(PdbGuid::from_bytes(&[0u8; 10]).is_none());
    }
    #[test]
    fn guid_from_bytes_ok() {
        let b: Vec<u8> = (0..16).collect();
        assert!(PdbGuid::from_bytes(&b).is_some());
    }
    #[test]
    fn guid_server_string_length() {
        let g = PdbGuid::new(
            0xAABB_CCDD,
            0x1122,
            0x3344,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
        );
        assert_eq!(g.to_server_string().len(), 32);
    }
    #[test]
    fn guid_dashed_string() {
        let g = PdbGuid::new(0, 0, 0, [0; 8]);
        let s = g.to_dashed_string();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
    }
    #[test]
    fn guid_display() {
        let g = PdbGuid::new(1, 2, 3, [0; 8]);
        assert!(format!("{g}").contains('-'));
    }

    // ── PdbRecordKind ─────────────────────────────────────────────────────────

    #[test]
    fn record_kind_pub32() {
        assert_eq!(PdbRecordKind::from_u16(0x110e), PdbRecordKind::Pub32);
    }
    #[test]
    fn record_kind_gproc32() {
        assert_eq!(PdbRecordKind::from_u16(0x1110), PdbRecordKind::GProc32);
    }
    #[test]
    fn record_kind_unknown() {
        assert!(matches!(
            PdbRecordKind::from_u16(0xffff),
            PdbRecordKind::Unknown(0xffff)
        ));
    }

    // ── PdbLeafKind ───────────────────────────────────────────────────────────

    #[test]
    fn leaf_struct() {
        assert_eq!(PdbLeafKind::from_u16(0x1505), PdbLeafKind::Struct);
    }
    #[test]
    fn leaf_unknown() {
        assert!(matches!(
            PdbLeafKind::from_u16(0x0000),
            PdbLeafKind::Unknown(0)
        ));
    }

    // ── PdbSymbolRecord ───────────────────────────────────────────────────────

    #[test]
    fn record_is_function() {
        assert!(make_proc("foo", 0x100, 50).is_function());
        assert!(!make_rec("bar", 0x200, PdbRecordKind::GData32).is_function());
    }
    #[test]
    fn record_is_data() {
        assert!(make_rec("g_var", 0, PdbRecordKind::GData32).is_data());
        assert!(!make_proc("f", 0, 10).is_data());
    }
    #[test]
    fn record_to_symbol() {
        let rec = make_proc("MyFunc", 0x1000, 0x200);
        let sym = rec.to_symbol(0); // section_base 0
        assert_eq!(sym.name, "MyFunc");
        assert_eq!(sym.address, 0x1000);
        assert_eq!(sym.size, Some(0x200));
    }
    #[test]
    fn record_to_unified() {
        let rec = make_proc("Proc", 0x2000, 0x80);
        let u = rec.to_unified(0);
        assert_eq!(u.name, "Proc");
        assert_eq!(u.source, SymbolSource::Pdb);
    }

    // ── PdbNameMap ────────────────────────────────────────────────────────────

    #[test]
    fn namemap_insert_get() {
        let mut m = PdbNameMap::new();
        m.insert(0, "hello");
        m.insert(6, "world");
        assert_eq!(m.get(0), Some("hello"));
        assert_eq!(m.get(6), Some("world"));
        assert!(m.get(99).is_none());
    }
    #[test]
    fn namemap_parse_heap() {
        let heap = b"hello\0world\0foo\0";
        let m = PdbNameMap::parse_heap(heap);
        assert_eq!(m.get(0), Some("hello"));
        assert_eq!(m.get(6), Some("world"));
    }
    #[test]
    fn namemap_len() {
        let mut m = PdbNameMap::new();
        assert!(m.is_empty());
        m.insert(0, "x");
        assert_eq!(m.len(), 1);
    }

    // ── PdbSymbolProvider ─────────────────────────────────────────────────────

    #[test]
    fn provider_new_empty() {
        let p = PdbSymbolProvider::new("test.pdb");
        assert_eq!(p.record_count(), 0);
    }
    #[test]
    fn provider_from_records() {
        let recs = vec![
            make_proc("main", 0x1000, 0x100),
            make_proc("init", 0x2000, 0x50),
        ];
        let p = PdbSymbolProvider::from_records("test.pdb", recs);
        assert_eq!(p.record_count(), 2);
    }
    #[test]
    fn provider_lookup_name() {
        let p = PdbSymbolProvider::from_records("t.pdb", vec![make_proc("main", 0x1000, 10)]);
        assert!(p.lookup_name("main").is_some());
        assert!(p.lookup_name("foo").is_none());
    }
    #[test]
    fn provider_lookup_address() {
        let p = PdbSymbolProvider::from_records("t.pdb", vec![make_proc("main", 0x1000, 10)]);
        assert!(p.lookup_address(0x1000).is_some());
        assert!(p.lookup_address(0x9999).is_none());
    }
    #[test]
    fn provider_lookup_nearest() {
        let recs = vec![make_proc("a", 0x1000, 10), make_proc("b", 0x2000, 10)];
        let p = PdbSymbolProvider::from_records("t.pdb", recs);
        assert_eq!(p.lookup_nearest(0x1500).unwrap().name, "a");
    }
    #[test]
    fn provider_all_symbols() {
        let recs = vec![
            make_proc("f", 0x1000, 0),
            make_rec("d", 0x2000, PdbRecordKind::GData32),
        ];
        let p = PdbSymbolProvider::from_records("t.pdb", recs);
        assert_eq!(p.all_symbols().len(), 2);
    }
    #[test]
    fn provider_all_functions() {
        let recs = vec![
            make_proc("f", 0x1000, 0),
            make_rec("d", 0x2000, PdbRecordKind::GData32),
        ];
        let p = PdbSymbolProvider::from_records("t.pdb", recs);
        assert_eq!(p.all_functions().len(), 1);
    }
    #[test]
    fn provider_source_line_none() {
        let p = PdbSymbolProvider::new("t.pdb");
        assert!(p.source_line_for_address(0x1000).is_none());
    }
    #[test]
    fn provider_name() {
        let p = PdbSymbolProvider::new("ntdll.pdb");
        assert_eq!(p.name(), "ntdll.pdb");
    }
    #[test]
    fn provider_section_base() {
        let mut p = PdbSymbolProvider::from_records("t.pdb", vec![make_proc("f", 0x100, 10)]);
        p.set_section_base(1, 0x0040_1000);
        let sym = p.lookup_address(0x0040_1100).unwrap();
        assert_eq!(sym.name, "f");
        assert_eq!(sym.address, 0x0040_1100);
    }
    #[test]
    fn provider_add_type() {
        let mut p = PdbSymbolProvider::new("t.pdb");
        p.add_type(PdbTypeInfo {
            type_index: 0x1000,
            leaf: PdbLeafKind::Struct,
            name: Some("MyStruct".into()),
            size: Some(16),
        });
        assert_eq!(p.type_count(), 1);
    }

    // ── SymbolServerClient ────────────────────────────────────────────────────

    #[test]
    fn server_url_format() {
        let client = SymbolServerClient::msdl();
        let guid = PdbGuid::new(
            0xAABB_CCDD,
            0x1122,
            0x3344,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
        );
        let url = client.url_for("ntdll.pdb", &guid, 1);
        assert!(url.starts_with("https://msdl.microsoft.com"));
        assert!(url.contains("ntdll.pdb"));
    }
    #[test]
    fn server_cache_path() {
        let client = SymbolServerClient::new("http://symsrv").with_cache_dir("/tmp/syms");
        let guid = PdbGuid::new(0, 0, 0, [0; 8]);
        let p = client.cache_path("foo.pdb", &guid, 1).unwrap();
        assert!(p.starts_with("/tmp/syms"));
    }
    #[test]
    fn server_download_no_cache() {
        let client = SymbolServerClient::new("http://symsrv");
        let guid = PdbGuid::new(0, 0, 0, [0; 8]);
        let err = client.download_pdb("foo.pdb", &guid, 1).unwrap_err();
        assert!(matches!(err, PdbError::Http(_)));
    }
    #[test]
    fn server_download_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let guid = PdbGuid::new(0, 0, 0, [0; 8]);
        let client = SymbolServerClient::new("http://x").with_cache_dir(dir.path());
        let cache = client.cache_path("a.pdb", &guid, 1).unwrap();
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, b"fake pdb").unwrap();
        let result = client.download_pdb("a.pdb", &guid, 1).unwrap();
        assert_eq!(result, cache);
    }

    // ── PdbParser ─────────────────────────────────────────────────────────────

    #[test]
    fn parser_detect_new() {
        let mut d = vec![0u8; 32];
        d[..8].copy_from_slice(&MSF_MAGIC_NEW[..8]);
        assert!(PdbParser::detect(&d));
    }
    #[test]
    fn parser_detect_old() {
        let mut d = vec![0u8; 48];
        d[..8].copy_from_slice(&MSF_MAGIC_OLD[..8]);
        assert!(PdbParser::detect(&d));
    }
    #[test]
    fn parser_detect_false() {
        assert!(!PdbParser::detect(b"not a pdb"));
    }
    #[test]
    fn parser_format_version() {
        let mut d = vec![0u8; 32];
        d[..8].copy_from_slice(&MSF_MAGIC_NEW[..8]);
        assert_eq!(PdbParser::format_version(&d), Some("MSF7"));
    }
    #[test]
    fn parser_read_name() {
        let data = b"hello\0world\0";
        assert_eq!(PdbParser::read_name(data, 0), Some("hello".into()));
        assert_eq!(PdbParser::read_name(data, 6), Some("world".into()));
    }
    #[test]
    fn parser_read_u32() {
        let data = &[0x01, 0x00, 0x00, 0x00];
        assert_eq!(PdbParser::read_u32(data, 0), Some(1));
    }
    #[test]
    fn parser_read_u16() {
        let data = &[0x34, 0x12];
        assert_eq!(PdbParser::read_u16(data, 0), Some(0x1234));
    }
    #[test]
    fn parse_does_not_fabricate_header_from_superblock() {
        // Offsets 0x18/0x20 hold MSF superblock fields, not GUID/age; a
        // fabricated header produced symbol-server URLs that never resolve.
        let mut d = vec![0xABu8; 4096];
        d[..8].copy_from_slice(&MSF_MAGIC_NEW[..8]);
        let p = PdbSymbolProvider::parse(&d, "t.pdb").unwrap();
        assert!(p.header().is_none());
    }

    #[test]
    fn provider_indexed_lookups_with_section_base() {
        let mut p = PdbSymbolProvider::new("t");
        p.add_record(make_rec("f1", 0x100, PdbRecordKind::GProc32));
        p.add_record(make_rec("f2", 0x200, PdbRecordKind::GProc32));
        p.set_section_base(1, 0x1000);
        assert_eq!(p.lookup_name("f1").unwrap().address, 0x1100);
        assert_eq!(p.lookup_address(0x1200).unwrap().name, "f2");
        assert!(p.lookup_address(0x1201).is_none());
        assert_eq!(p.lookup_nearest(0x11ff).unwrap().name, "f1");
        assert_eq!(p.lookup_nearest(0x1200).unwrap().name, "f2");
        assert!(p.lookup_nearest(0x10ff).is_none());
        // Records added after the base is set are indexed too.
        p.add_record(make_rec("f3", 0x300, PdbRecordKind::GProc32));
        assert_eq!(p.lookup_address(0x1300).unwrap().name, "f3");
    }

    #[test]
    fn parser_parse_invalid_too_short() {
        assert!(matches!(
            PdbSymbolProvider::parse(b"hi", "t.pdb"),
            Err(PdbError::InvalidSignature)
        ));
    }

    // ── PdbParser::parse_publics_stream ───────────────────────────────────────

    #[test]
    fn parse_publics_empty() {
        assert_eq!(PdbParser::parse_publics_stream(&[]).len(), 0);
    }
    #[test]
    fn parse_publics_truncated() {
        // Only 3 bytes — not enough for any record
        let data = [0x10u8, 0x00, 0x10];
        assert_eq!(PdbParser::parse_publics_stream(&data).len(), 0);
    }

    /// Build one CV record: u16 length, u16 kind, then `payload`.
    /// `length` counts the kind field plus the payload.
    fn cv_record(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut out = length.to_le_bytes().to_vec();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parse_publics_pub32_name_round_trip() {
        // PublicSym32: u32 flags, u32 offset, u16 segment, then the name.
        // The name begins at payload byte 10, not 11.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes()); // flags
        payload.extend_from_slice(&0x1234u32.to_le_bytes()); // offset
        payload.extend_from_slice(&1u16.to_le_bytes()); // segment
        payload.extend_from_slice(b"_main\0");
        let recs = PdbParser::parse_publics_stream(&cv_record(0x110e, &payload));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "_main", "leading underscore must not be eaten");
        assert_eq!(recs[0].offset, 0x1234);
        assert_eq!(recs[0].section, 1);
    }

    #[test]
    fn parse_publics_data32_name_round_trip() {
        // DataSym: u32 type_index, u32 offset, u16 segment, then the name.
        let mut payload = Vec::new();
        payload.extend_from_slice(&7u32.to_le_bytes()); // type index
        payload.extend_from_slice(&0x40u32.to_le_bytes()); // offset
        payload.extend_from_slice(&2u16.to_le_bytes()); // segment
        payload.extend_from_slice(b"_g_counter\0");
        let recs = PdbParser::parse_publics_stream(&cv_record(0x110d, &payload));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "_g_counter");
        assert_eq!(recs[0].type_index, Some(7));
    }

    // ── S_LPROC32 is 0x110F; 0x1111 is S_REGREL32 ─────────────────────────────

    #[test]
    fn record_kind_lproc32_is_110f() {
        assert_eq!(PdbRecordKind::from_u16(0x110f), PdbRecordKind::LProc32);
    }

    #[test]
    fn record_kind_regrel32_is_not_a_procedure() {
        // 0x1111 is S_REGREL32, a register-relative *local variable*. It must
        // not be decoded with the ProcSym32 layout.
        assert!(matches!(
            PdbRecordKind::from_u16(0x1111),
            PdbRecordKind::Unknown(0x1111)
        ));
    }

    #[test]
    fn parse_publics_regrel32_emits_no_function() {
        // A plausible S_REGREL32 payload, long enough (>= 35 bytes) that the
        // old code would have parsed it as a procedure.
        let payload = vec![0xAAu8; 48];
        let recs = PdbParser::parse_publics_stream(&cv_record(0x1111, &payload));
        assert!(recs.is_empty(), "S_REGREL32 must not yield a function");
    }

    #[test]
    fn parse_publics_lproc32_is_recovered() {
        // ProcSym32 fixed prefix is 35 bytes, then the name.
        let mut payload = vec![0u8; 35];
        payload[12..16].copy_from_slice(&0x20u32.to_le_bytes()); // proc length
        payload[24..28].copy_from_slice(&3u32.to_le_bytes()); // type index
        payload[28..32].copy_from_slice(&0x500u32.to_le_bytes()); // offset
        payload[32..34].copy_from_slice(&1u16.to_le_bytes()); // segment
        payload.extend_from_slice(b"static_helper\0");
        let recs = PdbParser::parse_publics_stream(&cv_record(0x110f, &payload));
        assert_eq!(recs.len(), 1, "S_LPROC32 (0x110F) must be recovered");
        assert_eq!(recs[0].kind, PdbRecordKind::LProc32);
        assert_eq!(recs[0].name, "static_helper");
        assert_eq!(recs[0].offset, 0x500);
        assert_eq!(recs[0].length, Some(0x20));
    }
}
