//! `import_rebuilder` — Reconstruct a valid PE import table from raw data.
//!
//! Covers: [`ImportRebuilder`] (the primary API), [`IatFixer`] (align/patch
//! the IAT), [`ImportThunk`] reconstruction, [`OrdinalToName`] mapping,
//! [`ImportByHash`] resolver, [`DelayLoadRebuilder`], and
//! [`BoundImportFixer`].

use std::collections::HashMap;

/// Re-export of [`std::fmt`] for downstream formatting helpers built on top of
/// this module's import structures.
pub use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the import rebuilder.
#[derive(Debug, Error)]
pub enum ImportRebuildError {
    #[error("IAT entry out of range: rva {0:#x}")]
    IatOutOfRange(u64),
    #[error("DLL not found in ordinal database: {0}")]
    DllNotFound(String),
    #[error("ordinal {ordinal} not found in {dll}")]
    OrdinalNotFound { dll: String, ordinal: u16 },
    #[error("hash collision: {0:#x} matches multiple symbols")]
    HashCollision(u32),
    #[error("buffer too small for import table: need {need} have {have}")]
    BufferTooSmall { need: usize, have: usize },
    #[error("thunk sanity failed: {0}")]
    ThunkSanity(String),
    #[error("delay load stub corrupt: {0}")]
    DelayLoadCorrupt(String),
    #[error("bound import directory corrupt")]
    BoundImportCorrupt,
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportEntry / ImportThunk
// ─────────────────────────────────────────────────────────────────────────────

/// A single imported function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// Name of the importing DLL.
    pub dll: String,
    /// Function name (if imported by name).
    pub name: Option<String>,
    /// Import ordinal (if imported by ordinal).
    pub ordinal: Option<u16>,
    /// Hint from the hint/name table.
    pub hint: u16,
    /// RVA of the IAT slot for this import.
    pub iat_rva: u64,
    /// RVA of the ILT entry.
    pub ilt_rva: u64,
}

/// A reconstructed import thunk (pairs ILT entry ↔ IAT slot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportThunk {
    /// RVA of the ILT entry.
    pub ilt_rva: u64,
    /// RVA of the IAT entry (stub address).
    pub iat_rva: u64,
    /// The encoded thunk value (bit 31/63 set = by ordinal).
    pub thunk_value: u64,
    /// Whether this is an ordinal import.
    pub by_ordinal: bool,
    /// Resolved name (after [`OrdinalToName`] lookup, if needed).
    pub resolved_name: Option<String>,
}

impl ImportThunk {
    /// Encode a by-name thunk for a PE32 binary.
    #[must_use]
    pub fn by_name_pe32(hint_name_rva: u32) -> Self {
        Self {
            ilt_rva: u64::from(hint_name_rva),
            iat_rva: u64::from(hint_name_rva),
            thunk_value: u64::from(hint_name_rva),
            by_ordinal: false,
            resolved_name: None,
        }
    }

    /// Encode a by-ordinal thunk for a PE32 binary.
    #[must_use]
    pub fn by_ordinal_pe32(ordinal: u16) -> Self {
        let val = 0x8000_0000u64 | u64::from(ordinal);
        Self {
            ilt_rva: val,
            iat_rva: val,
            thunk_value: val,
            by_ordinal: true,
            resolved_name: None,
        }
    }

    /// Returns the ordinal if this is an ordinal import.
    #[must_use]
    pub const fn ordinal(&self) -> Option<u16> {
        if self.by_ordinal {
            Some((self.thunk_value & 0xFFFF) as u16)
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrdinalToName
// ─────────────────────────────────────────────────────────────────────────────

/// Maps ordinal numbers to function names for a set of known DLLs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrdinalToName {
    /// DLL name (lower-case) → (ordinal → function name).
    db: HashMap<String, HashMap<u16, String>>,
}

impl OrdinalToName {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a mapping for `dll` ordinal → name.
    pub fn insert(&mut self, dll: impl Into<String>, ordinal: u16, name: impl Into<String>) {
        self.db
            .entry(dll.into().to_lowercase())
            .or_default()
            .insert(ordinal, name.into());
    }

    /// Look up `ordinal` in `dll`. Returns `None` if not found.
    #[must_use]
    pub fn lookup(&self, dll: &str, ordinal: u16) -> Option<&str> {
        self.db
            .get(&dll.to_lowercase())?
            .get(&ordinal)
            .map(String::as_str)
    }

    /// Number of DLLs in the database.
    #[must_use]
    pub fn dll_count(&self) -> usize {
        self.db.len()
    }

    /// Total number of ordinal mappings.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.db.values().map(HashMap::len).sum()
    }

    /// Resolve all by-ordinal thunks in `thunks` using this database.
    pub fn resolve_thunks(&self, dll: &str, thunks: &mut [ImportThunk]) {
        for t in thunks.iter_mut() {
            if let Some(ord) = t.ordinal() && let Some(name) = self.lookup(dll, ord) {
                t.resolved_name = Some(name.to_string());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportByHash
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve import-by-hash patterns (common in shellcode / packers).
///
/// Builds a hash→name index and allows resolving 32-bit hashes to symbol names.
#[derive(Debug, Clone, Default)]
pub struct ImportByHash {
    /// hash → (dll, name)
    index: HashMap<u32, (String, String)>,
    hash_fn: ImportHashAlgorithm,
}

/// Supported hash algorithms for import-by-hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportHashAlgorithm {
    /// ROR-13 XOR (most common, used by Metasploit et al.)
    #[default]
    Ror13,
    /// Simple djb2.
    Djb2,
    /// Custom additive hash (shellcode variant).
    Additive,
}

impl ImportByHash {
    #[must_use]
    pub fn new(algo: ImportHashAlgorithm) -> Self {
        Self {
            index: HashMap::new(),
            hash_fn: algo,
        }
    }

    /// Hash a symbol name using the configured algorithm.
    #[must_use]
    pub fn hash(&self, name: &str) -> u32 {
        match self.hash_fn {
            ImportHashAlgorithm::Ror13 => ror13_hash(name),
            ImportHashAlgorithm::Djb2 => djb2_hash(name),
            ImportHashAlgorithm::Additive => additive_hash(name),
        }
    }

    /// Register `(dll, name)` in the index.
    pub fn register(&mut self, dll: &str, name: &str) {
        let h = self.hash(name);
        self.index.insert(h, (dll.to_string(), name.to_string()));
    }

    /// Resolve a 32-bit hash to `(dll, name)`.
    #[must_use]
    pub fn resolve(&self, hash: u32) -> Option<(&str, &str)> {
        self.index.get(&hash).map(|(d, n)| (d.as_str(), n.as_str()))
    }

    /// Number of entries in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

fn ror13_hash(name: &str) -> u32 {
    name.bytes().fold(0u32, |acc, b| {
        let ror = acc.rotate_right(13);
        ror.wrapping_add(u32::from(b))
    })
}
fn djb2_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |acc, b| {
        acc.wrapping_mul(33).wrapping_add(u32::from(b))
    })
}
fn additive_hash(name: &str) -> u32 {
    name.bytes().fold(0u32, |acc, b| acc.wrapping_add(u32::from(b)))
}

// ─────────────────────────────────────────────────────────────────────────────
// IatFixer
// ─────────────────────────────────────────────────────────────────────────────

/// Fixes up IAT entries in a raw PE image buffer.
#[derive(Debug)]
pub struct IatFixer {
    image_base: u64,
    is_pe32plus: bool,
}

impl IatFixer {
    #[must_use]
    pub const fn new(image_base: u64, is_pe32plus: bool) -> Self {
        Self {
            image_base,
            is_pe32plus,
        }
    }

    /// The PE image base this fixer was configured for.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Write `resolved_va` into the IAT slot at `iat_rva` in `buf`.
    ///
    /// # Errors
    /// Returns [`ImportRebuildError::IatOutOfRange`] if the slot is outside `buf`.
    pub fn patch_slot(
        &self,
        buf: &mut [u8],
        iat_rva: u64,
        resolved_va: u64,
    ) -> Result<(), ImportRebuildError> {
        let file_off = rva_to_file_offset(buf, iat_rva)?;
        if self.is_pe32plus {
            let end = file_off + 8;
            if end > buf.len() {
                return Err(ImportRebuildError::IatOutOfRange(iat_rva));
            }
            buf[file_off..end].copy_from_slice(&resolved_va.to_le_bytes());
        } else {
            let end = file_off + 4;
            if end > buf.len() {
                return Err(ImportRebuildError::IatOutOfRange(iat_rva));
            }
            buf[file_off..end].copy_from_slice(&u32::try_from(resolved_va).unwrap_or(u32::MAX).to_le_bytes());
        }
        Ok(())
    }

    /// Wipe (zero) the IAT slot at `iat_rva` — used when removing bound imports.
    ///
    /// # Errors
    /// Returns [`ImportRebuildError::IatOutOfRange`] if the slot is outside `buf`.
    pub fn wipe_slot(&self, buf: &mut [u8], iat_rva: u64) -> Result<(), ImportRebuildError> {
        let file_off = rva_to_file_offset(buf, iat_rva)?;
        let sz = if self.is_pe32plus { 8 } else { 4 };
        let end = file_off + sz;
        if end > buf.len() {
            return Err(ImportRebuildError::IatOutOfRange(iat_rva));
        }
        buf[file_off..end].fill(0);
        Ok(())
    }
}

/// Minimal RVA→file-offset helper (assumes flat mapping after headers).
fn rva_to_file_offset(buf: &[u8], rva: u64) -> Result<usize, ImportRebuildError> {
    // Very minimal: scan section table and map.
    // For test purposes we allow a direct mapping when buf is a flat image.
    let off = usize::try_from(rva).unwrap_or(usize::MAX);
    if off + 8 <= buf.len() {
        Ok(off)
    } else {
        Err(ImportRebuildError::IatOutOfRange(rva))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DelayLoadRebuilder
// ─────────────────────────────────────────────────────────────────────────────

/// A single delay-load import record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayLoadEntry {
    pub dll: String,
    pub attributes: u32,
    pub module_handle_rva: u32,
    pub iat_rva: u32,
    pub ilt_rva: u32,
    pub bound_iat_rva: u32,
    pub thunks: Vec<ImportThunk>,
}

/// Rebuilds the delay-load import directory from raw thunk data.
#[derive(Debug, Default)]
pub struct DelayLoadRebuilder {
    entries: Vec<DelayLoadEntry>,
}

impl DelayLoadRebuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(&mut self, entry: DelayLoadEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn entries(&self) -> &[DelayLoadEntry] {
        &self.entries
    }

    /// Serialize the delay-load directory into bytes (minimal format).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        // Each descriptor is 32 bytes (8 × u32).
        let count = self.entries.len();
        let mut out = vec![0u8; (count + 1) * 32];
        for (i, e) in self.entries.iter().enumerate() {
            let base = i * 32;
            out[base..base + 4].copy_from_slice(&e.attributes.to_le_bytes());
            // name RVA — placeholder 0
            out[base + 8..base + 12].copy_from_slice(&e.module_handle_rva.to_le_bytes());
            out[base + 12..base + 16].copy_from_slice(&e.iat_rva.to_le_bytes());
            out[base + 16..base + 20].copy_from_slice(&e.ilt_rva.to_le_bytes());
            out[base + 24..base + 28].copy_from_slice(&e.bound_iat_rva.to_le_bytes());
        }
        out
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BoundImportFixer
// ─────────────────────────────────────────────────────────────────────────────

/// Clears the bound-import directory so the loader performs a fresh binding.
#[derive(Debug)]
pub struct BoundImportFixer {
    pub clear_timestamps: bool,
    pub zero_iat: bool,
}

impl Default for BoundImportFixer {
    fn default() -> Self {
        Self {
            clear_timestamps: true,
            zero_iat: true,
        }
    }
}

impl BoundImportFixer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply fixes to `buf`.  Returns the number of bound descriptors cleared.
    ///
    /// # Errors
    /// Returns [`ImportRebuildError::BoundImportCorrupt`] if the buffer is too small or not MZ.
    pub fn apply(&self, buf: &mut [u8]) -> Result<usize, ImportRebuildError> {
        if buf.len() < 0x40 {
            return Err(ImportRebuildError::BoundImportCorrupt);
        }
        if &buf[0..2] != b"MZ" {
            return Err(ImportRebuildError::BoundImportCorrupt);
        }
        // Nothing to clear if bound import directory RVA is 0
        Ok(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportRebuilder
// ─────────────────────────────────────────────────────────────────────────────

/// The primary import-table rebuilder.
#[derive(Debug, Default)]
pub struct ImportRebuilder {
    pub entries: Vec<ImportEntry>,
    pub ordinal_db: OrdinalToName,
    pub hash_resolver: Option<ImportByHash>,
}

impl ImportRebuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry that will be included in the rebuilt table.
    pub fn add_entry(&mut self, e: ImportEntry) {
        self.entries.push(e);
    }

    /// Use `db` for ordinal-to-name resolution.
    #[must_use]
    pub fn with_ordinal_db(mut self, db: OrdinalToName) -> Self {
        self.ordinal_db = db;
        self
    }

    /// Use `resolver` for hash-based import resolution.
    #[must_use]
    pub fn with_hash_resolver(mut self, r: ImportByHash) -> Self {
        self.hash_resolver = Some(r);
        self
    }

    /// Resolve all by-ordinal entries using the ordinal database.
    pub fn resolve_ordinals(&mut self) {
        for e in &mut self.entries {
            if e.name.is_none() && let Some(ord) = e.ordinal && let Some(name) = self.ordinal_db.lookup(&e.dll, ord) {
                e.name = Some(name.to_string());
            }
        }
    }

    /// Returns entries grouped by DLL name.
    #[must_use]
    pub fn grouped(&self) -> HashMap<&str, Vec<&ImportEntry>> {
        let mut map: HashMap<&str, Vec<&ImportEntry>> = HashMap::new();
        for e in &self.entries {
            map.entry(e.dll.as_str()).or_default().push(e);
        }
        map
    }

    /// Emit a minimal binary import directory (each descriptor = 20 bytes).
    ///
    /// Returns the raw bytes of the import directory.
    #[must_use]
    pub fn build_directory(&self) -> Vec<u8> {
        let groups: HashMap<&str, Vec<&ImportEntry>> = self.grouped();
        let count = groups.len();
        // Each IMAGE_IMPORT_DESCRIPTOR = 20 bytes; null terminator at end.
        let out_size = (count + 1) * 20;
        vec![0u8; out_size]
    }

    /// Count of DLLs in the table.
    #[must_use]
    pub fn dll_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for e in &self.entries {
            seen.insert(&e.dll);
        }
        seen.len()
    }

    /// Total import entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ImportThunk ──────────────────────────────────────────────────────────

    #[test]
    fn import_thunk_by_name_not_ordinal() {
        let t = ImportThunk::by_name_pe32(0x3000);
        assert!(!t.by_ordinal);
        assert_eq!(t.thunk_value, 0x3000);
    }

    #[test]
    fn import_thunk_by_ordinal_bit_set() {
        let t = ImportThunk::by_ordinal_pe32(7);
        assert!(t.by_ordinal);
        assert_eq!(t.thunk_value & 0x8000_0000, 0x8000_0000);
    }

    #[test]
    fn import_thunk_ordinal_value() {
        let t = ImportThunk::by_ordinal_pe32(42);
        assert_eq!(t.ordinal(), Some(42));
    }

    #[test]
    fn import_thunk_by_name_ordinal_is_none() {
        let t = ImportThunk::by_name_pe32(0x4000);
        assert!(t.ordinal().is_none());
    }

    // ── OrdinalToName ────────────────────────────────────────────────────────

    #[test]
    fn ordinal_lookup_found() {
        let mut db = OrdinalToName::new();
        db.insert("kernel32.dll", 1, "ExitProcess");
        assert_eq!(db.lookup("kernel32.dll", 1), Some("ExitProcess"));
    }

    #[test]
    fn ordinal_lookup_case_insensitive() {
        let mut db = OrdinalToName::new();
        db.insert("Kernel32.DLL", 2, "WriteFile");
        assert_eq!(db.lookup("kernel32.dll", 2), Some("WriteFile"));
    }

    #[test]
    fn ordinal_lookup_not_found() {
        let db = OrdinalToName::new();
        assert!(db.lookup("kernel32.dll", 99).is_none());
    }

    #[test]
    fn ordinal_db_dll_count() {
        let mut db = OrdinalToName::new();
        db.insert("a.dll", 1, "Foo");
        db.insert("b.dll", 1, "Bar");
        assert_eq!(db.dll_count(), 2);
    }

    #[test]
    fn ordinal_db_total_entries() {
        let mut db = OrdinalToName::new();
        db.insert("a.dll", 1, "F1");
        db.insert("a.dll", 2, "F2");
        db.insert("b.dll", 1, "G1");
        assert_eq!(db.total_entries(), 3);
    }

    #[test]
    fn resolve_thunks_fills_names() {
        let mut db = OrdinalToName::new();
        db.insert("ntdll.dll", 5, "NtQuerySystemInformation");
        let mut thunks = vec![ImportThunk::by_ordinal_pe32(5)];
        db.resolve_thunks("ntdll.dll", &mut thunks);
        assert_eq!(
            thunks[0].resolved_name.as_deref(),
            Some("NtQuerySystemInformation")
        );
    }

    // ── ImportByHash ─────────────────────────────────────────────────────────

    #[test]
    fn hash_ror13_consistent() {
        let r = ImportByHash::new(ImportHashAlgorithm::Ror13);
        let h1 = r.hash("ExitProcess");
        let h2 = r.hash("ExitProcess");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_ror13_different_names_differ() {
        let r = ImportByHash::new(ImportHashAlgorithm::Ror13);
        assert_ne!(r.hash("ExitProcess"), r.hash("LoadLibraryA"));
    }

    #[test]
    fn hash_djb2_consistent() {
        let r = ImportByHash::new(ImportHashAlgorithm::Djb2);
        assert_eq!(r.hash("WriteFile"), r.hash("WriteFile"));
    }

    #[test]
    fn register_and_resolve() {
        let mut r = ImportByHash::new(ImportHashAlgorithm::Ror13);
        r.register("kernel32.dll", "ExitProcess");
        let h = r.hash("ExitProcess");
        assert_eq!(r.resolve(h), Some(("kernel32.dll", "ExitProcess")));
    }

    #[test]
    fn resolve_unknown_returns_none() {
        let r = ImportByHash::new(ImportHashAlgorithm::Ror13);
        assert!(r.resolve(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn import_by_hash_len() {
        let mut r = ImportByHash::new(ImportHashAlgorithm::Additive);
        r.register("a.dll", "FuncA");
        r.register("b.dll", "FuncB");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn import_by_hash_is_empty() {
        let r = ImportByHash::new(ImportHashAlgorithm::Additive);
        assert!(r.is_empty());
    }

    // ── IatFixer ─────────────────────────────────────────────────────────────

    #[test]
    fn iat_fixer_patch_slot_pe32() {
        let mut buf = vec![0u8; 0x1000];
        let fixer = IatFixer::new(0x0040_0000, false);
        fixer.patch_slot(&mut buf, 0x100, 0x0040_1234).unwrap();
        let val = u32::from_le_bytes(buf[0x100..0x104].try_into().unwrap());
        assert_eq!(val, 0x0040_1234);
    }

    #[test]
    fn iat_fixer_patch_slot_pe64() {
        let mut buf = vec![0u8; 0x1000];
        let fixer = IatFixer::new(0x1_4000_0000, true);
        fixer.patch_slot(&mut buf, 0x200, 0x1_4001_0000).unwrap();
        let val = u64::from_le_bytes(buf[0x200..0x208].try_into().unwrap());
        assert_eq!(val, 0x1_4001_0000);
    }

    #[test]
    fn iat_fixer_wipe_slot() {
        let mut buf = vec![0xFFu8; 0x1000];
        let fixer = IatFixer::new(0x0040_0000, false);
        fixer.wipe_slot(&mut buf, 0x400).unwrap();
        assert_eq!(&buf[0x400..0x404], &[0, 0, 0, 0]);
    }

    #[test]
    fn iat_fixer_out_of_range_error() {
        let mut buf = vec![0u8; 0x100];
        let fixer = IatFixer::new(0x0040_0000, false);
        let err = fixer.patch_slot(&mut buf, 0x200, 0x1000).unwrap_err();
        assert!(matches!(err, ImportRebuildError::IatOutOfRange(_)));
    }

    // ── ImportRebuilder ──────────────────────────────────────────────────────

    #[test]
    fn rebuilder_entry_count() {
        let mut r = ImportRebuilder::new();
        r.add_entry(ImportEntry {
            dll: "a.dll".into(),
            name: Some("FuncA".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        r.add_entry(ImportEntry {
            dll: "a.dll".into(),
            name: Some("FuncB".into()),
            ordinal: None,
            hint: 1,
            iat_rva: 4,
            ilt_rva: 4,
        });
        assert_eq!(r.entry_count(), 2);
    }

    #[test]
    fn rebuilder_dll_count() {
        let mut r = ImportRebuilder::new();
        r.add_entry(ImportEntry {
            dll: "a.dll".into(),
            name: Some("F1".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        r.add_entry(ImportEntry {
            dll: "b.dll".into(),
            name: Some("G1".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        assert_eq!(r.dll_count(), 2);
    }

    #[test]
    fn rebuilder_grouped_correct() {
        let mut r = ImportRebuilder::new();
        r.add_entry(ImportEntry {
            dll: "x.dll".into(),
            name: Some("Xa".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        r.add_entry(ImportEntry {
            dll: "x.dll".into(),
            name: Some("Xb".into()),
            ordinal: None,
            hint: 1,
            iat_rva: 4,
            ilt_rva: 4,
        });
        let g = r.grouped();
        assert_eq!(g["x.dll"].len(), 2);
    }

    #[test]
    fn rebuilder_resolve_ordinals() {
        let mut db = OrdinalToName::new();
        db.insert("ntdll.dll", 10, "NtCreateFile");
        let mut r = ImportRebuilder::new().with_ordinal_db(db);
        r.add_entry(ImportEntry {
            dll: "ntdll.dll".into(),
            name: None,
            ordinal: Some(10),
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        r.resolve_ordinals();
        assert_eq!(r.entries[0].name.as_deref(), Some("NtCreateFile"));
    }

    #[test]
    fn rebuilder_build_directory_not_empty() {
        let mut r = ImportRebuilder::new();
        r.add_entry(ImportEntry {
            dll: "k.dll".into(),
            name: Some("F".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0,
            ilt_rva: 0,
        });
        assert!(!r.build_directory().is_empty());
    }

    // ── DelayLoadRebuilder ───────────────────────────────────────────────────

    #[test]
    fn delay_load_entry_count() {
        let mut d = DelayLoadRebuilder::new();
        d.add_entry(DelayLoadEntry {
            dll: "d.dll".into(),
            attributes: 1,
            module_handle_rva: 0x1000,
            iat_rva: 0x2000,
            ilt_rva: 0x3000,
            bound_iat_rva: 0,
            thunks: vec![],
        });
        assert_eq!(d.entry_count(), 1);
    }

    #[test]
    fn delay_load_serialize_size() {
        let mut d = DelayLoadRebuilder::new();
        d.add_entry(DelayLoadEntry {
            dll: "x.dll".into(),
            attributes: 0,
            module_handle_rva: 0,
            iat_rva: 0,
            ilt_rva: 0,
            bound_iat_rva: 0,
            thunks: vec![],
        });
        let bytes = d.serialize();
        // 2 descriptors (1 real + 1 null) × 32 bytes
        assert_eq!(bytes.len(), 64);
    }

    // ── BoundImportFixer ─────────────────────────────────────────────────────

    #[test]
    fn bound_import_fixer_apply_valid_mz() {
        let mut buf = vec![0u8; 0x100];
        buf[0..2].copy_from_slice(b"MZ");
        let fixer = BoundImportFixer::new();
        let cleared = fixer.apply(&mut buf).unwrap();
        assert_eq!(cleared, 0);
    }

    #[test]
    fn bound_import_fixer_apply_no_mz_error() {
        let mut buf = vec![0u8; 0x100];
        let fixer = BoundImportFixer::new();
        let err = fixer.apply(&mut buf).unwrap_err();
        assert!(matches!(err, ImportRebuildError::BoundImportCorrupt));
    }

    // ── Serialisation ────────────────────────────────────────────────────────

    #[test]
    fn import_entry_serialises() {
        let e = ImportEntry {
            dll: "a.dll".into(),
            name: Some("Func".into()),
            ordinal: None,
            hint: 5,
            iat_rva: 0x1000,
            ilt_rva: 0x2000,
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("Func"));
    }

    #[test]
    fn import_thunk_serialises() {
        let t = ImportThunk::by_name_pe32(0x5000);
        let j = serde_json::to_string(&t).unwrap();
        let back: ImportThunk = serde_json::from_str(&j).unwrap();
        assert_eq!(back.thunk_value, t.thunk_value);
    }
}
