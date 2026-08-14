//! Template library for the hex-template crate.
//!
//! Provides [`TemplateLibrary`] as the top-level store for binary-format
//! templates, [`TemplateEntry`] as a single template record,
//! [`TemplateCategory`] as a coarse classification, [`TemplateSearch`] for
//! multi-field query matching, and [`TemplateExport`] for serialising the
//! library to JSON / TOML.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the template-library module.
#[derive(Debug, Error)]
pub enum LibraryError {
    #[error("template id {0:?} already exists")]
    DuplicateId(String),
    #[error("template id {0:?} not found")]
    NotFound(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("import error: {0}")]
    Import(String),
    #[error("empty id")]
    EmptyId,
    #[error("empty name")]
    EmptyName,
}

pub type LibraryResult<T> = Result<T, LibraryError>;

// ---------------------------------------------------------------------------
// TemplateCategory
// ---------------------------------------------------------------------------

/// Coarse classification of binary-format templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemplateCategory {
    /// Executable formats: ELF, PE, Mach-O, …
    Executable,
    /// Archive / container formats: ZIP, RAR, 7z, tar, …
    Archive,
    /// Image formats: PNG, JPEG, BMP, GIF, TIFF, …
    Image,
    /// Document formats: PDF, DOCX, XLSX, ODF, …
    Document,
    /// Cryptographic artifacts: X.509 certificates, PEM, PKCS, …
    Crypto,
    /// Network packet / protocol captures: PCAP, DNS, TLS, …
    Network,
    /// Firmware / BIOS / UEFI images.
    Firmware,
    /// Database files: SQLite, LevelDB, …
    Database,
    /// Font files: TTF, OTF, WOFF, …
    Font,
    /// User-defined / miscellaneous.
    Custom,
}

impl fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Executable => "Executable",
            Self::Archive => "Archive",
            Self::Image => "Image",
            Self::Document => "Document",
            Self::Crypto => "Crypto",
            Self::Network => "Network",
            Self::Firmware => "Firmware",
            Self::Database => "Database",
            Self::Font => "Font",
            Self::Custom => "Custom",
        };
        write!(f, "{}", s)
    }
}

impl TemplateCategory {
    /// Return all category variants in definition order.
    pub fn all() -> &'static [TemplateCategory] {
        use TemplateCategory::*;
        &[
            Executable, Archive, Image, Document, Crypto, Network, Firmware, Database, Font,
            Custom,
        ]
    }
}

// ---------------------------------------------------------------------------
// TemplateEntry
// ---------------------------------------------------------------------------

/// A single binary-format template stored in the library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEntry {
    /// Unique machine-readable identifier, e.g. `"pe32"`.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// Coarse category.
    pub category: TemplateCategory,
    /// Template body in the ImHex pattern language (or custom DSL).
    pub body: String,
    /// File extensions this template is designed for (lower-case, no dot).
    pub extensions: Vec<String>,
    /// Magic bytes / signatures for auto-detection (each entry is a hex string).
    pub magic: Vec<String>,
    /// Semantic version string.
    pub version: String,
    /// Author name or handle.
    pub author: String,
    /// Tags for freeform search (lower-case).
    pub tags: Vec<String>,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last-modified timestamp (Unix seconds).
    pub updated_at: u64,
}

impl TemplateEntry {
    /// Create a minimal entry with required fields.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: TemplateCategory,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category,
            body: String::new(),
            extensions: Vec::new(),
            magic: Vec::new(),
            version: "0.1.0".into(),
            author: String::new(),
            tags: Vec::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    /// Builder: set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set the body.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Builder: set file extensions (comma-separated or individual calls).
    pub fn with_extensions(mut self, exts: &[&str]) -> Self {
        self.extensions = exts.iter().map(|s| s.to_lowercase()).collect();
        self
    }

    /// Builder: set magic signatures.
    pub fn with_magic(mut self, magic: &[&str]) -> Self {
        self.magic = magic.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Builder: set tags.
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|s| s.to_lowercase()).collect();
        self
    }

    /// Builder: set author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Builder: set version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// True when `self.body` is non-empty.
    #[must_use]
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// True when any magic signature matches the beginning of `data`.
    #[must_use]
    pub fn matches_magic(&self, data: &[u8]) -> bool {
        for hex_sig in &self.magic {
            if let Ok(sig_bytes) = parse_hex(hex_sig) {
                if data.starts_with(&sig_bytes) {
                    return true;
                }
            }
        }
        false
    }
}

impl fmt::Display for TemplateEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({})", self.category, self.name, self.id)
    }
}

// ---------------------------------------------------------------------------
// TemplateSearch
// ---------------------------------------------------------------------------

/// Multi-field query for filtering templates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateSearch {
    /// Free-text substring matched against `name`, `description`, and `tags`.
    pub text: Option<String>,
    /// Filter by category.
    pub category: Option<TemplateCategory>,
    /// Filter by extension (lower-case, no dot).
    pub extension: Option<String>,
    /// Filter by author substring.
    pub author: Option<String>,
    /// Only include entries with at least one magic signature.
    pub has_magic: Option<bool>,
    /// Only include entries with a non-empty body.
    pub has_body: Option<bool>,
}

impl TemplateSearch {
    /// Create an empty (match-all) search.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the free-text filter.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into().to_lowercase());
        self
    }

    /// Set the category filter.
    pub fn with_category(mut self, cat: TemplateCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Set the extension filter.
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extension = Some(ext.into().to_lowercase());
        self
    }

    /// Test whether a `TemplateEntry` matches this query.
    #[must_use]
    pub fn matches(&self, entry: &TemplateEntry) -> bool {
        if let Some(cat) = self.category {
            if entry.category != cat {
                return false;
            }
        }
        if let Some(ref ext) = self.extension {
            if !entry.extensions.iter().any(|e| e == ext) {
                return false;
            }
        }
        if let Some(ref author) = self.author {
            if !entry.author.to_lowercase().contains(&author.to_lowercase()) {
                return false;
            }
        }
        if let Some(hm) = self.has_magic {
            if hm != !entry.magic.is_empty() {
                return false;
            }
        }
        if let Some(hb) = self.has_body {
            if hb != entry.has_body() {
                return false;
            }
        }
        if let Some(ref text) = self.text {
            let lo_name = entry.name.to_lowercase();
            let lo_desc = entry.description.to_lowercase();
            let lo_author = entry.author.to_lowercase();
            let lo_id = entry.id.to_lowercase();
            let tag_hit = entry.tags.iter().any(|t| t.to_lowercase().contains(text.as_str()));
            if !lo_name.contains(text.as_str())
                && !lo_desc.contains(text.as_str())
                && !lo_author.contains(text.as_str())
                && !lo_id.contains(text.as_str())
                && !tag_hit
            {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// TemplateExport
// ---------------------------------------------------------------------------

/// Export format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    JsonPretty,
}

impl Default for ExportFormat {
    fn default() -> Self {
        Self::JsonPretty
    }
}

/// Exporter that serialises a template library to a byte buffer.
#[derive(Debug, Clone, Default)]
pub struct TemplateExport {
    pub format: ExportFormat,
}

impl TemplateExport {
    /// Create an exporter with the given format.
    #[must_use]
    pub fn new(format: ExportFormat) -> Self {
        Self { format }
    }

    /// Serialise `library` to a UTF-8 byte vector.
    pub fn export(&self, library: &TemplateLibrary) -> LibraryResult<Vec<u8>> {
        let entries: Vec<&TemplateEntry> = library.iter().collect();
        match self.format {
            ExportFormat::Json => serde_json::to_vec(&entries)
                .map_err(|e| LibraryError::Export(e.to_string())),
            ExportFormat::JsonPretty => serde_json::to_vec_pretty(&entries)
                .map_err(|e| LibraryError::Export(e.to_string())),
        }
    }

    /// Deserialise a library from a JSON byte slice.
    pub fn import(&self, data: &[u8]) -> LibraryResult<Vec<TemplateEntry>> {
        serde_json::from_slice(data).map_err(|e| LibraryError::Import(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// TemplateLibrary
// ---------------------------------------------------------------------------

/// The main template store.
///
/// Templates are stored in insertion order and indexed by `id` for O(1)
/// lookup. The library supports CRUD operations, multi-field search, and
/// bulk import/export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateLibrary {
    /// Ordered list of template entries.
    entries: Vec<TemplateEntry>,
    /// `id` → index in `entries`.
    index: HashMap<String, usize>,
}

impl TemplateLibrary {
    /// Create an empty library.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    /// Insert a new template. Returns an error if the id already exists.
    pub fn insert(&mut self, entry: TemplateEntry) -> LibraryResult<()> {
        if entry.id.is_empty() {
            return Err(LibraryError::EmptyId);
        }
        if entry.name.is_empty() {
            return Err(LibraryError::EmptyName);
        }
        if self.index.contains_key(&entry.id) {
            return Err(LibraryError::DuplicateId(entry.id));
        }
        let idx = self.entries.len();
        self.index.insert(entry.id.clone(), idx);
        self.entries.push(entry);
        Ok(())
    }

    /// Update an existing entry in-place. Returns an error if not found.
    pub fn update(&mut self, entry: TemplateEntry) -> LibraryResult<()> {
        let idx = *self
            .index
            .get(&entry.id)
            .ok_or_else(|| LibraryError::NotFound(entry.id.clone()))?;
        self.entries[idx] = entry;
        Ok(())
    }

    /// Insert or update.
    pub fn upsert(&mut self, entry: TemplateEntry) -> LibraryResult<()> {
        if self.index.contains_key(&entry.id) {
            self.update(entry)
        } else {
            self.insert(entry)
        }
    }

    /// Remove a template by id.
    pub fn remove(&mut self, id: &str) -> LibraryResult<TemplateEntry> {
        let idx = *self
            .index
            .get(id)
            .ok_or_else(|| LibraryError::NotFound(id.to_string()))?;
        self.index.remove(id);
        let removed = self.entries.remove(idx);
        // Re-build the index after removal.
        for (i, e) in self.entries.iter().enumerate() {
            self.index.insert(e.id.clone(), i);
        }
        Ok(removed)
    }

    /// Look up a template by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&TemplateEntry> {
        self.index.get(id).map(|&i| &self.entries[i])
    }

    /// Mutable look-up.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut TemplateEntry> {
        if let Some(&i) = self.index.get(id) {
            Some(&mut self.entries[i])
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Query / iteration
    // -----------------------------------------------------------------------

    /// Iterator over all entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &TemplateEntry> {
        self.entries.iter()
    }

    /// Number of stored templates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Search the library with a [`TemplateSearch`] query.
    #[must_use]
    pub fn search(&self, query: &TemplateSearch) -> Vec<&TemplateEntry> {
        self.entries
            .iter()
            .filter(|e| query.matches(e))
            .collect()
    }

    /// Return all entries in a category.
    #[must_use]
    pub fn by_category(&self, cat: TemplateCategory) -> Vec<&TemplateEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == cat)
            .collect()
    }

    /// Return the template (if any) whose magic signature matches `data`.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Option<&TemplateEntry> {
        self.entries.iter().find(|e| e.matches_magic(data))
    }

    // -----------------------------------------------------------------------
    // Import / Export
    // -----------------------------------------------------------------------

    /// Bulk-import a list of entries (upsert semantics).
    pub fn import_entries(&mut self, entries: Vec<TemplateEntry>) -> LibraryResult<usize> {
        let mut count = 0;
        for e in entries {
            self.upsert(e)?;
            count += 1;
        }
        Ok(count)
    }

    /// Export the full library using the given exporter.
    pub fn export(&self, exporter: &TemplateExport) -> LibraryResult<Vec<u8>> {
        exporter.export(self)
    }

    /// Round-trip: export then re-import into a fresh library.
    pub fn round_trip(&self, exporter: &TemplateExport) -> LibraryResult<TemplateLibrary> {
        let bytes = self.export(exporter)?;
        let entries = exporter.import(&bytes)?;
        let mut lib = TemplateLibrary::new();
        lib.import_entries(entries)?;
        Ok(lib)
    }

    /// Count entries per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            *counts.entry(e.category.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_hex(s: &str) -> Result<Vec<u8>, ()> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(());
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).map_err(|_| ()))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_entry() -> TemplateEntry {
        TemplateEntry::new("pe32", "PE32", TemplateCategory::Executable)
            .with_description("32-bit Portable Executable")
            .with_extensions(&["exe", "dll", "sys"])
            .with_magic(&["4D5A"])
            .with_tags(&["windows", "pe", "executable"])
            .with_author("rustre")
            .with_version("1.0.0")
            .with_body("// PE32 template body")
    }

    fn elf_entry() -> TemplateEntry {
        TemplateEntry::new("elf64", "ELF64", TemplateCategory::Executable)
            .with_magic(&["7F454C46"])
            .with_extensions(&["elf", "so", "ko"])
    }

    fn png_entry() -> TemplateEntry {
        TemplateEntry::new("png", "PNG", TemplateCategory::Image)
            .with_magic(&["89504E47"])
            .with_extensions(&["png"])
    }

    fn zip_entry() -> TemplateEntry {
        TemplateEntry::new("zip", "ZIP", TemplateCategory::Archive)
            .with_magic(&["504B0304"])
            .with_extensions(&["zip"])
    }

    fn populated_library() -> TemplateLibrary {
        let mut lib = TemplateLibrary::new();
        lib.insert(pe_entry()).unwrap();
        lib.insert(elf_entry()).unwrap();
        lib.insert(png_entry()).unwrap();
        lib.insert(zip_entry()).unwrap();
        lib
    }

    // --- TemplateCategory ---

    #[test]
    fn test_category_display() {
        assert_eq!(TemplateCategory::Executable.to_string(), "Executable");
        assert_eq!(TemplateCategory::Archive.to_string(), "Archive");
        assert_eq!(TemplateCategory::Image.to_string(), "Image");
        assert_eq!(TemplateCategory::Document.to_string(), "Document");
        assert_eq!(TemplateCategory::Crypto.to_string(), "Crypto");
    }

    #[test]
    fn test_category_all() {
        let all = TemplateCategory::all();
        assert!(all.len() >= 5);
        assert!(all.contains(&TemplateCategory::Executable));
    }

    // --- TemplateEntry ---

    #[test]
    fn test_entry_basic_fields() {
        let e = pe_entry();
        assert_eq!(e.id, "pe32");
        assert_eq!(e.name, "PE32");
        assert_eq!(e.category, TemplateCategory::Executable);
    }

    #[test]
    fn test_entry_has_body() {
        let e = pe_entry();
        assert!(e.has_body());
    }

    #[test]
    fn test_entry_no_body() {
        let e = TemplateEntry::new("x", "X", TemplateCategory::Custom);
        assert!(!e.has_body());
    }

    #[test]
    fn test_entry_matches_magic_pe() {
        let e = pe_entry();
        assert!(e.matches_magic(b"MZ\x00\x00"));
        assert!(!e.matches_magic(b"\x7FELF"));
    }

    #[test]
    fn test_entry_matches_magic_elf() {
        let e = elf_entry();
        assert!(e.matches_magic(b"\x7FELF\x02\x01\x01"));
    }

    #[test]
    fn test_entry_display() {
        let s = pe_entry().to_string();
        assert!(s.contains("PE32"));
        assert!(s.contains("pe32"));
    }

    #[test]
    fn test_entry_extensions_lowercase() {
        let e = TemplateEntry::new("x", "X", TemplateCategory::Custom)
            .with_extensions(&["EXE", "DLL"]);
        assert!(e.extensions.contains(&"exe".to_string()));
        assert!(e.extensions.contains(&"dll".to_string()));
    }

    // --- TemplateSearch ---

    #[test]
    fn test_search_match_all() {
        let lib = populated_library();
        let q = TemplateSearch::new();
        assert_eq!(lib.search(&q).len(), 4);
    }

    #[test]
    fn test_search_by_category() {
        let lib = populated_library();
        let q = TemplateSearch::new().with_category(TemplateCategory::Executable);
        let results = lib.search(&q);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_by_extension() {
        let lib = populated_library();
        let q = TemplateSearch::new().with_extension("png");
        let results = lib.search(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "png");
    }

    #[test]
    fn test_search_by_text_name() {
        let lib = populated_library();
        let q = TemplateSearch::new().with_text("PE");
        let results = lib.search(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "pe32");
    }

    #[test]
    fn test_search_has_magic() {
        let mut lib = TemplateLibrary::new();
        lib.insert(pe_entry()).unwrap();
        lib.insert(TemplateEntry::new("nomag", "NoMagic", TemplateCategory::Custom)).unwrap();
        let q = TemplateSearch::new();
        // has_magic = false: should match entries WITHOUT magic
        let q2 = TemplateSearch { has_magic: Some(false), ..q.clone() };
        let r = lib.search(&q2);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "nomag");
    }

    #[test]
    fn test_search_by_author() {
        let lib = populated_library();
        let q = TemplateSearch::new().with_text("rustre");
        let results = lib.search(&q);
        // "rustre" is in tags of pe_entry
        assert!(results.iter().any(|e| e.id == "pe32"));
    }

    // --- TemplateLibrary CRUD ---

    #[test]
    fn test_insert_and_get() {
        let mut lib = TemplateLibrary::new();
        lib.insert(pe_entry()).unwrap();
        let e = lib.get("pe32").unwrap();
        assert_eq!(e.name, "PE32");
    }

    #[test]
    fn test_insert_duplicate_error() {
        let mut lib = TemplateLibrary::new();
        lib.insert(pe_entry()).unwrap();
        assert!(matches!(
            lib.insert(pe_entry()),
            Err(LibraryError::DuplicateId(_))
        ));
    }

    #[test]
    fn test_insert_empty_id_error() {
        let mut lib = TemplateLibrary::new();
        let e = TemplateEntry::new("", "X", TemplateCategory::Custom);
        assert!(matches!(lib.insert(e), Err(LibraryError::EmptyId)));
    }

    #[test]
    fn test_insert_empty_name_error() {
        let mut lib = TemplateLibrary::new();
        let e = TemplateEntry::new("x", "", TemplateCategory::Custom);
        assert!(matches!(lib.insert(e), Err(LibraryError::EmptyName)));
    }

    #[test]
    fn test_remove() {
        let mut lib = populated_library();
        let removed = lib.remove("pe32").unwrap();
        assert_eq!(removed.id, "pe32");
        assert!(lib.get("pe32").is_none());
        assert_eq!(lib.len(), 3);
    }

    #[test]
    fn test_remove_missing() {
        let mut lib = TemplateLibrary::new();
        assert!(matches!(lib.remove("x"), Err(LibraryError::NotFound(_))));
    }

    #[test]
    fn test_update() {
        let mut lib = populated_library();
        let mut e = lib.get("pe32").unwrap().clone();
        e.author = "test_author".into();
        lib.update(e).unwrap();
        assert_eq!(lib.get("pe32").unwrap().author, "test_author");
    }

    #[test]
    fn test_upsert_insert() {
        let mut lib = TemplateLibrary::new();
        lib.upsert(pe_entry()).unwrap();
        assert_eq!(lib.len(), 1);
    }

    #[test]
    fn test_upsert_update() {
        let mut lib = TemplateLibrary::new();
        lib.insert(pe_entry()).unwrap();
        let mut e2 = pe_entry();
        e2.author = "updated".into();
        lib.upsert(e2).unwrap();
        assert_eq!(lib.get("pe32").unwrap().author, "updated");
        assert_eq!(lib.len(), 1);
    }

    #[test]
    fn test_by_category() {
        let lib = populated_library();
        let execs = lib.by_category(TemplateCategory::Executable);
        assert_eq!(execs.len(), 2);
    }

    #[test]
    fn test_detect_pe() {
        let lib = populated_library();
        let entry = lib.detect(b"MZ\x00\x00");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().id, "pe32");
    }

    #[test]
    fn test_detect_unknown() {
        let lib = populated_library();
        assert!(lib.detect(b"\xDE\xAD\xBE\xEF").is_none());
    }

    #[test]
    fn test_category_counts() {
        let lib = populated_library();
        let counts = lib.category_counts();
        assert_eq!(counts["Executable"], 2);
        assert_eq!(counts["Image"], 1);
        assert_eq!(counts["Archive"], 1);
    }

    // --- TemplateExport ---

    #[test]
    fn test_export_json_pretty() {
        let lib = populated_library();
        let exp = TemplateExport::new(ExportFormat::JsonPretty);
        let bytes = lib.export(&exp).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("pe32"));
    }

    #[test]
    fn test_export_json_compact() {
        let lib = populated_library();
        let exp = TemplateExport::new(ExportFormat::Json);
        let bytes = lib.export(&exp).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("pe32"));
        // Compact JSON should not have indented newlines
        assert!(!s.contains("    "));
    }

    #[test]
    fn test_import_round_trip() {
        let lib = populated_library();
        let exp = TemplateExport::new(ExportFormat::JsonPretty);
        let lib2 = lib.round_trip(&exp).unwrap();
        assert_eq!(lib2.len(), lib.len());
        assert!(lib2.get("pe32").is_some());
    }

    #[test]
    fn test_import_invalid_json_error() {
        let exp = TemplateExport::default();
        let result = exp.import(b"not json at all {{{");
        assert!(matches!(result, Err(LibraryError::Import(_))));
    }
}
