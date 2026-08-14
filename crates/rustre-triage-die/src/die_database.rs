//! DIE signature database: load `.diec` files, index by file type, signature versioning.
//!
//! The `.diec` format (Detect-It-Easy Compiled) is a JSON-based signature bundle.
//! This module handles loading, caching, versioning, and querying of such bundles.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::die_signatures::{DieSignature, FileFormat};

// ---------------------------------------------------------------------------
// DiecEntry — one entry inside a .diec JSON file
// ---------------------------------------------------------------------------

/// A single rule entry as encoded in a `.diec` JSON signature file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiecEntry {
    /// Display name.
    pub name: String,
    /// Tool/compiler/packer category.
    pub category: String,
    /// Version string (optional).
    #[serde(default)]
    pub version: Option<String>,
    /// Base confidence 0-100.
    #[serde(default = "default_confidence")]
    pub confidence: u8,
    /// DIE DSL condition expression.
    pub condition: String,
    /// Target format: "pe", "elf", "macho", or omit for any.
    #[serde(default)]
    pub format: Option<String>,
    /// Signature format version for backward compat.
    #[serde(default = "sig_version_one")]
    pub sig_version: u32,
    /// Author of this signature.
    #[serde(default)]
    pub author: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Tags for search / filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_confidence() -> u8 {
    70
}

fn sig_version_one() -> u32 {
    1
}

impl DiecEntry {
    /// Convert to a [`DieSignature`].
    pub fn to_die_signature(&self) -> DieSignature {
        let mut sig = DieSignature::new(
            self.name.clone(),
            self.category.clone(),
            self.condition.clone(),
            self.confidence,
        );
        sig.version = self.version.clone();
        sig.target_format = self.format.as_deref().and_then(|f| match f {
            "pe" | "PE" => Some(FileFormat::Pe),
            "elf" | "ELF" => Some(FileFormat::Elf),
            "macho" | "MachO" | "MACHO" => Some(FileFormat::MachO),
            _ => None,
        });
        sig
    }
}

// ---------------------------------------------------------------------------
// DiecBundle — a whole .diec file
// ---------------------------------------------------------------------------

/// A parsed `.diec` file with metadata and entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiecBundle {
    /// Bundle name (usually the library name).
    pub name: String,
    /// Bundle version (semver string).
    pub version: String,
    /// Schema version.
    #[serde(default = "schema_version_one")]
    pub schema_version: u32,
    /// File format this bundle targets ("pe", "elf", "macho", "any").
    #[serde(default = "any_format")]
    pub target: String,
    /// Signature entries.
    pub signatures: Vec<DiecEntry>,
    /// Optional description.
    #[serde(default)]
    pub description: String,
    /// Bundle creation timestamp (ISO-8601).
    #[serde(default)]
    pub created: String,
}

fn schema_version_one() -> u32 {
    1
}

fn any_format() -> String {
    "any".to_string()
}

impl DiecBundle {
    /// Number of signatures in this bundle.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Return the target [`FileFormat`] (None means "any").
    pub fn file_format(&self) -> Option<FileFormat> {
        match self.target.as_str() {
            "pe" | "PE" => Some(FileFormat::Pe),
            "elf" | "ELF" => Some(FileFormat::Elf),
            "macho" | "MachO" => Some(FileFormat::MachO),
            _ => None,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl fmt::Display for DiecBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiecBundle {{ name={}, version={}, target={}, sigs={} }}",
            self.name,
            self.version,
            self.target,
            self.signatures.len()
        )
    }
}

// ---------------------------------------------------------------------------
// BundleVersion — version comparison helper
// ---------------------------------------------------------------------------

/// A parsed semantic version with major/minor/patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl BundleVersion {
    /// Parse a version string like `"1.2.3"`.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Format as `"major.minor.patch"`.
    pub fn to_string_repr(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Display for BundleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// DatabaseEntry — indexed bundle record
// ---------------------------------------------------------------------------

/// An indexed record of a loaded bundle inside the database.
#[derive(Debug, Clone)]
pub struct DatabaseEntry {
    /// The bundle itself.
    pub bundle: DiecBundle,
    /// Source file path if loaded from disk.
    pub source_path: Option<PathBuf>,
    /// Time the bundle was loaded.
    pub loaded_at: SystemTime,
    /// Whether the bundle was loaded from disk vs injected programmatically.
    pub from_file: bool,
}

impl DatabaseEntry {
    /// Version of the contained bundle as a [`BundleVersion`].
    pub fn version(&self) -> BundleVersion {
        BundleVersion::parse(&self.bundle.version).unwrap_or(BundleVersion {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// FormatIndex — per-format signature index
// ---------------------------------------------------------------------------

/// Mapping from format tag to list of pre-compiled [`DieSignature`]s.
#[derive(Debug, Default)]
struct FormatIndex {
    pe: Vec<DieSignature>,
    elf: Vec<DieSignature>,
    macho: Vec<DieSignature>,
    any: Vec<DieSignature>,
}

impl FormatIndex {
    fn insert(&mut self, sig: DieSignature) {
        match sig.target_format {
            Some(FileFormat::Pe) => self.pe.push(sig),
            Some(FileFormat::Elf) => self.elf.push(sig),
            Some(FileFormat::MachO) => self.macho.push(sig),
            _ => self.any.push(sig),
        }
    }

    fn for_format(&self, fmt: FileFormat) -> impl Iterator<Item = &DieSignature> {
        let format_specific: &[DieSignature] = match fmt {
            FileFormat::Pe => &self.pe,
            FileFormat::Elf => &self.elf,
            FileFormat::MachO => &self.macho,
            FileFormat::Unknown => &[],
        };
        format_specific.iter().chain(self.any.iter())
    }

    fn total_len(&self) -> usize {
        self.pe.len() + self.elf.len() + self.macho.len() + self.any.len()
    }
}

// ---------------------------------------------------------------------------
// DieDatabase — main database type
// ---------------------------------------------------------------------------

/// DIE signature database.
///
/// Manages multiple [`DiecBundle`]s keyed by bundle name.  Provides fast
/// per-format lookups by maintaining a pre-built [`FormatIndex`].
pub struct DieDatabase {
    /// All loaded bundles, keyed by bundle name.
    bundles: HashMap<String, DatabaseEntry>,
    /// Pre-computed format index (rebuilt after each bundle load).
    index: FormatIndex,
    /// Whether to automatically deduplicate signatures when loading.
    dedup: bool,
    /// Statistics.
    stats: DatabaseStats,
}

/// Running statistics for a [`DieDatabase`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseStats {
    /// Total bundles loaded.
    pub bundles_loaded: usize,
    /// Total signatures across all bundles.
    pub total_signatures: usize,
    /// Number of PE-specific signatures.
    pub pe_signatures: usize,
    /// Number of ELF-specific signatures.
    pub elf_signatures: usize,
    /// Number of Mach-O-specific signatures.
    pub macho_signatures: usize,
    /// Number of format-agnostic signatures.
    pub any_signatures: usize,
    /// Number of times signatures were deduped.
    pub dedup_count: usize,
}

impl DieDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
            index: FormatIndex::default(),
            dedup: true,
            stats: DatabaseStats::default(),
        }
    }

    /// Enable or disable deduplication.
    pub fn set_dedup(&mut self, dedup: bool) {
        self.dedup = dedup;
    }

    /// Load a bundle from a JSON string.
    ///
    /// If a bundle with the same name already exists, the one with the higher
    /// version wins.
    pub fn load_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let bundle = DiecBundle::from_json(json)?;
        let added = bundle.len();
        self.insert_bundle(bundle, None);
        Ok(added)
    }

    /// Load a bundle from a `.diec` file.
    ///
    /// Returns the number of signatures loaded.
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let json = std::fs::read_to_string(path)?;
        let bundle = DiecBundle::from_json(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let added = bundle.len();
        self.insert_bundle(bundle, Some(path.to_path_buf()));
        Ok(added)
    }

    /// Load all `.diec` files from a directory.
    ///
    /// Returns the total number of signatures loaded across all files.
    pub fn load_directory(&mut self, dir: &Path) -> std::io::Result<usize> {
        let mut total = 0;
        if !dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} is not a directory", dir.display()),
            ));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("diec") {
                match self.load_file(&path) {
                    Ok(n) => total += n,
                    Err(e) => {
                        eprintln!("Warning: skipping {:?}: {e}", path.file_name());
                    }
                }
            }
        }
        Ok(total)
    }

    /// Inject a pre-built [`DiecBundle`] programmatically.
    pub fn insert_bundle(&mut self, bundle: DiecBundle, source: Option<PathBuf>) {
        let name = bundle.name.clone();
        let new_ver = BundleVersion::parse(&bundle.version).unwrap_or(BundleVersion {
            major: 0,
            minor: 0,
            patch: 0,
        });

        // Version-gating: only replace if new version ≥ existing version
        if let Some(existing) = self.bundles.get(&name) {
            if existing.version() > new_ver {
                return;
            }
        }

        let entry = DatabaseEntry {
            bundle,
            source_path: source,
            loaded_at: SystemTime::now(),
            from_file: true,
        };
        self.bundles.insert(name, entry);
        self.rebuild_index();
    }

    /// Remove a bundle by name.
    pub fn remove_bundle(&mut self, name: &str) -> bool {
        let removed = self.bundles.remove(name).is_some();
        if removed {
            self.rebuild_index();
        }
        removed
    }

    /// Rebuild the format index from all loaded bundles.
    fn rebuild_index(&mut self) {
        self.index = FormatIndex::default();
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut dedup_count = 0usize;

        for entry in self.bundles.values() {
            for diec_entry in &entry.bundle.signatures {
                let sig = diec_entry.to_die_signature();
                // Deduplication: skip if (name, condition) already seen.
                if self.dedup {
                    let key = format!("{}|{}", sig.name, sig.condition_src);
                    if !seen_keys.insert(key) {
                        dedup_count += 1;
                        continue;
                    }
                }
                self.index.insert(sig);
            }
        }

        self.stats.bundles_loaded = self.bundles.len();
        self.stats.total_signatures = self.index.total_len();
        self.stats.pe_signatures = self.index.pe.len();
        self.stats.elf_signatures = self.index.elf.len();
        self.stats.macho_signatures = self.index.macho.len();
        self.stats.any_signatures = self.index.any.len();
        self.stats.dedup_count = dedup_count;
    }

    /// Return all signatures applicable to `fmt`.
    pub fn signatures_for_format(&self, fmt: FileFormat) -> Vec<&DieSignature> {
        self.index.for_format(fmt).collect()
    }

    /// Return all PE signatures.
    pub fn pe_signatures(&self) -> &[DieSignature] {
        &self.index.pe
    }

    /// Return all ELF signatures.
    pub fn elf_signatures(&self) -> &[DieSignature] {
        &self.index.elf
    }

    /// Return all Mach-O signatures.
    pub fn macho_signatures(&self) -> &[DieSignature] {
        &self.index.macho
    }

    /// Return format-agnostic signatures.
    pub fn any_signatures(&self) -> &[DieSignature] {
        &self.index.any
    }

    /// Search signatures by name substring (case-insensitive).
    pub fn search_by_name(&self, query: &str) -> Vec<&DieSignature> {
        let q = query.to_lowercase();
        self.index
            .pe
            .iter()
            .chain(self.index.elf.iter())
            .chain(self.index.macho.iter())
            .chain(self.index.any.iter())
            .filter(|s| s.name.to_lowercase().contains(&q))
            .collect()
    }

    /// Search signatures by category (case-insensitive).
    pub fn search_by_category(&self, cat: &str) -> Vec<&DieSignature> {
        let c = cat.to_lowercase();
        self.index
            .pe
            .iter()
            .chain(self.index.elf.iter())
            .chain(self.index.macho.iter())
            .chain(self.index.any.iter())
            .filter(|s| s.category.to_lowercase() == c)
            .collect()
    }

    /// Current database statistics.
    pub fn stats(&self) -> &DatabaseStats {
        &self.stats
    }

    /// Names of all loaded bundles.
    pub fn bundle_names(&self) -> Vec<&str> {
        self.bundles.keys().map(String::as_str).collect()
    }

    /// Look up a bundle by name.
    pub fn get_bundle(&self, name: &str) -> Option<&DatabaseEntry> {
        self.bundles.get(name)
    }

    /// Total signature count.
    pub fn total_signature_count(&self) -> usize {
        self.index.total_len()
    }

    /// Export the entire database to a single JSON bundle.
    pub fn export_merged(&self, name: &str, version: &str) -> DiecBundle {
        let signatures: Vec<DiecEntry> = self
            .index
            .pe
            .iter()
            .chain(self.index.elf.iter())
            .chain(self.index.macho.iter())
            .chain(self.index.any.iter())
            .map(|sig| DiecEntry {
                name: sig.name.clone(),
                category: sig.category.clone(),
                version: sig.version.clone(),
                confidence: sig.confidence,
                condition: sig.condition_src.clone(),
                format: sig.target_format.map(|f| format!("{f:?}").to_lowercase()),
                sig_version: 1,
                author: "rustre-triage-die".to_string(),
                description: String::new(),
                tags: Vec::new(),
            })
            .collect();

        DiecBundle {
            name: name.to_string(),
            version: version.to_string(),
            schema_version: 1,
            target: "any".to_string(),
            signatures,
            description: "Merged export from DieDatabase".to_string(),
            created: String::new(),
        }
    }

    /// Load the built-in default signatures into the database.
    pub fn load_defaults(&mut self) {
        let bundle_json = serde_json::json!({
            "name": "rustre-builtins",
            "version": "1.0.0",
            "schema_version": 1,
            "target": "any",
            "description": "Built-in RustRE detection signatures",
            "created": "2024-01-01",
            "signatures": [
                {"name": "UPX 3.x", "category": "Packer", "confidence": 95,
                 "condition": "hasSection(\"UPX0\") && hasSection(\"UPX1\")",
                 "format": "pe", "version": "3.x", "author": "rustre", "description": "UPX packer v3", "tags": ["packer"]},
                {"name": "UPX 4.x", "category": "Packer", "confidence": 97,
                 "condition": "hasSection(\"UPX0\") && hasSection(\"UPX1\") && contains(\"UPX!\")",
                 "format": "pe", "version": "4.x", "author": "rustre", "description": "UPX packer v4", "tags": ["packer"]},
                {"name": "MPRESS", "category": "Packer", "confidence": 90,
                 "condition": "hasSection(\".MPRESS1\")",
                 "format": "pe", "version": "2.x", "author": "rustre", "description": "", "tags": ["packer"]},
                {"name": "ASPack", "category": "Packer", "confidence": 90,
                 "condition": "hasSection(\".aspack\")",
                 "format": "pe", "version": "2.x", "author": "rustre", "description": "", "tags": ["packer"]},
                {"name": "PECompact", "category": "Packer", "confidence": 88,
                 "condition": "contains(\"PECompact2\")",
                 "format": "pe", "version": "2.x", "author": "rustre", "description": "", "tags": ["packer"]},
                {"name": "Themida", "category": "Protector", "confidence": 93,
                 "condition": "hasSection(\".themida\")",
                 "format": "pe", "version": "3.x", "author": "rustre", "description": "", "tags": ["protector"]},
                {"name": "VMProtect", "category": "Protector", "confidence": 92,
                 "condition": "hasSection(\".vmp0\") || hasSection(\".vmp1\")",
                 "format": "pe", "version": "2-3.x", "author": "rustre", "description": "", "tags": ["protector"]},
                {"name": "Enigma Protector", "category": "Protector", "confidence": 88,
                 "condition": "contains(\".enigma1\")",
                 "format": "pe", "version": "7.x", "author": "rustre", "description": "", "tags": ["protector"]},
                {"name": "NSIS", "category": "Installer", "confidence": 85,
                 "condition": "contains(\"Nullsoft\")",
                 "format": "pe", "version": "3.x", "author": "rustre", "description": "", "tags": ["installer"]},
                {"name": "InnoSetup", "category": "Installer", "confidence": 90,
                 "condition": "contains(\"Inno Setup\")",
                 "format": "pe", "version": "6.x", "author": "rustre", "description": "", "tags": ["installer"]},
                {"name": "GCC/MinGW", "category": "Compiler", "confidence": 82,
                 "condition": "contains(\"MinGW\")",
                 "format": "pe", "version": "4+", "author": "rustre", "description": "", "tags": ["compiler"]},
                {"name": "Rust", "category": "Compiler", "confidence": 85,
                 "condition": "contains(\"rustc\")",
                 "format": "pe", "version": "1.x", "author": "rustre", "description": "", "tags": ["compiler"]},
                {"name": "PyInstaller", "category": "Tool", "confidence": 90,
                 "condition": "contains(\"MEI\")",
                 "format": "pe", "version": "6.x", "author": "rustre", "description": "", "tags": ["tool", "python"]},
                {"name": "AutoIt", "category": "Tool", "confidence": 93,
                 "condition": "contains(\"AU3!EA\")",
                 "format": "pe", "version": "3.x", "author": "rustre", "description": "", "tags": ["tool", "autoit"]}
            ]
        });

        if let Ok(json_str) = serde_json::to_string(&bundle_json) {
            let _ = self.load_json(&json_str);
        }
    }

    /// Check if any bundle by `name` exists.
    pub fn has_bundle(&self, name: &str) -> bool {
        self.bundles.contains_key(name)
    }

    /// Clear all bundles.
    pub fn clear(&mut self) {
        self.bundles.clear();
        self.index = FormatIndex::default();
        self.stats = DatabaseStats::default();
    }

    /// Return a sorted list of (category, count) pairs.
    pub fn category_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for sig in self
            .index
            .pe
            .iter()
            .chain(&self.index.elf)
            .chain(&self.index.macho)
            .chain(&self.index.any)
        {
            *counts.entry(sig.category.clone()).or_insert(0) += 1;
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Iterate over all signatures regardless of format.
    pub fn all_signatures(&self) -> impl Iterator<Item = &DieSignature> {
        self.index
            .pe
            .iter()
            .chain(self.index.elf.iter())
            .chain(self.index.macho.iter())
            .chain(self.index.any.iter())
    }
}

impl Default for DieDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DieDatabase")
            .field("bundles", &self.bundles.len())
            .field("total_signatures", &self.index.total_len())
            .field("pe", &self.index.pe.len())
            .field("elf", &self.index.elf.len())
            .field("macho", &self.index.macho.len())
            .field("any", &self.index.any.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DieDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DieDatabase {{ bundles={}, sigs={} }}",
            self.bundles.len(),
            self.index.total_len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_bundle(name: &str, version: &str, format: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "name": name,
            "version": version,
            "schema_version": 1,
            "target": format,
            "description": "test",
            "created": "2024-01-01",
            "signatures": [
                {"name": "TestSig", "category": "Packer", "confidence": 90,
                 "condition": "contains(\"TESTMAGIC\")", "format": format,
                 "version": "1.0", "author": "test", "description": "", "tags": []}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn test_empty_db() {
        let db = DieDatabase::new();
        assert_eq!(db.total_signature_count(), 0);
        assert!(db.bundle_names().is_empty());
    }

    #[test]
    fn test_load_json() {
        let mut db = DieDatabase::new();
        let json = minimal_bundle("test", "1.0.0", "pe");
        let n = db.load_json(&json).unwrap();
        assert_eq!(n, 1);
        assert_eq!(db.total_signature_count(), 1);
    }

    #[test]
    fn test_version_gating() {
        let mut db = DieDatabase::new();
        db.load_json(&minimal_bundle("lib", "2.0.0", "pe")).unwrap();
        // Lower version should be ignored
        db.load_json(&minimal_bundle("lib", "1.0.0", "pe")).unwrap();
        assert_eq!(db.total_signature_count(), 1);
        assert_eq!(
            db.get_bundle("lib").unwrap().bundle.version,
            "2.0.0"
        );
    }

    #[test]
    fn test_load_defaults() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        assert!(db.total_signature_count() > 5);
        assert!(db.has_bundle("rustre-builtins"));
    }

    #[test]
    fn test_search_by_name() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let hits = db.search_by_name("upx");
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|s| s.name.to_lowercase().contains("upx")));
    }

    #[test]
    fn test_search_by_category() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let packers = db.search_by_category("packer");
        assert!(!packers.is_empty());
        assert!(packers.iter().all(|s| s.category == "Packer"));
    }

    #[test]
    fn test_category_counts() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let counts = db.category_counts();
        assert!(!counts.is_empty());
        // Check that all counts are positive
        for (_, c) in &counts {
            assert!(*c > 0);
        }
    }

    #[test]
    fn test_clear() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        assert!(db.total_signature_count() > 0);
        db.clear();
        assert_eq!(db.total_signature_count(), 0);
    }

    #[test]
    fn test_remove_bundle() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let before = db.total_signature_count();
        assert!(before > 0);
        let removed = db.remove_bundle("rustre-builtins");
        assert!(removed);
        assert_eq!(db.total_signature_count(), 0);
    }

    #[test]
    fn test_signatures_for_format_pe() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let sigs = db.signatures_for_format(FileFormat::Pe);
        assert!(!sigs.is_empty());
    }

    #[test]
    fn test_export_merged() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let merged = db.export_merged("merged", "1.0.0");
        assert_eq!(merged.name, "merged");
        assert!(merged.signatures.len() > 0);
    }

    #[test]
    fn test_bundle_version_ordering() {
        let v1 = BundleVersion::parse("1.2.3").unwrap();
        let v2 = BundleVersion::parse("1.2.4").unwrap();
        let v3 = BundleVersion::parse("2.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert_eq!(v1.to_string_repr(), "1.2.3");
    }

    #[test]
    fn test_stats_after_load() {
        let mut db = DieDatabase::new();
        db.load_defaults();
        let stats = db.stats();
        assert_eq!(stats.bundles_loaded, 1);
        assert!(stats.total_signatures > 0);
    }
}
