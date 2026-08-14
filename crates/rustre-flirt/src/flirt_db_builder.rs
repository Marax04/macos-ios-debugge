// flirt_db_builder.rs — Build a FLIRT signature database from library sources

use std::collections::{BTreeMap, HashSet};
// AHashMap is used for maps keyed by attacker-controlled symbol names to prevent
// hash-collision DoS when processing adversarial .pat / library files.
use ahash::AHashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pat_parser_v2::{crc16_ccitt, PatByte, PatternEntry, ModuleRef, ModuleRefKind};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DbBuilderError {
    #[error("library source {name:?} not found at {path}")]
    SourceNotFound { name: String, path: String },
    #[error("function {name:?} is too short to build a pattern ({len} bytes)")]
    FunctionTooShort { name: String, len: usize },
    #[error("duplicate signature for {name:?}")]
    DuplicateSignature { name: String },
    #[error("pattern prefix too long (max {max}, got {got})")]
    PrefixTooLong { max: usize, got: usize },
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Library source ───────────────────────────────────────────────────────────

/// Describes one library (or object file) to extract signatures from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySource {
    /// Display name for the library (e.g. "msvcrt140").
    pub name: String,
    /// Path to the file on disk (optional — may be in-memory).
    pub path: Option<PathBuf>,
    /// Platform/architecture tag (e.g. "x86", "x64", "arm").
    pub arch: String,
    /// Library version string (e.g. "14.0.0").
    pub version: String,
    /// Additional free-form tags.
    pub tags: Vec<String>,
}

impl LibrarySource {
    pub fn new(name: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: None,
            arch: arch.into(),
            version: String::new(),
            tags: vec![],
        }
    }

    #[must_use]
    pub fn with_path(mut self, p: impl AsRef<Path>) -> Self {
        self.path = Some(p.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = v.into();
        self
    }

    #[must_use]
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }
}

// ─── Raw function record ──────────────────────────────────────────────────────

/// A raw function extracted from a library, before signature building.
#[derive(Debug, Clone)]
pub struct RawFunction {
    /// Function name (undecorated).
    pub name: String,
    /// Raw bytes of the function body.
    pub bytes: Vec<u8>,
    /// Relocation offsets within the function body (bytes to mask as wildcard).
    pub reloc_offsets: Vec<usize>,
    /// Source library index.
    pub library_idx: usize,
    /// Offset within the library file.
    pub file_offset: u64,
}

impl RawFunction {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
            reloc_offsets: vec![],
            library_idx: 0,
            file_offset: 0,
        }
    }

    #[must_use] 
    pub fn with_relocs(mut self, relocs: Vec<usize>) -> Self {
        self.reloc_offsets = relocs;
        self
    }
}

// ─── Signature set ────────────────────────────────────────────────────────────

/// A set of built signatures ready for matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSet {
    /// All built pattern entries.
    pub entries: Vec<PatternEntry>,
    /// Trie-like prefix index: first 4 concrete bytes → list of entry indices.
    #[serde(skip)]
    pub prefix_index: BTreeMap<[u8; 4], Vec<usize>>,
    /// Name → entry index (for quick lookup).
    /// Uses ahash to resist hash-collision `DoS` from attacker-controlled symbol names.
    #[serde(skip)]
    pub name_index: AHashMap<String, usize>,
    /// Set metadata.
    pub metadata: SignatureSetMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSetMeta {
    pub source_count: usize,
    pub function_count: usize,
    pub signature_count: usize,
    pub deduplicated_count: usize,
    pub arch: String,
    pub created_at: String,
}

impl SignatureSet {
    #[must_use] 
    pub fn new(metadata: SignatureSetMeta) -> Self {
        Self {
            entries: vec![],
            prefix_index: BTreeMap::new(),
            name_index: AHashMap::new(),
            metadata,
        }
    }

    /// Add an entry and update indices.
    pub fn add(&mut self, entry: PatternEntry) {
        let idx = self.entries.len();
        // Update name index.
        if let Some(name) = entry.primary_name() {
            self.name_index.insert(name.to_string(), idx);
        }
        // Update prefix index.
        let prefix = extract_prefix4(&entry.pattern);
        self.prefix_index.entry(prefix).or_default().push(idx);
        self.entries.push(entry);
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up candidates by the first 4 bytes of a buffer.
    #[must_use] 
    pub fn candidates_for(&self, buf: &[u8]) -> &[usize] {
        if buf.len() < 4 {
            return &[];
        }
        let key: [u8; 4] = [buf[0], buf[1], buf[2], buf[3]];
        self.prefix_index.get(&key).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Rebuild the runtime indices (call after deserialising).
    pub fn rebuild_indices(&mut self) {
        self.prefix_index.clear();
        self.name_index.clear();
        let entries: Vec<PatternEntry> = self.entries.drain(..).collect();
        for entry in entries {
            self.add(entry);
        }
    }
}

fn extract_prefix4(pattern: &[PatByte]) -> [u8; 4] {
    let mut key = [0u8; 4];
    for (i, pb) in pattern.iter().enumerate().take(4) {
        key[i] = match pb {
            PatByte::Exact(v) => *v,
            PatByte::Wild => 0,
        };
    }
    key
}

// ─── Builder configuration ────────────────────────────────────────────────────

/// Configuration for the FLIRT database builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbBuilderConfig {
    /// Number of leading bytes to put in the pattern (up to 32).
    pub pattern_prefix_len: usize,
    /// Number of bytes after the prefix to CRC-check for disambiguation.
    pub crc16_len: u8,
    /// Minimum function length to include (bytes).
    pub min_func_len: usize,
    /// Maximum function length (0 = no limit).
    pub max_func_len: usize,
    /// If true, skip functions whose pattern clashes with an already-added one.
    pub skip_duplicates: bool,
    /// If true, merge identical patterns from different libraries.
    pub merge_identical: bool,
}

impl Default for DbBuilderConfig {
    fn default() -> Self {
        Self {
            pattern_prefix_len: 32,
            crc16_len: 8,
            min_func_len: 4,
            max_func_len: 0,
            skip_duplicates: true,
            merge_identical: true,
        }
    }
}

// ─── FLIRT DB builder ─────────────────────────────────────────────────────────

/// Builds a `SignatureSet` from multiple library sources.
pub struct FlirtDbBuilder {
    config: DbBuilderConfig,
    sources: Vec<LibrarySource>,
    functions: Vec<RawFunction>,
    seen_patterns: HashSet<Vec<PatByte>>,
    /// Uses ahash to resist hash-collision `DoS` from attacker-controlled function names.
    seen_names: AHashMap<String, usize>,
}

impl FlirtDbBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::with_config(DbBuilderConfig::default())
    }

    #[must_use] 
    pub fn with_config(config: DbBuilderConfig) -> Self {
        Self {
            config,
            sources: vec![],
            functions: vec![],
            seen_patterns: HashSet::new(),
            seen_names: AHashMap::new(),
        }
    }

    pub fn add_source(&mut self, source: LibrarySource) -> usize {
        let idx = self.sources.len();
        self.sources.push(source);
        idx
    }

    pub fn add_function(&mut self, mut func: RawFunction, source_idx: usize) {
        func.library_idx = source_idx;
        self.functions.push(func);
    }

    /// Build a pattern entry from a raw function.
    ///
    /// # Errors
    /// Returns [`DbBuilderError::FunctionTooShort`] if the function is shorter than `config.min_func_len`.
    pub fn build_pattern(
        &self,
        func: &RawFunction,
    ) -> Result<PatternEntry, DbBuilderError> {
        let len = func.bytes.len();
        if len < self.config.min_func_len {
            return Err(DbBuilderError::FunctionTooShort {
                name: func.name.clone(),
                len,
            });
        }

        let prefix_len = self.config.pattern_prefix_len.min(len);
        let reloc_set: HashSet<usize> = func.reloc_offsets.iter().copied().collect();

        // Build pattern bytes.
        let pattern: Vec<PatByte> = (0..prefix_len)
            .map(|i| {
                if reloc_set.contains(&i) {
                    PatByte::Wild
                } else {
                    PatByte::Exact(func.bytes[i])
                }
            })
            .collect();

        // CRC-16 over the next `crc16_len` bytes.
        let crc_start = prefix_len;
        let crc_end = (crc_start + self.config.crc16_len as usize).min(len);
        let crc16_len = u8::try_from(crc_end - crc_start).unwrap_or(u8::MAX);
        let crc16 = if crc16_len > 0 {
            crc16_ccitt(&func.bytes[crc_start..crc_end])
        } else {
            0
        };

        let refs = vec![ModuleRef {
            offset: 0,
            kind: ModuleRefKind::Public,
            delta: 0,
            name: func.name.clone(),
            is_primary: true,
        }];

        Ok(PatternEntry {
            pattern,
            crc16_len,
            crc16,
            total_len: u32::try_from(len).unwrap_or(u32::MAX),
            refs,
            source_line: 0,
        })
    }

    /// Finalise and produce a `SignatureSet`.
    ///
    /// # Errors
    /// Returns [`DbBuilderError`] if pattern building fails for any reason other than a too-short function.
    pub fn finish(mut self) -> Result<SignatureSet, DbBuilderError> {
        let arch = self
            .sources
            .first().map_or_else(|| "unknown".to_string(), |s| s.arch.clone());

        let meta = SignatureSetMeta {
            source_count: self.sources.len(),
            function_count: self.functions.len(),
            signature_count: 0,
            deduplicated_count: 0,
            arch,
            created_at: "2026-06-10".to_string(),
        };

        let mut sig_set = SignatureSet::new(meta);
        let mut dedup_count = 0usize;

        let functions = std::mem::take(&mut self.functions);
        for func in &functions {
            let entry = match self.build_pattern(func) {
                Ok(e) => e,
                Err(DbBuilderError::FunctionTooShort { .. }) => continue,
                Err(e) => return Err(e),
            };

            let pat_key = entry.pattern.clone();
            let name = func.name.clone();

            if self.config.skip_duplicates && self.seen_patterns.contains(&pat_key) {
                dedup_count += 1;
                continue;
            }

            if self.config.merge_identical
                && let Some(&existing_idx) = self.seen_names.get(&name) {
                    // Same name, same lib: skip.
                    let _ = existing_idx;
                    dedup_count += 1;
                    continue;
                }

            self.seen_patterns.insert(pat_key);
            self.seen_names.insert(name, sig_set.len());
            sig_set.add(entry);
        }

        sig_set.metadata.signature_count = sig_set.len();
        sig_set.metadata.deduplicated_count = dedup_count;
        Ok(sig_set)
    }
}

impl Default for FlirtDbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Signature merge ──────────────────────────────────────────────────────────

/// Merge multiple `SignatureSet`s into one, deduplicating by pattern.
#[must_use] 
pub fn merge_signature_sets(sets: Vec<SignatureSet>) -> SignatureSet {
    let total_sources: usize = sets.iter().map(|s| s.metadata.source_count).sum();
    let total_funcs: usize = sets.iter().map(|s| s.metadata.function_count).sum();

    let meta = SignatureSetMeta {
        source_count: total_sources,
        function_count: total_funcs,
        signature_count: 0,
        deduplicated_count: 0,
        arch: sets
            .first()
            .map(|s| s.metadata.arch.clone())
            .unwrap_or_default(),
        created_at: "2026-06-10".to_string(),
    };

    let mut out = SignatureSet::new(meta);
    let mut seen: HashSet<Vec<PatByte>> = HashSet::new();
    let mut dedup = 0usize;

    for set in sets {
        for entry in set.entries {
            let key = entry.pattern.clone();
            if seen.insert(key) {
                out.add(entry);
            } else {
                dedup += 1;
            }
        }
    }

    out.metadata.signature_count = out.len();
    out.metadata.deduplicated_count = dedup;
    out
}

// ─── Statistics ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total_entries: usize,
    pub unique_names: usize,
    pub wildcard_entries: usize,
    pub fully_concrete: usize,
    pub avg_concrete_bytes: f64,
    pub crc16_entries: usize,
}

impl DbStats {
    #[must_use] 
    pub fn from(set: &SignatureSet) -> Self {
        let total_entries = set.len();
        let unique_names = set.name_index.len();
        let wildcard_entries = set
            .entries
            .iter()
            .filter(|e| e.pattern.iter().any(super::pat_parser_v2::PatByte::is_wild))
            .count();
        let fully_concrete = set
            .entries
            .iter()
            .filter(|e| e.concrete_bytes() == e.pattern.len())
            .count();
        let avg_concrete_bytes = if total_entries > 0 {
            set.entries.iter().map(|e| f64::from(u32::try_from(e.concrete_bytes()).unwrap_or(u32::MAX))).sum::<f64>()
                / f64::from(u32::try_from(total_entries).unwrap_or(u32::MAX))
        } else {
            0.0
        };
        let crc16_entries = set.entries.iter().filter(|e| e.crc16_len > 0).count();
        Self {
            total_entries,
            unique_names,
            wildcard_entries,
            fully_concrete,
            avg_concrete_bytes,
            crc16_entries,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str, bytes: Vec<u8>) -> RawFunction {
        RawFunction::new(name, bytes)
    }

    #[test]
    fn test_build_single_function() {
        let mut b = FlirtDbBuilder::new();
        let src = b.add_source(LibrarySource::new("libc", "x86"));
        b.add_function(make_func("malloc", vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04]), src);
        let set = b.finish().unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_function_too_short_skipped() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            min_func_len: 8,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("tiny", "x86"));
        b.add_function(make_func("tiny_func", vec![0x55, 0x8B]), src);
        let set = b.finish().unwrap();
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_deduplication_skips_identical_pattern() {
        let mut b = FlirtDbBuilder::new();
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        let bytes = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0x00, 0x00];
        b.add_function(make_func("func1", bytes.clone()), src);
        b.add_function(make_func("func2", bytes), src);
        let set = b.finish().unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.metadata.deduplicated_count, 1);
    }

    #[test]
    fn test_reloc_bytes_become_wildcards() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            crc16_len: 0,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("obj", "x64"));
        let func = RawFunction::new("reloc_func", vec![0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11])
            .with_relocs(vec![1, 2]);
        b.add_function(func, src);
        let set = b.finish().unwrap();
        assert!(matches!(set.entries[0].pattern[1], PatByte::Wild));
        assert!(matches!(set.entries[0].pattern[2], PatByte::Wild));
        assert!(matches!(set.entries[0].pattern[0], PatByte::Exact(0x55)));
    }

    #[test]
    fn test_pattern_crc16_computed() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            pattern_prefix_len: 4,
            crc16_len: 4,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        let bytes = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x57, 0x56];
        let expected_crc = crc16_ccitt(&bytes[4..8]);
        b.add_function(make_func("complex", bytes), src);
        let set = b.finish().unwrap();
        assert_eq!(set.entries[0].crc16, expected_crc);
        assert_eq!(set.entries[0].crc16_len, 4);
    }

    #[test]
    fn test_candidates_for_lookup() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            crc16_len: 0,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        b.add_function(make_func("f1", vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04]), src);
        let set = b.finish().unwrap();
        let candidates = set.candidates_for(&[0x55, 0x8B, 0xEC, 0x83, 0x00]);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_merge_two_sets() {
        let mut b1 = FlirtDbBuilder::new();
        let s1 = b1.add_source(LibrarySource::new("lib1", "x86"));
        b1.add_function(make_func("f1", vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0x00, 0x00]), s1);
        let set1 = b1.finish().unwrap();

        let mut b2 = FlirtDbBuilder::new();
        let s2 = b2.add_source(LibrarySource::new("lib2", "x86"));
        b2.add_function(make_func("f2", vec![0x56, 0x57, 0x8B, 0xF1, 0x8B, 0xFE, 0x00, 0x00]), s2);
        let set2 = b2.finish().unwrap();

        let merged = merge_signature_sets(vec![set1, set2]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_db_stats() {
        let mut b = FlirtDbBuilder::new();
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        b.add_function(make_func("f1", vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0x00, 0x00]), src);
        let set = b.finish().unwrap();
        let stats = DbStats::from(&set);
        assert_eq!(stats.total_entries, 1);
        assert!(stats.avg_concrete_bytes > 0.0);
    }

    #[test]
    fn test_name_index_populated() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            crc16_len: 0,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        b.add_function(make_func("named_func", vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), src);
        let set = b.finish().unwrap();
        assert!(set.name_index.contains_key("named_func"));
    }

    #[test]
    fn test_primary_name_in_entry() {
        let mut b = FlirtDbBuilder::with_config(DbBuilderConfig {
            crc16_len: 0,
            ..Default::default()
        });
        let src = b.add_source(LibrarySource::new("lib", "x86"));
        b.add_function(make_func("export_fn", vec![0x55, 0x8B, 0xEC, 0x00, 0x00, 0x00]), src);
        let set = b.finish().unwrap();
        assert_eq!(set.entries[0].primary_name(), Some("export_fn"));
    }

    #[test]
    fn test_library_source_builder() {
        let src = LibrarySource::new("msvcrt", "x64")
            .with_version("14.0")
            .with_tag("release")
            .with_tag("static");
        assert_eq!(src.arch, "x64");
        assert_eq!(src.version, "14.0");
        assert_eq!(src.tags.len(), 2);
    }
}
