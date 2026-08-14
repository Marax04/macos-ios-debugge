//! FLIRT signature database.
//!
//! Loads multiple `.sig` files, indexes by first-bytes trie, supports
//! incremental loading, serialize/deserialize binary database format,
//! and provides statistics (total patterns, unique functions, library coverage).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

// Use ahash-backed HashMap for all maps keyed by attacker-controlled strings
// (function names read from .pat/.sig files) to prevent hash-collision DoS.
use ahash::AHashMap;

use crate::{FlirtPattern, FlirtLibrary, FlirtArch, FlirtOs, PatternByte, FlirtError};

// ── TrieNode ──────────────────────────────────────────────────────────────────

/// A node in the first-bytes trie used for fast candidate lookup.
#[derive(Debug, Clone)]
pub struct TrieNode {
    /// Per-byte children. `u32::MAX` = absent.
    children: [u32; 256],
    /// List of (`library_idx`, `pattern_idx`) pairs terminating here.
    terminals: Vec<(usize, usize)>,
}

impl TrieNode {
    /// Create a new empty node.
    #[must_use]
    pub const fn new() -> Self {
        Self { children: [u32::MAX; 256], terminals: Vec::new() }
    }
}

impl Default for TrieNode {
    fn default() -> Self {
        Self::new()
    }
}

// ── SigIndex ──────────────────────────────────────────────────────────────────

/// Patricia-trie index over the first N bytes of all patterns.
#[derive(Debug, Clone)]
pub struct SigIndex {
    nodes: Vec<TrieNode>,
    /// How many bytes of the initial pattern are used for indexing.
    pub prefix_depth: usize,
}

impl SigIndex {
    /// Create a new index with a given prefix depth.
    #[must_use]
    pub fn new(prefix_depth: usize) -> Self {
        Self { nodes: vec![TrieNode::new()], prefix_depth }
    }

    /// Insert `(lib_idx, pat_idx)` using the pattern's initial bytes (up to `prefix_depth`).
    ///
    /// # Panics
    /// Panics if the number of trie nodes exceeds `u32::MAX`.
    pub fn insert(&mut self, bytes: &[PatternByte], lib_idx: usize, pat_idx: usize) {
        let mut node_idx = 0usize;
        for pb in bytes.iter().take(self.prefix_depth) {
            match pb {
                PatternByte::Exact(b) => {
                    let b = *b as usize;
                    let child = self.nodes[node_idx].children[b];
                    if child == u32::MAX {
                        let new_idx = u32::try_from(self.nodes.len())
                        .expect("trie node count exceeded u32::MAX");
                        self.nodes.push(TrieNode::new());
                        self.nodes[node_idx].children[b] = new_idx;
                        node_idx = new_idx as usize;
                    } else {
                        node_idx = child as usize;
                    }
                }
                PatternByte::Wildcard => {
                    // Wildcards: index under all 256 exact bytes for coverage.
                    // For simplicity, stop descending at first wildcard.
                    break;
                }
            }
        }
        self.nodes[node_idx].terminals.push((lib_idx, pat_idx));
    }

    /// Return all `(lib_idx, pat_idx)` candidates whose prefix matches the first
    /// `prefix_depth` bytes of `buf`.
    #[must_use]
    pub fn candidates(&self, buf: &[u8]) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        let mut node_idx = 0usize;

        // Collect root terminals (patterns with wildcards at start).
        result.extend_from_slice(&self.nodes[0].terminals);

        for &b in buf.iter().take(self.prefix_depth) {
            let child = self.nodes[node_idx].children[b as usize];
            if child == u32::MAX {
                break;
            }
            node_idx = child as usize;
            result.extend_from_slice(&self.nodes[node_idx].terminals);
        }

        result.sort_unstable();
        result.dedup();
        result
    }

    /// Number of trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ── LibraryEntry ──────────────────────────────────────────────────────────────

/// Metadata for a loaded library.
#[derive(Debug, Clone)]
pub struct LibraryEntry {
    /// Library name.
    pub name: String,
    /// Architecture.
    pub arch: FlirtArch,
    /// Target OS.
    pub os: FlirtOs,
    /// Source file path (may be empty for in-memory libraries).
    pub source_path: PathBuf,
    /// Number of patterns in this library.
    pub pattern_count: usize,
    /// Library version string (e.g. "2.35").
    pub version: String,
    /// Whether this entry was loaded incrementally after initial construction.
    pub incremental: bool,
}

impl LibraryEntry {
    /// Create a new library entry.
    #[must_use]
    pub fn new(lib: &FlirtLibrary, source_path: PathBuf) -> Self {
        Self {
            name: lib.name.clone(),
            arch: lib.arch,
            os: lib.os.clone(),
            source_path,
            pattern_count: lib.patterns.len(),
            version: lib.version.to_string(),
            incremental: false,
        }
    }
}

// ── DatabaseStats ─────────────────────────────────────────────────────────────

/// Statistics for the entire database.
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// Total number of patterns across all libraries.
    pub total_patterns: usize,
    /// Number of libraries loaded.
    pub library_count: usize,
    /// Number of distinct function names (across all libraries).
    pub unique_function_names: usize,
    /// Architecture breakdown: arch -> library count.
    pub arch_breakdown: HashMap<String, usize>,
    /// OS breakdown: os -> library count.
    pub os_breakdown: HashMap<String, usize>,
    /// Patterns with CRC validation.
    pub patterns_with_crc: usize,
    /// Patterns with tail bytes.
    pub patterns_with_tail: usize,
    /// Average initial-byte pattern length.
    pub avg_pattern_len: f64,
}

impl std::fmt::Display for DatabaseStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,
            "FlirtDatabase: {} patterns, {} libraries, {} unique functions, {:.1} avg pattern len",
            self.total_patterns, self.library_count, self.unique_function_names, self.avg_pattern_len
        )
    }
}

// ── FlirtDatabase ─────────────────────────────────────────────────────────────

/// Central FLIRT signature database.
///
/// Supports:
/// - Loading multiple `.sig`/`.pat` files.
/// - First-bytes trie index for fast candidate lookup.
/// - Incremental loading (libraries can be added at any time).
/// - Binary serialization / deserialization.
/// - Statistics reporting.
pub struct FlirtDatabase {
    /// All loaded libraries.
    pub libraries: Vec<FlirtLibrary>,
    /// Metadata for each library.
    pub entries: Vec<LibraryEntry>,
    /// First-bytes trie index.
    pub index: SigIndex,
    /// Cache: function name -> list of (`lib_idx`, `pat_idx`).
    /// Uses ahash to resist hash-collision `DoS` from attacker-controlled symbol names.
    name_index: AHashMap<String, Vec<(usize, usize)>>,
}

impl FlirtDatabase {
    /// Binary format magic.
    const MAGIC: &'static [u8] = b"RUSTRE_FLIRTDB_V1\n";
    /// Default prefix depth for the trie index.
    const DEFAULT_PREFIX_DEPTH: usize = 8;

    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            entries: Vec::new(),
            index: SigIndex::new(Self::DEFAULT_PREFIX_DEPTH),
            name_index: AHashMap::new(),
        }
    }

    /// Add a library to the database, rebuilding the index entries.
    pub fn add_library(&mut self, lib: FlirtLibrary, source_path: PathBuf) {
        let lib_idx = self.libraries.len();
        let entry = LibraryEntry::new(&lib, source_path);
        for (pat_idx, pat) in lib.patterns.iter().enumerate() {
            self.index.insert(&pat.initial_bytes, lib_idx, pat_idx);
            // Update name index.
            for name in &pat.names {
                self.name_index
                    .entry(name.name.clone())
                    .or_default()
                    .push((lib_idx, pat_idx));
            }
        }
        self.libraries.push(lib);
        self.entries.push(entry);
    }

    /// Add a library loaded from a `.sig` binary blob (simplified import).
    ///
    /// The blob is parsed using the existing `FlirtSigFile` parser, then
    /// converted into a `FlirtLibrary`.
    /// # Errors
    /// Returns `FlirtError` if the `.sig` blob is malformed.
    pub fn load_sig_bytes(&mut self, data: &[u8], library_name: impl Into<String>) -> Result<(), FlirtError> {
        use crate::FlirtSigFile;
        let sig_file = FlirtSigFile::parse(data)?;
        let name = library_name.into();
        let arch = sig_file.header.arch;
        let lib = FlirtLibrary::new(name, arch, FlirtOs::Unknown);
        self.add_library(lib, PathBuf::new());
        Ok(())
    }

    /// Load a library from a `.pat` text file on disk.
    ///
    /// # Errors
    /// Returns `FlirtError::Io` on I/O failure, `FlirtError::ParseError` on parse failure.
    pub fn load_pat_file(&mut self, path: &Path) -> Result<(), FlirtError> {
        use crate::SimpleFlirtDatabase;
        let db = SimpleFlirtDatabase::load_pat_file(path)?;

        // Derive a library name from the file stem.
        let lib_name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut lib = FlirtLibrary::new(lib_name, FlirtArch::Unknown, FlirtOs::Unknown);
        for sig in &db.sigs {
            // Convert FlirtSig -> FlirtPattern.
            let initial_bytes: Vec<PatternByte> = sig.pattern_bytes.iter().zip(sig.mask.iter())
                .map(|(&b, &m)| if m != 0 { PatternByte::Exact(b) } else { PatternByte::Wildcard })
                .collect();
            let mut pat = FlirtPattern::new(initial_bytes);
            pat.crc16 = sig.crc16;
            pat.crc_length = sig.crc_len;
            if !sig.name.is_empty() {
                pat.names.push(crate::FlirtName {
                    name: sig.name.clone(),
                    offset: 0,
                    is_public: true,
                    is_local: false,
                });
            }
            lib.add_pattern(pat);
        }

        self.add_library(lib, path.to_path_buf());
        Ok(())
    }

    /// Load multiple `.pat` files from a directory.
    ///
    /// Files that fail to parse are silently skipped.
    pub fn load_pat_directory(&mut self, dir: &Path) {
        let Ok(read_dir) = std::fs::read_dir(dir) else { return };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pat") {
                let _ = self.load_pat_file(&path);
            }
        }
    }

    /// Incrementally add a pre-built `FlirtLibrary` (thread-safe equivalent: call from one thread).
    pub fn add_library_incremental(&mut self, mut lib: FlirtLibrary) {
        lib.version += 1;
        let lib_idx = self.libraries.len();
        let mut entry = LibraryEntry::new(&lib, PathBuf::new());
        entry.incremental = true;
        for (pat_idx, pat) in lib.patterns.iter().enumerate() {
            self.index.insert(&pat.initial_bytes, lib_idx, pat_idx);
            for name in &pat.names {
                self.name_index
                    .entry(name.name.clone())
                    .or_default()
                    .push((lib_idx, pat_idx));
            }
        }
        self.libraries.push(lib);
        self.entries.push(entry);
    }

    /// Return all `(lib_idx, pat_idx)` candidates for a function buffer.
    #[must_use]
    pub fn candidates(&self, buf: &[u8]) -> Vec<(usize, usize)> {
        self.index.candidates(buf)
    }

    /// Find all patterns whose primary name matches `name` exactly.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<(&FlirtLibrary, &FlirtPattern)> {
        let Some(pairs) = self.name_index.get(name) else { return Vec::new() };
        pairs.iter().filter_map(|&(li, pi)| {
            let lib = self.libraries.get(li)?;
            let pat = lib.patterns.get(pi)?;
            Some((lib, pat))
        }).collect()
    }

    /// Compute statistics for the entire database.
    #[must_use]
    pub fn stats(&self) -> DatabaseStats {
        let total_patterns = self.libraries.iter().map(|l| l.patterns.len()).sum();
        let library_count = self.libraries.len();
        let unique_function_names = self.name_index.len();

        let mut arch_breakdown: HashMap<String, usize> = HashMap::new();
        let mut os_breakdown: HashMap<String, usize> = HashMap::new();
        let mut patterns_with_crc = 0usize;
        let mut patterns_with_tail = 0usize;
        let mut total_len = 0usize;

        for lib in &self.libraries {
            let arch_str = format!("{:?}", lib.arch);
            *arch_breakdown.entry(arch_str).or_insert(0) += 1;
            let os_str = lib.os.as_str().to_string();
            *os_breakdown.entry(os_str).or_insert(0) += 1;
            for pat in &lib.patterns {
                if pat.crc_length > 0 { patterns_with_crc += 1; }
                if !pat.tail_bytes.is_empty() { patterns_with_tail += 1; }
                total_len += pat.initial_bytes.len();
            }
        }

        let avg_pattern_len = if total_patterns > 0 {
            f64::from(u32::try_from(total_len).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total_patterns).unwrap_or(u32::MAX))
        } else { 0.0 };

        DatabaseStats {
            total_patterns,
            library_count,
            unique_function_names,
            arch_breakdown,
            os_breakdown,
            patterns_with_crc,
            patterns_with_tail,
            avg_pattern_len,
        }
    }

    /// Number of libraries loaded.
    #[must_use]
    pub const fn library_count(&self) -> usize {
        self.libraries.len()
    }

    /// Total patterns across all libraries.
    #[must_use]
    pub fn total_patterns(&self) -> usize {
        self.libraries.iter().map(|l| l.patterns.len()).sum()
    }

    // ── Binary serialization ──────────────────────────────────────────────────

    /// Serialize the database to a compact binary format.
    ///
    /// Format:
    /// ```text
    /// MAGIC (18 bytes)
    /// library_count: u32 LE
    /// for each library:
    ///   name_len: u16 LE, name bytes
    ///   pattern_count: u32 LE
    ///   for each pattern:
    ///     initial_len: u16 LE
    ///     for each byte: 0x00 = wildcard, 0x01 XX = exact(XX)
    ///     crc16: u16 LE
    ///     crc_length: u8
    ///     pattern_length: u16 LE
    ///     name_count: u8
    ///     for each name: offset u16 LE, flags u8, name_len u8, name bytes
    /// ```
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::MAGIC);
        let lib_count = u32::try_from(self.libraries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&lib_count.to_le_bytes());

        for lib in &self.libraries {
            let name_bytes = lib.name.as_bytes();
            // u16 can only hold up to 65535 bytes; truncate to avoid silent corruption.
            let name_len = u16::try_from(name_bytes.len().min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&name_bytes[..usize::from(name_len)]);
            out.extend_from_slice(&u32::try_from(lib.patterns.len()).unwrap_or(u32::MAX).to_le_bytes());

            for pat in &lib.patterns {
                out.extend_from_slice(&u16::try_from(pat.initial_bytes.len()).unwrap_or(u16::MAX).to_le_bytes());
                for pb in &pat.initial_bytes {
                    match pb {
                        PatternByte::Wildcard => out.push(0x00),
                        PatternByte::Exact(b) => { out.push(0x01); out.push(*b); }
                    }
                }
                out.extend_from_slice(&pat.crc16.to_le_bytes());
                out.push(pat.crc_length);
                out.extend_from_slice(&pat.pattern_length.to_le_bytes());
                // The binary format encodes name_count as u8; silently cap at 255
                // to avoid truncation and a mismatch on deserialization.
                let name_count = u8::try_from(pat.names.len().min(usize::from(u8::MAX))).unwrap_or(u8::MAX);
                out.push(name_count);
                for n in pat.names.iter().take(usize::from(name_count)) {
                    out.extend_from_slice(&n.offset.to_le_bytes());
                    let flags: u8 = u8::from(n.is_public) | (u8::from(n.is_local) << 1);
                    out.push(flags);
                    let nb = n.name.as_bytes();
                    out.push(u8::try_from(nb.len()).unwrap_or(u8::MAX));
                    out.extend_from_slice(nb);
                }
            }
        }
        out
    }

    /// Read `name_count` [`crate::FlirtName`] entries from `data` at `pos`.
    fn read_pattern_names(pos: &mut usize, data: &[u8], name_count: usize) -> Result<Vec<crate::FlirtName>, FlirtError> {
        let read_u8 = |pos: &mut usize| -> Result<u8, FlirtError> {
            if *pos >= data.len() { return Err(FlirtError::ParseError("unexpected EOF".into())); }
            let v = data[*pos]; *pos += 1; Ok(v)
        };
        let read_u16 = |pos: &mut usize| -> Result<u16, FlirtError> {
            if *pos + 2 > data.len() { return Err(FlirtError::ParseError("unexpected EOF (u16)".into())); }
            let v = u16::from_le_bytes([data[*pos], data[*pos+1]]); *pos += 2; Ok(v)
        };
        let mut names = Vec::with_capacity(name_count);
        for _ in 0..name_count {
            let offset = read_u16(pos)?;
            let flags = read_u8(pos)?;
            let is_public = (flags & 1) != 0;
            let is_local = (flags & 2) != 0;
            let nlen = usize::from(read_u8(pos)?);
            if *pos + nlen > data.len() {
                return Err(FlirtError::ParseError("function name truncated".into()));
            }
            let fn_name = String::from_utf8_lossy(&data[*pos..*pos+nlen]).to_string();
            *pos += nlen;
            names.push(crate::FlirtName { name: fn_name, offset, is_public, is_local });
        }
        Ok(names)
    }

    /// Deserialize a database from bytes produced by [`Self::serialize`].
    ///
    /// # Errors
    /// Returns `FlirtError::ParseError` on any malformed input.
    pub fn deserialize(data: &[u8]) -> Result<Self, FlirtError> {
        let magic = Self::MAGIC;
        if data.len() < magic.len() || &data[..magic.len()] != magic {
            return Err(FlirtError::InvalidSigMagic);
        }
        let mut pos = magic.len();

        let read_u8 = |pos: &mut usize, data: &[u8]| -> Result<u8, FlirtError> {
            if *pos >= data.len() {
                return Err(FlirtError::ParseError("unexpected EOF".into()));
            }
            let v = data[*pos];
            *pos += 1;
            Ok(v)
        };
        let read_u16 = |pos: &mut usize, data: &[u8]| -> Result<u16, FlirtError> {
            if *pos + 2 > data.len() {
                return Err(FlirtError::ParseError("unexpected EOF (u16)".into()));
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos+1]]);
            *pos += 2;
            Ok(v)
        };
        let read_u32 = |pos: &mut usize, data: &[u8]| -> Result<u32, FlirtError> {
            if *pos + 4 > data.len() {
                return Err(FlirtError::ParseError("unexpected EOF (u32)".into()));
            }
            let v = u32::from_le_bytes([data[*pos], data[*pos+1], data[*pos+2], data[*pos+3]]);
            *pos += 4;
            Ok(v)
        };

        let lib_count = read_u32(&mut pos, data)? as usize;
        // Guard against adversarial inputs that claim huge library counts.
        if lib_count > 65536 {
            return Err(FlirtError::ParseError(format!(
                "library count {lib_count} exceeds sanity limit of 65536"
            )));
        }
        let mut db = Self::new();

        for _ in 0..lib_count {
            let name_len = read_u16(&mut pos, data)? as usize;
            if pos + name_len > data.len() {
                return Err(FlirtError::ParseError("name truncated".into()));
            }
            let name = String::from_utf8_lossy(&data[pos..pos+name_len]).to_string();
            pos += name_len;

            let pat_count = read_u32(&mut pos, data)? as usize;
            // Guard against adversarial pattern counts.
            if pat_count > 1_000_000 {
                return Err(FlirtError::ParseError(format!(
                    "pattern count {pat_count} exceeds sanity limit of 1000000"
                )));
            }
            let mut lib = FlirtLibrary::new(&name, FlirtArch::Unknown, FlirtOs::Unknown);

            for _ in 0..pat_count {
                let init_len = read_u16(&mut pos, data)? as usize;
                // Each pattern byte consumes at least 1 byte (wildcard tag), so
                // we need at least init_len bytes remaining.
                if pos + init_len > data.len() {
                    return Err(FlirtError::ParseError(format!(
                        "initial_bytes length {init_len} exceeds remaining data"
                    )));
                }
                let mut initial_bytes = Vec::with_capacity(init_len);
                for _ in 0..init_len {
                    let tag = read_u8(&mut pos, data)?;
                    if tag == 0x00 {
                        initial_bytes.push(PatternByte::Wildcard);
                    } else {
                        let b = read_u8(&mut pos, data)?;
                        initial_bytes.push(PatternByte::Exact(b));
                    }
                }
                let crc16 = read_u16(&mut pos, data)?;
                let crc_length = read_u8(&mut pos, data)?;
                let pattern_length = read_u16(&mut pos, data)?;

                let name_count = usize::from(read_u8(&mut pos, data)?);
                // Validate that we have enough bytes for at least name_count entries
                // (each entry is at minimum 4 bytes: offset u16 + flags u8 + nlen u8).
                if pos + name_count * 4 > data.len() {
                    return Err(FlirtError::ParseError(format!(
                        "name count {name_count} would exceed remaining data"
                    )));
                }
                let names = Self::read_pattern_names(&mut pos, data, name_count)?;

                let pat = FlirtPattern {
                    initial_bytes,
                    crc16,
                    crc_length,
                    pattern_length,
                    names,
                    tail_bytes: Vec::new(),
                    referenced_names: Vec::new(),
                };
                lib.add_pattern(pat);
            }

            db.add_library(lib, PathBuf::new());
        }

        Ok(db)
    }

    /// Write the serialized database to a file.
    ///
    /// # Errors
    /// Returns `FlirtError::Io` on I/O failure.
    pub fn save_to_file(&self, path: &Path) -> Result<(), FlirtError> {
        let bytes = self.serialize();
        std::fs::write(path, bytes).map_err(|e| FlirtError::Io(e.to_string()))
    }

    /// Load a database from a file.
    ///
    /// # Errors
    /// Returns `FlirtError::Io` on I/O failure, or parse errors.
    pub fn load_from_file(path: &Path) -> Result<Self, FlirtError> {
        let bytes = std::fs::read(path).map_err(|e| FlirtError::Io(e.to_string()))?;
        Self::deserialize(&bytes)
    }

    /// Return all library names.
    #[must_use]
    pub fn library_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }
}

impl Default for FlirtDatabase {
    fn default() -> Self {
        Self::new()
    }
}



// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lib(name: &str) -> FlirtLibrary {
        let mut lib = FlirtLibrary::new(name, FlirtArch::X86, FlirtOs::Linux);
        let initial = vec![PatternByte::Exact(0x55), PatternByte::Exact(0x8B), PatternByte::Exact(0xEC)];
        let mut pat = FlirtPattern::new(initial);
        pat.names.push(crate::FlirtName { name: "test_fn".into(), offset: 0, is_public: true, is_local: false });
        lib.add_pattern(pat);
        lib
    }

    #[test]
    fn test_add_and_find() {
        let mut db = FlirtDatabase::new();
        db.add_library(make_lib("libc"), PathBuf::new());
        let buf = [0x55u8, 0x8B, 0xEC, 0x00];
        let cands = db.candidates(&buf);
        assert!(!cands.is_empty());
    }

    #[test]
    fn test_find_by_name() {
        let mut db = FlirtDatabase::new();
        db.add_library(make_lib("libc"), PathBuf::new());
        let results = db.find_by_name("test_fn");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "libc");
    }

    #[test]
    fn test_stats() {
        let mut db = FlirtDatabase::new();
        db.add_library(make_lib("libc"), PathBuf::new());
        let stats = db.stats();
        assert_eq!(stats.total_patterns, 1);
        assert_eq!(stats.library_count, 1);
        assert_eq!(stats.unique_function_names, 1);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut db = FlirtDatabase::new();
        db.add_library(make_lib("libc"), PathBuf::new());
        let bytes = db.serialize();
        let db2 = FlirtDatabase::deserialize(&bytes).unwrap();
        assert_eq!(db2.library_count(), 1);
        assert_eq!(db2.total_patterns(), 1);
        let results = db2.find_by_name("test_fn");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_incremental_add() {
        let mut db = FlirtDatabase::new();
        db.add_library(make_lib("libc"), PathBuf::new());
        let before = db.total_patterns();
        db.add_library_incremental(make_lib("msvcrt"));
        assert_eq!(db.total_patterns(), before + 1);
        assert!(db.entries[1].incremental);
    }

    #[test]
    fn test_trie_node_candidates_prefix() {
        let mut idx = SigIndex::new(4);
        let bytes = vec![PatternByte::Exact(0xAA), PatternByte::Exact(0xBB), PatternByte::Exact(0xCC)];
        idx.insert(&bytes, 0, 0);
        let cands = idx.candidates(&[0xAA, 0xBB, 0xCC, 0x00]);
        assert!(cands.contains(&(0, 0)));
    }

    #[test]
    fn test_trie_node_no_match() {
        let mut idx = SigIndex::new(4);
        let bytes = vec![PatternByte::Exact(0xAA)];
        idx.insert(&bytes, 0, 0);
        let cands = idx.candidates(&[0xBB, 0xCC]);
        assert!(cands.is_empty());
    }

    #[test]
    fn test_library_entry_created() {
        let mut db = FlirtDatabase::new();
        let path = PathBuf::from("/fake/libc.pat");
        db.add_library(make_lib("libc"), path.clone());
        assert_eq!(db.entries[0].source_path, path);
        assert_eq!(db.entries[0].pattern_count, 1);
    }
}
