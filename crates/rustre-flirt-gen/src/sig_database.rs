//! Persistent signature database for `rustre-flirt-gen`.
//!
//! Provides:
//! * [`SigDatabase`] — in-memory store with binary-serialised persistence.
//! * Prefix-trie lookup for fast matching of a byte sequence against stored patterns.
//! * Merge of multiple `.sig` / database files with deduplication.
//! * Version tagging and format-compatibility checks.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// DbError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by database operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The binary header magic does not match.
    BadMagic,
    /// The stored format version is newer than this implementation supports.
    UnsupportedVersion(u16),
    /// A record could not be decoded.
    Corrupt(String),
    /// I/O-level error (carries a message).
    Io(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "invalid database magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported database version {v}"),
            Self::Corrupt(s) => write!(f, "corrupt database: {s}"),
            Self::Io(s) => write!(f, "IO error: {s}"),
        }
    }
}

impl std::error::Error for DbError {}

// ─────────────────────────────────────────────────────────────────────────────
// SigRecord
// ─────────────────────────────────────────────────────────────────────────────

/// A single stored signature record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigRecord {
    /// Function name.
    pub name: String,
    /// Library identifier (e.g. `"msvcrt140"`).
    pub library: String,
    /// Pattern bytes: `0xFF` = wildcard (stored as a flat byte string for compactness).
    pub pattern: Vec<u8>,
    /// Wildcard mask: bit `i` = 1 → byte `i` is a wildcard.
    pub wildcard_mask: Vec<u64>,
    /// CRC-16 of the verification window.
    pub crc: u16,
    /// Byte offset of the CRC window.
    pub crc_offset: u16,
    /// Length of the CRC window.
    pub crc_len: u8,
    /// Total expected function length (0 = unknown).
    pub total_len: u32,
    /// Source file tag (e.g. `"msvcrt140_x64.sig"`).
    pub source_tag: String,
}

impl SigRecord {
    /// Create a minimal record with no CRC and no library.
    #[must_use]
    pub fn new(name: impl Into<String>, pattern: Vec<u8>) -> Self {
        let len = pattern.len().div_ceil(64);
        Self {
            name: name.into(),
            library: String::new(),
            pattern,
            wildcard_mask: vec![0u64; len],
            crc: 0,
            crc_offset: 0,
            crc_len: 0,
            total_len: 0,
            source_tag: String::new(),
        }
    }

    /// Returns `true` if byte at position `i` is a wildcard.
    #[must_use]
    pub fn is_wildcard(&self, i: usize) -> bool {
        let word = i / 64;
        let bit = i % 64;
        if word >= self.wildcard_mask.len() {
            return false;
        }
        (self.wildcard_mask[word] >> bit) & 1 == 1
    }

    /// Set wildcard bit at position `i`.
    pub fn set_wildcard(&mut self, i: usize) {
        let word = i / 64;
        let bit = i % 64;
        let needed = word + 1;
        if self.wildcard_mask.len() < needed {
            self.wildcard_mask.resize(needed, 0);
        }
        self.wildcard_mask[word] |= 1 << bit;
    }

    /// Returns the number of leading bytes in this pattern (length of `pattern`).
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        self.pattern.len()
    }

    /// A string representation suitable for a `.pat` line (for debugging).
    #[must_use]
    pub fn as_pat_line(&self) -> String {
        let hex: String = self.pattern.iter().enumerate().map(|(i, &b)| {
            if self.is_wildcard(i) { "..".to_string() } else { format!("{b:02X}") }
        }).collect::<String>();
        format!("{hex} {:02X} {:04X} {:04X} :0000 {}", self.crc_len, self.crc, self.total_len, self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database binary format constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes at the start of a serialised database blob.
pub const DB_MAGIC: [u8; 8] = *b"RSTREDB\x01";
/// Current format version.
pub const DB_VERSION: u16 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// DbLookupNode (prefix trie)
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the prefix trie used for fast pattern lookup.
#[derive(Debug, Default)]
struct DbLookupNode {
    children: HashMap<u8, Box<Self>>,
    /// Record indices that have a terminal here.
    terminals: Vec<usize>,
}

impl DbLookupNode {
    fn insert(&mut self, prefix: &[u8], idx: usize) {
        if prefix.is_empty() {
            self.terminals.push(idx);
            return;
        }
        let child = self.children.entry(prefix[0]).or_insert_with(|| Box::new(Self::default()));
        child.insert(&prefix[1..], idx);
    }

    fn lookup(&self, data: &[u8], out: &mut Vec<usize>) {
        out.extend_from_slice(&self.terminals);
        if let Some(next_byte) = data.first()
            && let Some(child) = self.children.get(next_byte) {
            child.lookup(&data[1..], out);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SigDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory signature database with trie-backed lookup and binary persistence.
pub struct SigDatabase {
    records: Vec<SigRecord>,
    trie: DbLookupNode,
    /// Metadata: library → record indices.
    by_library: HashMap<String, Vec<usize>>,
    /// Version tag for compatibility checks.
    pub version: u16,
    /// Human-readable database name.
    pub name: String,
}

impl SigDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            records: Vec::new(),
            trie: DbLookupNode::default(),
            by_library: HashMap::new(),
            version: DB_VERSION,
            name: name.into(),
        }
    }

    /// Number of records stored.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when the database has no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert a [`SigRecord`].  Returns the record index.
    pub fn insert(&mut self, record: SigRecord) -> usize {
        let idx = self.records.len();
        // Build concrete prefix (first 8 non-wildcard bytes).
        let prefix: Vec<u8> = record.pattern.iter().enumerate()
            .filter(|(i, _)| !record.is_wildcard(*i))
            .take(8)
            .map(|(_, &b)| b)
            .collect();
        self.trie.insert(&prefix, idx);
        self.by_library.entry(record.library.clone()).or_default().push(idx);
        self.records.push(record);
        idx
    }

    /// Look up all records whose prefix is compatible with the start of `data`.
    ///
    /// Returns record indices; callers should verify CRC and total length.
    #[must_use]
    pub fn lookup_prefix(&self, data: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        self.trie.lookup(data, &mut out);
        out
    }

    /// Retrieve a record by index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&SigRecord> {
        self.records.get(idx)
    }

    /// Return all records for a library.
    #[must_use]
    pub fn by_library(&self, lib: &str) -> Vec<&SigRecord> {
        self.by_library.get(lib)
            .map(|idxs| idxs.iter().map(|&i| &self.records[i]).collect())
            .unwrap_or_default()
    }

    /// List library names present in this database.
    #[must_use]
    pub fn libraries(&self) -> Vec<&str> {
        self.by_library.keys().map(String::as_str).collect()
    }

    /// Merge another database into `self`, deduplicating by `(name, pattern)`.
    pub fn merge(&mut self, other: Self) {
        // Build a set of existing (name, pattern) for dedup.
        let existing: std::collections::HashSet<(String, Vec<u8>)> = self.records.iter()
            .map(|r| (r.name.clone(), r.pattern.clone()))
            .collect();
        for record in other.records {
            let key = (record.name.clone(), record.pattern.clone());
            if !existing.contains(&key) {
                self.insert(record);
            }
        }
    }

    /// Serialise to a compact binary blob.
    ///
    /// Format:
    /// ```text
    /// [8]  magic
    /// [2]  version (LE)
    /// [4]  record_count (LE)
    /// for each record:
    ///   [2]  name_len
    ///   [N]  name UTF-8
    ///   [2]  lib_len
    ///   [N]  lib UTF-8
    ///   [2]  pattern_len
    ///   [N]  pattern bytes
    ///   [M]  wildcard_mask  (ceil(pattern_len/64) * 8 bytes, LE u64s)
    ///   [2]  crc
    ///   [2]  crc_offset
    ///   [1]  crc_len
    ///   [4]  total_len
    ///   [2]  source_tag_len
    ///   [N]  source_tag UTF-8
    /// ```
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&DB_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.records.len()).unwrap_or(u32::MAX).to_le_bytes());
        for r in &self.records {
            push_str(&mut out, &r.name);
            push_str(&mut out, &r.library);
            out.extend_from_slice(&u16::try_from(r.pattern.len()).unwrap_or(u16::MAX).to_le_bytes());
            out.extend_from_slice(&r.pattern);
            let mask_words = r.pattern.len().div_ceil(64);
            for i in 0..mask_words {
                let w = r.wildcard_mask.get(i).copied().unwrap_or(0);
                out.extend_from_slice(&w.to_le_bytes());
            }
            out.extend_from_slice(&r.crc.to_le_bytes());
            out.extend_from_slice(&r.crc_offset.to_le_bytes());
            out.push(r.crc_len);
            out.extend_from_slice(&r.total_len.to_le_bytes());
            push_str(&mut out, &r.source_tag);
        }
        out
    }

    /// Deserialise from a binary blob produced by [`Self::serialize`].
    ///
    /// # Errors
    /// Returns [`DbError`] if the data is corrupt, has a bad magic, or unsupported version.
    pub fn deserialize(data: &[u8]) -> Result<Self, DbError> {
        let mut cur = 0usize;

        macro_rules! need {
            ($n:expr) => {
                if cur + $n > data.len() {
                    return Err(DbError::Corrupt("truncated".into()));
                }
            };
        }

        need!(10);
        if data[0..8] != DB_MAGIC {
            return Err(DbError::BadMagic);
        }
        cur += 8;
        let version = u16::from_le_bytes([data[cur], data[cur+1]]);
        cur += 2;
        if version > DB_VERSION {
            return Err(DbError::UnsupportedVersion(version));
        }
        need!(4);
        let record_count = u32::from_le_bytes([data[cur], data[cur+1], data[cur+2], data[cur+3]]) as usize;
        cur += 4;

        let mut db = Self::new("");
        db.version = version;

        for _ in 0..record_count {
            let name = read_str(data, &mut cur)?;
            let library = read_str(data, &mut cur)?;

            need!(2);
            let pat_len = u16::from_le_bytes([data[cur], data[cur+1]]) as usize;
            cur += 2;
            need!(pat_len);
            let pattern = data[cur..cur+pat_len].to_vec();
            cur += pat_len;

            let mask_words = pat_len.div_ceil(64);
            let mask_bytes = mask_words * 8;
            need!(mask_bytes);
            let mut wildcard_mask = Vec::with_capacity(mask_words);
            for _ in 0..mask_words {
                let w = u64::from_le_bytes(data[cur..cur+8].try_into()
                    .map_err(|_| DbError::Corrupt("mask word".into()))?);
                wildcard_mask.push(w);
                cur += 8;
            }

            need!(9);
            let crc = u16::from_le_bytes([data[cur], data[cur+1]]); cur += 2;
            let crc_offset = u16::from_le_bytes([data[cur], data[cur+1]]); cur += 2;
            let crc_len = data[cur]; cur += 1;
            let total_len = u32::from_le_bytes([data[cur], data[cur+1], data[cur+2], data[cur+3]]); cur += 4;
            let source_tag = read_str(data, &mut cur)?;

            let rec = SigRecord { name, library, pattern, wildcard_mask, crc, crc_offset, crc_len, total_len, source_tag };
            db.insert(rec);
        }

        Ok(db)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&u16::try_from(b.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(b);
}

fn read_str(data: &[u8], cur: &mut usize) -> Result<String, DbError> {
    if *cur + 2 > data.len() {
        return Err(DbError::Corrupt("string length".into()));
    }
    let len = u16::from_le_bytes([data[*cur], data[*cur+1]]) as usize;
    *cur += 2;
    if *cur + len > data.len() {
        return Err(DbError::Corrupt("string body".into()));
    }
    let s = std::str::from_utf8(&data[*cur..*cur+len])
        .map_err(|_| DbError::Corrupt("utf8".into()))?
        .to_string();
    *cur += len;
    Ok(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// DbStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a database.
#[derive(Debug, Clone, Default)]
pub struct DbStats {
    pub total_records: usize,
    pub unique_libraries: usize,
    pub avg_pattern_len: f64,
    pub max_pattern_len: usize,
    pub min_pattern_len: usize,
}

impl DbStats {
    /// Compute stats from a database.
    #[must_use]
    pub fn from_db(db: &SigDatabase) -> Self {
        if db.is_empty() {
            return Self::default();
        }
        let lengths: Vec<usize> = db.records.iter().map(SigRecord::pattern_len).collect();
        let total: usize = lengths.iter().sum();
        Self {
            total_records: db.len(),
            unique_libraries: db.by_library.len(),
            avg_pattern_len: f64::from(u32::try_from(total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(lengths.len()).unwrap_or(u32::MAX)),
            max_pattern_len: *lengths.iter().max().unwrap_or(&0),
            min_pattern_len: *lengths.iter().min().unwrap_or(&0),
        }
    }
}

impl fmt::Display for DbStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "records={} libs={} avg_pat={:.1} min_pat={} max_pat={}",
            self.total_records, self.unique_libraries,
            self.avg_pattern_len, self.min_pattern_len, self.max_pattern_len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(name: &str, lib: &str, pattern: Vec<u8>) -> SigRecord {
        let mut r = SigRecord::new(name, pattern);
        r.library = lib.into();
        r
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut db = SigDatabase::new("test");
        db.insert(make_record("foo", "libc", vec![0x55, 0x48, 0x89, 0xE5]));
        db.insert(make_record("bar", "libc", vec![0x55, 0x53, 0x48, 0x83]));

        let hits = db.lookup_prefix(&[0x55, 0x48, 0x89, 0xE5, 0x00]);
        assert!(hits.contains(&0));

        let hits2 = db.lookup_prefix(&[0xFF, 0x00]);
        assert!(hits2.is_empty());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let mut db = SigDatabase::new("roundtrip");
        let mut r = make_record("func_a", "msvcrt", vec![0x55, 0x48, 0x89, 0xE5, 0x41, 0x54]);
        r.crc = 0xBEEF;
        r.crc_offset = 32;
        r.crc_len = 8;
        r.total_len = 64;
        r.source_tag = "test.sig".into();
        db.insert(r);

        let blob = db.serialize();
        let db2 = SigDatabase::deserialize(&blob).expect("deserialize");
        assert_eq!(db2.len(), 1);
        let rec = db2.get(0).unwrap();
        assert_eq!(rec.name, "func_a");
        assert_eq!(rec.crc, 0xBEEF);
        assert_eq!(rec.total_len, 64);
    }

    #[test]
    fn test_merge_dedup() {
        let mut db1 = SigDatabase::new("a");
        db1.insert(make_record("foo", "lib", vec![0x55, 0x48]));
        let mut db2 = SigDatabase::new("b");
        db2.insert(make_record("foo", "lib", vec![0x55, 0x48])); // duplicate
        db2.insert(make_record("bar", "lib", vec![0x41, 0x54]));
        db1.merge(db2);
        assert_eq!(db1.len(), 2);
    }

    #[test]
    fn test_wildcard_mask() {
        let mut r = SigRecord::new("w", vec![0x00; 70]);
        r.set_wildcard(0);
        r.set_wildcard(63);
        r.set_wildcard(64);
        r.set_wildcard(69);
        assert!(r.is_wildcard(0));
        assert!(r.is_wildcard(63));
        assert!(r.is_wildcard(64));
        assert!(r.is_wildcard(69));
        assert!(!r.is_wildcard(1));
    }
}
