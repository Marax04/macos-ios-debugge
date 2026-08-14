//! PAT file writer.
//!
//! Writes FLIRT `.pat` signature files in the IDA FLIRT format.
//! Handles duplicate patterns, multi-name modules, public and local
//! reference names, collision resolution, and optional sorting.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};

use crate::signature_extractor::FunctionSignature;

// ── PAT format constants ──────────────────────────────────────────────────────

pub const PAT_HEADER: &str = "---";
pub const PAT_END: &str = "---";
pub const PAT_MAX_PATTERN_LEN: usize = 64; // hex nibbles
pub const PAT_INITIAL_BYTES: usize = 32;   // bytes → 64 nibbles

// ── PatEntry ──────────────────────────────────────────────────────────────────

/// A single entry in a PAT file.
#[derive(Debug, Clone)]
pub struct PatEntry {
    /// Hex pattern (uppercase, spaces between bytes, `..` for wildcards).
    pub pattern: String,
    /// CRC16 check byte length (decimal).
    pub crc_len: u8,
    /// CRC16 value (hex, 4 digits).
    pub crc16: u16,
    /// Total function length (hex, 4 digits).
    pub total_len: u16,
    /// Public name definitions: (offset, name)
    pub public_names: Vec<(u32, String)>,
    /// Reference names: (offset, name) — tails/callees.
    pub ref_names: Vec<(u32, String)>,
    /// Local names (prefixed with `:` in output).
    pub local_names: Vec<(u32, String)>,
    /// True if this pattern is known to collide with another (multiple names).
    pub is_collision: bool,
}

impl PatEntry {
    #[must_use]
    pub fn new(sig: &FunctionSignature) -> Self {
        let public_names = {
            let v = vec![(sig.offset, sig.name.clone())];
            v
        };
        Self {
            pattern: normalize_pattern(&sig.pattern),
            crc_len: u8::try_from(sig.crc_length).unwrap_or(u8::MAX),
            crc16: sig.crc16,
            total_len: u16::try_from(sig.total_length).unwrap_or(u16::MAX),
            public_names,
            ref_names: sig.refs.clone(),
            local_names: Vec::new(),
            is_collision: false,
        }
    }

    /// Add an extra public name (for functions sharing the same pattern).
    pub fn add_public_name(&mut self, offset: u32, name: &str) {
        if !self.public_names.iter().any(|(o, n)| *o == offset && n == name) {
            self.public_names.push((offset, name.to_string()));
        }
    }

    /// Format as a PAT file line.
    #[must_use]
    pub fn format_line(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        // Pattern (pad to PAT_MAX_PATTERN_LEN hex chars if needed, no spaces in pattern field)
        let compact = self.pattern.replace(' ', "");
        s.push_str(&compact);
        // Pad to 64 chars (32 bytes) with dots
        if compact.len() < PAT_MAX_PATTERN_LEN {
            for _ in compact.len()..PAT_MAX_PATTERN_LEN {
                s.push('.');
            }
        }
        s.push(' ');
        // CRC byte length (2 hex digits)
        let _ = write!(s, "{:02X}", self.crc_len);
        s.push(' ');
        // CRC16 (4 hex digits)
        let _ = write!(s, "{:04X}", self.crc16);
        s.push(' ');
        // Total length (4 hex digits)
        let _ = write!(s, "{:04X}", self.total_len);
        s.push(' ');
        // Public names: `:OFFSET NAME`
        let mut first = true;
        for (off, name) in &self.public_names {
            if first {
                let _ = write!(s, ":{off:04X} {name}");
                first = false;
            } else {
                let _ = write!(s, " :{off:04X} {name}");
            }
        }
        // Reference names: `^OFFSET NAME`
        for (off, name) in &self.ref_names {
            let _ = write!(s, " ^{off:04X} {name}");
        }
        // Local names: `~OFFSET NAME`
        for (off, name) in &self.local_names {
            let _ = write!(s, " ~{off:04X} {name}");
        }
        s
    }

    /// Return the primary name for this entry.
    #[must_use]
    pub fn primary_name(&self) -> &str {
        self.public_names
            .first()
            .map_or("", |(_, n)| n.as_str())
    }

    /// Check whether two entries have identical patterns (collision).
    #[must_use]
    pub fn same_pattern(&self, other: &Self) -> bool {
        let a = self.pattern.replace(' ', "");
        let b = other.pattern.replace(' ', "");
        a == b && self.crc16 == other.crc16
    }
}

impl fmt::Display for PatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_line())
    }
}

// ── PatDatabase ───────────────────────────────────────────────────────────────

/// Deduplicating collection of PAT entries.
pub struct PatDatabase {
    /// Key: compact pattern + crc16
    entries: BTreeMap<String, PatEntry>,
    /// Entries that had duplicate patterns (names merged into primary).
    collision_count: usize,
    /// Total entries added (including duplicates).
    total_added: usize,
}

impl PatDatabase {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            collision_count: 0,
            total_added: 0,
        }
    }

    fn make_key(entry: &PatEntry) -> String {
        let compact = entry.pattern.replace(' ', "");
        format!("{}{:04X}", compact, entry.crc16)
    }

    /// Add a signature to the database.
    pub fn add_signature(&mut self, sig: &FunctionSignature) {
        self.total_added += 1;
        let entry = PatEntry::new(sig);
        let key = Self::make_key(&entry);
        if let Some(existing) = self.entries.get_mut(&key) {
            // Merge names.
            for (off, name) in &entry.public_names {
                existing.add_public_name(*off, name);
            }
            existing.is_collision = true;
            self.collision_count += 1;
        } else {
            self.entries.insert(key, entry);
        }
    }

    /// Add multiple signatures at once.
    pub fn add_all(&mut self, sigs: &[FunctionSignature]) {
        for sig in sigs {
            self.add_signature(sig);
        }
    }

    /// Number of unique pattern entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn collision_count(&self) -> usize {
        self.collision_count
    }

    #[must_use]
    pub const fn total_added(&self) -> usize {
        self.total_added
    }

    /// Iterate entries in sorted order (lexicographic by pattern).
    pub fn entries(&self) -> impl Iterator<Item = &PatEntry> {
        self.entries.values()
    }

    /// Remove entries whose pattern contains only wildcards (all `..`).
    pub fn remove_all_wildcard(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| !e.pattern.replace(['.', ' '], "").is_empty());
        before - self.entries.len()
    }

    /// Remove duplicate names (same name appearing more than once).
    pub fn deduplicate_names(&mut self) {
        let mut seen_names: HashSet<String> = HashSet::new();
        for entry in self.entries.values_mut() {
            entry.public_names.retain(|(_, name)| seen_names.insert(name.clone()));
        }
        // Remove entries that have no names left.
        self.entries.retain(|_, e| !e.public_names.is_empty());
    }

    /// Build collision report.
    #[must_use]
    pub fn collision_report(&self) -> CollisionReport {
        let collisions: Vec<CollisionInfo> = self
            .entries
            .values()
            .filter(|e| e.is_collision)
            .map(|e| CollisionInfo {
                pattern: e.pattern.clone(),
                names: e.public_names.iter().map(|(_, n)| n.clone()).collect(),
            })
            .collect();
        CollisionReport {
            total: self.total_added,
            unique: self.entries.len(),
            collisions,
        }
    }
}

impl Default for PatDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ── CollisionReport ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CollisionInfo {
    pub pattern: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CollisionReport {
    pub total: usize,
    pub unique: usize,
    pub collisions: Vec<CollisionInfo>,
}

impl CollisionReport {
    #[must_use]
    pub const fn has_collisions(&self) -> bool {
        !self.collisions.is_empty()
    }

    #[must_use]
    pub fn display(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "PAT Collision Report\n\
             Total:    {}\n\
             Unique:   {}\n\
             Collisions: {}\n",
            self.total,
            self.unique,
            self.collisions.len()
        );
        for col in &self.collisions {
            let _ = writeln!(out, "  {} -> [{}]", col.pattern, col.names.join(", "));
        }
        out
    }
}

// ── PatWriter ─────────────────────────────────────────────────────────────────

/// Configuration for PAT writing.
#[derive(Debug, Clone)]
pub struct PatWriterConfig {
    /// Sort entries lexicographically.
    pub sort: bool,
    /// Remove collision entries (only keep first name).
    pub resolve_collisions: CollisionResolution,
    /// Minimum total function length to write.
    pub min_length: u16,
    /// Include a comment header with metadata.
    pub include_header: bool,
    /// Module name for the header comment.
    pub module_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionResolution {
    /// Keep all names merged into one line.
    Merge,
    /// Keep only the first name.
    KeepFirst,
    /// Mark colliding entries with a `#` comment.
    Comment,
    /// Drop entries that collide.
    Drop,
}

impl Default for PatWriterConfig {
    fn default() -> Self {
        Self {
            sort: true,
            resolve_collisions: CollisionResolution::Merge,
            min_length: 4,
            include_header: false,
            module_name: None,
        }
    }
}

/// Writes a PAT file from a `PatDatabase`.
pub struct PatWriter {
    config: PatWriterConfig,
}

impl PatWriter {
    #[must_use]
    pub const fn new(config: PatWriterConfig) -> Self {
        Self { config }
    }

    /// Write the full PAT content to a `Write` sink.
    ///
    /// # Errors
    /// Returns an error if writing to the sink fails.
    pub fn write<W: Write>(&self, db: &PatDatabase, writer: &mut W) -> Result<()> {
        let mut out = BufWriter::new(writer);
        if self.config.include_header {
            let module = self
                .config
                .module_name
                .as_deref()
                .unwrap_or("unknown_module");
            writeln!(out, ";; Generated by rustre-flirt-gen")?;
            writeln!(out, ";; Module: {module}")?;
            writeln!(out, ";; Entries: {} (unique: {})", db.total_added(), db.len())?;
            writeln!(out)?;
        }
        for entry in db.entries() {
            // Skip entries below minimum length.
            if entry.total_len < self.config.min_length {
                continue;
            }
            // Apply collision resolution.
            let line = match self.config.resolve_collisions {
                CollisionResolution::Merge => entry.format_line(),
                CollisionResolution::KeepFirst => {
                    let mut e = entry.clone();
                    if e.is_collision {
                        e.public_names.truncate(1);
                    }
                    e.format_line()
                }
                CollisionResolution::Comment => {
                    if entry.is_collision {
                        format!("# COLLISION: {}", entry.format_line())
                    } else {
                        entry.format_line()
                    }
                }
                CollisionResolution::Drop => {
                    if entry.is_collision {
                        continue;
                    }
                    entry.format_line()
                }
            };
            writeln!(out, "{line}")?;
        }
        // End marker
        writeln!(out, "{PAT_END}")?;
        out.flush()?;
        Ok(())
    }

    /// Convenience: write to a `Vec<u8>`.
    ///
    /// # Errors
    /// Returns an error if writing fails.
    pub fn write_to_vec(&self, db: &PatDatabase) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write(db, &mut buf)?;
        Ok(buf)
    }

    /// Convenience: write to a `String`.
    ///
    /// # Errors
    /// Returns an error if writing or UTF-8 conversion fails.
    pub fn write_to_string(&self, db: &PatDatabase) -> Result<String> {
        let bytes = self.write_to_vec(db)?;
        String::from_utf8(bytes).context("non-UTF8 in PAT output")
    }
}

impl Default for PatWriter {
    fn default() -> Self {
        Self::new(PatWriterConfig::default())
    }
}

// ── PatParser (round-trip) ────────────────────────────────────────────────────

/// Parse a PAT file back into `PatEntry` list.
pub struct PatParser;

impl PatParser {
    #[must_use]
    pub fn parse(text: &str) -> Vec<PatEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == PAT_END || trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }
            if let Some(entry) = Self::parse_line(trimmed) {
                entries.push(entry);
            }
        }
        entries
    }

    fn parse_line(line: &str) -> Option<PatEntry> {
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 {
            return None;
        }
        let pattern_compact = parts[0];
        let crc_len = u8::from_str_radix(parts[1], 16).ok()?;
        let crc16 = u16::from_str_radix(parts[2], 16).ok()?;
        let total_len = u16::from_str_radix(parts[3], 16).ok()?;
        let rest = parts[4..].join(" ");
        // Parse name entries from rest: `:OFFSET NAME` and `^OFFSET NAME`
        let mut public_names = Vec::new();
        let mut ref_names = Vec::new();
        let mut local_names = Vec::new();
        for token in rest.split_whitespace().collect::<Vec<_>>().chunks(2) {
            if token.len() < 2 {
                continue;
            }
            let tag = token[0];
            let name = token[1];
            if let Some(off_str) = tag.strip_prefix(':') {
                let off = u32::from_str_radix(off_str, 16).unwrap_or(0);
                public_names.push((off, name.to_string()));
            } else if let Some(off_str) = tag.strip_prefix('^') {
                let off = u32::from_str_radix(off_str, 16).unwrap_or(0);
                ref_names.push((off, name.to_string()));
            } else if let Some(off_str) = tag.strip_prefix('~') {
                let off = u32::from_str_radix(off_str, 16).unwrap_or(0);
                local_names.push((off, name.to_string()));
            }
        }
        // Reconstruct pattern with spaces.
        let mut pattern = String::new();
        let chars: Vec<char> = pattern_compact.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            if *ch == '.' {
                // Pad: two dots = one wildcard byte
                if i % 2 == 0 {
                    pattern.push('.');
                    pattern.push('.');
                    if i + 2 < chars.len() {
                        pattern.push(' ');
                    }
                }
            } else if i % 2 == 0 && i + 1 < chars.len() {
                pattern.push(*ch);
                pattern.push(chars[i + 1]);
                pattern.push(' ');
            }
        }
        let pattern = pattern.trim_end().to_string();
        Some(PatEntry {
            pattern,
            crc_len,
            crc16,
            total_len,
            public_names,
            ref_names,
            local_names,
            is_collision: false,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Normalise a hex pattern: ensure uppercase and single spaces between bytes.
fn normalize_pattern(pat: &str) -> String {
    let mut parts = Vec::new();
    let mut chars = pat.chars().peekable();
    while let Some(a) = chars.next() {
        if a.is_ascii_whitespace() {
            continue;
        }
        if a == '.' {
            let _ = chars.next(); // consume second dot
            parts.push("..".to_string());
        } else if let Some(&b) = chars.peek() {
            if !b.is_ascii_whitespace() && b != '.' {
                chars.next();
                parts.push(format!("{}{}", a.to_ascii_uppercase(), b.to_ascii_uppercase()));
            } else {
                parts.push(format!("{}?", a.to_ascii_uppercase()));
            }
        }
    }
    parts.join(" ")
}

// ── Library module builder ────────────────────────────────────────────────────

/// Collects signatures from multiple object files/modules and writes a combined PAT.
pub struct LibraryPatBuilder {
    db: PatDatabase,
    module_count: usize,
    func_count: usize,
}

impl LibraryPatBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            db: PatDatabase::new(),
            module_count: 0,
            func_count: 0,
        }
    }

    pub fn add_signatures(&mut self, sigs: &[FunctionSignature]) {
        self.func_count += sigs.len();
        self.module_count += 1;
        self.db.add_all(sigs);
    }

    #[must_use]
    pub const fn module_count(&self) -> usize {
        self.module_count
    }

    #[must_use]
    pub const fn func_count(&self) -> usize {
        self.func_count
    }

    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.db.len()
    }

    /// # Errors
    /// Returns an error if pattern writing fails.
    pub fn finish(mut self, config: PatWriterConfig) -> Result<String> {
        self.db.remove_all_wildcard();
        self.db.deduplicate_names();
        let writer = PatWriter::new(config);
        writer.write_to_string(&self.db)
    }

    #[must_use]
    pub fn collision_report(&self) -> CollisionReport {
        self.db.collision_report()
    }
}

impl Default for LibraryPatBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_extractor::FunctionSignature;

    fn make_sig(name: &str, pattern: &str, crc: u16, len: u32) -> FunctionSignature {
        FunctionSignature {
            pattern: pattern.to_string(),
            crc16: crc,
            crc_length: 16,
            total_length: len,
            name: name.to_string(),
            offset: 0,
            refs: Vec::new(),
        }
    }

    #[test]
    fn test_pat_entry_format_line() {
        let sig = make_sig("foo", "55 48 89 E5", 0xABCD, 64);
        let entry = PatEntry::new(&sig);
        let line = entry.format_line();
        assert!(line.contains("foo"));
        assert!(line.contains("ABCD"));
    }

    #[test]
    fn test_pat_database_dedup() {
        let mut db = PatDatabase::new();
        let s1 = make_sig("func_a", "55 48 89 E5", 0x1234, 32);
        let s2 = make_sig("func_b", "55 48 89 E5", 0x1234, 32);
        db.add_signature(&s1);
        db.add_signature(&s2);
        assert_eq!(db.len(), 1);
        assert_eq!(db.collision_count(), 1);
        let entry = db.entries().next().unwrap();
        assert_eq!(entry.public_names.len(), 2);
    }

    #[test]
    fn test_pat_writer_output() {
        let mut db = PatDatabase::new();
        db.add_signature(&make_sig("my_func", "55 48 89 E5 48 83 EC 10", 0x5678, 128));
        let writer = PatWriter::default();
        let out = writer.write_to_string(&db).unwrap();
        assert!(out.contains("my_func"));
        assert!(out.contains("---"));
    }

    #[test]
    fn test_collision_resolution_drop() {
        let mut db = PatDatabase::new();
        db.add_signature(&make_sig("a", "AA BB CC DD", 0x0001, 16));
        db.add_signature(&make_sig("b", "AA BB CC DD", 0x0001, 16));
        let cfg = PatWriterConfig {
            resolve_collisions: CollisionResolution::Drop,
            ..Default::default()
        };
        let writer = PatWriter::new(cfg);
        let out = writer.write_to_string(&db).unwrap();
        assert!(!out.contains(" a"));
        assert!(!out.contains(" b"));
    }

    #[test]
    fn test_collision_resolution_keep_first() {
        let mut db = PatDatabase::new();
        db.add_signature(&make_sig("first", "11 22 33 44", 0xBEEF, 16));
        db.add_signature(&make_sig("second", "11 22 33 44", 0xBEEF, 16));
        let cfg = PatWriterConfig {
            resolve_collisions: CollisionResolution::KeepFirst,
            ..Default::default()
        };
        let writer = PatWriter::new(cfg);
        let out = writer.write_to_string(&db).unwrap();
        assert!(out.contains("first"));
        assert!(!out.contains("second"));
    }

    #[test]
    fn test_normalize_pattern() {
        let p = normalize_pattern("55 48 89 e5 .. ..");
        assert!(p.contains("55"));
        assert!(p.contains("E5"));
        assert!(p.contains(".."));
    }

    #[test]
    fn test_library_builder() {
        let mut builder = LibraryPatBuilder::new();
        let sigs = vec![
            make_sig("func1", "55 48 89 E5", 0x1111, 32),
            make_sig("func2", "48 83 EC 10", 0x2222, 48),
        ];
        builder.add_signatures(&sigs);
        let pat = builder.finish(PatWriterConfig::default()).unwrap();
        assert!(pat.contains("func1") || pat.contains("func2"));
    }

    #[test]
    fn test_pat_parser_round_trip() {
        let line = "55489BE54883EC104889E59090909090909090909090909090909090909090909090 10 1234 0040 :0000 my_func";
        let entries = PatParser::parse(line);
        // This assertion used to read `!entries.is_empty() || true`, which is
        // constant-true: the test could not fail no matter what the parser did.
        assert!(
            !entries.is_empty(),
            "PatParser::parse produced no entry for a well-formed .pat line"
        );
    }

    #[test]
    fn test_collision_report_display() {
        let mut db = PatDatabase::new();
        db.add_signature(&make_sig("x", "FF FF FF FF", 0x9999, 16));
        db.add_signature(&make_sig("y", "FF FF FF FF", 0x9999, 16));
        let report = db.collision_report();
        let text = report.display();
        assert!(text.contains("Collision"));
    }

    #[test]
    fn test_remove_all_wildcard() {
        let mut db = PatDatabase::new();
        // All-wildcard pattern
        let s = FunctionSignature {
            pattern: ".. .. .. .. .. .. .. ..".into(),
            crc16: 0,
            crc_length: 0,
            total_length: 8,
            name: "wild".into(),
            offset: 0,
            refs: Vec::new(),
        };
        db.add_signature(&s);
        db.add_signature(&make_sig("real", "55 48 89 E5", 0xAAAA, 16));
        let removed = db.remove_all_wildcard();
        assert_eq!(removed, 1);
        assert_eq!(db.len(), 1);
    }
}
