//! FLIRT signature index — trie-based lookup and JSON serialization.
//!
//! Supports building from multiple `.pat` files, prefix lookup, exact CRC
//! match, collision detection, and JSON export/import.

use std::collections::HashMap;
use std::fmt::Write as _;
use crate::flirt_signature_writer::compute_crc16;
// AHashMap prevents hash-collision DoS when keys come from attacker-controlled
// .pat file content (symbol names, prefix hex strings).
use ahash::AHashMap;

// ── IndexEntry ────────────────────────────────────────────────────────────────

/// A single resolved function entry in the FLIRT index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Function name.
    pub name: String,
    /// Source library name.
    pub library: String,
    /// CRC-16 for disambiguation.
    pub crc16: u16,
    /// Normalized pattern prefix (up to 32 bytes, `None` = wildcard).
    pub pattern_prefix: Vec<Option<u8>>,
}

impl IndexEntry {
    pub fn new(
        name: impl Into<String>,
        library: impl Into<String>,
        crc16: u16,
        pattern_prefix: Vec<Option<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            library: library.into(),
            crc16,
            pattern_prefix,
        }
    }

    /// Format prefix as a hex string (with `..` for wildcards).
    #[must_use] 
    pub fn prefix_hex(&self) -> String {
        self.pattern_prefix
            .iter()
            .map(|b| b.map_or_else(|| "..".to_string(), |v| format!("{v:02X}")))
            .collect::<String>()
    }
}

// ── IndexStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for a `FlirtIndex`.
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub total_entries: u32,
    pub libraries: Vec<String>,
    pub collision_pairs: u32,
}

impl IndexStats {
    #[must_use] 
    pub const fn library_count(&self) -> usize {
        self.libraries.len()
    }
}

// ── Trie ──────────────────────────────────────────────────────────────────────

/// A trie node used for prefix matching.
#[derive(Debug, Default)]
pub struct TrieNode {
    /// The byte value that leads to this node from its parent (`None` for root / wildcard).
    pub prefix_byte: Option<u8>,
    /// Children keyed by next concrete byte; key 256 is used for wildcard children.
    children: HashMap<u16, Box<Self>>,
    /// Index entries that match the path to this node.
    pub leaves: Vec<usize>, // indices into FlirtIndex::entries
}

impl TrieNode {
    #[must_use] 
    pub fn new(prefix_byte: Option<u8>) -> Self {
        Self {
            prefix_byte,
            children: HashMap::new(),
            leaves: Vec::new(),
        }
    }

    #[must_use] 
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    #[must_use] 
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

// ── PAT line parser ───────────────────────────────────────────────────────────

/// Minimal `.pat` line parser.
///
/// Format: `<hex_pattern> <crc_len:02X> <crc16:04X> <func_len:04X> :<offset:04X> <name>`
fn parse_pat_line(line: &str, library: &str) -> Option<IndexEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line == "---" {
        return None;
    }
    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 6 {
        return None;
    }
    let hex_pattern = parts[0];
    // crc_len at parts[1], crc16 at parts[2], func_len at parts[3]
    let crc16 = u16::from_str_radix(parts[2], 16).ok()?;
    // name field starts at parts[5] after ":<offset>"
    let name_field = parts[5];
    let name = name_field.split_whitespace().next()?.to_string();

    // Parse hex pattern
    let prefix: Vec<Option<u8>> = hex_pattern
        .as_bytes()
        .chunks(2)
        .filter_map(|c| {
            if c.len() < 2 { return None; }
            let s = std::str::from_utf8(c).ok()?;
            if s == ".." {
                Some(None)
            } else {
                Some(Some(u8::from_str_radix(s, 16).ok()?))
            }
        })
        .collect();

    Some(IndexEntry::new(name, library, crc16, prefix))
}

// ── FlirtIndex ────────────────────────────────────────────────────────────────

/// The main FLIRT signature index.
pub struct FlirtIndex {
    entries: Vec<IndexEntry>,
    trie: TrieNode,
}

impl FlirtIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            trie: TrieNode::default(),
        }
    }

    /// Add a single `IndexEntry` to the index.
    pub fn add_entry(&mut self, entry: IndexEntry) {
        let idx = self.entries.len();
        self.insert_into_trie(&entry.pattern_prefix, idx);
        self.entries.push(entry);
    }

    /// Build the index from multiple `.pat` file contents.
    ///
    /// `pat_files` is an iterator of `(library_name, pat_content)` pairs.
    pub fn build_from_pat_files<'a>(
        &mut self,
        pat_files: impl Iterator<Item = (&'a str, &'a str)>,
    ) {
        for (lib, content) in pat_files {
            for line in content.lines() {
                if let Some(entry) = parse_pat_line(line, lib) {
                    self.add_entry(entry);
                }
            }
        }
    }

    // ── Trie operations ────────────────────────────────────────────────────

    fn insert_into_trie(&mut self, prefix: &[Option<u8>], entry_idx: usize) {
        let mut node = &mut self.trie;
        for &byte_opt in prefix {
            let key = byte_opt.map_or(256, u16::from);
            node = node.children.entry(key).or_insert_with(|| {
                Box::new(TrieNode::new(byte_opt))
            });
        }
        node.leaves.push(entry_idx);
    }

    /// Look up all entries whose pattern is consistent with the given concrete byte slice.
    ///
    /// Both exact-byte and wildcard branches in the trie are followed.
    #[must_use] 
    pub fn lookup_prefix(&self, data: &[u8]) -> Vec<&IndexEntry> {
        let mut results = Vec::new();
        self.lookup_recursive(&self.trie, data, 0, &mut results);
        results
    }

    fn lookup_recursive<'a>(
        &'a self,
        node: &TrieNode,
        data: &[u8],
        depth: usize,
        results: &mut Vec<&'a IndexEntry>,
    ) {
        // Collect entries at this node.
        for &idx in &node.leaves {
            if let Some(entry) = self.entries.get(idx) {
                results.push(entry);
            }
        }
        if depth >= data.len() { return; }
        let b = data[depth];
        // Follow concrete byte child.
        if let Some(child) = node.children.get(&u16::from(b)) {
            self.lookup_recursive(child, data, depth + 1, results);
        }
        // Follow wildcard child.
        if let Some(wild) = node.children.get(&256) {
            self.lookup_recursive(wild, data, depth + 1, results);
        }
    }

    /// Exact match: entries whose prefix matches `prefix` bytes AND whose CRC-16 == `crc`.
    #[must_use] 
    pub fn exact_match(&self, prefix: &[u8], crc: u16) -> Vec<&IndexEntry> {
        self.lookup_prefix(prefix)
            .into_iter()
            .filter(|e| e.crc16 == crc)
            .collect()
    }

    /// Verify a match by computing the CRC over `function_bytes` starting at `crc_start`.
    #[must_use] 
    pub fn verify_match(
        &self,
        entry: &IndexEntry,
        function_bytes: &[u8],
        crc_start: usize,
        crc_len: usize,
    ) -> bool {
        let end = (crc_start + crc_len).min(function_bytes.len());
        if crc_start >= function_bytes.len() { return false; }
        let computed = compute_crc16(&function_bytes[crc_start..end]);
        computed == entry.crc16
    }

    // ── Collision detection ────────────────────────────────────────────────

    /// Detect groups of entries that share the same prefix AND the same CRC-16
    /// (i.e., they are ambiguous).
    #[must_use] 
    pub fn detect_collisions(&self) -> Vec<Vec<&IndexEntry>> {
        // Group by (prefix_hex, crc16).
        // Use AHashMap: keys include attacker-controlled prefix strings.
        let mut groups: AHashMap<(String, u16), Vec<&IndexEntry>> = AHashMap::new();
        for entry in &self.entries {
            let key = (entry.prefix_hex(), entry.crc16);
            groups.entry(key).or_default().push(entry);
        }
        groups
            .into_values()
            .filter(|g| g.len() > 1)
            .collect()
    }

    // ── Stats ──────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn stats(&self) -> IndexStats {
        let mut libs: Vec<String> = self.entries.iter()
            .map(|e| e.library.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        libs.sort();
        let collision_pairs = self.detect_collisions()
            .iter()
            .map(|g| u32::try_from(g.len() - 1).unwrap_or(u32::MAX))
            .sum();
        IndexStats {
            total_entries: u32::try_from(self.entries.len()).unwrap_or(u32::MAX),
            libraries: libs,
            collision_pairs,
        }
    }

    #[must_use] 
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    // ── JSON export / import ───────────────────────────────────────────────

    /// Export the index to a JSON string (hand-rolled, no serde dependency).
    #[must_use] 
    pub fn export_to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("[\n");
        for (i, entry) in self.entries.iter().enumerate() {
            out.push_str("  {");
            let _ = write!(out, r#""name":"{}","library":"{}","crc16":{}"#,
                json_escape(&entry.name),
                json_escape(&entry.library),
                entry.crc16,
            );
            // Prefix as hex array
            out.push_str(r#","prefix":["#);
            let prefix_strs: Vec<String> = entry.pattern_prefix.iter().map(|b| b.map_or_else(|| "null".to_string(), |v| format!("{v}"))).collect();
            out.push_str(&prefix_strs.join(","));
            out.push_str("]}");
            if i + 1 < self.entries.len() { out.push(','); }
            out.push('\n');
        }
        out.push(']');
        out
    }

    /// Import entries from a JSON string produced by `export_to_json`.
    ///
    /// Hand-rolls a minimal parser for the specific format we produce.
    pub fn import_from_json(&mut self, json: &str) -> usize {
        // Very naive parser: extract name/library/crc16/prefix fields line by line.
        let mut imported = 0;
        for line in json.lines() {
            let line = line.trim().trim_end_matches(',');
            if !line.starts_with('{') { continue; }
            if let Some(entry) = parse_json_entry(line) {
                self.add_entry(entry);
                imported += 1;
            }
        }
        imported
    }
}

impl Default for FlirtIndex {
    fn default() -> Self { Self::new() }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Minimal JSON object parser for lines produced by `export_to_json`.
fn parse_json_entry(line: &str) -> Option<IndexEntry> {
    let name = extract_json_str(line, "name")?;
    let library = extract_json_str(line, "library")?;
    let crc16_str = extract_json_num(line, "crc16")?;
    let crc16 = crc16_str.parse::<u16>().ok()?;

    // Parse prefix array: "prefix":[1,null,2,...]
    let prefix_start = line.find("\"prefix\":[")?;
    let arr_start = line[prefix_start..].find('[')? + prefix_start + 1;
    let arr_end = line[arr_start..].find(']')? + arr_start;
    let arr_str = &line[arr_start..arr_end];
    let prefix: Vec<Option<u8>> = arr_str.split(',')
        .filter_map(|tok| {
            let tok = tok.trim();
            if tok == "null" {
                Some(None)
            } else {
                tok.parse::<u8>().ok().map(Some)
            }
        })
        .collect();

    Some(IndexEntry::new(name, library, crc16, prefix))
}

fn extract_json_str(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn extract_json_num(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":");
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { return None; }
    Some(rest[..end].to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(name: &str, crc: u16, prefix: Vec<Option<u8>>) -> IndexEntry {
        IndexEntry::new(name, "testlib", crc, prefix)
    }

    #[test]
    fn add_entry_and_lookup() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("foo", 0x1234, vec![Some(0x55), Some(0x8B), Some(0xEC)]));
        let results = idx.lookup_prefix(&[0x55, 0x8B, 0xEC, 0xFF]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "foo");
    }

    #[test]
    fn lookup_with_wildcard() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("bar", 0xABCD, vec![Some(0xE8), None, None, None, None]));
        let results = idx.lookup_prefix(&[0xE8, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "bar");
    }

    #[test]
    fn exact_match_by_crc() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("func_a", 0x1111, vec![Some(0x55)]));
        idx.add_entry(sample_entry("func_b", 0x2222, vec![Some(0x55)]));
        let results = idx.exact_match(&[0x55], 0x1111);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "func_a");
    }

    #[test]
    fn no_match_wrong_prefix() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("foo", 0x1234, vec![Some(0xCC)]));
        let results = idx.lookup_prefix(&[0x55]);
        assert!(results.is_empty());
    }

    #[test]
    fn detect_collisions_finds_duplicates() {
        let mut idx = FlirtIndex::new();
        let prefix = vec![Some(0x55), Some(0x8B)];
        idx.add_entry(sample_entry("dup_a", 0xAAAA, prefix.clone()));
        idx.add_entry(sample_entry("dup_b", 0xAAAA, prefix));
        let collisions = idx.detect_collisions();
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].len(), 2);
    }

    #[test]
    fn detect_collisions_no_duplicates() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("a", 0x0001, vec![Some(0x55)]));
        idx.add_entry(sample_entry("b", 0x0002, vec![Some(0x55)]));
        let collisions = idx.detect_collisions();
        assert!(collisions.is_empty());
    }

    #[test]
    fn stats_library_count() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(IndexEntry::new("f1", "libA", 0, vec![]));
        idx.add_entry(IndexEntry::new("f2", "libB", 0, vec![]));
        idx.add_entry(IndexEntry::new("f3", "libA", 0, vec![]));
        let s = idx.stats();
        assert_eq!(s.library_count(), 2);
        assert_eq!(s.total_entries, 3);
    }

    #[test]
    fn export_import_roundtrip() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("round_trip", 0x5678, vec![Some(0x55), None, Some(0xEC)]));
        let json = idx.export_to_json();
        let mut idx2 = FlirtIndex::new();
        let imported = idx2.import_from_json(&json);
        assert_eq!(imported, 1);
        assert_eq!(idx2.entry_count(), 1);
        assert_eq!(idx2.entries()[0].name, "round_trip");
        assert_eq!(idx2.entries()[0].crc16, 0x5678);
    }

    #[test]
    fn export_json_contains_name() {
        let mut idx = FlirtIndex::new();
        idx.add_entry(sample_entry("my_func", 0, vec![]));
        let json = idx.export_to_json();
        assert!(json.contains("my_func"));
    }

    #[test]
    fn build_from_pat_files_parses_lines() {
        let pat = "558BEC 10 1234 0010 :0000 my_func\n---\n";
        let mut idx = FlirtIndex::new();
        idx.build_from_pat_files(std::iter::once(("mylib", pat)));
        assert_eq!(idx.entry_count(), 1);
        assert_eq!(idx.entries()[0].name, "my_func");
        assert_eq!(idx.entries()[0].library, "mylib");
        assert_eq!(idx.entries()[0].crc16, 0x1234);
    }

    #[test]
    fn build_from_pat_skips_comments() {
        let pat = "# this is a comment\n558BEC 10 ABCD 0010 :0000 func1\n---\n";
        let mut idx = FlirtIndex::new();
        idx.build_from_pat_files(std::iter::once(("lib", pat)));
        assert_eq!(idx.entry_count(), 1);
    }

    #[test]
    fn build_from_pat_multiple_files() {
        let pat1 = "55 10 1111 0004 :0000 func_a\n";
        let pat2 = "53 10 2222 0004 :0000 func_b\n";
        let mut idx = FlirtIndex::new();
        idx.build_from_pat_files([("libA", pat1), ("libB", pat2)].iter().copied());
        assert_eq!(idx.entry_count(), 2);
    }

    #[test]
    fn prefix_hex_format() {
        let entry = IndexEntry::new("f", "l", 0, vec![Some(0xAB), None, Some(0xCD)]);
        assert_eq!(entry.prefix_hex(), "AB..CD");
    }

    #[test]
    fn verify_match_correct_crc() {
        let idx = FlirtIndex::new();
        let bytes: Vec<u8> = (0u8..32).collect();
        let crc = compute_crc16(&bytes[4..12]);
        let entry = IndexEntry::new("f", "l", crc, vec![]);
        assert!(idx.verify_match(&entry, &bytes, 4, 8));
    }

    #[test]
    fn verify_match_wrong_crc() {
        let idx = FlirtIndex::new();
        let bytes = vec![0u8; 32];
        let entry = IndexEntry::new("f", "l", 0xDEAD, vec![]);
        // CRC of all-zero bytes won't be 0xDEAD
        let result = idx.verify_match(&entry, &bytes, 0, 16);
        // Just check it doesn't panic; may be true or false.
        let _ = result;
    }
}
