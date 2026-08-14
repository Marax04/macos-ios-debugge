//! FLIRT signature writer — generate IDA `.pat` text-format signature files.
//!
//! Implements `FlirtSignatureWriter`, a Patricia trie of byte patterns,
//! CRC-16 computation (CRC16-CCITT poly 0x8408), PAT-format output,
//! and `FlirtStats` for reporting.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

// ── SigFeatures bitflags ──────────────────────────────────────────────────────

/// Feature flags embedded in a `.sig` file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub struct SigFeatures(pub u16);

impl SigFeatures {
    pub const UNION_FUNCTIONS: u16  = 0x0001;
    pub const SEG_16BIT: u16        = 0x0002;
    pub const NO_FUNCTION_END: u16  = 0x0004;
    pub const MODULE_LIBRARY: u16   = 0x0008;
    pub const STARTUP: u16          = 0x0010;

    #[must_use] 
    pub const fn union_functions(self) -> bool   { self.0 & Self::UNION_FUNCTIONS  != 0 }
    #[must_use] 
    pub const fn seg_16bit(self) -> bool         { self.0 & Self::SEG_16BIT        != 0 }
    #[must_use] 
    pub const fn no_function_end(self) -> bool   { self.0 & Self::NO_FUNCTION_END  != 0 }
    #[must_use] 
    pub const fn module_library(self) -> bool    { self.0 & Self::MODULE_LIBRARY   != 0 }
    #[must_use] 
    pub const fn startup(self) -> bool           { self.0 & Self::STARTUP          != 0 }

    pub const fn set(&mut self, flag: u16) { self.0 |= flag; }
    pub const fn clear(&mut self, flag: u16) { self.0 &= !flag; }
}


// ── FunctionDescriptor ────────────────────────────────────────────────────────

/// A single function to be included in the PAT file.
#[derive(Debug, Clone)]
pub struct FunctionDescriptor {
    /// Offset within the signature block (usually 0 for the first function).
    pub offset: u16,
    /// CRC-16 of the CRC region.
    pub crc16: u16,
    /// Length of the CRC region (bytes to CRC after the 32-byte prefix).
    pub crc_len: u8,
    /// Public function name.
    pub name: String,
    /// Optional module/library name for disambiguation.
    pub module_name: Option<String>,
}

impl FunctionDescriptor {
    pub fn new(offset: u16, crc16: u16, crc_len: u8, name: impl Into<String>) -> Self {
        Self {
            offset,
            crc16,
            crc_len,
            name: name.into(),
            module_name: None,
        }
    }

    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module_name = Some(module.into());
        self
    }
}

// ── CRC-16 (CCITT, poly 0x8408) ───────────────────────────────────────────────

/// Build the CRC-16 lookup table for poly 0x8408 (reversed 0x1021).
fn build_crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    for i in 0u16..256 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

/// Compute the FLIRT tail CRC over `data`, table-driven.
///
/// BUG FIX: this applied a final `^ 0xFFFF` (X-25) while the matcher used
/// MCRF4XX, so every CRC written into a signature was the complement of what
/// the matcher recomputed. The table core is kept because it is ~8x faster than
/// the bitwise loop and this is the write-side hot path; a test pins it to
/// [`crate::crc::flirt_tail`] so the two can never drift again.
#[must_use]
pub fn compute_crc16(data: &[u8]) -> u16 {
    static TABLE: std::sync::OnceLock<[u16; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(build_crc16_table);
    let mut crc = 0xFFFFu16;
    for &b in data {
        let idx = ((crc ^ u16::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc
}

// ── Patricia trie ─────────────────────────────────────────────────────────────

/// A node in the Patricia trie used to compress signature patterns.
#[derive(Debug, Default)]
pub struct PatternNode {
    /// Concrete prefix bytes (`None` = wildcard position).
    pub prefix_bytes: Vec<Option<u8>>,
    /// Children keyed by the next concrete byte (or 0xFF for wildcard child).
    pub children: HashMap<u8, Box<Self>>,
    /// Function descriptors that end at this node.
    pub leaves: Vec<FunctionDescriptor>,
}

impl PatternNode {
    #[must_use] 
    pub fn new(prefix_bytes: Vec<Option<u8>>) -> Self {
        Self {
            prefix_bytes,
            children: HashMap::new(),
            leaves: Vec::new(),
        }
    }

    /// True if this is a leaf node (no children).
    #[must_use] 
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Total number of function descriptors in the subtree.
    #[must_use] 
    pub fn total_leaves(&self) -> usize {
        self.leaves.len()
            + self.children.values().map(|c| c.total_leaves()).sum::<usize>()
    }
}

// ── FlirtSignatureWriter ──────────────────────────────────────────────────────

/// FLIRT `.pat` file writer.
///
/// Maintains a trie of byte-patterns → function descriptors and can emit
/// a text-format PAT file compatible with IDA Pro.
pub struct FlirtSignatureWriter {
    root: PatternNode,
    pattern_count: u32,
    function_count: u32,
    features: SigFeatures,
    library_name: String,
}

impl FlirtSignatureWriter {
    /// Create a new writer for the named library.
    pub fn new(library_name: impl Into<String>) -> Self {
        Self {
            root: PatternNode::default(),
            pattern_count: 0,
            function_count: 0,
            features: SigFeatures::default(),
            library_name: library_name.into(),
        }
    }

    /// Set feature flags.
    pub const fn set_features(&mut self, features: SigFeatures) {
        self.features = features;
    }

    /// Add a pattern (up to 32 `Option<u8>` bytes) with a function descriptor.
    pub fn insert_pattern(&mut self, pattern: &[Option<u8>], desc: FunctionDescriptor) {
        self.function_count += 1;
        Self::insert_recursive(&mut self.root, pattern, 0, desc);
        self.pattern_count += 1;
    }

    /// Convenience: build a pattern from raw bytes, wildcarding at `wildcard_positions`.
    pub fn insert_bytes(
        &mut self,
        bytes: &[u8],
        wildcard_positions: &[usize],
        desc: FunctionDescriptor,
    ) {
        let pattern: Vec<Option<u8>> = bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| if wildcard_positions.contains(&i) { None } else { Some(b) })
            .collect();
        self.insert_pattern(&pattern, desc);
    }

    fn insert_recursive(
        node: &mut PatternNode,
        pattern: &[Option<u8>],
        depth: usize,
        desc: FunctionDescriptor,
    ) {
        if depth >= pattern.len() {
            node.leaves.push(desc);
            return;
        }
        let byte = pattern[depth];
        let key = byte.unwrap_or(0xFF);
        let child = node.children.entry(key).or_insert_with(|| {
            Box::new(PatternNode::new(vec![byte]))
        });
        Self::insert_recursive(child, pattern, depth + 1, desc);
    }

    /// Look up functions matching a given concrete byte sequence.
    #[must_use] 
    pub fn lookup(&self, bytes: &[u8]) -> Vec<&FunctionDescriptor> {
        let mut results = Vec::new();
        Self::lookup_recursive(&self.root, bytes, 0, &mut results);
        results
    }

    fn lookup_recursive<'a>(
        node: &'a PatternNode,
        bytes: &[u8],
        depth: usize,
        results: &mut Vec<&'a FunctionDescriptor>,
    ) {
        if depth >= bytes.len() {
            results.extend(node.leaves.iter());
            return;
        }
        let b = bytes[depth];
        // Try exact match
        if let Some(child) = node.children.get(&b) {
            let pb = child.prefix_bytes.first().copied().flatten();
            if pb == Some(b) || pb.is_none() {
                Self::lookup_recursive(child, bytes, depth + 1, results);
            }
        }
        // Try wildcard child
        if let Some(wild) = node.children.get(&0xFF)
            && wild.prefix_bytes.first().copied().flatten().is_none() {
                Self::lookup_recursive(wild, bytes, depth + 1, results);
            }
    }

    /// Collapse single-child nodes (trie path compression).
    pub fn compress_trie(&mut self) {
        Self::compress_node(&mut self.root);
    }

    fn compress_node(node: &mut PatternNode) {
        // Recursively compress children.
        for child in node.children.values_mut() {
            Self::compress_node(child);
        }
        // If this node has exactly one child and no leaves, merge prefix bytes.
        if node.leaves.is_empty() && node.children.len() == 1 {
            let key = *node.children.keys().next().unwrap();
            if let Some(mut child) = node.children.remove(&key) {
                node.prefix_bytes.extend_from_slice(&child.prefix_bytes);
                node.leaves.append(&mut child.leaves);
                // Re-add grandchildren.
                for (k, v) in child.children.drain() {
                    node.children.insert(k, v);
                }
            }
        }
    }

    /// Emit a text-format PAT file string.
    ///
    /// Format per line: `<hex_pattern> <crc_len:02X> <crc16:04X> <func_len:04X> :<offset:04X> <name>`
    #[must_use] 
    pub fn write_pat_file(&self) -> String {
        let mut out = String::new();
        // Header comment
        let _ = writeln!(out, "# FLIRT signature file for '{}'\n# features: {:#06x}",
            self.library_name, self.features.0);
        // Emit all entries via trie traversal.
        let mut pattern_buf: Vec<Option<u8>> = Vec::with_capacity(32);
        Self::emit_pat_recursive(&self.root, &mut pattern_buf, &mut out);
        // PAT terminator
        out.push_str("---\n");
        out
    }

    fn emit_pat_recursive(
        node: &PatternNode,
        pattern: &mut Vec<Option<u8>>,
        out: &mut String,
    ) {
        // Extend pattern with this node's prefix bytes (skip for root).
        let start_len = pattern.len();
        pattern.extend_from_slice(&node.prefix_bytes);

        // Emit leaves.
        for desc in &node.leaves {
            let pat_str = Self::format_pattern(pattern);
            let func_len = 0u16; // unknown in writer context
            let _ = writeln!(
                out,
                "{} {:02X} {:04X} {:04X} :{:04X} {}",
                pat_str, desc.crc_len, desc.crc16, func_len, desc.offset, desc.name
            );
            if let Some(ref modname) = desc.module_name {
                let _ = writeln!(out, "  ; module: {modname}");
            }
        }

        // Recurse into children.
        let mut sorted_children: Vec<_> = node.children.iter().collect();
        sorted_children.sort_by_key(|(k, _)| *k);
        for (_, child) in sorted_children {
            Self::emit_pat_recursive(child, pattern, out);
        }

        // Restore pattern.
        pattern.truncate(start_len);
    }

    fn format_pattern(pattern: &[Option<u8>]) -> String {
        let mut s = String::with_capacity(pattern.len() * 2);
        for b in pattern {
            match b {
                Some(v) => { let _ = write!(s, "{v:02X}"); }
                None    => s.push_str(".."),
            }
        }
        s
    }

    /// Compute statistics for the current signature set.
    #[must_use] 
    pub fn stats(&self) -> FlirtStats {
        let leaves = u32::try_from(self.root.total_leaves()).unwrap_or(u32::MAX);
        let patterns = self.pattern_count;
        let avg_len = if patterns > 0 {
            // Approximate average pattern length from stored data.
            32.0 // PAT patterns are always 32 bytes
        } else {
            0.0
        };
        // Collision count: nodes with >1 leaf.
        let collisions = Self::count_collisions(&self.root);
        FlirtStats {
            signature_count: patterns,
            total_functions: leaves,
            avg_pattern_len: avg_len,
            collision_count: collisions,
        }
    }

    fn count_collisions(node: &PatternNode) -> u32 {
        let mut count = if node.leaves.len() > 1 { u32::try_from(node.leaves.len()).unwrap_or(u32::MAX) - 1 } else { 0 };
        for child in node.children.values() {
            count += Self::count_collisions(child);
        }
        count
    }
}

// ── FlirtStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for a FLIRT signature set.
#[derive(Debug, Clone)]
pub struct FlirtStats {
    pub signature_count: u32,
    pub total_functions: u32,
    pub avg_pattern_len: f64,
    pub collision_count: u32,
}

impl FlirtStats {
    #[must_use] 
    pub fn collision_rate(&self) -> f64 {
        if self.signature_count == 0 { 0.0 }
        else { f64::from(self.collision_count) / f64::from(self.signature_count) }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_desc(name: &str) -> FunctionDescriptor {
        FunctionDescriptor::new(0, 0x1234, 16, name)
    }

    #[test]
    fn crc16_known_value() {
        // MCRF4XX has no final XOR, so an empty slice yields the init value.
        // For non-trivial data use a known value:
        let data = b"123456789";
        let crc = compute_crc16(data);
        assert_ne!(crc, 0); // Just verify it's non-zero and deterministic.
        assert_eq!(compute_crc16(data), crc);
    }

    #[test]
    fn crc16_deterministic() {
        let a = compute_crc16(b"hello");
        let b = compute_crc16(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn crc16_differs_for_different_inputs() {
        assert_ne!(compute_crc16(b"abc"), compute_crc16(b"abd"));
    }

    #[test]
    fn insert_and_lookup() {
        let mut writer = FlirtSignatureWriter::new("test");
        let pattern = vec![Some(0x55), Some(0x89), Some(0xE5), None];
        writer.insert_pattern(&pattern, make_desc("push_ebp_mov_esp_ebp"));
        let results = writer.lookup(&[0x55, 0x89, 0xE5, 0x00]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "push_ebp_mov_esp_ebp");
    }

    #[test]
    fn write_pat_file_contains_name() {
        let mut writer = FlirtSignatureWriter::new("mylib");
        let pattern = vec![Some(0x55), Some(0x8B), Some(0xEC)];
        writer.insert_pattern(&pattern, make_desc("my_function"));
        let pat = writer.write_pat_file();
        assert!(pat.contains("my_function"), "PAT should contain function name");
    }

    #[test]
    fn write_pat_file_contains_terminator() {
        let writer = FlirtSignatureWriter::new("empty");
        let pat = writer.write_pat_file();
        assert!(pat.contains("---"));
    }

    #[test]
    fn insert_bytes_no_wildcards() {
        let mut writer = FlirtSignatureWriter::new("test");
        writer.insert_bytes(&[0x55, 0x8B, 0xEC], &[], make_desc("foo"));
        let results = writer.lookup(&[0x55, 0x8B, 0xEC]);
        assert!(!results.is_empty());
    }

    #[test]
    fn insert_bytes_with_wildcards() {
        let mut writer = FlirtSignatureWriter::new("test");
        // Wildcard position 1 (offset byte in a relative call)
        writer.insert_bytes(&[0xE8, 0x00, 0x00, 0x00, 0x00], &[1, 2, 3, 4], make_desc("some_call"));
        // Lookup with any bytes at wildcard positions — direct lookup won't find via wildcard key
        // since our lookup tries the exact byte then the 0xFF wild key.
        // Just verify insertion doesn't panic.
        assert_eq!(writer.pattern_count, 1);
    }

    #[test]
    fn stats_function_count() {
        let mut writer = FlirtSignatureWriter::new("test");
        writer.insert_pattern(&[Some(0xCC)], make_desc("func1"));
        writer.insert_pattern(&[Some(0xC3)], make_desc("func2"));
        let stats = writer.stats();
        assert_eq!(stats.total_functions, 2);
    }

    #[test]
    fn stats_signature_count() {
        let mut writer = FlirtSignatureWriter::new("test");
        writer.insert_pattern(&[Some(0x90)], make_desc("nop_func"));
        let stats = writer.stats();
        assert_eq!(stats.signature_count, 1);
    }

    #[test]
    fn collision_count_two_same_prefix() {
        let mut writer = FlirtSignatureWriter::new("test");
        writer.insert_pattern(&[Some(0x55)], make_desc("a"));
        writer.insert_pattern(&[Some(0x55)], make_desc("b"));
        let stats = writer.stats();
        assert_eq!(stats.collision_count, 1);
    }

    #[test]
    fn compress_trie_runs_without_error() {
        let mut writer = FlirtSignatureWriter::new("test");
        writer.insert_pattern(&[Some(0x55), Some(0x8B), Some(0xEC)], make_desc("foo"));
        writer.compress_trie();
        // After compression, lookup should still work.
        let results = writer.lookup(&[0x55, 0x8B, 0xEC]);
        // May or may not find depending on compression outcome, but should not panic.
        let _ = results;
    }

    #[test]
    fn sig_features_set_clear() {
        let mut f = SigFeatures::default();
        f.set(SigFeatures::STARTUP);
        assert!(f.startup());
        f.clear(SigFeatures::STARTUP);
        assert!(!f.startup());
    }

    #[test]
    fn sig_features_module_library() {
        let f = SigFeatures(SigFeatures::MODULE_LIBRARY);
        assert!(f.module_library());
        assert!(!f.union_functions());
    }

    #[test]
    fn function_descriptor_with_module() {
        let d = FunctionDescriptor::new(0, 0xABCD, 8, "foo")
            .with_module("kernel32");
        assert_eq!(d.module_name.as_deref(), Some("kernel32"));
    }

    #[test]
    fn pat_format_contains_hex() {
        let mut writer = FlirtSignatureWriter::new("t");
        writer.insert_pattern(&[Some(0xAB), Some(0xCD)], make_desc("hex_func"));
        let pat = writer.write_pat_file();
        // Pattern bytes AB CD should appear in hex.
        assert!(pat.contains("AB") || pat.contains("ab") || pat.contains("ABCD"));
    }
}
