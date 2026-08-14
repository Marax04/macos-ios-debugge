//! `sig_writer` — Write IDA-compatible .sig v9 binary signature files.
//!
//! Encodes a flat list of patterns into a compact trie, emits the 104-byte
//! .sig header, serialises collision lists and module entries, and produces
//! a byte-for-byte compatible .sig file that IDA Pro can load.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

// ── SigHeader ─────────────────────────────────────────────────────────────────

/// .sig v9 file header (104 bytes, little-endian).
#[derive(Debug, Clone)]
pub struct SigHeader {
    /// CPU architecture: 0 = x86, 75 = `x86_64`.
    pub arch: u8,
    /// IDA file-type bitmask (e.g. 0x0002 = PE).
    pub file_types: u32,
    /// IDA OS-type bitmask (e.g. 0x0002 = Win32).
    pub os_types: u16,
    /// Application-type bitmask.
    pub app_types: u16,
    /// Feature flags.
    pub feature_flags: u16,
    /// Number of functions encoded.
    pub num_functions: u32,
    /// Pattern size (leading bytes, default 32).
    pub pattern_size: u16,
    /// Library name (up to 63 bytes, null-terminated, padded to 64).
    pub library_name: String,
}

impl Default for SigHeader {
    fn default() -> Self {
        Self {
            arch: 75, file_types: 0x0002, os_types: 0x0002,
            app_types: 0x0001, feature_flags: 0, num_functions: 0,
            pattern_size: 32, library_name: String::new(),
        }
    }
}

impl SigHeader {
    /// Serialise the header in the published IDA layout.
    ///
    /// BUG FIX: this used to emit a fixed 104 bytes with `num_functions` as a
    /// `u32` at offset 34 and the library name in a fixed 40..104 window. Offset
    /// 34 is IDA's one-byte `library_name_len`, so files written this way could
    /// not be read by anything that follows the published layout — including
    /// IDA itself. Now delegated to the single codec in
    /// [`rustre_flirt::sig_header`]; the header is **variable length**.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use rustre_flirt::sig_header::SigFileHeader;

        let mut h = SigFileHeader {
            version: 9,
            arch: self.arch,
            file_types: self.file_types,
            os_types: self.os_types,
            app_types: self.app_types,
            feature_flags: self.feature_flags,
            n_functions: self.num_functions,
            pattern_size: self.pattern_size,
            lib_name: self.library_name.clone(),
            ..SigFileHeader::default()
        };
        // The CRC covers the bytes preceding its own slot, so encode once with a
        // zero placeholder, compute over [0..20), then re-encode with the value.
        h.crc16 = 0;
        let probe = h.encode();
        h.crc16 = crc16_header(&probe[..20]);
        h.encode()
    }
}

// ── CRC-16 (header variant, non-reflected) ───────────────────────────────────

fn crc16_header(data: &[u8]) -> u16 {
    rustre_flirt::crc::cms(data)
}

// ── ModuleEntry ───────────────────────────────────────────────────────────────

/// A named module at a specific offset (used in .sig trie leaves).
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// Byte offset of the primary name within the matched function.
    pub offset: u16,
    /// Function name.
    pub name: String,
    /// CRC-16 over the tail region.
    pub crc16: u16,
    /// Number of bytes covered by the CRC.
    pub crc_len: u8,
    /// Total function length in bytes.
    pub func_len: u16,
    /// Any referenced names (secondary labels at fixed offsets).
    pub referenced: Vec<(u16, String)>,
}

impl ModuleEntry {
    /// Encode this entry into the trie leaf payload.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.crc_len);
        buf.extend_from_slice(&self.crc16.to_le_bytes());
        buf.extend_from_slice(&self.func_len.to_le_bytes());
        // Flags: 0x00 = last name, 0x01 = more names follow
        let has_refs = !self.referenced.is_empty();
        buf.push(u8::from(has_refs));
        buf.extend_from_slice(&self.offset.to_le_bytes());
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len().min(1023);
        buf.extend_from_slice(&u16::try_from(name_len).unwrap_or(1023).to_le_bytes());
        buf.extend_from_slice(&name_bytes[..name_len]);
        for (ref_off, ref_name) in &self.referenced {
            buf.push(0x00); // continuation marker
            buf.extend_from_slice(&ref_off.to_le_bytes());
            let rn = ref_name.as_bytes();
            let rlen = rn.len().min(1023);
            buf.extend_from_slice(&u16::try_from(rlen).unwrap_or(1023).to_le_bytes());
            buf.extend_from_slice(&rn[..rlen]);
        }
    }
}

// ── CollisionEntry ────────────────────────────────────────────────────────────

/// A collision list entry when two functions share the same leading pattern.
#[derive(Debug, Clone)]
pub struct CollisionEntry {
    pub modules: Vec<ModuleEntry>,
}

impl CollisionEntry {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        for (i, m) in self.modules.iter().enumerate() {
            if i > 0 { buf.push(0x80); } // collision separator
            m.encode(buf);
        }
    }
}

// ── PatternTrieNode ───────────────────────────────────────────────────────────

/// Internal trie node for the .sig binary format.
#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<u8, Box<Self>>,
    leaves: Vec<ModuleEntry>,
}

impl TrieNode {
    fn insert(&mut self, pattern: &[Option<u8>], pos: usize, entry: ModuleEntry) {
        if pos >= pattern.len() {
            self.leaves.push(entry);
            return;
        }
        match pattern[pos] {
            Some(byte) => {
                self.children.entry(byte).or_insert_with(|| Box::new(Self::default()))
                    .insert(pattern, pos + 1, entry);
            }
            None => {
                // Wildcard — treat as end of discriminating prefix, push as leaf
                self.leaves.push(entry);
            }
        }
    }

    fn encode(&self, buf: &mut Vec<u8>, depth: u32) {
        // Encode leaves at this node
        for (i, leaf) in self.leaves.iter().enumerate() {
            if i > 0 { buf.push(0x80); } // collision
            leaf.encode(buf);
        }
        if !self.leaves.is_empty() && !self.children.is_empty() {
            buf.push(0x80); // separator between leaves and children
        }
        // Encode children sorted for deterministic output
        let mut children: Vec<(u8, &Box<Self>)> = self.children.iter().map(|(&b, n)| (b, n)).collect();
        children.sort_by_key(|&(b, _)| b);
        for (i, (byte, child)) in children.iter().enumerate() {
            buf.push(*byte);
            child.encode(buf, depth + 1);
            if i + 1 < children.len() {
                buf.push(0xFF); // child separator
            }
        }
        if depth > 0 {
            buf.push(0x00); // end-of-children sentinel
        }
    }
}

// ── PatternTrie ───────────────────────────────────────────────────────────────

/// The full pattern trie for a .sig file.
pub struct PatternTrie {
    root: TrieNode,
    pub entry_count: usize,
}

impl PatternTrie {
    #[must_use]
    pub fn new() -> Self { Self { root: TrieNode::default(), entry_count: 0 } }

    /// Insert a pattern entry.
    pub fn insert(&mut self, pattern: &[Option<u8>], entry: ModuleEntry) {
        self.root.insert(pattern, 0, entry);
        self.entry_count += 1;
    }

    /// Serialise the trie to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.root.encode(&mut buf, 0);
        buf.push(0x00); // end sentinel
        buf
    }
}

impl Default for PatternTrie {
    fn default() -> Self { Self::new() }
}

// ── RawPattern ────────────────────────────────────────────────────────────────

/// Input pattern for `SigWriter`.
#[derive(Debug, Clone)]
pub struct RawPattern {
    /// Leading bytes (up to `pattern_size`), None = wildcard.
    pub leading: Vec<Option<u8>>,
    /// CRC length.
    pub crc_len: u8,
    /// CRC-16.
    pub crc16: u16,
    /// Total function byte length.
    pub func_len: u16,
    /// Primary function name.
    pub name: String,
    /// Secondary names (offset, name).
    pub referenced: Vec<(u16, String)>,
}

// ── SigWriter ─────────────────────────────────────────────────────────────────

/// Serialises a collection of `RawPattern`s into an IDA .sig v9 binary.
pub struct SigWriter {
    pub header: SigHeader,
    patterns: Vec<RawPattern>,
}

impl SigWriter {
    #[must_use]
    pub fn new(lib_name: &str, arch: u8) -> Self {
        Self {
            header: SigHeader { library_name: lib_name.to_string(), arch, ..Default::default() },
            patterns: Vec::new(),
        }
    }

    /// Add a single pattern.
    pub fn add(&mut self, pat: RawPattern) {
        self.patterns.push(pat);
    }

    /// Add patterns from leading bytes (each encoded as hex nibbles; '..' = wildcard).
    pub fn add_from_hex(&mut self, hex: &str, crc16: u16, crc_len: u8,
                        func_len: u16, name: &str) {
        let leading = parse_hex_pattern(hex);
        self.patterns.push(RawPattern {
            leading, crc_len, crc16, func_len,
            name: name.to_string(), referenced: Vec::new(),
        });
    }

    /// Build and return the complete .sig file bytes.
    ///
    /// BUG FIX: this used to encode the trie with the private [`PatternTrie`]
    /// below, whose byte layout `rustre_flirt_apply::sig_file_loader` cannot
    /// decode — measured: a file written this way yielded **zero** signatures
    /// while the same patterns through [`crate::SigWriter`] yielded one. Two
    /// trie encoders, only one readable, and the unreadable one failed
    /// *silently*: the loader returned an empty set, which downstream is
    /// indistinguishable from "this binary contains no known functions".
    ///
    /// Both writers now emit the one encoding the loader understands.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

        let pats: Vec<FlirtPattern> = self
            .patterns
            .iter()
            .map(|p| {
                let mut fp = FlirtPattern::new(
                    p.leading
                        .iter()
                        .map(|b| b.map_or(PatternByte::Wildcard, PatternByte::Exact))
                        .collect(),
                );
                fp.crc16 = p.crc16;
                fp.crc_length = p.crc_len;
                fp.pattern_length = p.func_len;
                fp.names.push(FlirtName {
                    name: p.name.clone(),
                    offset: 0,
                    is_public: true,
                    is_local: false,
                });
                for (off, rname) in &p.referenced {
                    fp.names.push(FlirtName {
                        name: rname.clone(),
                        offset: *off,
                        is_public: false,
                        is_local: false,
                    });
                }
                fp
            })
            .collect();

        let writer = crate::SigWriter {
            arch: self.header.arch,
            file_types: self.header.file_types,
            os_types: self.header.os_types,
            app_types: self.header.app_types,
            feature_flags: self.header.feature_flags,
        };
        writer.build(&pats, &self.header.library_name)
    }

    /// Write the .sig file to `path`.
    ///
    /// # Errors
    /// Returns an [`io::Error`] if the file cannot be created or written.
    pub fn write_to_path(&self, path: &Path) -> io::Result<()> {
        let bytes = self.build();
        let mut f = std::fs::File::create(path)?;
        f.write_all(&bytes)
    }

    /// Return the number of patterns added.
    #[must_use]
    pub const fn pattern_count(&self) -> usize { self.patterns.len() }
}

// ── Hex pattern parser ─────────────────────────────────────────────────────────

/// Parse a hex-pattern string (e.g. `"5548..E5"`) into `Vec<Option<u8>>`.
#[must_use]
pub fn parse_hex_pattern(s: &str) -> Vec<Option<u8>> {
    let s = s.replace(' ', "");
    let mut result = Vec::new();
    let bytes_str: Vec<&str> = s.as_bytes().chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("00"))
        .collect();
    for chunk in bytes_str {
        if chunk == ".." || chunk == "??" {
            result.push(None);
        } else {
            let v = u8::from_str_radix(chunk, 16).unwrap_or(0);
            result.push(Some(v));
        }
    }
    result
}

/// Format a leading-bytes pattern as a hex string with `..` for wildcards.
#[must_use]
pub fn format_pattern(pattern: &[Option<u8>]) -> String {
    pattern.iter().map(|b| b.map_or_else(|| "..".to_string(), |v| format!("{v:02X}"))).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_header_magic() {
        let hdr = SigHeader::default();
        let bytes = hdr.to_bytes();
        assert_eq!(&bytes[..6], b"IDASGN");
        assert_eq!(bytes[6], 9);
    }

    #[test]
    fn sig_header_version() {
        let hdr = SigHeader::default();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[6], 9);
    }

    #[test]
    fn sig_header_arch_byte() {
        let hdr = SigHeader { arch: 0, ..Default::default() };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[7], 0);
    }

    #[test]
    fn sig_header_library_name_embedded() {
        // Verified by decoding with the canonical codec rather than by poking a
        // fixed 40..104 window: that window was the old, wrong layout.
        let hdr = SigHeader { library_name: "mylib".to_string(), ..Default::default() };
        let bytes = hdr.to_bytes();
        let decoded = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("l'header scritto deve essere leggibile dal codec canonico");
        assert_eq!(decoded.lib_name, "mylib");
    }

    #[test]
    fn sig_header_length_is_variable_not_104() {
        // The IDA header ends where the library name ends; a fixed 104 was the
        // defect, not the spec.
        let hdr = SigHeader { library_name: "abc".to_string(), ..Default::default() };
        assert_eq!(hdr.to_bytes().len(), 43 + 3);
        let empty = SigHeader { library_name: String::new(), ..Default::default() };
        assert_eq!(empty.to_bytes().len(), 43);
        assert_eq!(hdr.to_bytes()[6], 9, "versione 9");
    }

    #[test]
    fn sig_header_crc_not_zero() {
        let hdr = SigHeader { library_name: "test".to_string(), ..Default::default() };
        let bytes = hdr.to_bytes();
        let crc = u16::from_le_bytes([bytes[20], bytes[21]]);
        assert_ne!(crc, 0);
    }

    #[test]
    fn parse_hex_pattern_basic() {
        let p = parse_hex_pattern("5548..E5");
        assert_eq!(p, vec![Some(0x55), Some(0x48), None, Some(0xE5)]);
    }

    #[test]
    fn parse_hex_pattern_all_wildcards() {
        let p = parse_hex_pattern("....");
        assert_eq!(p, vec![None, None]);
    }

    #[test]
    fn format_pattern_roundtrip() {
        let p = vec![Some(0xAB), None, Some(0xCD)];
        let s = format_pattern(&p);
        assert_eq!(s, "AB..CD");
    }

    #[test]
    fn sig_writer_empty() {
        let writer = SigWriter::new("lib", 75);
        let bytes = writer.build();
        assert_eq!(&bytes[..6], b"IDASGN");
        assert_eq!(bytes[6], 9);
    }

    #[test]
    fn sig_writer_one_pattern() {
        let mut writer = SigWriter::new("testlib", 75);
        writer.add_from_hex("5548..E5C3", 0xABCD, 4, 10, "func_a");
        assert_eq!(writer.pattern_count(), 1);
        let bytes = writer.build();
        let num = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("il file scritto deve decodificarsi")
            .n_functions;
        assert_eq!(num, 1);
    }

    #[test]
    fn sig_writer_two_patterns() {
        let mut writer = SigWriter::new("lib2", 0);
        writer.add_from_hex("5548", 0x1234, 2, 5, "f1");
        writer.add_from_hex("564889", 0x5678, 3, 8, "f2");
        assert_eq!(writer.pattern_count(), 2);
        let bytes = writer.build();
        let num = rustre_flirt::sig_header::SigFileHeader::decode(&bytes)
            .expect("il file scritto deve decodificarsi")
            .n_functions;
        assert_eq!(num, 2);
    }

    #[test]
    fn module_entry_encode_basic() {
        let entry = ModuleEntry {
            offset: 0, name: "foo".to_string(),
            crc16: 0x1234, crc_len: 4, func_len: 32, referenced: vec![],
        };
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        assert!(!buf.is_empty());
        assert_eq!(buf[0], 4); // crc_len
    }

    #[test]
    fn pattern_trie_encode_nonempty() {
        let mut trie = PatternTrie::new();
        trie.insert(&[Some(0x55), Some(0x48)], ModuleEntry {
            offset: 0, name: "test".to_string(),
            crc16: 0, crc_len: 0, func_len: 8, referenced: vec![],
        });
        let encoded = trie.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn sig_writer_write_to_path() {
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_test_sig_writer.sig");
        let mut writer = SigWriter::new("libtest", 75);
        writer.add_from_hex("5548E5C3", 0x1111, 2, 8, "func_test");
        writer.write_to_path(&path).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[..6], b"IDASGN");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn crc16_header_deterministic() {
        let data = b"IDASGN\x09\x4B";
        let a = crc16_header(data);
        let b = crc16_header(data);
        assert_eq!(a, b);
    }
}
