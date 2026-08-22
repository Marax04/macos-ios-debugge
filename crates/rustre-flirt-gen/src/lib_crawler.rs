//! `lib_crawler` — Crawl COFF/AR library archives and batch-extract FLIRT patterns.
//!
//! Parses `.lib` (COFF import/static library, AR format) and `.a` (GNU AR) archives,
//! extracts member `.obj` files, deduplicates identical functions, and produces a
//! consolidated batch of patterns ready for `PatternExtractor`.

use std::collections::HashMap;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CrawlError {
    TooShort,
    BadMagic,
    MemberTruncated { member: String, expected: usize, available: usize },
    Parse(String),
}

impl std::fmt::Display for CrawlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "data too short for archive"),
            Self::BadMagic => write!(f, "not a valid AR archive (bad magic)"),
            Self::MemberTruncated { member, expected, available } =>
                write!(f, "member {member}: expected {expected} bytes, only {available} available"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for CrawlError {}

// ── ArHeader ──────────────────────────────────────────────────────────────────

/// 60-byte AR member header (POSIX/BSD/GNU format).
#[derive(Debug, Clone)]
pub struct ArHeader {
    /// Member name (decoded from header, may reference long-name table).
    pub name: String,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Owner ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// File mode (octal).
    pub mode: u32,
    /// Size in bytes of member data.
    pub size: usize,
}

impl ArHeader {
    /// Parse a 60-byte AR header slice.
    fn parse(data: &[u8], long_names: &[u8]) -> Option<Self> {
        if data.len() < 60 { return None; }
        let name_raw = trim_ar_field(&data[0..16]);
        let timestamp = parse_ar_decimal(&data[16..28]).unwrap_or(0);
        let uid  = u32::try_from(parse_ar_decimal(&data[28..34]).unwrap_or(0)).unwrap_or(0);
        let gid  = u32::try_from(parse_ar_decimal(&data[34..40]).unwrap_or(0)).unwrap_or(0);
        let mode = u32::try_from(parse_ar_octal(&data[40..48]).unwrap_or(0)).unwrap_or(0);
        let size = usize::try_from(parse_ar_decimal(&data[48..58]).unwrap_or(0)).unwrap_or(0);
        // Validate terminator
        if data[58] != b'`' || data[59] != b'\n' { return None; }

        // Resolve long name
        let name = if name_raw.starts_with("//") {
            // Long names table entry itself
            "//".to_string()
        } else if name_raw.starts_with('/') && name_raw.len() > 1 {
            // GNU long name: offset into long-names table
            let off_str = &name_raw[1..];
            let off = off_str.trim().parse::<usize>().unwrap_or(0);
            read_long_name_at(long_names, off)
        } else if name_raw.ends_with('/') {
            // SYSV short name ending with /
            name_raw.trim_end_matches('/').to_string()
        } else {
            name_raw
        };

        Some(Self { name, timestamp, uid, gid, mode, size })
    }
}

fn trim_ar_field(data: &[u8]) -> String {
    String::from_utf8_lossy(data).trim_end_matches(' ').to_string()
}

fn parse_ar_decimal(data: &[u8]) -> Option<u64> {
    let s = String::from_utf8_lossy(data).trim().to_string();
    s.parse::<u64>().ok()
}

fn parse_ar_octal(data: &[u8]) -> Option<u64> {
    let s = String::from_utf8_lossy(data).trim().to_string();
    u64::from_str_radix(&s, 8).ok()
}

fn read_long_name_at(table: &[u8], off: usize) -> String {
    if off >= table.len() { return String::new(); }
    let end = table[off..].iter().position(|&b| b == b'/' || b == b'\n')
        .unwrap_or(table.len() - off);
    String::from_utf8_lossy(&table[off..off + end]).to_string()
}

// ── ArchiveMember ─────────────────────────────────────────────────────────────

/// A single member extracted from an archive.
#[derive(Debug, Clone)]
pub struct ArchiveMember {
    /// Member name (usually the .obj filename).
    pub name: String,
    /// Raw bytes of the member.
    pub data: Vec<u8>,
    /// Byte offset in the archive where this member starts.
    pub archive_offset: usize,
}

impl ArchiveMember {
    /// Best-effort determination of whether this member is a COFF object.
    #[must_use]
    pub fn looks_like_coff(&self) -> bool {
        if self.data.len() < 2 { return false; }
        let machine = u16::from_le_bytes([self.data[0], self.data[1]]);
        matches!(machine, 0x014C | 0x8664 | 0x01C4 | 0xAA64 | 0x0200 | 0x01C0)
    }
}

// ── CoffMember ────────────────────────────────────────────────────────────────

/// A confirmed COFF object member with pre-parsed machine type.
#[derive(Debug, Clone)]
pub struct CoffMember {
    pub name: String,
    pub machine: u16,
    pub data: Vec<u8>,
    pub archive_offset: usize,
}

// ── DuplicateResolver ─────────────────────────────────────────────────────────

/// Tracks and deduplicates functions across archive members.
pub struct DuplicateResolver {
    /// Map from function body hash to first-seen name.
    seen: HashMap<u64, String>,
    /// Number of duplicates suppressed.
    pub duplicates_removed: usize,
}

impl DuplicateResolver {
    #[must_use]
    pub fn new() -> Self { Self { seen: HashMap::new(), duplicates_removed: 0 } }

    /// Return true if this `(name, bytes)` pair is a duplicate.
    pub fn is_duplicate(&mut self, name: &str, bytes: &[u8]) -> bool {
        let h = fnv64(bytes);
        match self.seen.get(&h) {
            Some(existing) if existing == name => {
                self.duplicates_removed += 1;
                true
            }
            Some(_) => false, // Hash collision with different name — keep both
            None => {
                self.seen.insert(h, name.to_string());
                false
            }
        }
    }

    /// Reset state.
    pub fn reset(&mut self) {
        self.seen.clear();
        self.duplicates_removed = 0;
    }
}

impl Default for DuplicateResolver {
    fn default() -> Self { Self::new() }
}

/// FNV-1a 64-bit hash (fast, good for byte blobs).
fn fnv64(data: &[u8]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = BASIS;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ── LibCrawler ────────────────────────────────────────────────────────────────

/// Crawls COFF/AR library archives and exposes contained object members.
pub struct LibCrawler {
    /// Deduplicate identical function bodies.
    pub dedup: bool,
    /// Skip members whose names do not end in `.obj` or `.o`.
    pub filter_by_extension: bool,
}

impl Default for LibCrawler {
    fn default() -> Self { Self { dedup: true, filter_by_extension: false } }
}

impl LibCrawler {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Parse an AR-format archive and return all members.
    ///
    /// # Errors
    /// Returns [`CrawlError`] if the data is too short, has a bad magic, or a member is truncated.
    pub fn parse_archive(&self, data: &[u8]) -> Result<Vec<ArchiveMember>, CrawlError> {
        if data.len() < 8 { return Err(CrawlError::TooShort); }
        if &data[..8] != b"!<arch>\n" { return Err(CrawlError::BadMagic); }

        let mut pos = 8usize;
        let mut members = Vec::new();
        let mut long_names: Vec<u8> = Vec::new();

        // First pass: collect long-names table if present
        let mut scan = 8usize;
        while scan + 60 <= data.len() {
            if scan + 60 > data.len() { break; }
            let size = usize::try_from(parse_ar_decimal(&data[scan + 48..scan + 58]).unwrap_or(0)).unwrap_or(0);
            let name_raw = trim_ar_field(&data[scan..scan + 16]);
            if name_raw == "//" {
                let lstart = scan + 60;
                let lend = (lstart + size).min(data.len());
                long_names = data[lstart..lend].to_vec();
                break;
            }
            let skip = 60 + size + (size & 1);
            scan += skip;
        }

        while pos + 60 <= data.len() {
            let Some(hdr) = ArHeader::parse(&data[pos..pos + 60], &long_names) else { break };
            let data_start = pos + 60;
            let data_end = data_start + hdr.size;
            if data_end > data.len() {
                return Err(CrawlError::MemberTruncated {
                    member: hdr.name.clone(),
                    expected: hdr.size,
                    available: data.len() - data_start,
                });
            }

            let member_data = data[data_start..data_end].to_vec();
            let archive_offset = data_start;

            // Skip special members
            let n = &hdr.name;
            let ext_ok = !self.filter_by_extension || {
                let p = std::path::Path::new(n.as_str());
                p.extension().is_some_and(|e| e.eq_ignore_ascii_case("obj") || e.eq_ignore_ascii_case("o"))
            };
            if !n.is_empty() && n != "/" && n != "//" && n != "__SYMDEF"
                && !n.starts_with("__.SYMDEF") && ext_ok
            {
                members.push(ArchiveMember {
                    name: hdr.name.clone(),
                    data: member_data,
                    archive_offset,
                });
            }

            // Advance, respecting 2-byte alignment
            pos += 60 + hdr.size + (hdr.size & 1);
        }

        Ok(members)
    }

    /// Filter and wrap members that look like COFF objects.
    ///
    /// # Errors
    /// Returns [`CrawlError`] if archive parsing fails.
    pub fn coff_members_from_archive(&self, data: &[u8])
        -> Result<Vec<CoffMember>, CrawlError>
    {
        let members = self.parse_archive(data)?;
        let mut result = Vec::new();
        for m in members {
            if m.looks_like_coff() {
                let machine = u16::from_le_bytes([m.data[0], m.data[1]]);
                result.push(CoffMember {
                    name: m.name,
                    machine,
                    data: m.data,
                    archive_offset: m.archive_offset,
                });
            }
        }
        Ok(result)
    }

    /// Thin-archive check: COFF import libraries contain short stubs.
    #[must_use]
    pub fn is_thin_archive(data: &[u8]) -> bool {
        data.len() >= 8 && &data[..7] == b"!<thin>"
    }

    /// Detect duplicate COFF members by content hash.
    #[must_use]
    pub fn deduplicate_members(&self, members: Vec<CoffMember>) -> (Vec<CoffMember>, usize) {
        if !self.dedup { return (members, 0); }
        let mut seen: HashMap<u64, usize> = HashMap::new();
        let mut unique = Vec::new();
        let mut removed = 0usize;
        for m in members {
            let h = fnv64(&m.data);
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(h) {
                e.insert(unique.len());
                unique.push(m);
            } else {
                removed += 1;
            }
        }
        (unique, removed)
    }
}

// ── ArchiveStats ──────────────────────────────────────────────────────────────

/// Summary statistics for an archive crawl.
#[derive(Debug, Clone, Default)]
pub struct ArchiveStats {
    pub total_members: usize,
    pub coff_members: usize,
    pub duplicates_removed: usize,
    pub total_bytes_processed: usize,
    /// Machine type frequency.
    pub machine_types: HashMap<u16, usize>,
}

impl ArchiveStats {
    #[must_use]
    pub fn from_members(members: &[CoffMember], duplicates_removed: usize) -> Self {
        let mut machine_types = HashMap::new();
        let mut total_bytes = 0;
        for m in members {
            *machine_types.entry(m.machine).or_default() += 1;
            total_bytes += m.data.len();
        }
        Self {
            total_members: members.len() + duplicates_removed,
            coff_members: members.len(),
            duplicates_removed,
            total_bytes_processed: total_bytes,
            machine_types,
        }
    }

    #[must_use]
    pub const fn machine_name(machine: u16) -> &'static str {
        match machine {
            0x014C => "x86",    0x8664 => "x86_64",
            0x01C4 => "ARMv7",  0xAA64 => "ARM64",
            0x0200 => "IA-64",  0x01C0 => "ARM",
            _ => "unknown",
        }
    }
}

// ── Batch pattern input ───────────────────────────────────────────────────────

/// Consolidated function entry ready for pattern extraction.
#[derive(Debug, Clone)]
pub struct BatchFunctionEntry {
    /// Source library member name.
    pub member_name: String,
    /// Function name.
    pub func_name: String,
    /// Machine type.
    pub machine: u16,
    /// Raw function bytes.
    pub bytes: Vec<u8>,
    /// Relocation byte ranges (offset, size).
    pub relocs: Vec<(u32, u8)>,
}

/// Collect all function entries from a set of COFF members using a closure
/// that parses individual object files.
pub fn batch_collect<F>(members: &[CoffMember], extractor: F) -> Vec<BatchFunctionEntry>
where
    F: Fn(&CoffMember) -> Vec<(String, Vec<u8>, Vec<(u32, u8)>)>,
{
    let mut result = Vec::new();
    for member in members {
        for (name, bytes, relocs) in extractor(member) {
            result.push(BatchFunctionEntry {
                member_name: member.name.clone(),
                func_name: name,
                machine: member.machine,
                bytes,
                relocs,
            });
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ar_header(name: &[u8; 16], size: usize) -> Vec<u8> {
        let mut hdr = Vec::with_capacity(60);
        hdr.extend_from_slice(name);         // [0..16]  name
        hdr.extend_from_slice(b"0           "); // [16..28] timestamp (12 chars)
        hdr.extend_from_slice(b"0     ");    // [28..34] uid
        hdr.extend_from_slice(b"0     ");    // [34..40] gid
        hdr.extend_from_slice(b"100644  ");  // [40..48] mode
        let size_str = format!("{size:<10}");
        hdr.extend_from_slice(size_str.as_bytes()); // [48..58] size
        hdr.push(b'`');
        hdr.push(b'\n');
        assert_eq!(hdr.len(), 60);
        hdr
    }

    fn make_minimal_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data = b"!<arch>\n".to_vec();
        for (name, content) in members {
            let mut name_padded = [b' '; 16];
            let nb = name.as_bytes();
            let copy = nb.len().min(15);
            name_padded[..copy].copy_from_slice(&nb[..copy]);
            name_padded[copy] = b'/';
            data.extend_from_slice(&make_ar_header(&name_padded, content.len()));
            data.extend_from_slice(content);
            if content.len() & 1 != 0 { data.push(b'\n'); }
        }
        data
    }

    #[test]
    fn parse_empty_archive() {
        let data = b"!<arch>\n";
        let crawler = LibCrawler::new();
        let members = crawler.parse_archive(data).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn parse_archive_bad_magic() {
        let data = b"notanarch\n";
        let crawler = LibCrawler::new();
        assert!(matches!(crawler.parse_archive(data), Err(CrawlError::BadMagic)));
    }

    #[test]
    fn parse_archive_too_short() {
        let crawler = LibCrawler::new();
        assert!(matches!(crawler.parse_archive(b"!<ar"), Err(CrawlError::TooShort)));
    }

    #[test]
    fn parse_archive_single_member() {
        let content = b"hello world";
        let archive = make_minimal_archive(&[("test.o", content)]);
        let crawler = LibCrawler::new();
        let members = crawler.parse_archive(&archive).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "test.o");
        assert_eq!(members[0].data, content);
    }

    #[test]
    fn parse_archive_two_members() {
        let archive = make_minimal_archive(&[("a.obj", b"aaa"), ("b.obj", b"bbbb")]);
        let crawler = LibCrawler::new();
        let members = crawler.parse_archive(&archive).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "a.obj");
        assert_eq!(members[1].name, "b.obj");
    }

    #[test]
    fn archive_member_looks_like_coff_true() {
        // x86_64 machine type
        let data = [0x64u8, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let m = ArchiveMember { name: "f.obj".to_string(), data: data.to_vec(), archive_offset: 0 };
        assert!(m.looks_like_coff());
    }

    #[test]
    fn archive_member_looks_like_coff_false() {
        let m = ArchiveMember { name: "f.txt".to_string(), data: vec![0x41, 0x42], archive_offset: 0 };
        assert!(!m.looks_like_coff());
    }

    #[test]
    fn duplicate_resolver_detects_dup() {
        let mut resolver = DuplicateResolver::new();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        assert!(!resolver.is_duplicate("foo", &bytes));
        assert!(resolver.is_duplicate("foo", &bytes));
        assert_eq!(resolver.duplicates_removed, 1);
    }

    #[test]
    fn duplicate_resolver_different_names_same_bytes() {
        let mut resolver = DuplicateResolver::new();
        let bytes = vec![0x55u8, 0x48];
        assert!(!resolver.is_duplicate("foo", &bytes));
        // Same hash but different name — keep
        assert!(!resolver.is_duplicate("bar", &bytes));
    }

    #[test]
    fn duplicate_resolver_reset() {
        let mut resolver = DuplicateResolver::new();
        let bytes = vec![0x55u8];
        resolver.is_duplicate("x", &bytes);
        resolver.reset();
        assert!(!resolver.is_duplicate("x", &bytes));
        assert_eq!(resolver.duplicates_removed, 0);
    }

    #[test]
    fn fnv64_deterministic() {
        let a = fnv64(b"hello");
        let b = fnv64(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv64_different_inputs() {
        assert_ne!(fnv64(b"foo"), fnv64(b"bar"));
    }

    #[test]
    fn lib_crawler_dedup_members() {
        let crawler = LibCrawler { dedup: true, ..Default::default() };
        let m = CoffMember { name: "a.obj".to_string(), machine: 0x8664,
            data: vec![0x64u8, 0x86], archive_offset: 0 };
        let members = vec![m.clone(), m];
        let (unique, removed) = crawler.deduplicate_members(members);
        assert_eq!(unique.len(), 1);
        assert_eq!(removed, 1);
    }

    #[test]
    fn archive_stats_machine_name() {
        assert_eq!(ArchiveStats::machine_name(0x8664), "x86_64");
        assert_eq!(ArchiveStats::machine_name(0x014C), "x86");
        assert_eq!(ArchiveStats::machine_name(0x0001), "unknown");
    }

    #[test]
    fn is_thin_archive_false() {
        assert!(!LibCrawler::is_thin_archive(b"!<arch>\n"));
    }

    #[test]
    fn batch_collect_empty() {
        let members: Vec<CoffMember> = vec![];
        let result = batch_collect(&members, |_| vec![]);
        assert!(result.is_empty());
    }
}
