//! PDF cross-reference table and stream parser.
//!
//! Handles both traditional `xref` keyword tables (PDF 1.0–1.4) and compressed
//! xref streams (PDF 1.5+).

use std::collections::HashMap;
use std::fmt;

// ─── XrefKind ─────────────────────────────────────────────────────────────────

/// The kind of a cross-reference entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// Free object (type 0).  `offset` holds the next free object number.
    Free,
    /// Uncompressed in-use object (type 1).  `offset` is a file byte offset.
    InUse,
    /// Compressed object inside an object stream (type 2).
    /// `offset` holds the object-stream number; `generation` holds the index
    /// within that stream.
    Compressed,
}

impl fmt::Display for XrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => write!(f, "free"),
            Self::InUse => write!(f, "in-use"),
            Self::Compressed => write!(f, "compressed"),
        }
    }
}

// ─── XrefEntry ────────────────────────────────────────────────────────────────

/// A single cross-reference entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrefEntry {
    /// Object number.
    pub object_number: u32,
    /// Generation number.
    pub generation: u32,
    /// Byte offset (type 1) or stream object number (type 2).
    pub offset: u64,
    /// Entry kind.
    pub kind: XrefKind,
}

impl XrefEntry {
    /// Create an in-use entry.
    #[must_use]
    pub const fn in_use(object_number: u32, generation: u32, offset: u64) -> Self {
        Self { object_number, generation, offset, kind: XrefKind::InUse }
    }

    /// Create a free entry.
    #[must_use]
    pub const fn free(object_number: u32, generation: u32, next_free: u64) -> Self {
        Self { object_number, generation, offset: next_free, kind: XrefKind::Free }
    }

    /// Create a compressed entry.
    #[must_use]
    pub const fn compressed(object_number: u32, stream_obj: u64, index_in_stream: u32) -> Self {
        Self {
            object_number,
            generation: index_in_stream,
            offset: stream_obj,
            kind: XrefKind::Compressed,
        }
    }

    /// Returns `true` if the entry is usable (in-use or compressed).
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self.kind, XrefKind::InUse | XrefKind::Compressed)
    }
}

impl fmt::Display for XrefEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "obj {} gen {} @ {:#x} ({})",
            self.object_number, self.generation, self.offset, self.kind
        )
    }
}

// ─── XrefSubsection ───────────────────────────────────────────────────────────

/// A subsection of a traditional xref table: a run of consecutive object numbers.
#[derive(Debug, Clone)]
pub struct XrefSubsection {
    /// First object number in this subsection.
    pub first_object: u32,
    /// Entries in this subsection.
    pub entries: Vec<XrefEntry>,
}

impl XrefSubsection {
    /// Create a new subsection.
    #[must_use]
    pub const fn new(first_object: u32) -> Self {
        Self { first_object, entries: Vec::new() }
    }

    /// Number of entries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

// ─── CrossRefTable ────────────────────────────────────────────────────────────

/// A merged cross-reference table built from one or more xref sections/streams.
#[derive(Debug, Default, Clone)]
pub struct CrossRefTable {
    entries: HashMap<u32, XrefEntry>,
    /// The byte offsets of all `startxref` values in the file (for chained xrefs).
    pub startxref_offsets: Vec<u64>,
}

impl CrossRefTable {
    /// Create an empty cross-reference table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge entries from a subsection.  Earlier entries win (revision chaining).
    pub fn merge_subsection(&mut self, subsection: XrefSubsection) {
        for entry in subsection.entries {
            self.entries.entry(entry.object_number).or_insert(entry);
        }
    }

    /// Insert a single entry (earlier entries win).
    pub fn insert(&mut self, entry: XrefEntry) {
        self.entries.entry(entry.object_number).or_insert(entry);
    }

    /// Look up an entry by object number.
    #[must_use]
    pub fn get(&self, object_number: u32) -> Option<&XrefEntry> {
        self.entries.get(&object_number)
    }

    /// Number of entries (free + in-use + compressed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All in-use entries sorted by object number.
    #[must_use]
    pub fn live_entries(&self) -> Vec<&XrefEntry> {
        let mut v: Vec<&XrefEntry> = self.entries.values().filter(|e| e.is_live()).collect();
        v.sort_by_key(|e| e.object_number);
        v
    }

    /// All free entries sorted by object number.
    #[must_use]
    pub fn free_entries(&self) -> Vec<&XrefEntry> {
        let mut v: Vec<&XrefEntry> = self
            .entries
            .values()
            .filter(|e| e.kind == XrefKind::Free)
            .collect();
        v.sort_by_key(|e| e.object_number);
        v
    }

    /// Highest object number present.
    #[must_use]
    pub fn max_object_number(&self) -> Option<u32> {
        self.entries.keys().copied().max()
    }

    /// Validate that all in-use byte offsets are within `file_len`.
    #[must_use]
    pub fn validate_offsets(&self, file_len: usize) -> Vec<u32> {
        let mut bad = Vec::new();
        for e in self.entries.values() {
            if e.kind == XrefKind::InUse && e.offset as usize >= file_len {
                bad.push(e.object_number);
            }
        }
        bad.sort_unstable();
        bad
    }
}

// ─── PdfXrefParser ────────────────────────────────────────────────────────────

/// Parses PDF cross-reference tables and streams from a raw byte slice.
pub struct PdfXrefParser<'a> {
    data: &'a [u8],
}

impl<'a> PdfXrefParser<'a> {
    /// Create a new parser for `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Locate the last `startxref` keyword and return the xref byte offset.
    #[must_use]
    pub fn find_startxref(&self) -> Option<u64> {
        let needle = b"startxref";
        // Search backward for the last occurrence.
        let pos = self.data
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .next_back()?;

        let after_needle = pos + needle.len();
        let slice = self.data.get(after_needle..)?;
        let skip = slice.iter().take_while(|&&b| b == b'\n' || b == b'\r' || b == b' ').count();
        let num_slice = &slice[skip..];
        let num_len = num_slice.iter().take_while(|&&b| b.is_ascii_digit()).count();
        let s = std::str::from_utf8(&num_slice[..num_len]).ok()?;
        s.parse().ok()
    }

    /// Collect all `startxref` offsets (from oldest to newest revision).
    #[must_use]
    pub fn find_all_startxref(&self) -> Vec<u64> {
        let needle = b"startxref";
        let mut offsets = Vec::new();
        let mut search = 0usize;
        while search + needle.len() <= self.data.len() {
            let found = self.data[search..]
                .windows(needle.len())
                .position(|w| w == needle);
            let pos = match found {
                Some(p) => search + p,
                None => break,
            };
            let after = pos + needle.len();
            if let Some(slice) = self.data.get(after..) {
                let skip = slice.iter().take_while(|&&b| matches!(b, b'\n' | b'\r' | b' ')).count();
                let num_slice = &slice[skip..];
                let num_len = num_slice.iter().take_while(|&&b| b.is_ascii_digit()).count();
                if let Ok(s) = std::str::from_utf8(&num_slice[..num_len])
                    && let Ok(n) = s.parse::<u64>() {
                        offsets.push(n);
                    }
            }
            search = pos + needle.len();
        }
        offsets
    }

    /// Parse a traditional `xref` table starting at `offset`.
    ///
    /// Returns the parsed subsections.
    #[must_use]
    pub fn parse_xref_table(&self, offset: usize) -> Vec<XrefSubsection> {
        let mut subsections = Vec::new();
        if self.data.get(offset..offset + 4) != Some(b"xref") {
            return subsections;
        }
        let mut pos = offset + 4;
        pos = self.skip_whitespace(pos);

        loop {
            // Check for "trailer" keyword.
            if pos + 7 <= self.data.len() && &self.data[pos..pos + 7] == b"trailer" {
                break;
            }
            if pos >= self.data.len() {
                break;
            }
            // Parse subsection header "first_obj count".
            let line_end = self.data[pos..]
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
                .unwrap_or(self.data.len() - pos);
            let header = std::str::from_utf8(&self.data[pos..pos + line_end]).unwrap_or("");
            let parts: Vec<&str> = header.split_ascii_whitespace().collect();
            if parts.len() < 2 {
                break;
            }
            let first_obj: u32 = parts[0].parse().unwrap_or(0);
            let count: u32 = parts[1].parse().unwrap_or(0);
            pos += line_end + 1;
            if self.data.get(pos) == Some(&b'\r') {
                pos += 1;
            }

            let mut subsection = XrefSubsection::new(first_obj);
            for i in 0..count {
                if pos + 20 > self.data.len() {
                    break;
                }
                let entry_bytes = &self.data[pos..pos + 20];
                if let Ok(s) = std::str::from_utf8(entry_bytes) {
                    let ep: Vec<&str> = s.split_ascii_whitespace().collect();
                    if ep.len() >= 3 {
                        let offset_val: u64 = ep[0].parse().unwrap_or(0);
                        let gen_val: u32 = ep[1].parse().unwrap_or(0);
                        let kind_char = ep[2];
                        let obj_num = match first_obj.checked_add(i) {
                            Some(n) => n,
                            None => break, // integer overflow on malformed xref
                        };
                        let entry = if kind_char == "n" {
                            XrefEntry::in_use(obj_num, gen_val, offset_val)
                        } else {
                            XrefEntry::free(obj_num, gen_val, offset_val)
                        };
                        subsection.entries.push(entry);
                    }
                }
                pos += 20;
            }
            subsections.push(subsection);
            pos = self.skip_whitespace(pos);
        }
        subsections
    }

    /// Parse a compressed xref stream at `offset`.
    ///
    /// `w` is the `/W` array (field widths).  `index` is the `/Index` array
    /// (pairs of first-obj, count).  `stream_data` is the raw (possibly
    /// decompressed) stream bytes.
    #[must_use]
    pub fn parse_xref_stream(
        stream_data: &[u8],
        w: &[usize; 3],
        index: &[(u32, u32)],
    ) -> Vec<XrefEntry> {
        let row_size = w[0] + w[1] + w[2];
        if row_size == 0 {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let mut data_pos = 0usize;
        for &(first_obj, count) in index {
            for i in 0..count {
                if data_pos + row_size > stream_data.len() {
                    break;
                }
                let row = &stream_data[data_pos..data_pos + row_size];
                let field_type = read_be_uint(row, 0, w[0]);
                let field2 = read_be_uint(row, w[0], w[1]);
                let field3 = read_be_uint(row, w[0] + w[1], w[2]);
                let obj_num = match first_obj.checked_add(i) {
                    Some(n) => n,
                    None => { data_pos += row_size; continue; } // overflow: skip entry
                };
                let entry = match field_type {
                    0 => XrefEntry::free(obj_num, field3 as u32, field2),
                    1 => XrefEntry::in_use(obj_num, field3 as u32, field2),
                    2 => XrefEntry::compressed(obj_num, field2, field3 as u32),
                    _ => {
                        data_pos += row_size;
                        continue;
                    }
                };
                entries.push(entry);
                data_pos += row_size;
            }
        }
        entries
    }

    /// Full parse: locate `startxref`, resolve all revisions, return a merged table.
    #[must_use]
    pub fn build_cross_ref_table(&self) -> CrossRefTable {
        let mut table = CrossRefTable::new();
        let startxref_offsets = self.find_all_startxref();
        for &off in &startxref_offsets {
            table.startxref_offsets.push(off);
            let offset = off as usize;
            if offset + 4 > self.data.len() {
                continue;
            }
            if self.data.get(offset..offset + 4) == Some(b"xref") {
                let subsections = self.parse_xref_table(offset);
                for sub in subsections {
                    table.merge_subsection(sub);
                }
            }
            // Compressed xref streams require a full PDF object parser;
            // we register the offset so callers can delegate.
        }
        table
    }

    fn skip_whitespace(&self, mut pos: usize) -> usize {
        while pos < self.data.len() && matches!(self.data[pos], b'\n' | b'\r' | b' ' | b'\t') {
            pos += 1;
        }
        pos
    }
}

/// Read a big-endian unsigned integer of `width` bytes from `data` starting at `offset`.
fn read_be_uint(data: &[u8], offset: usize, width: usize) -> u64 {
    if width == 0 {
        return 0;
    }
    let mut val = 0u64;
    for i in 0..width {
        if let Some(&b) = data.get(offset + i) {
            val = (val << 8) | u64::from(b);
        }
    }
    val
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xref_table_data() -> Vec<u8> {
        let mut d: Vec<u8> = b"%PDF-1.7\n".to_vec();
        d.extend_from_slice(b"1 0 obj\n<<>>\nendobj\n");
        let xref_off = d.len();
        d.extend_from_slice(b"xref\n0 3\n");
        d.extend_from_slice(b"0000000000 65535 f \r\n");
        d.extend_from_slice(b"0000000009 00000 n \r\n");
        d.extend_from_slice(b"0000000030 00001 n \r\n");
        d.extend_from_slice(b"trailer\n<<\n/Size 3\n>>\n");
        d.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        d
    }

    #[test]
    fn test_find_startxref() {
        let data = make_xref_table_data();
        let parser = PdfXrefParser::new(&data);
        let off = parser.find_startxref();
        assert!(off.is_some());
    }

    #[test]
    fn test_parse_xref_table_subsections() {
        let data = make_xref_table_data();
        let parser = PdfXrefParser::new(&data);
        let xref_off = parser.find_startxref().unwrap() as usize;
        let subs = parser.parse_xref_table(xref_off);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].count(), 3);
    }

    #[test]
    fn test_xref_kinds() {
        let data = make_xref_table_data();
        let parser = PdfXrefParser::new(&data);
        let xref_off = parser.find_startxref().unwrap() as usize;
        let subs = parser.parse_xref_table(xref_off);
        let entries = &subs[0].entries;
        assert_eq!(entries[0].kind, XrefKind::Free);
        assert_eq!(entries[1].kind, XrefKind::InUse);
        assert_eq!(entries[1].offset, 9);
    }

    #[test]
    fn test_build_cross_ref_table() {
        let data = make_xref_table_data();
        let table = PdfXrefParser::new(&data).build_cross_ref_table();
        assert!(table.len() > 0);
        let live = table.live_entries();
        assert!(!live.is_empty());
    }

    #[test]
    fn test_cross_ref_table_validate_offsets() {
        let mut table = CrossRefTable::new();
        table.insert(XrefEntry::in_use(1, 0, 5));
        table.insert(XrefEntry::in_use(2, 0, 99999));
        let bad = table.validate_offsets(100);
        assert_eq!(bad, vec![2]);
    }

    #[test]
    fn test_parse_xref_stream_type1() {
        let w = [1usize, 4, 2];
        let index = vec![(0u32, 2u32)];
        let stream: Vec<u8> = vec![
            // type=1, offset=0x00000009, gen=0
            1, 0, 0, 0, 9, 0, 0,
            // type=0, next_free=0, gen=0xFFFF
            0, 0, 0, 0, 0, 0xFF, 0xFF,
        ];
        let entries = PdfXrefParser::parse_xref_stream(&stream, &w, &index);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, XrefKind::InUse);
        assert_eq!(entries[0].offset, 9);
        assert_eq!(entries[1].kind, XrefKind::Free);
    }

    #[test]
    fn test_xref_entry_is_live() {
        assert!(XrefEntry::in_use(1, 0, 100).is_live());
        assert!(XrefEntry::compressed(2, 5, 3).is_live());
        assert!(!XrefEntry::free(0, 0xFFFF, 0).is_live());
    }

    #[test]
    fn test_cross_ref_table_max_object_number() {
        let mut table = CrossRefTable::new();
        table.insert(XrefEntry::in_use(1, 0, 10));
        table.insert(XrefEntry::in_use(5, 0, 50));
        assert_eq!(table.max_object_number(), Some(5));
    }

    #[test]
    fn test_read_be_uint_zero_width() {
        assert_eq!(read_be_uint(&[0xFF], 0, 0), 0);
    }
}
