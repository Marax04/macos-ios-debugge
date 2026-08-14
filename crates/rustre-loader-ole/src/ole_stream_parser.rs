//! `ole_stream_parser` — Parse individual OLE2 (CFB) streams.
//!
//! Provides `OleStreamParser` which operates on the raw byte content of a
//! single OLE stream entry (already extracted from the CFB container) and
//! decodes its internal structure based on the `StreamKind` heuristic.

use std::fmt;
use std::io::{self, Cursor, Read};

// ── StreamKind ────────────────────────────────────────────────────────────────

/// Detected or declared kind of an OLE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// Microsoft Word document stream (`WordDocument`).
    WordDocument,
    /// Excel workbook stream (Workbook).
    ExcelWorkbook,
    /// `PowerPoint` Current User stream.
    PowerPointCurrentUser,
    /// VBA project stream (_`VBA_PROJECT`).
    VbaProject,
    /// VBA module stream (decompressed p-code).
    VbaModule,
    /// VBA dir stream (module metadata).
    VbaDir,
    /// OLE property set (`SummaryInformation` / `DocSummaryInformation`).
    PropertySet,
    /// Thumbnail / CONTENTS stream.
    Thumbnail,
    /// Unknown or user-defined stream.
    Unknown,
}

impl StreamKind {
    /// Heuristically detect the stream kind from its name and first bytes.
    #[must_use]
    pub fn detect(name: &str, data: &[u8]) -> Self {
        match name {
            "WordDocument" => return Self::WordDocument,
            "Workbook" | "Book" => return Self::ExcelWorkbook,
            "Current User" => return Self::PowerPointCurrentUser,
            "_VBA_PROJECT" => return Self::VbaProject,
            "dir" => return Self::VbaDir,
            "\x05SummaryInformation" | "\x05DocumentSummaryInformation" => {
                return Self::PropertySet
            }
            "CONTENTS" => return Self::Thumbnail,
            _ => {}
        }
        // Secondary heuristic: name contains "Module" or data starts with compressed VBA magic.
        if name.ends_with("Module") || name.starts_with("Module") {
            return Self::VbaModule;
        }
        if data.starts_with(b"\x01Ole") || data.starts_with(b"\x02Ole") {
            return Self::PropertySet;
        }
        Self::Unknown
    }
}

impl fmt::Display for StreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::WordDocument => "WordDocument",
            Self::ExcelWorkbook => "ExcelWorkbook",
            Self::PowerPointCurrentUser => "PowerPointCurrentUser",
            Self::VbaProject => "VbaProject",
            Self::VbaModule => "VbaModule",
            Self::VbaDir => "VbaDir",
            Self::PropertySet => "PropertySet",
            Self::Thumbnail => "Thumbnail",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ── OleStream ─────────────────────────────────────────────────────────────────

/// A parsed OLE stream.
#[derive(Debug, Clone)]
pub struct OleStream {
    /// Stream name (UTF-16 decoded).
    pub name: String,
    /// Detected stream kind.
    pub kind: StreamKind,
    /// Raw stream bytes.
    pub data: Vec<u8>,
    /// Size of the stream in bytes.
    pub size: u32,
    /// Offset within the CFB where this stream's data begins (if known).
    pub cfb_offset: Option<u64>,
    /// Parsed structured records (if any).
    pub records: Vec<StreamRecord>,
}

impl OleStream {
    /// Create a new stream with raw data.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        let name = name.into();
        let kind = StreamKind::detect(&name, &data);
        let size = data.len() as u32;
        Self {
            name,
            kind,
            size,
            data,
            cfb_offset: None,
            records: Vec::new(),
        }
    }

    /// Return a slice of the stream data.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return a hex dump of the first `n` bytes.
    #[must_use]
    pub fn hex_dump(&self, n: usize) -> String {
        let limit = n.min(self.data.len());
        let mut out = String::new();
        for (i, chunk) in self.data[..limit].chunks(16).enumerate() {
            out.push_str(&format!("{:04x}  ", i * 16));
            for b in chunk {
                out.push_str(&format!("{b:02x} "));
            }
            out.push('\n');
        }
        out
    }
}

impl fmt::Display for OleStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OleStream({:?}) kind={} size={}",
            self.name, self.kind, self.size
        )
    }
}

// ── StreamRecord ──────────────────────────────────────────────────────────────

/// A single structured record inside an OLE stream.
#[derive(Debug, Clone)]
pub struct StreamRecord {
    /// Record type identifier.
    pub record_type: u16,
    /// Byte offset within the stream.
    pub offset: u64,
    /// Raw record payload.
    pub payload: Vec<u8>,
}

impl StreamRecord {
    /// Create a new stream record.
    #[must_use]
    pub const fn new(record_type: u16, offset: u64, payload: Vec<u8>) -> Self {
        Self {
            record_type,
            offset,
            payload,
        }
    }

    /// Return the payload length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.payload.len()
    }

    /// Return `true` if the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl fmt::Display for StreamRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Record(type=0x{:04x} offset=0x{:x} len={})",
            self.record_type,
            self.offset,
            self.len()
        )
    }
}

// ── OleStreamParser ───────────────────────────────────────────────────────────

/// Parses an OLE stream into its constituent records.
///
/// For most stream kinds records follow the pattern:
/// ```text
/// [2 bytes] record type (LE u16)
/// [4 bytes] record length (LE u32)
/// [N bytes] payload
/// ```
/// This is the BIFF8 / MS-CFB record framing used by Word, Excel, etc.
#[derive(Debug)]
pub struct OleStreamParser {
    /// Maximum number of records to parse (0 = unlimited).
    pub max_records: usize,
    /// Minimum payload size to emit (0 = all).
    pub min_payload: usize,
    /// Whether to skip records with zero-length payload.
    pub skip_empty: bool,
}

impl OleStreamParser {
    /// Create a new parser with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_records: 0,
            min_payload: 0,
            skip_empty: false,
        }
    }

    /// Set maximum record count.
    #[must_use]
    pub const fn with_max_records(mut self, n: usize) -> Self {
        self.max_records = n;
        self
    }

    /// Set minimum payload size.
    #[must_use]
    pub const fn with_min_payload(mut self, n: usize) -> Self {
        self.min_payload = n;
        self
    }

    /// Skip records with zero-length payload.
    #[must_use]
    pub const fn skip_empty(mut self) -> Self {
        self.skip_empty = true;
        self
    }

    /// Parse a raw byte slice and return the parsed `OleStream`.
    pub fn parse_stream(&self, name: &str, data: &[u8]) -> io::Result<OleStream> {
        let mut stream = OleStream::new(name, data.to_vec());
        stream.records = self.parse_records(data)?;
        Ok(stream)
    }

    /// Parse BIFF8-style records from a byte slice.
    fn parse_records(&self, data: &[u8]) -> io::Result<Vec<StreamRecord>> {
        let mut records = Vec::new();
        let mut cursor = Cursor::new(data);
        let limit = if self.max_records == 0 {
            usize::MAX
        } else {
            self.max_records
        };

        while (cursor.position() as usize) + 6 <= data.len() && records.len() < limit {
            let offset = cursor.position();
            let mut type_buf = [0u8; 2];
            cursor.read_exact(&mut type_buf)?;
            let record_type = u16::from_le_bytes(type_buf);

            let mut len_buf = [0u8; 4];
            cursor.read_exact(&mut len_buf)?;
            let payload_len = u32::from_le_bytes(len_buf) as usize;

            // Guard: don't read past end of data.
            let remaining = data.len() - cursor.position() as usize;
            let actual_len = payload_len.min(remaining);
            let mut payload = vec![0u8; actual_len];
            cursor.read_exact(&mut payload)?;

            if self.skip_empty && payload.is_empty() {
                continue;
            }
            if payload.len() < self.min_payload {
                continue;
            }

            records.push(StreamRecord::new(record_type, offset, payload));

            // If payload_len exceeded data, we've consumed everything.
            if actual_len < payload_len {
                break;
            }
        }

        Ok(records)
    }

    /// Compute a simple checksum (sum of all bytes) of the stream data.
    #[must_use]
    pub fn checksum(data: &[u8]) -> u32 {
        data.iter().map(|&b| u32::from(b)).sum()
    }

    /// Return the number of bytes that look like printable ASCII in the stream.
    #[must_use]
    pub fn printable_ratio(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let printable = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
        printable as f64 / data.len() as f64
    }
}

impl Default for OleStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(rtype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&rtype.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn test_stream_kind_detect_by_name() {
        assert_eq!(StreamKind::detect("WordDocument", &[]), StreamKind::WordDocument);
        assert_eq!(StreamKind::detect("Workbook", &[]), StreamKind::ExcelWorkbook);
        assert_eq!(StreamKind::detect("_VBA_PROJECT", &[]), StreamKind::VbaProject);
        assert_eq!(StreamKind::detect("dir", &[]), StreamKind::VbaDir);
    }

    #[test]
    fn test_stream_kind_detect_vba_module() {
        assert_eq!(StreamKind::detect("Module1", &[]), StreamKind::VbaModule);
        assert_eq!(StreamKind::detect("TestModule", &[]), StreamKind::VbaModule);
    }

    #[test]
    fn test_stream_kind_detect_property_set() {
        assert_eq!(
            StreamKind::detect("\x05SummaryInformation", &[]),
            StreamKind::PropertySet
        );
    }

    #[test]
    fn test_stream_kind_display() {
        assert_eq!(StreamKind::WordDocument.to_string(), "WordDocument");
        assert_eq!(StreamKind::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_ole_stream_new() {
        let s = OleStream::new("WordDocument", vec![0x42; 32]);
        assert_eq!(s.kind, StreamKind::WordDocument);
        assert_eq!(s.size, 32);
    }

    #[test]
    fn test_ole_stream_display() {
        let s = OleStream::new("Workbook", vec![0; 10]);
        let d = s.to_string();
        assert!(d.contains("ExcelWorkbook"));
        assert!(d.contains("size=10"));
    }

    #[test]
    fn test_hex_dump() {
        let s = OleStream::new("X", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let dump = s.hex_dump(4);
        assert!(dump.contains("de"));
        assert!(dump.contains("ad"));
    }

    #[test]
    fn test_parse_single_record() {
        let data = make_record(0x0809, b"hello");
        let parser = OleStreamParser::new();
        let stream = parser.parse_stream("WordDocument", &data).unwrap();
        assert_eq!(stream.records.len(), 1);
        assert_eq!(stream.records[0].record_type, 0x0809);
        assert_eq!(&stream.records[0].payload, b"hello");
    }

    #[test]
    fn test_parse_multiple_records() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_record(0x0001, b"first"));
        data.extend_from_slice(&make_record(0x0002, b"second"));
        let parser = OleStreamParser::new();
        let stream = parser.parse_stream("X", &data).unwrap();
        assert_eq!(stream.records.len(), 2);
    }

    #[test]
    fn test_max_records() {
        let mut data = Vec::new();
        for i in 0u16..5 {
            data.extend_from_slice(&make_record(i, b"payload"));
        }
        let parser = OleStreamParser::new().with_max_records(2);
        let stream = parser.parse_stream("X", &data).unwrap();
        assert_eq!(stream.records.len(), 2);
    }

    #[test]
    fn test_skip_empty_records() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_record(0x0001, b"")); // empty
        data.extend_from_slice(&make_record(0x0002, b"data"));
        let parser = OleStreamParser::new().skip_empty();
        let stream = parser.parse_stream("X", &data).unwrap();
        assert_eq!(stream.records.len(), 1);
    }

    #[test]
    fn test_min_payload() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_record(0x0001, b"ab"));
        data.extend_from_slice(&make_record(0x0002, b"abcdefgh"));
        let parser = OleStreamParser::new().with_min_payload(5);
        let stream = parser.parse_stream("X", &data).unwrap();
        assert_eq!(stream.records.len(), 1);
        assert_eq!(&stream.records[0].payload, b"abcdefgh");
    }

    #[test]
    fn test_checksum() {
        let data = [1u8, 2, 3];
        assert_eq!(OleStreamParser::checksum(&data), 6);
    }

    #[test]
    fn test_printable_ratio() {
        let data = b"Hello World!";
        let r = OleStreamParser::printable_ratio(data);
        assert!((r - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_printable_ratio_empty() {
        assert_eq!(OleStreamParser::printable_ratio(&[]), 0.0);
    }

    #[test]
    fn test_stream_record_display() {
        let r = StreamRecord::new(0x0809, 16, b"test".to_vec());
        let s = r.to_string();
        assert!(s.contains("0809"));
        assert!(s.contains("len=4"));
    }

    #[test]
    fn test_stream_record_is_empty() {
        let r = StreamRecord::new(0x0001, 0, vec![]);
        assert!(r.is_empty());
    }

    #[test]
    fn test_stream_record_len() {
        let r = StreamRecord::new(0x0001, 0, b"abc".to_vec());
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_partial_record_handled() {
        // 2-byte record type, 4-byte length claiming 100 bytes but only 2 available.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_le_bytes());
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(b"ab");
        let parser = OleStreamParser::new();
        let stream = parser.parse_stream("X", &data).unwrap();
        assert_eq!(stream.records.len(), 1);
        assert_eq!(stream.records[0].payload.len(), 2);
    }

    #[test]
    fn test_empty_data() {
        let parser = OleStreamParser::new();
        let stream = parser.parse_stream("X", &[]).unwrap();
        assert!(stream.records.is_empty());
    }
}
