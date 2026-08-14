//! PDB TPI (Type Information) stream reader.
//!
//! Reads the TPI stream from a Microsoft PDB 7.0 file, which begins with a
//! 56-byte header followed by type records.  Handles type index tables,
//! forward reference resolution, and type record iteration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{read_u16, read_u32, CvTypeKind};
use crate::codeview_type_parser::{CodeViewTypeParser, CvTypeLeaf, ParsedTypeRecord};

// ---------------------------------------------------------------------------
// TPI stream header (56 bytes)
// ---------------------------------------------------------------------------

/// Magic version tag for a PDB 7.0 TPI stream.
pub const TPI_HEADER_VERSION_V80: u32 = 20_040_203;

/// Raw TPI stream header (56 bytes for PDB 7.0).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TpiHeader {
    /// Version (must be `TPI_HEADER_VERSION_V80 = 20_040_203`).
    pub version: u32,
    /// Size of this header in bytes (always 56 for V8).
    pub header_size: u32,
    /// Minimum type index in this TPI stream (usually 0x1000).
    pub type_index_min: u32,
    /// One past the maximum type index.
    pub type_index_max: u32,
    /// Total byte size of the type record data that follows.
    pub type_record_bytes: u32,
    /// Stream index of the hash stream.
    pub hash_stream_index: u16,
    /// Padding / auxiliary hash stream index.
    pub hash_aux_stream_index: u16,
    /// Size in bytes of each hash value.
    pub hash_key_size: u32,
    /// Number of hash buckets.
    pub num_hash_buckets: u32,
    /// Byte offset of the hash values buffer within the hash stream.
    pub hash_value_buffer_offset: i32,
    /// Byte length of the hash values buffer.
    pub hash_value_buffer_length: u32,
    /// Byte offset of the index offset buffer within the hash stream.
    pub index_offset_buffer_offset: i32,
    /// Byte length of the index offset buffer.
    pub index_offset_buffer_length: u32,
    /// Byte offset of the hash adjust buffer within the hash stream.
    pub hash_adjust_buffer_offset: i32,
    /// Byte length of the hash adjust buffer.
    pub hash_adjust_buffer_length: u32,
}

impl TpiHeader {
    /// Minimum size of a well-formed TPI stream.
    pub const SIZE: usize = 56;

    /// Parse a `TpiHeader` from the first 56 bytes of a TPI stream.
    ///
    /// # Errors
    ///
    /// Returns [`TpiError::HeaderTooShort`] if `data` has fewer than 56 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, TpiError> {
        if data.len() < Self::SIZE {
            return Err(TpiError::HeaderTooShort {
                available: data.len(),
            });
        }
        let r = |off: usize| read_u32(data, off);
        let r16 = |off: usize| read_u16(data, off);
        let ri32 = |off: usize| -> i32 { i32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4])) };
        Ok(Self {
            version: r(0),
            header_size: r(4),
            type_index_min: r(8),
            type_index_max: r(12),
            type_record_bytes: r(16),
            hash_stream_index: r16(20),
            hash_aux_stream_index: r16(22),
            hash_key_size: r(24),
            num_hash_buckets: r(28),
            hash_value_buffer_offset: ri32(32),
            hash_value_buffer_length: r(36),
            index_offset_buffer_offset: ri32(40),
            index_offset_buffer_length: r(44),
            hash_adjust_buffer_offset: ri32(48),
            hash_adjust_buffer_length: r(52),
        })
    }

    /// Returns `true` if the version tag is the expected PDB 7.0 value.
    #[must_use]
    pub const fn is_valid_version(&self) -> bool {
        self.version == TPI_HEADER_VERSION_V80
    }

    /// Number of type records declared in the header.
    #[must_use]
    pub const fn declared_type_count(&self) -> u32 {
        self.type_index_max.saturating_sub(self.type_index_min)
    }
}

// ---------------------------------------------------------------------------
// TpiError
// ---------------------------------------------------------------------------

/// Errors produced by the TPI reader.
#[derive(Debug)]
pub enum TpiError {
    /// The TPI stream does not have enough bytes for the header.
    HeaderTooShort { available: usize },
    /// The version field does not match the expected value.
    BadVersion(u32),
    /// The declared header size is not 56.
    BadHeaderSize(u32),
    /// The type record region extends beyond the buffer.
    RecordRegionTooLarge { declared: usize, available: usize },
    /// A specific type record is truncated.
    RecordTruncated { type_index: u32, offset: usize },
}

impl std::fmt::Display for TpiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTooShort { available } => {
                write!(f, "TPI header too short: {available} bytes")
            }
            Self::BadVersion(v) => write!(f, "unknown TPI version: {v}"),
            Self::BadHeaderSize(s) => write!(f, "unexpected header size: {s}"),
            Self::RecordRegionTooLarge { declared, available } => write!(
                f,
                "declared record region {declared} > available {available}"
            ),
            Self::RecordTruncated { type_index, offset } => {
                write!(f, "type {type_index:#x} truncated at offset {offset:#x}")
            }
        }
    }
}

impl std::error::Error for TpiError {}

// ---------------------------------------------------------------------------
// TypeIndex
// ---------------------------------------------------------------------------

/// A `CodeView` TPI type index.
///
/// Indices below `0x1000` are built-in primitive types; user-defined types
/// start at `0x1000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeIndex(pub u32);

impl TypeIndex {
    /// The first user-defined type index.
    pub const USER_FIRST: Self = Self(0x1000);

    /// Returns `true` if this is a built-in primitive type.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        self.0 < 0x1000
    }

    /// Raw index value.
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for TypeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// TypeRecord
// ---------------------------------------------------------------------------

/// A type record as seen by `TpiReader` consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRecord {
    /// Assigned TPI index.
    pub index: TypeIndex,
    /// The parsed leaf.
    pub leaf: CvTypeLeaf,
    /// Byte offset within the type-record region.
    pub stream_offset: usize,
}

impl TypeRecord {
    /// Returns `true` if this is a forward declaration.
    #[must_use]
    pub fn is_forward_ref(&self) -> bool {
        self.leaf.is_forward_ref()
    }

    /// Returns the type name if the leaf carries one.
    #[must_use]
    pub const fn name(&self) -> Option<&str> {
        self.leaf.name()
    }
}

impl std::fmt::Display for TypeRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.index, self.leaf)
    }
}

// ---------------------------------------------------------------------------
// TpiReader
// ---------------------------------------------------------------------------

/// High-level reader for a PDB TPI stream.
///
/// Parses the 56-byte header and all type records that follow, then
/// provides query methods for looking up types by index or name.
#[derive(Debug)]
pub struct TpiReader {
    /// Parsed TPI header.
    pub header: TpiHeader,
    /// All type records, ordered by ascending type index.
    records: Vec<TypeRecord>,
    /// Fast lookup: `TypeIndex` → position in `records`.
    index_map: HashMap<u32, usize>,
    /// Name → list of record positions (may contain forward refs).
    name_map: HashMap<String, Vec<usize>>,
}

impl TpiReader {
    /// Parse a complete TPI stream.
    ///
    /// `data` should be the full byte content of the TPI MSF stream,
    /// starting with the 56-byte header.
    ///
    /// # Errors
    ///
    /// Returns [`TpiError`] if the header is invalid or a record is truncated.
    pub fn parse(data: &[u8]) -> Result<Self, TpiError> {
        let header = TpiHeader::parse(data)?;

        if !header.is_valid_version() {
            return Err(TpiError::BadVersion(header.version));
        }
        if header.header_size as usize != TpiHeader::SIZE {
            return Err(TpiError::BadHeaderSize(header.header_size));
        }

        let record_start = header.header_size as usize;
        let record_len = header.type_record_bytes as usize;
        let record_end = record_start.checked_add(record_len).ok_or_else(|| {
            TpiError::RecordRegionTooLarge {
                declared: record_len,
                available: data.len().saturating_sub(record_start),
            }
        })?;

        if record_end > data.len() {
            return Err(TpiError::RecordRegionTooLarge {
                declared: record_len,
                available: data.len().saturating_sub(record_start),
            });
        }

        let record_data = &data[record_start..record_end];

        // Use CodeViewTypeParser for the actual record parsing. Seed it with
        // the header's TypeIndexBegin: hardcoding 0x1000 numbers every record
        // too low whenever a type server reserved the low indices.
        let mut parser = CodeViewTypeParser::with_start_index(header.type_index_min);
        parser.parse_stream(record_data);

        // Build our TypeRecord list.
        let mut records = Vec::with_capacity(parser.len());
        let mut index_map: HashMap<u32, usize> = HashMap::with_capacity(parser.len());
        let mut name_map: HashMap<String, Vec<usize>> = HashMap::new();

        // Reconstruct stream offsets by re-scanning.
        let mut stream_off = 0usize;
        for parsed in parser.records() {
            let pos = records.len();
            if let Some(name) = parsed.leaf.name()
                && !name.is_empty() {
                    name_map.entry(name.to_owned()).or_default().push(pos);
                }
            index_map.insert(parsed.type_index, pos);
            records.push(TypeRecord {
                index: TypeIndex(parsed.type_index),
                leaf: parsed.leaf.clone(),
                stream_offset: stream_off,
            });

            // Advance stream_off by the record size.
            if stream_off + 2 <= record_data.len() {
                let len = read_u16(record_data, stream_off) as usize;
                stream_off += 2 + len.max(2);
            } else {
                break;
            }
        }

        Ok(Self {
            header,
            records,
            index_map,
            name_map,
        })
    }

    /// Parse a TPI stream that does *not* have a standard header (raw record bytes).
    ///
    /// Useful when the header has been stripped or is absent (e.g. when reading
    /// from a `.debug$T` section that starts directly with type records).
    ///
    /// Assigns type indices starting at `0x1000`.
    #[must_use]
    pub fn parse_raw_records(data: &[u8]) -> Self {
        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(data);

        let mut records = Vec::with_capacity(parser.len());
        let mut index_map: HashMap<u32, usize> = HashMap::new();
        let mut name_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut stream_off = 0usize;

        for parsed in parser.records() {
            let pos = records.len();
            if let Some(name) = parsed.leaf.name()
                && !name.is_empty() {
                    name_map.entry(name.to_owned()).or_default().push(pos);
                }
            index_map.insert(parsed.type_index, pos);
            records.push(TypeRecord {
                index: TypeIndex(parsed.type_index),
                leaf: parsed.leaf.clone(),
                stream_offset: stream_off,
            });
            if stream_off + 2 <= data.len() {
                let len = read_u16(data, stream_off) as usize;
                stream_off += 2 + len.max(2);
            } else {
                break;
            }
        }

        Self {
            header: TpiHeader {
                version: TPI_HEADER_VERSION_V80,
                header_size: 56,
                type_index_min: 0x1000,
                type_index_max: 0x1000 + crate::casts::usize_to_u32(records.len()),
                type_record_bytes: crate::casts::usize_to_u32(data.len()),
                hash_stream_index: 0xFFFF,
                hash_aux_stream_index: 0xFFFF,
                hash_key_size: 4,
                num_hash_buckets: 0,
                hash_value_buffer_offset: 0,
                hash_value_buffer_length: 0,
                index_offset_buffer_offset: 0,
                index_offset_buffer_length: 0,
                hash_adjust_buffer_offset: 0,
                hash_adjust_buffer_length: 0,
            },
            records,
            index_map,
            name_map,
        }
    }

    /// Total number of type records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no records are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up a type record by `TypeIndex`.
    #[must_use]
    pub fn lookup(&self, index: TypeIndex) -> Option<&TypeRecord> {
        self.index_map
            .get(&index.0)
            .and_then(|&pos| self.records.get(pos))
    }

    /// Look up a type record by raw index `u32`.
    #[must_use]
    pub fn lookup_raw(&self, index: u32) -> Option<&TypeRecord> {
        self.lookup(TypeIndex(index))
    }

    /// Find all type records whose name matches `name` exactly.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&TypeRecord> {
        self.name_map
            .get(name)
            .map(|positions| {
                positions
                    .iter()
                    .filter_map(|&pos| self.records.get(pos))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the concrete (non-forward-ref) definition of a type by name.
    #[must_use]
    pub fn find_concrete(&self, name: &str) -> Option<&TypeRecord> {
        self.find_by_name(name)
            .into_iter()
            .find(|r| !r.is_forward_ref())
    }

    /// Resolve a forward reference to its concrete definition.
    ///
    /// If `rec` is not a forward reference, returns `Some(rec)` unchanged.
    #[must_use]
    pub fn resolve<'a>(&'a self, rec: &'a TypeRecord) -> Option<&'a TypeRecord> {
        if !rec.is_forward_ref() {
            return Some(rec);
        }
        let name = rec.leaf.name()?;
        self.find_concrete(name)
    }

    /// All type records (read-only slice).
    #[must_use]
    pub fn records(&self) -> &[TypeRecord] {
        &self.records
    }

    /// All struct/class records (excluding forward refs).
    #[must_use]
    pub fn structs(&self) -> Vec<&TypeRecord> {
        self.records
            .iter()
            .filter(|r| {
                matches!(&r.leaf, CvTypeLeaf::Structure { .. }) && !r.is_forward_ref()
            })
            .collect()
    }

    /// All union records (excluding forward refs).
    #[must_use]
    pub fn unions(&self) -> Vec<&TypeRecord> {
        self.records
            .iter()
            .filter(|r| matches!(&r.leaf, CvTypeLeaf::Union { .. }) && !r.is_forward_ref())
            .collect()
    }

    /// All enum records (excluding forward refs).
    #[must_use]
    pub fn enums(&self) -> Vec<&TypeRecord> {
        self.records
            .iter()
            .filter(|r| matches!(&r.leaf, CvTypeLeaf::Enum { .. }) && !r.is_forward_ref())
            .collect()
    }

    /// All procedure type records.
    #[must_use]
    pub fn procedures(&self) -> Vec<&TypeRecord> {
        self.records
            .iter()
            .filter(|r| matches!(&r.leaf, CvTypeLeaf::Procedure { .. }))
            .collect()
    }

    /// All pointer type records.
    #[must_use]
    pub fn pointers(&self) -> Vec<&TypeRecord> {
        self.records
            .iter()
            .filter(|r| matches!(&r.leaf, CvTypeLeaf::Pointer { .. }))
            .collect()
    }

    /// Build a `name → size` map for all concrete aggregate types.
    #[must_use]
    pub fn size_map(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for rec in self.structs().into_iter().chain(self.unions()) {
            let name_size = match &rec.leaf {
                CvTypeLeaf::Structure { name, size, .. }
                | CvTypeLeaf::Union { name, size, .. } => {
                    if name.is_empty() {
                        None
                    } else {
                        Some((name.clone(), *size))
                    }
                }
                _ => None,
            };
            if let Some((name, size)) = name_size {
                map.insert(name, size);
            }
        }
        map
    }

    /// Walk the type graph starting at `root_index`, collecting all transitively
    /// referenced type indices (BFS, up to `max_depth`).
    #[must_use]
    pub fn reachable_types(&self, root_index: TypeIndex, max_depth: usize) -> Vec<TypeIndex> {
        let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();

        queue.push_back((root_index, 0usize));
        while let Some((idx, depth)) = queue.pop_front() {
            if !visited.insert(idx.0) || depth > max_depth {
                continue;
            }
            result.push(idx);

            // Enqueue children based on the leaf kind.
            if let Some(rec) = self.lookup(idx) {
                match &rec.leaf {
                    CvTypeLeaf::Structure { field_list_index, .. }
                    | CvTypeLeaf::Union { field_list_index, .. } => {
                        queue.push_back((TypeIndex(*field_list_index), depth + 1));
                    }
                    CvTypeLeaf::Pointer { target_type, .. } => {
                        queue.push_back((TypeIndex(*target_type), depth + 1));
                    }
                    CvTypeLeaf::Procedure {
                        return_type,
                        arglist_index,
                        ..
                    } => {
                        queue.push_back((TypeIndex(*return_type), depth + 1));
                        queue.push_back((TypeIndex(*arglist_index), depth + 1));
                    }
                    CvTypeLeaf::Array { element_type, .. } => {
                        queue.push_back((TypeIndex(*element_type), depth + 1));
                    }
                    CvTypeLeaf::Modifier { modified_type, .. } => {
                        queue.push_back((TypeIndex(*modified_type), depth + 1));
                    }
                    _ => {}
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers (cable imports)
// ---------------------------------------------------------------------------

/// Parse a single `CodeView` type record from `data` using the shared
/// `CodeViewTypeParser`, returning the raw `ParsedTypeRecord` (kind + bytes).
///
/// This is a thin wrapper used by tools that already have a single record
/// blob (no surrounding TPI header) and want to decode it without
/// instantiating a full `TpiReader`. It uses `read_u16` / `read_u32` from
/// the crate root so byte handling matches the rest of the parser surface.
#[must_use] 
pub fn parse_single_type_record(
    data: &[u8],
) -> Option<ParsedTypeRecord> {
    if data.len() < 4 {
        return None;
    }
    let _record_len = read_u16(data, 0);
    let _leaf_tag = read_u16(data, 2);
    // 4-byte fingerprint used in some diagnostics: low 32 bits of the record.
    let _fingerprint = read_u32(data, 0);
    let mut parser = CodeViewTypeParser::new();
    let n = parser.parse_stream(data);
    if n == 0 {
        return None;
    }
    parser.records().first().cloned()
}

/// Classify a `CodeView` leaf code into its high-level [`CvTypeKind`].
///
/// Exposed so symbol-resolver layers can bucket records (procedures,
/// aggregates, pointers, ...) without re-deriving the mapping.
#[must_use] 
pub const fn classify_leaf_kind(leaf: u16) -> CvTypeKind {
    CvTypeKind::from_u16(leaf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build minimal raw type record bytes for a single `LF_STRUCTURE`.
    fn structure_raw(name: &str, size: u16) -> Vec<u8> {
        // Body: count(2) property(2) fieldlist(4) derived(4) vshape(4) size(2 inline) name\0 unique\0
        let mut body = vec![0u8; 16];
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0); // NUL
        body.push(0); // empty unique_name
        let leaf: u16 = 0x1005;
        let len = crate::casts::usize_to_u16(2 + body.len());
        let mut rec = Vec::new();
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&leaf.to_le_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    fn make_raw_reader(name: &str, size: u16) -> TpiReader {
        let data = structure_raw(name, size);
        TpiReader::parse_raw_records(&data)
    }

    #[test]
    fn parse_raw_single_struct() {
        let reader = make_raw_reader("Widget", 128);
        assert_eq!(reader.len(), 1);
        let rec = reader.lookup(TypeIndex(0x1000)).unwrap();
        match &rec.leaf {
            CvTypeLeaf::Structure { name, size, .. } => {
                assert_eq!(name, "Widget");
                assert_eq!(*size, 128);
            }
            other => panic!("expected Structure, got {other:?}"),
        }
    }

    #[test]
    fn find_by_name() {
        let mut data = structure_raw("Node", 24);
        data.extend(structure_raw("Edge", 16));
        let reader = TpiReader::parse_raw_records(&data);
        let nodes = reader.find_by_name("Node");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn structs_excludes_forward_refs() {
        // Build a forward-ref record (property bit 7 set).
        let mut body = vec![0u8; 16];
        body[2] = 0x80; // property |= 0x80
        body.extend_from_slice(&[0x00, 0x00]); // size = 0
        body.extend_from_slice(b"FwdFoo\0\0");
        let leaf: u16 = 0x1005;
        let len = crate::casts::usize_to_u16(2 + body.len());
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&leaf.to_le_bytes());
        data.extend_from_slice(&body);
        // Append a concrete definition.
        data.extend(structure_raw("FwdFoo", 32));

        let reader = TpiReader::parse_raw_records(&data);
        let structs = reader.structs();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name().unwrap(), "FwdFoo");
        assert!(!structs[0].is_forward_ref());
    }

    #[test]
    fn size_map() {
        let mut data = structure_raw("A", 8);
        data.extend(structure_raw("B", 16));
        let reader = TpiReader::parse_raw_records(&data);
        let map = reader.size_map();
        assert_eq!(map.get("A"), Some(&8u64));
        assert_eq!(map.get("B"), Some(&16u64));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let reader = make_raw_reader("X", 4);
        assert!(reader.lookup(TypeIndex(0x9999)).is_none());
    }

    #[test]
    fn type_index_is_primitive() {
        assert!(TypeIndex(0x0074).is_primitive());
        assert!(!TypeIndex(0x1000).is_primitive());
    }

    #[test]
    fn type_index_display() {
        let s = TypeIndex(0x1005).to_string();
        assert!(s.contains("0x1005") || s.contains("1005"));
    }

    #[test]
    fn tpi_header_declared_type_count() {
        let h = TpiHeader {
            version: TPI_HEADER_VERSION_V80,
            header_size: 56,
            type_index_min: 0x1000,
            type_index_max: 0x1010,
            type_record_bytes: 0,
            hash_stream_index: 0xFFFF,
            hash_aux_stream_index: 0xFFFF,
            hash_key_size: 4,
            num_hash_buckets: 0,
            hash_value_buffer_offset: 0,
            hash_value_buffer_length: 0,
            index_offset_buffer_offset: 0,
            index_offset_buffer_length: 0,
            hash_adjust_buffer_offset: 0,
            hash_adjust_buffer_length: 0,
        };
        assert_eq!(h.declared_type_count(), 0x10);
    }

    #[test]
    fn find_concrete_skips_forward_ref() {
        let mut body = vec![0u8; 16];
        body[2] = 0x80; // forward ref
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(b"Thing\0\0");
        let leaf: u16 = 0x1005;
        let len = crate::casts::usize_to_u16(2 + body.len());
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&leaf.to_le_bytes());
        data.extend_from_slice(&body);
        data.extend(structure_raw("Thing", 64));

        let reader = TpiReader::parse_raw_records(&data);
        let concrete = reader.find_concrete("Thing");
        assert!(concrete.is_some());
        assert!(!concrete.unwrap().is_forward_ref());
    }
}
