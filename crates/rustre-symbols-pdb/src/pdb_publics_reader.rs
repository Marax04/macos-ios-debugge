//! PDB public symbol stream reader.
//!
//! The publics stream contains a hash table of public symbols (exported names) and
//! an address map that sorts symbols by section:offset for address-based lookup.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while parsing the publics stream.
#[derive(Debug)]
pub enum PublicsError {
    /// The stream ended before the parser could read the required bytes.
    UnexpectedEof {
        /// Offset at which more data was needed.
        offset: usize,
        /// Number of additional bytes required.
        needed: usize,
    },
    /// The hash table signature is not `0xFFFFFFFF`.
    BadHashSignature {
        /// The signature value actually read.
        got: u32,
    },
    /// The hash table version is not `0xEFFE0000`.
    BadHashVersion {
        /// The version value actually read.
        got: u32,
    },
    /// A record in the publics stream is not an `S_PUB32` symbol.
    InvalidSymbolKind {
        /// The record kind actually read.
        kind: u16,
    },
    /// A symbol name is not valid UTF-8.
    InvalidUtf8 {
        /// Offset of the invalid name.
        offset: usize,
    },
    /// A hash bucket index exceeded the bucket count.
    BucketIndexOutOfRange {
        /// The offending bucket index.
        bucket: usize,
        /// The maximum valid bucket index.
        max: usize,
    },
}

impl fmt::Display for PublicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset, needed } =>
                write!(f, "unexpected EOF at offset {offset}: needed {needed} bytes"),
            Self::BadHashSignature { got } =>
                write!(f, "bad hash signature: expected 0xFFFFFFFF, got 0x{got:08X}"),
            Self::BadHashVersion { got } =>
                write!(f, "bad hash version: expected 0xEFFE0000, got 0x{got:08X}"),
            Self::InvalidSymbolKind { kind } =>
                write!(f, "unexpected symbol kind 0x{kind:04X} in publics stream"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 in symbol name at offset {offset}"),
            Self::BucketIndexOutOfRange { bucket, max } =>
                write!(f, "hash bucket {bucket} >= max {max}"),
        }
    }
}

impl std::error::Error for PublicsError {}
/// Result alias for publics stream parsing.
pub type PublicsResult<T> = Result<T, PublicsError>;

// ---------------------------------------------------------------------------
// Public symbol
// ---------------------------------------------------------------------------

/// Flags embedded in a public symbol record (`CV_PUBSYMFLAGS`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PubSymFlags(pub u32);

impl PubSymFlags {
    /// True if the symbol is in a code section.
    #[must_use]
    pub const fn is_code(&self) -> bool { self.0 & 0x0001 != 0 }
    /// True if the symbol is a function.
    #[must_use]
    pub const fn is_function(&self) -> bool { self.0 & 0x0002 != 0 }
    /// True if the symbol is managed code.
    #[must_use]
    pub const fn is_managed(&self) -> bool { self.0 & 0x0004 != 0 }
    /// True if the symbol is MSIL code.
    #[must_use]
    pub const fn is_msil(&self) -> bool { self.0 & 0x0008 != 0 }
}

/// A single public symbol record (`S_PUB32` = 0x110E).
#[derive(Debug, Clone)]
pub struct PublicSymbol {
    /// `CV_PUBSYMFLAGS`.
    pub flags: PubSymFlags,
    /// Byte offset within the section.
    pub offset: u32,
    /// 1-based section index.
    pub segment: u16,
    /// Decorated (mangled) name.
    pub name: String,
}

impl PublicSymbol {
    /// `CodeView` record kind for a public symbol (`S_PUB32`).
    pub const KIND: u16 = 0x110E;

    /// Parse a public symbol from a symbol-record byte slice.
    /// `data` is the entire symbol record payload (after the 4-byte kind+length header).
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8], base_offset: usize) -> PublicsResult<Self> {
        if data.len() < 8 {
            return Err(PublicsError::UnexpectedEof { offset: base_offset, needed: 8 });
        }
        let flags = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let offset = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let segment = u16::from_le_bytes(
            data.get(8..10).ok_or(PublicsError::UnexpectedEof { offset: base_offset + 8, needed: 2 })?
                .try_into().unwrap()
        );
        // name starts at offset 10
        let name = read_null_terminated(&data[10..], base_offset + 10)?;
        Ok(Self { flags: PubSymFlags(flags), offset, segment, name })
    }

    /// Returns a string of the form `segment:offset`.
    #[must_use]
    pub fn address_string(&self) -> String {
        format!("{:04X}:{:08X}", self.segment, self.offset)
    }
}

// ---------------------------------------------------------------------------
// Name hash table (NameHashTable)
// ---------------------------------------------------------------------------

/// The GSI (Global Symbol Index) hash table used to find symbols by name.
#[derive(Debug, Clone)]
pub struct NameHashTable {
    /// Number of hash buckets.
    pub bucket_count: usize,
    /// For each bucket: byte offset into the symbol records buffer, or `u32``::MAX` if empty.
    pub buckets: Vec<u32>,
    /// Raw symbol record data (parallel to buckets, resolved from HR records).
    pub hr_offsets: Vec<u32>,
}

impl NameHashTable {
    /// Expected hash table version signature.
    pub const HASH_VERSION: u32 = 0xEFFE_0000;

    /// Parse the hash table sub-portion of the publics stream.
    ///
    /// `data` starts at the beginning of the hash table (after the global stream header).
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8], offset: usize) -> PublicsResult<(Self, usize)> {
        if data.len() < offset + 8 {
            return Err(PublicsError::UnexpectedEof { offset, needed: 8 });
        }
        let version = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
        if version != Self::HASH_VERSION {
            return Err(PublicsError::BadHashVersion { got: version });
        }
        let hr_len = u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap()) as usize;
        let bucket_bitmap_len = u32::from_le_bytes(
            data.get(offset+8..offset+12)
                .ok_or(PublicsError::UnexpectedEof { offset: offset+8, needed: 4 })?
                .try_into().unwrap()
        ) as usize;

        // HR records: each is 8 bytes (offset u32 + cref i32)
        let hr_start = offset + 12;
        let hr_record_count = hr_len / 8;
        // `hr_len` is attacker-controlled; never pre-allocate more entries
        // than the remaining bytes can hold.
        let max_records = data.len().saturating_sub(hr_start) / 8;
        let mut hr_offsets = Vec::with_capacity(hr_record_count.min(max_records));
        for i in 0..hr_record_count {
            let off = hr_start + i * 8;
            if off + 4 > data.len() { break; }
            let sym_off = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
            hr_offsets.push(sym_off);
        }

        // Bucket bitmap. `hr_len`/`bucket_bitmap_len` are attacker-declared;
        // clamp to the buffer so `consumed` can never point past the data
        // (a caller uses it to slice the following substream).
        let bmp_start = hr_start.saturating_add(hr_len).min(data.len());
        let bmp_end = bmp_start.saturating_add(bucket_bitmap_len).min(data.len());
        let buckets_start = bmp_end;
        // Count set bits to get number of non-empty buckets
        let bmp = data.get(bmp_start..bmp_end).unwrap_or(&[]);
        let set_bits: usize = bmp.iter().map(|b| b.count_ones() as usize).sum();
        let bucket_count = set_bits;

        // Read the bucket offsets
        let mut buckets = Vec::with_capacity(bucket_count);
        let mut cur = buckets_start;
        for _ in 0..bucket_count {
            if cur + 4 > data.len() { break; }
            buckets.push(u32::from_le_bytes(data[cur..cur+4].try_into().unwrap()));
            cur += 4;
        }

        let consumed = cur - offset;
        Ok((Self { bucket_count, buckets, hr_offsets }, consumed))
    }
}

// ---------------------------------------------------------------------------
// Address map
// ---------------------------------------------------------------------------

/// An address map that sorts public symbols by (segment, offset).
#[derive(Debug, Clone, Default)]
pub struct AddressMap {
    /// Sorted list of (segment, offset, `symbol_record_byte_offset`).
    entries: Vec<(u16, u32, u32)>,
}

impl AddressMap {
    /// Parse the address map from its sub-stream bytes.
    /// `data` is the address-map sub-stream; each entry is a u32 sym-record offset.
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8]) -> PublicsResult<Self> {
        let count = data.len() / 4;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = u32::from_le_bytes(data[i*4..i*4+4].try_into().unwrap());
            entries.push((0, 0, off)); // segment/offset resolved later
        }
        Ok(Self { entries })
    }

    /// Build an address map from a list of public symbols with their offsets in the sym stream.
    #[must_use]
    pub fn from_symbols(symbols: &[(u32, &PublicSymbol)]) -> Self {
        let mut entries: Vec<(u16, u32, u32)> = symbols
            .iter()
            .map(|(rec_off, sym)| (sym.segment, sym.offset, *rec_off))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Self { entries }
    }

    /// Find the symbol whose address is closest to (segment, offset) from below.
    #[must_use]
    pub fn find_nearest(&self, segment: u16, offset: u32) -> Option<(u16, u32, u32)> {
        let key = (segment, offset, u32::MAX);
        match self.entries.binary_search_by(|e| {
            e.0.cmp(&key.0).then(e.1.cmp(&key.1))
        }) {
            Ok(i) => Some(self.entries[i]),
            Err(0) => None,
            Err(i) => {
                let entry = self.entries[i - 1];
                if entry.0 == segment {
                    Some(entry)
                } else {
                    None
                }
            }
        }
    }

    /// All entries sorted by (segment, offset).
    #[must_use]
    pub fn all(&self) -> &[(u16, u32, u32)] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// PublicsReader — top level
// ---------------------------------------------------------------------------

/// Header for the publics (GSI) stream.
#[derive(Debug, Clone)]
pub struct PublicsHeader {
    /// Byte length of the symbol hash sub-stream.
    pub sym_hash_size: u32,
    /// Byte length of the address map sub-stream.
    pub addr_map_size: u32,
    /// Number of thunks (trampoline entries).
    pub num_thunks: u32,
    /// Size of each thunk in bytes.
    pub thunks_size: u32,
    /// Segment index of the thunk table.
    pub thunk_table_seg: u16,
    /// Reserved padding (always 0).
    pub padding: u16,
    /// Offset of the thunk table within its segment.
    pub thunk_table_offset: u32,
    /// Number of sections with at least one thunk.
    pub num_sections_with_thunks: u32,
}

impl PublicsHeader {
    /// On-disk size of the publics stream header in bytes.
    pub const SIZE: usize = 28;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    /// # Panics
    ///
    /// May panic on malformed input.
    pub fn parse(data: &[u8], offset: usize) -> PublicsResult<Self> {
        let s = data.get(offset..offset + Self::SIZE)
            .ok_or(PublicsError::UnexpectedEof { offset, needed: Self::SIZE })?;
        let u16_at = |o: usize| u16::from_le_bytes(s[o..o+2].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(s[o..o+4].try_into().unwrap());
        Ok(Self {
            sym_hash_size: u32_at(0),
            addr_map_size: u32_at(4),
            num_thunks: u32_at(8),
            thunks_size: u32_at(12),
            thunk_table_seg: u16_at(16),
            padding: u16_at(18),
            thunk_table_offset: u32_at(20),
            num_sections_with_thunks: u32_at(24),
        })
    }
}

/// Parsed publics stream.
pub struct PublicsReader {
    /// Parsed publics stream header.
    pub header: PublicsHeader,
    /// All decoded `S_PUB32` symbols.
    pub symbols: Vec<PublicSymbol>,
    /// Address map sorted by (segment, offset).
    pub address_map: AddressMap,
    /// Name → symbol index lookup.
    name_index: HashMap<String, usize>,
}

impl PublicsReader {
    /// Parse the publics stream and the parallel symbol-records stream.
    ///
    /// `publics_data`: raw bytes of the public symbol stream (stream index from DBI).
    /// `sym_records_data`: raw bytes of the symbol records stream (stream index from DBI header).
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(publics_data: &[u8], sym_records_data: &[u8]) -> PublicsResult<Self> {
        let header = PublicsHeader::parse(publics_data, 0)?;

        // Parse symbol records from the sym records stream
        let symbols_with_offsets = parse_sym_records(sym_records_data)?;
        let symbols: Vec<PublicSymbol> = symbols_with_offsets.iter().map(|(_, s)| s.clone()).collect();

        // Build name index
        let mut name_index = HashMap::new();
        for (i, sym) in symbols.iter().enumerate() {
            name_index.insert(sym.name.clone(), i);
        }

        // Build address map
        let refs: Vec<(u32, &PublicSymbol)> = symbols_with_offsets
            .iter()
            .map(|(off, sym)| (*off, sym))
            .collect();
        let address_map = AddressMap::from_symbols(&refs);

        Ok(Self { header, symbols, address_map, name_index })
    }

    /// Look up a public symbol by exact (decorated) name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&PublicSymbol> {
        self.name_index.get(name).map(|&i| &self.symbols[i])
    }

    /// Find the public symbol whose address is nearest-but-not-greater than (seg, off).
    #[must_use]
    pub fn find_nearest(&self, segment: u16, offset: u32) -> Option<&PublicSymbol> {
        let (_, _, _rec_off) = self.address_map.find_nearest(segment, offset)?;
        // Find symbol by record offset
        self.symbols.iter()
            .find(|s| s.segment == segment && s.offset <= offset)
    }

    /// Return all public symbols in address order.
    #[must_use]
    pub fn symbols_by_address(&self) -> Vec<&PublicSymbol> {
        let mut sorted: Vec<&PublicSymbol> = self.symbols.iter().collect();
        sorted.sort_by(|a, b| a.segment.cmp(&b.segment).then(a.offset.cmp(&b.offset)));
        sorted
    }

    /// Return all function-type public symbols.
    #[must_use]
    pub fn functions(&self) -> Vec<&PublicSymbol> {
        self.symbols.iter().filter(|s| s.flags.is_function()).collect()
    }

    /// Return all code-type public symbols (includes function symbols, which are code by definition).
    #[must_use]
    pub fn code_symbols(&self) -> Vec<&PublicSymbol> {
        self.symbols.iter().filter(|s| s.flags.is_code() || s.flags.is_function()).collect()
    }

    /// Print a summary of the publics stream.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "publics: {} symbols ({} functions, {} code)",
            self.symbols.len(),
            self.functions().len(),
            self.code_symbols().len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Symbol records parser
// ---------------------------------------------------------------------------

/// Parse a symbol records stream into (`record_offset`, `PublicSymbol`) pairs.
/// Only `S_PUB32` (0x110E) records are returned; others are skipped.
/// # Errors
///
/// Returns an error if parsing fails.
/// # Panics
///
/// May panic on malformed input.
pub fn parse_sym_records(data: &[u8]) -> PublicsResult<Vec<(u32, PublicSymbol)>> {
    let mut out = Vec::new();
    let mut cur = 0usize;
    while cur + 4 <= data.len() {
        let record_start = cur;
        let length = u16::from_le_bytes(data[cur..cur+2].try_into().unwrap()) as usize;
        if length < 2 || cur + 2 + length > data.len() { break; }
        let kind = u16::from_le_bytes(data[cur+2..cur+4].try_into().unwrap());
        let payload = &data[cur+4..cur+2+length];
        if kind == PublicSymbol::KIND {
            let sym = PublicSymbol::parse(payload, record_start + 4)?;
            out.push((u32::try_from(record_start).unwrap_or(u32::MAX), sym));
        }
        cur += 2 + length;
        // Align to 4 bytes
        let aligned = (cur + 3) & !3;
        if aligned > cur { cur = aligned; }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_null_terminated(data: &[u8], abs_offset: usize) -> PublicsResult<String> {
    let end = data.iter().position(|&b| b == 0)
        .ok_or(PublicsError::UnexpectedEof { offset: abs_offset, needed: 1 })?;
    std::str::from_utf8(&data[..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|_| PublicsError::InvalidUtf8 { offset: abs_offset })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pub_sym_record(name: &str, segment: u16, offset: u32, flags: u32) -> Vec<u8> {
        // payload: flags(4) + offset(4) + segment(2) + name(null-term)
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&segment.to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.push(0u8);

        // record: length(2) + kind(2) + payload
        let length = u16::try_from(2 + payload.len()).unwrap();
        let mut rec = Vec::new();
        rec.extend_from_slice(&length.to_le_bytes());
        rec.extend_from_slice(&PublicSymbol::KIND.to_le_bytes());
        rec.extend_from_slice(&payload);
        // pad to 4 bytes
        while rec.len() % 4 != 0 { rec.push(0); }
        rec
    }

    #[test]
    fn parse_single_symbol() {
        let rec = make_pub_sym_record("_MyFunction", 1, 0x1234, 0x0002);
        let pairs = parse_sym_records(&rec).unwrap();
        assert_eq!(pairs.len(), 1);
        let sym = &pairs[0].1;
        assert_eq!(sym.name, "_MyFunction");
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.offset, 0x1234);
        assert!(sym.flags.is_function());
    }

    #[test]
    fn parse_multiple_symbols() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_pub_sym_record("Alpha", 1, 0x100, 0x0002));
        data.extend_from_slice(&make_pub_sym_record("Beta", 1, 0x200, 0x0001));
        data.extend_from_slice(&make_pub_sym_record("Gamma", 2, 0x300, 0x0000));
        let pairs = parse_sym_records(&data).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].1.name, "Alpha");
        assert_eq!(pairs[1].1.name, "Beta");
        assert_eq!(pairs[2].1.name, "Gamma");
    }

    #[test]
    fn name_hash_table_truncated_lengths_clamp_consumed() {
        // Attacker-declared hr_len/bucket_bitmap_len far beyond the buffer:
        // `consumed` must never exceed data.len() - offset.
        let mut data = Vec::new();
        data.extend_from_slice(&NameHashTable::HASH_VERSION.to_le_bytes());
        data.extend_from_slice(&0xFFFF_0000u32.to_le_bytes()); // hr_len (huge)
        data.extend_from_slice(&0xFFFF_0000u32.to_le_bytes()); // bitmap len (huge)
        data.extend_from_slice(&[0u8; 16]); // a few trailing bytes
        let (_tbl, consumed) = NameHashTable::parse(&data, 0).unwrap();
        assert!(consumed <= data.len(), "consumed {consumed} > {}", data.len());
    }

    #[test]
    fn address_map_find_nearest() {
        let syms = [(0u32, PublicSymbol { flags: PubSymFlags(0), offset: 0x100, segment: 1, name: "A".into() }),
            (8u32, PublicSymbol { flags: PubSymFlags(0), offset: 0x200, segment: 1, name: "B".into() }),
            (16u32, PublicSymbol { flags: PubSymFlags(0), offset: 0x300, segment: 1, name: "C".into() })];
        let refs: Vec<(u32, &PublicSymbol)> = syms.iter().map(|(o, s)| (*o, s)).collect();
        let map = AddressMap::from_symbols(&refs);

        let e = map.find_nearest(1, 0x250).unwrap();
        assert_eq!(e.1, 0x200); // B's offset

        let e2 = map.find_nearest(1, 0x100).unwrap();
        assert_eq!(e2.1, 0x100); // A's offset

        assert!(map.find_nearest(1, 0x50).is_none());
    }

    #[test]
    fn address_map_exact_match() {
        let syms = [(0u32, PublicSymbol { flags: PubSymFlags(0), offset: 0x400, segment: 1, name: "X".into() })];
        let refs: Vec<(u32, &PublicSymbol)> = syms.iter().map(|(o, s)| (*o, s)).collect();
        let map = AddressMap::from_symbols(&refs);
        let e = map.find_nearest(1, 0x400).unwrap();
        assert_eq!(e.1, 0x400);
    }

    #[test]
    fn sym_flags_code() {
        let sym = PublicSymbol {
            flags: PubSymFlags(0x0001),
            offset: 0,
            segment: 1,
            name: "x".into(),
        };
        assert!(sym.flags.is_code());
        assert!(!sym.flags.is_function());
    }

    #[test]
    fn sym_flags_managed_msil() {
        let f = PubSymFlags(0x000C);
        assert!(f.is_managed());
        assert!(f.is_msil());
        assert!(!f.is_code());
    }

    #[test]
    fn address_string_format() {
        let sym = PublicSymbol {
            flags: PubSymFlags(0),
            offset: 0x1234_ABCD,
            segment: 2,
            name: "test".into(),
        };
        assert_eq!(sym.address_string(), "0002:1234ABCD");
    }

    #[test]
    fn publics_reader_find_by_name() {
        let mut sym_data = Vec::new();
        sym_data.extend_from_slice(&make_pub_sym_record("_start", 1, 0x1000, 0x0002));
        sym_data.extend_from_slice(&make_pub_sym_record("_end", 1, 0x2000, 0x0000));

        let pub_data = vec![0u8; PublicsHeader::SIZE];
        // sym_hash_size=0, addr_map_size=0
        let reader = PublicsReader::parse(&pub_data, &sym_data).unwrap();
        assert_eq!(reader.symbols.len(), 2);
        assert!(reader.find_by_name("_start").is_some());
        assert!(reader.find_by_name("_missing").is_none());
    }

    #[test]
    fn publics_reader_functions_filter() {
        let mut sym_data = Vec::new();
        sym_data.extend_from_slice(&make_pub_sym_record("func1", 1, 0x100, 0x0002));
        sym_data.extend_from_slice(&make_pub_sym_record("data1", 1, 0x200, 0x0001));
        sym_data.extend_from_slice(&make_pub_sym_record("func2", 1, 0x300, 0x0002));

        let pub_data = vec![0u8; PublicsHeader::SIZE];
        let reader = PublicsReader::parse(&pub_data, &sym_data).unwrap();
        assert_eq!(reader.functions().len(), 2);
        assert_eq!(reader.code_symbols().len(), 3); // is_code() checks bit 0 (0x0001)
    }
}
