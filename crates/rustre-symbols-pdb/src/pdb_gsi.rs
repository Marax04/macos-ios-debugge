// pdb_gsi.rs — Global Symbol Index (GSI) and Public Symbol Index (PSI) for PDB files
//
// The GSI maps symbol names to symbol record offsets within the symbol record stream.
// The PSI extends GSI with address-sorted public symbols (functions, thunks, statics)
// and supports lookup by virtual address as well as by name.
//
// Binary layout (both GSI and PSI share the GSI hash header):
//
//   GSIHashHeader (8 bytes):
//     u32 ver_signature  — always 0xFFFFFFFF
//     u32 ver_header     — always 0x80000001
//
//   followed by:
//     u32 hr_size        — byte size of the hash record array
//     u32 num_buckets    — byte size of the bucket bitmap
//
//   Hash records: array of HRFile { offset_cf: i32, cref: i32 }
//   Bitmap:       bitvector for 4096 buckets
//   Hash buckets: u32[] of chain offsets
//
//  PSI extends this with a sorted address table for RVA-based lookup.

use std::collections::HashMap;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// GSI hash header version signature (always `0xFFFFFFFF` for V7 PDBs).
pub const GSI_HASH_V70_SIG: u32 = 0xFFFF_FFFF;
/// GSI hash header version constant (always `0x80000001` for V7 PDBs).
pub const GSI_HASH_V70_HDR: u32 = 0x8000_0001;
/// Number of hash buckets in the GSI hash table (`IPHR_HASH`).
pub const GSI_NUM_BUCKETS: usize = 4096;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing GSI/PSI stream data.
#[derive(Debug)]
pub enum GsiError {
    /// The stream is shorter than the parser required.
    TooShort {
        /// Number of bytes required.
        need: usize,
        /// Number of bytes available.
        have: usize,
    },
    /// The GSI hash header signature is not `0xFFFFFFFF`.
    BadSignature {
        /// The signature value actually read.
        got: u32,
    },
    /// The GSI hash header version is not `0x80000001`.
    BadHeaderVersion {
        /// The version value actually read.
        got: u32,
    },
    /// The bucket bitmap is smaller than the expected on-disk size.
    BadBitmapSize {
        /// Expected bitmap size in bytes.
        expected: usize,
        /// Actual bitmap size in bytes.
        got: usize,
    },
    /// A hash record could not be decoded.
    BadRecordData,
}

impl fmt::Display for GsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, have } => write!(f, "GSI too short: need {need}, have {have}"),
            Self::BadSignature { got } => write!(f, "GSI bad signature: {got:#010x}"),
            Self::BadHeaderVersion { got } => write!(f, "GSI bad header version: {got:#010x}"),
            Self::BadBitmapSize { expected, got } => write!(f, "GSI bitmap size: expected {expected}, got {got}"),
            Self::BadRecordData => write!(f, "GSI record data error"),
        }
    }
}

impl std::error::Error for GsiError {}

// ── GSI Hash Header ───────────────────────────────────────────────────────────

/// Parsed GSI hash header (16 bytes at the start of the hash section).
#[derive(Debug, Clone)]
pub struct GsiHashHeader {
    /// Version signature, always [`GSI_HASH_V70_SIG`].
    pub ver_signature: u32,
    /// Header version, always [`GSI_HASH_V70_HDR`].
    pub ver_header: u32,
    /// Byte size of the hash record array.
    pub hr_size: u32,
    /// Byte size of the bucket bitmap plus bucket table.
    pub num_buckets: u32,
}

impl GsiHashHeader {
    /// On-disk size of the header in bytes.
    pub const SIZE: usize = 16;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, GsiError> {
        if data.len() < Self::SIZE {
            return Err(GsiError::TooShort { need: Self::SIZE, have: data.len() });
        }
        let ver_signature = read_u32_le(data, 0);
        if ver_signature != GSI_HASH_V70_SIG {
            return Err(GsiError::BadSignature { got: ver_signature });
        }
        let ver_header = read_u32_le(data, 4);
        if ver_header != GSI_HASH_V70_HDR {
            return Err(GsiError::BadHeaderVersion { got: ver_header });
        }
        Ok(Self {
            ver_signature,
            ver_header,
            hr_size: read_u32_le(data, 8),
            num_buckets: read_u32_le(data, 12),
        })
    }

    /// Number of hash records in the hash record array
    #[must_use]
    pub const fn hash_record_count(&self) -> usize {
        self.hr_size as usize / HRFile::SIZE
    }
}

// ── Hash Record ───────────────────────────────────────────────────────────────

/// Hash record as stored in the GSI stream (`HRFile`)
#[derive(Debug, Clone, Copy)]
pub struct HRFile {
    /// Byte offset of the symbol in the symbol record stream (plus 1)
    pub offset_cf: i32,
    /// Reference count (in V7 PDB this is always 1; used by incremental linking)
    pub cref: i32,
}

/// Size of one hash record in the writer's *in-memory* representation.
///
/// The writer computed bucket-table offsets over `{ void* psym; long cref; }`
/// (12 bytes), so bucket offsets in the stream are in these units, while the
/// records themselves are stored in the 8-byte on-disk form
/// ([`HRFile::SIZE`]). LLVM's PDB reader carries the same distinction.
pub const HR_IN_MEMORY_SIZE: usize = 12;

impl HRFile {
    /// On-disk size of one hash record: `i32 offset_cf` + `i32 cref`.
    pub const SIZE: usize = 8;

    /// Parse one hash record at `offset`; `None` if out of bounds.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + Self::SIZE > data.len() {
            return None;
        }
        Some(Self {
            offset_cf: i32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]),
            cref: i32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]),
        })
    }

    /// Return the 0-based symbol record offset (`offset_cf` - 1)
    #[must_use]
    pub const fn sym_offset(&self) -> Option<u32> {
        if self.offset_cf > 0 {
            Some((self.offset_cf - 1).cast_unsigned())
        } else {
            None
        }
    }
}

// ── Bitmap helper ─────────────────────────────────────────────────────────────

/// Bitmap over 4096 buckets; each bit indicates whether a chain is non-empty
#[derive(Debug, Clone)]
pub struct GsiBitmap {
    data: Vec<u8>,
}

impl GsiBitmap {
    /// Expected on-disk byte size of the bucket bitmap.
    ///
    /// The bitmap covers `IPHR_HASH + 1` = 4097 bits (one trailing sentinel
    /// bucket), rounded up to a 32-bit boundary: 4128 bits = **516 bytes**.
    /// It is *not* `GSI_NUM_BUCKETS / 8` (512) — using 512 desynchronizes the
    /// bucket table that follows by 4 bytes.
    pub const EXPECTED_BYTES: usize = (GSI_NUM_BUCKETS + 1).div_ceil(32) * 4;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, GsiError> {
        if data.len() < Self::EXPECTED_BYTES {
            return Err(GsiError::BadBitmapSize {
                expected: Self::EXPECTED_BYTES,
                got: data.len(),
            });
        }
        Ok(Self { data: data[..Self::EXPECTED_BYTES].to_vec() })
    }

    /// True if the given bucket's chain is non-empty.
    #[must_use]
    pub fn is_set(&self, bucket: usize) -> bool {
        if bucket >= GSI_NUM_BUCKETS {
            return false;
        }
        let byte_idx = bucket / 8;
        let bit_idx = bucket % 8;
        self.data[byte_idx] & (1 << bit_idx) != 0
    }

    /// Iterate over set bucket indices
    pub fn set_buckets(&self) -> impl Iterator<Item = usize> + '_ {
        (0..GSI_NUM_BUCKETS).filter(move |&b| self.is_set(b))
    }

    /// Count of non-empty buckets.
    ///
    /// Bounded to `GSI_NUM_BUCKETS` on purpose: the on-disk bitmap is padded
    /// past the last real bucket, and popcounting the raw buffer would inflate
    /// the bucket-table length by however many padding bits happen to be set.
    #[must_use]
    pub fn count_set(&self) -> usize {
        self.set_buckets().count()
    }
}

// ── GSI Hash Table ─────────────────────────────────────────────────────────────

/// Full parsed GSI hash structure
#[derive(Debug)]
pub struct GsiHash {
    /// Parsed GSI hash header.
    pub header: GsiHashHeader,
    /// All hash records (`HRFile`) in stream order.
    pub hash_records: Vec<HRFile>,
    /// Bitmap of non-empty buckets.
    pub bitmap: GsiBitmap,
    /// Bucket table: `bucket_index` → offset in hash record array
    pub bucket_table: Vec<i32>,
}

impl GsiHash {
    /// Parse the GSI hash section from raw stream data
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, GsiError> {
        let header = GsiHashHeader::parse(data)?;
        let mut offset = GsiHashHeader::SIZE;

        // Hash record array
        let hr_size = header.hr_size as usize;
        if offset + hr_size > data.len() {
            return Err(GsiError::TooShort { need: offset + hr_size, have: data.len() });
        }
        let count = hr_size / HRFile::SIZE;
        let mut hash_records = Vec::with_capacity(count);
        for i in 0..count {
            match HRFile::parse(&data[offset..], i * HRFile::SIZE) {
                Some(hr) => hash_records.push(hr),
                None => return Err(GsiError::BadRecordData),
            }
        }
        offset += hr_size;

        // Bitmap
        if offset + GsiBitmap::EXPECTED_BYTES > data.len() {
            return Err(GsiError::TooShort { need: offset + GsiBitmap::EXPECTED_BYTES, have: data.len() });
        }
        let bitmap = GsiBitmap::parse(&data[offset..])?;
        offset += GsiBitmap::EXPECTED_BYTES;

        // Bucket table: one i32 per set bit in bitmap
        let set_count = bitmap.count_set();
        let bucket_bytes = set_count * 4;
        if offset + bucket_bytes > data.len() {
            return Err(GsiError::TooShort { need: offset + bucket_bytes, have: data.len() });
        }
        let mut bucket_table = Vec::with_capacity(set_count);
        for i in 0..set_count {
            bucket_table.push(i32::from_le_bytes([
                data[offset + i*4],
                data[offset + i*4 + 1],
                data[offset + i*4 + 2],
                data[offset + i*4 + 3],
            ]));
        }

        Ok(Self { header, hash_records, bitmap, bucket_table })
    }

    /// Compute the GSI hash of a symbol name (Microsoft's `HashStringV1`).
    ///
    /// The algorithm is: XOR the name in 4-byte little-endian longs, XOR the
    /// 2-byte then 1-byte remainder, **case-fold with `|= 0x2020_2020`**, then
    /// apply the two shift-XOR scrambles. Omitting the case-fold makes every
    /// computed bucket differ from the one the linker wrote, so no lookup ever
    /// hits.
    #[must_use]
    pub fn hash_name(name: &str) -> usize {
        let bytes = name.as_bytes();
        let mut hash: u32 = 0;

        let chunks = bytes.len() / 4;
        for i in 0..chunks {
            let b = &bytes[i * 4..i * 4 + 4];
            hash ^= u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let mut rest = &bytes[chunks * 4..];
        if rest.len() >= 2 {
            hash ^= u32::from(u16::from_le_bytes([rest[0], rest[1]]));
            rest = &rest[2..];
        }
        if let Some(&b) = rest.first() {
            hash ^= u32::from(b);
        }

        // Case-fold (tolower on each byte lane), then scramble.
        hash |= 0x2020_2020;
        hash ^= hash >> 11;
        hash ^= hash >> 16;

        (hash as usize) % GSI_NUM_BUCKETS
    }

    /// Resolve all symbol offsets in a given bucket
    #[must_use]
    pub fn offsets_for_bucket(&self, bucket: usize) -> Vec<u32> {
        if !self.bitmap.is_set(bucket) {
            return vec![];
        }
        // Count how many set buckets precede this one → gives index into bucket_table
        let preceding_set = (0..bucket).filter(|&b| self.bitmap.is_set(b)).count();
        if preceding_set >= self.bucket_table.len() {
            return vec![];
        }
        let start = self.bucket_table[preceding_set];
        if start < 0 {
            return vec![];
        }
        // Bucket offsets are expressed in units of the 12-byte *in-memory*
        // HRFile representation, not the 8-byte on-disk one. Dividing by
        // HRFile::SIZE (8) lands 1.5x too far into the record array.
        let start_idx = (usize::try_from(start).unwrap_or(0)) / HR_IN_MEMORY_SIZE;

        // The chain ends where the *next* set bucket's chain begins — `cref` is
        // a reference count (normally 1 for every record in a V7 PDB), not a
        // sentinel, so terminating on it walks to the end of the stream and
        // returns every symbol.
        let end_idx = self
            .bucket_table
            .get(preceding_set + 1)
            .and_then(|&next| usize::try_from(next).ok())
            .map_or(self.hash_records.len(), |next| next / HR_IN_MEMORY_SIZE)
            .min(self.hash_records.len());

        let mut result = Vec::new();
        let mut idx = start_idx;
        while idx < end_idx {
            if let Some(off) = self.hash_records[idx].sym_offset() {
                result.push(off);
            }
            idx += 1;
        }
        result
    }
}

// ── Symbol Record Reader ───────────────────────────────────────────────────────

/// Reads a symbol name from the symbol record stream at a given offset.
///
/// Symbol records are: u16 length, u16 type, data...
/// For `S_PUB32` / `S_GDATA32` / `S_PROCREF` the name is a null-terminated string
/// at a known offset within the record body.
#[derive(Debug, Clone)]
pub struct SymbolRecord {
    /// `CodeView` record type code (e.g. `S_PUB32`).
    pub record_type: u16,
    /// Record body bytes (after the 4-byte length/type header).
    pub data: Vec<u8>,
    /// Byte offset of the record within the symbol record stream.
    pub offset_in_stream: u32,
}

impl SymbolRecord {
    /// Read a symbol record from the symbol record stream at given offset
    #[must_use]
    pub fn read(sym_data: &[u8], offset: u32) -> Option<Self> {
        let off = offset as usize;
        if off + 4 > sym_data.len() {
            return None;
        }
        let length = read_u16_le(sym_data, off) as usize;
        let record_type = read_u16_le(sym_data, off + 2);
        if off + 2 + length > sym_data.len() {
            return None;
        }
        Some(Self {
            record_type,
            data: sym_data[off + 4..off + 2 + length].to_vec(),
            offset_in_stream: offset,
        })
    }

    // Values mirror `crate::sym_kinds` (cvinfo.h SYM_ENUM_e).
    /// `S_PUB32` — public symbol record type.
    pub const S_PUB32: u16 = crate::sym_kinds::S_PUB32;
    /// `S_GDATA32` — global data symbol record type.
    pub const S_GDATA32: u16 = crate::sym_kinds::S_GDATA32;
    /// `S_LTHREAD32` — local thread-local storage symbol record type.
    pub const S_LTHREAD32: u16 = crate::sym_kinds::S_LTHREAD32;
    /// `S_GTHREAD32` — global thread-local storage symbol record type.
    pub const S_GTHREAD32: u16 = crate::sym_kinds::S_GTHREAD32;
    /// `S_PROCREF` — reference to a procedure in a module stream.
    pub const S_PROCREF: u16 = crate::sym_kinds::S_PROCREF;
    /// `S_DATAREF` — reference to a data symbol in a module stream.
    pub const S_DATAREF: u16 = crate::sym_kinds::S_DATAREF;
    /// `S_LPROCREF` — reference to a local procedure in a module stream.
    pub const S_LPROCREF: u16 = crate::sym_kinds::S_LPROCREF;
    /// `S_LDATA32` — local data symbol record type.
    pub const S_LDATA32: u16 = crate::sym_kinds::S_LDATA32;
    /// `S_UDT` — user-defined type alias record type.
    pub const S_UDT: u16 = crate::sym_kinds::S_UDT;
    /// `S_CONSTANT` — named constant record type.
    pub const S_CONSTANT: u16 = crate::sym_kinds::S_CONSTANT;

    /// Extract the symbol name from a PUB32 record
    /// Layout: u32 `pub_sym_flags`, u32 offset, u16 segment, name (cstr)
    #[must_use]
    pub fn pub32_name(&self) -> Option<&str> {
        if self.record_type == Self::S_PUB32 && self.data.len() > 10 {
            let name_start = 10;
            self.cstr_at(name_start)
        } else {
            None
        }
    }

    /// Extract (segment, offset) from a PUB32 record
    #[must_use]
    pub fn pub32_addr(&self) -> Option<(u16, u32)> {
        if self.record_type == Self::S_PUB32 && self.data.len() >= 10 {
            let offset = read_u32_le(&self.data, 4);
            let segment = read_u16_le(&self.data, 8);
            Some((segment, offset))
        } else {
            None
        }
    }

    /// PUB32 flags: 1=function 2=abs 4=managed 8=MSIL
    #[must_use]
    pub fn pub32_flags(&self) -> Option<u32> {
        if self.record_type == Self::S_PUB32 && self.data.len() >= 4 {
            Some(read_u32_le(&self.data, 0))
        } else {
            None
        }
    }

    /// Extract name from GDATA32 / LDATA32
    #[must_use]
    pub fn gdata32_name(&self) -> Option<&str> {
        // Layout: u32 type_index, u32 offset, u16 segment, name
        if (self.record_type == Self::S_GDATA32 || self.record_type == Self::S_LDATA32)
            && self.data.len() > 10
        {
            self.cstr_at(10)
        } else {
            None
        }
    }

    /// Extract the symbol name for any supported record type.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self.record_type {
            Self::S_PUB32 => self.pub32_name(),
            Self::S_GDATA32 | Self::S_LDATA32 => self.gdata32_name(),
            Self::S_PROCREF | Self::S_LPROCREF | Self::S_DATAREF => {
                // Layout: u32 sumName, u32 ibSym, u16 imod, name
                if self.data.len() > 10 { self.cstr_at(10) } else { None }
            }
            Self::S_UDT => {
                // Layout: u32 type_index, name
                if self.data.len() > 4 { self.cstr_at(4) } else { None }
            }
            _ => None,
        }
    }

    fn cstr_at(&self, start: usize) -> Option<&str> {
        let slice = &self.data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end]).ok()
    }

    /// True if this is an `S_PUB32` record with the function flag set.
    #[must_use]
    pub fn is_function(&self) -> bool {
        self.pub32_flags().is_some_and(|f| f & 1 != 0)
    }
}

// ── Global Symbol Index ────────────────────────────────────────────────────────

/// High-level Global Symbol Index: maps symbol names to their offsets in the
/// symbol record stream.
pub struct GlobalSymbolIndex {
    hash: GsiHash,
    /// Cached name→offset map, built lazily
    name_cache: HashMap<String, Vec<u32>>,
}

impl GlobalSymbolIndex {
    /// Wrap an already-parsed GSI hash table.
    #[must_use]
    pub fn new(hash: GsiHash) -> Self {
        Self { hash, name_cache: HashMap::new() }
    }

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(gsi_stream: &[u8]) -> Result<Self, GsiError> {
        let hash = GsiHash::parse(gsi_stream)?;
        Ok(Self::new(hash))
    }

    /// Look up symbol record offsets by exact name
    pub fn lookup_by_name(&mut self, name: &str, sym_data: &[u8]) -> Vec<SymbolRecord> {
        // Check cache first
        let offsets = if let Some(cached) = self.name_cache.get(name) {
            cached.clone()
        } else {
            let bucket = GsiHash::hash_name(name);
            let offsets = self.hash.offsets_for_bucket(bucket);
            self.name_cache.insert(name.to_string(), offsets.clone());
            offsets
        };

        offsets.iter()
            .filter_map(|&off| SymbolRecord::read(sym_data, off))
            .filter(|rec| rec.name() == Some(name))
            .collect()
    }

    /// Enumerate ALL symbol records in the GSI
    pub fn all_symbol_offsets(&self) -> impl Iterator<Item = u32> + '_ {
        self.hash.hash_records.iter().filter_map(HRFile::sym_offset)
    }

    /// Build a full name→records map by scanning the entire hash table
    #[must_use]
    pub fn build_full_index(&self, sym_data: &[u8]) -> HashMap<String, Vec<SymbolRecord>> {
        let mut map: HashMap<String, Vec<SymbolRecord>> = HashMap::new();
        for off in self.all_symbol_offsets() {
            if let Some(rec) = SymbolRecord::read(sym_data, off)
                && let Some(name) = rec.name() {
                    map.entry(name.to_string()).or_default().push(rec);
                }
        }
        map
    }

    /// Number of hash records in the GSI.
    #[must_use]
    pub const fn hash_record_count(&self) -> usize { self.hash.hash_records.len() }
    /// Number of non-empty hash buckets.
    #[must_use]
    pub fn non_empty_buckets(&self) -> usize { self.hash.bitmap.count_set() }
}

// ── Public Symbol Index ────────────────────────────────────────────────────────

/// Address-sorted public symbol entry (used by PSI for RVA lookup)
#[derive(Debug, Clone)]
pub struct AddrMapEntry {
    /// Offset of the symbol record in the symbol record stream
    pub sym_offset: u32,
    /// Virtual address (RVA) from the symbol's segment+offset
    pub rva: u64,
}

/// The Public Symbol Index extends GSI with a sorted address table
pub struct PublicSymbolIndex {
    /// Underlying name-hash index shared with the GSI format.
    pub gsi: GlobalSymbolIndex,
    /// Symbols sorted by RVA for binary-search address lookup
    pub addr_map: Vec<AddrMapEntry>,
}

impl PublicSymbolIndex {
    /// Parse PSI from its stream bytes (GSI hash + address map)
    /// The PSI stream layout:
    ///   `GSIHashHeader` (16 bytes)
    ///   ... hash records, bitmap, bucket table (same as GSI) ...
    ///   u32 `addr_map_size` — byte count of sorted address table
    ///   u32[] `addr_map`   — sorted symbol offsets (into sym record stream)
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(psi_stream: &[u8], sym_data: &[u8]) -> Result<Self, GsiError> {
        // The PSI has a special header before the GSI hash header
        // PSI header: u32 sym_hash_size, u32 addr_map_size, u32 num_thunks, u32 thunk_size,
        //             u16 isect_thunk_table, u16 padding, u32 off_thunk_table, u32 num_sects
        const PSI_HEADER_SIZE: usize = 28;

        if psi_stream.len() < PSI_HEADER_SIZE {
            return Err(GsiError::TooShort { need: PSI_HEADER_SIZE, have: psi_stream.len() });
        }

        let sym_hash_size = read_u32_le(psi_stream, 0) as usize;
        let addr_map_size = read_u32_le(psi_stream, 4) as usize;

        let gsi_data_start = PSI_HEADER_SIZE;
        let gsi_data_end = gsi_data_start + sym_hash_size;

        if gsi_data_end > psi_stream.len() {
            return Err(GsiError::TooShort { need: gsi_data_end, have: psi_stream.len() });
        }

        let gsi = GlobalSymbolIndex::parse(&psi_stream[gsi_data_start..gsi_data_end])?;

        // Address map immediately follows the GSI hash data
        let addr_start = gsi_data_end;
        let addr_count = addr_map_size / 4;

        // `addr_map_size` is attacker-controlled; cap the pre-allocation by
        // the entries the remaining stream bytes can hold.
        let max_entries = psi_stream.len().saturating_sub(addr_start) / 4;
        let mut addr_map = Vec::with_capacity(addr_count.min(max_entries));
        for i in 0..addr_count {
            let off = addr_start + i * 4;
            if off + 4 > psi_stream.len() { break; }
            let sym_off = read_u32_le(psi_stream, off);
            // Resolve segment+offset → RVA using the symbol record
            let rva = SymbolRecord::read(sym_data, sym_off).map_or(0, |rec| rec.pub32_addr()
                    .map_or(0, |(seg, soff)| compute_rva(seg, soff)));
            addr_map.push(AddrMapEntry { sym_offset: sym_off, rva });
        }

        // Ensure sorted by RVA (should already be, but guarantee it)
        addr_map.sort_by_key(|e| e.rva);

        Ok(Self { gsi, addr_map })
    }

    /// Look up the nearest public symbol at or below a given RVA
    #[must_use]
    pub fn nearest_symbol(&self, rva: u64, sym_data: &[u8]) -> Option<(SymbolRecord, u64)> {
        let idx = match self.addr_map.binary_search_by_key(&rva, |e| e.rva) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let entry = &self.addr_map[idx];
        let rec = SymbolRecord::read(sym_data, entry.sym_offset)?;
        Some((rec, rva - entry.rva))
    }

    /// Look up the exact symbol at a given RVA
    #[must_use]
    pub fn symbol_at_rva(&self, rva: u64, sym_data: &[u8]) -> Option<SymbolRecord> {
        let idx = self.addr_map.binary_search_by_key(&rva, |e| e.rva).ok()?;
        SymbolRecord::read(sym_data, self.addr_map[idx].sym_offset)
    }

    /// Collect all public symbols, sorted by RVA
    #[must_use]
    pub fn all_public_symbols(&self, sym_data: &[u8]) -> Vec<PublicSymbol> {
        self.addr_map.iter()
            .filter_map(|entry| {
                let rec = SymbolRecord::read(sym_data, entry.sym_offset)?;
                let name = rec.name()?.to_string();
                let (segment, offset) = rec.pub32_addr()?;
                Some(PublicSymbol {
                    name,
                    segment,
                    offset,
                    rva: entry.rva,
                    is_function: rec.is_function(),
                    sym_offset: entry.sym_offset,
                })
            })
            .collect()
    }

    /// Number of entries in the sorted address map
    #[must_use]
    pub const fn addr_map_count(&self) -> usize { self.addr_map.len() }
}

/// A decoded public symbol
#[derive(Debug, Clone)]
pub struct PublicSymbol {
    /// Mangled symbol name.
    pub name: String,
    /// PE section (1-based)
    pub segment: u16,
    /// Offset within the section
    pub offset: u32,
    /// Computed RVA
    pub rva: u64,
    /// True if the `S_PUB32` function flag is set.
    pub is_function: bool,
    /// Byte offset in the symbol record stream
    pub sym_offset: u32,
}

impl PublicSymbol {
    /// Heuristic: true if the name looks like an import thunk.
    #[must_use]
    pub fn is_thunk(&self) -> bool {
        self.name.starts_with("__imp_") || self.name.contains("$thunk$")
    }

    /// Rough demangling hint: strips the leading MSVC cdecl underscore.
    #[must_use]
    pub fn demangled_hint(&self) -> &str {
        // Very rough: strip leading underscore common in MSVC cdecl
        let s = self.name.as_str();
        if s.starts_with('_') && s.len() > 1 && s.chars().nth(1).is_some_and(char::is_alphabetic) {
            &s[1..]
        } else {
            s
        }
    }
}

// ── Symbol Name Lookup ─────────────────────────────────────────────────────────

/// Scan the entire symbol record stream and collect all public symbols by name
#[must_use]
pub fn collect_all_pub_symbols(sym_data: &[u8]) -> HashMap<String, PublicSymbol> {
    let mut map = HashMap::new();
    let mut offset = 0usize;
    while offset + 4 <= sym_data.len() {
        let length = read_u16_le(sym_data, offset) as usize;
        if length < 2 || offset + 2 + length > sym_data.len() {
            break;
        }
        let rec_type = read_u16_le(sym_data, offset + 2);
        if rec_type == SymbolRecord::S_PUB32
            && let Some(rec) = SymbolRecord::read(sym_data, u32::try_from(offset).unwrap_or(u32::MAX))
                && let (Some(name), Some((seg, off))) = (rec.name(), rec.pub32_addr()) {
                    let rva = compute_rva(seg, off);
                    map.insert(name.to_string(), PublicSymbol {
                        name: name.to_string(),
                        segment: seg,
                        offset: off,
                        rva,
                        is_function: rec.is_function(),
                        sym_offset: u32::try_from(offset).unwrap_or(u32::MAX),
                    });
                }
        let next = offset + 2 + length;
        if next <= offset { break; }
        offset = next;
    }
    map
}

/// Scan symbol records and collect global data symbols (`S_GDATA32`)
#[must_use]
pub fn collect_global_data(sym_data: &[u8]) -> Vec<(String, u16, u32)> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= sym_data.len() {
        let length = read_u16_le(sym_data, offset) as usize;
        if length < 2 || offset + 2 + length > sym_data.len() { break; }
        let rec_type = read_u16_le(sym_data, offset + 2);
        if rec_type == SymbolRecord::S_GDATA32
            && let Some(rec) = SymbolRecord::read(sym_data, u32::try_from(offset).unwrap_or(u32::MAX)) {
                // Layout: u32 type, u32 data_offset, u16 segment, name
                if rec.data.len() >= 10 {
                    let data_offset = read_u32_le(&rec.data, 4);
                    let segment = read_u16_le(&rec.data, 8);
                    if let Some(name) = rec.name() {
                        result.push((name.to_string(), segment, data_offset));
                    }
                }
            }
        let next = offset + 2 + length;
        if next <= offset { break; }
        offset = next;
    }
    result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute an approximate RVA from segment+offset.
/// Without an actual section header table we can only approximate; callers
/// with access to the PE header should apply the real section base.
fn compute_rva(segment: u16, offset: u32) -> u64 {
    // For symbols in segment 0 (absolute), we cannot determine an RVA.
    if segment == 0 { return 0; }
    // Otherwise, treat offset as the RVA directly (correct for non-ASLR, same-base PE)
    u64::from(offset)
}

/// Build a lookup table from section headers (PE `IMAGE_SECTION_HEADER` array).
/// Each entry is (`virtual_address`, `size_of_raw_data`). Returns
/// a function that maps (segment, offset) → RVA.
pub struct SectionRvaMap {
    sections: Vec<(u32, u32)>, // (virtual_address, size)
}

impl SectionRvaMap {
    /// Parse from raw PE section header bytes (40 bytes per entry)
    #[must_use]
    pub fn parse_from_section_headers(data: &[u8]) -> Self {
        const HDR_SIZE: usize = 40;
        let count = data.len() / HDR_SIZE;
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let base = i * HDR_SIZE;
            if base + HDR_SIZE > data.len() { break; }
            let virt_addr = read_u32_le(data, base + 12);
            let virt_size = read_u32_le(data, base + 8);
            sections.push((virt_addr, virt_size));
        }
        Self { sections }
    }

    /// Map a (segment, offset) pair to an RVA using the section table.
    #[must_use]
    pub fn rva_for(&self, segment: u16, offset: u32) -> Option<u64> {
        let idx = segment.checked_sub(1)? as usize;
        let (virt_addr, _) = self.sections.get(idx)?;
        Some(u64::from(*virt_addr) + u64::from(offset))
    }

    /// Number of sections in the map.
    #[must_use]
    pub const fn count(&self) -> usize { self.sections.len() }
}

// ── GSI summary ───────────────────────────────────────────────────────────────

/// Summary statistics about a parsed GSI.
#[derive(Debug)]
pub struct GsiSummary {
    /// Number of hash records.
    pub hash_record_count: usize,
    /// Number of non-empty hash buckets.
    pub non_empty_buckets: usize,
    /// Total bucket count ([`GSI_NUM_BUCKETS`]).
    pub total_buckets: usize,
}

impl fmt::Display for GsiSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "GSI: {} hash records, {}/{} buckets non-empty ({:.1}% load)",
            self.hash_record_count,
            self.non_empty_buckets,
            self.total_buckets,
            {
                // Convert via u32 to f64 losslessly (u32 fits exactly in f64).
                let neb = u32::try_from(self.non_empty_buckets).unwrap_or(u32::MAX);
                let tb  = u32::try_from(self.total_buckets).unwrap_or(u32::MAX);
                f64::from(neb) / f64::from(tb.max(1)) * 100.0
            }
        )
    }
}

/// Build a [`GsiSummary`] for a parsed [`GlobalSymbolIndex`].
#[must_use]
pub fn gsi_summary(gsi: &GlobalSymbolIndex) -> GsiSummary {
    GsiSummary {
        hash_record_count: gsi.hash_record_count(),
        non_empty_buckets: gsi.non_empty_buckets(),
        total_buckets: GSI_NUM_BUCKETS,
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gsi_header_bytes(hr_size: u32, num_buckets: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(GsiHashHeader::SIZE);
        v.extend_from_slice(&GSI_HASH_V70_SIG.to_le_bytes());
        v.extend_from_slice(&GSI_HASH_V70_HDR.to_le_bytes());
        v.extend_from_slice(&hr_size.to_le_bytes());
        v.extend_from_slice(&num_buckets.to_le_bytes());
        v
    }

    #[test]
    fn test_gsi_header_parse() {
        let data = make_gsi_header_bytes(16, 512);
        let hdr = GsiHashHeader::parse(&data).unwrap();
        assert_eq!(hdr.ver_signature, GSI_HASH_V70_SIG);
        assert_eq!(hdr.hr_size, 16);
        assert_eq!(hdr.hash_record_count(), 2); // 16/8
    }

    #[test]
    fn test_gsi_header_bad_sig() {
        let mut data = make_gsi_header_bytes(0, 0);
        data[0] = 0x00;
        assert!(matches!(GsiHashHeader::parse(&data), Err(GsiError::BadSignature { .. })));
    }

    #[test]
    fn test_hrfile_sym_offset() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&5i32.to_le_bytes()); // offset_cf=5 → sym_offset=4
        data[4..8].copy_from_slice(&1i32.to_le_bytes());
        let hr = HRFile::parse(&data, 0).unwrap();
        assert_eq!(hr.sym_offset(), Some(4));
    }

    #[test]
    fn test_hrfile_negative_offset() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&(-1i32).to_le_bytes());
        data[4..8].copy_from_slice(&1i32.to_le_bytes());
        let hr = HRFile::parse(&data, 0).unwrap();
        assert_eq!(hr.sym_offset(), None);
    }

    #[test]
    fn test_bitmap_set_get() {
        let mut data = vec![0u8; GsiBitmap::EXPECTED_BYTES];
        data[0] = 0b0000_0101; // bits 0 and 2 set
        let bm = GsiBitmap::parse(&data).unwrap();
        assert!(bm.is_set(0));
        assert!(!bm.is_set(1));
        assert!(bm.is_set(2));
        assert_eq!(bm.count_set(), 2);
    }

    #[test]
    fn test_hash_name_basic() {
        // Ensure it doesn't panic and returns a valid bucket
        let bucket = GsiHash::hash_name("SomeFunction");
        assert!(bucket < GSI_NUM_BUCKETS);
        // Same input must always produce same bucket
        assert_eq!(GsiHash::hash_name("SomeFunction"), bucket);
    }

    #[test]
    fn test_section_rva_map() {
        let mut data = vec![0u8; 40]; // one section
        // name (8 bytes), virtual size (4), virtual addr (4), ...
        data[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // virt addr
        data[16..20].copy_from_slice(&0x500u32.to_le_bytes());  // virt size
        let map = SectionRvaMap::parse_from_section_headers(&data);
        assert_eq!(map.count(), 1);
        assert_eq!(map.rva_for(1, 0x10), Some(0x1010));
        assert_eq!(map.rva_for(2, 0), None); // no second section
    }

    #[test]
    fn test_symbol_record_pub32_name() {
        // Build a minimal PUB32 symbol record in a sym stream
        // Record: u16 length, u16 S_PUB32, u32 flags, u32 offset, u16 segment, name\0
        let name = b"MyFunction\0";
        let body_len: usize = 4 + 4 + 2 + name.len(); // flags + offset + segment + name
        let length = u16::try_from(2 + body_len).unwrap(); // type word + body
        let mut data = Vec::new();
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&SymbolRecord::S_PUB32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // flags (function=1)
        data.extend_from_slice(&0x1234u32.to_le_bytes()); // offset
        data.extend_from_slice(&1u16.to_le_bytes()); // segment
        data.extend_from_slice(name);

        let rec = SymbolRecord::read(&data, 0).unwrap();
        assert_eq!(rec.pub32_name(), Some("MyFunction"));
        assert_eq!(rec.pub32_addr(), Some((1, 0x1234)));
        assert!(rec.is_function());
    }
}
