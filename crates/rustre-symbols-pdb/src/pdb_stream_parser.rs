// rustre-symbols-pdb/src/pdb_stream_parser.rs
// PDB Multi-Stream File (MSF) parser: superblock, FPM, stream directory,
// and arbitrary stream access by index.

use std::collections::HashMap;

use crate::{PdbError, Result};

// ─── MSF Magic ────────────────────────────────────────────────────────────────

/// The 32-byte magic that starts every MSF v7 file.
pub const MSF_MAGIC_V7: &[u8; 32] =
    b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

/// The (older, less common) MSF v2 magic.
pub const MSF_MAGIC_V2: &[u8; 49] =
    b"Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47\x00\x00\x00\x00\x00\x00\x00";

// ─── Superblock ───────────────────────────────────────────────────────────────

/// Parsed MSF superblock (first block of the file).
///
/// Layout (all fields little-endian, starting after the 32-byte magic):
///
/// | Offset | Size | Field                  |
/// |--------|------|------------------------|
/// | 32     | 4    | `block_size`           |
/// | 36     | 4    | `free_block_map_block` |
/// | 40     | 4    | `num_blocks`           |
/// | 44     | 4    | `num_dir_bytes`        |
/// | 48     | 4    | (reserved)             |
/// | 52     | 4    | `block_map_addr`       |
#[derive(Debug, Clone)]
pub struct MsfSuperblock {
    /// Page/block size in bytes (typically 512, 1024, 2048, or 4096).
    pub block_size: u32,
    /// Page index of the Free Page Map (FPM) used by this file.
    pub free_block_map_block: u32,
    /// Total number of blocks in the file.
    pub num_blocks: u32,
    /// Byte size of the stream directory.
    pub num_dir_bytes: u32,
    /// Block index of the block-map array (list of pages that hold the directory).
    pub block_map_addr: u32,
}

impl MsfSuperblock {
    /// Parse the superblock from raw PDB bytes.
    ///
    /// # Errors
    /// Returns [`PdbError::BadMagic`] if the magic bytes do not match MSF v7,
    /// [`PdbError::StreamTooShort`] if the data is too short, or
    /// [`PdbError::CorruptData`] if the declared geometry is not a well-formed
    /// MSF container (non-power-of-two block size, out-of-range FPM index, or a
    /// block count larger than the file can hold).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 56 {
            return Err(PdbError::BadMagic);
        }
        if &raw[0..32] != MSF_MAGIC_V7 {
            return Err(PdbError::BadMagic);
        }
        let sb = Self {
            block_size: read_u32_le(raw, 32)?,
            free_block_map_block: read_u32_le(raw, 36)?,
            num_blocks: read_u32_le(raw, 40)?,
            num_dir_bytes: read_u32_le(raw, 44)?,
            // 48 is reserved
            block_map_addr: read_u32_le(raw, 52)?,
        };
        sb.validate()?;
        Ok(sb)
    }

    /// Reject superblocks whose declared geometry cannot describe a real MSF
    /// container.
    ///
    /// Everything downstream multiplies and divides by `block_size`; a value of
    /// 3 or 0x4000_0000 reassembles a coherent-looking but entirely wrong
    /// stream with no error anywhere in the chain.
    ///
    /// # Errors
    /// [`PdbError::CorruptData`] when any field is out of range.
    pub fn validate(&self) -> Result<()> {
        if !self.is_valid_block_size() {
            return Err(PdbError::CorruptData);
        }
        // The FPM lives at block 1 or 2 in every writer we know of.
        if self.free_block_map_block != 1 && self.free_block_map_block != 2 {
            return Err(PdbError::CorruptData);
        }
        Ok(())
    }

    /// Additionally check `num_blocks` against the bytes actually present.
    ///
    /// Kept separate from [`Self::validate`] because a superblock can be parsed
    /// from a header-only slice.
    ///
    /// # Errors
    /// [`PdbError::CorruptData`] if the file is smaller than `num_blocks`
    /// blocks.
    pub fn validate_against(&self, raw_len: usize) -> Result<()> {
        self.validate()?;
        let bs = self.block_size as usize;
        if bs == 0 || (self.num_blocks as usize) > raw_len.div_ceil(bs) {
            return Err(PdbError::CorruptData);
        }
        Ok(())
    }

    /// Return the number of blocks required to hold `byte_count` bytes.
    #[must_use]
    pub const fn blocks_needed(&self, byte_count: u32) -> u32 {
        if self.block_size == 0 {
            return 0;
        }
        byte_count.div_ceil(self.block_size)
    }

    /// Return the byte offset of block `n` in the file.
    #[must_use]
    pub const fn block_offset(&self, n: u32) -> usize {
        (n as usize).saturating_mul(self.block_size as usize)
    }

    /// Return `true` if the block size is a supported power-of-two value.
    ///
    /// 8192-byte pages are accepted: real MSF files use them. The point is
    /// rejecting non-powers-of-two, not shrinking the set.
    #[must_use]
    pub const fn is_valid_block_size(&self) -> bool {
        self.block_size.is_power_of_two() && self.block_size >= 512 && self.block_size <= 8192
    }
}

// ─── Free Page Map ────────────────────────────────────────────────────────────

/// Parsed Free Page Map (FPM) — tracks which blocks in the file are allocated.
///
/// In MSF, the FPM is one page (or two alternating pages in bigger files) where
/// each bit corresponds to one block: 0 = allocated, 1 = free.
#[derive(Debug, Clone)]
pub struct FreePageMap {
    /// Raw bit-map bytes.
    pub bitmap: Vec<u8>,
    /// Block size this FPM was built with.
    pub block_size: u32,
}

impl FreePageMap {
    /// Parse the FPM from the raw file bytes and superblock.
    ///
    /// # Errors
    /// Returns [`PdbError::StreamTooShort`] if the FPM block is out of range.
    pub fn parse(raw: &[u8], sb: &MsfSuperblock) -> Result<Self> {
        let fpm_block = sb.free_block_map_block;
        let start = sb.block_offset(fpm_block);
        let end = start + sb.block_size as usize;
        if end > raw.len() {
            return Err(PdbError::StreamTooShort);
        }
        Ok(Self {
            bitmap: raw[start..end].to_vec(),
            block_size: sb.block_size,
        })
    }

    /// Return `true` if block `n` is free.
    #[must_use]
    pub fn is_free(&self, n: u32) -> bool {
        let byte = (n / 8) as usize;
        let bit = n % 8;
        if byte >= self.bitmap.len() {
            return false;
        }
        (self.bitmap[byte] >> bit) & 1 == 1
    }

    /// Return `true` if block `n` is allocated (in use).
    #[must_use]
    pub fn is_allocated(&self, n: u32) -> bool {
        !self.is_free(n)
    }

    /// Count the number of free blocks.
    #[must_use]
    pub fn free_count(&self) -> u32 {
        self.bitmap
            .iter()
            .map(|&b| b.count_ones())
            .sum()
    }

    /// Count the number of allocated blocks.
    #[must_use]
    pub fn allocated_count(&self, total_blocks: u32) -> u32 {
        total_blocks.saturating_sub(self.free_count())
    }

    /// Return the list of all free block indices (up to `limit`).
    #[must_use]
    pub fn free_blocks(&self, total_blocks: u32, limit: usize) -> Vec<u32> {
        (0..total_blocks)
            .filter(|&n| self.is_free(n))
            .take(limit)
            .collect()
    }
}

// ─── Stream Directory ─────────────────────────────────────────────────────────

/// Parsed stream directory: maps stream index → stream bytes.
#[derive(Debug, Clone)]
pub struct StreamDirectory {
    /// Total number of streams.
    pub stream_count: u32,
    /// Per-stream byte sizes (`0xFFFF_FFFF` = nil stream).
    pub stream_sizes: Vec<u32>,
    /// Per-stream block lists.
    pub stream_blocks: Vec<Vec<u32>>,
}

impl StreamDirectory {
    /// Parse the stream directory from raw file bytes and the superblock.
    ///
    /// # Errors
    /// Returns a [`PdbError`] if the directory data is corrupt or out-of-range.
    pub fn parse(raw: &[u8], sb: &MsfSuperblock) -> Result<Self> {
        let dir_bytes = collect_blocks_from_map(raw, sb)?;
        Self::parse_from_bytes(&dir_bytes, sb.block_size)
    }

    /// Parse the stream directory from an already-assembled byte slice.
    fn parse_from_bytes(dir: &[u8], block_size: u32) -> Result<Self> {
        if dir.len() < 4 {
            return Err(PdbError::StreamTooShort);
        }
        let stream_count = read_u32_le(dir, 0)?;
        let mut off = 4usize;
        // Cap pre-allocations by what the directory bytes can actually hold —
        // `stream_count` is attacker-controlled.
        let max_entries = dir.len() / 4;
        let mut sizes = Vec::with_capacity((stream_count as usize).min(max_entries));
        for _ in 0..stream_count {
            sizes.push(read_u32_le(dir, off)?);
            off += 4;
        }
        let mut blocks: Vec<Vec<u32>> = Vec::with_capacity((stream_count as usize).min(max_entries));
        for &sz in &sizes {
            if sz == 0xFFFF_FFFF {
                blocks.push(Vec::new());
                continue;
            }
            let num_blocks = sz.div_ceil(block_size) as usize;
            let mut stream_blocks =
                Vec::with_capacity(num_blocks.min(dir.len().saturating_sub(off) / 4));
            for _ in 0..num_blocks {
                stream_blocks.push(read_u32_le(dir, off)?);
                off += 4;
            }
            blocks.push(stream_blocks);
        }
        Ok(Self {
            stream_count,
            stream_sizes: sizes,
            stream_blocks: blocks,
        })
    }

    /// Return the number of streams (including nil streams).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stream_count as usize
    }

    /// Return `true` if there are no streams.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stream_count == 0
    }

    /// Return `true` if stream `index` is a nil stream.
    #[must_use]
    pub fn is_nil_stream(&self, index: u32) -> bool {
        let sz = self.stream_sizes.get(index as usize).copied().unwrap_or(0);
        sz == 0xFFFF_FFFF
    }

    /// Return the size in bytes of stream `index`.
    #[must_use]
    pub fn stream_size(&self, index: u32) -> Option<u32> {
        let sz = *self.stream_sizes.get(index as usize)?;
        if sz == 0xFFFF_FFFF {
            None
        } else {
            Some(sz)
        }
    }

    /// Return the block list for stream `index`.
    #[must_use]
    pub fn stream_block_list(&self, index: u32) -> Option<&[u32]> {
        self.stream_blocks.get(index as usize).map(std::vec::Vec::as_slice)
    }
}

// ─── MSF Parser ───────────────────────────────────────────────────────────────

/// Complete low-level MSF parser.
///
/// Parses the full MSF container (superblock + FPM + stream directory) and
/// provides random access to any stream by index.
pub struct MsfParser {
    /// Parsed superblock.
    pub superblock: MsfSuperblock,
    /// Free page map.
    pub fpm: FreePageMap,
    /// Stream directory.
    pub directory: StreamDirectory,
    /// Full raw file data (owned copy for stream reassembly).
    raw: Vec<u8>,
}

impl MsfParser {
    /// Open a PDB file from a byte slice.
    ///
    /// # Errors
    /// Returns [`PdbError::BadMagic`] for non-PDB data,
    /// or [`PdbError::CorruptData`] / [`PdbError::StreamTooShort`] on parse failure.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let raw = data.to_vec();
        let superblock = MsfSuperblock::parse(&raw)?;
        superblock.validate_against(raw.len())?;
        let fpm = FreePageMap::parse(&raw, &superblock)?;
        let directory = StreamDirectory::parse(&raw, &superblock)?;
        Ok(Self {
            superblock,
            fpm,
            directory,
            raw,
        })
    }

    /// Open a PDB file from disk.
    ///
    /// # Errors
    /// Returns [`PdbError::Io`] on read failure, or other errors on parse failure.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read(path)?;
        Self::from_bytes(&raw)
    }

    /// Return the number of streams in this PDB.
    #[must_use]
    pub const fn stream_count(&self) -> u32 {
        self.directory.stream_count
    }

    /// Read stream `index` and return its bytes.
    ///
    /// # Errors
    /// Returns [`PdbError::StreamOutOfRange`] if `index >= stream_count`,
    /// or [`PdbError::StreamTooShort`] if the data is truncated.
    pub fn read_stream(&self, index: u32) -> Result<Vec<u8>> {
        if index >= self.directory.stream_count {
            return Err(PdbError::StreamOutOfRange(index));
        }
        if self.directory.is_nil_stream(index) {
            return Ok(Vec::new());
        }
        let sz = self.directory.stream_size(index).unwrap_or(0) as usize;
        let block_list = self.directory.stream_block_list(index).unwrap_or(&[]);
        let block_size = self.superblock.block_size as usize;
        // `sz` comes from the file; cap the pre-allocation by the bytes the
        // block list can actually deliver.
        let deliverable = block_list.len().saturating_mul(block_size).min(self.raw.len());
        let mut content = Vec::with_capacity(sz.min(deliverable));
        for &block_n in block_list {
            let start = (block_n as usize).saturating_mul(block_size);
            // An out-of-range block index used to `break`, silently truncating
            // the stream. Report it instead: a short stream is indistinguishable
            // from a legitimately short one and fails much further downstream.
            if start >= self.raw.len() {
                return Err(PdbError::CorruptData);
            }
            let end = (start + block_size).min(self.raw.len());
            content.extend_from_slice(&self.raw[start..end]);
        }
        content.truncate(sz);
        Ok(content)
    }

    /// Read all streams and return a map of index → bytes.
    ///
    /// # Errors
    /// Returns a [`PdbError`] if any stream cannot be read.
    pub fn read_all_streams(&self) -> Result<HashMap<u32, Vec<u8>>> {
        let mut map = HashMap::new();
        for i in 0..self.directory.stream_count {
            let data = self.read_stream(i)?;
            map.insert(i, data);
        }
        Ok(map)
    }

    /// Return stream sizes as a sorted list of `(index, size_bytes)`.
    #[must_use]
    pub fn stream_sizes(&self) -> Vec<(u32, u32)> {
        (0..self.directory.stream_count)
            .filter_map(|i| {
                self.directory.stream_size(i).map(|sz| (i, sz))
            })
            .collect()
    }

    /// Return the largest stream index and size.
    #[must_use]
    pub fn largest_stream(&self) -> Option<(u32, u32)> {
        self.stream_sizes()
            .into_iter()
            .max_by_key(|(_, sz)| *sz)
    }

    /// Return summary statistics for this PDB.
    #[must_use]
    pub fn summary(&self) -> MsfSummary {
        MsfSummary {
            block_size: self.superblock.block_size,
            total_blocks: self.superblock.num_blocks,
            stream_count: self.directory.stream_count,
            free_blocks: self.fpm.free_count(),
            allocated_blocks: self.fpm.allocated_count(self.superblock.num_blocks),
            file_size: self.raw.len(),
        }
    }

    /// Check whether the file has valid MSF structure (non-nil streams for
    /// well-known indices 1–4).
    #[must_use]
    pub fn sanity_check(&self) -> bool {
        !self.directory.is_nil_stream(1) // PDB Info
            && self.directory.stream_count >= 5
    }
}

/// Summary statistics for an MSF file.
#[derive(Debug, Clone)]
pub struct MsfSummary {
    /// Block size in bytes.
    pub block_size: u32,
    /// Total blocks in the file.
    pub total_blocks: u32,
    /// Number of streams (including nil).
    pub stream_count: u32,
    /// Number of free blocks.
    pub free_blocks: u32,
    /// Number of allocated blocks.
    pub allocated_blocks: u32,
    /// File size in bytes.
    pub file_size: usize,
}

impl std::fmt::Display for MsfSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MSF: block_size={} total_blocks={} streams={} free={} alloc={} file={}B",
            self.block_size,
            self.total_blocks,
            self.stream_count,
            self.free_blocks,
            self.allocated_blocks,
            self.file_size,
        )
    }
}

// ─── Named Stream Locator ─────────────────────────────────────────────────────

/// Standard PDB stream indices (fixed by specification).
pub mod stream_index {
    /// Old MSF directory / invalid.
    pub const OLD_DIRECTORY: u32 = 0;
    /// PDB Info stream (version, GUID, age, named stream map).
    pub const PDB_INFO: u32 = 1;
    /// TPI (Type Information) stream.
    pub const TPI: u32 = 2;
    /// DBI (Debug Information) stream.
    pub const DBI: u32 = 3;
    /// IPI (ID Information) stream.
    pub const IPI: u32 = 4;
}

/// Parse the named-stream map from PDB Info stream bytes.
///
/// The named-stream map is stored after the fixed 28-byte header in stream 1:
/// - `u32` string buffer size
/// - `[u8; string_buffer_size]` NUL-separated names
/// - `u32` capacity
/// - `u32` `present_word_count`, `[u32; present_word_count]` (bit-set)
/// - `u32` `deleted_word_count`, `[u32; deleted_word_count]`
/// - `[u32 key, u32 value; num_entries]` pairs
///
/// Returns a map of stream name → stream index.
///
/// # Errors
/// Returns an empty map (never panics) — callers must treat parse failures as
/// "no named streams available".
#[must_use]
pub fn parse_named_stream_map(pdb_info_stream: &[u8]) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    if pdb_info_stream.len() < 32 {
        return out;
    }
    let mut off = 28usize; // skip version(4)+signature(4)+age(4)+guid(16)

    let strbuf_size = match read_u32_le_opt(pdb_info_stream, off) {
        Some(v) => v as usize,
        None => return out,
    };
    off += 4;
    if off + strbuf_size > pdb_info_stream.len() {
        return out;
    }
    let strbuf = &pdb_info_stream[off..off + strbuf_size];
    off += strbuf_size;

    // capacity
    off += 4;
    let present_words = match read_u32_le_opt(pdb_info_stream, off) {
        Some(v) => v as usize,
        None => return out,
    };
    off += 4;

    // Count set bits (= number of key/value pairs); no need to materialise
    // the bitset, and `present_words` is attacker-controlled so we must not
    // pre-allocate from it.
    let mut num_entries = 0usize;
    for _ in 0..present_words {
        let Some(word) = read_u32_le_opt(pdb_info_stream, off) else { return out };
        off += 4;
        num_entries += word.count_ones() as usize;
    }

    // deleted word count
    let deleted_words = match read_u32_le_opt(pdb_info_stream, off) {
        Some(v) => v as usize,
        None => return out,
    };
    off += 4;
    off = off.saturating_add(deleted_words.saturating_mul(4));

    for _ in 0..num_entries {
        if off + 8 > pdb_info_stream.len() {
            break;
        }
        let key_off = match read_u32_le_opt(pdb_info_stream, off) {
            Some(v) => v as usize,
            None => break,
        };
        let Some(stream_idx) = read_u32_le_opt(pdb_info_stream, off + 4) else { break };
        off += 8;
        if key_off < strbuf.len() {
            let end = strbuf[key_off..]
                .iter()
                .position(|&b| b == 0)
                .map_or(strbuf.len(), |p| key_off + p);
            let name = String::from_utf8_lossy(&strbuf[key_off..end]).into_owned();
            if !name.is_empty() {
                out.insert(name, stream_idx);
            }
        }
    }
    out
}

// ─── Block collector ─────────────────────────────────────────────────────────

/// Collect the stream directory bytes by following the block-map from the superblock.
fn collect_blocks_from_map(raw: &[u8], sb: &MsfSuperblock) -> Result<Vec<u8>> {
    let block_size = sb.block_size as usize;
    let blocks_needed = sb.blocks_needed(sb.num_dir_bytes) as usize;

    let bm_off = (sb.block_map_addr as usize).saturating_mul(block_size);

    // `num_dir_bytes` is attacker-controlled; the directory can never exceed
    // the file size, so cap the pre-allocation there.
    let mut dir_data: Vec<u8> =
        Vec::with_capacity((sb.num_dir_bytes as usize).min(raw.len()));
    for i in 0..blocks_needed {
        let page_n = read_u32_le(raw, bm_off + i * 4)? as usize;
        let start = page_n.saturating_mul(block_size);
        let end = start.saturating_add(block_size).min(raw.len());
        if start >= raw.len() {
            break;
        }
        dir_data.extend_from_slice(&raw[start..end]);
    }
    dir_data.truncate(sb.num_dir_bytes as usize);
    Ok(dir_data)
}

// ─── Byte helpers ─────────────────────────────────────────────────────────────

pub(crate) fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(PdbError::StreamTooShort)
}

/// Read a little-endian `u16` from `data` at byte offset `off`.
///
/// Public so external consumers can decode PDB substreams using the same
/// bounds-checked primitives as the in-crate parsers.
/// # Errors
///
/// Returns an error if parsing fails.
pub fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(PdbError::StreamTooShort)
}

fn read_u32_le_opt(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Read a null-terminated C string at `off`; return `(string, next_offset)`.
///
/// Public so external consumers can walk symbol/type substreams without
/// re-implementing the lossy UTF-8 decoding rules used by the PDB parser.
#[must_use]
pub fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    let start = off;
    let mut pos = off;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..pos]).into_owned();
    let next = if pos < data.len() { pos + 1 } else { pos };
    (s, next)
}

// ─── PDB Info stream ──────────────────────────────────────────────────────────

/// Structured contents of the PDB Info stream (stream index 1).
#[derive(Debug, Clone)]
pub struct PdbInfoStream {
    /// PDB format version.
    pub version: u32,
    /// Timestamp / signature written at link time.
    pub signature: u32,
    /// Age counter (used for symbol-server matching).
    pub age: u32,
    /// 128-bit GUID.
    pub guid: [u8; 16],
    /// Named stream map extracted from the variable-length portion.
    pub named_streams: HashMap<String, u32>,
}

impl PdbInfoStream {
    /// Parse from raw stream bytes.
    ///
    /// # Errors
    /// Returns [`PdbError::StreamTooShort`] if the stream is too short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            return Err(PdbError::StreamTooShort);
        }
        let version = read_u32_le(data, 0)?;
        let signature = read_u32_le(data, 4)?;
        let age = read_u32_le(data, 8)?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[12..28]);
        let named_streams = parse_named_stream_map(data);
        Ok(Self {
            version,
            signature,
            age,
            guid,
            named_streams,
        })
    }

    /// Format the GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    #[must_use]
    pub fn guid_string(&self) -> String {
        let d = &self.guid;
        format!(
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
             {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            d[3], d[2], d[1], d[0],
            d[5], d[4],
            d[7], d[6],
            d[8], d[9],
            d[10], d[11], d[12], d[13], d[14], d[15],
        )
    }
}

// ─── Stream iterator ──────────────────────────────────────────────────────────

/// Iterator over all non-nil streams in an [`MsfParser`].
pub struct StreamIter<'a> {
    parser: &'a MsfParser,
    current: u32,
}

impl<'a> StreamIter<'a> {
    /// Create a new iterator over the parser's streams.
    #[must_use]
    pub const fn new(parser: &'a MsfParser) -> Self {
        Self { parser, current: 0 }
    }
}

impl Iterator for StreamIter<'_> {
    type Item = (u32, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current >= self.parser.stream_count() {
                return None;
            }
            let idx = self.current;
            self.current += 1;
            if self.parser.directory.is_nil_stream(idx) {
                continue;
            }
            if let Ok(data) = self.parser.read_stream(idx) {
                return Some((idx, data));
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_superblock_bytes(block_size: u32, num_blocks: u32, dir_bytes: u32, bm_addr: u32) -> Vec<u8> {
        let mut v = vec![0u8; 56];
        v[0..32].copy_from_slice(MSF_MAGIC_V7);
        v[32..36].copy_from_slice(&block_size.to_le_bytes());
        v[36..40].copy_from_slice(&1u32.to_le_bytes()); // fpm block = 1
        v[40..44].copy_from_slice(&num_blocks.to_le_bytes());
        v[44..48].copy_from_slice(&dir_bytes.to_le_bytes());
        // v[48..52] reserved
        v[52..56].copy_from_slice(&bm_addr.to_le_bytes());
        v
    }

    #[test]
    fn test_superblock_parse_valid() {
        let raw = make_superblock_bytes(512, 100, 64, 2);
        let sb = MsfSuperblock::parse(&raw).unwrap();
        assert_eq!(sb.block_size, 512);
        assert_eq!(sb.num_blocks, 100);
        assert_eq!(sb.num_dir_bytes, 64);
        assert_eq!(sb.block_map_addr, 2);
    }

    #[test]
    fn test_superblock_bad_magic() {
        let raw = vec![0xFFu8; 56];
        assert!(matches!(MsfSuperblock::parse(&raw), Err(PdbError::BadMagic)));
    }

    #[test]
    fn test_superblock_too_short() {
        let raw = vec![0u8; 10];
        assert!(matches!(MsfSuperblock::parse(&raw), Err(PdbError::BadMagic)));
    }

    #[test]
    fn test_superblock_blocks_needed() {
        let raw = make_superblock_bytes(4096, 1, 1, 2);
        let sb = MsfSuperblock::parse(&raw).unwrap();
        assert_eq!(sb.blocks_needed(4096), 1);
        assert_eq!(sb.blocks_needed(4097), 2);
        assert_eq!(sb.blocks_needed(0), 0);
    }

    #[test]
    fn test_superblock_block_offset() {
        let raw = make_superblock_bytes(512, 10, 64, 2);
        let sb = MsfSuperblock::parse(&raw).unwrap();
        assert_eq!(sb.block_offset(0), 0);
        assert_eq!(sb.block_offset(1), 512);
        assert_eq!(sb.block_offset(3), 1536);
    }

    #[test]
    fn test_superblock_valid_block_sizes() {
        let raw = make_superblock_bytes(4096, 1, 4, 1);
        let sb = MsfSuperblock::parse(&raw).unwrap();
        assert!(sb.is_valid_block_size());
        // A non-power-of-two block size is now rejected at parse time rather
        // than parsed into a superblock nobody ever validates.
        let raw2 = make_superblock_bytes(300, 1, 4, 1);
        assert!(matches!(
            MsfSuperblock::parse(&raw2),
            Err(PdbError::CorruptData)
        ));
    }

    #[test]
    fn superblock_rejects_bad_block_size_and_fpm() {
        // Regression: `is_valid_block_size()` existed but was never called, so
        // block_size = 3 produced a coherent-looking, entirely wrong parse.
        for bad in [0u32, 3, 300, 0x4000_0000, 256, 16384] {
            let raw = make_superblock_bytes(bad, 1, 4, 1);
            assert!(
                matches!(MsfSuperblock::parse(&raw), Err(PdbError::CorruptData)),
                "block_size {bad} should be rejected"
            );
        }
        for good in [512u32, 1024, 2048, 4096, 8192] {
            let raw = make_superblock_bytes(good, 1, 4, 1);
            assert!(
                MsfSuperblock::parse(&raw).is_ok(),
                "block_size {good} should be accepted"
            );
        }
        // free_block_map_block must be 1 or 2.
        let mut raw = make_superblock_bytes(4096, 1, 4, 1);
        raw[36..40].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            MsfSuperblock::parse(&raw),
            Err(PdbError::CorruptData)
        ));
    }

    #[test]
    fn superblock_validate_against_rejects_oversized_num_blocks() {
        let raw = make_superblock_bytes(512, 100_000, 4, 1);
        let sb = MsfSuperblock::parse(&raw).unwrap();
        // 100000 blocks * 512 bytes cannot fit in a 56-byte buffer.
        assert!(matches!(
            sb.validate_against(raw.len()),
            Err(PdbError::CorruptData)
        ));
    }

    #[test]
    fn test_fpm_is_free() {
        // bitmap byte 0x01 means bit 0 is set (free), rest allocated.
        let bitmap = vec![0x01u8, 0xFF, 0x00]; // blocks 0,8..15 free; 2..7 allocated
        let fpm = FreePageMap { bitmap, block_size: 512 };
        assert!(fpm.is_free(0));
        assert!(!fpm.is_free(1));
        assert!(fpm.is_free(8));
        assert!(!fpm.is_allocated(0));
        assert!(fpm.is_allocated(1));
    }

    #[test]
    fn test_fpm_free_count() {
        let fpm = FreePageMap { bitmap: vec![0xFF], block_size: 512 };
        assert_eq!(fpm.free_count(), 8);
        let fpm2 = FreePageMap { bitmap: vec![0x00], block_size: 512 };
        assert_eq!(fpm2.free_count(), 0);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x34u8, 0x12];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\x00world\x00";
        let (s, next) = read_cstring(data, 0);
        assert_eq!(s, "hello");
        assert_eq!(next, 6);
    }

    #[test]
    fn test_pdb_info_stream_parse() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&20_000_404u32.to_le_bytes());
        data[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        for (i, b) in data[12..28].iter_mut().enumerate() {
            *b = u8::try_from(i + 1).unwrap();
        }
        let info = PdbInfoStream::parse(&data).unwrap();
        assert_eq!(info.version, 20_000_404);
        assert_eq!(info.age, 3);
        assert_eq!(info.guid[0], 1);
        assert!(info.guid_string().starts_with('{'));
    }

    #[test]
    fn test_pdb_info_stream_too_short() {
        let data = vec![0u8; 10];
        assert!(PdbInfoStream::parse(&data).is_err());
    }

    #[test]
    fn test_stream_directory_empty() {
        // 4 bytes: stream_count = 0
        let dir = 0u32.to_le_bytes().to_vec();
        let sd = StreamDirectory::parse_from_bytes(&dir, 512).unwrap();
        assert_eq!(sd.stream_count, 0);
        assert!(sd.is_empty());
    }

    #[test]
    fn test_stream_indices_constants() {
        assert_eq!(stream_index::PDB_INFO, 1);
        assert_eq!(stream_index::TPI, 2);
        assert_eq!(stream_index::DBI, 3);
        assert_eq!(stream_index::IPI, 4);
    }

    #[test]
    fn test_parse_named_stream_map_empty_on_short_input() {
        let map = parse_named_stream_map(&[0u8; 8]);
        assert!(map.is_empty());
    }
}
