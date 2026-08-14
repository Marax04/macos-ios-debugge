//! `ole_parser` — OLE2 compound file binary (CFB) deep parser.
//!
//! Implements full MS-CFB parsing: header validation, DIFAT chain traversal,
//! FAT / mini-FAT reconstruction, directory entry tree, and stream extraction
//! by directory path.  All code targets `std` only — no external dependencies.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// OLE2 magic bytes at offset 0.
pub const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Sector IDs with special meanings per MS-CFB §2.2.
pub const MAXREGSECT: u32 = 0xFFFF_FFFA;
pub const RESERVED_SECT: u32 = 0xFFFF_FFFB;
pub const DIFSECT: u32 = 0xFFFF_FFFC;
pub const FATSECT: u32 = 0xFFFF_FFFD;
pub const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
pub const FREESECT: u32 = 0xFFFF_FFFF;

/// Number of DIFAT entries embedded in the header (MS-CFB §2.7).
const HEADER_DIFAT_LEN: usize = 109;
/// CFB header size in bytes.
const HEADER_SIZE: usize = 512;
/// Mini-sector size is always 64 bytes.
const MINI_SECTOR_SIZE: usize = 64;
/// Default mini-stream cutoff: streams smaller than this use the mini-stream.
const DEFAULT_MINI_CUTOFF: u32 = 4096;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by [`OleParser`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OleParserError {
    /// Magic bytes do not match `D0 CF 11 E0 A1 B1 1A E1`.
    InvalidMagic,
    /// Data is too short to contain a valid structure.
    Truncated,
    /// Version field is not 3 or 4.
    UnsupportedVersion(u16),
    /// A referenced sector ID is out of bounds.
    InvalidSector(u32),
    /// A directory entry is malformed.
    InvalidDirEntry,
    /// Generic parse failure with a message.
    ParseError(String),
    /// The requested stream path was not found.
    StreamNotFound(String),
}

impl fmt::Display for OleParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid OLE2 magic"),
            Self::Truncated => write!(f, "data truncated"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            Self::InvalidSector(id) => write!(f, "invalid sector id {id:#010x}"),
            Self::InvalidDirEntry => write!(f, "invalid directory entry"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::StreamNotFound(p) => write!(f, "stream not found: {p}"),
        }
    }
}

// ── OleHeader ─────────────────────────────────────────────────────────────────

/// Parsed OLE2 compound file header (512 bytes).
#[derive(Debug, Clone)]
pub struct OleHeader {
    /// Minor version field.
    pub minor_version: u16,
    /// Major version: 3 (512-byte sectors) or 4 (4096-byte sectors).
    pub major_version: u16,
    /// Sector size exponent: 9 → 512 bytes, 12 → 4096 bytes.
    pub sector_size_exp: u16,
    /// Mini-sector size exponent (always 6 → 64 bytes).
    pub mini_sector_size_exp: u16,
    /// Number of FAT sectors.
    pub fat_sector_count: u32,
    /// Starting sector of the directory chain.
    pub first_dir_sector: u32,
    /// Minimum stream size for the regular FAT (default 4096).
    pub mini_stream_cutoff: u32,
    /// Starting sector of the mini-FAT chain.
    pub first_mini_fat: u32,
    /// Number of mini-FAT sectors.
    pub mini_fat_count: u32,
    /// First sector of the first chained DIFAT sector (if any).
    pub first_difat_sector: u32,
    /// Number of chained DIFAT sectors beyond the header.
    pub difat_sector_count: u32,
    /// DIFAT sector IDs embedded in the header.
    pub difat: Vec<u32>,
}

impl OleHeader {
    /// Parse a 512-byte header from the beginning of `data`.
    ///
    /// # Errors
    /// Returns [`OleParserError::Truncated`] or [`OleParserError::InvalidMagic`]
    /// on format violations.
    pub fn parse(data: &[u8]) -> Result<Self, OleParserError> {
        if data.len() < HEADER_SIZE {
            return Err(OleParserError::Truncated);
        }
        if data[..8] != OLE_MAGIC {
            return Err(OleParserError::InvalidMagic);
        }
        let minor_version = u16_le(data, 24);
        let major_version = u16_le(data, 26);
        if major_version != 3 && major_version != 4 {
            return Err(OleParserError::UnsupportedVersion(major_version));
        }
        let sector_size_exp = u16_le(data, 30);
        let mini_sector_size_exp = u16_le(data, 32);
        let fat_sector_count = u32_le(data, 44);
        let first_dir_sector = u32_le(data, 48);
        let mini_stream_cutoff = u32_le(data, 56);
        let first_mini_fat = u32_le(data, 60);
        let mini_fat_count = u32_le(data, 64);
        let first_difat_sector = u32_le(data, 68);
        let difat_sector_count = u32_le(data, 72);
        let mut difat = Vec::with_capacity(HEADER_DIFAT_LEN);
        for i in 0..HEADER_DIFAT_LEN {
            difat.push(u32_le(data, 76 + i * 4));
        }
        Ok(Self {
            minor_version,
            major_version,
            sector_size_exp,
            mini_sector_size_exp,
            fat_sector_count,
            first_dir_sector,
            mini_stream_cutoff,
            first_mini_fat,
            mini_fat_count,
            first_difat_sector,
            difat_sector_count,
            difat,
        })
    }

    /// Sector size in bytes.
    #[must_use]
    pub const fn sector_size(&self) -> usize {
        1usize << self.sector_size_exp
    }
}

impl fmt::Display for OleHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OLE2 v{}.{} ss={} fat_sects={} dir_sect={:#010x}",
            self.major_version,
            self.minor_version,
            self.sector_size(),
            self.fat_sector_count,
            self.first_dir_sector,
        )
    }
}

// ── FatSector ─────────────────────────────────────────────────────────────────

/// A single FAT sector: a flat array of 32-bit next-sector pointers.
#[derive(Debug, Clone)]
pub struct FatSector {
    /// Sector ID of this FAT sector in the file.
    pub sector_id: u32,
    /// The FAT entries stored in this sector.
    pub entries: Vec<u32>,
}

impl FatSector {
    /// Parse FAT entries from `sector_data` (length = sector size).
    #[must_use]
    pub fn parse(sector_id: u32, sector_data: &[u8]) -> Self {
        let entries = sector_data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Self { sector_id, entries }
    }
}

impl fmt::Display for FatSector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FatSector #{} entries={}",
            self.sector_id,
            self.entries.len()
        )
    }
}

// ── DirEntryType ─────────────────────────────────────────────────────────────

/// Type field of an OLE2 directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirEntryType {
    Empty,
    Storage,
    Stream,
    Root,
    Unknown(u8),
}

impl DirEntryType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Empty,
            1 => Self::Storage,
            2 => Self::Stream,
            5 => Self::Root,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for DirEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "empty",
            Self::Storage => "storage",
            Self::Stream => "stream",
            Self::Root => "root",
            Self::Unknown(b) => return write!(f, "unknown({b})"),
        };
        write!(f, "{s}")
    }
}

// ── DirEntry ──────────────────────────────────────────────────────────────────

/// A parsed 128-byte OLE2 directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name (decoded from UTF-16LE).
    pub name: String,
    /// Object type.
    pub entry_type: DirEntryType,
    /// Red-black tree color (0=red, 1=black).
    pub color: u8,
    /// Left sibling SID.
    pub left_sibling: u32,
    /// Right sibling SID.
    pub right_sibling: u32,
    /// Child SID (for Storage and Root).
    pub child: u32,
    /// CLSID (16 bytes).
    pub clsid: [u8; 16],
    /// State bits.
    pub state_bits: u32,
    /// Creation time (Windows FILETIME).
    pub created: u64,
    /// Last modification time (Windows FILETIME).
    pub modified: u64,
    /// Starting sector for the stream / mini-stream data.
    pub start_sector: u32,
    /// Stream size in bytes.
    pub size: u64,
}

impl DirEntry {
    /// Parse a 128-byte directory entry from `slice`.
    ///
    /// # Errors
    /// Returns [`OleParserError::InvalidDirEntry`] if `slice.len() < 128`.
    pub fn parse(slice: &[u8]) -> Result<Self, OleParserError> {
        if slice.len() < 128 {
            return Err(OleParserError::InvalidDirEntry);
        }
        let name_len = u16_le(slice, 64) as usize;
        let raw_len = name_len.min(64);
        let units: Vec<u16> = slice[..raw_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string();
        let entry_type = DirEntryType::from_byte(slice[66]);
        let color = slice[67];
        let left_sibling = u32_le(slice, 68);
        let right_sibling = u32_le(slice, 72);
        let child = u32_le(slice, 76);
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&slice[80..96]);
        let state_bits = u32_le(slice, 96);
        let created = u64_le(slice, 100);
        let modified = u64_le(slice, 108);
        let start_sector = u32_le(slice, 116);
        let size_lo = u64::from(u32_le(slice, 120));
        let size_hi = u64::from(u32_le(slice, 124));
        let size = (size_hi << 32) | size_lo;
        Ok(Self {
            name,
            entry_type,
            color,
            left_sibling,
            right_sibling,
            child,
            clsid,
            state_bits,
            created,
            modified,
            start_sector,
            size,
        })
    }

    /// Returns `true` if this entry is the root storage (type 5).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.entry_type == DirEntryType::Root
    }

    /// Returns `true` if this entry is a storage (type 1).
    #[must_use]
    pub fn is_storage(&self) -> bool {
        self.entry_type == DirEntryType::Storage
    }

    /// Returns `true` if this entry is a stream (type 2).
    #[must_use]
    pub fn is_stream(&self) -> bool {
        self.entry_type == DirEntryType::Stream
    }

    /// Returns `true` if this entry is empty (type 0).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entry_type == DirEntryType::Empty
    }

    /// Format the CLSID as a GUID string `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    #[must_use]
    pub fn clsid_string(&self) -> String {
        let c = &self.clsid;
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
            u16::from_le_bytes([c[4], c[5]]),
            u16::from_le_bytes([c[6], c[7]]),
            c[8],
            c[9],
            c[10],
            c[11],
            c[12],
            c[13],
            c[14],
            c[15],
        )
    }
}

impl fmt::Display for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' ({}) sector={:#010x} size={}",
            self.name, self.entry_type, self.start_sector, self.size
        )
    }
}

// ── OleParser ────────────────────────────────────────────────────────────────

/// Full OLE2 compound file parser.
///
/// Parses the header, builds the FAT and mini-FAT, loads all directory entries,
/// and provides stream extraction by path.
pub struct OleParser {
    data: Vec<u8>,
    /// Sector size in bytes (512 or 4096).
    pub sector_size: usize,
    /// Mini-sector size in bytes (always 64).
    pub mini_sector_size: usize,
    /// Mini-stream cutoff size in bytes.
    pub mini_cutoff: u32,
    /// Full FAT: index = sector id → next sector id.
    pub fat: Vec<u32>,
    /// Full mini-FAT: index = mini-sector id → next mini-sector id.
    pub mini_fat: Vec<u32>,
    /// Directory entries, indexed by SID.
    pub dir_entries: Vec<DirEntry>,
    /// Parsed file header.
    pub header: OleHeader,
}

impl OleParser {
    /// Parse a compound file from `data`.
    ///
    /// # Errors
    /// Returns [`OleParserError`] on any format violation.
    pub fn parse(data: Vec<u8>) -> Result<Self, OleParserError> {
        let header = OleHeader::parse(&data)?;
        let ss = header.sector_size();
        let mini_cutoff = if header.mini_stream_cutoff == 0 {
            DEFAULT_MINI_CUTOFF
        } else {
            header.mini_stream_cutoff
        };

        // Build FAT from DIFAT entries.
        let fat = Self::build_fat(&data, &header, ss)?;

        // Build mini-FAT.
        let mini_fat = Self::build_mini_fat(&data, &header, &fat, ss)?;

        // Parse directory entries.
        let dir_entries = Self::parse_dir_entries(&data, &header, &fat, ss)?;

        Ok(Self {
            data,
            sector_size: ss,
            mini_sector_size: MINI_SECTOR_SIZE,
            mini_cutoff,
            fat,
            mini_fat,
            dir_entries,
            header,
        })
    }

    // ── FAT construction ────────────────────────────────────────────────────

    fn build_fat(data: &[u8], hdr: &OleHeader, ss: usize) -> Result<Vec<u32>, OleParserError> {
        let entries_per_sect = ss / 4;
        let max_fat_sects = hdr.fat_sector_count as usize;
        let mut fat: Vec<u32> = Vec::with_capacity(max_fat_sects * entries_per_sect);

        // Collect all FAT sector IDs from DIFAT (header + chained DIFAT sectors).
        let fat_sect_ids = Self::collect_difat_entries(data, hdr, ss)?;

        for &sid in fat_sect_ids.iter().take(max_fat_sects) {
            if sid == FREESECT || sid == FATSECT || sid == DIFSECT {
                continue;
            }
            let sect = Self::sector_slice_raw(data, sid, ss)?;
            for chunk in sect.chunks_exact(4) {
                fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
        Ok(fat)
    }

    fn collect_difat_entries(
        data: &[u8],
        hdr: &OleHeader,
        ss: usize,
    ) -> Result<Vec<u32>, OleParserError> {
        let mut ids: Vec<u32> = hdr
            .difat
            .iter()
            .copied()
            .filter(|&v| v != FREESECT && v != FATSECT && v != DIFSECT)
            .collect();

        // Follow chained DIFAT sectors.
        if hdr.difat_sector_count > 0
            && hdr.first_difat_sector != FREESECT
            && hdr.first_difat_sector != ENDOFCHAIN
        {
            let entries_per_difat = (ss / 4).saturating_sub(1);
            let mut next = hdr.first_difat_sector;
            let mut guard = 0u32;
            while next != FREESECT && next != ENDOFCHAIN && guard < hdr.difat_sector_count + 10 {
                let sect = Self::sector_slice_raw(data, next, ss)?;
                for i in 0..entries_per_difat {
                    let v = u32::from_le_bytes([
                        sect[i * 4],
                        sect[i * 4 + 1],
                        sect[i * 4 + 2],
                        sect[i * 4 + 3],
                    ]);
                    if v != FREESECT && v != FATSECT && v != DIFSECT {
                        ids.push(v);
                    }
                }
                // Last u32 = pointer to next DIFAT sector.
                let tail_off = entries_per_difat * 4;
                next = u32::from_le_bytes([
                    sect[tail_off],
                    sect[tail_off + 1],
                    sect[tail_off + 2],
                    sect[tail_off + 3],
                ]);
                guard += 1;
            }
        }
        Ok(ids)
    }

    fn build_mini_fat(
        data: &[u8],
        hdr: &OleHeader,
        fat: &[u32],
        ss: usize,
    ) -> Result<Vec<u32>, OleParserError> {
        if hdr.mini_fat_count == 0
            || hdr.first_mini_fat == FREESECT
            || hdr.first_mini_fat == ENDOFCHAIN
        {
            return Ok(vec![]);
        }
        let chain = Self::follow_chain(fat, hdr.first_mini_fat);
        let mut mini_fat = Vec::with_capacity(chain.len() * (ss / 4));
        for sid in chain {
            let sect = match Self::sector_slice_raw(data, sid, ss) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for chunk in sect.chunks_exact(4) {
                mini_fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
        Ok(mini_fat)
    }

    fn parse_dir_entries(
        data: &[u8],
        hdr: &OleHeader,
        fat: &[u32],
        ss: usize,
    ) -> Result<Vec<DirEntry>, OleParserError> {
        let chain = Self::follow_chain(fat, hdr.first_dir_sector);
        let mut entries = Vec::with_capacity(chain.len() * (ss / 128));
        for sid in chain {
            let sect = match Self::sector_slice_raw(data, sid, ss) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let per_sector = ss / 128;
            for i in 0..per_sector {
                let off = i * 128;
                if off + 128 > sect.len() {
                    break;
                }
                entries.push(DirEntry::parse(&sect[off..off + 128])?);
            }
        }
        Ok(entries)
    }

    // ── Stream extraction ───────────────────────────────────────────────────

    /// Extract the raw bytes of a stream by its directory entry `SID`.
    ///
    /// # Errors
    /// Returns [`OleParserError`] if the sector chain is broken or data is truncated.
    pub fn read_stream_by_sid(&self, sid: u32) -> Result<Vec<u8>, OleParserError> {
        let entry = self
            .dir_entries
            .get(sid as usize)
            .ok_or(OleParserError::InvalidSector(sid))?;
        if entry.size == 0 {
            return Ok(vec![]);
        }
        let size = usize::try_from(entry.size)
            .map_err(|_| OleParserError::ParseError("stream size exceeds address space".into()))?;
        if !entry.is_root() && entry.size < u64::from(self.mini_cutoff) {
            self.read_mini_stream(entry.start_sector, size)
        } else {
            self.read_regular_stream(entry.start_sector, size)
        }
    }

    /// Extract a stream by path, e.g. `"VBA/dir"`.
    ///
    /// The root storage is the implicit root; the first component of the path
    /// is matched against direct children of the root.
    ///
    /// # Errors
    /// Returns [`OleParserError::StreamNotFound`] if the path cannot be resolved.
    pub fn read_stream_by_path(&self, path: &str) -> Result<Vec<u8>, OleParserError> {
        let entry = self
            .find_entry_by_path(path)
            .ok_or_else(|| OleParserError::StreamNotFound(path.to_string()))?;
        let sid = self
            .dir_entries
            .iter()
            .position(|e| std::ptr::eq(e, entry))
            .ok_or_else(|| OleParserError::StreamNotFound(path.to_string()))? as u32;
        self.read_stream_by_sid(sid)
    }

    /// Find a directory entry by path.
    ///
    /// Path components are separated by `/`; comparison is case-insensitive.
    #[must_use]
    pub fn find_entry_by_path(&self, path: &str) -> Option<&DirEntry> {
        let path = path.trim_start_matches('/');
        let path = if path.to_ascii_lowercase().starts_with("root entry/") {
            &path["Root Entry/".len()..]
        } else {
            path
        };
        if path.is_empty() {
            return self.dir_entries.first();
        }
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let root = self.dir_entries.first()?;
        self.find_in_storage(root.child, &parts, 0)
    }

    fn find_in_storage<'a>(
        &'a self,
        start_sid: u32,
        parts: &[&str],
        depth: usize,
    ) -> Option<&'a DirEntry> {
        if depth >= parts.len() || start_sid == FREESECT || start_sid == ENDOFCHAIN {
            return None;
        }
        let target = parts[depth];
        let mut queue: VecDeque<u32> = VecDeque::new();
        queue.push_back(start_sid);
        let mut visited: HashSet<u32> = HashSet::new();
        while let Some(sid) = queue.pop_front() {
            if sid == FREESECT || sid == ENDOFCHAIN || !visited.insert(sid) {
                continue;
            }
            let entry = self.dir_entries.get(sid as usize)?;
            if entry.name.eq_ignore_ascii_case(target) {
                if depth + 1 == parts.len() {
                    return Some(entry);
                }
                return self.find_in_storage(entry.child, parts, depth + 1);
            }
            if entry.left_sibling != FREESECT && entry.left_sibling != ENDOFCHAIN {
                queue.push_back(entry.left_sibling);
            }
            if entry.right_sibling != FREESECT && entry.right_sibling != ENDOFCHAIN {
                queue.push_back(entry.right_sibling);
            }
        }
        None
    }

    /// Return all stream entries as `(path, SID)` pairs.
    #[must_use]
    pub fn list_streams(&self) -> Vec<(String, u32)> {
        let mut result = Vec::new();
        if let Some(root) = self.dir_entries.first() {
            self.enumerate_storage(root.child, "", &mut result);
        }
        result
    }

    fn enumerate_storage(&self, start_sid: u32, parent: &str, out: &mut Vec<(String, u32)>) {
        if start_sid == FREESECT || start_sid == ENDOFCHAIN {
            return;
        }
        let mut stack = vec![start_sid];
        let mut visited: HashSet<u32> = HashSet::new();
        while let Some(sid) = stack.pop() {
            if sid == FREESECT || sid == ENDOFCHAIN || !visited.insert(sid) {
                continue;
            }
            if let Some(entry) = self.dir_entries.get(sid as usize) {
                let path = if parent.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{parent}/{}", entry.name)
                };
                if entry.is_stream() {
                    out.push((path.clone(), sid));
                }
                if (entry.is_storage() || entry.is_root())
                    && entry.child != FREESECT
                    && entry.child != ENDOFCHAIN
                {
                    self.enumerate_storage(entry.child, &path, out);
                }
                if entry.left_sibling != FREESECT && entry.left_sibling != ENDOFCHAIN {
                    stack.push(entry.left_sibling);
                }
                if entry.right_sibling != FREESECT && entry.right_sibling != ENDOFCHAIN {
                    stack.push(entry.right_sibling);
                }
            }
        }
    }

    // ── Low-level I/O ────────────────────────────────────────────────────────

    fn sector_slice_raw(data: &[u8], sid: u32, ss: usize) -> Result<&[u8], OleParserError> {
        if sid >= MAXREGSECT {
            return Err(OleParserError::InvalidSector(sid));
        }
        let offset = (sid as usize)
            .checked_mul(ss)
            .and_then(|v| v.checked_add(HEADER_SIZE))
            .ok_or(OleParserError::Truncated)?;
        let end = offset.checked_add(ss).ok_or(OleParserError::Truncated)?;
        if end > data.len() {
            return Err(OleParserError::Truncated);
        }
        Ok(&data[offset..end])
    }

    fn sector_slice(&self, sid: u32) -> Result<&[u8], OleParserError> {
        Self::sector_slice_raw(&self.data, sid, self.sector_size)
    }

    fn follow_chain(fat: &[u32], start: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut cur = start;
        let max = fat.len() + 2;
        let mut guard = 0usize;
        loop {
            if cur == ENDOFCHAIN || cur == FREESECT || cur == FATSECT || cur == DIFSECT {
                break;
            }
            if guard > max {
                break; // cycle guard
            }
            chain.push(cur);
            cur = fat.get(cur as usize).copied().unwrap_or(ENDOFCHAIN);
            guard += 1;
        }
        chain
    }

    fn read_regular_stream(&self, start: u32, size: usize) -> Result<Vec<u8>, OleParserError> {
        let chain = Self::follow_chain(&self.fat, start);
        let mut out = Vec::with_capacity(size.min(chain.len() * self.sector_size));
        let mut remaining = size;
        for sid in chain {
            if remaining == 0 {
                break;
            }
            let sect = self.sector_slice(sid)?;
            let take = remaining.min(sect.len());
            out.extend_from_slice(&sect[..take]);
            remaining -= take;
        }
        Ok(out)
    }

    fn read_mini_stream(&self, start: u32, size: usize) -> Result<Vec<u8>, OleParserError> {
        let root = self
            .dir_entries
            .first()
            .ok_or(OleParserError::InvalidDirEntry)?;
        let root_size = usize::try_from(root.size)
            .map_err(|_| OleParserError::ParseError("root stream size exceeds address space".into()))?;
        let root_data =
            self.read_regular_stream(root.start_sector, root_size)?;
        let chain = Self::follow_chain(&self.mini_fat, start);
        let mut out = Vec::with_capacity(size.min(chain.len() * self.mini_sector_size));
        let mut remaining = size;
        for mini_sid in chain {
            if remaining == 0 {
                break;
            }
            let off = mini_sid as usize * self.mini_sector_size;
            if off >= root_data.len() {
                return Err(OleParserError::InvalidSector(mini_sid));
            }
            let end = (off + self.mini_sector_size).min(root_data.len());
            let take = remaining.min(end - off);
            out.extend_from_slice(&root_data[off..off + take]);
            remaining -= take;
        }
        Ok(out)
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return a summary map of stream names to sizes.
    #[must_use]
    pub fn stream_summary(&self) -> HashMap<String, u64> {
        let streams = self.list_streams();
        streams
            .into_iter()
            .filter_map(|(path, sid)| {
                let entry = self.dir_entries.get(sid as usize)?;
                Some((path, entry.size))
            })
            .collect()
    }

    /// Return `true` if the file appears to contain a VBA project.
    #[must_use]
    pub fn has_vba(&self) -> bool {
        self.dir_entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case("VBA") || e.name.eq_ignore_ascii_case("_VBA_PROJECT"))
    }
}

impl fmt::Debug for OleParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OleParser")
            .field("sector_size", &self.sector_size)
            .field("fat_len", &self.fat.len())
            .field("mini_fat_len", &self.mini_fat.len())
            .field("dir_entries", &self.dir_entries.len())
            .finish_non_exhaustive()
    }
}

// ── Low-level byte helpers ────────────────────────────────────────────────────

#[inline(always)]
fn u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline(always)]
fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

#[inline(always)]
fn u64_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_bytes() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(&OLE_MAGIC);
        h[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        h[26..28].copy_from_slice(&3u16.to_le_bytes());
        h[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        h[30..32].copy_from_slice(&9u16.to_le_bytes()); // ss exp = 9 → 512
        h[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini exp = 6 → 64
        h[44..48].copy_from_slice(&1u32.to_le_bytes()); // fat_sector_count
        h[48..52].copy_from_slice(&1u32.to_le_bytes()); // first_dir_sector
        h[56..60].copy_from_slice(&0u32.to_le_bytes()); // mini_cutoff = 0
        h[60..64].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first_mini_fat
        h[64..68].copy_from_slice(&0u32.to_le_bytes()); // mini_fat_count
        h[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first_difat_sector
        h[72..76].copy_from_slice(&0u32.to_le_bytes()); // difat_sector_count
        h[76..80].copy_from_slice(&0u32.to_le_bytes()); // difat[0] = FAT at sector 0
        for i in 1..HEADER_DIFAT_LEN {
            let off = 76 + i * 4;
            h[off..off + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }
        h
    }

    fn make_fat_sector() -> Vec<u8> {
        let mut s = vec![0u8; 512];
        // sector 0 = FATSECT
        s[0..4].copy_from_slice(&FATSECT.to_le_bytes());
        // sector 1 = ENDOFCHAIN (dir)
        s[4..8].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // fill rest with FREESECT
        for i in 2..(512 / 4) {
            let off = i * 4;
            s[off..off + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }
        s
    }

    fn make_dir_entry_bytes(name: &str, kind: u8, sector: u32, size: u32) -> Vec<u8> {
        let mut e = vec![0u8; 128];
        let u16s: Vec<u16> = name.encode_utf16().collect();
        for (i, &c) in u16s.iter().enumerate() {
            if i * 2 + 2 > 64 {
                break;
            }
            e[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let name_len = ((u16s.len() + 1) * 2).min(64) as u16;
        e[64..66].copy_from_slice(&name_len.to_le_bytes());
        e[66] = kind;
        e[67] = 1;
        e[68..72].copy_from_slice(&FREESECT.to_le_bytes());
        e[72..76].copy_from_slice(&FREESECT.to_le_bytes());
        e[76..80].copy_from_slice(&FREESECT.to_le_bytes());
        e[116..120].copy_from_slice(&sector.to_le_bytes());
        e[120..124].copy_from_slice(&size.to_le_bytes());
        e
    }

    fn build_minimal_ole() -> Vec<u8> {
        let mut data = make_header_bytes();
        data.extend_from_slice(&make_fat_sector()); // sector 0: FAT
        let mut dir_sector = vec![0u8; 512]; // sector 1: directory
        let root = make_dir_entry_bytes("Root Entry", 5, ENDOFCHAIN, 0);
        dir_sector[0..128].copy_from_slice(&root);
        data.extend_from_slice(&dir_sector);
        data
    }

    #[test]
    fn test_ole_header_parse_valid() {
        let hdr = OleHeader::parse(&make_header_bytes()).unwrap();
        assert_eq!(hdr.major_version, 3);
        assert_eq!(hdr.sector_size(), 512);
        assert_eq!(hdr.fat_sector_count, 1);
    }

    #[test]
    fn test_ole_header_invalid_magic() {
        let data = vec![0u8; 512];
        assert!(matches!(
            OleHeader::parse(&data),
            Err(OleParserError::InvalidMagic)
        ));
    }

    #[test]
    fn test_ole_header_truncated() {
        assert!(matches!(
            OleHeader::parse(&[0u8; 32]),
            Err(OleParserError::Truncated)
        ));
    }

    #[test]
    fn test_dir_entry_type_roundtrip() {
        assert_eq!(DirEntryType::from_byte(0), DirEntryType::Empty);
        assert_eq!(DirEntryType::from_byte(1), DirEntryType::Storage);
        assert_eq!(DirEntryType::from_byte(2), DirEntryType::Stream);
        assert_eq!(DirEntryType::from_byte(5), DirEntryType::Root);
        assert!(matches!(DirEntryType::from_byte(9), DirEntryType::Unknown(9)));
    }

    #[test]
    fn test_dir_entry_parse_root() {
        let bytes = make_dir_entry_bytes("Root Entry", 5, ENDOFCHAIN, 0);
        let de = DirEntry::parse(&bytes).unwrap();
        assert!(de.is_root());
        assert_eq!(de.name, "Root Entry");
    }

    #[test]
    fn test_dir_entry_parse_stream() {
        let bytes = make_dir_entry_bytes("Workbook", 2, 5, 1024);
        let de = DirEntry::parse(&bytes).unwrap();
        assert!(de.is_stream());
        assert_eq!(de.size, 1024);
    }

    #[test]
    fn test_dir_entry_clsid_string() {
        let bytes = make_dir_entry_bytes("Root", 5, 0, 0);
        let de = DirEntry::parse(&bytes).unwrap();
        let s = de.clsid_string();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
    }

    #[test]
    fn test_fat_sector_parse() {
        let s = make_fat_sector();
        let fs = FatSector::parse(0, &s);
        assert_eq!(fs.entries[0], FATSECT);
        assert_eq!(fs.entries[1], ENDOFCHAIN);
        assert_eq!(fs.entries[2], FREESECT);
    }

    #[test]
    fn test_ole_parser_minimal() {
        let data = build_minimal_ole();
        let parser = OleParser::parse(data).unwrap();
        assert_eq!(parser.sector_size, 512);
        assert!(!parser.dir_entries.is_empty());
        assert!(parser.dir_entries[0].is_root());
    }

    #[test]
    fn test_list_streams_empty() {
        let data = build_minimal_ole();
        let parser = OleParser::parse(data).unwrap();
        assert!(parser.list_streams().is_empty());
    }

    #[test]
    fn test_has_vba_false() {
        let data = build_minimal_ole();
        let parser = OleParser::parse(data).unwrap();
        assert!(!parser.has_vba());
    }

    #[test]
    fn test_stream_not_found() {
        let data = build_minimal_ole();
        let parser = OleParser::parse(data).unwrap();
        assert!(matches!(
            parser.read_stream_by_path("nonexistent"),
            Err(OleParserError::StreamNotFound(_))
        ));
    }

    #[test]
    fn test_follow_chain_endofchain() {
        let fat = vec![ENDOFCHAIN; 10];
        let chain = OleParser::follow_chain(&fat, 0);
        assert_eq!(chain, vec![0]);
    }

    #[test]
    fn test_follow_chain_linear() {
        let fat = vec![1u32, 2, 3, ENDOFCHAIN];
        let chain = OleParser::follow_chain(&fat, 0);
        assert_eq!(chain, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_ole_parser_debug() {
        let data = build_minimal_ole();
        let parser = OleParser::parse(data).unwrap();
        let dbg = format!("{parser:?}");
        assert!(dbg.contains("OleParser"));
    }

    #[test]
    fn test_ole_header_display() {
        let hdr = OleHeader::parse(&make_header_bytes()).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("OLE2"));
        assert!(s.contains("512"));
    }
}
