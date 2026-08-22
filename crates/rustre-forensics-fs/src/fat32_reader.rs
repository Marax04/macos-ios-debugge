// fat32_reader.rs — FAT32 filesystem reader
// Parses BPB, directory entries (8.3 + LFN), FAT chains, deleted entry recovery.

use std::collections::HashMap;
use std::fmt;

// ── FAT32 BPB ────────────────────────────────────────────────────────────────

/// FAT32 BIOS Parameter Block (BPB) parsed from the Volume Boot Record.
#[derive(Debug, Clone)]
pub struct Fat32Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub total_sectors: u32,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub volume_serial: u32,
    pub volume_label: [u8; 11],
    pub fs_type: [u8; 8],
}

/// Errors that can occur when parsing FAT32 structures.
#[derive(Debug, Clone)]
pub enum Fat32Error {
    TooShort { need: usize, got: usize },
    InvalidSignature { expected: u16, got: u16 },
    InvalidBpb(String),
    InvalidCluster(u32),
    EndOfChain(u32),
    BadCluster(u32),
    FreeCluster(u32),
    Utf16Error(String),
    IoError(String),
}

impl fmt::Display for Fat32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => {
                write!(f, "buffer too short: need {need}, got {got}")
            }
            Self::InvalidSignature { expected, got } => {
                write!(f, "bad signature: expected 0x{expected:04X}, got 0x{got:04X}")
            }
            Self::InvalidBpb(s) => write!(f, "invalid BPB: {s}"),
            Self::InvalidCluster(c) => write!(f, "invalid cluster {c}"),
            Self::EndOfChain(c) => write!(f, "end of chain at cluster {c}"),
            Self::BadCluster(c) => write!(f, "bad sector cluster {c}"),
            Self::FreeCluster(c) => write!(f, "free cluster {c}"),
            Self::Utf16Error(s) => write!(f, "UTF-16 decode error: {s}"),
            Self::IoError(s) => write!(f, "I/O error: {s}"),
        }
    }
}

impl Fat32Bpb {
    /// Parse from a 512-byte sector image.
    pub fn parse(sector: &[u8]) -> Result<Self, Fat32Error> {
        if sector.len() < 512 {
            return Err(Fat32Error::TooShort { need: 512, got: sector.len() });
        }
        let sig = u16::from_le_bytes([sector[510], sector[511]]);
        if sig != 0xAA55 {
            return Err(Fat32Error::InvalidSignature { expected: 0xAA55, got: sig });
        }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector == 0 || !bytes_per_sector.is_multiple_of(512) {
            return Err(Fat32Error::InvalidBpb(format!(
                "bytes_per_sector={bytes_per_sector}"
            )));
        }
        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 || (sectors_per_cluster & (sectors_per_cluster - 1)) != 0 {
            return Err(Fat32Error::InvalidBpb(format!(
                "sectors_per_cluster={sectors_per_cluster}"
            )));
        }
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        // FAT32 specific: root entry count must be 0
        let root_entry_count = u16::from_le_bytes([sector[17], sector[18]]);
        if root_entry_count != 0 {
            return Err(Fat32Error::InvalidBpb("root_entry_count != 0".into()));
        }
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let fat_size_16 = u16::from_le_bytes([sector[22], sector[23]]);
        if fat_size_16 != 0 {
            return Err(Fat32Error::InvalidBpb("fat_size_16 != 0 (not FAT32)".into()));
        }
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let total_sectors = if total_sectors_16 != 0 {
            u32::from(total_sectors_16)
        } else {
            total_sectors_32
        };
        let sectors_per_fat =
            u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let root_cluster =
            u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        let fs_info_sector = u16::from_le_bytes([sector[48], sector[49]]);
        let backup_boot_sector = u16::from_le_bytes([sector[50], sector[51]]);
        let volume_serial =
            u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]]);
        let mut volume_label = [0u8; 11];
        volume_label.copy_from_slice(&sector[71..82]);
        let mut fs_type = [0u8; 8];
        fs_type.copy_from_slice(&sector[82..90]);
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors,
            sectors_per_fat,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
            volume_serial,
            volume_label,
            fs_type,
        })
    }

    #[must_use] 
    pub const fn cluster_size(&self) -> u64 {
        (self.bytes_per_sector) as u64 * (self.sectors_per_cluster) as u64
    }

    #[must_use] 
    pub const fn fat_byte_offset(&self, fat_index: u8) -> u64 {
        let start = (self.reserved_sectors) as u64 * (self.bytes_per_sector) as u64;
        start + (fat_index) as u64 * (self.sectors_per_fat) as u64 * (self.bytes_per_sector) as u64
    }

    #[must_use] 
    pub const fn data_start_byte(&self) -> u64 {
        let _fat_end = self.fat_byte_offset(0)
            + (self.num_fats) as u64
                * (self.sectors_per_fat) as u64
                * (self.bytes_per_sector) as u64;
        self.fat_byte_offset(0)
            + self.num_fats as u64
                * self.sectors_per_fat as u64
                * self.bytes_per_sector as u64
    }

    #[must_use] 
    pub fn cluster_byte_offset(&self, cluster: u32) -> u64 {
        // Cluster 2 is the first data cluster; clusters 0 and 1 are reserved.
        // Guard subtraction against underflow for invalid cluster values.
        let cluster_index = u64::from(cluster).saturating_sub(2);
        self.data_start_byte()
            .saturating_add(cluster_index.saturating_mul(self.cluster_size()))
    }

    #[must_use] 
    pub fn volume_label_str(&self) -> String {
        String::from_utf8_lossy(&self.volume_label).trim().to_string()
    }

    #[must_use] 
    pub fn fs_type_str(&self) -> String {
        String::from_utf8_lossy(&self.fs_type).trim().to_string()
    }
}

// ── Directory entry ───────────────────────────────────────────────────────────

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LFN: u8 = 0x0F;

pub const ENTRY_DELETED: u8 = 0xE5;
pub const ENTRY_FREE: u8 = 0x00;

/// A short (8.3) directory entry, 32 bytes.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: [u8; 8],
    pub ext: [u8; 3],
    pub attributes: u8,
    pub nt_reserved: u8,
    pub created_time_tenth: u8,
    pub created_time: u16,
    pub created_date: u16,
    pub last_access_date: u16,
    pub cluster_hi: u16,
    pub modified_time: u16,
    pub modified_date: u16,
    pub cluster_lo: u16,
    pub file_size: u32,
    pub is_deleted: bool,
}

impl DirEntry {
    pub fn parse(buf: &[u8]) -> Result<Self, Fat32Error> {
        if buf.len() < 32 {
            return Err(Fat32Error::TooShort { need: 32, got: buf.len() });
        }
        let first = buf[0];
        let is_deleted = first == ENTRY_DELETED;
        let mut name = [0u8; 8];
        let mut ext = [0u8; 3];
        name.copy_from_slice(&buf[0..8]);
        ext.copy_from_slice(&buf[8..11]);
        Ok(Self {
            name,
            ext,
            attributes: buf[11],
            nt_reserved: buf[12],
            created_time_tenth: buf[13],
            created_time: u16::from_le_bytes([buf[14], buf[15]]),
            created_date: u16::from_le_bytes([buf[16], buf[17]]),
            last_access_date: u16::from_le_bytes([buf[18], buf[19]]),
            cluster_hi: u16::from_le_bytes([buf[20], buf[21]]),
            modified_time: u16::from_le_bytes([buf[22], buf[23]]),
            modified_date: u16::from_le_bytes([buf[24], buf[25]]),
            cluster_lo: u16::from_le_bytes([buf[26], buf[27]]),
            file_size: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            is_deleted,
        })
    }

    #[must_use] 
    pub const fn is_lfn(&self) -> bool {
        self.attributes == ATTR_LFN
    }

    #[must_use] 
    pub const fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    #[must_use] 
    pub const fn is_free(&self) -> bool {
        self.name[0] == ENTRY_FREE
    }

    #[must_use] 
    pub const fn is_volume_id(&self) -> bool {
        self.attributes & ATTR_VOLUME_ID != 0
    }

    #[must_use] 
    pub const fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | (self.cluster_lo) as u32
    }

    /// Return the 8.3 short name, handling deleted-entry first byte.
    #[must_use] 
    pub fn short_name(&self) -> String {
        let mut n = self.name;
        if self.is_deleted && n[0] == ENTRY_DELETED {
            n[0] = b'?';
        }
        let name_s = String::from_utf8_lossy(&n).trim().to_string();
        let ext_s = String::from_utf8_lossy(&self.ext).trim().to_string();
        if ext_s.is_empty() {
            name_s
        } else {
            format!("{name_s}.{ext_s}")
        }
    }

    /// Decode FAT date: bits 15-9 = year offset from 1980, 8-5 = month, 4-0 = day.
    #[must_use] 
    pub const fn decode_date(d: u16) -> (u16, u8, u8) {
        let year = 1980 + (d >> 9);
        let month = ((d >> 5) & 0x0F) as u8;
        let day = (d & 0x1F) as u8;
        (year, month, day)
    }

    /// Decode FAT time: bits 15-11 = hours, 10-5 = minutes, 4-0 = seconds/2.
    #[must_use] 
    pub const fn decode_time(t: u16) -> (u8, u8, u8) {
        let hour = (t >> 11) as u8;
        let min = ((t >> 5) & 0x3F) as u8;
        let sec = ((t & 0x1F) * 2) as u8;
        (hour, min, sec)
    }

    #[must_use] 
    pub fn modified_datetime_str(&self) -> String {
        let (y, mo, d) = Self::decode_date(self.modified_date);
        let (h, mi, s) = Self::decode_time(self.modified_time);
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
    }
}

// ── Long Filename Entry ───────────────────────────────────────────────────────

/// A single LFN (Long File Name) directory entry slot, 32 bytes.
#[derive(Debug, Clone)]
pub struct LfnEntry {
    pub order: u8,
    pub name1: [u16; 5],
    pub checksum: u8,
    pub name2: [u16; 6],
    pub name3: [u16; 2],
}

impl LfnEntry {
    pub const LAST_LFN_ENTRY: u8 = 0x40;

    pub fn parse(buf: &[u8]) -> Result<Self, Fat32Error> {
        if buf.len() < 32 {
            return Err(Fat32Error::TooShort { need: 32, got: buf.len() });
        }
        let order = buf[0];
        let mut name1 = [0u16; 5];
        let mut name2 = [0u16; 6];
        let mut name3 = [0u16; 2];
        for i in 0..5 {
            name1[i] = u16::from_le_bytes([buf[1 + i * 2], buf[2 + i * 2]]);
        }
        let checksum = buf[13];
        for i in 0..6 {
            name2[i] = u16::from_le_bytes([buf[14 + i * 2], buf[15 + i * 2]]);
        }
        for i in 0..2 {
            name3[i] = u16::from_le_bytes([buf[28 + i * 2], buf[29 + i * 2]]);
        }
        Ok(Self { order, name1, checksum, name2, name3 })
    }

    #[must_use] 
    pub const fn is_last(&self) -> bool {
        self.order & Self::LAST_LFN_ENTRY != 0
    }

    #[must_use] 
    pub const fn sequence(&self) -> u8 {
        self.order & !Self::LAST_LFN_ENTRY
    }

    #[must_use] 
    pub fn name_chars(&self) -> Vec<u16> {
        let mut v = Vec::with_capacity(13);
        v.extend_from_slice(&self.name1);
        v.extend_from_slice(&self.name2);
        v.extend_from_slice(&self.name3);
        v
    }

    /// Compute LFN checksum of a short-name 11-byte array.
    #[must_use] 
    pub fn compute_checksum(short_name: &[u8; 11]) -> u8 {
        let mut sum: u8 = 0;
        for &b in short_name {
            sum = sum.rotate_right(1);
            sum = sum.wrapping_add(b);
        }
        sum
    }
}

// ── FAT chain walker ──────────────────────────────────────────────────────────

pub const FAT_FREE: u32 = 0x0000_0000;
pub const FAT_BAD: u32 = 0x0FFF_FFF7;
pub const FAT_END_MIN: u32 = 0x0FFF_FFF8;
pub const FAT_END_MAX: u32 = 0x0FFF_FFFF;
pub const FAT_MASK: u32 = 0x0FFF_FFFF;

/// Iterator over the FAT32 cluster chain.
#[derive(Debug, Clone)]
pub struct FatChain<'a> {
    fat: &'a [u8],
    current: u32,
    done: bool,
}

impl<'a> FatChain<'a> {
    /// Create a new chain iterator. `fat` is the raw FAT bytes (first FAT copy).
    #[must_use] 
    pub const fn new(fat: &'a [u8], start_cluster: u32) -> Self {
        Self { fat, current: start_cluster, done: start_cluster < 2 }
    }

    fn read_fat_entry(&self, cluster: u32) -> u32 {
        let offset = (cluster as usize) * 4;
        if offset + 4 > self.fat.len() {
            return FAT_END_MAX;
        }
        u32::from_le_bytes([
            self.fat[offset],
            self.fat[offset + 1],
            self.fat[offset + 2],
            self.fat[offset + 3],
        ]) & FAT_MASK
    }

    #[must_use] 
    pub const fn is_end(cluster: u32) -> bool {
        cluster >= FAT_END_MIN
    }

    #[must_use] 
    pub const fn is_bad(cluster: u32) -> bool {
        cluster == FAT_BAD
    }

    #[must_use] 
    pub const fn is_free(cluster: u32) -> bool {
        cluster == FAT_FREE
    }
}

impl Iterator for FatChain<'_> {
    type Item = Result<u32, Fat32Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let c = self.current;
        let next = self.read_fat_entry(c);
        if Self::is_bad(next) {
            self.done = true;
            return Some(Err(Fat32Error::BadCluster(c)));
        }
        if Self::is_end(next) {
            self.done = true;
            return Some(Ok(c));
        }
        if Self::is_free(next) {
            self.done = true;
            return Some(Err(Fat32Error::FreeCluster(c)));
        }
        self.current = next;
        Some(Ok(c))
    }
}

// ── Parsed file record ────────────────────────────────────────────────────────

/// A file or directory entry as recovered from the FAT32 directory structure.
#[derive(Debug, Clone)]
pub struct Fat32Entry {
    pub long_name: Option<String>,
    pub short_name: String,
    pub attributes: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    pub modified_datetime: String,
    pub is_deleted: bool,
}

impl Fat32Entry {
    #[must_use] 
    pub const fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    #[must_use] 
    pub fn name(&self) -> &str {
        self.long_name.as_deref().unwrap_or(&self.short_name)
    }
}

// ── Directory parser ──────────────────────────────────────────────────────────

/// Parses a raw directory cluster into directory entries.
/// Handles interleaved LFN entries.
#[must_use] 
pub fn parse_directory(data: &[u8]) -> Vec<Fat32Entry> {
    let mut entries = Vec::new();
    let mut lfn_parts: Vec<LfnEntry> = Vec::new();
    let mut i = 0;
    while i + 32 <= data.len() {
        let buf = &data[i..i + 32];
        let first = buf[0];
        if first == ENTRY_FREE {
            // No more entries after a free entry.
            break;
        }
        let attrs = buf[11];
        if attrs == ATTR_LFN {
            if let Ok(lfn) = LfnEntry::parse(buf) {
                lfn_parts.push(lfn);
            }
        } else if let Ok(de) = DirEntry::parse(buf) {
            if !de.is_volume_id() {
                let long_name = assemble_lfn(&lfn_parts);
                entries.push(Fat32Entry {
                    long_name,
                    short_name: de.short_name(),
                    attributes: de.attributes,
                    first_cluster: de.first_cluster(),
                    file_size: de.file_size,
                    modified_datetime: de.modified_datetime_str(),
                    is_deleted: de.is_deleted,
                });
            }
            lfn_parts.clear();
        }
        i += 32;
    }
    entries
}

fn assemble_lfn(parts: &[LfnEntry]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    // Parts are stored in reverse order (last LFN slot first).
    let mut ordered: Vec<&LfnEntry> = parts.iter().collect();
    ordered.sort_by_key(|e| e.sequence());
    let mut chars: Vec<u16> = Vec::new();
    for part in &ordered {
        chars.extend_from_slice(&part.name_chars());
    }
    // Trim null terminators and padding (0xFFFF).
    let trimmed: Vec<u16> = chars
        .into_iter()
        .take_while(|&c| c != 0x0000)
        .filter(|&c| c != 0xFFFF)
        .collect();
    if trimmed.is_empty() {
        return None;
    }
    String::from_utf16(&trimmed).ok()
}

// ── FAT32 Reader ──────────────────────────────────────────────────────────────

/// High-level FAT32 volume reader operating on a byte slice image.
pub struct Fat32Reader {
    data: Vec<u8>,
    bpb: Fat32Bpb,
    _fat_cache: HashMap<u32, u32>,
}

impl Fat32Reader {
    pub fn new(data: Vec<u8>) -> Result<Self, Fat32Error> {
        let bpb = Fat32Bpb::parse(&data)?;
        Ok(Self { data, bpb, _fat_cache: HashMap::new() })
    }

    #[must_use] 
    pub const fn bpb(&self) -> &Fat32Bpb {
        &self.bpb
    }

    fn read_bytes(&self, offset: u64, len: usize) -> Result<&[u8], Fat32Error> {
        let start = offset as usize;
        let end = start + len;
        if end > self.data.len() {
            return Err(Fat32Error::TooShort { need: end, got: self.data.len() });
        }
        Ok(&self.data[start..end])
    }

    #[must_use] 
    pub fn read_fat_entry(&self, cluster: u32) -> u32 {
        let fat_off = self.bpb.fat_byte_offset(0) as usize + cluster as usize * 4;
        if fat_off + 4 > self.data.len() {
            return FAT_END_MAX;
        }
        u32::from_le_bytes([
            self.data[fat_off],
            self.data[fat_off + 1],
            self.data[fat_off + 2],
            self.data[fat_off + 3],
        ]) & FAT_MASK
    }

    /// Collect all clusters in a chain, up to a safety limit.
    pub fn cluster_chain(&mut self, start: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut c = start;
        let limit = 65536usize;
        while c >= 2 && chain.len() < limit {
            chain.push(c);
            let next = self.read_fat_entry(c);
            if FatChain::is_end(next) || FatChain::is_bad(next) || FatChain::is_free(next) {
                break;
            }
            c = next;
        }
        chain
    }

    /// Read all data bytes for a cluster chain.
    pub fn read_chain_data(&mut self, start: u32, size: Option<u32>) -> Result<Vec<u8>, Fat32Error> {
        let chain = self.cluster_chain(start);
        let cluster_sz = self.bpb.cluster_size() as usize;
        // Cap the pre-allocation to avoid exhausting memory when both
        // chain length (up to 65536) and cluster_size (up to ~512 KB for valid
        // FAT32) are at their maximums.  We allocate at most 256 MiB up front
        // and let the Vec grow naturally beyond that if the actual data warrants
        // it (real reads are still bounded by `self.data.len()`).
        const MAX_PREALLOC: usize = 256 * 1024 * 1024;
        // `read_bytes` can never yield more than the image itself, so the
        // chain/cluster product (up to ~1 TB from header fields alone) must
        // also be capped by the real buffer: otherwise a 1 KB crafted image
        // still forces the full 256 MiB reservation.
        let prealloc = (chain.len() * cluster_sz)
            .min(MAX_PREALLOC)
            .min(self.data.len());
        let mut buf = Vec::with_capacity(prealloc);
        for &c in &chain {
            let off = self.bpb.cluster_byte_offset(c);
            let slice = self.read_bytes(off, cluster_sz)?;
            buf.extend_from_slice(slice);
        }
        if let Some(sz) = size {
            buf.truncate(sz as usize);
        }
        Ok(buf)
    }

    /// Read and parse the directory at the given start cluster.
    pub fn read_directory(&mut self, start_cluster: u32) -> Result<Vec<Fat32Entry>, Fat32Error> {
        let data = self.read_chain_data(start_cluster, None)?;
        Ok(parse_directory(&data))
    }

    /// List root directory entries.
    pub fn list_root(&mut self) -> Result<Vec<Fat32Entry>, Fat32Error> {
        let root = self.bpb.root_cluster;
        self.read_directory(root)
    }

    /// Recursively list all files and directories. Returns (path, entry) pairs.
    pub fn list_all(&mut self) -> Result<Vec<(String, Fat32Entry)>, Fat32Error> {
        let root = self.bpb.root_cluster;
        let mut result = Vec::new();
        self.list_recursive(root, String::from("/"), &mut result, 0)?;
        Ok(result)
    }

    fn list_recursive(
        &mut self,
        cluster: u32,
        prefix: String,
        out: &mut Vec<(String, Fat32Entry)>,
        depth: usize,
    ) -> Result<(), Fat32Error> {
        if depth > 32 {
            return Ok(());
        }
        let entries = self.read_directory(cluster)?;
        for entry in entries {
            let n = entry.name().to_string();
            if n == "." || n == ".." {
                continue;
            }
            let path = format!("{prefix}{n}");
            if entry.is_directory() && entry.first_cluster >= 2 {
                out.push((path.clone() + "/", entry.clone()));
                self.list_recursive(
                    entry.first_cluster,
                    path + "/",
                    out,
                    depth + 1,
                )?;
            } else {
                out.push((path, entry));
            }
        }
        Ok(())
    }

    /// Scan root directory for deleted entries (first byte == 0xE5).
    pub fn recover_deleted(&mut self) -> Result<Vec<Fat32Entry>, Fat32Error> {
        let root = self.bpb.root_cluster;
        let data = self.read_chain_data(root, None)?;
        let all = parse_directory_with_deleted(&data);
        Ok(all.into_iter().filter(|e| e.is_deleted).collect())
    }

    /// Read file content by following its cluster chain.
    pub fn read_file(&mut self, entry: &Fat32Entry) -> Result<Vec<u8>, Fat32Error> {
        if entry.is_directory() {
            return Err(Fat32Error::InvalidBpb("entry is a directory".into()));
        }
        self.read_chain_data(entry.first_cluster, Some(entry.file_size))
    }

    #[must_use] 
    pub const fn volume_size_bytes(&self) -> u64 {
        (self.bpb.total_sectors) as u64 * (self.bpb.bytes_per_sector) as u64
    }
}

/// Like `parse_directory` but does not stop at free entries (for deleted recovery).
fn parse_directory_with_deleted(data: &[u8]) -> Vec<Fat32Entry> {
    let mut entries = Vec::new();
    let mut lfn_parts: Vec<LfnEntry> = Vec::new();
    let mut i = 0;
    while i + 32 <= data.len() {
        let buf = &data[i..i + 32];
        let first = buf[0];
        // Skip completely zeroed entries only if attribute byte is also 0.
        if first == ENTRY_FREE && buf[11] == 0 {
            i += 32;
            continue;
        }
        let attrs = buf[11];
        let is_deleted = first == ENTRY_DELETED;
        if attrs == ATTR_LFN && !is_deleted {
            if let Ok(lfn) = LfnEntry::parse(buf) {
                lfn_parts.push(lfn);
            }
        } else if let Ok(de) = DirEntry::parse(buf) {
            if !de.is_volume_id() {
                let long_name = assemble_lfn(&lfn_parts);
                entries.push(Fat32Entry {
                    long_name,
                    short_name: de.short_name(),
                    attributes: de.attributes,
                    first_cluster: de.first_cluster(),
                    file_size: de.file_size,
                    modified_datetime: de.modified_datetime_str(),
                    is_deleted: de.is_deleted,
                });
            }
            lfn_parts.clear();
        }
        i += 32;
    }
    entries
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vbr() -> Vec<u8> {
        let mut v = vec![0u8; 512];
        // OEM
        v[3..11].copy_from_slice(b"MSDOS5.0");
        // bytes_per_sector = 512
        v[11] = 0x00;
        v[12] = 0x02;
        // sectors_per_cluster = 8
        v[13] = 8;
        // reserved_sectors = 32
        v[14] = 32;
        v[15] = 0;
        // num_fats = 2
        v[16] = 2;
        // root_entry_count = 0 (FAT32)
        v[17] = 0;
        v[18] = 0;
        // total_sectors_16 = 0
        v[19] = 0;
        v[20] = 0;
        // media = 0xF8
        v[21] = 0xF8;
        // fat_size_16 = 0 (FAT32)
        v[22] = 0;
        v[23] = 0;
        // total_sectors_32 = 0x20000
        v[32] = 0x00;
        v[33] = 0x00;
        v[34] = 0x02;
        v[35] = 0x00;
        // sectors_per_fat32 = 512
        v[36] = 0x00;
        v[37] = 0x02;
        v[38] = 0;
        v[39] = 0;
        // root_cluster = 2
        v[44] = 2;
        v[45] = 0;
        v[46] = 0;
        v[47] = 0;
        // fs_info_sector = 1
        v[48] = 1;
        v[49] = 0;
        // backup_boot_sector = 6
        v[50] = 6;
        v[51] = 0;
        // volume_serial
        v[67] = 0xAB;
        v[68] = 0xCD;
        v[69] = 0xEF;
        v[70] = 0x01;
        // volume_label
        v[71..82].copy_from_slice(b"TESTVOL    ");
        // fs_type
        v[82..90].copy_from_slice(b"FAT32   ");
        // signature
        v[510] = 0x55;
        v[511] = 0xAA;
        v
    }

    #[test]
    fn test_bpb_parse() {
        let vbr = make_vbr();
        let bpb = Fat32Bpb::parse(&vbr).unwrap();
        assert_eq!(bpb.bytes_per_sector, 512);
        assert_eq!(bpb.sectors_per_cluster, 8);
        assert_eq!(bpb.num_fats, 2);
        assert_eq!(bpb.root_cluster, 2);
        assert_eq!(bpb.volume_label_str(), "TESTVOL");
        assert_eq!(bpb.fs_type_str(), "FAT32");
    }

    #[test]
    fn test_bpb_cluster_size() {
        let vbr = make_vbr();
        let bpb = Fat32Bpb::parse(&vbr).unwrap();
        assert_eq!(bpb.cluster_size(), 512 * 8);
    }

    #[test]
    fn test_bpb_wrong_sig() {
        let mut vbr = make_vbr();
        vbr[510] = 0x00;
        assert!(Fat32Bpb::parse(&vbr).is_err());
    }

    #[test]
    fn test_bpb_not_fat32_root_entry_count() {
        let mut vbr = make_vbr();
        vbr[17] = 0x10; // root_entry_count != 0
        assert!(Fat32Bpb::parse(&vbr).is_err());
    }

    #[test]
    fn test_dir_entry_parse() {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(b"HELLO   ");
        buf[8..11].copy_from_slice(b"TXT");
        buf[11] = ATTR_ARCHIVE;
        buf[26] = 3; // cluster_lo = 3
        buf[28] = 100; // file_size = 100
        let de = DirEntry::parse(&buf).unwrap();
        assert_eq!(de.short_name(), "HELLO.TXT");
        assert_eq!(de.first_cluster(), 3);
        assert_eq!(de.file_size, 100);
        assert!(!de.is_deleted);
    }

    #[test]
    fn test_dir_entry_deleted() {
        let mut buf = [0u8; 32];
        buf[0] = ENTRY_DELETED;
        buf[1..8].copy_from_slice(b"FILE   ");
        buf[8..11].copy_from_slice(b"   ");
        buf[11] = ATTR_ARCHIVE;
        let de = DirEntry::parse(&buf).unwrap();
        assert!(de.is_deleted);
        assert!(de.short_name().starts_with('?'));
    }

    #[test]
    fn test_dir_entry_is_directory() {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(b"MYDIR   ");
        buf[8..11].copy_from_slice(b"   ");
        buf[11] = ATTR_DIRECTORY;
        let de = DirEntry::parse(&buf).unwrap();
        assert!(de.is_directory());
    }

    #[test]
    fn test_fat_chain_end() {
        // Single cluster that points to EOF
        let mut fat = vec![0u8; 16];
        // Cluster 2 -> 0x0FFFFFFF (EOF)
        let eoc: u32 = 0x0FFFFFFF;
        fat[8] = (eoc & 0xFF) as u8;
        fat[9] = ((eoc >> 8) & 0xFF) as u8;
        fat[10] = ((eoc >> 16) & 0xFF) as u8;
        fat[11] = ((eoc >> 24) & 0xFF) as u8;
        let chain: Vec<_> = FatChain::new(&fat, 2).collect();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].as_ref().unwrap(), &2u32);
    }

    #[test]
    fn test_fat_chain_two_clusters() {
        let mut fat = vec![0u8; 24];
        // Cluster 2 -> 3
        fat[8] = 3;
        fat[9] = 0;
        fat[10] = 0;
        fat[11] = 0;
        // Cluster 3 -> EOF
        let eoc: u32 = 0x0FFFFFFF;
        fat[12] = (eoc & 0xFF) as u8;
        fat[13] = ((eoc >> 8) & 0xFF) as u8;
        fat[14] = ((eoc >> 16) & 0xFF) as u8;
        fat[15] = ((eoc >> 24) & 0xFF) as u8;
        let chain: Vec<u32> = FatChain::new(&fat, 2)
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(chain, vec![2, 3]);
    }

    #[test]
    fn test_fat_decode_date() {
        // 2023-07-15: year=43, month=7, day=15
        let d: u16 = ((43u16) << 9) | (7u16 << 5) | 15u16;
        let (y, mo, day) = DirEntry::decode_date(d);
        assert_eq!(y, 2023);
        assert_eq!(mo, 7);
        assert_eq!(day, 15);
    }

    #[test]
    fn test_fat_decode_time() {
        // 14:30:22 -> hour=14, min=30, sec=11 (stored as sec/2)
        let t: u16 = (14u16 << 11) | (30u16 << 5) | 11u16;
        let (h, mi, s) = DirEntry::decode_time(t);
        assert_eq!(h, 14);
        assert_eq!(mi, 30);
        assert_eq!(s, 22);
    }

    #[test]
    fn test_lfn_checksum() {
        let mut name = [0u8; 11];
        name.copy_from_slice(b"HELLO   TXT");
        let c = LfnEntry::compute_checksum(&name);
        assert!(c > 0); // just verify it runs
    }

    #[test]
    fn test_parse_directory_empty() {
        let data = vec![0u8; 512];
        let entries = parse_directory(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_directory_single_entry() {
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(b"README  ");
        data[8..11].copy_from_slice(b"MD ");
        data[11] = ATTR_ARCHIVE;
        data[26] = 5;
        data[28] = 42;
        let entries = parse_directory(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].short_name, "README.MD");
        assert_eq!(entries[0].file_size, 42);
    }

    #[test]
    fn test_fat32_reader_new() {
        let mut img = vec![0u8; 1024 * 1024];
        // Write VBR to offset 0
        let vbr = make_vbr();
        img[..512].copy_from_slice(&vbr);
        let reader = Fat32Reader::new(img).unwrap();
        assert_eq!(reader.bpb().bytes_per_sector, 512);
    }

    #[test]
    fn test_fat32_error_display() {
        let e = Fat32Error::TooShort { need: 100, got: 50 };
        assert!(e.to_string().contains("50"));
        let e2 = Fat32Error::InvalidCluster(99);
        assert!(e2.to_string().contains("99"));
    }
}
