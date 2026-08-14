//! FAT12/FAT16/FAT32 filesystem analyser with deleted-entry recovery.
//!
//! Parses a raw disk image byte slice and exposes boot-sector metadata,
//! directory entries, FAT chain walking, and best-effort recovery of deleted
//! entries whose first cluster has not yet been overwritten.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FatError {
    #[error("image too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("invalid boot sector signature: expected 0xAA55, got 0x{got:04X}")]
    BadSignature { got: u16 },
    #[error("unsupported bytes-per-sector: {0}")]
    BadBytesPerSector(u16),
    #[error("unsupported sectors-per-cluster: {0}")]
    BadSectorsPerCluster(u8),
    #[error("FAT type detection failed: total clusters = {0}")]
    UnknownFatType(u32),
    #[error("cluster {0} out of range")]
    ClusterOutOfRange(u32),
    #[error("circular FAT chain detected at cluster {0}")]
    CircularChain(u32),
    #[error("parse error: {0}")]
    ParseError(String),
}

// ── FatType ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

impl fmt::Display for FatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fat12 => f.write_str("FAT12"),
            Self::Fat16 => f.write_str("FAT16"),
            Self::Fat32 => f.write_str("FAT32"),
        }
    }
}

impl FatType {
    /// Return the end-of-chain sentinel for this FAT type.
    #[must_use] 
    pub const fn eoc_min(self) -> u32 {
        match self {
            Self::Fat12 => 0xFF8,
            Self::Fat16 => 0xFFF8,
            Self::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// Return the bad-cluster marker for this FAT type.
    #[must_use] 
    pub const fn bad_cluster(self) -> u32 {
        match self {
            Self::Fat12 => 0xFF7,
            Self::Fat16 => 0xFFF7,
            Self::Fat32 => 0x0FFF_FFF7,
        }
    }

    /// Return the free-cluster value for this FAT type.
    #[must_use] 
    pub const fn free_cluster(self) -> u32 {
        0
    }
}

// ── FatTimestamp ─────────────────────────────────────────────────────────────

/// A decoded FAT date/time pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatTimestamp {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl FatTimestamp {
    /// Decode a FAT 16-bit date and 16-bit time field.
    ///
    /// Date bits: [15:9] year since 1980, [8:5] month 1-12, [4:0] day 1-31.
    /// Time bits: [15:11] hour, [10:5] minute, [4:0] second/2.
    #[must_use] 
    pub const fn decode(date: u16, time: u16) -> Self {
        let year = (date >> 9) + 1980;
        let month = ((date >> 5) & 0xF) as u8;
        let day = (date & 0x1F) as u8;
        let hour = (time >> 11) as u8;
        let minute = ((time >> 5) & 0x3F) as u8;
        let second = ((time & 0x1F) * 2) as u8;
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// Encode back to FAT date/time fields.
    #[must_use] 
    pub const fn encode(self) -> (u16, u16) {
        let date = ((self.year.saturating_sub(1980)) << 9)
            | (((self.month) as u16 & 0xF) << 5)
            | ((self.day) as u16 & 0x1F);
        let time =
            ((self.hour as u16) << 11) | ((self.minute as u16) << 5) | (self.second / 2) as u16;
        (date, time)
    }
}

impl fmt::Display for FatTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

// ── FatBootSector ────────────────────────────────────────────────────────────

/// Parsed BIOS Parameter Block / FAT boot sector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatBootSector {
    pub oem_name: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub total_sectors_16: u16,
    pub media_type: u8,
    pub fat_size_16: u16,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    // FAT32 extended fields
    pub fat_size_32: Option<u32>,
    pub root_cluster: Option<u32>,
    pub fs_info_sector: Option<u16>,
    pub volume_label: Option<String>,
    pub fs_type_label: Option<String>,
}

impl FatBootSector {
    /// Parse a 512-byte boot-sector slice.
    pub fn parse(data: &[u8]) -> Result<Self, FatError> {
        if data.len() < 512 {
            return Err(FatError::TooShort {
                need: 512,
                have: data.len(),
            });
        }
        let sig = u16::from_le_bytes([data[510], data[511]]);
        if sig != 0xAA55 {
            return Err(FatError::BadSignature { got: sig });
        }
        let bps = u16::from_le_bytes([data[11], data[12]]);
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(FatError::BadBytesPerSector(bps));
        }
        let spc = data[13];
        if spc == 0 || !spc.is_power_of_two() {
            return Err(FatError::BadSectorsPerCluster(spc));
        }

        let oem = String::from_utf8_lossy(&data[3..11]).trim().to_owned();
        let reserved = u16::from_le_bytes([data[14], data[15]]);
        let num_fats = data[16];
        let root_count = u16::from_le_bytes([data[17], data[18]]);
        let total16 = u16::from_le_bytes([data[19], data[20]]);
        let media = data[21];
        let fat16 = u16::from_le_bytes([data[22], data[23]]);
        let spt = u16::from_le_bytes([data[24], data[25]]);
        let heads = u16::from_le_bytes([data[26], data[27]]);
        let hidden = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let total32 = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

        // Detect FAT32 by checking fat_size_16 == 0
        let (fat_size_32, root_cluster, fs_info_sector, volume_label, fs_type_label) =
            if fat16 == 0 && data.len() >= 512 {
                let fs32 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
                let rc = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
                let fsi = u16::from_le_bytes([data[48], data[49]]);
                let vl = String::from_utf8_lossy(&data[71..82]).trim().to_owned();
                let ft = String::from_utf8_lossy(&data[82..90]).trim().to_owned();
                (Some(fs32), Some(rc), Some(fsi), Some(vl), Some(ft))
            } else {
                let vl = String::from_utf8_lossy(&data[43..54]).trim().to_owned();
                let ft = String::from_utf8_lossy(&data[54..62]).trim().to_owned();
                (None, None, None, Some(vl), Some(ft))
            };

        Ok(Self {
            oem_name: oem,
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            reserved_sectors: reserved,
            num_fats,
            root_entry_count: root_count,
            total_sectors_16: total16,
            media_type: media,
            fat_size_16: fat16,
            sectors_per_track: spt,
            num_heads: heads,
            hidden_sectors: hidden,
            total_sectors_32: total32,
            fat_size_32,
            root_cluster,
            fs_info_sector,
            volume_label,
            fs_type_label,
        })
    }

    /// Total sectors in the volume.
    #[must_use] 
    pub const fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            (self.total_sectors_16) as u32
        } else {
            self.total_sectors_32
        }
    }

    /// FAT size in sectors.
    #[must_use] 
    pub fn fat_size(&self) -> u32 {
        if self.fat_size_16 != 0 {
            (self.fat_size_16) as u32
        } else {
            self.fat_size_32.unwrap_or(0)
        }
    }

    /// First sector of the root directory (FAT12/16).
    #[must_use] 
    pub fn root_dir_first_sector(&self) -> u32 {
        u32::from(self.num_fats)
            .saturating_mul(self.fat_size())
            .saturating_add(u32::from(self.reserved_sectors))
    }

    /// Root directory size in sectors (FAT12/16 only; 0 for FAT32).
    #[must_use] 
    pub const fn root_dir_sectors(&self) -> u32 {
        (((self.root_entry_count) as u32 * 32) + (self.bytes_per_sector) as u32 - 1)
            / (self.bytes_per_sector) as u32
    }

    /// First data sector.
    #[must_use] 
    pub fn first_data_sector(&self) -> u32 {
        self.root_dir_first_sector() + self.root_dir_sectors()
    }

    /// Cluster count (used to determine FAT type).
    #[must_use] 
    pub fn cluster_count(&self) -> u32 {
        let data_sectors = self
            .total_sectors()
            .saturating_sub(self.first_data_sector());
        data_sectors / (self.sectors_per_cluster) as u32
    }

    /// Detect FAT type from cluster count (per Microsoft spec).
    pub fn fat_type(&self) -> Result<FatType, FatError> {
        let cc = self.cluster_count();
        if cc < 4085 {
            Ok(FatType::Fat12)
        } else if cc < 65525 {
            Ok(FatType::Fat16)
        } else {
            Ok(FatType::Fat32)
        }
    }
}

// ── DirectoryEntry ────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DirAttr: u8 {
        const READ_ONLY  = 0x01;
        const HIDDEN     = 0x02;
        const SYSTEM     = 0x04;
        const VOLUME_ID  = 0x08;
        const DIRECTORY  = 0x10;
        const ARCHIVE    = 0x20;
        const LONG_NAME  = 0x0F;
    }
}

/// A decoded FAT directory entry (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// 8.3 filename (or long-name if reconstructed).
    pub name: String,
    /// File extension (empty for directories or LFN).
    pub ext: String,
    pub attributes: DirAttr,
    pub created: FatTimestamp,
    pub accessed_date: u16,
    pub modified: FatTimestamp,
    /// First cluster of the file data.
    pub first_cluster: u32,
    /// File size in bytes.
    pub size: u32,
    /// True if this entry has been deleted (first byte was 0xE5).
    pub is_deleted: bool,
}

impl DirectoryEntry {
    /// Parse a single 32-byte directory entry.
    pub fn parse(raw: &[u8]) -> Result<Option<Self>, FatError> {
        if raw.len() < 32 {
            return Err(FatError::TooShort {
                need: 32,
                have: raw.len(),
            });
        }
        let first = raw[0];
        if first == 0x00 {
            return Ok(None); // end of directory
        }
        let is_deleted = first == 0xE5;

        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&raw[0..8]);
        if is_deleted {
            name_bytes[0] = b'_';
        }
        let name = String::from_utf8_lossy(&name_bytes).trim_end().to_owned();
        let ext = String::from_utf8_lossy(&raw[8..11]).trim_end().to_owned();

        let attrs = DirAttr::from_bits_truncate(raw[11]);

        // Skip LFN entries
        if attrs.contains(DirAttr::LONG_NAME) {
            return Ok(None);
        }

        let crt_time = u16::from_le_bytes([raw[14], raw[15]]);
        let crt_date = u16::from_le_bytes([raw[16], raw[17]]);
        let acc_date = u16::from_le_bytes([raw[18], raw[19]]);
        let wrt_time = u16::from_le_bytes([raw[22], raw[23]]);
        let wrt_date = u16::from_le_bytes([raw[24], raw[25]]);

        let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]);
        let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]);
        let first_cluster = ((cluster_hi as u32) << 16) | (cluster_lo) as u32;
        let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

        Ok(Some(Self {
            name,
            ext,
            attributes: attrs,
            created: FatTimestamp::decode(crt_date, crt_time),
            accessed_date: acc_date,
            modified: FatTimestamp::decode(wrt_date, wrt_time),
            first_cluster,
            size,
            is_deleted,
        }))
    }

    /// Full 8.3 filename string.
    #[must_use] 
    pub fn full_name(&self) -> String {
        if self.ext.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.name.trim_end(), self.ext.trim_end())
        }
    }

    #[must_use] 
    pub const fn is_directory(&self) -> bool {
        self.attributes.contains(DirAttr::DIRECTORY)
    }

    #[must_use] 
    pub const fn is_hidden(&self) -> bool {
        self.attributes.contains(DirAttr::HIDDEN)
    }

    #[must_use] 
    pub const fn is_system(&self) -> bool {
        self.attributes.contains(DirAttr::SYSTEM)
    }

    #[must_use] 
    pub const fn is_read_only(&self) -> bool {
        self.attributes.contains(DirAttr::READ_ONLY)
    }
}

// ── FatChain ─────────────────────────────────────────────────────────────────

/// A resolved FAT cluster chain for a single file/directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatChain {
    pub clusters: Vec<u32>,
    pub fat_type: FatType,
    pub is_truncated: bool,
}

impl FatChain {
    /// Number of clusters allocated.
    #[must_use] 
    pub const fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Theoretical data size covered by this chain (may exceed file size).
    #[must_use] 
    pub const fn chain_bytes(&self, cluster_size: u32) -> u64 {
        self.clusters.len() as u64 * (cluster_size) as u64
    }

    /// Check if the chain contains a specific cluster.
    #[must_use] 
    pub fn contains(&self, cluster: u32) -> bool {
        self.clusters.contains(&cluster)
    }
}

// ── DeletedEntry ─────────────────────────────────────────────────────────────

/// A deleted directory entry with recovery metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedEntry {
    pub entry: DirectoryEntry,
    /// Byte offset in the image where the entry was found.
    pub offset: u64,
    /// Whether the first cluster still points to potentially valid data.
    pub data_potentially_intact: bool,
    /// Guessed original first character of the filename.
    pub guessed_first_char: Option<char>,
}

// ── FatAnalyzer ──────────────────────────────────────────────────────────────

/// Main FAT filesystem analyser.
#[derive(Debug)]
pub struct FatAnalyzer<'a> {
    image: &'a [u8],
    pub boot: FatBootSector,
    pub fat_type: FatType,
    bytes_per_cluster: u32,
    fat_region_start: usize,
    data_region_start: usize,
}

impl<'a> FatAnalyzer<'a> {
    /// Construct a new analyser from a raw disk image.
    pub fn new(image: &'a [u8]) -> Result<Self, FatError> {
        if image.len() < 512 {
            return Err(FatError::TooShort {
                need: 512,
                have: image.len(),
            });
        }
        let boot = FatBootSector::parse(image)?;
        let fat_type = boot.fat_type()?;
        let bps = boot.bytes_per_sector as usize;
        let spc = boot.sectors_per_cluster as usize;
        let bytes_per_cluster = (bps * spc) as u32;
        let fat_region_start = boot.reserved_sectors as usize * bps;
        let data_region_start = boot.first_data_sector() as usize * bps;

        Ok(Self {
            image,
            boot,
            fat_type,
            bytes_per_cluster,
            fat_region_start,
            data_region_start,
        })
    }

    /// Return the cluster size in bytes.
    #[must_use] 
    pub const fn cluster_size(&self) -> u32 {
        self.bytes_per_cluster
    }

    /// Read the FAT value for a given cluster number.
    pub fn fat_entry(&self, cluster: u32) -> Result<u32, FatError> {
        let max = self.boot.cluster_count() + 2;
        if cluster as usize >= max as usize {
            return Err(FatError::ClusterOutOfRange(cluster));
        }
        let val = match self.fat_type {
            FatType::Fat12 => {
                let offset = self.fat_region_start + (cluster as usize * 3 / 2);
                if offset + 1 >= self.image.len() {
                    return Err(FatError::ClusterOutOfRange(cluster));
                }
                let word = u16::from_le_bytes([self.image[offset], self.image[offset + 1]]);
                if cluster & 1 == 0 {
                    (word & 0x0FFF) as u32
                } else {
                    (word >> 4) as u32
                }
            }
            FatType::Fat16 => {
                let offset = self.fat_region_start + (cluster as usize * 2);
                if offset + 1 >= self.image.len() {
                    return Err(FatError::ClusterOutOfRange(cluster));
                }
                u16::from_le_bytes([self.image[offset], self.image[offset + 1]]) as u32
            }
            FatType::Fat32 => {
                let offset = self.fat_region_start + (cluster as usize * 4);
                if offset + 3 >= self.image.len() {
                    return Err(FatError::ClusterOutOfRange(cluster));
                }
                u32::from_le_bytes([
                    self.image[offset],
                    self.image[offset + 1],
                    self.image[offset + 2],
                    self.image[offset + 3],
                ]) & 0x0FFF_FFFF
            }
        };
        Ok(val)
    }

    /// Walk the FAT chain starting at `start_cluster`.
    pub fn walk_chain(&self, start_cluster: u32) -> Result<FatChain, FatError> {
        let mut clusters = Vec::new();
        let mut current = start_cluster;
        let eoc = self.fat_type.eoc_min();
        let bad = self.fat_type.bad_cluster();
        let mut seen: HashMap<u32, bool> = HashMap::new();
        let is_truncated;

        loop {
            if seen.contains_key(&current) {
                return Err(FatError::CircularChain(current));
            }
            seen.insert(current, true);
            clusters.push(current);

            let next = self.fat_entry(current)?;
            if next >= eoc {
                is_truncated = false;
                break;
            }
            if next == bad || next == 0 {
                is_truncated = true;
                break;
            }
            current = next;
        }

        Ok(FatChain {
            clusters,
            fat_type: self.fat_type,
            is_truncated,
        })
    }

    /// Convert cluster number to byte offset in image.
    ///
    /// Clusters 0 and 1 are reserved, so `cluster - 2` underflows on a malformed
    /// image — the same case [`crate::fat32_reader`] already guards and explains.
    /// The multiply and add saturate for the same reason: every operand comes
    /// from the image.
    #[must_use]
    pub const fn cluster_to_offset(&self, cluster: u32) -> usize {
        let cluster_index = (cluster as usize).saturating_sub(2);
        self.data_region_start
            .saturating_add(cluster_index.saturating_mul(self.bytes_per_cluster as usize))
    }

    /// Read raw bytes for a cluster.
    pub fn read_cluster(&self, cluster: u32) -> Result<&[u8], FatError> {
        let off = self.cluster_to_offset(cluster);
        let end = off + self.bytes_per_cluster as usize;
        if end > self.image.len() {
            return Err(FatError::ClusterOutOfRange(cluster));
        }
        Ok(&self.image[off..end])
    }

    /// Parse directory entries from a given sector offset.
    pub fn read_directory_entries(&self, sector: u32) -> Result<Vec<DirectoryEntry>, FatError> {
        let off = sector as usize * self.boot.bytes_per_sector as usize;
        let end = off + self.bytes_per_cluster as usize;
        if end > self.image.len() {
            return Err(FatError::TooShort {
                need: end,
                have: self.image.len(),
            });
        }
        let mut entries = Vec::new();
        let data = &self.image[off..end];
        for chunk in data.chunks(32) {
            if chunk.len() < 32 {
                break;
            }
            match DirectoryEntry::parse(chunk)? {
                Some(e) => entries.push(e),
                None if chunk[0] == 0 => break,
                None => {}
            }
        }
        Ok(entries)
    }

    /// Scan ALL directory entries in the root directory (FAT12/16).
    pub fn root_dir_entries(&self) -> Result<Vec<DirectoryEntry>, FatError> {
        if self.fat_type == FatType::Fat32 {
            // `root_cluster` is read from the boot sector, so it may be 0 or 1 —
            // both reserved — and `rc - 2` would underflow.
            let rc = self.boot.root_cluster.unwrap_or(2);
            return self.read_directory_entries(
                self.boot.first_data_sector().saturating_add(
                    rc.saturating_sub(2)
                        .saturating_mul(u32::from(self.boot.sectors_per_cluster)),
                ),
            );
        }
        let root_start = self.boot.root_dir_first_sector();
        let root_sectors = self.boot.root_dir_sectors();
        let bps = self.boot.bytes_per_sector as usize;
        let root_off = root_start as usize * bps;
        let root_len = root_sectors as usize * bps;
        if root_off + root_len > self.image.len() {
            return Err(FatError::TooShort {
                need: root_off + root_len,
                have: self.image.len(),
            });
        }
        let data = &self.image[root_off..root_off + root_len];
        let mut entries = Vec::new();
        for chunk in data.chunks(32) {
            if chunk.len() < 32 {
                break;
            }
            if chunk[0] == 0x00 {
                break;
            }
            if let Some(e) = DirectoryEntry::parse(chunk)? { entries.push(e) }
        }
        Ok(entries)
    }

    /// Recover deleted entries from the root directory.
    pub fn recover_deleted_entries(&self) -> Result<Vec<DeletedEntry>, FatError> {
        let bps = self.boot.bytes_per_sector as usize;
        let root_start = self.boot.root_dir_first_sector() as usize * bps;
        let root_len = if self.fat_type == FatType::Fat32 {
            self.bytes_per_cluster as usize
        } else {
            self.boot.root_dir_sectors() as usize * bps
        };
        if root_start + root_len > self.image.len() {
            return Err(FatError::TooShort {
                need: root_start + root_len,
                have: self.image.len(),
            });
        }
        let data = &self.image[root_start..root_start + root_len];
        let mut recovered = Vec::new();
        let mut offset = 0usize;
        for chunk in data.chunks(32) {
            if chunk.len() < 32 {
                break;
            }
            if chunk[0] == 0xE5 && let Ok(Some(entry)) = DirectoryEntry::parse(chunk) {
                let cluster = entry.first_cluster;
                let data_ok =
                    cluster >= 2 && (cluster as u64) < (self.boot.cluster_count() as u64) + 2;
                recovered.push(DeletedEntry {
                    entry,
                    offset: (root_start + offset) as u64,
                    data_potentially_intact: data_ok,
                    guessed_first_char: None,
                });
            }
            offset += 32;
        }
        Ok(recovered)
    }

    /// List all clusters marked as free in the first FAT.
    pub fn free_clusters(&self) -> Result<Vec<u32>, FatError> {
        let max = self.boot.cluster_count() + 2;
        let mut free = Vec::new();
        for c in 2..max {
            if self.fat_entry(c)? == 0 {
                free.push(c);
            }
        }
        Ok(free)
    }

    /// Count free clusters.
    pub fn free_cluster_count(&self) -> Result<u32, FatError> {
        Ok(self.free_clusters()?.len() as u32)
    }

    /// Volume statistics.
    #[must_use] 
    pub fn volume_stats(&self) -> VolumeStats {
        let total = self.boot.cluster_count();
        let bpc = self.bytes_per_cluster;
        VolumeStats {
            fat_type: self.fat_type,
            total_clusters: total,
            bytes_per_cluster: bpc,
            total_bytes: (total) as u64 * (bpc) as u64,
            volume_label: self.boot.volume_label.clone().unwrap_or_default(),
        }
    }
}

/// Summary statistics for a FAT volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeStats {
    pub fat_type: FatType,
    pub total_clusters: u32,
    pub bytes_per_cluster: u32,
    pub total_bytes: u64,
    pub volume_label: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Minimal boot-sector builder for tests ────────────────────────────────

    fn make_fat16_boot_sector(total_sectors: u16, fat_size: u16, spc: u8) -> Vec<u8> {
        let mut bs = vec![0u8; 512];
        // OEM name
        bs[3..11].copy_from_slice(b"MSDOS5.0");
        // bytes/sector = 512
        bs[11] = 0x00;
        bs[12] = 0x02;
        // sectors/cluster
        bs[13] = spc;
        // reserved sectors = 1
        bs[14] = 1;
        bs[15] = 0;
        // num FATs = 2
        bs[16] = 2;
        // root entry count = 512
        bs[17] = 0x00;
        bs[18] = 0x02;
        // total sectors 16
        let ts = total_sectors.to_le_bytes();
        bs[19] = ts[0];
        bs[20] = ts[1];
        // media
        bs[21] = 0xF8;
        // FAT size 16
        let fs = fat_size.to_le_bytes();
        bs[22] = fs[0];
        bs[23] = fs[1];
        // sectors per track = 63
        bs[24] = 63;
        bs[25] = 0;
        // num heads = 255
        bs[26] = 255;
        bs[27] = 0;
        // hidden / total32 = 0
        // boot sig
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    fn make_minimal_image() -> Vec<u8> {
        // 32 MB FAT16: 65536 sectors of 512 bytes
        // FAT size = 128 sectors; spc = 4; total = 65536
        let total_sectors: u16 = 65535;
        let fat_size: u16 = 128;
        let spc: u8 = 4;
        let mut img = vec![0u8; 512 * total_sectors as usize];
        let bs = make_fat16_boot_sector(total_sectors, fat_size, spc);
        img[..512].copy_from_slice(&bs);

        // Mark FAT entries 0 and 1 as media/EOC
        let fat_start = 512; // 1 reserved sector
        img[fat_start] = 0xF8;
        img[fat_start + 1] = 0xFF; // FAT[0]
        img[fat_start + 2] = 0xFF;
        img[fat_start + 3] = 0xFF; // FAT[1]
        img
    }

    fn make_fat12_boot_sector() -> Vec<u8> {
        // FAT12 has < 4085 clusters
        // Use small volume: 128 sectors, spc=1, fat_size=1 => ~120 clusters (FAT12)
        let mut bs = vec![0u8; 512];
        bs[3..11].copy_from_slice(b"FAT12TST");
        bs[11] = 0x00;
        bs[12] = 0x02; // 512 bps
        bs[13] = 1; // spc
        bs[14] = 1;
        bs[15] = 0; // reserved
        bs[16] = 2; // num_fats
        bs[17] = 0x10;
        bs[18] = 0x00; // root_count = 16
        bs[19] = 128;
        bs[20] = 0; // total16
        bs[21] = 0xF8;
        bs[22] = 1;
        bs[23] = 0; // fat_size_16
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    // ── FatType tests ────────────────────────────────────────────────────────

    #[test]
    fn test_fat_type_display() {
        assert_eq!(FatType::Fat12.to_string(), "FAT12");
        assert_eq!(FatType::Fat16.to_string(), "FAT16");
        assert_eq!(FatType::Fat32.to_string(), "FAT32");
    }

    #[test]
    fn test_fat_type_eoc_fat12() {
        assert_eq!(FatType::Fat12.eoc_min(), 0xFF8);
    }

    #[test]
    fn test_fat_type_eoc_fat16() {
        assert_eq!(FatType::Fat16.eoc_min(), 0xFFF8);
    }

    #[test]
    fn test_fat_type_eoc_fat32() {
        assert_eq!(FatType::Fat32.eoc_min(), 0x0FFF_FFF8);
    }

    #[test]
    fn test_fat_type_bad_cluster() {
        assert_eq!(FatType::Fat12.bad_cluster(), 0xFF7);
        assert_eq!(FatType::Fat16.bad_cluster(), 0xFFF7);
        assert_eq!(FatType::Fat32.bad_cluster(), 0x0FFF_FFF7);
    }

    #[test]
    fn test_fat_type_free_cluster() {
        assert_eq!(FatType::Fat12.free_cluster(), 0);
    }

    // ── FatTimestamp tests ───────────────────────────────────────────────────

    #[test]
    fn test_timestamp_decode_encode_roundtrip() {
        let ts = FatTimestamp {
            year: 2024,
            month: 6,
            day: 15,
            hour: 10,
            minute: 30,
            second: 20,
        };
        let (date, time) = ts.encode();
        let decoded = FatTimestamp::decode(date, time);
        assert_eq!(decoded.year, 2024);
        assert_eq!(decoded.month, 6);
        assert_eq!(decoded.day, 15);
        assert_eq!(decoded.hour, 10);
        assert_eq!(decoded.minute, 30);
        assert_eq!(decoded.second, 20);
    }

    #[test]
    fn test_timestamp_display() {
        let ts = FatTimestamp {
            year: 2024,
            month: 1,
            day: 5,
            hour: 8,
            minute: 3,
            second: 0,
        };
        assert_eq!(ts.to_string(), "2024-01-05 08:03:00");
    }

    #[test]
    fn test_timestamp_epoch_1980() {
        let ts = FatTimestamp::decode(0x0000, 0x0000);
        assert_eq!(ts.year, 1980);
        assert_eq!(ts.month, 0);
        assert_eq!(ts.day, 0);
    }

    #[test]
    fn test_timestamp_max_values() {
        // year=2107 (127+1980), month=15, day=31
        let ts = FatTimestamp::decode(0xFFFF, 0xFFFF);
        assert_eq!(ts.year, 2107);
    }

    // ── FatBootSector tests ──────────────────────────────────────────────────

    #[test]
    fn test_boot_sector_parse_fat16() {
        let bs = make_fat16_boot_sector(65535, 128, 4);
        let boot = FatBootSector::parse(&bs).unwrap();
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 4);
        assert_eq!(boot.num_fats, 2);
        assert_eq!(boot.fat_size_16, 128);
    }

    #[test]
    fn test_boot_sector_bad_signature() {
        let mut bs = make_fat16_boot_sector(65535, 128, 4);
        bs[510] = 0;
        bs[511] = 0;
        let err = FatBootSector::parse(&bs).unwrap_err();
        assert!(matches!(err, FatError::BadSignature { .. }));
    }

    #[test]
    fn test_boot_sector_too_short() {
        let err = FatBootSector::parse(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, FatError::TooShort { .. }));
    }

    #[test]
    fn test_boot_sector_bad_bps() {
        let mut bs = make_fat16_boot_sector(65535, 128, 4);
        bs[11] = 0x01;
        bs[12] = 0x00; // 1 byte/sector
        let err = FatBootSector::parse(&bs).unwrap_err();
        assert!(matches!(err, FatError::BadBytesPerSector(1)));
    }

    #[test]
    fn test_boot_sector_bad_spc() {
        let mut bs = make_fat16_boot_sector(65535, 128, 4);
        bs[13] = 3; // not a power of 2
        let err = FatBootSector::parse(&bs).unwrap_err();
        assert!(matches!(err, FatError::BadSectorsPerCluster(3)));
    }

    #[test]
    fn test_boot_sector_fat12_type() {
        let bs = make_fat12_boot_sector();
        let boot = FatBootSector::parse(&bs).unwrap();
        let ft = boot.fat_type().unwrap();
        assert_eq!(ft, FatType::Fat12);
    }

    #[test]
    fn test_boot_sector_total_sectors() {
        let bs = make_fat16_boot_sector(65535, 128, 4);
        let boot = FatBootSector::parse(&bs).unwrap();
        assert_eq!(boot.total_sectors(), 65535);
    }

    #[test]
    fn test_boot_sector_fat_size() {
        let bs = make_fat16_boot_sector(65535, 128, 4);
        let boot = FatBootSector::parse(&bs).unwrap();
        assert_eq!(boot.fat_size(), 128);
    }

    // ── DirectoryEntry tests ─────────────────────────────────────────────────

    fn make_dir_entry(
        name: &[u8; 8],
        ext: &[u8; 3],
        attrs: u8,
        cluster: u16,
        size: u32,
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 32];
        raw[..8].copy_from_slice(name);
        raw[8..11].copy_from_slice(ext);
        raw[11] = attrs;
        // creation time/date: 2024-06-15 10:30:20
        let ts = FatTimestamp {
            year: 2024,
            month: 6,
            day: 15,
            hour: 10,
            minute: 30,
            second: 20,
        };
        let (date, time) = ts.encode();
        raw[14] = time as u8;
        raw[15] = (time >> 8) as u8;
        raw[16] = date as u8;
        raw[17] = (date >> 8) as u8;
        // cluster lo
        raw[26] = cluster as u8;
        raw[27] = (cluster >> 8) as u8;
        // size
        raw[28..32].copy_from_slice(&size.to_le_bytes());
        raw
    }

    #[test]
    fn test_dir_entry_parse_file() {
        let raw = make_dir_entry(b"HELLO   ", b"TXT", 0x20, 100, 512);
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert_eq!(entry.name.trim(), "HELLO");
        assert_eq!(entry.ext.trim(), "TXT");
        assert_eq!(entry.size, 512);
        assert_eq!(entry.first_cluster, 100);
        assert!(!entry.is_deleted);
    }

    #[test]
    fn test_dir_entry_full_name() {
        let raw = make_dir_entry(b"README  ", b"TXT", 0x20, 5, 100);
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert!(entry.full_name().contains("README"));
        assert!(entry.full_name().contains("TXT"));
    }

    #[test]
    fn test_dir_entry_deleted() {
        let mut raw = make_dir_entry(b"DELETED ", b"TXT", 0x20, 10, 50);
        raw[0] = 0xE5;
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert!(entry.is_deleted);
    }

    #[test]
    fn test_dir_entry_end_marker() {
        let raw = vec![0u8; 32];
        let result = DirectoryEntry::parse(&raw).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_dir_entry_directory_flag() {
        let raw = make_dir_entry(b"MYDIR   ", b"   ", 0x10, 20, 0);
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert!(entry.is_directory());
    }

    #[test]
    fn test_dir_entry_hidden_flag() {
        let raw = make_dir_entry(b"HIDDEN  ", b"SYS", 0x02, 3, 100);
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert!(entry.is_hidden());
    }

    #[test]
    fn test_dir_entry_readonly_flag() {
        let raw = make_dir_entry(b"READONLY", b"TXT", 0x01, 3, 10);
        let entry = DirectoryEntry::parse(&raw).unwrap().unwrap();
        assert!(entry.is_read_only());
    }

    // ── FatAnalyzer tests ────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_new() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        assert_eq!(fa.fat_type, FatType::Fat16);
    }

    #[test]
    fn test_analyzer_too_short() {
        let err = FatAnalyzer::new(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, FatError::TooShort { .. }));
    }

    #[test]
    fn test_analyzer_cluster_size() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        assert_eq!(fa.cluster_size(), 512 * 4); // 4 sectors/cluster
    }

    #[test]
    fn test_fat_entry_free() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        // Cluster 10 should be free (0) in our minimal image
        let val = fa.fat_entry(10).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_volume_stats() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        let stats = fa.volume_stats();
        assert_eq!(stats.fat_type, FatType::Fat16);
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_fat_chain_walk_eoc() {
        // Set up a single-cluster chain for cluster 2
        let mut img = make_minimal_image();
        let fat_start = 512; // 1 reserved sector * 512
        // FAT16: cluster 2 at offset fat_start + 4 (each entry 2 bytes)
        img[fat_start + 4] = 0xFF;
        img[fat_start + 5] = 0xFF; // EOC
        let fa = FatAnalyzer::new(&img).unwrap();
        let chain = fa.walk_chain(2).unwrap();
        assert_eq!(chain.clusters.len(), 1);
        assert!(!chain.is_truncated);
    }

    #[test]
    fn test_fat_chain_two_clusters() {
        let mut img = make_minimal_image();
        let fat_start = 512;
        // Cluster 2 -> 3, cluster 3 -> EOC (FAT16)
        img[fat_start + 4] = 0x03;
        img[fat_start + 5] = 0x00; // cluster 2 -> 3
        img[fat_start + 6] = 0xFF;
        img[fat_start + 7] = 0xFF; // cluster 3 -> EOC
        let fa = FatAnalyzer::new(&img).unwrap();
        let chain = fa.walk_chain(2).unwrap();
        assert_eq!(chain.clusters, vec![2, 3]);
    }

    #[test]
    fn test_fat_chain_contains() {
        let chain = FatChain {
            clusters: vec![2, 3, 5],
            fat_type: FatType::Fat16,
            is_truncated: false,
        };
        assert!(chain.contains(3));
        assert!(!chain.contains(4));
    }

    #[test]
    fn test_fat_chain_bytes() {
        let chain = FatChain {
            clusters: vec![2, 3],
            fat_type: FatType::Fat16,
            is_truncated: false,
        };
        assert_eq!(chain.chain_bytes(2048), 4096);
    }

    #[test]
    fn test_recover_deleted_entries_empty() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        // no deleted entries in a fresh image
        let del = fa.recover_deleted_entries().unwrap();
        assert!(del.is_empty());
    }

    #[test]
    fn test_free_clusters() {
        let img = make_minimal_image();
        let fa = FatAnalyzer::new(&img).unwrap();
        let free = fa.free_clusters().unwrap();
        assert!(!free.is_empty());
    }
}
