//! Deep FAT32 analysis: cluster chains, FAT traversal, directory trees,
//! deleted file scanning, slack space analysis, and filesystem timelines.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Constants ────────────────────────────────────────────────────────────────

/// FAT32 end-of-chain marker.
pub const FAT32_EOC: u32 = 0x0FFF_FFFF;
/// FAT32 bad cluster marker.
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;
/// FAT32 free cluster marker.
pub const FAT32_FREE: u32 = 0x0000_0000;

// ─── Fat32BootSector ──────────────────────────────────────────────────────────

/// Parsed FAT32 boot sector parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fat32BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub total_sectors_32: u32,
    pub fat_size_32: u32,
    pub root_cluster: u32,
    pub volume_id: u32,
    pub volume_label: String,
    pub fs_type: String,
}

impl Fat32BootSector {
    /// Parse from a 512-byte boot sector.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 90 {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
        if bytes_per_sector == 0 {
            return None;
        }
        let sectors_per_cluster = data[13];
        let reserved_sectors = u16::from_le_bytes([data[14], data[15]]);
        let num_fats = data[16];
        let total_sectors_32 = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let fat_size_32 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let root_cluster = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let volume_id = u32::from_le_bytes([data[67], data[68], data[69], data[70]]);
        let volume_label = String::from_utf8_lossy(&data[71..82]).trim().to_string();
        let fs_type = String::from_utf8_lossy(&data[82..90]).trim().to_string();

        Some(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors_32,
            fat_size_32,
            root_cluster,
            volume_id,
            volume_label,
            fs_type,
        })
    }

    /// Bytes per cluster.
    #[must_use]
    pub const fn bytes_per_cluster(&self) -> u32 {
        (self.bytes_per_sector) as u32 * (self.sectors_per_cluster) as u32
    }

    /// Size of the FAT region in sectors.
    ///
    /// Every field here comes from the boot sector of the image being examined,
    /// so `num_fats * fat_size_32` can exceed `u32`; the arithmetic saturates
    /// rather than wrapping into a small, plausible-looking offset.
    fn fat_region_sectors(&self) -> u64 {
        u64::from(self.num_fats)
            .saturating_mul(u64::from(self.fat_size_32))
            .saturating_add(u64::from(self.reserved_sectors))
    }

    /// Offset of the first data sector in bytes.
    #[must_use]
    pub fn data_offset(&self) -> u64 {
        self.fat_region_sectors()
            .saturating_mul(u64::from(self.bytes_per_sector))
    }

    /// Cluster offset within the image.
    ///
    /// Cluster 2 is the first data cluster; 0 and 1 are reserved and appear in a
    /// malformed image, so the `- 2` saturates — as it already does in
    /// [`crate::fat32_reader`], whose comment records the same reasoning. Left
    /// bare it underflowed: a panic in debug, and in release a colossal offset
    /// that then indexed the image.
    #[must_use]
    pub fn cluster_offset(&self, cluster: u32) -> u64 {
        let data_start = self.fat_region_sectors();
        let cluster_index = u64::from(cluster).saturating_sub(2);
        data_start
            .saturating_add(cluster_index.saturating_mul(u64::from(self.sectors_per_cluster)))
            .saturating_mul(u64::from(self.bytes_per_sector))
    }
}

// ─── FileAllocationTable ──────────────────────────────────────────────────────

/// An in-memory representation of the FAT32 file allocation table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAllocationTable {
    entries: Vec<u32>,
}

impl FileAllocationTable {
    /// Create from raw FAT bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let entries = data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) & 0x0FFF_FFFF)
            .collect();
        Self { entries }
    }

    /// Get the FAT value for a cluster.
    #[must_use]
    pub fn get(&self, cluster: u32) -> Option<u32> {
        self.entries.get(cluster as usize).copied()
    }

    /// Returns `true` if the cluster is free.
    #[must_use]
    pub fn is_free(&self, cluster: u32) -> bool {
        self.get(cluster).is_some_and(|v| v == FAT32_FREE)
    }

    /// Returns `true` if the cluster is end-of-chain.
    #[must_use]
    pub fn is_eoc(&self, cluster: u32) -> bool {
        self.get(cluster).is_some_and(|v| v >= 0x0FFF_FFF8)
    }

    /// Returns `true` if the cluster is marked bad.
    #[must_use]
    pub fn is_bad(&self, cluster: u32) -> bool {
        self.get(cluster).is_some_and(|v| v == FAT32_BAD)
    }

    /// Total entry count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count free clusters.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.entries.iter().filter(|&&v| v == FAT32_FREE).count()
    }

    /// Count allocated (non-free, non-bad) clusters.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|&&v| v != FAT32_FREE && v != FAT32_BAD)
            .count()
    }
}

// ─── ClusterChain ─────────────────────────────────────────────────────────────

/// A chain of clusters belonging to a file or directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterChain {
    pub first_cluster: u32,
    pub clusters: Vec<u32>,
}

impl ClusterChain {
    /// Follow a cluster chain from a starting cluster using the FAT.
    #[must_use]
    pub fn follow(fat: &FileAllocationTable, start: u32) -> Self {
        let mut clusters = Vec::new();
        let mut current = start;
        let mut visited = std::collections::HashSet::new();
        loop {
            if !(2..0x0FFF_FFF7).contains(&current) {
                break;
            }
            if !visited.insert(current) {
                break;
            } // break cycle
            // Don't include free or bad clusters in the chain.
            match fat.get(current) {
                Some(next) if next == FAT32_FREE || next == FAT32_BAD => break,
                Some(next) if next >= 0x0FFF_FFF8 => {
                    clusters.push(current);
                    break;
                } // EOC
                Some(next) => {
                    clusters.push(current);
                    current = next;
                }
                None => break,
            }
        }
        Self {
            first_cluster: start,
            clusters,
        }
    }

    /// Number of clusters in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.clusters.len()
    }

    /// Returns `true` if the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }

    /// Compute the data size given bytes-per-cluster.
    #[must_use]
    pub const fn data_size(&self, bytes_per_cluster: u32) -> u64 {
        self.clusters.len() as u64 * (bytes_per_cluster) as u64
    }
}

// ─── DirectoryEntry ───────────────────────────────────────────────────────────

/// A FAT32 directory entry (parsed 32-byte structure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub extension: String,
    pub attributes: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    pub created_ms: u64,
    pub modified_ms: u64,
    pub accessed_ms: u64,
    pub is_deleted: bool,
    pub is_directory: bool,
}

impl DirectoryEntry {
    /// Parse a 32-byte directory entry.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        if data[0] == 0x00 {
            return None;
        } // end-of-directory
        let is_deleted = data[0] == 0xE5;
        // Long-name entries have attr 0x0F — skip them.
        if data[11] == 0x0F {
            return None;
        }

        let raw_name = &data[0..8];
        let raw_ext = &data[8..11];

        let name = if is_deleted {
            let mut n = String::from_utf8_lossy(raw_name).trim_end().to_string();
            n.remove(0); // first byte was 0xE5
            format!("?{n}")
        } else {
            String::from_utf8_lossy(raw_name).trim_end().to_string()
        };
        let extension = String::from_utf8_lossy(raw_ext).trim_end().to_string();

        let attributes = data[11];
        let is_directory = attributes & 0x10 != 0;

        let hi_cluster = u16::from_le_bytes([data[20], data[21]]) as u32;
        let lo_cluster = u16::from_le_bytes([data[26], data[27]]) as u32;
        let first_cluster = (hi_cluster << 16) | lo_cluster;
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        // Simple timestamp parsing (FAT date/time format)
        let created_time = u16::from_le_bytes([data[14], data[15]]);
        let created_date = u16::from_le_bytes([data[16], data[17]]);
        let modified_time = u16::from_le_bytes([data[22], data[23]]);
        let modified_date = u16::from_le_bytes([data[24], data[25]]);
        let accessed_date = u16::from_le_bytes([data[18], data[19]]);

        Some(Self {
            name,
            extension,
            attributes,
            first_cluster,
            file_size,
            created_ms: fat_datetime_to_ms(created_date, created_time),
            modified_ms: fat_datetime_to_ms(modified_date, modified_time),
            accessed_ms: fat_datetime_to_ms(accessed_date, 0),
            is_deleted,
            is_directory,
        })
    }

    /// Full name including extension.
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.extension.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.name, self.extension)
        }
    }

    /// Returns `true` if the entry is a normal (non-deleted) file.
    #[must_use]
    pub const fn is_regular_file(&self) -> bool {
        !self.is_deleted && !self.is_directory && self.file_size > 0
    }
}

// ─── DirectoryTree ────────────────────────────────────────────────────────────

/// A node in the FAT32 directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirNode {
    pub path: String,
    pub cluster: u32,
    pub entries: Vec<DirectoryEntry>,
    pub children: Vec<Self>,
}

impl DirNode {
    /// Create a new directory node.
    #[must_use]
    pub fn new(path: impl Into<String>, cluster: u32, entries: Vec<DirectoryEntry>) -> Self {
        Self {
            path: path.into(),
            cluster,
            entries,
            children: vec![],
        }
    }

    /// Total files (including subdirectories recursively).
    #[must_use]
    pub fn total_files(&self) -> usize {
        let own: usize = self.entries.iter().filter(|e| e.is_regular_file()).count();
        own + self.children.iter().map(DirNode::total_files).sum::<usize>()
    }

    /// Total deleted files in this subtree.
    #[must_use]
    pub fn deleted_count(&self) -> usize {
        let own: usize = self.entries.iter().filter(|e| e.is_deleted).count();
        own + self
            .children
            .iter()
            .map(DirNode::deleted_count)
            .sum::<usize>()
    }
}

/// Represents the full FAT32 directory tree.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectoryTree {
    pub root: Option<DirNode>,
}

impl DirectoryTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total files in the tree.
    #[must_use]
    pub fn total_files(&self) -> usize {
        self.root.as_ref().map_or(0, DirNode::total_files)
    }

    /// Total deleted files in the tree.
    #[must_use]
    pub fn total_deleted(&self) -> usize {
        self.root.as_ref().map_or(0, DirNode::deleted_count)
    }
}

// ─── DeletedFileScanner ───────────────────────────────────────────────────────

/// Scans for deleted file entries in directory regions.
#[derive(Debug, Clone, Default)]
pub struct DeletedFileScanner;

/// A recovered deleted file record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFile {
    pub original_name: String,
    pub extension: String,
    pub first_cluster: u32,
    pub file_size: u32,
    pub deleted_at_ms: u64,
    pub recovery_confidence: u8,
}

impl DeletedFileScanner {
    /// Create a new scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan a raw directory region (multiple 32-byte entries) for deleted files.
    #[must_use]
    pub fn scan_region(&self, data: &[u8]) -> Vec<DeletedFile> {
        let mut found = Vec::new();
        for chunk in data.chunks_exact(32) {
            if chunk[0] != 0xE5 {
                continue;
            } // only deleted entries
            if chunk[11] == 0x0F {
                continue;
            } // skip LFN
            if let Some(entry) = DirectoryEntry::parse(chunk) && entry.is_deleted && entry.first_cluster >= 2 {
                let confidence = if entry.file_size > 0 { 80 } else { 40 };
                found.push(DeletedFile {
                    original_name: entry.name.clone(),
                    extension: entry.extension.clone(),
                    first_cluster: entry.first_cluster,
                    file_size: entry.file_size,
                    deleted_at_ms: entry.modified_ms,
                    recovery_confidence: confidence,
                });
            }
        }
        found
    }

    /// Scan multiple directory entries and return all recoverable files.
    #[must_use]
    pub fn scan_entries(&self, entries: &[DirectoryEntry]) -> Vec<DeletedFile> {
        entries
            .iter()
            .filter(|e| e.is_deleted && e.first_cluster >= 2)
            .map(|e| DeletedFile {
                original_name: e.name.clone(),
                extension: e.extension.clone(),
                first_cluster: e.first_cluster,
                file_size: e.file_size,
                deleted_at_ms: e.modified_ms,
                recovery_confidence: if e.file_size > 0 { 80 } else { 40 },
            })
            .collect()
    }
}

// ─── SlackSpace ───────────────────────────────────────────────────────────────

/// Represents slack space at the end of a file's last cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSpace {
    /// Cluster number of the last cluster.
    pub cluster: u32,
    /// Offset within the cluster where the file ends and slack begins.
    pub slack_start: u32,
    /// Number of slack bytes.
    pub slack_bytes: u32,
    /// Raw slack data (may be empty if not captured).
    pub data: Vec<u8>,
    /// Whether any interesting strings were found in the slack.
    pub contains_artifacts: bool,
}

impl SlackSpace {
    /// Compute the slack space for a file entry.
    #[must_use]
    pub const fn compute(entry: &DirectoryEntry, bytes_per_cluster: u32) -> Self {
        let file_size = entry.file_size;
        let last_cluster_usage = file_size % bytes_per_cluster;
        let slack_bytes = if last_cluster_usage == 0 {
            0
        } else {
            bytes_per_cluster - last_cluster_usage
        };
        Self {
            cluster: entry.first_cluster,
            slack_start: last_cluster_usage,
            slack_bytes,
            data: vec![],
            contains_artifacts: false,
        }
    }

    /// Scan slack data for interesting strings.
    pub fn analyze(&mut self) {
        let has_artifacts = self.data.iter().any(|&b| b.is_ascii_graphic()) && self.data.len() >= 4;
        self.contains_artifacts = has_artifacts;
    }

    /// Returns `true` if there is slack space.
    #[must_use]
    pub const fn has_slack(&self) -> bool {
        self.slack_bytes > 0
    }
}

// ─── FsTimeline ───────────────────────────────────────────────────────────────

/// A timeline entry derived from FAT32 directory entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsTimelineEntry {
    pub timestamp_ms: u64,
    pub event: FsEvent,
    pub path: String,
    pub cluster: u32,
    pub size: u32,
}

/// The type of filesystem event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEvent {
    Created,
    Modified,
    Accessed,
    Deleted,
}

impl fmt::Display for FsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Modified => write!(f, "modified"),
            Self::Accessed => write!(f, "accessed"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

/// Reconstructs a filesystem activity timeline from directory entries.
#[derive(Debug, Clone, Default)]
pub struct FsTimeline {
    pub entries: Vec<FsTimelineEntry>,
}

impl FsTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a timeline entry.
    pub fn add(&mut self, entry: FsTimelineEntry) {
        self.entries.push(entry);
    }

    /// Build a timeline from a list of directory entries.
    #[must_use]
    pub fn from_entries(dir_entries: &[DirectoryEntry], base_path: &str) -> Self {
        let mut tl = Self::new();
        tl.entries.reserve(dir_entries.len() * 2);
        for e in dir_entries {
            let path = format!("{}/{}", base_path, e.full_name());
            if e.created_ms > 0 {
                tl.add(FsTimelineEntry {
                    timestamp_ms: e.created_ms,
                    event: FsEvent::Created,
                    path: path.clone(),
                    cluster: e.first_cluster,
                    size: e.file_size,
                });
            }
            if e.modified_ms > 0 && e.modified_ms != e.created_ms {
                tl.add(FsTimelineEntry {
                    timestamp_ms: e.modified_ms,
                    event: FsEvent::Modified,
                    path: path.clone(),
                    cluster: e.first_cluster,
                    size: e.file_size,
                });
            }
            if e.accessed_ms > 0 {
                tl.add(FsTimelineEntry {
                    timestamp_ms: e.accessed_ms,
                    event: FsEvent::Accessed,
                    path: path.clone(),
                    cluster: e.first_cluster,
                    size: e.file_size,
                });
            }
            if e.is_deleted {
                tl.add(FsTimelineEntry {
                    timestamp_ms: e.modified_ms,
                    event: FsEvent::Deleted,
                    path,
                    cluster: e.first_cluster,
                    size: e.file_size,
                });
            }
        }
        tl.entries.sort_by_key(|e| e.timestamp_ms);
        tl
    }

    /// Filter entries within a timestamp range.
    #[must_use]
    pub fn in_range(&self, start_ms: u64, end_ms: u64) -> Vec<&FsTimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp_ms >= start_ms && e.timestamp_ms <= end_ms)
            .collect()
    }

    /// Return only deleted events.
    #[must_use]
    pub fn deleted_events(&self) -> Vec<&FsTimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event == FsEvent::Deleted)
            .collect()
    }

    /// Total entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Fat32Deep ────────────────────────────────────────────────────────────────

/// Deep FAT32 analysis engine.
pub struct Fat32Deep {
    pub boot_sector: Fat32BootSector,
    pub fat: FileAllocationTable,
    pub directory_tree: DirectoryTree,
    pub slack_spaces: Vec<SlackSpace>,
    pub deleted_files: Vec<DeletedFile>,
    pub timeline: FsTimeline,
}

impl Fat32Deep {
    /// Build a mock analysis object for testing.
    #[must_use]
    pub fn mock() -> Self {
        // Mock boot sector
        let boot = Fat32BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            reserved_sectors: 32,
            num_fats: 2,
            total_sectors_32: 1_048_576,
            fat_size_32: 4096,
            root_cluster: 2,
            volume_id: 0xDEAD_BEEF,
            volume_label: "TESTDISK   ".to_string(),
            fs_type: "FAT32   ".to_string(),
        };

        // Mock FAT with a simple chain: 2->3->4->EOC, and cluster 5 free
        let mut fat_entries = vec![0u32; 10];
        fat_entries[2] = 3;
        fat_entries[3] = 4;
        fat_entries[4] = FAT32_EOC;
        fat_entries[5] = FAT32_FREE;
        fat_entries[6] = FAT32_BAD;
        let fat = FileAllocationTable {
            entries: fat_entries,
        };

        // Mock directory entries
        let entries = vec![
            DirectoryEntry {
                name: "TESTFILE".to_string(),
                extension: "TXT".to_string(),
                attributes: 0x20,
                first_cluster: 2,
                file_size: 3800,
                created_ms: 1_700_000_000_000,
                modified_ms: 1_700_000_100_000,
                accessed_ms: 1_700_000_200_000,
                is_deleted: false,
                is_directory: false,
            },
            DirectoryEntry {
                name: "?ELETED ".to_string(),
                extension: "EXE".to_string(),
                attributes: 0x20,
                first_cluster: 5,
                file_size: 65536,
                created_ms: 1_699_000_000_000,
                modified_ms: 1_699_000_100_000,
                accessed_ms: 0,
                is_deleted: true,
                is_directory: false,
            },
        ];

        let scanner = DeletedFileScanner::new();
        let deleted_files = scanner.scan_entries(&entries);

        let root = DirNode::new("/", 2, entries.clone());
        let directory_tree = DirectoryTree { root: Some(root) };

        let slack_spaces = entries
            .iter()
            .map(|e| SlackSpace::compute(e, boot.bytes_per_cluster()))
            .collect();

        let timeline = FsTimeline::from_entries(&entries, "");

        Self {
            boot_sector: boot,
            fat,
            directory_tree,
            slack_spaces,
            deleted_files,
            timeline,
        }
    }

    /// Compute free space in bytes.
    #[must_use]
    pub fn free_space_bytes(&self) -> u64 {
        self.fat.free_count() as u64 * (self.boot_sector.bytes_per_cluster() as u64)
    }

    /// Follow a cluster chain starting at `start`.
    #[must_use]
    pub fn follow_chain(&self, start: u32) -> ClusterChain {
        ClusterChain::follow(&self.fat, start)
    }

    /// Return a summary of the filesystem.
    #[must_use]
    pub fn summary(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "volume_label".into(),
            self.boot_sector.volume_label.trim().to_string(),
        );
        m.insert(
            "bytes_per_cluster".into(),
            self.boot_sector.bytes_per_cluster().to_string(),
        );
        m.insert("free_clusters".into(), self.fat.free_count().to_string());
        m.insert(
            "allocated_clusters".into(),
            self.fat.allocated_count().to_string(),
        );
        m.insert("deleted_files".into(), self.deleted_files.len().to_string());
        m.insert("timeline_events".into(), self.timeline.len().to_string());
        m
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Convert FAT16/32 date+time to milliseconds since Unix epoch (approx.).
const fn fat_datetime_to_ms(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    let year = 1980 + ((date >> 9) as u64 & 0x7F);
    let month = (date >> 5) as u64 & 0x0F;
    let day = (date & 0x1F) as u64;
    let hour = (time >> 11) as u64 & 0x1F;
    let min = (time >> 5) as u64 & 0x3F;
    let sec = (time & 0x1F) as u64 * 2;
    // Approximate: days since epoch
    let days_per_year = 365u64;
    let epoch_year = 1970u64;
    let years = year.saturating_sub(epoch_year);
    let days = years * days_per_year + (month.saturating_sub(1)) * 30 + day;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    secs * 1000
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> Fat32Deep {
        Fat32Deep::mock()
    }

    // Fat32BootSector
    #[test]
    fn test_boot_bytes_per_cluster() {
        let m = mock();
        assert_eq!(m.boot_sector.bytes_per_cluster(), 512 * 8);
    }
    #[test]
    fn test_boot_data_offset_positive() {
        let m = mock();
        assert!(m.boot_sector.data_offset() > 0);
    }
    #[test]
    fn test_boot_cluster_offset() {
        let m = mock();
        let off = m.boot_sector.cluster_offset(2);
        assert!(off >= m.boot_sector.data_offset());
    }

    // FileAllocationTable
    #[test]
    fn test_fat_get_entry() {
        let m = mock();
        assert_eq!(m.fat.get(2), Some(3));
        assert_eq!(m.fat.get(3), Some(4));
    }
    #[test]
    fn test_fat_is_free() {
        let m = mock();
        assert!(m.fat.is_free(5));
    }
    #[test]
    fn test_fat_is_eoc() {
        let m = mock();
        assert!(m.fat.is_eoc(4));
    }
    #[test]
    fn test_fat_is_bad() {
        let m = mock();
        assert!(m.fat.is_bad(6));
    }
    #[test]
    fn test_fat_free_count() {
        let m = mock();
        assert!(m.fat.free_count() >= 1);
    }
    #[test]
    fn test_fat_allocated_count() {
        let m = mock();
        assert!(m.fat.allocated_count() >= 2);
    }
    #[test]
    fn test_fat_len() {
        let m = mock();
        assert_eq!(m.fat.len(), 10);
    }

    // ClusterChain
    #[test]
    fn test_chain_follow() {
        let m = mock();
        let chain = ClusterChain::follow(&m.fat, 2);
        assert_eq!(chain.clusters, vec![2, 3, 4]);
    }
    #[test]
    fn test_chain_len() {
        let m = mock();
        let chain = ClusterChain::follow(&m.fat, 2);
        assert_eq!(chain.len(), 3);
    }
    #[test]
    fn test_chain_data_size() {
        let m = mock();
        let chain = ClusterChain::follow(&m.fat, 2);
        assert_eq!(chain.data_size(4096), 3 * 4096);
    }
    #[test]
    fn test_chain_free_cluster_empty() {
        let m = mock();
        let chain = ClusterChain::follow(&m.fat, 5);
        assert!(chain.is_empty());
    }

    // DirectoryEntry
    #[test]
    fn test_dir_entry_full_name_with_ext() {
        let e = DirectoryEntry {
            name: "README".to_string(),
            extension: "TXT".to_string(),
            attributes: 0x20,
            first_cluster: 2,
            file_size: 100,
            created_ms: 0,
            modified_ms: 0,
            accessed_ms: 0,
            is_deleted: false,
            is_directory: false,
        };
        assert_eq!(e.full_name(), "README.TXT");
    }
    #[test]
    fn test_dir_entry_full_name_no_ext() {
        let e = DirectoryEntry {
            name: "NOEXT".to_string(),
            extension: "".to_string(),
            attributes: 0x10,
            first_cluster: 2,
            file_size: 0,
            created_ms: 0,
            modified_ms: 0,
            accessed_ms: 0,
            is_deleted: false,
            is_directory: true,
        };
        assert_eq!(e.full_name(), "NOEXT");
    }
    #[test]
    fn test_dir_entry_is_regular_file() {
        let m = mock();
        let entries = &m.directory_tree.root.as_ref().unwrap().entries;
        assert!(entries[0].is_regular_file());
    }
    #[test]
    fn test_dir_entry_deleted_not_regular() {
        let m = mock();
        let entries = &m.directory_tree.root.as_ref().unwrap().entries;
        assert!(!entries[1].is_regular_file());
    }

    // DirectoryTree
    #[test]
    fn test_tree_total_files() {
        let m = mock();
        assert_eq!(m.directory_tree.total_files(), 1);
    }
    #[test]
    fn test_tree_total_deleted() {
        let m = mock();
        assert_eq!(m.directory_tree.total_deleted(), 1);
    }

    // DeletedFileScanner
    #[test]
    fn test_scanner_finds_deleted() {
        assert_eq!(Fat32Deep::mock().deleted_files.len(), 1);
    }
    #[test]
    fn test_scanner_confidence() {
        let d = &Fat32Deep::mock().deleted_files[0];
        assert!(d.recovery_confidence > 0);
    }

    // SlackSpace
    #[test]
    fn test_slack_compute_has_slack() {
        let fat = Fat32Deep::mock();
        let entry = &fat
            .directory_tree
            .root
            .as_ref()
            .unwrap()
            .entries[0];
        let slack = SlackSpace::compute(entry, 4096);
        assert!(slack.has_slack());
    }
    #[test]
    fn test_slack_no_slack_when_aligned() {
        let entry = DirectoryEntry {
            name: "FULL".to_string(),
            extension: "".to_string(),
            attributes: 0x20,
            first_cluster: 2,
            file_size: 4096,
            created_ms: 0,
            modified_ms: 0,
            accessed_ms: 0,
            is_deleted: false,
            is_directory: false,
        };
        let slack = SlackSpace::compute(&entry, 4096);
        assert!(!slack.has_slack());
    }
    #[test]
    fn test_slack_analyze() {
        let mut slack = SlackSpace {
            cluster: 2,
            slack_start: 100,
            slack_bytes: 412,
            data: b"interesting strings here".to_vec(),
            contains_artifacts: false,
        };
        slack.analyze();
        assert!(slack.contains_artifacts);
    }

    // FsTimeline
    #[test]
    fn test_timeline_has_entries() {
        assert!(!Fat32Deep::mock().timeline.is_empty());
    }
    #[test]
    fn test_timeline_deleted_events() {
        let m = mock();
        assert!(!m.timeline.deleted_events().is_empty());
    }
    #[test]
    fn test_timeline_in_range() {
        let m = mock();
        let range = m.timeline.in_range(0, u64::MAX);
        assert_eq!(range.len(), m.timeline.len());
    }
    #[test]
    fn test_timeline_sorted() {
        let m = mock();
        let ts: Vec<u64> = m.timeline.entries.iter().map(|e| e.timestamp_ms).collect();
        let mut sorted = ts.clone();
        sorted.sort_unstable();
        assert_eq!(ts, sorted);
    }
    #[test]
    fn test_fs_event_display() {
        assert_eq!(FsEvent::Deleted.to_string(), "deleted");
    }

    // Fat32Deep
    #[test]
    fn test_free_space_nonzero() {
        assert!(mock().free_space_bytes() > 0);
    }
    #[test]
    fn test_follow_chain_2() {
        let m = mock();
        let chain = m.follow_chain(2);
        assert_eq!(chain.clusters, vec![2, 3, 4]);
    }
    #[test]
    fn test_summary_keys() {
        let summary = mock().summary();
        assert!(summary.contains_key("volume_label"));
        assert!(summary.contains_key("free_clusters"));
    }
    #[test]
    fn test_fat_from_bytes_roundtrip() {
        let data: Vec<u8> = (0u32..8).flat_map(|i| i.to_le_bytes()).collect();
        let fat = FileAllocationTable::from_bytes(&data);
        assert_eq!(fat.len(), 8);
    }
    #[test]
    fn test_fat_datetime_zero() {
        assert_eq!(fat_datetime_to_ms(0, 0), 0);
    }
    #[test]
    fn test_fat_datetime_nonzero() {
        // date = 0 → 1980, encoded as 0x0021 (bit 5-8 = 0, bit 0-4 = 1, year=0)
        let date: u16 = (10 << 9) | (6 << 5) | 15; // 1990-06-15
        let time: u16 = (12 << 11) | (30 << 5) | 10; // 12:30:20
        assert!(fat_datetime_to_ms(date, time) > 0);
    }
}
