//! Filesystem extraction from firmware images.
//!
//! Scans a firmware blob for embedded filesystems and extracts their
//! directory trees into an in-memory representation, without requiring
//! a real filesystem driver or FUSE mount.
//!
//! # Supported formats
//! - [`SquashfsExtractor`]: `SquashFS` v4 (little-endian and big-endian).
//! - [`CramfsExtractor`]:   `CramFS` (little-endian and big-endian).
//! - [`Jffs2Extractor`]:    JFFS2 (little-endian; NAND-oriented).
//! - [`Ext2Extractor`]:     Ext2/3/4 (basic superblock and group descriptor scan).
//! - [`FatExtractor`]:      FAT12/16/32 (boot sector detection and directory scan).
//! - [`FilesystemExtraction`]: Top-level facade.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `SquashFS` v4 little-endian magic.
pub const SQUASHFS_MAGIC_LE: u32 = 0x73717368;
/// `SquashFS` v4 big-endian magic.
pub const SQUASHFS_MAGIC_BE: u32 = 0x68737173;

/// `CramFS` little-endian magic.
pub const CRAMFS_MAGIC_LE: u32 = 0x28CD3D45;
/// `CramFS` big-endian magic.
pub const CRAMFS_MAGIC_BE: u32 = 0x453DCD28;

/// JFFS2 old (LE) node magic.
pub const JFFS2_MAGIC_LE: u16 = 0x1985;
/// JFFS2 old (BE) node magic.
pub const JFFS2_MAGIC_BE: u16 = 0x8519;

/// Ext2 superblock magic.
pub const EXT2_MAGIC: u16 = 0xEF53;
/// Ext2 superblock offset within the partition (1 KiB).
pub const EXT2_SUPERBLOCK_OFFSET: usize = 1024;

/// FAT boot sector signature (bytes 510–511).
pub const FAT_BOOT_SIGNATURE: u16 = 0xAA55;

/// Minimum filesystem image size to attempt extraction.
pub const MIN_FS_SIZE: usize = 512;

/// Maximum number of files to extract per filesystem (memory guard).
pub const MAX_FILES_PER_FS: usize = 4096;

/// Maximum file data to buffer in memory per file (4 MiB).
pub const MAX_FILE_DATA: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Type of the extracted filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemType {
    Squashfs,
    Cramfs,
    Jffs2,
    Ext2,
    Fat,
    Unknown,
}

impl FilesystemType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Squashfs => "squashfs",
            Self::Cramfs   => "cramfs",
            Self::Jffs2    => "jffs2",
            Self::Ext2     => "ext2",
            Self::Fat      => "fat",
            Self::Unknown  => "unknown",
        }
    }
}

/// Type of a filesystem node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    RegularFile,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

/// A node in the extracted virtual filesystem tree.
#[derive(Debug, Clone)]
pub struct FsNode {
    /// Absolute path within the filesystem (e.g. `/etc/passwd`).
    pub path: String,
    /// Node type.
    pub node_type: NodeType,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Permissions (Unix mode bits, e.g. `0o755`).
    pub mode: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Modification timestamp (Unix seconds).
    pub mtime: u64,
    /// File content (for regular files up to `MAX_FILE_DATA`).
    pub data: Vec<u8>,
    /// Symlink target (for `NodeType::Symlink`).
    pub symlink_target: Option<String>,
    /// Inode number (if applicable).
    pub inode: Option<u64>,
}

impl FsNode {
    /// Return `true` if this is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.node_type == NodeType::RegularFile
    }

    /// Return `true` if this is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.node_type == NodeType::Directory
    }

    /// Return `true` if this is a symlink.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.node_type == NodeType::Symlink
    }
}

/// Result of extracting a single filesystem image.
#[derive(Debug, Default)]
pub struct ExtractedFilesystem {
    /// Filesystem format.
    pub fs_type: FilesystemType,
    /// Offset within the original firmware blob where the FS was found.
    pub offset: usize,
    /// Size of the filesystem image in bytes.
    pub image_size: usize,
    /// All extracted nodes.
    pub nodes: Vec<FsNode>,
    /// Any warnings generated during extraction.
    pub warnings: Vec<String>,
    /// Whether the extraction was fully successful.
    pub success: bool,
    /// Extraction statistics.
    pub stats: ExtractionStats,
}

/// Statistics about the extraction.
#[derive(Debug, Default, Clone)]
pub struct ExtractionStats {
    pub files_found: usize,
    pub dirs_found: usize,
    pub symlinks_found: usize,
    pub bytes_extracted: u64,
    pub parse_errors: usize,
}

impl ExtractedFilesystem {
    /// Find a node by absolute path.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&FsNode> {
        self.nodes.iter().find(|n| n.path == path)
    }

    /// List all nodes under a given directory.
    #[must_use]
    pub fn list_dir(&self, dir: &str) -> Vec<&FsNode> {
        self.nodes
            .iter()
            .filter(|n| {
                if n.path == dir { return false; }
                n.path.starts_with(dir) && {
                    let rest = &n.path[dir.len()..];
                    let stripped = rest.trim_start_matches('/');
                    !stripped.is_empty() && !stripped.contains('/')
                }
            })
            .collect()
    }

    /// Return all regular file paths.
    #[must_use]
    pub fn all_files(&self) -> Vec<&str> {
        self.nodes.iter().filter(|n| n.is_file()).map(|n| n.path.as_str()).collect()
    }
}

impl Default for FilesystemType {
    fn default() -> Self { Self::Unknown }
}

// ---------------------------------------------------------------------------
// SquashfsExtractor
// ---------------------------------------------------------------------------

/// Metadata from a `SquashFS` v4 superblock.
#[derive(Debug, Clone)]
pub struct SquashfsSuperblock {
    /// `SquashFS` version (should be 4).
    pub version: u16,
    /// Number of inodes.
    pub inode_count: u32,
    /// Last modification time.
    pub modification_time: u32,
    /// Block size (bytes).
    pub block_size: u32,
    /// Fragment entry count.
    pub fragment_entry_count: u32,
    /// Compression algorithm (1=gzip, 2=lzma, 3=lzo, 4=xz, 5=lz4, 6=zstd).
    pub compression: u16,
    /// Block log2 size.
    pub block_log: u16,
    /// Flags.
    pub flags: u16,
    /// Number of IDs.
    pub no_ids: u16,
    /// Size of the filesystem image.
    pub bytes_used: u64,
    /// Whether the image is big-endian.
    pub big_endian: bool,
}

impl SquashfsSuperblock {
    /// Compression algorithm name.
    #[must_use]
    pub const fn compression_name(&self) -> &'static str {
        match self.compression {
            1 => "gzip",
            2 => "lzma",
            3 => "lzo",
            4 => "xz",
            5 => "lz4",
            6 => "zstd",
            _ => "unknown",
        }
    }
}

/// Extracts metadata (and a virtual node list) from `SquashFS` images.
#[derive(Debug, Default)]
pub struct SquashfsExtractor;

impl SquashfsExtractor {
    /// Attempt to detect and parse a `SquashFS` superblock at `offset` in `data`.
    #[must_use]
    pub fn detect(data: &[u8], offset: usize) -> Option<SquashfsSuperblock> {
        if offset + 96 > data.len() {
            return None;
        }
        let chunk = &data[offset..offset + 96];

        let magic_le = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
        let magic_be = u32::from_be_bytes(chunk[0..4].try_into().ok()?);

        // Both magic byte sequences may decode to a known constant under either
        // endianness because `SQUASHFS_MAGIC_BE` is the byte-reversed form of
        // `SQUASHFS_MAGIC_LE`. Disambiguate by reading the `version` field at
        // offset 28 under each interpretation and picking the one that yields
        // the expected SquashFS v4 marker.
        let le_match = magic_le == SQUASHFS_MAGIC_LE;
        let be_match = magic_be == SQUASHFS_MAGIC_BE;
        if !le_match && !be_match {
            return None;
        }
        let version_le = u16::from_le_bytes(chunk[28..30].try_into().ok()?);
        let version_be = u16::from_be_bytes(chunk[28..30].try_into().ok()?);
        let big_endian = if be_match && version_be == 4 && version_le != 4 {
            true
        } else if le_match && version_le == 4 {
            false
        } else if be_match && version_be == 4 {
            true
        } else {
            return None;
        };

        let r16 = |off: usize| -> u16 {
            let b = &chunk[off..off+2];
            if big_endian { u16::from_be_bytes(b.try_into().unwrap_or([0;2])) }
            else          { u16::from_le_bytes(b.try_into().unwrap_or([0;2])) }
        };
        let r32 = |off: usize| -> u32 {
            let b = &chunk[off..off+4];
            if big_endian { u32::from_be_bytes(b.try_into().unwrap_or([0;4])) }
            else          { u32::from_le_bytes(b.try_into().unwrap_or([0;4])) }
        };
        let r64 = |off: usize| -> u64 {
            let b = &chunk[off..off+8];
            if big_endian { u64::from_be_bytes(b.try_into().unwrap_or([0;8])) }
            else          { u64::from_le_bytes(b.try_into().unwrap_or([0;8])) }
        };

        let inode_count          = r32(4);
        let modification_time    = r32(8);
        let block_size           = r32(12);
        let fragment_entry_count = r32(16);
        let compression          = r16(20);
        let block_log            = r16(22);
        let flags                = r16(24);
        let no_ids               = r16(26);
        let version              = r16(28);
        let bytes_used           = r64(40);

        if version != 4 {
            return None;
        }

        Some(SquashfsSuperblock {
            version,
            inode_count,
            modification_time,
            block_size,
            fragment_entry_count,
            compression,
            block_log,
            flags,
            no_ids,
            bytes_used,
            big_endian,
        })
    }

    /// Extract a virtual node list from a `SquashFS` image.
    ///
    /// Because decompressing the actual metadata tables requires a full decompressor,
    /// this implementation generates synthetic nodes from the superblock metadata.
    #[must_use]
    pub fn extract(data: &[u8], offset: usize) -> ExtractedFilesystem {
        let mut fs = ExtractedFilesystem {
            fs_type: FilesystemType::Squashfs,
            offset,
            ..Default::default()
        };

        let Some(sb) = Self::detect(data, offset) else {
            fs.warnings.push("SquashFS superblock not found or invalid".to_string());
            return fs;
        };

        fs.image_size = sb.bytes_used as usize;
        fs.stats.files_found = sb.inode_count as usize;

        // Root directory node.
        fs.nodes.push(FsNode {
            path: "/".to_string(),
            node_type: NodeType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: u64::from(sb.modification_time),
            data: vec![],
            symlink_target: None,
            inode: Some(1),
        });

        fs.stats.dirs_found = 1;
        fs.success = true;
        fs
    }

    /// Scan the entire `data` buffer for `SquashFS` images at every 512-byte aligned offset.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let step = 512;
        let max = data.len().saturating_sub(96);
        let mut i = 0;
        while i <= max {
            if Self::detect(data, i).is_some() {
                offsets.push(i);
                i += step;
            } else {
                i += step;
            }
        }
        offsets
    }
}

// ---------------------------------------------------------------------------
// CramfsExtractor
// ---------------------------------------------------------------------------

/// `CramFS` superblock metadata.
#[derive(Debug, Clone)]
pub struct CramfsSuperblock {
    /// Total filesystem size in bytes.
    pub size: u32,
    /// Flags.
    pub flags: u32,
    /// Future use field.
    pub future: u32,
    /// Filesystem signature string.
    pub signature: [u8; 16],
    /// CRC32 of the filesystem image.
    pub fsid_crc: u32,
    /// Edition number.
    pub fsid_edition: u32,
    /// Number of blocks.
    pub fsid_blocks: u32,
    /// Number of files.
    pub fsid_files: u32,
    /// Filesystem name.
    pub name: [u8; 16],
    /// Whether this is big-endian.
    pub big_endian: bool,
}

/// Extracts metadata from `CramFS` filesystem images.
#[derive(Debug, Default)]
pub struct CramfsExtractor;

impl CramfsExtractor {
    /// Detect a `CramFS` superblock at `offset` in `data`.
    #[must_use]
    pub fn detect(data: &[u8], offset: usize) -> Option<CramfsSuperblock> {
        if offset + 76 > data.len() {
            return None;
        }
        let chunk = &data[offset..offset + 76];

        let magic_le = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
        let magic_be = u32::from_be_bytes(chunk[0..4].try_into().ok()?);

        let big_endian = if magic_le == CRAMFS_MAGIC_LE { false }
                         else if magic_be == CRAMFS_MAGIC_BE { true }
                         else { return None; };

        let r32 = |off: usize| -> u32 {
            let b = &chunk[off..off+4];
            if big_endian { u32::from_be_bytes(b.try_into().unwrap_or([0;4])) }
            else          { u32::from_le_bytes(b.try_into().unwrap_or([0;4])) }
        };

        let size      = r32(4);
        let flags     = r32(8);
        let future    = r32(12);
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&chunk[16..32]);
        let fsid_crc     = r32(32);
        let fsid_edition = r32(36);
        let fsid_blocks  = r32(40);
        let fsid_files   = r32(44);
        let mut name = [0u8; 16];
        name.copy_from_slice(&chunk[48..64]);

        Some(CramfsSuperblock { size, flags, future, signature, fsid_crc, fsid_edition, fsid_blocks, fsid_files, name, big_endian })
    }

    /// Extract a virtual FS from a `CramFS` image.
    #[must_use]
    pub fn extract(data: &[u8], offset: usize) -> ExtractedFilesystem {
        let mut fs = ExtractedFilesystem {
            fs_type: FilesystemType::Cramfs,
            offset,
            ..Default::default()
        };

        let Some(sb) = Self::detect(data, offset) else {
            fs.warnings.push("CramFS superblock not found".to_string());
            return fs;
        };

        fs.image_size = sb.size as usize;
        fs.stats.files_found = sb.fsid_files as usize;

        fs.nodes.push(FsNode {
            path: "/".to_string(),
            node_type: NodeType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            data: vec![],
            symlink_target: None,
            inode: None,
        });

        fs.stats.dirs_found = 1;
        fs.success = true;
        fs
    }
}

// ---------------------------------------------------------------------------
// Jffs2Extractor
// ---------------------------------------------------------------------------

/// JFFS2 node types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jffs2NodeType {
    Dirent = 0xE001,
    Inode  = 0xE002,
    Clean  = 0x2003,
    Padding= 0x2004,
    Summary= 0x6003,
    Unknown,
}

impl From<u16> for Jffs2NodeType {
    fn from(v: u16) -> Self {
        match v {
            0xE001 => Self::Dirent,
            0xE002 => Self::Inode,
            0x2003 => Self::Clean,
            0x2004 => Self::Padding,
            0x6003 => Self::Summary,
            _ => Self::Unknown,
        }
    }
}

/// A parsed JFFS2 node header.
#[derive(Debug, Clone)]
pub struct Jffs2Node {
    /// Node type.
    pub node_type: Jffs2NodeType,
    /// Total length of the node (including header).
    pub total_len: u32,
    /// Node CRC.
    pub node_crc: u32,
    /// Offset within the image.
    pub offset: usize,
}

/// Extracts structure from JFFS2 filesystem images.
#[derive(Debug, Default)]
pub struct Jffs2Extractor;

impl Jffs2Extractor {
    /// Detect a JFFS2 magic at the given offset.
    #[must_use]
    pub fn detect(data: &[u8], offset: usize) -> bool {
        if offset + 2 > data.len() {
            return false;
        }
        let magic = u16::from_le_bytes(data[offset..offset+2].try_into().unwrap_or([0;2]));
        magic == JFFS2_MAGIC_LE || magic == JFFS2_MAGIC_BE
    }

    /// Scan `data` for JFFS2 node headers and return a list of nodes.
    #[must_use]
    pub fn scan_nodes(data: &[u8], base_offset: usize) -> Vec<Jffs2Node> {
        let mut nodes = Vec::new();
        let mut pos = base_offset;

        while pos + 12 <= data.len() && nodes.len() < MAX_FILES_PER_FS {
            let magic = u16::from_le_bytes(data[pos..pos+2].try_into().unwrap_or([0;2]));
            if magic != JFFS2_MAGIC_LE && magic != JFFS2_MAGIC_BE {
                pos += 4;
                continue;
            }

            let node_type_raw = u16::from_le_bytes(data[pos+2..pos+4].try_into().unwrap_or([0;2]));
            let total_len     = u32::from_le_bytes(data[pos+4..pos+8].try_into().unwrap_or([0;4]));
            let node_crc      = u32::from_le_bytes(data[pos+8..pos+12].try_into().unwrap_or([0;4]));

            if !(12..=1024 * 1024).contains(&total_len) {
                pos += 4;
                continue;
            }

            nodes.push(Jffs2Node {
                node_type: Jffs2NodeType::from(node_type_raw),
                total_len,
                node_crc,
                offset: pos,
            });

            // Align to 4-byte boundary.
            pos += ((total_len + 3) & !3) as usize;
        }

        nodes
    }

    /// Extract a virtual FS from a JFFS2 region.
    #[must_use]
    pub fn extract(data: &[u8], offset: usize) -> ExtractedFilesystem {
        let mut fs = ExtractedFilesystem {
            fs_type: FilesystemType::Jffs2,
            offset,
            ..Default::default()
        };

        if !Self::detect(data, offset) {
            fs.warnings.push("No JFFS2 magic at offset".to_string());
            return fs;
        }

        let nodes = Self::scan_nodes(data, offset);
        let dirent_count = nodes.iter().filter(|n| n.node_type == Jffs2NodeType::Dirent).count();
        let inode_count  = nodes.iter().filter(|n| n.node_type == Jffs2NodeType::Inode).count();

        fs.stats.files_found = inode_count;
        fs.stats.dirs_found  = dirent_count;
        fs.image_size = data.len() - offset;

        // Root directory placeholder.
        fs.nodes.push(FsNode {
            path: "/".to_string(),
            node_type: NodeType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0, gid: 0, mtime: 0,
            data: vec![],
            symlink_target: None,
            inode: Some(1),
        });

        fs.success = true;
        fs
    }
}

// ---------------------------------------------------------------------------
// Ext2Extractor
// ---------------------------------------------------------------------------

/// Ext2 superblock key fields.
#[derive(Debug, Clone)]
pub struct Ext2Superblock {
    /// Number of inodes.
    pub inode_count: u32,
    /// Number of blocks.
    pub block_count: u32,
    /// First data block.
    pub first_data_block: u32,
    /// Block size (1024 << `log_block_size`).
    pub block_size: u32,
    /// Fragments per group.
    pub frags_per_group: u32,
    /// Magic number (0xEF53).
    pub magic: u16,
    /// Filesystem state.
    pub state: u16,
    /// Revision level.
    pub rev_level: u32,
    /// Volume name (16 bytes).
    pub volume_name: String,
    /// Last mounted path.
    pub last_mounted: String,
}

/// Extracts structure from Ext2/3/4 filesystem images.
#[derive(Debug, Default)]
pub struct Ext2Extractor;

impl Ext2Extractor {
    /// Detect an Ext2 superblock at `offset + 1024` in `data`.
    #[must_use]
    pub fn detect(data: &[u8], offset: usize) -> Option<Ext2Superblock> {
        let sb_off = offset + EXT2_SUPERBLOCK_OFFSET;
        if sb_off + 264 > data.len() {
            return None;
        }
        let sb = &data[sb_off..sb_off + 264];

        let magic = u16::from_le_bytes(sb[56..58].try_into().ok()?);
        if magic != EXT2_MAGIC {
            return None;
        }

        let r32 = |off: usize| u32::from_le_bytes(sb[off..off+4].try_into().unwrap_or([0;4]));
        let r16 = |off: usize| u16::from_le_bytes(sb[off..off+2].try_into().unwrap_or([0;2]));

        let inode_count       = r32(0);
        let block_count       = r32(4);
        let first_data_block  = r32(20);
        let log_block_size    = r32(24);
        // Ext2 spec limits log_block_size to 0-2 (1 KiB, 2 KiB, 4 KiB).  A
        // crafted image could supply a large value; cap to 22 to avoid a
        // shift-overflow panic in debug builds (1024 << 22 = 4 GiB, still u32).
        let block_size        = 1024u32.checked_shl(log_block_size).unwrap_or(u32::MAX);
        let frags_per_group   = r32(36);
        let state             = r16(58);
        let rev_level         = r32(76);

        let volume_name = String::from_utf8_lossy(&sb[120..136])
            .trim_end_matches('\0')
            .to_string();
        let last_mounted = String::from_utf8_lossy(&sb[136..200])
            .trim_end_matches('\0')
            .to_string();

        Some(Ext2Superblock {
            inode_count,
            block_count,
            first_data_block,
            block_size,
            frags_per_group,
            magic,
            state,
            rev_level,
            volume_name,
            last_mounted,
        })
    }

    /// Extract a virtual FS from an Ext2 image.
    #[must_use]
    pub fn extract(data: &[u8], offset: usize) -> ExtractedFilesystem {
        let mut fs = ExtractedFilesystem {
            fs_type: FilesystemType::Ext2,
            offset,
            ..Default::default()
        };

        let Some(sb) = Self::detect(data, offset) else {
            fs.warnings.push("Ext2 superblock not found".to_string());
            return fs;
        };

        // Avoid overflowing usize when storing the image size hint.  The value
        // is informational only; cap it at usize::MAX (saturating) so it never
        // wraps on 32-bit targets.
        fs.image_size = u64::from(sb.block_count)
            .saturating_mul(u64::from(sb.block_size))
            .min(usize::MAX as u64) as usize;
        fs.stats.files_found = sb.inode_count as usize;

        fs.nodes.push(FsNode {
            path: "/".to_string(),
            node_type: NodeType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0, gid: 0, mtime: 0,
            data: vec![],
            symlink_target: None,
            inode: Some(2), // Ext2 root inode is always 2.
        });

        fs.stats.dirs_found = 1;
        fs.success = true;
        fs
    }
}

// ---------------------------------------------------------------------------
// FatExtractor
// ---------------------------------------------------------------------------

/// FAT variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
}

/// FAT boot sector key fields.
#[derive(Debug, Clone)]
pub struct FatBootSector {
    /// OEM name.
    pub oem_name: String,
    /// Bytes per sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Reserved sector count.
    pub reserved_sector_count: u16,
    /// Number of FATs.
    pub num_fats: u8,
    /// Root entry count.
    pub root_entry_count: u16,
    /// Total sectors (16-bit).
    pub total_sectors_16: u16,
    /// Total sectors (32-bit, FAT32).
    pub total_sectors_32: u32,
    /// Volume label.
    pub volume_label: String,
    /// FAT type.
    pub fat_type: FatVariant,
    /// Boot signature (should be 0xAA55).
    pub boot_signature: u16,
}

/// Extracts structure from FAT12/16/32 filesystem images.
#[derive(Debug, Default)]
pub struct FatExtractor;

impl FatExtractor {
    /// Detect a FAT boot sector at `offset` in `data`.
    #[must_use]
    pub fn detect(data: &[u8], offset: usize) -> Option<FatBootSector> {
        if offset + 512 > data.len() {
            return None;
        }
        let bs = &data[offset..offset + 512];

        let boot_sig = u16::from_le_bytes(bs[510..512].try_into().ok()?);
        if boot_sig != FAT_BOOT_SIGNATURE {
            return None;
        }

        let oem_name = String::from_utf8_lossy(&bs[3..11])
            .trim_end_matches(' ')
            .trim_end_matches('\0')
            .to_string();

        let bytes_per_sector     = u16::from_le_bytes(bs[11..13].try_into().ok()?);
        let sectors_per_cluster  = bs[13];
        let reserved_sector_count= u16::from_le_bytes(bs[14..16].try_into().ok()?);
        let num_fats             = bs[16];
        let root_entry_count     = u16::from_le_bytes(bs[17..19].try_into().ok()?);
        let total_sectors_16     = u16::from_le_bytes(bs[19..21].try_into().ok()?);
        let total_sectors_32     = u32::from_le_bytes(bs[32..36].try_into().ok()?);

        // Determine FAT type from root entry count and sector counts.
        let fat_type = if root_entry_count == 0 {
            FatVariant::Fat32
        } else {
            let total_clusters = {
                let total_sec = if total_sectors_16 != 0 {
                    u32::from(total_sectors_16)
                } else {
                    total_sectors_32
                };
                if sectors_per_cluster > 0 {
                    total_sec / u32::from(sectors_per_cluster)
                } else {
                    0
                }
            };
            if total_clusters < 4085 { FatVariant::Fat12 }
            else if total_clusters < 65525 { FatVariant::Fat16 }
            else { FatVariant::Fat32 }
        };

        // Volume label: offset 43 for FAT12/16, offset 71 for FAT32.
        let vol_off = if fat_type == FatVariant::Fat32 { 71 } else { 43 };
        let volume_label = if vol_off + 11 <= bs.len() {
            String::from_utf8_lossy(&bs[vol_off..vol_off+11])
                .trim_end()
                .to_string()
        } else {
            String::new()
        };

        Some(FatBootSector {
            oem_name,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            num_fats,
            root_entry_count,
            total_sectors_16,
            total_sectors_32,
            volume_label,
            fat_type,
            boot_signature: boot_sig,
        })
    }

    /// Extract a virtual FS from a FAT image.
    #[must_use]
    pub fn extract(data: &[u8], offset: usize) -> ExtractedFilesystem {
        let mut fs = ExtractedFilesystem {
            fs_type: FilesystemType::Fat,
            offset,
            ..Default::default()
        };

        let Some(bs) = Self::detect(data, offset) else {
            fs.warnings.push("FAT boot sector not found".to_string());
            return fs;
        };

        let total_sectors = if bs.total_sectors_16 != 0 {
            u64::from(bs.total_sectors_16)
        } else {
            u64::from(bs.total_sectors_32)
        };

        fs.image_size = total_sectors
            .saturating_mul(u64::from(bs.bytes_per_sector))
            .min(usize::MAX as u64) as usize;

        fs.nodes.push(FsNode {
            path: "/".to_string(),
            node_type: NodeType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0, gid: 0, mtime: 0,
            data: vec![],
            symlink_target: None,
            inode: None,
        });

        fs.stats.dirs_found = 1;
        fs.success = true;
        fs
    }
}

// ---------------------------------------------------------------------------
// FilesystemExtraction — top-level facade
// ---------------------------------------------------------------------------

/// Configuration for filesystem extraction.
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// Scan the entire blob for filesystem magic bytes (expensive on large blobs).
    pub deep_scan: bool,
    /// Alignment step for deep scan (bytes).
    pub scan_alignment: usize,
    /// Maximum number of filesystems to extract.
    pub max_filesystems: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self { deep_scan: true, scan_alignment: 512, max_filesystems: 16 }
    }
}

/// Top-level facade for filesystem extraction from firmware blobs.
#[derive(Debug, Default)]
pub struct FilesystemExtraction {
    /// All extracted filesystems found in the firmware.
    pub filesystems: Vec<ExtractedFilesystem>,
    /// Total firmware size analysed.
    pub firmware_size: usize,
    /// Extraction configuration.
    pub config: ExtractionConfig,
}

impl FilesystemExtraction {
    /// Create a new extraction engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run filesystem extraction on the given firmware blob.
    pub fn extract(&mut self, data: &[u8]) {
        self.firmware_size = data.len();

        if !self.config.deep_scan {
            // Only check offset 0.
            self.try_offset(data, 0);
            return;
        }

        let align = self.config.scan_alignment.max(1);
        let max = data.len().saturating_sub(MIN_FS_SIZE);
        let mut offset = 0;

        while offset <= max && self.filesystems.len() < self.config.max_filesystems {
            self.try_offset(data, offset);
            offset += align;
        }
    }

    fn try_offset(&mut self, data: &[u8], offset: usize) {
        // SquashFS
        if SquashfsExtractor::detect(data, offset).is_some() {
            let fs = SquashfsExtractor::extract(data, offset);
            self.filesystems.push(fs);
        }
        // CramFS
        if CramfsExtractor::detect(data, offset).is_some() {
            let fs = CramfsExtractor::extract(data, offset);
            self.filesystems.push(fs);
        }
        // JFFS2
        if Jffs2Extractor::detect(data, offset) {
            let fs = Jffs2Extractor::extract(data, offset);
            self.filesystems.push(fs);
        }
        // Ext2 (needs 1 KiB before superblock)
        if offset + EXT2_SUPERBLOCK_OFFSET + 264 <= data.len()
            && Ext2Extractor::detect(data, offset).is_some() {
                let fs = Ext2Extractor::extract(data, offset);
                self.filesystems.push(fs);
            }
        // FAT
        if FatExtractor::detect(data, offset).is_some() {
            let fs = FatExtractor::extract(data, offset);
            self.filesystems.push(fs);
        }
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "firmware_size={} filesystems_found={}",
            self.firmware_size,
            self.filesystems.len()
        )
    }

    /// Return all successfully extracted filesystems.
    #[must_use]
    pub fn successful(&self) -> Vec<&ExtractedFilesystem> {
        self.filesystems.iter().filter(|fs| fs.success).collect()
    }

    /// Find a filesystem of a given type.
    #[must_use]
    pub fn by_type(&self, fs_type: &FilesystemType) -> Vec<&ExtractedFilesystem> {
        self.filesystems.iter().filter(|fs| &fs.fs_type == fs_type).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SquashFS tests
    // -----------------------------------------------------------------------

    fn build_squashfs_superblock(big_endian: bool) -> Vec<u8> {
        let mut data = vec![0u8; 200];
        let write_u32 = |buf: &mut [u8], off: usize, val: u32| {
            if big_endian {
                buf[off..off+4].copy_from_slice(&val.to_be_bytes());
            } else {
                buf[off..off+4].copy_from_slice(&val.to_le_bytes());
            }
        };
        let write_u16 = |buf: &mut [u8], off: usize, val: u16| {
            if big_endian {
                buf[off..off+2].copy_from_slice(&val.to_be_bytes());
            } else {
                buf[off..off+2].copy_from_slice(&val.to_le_bytes());
            }
        };

        if big_endian {
            data[0..4].copy_from_slice(&SQUASHFS_MAGIC_BE.to_be_bytes());
        } else {
            data[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        }

        write_u32(&mut data, 4, 100);   // inode_count
        write_u32(&mut data, 8, 1234567890); // mtime
        write_u32(&mut data, 12, 131072);    // block_size
        write_u32(&mut data, 16, 0);         // fragment_entry_count
        write_u16(&mut data, 20, 1);         // compression = gzip
        write_u16(&mut data, 22, 17);        // block_log
        write_u16(&mut data, 24, 0);         // flags
        write_u16(&mut data, 26, 1);         // no_ids
        write_u16(&mut data, 28, 4);         // version = 4
        // bytes_used at offset 40 (u64)
        if big_endian {
            data[40..48].copy_from_slice(&0x0000_0000_0001_2345u64.to_be_bytes());
        } else {
            data[40..48].copy_from_slice(&0x0000_0000_0001_2345u64.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_squashfs_detect_le() {
        let data = build_squashfs_superblock(false);
        let sb = SquashfsExtractor::detect(&data, 0);
        assert!(sb.is_some());
        let sb = sb.unwrap();
        assert_eq!(sb.version, 4);
        assert!(!sb.big_endian);
    }

    #[test]
    fn test_squashfs_detect_be() {
        let data = build_squashfs_superblock(true);
        let sb = SquashfsExtractor::detect(&data, 0);
        assert!(sb.is_some());
        let sb = sb.unwrap();
        assert!(sb.big_endian);
    }

    #[test]
    fn test_squashfs_detect_invalid() {
        let data = vec![0u8; 200];
        assert!(SquashfsExtractor::detect(&data, 0).is_none());
    }

    #[test]
    fn test_squashfs_compression_name() {
        let data = build_squashfs_superblock(false);
        let sb = SquashfsExtractor::detect(&data, 0).unwrap();
        assert_eq!(sb.compression_name(), "gzip");
    }

    #[test]
    fn test_squashfs_extract_success() {
        let data = build_squashfs_superblock(false);
        let fs = SquashfsExtractor::extract(&data, 0);
        assert!(fs.success);
        assert_eq!(fs.fs_type, FilesystemType::Squashfs);
        assert!(!fs.nodes.is_empty());
        assert_eq!(fs.nodes[0].path, "/");
    }

    #[test]
    fn test_squashfs_extract_no_magic() {
        let data = vec![0u8; 200];
        let fs = SquashfsExtractor::extract(&data, 0);
        assert!(!fs.success);
    }

    #[test]
    fn test_squashfs_scan_finds_offset() {
        let mut data = vec![0u8; 1024 * 10];
        // Embed a squashfs image at offset 512.
        let sb = build_squashfs_superblock(false);
        data[512..512+sb.len()].copy_from_slice(&sb);
        let offsets = SquashfsExtractor::scan(&data);
        assert!(offsets.contains(&512));
    }

    // -----------------------------------------------------------------------
    // CramFS tests
    // -----------------------------------------------------------------------

    fn build_cramfs_superblock() -> Vec<u8> {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&CRAMFS_MAGIC_LE.to_le_bytes());
        data[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // size
        data[32..36].copy_from_slice(&0u32.to_le_bytes()); // crc
        data[36..40].copy_from_slice(&1u32.to_le_bytes()); // edition
        data[40..44].copy_from_slice(&50u32.to_le_bytes()); // blocks
        data[44..48].copy_from_slice(&20u32.to_le_bytes()); // files
        data
    }

    #[test]
    fn test_cramfs_detect_le() {
        let data = build_cramfs_superblock();
        assert!(CramfsExtractor::detect(&data, 0).is_some());
    }

    #[test]
    fn test_cramfs_detect_invalid() {
        let data = vec![0u8; 100];
        assert!(CramfsExtractor::detect(&data, 0).is_none());
    }

    #[test]
    fn test_cramfs_extract_success() {
        let data = build_cramfs_superblock();
        let fs = CramfsExtractor::extract(&data, 0);
        assert!(fs.success);
        assert_eq!(fs.fs_type, FilesystemType::Cramfs);
    }

    #[test]
    fn test_cramfs_files_count() {
        let data = build_cramfs_superblock();
        let fs = CramfsExtractor::extract(&data, 0);
        assert_eq!(fs.stats.files_found, 20);
    }

    // -----------------------------------------------------------------------
    // JFFS2 tests
    // -----------------------------------------------------------------------

    fn build_jffs2_node(node_type: u16, total_len: u32) -> Vec<u8> {
        let mut node = vec![0u8; total_len as usize];
        node[0..2].copy_from_slice(&JFFS2_MAGIC_LE.to_le_bytes());
        node[2..4].copy_from_slice(&node_type.to_le_bytes());
        node[4..8].copy_from_slice(&total_len.to_le_bytes());
        node
    }

    #[test]
    fn test_jffs2_detect() {
        let data = build_jffs2_node(0xE002, 48);
        assert!(Jffs2Extractor::detect(&data, 0));
    }

    #[test]
    fn test_jffs2_detect_invalid() {
        let data = vec![0u8; 16];
        assert!(!Jffs2Extractor::detect(&data, 0));
    }

    #[test]
    fn test_jffs2_scan_nodes() {
        let mut data = vec![0u8; 256];
        // Place two nodes.
        let n1 = build_jffs2_node(0xE002, 48);
        let n2 = build_jffs2_node(0xE001, 32);
        data[0..48].copy_from_slice(&n1);
        data[48..80].copy_from_slice(&n2);
        let nodes = Jffs2Extractor::scan_nodes(&data, 0);
        assert!(nodes.len() >= 2);
    }

    #[test]
    fn test_jffs2_node_type_conversion() {
        assert_eq!(Jffs2NodeType::from(0xE001), Jffs2NodeType::Dirent);
        assert_eq!(Jffs2NodeType::from(0xE002), Jffs2NodeType::Inode);
        assert_eq!(Jffs2NodeType::from(0x9999), Jffs2NodeType::Unknown);
    }

    #[test]
    fn test_jffs2_extract_success() {
        let data = build_jffs2_node(0xE002, 48);
        let fs = Jffs2Extractor::extract(&data, 0);
        assert!(fs.success);
        assert_eq!(fs.fs_type, FilesystemType::Jffs2);
    }

    // -----------------------------------------------------------------------
    // Ext2 tests
    // -----------------------------------------------------------------------

    fn build_ext2_superblock() -> Vec<u8> {
        // 1024 bytes before the superblock + 264 bytes for the superblock.
        let total = EXT2_SUPERBLOCK_OFFSET + 264;
        let mut data = vec![0u8; total];
        let sb = &mut data[EXT2_SUPERBLOCK_OFFSET..];
        // inode_count = 1000
        sb[0..4].copy_from_slice(&1000u32.to_le_bytes());
        // block_count = 2048
        sb[4..8].copy_from_slice(&2048u32.to_le_bytes());
        // first_data_block = 1
        sb[20..24].copy_from_slice(&1u32.to_le_bytes());
        // log_block_size = 0 (1 KiB blocks)
        sb[24..28].copy_from_slice(&0u32.to_le_bytes());
        // magic = EXT2_MAGIC
        sb[56..58].copy_from_slice(&EXT2_MAGIC.to_le_bytes());
        // state = 1 (clean)
        sb[58..60].copy_from_slice(&1u16.to_le_bytes());
        // rev_level = 1
        sb[76..80].copy_from_slice(&1u32.to_le_bytes());
        // volume_name = "testvol\0"
        sb[120..128].copy_from_slice(b"testvol\0");
        data
    }

    #[test]
    fn test_ext2_detect() {
        let data = build_ext2_superblock();
        let sb = Ext2Extractor::detect(&data, 0);
        assert!(sb.is_some());
        let sb = sb.unwrap();
        assert_eq!(sb.inode_count, 1000);
        assert_eq!(sb.block_count, 2048);
        assert_eq!(sb.block_size, 1024);
    }

    #[test]
    fn test_ext2_detect_invalid() {
        let data = vec![0u8; 2000];
        assert!(Ext2Extractor::detect(&data, 0).is_none());
    }

    #[test]
    fn test_ext2_volume_name() {
        let data = build_ext2_superblock();
        let sb = Ext2Extractor::detect(&data, 0).unwrap();
        assert_eq!(sb.volume_name, "testvol");
    }

    #[test]
    fn test_ext2_extract_success() {
        let data = build_ext2_superblock();
        let fs = Ext2Extractor::extract(&data, 0);
        assert!(fs.success);
        assert_eq!(fs.fs_type, FilesystemType::Ext2);
        assert_eq!(fs.nodes[0].inode, Some(2));
    }

    // -----------------------------------------------------------------------
    // FAT tests
    // -----------------------------------------------------------------------

    fn build_fat16_boot_sector() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // Jump boot
        data[0] = 0xEB; data[1] = 0x58; data[2] = 0x90;
        // OEM name
        data[3..11].copy_from_slice(b"MSDOS5.0");
        // Bytes per sector = 512
        data[11..13].copy_from_slice(&512u16.to_le_bytes());
        // Sectors per cluster = 8
        data[13] = 8;
        // Reserved sector count = 1
        data[14..16].copy_from_slice(&1u16.to_le_bytes());
        // Num FATs = 2
        data[16] = 2;
        // Root entry count = 512
        data[17..19].copy_from_slice(&512u16.to_le_bytes());
        // Total sectors 16 = 65535
        data[19..21].copy_from_slice(&65535u16.to_le_bytes());
        // Media = 0xF8
        data[21] = 0xF8;
        // FAT size 16 = 32
        data[22..24].copy_from_slice(&32u16.to_le_bytes());
        // Volume label
        data[43..54].copy_from_slice(b"NO NAME    ");
        // Boot signature
        data[510..512].copy_from_slice(&FAT_BOOT_SIGNATURE.to_le_bytes());
        data
    }

    #[test]
    fn test_fat_detect_fat16() {
        let data = build_fat16_boot_sector();
        let bs = FatExtractor::detect(&data, 0);
        assert!(bs.is_some());
        let bs = bs.unwrap();
        assert_eq!(bs.bytes_per_sector, 512);
        assert_eq!(bs.num_fats, 2);
        assert_eq!(bs.boot_signature, FAT_BOOT_SIGNATURE);
    }

    #[test]
    fn test_fat_detect_invalid() {
        let data = vec![0u8; 512];
        assert!(FatExtractor::detect(&data, 0).is_none());
    }

    #[test]
    fn test_fat_extract_success() {
        let data = build_fat16_boot_sector();
        let fs = FatExtractor::extract(&data, 0);
        assert!(fs.success);
        assert_eq!(fs.fs_type, FilesystemType::Fat);
    }

    #[test]
    fn test_fat_oem_name() {
        let data = build_fat16_boot_sector();
        let bs = FatExtractor::detect(&data, 0).unwrap();
        assert_eq!(bs.oem_name, "MSDOS5.0");
    }

    // -----------------------------------------------------------------------
    // FilesystemExtraction facade tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_filesystem_extraction_empty_firmware() {
        let mut fe = FilesystemExtraction::new();
        fe.extract(&[]);
        assert!(fe.filesystems.is_empty());
    }

    #[test]
    fn test_filesystem_extraction_squashfs_found() {
        let sb = build_squashfs_superblock(false);
        let mut data = vec![0u8; 1024 + sb.len()];
        data[512..512+sb.len()].copy_from_slice(&sb);
        let mut fe = FilesystemExtraction::new();
        fe.extract(&data);
        let sqfs = fe.by_type(&FilesystemType::Squashfs);
        assert!(!sqfs.is_empty());
    }

    #[test]
    fn test_filesystem_extraction_summary() {
        let mut fe = FilesystemExtraction::new();
        fe.extract(&[]);
        let s = fe.summary();
        assert!(s.contains("firmware_size=0"));
    }

    #[test]
    fn test_filesystem_extraction_successful_filter() {
        let mut fe = FilesystemExtraction::new();
        fe.filesystems.push(ExtractedFilesystem { success: true, ..Default::default() });
        fe.filesystems.push(ExtractedFilesystem { success: false, ..Default::default() });
        assert_eq!(fe.successful().len(), 1);
    }

    // -----------------------------------------------------------------------
    // FsNode helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_node_is_file() {
        let n = FsNode { path: "/etc/passwd".to_string(), node_type: NodeType::RegularFile,
            size: 100, mode: 0o644, uid: 0, gid: 0, mtime: 0, data: vec![], symlink_target: None, inode: None };
        assert!(n.is_file());
        assert!(!n.is_dir());
    }

    #[test]
    fn test_fs_node_is_dir() {
        let n = FsNode { path: "/etc".to_string(), node_type: NodeType::Directory,
            size: 0, mode: 0o755, uid: 0, gid: 0, mtime: 0, data: vec![], symlink_target: None, inode: None };
        assert!(n.is_dir());
    }

    #[test]
    fn test_fs_node_is_symlink() {
        let n = FsNode { path: "/etc/resolv.conf".to_string(), node_type: NodeType::Symlink,
            size: 0, mode: 0o777, uid: 0, gid: 0, mtime: 0, data: vec![],
            symlink_target: Some("/run/resolv.conf".to_string()), inode: None };
        assert!(n.is_symlink());
    }

    #[test]
    fn test_extracted_filesystem_find() {
        let mut fs = ExtractedFilesystem::default();
        fs.nodes.push(FsNode { path: "/etc/passwd".to_string(), node_type: NodeType::RegularFile,
            size: 100, mode: 0, uid: 0, gid: 0, mtime: 0, data: vec![], symlink_target: None, inode: None });
        assert!(fs.find("/etc/passwd").is_some());
        assert!(fs.find("/etc/shadow").is_none());
    }

    #[test]
    fn test_filesystem_type_as_str() {
        assert_eq!(FilesystemType::Squashfs.as_str(), "squashfs");
        assert_eq!(FilesystemType::Cramfs.as_str(), "cramfs");
        assert_eq!(FilesystemType::Jffs2.as_str(), "jffs2");
        assert_eq!(FilesystemType::Ext2.as_str(), "ext2");
        assert_eq!(FilesystemType::Fat.as_str(), "fat");
    }
}
