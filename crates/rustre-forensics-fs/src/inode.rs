//! Inode and MFT record parsing.
//!
//! Provides in-memory representations of inodes (from NTFS MFT records and
//! ext4 inode tables), a searchable inode table, and minimal binary parsers
//! for both filesystem formats.

// ─── InodeFlags ───────────────────────────────────────────────────────────────

/// Bit-flag constants for inode attributes.
pub struct InodeFlags;

impl InodeFlags {
    /// File is read-only.
    pub const READ_ONLY: u32 = 0x0001;
    /// File is hidden from normal directory listings.
    pub const HIDDEN: u32 = 0x0002;
    /// File is a system file.
    pub const SYSTEM: u32 = 0x0004;
    /// Entry is a directory.
    pub const DIRECTORY: u32 = 0x0010;
    /// File has been marked for archiving.
    pub const ARCHIVE: u32 = 0x0020;
    /// Entry is a device.
    pub const DEVICE: u32 = 0x0040;
    /// File has no special attributes (normal).
    pub const NORMAL: u32 = 0x0080;
    /// File is a temporary file.
    pub const TEMPORARY: u32 = 0x0100;
    /// File is a sparse file.
    pub const SPARSE: u32 = 0x0200;
    /// File has a reparse point (junction, symlink, etc.).
    pub const REPARSE_POINT: u32 = 0x0400;
    /// File is compressed.
    pub const COMPRESSED: u32 = 0x0800;
    /// File is offline (data may not be immediately available).
    pub const OFFLINE: u32 = 0x1000;
    /// File is encrypted.
    pub const ENCRYPTED: u32 = 0x4000;
    /// Inode has been deleted (synthetic flag for forensics).
    pub const DELETED: u32 = 0x8000;
}

// ─── DataRun ──────────────────────────────────────────────────────────────────

/// A single data run describing a contiguous range of clusters on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    /// Logical Cluster Number (start of run on volume).
    pub lcn: u64,
    /// Length of the run in clusters.
    pub length: u64,
    /// True if this run is a sparse (unallocated) hole.
    pub sparse: bool,
}

impl DataRun {
    /// Create a new non-sparse data run.
    #[must_use]
    pub const fn new(lcn: u64, length: u64) -> Self {
        Self {
            lcn,
            length,
            sparse: false,
        }
    }

    /// Create a new sparse data run (all-zeros range).
    #[must_use]
    pub const fn sparse(length: u64) -> Self {
        Self {
            lcn: 0,
            length,
            sparse: true,
        }
    }

    /// Size of this run in bytes given `cluster_size` bytes per cluster.
    #[must_use]
    pub const fn byte_size(&self, cluster_size: u64) -> u64 {
        // `length` is read straight out of a run list (`parse_data_runs`), where
        // the header's low nibble allows up to 15 length bytes — so it can hold
        // any `u64`. Multiplying that by a cluster size overflows: in release the
        // product wrapped, reporting a colossal run as a handful of bytes, and in
        // debug it panicked on a malformed image. Saturating keeps the answer
        // monotonic in `length`, so an absurd run reads as absurdly large instead
        // of small.
        self.length.saturating_mul(cluster_size)
    }
}

// ─── Inode ────────────────────────────────────────────────────────────────────

/// Unified inode representation for NTFS and ext4.
#[derive(Debug, Clone)]
pub struct Inode {
    /// Inode / MFT record number.
    pub inode_num: u64,
    /// File name (may be empty if not resolved).
    pub name: String,
    /// Logical file size in bytes.
    pub size: u64,
    /// Allocated size on disk (rounded to cluster/block).
    pub alloc_size: u64,
    /// Attribute flags (see [`InodeFlags`]).
    pub flags: u32,
    /// Number of hard links pointing to this inode.
    pub link_count: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// POSIX mode bits (type + rwxrwxrwx).
    pub mode: u32,
    /// Last access time (POSIX seconds or NTFS 100-ns units, caller-determined).
    pub atime: u64,
    /// Last data-modification time.
    pub mtime: u64,
    /// Last metadata-change time (ext4 ctime) or MFT-record-change time.
    pub ctime: u64,
    /// File creation time (NTFS `$STANDARD_INFORMATION` crtime, or ext4 crtime).
    pub crtime: u64,
    /// Data runs (may be empty for resident or inline data).
    pub data_runs: Vec<DataRun>,
}

impl Inode {
    /// Returns `true` if this inode appears to be deleted.
    ///
    /// Heuristic: `link_count == 0` and `size > 0`, or the `DELETED` flag is set.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        (self.link_count == 0 && self.size > 0) || (self.flags & InodeFlags::DELETED != 0)
    }

    /// Returns `true` if this inode is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.flags & InodeFlags::DIRECTORY != 0 || (self.mode & 0xF000) == 0x4000
    }

    /// Returns `true` if encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags & InodeFlags::ENCRYPTED != 0
    }

    /// Total byte size across all data runs given `cluster_size`.
    #[must_use]
    pub fn total_run_bytes(&self, cluster_size: u64) -> u64 {
        // `sum()` wraps in release and panics in debug; the run list comes from
        // the image being examined, so both are reachable. Fold saturatingly for
        // the same reason as [`DataRun::byte_size`].
        self.data_runs
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.byte_size(cluster_size)))
    }
}

// ─── InodeTable ───────────────────────────────────────────────────────────────

/// A searchable map of inode number → [`Inode`].
#[derive(Debug, Default)]
pub struct InodeTable {
    inodes: std::collections::HashMap<u64, Inode>,
}

impl InodeTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inodes: std::collections::HashMap::new(),
        }
    }

    /// Insert or replace an inode.
    pub fn insert(&mut self, inode: Inode) {
        self.inodes.insert(inode.inode_num, inode);
    }

    /// Get an inode by number.
    #[must_use]
    pub fn get(&self, num: u64) -> Option<&Inode> {
        self.inodes.get(&num)
    }

    /// Return all inodes whose name contains `name` (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&Inode> {
        let lower = name.to_lowercase();
        self.inodes
            .values()
            .filter(|i| i.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Return all inodes that appear to be deleted.
    ///
    /// Criteria: `link_count == 0` and `size > 0`, or `DELETED` flag set.
    #[must_use]
    pub fn find_deleted(&self) -> Vec<&Inode> {
        self.inodes.values().filter(|i| i.is_deleted()).collect()
    }

    /// Total allocated size across all inodes.
    #[must_use]
    pub fn total_allocated_size(&self) -> u64 {
        self.inodes.values().map(|i| i.alloc_size).sum()
    }

    /// Number of inodes in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inodes.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inodes.is_empty()
    }
}

// ─── NTFS MFT minimal parser ─────────────────────────────────────────────────

/// Parse a minimal NTFS MFT record from raw bytes.
///
/// The real MFT record layout (simplified):
/// ```text
/// Offset  Size  Field
/// 0       4     Signature ("FILE")
/// 4       2     Update Sequence Offset
/// 6       2     Update Sequence Count
/// 8       8     $LogFile LSN
/// 16      2     Sequence Number
/// 18      2     Hard Link Count
/// 20      2     First Attribute Offset
/// 22      2     Flags  (0=in-use, 1=deleted; bit1=directory)
/// 24      4     Used Size of MFT Entry
/// 28      4     Allocated Size of MFT Entry
/// 32      8     File Reference to Base Record
/// 40      2     Next Attribute ID
/// --- Attributes follow at FirstAttributeOffset ---
/// Attribute Header:
///   0  4  Type
///   4  4  Length
///   8  1  Non-resident flag
///   9  1  Name Length
///  10  2  Name Offset
///  12  2  Flags
///  14  2  Attribute ID
///  16  4  (resident) Value Length
///  20  2  (resident) Value Offset
///  22  1  (resident) Indexed Flag
///  23  1  (resident) Padding
/// ```
#[must_use]
pub fn parse_mft_record_minimal(data: &[u8], record_num: u64) -> Option<Inode> {
    if data.len() < 48 {
        return None;
    }
    // Check FILE magic
    if &data[0..4] != b"FILE" {
        return None;
    }

    let link_count = u32::from(u16::from_le_bytes(data[18..20].try_into().ok()?));
    let first_attr_offset = u16::from_le_bytes(data[20..22].try_into().ok()?) as usize;
    let flags_raw = u16::from_le_bytes(data[22..24].try_into().ok()?);

    // flags_raw: bit0 = in-use, bit1 = directory
    let deleted = (flags_raw & 0x0001) == 0;
    let is_dir = (flags_raw & 0x0002) != 0;

    let mut inode_flags: u32 = 0;
    if deleted {
        inode_flags |= InodeFlags::DELETED;
    }
    if is_dir {
        inode_flags |= InodeFlags::DIRECTORY;
    }

    // Walk attributes
    let mut name = String::new();
    let mut size = 0u64;
    let mut alloc_size = 0u64;
    let mut atime = 0u64;
    let mut mtime = 0u64;
    let mut ctime = 0u64;
    let mut crtime = 0u64;
    let mut data_runs: Vec<DataRun> = Vec::new();

    let mut pos = first_attr_offset;

    while pos + 8 <= data.len() {
        let attr_type = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        if attr_type == 0xFFFF_FFFF {
            break; // End marker
        }
        let attr_len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize;
        if attr_len == 0 || pos + attr_len > data.len() {
            break;
        }

        let non_resident = if pos + 9 <= data.len() {
            data[pos + 8]
        } else {
            0
        };

        match attr_type {
            // $STANDARD_INFORMATION (0x10) – timestamps
            0x10 => {
                if non_resident == 0 && pos + 24 + 32 <= data.len() {
                    let val_off = if pos + 20 <= data.len() {
                        u16::from_le_bytes(data[pos + 20..pos + 22].try_into().ok()?) as usize
                    } else {
                        24
                    };
                    let base = pos + val_off;
                    if base + 32 <= data.len() {
                        crtime = u64::from_le_bytes(data[base..base + 8].try_into().ok()?);
                        mtime = u64::from_le_bytes(data[base + 8..base + 16].try_into().ok()?);
                        ctime = u64::from_le_bytes(data[base + 16..base + 24].try_into().ok()?);
                        atime = u64::from_le_bytes(data[base + 24..base + 32].try_into().ok()?);
                    }
                }
            }
            // $FILE_NAME (0x30) – filename + timestamps
            0x30 => {
                if non_resident == 0 && pos + 24 <= data.len() {
                    let val_off =
                        u16::from_le_bytes(data[pos + 20..pos + 22].try_into().ok()?) as usize;
                    let base = pos + val_off;
                    // $FILE_NAME layout: parent_ref(8) + crtime(8) + mtime(8) + ctime(8) + atime(8)
                    // + alloc_size(8) + data_size(8) + flags(4) + reparse(4) + name_len(1) + ns(1) + name(2*name_len)
                    if base + 66 <= data.len() {
                        if crtime == 0 {
                            crtime = u64::from_le_bytes(data[base + 8..base + 16].try_into().ok()?);
                        }
                        if mtime == 0 {
                            mtime = u64::from_le_bytes(data[base + 16..base + 24].try_into().ok()?);
                        }
                        if ctime == 0 {
                            ctime = u64::from_le_bytes(data[base + 24..base + 32].try_into().ok()?);
                        }
                        if atime == 0 {
                            atime = u64::from_le_bytes(data[base + 32..base + 40].try_into().ok()?);
                        }
                        alloc_size =
                            u64::from_le_bytes(data[base + 40..base + 48].try_into().ok()?);
                        size = u64::from_le_bytes(data[base + 48..base + 56].try_into().ok()?);
                        let name_len = data[base + 64] as usize;
                        if name.is_empty() && base + 66 + name_len * 2 <= data.len() {
                            let raw: Vec<u16> = data[base + 66..base + 66 + name_len * 2]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            name = String::from_utf16_lossy(&raw);
                        }
                    }
                }
            }
            // $DATA (0x80) – size (for resident), or data runs (for non-resident)
            0x80 => {
                if non_resident == 0 {
                    // Resident: value length at offset 16
                    if pos + 20 <= data.len() {
                        let val_len = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().ok()?);
                        if size == 0 {
                            size = u64::from(val_len);
                        }
                        if alloc_size == 0 {
                            alloc_size = size;
                        }
                    }
                } else {
                    // Non-resident: real_size at offset 48 relative to attr header
                    if pos + 56 <= data.len() {
                        let real_size =
                            u64::from_le_bytes(data[pos + 48..pos + 56].try_into().ok()?);
                        if size == 0 {
                            size = real_size;
                        }
                        // Parse minimal data runs (simplified: just emit one run stub)
                        let run_list_off =
                            u16::from_le_bytes(data[pos + 32..pos + 34].try_into().ok()?) as usize;
                        let run_base = pos + run_list_off;
                        if run_base < data.len() {
                            data_runs.extend(parse_data_runs(
                                &data[run_base..data.len().min(run_base + 256)],
                            ));
                        }
                        if alloc_size == 0 && pos + 40 <= data.len() {
                            alloc_size =
                                u64::from_le_bytes(data[pos + 40..pos + 48].try_into().ok()?);
                        }
                    }
                }
            }
            _ => {}
        }

        pos += attr_len;
    }

    Some(Inode {
        inode_num: record_num,
        name,
        size,
        alloc_size,
        flags: inode_flags,
        link_count,
        uid: 0,
        gid: 0,
        mode: if is_dir { 0x4000 } else { 0x8000 },
        atime,
        mtime,
        ctime,
        crtime,
        data_runs,
    })
}

/// Parse NTFS data runs from a raw run-list byte sequence.
///
/// Data run format: header byte = (`offset_bytes` << 4) | `length_bytes`.
/// Both fields are little-endian signed integers.
fn parse_data_runs(data: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut current_lcn: i64 = 0;

    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break;
        }
        pos += 1;

        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;

        if pos + len_bytes + off_bytes > data.len() {
            break;
        }

        let mut run_length: u64 = 0;
        for i in (0..len_bytes).rev() {
            run_length = (run_length << 8) | u64::from(data[pos + i]);
        }
        pos += len_bytes;

        if off_bytes == 0 {
            // Sparse run
            runs.push(DataRun::sparse(run_length));
        } else {
            let mut run_offset: i64 = 0;
            for i in (0..off_bytes).rev() {
                run_offset = (run_offset << 8) | i64::from(data[pos + i]);
            }
            // Sign-extend
            if off_bytes < 8 {
                let shift = 64 - (off_bytes * 8);
                run_offset = (run_offset << shift) >> shift;
            }
            pos += off_bytes;
            current_lcn += run_offset;
            runs.push(DataRun::new(current_lcn.cast_unsigned(), run_length));
        }
    }

    runs
}

// ─── ext4 minimal inode parser ────────────────────────────────────────────────

/// Parse a minimal ext4 on-disk inode from 128+ bytes of raw data.
///
/// ext4 inode layout (abbreviated):
/// ```text
/// Offset  Size  Field
/// 0       2     i_mode
/// 2       2     i_uid (low 16 bits)
/// 4       4     i_size_lo
/// 8       4     i_atime
/// 12      4     i_ctime
/// 16      4     i_mtime
/// 20      4     i_dtime
/// 24      2     i_gid (low 16 bits)
/// 26      2     i_links_count
/// 28      4     i_blocks_lo
/// 32      4     i_flags
/// ```
#[must_use]
pub fn parse_ext4_inode_minimal(data: &[u8], inode_num: u64) -> Option<Inode> {
    if data.len() < 40 {
        return None;
    }

    let mode = u32::from(u16::from_le_bytes(data[0..2].try_into().ok()?));
    let uid = u32::from(u16::from_le_bytes(data[2..4].try_into().ok()?));
    let size = u64::from(u32::from_le_bytes(data[4..8].try_into().ok()?));
    let atime = u64::from(u32::from_le_bytes(data[8..12].try_into().ok()?));
    let ctime = u64::from(u32::from_le_bytes(data[12..16].try_into().ok()?));
    let mtime = u64::from(u32::from_le_bytes(data[16..20].try_into().ok()?));
    let gid = u32::from(u16::from_le_bytes(data[24..26].try_into().ok()?));
    let link_count = u32::from(u16::from_le_bytes(data[26..28].try_into().ok()?));
    let blocks = u32::from_le_bytes(data[28..32].try_into().ok()?);
    // alloc_size in 512-byte units (ext4 uses 512-byte block units in i_blocks_lo)
    let alloc_size = u64::from(blocks) * 512;

    // Map ext4 mode type bits to InodeFlags
    let mut flags: u32 = 0;
    let file_type = mode & 0xF000;
    if file_type == 0x4000 {
        flags |= InodeFlags::DIRECTORY;
    }
    if link_count == 0 && size > 0 {
        flags |= InodeFlags::DELETED;
    }

    Some(Inode {
        inode_num,
        name: String::new(),
        size,
        alloc_size,
        flags,
        link_count,
        uid,
        gid,
        mode,
        atime,
        mtime,
        ctime,
        crtime: 0, // ext4 extra field; not present in base 128-byte inode
        data_runs: Vec::new(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── InodeFlags ────────────────────────────────────────────────────────────

    #[test]
    fn inode_flags_distinct() {
        let flags = [
            InodeFlags::READ_ONLY,
            InodeFlags::HIDDEN,
            InodeFlags::SYSTEM,
            InodeFlags::DIRECTORY,
            InodeFlags::ARCHIVE,
            InodeFlags::DEVICE,
            InodeFlags::NORMAL,
            InodeFlags::TEMPORARY,
            InodeFlags::SPARSE,
            InodeFlags::REPARSE_POINT,
            InodeFlags::COMPRESSED,
            InodeFlags::OFFLINE,
            InodeFlags::ENCRYPTED,
            InodeFlags::DELETED,
        ];
        for i in 0..flags.len() {
            for j in 0..flags.len() {
                if i != j {
                    assert_ne!(flags[i], flags[j], "flags[{i}] == flags[{j}]");
                }
            }
        }
    }

    #[test]
    fn inode_flags_nonzero() {
        assert_ne!(InodeFlags::READ_ONLY, 0);
        assert_ne!(InodeFlags::DELETED, 0);
    }

    // ── DataRun ───────────────────────────────────────────────────────────────

    #[test]
    fn data_run_new() {
        let r = DataRun::new(100, 8);
        assert_eq!(r.lcn, 100);
        assert_eq!(r.length, 8);
        assert!(!r.sparse);
    }

    #[test]
    fn data_run_sparse() {
        let r = DataRun::sparse(4);
        assert!(r.sparse);
        assert_eq!(r.lcn, 0);
    }

    #[test]
    fn data_run_byte_size() {
        let r = DataRun::new(10, 4);
        assert_eq!(r.byte_size(4096), 16384);
    }

    // ── Inode ─────────────────────────────────────────────────────────────────

    fn make_inode(link_count: u32, size: u64, flags: u32) -> Inode {
        Inode {
            inode_num: 42,
            name: "test.txt".into(),
            size,
            alloc_size: size,
            flags,
            link_count,
            uid: 1000,
            gid: 1000,
            mode: 0x81A4, // regular file, rw-r--r--
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            data_runs: vec![DataRun::new(100, 1)],
        }
    }

    #[test]
    fn inode_is_deleted_link_count_zero() {
        let i = make_inode(0, 100, 0);
        assert!(i.is_deleted());
    }

    #[test]
    fn inode_is_deleted_flag() {
        let i = make_inode(1, 100, InodeFlags::DELETED);
        assert!(i.is_deleted());
    }

    #[test]
    fn inode_not_deleted() {
        let i = make_inode(1, 100, 0);
        assert!(!i.is_deleted());
    }

    #[test]
    fn inode_is_directory_via_flag() {
        let i = make_inode(1, 0, InodeFlags::DIRECTORY);
        assert!(i.is_directory());
    }

    #[test]
    fn inode_is_directory_via_mode() {
        let mut i = make_inode(1, 0, 0);
        i.mode = 0x41ED; // directory
        assert!(i.is_directory());
    }

    #[test]
    fn inode_is_encrypted() {
        let i = make_inode(1, 100, InodeFlags::ENCRYPTED);
        assert!(i.is_encrypted());
    }

    #[test]
    fn inode_total_run_bytes() {
        let i = make_inode(1, 4096, 0); // one run of 1 cluster at 4096 bytes/cluster
        assert_eq!(i.total_run_bytes(4096), 4096);
    }

    // ── InodeTable ────────────────────────────────────────────────────────────

    #[test]
    fn inode_table_insert_get() {
        let mut t = InodeTable::new();
        t.insert(make_inode(1, 100, 0));
        assert!(t.get(42).is_some());
        assert!(t.get(99).is_none());
    }

    #[test]
    fn inode_table_len() {
        let mut t = InodeTable::new();
        assert_eq!(t.len(), 0);
        t.insert(make_inode(1, 100, 0));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn inode_table_find_by_name() {
        let mut t = InodeTable::new();
        t.insert(make_inode(1, 100, 0)); // name = "test.txt"
        let found = t.find_by_name("test");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn inode_table_find_by_name_case_insensitive() {
        let mut t = InodeTable::new();
        t.insert(make_inode(1, 100, 0));
        assert!(!t.find_by_name("TEST").is_empty());
    }

    #[test]
    fn inode_table_find_deleted() {
        let mut t = InodeTable::new();
        let mut deleted = make_inode(0, 100, 0);
        deleted.inode_num = 43;
        t.insert(make_inode(1, 100, 0)); // not deleted
        t.insert(deleted);
        let del = t.find_deleted();
        assert_eq!(del.len(), 1);
        assert_eq!(del[0].inode_num, 43);
    }

    #[test]
    fn inode_table_total_allocated_size() {
        let mut t = InodeTable::new();
        let mut i1 = make_inode(1, 100, 0);
        i1.alloc_size = 4096;
        let mut i2 = make_inode(1, 200, 0);
        i2.inode_num = 43;
        i2.alloc_size = 8192;
        t.insert(i1);
        t.insert(i2);
        assert_eq!(t.total_allocated_size(), 12288);
    }

    // ── parse_mft_record_minimal ──────────────────────────────────────────────

    fn make_mft_record() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // FILE magic
        data[0..4].copy_from_slice(b"FILE");
        // link_count = 1 at offset 18
        data[18..20].copy_from_slice(&1u16.to_le_bytes());
        // first_attr_offset = 56 at offset 20
        data[20..22].copy_from_slice(&56u16.to_le_bytes());
        // flags = 1 (in-use) at offset 22
        data[22..24].copy_from_slice(&1u16.to_le_bytes());

        // Embed a $DATA (0x80) resident attribute at offset 56
        let attr_off = 56usize;
        data[attr_off..attr_off + 4].copy_from_slice(&0x80u32.to_le_bytes()); // type
        data[attr_off + 4..attr_off + 8].copy_from_slice(&40u32.to_le_bytes()); // length
        data[attr_off + 8] = 0; // resident
        data[attr_off + 16..attr_off + 20].copy_from_slice(&1234u32.to_le_bytes()); // value length
        data[attr_off + 20..attr_off + 22].copy_from_slice(&24u16.to_le_bytes()); // value offset

        // End marker
        let end = attr_off + 40;
        data[end..end + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        data
    }

    #[test]
    fn mft_record_parse_magic() {
        let data = make_mft_record();
        let inode = parse_mft_record_minimal(&data, 5).unwrap();
        assert_eq!(inode.inode_num, 5);
    }

    #[test]
    fn mft_record_bad_magic() {
        let data = b"BADD\x00\x00\x00\x00".to_vec();
        assert!(parse_mft_record_minimal(&data, 0).is_none());
    }

    #[test]
    fn mft_record_too_short() {
        assert!(parse_mft_record_minimal(b"FILE", 0).is_none());
    }

    #[test]
    fn mft_record_link_count() {
        let data = make_mft_record();
        let inode = parse_mft_record_minimal(&data, 1).unwrap();
        assert_eq!(inode.link_count, 1);
    }

    #[test]
    fn mft_record_in_use_flag() {
        let data = make_mft_record();
        let inode = parse_mft_record_minimal(&data, 1).unwrap();
        // flags = 1 means in-use, so DELETED should NOT be set
        assert!(!inode.is_deleted());
    }

    // ── parse_ext4_inode_minimal ──────────────────────────────────────────────

    fn make_ext4_inode(
        mode: u16,
        uid: u16,
        size: u32,
        atime: u32,
        ctime: u32,
        mtime: u32,
        gid: u16,
        links: u16,
        blocks: u32,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(&mode.to_le_bytes());
        data[2..4].copy_from_slice(&uid.to_le_bytes());
        data[4..8].copy_from_slice(&size.to_le_bytes());
        data[8..12].copy_from_slice(&atime.to_le_bytes());
        data[12..16].copy_from_slice(&ctime.to_le_bytes());
        data[16..20].copy_from_slice(&mtime.to_le_bytes());
        data[24..26].copy_from_slice(&gid.to_le_bytes());
        data[26..28].copy_from_slice(&links.to_le_bytes());
        data[28..32].copy_from_slice(&blocks.to_le_bytes());
        data
    }

    #[test]
    fn ext4_inode_regular_file() {
        let data = make_ext4_inode(0x81A4, 1000, 4096, 1000, 2000, 3000, 1000, 1, 8);
        let inode = parse_ext4_inode_minimal(&data, 10).unwrap();
        assert_eq!(inode.inode_num, 10);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.link_count, 1);
        assert!(!inode.is_directory());
    }

    #[test]
    fn ext4_inode_directory() {
        let data = make_ext4_inode(0x41ED, 0, 0, 0, 0, 0, 0, 2, 0);
        let inode = parse_ext4_inode_minimal(&data, 2).unwrap();
        assert!(inode.is_directory());
    }

    #[test]
    fn ext4_inode_deleted() {
        let data = make_ext4_inode(0x81A4, 0, 512, 0, 0, 0, 0, 0, 0);
        let inode = parse_ext4_inode_minimal(&data, 100).unwrap();
        assert!(inode.is_deleted());
    }

    #[test]
    fn ext4_inode_too_short() {
        assert!(parse_ext4_inode_minimal(b"\x00\x00\x00\x00", 1).is_none());
    }

    #[test]
    fn ext4_inode_alloc_size() {
        // blocks = 8 → 8 * 512 = 4096
        let data = make_ext4_inode(0x81A4, 0, 100, 0, 0, 0, 0, 1, 8);
        let inode = parse_ext4_inode_minimal(&data, 1).unwrap();
        assert_eq!(inode.alloc_size, 4096);
    }
}
