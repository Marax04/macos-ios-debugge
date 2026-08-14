
// ── Ext4 on-disk structures ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mount_time: u32,
    pub write_time: u32,
    pub magic: u16,
    pub state: u16,
    pub errors_behavior: u16,
    pub creator_os: u32,
    pub rev_level: u32,
    pub first_inode: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub volume_name: String,
    pub last_mounted: String,
    pub uuid: [u8; 16],
    pub journal_inum: u32,
    pub desc_size: u16,
}

impl Ext4Superblock {
    #[must_use] 
    pub fn block_size(&self) -> u64 {
        // log_block_size is from disk; cap shift to avoid panic/overflow.
        let shift = self.log_block_size.min(20); // max 1 GiB blocks
        1024u64 << shift
    }

    #[must_use] 
    pub const fn group_count(&self) -> u64 {
        if self.blocks_per_group == 0 { return 0; }
        (self.blocks_count + (self.blocks_per_group) as u64 - 1) / (self.blocks_per_group) as u64
    }

    #[must_use] 
    pub const fn has_64bit(&self) -> bool {
        self.feature_incompat & 0x80 != 0
    }

    #[must_use] 
    pub const fn has_extents(&self) -> bool {
        self.feature_incompat & 0x40 != 0
    }

    #[must_use] 
    pub const fn has_dir_index(&self) -> bool {
        self.feature_compat & 0x20 != 0
    }

    #[must_use] 
    pub const fn has_large_file(&self) -> bool {
        self.feature_ro_compat & 0x2 != 0
    }

    #[must_use] 
    pub const fn has_sparse_super(&self) -> bool {
        self.feature_ro_compat & 0x1 != 0
    }

    #[must_use] 
    pub const fn has_dir_nlink(&self) -> bool {
        self.feature_ro_compat & 0x20 != 0
    }

    #[must_use] 
    pub const fn has_metadata_csum(&self) -> bool {
        self.feature_ro_compat & 0x400 != 0
    }
}

#[derive(Debug, Clone)]
pub struct Ext4BlockGroupDesc {
    pub block_bitmap_lo: u32,
    pub inode_bitmap_lo: u32,
    pub inode_table_lo: u32,
    pub free_blocks_count_lo: u16,
    pub free_inodes_count_lo: u16,
    pub used_dirs_count_lo: u16,
    pub flags: u16,
    pub block_bitmap_hi: u32,
    pub inode_bitmap_hi: u32,
    pub inode_table_hi: u32,
    pub free_blocks_count_hi: u16,
    pub free_inodes_count_hi: u16,
    pub used_dirs_count_hi: u16,
    pub itable_unused_lo: u16,
    pub itable_unused_hi: u16,
    pub checksum: u16,
}

impl Ext4BlockGroupDesc {
    #[must_use] 
    pub const fn block_bitmap(&self) -> u64 {
        (self.block_bitmap_lo) as u64 | ((self.block_bitmap_hi as u64) << 32)
    }

    #[must_use] 
    pub const fn inode_bitmap(&self) -> u64 {
        (self.inode_bitmap_lo) as u64 | ((self.inode_bitmap_hi as u64) << 32)
    }

    #[must_use] 
    pub const fn inode_table(&self) -> u64 {
        (self.inode_table_lo) as u64 | ((self.inode_table_hi as u64) << 32)
    }

    #[must_use] 
    pub const fn free_blocks_count(&self) -> u32 {
        (self.free_blocks_count_lo) as u32 | ((self.free_blocks_count_hi as u32) << 16)
    }

    #[must_use] 
    pub const fn free_inodes_count(&self) -> u32 {
        (self.free_inodes_count_lo) as u32 | ((self.free_inodes_count_hi as u32) << 16)
    }
}

// ── Inode ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ext4Inode {
    pub inode_num: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub links_count: u16,
    pub blocks: u64,
    pub flags: u32,
    pub block_data: [u32; 15],
    pub generation: u32,
    pub file_acl: u64,
    pub crtime: u32,
    pub extra_isize: u16,
}

impl Ext4Inode {
    #[must_use] 
    pub const fn file_type(&self) -> Ext4FileType {
        match self.mode & 0xF000 {
            0x8000 => Ext4FileType::RegularFile,
            0x4000 => Ext4FileType::Directory,
            0xA000 => Ext4FileType::Symlink,
            0x6000 => Ext4FileType::BlockDevice,
            0x2000 => Ext4FileType::CharDevice,
            0x1000 => Ext4FileType::Fifo,
            0xC000 => Ext4FileType::Socket,
            _ => Ext4FileType::Unknown,
        }
    }

    #[must_use] 
    pub fn perms(&self) -> String {
        let ft = match self.file_type() {
            Ext4FileType::RegularFile => '-',
            Ext4FileType::Directory => 'd',
            Ext4FileType::Symlink => 'l',
            Ext4FileType::BlockDevice => 'b',
            Ext4FileType::CharDevice => 'c',
            Ext4FileType::Fifo => 'p',
            Ext4FileType::Socket => 's',
            Ext4FileType::Unknown => '?',
        };
        let m = self.mode;
        let bits = |shift: u16| -> String {
            let r = if m & (0x100 >> (shift) as u32) as u16 != 0 { 'r' } else { '-' };
            let w = if m & (0x080 >> (shift) as u32) as u16 != 0 { 'w' } else { '-' };
            let x = if m & (0x040 >> (shift) as u32) as u16 != 0 { 'x' } else { '-' };
            format!("{r}{w}{x}")
        };
        format!("{}{}{}{}", ft, bits(0), bits(3), bits(6))
    }

    #[must_use] 
    pub const fn has_extent_tree(&self) -> bool {
        self.flags & 0x80000 != 0
    }

    #[must_use] 
    pub const fn is_deleted(&self) -> bool {
        self.dtime != 0 && self.links_count == 0
    }

    #[must_use] 
    pub const fn is_inline_data(&self) -> bool {
        self.flags & 0x1000_0000 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ext4FileType {
    Unknown,
    RegularFile,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

// ── Extent tree ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ext4ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max_entries: u16,
    pub depth: u16,
    pub generation: u32,
}

#[derive(Debug, Clone)]
pub struct Ext4Extent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_start_hi: u16,
    pub ee_start_lo: u32,
}

impl Ext4Extent {
    #[must_use] 
    pub const fn start_block(&self) -> u64 {
        (self.ee_start_lo) as u64 | ((self.ee_start_hi as u64) << 32)
    }

    #[must_use] 
    pub const fn len(&self) -> u32 {
        if self.ee_len > 0x8000 {
            (self.ee_len - 0x8000) as u32
        } else {
            (self.ee_len) as u32
        }
    }

    #[must_use] 
    pub const fn is_uninitialized(&self) -> bool {
        self.ee_len > 0x8000
    }
}

#[derive(Debug, Clone)]
pub struct Ext4ExtentIndex {
    pub ei_block: u32,
    pub ei_leaf_lo: u32,
    pub ei_leaf_hi: u16,
}

impl Ext4ExtentIndex {
    #[must_use] 
    pub const fn leaf(&self) -> u64 {
        (self.ei_leaf_lo) as u64 | ((self.ei_leaf_hi as u64) << 32)
    }
}

// ── Directory entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ext4DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: String,
}

impl Ext4DirEntry {
    #[must_use] 
    pub const fn entry_type(&self) -> Ext4FileType {
        match self.file_type {
            1 => Ext4FileType::RegularFile,
            2 => Ext4FileType::Directory,
            3 => Ext4FileType::CharDevice,
            4 => Ext4FileType::BlockDevice,
            5 => Ext4FileType::Fifo,
            6 => Ext4FileType::Socket,
            7 => Ext4FileType::Symlink,
            _ => Ext4FileType::Unknown,
        }
    }

    #[must_use] 
    pub const fn is_deleted(&self) -> bool {
        self.inode == 0
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub struct Ext4Parser<'a> {
    data: &'a [u8],
    pub sb: Ext4Superblock,
}

impl<'a> Ext4Parser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 0x800 {
            return Err("data too small for ext4 superblock".to_string());
        }
        let sb = Self::parse_superblock(&data[0x400..0x800])?;
        if sb.magic != 0xEF53 {
            return Err(format!("invalid ext4 magic: 0x{:x}", sb.magic));
        }
        Ok(Self { data, sb })
    }

    fn parse_superblock(b: &[u8]) -> Result<Ext4Superblock, String> {
        if b.len() < 0x400 { return Err("superblock too small".to_string()); }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]])
        };
        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes([b[off], b[off+1]])
        };
        let inodes_count = r32(0);
        let blocks_count_lo = r32(4) as u64;
        let free_blocks_lo = r32(12) as u64;
        let free_inodes = r32(16);
        let first_data_block = r32(20);
        let log_block_size = r32(24);
        let blocks_per_group = r32(32);
        let inodes_per_group = r32(40);
        let mount_time = r32(44);
        let write_time = r32(48);
        let magic = r16(56);
        let state = r16(58);
        let errors_behavior = r16(60);
        let creator_os = r32(72);
        let rev_level = r32(76);
        let first_inode = if rev_level >= 1 { r32(84) } else { 11 };
        let inode_size = if rev_level >= 1 { r16(88) } else { 128 };
        let feature_compat = r32(92);
        let feature_incompat = r32(96);
        let feature_ro_compat = r32(100);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[104..120]);
        let vol_bytes: Vec<u8> = b[120..136].iter().take_while(|&&x| x != 0).copied().collect();
        let volume_name = String::from_utf8_lossy(&vol_bytes).to_string();
        let mnt_bytes: Vec<u8> = b[136..200].iter().take_while(|&&x| x != 0).copied().collect();
        let last_mounted = String::from_utf8_lossy(&mnt_bytes).to_string();
        let journal_inum = r32(232);
        let blocks_count_hi = if b.len() >= 0x150 { r32(0x150) as u64 } else { 0 };
        let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
        let free_blocks_hi = if b.len() >= 0x168 { r32(0x168) as u64 } else { 0 };
        let free_blocks_count = free_blocks_lo | (free_blocks_hi << 32);
        let desc_size = if b.len() >= 0xFE { r16(0xFE) } else { 32 };
        Ok(Ext4Superblock {
            inodes_count, blocks_count, free_blocks_count, free_inodes_count: free_inodes,
            first_data_block, log_block_size, blocks_per_group, inodes_per_group,
            mount_time, write_time, magic, state, errors_behavior, creator_os, rev_level,
            first_inode, inode_size, feature_compat, feature_incompat, feature_ro_compat,
            volume_name, last_mounted, uuid, journal_inum, desc_size,
        })
    }

    #[must_use] 
    pub fn block_offset(&self, block: u64) -> usize {
        // Use saturating arithmetic to avoid overflow when block number or size is large.
        block
            .saturating_mul(self.sb.block_size())
            .min(usize::MAX as u64) as usize
    }

    #[must_use] 
    pub fn read_block(&self, block: u64) -> Option<&[u8]> {
        let off = self.block_offset(block);
        let end = off + self.sb.block_size() as usize;
        if end <= self.data.len() { Some(&self.data[off..end]) } else { None }
    }

    #[must_use] 
    pub fn parse_block_group_desc(&self, group: u64) -> Option<Ext4BlockGroupDesc> {
        let bs = self.sb.block_size();
        let gdt_block = if bs == 1024 { 2u64 } else { 1 };
        let desc_size = (self.sb.desc_size) as u64;
        let off = self.block_offset(gdt_block) + (group * desc_size) as usize;
        if off + 32 > self.data.len() { return None; }
        let b = &self.data[off..];
        let r32 = |o: usize| u32::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3]]);
        let r16 = |o: usize| u16::from_le_bytes([b[o], b[o+1]]);
        let (block_bitmap_hi, inode_bitmap_hi, inode_table_hi, fbc_hi, fic_hi, udc_hi, itu_hi) =
            if desc_size >= 64 && off + 64 <= self.data.len() {
                (r32(32), r32(36), r32(40), r16(44), r16(46), r16(48), r16(56))
            } else { (0, 0, 0, 0, 0, 0, 0) };
        Some(Ext4BlockGroupDesc {
            block_bitmap_lo: r32(0), inode_bitmap_lo: r32(4), inode_table_lo: r32(8),
            free_blocks_count_lo: r16(12), free_inodes_count_lo: r16(14),
            used_dirs_count_lo: r16(16), flags: r16(18),
            block_bitmap_hi, inode_bitmap_hi, inode_table_hi,
            free_blocks_count_hi: fbc_hi, free_inodes_count_hi: fic_hi,
            used_dirs_count_hi: udc_hi, itable_unused_lo: r16(20), itable_unused_hi: itu_hi,
            checksum: r16(30),
        })
    }

    #[must_use] 
    pub fn parse_inode(&self, inode_num: u32) -> Option<Ext4Inode> {
        if inode_num == 0 { return None; }
        let idx = (inode_num - 1) as u64;
        let group = idx / (self.sb.inodes_per_group) as u64;
        let local_idx = idx % (self.sb.inodes_per_group) as u64;
        let desc = self.parse_block_group_desc(group)?;
        let inode_table_block = desc.inode_table();
        let inode_size = (self.sb.inode_size) as u64;
        let off = self.block_offset(inode_table_block) + (local_idx * inode_size) as usize;
        if off + 128 > self.data.len() { return None; }
        let b = &self.data[off..];
        let r32 = |o: usize| u32::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3]]);
        let r16 = |o: usize| u16::from_le_bytes([b[o], b[o+1]]);
        let mode = r16(0);
        let uid_lo = r16(2) as u32;
        let size_lo = r32(4) as u64;
        let atime = r32(8);
        let ctime = r32(12);
        let mtime = r32(16);
        let dtime = r32(20);
        let gid_lo = r16(24) as u32;
        let links_count = r16(26);
        let blocks_lo = r32(28) as u64;
        let flags = r32(32);
        let mut block_data = [0u32; 15];
        for i in 0..15 { block_data[i] = r32(40 + i * 4); }
        let generation = r32(100);
        let size_hi = r32(108) as u64;
        let size = size_lo | (size_hi << 32);
        let file_acl = r32(104) as u64;
        let (uid, gid) = if inode_size >= 156 && off + 156 <= self.data.len() {
            let uid_hi = r16(120) as u32;
            let gid_hi = r16(122) as u32;
            (uid_lo | (uid_hi << 16), gid_lo | (gid_hi << 16))
        } else { (uid_lo, gid_lo) };
        let blocks = blocks_lo * 512 / self.sb.block_size();
        let (crtime, extra_isize) = if inode_size >= 160 && off + 160 <= self.data.len() {
            (r32(144), r16(128))
        } else { (0, 0) };
        Some(Ext4Inode { inode_num, mode, uid, gid, size, atime, ctime, mtime, dtime,
            links_count, blocks, flags, block_data, generation, file_acl, crtime, extra_isize })
    }

    #[must_use] 
    pub fn parse_extents(&self, inode: &Ext4Inode) -> Vec<Ext4Extent> {
        if !inode.has_extent_tree() { return Vec::new(); }
        let b: Vec<u8> = inode.block_data.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let mut extents = Vec::new();
        self.parse_extent_tree(&b, &mut extents, 0);
        extents
    }

    fn parse_extent_tree(&self, b: &[u8], extents: &mut Vec<Ext4Extent>, depth_guard: u32) {
        if depth_guard > 5 || b.len() < 12 { return; }
        let magic = u16::from_le_bytes([b[0], b[1]]);
        if magic != 0xF30A { return; }
        let entries = u16::from_le_bytes([b[2], b[3]]) as usize;
        let depth = u16::from_le_bytes([b[6], b[7]]);
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > b.len() { break; }
            if depth == 0 {
                let ee_block = u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]);
                let ee_len = u16::from_le_bytes([b[off+4], b[off+5]]);
                let ee_start_hi = u16::from_le_bytes([b[off+6], b[off+7]]);
                let ee_start_lo = u32::from_le_bytes([b[off+8], b[off+9], b[off+10], b[off+11]]);
                extents.push(Ext4Extent { ee_block, ee_len, ee_start_hi, ee_start_lo });
            } else {
                let idx = Ext4ExtentIndex {
                    ei_block: u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]),
                    ei_leaf_lo: u32::from_le_bytes([b[off+4], b[off+5], b[off+6], b[off+7]]),
                    ei_leaf_hi: u16::from_le_bytes([b[off+8], b[off+9]]),
                };
                if let Some(leaf_block) = self.read_block(idx.leaf()) {
                    self.parse_extent_tree(leaf_block, extents, depth_guard + 1);
                }
            }
        }
    }

    #[must_use] 
    pub fn list_directory(&self, inode: &Ext4Inode) -> Vec<Ext4DirEntry> {
        let mut entries = Vec::new();
        let extents = self.parse_extents(inode);
        for ext in &extents {
            for blk in 0..ext.len() {
                let block = ext.start_block() + (blk) as u64;
                if let Some(data) = self.read_block(block) {
                    let mut off = 0;
                    while off + 8 <= data.len() {
                        let inode_num = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
                        let rec_len = u16::from_le_bytes([data[off+4], data[off+5]]) as usize;
                        if rec_len < 8 || off + rec_len > data.len() { break; }
                        let name_len = data[off+6] as usize;
                        let file_type = data[off+7];
                        let name = if off + 8 + name_len <= data.len() {
                            String::from_utf8_lossy(&data[off+8..off+8+name_len]).to_string()
                        } else { String::new() };
                        entries.push(Ext4DirEntry { inode: inode_num, rec_len: rec_len as u16, name_len: name_len as u8, file_type, name });
                        off += rec_len;
                    }
                }
            }
        }
        entries
    }

    #[must_use] 
    pub fn find_deleted_inodes(&self) -> Vec<Ext4Inode> {
        let mut deleted = Vec::new();
        for i in 1..=self.sb.inodes_count {
            if let Some(inode) = self.parse_inode(i)
                && inode.is_deleted() && inode.size > 0 {
                    deleted.push(inode);
                }
        }
        deleted
    }

    #[must_use] 
    pub fn stats(&self) -> Ext4FsStats {
        let block_size = self.sb.block_size();
        // Both counts come from the superblock, so the product can exceed u64.
        // The `saturating_sub` below already guards its own case; this multiply
        // was the one left bare.
        let total_space = self.sb.blocks_count.saturating_mul(block_size);
        let free_space = self.sb.free_blocks_count.saturating_mul(block_size);
        let used_space = total_space.saturating_sub(free_space);
        let inodes_used = self.sb.inodes_count.saturating_sub(self.sb.free_inodes_count);
        Ext4FsStats {
            volume_name: self.sb.volume_name.clone(),
            block_size,
            total_blocks: self.sb.blocks_count,
            free_blocks: self.sb.free_blocks_count,
            total_inodes: self.sb.inodes_count,
            free_inodes: self.sb.free_inodes_count,
            inodes_used,
            total_space,
            used_space,
            free_space,
            group_count: self.sb.group_count(),
            has_journal: self.sb.journal_inum != 0,
            has_extents: self.sb.has_extents(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ext4FsStats {
    pub volume_name: String,
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u32,
    pub free_inodes: u32,
    pub inodes_used: u32,
    pub total_space: u64,
    pub used_space: u64,
    pub free_space: u64,
    pub group_count: u64,
    pub has_journal: bool,
    pub has_extents: bool,
}

impl Ext4FsStats {
    #[must_use] 
    pub fn usage_percent(&self) -> f64 {
        if self.total_space == 0 { return 0.0; }
        self.used_space as f64 / self.total_space as f64 * 100.0
    }

    #[must_use] 
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Volume: {}\n", self.volume_name));
        s.push_str(&format!("Block size: {} bytes\n", self.block_size));
        s.push_str(&format!("Total blocks: {} ({} MB)\n", self.total_blocks, self.total_space / 1_048_576));
        s.push_str(&format!("Used: {} MB ({:.1}%)\n", self.used_space / 1_048_576, self.usage_percent()));
        s.push_str(&format!("Free: {} MB\n", self.free_space / 1_048_576));
        s.push_str(&format!("Inodes: {}/{} used\n", self.inodes_used, self.total_inodes));
        s.push_str(&format!("Block groups: {}\n", self.group_count));
        s.push_str(&format!("Journal: {}\n", if self.has_journal { "yes" } else { "no" }));
        s.push_str(&format!("Extents: {}\n", if self.has_extents { "yes" } else { "no" }));
        s
    }
}
