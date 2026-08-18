//! NTFS forensics: parse MBR/GPT, find NTFS partitions, read VBR (NTFS boot sector),
//! parse $MFT entries (`standard_information`, `file_name`, data, $I30 index),
//! recover deleted files, and compute file timestamps.

use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────────

/// NTFS magic signature in VBR: "NTFS    " (8 bytes).
pub const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
/// MFT record magic: "FILE" (0x454C4946).
pub const MFT_FILE_MAGIC: u32 = 0x454C_4946;
/// MFT record magic: "BAAD" (corrupt record).
pub const MFT_BAAD_MAGIC: u32 = 0x4441_4142;
/// Size of a standard MFT record (1024 bytes).
pub const MFT_RECORD_SIZE: usize = 1024;
/// GPT partition type GUID for NTFS (little-endian bytes of EBD0A0A2-B9E5-4433-87C0-68B6B72699C7).
pub const NTFS_PARTITION_GUID: &[u8; 16] = &[
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];
/// NTFS attribute type codes.
pub mod attr_type {
    pub const STANDARD_INFORMATION: u32 = 0x10;
    pub const ATTRIBUTE_LIST: u32 = 0x20;
    pub const FILE_NAME: u32 = 0x30;
    pub const OBJECT_ID: u32 = 0x40;
    pub const SECURITY_DESCRIPTOR: u32 = 0x50;
    pub const VOLUME_NAME: u32 = 0x60;
    pub const VOLUME_INFORMATION: u32 = 0x70;
    pub const DATA: u32 = 0x80;
    pub const INDEX_ROOT: u32 = 0x90;
    pub const INDEX_ALLOCATION: u32 = 0xA0;
    pub const BITMAP: u32 = 0xB0;
    pub const REPARSE_POINT: u32 = 0xC0;
    pub const END: u32 = 0xFFFF_FFFF;
}

// ── NtfsTimestamp ─────────────────────────────────────────────────────────────

/// A Windows FILETIME timestamp (100-nanosecond intervals since 1601-01-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NtfsTimestamp(pub u64);

impl NtfsTimestamp {
    /// The Windows FILETIME epoch offset from Unix epoch in 100-ns units.
    const FILETIME_UNIX_OFFSET: u64 = 116_444_736_000_000_000;

    /// Create from raw FILETIME value.
    #[must_use]
    pub const fn new(filetime: u64) -> Self {
        Self(filetime)
    }

    /// Convert to Unix timestamp (seconds since 1970-01-01).
    #[must_use]
    pub const fn to_unix_secs(&self) -> i64 {
        if self.0 < Self::FILETIME_UNIX_OFFSET {
            return -((Self::FILETIME_UNIX_OFFSET - self.0) / 10_000_000).cast_signed();
        }
        ((self.0 - Self::FILETIME_UNIX_OFFSET) / 10_000_000).cast_signed()
    }

    /// Whether this timestamp is zero (unset).
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Parse from a little-endian byte slice (8 bytes).
    #[must_use]
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 8 {
            return Self(0);
        }
        Self(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

impl std::fmt::Display for NtfsTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unix = self.to_unix_secs();
        let (sign, abs_unix) = if unix < 0 {
            ("-", (-unix).cast_unsigned())
        } else {
            ("", unix.cast_unsigned())
        };
        let year_approx = 1970i64 + unix / 31_557_600;
        write!(f, "{sign}{abs_unix}s (≈{year_approx})")
    }
}

// ── MBR / GPT partition table ─────────────────────────────────────────────────

/// A partition entry from MBR or GPT.
#[derive(Debug, Clone)]
pub struct PartitionEntry {
    /// Partition type (0x07 = NTFS for MBR, GUID for GPT).
    pub partition_type: u8,
    /// Partition type GUID (GPT only; zeros for MBR).
    pub type_guid: [u8; 16],
    /// Start LBA (logical block address).
    pub start_lba: u64,
    /// Size in sectors.
    pub size_sectors: u64,
    /// Whether this is an NTFS partition.
    pub is_ntfs: bool,
}

impl PartitionEntry {
    /// Parse an MBR partition entry from 16 bytes.
    #[must_use]
    pub fn from_mbr(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let _status = data[0];
        let part_type = data[4];
        let start_lba = u64::from(u32::from_le_bytes([data[8], data[9], data[10], data[11]]));
        let size_sectors = u64::from(u32::from_le_bytes([data[12], data[13], data[14], data[15]]));
        if size_sectors == 0 {
            return None;
        }
        let is_ntfs = part_type == 0x07 || part_type == 0x17;
        Some(Self {
            partition_type: part_type,
            type_guid: [0u8; 16],
            start_lba,
            size_sectors,
            is_ntfs,
        })
    }

    /// Parse a GPT partition entry from 128 bytes.
    #[must_use]
    pub fn from_gpt(data: &[u8]) -> Option<Self> {
        if data.len() < 128 {
            return None;
        }
        let type_guid: [u8; 16] = data[0..16].try_into().ok()?;
        let start_lba = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let end_lba = u64::from_le_bytes(data[40..48].try_into().ok()?);
        if start_lba == 0 && end_lba == 0 {
            return None;
        }
        let size_sectors = end_lba.saturating_sub(start_lba) + 1;
        let is_ntfs = type_guid == *NTFS_PARTITION_GUID;
        Some(Self {
            partition_type: if is_ntfs { 0x07 } else { 0x00 },
            type_guid,
            start_lba,
            size_sectors,
            is_ntfs,
        })
    }
}

/// Parse MBR partition table (sectors 0..3, at offsets 0x1BE–0x1FE).
#[must_use]
pub fn parse_mbr_partitions(sector: &[u8]) -> Vec<PartitionEntry> {
    if sector.len() < 512 {
        return Vec::new();
    }
    // Check boot signature
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Vec::new();
    }
    (0..4)
        .filter_map(|i| {
            let off = 0x1BE + i * 16;
            PartitionEntry::from_mbr(&sector[off..off + 16])
        })
        .collect()
}

// ── NtfsVbr ───────────────────────────────────────────────────────────────────

/// NTFS Volume Boot Record (VBR / BPB).
#[derive(Debug, Clone)]
pub struct NtfsVbr {
    /// Bytes per sector (typically 512 or 4096).
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Total sectors on the volume.
    pub total_sectors: u64,
    /// LCN of $MFT.
    pub mft_lcn: u64,
    /// LCN of $`MFTMirr`.
    pub mft_mirr_lcn: u64,
    /// Clusters per MFT record (if positive) or 2^(-n) bytes if negative.
    pub clusters_per_mft_record: i8,
    /// Clusters per index block.
    pub clusters_per_index_block: i8,
    /// Volume serial number.
    pub volume_serial: u64,
}

impl NtfsVbr {
    /// Parse from a 512-byte VBR sector.
    ///
    /// Returns `None` if the NTFS signature is not found.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 84 {
            return None;
        }
        // Check OEM ID at offset 3
        if &data[3..11] != NTFS_OEM_ID {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
        let sectors_per_cluster = data[13];
        let total_sectors = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]);
        let mft_lcn = u64::from_le_bytes([
            data[48], data[49], data[50], data[51],
            data[52], data[53], data[54], data[55],
        ]);
        let mft_mirr_lcn = u64::from_le_bytes([
            data[56], data[57], data[58], data[59],
            data[60], data[61], data[62], data[63],
        ]);
        let clusters_per_mft_record = data[64].cast_signed();
        let clusters_per_index_block = data[68].cast_signed();
        let volume_serial = u64::from_le_bytes([
            data[72], data[73], data[74], data[75],
            data[76], data[77], data[78], data[79],
        ]);
        Some(Self {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_lcn,
            mft_mirr_lcn,
            clusters_per_mft_record,
            clusters_per_index_block,
            volume_serial,
        })
    }

    /// Return the cluster size in bytes.
    #[must_use]
    pub const fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Return the MFT record size in bytes.
    #[must_use]
    pub const fn mft_record_size(&self) -> u64 {
        if self.clusters_per_mft_record > 0 {
            self.cluster_size() * self.clusters_per_mft_record as u64
        } else {
            1u64 << (-(self.clusters_per_mft_record) as i32) as u32
        }
    }

    /// Return the byte offset of $MFT from the volume start.
    #[must_use]
    pub const fn mft_byte_offset(&self) -> u64 {
        self.mft_lcn * self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }
}

// ── FileAttribute ─────────────────────────────────────────────────────────────

/// An NTFS file attribute parsed from an MFT record.
#[derive(Debug, Clone)]
pub struct FileAttribute {
    /// Attribute type code.
    pub attr_type: u32,
    /// Attribute name (empty for unnamed attributes).
    pub name: String,
    /// Whether the attribute is non-resident.
    pub non_resident: bool,
    /// Resident attribute data (if resident).
    pub resident_data: Vec<u8>,
    /// Non-resident: starting VCN.
    pub start_vcn: u64,
    /// Non-resident: data size in bytes.
    pub data_size: u64,
}

impl FileAttribute {
    /// Create a resident attribute.
    #[must_use]
    pub const fn resident(attr_type: u32, data: Vec<u8>) -> Self {
        Self {
            attr_type,
            name: String::new(),
            non_resident: false,
            resident_data: data,
            start_vcn: 0,
            data_size: 0,
        }
    }

    /// Create a non-resident attribute.
    #[must_use]
    pub const fn non_resident(attr_type: u32, start_vcn: u64, data_size: u64) -> Self {
        Self {
            attr_type,
            name: String::new(),
            non_resident: true,
            resident_data: Vec::new(),
            start_vcn,
            data_size,
        }
    }

    /// Whether this is the $DATA attribute.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.attr_type == attr_type::DATA
    }

    /// Whether this is the $`FILE_NAME` attribute.
    #[must_use]
    pub const fn is_file_name(&self) -> bool {
        self.attr_type == attr_type::FILE_NAME
    }

    /// Whether this is the $`STANDARD_INFORMATION` attribute.
    #[must_use]
    pub const fn is_standard_information(&self) -> bool {
        self.attr_type == attr_type::STANDARD_INFORMATION
    }
}

// ── MftRecord ─────────────────────────────────────────────────────────────────

/// A parsed NTFS MFT record.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// MFT record number (inode).
    pub record_number: u64,
    /// Whether this record is in use (not deleted).
    pub in_use: bool,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Sequence number (for reference validation).
    pub sequence_number: u16,
    /// Hard-link count.
    pub hard_link_count: u16,
    /// Parsed attributes.
    pub attributes: Vec<FileAttribute>,
    /// File name (from $`FILE_NAME` attribute), if found.
    pub file_name: Option<String>,
    /// Parent directory record number.
    pub parent_record: Option<u64>,
    /// Timestamps from $`STANDARD_INFORMATION`.
    pub created: NtfsTimestamp,
    pub modified: NtfsTimestamp,
    pub mft_modified: NtfsTimestamp,
    pub accessed: NtfsTimestamp,
    /// File size in bytes (from $DATA attribute).
    pub file_size: u64,
}

impl MftRecord {
    /// Parse an MFT record from raw bytes.
    ///
    /// Returns `None` if the magic signature is invalid.
    #[must_use]
    pub fn parse(data: &[u8], record_number: u64) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MFT_FILE_MAGIC {
            return None;
        }
        let flags = u16::from_le_bytes([data[22], data[23]]);
        let in_use = flags & 0x01 != 0;
        let is_directory = flags & 0x02 != 0;
        let sequence_number = u16::from_le_bytes([data[16], data[17]]);
        let hard_link_count = u16::from_le_bytes([data[18], data[19]]);
        let attr_offset = u16::from_le_bytes([data[20], data[21]]) as usize;

        let mut rec = Self {
            record_number,
            in_use,
            is_directory,
            sequence_number,
            hard_link_count,
            attributes: Vec::new(),
            file_name: None,
            parent_record: None,
            created: NtfsTimestamp(0),
            modified: NtfsTimestamp(0),
            mft_modified: NtfsTimestamp(0),
            accessed: NtfsTimestamp(0),
            file_size: 0,
        };

        // Walk attributes
        let mut offset = attr_offset;
        while offset + 8 <= data.len() {
            let attr_type_code = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]);
            if attr_type_code == attr_type::END {
                break;
            }
            let attr_len = u32::from_le_bytes([
                data[offset+4], data[offset+5], data[offset+6], data[offset+7]
            ]) as usize;
            if attr_len == 0 || offset + attr_len > data.len() {
                break;
            }
            let attr_data = &data[offset..offset + attr_len];
            rec.parse_attribute(attr_type_code, attr_data);
            offset += attr_len;
        }
        Some(rec)
    }

    fn parse_attribute(&mut self, attr_type_code: u32, data: &[u8]) {
        if data.len() < 16 {
            return;
        }
        let non_resident = data[8] != 0;

        match attr_type_code {
            attr_type::STANDARD_INFORMATION => {
                // Resident: 48 or 72 bytes of timestamps and flags
                let content_off = u16::from_le_bytes([data[20], data[21]]) as usize;
                let content = &data[content_off.min(data.len())..];
                if content.len() >= 32 {
                    self.created = NtfsTimestamp::from_le_bytes(content);
                    self.modified = NtfsTimestamp::from_le_bytes(&content[8..]);
                    self.mft_modified = NtfsTimestamp::from_le_bytes(&content[16..]);
                    self.accessed = NtfsTimestamp::from_le_bytes(&content[24..]);
                }
                self.attributes.push(FileAttribute::resident(
                    attr_type_code,
                    content.to_vec(),
                ));
            }
            attr_type::FILE_NAME => {
                let content_off = u16::from_le_bytes([data[20], data[21]]) as usize;
                let content = &data[content_off.min(data.len())..];
                if content.len() >= 66 {
                    let parent_ref = u64::from_le_bytes([
                        content[0], content[1], content[2], content[3],
                        content[4], content[5], content[6], content[7],
                    ]);
                    self.parent_record = Some(parent_ref & 0x0000_FFFF_FFFF_FFFF);
                    let name_len = content[64] as usize;
                    let name_start = 66;
                    let name_end = name_start + name_len * 2;
                    if content.len() >= name_end {
                        let name_utf16: Vec<u16> = content[name_start..name_end]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        self.file_name = String::from_utf16(&name_utf16).ok();
                    }
                }
                self.attributes.push(FileAttribute::resident(
                    attr_type_code,
                    content.to_vec(),
                ));
            }
            attr_type::DATA => {
                if non_resident {
                    if data.len() >= 56 {
                        let start_vcn = u64::from_le_bytes(data[16..24].try_into().unwrap_or([0;8]));
                        let data_size = u64::from_le_bytes(data[48..56].try_into().unwrap_or([0;8]));
                        self.file_size = data_size;
                        self.attributes.push(FileAttribute::non_resident(
                            attr_type_code, start_vcn, data_size,
                        ));
                    }
                } else {
                    let content_len = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0;4])) as usize;
                    let content_off = u16::from_le_bytes([data[20], data[21]]) as usize;
                    let end = (content_off + content_len).min(data.len());
                    let content = data[content_off.min(data.len())..end].to_vec();
                    self.file_size = content.len() as u64;
                    self.attributes.push(FileAttribute::resident(attr_type_code, content));
                }
            }
            _ => {
                // Store other attributes as opaque resident data
                let content_off = if !non_resident && data.len() > 20 {
                    u16::from_le_bytes([data[20], data[21]]) as usize
                } else {
                    0
                };
                let content = if content_off < data.len() {
                    data[content_off..].to_vec()
                } else {
                    Vec::new()
                };
                self.attributes.push(FileAttribute::resident(attr_type_code, content));
            }
        }
    }

    /// Whether this record is deleted (not in use).
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        !self.in_use
    }

    /// Return the $DATA attribute, if present.
    #[must_use]
    pub fn data_attr(&self) -> Option<&FileAttribute> {
        self.attributes.iter().find(|a| a.is_data())
    }
}

// ── NtfsReader ────────────────────────────────────────────────────────────────

/// NTFS volume reader: parses a byte slice as an NTFS volume.
pub struct NtfsReader {
    /// Raw volume data.
    data: Vec<u8>,
    /// Parsed VBR.
    pub vbr: NtfsVbr,
    /// Cached MFT records.
    mft_cache: HashMap<u64, MftRecord>,
}

impl NtfsReader {
    /// Attempt to create a reader from raw volume bytes.
    ///
    /// # Errors
    /// Returns `Err(String)` if the VBR cannot be parsed.
    pub fn new(data: Vec<u8>) -> Result<Self, String> {
        let vbr = NtfsVbr::parse(&data)
            .ok_or_else(|| "not an NTFS volume: VBR signature not found".to_string())?;
        Ok(Self {
            data,
            vbr,
            mft_cache: HashMap::new(),
        })
    }

    /// Read `len` bytes from the volume at byte `offset`.
    #[must_use]
    pub fn read_bytes(&self, offset: u64, len: usize) -> &[u8] {
        let start = offset as usize;
        let end = (start + len).min(self.data.len());
        if start >= self.data.len() {
            return &[];
        }
        &self.data[start..end]
    }

    /// Read an MFT record by record number.
    pub fn read_mft_record(&mut self, record_number: u64) -> Option<&MftRecord> {
        if self.mft_cache.contains_key(&record_number) {
            return self.mft_cache.get(&record_number);
        }
        let mft_off = self.vbr.mft_byte_offset();
        let rec_size = self.vbr.mft_record_size() as usize;
        let byte_off = mft_off + record_number * rec_size as u64;
        let rec_bytes = self.read_bytes(byte_off, rec_size);
        let rec = MftRecord::parse(rec_bytes, record_number)?;
        self.mft_cache.insert(record_number, rec);
        self.mft_cache.get(&record_number)
    }

    /// Scan the entire MFT and return all parsed records.
    pub fn scan_mft(&mut self) -> Vec<MftRecord> {
        let mft_off = self.vbr.mft_byte_offset();
        let rec_size = self.vbr.mft_record_size() as usize;
        if rec_size == 0 {
            return Vec::new();
        }
        let max_records = (self.data.len().saturating_sub(mft_off as usize)) / rec_size;
        let max_records = max_records.min(65536); // safety cap
        let mut records = Vec::new();
        for i in 0..max_records as u64 {
            if let Some(rec) = self.read_mft_record(i) {
                records.push(rec.clone());
            }
        }
        records
    }

    /// Find all deleted files (MFT records with ALLOCATED flag cleared).
    pub fn recover_deleted(&mut self) -> Vec<MftRecord> {
        self.scan_mft()
            .into_iter()
            .filter(|r| r.is_deleted() && r.file_name.is_some())
            .collect()
    }

    /// List all active (non-deleted) files.
    pub fn list_files(&mut self) -> Vec<MftRecord> {
        self.scan_mft()
            .into_iter()
            .filter(|r| r.in_use && r.file_name.is_some())
            .collect()
    }

    /// Return total volume size in bytes.
    #[must_use]
    pub const fn volume_size(&self) -> u64 {
        self.vbr.total_sectors * self.vbr.bytes_per_sector as u64
    }

    /// Return the cluster size in bytes.
    #[must_use]
    pub const fn cluster_size(&self) -> u64 {
        self.vbr.cluster_size()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_vbr() -> Vec<u8> {
        let mut vbr = vec![0u8; 512];
        // OEM ID at offset 3
        vbr[3..11].copy_from_slice(NTFS_OEM_ID);
        // bytes_per_sector = 512
        vbr[11] = 0x00; vbr[12] = 0x02;
        // sectors_per_cluster = 8
        vbr[13] = 8;
        // total_sectors
        let ts: u64 = 0x0010_0000;
        vbr[40..48].copy_from_slice(&ts.to_le_bytes());
        // mft_lcn = 4
        vbr[48..56].copy_from_slice(&4u64.to_le_bytes());
        // mft_mirr_lcn = 2
        vbr[56..64].copy_from_slice(&2u64.to_le_bytes());
        // clusters_per_mft_record = -10 (means 2^10 = 1024 bytes)
        vbr[64] = (-10i8) as u8;
        // clusters_per_index_block = 1
        vbr[68] = 1;
        // volume_serial
        vbr[72..80].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        vbr
    }

    #[test]
    fn test_ntfs_vbr_parse() {
        let vbr_bytes = make_fake_vbr();
        let vbr = NtfsVbr::parse(&vbr_bytes).expect("should parse");
        assert_eq!(vbr.bytes_per_sector, 512);
        assert_eq!(vbr.sectors_per_cluster, 8);
        assert_eq!(vbr.mft_lcn, 4);
    }

    #[test]
    fn test_ntfs_vbr_cluster_size() {
        let vbr_bytes = make_fake_vbr();
        let vbr = NtfsVbr::parse(&vbr_bytes).unwrap();
        assert_eq!(vbr.cluster_size(), 512 * 8);
    }

    #[test]
    fn test_ntfs_vbr_mft_record_size_negative() {
        let vbr_bytes = make_fake_vbr();
        let vbr = NtfsVbr::parse(&vbr_bytes).unwrap();
        // clusters_per_mft_record = -10 → 2^10 = 1024
        assert_eq!(vbr.mft_record_size(), 1024);
    }

    #[test]
    fn test_ntfs_vbr_invalid_signature() {
        let data = vec![0u8; 512];
        assert!(NtfsVbr::parse(&data).is_none());
    }

    #[test]
    fn test_ntfs_timestamp_unix_conversion() {
        // 2024-01-01T00:00:00Z as FILETIME = 133484160000000000
        let ts = NtfsTimestamp::new(133_484_160_000_000_000);
        let unix = ts.to_unix_secs();
        // Should be close to 1704067200
        assert!(unix > 1_700_000_000 && unix < 1_710_000_000);
    }

    #[test]
    fn test_ntfs_timestamp_zero() {
        let ts = NtfsTimestamp::new(0);
        assert!(ts.is_zero());
    }

    #[test]
    fn test_ntfs_timestamp_from_bytes() {
        let val: u64 = 133_484_160_000_000_000;
        let bytes = val.to_le_bytes();
        let ts = NtfsTimestamp::from_le_bytes(&bytes);
        assert_eq!(ts.0, val);
    }

    #[test]
    fn test_mbr_parse_empty() {
        let data = vec![0u8; 512];
        let parts = parse_mbr_partitions(&data);
        assert!(parts.is_empty()); // no boot signature
    }

    #[test]
    fn test_mbr_parse_with_signature() {
        let mut sector = vec![0u8; 512];
        sector[510] = 0x55;
        sector[511] = 0xAA;
        // Write a fake NTFS partition entry at 0x1BE
        let off = 0x1BE;
        sector[off] = 0x80; // active
        sector[off + 4] = 0x07; // NTFS type
        // start_lba = 2048
        let start: u32 = 2048;
        sector[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        // size = 10000 sectors
        let size: u32 = 10000;
        sector[off + 12..off + 16].copy_from_slice(&size.to_le_bytes());
        let parts = parse_mbr_partitions(&sector);
        assert!(!parts.is_empty());
        assert!(parts[0].is_ntfs);
        assert_eq!(parts[0].start_lba, 2048);
    }

    #[test]
    fn test_mft_record_invalid_magic() {
        let data = vec![0u8; 1024];
        assert!(MftRecord::parse(&data, 0).is_none());
    }

    #[test]
    fn test_mft_record_parse_basic() {
        let mut data = vec![0u8; 1024];
        // Write FILE magic
        data[0..4].copy_from_slice(b"FILE");
        // update sequence offset = 48 (beyond attr_offset)
        data[4] = 48; data[5] = 0;
        // update sequence size = 3
        data[6] = 3; data[7] = 0;
        // sequence number = 1
        data[16] = 1;
        // hard link count = 1
        data[18] = 1;
        // attribute offset (first attribute) = 48
        data[20] = 48; data[21] = 0;
        // flags: in_use = 1
        data[22] = 1;
        // Write END attribute marker at offset 48
        data[48..52].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let rec = MftRecord::parse(&data, 5).expect("should parse FILE record");
        assert_eq!(rec.record_number, 5);
        assert!(rec.in_use);
        assert!(!rec.is_directory);
    }

    #[test]
    fn test_file_attribute_resident() {
        let attr = FileAttribute::resident(0x80, vec![1, 2, 3]);
        assert!(attr.is_data());
        assert!(!attr.non_resident);
        assert_eq!(attr.resident_data, vec![1, 2, 3]);
    }

    #[test]
    fn test_file_attribute_non_resident() {
        let attr = FileAttribute::non_resident(0x80, 0, 4096);
        assert!(attr.is_data());
        assert!(attr.non_resident);
        assert_eq!(attr.data_size, 4096);
    }

    #[test]
    fn test_ntfs_reader_invalid_vbr() {
        let data = vec![0u8; 512];
        assert!(NtfsReader::new(data).is_err());
    }

    #[test]
    fn test_ntfs_reader_volume_size() {
        let mut vol = make_fake_vbr();
        vol.resize(512 * 1024, 0);
        let reader = NtfsReader::new(vol).unwrap();
        assert!(reader.volume_size() > 0);
    }

    #[test]
    fn test_ntfs_reader_cluster_size() {
        let mut vol = make_fake_vbr();
        vol.resize(512 * 1024, 0);
        let reader = NtfsReader::new(vol).unwrap();
        assert_eq!(reader.cluster_size(), 512 * 8);
    }

    #[test]
    fn test_gpt_partition_ntfs() {
        let mut entry = vec![0u8; 128];
        entry[0..16].copy_from_slice(NTFS_PARTITION_GUID);
        let start: u64 = 2048;
        let end: u64 = 1048575;
        entry[32..40].copy_from_slice(&start.to_le_bytes());
        entry[40..48].copy_from_slice(&end.to_le_bytes());
        let part = PartitionEntry::from_gpt(&entry).unwrap();
        assert!(part.is_ntfs);
        assert_eq!(part.start_lba, 2048);
    }
}
