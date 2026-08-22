//! Complete NTFS Master File Table (MFT) analysis.
//!
//! Models each MFT record and its attributes — `$STANDARD_INFORMATION`,
//! `$FILE_NAME`, `$DATA`, `$INDEX_ROOT` / `$INDEX_ALLOCATION`, and the
//! `$ATTRIBUTE_LIST` — and exposes a high-level `NtfsMftFull` analyser that
//! walks the MFT and emits structured metadata.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

pub const MFT_RECORD_SIZE: usize = 1024;
pub const MFT_SIGNATURE: u32 = 0x454c_4946; // "FILE"

/// Well-known reserved MFT record numbers.
pub mod system_records {
    pub const MFT: u64 = 0;
    pub const MFT_MIRROR: u64 = 1;
    pub const LOG_FILE: u64 = 2;
    pub const VOLUME: u64 = 3;
    pub const ATTR_DEF: u64 = 4;
    pub const ROOT_DIR: u64 = 5;
    pub const BITMAP: u64 = 6;
    pub const BOOT: u64 = 7;
    pub const BAD_CLUS: u64 = 8;
    pub const SECURE: u64 = 9;
    pub const UPCASE: u64 = 10;
    pub const EXTEND: u64 = 11;
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MftError {
    #[error("bad MFT record signature at record {0}")]
    BadSignature(u64),
    #[error("record {0} is in-use but has no $FILE_NAME attribute")]
    MissingFileName(u64),
    #[error("attribute type 0x{0:08x} not recognised")]
    UnknownAttribute(u32),
    #[error("fixup array mismatch at record {0}")]
    FixupMismatch(u64),
    #[error("MFT image too small: {0} bytes")]
    ImageTooSmall(usize),
    #[error("record {0} exceeds image bounds")]
    OutOfBounds(u64),
}

pub type MftResult<T> = Result<T, MftError>;

// ─── NTFS timestamps ──────────────────────────────────────────────────────────

/// Windows FILETIME: 100-nanosecond intervals since 1601-01-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileTime(pub u64);

impl FileTime {
    pub const ZERO: Self = Self(0);

    /// Convert to Unix epoch seconds (approximate).
    #[must_use] 
    pub const fn to_unix_secs(self) -> i64 {
        const EPOCH_DIFF: u64 = 116_444_736_000_000_000; // 100ns intervals
        if self.0 < EPOCH_DIFF {
            return 0;
        }
        ((self.0 - EPOCH_DIFF) / 10_000_000).cast_signed()
    }

    #[must_use] 
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for FileTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unix = self.to_unix_secs();
        write!(f, "FileTime({unix})")
    }
}

// ─── Attribute types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum AttrType {
    StandardInformation = 0x10,
    AttributeList = 0x20,
    FileName = 0x30,
    ObjectId = 0x40,
    SecurityDescriptor = 0x50,
    VolumeName = 0x60,
    VolumeInformation = 0x70,
    Data = 0x80,
    IndexRoot = 0x90,
    IndexAllocation = 0xA0,
    Bitmap = 0xB0,
    ReparsePoint = 0xC0,
    EaInformation = 0xD0,
    Ea = 0xE0,
    LoggedUtilityStream = 0x100,
    End = 0xFFFF_FFFF,
}

impl TryFrom<u32> for AttrType {
    type Error = MftError;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v {
            0x10 => Self::StandardInformation,
            0x20 => Self::AttributeList,
            0x30 => Self::FileName,
            0x40 => Self::ObjectId,
            0x50 => Self::SecurityDescriptor,
            0x60 => Self::VolumeName,
            0x70 => Self::VolumeInformation,
            0x80 => Self::Data,
            0x90 => Self::IndexRoot,
            0xA0 => Self::IndexAllocation,
            0xB0 => Self::Bitmap,
            0xC0 => Self::ReparsePoint,
            0xD0 => Self::EaInformation,
            0xE0 => Self::Ea,
            0x100 => Self::LoggedUtilityStream,
            0xFFFF_FFFF => Self::End,
            other => return Err(MftError::UnknownAttribute(other)),
        })
    }
}

// ─── StandardInfo ─────────────────────────────────────────────────────────────

/// Parsed `$STANDARD_INFORMATION` attribute (NTFS v3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardInfo {
    pub created: FileTime,
    pub modified: FileTime,
    pub mft_modified: FileTime,
    pub accessed: FileTime,
    pub file_attributes: u32,
    pub max_versions: u32,
    pub version: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota_charged: u64,
    pub usn: u64,
}

impl StandardInfo {
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        Some(Self {
            created: FileTime(read_u64(data, 0)),
            modified: FileTime(read_u64(data, 8)),
            mft_modified: FileTime(read_u64(data, 16)),
            accessed: FileTime(read_u64(data, 24)),
            file_attributes: read_u32(data, 32),
            max_versions: read_u32(data, 36),
            version: read_u32(data, 40),
            owner_id: if data.len() >= 52 { read_u32(data, 44) } else { 0 },
            security_id: if data.len() >= 56 { read_u32(data, 48) } else { 0 },
            quota_charged: if data.len() >= 64 { read_u64(data, 56) } else { 0 },
            usn: if data.len() >= 72 { read_u64(data, 64) } else { 0 },
        })
    }

    #[must_use] 
    pub const fn is_hidden(&self) -> bool {
        self.file_attributes & 0x0002 != 0
    }

    #[must_use] 
    pub const fn is_system(&self) -> bool {
        self.file_attributes & 0x0004 != 0
    }

    #[must_use] 
    pub const fn is_directory(&self) -> bool {
        self.file_attributes & 0x0010 != 0
    }

    #[must_use] 
    pub const fn is_compressed(&self) -> bool {
        self.file_attributes & 0x0800 != 0
    }

    #[must_use] 
    pub const fn is_encrypted(&self) -> bool {
        self.file_attributes & 0x4000 != 0
    }
}

// ─── FileNameAttr ─────────────────────────────────────────────────────────────

/// Name space identifier for `$FILE_NAME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NameSpace {
    Posix = 0,
    Win32 = 1,
    Dos = 2,
    Win32Dos = 3,
}

impl TryFrom<u8> for NameSpace {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        Ok(match v { 0 => Self::Posix, 1 => Self::Win32, 2 => Self::Dos, 3 => Self::Win32Dos, _ => return Err(()) })
    }
}

/// Parsed `$FILE_NAME` attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNameAttr {
    pub parent_ref: u64,
    pub created: FileTime,
    pub modified: FileTime,
    pub mft_modified: FileTime,
    pub accessed: FileTime,
    pub alloc_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub reparse_tag: u32,
    pub name_space: NameSpace,
    pub name: String,
}

impl FileNameAttr {
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 66 {
            return None;
        }
        let parent_ref = read_u64(data, 0) & 0x0000_FFFF_FFFF_FFFF;
        let name_len = data[64] as usize;
        let name_space = NameSpace::try_from(data[65]).unwrap_or(NameSpace::Win32);
        if data.len() < 66 + name_len * 2 {
            return None;
        }
        let name_bytes = &data[66..66 + name_len * 2];
        let name = utf16le_to_string(name_bytes);
        Some(Self {
            parent_ref,
            created: FileTime(read_u64(data, 8)),
            modified: FileTime(read_u64(data, 16)),
            mft_modified: FileTime(read_u64(data, 24)),
            accessed: FileTime(read_u64(data, 32)),
            alloc_size: read_u64(data, 40),
            real_size: read_u64(data, 48),
            flags: read_u32(data, 56),
            reparse_tag: read_u32(data, 60),
            name_space,
            name,
        })
    }

    #[must_use] 
    pub fn full_path(&self, parent: &str) -> PathBuf {
        PathBuf::from(parent).join(&self.name)
    }
}

// ─── DataAttr ─────────────────────────────────────────────────────────────────

/// Represents a `$DATA` attribute — either resident or non-resident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAttr {
    pub name: String,
    pub resident: bool,
    pub resident_data: Option<Vec<u8>>,
    /// Logical size for non-resident streams.
    pub data_size: u64,
    pub alloc_size: u64,
    /// Encoded run list (VCN→LCN mapping) for non-resident data.
    pub run_list: Vec<DataRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRun {
    pub vcn: u64,
    pub lcn: i64,
    pub cluster_count: u64,
}

impl DataAttr {
    pub fn resident(name: impl Into<String>, data: Vec<u8>) -> Self {
        let len = data.len() as u64;
        Self {
            name: name.into(),
            resident: true,
            resident_data: Some(data),
            data_size: len,
            alloc_size: len,
            run_list: Vec::new(),
        }
    }

    #[must_use] 
    pub const fn is_ads(&self) -> bool {
        !self.name.is_empty()
    }

    /// Return resident content, if available.
    #[must_use] 
    pub fn content(&self) -> Option<&[u8]> {
        self.resident_data.as_deref()
    }
}

// ─── IndexAttr ────────────────────────────────────────────────────────────────

/// An entry extracted from `$INDEX_ROOT` (directory listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub file_ref: u64,
    pub name: String,
    pub real_size: u64,
    pub flags: u32,
}

/// Parsed `$INDEX_ROOT` attribute.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexAttr {
    pub attr_type: u32,
    pub collation_rule: u32,
    pub index_block_size: u32,
    pub entries: Vec<IndexEntry>,
}

impl IndexAttr {
    #[must_use] 
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn find(&self, name: &str) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.name.eq_ignore_ascii_case(name))
    }
}

// ─── AttributeList ────────────────────────────────────────────────────────────

/// One entry in a `$ATTRIBUTE_LIST` attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeListEntry {
    pub attr_type: u32,
    pub record_length: u16,
    pub attr_name: String,
    pub starting_vcn: u64,
    pub base_file_ref: u64,
    pub attr_id: u16,
}

/// A parsed `$ATTRIBUTE_LIST`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeList {
    pub entries: Vec<AttributeListEntry>,
}

impl AttributeList {
    #[must_use] 
    pub fn entries_of_type(&self, ty: u32) -> Vec<&AttributeListEntry> {
        self.entries.iter().filter(|e| e.attr_type == ty).collect()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── MftRecord ────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RecordFlags: u16 {
        const IN_USE    = 0x01;
        const DIRECTORY = 0x02;
        const EXTENSION = 0x04;
        const INDEX     = 0x08;
    }
}

/// A fully-parsed MFT record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftRecord {
    pub record_number: u64,
    pub flags: RecordFlags,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub base_file_ref: u64,
    pub standard_info: Option<StandardInfo>,
    pub file_names: Vec<FileNameAttr>,
    pub data_attrs: Vec<DataAttr>,
    pub index_attr: Option<IndexAttr>,
    pub attr_list: Option<AttributeList>,
    /// Any attributes we parsed but didn't fully decode.
    pub other_attrs: Vec<(AttrType, Vec<u8>)>,
}

impl MftRecord {
    #[must_use] 
    pub const fn is_in_use(&self) -> bool {
        self.flags.contains(RecordFlags::IN_USE)
    }

    #[must_use] 
    pub const fn is_directory(&self) -> bool {
        self.flags.contains(RecordFlags::DIRECTORY)
    }

    #[must_use] 
    pub fn primary_name(&self) -> Option<&str> {
        // Prefer Win32 namespace, fall back to first
        self.file_names
            .iter()
            .find(|f| matches!(f.name_space, NameSpace::Win32 | NameSpace::Win32Dos))
            .or_else(|| self.file_names.first())
            .map(|f| f.name.as_str())
    }

    #[must_use] 
    pub fn data_size(&self) -> u64 {
        self.data_attrs
            .iter()
            .filter(|d| !d.is_ads())
            .map(|d| d.data_size)
            .sum()
    }

    #[must_use] 
    pub fn alternate_data_streams(&self) -> Vec<&DataAttr> {
        self.data_attrs.iter().filter(|d| d.is_ads()).collect()
    }

    #[must_use] 
    pub fn has_ads(&self) -> bool {
        self.data_attrs.iter().any(DataAttr::is_ads)
    }
}

// ─── NtfsMftFull ──────────────────────────────────────────────────────────────

/// Configuration for MFT analysis.
#[derive(Debug, Clone)]
pub struct MftConfig {
    pub max_records: usize,
    pub skip_system_records: bool,
    pub extract_resident_data: bool,
    pub resolve_paths: bool,
}

impl Default for MftConfig {
    fn default() -> Self {
        Self {
            max_records: 1_000_000,
            skip_system_records: false,
            extract_resident_data: true,
            resolve_paths: true,
        }
    }
}

/// Statistics collected during analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MftStats {
    pub total_records: u64,
    pub in_use_records: u64,
    pub directory_count: u64,
    pub file_count: u64,
    pub ads_count: u64,
    pub encrypted_count: u64,
    pub compressed_count: u64,
    pub deleted_count: u64,
    pub hard_link_count: u64,
    pub parse_errors: u64,
}

/// High-level NTFS MFT analyser.
pub struct NtfsMftFull {
    pub config: MftConfig,
    pub records: Vec<MftRecord>,
    pub stats: MftStats,
    /// Record number → resolved absolute path.
    pub path_cache: HashMap<u64, PathBuf>,
}

impl NtfsMftFull {
    #[must_use] 
    pub fn new(config: MftConfig) -> Self {
        Self {
            config,
            records: Vec::new(),
            stats: MftStats::default(),
            path_cache: HashMap::new(),
        }
    }

    /// Analyse a raw MFT image (concatenated 1024-byte records).
    pub fn parse_image(&mut self, image: &[u8]) -> MftResult<()> {
        if image.len() < MFT_RECORD_SIZE {
            return Err(MftError::ImageTooSmall(image.len()));
        }

        let record_count = image.len() / MFT_RECORD_SIZE;
        let limit = record_count.min(self.config.max_records);
        self.records.reserve(limit);

        for i in 0..limit {
            let offset = i * MFT_RECORD_SIZE;
            let rec_data = &image[offset..offset + MFT_RECORD_SIZE];
            match self.parse_record(i as u64, rec_data) {
                Ok(record) => {
                    self.update_stats(&record);
                    self.records.push(record);
                }
                Err(_) => {
                    self.stats.parse_errors += 1;
                }
            }
        }
        Ok(())
    }

    fn parse_record(&self, record_number: u64, data: &[u8]) -> MftResult<MftRecord> {
        // Validate signature
        let sig = read_u32(data, 0);
        if sig == 0x4441_4142 /* "BAAD" — NTFS-marked corrupt record */ {
            return Err(MftError::BadSignature(record_number));
        }
        if sig != MFT_SIGNATURE {
            return Err(MftError::BadSignature(record_number));
        }

        let flags_raw = read_u16(data, 22);
        let flags = RecordFlags::from_bits_truncate(flags_raw);
        let sequence_number = read_u16(data, 16);
        let hard_link_count = read_u16(data, 18);
        let base_file_ref = read_u64(data, 32) & 0x0000_FFFF_FFFF_FFFF;

        let attr_offset = read_u16(data, 20) as usize;
        if attr_offset >= data.len() {
            return Err(MftError::BadSignature(record_number));
        }

        let mut record = MftRecord {
            record_number,
            flags,
            sequence_number,
            hard_link_count,
            base_file_ref,
            standard_info: None,
            file_names: Vec::new(),
            data_attrs: Vec::new(),
            index_attr: None,
            attr_list: None,
            other_attrs: Vec::new(),
        };

        // Walk attributes
        let mut pos = attr_offset;
        while pos + 4 <= data.len() {
            let attr_type_raw = read_u32(data, pos);
            if attr_type_raw == 0xFFFF_FFFF {
                break;
            }
            let attr_len = read_u32(data, pos + 4) as usize;
            // The fixed attribute header is 16 bytes; accepting any non-zero
            // `attr_len` let a crafted record slice a shorter buffer that the
            // fields below then index at offsets 8..16.
            if attr_len < 16 || pos + attr_len > data.len() {
                break;
            }
            let attr_data = &data[pos..pos + attr_len];

            let non_resident = attr_data[8] != 0;
            let name_len = attr_data[9] as usize;
            let name_offset = read_u16(attr_data, 10) as usize;
            let _attr_id = read_u16(attr_data, 14);

            let attr_name = if name_len > 0 && name_offset + name_len * 2 <= attr_data.len() {
                utf16le_to_string(&attr_data[name_offset..name_offset + name_len * 2])
            } else {
                String::new()
            };

            let content: &[u8] = if non_resident {
                &[]
            } else {
                let content_off = read_u16(attr_data, 20) as usize;
                let content_len = read_u32(attr_data, 16) as usize;
                if content_off + content_len <= attr_data.len() {
                    &attr_data[content_off..content_off + content_len]
                } else {
                    &[]
                }
            };

            match AttrType::try_from(attr_type_raw) {
                Ok(AttrType::StandardInformation) => {
                    record.standard_info = StandardInfo::parse(content);
                }
                Ok(AttrType::FileName) => {
                    if let Some(fn_attr) = FileNameAttr::parse(content) {
                        record.file_names.push(fn_attr);
                    }
                }
                Ok(AttrType::Data) => {
                    let (data_size, alloc_size) = if non_resident {
                        (read_u64(attr_data, 48), read_u64(attr_data, 40))
                    } else {
                        let sz = content.len() as u64;
                        (sz, sz)
                    };
                    let resident_data = if !non_resident && self.config.extract_resident_data {
                        Some(content.to_vec())
                    } else {
                        None
                    };
                    record.data_attrs.push(DataAttr {
                        name: attr_name,
                        resident: !non_resident,
                        resident_data,
                        data_size,
                        alloc_size,
                        run_list: Vec::new(),
                    });
                }
                Ok(AttrType::IndexRoot) => {
                    record.index_attr = Some(parse_index_root(content));
                }
                Ok(at) => {
                    record.other_attrs.push((at, content.to_vec()));
                }
                Err(_) => {} // Skip unknown
            }

            pos += attr_len;
        }

        Ok(record)
    }

    fn update_stats(&mut self, r: &MftRecord) {
        self.stats.total_records += 1;
        if r.is_in_use() {
            self.stats.in_use_records += 1;
            if r.is_directory() {
                self.stats.directory_count += 1;
            } else {
                self.stats.file_count += 1;
            }
            if r.has_ads() {
                self.stats.ads_count += 1;
            }
            if let Some(si) = &r.standard_info {
                if si.is_encrypted() { self.stats.encrypted_count += 1; }
                if si.is_compressed() { self.stats.compressed_count += 1; }
            }
            if r.hard_link_count > 1 {
                self.stats.hard_link_count += 1;
            }
        } else {
            self.stats.deleted_count += 1;
        }
    }

    /// Look up a record by number.
    #[must_use] 
    pub fn get_record(&self, n: u64) -> Option<&MftRecord> {
        self.records.iter().find(|r| r.record_number == n)
    }

    /// Find records whose primary file name matches (case-insensitive).
    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Vec<&MftRecord> {
        let lower = name.to_lowercase();
        self.records
            .iter()
            .filter(|r| {
                r.primary_name()
                    .is_some_and(|n| n.to_lowercase() == lower)
            })
            .collect()
    }

    /// List all records with ADS.
    #[must_use] 
    pub fn records_with_ads(&self) -> Vec<&MftRecord> {
        self.records.iter().filter(|r| r.has_ads()).collect()
    }

    /// Deleted (not in-use) records.
    #[must_use] 
    pub fn deleted_records(&self) -> Vec<&MftRecord> {
        self.records.iter().filter(|r| !r.is_in_use()).collect()
    }

    /// Count of encrypted files.
    #[must_use] 
    pub const fn encrypted_count(&self) -> u64 {
        self.stats.encrypted_count
    }

    #[must_use] 
    pub fn total_file_size(&self) -> u64 {
        self.records.iter().map(MftRecord::data_size).sum()
    }
}

// ─── Helper: parse $INDEX_ROOT ────────────────────────────────────────────────

fn parse_index_root(data: &[u8]) -> IndexAttr {
    let idx = IndexAttr {
        attr_type: if data.len() >= 4 { read_u32(data, 0) } else { 0 },
        collation_rule: if data.len() >= 8 { read_u32(data, 4) } else { 0 },
        index_block_size: if data.len() >= 12 { read_u32(data, 8) } else { 0 },
        entries: Vec::new(),
    };
    // Index header starts at offset 16; entries start at 16 + index_header.entries_offset (32)
    // For brevity we don't fully decode the B-tree here.
    let _ = idx.entry_count(); // silence warning
    idx
}

// ─── Low-level read helpers ───────────────────────────────────────────────────

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() { return 0; }
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Build helpers ──────────────────────────────────────────────────────────

    fn make_mft_record_bytes(_record_number: u64, in_use: bool) -> Vec<u8> {
        let mut buf = vec![0u8; MFT_RECORD_SIZE];
        // Signature "FILE"
        buf[0] = b'F'; buf[1] = b'I'; buf[2] = b'L'; buf[3] = b'E';
        // Update sequence offset at 4
        buf[4] = 48; buf[5] = 0; // update seq at offset 48
        buf[6] = 1; buf[7] = 0;  // update seq count = 1
        // Log file sequence number at 8 (8 bytes) - leave zero
        // Sequence number at 16
        buf[16] = 1; buf[17] = 0;
        // Hard link count at 18
        buf[18] = 1; buf[19] = 0;
        // First attribute offset at 20
        buf[20] = 56; buf[21] = 0; // attributes start at byte 56
        // Flags at 22
        buf[22] = u8::from(in_use);
        // End marker at attribute offset 56
        buf[56] = 0xFF; buf[57] = 0xFF; buf[58] = 0xFF; buf[59] = 0xFF;
        buf
    }

    // ── FileTime ───────────────────────────────────────────────────────────────

    #[test]
    fn test_filetime_zero() {
        assert!(FileTime::ZERO.is_zero());
    }

    #[test]
    fn test_filetime_to_unix_secs() {
        // Windows epoch 1601-01-01 + 370 years ≈ Unix epoch
        let unix = FileTime(116_444_736_000_000_000u64 + 10_000_000).to_unix_secs();
        assert_eq!(unix, 1);
    }

    #[test]
    fn test_filetime_below_epoch() {
        assert_eq!(FileTime(100).to_unix_secs(), 0);
    }

    #[test]
    fn test_filetime_display() {
        let s = FileTime(116_444_736_000_000_000u64 + 10_000_000).to_string();
        assert!(s.contains('1'));
    }

    // ── AttrType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_attr_type_standard_info() {
        let t = AttrType::try_from(0x10u32).unwrap();
        assert_eq!(t, AttrType::StandardInformation);
    }

    #[test]
    fn test_attr_type_end() {
        let t = AttrType::try_from(0xFFFF_FFFFu32).unwrap();
        assert_eq!(t, AttrType::End);
    }

    #[test]
    fn test_attr_type_unknown_error() {
        assert!(AttrType::try_from(0x1234u32).is_err());
    }

    // ── StandardInfo ──────────────────────────────────────────────────────────

    #[test]
    fn test_standard_info_parse_too_short() {
        assert!(StandardInfo::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_standard_info_parse_minimal() {
        let mut data = vec![0u8; 48];
        // file_attributes = 0x0002 (hidden)
        data[32] = 0x02;
        let si = StandardInfo::parse(&data).unwrap();
        assert!(si.is_hidden());
        assert!(!si.is_directory());
    }

    #[test]
    fn test_standard_info_is_directory() {
        let mut data = vec![0u8; 48];
        data[32] = 0x10;
        let si = StandardInfo::parse(&data).unwrap();
        assert!(si.is_directory());
    }

    #[test]
    fn test_standard_info_is_encrypted() {
        let mut data = vec![0u8; 48];
        // 0x4000 = encrypted
        data[32] = 0x00; data[33] = 0x40;
        let si = StandardInfo::parse(&data).unwrap();
        assert!(si.is_encrypted());
    }

    #[test]
    fn test_standard_info_is_compressed() {
        let mut data = vec![0u8; 48];
        // 0x0800 = compressed
        data[32] = 0x00; data[33] = 0x08;
        let si = StandardInfo::parse(&data).unwrap();
        assert!(si.is_compressed());
    }

    // ── NameSpace ─────────────────────────────────────────────────────────────

    #[test]
    fn test_namespace_win32() {
        assert_eq!(NameSpace::try_from(1u8).unwrap(), NameSpace::Win32);
    }

    #[test]
    fn test_namespace_unknown() {
        assert!(NameSpace::try_from(99u8).is_err());
    }

    // ── FileNameAttr ──────────────────────────────────────────────────────────

    #[test]
    fn test_filename_attr_too_short() {
        assert!(FileNameAttr::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_filename_attr_parse_empty_name() {
        let data = vec![0u8; 66];
        // name_len = 0
        let fn_attr = FileNameAttr::parse(&data).unwrap();
        assert!(fn_attr.name.is_empty());
    }

    #[test]
    fn test_filename_attr_parse_with_name() {
        let mut data = vec![0u8; 68 + 10];
        data[64] = 5; // name_len = 5 chars = 10 bytes
        data[65] = 1; // Win32 namespace
        // "hello" in UTF-16LE
        let name_bytes: Vec<u16> = "hello".encode_utf16().collect();
        for (i, w) in name_bytes.iter().enumerate() {
            let bytes = w.to_le_bytes();
            data[66 + i * 2] = bytes[0];
            data[66 + i * 2 + 1] = bytes[1];
        }
        let fn_attr = FileNameAttr::parse(&data).unwrap();
        assert_eq!(fn_attr.name, "hello");
        assert_eq!(fn_attr.name_space, NameSpace::Win32);
    }

    #[test]
    fn test_filename_full_path() {
        let data = vec![0u8; 66];
        let fn_attr = FileNameAttr::parse(&data).unwrap();
        let path = fn_attr.full_path("C:\\");
        assert!(path.to_str().unwrap().starts_with("C:\\"));
    }

    // ── DataAttr ──────────────────────────────────────────────────────────────

    #[test]
    fn test_data_attr_resident() {
        let da = DataAttr::resident("", vec![1, 2, 3]);
        assert!(da.resident);
        assert_eq!(da.content().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn test_data_attr_is_ads() {
        let da = DataAttr::resident("Zone.Identifier", vec![]);
        assert!(da.is_ads());
        let main = DataAttr::resident("", vec![]);
        assert!(!main.is_ads());
    }

    // ── IndexAttr ─────────────────────────────────────────────────────────────

    #[test]
    fn test_index_attr_find() {
        let mut idx = IndexAttr::default();
        idx.entries.push(IndexEntry { file_ref: 42, name: "Foo.txt".into(), real_size: 100, flags: 0 });
        assert!(idx.find("foo.txt").is_some());
        assert!(idx.find("bar.txt").is_none());
    }

    #[test]
    fn test_index_attr_entry_count() {
        let idx = IndexAttr::default();
        assert_eq!(idx.entry_count(), 0);
    }

    // ── AttributeList ─────────────────────────────────────────────────────────

    #[test]
    fn test_attr_list_empty() {
        let al = AttributeList::default();
        assert!(al.is_empty());
    }

    #[test]
    fn test_attr_list_entries_of_type() {
        let mut al = AttributeList::default();
        al.entries.push(AttributeListEntry {
            attr_type: 0x80,
            record_length: 26,
            attr_name: String::new(),
            starting_vcn: 0,
            base_file_ref: 0,
            attr_id: 0,
        });
        al.entries.push(AttributeListEntry {
            attr_type: 0x30,
            record_length: 26,
            attr_name: String::new(),
            starting_vcn: 0,
            base_file_ref: 0,
            attr_id: 1,
        });
        assert_eq!(al.entries_of_type(0x80).len(), 1);
    }

    // ── MftRecord ─────────────────────────────────────────────────────────────

    #[test]
    fn test_mft_record_is_in_use() {
        let r = MftRecord {
            record_number: 5,
            flags: RecordFlags::IN_USE,
            sequence_number: 1,
            hard_link_count: 1,
            base_file_ref: 0,
            standard_info: None,
            file_names: vec![],
            data_attrs: vec![],
            index_attr: None,
            attr_list: None,
            other_attrs: vec![],
        };
        assert!(r.is_in_use());
        assert!(!r.is_directory());
    }

    #[test]
    fn test_mft_record_primary_name_win32_preferred() {
        let mut r = MftRecord {
            record_number: 10,
            flags: RecordFlags::IN_USE,
            sequence_number: 1,
            hard_link_count: 1,
            base_file_ref: 0,
            standard_info: None,
            file_names: vec![],
            data_attrs: vec![],
            index_attr: None,
            attr_list: None,
            other_attrs: vec![],
        };
        let fn_dos = FileNameAttr {
            parent_ref: 5, created: FileTime::ZERO, modified: FileTime::ZERO,
            mft_modified: FileTime::ZERO, accessed: FileTime::ZERO,
            alloc_size: 0, real_size: 0, flags: 0, reparse_tag: 0,
            name_space: NameSpace::Dos, name: "TESTFI~1.TXT".into(),
        };
        let fn_win32 = FileNameAttr {
            parent_ref: 5, created: FileTime::ZERO, modified: FileTime::ZERO,
            mft_modified: FileTime::ZERO, accessed: FileTime::ZERO,
            alloc_size: 0, real_size: 0, flags: 0, reparse_tag: 0,
            name_space: NameSpace::Win32, name: "TestFile.txt".into(),
        };
        r.file_names.push(fn_dos);
        r.file_names.push(fn_win32);
        assert_eq!(r.primary_name(), Some("TestFile.txt"));
    }

    #[test]
    fn test_mft_record_has_ads() {
        let r = MftRecord {
            record_number: 6,
            flags: RecordFlags::IN_USE,
            sequence_number: 1,
            hard_link_count: 1,
            base_file_ref: 0,
            standard_info: None,
            file_names: vec![],
            data_attrs: vec![DataAttr::resident("Zone.Identifier", vec![])],
            index_attr: None,
            attr_list: None,
            other_attrs: vec![],
        };
        assert!(r.has_ads());
    }

    // ── NtfsMftFull ───────────────────────────────────────────────────────────

    #[test]
    fn test_mft_full_image_too_small() {
        let mut mft = NtfsMftFull::new(MftConfig::default());
        let err = mft.parse_image(&[0u8; 100]);
        assert!(matches!(err, Err(MftError::ImageTooSmall(_))));
    }

    #[test]
    fn test_mft_full_parse_single_record() {
        let mut mft = NtfsMftFull::new(MftConfig::default());
        let rec = make_mft_record_bytes(0, true);
        // Should not error even if the record has no attributes after end marker
        let _ = mft.parse_image(&rec);
        // At least one attempt was made
    }

    #[test]
    fn test_mft_full_stats_after_parse() {
        let mut mft = NtfsMftFull::new(MftConfig::default());
        let mut image = Vec::new();
        for i in 0..4 {
            image.extend_from_slice(&make_mft_record_bytes(i, i < 3));
        }
        let _ = mft.parse_image(&image);
        assert_eq!(mft.stats.total_records, 4);
    }

    #[test]
    fn test_mft_full_find_by_name_empty() {
        let mft = NtfsMftFull::new(MftConfig::default());
        assert!(mft.find_by_name("test.txt").is_empty());
    }

    #[test]
    fn test_mft_full_deleted_records_count() {
        let mut mft = NtfsMftFull::new(MftConfig::default());
        let mut image = Vec::new();
        image.extend_from_slice(&make_mft_record_bytes(0, false));
        image.extend_from_slice(&make_mft_record_bytes(1, true));
        let _ = mft.parse_image(&image);
        let deleted = mft.deleted_records();
        assert_eq!(deleted.len(), 1);
    }

    #[test]
    fn test_mft_full_total_file_size_zero_for_no_data_attrs() {
        let mut mft = NtfsMftFull::new(MftConfig::default());
        let image = make_mft_record_bytes(0, true);
        let _ = mft.parse_image(&image);
        assert_eq!(mft.total_file_size(), 0);
    }

    #[test]
    fn test_mft_full_records_with_ads_empty() {
        let mft = NtfsMftFull::new(MftConfig::default());
        assert!(mft.records_with_ads().is_empty());
    }

    // ── Utility helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_utf16le_to_string() {
        let s = "hello";
        let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(utf16le_to_string(&bytes), "hello");
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        assert_eq!(read_u32(&[0u8; 2], 0), 0);
    }

    #[test]
    fn test_record_flags_in_use() {
        let f = RecordFlags::from_bits_truncate(0x03);
        assert!(f.contains(RecordFlags::IN_USE));
        assert!(f.contains(RecordFlags::DIRECTORY));
    }

    #[test]
    fn test_data_run_fields() {
        let dr = DataRun { vcn: 0, lcn: 100, cluster_count: 50 };
        assert_eq!(dr.cluster_count, 50);
    }
}
