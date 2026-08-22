//! NTFS filesystem analyzer for `rustre-forensics-fs`.
//!
//! Provides structures and analysis logic for NTFS:
//! - [`MftRecord`] with attribute parsing (`$STANDARD_INFORMATION`,
//!   `$FILE_NAME`, `$DATA`, `$ATTRIBUTE_LIST`).
//! - [`UsnjrnlReader`] for reading the NTFS Change Journal.
//! - [`AlternateDataStreams`] for ADS discovery.
//! - [`DeletedFileRecovery`] for recovering unlinked MFT entries.
//! - [`TimelineBuilder`] with timestomp detection via `$STANDARD_INFORMATION`
//!   vs `$FILE_NAME` timestamp comparison.
//! - [`NtfsTimestomp`] for reporting timestamp manipulation.

use std::fmt;

pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from NTFS analysis operations.
#[derive(Debug, thiserror::Error)]
pub enum NtfsError {
    #[error("invalid MFT record: {0}")]
    InvalidRecord(String),
    #[error("attribute parse error: {0}")]
    AttributeParse(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
    #[error("data too short")]
    TooShort,
}

// ---------------------------------------------------------------------------
// NTFS Timestamps
// ---------------------------------------------------------------------------

/// Windows FILETIME: 100-nanosecond intervals since 1601-01-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct FileTime(pub u64);

impl FileTime {
    /// Unix epoch as `FileTime`.
    pub const UNIX_EPOCH: Self = Self(116_444_736_000_000_000);

    /// Convert to Unix timestamp (seconds).
    #[must_use]
    pub const fn to_unix_secs(self) -> i64 {
        if self.0 < Self::UNIX_EPOCH.0 {
            return -((Self::UNIX_EPOCH.0 - self.0).cast_signed() / 10_000_000);
        }
        ((self.0 - Self::UNIX_EPOCH.0) / 10_000_000).cast_signed()
    }

    /// Parse 8 bytes (little-endian) into a `FileTime`.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let v = u64::from_le_bytes(b[0..8].try_into().ok()?);
        Some(Self(v))
    }

    /// Returns `true` if this timestamp is zero (unset).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for FileTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileTime({})", self.to_unix_secs())
    }
}

/// The four NTFS timestamps: created, modified, `metadata_modified`, accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NtfsTimestamps {
    pub created: FileTime,
    pub modified: FileTime,
    pub metadata_modified: FileTime,
    pub accessed: FileTime,
}

impl NtfsTimestamps {
    /// Parse timestamps from a 32-byte slice (4 × 8-byte `FileTime` LE).
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 32 {
            return None;
        }
        Some(Self {
            created: FileTime::from_bytes(&b[0..8])?,
            modified: FileTime::from_bytes(&b[8..16])?,
            metadata_modified: FileTime::from_bytes(&b[16..24])?,
            accessed: FileTime::from_bytes(&b[24..32])?,
        })
    }

    /// Returns `true` if any timestamp is zero.
    #[must_use]
    pub const fn has_zero_timestamps(&self) -> bool {
        self.created.is_zero()
            || self.modified.is_zero()
            || self.metadata_modified.is_zero()
            || self.accessed.is_zero()
    }
}

// ---------------------------------------------------------------------------
// MFT Attribute types
// ---------------------------------------------------------------------------

/// Type code for an NTFS MFT attribute.
///
/// Note: this enum mixes explicit discriminants with a data-carrying
/// `Unknown(u32)` variant. With the original `End = 0xFFFF_FFFF` plus
/// `#[repr(u32)]`, the auto-assigned discriminant for `Unknown` overflowed
/// `u32`. We give `Unknown` its own non-colliding explicit discriminant
/// (`0xFFFE_FFFF`) so the layout stays within `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum AttributeType {
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
    LoggedUtilityStream = 0x100,
    Unknown(u32) = 0xFFFE_FFFF,
    End = 0xFFFF_FFFF,
}

impl AttributeType {
    /// Parse from a u32 value.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
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
            0x100 => Self::LoggedUtilityStream,
            0xFFFF_FFFF => Self::End,
            v => Self::Unknown(v),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StandardInformation => "$STANDARD_INFORMATION",
            Self::AttributeList => "$ATTRIBUTE_LIST",
            Self::FileName => "$FILE_NAME",
            Self::ObjectId => "$OBJECT_ID",
            Self::SecurityDescriptor => "$SECURITY_DESCRIPTOR",
            Self::VolumeName => "$VOLUME_NAME",
            Self::VolumeInformation => "$VOLUME_INFORMATION",
            Self::Data => "$DATA",
            Self::IndexRoot => "$INDEX_ROOT",
            Self::IndexAllocation => "$INDEX_ALLOCATION",
            Self::Bitmap => "$BITMAP",
            Self::ReparsePoint => "$REPARSE_POINT",
            Self::LoggedUtilityStream => "$LOGGED_UTILITY_STREAM",
            Self::End => "$END",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed Attributes
// ---------------------------------------------------------------------------

/// Parsed `$STANDARD_INFORMATION` attribute (0x10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardInformation {
    pub timestamps: NtfsTimestamps,
    pub file_attributes: u32,
    pub max_versions: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota_charged: u64,
    pub usn: u64,
}

impl StandardInformation {
    /// Parse from raw attribute data (minimum 48 bytes for v1.x, 72 for v3+).
    ///
    /// # Errors
    /// Returns `NtfsError::TooShort` if `data` is too small.
    pub fn parse(data: &[u8]) -> Result<Self, NtfsError> {
        if data.len() < 48 {
            return Err(NtfsError::TooShort);
        }
        let timestamps = NtfsTimestamps::from_bytes(&data[0..32]).ok_or(NtfsError::TooShort)?;
        let file_attributes = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let max_versions = u32::from_le_bytes(data[36..40].try_into().unwrap());
        let version = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let class_id = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let (owner_id, security_id, quota_charged, usn) = if data.len() >= 72 {
            (
                u32::from_le_bytes(data[48..52].try_into().unwrap()),
                u32::from_le_bytes(data[52..56].try_into().unwrap()),
                u64::from_le_bytes(data[56..64].try_into().unwrap()),
                u64::from_le_bytes(data[64..72].try_into().unwrap()),
            )
        } else {
            (0, 0, 0, 0)
        };
        Ok(Self {
            timestamps,
            file_attributes,
            max_versions,
            version,
            class_id,
            owner_id,
            security_id,
            quota_charged,
            usn,
        })
    }
}

/// Parsed `$FILE_NAME` attribute (0x30).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNameAttribute {
    /// MFT reference of the parent directory.
    pub parent_ref: u64,
    pub timestamps: NtfsTimestamps,
    pub allocated_size: u64,
    pub real_size: u64,
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub name: String,
    pub namespace: FileNameNamespace,
}

/// NTFS filename namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileNameNamespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
    Unknown(u8),
}

impl FileNameNamespace {
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Posix,
            1 => Self::Win32,
            2 => Self::Dos,
            3 => Self::Win32AndDos,
            v => Self::Unknown(v),
        }
    }
}

impl FileNameAttribute {
    /// Parse from raw attribute data.
    ///
    /// # Errors
    /// Returns `NtfsError::TooShort` if data is too small.
    pub fn parse(data: &[u8]) -> Result<Self, NtfsError> {
        if data.len() < 66 {
            return Err(NtfsError::TooShort);
        }
        let parent_ref = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let timestamps = NtfsTimestamps::from_bytes(&data[8..40]).ok_or(NtfsError::TooShort)?;
        let allocated_size = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let real_size = u64::from_le_bytes(data[48..56].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(data[56..60].try_into().unwrap());
        let reparse_tag = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let name_len = data[64] as usize;
        let namespace = FileNameNamespace::from_u8(data[65]);
        let name_end = 66 + name_len * 2;
        let name = if data.len() >= name_end {
            // UTF-16 LE decode.
            let u16_pairs: Vec<u16> = data[66..name_end]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            String::from_utf16_lossy(&u16_pairs)
        } else {
            String::new()
        };
        Ok(Self {
            parent_ref,
            timestamps,
            allocated_size,
            real_size,
            file_attributes,
            reparse_tag,
            name,
            namespace,
        })
    }
}

/// Parsed `$DATA` attribute (0x80) — resident data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAttribute {
    /// Stream name (empty for the default unnamed stream).
    pub name: String,
    /// Resident data bytes (if resident).
    pub data: Vec<u8>,
    /// `true` if the attribute is non-resident (data is on disk, not inline).
    pub non_resident: bool,
    /// Logical size of the data (from the non-resident header).
    pub data_size: u64,
}

/// An `$ATTRIBUTE_LIST` entry pointing to an attribute in another MFT record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeListEntry {
    pub attr_type: AttributeType,
    pub record_len: u16,
    pub name: String,
    pub attr_id: u16,
    pub mft_reference: u64,
}

/// A raw MFT attribute, either parsed or raw bytes.
#[derive(Debug, Clone)]
pub enum ParsedAttribute {
    StandardInformation(StandardInformation),
    FileName(FileNameAttribute),
    Data(DataAttribute),
    AttributeList(Vec<AttributeListEntry>),
    Raw {
        attr_type: AttributeType,
        data: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// MftRecord
// ---------------------------------------------------------------------------

/// A parsed NTFS MFT record.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// MFT record index.
    pub record_number: u64,
    /// Record sequence number.
    pub sequence_number: u16,
    /// Whether this record is in use.
    pub in_use: bool,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Parsed attributes.
    pub attributes: Vec<ParsedAttribute>,
    /// Raw record bytes (for signature verification).
    pub raw: Vec<u8>,
}

impl MftRecord {
    /// NTFS MFT record signature.
    const SIGNATURE: &'static [u8; 4] = b"FILE";
    /// Standard MFT record size (1024 bytes for most NTFS volumes).
    pub const RECORD_SIZE: usize = 1024;

    /// Parse an MFT record from a 1024-byte slice.
    ///
    /// # Errors
    /// Returns [`NtfsError::InvalidRecord`] if the signature does not match.
    pub fn parse(data: &[u8], record_number: u64) -> Result<Self, NtfsError> {
        if data.len() < 42 {
            return Err(NtfsError::TooShort);
        }
        if &data[0..4] != Self::SIGNATURE {
            return Err(NtfsError::InvalidRecord(format!(
                "bad signature at record {record_number}: {:02X?}",
                &data[0..4]
            )));
        }

        let sequence_number = u16::from_le_bytes(data[16..18].try_into().unwrap());
        let flags = u16::from_le_bytes(data[22..24].try_into().unwrap());
        let in_use = flags & 0x01 != 0;
        let is_directory = flags & 0x02 != 0;

        let attr_offset = u16::from_le_bytes(data[20..22].try_into().unwrap()) as usize;
        let record_size = u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize;
        let alloc_size = u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
        let _ = alloc_size;

        let mut attributes = Vec::new();
        // `record_size` is an attacker-controlled header field and may be
        // smaller than `attr_offset`, which would make the range start exceed
        // its end and panic.  Clamp the end below.
        let attr_end = data.len().min(record_size).max(attr_offset);
        if attr_offset < data.len() {
            Self::parse_attributes(&data[attr_offset..attr_end], &mut attributes);
        }

        Ok(Self {
            record_number,
            sequence_number,
            in_use,
            is_directory,
            attributes,
            raw: data.to_vec(),
        })
    }

    fn parse_attributes(data: &[u8], out: &mut Vec<ParsedAttribute>) {
        let mut pos = 0;
        while pos + 8 <= data.len() {
            let type_raw = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let attr_type = AttributeType::from_u32(type_raw);
            if attr_type == AttributeType::End {
                break;
            }
            if pos + 8 > data.len() {
                break;
            }
            let attr_len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            if attr_len < 16 || pos + attr_len > data.len() {
                break;
            }

            let non_resident = data[pos + 8] != 0;
            let name_len = data[pos + 9] as usize;
            let name_off =
                u16::from_le_bytes(data[pos + 10..pos + 12].try_into().unwrap()) as usize;
            let attr_flags = u16::from_le_bytes(data[pos + 12..pos + 14].try_into().unwrap());
            let _ = attr_flags;

            // Attribute name (for ADS etc.).
            let attr_name = if name_len > 0 && pos + name_off + name_len * 2 <= data.len() {
                let u16s: Vec<u16> = data[pos + name_off..pos + name_off + name_len * 2]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::new()
            };

            let attr_data = if non_resident {
                Vec::new()
            } else {
                // Resident: read inline.
                // The loop guard only proves `pos + attr_len <= data.len()`
                // with `attr_len >= 16`, so the resident-content header at
                // +16..+22 can lie past the end of a crafted record.  Index
                // through `get` so a truncated attribute yields an empty
                // value instead of panicking.
                let content_len = data
                    .get(pos + 16..pos + 20)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map_or(0usize, |b| u32::from_le_bytes(b) as usize);
                let content_off = data
                    .get(pos + 20..pos + 22)
                    .and_then(|b| <[u8; 2]>::try_from(b).ok())
                    .map_or(0usize, |b| u16::from_le_bytes(b) as usize);
                let start = pos + content_off;
                let end = (start + content_len).min(pos + attr_len);
                if start <= end && end <= data.len() {
                    data[start..end].to_vec()
                } else {
                    Vec::new()
                }
            };

            let parsed = match attr_type {
                AttributeType::StandardInformation => {
                    StandardInformation::parse(&attr_data).map_or(ParsedAttribute::Raw {
                            attr_type,
                            data: attr_data,
                        }, ParsedAttribute::StandardInformation)
                }
                AttributeType::FileName => {
                    FileNameAttribute::parse(&attr_data).map_or(ParsedAttribute::Raw {
                            attr_type,
                            data: attr_data,
                        }, ParsedAttribute::FileName)
                }
                AttributeType::Data => ParsedAttribute::Data(DataAttribute {
                    name: attr_name,
                    data: attr_data,
                    non_resident,
                    data_size: 0,
                }),
                _ => ParsedAttribute::Raw {
                    attr_type,
                    data: attr_data,
                },
            };

            out.push(parsed);
            pos += attr_len.max(1);
        }
    }

    /// Return the `$STANDARD_INFORMATION` attribute, if present.
    #[must_use]
    pub fn standard_information(&self) -> Option<&StandardInformation> {
        self.attributes.iter().find_map(|a| {
            if let ParsedAttribute::StandardInformation(si) = a {
                Some(si)
            } else {
                None
            }
        })
    }

    /// Return all `$FILE_NAME` attributes.
    #[must_use]
    pub fn file_names(&self) -> Vec<&FileNameAttribute> {
        self.attributes
            .iter()
            .filter_map(|a| {
                if let ParsedAttribute::FileName(fn_attr) = a {
                    Some(fn_attr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all `$DATA` attributes.
    #[must_use]
    pub fn data_attributes(&self) -> Vec<&DataAttribute> {
        self.attributes
            .iter()
            .filter_map(|a| {
                if let ParsedAttribute::Data(d) = a {
                    Some(d)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the primary filename (Win32 or `Win32AndDos` namespace).
    #[must_use]
    pub fn primary_name(&self) -> Option<&str> {
        self.file_names()
            .into_iter()
            .find(|f| {
                matches!(
                    f.namespace,
                    FileNameNamespace::Win32 | FileNameNamespace::Win32AndDos
                )
            })
            .map(|f| f.name.as_str())
    }
}

// ---------------------------------------------------------------------------
// AlternateDataStreams
// ---------------------------------------------------------------------------

/// Discovered alternate data stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdsEntry {
    /// Parent file path.
    pub file_path: String,
    /// Stream name (without leading colon).
    pub stream_name: String,
    /// Size of the stream in bytes.
    pub size: u64,
    /// Resident data (if small enough to be inline).
    pub data: Vec<u8>,
}

impl AdsEntry {
    /// Full ADS path: `file_path:stream_name`.
    #[must_use]
    pub fn full_path(&self) -> String {
        format!("{}:{}", self.file_path, self.stream_name)
    }
}

/// Discovers Alternate Data Streams in a set of MFT records.
#[derive(Debug, Default)]
pub struct AlternateDataStreams {
    pub entries: Vec<AdsEntry>,
}

impl AlternateDataStreams {
    /// Create an empty ADS collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a list of MFT records and collect all named `$DATA` streams.
    pub fn scan(&mut self, records: &[MftRecord]) {
        for rec in records {
            let base_path = rec
                .primary_name().map_or_else(|| format!("[MFT#{}]", rec.record_number), std::string::ToString::to_string);

            for data_attr in rec.data_attributes() {
                if data_attr.name.is_empty() {
                    continue; // unnamed default stream
                }
                self.entries.push(AdsEntry {
                    file_path: base_path.clone(),
                    stream_name: data_attr.name.clone(),
                    size: data_attr.data.len() as u64,
                    data: data_attr.data.clone(),
                });
            }
        }
    }

    /// Number of ADS entries found.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// UsnjrnlReader
// ---------------------------------------------------------------------------

/// Reason flags for a USN journal entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UsnReasonFlags(pub u32);

impl UsnReasonFlags {
    pub const DATA_OVERWRITE: Self = Self(0x0000_0001);
    pub const DATA_EXTEND: Self = Self(0x0000_0002);
    pub const DATA_TRUNCATION: Self = Self(0x0000_0004);
    pub const NAMED_DATA_OVERWRITE: Self = Self(0x0000_0010);
    pub const FILE_CREATE: Self = Self(0x0000_0100);
    pub const FILE_DELETE: Self = Self(0x0000_0200);
    pub const RENAME_OLD_NAME: Self = Self(0x0000_1000);
    pub const RENAME_NEW_NAME: Self = Self(0x0000_2000);
    pub const SECURITY_CHANGE: Self = Self(0x0000_8000);
    pub const CLOSE: Self = Self(0x8000_0000);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Every reason bit set on this entry, in USN documentation order.
    ///
    /// This is the single place that knows the full reason vocabulary; the
    /// classifiers below consult the same constants, so a reason the crate
    /// can name is never silently dropped from a timeline.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        const TABLE: [(UsnReasonFlags, &str); 10] = [
            (UsnReasonFlags::DATA_OVERWRITE, "DATA_OVERWRITE"),
            (UsnReasonFlags::DATA_EXTEND, "DATA_EXTEND"),
            (UsnReasonFlags::DATA_TRUNCATION, "DATA_TRUNCATION"),
            (UsnReasonFlags::NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
            (UsnReasonFlags::FILE_CREATE, "FILE_CREATE"),
            (UsnReasonFlags::FILE_DELETE, "FILE_DELETE"),
            (UsnReasonFlags::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
            (UsnReasonFlags::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
            (UsnReasonFlags::SECURITY_CHANGE, "SECURITY_CHANGE"),
            (UsnReasonFlags::CLOSE, "CLOSE"),
        ];
        TABLE
            .iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, name)| *name)
            .collect()
    }

    /// True if any bit represents a change to file *content*.
    ///
    /// `DATA_TRUNCATION` and `NAMED_DATA_OVERWRITE` belong here: a truncated
    /// or overwritten alternate stream is a content change, and treating it
    /// as a metadata touch hides the usual wipe signature.
    #[must_use]
    pub const fn is_data_change(self) -> bool {
        self.contains(Self::DATA_OVERWRITE)
            || self.contains(Self::DATA_EXTEND)
            || self.contains(Self::DATA_TRUNCATION)
            || self.contains(Self::NAMED_DATA_OVERWRITE)
    }

    /// True if any bit represents a rename, from either side of the pair.
    #[must_use]
    pub const fn is_rename(self) -> bool {
        self.contains(Self::RENAME_NEW_NAME) || self.contains(Self::RENAME_OLD_NAME)
    }
}

/// A single entry from the NTFS Change Journal (`$UsnJrnl:$J`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEntry {
    /// Record length.
    pub record_len: u32,
    /// File reference (MFT record number + sequence).
    pub file_ref: u64,
    /// Parent directory reference.
    pub parent_ref: u64,
    /// Update sequence number.
    pub usn: u64,
    /// Timestamp of the change.
    pub timestamp: FileTime,
    /// Reason flags.
    pub reason: UsnReasonFlags,
    /// Source information.
    pub source_info: u32,
    /// Security ID.
    pub security_id: u32,
    /// File attributes at the time of the record.
    pub file_attributes: u32,
    /// Filename.
    pub filename: String,
}

impl UsnEntry {
    /// Parse a USN V2 record from raw bytes.
    ///
    /// # Errors
    /// Returns [`NtfsError::TooShort`] if the data is too small.
    pub fn parse(data: &[u8]) -> Result<Self, NtfsError> {
        if data.len() < 60 {
            return Err(NtfsError::TooShort);
        }
        let record_len = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let file_ref = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let parent_ref = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let usn = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let timestamp = FileTime(u64::from_le_bytes(data[32..40].try_into().unwrap()));
        let reason = UsnReasonFlags(u32::from_le_bytes(data[40..44].try_into().unwrap()));
        let source_info = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let security_id = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let name_len = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
        let name_off = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
        let name_end = name_off + name_len;
        let filename = if data.len() >= name_end {
            let u16s: Vec<u16> = data[name_off..name_end]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            String::from_utf16_lossy(&u16s)
        } else {
            String::new()
        };
        Ok(Self {
            record_len,
            file_ref,
            parent_ref,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            filename,
        })
    }
}

/// Reads and parses the NTFS Change Journal (`$UsnJrnl:$J`).
#[derive(Debug, Default)]
pub struct UsnjrnlReader {
    pub entries: Vec<UsnEntry>,
}

impl UsnjrnlReader {
    /// Create an empty reader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse the raw `$J` stream and collect all entries.
    pub fn parse_stream(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 60 <= data.len() {
            let record_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            if record_len < 60 {
                pos += 8;
                continue;
            }
            if pos + record_len > data.len() {
                break;
            }
            if let Ok(entry) = UsnEntry::parse(&data[pos..pos + record_len]) {
                self.entries.push(entry);
            }
            pos += record_len;
        }
    }

    /// Return entries for a specific file reference.
    #[must_use]
    pub fn entries_for_file(&self, file_ref: u64) -> Vec<&UsnEntry> {
        self.entries
            .iter()
            .filter(|e| e.file_ref == file_ref)
            .collect()
    }

    /// Return all delete events.
    #[must_use]
    pub fn delete_events(&self) -> Vec<&UsnEntry> {
        self.entries
            .iter()
            .filter(|e| e.reason.contains(UsnReasonFlags::FILE_DELETE))
            .collect()
    }

    /// Return all rename events.
    #[must_use]
    pub fn rename_events(&self) -> Vec<&UsnEntry> {
        self.entries
            .iter()
            .filter(|e| e.reason.is_rename())
            .collect()
    }

    /// Return all entries whose reason bits indicate a content change.
    #[must_use]
    pub fn data_change_events(&self) -> Vec<&UsnEntry> {
        self.entries
            .iter()
            .filter(|e| e.reason.is_data_change())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DeletedFileRecovery
// ---------------------------------------------------------------------------

/// A recovered deleted file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    pub record_number: u64,
    pub filename: String,
    pub size: u64,
    pub sequence_number: u16,
    /// Whether data recovery succeeded (resident data available).
    pub data_recovered: bool,
    pub data: Vec<u8>,
    pub deletion_usn: Option<u64>,
}

/// Recovers deleted files from MFT records that are not in-use.
#[derive(Debug, Default)]
pub struct DeletedFileRecovery {
    pub recovered: Vec<RecoveredFile>,
}

impl DeletedFileRecovery {
    /// Create an empty recovery collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan MFT records for deleted (not in-use) entries.
    pub fn scan(&mut self, records: &[MftRecord]) {
        for rec in records {
            if rec.in_use {
                continue;
            }
            let filename = rec
                .primary_name().map_or_else(|| format!("[MFT#{}]", rec.record_number), std::string::ToString::to_string);

            let data_attrs = rec.data_attributes();
            let (data, data_recovered) = data_attrs.first().map_or((false, false), |d| (!d.data.is_empty(), !d.data.is_empty()));
            let data_bytes = data_attrs
                .first()
                .map(|d| d.data.clone())
                .unwrap_or_default();

            self.recovered.push(RecoveredFile {
                record_number: rec.record_number,
                filename,
                size: data_bytes.len() as u64,
                sequence_number: rec.sequence_number,
                data_recovered: data_recovered && data,
                data: data_bytes,
                deletion_usn: None,
            });
        }
    }

    /// Number of recovered files.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.recovered.len()
    }

    /// Files for which resident data was recovered.
    #[must_use]
    pub fn with_data(&self) -> Vec<&RecoveredFile> {
        self.recovered.iter().filter(|f| f.data_recovered).collect()
    }
}

// ---------------------------------------------------------------------------
// NtfsTimestomp
// ---------------------------------------------------------------------------

/// Describes a detected timestamp manipulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestompEvent {
    pub record_number: u64,
    pub filename: String,
    /// Difference between `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps
    /// for the creation time (in seconds).
    pub created_diff_secs: i64,
    /// Whether the `$STANDARD_INFORMATION` created timestamp is earlier than
    /// the `$FILE_NAME` created timestamp (common in timestomping).
    pub si_earlier_than_fn: bool,
    pub si_timestamps: Option<NtfsTimestamps>,
    pub fn_timestamps: Option<NtfsTimestamps>,
}

impl fmt::Display for TimestompEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timestomp[{}]: {} diff={}s si_earlier={}",
            self.record_number, self.filename, self.created_diff_secs, self.si_earlier_than_fn
        )
    }
}

/// Detects timestamp manipulation by comparing `$STANDARD_INFORMATION` with
/// `$FILE_NAME` timestamps.
#[derive(Debug, Default)]
pub struct NtfsTimestomp {
    pub events: Vec<TimestompEvent>,
}

impl NtfsTimestomp {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan MFT records for timestamp inconsistencies.
    ///
    /// The heuristic: `$STANDARD_INFORMATION.created < $FILE_NAME.created` is
    /// suspicious and indicates the tool changed SI but not FN timestamps.
    pub fn scan(&mut self, records: &[MftRecord]) {
        for rec in records {
            if !rec.in_use {
                continue;
            }
            let si = rec.standard_information();
            let fns = rec.file_names();
            let fn_attr = fns.first();
            if si.is_none() || fn_attr.is_none() {
                continue;
            }
            let si = si.unwrap();
            let fn_attr = fn_attr.unwrap();

            let si_created = si.timestamps.created.to_unix_secs();
            let fn_created = fn_attr.timestamps.created.to_unix_secs();
            let diff = (si_created - fn_created).abs();
            let si_earlier = si_created < fn_created;

            // Only flag if there is a non-trivial difference (> 1 second).
            if diff > 1 || si_earlier {
                self.events.push(TimestompEvent {
                    record_number: rec.record_number,
                    filename: fn_attr.name.clone(),
                    created_diff_secs: si_created - fn_created,
                    si_earlier_than_fn: si_earlier,
                    si_timestamps: Some(si.timestamps),
                    fn_timestamps: Some(fn_attr.timestamps),
                });
            }
        }
    }

    /// Return only definitive timestomp events (SI earlier than FN).
    #[must_use]
    pub fn definitive_events(&self) -> Vec<&TimestompEvent> {
        self.events
            .iter()
            .filter(|e| e.si_earlier_than_fn)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TimelineBuilder
// ---------------------------------------------------------------------------

/// A single entry in the NTFS timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: FileTime,
    pub record_number: u64,
    pub filename: String,
    pub event: TimelineEvent,
    pub source: TimelineSource,
}

/// The type of filesystem event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineEvent {
    Created,
    Modified,
    MetadataModified,
    Accessed,
    Deleted,
    Renamed,
}

/// Source of the timestamp information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineSource {
    StandardInformation,
    FileName,
    UsnJournal,
}

/// Builds a unified timeline from MFT records and USN Journal entries.
#[derive(Debug, Default)]
pub struct TimelineBuilder {
    pub entries: Vec<TimelineEntry>,
}

impl TimelineBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add timeline entries from MFT records.
    pub fn ingest_mft(&mut self, records: &[MftRecord]) {
        for rec in records {
            if !rec.in_use {
                continue;
            }
            let name = rec
                .primary_name().map_or_else(|| format!("[MFT#{}]", rec.record_number), std::string::ToString::to_string);

            if let Some(si) = rec.standard_information() {
                self.push_timestamps(
                    &si.timestamps,
                    rec.record_number,
                    &name,
                    TimelineSource::StandardInformation,
                );
            }
            for fn_attr in rec.file_names() {
                self.push_timestamps(
                    &fn_attr.timestamps,
                    rec.record_number,
                    &name,
                    TimelineSource::FileName,
                );
            }
        }
    }

    /// Add timeline entries from USN Journal.
    pub fn ingest_usnjrnl(&mut self, reader: &UsnjrnlReader) {
        for entry in &reader.entries {
            let event = if entry.reason.contains(UsnReasonFlags::FILE_DELETE) {
                TimelineEvent::Deleted
            } else if entry.reason.is_rename() {
                TimelineEvent::Renamed
            } else if entry.reason.is_data_change() {
                TimelineEvent::Modified
            } else {
                TimelineEvent::MetadataModified
            };
            self.entries.push(TimelineEntry {
                timestamp: entry.timestamp,
                record_number: entry.file_ref,
                filename: entry.filename.clone(),
                event,
                source: TimelineSource::UsnJournal,
            });
        }
    }

    fn push_timestamps(
        &mut self,
        ts: &NtfsTimestamps,
        rec_no: u64,
        name: &str,
        src: TimelineSource,
    ) {
        let events = [
            (ts.created, TimelineEvent::Created),
            (ts.modified, TimelineEvent::Modified),
            (ts.metadata_modified, TimelineEvent::MetadataModified),
            (ts.accessed, TimelineEvent::Accessed),
        ];
        for (time, event) in events {
            if !time.is_zero() {
                self.entries.push(TimelineEntry {
                    timestamp: time,
                    record_number: rec_no,
                    filename: name.to_string(),
                    event,
                    source: src.clone(),
                });
            }
        }
    }

    /// Sort timeline entries by timestamp (oldest first).
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.timestamp);
    }

    /// Return entries in the given Unix timestamp range.
    #[must_use]
    pub fn in_range(&self, start_secs: i64, end_secs: i64) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| {
                let t = e.timestamp.to_unix_secs();
                t >= start_secs && t <= end_secs
            })
            .collect()
    }

    /// Return entries for a specific event type.
    #[must_use]
    pub fn events_of_type(&self, event: &TimelineEvent) -> Vec<&TimelineEntry> {
        self.entries.iter().filter(|e| &e.event == event).collect()
    }
}

// ---------------------------------------------------------------------------
// NtfsAnalyzer
// ---------------------------------------------------------------------------

/// High-level NTFS analyzer that orchestrates all sub-analyzers.
#[derive(Debug)]
pub struct NtfsAnalyzer {
    pub records: Vec<MftRecord>,
    pub usnjrnl: UsnjrnlReader,
    pub ads: AlternateDataStreams,
    pub deleted: DeletedFileRecovery,
    pub timestomp: NtfsTimestomp,
    pub timeline: TimelineBuilder,
}

impl NtfsAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            usnjrnl: UsnjrnlReader::new(),
            ads: AlternateDataStreams::new(),
            deleted: DeletedFileRecovery::new(),
            timestomp: NtfsTimestomp::new(),
            timeline: TimelineBuilder::new(),
        }
    }

    /// Add a pre-parsed MFT record.
    pub fn add_record(&mut self, rec: MftRecord) {
        self.records.push(rec);
    }

    /// Parse a raw MFT record and add it.
    ///
    /// # Errors
    /// Returns [`NtfsError`] if parsing fails.
    pub fn parse_and_add(&mut self, data: &[u8], record_number: u64) -> Result<(), NtfsError> {
        let rec = MftRecord::parse(data, record_number)?;
        self.records.push(rec);
        Ok(())
    }

    /// Run all analysis passes.
    pub fn analyze(&mut self) {
        self.ads.scan(&self.records);
        self.deleted.scan(&self.records);
        self.timestomp.scan(&self.records);
        self.timeline.ingest_mft(&self.records);
        self.timeline.ingest_usnjrnl(&self.usnjrnl);
        self.timeline.sort();
    }

    /// Summary report.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "NtfsAnalyzer: {} records, {} ADS, {} deleted, {} timestomp events, {} timeline entries",
            self.records.len(),
            self.ads.count(),
            self.deleted.count(),
            self.timestomp.events.len(),
            self.timeline.entries.len(),
        )
    }
}

impl Default for NtfsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mft_header(_record_number: u64, in_use: bool, is_dir: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        // Signature
        buf[0..4].copy_from_slice(b"FILE");
        // update_seq_offset = 48, count = 3
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        // log_file_seq = 0
        // sequence_number at offset 16
        buf[16..18].copy_from_slice(&42u16.to_le_bytes());
        // link_count at 18
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        // attr_offset at 20 (point to end of header, no attrs)
        buf[20..22].copy_from_slice(&56u16.to_le_bytes());
        // flags at 22
        let flags: u16 = u16::from(in_use) | if is_dir { 0x02 } else { 0x00 };
        buf[22..24].copy_from_slice(&flags.to_le_bytes());
        // record_real_size at 28
        buf[28..32].copy_from_slice(&56u32.to_le_bytes());
        // record_alloc_size at 32
        buf[32..36].copy_from_slice(&1024u32.to_le_bytes());
        // End attribute at offset 56
        buf[56..60].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf
    }

    // ── FileTime ─────────────────────────────────────────────────────────

    #[test]
    fn filetime_zero_is_zero() {
        assert!(FileTime(0).is_zero());
        assert!(!FileTime(1).is_zero());
    }

    #[test]
    fn filetime_unix_epoch() {
        let unix = FileTime::UNIX_EPOCH.to_unix_secs();
        assert_eq!(unix, 0);
    }

    #[test]
    fn filetime_from_bytes() {
        let ts = FileTime::UNIX_EPOCH.0;
        let bytes = ts.to_le_bytes();
        let ft = FileTime::from_bytes(&bytes).unwrap();
        assert_eq!(ft.0, ts);
    }

    #[test]
    fn filetime_from_bytes_too_short() {
        assert!(FileTime::from_bytes(&[0; 4]).is_none());
    }

    #[test]
    fn filetime_display() {
        let s = FileTime(0).to_string();
        assert!(s.contains("FileTime"));
    }

    // ── NtfsTimestamps ────────────────────────────────────────────────────

    #[test]
    fn ntfs_timestamps_from_bytes() {
        let buf = vec![0u8; 32];
        let ts = NtfsTimestamps::from_bytes(&buf).unwrap();
        assert!(ts.created.is_zero());
        assert!(ts.has_zero_timestamps());
    }

    #[test]
    fn ntfs_timestamps_from_bytes_too_short() {
        assert!(NtfsTimestamps::from_bytes(&[0; 16]).is_none());
    }

    // ── AttributeType ────────────────────────────────────────────────────

    #[test]
    fn attribute_type_from_u32_known() {
        assert_eq!(
            AttributeType::from_u32(0x10),
            AttributeType::StandardInformation
        );
        assert_eq!(AttributeType::from_u32(0x30), AttributeType::FileName);
        assert_eq!(AttributeType::from_u32(0x80), AttributeType::Data);
    }

    #[test]
    fn attribute_type_name() {
        assert_eq!(AttributeType::Data.name(), "$DATA");
        assert_eq!(AttributeType::End.name(), "$END");
    }

    #[test]
    fn attribute_type_unknown() {
        let t = AttributeType::from_u32(0xABCD);
        assert!(matches!(t, AttributeType::Unknown(_)));
    }

    // ── MftRecord ─────────────────────────────────────────────────────────

    #[test]
    fn mft_record_parse_basic() {
        let buf = make_mft_header(5, true, false);
        let rec = MftRecord::parse(&buf, 5).unwrap();
        assert_eq!(rec.record_number, 5);
        assert_eq!(rec.sequence_number, 42);
        assert!(rec.in_use);
        assert!(!rec.is_directory);
    }

    #[test]
    fn mft_record_parse_directory() {
        let buf = make_mft_header(1, true, true);
        let rec = MftRecord::parse(&buf, 1).unwrap();
        assert!(rec.is_directory);
    }

    #[test]
    fn mft_record_parse_deleted() {
        let buf = make_mft_header(2, false, false);
        let rec = MftRecord::parse(&buf, 2).unwrap();
        assert!(!rec.in_use);
    }

    #[test]
    fn mft_record_bad_signature() {
        let mut buf = vec![0u8; 1024];
        buf[0..4].copy_from_slice(b"BAAD");
        let err = MftRecord::parse(&buf, 0).unwrap_err();
        assert!(matches!(err, NtfsError::InvalidRecord(_)));
    }

    #[test]
    fn mft_record_too_short() {
        let err = MftRecord::parse(&[0; 10], 0).unwrap_err();
        assert!(matches!(err, NtfsError::TooShort));
    }

    // ── AlternateDataStreams ──────────────────────────────────────────────

    #[test]
    fn ads_empty_scan() {
        let mut ads = AlternateDataStreams::new();
        ads.scan(&[]);
        assert_eq!(ads.count(), 0);
    }

    #[test]
    fn ads_entry_full_path() {
        let e = AdsEntry {
            file_path: "test.txt".to_string(),
            stream_name: "secret".to_string(),
            size: 10,
            data: vec![],
        };
        assert_eq!(e.full_path(), "test.txt:secret");
    }

    // ── UsnjrnlReader ─────────────────────────────────────────────────────

    #[test]
    fn usnjrnl_reader_empty() {
        let r = UsnjrnlReader::new();
        assert!(r.entries.is_empty());
        assert!(r.delete_events().is_empty());
        assert!(r.rename_events().is_empty());
    }

    #[test]
    fn usnjrnl_parse_too_short_stream() {
        let mut r = UsnjrnlReader::new();
        r.parse_stream(&[0u8; 10]);
        assert!(r.entries.is_empty());
    }

    // ── DeletedFileRecovery ───────────────────────────────────────────────

    #[test]
    fn deleted_file_recovery_in_use_skipped() {
        let buf = make_mft_header(0, true, false);
        let rec = MftRecord::parse(&buf, 0).unwrap();
        let mut dfr = DeletedFileRecovery::new();
        dfr.scan(&[rec]);
        assert_eq!(dfr.count(), 0);
    }

    #[test]
    fn deleted_file_recovery_deleted_found() {
        let buf = make_mft_header(3, false, false);
        let rec = MftRecord::parse(&buf, 3).unwrap();
        let mut dfr = DeletedFileRecovery::new();
        dfr.scan(&[rec]);
        assert_eq!(dfr.count(), 1);
        assert!(!dfr.recovered[0].data_recovered);
    }

    // ── NtfsTimestomp ─────────────────────────────────────────────────────

    #[test]
    fn timestomp_empty_scan() {
        let mut ts = NtfsTimestomp::new();
        ts.scan(&[]);
        assert!(ts.events.is_empty());
    }

    #[test]
    fn timestomp_definitive_events_empty() {
        let ts = NtfsTimestomp::new();
        assert!(ts.definitive_events().is_empty());
    }

    // ── TimelineBuilder ──────────────────────────────────────────────────

    #[test]
    fn timeline_empty() {
        let mut tb = TimelineBuilder::new();
        tb.sort();
        assert!(tb.entries.is_empty());
    }

    #[test]
    fn timeline_in_range_empty() {
        let tb = TimelineBuilder::new();
        let r = tb.in_range(0, i64::MAX);
        assert!(r.is_empty());
    }

    #[test]
    fn timeline_events_of_type_empty() {
        let tb = TimelineBuilder::new();
        assert!(tb.events_of_type(&TimelineEvent::Created).is_empty());
    }

    // ── NtfsAnalyzer ─────────────────────────────────────────────────────

    #[test]
    fn ntfs_analyzer_new_empty() {
        let a = NtfsAnalyzer::new();
        assert_eq!(a.records.len(), 0);
        assert!(a.summary().contains("0 records"));
    }

    #[test]
    fn ntfs_analyzer_parse_and_add() {
        let mut a = NtfsAnalyzer::new();
        let buf = make_mft_header(1, true, false);
        a.parse_and_add(&buf, 1).unwrap();
        assert_eq!(a.records.len(), 1);
    }

    #[test]
    fn ntfs_analyzer_analyze_no_panic() {
        let mut a = NtfsAnalyzer::new();
        let buf = make_mft_header(0, true, false);
        a.parse_and_add(&buf, 0).unwrap();
        a.analyze();
        let _ = a.summary();
    }

    #[test]
    fn usn_truncation_is_a_data_change() {
        // Regression: DATA_TRUNCATION and NAMED_DATA_OVERWRITE were declared
        // but never routed, so a truncated file (the usual wipe signature)
        // was classified as a mere metadata touch.
        let trunc = UsnReasonFlags(UsnReasonFlags::DATA_TRUNCATION.0);
        assert!(trunc.is_data_change());
        let ads = UsnReasonFlags(UsnReasonFlags::NAMED_DATA_OVERWRITE.0);
        assert!(ads.is_data_change());
        let sec = UsnReasonFlags(UsnReasonFlags::SECURITY_CHANGE.0);
        assert!(!sec.is_data_change(), "a security change is not content");
    }

    #[test]
    fn usn_rename_matches_both_sides() {
        let old = UsnReasonFlags(UsnReasonFlags::RENAME_OLD_NAME.0);
        let new = UsnReasonFlags(UsnReasonFlags::RENAME_NEW_NAME.0);
        assert!(old.is_rename() && new.is_rename());
    }

    #[test]
    fn usn_names_covers_every_declared_reason() {
        let all = UsnReasonFlags(
            UsnReasonFlags::DATA_OVERWRITE.0
                | UsnReasonFlags::DATA_EXTEND.0
                | UsnReasonFlags::DATA_TRUNCATION.0
                | UsnReasonFlags::NAMED_DATA_OVERWRITE.0
                | UsnReasonFlags::FILE_CREATE.0
                | UsnReasonFlags::FILE_DELETE.0
                | UsnReasonFlags::RENAME_OLD_NAME.0
                | UsnReasonFlags::RENAME_NEW_NAME.0
                | UsnReasonFlags::SECURITY_CHANGE.0
                | UsnReasonFlags::CLOSE.0,
        );
        assert_eq!(all.names().len(), 10);
        assert!(all.names().contains(&"DATA_TRUNCATION"));
        assert!(UsnReasonFlags(0).names().is_empty());
    }

    #[test]
    fn usn_reason_flags_contains() {
        let r = UsnReasonFlags(UsnReasonFlags::FILE_DELETE.0 | UsnReasonFlags::CLOSE.0);
        assert!(r.contains(UsnReasonFlags::FILE_DELETE));
        assert!(r.contains(UsnReasonFlags::CLOSE));
        assert!(!r.contains(UsnReasonFlags::FILE_CREATE));
    }

    #[test]
    fn timestomp_display() {
        let e = TimestompEvent {
            record_number: 5,
            filename: "evil.exe".to_string(),
            created_diff_secs: -86400,
            si_earlier_than_fn: true,
            si_timestamps: None,
            fn_timestamps: None,
        };
        let s = e.to_string();
        assert!(s.contains("evil.exe"));
        assert!(s.contains("true"));
    }
    #[test]
    fn truncated_resident_attribute_does_not_panic() {
        // A resident attribute whose declared length (16) stops exactly at the
        // end of the record: the resident-content header (offsets +16..+22)
        // then lies past the buffer.  Must return, not panic.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"FILE");
        data[20..22].copy_from_slice(&48u16.to_le_bytes()); // attr_offset
        data[28..32].copy_from_slice(&64u32.to_le_bytes()); // record_size
        data[48..52].copy_from_slice(&0x80u32.to_le_bytes()); // $DATA
        data[52..56].copy_from_slice(&16u32.to_le_bytes()); // attr_len == 16
        data[56] = 0; // resident
        data[57] = 0; // name_len
        let rec = MftRecord::parse(&data, 0).expect("header is well formed");
        assert!(rec.attributes.len() <= 1);
    }

}
