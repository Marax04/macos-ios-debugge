//! Filesystem timeline generation: MFT entry parsing, MAC(b) timestamps,
//! timeline correlation, and NTFS Journal replay.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TimelineError {
    #[error("invalid MFT signature at offset {0}")]
    InvalidMftSignature(usize),
    #[error("invalid MFT record size: {0}")]
    InvalidRecordSize(u32),
    #[error("attribute parsing error at offset {0}: {1}")]
    AttributeError(usize, String),
    #[error("USN journal parse error: {0}")]
    JournalError(String),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
}

// ─── MFT constants ────────────────────────────────────────────────────────────

/// NTFS MFT record signature "FILE".
pub const MFT_RECORD_SIG: &[u8; 4] = b"FILE";
/// NTFS MFT record size (512 bytes for small records, 1024 for standard).
pub const MFT_RECORD_SIZE_SMALL: u32 = 512;
pub const MFT_RECORD_SIZE_STANDARD: u32 = 1024;

/// NTFS attribute type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    LoggedToolStream = 0x100,
    EndOfRecord = 0xFFFF_FFFF,
}

impl AttributeType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x10 => Some(Self::StandardInformation),
            0x20 => Some(Self::AttributeList),
            0x30 => Some(Self::FileName),
            0x40 => Some(Self::ObjectId),
            0x50 => Some(Self::SecurityDescriptor),
            0x60 => Some(Self::VolumeName),
            0x70 => Some(Self::VolumeInformation),
            0x80 => Some(Self::Data),
            0x90 => Some(Self::IndexRoot),
            0xA0 => Some(Self::IndexAllocation),
            0xB0 => Some(Self::Bitmap),
            0xC0 => Some(Self::ReparsePoint),
            0x100 => Some(Self::LoggedToolStream),
            0xFFFF_FFFF => Some(Self::EndOfRecord),
            _ => None,
        }
    }
}

// ─── MACB timestamps ──────────────────────────────────────────────────────────

/// The four NTFS timestamps for a file (MACB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacbTimestamps {
    /// Last modification time.
    pub modified: i64,
    /// Last access time.
    pub accessed: i64,
    /// MFT entry change time (metadata changed).
    pub changed: i64,
    /// File creation/birth time.
    pub born: i64,
}

impl MacbTimestamps {
    #[must_use]
    pub const fn from_filetimes(m: u64, a: u64, c: u64, b: u64) -> Self {
        Self {
            modified: filetime_to_unix(m),
            accessed: filetime_to_unix(a),
            changed: filetime_to_unix(c),
            born: filetime_to_unix(b),
        }
    }

    /// Return the earliest of the four timestamps.
    #[must_use]
    pub fn earliest(&self) -> i64 {
        [self.modified, self.accessed, self.changed, self.born]
            .iter()
            .copied()
            .filter(|&t| t > 0)
            .min()
            .unwrap_or(0)
    }

    /// Return the latest of the four timestamps.
    #[must_use]
    pub fn latest(&self) -> i64 {
        [self.modified, self.accessed, self.changed, self.born]
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }

    /// Detect timestamp manipulation: $`STANDARD_INFORMATION` modified earlier than $`FILE_NAME`.
    #[must_use]
    pub const fn is_timestomped_vs(&self, fn_stamps: &Self) -> bool {
        // If $SI modified < $FN modified by more than 1 second, suspect timestomping
        fn_stamps.modified - self.modified > 1
    }
}

const fn filetime_to_unix(ft: u64) -> i64 {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    ((ft.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
}

// ─── MFT record ───────────────────────────────────────────────────────────────

/// Flags from the MFT record header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftFlags {
    pub in_use: bool,
    pub is_directory: bool,
    pub is_extension: bool,
    pub is_special_index: bool,
}

impl MftFlags {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        Self {
            in_use: v & 0x01 != 0,
            is_directory: v & 0x02 != 0,
            is_extension: v & 0x04 != 0,
            is_special_index: v & 0x08 != 0,
        }
    }
}

/// A parsed NTFS MFT record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    /// Logical record number (index in $MFT).
    pub record_number: u64,
    /// Record sequence number.
    pub sequence_number: u16,
    /// Number of hard links.
    pub link_count: u16,
    /// Offset to the first attribute.
    pub first_attribute_offset: u16,
    /// Record flags.
    pub flags: MftFlags,
    /// Used size of the MFT record.
    pub bytes_in_use: u32,
    /// Allocated size of the MFT record.
    pub bytes_allocated: u32,
    /// Base MFT record reference (0 for base records).
    pub base_record: u64,
    /// Timestamps from $`STANDARD_INFORMATION`.
    pub si_timestamps: Option<MacbTimestamps>,
    /// Timestamps from $`FILE_NAME`.
    pub fn_timestamps: Option<MacbTimestamps>,
    /// File name.
    pub file_name: String,
    /// Parent directory MFT reference.
    pub parent_ref: u64,
    /// File size (logical).
    pub file_size: u64,
    /// Allocated file size.
    pub allocated_size: u64,
    /// File attributes from $`FILE_NAME`.
    pub file_attributes: u32,
    /// Data runs count (for non-resident $DATA).
    pub data_run_count: usize,
}

impl MftEntry {
    pub const SIGNATURE: &'static [u8; 4] = MFT_RECORD_SIG;

    /// Parse an MFT record from a raw slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn parse(data: &[u8], record_number: u64) -> Result<Self, TimelineError> {
        if data.len() < 48 {
            return Err(TimelineError::Truncated(0));
        }
        if &data[0..4] != Self::SIGNATURE {
            return Err(TimelineError::InvalidMftSignature(0));
        }
        let sequence_number = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let link_count = u16::from_le_bytes(data[18..20].try_into().unwrap());
        let first_attribute_offset = u16::from_le_bytes(data[20..22].try_into().unwrap());
        let flags_raw = u16::from_le_bytes(data[22..24].try_into().unwrap());
        let flags = MftFlags::from_u16(flags_raw);
        let bytes_in_use = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let bytes_allocated = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let base_record = u64::from_le_bytes(data[32..40].try_into().unwrap());

        // Parse attributes
        let mut si_timestamps = None;
        let mut fn_timestamps = None;
        let mut file_name = String::new();
        let mut parent_ref = 0u64;
        let mut file_size = 0u64;
        let mut allocated_size = 0u64;
        let mut file_attributes = 0u32;
        let mut data_run_count = 0usize;

        let mut attr_off = first_attribute_offset as usize;
        let limit = bytes_in_use as usize;

        loop {
            if attr_off + 4 > limit || attr_off + 4 > data.len() {
                break;
            }
            let attr_type_raw =
                u32::from_le_bytes(data[attr_off..attr_off + 4].try_into().unwrap());
            if attr_type_raw == 0xFFFF_FFFF {
                break;
            }
            if attr_off + 8 > data.len() {
                break;
            }
            let attr_len =
                u32::from_le_bytes(data[attr_off + 4..attr_off + 8].try_into().unwrap()) as usize;
            if attr_len == 0 || attr_off + attr_len > data.len() {
                break;
            }

            let non_resident = data[attr_off + 8] != 0;
            let content_off = u16::from_le_bytes(
                data[attr_off + 20..attr_off + 22]
                    .try_into()
                    .unwrap_or([0; 2]),
            ) as usize;
            let content_start = attr_off + content_off;
            let content = &data[content_start..(attr_off + attr_len).min(data.len())];

            match AttributeType::from_u32(attr_type_raw) {
                Some(AttributeType::StandardInformation) => {
                    if content.len() >= 32 {
                        let m = u64::from_le_bytes(content[0..8].try_into().unwrap_or([0; 8]));
                        let a = u64::from_le_bytes(content[8..16].try_into().unwrap_or([0; 8]));
                        let c = u64::from_le_bytes(content[16..24].try_into().unwrap_or([0; 8]));
                        let b = u64::from_le_bytes(content[24..32].try_into().unwrap_or([0; 8]));
                        si_timestamps = Some(MacbTimestamps::from_filetimes(m, a, c, b));
                    }
                }
                Some(AttributeType::FileName) => {
                    if content.len() >= 66 {
                        parent_ref = u64::from_le_bytes(content[0..8].try_into().unwrap_or([0; 8]));
                        let m = u64::from_le_bytes(content[8..16].try_into().unwrap_or([0; 8]));
                        let a = u64::from_le_bytes(content[16..24].try_into().unwrap_or([0; 8]));
                        let c = u64::from_le_bytes(content[24..32].try_into().unwrap_or([0; 8]));
                        let b = u64::from_le_bytes(content[32..40].try_into().unwrap_or([0; 8]));
                        fn_timestamps = Some(MacbTimestamps::from_filetimes(m, a, c, b));
                        allocated_size =
                            u64::from_le_bytes(content[40..48].try_into().unwrap_or([0; 8]));
                        file_size =
                            u64::from_le_bytes(content[48..56].try_into().unwrap_or([0; 8]));
                        file_attributes =
                            u32::from_le_bytes(content[56..60].try_into().unwrap_or([0; 4]));
                        let fname_len = content[64] as usize;
                        if 66 + fname_len * 2 <= content.len() {
                            let fname_shorts: Vec<u16> = content[66..66 + fname_len * 2]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            file_name = String::from_utf16_lossy(&fname_shorts);
                        }
                    }
                }
                Some(AttributeType::Data) if non_resident => {
                    data_run_count += 1;
                }
                _ => {}
            }
            attr_off += attr_len;
        }

        Ok(Self {
            record_number,
            sequence_number,
            link_count,
            first_attribute_offset,
            flags,
            bytes_in_use,
            bytes_allocated,
            base_record,
            si_timestamps,
            fn_timestamps,
            file_name,
            parent_ref,
            file_size,
            allocated_size,
            file_attributes,
            data_run_count,
        })
    }

    /// Returns `true` if the file has been timestomped.
    #[must_use]
    pub const fn is_timestomped(&self) -> bool {
        match (&self.si_timestamps, &self.fn_timestamps) {
            (Some(si), Some(fn_)) => si.is_timestomped_vs(fn_),
            _ => false,
        }
    }
}

// ─── MFT parser ───────────────────────────────────────────────────────────────

/// Scan a raw byte slice for MFT records.
pub struct MftScanner;

impl MftScanner {
    /// Scan `data` for FILE records using the standard 1024-byte stride.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<MftEntry> {
        let mut entries = Vec::new();
        let stride = MFT_RECORD_SIZE_STANDARD as usize;
        for (record_num, chunk) in data.chunks(stride).enumerate().map(|(i, c)| (i as u64, c)) {
            if chunk.len() >= 4 && &chunk[..4] == MFT_RECORD_SIG
                && let Ok(entry) = MftEntry::parse(chunk, record_num) {
                    entries.push(entry);
                }
        }
        entries
    }

    /// Scan with a 512-byte stride for older/compressed MFT formats.
    #[must_use]
    pub fn scan_small(data: &[u8]) -> Vec<MftEntry> {
        let mut entries = Vec::new();
        let stride = MFT_RECORD_SIZE_SMALL as usize;
        for (record_num, chunk) in data.chunks(stride).enumerate().map(|(i, c)| (i as u64, c)) {
            if chunk.len() >= 4 && &chunk[..4] == MFT_RECORD_SIG
                && let Ok(entry) = MftEntry::parse(chunk, record_num) {
                    entries.push(entry);
                }
        }
        entries
    }
}

// ─── Timeline event ───────────────────────────────────────────────────────────

/// A single timeline event derived from filesystem metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: i64,
    pub timestamp_type: TimestampType,
    pub file_name: String,
    pub record_number: u64,
    pub file_size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
    pub source: TimelineSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampType {
    Modified,
    Accessed,
    Changed,
    Born,
}

impl TimestampType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Modified => "M",
            Self::Accessed => "A",
            Self::Changed => "C",
            Self::Born => "B",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineSource {
    MftStandardInfo,
    MftFileName,
    UsnJournal,
    Prefetch,
    EventLog,
}

// ─── Timeline builder ─────────────────────────────────────────────────────────

/// Builds a timeline from MFT entries.
pub struct TimelineBuilder;

impl TimelineBuilder {
    /// Convert MFT entries into timeline events (4 events per file: MACB).
    #[must_use]
    pub fn from_mft(entries: &[MftEntry]) -> Vec<TimelineEvent> {
        let mut events = Vec::new();
        for entry in entries {
            let is_dir = entry.flags.is_directory;
            let is_del = !entry.flags.in_use;
            if let Some(ref si) = entry.si_timestamps {
                Self::push_macb(
                    &mut events,
                    si,
                    &entry.file_name,
                    entry.record_number,
                    entry.file_size,
                    is_dir,
                    is_del,
                    TimelineSource::MftStandardInfo,
                );
            }
            if let Some(ref fn_) = entry.fn_timestamps {
                Self::push_macb(
                    &mut events,
                    fn_,
                    &entry.file_name,
                    entry.record_number,
                    entry.file_size,
                    is_dir,
                    is_del,
                    TimelineSource::MftFileName,
                );
            }
        }
        events.sort_by_key(|e| e.timestamp);
        events
    }

    fn push_macb(
        events: &mut Vec<TimelineEvent>,
        ts: &MacbTimestamps,
        name: &str,
        rec: u64,
        size: u64,
        is_dir: bool,
        is_del: bool,
        source: TimelineSource,
    ) {
        let types = [
            (ts.modified, TimestampType::Modified),
            (ts.accessed, TimestampType::Accessed),
            (ts.changed, TimestampType::Changed),
            (ts.born, TimestampType::Born),
        ];
        for (t, typ) in types {
            if t > 0 {
                events.push(TimelineEvent {
                    timestamp: t,
                    timestamp_type: typ,
                    file_name: name.to_string(),
                    record_number: rec,
                    file_size: size,
                    is_directory: is_dir,
                    is_deleted: is_del,
                    source: source.clone(),
                });
            }
        }
    }

    /// Group timeline events by date (YYYY-MM-DD).
    #[must_use]
    pub fn group_by_day(events: &[TimelineEvent]) -> HashMap<String, Vec<&TimelineEvent>> {
        let mut map: HashMap<String, Vec<&TimelineEvent>> = HashMap::new();
        for e in events {
            let day = unix_to_date_str(e.timestamp);
            map.entry(day).or_default().push(e);
        }
        map
    }
}

fn unix_to_date_str(unix: i64) -> String {
    if unix <= 0 {
        return "1970-01-01".into();
    }
    // Very simple: compute year/month/day from Unix timestamp
    let days = unix / 86400;
    let mut year = 1970i32;
    let mut rem = days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if rem < days_in_year {
            break;
        }
        rem -= days_in_year;
        year += 1;
    }
    let months = if is_leap(year) {
        &[31i32, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31i32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1i32;
    for &m in months {
        let m_i64: i64 = i64::from(m);
        if rem < m_i64 {
            break;
        }
        rem -= m_i64;
        month += 1;
    }
    format!("{:04}-{:02}-{:02}", year, month, rem + 1)
}

const fn is_leap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

// ─── USN Journal parser ───────────────────────────────────────────────────────

/// A USN journal change reason bitmask.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnReasons {
    pub data_overwrite: bool,
    pub data_extend: bool,
    pub data_truncation: bool,
    pub named_data_overwrite: bool,
    pub named_data_extend: bool,
    pub named_data_truncation: bool,
    pub file_create: bool,
    pub file_delete: bool,
    pub ea_change: bool,
    pub security_change: bool,
    pub rename_old_name: bool,
    pub rename_new_name: bool,
    pub indexable_change: bool,
    pub basic_info_change: bool,
    pub hard_link_change: bool,
    pub compression_change: bool,
    pub encryption_change: bool,
    pub object_id_change: bool,
    pub reparse_point_change: bool,
    pub stream_change: bool,
    pub close: bool,
}

impl UsnReasons {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        Self {
            data_overwrite: v & 0x0000_0001 != 0,
            data_extend: v & 0x0000_0002 != 0,
            data_truncation: v & 0x0000_0004 != 0,
            named_data_overwrite: v & 0x0000_0010 != 0,
            named_data_extend: v & 0x0000_0020 != 0,
            named_data_truncation: v & 0x0000_0040 != 0,
            file_create: v & 0x0000_0100 != 0,
            file_delete: v & 0x0000_0200 != 0,
            ea_change: v & 0x0000_0400 != 0,
            security_change: v & 0x0000_0800 != 0,
            rename_old_name: v & 0x0000_1000 != 0,
            rename_new_name: v & 0x0000_2000 != 0,
            indexable_change: v & 0x0000_4000 != 0,
            basic_info_change: v & 0x0000_8000 != 0,
            hard_link_change: v & 0x0001_0000 != 0,
            compression_change: v & 0x0002_0000 != 0,
            encryption_change: v & 0x0004_0000 != 0,
            object_id_change: v & 0x0008_0000 != 0,
            reparse_point_change: v & 0x0010_0000 != 0,
            stream_change: v & 0x0020_0000 != 0,
            close: v & 0x8000_0000 != 0,
        }
    }
}

/// A single USN journal record (`USN_RECORD_V2`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnRecord {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub parent_file_reference: u64,
    pub usn: u64,
    pub time_stamp: i64,
    pub reason: UsnReasons,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
}

/// Parser for USN journal ($UsnJrnl:$J) data.
pub struct UsnJournalParser;

impl UsnJournalParser {
    #[must_use]
    pub fn parse(data: &[u8]) -> Vec<UsnRecord> {
        let mut records = Vec::new();
        let mut pos = 0usize;
        while pos + 60 <= data.len() {
            let record_length = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4]));
            if record_length == 0 {
                pos += 8;
                continue;
            }
            if record_length < 60 || record_length as usize + pos > data.len() {
                pos += 4;
                continue;
            }
            let major_version =
                u16::from_le_bytes(data[pos + 4..pos + 6].try_into().unwrap_or([0; 2]));
            if major_version != 2 {
                pos += record_length as usize;
                continue;
            }
            let minor_version =
                u16::from_le_bytes(data[pos + 6..pos + 8].try_into().unwrap_or([0; 2]));
            let file_reference_number =
                u64::from_le_bytes(data[pos + 8..pos + 16].try_into().unwrap_or([0; 8]));
            let parent_file_reference =
                u64::from_le_bytes(data[pos + 16..pos + 24].try_into().unwrap_or([0; 8]));
            let usn = u64::from_le_bytes(data[pos + 24..pos + 32].try_into().unwrap_or([0; 8]));
            let time_ft = u64::from_le_bytes(data[pos + 32..pos + 40].try_into().unwrap_or([0; 8]));
            let reason_raw =
                u32::from_le_bytes(data[pos + 40..pos + 44].try_into().unwrap_or([0; 4]));
            let source_info =
                u32::from_le_bytes(data[pos + 44..pos + 48].try_into().unwrap_or([0; 4]));
            let security_id =
                u32::from_le_bytes(data[pos + 48..pos + 52].try_into().unwrap_or([0; 4]));
            let file_attributes =
                u32::from_le_bytes(data[pos + 52..pos + 56].try_into().unwrap_or([0; 4]));
            let fname_length =
                u16::from_le_bytes(data[pos + 56..pos + 58].try_into().unwrap_or([0; 2])) as usize;
            let fname_offset =
                u16::from_le_bytes(data[pos + 58..pos + 60].try_into().unwrap_or([0; 2])) as usize;
            let fname_start = pos + fname_offset;
            let fname_end = (fname_start + fname_length)
                .min(pos + record_length as usize)
                .min(data.len());
            let fname_shorts: Vec<u16> = data[fname_start..fname_end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let file_name = String::from_utf16_lossy(&fname_shorts);
            records.push(UsnRecord {
                record_length,
                major_version,
                minor_version,
                file_reference_number,
                parent_file_reference,
                usn,
                time_stamp: filetime_to_unix(time_ft),
                reason: UsnReasons::from_u32(reason_raw),
                source_info,
                security_id,
                file_attributes,
                file_name,
            });
            pos += record_length as usize;
        }
        records
    }

    /// Convert USN records to timeline events.
    #[must_use]
    pub fn to_timeline_events(records: &[UsnRecord]) -> Vec<TimelineEvent> {
        records
            .iter()
            .map(|r| TimelineEvent {
                timestamp: r.time_stamp,
                timestamp_type: if r.reason.file_create {
                    TimestampType::Born
                } else if r.reason.data_overwrite || r.reason.data_extend {
                    TimestampType::Modified
                } else {
                    TimestampType::Changed
                },
                file_name: r.file_name.clone(),
                record_number: r.file_reference_number & 0x0000_FFFF_FFFF_FFFF,
                file_size: 0,
                is_directory: r.file_attributes & 0x10 != 0,
                is_deleted: r.reason.file_delete,
                source: TimelineSource::UsnJournal,
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mft_record(name: &str) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"FILE");
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // update_seq_offset
        data[6..8].copy_from_slice(&1u16.to_le_bytes()); // update_seq_count
        data[18..20].copy_from_slice(&1u16.to_le_bytes()); // link_count
        data[20..22].copy_from_slice(&56u16.to_le_bytes()); // first_attr_offset
        data[22..24].copy_from_slice(&1u16.to_le_bytes()); // flags: IN_USE
        data[24..28].copy_from_slice(&200u32.to_le_bytes()); // bytes_in_use
        data[28..32].copy_from_slice(&1024u32.to_le_bytes()); // bytes_alloc
        // $STANDARD_INFORMATION at offset 56
        let si_off = 56usize;
        data[si_off..si_off + 4].copy_from_slice(&0x10u32.to_le_bytes()); // type
        data[si_off + 4..si_off + 8].copy_from_slice(&96u32.to_le_bytes()); // length
        data[si_off + 8] = 0; // resident
        data[si_off + 20..si_off + 22].copy_from_slice(&24u16.to_le_bytes()); // content_off=24
        // Put timestamps at si_off+24 (all zeros = 1601)
        // $FILE_NAME at offset 56+96=152
        let fn_off = si_off + 96;
        data[fn_off..fn_off + 4].copy_from_slice(&0x30u32.to_le_bytes()); // type
        let fn_content_off = 24usize;
        let fname_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes().to_vec())
            .collect();
        let fn_attr_len = (fn_content_off + 66 + fname_utf16.len()) as u32;
        data[fn_off + 4..fn_off + 8].copy_from_slice(&fn_attr_len.to_le_bytes()); // length
        data[fn_off + 8] = 0; // resident
        data[fn_off + 20..fn_off + 22].copy_from_slice(&(fn_content_off as u16).to_le_bytes()); // content_off
        let fn_c = fn_off + fn_content_off;
        data[fn_c + 64] = name.len() as u8; // fname_len
        let end = (fn_c + 66 + fname_utf16.len()).min(data.len());
        data[fn_c + 66..end].copy_from_slice(&fname_utf16[..end - fn_c - 66]);
        // End of record
        let eor_off = fn_off + fn_attr_len as usize;
        if eor_off + 4 <= data.len() {
            data[eor_off..eor_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }
        data
    }

    #[test]
    fn mft_entry_parse_valid() {
        let data = make_mft_record("test.txt");
        let entry = MftEntry::parse(&data, 5).unwrap();
        assert_eq!(entry.record_number, 5);
        assert!(entry.flags.in_use);
        assert!(!entry.flags.is_directory);
    }

    #[test]
    fn mft_entry_parse_invalid_sig() {
        let data = vec![0u8; 1024];
        assert!(MftEntry::parse(&data, 0).is_err());
    }

    #[test]
    fn mft_scanner_finds_records() {
        let mut data = vec![0u8; 1024 * 3];
        let record = make_mft_record("file.txt");
        data[0..1024].copy_from_slice(&record);
        data[2048..3072].copy_from_slice(&record);
        let entries = MftScanner::scan(&data);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn macb_timestamps_earliest() {
        let ts = MacbTimestamps {
            modified: 1000,
            accessed: 2000,
            changed: 500,
            born: 300,
        };
        assert_eq!(ts.earliest(), 300);
        assert_eq!(ts.latest(), 2000);
    }

    #[test]
    fn timestomping_detection() {
        let si = MacbTimestamps {
            modified: 100,
            accessed: 200,
            changed: 300,
            born: 50,
        };
        let fn_ = MacbTimestamps {
            modified: 200,
            accessed: 300,
            changed: 400,
            born: 100,
        };
        assert!(si.is_timestomped_vs(&fn_));
    }

    #[test]
    fn timeline_builder_from_mft() {
        let entry = MftEntry {
            record_number: 1,
            sequence_number: 1,
            link_count: 1,
            first_attribute_offset: 56,
            flags: MftFlags::from_u16(1),
            bytes_in_use: 200,
            bytes_allocated: 1024,
            base_record: 0,
            si_timestamps: Some(MacbTimestamps {
                modified: 1_700_000_000,
                accessed: 1_700_000_001,
                changed: 1_700_000_002,
                born: 1_699_000_000,
            }),
            fn_timestamps: None,
            file_name: "important.doc".into(),
            parent_ref: 5,
            file_size: 4096,
            allocated_size: 4096,
            file_attributes: 0x20,
            data_run_count: 1,
        };
        let events = TimelineBuilder::from_mft(&[entry]);
        // 4 events (MACB) all from SI timestamps
        assert_eq!(events.len(), 4);
        assert!(
            events
                .iter()
                .any(|e| e.timestamp_type == TimestampType::Born)
        );
    }

    #[test]
    fn unix_to_date_str_basic() {
        // 2023-01-01 = 1672531200
        let d = unix_to_date_str(1_672_531_200);
        assert_eq!(d, "2023-01-01");
    }

    #[test]
    fn usn_journal_parse_empty() {
        let data = vec![0u8; 1024];
        let records = UsnJournalParser::parse(&data);
        assert!(records.is_empty());
    }

    #[test]
    fn usn_reasons_from_u32() {
        let r = UsnReasons::from_u32(0x0000_0100); // FILE_CREATE
        assert!(r.file_create);
        assert!(!r.file_delete);
        let r2 = UsnReasons::from_u32(0x0000_0200); // FILE_DELETE
        assert!(r2.file_delete);
        assert!(!r2.file_create);
    }

    #[test]
    fn attribute_type_from_u32() {
        assert_eq!(
            AttributeType::from_u32(0x10),
            Some(AttributeType::StandardInformation)
        );
        assert_eq!(AttributeType::from_u32(0x30), Some(AttributeType::FileName));
        assert_eq!(AttributeType::from_u32(0x80), Some(AttributeType::Data));
        assert_eq!(AttributeType::from_u32(0x99), None);
    }

    #[test]
    fn mft_flags_parsing() {
        let f = MftFlags::from_u16(0x03);
        assert!(f.in_use);
        assert!(f.is_directory);
        let f2 = MftFlags::from_u16(0x00);
        assert!(!f2.in_use);
    }
}
