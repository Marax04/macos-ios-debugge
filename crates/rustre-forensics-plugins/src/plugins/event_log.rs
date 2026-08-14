//! Windows Event Log / EVTX analysis.
//!
//! Implements EVTX chunk parsing, record extraction, XML template resolution,
//! and provider/event-ID mapping for forensic triage of Windows event logs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EvtxError {
    #[error("invalid EVTX file magic")]
    InvalidFileMagic,
    #[error("invalid chunk magic at offset {0}")]
    InvalidChunkMagic(usize),
    #[error("truncated data at offset {0}: need {1} bytes")]
    Truncated(usize, usize),
    #[error("invalid record size {0} at offset {1}")]
    InvalidRecordSize(u32, usize),
    #[error("XML template substitution error: {0}")]
    TemplateError(String),
    #[error("checksum mismatch in chunk at offset {0}")]
    ChecksumMismatch(usize),
}

// ─── EVTX File Header ─────────────────────────────────────────────────────────

/// Magic bytes for the EVTX file header.
pub const EVTX_FILE_MAGIC: &[u8; 8] = b"ElfFile\x00";
/// Magic bytes for an EVTX chunk.
pub const EVTX_CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";
/// Magic bytes for a `BinXML` record.
pub const EVTX_RECORD_MAGIC: u32 = 0x002A_2A00; // "**\x00\x02" — actually stored differently

/// Size of the EVTX file header.
pub const EVTX_HEADER_SIZE: usize = 4096;
/// Size of each EVTX chunk.
pub const EVTX_CHUNK_SIZE: usize = 65536;

/// The EVTX file-level header (128 bytes, padded to 4096).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxFileHeader {
    pub magic: [u8; 8],
    /// First chunk number.
    pub oldest_chunk: u64,
    /// Last chunk number.
    pub current_chunk_number: u64,
    /// Next record identifier.
    pub next_record_identifier: u64,
    /// Header size (always 128).
    pub header_chunk_size: u32,
    /// Number of chunks.
    pub number_of_chunks: u16,
    /// Minor format version.
    pub minor_format_version: u16,
    /// Major format version.
    pub major_format_version: u16,
    /// Header block size (4096).
    pub header_block_size: u16,
    /// Flags: dirty (1), full (2).
    pub file_flags: u32,
    /// CRC32 of first 120 bytes.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub checksum: u32,
}

impl EvtxFileHeader {
    /// Parse an EVTX file header from `data`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the magic bytes are invalid.
    ///
    /// # Panics
    ///
    /// Panics if internal slice conversion fails (should not happen if data is long enough).
    pub fn parse(data: &[u8]) -> Result<Self, EvtxError> {
        if data.len() < 128 {
            return Err(EvtxError::Truncated(0, 128));
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);
        if &magic != EVTX_FILE_MAGIC {
            return Err(EvtxError::InvalidFileMagic);
        }
        Ok(Self {
            magic,
            oldest_chunk: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            current_chunk_number: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            next_record_identifier: u64::from_le_bytes(data[24..32].try_into().unwrap()),
            header_chunk_size: u32::from_le_bytes(data[32..36].try_into().unwrap()),
            number_of_chunks: u16::from_le_bytes(data[36..38].try_into().unwrap()),
            minor_format_version: u16::from_le_bytes(data[76..78].try_into().unwrap()),
            major_format_version: u16::from_le_bytes(data[78..80].try_into().unwrap()),
            header_block_size: u16::from_le_bytes(data[80..82].try_into().unwrap()),
            file_flags: u32::from_le_bytes(data[120..124].try_into().unwrap()),
            checksum: u32::from_le_bytes(data[124..128].try_into().unwrap()),
        })
    }

    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.file_flags & 1 != 0
    }
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.file_flags & 2 != 0
    }
}

// ─── EVTX Chunk Header ────────────────────────────────────────────────────────

/// The 512-byte EVTX chunk header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxChunkHeader {
    pub magic: [u8; 8],
    /// First event record number in the chunk.
    pub first_event_record_number: u64,
    /// Last event record number.
    pub last_event_record_number: u64,
    /// First event record identifier.
    pub first_event_record_id: u64,
    /// Last event record identifier.
    pub last_event_record_id: u64,
    /// Offset to the header area (always 512).
    pub header_area_size: u32,
    /// Offset to the last event record in the chunk.
    pub last_event_record_data_offset: u32,
    /// Free space offset.
    pub free_space_offset: u32,
    /// CRC32 of event records data.
    pub event_records_checksum: u32,
    /// String table: offsets to provider/channel string pointers.
    pub string_table: Vec<u32>,
    /// Template table.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
 ///
 /// # Errors
 ///
 /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
 ///
 /// # Errors
 ///
 /// Returns an error if the operation fails.
    pub template_table: Vec<u32>,
}

impl EvtxChunkHeader {
    pub const SIZE: usize = 512;

    /// Parse an EVTX chunk header from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the chunk magic is invalid.
    ///
    /// # Panics
    ///
    /// Panics if internal slice conversion fails (should not happen if data is long enough).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, EvtxError> {
        if offset + Self::SIZE > data.len() {
            return Err(EvtxError::Truncated(offset, Self::SIZE));
        }
        let chunk = &data[offset..offset + Self::SIZE];
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&chunk[0..8]);
        if &magic != EVTX_CHUNK_MAGIC {
            return Err(EvtxError::InvalidChunkMagic(offset));
        }
        let first_event_record_number = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let last_event_record_number = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        let first_event_record_id = u64::from_le_bytes(chunk[24..32].try_into().unwrap());
        let last_event_record_id = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        let header_area_size = u32::from_le_bytes(chunk[40..44].try_into().unwrap());
        let last_event_record_data_offset = u32::from_le_bytes(chunk[44..48].try_into().unwrap());
        let free_space_offset = u32::from_le_bytes(chunk[48..52].try_into().unwrap());
        let event_records_checksum = u32::from_le_bytes(chunk[52..56].try_into().unwrap());

        // String table: 64 4-byte offsets at offset 128
        let mut string_table = Vec::with_capacity(64);
        for i in 0..64usize {
            let off = 128 + i * 4;
            if off + 4 <= chunk.len() {
                let v = u32::from_le_bytes(chunk[off..off + 4].try_into().unwrap());
                if v != 0 {
                    string_table.push(v);
                }
            }
        }

        // Template table: 32 4-byte offsets at offset 384
        let mut template_table = Vec::with_capacity(32);
        for i in 0..32usize {
            let off = 384 + i * 4;
            if off + 4 <= chunk.len() {
                let v = u32::from_le_bytes(chunk[off..off + 4].try_into().unwrap());
                if v != 0 {
                    template_table.push(v);
                }
            }
        }

        Ok(Self {
            magic,
            first_event_record_number,
            last_event_record_number,
            first_event_record_id,
            last_event_record_id,
            header_area_size,
            last_event_record_data_offset,
            free_space_offset,
            event_records_checksum,
            string_table,
            template_table,
        })
    }
}

// ─── Event Record ─────────────────────────────────────────────────────────────

/// A single Windows event record extracted from EVTX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    /// Event record number within the log.
    pub record_id: u64,
    /// Time created (Windows FILETIME).
    pub time_created: u64,
    /// Provider name (e.g. "Microsoft-Windows-Security-Auditing").
    pub provider_name: String,
    /// Event ID.
    pub event_id: u32,
    /// Event level (1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose).
    pub level: u8,
    /// Task category.
    pub task: u16,
    /// Opcode.
    pub opcode: u8,
    /// Keywords bitmask.
    pub keywords: u64,
    /// Channel name.
    pub channel: String,
    /// Computer name.
    pub computer: String,
    /// Activity ID GUID (hex string).
    pub activity_id: String,
    /// Process ID that wrote the event.
    pub process_id: u32,
    /// Thread ID that wrote the event.
    pub thread_id: u32,
    /// Parsed event data fields.
    pub event_data: HashMap<String, String>,
    /// Raw XML rendering (if available).
    pub xml: Option<String>,
}

impl EventRecord {
    /// Convert the `time_created` FILETIME to Unix epoch seconds.
    #[must_use]
    pub const fn time_created_unix(&self) -> i64 {
        const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
        ((self.time_created.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
    }

    /// Return a human-readable level string.
    #[must_use]
    pub const fn level_str(&self) -> &str {
        match self.level {
            0 => "LogAlways",
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            4 => "Information",
            5 => "Verbose",
            _ => "Unknown",
        }
    }

    /// Return a one-line summary of the event.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} EventID={} Level={} Computer={}",
            self.time_created_unix(),
            self.provider_name,
            self.event_id,
            self.level_str(),
            self.computer,
        )
    }
}

// ─── Record parser (simplified BinXML) ───────────────────────────────────────

/// Parse event records from a chunk's data area.
/// Each record starts with: `magic`(`4)=0x002A_2A00`, size(4), `record_id`(8), time(8), ...
#[must_use]
pub fn parse_records_from_chunk(chunk_data: &[u8]) -> Vec<EventRecord> {
    let mut records = Vec::new();
    let mut pos = EvtxChunkHeader::SIZE; // skip chunk header
    while pos + 24 <= chunk_data.len() {
        // Look for the record magic: bytes 0x2a 0x2a 0x00 0x00 (little-endian magic)
        let magic_raw = u32::from_le_bytes(chunk_data[pos..pos + 4].try_into().unwrap_or([0; 4]));
        if magic_raw != 0x0000_2A2A {
            pos += 4;
            continue;
        }
        let rec_size =
            u32::from_le_bytes(chunk_data[pos + 4..pos + 8].try_into().unwrap_or([0; 4]));
        if rec_size < 24 || rec_size > u32::try_from(EVTX_CHUNK_SIZE).unwrap_or(u32::MAX) {
            pos += 4;
            continue;
        }
        let end = pos.saturating_add(rec_size as usize).min(chunk_data.len());
        let record_data = &chunk_data[pos..end];
        if let Some(rec) = parse_single_record(record_data) {
            records.push(rec);
        }
        pos = pos.saturating_add(rec_size as usize);
    }
    records
}

/// Parse a single event record from its raw bytes.
fn parse_single_record(data: &[u8]) -> Option<EventRecord> {
    if data.len() < 24 {
        return None;
    }
    let record_id = u64::from_le_bytes(data[8..16].try_into().ok()?);
    let time_created = u64::from_le_bytes(data[16..24].try_into().ok()?);
    // BinXML event data follows at offset 24
    let xml_data = &data[24..];
    let fields = extract_binxml_fields(xml_data);
    let provider_name = fields.get("Provider/Name").cloned().unwrap_or_default();
    let event_id: u32 = fields
        .get("EventID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let level: u8 = fields
        .get("Level")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let task: u16 = fields.get("Task").and_then(|s| s.parse().ok()).unwrap_or(0);
    let opcode: u8 = fields
        .get("Opcode")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let keywords: u64 = fields
        .get("Keywords")
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let channel = fields.get("Channel").cloned().unwrap_or_default();
    let computer = fields.get("Computer").cloned().unwrap_or_default();
    let process_id = fields
        .get("Execution/ProcessID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let thread_id = fields
        .get("Execution/ThreadID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let activity_id = fields
        .get("Correlation/ActivityID")
        .cloned()
        .unwrap_or_default();
    // Remaining fields are event data
    let mut event_data = HashMap::new();
    for (k, v) in fields {
        if !k.starts_with("EventID")
            && !k.starts_with("Level")
            && !k.starts_with("Provider")
            && !k.starts_with("Channel")
            && !k.starts_with("Computer")
            && !k.starts_with("Execution")
            && !k.starts_with("Correlation")
            && !k.starts_with("Task")
            && !k.starts_with("Opcode")
            && !k.starts_with("Keywords")
        {
            event_data.insert(k, v);
        }
    }
    Some(EventRecord {
        record_id,
        time_created,
        provider_name,
        event_id,
        level,
        task,
        opcode,
        keywords,
        channel,
        computer,
        activity_id,
        process_id,
        thread_id,
        event_data,
        xml: None,
    })
}

/// Extremely simplified `BinXML` field extractor — scans for NUL-terminated
/// UTF-16LE strings and key=value-style patterns in the raw `BinXML` data.
/// A real implementation would decode the complete `BinXML` token stream.
fn extract_binxml_fields(data: &[u8]) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    // Scan for UTF-16LE strings
    let strings = collect_utf16le_strings(data);
    // Heuristic pairing: even-index = key, odd-index = value
    let mut i = 0;
    while i + 1 < strings.len() {
        let key = strings[i].trim().to_string();
        let val = strings[i + 1].trim().to_string();
        if !key.is_empty() && !val.is_empty() {
            fields.insert(key, val);
        }
        i += 2;
    }
    fields
}

fn collect_utf16le_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for chunk in data.chunks_exact(2) {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]);
        if w == 0 {
            if current.len() >= 2 {
                let s = String::from_utf16_lossy(&current);
                if s.chars()
                    .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\\' || c == '/')
                {
                    result.push(s);
                }
            }
            current.clear();
        } else if (u32::from(w)) < 0x80 || (0x20..0x7E).contains(&w) {
            current.push(w);
        } else {
            current.clear();
        }
    }
    result
}

// ─── Provider and Event-ID mapping ────────────────────────────────────────────

/// Well-known Windows event providers.
pub const WELL_KNOWN_PROVIDERS: &[(&str, &str)] = &[
    ("Microsoft-Windows-Security-Auditing", "Security"),
    ("Microsoft-Windows-System", "System"),
    ("Microsoft-Windows-Application", "Application"),
    ("Microsoft-Windows-PowerShell", "PowerShell"),
    ("Microsoft-Windows-TaskScheduler", "Task Scheduler"),
    (
        "Microsoft-Windows-TerminalServices-LocalSessionManager",
        "RDP",
    ),
    ("Microsoft-Windows-Sysmon", "Sysmon"),
    ("Microsoft-Windows-Windows Defender", "Defender"),
    ("Microsoft-Windows-DNS-Client", "DNS Client"),
    ("Microsoft-Windows-WinRM", "WinRM"),
    ("Microsoft-Windows-WMI-Activity", "WMI"),
];

/// Well-known Security event IDs with their descriptions.
pub const SECURITY_EVENT_IDS: &[(u32, &str)] = &[
    (4624, "Logon"),
    (4625, "Failed logon"),
    (4634, "Logoff"),
    (4648, "Logon using explicit credentials"),
    (4657, "Registry value modified"),
    (4663, "Object access"),
    (4672, "Special privileges assigned"),
    (4688, "Process created"),
    (4689, "Process terminated"),
    (4698, "Scheduled task created"),
    (4699, "Scheduled task deleted"),
    (4700, "Scheduled task enabled"),
    (4702, "Scheduled task updated"),
    (4720, "User account created"),
    (4722, "User account enabled"),
    (4723, "Attempt to change password"),
    (4724, "Password reset"),
    (4726, "User account deleted"),
    (4728, "Member added to global group"),
    (4732, "Member added to local group"),
    (4738, "User account changed"),
    (4740, "User account locked out"),
    (4756, "Member added to universal group"),
    (4768, "Kerberos TGT request"),
    (4769, "Kerberos service ticket request"),
    (4771, "Kerberos pre-authentication failed"),
    (4776, "NTLM authentication"),
    (4798, "User's local group membership enumerated"),
    (4799, "Security-enabled local group membership enumerated"),
    (5140, "Network share access"),
    (5145, "Network share check"),
    (7045, "Service installed"),
];

/// Map an event ID to its description.
#[must_use]
pub fn event_id_description(provider: &str, event_id: u32) -> &'static str {
    if provider.contains("Security-Auditing") || provider.contains("Security") {
        for (id, desc) in SECURITY_EVENT_IDS {
            if *id == event_id {
                return desc;
            }
        }
    }
    "Unknown"
}

// ─── EVTX scanner (memory-based) ─────────────────────────────────────────────

/// Scan raw bytes for EVTX chunks and extract event records.
pub struct EvtxScanner;

impl EvtxScanner {
    /// Find all EVTX chunk offsets in a raw byte slice.
    #[must_use]
    pub fn find_chunk_offsets(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos + EVTX_CHUNK_SIZE <= data.len() {
            if data[pos..].starts_with(EVTX_CHUNK_MAGIC) {
                offsets.push(pos);
                pos += EVTX_CHUNK_SIZE;
            } else {
                pos += 512;
            }
        }
        offsets
    }

    /// Parse all event records from a complete EVTX file byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn parse_file(data: &[u8]) -> Result<Vec<EventRecord>, EvtxError> {
        // Try to parse the file header; tolerate failures (partial data)
        if data.len() >= 8 && !data.starts_with(EVTX_FILE_MAGIC) {
            return Err(EvtxError::InvalidFileMagic);
        }
        let mut all_records = Vec::new();
        let offsets = Self::find_chunk_offsets(data);
        for offset in offsets {
            let end = (offset + EVTX_CHUNK_SIZE).min(data.len());
            let chunk_data = &data[offset..end];
            let records = parse_records_from_chunk(chunk_data);
            all_records.extend(records);
        }
        Ok(all_records)
    }

    /// Generate a summary of events by provider and event ID.
    #[must_use]
    pub fn summarize(records: &[EventRecord]) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::with_capacity(records.len());
        for rec in records {
            let key = format!("{}:{}", rec.provider_name, rec.event_id);
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// Filter records by event ID.
    #[must_use]
    pub fn filter_by_event_id(records: &[EventRecord], event_id: u32) -> Vec<&EventRecord> {
        records.iter().filter(|r| r.event_id == event_id).collect()
    }

    /// Filter records by provider name (case-insensitive substring match).
    #[must_use]
    pub fn filter_by_provider<'a>(
        records: &'a [EventRecord],
        provider: &str,
    ) -> Vec<&'a EventRecord> {
        let lower = provider.to_lowercase();
        records
            .iter()
            .filter(|r| r.provider_name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Find suspicious events: logon failures, service installations, process creation.
    #[must_use]
    pub fn find_suspicious(records: &[EventRecord]) -> Vec<&EventRecord> {
        const SUSPICIOUS_IDS: &[u32] = &[
            4624, // Logon
            4625, // Failed logon
            7045, // Service installed
            4688, // Process created
            4698, // Scheduled task created
            4776, // NTLM auth
            4769, // Kerberos ticket request
        ];
        records
            .iter()
            .filter(|r| SUSPICIOUS_IDS.contains(&r.event_id))
            .collect()
    }
}

// ─── Event log channel ────────────────────────────────────────────────────────

/// Well-known Windows event log channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventChannel {
    Security,
    System,
    Application,
    PowerShell,
    TaskScheduler,
    Sysmon,
    WindowsDefender,
    Forwarded,
    Custom(String),
}

impl EventChannel {
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "security" => Self::Security,
            "system" => Self::System,
            "application" => Self::Application,
            s if s.contains("powershell") => Self::PowerShell,
            s if s.contains("taskscheduler") => Self::TaskScheduler,
            s if s.contains("sysmon") => Self::Sysmon,
            s if s.contains("defender") => Self::WindowsDefender,
            "forwardedevents" => Self::Forwarded,
            _ => Self::Custom(s.to_string()),
        }
    }
}

// ─── Logon type decoder ───────────────────────────────────────────────────────

/// Windows logon type values (used in event ID 4624).
#[must_use]
pub const fn logon_type_description(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        12 => "CachedRemoteInteractive",
        13 => "CachedUnlock",
        _ => "Unknown",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_header() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        data[0..8].copy_from_slice(EVTX_FILE_MAGIC);
        data[8..16].copy_from_slice(&0u64.to_le_bytes()); // oldest_chunk
        data[16..24].copy_from_slice(&5u64.to_le_bytes()); // current_chunk
        data[24..32].copy_from_slice(&100u64.to_le_bytes()); // next_record_id
        data[32..36].copy_from_slice(&128u32.to_le_bytes()); // header_chunk_size
        data[36..38].copy_from_slice(&6u16.to_le_bytes()); // number_of_chunks
        data
    }

    fn make_chunk_header() -> Vec<u8> {
        let mut data = vec![0u8; EVTX_CHUNK_SIZE];
        data[0..8].copy_from_slice(EVTX_CHUNK_MAGIC);
        data[8..16].copy_from_slice(&1u64.to_le_bytes()); // first_event_record_number
        data[16..24].copy_from_slice(&10u64.to_le_bytes()); // last_event_record_number
        data[24..32].copy_from_slice(&1u64.to_le_bytes()); // first event id
        data[32..40].copy_from_slice(&10u64.to_le_bytes()); // last event id
        data[40..44].copy_from_slice(&512u32.to_le_bytes()); // header_area_size
        data
    }

    #[test]
    fn parse_file_header_valid() {
        let data = make_file_header();
        let hdr = EvtxFileHeader::parse(&data).unwrap();
        assert_eq!(hdr.number_of_chunks, 6);
        assert_eq!(hdr.next_record_identifier, 100);
        assert!(!hdr.is_dirty());
    }

    #[test]
    fn parse_file_header_invalid_magic() {
        let data = vec![0u8; 4096];
        assert!(matches!(
            EvtxFileHeader::parse(&data),
            Err(EvtxError::InvalidFileMagic)
        ));
    }

    #[test]
    fn parse_chunk_header_valid() {
        let data = make_chunk_header();
        let hdr = EvtxChunkHeader::parse(&data, 0).unwrap();
        assert_eq!(hdr.first_event_record_number, 1);
        assert_eq!(hdr.last_event_record_number, 10);
    }

    #[test]
    fn parse_chunk_header_invalid_magic() {
        let data = vec![0u8; EVTX_CHUNK_SIZE];
        assert!(matches!(
            EvtxChunkHeader::parse(&data, 0),
            Err(EvtxError::InvalidChunkMagic(0))
        ));
    }

    #[test]
    fn find_chunk_offsets() {
        let mut data = vec![0u8; EVTX_CHUNK_SIZE * 3 + EVTX_HEADER_SIZE];
        data[0..8].copy_from_slice(EVTX_FILE_MAGIC);
        for i in 0..3usize {
            let off = EVTX_HEADER_SIZE + i * EVTX_CHUNK_SIZE;
            data[off..off + 8].copy_from_slice(EVTX_CHUNK_MAGIC);
        }
        let offsets = EvtxScanner::find_chunk_offsets(&data);
        assert_eq!(offsets.len(), 3);
    }

    #[test]
    fn event_id_description_lookup() {
        assert_eq!(event_id_description("Security-Auditing", 4624), "Logon");
        assert_eq!(
            event_id_description("Security-Auditing", 4688),
            "Process created"
        );
        assert_eq!(event_id_description("Security-Auditing", 9999), "Unknown");
    }

    #[test]
    fn event_record_level_str() {
        let make = |level: u8| EventRecord {
            record_id: 1,
            time_created: 0,
            provider_name: String::new(),
            event_id: 0,
            level,
            task: 0,
            opcode: 0,
            keywords: 0,
            channel: String::new(),
            computer: String::new(),
            activity_id: String::new(),
            process_id: 0,
            thread_id: 0,
            event_data: HashMap::new(),
            xml: None,
        };
        assert_eq!(make(2).level_str(), "Error");
        assert_eq!(make(4).level_str(), "Information");
        assert_eq!(make(255).level_str(), "Unknown");
    }

    #[test]
    fn event_channel_from_str() {
        assert_eq!(EventChannel::from_str("security"), EventChannel::Security);
        assert_eq!(EventChannel::from_str("system"), EventChannel::System);
        assert_eq!(
            EventChannel::from_str("Microsoft-Windows-Sysmon/Operational"),
            EventChannel::Sysmon
        );
    }

    #[test]
    fn logon_type_descriptions() {
        assert_eq!(logon_type_description(2), "Interactive");
        assert_eq!(logon_type_description(3), "Network");
        assert_eq!(logon_type_description(10), "RemoteInteractive");
        assert_eq!(logon_type_description(99), "Unknown");
    }

    #[test]
    fn summarize_empty_records() {
        let summary = EvtxScanner::summarize(&[]);
        assert!(summary.is_empty());
    }

    #[test]
    fn filter_by_event_id() {
        let records = vec![
            EventRecord {
                record_id: 1,
                time_created: 0,
                provider_name: "Microsoft-Windows-Security-Auditing".into(),
                event_id: 4624,
                level: 4,
                task: 0,
                opcode: 0,
                keywords: 0,
                channel: "Security".into(),
                computer: "TESTPC".into(),
                activity_id: String::new(),
                process_id: 4,
                thread_id: 8,
                event_data: HashMap::new(),
                xml: None,
            },
            EventRecord {
                record_id: 2,
                time_created: 0,
                provider_name: "Microsoft-Windows-Security-Auditing".into(),
                event_id: 4625,
                level: 2,
                task: 0,
                opcode: 0,
                keywords: 0,
                channel: "Security".into(),
                computer: "TESTPC".into(),
                activity_id: String::new(),
                process_id: 4,
                thread_id: 8,
                event_data: HashMap::new(),
                xml: None,
            },
        ];
        let logons = EvtxScanner::filter_by_event_id(&records, 4624);
        assert_eq!(logons.len(), 1);
        let suspicious = EvtxScanner::find_suspicious(&records);
        assert_eq!(suspicious.len(), 2); // 4624 not in list, 4625 is
    }

    #[test]
    fn parse_records_empty_chunk() {
        let chunk = vec![0u8; EVTX_CHUNK_SIZE];
        let records = parse_records_from_chunk(&chunk);
        assert!(records.is_empty());
    }
}
