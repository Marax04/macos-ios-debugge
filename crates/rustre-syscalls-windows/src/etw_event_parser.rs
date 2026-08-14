//! Parse ETW (Event Tracing for Windows) event records from raw byte blobs.
//!
//! **Layer**: binary deserialization of flat `EVENT_RECORD` buffers.
//!
//! Provides [`EtwEventParser`] which accepts raw `EVENT_RECORD`-compatible byte
//! blobs and returns structured [`EtwEvent`] values.  No OS calls are made;
//! everything works on in-memory buffers so the module is equally usable in
//!
//! Relationship to [`crate::windows_events`]: that module handles the *session
//! and consumer* model (provider registration, event filtering, session
//! management) whereas this module only performs *binary parsing* of individual
//! event records already in memory.  Use both together: `windows_events` to
//! manage what to capture, this module to decode each captured buffer.
//!
//! offline analysis and in live kernel callbacks.
//!
//! # Layout assumed
//! ```text
//! EVENT_RECORD {
//!   EventHeader   (0x00, 80 bytes)
//!   ExtendedData  (pointer, skipped in flat-buffer mode)
//!   UserData      (pointer, skipped in flat-buffer mode)
//!   UserDataLength (0x58, u16)
//!   … padding …
//!   [USER_DATA follows inline in our flat representation]
//! }
//! ```
//! Because real `EVENT_RECORD` structs contain pointers, we use an offset-based
//! *flat record* layout:
//! ```text
//! Offset  Size  Field
//! 0x00    2     Header size (must equal 0x50 = 80)
//! 0x02    2     Header type (must equal 0x04)
//! 0x04    4     Flags
//! 0x08    4     EventProperty
//! 0x0C    4     ThreadId
//! 0x10    4     ProcessId
//! 0x18    8     TimeStamp (LARGE_INTEGER / FILETIME)
//! 0x20    16    ProviderId (GUID)
//! 0x30    2     EventId
//! 0x32    1     Version
//! 0x33    1     Channel
//! 0x34    1     Level
//! 0x35    1     Opcode
//! 0x36    2     Task
//! 0x38    8     Keyword
//! 0x40    8     ProcessorTime
//! 0x48    8     ActivityId (low 8 bytes of GUID)
//! 0x50    2     UserDataLength
//! 0x52    2     _pad
//! 0x54    [UserData bytes …]
//! ```

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the ETW parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtwParseError {
    /// The buffer is too short.
    BufferTooShort { needed: usize, got: usize },
    /// The header size field does not match 0x50.
    BadHeaderSize(u16),
    /// The header type field does not match 0x04.
    BadHeaderType(u16),
    /// A named field was not found in the user-data schema.
    FieldNotFound(String),
}

impl fmt::Display for EtwParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, got } =>
                write!(f, "buffer too short: need {needed} bytes, got {got}"),
            Self::BadHeaderSize(s) => write!(f, "bad EVENT_HEADER.Size: {s:#x}"),
            Self::BadHeaderType(t) => write!(f, "bad EVENT_HEADER.HeaderType: {t:#x}"),
            Self::FieldNotFound(n) => write!(f, "field not found: {n}"),
        }
    }
}

impl std::error::Error for EtwParseError {}

// ── GUID ──────────────────────────────────────────────────────────────────────

/// A 128-bit GUID stored in the Microsoft mixed-endian layout.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    #[must_use]
    pub const fn zero() -> Self {
        Self { data1: 0, data2: 0, data3: 0, data4: [0u8; 8] }
    }

    /// Parse from 16 raw bytes in the mixed-endian wire format.
    #[must_use]
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let data2 = u16::from_le_bytes([b[4], b[5]]);
        let data3 = u16::from_le_bytes([b[6], b[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&b[8..16]);
        Self { data1, data2, data3, data4 }
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4],
            self.data4[5], self.data4[6], self.data4[7],
        )
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ── EventHeader ───────────────────────────────────────────────────────────────

/// The parsed `EVENT_HEADER` portion of an ETW record.
#[derive(Debug, Clone)]
pub struct EventHeader {
    pub flags: u32,
    pub event_property: u32,
    pub thread_id: u32,
    pub process_id: u32,
    /// FILETIME-style timestamp (100-ns intervals since 1601-01-01).
    pub timestamp: u64,
    /// Provider GUID.
    pub provider_id: Guid,
    pub event_id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
    pub processor_time: u64,
    /// Low 8 bytes of the activity-id GUID.
    pub activity_id_lo: u64,
}

impl EventHeader {
    const HEADER_BYTES: usize = 0x50;

    fn parse(buf: &[u8]) -> Result<Self, EtwParseError> {
        if buf.len() < Self::HEADER_BYTES {
            return Err(EtwParseError::BufferTooShort {
                needed: Self::HEADER_BYTES,
                got: buf.len(),
            });
        }
        let size = u16::from_le_bytes([buf[0], buf[1]]);
        if size != 0x50 {
            return Err(EtwParseError::BadHeaderSize(size));
        }
        let header_type = u16::from_le_bytes([buf[2], buf[3]]);
        if header_type != 0x04 {
            return Err(EtwParseError::BadHeaderType(header_type));
        }
        let flags = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let event_property = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let thread_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let process_id = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        // 4 bytes padding at 0x14
        let timestamp = u64::from_le_bytes([
            buf[0x18], buf[0x19], buf[0x1A], buf[0x1B],
            buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F],
        ]);
        let guid_bytes: [u8; 16] = buf[0x20..0x30].try_into().unwrap();
        let provider_id = Guid::from_bytes(&guid_bytes);
        let event_id = u16::from_le_bytes([buf[0x30], buf[0x31]]);
        let version = buf[0x32];
        let channel = buf[0x33];
        let level = buf[0x34];
        let opcode = buf[0x35];
        let task = u16::from_le_bytes([buf[0x36], buf[0x37]]);
        let keyword = u64::from_le_bytes([
            buf[0x38], buf[0x39], buf[0x3A], buf[0x3B],
            buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F],
        ]);
        let processor_time = u64::from_le_bytes([
            buf[0x40], buf[0x41], buf[0x42], buf[0x43],
            buf[0x44], buf[0x45], buf[0x46], buf[0x47],
        ]);
        let activity_id_lo = u64::from_le_bytes([
            buf[0x48], buf[0x49], buf[0x4A], buf[0x4B],
            buf[0x4C], buf[0x4D], buf[0x4E], buf[0x4F],
        ]);
        Ok(Self {
            flags,
            event_property,
            thread_id,
            process_id,
            timestamp,
            provider_id,
            event_id,
            version,
            channel,
            level,
            opcode,
            task,
            keyword,
            processor_time,
            activity_id_lo,
        })
    }
}

// ── EtwLevel / EtwOpcode ──────────────────────────────────────────────────────

/// ETW event severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwLevel {
    Always,
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
    Unknown(u8),
}

impl From<u8> for EtwLevel {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Always,
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            4 => Self::Information,
            5 => Self::Verbose,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for EtwLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Always => "always",
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
            Self::Verbose => "verbose",
            Self::Unknown(v) => return write!(f, "unknown({v})"),
        };
        write!(f, "{s}")
    }
}

/// Well-known ETW opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwOpcode {
    Info,
    Start,
    Stop,
    DataCollectionStart,
    DataCollectionStop,
    Extension,
    Reply,
    Resume,
    Suspend,
    Send,
    Receive,
    Unknown(u8),
}

impl From<u8> for EtwOpcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Info,
            1 => Self::Start,
            2 => Self::Stop,
            3 => Self::DataCollectionStart,
            4 => Self::DataCollectionStop,
            5 => Self::Extension,
            6 => Self::Reply,
            7 => Self::Resume,
            8 => Self::Suspend,
            9 => Self::Send,
            240 => Self::Receive,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for EtwOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::DataCollectionStart => "dc_start",
            Self::DataCollectionStop => "dc_stop",
            Self::Extension => "extension",
            Self::Reply => "reply",
            Self::Resume => "resume",
            Self::Suspend => "suspend",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Unknown(v) => return write!(f, "opcode({v})"),
        };
        write!(f, "{s}")
    }
}

// ── Parsed field value ─────────────────────────────────────────────────────────

/// A decoded field from ETW user-data.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bool(bool),
    Guid(Guid),
    Bytes(Vec<u8>),
    String(String),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}"),
            Self::F32(v) => write!(f, "{v}"),
            Self::F64(v) => write!(f, "{v}"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Guid(g) => write!(f, "{g}"),
            Self::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Self::String(s) => write!(f, "{s}"),
        }
    }
}

// ── Field descriptor ──────────────────────────────────────────────────────────

/// Describes one field in a user-data schema.
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub name: String,
    pub kind: FieldKind,
}

/// The wire type of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    F32,
    F64,
    Bool8,
    Bool32,
    Guid,
    /// Fixed-length byte blob.
    Bytes(usize),
    /// Null-terminated UTF-8 string.
    CString,
    /// Length-prefixed UTF-16LE string (u16 length in chars).
    WString,
}

impl FieldKind {
    /// Fixed wire size in bytes, or `None` for variable-length fields.
    #[must_use]
    pub const fn wire_size(self) -> Option<usize> {
        match self {
            Self::U8 | Self::Bool8 => Some(1),
            Self::U16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 | Self::Bool32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::Guid => Some(16),
            Self::Bytes(n) => Some(n),
            Self::CString | Self::WString => None, // variable
        }
    }
}

// ── EventSchema ───────────────────────────────────────────────────────────────

/// Describes the layout of a specific event's user-data.
#[derive(Debug, Clone)]
pub struct EventSchema {
    pub provider_id: Guid,
    pub event_id: u16,
    pub version: u8,
    pub name: String,
    pub fields: Vec<FieldDescriptor>,
}

impl EventSchema {
    pub fn new(
        provider_id: Guid,
        event_id: u16,
        version: u8,
        name: impl Into<String>,
        fields: Vec<FieldDescriptor>,
    ) -> Self {
        Self { provider_id, event_id, version, name: name.into(), fields }
    }
}

// ── EtwEvent ──────────────────────────────────────────────────────────────────

/// A fully parsed ETW event.
#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub header: EventHeader,
    pub level: EtwLevel,
    pub opcode: EtwOpcode,
    /// Schema name if a schema was matched.
    pub schema_name: Option<String>,
    /// Decoded user-data fields (empty if no schema was matched).
    pub fields: HashMap<String, FieldValue>,
    /// Raw user-data bytes (always present).
    pub user_data: Vec<u8>,
}

impl EtwEvent {
    /// Return the process ID.
    #[must_use]
    pub const fn pid(&self) -> u32 { self.header.process_id }

    /// Return the thread ID.
    #[must_use]
    pub const fn tid(&self) -> u32 { self.header.thread_id }

    /// Return the FILETIME timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u64 { self.header.timestamp }

    /// Return a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&FieldValue> {
        self.fields.get(name)
    }

    /// Return `true` if an error-level event.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.level, EtwLevel::Critical | EtwLevel::Error)
    }
}

// ── EtwEventParser ────────────────────────────────────────────────────────────

/// Parses raw flat ETW records into [`EtwEvent`] values.
///
/// Register schemas with [`EtwEventParser::register_schema`] before parsing; events that match
/// a registered schema will have their `fields` populated.
pub struct EtwEventParser {
    schemas: Vec<EventSchema>,
    /// Number of records successfully parsed.
    parsed_count: u64,
    /// Number of records that failed to parse.
    error_count: u64,
}

impl EtwEventParser {
    /// Create an empty parser.
    #[must_use]
    pub const fn new() -> Self {
        Self { schemas: Vec::new(), parsed_count: 0, error_count: 0 }
    }

    /// Register a user-data schema for a specific (`provider_id`, `event_id`, `version`) tuple.
    pub fn register_schema(&mut self, schema: EventSchema) {
        self.schemas.push(schema);
    }

    /// Return the total number of successfully parsed records.
    #[must_use]
    pub const fn parsed_count(&self) -> u64 { self.parsed_count }

    /// Return the total number of failed-parse records.
    #[must_use]
    pub const fn error_count(&self) -> u64 { self.error_count }

    /// Parse a single flat ETW record from `buf`.
    ///
    /// The buffer must start at the beginning of the flat record described in
    /// the module-level documentation.
    ///
    /// # Errors
    /// Returns [`EtwParseError`] on malformed input.
    pub fn parse_etw_record(&mut self, buf: &[u8]) -> Result<EtwEvent, EtwParseError> {
        // Minimum length: header (0x50) + user_data_length field (2) + pad (2)
        const MIN_LEN: usize = 0x54;
        if buf.len() < MIN_LEN {
            self.error_count += 1;
            return Err(EtwParseError::BufferTooShort { needed: MIN_LEN, got: buf.len() });
        }

        let header = EventHeader::parse(buf).inspect_err(|_| { self.error_count += 1; })?;

        let ud_len = u16::from_le_bytes([buf[0x50], buf[0x51]]) as usize;
        let total = 0x54 + ud_len;
        if buf.len() < total {
            self.error_count += 1;
            return Err(EtwParseError::BufferTooShort { needed: total, got: buf.len() });
        }
        let user_data = buf[0x54..0x54 + ud_len].to_vec();

        let level = EtwLevel::from(header.level);
        let opcode = EtwOpcode::from(header.opcode);

        let (schema_name, fields) = self.decode_fields(&header, &user_data);

        self.parsed_count += 1;
        Ok(EtwEvent { header, level, opcode, schema_name, fields, user_data })
    }

    /// Parse multiple concatenated flat records from `buf`.
    /// Each record is self-delimiting: header size (`0x50`) + `user_data_length`.
    pub fn parse_batch(&mut self, buf: &[u8]) -> Vec<Result<EtwEvent, EtwParseError>> {
        let mut results = Vec::new();
        let mut offset = 0;
        while offset < buf.len() {
            let remaining = &buf[offset..];
            // We need at least 0x54 bytes to determine the user-data length.
            if remaining.len() < 0x54 {
                results.push(Err(EtwParseError::BufferTooShort {
                    needed: 0x54,
                    got: remaining.len(),
                }));
                break;
            }
            let ud_len = u16::from_le_bytes([remaining[0x50], remaining[0x51]]) as usize;
            let record_size = 0x54 + ud_len;
            if remaining.len() < record_size {
                results.push(Err(EtwParseError::BufferTooShort {
                    needed: record_size,
                    got: remaining.len(),
                }));
                break;
            }
            results.push(self.parse_etw_record(&remaining[..record_size]));
            offset += record_size;
        }
        results
    }

    /// Decode user-data fields according to a registered schema.
    fn decode_fields(
        &self,
        header: &EventHeader,
        user_data: &[u8],
    ) -> (Option<String>, HashMap<String, FieldValue>) {
        let schema = self.schemas.iter().find(|s| {
            s.provider_id == header.provider_id
                && s.event_id == header.event_id
                && s.version == header.version
        });
        let Some(schema) = schema else { return (None, HashMap::new()); };

        let mut fields = HashMap::with_capacity(schema.fields.len());
        let mut cursor = 0usize;

        for desc in &schema.fields {
            if cursor >= user_data.len() {
                break;
            }
            match decode_field(desc.kind, user_data, cursor) {
                Some((value, consumed)) => {
                    cursor += consumed;
                    fields.insert(desc.name.clone(), value);
                }
                None => break,
            }
        }

        (Some(schema.name.clone()), fields)
    }
}

impl Default for EtwEventParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EtwEventParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EtwEventParser {{ schemas: {}, parsed: {}, errors: {} }}",
            self.schemas.len(), self.parsed_count, self.error_count
        )
    }
}

// ── Field decoder ─────────────────────────────────────────────────────────────

fn decode_field(kind: FieldKind, data: &[u8], offset: usize) -> Option<(FieldValue, usize)> {
    let remaining = data.get(offset..)?;
    match kind {
        FieldKind::U8 | FieldKind::Bool8 => {
            let v = *remaining.first()?;
            let value = if kind == FieldKind::Bool8 {
                FieldValue::Bool(v != 0)
            } else {
                FieldValue::U8(v)
            };
            Some((value, 1))
        }
        FieldKind::U16 => {
            if remaining.len() < 2 { return None; }
            Some((FieldValue::U16(u16::from_le_bytes([remaining[0], remaining[1]])), 2))
        }
        FieldKind::U32 | FieldKind::Bool32 => {
            if remaining.len() < 4 { return None; }
            let v = u32::from_le_bytes(remaining[..4].try_into().ok()?);
            let value = if kind == FieldKind::Bool32 {
                FieldValue::Bool(v != 0)
            } else {
                FieldValue::U32(v)
            };
            Some((value, 4))
        }
        FieldKind::I32 => {
            if remaining.len() < 4 { return None; }
            let v = i32::from_le_bytes(remaining[..4].try_into().ok()?);
            Some((FieldValue::I32(v), 4))
        }
        FieldKind::F32 => {
            if remaining.len() < 4 { return None; }
            let v = f32::from_le_bytes(remaining[..4].try_into().ok()?);
            Some((FieldValue::F32(v), 4))
        }
        FieldKind::U64 => {
            if remaining.len() < 8 { return None; }
            let v = u64::from_le_bytes(remaining[..8].try_into().ok()?);
            Some((FieldValue::U64(v), 8))
        }
        FieldKind::I64 => {
            if remaining.len() < 8 { return None; }
            let v = i64::from_le_bytes(remaining[..8].try_into().ok()?);
            Some((FieldValue::I64(v), 8))
        }
        FieldKind::F64 => {
            if remaining.len() < 8 { return None; }
            let v = f64::from_le_bytes(remaining[..8].try_into().ok()?);
            Some((FieldValue::F64(v), 8))
        }
        FieldKind::Guid => {
            if remaining.len() < 16 { return None; }
            let arr: [u8; 16] = remaining[..16].try_into().ok()?;
            Some((FieldValue::Guid(Guid::from_bytes(&arr)), 16))
        }
        FieldKind::Bytes(n) => {
            if remaining.len() < n { return None; }
            Some((FieldValue::Bytes(remaining[..n].to_vec()), n))
        }
        FieldKind::CString => {
            let null_pos = remaining.iter().position(|&b| b == 0)?;
            let s = String::from_utf8_lossy(&remaining[..null_pos]).into_owned();
            Some((FieldValue::String(s), null_pos + 1))
        }
        FieldKind::WString => {
            // u16 length prefix (number of UTF-16 code units)
            if remaining.len() < 2 { return None; }
            let char_count = u16::from_le_bytes([remaining[0], remaining[1]]) as usize;
            let byte_count = char_count * 2;
            if remaining.len() < 2 + byte_count { return None; }
            let units: Vec<u16> = remaining[2..2 + byte_count]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&units);
            Some((FieldValue::String(s), 2 + byte_count))
        }
    }
}

// ── Well-known provider helpers ───────────────────────────────────────────────

/// GUID for the NT Kernel Logger provider.
#[must_use]
pub fn nt_kernel_logger_guid() -> Guid {
    Guid::from_bytes(&[
        0x9e, 0x61, 0x46, 0x68, 0xdf, 0x79, 0x58, 0x54,
        0x2b, 0x24, 0x83, 0x4e, 0xba, 0x03, 0xd5, 0xad,
    ])
}

/// GUID for the Microsoft-Windows-Security-Auditing provider.
#[must_use]
pub fn security_auditing_guid() -> Guid {
    Guid::from_bytes(&[
        0x54, 0x84, 0x9e, 0x54, 0xf6, 0x4e, 0x11, 0xd9,
        0x85, 0xbd, 0x00, 0x0c, 0x29, 0x57, 0x06, 0x51,
    ])
}

// ── Flat record builder (for tests / offline analysis) ───────────────────────

/// Parameters for [`build_flat_record`], bundled to keep argument count in check.
pub struct FlatRecordParams {
    /// ETW provider GUID.
    pub provider_id: Guid,
    /// Event descriptor ID.
    pub event_id: u16,
    /// Event descriptor version.
    pub version: u8,
    /// Event descriptor level.
    pub level: u8,
    /// Event descriptor opcode.
    pub opcode: u8,
    /// Process ID that emitted the event.
    pub process_id: u32,
    /// Thread ID that emitted the event.
    pub thread_id: u32,
    /// Windows FILETIME timestamp (100-ns ticks since 1601-01-01).
    pub timestamp: u64,
}

/// Build a minimal valid flat ETW record buffer.
///
/// # Panics
/// Panics if `user_data.len()` exceeds 65535 bytes (the maximum ETW user-data length).
#[must_use]
pub fn build_flat_record(params: &FlatRecordParams, user_data: &[u8]) -> Vec<u8> {
    let FlatRecordParams { provider_id, event_id, version, level, opcode, process_id, thread_id, timestamp } = *params;
    let ud_len: u16 = u16::try_from(user_data.len())
        .expect("user_data too long for ETW flat record (max 65535 bytes)");
    let mut buf = vec![0u8; 0x54 + user_data.len()];

    // Header size
    buf[0] = 0x50;
    buf[1] = 0x00;
    // Header type
    buf[2] = 0x04;
    buf[3] = 0x00;
    // ThreadId
    buf[12..16].copy_from_slice(&thread_id.to_le_bytes());
    // ProcessId
    buf[16..20].copy_from_slice(&process_id.to_le_bytes());
    // TimeStamp
    buf[0x18..0x20].copy_from_slice(&timestamp.to_le_bytes());
    // ProviderId (mixed-endian back to bytes: data1 LE, data2 LE, data3 LE, data4 raw)
    buf[0x20..0x24].copy_from_slice(&provider_id.data1.to_le_bytes());
    buf[0x24..0x26].copy_from_slice(&provider_id.data2.to_le_bytes());
    buf[0x26..0x28].copy_from_slice(&provider_id.data3.to_le_bytes());
    buf[0x28..0x30].copy_from_slice(&provider_id.data4);
    // EventId / Version / Level / Opcode
    buf[0x30..0x32].copy_from_slice(&event_id.to_le_bytes());
    buf[0x32] = version;
    buf[0x34] = level;
    buf[0x35] = opcode;
    // UserDataLength
    buf[0x50..0x52].copy_from_slice(&ud_len.to_le_bytes());
    // UserData
    buf[0x54..].copy_from_slice(user_data);
    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn trivial_guid() -> Guid {
        Guid { data1: 0x1122_3344, data2: 0x5566, data3: 0x7788, data4: [1,2,3,4,5,6,7,8] }
    }

    fn basic_record(ud: &[u8]) -> Vec<u8> {
        build_flat_record(&FlatRecordParams {
            provider_id: trivial_guid(),
            event_id: 100,
            version: 1,
            level: 4,
            opcode: 0,
            process_id: 1234,
            thread_id: 5678,
            timestamp: 0xABCD_EF01,
        }, ud)
    }

    #[test]
    fn test_parse_minimal() {
        let mut parser = EtwEventParser::new();
        let buf = basic_record(&[]);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.pid(), 1234);
        assert_eq!(ev.tid(), 5678);
        assert_eq!(ev.timestamp(), 0xABCD_EF01);
        assert_eq!(ev.header.event_id, 100);
        assert_eq!(ev.header.version, 1);
        assert!(ev.user_data.is_empty());
    }

    #[test]
    fn test_parse_level_info() {
        let mut parser = EtwEventParser::new();
        let buf = basic_record(&[]);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.level, EtwLevel::Information);
    }

    #[test]
    fn test_parse_opcode_info() {
        let mut parser = EtwEventParser::new();
        let buf = basic_record(&[]);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.opcode, EtwOpcode::Info);
    }

    #[test]
    fn test_buffer_too_short() {
        let mut parser = EtwEventParser::new();
        let err = parser.parse_etw_record(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, EtwParseError::BufferTooShort { .. }));
    }

    #[test]
    fn test_bad_header_size() {
        let mut buf = basic_record(&[]);
        buf[0] = 0x10; // wrong size
        let mut parser = EtwEventParser::new();
        let err = parser.parse_etw_record(&buf).unwrap_err();
        assert!(matches!(err, EtwParseError::BadHeaderSize(_)));
    }

    #[test]
    fn test_bad_header_type() {
        let mut buf = basic_record(&[]);
        buf[2] = 0x01; // wrong type
        let mut parser = EtwEventParser::new();
        let err = parser.parse_etw_record(&buf).unwrap_err();
        assert!(matches!(err, EtwParseError::BadHeaderType(_)));
    }

    #[test]
    fn test_schema_field_u32() {
        let mut parser = EtwEventParser::new();
        let schema = EventSchema::new(
            trivial_guid(), 100, 1, "TestEvent",
            vec![FieldDescriptor { name: "Status".into(), kind: FieldKind::U32 }],
        );
        parser.register_schema(schema);

        let ud: Vec<u8> = 0x0000_C0DEu32.to_le_bytes().to_vec();
        let buf = basic_record(&ud);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.schema_name.as_deref(), Some("TestEvent"));
        assert_eq!(ev.field("Status"), Some(&FieldValue::U32(0x0000_C0DE)));
    }

    #[test]
    fn test_schema_field_cstring() {
        let mut parser = EtwEventParser::new();
        let schema = EventSchema::new(
            trivial_guid(), 100, 1, "StrEvent",
            vec![FieldDescriptor { name: "Path".into(), kind: FieldKind::CString }],
        );
        parser.register_schema(schema);

        let mut ud = b"C:\\Windows\\system32".to_vec();
        ud.push(0); // null terminator
        let buf = basic_record(&ud);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.field("Path"), Some(&FieldValue::String("C:\\Windows\\system32".into())));
    }

    #[test]
    fn test_schema_multiple_fields() {
        let mut parser = EtwEventParser::new();
        let schema = EventSchema::new(
            trivial_guid(), 100, 1, "MultiEvent",
            vec![
                FieldDescriptor { name: "Pid".into(), kind: FieldKind::U32 },
                FieldDescriptor { name: "Handle".into(), kind: FieldKind::U64 },
            ],
        );
        parser.register_schema(schema);

        let mut ud = Vec::new();
        ud.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        ud.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let buf = basic_record(&ud);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.field("Pid"), Some(&FieldValue::U32(0xDEAD_BEEF)));
        assert_eq!(ev.field("Handle"), Some(&FieldValue::U64(0x1122_3344_5566_7788)));
    }

    #[test]
    fn test_no_schema_match() {
        let mut parser = EtwEventParser::new();
        let buf = basic_record(&[1, 2, 3]);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert!(ev.schema_name.is_none());
        assert!(ev.fields.is_empty());
    }

    #[test]
    fn test_parsed_count() {
        let mut parser = EtwEventParser::new();
        let buf = basic_record(&[]);
        parser.parse_etw_record(&buf).unwrap();
        parser.parse_etw_record(&buf).unwrap();
        assert_eq!(parser.parsed_count(), 2);
    }

    #[test]
    fn test_error_count() {
        let mut parser = EtwEventParser::new();
        let _ = parser.parse_etw_record(&[0u8; 5]);
        assert_eq!(parser.error_count(), 1);
    }

    #[test]
    fn test_batch_parse() {
        let mut parser = EtwEventParser::new();
        let rec = basic_record(&[0xAA, 0xBB]);
        let mut batch = rec.clone();
        batch.extend_from_slice(&rec);
        let results = parser.parse_batch(&batch);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
    }

    #[test]
    fn test_bool_field() {
        let mut parser = EtwEventParser::new();
        let schema = EventSchema::new(
            trivial_guid(), 100, 1, "BoolEvent",
            vec![FieldDescriptor { name: "Active".into(), kind: FieldKind::Bool8 }],
        );
        parser.register_schema(schema);
        let buf = basic_record(&[1]);
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert_eq!(ev.field("Active"), Some(&FieldValue::Bool(true)));
    }

    #[test]
    fn test_is_error_level() {
        let mut parser = EtwEventParser::new();
        let buf = build_flat_record(&FlatRecordParams {
            provider_id: trivial_guid(), event_id: 1, version: 1,
            level: 2, opcode: 0, process_id: 0, thread_id: 0, timestamp: 0,
        }, &[]); // level=Error
        let ev = parser.parse_etw_record(&buf).unwrap();
        assert!(ev.is_error());
    }

    #[test]
    fn test_guid_display() {
        let g = trivial_guid();
        let s = g.to_string();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert!(s.contains("11223344"));
    }

    #[test]
    fn test_etw_level_display() {
        assert_eq!(EtwLevel::Error.to_string(), "error");
        assert_eq!(EtwLevel::Unknown(99).to_string(), "unknown(99)");
    }

    #[test]
    fn test_etw_opcode_display() {
        assert_eq!(EtwOpcode::Start.to_string(), "start");
    }

    #[test]
    fn test_nt_kernel_logger_guid_roundtrip() {
        let g = nt_kernel_logger_guid();
        assert_ne!(g, Guid::zero());
    }
}
