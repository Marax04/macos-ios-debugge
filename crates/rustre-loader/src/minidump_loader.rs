/// `minidump_loader.rs` — Load and parse Windows Minidump (.dmp) files.
///
/// Implements parsing of the `MINIDUMP_HEADER`, `MINIDUMP_DIRECTORY`, and a
/// selection of stream types:
///   * `SystemInfo` (stream type 7)
///   * Exception (stream type 6)
///   * `ThreadList` (stream type 3)
///   * `ModuleList` (stream type 4)
///   * `MemoryList` (stream type 5)
///   * `Memory64List` (stream type 9)
///
/// Reference: <https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/>
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum MinidumpError {
    #[error("Buffer too small ({size} bytes)")]
    TooSmall { size: usize },
    #[error("Invalid minidump signature: expected MDMP, got {got:?}")]
    InvalidSignature { got: [u8; 4] },
    #[error("Unsupported minidump version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("Stream directory extends beyond file")]
    TruncatedDirectory,
    #[error("Stream type {stream_type} at offset {offset} size {size} is out of bounds")]
    StreamOutOfBounds {
        stream_type: u32,
        offset: u64,
        size: u64,
    },
    #[error("Stream type {stream_type} has malformed data: {detail}")]
    MalformedStream { stream_type: u32, detail: String },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MDMP_SIGNATURE: &[u8; 4] = b"MDMP";
const HEADER_SIZE: usize = 32;
const DIRECTORY_ENTRY_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// MINIDUMP_HEADER
// ---------------------------------------------------------------------------

/// Parsed `MINIDUMP_HEADER`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpHeader {
    /// Signature — should be "MDMP".
    pub signature: [u8; 4],
    /// Version of the minidump format.
    pub version: u32,
    /// Number of streams in the directory.
    pub number_of_streams: u32,
    /// File offset of the stream directory array.
    pub stream_directory_rva: u32,
    /// Checksum (0 if not used).
    pub check_sum: u32,
    /// Timestamp (seconds since 1970-01-01).
    pub time_date_stamp: u32,
    /// Flags describing the minidump contents.
    pub flags: u64,
}

impl MinidumpHeader {
    fn parse(data: &[u8]) -> Result<Self, MinidumpError> {
        // Check signature first so callers passing short non-minidump buffers
        // (e.g. `b"NOTMDMP"`) get the more informative `InvalidSignature` error
        // rather than a generic `TooSmall`.
        if data.len() >= 4 {
            let sig = [data[0], data[1], data[2], data[3]];
            if &sig != MDMP_SIGNATURE {
                return Err(MinidumpError::InvalidSignature { got: sig });
            }
        }
        if data.len() < HEADER_SIZE {
            return Err(MinidumpError::TooSmall { size: data.len() });
        }
        let sig = [data[0], data[1], data[2], data[3]];
        Ok(Self {
            signature: sig,
            version: read_u32(data, 4),
            number_of_streams: read_u32(data, 8),
            stream_directory_rva: read_u32(data, 12),
            check_sum: read_u32(data, 16),
            time_date_stamp: read_u32(data, 20),
            flags: read_u64(data, 24),
        })
    }
}

// ---------------------------------------------------------------------------
// MINIDUMP_DIRECTORY entry
// ---------------------------------------------------------------------------

/// A single entry in the `MINIDUMP_DIRECTORY` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpDirectoryEntry {
    /// Stream type identifier.
    pub stream_type: u32,
    /// Human-readable name of the stream type.
    pub stream_type_name: String,
    /// Size of the stream data in bytes.
    pub data_size: u32,
    /// File offset (RVA from start of file) of the stream data.
    pub rva: u32,
}

impl MinidumpDirectoryEntry {
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + DIRECTORY_ENTRY_SIZE > data.len() {
            return None;
        }
        let stream_type = read_u32(data, offset);
        let data_size = read_u32(data, offset + 4);
        let rva = read_u32(data, offset + 8);
        Some(Self {
            stream_type_name: stream_type_name(stream_type).to_string(),
            stream_type,
            data_size,
            rva,
        })
    }
}

const fn stream_type_name(t: u32) -> &'static str {
    match t {
        0 => "UnusedStream",
        1 => "ReservedStream0",
        2 => "ReservedStream1",
        3 => "ThreadListStream",
        4 => "ModuleListStream",
        5 => "MemoryListStream",
        6 => "ExceptionStream",
        7 => "SystemInfoStream",
        8 => "ThreadExListStream",
        9 => "Memory64ListStream",
        10 => "CommentStreamA",
        11 => "CommentStreamW",
        12 => "HandleDataStream",
        13 => "FunctionTableStream",
        14 => "UnloadedModuleListStream",
        15 => "MiscInfoStream",
        16 => "MemoryInfoListStream",
        17 => "ThreadInfoListStream",
        18 => "HandleOperationListStream",
        19 => "TokenStream",
        0x8000 => "ceStreamNull",
        0xFFFF => "LastReservedStream",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Stream types
// ---------------------------------------------------------------------------

/// Known parsed stream variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinidumpStream {
    SystemInfo(SystemInfoStream),
    Exception(ExceptionStream),
    ThreadList(ThreadListStream),
    ModuleList(ModuleListStream),
    MemoryList(MemoryListStream),
    Memory64List(Memory64ListStream),
    Unknown { stream_type: u32, size: u32 },
}

// ---------------------------------------------------------------------------
// SystemInfoStream (type 7)
// ---------------------------------------------------------------------------

/// `MINIDUMP_SYSTEM_INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoStream {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version_rva: u32,
    pub suite_mask: u16,
    pub reserved2: u16,
}

impl SystemInfoStream {
    const SIZE: usize = 56;

    fn parse(data: &[u8], offset: usize, size: usize) -> Result<Self, MinidumpError> {
        if size < Self::SIZE || offset + Self::SIZE > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 7,
                detail: format!("expected {} bytes, got {}", Self::SIZE, size),
            });
        }
        Ok(Self {
            processor_architecture: read_u16(data, offset),
            processor_level: read_u16(data, offset + 2),
            processor_revision: read_u16(data, offset + 4),
            number_of_processors: data[offset + 6],
            product_type: data[offset + 7],
            major_version: read_u32(data, offset + 8),
            minor_version: read_u32(data, offset + 12),
            build_number: read_u32(data, offset + 16),
            platform_id: read_u32(data, offset + 20),
            csd_version_rva: read_u32(data, offset + 24),
            suite_mask: read_u16(data, offset + 28),
            reserved2: read_u16(data, offset + 30),
        })
    }

    /// Returns the Windows version string (e.g. "10.0.19041").
    #[must_use]
    pub fn windows_version(&self) -> String {
        format!(
            "{}.{}.{}",
            self.major_version, self.minor_version, self.build_number
        )
    }

    /// Returns the processor architecture name.
    #[must_use]
    pub const fn arch_name(&self) -> &'static str {
        match self.processor_architecture {
            0 => "x86",
            5 => "ARM",
            6 => "IA-64",
            9 => "AMD64",
            12 => "ARM64",
            _ => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// ExceptionStream (type 6)
// ---------------------------------------------------------------------------

/// `MINIDUMP_EXCEPTION_STREAM`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionStream {
    pub thread_id: u32,
    /// `MINIDUMP_EXCEPTION.ExceptionCode`
    pub exception_code: u32,
    /// `MINIDUMP_EXCEPTION.ExceptionFlags`
    pub exception_flags: u32,
    /// RVA of the CONTEXT record.
    pub thread_context_rva: u32,
    pub thread_context_size: u32,
    /// Exception address.
    pub exception_address: u64,
    /// Number of exception parameters.
    pub number_of_parameters: u32,
    /// Exception parameters (up to 15).
    pub exception_information: Vec<u64>,
}

impl ExceptionStream {
    fn parse(data: &[u8], offset: usize, _size: usize) -> Result<Self, MinidumpError> {
        if offset + 168 > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 6,
                detail: "truncated exception stream".to_string(),
            });
        }
        let thread_id = read_u32(data, offset);
        // +4: __alignment
        // MINIDUMP_EXCEPTION starts at offset+8
        let exc_base = offset + 8;
        let exception_code = read_u32(data, exc_base);
        let exception_flags = read_u32(data, exc_base + 4);
        let exception_address = read_u64(data, exc_base + 16);
        let number_of_parameters = read_u32(data, exc_base + 24).min(15);
        let mut exception_information = Vec::new();
        for i in 0..number_of_parameters as usize {
            exception_information.push(read_u64(data, exc_base + 28 + i * 8));
        }
        // ThreadContext RVA is at offset+160 (after MINIDUMP_EXCEPTION 152 bytes + thread_id 4 + pad 4)
        let ctx_rva = if offset + 168 <= data.len() {
            read_u32(data, offset + 160)
        } else {
            0
        };
        let ctx_size = if offset + 172 <= data.len() {
            read_u32(data, offset + 164)
        } else {
            0
        };
        Ok(Self {
            thread_id,
            exception_code,
            exception_flags,
            thread_context_rva: ctx_rva,
            thread_context_size: ctx_size,
            exception_address,
            number_of_parameters,
            exception_information,
        })
    }

    /// Translates the exception code to a human-readable name.
    #[must_use]
    pub const fn exception_name(&self) -> &'static str {
        match self.exception_code {
            0xC000_0005 => "ACCESS_VIOLATION",
            0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO",
            0xC000_008D => "FLOAT_DENORMAL_OPERAND",
            0xC000_008E => "FLOAT_DIVIDE_BY_ZERO",
            0xC000_008F => "FLOAT_INEXACT_RESULT",
            0xC000_0090 => "FLOAT_INVALID_OPERATION",
            0xC000_0091 => "FLOAT_OVERFLOW",
            0xC000_0092 => "FLOAT_STACK_CHECK",
            0xC000_0093 => "FLOAT_UNDERFLOW",
            0xC000_001D => "ILLEGAL_INSTRUCTION",
            0xC000_0096 => "PRIVILEGED_INSTRUCTION",
            0xC000_00FD => "STACK_OVERFLOW",
            0x8000_0003 => "BREAKPOINT",
            0x8000_0004 => "SINGLE_STEP",
            0xE06D_7363 => "CPP_EXCEPTION",
            0xC000_0409 => "STACK_BUFFER_OVERRUN",
            0xC000_0374 => "HEAP_CORRUPTION",
            _ => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// ThreadListStream (type 3)
// ---------------------------------------------------------------------------

/// One thread entry in `MINIDUMP_THREAD_LIST`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpThread {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    pub stack_start_of_memory_range: u64,
    pub stack_data_size: u32,
    pub stack_rva: u32,
    pub context_rva: u32,
    pub context_size: u32,
}

/// Parsed `MINIDUMP_THREAD_LIST` stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadListStream {
    pub threads: Vec<MinidumpThread>,
}

impl ThreadListStream {
    const THREAD_ENTRY_SIZE: usize = 48;

    fn parse(data: &[u8], offset: usize, _size: usize) -> Result<Self, MinidumpError> {
        if offset + 4 > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 3,
                detail: "cannot read thread count".to_string(),
            });
        }
        let count = read_u32(data, offset) as usize;
        // Cap allocation to avoid OOM on malformed input: a process can have at
        // most a few thousand threads in practice.
        let count = count.min(65536);
        let mut threads = Vec::with_capacity(count);
        for i in 0..count {
            let base = offset + 4 + i * Self::THREAD_ENTRY_SIZE;
            if base + Self::THREAD_ENTRY_SIZE > data.len() {
                break;
            }
            threads.push(MinidumpThread {
                thread_id: read_u32(data, base),
                suspend_count: read_u32(data, base + 4),
                priority_class: read_u32(data, base + 8),
                priority: read_u32(data, base + 12),
                teb: read_u64(data, base + 16),
                stack_start_of_memory_range: read_u64(data, base + 24),
                stack_data_size: read_u32(data, base + 32),
                stack_rva: read_u32(data, base + 36),
                context_rva: read_u32(data, base + 40),
                context_size: read_u32(data, base + 44),
            });
        }
        Ok(Self { threads })
    }
}

// ---------------------------------------------------------------------------
// ModuleListStream (type 4)
// ---------------------------------------------------------------------------

/// A loaded module entry in `MINIDUMP_MODULE_LIST`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub module_name_rva: u32,
    /// The module name decoded from the `MINIDUMP_STRING` at `module_name_rva`.
    pub name: String,
    pub version_info_signature: u32,
    pub file_version: u64,
    pub product_version: u64,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
}

/// Parsed `MINIDUMP_MODULE_LIST` stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleListStream {
    pub modules: Vec<MinidumpModule>,
}

impl ModuleListStream {
    const MODULE_SIZE: usize = 108;

    fn parse(data: &[u8], offset: usize, _size: usize) -> Result<Self, MinidumpError> {
        if offset + 4 > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 4,
                detail: "cannot read module count".to_string(),
            });
        }
        let count = read_u32(data, offset) as usize;
        // Cap allocation: no sane process loads millions of modules.
        let count = count.min(65536);
        let mut modules = Vec::with_capacity(count);
        for i in 0..count {
            let base = offset + 4 + i * Self::MODULE_SIZE;
            if base + Self::MODULE_SIZE > data.len() {
                break;
            }
            let name_rva = read_u32(data, base + 24);
            let name = read_minidump_string(data, name_rva as usize);
            modules.push(MinidumpModule {
                base_of_image: read_u64(data, base),
                size_of_image: read_u32(data, base + 8),
                checksum: read_u32(data, base + 12),
                time_date_stamp: read_u32(data, base + 16),
                module_name_rva: name_rva,
                name,
                version_info_signature: read_u32(data, base + 28),
                file_version: read_u64(data, base + 44),
                product_version: read_u64(data, base + 52),
                file_flags_mask: read_u32(data, base + 60),
                file_flags: read_u32(data, base + 64),
                file_os: read_u32(data, base + 68),
                file_type: read_u32(data, base + 72),
                file_subtype: read_u32(data, base + 76),
            });
        }
        Ok(Self { modules })
    }
}

/// Read a `MINIDUMP_STRING` (u32 length in bytes followed by UTF-16LE data).
fn read_minidump_string(data: &[u8], offset: usize) -> String {
    // Cap string byte-length to 64 KiB (32 768 UTF-16 code units).  The raw
    // length field is a u32 from untrusted input; without a cap a crafted
    // MINIDUMP_STRING length of u32::MAX causes the collect() below to attempt
    // a ~2 GiB Vec<u16> allocation, exhausting memory.
    const MAX_STRING_BYTES: usize = 65_536;
    if offset + 4 > data.len() {
        return String::new();
    }
    let byte_len = (read_u32(data, offset) as usize).min(MAX_STRING_BYTES);
    let str_start = offset + 4;
    if str_start + byte_len > data.len() {
        return String::new();
    }
    let utf16: Vec<u16> = data[str_start..str_start + byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&utf16)
}

// ---------------------------------------------------------------------------
// MemoryListStream (type 5)
// ---------------------------------------------------------------------------

/// A memory descriptor in `MINIDUMP_MEMORY_LIST`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDescriptor {
    pub start_of_memory_range: u64,
    pub data_size: u32,
    pub rva: u32,
}

/// Parsed `MINIDUMP_MEMORY_LIST` stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryListStream {
    pub descriptors: Vec<MemoryDescriptor>,
}

impl MemoryListStream {
    fn parse(data: &[u8], offset: usize, _size: usize) -> Result<Self, MinidumpError> {
        if offset + 4 > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 5,
                detail: "cannot read descriptor count".to_string(),
            });
        }
        let count = read_u32(data, offset) as usize;
        // Cap allocation to bound memory usage on malformed input.
        let count = count.min(1_000_000);
        let mut descriptors = Vec::with_capacity(count);
        for i in 0..count {
            let base = offset + 4 + i * 16;
            if base + 16 > data.len() {
                break;
            }
            descriptors.push(MemoryDescriptor {
                start_of_memory_range: read_u64(data, base),
                data_size: read_u32(data, base + 8),
                rva: read_u32(data, base + 12),
            });
        }
        Ok(Self { descriptors })
    }
}

// ---------------------------------------------------------------------------
// Memory64ListStream (type 9)
// ---------------------------------------------------------------------------

/// A 64-bit memory descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDescriptor64 {
    pub start_of_memory_range: u64,
    pub data_size: u64,
}

/// Parsed `MINIDUMP_MEMORY64_LIST` stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory64ListStream {
    pub base_rva: u64,
    pub descriptors: Vec<MemoryDescriptor64>,
}

impl Memory64ListStream {
    fn parse(data: &[u8], offset: usize, _size: usize) -> Result<Self, MinidumpError> {
        if offset + 16 > data.len() {
            return Err(MinidumpError::MalformedStream {
                stream_type: 9,
                detail: "too small for memory64 list header".to_string(),
            });
        }
        // read_u64 can produce a value far larger than available memory; cap it.
        let count = usize::try_from(read_u64(data, offset))
            .unwrap_or(1_000_000)
            .min(1_000_000);
        let base_rva = read_u64(data, offset + 8);
        let mut descriptors = Vec::with_capacity(count);
        for i in 0..count {
            let base = offset + 16 + i * 16;
            if base + 16 > data.len() {
                break;
            }
            descriptors.push(MemoryDescriptor64 {
                start_of_memory_range: read_u64(data, base),
                data_size: read_u64(data, base + 8),
            });
        }
        Ok(Self {
            base_rva,
            descriptors,
        })
    }
}

// ---------------------------------------------------------------------------
// Parsed minidump
// ---------------------------------------------------------------------------

/// Full parsed result of loading a minidump file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedMinidump {
    pub header: MinidumpHeader,
    pub directory: Vec<MinidumpDirectoryEntry>,
    pub streams: Vec<MinidumpStream>,
    /// Summary statistics.
    pub summary: MinidumpSummary,
}

impl ParsedMinidump {
    /// Returns the `SystemInfo` stream if present.
    #[must_use]
    pub fn system_info(&self) -> Option<&SystemInfoStream> {
        self.streams.iter().find_map(|s| {
            if let MinidumpStream::SystemInfo(si) = s {
                Some(si)
            } else {
                None
            }
        })
    }

    /// Returns the `ExceptionStream` if present.
    #[must_use]
    pub fn exception(&self) -> Option<&ExceptionStream> {
        self.streams.iter().find_map(|s| {
            if let MinidumpStream::Exception(e) = s {
                Some(e)
            } else {
                None
            }
        })
    }

    /// Returns the `ModuleList` stream if present.
    #[must_use]
    pub fn module_list(&self) -> Option<&ModuleListStream> {
        self.streams.iter().find_map(|s| {
            if let MinidumpStream::ModuleList(m) = s {
                Some(m)
            } else {
                None
            }
        })
    }

    /// Returns the `ThreadList` stream if present.
    #[must_use]
    pub fn thread_list(&self) -> Option<&ThreadListStream> {
        self.streams.iter().find_map(|s| {
            if let MinidumpStream::ThreadList(t) = s {
                Some(t)
            } else {
                None
            }
        })
    }

    /// Extract memory bytes at a given virtual address using the memory list.
    #[must_use]
    pub fn read_memory<'a>(&self, data: &'a [u8], va: u64, size: usize) -> Option<&'a [u8]> {
        // Try MemoryList first.
        if let Some(s) = self.streams.iter().find_map(|s| {
            if let MinidumpStream::MemoryList(ml) = s {
                Some(ml)
            } else {
                None
            }
        }) {
            // Every field below is unvalidated attacker data from MINIDUMP_MEMORY_LIST
            // (only the descriptor *count* is clamped at parse time). In release each
            // `+` wraps silently: a `start_of_memory_range` near u64::MAX wraps `end`
            // down so the containment test succeeds, and `rva + size` then wraps below
            // `data.len()`, reaching `data[rva..rva + size]` with start > end -> panic.
            // Doing the whole chain with checked arithmetic makes a bad descriptor be
            // skipped instead.
            let Ok(size_u64) = u64::try_from(size) else {
                return None;
            };
            for desc in &s.descriptors {
                let Some(end) = desc
                    .start_of_memory_range
                    .checked_add(u64::from(desc.data_size))
                else {
                    continue;
                };
                let Some(va_end) = va.checked_add(size_u64) else {
                    continue;
                };
                if va < desc.start_of_memory_range || va_end > end {
                    continue;
                }
                let Ok(inner) = usize::try_from(va - desc.start_of_memory_range) else {
                    continue;
                };
                let Ok(base) = usize::try_from(desc.rva) else {
                    continue;
                };
                let Some(rva) = base.checked_add(inner) else {
                    continue;
                };
                let Some(rva_end) = rva.checked_add(size) else {
                    continue;
                };
                if let Some(slice) = data.get(rva..rva_end) {
                    return Some(slice);
                }
            }
        }
        // Try Memory64List.
        if let Some(s) = self.streams.iter().find_map(|s| {
            if let MinidumpStream::Memory64List(ml) = s {
                Some(ml)
            } else {
                None
            }
        }) {
            // Same unvalidated-descriptor problem as the MemoryList branch above, plus
            // `running_rva` accumulating attacker-controlled `data_size` across
            // descriptors: saturating on overflow there would silently alias a later
            // descriptor onto a valid offset, so stop walking instead.
            let Ok(size_u64) = u64::try_from(size) else {
                return None;
            };
            let Ok(mut running_rva) = usize::try_from(s.base_rva) else {
                return None;
            };
            for desc in &s.descriptors {
                // NB: no early `continue` here -- the cursor update at the bottom of
                // the loop must run for every descriptor, or a rejected descriptor
                // silently aliases the next one onto its offset.
                let end = desc.start_of_memory_range.checked_add(desc.data_size);
                let va_end = va.checked_add(size_u64);
                if let (Some(end), Some(va_end)) = (end, va_end) {
                    if va >= desc.start_of_memory_range && va_end <= end {
                        if let Ok(inner) = usize::try_from(va - desc.start_of_memory_range) {
                            if let Some(rva) = running_rva.checked_add(inner) {
                                if let Some(rva_end) = rva.checked_add(size) {
                                    if let Some(slice) = data.get(rva..rva_end) {
                                        return Some(slice);
                                    }
                                }
                            }
                        }
                    }
                }
                let Ok(step) = usize::try_from(desc.data_size) else {
                    break;
                };
                let Some(next) = running_rva.checked_add(step) else {
                    break;
                };
                running_rva = next;
            }
        }
        None
    }
}

/// High-level summary extracted from a minidump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpSummary {
    pub total_streams: usize,
    pub num_threads: usize,
    pub num_modules: usize,
    pub num_memory_regions: usize,
    pub has_exception: bool,
    pub windows_version: Option<String>,
    pub architecture: Option<String>,
    pub crash_address: Option<u64>,
    pub exception_code: Option<u32>,
    pub exception_name: Option<String>,
    pub module_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// Low-level read helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    data.get(offset..offset + 8).map_or(0, |b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

/// Loads and parses a Windows minidump file.
pub struct MinidumpLoader;

impl MinidumpLoader {
    /// Returns `true` if `data` starts with the MDMP signature.
    #[must_use]
    pub fn is_minidump(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == MDMP_SIGNATURE
    }

    /// Parse the minidump from `data` and return a `ParsedMinidump`.
    ///
    /// # Errors
    /// Returns a [`MinidumpError`] if the data is not a valid minidump.
    pub fn load(data: &[u8]) -> Result<ParsedMinidump, MinidumpError> {
        let header = MinidumpHeader::parse(data)?;

        // Parse directory.
        let dir_offset = header.stream_directory_rva as usize;
        // Guard against integer overflow: number_of_streams * DIRECTORY_ENTRY_SIZE can
        // overflow usize on malformed input (e.g. number_of_streams = u32::MAX).
        let dir_end = dir_offset
            .checked_add(
                (header.number_of_streams as usize)
                    .checked_mul(DIRECTORY_ENTRY_SIZE)
                    .ok_or(MinidumpError::TruncatedDirectory)?,
            )
            .ok_or(MinidumpError::TruncatedDirectory)?;
        if dir_end > data.len() {
            return Err(MinidumpError::TruncatedDirectory);
        }

        let mut directory: Vec<MinidumpDirectoryEntry> = Vec::new();
        for i in 0..header.number_of_streams as usize {
            let offset = dir_offset + i * DIRECTORY_ENTRY_SIZE;
            if let Some(entry) = MinidumpDirectoryEntry::parse(data, offset) {
                directory.push(entry);
            }
        }

        // Parse streams.
        let mut streams: Vec<MinidumpStream> = Vec::new();
        for entry in &directory {
            let offset = entry.rva as usize;
            let size = entry.data_size as usize;
            if entry.data_size > 0 {
                let end = offset + size;
                if end > data.len() {
                    return Err(MinidumpError::StreamOutOfBounds {
                        stream_type: entry.stream_type,
                        offset: offset as u64,
                        size: size as u64,
                    });
                }
            }

            let stream = match entry.stream_type {
                7 => MinidumpStream::SystemInfo(SystemInfoStream::parse(data, offset, size)?),
                6 => MinidumpStream::Exception(ExceptionStream::parse(data, offset, size)?),
                3 => MinidumpStream::ThreadList(ThreadListStream::parse(data, offset, size)?),
                4 => MinidumpStream::ModuleList(ModuleListStream::parse(data, offset, size)?),
                5 => MinidumpStream::MemoryList(MemoryListStream::parse(data, offset, size)?),
                9 => MinidumpStream::Memory64List(Memory64ListStream::parse(data, offset, size)?),
                _ => MinidumpStream::Unknown {
                    stream_type: entry.stream_type,
                    size: entry.data_size,
                },
            };
            streams.push(stream);
        }

        let summary = Self::build_summary(&streams);

        Ok(ParsedMinidump {
            header,
            directory,
            streams,
            summary,
        })
    }

    fn build_summary(streams: &[MinidumpStream]) -> MinidumpSummary {
        let mut summary = MinidumpSummary {
            total_streams: streams.len(),
            num_threads: 0,
            num_modules: 0,
            num_memory_regions: 0,
            has_exception: false,
            windows_version: None,
            architecture: None,
            crash_address: None,
            exception_code: None,
            exception_name: None,
            module_names: Vec::new(),
        };

        for stream in streams {
            match stream {
                MinidumpStream::SystemInfo(si) => {
                    summary.windows_version = Some(si.windows_version());
                    summary.architecture = Some(si.arch_name().to_string());
                }
                MinidumpStream::Exception(e) => {
                    summary.has_exception = true;
                    summary.crash_address = Some(e.exception_address);
                    summary.exception_code = Some(e.exception_code);
                    summary.exception_name = Some(e.exception_name().to_string());
                }
                MinidumpStream::ThreadList(tl) => {
                    summary.num_threads = tl.threads.len();
                }
                MinidumpStream::ModuleList(ml) => {
                    summary.num_modules = ml.modules.len();
                    summary.module_names = ml.modules.iter().map(|m| m.name.clone()).collect();
                }
                MinidumpStream::MemoryList(ml) => {
                    summary.num_memory_regions += ml.descriptors.len();
                }
                MinidumpStream::Memory64List(ml) => {
                    summary.num_memory_regions += ml.descriptors.len();
                }
                MinidumpStream::Unknown { .. } => {}
            }
        }

        summary
    }
}

// ---------------------------------------------------------------------------
// Additional helpers
// ---------------------------------------------------------------------------

/// Returns the stream directory as a map from stream-type to (size, rva).
#[must_use]
pub fn stream_map(dump: &ParsedMinidump) -> HashMap<u32, (u32, u32)> {
    dump.directory
        .iter()
        .map(|e| (e.stream_type, (e.data_size, e.rva)))
        .collect()
}

/// Converts a MINIDUMP timestamp to a naive date/time string.
#[must_use]
pub fn format_timestamp(ts: u32) -> String {
    // Simple conversion: seconds since 1970.  No external dep needed.
    let days = ts / 86400;
    let years = 1970 + days / 365;
    let doy = days % 365;
    let month = 1 + doy / 30;
    let day = 1 + doy % 30;
    let hms = ts % 86400;
    let h = hms / 3600;
    let m = (hms % 3600) / 60;
    let s = hms % 60;
    format!("{years:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod overflow_regression_tests {
    use super::*;

    fn empty_parsed(streams: Vec<MinidumpStream>) -> ParsedMinidump {
        ParsedMinidump {
            header: MinidumpHeader {
                signature: *b"MDMP",
                version: 0,
                number_of_streams: 0,
                stream_directory_rva: 0,
                check_sum: 0,
                time_date_stamp: 0,
                flags: 0,
            },
            directory: Vec::new(),
            summary: MinidumpSummary {
                total_streams: 0,
                num_threads: 0,
                num_modules: 0,
                num_memory_regions: 0,
                has_exception: false,
                windows_version: None,
                architecture: None,
                crash_address: None,
                exception_code: None,
                exception_name: None,
                module_names: Vec::new(),
            },
            streams,
        }
    }

    /// The MemoryList branch caps out at a u32 `data_size`, so on a 64-bit target the
    /// wrapping additions cannot in fact drive `rva` past usize -- measured, not
    /// assumed: this test passes against the pre-fix code too. It guards the
    /// hardening against regression, and covers the 32-bit target where
    /// `usize::try_from(..).unwrap_or(usize::MAX)` did make `rva` wrap.
    #[test]
    fn memory_list_wrapping_descriptor_does_not_panic() {
        let md = empty_parsed(vec![MinidumpStream::MemoryList(MemoryListStream {
            descriptors: vec![MemoryDescriptor {
                start_of_memory_range: u64::MAX - 4,
                data_size: u32::MAX,
                rva: u32::MAX,
            }],
        })]);
        let data = vec![0u8; 64];
        assert_eq!(md.read_memory(&data, 0, 16), None);
        assert_eq!(md.read_memory(&data, u64::MAX - 4, 16), None);
    }

    /// The Memory64 branch is the genuinely exploitable one: `data_size` is a full
    /// u64 there, so one descriptor covering the whole address space makes `inner`
    /// (and hence `rva`) enormous, `rva + size` wraps back under `data.len()`, and
    /// the old code evaluated `&data[rva..rva + size]` with start > end -> slice
    /// index panic. Confirmed to panic against the pre-fix code.
    #[test]
    fn memory64_list_wrapping_rva_does_not_panic() {
        let md = empty_parsed(vec![MinidumpStream::Memory64List(Memory64ListStream {
            base_rva: 0,
            descriptors: vec![MemoryDescriptor64 {
                start_of_memory_range: 0,
                data_size: u64::MAX,
            }],
        })]);
        let data = vec![0u8; 64];
        // va + size wraps to 7, which passes `<= end`; rva + size then wraps to 7 too.
        assert_eq!(md.read_memory(&data, u64::MAX - 8, 16), None);
    }

    /// `running_rva += data_size` was unchecked, so a first descriptor with a huge
    /// `data_size` wrapped the cursor and aliased the second descriptor onto a low,
    /// in-bounds offset -- silently returning the wrong bytes rather than nothing.
    #[test]
    fn memory64_list_running_rva_overflow_does_not_alias() {
        let md = empty_parsed(vec![MinidumpStream::Memory64List(Memory64ListStream {
            base_rva: 16,
            descriptors: vec![
                MemoryDescriptor64 {
                    start_of_memory_range: 0x1000,
                    data_size: u64::MAX,
                },
                MemoryDescriptor64 {
                    start_of_memory_range: 0x2000,
                    data_size: 8,
                },
            ],
        })]);
        let data = vec![0u8; 64];
        assert_eq!(md.read_memory(&data, 0x2000, 8), None);
    }

    /// A well-formed Memory64 descriptor must still resolve after the hardening.
    #[test]
    fn memory64_list_valid_descriptor_still_reads() {
        let md = empty_parsed(vec![MinidumpStream::Memory64List(Memory64ListStream {
            base_rva: 4,
            descriptors: vec![
                MemoryDescriptor64 {
                    start_of_memory_range: 0x1000,
                    data_size: 8,
                },
                MemoryDescriptor64 {
                    start_of_memory_range: 0x2000,
                    data_size: 8,
                },
            ],
        })]);
        let mut data = vec![0u8; 32];
        data[4..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(md.read_memory(&data, 0x1000, 8), Some(&data[4..12]));
        // second descriptor lives at base_rva + first data_size = 12
        assert_eq!(md.read_memory(&data, 0x2000, 8), Some(&data[12..20]));
    }

    /// A well-formed descriptor must still resolve after the hardening.
    #[test]
    fn memory_list_valid_descriptor_still_reads() {
        let md = empty_parsed(vec![MinidumpStream::MemoryList(MemoryListStream {
            descriptors: vec![MemoryDescriptor {
                start_of_memory_range: 0x1000,
                data_size: 8,
                rva: 4,
            }],
        })]);
        let mut data = vec![0u8; 32];
        data[4..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(md.read_memory(&data, 0x1000, 8), Some(&data[4..12]));
        assert_eq!(md.read_memory(&data, 0x1002, 4), Some(&data[6..10]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_minidump(streams: &[(u32, &[u8])]) -> Vec<u8> {
        const HDR: usize = 32;
        let dir_offset: u32 = HDR as u32;
        let n = streams.len() as u32;
        let dir_size = n as usize * 12;

        // Build stream data starting after header + directory.
        let data_start = HDR + dir_size;
        let mut stream_data_offsets: Vec<u32> = Vec::new();
        let mut all_stream_data: Vec<u8> = Vec::new();
        for (_, data) in streams {
            stream_data_offsets.push((data_start + all_stream_data.len()) as u32);
            all_stream_data.extend_from_slice(data);
        }

        let mut buf = vec![0u8; data_start + all_stream_data.len()];
        // Header
        buf[0..4].copy_from_slice(b"MDMP");
        buf[4..8].copy_from_slice(&0x0000_A793u32.to_le_bytes()); // version
        buf[8..12].copy_from_slice(&n.to_le_bytes());
        buf[12..16].copy_from_slice(&dir_offset.to_le_bytes());
        // flags
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());

        // Directory entries
        for (i, ((stream_type, data), offset)) in
            streams.iter().zip(stream_data_offsets.iter()).enumerate()
        {
            let base = HDR + i * 12;
            buf[base..base + 4].copy_from_slice(&stream_type.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[base + 8..base + 12].copy_from_slice(&offset.to_le_bytes());
        }

        // Stream data
        buf[data_start..].copy_from_slice(&all_stream_data);
        buf
    }

    #[test]
    fn test_is_minidump() {
        let buf = make_minimal_minidump(&[]);
        assert!(MinidumpLoader::is_minidump(&buf));
        assert!(!MinidumpLoader::is_minidump(b"NOTD"));
    }

    #[test]
    fn test_load_empty_streams() {
        let buf = make_minimal_minidump(&[]);
        let dump = MinidumpLoader::load(&buf).unwrap();
        assert_eq!(dump.directory.len(), 0);
        assert_eq!(dump.streams.len(), 0);
    }

    #[test]
    fn test_load_unknown_stream() {
        // Stream type 99 (unknown)
        let stream_data = vec![0xABu8; 20];
        let buf = make_minimal_minidump(&[(99, &stream_data)]);
        let dump = MinidumpLoader::load(&buf).unwrap();
        assert_eq!(dump.directory.len(), 1);
        assert!(matches!(
            &dump.streams[0],
            MinidumpStream::Unknown {
                stream_type: 99,
                ..
            }
        ));
    }

    #[test]
    fn test_system_info_parse() {
        // Build a 56-byte SystemInfo blob.
        let mut blob = vec![0u8; 56];
        // processor_architecture = 9 (AMD64)
        blob[0] = 9;
        // major_version = 10, minor_version = 0, build_number = 19041
        blob[8..12].copy_from_slice(&10u32.to_le_bytes());
        blob[12..16].copy_from_slice(&0u32.to_le_bytes());
        blob[16..20].copy_from_slice(&19041u32.to_le_bytes());

        let si = SystemInfoStream::parse(&blob, 0, blob.len()).unwrap();
        assert_eq!(si.arch_name(), "AMD64");
        assert_eq!(si.windows_version(), "10.0.19041");
    }

    #[test]
    fn test_invalid_signature() {
        let result = MinidumpLoader::load(b"NOTMDMP");
        assert!(matches!(
            result,
            Err(MinidumpError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_format_timestamp() {
        let s = format_timestamp(0);
        assert!(s.starts_with("1970"));
    }

    #[test]
    fn test_stream_map() {
        let buf = make_minimal_minidump(&[(99u32, &[0u8; 8])]);
        let dump = MinidumpLoader::load(&buf).unwrap();
        let map = stream_map(&dump);
        assert!(map.contains_key(&99));
        assert_eq!(map[&99].0, 8);
    }

    #[test]
    fn test_thread_list_stream() {
        // Build a ThreadList with 1 thread (4 bytes count + 48 bytes entry).
        let mut blob = vec![0u8; 4 + 48];
        blob[0] = 1; // count = 1
        blob[4..8].copy_from_slice(&42u32.to_le_bytes()); // thread_id = 42
        let buf = make_minimal_minidump(&[(3, &blob)]);
        let dump = MinidumpLoader::load(&buf).unwrap();
        let tl = dump.thread_list().unwrap();
        assert_eq!(tl.threads.len(), 1);
        assert_eq!(tl.threads[0].thread_id, 42);
        assert_eq!(dump.summary.num_threads, 1);
    }
}
