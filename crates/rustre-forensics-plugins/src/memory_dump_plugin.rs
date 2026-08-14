//! Memory Dump Analyzer Plugin
//!
//! Detects and parses multiple memory dump formats (Raw, `LiME`, `WinPmem`, MiniDump/Crash,
//! ELF core), extracts memory ranges, process entries, kernel modules, performs
//! pattern/string carving, PE header detection, and computes statistics.

use std::collections::HashMap;
use std::fmt;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DumpError {
    UnknownFormat,
    BufferTooSmall { needed: usize, available: usize },
    InvalidHeader(String),
    ParseError(String),
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "Unknown dump format"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "Buffer too small: need {needed}, have {available}")
            }
            Self::InvalidHeader(s) => write!(f, "Invalid header: {s}"),
            Self::ParseError(s) => write!(f, "Parse error: {s}"),
        }
    }
}

// ─── Format enum ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    /// Flat physical memory image (no header).
    Raw,
    /// Linux `LiME` (Linux Memory Extractor) format.
    Lime,
    /// `WinPmem` format (signature-detected).
    Winpmem,
    /// Windows `MiniDump` / `CrashDump` (MDMP magic).
    Crash,
    /// ELF core dump (`e_type` == `ET_CORE`).
    Elf,
}

impl fmt::Display for DumpFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => write!(f, "Raw"),
            Self::Lime => write!(f, "LiME"),
            Self::Winpmem => write!(f, "WinPmem"),
            Self::Crash => write!(f, "MiniDump/Crash"),
            Self::Elf => write!(f, "ELF Core"),
        }
    }
}

// ─── LiME header ─────────────────────────────────────────────────────────────

/// `LiME` segment header (appears before each memory range chunk).
#[derive(Debug, Clone)]
pub struct LimeHeader {
    pub magic: u32,
    pub version: u32,
    pub start_physical: u64,
    pub end_physical: u64,
    pub reserved: [u8; 8],
}

const LIME_MAGIC: u32 = 0x4C69_4D45; // "LiME"
const LIME_HEADER_SIZE: usize = 32;

impl LimeHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < LIME_HEADER_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        if magic != LIME_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let start = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        let end = u64::from_le_bytes(buf[16..24].try_into().ok()?);
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[24..32]);
        Some(Self {
            magic,
            version,
            start_physical: start,
            end_physical: end,
            reserved,
        })
    }
}

// ─── MiniDump header ──────────────────────────────────────────────────────────

/// Windows `MiniDump` file header.
#[derive(Debug, Clone)]
pub struct MiniDumpHeader {
    pub signature: [u8; 4],
    pub version: u32,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub flags: u64,
}

const MDMP_MAGIC: &[u8; 4] = b"MDMP";
const MINIDUMP_HEADER_SIZE: usize = 32;

impl MiniDumpHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < MINIDUMP_HEADER_SIZE {
            return None;
        }
        if &buf[0..4] != MDMP_MAGIC {
            return None;
        }
        let mut sig = [0u8; 4];
        sig.copy_from_slice(&buf[0..4]);
        Some(Self {
            signature: sig,
            version: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            number_of_streams: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            stream_directory_rva: u32::from_le_bytes(buf[12..16].try_into().ok()?),
            checksum: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            time_date_stamp: u32::from_le_bytes(buf[20..24].try_into().ok()?),
            flags: u64::from_le_bytes(buf[24..32].try_into().ok()?),
        })
    }
}

// ─── MiniDump stream types ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiniDumpStreamType {
    UnusedStream,
    ReservedStream0,
    ReservedStream1,
    ThreadListStream,
    ModuleListStream,
    MemoryListStream,
    ExceptionStream,
    SystemInfoStream,
    ThreadExListStream,
    Memory64ListStream,
    CommentStreamA,
    CommentStreamW,
    HandleDataStream,
    FunctionTableStream,
    UnloadedModuleListStream,
    MiscInfoStream,
    MemoryInfoListStream,
    ThreadInfoListStream,
    HandleOperationListStream,
    TokenStream,
    Unknown(u32),
}

impl MiniDumpStreamType {
    const fn from_u32(n: u32) -> Self {
        match n {
            0 => Self::UnusedStream,
            1 => Self::ReservedStream0,
            2 => Self::ReservedStream1,
            3 => Self::ThreadListStream,
            4 => Self::ModuleListStream,
            5 => Self::MemoryListStream,
            6 => Self::ExceptionStream,
            7 => Self::SystemInfoStream,
            8 => Self::ThreadExListStream,
            9 => Self::Memory64ListStream,
            10 => Self::CommentStreamA,
            11 => Self::CommentStreamW,
            12 => Self::HandleDataStream,
            13 => Self::FunctionTableStream,
            14 => Self::UnloadedModuleListStream,
            15 => Self::MiscInfoStream,
            16 => Self::MemoryInfoListStream,
            17 => Self::ThreadInfoListStream,
            18 => Self::HandleOperationListStream,
            19 => Self::TokenStream,
            other => Self::Unknown(other),
        }
    }
}

/// A `MiniDump` stream directory entry.
#[derive(Debug, Clone)]
pub struct MiniDumpStream {
    pub stream_type: MiniDumpStreamType,
    pub rva: u32,
    pub data_size: u32,
}

// ─── Memory range ─────────────────────────────────────────────────────────────

/// A contiguous physical/virtual memory range from the dump.
#[derive(Debug, Clone)]
pub struct MemoryRange {
    pub physical_start: u64,
    pub physical_end: u64,
    pub virtual_start: u64,
    pub flags: u32,
}

impl MemoryRange {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.physical_end.saturating_sub(self.physical_start)
    }
}

// ─── Process entry ────────────────────────────────────────────────────────────

/// A process reconstructed from dump analysis.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: u64,
    pub dtb_offset: u64,
    pub vad_root: u64,
}

// ─── Kernel module entry ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KernelModuleEntry {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

// ─── Dump statistics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DumpStats {
    pub format: DumpFormat,
    pub range_count: usize,
    pub process_count: usize,
    pub module_count: usize,
    pub total_bytes: u64,
    pub entropy: f64,
    pub pe_header_count: usize,
    pub stream_count: usize,
}

// ─── ELF helpers ──────────────────────────────────────────────────────────────

const ELF_MAGIC: &[u8; 4] = &[0x7F, b'E', b'L', b'F'];
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const _PT_NOTE: u32 = 4;

fn parse_elf_ranges(data: &[u8]) -> Vec<MemoryRange> {
    if data.len() < 64 {
        return vec![];
    }
    if &data[0..4] != ELF_MAGIC {
        return vec![];
    }
    let bits = data[4]; // 1 = 32-bit, 2 = 64-bit
    let e_type = u16::from_le_bytes(data[16..18].try_into().unwrap_or([0; 2]));
    if e_type != ET_CORE {
        return vec![];
    }
    let mut ranges = Vec::new();
    if bits == 2 {
        // 64-bit ELF
        let ph_off = usize::try_from(u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
        let ph_num = u16::from_le_bytes(data[56..58].try_into().unwrap_or([0; 2])) as usize;
        let ph_size = u16::from_le_bytes(data[54..56].try_into().unwrap_or([0; 2])) as usize;
        for i in 0..ph_num {
            let off = ph_off + i * ph_size;
            if off + ph_size > data.len() {
                break;
            }
            let p_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
            if p_type == PT_LOAD {
                let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap_or([0; 8]));
                let p_vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap_or([0; 8]));
                let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap_or([0; 8]));
                ranges.push(MemoryRange {
                    physical_start: p_offset,
                    physical_end: p_offset + p_filesz,
                    virtual_start: p_vaddr,
                    flags: u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4])),
                });
            }
        }
    }
    ranges
}

// ─── Entropy helper ───────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / len;
        p.mul_add(-p.log2(), acc)
    })
}

// ─── MemoryDumpAnalyzer ───────────────────────────────────────────────────────

pub struct MemoryDumpAnalyzer<'a> {
    pub data: &'a [u8],
    pub format: DumpFormat,
}

impl<'a> MemoryDumpAnalyzer<'a> {
    /// Detect the format of a memory dump from its header bytes.
    #[must_use]
    pub fn detect_format(data: &[u8]) -> DumpFormat {
        if data.len() < 4 {
            return DumpFormat::Raw;
        }
        // LiME
        if data.len() >= 4 {
            let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
            if magic == LIME_MAGIC {
                return DumpFormat::Lime;
            }
        }
        // MiniDump
        if data.len() >= 4 && &data[0..4] == MDMP_MAGIC {
            return DumpFormat::Crash;
        }
        // ELF
        if data.len() >= 4 && &data[0..4] == ELF_MAGIC.as_ref()
            && data.len() >= 18 {
                let e_type = u16::from_le_bytes(data[16..18].try_into().unwrap_or([0; 2]));
                if e_type == ET_CORE {
                    return DumpFormat::Elf;
                }
            }
        // WinPmem: looks for "Win" at offset 0 in the metadata block (simplified)
        if data.len() >= 8 && &data[4..8] == b"WPm\x00" {
            return DumpFormat::Winpmem;
        }
        DumpFormat::Raw
    }

    /// Create a new analyzer for the given data.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        let format = Self::detect_format(data);
        MemoryDumpAnalyzer { data, format }
    }

    /// Parse all memory ranges from the dump.
    #[must_use]
    pub fn parse_ranges(&self) -> Vec<MemoryRange> {
        match self.format {
            DumpFormat::Lime => self.parse_lime_ranges(),
            DumpFormat::Crash => self.parse_minidump_ranges(),
            DumpFormat::Elf => parse_elf_ranges(self.data),
            DumpFormat::Winpmem => self.parse_winpmem_ranges(),
            DumpFormat::Raw => vec![MemoryRange {
                physical_start: 0,
                physical_end: self.data.len() as u64,
                virtual_start: 0,
                flags: 0,
            }],
        }
    }

    fn parse_lime_ranges(&self) -> Vec<MemoryRange> {
        let mut ranges = Vec::new();
        let mut off = 0usize;
        while off + LIME_HEADER_SIZE <= self.data.len() {
            let Some(hdr) = LimeHeader::parse(&self.data[off..]) else { break };
            let size = usize::try_from(hdr.end_physical.saturating_sub(hdr.start_physical) + 1).unwrap_or(usize::MAX);
            ranges.push(MemoryRange {
                physical_start: hdr.start_physical,
                physical_end: hdr.end_physical,
                virtual_start: hdr.start_physical,
                flags: 0,
            });
            off += LIME_HEADER_SIZE + size;
        }
        ranges
    }

    fn parse_minidump_ranges(&self) -> Vec<MemoryRange> {
        let Some(hdr) = MiniDumpHeader::parse(self.data) else { return vec![] };
        let streams = self.parse_streams(&hdr);
        let mut ranges = Vec::new();
        for stream in &streams {
            if stream.stream_type == MiniDumpStreamType::MemoryListStream {
                ranges.extend(self.parse_memory_list(stream.rva as usize));
            } else if stream.stream_type == MiniDumpStreamType::Memory64ListStream {
                ranges.extend(self.parse_memory64_list(stream.rva as usize));
            }
        }
        ranges
    }

    fn parse_winpmem_ranges(&self) -> Vec<MemoryRange> {
        // WinPmem: simplified — treat whole file as single range
        vec![MemoryRange {
            physical_start: 0,
            physical_end: self.data.len() as u64,
            virtual_start: 0,
            flags: 0,
        }]
    }

    /// Parse `MiniDump` stream directory.
    #[must_use]
    pub fn parse_streams(&self, hdr: &MiniDumpHeader) -> Vec<MiniDumpStream> {
        let dir_off = hdr.stream_directory_rva as usize;
        let n = hdr.number_of_streams as usize;
        let mut streams = Vec::new();
        for i in 0..n {
            let off = dir_off + i * 12;
            if off + 12 > self.data.len() {
                break;
            }
            let stream_type = u32::from_le_bytes(
                self.data[off..off + 4].try_into().unwrap_or([0; 4]),
            );
            let data_size = u32::from_le_bytes(
                self.data[off + 4..off + 8].try_into().unwrap_or([0; 4]),
            );
            let rva = u32::from_le_bytes(
                self.data[off + 8..off + 12].try_into().unwrap_or([0; 4]),
            );
            streams.push(MiniDumpStream {
                stream_type: MiniDumpStreamType::from_u32(stream_type),
                rva,
                data_size,
            });
        }
        streams
    }

    fn parse_memory_list(&self, off: usize) -> Vec<MemoryRange> {
        if off + 4 > self.data.len() {
            return vec![];
        }
        let count =
            u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        let mut ranges = Vec::new();
        for i in 0..count {
            let entry_off = off + 4 + i * 16;
            if entry_off + 16 > self.data.len() {
                break;
            }
            let start = u64::from_le_bytes(
                self.data[entry_off..entry_off + 8].try_into().unwrap_or([0; 8]),
            );
            let size_bytes = u64::from(u32::from_le_bytes(
                self.data[entry_off + 8..entry_off + 12]
                    .try_into()
                    .unwrap_or([0; 4]),
            ));
            let rva = u64::from(u32::from_le_bytes(
                self.data[entry_off + 12..entry_off + 16]
                    .try_into()
                    .unwrap_or([0; 4]),
            ));
            ranges.push(MemoryRange {
                physical_start: rva,
                physical_end: rva + size_bytes,
                virtual_start: start,
                flags: 0,
            });
        }
        ranges
    }

    fn parse_memory64_list(&self, off: usize) -> Vec<MemoryRange> {
        if off + 16 > self.data.len() {
            return vec![];
        }
        let count =
            usize::try_from(u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
        let base_rva =
            u64::from_le_bytes(self.data[off + 8..off + 16].try_into().unwrap_or([0; 8]));
        let mut ranges = Vec::new();
        let mut file_off = base_rva;
        for i in 0..count {
            let entry_off = off + 16 + i * 16;
            if entry_off + 16 > self.data.len() {
                break;
            }
            let start = u64::from_le_bytes(
                self.data[entry_off..entry_off + 8].try_into().unwrap_or([0; 8]),
            );
            let sz = u64::from_le_bytes(
                self.data[entry_off + 8..entry_off + 16]
                    .try_into()
                    .unwrap_or([0; 8]),
            );
            ranges.push(MemoryRange {
                physical_start: file_off,
                physical_end: file_off + sz,
                virtual_start: start,
                flags: 0,
            });
            file_off += sz;
        }
        ranges
    }

    /// Extract process entries by scanning for a lightweight process record tag.
    /// Record format: `b"PROC"` (4) | pid(4) | ppid(4) | `create_time`(8) |
    ///                `dtb_offset`(8) | `vad_root`(8) | name(16)
    #[must_use]
    pub fn extract_processes(&self) -> Vec<ProcessEntry> {
        const TAG: &[u8; 4] = b"PROC";
        const RECORD_SIZE: usize = 4 + 4 + 4 + 8 + 8 + 8 + 16; // 52
        let d = self.data;
        let mut result = Vec::new();
        let mut i = 0usize;
        while i + RECORD_SIZE <= d.len() {
            if &d[i..i + 4] == TAG {
                let pid = u32::from_le_bytes(d[i + 4..i + 8].try_into().unwrap_or([0; 4]));
                let parent_pid = u32::from_le_bytes(d[i + 8..i + 12].try_into().unwrap_or([0; 4]));
                let create_time = u64::from_le_bytes(d[i + 12..i + 20].try_into().unwrap_or([0; 8]));
                let dtb_offset = u64::from_le_bytes(d[i + 20..i + 28].try_into().unwrap_or([0; 8]));
                let vad_root = u64::from_le_bytes(d[i + 28..i + 36].try_into().unwrap_or([0; 8]));
                let name_bytes = &d[i + 36..i + 52];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
                result.push(ProcessEntry { pid, ppid: parent_pid, name, create_time, dtb_offset, vad_root });
                i += RECORD_SIZE;
                continue;
            }
            i += 4;
        }
        result
    }

    /// Extract kernel module entries by scanning for `b"KMOD"` tags.
    /// Record format: `b"KMOD"` (4) | base(8) | size(8) | name(32) | path(64)
    #[must_use]
    pub fn extract_modules(&self) -> Vec<KernelModuleEntry> {
        const TAG: &[u8; 4] = b"KMOD";
        const RECORD_SIZE: usize = 4 + 8 + 8 + 32 + 64; // 116
        let d = self.data;
        let mut result = Vec::new();
        let mut i = 0usize;
        while i + RECORD_SIZE <= d.len() {
            if &d[i..i + 4] == TAG {
                let base = u64::from_le_bytes(d[i + 4..i + 12].try_into().unwrap_or([0; 8]));
                let size = u64::from_le_bytes(d[i + 12..i + 20].try_into().unwrap_or([0; 8]));
                let name = nul_str(&d[i + 20..i + 52]);
                let path = nul_str(&d[i + 52..i + 116]);
                result.push(KernelModuleEntry { base, size, name, path });
                i += RECORD_SIZE;
                continue;
            }
            i += 1;
        }
        result
    }

    /// Search for a raw byte pattern in the dump data, returning all offsets.
    #[must_use]
    pub fn search_pattern(&self, pattern: &[u8]) -> Vec<u64> {
        if pattern.is_empty() || pattern.len() > self.data.len() {
            return vec![];
        }
        let mut offsets = Vec::new();
        let mut i = 0usize;
        while i + pattern.len() <= self.data.len() {
            if self.data[i..i + pattern.len()] == *pattern {
                offsets.push(i as u64);
                i += pattern.len();
            } else {
                i += 1;
            }
        }
        offsets
    }

    /// Carve printable ASCII strings of at least `min_len` bytes.
    #[must_use]
    pub fn carve_strings(&self, min_len: usize) -> Vec<(u64, String)> {
        let d = self.data;
        let mut result = Vec::new();
        let mut run_start = 0usize;
        let mut run: Vec<u8> = Vec::new();
        for (i, &b) in d.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(b);
            } else {
                if run.len() >= min_len {
                    let s = String::from_utf8_lossy(&run).to_string();
                    result.push((run_start as u64, s));
                }
                run.clear();
            }
        }
        if run.len() >= min_len {
            result.push((run_start as u64, String::from_utf8_lossy(&run).to_string()));
        }
        result
    }

    /// Find MZ/PE header locations in the dump data.
    #[must_use]
    pub fn find_pe_headers(&self) -> Vec<u64> {
        let d = self.data;
        let mut offsets = Vec::new();
        let mut i = 0usize;
        while i + 2 <= d.len() {
            if d[i] == b'M' && d[i + 1] == b'Z' {
                // Validate e_lfanew if possible
                if i + 0x40 <= d.len() {
                    let e_lfanew = u32::from_le_bytes(
                        d[i + 0x3C..i + 0x40].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    if e_lfanew > 0 && i + e_lfanew + 4 <= d.len()
                        && &d[i + e_lfanew..i + e_lfanew + 4] == b"PE\x00\x00" {
                            offsets.push(i as u64);
                        }
                }
            }
            i += 1;
        }
        offsets
    }

    /// Compute aggregate dump statistics.
    #[must_use]
    pub fn compute_statistics(&self) -> DumpStats {
        let ranges = self.parse_ranges();
        let processes = self.extract_processes();
        let modules = self.extract_modules();
        let total_bytes: u64 = ranges.iter().map(MemoryRange::size).sum();
        let pe_headers = self.find_pe_headers();
        let sample_size = self.data.len().min(65536);
        let entropy = shannon_entropy(&self.data[..sample_size]);

        let stream_count = if self.format == DumpFormat::Crash {
            MiniDumpHeader::parse(self.data).map_or(0, |hdr| self.parse_streams(&hdr).len())
        } else {
            0
        };

        DumpStats {
            format: self.format,
            range_count: ranges.len(),
            process_count: processes.len(),
            module_count: modules.len(),
            total_bytes,
            entropy,
            pe_header_count: pe_headers.len(),
            stream_count,
        }
    }
}

// ─── Plugin struct ────────────────────────────────────────────────────────────

pub struct MemoryDumpPlugin;

impl MemoryDumpPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyze a dump buffer, returning a statistics summary.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> DumpStats {
        let analyzer = MemoryDumpAnalyzer::new(data);
        analyzer.compute_statistics()
    }

    /// Batch-analyze multiple named dumps.
    #[must_use]
    pub fn analyze_all<'a>(
        &self,
        dumps: &'a HashMap<String, Vec<u8>>,
    ) -> HashMap<&'a str, DumpStats> {
        dumps
            .iter()
            .map(|(name, data)| (name.as_str(), MemoryDumpAnalyzer::new(data).compute_statistics()))
            .collect()
    }
}

impl Default for MemoryDumpPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn nul_str(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_lime_dump(ranges: &[(u64, u64, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (start, end, data) in ranges {
            let magic = LIME_MAGIC;
            buf.extend_from_slice(&magic.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes()); // version
            buf.extend_from_slice(&start.to_le_bytes());
            buf.extend_from_slice(&end.to_le_bytes());
            buf.extend_from_slice(&[0u8; 8]); // reserved
            buf.extend_from_slice(data);
        }
        buf
    }

    fn build_minidump(num_streams: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"MDMP");
        buf[4..8].copy_from_slice(&0xA793u32.to_le_bytes()); // version
        buf[8..12].copy_from_slice(&num_streams.to_le_bytes());
        buf[12..16].copy_from_slice(&32u32.to_le_bytes()); // stream directory rva
        buf[20..24].copy_from_slice(&0x005F_1234_u32.to_le_bytes()); // timestamp
        buf
    }

    fn build_raw_with_procs() -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        // Insert a PROC record
        const OFF: usize = 100;
        buf[OFF..OFF + 4].copy_from_slice(b"PROC");
        buf[OFF + 4..OFF + 8].copy_from_slice(&1234u32.to_le_bytes()); // pid
        buf[OFF + 8..OFF + 12].copy_from_slice(&1u32.to_le_bytes()); // ppid
        buf[OFF + 12..OFF + 20].copy_from_slice(&133_000_000_000u64.to_le_bytes());
        buf[OFF + 20..OFF + 28].copy_from_slice(&0x1234_5678u64.to_le_bytes());
        buf[OFF + 28..OFF + 36].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        buf[OFF + 36..OFF + 52].copy_from_slice(b"svchost.exe\x00\x00\x00\x00\x00");
        buf
    }

    #[test]
    fn test_detect_format_lime() {
        let data = build_lime_dump(&[(0, 0x1000, &[0u8; 0x1001])]);
        assert_eq!(MemoryDumpAnalyzer::detect_format(&data), DumpFormat::Lime);
    }

    #[test]
    fn test_detect_format_crash() {
        let data = build_minidump(0);
        assert_eq!(MemoryDumpAnalyzer::detect_format(&data), DumpFormat::Crash);
    }

    #[test]
    fn test_detect_format_raw() {
        let data = vec![0u8; 1024];
        assert_eq!(MemoryDumpAnalyzer::detect_format(&data), DumpFormat::Raw);
    }

    #[test]
    fn test_detect_format_elf_core() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(ELF_MAGIC.as_ref());
        data[4] = 2; // 64-bit
        data[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
        assert_eq!(MemoryDumpAnalyzer::detect_format(&data), DumpFormat::Elf);
    }

    #[test]
    fn test_parse_lime_ranges() {
        let content = vec![0x42u8; 0x1001];
        let dump = build_lime_dump(&[(0x1000, 0x2000, &content)]);
        let analyzer = MemoryDumpAnalyzer::new(&dump);
        let ranges = analyzer.parse_ranges();
        assert!(!ranges.is_empty());
        assert_eq!(ranges[0].physical_start, 0x1000);
        assert_eq!(ranges[0].physical_end, 0x2000);
    }

    #[test]
    fn test_parse_raw_single_range() {
        let data = vec![0xABu8; 4096];
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let ranges = analyzer.parse_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].physical_end, 4096);
    }

    #[test]
    fn test_extract_processes() {
        let data = build_raw_with_procs();
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let procs = analyzer.extract_processes();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 1234);
        assert_eq!(procs[0].ppid, 1);
        assert!(procs[0].name.contains("svchost"));
    }

    #[test]
    fn test_extract_modules() {
        let mut data = vec![0u8; 1024];
        let off = 50usize;
        data[off..off + 4].copy_from_slice(b"KMOD");
        data[off + 4..off + 12].copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        data[off + 12..off + 20].copy_from_slice(&0x10000u64.to_le_bytes());
        let name = b"ntoskrnl.exe\x00";
        data[off + 20..off + 20 + name.len()].copy_from_slice(name);
        let path = b"\\SystemRoot\\system32\\ntoskrnl.exe\x00";
        data[off + 52..off + 52 + path.len()].copy_from_slice(path);
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let mods = analyzer.extract_modules();
        assert_eq!(mods.len(), 1);
        assert!(mods[0].name.contains("ntoskrnl"));
    }

    #[test]
    fn test_search_pattern_found() {
        let data = b"ABCDEABCDE__ABCDE".to_vec();
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let hits = analyzer.search_pattern(b"ABCDE");
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0], 0);
        assert_eq!(hits[1], 5);
        assert_eq!(hits[2], 12);
    }

    #[test]
    fn test_search_pattern_not_found() {
        let data = vec![0u8; 100];
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let hits = analyzer.search_pattern(b"XXXXXX");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_carve_strings_min_len() {
        let data = b"hi\x00\x00hello_world\x00\x00short\x00tiny".to_vec();
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let strings = analyzer.carve_strings(8);
        assert!(strings.iter().any(|(_, s)| s == "hello_world"));
        assert!(!strings.iter().any(|(_, s)| s == "hi"));
    }

    #[test]
    fn test_find_pe_headers() {
        let mut data = vec![0u8; 8192];
        // Plant a valid-looking PE
        let pe_off = 0x1000usize;
        data[pe_off] = b'M';
        data[pe_off + 1] = b'Z';
        let e_lfanew: u32 = 0x40;
        data[pe_off + 0x3C..pe_off + 0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_sig_off = pe_off + e_lfanew as usize;
        data[pe_sig_off..pe_sig_off + 4].copy_from_slice(b"PE\x00\x00");
        let analyzer = MemoryDumpAnalyzer::new(&data);
        let headers = analyzer.find_pe_headers();
        assert!(headers.contains(&(pe_off as u64)));
    }

    #[test]
    fn test_compute_statistics_raw() {
        let data = vec![0x41u8; 4096];
        let plugin = MemoryDumpPlugin::new();
        let stats = plugin.analyze(&data);
        assert_eq!(stats.format, DumpFormat::Raw);
        assert_eq!(stats.range_count, 1);
        assert_eq!(stats.total_bytes, 4096);
    }

    #[test]
    fn test_dump_format_display() {
        assert_eq!(DumpFormat::Raw.to_string(), "Raw");
        assert_eq!(DumpFormat::Lime.to_string(), "LiME");
        assert_eq!(DumpFormat::Crash.to_string(), "MiniDump/Crash");
        assert_eq!(DumpFormat::Elf.to_string(), "ELF Core");
    }

    #[test]
    fn test_lime_header_parse_invalid() {
        let data = vec![0u8; 32];
        assert!(LimeHeader::parse(&data).is_none());
    }

    #[test]
    fn test_lime_header_parse_valid() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&LIME_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        let hdr = LimeHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic, LIME_MAGIC);
        assert_eq!(hdr.start_physical, 0x1000);
        assert_eq!(hdr.end_physical, 0x2000);
    }

    #[test]
    fn test_minidump_header_parse() {
        let data = build_minidump(3);
        let hdr = MiniDumpHeader::parse(&data).unwrap();
        assert_eq!(&hdr.signature, b"MDMP");
        assert_eq!(hdr.number_of_streams, 3);
    }

    #[test]
    fn test_stream_type_from_u32() {
        assert_eq!(MiniDumpStreamType::from_u32(3), MiniDumpStreamType::ThreadListStream);
        assert_eq!(MiniDumpStreamType::from_u32(4), MiniDumpStreamType::ModuleListStream);
        assert!(matches!(MiniDumpStreamType::from_u32(999), MiniDumpStreamType::Unknown(999)));
    }

    #[test]
    fn test_analyze_all_batch() {
        let plugin = MemoryDumpPlugin::new();
        let mut dumps = HashMap::new();
        dumps.insert("test1.raw".to_string(), vec![0u8; 1024]);
        dumps.insert("test2.raw".to_string(), vec![0xFFu8; 2048]);
        let results = plugin.analyze_all(&dumps);
        assert_eq!(results.len(), 2);
        assert!(results.contains_key("test1.raw"));
        assert!(results.contains_key("test2.raw"));
    }
}
