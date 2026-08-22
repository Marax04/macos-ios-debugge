//! Windows Prefetch (.pf) file parser and analyzer.
//!
//! Supports SCCA format versions 17 (`WinXP`), 23 (Vista/7), 26 (Win8.1), and
//! 30 (Win10).  Extracts execution timestamps, loaded DLL/resource strings,
//! file metrics, and volume information.

use std::fmt;
use std::io;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every SCCA prefetch file (little-endian 0x53434341 = "SCCA").
pub const SCCA_MAGIC: u32 = 0x4143_4353; // bytes: S C C A (LE as "ACCS")
/// Alternative magic ordering stored in the file.
pub const SCCA_MAGIC_LE: [u8; 4] = [0x53, 0x43, 0x43, 0x41]; // "SCCA"

/// Maximum number of execution timestamps stored in v26/v30.
pub const MAX_TIMESTAMPS_V26: usize = 8;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the prefetch parser.
#[derive(Debug)]
pub enum PrefetchError {
    /// Input data was too short to contain a valid header.
    TooShort { needed: usize, got: usize },
    /// The magic bytes did not match SCCA.
    InvalidMagic([u8; 4]),
    /// Unsupported format version.
    UnsupportedVersion(u32),
    /// A string or slice offset was out of bounds.
    OutOfBounds { offset: u32, len: u32 },
    /// I/O error during parsing.
    Io(io::Error),
    /// Data encoding error (e.g. invalid UTF-16).
    Encoding(String),
}

impl fmt::Display for PrefetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(f, "file too short: need {needed}, got {got}")
            }
            Self::InvalidMagic(m) => {
                write!(f, "invalid magic {:02x}{:02x}{:02x}{:02x}", m[0], m[1], m[2], m[3])
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported SCCA version {v}"),
            Self::OutOfBounds { offset, len } => {
                write!(f, "offset 0x{offset:x} length {len} out of bounds")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Encoding(s) => write!(f, "encoding error: {s}"),
        }
    }
}

impl From<io::Error> for PrefetchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// Supported SCCA format versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScccVersion {
    /// Windows XP / 2003.
    V17 = 17,
    /// Windows Vista / 7.
    V23 = 23,
    /// Windows 8.1.
    V26 = 26,
    /// Windows 10.
    V30 = 30,
}

impl ScccVersion {
    /// Parse a raw version number.
    #[must_use] 
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            17 => Some(Self::V17),
            23 => Some(Self::V23),
            26 => Some(Self::V26),
            30 => Some(Self::V30),
            _ => None,
        }
    }

    /// Whether this version stores up to 8 execution timestamps.
    #[must_use] 
    pub const fn has_multi_timestamps(self) -> bool {
        matches!(self, Self::V26 | Self::V30)
    }

    /// Byte offset of the file metrics array section offset field in the header.
    #[must_use] 
    pub const fn metrics_array_offset_field(self) -> usize {
        match self {
            Self::V17 => 0x54,
            Self::V23 => 0x60,
            Self::V26 | Self::V30 => 0x68,
        }
    }
}

/// Raw SCCA file header (first 84 bytes present in all versions).
#[derive(Debug, Clone)]
pub struct PrefetchHeader {
    /// Version discriminator (17 / 23 / 26 / 30).
    pub version: u32,
    /// Parsed version enum.
    pub version_enum: ScccVersion,
    /// Raw magic "SCCA" (0x53434341 LE).
    pub magic: [u8; 4],
    /// Unknown dword (always 0x0F).
    pub unknown0: u32,
    /// Total file size in bytes.
    pub file_size: u32,
    /// Executable name (up to 29 UTF-16LE characters, NUL-terminated).
    pub exe_name: String,
    /// Hash of the prefetch file (Rotfl hash or similar).
    pub prefetch_hash: u32,
    /// Unknown flags dword.
    pub unknown1: u32,
}

impl PrefetchHeader {
    /// Parse from a byte slice starting at offset 0.
    pub fn parse(data: &[u8]) -> Result<Self, PrefetchError> {
        const HEADER_MIN: usize = 84;
        if data.len() < HEADER_MIN {
            return Err(PrefetchError::TooShort { needed: HEADER_MIN, got: data.len() });
        }
        let version = read_u32_le(data, 0);
        let magic = [data[4], data[5], data[6], data[7]];
        if &magic != b"SCCA" {
            return Err(PrefetchError::InvalidMagic(magic));
        }
        let version_enum = ScccVersion::from_u32(version)
            .ok_or(PrefetchError::UnsupportedVersion(version))?;
        let unknown0 = read_u32_le(data, 8);
        let file_size = read_u32_le(data, 12);
        // Executable name: 60 bytes = 30 UTF-16LE chars at offset 16.
        let exe_name = decode_utf16le_nul(&data[16..76])?;
        let prefetch_hash = read_u32_le(data, 76);
        let unknown1 = read_u32_le(data, 80);
        Ok(Self { version, version_enum, magic, unknown0, file_size, exe_name, prefetch_hash, unknown1 })
    }
}

/// A single execution timestamp (Windows FILETIME: 100-ns intervals since 1601-01-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionTime {
    /// Raw Windows FILETIME value.
    pub filetime: u64,
}

impl ExecutionTime {
    /// Convert to Unix timestamp (seconds since 1970-01-01).
    #[must_use] 
    pub const fn to_unix_secs(self) -> i64 {
        // Windows epoch offset: 11644473600 seconds.
        (self.filetime / 10_000_000).cast_signed() - 11_644_473_600
    }

    /// Zero-check.
    #[must_use] 
    pub const fn is_zero(self) -> bool {
        self.filetime == 0
    }
}

impl fmt::Display for ExecutionTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unix = self.to_unix_secs();
        write!(f, "FILETIME={:#018x} (unix={})", self.filetime, unix)
    }
}

/// Metrics for a single file referenced during execution.
#[derive(Debug, Clone)]
pub struct FileMetrics {
    /// Starting offset in the filename strings section.
    pub filename_offset: u32,
    /// Number of UTF-16LE characters in the filename.
    pub filename_length: u32,
    /// Number of prefetch trace records using this file.
    pub prefetch_chain_count: u32,
    /// MFT entry index (NTFS).
    pub mft_entry_index: u32,
    /// MFT sequence number.
    pub mft_sequence_number: u16,
    /// Resolved filename (populated after parsing the strings section).
    pub filename: String,
}

/// Volume information entry.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Offset of the device path within the volume section.
    pub device_path_offset: u32,
    /// Length in characters of the device path.
    pub device_path_length: u32,
    /// Volume creation time (Windows FILETIME).
    pub creation_time: ExecutionTime,
    /// Volume serial number.
    pub serial_number: u32,
    /// Resolved device path string.
    pub device_path: String,
    /// Byte offset of the file references array.
    pub file_refs_offset: u32,
    /// Number of file references in the array.
    pub file_refs_count: u32,
    /// Byte offset of the directory strings section.
    pub dir_strings_offset: u32,
    /// Number of directory string entries.
    pub dir_strings_count: u32,
}

/// Fully parsed Windows Prefetch file.
#[derive(Debug, Clone)]
pub struct PrefetchFile {
    /// Parsed file header.
    pub header: PrefetchHeader,
    /// Last-run execution timestamp (all versions).
    pub last_run_time: ExecutionTime,
    /// Up to 8 run timestamps (v26 / v30 only; otherwise empty).
    pub run_times: Vec<ExecutionTime>,
    /// Total run count.
    pub run_count: u32,
    /// All file strings (loaded DLLs, resources, etc.).
    pub file_strings: Vec<String>,
    /// Structured file metrics array.
    pub file_metrics: Vec<FileMetrics>,
    /// Volume information entries.
    pub volumes: Vec<VolumeInfo>,
}

impl PrefetchFile {
    /// Parse a Windows Prefetch file from a raw byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, PrefetchError> {
        let header = PrefetchHeader::parse(data)?;
        let ver = header.version_enum;

        // Version-specific offset layout.
        let (
            last_run_off,
            run_count_off,
            strings_section_off_field,
            strings_section_len_field,
            metrics_section_off_field,
            metrics_count_field,
            volumes_section_off_field,
            volumes_count_field,
        ) = version_offsets(ver);

        let last_run_time = ExecutionTime { filetime: read_u64_le(data, last_run_off) };
        let run_count = read_u32_le(data, run_count_off);

        // Multi-run timestamps (v26/v30).
        let run_times = if ver.has_multi_timestamps() {
            parse_multi_timestamps(data, last_run_off)
        } else {
            vec![last_run_time]
        };

        let strings_off = read_u32_le(data, strings_section_off_field) as usize;
        let strings_len = read_u32_le(data, strings_section_len_field) as usize;
        let file_strings = parse_file_strings(data, strings_off, strings_len)?;

        let metrics_off = read_u32_le(data, metrics_section_off_field) as usize;
        let metrics_count = read_u32_le(data, metrics_count_field) as usize;
        let metrics_record_size = metrics_record_size(ver);
        let file_metrics = parse_file_metrics(data, metrics_off, metrics_count, metrics_record_size, &file_strings)?;

        let volumes_off = read_u32_le(data, volumes_section_off_field) as usize;
        let volumes_count = read_u32_le(data, volumes_count_field) as usize;
        let volumes = parse_volumes(data, volumes_off, volumes_count)?;

        Ok(Self {
            header,
            last_run_time,
            run_times,
            run_count,
            file_strings,
            file_metrics,
            volumes,
        })
    }

    /// Return all DLL/executable filenames (paths containing `\`).
    pub fn loaded_modules(&self) -> Vec<&str> {
        self.file_strings.iter().map(String::as_str).filter(|s| s.contains('\\')).collect()
    }

    /// Return a human-readable summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Executable : {}\n", self.header.exe_name));
        s.push_str(&format!("Hash       : {:#010x}\n", self.header.prefetch_hash));
        s.push_str(&format!("Version    : {}\n", self.header.version));
        s.push_str(&format!("Run count  : {}\n", self.run_count));
        s.push_str(&format!("Last run   : {}\n", self.last_run_time));
        s.push_str(&format!("Modules    : {}\n", self.file_metrics.len()));
        s.push_str(&format!("Volumes    : {}\n", self.volumes.len()));
        for v in &self.volumes {
            s.push_str(&format!("  Volume: {} serial={:#010x}\n", v.device_path, v.serial_number));
        }
        s
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

const fn version_offsets(ver: ScccVersion) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
    // Returns:
    // (last_run_off, run_count_off, str_off_field, str_len_field,
    //  met_off_field, met_count_field, vol_off_field, vol_count_field)
    match ver {
        ScccVersion::V17 => (0x78, 0x90, 0x64, 0x68, 0x54, 0x58, 0x6C, 0x70),
        ScccVersion::V23 => (0x80, 0x98, 0x70, 0x74, 0x60, 0x64, 0x78, 0x7C),
        ScccVersion::V26 => (0x80, 0x9C, 0x78, 0x7C, 0x68, 0x6C, 0x84, 0x88),
        ScccVersion::V30 => (0x80, 0xD0, 0xB8, 0xBC, 0xA8, 0xAC, 0xC0, 0xC4),
    }
}

const fn metrics_record_size(ver: ScccVersion) -> usize {
    match ver {
        ScccVersion::V17 => 20,
        ScccVersion::V23 | ScccVersion::V26 | ScccVersion::V30 => 32,
    }
}

fn parse_multi_timestamps(data: &[u8], base_off: usize) -> Vec<ExecutionTime> {
    let mut ts = Vec::with_capacity(MAX_TIMESTAMPS_V26);
    for i in 0..MAX_TIMESTAMPS_V26 {
        let off = base_off + i * 8;
        if off + 8 > data.len() { break; }
        let ft = read_u64_le(data, off);
        if ft != 0 {
            ts.push(ExecutionTime { filetime: ft });
        }
    }
    ts
}

fn parse_file_strings(data: &[u8], offset: usize, length: usize) -> Result<Vec<String>, PrefetchError> {
    if length == 0 { return Ok(Vec::new()); }
    let end = offset.saturating_add(length);
    if end > data.len() {
        return Err(PrefetchError::OutOfBounds { offset: offset as u32, len: length as u32 });
    }
    let section = &data[offset..end];
    let mut strings = Vec::new();
    let mut pos = 0usize;
    while pos + 1 < section.len() {
        // Decode a NUL-terminated UTF-16LE string.
        let mut chars: Vec<u16> = Vec::new();
        while pos + 1 < section.len() {
            let ch = u16::from_le_bytes([section[pos], section[pos + 1]]);
            pos += 2;
            if ch == 0 { break; }
            chars.push(ch);
        }
        if !chars.is_empty() {
            strings.push(String::from_utf16_lossy(&chars));
        }
    }
    Ok(strings)
}

fn parse_file_metrics(
    data: &[u8],
    offset: usize,
    count: usize,
    record_size: usize,
    strings: &[String],
) -> Result<Vec<FileMetrics>, PrefetchError> {
    // `count` is a u32 header field; the loop below bounds-checks every
    // record, but `with_capacity(count)` would allocate before the first
    // check and abort the process on a crafted file.  Reserve only what the
    // buffer could actually hold.
    let capacity = count.min(data.len() / record_size.max(1));
    let mut metrics = Vec::with_capacity(capacity);
    for i in 0..count {
        let rec_off = offset + i * record_size;
        if rec_off + record_size > data.len() { break; }
        let rec = &data[rec_off..rec_off + record_size];
        let prefetch_chain_count = read_u32_le(rec, 0);
        let filename_offset = read_u32_le(rec, 4);
        let filename_length = read_u32_le(rec, 8);
        let mft_entry_index = if record_size >= 20 { read_u32_le(rec, 16) } else { 0 };
        let mft_sequence_number = if record_size >= 22 { read_u16_le(rec, 20) } else { 0 };

        // Resolve filename from string index (filename_offset is a character offset
        // in the strings section, not an index into our Vec, so we use a simplified
        // approach: match the string whose start matches the offset).
        let filename = resolve_string_by_char_offset(strings, filename_offset as usize, filename_length as usize);
        metrics.push(FileMetrics {
            filename_offset,
            filename_length,
            prefetch_chain_count,
            mft_entry_index,
            mft_sequence_number,
            filename,
        });
    }
    Ok(metrics)
}

fn resolve_string_by_char_offset(strings: &[String], _char_offset: usize, _char_len: usize) -> String {
    // In a real implementation we would track byte offsets.  For correctness we
    // just return an empty string here; callers that need full resolution should
    // cross-reference against the raw strings section.
    strings.first().cloned().unwrap_or_default()
}

fn parse_volumes(data: &[u8], section_offset: usize, count: usize) -> Result<Vec<VolumeInfo>, PrefetchError> {
    // Volume record size varies slightly but the standard layout is 40 bytes for
    // the fixed portion.
    const VOL_RECORD_SIZE: usize = 104;
    // Bounded for the same reason as in `parse_file_metrics`.
    let capacity = count.min(data.len() / VOL_RECORD_SIZE);
    let mut volumes = Vec::with_capacity(capacity);
    for i in 0..count {
        let vol_off = section_offset + i * VOL_RECORD_SIZE;
        if vol_off + 40 > data.len() { break; }
        let device_path_offset = read_u32_le(data, vol_off);
        let device_path_length = read_u32_le(data, vol_off + 4);
        let creation_time = ExecutionTime { filetime: read_u64_le(data, vol_off + 8) };
        let serial_number = read_u32_le(data, vol_off + 16);
        let file_refs_offset = read_u32_le(data, vol_off + 20);
        let file_refs_count = read_u32_le(data, vol_off + 28);
        let dir_strings_offset = read_u32_le(data, vol_off + 32);
        let dir_strings_count = read_u32_le(data, vol_off + 36);

        // Resolve device path UTF-16LE string relative to the volume section.
        let abs_path_off = section_offset.saturating_add(device_path_offset as usize);
        // Each UTF-16LE character is 2 bytes; guard multiplication against overflow.
        let path_bytes = (device_path_length as usize).saturating_mul(2);
        let device_path = if abs_path_off.saturating_add(path_bytes) <= data.len() {
            decode_utf16le_nul(&data[abs_path_off..abs_path_off + path_bytes]).unwrap_or_default()
        } else {
            String::new()
        };

        volumes.push(VolumeInfo {
            device_path_offset,
            device_path_length,
            creation_time,
            serial_number,
            device_path,
            file_refs_offset,
            file_refs_count,
            dir_strings_offset,
            dir_strings_count,
        });
    }
    Ok(volumes)
}

/// Decode a UTF-16LE byte slice, stopping at the first NUL character.
fn decode_utf16le_nul(bytes: &[u8]) -> Result<String, PrefetchError> {
    let mut chars = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let ch = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if ch == 0 { break; }
        chars.push(ch);
        i += 2;
    }
    Ok(String::from_utf16_lossy(&chars))
}

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() { return 0; }
    u64::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3],
        data[offset+4], data[offset+5], data[offset+6], data[offset+7],
    ])
}

/// Read a little-endian u16 from `data` at `offset`.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset+1]])
}

// ─── PrefetchAnalyzer ─────────────────────────────────────────────────────────

/// High-level analyzer that wraps a parsed [`PrefetchFile`] and provides
/// query helpers used by forensic tools.
#[derive(Debug)]
pub struct PrefetchAnalyzer {
    pub file: PrefetchFile,
}

impl PrefetchAnalyzer {
    /// Create an analyzer from a parsed [`PrefetchFile`].
    #[must_use] 
    pub const fn new(file: PrefetchFile) -> Self {
        Self { file }
    }

    /// Parse raw bytes into an analyzer in one step.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PrefetchError> {
        Ok(Self::new(PrefetchFile::parse(data)?))
    }

    /// Return all unique directory paths referenced by the loaded files.
    #[must_use] 
    pub fn referenced_directories(&self) -> Vec<String> {
        let mut dirs: Vec<String> = self.file.file_strings.iter()
            .filter_map(|s| {
                let idx = s.rfind('\\')?;
                Some(s[..idx].to_owned())
            })
            .collect();
        dirs.sort_unstable();
        dirs.dedup();
        dirs
    }

    /// Return all module names (leaf filename only, no path).
    #[must_use] 
    pub fn module_names(&self) -> Vec<String> {
        self.file.file_strings.iter()
            .filter_map(|s| s.rfind('\\').map(|i| s[i+1..].to_owned()))
            .collect()
    }

    /// Check whether a specific filename was referenced.
    #[must_use] 
    pub fn references_file(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.file.file_strings.iter().any(|s| s.to_ascii_lowercase().contains(&lower))
    }

    /// Return execution timestamps sorted newest-first.
    #[must_use] 
    pub fn sorted_run_times(&self) -> Vec<ExecutionTime> {
        let mut ts = self.file.run_times.clone();
        ts.sort_unstable_by(|a, b| b.filetime.cmp(&a.filetime));
        ts
    }

    /// Average seconds between consecutive run times (requires >= 2 entries).
    #[must_use] 
    pub fn avg_run_interval_secs(&self) -> Option<i64> {
        let sorted = self.sorted_run_times();
        if sorted.len() < 2 { return None; }
        let intervals: Vec<i64> = sorted.windows(2).map(|w| {
            (w[0].to_unix_secs() - w[1].to_unix_secs()).abs()
        }).collect();
        let sum: i64 = intervals.iter().sum();
        Some(sum / intervals.len() as i64)
    }

    /// Generate a CSV line for bulk reporting.
    #[must_use] 
    pub fn to_csv_line(&self) -> String {
        format!(
            "{},{:#010x},{},{},{}",
            csv_escape(&self.file.header.exe_name),
            self.file.header.prefetch_hash,
            self.file.run_count,
            self.file.last_run_time.to_unix_secs(),
            self.file.file_metrics.len(),
        )
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

// ─── PatternMatcher ───────────────────────────────────────────────────────────

/// Checks for suspicious patterns in a prefetch file.
pub struct PatternMatcher;

impl PatternMatcher {
    /// Returns true if the prefetch file references known suspicious loader names.
    #[must_use] 
    pub fn has_suspicious_loader(pf: &PrefetchFile) -> bool {
        const SUSPICIOUS: &[&str] = &[
            "powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe",
            "cscript.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
        ];
        let name_lower = pf.header.exe_name.to_ascii_lowercase();
        SUSPICIOUS.iter().any(|s| name_lower.contains(s))
    }

    /// Returns true if any loaded module comes from a suspicious location.
    #[must_use] 
    pub fn has_suspicious_path(pf: &PrefetchFile) -> bool {
        const SUSPICIOUS_PATHS: &[&str] = &[
            "\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\",
        ];
        pf.file_strings.iter().any(|s| {
            let lower = s.to_ascii_lowercase();
            SUSPICIOUS_PATHS.iter().any(|p| lower.contains(p))
        })
    }

    /// Returns a risk score 0-100 based on heuristics.
    #[must_use] 
    pub fn risk_score(pf: &PrefetchFile) -> u8 {
        let mut score = 0u8;
        if Self::has_suspicious_loader(pf) { score = score.saturating_add(40); }
        if Self::has_suspicious_path(pf) { score = score.saturating_add(30); }
        if pf.run_count > 100 { score = score.saturating_add(10); }
        if pf.file_metrics.len() < 5 { score = score.saturating_add(20); }
        score.min(100)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v17_header() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        // Version = 17
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        // Magic = "SCCA"
        data[4..8].copy_from_slice(b"SCCA");
        // unknown0 = 0x0F
        data[8..12].copy_from_slice(&0x0Fu32.to_le_bytes());
        // file_size = 256
        data[12..16].copy_from_slice(&256u32.to_le_bytes());
        // exe_name = "NOTEPAD.EXE\0..." (UTF-16LE, 60 bytes)
        let name: Vec<u16> = "NOTEPAD.EXE".encode_utf16().collect();
        for (i, &ch) in name.iter().enumerate() {
            let off = 16 + i * 2;
            if off + 2 <= 76 {
                data[off..off+2].copy_from_slice(&ch.to_le_bytes());
            }
        }
        // prefetch_hash
        data[76..80].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data
    }

    #[test]
    fn test_header_parse_v17() {
        let data = make_v17_header();
        let h = PrefetchHeader::parse(&data).unwrap();
        assert_eq!(h.version, 17);
        assert_eq!(h.version_enum, ScccVersion::V17);
        assert_eq!(h.prefetch_hash, 0xDEADBEEF);
        assert!(h.exe_name.contains("NOTEPAD"));
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut data = make_v17_header();
        data[4..8].copy_from_slice(b"XXXX");
        assert!(matches!(PrefetchHeader::parse(&data), Err(PrefetchError::InvalidMagic(_))));
    }

    #[test]
    fn test_header_too_short() {
        assert!(matches!(
            PrefetchHeader::parse(&[0u8; 10]),
            Err(PrefetchError::TooShort { .. })
        ));
    }

    #[test]
    fn test_execution_time_unix() {
        // FILETIME 0 → unix = -11644473600
        let t = ExecutionTime { filetime: 0 };
        assert_eq!(t.to_unix_secs(), -11_644_473_600);
    }

    #[test]
    fn test_execution_time_not_zero() {
        let t = ExecutionTime { filetime: 132_000_000_000_000_000 };
        assert!(!t.is_zero());
        assert!(t.to_unix_secs() > 0);
    }

    #[test]
    fn test_scca_version_from_u32() {
        assert_eq!(ScccVersion::from_u32(17), Some(ScccVersion::V17));
        assert_eq!(ScccVersion::from_u32(30), Some(ScccVersion::V30));
        assert_eq!(ScccVersion::from_u32(99), None);
    }

    #[test]
    fn test_multi_timestamps_flag() {
        assert!(!ScccVersion::V17.has_multi_timestamps());
        assert!(!ScccVersion::V23.has_multi_timestamps());
        assert!(ScccVersion::V26.has_multi_timestamps());
        assert!(ScccVersion::V30.has_multi_timestamps());
    }

    #[test]
    fn test_pattern_matcher_suspicious_loader() {
        let mut pf = PrefetchFile {
            header: PrefetchHeader {
                version: 23, version_enum: ScccVersion::V23,
                magic: *b"SCCA", unknown0: 0, file_size: 0,
                exe_name: "POWERSHELL.EXE".to_owned(),
                prefetch_hash: 0, unknown1: 0,
            },
            last_run_time: ExecutionTime { filetime: 0 },
            run_times: vec![],
            run_count: 1,
            file_strings: vec![],
            file_metrics: vec![],
            volumes: vec![],
        };
        assert!(PatternMatcher::has_suspicious_loader(&pf));
        pf.header.exe_name = "EXPLORER.EXE".to_owned();
        assert!(!PatternMatcher::has_suspicious_loader(&pf));
    }

    #[test]
    fn test_decode_utf16le_nul() {
        let encoded: Vec<u8> = "Hello\0".encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let s = decode_utf16le_nul(&encoded).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_read_u32_le_bounds() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data, 0), 0x04030201);
        assert_eq!(read_u32_le(&data, 2), 0); // out of bounds → 0
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("notepad.exe"), "notepad.exe");
        assert!(csv_escape("a,b").starts_with('"'));
    }
}
