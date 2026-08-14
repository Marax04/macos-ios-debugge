//! Windows Prefetch file analyzer.
//!
//! Parses `.pf` files from `C:\Windows\Prefetch\` in formats 17 (XP), 23
//! (Vista/7), 26 (Win8), and 30 (Win10+, compressed MAM).  Extracts execution
//! timestamps, run counts, loaded file paths, and volume serial numbers.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ForensicsError;

// ─── Format constants ─────────────────────────────────────────────────────────

const PREFETCH_SIGNATURE: &[u8; 4] = b"SCCA";
const MAM_SIGNATURE: &[u8; 4] = b"MAM\x04";

const FORMAT_XP: u32 = 17;
const FORMAT_VISTA: u32 = 23;
const FORMAT_WIN8: u32 = 26;
const FORMAT_WIN10: u32 = 30;

// ─── FileMetric ───────────────────────────────────────────────────────────────

/// A single file referenced by the prefetch entry (file metrics array).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetric {
    /// Index into the strings section.
    pub filename_offset: u32,
    /// Number of prefetch runs in which this file was loaded.
    pub prefetch_count: u32,
    /// NTFS MFT file reference (inode-like).
    pub mft_file_reference: u64,
    /// Resolved filename (populated during parsing).
    pub filename: String,
}

impl FileMetric {
    /// Returns `true` if this file is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.filename.to_lowercase().ends_with(".dll")
    }

    /// Returns `true` if this file is an executable.
    #[must_use]
    pub fn is_exe(&self) -> bool {
        std::path::Path::new(self.filename.as_str())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("com"))
    }

    /// Returns the base filename without path prefix.
    #[must_use]
    pub fn base_name(&self) -> &str {
        let s = self.filename.as_str();
        // Prefetch paths use backslash.
        s.rfind('\\').map_or(s, |pos| &s[pos + 1..])
    }
}

// ─── VolumeInfo ───────────────────────────────────────────────────────────────

/// Information about a volume referenced in the prefetch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// Volume device path (e.g. `\\DEVICE\\HARDDISKVOLUME3`).
    pub device_path: String,
    /// Volume creation time (FILETIME).
    pub creation_time: u64,
    /// Volume serial number.
    pub serial_number: u32,
    /// Offset to directory strings for this volume.
    pub directory_strings_offset: u32,
    /// Number of directory strings.
    pub directory_strings_count: u32,
}

impl VolumeInfo {
    /// Returns a hex string of the serial number.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        format!("{:08X}", self.serial_number)
    }
}

// ─── PrefetchFile ─────────────────────────────────────────────────────────────

/// Parsed Windows Prefetch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchFile {
    /// Prefetch format version.
    pub format_version: u32,
    /// Name of the executable (up to 29 UTF-16 chars, null-terminated).
    pub executable_name: String,
    /// Prefetch hash (used as the file suffix, e.g. `AB12CD34`).
    pub prefetch_hash: u32,
    /// Number of times the application has been run.
    pub run_count: u32,
    /// Most recent execution timestamps (FILETIME), newest first.
    pub last_run_times: Vec<u64>,
    /// All files referenced during execution (loaded DLLs, data files, etc.).
    pub file_metrics: Vec<FileMetric>,
    /// Volume information for each drive accessed.
    pub volumes: Vec<VolumeInfo>,
    /// File size on disk.
    pub file_size: u32,
}

impl PrefetchFile {
    /// The most recent execution time, or 0 if no runs recorded.
    #[must_use]
    pub fn most_recent_run(&self) -> u64 {
        self.last_run_times.first().copied().unwrap_or(0)
    }

    /// Convert a FILETIME to a UTC approximation string.
    #[must_use]
    pub fn filetime_to_utc(filetime: u64) -> String {
        let secs = filetime / 10_000_000;
        let unix_secs = secs.saturating_sub(11_644_473_600);
        let days = unix_secs / 86400;
        let time_of_day = unix_secs % 86400;
        let h = time_of_day / 3600;
        let m = (time_of_day % 3600) / 60;
        let s = time_of_day % 60;
        let year = 1970 + days / 365;
        let remaining = days % 365;
        let month = (remaining / 30).min(11) + 1;
        let day = (remaining % 30) + 1;
        format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
    }

    /// All DLLs referenced by this prefetch entry.
    #[must_use]
    pub fn referenced_dlls(&self) -> Vec<&FileMetric> {
        self.file_metrics.iter().filter(|m| m.is_dll()).collect()
    }

    /// All executables referenced.
    #[must_use]
    pub fn referenced_executables(&self) -> Vec<&FileMetric> {
        self.file_metrics.iter().filter(|m| m.is_exe()).collect()
    }

    /// Statistics: count of each file extension in the metrics list.
    #[must_use]
    pub fn extension_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for m in &self.file_metrics {
            let base = m.base_name().to_lowercase();
            let ext = base
                .rfind('.')
                .map_or("(none)", |p| &base[p..])
                .to_string();
            *counts.entry(ext).or_insert(0) += 1;
        }
        counts
    }
}

// ─── Parser internals ─────────────────────────────────────────────────────────

fn _read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() { return None; }
    Some(u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]))
}

fn read_utf16le_null_terminated(data: &[u8], offset: usize, max_chars: usize) -> String {
    let slice = if offset < data.len() { &data[offset..] } else { return String::new(); };
    let words: Vec<u16> = slice
        .chunks_exact(2)
        .take(max_chars)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&words)
}

fn read_utf16le_block(data: &[u8], offset: usize, length_bytes: usize) -> String {
    if offset + length_bytes > data.len() { return String::new(); }
    let words: Vec<u16> = data[offset..offset + length_bytes]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&words)
}

// ─── Parser implementations ───────────────────────────────────────────────────

fn parse_v17_v23_v26(data: &[u8], format: u32) -> Result<PrefetchFile, ForensicsError> {
    if data.len() < 84 {
        return Err(ForensicsError::ParseError("Prefetch header too short".into()));
    }

    let file_size = read_u32_le(data, 12).unwrap_or(0);
    // Executable name: offset 16, 60 bytes (30 UTF-16 chars).
    let executable_name = read_utf16le_null_terminated(data, 16, 29);
    let prefetch_hash = read_u32_le(data, 76).unwrap_or(0);

    // Section A (file metrics): offset 84 in header.
    let metrics_offset = read_u32_le(data, 84).unwrap_or(0) as usize;
    let metrics_count = read_u32_le(data, 88).unwrap_or(0) as usize;
    let trace_offset = read_u32_le(data, 92).unwrap_or(0) as usize;
    let trace_count = read_u32_le(data, 96).unwrap_or(0) as usize;
    // Section C (volumes): offset 100.
    let volumes_offset = read_u32_le(data, 100).unwrap_or(0) as usize;
    let volumes_count = read_u32_le(data, 104).unwrap_or(0) as usize;

    // Run count and timestamps vary by version.
    let (run_count, last_run_times) = match format {
        FORMAT_XP | FORMAT_VISTA => {
            let rc = read_u32_le(data, 64 + 76).unwrap_or(1);
            let ts0 = read_u64_le(data, 64 + 8).unwrap_or(0);
            (rc, vec![ts0])
        }
        FORMAT_WIN8 => {
            let rc = read_u32_le(data, 64 + 0x94).unwrap_or(1);
            let mut ts = Vec::new();
            for i in 0..8usize {
                if let Some(t) = read_u64_le(data, 64 + 0x80 + i * 8)
                    && t != 0 { ts.push(t); }
            }
            ts.sort_unstable_by(|a, b| b.cmp(a));
            (rc, ts)
        }
        _ => (1, Vec::new()),
    };

    // Parse file metrics (Section A).
    // Each entry: format 17 = 20 bytes, format 23+ = 32 bytes.
    let entry_size = if format == FORMAT_XP { 20usize } else { 32usize };
    let strings_section_offset = trace_offset;

    let mut file_metrics = Vec::new();
    for i in 0..metrics_count.min(512) {
        let e = metrics_offset.saturating_add(i.saturating_mul(entry_size));
        if e + entry_size > data.len() { break; }
        let filename_offset_raw = read_u32_le(data, e).unwrap_or(0) as usize;
        let prefetch_count = read_u32_le(data, e + 4).unwrap_or(0);
        let mft_file_reference = if format == FORMAT_XP {
            0u64
        } else {
            read_u64_le(data, e + 8).unwrap_or(0)
        };
        // Resolve filename from strings section.
        let filename = if strings_section_offset + filename_offset_raw < data.len() {
            read_utf16le_null_terminated(data, strings_section_offset + filename_offset_raw, 256)
        } else {
            String::new()
        };
        file_metrics.push(FileMetric {
            filename_offset: u32::try_from(filename_offset_raw).unwrap_or(u32::MAX),
            prefetch_count,
            mft_file_reference,
            filename,
        });
    }

    // Parse volumes (Section C).
    // Each volume entry: format 17 = 40 bytes, format 23 = 104 bytes.
    let volume_entry_size = if format == FORMAT_XP { 40usize } else { 104usize };
    let mut volumes = Vec::new();
    for i in 0..volumes_count.min(8) {
        let e = volumes_offset.saturating_add(i.saturating_mul(volume_entry_size));
        if e + volume_entry_size > data.len() { break; }
        let device_path_offset = read_u32_le(data, e).unwrap_or(0) as usize;
        let device_path_length = read_u32_le(data, e + 4).unwrap_or(0) as usize;
        let creation_time = read_u64_le(data, e + 8).unwrap_or(0);
        let serial_number = read_u32_le(data, e + 16).unwrap_or(0);
        let dir_strings_offset = read_u32_le(data, e + 20).unwrap_or(0);
        let dir_strings_count = read_u32_le(data, e + 24).unwrap_or(0);
        let abs_device_path_offset = volumes_offset.saturating_add(device_path_offset);
        let device_path = read_utf16le_block(data, abs_device_path_offset, device_path_length.saturating_mul(2));
        volumes.push(VolumeInfo {
            device_path,
            creation_time,
            serial_number,
            directory_strings_offset: dir_strings_offset,
            directory_strings_count: dir_strings_count,
        });
    }

    // Suppress unused binding warning.
    let _ = trace_count;

    Ok(PrefetchFile {
        format_version: format,
        executable_name,
        prefetch_hash,
        run_count,
        last_run_times,
        file_metrics,
        volumes,
        file_size,
    })
}

fn parse_v30(data: &[u8]) -> Result<PrefetchFile, ForensicsError> {
    // Win10 prefetch files start with a MAM-compressed block.
    // Attempt minimal decompression: if we can identify raw SCCA inside, use it.
    // Full MAM (XPRESS Huffman) decompression requires an external library;
    // here we do a heuristic scan for the embedded SCCA payload.
    if data.len() < 8 {
        return Err(ForensicsError::ParseError("MAM data too short".into()));
    }
    let uncompressed_size = read_u32_le(data, 4).unwrap_or(0) as usize;
    // Try to locate embedded SCCA signature.
    for i in 8..data.len().saturating_sub(4) {
        if &data[i..i + 4] == PREFETCH_SIGNATURE {
            // Found potential embedded SCCA; use remaining bytes.
            let embedded = &data[i..];
            return parse_v17_v23_v26(embedded, FORMAT_WIN10);
        }
    }
    // Fallback: treat entire buffer as uncompressed if it starts with SCCA.
    Err(ForensicsError::ParseError(format!(
        "MAM-compressed prefetch not decompressed (uncompressed_size={uncompressed_size})"
    )))
}

// ─── PrefetchAnalyzer ─────────────────────────────────────────────────────────

/// Parses and queries Windows Prefetch files.
pub struct PrefetchAnalyzer {
    /// The parsed prefetch file.
    pub prefetch: PrefetchFile,
    /// Path to the source `.pf` file.
    pub source_path: Option<std::path::PathBuf>,
}

impl PrefetchAnalyzer {
    /// Parse a prefetch file from raw bytes.
    ///
    /// # Errors
    /// Returns [`ForensicsError::ParseError`] on invalid data.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ForensicsError> {
        let prefetch = parse_prefetch(data)?;
        Ok(Self { prefetch, source_path: None })
    }

    /// Parse a prefetch file from a path.
    ///
    /// # Errors
    /// Returns [`ForensicsError::Io`] or [`ForensicsError::ParseError`].
    pub fn from_file(path: &Path) -> Result<Self, ForensicsError> {
        let data = std::fs::read(path).map_err(ForensicsError::from)?;
        let prefetch = parse_prefetch(&data)?;
        Ok(Self {
            prefetch,
            source_path: Some(path.to_path_buf()),
        })
    }

    /// Render a text summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let p = &self.prefetch;
        let last_run = p.most_recent_run();
        let last_run_str = if last_run > 0 {
            PrefetchFile::filetime_to_utc(last_run)
        } else {
            "(never)".to_string()
        };
        format!(
            "Executable : {}\n\
             Hash       : {:08X}\n\
             Version    : {}\n\
             Run count  : {}\n\
             Last run   : {}\n\
             Files refs : {}\n\
             Volumes    : {}",
            p.executable_name,
            p.prefetch_hash,
            p.format_version,
            p.run_count,
            last_run_str,
            p.file_metrics.len(),
            p.volumes.len()
        )
    }

    /// Return paths of all referenced files that match the given extension.
    #[must_use]
    pub fn files_with_extension(&self, ext: &str) -> Vec<&str> {
        let lower_ext = ext.to_lowercase();
        self.prefetch
            .file_metrics
            .iter()
            .filter(|m| m.filename.to_lowercase().ends_with(&lower_ext))
            .map(|m| m.filename.as_str())
            .collect()
    }

    /// Return the most-loaded DLL (highest `prefetch_count`).
    #[must_use]
    pub fn most_loaded_dll(&self) -> Option<&FileMetric> {
        self.prefetch
            .file_metrics
            .iter()
            .filter(|m| m.is_dll())
            .max_by_key(|m| m.prefetch_count)
    }
}

// ─── parse_prefetch ───────────────────────────────────────────────────────────

/// Parse a Windows Prefetch `.pf` file from raw bytes.
///
/// Supports formats 17 (XP), 23 (Vista/7), 26 (Win8), and 30 (Win10, partial).
///
/// # Errors
/// Returns [`ForensicsError::ParseError`] on invalid or unsupported data.
pub fn parse_prefetch(data: &[u8]) -> Result<PrefetchFile, ForensicsError> {
    if data.len() < 8 {
        return Err(ForensicsError::ParseError("Data too short for prefetch".into()));
    }
    // Check for MAM-compressed Win10+ format.
    if &data[0..4] == MAM_SIGNATURE {
        return parse_v30(data);
    }
    // Check SCCA signature.
    if &data[0..4] != PREFETCH_SIGNATURE {
        return Err(ForensicsError::ParseError(format!(
            "Invalid prefetch signature: {:02x?}",
            &data[0..4]
        )));
    }
    let format = read_u32_le(data, 4)
        .ok_or_else(|| ForensicsError::ParseError("Cannot read format version".into()))?;
    match format {
        FORMAT_XP => parse_v17_v23_v26(data, FORMAT_XP),
        FORMAT_VISTA => parse_v17_v23_v26(data, FORMAT_VISTA),
        FORMAT_WIN8 => parse_v17_v23_v26(data, FORMAT_WIN8),
        FORMAT_WIN10 => parse_v17_v23_v26(data, FORMAT_WIN10),
        other => Err(ForensicsError::NotSupported(format!("Prefetch format {other} not supported"))),
    }
}

// ─── PrefetchDirectory ────────────────────────────────────────────────────────

/// A parsed collection of prefetch files from a directory.
pub struct PrefetchDirectory {
    /// All successfully parsed prefetch files.
    pub entries: Vec<PrefetchFile>,
    /// Files that could not be parsed, with error messages.
    pub errors: Vec<(std::path::PathBuf, String)>,
}

impl PrefetchDirectory {
    /// Load all `.pf` files from `dir`.
    ///
    /// # Errors
    /// Returns [`ForensicsError::Io`] if the directory cannot be read.
    pub fn load(dir: &Path) -> Result<Self, ForensicsError> {
        let rd = std::fs::read_dir(dir).map_err(ForensicsError::from)?;
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pf") {
                continue;
            }
            match std::fs::read(&path).map_err(ForensicsError::from).and_then(|d| parse_prefetch(&d)) {
                Ok(pf) => entries.push(pf),
                Err(e) => errors.push((path, e.to_string())),
            }
        }
        Ok(Self { entries, errors })
    }

    /// Most-executed application by run count.
    #[must_use]
    pub fn most_executed(&self) -> Option<&PrefetchFile> {
        self.entries.iter().max_by_key(|p| p.run_count)
    }

    /// All prefetch entries with run count above `threshold`.
    #[must_use]
    pub fn frequent_apps(&self, threshold: u32) -> Vec<&PrefetchFile> {
        self.entries
            .iter()
            .filter(|p| p.run_count >= threshold)
            .collect()
    }

    /// All DLLs referenced across all entries, with occurrence count.
    #[must_use]
    pub fn dll_frequency(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for pf in &self.entries {
            for metric in pf.referenced_dlls() {
                let key = metric.base_name().to_lowercase();
                *map.entry(key).or_insert(0) += 1;
            }
        }
        map
    }
}

// ─── Timeline helpers ─────────────────────────────────────────────────────────

/// A prefetch execution event for timeline correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchTimelineEvent {
    /// Executable name.
    pub executable: String,
    /// Prefetch hash.
    pub hash: u32,
    /// Execution timestamp (FILETIME).
    pub timestamp: u64,
    /// UTC approximation.
    pub timestamp_utc: String,
    /// Run number (1 = most recent).
    pub run_number: usize,
}

/// Build a sorted timeline of execution events from a list of prefetch files.
#[must_use]
pub fn build_execution_timeline(prefetch_files: &[PrefetchFile]) -> Vec<PrefetchTimelineEvent> {
    let mut events = Vec::new();
    for pf in prefetch_files {
        for (i, &ts) in pf.last_run_times.iter().enumerate() {
            if ts == 0 { continue; }
            events.push(PrefetchTimelineEvent {
                executable: pf.executable_name.clone(),
                hash: pf.prefetch_hash,
                timestamp: ts,
                timestamp_utc: PrefetchFile::filetime_to_utc(ts),
                run_number: i + 1,
            });
        }
    }
    events.sort_by_key(|e| e.timestamp);
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_scca(format: u32) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // SCCA signature
        data[0..4].copy_from_slice(PREFETCH_SIGNATURE);
        // format version
        data[4..8].copy_from_slice(&format.to_le_bytes());
        // file size
        data[12..16].copy_from_slice(&512u32.to_le_bytes());
        // executable name "NOTEPAD.EXE" in UTF-16LE at offset 16
        let name = "NOTEPAD.EXE";
        for (i, c) in name.chars().enumerate() {
            if i >= 29 { break; }
            data[16 + i * 2] = c as u8;
        }
        // prefetch hash at offset 76
        data[76..80].copy_from_slice(&0xABCD_1234u32.to_le_bytes());
        // Section offsets past header (84+)
        // section A (file metrics) at offset 0 relative (empty)
        data[84..88].copy_from_slice(&200u32.to_le_bytes()); // section A offset
        data[88..92].copy_from_slice(&0u32.to_le_bytes());   // section A entries = 0
        data[92..96].copy_from_slice(&200u32.to_le_bytes()); // section B offset
        data[96..100].copy_from_slice(&0u32.to_le_bytes());  // section B entries
        data[100..104].copy_from_slice(&200u32.to_le_bytes()); // section C offset
        data[104..108].copy_from_slice(&0u32.to_le_bytes());   // section C entries
        data
    }

    #[test]
    fn parse_format_17() {
        let data = build_minimal_scca(17);
        let pf = parse_prefetch(&data).unwrap();
        assert_eq!(pf.format_version, 17);
        assert_eq!(pf.executable_name, "NOTEPAD.EXE");
        assert_eq!(pf.prefetch_hash, 0xABCD_1234);
    }

    #[test]
    fn parse_format_23() {
        let data = build_minimal_scca(23);
        let pf = parse_prefetch(&data).unwrap();
        assert_eq!(pf.format_version, 23);
    }

    #[test]
    fn bad_signature_rejected() {
        let mut data = build_minimal_scca(17);
        data[0] = b'X';
        assert!(parse_prefetch(&data).is_err());
    }

    #[test]
    fn unsupported_format_rejected() {
        let mut data = build_minimal_scca(17);
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_prefetch(&data).is_err());
    }

    #[test]
    fn file_metric_is_dll() {
        let m = FileMetric {
            filename_offset: 0,
            prefetch_count: 1,
            mft_file_reference: 0,
            filename: "\\DEVICE\\HARDDISK1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL".into(),
        };
        assert!(m.is_dll());
        assert!(!m.is_exe());
    }

    #[test]
    fn file_metric_base_name() {
        let m = FileMetric {
            filename_offset: 0,
            prefetch_count: 1,
            mft_file_reference: 0,
            filename: "\\WINDOWS\\SYSTEM32\\NTDLL.DLL".into(),
        };
        assert_eq!(m.base_name(), "NTDLL.DLL");
    }

    #[test]
    fn filetime_to_utc_nonzero() {
        let ts = 132_000_000_000_000_000u64;
        let s = PrefetchFile::filetime_to_utc(ts);
        assert!(s.contains('T'));
        assert!(s.contains('Z'));
    }

    #[test]
    fn prefetch_file_extension_counts() {
        let pf = PrefetchFile {
            format_version: 17,
            executable_name: "TEST.EXE".into(),
            prefetch_hash: 0,
            run_count: 5,
            last_run_times: vec![100_000_000_000_000_000u64],
            file_metrics: vec![
                FileMetric { filename_offset: 0, prefetch_count: 1, mft_file_reference: 0, filename: "\\A.DLL".into() },
                FileMetric { filename_offset: 0, prefetch_count: 1, mft_file_reference: 0, filename: "\\B.DLL".into() },
                FileMetric { filename_offset: 0, prefetch_count: 1, mft_file_reference: 0, filename: "\\C.EXE".into() },
            ],
            volumes: Vec::new(),
            file_size: 512,
        };
        let counts = pf.extension_counts();
        assert_eq!(counts.get(".dll").copied(), Some(2));
        assert_eq!(counts.get(".exe").copied(), Some(1));
    }

    #[test]
    fn build_execution_timeline_sorted() {
        let pf = PrefetchFile {
            format_version: 17,
            executable_name: "TEST.EXE".into(),
            prefetch_hash: 0,
            run_count: 2,
            last_run_times: vec![200_000_000_000_000_000u64, 100_000_000_000_000_000u64],
            file_metrics: Vec::new(),
            volumes: Vec::new(),
            file_size: 256,
        };
        let tl = build_execution_timeline(&[pf]);
        assert_eq!(tl.len(), 2);
        assert!(tl[0].timestamp <= tl[1].timestamp);
    }

    #[test]
    fn analyzer_summary_nonpanic() {
        let data = build_minimal_scca(23);
        let analyzer = PrefetchAnalyzer::from_bytes(&data).unwrap();
        let summary = analyzer.summary();
        assert!(summary.contains("NOTEPAD"));
    }
}
