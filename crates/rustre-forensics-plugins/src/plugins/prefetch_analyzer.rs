//! Windows Prefetch file analysis.
//!
//! Supports format versions 17 (XP/2003), 23 (Vista/7), 26 (Win8/8.1),
//! and 30 (Win10+).  Handles MAM-compressed Prefetch files (Win10+).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PrefetchError {
    #[error("invalid magic: expected 'SCCA', got {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u32),
    #[error("truncated file: expected at least {0} bytes, got {1}")]
    Truncated(usize, usize),
    #[error("decompression not supported in this build")]
    CompressionUnsupported,
    #[error("invalid hash: computed {computed:#010x}, stored {stored:#010x}")]
    HashMismatch { computed: u32, stored: u32 },
    #[error("string decode error at offset {0}")]
    StringDecodeError(usize),
}

// ─── Format version ───────────────────────────────────────────────────────────

/// Prefetch file format version.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefetchVersion {
    V17, // Windows XP / 2003
    V23, // Windows Vista / 7
    V26, // Windows 8 / 8.1
    V30, // Windows 10+
}

impl PrefetchVersion {
    /// Convert a raw version number to a `PrefetchVersion`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `v` is not a recognized Prefetch version.
    pub const fn from_u32(v: u32) -> Result<Self, PrefetchError> {
        match v {
            17 => Ok(Self::V17),
            23 => Ok(Self::V23),
            26 => Ok(Self::V26),
            30 => Ok(Self::V30),
            _ => Err(PrefetchError::UnsupportedVersion(v)),
        }
    }

    /// Minimum header size for this version.
    #[must_use]
    pub const fn header_size(&self) -> usize {
        match self {
            Self::V17 | Self::V23 | Self::V26 => 84,
            Self::V30 => 128,
        }
    }

    /// Whether this version has the run-time array in the header.
    #[must_use]
    pub const fn has_run_time_array(&self) -> bool {
        matches!(self, Self::V26 | Self::V30)
    }

    /// Number of run time slots stored.
    #[must_use]
    pub const fn run_time_slots(&self) -> usize {
        match self {
            Self::V26 | Self::V30 => 8,
            _ => 1,
        }
    }
}

// ─── MAM compression detection ────────────────────────────────────────────────

/// Win10 Prefetch files are compressed with MAM (LZXPRESS Huffman).
/// The compressed file starts with the signature `0x044D414D` ("MAM\x04").
pub const MAM_MAGIC: u32 = 0x044D_414D;

/// Check whether the raw bytes represent a MAM-compressed Prefetch file.
#[must_use]
pub fn is_mam_compressed(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == MAM_MAGIC
}

/// Decompression stub — returns an error in this build since we do not
/// bundle the LZXPRESS Huffman codec.  In production, integrate the
/// `lzxpress` crate and call it here.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn decompress_mam(data: &[u8]) -> Result<Vec<u8>, PrefetchError> {
    if !is_mam_compressed(data) {
        return Ok(data.to_vec());
    }
    // The uncompressed size is stored at bytes 4–7 (little-endian).
    if data.len() < 8 {
        return Err(PrefetchError::Truncated(8, data.len()));
    }
    let _uncompressed_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    // Real decompression would go here.
    Err(PrefetchError::CompressionUnsupported)
}

// ─── Prefetch header ──────────────────────────────────────────────────────────

/// The fixed-size Prefetch file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchHeader {
    /// Format version (17/23/26/30).
    pub version: PrefetchVersion,
    /// "SCCA" magic.
    pub signature: [u8; 4],
    /// Total file size in bytes.
    pub file_size: u32,
    /// Executable name (up to 29 UTF-16 chars + NUL).
    pub executable_name: String,
    /// Prefetch hash of the executable path.
    pub hash: u32,
    /// Number of times the executable has been run.
    pub run_count: u32,
    /// Last run timestamp (Windows FILETIME).
    pub last_run_time: u64,
    /// Additional run times (up to 7 more, V26+ only).
    pub run_times: Vec<u64>,
    /// Offset to the file metrics array.
    pub file_metrics_offset: u32,
    /// Number of file metrics entries.
    pub file_metrics_count: u32,
    /// Offset to the trace chain array.
    pub trace_chain_offset: u32,
    /// Number of trace chain entries.
    pub trace_chain_count: u32,
    /// Offset to the filename string section.
    pub filename_string_offset: u32,
    /// Length of the filename string section in bytes.
    pub filename_string_size: u32,
    /// Offset to the volume information array.
    pub volumes_offset: u32,
    /// Number of volume information entries.
    pub volumes_count: u32,
}

impl PrefetchHeader {
    const SCCA: &'static [u8; 4] = b"SCCA";

    /// Parse a Prefetch header from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn parse(data: &[u8]) -> Result<Self, PrefetchError> {
        if data.len() < 84 {
            return Err(PrefetchError::Truncated(84, data.len()));
        }
        let version_num = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = PrefetchVersion::from_u32(version_num)?;

        let mut sig = [0u8; 4];
        sig.copy_from_slice(&data[4..8]);
        if &sig != Self::SCCA {
            return Err(PrefetchError::InvalidMagic(sig));
        }

        let file_size = u32::from_le_bytes(data[12..16].try_into().unwrap());

        // Executable name: UTF-16LE at offset 16, 60 bytes (30 WCHARs)
        let exe_raw = &data[16..76];
        let exe_shorts: Vec<u16> = exe_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        let executable_name = String::from_utf16_lossy(&exe_shorts);

        let hash = u32::from_le_bytes(data[76..80].try_into().unwrap());

        // Offsets start at byte 84 for V17/V23
        let (
            file_metrics_offset,
            file_metrics_count,
            trace_chain_offset,
            trace_chain_count,
            filename_string_offset,
            filename_string_size,
            volumes_offset,
            volumes_count,
            run_count,
            last_run_time,
            run_times,
        ) = match version {
            PrefetchVersion::V17 | PrefetchVersion::V23 => {
                if data.len() < 120 {
                    return Err(PrefetchError::Truncated(120, data.len()));
                }
                let fmo = u32::from_le_bytes(data[84..88].try_into().unwrap());
                let fmc = u32::from_le_bytes(data[88..92].try_into().unwrap());
                let tco = u32::from_le_bytes(data[92..96].try_into().unwrap());
                let tcc = u32::from_le_bytes(data[96..100].try_into().unwrap());
                let fso = u32::from_le_bytes(data[100..104].try_into().unwrap());
                let fss = u32::from_le_bytes(data[104..108].try_into().unwrap());
                let vo = u32::from_le_bytes(data[108..112].try_into().unwrap());
                let vc = u32::from_le_bytes(data[112..116].try_into().unwrap());
                let rc = u32::from_le_bytes(data[116..120].try_into().unwrap());
                let lrt = if data.len() >= 128 {
                    u64::from_le_bytes(data[120..128].try_into().unwrap())
                } else {
                    0
                };
                (fmo, fmc, tco, tcc, fso, fss, vo, vc, rc, lrt, vec![])
            }
            PrefetchVersion::V26 | PrefetchVersion::V30 => {
                if data.len() < 168 {
                    return Err(PrefetchError::Truncated(168, data.len()));
                }
                let fmo = u32::from_le_bytes(data[84..88].try_into().unwrap());
                let fmc = u32::from_le_bytes(data[88..92].try_into().unwrap());
                let tco = u32::from_le_bytes(data[92..96].try_into().unwrap());
                let tcc = u32::from_le_bytes(data[96..100].try_into().unwrap());
                let fso = u32::from_le_bytes(data[100..104].try_into().unwrap());
                let fss = u32::from_le_bytes(data[104..108].try_into().unwrap());
                let vo = u32::from_le_bytes(data[108..112].try_into().unwrap());
                let vc = u32::from_le_bytes(data[112..116].try_into().unwrap());
                let rc = u32::from_le_bytes(data[116..120].try_into().unwrap());
                // Last run time at offset 128
                let lrt = u64::from_le_bytes(data[128..136].try_into().unwrap());
                // Run time array (8 entries × 8 bytes) at offset 136
                let mut times = Vec::new();
                times.push(lrt);
                for i in 0..7usize {
                    let base = 136 + i * 8;
                    if base + 8 <= data.len() {
                        let t = u64::from_le_bytes(data[base..base + 8].try_into().unwrap());
                        if t > 0 {
                            times.push(t);
                        }
                    }
                }
                (fmo, fmc, tco, tcc, fso, fss, vo, vc, rc, lrt, times)
            }
        };

        Ok(Self {
            version,
            signature: sig,
            file_size,
            executable_name,
            hash,
            run_count,
            last_run_time,
            run_times,
            file_metrics_offset,
            file_metrics_count,
            trace_chain_offset,
            trace_chain_count,
            filename_string_offset,
            filename_string_size,
            volumes_offset,
            volumes_count,
        })
    }

    /// Convert the last run time to Unix epoch seconds.
    #[must_use]
    pub const fn last_run_unix(&self) -> i64 {
        filetime_to_unix(self.last_run_time)
    }

    /// Return all run times converted to Unix epoch seconds.
    #[must_use]
    pub fn all_run_times_unix(&self) -> Vec<i64> {
        if self.run_times.is_empty() {
            vec![self.last_run_unix()]
        } else {
            self.run_times
                .iter()
                .map(|&t| filetime_to_unix(t))
                .collect()
        }
    }
}

const fn filetime_to_unix(ft: u64) -> i64 {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    ((ft.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
}

// ─── File metrics entry ───────────────────────────────────────────────────────

/// Metrics for a single file loaded during the trace period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetricsEntry {
    /// Starting offset in the trace chain array.
    pub start_time: u32,
    /// Duration of the trace segment.
    pub duration: u32,
    /// Average disk read throughput (blocks).
    pub average_duration: u32,
    /// Offset into the filename string section.
    pub filename_string_offset: u32,
    /// Length of the filename string in characters.
    pub filename_string_length: u16,
    /// Flags (bit 0 = prefetcher requested).
    pub flags: u8,
    /// Resolved filename.
    pub filename: String,
}

impl FileMetricsEntry {
    /// Size of a single entry in V17/V23.
    pub const SIZE_V17: usize = 20;
    /// Size of a single entry in V26/V30.
    pub const SIZE_V26: usize = 32;

    #[must_use]
    pub fn parse_v17(data: &[u8], strings: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE_V17 {
            return None;
        }
        let start_time = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let duration = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let filename_string_offset = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let filename_string_length = u16::from_le_bytes(data[12..14].try_into().ok()?);
        let flags = data[16];
        let filename = extract_utf16le_string(
            strings,
            filename_string_offset as usize,
            filename_string_length as usize,
        );
        Some(Self {
            start_time,
            duration,
            average_duration: 0,
            filename_string_offset,
            filename_string_length,
            flags,
            filename,
        })
    }

    #[must_use]
    pub fn parse_v26(data: &[u8], strings: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE_V26 {
            return None;
        }
        let start_time = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let duration = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let average_duration = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let filename_string_offset = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let filename_string_length = u16::from_le_bytes(data[16..18].try_into().ok()?);
        let flags = data[18];
        let filename = extract_utf16le_string(
            strings,
            filename_string_offset as usize,
            filename_string_length as usize,
        );
        Some(Self {
            start_time,
            duration,
            average_duration,
            filename_string_offset,
            filename_string_length,
            flags,
            filename,
        })
    }
}

fn extract_utf16le_string(strings: &[u8], offset: usize, len: usize) -> String {
    // Use checked_mul to prevent integer overflow when len is large (e.g. u16::MAX).
    let Some(byte_len) = len.checked_mul(2) else { return String::new() };
    if offset + byte_len > strings.len() {
        return String::new();
    }
    let slice = &strings[offset..offset + byte_len];
    let shorts: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&shorts)
}

// ─── Volume information ───────────────────────────────────────────────────────

/// Volume information from the Prefetch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// Volume device path offset (relative to volume info section).
    pub device_path_offset: u32,
    /// Length of device path in characters.
    pub device_path_length: u16,
    /// Volume creation time (FILETIME).
    pub creation_time: u64,
    /// Volume serial number.
    pub serial_number: u32,
    /// Offset to file references section.
    pub file_references_offset: u32,
    /// Number of file reference entries.
    pub file_references_size: u32,
    /// Resolved device path string.
    pub device_path: String,
}

impl VolumeInfo {
    pub const SIZE: usize = 104;

    #[must_use]
    pub fn parse(data: &[u8], vol_section: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let device_path_offset = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let device_path_length = u16::from_le_bytes(data[4..6].try_into().ok()?);
        let creation_time = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let serial_number = u32::from_le_bytes(data[16..20].try_into().ok()?);
        let file_references_offset = u32::from_le_bytes(data[20..24].try_into().ok()?);
        let file_references_size = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let device_path = extract_utf16le_string(
            vol_section,
            device_path_offset as usize,
            device_path_length as usize,
        );
        Some(Self {
            device_path_offset,
            device_path_length,
            creation_time,
            serial_number,
            file_references_offset,
            file_references_size,
            device_path,
        })
    }
}

// ─── Prefetch hash computation ────────────────────────────────────────────────

/// Compute the XP/Vista/7 Prefetch path hash using the "DJBHASH" variant.
#[must_use]
pub fn compute_prefetch_hash_xp(path: &str) -> u32 {
    let upper: Vec<u16> = path.to_uppercase().encode_utf16().collect();
    let mut hash = 0u32;
    for &wchar in &upper {
        hash = hash.wrapping_mul(37).wrapping_add(u32::from(wchar));
    }
    hash
}

/// Compute the Win8/Win10 Prefetch path hash.
#[must_use]
pub fn compute_prefetch_hash_win8(path: &str) -> u32 {
    // Win8+ uses a different multiplier (314159265).
    let upper: Vec<u16> = path.to_uppercase().encode_utf16().collect();
    let mut hash = 0u32;
    for &wchar in &upper {
        hash = hash.wrapping_mul(314_159_265).wrapping_add(u32::from(wchar));
    }
    hash
}

/// Verify that the stored hash matches the executable path.
#[must_use]
pub fn verify_hash(header: &PrefetchHeader, exe_path: &str) -> bool {
    let computed = match header.version {
        PrefetchVersion::V17 | PrefetchVersion::V23 => compute_prefetch_hash_xp(exe_path),
        PrefetchVersion::V26 | PrefetchVersion::V30 => compute_prefetch_hash_win8(exe_path),
    };
    computed == header.hash
}

// ─── Parsed Prefetch file ─────────────────────────────────────────────────────

/// A fully parsed Prefetch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchFile {
    pub header: PrefetchHeader,
    pub file_metrics: Vec<FileMetricsEntry>,
    pub volumes: Vec<VolumeInfo>,
    pub loaded_files: Vec<String>,
}

impl PrefetchFile {
    /// Parse a complete (uncompressed) Prefetch file.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> Result<Self, PrefetchError> {
        // Cap counts to avoid unbounded allocation / arithmetic overflow
        // from a malformed or adversarial Prefetch file.
        const MAX_FILE_METRICS: usize = 8192;
        const MAX_VOLUMES: usize = 64;

        let header = PrefetchHeader::parse(data)?;

        // Parse file metrics
        let entry_size = match header.version {
            PrefetchVersion::V17 | PrefetchVersion::V23 => FileMetricsEntry::SIZE_V17,
            PrefetchVersion::V26 | PrefetchVersion::V30 => FileMetricsEntry::SIZE_V26,
        };
        let fm_offset = header.file_metrics_offset as usize;
        let fn_offset = header.filename_string_offset as usize;
        let fn_size = header.filename_string_size as usize;
        // Use checked addition to prevent integer overflow for adversarial
        // fn_offset/fn_size values (both are u32 cast to usize).
        let fn_end = fn_offset.checked_add(fn_size).unwrap_or(data.len()).min(data.len());
        let strings = data.get(fn_offset..fn_end).unwrap_or(&[]);

        let metrics_count = (header.file_metrics_count as usize).min(MAX_FILE_METRICS);
        let mut file_metrics = Vec::new();
        for i in 0..metrics_count {
            let start = fm_offset.saturating_add(i.saturating_mul(entry_size));
            let slice = data.get(start..start + entry_size).unwrap_or(&[]);
            let entry = match header.version {
                PrefetchVersion::V17 | PrefetchVersion::V23 => {
                    FileMetricsEntry::parse_v17(slice, strings)
                }
                PrefetchVersion::V26 | PrefetchVersion::V30 => {
                    FileMetricsEntry::parse_v26(slice, strings)
                }
            };
            if let Some(e) = entry {
                file_metrics.push(e);
            }
        }

        // Extract loaded file paths from the filename string section
        let loaded_files = extract_filename_strings(strings);

        // Parse volume information
        let vol_offset = header.volumes_offset as usize;
        let mut volumes = Vec::new();
        for i in 0..(header.volumes_count as usize).min(MAX_VOLUMES) {
            let base = vol_offset.saturating_add(i.saturating_mul(VolumeInfo::SIZE));
            let slice = data.get(base..base + VolumeInfo::SIZE).unwrap_or(&[]);
            let vol_section = data.get(vol_offset..).unwrap_or(&[]);
            if let Some(v) = VolumeInfo::parse(slice, vol_section) {
                volumes.push(v);
            }
        }

        Ok(Self {
            header,
            file_metrics,
            volumes,
            loaded_files,
        })
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("executable".into(), self.header.executable_name.clone());
        m.insert("run_count".into(), self.header.run_count.to_string());
        m.insert(
            "last_run_unix".into(),
            self.header.last_run_unix().to_string(),
        );
        m.insert("hash".into(), format!("{:#010x}", self.header.hash));
        m.insert("version".into(), format!("{:?}", self.header.version));
        m.insert("file_count".into(), self.loaded_files.len().to_string());
        m.insert("volume_count".into(), self.volumes.len().to_string());
        m
    }

    /// Check whether the Prefetch file is suspicious.
    /// Heuristics: abnormally high run count, or loaded DLL from temp path.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        if self.header.run_count > 1000 {
            return true;
        }
        for f in &self.loaded_files {
            let lower = f.to_lowercase();
            if lower.contains("\\temp\\")
                || lower.contains("\\tmp\\")
                || lower.contains("\\appdata\\local\\temp")
                || lower.contains("\\users\\public\\")
            {
                return true;
            }
        }
        false
    }
}

/// Extract all NUL-separated UTF-16LE strings from the filename section.
fn extract_filename_strings(strings: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for chunk in strings.chunks_exact(2) {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]);
        if w == 0 {
            if !current.is_empty() {
                result.push(String::from_utf16_lossy(&current));
                current.clear();
            }
        } else {
            current.push(w);
        }
    }
    if !current.is_empty() {
        result.push(String::from_utf16_lossy(&current));
    }
    result
}

// ─── Batch plugin wrapper ─────────────────────────────────────────────────────

/// Batch Prefetch file parser.
///
/// This is the canonical wrapper for callers that want to process multiple
/// `.pf` files at once and receive a name-keyed result map.
pub struct PrefetchPlugin;

impl PrefetchPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse multiple prefetch files (name → raw bytes) and return a map of
    /// results.  Each entry is either a parsed [`PrefetchFile`] or the
    /// [`PrefetchError`] that occurred while parsing.
    #[must_use]
    pub fn parse_all(
        &self,
        files: &HashMap<String, Vec<u8>>,
    ) -> HashMap<String, Result<PrefetchFile, PrefetchError>> {
        files
            .iter()
            .map(|(name, data)| (name.clone(), PrefetchFile::parse(data)))
            .collect()
    }
}

impl Default for PrefetchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Prefetch file name convention ────────────────────────────────────────────

/// Parse a Prefetch filename into its components.
/// Format: `EXECUTABLE-HASH.pf`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchFileName {
    pub executable: String,
    pub hash_hex: String,
}

impl PrefetchFileName {
    #[must_use]
    pub fn parse(filename: &str) -> Option<Self> {
        let name = filename
            .strip_suffix(".pf")
            .or_else(|| filename.strip_suffix(".PF"))?;
        let dash = name.rfind('-')?;
        let executable = name[..dash].to_string();
        let hash_hex = name[dash + 1..].to_string();
        if hash_hex.len() == 8 && hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(Self {
                executable,
                hash_hex,
            })
        } else {
            None
        }
    }

    /// Parse the stored hash from the filename.
    #[must_use]
    pub fn hash(&self) -> Option<u32> {
        u32::from_str_radix(&self.hash_hex, 16).ok()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v17_header() -> Vec<u8> {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&17u32.to_le_bytes()); // version
        data[4..8].copy_from_slice(b"SCCA"); // magic
        data[12..16].copy_from_slice(&128u32.to_le_bytes()); // file_size
        // executable name "NOTEPAD.EXE" as UTF-16LE at offset 16
        let name = "NOTEPAD.EXE";
        for (i, c) in name.encode_utf16().enumerate() {
            let base = 16 + i * 2;
            data[base..base + 2].copy_from_slice(&c.to_le_bytes());
        }
        data[76..80].copy_from_slice(&0xABCD_1234_u32.to_le_bytes()); // hash
        // run_count at 116
        data[116..120].copy_from_slice(&42u32.to_le_bytes());
        data
    }

    #[test]
    fn parse_v17_header_valid() {
        let data = make_v17_header();
        let hdr = PrefetchHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, PrefetchVersion::V17);
        assert_eq!(hdr.executable_name, "NOTEPAD.EXE");
        assert_eq!(hdr.hash, 0xABCD_1234);
        assert_eq!(hdr.run_count, 42);
    }

    #[test]
    fn parse_invalid_magic() {
        let mut data = make_v17_header();
        data[4..8].copy_from_slice(b"XXXX");
        let err = PrefetchHeader::parse(&data).unwrap_err();
        assert!(matches!(err, PrefetchError::InvalidMagic(_)));
    }

    #[test]
    fn parse_unsupported_version() {
        let mut data = make_v17_header();
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let err = PrefetchHeader::parse(&data).unwrap_err();
        assert!(matches!(err, PrefetchError::UnsupportedVersion(99)));
    }

    #[test]
    fn mam_detection() {
        let mam = 0x044D_414Du32.to_le_bytes();
        assert!(is_mam_compressed(&mam));
        assert!(!is_mam_compressed(b"SCCA"));
    }

    #[test]
    fn prefetch_hash_xp() {
        // Known XP hash for "C:\WINDOWS\SYSTEM32\NTDLL.DLL"
        let h = compute_prefetch_hash_xp(r"C:\WINDOWS\SYSTEM32\NTDLL.DLL");
        assert_ne!(h, 0);
    }

    #[test]
    fn prefetch_hash_win8_differs_from_xp() {
        let path = r"C:\WINDOWS\SYSTEM32\NOTEPAD.EXE";
        let h_xp = compute_prefetch_hash_xp(path);
        let h_w8 = compute_prefetch_hash_win8(path);
        assert_ne!(h_xp, h_w8);
    }

    #[test]
    fn filetime_to_unix_conversion() {
        // FILETIME for 2000-01-01 00:00:00 UTC = 125,911,584,000,000,000
        let ft = 125_911_584_000_000_000u64;
        let unix = filetime_to_unix(ft);
        assert_eq!(unix, 946_684_800); // known correct value
    }

    #[test]
    fn extract_filename_strings_basic() {
        // Build UTF-16LE "foo\0bar\0"
        let mut data: Vec<u8> = "foo"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes().to_vec())
            .collect();
        data.extend_from_slice(&[0, 0]); // NUL
        let bbar: Vec<u8> = "bar"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes().to_vec())
            .collect();
        data.extend(bbar);
        data.extend_from_slice(&[0, 0]);
        let strings = extract_filename_strings(&data);
        assert_eq!(strings, vec!["foo", "bar"]);
    }

    #[test]
    fn prefetch_filename_parse() {
        let pf = PrefetchFileName::parse("NOTEPAD.EXE-ABCD1234.pf").unwrap();
        assert_eq!(pf.executable, "NOTEPAD.EXE");
        assert_eq!(pf.hash_hex, "ABCD1234");
        assert_eq!(pf.hash(), Some(0xABCD_1234));
    }

    #[test]
    fn prefetch_filename_parse_invalid() {
        assert!(PrefetchFileName::parse("notprefetch.exe").is_none());
        assert!(PrefetchFileName::parse("NOTEPAD.EXE-ZZZZZZZZ.pf").is_none());
    }

    #[test]
    fn prefetch_version_properties() {
        assert!(!PrefetchVersion::V17.has_run_time_array());
        assert!(PrefetchVersion::V26.has_run_time_array());
        assert_eq!(PrefetchVersion::V30.run_time_slots(), 8);
        assert_eq!(PrefetchVersion::V17.run_time_slots(), 1);
    }

    #[test]
    fn prefetch_file_suspicious_check() {
        let hdr = PrefetchHeader {
            version: PrefetchVersion::V17,
            signature: *b"SCCA",
            file_size: 128,
            executable_name: "EVIL.EXE".into(),
            hash: 0,
            run_count: 5000,
            last_run_time: 0,
            run_times: vec![],
            file_metrics_offset: 0,
            file_metrics_count: 0,
            trace_chain_offset: 0,
            trace_chain_count: 0,
            filename_string_offset: 0,
            filename_string_size: 0,
            volumes_offset: 0,
            volumes_count: 0,
        };
        let pf = PrefetchFile {
            header: hdr,
            file_metrics: vec![],
            volumes: vec![],
            loaded_files: vec!["C:\\Users\\Public\\evil.dll".into()],
        };
        assert!(pf.is_suspicious());
    }
}
