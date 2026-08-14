//! `apk_zip_reader` — Low-level APK ZIP reader.
//!
//! Implements a zero-copy APK ZIP reader that walks the End of Central Directory
//! (EOCD), central directory entries, and local file headers, exposing raw
//! compressed payloads without external dependencies.
//!
//! Supports:
//! - ZIP32 and ZIP64 EOCD
//! - Stored (method 0) and Deflate (method 8) entries (inflate not bundled)
//! - Comment blocks up to 65535 bytes
//! - Streaming entry iteration
//! - Per-entry CRC-32 validation

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::AndroidLoaderError;

// ─── constants ───────────────────────────────────────────────────────────────

pub const ZIP_LOCAL_FILE_SIG: u32 = 0x0403_4B50;
pub const ZIP_CD_SIG: u32 = 0x0201_4B50;
pub const ZIP_EOCD_SIG: u32 = 0x0605_4B50;
pub const ZIP64_EOCD_SIG: u32 = 0x0606_4B50;
pub const ZIP64_EOCD_LOCATOR_SIG: u32 = 0x0704_4B50;

pub const COMPRESSION_STORED: u16 = 0;
pub const COMPRESSION_DEFLATED: u16 = 8;

/// Maximum valid comment length for the EOCD search window.
const MAX_EOCD_SEARCH: usize = 65535 + 22;

// ─── ZipError ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("no EOCD signature found")]
    NoEocd,
    #[error("truncated ZIP data at offset {0:#x}")]
    Truncated(usize),
    #[error("bad signature {found:#010x} at offset {offset:#x}")]
    BadSignature { found: u32, offset: usize },
    #[error("unsupported compression method {0}")]
    UnsupportedCompression(u16),
    #[error("CRC-32 mismatch: stored={stored:#010x} computed={computed:#010x}")]
    CrcMismatch { stored: u32, computed: u32 },
    #[error("entry not found: {0}")]
    EntryNotFound(String),
    #[error("ZIP64 not fully supported")]
    Zip64Unsupported,
}

impl From<ZipError> for AndroidLoaderError {
    fn from(e: ZipError) -> Self {
        match e {
            ZipError::Truncated(_) => Self::TruncatedHeader,
            other => Self::ParseError(other.to_string()),
        }
    }
}

// ─── CompressionMethod ────────────────────────────────────────────────────────

/// ZIP compression method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionMethod {
    Stored,
    Deflated,
    Other(u16),
}

impl CompressionMethod {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            COMPRESSION_STORED => Self::Stored,
            COMPRESSION_DEFLATED => Self::Deflated,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stored => write!(f, "stored"),
            Self::Deflated => write!(f, "deflated"),
            Self::Other(v) => write!(f, "method({v})"),
        }
    }
}

// ─── ZipEntry ────────────────────────────────────────────────────────────────

/// A single entry in a ZIP/APK archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipEntry {
    /// File name within the archive.
    pub name: String,
    /// Compression method.
    pub compression: CompressionMethod,
    /// CRC-32 checksum of the uncompressed data.
    pub crc32: u32,
    /// Compressed size in bytes.
    pub compressed_size: u32,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u32,
    /// Byte offset of the local file header within the archive.
    pub local_header_offset: u32,
    /// Last-modified date (MS-DOS format).
    pub last_mod_date: u16,
    /// Last-modified time (MS-DOS format).
    pub last_mod_time: u16,
    /// External file attributes (includes Unix permissions if bit 31 set).
    pub external_attributes: u32,
    /// Internal file attributes.
    pub internal_attributes: u16,
    /// Extra field bytes (variable).
    pub extra: Vec<u8>,
    /// File comment (optional).
    pub comment: String,
    /// `version made by` field from the central directory header.
    /// Low byte = ZIP spec version, high byte = host OS.
    pub version_made_by: u16,
}

impl ZipEntry {
    /// Returns `true` if this entry's name ends with `.dex`.
    #[must_use]
    pub fn is_dex(&self) -> bool {
        self.name.to_ascii_lowercase().ends_with(".dex")
    }

    /// Returns `true` if this is the binary Android manifest.
    #[must_use]
    pub fn is_manifest(&self) -> bool {
        self.name == "AndroidManifest.xml"
    }

    /// Returns `true` if this is the compiled resource table.
    #[must_use]
    pub fn is_resources(&self) -> bool {
        self.name == "resources.arsc"
    }

    /// Returns `true` if this is a native shared library.
    #[must_use]
    pub fn is_native_lib(&self) -> bool {
        self.name.starts_with("lib/") && self.name.ends_with(".so")
    }

    /// Returns the ABI directory for native libs (e.g. `"arm64-v8a"`).
    #[must_use]
    pub fn native_abi(&self) -> Option<&str> {
        if !self.is_native_lib() {
            return None;
        }
        self.name.split('/').nth(1)
    }

    /// Returns `true` if the data is stored (not compressed).
    #[must_use]
    pub fn is_stored(&self) -> bool {
        self.compression == CompressionMethod::Stored
    }

    /// Compression ratio as a fraction (0.0 = uncompressed, 1.0 = fully compressed).
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size == 0 {
            return 0.0;
        }
        1.0 - f64::from(self.compressed_size) / f64::from(self.uncompressed_size)
    }
}

impl fmt::Display for ZipEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] comp={} raw={}",
            self.name, self.compression, self.compressed_size, self.uncompressed_size,
        )
    }
}

// ─── ApkZipReader ─────────────────────────────────────────────────────────────

/// Zero-copy APK ZIP reader.
///
/// Parses the central directory and exposes per-entry raw byte slices.
#[derive(Debug)]
pub struct ApkZipReader<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
    /// Name → entry index map.
    name_map: HashMap<String, usize>,
    /// Offset of the central directory.
    cd_offset: usize,
    /// Size of the central directory in bytes.
    cd_size: usize,
    /// APK comment bytes (if any).
    comment: Vec<u8>,
}

impl<'a> ApkZipReader<'a> {
    /// Parse the ZIP central directory from `data`.
    ///
    /// # Errors
    /// Returns `ZipError::NoEocd` if no EOCD record is found.
    /// Returns `ZipError::Truncated` if the data is too short.
    pub fn parse(data: &'a [u8]) -> Result<Self, ZipError> {
        let (cd_offset, cd_size, cd_count, comment) = find_eocd(data)?;

        let entries = parse_central_directory(data, cd_offset, cd_count)?;
        let mut name_map = HashMap::with_capacity(entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            name_map.insert(entry.name.clone(), idx);
        }

        Ok(Self {
            data,
            entries,
            name_map,
            cd_offset,
            cd_size,
            comment,
        })
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Look up an entry by name.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&ZipEntry> {
        self.name_map.get(name).map(|&i| &self.entries[i])
    }

    /// Return the raw (possibly compressed) bytes for an entry.
    ///
    /// For `Stored` entries the bytes are the uncompressed data.
    /// For `Deflated` entries the caller must inflate.
    ///
    /// # Errors
    /// Returns `ZipError::EntryNotFound` or `ZipError::Truncated`.
    pub fn raw_data(&self, entry: &ZipEntry) -> Result<&'a [u8], ZipError> {
        let lhoff = entry.local_header_offset as usize;
        if lhoff + 30 > self.data.len() {
            return Err(ZipError::Truncated(lhoff));
        }
        let sig = read_u32_le(self.data, lhoff);
        if sig != ZIP_LOCAL_FILE_SIG {
            return Err(ZipError::BadSignature {
                found: sig,
                offset: lhoff,
            });
        }
        let fname_len = read_u16_le(self.data, lhoff + 26) as usize;
        let extra_len = read_u16_le(self.data, lhoff + 28) as usize;
        let data_start = lhoff.saturating_add(30).saturating_add(fname_len).saturating_add(extra_len);
        let data_end = data_start.saturating_add(entry.compressed_size as usize);
        if data_end > self.data.len() {
            return Err(ZipError::Truncated(data_start));
        }
        Ok(&self.data[data_start..data_end])
    }

    /// Return the raw bytes for a stored entry and verify its CRC-32.
    ///
    /// # Errors
    /// Returns `ZipError::UnsupportedCompression` if the entry is not stored.
    /// Returns `ZipError::CrcMismatch` if the CRC does not match.
    pub fn verified_data(&self, entry: &ZipEntry) -> Result<&'a [u8], ZipError> {
        if entry.compression != CompressionMethod::Stored {
            return Err(ZipError::UnsupportedCompression(
                match entry.compression {
                    CompressionMethod::Deflated => COMPRESSION_DEFLATED,
                    CompressionMethod::Other(v) => v,
                    CompressionMethod::Stored => 0,
                },
            ));
        }
        let raw = self.raw_data(entry)?;
        let computed = crc32(raw);
        if computed != entry.crc32 {
            return Err(ZipError::CrcMismatch {
                stored: entry.crc32,
                computed,
            });
        }
        Ok(raw)
    }

    /// Return the raw bytes for a named entry (stored entries only, CRC verified).
    ///
    /// # Errors
    /// Returns `ZipError::EntryNotFound` if the name is not in the archive.
    pub fn read_stored(&self, name: &str) -> Result<&'a [u8], ZipError> {
        let entry = self
            .entry(name)
            .ok_or_else(|| ZipError::EntryNotFound(name.to_owned()))?;
        self.verified_data(entry)
    }

    /// Return all DEX entries sorted by name.
    #[must_use]
    pub fn dex_entries(&self) -> Vec<&ZipEntry> {
        let mut v: Vec<&ZipEntry> = self.entries.iter().filter(|e| e.is_dex()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Return all native library entries grouped by ABI.
    #[must_use]
    pub fn native_libs_by_abi(&self) -> HashMap<String, Vec<&ZipEntry>> {
        let mut map: HashMap<String, Vec<&ZipEntry>> = HashMap::new();
        for entry in &self.entries {
            if let Some(abi) = entry.native_abi() {
                map.entry(abi.to_owned()).or_default().push(entry);
            }
        }
        map
    }

    /// Offset of the central directory.
    #[must_use]
    pub const fn cd_offset(&self) -> usize {
        self.cd_offset
    }

    /// Size of the central directory in bytes.
    #[must_use]
    pub const fn cd_size(&self) -> usize {
        self.cd_size
    }

    /// Total number of entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the archive comment bytes.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Returns `true` if the APK contains the `AndroidManifest.xml` entry.
    #[must_use]
    pub fn has_manifest(&self) -> bool {
        self.name_map.contains_key("AndroidManifest.xml")
    }

    /// Returns `true` if the APK contains `resources.arsc`.
    #[must_use]
    pub fn has_resources(&self) -> bool {
        self.name_map.contains_key("resources.arsc")
    }

    /// Compute the total uncompressed size of all entries.
    #[must_use]
    pub fn total_uncompressed_size(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| u64::from(e.uncompressed_size))
            .sum()
    }

    /// Return entries that are larger than `threshold_bytes` when compressed.
    #[must_use]
    pub fn large_entries(&self, threshold_bytes: u32) -> Vec<&ZipEntry> {
        self.entries
            .iter()
            .filter(|e| e.compressed_size >= threshold_bytes)
            .collect()
    }
}

// ─── EOCD search ─────────────────────────────────────────────────────────────

/// Find the End of Central Directory record.
/// Returns `(cd_offset, cd_size, entry_count, comment)`.
fn find_eocd(data: &[u8]) -> Result<(usize, usize, usize, Vec<u8>), ZipError> {
    if data.len() < 22 {
        return Err(ZipError::Truncated(0));
    }
    let search_start = data.len().saturating_sub(MAX_EOCD_SEARCH);
    let sig = ZIP_EOCD_SIG.to_le_bytes();

    let eocd_off = data[search_start..]
        .windows(4)
        .rposition(|w| w == sig)
        .map(|p| search_start + p)
        .ok_or(ZipError::NoEocd)?;

    if eocd_off + 22 > data.len() {
        return Err(ZipError::Truncated(eocd_off));
    }

    let disk_entries = read_u16_le(data, eocd_off + 8) as usize;
    let cd_size = read_u32_le(data, eocd_off + 12) as usize;
    let cd_offset = read_u32_le(data, eocd_off + 16) as usize;
    let comment_len = read_u16_le(data, eocd_off + 20) as usize;

    let comment_start = eocd_off + 22;
    let comment_end = comment_start + comment_len;
    let comment = if comment_end <= data.len() {
        data[comment_start..comment_end].to_vec()
    } else {
        vec![]
    };

    Ok((cd_offset, cd_size, disk_entries, comment))
}

// ─── Central directory parser ─────────────────────────────────────────────────

fn parse_central_directory(
    data: &[u8],
    cd_offset: usize,
    count: usize,
) -> Result<Vec<ZipEntry>, ZipError> {
    // Cap pre-allocation: each CD entry is at least 46 bytes, preventing OOM
    // from an attacker-controlled entry count in the EOCD.
    let capacity = count.min(data.len() / 46 + 1);
    let mut entries = Vec::with_capacity(capacity);
    let mut pos = cd_offset;

    for _ in 0..count {
        if pos + 46 > data.len() {
            break;
        }
        let sig = read_u32_le(data, pos);
        if sig != ZIP_CD_SIG {
            break;
        }

        let version_made_by = read_u16_le(data, pos + 4);
        let _version_needed = read_u16_le(data, pos + 6);
        let _general_purpose = read_u16_le(data, pos + 8);
        let compression_raw = read_u16_le(data, pos + 10);
        let last_mod_time = read_u16_le(data, pos + 12);
        let last_mod_date = read_u16_le(data, pos + 14);
        let crc32 = read_u32_le(data, pos + 16);
        let compressed_size = read_u32_le(data, pos + 20);
        let uncompressed_size = read_u32_le(data, pos + 24);
        let fname_len = read_u16_le(data, pos + 28) as usize;
        let extra_len = read_u16_le(data, pos + 30) as usize;
        let comment_len = read_u16_le(data, pos + 32) as usize;
        let _disk_start = read_u16_le(data, pos + 34);
        let internal_attributes = read_u16_le(data, pos + 36);
        let external_attributes = read_u32_le(data, pos + 38);
        let local_header_offset = read_u32_le(data, pos + 42);

        let name_start = pos + 46;
        let name_end = name_start + fname_len;
        if name_end > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

        let extra_start = name_end;
        let extra_end = extra_start + extra_len;
        let extra = if extra_end <= data.len() {
            data[extra_start..extra_end].to_vec()
        } else {
            vec![]
        };

        let comment_start = extra_end;
        let comment_end = comment_start + comment_len;
        let comment = if comment_end <= data.len() {
            String::from_utf8_lossy(&data[comment_start..comment_end]).into_owned()
        } else {
            String::new()
        };

        entries.push(ZipEntry {
            name,
            compression: CompressionMethod::from_u16(compression_raw),
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            last_mod_date,
            last_mod_time,
            external_attributes,
            internal_attributes,
            extra,
            comment,
            version_made_by,
        });

        pos = comment_end;
    }

    Ok(entries)
}

// ─── CRC-32 ───────────────────────────────────────────────────────────────────

/// Standard ZIP CRC-32 (polynomial `0xEDB88320`).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Pre-computed CRC-32 table (polynomial `0xEDB8_8320`).
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

// ─── Read helpers ─────────────────────────────────────────────────────────────

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

// ─── Build helpers ────────────────────────────────────────────────────────────

/// Build a minimal valid ZIP file in memory for testing.
///
/// Creates a ZIP with one stored entry named `name` containing `payload`.
#[must_use]
pub fn build_test_zip(name: &str, payload: &[u8]) -> Vec<u8> {
    let crc = crc32(payload);
    let comp_size = payload.len() as u32;
    let uncomp_size = payload.len() as u32;
    let fname = name.as_bytes();
    let fname_len = fname.len() as u16;

    // Local file header (30 bytes) + filename + payload
    let mut zip = Vec::new();

    // Local file header
    zip.extend_from_slice(&ZIP_LOCAL_FILE_SIG.to_le_bytes());
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // general purpose
    zip.extend_from_slice(&0u16.to_le_bytes()); // compression: stored
    zip.extend_from_slice(&0u16.to_le_bytes()); // last mod time
    zip.extend_from_slice(&0u16.to_le_bytes()); // last mod date
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&comp_size.to_le_bytes());
    zip.extend_from_slice(&uncomp_size.to_le_bytes());
    zip.extend_from_slice(&fname_len.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
    zip.extend_from_slice(fname);
    zip.extend_from_slice(payload);

    let local_header_offset = 0u32;
    let cd_offset = zip.len() as u32;

    // Central directory entry
    zip.extend_from_slice(&ZIP_CD_SIG.to_le_bytes());
    zip.extend_from_slice(&20u16.to_le_bytes()); // version made by
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // general purpose
    zip.extend_from_slice(&0u16.to_le_bytes()); // compression: stored
    zip.extend_from_slice(&0u16.to_le_bytes()); // last mod time
    zip.extend_from_slice(&0u16.to_le_bytes()); // last mod date
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&comp_size.to_le_bytes());
    zip.extend_from_slice(&uncomp_size.to_le_bytes());
    zip.extend_from_slice(&fname_len.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment len
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk start
    zip.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    zip.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    zip.extend_from_slice(&local_header_offset.to_le_bytes());
    zip.extend_from_slice(fname);

    let cd_size = (zip.len() as u32) - cd_offset;

    // EOCD
    zip.extend_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
    zip.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    zip.extend_from_slice(&1u16.to_le_bytes()); // total entries
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment length

    zip
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dex_zip() -> Vec<u8> {
        build_test_zip("classes.dex", b"dex\n035\0hello")
    }

    fn manifest_zip() -> Vec<u8> {
        build_test_zip("AndroidManifest.xml", b"\x03\x00\x08\x00")
    }

    #[test]
    fn parse_valid_zip() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert_eq!(reader.entry_count(), 1);
    }

    #[test]
    fn entry_name_correct() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert_eq!(reader.entries()[0].name, "classes.dex");
    }

    #[test]
    fn entry_lookup_by_name() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.entry("classes.dex").is_some());
        assert!(reader.entry("missing.txt").is_none());
    }

    #[test]
    fn raw_data_matches_payload() {
        let payload = b"hello world";
        let zip = build_test_zip("test.txt", payload);
        let reader = ApkZipReader::parse(&zip).unwrap();
        let entry = reader.entry("test.txt").unwrap();
        let data = reader.raw_data(entry).unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    fn verified_data_stored_ok() {
        let payload = b"hello";
        let zip = build_test_zip("a.txt", payload);
        let reader = ApkZipReader::parse(&zip).unwrap();
        let entry = reader.entry("a.txt").unwrap();
        let data = reader.verified_data(entry).unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    fn read_stored_ok() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        let data = reader.read_stored("classes.dex").unwrap();
        assert!(data.starts_with(b"dex\n"));
    }

    #[test]
    fn read_stored_missing() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        let err = reader.read_stored("missing.dex").unwrap_err();
        assert!(matches!(err, ZipError::EntryNotFound(_)));
    }

    #[test]
    fn dex_entries_filter() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        let dex = reader.dex_entries();
        assert_eq!(dex.len(), 1);
        assert!(dex[0].is_dex());
    }

    #[test]
    fn has_manifest_true() {
        let zip = manifest_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.has_manifest());
    }

    #[test]
    fn has_manifest_false() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(!reader.has_manifest());
    }

    #[test]
    fn has_resources_false() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(!reader.has_resources());
    }

    #[test]
    fn crc32_known_value() {
        // CRC-32 of empty slice is 0x00000000
        assert_eq!(crc32(b""), 0x00000000);
        // CRC-32 of "123456789" is 0xCBF43926 (standard test vector)
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn entry_is_dex() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.entries()[0].is_dex());
    }

    #[test]
    fn entry_is_manifest() {
        let zip = manifest_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.entries()[0].is_manifest());
    }

    #[test]
    fn entry_is_stored() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.entries()[0].is_stored());
    }

    #[test]
    fn compression_ratio_stored() {
        let e = ZipEntry {
            name: "a".into(),
            compression: CompressionMethod::Stored,
            crc32: 0,
            compressed_size: 100,
            uncompressed_size: 100,
            local_header_offset: 0,
            last_mod_date: 0,
            last_mod_time: 0,
            external_attributes: 0,
            internal_attributes: 0,
            extra: vec![],
            comment: String::new(),
            version_made_by: 0,
        };
        assert!((e.compression_ratio() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn compression_ratio_zero_uncompressed() {
        let e = ZipEntry {
            name: "a".into(),
            compression: CompressionMethod::Stored,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            local_header_offset: 0,
            last_mod_date: 0,
            last_mod_time: 0,
            external_attributes: 0,
            internal_attributes: 0,
            extra: vec![],
            comment: String::new(),
            version_made_by: 0,
        };
        assert_eq!(e.compression_ratio(), 0.0);
    }

    #[test]
    fn total_uncompressed_size() {
        let payload = vec![0u8; 50];
        let zip = build_test_zip("data.bin", &payload);
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert_eq!(reader.total_uncompressed_size(), 50);
    }

    #[test]
    fn large_entries_threshold() {
        let payload = vec![0u8; 100];
        let zip = build_test_zip("big.bin", &payload);
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert_eq!(reader.large_entries(50).len(), 1);
        assert_eq!(reader.large_entries(200).len(), 0);
    }

    #[test]
    fn no_eocd_errors() {
        let err = ApkZipReader::parse(b"not a zip").unwrap_err();
        assert!(matches!(err, ZipError::NoEocd | ZipError::Truncated(_)));
    }

    #[test]
    fn compression_method_display() {
        assert_eq!(CompressionMethod::Stored.to_string(), "stored");
        assert_eq!(CompressionMethod::Deflated.to_string(), "deflated");
        assert_eq!(CompressionMethod::Other(9).to_string(), "method(9)");
    }

    #[test]
    fn native_libs_by_abi_empty_for_no_libs() {
        let zip = dex_zip();
        let reader = ApkZipReader::parse(&zip).unwrap();
        assert!(reader.native_libs_by_abi().is_empty());
    }
}
