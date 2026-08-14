//! Windows Registry hive analyzer.
//!
//! Implements a pure-Rust parser for the REGF hive format used by Windows
//! registry files (`SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`, etc.).
//!
//! References:
//! - <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ForensicsError;

// ─── Constants ────────────────────────────────────────────────────────────────

const REGF_SIGNATURE: &[u8; 4] = b"regf";
const HBIN_SIGNATURE: &[u8; 4] = b"hbin";
const NK_SIGNATURE: u16 = 0x6b6e; // "nk" LE
const VK_SIGNATURE: u16 = 0x6b76; // "vk" LE
const _SK_SIGNATURE: u16 = 0x6b73; // "sk" LE
const LF_SIGNATURE: u16 = 0x666c; // "lf" LE
const LH_SIGNATURE: u16 = 0x686c; // "lh" LE
const _RI_SIGNATURE: u16 = 0x6972; // "ri" LE
const LI_SIGNATURE: u16 = 0x696c; // "li" LE

// ─── HiveValue types ──────────────────────────────────────────────────────────

/// Registry value type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ValueType {
    RegNone = 0,
    RegSz = 1,
    RegExpandSz = 2,
    RegBinary = 3,
    RegDword = 4,
    RegDwordBigEndian = 5,
    RegLink = 6,
    RegMultiSz = 7,
    RegResourceList = 8,
    RegFullResourceDescriptor = 9,
    RegResourceRequirementsList = 10,
    RegQword = 11,
    Unknown(u32),
}

impl ValueType {
    const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::RegNone,
            1 => Self::RegSz,
            2 => Self::RegExpandSz,
            3 => Self::RegBinary,
            4 => Self::RegDword,
            5 => Self::RegDwordBigEndian,
            6 => Self::RegLink,
            7 => Self::RegMultiSz,
            8 => Self::RegResourceList,
            9 => Self::RegFullResourceDescriptor,
            10 => Self::RegResourceRequirementsList,
            11 => Self::RegQword,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RegNone => "REG_NONE",
            Self::RegSz => "REG_SZ",
            Self::RegExpandSz => "REG_EXPAND_SZ",
            Self::RegBinary => "REG_BINARY",
            Self::RegDword => "REG_DWORD",
            Self::RegDwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::RegLink => "REG_LINK",
            Self::RegMultiSz => "REG_MULTI_SZ",
            Self::RegResourceList => "REG_RESOURCE_LIST",
            Self::RegFullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::RegResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::RegQword => "REG_QWORD",
            Self::Unknown(_) => "REG_UNKNOWN",
        }
    }
}

// ─── HiveValue ────────────────────────────────────────────────────────────────

/// A single value stored in a registry key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveValue {
    /// Value name (empty string for the default value `"(Default)"`).
    pub name: String,
    /// Type of the value data.
    pub value_type: ValueType,
    /// Raw data bytes.
    pub data: Vec<u8>,
}

impl HiveValue {
    /// Decode the value as a UTF-16LE string (for `REG_SZ` / `REG_EXPAND_SZ`).
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self.value_type {
            ValueType::RegSz | ValueType::RegExpandSz | ValueType::RegLink => {
                let words: Vec<u16> = self
                    .data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&w| w != 0)
                    .collect();
                Some(String::from_utf16_lossy(&words))
            }
            _ => None,
        }
    }

    /// Decode the value as a `u32` (for `REG_DWORD`).
    #[must_use]
    pub fn as_dword(&self) -> Option<u32> {
        if self.value_type == ValueType::RegDword && self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0], self.data[1], self.data[2], self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Decode the value as a `u64` (for `REG_QWORD`).
    #[must_use]
    pub fn as_qword(&self) -> Option<u64> {
        if self.value_type == ValueType::RegQword && self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0], self.data[1], self.data[2], self.data[3],
                self.data[4], self.data[5], self.data[6], self.data[7],
            ]))
        } else {
            None
        }
    }

    /// Decode the value as a list of strings (for `REG_MULTI_SZ`).
    #[must_use]
    pub fn as_multi_sz(&self) -> Option<Vec<String>> {
        if self.value_type != ValueType::RegMultiSz {
            return None;
        }
        let words: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut strings = Vec::new();
        let mut current: Vec<u16> = Vec::new();
        for &w in &words {
            if w == 0 {
                if !current.is_empty() {
                    strings.push(String::from_utf16_lossy(&current));
                    current.clear();
                }
            } else {
                current.push(w);
            }
        }
        Some(strings)
    }

    /// Hex-dump of the raw data (at most 64 bytes).
    #[must_use]
    pub fn hex_preview(&self) -> String {
        self.data
            .iter()
            .take(64)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ─── HiveCell ─────────────────────────────────────────────────────────────────

/// A raw cell read from an hbin block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveCell {
    /// Offset of this cell from the start of the hive data.
    pub offset: usize,
    /// Allocated size (positive cell length from hive header).
    pub size: usize,
    /// Cell type signature.
    pub signature: u16,
    /// Raw payload bytes (after signature).
    pub payload: Vec<u8>,
}

impl HiveCell {
    /// Whether this is a named-key (nk) cell.
    #[must_use]
    pub const fn is_nk(&self) -> bool {
        self.signature == NK_SIGNATURE
    }

    /// Whether this is a value-key (vk) cell.
    #[must_use]
    pub const fn is_vk(&self) -> bool {
        self.signature == VK_SIGNATURE
    }
}

// ─── HiveKey ──────────────────────────────────────────────────────────────────

/// A registry key with its values and subkey names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveKey {
    /// Absolute path in the hive (backslash separated).
    pub path: String,
    /// The key name component (last segment of `path`).
    pub name: String,
    /// Last-write timestamp (FILETIME, 100-nanosecond intervals since 1601-01-01).
    pub last_write_time: u64,
    /// All values stored in this key.
    pub values: Vec<HiveValue>,
    /// Names of immediate subkeys.
    pub subkey_names: Vec<String>,
    /// Key class string (rarely used).
    pub class_name: Option<String>,
    /// Security descriptor offset (raw).
    pub sk_offset: u32,
}

impl HiveKey {
    /// Find a value by name (case-insensitive).
    #[must_use]
    pub fn get_value(&self, name: &str) -> Option<&HiveValue> {
        let lower = name.to_lowercase();
        self.values
            .iter()
            .find(|v| v.name.to_lowercase() == lower)
    }

    /// Number of direct children.
    #[must_use]
    pub const fn subkey_count(&self) -> usize {
        self.subkey_names.len()
    }

    /// Convert last-write time to a human-readable UTC approximation.
    /// Returns an ISO-8601-like string.
    #[must_use]
    pub fn last_write_utc_approx(&self) -> String {
        // FILETIME: 100-ns intervals since 1601-01-01.
        // Unix epoch offset = 11644473600 seconds.
        let secs = self.last_write_time / 10_000_000;
        let unix_secs = secs.saturating_sub(11_644_473_600);
        let days = unix_secs / 86400;
        let time_of_day = unix_secs % 86400;
        let h = time_of_day / 3600;
        let m = (time_of_day % 3600) / 60;
        let s = time_of_day % 60;
        // Very rough date from days since 1970-01-01.
        let year = 1970 + days / 365;
        let remaining_days = days % 365;
        let month = (remaining_days / 30).min(11) + 1;
        let day = (remaining_days % 30) + 1;
        format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
    }
}

// ─── HiveHeader ───────────────────────────────────────────────────────────────

/// Parsed REGF file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveHeader {
    pub sequence_number_primary: u32,
    pub sequence_number_secondary: u32,
    pub last_written_timestamp: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub filename: String,
}

impl HiveHeader {
    fn parse(data: &[u8]) -> Result<Self, ForensicsError> {
        if data.len() < 512 {
            return Err(ForensicsError::ParseError("REGF header too short".into()));
        }
        if &data[0..4] != REGF_SIGNATURE {
            return Err(ForensicsError::ParseError(format!(
                "Invalid REGF signature: {:?}",
                &data[0..4]
            )));
        }
        let seq1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let seq2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let ts = u64::from_le_bytes([
            data[12], data[13], data[14], data[15],
            data[16], data[17], data[18], data[19],
        ]);
        let major = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let minor = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let root_offset = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let bins_size = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        // Filename at offset 48, UTF-16LE, 64 bytes (32 chars).
        let fname_words: Vec<u16> = data[48..112]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        let filename = String::from_utf16_lossy(&fname_words);
        Ok(Self {
            sequence_number_primary: seq1,
            sequence_number_secondary: seq2,
            last_written_timestamp: ts,
            major_version: major,
            minor_version: minor,
            root_cell_offset: root_offset,
            hive_bins_data_size: bins_size,
            filename,
        })
    }
}

// ─── RegistryHiveAnalyzer ─────────────────────────────────────────────────────

/// Parses and queries a Windows registry hive binary.
pub struct RegistryHiveAnalyzer {
    /// The raw hive bytes.
    data: Vec<u8>,
    /// Parsed header.
    pub header: HiveHeader,
    /// Start of hive bins section (typically 0x1000).
    bins_base: usize,
}

impl RegistryHiveAnalyzer {
    /// Parse a hive from raw bytes.
    ///
    /// # Errors
    /// Returns [`ForensicsError::ParseError`] for invalid/truncated data.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ForensicsError> {
        let header = HiveHeader::parse(&data)?;
        // Hive bins start at offset 0x1000 in REGF files.
        let bins_base = 0x1000usize;
        Ok(Self { data, header, bins_base })
    }

    /// Parse a hive from a file path.
    ///
    /// # Errors
    /// Returns [`ForensicsError::Io`] on read failure or [`ForensicsError::ParseError`].
    pub fn from_file(path: &std::path::Path) -> Result<Self, ForensicsError> {
        let data = std::fs::read(path).map_err(ForensicsError::from)?;
        Self::from_bytes(data)
    }

    /// Read a little-endian `u32` from the hive bins area at `relative_offset`.
    fn read_u32(&self, relative_offset: usize) -> Option<u32> {
        let abs = self.bins_base.checked_add(relative_offset)?;
        let end = abs.checked_add(4)?;
        if end > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[abs],
            self.data[abs + 1],
            self.data[abs + 2],
            self.data[abs + 3],
        ]))
    }

    /// Read a little-endian `u16` from the hive bins area at `relative_offset`.
    fn read_u16(&self, relative_offset: usize) -> Option<u16> {
        let abs = self.bins_base.checked_add(relative_offset)?;
        let end = abs.checked_add(2)?;
        if end > self.data.len() {
            return None;
        }
        Some(u16::from_le_bytes([self.data[abs], self.data[abs + 1]]))
    }

    /// Read `len` bytes from the hive bins area starting at `relative_offset`.
    fn read_bytes(&self, relative_offset: usize, len: usize) -> Option<&[u8]> {
        let abs = self.bins_base.checked_add(relative_offset)?;
        let end = abs.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[abs..end])
    }

    /// Parse a value key (VK) cell at `relative_offset`.
    fn parse_vk(&self, relative_offset: usize) -> Option<HiveValue> {
        let sig = self.read_u16(relative_offset)?;
        if sig != VK_SIGNATURE {
            return None;
        }
        let name_len = self.read_u16(relative_offset + 2)? as usize;
        let data_len_raw = self.read_u32(relative_offset + 4)?;
        let data_offset = self.read_u32(relative_offset + 8)?;
        let value_type_raw = self.read_u32(relative_offset + 12)?;
        let flags = self.read_u16(relative_offset + 16)?;

        let value_type = ValueType::from_u32(value_type_raw);

        // Flags bit 0: value name is ASCII.
        let name_ascii = flags & 1 != 0;
        let name = if name_len == 0 {
            String::new() // default value
        } else {
            let name_bytes = self.read_bytes(relative_offset + 20, name_len)?;
            if name_ascii {
                name_bytes
                    .iter()
                    .map(|&b| b as char)
                    .collect()
            } else {
                let words: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&words)
            }
        };

        // If bit 31 is set in data_len_raw, data is stored inline in data_offset.
        let data = if data_len_raw & 0x8000_0000 != 0 {
            let inline_len = (data_len_raw & 0x7fff_ffff) as usize;
            let raw = data_offset.to_le_bytes();
            raw[..inline_len.min(4)].to_vec()
        } else {
            let data_len = (data_len_raw & 0x7fff_ffff) as usize;
            // data_offset is relative to hive bins base, and points to a cell;
            // the first 4 bytes of the cell are the cell size (signed), then the data.
            let data_cell_offset = data_offset as usize + 4; // skip cell size
            self.read_bytes(data_cell_offset, data_len)
                .unwrap_or(&[])
                .to_vec()
        };

        Some(HiveValue { name, value_type, data })
    }

    /// Parse a named key (NK) cell at `relative_offset`, recursively building
    /// the key tree under `parent_path`.
    fn parse_nk(&self, relative_offset: usize, parent_path: &str) -> Option<HiveKey> {
        // Cell layout: [cell_size: i32][signature: u16][...]
        // We receive the offset already pointing past the cell size.
        let sig = self.read_u16(relative_offset)?;
        if sig != NK_SIGNATURE {
            return None;
        }
        let name_len = self.read_u16(relative_offset + 10)? as usize;
        let class_name_len = self.read_u16(relative_offset + 12)? as usize;
        let last_write = {
            let lo = self.read_u32(relative_offset + 4)?;
            let hi = self.read_u32(relative_offset + 8)?;
            (u64::from(hi) << 32) | u64::from(lo)
        };
        let subkey_count = self.read_u32(relative_offset + 16)? as usize;
        let subkey_list_offset = self.read_u32(relative_offset + 24)?;
        let value_count = self.read_u32(relative_offset + 36)? as usize;
        let value_list_offset = self.read_u32(relative_offset + 40)?;
        let sk_offset = self.read_u32(relative_offset + 44).unwrap_or(0);
        let class_name_offset = self.read_u32(relative_offset + 48)?;

        // Flags: bit 5 = ASCII name.
        let flags = self.read_u16(relative_offset + 2)?;
        let name_ascii = flags & 0x20 != 0;

        let name = if name_len == 0 {
            String::from("ROOT")
        } else {
            let name_bytes = self.read_bytes(relative_offset + 76, name_len)?;
            if name_ascii {
                name_bytes.iter().map(|&b| b as char).collect()
            } else {
                let words: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&words)
            }
        };

        let path = if parent_path.is_empty() {
            name.clone()
        } else {
            format!("{parent_path}\\{name}")
        };

        // Parse class name.
        let class_name = if class_name_len > 0 {
            self.read_bytes(class_name_offset as usize + 4, class_name_len)
                .map(|b| {
                    let words: Vec<u16> = b
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&words)
                })
        } else {
            None
        };

        // Parse value list.
        let mut values = Vec::new();
        if value_count > 0 && value_list_offset != 0xffff_ffff {
            let list_start = value_list_offset as usize + 4; // skip cell size
            for i in 0..value_count.min(256) {
                if let Some(vk_offset_raw) = self.read_u32(list_start + i * 4) {
                    let vk_offset = vk_offset_raw as usize;
                    if let Some(val) = self.parse_vk(vk_offset) {
                        values.push(val);
                    }
                }
            }
        }

        // Parse subkey list to get subkey names (not recursed here for stack safety).
        let subkey_names = self.read_subkey_names(subkey_list_offset, subkey_count);

        Some(HiveKey {
            path,
            name,
            last_write_time: last_write,
            values,
            subkey_names,
            class_name,
            sk_offset,
        })
    }

    /// Read the list of subkey names from an LF/LH/LI/RI list.
    fn read_subkey_names(&self, list_offset: u32, count: usize) -> Vec<String> {
        if list_offset == 0xffff_ffff || count == 0 {
            return Vec::new();
        }
        let list_start = list_offset as usize;
        let Some(sig) = self.read_u16(list_start) else { return Vec::new(); };
        let mut names = Vec::new();

        if sig == LF_SIGNATURE || sig == LH_SIGNATURE {
            // Each entry: [offset: u32][hint: u32] (8 bytes each)
            for i in 0..count.min(1024) {
                let entry_off = list_start + 4 + i * 8;
                if let Some(nk_offset) = self.read_u32(entry_off) {
                    let nk_off = nk_offset as usize;
                    if let Some(nk_name_len) = self.read_u16(nk_off + 10) {
                        let nk_flags = self.read_u16(nk_off + 2).unwrap_or(0);
                        let name_ascii = nk_flags & 0x20 != 0;
                        if let Some(bytes) = self.read_bytes(nk_off + 76, nk_name_len as usize) {
                            let name = if name_ascii {
                                bytes.iter().map(|&b| b as char).collect()
                            } else {
                                let words: Vec<u16> = bytes
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                String::from_utf16_lossy(&words).clone()
                            };
                            names.push(name);
                        }
                    }
                }
            }
        } else if sig == LI_SIGNATURE {
            // Each entry: [offset: u32] (4 bytes each).
            for i in 0..count.min(1024) {
                let entry_off = list_start + 4 + i * 4;
                if let Some(nk_offset) = self.read_u32(entry_off) {
                    let nk_off = nk_offset as usize;
                    if let Some(nk_name_len) = self.read_u16(nk_off + 10)
                        && let Some(bytes) = self.read_bytes(nk_off + 76, nk_name_len as usize) {
                            let name: String = bytes.iter().map(|&b| b as char).collect();
                            names.push(name);
                        }
                }
            }
        }
        names
    }

    /// Return the root key.
    ///
    /// # Errors
    /// Returns [`ForensicsError::ParseError`] if the root cell cannot be parsed.
    pub fn root_key(&self) -> Result<HiveKey, ForensicsError> {
        let root_offset = self.header.root_cell_offset as usize + 4; // skip cell size
        self.parse_nk(root_offset, "")
            .ok_or_else(|| ForensicsError::ParseError("Failed to parse root NK cell".into()))
    }

    /// Walk all accessible cells in the hive and enumerate every parseable key.
    ///
    /// This is a linear scan rather than a tree traversal, so it can recover
    /// keys from partially-corrupt hives.
    #[must_use]
    pub fn enumerate_all_keys(&self) -> Vec<HiveKey> {
        let mut keys = Vec::new();
        let bins_end = self.bins_base.saturating_add(self.header.hive_bins_data_size as usize);
        let scan_end = bins_end.min(self.data.len());
        let mut pos = self.bins_base;

        while pos + 32 < scan_end {
            // Look for hbin signature.
            if &self.data[pos..pos + 4] != HBIN_SIGNATURE {
                pos += 512;
                continue;
            }
            let bin_size = u32::from_le_bytes([
                self.data[pos + 8],
                self.data[pos + 9],
                self.data[pos + 10],
                self.data[pos + 11],
            ]) as usize;
            if bin_size == 0 || pos + bin_size > scan_end {
                pos += 4096;
                continue;
            }
            // Scan cells within this hbin.
            let mut cell_pos = pos + 32; // hbin header is 32 bytes
            let current_bin_end = pos + bin_size;
            while cell_pos + 8 < current_bin_end {
                let cell_size_raw = i32::from_le_bytes([
                    self.data[cell_pos],
                    self.data[cell_pos + 1],
                    self.data[cell_pos + 2],
                    self.data[cell_pos + 3],
                ]);
                let allocated = cell_size_raw < 0;
                let cell_size = cell_size_raw.unsigned_abs() as usize;
                if cell_size == 0 || cell_pos + cell_size > current_bin_end {
                    break;
                }
                if allocated && cell_size >= 6 {
                    let rel_off = cell_pos - self.bins_base;
                    let sig = u16::from_le_bytes([
                        self.data[cell_pos + 4],
                        self.data[cell_pos + 5],
                    ]);
                    if sig == NK_SIGNATURE
                        && let Some(key) = self.parse_nk(rel_off + 4, "") {
                            keys.push(key);
                        }
                }
                cell_pos += cell_size.max(8);
            }
            pos += bin_size;
        }
        keys
    }

    /// Look up a key by path (e.g. `"ROOT\\ControlSet001\\Services"`).
    ///
    /// Returns the first key whose `path` ends with the given suffix (case-insensitive).
    #[must_use]
    pub fn find_key(&self, path_suffix: &str) -> Option<HiveKey> {
        let lower = path_suffix.to_lowercase();
        self.enumerate_all_keys()
            .into_iter()
            .find(|k| k.path.to_lowercase().ends_with(&lower))
    }

    /// Extract all values from all keys matching a path suffix.
    #[must_use]
    pub fn query_values(&self, path_suffix: &str) -> Vec<HiveValue> {
        self.find_key(path_suffix)
            .map(|k| k.values)
            .unwrap_or_default()
    }

    /// Produce a flat `HashMap<path, Vec<HiveValue>>` from all parseable keys.
    #[must_use]
    pub fn all_values_by_path(&self) -> HashMap<String, Vec<HiveValue>> {
        self.enumerate_all_keys()
            .into_iter()
            .map(|k| (k.path, k.values))
            .collect()
    }
}

// ─── parse_hive ───────────────────────────────────────────────────────────────

/// Parse a registry hive from a file path.
///
/// # Errors
/// Returns [`ForensicsError`] on I/O or parse errors.
pub fn parse_hive(path: &std::path::Path) -> Result<RegistryHiveAnalyzer, ForensicsError> {
    RegistryHiveAnalyzer::from_file(path)
}

/// Parse a registry hive from raw bytes.
///
/// # Errors
/// Returns [`ForensicsError::ParseError`] on invalid data.
pub fn parse_hive_bytes(data: Vec<u8>) -> Result<RegistryHiveAnalyzer, ForensicsError> {
    RegistryHiveAnalyzer::from_bytes(data)
}

// ─── HiveValueFormatter ──────────────────────────────────────────────────────

/// Renders a [`HiveValue`] to a printable string regardless of type.
pub struct HiveValueFormatter;

impl HiveValueFormatter {
    /// Format a value to a human-readable string.
    #[must_use]
    pub fn format(value: &HiveValue) -> String {
        match value.value_type {
            ValueType::RegSz | ValueType::RegExpandSz | ValueType::RegLink => {
                value.as_string().unwrap_or_default()
            }
            ValueType::RegDword | ValueType::RegDwordBigEndian => {
                value
                    .as_dword()
                    .map_or_else(|| value.hex_preview(), |v| format!("0x{v:08x} ({v})"))
            }
            ValueType::RegQword => {
                value
                    .as_qword()
                    .map_or_else(|| value.hex_preview(), |v| format!("0x{v:016x} ({v})"))
            }
            ValueType::RegMultiSz => value
                .as_multi_sz()
                .unwrap_or_default()
                .join(" | "),
            ValueType::RegNone => "(none)".to_string(),
            _ => value.hex_preview(),
        }
    }
}

// ─── HiveDiff ────────────────────────────────────────────────────────────────

/// Compares two hives and reports differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveDiff {
    /// Keys present only in hive A.
    pub only_in_a: Vec<String>,
    /// Keys present only in hive B.
    pub only_in_b: Vec<String>,
    /// Keys present in both hives but with different values.
    pub modified: Vec<String>,
}

impl HiveDiff {
    /// Compute the diff between two analyzers.
    #[must_use]
    pub fn compute(a: &RegistryHiveAnalyzer, b: &RegistryHiveAnalyzer) -> Self {
        let map_a = a.all_values_by_path();
        let map_b = b.all_values_by_path();
        let mut only_in_a = Vec::new();
        let mut only_in_b = Vec::new();
        let mut modified = Vec::new();
        for (path, vals_a) in &map_a {
            if let Some(vals_b) = map_b.get(path) {
                // Compare value counts as a simple change heuristic.
                if vals_a.len() == vals_b.len() {
                    let changed = vals_a.iter().zip(vals_b.iter()).any(|(va, vb)| {
                        va.name != vb.name || va.data != vb.data
                    });
                    if changed {
                        modified.push(path.clone());
                    }
                } else {
                    modified.push(path.clone());
                }
            } else {
                only_in_a.push(path.clone());
            }
        }
        for path in map_b.keys() {
            if !map_a.contains_key(path) {
                only_in_b.push(path.clone());
            }
        }
        Self { only_in_a, only_in_b, modified }
    }

    /// Total number of differences.
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.only_in_a.len() + self.only_in_b.len() + self.modified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_regf() -> Vec<u8> {
        let mut data = vec![0u8; 0x1000 + 32];
        // REGF signature
        data[0..4].copy_from_slice(b"regf");
        // sequence numbers
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        // last written timestamp (zeroed)
        // major / minor version
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..28].copy_from_slice(&5u32.to_le_bytes());
        // root cell offset
        data[36..40].copy_from_slice(&0u32.to_le_bytes());
        // hive bins data size
        data[40..44].copy_from_slice(&32u32.to_le_bytes());
        // filename (UTF-16LE "TEST")
        data[48] = b'T';
        data[50] = b'E';
        data[52] = b'S';
        data[54] = b'T';
        // hbin signature
        data[0x1000..0x1004].copy_from_slice(b"hbin");
        // hbin size = 32
        data[0x1008..0x100c].copy_from_slice(&32u32.to_le_bytes());
        data
    }

    #[test]
    fn parse_header_signature() {
        let data = minimal_regf();
        let hdr = HiveHeader::parse(&data).unwrap();
        assert_eq!(hdr.major_version, 1);
        assert_eq!(hdr.minor_version, 5);
        assert!(hdr.filename.contains('T'));
    }

    #[test]
    fn reject_bad_signature() {
        let mut data = minimal_regf();
        data[0] = 0;
        assert!(HiveHeader::parse(&data).is_err());
    }

    #[test]
    fn value_type_from_u32() {
        assert_eq!(ValueType::from_u32(1), ValueType::RegSz);
        assert_eq!(ValueType::from_u32(4), ValueType::RegDword);
    }

    #[test]
    fn hive_value_as_dword() {
        let v = HiveValue {
            name: "Test".into(),
            value_type: ValueType::RegDword,
            data: 42u32.to_le_bytes().to_vec(),
        };
        assert_eq!(v.as_dword(), Some(42));
    }

    #[test]
    fn hive_value_as_string() {
        let s = "Hello";
        let utf16: Vec<u8> = s
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0u8, 0u8])
            .collect();
        let v = HiveValue {
            name: "str".into(),
            value_type: ValueType::RegSz,
            data: utf16,
        };
        assert_eq!(v.as_string().as_deref(), Some("Hello"));
    }

    #[test]
    fn hive_value_hex_preview() {
        let v = HiveValue {
            name: "bin".into(),
            value_type: ValueType::RegBinary,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let hex = v.hex_preview();
        assert!(hex.contains("de"));
        assert!(hex.contains("ef"));
    }

    #[test]
    fn hive_value_formatter_dword() {
        let v = HiveValue {
            name: "d".into(),
            value_type: ValueType::RegDword,
            data: 255u32.to_le_bytes().to_vec(),
        };
        let s = HiveValueFormatter::format(&v);
        assert!(s.contains("255") || s.contains("ff"));
    }

    #[test]
    fn hive_key_last_write_approx() {
        let key = HiveKey {
            path: "ROOT".into(),
            name: "ROOT".into(),
            last_write_time: 132_000_000_000_000_000u64,
            values: Vec::new(),
            subkey_names: Vec::new(),
            class_name: None,
            sk_offset: 0,
        };
        let ts = key.last_write_utc_approx();
        assert!(ts.contains('T'));
    }

    #[test]
    fn enumerate_no_panic_on_empty_bins() {
        let data = minimal_regf();
        let analyzer = RegistryHiveAnalyzer::from_bytes(data).unwrap();
        let keys = analyzer.enumerate_all_keys();
        // No panic is the key assertion.
        let _ = keys;
    }
}
