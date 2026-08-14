//! Windows Registry forensics: SAM hive parser, NTUSER.DAT analysis,
//! `RunKeys`, `UserAssist` decode, Shellbag decode, and MRU lists.
//!
//! # Layer distinction
//! This module is the **high-level artifact extractor**: it interprets the key
//! and value data already parsed by [`crate::registry_hive_plugin`] (REGF
//! cell-level parser) and turns it into typed forensics artifacts such as SAM
//! user accounts, `UserAssist` entries, Shellbag paths, and MRU lists.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Map of registry value name -> serialised value bytes, suitable for callers
/// building flat snapshots of a single hive key.
pub type RegistryValueMap = HashMap<String, Vec<u8>>;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid hive magic at offset {0}")]
    InvalidMagic(usize),
    #[error("truncated hive at offset {0}")]
    Truncated(usize),
    #[error("unsupported hive version {major}.{minor}")]
    UnsupportedVersion { major: u32, minor: u32 },
    #[error("corrupt cell at offset {offset}: {reason}")]
    CorruptCell { offset: usize, reason: String },
    #[error("ROT13 decode error: {0}")]
    Rot13Error(String),
}

// ─── Hive base block ──────────────────────────────────────────────────────────

/// The 512-byte base block at the start of every Windows registry hive file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveBaseBlock {
    /// "regf" magic signature.
    pub signature: [u8; 4],
    /// Sequence number (primary).
    pub sequence1: u32,
    /// Sequence number (secondary).
    pub sequence2: u32,
    /// Last write timestamp (Windows FILETIME).
    pub last_written: u64,
    /// Major version (must be 1).
    pub major_version: u32,
    /// Minor version (9–6 = pre-Vista; 3/5 = Vista+).
    pub minor_version: u32,
    /// Type (0 = primary, 1 = log).
    pub file_type: u32,
    /// Format (1 = direct memory load).
    pub format: u32,
    /// Root cell offset (relative to first hbin).
    pub root_cell_offset: u32,
    /// Total size of hive data.
    pub hive_bins_data_size: u32,
    /// Hive file name (UTF-16LE, max 64 chars).
    pub filename: String,
    /// GUID of the hive.
    pub guid: [u8; 16],
    /// Checksum of the base block.
    pub checksum: u32,
}

impl HiveBaseBlock {
    pub const MAGIC: &'static [u8; 4] = b"regf";
    pub const SIZE: usize = 512;

    /// Parse a hive base block from a 512-byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn parse(data: &[u8]) -> Result<Self, RegistryError> {
        if data.len() < Self::SIZE {
            return Err(RegistryError::Truncated(0));
        }
        let mut sig = [0u8; 4];
        sig.copy_from_slice(&data[0..4]);
        if &sig != Self::MAGIC {
            return Err(RegistryError::InvalidMagic(0));
        }
        let sequence1 = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let sequence2 = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let last_written = u64::from_le_bytes(data[12..20].try_into().unwrap());
        let major_version = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let minor_version = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let file_type = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let format = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let root_cell_offset = u32::from_le_bytes(data[36..40].try_into().unwrap());
        let hive_bins_data_size = u32::from_le_bytes(data[40..44].try_into().unwrap());
        // Filename is UTF-16LE at offset 48, length 64 WCHARs (128 bytes)
        let fname_bytes = &data[48..176];
        let filename = decode_utf16le(fname_bytes);
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[176..192]);
        let checksum = u32::from_le_bytes(data[508..512].try_into().unwrap());

        if major_version != 1 {
            return Err(RegistryError::UnsupportedVersion {
                major: major_version,
                minor: minor_version,
            });
        }
        Ok(Self {
            signature: sig,
            sequence1,
            sequence2,
            last_written,
            major_version,
            minor_version,
            file_type,
            format,
            root_cell_offset,
            hive_bins_data_size,
            filename,
            guid,
            checksum,
        })
    }

    /// Verify that sequence1 == sequence2 (hive is not dirty).
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.sequence1 == self.sequence2
    }

    /// Return the last-write time as Unix epoch seconds.
    #[must_use]
    pub const fn last_written_unix(&self) -> i64 {
        const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
        ((self.last_written.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
    }
}

fn decode_utf16le(data: &[u8]) -> String {
    let shorts: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&shorts)
}

// ─── Named key (nk) cell ──────────────────────────────────────────────────────

/// A named-key cell — the core node type of the registry B-tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedKey {
    /// "nk" signature.
    pub signature: [u8; 2],
    /// Flags: `KEY_VOLATILE` (0x01), `KEY_HIVE_ENTRY` (0x04), `KEY_HIVE_EXIT` (0x08),
    ///         `KEY_NO_DELETE` (0x10), `KEY_SYM_LINK` (0x20), `KEY_COMP_NAME` (0x20),
    ///         `KEY_PREDEFINED_HANDLE` (0x40)
    pub flags: u16,
    /// Last write timestamp.
    pub last_written: u64,
    /// Offset to parent nk cell.
    pub parent_offset: u32,
    /// Number of direct child subkeys.
    pub subkey_count: u32,
    /// Offset to subkey list.
    pub subkey_list_offset: u32,
    /// Number of values in this key.
    pub value_count: u32,
    /// Offset to value list.
    pub value_list_offset: u32,
    /// Offset to security descriptor cell.
    pub security_offset: u32,
    /// Offset to class name.
    pub classname_offset: u32,
    /// Length of the key name.
    pub name_length: u16,
    /// Key name (ASCII or Unicode depending on `KEY_COMP_NAME` flag).
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
    pub name: String,
}

impl NamedKey {
    pub const MAGIC: &'static [u8; 2] = b"nk";

    /// Parse a named-key cell from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the cell signature is invalid.
    ///
    /// # Panics
    ///
    /// Panics if internal slice conversion fails (should not happen when data is valid).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, RegistryError> {
        if offset + 76 > data.len() {
            return Err(RegistryError::Truncated(offset));
        }
        let cell = &data[offset..];
        let mut sig = [0u8; 2];
        sig.copy_from_slice(&cell[0..2]);
        if &sig != Self::MAGIC {
            return Err(RegistryError::CorruptCell {
                offset,
                reason: format!("expected 'nk', got {sig:?}"),
            });
        }
        let flags = u16::from_le_bytes(cell[2..4].try_into().unwrap());
        let last_written = u64::from_le_bytes(cell[4..12].try_into().unwrap());
        let parent_offset = u32::from_le_bytes(cell[16..20].try_into().unwrap());
        let subkey_count = u32::from_le_bytes(cell[20..24].try_into().unwrap());
        let subkey_list_offset = u32::from_le_bytes(cell[28..32].try_into().unwrap());
        let value_count = u32::from_le_bytes(cell[36..40].try_into().unwrap());
        let value_list_offset = u32::from_le_bytes(cell[40..44].try_into().unwrap());
        let security_offset = u32::from_le_bytes(cell[44..48].try_into().unwrap());
        let classname_offset = u32::from_le_bytes(cell[48..52].try_into().unwrap());
        let name_length = u16::from_le_bytes(cell[72..74].try_into().unwrap()) as usize;
        let name_len_clamped = name_length
            .min(256)
            .min(data.len().saturating_sub(offset + 76));
        let is_ascii = flags & 0x20 != 0;
        let name_bytes = &cell[76..76 + name_len_clamped];
        let name = if is_ascii {
            String::from_utf8_lossy(name_bytes).to_string()
        } else {
            decode_utf16le(name_bytes)
        };
        Ok(Self {
            signature: sig,
            flags,
            last_written,
            parent_offset,
            subkey_count,
            subkey_list_offset,
            value_count,
            value_list_offset,
            security_offset,
            classname_offset,
            name_length: u16::try_from(name_length).unwrap_or(u16::MAX),
            name,
        })
    }

    #[must_use]
    pub const fn last_written_unix(&self) -> i64 {
        const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
        ((self.last_written.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
    }
}

// ─── Value key (vk) cell ──────────────────────────────────────────────────────

/// Registry value data types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueType {
    RegNone,
    RegSz,
    RegExpandSz,
    RegBinary,
    RegDword,
    RegDwordBigEndian,
    RegLink,
    RegMultiSz,
    RegResourceList,
    RegFullResourceDescriptor,
    RegResourceRequirements,
    RegQword,
    Unknown(u32),
}

impl RegValueType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
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
            10 => Self::RegResourceRequirements,
            11 => Self::RegQword,
            n => Self::Unknown(n),
        }
    }
}

/// A single registry value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: RegValueType,
    /// Raw data bytes (up to 65535 bytes).
    pub data: Vec<u8>,
}

impl RegistryValue {
    /// Interpret the value as a `REG_SZ` / `REG_EXPAND_SZ` string.
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self.value_type {
            RegValueType::RegSz | RegValueType::RegExpandSz | RegValueType::RegLink => {
                Some(decode_utf16le(&self.data))
            }
            _ => None,
        }
    }

    /// Interpret the value as a `REG_DWORD` (little-endian u32).
    #[must_use]
    pub fn as_dword(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes(self.data[..4].try_into().ok()?))
        } else {
            None
        }
    }

    /// Interpret the value as a `REG_QWORD` (little-endian u64).
    #[must_use]
    pub fn as_qword(&self) -> Option<u64> {
        if self.data.len() >= 8 {
            Some(u64::from_le_bytes(self.data[..8].try_into().ok()?))
        } else {
            None
        }
    }

    /// Interpret a `REG_MULTI_SZ` as a list of strings.
    #[must_use]
    pub fn as_multi_sz(&self) -> Vec<String> {
        if self.value_type != RegValueType::RegMultiSz || self.data.len() < 2 {
            return vec![];
        }
        let shorts: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut result = Vec::new();
        let mut current = Vec::new();
        for &w in &shorts {
            if w == 0 {
                if !current.is_empty() {
                    result.push(String::from_utf16_lossy(&current));
                    current.clear();
                }
            } else {
                current.push(w);
            }
        }
        result
    }
}

// ─── SAM hive parsing ─────────────────────────────────────────────────────────

/// SAM account flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamAccountFlags {
    pub disabled: bool,
    pub password_not_required: bool,
    pub password_cannot_change: bool,
    pub password_does_not_expire: bool,
    pub locked_out: bool,
}

impl SamAccountFlags {
    #[must_use]
    pub const fn from_u32(flags: u32) -> Self {
        Self {
            disabled: flags & 0x0001 != 0,
            password_not_required: flags & 0x0020 != 0,
            password_cannot_change: flags & 0x0040 != 0,
            password_does_not_expire: flags & 0x0200 != 0,
            locked_out: flags & 0x0010 != 0,
        }
    }
}

/// A user account extracted from the SAM hive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamUser {
    pub rid: u32,
    pub username: String,
    pub full_name: String,
    pub comment: String,
    pub account_flags: SamAccountFlags,
    pub last_login: i64,
    pub last_password_change: i64,
    pub bad_password_count: u16,
    pub logon_count: u16,
    /// NT hash in hex (32 chars).
    pub nt_hash_hex: String,
    /// LM hash in hex (32 chars, may be empty/disabled).
    pub lm_hash_hex: String,
}

impl SamUser {
    /// The well-known empty NT hash (blank password).
    pub const EMPTY_NT_HASH: &'static str = "31d6cfe0d16ae931b73c59d7e0c089c0";
    /// The well-known disabled LM hash.
    pub const DISABLED_LM_HASH: &'static str = "aad3b435b51404eeaad3b435b51404ee";

    /// Returns `true` if the account has a blank password.
    /// Comparison is constant-time to prevent timing side-channels.
    #[must_use]
    pub fn has_blank_password(&self) -> bool {
        if self.nt_hash_hex.len() != Self::EMPTY_NT_HASH.len() {
            return false;
        }
        let is_blank: bool = self
            .nt_hash_hex
            .as_bytes()
            .ct_eq(Self::EMPTY_NT_HASH.as_bytes())
            .into();
        is_blank
    }

    /// Returns `true` if the LM hash is disabled (all-AA pattern).
    /// Comparison is constant-time to prevent timing side-channels.
    #[must_use]
    pub fn lm_disabled(&self) -> bool {
        if self.lm_hash_hex.is_empty() {
            return true;
        }
        if self.lm_hash_hex.len() != Self::DISABLED_LM_HASH.len() {
            return false;
        }
        let is_disabled: bool = self
            .lm_hash_hex
            .as_bytes()
            .ct_eq(Self::DISABLED_LM_HASH.as_bytes())
            .into();
        is_disabled
    }
}

// ─── UserAssist decoder ───────────────────────────────────────────────────────

/// A `UserAssist` entry — records GUI program execution via ROT-13 encoded keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAssistEntry {
    /// Decoded (ROT-13 reversed) program path.
    pub program_path: String,
    /// Number of times the program was launched.
    pub run_count: u32,
    /// Focus count (time window application was focused).
    pub focus_count: u32,
    /// Total focus time in milliseconds.
    pub focus_time_ms: u32,
    /// Last execution timestamp (Windows FILETIME).
    pub last_executed: i64,
}

impl UserAssistEntry {
    /// ROT-13 decode a string (`UserAssist` keys are ROT-13 encoded).
    #[must_use]
    pub fn rot13_decode(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                _ => c,
            })
            .collect()
    }

    /// Parse a `UserAssist` binary value (64-byte `USERASSIST_ENTRY` structure).
    #[must_use]
    pub fn parse_value(encoded_name: &str, data: &[u8]) -> Option<Self> {
        // Windows FILETIME epoch offset (100-ns intervals from 1601-01-01 to 1970-01-01)
        const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
        if data.len() < 64 {
            return None;
        }
        // USERASSIST_ENTRY layout (Vista+):
        // [0x00] session_id (u32)
        // [0x04] run_count (u32) — subtract 5 from raw value
        // [0x08] focus_count (u32)
        // [0x0c] focus_time_ms (u32)
        // [0x48] last_executed (FILETIME, u64)
        let run_count_raw = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let run_count = run_count_raw.saturating_sub(5);
        let focus_count = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let focus_time_ms = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let last_exec_ft = if data.len() >= 0x50 {
            u64::from_le_bytes(data[0x48..0x50].try_into().ok()?)
        } else {
            0u64
        };
        let last_executed = ((last_exec_ft.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed();
        Some(Self {
            program_path: Self::rot13_decode(encoded_name),
            run_count,
            focus_count,
            focus_time_ms,
            last_executed,
        })
    }
}

// ─── Shellbag decoder ─────────────────────────────────────────────────────────

/// A Shellbag entry — records folder navigation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellbagEntry {
    /// Reconstructed folder path.
    pub path: String,
    /// Registry key last-write time (approximates last access).
    pub last_interacted: i64,
    /// Bag MRU order index.
    pub bag_index: u32,
}

/// Parser for `ShellNoRoam`\\`BagMRU` and related keys.
pub struct ShellbagParser;

impl ShellbagParser {
    /// Extract a folder name from a raw shell item ID list (SHITEMID).
    /// This is a simplified parser that looks for ASCII/Unicode runs.
    #[must_use]
    pub fn decode_shitemid(data: &[u8]) -> String {
        if data.len() < 3 {
            return String::new();
        }
        // Item type byte at offset 2
        let item_type = data[2];
        match item_type {
            // 0x1F = special folder, 0x2F/0x23 = drive, 0x31/0x32 = file system
            0x31 | 0x32 | 0x35 | 0x36 => {
                // File system item: short name starts at offset 12
                if data.len() < 16 {
                    return String::new();
                }
                let nul = data[12..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(data.len() - 12);
                String::from_utf8_lossy(&data[12..12 + nul]).to_string()
            }
            0x2F | 0x23 => {
                // Drive letter
                if data.len() < 6 {
                    return String::new();
                }
                let d = data[3] as char;
                format!("{d}:")
            }
            _ => {
                // Generic: scan for printable ASCII run
                let mut run = Vec::new();
                for &b in &data[3..] {
                    if b.is_ascii_graphic() || b == b' ' {
                        run.push(b);
                    } else if run.len() > 2 {
                        break;
                    }
                }
                String::from_utf8_lossy(&run).to_string()
            }
        }
    }
}

// ─── Run key scanner ──────────────────────────────────────────────────────────

/// Well-known Run/RunOnce registry key paths.
pub const RUN_KEY_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\Classes\Exefile\Shell\Open\Command",
];

/// A single Run key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunKeyEntry {
    pub hive_path: String,
    pub key_path: String,
    pub value_name: String,
    pub command: String,
    pub suspicious: bool,
}

impl RunKeyEntry {
    /// Heuristically flag suspicious run entries.
    #[must_use]
    pub fn is_suspicious(command: &str) -> bool {
        let lower = command.to_lowercase();
        // Executables in non-standard locations
        let suspicious_paths = [
            r"c:\users",
            r"c:\temp",
            r"c:\programdata",
            r"%temp%",
            r"%appdata%",
            r"%userprofile%\downloads",
            "powershell",
            "wscript",
            "cscript",
            "mshta",
            "regsvr32",
            "rundll32",
            "certutil",
            "-enc",
        ];
        suspicious_paths.iter().any(|p| lower.contains(p))
    }
}

// ─── MRU list parser ──────────────────────────────────────────────────────────

/// An MRU (Most Recently Used) list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MruEntry {
    pub key_path: String,
    pub order_index: u32,
    pub value: String,
    pub mru_type: MruType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MruType {
    /// Run dialog MRU (`RunMRU` registry key).
    RunMru,
    /// Recently opened documents (`RecentDocs` registry key).
    RecentDocs,
    /// Open/Save dialog (`OpenSavePidlMRU` / `OpenSaveMRU` registry key).
    OpenSave,
    /// Typed URLs and paths (`TypedPaths` registry key).
    TypedPaths,
    /// Explorer search history
    SearchHistory,
    Other(String),
}

impl MruType {
    #[must_use]
    pub fn from_key_path(path: &str) -> Self {
        let lower = path.to_lowercase();
        if lower.contains("runmru") {
            return Self::RunMru;
        }
        if lower.contains("recentdocs") {
            return Self::RecentDocs;
        }
        if lower.contains("opensave") {
            return Self::OpenSave;
        }
        if lower.contains("typedpaths") {
            return Self::TypedPaths;
        }
        if lower.contains("worddwheel") || lower.contains("search") {
            return Self::SearchHistory;
        }
        Self::Other(path.to_string())
    }
}

// ─── NTUSER.DAT artifact collector ────────────────────────────────────────────

/// Aggregated artifacts from an NTUSER.DAT hive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtUserArtifacts {
    pub username: String,
    pub run_entries: Vec<RunKeyEntry>,
    pub userassist_entries: Vec<UserAssistEntry>,
    pub shellbag_entries: Vec<ShellbagEntry>,
    pub mru_entries: Vec<MruEntry>,
    pub typed_urls: Vec<String>,
    pub recent_docs: Vec<String>,
}

impl NtUserArtifacts {
    #[must_use]
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            run_entries: Vec::new(),
            userassist_entries: Vec::new(),
            shellbag_entries: Vec::new(),
            mru_entries: Vec::new(),
            typed_urls: Vec::new(),
            recent_docs: Vec::new(),
        }
    }

    /// Count suspicious artifacts across all categories.
    #[must_use]
    pub fn suspicious_count(&self) -> usize {
        self.run_entries.iter().filter(|e| e.suspicious).count()
    }

    /// Return all programs that were run, sorted by `run_count` descending.
    #[must_use]
    pub fn top_programs(&self, limit: usize) -> Vec<&UserAssistEntry> {
        let mut sorted: Vec<&UserAssistEntry> = self.userassist_entries.iter().collect();
        sorted.sort_by(|a, b| b.run_count.cmp(&a.run_count));
        sorted.truncate(limit);
        sorted
    }
}

// ─── Raw hive scanner ─────────────────────────────────────────────────────────

/// Scan a raw byte slice for registry artifact markers.
/// Used when a full hive parser is not available (e.g., memory dump triage).
pub struct RawHiveScanner;

impl RawHiveScanner {
    /// Scan for Run key command strings (look for ".exe" preceded by a path).
    #[must_use]
    pub fn scan_run_commands(data: &[u8]) -> Vec<String> {
        let mut commands = Vec::new();
        let marker = b".exe";
        let mut pos = 0usize;
        while pos + marker.len() <= data.len() {
            if data[pos..].starts_with(marker) {
                // Walk backward to find start of path
                let start = data[..pos]
                    .iter()
                    .rev()
                    .position(|&b| !(0x20..=0x7e).contains(&b))
                    .map_or(0, |i| pos.saturating_sub(i));
                let end = pos + marker.len();
                if let Ok(s) = std::str::from_utf8(&data[start..end])
                    && s.len() > 4 {
                        commands.push(s.to_string());
                    }
                pos = end;
            } else {
                pos += 1;
            }
        }
        commands
    }

    /// Scan for typed URL strings in HKCU `TypedURLs` key data.
    #[must_use]
    pub fn scan_typed_urls(data: &[u8]) -> Vec<String> {
        let prefixes: &[&[u8]] = &[b"http://", b"https://", b"ftp://", b"file://"];
        let mut urls = Vec::new();
        for prefix in prefixes {
            let mut pos = 0usize;
            while pos + prefix.len() < data.len() {
                if data[pos..].starts_with(prefix) {
                    let end = data[pos..]
                        .iter()
                        .position(|&b| b == 0 || b < 0x20).map_or_else(|| data.len().min(pos + 2048), |i| pos + i);
                    if let Ok(s) = std::str::from_utf8(&data[pos..end])
                        && s.len() > 8 {
                            urls.push(s.to_string());
                        }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    /// Scan for the "regf" hive signatures and return their offsets.
    #[must_use]
    pub fn find_hive_offsets(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let sig = b"regf";
        let mut pos = 0usize;
        while pos + 4 <= data.len() {
            if data[pos..].starts_with(sig) {
                offsets.push(pos);
                pos += 512; // skip to next likely candidate
            } else {
                pos += 4;
            }
        }
        offsets
    }

    /// Scan for SAM hive user account markers.
    /// SAM stores user data under SAM\Domains\Account\Users\<RID>.
    #[must_use]
    pub fn scan_sam_rids(data: &[u8]) -> Vec<u32> {
        let mut rids = Vec::new();
        // RID keys are stored as 8-hex-digit strings like "000001F4" (500)
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            let slice = &data[pos..pos + 8];
            if slice.iter().all(u8::is_ascii_hexdigit)
                && let Ok(s) = std::str::from_utf8(slice)
                    && let Ok(rid) = u32::from_str_radix(s, 16)
                        && (500..65536).contains(&rid) {
                            rids.push(rid);
                        }
            pos += 1;
        }
        rids.sort_unstable();
        rids.dedup();
        rids
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_base_block_parse_valid() {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(b"regf");
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // sequence1
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // sequence2
        data[20..24].copy_from_slice(&1u32.to_le_bytes()); // major_version
        data[24..28].copy_from_slice(&3u32.to_le_bytes()); // minor_version
        data[508..512].copy_from_slice(&0xABCDu32.to_le_bytes());
        let block = HiveBaseBlock::parse(&data).unwrap();
        assert_eq!(block.major_version, 1);
        assert_eq!(block.minor_version, 3);
        assert!(block.is_clean());
    }

    #[test]
    fn hive_base_block_invalid_magic() {
        let data = vec![0u8; 512];
        assert!(HiveBaseBlock::parse(&data).is_err());
    }

    #[test]
    fn hive_base_block_wrong_major() {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(b"regf");
        data[20..24].copy_from_slice(&2u32.to_le_bytes()); // invalid major
        let err = HiveBaseBlock::parse(&data).unwrap_err();
        assert!(matches!(
            err,
            RegistryError::UnsupportedVersion { major: 2, .. }
        ));
    }

    #[test]
    fn rot13_decode_roundtrip() {
        let encoded = "Zvpebfbsg";
        assert_eq!(UserAssistEntry::rot13_decode(encoded), "Microsoft");
        let re_encoded = UserAssistEntry::rot13_decode("Microsoft");
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn userassist_parse_value() {
        let mut data = vec![0u8; 72];
        // run_count = 7 (raw = 12, stored = count + 5)
        data[4..8].copy_from_slice(&12u32.to_le_bytes());
        data[8..12].copy_from_slice(&3u32.to_le_bytes()); // focus_count
        data[12..16].copy_from_slice(&5000u32.to_le_bytes()); // focus_time_ms
        let entry = UserAssistEntry::parse_value("PBZCHGRE.RKR", &data).unwrap();
        assert_eq!(entry.run_count, 7);
        assert_eq!(entry.program_path, "COMPUTER.EXE");
    }

    #[test]
    fn run_key_suspicious_detection() {
        assert!(RunKeyEntry::is_suspicious(r"C:\Users\Public\malware.exe"));
        assert!(RunKeyEntry::is_suspicious("powershell -enc dGVzdA=="));
        assert!(!RunKeyEntry::is_suspicious(
            r"C:\Windows\System32\notepad.exe"
        ));
    }

    #[test]
    fn registry_value_as_string() {
        let val = RegistryValue {
            name: "test".into(),
            value_type: RegValueType::RegSz,
            data: {
                let s = "hello";
                let mut utf16: Vec<u8> = s
                    .encode_utf16()
                    .flat_map(|w| w.to_le_bytes().to_vec())
                    .collect();
                utf16.extend_from_slice(&[0, 0]);
                utf16
            },
        };
        assert_eq!(val.as_string().unwrap(), "hello");
    }

    #[test]
    fn registry_value_as_dword() {
        let val = RegistryValue {
            name: "count".into(),
            value_type: RegValueType::RegDword,
            data: 42u32.to_le_bytes().to_vec(),
        };
        assert_eq!(val.as_dword(), Some(42));
    }

    #[test]
    fn mru_type_from_key_path() {
        assert_eq!(
            MruType::from_key_path(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            ),
            MruType::RunMru
        );
        assert_eq!(
            MruType::from_key_path(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            ),
            MruType::RecentDocs
        );
    }

    #[test]
    fn sam_user_blank_password() {
        let u = SamUser {
            rid: 500,
            username: "Administrator".into(),
            full_name: String::new(),
            comment: String::new(),
            account_flags: SamAccountFlags::from_u32(0),
            last_login: 0,
            last_password_change: 0,
            bad_password_count: 0,
            logon_count: 1,
            nt_hash_hex: SamUser::EMPTY_NT_HASH.into(),
            lm_hash_hex: SamUser::DISABLED_LM_HASH.into(),
        };
        assert!(u.has_blank_password());
        assert!(u.lm_disabled());
    }

    #[test]
    fn account_flags_parsing() {
        let f = SamAccountFlags::from_u32(0x0001 | 0x0200);
        assert!(f.disabled);
        assert!(f.password_does_not_expire);
        assert!(!f.locked_out);
    }

    #[test]
    fn raw_hive_scanner_finds_hive_offsets() {
        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(b"regf");
        data[1024..1028].copy_from_slice(b"regf");
        let offsets = RawHiveScanner::find_hive_offsets(&data);
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&1024));
    }

    #[test]
    fn raw_hive_scanner_typed_urls() {
        let data = b"\x00\x00https://google.com\x00http://evil.com/bad\x00garbage";
        let urls = RawHiveScanner::scan_typed_urls(data);
        assert!(urls.iter().any(|u| u.contains("google.com")));
        assert!(urls.iter().any(|u| u.contains("evil.com")));
    }

    #[test]
    fn shellbag_decode_drive() {
        let mut item = vec![0u8; 10];
        item[2] = 0x23; // drive type
        item[3] = b'C';
        let name = ShellbagParser::decode_shitemid(&item);
        assert_eq!(name, "C:");
    }

    #[test]
    fn reg_value_type_conversion() {
        assert_eq!(RegValueType::from_u32(1), RegValueType::RegSz);
        assert_eq!(RegValueType::from_u32(4), RegValueType::RegDword);
        assert_eq!(RegValueType::from_u32(99), RegValueType::Unknown(99));
    }
}
