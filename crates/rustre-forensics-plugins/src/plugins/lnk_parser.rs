//! Windows Shell Link (.lnk) / shortcut file parser.
//!
//! Implements the MS-SHLLINK specification covering:
//! - Shell Link Header
//! - `LinkTargetIDList`
//! - `LinkInfo` block (local/UNC paths, drive type, serial)
//! - `StringData` (Name, `RelativePath`, `WorkingDir`, Arguments, `IconLocation`)
//! - `ExtraData` blocks (Tracker, `SpecialFolder`, Console, `ExpandEnvironment`, etc.)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LnkError {
    #[error("invalid LNK magic: expected {SHELL_LINK_MAGIC:?}")]
    InvalidMagic,
    #[error("invalid CLSID: expected Shell Link CLSID")]
    InvalidClsid,
    #[error("truncated LNK file: need {need} bytes at offset {offset}")]
    Truncated { need: usize, offset: usize },
    #[error("LinkInfo block too small: {0}")]
    LinkInfoTooSmall(usize),
    #[error("unsupported code page: {0}")]
    UnsupportedCodePage(u32),
}

// ─── Magic values ─────────────────────────────────────────────────────────────

/// Shell Link file header magic (4 bytes, always 0x0000004C).
const SHELL_LINK_MAGIC: u32 = 0x0000_004C;

/// Shell Link CLSID: {00021401-0000-0000-C000-000000000046}
const SHELL_LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// ─── Drive type ───────────────────────────────────────────────────────────────

/// Drive type values from the `LinkInfo` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriveType {
    Unknown,
    NoRootDir,
    Removable,
    Fixed,
    Remote,
    CdRom,
    RamDisk,
}

impl DriveType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::NoRootDir,
            2 => Self::Removable,
            3 => Self::Fixed,
            4 => Self::Remote,
            5 => Self::CdRom,
            6 => Self::RamDisk,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Unknown => "Unknown",
            Self::NoRootDir => "NoRootDir",
            Self::Removable => "Removable",
            Self::Fixed => "Fixed",
            Self::Remote => "Remote",
            Self::CdRom => "CdRom",
            Self::RamDisk => "RamDisk",
        }
    }
}

// ─── Bitflags lite macro ──────────────────────────────────────────────────────

/// Minimal bitflags-like macro to avoid a crate dependency.
macro_rules! bitflags_lite {
    (pub struct $name:ident: $ty:ty {
        $(const $field:ident = $val:expr;)*
    }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(pub $ty);
        impl $name {
            $(pub const $field: Self = Self($val);)*

            pub fn contains(self, other: Self) -> bool { self.0 & other.0 != 0 }
            pub fn bits(self) -> $ty { self.0 }
        }
        impl From<$ty> for $name {
            fn from(v: $ty) -> Self { Self(v) }
        }
    };
    ($(#[$outer:meta])* pub struct $name:ident: $ty:ty {
        $($(#[$inner:meta])* const $field:ident = $val:expr;)*
    }) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(pub $ty);
        impl $name {
            $($(#[$inner])* pub const $field: Self = Self($val);)*

            pub const fn contains(self, other: Self) -> bool { self.0 & other.0 != 0 }
            pub const fn bits(self) -> $ty { self.0 }
        }
        impl From<$ty> for $name {
            fn from(v: $ty) -> Self { Self(v) }
        }
    };
}

// ─── Header flags ─────────────────────────────────────────────────────────────

bitflags_lite! {
    /// Shell Link Header flags.
    pub struct LinkFlags: u32 {
        const HAS_LINK_TARGET_ID_LIST  = 0x0000_0001;
        const HAS_LINK_INFO            = 0x0000_0002;
        const HAS_NAME                 = 0x0000_0004;
        const HAS_RELATIVE_PATH        = 0x0000_0008;
        const HAS_WORKING_DIR          = 0x0000_0010;
        const HAS_ARGUMENTS            = 0x0000_0020;
        const HAS_ICON_LOCATION        = 0x0000_0040;
        const IS_UNICODE               = 0x0000_0080;
        const FORCE_NO_LINK_INFO       = 0x0000_0100;
        const HAS_EXP_STRING           = 0x0000_0200;
        const RUN_IN_SEPARATE_PROCESS  = 0x0000_0400;
        const HAS_DARWIN_ID            = 0x0000_1000;
        const RUN_AS_USER              = 0x0000_2000;
        const HAS_EXP_ICON             = 0x0000_4000;
        const NO_PIDL_ALIAS            = 0x0000_8000;
        const RUN_WITH_SHIM_LAYER      = 0x0002_0000;
        const FORCE_NO_LINK_TRACK      = 0x0004_0000;
        const ENABLE_TARGET_METADATA   = 0x0008_0000;
        const DISABLE_LINK_PATH_TRACKING = 0x0010_0000;
        const DISABLE_KNOWN_FOLDER_TRACKING = 0x0020_0000;
        const DISABLE_KNOWN_FOLDER_ALIAS  = 0x0040_0000;
        const ALLOW_LINK_TO_LINK       = 0x0080_0000;
        const UNALIAS_ON_SAVE          = 0x0100_0000;
        const PREFER_ENVIRONMENT_PATH  = 0x0200_0000;
        const KEEP_LOCAL_IDLIST_FOR_UNC_TARGET = 0x0400_0000;
    }
}

// ─── File attributes ──────────────────────────────────────────────────────────

/// File attribute flags from the Shell Link Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttributes {
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
}

impl FileAttributes {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        Self {
            read_only: v & 0x0001 != 0,
            hidden: v & 0x0002 != 0,
            system: v & 0x0004 != 0,
            directory: v & 0x0010 != 0,
            archive: v & 0x0020 != 0,
            normal: v & 0x0080 != 0,
            temporary: v & 0x0100 != 0,
            sparse: v & 0x0200 != 0,
            reparse_point: v & 0x0400 != 0,
            compressed: v & 0x0800 != 0,
            offline: v & 0x1000 != 0,
            not_content_indexed: v & 0x2000 != 0,
            encrypted: v & 0x4000 != 0,
        }
    }
}

// ─── Shell Link Header ────────────────────────────────────────────────────────

/// The 76-byte Shell Link Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLinkHeader {
    /// Always 76.
    pub header_size: u32,
    /// Shell Link CLSID.
    pub link_clsid: [u8; 16],
    /// Link flags.
    pub link_flags: LinkFlags,
    /// File attributes of the link target.
    pub file_attributes: FileAttributes,
    /// Creation time of the link target (FILETIME).
    pub creation_time: u64,
    /// Access time (FILETIME).
    pub access_time: u64,
    /// Write time (FILETIME).
    pub write_time: u64,
    /// File size of the link target (low 32 bits).
    pub file_size: u32,
    /// Icon index.
    pub icon_index: i32,
    /// Show window command (SW_*).
    pub show_command: u32,
    /// Hot key virtual key code (low byte).
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
    pub hot_key: u16,
}

impl ShellLinkHeader {
    pub const SIZE: usize = 76;

    /// Parse a shell link header from `data`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the header magic is missing.
    ///
    /// # Panics
    ///
    /// Panics if internal slice conversion fails (should not happen when data is valid).
    pub fn parse(data: &[u8]) -> Result<Self, LnkError> {
        if data.len() < Self::SIZE {
            return Err(LnkError::Truncated {
                need: Self::SIZE,
                offset: 0,
            });
        }
        let header_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if header_size < 76 {
            return Err(LnkError::Truncated {
                need: 76,
                offset: 0,
            });
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        // Actually the magic is the header_size == 0x4C, and the CLSID follows
        if magic != 0x4C {
            return Err(LnkError::InvalidMagic);
        }
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&data[4..20]);
        if clsid != SHELL_LINK_CLSID {
            return Err(LnkError::InvalidClsid);
        }
        let link_flags = LinkFlags(u32::from_le_bytes(data[20..24].try_into().unwrap()));
        let file_attr_raw = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let creation_time = u64::from_le_bytes(data[28..36].try_into().unwrap());
        let access_time = u64::from_le_bytes(data[36..44].try_into().unwrap());
        let write_time = u64::from_le_bytes(data[44..52].try_into().unwrap());
        let file_size = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let icon_index = i32::from_le_bytes(data[56..60].try_into().unwrap());
        let show_command = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let hot_key = u16::from_le_bytes(data[64..66].try_into().unwrap());
        Ok(Self {
            header_size,
            link_clsid: clsid,
            link_flags,
            file_attributes: FileAttributes::from_u32(file_attr_raw),
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_command,
            hot_key,
        })
    }

    #[must_use]
    pub const fn creation_time_unix(&self) -> i64 {
        filetime_to_unix(self.creation_time)
    }
    #[must_use]
    pub const fn access_time_unix(&self) -> i64 {
        filetime_to_unix(self.access_time)
    }
    #[must_use]
    pub const fn write_time_unix(&self) -> i64 {
        filetime_to_unix(self.write_time)
    }
}

const fn filetime_to_unix(ft: u64) -> i64 {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    ((ft.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
}

// ─── LinkInfo block ───────────────────────────────────────────────────────────

/// Parsed `LinkInfo` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    pub link_info_size: u32,
    pub local_base_path: String,
    pub common_path_suffix: String,
    pub volume_label: String,
    pub drive_type: DriveType,
    pub drive_serial_number: u32,
    pub unc_share_name: String,
    /// Whether the target was on a local volume.
    pub has_local_base_path: bool,
    /// Whether the target was on a network share.
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
    pub has_unc_share: bool,
}

impl LinkInfo {
    pub const HEADER_SIZE: usize = 28;

    /// Parse link info from `data`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the link-info size is invalid.
    ///
    /// # Panics
    ///
    /// Panics if internal slice conversion fails (should not happen when data is valid).
    pub fn parse(data: &[u8]) -> Result<Self, LnkError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(LnkError::LinkInfoTooSmall(data.len()));
        }
        let link_info_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let size = link_info_size as usize;
        if size < Self::HEADER_SIZE || size > data.len() {
            return Err(LnkError::LinkInfoTooSmall(size));
        }
        let flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let vol_info_offset = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let local_base_offset = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let unc_share_offset = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let common_suffix_offset = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

        let has_local_base_path = flags & 0x01 != 0;
        let has_unc_share = flags & 0x02 != 0;

        // Volume information block starts at vol_info_offset within data
        let (drive_type, drive_serial_number, volume_label) = if vol_info_offset + 16 <= size {
            let vi = &data[vol_info_offset..];
            let _vi_size = u32::from_le_bytes(vi[0..4].try_into().unwrap_or([0; 4]));
            let dtype_raw = u32::from_le_bytes(vi[4..8].try_into().unwrap_or([0; 4]));
            let serial = u32::from_le_bytes(vi[8..12].try_into().unwrap_or([0; 4]));
            let label_off = u32::from_le_bytes(vi[12..16].try_into().unwrap_or([0; 4])) as usize;
            let label = read_nul_str(vi, label_off);
            (DriveType::from_u32(dtype_raw), serial, label)
        } else {
            (DriveType::Unknown, 0, String::new())
        };

        let local_base_path = if has_local_base_path && local_base_offset < size {
            read_nul_str(data, local_base_offset)
        } else {
            String::new()
        };

        let common_path_suffix = if common_suffix_offset < size {
            read_nul_str(data, common_suffix_offset)
        } else {
            String::new()
        };

        let unc_share_name = if has_unc_share && unc_share_offset < size {
            read_nul_str(data, unc_share_offset)
        } else {
            String::new()
        };

        Ok(Self {
            link_info_size,
            local_base_path,
            common_path_suffix,
            volume_label,
            drive_type,
            drive_serial_number,
            unc_share_name,
            has_local_base_path,
            has_unc_share,
        })
    }

    /// Reconstruct the full target path.
    #[must_use]
    pub fn target_path(&self) -> String {
        if !self.local_base_path.is_empty() {
            if self.common_path_suffix.is_empty() {
                self.local_base_path.clone()
            } else {
                format!("{}\\{}", self.local_base_path, self.common_path_suffix)
            }
        } else if !self.unc_share_name.is_empty() {
            if self.common_path_suffix.is_empty() {
                self.unc_share_name.clone()
            } else {
                format!("{}\\{}", self.unc_share_name, self.common_path_suffix)
            }
        } else {
            String::new()
        }
    }
}

fn read_nul_str(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let end = end.min(4096);
    String::from_utf8_lossy(&slice[..end]).to_string()
}

fn read_utf16le_nul(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let shorts: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&shorts)
}

// ─── StringData ───────────────────────────────────────────────────────────────

/// All string fields from the `StringData` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringData {
    pub name_string: String,
    pub relative_path: String,
    pub working_dir: String,
    pub command_line_arguments: String,
    pub icon_location: String,
}

impl StringData {
    /// Parse `StringData` from the LNK file.
    /// `offset` is the position right after the `LinkInfo` block.
    /// `is_unicode` controls whether strings are UTF-16LE or ANSI.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize, flags: LinkFlags, is_unicode: bool) -> Self {
        let mut sd = Self::default();
        let mut pos = offset;

        macro_rules! read_str_field {
            ($flag:expr, $field:expr) => {
                if flags.contains($flag) {
                    if let Some((s, n)) = read_counted_string(data, pos, is_unicode) {
                        $field = s;
                        pos += n;
                    }
                }
            };
        }

        read_str_field!(LinkFlags::HAS_NAME, sd.name_string);
        read_str_field!(LinkFlags::HAS_RELATIVE_PATH, sd.relative_path);
        read_str_field!(LinkFlags::HAS_WORKING_DIR, sd.working_dir);
        read_str_field!(LinkFlags::HAS_ARGUMENTS, sd.command_line_arguments);
        read_str_field!(LinkFlags::HAS_ICON_LOCATION, sd.icon_location);
        // Truncate any trailing fields if the final cursor walked past the
        // buffer end — indicates a malformed/truncated LNK and the consumer
        // should disregard partial captures.
        if pos > data.len() {
            sd = Self::default();
        }
        sd
    }
}

/// Read a counted string (u16 count, then characters).
/// Returns `(string, bytes_consumed)` or `None` if out-of-bounds.
fn read_counted_string(data: &[u8], offset: usize, unicode: bool) -> Option<(String, usize)> {
    if offset + 2 > data.len() {
        return None;
    }
    let count = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
    if unicode {
        // Use checked_mul to prevent integer overflow when count is u16::MAX.
        let byte_len = count.checked_mul(2)?;
        if offset + 2 + byte_len > data.len() {
            return None;
        }
        let shorts: Vec<u16> = data[offset + 2..offset + 2 + byte_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some((String::from_utf16_lossy(&shorts), 2 + byte_len))
    } else {
        let byte_len = count;
        if offset + 2 + byte_len > data.len() {
            return None;
        }
        Some((
            String::from_utf8_lossy(&data[offset + 2..offset + 2 + byte_len]).to_string(),
            2 + byte_len,
        ))
    }
}

// ─── ExtraData ────────────────────────────────────────────────────────────────

/// Known `ExtraData` block signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtraDataSignature {
    ConsoleProps,
    ConsoleFEProps,
    DarwinProps,
    EnvironmentProps,
    IconEnvironmentProps,
    KnownFolderProps,
    PropertyStoreProps,
    ShimLayerProps,
    SpecialFolderProps,
    TrackerProps,
    VistaAndAboveIdListProps,
    Unknown(u32),
}

impl ExtraDataSignature {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0xA000_0002 => Self::ConsoleProps,
            0xA000_0004 => Self::ConsoleFEProps,
            0xA000_0006 => Self::DarwinProps,
            0xA000_0001 => Self::EnvironmentProps,
            0xA000_0007 => Self::IconEnvironmentProps,
            0xA000_000B => Self::KnownFolderProps,
            0xA000_0009 => Self::PropertyStoreProps,
            0xA000_0008 => Self::ShimLayerProps,
            0xA000_0005 => Self::SpecialFolderProps,
            0xA000_0003 => Self::TrackerProps,
            0xA000_000C => Self::VistaAndAboveIdListProps,
            n => Self::Unknown(n),
        }
    }
}

/// A single `ExtraData` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraDataBlock {
    pub block_size: u32,
    pub signature: ExtraDataSignature,
    pub raw_data: Vec<u8>,
    /// Decoded string fields, if applicable.
    pub decoded: HashMap<String, String>,
}

impl ExtraDataBlock {
    /// Parse all `ExtraData` blocks from the given offset.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    #[must_use]
    pub fn parse_all(data: &[u8], offset: usize) -> Vec<Self> {
        let mut blocks = Vec::new();
        let mut pos = offset;
        loop {
            if pos + 8 > data.len() {
                break;
            }
            let block_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            if block_size < 8 {
                break;
            }
            let sig_raw = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
            let sig = ExtraDataSignature::from_u32(sig_raw);
            let raw_end = (pos + block_size as usize).min(data.len());
            let raw_data = data[pos + 8..raw_end].to_vec();
            let decoded = Self::decode_block(&sig, &raw_data);
            blocks.push(Self {
                block_size,
                signature: sig,
                raw_data,
                decoded,
            });
            pos += block_size as usize;
            if pos >= data.len() {
                break;
            }
        }
        blocks
    }

    fn decode_block(sig: &ExtraDataSignature, data: &[u8]) -> HashMap<String, String> {
        let mut m = HashMap::new();
        match sig {
            ExtraDataSignature::TrackerProps => {
                // TrackerProps: version(4), machine_id(16), droid1_a(16), droid1_b(16), ...
                if data.len() >= 4 {
                    let ver = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
                    m.insert("version".into(), ver.to_string());
                }
                if data.len() >= 20 {
                    let machine = read_nul_str(data, 4);
                    if !machine.is_empty() {
                        m.insert("machine_id".into(), machine);
                    }
                }
            }
            ExtraDataSignature::EnvironmentProps | ExtraDataSignature::IconEnvironmentProps => {
                // CountedString of the target path
                if data.len() > 4 {
                    let target = read_nul_str(data, 4);
                    m.insert("target_ansi".into(), target);
                    let unicode_target = read_utf16le_nul(data, 4 + 260);
                    if !unicode_target.is_empty() {
                        m.insert("target_unicode".into(), unicode_target);
                    }
                }
            }
            ExtraDataSignature::SpecialFolderProps
                if data.len() >= 8 => {
                    let folder_id = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
                    m.insert("special_folder_id".into(), folder_id.to_string());
                    m.insert(
                        "folder_name".into(),
                        known_folder_name(folder_id).to_string(),
                    );
                }
            _ => {}
        }
        m
    }
}

const fn known_folder_name(id: u32) -> &'static str {
    match id {
        0x0000 => "DESKTOP",
        0x0002 => "PROGRAMS",
        0x0005 => "PERSONAL",
        0x0006 => "FAVORITES",
        0x0007 => "STARTUP",
        0x0008 => "RECENT",
        0x0009 => "SENDTO",
        0x000B => "STARTMENU",
        0x000E => "MYMUSIC",
        0x0010 => "MYVIDEOS",
        0x0012 => "NETHOOD",
        0x0014 => "FONTS",
        0x0015 => "TEMPLATES",
        0x001C => "APPDATA",
        0x001D => "PRINTHOOD",
        0x001E => "LOCAL_APPDATA",
        0x0021 => "INTERNET_CACHE",
        0x0023 => "COOKIES",
        0x0024 => "HISTORY",
        0x0025 => "COMMON_APPDATA",
        0x0026 => "WINDOWS",
        0x0027 => "SYSTEM",
        0x0028 => "PROGRAM_FILES",
        0x002A => "SYSTEM_X86",
        0x002B => "PROGRAM_FILES_X86",
        0x002E => "COMMON_DOCUMENTS",
        _ => "UNKNOWN",
    }
}

// ─── Full parsed LNK file ─────────────────────────────────────────────────────

/// A fully parsed Shell Link (.lnk) file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLink {
    pub header: ShellLinkHeader,
    pub id_list_size: Option<u16>,
    pub link_info: Option<LinkInfo>,
    pub string_data: StringData,
    pub extra_data: Vec<ExtraDataBlock>,
}

impl ShellLink {
    /// Parse a Shell Link file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn parse(data: &[u8]) -> Result<Self, LnkError> {
        let header = ShellLinkHeader::parse(data)?;
        let mut pos = ShellLinkHeader::SIZE;

        // Optional LinkTargetIDList
        let id_list_size = if header
            .link_flags
            .contains(LinkFlags::HAS_LINK_TARGET_ID_LIST)
        {
            if pos + 2 > data.len() {
                return Err(LnkError::Truncated {
                    need: pos + 2,
                    offset: pos,
                });
            }
            let sz = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
            pos += 2 + sz as usize;
            Some(sz)
        } else {
            None
        };

        // Optional LinkInfo
        let link_info = if header.link_flags.contains(LinkFlags::HAS_LINK_INFO) {
            if pos + 4 > data.len() {
                return Err(LnkError::Truncated {
                    need: pos + 4,
                    offset: pos,
                });
            }
            let li_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let li = LinkInfo::parse(&data[pos..pos + li_size.min(data.len() - pos)])?;
            pos += li_size;
            Some(li)
        } else {
            None
        };

        // StringData
        let is_unicode = header.link_flags.contains(LinkFlags::IS_UNICODE);
        let string_data = StringData::parse(data, pos, header.link_flags, is_unicode);

        // Approximate end of StringData by scanning forward
        let extra_start = find_extra_data_start(data, pos, &header);
        let extra_data = ExtraDataBlock::parse_all(data, extra_start);

        Ok(Self {
            header,
            id_list_size,
            link_info,
            string_data,
            extra_data,
        })
    }

    /// Return the resolved target path (best effort).
    #[must_use]
    pub fn target_path(&self) -> String {
        if let Some(ref li) = self.link_info {
            let p = li.target_path();
            if !p.is_empty() {
                return p;
            }
        }
        if !self.string_data.relative_path.is_empty() {
            return self.string_data.relative_path.clone();
        }
        String::new()
    }

    /// Return a flat summary map suitable for `PluginOutput` rows.
    #[must_use]
    pub fn to_row(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("target_path".into(), self.target_path());
        m.insert(
            "creation_time".into(),
            self.header.creation_time_unix().to_string(),
        );
        m.insert(
            "write_time".into(),
            self.header.write_time_unix().to_string(),
        );
        m.insert(
            "access_time".into(),
            self.header.access_time_unix().to_string(),
        );
        m.insert("file_size".into(), self.header.file_size.to_string());
        m.insert("icon_index".into(), self.header.icon_index.to_string());
        m.insert("show_command".into(), self.header.show_command.to_string());
        m.insert(
            "arguments".into(),
            self.string_data.command_line_arguments.clone(),
        );
        m.insert("working_dir".into(), self.string_data.working_dir.clone());
        m.insert(
            "icon_location".into(),
            self.string_data.icon_location.clone(),
        );
        if let Some(ref li) = self.link_info {
            m.insert("drive_type".into(), li.drive_type.as_str().to_string());
            m.insert(
                "drive_serial".into(),
                format!("{:#010x}", li.drive_serial_number),
            );
            m.insert("volume_label".into(), li.volume_label.clone());
        }
        m
    }

    /// Check whether this LNK file exhibits suspicious characteristics.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        let target = self.target_path().to_lowercase();
        // Pointing to PowerShell, wscript, cmd, mshta etc.
        let suspicious_targets = [
            "powershell",
            "wscript",
            "cscript",
            "mshta",
            "cmd.exe",
            "rundll32",
        ];
        for t in &suspicious_targets {
            if target.contains(t) {
                return true;
            }
        }
        // Arguments with base64 or -enc
        let args = self.string_data.command_line_arguments.to_lowercase();
        if args.contains("-enc")
            || args.contains("-encodedcommand")
            || args.contains("downloadstring")
            || args.contains("iex")
        {
            return true;
        }
        // File in temp / appdata locations
        if target.contains("\\temp\\")
            || target.contains("\\appdata\\")
            || target.contains("\\public\\")
        {
            return true;
        }
        false
    }
}

fn find_extra_data_start(data: &[u8], from: usize, _header: &ShellLinkHeader) -> usize {
    // Heuristic: scan for a u32 with value 0xA000_0xxx
    let mut pos = from;
    while pos + 8 <= data.len() {
        let candidate = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4]));
        if (8..0x10000).contains(&candidate) {
            let sig = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4]));
            if sig & 0xF000_0000 == 0xA000_0000 {
                return pos;
            }
        }
        pos += 2;
    }
    pos
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lnk_header_bytes() -> Vec<u8> {
        let mut data = vec![0u8; 76];
        data[0..4].copy_from_slice(&76u32.to_le_bytes()); // header_size
        data[4..20].copy_from_slice(&SHELL_LINK_CLSID);
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // no flags
        data[60..64].copy_from_slice(&1u32.to_le_bytes()); // SW_NORMAL
        data
    }

    #[test]
    fn parse_shell_link_header_valid() {
        let data = make_lnk_header_bytes();
        let hdr = ShellLinkHeader::parse(&data).unwrap();
        assert_eq!(hdr.header_size, 76);
        assert_eq!(hdr.link_clsid, SHELL_LINK_CLSID);
        assert_eq!(hdr.show_command, 1);
    }

    #[test]
    fn parse_shell_link_header_invalid_magic() {
        let mut data = make_lnk_header_bytes();
        data[0..4].copy_from_slice(&99u32.to_le_bytes()); // wrong size
        assert!(ShellLinkHeader::parse(&data).is_err());
    }

    #[test]
    fn parse_shell_link_header_invalid_clsid() {
        let mut data = make_lnk_header_bytes();
        data[4..20].fill(0xAB);
        assert!(ShellLinkHeader::parse(&data).is_err());
    }

    #[test]
    fn drive_type_conversion() {
        assert_eq!(DriveType::from_u32(2), DriveType::Removable);
        assert_eq!(DriveType::from_u32(3), DriveType::Fixed);
        assert_eq!(DriveType::from_u32(99), DriveType::Unknown);
        assert_eq!(DriveType::Fixed.as_str(), "Fixed");
    }

    #[test]
    fn file_attributes_parsing() {
        let fa = FileAttributes::from_u32(0x0020 | 0x0002 | 0x0001);
        assert!(fa.archive);
        assert!(fa.hidden);
        assert!(fa.read_only);
        assert!(!fa.directory);
    }

    #[test]
    fn link_info_parse_minimal() {
        let mut data = vec![0u8; 28];
        data[0..4].copy_from_slice(&28u32.to_le_bytes()); // link_info_size
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // flags: no local, no unc
        let li = LinkInfo::parse(&data).unwrap();
        assert!(!li.has_local_base_path);
        assert!(!li.has_unc_share);
        assert_eq!(li.target_path(), "");
    }

    #[test]
    fn extra_data_signature_known() {
        assert_eq!(
            ExtraDataSignature::from_u32(0xA000_0003),
            ExtraDataSignature::TrackerProps
        );
        assert_eq!(
            ExtraDataSignature::from_u32(0xA000_0005),
            ExtraDataSignature::SpecialFolderProps
        );
    }

    #[test]
    fn extra_data_parse_empty() {
        let data = vec![0u8; 8];
        let blocks = ExtraDataBlock::parse_all(&data, 0);
        assert!(blocks.is_empty());
    }

    #[test]
    fn counted_string_unicode() {
        // "AB" as UTF-16LE
        let data: Vec<u8> = vec![
            2, 0, // count = 2 chars
            b'A', 0, b'B', 0,
        ];
        let (s, n) = read_counted_string(&data, 0, true).unwrap();
        assert_eq!(s, "AB");
        assert_eq!(n, 6);
    }

    #[test]
    fn counted_string_ansi() {
        let data = vec![3, 0, b'f', b'o', b'o'];
        let (s, n) = read_counted_string(&data, 0, false).unwrap();
        assert_eq!(s, "foo");
        assert_eq!(n, 5);
    }

    #[test]
    fn known_folder_names() {
        assert_eq!(known_folder_name(0x001C), "APPDATA");
        assert_eq!(known_folder_name(0x0026), "WINDOWS");
        assert_eq!(known_folder_name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn suspicious_lnk_detection() {
        let mut link = ShellLink {
            header: ShellLinkHeader::parse(&make_lnk_header_bytes()).unwrap(),
            id_list_size: None,
            link_info: None,
            string_data: StringData {
                name_string: String::new(),
                relative_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
                working_dir: String::new(),
                command_line_arguments: "-EncodedCommand dGVzdA==".into(),
                icon_location: String::new(),
            },
            extra_data: vec![],
        };
        assert!(link.is_suspicious());
        link.string_data.relative_path = r"C:\Windows\Notepad.exe".into();
        link.string_data.command_line_arguments = String::new();
        assert!(!link.is_suspicious());
    }
}
