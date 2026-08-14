//! Windows registry hive binary parser.
//!
//! Parses the on-disk format of Windows registry hives (REGF/HBIN) as written
//! by `ntoskrnl.exe`.  Supports NK (key), VK (value), and LF/LH/LI/RI
//! (subkey list) cells.

use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum HiveError {
    TooShort { needed: usize, got: usize },
    InvalidMagic { expected: &'static str, got: [u8; 4] },
    InvalidSignature { expected: &'static str, got: [u8; 2] },
    OffsetOutOfBounds { offset: u32 },
    InvalidData(String),
    Encoding(String),
    RecursionLimit,
}

impl fmt::Display for HiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => write!(f, "too short: need {needed}, got {got}"),
            Self::InvalidMagic { expected, got } => {
                write!(f, "bad magic: expected {expected}, got {:?}", std::str::from_utf8(got).unwrap_or("??"))
            }
            Self::InvalidSignature { expected, got } => {
                write!(f, "bad sig: expected {expected}, got {:?}", std::str::from_utf8(got).unwrap_or("??"))
            }
            Self::OffsetOutOfBounds { offset } => write!(f, "offset {offset:#x} out of bounds"),
            Self::InvalidData(s) => write!(f, "invalid data: {s}"),
            Self::Encoding(s) => write!(f, "encoding error: {s}"),
            Self::RecursionLimit => write!(f, "recursion limit reached"),
        }
    }
}

// ─── Constants ────────────────────────────────────────────────────────────────

/// Size of the REGF header.
pub const REGF_HEADER_SIZE: usize = 512;
/// Size of an HBIN page header.
pub const HBIN_HEADER_SIZE: usize = 32;
/// Offset of the hive data area (after the REGF header).
pub const HIVE_DATA_OFFSET: usize = 4096;
/// NK cell signature.
pub const NK_SIG: [u8; 2] = [0x6E, 0x6B]; // "nk"
/// VK cell signature.
pub const VK_SIG: [u8; 2] = [0x76, 0x6B]; // "vk"
/// LF list signature.
pub const LF_SIG: [u8; 2] = [0x6C, 0x66]; // "lf"
/// LH list signature.
pub const LH_SIG: [u8; 2] = [0x6C, 0x68]; // "lh"
/// LI list signature.
pub const LI_SIG: [u8; 2] = [0x6C, 0x69]; // "li"
/// RI list signature.
pub const RI_SIG: [u8; 2] = [0x72, 0x69]; // "ri"
/// SK cell signature.
pub const SK_SIG: [u8; 2] = [0x73, 0x6B]; // "sk"

/// Maximum recursion depth when traversing the key tree.
pub const MAX_RECURSION_DEPTH: usize = 512;

// ─── Registry data types ──────────────────────────────────────────────────────

/// Registry value data type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RegDataType {
    None = 0,
    Sz = 1,
    ExpandSz = 2,
    Binary = 3,
    Dword = 4,
    DwordBigEndian = 5,
    Link = 6,
    MultiSz = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    Qword = 11,
    Unknown(u32),
}

impl RegDataType {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Unknown(_) => "REG_UNKNOWN",
        }
    }
}

impl fmt::Display for RegDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── REGF header ─────────────────────────────────────────────────────────────

/// The 512-byte REGF hive header.
#[derive(Debug, Clone)]
pub struct RegHiveHeader {
    /// Signature "regf".
    pub magic: [u8; 4],
    /// Primary sequence number.
    pub seq1: u32,
    /// Secondary sequence number.
    pub seq2: u32,
    /// Last write time (Windows FILETIME).
    pub last_write_time: u64,
    /// Major format version.
    pub major_version: u32,
    /// Minor format version.
    pub minor_version: u32,
    /// Type: 0 = primary, 1 = log.
    pub hive_type: u32,
    /// Format: 1 = memory-mapped, 0 = file.
    pub hive_format: u32,
    /// Offset to the root NK cell (relative to hive data area start, i.e. after the 4096-byte header).
    pub root_cell_offset: u32,
    /// Total hive data size in bytes.
    pub hive_data_size: u32,
    /// Cluster factor.
    pub cluster_factor: u32,
    /// Filename (UTF-16LE, 64 bytes).
    pub filename: String,
    /// Header checksum (XOR of first 127 dwords).
    pub checksum: u32,
}

impl RegHiveHeader {
    pub fn parse(data: &[u8]) -> Result<Self, HiveError> {
        if data.len() < REGF_HEADER_SIZE {
            return Err(HiveError::TooShort { needed: REGF_HEADER_SIZE, got: data.len() });
        }
        let magic = [data[0], data[1], data[2], data[3]];
        if &magic != b"regf" {
            return Err(HiveError::InvalidMagic { expected: "regf", got: magic });
        }
        let seq1 = read_u32(data, 4);
        let seq2 = read_u32(data, 8);
        let last_write_time = read_u64(data, 12);
        let major_version = read_u32(data, 20);
        let minor_version = read_u32(data, 24);
        let hive_type = read_u32(data, 28);
        let hive_format = read_u32(data, 32);
        let root_cell_offset = read_u32(data, 36);
        let hive_data_size = read_u32(data, 40);
        let cluster_factor = read_u32(data, 44);
        // Filename: 64 bytes starting at offset 48 (UTF-16LE).
        let filename = decode_utf16le_limited(&data[48..112]);
        let checksum = read_u32(data, 508);
        Ok(Self {
            magic, seq1, seq2, last_write_time, major_version, minor_version,
            hive_type, hive_format, root_cell_offset, hive_data_size, cluster_factor,
            filename, checksum,
        })
    }

    /// Verify the header checksum.
    #[must_use] 
    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        if data.len() < 508 { return false; }
        let mut xor = 0u32;
        for i in 0..127 {
            xor ^= read_u32(data, i * 4);
        }
        xor == self.checksum
    }
}

// ─── HBIN page header ─────────────────────────────────────────────────────────

/// A single HBIN (hive bin) page header.
#[derive(Debug, Clone)]
pub struct HbinPage {
    /// Page offset within the hive data area.
    pub page_offset: u32,
    /// Page size in bytes (always a multiple of 4096).
    pub page_size: u32,
    /// Last write time of this page.
    pub last_write_time: u64,
    /// Cells contained within this page (parsed on demand).
    pub cell_count: usize,
}

impl HbinPage {
    /// Parse an HBIN header from `data` at `abs_offset` (absolute from hive start).
    pub fn parse(data: &[u8], abs_offset: usize) -> Result<Self, HiveError> {
        if abs_offset + HBIN_HEADER_SIZE > data.len() {
            return Err(HiveError::OffsetOutOfBounds { offset: abs_offset as u32 });
        }
        let sig = [data[abs_offset], data[abs_offset+1], data[abs_offset+2], data[abs_offset+3]];
        if &sig != b"hbin" {
            return Err(HiveError::InvalidMagic { expected: "hbin", got: sig });
        }
        let page_offset = read_u32(data, abs_offset + 4);
        let page_size = read_u32(data, abs_offset + 8);
        let last_write_time = read_u64(data, abs_offset + 16);
        // Count cells by walking the page.
        let cell_count = count_cells(data, abs_offset + HBIN_HEADER_SIZE, page_size as usize);
        Ok(Self { page_offset, page_size, last_write_time, cell_count })
    }
}

fn count_cells(data: &[u8], start: usize, page_size: usize) -> usize {
    let end = start + page_size.saturating_sub(HBIN_HEADER_SIZE).min(data.len().saturating_sub(start));
    let mut pos = start;
    let mut count = 0;
    while pos + 4 <= end && pos < data.len() {
        let raw_size = read_i32(data, pos);
        let cell_size = raw_size.unsigned_abs() as usize;
        if !(8..=0x10_0000).contains(&cell_size) { break; }
        count += 1;
        pos += cell_size;
    }
    count
}

// ─── NK cell ─────────────────────────────────────────────────────────────────

/// Flags on an NK cell.
#[derive(Debug, Clone, Copy)]
pub struct NkFlags(pub u16);

impl NkFlags {
    pub const ROOT_KEY: u16 = 0x0004;
    pub const LINK: u16 = 0x0002;
    pub const VOLATILE: u16 = 0x0001;
    pub const ASCII_KEY_NAME: u16 = 0x0020;

    #[must_use] 
    pub const fn is_root(self) -> bool { self.0 & Self::ROOT_KEY != 0 }
    #[must_use] 
    pub const fn is_link(self) -> bool { self.0 & Self::LINK != 0 }
    #[must_use] 
    pub const fn is_volatile(self) -> bool { self.0 & Self::VOLATILE != 0 }
    #[must_use] 
    pub const fn has_ascii_name(self) -> bool { self.0 & Self::ASCII_KEY_NAME != 0 }
}

/// A parsed NK (key) cell.
#[derive(Debug, Clone)]
pub struct NkCell {
    /// Absolute offset of this cell in the hive data.
    pub cell_offset: u32,
    /// NK flags.
    pub flags: NkFlags,
    /// Last write time.
    pub last_write_time: u64,
    /// Offset of the parent NK cell (0xFFFFFFFF for root).
    pub parent_offset: u32,
    /// Number of subkeys.
    pub subkey_count: u32,
    /// Offset of the stable subkey list.
    pub subkey_list_offset: u32,
    /// Number of values.
    pub value_count: u32,
    /// Offset of the value list.
    pub value_list_offset: u32,
    /// Class name offset (0xFFFFFFFF = none).
    pub class_name_offset: u32,
    /// Class name length in bytes.
    pub class_name_length: u16,
    /// Key name.
    pub name: String,
}

impl NkCell {
    /// Parse an NK cell from `data` at `abs_offset`.
    pub fn parse(data: &[u8], abs_offset: usize) -> Result<Self, HiveError> {
        if abs_offset + 76 > data.len() {
            return Err(HiveError::OffsetOutOfBounds { offset: abs_offset as u32 });
        }
        let sig = [data[abs_offset], data[abs_offset+1]];
        if sig != NK_SIG {
            return Err(HiveError::InvalidSignature { expected: "nk", got: sig });
        }
        let flags = NkFlags(read_u16(data, abs_offset + 2));
        let last_write_time = read_u64(data, abs_offset + 4);
        let parent_offset = read_u32(data, abs_offset + 16);
        let subkey_count = read_u32(data, abs_offset + 20);
        let subkey_list_offset = read_u32(data, abs_offset + 28);
        let value_count = read_u32(data, abs_offset + 36);
        let value_list_offset = read_u32(data, abs_offset + 40);
        let class_name_offset = read_u32(data, abs_offset + 52);
        let class_name_length = read_u16(data, abs_offset + 74);
        let name_length = read_u16(data, abs_offset + 72) as usize;

        let name_start = abs_offset + 76;
        let name = if name_start + name_length <= data.len() {
            if flags.has_ascii_name() {
                String::from_utf8_lossy(&data[name_start..name_start + name_length]).into_owned()
            } else {
                decode_utf16le_limited(&data[name_start..name_start + name_length])
            }
        } else {
            String::new()
        };

        Ok(Self {
            cell_offset: abs_offset as u32,
            flags,
            last_write_time,
            parent_offset,
            subkey_count,
            subkey_list_offset,
            value_count,
            value_list_offset,
            class_name_offset,
            class_name_length,
            name,
        })
    }
}

// ─── VK cell ─────────────────────────────────────────────────────────────────

/// A parsed VK (value) cell.
#[derive(Debug, Clone)]
pub struct VkCell {
    /// Absolute offset in the hive.
    pub cell_offset: u32,
    /// Value name.
    pub name: String,
    /// Data type.
    pub data_type: RegDataType,
    /// Raw data bytes.
    pub data: Vec<u8>,
    /// Whether the data is stored inline (≤ 4 bytes with flag 0x80000000).
    pub data_is_inline: bool,
}

impl VkCell {
    pub fn parse(data: &[u8], abs_offset: usize) -> Result<Self, HiveError> {
        if abs_offset + 24 > data.len() {
            return Err(HiveError::OffsetOutOfBounds { offset: abs_offset as u32 });
        }
        let sig = [data[abs_offset], data[abs_offset+1]];
        if sig != VK_SIG {
            return Err(HiveError::InvalidSignature { expected: "vk", got: sig });
        }
        let name_length = read_u16(data, abs_offset + 2) as usize;
        let data_size_raw = read_u32(data, abs_offset + 4);
        let data_offset_raw = read_u32(data, abs_offset + 8);
        let data_type_raw = read_u32(data, abs_offset + 12);
        let flags = read_u16(data, abs_offset + 16);
        let data_is_inline = (data_size_raw & 0x8000_0000) != 0;
        let data_size = (data_size_raw & 0x7FFF_FFFF) as usize;

        let name_start = abs_offset + 24;
        let name = if name_length > 0 && name_start + name_length <= data.len() {
            if flags & 1 != 0 {
                // ASCII name
                String::from_utf8_lossy(&data[name_start..name_start + name_length]).into_owned()
            } else {
                decode_utf16le_limited(&data[name_start..name_start + name_length])
            }
        } else {
            String::new() // default value
        };

        let parsed_data = if data_is_inline {
            // Inline data: stored in the offset field itself.
            data_offset_raw.to_le_bytes()[..data_size.min(4)].to_vec()
        } else {
            // External data: stored at data_offset within hive data area.
            let abs_data_off = HIVE_DATA_OFFSET + data_offset_raw as usize + 4; // skip cell size field
            if data_size == 0 {
                vec![]
            } else if abs_data_off + data_size <= data.len() {
                data[abs_data_off..abs_data_off + data_size].to_vec()
            } else {
                vec![]
            }
        };

        Ok(Self {
            cell_offset: abs_offset as u32,
            name,
            data_type: RegDataType::from_u32(data_type_raw),
            data: parsed_data,
            data_is_inline,
        })
    }

    /// Decode the value data as a `REG_SZ` string.
    #[must_use] 
    pub fn as_string(&self) -> Option<String> {
        match self.data_type {
            RegDataType::Sz | RegDataType::ExpandSz | RegDataType::Link => {
                Some(decode_utf16le_limited(&self.data))
            }
            _ => None,
        }
    }

    /// Decode the value data as a `REG_DWORD` u32.
    #[must_use] 
    pub fn as_dword(&self) -> Option<u32> {
        if self.data_type == RegDataType::Dword && self.data.len() >= 4 {
            Some(read_u32(&self.data, 0))
        } else {
            None
        }
    }

    /// Decode the value data as a `REG_QWORD` u64.
    #[must_use] 
    pub fn as_qword(&self) -> Option<u64> {
        if self.data_type == RegDataType::Qword && self.data.len() >= 8 {
            Some(read_u64(&self.data, 0))
        } else {
            None
        }
    }
}

// ─── SubkeyList ───────────────────────────────────────────────────────────────

/// The type of subkey list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubkeyListKind {
    Lf, Lh, Li, Ri,
}

/// A parsed subkey list (LF, LH, LI, or RI).
#[derive(Debug, Clone)]
pub struct SubkeyList {
    pub kind: SubkeyListKind,
    /// Cell offsets of the subkeys (relative to hive data area start).
    pub key_offsets: Vec<u32>,
}

impl SubkeyList {
    pub fn parse(data: &[u8], abs_offset: usize) -> Result<Self, HiveError> {
        if abs_offset + 4 > data.len() {
            return Err(HiveError::OffsetOutOfBounds { offset: abs_offset as u32 });
        }
        let sig = [data[abs_offset], data[abs_offset+1]];
        let kind = match sig {
            s if s == LF_SIG => SubkeyListKind::Lf,
            s if s == LH_SIG => SubkeyListKind::Lh,
            s if s == LI_SIG => SubkeyListKind::Li,
            s if s == RI_SIG => SubkeyListKind::Ri,
            _ => return Err(HiveError::InvalidSignature {
                expected: "lf/lh/li/ri", got: sig
            }),
        };
        let count_raw = read_u16(data, abs_offset + 2) as usize;
        // Cap count against the bytes actually remaining in `data` so an
        // attacker cannot force a huge allocation via a crafted count field.
        // Each entry is at least 4 bytes, so at most (remaining / 4) entries
        // can exist.  A hard cap of 65535 also prevents absurd allocations.
        let remaining_bytes = data.len().saturating_sub(abs_offset + 4);
        let count = count_raw.min(remaining_bytes / 4).min(65535);
        let mut key_offsets = Vec::with_capacity(count);
        match kind {
            SubkeyListKind::Lf | SubkeyListKind::Lh => {
                // Each entry: 4-byte offset + 4-byte hash.
                for i in 0..count {
                    let entry_off = abs_offset + 4 + i * 8;
                    if entry_off + 4 > data.len() { break; }
                    key_offsets.push(read_u32(data, entry_off));
                }
            }
            SubkeyListKind::Li => {
                // Each entry: 4-byte offset.
                for i in 0..count {
                    let entry_off = abs_offset + 4 + i * 4;
                    if entry_off + 4 > data.len() { break; }
                    key_offsets.push(read_u32(data, entry_off));
                }
            }
            SubkeyListKind::Ri => {
                // Each entry: 4-byte offset to sub-list.
                for i in 0..count {
                    let entry_off = abs_offset + 4 + i * 4;
                    if entry_off + 4 > data.len() { break; }
                    key_offsets.push(read_u32(data, entry_off));
                }
            }
        }
        Ok(Self { kind, key_offsets })
    }
}

// ─── RegHiveParser ────────────────────────────────────────────────────────────

/// Top-level parser for a Windows registry hive binary.
pub struct RegHiveParser<'a> {
    data: &'a [u8],
    pub header: RegHiveHeader,
}

impl<'a> RegHiveParser<'a> {
    /// Parse the REGF header and prepare the parser.
    pub fn new(data: &'a [u8]) -> Result<Self, HiveError> {
        let header = RegHiveHeader::parse(data)?;
        Ok(Self { data, header })
    }

    /// Absolute byte offset from the raw `data` slice for a hive-relative cell offset.
    const fn abs_offset(&self, cell_offset: u32) -> usize {
        // Guard against arithmetic overflow: saturate rather than wrap.
        HIVE_DATA_OFFSET
            .saturating_add(cell_offset as usize)
            .saturating_add(4) // skip cell size dword
    }

    /// Parse the root NK cell.
    pub fn root_key(&self) -> Result<NkCell, HiveError> {
        let off = self.abs_offset(self.header.root_cell_offset);
        NkCell::parse(self.data, off)
    }

    /// Parse an NK cell at a given hive-relative offset.
    pub fn nk_at(&self, cell_offset: u32) -> Result<NkCell, HiveError> {
        NkCell::parse(self.data, self.abs_offset(cell_offset))
    }

    /// Parse a VK cell at a given hive-relative offset.
    pub fn vk_at(&self, cell_offset: u32) -> Result<VkCell, HiveError> {
        VkCell::parse(self.data, self.abs_offset(cell_offset))
    }

    /// Parse a subkey list at a given hive-relative offset.
    pub fn subkey_list_at(&self, cell_offset: u32) -> Result<SubkeyList, HiveError> {
        SubkeyList::parse(self.data, self.abs_offset(cell_offset))
    }

    /// List all direct child key names under an NK cell.
    #[must_use] 
    pub fn child_key_names(&self, nk: &NkCell) -> Vec<String> {
        if nk.subkey_count == 0 || nk.subkey_list_offset == 0xFFFF_FFFF {
            return vec![];
        }
        let Ok(list) = self.subkey_list_at(nk.subkey_list_offset) else { return vec![] };
        list.key_offsets.iter().filter_map(|&off| {
            self.nk_at(off).ok().map(|c| c.name)
        }).collect()
    }

    /// Parse all values under an NK cell.
    #[must_use] 
    pub fn values_of(&self, nk: &NkCell) -> Vec<VkCell> {
        if nk.value_count == 0 || nk.value_list_offset == 0xFFFF_FFFF {
            return vec![];
        }
        let list_off = self.abs_offset(nk.value_list_offset);
        // Clamp capacity to a safe bound; each value offset is 4 bytes so the list
        // cannot exceed (remaining_bytes / 4) entries.
        let max_possible = self.data.len().saturating_sub(list_off) / 4;
        let safe_cap = (nk.value_count as usize).min(max_possible).min(65536);
        let mut values = Vec::with_capacity(safe_cap);
        for i in 0..nk.value_count as usize {
            let vk_off_abs = list_off + i * 4;
            if vk_off_abs + 4 > self.data.len() { break; }
            let vk_rel = read_u32(self.data, vk_off_abs);
            if let Ok(vk) = self.vk_at(vk_rel) {
                values.push(vk);
            }
        }
        values
    }

    /// Recursively enumerate all keys as (path, `NkCell`) pairs.
    #[must_use] 
    pub fn enumerate_keys(&self) -> Vec<(String, NkCell)> {
        let mut result = Vec::new();
        if let Ok(root) = self.root_key() {
            self.enumerate_keys_recursive(&root, String::new(), &mut result, 0);
        }
        result
    }

    fn enumerate_keys_recursive(
        &self,
        nk: &NkCell,
        prefix: String,
        out: &mut Vec<(String, NkCell)>,
        depth: usize,
    ) {
        if depth > MAX_RECURSION_DEPTH { return; }
        let path = if prefix.is_empty() {
            nk.name.clone()
        } else {
            format!("{}\\{}", prefix, nk.name)
        };
        out.push((path.clone(), nk.clone()));
        if nk.subkey_count == 0 || nk.subkey_list_offset == 0xFFFF_FFFF { return; }
        let Ok(list) = self.subkey_list_at(nk.subkey_list_offset) else { return };
        for &off in &list.key_offsets {
            if let Ok(child) = self.nk_at(off) {
                self.enumerate_keys_recursive(&child, path.clone(), out, depth + 1);
            }
        }
    }

    /// Parse all HBIN pages and return them.
    #[must_use] 
    pub fn hbin_pages(&self) -> Vec<HbinPage> {
        let mut pages = Vec::new();
        let mut off = HIVE_DATA_OFFSET;
        while off + HBIN_HEADER_SIZE <= self.data.len() {
            if &self.data[off..off+4] != b"hbin" { break; }
            match HbinPage::parse(self.data, off) {
                Ok(p) => {
                    let next = off + p.page_size as usize;
                    pages.push(p);
                    if next <= off { break; }
                    off = next;
                }
                Err(_) => break,
            }
        }
        pages
    }

    /// Build a flat map of {path -> `HashMap`<`value_name`, `VkCell`>}.
    #[must_use] 
    pub fn flat_key_value_map(&self) -> HashMap<String, HashMap<String, VkCell>> {
        let mut map = HashMap::new();
        for (path, nk) in self.enumerate_keys() {
            let values = self.values_of(&nk);
            let mut val_map = HashMap::new();
            for vk in values {
                val_map.insert(vk.name.clone(), vk);
            }
            map.insert(path, val_map);
        }
        map
    }
}

// ─── Primitive readers ────────────────────────────────────────────────────────

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() { return 0; }
    u64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ])
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off+1]])
}

fn read_i32(data: &[u8], off: usize) -> i32 {
    if off + 4 > data.len() { return 0; }
    i32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}

fn decode_utf16le_limited(bytes: &[u8]) -> String {
    let pairs = bytes.len() / 2;
    let chars: Vec<u16> = (0..pairs).map(|i| u16::from_le_bytes([bytes[i*2], bytes[i*2+1]])).collect();
    let nul_pos = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
    String::from_utf16_lossy(&chars[..nul_pos])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regf_header(root_offset: u32) -> Vec<u8> {
        let mut data = vec![0u8; 4096 + 32]; // REGF + minimal hive space
        data[0..4].copy_from_slice(b"regf");
        data[4..8].copy_from_slice(&1u32.to_le_bytes());  // seq1
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // seq2
        data[36..40].copy_from_slice(&root_offset.to_le_bytes());
        data[40..44].copy_from_slice(&4096u32.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes()); // major
        data[24..28].copy_from_slice(&5u32.to_le_bytes()); // minor
        // Compute checksum.
        let mut xor = 0u32;
        for i in 0..127 { xor ^= read_u32(&data, i * 4); }
        data[508..512].copy_from_slice(&xor.to_le_bytes());
        data
    }

    #[test]
    fn test_regf_parse_magic() {
        let data = make_regf_header(32);
        let h = RegHiveHeader::parse(&data).unwrap();
        assert_eq!(&h.magic, b"regf");
        assert_eq!(h.major_version, 1);
        assert_eq!(h.root_cell_offset, 32);
    }

    #[test]
    fn test_regf_invalid_magic() {
        let mut data = make_regf_header(0);
        data[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(RegHiveHeader::parse(&data), Err(HiveError::InvalidMagic { .. })));
    }

    #[test]
    fn test_regf_checksum() {
        let data = make_regf_header(32);
        let h = RegHiveHeader::parse(&data).unwrap();
        assert!(h.verify_checksum(&data));
    }

    #[test]
    fn test_reg_data_type_from_u32() {
        assert_eq!(RegDataType::from_u32(1), RegDataType::Sz);
        assert_eq!(RegDataType::from_u32(4), RegDataType::Dword);
        assert!(matches!(RegDataType::from_u32(999), RegDataType::Unknown(999)));
    }

    #[test]
    fn test_reg_data_type_display() {
        assert_eq!(RegDataType::Sz.to_string(), "REG_SZ");
        assert_eq!(RegDataType::Dword.to_string(), "REG_DWORD");
    }

    #[test]
    fn test_vk_dword_inline() {
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(&VK_SIG); // "vk"
        // name_length = 0
        // data_size = 4 | inline flag
        let size = 4u32 | 0x8000_0000u32;
        data[4..8].copy_from_slice(&size.to_le_bytes());
        // data_offset (inline value) = 0x0000_0042
        data[8..12].copy_from_slice(&0x42u32.to_le_bytes());
        // data_type = REG_DWORD = 4
        data[12..16].copy_from_slice(&4u32.to_le_bytes());
        data[16..18].copy_from_slice(&0u16.to_le_bytes()); // flags
        let vk = VkCell::parse(&data, 0).unwrap();
        assert!(vk.data_is_inline);
        assert_eq!(vk.data_type, RegDataType::Dword);
        assert_eq!(vk.as_dword(), Some(0x42));
    }

    #[test]
    fn test_nk_flags() {
        let f = NkFlags(NkFlags::ROOT_KEY | NkFlags::ASCII_KEY_NAME);
        assert!(f.is_root());
        assert!(!f.is_link());
        assert!(f.has_ascii_name());
    }

    #[test]
    fn test_subkey_list_li_parse() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&LI_SIG);
        data[2..4].copy_from_slice(&2u16.to_le_bytes()); // count = 2
        data[4..8].copy_from_slice(&100u32.to_le_bytes());
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        let list = SubkeyList::parse(&data, 0).unwrap();
        assert_eq!(list.kind, SubkeyListKind::Li);
        assert_eq!(list.key_offsets, vec![100, 200]);
    }

    #[test]
    fn test_decode_utf16le_limited() {
        let s = "hello";
        let encoded: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(decode_utf16le_limited(&encoded), "hello");
    }

    #[test]
    fn test_hive_too_short() {
        assert!(matches!(RegHiveHeader::parse(&[]), Err(HiveError::TooShort { .. })));
    }
}
