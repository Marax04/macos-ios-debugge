//! Windows Registry Hive Parser Plugin
//!
//! Parses raw REGF-format registry hive bytes, reconstructing the key/value
//! tree and providing search, export, and deleted-key recovery capabilities.
//!
//! # Layer distinction
//! This module is the **low-level structural parser**: it decodes NK/VK/SK/LF
//! cells and reconstructs the full key tree from a REGF hive binary.  The
//! complementary high-level artifact module lives in
//! [`crate::plugins::registry_artifacts`] and implements SAM user extraction,
//! `UserAssist` decode, Shellbag parsing, Run-key scanning, and MRU lists.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum HiveError {
    InvalidMagic(String),
    BufferTooSmall { needed: usize, available: usize },
    InvalidCellOffset(u32),
    UnknownCellType([u8; 2]),
    InvalidUtf16,
    CorruptStructure(String),
}

impl fmt::Display for HiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(s) => write!(f, "Invalid magic: {s}"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "Buffer too small: need {needed}, have {available}")
            }
            Self::InvalidCellOffset(off) => write!(f, "Invalid cell offset: 0x{off:08x}"),
            Self::UnknownCellType(t) => {
                write!(f, "Unknown cell type: {:?}", std::str::from_utf8(t))
            }
            Self::InvalidUtf16 => write!(f, "Invalid UTF-16 sequence"),
            Self::CorruptStructure(s) => write!(f, "Corrupt structure: {s}"),
        }
    }
}

// ─── Hive type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveType {
    /// HKLM\SYSTEM
    System,
    /// HKLM\SOFTWARE
    Software,
    /// HKLM\SAM
    Sam,
    /// HKLM\SECURITY
    Security,
    /// HKCU (NTUSER.DAT)
    NtUser,
    /// Unknown / generic
    Unknown,
}

impl HiveType {
    fn detect(root_name: &str) -> Self {
        match root_name.to_uppercase().as_str() {
            n if n.contains("SYSTEM") => Self::System,
            n if n.contains("SOFTWARE") => Self::Software,
            n if n.contains("SAM") => Self::Sam,
            n if n.contains("SECURITY") => Self::Security,
            n if n.contains("NTUSER") || n.contains("$$$PROTO.HIV") => Self::NtUser,
            _ => Self::Unknown,
        }
    }
}

// ─── Registry data types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegDataType {
    None,
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiSz,
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    Qword,
}

impl RegDataType {
    const fn from_u32(n: u32) -> Self {
        match n {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            _ => Self::Binary,
        }
    }
}

// ─── Registry value ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RegValue {
    None,
    String(String),
    ExpandString(String),
    Binary(Vec<u8>),
    Dword(u32),
    DwordBigEndian(u32),
    Link(String),
    MultiString(Vec<String>),
    Qword(u64),
    Unknown { data_type: u32, data: Vec<u8> },
}

impl fmt::Display for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "(none)"),
            Self::String(s) | Self::ExpandString(s) | Self::Link(s) => {
                write!(f, "{s}")
            }
            Self::Binary(b) => {
                let hex: String = b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
                write!(f, "{hex}")
            }
            Self::Dword(n) => write!(f, "0x{n:08x}"),
            Self::DwordBigEndian(n) => write!(f, "0x{n:08x} (BE)"),
            Self::MultiString(v) => write!(f, "{}", v.join("|")),
            Self::Qword(n) => write!(f, "0x{n:016x}"),
            Self::Unknown { data_type, data } => {
                write!(f, "type={data_type} len={}", data.len())
            }
        }
    }
}

// ─── Cell structures ──────────────────────────────────────────────────────────

/// NK (Named Key) cell — represents a registry key node.
#[derive(Debug, Clone)]
pub struct NkCell {
    pub key_name: String,
    pub subkeys_count: u32,
    pub values_count: u32,
    pub parent_offset: u32,
    pub subkeys_list_offset: u32,
    pub values_list_offset: u32,
    pub classname_offset: u32,
    pub last_written: u64,
    pub flags: u16,
}

impl NkCell {
    /// Whether the NK cell has the `KEY_HIVE_ENTRY` flag (root node).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Whether the key name is stored as ASCII (flag 0x0020).
    #[must_use]
    pub const fn is_ascii_name(&self) -> bool {
        self.flags & 0x0020 != 0
    }
}

/// VK (Value Key) cell — represents a single registry value.
#[derive(Debug, Clone)]
pub struct VkCell {
    pub value_name: String,
    pub data_type: RegDataType,
    pub data_size: u32,
    pub data_offset: u32,
    pub data_inline: bool,
}

impl VkCell {
    /// Parse the raw data bytes into a typed `RegValue`.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn parse_data(&self, hbin_data: &[u8]) -> RegValue {
        let raw: Vec<u8> = if self.data_inline {
            // Inline: low 4 bytes of data_offset field hold the value
            self.data_offset.to_le_bytes().to_vec()
        } else {
            let off = self.data_offset as usize;
            if off.saturating_add(4) > hbin_data.len() {
                return RegValue::Binary(vec![]);
            }
            // Cell size is at the offset; data starts at off+4
            let cell_size_raw =
                i32::from_le_bytes(hbin_data[off..off + 4].try_into().unwrap_or([0; 4]));
            let cell_size = (cell_size_raw.unsigned_abs()) as usize;
            let data_len = (self.data_size & 0x7FFF_FFFF) as usize;
            let avail = cell_size.saturating_sub(4).min(data_len);
            if off + 4 + avail > hbin_data.len() {
                return RegValue::Binary(vec![]);
            }
            hbin_data[off + 4..off + 4 + avail].to_vec()
        };

        let data_len = (self.data_size & 0x7FFF_FFFF) as usize;
        let trimmed = &raw[..raw.len().min(data_len)];

        match self.data_type {
            RegDataType::Dword => {
                if trimmed.len() >= 4 {
                    RegValue::Dword(u32::from_le_bytes(trimmed[..4].try_into().unwrap()))
                } else {
                    RegValue::Dword(0)
                }
            }
            RegDataType::DwordBigEndian => {
                if trimmed.len() >= 4 {
                    RegValue::DwordBigEndian(u32::from_be_bytes(trimmed[..4].try_into().unwrap()))
                } else {
                    RegValue::DwordBigEndian(0)
                }
            }
            RegDataType::Qword => {
                if trimmed.len() >= 8 {
                    RegValue::Qword(u64::from_le_bytes(trimmed[..8].try_into().unwrap()))
                } else {
                    RegValue::Qword(0)
                }
            }
            RegDataType::Sz | RegDataType::ExpandSz | RegDataType::Link => {
                let s = utf16le_to_string(trimmed).unwrap_or_else(|_| {
                    String::from_utf8_lossy(trimmed).trim_end_matches('\0').to_string()
                });
                match self.data_type {
                    RegDataType::ExpandSz => RegValue::ExpandString(s),
                    RegDataType::Link => RegValue::Link(s),
                    _ => RegValue::String(s),
                }
            }
            RegDataType::MultiSz => {
                // Decode all UTF-16LE code units (including embedded nulls) to split on.
                let words: Vec<u16> = trimmed
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let mut parts = Vec::new();
                let mut start = 0;
                for (idx, &w) in words.iter().enumerate() {
                    if w == 0 {
                        if idx > start {
                            if let Ok(s) = String::from_utf16(&words[start..idx]) {
                                if !s.is_empty() {
                                    parts.push(s);
                                }
                            }
                        }
                        start = idx + 1;
                    }
                }
                RegValue::MultiString(parts)
            }
            RegDataType::None => RegValue::None,
            RegDataType::Binary
            | RegDataType::ResourceList
            | RegDataType::FullResourceDescriptor
            | RegDataType::ResourceRequirementsList => RegValue::Binary(trimmed.to_vec()),
        }
    }
}

/// SK (Security Key) cell — holds a security descriptor.
#[derive(Debug, Clone)]
pub struct SkCell {
    pub fwd_offset: u32,
    pub bwd_offset: u32,
    pub ref_count: u32,
    pub sd_size: u32,
    pub owner_sid_offset: u32,
    pub group_sid_offset: u32,
    pub sacl_offset: u32,
    pub dacl_offset: u32,
}

/// LF/LH cell — subkey list with hash entries.
#[derive(Debug, Clone)]
pub struct LfCell {
    pub elements: Vec<LfElement>,
}

#[derive(Debug, Clone)]
pub struct LfElement {
    pub key_offset: u32,
    pub name_hint: [u8; 4],
}

/// RI (Root Index) cell — indirect subkey list of LF/LH blocks.
#[derive(Debug, Clone)]
pub struct RiCell {
    pub list_offsets: Vec<u32>,
}

/// LI cell — direct list of offsets (no hashes).
#[derive(Debug, Clone)]
pub struct LiCell {
    pub key_offsets: Vec<u32>,
}

// ─── High-level structures ────────────────────────────────────────────────────

/// A fully parsed registry key with its values and child keys.
#[derive(Debug, Clone)]
pub struct RegistryKey {
    pub path: String,
    pub last_written: u64,
    pub values: HashMap<String, RegValue>,
    pub subkeys: Vec<Self>,
}

impl RegistryKey {
    fn new(path: String, last_written: u64) -> Self {
        Self {
            path,
            last_written,
            values: HashMap::new(),
            subkeys: Vec::new(),
        }
    }
}

/// A fully parsed registry hive.
#[derive(Debug)]
pub struct RegistryHive {
    pub root: RegistryKey,
    pub hive_type: HiveType,
    pub sequence_number_primary: u32,
    pub sequence_number_secondary: u32,
    pub last_written: u64,
}

// ─── REGF header ─────────────────────────────────────────────────────────────

const REGF_MAGIC: &[u8; 4] = b"regf";
const _HBIN_MAGIC: &[u8; 4] = b"hbin";
const REGF_HEADER_SIZE: usize = 512;
const HBIN_HEADER_SIZE: usize = 32;

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

fn utf16le_to_string(bytes: &[u8]) -> Result<String, HiveError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(HiveError::InvalidUtf16);
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = words.iter().position(|&w| w == 0).unwrap_or(words.len());
    String::from_utf16(&words[..end]).map_err(|_| HiveError::InvalidUtf16)
}

// ─── Parser ───────────────────────────────────────────────────────────────────

pub struct HiveParser<'a> {
    data: &'a [u8],
    /// Offset where the first HBIN starts (typically 0x1000).
    hbin_start: usize,
}

impl<'a> HiveParser<'a> {
    const fn new(data: &'a [u8]) -> Result<Self, HiveError> {
        if data.len() < REGF_HEADER_SIZE {
            return Err(HiveError::BufferTooSmall {
                needed: REGF_HEADER_SIZE,
                available: data.len(),
            });
        }
        Ok(HiveParser {
            data,
            hbin_start: REGF_HEADER_SIZE,
        })
    }

    /// Byte slice of the HBIN data area (after the REGF header).
    fn hbin_data(&self) -> &[u8] {
        &self.data[self.hbin_start..]
    }

    fn cell_at(&self, offset: u32) -> Result<&[u8], HiveError> {
        let off = offset as usize;
        let hd = self.hbin_data();
        if off + 4 > hd.len() {
            return Err(HiveError::InvalidCellOffset(offset));
        }
        let cell_size_raw =
            i32::from_le_bytes(hd[off..off + 4].try_into().map_err(|_| HiveError::InvalidCellOffset(offset))?);
        let cell_size = (cell_size_raw.unsigned_abs()) as usize;
        if cell_size < 4 || off + cell_size > hd.len() {
            return Err(HiveError::InvalidCellOffset(offset));
        }
        Ok(&hd[off + 4..off + cell_size])
    }

    fn parse_nk(&self, offset: u32) -> Result<NkCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 76 {
            return Err(HiveError::BufferTooSmall { needed: 76, available: cell.len() });
        }
        if &cell[0..2] != b"nk" {
            return Err(HiveError::UnknownCellType([cell[0], cell[1]]));
        }
        let flags = read_u16_le(cell, 2).unwrap_or(0);
        let last_written = read_u64_le(cell, 4).unwrap_or(0);
        let parent_offset = read_u32_le(cell, 16).unwrap_or(0);
        let subkeys_count = read_u32_le(cell, 20).unwrap_or(0);
        let subkeys_list_offset = read_u32_le(cell, 28).unwrap_or(0xFFFF_FFFF);
        let values_count = read_u32_le(cell, 36).unwrap_or(0);
        let values_list_offset = read_u32_le(cell, 40).unwrap_or(0xFFFF_FFFF);
        let classname_offset = read_u32_le(cell, 56).unwrap_or(0xFFFF_FFFF);
        let key_name_size = read_u16_le(cell, 72).unwrap_or(0) as usize;
        if cell.len() < 76 + key_name_size {
            return Err(HiveError::BufferTooSmall {
                needed: 76 + key_name_size,
                available: cell.len(),
            });
        }
        let name_bytes = &cell[76..76 + key_name_size];
        let key_name = if flags & 0x0020 != 0 {
            String::from_utf8_lossy(name_bytes).to_string()
        } else {
            utf16le_to_string(name_bytes).unwrap_or_else(|_| String::from_utf8_lossy(name_bytes).to_string())
        };
        Ok(NkCell {
            key_name,
            subkeys_count,
            values_count,
            parent_offset,
            subkeys_list_offset,
            values_list_offset,
            classname_offset,
            last_written,
            flags,
        })
    }

    fn parse_vk(&self, offset: u32) -> Result<VkCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 20 {
            return Err(HiveError::BufferTooSmall { needed: 20, available: cell.len() });
        }
        if &cell[0..2] != b"vk" {
            return Err(HiveError::UnknownCellType([cell[0], cell[1]]));
        }
        let name_size = read_u16_le(cell, 2).unwrap_or(0) as usize;
        let data_size_raw = read_u32_le(cell, 4).unwrap_or(0);
        let data_inline = data_size_raw & 0x8000_0000 != 0;
        let data_size = data_size_raw & 0x7FFF_FFFF;
        let data_offset = read_u32_le(cell, 8).unwrap_or(0);
        let data_type_raw = read_u32_le(cell, 12).unwrap_or(0);
        let data_type = RegDataType::from_u32(data_type_raw);
        let flags = read_u16_le(cell, 16).unwrap_or(0);
        let value_name = if name_size == 0 {
            String::new()
        } else {
            if cell.len() < 20 + name_size {
                return Err(HiveError::BufferTooSmall { needed: 20 + name_size, available: cell.len() });
            }
            let name_bytes = &cell[20..20 + name_size];
            if flags & 0x0001 != 0 {
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                utf16le_to_string(name_bytes)
                    .unwrap_or_else(|_| String::from_utf8_lossy(name_bytes).to_string())
            }
        };
        Ok(VkCell {
            value_name,
            data_type,
            data_size,
            data_offset,
            data_inline,
        })
    }

    fn _parse_sk(&self, offset: u32) -> Result<SkCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 36 {
            return Err(HiveError::BufferTooSmall { needed: 36, available: cell.len() });
        }
        if &cell[0..2] != b"sk" {
            return Err(HiveError::UnknownCellType([cell[0], cell[1]]));
        }
        Ok(SkCell {
            fwd_offset: read_u32_le(cell, 4).unwrap_or(0),
            bwd_offset: read_u32_le(cell, 8).unwrap_or(0),
            ref_count: read_u32_le(cell, 12).unwrap_or(0),
            sd_size: read_u32_le(cell, 16).unwrap_or(0),
            // Simplified: offsets into the SD blob
            owner_sid_offset: read_u32_le(cell, 20).unwrap_or(0),
            group_sid_offset: read_u32_le(cell, 24).unwrap_or(0),
            sacl_offset: read_u32_le(cell, 28).unwrap_or(0),
            dacl_offset: read_u32_le(cell, 32).unwrap_or(0),
        })
    }

    fn parse_lf(&self, offset: u32) -> Result<LfCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 4 {
            return Err(HiveError::BufferTooSmall { needed: 4, available: cell.len() });
        }
        let tag = [cell[0], cell[1]];
        if tag != *b"lf" && tag != *b"lh" {
            return Err(HiveError::UnknownCellType(tag));
        }
        let count = read_u16_le(cell, 2).unwrap_or(0) as usize;
        let mut elements = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 8;
            if base + 8 > cell.len() {
                break;
            }
            let key_offset = read_u32_le(cell, base).unwrap_or(0);
            let mut name_hint = [0u8; 4];
            name_hint.copy_from_slice(&cell[base + 4..base + 8]);
            elements.push(LfElement { key_offset, name_hint });
        }
        Ok(LfCell { elements })
    }

    fn parse_ri(&self, offset: u32) -> Result<RiCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 4 {
            return Err(HiveError::BufferTooSmall { needed: 4, available: cell.len() });
        }
        if &cell[0..2] != b"ri" {
            return Err(HiveError::UnknownCellType([cell[0], cell[1]]));
        }
        let count = read_u16_le(cell, 2).unwrap_or(0) as usize;
        let mut list_offsets = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 4;
            if base + 4 > cell.len() {
                break;
            }
            list_offsets.push(read_u32_le(cell, base).unwrap_or(0));
        }
        Ok(RiCell { list_offsets })
    }

    fn parse_li(&self, offset: u32) -> Result<LiCell, HiveError> {
        let cell = self.cell_at(offset)?;
        if cell.len() < 4 {
            return Err(HiveError::BufferTooSmall { needed: 4, available: cell.len() });
        }
        if &cell[0..2] != b"li" {
            return Err(HiveError::UnknownCellType([cell[0], cell[1]]));
        }
        let count = read_u16_le(cell, 2).unwrap_or(0) as usize;
        let mut key_offsets = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 4;
            if base + 4 > cell.len() {
                break;
            }
            key_offsets.push(read_u32_le(cell, base).unwrap_or(0));
        }
        Ok(LiCell { key_offsets })
    }

    /// Collect all subkey offsets from an LF, LH, RI, or LI list cell.
    fn collect_subkey_offsets(&self, list_offset: u32) -> Vec<u32> {
        self.collect_subkey_offsets_inner(list_offset, 0)
    }

    /// Inner implementation with a depth counter to prevent unbounded recursion
    /// on adversarially crafted RI-within-RI chains that could overflow the stack.
    fn collect_subkey_offsets_inner(&self, list_offset: u32, depth: u32) -> Vec<u32> {
        // RI cells should not nest more than a few levels deep in any real hive.
        // Cap at 32 to defend against crafted hives with circular or deeply-nested RI lists.
        if depth > 32 {
            return vec![];
        }
        if list_offset == 0xFFFF_FFFF {
            return vec![];
        }
        let Ok(cell) = self.cell_at(list_offset) else { return vec![] };
        if cell.len() < 2 {
            return vec![];
        }
        match &[cell[0], cell[1]] {
            b"lf" | b"lh" => {
                self.parse_lf(list_offset)
                    .map(|lf| lf.elements.iter().map(|e| e.key_offset).collect())
                    .unwrap_or_default()
            }
            b"ri" => {
                let Ok(ri) = self.parse_ri(list_offset) else { return vec![] };
                ri.list_offsets
                    .iter()
                    .flat_map(|&sub| self.collect_subkey_offsets_inner(sub, depth + 1))
                    .collect()
            }
            b"li" => {
                self.parse_li(list_offset)
                    .map(|li| li.key_offsets)
                    .unwrap_or_default()
            }
            _ => vec![],
        }
    }

    /// Recursively build a `RegistryKey` from an NK cell offset.
    fn build_key(
        &self,
        nk_offset: u32,
        parent_path: &str,
        depth: u32,
    ) -> Result<RegistryKey, HiveError> {
        if depth > 512 {
            return Err(HiveError::CorruptStructure("recursion depth exceeded".into()));
        }
        let nk = self.parse_nk(nk_offset)?;
        let path = if parent_path.is_empty() {
            nk.key_name.clone()
        } else {
            format!("{parent_path}\\{}", nk.key_name)
        };
        let mut key = RegistryKey::new(path.clone(), nk.last_written);

        // Parse values
        if nk.values_count > 0 && nk.values_list_offset != 0xFFFF_FFFF {
            let vl_cell = self.cell_at(nk.values_list_offset)?;
            let count = (nk.values_count as usize).min(vl_cell.len() / 4);
            for i in 0..count {
                let Some(vk_offset) = read_u32_le(vl_cell, i * 4) else { continue };
                let Ok(vk) = self.parse_vk(vk_offset) else { continue };
                let value = vk.parse_data(self.hbin_data());
                key.values.insert(vk.value_name.clone(), value);
            }
        }

        // Parse subkeys
        if nk.subkeys_count > 0 {
            let subkey_offsets = self.collect_subkey_offsets(nk.subkeys_list_offset);
            for sub_off in subkey_offsets {
                if sub_off == 0 || sub_off == 0xFFFF_FFFF {
                    continue;
                }
                if let Ok(subkey) = self.build_key(sub_off, &path, depth + 1) { key.subkeys.push(subkey) }
            }
        }

        Ok(key)
    }
}

// ─── Public parse function ────────────────────────────────────────────────────

/// Parse raw registry hive bytes, returning a `RegistryHive`.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_hive_bytes(data: &[u8]) -> Result<RegistryHive, HiveError> {
    if data.len() < REGF_HEADER_SIZE {
        return Err(HiveError::BufferTooSmall {
            needed: REGF_HEADER_SIZE,
            available: data.len(),
        });
    }
    if &data[0..4] != REGF_MAGIC {
        return Err(HiveError::InvalidMagic(format!("{:?}", &data[0..4])));
    }
    let seq_primary = read_u32_le(data, 4).unwrap_or(0);
    let seq_secondary = read_u32_le(data, 8).unwrap_or(0);
    let last_written = read_u64_le(data, 12).unwrap_or(0);
    let root_cell_offset = read_u32_le(data, 36).unwrap_or(0);

    let parser = HiveParser::new(data)?;
    let root = parser.build_key(root_cell_offset, "", 0)?;
    let hive_type = HiveType::detect(&root.path);

    Ok(RegistryHive {
        root,
        hive_type,
        sequence_number_primary: seq_primary,
        sequence_number_secondary: seq_secondary,
        last_written,
    })
}

// ─── ForensicsPlugin implementation ──────────────────────────────────────────

pub struct RegHivePlugin;

impl RegHivePlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RegHivePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Walking and search helpers ───────────────────────────────────────────────

/// Iterator that walks all keys in a hive depth-first.
pub struct HiveWalker<'a> {
    stack: Vec<&'a RegistryKey>,
}

impl<'a> HiveWalker<'a> {
    #[must_use]
    pub fn new(hive: &'a RegistryHive) -> Self {
        HiveWalker {
            stack: vec![&hive.root],
        }
    }
}

impl<'a> Iterator for HiveWalker<'a> {
    type Item = &'a RegistryKey;
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.stack.pop()?;
        for sub in key.subkeys.iter().rev() {
            self.stack.push(sub);
        }
        Some(key)
    }
}

/// Walk all keys in the hive.
#[must_use]
pub fn walk_keys(hive: &RegistryHive) -> HiveWalker<'_> {
    HiveWalker::new(hive)
}

/// Search for keys whose name contains `query` (case-insensitive).
#[must_use]
pub fn search_by_name<'a>(hive: &'a RegistryHive, query: &str) -> Vec<&'a RegistryKey> {
    let q = query.to_lowercase();
    walk_keys(hive)
        .filter(|k| {
            k.path
                .split('\\')
                .next_back()
                .is_some_and(|n| n.to_lowercase().contains(&q))
        })
        .collect()
}

/// Search for keys that have a value whose data `Display` contains `query`.
#[must_use]
pub fn search_by_value_data<'a>(hive: &'a RegistryHive, query: &str) -> Vec<&'a RegistryKey> {
    let q = query.to_lowercase();
    walk_keys(hive)
        .filter(|k| {
            k.values.values().any(|v| v.to_string().to_lowercase().contains(&q))
        })
        .collect()
}

/// Escape a value for use inside a JSON string literal.
///
/// Registry value names and data routinely contain backslashes — they are
/// mostly paths. The `path` field here was already escaped in the right order
/// (`\` before `"`); the value name and data beside it substituted only `"`,
/// which is worse than doing nothing for anything ending in a backslash: `x\`
/// became `x\"`, so the closing delimiter turned into an escaped character and
/// the rest of the document ran on. The order is part of the correctness.
///
/// RFC 8259 also forbids raw characters below U+0020 inside a string, so tabs
/// and stray control bytes go out as `\u00XX`.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Export the hive tree to a compact JSON string.
#[must_use]
pub fn export_to_json(hive: &RegistryHive) -> String {
    fn key_to_json(key: &RegistryKey, buf: &mut String, indent: usize) {
        let pad = " ".repeat(indent);
        let pad2 = " ".repeat(indent + 2);
        writeln!(buf, "{pad}{{").unwrap();
        writeln!(
            buf,
            "{pad2}\"path\": \"{}\",",
            json_string(&key.path)
        ).unwrap();
        writeln!(buf, "{pad2}\"last_written\": {},", key.last_written).unwrap();
        writeln!(buf, "{pad2}\"values\": {{").unwrap();
        let vals: Vec<_> = key.values.iter().collect();
        for (i, (name, val)) in vals.iter().enumerate() {
            let comma = if i + 1 < vals.len() { "," } else { "" };
            let v_str = json_string(&val.to_string());
            let n_str = json_string(name);
            writeln!(buf, "{pad2}  \"{n_str}\": \"{v_str}\"{comma}").unwrap();
        }
        writeln!(buf, "{pad2}}},").unwrap();
        writeln!(buf, "{pad2}\"subkeys\": [").unwrap();
        for (i, sub) in key.subkeys.iter().enumerate() {
            key_to_json(sub, buf, indent + 4);
            if i + 1 < key.subkeys.len() {
                buf.push(',');
            }
            buf.push('\n');
        }
        writeln!(buf, "{pad2}]").unwrap();
        write!(buf, "{pad}}}").unwrap();
    }

    let mut out = String::new();
    writeln!(
        out,
        "{{\"hive_type\": \"{:?}\", \"last_written\": {}, \"root\":",
        hive.hive_type, hive.last_written
    ).unwrap();
    key_to_json(&hive.root, &mut out, 2);
    out.push_str("\n}");
    out
}

/// Scan HBIN data for cells with the 0xFFFF allocation signature (deleted/free cells)
/// and attempt to recover NK cells from them.
#[must_use]
pub fn deleted_key_scanner(data: &[u8]) -> Vec<NkCell> {
    let mut recovered = Vec::new();
    if data.len() < REGF_HEADER_SIZE + HBIN_HEADER_SIZE {
        return recovered;
    }
    let hbin = &data[REGF_HEADER_SIZE..];
    let mut i = 0usize;
    while i + 8 <= hbin.len() {
        // Free cell: positive cell size (MSB = 0)
        let cell_size_raw = i32::from_le_bytes(
            hbin[i..i + 4].try_into().unwrap_or([0; 4]),
        );
        if cell_size_raw > 0 {
            let cell_size = usize::try_from(cell_size_raw).unwrap_or(0);
            let content_start = i + 4;
            if content_start + 2 <= hbin.len()
                && &hbin[content_start..content_start + 2] == b"nk"
            {
                // Attempt to parse as NK cell
                let parser = HiveParser {
                    data,
                    hbin_start: REGF_HEADER_SIZE,
                };
                if let Ok(nk) = parser.parse_nk(u32::try_from(i).unwrap_or(u32::MAX)) {
                    recovered.push(nk);
                }
            }
            i += cell_size.max(8);
        } else {
            let cs = (cell_size_raw.unsigned_abs() as usize).max(8);
            i += cs;
        }
    }
    recovered
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_hive() -> Vec<u8> {
        // Build a minimal valid REGF hive in memory
        let mut buf = vec![0u8; 8192];

        // REGF header
        buf[0..4].copy_from_slice(b"regf");
        // seq primary = 1
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        // seq secondary = 1
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        // last_written timestamp
        buf[12..20].copy_from_slice(&133_000_000_000u64.to_le_bytes());
        // root_cell_offset = 0x20 (relative to HBIN data)
        buf[36..40].copy_from_slice(&0x20u32.to_le_bytes());

        // HBIN starts at offset 512
        let hbin_base = 512usize;
        buf[hbin_base..hbin_base + 4].copy_from_slice(b"hbin");

        // NK cell at hbin_base + 0x24 (offset 0x20 in HBIN data, +4 for cell size)
        let nk_off = hbin_base + 0x20;
        // Cell size (negative = allocated)
        let cell_size = -0x80i32;
        buf[nk_off..nk_off + 4].copy_from_slice(&cell_size.to_le_bytes());
        let nk_body = nk_off + 4;
        // NK signature
        buf[nk_body] = b'n';
        buf[nk_body + 1] = b'k';
        // flags: KEY_HIVE_ENTRY | KEY_ASCII_NAME
        buf[nk_body + 2..nk_body + 4].copy_from_slice(&0x0025u16.to_le_bytes());
        // last_written
        buf[nk_body + 4..nk_body + 12].copy_from_slice(&133_000_000_000u64.to_le_bytes());
        // parent = 0xFFFFFFFF (root has no parent)
        buf[nk_body + 16..nk_body + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // subkeys_count = 0
        // values_count = 0
        // subkeys_list_offset = 0xFFFFFFFF
        buf[nk_body + 28..nk_body + 32].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // values_list_offset = 0xFFFFFFFF
        buf[nk_body + 40..nk_body + 44].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // classname_offset = 0xFFFFFFFF
        buf[nk_body + 56..nk_body + 60].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // key_name_size = 6 (len of "SYSTEM")
        buf[nk_body + 72..nk_body + 74].copy_from_slice(&6u16.to_le_bytes());
        // key_name
        buf[nk_body + 76..nk_body + 82].copy_from_slice(b"SYSTEM");

        buf
    }

    #[test]
    fn test_parse_hive_magic_check() {
        let mut bad = vec![0u8; 512];
        bad[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(parse_hive_bytes(&bad), Err(HiveError::InvalidMagic(_))));
    }

    #[test]
    fn test_parse_hive_too_small() {
        let tiny = vec![0u8; 10];
        assert!(matches!(
            parse_hive_bytes(&tiny),
            Err(HiveError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn test_parse_minimal_hive() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).expect("should parse minimal hive");
        assert_eq!(hive.root.path, "SYSTEM");
        assert_eq!(hive.sequence_number_primary, 1);
        assert_eq!(hive.sequence_number_secondary, 1);
    }

    #[test]
    fn test_hive_type_detection_system() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        assert_eq!(hive.hive_type, HiveType::System);
    }

    #[test]
    fn test_reg_data_type_from_u32() {
        assert_eq!(RegDataType::from_u32(1), RegDataType::Sz);
        assert_eq!(RegDataType::from_u32(4), RegDataType::Dword);
        assert_eq!(RegDataType::from_u32(11), RegDataType::Qword);
        assert_eq!(RegDataType::from_u32(255), RegDataType::Binary);
    }

    #[test]
    fn test_vk_parse_dword_inline() {
        let vk = VkCell {
            value_name: "Test".into(),
            data_type: RegDataType::Dword,
            data_size: 0x8000_0004, // inline flag
            data_offset: 0x0000_0042,
            data_inline: true,
        };
        let val = vk.parse_data(&[]);
        assert!(matches!(val, RegValue::Dword(0x42)));
    }

    #[test]
    fn test_vk_parse_qword() {
        let mut hbin = vec![0u8; 64];
        let cell_size = -0x20i32;
        hbin[0..4].copy_from_slice(&cell_size.to_le_bytes());
        hbin[4..12].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        let vk = VkCell {
            value_name: "Q".into(),
            data_type: RegDataType::Qword,
            data_size: 8,
            data_offset: 0,
            data_inline: false,
        };
        let val = vk.parse_data(&hbin);
        assert!(matches!(val, RegValue::Qword(0xDEAD_BEEF_CAFE_BABE)));
    }

    #[test]
    fn test_vk_parse_sz_utf16() {
        let text: Vec<u16> = "Hello".encode_utf16().collect();
        let mut raw: Vec<u8> = text.iter().flat_map(|&w| w.to_le_bytes()).collect();
        raw.extend_from_slice(&[0, 0]); // NUL terminator
        let data_len = raw.len();
        let mut hbin = vec![0u8; 4 + raw.len()];
        let cell_size = -(4 + raw.len() as i32);
        hbin[0..4].copy_from_slice(&cell_size.to_le_bytes());
        hbin[4..4 + raw.len()].copy_from_slice(&raw);
        let vk = VkCell {
            value_name: "S".into(),
            data_type: RegDataType::Sz,
            data_size: data_len as u32,
            data_offset: 0,
            data_inline: false,
        };
        let val = vk.parse_data(&hbin);
        assert!(matches!(val, RegValue::String(ref s) if s == "Hello"));
    }

    #[test]
    fn test_walk_keys_empty_hive() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        let keys: Vec<_> = walk_keys(&hive).collect();
        assert!(!keys.is_empty());
        assert_eq!(keys[0].path, "SYSTEM");
    }

    #[test]
    fn test_search_by_name() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        let results = search_by_name(&hive, "sys");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_by_name_no_match() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        let results = search_by_name(&hive, "NONEXISTENT_ZZZZ");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_value_data_no_values() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        let results = search_by_value_data(&hive, "something");
        assert!(results.is_empty());
    }

    #[test]
    fn test_export_to_json_contains_path() {
        let buf = build_minimal_hive();
        let hive = parse_hive_bytes(&buf).unwrap();
        let json = export_to_json(&hive);
        assert!(json.contains("SYSTEM"));
        assert!(json.contains("hive_type"));
    }

    #[test]
    fn test_nk_cell_is_root_flag() {
        let nk = NkCell {
            key_name: "Root".into(),
            subkeys_count: 0,
            values_count: 0,
            parent_offset: 0xFFFF_FFFF,
            subkeys_list_offset: 0xFFFF_FFFF,
            values_list_offset: 0xFFFF_FFFF,
            classname_offset: 0xFFFF_FFFF,
            last_written: 0,
            flags: 0x0004,
        };
        assert!(nk.is_root());
        assert!(!nk.is_ascii_name());
    }

    #[test]
    fn test_nk_cell_is_ascii_flag() {
        let nk = NkCell {
            key_name: "Key".into(),
            subkeys_count: 0,
            values_count: 0,
            parent_offset: 0,
            subkeys_list_offset: 0xFFFF_FFFF,
            values_list_offset: 0xFFFF_FFFF,
            classname_offset: 0xFFFF_FFFF,
            last_written: 0,
            flags: 0x0020,
        };
        assert!(nk.is_ascii_name());
        assert!(!nk.is_root());
    }

    #[test]
    fn test_deleted_key_scanner_empty() {
        let buf = vec![0u8; 512];
        let result = deleted_key_scanner(&buf);
        assert!(result.is_empty());
    }

    #[test]
    fn test_reg_value_display_binary() {
        let v = RegValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(v.to_string(), "de ad be ef");
    }

    #[test]
    fn test_reg_value_display_dword() {
        let v = RegValue::Dword(0xFF);
        assert_eq!(v.to_string(), "0x000000ff");
    }

    #[test]
    fn test_multi_sz_parsing() {
        let parts = ["hello", "world"];
        let mut raw_u16: Vec<u16> = Vec::new();
        for p in &parts {
            raw_u16.extend(p.encode_utf16());
            raw_u16.push(0);
        }
        raw_u16.push(0); // double-null terminator
        let raw_bytes: Vec<u8> = raw_u16.iter().flat_map(|&w| w.to_le_bytes()).collect();
        let data_len = raw_bytes.len();
        let mut hbin = vec![0u8; 4 + raw_bytes.len()];
        let cell_size = -(4 + raw_bytes.len() as i32);
        hbin[0..4].copy_from_slice(&cell_size.to_le_bytes());
        hbin[4..4 + raw_bytes.len()].copy_from_slice(&raw_bytes);
        let vk = VkCell {
            value_name: "M".into(),
            data_type: RegDataType::MultiSz,
            data_size: data_len as u32,
            data_offset: 0,
            data_inline: false,
        };
        let val = vk.parse_data(&hbin);
        match val {
            RegValue::MultiString(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0], "hello");
                assert_eq!(v[1], "world");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
