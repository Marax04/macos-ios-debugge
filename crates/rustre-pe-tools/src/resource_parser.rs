//! PE resource directory parser.
//!
//! Provides [`ResourceDirectory`] (the root of the parsed resource tree),
//! [`ResourceEntry`] (a leaf data entry), and helper functions:
//! * [`walk_resources`] — depth-first walk over the resource directory.
//! * [`extract_resource_by_type`] — convenience extraction for
//!   `RT_VERSION`, `RT_MANIFEST`, `RT_ICON`, `RT_DIALOG`.
//! * [`parse_version_info`] — parses a `VS_VERSION_INFO` blob.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── ResourceError ────────────────────────────────────────────────────────────

/// Errors produced by the resource parser.
#[derive(Debug, Error)]
pub enum ResourceError {
    /// Buffer is too short to read the requested structure.
    #[error("buffer too short: need {needed} at offset {offset}")]
    TooShort { needed: usize, offset: usize },
    /// No resource section found in the PE.
    #[error("no .rsrc section")]
    NoRsrcSection,
    /// No resource of the requested type was found.
    #[error("resource type {0} not found")]
    TypeNotFound(u16),
    /// Resource name/id not found under the type.
    #[error("resource id {0} not found")]
    IdNotFound(u16),
    /// `VS_VERSION_INFO` magic is wrong.
    #[error("invalid VS_VERSION_INFO magic")]
    BadVersionInfo,
    /// String encoding is unsupported (not UTF-16 LE).
    #[error("unsupported string encoding in VS_VERSION_INFO")]
    UnsupportedEncoding,
}

// ─── Well-known type constants ────────────────────────────────────────────────

/// Well-known PE resource type IDs.
pub mod rt {
    pub const CURSOR: u16 = 1;
    pub const BITMAP: u16 = 2;
    pub const ICON: u16 = 3;
    pub const MENU: u16 = 4;
    pub const DIALOG: u16 = 5;
    pub const STRING: u16 = 6;
    pub const FONTDIR: u16 = 7;
    pub const FONT: u16 = 8;
    pub const ACCELERATOR: u16 = 9;
    pub const RCDATA: u16 = 10;
    pub const MESSAGETABLE: u16 = 11;
    pub const GROUP_CURSOR: u16 = 12;
    pub const GROUP_ICON: u16 = 14;
    pub const VERSION: u16 = 16;
    pub const DLGINCLUDE: u16 = 17;
    pub const PLUGPLAY: u16 = 19;
    pub const VXD: u16 = 20;
    pub const ANICURSOR: u16 = 21;
    pub const ANIICON: u16 = 22;
    pub const HTML: u16 = 23;
    pub const MANIFEST: u16 = 24;

    /// Return a human-readable type name for a resource type ID.
    #[must_use]
    pub const fn name(id: u16) -> &'static str {
        match id {
            CURSOR => "RT_CURSOR",
            BITMAP => "RT_BITMAP",
            ICON => "RT_ICON",
            MENU => "RT_MENU",
            DIALOG => "RT_DIALOG",
            STRING => "RT_STRING",
            FONTDIR => "RT_FONTDIR",
            FONT => "RT_FONT",
            ACCELERATOR => "RT_ACCELERATOR",
            RCDATA => "RT_RCDATA",
            MESSAGETABLE => "RT_MESSAGETABLE",
            GROUP_CURSOR => "RT_GROUP_CURSOR",
            GROUP_ICON => "RT_GROUP_ICON",
            VERSION => "RT_VERSION",
            DLGINCLUDE => "RT_DLGINCLUDE",
            PLUGPLAY => "RT_PLUGPLAY",
            VXD => "RT_VXD",
            ANICURSOR => "RT_ANICURSOR",
            ANIICON => "RT_ANIICON",
            HTML => "RT_HTML",
            MANIFEST => "RT_MANIFEST",
            _ => "RT_UNKNOWN",
        }
    }
}

// ─── ResourceId ───────────────────────────────────────────────────────────────

/// A resource identifier: either a numeric ID or a Unicode name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceId {
    /// Integer identifier.
    Id(u16),
    /// Named identifier (string).
    Name(String),
}

impl ResourceId {
    /// Return the integer ID, if this is an `Id` variant.
    #[must_use]
    pub const fn as_id(&self) -> Option<u16> {
        match self {
            Self::Id(id) => Some(*id),
            Self::Name(_) => None,
        }
    }

    /// Return the name, if this is a `Name` variant.
    #[must_use]
    pub const fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(n) => Some(n.as_str()),
            Self::Id(_) => None,
        }
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "#{id}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

// ─── ResourceData ─────────────────────────────────────────────────────────────

/// The data payload of a resource leaf node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceData {
    /// Type identifier (level 1).
    pub type_id: ResourceId,
    /// Name/ID identifier (level 2).
    pub name_id: ResourceId,
    /// Language ID (level 3).
    pub lang_id: u16,
    /// Raw resource data bytes.
    pub data: Vec<u8>,
    /// Code page.
    pub code_page: u32,
    /// RVA of the data.
    pub rva: u32,
}

impl ResourceData {
    /// Create a new resource data entry.
    #[must_use]
    pub const fn new(
        type_id: ResourceId,
        name_id: ResourceId,
        lang_id: u16,
        data: Vec<u8>,
        code_page: u32,
        rva: u32,
    ) -> Self {
        Self {
            type_id,
            name_id,
            lang_id,
            data,
            code_page,
            rva,
        }
    }

    /// Return `true` if this is a manifest resource.
    #[must_use]
    pub fn is_manifest(&self) -> bool {
        self.type_id == ResourceId::Id(rt::MANIFEST)
    }

    /// Return `true` if this is a version-info resource.
    #[must_use]
    pub fn is_version_info(&self) -> bool {
        self.type_id == ResourceId::Id(rt::VERSION)
    }

    /// Return `true` if this is an icon resource.
    #[must_use]
    pub fn is_icon(&self) -> bool {
        self.type_id == ResourceId::Id(rt::ICON)
    }

    /// Return the data as a UTF-8 string if it's valid UTF-8.
    #[must_use]
    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }

    /// Return the data as a UTF-16 LE string if it's even-length.
    #[must_use]
    pub fn as_utf16_le(&self) -> Option<String> {
        if !self.data.len().is_multiple_of(2) {
            return None;
        }
        char::decode_utf16(
            self.data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]])),
        )
        .collect::<Result<String, _>>()
        .ok()
    }
}

impl fmt::Display for ResourceData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] lang={} size={}",
            self.type_id,
            self.name_id,
            self.lang_id,
            self.data.len()
        )
    }
}

// ─── ResourceEntry (tree node) ────────────────────────────────────────────────

/// A node in the resource directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceEntry {
    /// Leaf node containing actual data.
    Data(ResourceData),
    /// Sub-directory node.
    Dir {
        /// Identifier for this directory level.
        id: ResourceId,
        /// Child entries.
        children: Vec<Self>,
    },
}

impl ResourceEntry {
    /// Return `true` if this is a leaf data node.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// Return the data payload if this is a leaf.
    #[must_use]
    pub const fn as_data(&self) -> Option<&ResourceData> {
        match self {
            Self::Data(d) => Some(d),
            Self::Dir { .. } => None,
        }
    }

    /// Return all leaf data nodes in a depth-first walk.
    #[must_use]
    pub fn all_data(&self) -> Vec<&ResourceData> {
        let mut out = Vec::new();
        self.collect_data(&mut out);
        out
    }

    fn collect_data<'a>(&'a self, out: &mut Vec<&'a ResourceData>) {
        match self {
            Self::Data(d) => out.push(d),
            Self::Dir { children, .. } => {
                for c in children {
                    c.collect_data(out);
                }
            }
        }
    }
}

// ─── ResourceDirectory ────────────────────────────────────────────────────────

/// The root of a PE resource tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDirectory {
    /// All top-level type entries.
    pub entries: Vec<ResourceEntry>,
}

impl ResourceDirectory {
    /// Create an empty resource directory.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Parse the resource directory from the raw PE file data and the virtual
    /// address / size of the `.rsrc` section (from the data directory entry
    /// index 2).
    ///
    /// `rsrc_va`  — virtual address of the resource section.
    /// `rsrc_raw` — raw bytes of the resource section (`.rsrc` data).
    ///
    /// # Errors
    ///
    /// Returns [`ResourceError`] if the directory structure is malformed.
    pub fn parse(rsrc_raw: &[u8], rsrc_va: u32) -> Result<Self, ResourceError> {
        let entries = parse_dir(rsrc_raw, 0, rsrc_va, 0, None, None)?;
        Ok(Self { entries })
    }

    /// Return all leaf resource data nodes with the given type ID.
    #[must_use]
    pub fn by_type(&self, type_id: u16) -> Vec<&ResourceData> {
        let target = ResourceId::Id(type_id);
        for entry in &self.entries {
            if let ResourceEntry::Dir { id, children } = entry
                && *id == target
            {
                let mut out = Vec::new();
                for c in children {
                    c.collect_data(&mut out);
                }
                return out;
            }
        }
        Vec::new()
    }

    /// Return all leaf data nodes across the entire tree.
    #[must_use]
    pub fn all_data(&self) -> Vec<&ResourceData> {
        self.entries.iter().flat_map(|e| e.all_data()).collect()
    }

    /// Total number of leaf data nodes.
    #[must_use]
    pub fn data_count(&self) -> usize {
        self.all_data().len()
    }

    /// Total number of top-level type entries.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── Internal parse helpers ───────────────────────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> Result<u16, ResourceError> {
    if off + 2 > data.len() {
        return Err(ResourceError::TooShort {
            needed: 2,
            offset: off,
        });
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, ResourceError> {
    if off + 4 > data.len() {
        return Err(ResourceError::TooShort {
            needed: 4,
            offset: off,
        });
    }
    Ok(u32::from_le_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    ))
}

/// Read a resource name string from a `NAME_STRING` entry (UTF-16 LE, length-prefixed).
fn read_name_string(data: &[u8], off: usize) -> Result<String, ResourceError> {
    let length = read_u16(data, off)? as usize;
    let byte_start = off.checked_add(2).ok_or(ResourceError::TooShort { needed: 2, offset: off })?;
    let byte_end = length.checked_mul(2).and_then(|n| byte_start.checked_add(n)).ok_or(ResourceError::TooShort { needed: usize::MAX, offset: off })?;
    if byte_end > data.len() {
        return Err(ResourceError::TooShort {
            needed: byte_end,
            offset: off,
        });
    }
    let wchars: Vec<u16> = data[byte_start..byte_end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&wchars).map_err(|_| ResourceError::UnsupportedEncoding)
}

/// Maximum depth allowed when recursing into resource sub-directories.
const MAX_RESOURCE_DEPTH: u8 = 8;

/// Parse a resource directory (`IMAGE_RESOURCE_DIRECTORY`) at `dir_off` within
/// `rsrc_raw`.  `level` is 0=type, 1=name, 2=language.
fn parse_dir(
    rsrc_raw: &[u8],
    dir_off: usize,
    rsrc_va: u32,
    level: u8,
    type_id: Option<&ResourceId>,
    name_id: Option<&ResourceId>,
) -> Result<Vec<ResourceEntry>, ResourceError> {
    if level > MAX_RESOURCE_DEPTH {
        return Ok(Vec::new());
    }
    if dir_off + 16 > rsrc_raw.len() {
        return Err(ResourceError::TooShort {
            needed: 16,
            offset: dir_off,
        });
    }
    // IMAGE_RESOURCE_DIRECTORY is 16 bytes:
    // +0  Characteristics (u32)
    // +4  TimeDateStamp (u32)
    // +8  MajorVersion (u16)
    // +10 MinorVersion (u16)
    // +12 NumberOfNamedEntries (u16)
    // +14 NumberOfIdEntries (u16)
    let named_count = read_u16(rsrc_raw, dir_off + 12)? as usize;
    let id_count = read_u16(rsrc_raw, dir_off + 14)? as usize;
    let total = named_count.saturating_add(id_count);

    let mut entries = Vec::with_capacity(total);
    let entries_base = dir_off + 16;

    for i in 0..total {
        let e_off = entries_base + i * 8;
        if e_off + 8 > rsrc_raw.len() {
            break;
        }
        let name_offset = read_u32(rsrc_raw, e_off)?;
        let data_or_subdir = read_u32(rsrc_raw, e_off + 4)?;

        // Decode the identifier.
        let id = if (name_offset & 0x8000_0000) != 0 {
            // High bit set → string name
            let str_off = (name_offset & 0x7FFF_FFFF) as usize;
            let name =
                read_name_string(rsrc_raw, str_off).unwrap_or_else(|_| format!("@{str_off:#x}"));
            ResourceId::Name(name)
        } else {
            ResourceId::Id(u16::try_from(name_offset & 0xFFFF).unwrap_or(u16::MAX))
        };

        // High bit of data_or_subdir: 1 = subdirectory, 0 = leaf data entry.
        if (data_or_subdir & 0x8000_0000) != 0 {
            // Subdirectory.
            let sub_off = (data_or_subdir & 0x7FFF_FFFF) as usize;

            let (tid, nid): (Option<ResourceId>, Option<ResourceId>) = match level {
                0 => (Some(id.clone()), None),
                1 => (type_id.cloned(), Some(id.clone())),
                _ => (type_id.cloned(), name_id.cloned()),
            };

            let children = parse_dir(
                rsrc_raw,
                sub_off,
                rsrc_va,
                level + 1,
                tid.as_ref(),
                nid.as_ref(),
            )?;
            entries.push(ResourceEntry::Dir { id, children });
        } else {
            // Leaf: IMAGE_RESOURCE_DATA_ENTRY (16 bytes).
            let leaf_off = data_or_subdir as usize;
            if leaf_off + 16 > rsrc_raw.len() {
                continue;
            }
            let data_rva = read_u32(rsrc_raw, leaf_off)?;
            let data_size = read_u32(rsrc_raw, leaf_off + 4)? as usize;
            let code_page = read_u32(rsrc_raw, leaf_off + 8)?;

            // Convert RVA to offset within rsrc_raw.
            // If data_rva < rsrc_va the resource points outside the section — return empty.
            let data_off = if let Some(delta) = data_rva.checked_sub(rsrc_va) { delta as usize } else {
                entries.push(ResourceEntry::Data(ResourceData::new(
                    type_id.cloned().unwrap_or(ResourceId::Id(0)),
                    name_id.cloned().unwrap_or(ResourceId::Id(0)),
                    match &id { ResourceId::Id(lid) => *lid, ResourceId::Name(_) => 0 },
                    Vec::new(),
                    code_page,
                    data_rva,
                )));
                continue;
            };
            let data_end = data_off.saturating_add(data_size);
            let data_bytes = if data_end <= rsrc_raw.len() {
                rsrc_raw[data_off..data_end].to_vec()
            } else {
                Vec::new()
            };

            let lang_id = match &id {
                ResourceId::Id(lid) => *lid,
                ResourceId::Name(_) => 0,
            };

            let type_id_final = type_id.cloned().unwrap_or(ResourceId::Id(0));
            let name_id_final = name_id.cloned().unwrap_or(ResourceId::Id(0));

            entries.push(ResourceEntry::Data(ResourceData::new(
                type_id_final,
                name_id_final,
                lang_id,
                data_bytes,
                code_page,
                data_rva,
            )));
        }
    }

    Ok(entries)
}

// ─── Public helpers ───────────────────────────────────────────────────────────

/// Walk all resource data entries in the directory, calling `f` for each.
pub fn walk_resources<F>(dir: &ResourceDirectory, mut f: F)
where
    F: FnMut(&ResourceData),
{
    fn walk_entry<F: FnMut(&ResourceData)>(entry: &ResourceEntry, f: &mut F) {
        match entry {
            ResourceEntry::Data(d) => f(d),
            ResourceEntry::Dir { children, .. } => {
                for c in children {
                    walk_entry(c, f);
                }
            }
        }
    }
    for e in &dir.entries {
        walk_entry(e, &mut f);
    }
}

/// Extract all resources of a given type.
///
/// # Errors
///
/// Returns [`ResourceError::TypeNotFound`] if no resources of the given type
/// exist.
pub fn extract_resource_by_type(
    dir: &ResourceDirectory,
    type_id: u16,
) -> Result<Vec<ResourceData>, ResourceError> {
    let results = dir.by_type(type_id);
    if results.is_empty() {
        Err(ResourceError::TypeNotFound(type_id))
    } else {
        Ok(results.into_iter().cloned().collect())
    }
}

// ─── VersionInfo ──────────────────────────────────────────────────────────────

/// Parsed `VS_VERSION_INFO` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Fixed file information fields.
    pub fixed: FixedFileInfo,
    /// String tables: map from locale string to key→value pairs.
    pub string_tables: Vec<StringTable>,
}

/// Fixed binary fields from `VS_FIXEDFILEINFO`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FixedFileInfo {
    /// File version as (major, minor, patch, build).
    pub file_version: (u16, u16, u16, u16),
    /// Product version as (major, minor, patch, build).
    pub product_version: (u16, u16, u16, u16),
    /// File flags (debug, prerelease, etc.).
    pub file_flags: u32,
    /// File OS (WIN32, NT, etc.).
    pub file_os: u32,
    /// File type (app, dll, driver, etc.).
    pub file_type: u32,
    /// File subtype.
    pub file_subtype: u32,
}

/// A string table from `StringFileInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringTable {
    /// Locale key (e.g. `"040904b0"`).
    pub locale: String,
    /// Key → value string pairs.
    pub entries: HashMap<String, String>,
}

/// Parse a `VS_VERSION_INFO` blob.
///
/// The format is:
/// ```text
/// WORD wLength; WORD wValueLength; WORD wType;
/// WCHAR szKey[]; // "VS_VERSION_INFO\0"
/// <padding to DWORD alignment>
/// VS_FIXEDFILEINFO Value;
/// <padding>
/// [StringFileInfo / VarFileInfo children]
/// ```
///
/// # Errors
///
/// Returns [`ResourceError`] if the blob is malformed.
pub fn parse_version_info(data: &[u8]) -> Result<VersionInfo, ResourceError> {
    if data.len() < 6 {
        return Err(ResourceError::TooShort {
            needed: 6,
            offset: 0,
        });
    }

    let w_length = read_u16(data, 0)? as usize;
    let _w_value_len = read_u16(data, 2)?;
    let _w_type = read_u16(data, 4)?;

    // szKey should be "VS_VERSION_INFO\0" (16 wide chars = 32 bytes)
    if data.len() < 6 + 32 {
        return Err(ResourceError::TooShort {
            needed: 38,
            offset: 6,
        });
    }
    let key_wchars: Vec<u16> = data[6..6 + 32]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let key_str = String::from_utf16_lossy(&key_wchars);
    let key_trimmed = key_str.trim_end_matches('\0');
    if key_trimmed != "VS_VERSION_INFO" {
        return Err(ResourceError::BadVersionInfo);
    }

    // Skip szKey (16 wide chars) + potential NUL = 34 bytes, then DWORD-align.
    let key_end = 6 + 32; // 38
    let pad = if key_end % 4 != 0 {
        4 - (key_end % 4)
    } else {
        0
    };
    let fixed_off = key_end + pad;

    // VS_FIXEDFILEINFO is 52 bytes.
    if fixed_off + 52 > data.len() {
        return Err(ResourceError::TooShort {
            needed: fixed_off + 52,
            offset: fixed_off,
        });
    }

    // Signature = 0xFEEF04BD
    let sig = read_u32(data, fixed_off)?;
    if sig != 0xFEEF_04BD {
        return Err(ResourceError::BadVersionInfo);
    }

    let file_version_high = read_u32(data, fixed_off + 8)?;
    let file_version_low = read_u32(data, fixed_off + 12)?;
    let prod_version_high = read_u32(data, fixed_off + 16)?;
    let prod_version_low = read_u32(data, fixed_off + 20)?;
    let file_flags = read_u32(data, fixed_off + 28)?;
    let file_os = read_u32(data, fixed_off + 32)?;
    let file_type = read_u32(data, fixed_off + 36)?;
    let file_subtype = read_u32(data, fixed_off + 40)?;

    let fixed = FixedFileInfo {
        file_version: (
            u16::try_from(file_version_high >> 16).unwrap_or(u16::MAX),
            u16::try_from(file_version_high & 0xFFFF).unwrap_or(u16::MAX),
            u16::try_from(file_version_low >> 16).unwrap_or(u16::MAX),
            u16::try_from(file_version_low & 0xFFFF).unwrap_or(u16::MAX),
        ),
        product_version: (
            u16::try_from(prod_version_high >> 16).unwrap_or(u16::MAX),
            u16::try_from(prod_version_high & 0xFFFF).unwrap_or(u16::MAX),
            u16::try_from(prod_version_low >> 16).unwrap_or(u16::MAX),
            u16::try_from(prod_version_low & 0xFFFF).unwrap_or(u16::MAX),
        ),
        file_flags,
        file_os,
        file_type,
        file_subtype,
    };

    // Parse children (StringFileInfo, VarFileInfo) after FIXEDFILEINFO.
    let children_start = fixed_off + 52;
    let children_start = if children_start % 4 != 0 {
        children_start + (4 - children_start % 4)
    } else {
        children_start
    };

    let end = w_length.min(data.len());
    let mut string_tables = Vec::new();
    let mut pos = children_start;

    while pos + 6 <= end {
        let entry_len = read_u16(data, pos)? as usize;
        if entry_len == 0 {
            break;
        }
        let entry_end = (pos + entry_len).min(end);
        let _val_len = read_u16(data, pos + 2)?;
        let _ty = read_u16(data, pos + 4)?;

        // Read the key string (UTF-16 LE, NUL terminated) starting at pos + 6.
        let key_start = pos + 6;
        let key = read_wide_str(data, key_start, entry_end);

        if key.as_deref() == Some("StringFileInfo") {
            // Parse StringTable children.
            let tables = parse_string_file_info(data, pos, entry_end)?;
            string_tables.extend(tables);
        }

        pos = entry_end;
        // DWORD align
        if pos % 4 != 0 {
            pos += 4 - (pos % 4);
        }
    }

    Ok(VersionInfo {
        fixed,
        string_tables,
    })
}

fn read_wide_str(data: &[u8], start: usize, limit: usize) -> Option<String> {
    let mut wchars = Vec::with_capacity(limit.saturating_sub(start) / 2);
    let mut pos = start;
    while pos + 1 < limit {
        let wc = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if wc == 0 {
            break;
        }
        wchars.push(wc);
        pos += 2;
    }
    String::from_utf16(&wchars).ok()
}

fn parse_string_file_info(
    data: &[u8],
    sf_off: usize,
    sf_end: usize,
) -> Result<Vec<StringTable>, ResourceError> {
    let mut tables = Vec::new();
    // Children start after the StringFileInfo header + key.
    // StringFileInfo key = "StringFileInfo\0" (15+1 wide chars = 32 bytes)
    let key_start = sf_off + 6;
    // Find end of wide key.
    let mut key_end = key_start;
    while key_end + 1 < sf_end {
        let wc = u16::from_le_bytes([data[key_end], data[key_end + 1]]);
        key_end += 2;
        if wc == 0 {
            break;
        }
    }
    let mut pos = key_end;
    if !pos.is_multiple_of(4) {
        pos += 4 - (pos % 4);
    }

    while pos + 6 <= sf_end {
        let tbl_len = read_u16(data, pos)? as usize;
        if tbl_len == 0 {
            break;
        }
        let tbl_end = (pos + tbl_len).min(sf_end);
        // Table key (locale, e.g. "040904b0")
        let locale_start = pos + 6;
        let locale = read_wide_str(data, locale_start, tbl_end).unwrap_or_default();
        let mut locale_end = locale_start;
        while locale_end + 1 < tbl_end {
            let wc = u16::from_le_bytes([data[locale_end], data[locale_end + 1]]);
            locale_end += 2;
            if wc == 0 {
                break;
            }
        }
        if !locale_end.is_multiple_of(4) {
            locale_end += 4 - (locale_end % 4);
        }

        let mut entries = HashMap::new();
        let mut str_pos = locale_end;
        while str_pos + 6 <= tbl_end {
            let s_len = read_u16(data, str_pos)? as usize;
            if s_len == 0 {
                break;
            }
            let string_end = (str_pos + s_len).min(tbl_end);
            // skip wValueLength field (str_pos + 2..str_pos + 4); read for bounds-check
            read_u16(data, str_pos + 2)?;
            let k_start = str_pos + 6;
            let mut k_end = k_start;
            while k_end + 1 < string_end {
                let wc = u16::from_le_bytes([data[k_end], data[k_end + 1]]);
                k_end += 2;
                if wc == 0 {
                    break;
                }
            }
            if !k_end.is_multiple_of(4) {
                k_end += 4 - (k_end % 4);
            }
            let key = read_wide_str(data, str_pos + 6, k_end).unwrap_or_default();
            let value = read_wide_str(data, k_end, string_end).unwrap_or_default();
            entries.insert(key, value);
            str_pos = string_end;
            if !str_pos.is_multiple_of(4) {
                str_pos += 4 - (str_pos % 4);
            }
        }

        tables.push(StringTable { locale, entries });
        pos = tbl_end;
        if !pos.is_multiple_of(4) {
            pos += 4 - (pos % 4);
        }
    }

    Ok(tables)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_display() {
        let id = ResourceId::Id(3);
        assert_eq!(id.to_string(), "#3");
        let n = ResourceId::Name("icon".to_string());
        assert_eq!(n.to_string(), "icon");
    }

    #[test]
    fn resource_id_accessors() {
        let id = ResourceId::Id(10);
        assert_eq!(id.as_id(), Some(10));
        assert_eq!(id.as_name(), None);
        let n = ResourceId::Name("foo".to_string());
        assert_eq!(n.as_id(), None);
        assert_eq!(n.as_name(), Some("foo"));
    }

    #[test]
    fn resource_data_is_manifest() {
        let d = ResourceData::new(
            ResourceId::Id(rt::MANIFEST),
            ResourceId::Id(1),
            0,
            b"<manifest/>".to_vec(),
            0,
            0,
        );
        assert!(d.is_manifest());
        assert!(!d.is_version_info());
        assert!(!d.is_icon());
    }

    #[test]
    fn resource_data_as_utf8() {
        let d = ResourceData::new(
            ResourceId::Id(rt::MANIFEST),
            ResourceId::Id(1),
            0,
            b"hello".to_vec(),
            0,
            0,
        );
        assert_eq!(d.as_utf8(), Some("hello"));
    }

    #[test]
    fn resource_data_display() {
        let d = ResourceData::new(
            ResourceId::Id(rt::ICON),
            ResourceId::Id(2),
            1033,
            vec![0u8; 128],
            0,
            0,
        );
        let s = d.to_string();
        assert!(s.contains("128"));
    }

    #[test]
    fn rt_name_known() {
        assert_eq!(rt::name(rt::ICON), "RT_ICON");
        assert_eq!(rt::name(rt::MANIFEST), "RT_MANIFEST");
        assert_eq!(rt::name(rt::VERSION), "RT_VERSION");
        assert_eq!(rt::name(0xFFFF), "RT_UNKNOWN");
    }

    #[test]
    fn resource_directory_empty() {
        let dir = ResourceDirectory::empty();
        assert_eq!(dir.data_count(), 0);
        assert_eq!(dir.type_count(), 0);
    }

    #[test]
    fn resource_directory_by_type_empty() {
        let dir = ResourceDirectory::empty();
        assert!(dir.by_type(rt::ICON).is_empty());
    }

    #[test]
    fn walk_resources_callback() {
        // Build a minimal directory manually.
        let leaf = ResourceData::new(
            ResourceId::Id(rt::RCDATA),
            ResourceId::Id(1),
            0,
            b"payload".to_vec(),
            0,
            0,
        );
        let dir = ResourceDirectory {
            entries: vec![ResourceEntry::Dir {
                id: ResourceId::Id(rt::RCDATA),
                children: vec![ResourceEntry::Dir {
                    id: ResourceId::Id(1),
                    children: vec![ResourceEntry::Data(leaf)],
                }],
            }],
        };

        let mut found = Vec::new();
        walk_resources(&dir, |d| found.push(d.data.clone()));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], b"payload");
    }

    #[test]
    fn extract_resource_by_type_ok() {
        let leaf = ResourceData::new(
            ResourceId::Id(rt::MANIFEST),
            ResourceId::Id(1),
            0,
            b"<manifest/>".to_vec(),
            0,
            0,
        );
        let dir = ResourceDirectory {
            entries: vec![ResourceEntry::Dir {
                id: ResourceId::Id(rt::MANIFEST),
                children: vec![ResourceEntry::Dir {
                    id: ResourceId::Id(1),
                    children: vec![ResourceEntry::Data(leaf)],
                }],
            }],
        };

        let results = extract_resource_by_type(&dir, rt::MANIFEST).expect("extract");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_utf8(), Some("<manifest/>"));
    }

    #[test]
    fn extract_resource_by_type_not_found() {
        let dir = ResourceDirectory::empty();
        let err = extract_resource_by_type(&dir, rt::VERSION);
        assert!(matches!(err, Err(ResourceError::TypeNotFound(_))));
    }

    #[test]
    fn parse_version_info_bad_data() {
        let err = parse_version_info(b"bad");
        assert!(err.is_err());
    }

    #[test]
    fn parse_version_info_wrong_key() {
        // Build a fake header with correct length but wrong key.
        let mut data = vec![0u8; 100];
        // wLength = 100
        data[0] = 100;
        data[1] = 0;
        // szKey = "VS_WRONG_INFO\0" encoded as UTF-16 LE (don't bother, just zeroes)
        let err = parse_version_info(&data);
        assert!(matches!(err, Err(ResourceError::BadVersionInfo)));
    }

    #[test]
    fn parse_dir_empty_buffer() {
        let err = parse_dir(b"", 0, 0, 0, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn resource_entry_all_data() {
        let leaf = ResourceData::new(ResourceId::Id(1), ResourceId::Id(1), 0, vec![1, 2, 3], 0, 0);
        let entry = ResourceEntry::Dir {
            id: ResourceId::Id(1),
            children: vec![ResourceEntry::Data(leaf)],
        };
        let all = entry.all_data();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn fixed_file_info_default() {
        let fi = FixedFileInfo::default();
        assert_eq!(fi.file_version, (0, 0, 0, 0));
    }
}
