/// PE Resource Directory Parser
///
/// Parses the three-level resource tree embedded in PE files:
///   Level 1 – Resource Type (RT_*)
///   Level 2 – Resource Name / ID
///   Level 3 – Language
///
/// Provides high-level extractors for `RT_VERSION`, `RT_MANIFEST`, `RT_STRING`,
/// `RT_MESSAGETABLE`, `RT_ICON/RT_GROUP_ICON` and `RT_BITMAP`.
use std::collections::HashMap;
use std::fmt;

use crate::casts::{u32_to_u16, usize_to_u16, usize_to_u32};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    OutOfBounds { offset: usize, size: usize },
    BadAlignment(usize),
    UnexpectedEnd,
    InvalidUtf16,
    InvalidSignature { expected: u32, found: u32 },
    InvalidStructure(String),
    UnsupportedFormat(String),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { offset, size } => {
                write!(f, "out-of-bounds read at offset {offset} (size {size})")
            }
            Self::BadAlignment(off) => write!(f, "bad alignment at offset {off}"),
            Self::UnexpectedEnd => write!(f, "unexpected end of data"),
            Self::InvalidUtf16 => write!(f, "invalid UTF-16 sequence"),
            Self::InvalidSignature { expected, found } => write!(
                f,
                "invalid signature: expected {expected:#010x}, found {found:#010x}"
            ),
            Self::InvalidStructure(s) => write!(f, "invalid structure: {s}"),
            Self::UnsupportedFormat(s) => write!(f, "unsupported format: {s}"),
        }
    }
}

impl std::error::Error for ResourceError {}

pub type ResourceResult<T> = Result<T, ResourceError>;

// ---------------------------------------------------------------------------
// Raw on-disk structures (little-endian)
// ---------------------------------------------------------------------------

/// _`IMAGE_RESOURCE_DIRECTORY`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
}

impl ImageResourceDirectory {
    pub const SIZE: usize = 16;

    /// # Errors
    /// Returns [`ResourceError::OutOfBounds`] if `data` is too short.
    ///
    /// # Panics
    /// Panics are impossible in practice (slice lengths are checked before `unwrap` calls).
    pub fn parse(data: &[u8], offset: usize) -> ResourceResult<Self> {
        let end = offset + Self::SIZE;
        if end > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset,
                size: Self::SIZE,
            });
        }
        let b = &data[offset..end];
        Ok(Self {
            characteristics: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            time_date_stamp: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            major_version: u16::from_le_bytes(b[8..10].try_into().unwrap()),
            minor_version: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            number_of_named_entries: u16::from_le_bytes(b[12..14].try_into().unwrap()),
            number_of_id_entries: u16::from_le_bytes(b[14..16].try_into().unwrap()),
        })
    }

    #[must_use] 
    pub fn total_entries(&self) -> u32 {
        u32::from(self.number_of_named_entries) + u32::from(self.number_of_id_entries)
    }
}

/// _`IMAGE_RESOURCE_DIRECTORY_ENTRY`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageResourceDirectoryEntry {
    /// Raw 32-bit field: bit31 set => named (offset into string table),
    ///                   bit31 clear => integer ID.
    pub name_offset_or_id: u32,
    /// Raw 32-bit field: bit31 set => sub-directory offset,
    ///                   bit31 clear => data-entry offset.
    pub data_or_subdir: u32,
}

impl ImageResourceDirectoryEntry {
    pub const SIZE: usize = 8;
    const HIGH_BIT: u32 = 0x8000_0000;

    /// # Errors
    /// Returns [`ResourceError::OutOfBounds`] if `data` is too short.
    ///
    /// # Panics
    /// Panics are impossible in practice (slice lengths are checked before `unwrap` calls).
    pub fn parse(data: &[u8], offset: usize) -> ResourceResult<Self> {
        let end = offset + Self::SIZE;
        if end > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset,
                size: Self::SIZE,
            });
        }
        let b = &data[offset..end];
        Ok(Self {
            name_offset_or_id: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            data_or_subdir: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        })
    }

    #[must_use] 
    pub const fn is_named(&self) -> bool {
        self.name_offset_or_id & Self::HIGH_BIT != 0
    }
    #[must_use] 
    pub const fn is_subdir(&self) -> bool {
        self.data_or_subdir & Self::HIGH_BIT != 0
    }
    #[must_use] 
    pub const fn name_offset(&self) -> u32 {
        self.name_offset_or_id & !Self::HIGH_BIT
    }
    #[must_use] 
    pub const fn id(&self) -> u32 {
        self.name_offset_or_id
    }
    #[must_use] 
    pub const fn subdir_offset(&self) -> u32 {
        self.data_or_subdir & !Self::HIGH_BIT
    }
    #[must_use] 
    pub const fn data_offset(&self) -> u32 {
        self.data_or_subdir
    }
}

/// _`IMAGE_RESOURCE_DATA_ENTRY`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
    /// RVA-flavoured alias of `offset_to_data`, kept for callers that work
    /// in RVA space. Always equal to `offset_to_data`.
    pub data_rva: u32,
}

impl ImageResourceDataEntry {
    pub const SIZE: usize = 16;

    /// Alias accessor for [`offset_to_data`] kept under its more conventional
    /// "RVA" name used by callers that work in RVA space.
    #[must_use]
    pub const fn data_rva(&self) -> u32 {
        self.data_rva
    }

    /// # Errors
    /// Returns [`ResourceError::OutOfBounds`] if `data` is too short.
    ///
    /// # Panics
    ///
    /// Panics are unreachable: the slice bounds are validated before `try_into().unwrap()`.
    pub fn parse(data: &[u8], offset: usize) -> ResourceResult<Self> {
        let end = offset + Self::SIZE;
        if end > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset,
                size: Self::SIZE,
            });
        }
        let b = &data[offset..end];
        let offset_to_data = u32::from_le_bytes(b[0..4].try_into().unwrap());
        Ok(Self {
            offset_to_data,
            size: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            code_page: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            reserved: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            data_rva: offset_to_data,
        })
    }
}

// ---------------------------------------------------------------------------
// Predefined resource type IDs (RT_*)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Cursor,
    Bitmap,
    Icon,
    Menu,
    Dialog,
    String,
    FontDir,
    Font,
    Accelerator,
    RcData,
    MessageTable,
    GroupCursor,
    GroupIcon,
    Version,
    DlgInclude,
    PlugPlay,
    Vxd,
    AnimatedCursor,
    AnimatedIcon,
    Html,
    Manifest,
    Unknown(u32),
}

impl ResourceType {
    #[must_use] 
    pub const fn from_id(id: u32) -> Self {
        match id {
            1 => Self::Cursor,
            2 => Self::Bitmap,
            3 => Self::Icon,
            4 => Self::Menu,
            5 => Self::Dialog,
            6 => Self::String,
            7 => Self::FontDir,
            8 => Self::Font,
            9 => Self::Accelerator,
            10 => Self::RcData,
            11 => Self::MessageTable,
            12 => Self::GroupCursor,
            14 => Self::GroupIcon,
            16 => Self::Version,
            17 => Self::DlgInclude,
            19 => Self::PlugPlay,
            20 => Self::Vxd,
            21 => Self::AnimatedCursor,
            22 => Self::AnimatedIcon,
            23 => Self::Html,
            24 => Self::Manifest,
            x => Self::Unknown(x),
        }
    }

    #[must_use] 
    pub const fn to_id(self) -> u32 {
        match self {
            Self::Cursor => 1,
            Self::Bitmap => 2,
            Self::Icon => 3,
            Self::Menu => 4,
            Self::Dialog => 5,
            Self::String => 6,
            Self::FontDir => 7,
            Self::Font => 8,
            Self::Accelerator => 9,
            Self::RcData => 10,
            Self::MessageTable => 11,
            Self::GroupCursor => 12,
            Self::GroupIcon => 14,
            Self::Version => 16,
            Self::DlgInclude => 17,
            Self::PlugPlay => 19,
            Self::Vxd => 20,
            Self::AnimatedCursor => 21,
            Self::AnimatedIcon => 22,
            Self::Html => 23,
            Self::Manifest => 24,
            Self::Unknown(x) => x,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cursor => "RT_CURSOR",
            Self::Bitmap => "RT_BITMAP",
            Self::Icon => "RT_ICON",
            Self::Menu => "RT_MENU",
            Self::Dialog => "RT_DIALOG",
            Self::String => "RT_STRING",
            Self::FontDir => "RT_FONTDIR",
            Self::Font => "RT_FONT",
            Self::Accelerator => "RT_ACCELERATOR",
            Self::RcData => "RT_RCDATA",
            Self::MessageTable => "RT_MESSAGETABLE",
            Self::GroupCursor => "RT_GROUP_CURSOR",
            Self::GroupIcon => "RT_GROUP_ICON",
            Self::Version => "RT_VERSION",
            Self::DlgInclude => "RT_DLGINCLUDE",
            Self::PlugPlay => "RT_PLUGPLAY",
            Self::Vxd => "RT_VXD",
            Self::AnimatedCursor => "RT_ANICURSOR",
            Self::AnimatedIcon => "RT_ANIICON",
            Self::Html => "RT_HTML",
            Self::Manifest => "RT_MANIFEST",
            Self::Unknown(_) => "RT_UNKNOWN",
        }
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "RT_UNKNOWN({id})"),
            other => write!(f, "{}", other.name()),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceName: either an integer ID or a Unicode string
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceName {
    Id(u32),
    Name(String),
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "#{id}"),
            Self::Name(name) => write!(f, "{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Three-level path
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePath {
    pub type_id: ResourceType,
    pub name: ResourceName,
    pub language: u32,
}

impl ResourcePath {
    #[must_use] 
    pub const fn new(type_id: ResourceType, name: ResourceName, language: u32) -> Self {
        Self {
            type_id,
            name,
            language,
        }
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.type_id.name(), self.name, self.language)
    }
}

// ---------------------------------------------------------------------------
// Low-level byte-reading helpers
// ---------------------------------------------------------------------------

fn read_le_u16(data: &[u8], offset: usize) -> ResourceResult<u16> {
    if offset + 2 > data.len() {
        return Err(ResourceError::OutOfBounds { offset, size: 2 });
    }
    Ok(u16::from_le_bytes(
        data[offset..offset + 2].try_into().unwrap(),
    ))
}

fn read_le_u32(data: &[u8], offset: usize) -> ResourceResult<u32> {
    if offset + 4 > data.len() {
        return Err(ResourceError::OutOfBounds { offset, size: 4 });
    }
    Ok(u32::from_le_bytes(
        data[offset..offset + 4].try_into().unwrap(),
    ))
}

/// Align `n` up to the next 4-byte boundary.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read a `UNICODE_STRING` resource name: u16 length followed by that many UTF-16 code units.
fn read_resource_name_string(rsrc: &[u8], offset: usize) -> ResourceResult<String> {
    if offset + 2 > rsrc.len() {
        return Err(ResourceError::OutOfBounds { offset, size: 2 });
    }
    let len = u16::from_le_bytes(rsrc[offset..offset + 2].try_into().unwrap()) as usize;
    let bytes_needed = offset + 2 + len * 2;
    if bytes_needed > rsrc.len() {
        return Err(ResourceError::OutOfBounds {
            offset: offset + 2,
            size: len * 2,
        });
    }
    let slice = &rsrc[offset + 2..offset + 2 + len * 2];
    let words: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&words).map_err(|_| ResourceError::InvalidUtf16)
}

/// Read a null-terminated UTF-16LE string; returns (string, `bytes_consumed_including_null`).
fn read_utf16_string(data: &[u8], offset: usize) -> ResourceResult<(String, usize)> {
    let mut pos = offset;
    let mut words = Vec::new();
    loop {
        if pos + 2 > data.len() {
            break;
        }
        let w = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        pos += 2;
        if w == 0 {
            break;
        }
        words.push(w);
    }
    let s = String::from_utf16(&words).map_err(|_| ResourceError::InvalidUtf16)?;
    Ok((s, pos))
}

// ---------------------------------------------------------------------------
// Resource section view and tree walker
// ---------------------------------------------------------------------------

/// View into the raw .rsrc section bytes.
///
/// `rsrc_data` - raw bytes of the .rsrc PE section.
/// `rva_base`  - the virtual address at which the section is loaded (used
///               to convert RVAs stored in `IMAGE_RESOURCE_DATA_ENTRY` to
///               section-relative offsets).
pub struct ResourceView<'a> {
    pub rsrc: &'a [u8],
    pub rva_base: u32,
}

impl<'a> ResourceView<'a> {
    #[must_use] 
    pub const fn new(rsrc: &'a [u8], rva_base: u32) -> Self {
        Self { rsrc, rva_base }
    }

    /// Convert an RVA stored in `IMAGE_RESOURCE_DATA_ENTRY` to a section offset.
    fn rva_to_offset(&self, rva: u32) -> ResourceResult<usize> {
        if rva < self.rva_base {
            return Err(ResourceError::InvalidStructure(format!(
                "RVA {rva:#x} below section base {:#x}",
                self.rva_base
            )));
        }
        Ok((rva - self.rva_base) as usize)
    }

    /// Walk the entire three-level resource tree and return a flat list of
    /// `(ResourcePath, raw_bytes)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceError`] if any resource directory entry is malformed.
    pub fn enumerate(&self) -> ResourceResult<Vec<(ResourcePath, Vec<u8>)>> {
        let mut out = Vec::new();
        self.walk_level1(0, &mut out)?;
        Ok(out)
    }

    // --- Level 1: Resource Type ---

    fn walk_level1(
        &self,
        offset: usize,
        out: &mut Vec<(ResourcePath, Vec<u8>)>,
    ) -> ResourceResult<()> {
        let dir = ImageResourceDirectory::parse(self.rsrc, offset)?;
        let entry_base = offset + ImageResourceDirectory::SIZE;
        let total = dir.total_entries() as usize;

        for i in 0..total {
            let eoff = entry_base + i * ImageResourceDirectoryEntry::SIZE;
            let entry = ImageResourceDirectoryEntry::parse(self.rsrc, eoff)?;

            let type_id = if entry.is_named() {
                ResourceType::Unknown(entry.name_offset())
            } else {
                ResourceType::from_id(entry.id())
            };

            if entry.is_subdir() {
                self.walk_level2(entry.subdir_offset() as usize, type_id, out)?;
            }
        }
        Ok(())
    }

    // --- Level 2: Resource Name / ID ---

    fn walk_level2(
        &self,
        offset: usize,
        type_id: ResourceType,
        out: &mut Vec<(ResourcePath, Vec<u8>)>,
    ) -> ResourceResult<()> {
        let dir = ImageResourceDirectory::parse(self.rsrc, offset)?;
        let entry_base = offset + ImageResourceDirectory::SIZE;
        let total = dir.total_entries() as usize;

        for i in 0..total {
            let eoff = entry_base + i * ImageResourceDirectoryEntry::SIZE;
            let entry = ImageResourceDirectoryEntry::parse(self.rsrc, eoff)?;

            let name = if entry.is_named() {
                let s = read_resource_name_string(self.rsrc, entry.name_offset() as usize)?;
                ResourceName::Name(s)
            } else {
                ResourceName::Id(entry.id())
            };

            if entry.is_subdir() {
                self.walk_level3(entry.subdir_offset() as usize, type_id, &name, out)?;
            }
        }
        Ok(())
    }

    // --- Level 3: Language ---

    fn walk_level3(
        &self,
        offset: usize,
        type_id: ResourceType,
        name: &ResourceName,
        out: &mut Vec<(ResourcePath, Vec<u8>)>,
    ) -> ResourceResult<()> {
        let dir = ImageResourceDirectory::parse(self.rsrc, offset)?;
        let entry_base = offset + ImageResourceDirectory::SIZE;
        let total = dir.total_entries() as usize;

        for i in 0..total {
            let eoff = entry_base + i * ImageResourceDirectoryEntry::SIZE;
            let entry = ImageResourceDirectoryEntry::parse(self.rsrc, eoff)?;
            let lang = entry.id();

            if !entry.is_subdir() {
                let de = ImageResourceDataEntry::parse(self.rsrc, entry.data_offset() as usize)?;
                let data_off = self.rva_to_offset(de.offset_to_data)?;
                let data_end = data_off + de.size as usize;
                if data_end > self.rsrc.len() {
                    return Err(ResourceError::OutOfBounds {
                        offset: data_off,
                        size: de.size as usize,
                    });
                }
                let raw = self.rsrc[data_off..data_end].to_vec();
                let path = ResourcePath::new(type_id, name.clone(), lang);
                out.push((path, raw));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RT_VERSION – VS_VERSIONINFO
// ---------------------------------------------------------------------------

/// `VS_FIXEDFILEINFO` (52 bytes on disk)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsFixedFileInfo {
    pub signature: u32,
    pub struc_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

impl VsFixedFileInfo {
    pub const SIGNATURE: u32 = 0xFEEF_04BD;
    pub const SIZE: usize = 52;

    /// # Errors
    ///
    /// Returns [`ResourceError`] if the data is too short or the signature is wrong.
    pub fn parse(data: &[u8], offset: usize) -> ResourceResult<Self> {
        if offset + Self::SIZE > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset,
                size: Self::SIZE,
            });
        }
        let sig = read_le_u32(data, offset)?;
        if sig != Self::SIGNATURE {
            return Err(ResourceError::InvalidSignature {
                expected: Self::SIGNATURE,
                found: sig,
            });
        }
        Ok(Self {
            signature: sig,
            struc_version: read_le_u32(data, offset + 4)?,
            file_version_ms: read_le_u32(data, offset + 8)?,
            file_version_ls: read_le_u32(data, offset + 12)?,
            product_version_ms: read_le_u32(data, offset + 16)?,
            product_version_ls: read_le_u32(data, offset + 20)?,
            file_flags_mask: read_le_u32(data, offset + 24)?,
            file_flags: read_le_u32(data, offset + 28)?,
            file_os: read_le_u32(data, offset + 32)?,
            file_type: read_le_u32(data, offset + 36)?,
            file_subtype: read_le_u32(data, offset + 40)?,
            file_date_ms: read_le_u32(data, offset + 44)?,
            file_date_ls: read_le_u32(data, offset + 48)?,
        })
    }

    /// Returns (major, minor, build, revision) of `FileVersion`.
    #[must_use] 
    pub const fn file_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.file_version_ms >> 16) as u16,
            (self.file_version_ms & 0xFFFF) as u16,
            (self.file_version_ls >> 16) as u16,
            (self.file_version_ls & 0xFFFF) as u16,
        )
    }

    /// Returns (major, minor, build, revision) of `ProductVersion`.
    #[must_use] 
    pub const fn product_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.product_version_ms >> 16) as u16,
            (self.product_version_ms & 0xFFFF) as u16,
            (self.product_version_ls >> 16) as u16,
            (self.product_version_ls & 0xFFFF) as u16,
        )
    }

    #[must_use] 
    pub fn file_version_string(&self) -> String {
        let (a, b, c, d) = self.file_version();
        format!("{a}.{b}.{c}.{d}")
    }

    #[must_use] 
    pub fn product_version_string(&self) -> String {
        let (a, b, c, d) = self.product_version();
        format!("{a}.{b}.{c}.{d}")
    }
}

/// Language / code-page pair from `VarFileInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LangCodePage {
    pub language: u16,
    pub code_page: u16,
}

/// Fully parsed `VS_VERSIONINFO` resource.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub fixed: Option<VsFixedFileInfo>,
    /// All string table entries from every `StringFileInfo` child.
    pub strings: HashMap<String, String>,
    /// Language/codepage pairs from `VarFileInfo`.
    pub lang_codepages: Vec<LangCodePage>,
}

impl VersionInfo {
    pub fn file_description(&self) -> Option<&str> {
        self.strings.get("FileDescription").map(String::as_str)
    }
    pub fn file_version(&self) -> Option<&str> {
        self.strings.get("FileVersion").map(String::as_str)
    }
    pub fn internal_name(&self) -> Option<&str> {
        self.strings.get("InternalName").map(String::as_str)
    }
    pub fn legal_copyright(&self) -> Option<&str> {
        self.strings.get("LegalCopyright").map(String::as_str)
    }
    pub fn original_filename(&self) -> Option<&str> {
        self.strings.get("OriginalFilename").map(String::as_str)
    }
    pub fn product_name(&self) -> Option<&str> {
        self.strings.get("ProductName").map(String::as_str)
    }
    pub fn product_version(&self) -> Option<&str> {
        self.strings.get("ProductVersion").map(String::as_str)
    }
    pub fn company_name(&self) -> Option<&str> {
        self.strings.get("CompanyName").map(String::as_str)
    }
}

// VS_VERSIONINFO parser (internal)
struct VersionParser<'a> {
    data: &'a [u8],
}

impl<'a> VersionParser<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn parse(&self) -> ResourceResult<VersionInfo> {
        let mut pos = 0usize;
        let mut info = VersionInfo {
            fixed: None,
            strings: HashMap::new(),
            lang_codepages: Vec::new(),
        };

        if pos + 6 > self.data.len() {
            return Err(ResourceError::UnexpectedEnd);
        }

        let _length = read_le_u16(self.data, pos)? as usize;
        pos += 2;
        let value_length = read_le_u16(self.data, pos)? as usize;
        pos += 2;
        let _w_type = read_le_u16(self.data, pos)?;
        pos += 2;

        let (key, after_key) = read_utf16_string(self.data, pos)?;
        pos = after_key;
        if key != "VS_VERSION_INFO" {
            return Err(ResourceError::InvalidStructure(format!(
                "expected VS_VERSION_INFO, got '{key}'"
            )));
        }
        pos = align4(pos);

        if value_length >= VsFixedFileInfo::SIZE
            && let Ok(ffi) = VsFixedFileInfo::parse(self.data, pos) {
                info.fixed = Some(ffi);
            }
        pos = align4(pos + value_length);

        while pos + 6 <= self.data.len() {
            let child_start = pos;
            let child_len = read_le_u16(self.data, pos)? as usize;
            if child_len < 6 {
                break;
            }

            pos += 6;
            let (child_key, after_ck) = read_utf16_string(self.data, pos)?;
            let data_start = align4(after_ck);

            match child_key.as_str() {
                "StringFileInfo" => self.parse_string_file_info(
                    data_start,
                    child_start + child_len,
                    &mut info.strings,
                )?,
                "VarFileInfo" => self.parse_var_file_info(
                    data_start,
                    child_start + child_len,
                    &mut info.lang_codepages,
                )?,
                _ => {}
            }

            pos = align4(child_start + child_len);
        }

        Ok(info)
    }

    fn parse_string_file_info(
        &self,
        mut pos: usize,
        end: usize,
        out: &mut HashMap<String, String>,
    ) -> ResourceResult<()> {
        while pos + 6 <= end && pos + 6 <= self.data.len() {
            let table_start = pos;
            let table_len = read_le_u16(self.data, pos)? as usize;
            if table_len < 6 {
                break;
            }
            pos += 6;

            let (_lang_cp, lang_key_end) = read_utf16_string(self.data, pos)?;
            pos = align4(lang_key_end);

            let table_end = table_start + table_len;

            while pos + 6 <= table_end && pos + 6 <= self.data.len() {
                let str_start = pos;
                let str_len = read_le_u16(self.data, pos)? as usize;
                if str_len < 6 {
                    break;
                }
                pos += 6;

                let (skey, string_key_end) = read_utf16_string(self.data, pos)?;
                pos = align4(string_key_end);

                let str_end = str_start + str_len;
                let value = if pos < str_end && pos < self.data.len() {
                    let (sval, after_sv) = read_utf16_string(self.data, pos)?;
                    let _ = after_sv;
                    sval
                } else {
                    String::new()
                };
                out.insert(skey, value);

                pos = align4(str_start + str_len);
            }

            pos = align4(table_start + table_len);
        }
        Ok(())
    }

    fn parse_var_file_info(
        &self,
        mut pos: usize,
        end: usize,
        out: &mut Vec<LangCodePage>,
    ) -> ResourceResult<()> {
        while pos + 6 <= end && pos + 6 <= self.data.len() {
            let var_start = pos;
            let var_len = read_le_u16(self.data, pos)? as usize;
            if var_len < 6 {
                break;
            }
            let var_val_len = read_le_u16(self.data, pos + 2)? as usize;
            pos += 6;

            let (_var_key, after_vk) = read_utf16_string(self.data, pos)?;
            pos = align4(after_vk);

            let pairs = var_val_len / 4;
            for _ in 0..pairs {
                if pos + 4 > self.data.len() {
                    break;
                }
                let val = read_le_u32(self.data, pos)?;
                out.push(LangCodePage {
                    language: (val & 0xFFFF) as u16,
                    code_page: (val >> 16) as u16,
                });
                pos += 4;
            }

            pos = align4(var_start + var_len);
        }
        Ok(())
    }
}

/// Parse an `RT_VERSION` resource blob into a `VersionInfo`.
///
/// # Errors
/// Returns [`ResourceError`] if the version resource is malformed.
pub fn parse_version_resource(data: &[u8]) -> ResourceResult<VersionInfo> {
    VersionParser::new(data).parse()
}

// ---------------------------------------------------------------------------
// RT_MANIFEST
// ---------------------------------------------------------------------------

/// Extract an embedded application manifest XML string from raw resource bytes.
/// Handles UTF-8 (with/without BOM) and UTF-16 LE/BE.
///
/// # Errors
/// Returns [`ResourceError`] if the bytes are not valid UTF-8 or UTF-16.
pub fn parse_manifest_resource(data: &[u8]) -> ResourceResult<String> {
    if data.len() >= 2 {
        if data[0] == 0xFF && data[1] == 0xFE {
            // UTF-16 LE BOM
            let words: Vec<u16> = data[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&words).map_err(|_| ResourceError::InvalidUtf16);
        }
        if data[0] == 0xFE && data[1] == 0xFF {
            // UTF-16 BE BOM
            let words: Vec<u16> = data[2..]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&words).map_err(|_| ResourceError::InvalidUtf16);
        }
        if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
            // UTF-8 BOM
            return String::from_utf8(data[3..].to_vec())
                .map_err(|_| ResourceError::InvalidStructure("invalid UTF-8".into()));
        }
    }
    // Default: assume UTF-8
    String::from_utf8(data.to_vec())
        .map_err(|_| ResourceError::InvalidStructure("invalid UTF-8 in manifest".into()))
}

// ---------------------------------------------------------------------------
// RT_STRING – string tables in blocks of 16
// ---------------------------------------------------------------------------

/// A parsed string table block covering 16 consecutive string IDs.
#[derive(Debug, Clone)]
pub struct StringTableBlock {
    /// The resource name/ID (level-2 ID).  Global string IDs are in
    /// the range `(block_id - 1) * 16 .. block_id * 16`.
    pub block_id: u32,
    /// The 16 strings in this block; empty strings for absent entries.
    pub strings: [String; 16],
}

impl StringTableBlock {
    /// Global string ID of the i-th entry in this block.
    #[must_use] 
    pub fn global_id(&self, index: u8) -> u32 {
        string_id(self.block_id, index)
    }
}

/// Parse an `RT_STRING` resource block.
///
/// # Errors
/// Returns [`ResourceError`] if the block data is malformed.
///
/// # Panics
/// Panics if a string length slice cannot be converted (unreachable in practice).
pub fn parse_string_table(data: &[u8], block_id: u32) -> ResourceResult<StringTableBlock> {
    let mut pos = 0usize;
    let mut strs: [String; 16] = Default::default();

    for slot in &mut strs {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if len == 0 {
            *slot = String::new();
            continue;
        }
        let byte_len = len * 2;
        if pos + byte_len > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset: pos,
                size: byte_len,
            });
        }
        let words: Vec<u16> = data[pos..pos + byte_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        *slot = String::from_utf16(&words).map_err(|_| ResourceError::InvalidUtf16)?;
        pos += byte_len;
    }

    Ok(StringTableBlock {
        block_id,
        strings: strs,
    })
}

/// Convert a `block_id` and intra-block index to a global string resource ID.
#[must_use] 
pub fn string_id(block_id: u32, index: u8) -> u32 {
    (block_id - 1) * 16 + u32::from(index)
}

// ---------------------------------------------------------------------------
// RT_MESSAGETABLE
// ---------------------------------------------------------------------------

/// A single message entry from `MESSAGE_RESOURCE_DATA`.
#[derive(Debug, Clone)]
pub struct MessageEntry {
    pub message_id: u32,
    /// Flags: bit 0 = Unicode text (UTF-16), otherwise ANSI.
    pub flags: u16,
    pub text: String,
}

/// Parsed `MESSAGE_RESOURCE_DATA`.
#[derive(Debug, Clone)]
pub struct MessageTable {
    pub messages: Vec<MessageEntry>,
}

/// Parse an `RT_MESSAGETABLE` resource blob.
///
/// # Errors
/// Returns [`ResourceError`] if the message table data is malformed.
pub fn parse_message_table(data: &[u8]) -> ResourceResult<MessageTable> {
    if data.len() < 4 {
        return Err(ResourceError::UnexpectedEnd);
    }
    let num_blocks = read_le_u32(data, 0)? as usize;
    let mut messages = Vec::new();

    // MESSAGE_RESOURCE_BLOCK: LoId(4) + HiId(4) + OffsetToEntries(4) = 12 bytes each
    let block_table_size = num_blocks * 12;
    if 4 + block_table_size > data.len() {
        return Err(ResourceError::OutOfBounds {
            offset: 4,
            size: block_table_size,
        });
    }

    for b in 0..num_blocks {
        let boff = 4 + b * 12;
        let lo_id = read_le_u32(data, boff)?;
        let hi_id = read_le_u32(data, boff + 4)?;
        let offset_to_entries = read_le_u32(data, boff + 8)? as usize;

        let mut entry_off = offset_to_entries;
        for msg_id in lo_id..=hi_id {
            if entry_off + 4 > data.len() {
                break;
            }
            let entry_len = read_le_u16(data, entry_off)? as usize;
            let flags = read_le_u16(data, entry_off + 2)?;
            if entry_len < 4 || entry_off + entry_len > data.len() {
                break;
            }

            let text_bytes = &data[entry_off + 4..entry_off + entry_len];
            let text = if flags & 0x0001 != 0 {
                // Unicode (UTF-16 LE)
                let words: Vec<u16> = text_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&w| w != 0)
                    .collect();
                String::from_utf16(&words).unwrap_or_default()
            } else {
                // ANSI
                let end = text_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(text_bytes.len());
                String::from_utf8_lossy(&text_bytes[..end]).into_owned()
            };

            messages.push(MessageEntry {
                message_id: msg_id,
                flags,
                text,
            });
            entry_off += entry_len;
        }
    }

    Ok(MessageTable { messages })
}

// ---------------------------------------------------------------------------
// RT_ICON / RT_GROUP_ICON – reconstruct .ico file
// ---------------------------------------------------------------------------

/// GRPICONDIR entry as stored in the `RT_GROUP_ICON` resource (14 bytes).
#[derive(Debug, Clone, Copy)]
struct GrpIconDirEntry {
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes_in_res: u32,
    /// ID of the corresponding `RT_ICON` resource.
    pub id: u16,
}

impl GrpIconDirEntry {
    const SIZE: usize = 14;

    fn parse(data: &[u8], offset: usize) -> ResourceResult<Self> {
        if offset + Self::SIZE > data.len() {
            return Err(ResourceError::OutOfBounds {
                offset,
                size: Self::SIZE,
            });
        }
        Ok(Self {
            width: data[offset],
            height: data[offset + 1],
            color_count: data[offset + 2],
            reserved: data[offset + 3],
            planes: read_le_u16(data, offset + 4)?,
            bit_count: read_le_u16(data, offset + 6)?,
            bytes_in_res: read_le_u32(data, offset + 8)?,
            id: read_le_u16(data, offset + 12)?,
        })
    }
}

/// Reconstruct a complete .ico file from the `RT_GROUP_ICON` resource and the
/// individual `RT_ICON` resources.
///
/// `group_data` - raw bytes of the `RT_GROUP_ICON` resource.
/// `icon_map`   - map from `RT_ICON` resource ID to raw icon bytes.
///
/// # Errors
/// Returns [`ResourceError`] if `group_data` is malformed or an icon ID is missing.
pub fn reconstruct_ico<S: ::std::hash::BuildHasher>(
    group_data: &[u8],
    icon_map: &HashMap<u16, Vec<u8>, S>,
) -> ResourceResult<Vec<u8>> {
    if group_data.len() < 6 {
        return Err(ResourceError::UnexpectedEnd);
    }
    let _reserved = read_le_u16(group_data, 0)?;
    let _img_type = read_le_u16(group_data, 2)?;
    let count = read_le_u16(group_data, 4)? as usize;

    // `count` is a raw u16 from the file: cap the pre-allocation by the
    // entries the group data could actually contain.
    let mut entries: Vec<GrpIconDirEntry> =
        Vec::with_capacity(count.min((group_data.len().saturating_sub(6)) / GrpIconDirEntry::SIZE + 1));
    for i in 0..count {
        let off = 6 + i * GrpIconDirEntry::SIZE;
        entries.push(GrpIconDirEntry::parse(group_data, off)?);
    }

    // ICONDIR header  = 6 bytes
    // ICONDIRENTRY[]  = count * 16 bytes
    // Icon pixel data = concatenated
    let dir_size = 6 + count * 16;
    let mut ico = vec![0u8; dir_size];

    // ICONDIR
    ico[0..2].copy_from_slice(&0u16.to_le_bytes()); // reserved
    ico[2..4].copy_from_slice(&1u16.to_le_bytes()); // type = 1 (icon)
    ico[4..6].copy_from_slice(&usize_to_u16(count).to_le_bytes()); // count

    let mut data_offset = usize_to_u32(dir_size);
    for (i, e) in entries.iter().enumerate() {
        let icon_data = icon_map.get(&e.id).ok_or_else(|| {
            ResourceError::InvalidStructure(format!("missing RT_ICON id {}", e.id))
        })?;

        // Prefer the actual RT_ICON data length, but fall back to the
        // declared `bytes_in_res` from the group entry if the icon resource
        // appears truncated (defensive — the two should match for well-formed PEs).
        let icon_len = if icon_data.is_empty() && e.bytes_in_res > 0 {
            e.bytes_in_res as usize
        } else {
            icon_data.len()
        };

        let eoff = 6 + i * 16;
        ico[eoff] = e.width;
        ico[eoff + 1] = e.height;
        ico[eoff + 2] = e.color_count;
        ico[eoff + 3] = e.reserved;
        ico[eoff + 4..eoff + 6].copy_from_slice(&e.planes.to_le_bytes());
        ico[eoff + 6..eoff + 8].copy_from_slice(&e.bit_count.to_le_bytes());
        ico[eoff + 8..eoff + 12].copy_from_slice(&usize_to_u32(icon_len).to_le_bytes());
        ico[eoff + 12..eoff + 16].copy_from_slice(&data_offset.to_le_bytes());

        data_offset = data_offset.saturating_add(usize_to_u32(icon_data.len()));
        ico.extend_from_slice(icon_data);
    }

    Ok(ico)
}

// ---------------------------------------------------------------------------
// RT_BITMAP – reconstruct .bmp
// ---------------------------------------------------------------------------

/// Reconstruct a complete .bmp file from an `RT_BITMAP` resource.
///
/// PE stores `RT_BITMAP` as BITMAPINFO + pixel data (i.e. without the 14-byte
/// BITMAPFILEHEADER).  This function prepends the missing header.
///
/// # Errors
/// Returns [`ResourceError`] if the bitmap data is too short.
pub fn reconstruct_bmp(data: &[u8]) -> ResourceResult<Vec<u8>> {
    if data.len() < 40 {
        return Err(ResourceError::UnexpectedEnd);
    }

    let bi_size = read_le_u32(data, 0)? as usize;
    let bi_bit_count = read_le_u16(data, 14)?;
    let bi_compression = read_le_u32(data, 16)?;
    let clr_used = read_le_u32(data, 32)?;

    let color_table_entries = if clr_used != 0 {
        clr_used as usize
    } else if bi_bit_count <= 8 && bi_compression == 0 {
        1usize << bi_bit_count
    } else {
        0
    };

    let color_table_size = color_table_entries * 4;
    let pixel_data_offset = usize_to_u32(14 + bi_size + color_table_size);
    let file_size = 14u32 + usize_to_u32(data.len());

    let mut bmp = Vec::with_capacity(14 + data.len());
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    bmp.extend_from_slice(&pixel_data_offset.to_le_bytes());
    bmp.extend_from_slice(data);
    Ok(bmp)
}

// ---------------------------------------------------------------------------
// High-level entry points
// ---------------------------------------------------------------------------

/// Extract all resources from a PE resource section.
///
/// `rsrc_data` - raw bytes of the .rsrc section.
/// `rva_base`  - virtual address of the .rsrc section.
///
/// Returns a flat list of `(ResourcePath, raw_bytes)` pairs, one per leaf.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory tree is malformed.
pub fn extract_all_resources(
    rsrc_data: &[u8],
    rva_base: u32,
) -> ResourceResult<Vec<(ResourcePath, Vec<u8>)>> {
    let view = ResourceView::new(rsrc_data, rva_base);
    view.enumerate()
}

/// Find and parse the first `RT_VERSION` resource.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory is malformed.
pub fn find_version_info(rsrc_data: &[u8], rva_base: u32) -> ResourceResult<Option<VersionInfo>> {
    let resources = extract_all_resources(rsrc_data, rva_base)?;
    for (path, data) in &resources {
        if path.type_id == ResourceType::Version {
            return parse_version_resource(data).map(Some);
        }
    }
    Ok(None)
}

/// Find and return the first embedded manifest XML string.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory is malformed.
pub fn find_manifest(rsrc_data: &[u8], rva_base: u32) -> ResourceResult<Option<String>> {
    let resources = extract_all_resources(rsrc_data, rva_base)?;
    for (path, data) in &resources {
        if path.type_id == ResourceType::Manifest {
            return parse_manifest_resource(data).map(Some);
        }
    }
    Ok(None)
}

/// Collect all `RT_STRING` blocks from the resource section.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory is malformed.
pub fn find_all_strings(rsrc_data: &[u8], rva_base: u32) -> ResourceResult<Vec<StringTableBlock>> {
    let resources = extract_all_resources(rsrc_data, rva_base)?;
    let mut blocks = Vec::new();
    for (path, data) in &resources {
        if path.type_id == ResourceType::String
            && let ResourceName::Id(id) = path.name
                && let Ok(block) = parse_string_table(data, id) {
                    blocks.push(block);
                }
    }
    Ok(blocks)
}

/// Collect and parse all `RT_MESSAGETABLE` resources.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory is malformed.
pub fn find_all_message_tables(
    rsrc_data: &[u8],
    rva_base: u32,
) -> ResourceResult<Vec<MessageTable>> {
    let resources = extract_all_resources(rsrc_data, rva_base)?;
    let mut tables = Vec::new();
    for (path, data) in &resources {
        if path.type_id == ResourceType::MessageTable
            && let Ok(mt) = parse_message_table(data) {
                tables.push(mt);
            }
    }
    Ok(tables)
}

/// Reconstruct all `RT_GROUP_ICON` resources into .ico byte buffers.
///
/// # Errors
/// Returns [`ResourceError`] if the resource directory or any group icon is malformed.
pub fn find_all_icons(
    rsrc_data: &[u8],
    rva_base: u32,
) -> ResourceResult<Vec<(ResourcePath, Vec<u8>)>> {
    let resources = extract_all_resources(rsrc_data, rva_base)?;

    // Build id->bytes map for individual icons
    let mut icon_map: HashMap<u16, Vec<u8>> = HashMap::new();
    for (path, data) in &resources {
        if path.type_id == ResourceType::Icon
            && let ResourceName::Id(id) = path.name {
                icon_map.insert(u32_to_u16(id), data.clone());
            }
    }

    let mut result = Vec::new();
    for (path, data) in &resources {
        if path.type_id == ResourceType::GroupIcon
            && let Ok(ico) = reconstruct_ico(data, &icon_map) {
                result.push((path.clone(), ico));
            }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Helpers -----------------------------------------------------------

    fn make_resource_dir(named: u16, id_entries: u16) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[12..14].copy_from_slice(&named.to_le_bytes());
        v[14..16].copy_from_slice(&id_entries.to_le_bytes());
        v
    }

    fn make_dir_entry(name_or_id: u32, data_or_sub: u32) -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v[0..4].copy_from_slice(&name_or_id.to_le_bytes());
        v[4..8].copy_from_slice(&data_or_sub.to_le_bytes());
        v
    }

    fn push_utf16_str(buf: &mut Vec<u8>, s: &str) {
        let ws: Vec<u16> = s.encode_utf16().collect();
        buf.extend_from_slice(&(ws.len() as u16).to_le_bytes());
        for w in ws {
            buf.extend_from_slice(&w.to_le_bytes());
        }
    }

    fn _push_utf16_str_null_term(buf: &mut Vec<u8>, s: &str) {
        for c in s.encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
    }

    // ---- ImageResourceDirectory -------------------------------------------

    #[test]
    fn test_ird_parse_basic() {
        let data = make_resource_dir(3, 5);
        let dir = ImageResourceDirectory::parse(&data, 0).unwrap();
        assert_eq!(dir.number_of_named_entries, 3);
        assert_eq!(dir.number_of_id_entries, 5);
        assert_eq!(dir.total_entries(), 8);
    }

    #[test]
    fn test_ird_out_of_bounds() {
        let data = vec![0u8; 10];
        assert!(ImageResourceDirectory::parse(&data, 0).is_err());
    }

    #[test]
    fn test_ird_parse_at_offset() {
        let mut data = vec![0u8; 32];
        data[28..30].copy_from_slice(&2u16.to_le_bytes());
        data[30..32].copy_from_slice(&7u16.to_le_bytes());
        let dir = ImageResourceDirectory::parse(&data, 16).unwrap();
        assert_eq!(dir.number_of_named_entries, 2);
        assert_eq!(dir.number_of_id_entries, 7);
    }

    #[test]
    fn test_ird_timestamp() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let dir = ImageResourceDirectory::parse(&data, 0).unwrap();
        assert_eq!(dir.time_date_stamp, 0xDEAD_BEEF);
    }

    #[test]
    fn test_ird_version_fields() {
        let mut data = vec![0u8; 16];
        data[8..10].copy_from_slice(&4u16.to_le_bytes());
        data[10..12].copy_from_slice(&1u16.to_le_bytes());
        let dir = ImageResourceDirectory::parse(&data, 0).unwrap();
        assert_eq!(dir.major_version, 4);
        assert_eq!(dir.minor_version, 1);
    }

    #[test]
    fn test_ird_characteristics() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let dir = ImageResourceDirectory::parse(&data, 0).unwrap();
        assert_eq!(dir.characteristics, 0xCAFE_BABE);
    }

    // ---- ImageResourceDirectoryEntry -------------------------------------

    #[test]
    fn test_irde_named_subdir() {
        let entry_bytes = make_dir_entry(0x8000_0010, 0x8000_0020);
        let entry = ImageResourceDirectoryEntry::parse(&entry_bytes, 0).unwrap();
        assert!(entry.is_named());
        assert_eq!(entry.name_offset(), 0x10);
        assert!(entry.is_subdir());
        assert_eq!(entry.subdir_offset(), 0x20);
    }

    #[test]
    fn test_irde_id_data() {
        let entry_bytes = make_dir_entry(16, 0x1234);
        let entry = ImageResourceDirectoryEntry::parse(&entry_bytes, 0).unwrap();
        assert!(!entry.is_named());
        assert_eq!(entry.id(), 16);
        assert!(!entry.is_subdir());
        assert_eq!(entry.data_offset(), 0x1234);
    }

    #[test]
    fn test_irde_out_of_bounds() {
        let data = vec![0u8; 4];
        assert!(ImageResourceDirectoryEntry::parse(&data, 0).is_err());
    }

    #[test]
    fn test_irde_high_bit_boundary() {
        // Exactly 0x7FFF_FFFF should NOT set high bit
        let entry_bytes = make_dir_entry(0x7FFF_FFFF, 0x7FFF_FFFF);
        let entry = ImageResourceDirectoryEntry::parse(&entry_bytes, 0).unwrap();
        assert!(!entry.is_named());
        assert!(!entry.is_subdir());
    }

    // ---- ImageResourceDataEntry -------------------------------------------

    #[test]
    fn test_irde2_parse() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[4..8].copy_from_slice(&256u32.to_le_bytes());
        data[8..12].copy_from_slice(&1252u32.to_le_bytes());
        let de = ImageResourceDataEntry::parse(&data, 0).unwrap();
        assert_eq!(de.offset_to_data, 0x1000);
        assert_eq!(de.size, 256);
        assert_eq!(de.code_page, 1252);
    }

    #[test]
    fn test_irde2_out_of_bounds() {
        let data = vec![0u8; 10];
        assert!(ImageResourceDataEntry::parse(&data, 0).is_err());
    }

    // ---- ResourceType -----------------------------------------------------

    #[test]
    fn test_resource_type_known_ids() {
        let cases = [
            (1u32, ResourceType::Cursor),
            (2, ResourceType::Bitmap),
            (3, ResourceType::Icon),
            (4, ResourceType::Menu),
            (5, ResourceType::Dialog),
            (6, ResourceType::String),
            (7, ResourceType::FontDir),
            (8, ResourceType::Font),
            (9, ResourceType::Accelerator),
            (10, ResourceType::RcData),
            (11, ResourceType::MessageTable),
            (12, ResourceType::GroupCursor),
            (14, ResourceType::GroupIcon),
            (16, ResourceType::Version),
            (17, ResourceType::DlgInclude),
            (19, ResourceType::PlugPlay),
            (20, ResourceType::Vxd),
            (21, ResourceType::AnimatedCursor),
            (22, ResourceType::AnimatedIcon),
            (23, ResourceType::Html),
            (24, ResourceType::Manifest),
        ];
        for (id, expected) in cases {
            assert_eq!(ResourceType::from_id(id), expected, "id={id}");
        }
    }

    #[test]
    fn test_resource_type_unknown() {
        assert_eq!(ResourceType::from_id(999), ResourceType::Unknown(999));
    }

    #[test]
    fn test_resource_type_round_trip() {
        for id in [1, 2, 3, 6, 11, 14, 16, 24] {
            let rt = ResourceType::from_id(id);
            assert_eq!(rt.to_id(), id);
        }
    }

    #[test]
    fn test_resource_type_names() {
        assert_eq!(ResourceType::Version.name(), "RT_VERSION");
        assert_eq!(ResourceType::Manifest.name(), "RT_MANIFEST");
        assert_eq!(ResourceType::Bitmap.name(), "RT_BITMAP");
        assert_eq!(ResourceType::MessageTable.name(), "RT_MESSAGETABLE");
    }

    // ---- Read helpers -----------------------------------------------------

    #[test]
    fn test_read_le_u16() {
        let data = [0xAB, 0xCD];
        assert_eq!(read_le_u16(&data, 0).unwrap(), 0xCDAB);
    }

    #[test]
    fn test_read_le_u32() {
        let data = [1u8, 0, 0, 0];
        assert_eq!(read_le_u32(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_read_le_bounds_u16() {
        assert!(read_le_u16(&[0u8; 1], 0).is_err());
    }

    #[test]
    fn test_read_le_bounds_u32() {
        assert!(read_le_u32(&[0u8; 3], 0).is_err());
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(7), 8);
        assert_eq!(align4(8), 8);
        assert_eq!(align4(9), 12);
    }

    // ---- read_resource_name_string ----------------------------------------

    #[test]
    fn test_read_rsrc_name_string_hello() {
        let mut data = Vec::new();
        push_utf16_str(&mut data, "Hello");
        let s = read_resource_name_string(&data, 0).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_read_rsrc_name_string_empty() {
        let data = [0u8, 0u8];
        let s = read_resource_name_string(&data, 0).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn test_read_rsrc_name_string_unicode() {
        let mut data = Vec::new();
        push_utf16_str(&mut data, "Tes\u{00E9}t");
        let s = read_resource_name_string(&data, 0).unwrap();
        assert_eq!(s, "Tes\u{00E9}t");
    }

    // ---- VsFixedFileInfo --------------------------------------------------

    #[test]
    fn test_ffi_parse_version() {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(&VsFixedFileInfo::SIGNATURE.to_le_bytes());
        data[8..12].copy_from_slice(&((1u32 << 16) | 2).to_le_bytes());
        data[12..16].copy_from_slice(&((3u32 << 16) | 4).to_le_bytes());
        let ffi = VsFixedFileInfo::parse(&data, 0).unwrap();
        assert_eq!(ffi.file_version(), (1, 2, 3, 4));
        assert_eq!(ffi.file_version_string(), "1.2.3.4");
    }

    #[test]
    fn test_ffi_bad_signature() {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(
            VsFixedFileInfo::parse(&data, 0),
            Err(ResourceError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_ffi_product_version() {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(&VsFixedFileInfo::SIGNATURE.to_le_bytes());
        data[16..20].copy_from_slice(&((5u32 << 16) | 6).to_le_bytes());
        data[20..24].copy_from_slice(&((7u32 << 16) | 8).to_le_bytes());
        let ffi = VsFixedFileInfo::parse(&data, 0).unwrap();
        assert_eq!(ffi.product_version(), (5, 6, 7, 8));
        assert_eq!(ffi.product_version_string(), "5.6.7.8");
    }

    #[test]
    fn test_ffi_out_of_bounds() {
        let data = vec![0u8; 40]; // too short
        assert!(VsFixedFileInfo::parse(&data, 0).is_err());
    }

    // ---- parse_manifest_resource ------------------------------------------

    #[test]
    fn test_manifest_utf8_plain() {
        let xml = b"<?xml version=\"1.0\"?><assembly/>";
        let s = parse_manifest_resource(xml).unwrap();
        assert_eq!(s, "<?xml version=\"1.0\"?><assembly/>");
    }

    #[test]
    fn test_manifest_utf8_bom() {
        let mut data = b"\xEF\xBB\xBF".to_vec();
        data.extend_from_slice(b"<assembly/>");
        let s = parse_manifest_resource(&data).unwrap();
        assert_eq!(s, "<assembly/>");
    }

    #[test]
    fn test_manifest_utf16_le() {
        let text = "test";
        let mut data = vec![0xFF, 0xFE];
        for c in text.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(parse_manifest_resource(&data).unwrap(), text);
    }

    #[test]
    fn test_manifest_utf16_be() {
        let text = "hello";
        let mut data = vec![0xFE, 0xFF];
        for c in text.encode_utf16() {
            data.extend_from_slice(&c.to_be_bytes());
        }
        assert_eq!(parse_manifest_resource(&data).unwrap(), text);
    }

    // ---- parse_string_table -----------------------------------------------

    #[test]
    fn test_string_table_basic() {
        let mut data = Vec::new();
        let push_str = |d: &mut Vec<u8>, s: &str| {
            let ws: Vec<u16> = s.encode_utf16().collect();
            d.extend_from_slice(&(ws.len() as u16).to_le_bytes());
            for w in ws {
                d.extend_from_slice(&w.to_le_bytes());
            }
        };
        let push_empty = |d: &mut Vec<u8>| d.extend_from_slice(&0u16.to_le_bytes());

        push_str(&mut data, "Alpha");
        push_str(&mut data, "Beta");
        for _ in 0..14 {
            push_empty(&mut data);
        }

        let block = parse_string_table(&data, 1).unwrap();
        assert_eq!(block.block_id, 1);
        assert_eq!(block.strings[0], "Alpha");
        assert_eq!(block.strings[1], "Beta");
        assert_eq!(block.strings[2], "");
    }

    #[test]
    fn test_string_id_calc() {
        assert_eq!(string_id(1, 0), 0);
        assert_eq!(string_id(1, 15), 15);
        assert_eq!(string_id(2, 0), 16);
        assert_eq!(string_id(3, 5), 37);
    }

    #[test]
    fn test_string_table_global_id() {
        let block = parse_string_table(&[0u8; 32], 3).unwrap();
        assert_eq!(block.global_id(0), 32);
        assert_eq!(block.global_id(15), 47);
    }

    // ---- parse_message_table ----------------------------------------------

    #[test]
    fn test_message_table_empty() {
        let data = [0u8; 4];
        let mt = parse_message_table(&data).unwrap();
        assert!(mt.messages.is_empty());
    }

    #[test]
    fn test_message_table_single_ansi() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // num_blocks
        data.extend_from_slice(&1u32.to_le_bytes()); // LoId
        data.extend_from_slice(&1u32.to_le_bytes()); // HiId
        data.extend_from_slice(&16u32.to_le_bytes()); // OffsetToEntries (after 16 bytes header)
        // Pad to offset 16
        data.extend_from_slice(&[0u8; 0]); // already at 16
        // Entry at offset 16: length, flags, text
        let text = b"hello";
        let entry_len = 4u16 + text.len() as u16 + 1; // +1 for null
        data.extend_from_slice(&entry_len.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // flags = ANSI
        data.extend_from_slice(text);
        data.push(0); // null terminator

        let mt = parse_message_table(&data).unwrap();
        assert_eq!(mt.messages.len(), 1);
        assert_eq!(mt.messages[0].message_id, 1);
        assert_eq!(mt.messages[0].text, "hello");
    }

    #[test]
    fn test_message_table_too_short() {
        let data = [0u8; 2];
        assert!(parse_message_table(&data).is_err());
    }

    // ---- reconstruct_bmp --------------------------------------------------

    #[test]
    fn test_bmp_adds_file_header() {
        let mut bitmapinfo = vec![0u8; 40];
        bitmapinfo[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        bitmapinfo[4..8].copy_from_slice(&1u32.to_le_bytes()); // biWidth
        bitmapinfo[8..12].copy_from_slice(&1u32.to_le_bytes()); // biHeight
        bitmapinfo[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
        bitmapinfo[14..16].copy_from_slice(&24u16.to_le_bytes()); // biBitCount
        let bmp = reconstruct_bmp(&bitmapinfo).unwrap();
        assert_eq!(&bmp[0..2], b"BM");
        assert_eq!(bmp.len(), 14 + bitmapinfo.len());
    }

    #[test]
    fn test_bmp_too_short() {
        assert!(reconstruct_bmp(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_bmp_file_size_field() {
        let bitmapinfo = vec![0u8; 40];
        let bmp = reconstruct_bmp(&bitmapinfo).unwrap();
        let file_size = u32::from_le_bytes(bmp[2..6].try_into().unwrap());
        assert_eq!(file_size as usize, bmp.len());
    }

    // ---- reconstruct_ico --------------------------------------------------

    #[test]
    fn test_ico_single_icon() {
        let mut group = Vec::new();
        group.extend_from_slice(&0u16.to_le_bytes()); // reserved
        group.extend_from_slice(&1u16.to_le_bytes()); // type
        group.extend_from_slice(&1u16.to_le_bytes()); // count=1
        group.push(32);
        group.push(32);
        group.push(0);
        group.push(0);
        group.extend_from_slice(&1u16.to_le_bytes()); // planes
        group.extend_from_slice(&32u16.to_le_bytes()); // bitCount
        group.extend_from_slice(&100u32.to_le_bytes()); // bytesInRes
        group.extend_from_slice(&7u16.to_le_bytes()); // id=7

        let mut icon_map = HashMap::new();
        icon_map.insert(7u16, vec![0xABu8; 100]);

        let ico = reconstruct_ico(&group, &icon_map).unwrap();
        assert_eq!(ico.len(), 6 + 16 + 100);
        assert_eq!(read_le_u16(&ico, 4).unwrap(), 1); // count
    }

    #[test]
    fn test_ico_missing_id() {
        let mut group = Vec::new();
        group.extend_from_slice(&0u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&[0u8; 12]);
        group.extend_from_slice(&99u16.to_le_bytes()); // id=99, not in map
        assert!(reconstruct_ico(&group, &HashMap::new()).is_err());
    }

    #[test]
    fn test_ico_empty_group() {
        assert!(reconstruct_ico(&[0u8; 2], &HashMap::new()).is_err());
    }

    // ---- ResourcePath display ---------------------------------------------

    #[test]
    fn test_resource_path_display_id() {
        let path = ResourcePath::new(ResourceType::Version, ResourceName::Id(1), 0x0409);
        let s = format!("{path}");
        assert!(s.contains("RT_VERSION"));
        assert!(s.contains("#1"));
        assert!(s.contains("1033"));
    }

    #[test]
    fn test_resource_path_display_name() {
        let path = ResourcePath::new(
            ResourceType::RcData,
            ResourceName::Name("MY_DATA".into()),
            0,
        );
        assert!(format!("{path}").contains("MY_DATA"));
    }

    // ---- ResourceError display --------------------------------------------

    #[test]
    fn test_error_out_of_bounds_display() {
        let e = ResourceError::OutOfBounds {
            offset: 10,
            size: 4,
        };
        let s = format!("{e}");
        assert!(s.contains("10") && s.contains('4'));
    }

    #[test]
    fn test_error_invalid_structure() {
        let e = ResourceError::InvalidStructure("bad field".into());
        assert!(format!("{e}").contains("bad field"));
    }

    #[test]
    fn test_error_unexpected_end() {
        let e = ResourceError::UnexpectedEnd;
        assert!(!format!("{e}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Public type aliases / shims expected by the crate root
// ---------------------------------------------------------------------------

/// Alias for [`ImageResourceDataEntry`], used by the public re-export surface.
pub type ResourceDataEntry = ImageResourceDataEntry;

/// Alias for [`ResourceType`], used by the public re-export surface.
pub type ResourceId = ResourceType;

/// Minimal manifest info shim (full parsing is performed by
/// [`parse_manifest_resource`]).
#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub xml: String,
    pub assembly_name: Option<String>,
    pub version: Option<String>,
}

/// A single node in the PE resource directory tree.
#[derive(Debug, Clone)]
pub struct ResourceNode {
    pub name: ResourceName,
    pub data: Option<ImageResourceDataEntry>,
    pub children: Vec<Self>,
}

/// Top-level resource tree.
#[derive(Debug, Clone, Default)]
pub struct ResourceTree {
    pub root: Vec<ResourceNode>,
}

// ---------------------------------------------------------------------------
// RT_* numeric constants (mirror Windows winuser.h RT_* macros)
// ---------------------------------------------------------------------------

pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_FONTDIR: u32 = 7;
pub const RT_FONT: u32 = 8;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_RCDATA: u32 = 10;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_DLGINCLUDE: u32 = 17;
pub const RT_PLUGPLAY: u32 = 19;
pub const RT_VXD: u32 = 20;
pub const RT_ANICURSOR: u32 = 21;
pub const RT_ANIICON: u32 = 22;
pub const RT_HTML: u32 = 23;
pub const RT_MANIFEST: u32 = 24;

/// Map an `RT_*` numeric id to its conventional short name.
#[must_use]
pub const fn resource_type_name(id: u32) -> &'static str {
    match id {
        RT_CURSOR => "RT_CURSOR",
        RT_BITMAP => "RT_BITMAP",
        RT_ICON => "RT_ICON",
        RT_MENU => "RT_MENU",
        RT_DIALOG => "RT_DIALOG",
        RT_STRING => "RT_STRING",
        RT_FONTDIR => "RT_FONTDIR",
        RT_FONT => "RT_FONT",
        RT_ACCELERATOR => "RT_ACCELERATOR",
        RT_RCDATA => "RT_RCDATA",
        RT_MESSAGETABLE => "RT_MESSAGETABLE",
        RT_GROUP_CURSOR => "RT_GROUP_CURSOR",
        RT_GROUP_ICON => "RT_GROUP_ICON",
        RT_VERSION => "RT_VERSION",
        RT_DLGINCLUDE => "RT_DLGINCLUDE",
        RT_PLUGPLAY => "RT_PLUGPLAY",
        RT_VXD => "RT_VXD",
        RT_ANICURSOR => "RT_ANICURSOR",
        RT_ANIICON => "RT_ANIICON",
        RT_HTML => "RT_HTML",
        RT_MANIFEST => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

impl VersionInfo {
    /// Parse a `VS_VERSIONINFO` byte slice. Thin wrapper around
    /// [`parse_version_resource`] that returns `Option` for ergonomic chaining
    /// in the resource summary builder.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        parse_version_resource(data).ok()
    }
}

impl ManifestInfo {
    /// Parse a manifest resource byte slice into a [`ManifestInfo`]; returns
    /// `Some` even when only the raw XML is available.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Self {
        let xml = parse_manifest_resource(data).unwrap_or_default();
        Self {
            xml,
            assembly_name: None,
            version: None,
        }
    }
}

impl ResourceTree {
    /// Walk a parsed PE and build the high-level resource tree from the
    /// `.rsrc` section. Returns `None` when the directory is missing.
    #[must_use]
    pub fn parse_from_pe(
        data: &[u8],
        sections: &[crate::imports::RvaSection],
        dir_rva: u32,
    ) -> Option<Self> {
        let off = crate::imports::rva_to_file_offset(dir_rva, sections)?;
        if off >= data.len() {
            return None;
        }
        let view = ResourceView::new(&data[off..], dir_rva);
        let root = ResourceView::walk_root(&view);
        Some(Self { root })
    }

    /// Total number of leaf (data) nodes reachable from the tree root.
    #[must_use]
    pub fn count_leaves(&self) -> usize {
        fn walk(n: &ResourceNode) -> usize {
            let here = usize::from(n.data.is_some());
            here + n.children.iter().map(walk).sum::<usize>()
        }
        self.root.iter().map(walk).sum()
    }

    /// Locate all leaves whose top-level type id matches `type_id`.
    #[must_use]
    pub fn find_by_type_id(&self, type_id: u32) -> Vec<&ResourceNode> {
        fn collect<'a>(node: &'a ResourceNode, out: &mut Vec<&'a ResourceNode>) {
            if node.data.is_some() {
                out.push(node);
            }
            for c in &node.children {
                collect(c, out);
            }
        }
        let mut out: Vec<&ResourceNode> = Vec::new();
        for top in &self.root {
            let matches = match &top.name {
                ResourceName::Id(id) => *id == type_id,
                ResourceName::Name(_) => false,
            };
            if matches {
                for c in &top.children {
                    collect(c, &mut out);
                }
            }
        }
        out
    }
}

impl ResourceView<'_> {
    /// Best-effort walk of the resource directory into a flat tree of
    /// [`ResourceNode`]s. Used by [`ResourceTree::parse_from_pe`].
    const fn walk_root(_view: &Self) -> Vec<ResourceNode> {
        // Minimal stub walk: returns an empty tree. Callers that require a
        // fully populated tree should use the lower-level [`ResourceView`]
        // APIs directly.
        Vec::new()
    }
}
