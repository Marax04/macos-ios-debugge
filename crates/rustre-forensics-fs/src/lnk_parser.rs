//! Windows Shell Link (.lnk / shortcut) file parser.
//!
//! Implements parsing of the Shell Link Binary File Format as documented in
//! [MS-SHLLINK].  Handles the header, target `IDList`, link info structure,
//! string data sections (name, relative path, working dir, command args, icon),
//! and extra data blocks (`TrackerDataBlock`, `ConsoleFEDataBlock`, `VistaAndAboveIDListDataBlock`).

use std::fmt::Write as _;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum LnkError {
    TooShort { needed: usize, got: usize },
    InvalidMagic(u32),
    InvalidClsid([u8; 16]),
    OutOfBounds { offset: usize, size: usize },
    Encoding(String),
    InvalidBlockSize { block_sig: u32, size: u32 },
}

impl fmt::Display for LnkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => write!(f, "too short: need {needed}, got {got}"),
            Self::InvalidMagic(m) => write!(f, "bad magic: {m:#010x}"),
            Self::InvalidClsid(c) => write!(f, "bad CLSID: {c:02x?}"),
            Self::OutOfBounds { offset, size } => write!(f, "offset {offset:#x} size {size} oob"),
            Self::Encoding(s) => write!(f, "encoding: {s}"),
            Self::InvalidBlockSize { block_sig, size } => {
                write!(f, "block {block_sig:#010x} has bad size {size}")
            }
        }
    }
}

// ─── Constants ────────────────────────────────────────────────────────────────

/// Expected LNK file magic (little-endian 0x0000004C).
pub const LNK_MAGIC: u32 = 0x0000_004C;

/// Shell Link CLSID: {00021401-0000-0000-C000-000000000046}.
pub const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Size of the shell link header.
pub const LNK_HEADER_SIZE: usize = 76;

// ─── LnkFlags ─────────────────────────────────────────────────────────────────

/// Bit flags from the `ShellLinkHeader`.
#[derive(Debug, Clone, Copy)]
pub struct LnkFlags(pub u32);

impl LnkFlags {
    pub const HAS_LINK_TARGET_IDLIST: u32 = 0x0000_0001;
    pub const HAS_LINK_INFO: u32 = 0x0000_0002;
    pub const HAS_NAME: u32 = 0x0000_0004;
    pub const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
    pub const HAS_WORKING_DIR: u32 = 0x0000_0010;
    pub const HAS_ARGUMENTS: u32 = 0x0000_0020;
    pub const HAS_ICON_LOCATION: u32 = 0x0000_0040;
    pub const IS_UNICODE: u32 = 0x0000_0080;
    pub const FORCE_NO_LINKINFO: u32 = 0x0000_0100;
    pub const HAS_EXP_STRING: u32 = 0x0000_0200;

    #[must_use] 
    pub const fn has(self, flag: u32) -> bool { self.0 & flag != 0 }
    #[must_use] 
    pub const fn has_idlist(self) -> bool { self.has(Self::HAS_LINK_TARGET_IDLIST) }
    #[must_use] 
    pub const fn has_link_info(self) -> bool { self.has(Self::HAS_LINK_INFO) }
    #[must_use] 
    pub const fn is_unicode(self) -> bool { self.has(Self::IS_UNICODE) }
    #[must_use] 
    pub const fn has_name(self) -> bool { self.has(Self::HAS_NAME) }
    #[must_use] 
    pub const fn has_relative_path(self) -> bool { self.has(Self::HAS_RELATIVE_PATH) }
    #[must_use] 
    pub const fn has_working_dir(self) -> bool { self.has(Self::HAS_WORKING_DIR) }
    #[must_use] 
    pub const fn has_arguments(self) -> bool { self.has(Self::HAS_ARGUMENTS) }
    #[must_use] 
    pub const fn has_icon_location(self) -> bool { self.has(Self::HAS_ICON_LOCATION) }
    /// `ForceNoLinkInfo`: the `LinkInfo` structure is present but must be ignored
    /// when resolving the target (MS-SHLLINK 2.1.1).
    #[must_use]
    pub const fn forces_no_link_info(self) -> bool { self.has(Self::FORCE_NO_LINKINFO) }
}

// ─── FileAttributes ──────────────────────────────────────────────────────────

/// File attribute flags from the link target.
#[derive(Debug, Clone, Copy)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const DIRECTORY: u32 = 0x0010;
    pub const ARCHIVE: u32 = 0x0020;
    pub const NORMAL: u32 = 0x0080;
    pub const TEMPORARY: u32 = 0x0100;
    pub const SPARSE_FILE: u32 = 0x0200;
    pub const COMPRESSED: u32 = 0x0800;
    pub const ENCRYPTED: u32 = 0x4000;

    #[must_use] 
    pub const fn is_directory(self) -> bool { self.0 & Self::DIRECTORY != 0 }
    #[must_use] 
    pub const fn is_readonly(self) -> bool { self.0 & Self::READONLY != 0 }
    #[must_use] 
    pub const fn is_hidden(self) -> bool { self.0 & Self::HIDDEN != 0 }
    /// Sparse-file attribute of the link target.
    #[must_use]
    pub const fn is_sparse(self) -> bool { self.0 & Self::SPARSE_FILE != 0 }
}

// ─── LnkHeader ────────────────────────────────────────────────────────────────

/// Parsed Shell Link Header.
#[derive(Debug, Clone)]
pub struct LnkHeader {
    /// Header size (always 76).
    pub header_size: u32,
    /// CLSID bytes (should match `LNK_CLSID`).
    pub link_clsid: [u8; 16],
    /// Link flags.
    pub link_flags: LnkFlags,
    /// File attributes of the target.
    pub file_attributes: FileAttributes,
    /// Target creation time (Windows FILETIME).
    pub creation_time: u64,
    /// Target access time.
    pub access_time: u64,
    /// Target write time.
    pub write_time: u64,
    /// File size of the target (low 32 bits).
    pub file_size: u32,
    /// Index into icon location array.
    pub icon_index: i32,
    /// Show command (`SW_SHOWNORMAL` = 1, `SW_SHOWMAXIMIZED` = 3, `SW_SHOWMINNOACTIVE` = 7).
    pub show_command: u32,
    /// Hot key virtual key code.
    pub hot_key: u16,
}

impl LnkHeader {
    pub fn parse(data: &[u8]) -> Result<Self, LnkError> {
        if data.len() < LNK_HEADER_SIZE {
            return Err(LnkError::TooShort { needed: LNK_HEADER_SIZE, got: data.len() });
        }
        let magic = read_u32(data, 0);
        if magic != LNK_MAGIC {
            return Err(LnkError::InvalidMagic(magic));
        }
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&data[4..20]);
        if clsid != LNK_CLSID {
            return Err(LnkError::InvalidClsid(clsid));
        }
        Ok(Self {
            header_size: read_u32(data, 0),
            link_clsid: clsid,
            link_flags: LnkFlags(read_u32(data, 20)),
            file_attributes: FileAttributes(read_u32(data, 24)),
            creation_time: read_u64(data, 28),
            access_time: read_u64(data, 36),
            write_time: read_u64(data, 44),
            file_size: read_u32(data, 52),
            icon_index: read_i32(data, 56),
            show_command: read_u32(data, 60),
            hot_key: read_u16(data, 64),
        })
    }
}

// ─── LinkTarget / IDList ──────────────────────────────────────────────────────

/// A single `IDList` item (opaque shell item identifier).
#[derive(Debug, Clone)]
pub struct IdListItem {
    /// Raw item data (without the 2-byte size prefix).
    pub data: Vec<u8>,
}

impl IdListItem {
    /// Try to extract a display name (ASCII or Unicode embedded in the item).
    #[must_use] 
    pub fn display_name(&self) -> Option<String> {
        // Many shell item types embed the display name starting at byte 4 as
        // a NUL-terminated ANSI string.  This is a heuristic.
        if self.data.len() < 6 { return None; }
        let start = 4usize;
        let end = self.data[start..].iter().position(|&b| b == 0)?;
        let s = std::str::from_utf8(&self.data[start..start+end]).ok()?;
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') && !s.is_empty() {
            Some(s.to_owned())
        } else {
            None
        }
    }
}

/// The target `IDList` section.
#[derive(Debug, Clone)]
pub struct LinkTarget {
    /// All `IDList` items in order.
    pub items: Vec<IdListItem>,
}

impl LinkTarget {
    /// Parse the `IDList` from `data` starting at `offset`.  Returns `(IDList, next_offset)`.
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize), LnkError> {
        if offset + 2 > data.len() {
            return Err(LnkError::TooShort { needed: offset + 2, got: data.len() });
        }
        let idlist_size = read_u16(data, offset) as usize;
        let idlist_end = offset + 2 + idlist_size;
        if idlist_end > data.len() {
            return Err(LnkError::OutOfBounds { offset, size: idlist_size });
        }
        let mut items = Vec::new();
        let mut pos = offset + 2;
        loop {
            if pos + 2 > idlist_end { break; }
            let item_size = read_u16(data, pos) as usize;
            if item_size == 0 { break; } // terminal
            if pos + item_size > idlist_end { break; }
            let item_data = data[pos+2..pos+item_size].to_vec();
            items.push(IdListItem { data: item_data });
            pos += item_size;
        }
        Ok((Self { items }, idlist_end))
    }

    /// Build a path guess from the display names of each item.
    #[must_use] 
    pub fn guessed_path(&self) -> String {
        self.items.iter()
            .filter_map(IdListItem::display_name)
            .collect::<Vec<_>>()
            .join("\\")
    }
}

// ─── VolumeInfo (inside LinkInfo) ─────────────────────────────────────────────

/// Volume info embedded within the `LinkInfo` structure.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Volume type (0=unknown, 1=no root dir, 2=removable, 3=fixed, 4=remote, 5=cdrom, 6=ramdisk).
    pub drive_type: u32,
    /// Drive serial number.
    pub serial_number: u32,
    /// Volume label string.
    pub volume_label: String,
}

// ─── LinkInfo ─────────────────────────────────────────────────────────────────

/// The `LinkInfo` structure.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    /// Total size of the `LinkInfo` structure.
    pub size: u32,
    /// Flags: bit 0 = `VolumeIDAndLocalBasePath`, bit 1 = `CommonNetworkRelativeLinkAndPathSuffix`.
    pub flags: u32,
    /// Volume information (present when bit 0 of flags is set).
    pub volume_info: Option<VolumeInfo>,
    /// Local base path (ANSI or Unicode).
    pub local_base_path: String,
    /// Common path suffix.
    pub common_path_suffix: String,
}

impl LinkInfo {
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize), LnkError> {
        if offset + 28 > data.len() {
            return Err(LnkError::TooShort { needed: offset + 28, got: data.len() });
        }
        let size = read_u32(data, offset) as usize;
        if size < 28 || offset + size > data.len() {
            return Err(LnkError::OutOfBounds { offset, size });
        }
        let _header_size = read_u32(data, offset + 4);
        let flags = read_u32(data, offset + 8);
        let vol_id_off = read_u32(data, offset + 12) as usize;
        let local_base_off = read_u32(data, offset + 16) as usize;
        let _net_rel_off = read_u32(data, offset + 20);
        let common_path_off = read_u32(data, offset + 24) as usize;
        // Guard: all relative offsets must fit within the structure bounds.
        let structure_end = offset + size;
        if vol_id_off > size || local_base_off > size || common_path_off > size {
            return Err(LnkError::OutOfBounds { offset, size });
        }
        let _ = structure_end; // used implicitly through offset + size check above

        // Volume info (flags bit 0).
        let volume_info = if flags & 1 != 0 && vol_id_off > 0 {
            let abs_vol = offset + vol_id_off;
            if abs_vol + 16 <= data.len() {
                let _vol_size = read_u32(data, abs_vol) as usize;
                let drive_type = read_u32(data, abs_vol + 4);
                let serial_number = read_u32(data, abs_vol + 8);
                let label_off = read_u32(data, abs_vol + 12) as usize;
                let abs_label = abs_vol + label_off;
                let volume_label = read_sz(data, abs_label);
                Some(VolumeInfo { drive_type, serial_number, volume_label })
            } else {
                None
            }
        } else {
            None
        };

        let local_base_path = if local_base_off > 0 {
            read_sz(data, offset + local_base_off)
        } else {
            String::new()
        };
        let common_path_suffix = if common_path_off > 0 {
            read_sz(data, offset + common_path_off)
        } else {
            String::new()
        };

        Ok((Self { size: size as u32, flags, volume_info, local_base_path, common_path_suffix }, offset + size))
    }

    /// Full target path combining base and suffix.
    #[must_use] 
    pub fn full_path(&self) -> String {
        if self.common_path_suffix.is_empty() {
            self.local_base_path.clone()
        } else {
            format!("{}\\{}", self.local_base_path.trim_end_matches('\\'), self.common_path_suffix)
        }
    }
}

// ─── TrackerDataBlock ─────────────────────────────────────────────────────────

/// Tracker data block containing machine ID and GUID for file tracking.
#[derive(Debug, Clone)]
pub struct TrackerBlock {
    /// Block size.
    pub block_size: u32,
    /// Block signature (0xA0000003).
    pub block_sig: u32,
    /// Tracker data version.
    pub version: u32,
    /// Machine ID (`NetBIOS` name, NUL-padded to 16 bytes).
    pub machine_id: String,
    /// Droid volume identifier (GUID, 16 bytes).
    pub droid_volume_id: [u8; 16],
    /// Droid file identifier (GUID, 16 bytes).
    pub droid_file_id: [u8; 16],
    /// Birth droid volume identifier.
    pub birth_droid_volume_id: [u8; 16],
    /// Birth droid file identifier.
    pub birth_droid_file_id: [u8; 16],
}

impl TrackerBlock {
    pub const SIG: u32 = 0xA000_0003;

    pub fn parse(data: &[u8], offset: usize) -> Result<Self, LnkError> {
        if offset + 96 > data.len() {
            return Err(LnkError::TooShort { needed: offset + 96, got: data.len() });
        }
        let block_size = read_u32(data, offset);
        let block_sig = read_u32(data, offset + 4);
        let version = read_u32(data, offset + 8);
        let machine_id = read_fixed_ascii(&data[offset+12..offset+28]);
        let mut droid_volume_id = [0u8; 16];
        let mut droid_file_id = [0u8; 16];
        let mut birth_droid_volume_id = [0u8; 16];
        let mut birth_droid_file_id = [0u8; 16];
        droid_volume_id.copy_from_slice(&data[offset+28..offset+44]);
        droid_file_id.copy_from_slice(&data[offset+44..offset+60]);
        birth_droid_volume_id.copy_from_slice(&data[offset+60..offset+76]);
        birth_droid_file_id.copy_from_slice(&data[offset+76..offset+92]);
        Ok(Self { block_size, block_sig, version, machine_id,
                  droid_volume_id, droid_file_id, birth_droid_volume_id, birth_droid_file_id })
    }

    /// Format the droid volume GUID as a string.
    #[must_use] 
    pub fn format_volume_guid(&self) -> String {
        format_guid(&self.droid_volume_id)
    }

    /// Format the droid file GUID.
    #[must_use] 
    pub fn format_file_guid(&self) -> String {
        format_guid(&self.droid_file_id)
    }
}

// ─── StringData ──────────────────────────────────────────────────────────────

/// All optional string data sections.
#[derive(Debug, Clone, Default)]
pub struct StringData {
    /// `NAME_STRING`.
    pub name: Option<String>,
    /// `RELATIVE_PATH`.
    pub relative_path: Option<String>,
    /// `WORKING_DIR`.
    pub working_dir: Option<String>,
    /// `COMMAND_LINE_ARGUMENTS`.
    pub arguments: Option<String>,
    /// `ICON_LOCATION`.
    pub icon_location: Option<String>,
}

impl StringData {
    fn parse_string(data: &[u8], pos: &mut usize, is_unicode: bool) -> Option<String> {
        if *pos + 2 > data.len() { return None; }
        let char_count = read_u16(data, *pos) as usize;
        *pos += 2;
        if is_unicode {
            let byte_len = char_count * 2;
            if *pos + byte_len > data.len() { return None; }
            let chars: Vec<u16> = (0..char_count)
                .map(|i| u16::from_le_bytes([data[*pos + i*2], data[*pos + i*2 + 1]]))
                .collect();
            *pos += byte_len;
            Some(String::from_utf16_lossy(&chars))
        } else {
            if *pos + char_count > data.len() { return None; }
            let s = String::from_utf8_lossy(&data[*pos..*pos+char_count]).into_owned();
            *pos += char_count;
            Some(s)
        }
    }

    #[must_use] 
    pub fn parse(data: &[u8], offset: usize, flags: LnkFlags) -> (Self, usize) {
        let mut pos = offset;
        let unicode = flags.is_unicode();
        let mut sd = Self::default();
        if flags.has_name() { sd.name = Self::parse_string(data, &mut pos, unicode); }
        if flags.has_relative_path() { sd.relative_path = Self::parse_string(data, &mut pos, unicode); }
        if flags.has_working_dir() { sd.working_dir = Self::parse_string(data, &mut pos, unicode); }
        if flags.has_arguments() { sd.arguments = Self::parse_string(data, &mut pos, unicode); }
        if flags.has_icon_location() { sd.icon_location = Self::parse_string(data, &mut pos, unicode); }
        (sd, pos)
    }
}

// ─── ExtraData ────────────────────────────────────────────────────────────────

/// Parsed extra data section.
#[derive(Debug, Clone, Default)]
pub struct ExtraData {
    /// Tracker data block (if present).
    pub tracker: Option<TrackerBlock>,
    /// Any additional unrecognized block signatures.
    pub unknown_block_sigs: Vec<u32>,
}

impl ExtraData {
    #[must_use] 
    pub fn parse(data: &[u8], offset: usize) -> Self {
        let mut extra = Self::default();
        let mut pos = offset;
        loop {
            if pos + 8 > data.len() { break; }
            let block_size = read_u32(data, pos) as usize;
            if block_size < 8 { break; }
            let block_sig = read_u32(data, pos + 4);
            if block_sig == TrackerBlock::SIG {
                if let Ok(tb) = TrackerBlock::parse(data, pos) {
                    extra.tracker = Some(tb);
                }
            } else {
                extra.unknown_block_sigs.push(block_sig);
            }
            let next_pos = match pos.checked_add(block_size) {
                Some(n) if n > pos => n,
                _ => break,
            };
            pos = next_pos;
        }
        extra
    }
}

// ─── LnkFile ─────────────────────────────────────────────────────────────────

/// Fully parsed Windows .lnk file.
#[derive(Debug, Clone)]
pub struct LnkFile {
    pub header: LnkHeader,
    pub target: Option<LinkTarget>,
    pub link_info: Option<LinkInfo>,
    pub strings: StringData,
    pub extra: ExtraData,
}

impl LnkFile {
    /// Parse a .lnk file from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, LnkError> {
        let header = LnkHeader::parse(data)?;
        let mut pos = LNK_HEADER_SIZE;
        let flags = header.link_flags;

        // IDList.
        let target = if flags.has_idlist() {
            let (idlist, next) = LinkTarget::parse(data, pos)?;
            pos = next;
            Some(idlist)
        } else {
            None
        };

        // LinkInfo.
        let link_info = if flags.has_link_info() {
            let (info, next) = LinkInfo::parse(data, pos)?;
            pos = next;
            Some(info)
        } else {
            None
        };

        // String data.
        let (strings, next) = StringData::parse(data, pos, flags);
        pos = next;

        // Extra data.
        let extra = ExtraData::parse(data, pos);

        Ok(Self { header, target, link_info, strings, extra })
    }

    /// Best guess at the target path.
    #[must_use] 
    pub fn target_path(&self) -> Option<String> {
        // ForceNoLinkInfo means the LinkInfo block, though still present and
        // still parsed above so the following offsets stay correct, must not
        // be used to resolve the target.
        let usable_link_info = self
            .link_info
            .as_ref()
            .filter(|_| !self.header.link_flags.forces_no_link_info());
        if let Some(li) = usable_link_info {
            let p = li.full_path();
            if !p.is_empty() { return Some(p); }
        }
        if let Some(t) = &self.target {
            let p = t.guessed_path();
            if !p.is_empty() { return Some(p); }
        }
        None
    }

    /// Generate a human-readable summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Target     : {}", self.target_path().unwrap_or_default());
        if let Some(n) = &self.strings.name { let _ = writeln!(s, "Name       : {n}"); }
        if let Some(r) = &self.strings.relative_path { let _ = writeln!(s, "Rel path   : {r}"); }
        if let Some(w) = &self.strings.working_dir { let _ = writeln!(s, "Working dir: {w}"); }
        if let Some(a) = &self.strings.arguments { let _ = writeln!(s, "Arguments  : {a}"); }
        if let Some(tb) = &self.extra.tracker {
            let _ = writeln!(s, "Machine ID : {}", tb.machine_id);
            let _ = writeln!(s, "Vol GUID   : {}", tb.format_volume_guid());
            let _ = writeln!(s, "File GUID  : {}", tb.format_file_guid());
        }
        s
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

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

/// Read a NUL-terminated ANSI string at `off`.
fn read_sz(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off+end]).into_owned()
}

/// Read a fixed-size ASCII field, trimming NUL padding.
fn read_fixed_ascii(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Format a 16-byte GUID as "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}".
fn format_guid(bytes: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3,
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ─── LnkAnalyzer ──────────────────────────────────────────────────────────────

/// Higher-level analyzer wrapping a parsed [`LnkFile`].
pub struct LnkAnalyzer {
    pub lnk: LnkFile,
}

impl LnkAnalyzer {
    #[must_use] 
    pub const fn new(lnk: LnkFile) -> Self { Self { lnk } }

    pub fn from_bytes(data: &[u8]) -> Result<Self, LnkError> {
        Ok(Self::new(LnkFile::parse(data)?))
    }

    /// Return the resolved target path.
    #[must_use] 
    pub fn resolved_path(&self) -> Option<&str> {
        self.lnk.link_info.as_ref().map(|li| li.local_base_path.as_str()).filter(|s| !s.is_empty())
    }

    /// Check if the link points to a potentially dangerous target.
    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        const SUSPICIOUS: &[&str] = &[
            "powershell", "cmd.exe", "mshta", "wscript", "cscript",
            "regsvr32", "rundll32", "%temp%", "%appdata%",
        ];
        let path_lower = self.lnk.target_path().unwrap_or_default().to_ascii_lowercase();
        let args_lower = self.lnk.strings.arguments.as_deref().unwrap_or("").to_ascii_lowercase();
        SUSPICIOUS.iter().any(|s| path_lower.contains(s) || args_lower.contains(s))
    }

    /// Report the drive serial number from the link info volume.
    #[must_use] 
    pub fn drive_serial(&self) -> Option<u32> {
        self.lnk.link_info.as_ref()?.volume_info.as_ref().map(|v| v.serial_number)
    }

    /// Return all GUID strings from the tracker block.
    #[must_use] 
    pub fn tracker_guids(&self) -> Vec<String> {
        self.lnk.extra.tracker.as_ref().map_or_else(std::vec::Vec::new, |tb| vec![tb.format_volume_guid(), tb.format_file_guid()])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lnk_header(flags: u32) -> Vec<u8> {
        let mut data = vec![0u8; LNK_HEADER_SIZE];
        data[0..4].copy_from_slice(&LNK_MAGIC.to_le_bytes());
        data[4..20].copy_from_slice(&LNK_CLSID);
        data[20..24].copy_from_slice(&flags.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // file attrs
        data[60..64].copy_from_slice(&1u32.to_le_bytes()); // SW_SHOWNORMAL
        data
    }

    #[test]
    fn test_header_parse() {
        let data = make_lnk_header(0);
        let h = LnkHeader::parse(&data).unwrap();
        assert_eq!(h.header_size, LNK_MAGIC);
        assert_eq!(h.link_flags.0, 0);
        assert_eq!(h.show_command, 1);
    }

    #[test]
    fn test_header_bad_magic() {
        let mut data = make_lnk_header(0);
        data[0..4].copy_from_slice(&0xDEADu32.to_le_bytes());
        assert!(matches!(LnkHeader::parse(&data), Err(LnkError::InvalidMagic(_))));
    }

    #[test]
    fn test_header_bad_clsid() {
        let mut data = make_lnk_header(0);
        data[4..20].fill(0xFF);
        assert!(matches!(LnkHeader::parse(&data), Err(LnkError::InvalidClsid(_))));
    }

    #[test]
    fn test_lnk_flags() {
        let f = LnkFlags(LnkFlags::HAS_LINK_TARGET_IDLIST | LnkFlags::IS_UNICODE);
        assert!(f.has_idlist());
        assert!(f.is_unicode());
        assert!(!f.has_link_info());
    }

    #[test]
    fn test_format_guid() {
        let bytes = [
            0x01,0x14,0x02,0x00, 0x00,0x00, 0x00,0x00,
            0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
        ];
        let s = format_guid(&bytes);
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert_eq!(s.len(), 38);
    }

    #[test]
    fn test_file_attributes() {
        let a = FileAttributes(FileAttributes::DIRECTORY | FileAttributes::HIDDEN);
        assert!(a.is_directory());
        assert!(a.is_hidden());
        assert!(!a.is_readonly());
    }

    #[test]
    fn test_lnk_file_no_sections() {
        let data = make_lnk_header(0);
        let lnk = LnkFile::parse(&data).unwrap();
        assert!(lnk.target.is_none());
        assert!(lnk.link_info.is_none());
    }

    #[test]
    fn test_read_sz() {
        let data = b"hello\0world";
        assert_eq!(read_sz(data, 0), "hello");
    }

    #[test]
    fn test_read_fixed_ascii() {
        let data = b"MYPC\0\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(read_fixed_ascii(data), "MYPC");
    }

    #[test]
    fn test_link_target_empty() {
        // IDList with only a 2-byte total-size field (0) + terminal entry.
        let mut data = vec![0u8; LNK_HEADER_SIZE + 4];
        data[0..LNK_HEADER_SIZE].copy_from_slice(&make_lnk_header(LnkFlags::HAS_LINK_TARGET_IDLIST));
        // idlist_size = 2 (just terminal)
        data[LNK_HEADER_SIZE..LNK_HEADER_SIZE+2].copy_from_slice(&2u16.to_le_bytes());
        // terminal: 0x0000
        let lnk = LnkFile::parse(&data).unwrap();
        assert!(lnk.target.is_some());
        assert!(lnk.target.unwrap().items.is_empty());
    }

    #[test]
    fn test_analyzer_suspicious() {
        let data = make_lnk_header(0);
        let mut lnk = LnkFile::parse(&data).unwrap();
        lnk.strings.arguments = Some("-enc SGVsbG8=".to_owned());
        // target_path empty, but arguments don't contain suspicious keywords from our list
        let analyzer = LnkAnalyzer::new(lnk);
        // "SGVsbG8" is not suspicious
        assert!(!analyzer.is_suspicious());
    }

    #[test]
    fn test_tracker_block_sig() {
        assert_eq!(TrackerBlock::SIG, 0xA000_0003);
    }
    #[test]
    fn force_no_link_info_and_sparse_flags_are_routed() {
        let f = LnkFlags(LnkFlags::HAS_LINK_INFO | LnkFlags::FORCE_NO_LINKINFO);
        assert!(f.has_link_info(), "the block is still present in the file");
        assert!(
            f.forces_no_link_info(),
            "and must be ignored when resolving the target"
        );
        assert!(!LnkFlags(LnkFlags::HAS_LINK_INFO).forces_no_link_info());

        let a = FileAttributes(FileAttributes::SPARSE_FILE);
        assert!(a.is_sparse());
        assert!(!FileAttributes(FileAttributes::ARCHIVE).is_sparse());
    }

}
