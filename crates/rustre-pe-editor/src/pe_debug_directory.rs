//! `pe_debug_directory` — PE debug directory parser and editor.
//!
//! Parses `IMAGE_DEBUG_DIRECTORY` entries from `DataDirectory[6]` of a PE
//! image, decodes `CodeView` PDB70 / PDB20 info blocks, and provides structures
//! for editing debug information.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by debug directory operations.
#[derive(Debug, Error, Clone)]
pub enum DebugDirError {
    /// The buffer is too short to read the required data.
    #[error("buffer too short: need {needed}, have {got}")]
    TooShort { needed: usize, got: usize },
    /// PE header is invalid.
    #[error("invalid PE header: {0}")]
    InvalidHeader(String),
    /// A debug entry has an inconsistent size or offset.
    #[error("malformed debug entry at index {index}: {reason}")]
    MalformedEntry { index: usize, reason: String },
    /// The `CodeView` signature is not recognised.
    #[error("unknown CodeView signature: {0:#010x}")]
    UnknownCvSignature(u32),
    /// An RVA could not be translated to a file offset.
    #[error("RVA {0:#x} could not be resolved to a file offset")]
    RvaUnresolvable(u32),
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugType
// ─────────────────────────────────────────────────────────────────────────────

/// Values for `IMAGE_DEBUG_DIRECTORY.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugType {
    /// Unknown type.
    Unknown,
    /// COFF debug information.
    Coff,
    /// `CodeView` (PDB pointer).
    CodeView,
    /// Frame Pointer Omission.
    Fpo,
    /// Copy of .DBG file.
    Misc,
    /// Exception table.
    Exception,
    /// Fixup data.
    Fixup,
    /// OMAP from source.
    OmapToSrc,
    /// OMAP to source.
    OmapFromSrc,
    /// Borland-specific.
    Borland,
    /// Reserved.
    Reserved10,
    /// CLR token mapping.
    ClrTokenMap,
    /// Extended DLL characteristics.
    VcFeature,
    /// Profile-guided optimization.
    Pogo,
    /// Incremental linker.
    Iltcg,
    /// MPX (Intel Memory Protection Extensions).
    Mpx,
    /// Repro build info.
    Repro,
    /// Spgo (Profile Guided Optimization).
    Spgo,
    /// Embeds portable PDB into the PE.
    EmbeddedPortablePdb,
    /// Other / vendor-specific.
    Other(u32),
}

impl DebugType {
    /// Construct from a raw `u32`.
    #[must_use]
    pub const fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Unknown,
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSrc,
            8 => Self::OmapFromSrc,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::ClrTokenMap,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Repro,
            17 => Self::Spgo,
            18 => Self::EmbeddedPortablePdb,
            other => Self::Other(other),
        }
    }

    /// Return the raw value.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Coff => 1,
            Self::CodeView => 2,
            Self::Fpo => 3,
            Self::Misc => 4,
            Self::Exception => 5,
            Self::Fixup => 6,
            Self::OmapToSrc => 7,
            Self::OmapFromSrc => 8,
            Self::Borland => 9,
            Self::Reserved10 => 10,
            Self::ClrTokenMap => 11,
            Self::VcFeature => 12,
            Self::Pogo => 13,
            Self::Iltcg => 14,
            Self::Mpx => 15,
            Self::Repro => 16,
            Self::Spgo => 17,
            Self::EmbeddedPortablePdb => 18,
            Self::Other(v) => v,
        }
    }
}

impl fmt::Display for DebugType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Coff => write!(f, "COFF"),
            Self::CodeView => write!(f, "CodeView"),
            Self::Fpo => write!(f, "FPO"),
            Self::Misc => write!(f, "Misc"),
            Self::Exception => write!(f, "Exception"),
            Self::Fixup => write!(f, "Fixup"),
            Self::OmapToSrc => write!(f, "OmapToSrc"),
            Self::OmapFromSrc => write!(f, "OmapFromSrc"),
            Self::Borland => write!(f, "Borland"),
            Self::Reserved10 => write!(f, "Reserved10"),
            Self::ClrTokenMap => write!(f, "ClrTokenMap"),
            Self::VcFeature => write!(f, "VcFeature"),
            Self::Pogo => write!(f, "POGO"),
            Self::Iltcg => write!(f, "ILTCG"),
            Self::Mpx => write!(f, "MPX"),
            Self::Repro => write!(f, "Repro"),
            Self::Spgo => write!(f, "SPGO"),
            Self::EmbeddedPortablePdb => write!(f, "EmbeddedPortablePDB"),
            Self::Other(v) => write!(f, "Other({v})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `IMAGE_DEBUG_DIRECTORY` entry (28 bytes each).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEntry {
    /// Index in the debug directory array.
    pub index: usize,
    /// Characteristics flags (reserved, always 0).
    pub characteristics: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version of the debug data format.
    pub major_version: u16,
    /// Minor version of the debug data format.
    pub minor_version: u16,
    /// Type of debug data.
    pub debug_type: DebugType,
    /// Size of the debug data.
    pub size_of_data: u32,
    /// RVA of the debug data when mapped.
    pub address_of_raw_data: u32,
    /// File offset of the debug data.
    pub pointer_to_raw_data: u32,
    /// Decoded `CodeView` info, if this entry is a `CodeView` entry.
    pub code_view_info: Option<CodeViewInfo>,
}

impl DebugEntry {
    /// Parse from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError::TooShort`] if the buffer is too short.
    pub fn parse(data: &[u8], offset: usize, index: usize) -> Result<Self, DebugDirError> {
        let needed = offset + 28;
        if data.len() < needed {
            return Err(DebugDirError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let characteristics = r32(data, offset);
        let time_date_stamp = r32(data, offset + 4);
        let major_version = r16(data, offset + 8);
        let minor_version = r16(data, offset + 10);
        let debug_type = DebugType::from_raw(r32(data, offset + 12));
        let size_of_data = r32(data, offset + 16);
        let address_of_raw_data = r32(data, offset + 20);
        let pointer_to_raw_data = r32(data, offset + 24);

        let code_view_info = if matches!(debug_type, DebugType::CodeView)
            && pointer_to_raw_data > 0
            && size_of_data >= 4
        {
            let raw_off = pointer_to_raw_data as usize;
            let raw_end = raw_off + size_of_data as usize;
            if raw_end <= data.len() {
                CodeViewInfo::parse(&data[raw_off..raw_end]).ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            index,
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            debug_type,
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
            code_view_info,
        })
    }

    /// Write this entry back into `data` at `offset` (does not write CV data).
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError::TooShort`] if the buffer is too short.
    pub fn write_header(&self, data: &mut [u8], offset: usize) -> Result<(), DebugDirError> {
        let needed = offset + 28;
        if data.len() < needed {
            return Err(DebugDirError::TooShort {
                needed,
                got: data.len(),
            });
        }
        w32(data, offset, self.characteristics);
        w32(data, offset + 4, self.time_date_stamp);
        w16(data, offset + 8, self.major_version);
        w16(data, offset + 10, self.minor_version);
        w32(data, offset + 12, self.debug_type.to_raw());
        w32(data, offset + 16, self.size_of_data);
        w32(data, offset + 20, self.address_of_raw_data);
        w32(data, offset + 24, self.pointer_to_raw_data);
        Ok(())
    }

    /// Returns the PDB path if this is a `CodeView` PDB70 or PDB20 entry.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        self.code_view_info.as_ref()?.pdb_path()
    }
}

impl fmt::Display for DebugEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DebugEntry[{}] type={} ts={:#010x} size={}",
            self.index, self.debug_type, self.time_date_stamp, self.size_of_data,
        )?;
        if let Some(pdb) = self.pdb_path() {
            write!(f, " pdb={pdb}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeViewInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded `CodeView` debug information block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodeViewInfo {
    /// `RSDS` (PDB 7.0) — most common format.
    Pdb70(Pdb70Info),
    /// `NB10` (PDB 2.0) — legacy format.
    Pdb20(Pdb20Info),
}

impl CodeViewInfo {
    /// Parse from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError::UnknownCvSignature`] for unrecognised signatures.
    pub fn parse(data: &[u8]) -> Result<Self, DebugDirError> {
        if data.len() < 4 {
            return Err(DebugDirError::TooShort {
                needed: 4,
                got: data.len(),
            });
        }
        let sig = r32(data, 0);
        match sig {
            0x5344_5352 => Ok(Self::Pdb70(Pdb70Info::parse(data)?)),
            0x3031_424E => Ok(Self::Pdb20(Pdb20Info::parse(data)?)),
            other => Err(DebugDirError::UnknownCvSignature(other)),
        }
    }

    /// The PDB file path regardless of version.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        match self {
            Self::Pdb70(info) => Some(&info.pdb_path),
            Self::Pdb20(info) => Some(&info.pdb_path),
        }
    }

    /// Returns `true` if this is a PDB 7.0 `RSDS` entry.
    #[must_use]
    pub const fn is_pdb70(&self) -> bool {
        matches!(self, Self::Pdb70(_))
    }

    /// Returns `true` if this is a PDB 2.0 `NB10` entry.
    #[must_use]
    pub const fn is_pdb20(&self) -> bool {
        matches!(self, Self::Pdb20(_))
    }
}

impl fmt::Display for CodeViewInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pdb70(i) => write!(
                f,
                "RSDS guid={} age={} path={}",
                i.guid_str(),
                i.age,
                i.pdb_path
            ),
            Self::Pdb20(i) => write!(
                f,
                "NB10 sig={:#010x} age={} path={}",
                i.signature, i.age, i.pdb_path
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pdb70Info / Pdb20Info
// ─────────────────────────────────────────────────────────────────────────────

/// `RSDS` `CodeView` PDB 7.0 info block.
///
/// ```text
/// DWORD  Signature;    // 0x53445352 "RSDS"
/// GUID   Guid;         // 16 bytes
/// DWORD  Age;
/// char   PdbFileName[]; // NUL-terminated
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pdb70Info {
    /// 16-byte GUID identifying the PDB.
    pub guid: [u8; 16],
    /// Age counter — must match the PDB.
    pub age: u32,
    /// Path to the PDB file.
    pub pdb_path: String,
}

impl Pdb70Info {
    /// Parse from the raw `CodeView` data block (must start with `RSDS`).
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError::TooShort`] if the data is truncated.
    pub fn parse(data: &[u8]) -> Result<Self, DebugDirError> {
        // Signature (4) + GUID (16) + Age (4) = 24 bytes minimum
        let needed = 24;
        if data.len() < needed {
            return Err(DebugDirError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[4..20]);
        let age = r32(data, 20);
        let pdb_path = read_cstr(&data[24..]);
        Ok(Self { guid, age, pdb_path })
    }

    /// Return a string representation of the GUID in the standard format
    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    #[must_use]
    pub fn guid_str(&self) -> String {
        let g = &self.guid;
        let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
        let d2 = u16::from_le_bytes([g[4], g[5]]);
        let d3 = u16::from_le_bytes([g[6], g[7]]);
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
        )
    }

    /// Serialize the `RSDS` block back to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"RSDS");
        out.extend_from_slice(&self.guid);
        out.extend_from_slice(&self.age.to_le_bytes());
        out.extend_from_slice(self.pdb_path.as_bytes());
        out.push(0); // NUL terminator
        out
    }
}

/// `NB10` `CodeView` PDB 2.0 info block.
///
/// ```text
/// DWORD  Signature;    // 0x3031424E "NB10"
/// DWORD  Offset;       // always 0
/// DWORD  Signature2;   // timestamp of the PDB
/// DWORD  Age;
/// char   PdbFileName[]; // NUL-terminated
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pdb20Info {
    /// File offset field (always 0 in practice).
    pub offset: u32,
    /// Timestamp signature matching the PDB.
    pub signature: u32,
    /// Age counter.
    pub age: u32,
    /// Path to the PDB file.
    pub pdb_path: String,
}

impl Pdb20Info {
    /// Parse from the raw `CodeView` data block (must start with `NB10`).
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError::TooShort`] if the data is truncated.
    pub fn parse(data: &[u8]) -> Result<Self, DebugDirError> {
        let needed = 16;
        if data.len() < needed {
            return Err(DebugDirError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let offset = r32(data, 4);
        let signature = r32(data, 8);
        let age = r32(data, 12);
        let pdb_path = read_cstr(&data[16..]);
        Ok(Self { offset, signature, age, pdb_path })
    }

    /// Serialize the `NB10` block back to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"NB10");
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.signature.to_le_bytes());
        out.extend_from_slice(&self.age.to_le_bytes());
        out.extend_from_slice(self.pdb_path.as_bytes());
        out.push(0);
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeDebugDirectory
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the debug directory of a PE binary.
///
/// Parses `DataDirectory[6]` and provides access to all debug entries,
/// including `CodeView` PDB pointers.  Also provides in-place editing to
/// strip or replace debug information.
pub struct PeDebugDirectory {
    data: Vec<u8>,
    dir_offset: usize,
    entry_count: usize,
    entries: Vec<DebugEntry>,
}

impl PeDebugDirectory {
    /// Parse the debug directory from a PE image.
    ///
    /// If no debug directory is present, [`Self::entry_count`] will return 0.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError`] if the PE header is invalid.
    pub fn parse(data: Vec<u8>) -> Result<Self, DebugDirError> {
        let (dir_rva, dir_size) = debug_data_directory(&data)?;
        if dir_rva == 0 || dir_size == 0 {
            return Ok(Self {
                data,
                dir_offset: 0,
                entry_count: 0,
                entries: Vec::new(),
            });
        }
        let dir_offset = rva_to_file_offset(&data, dir_rva)? as usize;
        let entry_count = dir_size as usize / 28;
        let mut entries = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let off = dir_offset + i * 28;
            match DebugEntry::parse(&data, off, i) {
                Ok(e) => entries.push(e),
                Err(DebugDirError::TooShort { .. }) => break,
                Err(e) => {
                    return Err(DebugDirError::MalformedEntry {
                        index: i,
                        reason: e.to_string(),
                    })
                }
            }
        }
        Ok(Self {
            data,
            dir_offset,
            entry_count,
            entries,
        })
    }

    /// Number of debug directory entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Iterate over all parsed entries.
    pub fn iter(&self) -> impl Iterator<Item = &DebugEntry> {
        self.entries.iter()
    }

    /// Return all `CodeView` entries.
    #[must_use]
    pub fn code_view_entries(&self) -> Vec<&DebugEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.debug_type, DebugType::CodeView))
            .collect()
    }

    /// Return the first PDB path found in any `CodeView` entry.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        self.entries.iter().find_map(|e| e.pdb_path())
    }

    /// Replace the PDB path in all RSDS `CodeView` entries.
    ///
    /// The new path is written into the raw data block in-place.  If the new
    /// path is longer than the existing one, it is truncated to fit.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError`] if entries cannot be written.
    pub fn set_pdb_path(&mut self, new_path: &str) -> Result<usize, DebugDirError> {
        let mut count = 0;
        for entry in &self.entries {
            if !matches!(entry.debug_type, DebugType::CodeView) {
                continue;
            }
            let raw_off = entry.pointer_to_raw_data as usize;
            let raw_size = entry.size_of_data as usize;
            if raw_off + raw_size > self.data.len() || raw_size < 24 {
                continue;
            }
            let sig = r32(&self.data, raw_off);
            if sig == 0x5344_5352 {
                // RSDS
                let path_start = raw_off + 24;
                let path_end = raw_off + raw_size;
                let max_len = path_end.saturating_sub(path_start).saturating_sub(1);
                let write_len = new_path.len().min(max_len);
                self.data[path_start..path_start + write_len]
                    .copy_from_slice(&new_path.as_bytes()[..write_len]);
                if path_start + write_len < path_end {
                    self.data[path_start + write_len] = 0;
                }
                count += 1;
            }
        }
        Ok(count)
    }

    /// Zero the timestamp field in all debug directory entries.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError`] if the buffer is too short.
    pub fn zero_timestamps(&mut self) -> Result<(), DebugDirError> {
        for i in 0..self.entry_count {
            let off = self.dir_offset + i * 28 + 4;
            if off + 4 <= self.data.len() {
                w32(&mut self.data, off, 0);
            }
        }
        Ok(())
    }

    /// Strip all debug directory entries by zeroing the data directory entry
    /// and the raw debug data.
    ///
    /// # Errors
    ///
    /// Returns [`DebugDirError`] if the PE header is malformed.
    pub fn strip_all(mut self) -> Result<Vec<u8>, DebugDirError> {
        // Zero raw data blocks
        for entry in &self.entries {
            let raw_off = entry.pointer_to_raw_data as usize;
            let raw_sz = entry.size_of_data as usize;
            let end = (raw_off + raw_sz).min(self.data.len());
            if raw_off < end {
                self.data[raw_off..end].fill(0);
            }
        }
        // Zero the directory itself
        if self.dir_offset > 0 {
            let end = (self.dir_offset + self.entry_count * 28).min(self.data.len());
            self.data[self.dir_offset..end].fill(0);
        }
        // Clear data directory[6]
        clear_debug_directory(&mut self.data)?;
        Ok(self.data)
    }

    /// Consume the editor and return the (possibly modified) bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl fmt::Debug for PeDebugDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeDebugDirectory {{ dir_offset={:#x} entries={} }}",
            self.dir_offset,
            self.entries.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn debug_data_directory(data: &[u8]) -> Result<(u32, u32), DebugDirError> {
    if data.len() < 64 {
        return Err(DebugDirError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    if pe_off + 24 + 2 > data.len() {
        return Err(DebugDirError::InvalidHeader("truncated".to_string()));
    }
    let sig = r32(data, pe_off);
    if sig != 0x0000_4550 {
        return Err(DebugDirError::InvalidHeader("bad PE sig".to_string()));
    }
    let opt_off = pe_off + 24;
    let magic = r16(data, opt_off);
    let is_64 = magic == 0x020B;
    let dd_base = if is_64 { opt_off + 112 } else { opt_off + 96 };
    let debug_dd_off = dd_base + 6 * 8; // DataDirectory[6]
    if debug_dd_off + 8 > data.len() {
        return Ok((0, 0));
    }
    Ok((r32(data, debug_dd_off), r32(data, debug_dd_off + 4)))
}

fn clear_debug_directory(data: &mut [u8]) -> Result<(), DebugDirError> {
    if data.len() < 64 {
        return Err(DebugDirError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    let opt_off = pe_off + 24;
    let magic = r16(data, opt_off);
    let is_64 = magic == 0x020B;
    let dd_base = if is_64 { opt_off + 112 } else { opt_off + 96 };
    let debug_dd_off = dd_base + 6 * 8;
    if debug_dd_off + 8 <= data.len() {
        data[debug_dd_off..debug_dd_off + 8].fill(0);
    }
    Ok(())
}

fn rva_to_file_offset(data: &[u8], rva: u32) -> Result<u32, DebugDirError> {
    if data.len() < 64 {
        return Err(DebugDirError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    let n_sects = r16(data, pe_off + 6) as usize;
    let opt_size = r16(data, pe_off + 20) as usize;
    let sect_base = pe_off + 24 + opt_size;
    for i in 0..n_sects {
        let off = sect_base + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let va = r32(data, off + 12);
        let vsz = r32(data, off + 8);
        let raw = r32(data, off + 20);
        if rva >= va && rva < va.saturating_add(vsz) {
            return Ok(raw + (rva - va));
        }
    }
    Err(DebugDirError::RvaUnresolvable(rva))
}

fn read_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

#[inline]
fn r16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn r32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn w32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn w16(data: &mut [u8], off: usize, val: u16) {
    data[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_type_roundtrip() {
        for &v in &[0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 999] {
            assert_eq!(DebugType::from_raw(v).to_raw(), v);
        }
    }

    #[test]
    fn test_pdb70_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0x01u8; 16]); // GUID
        data.extend_from_slice(&2u32.to_le_bytes()); // age
        data.extend_from_slice(b"C:\\foo\\bar.pdb\0");
        let info = Pdb70Info::parse(&data).unwrap();
        assert_eq!(info.age, 2);
        assert_eq!(info.pdb_path, "C:\\foo\\bar.pdb");
    }

    #[test]
    fn test_pdb70_guid_str() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"x.pdb\0");
        let info = Pdb70Info::parse(&data).unwrap();
        let g = info.guid_str();
        assert!(g.starts_with('{'));
        assert!(g.ends_with('}'));
    }

    #[test]
    fn test_pdb20_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NB10");
        data.extend_from_slice(&0u32.to_le_bytes()); // offset
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sig
        data.extend_from_slice(&3u32.to_le_bytes()); // age
        data.extend_from_slice(b"old.pdb\0");
        let info = Pdb20Info::parse(&data).unwrap();
        assert_eq!(info.signature, 0xDEAD_BEEF);
        assert_eq!(info.age, 3);
        assert_eq!(info.pdb_path, "old.pdb");
    }

    #[test]
    fn test_code_view_info_rsds() {
        let mut data = Vec::new();
        data.extend_from_slice(b"RSDS");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"test.pdb\0");
        let cv = CodeViewInfo::parse(&data).unwrap();
        assert!(cv.is_pdb70());
        assert_eq!(cv.pdb_path(), Some("test.pdb"));
    }

    #[test]
    fn test_code_view_info_unknown_sig() {
        let data = b"XXXX\x00\x00\x00\x00".to_vec();
        assert!(matches!(
            CodeViewInfo::parse(&data),
            Err(DebugDirError::UnknownCvSignature(_))
        ));
    }

    #[test]
    fn test_pdb70_to_bytes_roundtrip() {
        let orig = Pdb70Info {
            guid: [0xABu8; 16],
            age: 7,
            pdb_path: "myapp.pdb".to_string(),
        };
        let bytes = orig.to_bytes();
        let parsed = Pdb70Info::parse(&bytes).unwrap();
        assert_eq!(parsed.guid, orig.guid);
        assert_eq!(parsed.age, orig.age);
        assert_eq!(parsed.pdb_path, orig.pdb_path);
    }

    #[test]
    fn test_debug_entry_write_header_roundtrip() {
        let mut buf = vec![0u8; 28];
        // Write a fake entry
        let entry = DebugEntry {
            index: 0,
            characteristics: 0,
            time_date_stamp: 0x1234_5678,
            major_version: 1,
            minor_version: 0,
            debug_type: DebugType::CodeView,
            size_of_data: 100,
            address_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
            code_view_info: None,
        };
        entry.write_header(&mut buf, 0).unwrap();
        let parsed = DebugEntry::parse(&buf, 0, 0).unwrap();
        assert_eq!(parsed.time_date_stamp, 0x1234_5678);
        assert!(matches!(parsed.debug_type, DebugType::CodeView));
    }
}
