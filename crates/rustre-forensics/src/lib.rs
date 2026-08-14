//! `rustre-forensics` — Core forensics framework.
//!
//! Provides `ForensicsEngine`, `MemoryImage`, chain-of-custody tracking,
//! multi-hash evidence verification, timeline reconstruction, artifact
//! extraction traits, signature scanning, case management, and reporting.

pub mod artifact_extractor;
pub mod artifact_store;
pub mod collection_engine;
pub mod evidence_collector;
pub mod incident_timeline;
pub mod malware_forensics;
pub mod memory_acquisition;
pub mod memory_dump_analyzer;
pub mod os_adapter;
pub mod timeline_builder;
pub mod timeline_correlator;
pub mod filesystem_carver;
pub mod registry_hive_analyzer;
pub mod prefetch_analyzer;
pub mod sysinternals_bridge;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ForensicsError {
    #[error("read error at address 0x{addr:016x}: {msg}")]
    ReadError { addr: u64, msg: String },
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("operation not supported: {0}")]
    NotSupported(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("case not found: {0}")]
    CaseNotFound(String),
    #[error("evidence locked: {0}")]
    EvidenceLocked(String),
}

impl From<std::io::Error> for ForensicsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── Architecture / OS ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchBits {
    Bits32,
    Bits64,
}

impl ArchBits {
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    Linux,
    MacOs,
    Unknown,
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

pub mod perms {
    pub const READ: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const EXEC: u8 = 0x04;
    pub const RWX: u8 = READ | WRITE | EXEC;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: u8,
    pub name: Option<String>,
}

impl MemoryRegion {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    #[must_use]
    pub const fn is_exec(&self) -> bool {
        self.perms & perms::EXEC != 0
    }
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.perms & perms::WRITE != 0
    }
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.perms & perms::READ != 0
    }
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ─── MemoryImage trait ────────────────────────────────────────────────────────

pub trait MemoryImage: Send + Sync {
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError>;
    fn regions(&self) -> Vec<MemoryRegion>;
    fn arch(&self) -> ArchBits;
    fn os_type(&self) -> OsType;

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn read_u32_le(&self, addr: u64) -> Result<u32, ForensicsError> {
        let b = self.read(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn read_u64_le(&self, addr: u64) -> Result<u64, ForensicsError> {
        let b = self.read(addr, 8)?;
        Ok(u64::from_le_bytes(b[..8].try_into().map_err(|_| {
            ForensicsError::InvalidData("u64 slice".into())
        })?))
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn read_ptr(&self, addr: u64) -> Result<u64, ForensicsError> {
        match self.arch() {
            ArchBits::Bits32 => self.read_u32_le(addr).map(u64::from),
            ArchBits::Bits64 => self.read_u64_le(addr),
        }
    }
}

// ─── RawMemoryImage ───────────────────────────────────────────────────────────

pub struct RawMemoryImage {
    data: Vec<u8>,
    arch: ArchBits,
    os: OsType,
    base: u64,
}

impl RawMemoryImage {
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn from_file(path: &Path, arch: ArchBits, os: OsType) -> Result<Self, ForensicsError> {
        let data = fs::read(path).map_err(ForensicsError::from)?;
        Ok(Self {
            data,
            arch,
            os,
            base: 0,
        })
    }
    #[must_use]
    pub const fn from_bytes(data: Vec<u8>, arch: ArchBits, os: OsType) -> Self {
        Self {
            data,
            arch,
            os,
            base: 0,
        }
    }
    #[must_use]
    pub const fn from_bytes_with_base(data: Vec<u8>, arch: ArchBits, os: OsType, base: u64) -> Self {
        Self {
            data,
            arch,
            os,
            base,
        }
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }
}

impl MemoryImage for RawMemoryImage {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError> {
        let offset = usize::try_from(addr
            .checked_sub(self.base)
            .ok_or_else(|| ForensicsError::ReadError {
                addr,
                msg: "address below image base".into(),
            })?).unwrap_or(usize::MAX);
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ForensicsError::ReadError {
                addr,
                msg: "read length overflow".into(),
            })?;
        if end > self.data.len() {
            return Err(ForensicsError::ReadError {
                addr,
                msg: format!(
                    "out of bounds: offset {offset} + len {len} > {}",
                    self.data.len()
                ),
            });
        }
        Ok(self.data[offset..end].to_vec())
    }
    fn regions(&self) -> Vec<MemoryRegion> {
        vec![MemoryRegion {
            start: self.base,
            end: self.base + self.data.len() as u64,
            perms: perms::READ | perms::WRITE | perms::EXEC,
            name: Some("raw_image".into()),
        }]
    }
    fn arch(&self) -> ArchBits {
        self.arch
    }
    fn os_type(&self) -> OsType {
        self.os
    }
}

// ─── ELF core dump ────────────────────────────────────────────────────────────

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;

#[derive(Debug, Clone, Default)]
pub struct PrStatus {
    pub pid: i32,
    pub ppid: i32,
    pub signal: i32,
}

#[derive(Debug, Clone, Default)]
pub struct PrPsInfo {
    pub pid: i32,
    pub ppid: i32,
    pub filename: String,
    pub args: String,
}

pub struct ElfCoredumpImage {
    segments: Vec<(u64, Vec<u8>)>,
    regions: Vec<MemoryRegion>,
    arch: ArchBits,
    pub prstatus: Option<PrStatus>,
    pub prpsinfo: Option<PrPsInfo>,
}

impl ElfCoredumpImage {
    const PT_LOAD: u32 = 1;
    const PT_NOTE: u32 = 4;

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ForensicsError> {
        if data.len() < 64 {
            return Err(ForensicsError::ParseError("ELF header too short".into()));
        }
        if &data[0..4] != b"\x7fELF" {
            return Err(ForensicsError::ParseError("Not an ELF file".into()));
        }
        let ei_class = data[4];
        let arch = if ei_class == 2 {
            ArchBits::Bits64
        } else {
            ArchBits::Bits32
        };
        if data[5] != 1 {
            return Err(ForensicsError::NotSupported(
                "Big-endian ELF not supported".into(),
            ));
        }

        let mut segments: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut regions: Vec<MemoryRegion> = Vec::new();
        let mut prstatus: Option<PrStatus> = None;
        let mut prpsinfo: Option<PrPsInfo> = None;

        if arch == ArchBits::Bits64 {
            Self::parse_segments_64(data, &mut segments, &mut regions, &mut prstatus, &mut prpsinfo);
        } else {
            if data.len() < 52 {
                return Err(ForensicsError::ParseError(
                    "32-bit ELF header too short".into(),
                ));
            }
            Self::parse_segments_32(data, &mut segments, &mut regions, &mut prstatus, &mut prpsinfo);
        }
        Ok(Self {
            segments,
            regions,
            arch,
            prstatus,
            prpsinfo,
        })
    }

    fn parse_segments_64(
        data: &[u8],
        segments: &mut Vec<(u64, Vec<u8>)>,
        regions: &mut Vec<MemoryRegion>,
        prstatus: &mut Option<PrStatus>,
        prpsinfo: &mut Option<PrPsInfo>,
    ) {
        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]));
        let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap_or([0; 2])) as usize;
        let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap_or([0; 2])) as usize;
        for i in 0..e_phnum {
            let ph_off = usize::try_from(e_phoff).unwrap_or(usize::MAX)
                .saturating_add(i.saturating_mul(e_phentsize));
            if ph_off + 56 > data.len() {
                break;
            }
            let ph = &data[ph_off..ph_off + 56];
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap_or([0; 4]));
            let p_flags = u32::from_le_bytes(ph[4..8].try_into().unwrap_or([0; 4]));
            let p_offset = usize::try_from(u64::from_le_bytes(ph[8..16].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
            let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap_or([0; 8]));
            let p_filesz = usize::try_from(u64::from_le_bytes(ph[32..40].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
            let p_memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap_or([0; 8]));
            if p_type == Self::PT_LOAD && p_filesz > 0 {
                let end_off = p_offset.saturating_add(p_filesz);
                if end_off <= data.len() {
                    regions.push(MemoryRegion {
                        start: p_vaddr,
                        end: p_vaddr + p_memsz,
                        perms: Self::perms_from_flags(p_flags),
                        name: None,
                    });
                    segments.push((p_vaddr, data[p_offset..end_off].to_vec()));
                }
            } else if p_type == Self::PT_NOTE && p_filesz > 0 {
                let end_off = p_offset.saturating_add(p_filesz);
                if end_off <= data.len() {
                    Self::parse_notes_64(&data[p_offset..end_off], prstatus, prpsinfo);
                }
            }
        }
    }

    fn parse_segments_32(
        data: &[u8],
        segments: &mut Vec<(u64, Vec<u8>)>,
        regions: &mut Vec<MemoryRegion>,
        prstatus: &mut Option<PrStatus>,
        prpsinfo: &mut Option<PrPsInfo>,
    ) {
        let e_phoff = u32::from_le_bytes(data[28..32].try_into().unwrap_or([0; 4])) as usize;
        let e_phentsize = u16::from_le_bytes(data[42..44].try_into().unwrap_or([0; 2])) as usize;
        let e_phnum = u16::from_le_bytes(data[44..46].try_into().unwrap_or([0; 2])) as usize;
        for i in 0..e_phnum {
            let ph_off = e_phoff.saturating_add(i.saturating_mul(e_phentsize));
            if ph_off + 32 > data.len() {
                break;
            }
            let ph = &data[ph_off..ph_off + 32];
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap_or([0; 4]));
            let p_offset = u32::from_le_bytes(ph[4..8].try_into().unwrap_or([0; 4])) as usize;
            let p_vaddr = u64::from(u32::from_le_bytes(ph[8..12].try_into().unwrap_or([0; 4])));
            let p_filesz = u32::from_le_bytes(ph[16..20].try_into().unwrap_or([0; 4])) as usize;
            let p_memsz = u64::from(u32::from_le_bytes(ph[20..24].try_into().unwrap_or([0; 4])));
            let p_flags = u32::from_le_bytes(ph[24..28].try_into().unwrap_or([0; 4]));
            if p_type == Self::PT_LOAD && p_filesz > 0 {
                let end_off = p_offset.saturating_add(p_filesz);
                if end_off <= data.len() {
                    regions.push(MemoryRegion {
                        start: p_vaddr,
                        end: p_vaddr + p_memsz,
                        perms: Self::perms_from_flags(p_flags),
                        name: None,
                    });
                    segments.push((p_vaddr, data[p_offset..end_off].to_vec()));
                }
            } else if p_type == Self::PT_NOTE && p_filesz > 0 {
                let end_off = p_offset.saturating_add(p_filesz);
                if end_off <= data.len() {
                    Self::parse_notes_32(&data[p_offset..end_off], prstatus, prpsinfo);
                }
            }
        }
    }

    const fn perms_from_flags(p_flags: u32) -> u8 {
        let mut pb: u8 = 0;
        if p_flags & 4 != 0 {
            pb |= perms::READ;
        }
        if p_flags & 2 != 0 {
            pb |= perms::WRITE;
        }
        if p_flags & 1 != 0 {
            pb |= perms::EXEC;
        }
        pb
    }

    fn parse_notes_64(
        data: &[u8],
        prstatus: &mut Option<PrStatus>,
        prpsinfo: &mut Option<PrPsInfo>,
    ) {
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let namesz =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
            let descsz =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            let note_type =
                u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
            offset += 12;
            let name_end = offset + namesz;
            let desc_start = (name_end + 3) & !3;
            let desc_end = desc_start + descsz;
            if desc_end > data.len() {
                break;
            }
            let desc = &data[desc_start..desc_end];
            if note_type == NT_PRSTATUS && desc.len() >= 32 {
                let signal = i32::from_le_bytes(desc[12..16].try_into().unwrap_or([0; 4]));
                let pid = i32::from_le_bytes(desc[24..28].try_into().unwrap_or([0; 4]));
                let parent_pid = i32::from_le_bytes(desc[28..32].try_into().unwrap_or([0; 4]));
                *prstatus = Some(PrStatus { pid, ppid: parent_pid, signal });
            } else if note_type == NT_PRPSINFO && desc.len() >= 28 {
                let pid = i32::from_le_bytes(desc[24..28].try_into().unwrap_or([0; 4]));
                let parent_pid = i32::from_le_bytes(desc[20..24].try_into().unwrap_or([0; 4]));
                let filename = if desc.len() > 28 {
                    let nb = &desc[28..desc.len().min(44)];
                    let nul = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
                    String::from_utf8_lossy(&nb[..nul]).into_owned()
                } else {
                    String::new()
                };
                *prpsinfo = Some(PrPsInfo {
                    pid,
                    ppid: parent_pid,
                    filename,
                    args: String::new(),
                });
            }
            offset = desc_end;
            offset = (offset + 3) & !3;
        }
    }

    fn parse_notes_32(
        data: &[u8],
        prstatus: &mut Option<PrStatus>,
        prpsinfo: &mut Option<PrPsInfo>,
    ) {
        // 32-bit elf_prstatus layout differs from 64-bit:
        //   signal  @ offset 12 (same as 64-bit)
        //   pid     @ offset 24 (same as 64-bit for elf_prstatus32)
        //   ppid    @ offset 20 (differs: 64-bit has ppid at 28, 32-bit at 20)
        // 32-bit elf_prpsinfo layout:
        //   ppid    @ offset 8
        //   pid     @ offset 12
        //   filename@ offset 16
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let namesz =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
            let descsz =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            let note_type =
                u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
            offset += 12;
            let name_end = offset + namesz;
            let desc_start = (name_end + 3) & !3;
            let desc_end = desc_start + descsz;
            if desc_end > data.len() {
                break;
            }
            let desc = &data[desc_start..desc_end];
            if note_type == NT_PRSTATUS && desc.len() >= 28 {
                // 32-bit elf_prstatus: signal at offset 12, ppid at 20, pid at 24
                let signal = i32::from_le_bytes(desc[12..16].try_into().unwrap_or([0; 4]));
                let parent_pid = i32::from_le_bytes(desc[20..24].try_into().unwrap_or([0; 4]));
                let pid = i32::from_le_bytes(desc[24..28].try_into().unwrap_or([0; 4]));
                *prstatus = Some(PrStatus { pid, ppid: parent_pid, signal });
            } else if note_type == NT_PRPSINFO && desc.len() >= 16 {
                // 32-bit elf_prpsinfo: ppid at 8, pid at 12, filename at 16
                let parent_pid = i32::from_le_bytes(desc[8..12].try_into().unwrap_or([0; 4]));
                let pid = i32::from_le_bytes(desc[12..16].try_into().unwrap_or([0; 4]));
                let filename = if desc.len() > 16 {
                    let nb = &desc[16..desc.len().min(32)];
                    let nul = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
                    String::from_utf8_lossy(&nb[..nul]).into_owned()
                } else {
                    String::new()
                };
                *prpsinfo = Some(PrPsInfo {
                    pid,
                    ppid: parent_pid,
                    filename,
                    args: String::new(),
                });
            }
            offset = desc_end;
            offset = (offset + 3) & !3;
        }
    }
}

impl MemoryImage for ElfCoredumpImage {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError> {
        for (vaddr, data) in &self.segments {
            let end = *vaddr + data.len() as u64;
            if addr >= *vaddr && addr < end {
                let off = usize::try_from(addr - vaddr).unwrap_or(usize::MAX);
                if off + len > data.len() {
                    return Err(ForensicsError::ReadError {
                        addr,
                        msg: "read crosses segment boundary".into(),
                    });
                }
                return Ok(data[off..off + len].to_vec());
            }
        }
        Err(ForensicsError::ReadError {
            addr,
            msg: "address not mapped".into(),
        })
    }
    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions.clone()
    }
    fn arch(&self) -> ArchBits {
        self.arch
    }
    fn os_type(&self) -> OsType {
        OsType::Linux
    }
}

// ─── Windows Minidump ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniModule {
    pub base: u64,
    pub size: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiniThread {
    pub thread_id: u32,
    pub stack_start: u64,
    pub stack_size: u32,
}

pub struct MinidumpImage {
    memory_blocks: Vec<(u64, Vec<u8>)>,
    regions: Vec<MemoryRegion>,
    pub modules: Vec<MiniModule>,
    pub threads: Vec<MiniThread>,
    arch: ArchBits,
}

impl MinidumpImage {
    const MINIDUMP_SIGNATURE: u32 = 0x504d_444d;

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ForensicsError> {
        if data.len() < 32 {
            return Err(ForensicsError::ParseError("Minidump too short".into()));
        }
        let sig = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if sig != Self::MINIDUMP_SIGNATURE {
            return Err(ForensicsError::ParseError(format!(
                "Not a minidump: 0x{sig:08x}"
            )));
        }
        let num_streams = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4])) as usize;
        let stream_dir_rva = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4])) as usize;
        let mut memory_blocks: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut regions: Vec<MemoryRegion> = Vec::new();
        let mut modules: Vec<MiniModule> = Vec::new();
        let mut threads: Vec<MiniThread> = Vec::new();
        // Default to 64-bit; updated when we find the SystemInfoStream (type 7).
        let mut arch = ArchBits::Bits64;
        for i in 0..num_streams {
            let entry_off = stream_dir_rva.saturating_add(i.saturating_mul(12));
            if entry_off + 12 > data.len() {
                break;
            }
            let stream_type =
                u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap_or([0; 4]));
            let data_size = u32::from_le_bytes(
                data[entry_off + 4..entry_off + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let rva = u32::from_le_bytes(
                data[entry_off + 8..entry_off + 12]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            if rva.saturating_add(data_size) > data.len() {
                continue;
            }
            let sd = &data[rva..rva + data_size];
            match stream_type {
                5 => Self::parse_memory_list(sd, data, &mut memory_blocks, &mut regions),
                9 => Self::parse_memory64_list(sd, data, &mut memory_blocks, &mut regions),
                4 => Self::parse_module_list(sd, data, &mut modules),
                3 => Self::parse_thread_list(sd, &mut threads),
                // SystemInfoStream: first 2 bytes are ProcessorArchitecture
                // PROCESSOR_ARCHITECTURE_INTEL (0) and PROCESSOR_ARCHITECTURE_ARM (5) => 32-bit
                // PROCESSOR_ARCHITECTURE_AMD64 (9) and PROCESSOR_ARCHITECTURE_ARM64 (12) => 64-bit
                7
                    if sd.len() >= 2 => {
                        let proc_arch =
                            u16::from_le_bytes(sd[0..2].try_into().unwrap_or([0; 2]));
                        arch = match proc_arch {
                            9 | 12 => ArchBits::Bits64,
                            _ => ArchBits::Bits32,
                        };
                    }
                _ => {}
            }
        }
        Ok(Self {
            memory_blocks,
            regions,
            modules,
            threads,
            arch,
        })
    }

    fn parse_memory_list(
        stream: &[u8],
        full: &[u8],
        blocks: &mut Vec<(u64, Vec<u8>)>,
        regions: &mut Vec<MemoryRegion>,
    ) {
        if stream.len() < 4 {
            return;
        }
        let count = u32::from_le_bytes(stream[0..4].try_into().unwrap_or([0; 4])) as usize;
        for i in 0..count {
            let off = 4 + i * 16;
            if off + 16 > stream.len() {
                break;
            }
            let start = u64::from_le_bytes(stream[off..off + 8].try_into().unwrap_or([0; 8]));
            let sz =
                u32::from_le_bytes(stream[off + 8..off + 12].try_into().unwrap_or([0; 4])) as usize;
            let rva = u32::from_le_bytes(stream[off + 12..off + 16].try_into().unwrap_or([0; 4]))
                as usize;
            let end_rva = rva.saturating_add(sz);
            if end_rva <= full.len() && sz > 0 {
                blocks.push((start, full[rva..end_rva].to_vec()));
                regions.push(MemoryRegion {
                    start,
                    end: start + sz as u64,
                    perms: perms::READ,
                    name: None,
                });
            }
        }
    }

    fn parse_memory64_list(
        stream: &[u8],
        full: &[u8],
        blocks: &mut Vec<(u64, Vec<u8>)>,
        regions: &mut Vec<MemoryRegion>,
    ) {
        if stream.len() < 16 {
            return;
        }
        let count = usize::try_from(u64::from_le_bytes(stream[0..8].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
        let base_rva = usize::try_from(u64::from_le_bytes(stream[8..16].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
        let mut current_rva = base_rva;
        for i in 0..count {
            let off = 16 + i * 16;
            if off + 16 > stream.len() {
                break;
            }
            let start = u64::from_le_bytes(stream[off..off + 8].try_into().unwrap_or([0; 8]));
            let sz =
                usize::try_from(u64::from_le_bytes(stream[off + 8..off + 16].try_into().unwrap_or([0; 8]))).unwrap_or(usize::MAX);
            let end_rva = current_rva.saturating_add(sz);
            if end_rva <= full.len() && sz > 0 {
                blocks.push((start, full[current_rva..end_rva].to_vec()));
                regions.push(MemoryRegion {
                    start,
                    end: start + sz as u64,
                    perms: perms::READ,
                    name: None,
                });
            }
            current_rva += sz;
        }
    }

    fn parse_module_list(stream: &[u8], full: &[u8], modules: &mut Vec<MiniModule>) {
        if stream.len() < 4 {
            return;
        }
        let count = u32::from_le_bytes(stream[0..4].try_into().unwrap_or([0; 4])) as usize;
        for i in 0..count {
            let off = 4 + i * 108;
            if off + 108 > stream.len() {
                break;
            }
            let base = u64::from_le_bytes(stream[off..off + 8].try_into().unwrap_or([0; 8]));
            let size = u32::from_le_bytes(stream[off + 8..off + 12].try_into().unwrap_or([0; 4]));
            let name_rva =
                u32::from_le_bytes(stream[off + 104..off + 108].try_into().unwrap_or([0; 4]))
                    as usize;
            let name = Self::read_minidump_string(full, name_rva);
            modules.push(MiniModule { base, size, name });
        }
    }

    fn parse_thread_list(stream: &[u8], threads: &mut Vec<MiniThread>) {
        if stream.len() < 4 {
            return;
        }
        let count = u32::from_le_bytes(stream[0..4].try_into().unwrap_or([0; 4])) as usize;
        for i in 0..count {
            let off = 4 + i * 48;
            if off + 48 > stream.len() {
                break;
            }
            let tid = u32::from_le_bytes(stream[off..off + 4].try_into().unwrap_or([0; 4]));
            let stack_start =
                u64::from_le_bytes(stream[off + 16..off + 24].try_into().unwrap_or([0; 8]));
            let stack_size =
                u32::from_le_bytes(stream[off + 24..off + 28].try_into().unwrap_or([0; 4]));
            threads.push(MiniThread {
                thread_id: tid,
                stack_start,
                stack_size,
            });
        }
    }

    fn read_minidump_string(data: &[u8], rva: usize) -> String {
        if rva + 4 > data.len() {
            return String::new();
        }
        let len = u32::from_le_bytes(data[rva..rva + 4].try_into().unwrap_or([0; 4])) as usize;
        let str_start = rva + 4;
        let str_end = str_start + len;
        if str_end > data.len() {
            return String::new();
        }
        let utf16: Vec<u16> = data[str_start..str_end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    }
}

impl MemoryImage for MinidumpImage {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError> {
        for (vaddr, data) in &self.memory_blocks {
            let end = *vaddr + data.len() as u64;
            if addr >= *vaddr && addr < end {
                let off = usize::try_from(addr - vaddr).unwrap_or(usize::MAX);
                if off + len > data.len() {
                    return Err(ForensicsError::ReadError {
                        addr,
                        msg: "read crosses block boundary".into(),
                    });
                }
                return Ok(data[off..off + len].to_vec());
            }
        }
        Err(ForensicsError::ReadError {
            addr,
            msg: "address not in any memory block".into(),
        })
    }
    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions.clone()
    }
    fn arch(&self) -> ArchBits {
        self.arch
    }
    fn os_type(&self) -> OsType {
        OsType::Windows
    }
}

// ─── Plugin infrastructure ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginArgs {
    pub named: HashMap<String, String>,
}

impl PluginArgs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.named.insert(key.into(), value.into());
    }
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.named.get(key).map(String::as_str)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginOutput {
    pub rows: Vec<HashMap<String, String>>,
    pub raw: Option<String>,
}

impl PluginOutput {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_row(&mut self, row: HashMap<String, String>) {
        self.rows.push(row);
    }
    #[must_use]
    pub fn to_csv(&self) -> String {
        /// RFC-4180 CSV field escape.
        fn csv_field(s: &str) -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        }
        if self.rows.is_empty() {
            return String::new();
        }
        let mut keys: Vec<&str> = self.rows[0].keys().map(String::as_str).collect();
        keys.sort_unstable();
        // Escape header column names (plugin-defined, potentially attacker-influenced).
        let mut out = keys.iter().map(|k| csv_field(k)).collect::<Vec<_>>().join(",");
        out.push('\n');
        for row in &self.rows {
            let vals: Vec<String> = keys
                .iter()
                .map(|k| csv_field(row.get(*k).map_or("", String::as_str)))
                .collect();
            out.push_str(&vals.join(","));
            out.push('\n');
        }
        out
    }
}

pub trait ForensicsPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn run(
        &self,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError>;
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn ForensicsPlugin>>,
}

impl PluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, plugin: Box<dyn ForensicsPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn ForensicsPlugin> {
        self.plugins.get(name).map(std::convert::AsRef::as_ref)
    }
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.plugins.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn run(
        &self,
        name: &str,
        image: &dyn MemoryImage,
        args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let plugin = self
            .get(name)
            .ok_or_else(|| ForensicsError::NotSupported(format!("plugin '{name}' not found")))?;
        plugin.run(image, args)
    }
}

// ─── AcquisitionMode ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionMode {
    Physical,
    Logical,
    Volume,
    Memory,
    Network,
    Cloud,
}

impl AcquisitionMode {
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Physical => "Physical sector-by-sector copy",
            Self::Logical => "Logical file-level copy",
            Self::Volume => "Volume shadow copy",
            Self::Memory => "Live memory capture",
            Self::Network => "Network packet capture",
            Self::Cloud => "Cloud storage acquisition",
        }
    }
}

// ─── EvidenceHash ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
    #[must_use]
    pub const fn digest_len(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Simple pure-Rust hash implementations for forensic evidence verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceHash {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

impl EvidenceHash {
    /// Compute a hash for evidence verification.
    #[must_use]
    pub fn compute(data: &[u8], algorithm: HashAlgorithm) -> Self {
        let value = match &algorithm {
            HashAlgorithm::Md5 => compute_md5(data),
            HashAlgorithm::Sha1 => compute_sha1(data),
            HashAlgorithm::Sha256 => compute_sha256(data),
            HashAlgorithm::Sha512 => compute_sha512(data),
        };
        Self { algorithm, value }
    }

    /// Verify data matches the stored hash.
    ///
    /// The digest comparison is performed in constant time to prevent
    /// timing-based oracles that could reveal whether submitted data
    /// partially matches a stored (known-bad) hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn verify(&self, data: &[u8]) -> Result<(), ForensicsError> {
        let actual = Self::compute(data, self.algorithm.clone());
        // Constant-time comparison: accumulate XOR of every byte pair so that
        // the runtime does not depend on where the first differing byte is.
        let a = actual.value.as_bytes();
        let b = self.value.as_bytes();
        // If lengths differ the hashes cannot match; still run the loop over
        // the shorter length to avoid leaking which digest is shorter.
        let min_len = a.len().min(b.len());
        let mut diff: u8 = u8::from(a.len() != b.len());
        for i in 0..min_len {
            diff |= a[i] ^ b[i];
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(ForensicsError::HashMismatch {
                expected: self.value.clone(),
                actual: actual.value,
            })
        }
    }
}

#[must_use] 
pub fn compute_md5(data: &[u8]) -> String {
    // Structure-correct MD5 (RFC 1321) — real digest
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let k: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
        0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
        0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
        0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
        0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
        0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
        0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
        0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 16];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let (mut ha, mut hb, mut hc, mut hd) = (state[0], state[1], state[2], state[3]);
        for round in 0..64usize {
            let (fval, gidx) = match round {
                0..=15 => ((hb & hc) | (!hb & hd), round),
                16..=31 => ((hd & hb) | (!hd & hc), (5 * round + 1) % 16),
                32..=47 => (hb ^ hc ^ hd, (3 * round + 5) % 16),
                _ => (hc ^ (hb | !hd), (7 * round) % 16),
            };
            let temp = hd;
            hd = hc;
            hc = hb;
            hb = hb.wrapping_add(
                (ha.wrapping_add(fval).wrapping_add(k[round]).wrapping_add(w[gidx])).rotate_left(s[round]),
            );
            ha = temp;
        }
        state[0] = state[0].wrapping_add(ha);
        state[1] = state[1].wrapping_add(hb);
        state[2] = state[2].wrapping_add(hc);
        state[3] = state[3].wrapping_add(hd);
    }
    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        state[0].swap_bytes(),
        state[1].swap_bytes(),
        state[2].swap_bytes(),
        state[3].swap_bytes()
    )
}

#[must_use] 
pub fn compute_sha1(data: &[u8]) -> String {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut ha, mut hb, mut hc, mut hd, mut he) = (h[0], h[1], h[2], h[3], h[4]);
        for (round, &w_round) in w.iter().enumerate() {
            let (fval, kval) = match round {
                0..=19 => ((hb & hc) | (!hb & hd), 0x5A82_7999u32),
                20..=39 => (hb ^ hc ^ hd, 0x6ED9_EBA1u32),
                40..=59 => ((hb & hc) | (hb & hd) | (hc & hd), 0x8F1B_BCDCu32),
                _ => (hb ^ hc ^ hd, 0xCA62_C1D6u32),
            };
            let temp = ha
                .rotate_left(5)
                .wrapping_add(fval)
                .wrapping_add(he)
                .wrapping_add(kval)
                .wrapping_add(w_round);
            he = hd;
            hd = hc;
            hc = hb.rotate_left(30);
            hb = ha;
            ha = temp;
        }
        h[0] = h[0].wrapping_add(ha);
        h[1] = h[1].wrapping_add(hb);
        h[2] = h[2].wrapping_add(hc);
        h[3] = h[3].wrapping_add(hd);
        h[4] = h[4].wrapping_add(he);
    }
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4]
    )
}

#[must_use] 
pub fn compute_sha256(data: &[u8]) -> String {
    let k: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut ha, mut hb, mut hc, mut hd, mut he, mut hf, mut hg, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for round in 0..64usize {
            let sig1 = he.rotate_right(6) ^ he.rotate_right(11) ^ he.rotate_right(25);
            let ch = (he & hf) ^ (!he & hg);
            let temp1 = hh
                .wrapping_add(sig1)
                .wrapping_add(ch)
                .wrapping_add(k[round])
                .wrapping_add(w[round]);
            let sig0 = ha.rotate_right(2) ^ ha.rotate_right(13) ^ ha.rotate_right(22);
            let maj = (ha & hb) ^ (ha & hc) ^ (hb & hc);
            let temp2 = sig0.wrapping_add(maj);
            hh = hg;
            hg = hf;
            hf = he;
            he = hd.wrapping_add(temp1);
            hd = hc;
            hc = hb;
            hb = ha;
            ha = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(ha);
        h[1] = h[1].wrapping_add(hb);
        h[2] = h[2].wrapping_add(hc);
        h[3] = h[3].wrapping_add(hd);
        h[4] = h[4].wrapping_add(he);
        h[5] = h[5].wrapping_add(hf);
        h[6] = h[6].wrapping_add(hg);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().fold(String::with_capacity(h.len() * 8), |mut acc, x| {
        let _ = write!(acc, "{x:08x}");
        acc
    })
}

const SHA512_K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[must_use]
pub fn compute_sha512(data: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let _ = &SHA512_K;
    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().fold(String::with_capacity(digest.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ─── DigitalEvidence ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalEvidence {
    pub id: String,
    pub description: String,
    pub source: String,
    pub acquisition_mode: AcquisitionMode,
    pub hashes: Vec<EvidenceHash>,
    pub size_bytes: u64,
    pub acquisition_time: u64,
    pub chain_of_custody: Vec<CustodyEntry>,
    pub tags: Vec<String>,
}

impl DigitalEvidence {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        source: impl Into<String>,
        mode: AcquisitionMode,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            source: source.into(),
            acquisition_mode: mode,
            hashes: vec![],
            size_bytes: 0,
            acquisition_time: 0,
            chain_of_custody: vec![],
            tags: vec![],
        }
    }

    pub fn add_hash(&mut self, hash: EvidenceHash) {
        self.hashes.push(hash);
    }

    pub fn add_custody(
        &mut self,
        actor: impl Into<String>,
        action: impl Into<String>,
        note: Option<String>,
    ) {
        self.chain_of_custody.push(CustodyEntry {
            timestamp: 0,
            actor: actor.into(),
            action: action.into(),
            note,
        });
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn verify(&self, data: &[u8]) -> Result<(), ForensicsError> {
        for hash in &self.hashes {
            hash.verify(data)?;
        }
        Ok(())
    }
}

// ─── ForensicsTimeline ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineEventType {
    FileCreate,
    FileModify,
    FileDelete,
    FileAccess,
    FileRename,
    ProcessCreate,
    ProcessTerminate,
    NetworkConnect,
    NetworkDisconnect,
    RegistryCreate,
    RegistryModify,
    RegistryDelete,
    UserLogon,
    UserLogoff,
    ServiceStart,
    ServiceStop,
    ServiceInstall,
    ScheduledTaskCreate,
    ScheduledTaskRun,
    Custom(String),
}

impl TimelineEventType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::FileCreate => "file_create",
            Self::FileModify => "file_modify",
            Self::FileDelete => "file_delete",
            Self::FileAccess => "file_access",
            Self::FileRename => "file_rename",
            Self::ProcessCreate => "process_create",
            Self::ProcessTerminate => "process_terminate",
            Self::NetworkConnect => "network_connect",
            Self::NetworkDisconnect => "network_disconnect",
            Self::RegistryCreate => "registry_create",
            Self::RegistryModify => "registry_modify",
            Self::RegistryDelete => "registry_delete",
            Self::UserLogon => "user_logon",
            Self::UserLogoff => "user_logoff",
            Self::ServiceStart => "service_start",
            Self::ServiceStop => "service_stop",
            Self::ServiceInstall => "service_install",
            Self::ScheduledTaskCreate => "task_create",
            Self::ScheduledTaskRun => "task_run",
            Self::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: u64,
    pub source: String,
    pub event_type: TimelineEventType,
    pub description: String,
    pub artifacts: Vec<String>,
    pub actor: Option<String>,
    pub severity: u8,
}

impl TimelineEvent {
    #[must_use]
    pub fn new(
        timestamp: u64,
        source: impl Into<String>,
        event_type: TimelineEventType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            source: source.into(),
            event_type,
            description: description.into(),
            artifacts: vec![],
            actor: None,
            severity: 0,
        }
    }
    #[must_use]
    pub fn with_artifact(mut self, artifact: impl Into<String>) -> Self {
        self.artifacts.push(artifact.into());
        self
    }
    #[must_use]
    pub const fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity;
        self
    }
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }
}

#[derive(Debug, Default)]
pub struct ForensicsTimeline {
    events: Vec<TimelineEvent>,
}

impl ForensicsTimeline {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }
    pub fn sort(&mut self) {
        self.events.sort_by_key(|e| e.timestamp);
    }

    #[must_use]
    pub fn events_in_range(&self, start: u64, end: u64) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    #[must_use]
    pub fn events_by_type(&self, et: &TimelineEventType) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| &e.event_type == et).collect()
    }

    #[must_use]
    pub fn events_by_source(&self, source: &str) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.source == source).collect()
    }

    #[must_use]
    pub fn all_events(&self) -> &[TimelineEvent] {
        &self.events
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[must_use]
    pub fn high_severity_events(&self, threshold: u8) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.severity >= threshold)
            .collect()
    }
}

// ─── TimelineAnalyzer ────────────────────────────────────────────────────────

pub struct TimelineAnalyzer;

impl TimelineAnalyzer {
    #[must_use]
    pub fn merge(timelines: Vec<ForensicsTimeline>) -> ForensicsTimeline {
        let mut merged = ForensicsTimeline::new();
        for tl in timelines {
            for ev in tl.events {
                merged.add_event(ev);
            }
        }
        merged.sort();
        merged
    }

    #[must_use]
    pub fn find_bursts(
        timeline: &ForensicsTimeline,
        window_ms: u64,
        min_count: usize,
    ) -> Vec<Vec<&TimelineEvent>> {
        let events = timeline.all_events();
        let mut bursts = Vec::new();
        let mut i = 0;
        while i < events.len() {
            let mut group = vec![&events[i]];
            let mut j = i + 1;
            while j < events.len() && events[j].timestamp - events[i].timestamp <= window_ms {
                if events[j].source == events[i].source {
                    group.push(&events[j]);
                }
                j += 1;
            }
            if group.len() >= min_count {
                bursts.push(group);
            }
            i += 1;
        }
        bursts
    }

    #[must_use]
    pub fn correlate(timeline: &ForensicsTimeline, window_ms: u64) -> Vec<(usize, usize)> {
        let events = timeline.all_events();
        let mut pairs = Vec::new();
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                if events[j].timestamp.saturating_sub(events[i].timestamp) <= window_ms
                    && events[i].source != events[j].source
                {
                    pairs.push((i, j));
                }
            }
        }
        pairs
    }
}

// ─── ForensicsArtifact ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactType {
    File,
    RegistryKey,
    NetworkConnection,
    Process,
    Memory,
    Email,
    Browser,
    Prefetch,
    EventLog,
    ShellBag,
    JumpList,
    RecycleBin,
    LnkFile,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsArtifact {
    pub id: String,
    pub artifact_type: ArtifactType,
    pub source: String,
    pub description: String,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub hashes: Vec<EvidenceHash>,
    pub timestamp: Option<u64>,
    pub tags: Vec<String>,
}

impl ForensicsArtifact {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        artifact_type: ArtifactType,
        source: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            artifact_type,
            source: source.into(),
            description: description.into(),
            data: vec![],
            metadata: HashMap::new(),
            hashes: vec![],
            timestamp: None,
            tags: vec![],
        }
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        let sha256 = EvidenceHash::compute(&data, HashAlgorithm::Sha256);
        let md5 = EvidenceHash::compute(&data, HashAlgorithm::Md5);
        self.hashes = vec![md5, sha256];
        self.data = data;
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }
}

// ─── ArtifactExtractor trait ──────────────────────────────────────────────────

pub trait ArtifactExtractor: Send + Sync {
    fn name(&self) -> &str;
    fn extract(&self, data: &[u8]) -> Vec<ForensicsArtifact>;
}

// ─── MetadataExtractor ────────────────────────────────────────────────────────

pub struct MetadataExtractor;

impl ArtifactExtractor for MetadataExtractor {
    fn name(&self) -> &'static str {
        "metadata"
    }
    fn extract(&self, data: &[u8]) -> Vec<ForensicsArtifact> {
        let mut art = ForensicsArtifact::new(
            "metadata-0",
            ArtifactType::File,
            "MetadataExtractor",
            "File metadata",
        );
        art.set_metadata("size", data.len().to_string());
        art.set_metadata("sha256", compute_sha256(data));
        art.set_metadata("md5", compute_md5(data));
        let magic = if data.starts_with(b"\x7fELF") {
            "ELF"
        } else if data.starts_with(b"MZ") {
            "PE"
        } else if data.starts_with(b"\x89PNG") {
            "PNG"
        } else if data.starts_with(b"\xff\xd8\xff") {
            "JPEG"
        } else if data.starts_with(b"PK\x03\x04") {
            "ZIP"
        } else if data.starts_with(b"%PDF") {
            "PDF"
        } else {
            "unknown"
        };
        art.set_metadata("file_type", magic);
        vec![art]
    }
}

// ─── ContentExtractor ────────────────────────────────────────────────────────

pub struct ContentExtractor {
    pub min_len: usize,
}

impl ArtifactExtractor for ContentExtractor {
    fn name(&self) -> &'static str {
        "content"
    }
    fn extract(&self, data: &[u8]) -> Vec<ForensicsArtifact> {
        let mut strings = Vec::new();
        let mut buf = Vec::new();
        for &b in data {
            if b.is_ascii_graphic() || b == b' ' {
                buf.push(b);
            } else {
                if buf.len() >= self.min_len {
                    strings.push(String::from_utf8_lossy(&buf).into_owned());
                }
                buf.clear();
            }
        }
        if buf.len() >= self.min_len {
            strings.push(String::from_utf8_lossy(&buf).into_owned());
        }

        let mut art = ForensicsArtifact::new(
            "content-0",
            ArtifactType::Other("strings".into()),
            "ContentExtractor",
            "Extracted strings",
        );
        art.set_metadata("count", strings.len().to_string());
        art.set_data(strings.join("\n").into_bytes());
        vec![art]
    }
}

// ─── EmbeddedFileExtractor ───────────────────────────────────────────────────

pub struct EmbeddedFileExtractor;

impl ArtifactExtractor for EmbeddedFileExtractor {
    fn name(&self) -> &'static str {
        "embedded"
    }
    fn extract(&self, data: &[u8]) -> Vec<ForensicsArtifact> {
        let mut found = Vec::new();
        let signatures: &[(&[u8], &str)] = &[
            (b"\x7fELF", "ELF"),
            (b"MZ", "PE"),
            (b"PK\x03\x04", "ZIP"),
            (b"%PDF", "PDF"),
            (b"\x89PNG\r\n\x1a\n", "PNG"),
            (b"\xff\xd8\xff", "JPEG"),
        ];
        for (sig, kind) in signatures {
            let mut offset = 0;
            while offset + sig.len() <= data.len() {
                if &data[offset..offset + sig.len()] == *sig {
                    let end = (offset + 65536).min(data.len());
                    let mut art = ForensicsArtifact::new(
                        format!("embedded-{offset}"),
                        ArtifactType::File,
                        "EmbeddedFileExtractor",
                        format!("Embedded {kind} at offset {offset}"),
                    );
                    art.set_data(data[offset..end].to_vec());
                    art.set_metadata("offset", offset.to_string());
                    art.set_metadata("kind", kind.to_string());
                    found.push(art);
                    offset += sig.len();
                } else {
                    offset += 1;
                }
            }
        }
        found
    }
}

// ─── SignatureScanner ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub rule_name: String,
    pub offset: usize,
    pub matched_bytes: Vec<u8>,
    pub severity: u8,
}

pub struct SignatureScanner {
    rules: Vec<(String, Vec<u8>, u8)>,
}

impl SignatureScanner {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, name: impl Into<String>, pattern: Vec<u8>, severity: u8) {
        self.rules.push((name.into(), pattern, severity));
    }

    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();
        for (name, pattern, severity) in &self.rules {
            if pattern.is_empty() {
                continue;
            }
            let mut offset = 0;
            while offset + pattern.len() <= data.len() {
                if &data[offset..offset + pattern.len()] == pattern.as_slice() {
                    matches.push(SignatureMatch {
                        rule_name: name.clone(),
                        offset,
                        matched_bytes: pattern.clone(),
                        severity: *severity,
                    });
                    offset += pattern.len();
                } else {
                    offset += 1;
                }
            }
        }
        matches
    }

    #[must_use]
    pub fn default_rules() -> Self {
        let mut s = Self::new();
        s.add_rule("mz_header", b"MZ".to_vec(), 20);
        s.add_rule("elf_header", b"\x7fELF".to_vec(), 20);
        s.add_rule("nop_sled", vec![0x90; 8], 60);
        s.add_rule("shellcode_entry", vec![0xfc, 0xe8], 70);
        s.add_rule("int3_patch", vec![0xcc, 0xcc, 0xcc, 0xcc], 50);
        s.add_rule("mimikatz_str", b"sekurlsa".to_vec(), 90);
        s.add_rule("metasploit_str", b"metsrv".to_vec(), 85);
        s.add_rule("cobalt_strike", b"beacon.x64".to_vec(), 90);
        s
    }
}

impl Default for SignatureScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ForensicsReport ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsReportFinding {
    pub title: String,
    pub description: String,
    pub severity: u8,
    pub artifacts: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ForensicsReport {
    pub title: String,
    pub case_id: String,
    pub analyst: String,
    pub created_at: u64,
    pub findings: Vec<ForensicsReportFinding>,
    pub artifacts: Vec<ForensicsArtifact>,
    pub timeline: Vec<TimelineEvent>,
    pub recommendations: Vec<String>,
    pub summary: String,
}

impl ForensicsReport {
    #[must_use]
    pub fn new(title: impl Into<String>, case_id: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            case_id: case_id.into(),
            ..Default::default()
        }
    }

    pub fn add_finding(&mut self, finding: ForensicsReportFinding) {
        self.findings.push(finding);
    }
    pub fn add_artifact(&mut self, artifact: ForensicsArtifact) {
        self.artifacts.push(artifact);
    }
    pub fn add_timeline_event(&mut self, event: TimelineEvent) {
        self.timeline.push(event);
    }
    pub fn add_recommendation(&mut self, rec: impl Into<String>) {
        self.recommendations.push(rec.into());
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# {}\n\n**Case:** {}\n\n## Summary\n{}\n\n## Findings\n\n",
            self.title, self.case_id, self.summary
        );
        for f in &self.findings {
            let _ = write!(out, "### {} (severity: {})\n{}\n**Recommendation:** {}\n\n",
                f.title, f.severity, f.description, f.recommendation);
        }
        out.push_str("## Recommendations\n\n");
        for r in &self.recommendations {
            let _ = writeln!(out, "- {r}");
        }
        out
    }

    #[must_use]
    pub fn critical_findings(&self) -> Vec<&ForensicsReportFinding> {
        self.findings.iter().filter(|f| f.severity >= 80).collect()
    }
}

// ─── ForensicsDb ─────────────────────────────────────────────────────────────

/// In-memory forensics database with optional export (SQLite/MySQL abstracted).
pub struct ForensicsDb {
    cases: HashMap<String, ForensicsCase>,
    artifacts: Vec<ForensicsArtifact>,
    reports: Vec<ForensicsReport>,
    db_url: Option<String>,
}

impl ForensicsDb {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cases: HashMap::new(),
            artifacts: Vec::new(),
            reports: Vec::new(),
            db_url: None,
        }
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.db_url = Some(url.into());
        self
    }

    pub fn insert_case(&mut self, case: ForensicsCase) {
        self.cases.insert(case.id.clone(), case);
    }
    pub fn insert_artifact(&mut self, artifact: ForensicsArtifact) {
        self.artifacts.push(artifact);
    }
    pub fn insert_report(&mut self, report: ForensicsReport) {
        self.reports.push(report);
    }

    #[must_use]
    pub fn get_case(&self, id: &str) -> Option<&ForensicsCase> {
        self.cases.get(id)
    }
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
    #[must_use]
    pub const fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
    #[must_use]
    pub const fn report_count(&self) -> usize {
        self.reports.len()
    }
    #[must_use]
    pub fn db_url(&self) -> Option<&str> {
        self.db_url.as_deref()
    }

    #[must_use] 
    pub fn search_artifacts(&self, query: &str) -> Vec<&ForensicsArtifact> {
        self.artifacts
            .iter()
            .filter(|a| {
                a.description.contains(query) || a.source.contains(query) || a.id.contains(query)
            })
            .collect()
    }

    #[must_use] 
    pub fn export_json(&self) -> String {
        let mut obj = HashMap::new();
        obj.insert("case_count", self.cases.len().to_string());
        obj.insert("artifact_count", self.artifacts.len().to_string());
        obj.insert("report_count", self.reports.len().to_string());
        serde_json::to_string(&obj).unwrap_or_default()
    }
}

impl Default for ForensicsDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CaseManager ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsCase {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: u64,
    pub evidence: Vec<DigitalEvidence>,
    pub reports: Vec<String>,
    pub status: CaseStatus,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseStatus {
    Open,
    InProgress,
    Closed,
    Archived,
}

impl ForensicsCase {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            created_at: 0,
            evidence: vec![],
            reports: vec![],
            status: CaseStatus::Open,
            tags: vec![],
        }
    }
    pub fn add_evidence(&mut self, ev: DigitalEvidence) {
        self.evidence.push(ev);
    }
    pub fn add_report(&mut self, report_id: impl Into<String>) {
        self.reports.push(report_id.into());
    }
    pub const fn close(&mut self) {
        self.status = CaseStatus::Closed;
    }
}

#[derive(Default)]
pub struct CaseManager {
    cases: HashMap<String, ForensicsCase>,
}

impl CaseManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn create_case(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
    ) -> &mut ForensicsCase {
        let id_str: String = id.into();
        self.cases
            .entry(id_str.clone())
            .or_insert_with(|| ForensicsCase::new(id_str.clone(), name));
        self.cases.get_mut(&id_str).unwrap()
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn get_case(&self, id: &str) -> Result<&ForensicsCase, ForensicsError> {
        self.cases
            .get(id)
            .ok_or_else(|| ForensicsError::CaseNotFound(id.into()))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn get_case_mut(&mut self, id: &str) -> Result<&mut ForensicsCase, ForensicsError> {
        self.cases
            .get_mut(id)
            .ok_or_else(|| ForensicsError::CaseNotFound(id.into()))
    }

    #[must_use]
    pub fn list_cases(&self) -> Vec<&ForensicsCase> {
        let mut cases: Vec<&ForensicsCase> = self.cases.values().collect();
        cases.sort_by_key(|c| &c.id);
        cases
    }

    #[must_use]
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

// ─── HashDatabase ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct HashDatabase {
    known_good: std::collections::HashSet<String>,
    known_bad: std::collections::HashSet<String>,
}

impl HashDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_known_good(&mut self, hash: impl Into<String>) {
        self.known_good.insert(hash.into());
    }
    pub fn add_known_bad(&mut self, hash: impl Into<String>) {
        self.known_bad.insert(hash.into());
    }

    #[must_use]
    pub fn is_known_good(&self, hash: &str) -> bool {
        self.known_good.contains(hash)
    }
    #[must_use]
    pub fn is_known_bad(&self, hash: &str) -> bool {
        self.known_bad.contains(hash)
    }
    #[must_use]
    pub fn is_known(&self, hash: &str) -> bool {
        self.is_known_good(hash) || self.is_known_bad(hash)
    }

    pub fn load_nsrl_csv(&mut self, csv: &str) {
        for line in csv.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if let Some(hash) = parts.first() {
                self.add_known_good(hash.trim_matches('"'));
            }
        }
    }

    #[must_use]
    pub fn known_good_count(&self) -> usize {
        self.known_good.len()
    }
    #[must_use]
    pub fn known_bad_count(&self) -> usize {
        self.known_bad.len()
    }
}

// ─── KnownGoodFilter ─────────────────────────────────────────────────────────

pub struct KnownGoodFilter {
    db: HashDatabase,
}

impl KnownGoodFilter {
    #[must_use]
    pub const fn new(db: HashDatabase) -> Self {
        Self { db }
    }

    #[must_use]
    pub fn filter(&self, artifacts: Vec<ForensicsArtifact>) -> Vec<ForensicsArtifact> {
        artifacts
            .into_iter()
            .filter(|art| !art.hashes.iter().any(|h| self.db.is_known_good(&h.value)))
            .collect()
    }

    #[must_use]
    pub fn flag_known_bad<'a>(
        &self,
        artifacts: &'a [ForensicsArtifact],
    ) -> Vec<&'a ForensicsArtifact> {
        artifacts
            .iter()
            .filter(|art| art.hashes.iter().any(|h| self.db.is_known_bad(&h.value)))
            .collect()
    }
}

// ─── CarveResult ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveResult {
    pub file_type: String,
    pub offset: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub confidence: f32,
    pub hash: Option<EvidenceHash>,
}

impl CarveResult {
    #[must_use]
    pub fn new(file_type: impl Into<String>, offset: u64, data: Vec<u8>, confidence: f32) -> Self {
        let size = data.len() as u64;
        let hash = if data.is_empty() {
            None
        } else {
            Some(EvidenceHash::compute(&data, HashAlgorithm::Sha256))
        };
        Self {
            file_type: file_type.into(),
            offset,
            size,
            data,
            confidence,
            hash,
        }
    }
}

// ─── EvidenceLocker ──────────────────────────────────────────────────────────

pub struct EvidenceLocker {
    entries: HashMap<String, (Vec<u8>, Vec<EvidenceHash>)>,
}

impl EvidenceLocker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn store(&mut self, id: impl Into<String>, data: Vec<u8>) -> Vec<EvidenceHash> {
        let id_str = id.into();
        let hashes = vec![
            EvidenceHash::compute(&data, HashAlgorithm::Md5),
            EvidenceHash::compute(&data, HashAlgorithm::Sha256),
        ];
        self.entries.insert(id_str, (data, hashes.clone()));
        hashes
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn retrieve(&self, id: &str) -> Result<&[u8], ForensicsError> {
        self.entries
            .get(id)
            .map(|(d, _)| d.as_slice())
            .ok_or_else(|| ForensicsError::EvidenceLocked(format!("evidence '{id}' not found")))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn verify(&self, id: &str, data: &[u8]) -> Result<bool, ForensicsError> {
        let (stored, hashes) = self
            .entries
            .get(id)
            .ok_or_else(|| ForensicsError::EvidenceLocked(format!("'{id}' not found")))?;
        if stored.len() != data.len() {
            return Ok(false);
        }
        for h in hashes {
            h.verify(data)?;
        }
        Ok(true)
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for EvidenceLocker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ForensicsEngine ─────────────────────────────────────────────────────────

pub struct ForensicsEngine {
    pub case_manager: CaseManager,
    pub hash_db: HashDatabase,
    pub locker: EvidenceLocker,
    pub scanner: SignatureScanner,
    pub plugin_registry: PluginRegistry,
    pub db: ForensicsDb,
    extractors: Vec<Box<dyn ArtifactExtractor>>,
}

impl ForensicsEngine {
    #[must_use]
    pub fn new() -> Self {
        let mut plugin_registry = PluginRegistry::new();
        plugin_registry.register(Box::new(
            crate::sysinternals_bridge::SysinternalsSnapshotPlugin::<
                crate::sysinternals_bridge::InMemorySystemMonitor,
            >::default(),
        ));
        Self {
            case_manager: CaseManager::new(),
            hash_db: HashDatabase::new(),
            locker: EvidenceLocker::new(),
            scanner: SignatureScanner::default_rules(),
            plugin_registry,
            db: ForensicsDb::new(),
            extractors: Vec::new(),
        }
    }

    pub fn add_extractor(&mut self, extractor: Box<dyn ArtifactExtractor>) {
        self.extractors.push(extractor);
    }

    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> Vec<ForensicsArtifact> {
        let mut all = Vec::new();
        for extractor in &self.extractors {
            all.extend(extractor.extract(data));
        }
        all
    }

    #[must_use] 
    pub fn scan_signatures(&self, data: &[u8]) -> Vec<SignatureMatch> {
        self.scanner.scan(data)
    }

    pub fn store_evidence(&mut self, id: impl Into<String>, data: Vec<u8>) -> Vec<EvidenceHash> {
        self.locker.store(id, data)
    }

    pub fn create_case(&mut self, id: impl Into<String>, name: impl Into<String>) {
        let id_s = id.into();
        let name_s = name.into();
        let case = ForensicsCase::new(id_s, name_s);
        self.db.insert_case(case);
    }

    pub fn add_to_timeline(&self, timeline: &mut ForensicsTimeline, event: TimelineEvent) {
        timeline.add_event(event);
    }
}

impl Default for ForensicsEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ForensicsIocExtractor ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: f32,
    pub context: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Hash,
    Email,
    FileName,
    RegistryKey,
    MutexName,
    ServiceName,
    Other(String),
}

pub struct ForensicsIocExtractor;

impl ForensicsIocExtractor {
    #[must_use]
    pub fn extract_from_text(text: &str) -> Vec<ForensicsIoc> {
        let mut iocs = Vec::new();
        // Extract IP-like patterns
        for word in text.split_whitespace() {
            let mut parts_iter = word.split('.');
            let is_ipv4 = (&mut parts_iter).take(4).filter(|p| p.parse::<u8>().is_ok()).count() == 4
                && parts_iter.next().is_none();
            if is_ipv4 {
                iocs.push(ForensicsIoc {
                    ioc_type: IocType::Ip,
                    value: word.to_string(),
                    confidence: 0.9,
                    context: text[..text.len().min(50)].to_string(),
                });
            }
            if std::path::Path::new(word)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("bat"))
            {
                iocs.push(ForensicsIoc {
                    ioc_type: IocType::FileName,
                    value: word.to_string(),
                    confidence: 0.7,
                    context: String::new(),
                });
            }
            if word.starts_with("HKEY_") || word.starts_with("HKLM") || word.starts_with("HKCU") {
                iocs.push(ForensicsIoc {
                    ioc_type: IocType::RegistryKey,
                    value: word.to_string(),
                    confidence: 0.8,
                    context: String::new(),
                });
            }
        }
        iocs
    }
}

// ─── ForensicsExporter ────────────────────────────────────────────────────────

pub struct ForensicsExporter;

impl ForensicsExporter {
    #[must_use]
    pub fn export_report_html(report: &ForensicsReport) -> String {
        /// Escape special HTML characters to prevent XSS / HTML injection when
        /// analyst-supplied or evidence-derived strings are embedded in the report.
        fn html_escape(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;")
        }
        let mut html = format!(
            "<html><head><title>{}</title></head><body>",
            html_escape(&report.title)
        );
        let _ = write!(html, "<h1>{}</h1>", html_escape(&report.title));
        let _ = write!(html, "<p><strong>Case:</strong> {}</p>",
            html_escape(&report.case_id));
        let _ = write!(html, "<p><strong>Summary:</strong> {}</p>",
            html_escape(&report.summary));
        html.push_str("<h2>Findings</h2><ul>");
        for f in &report.findings {
            let _ = write!(html, "<li><strong>{}</strong> (severity {}): {}</li>",
                html_escape(&f.title),
                f.severity,
                html_escape(&f.description));
        }
        html.push_str("</ul></body></html>");
        html
    }

    #[must_use]
    pub fn export_timeline_csv(timeline: &ForensicsTimeline) -> String {
        /// RFC-4180 CSV escape: wrap in double-quotes and escape inner quotes.
        fn csv_field(s: &str) -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        }
        let mut out = "timestamp,source,event_type,description,severity\n".to_string();
        for ev in timeline.all_events() {
            let _ = writeln!(out, "{},{},{},{},{}",
                ev.timestamp,
                csv_field(&ev.source),
                csv_field(ev.event_type.as_str()),
                csv_field(&ev.description),
                ev.severity);
        }
        out
    }

    #[must_use]
    pub fn export_artifacts_json(artifacts: &[ForensicsArtifact]) -> String {
        let rows: Vec<HashMap<&str, String>> = artifacts
            .iter()
            .map(|a| {
                let mut m = HashMap::new();
                m.insert("id", a.id.clone());
                m.insert("source", a.source.clone());
                m.insert("description", a.description.clone());
                m
            })
            .collect();
        serde_json::to_string_pretty(&rows).unwrap_or_default()
    }
}

// ─── SectorReader ─────────────────────────────────────────────────────────────

pub struct SectorReader {
    pub sector_size: usize,
    data: Vec<u8>,
}

impl SectorReader {
    #[must_use]
    pub const fn new(data: Vec<u8>, sector_size: usize) -> Self {
        Self { sector_size, data }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_sector(&self, lba: u64) -> Result<&[u8], ForensicsError> {
        let lba_usize = usize::try_from(lba).map_err(|_| ForensicsError::ReadError {
            addr: lba,
            msg: "LBA exceeds usize range".into(),
        })?;
        let offset = lba_usize
            .checked_mul(self.sector_size)
            .ok_or_else(|| ForensicsError::ReadError {
                addr: lba,
                msg: "LBA * sector_size overflows".into(),
            })?;
        if offset + self.sector_size > self.data.len() {
            return Err(ForensicsError::ReadError {
                addr: lba,
                msg: format!("LBA {lba} out of range"),
            });
        }
        Ok(&self.data[offset..offset + self.sector_size])
    }

    #[must_use]
    pub const fn sector_count(&self) -> u64 {
        (self.data.len() / self.sector_size) as u64
    }
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.data.len()
    }
}

// ─── FileCarver ──────────────────────────────────────────────────────────────

/// Carver signature entry: (header, optional footer, label, max-size).
pub type FileCarverSignature = (Vec<u8>, Option<Vec<u8>>, String, usize);

pub struct FileCarver {
    signatures: Vec<FileCarverSignature>,
}

impl FileCarver {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn add_signature(
        &mut self,
        header: Vec<u8>,
        footer: Option<Vec<u8>>,
        name: impl Into<String>,
        max_size: usize,
    ) {
        self.signatures
            .push((header, footer, name.into(), max_size));
    }

    #[must_use]
    pub fn default_signatures() -> Self {
        let mut c = Self::new();
        c.add_signature(b"MZ".to_vec(), None, "PE", 10_000_000);
        c.add_signature(b"\x7fELF".to_vec(), None, "ELF", 10_000_000);
        c.add_signature(
            b"PK\x03\x04".to_vec(),
            Some(b"PK\x05\x06".to_vec()),
            "ZIP",
            100_000_000,
        );
        c.add_signature(
            b"%PDF-".to_vec(),
            Some(b"%%EOF".to_vec()),
            "PDF",
            50_000_000,
        );
        c.add_signature(
            b"\xff\xd8\xff".to_vec(),
            Some(b"\xff\xd9".to_vec()),
            "JPEG",
            20_000_000,
        );
        c.add_signature(
            b"\x89PNG\r\n\x1a\n".to_vec(),
            Some(b"IEND\xaeB`\x82".to_vec()),
            "PNG",
            20_000_000,
        );
        c
    }

    #[must_use]
    pub fn carve(&self, data: &[u8]) -> Vec<CarveResult> {
        let mut results = Vec::new();
        for (header, footer, name, max_size) in &self.signatures {
            let mut pos = 0;
            while pos + header.len() <= data.len() {
                if &data[pos..pos + header.len()] == header.as_slice() {
                    let end = footer.as_ref().map_or_else(
                        || (pos + *max_size).min(data.len()),
                        |ft| {
                            let search_end = (pos + max_size).min(data.len());
                            let mut found_end = None;
                            let mut fp = pos + header.len();
                            while fp + ft.len() <= search_end {
                                if &data[fp..fp + ft.len()] == ft.as_slice() {
                                    found_end = Some(fp + ft.len());
                                    break;
                                }
                                fp += 1;
                            }
                            found_end.unwrap_or_else(|| (pos + *max_size).min(data.len()))
                        },
                    );
                    let carved = data[pos..end].to_vec();
                    results.push(CarveResult::new(name.clone(), pos as u64, carved, 0.75));
                }
                pos += 1;
            }
        }
        results
    }
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MemoryImageFile ──────────────────────────────────────────────────────────

/// A memory image backed by a flat file on disk (raw physical memory dump,
/// e.g. `.raw`, `.bin`, `.mem`).
///
/// The file is read into memory in full on `open_raw`; for production use
/// on very large images a memory-mapped approach (via `memmap2`) would be
/// preferred, but this keeps the crate dependency-free.
pub struct MemoryImageFile {
    data: Vec<u8>,
    arch: ArchBits,
    os: OsType,
    /// Path retained for display / audit purposes.
    path: std::path::PathBuf,
}

impl MemoryImageFile {
    /// Open a raw flat physical memory dump from `path`.
    ///
    /// The file is treated as a contiguous flat address space starting at
    /// physical address 0.  The caller must supply `arch` and `os` hints
    /// because raw dumps have no header.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn open_raw(path: &Path) -> Result<Self, ForensicsError> {
        let data = std::fs::read(path)?;
        Ok(Self {
            data,
            arch: ArchBits::Bits64,
            os: OsType::Windows,
            path: path.to_path_buf(),
        })
    }

    /// Open with explicit architecture and OS hints.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn open_raw_with_hints(
        path: &Path,
        arch: ArchBits,
        os: OsType,
    ) -> Result<Self, ForensicsError> {
        let data = std::fs::read(path)?;
        Ok(Self {
            data,
            arch,
            os,
            path: path.to_path_buf(),
        })
    }

    /// Total size of the image in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Path to the backing file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a raw byte slice from a physical offset (not virtual address).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_physical(&self, offset: u64, len: usize) -> Result<&[u8], ForensicsError> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = start
            .checked_add(len)
            .ok_or_else(|| ForensicsError::ReadError {
                addr: offset,
                msg: "length overflow".into(),
            })?;
        if end > self.data.len() {
            return Err(ForensicsError::ReadError {
                addr: offset,
                msg: format!(
                    "out of bounds: offset {offset:#x} + {len} > {:#x}",
                    self.data.len()
                ),
            });
        }
        Ok(&self.data[start..end])
    }

    /// Compute a SHA-256 hash of the entire image for integrity verification.
    #[must_use]
    pub fn integrity_hash(&self) -> EvidenceHash {
        EvidenceHash::compute(&self.data, HashAlgorithm::Sha256)
    }
}

impl MemoryImage for MemoryImageFile {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ForensicsError> {
        Ok(self.read_physical(addr, len)?.to_vec())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        vec![MemoryRegion {
            start: 0,
            end: self.data.len() as u64,
            perms: perms::READ,
            name: Some(
                self.path
                    .file_name().map_or_else(|| "raw_dump".into(), |n| n.to_string_lossy().into_owned()),
            ),
        }]
    }

    fn arch(&self) -> ArchBits {
        self.arch
    }
    fn os_type(&self) -> OsType {
        self.os
    }
}

// ─── ScanResult ───────────────────────────────────────────────────────────────

/// Utility for linear byte-pattern and string scans over a `MemoryImage`.
pub struct ScanResult;

impl ScanResult {
    /// Scan the entire image linearly for occurrences of `magic` and return
    /// all offsets (relative to each region's start) where it is found.
    ///
    /// Regions larger than 256 MiB are skipped to avoid excessive memory
    /// consumption.
    #[must_use]
    pub fn scan_for_magic(image: &dyn MemoryImage, magic: &[u8]) -> Vec<u64> {
        if magic.is_empty() {
            return Vec::new();
        }
        let mut offsets = Vec::new();
        for region in image.regions() {
            let size = usize::try_from(region.end.saturating_sub(region.start)).unwrap_or(usize::MAX);
            if size == 0 || size > 256 * 1024 * 1024 {
                continue;
            }
            let Ok(data) = image.read(region.start, size) else {
                continue;
            };
            let mut pos = 0usize;
            while pos + magic.len() <= data.len() {
                if data[pos..pos + magic.len()] == *magic {
                    offsets.push(region.start + pos as u64);
                    pos += magic.len(); // skip past this match to avoid overlapping
                } else {
                    pos += 1;
                }
            }
        }
        offsets
    }

    /// Scan for occurrences of the UTF-8 string `s` and return all offsets.
    ///
    /// The search is byte-exact (no Unicode normalization).
    #[must_use]
    pub fn scan_for_string(image: &dyn MemoryImage, s: &str) -> Vec<u64> {
        Self::scan_for_magic(image, s.as_bytes())
    }

    /// Count total occurrences of `magic` across all regions.
    #[must_use]
    pub fn count_magic(image: &dyn MemoryImage, magic: &[u8]) -> usize {
        Self::scan_for_magic(image, magic).len()
    }

    /// Return the first offset where `magic` is found, or `None`.
    #[must_use]
    pub fn find_first_magic(image: &dyn MemoryImage, magic: &[u8]) -> Option<u64> {
        Self::scan_for_magic(image, magic).into_iter().next()
    }

    /// Scan for a magic bytes at a known address range `[start, end)`.
    #[must_use]
    pub fn scan_range_for_magic(
        image: &dyn MemoryImage,
        start: u64,
        end: u64,
        magic: &[u8],
    ) -> Vec<u64> {
        if magic.is_empty() || end <= start {
            return Vec::new();
        }
        let size = usize::try_from(end - start).unwrap_or(usize::MAX);
        if size > 256 * 1024 * 1024 {
            return Vec::new();
        }
        let Ok(data) = image.read(start, size) else {
            return Vec::new();
        };
        let mut offsets = Vec::new();
        let mut pos = 0usize;
        while pos + magic.len() <= data.len() {
            if data[pos..pos + magic.len()] == *magic {
                offsets.push(start + pos as u64);
                pos += magic.len();
            } else {
                pos += 1;
            }
        }
        offsets
    }
}

// ─── KernelStructureOffsets ───────────────────────────────────────────────────

/// Well-known field offsets for kernel structures, parameterised by OS version.
///
/// All offset values are in bytes from the start of the parent structure.
/// These are the most commonly used offsets for memory forensics automation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStructureOffsets {
    // ── Windows EPROCESS ──────────────────────────────────────────────────────
    /// EPROCESS.UniqueProcessId offset.
    pub eprocess_unique_process_id: u64,
    /// EPROCESS.ActiveProcessLinks (`LIST_ENTRY.Flink`) offset.
    pub eprocess_active_process_links: u64,
    /// EPROCESS.ImageFileName (15-byte char array) offset.
    pub eprocess_image_file_name: u64,
    /// EPROCESS.Peb (pointer to PEB) offset.
    pub eprocess_peb: u64,
    /// EPROCESS.InheritedFromUniqueProcessId offset.
    pub eprocess_parent_pid: u64,
    /// EPROCESS.CreateTime (`LARGE_INTEGER`) offset.
    pub eprocess_create_time: u64,
    /// EPROCESS.VadRoot offset (pointer to VAD tree root).
    pub eprocess_vad_root: u64,
    /// EPROCESS.ObjectTable offset (handle table).
    pub eprocess_object_table: u64,
    /// EPROCESS.Token (`EX_FAST_REF`) offset.
    pub eprocess_token: u64,

    // ── Windows PEB ───────────────────────────────────────────────────────────
    /// PEB.Ldr offset (pointer to `PEB_LDR_DATA`).
    pub peb_ldr: u64,
    /// PEB.ProcessParameters offset (pointer to `RTL_USER_PROCESS_PARAMETERS`).
    pub peb_process_parameters: u64,

    // ── Linux task_struct ─────────────────────────────────────────────────────
    /// `task_struct.pid` offset.
    pub task_pid: u64,
    /// `task_struct.tgid` (thread group ID / process ID) offset.
    pub task_tgid: u64,
    /// `task_struct.comm` (16-byte name) offset.
    pub task_comm: u64,
    /// `task_struct.tasks.next` (`list_head.next`) offset.
    pub task_tasks_next: u64,
    /// `task_struct.mm` offset (pointer to `mm_struct`, NULL for kernel threads).
    pub task_mm: u64,
    /// `task_struct.real_parent` offset (pointer to parent `task_struct`).
    pub task_real_parent: u64,
    /// `task_struct.cred` offset (pointer to struct cred).
    pub task_cred: u64,

    // ── Linux mm_struct ───────────────────────────────────────────────────────
    /// `mm_struct.pgd` offset (pointer to page global directory).
    pub mm_pgd: u64,
    /// `mm_struct.start_code` offset.
    pub mm_start_code: u64,
    /// `mm_struct.end_code` offset.
    pub mm_end_code: u64,
    /// `mm_struct.start_stack` offset.
    pub mm_start_stack: u64,

    // ── Human-readable label ──────────────────────────────────────────────────
    /// Description of this offset table (e.g. "Windows 10 x64 20H2").
    pub label: String,
}

impl KernelStructureOffsets {
    /// Offsets for Windows 10 x64 (builds 18362 – 19045, i.e. 1903–22H2).
    ///
    /// Sources: Volatility3 symbol tables, `WinDbg` `dt nt!_EPROCESS`, public
    /// Microsoft symbol information.
    #[must_use]
    pub fn windows_10_x64() -> Self {
        Self {
            // EPROCESS
            eprocess_unique_process_id: 0x0440,
            eprocess_active_process_links: 0x0448,
            eprocess_image_file_name: 0x05A0,
            eprocess_peb: 0x0550,
            eprocess_parent_pid: 0x0498,
            eprocess_create_time: 0x0478,
            eprocess_vad_root: 0x07D8,
            eprocess_object_table: 0x0570,
            eprocess_token: 0x04B8,
            // PEB
            peb_ldr: 0x0018,
            peb_process_parameters: 0x0020,
            // Linux (not applicable — zeroed)
            task_pid: 0,
            task_tgid: 0,
            task_comm: 0,
            task_tasks_next: 0,
            task_mm: 0,
            task_real_parent: 0,
            task_cred: 0,
            mm_pgd: 0,
            mm_start_code: 0,
            mm_end_code: 0,
            mm_start_stack: 0,
            label: "Windows 10 x64 (19041–19045)".into(),
        }
    }

    /// Offsets for Windows 11 x64 (builds 22000+).
    ///
    /// Several EPROCESS fields shifted relative to Windows 10.
    #[must_use]
    pub fn windows_11_x64() -> Self {
        Self {
            eprocess_unique_process_id: 0x0440,
            eprocess_active_process_links: 0x0448,
            eprocess_image_file_name: 0x05A8,
            eprocess_peb: 0x0558,
            eprocess_parent_pid: 0x04A0,
            eprocess_create_time: 0x0480,
            eprocess_vad_root: 0x07E0,
            eprocess_object_table: 0x0578,
            eprocess_token: 0x04C0,
            peb_ldr: 0x0018,
            peb_process_parameters: 0x0020,
            task_pid: 0,
            task_tgid: 0,
            task_comm: 0,
            task_tasks_next: 0,
            task_mm: 0,
            task_real_parent: 0,
            task_cred: 0,
            mm_pgd: 0,
            mm_start_code: 0,
            mm_end_code: 0,
            mm_start_stack: 0,
            label: "Windows 11 x64 (22000+)".into(),
        }
    }

    /// Offsets for Linux kernel 5.x `x86_64` (approximately 5.4 – 5.19).
    ///
    /// Sources: kernel source `include/linux/sched.h`, `include/linux/mm_types.h`,
    /// Volatility3 ISF profiles.
    #[must_use]
    pub fn linux_5x() -> Self {
        Self {
            // EPROCESS (not applicable — zeroed)
            eprocess_unique_process_id: 0,
            eprocess_active_process_links: 0,
            eprocess_image_file_name: 0,
            eprocess_peb: 0,
            eprocess_parent_pid: 0,
            eprocess_create_time: 0,
            eprocess_vad_root: 0,
            eprocess_object_table: 0,
            eprocess_token: 0,
            peb_ldr: 0,
            peb_process_parameters: 0,
            // task_struct
            task_pid: 0x03C8,
            task_tgid: 0x03CC,
            task_comm: 0x0640,
            task_tasks_next: 0x0348,
            task_mm: 0x0300,
            task_real_parent: 0x02E8,
            task_cred: 0x07B0,
            // mm_struct
            mm_pgd: 0x0050,
            mm_start_code: 0x00E0,
            mm_end_code: 0x00E8,
            mm_start_stack: 0x00F8,
            label: "Linux 5.x x86_64".into(),
        }
    }

    /// Offsets for Linux kernel 6.x `x86_64` (approximately 6.0 – 6.6).
    ///
    /// The `task_struct` layout saw notable changes in 6.0 (removal of several
    /// fields, reorganisation of the credential area).
    #[must_use]
    pub fn linux_6x() -> Self {
        Self {
            eprocess_unique_process_id: 0,
            eprocess_active_process_links: 0,
            eprocess_image_file_name: 0,
            eprocess_peb: 0,
            eprocess_parent_pid: 0,
            eprocess_create_time: 0,
            eprocess_vad_root: 0,
            eprocess_object_table: 0,
            eprocess_token: 0,
            peb_ldr: 0,
            peb_process_parameters: 0,
            task_pid: 0x03D0,
            task_tgid: 0x03D4,
            task_comm: 0x0670,
            task_tasks_next: 0x0358,
            task_mm: 0x0310,
            task_real_parent: 0x02F8,
            task_cred: 0x07C8,
            mm_pgd: 0x0050,
            mm_start_code: 0x00E8,
            mm_end_code: 0x00F0,
            mm_start_stack: 0x0100,
            label: "Linux 6.x x86_64".into(),
        }
    }

    /// Attempt to resolve a field offset by name string.
    ///
    /// Returns `None` if the field name is not recognised.
    #[must_use]
    pub fn field_offset(&self, field: &str) -> Option<u64> {
        match field {
            "eprocess_unique_process_id" => Some(self.eprocess_unique_process_id),
            "eprocess_active_process_links" => Some(self.eprocess_active_process_links),
            "eprocess_image_file_name" => Some(self.eprocess_image_file_name),
            "eprocess_peb" => Some(self.eprocess_peb),
            "eprocess_parent_pid" => Some(self.eprocess_parent_pid),
            "eprocess_create_time" => Some(self.eprocess_create_time),
            "eprocess_vad_root" => Some(self.eprocess_vad_root),
            "eprocess_object_table" => Some(self.eprocess_object_table),
            "eprocess_token" => Some(self.eprocess_token),
            "peb_ldr" => Some(self.peb_ldr),
            "peb_process_parameters" => Some(self.peb_process_parameters),
            "task_pid" => Some(self.task_pid),
            "task_tgid" => Some(self.task_tgid),
            "task_comm" => Some(self.task_comm),
            "task_tasks_next" => Some(self.task_tasks_next),
            "task_mm" => Some(self.task_mm),
            "task_real_parent" => Some(self.task_real_parent),
            "task_cred" => Some(self.task_cred),
            "mm_pgd" => Some(self.mm_pgd),
            "mm_start_code" => Some(self.mm_start_code),
            "mm_end_code" => Some(self.mm_end_code),
            "mm_start_stack" => Some(self.mm_start_stack),
            _ => None,
        }
    }

    /// Read a pointer-sized value from `base + field_offset(field)` in the image.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_field(
        &self,
        image: &dyn MemoryImage,
        base: u64,
        field: &str,
    ) -> Result<u64, ForensicsError> {
        let off = self
            .field_offset(field)
            .ok_or_else(|| ForensicsError::ParseError(format!("unknown field: {field}")))?;
        image.read_ptr(base + off)
    }

    /// Read a fixed-length byte slice for a string field (e.g. `comm`, `ImageFileName`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn read_string_field(
        &self,
        image: &dyn MemoryImage,
        base: u64,
        field: &str,
        max_len: usize,
    ) -> Result<String, ForensicsError> {
        let off = self
            .field_offset(field)
            .ok_or_else(|| ForensicsError::ParseError(format!("unknown field: {field}")))?;
        let bytes = image.read(base + off, max_len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Return whether this offset table is for a Windows kernel.
    #[must_use]
    pub const fn is_windows(&self) -> bool {
        self.eprocess_unique_process_id != 0
    }

    /// Return whether this offset table is for a Linux kernel.
    #[must_use]
    pub const fn is_linux(&self) -> bool {
        self.task_pid != 0
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(size: usize) -> RawMemoryImage {
        let mut data = vec![0u8; size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(u8::MAX);
        }
        RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Linux)
    }

    #[test]
    fn arch_bits_pointer_size() {
        assert_eq!(ArchBits::Bits32.pointer_size(), 4);
        assert_eq!(ArchBits::Bits64.pointer_size(), 8);
    }

    #[test]
    fn memory_region_size() {
        let r = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            perms: perms::READ,
            name: None,
        };
        assert_eq!(r.size(), 0x1000);
    }

    #[test]
    fn memory_region_contains() {
        let r = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            perms: perms::READ,
            name: None,
        };
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1fff));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn memory_region_perms() {
        let r = MemoryRegion {
            start: 0,
            end: 0x1000,
            perms: perms::RWX,
            name: None,
        };
        assert!(r.is_exec());
        assert!(r.is_writable());
        assert!(r.is_readable());
    }

    #[test]
    fn memory_region_no_exec() {
        let r = MemoryRegion {
            start: 0,
            end: 0x1000,
            perms: perms::READ | perms::WRITE,
            name: None,
        };
        assert!(!r.is_exec());
    }

    #[test]
    fn raw_image_read_success() {
        let img = make_raw(256);
        let bytes = img.read(0, 4).unwrap();
        assert_eq!(bytes, vec![0, 1, 2, 3]);
    }

    #[test]
    fn raw_image_read_oob_fails() {
        let img = make_raw(64);
        assert!(img.read(60, 10).is_err());
    }

    #[test]
    fn raw_image_read_below_base_fails() {
        let img = RawMemoryImage::from_bytes_with_base(
            vec![0u8; 64],
            ArchBits::Bits64,
            OsType::Windows,
            0x1000,
        );
        assert!(img.read(0x0fff, 1).is_err());
    }

    #[test]
    fn raw_image_regions() {
        let img = make_raw(128);
        let regions = img.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].end - regions[0].start, 128);
    }

    #[test]
    fn raw_image_read_u32_le() {
        let data = vec![0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0];
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits32, OsType::Windows);
        assert_eq!(img.read_u32_le(0).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn raw_image_read_u64_le() {
        let data = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Linux);
        assert_eq!(img.read_u64_le(0).unwrap(), 1u64);
    }

    #[test]
    fn plugin_args_set_get() {
        let mut args = PluginArgs::new();
        args.set("pid", "4");
        assert_eq!(args.get("pid"), Some("4"));
        assert_eq!(args.get("missing"), None);
    }

    #[test]
    fn plugin_output_add_row() {
        let mut out = PluginOutput::new();
        let mut row = HashMap::new();
        row.insert("pid".into(), "4".into());
        out.add_row(row);
        assert_eq!(out.rows.len(), 1);
    }

    #[test]
    fn plugin_output_to_csv() {
        let mut out = PluginOutput::new();
        let mut row = HashMap::new();
        row.insert("a".into(), "1".into());
        row.insert("b".into(), "2".into());
        out.add_row(row);
        let csv = out.to_csv();
        assert!(csv.contains("a,b") || csv.contains("b,a"));
    }

    struct DummyPlugin;
    impl ForensicsPlugin for DummyPlugin {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn description(&self) -> &'static str {
            "A dummy test plugin"
        }
        fn run(
            &self,
            _image: &dyn MemoryImage,
            _args: &PluginArgs,
        ) -> Result<PluginOutput, ForensicsError> {
            let mut out = PluginOutput::new();
            let mut row = HashMap::new();
            row.insert("result".into(), "ok".into());
            out.add_row(row);
            Ok(out)
        }
    }

    #[test]
    fn registry_register_and_run() {
        let mut reg = PluginRegistry::new();
        reg.register(Box::new(DummyPlugin));
        let img = make_raw(64);
        let out = reg.run("dummy", &img, &PluginArgs::new()).unwrap();
        assert_eq!(out.rows[0]["result"], "ok");
    }

    #[test]
    fn minidump_bad_signature() {
        assert!(MinidumpImage::from_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn minidump_valid_header_no_streams() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0x504d_444d_u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&32u32.to_le_bytes());
        let img = MinidumpImage::from_bytes(&data).unwrap();
        assert_eq!(img.regions().len(), 0);
    }

    #[test]
    fn elf_bad_magic() {
        assert!(ElfCoredumpImage::from_bytes(&[0u8; 128]).is_err());
    }

    #[test]
    fn elf_64bit_no_segments() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        let img = ElfCoredumpImage::from_bytes(&data).unwrap();
        assert_eq!(img.regions().len(), 0);
    }

    #[test]
    fn elf_big_endian_unsupported() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 2;
        assert!(ElfCoredumpImage::from_bytes(&data).is_err());
    }

    #[test]
    fn evidence_hash_md5() {
        let h = EvidenceHash::compute(b"hello world", HashAlgorithm::Md5);
        assert_eq!(h.value, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn evidence_hash_sha256_empty() {
        let h = EvidenceHash::compute(b"", HashAlgorithm::Sha256);
        assert_eq!(
            h.value,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn evidence_hash_verify_ok() {
        let data = b"test data for forensics";
        let h = EvidenceHash::compute(data, HashAlgorithm::Sha256);
        assert!(h.verify(data).is_ok());
    }

    #[test]
    fn evidence_hash_verify_fail() {
        let h = EvidenceHash::compute(b"original", HashAlgorithm::Sha256);
        assert!(h.verify(b"tampered").is_err());
    }

    #[test]
    fn sha1_known_value() {
        let h = EvidenceHash::compute(b"", HashAlgorithm::Sha1);
        assert_eq!(h.value, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn digital_evidence_chain_of_custody() {
        let mut ev =
            DigitalEvidence::new("EV001", "Disk image", "/dev/sda", AcquisitionMode::Physical);
        ev.add_custody("Alice", "acquired", None);
        ev.add_custody("Bob", "transferred", Some("sealed bag".into()));
        assert_eq!(ev.chain_of_custody.len(), 2);
    }

    #[test]
    fn timeline_sort_and_query() {
        let mut tl = ForensicsTimeline::new();
        tl.add_event(TimelineEvent::new(
            2000,
            "fs",
            TimelineEventType::FileCreate,
            "late",
        ));
        tl.add_event(TimelineEvent::new(
            1000,
            "fs",
            TimelineEventType::FileDelete,
            "early",
        ));
        tl.sort();
        assert_eq!(tl.all_events()[0].timestamp, 1000);
    }

    #[test]
    fn timeline_events_in_range() {
        let mut tl = ForensicsTimeline::new();
        for i in 0..10u64 {
            tl.add_event(TimelineEvent::new(
                i * 1000,
                "src",
                TimelineEventType::FileCreate,
                "ev",
            ));
        }
        let range = tl.events_in_range(2000, 5000);
        assert_eq!(range.len(), 4);
    }

    #[test]
    fn timeline_analyzer_merge() {
        let mut t1 = ForensicsTimeline::new();
        t1.add_event(TimelineEvent::new(
            100,
            "a",
            TimelineEventType::FileCreate,
            "x",
        ));
        let mut t2 = ForensicsTimeline::new();
        t2.add_event(TimelineEvent::new(
            50,
            "b",
            TimelineEventType::ProcessCreate,
            "y",
        ));
        let merged = TimelineAnalyzer::merge(vec![t1, t2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged.all_events()[0].timestamp, 50);
    }

    #[test]
    fn signature_scanner_default_rules() {
        let scanner = SignatureScanner::default_rules();
        let data = b"MZ\x90\x00some pe header";
        let matches = scanner.scan(data);
        assert!(matches.iter().any(|m| m.rule_name == "mz_header"));
    }

    #[test]
    fn metadata_extractor_detects_pe() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        let extractor = MetadataExtractor;
        let arts = extractor.extract(&data);
        assert_eq!(arts[0].metadata.get("file_type"), Some(&"PE".to_string()));
    }

    #[test]
    fn content_extractor_finds_strings() {
        let data = b"hello world\x00this is a string\x00";
        let extractor = ContentExtractor { min_len: 4 };
        let arts = extractor.extract(data);
        assert!(!arts.is_empty());
    }

    #[test]
    fn embedded_file_extractor_finds_pe() {
        let mut data = vec![0u8; 200];
        data[50] = b'M';
        data[51] = b'Z';
        let extractor = EmbeddedFileExtractor;
        let arts = extractor.extract(&data);
        assert!(!arts.is_empty());
    }

    #[test]
    fn hash_database_known_good_bad() {
        let mut db = HashDatabase::new();
        db.add_known_good("aabbcc");
        db.add_known_bad("deadbeef");
        assert!(db.is_known_good("aabbcc"));
        assert!(db.is_known_bad("deadbeef"));
        assert!(db.is_known("aabbcc"));
    }

    #[test]
    fn evidence_locker_store_retrieve() {
        let mut locker = EvidenceLocker::new();
        let data = b"forensics evidence data".to_vec();
        let hashes = locker.store("ev001", data.clone());
        assert_eq!(hashes.len(), 2);
        let retrieved = locker.retrieve("ev001").unwrap();
        assert_eq!(retrieved, data.as_slice());
    }

    #[test]
    fn case_manager_create_and_get() {
        let mut mgr = CaseManager::new();
        mgr.create_case("C001", "Test Case");
        let case = mgr.get_case("C001").unwrap();
        assert_eq!(case.id, "C001");
    }

    #[test]
    fn case_manager_not_found() {
        let mgr = CaseManager::new();
        assert!(mgr.get_case("NONEXISTENT").is_err());
    }

    #[test]
    fn forensics_report_markdown() {
        let mut report = ForensicsReport::new("Test Report", "C001");
        report.summary = "All clear".into();
        report.add_finding(ForensicsReportFinding {
            title: "Finding 1".into(),
            description: "desc".into(),
            severity: 90,
            artifacts: vec![],
            recommendation: "fix it".into(),
        });
        let md = report.to_markdown();
        assert!(md.contains("# Test Report"));
        assert!(md.contains("Finding 1"));
    }

    #[test]
    fn forensics_engine_analyze() {
        let mut engine = ForensicsEngine::new();
        engine.add_extractor(Box::new(MetadataExtractor));
        let mut data = vec![0u8; 100];
        data[0] = b'M';
        data[1] = b'Z';
        let arts = engine.analyze(&data);
        assert!(!arts.is_empty());
    }

    #[test]
    fn carve_result_hash() {
        let data = b"carved file data".to_vec();
        let result = CarveResult::new("PE", 0x1000, data, 0.95);
        assert!(result.hash.is_some());
        assert!((result.confidence - 0.95_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn acquisition_mode_description() {
        assert!(!AcquisitionMode::Physical.description().is_empty());
        assert!(!AcquisitionMode::Cloud.description().is_empty());
    }

    #[test]
    fn timeline_high_severity() {
        let mut tl = ForensicsTimeline::new();
        tl.add_event(
            TimelineEvent::new(0, "src", TimelineEventType::FileCreate, "low").with_severity(30),
        );
        tl.add_event(
            TimelineEvent::new(1, "src", TimelineEventType::ProcessCreate, "high")
                .with_severity(90),
        );
        let high = tl.high_severity_events(80);
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn known_good_filter() {
        let mut db = HashDatabase::new();
        let data = b"known good file";
        let hash = compute_sha256(data);
        db.add_known_good(&hash);
        let filter = KnownGoodFilter::new(db);
        let mut art = ForensicsArtifact::new("a1", ArtifactType::File, "src", "desc");
        art.set_data(data.to_vec());
        let remaining = filter.filter(vec![art]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn forensics_error_display() {
        let e = ForensicsError::ReadError {
            addr: 0x1000,
            msg: "oob".into(),
        };
        let s = e.to_string();
        assert!(s.contains("0x0000000000001000"));
    }

    #[test]
    fn raw_image_from_bytes_with_base() {
        let img = RawMemoryImage::from_bytes_with_base(
            vec![0xAA; 16],
            ArchBits::Bits64,
            OsType::Windows,
            0x8000,
        );
        assert_eq!(img.base(), 0x8000);
        let bytes = img.read(0x8000, 4).unwrap();
        assert_eq!(bytes, vec![0xAA; 4]);
    }

    #[test]
    fn sector_reader_basic() {
        let data: Vec<u8> = (0..1024u16).map(|x| (x & 0xff) as u8).collect();
        let reader = SectorReader::new(data, 512);
        assert_eq!(reader.sector_count(), 2);
        let sector = reader.read_sector(0).unwrap();
        assert_eq!(sector.len(), 512);
        assert_eq!(sector[0], 0);
    }

    #[test]
    fn sector_reader_out_of_range() {
        let data = vec![0u8; 512];
        let reader = SectorReader::new(data, 512);
        assert!(reader.read_sector(2).is_err());
    }

    #[test]
    fn file_carver_default_signatures() {
        let carver = FileCarver::default_signatures();
        let mut data = vec![0u8; 1000];
        data[100] = b'M';
        data[101] = b'Z';
        let results = carver.carve(&data);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.file_type == "PE"));
    }

    #[test]
    fn forensics_db_operations() {
        let mut db = ForensicsDb::new();
        db.insert_case(ForensicsCase::new("C001", "Test"));
        let mut art = ForensicsArtifact::new("A001", ArtifactType::File, "src", "desc");
        art.set_data(b"test data".to_vec());
        db.insert_artifact(art);
        assert_eq!(db.case_count(), 1);
        assert_eq!(db.artifact_count(), 1);
    }

    #[test]
    fn ioc_extractor_finds_ips() {
        let text = "Connection to 192.168.1.1 port 443 and 8.8.8.8";
        let iocs = ForensicsIocExtractor::extract_from_text(text);
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Ip));
    }

    #[test]
    fn forensics_exporter_html() {
        let report = ForensicsReport::new("Test", "C001");
        let html = ForensicsExporter::export_report_html(&report);
        assert!(html.contains("<html>"));
        assert!(html.contains("Test"));
    }

    #[test]
    fn forensics_exporter_csv_timeline() {
        let mut tl = ForensicsTimeline::new();
        tl.add_event(TimelineEvent::new(
            1000,
            "fs",
            TimelineEventType::FileCreate,
            "desc",
        ));
        let csv = ForensicsExporter::export_timeline_csv(&tl);
        assert!(csv.contains("timestamp"));
        assert!(csv.contains("1000"));
    }

    #[test]
    fn hash_algorithm_names() {
        assert_eq!(HashAlgorithm::Md5.name(), "MD5");
        assert_eq!(HashAlgorithm::Sha512.name(), "SHA512");
    }

    #[test]
    fn hash_algorithm_digest_lens() {
        assert_eq!(HashAlgorithm::Md5.digest_len(), 16);
        assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(HashAlgorithm::Sha512.digest_len(), 64);
    }

    #[test]
    fn compute_sha512_matches_reference_vectors() {
        // Empty input — RFC 6234 test vector.
        assert_eq!(
            compute_sha512(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                .replace(char::is_whitespace, "")
        );
        // "abc" — RFC 6234 test vector.
        assert_eq!(
            compute_sha512(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(char::is_whitespace, "")
        );
        // 40 * 'a' — spans the padding boundary that historically was miscomputed;
        // cross-check the domain function against the sha2 crate directly.
        let forty_a = vec![b'a'; 40];
        use sha2::Digest;
        let expected: String =
            sha2::Sha512::digest(&forty_a)
                .iter()
                .fold(String::with_capacity(128), |mut acc, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{byte:02x}");
                    acc
                });
        assert_eq!(compute_sha512(&forty_a), expected);
        // The digest must not be the empty-input digest — regression guard for
        // the wire wrapper that historically hashed no bytes.
        assert_ne!(compute_sha512(&forty_a), compute_sha512(b""));
    }

    #[test]
    fn timeline_events_by_source() {
        let mut tl = ForensicsTimeline::new();
        tl.add_event(TimelineEvent::new(
            0,
            "fs",
            TimelineEventType::FileCreate,
            "a",
        ));
        tl.add_event(TimelineEvent::new(
            1,
            "net",
            TimelineEventType::NetworkConnect,
            "b",
        ));
        tl.add_event(TimelineEvent::new(
            2,
            "fs",
            TimelineEventType::FileDelete,
            "c",
        ));
        let fs = tl.events_by_source("fs");
        assert_eq!(fs.len(), 2);
    }

    #[test]
    fn forensics_report_json() {
        let report = ForensicsReport::new("Test", "C001");
        let json = report.to_json();
        assert!(json.contains("Test"));
    }

    #[test]
    fn case_manager_list_cases() {
        let mut mgr = CaseManager::new();
        mgr.create_case("C001", "Case 1");
        mgr.create_case("C002", "Case 2");
        assert!(mgr.case_count() >= 1);
    }

    #[test]
    fn artifact_extractor_metadata_size() {
        let data = vec![0xAA; 500];
        let extractor = MetadataExtractor;
        let arts = extractor.extract(&data);
        assert_eq!(arts[0].metadata["size"], "500");
    }

    // ── MemoryImageFile ────────────────────────────────────────────────────────
    #[test]
    fn memory_image_file_size() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_image_file_size.bin");
        let data = vec![0xABu8; 4096];
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }
        let img = MemoryImageFile::open_raw(&path).unwrap();
        assert_eq!(img.size(), 4096);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn memory_image_file_implements_memory_image() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_image_file_impl.bin");
        let data: Vec<u8> = (0u8..=255).collect();
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }
        let img = MemoryImageFile::open_raw(&path).unwrap();
        let bytes = img.read(0, 4).unwrap();
        assert_eq!(bytes, vec![0, 1, 2, 3]);
        let regions = img.regions();
        assert_eq!(regions.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn memory_image_file_oob_read_fails() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_image_file_oob.bin");
        let data = vec![0u8; 64];
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }
        let img = MemoryImageFile::open_raw(&path).unwrap();
        assert!(img.read(60, 10).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn memory_image_file_integrity_hash_is_sha256() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_image_file_hash.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello").unwrap();
        }
        let img = MemoryImageFile::open_raw(&path).unwrap();
        let h = img.integrity_hash();
        assert_eq!(h.algorithm, HashAlgorithm::Sha256);
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            h.value,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn memory_image_file_path_accessor() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_image_file_path.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&[0u8; 16]).unwrap();
        }
        let img = MemoryImageFile::open_raw(&path).unwrap();
        assert_eq!(img.path(), path.as_path());
        std::fs::remove_file(&path).ok();
    }

    // ── ScanResult ─────────────────────────────────────────────────────────────
    #[test]
    fn scan_result_finds_magic() {
        let data = b"\x00\x00MZ\x00\x00MZ\x00".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let offsets = ScanResult::scan_for_magic(&img, b"MZ");
        assert_eq!(offsets.len(), 2);
        assert!(offsets.contains(&2));
        assert!(offsets.contains(&6));
    }

    #[test]
    fn scan_result_finds_string() {
        let data = b"prefix hello world suffix hello".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Linux);
        let offsets = ScanResult::scan_for_string(&img, "hello");
        assert_eq!(offsets.len(), 2);
    }

    #[test]
    fn scan_result_empty_magic_returns_empty() {
        let img = RawMemoryImage::from_bytes(vec![0u8; 64], ArchBits::Bits64, OsType::Linux);
        let offsets = ScanResult::scan_for_magic(&img, b"");
        assert!(offsets.is_empty());
    }

    #[test]
    fn scan_result_no_match_returns_empty() {
        let img = RawMemoryImage::from_bytes(vec![0u8; 64], ArchBits::Bits64, OsType::Linux);
        let offsets = ScanResult::scan_for_magic(&img, b"NOTFOUND");
        assert!(offsets.is_empty());
    }

    #[test]
    fn scan_result_find_first_magic() {
        let data = b"\x00PE\x00\x00PE\x00".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let first = ScanResult::find_first_magic(&img, b"PE");
        assert_eq!(first, Some(1));
    }

    #[test]
    fn scan_result_count_magic() {
        let data = b"aabaabaabaab".to_vec();
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Linux);
        let count = ScanResult::count_magic(&img, b"aab");
        assert_eq!(count, 4);
    }

    #[test]
    fn scan_result_range_scan() {
        // Put the pattern only in the second half of the region.
        let mut data = vec![0u8; 128];
        data[64] = b'X';
        data[65] = b'Y';
        data[66] = b'Z';
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Linux);
        // Searching in first half should miss.
        let miss = ScanResult::scan_range_for_magic(&img, 0, 64, b"XYZ");
        assert!(miss.is_empty());
        // Searching in full range should hit.
        let hit = ScanResult::scan_range_for_magic(&img, 0, 128, b"XYZ");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0], 64);
    }

    // ── KernelStructureOffsets ─────────────────────────────────────────────────
    #[test]
    fn kernel_offsets_windows_10_x64_values() {
        let off = KernelStructureOffsets::windows_10_x64();
        assert_eq!(off.eprocess_unique_process_id, 0x0440);
        assert_eq!(off.eprocess_active_process_links, 0x0448);
        assert_eq!(off.eprocess_image_file_name, 0x05A0);
        assert_eq!(off.eprocess_peb, 0x0550);
        assert!(off.is_windows());
        assert!(!off.is_linux());
    }

    #[test]
    fn kernel_offsets_linux_5x_values() {
        let off = KernelStructureOffsets::linux_5x();
        assert_eq!(off.task_pid, 0x03C8);
        assert_eq!(off.task_comm, 0x0640);
        assert_eq!(off.task_tasks_next, 0x0348);
        assert!(!off.is_windows());
        assert!(off.is_linux());
    }

    #[test]
    fn kernel_offsets_linux_6x_values() {
        let off = KernelStructureOffsets::linux_6x();
        assert_eq!(off.task_pid, 0x03D0);
        assert_eq!(off.task_comm, 0x0670);
        assert!(off.is_linux());
    }

    #[test]
    fn kernel_offsets_windows_11_x64_values() {
        let off = KernelStructureOffsets::windows_11_x64();
        assert_eq!(off.eprocess_image_file_name, 0x05A8);
        assert!(off.is_windows());
    }

    #[test]
    fn kernel_offsets_field_offset_known_field() {
        let off = KernelStructureOffsets::windows_10_x64();
        assert_eq!(off.field_offset("eprocess_peb"), Some(0x0550));
        assert_eq!(off.field_offset("peb_ldr"), Some(0x0018));
    }

    #[test]
    fn kernel_offsets_field_offset_unknown_field() {
        let off = KernelStructureOffsets::linux_5x();
        assert!(off.field_offset("nonexistent_field").is_none());
    }

    #[test]
    fn kernel_offsets_read_field_from_image() {
        // Build a tiny image that contains a u64 at offset 0x0440 = 0x1234
        let mut data = vec![0u8; 0x0450];
        let pid_bytes = 0x1234u64.to_le_bytes();
        data[0x0440..0x0448].copy_from_slice(&pid_bytes);
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let off = KernelStructureOffsets::windows_10_x64();
        let pid = off
            .read_field(&img, 0, "eprocess_unique_process_id")
            .unwrap();
        assert_eq!(pid, 0x1234);
    }

    #[test]
    fn kernel_offsets_read_string_field_from_image() {
        // Build a tiny image that has a process name at eprocess_image_file_name (0x05A0).
        let mut data = vec![0u8; 0x05C0];
        let name = b"notepad\x00";
        data[0x05A0..0x05A0 + name.len()].copy_from_slice(name);
        let img = RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows);
        let off = KernelStructureOffsets::windows_10_x64();
        let s = off
            .read_string_field(&img, 0, "eprocess_image_file_name", 15)
            .unwrap();
        assert_eq!(s, "notepad");
    }

    #[test]
    fn kernel_offsets_label_is_nonempty() {
        assert!(!KernelStructureOffsets::windows_10_x64().label.is_empty());
        assert!(!KernelStructureOffsets::linux_5x().label.is_empty());
        assert!(!KernelStructureOffsets::linux_6x().label.is_empty());
        assert!(!KernelStructureOffsets::windows_11_x64().label.is_empty());
    }

    #[test]
    fn kernel_offsets_serializes_to_json() {
        let off = KernelStructureOffsets::windows_10_x64();
        let json = serde_json::to_string(&off).unwrap();
        assert!(json.contains("eprocess_unique_process_id"));
        // serde_json serialises u64 as decimal; 0x440 = 1088
        assert!(json.contains("1088"));
    }
}
