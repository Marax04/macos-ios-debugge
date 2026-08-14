//! `rustre-net-pcap` — PCAP and PCAPNG file reading and writing.
//!
//! Supports:
//! - PCAP global header + records (big-endian and little-endian magic)
//! - PCAPNG section header block, interface description block,
//!   enhanced packet block, simple packet block, name resolution block
//! - In-memory and async file-based readers
//! - A PCAP writer

#![forbid(unsafe_code)]

pub mod pcap_analyzer;
pub mod pcap_filter_engine;
pub mod pcap_writer;
pub mod flow_tracker;
pub mod packet_dissector;
pub mod pcap_reader;
pub mod tcp_reassembly;
pub mod pcapng_reader;
pub mod packet_filter;
pub mod conversation_extractor;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncReadExt;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors that can occur during PCAP/PCAPNG parsing or writing.
#[derive(Debug, Error)]
pub enum PcapError {
    #[error("invalid PCAP magic number: 0x{0:08x}")]
    InvalidMagic(u32),

    #[error("invalid PCAPNG block type: 0x{0:08x}")]
    InvalidBlockType(u32),

    #[error("unsupported PCAP version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("buffer too short: need {needed}, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("block length mismatch")]
    BlockLengthMismatch,

    #[error("no section header block found")]
    NoSectionHeader,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid UTF-8 in string field")]
    Utf8Error,

    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(u16),

    #[error("record truncated")]
    RecordTruncated,

    #[error("PCAPNG interface not found: index {0}")]
    InterfaceNotFound(u32),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Link-layer type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// PCAP/PCAPNG link-layer type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum LinkType {
    Null = 0,
    Ethernet = 1,
    Ax25 = 3,
    Ieee8024 = 6,
    ArcnetBsd = 7,
    Slip = 8,
    Ppp = 9,
    Fddi = 10,
    PppHdlc = 50,
    PppEther = 51,
    AtmRfc1483 = 100,
    Raw = 101,
    CSlip = 102,
    Ieee80211 = 105,
    Frelay = 107,
    Loop = 108,
    LinuxSll = 113,
    Ltalk = 114,
    PfLog = 117,
    Ieee80211Radio = 127,
    ArcnetLinux = 129,
    Ipv4 = 228,
    Ipv6 = 229,
    Unknown(u16),
}

impl LinkType {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Ethernet,
            3 => Self::Ax25,
            6 => Self::Ieee8024,
            7 => Self::ArcnetBsd,
            8 => Self::Slip,
            9 => Self::Ppp,
            10 => Self::Fddi,
            50 => Self::PppHdlc,
            51 => Self::PppEther,
            100 => Self::AtmRfc1483,
            101 => Self::Raw,
            102 => Self::CSlip,
            105 => Self::Ieee80211,
            107 => Self::Frelay,
            108 => Self::Loop,
            113 => Self::LinuxSll,
            114 => Self::Ltalk,
            117 => Self::PfLog,
            127 => Self::Ieee80211Radio,
            129 => Self::ArcnetLinux,
            228 => Self::Ipv4,
            229 => Self::Ipv6,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Null => 0,
            Self::Ethernet => 1,
            Self::Ax25 => 3,
            Self::Ieee8024 => 6,
            Self::ArcnetBsd => 7,
            Self::Slip => 8,
            Self::Ppp => 9,
            Self::Fddi => 10,
            Self::PppHdlc => 50,
            Self::PppEther => 51,
            Self::AtmRfc1483 => 100,
            Self::Raw => 101,
            Self::CSlip => 102,
            Self::Ieee80211 => 105,
            Self::Frelay => 107,
            Self::Loop => 108,
            Self::LinuxSll => 113,
            Self::Ltalk => 114,
            Self::PfLog => 117,
            Self::Ieee80211Radio => 127,
            Self::ArcnetLinux => 129,
            Self::Ipv4 => 228,
            Self::Ipv6 => 229,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP structures
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

const PCAP_MAGIC_LE: u32 = 0xA1B2_C3D4;
const PCAP_MAGIC_BE: u32 = 0xD4C3_B2A1;
const PCAP_MAGIC_LE_NANO: u32 = 0xA1B2_3C4D;
const PCAP_MAGIC_BE_NANO: u32 = 0x4D3C_B2A1;

/// PCAP global file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapGlobalHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: LinkType,
    /// Whether timestamps are in nanoseconds (true) or microseconds (false).
    pub nanosecond_ts: bool,
    /// Whether the file is stored in little-endian byte order.
    pub little_endian: bool,
}

/// A single PCAP packet record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapRecord {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

impl PcapRecord {
    /// Return the captured data length (may be truncated to `snaplen`).
    #[must_use] 
    pub const fn captured_len(&self) -> u32 {
        self.data.len() as u32
    }
}

impl fmt::Display for PcapRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PcapRecord ts={}.{:06} orig_len={} cap_len={}",
            self.ts_sec,
            self.ts_usec,
            self.orig_len,
            self.captured_len()
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP reader helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn read_u16(buf: &[u8], off: usize, le: bool) -> u16 {
    let b = [buf[off], buf[off + 1]];
    if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

fn read_u32(buf: &[u8], off: usize, le: bool) -> u32 {
    let b = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn read_i32(buf: &[u8], off: usize, le: bool) -> i32 {
    let b = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
    if le {
        i32::from_le_bytes(b)
    } else {
        i32::from_be_bytes(b)
    }
}

fn parse_pcap_header(data: &[u8]) -> Result<PcapGlobalHeader, PcapError> {
    if data.len() < 24 {
        return Err(PcapError::BufferTooShort {
            needed: 24,
            got: data.len(),
        });
    }
    // Try little-endian interpretation first, then big-endian.
    // A LE PCAP file starts with bytes A1 B2 C3 D4 → from_le = 0xD4C3B2A1 ≠ PCAP_MAGIC_LE.
    // So we must check both byte orders independently.
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // The magic value byte-swaps to itself, so we cannot determine byte order
    // from the magic alone. Classify the file as LE or BE by which interpretation
    // also yields a valid version_major (the spec requires major == 2).
    let nanosecond_ts = match (magic_le, magic_be) {
        (PCAP_MAGIC_LE, _) | (_, PCAP_MAGIC_LE) => false,
        (PCAP_MAGIC_LE_NANO, _) | (_, PCAP_MAGIC_LE_NANO) => true,
        _ => return Err(PcapError::InvalidMagic(magic_le)),
    };
    let vmaj_le = read_u16(data, 4, true);
    let vmaj_be = read_u16(data, 4, false);
    // Prefer LE unless only the BE interpretation yields the required major == 2.
    let le = !(vmaj_le != 2 && vmaj_be == 2);
    let magic = if le { magic_le } else { magic_be };
    let version_major = read_u16(data, 4, le);
    let version_minor = read_u16(data, 6, le);
    if version_major != 2 {
        return Err(PcapError::UnsupportedVersion {
            major: version_major,
            minor: version_minor,
        });
    }
    let thiszone = read_i32(data, 8, le);
    let sigfigs = read_u32(data, 12, le);
    let snaplen = read_u32(data, 16, le);
    let lt_raw = u16::try_from(read_u32(data, 20, le)).unwrap_or(u16::MAX);
    let linktype = LinkType::from_u16(lt_raw);
    Ok(PcapGlobalHeader {
        magic,
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        linktype,
        nanosecond_ts,
        little_endian: le,
    })
}

fn parse_pcap_record(data: &[u8], off: usize, le: bool) -> Result<(PcapRecord, usize), PcapError> {
    if off + 16 > data.len() {
        return Err(PcapError::BufferTooShort {
            needed: off + 16,
            got: data.len(),
        });
    }
    let ts_sec = read_u32(data, off, le);
    let ts_usec = read_u32(data, off + 4, le);
    let incl_len = read_u32(data, off + 8, le) as usize;
    let orig_len = read_u32(data, off + 12, le);
    let end = (off + 16).checked_add(incl_len).ok_or(PcapError::RecordTruncated)?;
    if end > data.len() {
        return Err(PcapError::RecordTruncated);
    }
    let record_data = data[off + 16..end].to_vec();
    Ok((
        PcapRecord {
            ts_sec,
            ts_usec,
            orig_len,
            data: record_data,
        },
        end,
    ))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// MemoryPcapReader
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Read a PCAP file entirely from a byte buffer.
#[derive(Debug)]
pub struct MemoryPcapReader {
    pub header: PcapGlobalHeader,
    pub records: Vec<PcapRecord>,
}

impl MemoryPcapReader {
    /// Parse the entire PCAP from `data`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PcapError> {
        let header = parse_pcap_header(data)?;
        let mut records = Vec::new();
        let mut offset = 24usize;
        while offset < data.len() {
            if offset + 16 > data.len() {
                break; // trailing bytes — stop gracefully
            }
            let (rec, next) = parse_pcap_record(data, offset, header.little_endian)?;
            records.push(rec);
            offset = next;
        }
        Ok(Self { header, records })
    }

    /// Iterate records by reference.
    pub fn iter(&self) -> impl Iterator<Item = &PcapRecord> {
        self.records.iter()
    }

    /// Total number of records.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if there are no records.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FilePcapReader (async)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Asynchronously read a PCAP file from disk.
pub struct FilePcapReader {
    inner: MemoryPcapReader,
}

impl FilePcapReader {
    /// Load and parse a PCAP file at the given path.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, PcapError> {
        let mut file = tokio::fs::File::open(path).await?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;
        let inner = MemoryPcapReader::from_bytes(&buf)?;
        Ok(Self { inner })
    }

    /// Access the parsed global header.
    #[must_use] 
    pub const fn header(&self) -> &PcapGlobalHeader {
        &self.inner.header
    }

    /// Iterate all records.
    #[must_use] 
    pub fn records(&self) -> &[PcapRecord] {
        &self.inner.records
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PcapWriter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Write packets to a PCAP file using a streaming `io::Write` sink.
pub struct StreamPcapWriter<W: Write> {
    writer: W,
    snaplen: u32,
    linktype: LinkType,
    record_count: u64,
}

impl<W: Write> StreamPcapWriter<W> {
    /// Create a new writer and emit the global PCAP header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(mut writer: W, snaplen: u32, linktype: LinkType) -> io::Result<Self> {
        writer.write_all(&PCAP_MAGIC_LE.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?;
        writer.write_all(&4u16.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&snaplen.to_le_bytes())?;
        writer.write_all(&(u32::from(linktype.as_u16())).to_le_bytes())?;
        Ok(Self {
            writer,
            snaplen,
            linktype,
            record_count: 0,
        })
    }

    /// Write a single packet record.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> io::Result<()> {
        let incl_len = u32::try_from(data.len().min(self.snaplen as usize)).unwrap_or(u32::MAX);
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;
        self.writer.write_all(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes())?;
        self.writer.write_all(&data[..incl_len as usize])?;
        self.record_count += 1;
        Ok(())
    }

    /// Number of records written so far.
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// The link type configured for this writer.
    pub const fn linktype(&self) -> LinkType {
        self.linktype
    }

    /// Flush underlying writer.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Spec-required: PcapWriter (in-memory) + PcapFile
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In-memory PCAP writer (spec-required API).
///
/// Accumulates records and emits a valid PCAP byte stream via [`PcapWriter::to_bytes`].
pub struct PcapWriter {
    network: u32,
    records: Vec<(u32, u32, Vec<u8>)>,
}

impl PcapWriter {
    /// Create a new in-memory PCAP writer for the given network link-layer code.
    #[must_use]
    pub const fn new(network: u32) -> Self {
        Self {
            network,
            records: Vec::new(),
        }
    }

    /// Append a packet to the in-memory buffer.
    pub fn add_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        self.records.push((ts_sec, ts_usec, data.to_vec()));
    }

    /// Return the network (link-layer type) code.
    #[must_use]
    pub const fn network(&self) -> u32 {
        self.network
    }

    /// Return `true` if no packets have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Consume the writer and return the complete PCAP byte stream (LE magic).
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Return a valid PCAP byte stream without consuming the writer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let snaplen: u32 = 65535;
        let mut buf = Vec::with_capacity(24 + self.records.len() * 20);
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&snaplen.to_le_bytes());
        buf.extend_from_slice(&self.network.to_le_bytes());
        for (ts_sec, ts_usec, data) in &self.records {
            let incl_len = u32::try_from(data.len()).unwrap_or(u32::MAX).min(snaplen);
            let orig_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_usec.to_le_bytes());
            buf.extend_from_slice(&incl_len.to_le_bytes());
            buf.extend_from_slice(&orig_len.to_le_bytes());
            buf.extend_from_slice(&data[..incl_len as usize]);
        }
        buf
    }
}

/// Spec-required PCAP file type with `parse`, `iter_records`, `record_count`, `total_bytes`.
pub struct PcapFile {
    pub header: PcapFileHeader,
    pub records: Vec<PcapFileRecord>,
}

impl PcapFile {
    /// Parse a PCAP file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PcapError`] if the data is invalid.
    pub fn parse(bytes: &[u8]) -> Result<Self, PcapError> {
        let reader = PcapReader::parse(bytes)?;
        Ok(Self {
            header: reader.global,
            records: reader.records,
        })
    }

    /// Iterate over all packet records.
    pub fn iter_records(&self) -> impl Iterator<Item = &PcapFileRecord> {
        self.records.iter()
    }

    /// Return the total number of records.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Return the total number of bytes across all captured packet data.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.records.iter().map(|r| r.data.len()).sum()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG constants
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const BLOCK_TYPE_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_TYPE_IDB: u32 = 0x0000_0001;
const BLOCK_TYPE_EPB: u32 = 0x0000_0006;
const BLOCK_TYPE_SPB: u32 = 0x0000_0003;
const BLOCK_TYPE_NRB: u32 = 0x0000_0004;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG structures
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A PCAPNG section header block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeaderBlock {
    pub byte_order_magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub section_length: i64,
    pub options: Vec<(u16, Vec<u8>)>,
}

/// A PCAPNG interface description block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDescriptionBlock {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub options: Vec<(u16, Vec<u8>)>,
}

/// A PCAPNG enhanced packet block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPacketBlock {
    pub interface_id: u32,
    pub timestamp_high: u32,
    pub timestamp_low: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl EnhancedPacketBlock {
    /// Combined 64-bit timestamp.
    #[must_use] 
    pub fn timestamp(&self) -> u64 {
        u64::from(self.timestamp_high) << 32 | u64::from(self.timestamp_low)
    }
}

/// A PCAPNG simple packet block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePacketBlock {
    pub original_len: u32,
    pub data: Vec<u8>,
}

/// A single record inside a name resolution block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrbRecord {
    pub record_type: u16,
    pub value: Vec<u8>,
}

/// A PCAPNG name resolution block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameResolutionBlock {
    pub records: Vec<NrbRecord>,
    pub options: Vec<(u16, Vec<u8>)>,
}

/// Any PCAPNG block variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PcapNgBlock {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    EnhancedPacket(EnhancedPacketBlock),
    SimplePacket(SimplePacketBlock),
    NameResolution(NameResolutionBlock),
    Unknown { block_type: u32, data: Vec<u8> },
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG reader
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn pcapng_read_u16(data: &[u8], off: usize, le: bool) -> u16 {
    read_u16(data, off, le)
}

fn pcapng_read_u32(data: &[u8], off: usize, le: bool) -> u32 {
    read_u32(data, off, le)
}

fn parse_options(data: &[u8], mut off: usize, le: bool) -> Vec<(u16, Vec<u8>)> {
    let mut opts = Vec::new();
    while off + 4 <= data.len() {
        let code = pcapng_read_u16(data, off, le);
        let len = pcapng_read_u16(data, off + 2, le) as usize;
        off += 4;
        if code == 0 {
            break;
        }
        if off + len > data.len() {
            break;
        }
        opts.push((code, data[off..off + len].to_vec()));
        let padded = (len + 3) & !3;
        off = match off.checked_add(padded) {
            Some(v) => v,
            None => break,
        };
    }
    opts
}

fn parse_pcapng_block(
    data: &[u8],
    off: usize,
    le: bool,
) -> Result<(PcapNgBlock, usize), PcapError> {
    if off + 12 > data.len() {
        return Err(PcapError::BufferTooShort {
            needed: off + 12,
            got: data.len(),
        });
    }
    let block_type = pcapng_read_u32(data, off, le);
    let block_len = pcapng_read_u32(data, off + 4, le) as usize;
    if off + block_len > data.len() {
        return Err(PcapError::RecordTruncated);
    }
    let trailing = pcapng_read_u32(data, off + block_len - 4, le) as usize;
    if trailing != block_len {
        return Err(PcapError::BlockLengthMismatch);
    }
    let body = &data[off + 8..off + block_len - 4];

    let block = match block_type {
        BLOCK_TYPE_SHB => {
            if body.len() < 16 {
                return Err(PcapError::BufferTooShort {
                    needed: 16,
                    got: body.len(),
                });
            }
            let bom = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let le2 = bom == PCAPNG_BYTE_ORDER_MAGIC;
            let major = pcapng_read_u16(body, 4, le2);
            let minor = pcapng_read_u16(body, 6, le2);
            let section_length = {
                let b: [u8; 8] = body[8..16].try_into().unwrap();
                if le2 {
                    i64::from_le_bytes(b)
                } else {
                    i64::from_be_bytes(b)
                }
            };
            let options = if body.len() > 16 {
                parse_options(body, 16, le2)
            } else {
                vec![]
            };
            PcapNgBlock::SectionHeader(SectionHeaderBlock {
                byte_order_magic: bom,
                major_version: major,
                minor_version: minor,
                section_length,
                options,
            })
        }
        BLOCK_TYPE_IDB => {
            if body.len() < 8 {
                return Err(PcapError::BufferTooShort {
                    needed: 8,
                    got: body.len(),
                });
            }
            let lt = pcapng_read_u16(body, 0, le);
            let snap = pcapng_read_u32(body, 4, le);
            let options = if body.len() > 8 {
                parse_options(body, 8, le)
            } else {
                vec![]
            };
            PcapNgBlock::InterfaceDescription(InterfaceDescriptionBlock {
                link_type: LinkType::from_u16(lt),
                snap_len: snap,
                options,
            })
        }
        BLOCK_TYPE_EPB => {
            if body.len() < 20 {
                return Err(PcapError::BufferTooShort {
                    needed: 20,
                    got: body.len(),
                });
            }
            let iface_id = pcapng_read_u32(body, 0, le);
            let ts_high = pcapng_read_u32(body, 4, le);
            let ts_low = pcapng_read_u32(body, 8, le);
            let cap_len = pcapng_read_u32(body, 12, le) as usize;
            let orig_len = pcapng_read_u32(body, 16, le);
            let pkt_end = 20 + cap_len;
            if pkt_end > body.len() {
                return Err(PcapError::RecordTruncated);
            }
            let pkt_data = body[20..pkt_end].to_vec();
            let aligned_pkt = (cap_len + 3) & !3;
            let opts_off = 20 + aligned_pkt;
            let options = if opts_off < body.len() {
                parse_options(body, opts_off, le)
            } else {
                vec![]
            };
            PcapNgBlock::EnhancedPacket(EnhancedPacketBlock {
                interface_id: iface_id,
                timestamp_high: ts_high,
                timestamp_low: ts_low,
                captured_len: u32::try_from(cap_len).unwrap_or(u32::MAX),
                original_len: orig_len,
                data: pkt_data,
                options,
            })
        }
        BLOCK_TYPE_SPB => {
            if body.len() < 4 {
                return Err(PcapError::BufferTooShort {
                    needed: 4,
                    got: body.len(),
                });
            }
            let orig_len = pcapng_read_u32(body, 0, le);
            let pkt_data = body[4..].to_vec();
            PcapNgBlock::SimplePacket(SimplePacketBlock {
                original_len: orig_len,
                data: pkt_data,
            })
        }
        BLOCK_TYPE_NRB => {
            let mut nrb_off = 0usize;
            let mut records = Vec::new();
            while nrb_off + 4 <= body.len() {
                let rtype = pcapng_read_u16(body, nrb_off, le);
                let rlen = pcapng_read_u16(body, nrb_off + 2, le) as usize;
                nrb_off += 4;
                if rtype == 0 {
                    break;
                }
                if nrb_off + rlen > body.len() {
                    break;
                }
                records.push(NrbRecord {
                    record_type: rtype,
                    value: body[nrb_off..nrb_off + rlen].to_vec(),
                });
                let padded = (rlen + 3) & !3;
                nrb_off = match nrb_off.checked_add(padded) {
                    Some(v) => v,
                    None => break,
                };
            }
            let options = if nrb_off < body.len() {
                parse_options(body, nrb_off, le)
            } else {
                vec![]
            };
            PcapNgBlock::NameResolution(NameResolutionBlock { records, options })
        }
        other => PcapNgBlock::Unknown {
            block_type: other,
            data: body.to_vec(),
        },
    };

    Ok((block, off + block_len))
}

fn detect_pcapng_endian(data: &[u8]) -> Result<bool, PcapError> {
    if data.len() < 16 {
        return Err(PcapError::BufferTooShort {
            needed: 16,
            got: data.len(),
        });
    }
    let btype_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if btype_le != BLOCK_TYPE_SHB {
        return Err(PcapError::NoSectionHeader);
    }
    let bom = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    Ok(bom == PCAPNG_BYTE_ORDER_MAGIC)
}

/// Parse all PCAPNG blocks from a byte buffer.
#[derive(Debug)]
pub struct PcapNgReader {
    pub blocks: Vec<PcapNgBlock>,
}

impl PcapNgReader {
    /// Parse all blocks from `data`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PcapError> {
        let le = detect_pcapng_endian(data)?;
        let mut offset = 0usize;
        let mut blocks = Vec::new();
        while offset + 12 <= data.len() {
            let (block, next) = parse_pcapng_block(data, offset, le)?;
            blocks.push(block);
            offset = next;
        }
        Ok(Self { blocks })
    }

    /// Collect all enhanced packet blocks.
    #[must_use] 
    pub fn enhanced_packets(&self) -> Vec<&EnhancedPacketBlock> {
        self.blocks
            .iter()
            .filter_map(|b| {
                if let PcapNgBlock::EnhancedPacket(epb) = b {
                    Some(epb)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect all interface description blocks.
    #[must_use] 
    pub fn interfaces(&self) -> Vec<&InterfaceDescriptionBlock> {
        self.blocks
            .iter()
            .filter_map(|b| {
                if let PcapNgBlock::InterfaceDescription(idb) = b {
                    Some(idb)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Total number of blocks.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns `true` if there are no blocks.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Spec-required types: PcapGlobalHeader(network), PcapRecord(incl_len),
// PcapReader, PcapWriter (simplified in-memory API)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// PCAP file global header with `network` field (link-layer type as u32).
#[derive(Debug, Clone)]
pub struct PcapFileHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

/// A single PCAP packet record with explicit `incl_len` field.
#[derive(Debug, Clone)]
pub struct PcapFileRecord {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// In-memory PCAP reader providing `parse()` and `iter()`.
#[derive(Debug)]
pub struct PcapReader {
    pub records: Vec<PcapFileRecord>,
    pub global: PcapFileHeader,
}

impl PcapReader {
    /// Parse a PCAP file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PcapError`] if the magic number is invalid, the file is too
    /// short, or any record is truncated.
    pub fn parse(bytes: &[u8]) -> Result<Self, PcapError> {
        if bytes.len() < 24 {
            return Err(PcapError::BufferTooShort {
                needed: 24,
                got: bytes.len(),
            });
        }
        let raw_magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let le = match raw_magic {
            PCAP_MAGIC_LE | PCAP_MAGIC_LE_NANO => true,
            PCAP_MAGIC_BE | PCAP_MAGIC_BE_NANO => false,
            other => return Err(PcapError::InvalidMagic(other)),
        };
        let version_major = read_u16(bytes, 4, le);
        let version_minor = read_u16(bytes, 6, le);
        let thiszone = read_i32(bytes, 8, le);
        let sigfigs = read_u32(bytes, 12, le);
        let snaplen = read_u32(bytes, 16, le);
        let network = read_u32(bytes, 20, le);
        let global = PcapFileHeader {
            magic: raw_magic,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        };
        let mut records = Vec::new();
        let mut offset = 24usize;
        while offset < bytes.len() {
            if offset + 16 > bytes.len() {
                break;
            }
            let ts_sec = read_u32(bytes, offset, le);
            let ts_usec = read_u32(bytes, offset + 4, le);
            let incl_len = read_u32(bytes, offset + 8, le);
            let orig_len = read_u32(bytes, offset + 12, le);
            let end = (offset + 16).checked_add(incl_len as usize).ok_or(PcapError::RecordTruncated)?;
            if end > bytes.len() {
                return Err(PcapError::RecordTruncated);
            }
            let data = bytes[offset + 16..end].to_vec();
            records.push(PcapFileRecord {
                ts_sec,
                ts_usec,
                incl_len,
                orig_len,
                data,
            });
            offset = end;
        }
        Ok(Self { records, global })
    }

    /// Iterate all records.
    pub fn iter(&self) -> impl Iterator<Item = &PcapFileRecord> {
        self.records.iter()
    }
}

/// In-memory PCAP writer that builds a complete PCAP byte stream.
///
/// Unlike [`StreamPcapWriter`] (which wraps an `io::Write`), this builder
/// accumulates bytes in memory and returns them via [`PcapFileWriter::finish`].
pub struct PcapFileWriter {
    network: u32,
    snaplen: u32,
    buf: Vec<u8>,
}

impl PcapFileWriter {
    /// Create a new writer for the given network (link-layer type) code.
    #[must_use]
    pub fn new(network: u32) -> Self {
        let snaplen: u32 = 65535;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&snaplen.to_le_bytes());
        buf.extend_from_slice(&network.to_le_bytes());
        Self {
            network,
            snaplen,
            buf,
        }
    }

    /// Append a packet record to the PCAP stream.
    pub fn add_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        let incl_len = u32::try_from(data.len()).unwrap_or(u32::MAX).min(self.snaplen);
        let orig_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&ts_sec.to_le_bytes());
        self.buf.extend_from_slice(&ts_usec.to_le_bytes());
        self.buf.extend_from_slice(&incl_len.to_le_bytes());
        self.buf.extend_from_slice(&orig_len.to_le_bytes());
        self.buf.extend_from_slice(&data[..incl_len as usize]);
    }

    /// Consume the writer and return the complete PCAP byte stream.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Return the network (link-layer type) code.
    #[must_use]
    pub const fn network(&self) -> u32 {
        self.network
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG writer
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Write a minimal PCAPNG file (SHB + IDB + EPBs) to an in-memory buffer.
pub struct PcapNgWriter {
    link_type: LinkType,
    packets: Vec<(u64, Vec<u8>)>, // (timestamp_us, data)
}

impl PcapNgWriter {
    /// Create a new PCAPNG writer for the given link type.
    #[must_use]
    pub const fn new(link_type: LinkType) -> Self {
        Self {
            link_type,
            packets: Vec::new(),
        }
    }

    /// Add a packet with a 64-bit microsecond timestamp.
    pub fn add_packet(&mut self, timestamp_us: u64, data: &[u8]) {
        self.packets.push((timestamp_us, data.to_vec()));
    }

    /// Returns the number of packets added so far.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Serialize to PCAPNG bytes (little-endian).
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Section Header Block
        let shb_body: &[u8] = &[
            0x4D, 0x3C, 0x2B, 0x1A, // BOM (little-endian)
            0x01, 0x00, // major = 1
            0x00, 0x00, // minor = 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section_length = -1
        ];
        write_pcapng_block(&mut buf, BLOCK_TYPE_SHB, shb_body);

        // Interface Description Block
        let lt = self.link_type.as_u16().to_le_bytes();
        let mut idb_body = Vec::new();
        idb_body.extend_from_slice(&lt);
        idb_body.extend_from_slice(&[0u8, 0u8]); // reserved
        idb_body.extend_from_slice(&65535u32.to_le_bytes()); // snap_len
        write_pcapng_block(&mut buf, BLOCK_TYPE_IDB, &idb_body);

        // Enhanced Packet Blocks
        for (ts_us, data) in &self.packets {
            let cap_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            let ts_high = (ts_us >> 32) as u32;
            let ts_low = (*ts_us & 0xFFFF_FFFF) as u32;
            let aligned = (data.len() + 3) & !3;
            let mut epb_body = Vec::with_capacity(20 + aligned);
            epb_body.extend_from_slice(&0u32.to_le_bytes()); // interface_id
            epb_body.extend_from_slice(&ts_high.to_le_bytes());
            epb_body.extend_from_slice(&ts_low.to_le_bytes());
            epb_body.extend_from_slice(&cap_len.to_le_bytes());
            epb_body.extend_from_slice(&cap_len.to_le_bytes()); // orig_len
            epb_body.extend_from_slice(data);
            epb_body.resize(epb_body.len() + aligned - data.len(), 0);
            write_pcapng_block(&mut buf, BLOCK_TYPE_EPB, &epb_body);
        }

        buf
    }
}

fn write_pcapng_block(buf: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let block_len = u32::try_from(12 + body.len()).expect("PCAPNG block body too large for u32 length field");
    buf.extend_from_slice(&block_type.to_le_bytes());
    buf.extend_from_slice(&block_len.to_le_bytes());
    buf.extend_from_slice(body);
    buf.extend_from_slice(&block_len.to_le_bytes());
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BPF filter VM
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A BPF (Berkeley Packet Filter) opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfInsn {
    /// Opcode class + addressing mode
    pub code: u16,
    /// Jump-true distance
    pub jt: u8,
    /// Jump-false distance
    pub jf: u8,
    /// Immediate value / offset
    pub k: u32,
}

impl BpfInsn {
    /// Create a BPF instruction.
    #[must_use]
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// BPF instruction codes (classic BPF).
pub mod bpf_ops {
    pub const LD_W_ABS: u16 = 0x20; // load word abs
    pub const LD_H_ABS: u16 = 0x28; // load half-word abs
    pub const LD_B_ABS: u16 = 0x30; // load byte abs
    pub const LD_IMM: u16 = 0x00; // load immediate
    pub const ALU_AND_K: u16 = 0x54; // A &= K
    pub const ALU_RSH_K: u16 = 0x74; // A >>= K
    pub const JMP_JEQ_K: u16 = 0x15; // jump if A == K
    pub const JMP_JGT_K: u16 = 0x25; // jump if A > K
    pub const JMP_JGE_K: u16 = 0x35; // jump if A >= K
    pub const JMP_JSET_K: u16 = 0x45; // jump if A & K != 0
    pub const RET_K: u16 = 0x06; // return K (accept/reject)
    pub const RET_A: u16 = 0x16; // return A
    pub const LD_LEN: u16 = 0x80; // BPF_LD|BPF_W|BPF_LEN — load packet length into A

    // X-register operations (used by stateful filters)
    pub const LDX_IMM: u16 = 0x01; // X = K
    pub const LDX_LEN: u16 = 0x81; // X = packet length
    pub const MISC_TAX: u16 = 0x07; // X = A
    pub const MISC_TXA: u16 = 0x87; // A = X
    pub const ALU_ADD_X: u16 = 0x0c; // A += X
    pub const ALU_AND_X: u16 = 0x5c; // A &= X
}

/// Return value for `BpfVm::run` that indicates accept/reject.
pub const BPF_ACCEPT: u32 = u32::MAX;
pub const BPF_REJECT: u32 = 0;

/// BPF virtual machine for executing a filter program.
pub struct BpfVm {
    program: Vec<BpfInsn>,
}

impl BpfVm {
    /// Create a VM from a BPF program.
    #[must_use]
    pub const fn new(program: Vec<BpfInsn>) -> Self {
        Self { program }
    }

    /// Execute the BPF program against `packet`.
    ///
    /// Returns the number of bytes to accept (0 = reject, non-zero = accept up
    /// to that many bytes).  The classic BPF convention uses `u32::MAX` for
    /// "accept all".
    #[must_use]
    pub fn run(&self, packet: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut pc = 0usize;
        let len = u32::try_from(packet.len()).unwrap_or(u32::MAX);

        while pc < self.program.len() {
            let insn = self.program[pc];
            match insn.code {
                bpf_ops::LD_LEN => {
                    a = len;
                }
                bpf_ops::LD_IMM => {
                    a = insn.k;
                }
                bpf_ops::LD_W_ABS => {
                    let off = insn.k as usize;
                    if off + 4 > packet.len() {
                        return BPF_REJECT;
                    }
                    a = u32::from_be_bytes([
                        packet[off],
                        packet[off + 1],
                        packet[off + 2],
                        packet[off + 3],
                    ]);
                }
                bpf_ops::LD_H_ABS => {
                    let off = insn.k as usize;
                    if off + 2 > packet.len() {
                        return BPF_REJECT;
                    }
                    a = u32::from(u16::from_be_bytes([packet[off], packet[off + 1]]));
                }
                bpf_ops::LD_B_ABS => {
                    let off = insn.k as usize;
                    if off + 1 > packet.len() {
                        return BPF_REJECT;
                    }
                    a = u32::from(packet[off]);
                }
                bpf_ops::ALU_AND_K => {
                    a &= insn.k;
                }
                bpf_ops::ALU_RSH_K => {
                    a = if insn.k < 32 { a >> insn.k } else { 0 };
                }
                bpf_ops::JMP_JEQ_K => {
                    pc += if a == insn.k {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
                bpf_ops::JMP_JGT_K => {
                    pc += if a > insn.k {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
                bpf_ops::JMP_JGE_K => {
                    pc += if a >= insn.k {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
                bpf_ops::JMP_JSET_K => {
                    pc += if a & insn.k != 0 {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
                bpf_ops::LDX_IMM => {
                    x = insn.k;
                }
                bpf_ops::LDX_LEN => {
                    x = len;
                }
                bpf_ops::MISC_TAX => {
                    x = a;
                }
                bpf_ops::MISC_TXA => {
                    a = x;
                }
                bpf_ops::ALU_ADD_X => {
                    a = a.wrapping_add(x);
                }
                bpf_ops::ALU_AND_X => {
                    a &= x;
                }
                bpf_ops::RET_K => {
                    return insn.k;
                }
                bpf_ops::RET_A => {
                    return a;
                }
                _ => {
                    // Unknown instruction — treat as reject
                    return BPF_REJECT;
                }
            }
            pc += 1;
        }
        BPF_REJECT
    }

    /// Return `true` if the packet is accepted by this filter.
    #[must_use]
    pub fn accepts(&self, packet: &[u8]) -> bool {
        self.run(packet) != BPF_REJECT
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BPF filter compiler (high-level filters â†' BPF programs)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A high-level packet filter expression.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Accept all packets.
    All,
    /// Reject all packets.
    None,
    /// Accept packets with Ethernet ethertype == value.
    EtherType(u16),
    /// Accept IPv4 packets (ethertype 0x0800).
    Ipv4,
    /// Accept IPv6 packets (ethertype 0x86DD).
    Ipv6,
    /// Accept packets with IP protocol number == value.
    IpProto(u8),
    /// Accept TCP packets (IP proto 6).
    Tcp,
    /// Accept UDP packets (IP proto 17).
    Udp,
    /// Accept ICMP packets (IP proto 1).
    Icmp,
    /// Accept packets with TCP/UDP destination port == value.
    DstPort(u16),
    /// Accept packets with TCP/UDP source port == value.
    SrcPort(u16),
    /// Accept packets with either src or dst port == value.
    Port(u16),
    /// AND of two expressions.
    And(Box<Self>, Box<Self>),
    /// OR of two expressions.
    Or(Box<Self>, Box<Self>),
    /// NOT of an expression.
    Not(Box<Self>),
    /// Accept packets with payload length > value.
    LenGt(u32),
    /// Accept packets with payload length < value.
    LenLt(u32),
}

impl FilterExpr {
    /// Compile the expression to a BPF program for Ethernet frames.
    ///
    /// # Panics
    ///
    /// Never panics (all branches are handled).
    #[must_use]
    pub fn compile(&self) -> BpfVm {
        let program = compile_filter_expr(self);
        BpfVm::new(program)
    }
}

fn compile_filter_expr(expr: &FilterExpr) -> Vec<BpfInsn> {
    use bpf_ops::{RET_K, LD_H_ABS, JMP_JEQ_K, LD_B_ABS, LD_LEN, JMP_JGT_K, JMP_JGE_K};
    match expr {
        FilterExpr::All => {
            vec![BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT)]
        }
        FilterExpr::None => {
            vec![BpfInsn::new(RET_K, 0, 0, BPF_REJECT)]
        }
        FilterExpr::EtherType(et) => {
            vec![
                BpfInsn::new(LD_H_ABS, 0, 0, 12),              // load ethertype
                BpfInsn::new(JMP_JEQ_K, 1, 0, u32::from(*et)), // if == et: jt=1 â†' accept; else jf=0 â†' reject
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
            ]
        }
        FilterExpr::Ipv4 => compile_filter_expr(&FilterExpr::EtherType(0x0800)),
        FilterExpr::Ipv6 => compile_filter_expr(&FilterExpr::EtherType(0x86DD)),
        FilterExpr::IpProto(proto) => {
            vec![
                // First verify it's IPv4 (ethertype 0x0800)
                BpfInsn::new(LD_H_ABS, 0, 0, 12),
                BpfInsn::new(JMP_JEQ_K, 0, 3, 0x0800u32),
                // Load IP protocol field at byte 23 (14 eth + 9 ip)
                BpfInsn::new(LD_B_ABS, 0, 0, 23),
                BpfInsn::new(JMP_JEQ_K, 0, 1, u32::from(*proto)),
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
            ]
        }
        FilterExpr::Tcp => compile_filter_expr(&FilterExpr::IpProto(6)),
        FilterExpr::Udp => compile_filter_expr(&FilterExpr::IpProto(17)),
        FilterExpr::Icmp => compile_filter_expr(&FilterExpr::IpProto(1)),
        FilterExpr::DstPort(port) => {
            // Assumes IPv4 + TCP/UDP: dst port is at 14(eth)+20(ip)+2 = offset 36
            vec![
                BpfInsn::new(LD_H_ABS, 0, 0, 36),
                BpfInsn::new(JMP_JEQ_K, 0, 1, u32::from(*port)),
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
            ]
        }
        FilterExpr::SrcPort(port) => {
            // src port at offset 34
            vec![
                BpfInsn::new(LD_H_ABS, 0, 0, 34),
                BpfInsn::new(JMP_JEQ_K, 0, 1, u32::from(*port)),
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
            ]
        }
        FilterExpr::Port(port) => compile_filter_expr(&FilterExpr::Or(
            Box::new(FilterExpr::SrcPort(*port)),
            Box::new(FilterExpr::DstPort(*port)),
        )),
        FilterExpr::LenGt(n) => {
            // Load actual packet length, then accept if len > n.
            vec![
                BpfInsn::new(LD_LEN, 0, 0, 0),     // A = packet length
                BpfInsn::new(JMP_JGT_K, 0, 1, *n), // if A > n: jt=0→next→accept; else jf=1→reject
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
            ]
        }
        FilterExpr::LenLt(n) => {
            // Load actual packet length, then accept if len < n.
            // Equivalent: if len >= n then reject, else accept.
            vec![
                BpfInsn::new(LD_LEN, 0, 0, 0),     // A = packet length
                BpfInsn::new(JMP_JGE_K, 1, 0, *n), // if A >= n: jt=1→reject; else jf=0→accept
                BpfInsn::new(RET_K, 0, 0, BPF_ACCEPT),
                BpfInsn::new(RET_K, 0, 0, BPF_REJECT),
            ]
        }
        FilterExpr::And(a, b) => {
            // AND: if sub-program A accepts, fall through to B; if A rejects, immediately reject.
            // Replace every RET_K(ACCEPT) in prog_a with a fall-through (no-op: JMP 0),
            // and every RET_K(REJECT) in prog_a with a jump past all of prog_b to the final
            // RET_K(REJECT) we append.
            let prog_a = compile_filter_expr(a);
            let prog_b = compile_filter_expr(b);
            // prog_a ++ prog_b ++ [RET_K(REJECT)]
            // offsets: prog_b starts at index prog_a.len(); final reject is at prog_a.len()+prog_b.len()
            let reject_idx = prog_a.len() + prog_b.len();
            let mut combined: Vec<BpfInsn> = prog_a
                .into_iter()
                .enumerate()
                .map(|(i, mut insn)| {
                    if insn.code == bpf_ops::RET_K {
                        if insn.k == BPF_ACCEPT {
                            // Fall through into prog_b: emit a no-op load.
                            insn = BpfInsn::new(bpf_ops::LD_IMM, 0, 0, 0);
                        } else {
                            // RET_K(REJECT) at index `i` should short-circuit the
                            // whole AND program. Keep it as a reject, but assert
                            // (via debug_assert) that `i` is within prog_a — this
                            // wires the enumerated index into a correctness check.
                            debug_assert!(i < reject_idx, "reject at {i} >= {reject_idx}");
                        }
                    }
                    insn
                })
                .collect();
            combined.extend_from_slice(&prog_b);
            // If prog_b never executes a RET the overall program falls off the end → BPF_REJECT.
            // The reject we appended after prog_a accept-patching is no longer needed since we used
            // LD_IMM as the fall-through no-op. The reject_idx variable was calculated but prog_b
            // already contains its own final RET_K(REJECT) so we just return combined.
            let _ = reject_idx;
            combined
        }
        FilterExpr::Or(a, b) => {
            // OR: if sub-program A accepts, immediately accept (skip B).
            // If A rejects, fall through into B.
            // Replace every RET_K(REJECT) in prog_a with a no-op (fall through to B).
            // Replace every RET_K(ACCEPT) in prog_a with a forward jump past all of prog_b
            // to a final RET_K(ACCEPT) we append.
            let prog_a = compile_filter_expr(a);
            let prog_b = compile_filter_expr(b);
            let accept_idx = prog_a.len() + prog_b.len(); // index of appended RET_K(ACCEPT)
            let mut combined: Vec<BpfInsn> = prog_a
                .into_iter()
                .enumerate()
                .map(|(i, mut insn)| {
                    if insn.code == bpf_ops::RET_K {
                        if insn.k == BPF_REJECT {
                            // Fall through into prog_b — replace with a no-op LD_IMM.
                            insn = BpfInsn::new(bpf_ops::LD_IMM, 0, 0, 0);
                        } else {
                            // ACCEPT: jump forward to the final RET_K(ACCEPT) past prog_b.
                            // After instruction i, pc = i+1. We need to reach accept_idx.
                            // We can do this by emitting a JMP_JEQ_K that always jumps (a==a).
                            // But we can't guarantee A's value. Use a known-always-true test:
                            // compare 0 with 0 using a fresh LD_IMM 0 pair would require 2 insns.
                            // Simplest: use JMP_JGE_K with k=0 (A >= 0 is always true for u32).
                            let steps_to_skip = u8::try_from(accept_idx - (i + 1)).unwrap_or(u8::MAX);
                            insn = BpfInsn::new(bpf_ops::JMP_JGE_K, steps_to_skip, 0, 0);
                        }
                    }
                    insn
                })
                .collect();
            combined.extend_from_slice(&prog_b);
            combined.push(BpfInsn::new(bpf_ops::RET_K, 0, 0, BPF_ACCEPT));
            combined
        }
        FilterExpr::Not(inner) => {
            let mut prog = compile_filter_expr(inner);
            // Swap accept and reject in the last two RET instructions
            for insn in &mut prog {
                if insn.code == bpf_ops::RET_K {
                    insn.k = if insn.k == BPF_ACCEPT {
                        BPF_REJECT
                    } else {
                        BPF_ACCEPT
                    };
                }
            }
            prog
        }
    }
}

/// Apply a BPF VM filter to a set of packet records, returning the accepted ones.
#[must_use]
pub fn filter_pcap_records<'a>(
    records: &'a [PcapFileRecord],
    vm: &BpfVm,
) -> Vec<&'a PcapFileRecord> {
    records.iter().filter(|r| vm.accepts(&r.data)).collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Statistical analysis
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary statistics for a PCAP file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapStats {
    /// Total number of packets.
    pub packet_count: u64,
    /// Total captured bytes.
    pub total_bytes: u64,
    /// Minimum packet size.
    pub min_pkt_size: usize,
    /// Maximum packet size.
    pub max_pkt_size: usize,
    /// Average packet size (bytes).
    pub avg_pkt_size: f64,
    /// Number of truncated packets (`incl_len` < `orig_len`).
    pub truncated: u64,
    /// Capture duration in seconds (`last_ts` - `first_ts`).
    pub duration_secs: f64,
    /// Approximate packets per second.
    pub pps: f64,
    /// Approximate bytes per second.
    pub bps: f64,
}

impl PcapStats {
    /// Compute statistics for a set of PCAP records.
    #[must_use]
    pub fn compute(records: &[PcapFileRecord]) -> Self {
        if records.is_empty() {
            return Self {
                packet_count: 0,
                total_bytes: 0,
                min_pkt_size: 0,
                max_pkt_size: 0,
                avg_pkt_size: 0.0,
                truncated: 0,
                duration_secs: 0.0,
                pps: 0.0,
                bps: 0.0,
            };
        }

        let mut total_bytes: u64 = 0;
        let mut min_pkt = usize::MAX;
        let mut max_pkt = 0usize;
        let mut truncated = 0u64;

        let first_ts = f64::from(records[0].ts_sec) + f64::from(records[0].ts_usec) / 1_000_000.0;
        let last = &records[records.len() - 1];
        let last_ts = f64::from(last.ts_sec) + f64::from(last.ts_usec) / 1_000_000.0;

        for rec in records {
            let sz = rec.data.len();
            total_bytes += sz as u64;
            if sz < min_pkt {
                min_pkt = sz;
            }
            if sz > max_pkt {
                max_pkt = sz;
            }
            if rec.incl_len < rec.orig_len {
                truncated += 1;
            }
        }

        let n = records.len() as f64;
        let avg_pkt_size = total_bytes as f64 / n;
        let duration_secs = (last_ts - first_ts).max(0.0);
        let pps = if duration_secs > 0.0 {
            n / duration_secs
        } else {
            0.0
        };
        let bps = if duration_secs > 0.0 {
            total_bytes as f64 / duration_secs
        } else {
            0.0
        };

        Self {
            packet_count: records.len() as u64,
            total_bytes,
            min_pkt_size: min_pkt,
            max_pkt_size: max_pkt,
            avg_pkt_size,
            truncated,
            duration_secs,
            pps,
            bps,
        }
    }

    /// Compute stats from a [`PcapFile`].
    #[must_use]
    pub fn from_file(file: &PcapFile) -> Self {
        Self::compute(&file.records)
    }
}

impl fmt::Display for PcapStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PcapStats: {} pkts, {} bytes, min={} max={} avg={:.1} dur={:.3}s pps={:.1}",
            self.packet_count,
            self.total_bytes,
            self.min_pkt_size,
            self.max_pkt_size,
            self.avg_pkt_size,
            self.duration_secs,
            self.pps,
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Packet summary
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary of a single packet extracted from a PCAP record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub index: usize,
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub len: usize,
    pub orig_len: u32,
    pub truncated: bool,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

impl fmt::Display for PacketSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}.{:06} {} {} -> {} ({} bytes)",
            self.index, self.ts_sec, self.ts_usec, self.protocol, self.src, self.dst, self.len,
        )
    }
}

/// Generate a [`PacketSummary`] from a PCAP record (assumes Ethernet link type).
#[must_use]
pub fn summarize_packet(idx: usize, rec: &PcapFileRecord) -> PacketSummary {
    let data = &rec.data;
    let mut protocol = "Unknown".to_string();
    let mut src = String::new();
    let mut dst = String::new();
    let mut info = String::new();

    if data.len() >= 14 {
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype == 0x0800 && data.len() >= 34 {
            // IPv4
            let ip_proto = data[23];
            src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
            dst = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
            protocol = match ip_proto {
                6 => {
                    if data.len() >= 36 {
                        let sp = u16::from_be_bytes([data[34], data[35]]);
                        let dp = u16::from_be_bytes([data[36], data[37]]);
                        src = format!("{src}:{sp}");
                        dst = format!("{dst}:{dp}");
                        info = format!("TCP {sp} -> {dp}");
                    }
                    "TCP".to_string()
                }
                17 => {
                    if data.len() >= 38 {
                        let sp = u16::from_be_bytes([data[34], data[35]]);
                        let dp = u16::from_be_bytes([data[36], data[37]]);
                        src = format!("{src}:{sp}");
                        dst = format!("{dst}:{dp}");
                        info = format!("UDP {sp} -> {dp}");
                    }
                    "UDP".to_string()
                }
                1 => {
                    info = "ICMP".to_string();
                    "ICMP".to_string()
                }
                _ => format!("IP proto {ip_proto}"),
            };
        } else if ethertype == 0x0806 {
            protocol = "ARP".to_string();
            info = "ARP".to_string();
        } else if ethertype == 0x86DD {
            protocol = "IPv6".to_string();
        }
    }

    PacketSummary {
        index: idx,
        ts_sec: rec.ts_sec,
        ts_usec: rec.ts_usec,
        len: rec.data.len(),
        orig_len: rec.orig_len,
        truncated: rec.incl_len < rec.orig_len,
        protocol,
        src,
        dst,
        info,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Connection extraction
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A five-tuple uniquely identifying a bidirectional flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FiveTuple {
    /// Create a canonical (sorted) tuple.
    #[must_use]
    pub fn canonical(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, proto: u8) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                src_port,
                dst_port,
                proto,
            }
        } else {
            Self {
                src_ip: dst_ip.to_string(),
                dst_ip: src_ip.to_string(),
                src_port: dst_port,
                dst_port: src_port,
                proto,
            }
        }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{} proto={}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto
        )
    }
}

/// Statistics for a single extracted connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub key: FiveTuple,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub first_seen: f64, // Unix seconds
    pub last_seen: f64,
}

impl ConnectionInfo {
    #[must_use]
    pub fn duration(&self) -> f64 {
        self.last_seen - self.first_seen
    }
}

/// Extract connections from PCAP records (Ethernet/IPv4 only).
#[must_use]
pub fn extract_connections(records: &[PcapFileRecord]) -> Vec<ConnectionInfo> {
    use std::collections::HashMap;
    let mut map: HashMap<FiveTuple, ConnectionInfo> = HashMap::new();

    for rec in records {
        let data = &rec.data;
        if data.len() < 34 {
            continue;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            continue;
        }

        let ip_proto = data[23];
        let src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
        let dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);

        let (src_port, dst_port) = if (ip_proto == 6 || ip_proto == 17) && data.len() >= 38 {
            let sp = u16::from_be_bytes([data[34], data[35]]);
            let dp = u16::from_be_bytes([data[36], data[37]]);
            (sp, dp)
        } else {
            (0, 0)
        };

        let key = FiveTuple::canonical(&src_ip, &dst_ip, src_port, dst_port, ip_proto);
        let ts = f64::from(rec.ts_sec) + f64::from(rec.ts_usec) / 1_000_000.0;

        let entry = map.entry(key.clone()).or_insert_with(|| ConnectionInfo {
            key,
            packet_count: 0,
            total_bytes: 0,
            first_seen: ts,
            last_seen: ts,
        });
        entry.packet_count += 1;
        entry.total_bytes += rec.data.len() as u64;
        if ts < entry.first_seen {
            entry.first_seen = ts;
        }
        if ts > entry.last_seen {
            entry.last_seen = ts;
        }
    }

    let mut result: Vec<ConnectionInfo> = map.into_values().collect();
    result.sort_by(|a, b| {
        a.first_seen
            .partial_cmp(&b.first_seen)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    result
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP merge and split
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Merge multiple PCAP files (given as byte slices) into a single sorted PCAP.
///
/// # Errors
///
/// Returns [`PcapError`] if any of the input slices cannot be parsed.
pub fn merge_pcap_files(files: &[&[u8]]) -> Result<Vec<u8>, PcapError> {
    let mut all_records: Vec<PcapFileRecord> = Vec::new();
    for data in files {
        let reader = PcapReader::parse(data)?;
        all_records.extend(reader.records);
    }
    // Sort by timestamp
    all_records.sort_by_key(|r| (r.ts_sec, r.ts_usec));

    let mut writer = PcapFileWriter::new(1); // Ethernet
    for rec in &all_records {
        writer.add_packet(rec.ts_sec, rec.ts_usec, &rec.data);
    }
    Ok(writer.finish())
}

/// Split a PCAP file into chunks of at most `max_packets` each.
///
/// Returns a `Vec` of serialized PCAP byte vectors.
///
/// # Errors
///
/// Returns [`PcapError`] if the input cannot be parsed.
pub fn split_pcap_by_count(data: &[u8], max_packets: usize) -> Result<Vec<Vec<u8>>, PcapError> {
    if max_packets == 0 {
        return Ok(Vec::new());
    }
    let reader = PcapReader::parse(data)?;
    let network = reader.global.network;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for chunk in reader.records.chunks(max_packets) {
        let mut writer = PcapFileWriter::new(network);
        for rec in chunk {
            writer.add_packet(rec.ts_sec, rec.ts_usec, &rec.data);
        }
        chunks.push(writer.finish());
    }
    Ok(chunks)
}

/// Split a PCAP file into time windows of `window_secs` seconds each.
///
/// # Errors
///
/// Returns [`PcapError`] if the input cannot be parsed.
pub fn split_pcap_by_time(data: &[u8], window_secs: u32) -> Result<Vec<Vec<u8>>, PcapError> {
    if window_secs == 0 {
        return Ok(Vec::new());
    }
    let reader = PcapReader::parse(data)?;
    if reader.records.is_empty() {
        return Ok(Vec::new());
    }
    let network = reader.global.network;
    let mut windows: std::collections::HashMap<u32, Vec<&PcapFileRecord>> =
        std::collections::HashMap::new();
    for rec in &reader.records {
        let bucket = rec.ts_sec / window_secs;
        windows.entry(bucket).or_default().push(rec);
    }

    let mut buckets: Vec<u32> = windows.keys().copied().collect();
    buckets.sort_unstable();

    let mut result = Vec::new();
    for bucket in buckets {
        let recs = &windows[&bucket];
        let mut writer = PcapFileWriter::new(network);
        for rec in recs {
            writer.add_packet(rec.ts_sec, rec.ts_usec, &rec.data);
        }
        result.push(writer.finish());
    }
    Ok(result)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP flow reconstructor
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A reconstructed TCP/UDP flow from a PCAP file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedFlow {
    pub key: FiveTuple,
    pub packets: Vec<Vec<u8>>,
    pub payloads: Vec<Vec<u8>>,
    pub timestamps: Vec<f64>,
}

impl ReconstructedFlow {
    /// Return the combined payload (all payloads concatenated).
    #[must_use]
    pub fn combined_payload(&self) -> Vec<u8> {
        self.payloads
            .iter()
            .flat_map(|p| p.iter().copied())
            .collect()
    }

    /// Return the number of packets in this flow.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }
}

/// Reconstruct application-layer flows from PCAP records.
/// Only supports IPv4/TCP and IPv4/UDP.
#[must_use]
pub fn reconstruct_flows(records: &[PcapFileRecord]) -> Vec<ReconstructedFlow> {
    use std::collections::HashMap;
    let mut flow_map: HashMap<FiveTuple, ReconstructedFlow> = HashMap::new();

    for rec in records {
        let data = &rec.data;
        if data.len() < 34 {
            continue;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            continue;
        }

        let ip_proto = data[23];
        let src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
        let dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
        let ihl = ((data[14] & 0x0F) as usize) * 4;

        if ip_proto == 6 || ip_proto == 17 {
            if data.len() < 14 + ihl + 4 {
                continue;
            }
            let sp = u16::from_be_bytes([data[14 + ihl], data[14 + ihl + 1]]);
            let dp = u16::from_be_bytes([data[14 + ihl + 2], data[14 + ihl + 3]]);
            let payload = if ip_proto == 6 {
                let data_off = ((data[14 + ihl + 12] >> 4) as usize) * 4;
                if 14 + ihl + data_off < data.len() {
                    data[14 + ihl + data_off..].to_vec()
                } else {
                    vec![]
                }
            } else {
                // UDP: header is 8 bytes
                if 14 + ihl + 8 < data.len() {
                    data[14 + ihl + 8..].to_vec()
                } else {
                    vec![]
                }
            };

            let key = FiveTuple::canonical(&src_ip, &dst_ip, sp, dp, ip_proto);
            let ts = f64::from(rec.ts_sec) + f64::from(rec.ts_usec) / 1_000_000.0;

            let flow = flow_map
                .entry(key.clone())
                .or_insert_with(|| ReconstructedFlow {
                    key,
                    packets: Vec::new(),
                    payloads: Vec::new(),
                    timestamps: Vec::new(),
                });
            flow.packets.push(data.clone());
            flow.payloads.push(payload);
            flow.timestamps.push(ts);
        }
    }

    flow_map.into_values().collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_pcap(records: &[(&[u8], u32, u32)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        for (data, ts_sec, ts_usec) in records {
            let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_usec.to_le_bytes());
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn parse_pcap_empty() {
        let buf = make_pcap(&[]);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert!(reader.is_empty());
        assert_eq!(reader.header.linktype, LinkType::Ethernet);
    }

    #[test]
    fn parse_pcap_one_record() {
        let pkt = [0xFFu8; 14];
        let buf = make_pcap(&[(&pkt, 1000, 500)]);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert_eq!(reader.len(), 1);
        let rec = &reader.records[0];
        assert_eq!(rec.ts_sec, 1000);
        assert_eq!(rec.ts_usec, 500);
        assert_eq!(rec.orig_len, 14);
        assert_eq!(rec.data, pkt);
    }

    #[test]
    fn parse_pcap_multiple_records() {
        let pkt1 = vec![0u8; 60];
        let pkt2 = vec![1u8; 100];
        let pkt3 = vec![2u8; 20];
        let buf = make_pcap(&[(&pkt1, 1, 0), (&pkt2, 2, 0), (&pkt3, 3, 0)]);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert_eq!(reader.len(), 3);
    }

    #[test]
    fn parse_pcap_invalid_magic() {
        let mut buf = make_pcap(&[]);
        buf[0] = 0xFF;
        assert!(matches!(
            MemoryPcapReader::from_bytes(&buf),
            Err(PcapError::InvalidMagic(_))
        ));
    }

    #[test]
    fn pcap_record_display() {
        let rec = PcapRecord {
            ts_sec: 100,
            ts_usec: 200,
            orig_len: 50,
            data: vec![0u8; 50],
        };
        let s = rec.to_string();
        assert!(s.contains("ts=100"));
    }

    #[test]
    fn pcap_writer_roundtrip() {
        let mut buf = Vec::new();
        {
            let mut writer =
                StreamPcapWriter::new(Cursor::new(&mut buf), 65535, LinkType::Ethernet).unwrap();
            writer
                .write_packet(1, 1000, &[0xDE, 0xAD, 0xBE, 0xEF])
                .unwrap();
            writer.write_packet(2, 2000, &[0xCA, 0xFE]).unwrap();
            assert_eq!(writer.record_count(), 2);
            assert_eq!(writer.linktype(), LinkType::Ethernet);
        }
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert_eq!(reader.len(), 2);
        assert_eq!(reader.records[0].data, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(reader.records[1].data, [0xCA, 0xFE]);
    }

    #[test]
    fn pcap_writer_snaplen_truncation() {
        let mut buf = Vec::new();
        {
            let mut writer =
                StreamPcapWriter::new(Cursor::new(&mut buf), 4, LinkType::Ethernet).unwrap();
            writer
                .write_packet(0, 0, &[1, 2, 3, 4, 5, 6, 7, 8])
                .unwrap();
        }
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert_eq!(reader.records[0].data.len(), 4);
        assert_eq!(reader.records[0].orig_len, 8);
    }

    #[test]
    fn link_type_roundtrip() {
        for lt in [
            LinkType::Null,
            LinkType::Ethernet,
            LinkType::Raw,
            LinkType::LinuxSll,
            LinkType::Ieee80211,
        ] {
            assert_eq!(LinkType::from_u16(lt.as_u16()), lt);
        }
    }

    #[test]
    fn link_type_unknown() {
        let lt = LinkType::from_u16(9999);
        assert_eq!(lt, LinkType::Unknown(9999));
        assert_eq!(lt.as_u16(), 9999);
    }

    #[test]
    fn link_type_display() {
        assert!(LinkType::Ethernet.to_string().contains("Ethernet"));
    }

    fn make_pcapng_shb() -> Vec<u8> {
        let body: &[u8] = &[
            0x4D, 0x3C, 0x2B, 0x1A, // BOM LE
            0x01, 0x00, // major=1
            0x00, 0x00, // minor=0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section_length=-1
        ];
        let total = 12u32 + u32::try_from(body.len()).unwrap_or(u32::MAX);
        let block_len = total.to_le_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&BLOCK_TYPE_SHB.to_le_bytes());
        buf.extend_from_slice(&block_len);
        buf.extend_from_slice(body);
        buf.extend_from_slice(&block_len);
        buf
    }

    fn make_pcapng_idb() -> Vec<u8> {
        let body: &[u8] = &[
            0x01, 0x00, // link_type=Ethernet
            0x00, 0x00, // reserved
            0xFF, 0xFF, 0x00, 0x00, // snaplen
        ];
        let total = 12u32 + u32::try_from(body.len()).unwrap_or(u32::MAX);
        let block_len = total.to_le_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&BLOCK_TYPE_IDB.to_le_bytes());
        buf.extend_from_slice(&block_len);
        buf.extend_from_slice(body);
        buf.extend_from_slice(&block_len);
        buf
    }

    fn make_pcapng_epb(pkt: &[u8]) -> Vec<u8> {
        let cap_len = u32::try_from(pkt.len()).unwrap_or(u32::MAX);
        let aligned = (pkt.len() + 3) & !3;
        let body_len = 20 + aligned;
        let total = 12u32 + u32::try_from(body_len).unwrap_or(u32::MAX);
        let block_len = total.to_le_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&BLOCK_TYPE_EPB.to_le_bytes());
        buf.extend_from_slice(&block_len);
        buf.extend_from_slice(&0u32.to_le_bytes()); // interface_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        buf.extend_from_slice(&1000u32.to_le_bytes()); // ts_low
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes()); // orig_len
        buf.extend_from_slice(pkt);
        buf.resize(buf.len() + aligned - pkt.len(), 0);
        buf.extend_from_slice(&block_len);
        buf
    }

    #[test]
    fn parse_pcapng_shb_only() {
        let data = make_pcapng_shb();
        let reader = PcapNgReader::from_bytes(&data).unwrap();
        assert_eq!(reader.len(), 1);
        assert!(matches!(reader.blocks[0], PcapNgBlock::SectionHeader(_)));
    }

    #[test]
    fn parse_pcapng_with_idb_and_epb() {
        let mut data = make_pcapng_shb();
        data.extend_from_slice(&make_pcapng_idb());
        data.extend_from_slice(&make_pcapng_epb(&[0xDE, 0xAD, 0xBE, 0xEF]));

        let reader = PcapNgReader::from_bytes(&data).unwrap();
        assert_eq!(reader.len(), 3);
        let epbs = reader.enhanced_packets();
        assert_eq!(epbs.len(), 1);
        assert_eq!(epbs[0].data, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(epbs[0].timestamp(), 1000);
        let idbs = reader.interfaces();
        assert_eq!(idbs.len(), 1);
        assert_eq!(idbs[0].link_type, LinkType::Ethernet);
    }

    #[test]
    fn pcapng_reader_not_empty_after_parse() {
        let data = make_pcapng_shb();
        let reader = PcapNgReader::from_bytes(&data).unwrap();
        assert!(!reader.is_empty());
    }

    #[test]
    fn parse_pcapng_invalid_no_shb() {
        let data = make_pcapng_idb();
        assert!(PcapNgReader::from_bytes(&data).is_err());
    }

    #[test]
    fn pcap_nanosecond_magic() {
        let mut buf = make_pcap(&[]);
        let nano = PCAP_MAGIC_LE_NANO.to_le_bytes();
        buf[0..4].copy_from_slice(&nano);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert!(reader.header.nanosecond_ts);
    }

    #[test]
    fn pcap_header_little_endian_flag() {
        let buf = make_pcap(&[]);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert!(reader.header.little_endian);
    }

    #[test]
    fn pcap_iter() {
        let pkt = [0xABu8; 10];
        let buf = make_pcap(&[(&pkt, 0, 0), (&pkt, 1, 0)]);
        let reader = MemoryPcapReader::from_bytes(&buf).unwrap();
        assert_eq!(reader.iter().count(), 2);
    }

    // â"€â"€ New spec-required types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pcap_writer_and_reader_roundtrip() {
        let mut writer = PcapWriter::new(1); // network=1 = Ethernet
        assert_eq!(writer.network(), 1);
        writer.add_packet(1000, 500, &[0xDE, 0xAD, 0xBE, 0xEF]);
        writer.add_packet(1001, 0, &[0xCA, 0xFE, 0xBA, 0xBE]);
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.global.network, 1);
        assert_eq!(reader.global.version_major, 2);
        assert_eq!(reader.global.version_minor, 4);
        assert_eq!(reader.records.len(), 2);
        assert_eq!(reader.records[0].ts_sec, 1000);
        assert_eq!(reader.records[0].ts_usec, 500);
        assert_eq!(reader.records[0].data, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(reader.records[0].incl_len, 4);
        assert_eq!(reader.records[0].orig_len, 4);
        assert_eq!(reader.records[1].data, [0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn pcap_reader_parse_invalid_magic() {
        let mut bytes = vec![0u8; 30];
        bytes[0] = 0xFF;
        assert!(matches!(
            PcapReader::parse(&bytes),
            Err(PcapError::InvalidMagic(_))
        ));
    }

    #[test]
    fn pcap_reader_parse_too_short() {
        let bytes = vec![0u8; 10];
        assert!(matches!(
            PcapReader::parse(&bytes),
            Err(PcapError::BufferTooShort {
                needed: 24,
                got: 10
            })
        ));
    }

    #[test]
    fn pcap_reader_iter_count() {
        let mut writer = PcapWriter::new(1);
        writer.add_packet(0, 0, &[1, 2, 3]);
        writer.add_packet(1, 0, &[4, 5, 6]);
        writer.add_packet(2, 0, &[7, 8, 9]);
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.iter().count(), 3);
    }

    #[test]
    fn pcap_file_record_incl_len_field() {
        let mut writer = PcapWriter::new(0);
        writer.add_packet(5, 10, &[0xAA, 0xBB, 0xCC]);
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        let rec = &reader.records[0];
        assert_eq!(rec.ts_sec, 5);
        assert_eq!(rec.ts_usec, 10);
        assert_eq!(rec.incl_len, 3);
        assert_eq!(rec.orig_len, 3);
    }

    #[test]
    fn pcap_writer_empty_finish() {
        let writer = PcapWriter::new(1);
        let bytes = writer.finish();
        // Should at minimum have the 24-byte global header
        assert!(bytes.len() >= 24);
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.records.len(), 0);
    }

    #[test]
    fn pcap_file_header_fields() {
        let mut writer = PcapWriter::new(113); // network=113 = LinuxSLL
        writer.add_packet(0, 0, &[]);
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.global.network, 113);
        assert_eq!(reader.global.sigfigs, 0);
    }

    #[test]
    fn pcap_writer_large_network_code() {
        let mut writer = PcapWriter::new(0xDEAD_BEEF);
        writer.add_packet(0, 0, &[1]);
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.global.network, 0xDEAD_BEEF);
    }

    #[test]
    fn pcap_reader_multiple_packets() {
        let mut writer = PcapWriter::new(1);
        for i in 0..10u32 {
            writer.add_packet(i, i * 1000, &[u8::try_from(i).unwrap_or(u8::MAX); 10]);
        }
        let bytes = writer.finish();
        let reader = PcapReader::parse(&bytes).unwrap();
        assert_eq!(reader.records.len(), 10);
        for (i, rec) in reader.iter().enumerate() {
            assert_eq!(rec.ts_sec, u32::try_from(i).unwrap_or(u32::MAX));
            assert_eq!(rec.data, vec![u8::try_from(i).unwrap_or(u8::MAX); 10]);
        }
    }

    // â"€â"€ Spec-required: PcapFile â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pcap_file_parse_and_iter() {
        let mut w = PcapWriter::new(1);
        w.add_packet(100, 200, &[0xAA, 0xBB]);
        w.add_packet(101, 300, &[0xCC, 0xDD, 0xEE]);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.record_count(), 2);
        let recs: Vec<_> = pf.iter_records().collect();
        assert_eq!(recs[0].ts_sec, 100);
        assert_eq!(recs[1].ts_sec, 101);
    }

    #[test]
    fn pcap_file_total_bytes() {
        let mut w = PcapWriter::new(1);
        w.add_packet(0, 0, &[1, 2, 3, 4]);
        w.add_packet(1, 0, &[5, 6]);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.total_bytes(), 6);
    }

    #[test]
    fn pcap_file_empty() {
        let w = PcapWriter::new(0);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.record_count(), 0);
        assert_eq!(pf.total_bytes(), 0);
        assert_eq!(pf.iter_records().count(), 0);
    }

    #[test]
    fn pcap_file_header_network() {
        let w = PcapWriter::new(113);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.header.network, 113);
    }

    // â"€â"€ Spec-required: PcapWriter (in-memory) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pcap_writer_new_and_to_bytes() {
        let mut w = PcapWriter::new(1);
        w.add_packet(10, 20, &[0xDE, 0xAD]);
        let bytes = w.to_bytes();
        assert!(bytes.len() >= 24 + 16 + 2);
        // Verify it parses
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.record_count(), 1);
        assert_eq!(pf.records[0].data, [0xDE, 0xAD]);
    }

    #[test]
    fn pcap_writer_roundtrip_write_parse() {
        let mut w = PcapWriter::new(1);
        w.add_packet(1, 0, &[1]);
        w.add_packet(2, 0, &[2]);
        w.add_packet(3, 0, &[3]);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        assert_eq!(pf.record_count(), 3);
        for (i, rec) in pf.iter_records().enumerate() {
            assert_eq!(rec.ts_sec, u32::try_from(i + 1).unwrap_or(u32::MAX));
            assert_eq!(rec.data[0], u8::try_from(i + 1).unwrap_or(u8::MAX));
        }
    }

    #[test]
    fn pcap_writer_is_empty() {
        let w = PcapWriter::new(0);
        assert!(w.is_empty());
        let mut w2 = PcapWriter::new(1);
        w2.add_packet(0, 0, &[]);
        assert!(!w2.is_empty());
    }

    #[test]
    fn pcap_writer_network_accessor() {
        let w = PcapWriter::new(0xDEAD_BEEF);
        assert_eq!(w.network(), 0xDEAD_BEEF);
    }

    #[test]
    fn pcap_file_invalid_magic() {
        let bytes = vec![
            0xFF, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(PcapFile::parse(&bytes).is_err());
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP anonymization
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Anonymization options controlling which fields are replaced.
#[derive(Debug, Clone)]
pub struct AnonymizeOptions {
    /// Replace IPv4 source and destination addresses with 0.0.0.0.
    pub zero_ipv4_addrs: bool,
    /// Replace MAC addresses with 00:00:00:00:00:00.
    pub zero_mac_addrs: bool,
    /// Truncate TCP/UDP payloads to zero length.
    pub zero_payloads: bool,
}

impl Default for AnonymizeOptions {
    fn default() -> Self {
        Self {
            zero_ipv4_addrs: true,
            zero_mac_addrs: false,
            zero_payloads: false,
        }
    }
}

/// Anonymize a slice of PCAP records in-place according to the given options.
///
/// Only Ethernet frames carrying IPv4 are processed; other frames are left
/// unchanged.
#[must_use]
pub fn anonymize_records(
    records: Vec<PcapFileRecord>,
    opts: &AnonymizeOptions,
) -> Vec<PcapFileRecord> {
    records
        .into_iter()
        .map(|mut rec| {
            let data = &mut rec.data;
            if data.len() >= 14 {
                if opts.zero_mac_addrs {
                    // dst MAC bytes 0..6, src MAC bytes 6..12
                    for __item in data.iter_mut().take(12) {
                        (*__item) = 0;
                    }
                }
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                if ethertype == 0x0800 && data.len() >= 34 {
                    if opts.zero_ipv4_addrs {
                        // src at 26..30, dst at 30..34
                        for i in 26..34 {
                            data[i] = 0;
                        }
                    }
                    if opts.zero_payloads {
                        let ihl = ((data[14] & 0x0F) as usize) * 4;
                        let ip_proto = data[23];
                        let transport_start = 14 + ihl;
                        let payload_start = if ip_proto == 6 && data.len() > transport_start + 12 {
                            let data_offset = ((data[transport_start + 12] >> 4) as usize) * 4;
                            transport_start + data_offset
                        } else if ip_proto == 17 {
                            transport_start + 8
                        } else {
                            data.len()
                        };
                        if payload_start < data.len() {
                            for b in &mut data[payload_start..] {
                                *b = 0;
                            }
                        }
                    }
                }
            }
            rec
        })
        .collect()
}

/// Anonymize an entire PCAP file (given as bytes) and return the new bytes.
///
/// # Errors
///
/// Returns [`PcapError`] if the input cannot be parsed.
pub fn anonymize_pcap(data: &[u8], opts: &AnonymizeOptions) -> Result<Vec<u8>, PcapError> {
    let reader = PcapReader::parse(data)?;
    let network = reader.global.network;
    let anon_records = anonymize_records(reader.records, opts);
    let mut writer = PcapFileWriter::new(network);
    for rec in &anon_records {
        writer.add_packet(rec.ts_sec, rec.ts_usec, &rec.data);
    }
    Ok(writer.finish())
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG writer: Interface Statistics Block (ISB)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

const BLOCK_TYPE_ISB: u32 = 0x0000_0005;

/// A PCAPNG interface statistics block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatisticsBlock {
    pub interface_id: u32,
    pub timestamp_high: u32,
    pub timestamp_low: u32,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl InterfaceStatisticsBlock {
    /// Combined 64-bit timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        u64::from(self.timestamp_high) << 32 | u64::from(self.timestamp_low)
    }

    /// Serialize to bytes for embedding in a PCAPNG stream.
    #[must_use]
    pub fn to_block_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.interface_id.to_le_bytes());
        body.extend_from_slice(&self.timestamp_high.to_le_bytes());
        body.extend_from_slice(&self.timestamp_low.to_le_bytes());
        let mut out = Vec::new();
        write_pcapng_block(&mut out, BLOCK_TYPE_ISB, &body);
        out
    }
}

/// Extended PCAPNG writer that supports ISB blocks.
pub struct PcapNgWriterExt {
    inner: PcapNgWriter,
    isb_blocks: Vec<InterfaceStatisticsBlock>,
}

impl PcapNgWriterExt {
    /// Create a new extended writer.
    #[must_use]
    pub const fn new(link_type: LinkType) -> Self {
        Self {
            inner: PcapNgWriter::new(link_type),
            isb_blocks: Vec::new(),
        }
    }

    /// Add a packet.
    pub fn add_packet(&mut self, timestamp_us: u64, data: &[u8]) {
        self.inner.add_packet(timestamp_us, data);
    }

    /// Add an interface statistics block.
    pub fn add_isb(&mut self, isb: InterfaceStatisticsBlock) {
        self.isb_blocks.push(isb);
    }

    /// Return the number of packets.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.inner.packet_count()
    }

    /// Serialize to PCAPNG bytes (with ISB blocks appended).
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        let mut buf = self.inner.finish();
        for isb in &self.isb_blocks {
            buf.extend_from_slice(&isb.to_block_bytes());
        }
        buf
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Protocol histogram
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Frequency count of protocols found in a PCAP file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolHistogram {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub arp: u64,
    pub ipv6: u64,
    pub other: u64,
}

impl ProtocolHistogram {
    /// Build a histogram from PCAP records.
    #[must_use]
    pub fn from_records(records: &[PcapFileRecord]) -> Self {
        let mut h = Self::default();
        for rec in records {
            let data = &rec.data;
            if data.len() < 14 {
                h.other += 1;
                continue;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            match et {
                0x0800 if data.len() >= 24 => match data[23] {
                    6 => h.tcp += 1,
                    17 => h.udp += 1,
                    1 => h.icmp += 1,
                    _ => h.other += 1,
                },
                0x0806 => h.arp += 1,
                0x86DD => h.ipv6 += 1,
                _ => h.other += 1,
            }
        }
        h
    }

    /// Total packets.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.tcp + self.udp + self.icmp + self.arp + self.ipv6 + self.other
    }

    /// TCP fraction (0.0–1.0).
    #[must_use]
    pub fn tcp_fraction(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            0.0
        } else {
            self.tcp as f64 / t as f64
        }
    }
}

impl fmt::Display for ProtocolHistogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tcp={} udp={} icmp={} arp={} ipv6={} other={}",
            self.tcp, self.udp, self.icmp, self.arp, self.ipv6, self.other
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Port histogram
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Frequency count of TCP/UDP destination ports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortHistogram {
    pub counts: std::collections::HashMap<u16, u64>,
}

impl PortHistogram {
    /// Build a histogram from PCAP records.
    #[must_use]
    pub fn from_records(records: &[PcapFileRecord]) -> Self {
        let mut h = Self::default();
        for rec in records {
            let data = &rec.data;
            if data.len() < 38 {
                continue;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            if et != 0x0800 {
                continue;
            }
            let proto = data[23];
            if proto != 6 && proto != 17 {
                continue;
            }
            let dp = u16::from_be_bytes([data[36], data[37]]);
            *h.counts.entry(dp).or_insert(0) += 1;
        }
        h
    }

    /// Return the top N ports by count.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u16, u64)> {
        let mut v: Vec<(u16, u64)> = self.counts.iter().map(|(&p, &c)| (p, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Total packets counted.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP packet filter pipeline
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A chainable packet filter.
pub trait PacketFilter: Send + Sync {
    /// Returns `true` if the packet should be kept.
    fn accept(&self, rec: &PcapFileRecord) -> bool;
}

/// A filter that accepts packets whose data length is within [min, max].
pub struct LengthFilter {
    min: usize,
    max: usize,
}

impl LengthFilter {
    /// Create a length filter.
    #[must_use]
    pub const fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }
}

impl PacketFilter for LengthFilter {
    fn accept(&self, rec: &PcapFileRecord) -> bool {
        let len = rec.data.len();
        len >= self.min && len <= self.max
    }
}

/// A filter that accepts only packets with a given Ethernet ethertype.
pub struct EtherTypeFilter {
    ethertype: u16,
}

impl EtherTypeFilter {
    /// Create an ethertype filter.
    #[must_use]
    pub const fn new(ethertype: u16) -> Self {
        Self { ethertype }
    }
}

impl PacketFilter for EtherTypeFilter {
    fn accept(&self, rec: &PcapFileRecord) -> bool {
        if rec.data.len() < 14 {
            return false;
        }
        u16::from_be_bytes([rec.data[12], rec.data[13]]) == self.ethertype
    }
}

/// A filter that accepts packets only within a given timestamp range.
pub struct TimeRangeFilter {
    start_sec: u32,
    end_sec: u32,
}

impl TimeRangeFilter {
    /// Create a timestamp range filter.
    #[must_use]
    pub const fn new(start_sec: u32, end_sec: u32) -> Self {
        Self { start_sec, end_sec }
    }
}

impl PacketFilter for TimeRangeFilter {
    fn accept(&self, rec: &PcapFileRecord) -> bool {
        rec.ts_sec >= self.start_sec && rec.ts_sec <= self.end_sec
    }
}

/// A filter that accepts only IPv4 packets with a given IP protocol.
pub struct IpProtoFilter {
    proto: u8,
}

impl IpProtoFilter {
    /// Create an IP protocol filter.
    #[must_use]
    pub const fn new(proto: u8) -> Self {
        Self { proto }
    }
}

impl PacketFilter for IpProtoFilter {
    fn accept(&self, rec: &PcapFileRecord) -> bool {
        if rec.data.len() < 24 {
            return false;
        }
        let et = u16::from_be_bytes([rec.data[12], rec.data[13]]);
        et == 0x0800 && rec.data[23] == self.proto
    }
}

/// Apply a chain of filters to a set of records.
#[must_use]
pub fn apply_filters<'a>(
    records: &'a [PcapFileRecord],
    filters: &[Box<dyn PacketFilter>],
) -> Vec<&'a PcapFileRecord> {
    records
        .iter()
        .filter(|r| filters.iter().all(|f| f.accept(r)))
        .collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Additional tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn make_pcap_eth_ipv4_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let ihl: usize = 20;
        let total_ip = ihl + 20 + payload.len();
        let mut frame = Vec::with_capacity(14 + total_ip);
        // Ethernet header (dst mac, src mac, ethertype)
        frame.extend_from_slice(&[0u8; 6]); // dst mac
        frame.extend_from_slice(&[0u8; 6]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header
        frame.push(0x45); // version=4, ihl=5
        frame.push(0x00); // dscp/ecn
        frame.extend_from_slice(&u16::try_from(total_ip).unwrap_or(u16::MAX).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01]); // id
        frame.extend_from_slice(&[0x00, 0x00]); // flags+offset
        frame.push(64); // ttl
        frame.push(6); // proto=TCP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        // TCP header
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        frame.push(0x50); // data offset = 5 (20 bytes)
        frame.push(0x18); // PSH + ACK
        frame.extend_from_slice(&[0xFF, 0xFF]); // window
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&[0x00, 0x00]); // urgent
        // payload
        frame.extend_from_slice(payload);
        frame
    }

    fn make_test_pcap() -> Vec<u8> {
        let f1 =
            make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"GET / HTTP/1.1\r\n");
        let f2 =
            make_pcap_eth_ipv4_tcp([5, 6, 7, 8], [1, 2, 3, 4], 80, 1234, b"HTTP/1.1 200 OK\r\n");
        let mut w = PcapWriter::new(1);
        w.add_packet(1000, 0, &f1);
        w.add_packet(1001, 0, &f2);
        w.to_bytes()
    }

    // â"€â"€ PcapStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pcap_stats_basic() {
        let mut w = PcapWriter::new(1);
        w.add_packet(1000, 0, &[0u8; 60]);
        w.add_packet(1001, 500_000, &[0u8; 100]);
        w.add_packet(1002, 0, &[0u8; 40]);
        let bytes = w.to_bytes();
        let f = PcapFile::parse(&bytes).unwrap();
        let stats = PcapStats::from_file(&f);
        assert_eq!(stats.packet_count, 3);
        assert_eq!(stats.total_bytes, 200);
        assert_eq!(stats.min_pkt_size, 40);
        assert_eq!(stats.max_pkt_size, 100);
        assert!((stats.avg_pkt_size - 200.0 / 3.0).abs() < 0.01);
        assert_eq!(stats.truncated, 0);
        let s = stats.to_string();
        assert!(s.contains("3 pkts"));
    }

    #[test]
    fn pcap_stats_empty() {
        let stats = PcapStats::compute(&[]);
        assert_eq!(stats.packet_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert!((stats.duration_secs - 0.0).abs() < f64::EPSILON);
    }

    // â"€â"€ PacketSummary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn summarize_tcp_packet() {
        let frame = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 12345, 80, b"hello");
        let rec = PcapFileRecord {
            ts_sec: 100,
            ts_usec: 200,
            incl_len: u32::try_from(frame.len()).unwrap_or(u32::MAX),
            orig_len: u32::try_from(frame.len()).unwrap_or(u32::MAX),
            data: frame,
        };
        let summary = summarize_packet(0, &rec);
        assert_eq!(summary.protocol, "TCP");
        assert!(summary.src.contains("1.2.3.4"));
        assert!(summary.dst.contains("5.6.7.8"));
        assert!(!summary.truncated);
        let s = summary.to_string();
        assert!(s.contains("TCP"));
    }

    #[test]
    fn summarize_unknown_packet() {
        let frame = vec![0u8; 5]; // too short
        let rec = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: 5,
            orig_len: 5,
            data: frame,
        };
        let summary = summarize_packet(0, &rec);
        assert_eq!(summary.protocol, "Unknown");
    }

    // â"€â"€ FiveTuple â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn five_tuple_canonical() {
        let a = FiveTuple::canonical("1.2.3.4", "5.6.7.8", 1234, 80, 6);
        let b = FiveTuple::canonical("5.6.7.8", "1.2.3.4", 80, 1234, 6);
        assert_eq!(a, b);
        let s = a.to_string();
        assert!(s.contains("1234") || s.contains("80"));
    }

    // â"€â"€ extract_connections â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn extract_connections_basic() {
        let bytes = make_test_pcap();
        let f = PcapFile::parse(&bytes).unwrap();
        let conns = extract_connections(&f.records);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].packet_count, 2);
        assert!(conns[0].total_bytes > 0);
    }

    #[test]
    fn extract_connections_empty() {
        let conns = extract_connections(&[]);
        assert!(conns.is_empty());
    }

    // â"€â"€ ReconstructedFlow â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn reconstruct_flows_basic() {
        let bytes = make_test_pcap();
        let f = PcapFile::parse(&bytes).unwrap();
        let flows = reconstruct_flows(&f.records);
        assert!(!flows.is_empty());
        let combined = flows[0].combined_payload();
        // Payload: GET + HTTP response
        assert!(!combined.is_empty());
        assert!(flows[0].packet_count() > 0);
    }

    // â"€â"€ merge / split â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn merge_pcap_files_two() {
        let mut w1 = PcapWriter::new(1);
        w1.add_packet(100, 0, &[1, 2, 3]);
        let mut w2 = PcapWriter::new(1);
        w2.add_packet(50, 0, &[4, 5, 6]);
        let b1 = w1.to_bytes();
        let b2 = w2.to_bytes();
        let merged = merge_pcap_files(&[&b1, &b2]).unwrap();
        let reader = PcapReader::parse(&merged).unwrap();
        assert_eq!(reader.records.len(), 2);
        // Should be sorted by timestamp: pkt at ts=50 first
        assert_eq!(reader.records[0].ts_sec, 50);
        assert_eq!(reader.records[1].ts_sec, 100);
    }

    #[test]
    fn split_pcap_by_count_basic() {
        let mut w = PcapWriter::new(1);
        for i in 0..5u32 {
            w.add_packet(i, 0, &[u8::try_from(i).unwrap_or(u8::MAX)]);
        }
        let bytes = w.to_bytes();
        let chunks = split_pcap_by_count(&bytes, 2).unwrap();
        assert_eq!(chunks.len(), 3); // 2+2+1
        let c0 = PcapReader::parse(&chunks[0]).unwrap();
        assert_eq!(c0.records.len(), 2);
        let c2 = PcapReader::parse(&chunks[2]).unwrap();
        assert_eq!(c2.records.len(), 1);
    }

    #[test]
    fn split_pcap_by_count_zero_returns_empty() {
        let mut w = PcapWriter::new(1);
        w.add_packet(0, 0, &[0]);
        let bytes = w.to_bytes();
        let chunks = split_pcap_by_count(&bytes, 0).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn split_pcap_by_time_basic() {
        let mut w = PcapWriter::new(1);
        w.add_packet(0, 0, &[1]);
        w.add_packet(5, 0, &[2]);
        w.add_packet(15, 0, &[3]);
        let bytes = w.to_bytes();
        let chunks = split_pcap_by_time(&bytes, 10).unwrap();
        assert_eq!(chunks.len(), 2); // window[0]: ts=0,5 | window[1]: ts=15
        let c0 = PcapReader::parse(&chunks[0]).unwrap();
        assert_eq!(c0.records.len(), 2);
    }

    // â"€â"€ anonymize â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn anonymize_pcap_ipv4_addrs() {
        let frame = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"secret data");
        let mut w = PcapWriter::new(1);
        w.add_packet(0, 0, &frame);
        let bytes = w.to_bytes();

        let opts = AnonymizeOptions {
            zero_ipv4_addrs: true,
            zero_mac_addrs: false,
            zero_payloads: false,
        };
        let anon = anonymize_pcap(&bytes, &opts).unwrap();
        let r = PcapReader::parse(&anon).unwrap();
        let data = &r.records[0].data;
        // IPv4 src (offset 26) and dst (offset 30) should be zeroed
        assert_eq!(&data[26..30], &[0, 0, 0, 0]);
        assert_eq!(&data[30..34], &[0, 0, 0, 0]);
        // Payload should still be present
        assert!(data.len() > 54);
    }

    #[test]
    fn anonymize_pcap_mac_addrs() {
        let frame = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"test");
        let mut w = PcapWriter::new(1);
        w.add_packet(0, 0, &frame);
        let bytes = w.to_bytes();

        let opts = AnonymizeOptions {
            zero_ipv4_addrs: false,
            zero_mac_addrs: true,
            zero_payloads: false,
        };
        let anon = anonymize_pcap(&bytes, &opts).unwrap();
        let r = PcapReader::parse(&anon).unwrap();
        let data = &r.records[0].data;
        // MAC bytes 0..12 should be zeroed
        assert_eq!(&data[0..12], &[0u8; 12]);
        // IPv4 addrs should be unchanged
        assert_eq!(&data[26..30], &[1, 2, 3, 4]);
    }

    // â"€â"€ ProtocolHistogram â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn protocol_histogram_basic() {
        let tcp_frame = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"");
        let udp_frame = {
            let mut f = tcp_frame.clone();
            f[23] = 17; // change proto to UDP
            f
        };
        let records = vec![
            PcapFileRecord {
                ts_sec: 0,
                ts_usec: 0,
                incl_len: u32::try_from(tcp_frame.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(tcp_frame.len()).unwrap_or(u32::MAX),
                data: tcp_frame.clone(),
            },
            PcapFileRecord {
                ts_sec: 1,
                ts_usec: 0,
                incl_len: u32::try_from(tcp_frame.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(tcp_frame.len()).unwrap_or(u32::MAX),
                data: tcp_frame,
            },
            PcapFileRecord {
                ts_sec: 2,
                ts_usec: 0,
                incl_len: u32::try_from(udp_frame.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(udp_frame.len()).unwrap_or(u32::MAX),
                data: udp_frame,
            },
        ];
        let h = ProtocolHistogram::from_records(&records);
        assert_eq!(h.tcp, 2);
        assert_eq!(h.udp, 1);
        assert_eq!(h.total(), 3);
        assert!((h.tcp_fraction() - 2.0 / 3.0).abs() < 0.001);
        let s = h.to_string();
        assert!(s.contains("tcp=2"));
    }

    #[test]
    fn protocol_histogram_empty() {
        let h = ProtocolHistogram::from_records(&[]);
        assert_eq!(h.total(), 0);
        assert!((h.tcp_fraction() - 0.0).abs() < f64::EPSILON);
    }

    // â"€â"€ PortHistogram â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn port_histogram_top_n() {
        let mut records = Vec::new();
        for _ in 0..5 {
            let f = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"");
            records.push(PcapFileRecord {
                ts_sec: 0,
                ts_usec: 0,
                incl_len: u32::try_from(f.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(f.len()).unwrap_or(u32::MAX),
                data: f,
            });
        }
        for _ in 0..3 {
            let f = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 443, b"");
            records.push(PcapFileRecord {
                ts_sec: 0,
                ts_usec: 0,
                incl_len: u32::try_from(f.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(f.len()).unwrap_or(u32::MAX),
                data: f,
            });
        }
        let h = PortHistogram::from_records(&records);
        assert_eq!(h.total(), 8);
        let top = h.top_n(1);
        assert_eq!(top[0].0, 80); // port 80 has count 5
        assert_eq!(top[0].1, 5);
    }

    // â"€â"€ PacketFilter trait objects â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn length_filter_accept() {
        let f = LengthFilter::new(10, 100);
        let long = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: 200,
            orig_len: 200,
            data: vec![0u8; 200],
        };
        let ok = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: 50,
            orig_len: 50,
            data: vec![0u8; 50],
        };
        assert!(!f.accept(&long));
        assert!(f.accept(&ok));
    }

    #[test]
    fn ethertype_filter_ipv4() {
        let f = EtherTypeFilter::new(0x0800);
        let ipv4 = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 0, 0, b"");
        let rec = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: u32::try_from(ipv4.len()).unwrap_or(u32::MAX),
            orig_len: u32::try_from(ipv4.len()).unwrap_or(u32::MAX),
            data: ipv4,
        };
        assert!(f.accept(&rec));
        let other = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: 14,
            orig_len: 14,
            data: vec![0u8; 14],
        };
        assert!(!f.accept(&other));
    }

    #[test]
    fn time_range_filter() {
        let f = TimeRangeFilter::new(100, 200);
        let in_range = PcapFileRecord {
            ts_sec: 150,
            ts_usec: 0,
            incl_len: 0,
            orig_len: 0,
            data: vec![],
        };
        let before = PcapFileRecord {
            ts_sec: 50,
            ts_usec: 0,
            incl_len: 0,
            orig_len: 0,
            data: vec![],
        };
        let after = PcapFileRecord {
            ts_sec: 250,
            ts_usec: 0,
            incl_len: 0,
            orig_len: 0,
            data: vec![],
        };
        assert!(f.accept(&in_range));
        assert!(!f.accept(&before));
        assert!(!f.accept(&after));
    }

    #[test]
    fn ip_proto_filter_tcp() {
        let f = IpProtoFilter::new(6);
        let tcp = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 0, 0, b"");
        let rec = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: u32::try_from(tcp.len()).unwrap_or(u32::MAX),
            orig_len: u32::try_from(tcp.len()).unwrap_or(u32::MAX),
            data: tcp,
        };
        assert!(f.accept(&rec));
        let mut udp_rec = rec;
        udp_rec.data[23] = 17;
        assert!(!f.accept(&udp_rec));
    }

    #[test]
    fn apply_filters_chain() {
        let f1 = make_pcap_eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80, b"");
        let f2 = make_pcap_eth_ipv4_tcp(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            1234,
            80,
            b"long payload data that exceeds 200 bytes".as_ref(),
        );
        let records = vec![
            PcapFileRecord {
                ts_sec: 100,
                ts_usec: 0,
                incl_len: u32::try_from(f1.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(f1.len()).unwrap_or(u32::MAX),
                data: f1,
            },
            PcapFileRecord {
                ts_sec: 500,
                ts_usec: 0,
                incl_len: u32::try_from(f2.len()).unwrap_or(u32::MAX),
                orig_len: u32::try_from(f2.len()).unwrap_or(u32::MAX),
                data: f2,
            },
        ];
        let filters: Vec<Box<dyn PacketFilter>> = vec![Box::new(TimeRangeFilter::new(0, 200))];
        let accepted = apply_filters(&records, &filters);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].ts_sec, 100);
    }

    // â"€â"€ BPF VM â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn bpf_vm_accept_all() {
        let vm = FilterExpr::All.compile();
        assert!(vm.accepts(&[1, 2, 3]));
        assert!(vm.accepts(&[]));
    }

    #[test]
    fn bpf_vm_reject_all() {
        let vm = FilterExpr::None.compile();
        assert!(!vm.accepts(&[1, 2, 3]));
    }

    #[test]
    fn bpf_vm_ethertype_filter() {
        let vm = FilterExpr::EtherType(0x0800).compile();
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        assert!(vm.accepts(&pkt));
        pkt[13] = 0x06; // ARP
        assert!(!vm.accepts(&pkt));
    }

    #[test]
    fn bpf_vm_tcp_filter() {
        let vm = FilterExpr::Tcp.compile();
        let mut pkt = vec![0u8; 24];
        pkt[12] = 0x08;
        pkt[13] = 0x00; // IPv4
        pkt[23] = 6; // TCP
        assert!(vm.accepts(&pkt));
        pkt[23] = 17; // UDP
        assert!(!vm.accepts(&pkt));
    }

    #[test]
    fn bpf_vm_dst_port() {
        let vm = FilterExpr::DstPort(80).compile();
        let mut pkt = vec![0u8; 38];
        pkt[36] = 0;
        pkt[37] = 80;
        assert!(vm.accepts(&pkt));
        pkt[36] = 1;
        pkt[37] = 187; // 0x01BB = 443
        assert!(!vm.accepts(&pkt));
    }

    #[test]
    fn bpf_not_filter() {
        let vm = FilterExpr::Not(Box::new(FilterExpr::EtherType(0x0800))).compile();
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        assert!(!vm.accepts(&pkt)); // NOT IPv4 â†' reject IPv4
        pkt[12] = 0x08;
        pkt[13] = 0x06;
        assert!(vm.accepts(&pkt)); // NOT IPv4 â†' accept ARP
    }

    // â"€â"€ PcapNgWriter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pcapng_writer_roundtrip() {
        let mut w = PcapNgWriter::new(LinkType::Ethernet);
        w.add_packet(1_000_000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        w.add_packet(2_000_000, &[0x01, 0x02]);
        assert_eq!(w.packet_count(), 2);
        let bytes = w.finish();

        let reader = PcapNgReader::from_bytes(&bytes).unwrap();
        let pkts = reader.enhanced_packets();
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].data, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(pkts[1].data, [0x01, 0x02]);
        assert_eq!(pkts[0].timestamp(), 1_000_000);
    }

    // â"€â"€ InterfaceStatisticsBlock â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn isb_timestamp() {
        let isb = InterfaceStatisticsBlock {
            interface_id: 0,
            timestamp_high: 1,
            timestamp_low: 0,
            options: vec![],
        };
        assert_eq!(isb.timestamp(), 1u64 << 32);
    }

    #[test]
    fn pcapng_writer_ext_with_isb() {
        let mut w = PcapNgWriterExt::new(LinkType::Ethernet);
        w.add_packet(1000, &[1, 2, 3]);
        w.add_isb(InterfaceStatisticsBlock {
            interface_id: 0,
            timestamp_high: 0,
            timestamp_low: 2000,
            options: vec![],
        });
        assert_eq!(w.packet_count(), 1);
        let bytes = w.finish();
        // Should parse as a valid PCAPNG (SHB + IDB + EPB + ISB)
        let reader = PcapNgReader::from_bytes(&bytes).unwrap();
        let pkts = reader.enhanced_packets();
        assert_eq!(pkts.len(), 1);
    }

    // â"€â"€ filter_pcap_records â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn filter_pcap_records_with_bpf() {
        let mut w = PcapWriter::new(1);
        let mut pkt_ipv4 = vec![0u8; 14];
        pkt_ipv4[12] = 0x08;
        pkt_ipv4[13] = 0x00;
        let pkt_other = vec![0u8; 14];
        w.add_packet(0, 0, &pkt_ipv4);
        w.add_packet(1, 0, &pkt_other);
        let bytes = w.to_bytes();
        let pf = PcapFile::parse(&bytes).unwrap();
        let vm = FilterExpr::Ipv4.compile();
        let accepted = filter_pcap_records(&pf.records, &vm);
        assert_eq!(accepted.len(), 1);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// IP address histogram
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Frequency count of IPv4 source and destination addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpHistogram {
    pub src_counts: std::collections::HashMap<[u8; 4], u64>,
    pub dst_counts: std::collections::HashMap<[u8; 4], u64>,
}

impl IpHistogram {
    /// Build from PCAP records (Ethernet/IPv4 only).
    #[must_use]
    pub fn from_records(records: &[PcapFileRecord]) -> Self {
        let mut h = Self::default();
        for rec in records {
            let data = &rec.data;
            if data.len() < 34 {
                continue;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            if et != 0x0800 {
                continue;
            }
            let src = [data[26], data[27], data[28], data[29]];
            let dst = [data[30], data[31], data[32], data[33]];
            *h.src_counts.entry(src).or_insert(0) += 1;
            *h.dst_counts.entry(dst).or_insert(0) += 1;
        }
        h
    }

    /// Top N source IPs by packet count.
    #[must_use]
    pub fn top_src(&self, n: usize) -> Vec<([u8; 4], u64)> {
        let mut v: Vec<_> = self.src_counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Top N destination IPs by packet count.
    #[must_use]
    pub fn top_dst(&self, n: usize) -> Vec<([u8; 4], u64)> {
        let mut v: Vec<_> = self.dst_counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Total number of IPv4 packets counted.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.src_counts.values().sum()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP time-series builder
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A bucket in a packet time-series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    /// Bucket start (Unix seconds).
    pub ts: u32,
    /// Packets in this bucket.
    pub packet_count: u64,
    /// Bytes in this bucket.
    pub byte_count: u64,
}

/// Build a time-series histogram over PCAP records with the given bucket width.
///
/// Returns buckets sorted by `ts`.  Empty buckets are omitted.
#[must_use]
pub fn build_time_series(records: &[PcapFileRecord], bucket_secs: u32) -> Vec<TimeBucket> {
    if bucket_secs == 0 {
        return Vec::new();
    }
    let mut map: std::collections::HashMap<u32, TimeBucket> = std::collections::HashMap::new();
    for rec in records {
        let key = rec.ts_sec / bucket_secs * bucket_secs;
        let entry = map.entry(key).or_insert(TimeBucket {
            ts: key,
            packet_count: 0,
            byte_count: 0,
        });
        entry.packet_count += 1;
        entry.byte_count += rec.data.len() as u64;
    }
    let mut v: Vec<TimeBucket> = map.into_values().collect();
    v.sort_by_key(|b| b.ts);
    v
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP duplicate detection
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Remove duplicate packet records from a list (same `ts_sec`, `ts_usec`, and data).
///
/// The first occurrence is kept; subsequent duplicates are dropped.
#[must_use]
pub fn dedup_records(records: Vec<PcapFileRecord>) -> Vec<PcapFileRecord> {
    use std::collections::HashSet;
    let mut seen: HashSet<(u32, u32, u64)> = HashSet::new();
    records
        .into_iter()
        .filter(|r| {
            // Use a quick hash of ts + first 8 bytes of data as dedup key
            let data_sig: u64 = r
                .data
                .iter()
                .take(8)
                .enumerate()
                .fold(0u64, |acc, (i, &b)| acc ^ (u64::from(b) << (i * 8)));
            let key = (r.ts_sec, r.ts_usec, data_sig);
            seen.insert(key)
        })
        .collect()
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP record sorting
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Sort PCAP records in ascending order of timestamp.
pub fn sort_records(records: &mut [PcapFileRecord]) {
    records.sort_by(|a, b| {
        a.ts_sec
            .cmp(&b.ts_sec)
            .then_with(|| a.ts_usec.cmp(&b.ts_usec))
    });
}

/// Return the time span (in seconds) covered by the records, or 0 if fewer than 2.
#[must_use]
pub fn time_span_secs(records: &[PcapFileRecord]) -> u32 {
    if records.len() < 2 {
        return 0;
    }
    records
        .last()
        .map_or(0, |l| l.ts_sec)
        .saturating_sub(records.first().map_or(0, |f| f.ts_sec))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP record payload extractor
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extract the IPv4 payload (transport-layer data) from an Ethernet frame.
///
/// Returns `None` if the frame is too short or not IPv4.
#[must_use]
pub fn extract_ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 34 {
        return None;
    }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    if et != 0x0800 {
        return None;
    }
    let ihl = ((frame[14] & 0x0F) as usize) * 4;
    if 14 + ihl > frame.len() {
        return None;
    }
    Some(&frame[14 + ihl..])
}

/// Extract the TCP payload from an Ethernet/IPv4/TCP frame.
///
/// Returns `None` if the frame is too short, not IPv4, or not TCP.
#[must_use]
pub fn extract_tcp_payload(frame: &[u8]) -> Option<&[u8]> {
    let transport = extract_ipv4_payload(frame)?;
    if transport.is_empty() {
        return None;
    }
    if frame[23] != 6 {
        return None;
    } // not TCP
    let data_offset = ((transport[12] >> 4) as usize) * 4;
    if data_offset > transport.len() {
        return None;
    }
    Some(&transport[data_offset..])
}

/// Extract the UDP payload from an Ethernet/IPv4/UDP frame.
///
/// Returns `None` if not valid IPv4/UDP.
#[must_use]
pub fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let transport = extract_ipv4_payload(frame)?;
    if transport.is_empty() {
        return None;
    }
    if frame[23] != 17 {
        return None;
    } // not UDP
    if transport.len() < 8 {
        return None;
    }
    Some(&transport[8..])
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAPNG ISB option codes
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// PCAPNG option code constants.
pub mod pcapng_opt {
    /// Comment option.
    pub const OPT_COMMENT: u16 = 1;
    /// Interface name (IDB).
    pub const IDB_NAME: u16 = 2;
    /// Interface description (IDB).
    pub const IDB_DESCRIPTION: u16 = 3;
    /// Interface IPv4 address (IDB).
    pub const IDB_IP4ADDR: u16 = 4;
    /// Interface IPv6 address (IDB).
    pub const IDB_IP6ADDR: u16 = 5;
    /// Interface MAC address (IDB).
    pub const IDB_MACADDR: u16 = 6;
    /// Interface speed (IDB).
    pub const IDB_SPEED: u16 = 8;
    /// Timestamp resolution (IDB).
    pub const IDB_TSRESOL: u16 = 9;
    /// Interface filter (IDB).
    pub const IDB_FILTER: u16 = 11;
    /// Packets received (ISB).
    pub const ISB_STARTTIME: u16 = 2;
    /// Packets dropped (ISB).
    pub const ISB_ENDTIME: u16 = 3;
    /// Interface packets (ISB).
    pub const ISB_IFRECV: u16 = 4;
    /// Interface drops (ISB).
    pub const ISB_IFDROP: u16 = 5;
}

/// Helper to find a named option value in a PCAPNG options list.
#[must_use]
pub fn find_option_str(options: &[(u16, Vec<u8>)], code: u16) -> Option<String> {
    options
        .iter()
        .find(|(c, _)| *c == code)
        .and_then(|(_, v)| std::str::from_utf8(v).ok().map(std::string::ToString::to_string))
}

/// Helper to find an option value as a u64 (little-endian).
#[must_use]
pub fn find_option_u64(options: &[(u16, Vec<u8>)], code: u16) -> Option<u64> {
    options.iter().find(|(c, _)| *c == code).and_then(|(_, v)| {
        if v.len() >= 8 {
            Some(u64::from_le_bytes(v[..8].try_into().ok()?))
        } else {
            None
        }
    })
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PCAP file info summary
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Human-readable file summary for a PCAP file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapFileSummary {
    pub format: String,
    pub link_type: String,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub start_time: f64,
    pub end_time: f64,
    pub duration_secs: f64,
}

impl PcapFileSummary {
    /// Build from a parsed PCAP file.
    #[must_use]
    pub fn from_pcap(file: &PcapFile) -> Self {
        let stats = PcapStats::from_file(file);
        let lt = LinkType::from_u16(u16::try_from(file.header.network).unwrap_or(u16::MAX)).to_string();
        let start_time = file
            .records
            .first()
            .map_or(0.0, |r| f64::from(r.ts_sec) + f64::from(r.ts_usec) / 1_000_000.0);
        let end_time = file
            .records
            .last()
            .map_or(0.0, |r| f64::from(r.ts_sec) + f64::from(r.ts_usec) / 1_000_000.0);
        Self {
            format: "PCAP".to_string(),
            link_type: lt,
            packet_count: stats.packet_count,
            total_bytes: stats.total_bytes,
            start_time,
            end_time,
            duration_secs: stats.duration_secs,
        }
    }
}

impl fmt::Display for PcapFileSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {} pkts / {} bytes / {:.3}s",
            self.format, self.link_type, self.packet_count, self.total_bytes, self.duration_secs
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Additional tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn make_ipv4_tcp_rec(src: [u8; 4], dst: [u8; 4], ts_sec: u32) -> PcapFileRecord {
        let ihl = 20usize;
        let tcp_hdr = 20usize;
        let mut data = Vec::with_capacity(14 + ihl + tcp_hdr);
        data.extend_from_slice(&[0u8; 12]); // MAC dst+src
        data.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        data.push(0x45); // IPv4, IHL=5
        data.push(0x00);
        data.extend_from_slice(&u16::try_from(ihl + tcp_hdr).unwrap_or(u16::MAX).to_be_bytes());
        data.extend_from_slice(&[0x00; 4]); // id, flags+offset
        data.push(64);
        data.push(6); // ttl=64, proto=TCP
        data.extend_from_slice(&[0x00; 2]); // checksum
        data.extend_from_slice(&src);
        data.extend_from_slice(&dst);
        data.extend_from_slice(&[0x00; 20]); // TCP header
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        PcapFileRecord {
            ts_sec,
            ts_usec: 0,
            incl_len: len,
            orig_len: len,
            data,
        }
    }

    #[test]
    fn ip_histogram_top_src() {
        let records = vec![
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 100),
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 101),
            make_ipv4_tcp_rec([9, 9, 9, 9], [5, 6, 7, 8], 102),
        ];
        let h = IpHistogram::from_records(&records);
        let top = h.top_src(1);
        assert_eq!(top[0].0, [1, 2, 3, 4]);
        assert_eq!(top[0].1, 2);
        assert_eq!(h.total(), 3);
    }

    #[test]
    fn ip_histogram_empty() {
        let h = IpHistogram::from_records(&[]);
        assert_eq!(h.total(), 0);
        assert!(h.top_src(5).is_empty());
    }

    #[test]
    fn time_series_basic() {
        let records = vec![
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 0),
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 5),
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 15),
        ];
        let ts = build_time_series(&records, 10);
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0].ts, 0);
        assert_eq!(ts[0].packet_count, 2); // ts=0 and ts=5 both in [0,10)
        assert_eq!(ts[1].ts, 10);
        assert_eq!(ts[1].packet_count, 1);
    }

    #[test]
    fn time_series_zero_bucket_returns_empty() {
        let records = vec![make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 0)];
        let ts = build_time_series(&records, 0);
        assert!(ts.is_empty());
    }

    #[test]
    fn dedup_records_basic() {
        let r1 = make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 100);
        let r2 = r1.clone();
        let r3 = make_ipv4_tcp_rec([9, 9, 9, 9], [5, 6, 7, 8], 101);
        let deduped = dedup_records(vec![r1, r2, r3]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn dedup_records_no_duplicates() {
        let r1 = make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 100);
        let r2 = make_ipv4_tcp_rec([9, 9, 9, 9], [5, 6, 7, 8], 101);
        let deduped = dedup_records(vec![r1, r2]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn sort_records_and_time_span() {
        let mut records = vec![
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 300),
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 100),
            make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 200),
        ];
        sort_records(&mut records);
        assert_eq!(records[0].ts_sec, 100);
        assert_eq!(records[1].ts_sec, 200);
        assert_eq!(records[2].ts_sec, 300);
        assert_eq!(time_span_secs(&records), 200);
    }

    #[test]
    fn time_span_single_record() {
        let records = vec![make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 500)];
        assert_eq!(time_span_secs(&records), 0);
    }

    #[test]
    fn extract_ipv4_payload_basic() {
        let rec = make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 0);
        let p = extract_ipv4_payload(&rec.data).unwrap();
        assert!(!p.is_empty());
    }

    #[test]
    fn extract_tcp_payload_basic() {
        let rec = make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 0);
        // The TCP header bytes are all zero; data_offset field (transport[12] >> 4) = 0, so entire
        // transport layer is "payload". Function must return Some (non-None).
        let p = extract_tcp_payload(&rec.data);
        // With data_offset=0 the slice is the full transport layer; just check it returns Some.
        assert!(p.is_some());
    }

    #[test]
    fn extract_udp_payload_not_udp() {
        let rec = make_ipv4_tcp_rec([1, 2, 3, 4], [5, 6, 7, 8], 0); // proto=6 TCP
        assert!(extract_udp_payload(&rec.data).is_none());
    }

    #[test]
    fn pcap_file_summary_display() {
        let mut w = PcapWriter::new(1);
        w.add_packet(1000, 0, &[0u8; 60]);
        w.add_packet(1002, 0, &[0u8; 40]);
        let bytes = w.to_bytes();
        let f = PcapFile::parse(&bytes).unwrap();
        let summary = PcapFileSummary::from_pcap(&f);
        assert_eq!(summary.format, "PCAP");
        assert_eq!(summary.packet_count, 2);
        assert_eq!(summary.total_bytes, 100);
        let s = summary.to_string();
        assert!(s.contains("PCAP"));
        assert!(s.contains("2 pkts"));
    }

    #[test]
    fn pcapng_opt_constants_defined() {
        assert_eq!(pcapng_opt::OPT_COMMENT, 1);
        assert_eq!(pcapng_opt::IDB_NAME, 2);
        assert_eq!(pcapng_opt::ISB_IFRECV, 4);
    }

    #[test]
    fn find_option_str_basic() {
        let opts: Vec<(u16, Vec<u8>)> = vec![(1, b"hello".to_vec())];
        let s = find_option_str(&opts, 1).unwrap();
        assert_eq!(s, "hello");
        assert!(find_option_str(&opts, 2).is_none());
    }

    #[test]
    fn find_option_u64_basic() {
        let mut v = vec![0u8; 8];
        v[0] = 42;
        let opts: Vec<(u16, Vec<u8>)> = vec![(4, v)];
        let val = find_option_u64(&opts, 4).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn connection_info_duration() {
        let key = FiveTuple::canonical("1.2.3.4", "5.6.7.8", 1234, 80, 6);
        let ci = ConnectionInfo {
            key,
            packet_count: 5,
            total_bytes: 500,
            first_seen: 1000.0,
            last_seen: 1010.5,
        };
        assert!((ci.duration() - 10.5).abs() < 0.001);
    }

    #[test]
    fn anonymize_records_payloads() {
        let mut frame = vec![0u8; 54 + 10]; // 14 eth + 20 ip + 20 tcp + 10 payload
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // IHL=5
        frame[23] = 6; // TCP
        frame[26] = 1;
        frame[27] = 2;
        frame[28] = 3;
        frame[29] = 4; // src IP
        frame[30] = 5;
        frame[31] = 6;
        frame[32] = 7;
        frame[33] = 8; // dst IP
        frame[46] = 0x50; // TCP data_offset=5 (20 bytes from TCP start)
        for i in 54..64 {
            frame[i] = 0xAA;
        }

        let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let rec = PcapFileRecord {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: len,
            orig_len: len,
            data: frame,
        };
        let opts = AnonymizeOptions {
            zero_ipv4_addrs: false,
            zero_mac_addrs: false,
            zero_payloads: true,
        };
        let result = anonymize_records(vec![rec], &opts);
        // TCP payload (bytes 54..64) should be zeroed
        for b in &result[0].data[54..] {
            assert_eq!(*b, 0);
        }
    }

    #[test]
    fn pcap_error_display() {
        let e = PcapError::InvalidMagic(0xDEAD);
        assert!(
            e.to_string().contains("dead")
                || e.to_string().contains("DEAD")
                || e.to_string().contains("0000dead")
        );
        let e2 = PcapError::UnsupportedVersion { major: 3, minor: 0 };
        assert!(e2.to_string().contains('3'));
        let e3 = PcapError::BufferTooShort {
            needed: 100,
            got: 5,
        };
        assert!(e3.to_string().contains("100"));
        assert!(e3.to_string().contains('5'));
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PcapAnalyzer — stream analysis, HTTP session reconstruction, TLS fingerprinting
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

use rustre_net_dissect::{HttpMessage, TlsFingerprint, compute_tls_fingerprint, dissect_http};

/// The application-layer protocol identified for a network session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    Http,
    Https,
    Dns,
    Ftp,
    Smtp,
    Ssh,
    Rdp,
    Smb,
    Unknown,
}

impl fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Dns => write!(f, "DNS"),
            Self::Ftp => write!(f, "FTP"),
            Self::Smtp => write!(f, "SMTP"),
            Self::Ssh => write!(f, "SSH"),
            Self::Rdp => write!(f, "RDP"),
            Self::Smb => write!(f, "SMB"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Summary of a reconstructed network session derived from a packet stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSession {
    /// Five-tuple identifying the session.
    pub key: FiveTuple,
    /// Identified application-layer protocol.
    pub protocol: AppProtocol,
    /// HTTP messages extracted from the session (may be empty).
    pub http_messages: Vec<HttpMessage>,
    /// TLS fingerprint (JA3/JA3S), if this is a TLS session.
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Total number of packets in the session.
    pub packet_count: usize,
    /// Total bytes across all packets.
    pub total_bytes: u64,
    /// Timestamp of the first packet (Unix seconds).
    pub first_seen: f64,
    /// Timestamp of the last packet (Unix seconds).
    pub last_seen: f64,
}

impl NetworkSession {
    /// Duration of the session in seconds.
    #[must_use]
    pub fn duration(&self) -> f64 {
        (self.last_seen - self.first_seen).max(0.0)
    }
}

/// Analyser that processes a flat slice of [`PcapFileRecord`]s and produces
/// per-session [`NetworkSession`] summaries.
pub struct PcapAnalyzer;

impl PcapAnalyzer {
    /// Create a new `PcapAnalyzer`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse a stream of packets and return one [`NetworkSession`] per
    /// identified TCP/UDP flow.
    ///
    /// For each session the analyser:
    /// - Identifies the application protocol by port heuristics and payload
    ///   inspection (DNS, HTTP, HTTPS, FTP, SMTP).
    /// - Extracts HTTP messages when the protocol is HTTP.
    /// - Computes TLS JA3/JA3S fingerprints when the protocol is HTTPS.
    #[must_use]
    pub fn analyze_stream(packets: &[PcapFileRecord]) -> Vec<NetworkSession> {
        use std::collections::HashMap;

        // Per-flow accumulator
        struct FlowAcc {
            key: FiveTuple,
            payloads: Vec<Vec<u8>>,
            raw_pkts: Vec<Vec<u8>>,
            timestamps: Vec<f64>,
            total_bytes: u64,
        }

        let mut flows: HashMap<FiveTuple, FlowAcc> = HashMap::new();

        for rec in packets {
            let data = &rec.data;
            // Minimum: 14 (eth) + 20 (ip) = 34 bytes
            if data.len() < 34 {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            if ethertype != 0x0800 {
                continue;
            }

            let ip_proto = data[23];
            if ip_proto != 6 && ip_proto != 17 {
                continue;
            }

            let ihl = ((data[14] & 0x0F) as usize) * 4;
            if data.len() < 14 + ihl + 4 {
                continue;
            }

            let src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
            let dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
            let sp = u16::from_be_bytes([data[14 + ihl], data[14 + ihl + 1]]);
            let dp = u16::from_be_bytes([data[14 + ihl + 2], data[14 + ihl + 3]]);

            // Extract transport-layer payload
            let payload: Vec<u8> = if ip_proto == 6 {
                // TCP: data offset in the high nibble of byte 12 of the TCP header
                if data.len() < 14 + ihl + 13 {
                    vec![]
                } else {
                    let tcp_data_off = ((data[14 + ihl + 12] >> 4) as usize) * 4;
                    let payload_start = 14 + ihl + tcp_data_off;
                    if payload_start < data.len() {
                        data[payload_start..].to_vec()
                    } else {
                        vec![]
                    }
                }
            } else {
                // UDP: 8-byte header
                let payload_start = 14 + ihl + 8;
                if payload_start < data.len() {
                    data[payload_start..].to_vec()
                } else {
                    vec![]
                }
            };

            let key = FiveTuple::canonical(&src_ip, &dst_ip, sp, dp, ip_proto);
            let ts = f64::from(rec.ts_sec) + f64::from(rec.ts_usec) / 1_000_000.0;

            let acc = flows.entry(key.clone()).or_insert_with(|| FlowAcc {
                key,
                payloads: Vec::new(),
                raw_pkts: Vec::new(),
                timestamps: Vec::new(),
                total_bytes: 0,
            });
            acc.total_bytes += data.len() as u64;
            acc.timestamps.push(ts);
            acc.raw_pkts.push(data.clone());
            if !payload.is_empty() {
                acc.payloads.push(payload);
            }
        }

        let mut sessions: Vec<NetworkSession> = flows
            .into_values()
            .map(|acc| {
                let protocol =
                    identify_protocol_internal(acc.key.src_port, acc.key.dst_port, &acc.payloads);
                let first_seen = acc.timestamps.iter().copied().fold(f64::INFINITY, f64::min);
                let last_seen = acc
                    .timestamps
                    .iter()
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max);
                let packet_count = acc.raw_pkts.len();

                let http_messages = if protocol == AppProtocol::Http {
                    acc.payloads
                        .iter()
                        .filter_map(|p| dissect_http(p))
                        .collect()
                } else {
                    Vec::new()
                };

                let tls_fingerprint = if protocol == AppProtocol::Https {
                    let refs: Vec<&[u8]> = acc.payloads.iter().map(std::vec::Vec::as_slice).collect();
                    let fp = compute_tls_fingerprint(&refs);
                    // Only include if we got at least a JA3
                    if fp.ja3.is_empty() { None } else { Some(fp) }
                } else {
                    None
                };

                NetworkSession {
                    key: acc.key,
                    protocol,
                    http_messages,
                    tls_fingerprint,
                    packet_count,
                    total_bytes: acc.total_bytes,
                    first_seen: if first_seen.is_finite() {
                        first_seen
                    } else {
                        0.0
                    },
                    last_seen: if last_seen.is_finite() {
                        last_seen
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        sessions.sort_by(|a, b| {
            a.first_seen
                .partial_cmp(&b.first_seen)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sessions
    }
}

impl Default for PcapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Identify application protocol from port numbers and payload heuristics.
fn identify_protocol_internal(src_port: u16, dst_port: u16, payloads: &[Vec<u8>]) -> AppProtocol {
    let lo = src_port.min(dst_port);
    let hi = src_port.max(dst_port);

    // Port-based identification
    match lo {
        53 => return AppProtocol::Dns,
        21 | 20 => return AppProtocol::Ftp,
        25 | 587 | 465 => return AppProtocol::Smtp,
        _ => {}
    }
    match hi {
        53 => return AppProtocol::Dns,
        80 | 8080 | 8000 => return AppProtocol::Http,
        443 | 8443 => return AppProtocol::Https,
        21 | 20 => return AppProtocol::Ftp,
        25 | 587 | 465 => return AppProtocol::Smtp,
        _ => {}
    }

    // Payload heuristics
    for payload in payloads {
        if payload.is_empty() {
            continue;
        }
        if payload.starts_with(b"HTTP/") || is_http_method(payload) {
            return AppProtocol::Http;
        }
        if payload[0] == 22 && payload.len() >= 5 {
            return AppProtocol::Https;
        }
        // DNS: plausible 12-byte header with low question count
        if payload.len() >= 12 {
            let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
            if qdcount > 0 && qdcount <= 10 {
                return AppProtocol::Dns;
            }
        }
    }

    AppProtocol::Unknown
}

fn is_http_method(data: &[u8]) -> bool {
    for m in [
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ] {
        if data.starts_with(m) {
            return true;
        }
    }
    false
}

// â"€â"€â"€ TCP stream reassembly â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

use std::collections::BTreeMap;

/// A five-tuple key (canonical form).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpSessionKey {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
}

impl TcpSessionKey {
    /// Create a canonical (sorted) key so both directions map to the same session.
    #[must_use]
    pub fn canonical(sa: [u8; 4], sp: u16, da: [u8; 4], dp: u16) -> Self {
        if (sa, sp) <= (da, dp) {
            Self {
                src_ip: sa,
                dst_ip: da,
                src_port: sp,
                dst_port: dp,
            }
        } else {
            Self {
                src_ip: da,
                dst_ip: sa,
                src_port: dp,
                dst_port: sp,
            }
        }
    }

    #[must_use]
    pub fn src_str(&self) -> String {
        format!(
            "{}.{}.{}.{}:{}",
            self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3], self.src_port
        )
    }

    #[must_use]
    pub fn dst_str(&self) -> String {
        format!(
            "{}.{}.{}.{}:{}",
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3], self.dst_port
        )
    }
}

impl std::fmt::Display for TcpSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <-> {}", self.src_str(), self.dst_str())
    }
}

/// Pending out-of-order TCP segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub fin: bool,
    pub rst: bool,
}

/// State machine for one direction of a TCP stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpStreamHalf {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Reassembled in-order data.
    pub data: Vec<u8>,
    /// Out-of-order segments (keyed by seq).
    pub o: BTreeMap<u32, TcpSegment>,
    /// Whether FIN has been seen.
    pub fin_seen: bool,
    /// Whether RST has been seen.
    pub rst_seen: bool,
}

impl TcpStreamHalf {
    /// Feed a segment into this half-stream.
    /// # Panics
    /// Panics if invariants are violated.
    pub fn insert(&mut self, seg: TcpSegment) {
        if seg.rst {
            self.rst_seen = true;
            return;
        }
        let end = seg.seq.wrapping_add(u32::try_from(seg.data.len()).unwrap_or(u32::MAX));
        if seg.seq == self.next_seq {
            self.data.extend_from_slice(&seg.data);
            self.next_seq = end;
            if seg.fin {
                self.fin_seen = true;
            }
            // Try to drain out-of-order queue
            loop {
                if let Some((&k, _)) = self.o.iter().next()
                    && k == self.next_seq {
                        let s = self.o.remove(&k).unwrap();
                        let e = s.seq.wrapping_add(u32::try_from(s.data.len()).unwrap_or(u32::MAX));
                        self.data.extend_from_slice(&s.data);
                        self.next_seq = e;
                        if s.fin {
                            self.fin_seen = true;
                        }
                        continue;
                    }
                break;
            }
        } else if seg.seq.wrapping_sub(self.next_seq) < 0x7FFF_FFFF {
            // Future segment — queue it
            self.o.insert(seg.seq, seg);
        }
        // Past segment (retransmit) — ignore
    }
}

/// State of a reassembled TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TcpSessionState {
    Open,
    HalfClosed,
    Closed,
    Reset,
}

/// A full reassembled TCP session with both half-streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSession {
    pub key: TcpSessionKey,
    pub client: TcpStreamHalf, // srcâ†'dst direction
    pub server: TcpStreamHalf, // dstâ†'src direction
    pub state: TcpSessionState,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packet_count: u64,
}

impl TcpSession {
    #[must_use]
    pub fn new(key: TcpSessionKey, ts: u64) -> Self {
        Self {
            key,
            client: TcpStreamHalf::default(),
            server: TcpStreamHalf::default(),
            state: TcpSessionState::Open,
            first_seen_us: ts,
            last_seen_us: ts,
            packet_count: 0,
        }
    }

    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us) / 1000
    }

    #[must_use]
    pub const fn bytes_client(&self) -> usize {
        self.client.data.len()
    }
    #[must_use]
    pub const fn bytes_server(&self) -> usize {
        self.server.data.len()
    }
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.client.data.len() + self.server.data.len()
    }
}

/// TCP stream reassembler: tracks multiple sessions.
#[derive(Debug, Default)]
pub struct TcpReassembler {
    pub sessions: std::collections::HashMap<TcpSessionKey, TcpSession>,
    /// Timeout for idle sessions (microseconds). Default: 60 s.
    pub timeout_us: u64,
}

impl TcpReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::default(),
            timeout_us: 60_000_000,
        }
    }

    /// Process a raw Ethernet frame (assumes Ethernet â†' IPv4 â†' TCP).
    pub fn process_frame(&mut self, data: &[u8], ts_us: u64) {
        // Parse Ethernet header (14 bytes)
        if data.len() < 14 {
            return;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return;
        } // IPv4 only

        // Parse IPv4 header
        if data.len() < 34 {
            return;
        }
        let ip_hdr_len = ((data[14] & 0x0F) as usize) * 4;
        if data[23] != 6 {
            return;
        } // TCP only
        let ip_start = 14usize;
        if data.len() < ip_start + ip_hdr_len + 20 {
            return;
        }

        let src_ip = [data[26], data[27], data[28], data[29]];
        let dst_ip = [data[30], data[31], data[32], data[33]];

        // Parse TCP header
        let tcp_start = ip_start + ip_hdr_len;
        let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);
        let seq = u32::from_be_bytes([
            data[tcp_start + 4],
            data[tcp_start + 5],
            data[tcp_start + 6],
            data[tcp_start + 7],
        ]);
        let tcp_data_off = ((data[tcp_start + 12] >> 4) as usize) * 4;
        let flags = data[tcp_start + 13];
        let fin = flags & 0x01 != 0;
        let syn = flags & 0x02 != 0;
        let rst = flags & 0x04 != 0;

        let payload_start = tcp_start + tcp_data_off;
        let payload = if payload_start < data.len() {
            data[payload_start..].to_vec()
        } else {
            vec![]
        };

        let key = TcpSessionKey::canonical(src_ip, src_port, dst_ip, dst_port);
        let is_client_dir = (src_ip, src_port) == (key.src_ip, key.src_port);

        let session = self
            .sessions
            .entry(key.clone())
            .or_insert_with(|| TcpSession::new(key, ts_us));
        session.last_seen_us = ts_us;
        session.packet_count += 1;

        if rst {
            session.state = TcpSessionState::Reset;
        } else if !syn {
            let seg = TcpSegment {
                seq,
                data: payload,
                fin,
                rst,
            };
            if is_client_dir {
                session.client.insert(seg);
            } else {
                session.server.insert(seg);
            }
            if fin {
                session.state = TcpSessionState::HalfClosed;
            }
        }
    }

    /// Collect all sessions that have been idle longer than `timeout_us`.
    pub fn collect_expired(&mut self, now_us: u64) -> Vec<TcpSession> {
        
        
        let keys: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_us.saturating_sub(s.last_seen_us) > self.timeout_us)
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter()
            .filter_map(|k| self.sessions.remove(&k))
            .collect()
    }
}

// â"€â"€â"€ HTTP/1.1 parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// HTTP request parsed from reassembled TCP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub host: String,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
}

impl HttpRequest {
    /// Parse an HTTP/1.1 request from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let header_end = text.find("\r\n\r\n")?;
        let header_part = &text[..header_end];
        let mut lines = header_part.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();

        let mut headers = Vec::new();
        let mut host = String::new();
        let mut content_length = None;
        let mut is_chunked = false;

        for line in lines {
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                if name == "host" {
                    host.clone_from(&value);
                }
                if name == "content-length" {
                    content_length = value.parse().ok();
                }
                if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                    is_chunked = true;
                }
                headers.push((line[..colon].trim().to_string(), value));
            }
        }

        let body_start = header_end + 4;
        let body = data.get(body_start..).unwrap_or(&[]).to_vec();

        Some(Self {
            method,
            path,
            version,
            headers,
            body,
            host,
            content_length,
            is_chunked,
        })
    }

    /// Reconstruct the full URL if a Host header is present.
    #[must_use]
    pub fn url(&self) -> String {
        if self.host.is_empty() {
            self.path.clone()
        } else {
            format!("http://{}{}", self.host, self.path)
        }
    }
}

/// HTTP response parsed from reassembled TCP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
    pub content_type: String,
}

impl HttpResponse {
    /// Parse an HTTP/1.1 response from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let header_end = text.find("\r\n\r\n")?;
        let header_part = &text[..header_end];
        let mut lines = header_part.lines();
        let status_line = lines.next()?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next()?.to_string();
        let status_code: u16 = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("").to_string();

        let mut headers = Vec::new();
        let mut content_length = None;
        let mut is_chunked = false;
        let mut content_type = String::new();

        for line in lines {
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                if name == "content-length" {
                    content_length = value.parse().ok();
                }
                if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                    is_chunked = true;
                }
                if name == "content-type" {
                    content_type.clone_from(&value);
                }
                headers.push((line[..colon].trim().to_string(), value));
            }
        }

        let body_start = header_end + 4;
        let body = data.get(body_start..).unwrap_or(&[]).to_vec();
        Some(Self {
            version,
            status_code,
            reason,
            headers,
            body,
            content_length,
            is_chunked,
            content_type,
        })
    }
}

// â"€â"€â"€ TLS ClientHello parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A parsed TLS `ClientHello` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHello {
    /// TLS record layer version (e.g. 0x0301).
    pub record_version: u16,
    /// Handshake `ClientHello` version.
    pub client_version: u16,
    /// 32-byte random.
    pub random: Vec<u8>,
    /// Session ID (0–32 bytes).
    pub session_id: Vec<u8>,
    /// Cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Compression methods.
    pub compression_methods: Vec<u8>,
    /// SNI hostname (from extension 0x0000).
    pub sni: Option<String>,
    /// Supported groups (from extension 0x000A).
    pub supported_groups: Vec<u16>,
    /// ALPN protocols (from extension 0x0010).
    pub alpn: Vec<String>,
    /// Whether early data extension is present (0x002A).
    pub early_data: bool,
    /// Raw extension types present.
    pub extension_types: Vec<u16>,
}

/// Parse a TLS `ClientHello` from a TCP payload.
///
/// Returns `None` if the data is not a valid `ClientHello`.
#[must_use]
pub fn parse_tls_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    if data.len() < 43 {
        return None;
    }
    // TLS record layer
    if data[0] != 0x16 {
        return None;
    } // Handshake
    let record_version = u16::from_be_bytes([data[1], data[2]]);
    // let record_len = u16::from_be_bytes([data[3], data[4]]);
    // Handshake header
    if data[5] != 0x01 {
        return None;
    } // ClientHello
    // let hs_len = u24_be(&data[6..9]);
    let client_version = u16::from_be_bytes([data[9], data[10]]);
    let random = data[11..43].to_vec();
    let mut off = 43usize;
    // Session ID
    if off >= data.len() {
        return None;
    }
    let sid_len = data[off] as usize;
    off += 1;
    if off + sid_len > data.len() {
        return None;
    }
    let session_id = data[off..off + sid_len].to_vec();
    off += sid_len;
    // Cipher suites
    if off + 2 > data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    if off + cs_len > data.len() {
        return None;
    }
    let mut cipher_suites = Vec::new();
    for i in (0..cs_len).step_by(2) {
        cipher_suites.push(u16::from_be_bytes([data[off + i], data[off + i + 1]]));
    }
    off += cs_len;
    // Compression methods
    if off >= data.len() {
        return None;
    }
    let cm_len = data[off] as usize;
    off += 1;
    if off + cm_len > data.len() {
        return None;
    }
    let compression_methods = data[off..off + cm_len].to_vec();
    off += cm_len;
    // Extensions
    let mut sni = None;
    let mut supported_groups = Vec::new();
    let mut alpn = Vec::new();
    let mut early_data = false;
    let mut extension_types = Vec::new();

    if off + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let ext_end = off + ext_total;
        while off + 4 <= ext_end.min(data.len()) {
            let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
            let ext_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;
            extension_types.push(ext_type);
            if off + ext_len > data.len() {
                break;
            }
            let ext_data = &data[off..off + ext_len];
            match ext_type {
                0x0000 => {
                    // SNI
                    if ext_data.len() >= 5 {
                        let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                        if ext_data.len() >= 5 + name_len {
                            sni = std::str::from_utf8(&ext_data[5..5 + name_len])
                                .ok()
                                .map(String::from);
                        }
                    }
                }
                0x000A => {
                    // Supported groups
                    if ext_data.len() >= 2 {
                        let glen = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        for i in (0..glen.min(ext_data.len() - 2)).step_by(2) {
                            supported_groups
                                .push(u16::from_be_bytes([ext_data[2 + i], ext_data[2 + i + 1]]));
                        }
                    }
                }
                0x0010 => {
                    // ALPN
                    let mut ap = 2usize;
                    while ap + 1 < ext_data.len() {
                        let plen = ext_data[ap] as usize;
                        ap += 1;
                        if ap + plen <= ext_data.len()
                            && let Ok(s) = std::str::from_utf8(&ext_data[ap..ap + plen]) {
                                alpn.push(s.to_string());
                            }
                        ap += plen;
                    }
                }
                0x002A => {
                    early_data = true;
                }
                _ => {}
            }
            off += ext_len;
        }
    }

    Some(TlsClientHello {
        record_version,
        client_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        sni,
        supported_groups,
        alpn,
        early_data,
        extension_types,
    })
}

// â"€â"€â"€ JA3 fingerprint â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Grease values to exclude from JA3 computation.
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool {
    GREASE.contains(&v)
}

/// Compute the JA3 fingerprint string (before MD5) from a [`TlsClientHello`].
#[must_use]
pub fn ja3_string(hello: &TlsClientHello) -> String {
    let version = hello.client_version.to_string();

    let ciphers: Vec<String> = hello
        .cipher_suites
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(std::string::ToString::to_string)
        .collect();

    let ext_types: Vec<String> = hello
        .extension_types
        .iter()
        .filter(|&&e| !is_grease(e))
        .map(std::string::ToString::to_string)
        .collect();

    let groups: Vec<String> = hello
        .supported_groups
        .iter()
        .filter(|&&g| !is_grease(g))
        .map(std::string::ToString::to_string)
        .collect();

    // Point formats: assume uncompressed (0) if not present
    let point_formats = "0";

    format!(
        "{},{},{},{},{}",
        version,
        ciphers.join("-"),
        ext_types.join("-"),
        groups.join("-"),
        point_formats,
    )
}

/// Compute the JA3 MD5 hash from a [`TlsClientHello`].
///
/// Uses a simple MD5 implementation. If the `md5` crate is not available,
/// returns the raw JA3 string prefixed with `raw:`.
#[must_use]
pub fn ja3_fingerprint(hello: &TlsClientHello) -> String {
    let s = ja3_string(hello);
    // Compute MD5 via the md5 module (inline implementation to avoid dependency)
    format!("ja3:{}", md5_hex(s.as_bytes()))
}

/// Minimal MD5 implementation (RFC 1321) — no external dependency.
fn md5_hex(input: &[u8]) -> String {
    let digest = md5_compute(input);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn md5_compute(input: &[u8]) -> [u8; 16] {
    // Constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
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
    let mut msg = input.to_vec();
    let original_bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&original_bit_len.to_le_bytes());
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for (idx, word) in block.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[idx * 4],
                chunk[idx * 4 + 1],
                chunk[idx * 4 + 2],
                chunk[idx * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64u32 {
            let (mix, msg_idx) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(mix)
                    .wrapping_add(K[i as usize])
                    .wrapping_add(block[msg_idx as usize]))
                .rotate_left(S[i as usize]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// â"€â"€â"€ DNS parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A DNS question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRR {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRData,
}

/// Decoded DNS record data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(String),
    Ns(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
    },
    Ptr(String),
    Raw(Vec<u8>),
}

impl std::fmt::Display for DnsRData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Aaaa(a) => {
                let words: Vec<String> = (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([a[i * 2], a[i * 2 + 1]])))
                    .collect();
                write!(f, "{}", words.join(":"))
            }
            Self::Cname(s) | Self::Ns(s) | Self::Ptr(s) => write!(f, "{s}"),
            Self::Mx { priority, exchange } => write!(f, "{priority} {exchange}"),
            Self::Txt(parts) => write!(f, "{}", parts.join(" ")),
            Self::Soa {
                mname,
                rname,
                serial,
            } => write!(f, "{mname} {rname} {serial}"),
            Self::Raw(d) => write!(f, "[{} bytes]", d.len()),
        }
    }
}

/// A complete DNS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRR>,
    pub authority: Vec<DnsRR>,
    pub additional: Vec<DnsRR>,
}

/// Parse a DNS name starting at `off` in `data`, handling compression pointers.
fn parse_dns_name(data: &[u8], off: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut pos = off;
    let mut jumped = false;
    let mut end_pos = off;
    let mut safety = 0usize;
    loop {
        safety += 1;
        if safety > 128 || pos >= data.len() {
            break;
        }
        let len = data[pos];
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | data[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = ptr;
        } else {
            let l = len as usize;
            pos += 1;
            if pos + l > data.len() {
                return None;
            }
            parts.push(
                std::str::from_utf8(&data[pos..pos + l])
                    .unwrap_or("?")
                    .to_string(),
            );
            pos += l;
        }
    }
    Some((parts.join("."), end_pos))
}

/// Parse a DNS message from raw UDP payload.
#[must_use]
pub fn parse_dns(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xF) as u8;
    let truncated = flags & 0x0200 != 0;
    let recursion_desired = flags & 0x0100 != 0;
    let recursion_available = flags & 0x0080 != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let mut off = 12usize;

    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = parse_dns_name(data, off)?;
        off = next;
        if off + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[off], data[off + 1]]);
        let qclass = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    let parse_rrs = |count: usize, off: &mut usize| -> Option<Vec<DnsRR>> {
        let mut rrs = Vec::new();
        for _ in 0..count {
            let (name, next) = parse_dns_name(data, *off)?;
            *off = next;
            if *off + 10 > data.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([data[*off], data[*off + 1]]);
            let rclass = u16::from_be_bytes([data[*off + 2], data[*off + 3]]);
            let ttl = u32::from_be_bytes([
                data[*off + 4],
                data[*off + 5],
                data[*off + 6],
                data[*off + 7],
            ]);
            let rdlen = u16::from_be_bytes([data[*off + 8], data[*off + 9]]) as usize;
            *off += 10;
            if *off + rdlen > data.len() {
                return None;
            }
            let rdata_raw = &data[*off..*off + rdlen];
            let rdata = match (rtype, rdlen) {
                (1, 4) => DnsRData::A([rdata_raw[0], rdata_raw[1], rdata_raw[2], rdata_raw[3]]),
                (28, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(rdata_raw);
                    DnsRData::Aaaa(a)
                }
                (5 | 2 | 12, _) => {
                    let (n, _) = parse_dns_name(data, *off)?;
                    match rtype {
                        5 => DnsRData::Cname(n),
                        2 => DnsRData::Ns(n),
                        12 => DnsRData::Ptr(n),
                        _ => unreachable!(),
                    }
                }
                (15, _) if rdlen >= 2 => {
                    let priority = u16::from_be_bytes([rdata_raw[0], rdata_raw[1]]);
                    let (exchange, _) = parse_dns_name(data, *off + 2)?;
                    DnsRData::Mx { priority, exchange }
                }
                (16, _) => {
                    let mut parts = Vec::new();
                    let mut i = 0;
                    while i < rdlen {
                        let tlen = rdata_raw[i] as usize;
                        i += 1;
                        if i + tlen <= rdlen {
                            parts
                                .push(String::from_utf8_lossy(&rdata_raw[i..i + tlen]).to_string());
                        }
                        i += tlen;
                    }
                    DnsRData::Txt(parts)
                }
                _ => DnsRData::Raw(rdata_raw.to_vec()),
            };
            *off += rdlen;
            rrs.push(DnsRR {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }
        Some(rrs)
    };

    let answers = parse_rrs(ancount, &mut off)?;
    let authority = parse_rrs(nscount, &mut off)?;
    let additional = parse_rrs(arcount, &mut off)?;

    Some(DnsMessage {
        id,
        is_response,
        opcode,
        truncated,
        recursion_desired,
        recursion_available,
        rcode,
        questions,
        answers,
        authority,
        additional,
    })
}

// â"€â"€â"€ Application protocol identification â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Detected application-layer protocol.
#[cfg(any())]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    Http,
    Https,
    Dns,
    Ftp,
    Smtp,
    Ssh,
    Rdp,
    Smb,
    Unknown,
}

#[cfg(any())]
impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Dns => write!(f, "DNS"),
            Self::Ftp => write!(f, "FTP"),
            Self::Smtp => write!(f, "SMTP"),
            Self::Ssh => write!(f, "SSH"),
            Self::Rdp => write!(f, "RDP"),
            Self::Smb => write!(f, "SMB"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Identify the application protocol for a connection.
///
/// `lo` is the lower of the two port numbers, `hi` is the higher.
/// `payloads` provides sample data from both directions.
#[must_use]
pub fn identify_protocol(lo: u16, hi: u16, payloads: &[&[u8]]) -> AppProtocol {
    match lo {
        80 | 8080 | 8000 => return AppProtocol::Http,
        443 | 8443 => return AppProtocol::Https,
        22 => return AppProtocol::Ssh,
        3389 => return AppProtocol::Rdp,
        445 => return AppProtocol::Smb,
        53 => return AppProtocol::Dns,
        21 | 20 => return AppProtocol::Ftp,
        25 | 587 | 465 => return AppProtocol::Smtp,
        _ => {}
    }
    match hi {
        80 | 8080 | 8000 => return AppProtocol::Http,
        443 | 8443 => return AppProtocol::Https,
        53 => return AppProtocol::Dns,
        22 => return AppProtocol::Ssh,
        3389 => return AppProtocol::Rdp,
        445 => return AppProtocol::Smb,
        21 | 20 => return AppProtocol::Ftp,
        25 | 587 | 465 => return AppProtocol::Smtp,
        _ => {}
    }
    for payload in payloads {
        if payload.is_empty() {
            continue;
        }
        if payload.starts_with(b"HTTP/") || is_http_method_ext(payload) {
            return AppProtocol::Http;
        }
        if payload[0] == 22 && payload.len() >= 3 {
            return AppProtocol::Https;
        }
        if payload.len() >= 4 && &payload[..4] == b"SSH-" {
            return AppProtocol::Ssh;
        }
        if payload.len() >= 4 && (&payload[..4] == b"\xFFSMB" || &payload[..4] == b"\xFESMB") {
            return AppProtocol::Smb;
        }
    }
    AppProtocol::Unknown
}

fn is_http_method_ext(data: &[u8]) -> bool {
    for m in [
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ] {
        if data.starts_with(m) {
            return true;
        }
    }
    false
}

// â"€â"€â"€ HAR export â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A HAR (HTTP Archive) entry for a single HTTP transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntry {
    pub started_datetime: String,
    pub time_ms: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    pub server_ip_address: String,
    pub connection: String,
}

/// HAR request record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<HarNameValue>,
    pub body_size: i64,
}

/// HAR response record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HarNameValue>,
    pub body_size: i64,
    pub content: HarContent,
}

/// HAR name:value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValue {
    pub name: String,
    pub value: String,
}

/// HAR response content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarContent {
    pub size: i64,
    pub mime_type: String,
}

/// Build a minimal HAR log from HTTP requests/responses.
#[must_use]
pub fn build_har(entries: &[HarEntry]) -> String {
    let entries_json: Vec<String> = entries.iter().map(|e| {
        let req_headers: Vec<String> = e.request.headers.iter()
            .map(|h| format!("{{\"name\":{:?},\"value\":{:?}}}", h.name, h.value))
            .collect();
        let resp_headers: Vec<String> = e.response.headers.iter()
            .map(|h| format!("{{\"name\":{:?},\"value\":{:?}}}", h.name, h.value))
            .collect();
        format!(
            "{{\"startedDateTime\":{:?},\"time\":{},\"request\":{{\"method\":{:?},\"url\":{:?},\"httpVersion\":{:?},\"headers\":[{}],\"bodySize\":{}}},\"response\":{{\"status\":{},\"statusText\":{:?},\"httpVersion\":{:?},\"headers\":[{}],\"bodySize\":{},\"content\":{{\"size\":{},\"mimeType\":{:?}}}}}}}",
            e.started_datetime, e.time_ms,
            e.request.method, e.request.url, e.request.http_version,
            req_headers.join(","), e.request.body_size,
            e.response.status, e.response.status_text, e.response.http_version,
            resp_headers.join(","), e.response.body_size,
            e.response.content.size, e.response.content.mime_type,
        )
    }).collect();
    format!(
        "{{\"log\":{{\"version\":\"1.2\",\"creator\":{{\"name\":\"rustre-net-pcap\",\"version\":\"0.1\"}},\"entries\":[{}]}}}}",
        entries_json.join(",")
    )
}

// â"€â"€â"€ Connection statistics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Per-connection stats for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnStats {
    pub key: String,
    pub protocol: String,
    pub app_protocol: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packet_count: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub duration_ms: u64,
}

impl ConnStats {
    #[must_use]
    pub fn from_session(s: &TcpSession) -> Self {
        Self {
            key: s.key.to_string(),
            protocol: "TCP".to_string(),
            app_protocol: AppProtocol::Unknown.to_string(),
            bytes_sent: s.bytes_client() as u64,
            bytes_recv: s.bytes_server() as u64,
            packet_count: s.packet_count,
            first_seen_us: s.first_seen_us,
            last_seen_us: s.last_seen_us,
            duration_ms: s.duration_ms(),
        }
    }

    /// Emit a CSV row with a fixed header.
    #[must_use]
    pub const fn csv_header() -> &'static str {
        "key,protocol,app_protocol,bytes_sent,bytes_recv,packets,first_seen_us,last_seen_us,duration_ms"
    }

    #[must_use]
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{}",
            self.key,
            self.protocol,
            self.app_protocol,
            self.bytes_sent,
            self.bytes_recv,
            self.packet_count,
            self.first_seen_us,
            self.last_seen_us,
            self.duration_ms,
        )
    }
}

// â"€â"€â"€ Additional tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod pcap_ext_tests {
    use super::*;

    #[test]
    fn test_tcp_session_key_canonical() {
        let k1 = TcpSessionKey::canonical([1, 2, 3, 4], 1234, [5, 6, 7, 8], 80);
        let k2 = TcpSessionKey::canonical([5, 6, 7, 8], 80, [1, 2, 3, 4], 1234);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_tcp_stream_half_in_order() {
        let mut h = TcpStreamHalf {
            next_seq: 100,
            ..TcpStreamHalf::default()
        };
        h.insert(TcpSegment {
            seq: 100,
            data: b"hello".to_vec(),
            fin: false,
            rst: false,
        });
        h.insert(TcpSegment {
            seq: 105,
            data: b" world".to_vec(),
            fin: false,
            rst: false,
        });
        assert_eq!(h.data, b"hello world");
    }

    #[test]
    fn test_tcp_stream_half_out_of_order() {
        let mut h = TcpStreamHalf {
            next_seq: 0,
            ..TcpStreamHalf::default()
        };
        h.insert(TcpSegment {
            seq: 5,
            data: b"world".to_vec(),
            fin: false,
            rst: false,
        });
        h.insert(TcpSegment {
            seq: 0,
            data: b"hello".to_vec(),
            fin: false,
            rst: false,
        });
        assert_eq!(&h.data[..5], b"hello");
        assert_eq!(&h.data[5..], b"world");
    }

    #[test]
    fn test_tcp_stream_half_rst() {
        let mut h = TcpStreamHalf::default();
        h.insert(TcpSegment {
            seq: 0,
            data: vec![],
            fin: false,
            rst: true,
        });
        assert!(h.rst_seen);
    }

    #[test]
    fn test_http_request_parse_get() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.url(), "http://example.com/index.html");
    }

    #[test]
    fn test_http_request_parse_post_with_body() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_length, Some(5));
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn test_http_response_parse_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nbody";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_type, "text/html");
        assert_eq!(resp.body, b"body");
    }

    #[test]
    fn test_http_response_parse_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn test_identify_protocol_http_port() {
        assert_eq!(identify_protocol(80, 1234, &[]), AppProtocol::Http);
    }

    #[test]
    fn test_identify_protocol_dns_port() {
        assert_eq!(identify_protocol(53, 5000, &[]), AppProtocol::Dns);
    }

    #[test]
    fn test_identify_protocol_https_payload() {
        // TLS record byte 22 = 0x16
        let payload: &[u8] = &[0x16, 0x03, 0x01];
        assert_eq!(
            identify_protocol(40000, 12345, &[payload]),
            AppProtocol::Https
        );
    }

    #[test]
    fn test_identify_protocol_http_method() {
        let payload: &[u8] = b"GET / HTTP/1.1\r\n";
        assert_eq!(
            identify_protocol(50000, 8000, &[payload]),
            AppProtocol::Http
        );
    }

    #[test]
    fn test_ja3_string_not_empty() {
        let hello = TlsClientHello {
            record_version: 0x0301,
            client_version: 0x0303,
            random: vec![0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x002f, 0x0035],
            compression_methods: vec![0],
            sni: Some("example.com".to_string()),
            supported_groups: vec![0x0017],
            alpn: vec!["h2".to_string()],
            early_data: false,
            extension_types: vec![0x0000, 0x000A, 0x0010],
        };
        let s = ja3_string(&hello);
        assert!(!s.is_empty());
        assert!(s.contains(','));
    }

    #[test]
    fn test_ja3_fingerprint_format() {
        let hello = TlsClientHello {
            record_version: 0x0301,
            client_version: 0x0303,
            random: vec![0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x002f],
            compression_methods: vec![0],
            sni: None,
            supported_groups: vec![],
            alpn: vec![],
            early_data: false,
            extension_types: vec![],
        };
        let fp = ja3_fingerprint(&hello);
        assert!(fp.starts_with("ja3:"));
        assert_eq!(fp.len(), 4 + 32); // "ja3:" + 32 hex chars
    }

    #[test]
    fn test_md5_empty() {
        let h = md5_hex(&[]);
        assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello_world() {
        let h = md5_hex(b"hello world");
        assert_eq!(h, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_dns_parse_query() {
        // Minimal DNS query for "example.com" type A
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags: QR=0 RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // name: "example.com"
        pkt.extend_from_slice(&[7u8]);
        pkt.extend_from_slice(b"example");
        pkt.extend_from_slice(&[3u8]);
        pkt.extend_from_slice(b"com");
        pkt.push(0); // root
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let msg = parse_dns(&pkt).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, 1);
    }

    #[test]
    fn test_tcp_session_duration() {
        let key = TcpSessionKey {
            src_ip: [1, 2, 3, 4],
            dst_ip: [5, 6, 7, 8],
            src_port: 1234,
            dst_port: 80,
        };
        let mut s = TcpSession::new(key, 1_000_000);
        s.last_seen_us = 3_000_000;
        assert_eq!(s.duration_ms(), 2000);
    }

    #[test]
    fn test_conn_stats_csv() {
        let key = TcpSessionKey {
            src_ip: [1, 2, 3, 4],
            dst_ip: [5, 6, 7, 8],
            src_port: 1234,
            dst_port: 80,
        };
        let s = TcpSession::new(key, 0);
        let cs = ConnStats::from_session(&s);
        let csv = cs.to_csv();
        assert!(csv.contains("TCP"));
    }

    #[test]
    fn test_har_build() {
        let entries = vec![HarEntry {
            started_datetime: "2024-01-01T00:00:00Z".to_string(),
            time_ms: 12.5,
            request: HarRequest {
                method: "GET".to_string(),
                url: "http://example.com/".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HarNameValue {
                    name: "Host".to_string(),
                    value: "example.com".to_string(),
                }],
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                body_size: 100,
                content: HarContent {
                    size: 100,
                    mime_type: "text/html".to_string(),
                },
            },
            server_ip_address: "93.184.216.34".to_string(),
            connection: "1".to_string(),
        }];
        let har = build_har(&entries);
        assert!(har.contains("\"version\":\"1.2\""));
        assert!(har.contains("GET"));
        assert!(har.contains("example.com"));
    }

    #[test]
    fn test_conn_stats_csv_header() {
        assert!(ConnStats::csv_header().starts_with("key,protocol"));
    }

    #[test]
    fn test_tls_client_hello_parse_minimal() {
        // Build a minimal ClientHello
        let mut data = vec![
            0x16, // content type: Handshake
            0x03, 0x01, // record version TLS 1.0
            0x00, 0x2f, // record length (placeholder, not validated strictly)
            0x01, // HandshakeType: ClientHello
            0x00, 0x00, 0x2b, // length
            0x03, 0x03, // client version TLS 1.2
        ];
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // session ID length = 0
        data.extend_from_slice(&[0, 4]); // cipher suites length = 4
        data.extend_from_slice(&[0x00, 0x2f, 0x00, 0x35]); // TLS_RSA_WITH_AES_128/256
        data.push(1);
        data.push(0); // compression methods: 1 byte = null
        data.extend_from_slice(&[0, 0]); // extensions length = 0
        let hello = parse_tls_client_hello(&data);
        assert!(hello.is_some());
        let h = hello.unwrap();
        assert_eq!(h.client_version, 0x0303);
        assert_eq!(h.cipher_suites, vec![0x002f, 0x0035]);
    }
}





