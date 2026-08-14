//! PCAP and PCAPNG file reader.
//!
//! Supports the legacy libpcap format (magic 0xa1b2c3d4 / 0xd4c3b2a1 for
//! byte-swapped) and the modern pcapng block-based format.  Both are parsed
//! from byte slices or via an incremental pull interface that can drive an
//! `std::io::Read` source.

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapReadError {
    UnexpectedEof,
    BadMagic(u32),
    UnsupportedVersion(u16, u16),
    BadBlockLength { expected: usize, got: usize },
    CorruptBlock(String),
    Io(String),
    SnaplenTooLarge(u32),
    LinkTypeUnknown(u16),
    TruncatedPacket { available: usize, claimed: usize },
}

impl std::fmt::Display for PcapReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of file"),
            Self::BadMagic(m) => write!(f, "bad magic number: 0x{m:08x}"),
            Self::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported PCAP version {maj}.{min}")
            }
            Self::BadBlockLength { expected, got } => {
                write!(f, "block length mismatch: expected {expected} got {got}")
            }
            Self::CorruptBlock(s) => write!(f, "corrupt block: {s}"),
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::SnaplenTooLarge(s) => write!(f, "snaplen too large: {s}"),
            Self::LinkTypeUnknown(t) => write!(f, "unknown link type: {t}"),
            Self::TruncatedPacket { available, claimed } => {
                write!(f, "truncated packet: {available} bytes available, {claimed} claimed")
            }
        }
    }
}

impl std::error::Error for PcapReadError {}

impl From<io::Error> for PcapReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── Link types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum LinkType {
    Null = 0,
    Ethernet = 1,
    Ieee80211 = 105,
    RawIp = 101,
    LinuxSll = 113,
    LinuxSll2 = 276,
    Ieee80211RadioTap = 127,
    Ppp = 9,
    Unknown(u16),
}

impl LinkType {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Ethernet,
            9 => Self::Ppp,
            101 => Self::RawIp,
            105 => Self::Ieee80211,
            113 => Self::LinuxSll,
            127 => Self::Ieee80211RadioTap,
            276 => Self::LinuxSll2,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn header_len(self) -> usize {
        match self {
            Self::Ethernet => 14,
            Self::Null => 4,
            Self::LinuxSll => 16,
            Self::LinuxSll2 => 20,
            Self::Ieee80211RadioTap => 8, // variable; 8 is the fixed header prefix
            _ => 0,
        }
    }
}

// ─── Timestamp ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    pub secs: u32,
    pub usecs: u32,
}

impl Timestamp {
    #[must_use] 
    pub const fn new(secs: u32, usecs: u32) -> Self {
        Self { secs, usecs }
    }

    #[must_use] 
    pub fn as_f64(self) -> f64 {
        f64::from(self.secs) + f64::from(self.usecs) / 1_000_000.0
    }

    #[must_use] 
    pub fn delta_micros(self, other: Self) -> i64 {
        let a = i64::from(self.secs) * 1_000_000 + i64::from(self.usecs);
        let b = i64::from(other.secs) * 1_000_000 + i64::from(other.usecs);
        a - b
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:06}", self.secs, self.usecs)
    }
}

// ─── Raw packet ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {
    pub ts: Timestamp,
    /// Number of bytes actually present (may be less than `orig_len` when capture
    /// was limited by snaplen).
    pub cap_len: u32,
    /// Original packet length on the wire.
    pub orig_len: u32,
    /// Link-layer header type for this specific packet (important for pcapng IDB).
    pub link_type: LinkType,
    /// Packet data as captured (up to `cap_len` bytes).
    pub data: Vec<u8>,
    /// Interface index (from pcapng, 0 for legacy pcap).
    pub if_index: u32,
    /// Optional comment from pcapng EPB/SPB option.
    pub comment: Option<String>,
}

impl RawPacket {
    #[must_use] 
    pub const fn is_truncated(&self) -> bool {
        self.cap_len < self.orig_len
    }

    #[must_use] 
    pub fn payload_after_link_header(&self) -> &[u8] {
        let skip = self.link_type.header_len().min(self.data.len());
        &self.data[skip..]
    }
}

// ─── PCAP global header ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapFileHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: LinkType,
    pub byte_swapped: bool,
}

// ─── Interface descriptor (pcapng) ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDescriptor {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub os: Option<String>,
    pub tsresol: u8, // pcapng option 9: timestamp resolution
    pub filter_bpf: Option<Vec<u8>>,
}

impl InterfaceDescriptor {
    #[must_use] 
    pub fn ts_factor(&self) -> u64 {
        // tsresol: high bit 0 → base 10, high bit 1 → base 2; lower 7 bits = exponent.
        if self.tsresol & 0x80 == 0 {
            let exp = u32::from(self.tsresol & 0x7f);
            10u64.pow(exp)
        } else {
            let exp = u32::from(self.tsresol & 0x7f);
            2u64.pow(exp)
        }
    }
}

// ─── Reader state ─────────────────────────────────────────────────────────────

pub enum FileFormat {
    LegacyPcap(PcapFileHeader),
    Pcapng,
}

pub struct PcapReader {
    format: FileFormat,
    interfaces: Vec<InterfaceDescriptor>,
    packet_count: u64,
    /// Cumulative byte offset into the underlying stream.
    byte_offset: u64,
}

// ─── Little/big endian helpers ────────────────────────────────────────────────

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}
fn read_u16_be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1; // byte-swapped
const PCAP_MAGIC_NS_LE: u32 = 0xa1b2_3c4d; // nanosecond variant
const PCAP_MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

const PCAPNG_SHB_TYPE: u32 = 0x0A0D_0D0A;
const PCAPNG_IDB_TYPE: u32 = 0x0000_0001;
const PCAPNG_EPB_TYPE: u32 = 0x0000_0006;
const PCAPNG_SPB_TYPE: u32 = 0x0000_0003;
const PCAPNG_OBS_TYPE: u32 = 0x0000_0002; // Obsolete Packet Block

impl PcapReader {
    // ─── Public constructors ──────────────────────────────────────────────

    /// Parse a full in-memory PCAP or PCAPNG byte slice.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, Vec<RawPacket>), PcapReadError> {
        if data.len() < 4 {
            return Err(PcapReadError::UnexpectedEof);
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == PCAPNG_SHB_TYPE {
            Self::parse_pcapng(data)
        } else {
            Self::parse_legacy(data)
        }
    }

    /// Streaming constructor: reads the file header from a reader, returns a reader
    /// ready to call `read_packet` in a loop.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn open<R: Read>(mut r: R) -> Result<Self, PcapReadError> {
        let mut header_buf = [0u8; 4];
        r.read_exact(&mut header_buf)?;
        let magic = u32::from_le_bytes(header_buf);
        if magic == PCAPNG_SHB_TYPE {
            // We need to buffer the whole SHB — read all remaining bytes.
            let mut rest = Vec::new();
            r.read_to_end(&mut rest)?;
            let mut all = header_buf.to_vec();
            all.extend_from_slice(&rest);
            let (reader, _packets) = Self::parse_pcapng(&all)?;
            Ok(reader)
        } else {
            let mut rest = [0u8; 20]; // remaining 20 bytes of 24-byte global header
            r.read_exact(&mut rest)?;
            let mut buf = Vec::with_capacity(24);
            buf.extend_from_slice(&header_buf);
            buf.extend_from_slice(&rest);
            Self::parse_legacy_header(&buf)
        }
    }

    // ─── Legacy PCAP ──────────────────────────────────────────────────────

    fn parse_legacy_header(buf: &[u8]) -> Result<Self, PcapReadError> {
        if buf.len() < 24 {
            return Err(PcapReadError::UnexpectedEof);
        }
        let magic = read_u32_le(buf, 0);
        let swapped = match magic {
            PCAP_MAGIC_LE | PCAP_MAGIC_NS_LE => false,
            PCAP_MAGIC_BE | PCAP_MAGIC_NS_BE => true,
            other => return Err(PcapReadError::BadMagic(other)),
        };
        let (ver_maj, ver_min, snaplen, network_raw) = if swapped {
            (
                read_u16_be(buf, 4),
                read_u16_be(buf, 6),
                read_u32_be(buf, 16),
                read_u32_be(buf, 20),
            )
        } else {
            (
                read_u16_le(buf, 4),
                read_u16_le(buf, 6),
                read_u32_le(buf, 16),
                read_u32_le(buf, 20),
            )
        };
        if ver_maj != 2 {
            return Err(PcapReadError::UnsupportedVersion(ver_maj, ver_min));
        }
        if snaplen > 262_144 {
            return Err(PcapReadError::SnaplenTooLarge(snaplen));
        }
        let link_type = LinkType::from_u16(u16::try_from(network_raw).unwrap_or(u16::MAX));
        let hdr = PcapFileHeader {
            magic,
            version_major: ver_maj,
            version_minor: ver_min,
            thiszone: if swapped {
                read_u32_be(buf, 8).cast_signed()
            } else {
                read_u32_le(buf, 8).cast_signed()
            },
            sigfigs: if swapped {
                read_u32_be(buf, 12)
            } else {
                read_u32_le(buf, 12)
            },
            snaplen,
            network: link_type,
            byte_swapped: swapped,
        };
        let iface = InterfaceDescriptor {
            link_type,
            snap_len: snaplen,
            name: None,
            description: None,
            os: None,
            tsresol: 6, // microseconds by default
            filter_bpf: None,
        };
        Ok(Self {
            format: FileFormat::LegacyPcap(hdr),
            interfaces: vec![iface],
            packet_count: 0,
            byte_offset: 24,
        })
    }

    fn parse_legacy(data: &[u8]) -> Result<(Self, Vec<RawPacket>), PcapReadError> {
        let reader = Self::parse_legacy_header(data)?;
        let swapped = matches!(&reader.format, FileFormat::LegacyPcap(h) if h.byte_swapped);
        let link_type = reader.interfaces[0].link_type;
        let mut pos: usize = 24;
        let mut packets = Vec::new();
        while pos + 16 <= data.len() {
            let (ts_sec, ts_usec, incl_len, orig_len) = if swapped {
                (
                    read_u32_be(data, pos),
                    read_u32_be(data, pos + 4),
                    read_u32_be(data, pos + 8),
                    read_u32_be(data, pos + 12),
                )
            } else {
                (
                    read_u32_le(data, pos),
                    read_u32_le(data, pos + 4),
                    read_u32_le(data, pos + 8),
                    read_u32_le(data, pos + 12),
                )
            };
            pos += 16;
            let end = pos + incl_len as usize;
            if end > data.len() {
                return Err(PcapReadError::TruncatedPacket {
                    available: data.len() - pos,
                    claimed: incl_len as usize,
                });
            }
            packets.push(RawPacket {
                ts: Timestamp::new(ts_sec, ts_usec),
                cap_len: incl_len,
                orig_len,
                link_type,
                data: data[pos..end].to_vec(),
                if_index: 0,
                comment: None,
            });
            pos = end;
        }
        Ok((reader, packets))
    }

    // ─── PCAPNG ───────────────────────────────────────────────────────────

    fn parse_pcapng(data: &[u8]) -> Result<(Self, Vec<RawPacket>), PcapReadError> {
        let mut pos = 0usize;
        let mut interfaces: Vec<InterfaceDescriptor> = Vec::new();
        let mut packets: Vec<RawPacket> = Vec::new();
        let mut byte_order_magic_checked = false;
        let mut little_endian = true;

        while pos + 12 <= data.len() {
            let block_type = read_u32_le(data, pos);
            // Determine endianness from SHB byte-order magic.
            if block_type == PCAPNG_SHB_TYPE {
                if pos + 12 > data.len() {
                    break;
                }
                let bom = read_u32_le(data, pos + 8);
                little_endian = bom == 0x1A2B_3C4D;
                byte_order_magic_checked = true;
            } else if !byte_order_magic_checked {
                return Err(PcapReadError::CorruptBlock(
                    "first block must be SHB".to_string(),
                ));
            }

            let block_len = if little_endian {
                read_u32_le(data, pos + 4)
            } else {
                read_u32_be(data, pos + 4)
            } as usize;

            if block_len < 12 || pos + block_len > data.len() {
                return Err(PcapReadError::BadBlockLength {
                    expected: block_len,
                    got: data.len() - pos,
                });
            }

            let block_data = &data[pos..pos + block_len];

            match block_type {
                PCAPNG_IDB_TYPE => {
                    let idb = Self::parse_idb(block_data, little_endian)?;
                    interfaces.push(idb);
                }
                PCAPNG_EPB_TYPE => {
                    let (pkt, if_idx) =
                        Self::parse_epb(block_data, little_endian, &interfaces)?;
                    let _ = if_idx;
                    packets.push(pkt);
                }
                PCAPNG_SPB_TYPE => {
                    if let Some(iface) = interfaces.first() {
                        let pkt = Self::parse_spb(block_data, little_endian, iface)?;
                        packets.push(pkt);
                    }
                }
                PCAPNG_OBS_TYPE => {
                    if let Some(iface) = interfaces.first() {
                        let pkt =
                            Self::parse_obs(block_data, little_endian, iface)?;
                        packets.push(pkt);
                    }
                }
                _ => {
                    // Unknown block — skip it.
                }
            }

            pos += block_len;
        }

        let reader = Self {
            format: FileFormat::Pcapng,
            interfaces,
            packet_count: packets.len() as u64,
            byte_offset: data.len() as u64,
        };
        Ok((reader, packets))
    }

    fn parse_idb(block: &[u8], le: bool) -> Result<InterfaceDescriptor, PcapReadError> {
        if block.len() < 20 {
            return Err(PcapReadError::CorruptBlock("IDB too short".to_string()));
        }
        let link_type_raw = if le {
            read_u16_le(block, 8)
        } else {
            read_u16_be(block, 8)
        };
        let snap_len = if le {
            read_u32_le(block, 12)
        } else {
            read_u32_be(block, 12)
        };
        let link_type = LinkType::from_u16(link_type_raw);
        let mut iface = InterfaceDescriptor {
            link_type,
            snap_len,
            name: None,
            description: None,
            os: None,
            tsresol: 6,
            filter_bpf: None,
        };
        // Parse options (start at offset 16, end at block_len - 4)
        let opts_end = block.len() - 4;
        let mut op = 16usize;
        while op + 4 <= opts_end {
            let opt_code = if le {
                read_u16_le(block, op)
            } else {
                read_u16_be(block, op)
            };
            let opt_len = if le {
                read_u16_le(block, op + 2)
            } else {
                read_u16_be(block, op + 2)
            } as usize;
            op += 4;
            if op + opt_len > opts_end {
                break;
            }
            let opt_data = &block[op..op + opt_len];
            match opt_code {
                0 => break, // opt_endofopt
                2 => iface.name = Some(String::from_utf8_lossy(opt_data).into_owned()),
                3 => iface.description = Some(String::from_utf8_lossy(opt_data).into_owned()),
                9 if !opt_data.is_empty() => iface.tsresol = opt_data[0],
                11 => iface.filter_bpf = Some(opt_data.to_vec()),
                12 => iface.os = Some(String::from_utf8_lossy(opt_data).into_owned()),
                _ => {}
            }
            // options are 32-bit aligned
            let padded = (opt_len + 3) & !3;
            op = match op.checked_add(padded) {
                Some(v) => v,
                None => break,
            };
        }
        Ok(iface)
    }

    fn parse_epb(
        block: &[u8],
        le: bool,
        interfaces: &[InterfaceDescriptor],
    ) -> Result<(RawPacket, u32), PcapReadError> {
        if block.len() < 28 {
            return Err(PcapReadError::CorruptBlock("EPB too short".to_string()));
        }
        let if_idx = if le {
            read_u32_le(block, 8)
        } else {
            read_u32_be(block, 8)
        };
        let ts_high = u64::from(if le {
            read_u32_le(block, 12)
        } else {
            read_u32_be(block, 12)
        });
        let ts_low = u64::from(if le {
            read_u32_le(block, 16)
        } else {
            read_u32_be(block, 16)
        });
        let cap_len = if le {
            read_u32_le(block, 20)
        } else {
            read_u32_be(block, 20)
        };
        let orig_len = if le {
            read_u32_le(block, 24)
        } else {
            read_u32_be(block, 24)
        };
        let ts_raw = (ts_high << 32) | ts_low;

        let iface = interfaces.get(if_idx as usize);
        let (link_type, ts_factor) = iface
            .map_or((LinkType::Ethernet, 1_000_000), |i| (i.link_type, i.ts_factor()));

        // Use u128 intermediate to avoid overflow when ts_raw * 1_000_000 exceeds u64::MAX.
        let ts_usec = u64::try_from(u128::from(ts_raw) * 1_000_000 / u128::from(ts_factor)).unwrap_or(u64::MAX);
        let ts = Timestamp::new(u32::try_from(ts_usec / 1_000_000).unwrap_or(u32::MAX), (ts_usec % 1_000_000) as u32);

        let data_start = 28usize;
        let data_end = data_start + cap_len as usize;
        if data_end > block.len() {
            return Err(PcapReadError::TruncatedPacket {
                available: block.len() - data_start,
                claimed: cap_len as usize,
            });
        }
        let data = block[data_start..data_end].to_vec();

        // Parse options after packet data (padded to 32-bit boundary).
        let padded_cap = (cap_len as usize + 3) & !3;
        let opts_start = data_start + padded_cap;
        let opts_end = block.len() - 4;
        let mut comment: Option<String> = None;
        if opts_start + 4 <= opts_end {
            let mut op = opts_start;
            while op + 4 <= opts_end {
                let opt_code = if le {
                    read_u16_le(block, op)
                } else {
                    read_u16_be(block, op)
                };
                let opt_len = if le {
                    read_u16_le(block, op + 2)
                } else {
                    read_u16_be(block, op + 2)
                } as usize;
                op += 4;
                if op + opt_len > opts_end {
                    break;
                }
                if opt_code == 0 {
                    break;
                }
                if opt_code == 1 {
                    comment =
                        Some(String::from_utf8_lossy(&block[op..op + opt_len]).into_owned());
                }
                let padded_opt = (opt_len + 3) & !3;
                op = match op.checked_add(padded_opt) {
                    Some(v) => v,
                    None => break,
                };
            }
        }

        Ok((
            RawPacket {
                ts,
                cap_len,
                orig_len,
                link_type,
                data,
                if_index: if_idx,
                comment,
            },
            if_idx,
        ))
    }

    fn parse_spb(
        block: &[u8],
        le: bool,
        iface: &InterfaceDescriptor,
    ) -> Result<RawPacket, PcapReadError> {
        if block.len() < 20 {
            return Err(PcapReadError::CorruptBlock("SPB too short".to_string()));
        }
        let orig_len = if le {
            read_u32_le(block, 8)
        } else {
            read_u32_be(block, 8)
        };
        let cap_len = orig_len.min(iface.snap_len);
        let data_end = 12 + cap_len as usize;
        if data_end > block.len() {
            return Err(PcapReadError::TruncatedPacket {
                available: block.len() - 12,
                claimed: cap_len as usize,
            });
        }
        Ok(RawPacket {
            ts: Timestamp::new(0, 0),
            cap_len,
            orig_len,
            link_type: iface.link_type,
            data: block[12..data_end].to_vec(),
            if_index: 0,
            comment: None,
        })
    }

    fn parse_obs(
        block: &[u8],
        le: bool,
        iface: &InterfaceDescriptor,
    ) -> Result<RawPacket, PcapReadError> {
        if block.len() < 28 {
            return Err(PcapReadError::CorruptBlock("OBS too short".to_string()));
        }
        let ts_high = u64::from(if le {
            read_u32_le(block, 8)
        } else {
            read_u32_be(block, 8)
        });
        let ts_low = u64::from(if le {
            read_u32_le(block, 12)
        } else {
            read_u32_be(block, 12)
        });
        let cap_len = if le {
            read_u32_le(block, 16)
        } else {
            read_u32_be(block, 16)
        };
        let orig_len = if le {
            read_u32_le(block, 20)
        } else {
            read_u32_be(block, 20)
        };
        let _snap_len = if le {
            read_u32_le(block, 24)
        } else {
            read_u32_be(block, 24)
        };
        let ts_raw = (ts_high << 32) | ts_low;
        let ts_usec = u64::try_from(u128::from(ts_raw) * 1_000_000 / u128::from(iface.ts_factor())).unwrap_or(u64::MAX);
        let ts = Timestamp::new(u32::try_from(ts_usec / 1_000_000).unwrap_or(u32::MAX), (ts_usec % 1_000_000) as u32);
        let data_end = 28 + cap_len as usize;
        if data_end > block.len() {
            return Err(PcapReadError::TruncatedPacket {
                available: block.len() - 28,
                claimed: cap_len as usize,
            });
        }
        Ok(RawPacket {
            ts,
            cap_len,
            orig_len,
            link_type: iface.link_type,
            data: block[28..data_end].to_vec(),
            if_index: 0,
            comment: None,
        })
    }

    // ─── Public accessors ─────────────────────────────────────────────────

    #[must_use] 
    pub fn interfaces(&self) -> &[InterfaceDescriptor] {
        &self.interfaces
    }

    #[must_use] 
    pub const fn packet_count(&self) -> u64 {
        self.packet_count
    }

    #[must_use] 
    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    #[must_use] 
    pub fn link_type(&self) -> Option<LinkType> {
        self.interfaces.first().map(|i| i.link_type)
    }

    #[must_use] 
    pub const fn is_pcapng(&self) -> bool {
        matches!(self.format, FileFormat::Pcapng)
    }
}

// ─── Metadata summary ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapSummary {
    pub format: String,
    pub interface_count: usize,
    pub packet_count: u64,
    pub first_ts: Option<Timestamp>,
    pub last_ts: Option<Timestamp>,
    pub duration_secs: f64,
    pub total_bytes: u64,
    pub link_types: Vec<String>,
}

#[must_use] 
pub fn summarize_packets(reader: &PcapReader, packets: &[RawPacket]) -> PcapSummary {
    let format = if reader.is_pcapng() {
        "pcapng".to_string()
    } else {
        "pcap".to_string()
    };
    let first_ts = packets.first().map(|p| p.ts);
    let last_ts = packets.last().map(|p| p.ts);
    let duration_secs = match (first_ts, last_ts) {
        (Some(f), Some(l)) => (l.delta_micros(f).abs() as f64) / 1_000_000.0,
        _ => 0.0,
    };
    let total_bytes: u64 = packets.iter().map(|p| u64::from(p.cap_len)).sum();
    let mut lt_set: std::collections::HashSet<String> = std::collections::HashSet::default();
    for p in packets {
        lt_set.insert(format!("{:?}", p.link_type));
    }
    PcapSummary {
        format,
        interface_count: reader.interfaces().len(),
        packet_count: packets.len() as u64,
        first_ts,
        last_ts,
        duration_secs,
        total_bytes,
        link_types: lt_set.into_iter().collect(),
    }
}

// ─── Convenience builder for synthetic test data ──────────────────────────────

pub struct PcapBuilder {
    packets: Vec<RawPacket>,
    link_type: LinkType,
    current_time: Timestamp,
}

impl PcapBuilder {
    #[must_use] 
    pub const fn new(link_type: LinkType) -> Self {
        Self {
            packets: Vec::new(),
            link_type,
            current_time: Timestamp::new(1_700_000_000, 0),
        }
    }

    pub fn add_packet(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        let d = data.into();
        let len = u32::try_from(d.len()).unwrap_or(u32::MAX);
        self.packets.push(RawPacket {
            ts: self.current_time,
            cap_len: len,
            orig_len: len,
            link_type: self.link_type,
            data: d,
            if_index: 0,
            comment: None,
        });
        self.current_time.usecs += 1000;
        if self.current_time.usecs >= 1_000_000 {
            self.current_time.usecs = 0;
            self.current_time.secs += 1;
        }
        self
    }

    #[must_use] 
    pub fn build(self) -> Vec<RawPacket> {
        self.packets
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_legacy_pcap(packets: &[(&[u8], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        // Global header
        out.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // major
        out.extend_from_slice(&4u16.to_le_bytes()); // minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB = 1
        for (data, orig) in packets {
            let incl = u32::try_from(data.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&1000u32.to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            out.extend_from_slice(&incl.to_le_bytes());
            out.extend_from_slice(&orig.to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn test_legacy_empty() {
        let raw = make_legacy_pcap(&[]);
        let (reader, pkts) = PcapReader::from_bytes(&raw).unwrap();
        assert!(!reader.is_pcapng());
        assert_eq!(pkts.len(), 0);
        assert_eq!(reader.link_type(), Some(LinkType::Ethernet));
    }

    #[test]
    fn test_legacy_single_packet() {
        let payload = vec![0xffu8; 14];
        let raw = make_legacy_pcap(&[(&payload, 60)]);
        let (_reader, pkts) = PcapReader::from_bytes(&raw).unwrap();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].cap_len, 14);
        assert_eq!(pkts[0].orig_len, 60);
        assert!(pkts[0].is_truncated());
    }

    #[test]
    fn test_legacy_multiple_packets() {
        let p1 = vec![0xaau8; 20];
        let p2 = vec![0xbbu8; 30];
        let raw = make_legacy_pcap(&[(&p1, 20), (&p2, 30)]);
        let (_r, pkts) = PcapReader::from_bytes(&raw).unwrap();
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].data, p1);
        assert_eq!(pkts[1].data, p2);
    }

    #[test]
    fn test_bad_magic() {
        let mut data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        data.resize(24, 0);
        assert!(matches!(
            PcapReader::from_bytes(&data),
            Err(PcapReadError::BadMagic(0xEFBE_ADDE))
        ));
    }

    #[test]
    fn test_too_short() {
        assert!(matches!(
            PcapReader::from_bytes(&[]),
            Err(PcapReadError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_timestamp_delta() {
        let a = Timestamp::new(100, 500_000);
        let b = Timestamp::new(100, 0);
        assert_eq!(a.delta_micros(b), 500_000);
    }

    #[test]
    fn test_timestamp_display() {
        let t = Timestamp::new(1, 123_456);
        assert_eq!(t.to_string(), "1.123456");
    }

    #[test]
    fn test_link_type_header_len() {
        assert_eq!(LinkType::Ethernet.header_len(), 14);
        assert_eq!(LinkType::Null.header_len(), 4);
        assert_eq!(LinkType::RawIp.header_len(), 0);
    }

    #[test]
    fn test_link_type_round_trip() {
        assert_eq!(LinkType::from_u16(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_u16(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_u16(999), LinkType::Unknown(999));
    }

    #[test]
    fn test_pcap_builder() {
        let mut b = PcapBuilder::new(LinkType::Ethernet);
        b.add_packet(vec![0u8; 60]);
        b.add_packet(vec![1u8; 40]);
        let pkts = b.build();
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].cap_len, 60);
        assert_eq!(pkts[1].ts.usecs, 1000);
    }

    #[test]
    fn test_summary() {
        let p1 = vec![0u8; 14];
        let p2 = vec![0u8; 60];
        let raw = make_legacy_pcap(&[(&p1, 14), (&p2, 60)]);
        let (reader, pkts) = PcapReader::from_bytes(&raw).unwrap();
        let s = summarize_packets(&reader, &pkts);
        assert_eq!(s.format, "pcap");
        assert_eq!(s.packet_count, 2);
        assert_eq!(s.total_bytes, 74);
    }

    #[test]
    fn test_idb_tsresol_base10() {
        let iface = InterfaceDescriptor {
            link_type: LinkType::Ethernet,
            snap_len: 65535,
            name: None,
            description: None,
            os: None,
            tsresol: 6,
            filter_bpf: None,
        };
        assert_eq!(iface.ts_factor(), 1_000_000);
    }

    #[test]
    fn test_idb_tsresol_base2() {
        let iface = InterfaceDescriptor {
            link_type: LinkType::Ethernet,
            snap_len: 65535,
            name: None,
            description: None,
            os: None,
            tsresol: 0x80 | 10, // base-2, 2^10 = 1024
            filter_bpf: None,
        };
        assert_eq!(iface.ts_factor(), 1024);
    }

    #[test]
    fn test_truncated_packet() {
        let mut raw = make_legacy_pcap(&[]);
        // Append a packet record claiming 100 bytes but only providing 10
        raw.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        raw.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        raw.extend_from_slice(&100u32.to_le_bytes()); // incl_len
        raw.extend_from_slice(&100u32.to_le_bytes()); // orig_len
        raw.extend_from_slice(&[0u8; 10]); // only 10 bytes
        assert!(matches!(
            PcapReader::from_bytes(&raw),
            Err(PcapReadError::TruncatedPacket { available: 10, claimed: 100 })
        ));
    }

    #[test]
    fn test_payload_after_link_header_ethernet() {
        let mut data = vec![0u8; 14]; // ethernet header
        data.extend_from_slice(&[0x45, 0x00]); // start of IP header
        let pkt = RawPacket {
            ts: Timestamp::new(0, 0),
            cap_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
            orig_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
            link_type: LinkType::Ethernet,
            data,
            if_index: 0,
            comment: None,
        };
        let payload = pkt.payload_after_link_header();
        assert_eq!(payload[0], 0x45);
    }
}
