//! Read PCAPNG files: IDB/EPB/SPB/NRB block parsing with full option support.
//!
//! Provides a streaming block iterator and high-level accessors for interface
//! descriptions, enhanced packets, simple packets, and name resolution records.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Block type codes ─────────────────────────────────────────────────────────

const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const BT_SPB: u32 = 0x0000_0003;
const BT_NRB: u32 = 0x0000_0004;
const BT_ISB: u32 = 0x0000_0005;
const BT_OPB: u32 = 0x0000_0002;

/// BOM value that signals little-endian section.
const PCAPNG_BOM_LE: u32 = 0x1A2B_3C4D;
/// BOM value that signals big-endian section.
const PCAPNG_BOM_BE: u32 = 0x4D3C_2B1A;

// ─── Link type ────────────────────────────────────────────────────────────────

/// PCAPNG link-layer type (DLT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkType(pub u16);

impl LinkType {
    pub const ETHERNET: Self = Self(1);
    pub const RAW: Self = Self(101);
    pub const LINUX_SLL: Self = Self(113);
    pub const IPV4: Self = Self(228);
    pub const IPV6: Self = Self(229);

    #[must_use] 
    pub const fn as_u16(self) -> u16 { self.0 }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "Ethernet"),
            101 => write!(f, "Raw"),
            113 => write!(f, "Linux SLL"),
            228 => write!(f, "IPv4"),
            229 => write!(f, "IPv6"),
            n => write!(f, "LinkType({n})"),
        }
    }
}

// ─── Option codes ─────────────────────────────────────────────────────────────

/// PCAPNG option code → value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapNgOption {
    pub code: u16,
    pub value: Vec<u8>,
}

impl PcapNgOption {
    /// Return the option value as a UTF-8 string, trimming NUL bytes.
    #[must_use] 
    pub fn as_str(&self) -> Option<&str> {
        let bytes = self.value.iter().position(|&b| b == 0)
            .map_or(self.value.as_slice(), |end| &self.value[..end]);
        std::str::from_utf8(bytes).ok()
    }
}

// ─── InterfaceDesc ────────────────────────────────────────────────────────────

/// Interface Description Block (IDB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDesc {
    /// Zero-based interface index within this section.
    pub if_id: u32,
    /// Link-layer type.
    pub link_type: LinkType,
    /// Snap length (0 = no limit).
    pub snap_len: u32,
    /// Options (`if_name`, `if_description`, `if_tsresol`, …).
    pub options: Vec<PcapNgOption>,
}

impl InterfaceDesc {
    /// Return the interface name from options (opt code 2), if present.
    #[must_use] 
    pub fn name(&self) -> Option<&str> {
        self.options.iter().find(|o| o.code == 2).and_then(|o| o.as_str())
    }

    /// Return the timestamp resolution (`if_tsresol`, opt 9).
    /// Returns 6 (microseconds) if not set.
    #[must_use] 
    pub fn ts_resol(&self) -> u8 {
        self.options
            .iter()
            .find(|o| o.code == 9)
            .and_then(|o| o.value.first().copied())
            .unwrap_or(6)
    }

    /// Compute the timestamp scale factor (seconds per tick).
    #[must_use] 
    pub fn ts_scale(&self) -> f64 {
        let r = self.ts_resol();
        if r & 0x80 == 0 {
            10_f64.powi(-i32::from(r))
        } else {
            2_f64.powi(-i32::from(r & 0x7F))
        }
    }
}

// ─── EnhancedPacket ───────────────────────────────────────────────────────────

/// Enhanced Packet Block (EPB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPacket {
    /// Interface index.
    pub if_id: u32,
    /// Combined 64-bit raw timestamp.
    pub timestamp: u64,
    /// Captured length.
    pub cap_len: u32,
    /// Original (untruncated) length.
    pub orig_len: u32,
    /// Packet data (captured bytes only).
    pub data: Vec<u8>,
    /// Block options (`epb_flags`, `epb_hash`, …).
    pub options: Vec<PcapNgOption>,
}

impl EnhancedPacket {
    /// Convert raw timestamp to seconds using the given scale.
    #[must_use] 
    pub fn timestamp_secs(&self, ts_scale: f64) -> f64 {
        self.timestamp as f64 * ts_scale
    }

    /// Returns `true` if the packet was truncated.
    #[must_use] 
    pub const fn is_truncated(&self) -> bool {
        self.cap_len < self.orig_len
    }

    /// Return the EPB flags word from options (opt 2), if present.
    #[must_use] 
    pub fn flags(&self) -> Option<u32> {
        self.options
            .iter()
            .find(|o| o.code == 2)
            .filter(|o| o.value.len() >= 4)
            .map(|o| u32::from_le_bytes([o.value[0], o.value[1], o.value[2], o.value[3]]))
    }
}

impl fmt::Display for EnhancedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EPB if={} ts={} cap={} orig={}",
            self.if_id, self.timestamp, self.cap_len, self.orig_len
        )
    }
}

// ─── NameRecord ───────────────────────────────────────────────────────────────

/// A single record inside a Name Resolution Block (NRB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameRecord {
    /// Record type (1 = IPv4, 2 = IPv6, 0 = end).
    pub record_type: u16,
    /// Raw bytes: address bytes followed by NUL-terminated name(s).
    pub data: Vec<u8>,
}

impl NameRecord {
    /// Return the IPv4 address as a string, if this is a type-1 record.
    #[must_use] 
    pub fn ipv4_addr(&self) -> Option<String> {
        if self.record_type == 1 && self.data.len() >= 4 {
            Some(format!(
                "{}.{}.{}.{}",
                self.data[0], self.data[1], self.data[2], self.data[3]
            ))
        } else {
            None
        }
    }

    /// Return the hostname string (after the address bytes).
    #[must_use] 
    pub fn hostname(&self) -> Option<&str> {
        let skip = match self.record_type {
            1 => 4,
            2 => 16,
            _ => return None,
        };
        if self.data.len() <= skip {
            return None;
        }
        let name_bytes = &self.data[skip..];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        std::str::from_utf8(&name_bytes[..end]).ok()
    }
}

// ─── Block ────────────────────────────────────────────────────────────────────

/// Any PCAPNG block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Block {
    SectionHeader {
        byte_order_magic: u32,
        major: u16,
        minor: u16,
        section_length: i64,
        options: Vec<PcapNgOption>,
    },
    InterfaceDescription(InterfaceDesc),
    EnhancedPacket(EnhancedPacket),
    SimplePacket {
        orig_len: u32,
        data: Vec<u8>,
    },
    NameResolution {
        records: Vec<NameRecord>,
        options: Vec<PcapNgOption>,
    },
    InterfaceStats {
        if_id: u32,
        timestamp: u64,
        options: Vec<PcapNgOption>,
    },
    ObsoletePacket {
        if_id: u16,
        drops: u16,
        timestamp: u64,
        cap_len: u32,
        orig_len: u32,
        data: Vec<u8>,
    },
    Unknown {
        block_type: u32,
        data: Vec<u8>,
    },
}

impl Block {
    /// Return the block type code.
    #[must_use] 
    pub const fn block_type(&self) -> u32 {
        match self {
            Self::SectionHeader { .. } => BT_SHB,
            Self::InterfaceDescription(_) => BT_IDB,
            Self::EnhancedPacket(_) => BT_EPB,
            Self::SimplePacket { .. } => BT_SPB,
            Self::NameResolution { .. } => BT_NRB,
            Self::InterfaceStats { .. } => BT_ISB,
            Self::ObsoletePacket { .. } => BT_OPB,
            Self::Unknown { block_type, .. } => *block_type,
        }
    }

    /// Return true if this is an SHB block.
    #[must_use] 
    pub const fn is_shb(&self) -> bool { matches!(self, Self::SectionHeader { .. }) }
}

// ─── PcapngReader ─────────────────────────────────────────────────────────────

/// Read PCAPNG data from a byte buffer.
///
/// Supports multiple sections (multiple SHBs) and all standard block types.
pub struct PcapngReader<'a> {
    data: &'a [u8],
    pos: usize,
    le: bool,
    /// Interfaces registered in the current section.
    interfaces: Vec<InterfaceDesc>,
    next_if_id: u32,
}

impl<'a> PcapngReader<'a> {
    /// Create a new reader wrapping the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error string if the buffer does not start with a valid SHB.
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err("buffer too short for SHB".into());
        }
        // The first four bytes must be the SHB block type regardless of endianness.
        let bt = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if bt != BT_SHB {
            return Err(format!("first block is not SHB: 0x{bt:08x}"));
        }
        // Peek at the BOM inside the SHB body.
        let blen_le = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if blen_le < 16 || blen_le > data.len() {
            return Err("SHB block length invalid".into());
        }
        let bom = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let le = bom == PCAPNG_BOM_LE;
        if bom != PCAPNG_BOM_LE && bom != PCAPNG_BOM_BE {
            return Err(format!("bad byte order magic: 0x{bom:08x}"));
        }
        Ok(Self {
            data,
            pos: 0,
            le,
            interfaces: Vec::new(),
            next_if_id: 0,
        })
    }

    /// Return the current byte-order setting (true = little-endian).
    #[must_use] 
    pub const fn is_little_endian(&self) -> bool { self.le }

    /// Registered interfaces so far.
    #[must_use] 
    pub fn interfaces(&self) -> &[InterfaceDesc] { &self.interfaces }

    /// Read the next block, or `None` if the buffer is exhausted.
    pub fn next_block(&mut self) -> Option<Result<Block, String>> {
        if self.pos + 12 > self.data.len() {
            return None;
        }
        let bt = self.read_u32(self.pos);
        let blen = self.read_u32(self.pos + 4) as usize;
        if blen < 12 || self.pos + blen > self.data.len() {
            return Some(Err(format!(
                "block at {:#x}: invalid length {blen}",
                self.pos
            )));
        }
        // Validate trailing length.
        let trailing = self.read_u32(self.pos + blen - 4) as usize;
        if trailing != blen {
            return Some(Err(format!(
                "block at {:#x}: length mismatch head={blen} tail={trailing}",
                self.pos
            )));
        }
        let body = &self.data[self.pos + 8..self.pos + blen - 4];
        let result = self.parse_block(bt, body);
        self.pos += blen;
        Some(result)
    }

    /// Collect all blocks into a Vec.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn collect_blocks(&mut self) -> Result<Vec<Block>, String> {
        let mut blocks = Vec::new();
        while let Some(r) = self.next_block() {
            blocks.push(r?);
        }
        Ok(blocks)
    }

    /// Extract all enhanced packets.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn enhanced_packets(&mut self) -> Result<Vec<EnhancedPacket>, String> {
        let mut pkts = Vec::new();
        while let Some(r) = self.next_block() {
            if let Block::EnhancedPacket(epb) = r? {
                pkts.push(epb);
            }
        }
        Ok(pkts)
    }

    // ── Internal parsers ──────────────────────────────────────────────────────

    fn parse_block(&mut self, bt: u32, body: &[u8]) -> Result<Block, String> {
        match bt {
            BT_SHB => self.parse_shb(body),
            BT_IDB => self.parse_idb(body),
            BT_EPB => self.parse_epb(body),
            BT_SPB => self.parse_spb(body),
            BT_NRB => self.parse_nrb(body),
            BT_ISB => self.parse_isb(body),
            BT_OPB => self.parse_opb(body),
            _ => Ok(Block::Unknown { block_type: bt, data: body.to_vec() }),
        }
    }

    fn parse_shb(&mut self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 16 {
            return Err("SHB body too short".into());
        }
        let bom = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        self.le = bom == PCAPNG_BOM_LE;
        let major = self.read_u16_from(body, 4);
        let minor = self.read_u16_from(body, 6);
        let section_length = self.read_i64_from(body, 8);
        let options = parse_options_from(&body[16..], self.le);
        // Reset interface tracking for the new section.
        self.interfaces.clear();
        self.next_if_id = 0;
        Ok(Block::SectionHeader { byte_order_magic: bom, major, minor, section_length, options })
    }

    fn parse_idb(&mut self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 8 {
            return Err("IDB body too short".into());
        }
        let link_type = LinkType(self.read_u16_from(body, 0));
        let snap_len = self.read_u32_from(body, 4);
        let options = parse_options_from(&body[8..], self.le);
        let idb = InterfaceDesc {
            if_id: self.next_if_id,
            link_type,
            snap_len,
            options,
        };
        self.next_if_id += 1;
        self.interfaces.push(idb.clone());
        Ok(Block::InterfaceDescription(idb))
    }

    fn parse_epb(&self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 20 {
            return Err("EPB body too short".into());
        }
        let if_id = self.read_u32_from(body, 0);
        let ts_high = self.read_u32_from(body, 4);
        let ts_low = self.read_u32_from(body, 8);
        let cap_len = self.read_u32_from(body, 12);
        let orig_len = self.read_u32_from(body, 16);
        let timestamp = (u64::from(ts_high) << 32) | u64::from(ts_low);
        let data_end = 20 + cap_len as usize;
        if data_end > body.len() {
            return Err("EPB: packet data overruns block".into());
        }
        let data = body[20..data_end].to_vec();
        let aligned = (cap_len as usize + 3) & !3;
        let opts_off = 20 + aligned;
        let options = if opts_off < body.len() {
            parse_options_from(&body[opts_off..], self.le)
        } else {
            vec![]
        };
        Ok(Block::EnhancedPacket(EnhancedPacket { if_id, timestamp, cap_len, orig_len, data, options }))
    }

    fn parse_spb(&self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 4 {
            return Err("SPB body too short".into());
        }
        let orig_len = self.read_u32_from(body, 0);
        let data = body[4..].to_vec();
        Ok(Block::SimplePacket { orig_len, data })
    }

    fn parse_nrb(&self, body: &[u8]) -> Result<Block, String> {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos + 4 <= body.len() {
            let rtype = self.read_u16_from(body, pos);
            let rlen = self.read_u16_from(body, pos + 2) as usize;
            pos += 4;
            if rtype == 0 { break; }
            if pos + rlen > body.len() { break; }
            records.push(NameRecord { record_type: rtype, data: body[pos..pos + rlen].to_vec() });
            let padded = (rlen + 3) & !3;
            pos = match pos.checked_add(padded) {
                Some(v) => v,
                None => break,
            };
        }
        let options = if pos < body.len() { parse_options_from(&body[pos..], self.le) } else { vec![] };
        Ok(Block::NameResolution { records, options })
    }

    fn parse_isb(&self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 12 {
            return Err("ISB body too short".into());
        }
        let if_id = self.read_u32_from(body, 0);
        let ts_high = self.read_u32_from(body, 4);
        let ts_low = self.read_u32_from(body, 8);
        let timestamp = (u64::from(ts_high) << 32) | u64::from(ts_low);
        let options = parse_options_from(&body[12..], self.le);
        Ok(Block::InterfaceStats { if_id, timestamp, options })
    }

    fn parse_opb(&self, body: &[u8]) -> Result<Block, String> {
        if body.len() < 20 {
            return Err("OPB body too short".into());
        }
        let if_id = self.read_u16_from(body, 0);
        let drops = self.read_u16_from(body, 2);
        let ts_high = self.read_u32_from(body, 4);
        let ts_low = self.read_u32_from(body, 8);
        let timestamp = (u64::from(ts_high) << 32) | u64::from(ts_low);
        let cap_len = self.read_u32_from(body, 12);
        let orig_len = self.read_u32_from(body, 16);
        let data_end = 20 + cap_len as usize;
        let data = if data_end <= body.len() { body[20..data_end].to_vec() } else { vec![] };
        Ok(Block::ObsoletePacket { if_id, drops, timestamp, cap_len, orig_len, data })
    }

    // ── Byte-order–aware readers ──────────────────────────────────────────────

    fn read_u32(&self, off: usize) -> u32 {
        let b = &self.data[off..off + 4];
        if self.le { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
        else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
    }

    fn read_u32_from(&self, buf: &[u8], off: usize) -> u32 {
        let b = &buf[off..off + 4];
        if self.le { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
        else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
    }

    fn read_u16_from(&self, buf: &[u8], off: usize) -> u16 {
        let b = &buf[off..off + 2];
        if self.le { u16::from_le_bytes([b[0], b[1]]) }
        else { u16::from_be_bytes([b[0], b[1]]) }
    }

    fn read_i64_from(&self, buf: &[u8], off: usize) -> i64 {
        let b: [u8; 8] = buf[off..off + 8].try_into().unwrap();
        if self.le { i64::from_le_bytes(b) } else { i64::from_be_bytes(b) }
    }
}

// ─── Option parser ────────────────────────────────────────────────────────────

fn parse_options_from(buf: &[u8], le: bool) -> Vec<PcapNgOption> {
    let mut opts = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let code = if le {
            u16::from_le_bytes([buf[pos], buf[pos + 1]])
        } else {
            u16::from_be_bytes([buf[pos], buf[pos + 1]])
        };
        let len = if le {
            u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) as usize
        } else {
            u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize
        };
        pos += 4;
        if code == 0 { break; }
        if pos + len > buf.len() { break; }
        opts.push(PcapNgOption { code, value: buf[pos..pos + len].to_vec() });
        let padded = (len + 3) & !3;
        pos = match pos.checked_add(padded) {
            Some(v) => v,
            None => break,
        };
    }
    opts
}

// ─── block_iterator convenience ───────────────────────────────────────────────

/// Return an iterator over all blocks in a PCAPNG buffer.
///
/// The iterator yields `Result<Block, String>`.
///
/// ⚠ This returned `impl Iterator` and so erased [`BlockIter`], which kept the
/// concrete type — and therefore its accessors — unreachable. Returning the
/// concrete type is strictly more permissive: it still satisfies every caller
/// that only wanted an `Iterator`, and it lets one that holds the iterator ask
/// for the backing capture via [`BlockIter::data`].
pub fn block_iterator(data: &[u8]) -> BlockIter<'_> {
    BlockIter { reader: PcapngReader::new(data).ok(), data }
}

/// Iterator over the blocks of a PCAPNG buffer, as returned by
/// [`block_iterator`].
pub struct BlockIter<'a> {
    reader: Option<PcapngReader<'a>>,
    data: &'a [u8],
}

impl<'a> BlockIter<'a> {
    /// The whole capture buffer this iterator walks.
    ///
    /// ⚠ `data` was stored and never read: the field existed, was populated at
    /// construction, and nothing could observe it. A field that only costs
    /// memory is not a feature, so it is now readable — a caller that has an
    /// iterator can recover the backing bytes (to hash the capture, or to
    /// re-parse a block at a byte offset a `Block` reports) without threading
    /// the original slice alongside the iterator.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Length in bytes of the capture being walked.
    #[must_use]
    pub const fn capture_len(&self) -> usize {
        self.data.len()
    }
}

impl Iterator for BlockIter<'_> {
    type Item = Result<Block, String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.as_mut()?.next_block()
    }
}

// ─── High-level summary ───────────────────────────────────────────────────────

/// Summary statistics derived from a full PCAPNG parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapngSummary {
    pub interface_count: usize,
    pub packet_count: usize,
    pub total_captured_bytes: u64,
    pub total_original_bytes: u64,
    pub name_record_count: usize,
    pub interface_names: Vec<String>,
    pub link_types: Vec<u16>,
}

impl PcapngSummary {
    /// Build a summary from raw PCAPNG data.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let mut reader = PcapngReader::new(data)?;
        let mut summary = Self {
            interface_count: 0,
            packet_count: 0,
            total_captured_bytes: 0,
            total_original_bytes: 0,
            name_record_count: 0,
            interface_names: Vec::new(),
            link_types: Vec::new(),
        };
        while let Some(r) = reader.next_block() {
            match r? {
                Block::InterfaceDescription(idb) => {
                    summary.interface_count += 1;
                    summary.interface_names.push(
                        idb.name().unwrap_or("<unnamed>").to_string(),
                    );
                    summary.link_types.push(idb.link_type.as_u16());
                }
                Block::EnhancedPacket(epb) => {
                    summary.packet_count += 1;
                    summary.total_captured_bytes += u64::from(epb.cap_len);
                    summary.total_original_bytes += u64::from(epb.orig_len);
                }
                Block::SimplePacket { data, orig_len } => {
                    summary.packet_count += 1;
                    summary.total_captured_bytes += data.len() as u64;
                    summary.total_original_bytes += u64::from(orig_len);
                }
                Block::NameResolution { records, .. } => {
                    summary.name_record_count += records.len();
                }
                _ => {}
            }
        }
        Ok(summary)
    }
}

impl fmt::Display for PcapngSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PcapngSummary: ifaces={} pkts={} cap_bytes={} orig_bytes={}",
            self.interface_count,
            self.packet_count,
            self.total_captured_bytes,
            self.total_original_bytes,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PCAPNG buffer: SHB + IDB + EPB.
    fn minimal_pcapng() -> Vec<u8> {
        let mut buf = Vec::new();

        // SHB
        let shb_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&PCAPNG_BOM_LE.to_le_bytes()); // BOM
            b.extend_from_slice(&1u16.to_le_bytes());           // major
            b.extend_from_slice(&0u16.to_le_bytes());           // minor
            b.extend_from_slice(&(-1i64).to_le_bytes());        // section_length = -1
            b
        };
        write_block(&mut buf, BT_SHB, &shb_body);

        // IDB: Ethernet, snap 65535
        let idb_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&1u16.to_le_bytes()); // link_type Ethernet
            b.extend_from_slice(&0u16.to_le_bytes()); // reserved
            b.extend_from_slice(&65535u32.to_le_bytes()); // snap_len
            b
        };
        write_block(&mut buf, BT_IDB, &idb_body);

        // EPB: 4 bytes of data
        let epb_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes()); // if_id
            b.extend_from_slice(&0u32.to_le_bytes()); // ts_high
            b.extend_from_slice(&1000u32.to_le_bytes()); // ts_low
            b.extend_from_slice(&4u32.to_le_bytes()); // cap_len
            b.extend_from_slice(&4u32.to_le_bytes()); // orig_len
            b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // data
            b
        };
        write_block(&mut buf, BT_EPB, &epb_body);

        buf
    }

    fn write_block(buf: &mut Vec<u8>, bt: u32, body: &[u8]) {
        let total = 12 + body.len();
        buf.extend_from_slice(&bt.to_le_bytes());
        buf.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_le_bytes());
    }

    #[test]
    fn test_reader_creates_ok() {
        let data = minimal_pcapng();
        assert!(PcapngReader::new(&data).is_ok());
    }

    #[test]
    fn test_collect_blocks() {
        let data = minimal_pcapng();
        let mut reader = PcapngReader::new(&data).unwrap();
        let blocks = reader.collect_blocks().unwrap();
        assert_eq!(blocks.len(), 3);
        assert!(matches!(blocks[0], Block::SectionHeader { .. }));
        assert!(matches!(blocks[1], Block::InterfaceDescription(_)));
        assert!(matches!(blocks[2], Block::EnhancedPacket(_)));
    }

    #[test]
    fn test_epb_data() {
        let data = minimal_pcapng();
        let mut reader = PcapngReader::new(&data).unwrap();
        let blocks = reader.collect_blocks().unwrap();
        if let Block::EnhancedPacket(epb) = &blocks[2] {
            assert_eq!(epb.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(epb.cap_len, 4);
        } else {
            panic!("expected EPB");
        }
    }

    #[test]
    fn test_idb_link_type() {
        let data = minimal_pcapng();
        let mut reader = PcapngReader::new(&data).unwrap();
        let blocks = reader.collect_blocks().unwrap();
        if let Block::InterfaceDescription(idb) = &blocks[1] {
            assert_eq!(idb.link_type, LinkType::ETHERNET);
        } else {
            panic!("expected IDB");
        }
    }

    #[test]
    fn test_block_iterator() {
        let data = minimal_pcapng();
        let count = block_iterator(&data).count();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_summary() {
        let data = minimal_pcapng();
        let summary = PcapngSummary::from_bytes(&data).unwrap();
        assert_eq!(summary.interface_count, 1);
        assert_eq!(summary.packet_count, 1);
        assert_eq!(summary.total_captured_bytes, 4);
    }

    #[test]
    fn test_bad_magic_rejected() {
        let data = vec![0u8; 64];
        assert!(PcapngReader::new(&data).is_err());
    }

    #[test]
    fn test_name_record_ipv4() {
        let nr = NameRecord {
            record_type: 1,
            data: vec![192, 168, 1, 1, b'h', b'o', b's', b't', 0],
        };
        assert_eq!(nr.ipv4_addr(), Some("192.168.1.1".to_string()));
        assert_eq!(nr.hostname(), Some("host"));
    }
}
