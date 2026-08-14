//! `pcap_writer` — PCAP and PCAPNG file writers: global header, packet
//! records, nanosecond precision, and PCAPNG block-based writing.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// GlobalHeader — classic PCAP file header
// ---------------------------------------------------------------------------

/// Magic number for microsecond-precision PCAP (little-endian).
pub const PCAP_MAGIC_MICROSEC_LE: u32 = 0xA1B2_C3D4;
/// Magic number for nanosecond-precision PCAP (little-endian).
pub const PCAP_MAGIC_NANOSEC_LE: u32 = 0xA1B2_3C4D;
/// Magic number for microsecond-precision PCAP (big-endian).
pub const PCAP_MAGIC_MICROSEC_BE: u32 = 0xD4C3_B2A1;

/// Link-layer type identifiers.
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IEEE802_11: u32 = 105;

/// The 24-byte global header at the start of a PCAP file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

impl GlobalHeader {
    /// Create a standard microsecond-precision Ethernet header.
    #[must_use]
    pub const fn ethernet_microsec() -> Self {
        Self {
            magic_number: PCAP_MAGIC_MICROSEC_LE,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: LINKTYPE_ETHERNET,
        }
    }

    /// Create a nanosecond-precision raw IP header.
    #[must_use]
    pub const fn raw_nanosec() -> Self {
        Self {
            magic_number: PCAP_MAGIC_NANOSEC_LE,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: LINKTYPE_RAW,
        }
    }

    /// Whether this header uses nanosecond timestamps.
    #[must_use]
    pub const fn is_nanosec(&self) -> bool {
        self.magic_number == PCAP_MAGIC_NANOSEC_LE
    }

    /// Serialise to little-endian bytes (24 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&self.magic_number.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version_major.to_le_bytes());
        buf[6..8].copy_from_slice(&self.version_minor.to_le_bytes());
        buf[8..12].copy_from_slice(&self.thiszone.cast_unsigned().to_le_bytes());
        buf[12..16].copy_from_slice(&self.sigfigs.to_le_bytes());
        buf[16..20].copy_from_slice(&self.snaplen.to_le_bytes());
        buf[20..24].copy_from_slice(&self.network.to_le_bytes());
        buf
    }

    /// Parse from 24 bytes.
    #[must_use]
    pub const fn from_bytes(b: &[u8; 24]) -> Self {
        Self {
            magic_number: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            version_major: u16::from_le_bytes([b[4], b[5]]),
            version_minor: u16::from_le_bytes([b[6], b[7]]),
            thiszone: i32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            sigfigs: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            snaplen: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            network: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
        }
    }
}

impl fmt::Display for GlobalHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GlobalHeader(magic=0x{:08x} v{}.{} snaplen={} network={})",
            self.magic_number, self.version_major, self.version_minor, self.snaplen, self.network
        )
    }
}

// ---------------------------------------------------------------------------
// PacketRecord — a single captured packet
// ---------------------------------------------------------------------------

/// A PCAP packet record (16-byte header + payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

impl PacketRecord {
    /// Create a packet record with the current timestamp.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let (sec, usec) = current_time_usec();
        let orig_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self {
            ts_sec: sec,
            ts_usec: usec,
            orig_len,
            data,
        }
    }

    /// Create a packet record with a specific timestamp.
    #[must_use]
    pub const fn with_timestamp(data: Vec<u8>, ts_sec: u32, ts_usec: u32) -> Self {
        let orig_len = data.len() as u32;
        Self {
            ts_sec,
            ts_usec,
            orig_len,
            data,
        }
    }

    /// Number of captured bytes (may be truncated to snaplen).
    #[must_use]
    pub const fn captured_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Serialise to bytes (16 bytes header + payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.data.len());
        buf.extend_from_slice(&self.ts_sec.to_le_bytes());
        buf.extend_from_slice(&self.ts_usec.to_le_bytes());
        buf.extend_from_slice(&self.captured_len().to_le_bytes());
        buf.extend_from_slice(&self.orig_len.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse from bytes (assumes at least 16 bytes available).
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        let ts_sec = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let ts_usec = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let incl_len = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as usize;
        let orig_len = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        if b.len() < 16 + incl_len {
            return None;
        }
        Some(Self {
            ts_sec,
            ts_usec,
            orig_len,
            data: b[16..16 + incl_len].to_vec(),
        })
    }

    /// Timestamp as a `Duration` since the Unix epoch.
    #[must_use]
    pub fn timestamp(&self) -> Duration {
        Duration::new(u64::from(self.ts_sec), self.ts_usec * 1000)
    }
}

impl fmt::Display for PacketRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet({}.{:06} {}/{}B)",
            self.ts_sec,
            self.ts_usec,
            self.captured_len(),
            self.orig_len
        )
    }
}

// ---------------------------------------------------------------------------
// NanosecondPcap — high-precision packet record
// ---------------------------------------------------------------------------

/// A nanosecond-precision packet record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanosecondPcap {
    pub ts_sec: u32,
    pub ts_nsec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

impl NanosecondPcap {
    /// Create with current nanosecond timestamp.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let (sec, nsec) = current_time_nsec();
        let orig_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self {
            ts_sec: sec,
            ts_nsec: nsec,
            orig_len,
            data,
        }
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.data.len());
        buf.extend_from_slice(&self.ts_sec.to_le_bytes());
        buf.extend_from_slice(&self.ts_nsec.to_le_bytes());
        let incl = u32::try_from(self.data.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&incl.to_le_bytes());
        buf.extend_from_slice(&self.orig_len.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}

impl fmt::Display for NanosecondPcap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NsPkt({}.{:09} {}B)",
            self.ts_sec,
            self.ts_nsec,
            self.data.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PcapRecord — wrapper enum
// ---------------------------------------------------------------------------

/// A PCAP record: either a microsecond or nanosecond packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PcapRecord {
    Microsec(PacketRecord),
    Nanosec(NanosecondPcap),
}

impl PcapRecord {
    /// Raw data of the packet payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Microsec(p) => &p.data,
            Self::Nanosec(p) => &p.data,
        }
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Microsec(p) => p.to_bytes(),
            Self::Nanosec(p) => p.to_bytes(),
        }
    }

    /// Payload length.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.data().len()
    }
}

impl fmt::Display for PcapRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Microsec(p) => write!(f, "PcapRecord::Microsec({p})"),
            Self::Nanosec(p) => write!(f, "PcapRecord::Nanosec({p})"),
        }
    }
}

// ---------------------------------------------------------------------------
// PcapWriter — writes classic PCAP files
// ---------------------------------------------------------------------------

/// A PCAP file writer.
pub struct PcapWriter<W: Write> {
    writer: W,
    header: GlobalHeader,
    packet_count: u64,
    total_bytes: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new PCAP writer and write the global header.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(mut writer: W, header: GlobalHeader) -> io::Result<Self> {
        writer.write_all(&header.to_bytes())?;
        Ok(Self {
            writer,
            header,
            packet_count: 0,
            total_bytes: 0,
        })
    }

    /// Create a standard Ethernet microsecond writer.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn ethernet(writer: W) -> io::Result<Self> {
        Self::new(writer, GlobalHeader::ethernet_microsec())
    }

    /// Write a single packet record.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_packet(&mut self, record: &PacketRecord) -> io::Result<()> {
        let bytes = record.to_bytes();
        self.writer.write_all(&bytes)?;
        self.packet_count += 1;
        self.total_bytes += bytes.len() as u64;
        Ok(())
    }

    /// Write raw bytes as a packet (auto-timestamps).
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        let snaplen = self.header.snaplen as usize;
        let truncated = &data[..data.len().min(snaplen)];
        let rec = PacketRecord::with_timestamp(
            truncated.to_vec(),
            0,
            0, // use zero timestamp for simplicity
        );
        self.write_packet(&rec)
    }

    /// Flush the underlying writer.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Number of packets written.
    #[must_use]
    pub const fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// Total bytes written (header + packets).
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes + 24 // 24 = global header
    }

    /// The global header.
    #[must_use]
    pub const fn header(&self) -> &GlobalHeader {
        &self.header
    }
}

// ---------------------------------------------------------------------------
// PcapngWriter — PCAPNG block-based format
// ---------------------------------------------------------------------------

/// PCAPNG block types.
pub const BLK_SHB: u32 = 0x0A0D_0D0A; // Section Header Block
pub const BLK_IDB: u32 = 0x0000_0001; // Interface Description Block
pub const BLK_EPB: u32 = 0x0000_0006; // Enhanced Packet Block
pub const BLK_SPB: u32 = 0x0000_0003; // Simple Packet Block

/// A PCAPNG block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapngBlock {
    pub block_type: u32,
    pub body: Vec<u8>,
}

impl PcapngBlock {
    /// Total length: type(4) + length(4) + body + length(4) = 12 + body
    #[must_use]
    pub const fn total_length(&self) -> u32 {
        12 + self.body.len() as u32
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let total = self.total_length();
        let mut buf = Vec::with_capacity(total as usize);
        buf.extend_from_slice(&self.block_type.to_le_bytes());
        buf.extend_from_slice(&total.to_le_bytes());
        buf.extend_from_slice(&self.body);
        buf.extend_from_slice(&total.to_le_bytes()); // repeated at end
        buf
    }

    /// Build a Section Header Block.
    #[must_use]
    pub fn section_header() -> Self {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
        body.extend_from_slice(&1u16.to_le_bytes()); // version major
        body.extend_from_slice(&0u16.to_le_bytes()); // version minor
        body.extend_from_slice(&u64::MAX.to_le_bytes()); // section length unknown
        Self {
            block_type: BLK_SHB,
            body,
        }
    }

    /// Build an Interface Description Block.
    #[must_use]
    pub fn interface_description(link_type: u16, snap_len: u32) -> Self {
        let mut body = Vec::new();
        body.extend_from_slice(&link_type.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&snap_len.to_le_bytes());
        Self {
            block_type: BLK_IDB,
            body,
        }
    }

    /// Build an Enhanced Packet Block.
    #[must_use]
    pub fn enhanced_packet(
        interface_id: u32,
        ts_high: u32,
        ts_low: u32,
        orig_len: u32,
        data: &[u8],
    ) -> Self {
        let padded_len = (data.len() + 3) & !3; // 4-byte aligned
        let mut body = Vec::new();
        body.extend_from_slice(&interface_id.to_le_bytes());
        body.extend_from_slice(&ts_high.to_le_bytes());
        body.extend_from_slice(&ts_low.to_le_bytes());
        body.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        body.extend_from_slice(&orig_len.to_le_bytes());
        body.extend_from_slice(data);
        // Padding
        body.resize(body.len() + (padded_len - data.len()), 0);
        Self {
            block_type: BLK_EPB,
            body,
        }
    }
}

impl fmt::Display for PcapngBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PcapngBlock(type=0x{:08x} len={})",
            self.block_type,
            self.total_length()
        )
    }
}

/// A PCAPNG file writer.
pub struct PcapngWriter<W: Write> {
    writer: W,
    packet_count: u64,
    interface_id: u32,
}

impl<W: Write> PcapngWriter<W> {
    /// Create a new PCAPNG writer, writing the SHB and IDB.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(mut writer: W, link_type: u16) -> io::Result<Self> {
        let shb = PcapngBlock::section_header();
        writer.write_all(&shb.to_bytes())?;
        let idb = PcapngBlock::interface_description(link_type, 65535);
        writer.write_all(&idb.to_bytes())?;
        Ok(Self {
            writer,
            packet_count: 0,
            interface_id: 0,
        })
    }

    /// Create an Ethernet PCAPNG writer.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn ethernet(writer: W) -> io::Result<Self> {
        Self::new(writer, 1) // LINKTYPE_ETHERNET = 1
    }

    /// Write a packet as an Enhanced Packet Block.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_packet(&mut self, data: &[u8], ts_usec: u64) -> io::Result<()> {
        let ts_high = (ts_usec >> 32) as u32;
        let ts_low = (ts_usec & 0xFFFF_FFFF) as u32;
        let epb = PcapngBlock::enhanced_packet(
            self.interface_id,
            ts_high,
            ts_low,
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            data,
        );
        self.writer.write_all(&epb.to_bytes())?;
        self.packet_count += 1;
        Ok(())
    }

    /// Write raw bytes with auto-timestamp.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        let (sec, usec) = current_time_usec();
        let ts_usec = u64::from(sec) * 1_000_000 + u64::from(usec);
        self.write_packet(data, ts_usec)
    }

    /// Flush.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Number of packets written.
    #[must_use]
    pub const fn packet_count(&self) -> u64 {
        self.packet_count
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn current_time_usec() -> (u32, u32) {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let sec = u32::try_from(dur.as_secs()).unwrap_or(u32::MAX);
    let usec = dur.subsec_micros();
    (sec, usec)
}

fn current_time_nsec() -> (u32, u32) {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let sec = u32::try_from(dur.as_secs()).unwrap_or(u32::MAX);
    let nsec = dur.subsec_nanos();
    (sec, nsec)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_header_ethernet() {
        let h = GlobalHeader::ethernet_microsec();
        assert_eq!(h.magic_number, PCAP_MAGIC_MICROSEC_LE);
        assert_eq!(h.network, LINKTYPE_ETHERNET);
        assert!(!h.is_nanosec());
    }

    #[test]
    fn test_global_header_nanosec() {
        let h = GlobalHeader::raw_nanosec();
        assert!(h.is_nanosec());
        assert_eq!(h.network, LINKTYPE_RAW);
    }

    #[test]
    fn test_global_header_to_bytes_roundtrip() {
        let h = GlobalHeader::ethernet_microsec();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 24);
        let h2 = GlobalHeader::from_bytes(&bytes);
        assert_eq!(h, h2);
    }

    #[test]
    fn test_global_header_display() {
        let h = GlobalHeader::ethernet_microsec();
        let s = h.to_string();
        assert!(s.contains("GlobalHeader"));
    }

    #[test]
    fn test_packet_record_new() {
        let data = vec![0u8; 100];
        let pkt = PacketRecord::new(data);
        assert_eq!(pkt.orig_len, 100);
        assert_eq!(pkt.captured_len(), 100);
    }

    #[test]
    fn test_packet_record_with_timestamp() {
        let pkt = PacketRecord::with_timestamp(vec![1, 2, 3], 1_234_567_890, 123_456);
        assert_eq!(pkt.ts_sec, 1_234_567_890);
        assert_eq!(pkt.ts_usec, 123_456);
    }

    #[test]
    fn test_packet_record_to_bytes() {
        let pkt = PacketRecord::with_timestamp(vec![0xDE, 0xAD], 0, 0);
        let bytes = pkt.to_bytes();
        assert_eq!(bytes.len(), 18); // 16 header + 2 data
        assert_eq!(bytes[16], 0xDE);
        assert_eq!(bytes[17], 0xAD);
    }

    #[test]
    fn test_packet_record_from_bytes() {
        let pkt = PacketRecord::with_timestamp(vec![1, 2, 3, 4], 100, 200);
        let bytes = pkt.to_bytes();
        let parsed = PacketRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ts_sec, 100);
        assert_eq!(parsed.ts_usec, 200);
        assert_eq!(parsed.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_packet_record_from_bytes_too_short() {
        assert!(PacketRecord::from_bytes(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_packet_record_timestamp() {
        let pkt = PacketRecord::with_timestamp(vec![], 100, 500_000);
        let ts = pkt.timestamp();
        assert_eq!(ts.as_secs(), 100);
    }

    #[test]
    fn test_packet_record_display() {
        let pkt = PacketRecord::with_timestamp(vec![0; 64], 1000, 0);
        let s = pkt.to_string();
        assert!(s.contains("Packet("));
    }

    #[test]
    fn test_nanosec_pcap_new() {
        let pkt = NanosecondPcap::new(vec![1, 2, 3]);
        assert_eq!(pkt.orig_len, 3);
        assert_eq!(pkt.data.len(), 3);
    }

    #[test]
    fn test_nanosec_pcap_to_bytes() {
        let pkt = NanosecondPcap {
            ts_sec: 0,
            ts_nsec: 0,
            orig_len: 2,
            data: vec![0xAB, 0xCD],
        };
        let bytes = pkt.to_bytes();
        assert_eq!(bytes.len(), 18);
        assert_eq!(bytes[16], 0xAB);
        assert_eq!(bytes[17], 0xCD);
    }

    #[test]
    fn test_nanosec_pcap_display() {
        let pkt = NanosecondPcap::new(vec![0; 20]);
        let s = pkt.to_string();
        assert!(s.contains("NsPkt("));
    }

    #[test]
    fn test_pcap_record_microsec() {
        let pkt = PacketRecord::with_timestamp(vec![1, 2], 0, 0);
        let r = PcapRecord::Microsec(pkt);
        assert_eq!(r.data(), &[1, 2]);
        assert_eq!(r.payload_len(), 2);
    }

    #[test]
    fn test_pcap_record_nanosec() {
        let pkt = NanosecondPcap {
            ts_sec: 0,
            ts_nsec: 0,
            orig_len: 3,
            data: vec![1, 2, 3],
        };
        let r = PcapRecord::Nanosec(pkt);
        assert_eq!(r.payload_len(), 3);
    }

    #[test]
    fn test_pcap_record_to_bytes_not_empty() {
        let pkt = PacketRecord::with_timestamp(vec![0xAB], 0, 0);
        let r = PcapRecord::Microsec(pkt);
        let bytes = r.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_pcap_writer_write_packet() {
        let mut buf = Vec::new();
        let mut writer = PcapWriter::ethernet(&mut buf).unwrap();
        let pkt = PacketRecord::with_timestamp(vec![1, 2, 3, 4], 0, 0);
        writer.write_packet(&pkt).unwrap();
        assert_eq!(writer.packet_count(), 1);
        assert!(buf.len() > 24);
    }

    #[test]
    fn test_pcap_writer_global_header_in_output() {
        let mut buf = Vec::new();
        let _ = PcapWriter::ethernet(&mut buf).unwrap();
        // First 4 bytes should be the magic number
        assert_eq!(&buf[0..4], &PCAP_MAGIC_MICROSEC_LE.to_le_bytes());
    }

    #[test]
    fn test_pcap_writer_write_raw() {
        let mut buf = Vec::new();
        let mut writer = PcapWriter::ethernet(&mut buf).unwrap();
        writer.write_raw(&[0u8; 60]).unwrap();
        assert_eq!(writer.packet_count(), 1);
    }

    #[test]
    fn test_pcap_writer_total_bytes() {
        let mut buf = Vec::new();
        let writer = PcapWriter::ethernet(&mut buf).unwrap();
        assert_eq!(writer.total_bytes(), 24); // just header
    }

    #[test]
    fn test_pcapng_block_section_header() {
        let shb = PcapngBlock::section_header();
        assert_eq!(shb.block_type, BLK_SHB);
        let bytes = shb.to_bytes();
        assert!(bytes.len() >= 12);
    }

    #[test]
    fn test_pcapng_block_interface_description() {
        let idb = PcapngBlock::interface_description(1, 65535);
        assert_eq!(idb.block_type, BLK_IDB);
    }

    #[test]
    fn test_pcapng_block_enhanced_packet() {
        let epb = PcapngBlock::enhanced_packet(0, 0, 0, 10, &[0xAA; 10]);
        assert_eq!(epb.block_type, BLK_EPB);
        let bytes = epb.to_bytes();
        assert!(bytes.len() >= 12 + 20 + 10); // 12 framing + 20 body header + data
    }

    #[test]
    fn test_pcapng_block_total_length() {
        let blk = PcapngBlock {
            block_type: BLK_EPB,
            body: vec![0u8; 20],
        };
        assert_eq!(blk.total_length(), 32); // 12 + 20
    }

    #[test]
    fn test_pcapng_block_to_bytes_repeated_length() {
        let blk = PcapngBlock {
            block_type: 1,
            body: vec![0u8; 4],
        };
        let bytes = blk.to_bytes();
        let len = blk.total_length();
        // First 4 bytes = type, next 4 = total_length, last 4 = total_length again
        let end_len = u32::from_le_bytes([
            bytes[bytes.len() - 4],
            bytes[bytes.len() - 3],
            bytes[bytes.len() - 2],
            bytes[bytes.len() - 1],
        ]);
        assert_eq!(end_len, len);
    }

    #[test]
    fn test_pcapng_block_display() {
        let blk = PcapngBlock::section_header();
        let s = blk.to_string();
        assert!(s.contains("PcapngBlock"));
    }

    #[test]
    fn test_pcapng_writer_write_packet() {
        let mut buf = Vec::new();
        let mut writer = PcapngWriter::ethernet(&mut buf).unwrap();
        writer.write_packet(&[0u8; 40], 123_456_789_u64).unwrap();
        assert_eq!(writer.packet_count(), 1);
    }

    #[test]
    fn test_pcapng_writer_write_raw() {
        let mut buf = Vec::new();
        let mut writer = PcapngWriter::ethernet(&mut buf).unwrap();
        writer.write_raw(&[0u8; 20]).unwrap();
        assert_eq!(writer.packet_count(), 1);
    }

    #[test]
    fn test_pcapng_writer_initial_blocks_in_output() {
        let mut buf = Vec::new();
        let _ = PcapngWriter::ethernet(&mut buf).unwrap();
        // Should have at least SHB + IDB written
        assert!(buf.len() > 40);
    }
}
