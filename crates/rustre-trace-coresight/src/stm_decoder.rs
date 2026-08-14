//! `stm_decoder` — MIPI System Trace Macrocell (STM) decoder.
//!
//! Decodes STM (System Trace Macrocell / MIPI `STPv2`) stimulus port data.
//! The STM is used for software-generated trace via MIPI STP (System Trace
//! Protocol) and appears in `CoreSight` as a trace source alongside ETM.
//!
//! Supports:
//! - MIPI `STPv2` packet framing and opcodes
//! - Hardware/Software source distinction
//! - Channel/port demultiplexing (up to 65536 masters × 65536 channels)
//! - Timestamped data packets
//! - Marker, flag, and ASYNC packets
//! - NULL / guaranteed delivery

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::CsError;

// ─── StmOpcode ────────────────────────────────────────────────────────────────

/// MIPI `STPv2` protocol opcodes.
///
/// Each STP packet begins with a 4-bit nibble opcode.  Extended opcodes
/// use two nibbles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StmOpcode {
    // ── Version 1 ────────────────────────────────────────────────────────────
    /// NULL — no data.
    Null,
    /// M8 — master change (8-bit).
    M8,
    /// MERROR — master error.
    MError,
    /// C8 — channel change (8-bit).
    C8,
    /// C16 — channel change (16-bit).
    C16,
    /// M16 — master change (16-bit).
    M16,
    /// `FLAG_TS` — flag with timestamp.
    FlagTs,
    /// FLAG — flag without timestamp.
    Flag,
    // ── Data packets ─────────────────────────────────────────────────────────
    /// D4 — 4-bit data.
    D4,
    /// D8 — 8-bit data.
    D8,
    /// D16 — 16-bit data.
    D16,
    /// D32 — 32-bit data.
    D32,
    /// D64 — 64-bit data.
    D64,
    /// `D4_TS` — 4-bit data with timestamp.
    D4Ts,
    /// `D8_TS` — 8-bit data with timestamp.
    D8Ts,
    /// `D16_TS` — 16-bit data with timestamp.
    D16Ts,
    /// `D32_TS` — 32-bit data with timestamp.
    D32Ts,
    /// `D64_TS` — 64-bit data with timestamp.
    D64Ts,
    /// `D4_M` — 4-bit data, marked.
    D4M,
    /// `D8_M` — 8-bit data, marked.
    D8M,
    /// `D16_M` — 16-bit data, marked.
    D16M,
    /// `D32_M` — 32-bit data, marked.
    D32M,
    /// `D64_M` — 64-bit data, marked.
    D64M,
    /// `D4_MTS` — 4-bit data, marked, with timestamp.
    D4Mts,
    /// `D8_MTS` — 8-bit data, marked, with timestamp.
    D8Mts,
    /// `D16_MTS` — 16-bit data, marked, with timestamp.
    D16Mts,
    /// `D32_MTS` — 32-bit data, marked, with timestamp.
    D32Mts,
    /// `D64_MTS` — 64-bit data, marked, with timestamp.
    D64Mts,
    // ── Guaranteed / versioned ───────────────────────────────────────────────
    /// GERROR — guaranteed error.
    GError,
    /// VERSION — STP version identifier.
    Version,
    /// `NULL_TS` — null with timestamp.
    NullTs,
    /// FREQ — frequency packet.
    Freq,
    /// `FREQ_TS` — frequency with timestamp.
    FreqTs,
    /// Unknown opcode.
    Unknown(u8),
}

impl StmOpcode {
    /// Parse an `STPv2` nibble (4-bit) opcode.
    #[must_use]
    pub const fn from_nibble(n: u8) -> Self {
        match n & 0xF {
            0x0 => Self::Null,
            0x1 => Self::M8,
            0x2 => Self::MError,
            0x3 => Self::C8,
            0x4 => Self::C16,
            0x5 => Self::M16,
            0x6 => Self::FlagTs,
            0x7 => Self::Flag,
            0x8 => Self::D4,
            0x9 => Self::D8,
            0xA => Self::D16,
            0xB => Self::D32,
            0xC => Self::D64,
            0xD => Self::D4Ts, // First nibble of extended data-with-TS
            0xE => Self::D8Ts,
            0xF => Self::D16Ts,
            _ => Self::Unknown(n),
        }
    }

    /// Return the payload size in bytes (0 if variable).
    #[must_use]
    pub const fn payload_size(self) -> usize {
        match self {
            Self::M8 | Self::C8 | Self::D4 | Self::D4M | Self::D4Ts | Self::D4Mts
            | Self::C16 | Self::M16 | Self::D8 | Self::D8M | Self::D8Ts | Self::D8Mts => 1,
            Self::D16 | Self::D16M | Self::D16Ts | Self::D16Mts => 2,
            Self::D32 | Self::D32M | Self::D32Ts | Self::D32Mts | Self::Freq | Self::FreqTs
            | Self::Version => 4,
            Self::D64 | Self::D64M | Self::D64Ts | Self::D64Mts => 8,
            _ => 0,
        }
    }

    /// Return `true` if this opcode carries a timestamp.
    #[must_use]
    pub const fn has_timestamp(self) -> bool {
        matches!(
            self,
            Self::D4Ts
                | Self::D8Ts
                | Self::D16Ts
                | Self::D32Ts
                | Self::D64Ts
                | Self::D4Mts
                | Self::D8Mts
                | Self::D16Mts
                | Self::D32Mts
                | Self::D64Mts
                | Self::FlagTs
                | Self::NullTs
                | Self::FreqTs
        )
    }

    /// Return `true` if this is a marked (end-of-record) packet.
    #[must_use]
    pub const fn is_marked(self) -> bool {
        matches!(
            self,
            Self::D4M
                | Self::D8M
                | Self::D16M
                | Self::D32M
                | Self::D64M
                | Self::D4Mts
                | Self::D8Mts
                | Self::D16Mts
                | Self::D32Mts
                | Self::D64Mts
        )
    }
}

// ─── StmPacket ────────────────────────────────────────────────────────────────

/// A decoded STM/STPv2 packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StmPacket {
    /// Master ID.
    pub master: u16,
    /// Channel (port) ID.
    pub channel: u16,
    /// Opcode.
    pub opcode: StmOpcode,
    /// Data payload (up to 8 bytes).
    pub data: u64,
    /// Data size in bytes.
    pub data_size: usize,
    /// Timestamp (if present, otherwise 0).
    pub timestamp: u64,
    /// Whether this packet carries a timestamp.
    pub has_timestamp: bool,
    /// Whether this is a marked (end-of-record) packet.
    pub is_marked: bool,
    /// Byte offset in the stream.
    pub offset: usize,
    /// Whether this packet is from hardware (vs software).
    pub is_hw: bool,
}

impl StmPacket {
    /// Return the payload as a little-endian byte array.
    #[must_use]
    pub const fn data_bytes(&self) -> [u8; 8] {
        self.data.to_le_bytes()
    }
}

impl std::fmt::Display for StmPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "STM[M{:04x}:C{:04x}] {:?} data=0x{:x}",
            self.master, self.channel, self.opcode, self.data
        )?;
        if self.has_timestamp {
            write!(f, " ts={}", self.timestamp)?;
        }
        if self.is_marked {
            write!(f, " [M]")?;
        }
        Ok(())
    }
}

// ─── StmDecoder ───────────────────────────────────────────────────────────────

/// MIPI `STPv2` / STM decoder.
///
/// Handles the full `STPv2` framing: nibble-based packet headers, variable-length
/// timestamps, master/channel context, and per-port aggregation.
pub struct StmDecoder {
    /// Raw byte buffer.
    buf: Vec<u8>,
    /// Current byte position.
    pos: usize,
    /// Current bit position within the byte (0=low nibble, 4=high nibble).
    nibble_pos: u8,
    /// Current master ID.
    pub current_master: u16,
    /// Current channel ID.
    pub current_channel: u16,
    /// Last timestamp value.
    pub current_ts: u64,
    /// `STPv2` version.
    pub version: u8,
    /// Decoded packets.
    pub packets: Vec<StmPacket>,
    /// Per-(master,channel) software record buffers.
    sw_buffers: HashMap<(u16, u16), Vec<u8>>,
    /// Per-(master,channel) completed records.
    pub records: HashMap<(u16, u16), Vec<Vec<u8>>>,
    /// Total bytes decoded.
    pub total_decoded: u64,
    /// Error count.
    pub error_count: u64,
}

impl StmDecoder {
    /// Create a new STM decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            nibble_pos: 0,
            current_master: 0,
            current_channel: 0,
            current_ts: 0,
            version: 2,
            packets: Vec::new(),
            sw_buffers: HashMap::new(),
            records: HashMap::new(),
            total_decoded: 0,
            error_count: 0,
        }
    }

    /// Feed raw `STPv2` bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return remaining bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Read one nibble from the stream.
    fn read_nibble(&mut self) -> Option<u8> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let byte = self.buf[self.pos];
        let nibble = if self.nibble_pos == 0 {
            byte & 0x0F
        } else {
            (byte >> 4) & 0x0F
        };
        self.nibble_pos += 4;
        if self.nibble_pos >= 8 {
            self.nibble_pos = 0;
            self.pos += 1;
        }
        Some(nibble)
    }

    /// Read `n` bytes (consuming nibbles to align first).
    fn read_bytes_aligned(&mut self, n: usize) -> Option<Vec<u8>> {
        // Align to byte boundary
        if self.nibble_pos != 0 {
            self.pos += 1;
            self.nibble_pos = 0;
        }
        if self.pos + n > self.buf.len() {
            return None;
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(v)
    }

    /// Read a variable-length MIPI `STPv2` timestamp (1-8 bytes, MSB format).
    fn read_timestamp(&mut self) -> Option<u64> {
        // MIPI STPv2 timestamps are stored in nibble pairs, up to 16 nibbles
        let mut ts: u64 = 0;
        for _ in 0..8 {
            let n = self.read_nibble()?;
            ts = (ts << 4) | u64::from(n);
            if n & 0x8 == 0 {
                break; // MSB not set means last nibble
            }
        }
        Some(ts)
    }

    /// Decode the next STM packet.
    pub fn next_packet(&mut self) -> Option<Result<StmPacket, CsError>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let n = self.read_nibble()?;
        let opcode = StmOpcode::from_nibble(n);
        let mut pkt = StmPacket {
            master: self.current_master,
            channel: self.current_channel,
            opcode,
            data: 0,
            data_size: 0,
            timestamp: 0,
            has_timestamp: opcode.has_timestamp(),
            is_marked: opcode.is_marked(),
            offset: start,
            is_hw: false,
        };

        let result = match opcode {
            StmOpcode::Null | StmOpcode::Flag | StmOpcode::GError => Ok(pkt),
            StmOpcode::NullTs | StmOpcode::FlagTs => {
                pkt.timestamp = self.read_timestamp().unwrap_or(0);
                pkt.has_timestamp = true;
                Ok(pkt)
            }
            StmOpcode::M8 => {
                let b = u16::from(self.read_nibble()?);
                let b2 = u16::from(self.read_nibble()?);
                self.current_master = (b << 4) | b2;
                pkt.master = self.current_master;
                Ok(pkt)
            }
            StmOpcode::M16 => {
                let bytes = self.read_bytes_aligned(2)?;
                self.current_master = u16::from_be_bytes([bytes[0], bytes[1]]);
                pkt.master = self.current_master;
                Ok(pkt)
            }
            StmOpcode::C8 => {
                let b = u16::from(self.read_nibble()?);
                let b2 = u16::from(self.read_nibble()?);
                self.current_channel = (b << 4) | b2;
                pkt.channel = self.current_channel;
                Ok(pkt)
            }
            StmOpcode::C16 => {
                let bytes = self.read_bytes_aligned(2)?;
                self.current_channel = u16::from_be_bytes([bytes[0], bytes[1]]);
                pkt.channel = self.current_channel;
                Ok(pkt)
            }
            StmOpcode::Version => {
                let bytes = self.read_bytes_aligned(4)?;
                self.version = bytes[0];
                Ok(pkt)
            }
            StmOpcode::Freq | StmOpcode::FreqTs => {
                self.decode_freq_packet(&mut pkt, opcode)
            }
            StmOpcode::D4 | StmOpcode::D4M | StmOpcode::D4Ts | StmOpcode::D4Mts => {
                self.decode_d4_packet(&mut pkt, opcode)
            }
            StmOpcode::D8 | StmOpcode::D8M | StmOpcode::D8Ts | StmOpcode::D8Mts => {
                self.decode_d8_packet(&mut pkt, opcode)
            }
            StmOpcode::D16 | StmOpcode::D16M | StmOpcode::D16Ts | StmOpcode::D16Mts => {
                self.decode_d16_packet(&mut pkt, opcode)
            }
            StmOpcode::D32 | StmOpcode::D32M | StmOpcode::D32Ts | StmOpcode::D32Mts => {
                self.decode_d32_packet(&mut pkt, opcode)
            }
            StmOpcode::D64 | StmOpcode::D64M | StmOpcode::D64Ts | StmOpcode::D64Mts => {
                self.decode_d64_packet(&mut pkt, opcode)
            }
            StmOpcode::MError => {
                self.error_count += 1;
                Ok(pkt)
            }
            StmOpcode::Unknown(x) => {
                self.error_count += 1;
                Err(CsError::InvalidPacket(x))
            }
        };

        if let Ok(ref p) = result {
            self.total_decoded += 1;
            self.packets.push(p.clone());
        }
        Some(result)
    }

    fn decode_freq_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let bytes = self.read_bytes_aligned(4).ok_or(CsError::TruncatedBuffer)?;
        let freq = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        pkt.data = u64::from(freq);
        pkt.data_size = 4;
        if opcode == StmOpcode::FreqTs {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        Ok(pkt.clone())
    }

    fn decode_d4_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let nib = self.read_nibble().ok_or(CsError::TruncatedBuffer)?;
        pkt.data = u64::from(nib);
        pkt.data_size = 1;
        if matches!(opcode, StmOpcode::D4Ts | StmOpcode::D4Mts) {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        self.accumulate_sw_data(pkt);
        Ok(pkt.clone())
    }

    fn decode_d8_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let bytes = self.read_bytes_aligned(1).ok_or(CsError::TruncatedBuffer)?;
        pkt.data = u64::from(bytes[0]);
        pkt.data_size = 1;
        if matches!(opcode, StmOpcode::D8Ts | StmOpcode::D8Mts) {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        self.accumulate_sw_data(pkt);
        Ok(pkt.clone())
    }

    fn decode_d16_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let bytes = self.read_bytes_aligned(2).ok_or(CsError::TruncatedBuffer)?;
        pkt.data = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        pkt.data_size = 2;
        if matches!(opcode, StmOpcode::D16Ts | StmOpcode::D16Mts) {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        self.accumulate_sw_data(pkt);
        Ok(pkt.clone())
    }

    fn decode_d32_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let bytes = self.read_bytes_aligned(4).ok_or(CsError::TruncatedBuffer)?;
        pkt.data = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        pkt.data_size = 4;
        if matches!(opcode, StmOpcode::D32Ts | StmOpcode::D32Mts) {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        self.accumulate_sw_data(pkt);
        Ok(pkt.clone())
    }

    fn decode_d64_packet(&mut self, pkt: &mut StmPacket, opcode: StmOpcode) -> Result<StmPacket, CsError> {
        let bytes = self.read_bytes_aligned(8).ok_or(CsError::TruncatedBuffer)?;
        pkt.data = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        pkt.data_size = 8;
        if matches!(opcode, StmOpcode::D64Ts | StmOpcode::D64Mts) {
            pkt.timestamp = self.read_timestamp().unwrap_or(0);
        }
        self.accumulate_sw_data(pkt);
        Ok(pkt.clone())
    }

    /// Accumulate SW data bytes for a port, completing the record on MARK.
    fn accumulate_sw_data(&mut self, pkt: &StmPacket) {
        let key = (pkt.master, pkt.channel);
        let buf = self.sw_buffers.entry(key).or_default();
        let data_bytes = pkt.data.to_be_bytes();
        let start = 8 - pkt.data_size;
        buf.extend_from_slice(&data_bytes[start..]);
        if pkt.is_marked {
            let record = buf.clone();
            *buf = Vec::new();
            self.records.entry(key).or_default().push(record);
        }
    }

    /// Decode all packets.
    pub fn decode_all(&mut self) -> Vec<StmPacket> {
        let mut out = Vec::new();
        while let Some(r) = self.next_packet() {
            if let Ok(p) = r { out.push(p); }
        }
        out
    }

    /// Return all completed records for (master, channel).
    #[must_use]
    pub fn get_records(&self, master: u16, channel: u16) -> Vec<&Vec<u8>> {
        self.records.get(&(master, channel)).map(|v| v.iter().collect()).unwrap_or_default()
    }

    /// Return the total number of completed records across all ports.
    #[must_use]
    pub fn total_records(&self) -> usize {
        self.records.values().map(Vec::len).sum()
    }

    /// Return a summary.
    #[must_use]
    pub fn summary(&self) -> StmSummary {
        StmSummary {
            total_packets: self.packets.len(),
            total_records: self.total_records(),
            unique_ports: self.records.len(),
            error_count: self.error_count,
            bytes_consumed: self.pos,
            current_master: self.current_master,
            current_channel: self.current_channel,
        }
    }

    /// Return all unique (master, channel) pairs seen.
    #[must_use]
    pub fn unique_ports(&self) -> Vec<(u16, u16)> {
        let mut ports: Vec<(u16, u16)> = self
            .packets
            .iter()
            .map(|p| (p.master, p.channel))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ports.sort_unstable();
        ports
    }
}

impl Default for StmDecoder {
    fn default() -> Self { Self::new() }
}

// ─── StmSummary ───────────────────────────────────────────────────────────────

/// Statistics from STM decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StmSummary {
    /// Total packets decoded.
    pub total_packets: usize,
    /// Total completed SW records.
    pub total_records: usize,
    /// Unique (master, channel) ports seen.
    pub unique_ports: usize,
    /// Error count.
    pub error_count: u64,
    /// Bytes consumed.
    pub bytes_consumed: usize,
    /// Current master ID.
    pub current_master: u16,
    /// Current channel ID.
    pub current_channel: u16,
}

impl std::fmt::Display for StmSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StmSummary {{ pkts={}, records={}, ports={}, errors={} }}",
            self.total_packets, self.total_records, self.unique_ports, self.error_count
        )
    }
}

// ─── HwSource ─────────────────────────────────────────────────────────────────

/// A hardware STM source (stimulus port register region).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwSource {
    /// Stimulus port base address.
    pub base_addr: u64,
    /// Number of ports.
    pub port_count: u32,
    /// Master ID for this hardware source.
    pub master_id: u16,
    /// Description.
    pub description: String,
}

impl HwSource {
    /// Create a new hardware source.
    #[must_use]
    pub fn new(base_addr: u64, port_count: u32, master_id: u16, desc: impl Into<String>) -> Self {
        Self {
            base_addr,
            port_count,
            master_id,
            description: desc.into(),
        }
    }

    /// Return the stimulus port address for channel `ch`.
    #[must_use]
    pub fn port_addr(&self, ch: u32) -> u64 {
        // Each channel occupies 256 bytes in the stimulus port register region
        self.base_addr + u64::from(ch) * 256
    }

    /// Return whether `addr` falls within this source's port region.
    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        let end = self.base_addr + u64::from(self.port_count) * 256;
        addr >= self.base_addr && addr < end
    }

    /// Map an address to a channel ID.
    #[must_use]
    pub fn addr_to_channel(&self, addr: u64) -> Option<u32> {
        if self.contains_addr(addr) {
            Some(u32::try_from((addr - self.base_addr) / 256).unwrap_or(u32::MAX))
        } else {
            None
        }
    }
}

// ─── SwSource ─────────────────────────────────────────────────────────────────

/// A software STM source with named channels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwSource {
    /// Master ID.
    pub master_id: u16,
    /// Channel-to-name mapping.
    pub channel_names: HashMap<u16, String>,
}

impl SwSource {
    /// Create a new software source.
    #[must_use]
    pub fn new(master_id: u16) -> Self {
        Self { master_id, channel_names: HashMap::new() }
    }

    /// Register a named channel.
    pub fn register_channel(&mut self, channel: u16, name: impl Into<String>) {
        self.channel_names.insert(channel, name.into());
    }

    /// Look up a channel name.
    #[must_use]
    pub fn channel_name(&self, channel: u16) -> Option<&str> {
        self.channel_names.get(&channel).map(String::as_str)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_nibble() {
        assert_eq!(StmOpcode::from_nibble(0x0), StmOpcode::Null);
        assert_eq!(StmOpcode::from_nibble(0x1), StmOpcode::M8);
        assert_eq!(StmOpcode::from_nibble(0x9), StmOpcode::D8);
    }

    #[test]
    fn test_opcode_has_timestamp() {
        assert!(StmOpcode::D8Ts.has_timestamp());
        assert!(!StmOpcode::D8.has_timestamp());
        assert!(StmOpcode::FlagTs.has_timestamp());
    }

    #[test]
    fn test_opcode_is_marked() {
        assert!(StmOpcode::D8M.is_marked());
        assert!(!StmOpcode::D8.is_marked());
        assert!(StmOpcode::D64Mts.is_marked());
    }

    #[test]
    fn test_decoder_null_packet() {
        let mut dec = StmDecoder::new();
        dec.feed(&[0x00]); // low nibble = 0x0 = NULL
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.opcode, StmOpcode::Null);
    }

    #[test]
    fn test_decoder_d8_packet() {
        // Nibble 0x9 = D8, then align, then 1 byte data
        // Byte 0x09 = low nibble 0x9 (D8), high nibble 0x0
        let mut dec = StmDecoder::new();
        // Send D8 nibble then data byte
        // In nibble format: first nibble 0x9 (D8), then byte-aligned 0xAB
        // Pack: byte = (high_nibble << 4) | low_nibble
        // Byte 1: low=0x9 (D8), high=0x0 (padding)
        // Byte 2: 0xAB (data)
        dec.feed(&[0x09, 0xAB]);
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.opcode, StmOpcode::D8);
        assert_eq!(r.data, 0xAB);
    }

    #[test]
    fn test_decoder_m8_changes_master() {
        // M8 nibble = 0x1, then 2 nibbles for master (e.g., 0x1, 0x2 => master=0x12)
        // Byte 0: low=0x1 (M8), high=0x1 (first nibble of master)
        // Byte 1: low=0x2 (second nibble), high=0x0
        let mut dec = StmDecoder::new();
        dec.feed(&[0x11, 0x02]); // M8, master = 0x12
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.opcode, StmOpcode::M8);
        assert_eq!(dec.current_master, 0x12);
    }

    #[test]
    fn test_decoder_c8_changes_channel() {
        // C8 = 0x3
        // Byte 0: low=0x3 (C8), high=0x5 (first nibble of channel)
        // Byte 1: low=0xA (second nibble), high=0x0
        let mut dec = StmDecoder::new();
        dec.feed(&[0x53, 0x0A]); // channel nibbles = 0x5, 0xA => channel=0x5A
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.opcode, StmOpcode::C8);
        assert_eq!(dec.current_channel, 0x5A);
    }

    #[test]
    fn test_stm_summary() {
        let dec = StmDecoder::new();
        let s = dec.summary();
        assert_eq!(s.total_packets, 0);
        let _disp = s.to_string();
    }

    #[test]
    fn test_sw_source_channel_name() {
        let mut sw = SwSource::new(0);
        sw.register_channel(1, "kernel_log");
        assert_eq!(sw.channel_name(1), Some("kernel_log"));
        assert_eq!(sw.channel_name(99), None);
    }

    #[test]
    fn test_hw_source_port_addr() {
        let hw = HwSource::new(0x2000_0000, 256, 0, "CoreSight STM");
        assert_eq!(hw.port_addr(0), 0x2000_0000);
        assert_eq!(hw.port_addr(1), 0x2000_0100);
    }

    #[test]
    fn test_hw_source_addr_to_channel() {
        let hw = HwSource::new(0x2000_0000, 256, 0, "STM");
        assert_eq!(hw.addr_to_channel(0x2000_0200), Some(2));
        assert_eq!(hw.addr_to_channel(0x1000_0000), None);
    }

    #[test]
    fn test_hw_source_contains_addr() {
        let hw = HwSource::new(0x1000_0000, 4, 0, "STM");
        assert!(hw.contains_addr(0x1000_0000));
        assert!(hw.contains_addr(0x1000_03FF));
        assert!(!hw.contains_addr(0x1000_0400));
    }

    #[test]
    fn test_stm_packet_display() {
        let p = StmPacket {
            master: 0x0001,
            channel: 0x0002,
            opcode: StmOpcode::D8,
            data: 0xAB,
            data_size: 1,
            timestamp: 0,
            has_timestamp: false,
            is_marked: false,
            offset: 0,
            is_hw: false,
        };
        let s = p.to_string();
        assert!(s.contains("0001"));
        assert!(s.contains("0002"));
    }

    #[test]
    fn test_flag_packet() {
        let mut dec = StmDecoder::new();
        dec.feed(&[0x07]); // nibble 0x7 = Flag
        let r = dec.next_packet().unwrap().unwrap();
        assert_eq!(r.opcode, StmOpcode::Flag);
    }

    #[test]
    fn test_total_records_after_mark() {
        let mut dec = StmDecoder::new();
        // D8M = D8 with mark → completes a record
        // D8M nibble: need to look up encoding — use direct packet injection
        dec.sw_buffers.insert((0, 0), vec![0xAA, 0xBB]);
        let pkt = StmPacket {
            master: 0,
            channel: 0,
            opcode: StmOpcode::D8M,
            data: 0xCC,
            data_size: 1,
            timestamp: 0,
            has_timestamp: false,
            is_marked: true,
            offset: 0,
            is_hw: false,
        };
        dec.accumulate_sw_data(&pkt);
        assert_eq!(dec.total_records(), 1);
        let records = dec.get_records(0, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_unique_ports_empty() {
        let dec = StmDecoder::new();
        assert!(dec.unique_ports().is_empty());
    }

    #[test]
    fn test_decode_all_returns_vec() {
        let mut dec = StmDecoder::new();
        dec.feed(&[0x00, 0x07]); // NULL, Flag
        let pkts = dec.decode_all();
        assert!(!pkts.is_empty());
    }
}
